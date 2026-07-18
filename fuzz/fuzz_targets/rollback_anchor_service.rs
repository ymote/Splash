#![no_main]

use libfuzzer_sys::fuzz_target;
use splash_storage::{
    rollback_anchor_service::{
        RollbackAnchorService, RollbackAnchorServiceTransport, TrustedServiceRollbackAnchor,
        MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES, MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES,
    },
    RollbackAnchor, RollbackAnchorState, StorageRecordKey, VolatileRollbackAnchor,
    ROLLBACK_ANCHOR_COMMITMENT_BYTES,
};

const MAX_FUZZ_MESSAGE_BYTES: usize =
    if MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES > MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES {
        MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES * 2
    } else {
        MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES * 2
    };

struct ReplayTransport {
    response: Vec<u8>,
}

impl RollbackAnchorServiceTransport for ReplayTransport {
    type Error = ();

    fn exchange(
        &mut self,
        _request: &[u8],
        _maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(self.response.clone())
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_MESSAGE_BYTES {
        return;
    }

    let mut service = RollbackAnchorService::new(VolatileRollbackAnchor::default());
    if let Ok(response) = service.handle_request(data) {
        assert!(response.len() <= MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES);
    }

    let key =
        StorageRecordKey::new("fuzz", "rollback-anchor").expect("fixed fuzz storage key is valid");
    let replacement =
        RollbackAnchorState::new(1, Some([0xA5; ROLLBACK_ANCHOR_COMMITMENT_BYTES]), 1)
            .expect("fixed fuzz replacement state is valid");
    let mut anchor = TrustedServiceRollbackAnchor::new(ReplayTransport {
        response: data.to_vec(),
    });

    if data.first().copied().unwrap_or_default() & 1 == 0 {
        let _ = anchor.load(&key);
        let _ = anchor.compare_and_swap(&key, RollbackAnchorState::initial(), replacement);
    } else {
        let _ = anchor.compare_and_swap(&key, RollbackAnchorState::initial(), replacement);
        let _ = anchor.load(&key);
    }

    assert!(anchor.observed_record_count() <= 1);
});
