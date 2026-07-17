#![no_main]

use std::num::NonZeroUsize;

use libfuzzer_sys::fuzz_target;
use splash_capabilities::{
    durable_audits::CapabilityAuditJournal, MAX_DURABLE_CAPABILITY_AUDIT_EVENTS,
    MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES,
};

fuzz_target!(|data: &[u8]| {
    let Ok(document) = std::str::from_utf8(data) else {
        return;
    };
    if document.len() > MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES {
        return;
    }

    let maximum_capacity = NonZeroUsize::new(MAX_DURABLE_CAPABILITY_AUDIT_EVENTS)
        .expect("the durable capability audit cap is nonzero");
    let Ok(journal) = CapabilityAuditJournal::from_json_with_capacity(document, maximum_capacity)
    else {
        return;
    };

    let encoded = journal
        .to_json()
        .expect("a bounded decoded capability audit journal must re-encode");
    assert!(encoded.len() <= MAX_DURABLE_CAPABILITY_AUDIT_JOURNAL_BYTES);
    let decoded = CapabilityAuditJournal::from_json_with_capacity(&encoded, maximum_capacity)
        .expect("a capability audit journal's current-format encoding must decode");
    assert_eq!(decoded, journal);

    let requested_capacity = usize::from(data.first().copied().unwrap_or_default())
        % MAX_DURABLE_CAPABILITY_AUDIT_EVENTS
        + 1;
    let requested_capacity = NonZeroUsize::new(requested_capacity)
        .expect("the fuzz-selected durable capability audit capacity is nonzero");
    let _ = CapabilityAuditJournal::from_json_with_capacity(document, requested_capacity);
});
