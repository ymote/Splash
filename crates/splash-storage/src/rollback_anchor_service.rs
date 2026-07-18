//! Bounded transactional-service protocol for rollback anchors.
//!
//! [`TrustedServiceRollbackAnchor`] turns a host-owned
//! [`RollbackAnchorServiceTransport`] into a [`crate::RollbackAnchor`], while
//! [`RollbackAnchorService`] dispatches the same bounded wire protocol on a
//! trusted service. The transport and dispatcher must reach or wrap one
//! separately trusted authority that durably enforces the documented per-record
//! compare-and-swap contract. This module validates the wire format, bounds
//! messages, rejects invalid requested transitions, and detects state
//! regressions observed during one process lifetime. It does not make an
//! ordinary HTTPS endpoint, keyring, local cache, or volatile backend rollback
//! resistant by itself.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{
    RollbackAnchor, RollbackAnchorCompareAndSwapOutcome, RollbackAnchorState, StorageRecordKey,
    ROLLBACK_ANCHOR_COMMITMENT_BYTES,
};

/// Protocol version used by the client and server-side dispatcher.
pub const ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION: u8 = 1;
/// Maximum JSON bytes accepted for one service request.
pub const MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES: usize = 4 * 1024;
/// Maximum JSON bytes accepted for one service response.
pub const MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES: usize = 4 * 1024;

/// Host-owned transport for one transactional rollback-anchor service request.
///
/// `exchange` must send the exact request bytes to one fixed host-selected
/// service endpoint, reject response bodies larger than `maximum_response_bytes`
/// instead of truncating them, and return only the complete response body. The
/// transport must not derive an endpoint, proxy, credential, or route from a
/// storage key or from any Splash value.
pub trait RollbackAnchorServiceTransport {
    type Error;

    fn exchange(
        &mut self,
        request: &[u8],
        maximum_response_bytes: usize,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// A rollback anchor backed by one host-owned transactional service transport.
///
/// The service is the production trust boundary. It must durably retain the
/// per-record state outside the rollback domain of the local payload storage,
/// reject regressing revisions and fences, and atomically report conflicts.
/// The client keeps only a process-local observed-state floor as defense in
/// depth; it does not substitute for a service that survives restart and
/// storage rollback.
pub struct TrustedServiceRollbackAnchor<T> {
    transport: RefCell<T>,
    observed: RefCell<BTreeMap<StorageRecordKey, RollbackAnchorState>>,
}

impl<T> TrustedServiceRollbackAnchor<T> {
    /// Creates an anchor over one host-owned transactional service transport.
    pub fn new(transport: T) -> Self {
        Self {
            transport: RefCell::new(transport),
            observed: RefCell::new(BTreeMap::new()),
        }
    }

    /// Returns how many record states have been observed in this process.
    ///
    /// This exposes no record names, state values, or transport configuration.
    pub fn observed_record_count(&self) -> usize {
        self.observed.borrow().len()
    }
}

impl<T> fmt::Debug for TrustedServiceRollbackAnchor<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedServiceRollbackAnchor")
            .field("observed_record_count", &self.observed.borrow().len())
            .finish_non_exhaustive()
    }
}

impl<T> TrustedServiceRollbackAnchor<T>
where
    T: RollbackAnchorServiceTransport,
{
    fn exchange(
        &self,
        request: WireRequest,
    ) -> Result<WireResponse, TrustedServiceRollbackAnchorError> {
        let request = serde_json::to_vec(&request)
            .map_err(|_| TrustedServiceRollbackAnchorError::InvalidRequest)?;
        if request.len() > MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES {
            return Err(TrustedServiceRollbackAnchorError::RequestTooLarge {
                maximum: MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES,
            });
        }
        let response = self
            .transport
            .borrow_mut()
            .exchange(&request, MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES)
            .map_err(|_| TrustedServiceRollbackAnchorError::Transport)?;
        if response.len() > MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES {
            return Err(TrustedServiceRollbackAnchorError::ResponseTooLarge {
                maximum: MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES,
            });
        }
        let response = serde_json::from_slice::<WireResponse>(&response)
            .map_err(|_| TrustedServiceRollbackAnchorError::InvalidResponse)?;
        if response.version() != ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION {
            return Err(TrustedServiceRollbackAnchorError::UnsupportedResponseVersion);
        }
        Ok(response)
    }

    fn observe(
        &self,
        key: &StorageRecordKey,
        state: RollbackAnchorState,
    ) -> Result<(), TrustedServiceRollbackAnchorError> {
        let mut observed = self.observed.borrow_mut();
        if let Some(previous) = observed.get(key).copied() {
            validate_state_transition(previous, state)
                .map_err(TrustedServiceRollbackAnchorError::ObservedStateRegression)?;
        }
        observed.insert(key.clone(), state);
        Ok(())
    }

    fn decode_state(
        &self,
        state: WireState,
    ) -> Result<RollbackAnchorState, TrustedServiceRollbackAnchorError> {
        state
            .into_domain()
            .map_err(|_| TrustedServiceRollbackAnchorError::InvalidResponse)
    }

    fn validate_expected_against_observed(
        &self,
        key: &StorageRecordKey,
        expected: RollbackAnchorState,
    ) -> Result<(), TrustedServiceRollbackAnchorError> {
        let observed = self.observed.borrow();
        if let Some(previous) = observed.get(key).copied() {
            validate_state_transition(previous, expected)
                .map_err(TrustedServiceRollbackAnchorError::ExpectedStateRegressed)?;
        }
        Ok(())
    }
}

impl<T> RollbackAnchor for TrustedServiceRollbackAnchor<T>
where
    T: RollbackAnchorServiceTransport,
{
    type Error = TrustedServiceRollbackAnchorError;

    fn load(&self, key: &StorageRecordKey) -> Result<RollbackAnchorState, Self::Error> {
        match self.exchange(WireRequest::load(key))? {
            WireResponse::State { state, .. } => {
                let state = self.decode_state(state)?;
                self.observe(key, state)?;
                Ok(state)
            }
            WireResponse::Stored { .. } | WireResponse::Conflict { .. } => {
                Err(TrustedServiceRollbackAnchorError::UnexpectedResponse)
            }
        }
    }

    fn compare_and_swap(
        &mut self,
        key: &StorageRecordKey,
        expected: RollbackAnchorState,
        replacement: RollbackAnchorState,
    ) -> Result<RollbackAnchorCompareAndSwapOutcome, Self::Error> {
        self.validate_expected_against_observed(key, expected)?;
        validate_state_transition(expected, replacement)
            .map_err(TrustedServiceRollbackAnchorError::InvalidRequestedTransition)?;
        match self.exchange(WireRequest::compare_and_swap(key, expected, replacement))? {
            WireResponse::Stored { .. } => {
                self.observe(key, replacement)?;
                Ok(RollbackAnchorCompareAndSwapOutcome::Stored)
            }
            WireResponse::Conflict { actual, .. } => {
                let actual = self.decode_state(actual)?;
                self.observe(key, actual)?;
                Ok(RollbackAnchorCompareAndSwapOutcome::Conflict { actual })
            }
            WireResponse::State { .. } => {
                Err(TrustedServiceRollbackAnchorError::UnexpectedResponse)
            }
        }
    }
}

/// Bounded server-side dispatcher for the transactional rollback-anchor
/// protocol.
///
/// This type is an embeddable request handler, not an HTTP listener or an
/// authentication mechanism. A deployment must authenticate and authorize a
/// caller before it passes request bytes here, serialize access to the handler
/// as appropriate for its backend, and provide an `A` that is a real durable,
/// rollback-resistant compare-and-swap authority. In particular,
/// [`crate::VolatileRollbackAnchor`] is suitable only for tests and local
/// development.
pub struct RollbackAnchorService<A> {
    anchor: A,
}

impl<A> RollbackAnchorService<A> {
    /// Creates a server-side dispatcher over one host-owned anchor backend.
    pub fn new(anchor: A) -> Self {
        Self { anchor }
    }

    /// Consumes this dispatcher and returns its host-owned anchor backend.
    pub fn into_inner(self) -> A {
        self.anchor
    }
}

impl<A> fmt::Debug for RollbackAnchorService<A> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RollbackAnchorService")
            .finish_non_exhaustive()
    }
}

impl<A> RollbackAnchorService<A>
where
    A: RollbackAnchor,
{
    /// Validates, dispatches, and encodes one complete protocol request.
    ///
    /// Request and response bodies are independently capped at 4 KiB. All
    /// malformed request, unsupported-version, and backend failures are
    /// represented by redacted errors; this type never embeds request bytes,
    /// record keys, anchor states, or backend diagnostics in an error.
    pub fn handle_request(
        &mut self,
        request: &[u8],
    ) -> Result<Vec<u8>, RollbackAnchorServiceError> {
        if request.len() > MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES {
            return Err(RollbackAnchorServiceError::RequestTooLarge {
                maximum: MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES,
            });
        }
        let request = serde_json::from_slice::<WireRequest>(request)
            .map_err(|_| RollbackAnchorServiceError::InvalidRequest)?;
        if request.version() != ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION {
            return Err(RollbackAnchorServiceError::UnsupportedRequestVersion);
        }
        let request = request
            .into_domain()
            .map_err(|_| RollbackAnchorServiceError::InvalidRequest)?;

        let response = match request {
            DecodedWireRequest::Load { key } => WireResponse::State {
                version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
                state: self
                    .anchor
                    .load(&key)
                    .map_err(|_| RollbackAnchorServiceError::Backend)?
                    .into(),
            },
            DecodedWireRequest::CompareAndSwap {
                key,
                expected,
                replacement,
            } => {
                validate_state_transition(expected, replacement)
                    .map_err(RollbackAnchorServiceError::InvalidRequestedTransition)?;
                match self
                    .anchor
                    .compare_and_swap(&key, expected, replacement)
                    .map_err(|_| RollbackAnchorServiceError::Backend)?
                {
                    RollbackAnchorCompareAndSwapOutcome::Stored => WireResponse::Stored {
                        version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
                    },
                    RollbackAnchorCompareAndSwapOutcome::Conflict { actual } => {
                        WireResponse::Conflict {
                            version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
                            actual: actual.into(),
                        }
                    }
                }
            }
        };
        let response =
            serde_json::to_vec(&response).map_err(|_| RollbackAnchorServiceError::Encoding)?;
        if response.len() > MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES {
            return Err(RollbackAnchorServiceError::ResponseTooLarge {
                maximum: MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES,
            });
        }
        Ok(response)
    }
}

/// Failure while dispatching one rollback-anchor service request.
///
/// Values deliberately redact request bytes, record identities, anchor states,
/// and backend diagnostics. An HTTP or RPC wrapper may map the variants to
/// status classes, but must not expose richer backend failure details to an
/// untrusted caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAnchorServiceError {
    RequestTooLarge { maximum: usize },
    InvalidRequest,
    UnsupportedRequestVersion,
    InvalidRequestedTransition(RollbackAnchorStateTransitionError),
    Backend,
    Encoding,
    ResponseTooLarge { maximum: usize },
}

impl Display for RollbackAnchorServiceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestTooLarge { maximum } => write!(
                formatter,
                "rollback-anchor service request exceeds the {maximum}-byte limit"
            ),
            Self::InvalidRequest => {
                formatter.write_str("rollback-anchor service request is invalid")
            }
            Self::UnsupportedRequestVersion => {
                formatter.write_str("rollback-anchor service request uses an unsupported version")
            }
            Self::InvalidRequestedTransition(error) => {
                write!(
                    formatter,
                    "rollback-anchor service request is invalid: {error}"
                )
            }
            Self::Backend => formatter.write_str("rollback-anchor service backend failed"),
            Self::Encoding => {
                formatter.write_str("rollback-anchor service response encoding failed")
            }
            Self::ResponseTooLarge { maximum } => write!(
                formatter,
                "rollback-anchor service response exceeds the {maximum}-byte limit"
            ),
        }
    }
}

impl std::error::Error for RollbackAnchorServiceError {}

/// Invalid monotonic state transition requested from or observed at a service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAnchorStateTransitionError {
    RevisionRegressed,
    FencingTokenRegressed,
    CommitmentChangedWithoutRevision,
}

impl Display for RollbackAnchorStateTransitionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RevisionRegressed => {
                formatter.write_str("rollback-anchor revision cannot decrease")
            }
            Self::FencingTokenRegressed => {
                formatter.write_str("rollback-anchor fencing token cannot decrease")
            }
            Self::CommitmentChangedWithoutRevision => formatter
                .write_str("rollback-anchor commitment cannot change without a revision advance"),
        }
    }
}

impl std::error::Error for RollbackAnchorStateTransitionError {}

/// Failure while using one [`TrustedServiceRollbackAnchor`].
///
/// Transport errors and response bytes are intentionally redacted: they can
/// contain service addresses, authentication metadata, or host record names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedServiceRollbackAnchorError {
    Transport,
    InvalidRequest,
    RequestTooLarge { maximum: usize },
    ResponseTooLarge { maximum: usize },
    InvalidResponse,
    UnsupportedResponseVersion,
    UnexpectedResponse,
    ExpectedStateRegressed(RollbackAnchorStateTransitionError),
    InvalidRequestedTransition(RollbackAnchorStateTransitionError),
    ObservedStateRegression(RollbackAnchorStateTransitionError),
}

impl Display for TrustedServiceRollbackAnchorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport => {
                formatter.write_str("trusted rollback-anchor service transport failed")
            }
            Self::InvalidRequest => {
                formatter.write_str("trusted rollback-anchor service request is invalid")
            }
            Self::RequestTooLarge { maximum } => write!(
                formatter,
                "trusted rollback-anchor service request exceeds the {maximum}-byte limit"
            ),
            Self::ResponseTooLarge { maximum } => write!(
                formatter,
                "trusted rollback-anchor service response exceeds the {maximum}-byte limit"
            ),
            Self::InvalidResponse => {
                formatter.write_str("trusted rollback-anchor service response is invalid")
            }
            Self::UnsupportedResponseVersion => formatter
                .write_str("trusted rollback-anchor service response uses an unsupported version"),
            Self::UnexpectedResponse => formatter
                .write_str("trusted rollback-anchor service returned an unexpected response"),
            Self::ExpectedStateRegressed(error) => write!(
                formatter,
                "requested rollback-anchor state regresses a state observed by this process: {error}"
            ),
            Self::InvalidRequestedTransition(error) => {
                write!(formatter, "invalid rollback-anchor transition: {error}")
            }
            Self::ObservedStateRegression(error) => {
                write!(
                    formatter,
                    "trusted rollback-anchor service state regressed: {error}"
                )
            }
        }
    }
}

impl std::error::Error for TrustedServiceRollbackAnchorError {}

fn validate_state_transition(
    previous: RollbackAnchorState,
    next: RollbackAnchorState,
) -> Result<(), RollbackAnchorStateTransitionError> {
    if next.revision_floor() < previous.revision_floor() {
        return Err(RollbackAnchorStateTransitionError::RevisionRegressed);
    }
    if next.fencing_token() < previous.fencing_token() {
        return Err(RollbackAnchorStateTransitionError::FencingTokenRegressed);
    }
    if next.revision_floor() == previous.revision_floor()
        && next.record_commitment() != previous.record_commitment()
    {
        return Err(RollbackAnchorStateTransitionError::CommitmentChangedWithoutRevision);
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum WireRequest {
    Load {
        version: u8,
        key: WireKey,
    },
    CompareAndSwap {
        version: u8,
        key: WireKey,
        expected: WireState,
        replacement: WireState,
    },
}

impl WireRequest {
    fn load(key: &StorageRecordKey) -> Self {
        Self::Load {
            version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
            key: WireKey::from(key),
        }
    }

    fn compare_and_swap(
        key: &StorageRecordKey,
        expected: RollbackAnchorState,
        replacement: RollbackAnchorState,
    ) -> Self {
        Self::CompareAndSwap {
            version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
            key: WireKey::from(key),
            expected: WireState::from(expected),
            replacement: WireState::from(replacement),
        }
    }

    fn version(&self) -> u8 {
        match self {
            Self::Load { version, .. } | Self::CompareAndSwap { version, .. } => *version,
        }
    }

    fn into_domain(self) -> Result<DecodedWireRequest, ()> {
        match self {
            Self::Load { key, .. } => Ok(DecodedWireRequest::Load {
                key: key.into_domain()?,
            }),
            Self::CompareAndSwap {
                key,
                expected,
                replacement,
                ..
            } => Ok(DecodedWireRequest::CompareAndSwap {
                key: key.into_domain()?,
                expected: expected.into_domain()?,
                replacement: replacement.into_domain()?,
            }),
        }
    }
}

enum DecodedWireRequest {
    Load {
        key: StorageRecordKey,
    },
    CompareAndSwap {
        key: StorageRecordKey,
        expected: RollbackAnchorState,
        replacement: RollbackAnchorState,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireKey {
    namespace: String,
    name: String,
}

impl From<&StorageRecordKey> for WireKey {
    fn from(key: &StorageRecordKey) -> Self {
        Self {
            namespace: key.namespace().to_owned(),
            name: key.name().to_owned(),
        }
    }
}

impl WireKey {
    fn into_domain(self) -> Result<StorageRecordKey, ()> {
        StorageRecordKey::new(self.namespace, self.name).map_err(|_| ())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum WireResponse {
    State { version: u8, state: WireState },
    Stored { version: u8 },
    Conflict { version: u8, actual: WireState },
}

impl WireResponse {
    fn version(&self) -> u8 {
        match self {
            Self::State { version, .. }
            | Self::Stored { version }
            | Self::Conflict { version, .. } => *version,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireState {
    revision_floor: String,
    record_commitment: Option<String>,
    fencing_token: String,
}

impl From<RollbackAnchorState> for WireState {
    fn from(state: RollbackAnchorState) -> Self {
        Self {
            revision_floor: state.revision_floor().to_string(),
            record_commitment: state
                .record_commitment()
                .map(|commitment| URL_SAFE_NO_PAD.encode(commitment)),
            fencing_token: state.fencing_token().to_string(),
        }
    }
}

impl WireState {
    fn into_domain(self) -> Result<RollbackAnchorState, ()> {
        let revision_floor = parse_canonical_u64(&self.revision_floor).ok_or(())?;
        let fencing_token = parse_canonical_u64(&self.fencing_token).ok_or(())?;
        let record_commitment = match self.record_commitment {
            Some(encoded) => Some(decode_commitment(encoded)?),
            None => None,
        };
        RollbackAnchorState::new(revision_floor, record_commitment, fencing_token).map_err(|_| ())
    }
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
    if value == "0" {
        return Some(0);
    }
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn decode_commitment(encoded: String) -> Result<[u8; ROLLBACK_ANCHOR_COMMITMENT_BYTES], ()> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| ())?;
    let commitment =
        <[u8; ROLLBACK_ANCHOR_COMMITMENT_BYTES]>::try_from(bytes.as_slice()).map_err(|_| ())?;
    if URL_SAFE_NO_PAD.encode(commitment) != encoded {
        return Err(());
    }
    Ok(commitment)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use serde_json::{json, Value};

    use super::*;
    use crate::VolatileRollbackAnchor;

    #[derive(Default)]
    struct ScriptedTransport {
        requests: Vec<Vec<u8>>,
        responses: VecDeque<Result<Vec<u8>, ()>>,
    }

    impl ScriptedTransport {
        fn with_responses(responses: impl IntoIterator<Item = WireResponse>) -> Self {
            Self {
                requests: Vec::new(),
                responses: responses
                    .into_iter()
                    .map(|response| Ok(serde_json::to_vec(&response).unwrap()))
                    .collect(),
            }
        }
    }

    impl RollbackAnchorServiceTransport for ScriptedTransport {
        type Error = ();

        fn exchange(
            &mut self,
            request: &[u8],
            _maximum_response_bytes: usize,
        ) -> Result<Vec<u8>, Self::Error> {
            self.requests.push(request.to_vec());
            self.responses.pop_front().unwrap_or(Err(()))
        }
    }

    struct LoopbackTransport {
        service: RollbackAnchorService<VolatileRollbackAnchor>,
    }

    impl LoopbackTransport {
        fn new(anchor: VolatileRollbackAnchor) -> Self {
            Self {
                service: RollbackAnchorService::new(anchor),
            }
        }
    }

    impl RollbackAnchorServiceTransport for LoopbackTransport {
        type Error = ();

        fn exchange(
            &mut self,
            request: &[u8],
            maximum_response_bytes: usize,
        ) -> Result<Vec<u8>, Self::Error> {
            let response = self.service.handle_request(request).map_err(|_| ())?;
            if response.len() > maximum_response_bytes {
                return Err(());
            }
            Ok(response)
        }
    }

    struct FailingAnchor;

    impl RollbackAnchor for FailingAnchor {
        type Error = &'static str;

        fn load(&self, _key: &StorageRecordKey) -> Result<RollbackAnchorState, Self::Error> {
            Err("backend-secret-metadata")
        }

        fn compare_and_swap(
            &mut self,
            _key: &StorageRecordKey,
            _expected: RollbackAnchorState,
            _replacement: RollbackAnchorState,
        ) -> Result<RollbackAnchorCompareAndSwapOutcome, Self::Error> {
            Err("backend-secret-metadata")
        }
    }

    fn key() -> StorageRecordKey {
        StorageRecordKey::new("workflow-ledger", "release-42").unwrap()
    }

    fn state(revision: u64, commitment_byte: u8, fencing_token: u64) -> RollbackAnchorState {
        RollbackAnchorState::new(
            revision,
            (revision != 0).then_some([commitment_byte; ROLLBACK_ANCHOR_COMMITMENT_BYTES]),
            fencing_token,
        )
        .unwrap()
    }

    #[test]
    fn server_core_round_trips_with_the_trusted_client_protocol() {
        let expected = RollbackAnchorState::initial();
        let replacement = state(1, 7, 3);
        let transport = LoopbackTransport::new(VolatileRollbackAnchor::default());
        let mut anchor = TrustedServiceRollbackAnchor::new(transport);

        assert_eq!(
            anchor
                .compare_and_swap(&key(), expected, replacement)
                .unwrap(),
            RollbackAnchorCompareAndSwapOutcome::Stored
        );
        assert_eq!(anchor.load(&key()).unwrap(), replacement);
    }

    #[test]
    fn server_core_returns_the_exact_conflict_state() {
        let current = state(1, 7, 2);
        let mut backing = VolatileRollbackAnchor::default();
        assert_eq!(
            backing
                .compare_and_swap(&key(), RollbackAnchorState::initial(), current)
                .unwrap(),
            RollbackAnchorCompareAndSwapOutcome::Stored
        );
        let transport = LoopbackTransport::new(backing);
        let mut anchor = TrustedServiceRollbackAnchor::new(transport);

        assert_eq!(
            anchor
                .compare_and_swap(&key(), RollbackAnchorState::initial(), state(2, 8, 3),)
                .unwrap(),
            RollbackAnchorCompareAndSwapOutcome::Conflict { actual: current }
        );
    }

    #[test]
    fn server_core_rejects_invalid_requests_without_mutating_its_backend() {
        let mut service = RollbackAnchorService::new(VolatileRollbackAnchor::default());
        let unsupported_version = br#"{"version":2,"operation":"load","key":{"namespace":"workflow-ledger","name":"release-42"}}"#;
        assert_eq!(
            service.handle_request(unsupported_version).unwrap_err(),
            RollbackAnchorServiceError::UnsupportedRequestVersion
        );

        let unknown_field = br#"{"version":1,"operation":"load","key":{"namespace":"workflow-ledger","name":"release-42"},"host_metadata":"secret-metadata"}"#;
        let error = service.handle_request(unknown_field).unwrap_err();
        assert_eq!(error, RollbackAnchorServiceError::InvalidRequest);
        assert!(!error.to_string().contains("secret-metadata"));
        assert!(!format!("{error:?}").contains("secret-metadata"));

        let invalid_key = br#"{"version":1,"operation":"load","key":{"namespace":"../host","name":"release-42"}}"#;
        assert_eq!(
            service.handle_request(invalid_key).unwrap_err(),
            RollbackAnchorServiceError::InvalidRequest
        );

        let invalid_state = br#"{"version":1,"operation":"compare_and_swap","key":{"namespace":"workflow-ledger","name":"release-42"},"expected":{"revision_floor":"1","record_commitment":null,"fencing_token":"0"},"replacement":{"revision_floor":"1","record_commitment":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","fencing_token":"0"}}"#;
        assert_eq!(
            service.handle_request(invalid_state).unwrap_err(),
            RollbackAnchorServiceError::InvalidRequest
        );

        let invalid_transition = serde_json::to_vec(&WireRequest::compare_and_swap(
            &key(),
            state(2, 7, 2),
            state(1, 7, 2),
        ))
        .unwrap();
        assert_eq!(
            service.handle_request(&invalid_transition).unwrap_err(),
            RollbackAnchorServiceError::InvalidRequestedTransition(
                RollbackAnchorStateTransitionError::RevisionRegressed
            )
        );

        let oversized = vec![b'x'; MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES + 1];
        assert_eq!(
            service.handle_request(&oversized).unwrap_err(),
            RollbackAnchorServiceError::RequestTooLarge {
                maximum: MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES,
            }
        );
        let load = serde_json::to_vec(&WireRequest::load(&key())).unwrap();
        let response = service.handle_request(&load).unwrap();
        let WireResponse::State { state, .. } = serde_json::from_slice(&response).unwrap() else {
            panic!("load must produce a state response");
        };
        assert_eq!(state.into_domain().unwrap(), RollbackAnchorState::initial());
    }

    #[test]
    fn server_core_redacts_backend_failures() {
        let mut service = RollbackAnchorService::new(FailingAnchor);
        let invalid_transition = serde_json::to_vec(&WireRequest::compare_and_swap(
            &key(),
            state(2, 7, 2),
            state(1, 7, 2),
        ))
        .unwrap();
        assert_eq!(
            service.handle_request(&invalid_transition).unwrap_err(),
            RollbackAnchorServiceError::InvalidRequestedTransition(
                RollbackAnchorStateTransitionError::RevisionRegressed
            )
        );

        let request = serde_json::to_vec(&WireRequest::load(&key())).unwrap();
        let error = service.handle_request(&request).unwrap_err();

        assert_eq!(error, RollbackAnchorServiceError::Backend);
        assert!(!error.to_string().contains("backend-secret-metadata"));
        assert!(!format!("{error:?}").contains("backend-secret-metadata"));
    }

    #[test]
    fn uses_a_canonical_bounded_protocol_and_remembers_stored_state() {
        let expected = RollbackAnchorState::initial();
        let replacement = state(1, 7, 3);
        let transport = ScriptedTransport::with_responses([
            WireResponse::Stored {
                version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
            },
            WireResponse::State {
                version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
                state: replacement.into(),
            },
        ]);
        let mut anchor = TrustedServiceRollbackAnchor::new(transport);

        assert_eq!(
            anchor
                .compare_and_swap(&key(), expected, replacement)
                .unwrap(),
            RollbackAnchorCompareAndSwapOutcome::Stored
        );
        assert_eq!(anchor.load(&key()).unwrap(), replacement);
        assert_eq!(anchor.observed_record_count(), 1);

        let requests = &anchor.transport.borrow().requests;
        let compare = serde_json::from_slice::<Value>(&requests[0]).unwrap();
        assert_eq!(compare["version"], json!(1));
        assert_eq!(compare["operation"], json!("compare_and_swap"));
        assert_eq!(compare["key"]["namespace"], json!("workflow-ledger"));
        assert_eq!(compare["key"]["name"], json!("release-42"));
        assert_eq!(compare["expected"]["revision_floor"], json!("0"));
        assert_eq!(compare["expected"]["record_commitment"], Value::Null);
        assert_eq!(compare["expected"]["fencing_token"], json!("0"));
        assert_eq!(compare["replacement"]["revision_floor"], json!("1"));
        assert_eq!(compare["replacement"]["fencing_token"], json!("3"));
        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn rejects_observed_regressions_after_a_conflict() {
        let actual = state(2, 8, 4);
        let stale = state(1, 7, 3);
        let transport = ScriptedTransport::with_responses([
            WireResponse::Conflict {
                version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
                actual: actual.into(),
            },
            WireResponse::State {
                version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
                state: stale.into(),
            },
        ]);
        let mut anchor = TrustedServiceRollbackAnchor::new(transport);

        assert_eq!(
            anchor
                .compare_and_swap(&key(), RollbackAnchorState::initial(), state(1, 7, 3))
                .unwrap(),
            RollbackAnchorCompareAndSwapOutcome::Conflict { actual }
        );
        assert!(matches!(
            anchor.load(&key()),
            Err(TrustedServiceRollbackAnchorError::ObservedStateRegression(
                RollbackAnchorStateTransitionError::RevisionRegressed
            ))
        ));
    }

    #[test]
    fn rejects_a_cas_expected_state_that_regresses_observed_state() {
        let observed = state(2, 8, 4);
        let transport = ScriptedTransport::with_responses([WireResponse::State {
            version: ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION,
            state: observed.into(),
        }]);
        let mut anchor = TrustedServiceRollbackAnchor::new(transport);

        assert_eq!(anchor.load(&key()).unwrap(), observed);
        assert_eq!(
            anchor
                .compare_and_swap(&key(), RollbackAnchorState::initial(), state(3, 9, 5))
                .unwrap_err(),
            TrustedServiceRollbackAnchorError::ExpectedStateRegressed(
                RollbackAnchorStateTransitionError::RevisionRegressed
            )
        );
        assert_eq!(anchor.transport.borrow().requests.len(), 1);
    }

    #[test]
    fn rejects_invalid_requests_and_response_data_without_disclosing_it() {
        let mut anchor = TrustedServiceRollbackAnchor::new(ScriptedTransport::default());
        let invalid_transition = anchor
            .compare_and_swap(&key(), state(2, 7, 2), state(1, 7, 2))
            .unwrap_err();
        assert_eq!(
            invalid_transition,
            TrustedServiceRollbackAnchorError::InvalidRequestedTransition(
                RollbackAnchorStateTransitionError::RevisionRegressed
            )
        );
        assert!(anchor.transport.borrow().requests.is_empty());

        let invalid_response = br#"{"outcome":"state","version":1,"state":{"revision_floor":"01","record_commitment":null,"fencing_token":"0"},"host_metadata":"secret-metadata"}"#.to_vec();
        let transport = ScriptedTransport {
            responses: VecDeque::from([Ok(invalid_response)]),
            ..ScriptedTransport::default()
        };
        let anchor = TrustedServiceRollbackAnchor::new(transport);
        let error = anchor.load(&key()).unwrap_err();
        assert_eq!(error, TrustedServiceRollbackAnchorError::InvalidResponse);
        assert!(!error.to_string().contains("secret-metadata"));
        assert!(!format!("{error:?}").contains("secret-metadata"));
    }

    #[test]
    fn rejects_responses_above_the_fixed_limit() {
        let response = vec![b'x'; MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES + 1];
        let transport = ScriptedTransport {
            responses: VecDeque::from([Ok(response)]),
            ..ScriptedTransport::default()
        };
        let anchor = TrustedServiceRollbackAnchor::new(transport);
        assert_eq!(
            anchor.load(&key()).unwrap_err(),
            TrustedServiceRollbackAnchorError::ResponseTooLarge {
                maximum: MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES,
            }
        );
    }

    #[test]
    fn rejects_noncanonical_commitments_and_versions() {
        let unsupported_version = br#"{"outcome":"state","version":2,"state":{"revision_floor":"1","record_commitment":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","fencing_token":"0"}}"#.to_vec();
        let transport = ScriptedTransport {
            responses: VecDeque::from([Ok(unsupported_version)]),
            ..ScriptedTransport::default()
        };
        let anchor = TrustedServiceRollbackAnchor::new(transport);
        assert_eq!(
            anchor.load(&key()).unwrap_err(),
            TrustedServiceRollbackAnchorError::UnsupportedResponseVersion
        );

        let noncanonical_commitment = br#"{"outcome":"state","version":1,"state":{"revision_floor":"1","record_commitment":"AQ==","fencing_token":"0"}}"#.to_vec();
        let transport = ScriptedTransport {
            responses: VecDeque::from([Ok(noncanonical_commitment)]),
            ..ScriptedTransport::default()
        };
        let anchor = TrustedServiceRollbackAnchor::new(transport);
        assert_eq!(
            anchor.load(&key()).unwrap_err(),
            TrustedServiceRollbackAnchorError::InvalidResponse
        );
    }
}
