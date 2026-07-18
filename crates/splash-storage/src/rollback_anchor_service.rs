//! Bounded transactional-service protocol for rollback anchors.
//!
//! [`TrustedServiceRollbackAnchor`] turns a host-owned
//! [`RollbackAnchorServiceTransport`] into a [`crate::RollbackAnchor`], while
//! [`RollbackAnchorService`] dispatches the same bounded wire protocol on a
//! trusted service. [`AuthorizedRollbackAnchorService`] can add a host-owned
//! exact request-authorization gate around that dispatcher. The transport and
//! dispatcher must reach or wrap one separately trusted authority that durably
//! enforces the documented per-record compare-and-swap contract. This module
//! validates the wire format, bounds messages, rejects invalid requested
//! transitions, and detects state regressions observed during one process
//! lifetime. It does not make an ordinary HTTPS endpoint, authentication
//! protocol, keyring, local cache, or volatile backend rollback resistant by
//! itself.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{
    is_valid_token, RollbackAnchor, RollbackAnchorCompareAndSwapOutcome, RollbackAnchorState,
    StorageRecordKey, ROLLBACK_ANCHOR_COMMITMENT_BYTES,
};

/// Protocol version used by the client and server-side dispatcher.
pub const ROLLBACK_ANCHOR_SERVICE_PROTOCOL_VERSION: u8 = 1;
/// Maximum JSON bytes accepted for one service request.
pub const MAX_ROLLBACK_ANCHOR_SERVICE_REQUEST_BYTES: usize = 4 * 1024;
/// Maximum JSON bytes accepted for one service response.
pub const MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES: usize = 4 * 1024;
/// Maximum byte length of one host-authenticated service caller identifier.
pub const MAX_ROLLBACK_ANCHOR_SERVICE_CALLER_ID_BYTES: usize = 64;
/// Maximum callers accepted by [`FixedRollbackAnchorServiceAuthorizer`].
pub const MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_CALLERS: usize = 128;
/// Maximum exact operation-and-record grants accepted by
/// [`FixedRollbackAnchorServiceAuthorizer`].
pub const MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_GRANTS: usize = 1024;

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

/// One rollback-anchor operation that a service caller may be authorized to
/// perform for an exact record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RollbackAnchorServiceOperation {
    Load,
    CompareAndSwap,
}

/// Opaque host-authenticated identity supplied to a rollback-anchor service.
///
/// This is a host-side identifier, not a bearer credential or protocol field.
/// A network deployment must map a successfully authenticated caller to this
/// value before it calls
/// [`AuthorizedRollbackAnchorService::handle_authenticated_request`]. Do not
/// construct it directly from an untrusted request header, path, or body.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct RollbackAnchorServiceCallerId(String);

impl RollbackAnchorServiceCallerId {
    /// Creates a bounded opaque caller identity for trusted service setup.
    pub fn new(value: impl Into<String>) -> Result<Self, RollbackAnchorServiceCallerIdError> {
        let value = value.into();
        if !is_valid_token(&value, MAX_ROLLBACK_ANCHOR_SERVICE_CALLER_ID_BYTES) {
            return Err(RollbackAnchorServiceCallerIdError::Invalid);
        }
        Ok(Self(value))
    }

    /// Returns the host-side opaque caller identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RollbackAnchorServiceCallerId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("RollbackAnchorServiceCallerId([REDACTED])")
    }
}

/// Rejection from [`RollbackAnchorServiceCallerId::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAnchorServiceCallerIdError {
    Invalid,
}

impl Display for RollbackAnchorServiceCallerIdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("rollback-anchor service caller ID must be a bounded lowercase token")
    }
}

impl std::error::Error for RollbackAnchorServiceCallerIdError {}

/// One exact capability grant for the fixed service authorizer.
///
/// Each grant covers one authenticated caller, one protocol operation, and one
/// host-selected durable record. It is configuration data only and never
/// appears in a client request or response.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct RollbackAnchorServiceAccessGrant {
    caller: RollbackAnchorServiceCallerId,
    operation: RollbackAnchorServiceOperation,
    key: StorageRecordKey,
}

impl RollbackAnchorServiceAccessGrant {
    /// Creates one exact rollback-anchor service capability grant.
    pub fn new(
        caller: RollbackAnchorServiceCallerId,
        operation: RollbackAnchorServiceOperation,
        key: StorageRecordKey,
    ) -> Self {
        Self {
            caller,
            operation,
            key,
        }
    }

    /// Returns the host-authenticated caller selected for this grant.
    pub fn caller(&self) -> &RollbackAnchorServiceCallerId {
        &self.caller
    }

    /// Returns the exact authorized rollback-anchor operation.
    pub const fn operation(&self) -> RollbackAnchorServiceOperation {
        self.operation
    }

    /// Returns the host-selected durable record selected for this grant.
    pub fn key(&self) -> &StorageRecordKey {
        &self.key
    }
}

impl fmt::Debug for RollbackAnchorServiceAccessGrant {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RollbackAnchorServiceAccessGrant")
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

/// Host-owned authorization hook for one parsed service request.
///
/// `caller` must already be authenticated by the embedding service. The hook
/// receives only the canonical operation and record identity, never raw wire
/// bytes or anchor state. Returning any error denies the request; the wrapper
/// deliberately redacts that error before it reaches an untrusted caller.
pub trait RollbackAnchorServiceRequestAuthorizer {
    type AuthenticatedCaller;
    type Error;

    fn authorize(
        &self,
        caller: &Self::AuthenticatedCaller,
        operation: RollbackAnchorServiceOperation,
        key: &StorageRecordKey,
    ) -> Result<(), Self::Error>;
}

/// Bounded static authorizer for exact `(caller, operation, record)` grants.
///
/// This is suitable when all service identities and record capabilities are
/// selected during trusted setup. Deployments with dynamic tenancy can provide
/// their own [`RollbackAnchorServiceRequestAuthorizer`] instead, but must keep
/// authentication and policy evaluation outside untrusted request data.
pub struct FixedRollbackAnchorServiceAuthorizer {
    grants: BTreeMap<
        RollbackAnchorServiceCallerId,
        BTreeMap<StorageRecordKey, BTreeSet<RollbackAnchorServiceOperation>>,
    >,
    grant_count: usize,
}

impl FixedRollbackAnchorServiceAuthorizer {
    /// Creates a fixed, bounded exact-grant authorizer.
    pub fn new(
        grants: impl IntoIterator<Item = RollbackAnchorServiceAccessGrant>,
    ) -> Result<Self, FixedRollbackAnchorServiceAuthorizerError> {
        let mut configured = BTreeMap::new();
        let mut grant_count = 0;
        for grant in grants {
            let RollbackAnchorServiceAccessGrant {
                caller,
                operation,
                key,
            } = grant;
            if !configured.contains_key(&caller)
                && configured.len() == MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_CALLERS
            {
                return Err(
                    FixedRollbackAnchorServiceAuthorizerError::CallerLimitExceeded {
                        maximum: MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_CALLERS,
                    },
                );
            }
            let operations = configured
                .entry(caller)
                .or_insert_with(BTreeMap::new)
                .entry(key)
                .or_insert_with(BTreeSet::new);
            if operations.contains(&operation) {
                return Err(FixedRollbackAnchorServiceAuthorizerError::DuplicateGrant);
            }
            if grant_count == MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_GRANTS {
                return Err(
                    FixedRollbackAnchorServiceAuthorizerError::GrantLimitExceeded {
                        maximum: MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_GRANTS,
                    },
                );
            }
            operations.insert(operation);
            grant_count += 1;
        }
        if grant_count == 0 {
            return Err(FixedRollbackAnchorServiceAuthorizerError::EmptyGrantSet);
        }
        Ok(Self {
            grants: configured,
            grant_count,
        })
    }

    /// Returns the number of configured callers without exposing their IDs.
    pub fn caller_count(&self) -> usize {
        self.grants.len()
    }

    /// Returns the number of exact operation-and-record grants.
    pub const fn grant_count(&self) -> usize {
        self.grant_count
    }
}

impl fmt::Debug for FixedRollbackAnchorServiceAuthorizer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixedRollbackAnchorServiceAuthorizer")
            .field("caller_count", &self.grants.len())
            .field("grant_count", &self.grant_count)
            .finish()
    }
}

impl RollbackAnchorServiceRequestAuthorizer for FixedRollbackAnchorServiceAuthorizer {
    type AuthenticatedCaller = RollbackAnchorServiceCallerId;
    type Error = ();

    fn authorize(
        &self,
        caller: &Self::AuthenticatedCaller,
        operation: RollbackAnchorServiceOperation,
        key: &StorageRecordKey,
    ) -> Result<(), Self::Error> {
        if self
            .grants
            .get(caller)
            .and_then(|records| records.get(key))
            .is_some_and(|operations| operations.contains(&operation))
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Invalid fixed service-authorizer configuration.
///
/// These errors intentionally omit caller IDs and record keys so trusted setup
/// code can report a configuration class without copying policy data into a
/// broad log sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedRollbackAnchorServiceAuthorizerError {
    EmptyGrantSet,
    DuplicateGrant,
    CallerLimitExceeded { maximum: usize },
    GrantLimitExceeded { maximum: usize },
}

impl Display for FixedRollbackAnchorServiceAuthorizerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGrantSet => formatter
                .write_str("rollback-anchor service authorizer requires at least one grant"),
            Self::DuplicateGrant => {
                formatter.write_str("rollback-anchor service authorizer has a duplicate grant")
            }
            Self::CallerLimitExceeded { maximum } => write!(
                formatter,
                "rollback-anchor service authorizer exceeds the {maximum}-caller limit"
            ),
            Self::GrantLimitExceeded { maximum } => write!(
                formatter,
                "rollback-anchor service authorizer exceeds the {maximum}-grant limit"
            ),
        }
    }
}

impl std::error::Error for FixedRollbackAnchorServiceAuthorizerError {}

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
        self.handle_decoded_request(decode_service_request(request)?)
    }

    fn handle_decoded_request(
        &mut self,
        request: DecodedWireRequest,
    ) -> Result<Vec<u8>, RollbackAnchorServiceError> {
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
        encode_service_response(response)
    }
}

/// Server dispatcher with an explicit authenticated-caller authorization gate.
///
/// The embedding service must authenticate a caller before passing it to
/// [`Self::handle_authenticated_request`]. This wrapper parses and validates a
/// bounded request, asks its host-owned authorizer to approve the exact
/// operation and record, and invokes the anchor only after that check passes.
/// It is not itself an authentication protocol, network listener, concurrency
/// primitive, or durable backend.
pub struct AuthorizedRollbackAnchorService<A, Z> {
    service: RollbackAnchorService<A>,
    authorizer: Z,
}

impl<A, Z> AuthorizedRollbackAnchorService<A, Z> {
    /// Wraps one service dispatcher with a host-owned authorization policy.
    pub fn new(service: RollbackAnchorService<A>, authorizer: Z) -> Self {
        Self {
            service,
            authorizer,
        }
    }

    /// Consumes this wrapper and returns its dispatcher and authorization
    /// policy to trusted host code.
    pub fn into_parts(self) -> (RollbackAnchorService<A>, Z) {
        (self.service, self.authorizer)
    }
}

impl<A, Z> fmt::Debug for AuthorizedRollbackAnchorService<A, Z> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedRollbackAnchorService")
            .finish_non_exhaustive()
    }
}

impl<A, Z> AuthorizedRollbackAnchorService<A, Z>
where
    A: RollbackAnchor,
    Z: RollbackAnchorServiceRequestAuthorizer,
{
    /// Handles one request from an already authenticated caller.
    ///
    /// A malformed or oversized request is rejected before policy evaluation.
    /// Any authorizer denial or failure becomes a generic authorization error,
    /// and the rollback-anchor backend is not called. Network wrappers should
    /// still return generic non-success responses and avoid exposing this
    /// error's variant or timing details to untrusted callers.
    pub fn handle_authenticated_request(
        &mut self,
        caller: &Z::AuthenticatedCaller,
        request: &[u8],
    ) -> Result<Vec<u8>, AuthorizedRollbackAnchorServiceError> {
        let request = decode_service_request(request)
            .map_err(AuthorizedRollbackAnchorServiceError::Service)?;
        self.authorizer
            .authorize(caller, request.operation(), request.key())
            .map_err(|_| AuthorizedRollbackAnchorServiceError::Unauthorized)?;
        self.service
            .handle_decoded_request(request)
            .map_err(AuthorizedRollbackAnchorServiceError::Service)
    }
}

/// Failure while handling an authenticated rollback-anchor service request.
///
/// Authorization failures deliberately omit the caller identity, record key,
/// and authorizer diagnostic. Service failures retain only the core dispatcher's
/// already-redacted error class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizedRollbackAnchorServiceError {
    Unauthorized,
    Service(RollbackAnchorServiceError),
}

impl Display for AuthorizedRollbackAnchorServiceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => {
                formatter.write_str("rollback-anchor service request is not authorized")
            }
            Self::Service(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AuthorizedRollbackAnchorServiceError {}

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

impl DecodedWireRequest {
    fn operation(&self) -> RollbackAnchorServiceOperation {
        match self {
            Self::Load { .. } => RollbackAnchorServiceOperation::Load,
            Self::CompareAndSwap { .. } => RollbackAnchorServiceOperation::CompareAndSwap,
        }
    }

    fn key(&self) -> &StorageRecordKey {
        match self {
            Self::Load { key } | Self::CompareAndSwap { key, .. } => key,
        }
    }
}

fn decode_service_request(
    request: &[u8],
) -> Result<DecodedWireRequest, RollbackAnchorServiceError> {
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
    request
        .into_domain()
        .map_err(|_| RollbackAnchorServiceError::InvalidRequest)
}

fn encode_service_response(response: WireResponse) -> Result<Vec<u8>, RollbackAnchorServiceError> {
    let response =
        serde_json::to_vec(&response).map_err(|_| RollbackAnchorServiceError::Encoding)?;
    if response.len() > MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES {
        return Err(RollbackAnchorServiceError::ResponseTooLarge {
            maximum: MAX_ROLLBACK_ANCHOR_SERVICE_RESPONSE_BYTES,
        });
    }
    Ok(response)
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
    use std::cell::Cell;
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

    #[derive(Default)]
    struct CountingAnchor {
        load_calls: Cell<usize>,
        compare_and_swap_calls: usize,
    }

    impl RollbackAnchor for CountingAnchor {
        type Error = ();

        fn load(&self, _key: &StorageRecordKey) -> Result<RollbackAnchorState, Self::Error> {
            self.load_calls.set(self.load_calls.get() + 1);
            Ok(RollbackAnchorState::initial())
        }

        fn compare_and_swap(
            &mut self,
            _key: &StorageRecordKey,
            _expected: RollbackAnchorState,
            _replacement: RollbackAnchorState,
        ) -> Result<RollbackAnchorCompareAndSwapOutcome, Self::Error> {
            self.compare_and_swap_calls += 1;
            Ok(RollbackAnchorCompareAndSwapOutcome::Stored)
        }
    }

    struct FailingAuthorizer;

    impl RollbackAnchorServiceRequestAuthorizer for FailingAuthorizer {
        type AuthenticatedCaller = ();
        type Error = &'static str;

        fn authorize(
            &self,
            _caller: &Self::AuthenticatedCaller,
            _operation: RollbackAnchorServiceOperation,
            _key: &StorageRecordKey,
        ) -> Result<(), Self::Error> {
            Err("authorizer-secret-metadata")
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
    fn fixed_authorizer_requires_unique_bounded_exact_grants() {
        let reader = RollbackAnchorServiceCallerId::new("reader-a").unwrap();
        let grant = RollbackAnchorServiceAccessGrant::new(
            reader.clone(),
            RollbackAnchorServiceOperation::Load,
            key(),
        );
        let authorizer = FixedRollbackAnchorServiceAuthorizer::new([grant.clone()]).unwrap();

        assert_eq!(authorizer.caller_count(), 1);
        assert_eq!(authorizer.grant_count(), 1);
        assert!(authorizer
            .authorize(&reader, RollbackAnchorServiceOperation::Load, &key())
            .is_ok());
        assert!(authorizer
            .authorize(
                &reader,
                RollbackAnchorServiceOperation::CompareAndSwap,
                &key(),
            )
            .is_err());
        assert!(authorizer
            .authorize(
                &reader,
                RollbackAnchorServiceOperation::Load,
                &StorageRecordKey::new("workflow-ledger", "release-43").unwrap(),
            )
            .is_err());
        assert_eq!(
            FixedRollbackAnchorServiceAuthorizer::new([grant.clone(), grant.clone()]).unwrap_err(),
            FixedRollbackAnchorServiceAuthorizerError::DuplicateGrant
        );
        assert_eq!(
            FixedRollbackAnchorServiceAuthorizer::new([]).unwrap_err(),
            FixedRollbackAnchorServiceAuthorizerError::EmptyGrantSet
        );
        assert_eq!(
            RollbackAnchorServiceCallerId::new("Reader-A"),
            Err(RollbackAnchorServiceCallerIdError::Invalid)
        );
        assert!(!format!("{reader:?}").contains("reader-a"));
        assert!(!format!("{grant:?}").contains("reader-a"));
        assert!(!format!("{authorizer:?}").contains("release-42"));

        let caller_limit_grants = (0..=MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_CALLERS).map(|index| {
            RollbackAnchorServiceAccessGrant::new(
                RollbackAnchorServiceCallerId::new(format!("caller-{index}")).unwrap(),
                RollbackAnchorServiceOperation::Load,
                key(),
            )
        });
        assert_eq!(
            FixedRollbackAnchorServiceAuthorizer::new(caller_limit_grants).unwrap_err(),
            FixedRollbackAnchorServiceAuthorizerError::CallerLimitExceeded {
                maximum: MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_CALLERS,
            }
        );

        let writer = RollbackAnchorServiceCallerId::new("writer-a").unwrap();
        let grant_limit_grants = (0..=MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_GRANTS).map(|index| {
            RollbackAnchorServiceAccessGrant::new(
                writer.clone(),
                RollbackAnchorServiceOperation::CompareAndSwap,
                StorageRecordKey::new("workflow-ledger", format!("record-{index}")).unwrap(),
            )
        });
        assert_eq!(
            FixedRollbackAnchorServiceAuthorizer::new(grant_limit_grants).unwrap_err(),
            FixedRollbackAnchorServiceAuthorizerError::GrantLimitExceeded {
                maximum: MAX_FIXED_ROLLBACK_ANCHOR_SERVICE_GRANTS,
            }
        );
    }

    #[test]
    fn authorized_service_requires_an_exact_grant_before_the_backend_runs() {
        let reader = RollbackAnchorServiceCallerId::new("reader-a").unwrap();
        let other = RollbackAnchorServiceCallerId::new("reader-b").unwrap();
        let authorizer =
            FixedRollbackAnchorServiceAuthorizer::new([RollbackAnchorServiceAccessGrant::new(
                reader.clone(),
                RollbackAnchorServiceOperation::Load,
                key(),
            )])
            .unwrap();
        let mut service = AuthorizedRollbackAnchorService::new(
            RollbackAnchorService::new(CountingAnchor::default()),
            authorizer,
        );

        let load = serde_json::to_vec(&WireRequest::load(&key())).unwrap();
        assert!(service.handle_authenticated_request(&reader, &load).is_ok());

        assert_eq!(
            service
                .handle_authenticated_request(&other, &load)
                .unwrap_err(),
            AuthorizedRollbackAnchorServiceError::Unauthorized
        );
        let other_key = StorageRecordKey::new("workflow-ledger", "release-43").unwrap();
        let foreign_key_load = serde_json::to_vec(&WireRequest::load(&other_key)).unwrap();
        assert_eq!(
            service
                .handle_authenticated_request(&reader, &foreign_key_load)
                .unwrap_err(),
            AuthorizedRollbackAnchorServiceError::Unauthorized
        );
        let compare = serde_json::to_vec(&WireRequest::compare_and_swap(
            &key(),
            RollbackAnchorState::initial(),
            state(1, 7, 1),
        ))
        .unwrap();
        assert_eq!(
            service
                .handle_authenticated_request(&reader, &compare)
                .unwrap_err(),
            AuthorizedRollbackAnchorServiceError::Unauthorized
        );
        assert_eq!(
            service
                .handle_authenticated_request(&reader, b"not-json")
                .unwrap_err(),
            AuthorizedRollbackAnchorServiceError::Service(
                RollbackAnchorServiceError::InvalidRequest
            )
        );

        let (service, _) = service.into_parts();
        let anchor = service.into_inner();
        assert_eq!(anchor.load_calls.get(), 1);
        assert_eq!(anchor.compare_and_swap_calls, 0);
    }

    #[test]
    fn authorized_service_redacts_authorizer_failures_before_backend_use() {
        let mut service = AuthorizedRollbackAnchorService::new(
            RollbackAnchorService::new(CountingAnchor::default()),
            FailingAuthorizer,
        );
        assert_eq!(
            service
                .handle_authenticated_request(&(), b"not-json")
                .unwrap_err(),
            AuthorizedRollbackAnchorServiceError::Service(
                RollbackAnchorServiceError::InvalidRequest
            )
        );
        let request = serde_json::to_vec(&WireRequest::load(&key())).unwrap();
        let error = service
            .handle_authenticated_request(&(), &request)
            .unwrap_err();

        assert_eq!(error, AuthorizedRollbackAnchorServiceError::Unauthorized);
        assert!(!error.to_string().contains("authorizer-secret-metadata"));
        assert!(!format!("{error:?}").contains("authorizer-secret-metadata"));
        let (service, _) = service.into_parts();
        let anchor = service.into_inner();
        assert_eq!(anchor.load_calls.get(), 0);
        assert_eq!(anchor.compare_and_swap_calls, 0);
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
