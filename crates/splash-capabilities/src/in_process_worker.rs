//! Authenticated in-process transport for app-provided worker adapters.
//!
//! This adapter is deliberately not an OS sandbox. It is for the mobile and
//! embedded profile where a host owns a fixed trusted adapter catalog, but
//! still wants all calls to cross the authenticated worker-frame boundary.

use std::fmt::{self, Display, Formatter};

use splash_worker::{WorkerJournalStore, WorkerSession, WorkerSessionError};

use crate::{
    ProtocolError, SessionAuthenticator, SessionRole, WorkerInvocation, WorkerMessage,
    WorkerResult, WorkerTransport,
};

/// Runs one already-opened worker session in the host process while preserving
/// authenticated frame sequencing on every invocation.
///
/// Construct this only for app-provided, trusted adapters. A script still has
/// no handle to the transport, but the worker has the ambient authority of the
/// host process and is not contained from it.
pub struct InProcessAuthenticatedWorkerTransport<S> {
    host_authenticator: SessionAuthenticator,
    worker: WorkerSession,
    journal_store: S,
    poisoned: bool,
}

impl<S> InProcessAuthenticatedWorkerTransport<S> {
    /// Combines one host-role authenticator with a worker session opened from
    /// the same session ID.
    ///
    /// This checks the public session binding immediately. The first dispatch
    /// also verifies that both sides hold the same secret session key through
    /// the normal keyed frame authentication path.
    pub fn new(
        host_authenticator: SessionAuthenticator,
        worker: WorkerSession,
        journal_store: S,
    ) -> Result<Self, InProcessAuthenticatedWorkerTransportInitError> {
        if host_authenticator.role() != SessionRole::Host {
            return Err(InProcessAuthenticatedWorkerTransportInitError::RequiresHostAuthenticator);
        }
        let worker_session_id = worker.manifest().session_id.clone();
        if host_authenticator.session_id() != worker_session_id {
            return Err(
                InProcessAuthenticatedWorkerTransportInitError::SessionMismatch {
                    host: host_authenticator.session_id().to_owned(),
                    worker: worker_session_id,
                },
            );
        }
        Ok(Self {
            host_authenticator,
            worker,
            journal_store,
            poisoned: false,
        })
    }

    /// Returns the worker session for trusted host inspection.
    ///
    /// Its journal can retain terminal result data, so callers must not expose
    /// it to Splash source or untrusted logs.
    pub fn worker(&self) -> &WorkerSession {
        &self.worker
    }

    /// Returns the host-owned journal store.
    pub fn journal_store(&self) -> &S {
        &self.journal_store
    }

    /// Returns whether a host-side validation failure discarded this session.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Consumes the transport and returns its host-owned components.
    pub fn into_parts(self) -> (SessionAuthenticator, WorkerSession, S) {
        (self.host_authenticator, self.worker, self.journal_store)
    }
}

impl<S> WorkerTransport for InProcessAuthenticatedWorkerTransport<S>
where
    S: WorkerJournalStore,
    S::Error: Display,
{
    type Error = InProcessAuthenticatedWorkerTransportError<S::Error>;

    fn dispatch(&mut self, invocation: WorkerInvocation) -> Result<WorkerResult, Self::Error> {
        if self.poisoned {
            return Err(InProcessAuthenticatedWorkerTransportError::Poisoned);
        }
        let request = self
            .host_authenticator
            .seal(WorkerMessage::Invoke { invocation })
            .map_err(InProcessAuthenticatedWorkerTransportError::Protocol)?;
        let response = self
            .worker
            .handle(request, &mut self.journal_store)
            .map_err(InProcessAuthenticatedWorkerTransportError::Worker)?;
        let message = self
            .host_authenticator
            .open(response)
            .map_err(InProcessAuthenticatedWorkerTransportError::Protocol)?;
        match message {
            WorkerMessage::Result { result } => Ok(result),
            _ => Err(InProcessAuthenticatedWorkerTransportError::UnexpectedResponse),
        }
    }

    fn discard(&mut self) {
        self.poisoned = true;
    }
}

/// Rejection while wiring the in-process transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InProcessAuthenticatedWorkerTransportInitError {
    RequiresHostAuthenticator,
    SessionMismatch { host: String, worker: String },
}

impl Display for InProcessAuthenticatedWorkerTransportInitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiresHostAuthenticator => formatter
                .write_str("in-process worker transport requires a host-role authenticator"),
            Self::SessionMismatch { host, worker } => write!(
                formatter,
                "in-process worker transport session mismatch: host {host}, worker {worker}"
            ),
        }
    }
}

impl std::error::Error for InProcessAuthenticatedWorkerTransportInitError {}

/// Failure while dispatching one invocation through an in-process worker.
///
/// Worker-side failures are intentionally rendered generically. Hosts that
/// dispatch this transport directly can inspect the `Worker` variant, while a
/// `ProtocolWorkerClient` maps every transport error to one generic Splash
/// tool failure without exposing adapter or persistence context.
#[derive(Debug)]
pub enum InProcessAuthenticatedWorkerTransportError<E> {
    Protocol(ProtocolError),
    Worker(WorkerSessionError<E>),
    UnexpectedResponse,
    Poisoned,
}

impl<E: Display> Display for InProcessAuthenticatedWorkerTransportError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(
                formatter,
                "authenticated in-process worker protocol failure: {error}"
            ),
            Self::Worker(_) => formatter.write_str("in-process worker rejected the invocation"),
            Self::UnexpectedResponse => {
                formatter.write_str("in-process worker returned an unexpected response")
            }
            Self::Poisoned => formatter.write_str("in-process worker transport is poisoned"),
        }
    }
}

impl<E> std::error::Error for InProcessAuthenticatedWorkerTransportError<E> where
    E: std::error::Error + 'static
{
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::convert::Infallible;
    use std::rc::Rc;

    use splash_protocol::{
        CapabilityGrant, CapabilityManifest, SessionKey, ToolPayload, WorkerOperationJournal,
        AUTH_TAG_BYTES,
    };
    use splash_worker::{
        WorkerAdapter, WorkerAdapterError, WorkerAdapterRegistry, WorkerInvocationSafety,
        WorkerJournalLease, WorkerJournalRevision, WorkerSessionAdmission, WorkerSessionLimits,
    };

    use super::*;
    use crate::{CapabilityRuntime, JsonToolRequest, ProtocolWorkerClient, ToolError, ToolPolicy};

    #[derive(Default)]
    struct NoopJournalStore;

    impl WorkerJournalStore for NoopJournalStore {
        type Error = Infallible;

        fn persist(
            &mut self,
            _journal: &WorkerOperationJournal,
            _expected_revision: WorkerJournalRevision,
            _journal_lease: WorkerJournalLease,
        ) -> Result<WorkerJournalRevision, Self::Error> {
            unreachable!("non-durable invoke does not persist the worker journal")
        }
    }

    struct FixedAdmission;

    impl WorkerSessionAdmission for FixedAdmission {
        type Error = Infallible;

        fn admit(
            &mut self,
            _manifest: &CapabilityManifest,
            _journal_scope: &str,
        ) -> Result<u64, Self::Error> {
            Ok(1)
        }
    }

    struct AddAdapter {
        calls: Rc<RefCell<usize>>,
    }

    impl WorkerAdapter for AddAdapter {
        fn invocation_safety(&self) -> Option<WorkerInvocationSafety> {
            Some(WorkerInvocationSafety::ReadOnly)
        }

        fn invoke(
            &mut self,
            request: &WorkerInvocation,
            _grant: &splash_protocol::CapabilityGrant,
        ) -> Result<ToolPayload, WorkerAdapterError> {
            let ToolPayload::Json(input) = &request.payload else {
                return Err(WorkerAdapterError::Unsupported("text invoke"));
            };
            let left = input["left"]
                .as_i64()
                .ok_or(WorkerAdapterError::Unsupported("left input"))?;
            let right = input["right"]
                .as_i64()
                .ok_or(WorkerAdapterError::Unsupported("right input"))?;
            *self.calls.borrow_mut() += 1;
            Ok(ToolPayload::Json(serde_json::json!({
                "total": left + right
            })))
        }
    }

    fn open_worker(
        manifest: &CapabilityManifest,
        host_authenticator: &mut SessionAuthenticator,
        worker_authenticator: SessionAuthenticator,
        calls: Rc<RefCell<usize>>,
    ) -> WorkerSession {
        let opening = host_authenticator
            .seal(WorkerMessage::OpenSession {
                manifest: manifest.clone(),
            })
            .unwrap();
        let mut adapters = WorkerAdapterRegistry::default();
        adapters.register("math.add", AddAdapter { calls }).unwrap();
        WorkerSession::open(
            worker_authenticator,
            opening,
            WorkerOperationJournal::new("tenant-release").unwrap(),
            WorkerJournalRevision::default(),
            adapters,
            WorkerSessionLimits::default(),
            &mut FixedAdmission,
        )
        .unwrap()
    }

    fn manifest() -> CapabilityManifest {
        CapabilityManifest::new("worker-1", vec![CapabilityGrant::json("math.add")]).unwrap()
    }

    #[test]
    fn dispatches_a_protocol_worker_tool_through_authenticated_in_process_frames() {
        let manifest = manifest();
        let key = SessionKey::from_bytes([7; AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let worker_authenticator =
            SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();
        let calls = Rc::new(RefCell::new(0));
        let worker = open_worker(&manifest, &mut host, worker_authenticator, calls.clone());
        let transport =
            InProcessAuthenticatedWorkerTransport::new(host, worker, NoopJournalStore).unwrap();
        let client = Rc::new(RefCell::new(
            ProtocolWorkerClient::new(manifest, transport).unwrap(),
        ));
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_protocol_json_tool(ToolPolicy::json("math.add"), client)
            .unwrap();

        let report = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.call_json(\"math.add\", {left: 20, right: 22})\nlet response = raw.parse_json()\nassert(response.total == 42)",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(*calls.borrow(), 1);
    }

    #[test]
    fn rejects_a_non_host_authenticator_before_dispatch() {
        let manifest = manifest();
        let key = SessionKey::from_bytes([8; AUTH_TAG_BYTES]).unwrap();
        let mut opening_host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let worker_authenticator =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Worker).unwrap();
        let worker = open_worker(
            &manifest,
            &mut opening_host,
            worker_authenticator,
            Rc::new(RefCell::new(0)),
        );
        let non_host = SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();

        assert!(matches!(
            InProcessAuthenticatedWorkerTransport::new(non_host, worker, NoopJournalStore),
            Err(InProcessAuthenticatedWorkerTransportInitError::RequiresHostAuthenticator)
        ));
    }

    #[test]
    fn rejects_a_host_for_a_different_public_session_before_dispatch() {
        let manifest = manifest();
        let key = SessionKey::from_bytes([9; AUTH_TAG_BYTES]).unwrap();
        let mut opening_host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let worker_authenticator =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Worker).unwrap();
        let worker = open_worker(
            &manifest,
            &mut opening_host,
            worker_authenticator,
            Rc::new(RefCell::new(0)),
        );
        let other_session_host =
            SessionAuthenticator::new("worker-2", key, SessionRole::Host).unwrap();

        assert!(matches!(
            InProcessAuthenticatedWorkerTransport::new(
                other_session_host,
                worker,
                NoopJournalStore
            ),
            Err(InProcessAuthenticatedWorkerTransportInitError::SessionMismatch { host, worker })
                if host == "worker-2" && worker == "worker-1"
        ));
    }

    #[test]
    fn rejects_a_host_with_the_wrong_session_key_during_framed_dispatch() {
        let manifest = manifest();
        let worker_key = SessionKey::from_bytes([9; AUTH_TAG_BYTES]).unwrap();
        let mut opening_host =
            SessionAuthenticator::new("worker-1", worker_key.clone(), SessionRole::Host).unwrap();
        let worker_authenticator =
            SessionAuthenticator::new("worker-1", worker_key, SessionRole::Worker).unwrap();
        let worker = open_worker(
            &manifest,
            &mut opening_host,
            worker_authenticator,
            Rc::new(RefCell::new(0)),
        );
        let wrong_host = SessionAuthenticator::new(
            "worker-1",
            SessionKey::from_bytes([10; AUTH_TAG_BYTES]).unwrap(),
            SessionRole::Host,
        )
        .unwrap();
        let mut transport =
            InProcessAuthenticatedWorkerTransport::new(wrong_host, worker, NoopJournalStore)
                .unwrap();
        let invocation = WorkerInvocation::new(
            "worker-1",
            "request-1",
            "math.add",
            ToolPayload::Json(serde_json::json!({"left": 20, "right": 22})),
        )
        .unwrap();

        assert!(matches!(
            transport.dispatch(invocation),
            Err(InProcessAuthenticatedWorkerTransportError::Worker(
                WorkerSessionError::Protocol(ProtocolError::InvalidAuthenticationTag)
            ))
        ));
    }

    #[test]
    fn hides_worker_authentication_details_from_protocol_tool_errors() {
        let manifest = manifest();
        let worker_key = SessionKey::from_bytes([11; AUTH_TAG_BYTES]).unwrap();
        let mut opening_host =
            SessionAuthenticator::new("worker-1", worker_key.clone(), SessionRole::Host).unwrap();
        let worker_authenticator =
            SessionAuthenticator::new("worker-1", worker_key, SessionRole::Worker).unwrap();
        let worker = open_worker(
            &manifest,
            &mut opening_host,
            worker_authenticator,
            Rc::new(RefCell::new(0)),
        );
        let wrong_host = SessionAuthenticator::new(
            "worker-1",
            SessionKey::from_bytes([12; AUTH_TAG_BYTES]).unwrap(),
            SessionRole::Host,
        )
        .unwrap();
        let transport =
            InProcessAuthenticatedWorkerTransport::new(wrong_host, worker, NoopJournalStore)
                .unwrap();
        let mut client = ProtocolWorkerClient::new(manifest, transport).unwrap();

        let error = client
            .dispatch_json(&JsonToolRequest {
                name: "math.add".to_owned(),
                input: serde_json::json!({"left": 20, "right": 22}),
                call_index: 1,
            })
            .unwrap_err();

        assert!(matches!(
            &error,
            ToolError::Failed(message)
                if message == "worker transport failed"
        ));
        assert!(!error.to_string().contains("authentication"));
    }
}
