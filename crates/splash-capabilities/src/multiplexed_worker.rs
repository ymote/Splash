//! Concurrent authenticated host transport for cancellable worker calls.
//!
//! One coordinator owns the outgoing authenticator and writer. A demand-driven
//! reader owns the incoming stream and never authenticates or dispatches by
//! itself. This preserves one ordered sequence in each direction while allowing
//! a trusted host event loop to send `cancel` during an active adapter call.

use std::fmt::{self, Display, Formatter};
use std::io::{self, BufRead, Write};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};

use splash_protocol::{
    AuthorizedInvocation, AuthorizedWorkerCancellation, SessionFrameOpener, SessionFrameSealer,
};

use crate::bounded_worker::{
    SessionBoundWorkerExecutionSupervisor, WorkerIndeterminateCause, WorkerInvocationDeadline,
    WorkerInvocationOutcome,
};
use crate::json_line_worker::{read_json_line, JsonLineWorkerChannelError};
use crate::{
    AuthenticatedWorkerMessage, CapabilityManifest, CapabilityRuntime,
    ExternalToolCancellationRequest, ExternalToolError, ExternalToolId, ExternalToolInvocation,
    ProtocolError, SessionAuthenticator, SessionAuthorizer, SessionRole, WorkerCancellationOutcome,
    WorkerCancellationRequest, WorkerCancellationResult, WorkerInvocation, WorkerMessage,
    WorkerPayload, WorkerResult,
};

/// Host-owned authenticated JSON-line session with one active ordinary call.
///
/// The type is `Send` but not cloneable. Pending invocation handles retain only
/// a command sender and their own bounded one-shot receivers. The host must
/// still couple this transport to a process/session deadline: an unsupported or
/// unacknowledged cancellation is not permission to report `cancelled`.
pub struct MultiplexedAuthenticatedWorkerTransport {
    session_id: String,
    events: Sender<HostEvent>,
    join: Option<JoinHandle<()>>,
    closed: bool,
}

impl MultiplexedAuthenticatedWorkerTransport {
    /// Sends the authenticated opening frame and starts the directional I/O
    /// owners.
    pub fn new<R, W>(
        manifest: CapabilityManifest,
        authenticator: SessionAuthenticator,
        reader: R,
        mut writer: W,
    ) -> Result<Self, MultiplexedWorkerError>
    where
        R: BufRead + Send + 'static,
        W: Write + Send + 'static,
    {
        manifest
            .validate()
            .map_err(MultiplexedWorkerError::Protocol)?;
        if authenticator.role() != SessionRole::Host {
            return Err(MultiplexedWorkerError::RequiresHostAuthenticator);
        }
        if authenticator.session_id() != manifest.session_id {
            return Err(MultiplexedWorkerError::SessionMismatch {
                authenticator: authenticator.session_id().to_owned(),
                manifest: manifest.session_id,
            });
        }
        let session_id = manifest.session_id.clone();
        let authorizer =
            SessionAuthorizer::new(manifest.clone()).map_err(MultiplexedWorkerError::Protocol)?;
        let (mut sealer, opener) = authenticator.into_directional();
        send_frame(
            &mut sealer,
            &mut writer,
            WorkerMessage::OpenSession { manifest },
        )?;

        let (events, event_receiver) = mpsc::channel();
        let (ready_sender, ready_receiver) = mpsc::channel();
        let coordinator_events = events.clone();
        let join = thread::Builder::new()
            .name("splash-host-worker-multiplexer".to_owned())
            .spawn(move || {
                run_coordinator(
                    authorizer,
                    sealer,
                    opener,
                    reader,
                    writer,
                    event_receiver,
                    coordinator_events,
                    ready_sender,
                );
            })
            .map_err(MultiplexedWorkerError::from_io)?;
        ready_receiver
            .recv()
            .map_err(|_| MultiplexedWorkerError::Unavailable)??;

        Ok(Self {
            session_id,
            events,
            join: Some(join),
            closed: false,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Starts one ordinary invocation after host-side capability authorization.
    pub fn start(
        &self,
        invocation: WorkerInvocation,
    ) -> Result<PendingWorkerInvocation, MultiplexedWorkerError> {
        let request_id = invocation.request_id.clone();
        let tool = invocation.tool.clone();
        let (result_sender, result_receiver) = mpsc::channel();
        let (accepted_sender, accepted_receiver) = mpsc::channel();
        self.events
            .send(HostEvent::Command(HostCommand::Start {
                invocation,
                result: result_sender,
                accepted: accepted_sender,
            }))
            .map_err(|_| MultiplexedWorkerError::Unavailable)?;
        accepted_receiver
            .recv()
            .map_err(|_| MultiplexedWorkerError::Unavailable)??;
        Ok(PendingWorkerInvocation {
            request_id,
            tool,
            events: self.events.clone(),
            result: result_receiver,
        })
    }

    /// Closes an idle session and waits for the worker output stream to end.
    pub fn close(mut self) -> Result<(), MultiplexedWorkerError> {
        let (reply, response) = mpsc::channel();
        self.events
            .send(HostEvent::Command(HostCommand::Close { reply }))
            .map_err(|_| MultiplexedWorkerError::Unavailable)?;
        let result = response
            .recv()
            .map_err(|_| MultiplexedWorkerError::Unavailable)?;
        self.closed = result.is_ok();
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| MultiplexedWorkerError::CoordinatorPanicked)?;
        }
        result
    }
}

impl Drop for MultiplexedAuthenticatedWorkerTransport {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.events.send(HostEvent::Command(HostCommand::Abandon));
        }
    }
}

/// One active authenticated worker invocation.
pub struct PendingWorkerInvocation {
    request_id: String,
    tool: String,
    events: Sender<HostEvent>,
    result: Receiver<Result<MultiplexedWorkerInvocationOutcome, MultiplexedWorkerError>>,
}

impl PendingWorkerInvocation {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Sends one authenticated cancellation request for this exact invocation.
    pub fn request_cancellation(
        &self,
        cancellation_id: impl Into<String>,
    ) -> Result<PendingWorkerCancellation, MultiplexedWorkerError> {
        let cancellation_id = cancellation_id.into();
        let (result_sender, result_receiver) = mpsc::channel();
        let (accepted_sender, accepted_receiver) = mpsc::channel();
        self.events
            .send(HostEvent::Command(HostCommand::Cancel {
                cancellation_id: cancellation_id.clone(),
                request_id: self.request_id.clone(),
                tool: self.tool.clone(),
                result: result_sender,
                accepted: accepted_sender,
            }))
            .map_err(|_| MultiplexedWorkerError::Unavailable)?;
        accepted_receiver
            .recv()
            .map_err(|_| MultiplexedWorkerError::Unavailable)??;
        Ok(PendingWorkerCancellation {
            cancellation_id,
            result: result_receiver,
        })
    }

    pub fn wait(self) -> Result<MultiplexedWorkerInvocationOutcome, MultiplexedWorkerError> {
        self.result
            .recv()
            .map_err(|_| MultiplexedWorkerError::Unavailable)?
    }

    pub fn try_wait(
        &self,
    ) -> Result<Option<MultiplexedWorkerInvocationOutcome>, MultiplexedWorkerError> {
        match self.result.try_recv() {
            Ok(result) => result.map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(MultiplexedWorkerError::Unavailable),
        }
    }
}

impl fmt::Debug for PendingWorkerInvocation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingWorkerInvocation")
            .field("request_id", &self.request_id)
            .field("tool", &self.tool)
            .finish_non_exhaustive()
    }
}

/// Pending authenticated worker disposition for one cancellation request.
pub struct PendingWorkerCancellation {
    cancellation_id: String,
    result: Receiver<Result<WorkerCancellationResult, MultiplexedWorkerError>>,
}

impl PendingWorkerCancellation {
    pub fn cancellation_id(&self) -> &str {
        &self.cancellation_id
    }

    pub fn wait(self) -> Result<WorkerCancellationResult, MultiplexedWorkerError> {
        self.result
            .recv()
            .map_err(|_| MultiplexedWorkerError::Unavailable)?
    }

    pub fn try_wait(&self) -> Result<Option<WorkerCancellationResult>, MultiplexedWorkerError> {
        match self.result.try_recv() {
            Ok(result) => result.map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(MultiplexedWorkerError::Unavailable),
        }
    }
}

impl fmt::Debug for PendingWorkerCancellation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingWorkerCancellation")
            .field("cancellation_id", &self.cancellation_id)
            .finish_non_exhaustive()
    }
}

/// Terminal host observation for one multiplexed ordinary invocation.
#[derive(Clone, Debug, PartialEq)]
pub enum MultiplexedWorkerInvocationOutcome {
    Completed(WorkerResult),
    /// Contains an authenticated positive cancellation acknowledgement.
    Cancelled(WorkerCancellationResult),
}

/// Binding between one claimed Splash external tool and one authenticated
/// multiplexed worker invocation.
///
/// This host-only object retains the opaque runtime identity locally. Neither
/// `ExternalToolId` nor the external input is serialized into cancellation
/// frames. Call [`CapabilityRuntime::request_external_tool_cancellation`] first,
/// then pass the returned identity to [`Self::request_cancellation`].
pub struct ExternalToolWorkerBinding {
    id: ExternalToolId,
    name: String,
    call_index: usize,
    attempt: u32,
    idempotency_key: String,
    pending: PendingWorkerInvocation,
    cancellation: Option<PendingWorkerCancellation>,
    cancellation_requested: bool,
    terminal: bool,
}

struct PreparedExternalToolWorkerBinding {
    id: ExternalToolId,
    name: String,
    call_index: usize,
    attempt: u32,
    idempotency_key: String,
    worker: WorkerInvocation,
}

impl ExternalToolWorkerBinding {
    pub fn start(
        transport: &MultiplexedAuthenticatedWorkerTransport,
        invocation: &ExternalToolInvocation,
        request_id: impl Into<String>,
    ) -> Result<Self, ExternalToolWorkerBridgeError> {
        Self::prepare(transport.session_id(), invocation, request_id)?
            .dispatch(transport)
            .map_err(ExternalToolWorkerBridgeError::Transport)
    }

    fn prepare(
        session_id: &str,
        invocation: &ExternalToolInvocation,
        request_id: impl Into<String>,
    ) -> Result<PreparedExternalToolWorkerBinding, ExternalToolWorkerBridgeError> {
        let worker = WorkerInvocation::new(
            session_id,
            request_id,
            invocation.name.clone(),
            invocation
                .worker_payload()
                .map_err(ExternalToolWorkerBridgeError::External)?,
        )
        .map_err(ExternalToolWorkerBridgeError::Protocol)?;
        Ok(PreparedExternalToolWorkerBinding {
            id: invocation.id,
            name: invocation.name.clone(),
            call_index: invocation.call_index,
            attempt: invocation.attempt,
            idempotency_key: invocation.idempotency_key.clone(),
            worker,
        })
    }

    pub fn external_id(&self) -> ExternalToolId {
        self.id
    }

    /// Sends cancellation only when the runtime's current two-phase request
    /// exactly matches the originally dispatched external invocation.
    pub fn request_cancellation(
        &mut self,
        request: &ExternalToolCancellationRequest,
        cancellation_id: impl Into<String>,
    ) -> Result<(), ExternalToolWorkerBridgeError> {
        if self.terminal {
            return Err(ExternalToolWorkerBridgeError::AlreadyTerminal);
        }
        if request.id != self.id
            || request.name != self.name
            || request.call_index != self.call_index
            || request.attempt != self.attempt
            || request.idempotency_key != self.idempotency_key
        {
            return Err(ExternalToolWorkerBridgeError::CancellationBindingMismatch);
        }
        if self.cancellation_requested {
            return Err(ExternalToolWorkerBridgeError::CancellationAlreadyRequested);
        }
        self.cancellation = Some(
            self.pending
                .request_cancellation(cancellation_id)
                .map_err(ExternalToolWorkerBridgeError::Transport)?,
        );
        self.cancellation_requested = true;
        Ok(())
    }

    /// Applies at most one ready worker outcome to the single-threaded runtime.
    ///
    /// Invocation completion is polled before its cancellation disposition so a
    /// result-wins race resolves through the ordinary output contract. Only an
    /// authenticated positive acknowledgement calls
    /// [`CapabilityRuntime::confirm_external_tool_cancellation`].
    pub fn poll(
        &mut self,
        runtime: &mut CapabilityRuntime,
    ) -> Result<ExternalToolWorkerPoll, ExternalToolWorkerBridgeError> {
        self.poll_event()?.apply_to_runtime(runtime)
    }

    /// Returns one authenticated worker event without applying it to a
    /// particular host runtime.
    ///
    /// Workflow hosts should use this form and apply terminal events through
    /// `WorkflowEngine`, preserving its suspended-step state machine.
    pub fn poll_event(&mut self) -> Result<ExternalToolWorkerEvent, ExternalToolWorkerBridgeError> {
        let observation = self
            .poll_observation()
            .map_err(ExternalToolWorkerBridgeError::Transport)?;
        self.event_from_observation(observation)
    }

    fn poll_observation(
        &mut self,
    ) -> Result<ExternalToolWorkerObservation, MultiplexedWorkerError> {
        if self.terminal {
            return Err(MultiplexedWorkerError::ExternalBindingTerminal);
        }
        if let Some(outcome) = self.pending.try_wait()? {
            return Ok(ExternalToolWorkerObservation::Terminal(outcome));
        }
        if let Some(cancellation) = self.cancellation.as_ref() {
            if let Some(result) = cancellation.try_wait()? {
                self.cancellation = None;
                return match result.outcome {
                    WorkerCancellationOutcome::Acknowledged => {
                        Ok(ExternalToolWorkerObservation::Terminal(
                            MultiplexedWorkerInvocationOutcome::Cancelled(result),
                        ))
                    }
                    WorkerCancellationOutcome::TooLate => {
                        Ok(ExternalToolWorkerObservation::CancellationTooLate)
                    }
                    WorkerCancellationOutcome::Unsupported => {
                        Ok(ExternalToolWorkerObservation::CancellationUnsupported)
                    }
                };
            }
        }
        Ok(ExternalToolWorkerObservation::Pending)
    }

    fn event_from_observation(
        &mut self,
        observation: ExternalToolWorkerObservation,
    ) -> Result<ExternalToolWorkerEvent, ExternalToolWorkerBridgeError> {
        match observation {
            ExternalToolWorkerObservation::Pending => Ok(ExternalToolWorkerEvent::Pending),
            ExternalToolWorkerObservation::CancellationTooLate => {
                Ok(ExternalToolWorkerEvent::CancellationTooLate)
            }
            ExternalToolWorkerObservation::CancellationUnsupported => {
                Ok(ExternalToolWorkerEvent::CancellationUnsupported)
            }
            ExternalToolWorkerObservation::Terminal(outcome) => {
                self.event_from_invocation_outcome(outcome)
            }
        }
    }

    fn event_from_invocation_outcome(
        &mut self,
        outcome: MultiplexedWorkerInvocationOutcome,
    ) -> Result<ExternalToolWorkerEvent, ExternalToolWorkerBridgeError> {
        self.terminal = true;
        match outcome {
            MultiplexedWorkerInvocationOutcome::Completed(result) => {
                let output = match result.payload {
                    WorkerPayload::Text(output) => output,
                    WorkerPayload::Json(output) => {
                        serde_json::to_string(&output).map_err(|error| {
                            ExternalToolWorkerBridgeError::Serialization(error.to_string())
                        })?
                    }
                };
                Ok(ExternalToolWorkerEvent::Completed {
                    external_id: self.id,
                    output,
                })
            }
            MultiplexedWorkerInvocationOutcome::Cancelled(result) => {
                if result.outcome != WorkerCancellationOutcome::Acknowledged {
                    return Err(ExternalToolWorkerBridgeError::InvalidCancelledOutcome);
                }
                Ok(ExternalToolWorkerEvent::Cancelled {
                    external_id: self.id,
                    acknowledgement: result,
                })
            }
        }
    }
}

impl PreparedExternalToolWorkerBinding {
    fn external_id(&self) -> ExternalToolId {
        self.id
    }

    fn dispatch(
        self,
        transport: &MultiplexedAuthenticatedWorkerTransport,
    ) -> Result<ExternalToolWorkerBinding, MultiplexedWorkerError> {
        let pending = transport.start(self.worker)?;
        Ok(ExternalToolWorkerBinding {
            id: self.id,
            name: self.name,
            call_index: self.call_index,
            attempt: self.attempt,
            idempotency_key: self.idempotency_key,
            pending,
            cancellation: None,
            cancellation_requested: false,
            terminal: false,
        })
    }
}

enum ExternalToolWorkerObservation {
    Pending,
    CancellationTooLate,
    CancellationUnsupported,
    Terminal(MultiplexedWorkerInvocationOutcome),
}

impl fmt::Debug for ExternalToolWorkerBinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExternalToolWorkerBinding")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("call_index", &self.call_index)
            .field("attempt", &self.attempt)
            .field("idempotency_key", &"[redacted]")
            .field("cancellation_requested", &self.cancellation_requested)
            .field("terminal", &self.terminal)
            .finish_non_exhaustive()
    }
}

/// One nonblocking event-loop observation from an external worker binding.
#[derive(Debug)]
pub enum ExternalToolWorkerEvent {
    Pending,
    CancellationTooLate,
    CancellationUnsupported,
    Completed {
        external_id: ExternalToolId,
        output: String,
    },
    Cancelled {
        external_id: ExternalToolId,
        acknowledgement: WorkerCancellationResult,
    },
}

impl ExternalToolWorkerEvent {
    /// Applies this event through the standalone capability-runtime lifecycle.
    pub fn apply_to_runtime(
        self,
        runtime: &mut CapabilityRuntime,
    ) -> Result<ExternalToolWorkerPoll, ExternalToolWorkerBridgeError> {
        match self {
            Self::Pending => Ok(ExternalToolWorkerPoll::Pending),
            Self::CancellationTooLate => Ok(ExternalToolWorkerPoll::CancellationTooLate),
            Self::CancellationUnsupported => Ok(ExternalToolWorkerPoll::CancellationUnsupported),
            Self::Completed {
                external_id,
                output,
            } => runtime
                .complete_external_tool(external_id, Ok(output))
                .map(ExternalToolWorkerPoll::Completed)
                .map_err(ExternalToolWorkerBridgeError::External),
            Self::Cancelled {
                external_id,
                acknowledgement,
            } => {
                if acknowledgement.outcome != WorkerCancellationOutcome::Acknowledged {
                    return Err(ExternalToolWorkerBridgeError::InvalidCancelledOutcome);
                }
                runtime
                    .confirm_external_tool_cancellation(external_id)
                    .map(ExternalToolWorkerPoll::Cancelled)
                    .map_err(ExternalToolWorkerBridgeError::External)
            }
        }
    }
}

/// One nonblocking event after applying it to a standalone capability runtime.
#[derive(Debug)]
pub enum ExternalToolWorkerPoll {
    Pending,
    CancellationTooLate,
    CancellationUnsupported,
    Completed(Option<splash_core::Evaluation>),
    Cancelled(Option<splash_core::Evaluation>),
}

/// Failure while binding a claimed external operation to the multiplexed
/// worker transport.
#[derive(Debug)]
pub enum ExternalToolWorkerBridgeError {
    External(ExternalToolError),
    Protocol(ProtocolError),
    Transport(MultiplexedWorkerError),
    CancellationBindingMismatch,
    CancellationAlreadyRequested,
    InvalidCancelledOutcome,
    Serialization(String),
    AlreadyTerminal,
}

impl Display for ExternalToolWorkerBridgeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::External(error) => write!(formatter, "external tool lifecycle failed: {error}"),
            Self::Protocol(error) => {
                write!(formatter, "external worker request is invalid: {error}")
            }
            Self::Transport(error) => {
                write!(formatter, "external worker transport failed: {error}")
            }
            Self::CancellationBindingMismatch => formatter
                .write_str("external cancellation does not match its dispatched invocation"),
            Self::CancellationAlreadyRequested => {
                formatter.write_str("external worker cancellation was already requested")
            }
            Self::InvalidCancelledOutcome => {
                formatter.write_str("external worker returned a non-acknowledged cancelled outcome")
            }
            Self::Serialization(_) => {
                formatter.write_str("external worker JSON result could not be serialized")
            }
            Self::AlreadyTerminal => {
                formatter.write_str("external worker binding is already terminal")
            }
        }
    }
}

impl std::error::Error for ExternalToolWorkerBridgeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::External(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::CancellationBindingMismatch
            | Self::CancellationAlreadyRequested
            | Self::InvalidCancelledOutcome
            | Self::Serialization(_)
            | Self::AlreadyTerminal => None,
        }
    }
}

/// One authenticated external-tool call coupled to a session-bound process
/// supervisor.
///
/// The wrapper arms the host deadline before it writes `invoke` and disarms it
/// before applying a result or positive cancellation acknowledgement to the
/// Splash runtime. A process deadline or force-stop always leaves that runtime
/// operation pending for reconciliation; it never confirms cancellation.
pub struct SupervisedMultiplexedWorkerSession<S>
where
    S: SessionBoundWorkerExecutionSupervisor,
{
    transport: MultiplexedAuthenticatedWorkerTransport,
    supervisor: S,
    deadline: WorkerInvocationDeadline,
    active: Option<SupervisedExternalToolInvocation<S::Invocation>>,
    poisoned: bool,
}

struct SupervisedExternalToolInvocation<I> {
    binding: ExternalToolWorkerBinding,
    supervision: I,
}

impl<S> SupervisedMultiplexedWorkerSession<S>
where
    S: SessionBoundWorkerExecutionSupervisor,
{
    /// Binds an authenticated transport to the lifecycle supervisor for the
    /// exact same worker session.
    pub fn new(
        transport: MultiplexedAuthenticatedWorkerTransport,
        supervisor: S,
        deadline: WorkerInvocationDeadline,
    ) -> Result<Self, SupervisedMultiplexedWorkerInitError> {
        if transport.session_id() != supervisor.session_id() {
            return Err(SupervisedMultiplexedWorkerInitError {
                transport_session: transport.session_id().to_owned(),
                supervisor_session: supervisor.session_id().to_owned(),
            });
        }
        Ok(Self {
            transport,
            supervisor,
            deadline,
            active: None,
            poisoned: false,
        })
    }

    pub fn session_id(&self) -> &str {
        self.transport.session_id()
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub const fn has_active_invocation(&self) -> bool {
        self.active.is_some()
    }

    pub fn active_external_id(&self) -> Option<ExternalToolId> {
        self.active
            .as_ref()
            .map(|active| active.binding.external_id())
    }

    /// Gracefully closes an idle healthy protocol session and returns the
    /// supervisor so the host can reap the exited process and retain its audit
    /// observation. Calling this while active or poisoned discards the session.
    pub fn close(self) -> Result<S, SupervisedMultiplexedWorkerError<S::Error, S::Termination>> {
        if self.active.is_some() {
            return Err(SupervisedMultiplexedWorkerError::Busy);
        }
        if self.poisoned {
            return Err(SupervisedMultiplexedWorkerError::Poisoned);
        }
        let Self {
            transport,
            mut supervisor,
            ..
        } = self;
        match transport.close() {
            Ok(()) => Ok(supervisor),
            Err(source) => {
                let termination = supervisor.terminate();
                Err(SupervisedMultiplexedWorkerError::Transport {
                    source,
                    termination,
                })
            }
        }
    }

    /// Arms supervision and dispatches one already-claimed external tool.
    pub fn start_external_tool(
        &mut self,
        invocation: &ExternalToolInvocation,
        request_id: impl Into<String>,
    ) -> Result<(), SupervisedMultiplexedWorkerError<S::Error, S::Termination>> {
        self.require_available()?;
        if self.active.is_some() {
            return Err(SupervisedMultiplexedWorkerError::Busy);
        }

        let prepared =
            ExternalToolWorkerBinding::prepare(self.transport.session_id(), invocation, request_id)
                .map_err(SupervisedMultiplexedWorkerError::Bridge)?;
        let external_id = prepared.external_id();
        let supervision = match self.supervisor.begin_invocation(self.deadline) {
            Ok(supervision) => supervision,
            Err(source) => {
                self.poisoned = true;
                let termination = self.supervisor.terminate();
                return Err(SupervisedMultiplexedWorkerError::Supervisor {
                    source,
                    termination,
                });
            }
        };
        match prepared.dispatch(&self.transport) {
            Ok(binding) => {
                self.active = Some(SupervisedExternalToolInvocation {
                    binding,
                    supervision,
                });
                Ok(())
            }
            Err(source) => self.fail_transport(external_id, supervision, source),
        }
    }

    /// Sends the exact two-phase cancellation identity issued by the runtime.
    pub fn request_external_tool_cancellation(
        &mut self,
        request: &ExternalToolCancellationRequest,
        cancellation_id: impl Into<String>,
    ) -> Result<(), SupervisedMultiplexedWorkerError<S::Error, S::Termination>> {
        self.require_available()?;
        let result = self
            .active
            .as_mut()
            .ok_or(SupervisedMultiplexedWorkerError::NoActiveInvocation)?
            .binding
            .request_cancellation(request, cancellation_id);
        match result {
            Ok(()) => Ok(()),
            Err(ExternalToolWorkerBridgeError::Transport(source)) => {
                let active = self
                    .active
                    .take()
                    .ok_or(SupervisedMultiplexedWorkerError::NoActiveInvocation)?;
                self.fail_transport(active.binding.external_id(), active.supervision, source)
            }
            Err(source) => Err(SupervisedMultiplexedWorkerError::Bridge(source)),
        }
    }

    /// Applies at most one ready event to a standalone capability runtime after
    /// resolving the watchdog race.
    pub fn poll_external_tool(
        &mut self,
        runtime: &mut CapabilityRuntime,
    ) -> SupervisedMultiplexedWorkerResult<
        SupervisedExternalToolWorkerPoll<S::Termination>,
        S::Error,
        S::Termination,
    > {
        match self.poll_external_tool_event()? {
            SupervisedExternalToolWorkerEvent::Worker(event) => event
                .apply_to_runtime(runtime)
                .map(SupervisedExternalToolWorkerPoll::Worker)
                .map_err(SupervisedMultiplexedWorkerError::Bridge),
            SupervisedExternalToolWorkerEvent::Indeterminate {
                external_id,
                cause,
                termination,
            } => Ok(SupervisedExternalToolWorkerPoll::Indeterminate {
                external_id,
                cause,
                termination,
            }),
        }
    }

    /// Returns at most one authenticated event after resolving the watchdog
    /// race, without selecting a standalone or workflow completion sink.
    pub fn poll_external_tool_event(
        &mut self,
    ) -> SupervisedMultiplexedWorkerResult<
        SupervisedExternalToolWorkerEvent<S::Termination>,
        S::Error,
        S::Termination,
    > {
        self.require_available()?;
        let observation = self
            .active
            .as_mut()
            .ok_or(SupervisedMultiplexedWorkerError::NoActiveInvocation)?
            .binding
            .poll_observation();
        let observation = match observation {
            Ok(observation) => observation,
            Err(source) => {
                let active = self
                    .active
                    .take()
                    .ok_or(SupervisedMultiplexedWorkerError::NoActiveInvocation)?;
                return self.fail_transport(
                    active.binding.external_id(),
                    active.supervision,
                    source,
                );
            }
        };

        if !matches!(&observation, ExternalToolWorkerObservation::Terminal(_)) {
            let event = self
                .active
                .as_mut()
                .ok_or(SupervisedMultiplexedWorkerError::NoActiveInvocation)?
                .binding
                .event_from_observation(observation)
                .map_err(SupervisedMultiplexedWorkerError::Bridge)?;
            return Ok(SupervisedExternalToolWorkerEvent::Worker(event));
        }

        let mut active = self
            .active
            .take()
            .ok_or(SupervisedMultiplexedWorkerError::NoActiveInvocation)?;
        match self.supervisor.finish_invocation(active.supervision) {
            Ok(WorkerInvocationOutcome::Completed) => active
                .binding
                .event_from_observation(observation)
                .map(SupervisedExternalToolWorkerEvent::Worker)
                .map_err(SupervisedMultiplexedWorkerError::Bridge),
            Ok(WorkerInvocationOutcome::DeadlineElapsed(termination)) => {
                self.poisoned = true;
                Ok(SupervisedExternalToolWorkerEvent::Indeterminate {
                    external_id: active.binding.external_id(),
                    cause: WorkerIndeterminateCause::DeadlineElapsed,
                    termination,
                })
            }
            Ok(WorkerInvocationOutcome::SessionDeadlineElapsed(termination)) => {
                self.poisoned = true;
                Ok(SupervisedExternalToolWorkerEvent::Indeterminate {
                    external_id: active.binding.external_id(),
                    cause: WorkerIndeterminateCause::SessionDeadlineElapsed,
                    termination,
                })
            }
            Ok(WorkerInvocationOutcome::Terminated(termination)) => {
                self.poisoned = true;
                Ok(SupervisedExternalToolWorkerEvent::Indeterminate {
                    external_id: active.binding.external_id(),
                    cause: WorkerIndeterminateCause::WorkerTerminated,
                    termination,
                })
            }
            Err(source) => {
                self.poisoned = true;
                let termination = self.supervisor.terminate();
                Err(SupervisedMultiplexedWorkerError::Supervisor {
                    source,
                    termination,
                })
            }
        }
    }

    fn require_available(
        &self,
    ) -> Result<(), SupervisedMultiplexedWorkerError<S::Error, S::Termination>> {
        if self.poisoned {
            Err(SupervisedMultiplexedWorkerError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn fail_transport<R>(
        &mut self,
        external_id: ExternalToolId,
        supervision: S::Invocation,
        source: MultiplexedWorkerError,
    ) -> Result<R, SupervisedMultiplexedWorkerError<S::Error, S::Termination>> {
        self.poisoned = true;
        match self.supervisor.finish_invocation(supervision) {
            Ok(WorkerInvocationOutcome::Completed) => {
                let termination = self.supervisor.terminate();
                Err(SupervisedMultiplexedWorkerError::Transport {
                    source,
                    termination,
                })
            }
            Ok(WorkerInvocationOutcome::DeadlineElapsed(termination)) => {
                Err(SupervisedMultiplexedWorkerError::Indeterminate {
                    external_id,
                    cause: WorkerIndeterminateCause::DeadlineElapsed,
                    termination,
                })
            }
            Ok(WorkerInvocationOutcome::SessionDeadlineElapsed(termination)) => {
                Err(SupervisedMultiplexedWorkerError::Indeterminate {
                    external_id,
                    cause: WorkerIndeterminateCause::SessionDeadlineElapsed,
                    termination,
                })
            }
            Ok(WorkerInvocationOutcome::Terminated(termination)) => {
                Err(SupervisedMultiplexedWorkerError::Indeterminate {
                    external_id,
                    cause: WorkerIndeterminateCause::WorkerTerminated,
                    termination,
                })
            }
            Err(source) => {
                let termination = self.supervisor.terminate();
                Err(SupervisedMultiplexedWorkerError::Supervisor {
                    source,
                    termination,
                })
            }
        }
    }
}

/// Nonblocking authenticated event from a supervised external worker call.
#[derive(Debug)]
pub enum SupervisedExternalToolWorkerEvent<T> {
    /// The watchdog was disarmed before this worker event was exposed.
    Worker(ExternalToolWorkerEvent),
    /// Process lifecycle won the race. No completion sink has been changed.
    Indeterminate {
        external_id: ExternalToolId,
        cause: WorkerIndeterminateCause,
        termination: T,
    },
}

/// Nonblocking outcome after applying a supervised event to a standalone
/// capability runtime.
#[derive(Debug)]
pub enum SupervisedExternalToolWorkerPoll<T> {
    /// The worker protocol event was applied to the runtime.
    Worker(ExternalToolWorkerPoll),
    /// Process lifecycle won the race. The runtime operation remains pending.
    Indeterminate {
        external_id: ExternalToolId,
        cause: WorkerIndeterminateCause,
        termination: T,
    },
}

/// Construction failure for a transport/watchdog session mismatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisedMultiplexedWorkerInitError {
    transport_session: String,
    supervisor_session: String,
}

impl SupervisedMultiplexedWorkerInitError {
    pub fn transport_session(&self) -> &str {
        &self.transport_session
    }

    pub fn supervisor_session(&self) -> &str {
        &self.supervisor_session
    }
}

impl Display for SupervisedMultiplexedWorkerInitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("worker transport and lifecycle supervisor sessions do not match")
    }
}

impl std::error::Error for SupervisedMultiplexedWorkerInitError {}

/// Failure while coordinating a multiplexed call with process supervision.
#[derive(Debug)]
pub enum SupervisedMultiplexedWorkerError<SE, ST> {
    Bridge(ExternalToolWorkerBridgeError),
    Transport {
        source: MultiplexedWorkerError,
        termination: Result<ST, SE>,
    },
    Supervisor {
        source: SE,
        termination: Result<ST, SE>,
    },
    Indeterminate {
        external_id: ExternalToolId,
        cause: WorkerIndeterminateCause,
        termination: ST,
    },
    Busy,
    NoActiveInvocation,
    Poisoned,
}

/// Result type for one operation on a supervised multiplexed session.
pub type SupervisedMultiplexedWorkerResult<T, SE, ST> =
    Result<T, SupervisedMultiplexedWorkerError<SE, ST>>;

impl<SE: Display, ST> Display for SupervisedMultiplexedWorkerError<SE, ST> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bridge(error) => write!(formatter, "external worker bridge failed: {error}"),
            Self::Transport { .. } => formatter
                .write_str("multiplexed worker transport failed; the session was discarded"),
            Self::Supervisor { .. } => formatter
                .write_str("worker lifecycle supervision failed; the session was discarded"),
            Self::Indeterminate { cause, .. } => {
                write!(formatter, "worker call is indeterminate after {cause:?}")
            }
            Self::Busy => formatter.write_str("a supervised worker call is already active"),
            Self::NoActiveInvocation => {
                formatter.write_str("there is no active supervised worker call")
            }
            Self::Poisoned => formatter.write_str("supervised worker session is poisoned"),
        }
    }
}

impl<SE, ST> std::error::Error for SupervisedMultiplexedWorkerError<SE, ST>
where
    SE: std::error::Error + 'static,
    ST: fmt::Debug,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bridge(error) => Some(error),
            Self::Transport { source, .. } => Some(source),
            Self::Supervisor { source, .. } => Some(source),
            Self::Indeterminate { .. } | Self::Busy | Self::NoActiveInvocation | Self::Poisoned => {
                None
            }
        }
    }
}

enum HostEvent {
    Command(HostCommand),
    Frame(Result<AuthenticatedWorkerMessage, JsonLineWorkerChannelError>),
}

enum HostCommand {
    Start {
        invocation: WorkerInvocation,
        result: Sender<Result<MultiplexedWorkerInvocationOutcome, MultiplexedWorkerError>>,
        accepted: Sender<Result<(), MultiplexedWorkerError>>,
    },
    Cancel {
        cancellation_id: String,
        request_id: String,
        tool: String,
        result: Sender<Result<WorkerCancellationResult, MultiplexedWorkerError>>,
        accepted: Sender<Result<(), MultiplexedWorkerError>>,
    },
    Close {
        reply: Sender<Result<(), MultiplexedWorkerError>>,
    },
    Abandon,
}

struct ActiveInvocation {
    authorized: AuthorizedInvocation,
    result: Option<Sender<Result<MultiplexedWorkerInvocationOutcome, MultiplexedWorkerError>>>,
    completed: Option<WorkerResult>,
    cancellation: Option<ActiveCancellation>,
}

struct ActiveCancellation {
    authorized: AuthorizedWorkerCancellation,
    result: Sender<Result<WorkerCancellationResult, MultiplexedWorkerError>>,
}

#[allow(clippy::too_many_arguments)]
fn run_coordinator<R, W>(
    mut authorizer: SessionAuthorizer,
    mut sealer: SessionFrameSealer,
    mut opener: SessionFrameOpener,
    reader: R,
    mut writer: W,
    events: Receiver<HostEvent>,
    event_sender: Sender<HostEvent>,
    ready: Sender<Result<(), MultiplexedWorkerError>>,
) where
    R: BufRead + Send + 'static,
    W: Write,
{
    let (read_requests, read_request_receiver) = mpsc::channel();
    let reader_thread = match spawn_reader(reader, read_request_receiver, event_sender) {
        Ok(thread) => thread,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if request_next_frame(&read_requests).is_err() {
        let _ = ready.send(Err(MultiplexedWorkerError::Unavailable));
        return;
    }
    if ready.send(Ok(())).is_err() {
        return;
    }

    let mut active: Option<ActiveInvocation> = None;
    let mut closing: Option<Sender<Result<(), MultiplexedWorkerError>>> = None;

    while let Ok(event) = events.recv() {
        match event {
            HostEvent::Command(HostCommand::Start {
                invocation,
                result,
                accepted,
            }) => {
                if active.is_some() || closing.is_some() {
                    let _ = accepted.send(Err(MultiplexedWorkerError::Busy));
                    continue;
                }
                let authorized = match authorizer.authorize(invocation) {
                    Ok(authorized) => authorized,
                    Err(error) => {
                        let _ = accepted.send(Err(MultiplexedWorkerError::Protocol(error)));
                        continue;
                    }
                };
                let message = WorkerMessage::Invoke {
                    invocation: authorized.invocation().clone(),
                };
                if let Err(error) = send_frame(&mut sealer, &mut writer, message) {
                    let _ = accepted.send(Err(error.clone()));
                    fail_active(&mut active, error);
                    break;
                }
                active = Some(ActiveInvocation {
                    authorized,
                    result: Some(result),
                    completed: None,
                    cancellation: None,
                });
                let _ = accepted.send(Ok(()));
            }
            HostEvent::Command(HostCommand::Cancel {
                cancellation_id,
                request_id,
                tool,
                result,
                accepted,
            }) => {
                let Some(current) = active.as_mut() else {
                    let _ = accepted.send(Err(MultiplexedWorkerError::NoActiveInvocation));
                    continue;
                };
                if current.authorized.invocation().request_id != request_id
                    || current.authorized.invocation().tool != tool
                {
                    let _ = accepted.send(Err(MultiplexedWorkerError::TargetMismatch));
                    continue;
                }
                if current.cancellation.is_some() {
                    let _ = accepted.send(Err(MultiplexedWorkerError::CancellationPending));
                    continue;
                }
                let request = match WorkerCancellationRequest::new(
                    sealer.session_id(),
                    cancellation_id,
                    request_id,
                    tool,
                ) {
                    Ok(request) => request,
                    Err(error) => {
                        let _ = accepted.send(Err(MultiplexedWorkerError::Protocol(error)));
                        continue;
                    }
                };
                let cancellation =
                    match authorizer.authorize_cancellation(request.clone(), &current.authorized) {
                        Ok(cancellation) => cancellation,
                        Err(error) => {
                            let _ = accepted.send(Err(MultiplexedWorkerError::Protocol(error)));
                            continue;
                        }
                    };
                if let Err(error) =
                    send_frame(&mut sealer, &mut writer, WorkerMessage::Cancel { request })
                {
                    let _ = accepted.send(Err(error.clone()));
                    fail_active(&mut active, error);
                    break;
                }
                current.cancellation = Some(ActiveCancellation {
                    authorized: cancellation,
                    result,
                });
                let _ = accepted.send(Ok(()));
            }
            HostEvent::Command(HostCommand::Close { reply }) => {
                if active.is_some() || closing.is_some() {
                    let _ = reply.send(Err(MultiplexedWorkerError::Busy));
                    continue;
                }
                let message = WorkerMessage::CloseSession {
                    protocol_version: splash_protocol::PROTOCOL_VERSION,
                    session_id: sealer.session_id().to_owned(),
                };
                if let Err(error) = send_frame(&mut sealer, &mut writer, message) {
                    let _ = reply.send(Err(error));
                    break;
                }
                closing = Some(reply);
            }
            HostEvent::Command(HostCommand::Abandon) => {
                fail_active(&mut active, MultiplexedWorkerError::Abandoned);
                if let Some(reply) = closing.take() {
                    let _ = reply.send(Err(MultiplexedWorkerError::Abandoned));
                }
                break;
            }
            HostEvent::Frame(Err(JsonLineWorkerChannelError::UnexpectedEndOfStream))
                if closing.is_some() =>
            {
                if let Some(reply) = closing.take() {
                    let _ = reply.send(Ok(()));
                }
                drop(read_requests);
                let _ = reader_thread.join();
                return;
            }
            HostEvent::Frame(Err(error)) => {
                let error = MultiplexedWorkerError::from_channel(error);
                fail_active(&mut active, error.clone());
                if let Some(reply) = closing.take() {
                    let _ = reply.send(Err(error));
                }
                break;
            }
            HostEvent::Frame(Ok(frame)) => {
                let message = match opener.open(frame) {
                    Ok(message) => message,
                    Err(error) => {
                        let error = MultiplexedWorkerError::Protocol(error);
                        fail_active(&mut active, error.clone());
                        if let Some(reply) = closing.take() {
                            let _ = reply.send(Err(error));
                        }
                        break;
                    }
                };
                let result = handle_worker_message(&mut authorizer, &mut active, message);
                if let Err(error) = result {
                    fail_active(&mut active, error.clone());
                    if let Some(reply) = closing.take() {
                        let _ = reply.send(Err(error));
                    }
                    break;
                }
                if request_next_frame(&read_requests).is_err() {
                    fail_active(&mut active, MultiplexedWorkerError::Unavailable);
                    break;
                }
            }
        }
    }
}

fn handle_worker_message(
    authorizer: &mut SessionAuthorizer,
    active: &mut Option<ActiveInvocation>,
    message: WorkerMessage,
) -> Result<(), MultiplexedWorkerError> {
    match message {
        WorkerMessage::Result { result } => {
            let current = active
                .as_mut()
                .ok_or(MultiplexedWorkerError::UnexpectedMessage("result"))?;
            authorizer
                .validate_result(&current.authorized, &result)
                .map_err(MultiplexedWorkerError::Protocol)?;
            if current.result.is_none() || current.completed.is_some() {
                return Err(MultiplexedWorkerError::UnexpectedMessage(
                    "duplicate result",
                ));
            }
            if current.cancellation.is_some() {
                current.completed = Some(result);
            } else {
                let sender =
                    current
                        .result
                        .take()
                        .ok_or(MultiplexedWorkerError::UnexpectedMessage(
                            "duplicate result",
                        ))?;
                let _ = sender.send(Ok(MultiplexedWorkerInvocationOutcome::Completed(result)));
                *active = None;
            }
            Ok(())
        }
        WorkerMessage::CancellationResult { result } => {
            let current = active
                .as_mut()
                .ok_or(MultiplexedWorkerError::UnexpectedMessage(
                    "cancellation_result",
                ))?;
            let cancellation =
                current
                    .cancellation
                    .take()
                    .ok_or(MultiplexedWorkerError::UnexpectedMessage(
                        "unsolicited cancellation_result",
                    ))?;
            authorizer
                .validate_cancellation_result(&cancellation.authorized, &result)
                .map_err(MultiplexedWorkerError::Protocol)?;
            match result.outcome {
                WorkerCancellationOutcome::Acknowledged => {
                    let _ = cancellation.result.send(Ok(result.clone()));
                    let sender =
                        current
                            .result
                            .take()
                            .ok_or(MultiplexedWorkerError::UnexpectedMessage(
                                "cancellation after completed result",
                            ))?;
                    let _ = sender.send(Ok(MultiplexedWorkerInvocationOutcome::Cancelled(result)));
                    *active = None;
                }
                WorkerCancellationOutcome::TooLate => {
                    let completed = current.completed.take().ok_or(
                        MultiplexedWorkerError::UnexpectedMessage("too_late before result"),
                    )?;
                    let sender =
                        current
                            .result
                            .take()
                            .ok_or(MultiplexedWorkerError::UnexpectedMessage(
                                "too_late after delivered result",
                            ))?;
                    let _ =
                        sender.send(Ok(MultiplexedWorkerInvocationOutcome::Completed(completed)));
                    let _ = cancellation.result.send(Ok(result));
                    *active = None;
                }
                WorkerCancellationOutcome::Unsupported => {
                    let _ = cancellation.result.send(Ok(result));
                }
            }
            Ok(())
        }
        message => Err(MultiplexedWorkerError::UnexpectedMessage(message_kind(
            &message,
        ))),
    }
}

fn spawn_reader<R>(
    mut reader: R,
    requests: Receiver<()>,
    events: Sender<HostEvent>,
) -> Result<JoinHandle<()>, MultiplexedWorkerError>
where
    R: BufRead + Send + 'static,
{
    thread::Builder::new()
        .name("splash-host-worker-frame-reader".to_owned())
        .spawn(move || {
            while requests.recv().is_ok() {
                let frame = read_json_line(&mut reader).and_then(|line| {
                    AuthenticatedWorkerMessage::from_json_line(&line).map_err(Into::into)
                });
                let terminal = frame.is_err();
                if events.send(HostEvent::Frame(frame)).is_err() || terminal {
                    break;
                }
            }
        })
        .map_err(MultiplexedWorkerError::from_io)
}

fn request_next_frame(requests: &Sender<()>) -> Result<(), MultiplexedWorkerError> {
    requests
        .send(())
        .map_err(|_| MultiplexedWorkerError::Unavailable)
}

fn send_frame<W: Write>(
    sealer: &mut SessionFrameSealer,
    writer: &mut W,
    message: WorkerMessage,
) -> Result<(), MultiplexedWorkerError> {
    let frame = sealer
        .seal(message)
        .map_err(MultiplexedWorkerError::Protocol)?;
    let encoded = frame
        .to_json_line()
        .map_err(MultiplexedWorkerError::Protocol)?;
    writer
        .write_all(encoded.as_bytes())
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(MultiplexedWorkerError::from_io)
}

fn fail_active(active: &mut Option<ActiveInvocation>, error: MultiplexedWorkerError) {
    if let Some(mut current) = active.take() {
        if let Some(sender) = current.result.take() {
            let _ = sender.send(Err(error.clone()));
        }
        if let Some(cancellation) = current.cancellation.take() {
            let _ = cancellation.result.send(Err(error));
        }
    }
}

fn message_kind(message: &WorkerMessage) -> &'static str {
    match message {
        WorkerMessage::OpenSession { .. } => "open_session",
        WorkerMessage::Invoke { .. } => "invoke",
        WorkerMessage::Result { .. } => "result",
        WorkerMessage::DispatchOperation { .. } => "dispatch_operation",
        WorkerMessage::OperationResult { .. } => "operation_result",
        WorkerMessage::CompensateOperation { .. } => "compensate_operation",
        WorkerMessage::CompensationResult { .. } => "compensation_result",
        WorkerMessage::ReconcileOperation { .. } => "reconcile_operation",
        WorkerMessage::ReconciledOperation { .. } => "reconciled_operation",
        WorkerMessage::Cancel { .. } => "cancel",
        WorkerMessage::CancellationResult { .. } => "cancellation_result",
        WorkerMessage::CloseSession { .. } => "close_session",
    }
}

/// Cloneable failure delivered to all affected pending handles.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MultiplexedWorkerError {
    Protocol(ProtocolError),
    Io {
        kind: io::ErrorKind,
        message: String,
    },
    RequiresHostAuthenticator,
    SessionMismatch {
        authenticator: String,
        manifest: String,
    },
    Busy,
    NoActiveInvocation,
    TargetMismatch,
    CancellationPending,
    ExternalBindingTerminal,
    UnexpectedMessage(&'static str),
    Unavailable,
    Abandoned,
    CoordinatorPanicked,
}

impl MultiplexedWorkerError {
    fn from_io(error: io::Error) -> Self {
        Self::Io {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn from_channel(error: JsonLineWorkerChannelError) -> Self {
        match error {
            JsonLineWorkerChannelError::Io(error) => Self::from_io(error),
            JsonLineWorkerChannelError::Protocol(error) => Self::Protocol(error),
            JsonLineWorkerChannelError::InvalidUtf8 => Self::UnexpectedMessage("non-UTF-8 frame"),
            JsonLineWorkerChannelError::UnexpectedEndOfStream => {
                Self::UnexpectedMessage("unexpected end of worker stream")
            }
            JsonLineWorkerChannelError::Poisoned => Self::Unavailable,
        }
    }
}

impl Display for MultiplexedWorkerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => {
                write!(formatter, "multiplexed worker protocol failed: {error}")
            }
            Self::Io { .. } => formatter.write_str("multiplexed worker I/O failed"),
            Self::RequiresHostAuthenticator => {
                formatter.write_str("multiplexed worker requires a host authenticator")
            }
            Self::SessionMismatch { .. } => {
                formatter.write_str("multiplexed worker manifest session does not match")
            }
            Self::Busy => formatter.write_str("multiplexed worker already has active work"),
            Self::NoActiveInvocation => {
                formatter.write_str("multiplexed worker has no active invocation")
            }
            Self::TargetMismatch => {
                formatter.write_str("multiplexed worker handle targets another invocation")
            }
            Self::CancellationPending => {
                formatter.write_str("multiplexed worker cancellation is already pending")
            }
            Self::ExternalBindingTerminal => {
                formatter.write_str("external worker binding is already terminal")
            }
            Self::UnexpectedMessage(kind) => {
                write!(formatter, "multiplexed worker returned unexpected {kind}")
            }
            Self::Unavailable => formatter.write_str("multiplexed worker is unavailable"),
            Self::Abandoned => formatter.write_str("multiplexed worker session was abandoned"),
            Self::CoordinatorPanicked => {
                formatter.write_str("multiplexed worker coordinator panicked")
            }
        }
    }
}

impl std::error::Error for MultiplexedWorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Io { .. }
            | Self::RequiresHostAuthenticator
            | Self::SessionMismatch { .. }
            | Self::Busy
            | Self::NoActiveInvocation
            | Self::TargetMismatch
            | Self::CancellationPending
            | Self::ExternalBindingTerminal
            | Self::UnexpectedMessage(_)
            | Self::Unavailable
            | Self::Abandoned
            | Self::CoordinatorPanicked => None,
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::convert::Infallible;
    use std::io::{BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use splash_protocol::{
        CapabilityGrant, SessionKey, ToolPayload, WorkerCancellationResult, AUTH_TAG_BYTES,
    };

    use super::*;
    use crate::bounded_worker::{SessionBoundWorkerExecutionSupervisor, WorkerExecutionSupervisor};
    use crate::{AuditOutcome, ToolPolicy};

    fn manifest() -> CapabilityManifest {
        CapabilityManifest::new("session-1", vec![CapabilityGrant::text("work.run")]).unwrap()
    }

    fn invocation() -> WorkerInvocation {
        WorkerInvocation::new(
            "session-1",
            "request-1",
            "work.run",
            ToolPayload::Text("input".to_owned()),
        )
        .unwrap()
    }

    fn authenticators() -> (SessionAuthenticator, SessionAuthenticator) {
        let key = SessionKey::from_bytes([97; AUTH_TAG_BYTES]).unwrap();
        (
            SessionAuthenticator::new("session-1", key.clone(), SessionRole::Host).unwrap(),
            SessionAuthenticator::new("session-1", key, SessionRole::Worker).unwrap(),
        )
    }

    fn claimed_external_runtime() -> (CapabilityRuntime, ExternalToolInvocation) {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("work.run"))
            .unwrap();
        let initial = runtime
            .eval("use mod.tool\ntool.start(\"work.run\", \"input\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        (runtime, invocation)
    }

    #[derive(Default)]
    struct TestSupervisorState {
        begins: usize,
        finishes: usize,
        terminations: usize,
    }

    struct TestSupervisor {
        session_id: String,
        finish: WorkerInvocationOutcome<u64>,
        state: Arc<Mutex<TestSupervisorState>>,
    }

    impl WorkerExecutionSupervisor for TestSupervisor {
        type Invocation = u64;
        type Termination = u64;
        type Error = Infallible;

        fn begin_invocation(
            &mut self,
            _deadline: WorkerInvocationDeadline,
        ) -> Result<Self::Invocation, Self::Error> {
            let mut state = self.state.lock().unwrap();
            state.begins += 1;
            Ok(u64::try_from(state.begins).unwrap())
        }

        fn finish_invocation(
            &mut self,
            _invocation: Self::Invocation,
        ) -> Result<WorkerInvocationOutcome<Self::Termination>, Self::Error> {
            self.state.lock().unwrap().finishes += 1;
            Ok(self.finish.clone())
        }

        fn terminate(&mut self) -> Result<Self::Termination, Self::Error> {
            let mut state = self.state.lock().unwrap();
            state.terminations += 1;
            Ok(u64::try_from(state.terminations).unwrap())
        }
    }

    impl SessionBoundWorkerExecutionSupervisor for TestSupervisor {
        fn session_id(&self) -> &str {
            &self.session_id
        }
    }

    fn test_supervisor(
        finish: WorkerInvocationOutcome<u64>,
    ) -> (TestSupervisor, Arc<Mutex<TestSupervisorState>>) {
        let state = Arc::new(Mutex::new(TestSupervisorState::default()));
        (
            TestSupervisor {
                session_id: "session-1".to_owned(),
                finish,
                state: Arc::clone(&state),
            },
            state,
        )
    }

    fn read_message(
        reader: &mut BufReader<UnixStream>,
        authenticator: &mut SessionAuthenticator,
    ) -> WorkerMessage {
        let line = read_json_line(reader).unwrap();
        let frame = AuthenticatedWorkerMessage::from_json_line(&line).unwrap();
        authenticator.open(frame).unwrap()
    }

    fn write_message(
        writer: &mut UnixStream,
        authenticator: &mut SessionAuthenticator,
        message: WorkerMessage,
    ) {
        let line = authenticator.seal(message).unwrap().to_json_line().unwrap();
        writer.write_all(line.as_bytes()).unwrap();
        writer.write_all(b"\n").unwrap();
        writer.flush().unwrap();
    }

    #[test]
    fn positive_acknowledgement_resolves_both_pending_handles_as_cancelled() {
        let (host_socket, mut worker_socket) = UnixStream::pair().unwrap();
        let host_reader = BufReader::new(host_socket.try_clone().unwrap());
        let (host_authenticator, mut worker_authenticator) = authenticators();
        let worker_reader_socket = worker_socket.try_clone().unwrap();
        let worker = thread::spawn(move || {
            let mut reader = BufReader::new(worker_reader_socket);
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::OpenSession { .. }
            ));
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::Invoke { .. }
            ));
            let WorkerMessage::Cancel { request } =
                read_message(&mut reader, &mut worker_authenticator)
            else {
                panic!("expected cancellation request");
            };
            let result =
                WorkerCancellationResult::new(&request, WorkerCancellationOutcome::Acknowledged)
                    .unwrap();
            write_message(
                &mut worker_socket,
                &mut worker_authenticator,
                WorkerMessage::CancellationResult { result },
            );
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::CloseSession { .. }
            ));
        });

        let transport = MultiplexedAuthenticatedWorkerTransport::new(
            manifest(),
            host_authenticator,
            host_reader,
            host_socket,
        )
        .unwrap();
        let pending = transport.start(invocation()).unwrap();
        let cancellation = pending.request_cancellation("cancel-1").unwrap();

        let disposition = cancellation.wait().unwrap();
        assert_eq!(disposition.outcome, WorkerCancellationOutcome::Acknowledged);
        assert!(matches!(
            pending.wait().unwrap(),
            MultiplexedWorkerInvocationOutcome::Cancelled(result)
                if result == disposition
        ));
        transport.close().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn ordered_result_wins_before_a_too_late_disposition() {
        let (host_socket, mut worker_socket) = UnixStream::pair().unwrap();
        let host_reader = BufReader::new(host_socket.try_clone().unwrap());
        let (host_authenticator, mut worker_authenticator) = authenticators();
        let worker_reader_socket = worker_socket.try_clone().unwrap();
        let (invocation_seen, invocation_ready) = mpsc::channel();
        let (continue_sender, continue_receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut reader = BufReader::new(worker_reader_socket);
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::OpenSession { .. }
            ));
            let WorkerMessage::Invoke { invocation } =
                read_message(&mut reader, &mut worker_authenticator)
            else {
                panic!("expected invocation");
            };
            invocation_seen.send(()).unwrap();
            continue_receiver.recv().unwrap();
            let result = WorkerResult::new(
                invocation.session_id,
                invocation.request_id,
                ToolPayload::Text("done".to_owned()),
            )
            .unwrap();
            write_message(
                &mut worker_socket,
                &mut worker_authenticator,
                WorkerMessage::Result { result },
            );
            let WorkerMessage::Cancel { request } =
                read_message(&mut reader, &mut worker_authenticator)
            else {
                panic!("expected cancellation request");
            };
            let result =
                WorkerCancellationResult::new(&request, WorkerCancellationOutcome::TooLate)
                    .unwrap();
            write_message(
                &mut worker_socket,
                &mut worker_authenticator,
                WorkerMessage::CancellationResult { result },
            );
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::CloseSession { .. }
            ));
        });

        let transport = MultiplexedAuthenticatedWorkerTransport::new(
            manifest(),
            host_authenticator,
            host_reader,
            host_socket,
        )
        .unwrap();
        let pending = transport.start(invocation()).unwrap();
        invocation_ready.recv().unwrap();
        let cancellation = pending.request_cancellation("cancel-1").unwrap();
        continue_sender.send(()).unwrap();

        assert!(matches!(
            pending.wait().unwrap(),
            MultiplexedWorkerInvocationOutcome::Completed(result)
                if result.payload == ToolPayload::Text("done".to_owned())
        ));
        assert_eq!(
            cancellation.wait().unwrap().outcome,
            WorkerCancellationOutcome::TooLate
        );
        transport.close().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn unsupported_cancellation_keeps_the_invocation_active_for_its_result() {
        let (host_socket, mut worker_socket) = UnixStream::pair().unwrap();
        let host_reader = BufReader::new(host_socket.try_clone().unwrap());
        let (host_authenticator, mut worker_authenticator) = authenticators();
        let worker_reader_socket = worker_socket.try_clone().unwrap();
        let (continue_sender, continue_receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut reader = BufReader::new(worker_reader_socket);
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::OpenSession { .. }
            ));
            let WorkerMessage::Invoke { invocation } =
                read_message(&mut reader, &mut worker_authenticator)
            else {
                panic!("expected invocation");
            };
            let WorkerMessage::Cancel { request } =
                read_message(&mut reader, &mut worker_authenticator)
            else {
                panic!("expected cancellation request");
            };
            let cancellation =
                WorkerCancellationResult::new(&request, WorkerCancellationOutcome::Unsupported)
                    .unwrap();
            write_message(
                &mut worker_socket,
                &mut worker_authenticator,
                WorkerMessage::CancellationResult {
                    result: cancellation,
                },
            );
            continue_receiver.recv().unwrap();
            let result = WorkerResult::new(
                invocation.session_id,
                invocation.request_id,
                WorkerPayload::Text("done".to_owned()),
            )
            .unwrap();
            write_message(
                &mut worker_socket,
                &mut worker_authenticator,
                WorkerMessage::Result { result },
            );
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::CloseSession { .. }
            ));
        });

        let transport = MultiplexedAuthenticatedWorkerTransport::new(
            manifest(),
            host_authenticator,
            host_reader,
            host_socket,
        )
        .unwrap();
        let pending = transport.start(invocation()).unwrap();
        let cancellation = pending.request_cancellation("cancel-1").unwrap();
        assert_eq!(
            cancellation.wait().unwrap().outcome,
            WorkerCancellationOutcome::Unsupported
        );
        continue_sender.send(()).unwrap();
        assert!(matches!(
            pending.wait().unwrap(),
            MultiplexedWorkerInvocationOutcome::Completed(result)
                if result.payload == WorkerPayload::Text("done".to_owned())
        ));
        transport.close().unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn supervised_acknowledgement_confirms_the_exact_external_cancellation() {
        let (host_socket, mut worker_socket) = UnixStream::pair().unwrap();
        let host_reader = BufReader::new(host_socket.try_clone().unwrap());
        let (host_authenticator, mut worker_authenticator) = authenticators();
        let worker_reader_socket = worker_socket.try_clone().unwrap();
        let worker = thread::spawn(move || {
            let mut reader = BufReader::new(worker_reader_socket);
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::OpenSession { .. }
            ));
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::Invoke { .. }
            ));
            let WorkerMessage::Cancel { request } =
                read_message(&mut reader, &mut worker_authenticator)
            else {
                panic!("expected cancellation request");
            };
            let result =
                WorkerCancellationResult::new(&request, WorkerCancellationOutcome::Acknowledged)
                    .unwrap();
            write_message(
                &mut worker_socket,
                &mut worker_authenticator,
                WorkerMessage::CancellationResult { result },
            );
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::CloseSession { .. }
            ));
        });

        let transport = MultiplexedAuthenticatedWorkerTransport::new(
            manifest(),
            host_authenticator,
            host_reader,
            host_socket,
        )
        .unwrap();
        let (supervisor, state) = test_supervisor(WorkerInvocationOutcome::Completed);
        let deadline = WorkerInvocationDeadline::new(Duration::from_secs(1)).unwrap();
        let mut session =
            SupervisedMultiplexedWorkerSession::new(transport, supervisor, deadline).unwrap();
        let (mut runtime, invocation) = claimed_external_runtime();
        session
            .start_external_tool(&invocation, "request-1")
            .unwrap();

        let cancellation = runtime
            .request_external_tool_cancellation(invocation.id)
            .unwrap();
        let mut mismatched = cancellation.clone();
        mismatched.name = "other.run".to_owned();
        assert!(matches!(
            session.request_external_tool_cancellation(&mismatched, "cancel-wrong"),
            Err(SupervisedMultiplexedWorkerError::Bridge(
                ExternalToolWorkerBridgeError::CancellationBindingMismatch
            ))
        ));
        session
            .request_external_tool_cancellation(&cancellation, "cancel-1")
            .unwrap();

        let poll_deadline = Instant::now() + Duration::from_secs(2);
        let resumed = loop {
            assert!(
                Instant::now() < poll_deadline,
                "worker acknowledgement timed out"
            );
            match session.poll_external_tool(&mut runtime).unwrap() {
                SupervisedExternalToolWorkerPoll::Worker(ExternalToolWorkerPoll::Pending) => {
                    thread::sleep(Duration::from_millis(1));
                }
                SupervisedExternalToolWorkerPoll::Worker(ExternalToolWorkerPoll::Cancelled(
                    resumed,
                )) => break resumed,
                outcome => panic!("unexpected supervised worker outcome: {outcome:?}"),
            }
        };
        assert!(!resumed.unwrap().succeeded());
        assert_eq!(
            runtime.audit().last().unwrap().outcome,
            AuditOutcome::Cancelled
        );

        let _supervisor = session.close().unwrap();
        worker.join().unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.begins, 1);
        assert_eq!(state.finishes, 1);
        assert_eq!(state.terminations, 0);
    }

    #[test]
    fn watchdog_race_leaves_external_result_indeterminate_and_runtime_pending() {
        let (host_socket, mut worker_socket) = UnixStream::pair().unwrap();
        let host_reader = BufReader::new(host_socket.try_clone().unwrap());
        let (host_authenticator, mut worker_authenticator) = authenticators();
        let worker_reader_socket = worker_socket.try_clone().unwrap();
        let worker = thread::spawn(move || {
            let mut reader = BufReader::new(worker_reader_socket);
            assert!(matches!(
                read_message(&mut reader, &mut worker_authenticator),
                WorkerMessage::OpenSession { .. }
            ));
            let WorkerMessage::Invoke { invocation } =
                read_message(&mut reader, &mut worker_authenticator)
            else {
                panic!("expected invocation");
            };
            let result = WorkerResult::new(
                invocation.session_id,
                invocation.request_id,
                WorkerPayload::Text("done".to_owned()),
            )
            .unwrap();
            write_message(
                &mut worker_socket,
                &mut worker_authenticator,
                WorkerMessage::Result { result },
            );
        });

        let transport = MultiplexedAuthenticatedWorkerTransport::new(
            manifest(),
            host_authenticator,
            host_reader,
            host_socket,
        )
        .unwrap();
        let (supervisor, state) = test_supervisor(WorkerInvocationOutcome::DeadlineElapsed(41));
        let deadline = WorkerInvocationDeadline::new(Duration::from_secs(1)).unwrap();
        let mut session =
            SupervisedMultiplexedWorkerSession::new(transport, supervisor, deadline).unwrap();
        let (mut runtime, invocation) = claimed_external_runtime();
        session
            .start_external_tool(&invocation, "request-1")
            .unwrap();

        let poll_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(Instant::now() < poll_deadline, "worker result timed out");
            match session.poll_external_tool(&mut runtime).unwrap() {
                SupervisedExternalToolWorkerPoll::Worker(ExternalToolWorkerPoll::Pending) => {
                    thread::sleep(Duration::from_millis(1));
                }
                SupervisedExternalToolWorkerPoll::Indeterminate {
                    external_id,
                    cause,
                    termination,
                } => {
                    assert_eq!(external_id, invocation.id);
                    assert_eq!(cause, WorkerIndeterminateCause::DeadlineElapsed);
                    assert_eq!(termination, 41);
                    break;
                }
                outcome => panic!("unexpected supervised worker outcome: {outcome:?}"),
            }
        }

        assert!(session.is_poisoned());
        assert_eq!(runtime.pending_tools(), 1);
        assert!(runtime.audit().is_empty());
        drop(session);
        worker.join().unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.begins, 1);
        assert_eq!(state.finishes, 1);
        assert_eq!(state.terminations, 0);
    }
}
