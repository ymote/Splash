//! Multiplexed ordinary-invocation driver with authenticated cancellation.
//!
//! The adapter executes on one owned thread while this driver retains the
//! authenticated frame loop. Only an explicitly registered
//! [`CancellableWorkerAdapter`] can use this
//! path. Durable operations remain on the journaled single-exchange path and
//! must use reconciliation after an ambiguous process stop.

use std::fmt::{self, Display, Formatter};
use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use splash_protocol::{
    AuthenticatedWorkerMessage, AuthorizedInvocation, AuthorizedWorkerCancellation, ProtocolError,
    ToolResult, WorkerCancellationOutcome, WorkerCancellationResult, WorkerMessage,
    MAX_WIRE_FRAME_BYTES,
};

use crate::{
    CancellableWorkerAdapter, CancellableWorkerInvocationResult, WorkerAdapterError,
    WorkerAdapterRegistryError, WorkerCancellationToken, WorkerSession,
};

/// A worker session restricted to cancellable ordinary invocations.
///
/// Construct this only after [`WorkerSession::open`] authenticated and admitted
/// the matching `open_session` frame. Every manifest tool must have been
/// registered through
/// [`crate::WorkerAdapterRegistry::register_cancellable`]; mixed synchronous
/// adapters would block the frame loop and are rejected at construction.
pub struct CancellableWorkerSessionDriver<R, W> {
    session: WorkerSession,
    reader: R,
    writer: W,
}

impl<R, W> CancellableWorkerSessionDriver<R, W> {
    pub fn new(
        session: WorkerSession,
        reader: R,
        writer: W,
    ) -> Result<Self, CancellableWorkerSessionInitError> {
        if session.is_poisoned() {
            return Err(CancellableWorkerSessionInitError::SessionPoisoned);
        }
        for grant in &session.manifest().grants {
            if !session.adapters().is_cancellable(&grant.tool) {
                return Err(CancellableWorkerSessionInitError::AdapterNotCancellable(
                    grant.tool.clone(),
                ));
            }
            if !session
                .adapters()
                .has_declared_cancellable_invocation_safety(&grant.tool)
            {
                return Err(
                    CancellableWorkerSessionInitError::InvocationSafetyNotDeclared(
                        grant.tool.clone(),
                    ),
                );
            }
        }
        Ok(Self {
            session,
            reader,
            writer,
        })
    }
}

impl<R, W> CancellableWorkerSessionDriver<R, W>
where
    R: BufRead + Send + 'static,
    W: Write,
{
    /// Runs until the authenticated host sends `close_session`.
    ///
    /// The demand-driven reader owns at most one blocking read. It receives no
    /// next-read permit after a close frame, allowing the driver to join it and
    /// return both the session and writer without leaking an I/O thread.
    pub fn run(self) -> Result<CancellableWorkerSessionClosed<W>, CancellableWorkerSessionError> {
        let Self {
            mut session,
            reader,
            mut writer,
        } = self;
        let (events, event_receiver) = mpsc::channel();
        let (read_requests, read_request_receiver) = mpsc::channel();
        let reader_thread = spawn_frame_reader(reader, read_request_receiver, events.clone())?;
        request_next_frame(&read_requests)?;

        let mut active: Option<ActiveInvocation> = None;
        let mut last_completed: Option<AuthorizedInvocation> = None;

        loop {
            match event_receiver
                .recv()
                .map_err(|_| CancellableWorkerSessionError::EventLoopUnavailable)?
            {
                DriverEvent::Frame(frame) => {
                    let frame = frame?;
                    let message = session
                        .authenticator
                        .open(frame)
                        .map_err(CancellableWorkerSessionError::Protocol)?;
                    match (active.as_mut(), message) {
                        (None, WorkerMessage::Invoke { invocation }) => {
                            let tool = invocation.tool.clone();
                            if !session.adapters.is_cancellable(&tool) {
                                return Err(CancellableWorkerSessionError::AdapterNotCancellable(
                                    tool,
                                ));
                            }
                            if !session
                                .adapters
                                .has_declared_cancellable_invocation_safety(&tool)
                            {
                                return Err(
                                    CancellableWorkerSessionError::InvocationSafetyNotDeclared(
                                        tool,
                                    ),
                                );
                            }
                            let authorized = session
                                .authorizer
                                .authorize(invocation)
                                .map_err(CancellableWorkerSessionError::Protocol)?;
                            let adapter =
                                session.adapters.take_cancellable(&tool).ok_or_else(|| {
                                    CancellableWorkerSessionError::AdapterNotCancellable(
                                        tool.clone(),
                                    )
                                })?;
                            let token = WorkerCancellationToken::default();
                            let join = spawn_adapter(
                                adapter,
                                authorized.clone(),
                                token.clone(),
                                events.clone(),
                            )?;
                            active = Some(ActiveInvocation {
                                authorized,
                                token,
                                cancellation: None,
                                join: Some(join),
                            });
                            request_next_frame(&read_requests)?;
                        }
                        (Some(active), WorkerMessage::Cancel { request }) => {
                            let cancellation = session
                                .authorizer
                                .authorize_cancellation(request, &active.authorized)
                                .map_err(CancellableWorkerSessionError::Protocol)?;
                            active.token.request();
                            active.cancellation = Some(cancellation);
                        }
                        (None, WorkerMessage::Cancel { request }) => {
                            let completed = last_completed
                                .as_ref()
                                .ok_or(CancellableWorkerSessionError::CancellationWithoutTarget)?;
                            let cancellation = session
                                .authorizer
                                .authorize_cancellation(request, completed)
                                .map_err(CancellableWorkerSessionError::Protocol)?;
                            send_cancellation_result(
                                &mut session,
                                &mut writer,
                                &cancellation,
                                WorkerCancellationOutcome::TooLate,
                            )?;
                            request_next_frame(&read_requests)?;
                        }
                        (None, WorkerMessage::CloseSession { .. }) => {
                            drop(read_requests);
                            reader_thread
                                .join()
                                .map_err(|_| CancellableWorkerSessionError::ReaderPanicked)?;
                            return Ok(CancellableWorkerSessionClosed { session, writer });
                        }
                        (Some(_), WorkerMessage::CloseSession { .. }) => {
                            return Err(CancellableWorkerSessionError::CloseWhileInvocationActive);
                        }
                        (_, message) => {
                            return Err(CancellableWorkerSessionError::UnexpectedMessage(
                                message_kind(&message),
                            ));
                        }
                    }
                }
                DriverEvent::InvocationFinished(finished) => {
                    let mut current = active
                        .take()
                        .ok_or(CancellableWorkerSessionError::UnexpectedAdapterCompletion)?;
                    current.join_adapter()?;
                    let tool = current.authorized.invocation().tool.clone();
                    session
                        .adapters
                        .restore_cancellable(tool.clone(), finished.adapter)
                        .map_err(CancellableWorkerSessionError::Registry)?;

                    match finished.outcome {
                        AdapterThreadOutcome::Returned(Ok(
                            CancellableWorkerInvocationResult::Completed(payload),
                        )) => {
                            let invocation = current.authorized.invocation();
                            let result = ToolResult::new(
                                invocation.session_id.clone(),
                                invocation.request_id.clone(),
                                payload,
                            )
                            .map_err(CancellableWorkerSessionError::Protocol)?;
                            session
                                .authorizer
                                .validate_result(&current.authorized, &result)
                                .map_err(CancellableWorkerSessionError::Protocol)?;
                            send_message(
                                &mut session,
                                &mut writer,
                                WorkerMessage::Result { result },
                            )?;
                            if let Some(cancellation) = &current.cancellation {
                                send_cancellation_result(
                                    &mut session,
                                    &mut writer,
                                    cancellation,
                                    WorkerCancellationOutcome::TooLate,
                                )?;
                                request_next_frame(&read_requests)?;
                            }
                            last_completed = Some(current.authorized.clone());
                        }
                        AdapterThreadOutcome::Returned(Ok(
                            CancellableWorkerInvocationResult::CancellationAcknowledged,
                        )) => {
                            if !current.token.is_requested() {
                                return Err(
                                    CancellableWorkerSessionError::UnrequestedAcknowledgement,
                                );
                            }
                            let cancellation = current
                                .cancellation
                                .as_ref()
                                .ok_or(CancellableWorkerSessionError::UnrequestedAcknowledgement)?;
                            send_cancellation_result(
                                &mut session,
                                &mut writer,
                                cancellation,
                                WorkerCancellationOutcome::Acknowledged,
                            )?;
                            request_next_frame(&read_requests)?;
                            last_completed = None;
                        }
                        AdapterThreadOutcome::Returned(Err(error)) => {
                            return Err(CancellableWorkerSessionError::Adapter { tool, error });
                        }
                        AdapterThreadOutcome::Panicked => {
                            return Err(CancellableWorkerSessionError::AdapterPanicked);
                        }
                    }
                }
            }
        }
    }
}

/// Session and writer returned after an authenticated close.
pub struct CancellableWorkerSessionClosed<W> {
    session: WorkerSession,
    writer: W,
}

impl<W> CancellableWorkerSessionClosed<W> {
    pub fn into_parts(self) -> (WorkerSession, W) {
        (self.session, self.writer)
    }
}

struct ActiveInvocation {
    authorized: AuthorizedInvocation,
    token: WorkerCancellationToken,
    cancellation: Option<AuthorizedWorkerCancellation>,
    join: Option<JoinHandle<()>>,
}

impl ActiveInvocation {
    fn join_adapter(&mut self) -> Result<(), CancellableWorkerSessionError> {
        let join = self
            .join
            .take()
            .ok_or(CancellableWorkerSessionError::AdapterPanicked)?;
        join.join()
            .map_err(|_| CancellableWorkerSessionError::AdapterPanicked)
    }
}

impl Drop for ActiveInvocation {
    fn drop(&mut self) {
        let Some(join) = self.join.take() else {
            return;
        };
        // A fatal frame error must not return a detached effect to an embedding
        // process. An uncooperative adapter is bounded by the host watchdog.
        self.token.request();
        let _ = join.join();
    }
}

enum DriverEvent {
    Frame(Result<AuthenticatedWorkerMessage, CancellableWorkerFrameError>),
    InvocationFinished(InvocationFinished),
}

struct InvocationFinished {
    adapter: Box<dyn CancellableWorkerAdapter>,
    outcome: AdapterThreadOutcome,
}

enum AdapterThreadOutcome {
    Returned(Result<CancellableWorkerInvocationResult, WorkerAdapterError>),
    Panicked,
}

fn spawn_frame_reader<R>(
    mut reader: R,
    requests: Receiver<()>,
    events: Sender<DriverEvent>,
) -> Result<JoinHandle<()>, CancellableWorkerSessionError>
where
    R: BufRead + Send + 'static,
{
    thread::Builder::new()
        .name("splash-worker-frame-reader".to_owned())
        .spawn(move || {
            while requests.recv().is_ok() {
                let frame = read_frame(&mut reader);
                let terminal = frame.is_err();
                if events.send(DriverEvent::Frame(frame)).is_err() || terminal {
                    break;
                }
            }
        })
        .map_err(CancellableWorkerSessionError::ThreadSpawn)
}

fn spawn_adapter(
    mut adapter: Box<dyn CancellableWorkerAdapter>,
    authorized: AuthorizedInvocation,
    token: WorkerCancellationToken,
    events: Sender<DriverEvent>,
) -> Result<JoinHandle<()>, CancellableWorkerSessionError> {
    thread::Builder::new()
        .name("splash-worker-cancellable-adapter".to_owned())
        .spawn(move || {
            let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
                adapter.invoke_cancellable(authorized.invocation(), authorized.grant(), &token)
            }))
            .map_or(
                AdapterThreadOutcome::Panicked,
                AdapterThreadOutcome::Returned,
            );
            let _ = events.send(DriverEvent::InvocationFinished(InvocationFinished {
                adapter,
                outcome,
            }));
        })
        .map_err(CancellableWorkerSessionError::ThreadSpawn)
}

fn request_next_frame(requests: &Sender<()>) -> Result<(), CancellableWorkerSessionError> {
    requests
        .send(())
        .map_err(|_| CancellableWorkerSessionError::EventLoopUnavailable)
}

fn send_cancellation_result<W: Write>(
    session: &mut WorkerSession,
    writer: &mut W,
    cancellation: &AuthorizedWorkerCancellation,
    outcome: WorkerCancellationOutcome,
) -> Result<(), CancellableWorkerSessionError> {
    let result = WorkerCancellationResult::new(cancellation.request(), outcome)
        .map_err(CancellableWorkerSessionError::Protocol)?;
    session
        .authorizer
        .validate_cancellation_result(cancellation, &result)
        .map_err(CancellableWorkerSessionError::Protocol)?;
    send_message(
        session,
        writer,
        WorkerMessage::CancellationResult { result },
    )
}

fn send_message<W: Write>(
    session: &mut WorkerSession,
    writer: &mut W,
    message: WorkerMessage,
) -> Result<(), CancellableWorkerSessionError> {
    let frame = session
        .authenticator
        .seal(message)
        .map_err(CancellableWorkerSessionError::Protocol)?;
    let encoded = frame
        .to_json_line()
        .map_err(CancellableWorkerSessionError::Protocol)?;
    writer
        .write_all(encoded.as_bytes())
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(CancellableWorkerSessionError::Write)
}

fn read_frame<R: BufRead>(
    reader: &mut R,
) -> Result<AuthenticatedWorkerMessage, CancellableWorkerFrameError> {
    let line = read_json_line(reader)?;
    AuthenticatedWorkerMessage::from_json_line(&line).map_err(CancellableWorkerFrameError::Protocol)
}

fn read_json_line<R: BufRead>(reader: &mut R) -> Result<String, CancellableWorkerFrameError> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(CancellableWorkerFrameError::Read)?;
        if available.is_empty() {
            return Err(CancellableWorkerFrameError::UnexpectedEndOfStream);
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            let actual = line.len().saturating_add(newline);
            if actual > MAX_WIRE_FRAME_BYTES {
                return Err(CancellableWorkerFrameError::Protocol(
                    ProtocolError::WireFrameTooLarge {
                        actual,
                        maximum: MAX_WIRE_FRAME_BYTES,
                    },
                ));
            }
            line.extend_from_slice(&available[..newline]);
            reader.consume(newline + 1);
            return String::from_utf8(line).map_err(|_| CancellableWorkerFrameError::InvalidUtf8);
        }

        let remaining = MAX_WIRE_FRAME_BYTES
            .saturating_add(1)
            .saturating_sub(line.len());
        if remaining == 0 {
            return Err(CancellableWorkerFrameError::Protocol(
                ProtocolError::WireFrameTooLarge {
                    actual: line.len().saturating_add(1),
                    maximum: MAX_WIRE_FRAME_BYTES,
                },
            ));
        }
        let copied = available.len().min(remaining);
        line.extend_from_slice(&available[..copied]);
        reader.consume(copied);
        if line.len() > MAX_WIRE_FRAME_BYTES {
            return Err(CancellableWorkerFrameError::Protocol(
                ProtocolError::WireFrameTooLarge {
                    actual: line.len(),
                    maximum: MAX_WIRE_FRAME_BYTES,
                },
            ));
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

/// Construction failure for a cancellable session driver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancellableWorkerSessionInitError {
    SessionPoisoned,
    AdapterNotCancellable(String),
    InvocationSafetyNotDeclared(String),
}

impl Display for CancellableWorkerSessionInitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionPoisoned => formatter.write_str("worker session is poisoned"),
            Self::AdapterNotCancellable(tool) => {
                write!(formatter, "worker adapter is not cancellable: {tool}")
            }
            Self::InvocationSafetyNotDeclared(tool) => write!(
                formatter,
                "worker adapter did not declare non-durable invocation safety: {tool}"
            ),
        }
    }
}

impl std::error::Error for CancellableWorkerSessionInitError {}

/// Failure while running the authenticated cancellable worker frame loop.
#[derive(Debug)]
pub enum CancellableWorkerSessionError {
    Protocol(ProtocolError),
    Frame(CancellableWorkerFrameError),
    Write(io::Error),
    ThreadSpawn(io::Error),
    ReaderPanicked,
    AdapterPanicked,
    AdapterNotCancellable(String),
    InvocationSafetyNotDeclared(String),
    Adapter {
        tool: String,
        error: WorkerAdapterError,
    },
    Registry(WorkerAdapterRegistryError),
    CancellationWithoutTarget,
    UnrequestedAcknowledgement,
    CloseWhileInvocationActive,
    UnexpectedAdapterCompletion,
    UnexpectedMessage(&'static str),
    EventLoopUnavailable,
}

impl Display for CancellableWorkerSessionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => {
                write!(formatter, "worker cancellation protocol failed: {error}")
            }
            Self::Frame(_) => formatter.write_str("worker cancellation frame input failed"),
            Self::Write(_) => formatter.write_str("worker cancellation frame output failed"),
            Self::ThreadSpawn(_) => {
                formatter.write_str("worker cancellation thread could not start")
            }
            Self::ReaderPanicked => formatter.write_str("worker frame reader panicked"),
            Self::AdapterPanicked => formatter.write_str("cancellable worker adapter panicked"),
            Self::AdapterNotCancellable(tool) => {
                write!(formatter, "worker adapter is not cancellable: {tool}")
            }
            Self::InvocationSafetyNotDeclared(tool) => write!(
                formatter,
                "worker adapter did not declare non-durable invocation safety: {tool}"
            ),
            Self::Adapter { tool, .. } => write!(formatter, "worker adapter failed: {tool}"),
            Self::Registry(error) => write!(formatter, "worker adapter registry failed: {error}"),
            Self::CancellationWithoutTarget => {
                formatter.write_str("worker cancellation has no active or just-completed target")
            }
            Self::UnrequestedAcknowledgement => {
                formatter.write_str("worker adapter acknowledged cancellation before a request")
            }
            Self::CloseWhileInvocationActive => {
                formatter.write_str("worker session cannot close while an invocation is active")
            }
            Self::UnexpectedAdapterCompletion => {
                formatter.write_str("worker received an adapter completion with no active request")
            }
            Self::UnexpectedMessage(kind) => {
                write!(formatter, "worker received unexpected {kind} message")
            }
            Self::EventLoopUnavailable => {
                formatter.write_str("worker cancellation event loop is unavailable")
            }
        }
    }
}

impl std::error::Error for CancellableWorkerSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Frame(error) => Some(error),
            Self::Write(error) | Self::ThreadSpawn(error) => Some(error),
            Self::Adapter { error, .. } => Some(error),
            Self::Registry(error) => Some(error),
            Self::ReaderPanicked
            | Self::AdapterPanicked
            | Self::AdapterNotCancellable(_)
            | Self::InvocationSafetyNotDeclared(_)
            | Self::CancellationWithoutTarget
            | Self::UnrequestedAcknowledgement
            | Self::CloseWhileInvocationActive
            | Self::UnexpectedAdapterCompletion
            | Self::UnexpectedMessage(_)
            | Self::EventLoopUnavailable => None,
        }
    }
}

impl From<CancellableWorkerFrameError> for CancellableWorkerSessionError {
    fn from(error: CancellableWorkerFrameError) -> Self {
        Self::Frame(error)
    }
}

/// Bounded frame-read failure from the worker side of the JSON-line channel.
#[derive(Debug)]
pub enum CancellableWorkerFrameError {
    Read(io::Error),
    Protocol(ProtocolError),
    InvalidUtf8,
    UnexpectedEndOfStream,
}

impl Display for CancellableWorkerFrameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "worker frame read failed: {error}"),
            Self::Protocol(error) => write!(formatter, "worker frame is invalid: {error}"),
            Self::InvalidUtf8 => formatter.write_str("worker frame is not valid UTF-8"),
            Self::UnexpectedEndOfStream => {
                formatter.write_str("worker frame stream ended before a complete frame")
            }
        }
    }
}

impl std::error::Error for CancellableWorkerFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::InvalidUtf8 | Self::UnexpectedEndOfStream => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use splash_protocol::{
        CapabilityGrant, CapabilityManifest, SessionAuthenticator, SessionAuthorizer, SessionKey,
        SessionRole, ToolInvocation, ToolPayload, WorkerCancellationRequest, WorkerMessage,
        WorkerOperationJournal, AUTH_TAG_BYTES, PROTOCOL_VERSION,
    };

    use super::*;
    use crate::{
        WorkerAdapter, WorkerAdapterRegistry, WorkerInvocationSafety, WorkerJournalRevision,
        WorkerSessionAdmission, WorkerSessionLimits,
    };

    #[derive(Clone, Copy)]
    enum TestBehavior {
        Complete,
        WaitForCancellation,
    }

    struct TestCancellableAdapter {
        behavior: TestBehavior,
        observed_cancellation: Arc<AtomicBool>,
    }

    impl WorkerAdapter for TestCancellableAdapter {
        fn invocation_safety(&self) -> Option<WorkerInvocationSafety> {
            Some(WorkerInvocationSafety::ReadOnly)
        }
    }

    impl CancellableWorkerAdapter for TestCancellableAdapter {
        fn invoke_cancellable(
            &mut self,
            _request: &ToolInvocation,
            _grant: &CapabilityGrant,
            cancellation: &WorkerCancellationToken,
        ) -> Result<CancellableWorkerInvocationResult, WorkerAdapterError> {
            match self.behavior {
                TestBehavior::Complete => Ok(CancellableWorkerInvocationResult::Completed(
                    ToolPayload::Text("done".to_owned()),
                )),
                TestBehavior::WaitForCancellation => {
                    for _ in 0..100_000 {
                        if cancellation.is_requested() {
                            self.observed_cancellation.store(true, Ordering::Release);
                            return Ok(CancellableWorkerInvocationResult::CancellationAcknowledged);
                        }
                        thread::yield_now();
                    }
                    Err(WorkerAdapterError::Failed)
                }
            }
        }
    }

    struct StandardAdapter;

    impl WorkerAdapter for StandardAdapter {
        fn invocation_safety(&self) -> Option<WorkerInvocationSafety> {
            Some(WorkerInvocationSafety::ReadOnly)
        }

        fn invoke(
            &mut self,
            _request: &ToolInvocation,
            _grant: &CapabilityGrant,
        ) -> Result<ToolPayload, WorkerAdapterError> {
            Ok(ToolPayload::Text("done".to_owned()))
        }
    }

    struct UndeclaredCancellableAdapter;

    impl WorkerAdapter for UndeclaredCancellableAdapter {}

    impl CancellableWorkerAdapter for UndeclaredCancellableAdapter {
        fn invoke_cancellable(
            &mut self,
            _request: &ToolInvocation,
            _grant: &CapabilityGrant,
            _cancellation: &WorkerCancellationToken,
        ) -> Result<CancellableWorkerInvocationResult, WorkerAdapterError> {
            Ok(CancellableWorkerInvocationResult::Completed(
                ToolPayload::Text("done".to_owned()),
            ))
        }
    }

    struct TeardownAdapter {
        observed_cancellation: Arc<AtomicBool>,
        finished: mpsc::Sender<()>,
    }

    impl WorkerAdapter for TeardownAdapter {
        fn invocation_safety(&self) -> Option<WorkerInvocationSafety> {
            Some(WorkerInvocationSafety::ReadOnly)
        }
    }

    impl CancellableWorkerAdapter for TeardownAdapter {
        fn invoke_cancellable(
            &mut self,
            _request: &ToolInvocation,
            _grant: &CapabilityGrant,
            cancellation: &WorkerCancellationToken,
        ) -> Result<CancellableWorkerInvocationResult, WorkerAdapterError> {
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                if cancellation.is_requested() {
                    self.observed_cancellation.store(true, Ordering::Release);
                    let _ = self.finished.send(());
                    return Ok(CancellableWorkerInvocationResult::CancellationAcknowledged);
                }
                thread::yield_now();
            }
            let _ = self.finished.send(());
            Err(WorkerAdapterError::Failed)
        }
    }

    struct Admission;

    impl WorkerSessionAdmission for Admission {
        type Error = Infallible;

        fn admit(
            &mut self,
            _manifest: &CapabilityManifest,
            _journal_scope: &str,
        ) -> Result<u64, Self::Error> {
            Ok(1)
        }
    }

    fn manifest() -> CapabilityManifest {
        CapabilityManifest::new("session-1", vec![CapabilityGrant::text("work.run")]).unwrap()
    }

    fn invocation() -> ToolInvocation {
        ToolInvocation::new(
            "session-1",
            "request-1",
            "work.run",
            ToolPayload::Text("input".to_owned()),
        )
        .unwrap()
    }

    fn open_worker(
        registry: WorkerAdapterRegistry,
    ) -> (WorkerSession, SessionAuthenticator, SessionAuthorizer) {
        let key = SessionKey::from_bytes([83; AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("session-1", key.clone(), SessionRole::Host).unwrap();
        let worker = SessionAuthenticator::new("session-1", key, SessionRole::Worker).unwrap();
        let manifest = manifest();
        let opening = host
            .seal(WorkerMessage::OpenSession {
                manifest: manifest.clone(),
            })
            .unwrap();
        let session = WorkerSession::open(
            worker,
            opening,
            WorkerOperationJournal::new("tenant-1").unwrap(),
            WorkerJournalRevision::default(),
            registry,
            WorkerSessionLimits::default(),
            &mut Admission,
        )
        .unwrap();
        let authorizer = SessionAuthorizer::new(manifest).unwrap();
        (session, host, authorizer)
    }

    fn push_frame(encoded: &mut Vec<u8>, host: &mut SessionAuthenticator, message: WorkerMessage) {
        let frame = host.seal(message).unwrap().to_json_line().unwrap();
        encoded.extend_from_slice(frame.as_bytes());
        encoded.push(b'\n');
    }

    fn decode_worker_frames(
        encoded: Vec<u8>,
        host: &mut SessionAuthenticator,
    ) -> Vec<WorkerMessage> {
        String::from_utf8(encoded)
            .unwrap()
            .lines()
            .map(|line| {
                let frame = AuthenticatedWorkerMessage::from_json_line(line).unwrap();
                host.open(frame).unwrap()
            })
            .collect()
    }

    #[test]
    fn authenticated_cancellation_acknowledgement_suppresses_the_result() {
        let observed_cancellation = Arc::new(AtomicBool::new(false));
        let mut registry = WorkerAdapterRegistry::default();
        registry
            .register_cancellable(
                "work.run",
                TestCancellableAdapter {
                    behavior: TestBehavior::WaitForCancellation,
                    observed_cancellation: observed_cancellation.clone(),
                },
            )
            .unwrap();
        let (worker, mut host, mut host_authorizer) = open_worker(registry);
        let invocation = invocation();
        let authorized = host_authorizer.authorize(invocation.clone()).unwrap();
        let cancellation_request =
            WorkerCancellationRequest::new("session-1", "cancel-1", "request-1", "work.run")
                .unwrap();
        let cancellation = host_authorizer
            .authorize_cancellation(cancellation_request.clone(), &authorized)
            .unwrap();
        let mut input = Vec::new();
        push_frame(&mut input, &mut host, WorkerMessage::Invoke { invocation });
        push_frame(
            &mut input,
            &mut host,
            WorkerMessage::Cancel {
                request: cancellation_request,
            },
        );
        push_frame(
            &mut input,
            &mut host,
            WorkerMessage::CloseSession {
                protocol_version: PROTOCOL_VERSION,
                session_id: "session-1".to_owned(),
            },
        );

        let closed = CancellableWorkerSessionDriver::new(worker, Cursor::new(input), Vec::new())
            .unwrap()
            .run()
            .unwrap();
        let (_, output) = closed.into_parts();
        let messages = decode_worker_frames(output, &mut host);

        assert!(observed_cancellation.load(Ordering::Acquire));
        assert_eq!(messages.len(), 1);
        let WorkerMessage::CancellationResult { result } = &messages[0] else {
            panic!("expected a cancellation result");
        };
        assert_eq!(result.outcome, WorkerCancellationOutcome::Acknowledged);
        host_authorizer
            .validate_cancellation_result(&cancellation, result)
            .unwrap();
    }

    #[test]
    fn completed_result_wins_before_the_too_late_disposition() {
        let mut registry = WorkerAdapterRegistry::default();
        registry
            .register_cancellable(
                "work.run",
                TestCancellableAdapter {
                    behavior: TestBehavior::Complete,
                    observed_cancellation: Arc::new(AtomicBool::new(false)),
                },
            )
            .unwrap();
        let (worker, mut host, mut host_authorizer) = open_worker(registry);
        let invocation = invocation();
        let authorized = host_authorizer.authorize(invocation.clone()).unwrap();
        let cancellation_request =
            WorkerCancellationRequest::new("session-1", "cancel-1", "request-1", "work.run")
                .unwrap();
        let cancellation = host_authorizer
            .authorize_cancellation(cancellation_request.clone(), &authorized)
            .unwrap();
        let mut input = Vec::new();
        push_frame(&mut input, &mut host, WorkerMessage::Invoke { invocation });
        push_frame(
            &mut input,
            &mut host,
            WorkerMessage::Cancel {
                request: cancellation_request,
            },
        );
        push_frame(
            &mut input,
            &mut host,
            WorkerMessage::CloseSession {
                protocol_version: PROTOCOL_VERSION,
                session_id: "session-1".to_owned(),
            },
        );

        let closed = CancellableWorkerSessionDriver::new(worker, Cursor::new(input), Vec::new())
            .unwrap()
            .run()
            .unwrap();
        let (_, output) = closed.into_parts();
        let messages = decode_worker_frames(output, &mut host);

        assert_eq!(messages.len(), 2);
        let WorkerMessage::Result { result } = &messages[0] else {
            panic!("expected the ordinary result first");
        };
        host_authorizer
            .validate_result(&authorized, result)
            .unwrap();
        let WorkerMessage::CancellationResult { result } = &messages[1] else {
            panic!("expected the cancellation disposition second");
        };
        assert_eq!(result.outcome, WorkerCancellationOutcome::TooLate);
        host_authorizer
            .validate_cancellation_result(&cancellation, result)
            .unwrap();
    }

    #[test]
    fn driver_refuses_a_manifest_with_a_synchronous_adapter() {
        let mut registry = WorkerAdapterRegistry::default();
        registry.register("work.run", StandardAdapter).unwrap();
        let (worker, _, _) = open_worker(registry);

        assert!(matches!(
            CancellableWorkerSessionDriver::new(
                worker,
                Cursor::new(Vec::<u8>::new()),
                Vec::<u8>::new()
            ),
            Err(CancellableWorkerSessionInitError::AdapterNotCancellable(tool))
                if tool == "work.run"
        ));
    }

    #[test]
    fn driver_refuses_a_cancellable_adapter_without_an_invocation_safety_contract() {
        let mut registry = WorkerAdapterRegistry::default();
        registry
            .register_cancellable("work.run", UndeclaredCancellableAdapter)
            .unwrap();
        let (worker, _, _) = open_worker(registry);

        assert!(matches!(
            CancellableWorkerSessionDriver::new(
                worker,
                Cursor::new(Vec::<u8>::new()),
                Vec::<u8>::new()
            ),
            Err(CancellableWorkerSessionInitError::InvocationSafetyNotDeclared(tool))
                if tool == "work.run"
        ));
    }

    #[test]
    fn fatal_session_error_cancels_and_joins_the_active_adapter() {
        let observed_cancellation = Arc::new(AtomicBool::new(false));
        let (finished, completion) = mpsc::channel();
        let mut registry = WorkerAdapterRegistry::default();
        registry
            .register_cancellable(
                "work.run",
                TeardownAdapter {
                    observed_cancellation: Arc::clone(&observed_cancellation),
                    finished,
                },
            )
            .unwrap();
        let (worker, mut host, _) = open_worker(registry);
        let mut input = Vec::new();
        push_frame(
            &mut input,
            &mut host,
            WorkerMessage::Invoke {
                invocation: invocation(),
            },
        );
        push_frame(
            &mut input,
            &mut host,
            WorkerMessage::CloseSession {
                protocol_version: PROTOCOL_VERSION,
                session_id: "session-1".to_owned(),
            },
        );

        assert!(matches!(
            CancellableWorkerSessionDriver::new(worker, Cursor::new(input), Vec::new())
                .unwrap()
                .run(),
            Err(CancellableWorkerSessionError::CloseWhileInvocationActive)
        ));
        completion.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(observed_cancellation.load(Ordering::Acquire));
    }
}
