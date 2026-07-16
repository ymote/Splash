//! Automatic durable reconciliation after a Bubblewrap worker is reaped.
//!
//! This module deliberately automates only the mechanically enforceable part
//! of post-stop recovery: prove the old process is reaped, load and validate the
//! authenticated host ledger, reserve a fence, start a different contained
//! session, perform one authenticated reconciliation request, reap that
//! session, and persist the observation with compare-and-swap. It never
//! re-dispatches an ambiguous effect, resumes a Splash promise, or chooses
//! compensation.

use std::fmt::{self, Debug, Display, Formatter};
use std::io::BufReader;
use std::str;

use splash_capabilities::json_line_worker::{
    JsonLineWorkerChannel, JsonLineWorkerChannelError,
    OneShotAuthenticatedOperationWorkerTransport,
    OneShotAuthenticatedOperationWorkerTransportError,
    OneShotAuthenticatedOperationWorkerTransportInitError, WorkerFrameChannel,
};
use splash_protocol::{
    CapabilityManifest, OperationReconcileRequest, OperationReconcileResult,
    PrivatePipeWorkerBootstrap, ProtocolError, SessionAuthenticator, SessionKey, SessionRole,
    WorkerMessage, SESSION_KEY_BYTES,
};
use splash_sandbox::bubblewrap::{
    BubblewrapBootstrapError, BubblewrapCgroupBootstrapError, BubblewrapCommand,
    BubblewrapTermination, BubblewrapTerminationError, BubblewrapWorkerInvocationOutcome,
    BubblewrapWorkerReaped, BubblewrapWorkerSessionDeadline, BubblewrapWorkerWatchdogError,
};
use splash_sandbox::cgroup_v2::CgroupV2Policy;
use splash_storage::{
    AuthenticatedStore, AuthenticatedStoreError, FencedRollbackProtectedStore, StorageRecordKey,
};

use crate::{
    WorkflowEngine, WorkflowError, WorkflowEvent, WorkflowOperationLedger,
    WorkflowOperationLedgerError, WorkflowOperationState, WorkflowPlan,
};

/// A freshly keyed Bubblewrap command prepared for one recovery exchange.
///
/// The command retains the exact manifest used to compile containment. This
/// constructor generates a new authenticated session key from the operating
/// system and derives both ends of the private-pipe bootstrap from that key.
pub struct FreshBubblewrapRecoverySession {
    command: BubblewrapCommand,
    launch: BubblewrapRecoveryLaunch,
    bootstrap: PrivatePipeWorkerBootstrap,
    host_authenticator: SessionAuthenticator,
}

impl FreshBubblewrapRecoverySession {
    /// Generates a fresh authenticated session for an already compiled
    /// Bubblewrap command.
    pub fn generate(
        command: BubblewrapCommand,
    ) -> Result<Self, FreshBubblewrapRecoverySessionError> {
        Self::generate_for_launch(command, BubblewrapRecoveryLaunch::Standard)
    }

    /// Generates a fresh session whose worker must enter a new cgroup-v2
    /// child carrying the supplied finite resource limits.
    pub fn generate_in_cgroup(
        command: BubblewrapCommand,
        policy: CgroupV2Policy,
    ) -> Result<Self, FreshBubblewrapRecoverySessionError> {
        Self::generate_for_launch(command, BubblewrapRecoveryLaunch::Cgroup(policy))
    }

    fn generate_for_launch(
        command: BubblewrapCommand,
        launch: BubblewrapRecoveryLaunch,
    ) -> Result<Self, FreshBubblewrapRecoverySessionError> {
        command
            .manifest()
            .validate()
            .map_err(FreshBubblewrapRecoverySessionError::Protocol)?;
        let session_id = command.session_id().to_owned();
        let mut entropy = [0_u8; SESSION_KEY_BYTES];
        if let Err(error) = getrandom::fill(&mut entropy) {
            entropy.fill(0);
            return Err(FreshBubblewrapRecoverySessionError::Entropy(error));
        }
        let key =
            SessionKey::from_bytes(entropy).map_err(FreshBubblewrapRecoverySessionError::Protocol);
        entropy.fill(0);
        let key = key?;
        let bootstrap = PrivatePipeWorkerBootstrap::new(session_id.clone(), key.clone())
            .map_err(FreshBubblewrapRecoverySessionError::Protocol)?;
        let host_authenticator = SessionAuthenticator::new(session_id, key, SessionRole::Host)
            .map_err(FreshBubblewrapRecoverySessionError::Protocol)?;
        Ok(Self {
            command,
            launch,
            bootstrap,
            host_authenticator,
        })
    }

    /// Returns the non-secret authenticated session ID.
    pub fn session_id(&self) -> &str {
        self.command.session_id()
    }

    /// Returns the exact manifest used for both containment compilation and
    /// authenticated session admission.
    pub fn manifest(&self) -> &CapabilityManifest {
        self.command.manifest()
    }
}

impl Debug for FreshBubblewrapRecoverySession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshBubblewrapRecoverySession")
            .field("session_id", &self.session_id())
            .field("launch", &self.launch.kind())
            .field("session_key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// Host-selected process resource boundary for a fresh recovery worker.
enum BubblewrapRecoveryLaunch {
    Standard,
    Cgroup(CgroupV2Policy),
}

impl BubblewrapRecoveryLaunch {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Cgroup(_) => "cgroup_v2",
        }
    }
}

/// Failure while generating a fresh authenticated recovery session.
#[derive(Debug)]
pub enum FreshBubblewrapRecoverySessionError {
    Entropy(getrandom::Error),
    Protocol(ProtocolError),
}

impl Display for FreshBubblewrapRecoverySessionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entropy(_) => formatter
                .write_str("operating-system entropy is unavailable for a recovery session"),
            Self::Protocol(error) => {
                write!(formatter, "recovery session policy is invalid: {error}")
            }
        }
    }
}

impl std::error::Error for FreshBubblewrapRecoverySessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Entropy(_) => None,
            Self::Protocol(error) => Some(error),
        }
    }
}

/// Complete host input for one post-stop recovery attempt.
///
/// The fresh session is owned and consumed. The stopped-worker proof is
/// borrowed because a failed fresh launch must be retryable with a new session.
pub struct BubblewrapPostStopRecoveryRequest<'a> {
    stopped_worker: &'a BubblewrapWorkerReaped,
    fresh_session: FreshBubblewrapRecoverySession,
    ledger_key: &'a StorageRecordKey,
    operation_key: &'a str,
    current_input: &'a [u8],
    request_id: &'a str,
    deadline: BubblewrapWorkerSessionDeadline,
}

impl<'a> BubblewrapPostStopRecoveryRequest<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stopped_worker: &'a BubblewrapWorkerReaped,
        fresh_session: FreshBubblewrapRecoverySession,
        ledger_key: &'a StorageRecordKey,
        operation_key: &'a str,
        current_input: &'a [u8],
        request_id: &'a str,
        deadline: BubblewrapWorkerSessionDeadline,
    ) -> Self {
        Self {
            stopped_worker,
            fresh_session,
            ledger_key,
            operation_key,
            current_input,
            request_id,
            deadline,
        }
    }
}

impl Debug for BubblewrapPostStopRecoveryRequest<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BubblewrapPostStopRecoveryRequest")
            .field("stopped_session_id", &self.stopped_worker.session_id())
            .field("fresh_session_id", &self.fresh_session.session_id())
            .field("ledger_key", &self.ledger_key)
            .field("operation_key", &self.operation_key)
            .field("current_input", &"[redacted]")
            .field("request_id", &self.request_id)
            .field("deadline", &self.deadline)
            .finish()
    }
}

/// A worker observation durably committed to the authenticated host ledger.
///
/// Even a terminal observation is not approval to resume a workflow. The host
/// must separately validate current policy, recover any required output, and
/// decide whether to resume, retry, or compensate.
pub struct PersistedBubblewrapPostStopRecovery {
    stopped_session_id: String,
    fresh_session_id: String,
    stopped_termination: BubblewrapTermination,
    fresh_termination: BubblewrapTermination,
    storage_revision: u64,
    observed_state: WorkflowOperationState,
    ledger: WorkflowOperationLedger,
    result: OperationReconcileResult,
}

impl PersistedBubblewrapPostStopRecovery {
    pub fn stopped_session_id(&self) -> &str {
        &self.stopped_session_id
    }

    pub fn fresh_session_id(&self) -> &str {
        &self.fresh_session_id
    }

    pub fn stopped_termination(&self) -> &BubblewrapTermination {
        &self.stopped_termination
    }

    pub fn fresh_termination(&self) -> &BubblewrapTermination {
        &self.fresh_termination
    }

    pub const fn storage_revision(&self) -> u64 {
        self.storage_revision
    }

    pub const fn observed_state(&self) -> WorkflowOperationState {
        self.observed_state
    }

    pub fn ledger(&self) -> &WorkflowOperationLedger {
        &self.ledger
    }

    /// Returns the authenticated worker result without placing its payload in
    /// the durable ledger.
    ///
    /// The result may contain sensitive adapter output. Trusted host code must
    /// apply its current output contract and product policy before using it and
    /// must not log or persist the value by default.
    pub fn sensitive_result(&self) -> &OperationReconcileResult {
        &self.result
    }

    pub fn into_ledger(self) -> WorkflowOperationLedger {
        self.ledger
    }
}

impl Debug for PersistedBubblewrapPostStopRecovery {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedBubblewrapPostStopRecovery")
            .field("stopped_session_id", &self.stopped_session_id)
            .field("fresh_session_id", &self.fresh_session_id)
            .field("stopped_termination", &self.stopped_termination)
            .field("fresh_termination", &self.fresh_termination)
            .field("storage_revision", &self.storage_revision)
            .field("observed_state", &self.observed_state)
            .field("ledger_revision", &self.ledger.revision())
            .field("result", &"[redacted]")
            .finish()
    }
}

/// Reconciles one ambiguous operation after its old Bubblewrap worker was
/// reaped, then atomically persists the authenticated observation.
///
/// The backend must provide durable fencing and rollback protection. This
/// function validates the current authenticated ledger before reserving a
/// fresh writer fence, refuses a reused worker session ID, sends only
/// `reconcile_operation`, and consumes the fresh worker after one bounded
/// exchange. It never sends
/// `dispatch_operation` or `compensate_operation`.
pub fn recover_bubblewrap_operation<B>(
    engine: &mut WorkflowEngine,
    plan: &WorkflowPlan,
    storage: &mut AuthenticatedStore<B>,
    recovery: BubblewrapPostStopRecoveryRequest<'_>,
) -> Result<PersistedBubblewrapPostStopRecovery, BubblewrapPostStopRecoveryError<B::Error>>
where
    B: FencedRollbackProtectedStore,
{
    let BubblewrapPostStopRecoveryRequest {
        stopped_worker,
        fresh_session,
        ledger_key,
        operation_key,
        current_input,
        request_id,
        deadline,
    } = recovery;
    if stopped_worker.session_id() == fresh_session.session_id() {
        return Err(BubblewrapPostStopRecoveryError::ReusedSessionId);
    }
    let stopped_session_id = stopped_worker.session_id().to_owned();
    let stopped_termination = stopped_worker.termination().clone();
    let fresh_session_id = fresh_session.session_id().to_owned();

    let prepared = prepare_recovery_ledger(
        engine,
        plan,
        storage,
        ledger_key,
        operation_key,
        current_input,
        fresh_session.manifest(),
        &fresh_session_id,
        request_id,
    )?;

    let (result, fresh_reaped) = execute_reconciliation(fresh_session, &prepared.request, deadline)
        .map_err(BubblewrapPostStopRecoveryError::Exchange)?;
    let (_, fresh_termination) = fresh_reaped.into_parts();
    let (observed_state, storage_revision, ledger) =
        persist_recovery_observation(engine, plan, storage, ledger_key, prepared, &result)?;

    Ok(PersistedBubblewrapPostStopRecovery {
        stopped_session_id,
        fresh_session_id,
        stopped_termination,
        fresh_termination,
        storage_revision,
        observed_state,
        ledger,
        result,
    })
}

#[derive(Debug)]
struct PreparedRecoveryLedger {
    fencing_token: u64,
    expected_storage_revision: u64,
    ledger: WorkflowOperationLedger,
    request: OperationReconcileRequest,
}

#[allow(clippy::too_many_arguments)]
fn prepare_recovery_ledger<B>(
    engine: &WorkflowEngine,
    plan: &WorkflowPlan,
    storage: &mut AuthenticatedStore<B>,
    ledger_key: &StorageRecordKey,
    operation_key: &str,
    current_input: &[u8],
    recovery_manifest: &CapabilityManifest,
    fresh_session_id: &str,
    request_id: &str,
) -> Result<PreparedRecoveryLedger, BubblewrapPostStopRecoveryError<B::Error>>
where
    B: FencedRollbackProtectedStore,
{
    let stored = storage
        .load(ledger_key)
        .map_err(BubblewrapPostStopRecoveryError::Storage)?
        .ok_or(BubblewrapPostStopRecoveryError::MissingLedger)?;
    let expected_storage_revision = stored.revision();
    let encoded = str::from_utf8(stored.payload())
        .map_err(|_| BubblewrapPostStopRecoveryError::InvalidLedgerEncoding)?;
    let ledger = WorkflowOperationLedger::from_json(encoded)
        .map_err(BubblewrapPostStopRecoveryError::Ledger)?;
    engine
        .validate_operation_ledger(plan, &ledger)
        .map_err(BubblewrapPostStopRecoveryError::Workflow)?;
    let operation = ledger.operation(operation_key).ok_or_else(|| {
        BubblewrapPostStopRecoveryError::Ledger(WorkflowOperationLedgerError::UnknownOperation(
            operation_key.to_owned(),
        ))
    })?;
    let current_state = operation.state();
    if matches!(
        current_state,
        WorkflowOperationState::Succeeded
            | WorkflowOperationState::Failed
            | WorkflowOperationState::Cancelled
    ) {
        return Err(BubblewrapPostStopRecoveryError::RecoveryNotRequired(
            current_state,
        ));
    }
    if recovery_manifest.session_id != fresh_session_id {
        return Err(BubblewrapPostStopRecoveryError::RecoveryManifestSessionMismatch);
    }
    if recovery_manifest.grants.len() != 1 {
        return Err(
            BubblewrapPostStopRecoveryError::RecoveryManifestMustContainOneGrant {
                actual: recovery_manifest.grants.len(),
            },
        );
    }
    if recovery_manifest.grants[0].tool != operation.tool() {
        return Err(BubblewrapPostStopRecoveryError::RecoveryManifestToolMismatch);
    }
    let request = engine
        .operation_reconcile_request(
            plan,
            &ledger,
            operation_key,
            current_input,
            fresh_session_id,
            request_id,
        )
        .map_err(BubblewrapPostStopRecoveryError::Workflow)?;
    // Reserve only after every host-side check succeeds. A write between the
    // authenticated load and this reservation changes the expected revision;
    // a write after it either has an older rejected fence or supersedes this
    // fence, so the final fenced CAS still detects every race.
    let fencing_token = storage
        .reserve_fence(ledger_key)
        .map_err(BubblewrapPostStopRecoveryError::Storage)?;
    Ok(PreparedRecoveryLedger {
        fencing_token,
        expected_storage_revision,
        ledger,
        request,
    })
}

fn persist_recovery_observation<B>(
    engine: &mut WorkflowEngine,
    plan: &WorkflowPlan,
    storage: &mut AuthenticatedStore<B>,
    ledger_key: &StorageRecordKey,
    prepared: PreparedRecoveryLedger,
    result: &OperationReconcileResult,
) -> Result<
    (WorkflowOperationState, u64, WorkflowOperationLedger),
    BubblewrapPostStopRecoveryError<B::Error>,
>
where
    B: FencedRollbackProtectedStore,
{
    let PreparedRecoveryLedger {
        fencing_token,
        expected_storage_revision,
        mut ledger,
        request,
    } = prepared;
    engine
        .validate_operation_ledger(plan, &ledger)
        .map_err(BubblewrapPostStopRecoveryError::Workflow)?;
    let observed_state = ledger
        .apply_verified_reconciliation(&request, result)
        .map_err(BubblewrapPostStopRecoveryError::Ledger)?;
    let encoded = ledger
        .to_json()
        .map_err(BubblewrapPostStopRecoveryError::Ledger)?;
    // Write even when the worker repeats the current state. The fenced CAS is
    // also the final concurrency check that proves this observation was based
    // on the current authenticated ledger snapshot.
    let storage_revision = storage
        .compare_and_swap_fenced(
            ledger_key,
            Some(expected_storage_revision),
            encoded.as_bytes(),
            fencing_token,
        )
        .map_err(BubblewrapPostStopRecoveryError::Storage)?
        .revision();
    let operation = ledger.operation(&request.operation_key).ok_or_else(|| {
        BubblewrapPostStopRecoveryError::Ledger(WorkflowOperationLedgerError::UnknownOperation(
            request.operation_key.clone(),
        ))
    })?;
    engine.record_event(WorkflowEvent::OperationObserved {
        plan_id: plan.id(),
        step_id: operation.step_id().to_owned(),
        tool: operation.tool().to_owned(),
        state: observed_state,
    });
    Ok((observed_state, storage_revision, ledger))
}

fn execute_reconciliation(
    fresh_session: FreshBubblewrapRecoverySession,
    request: &OperationReconcileRequest,
    deadline: BubblewrapWorkerSessionDeadline,
) -> Result<(OperationReconcileResult, BubblewrapWorkerReaped), BubblewrapRecoveryExchangeError> {
    let FreshBubblewrapRecoverySession {
        command,
        launch,
        bootstrap,
        mut host_authenticator,
    } = fresh_session;
    let manifest = command.manifest().clone();
    let worker = match launch {
        BubblewrapRecoveryLaunch::Standard => command
            .spawn_with_bootstrap(&bootstrap)
            .map_err(BubblewrapRecoveryExchangeError::Spawn)?,
        BubblewrapRecoveryLaunch::Cgroup(policy) => command
            .spawn_with_bootstrap_in_cgroup(&policy, &bootstrap)
            .map_err(BubblewrapRecoveryExchangeError::CgroupSpawn)?,
    };
    let (mut watchdog, stdin, stdout) = match worker.into_session_watchdog_parts(deadline) {
        Ok(parts) => parts,
        Err(error) => {
            let cause = error.to_string();
            let mut lifecycle = error.into_lifecycle();
            let cleanup = lifecycle.terminate();
            return Err(BubblewrapRecoveryExchangeError::WatchdogStart { cause, cleanup });
        }
    };
    let invocation = match watchdog.begin_call(deadline.maximum()) {
        Ok(invocation) => invocation,
        Err(source) => {
            let cleanup = watchdog.close();
            return Err(BubblewrapRecoveryExchangeError::Watchdog {
                phase: BubblewrapRecoveryWatchdogPhase::Begin,
                source,
                cleanup,
            });
        }
    };
    let mut channel = JsonLineWorkerChannel::new(BufReader::new(stdout), stdin);
    let exchange = (|| {
        let opening = host_authenticator
            .seal(WorkerMessage::OpenSession {
                manifest: manifest.clone(),
            })
            .map_err(BubblewrapRecoveryProtocolExchangeError::Protocol)?;
        channel
            .send_frame(opening)
            .map_err(BubblewrapRecoveryProtocolExchangeError::Channel)?;
        let mut transport = OneShotAuthenticatedOperationWorkerTransport::new(
            manifest,
            host_authenticator,
            channel,
        )
        .map_err(BubblewrapRecoveryProtocolExchangeError::TransportInit)?;
        transport
            .reconcile_operation(request.clone())
            .map_err(BubblewrapRecoveryProtocolExchangeError::Transport)
    })();

    match watchdog.finish_call(invocation) {
        Ok(BubblewrapWorkerInvocationOutcome::Completed) => match exchange {
            Ok(result) => watchdog
                .close_reaped()
                .map(|reaped| (result, reaped))
                .map_err(BubblewrapRecoveryExchangeError::Cleanup),
            Err(source) => {
                let cleanup = watchdog.close();
                Err(BubblewrapRecoveryExchangeError::ProtocolExchange { source, cleanup })
            }
        },
        Ok(outcome) => {
            let cleanup = watchdog.close();
            Err(BubblewrapRecoveryExchangeError::Interrupted { outcome, cleanup })
        }
        Err(source) => {
            let cleanup = watchdog.close();
            Err(BubblewrapRecoveryExchangeError::Watchdog {
                phase: BubblewrapRecoveryWatchdogPhase::Finish,
                source,
                cleanup,
            })
        }
    }
}

/// Failure during the contained one-shot reconciliation exchange.
#[derive(Debug)]
pub enum BubblewrapRecoveryExchangeError {
    Spawn(BubblewrapBootstrapError),
    CgroupSpawn(BubblewrapCgroupBootstrapError),
    WatchdogStart {
        cause: String,
        cleanup: Result<BubblewrapTermination, BubblewrapTerminationError>,
    },
    Watchdog {
        phase: BubblewrapRecoveryWatchdogPhase,
        source: BubblewrapWorkerWatchdogError,
        cleanup: Result<BubblewrapTermination, BubblewrapWorkerWatchdogError>,
    },
    ProtocolExchange {
        source: BubblewrapRecoveryProtocolExchangeError,
        cleanup: Result<BubblewrapTermination, BubblewrapWorkerWatchdogError>,
    },
    Interrupted {
        outcome: BubblewrapWorkerInvocationOutcome,
        cleanup: Result<BubblewrapTermination, BubblewrapWorkerWatchdogError>,
    },
    Cleanup(BubblewrapWorkerWatchdogError),
}

impl Display for BubblewrapRecoveryExchangeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "could not start recovery worker: {error}"),
            Self::CgroupSpawn(error) => {
                write!(formatter, "could not start cgroup recovery worker: {error}")
            }
            Self::WatchdogStart { .. } => formatter.write_str(
                "could not start the recovery watchdog; worker termination was attempted",
            ),
            Self::Watchdog { phase, .. } => write!(
                formatter,
                "recovery watchdog failed during {phase}; worker termination was attempted"
            ),
            Self::ProtocolExchange { .. } => formatter.write_str(
                "authenticated recovery exchange failed; worker termination was attempted",
            ),
            Self::Interrupted { .. } => formatter
                .write_str("recovery exchange was interrupted and produced no durable observation"),
            Self::Cleanup(_) => formatter
                .write_str("recovery result was discarded because the fresh worker was not reaped"),
        }
    }
}

impl std::error::Error for BubblewrapRecoveryExchangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::CgroupSpawn(error) => Some(error),
            Self::Watchdog { source, .. } => Some(source),
            Self::ProtocolExchange { source, .. } => Some(source),
            Self::Cleanup(error) => Some(error),
            Self::WatchdogStart { .. } | Self::Interrupted { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BubblewrapRecoveryWatchdogPhase {
    Begin,
    Finish,
}

impl Display for BubblewrapRecoveryWatchdogPhase {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Begin => formatter.write_str("begin"),
            Self::Finish => formatter.write_str("finish"),
        }
    }
}

/// Authentication or framing failure inside a bounded recovery exchange.
#[derive(Debug)]
pub enum BubblewrapRecoveryProtocolExchangeError {
    Protocol(ProtocolError),
    Channel(JsonLineWorkerChannelError),
    TransportInit(OneShotAuthenticatedOperationWorkerTransportInitError),
    Transport(OneShotAuthenticatedOperationWorkerTransportError<JsonLineWorkerChannelError>),
}

impl Display for BubblewrapRecoveryProtocolExchangeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "worker frame is invalid: {error}"),
            Self::Channel(error) => write!(formatter, "worker channel failed: {error}"),
            Self::TransportInit(error) => {
                write!(formatter, "worker transport could not start: {error}")
            }
            Self::Transport(error) => write!(formatter, "worker transport failed: {error}"),
        }
    }
}

impl std::error::Error for BubblewrapRecoveryProtocolExchangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Channel(error) => Some(error),
            Self::TransportInit(error) => Some(error),
            Self::Transport(error) => Some(error),
        }
    }
}

/// Failure before a recovery observation was durably committed.
#[derive(Debug)]
pub enum BubblewrapPostStopRecoveryError<E> {
    ReusedSessionId,
    MissingLedger,
    InvalidLedgerEncoding,
    RecoveryNotRequired(WorkflowOperationState),
    RecoveryManifestSessionMismatch,
    RecoveryManifestMustContainOneGrant { actual: usize },
    RecoveryManifestToolMismatch,
    Storage(AuthenticatedStoreError<E>),
    Ledger(WorkflowOperationLedgerError),
    Workflow(WorkflowError),
    Exchange(BubblewrapRecoveryExchangeError),
}

impl<E: Display> Display for BubblewrapPostStopRecoveryError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReusedSessionId => formatter
                .write_str("post-stop recovery requires a different authenticated session ID"),
            Self::MissingLedger => formatter.write_str("post-stop recovery ledger does not exist"),
            Self::InvalidLedgerEncoding => {
                formatter.write_str("post-stop recovery ledger is not UTF-8")
            }
            Self::RecoveryNotRequired(state) => write!(
                formatter,
                "post-stop recovery is not required for terminal state {state:?}"
            ),
            Self::RecoveryManifestSessionMismatch => {
                formatter.write_str("post-stop recovery manifest session binding is inconsistent")
            }
            Self::RecoveryManifestMustContainOneGrant { actual } => write!(
                formatter,
                "post-stop recovery manifest must contain exactly one grant; got {actual}"
            ),
            Self::RecoveryManifestToolMismatch => formatter
                .write_str("post-stop recovery manifest does not match the durable operation tool"),
            Self::Storage(error) => write!(formatter, "post-stop recovery storage failed: {error}"),
            Self::Ledger(error) => write!(formatter, "post-stop recovery ledger failed: {error}"),
            Self::Workflow(error) => {
                write!(formatter, "post-stop recovery policy failed: {error}")
            }
            Self::Exchange(error) => write!(formatter, "post-stop recovery failed: {error}"),
        }
    }
}

impl<E> std::error::Error for BubblewrapPostStopRecoveryError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::Ledger(error) => Some(error),
            Self::Workflow(error) => Some(error),
            Self::Exchange(error) => Some(error),
            Self::ReusedSessionId
            | Self::MissingLedger
            | Self::InvalidLedgerEncoding
            | Self::RecoveryNotRequired(_)
            | Self::RecoveryManifestSessionMismatch
            | Self::RecoveryManifestMustContainOneGrant { .. }
            | Self::RecoveryManifestToolMismatch => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use splash_capabilities::CapabilityRuntime;
    use splash_protocol::{CapabilityGrant, OperationStatus, ToolPayload};
    use splash_storage::{
        StorageKey, StorageKeyId, StorageKeyring, VolatileMemoryStore, VolatileMemoryStoreError,
        STORAGE_KEY_BYTES,
    };

    use super::*;
    use crate::WorkflowStep;

    type TestStore = AuthenticatedStore<VolatileMemoryStore>;

    fn fixture() -> (WorkflowEngine, WorkflowPlan, TestStore, StorageRecordKey) {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new("publish", "let release = true")])
            .unwrap();
        let mut ledger = engine.operation_ledger(&plan).unwrap();
        engine
            .record_operation(
                &plan,
                &mut ledger,
                "publish",
                "release.publish",
                "release-2026-1",
                b"request",
            )
            .unwrap();
        let key = StorageRecordKey::new("workflow-ledger", "release-2026").unwrap();
        let keyring = StorageKeyring::new(
            StorageKeyId::new("storage-v1").unwrap(),
            StorageKey::from_bytes([71; STORAGE_KEY_BYTES]),
        );
        let mut storage = AuthenticatedStore::new(VolatileMemoryStore::default(), keyring);
        storage
            .create(&key, ledger.to_json().unwrap().as_bytes())
            .unwrap();
        (engine, plan, storage, key)
    }

    fn result_for(
        request: &OperationReconcileRequest,
        status: OperationStatus,
    ) -> OperationReconcileResult {
        OperationReconcileResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            request.tool.clone(),
            request.operation_key.clone(),
            status,
        )
        .unwrap()
    }

    fn recovery_manifest(session_id: &str) -> CapabilityManifest {
        CapabilityManifest::new(session_id, vec![CapabilityGrant::text("release.publish")]).unwrap()
    }

    #[test]
    fn fenced_recovery_persists_only_the_bound_observation() {
        let (mut engine, plan, mut storage, key) = fixture();
        let prepared = prepare_recovery_ledger(
            &engine,
            &plan,
            &mut storage,
            &key,
            "release-2026-1",
            b"request",
            &recovery_manifest("fresh-session"),
            "fresh-session",
            "reconcile-1",
        )
        .unwrap();
        assert_eq!(storage.current_fence(&key).unwrap(), 1);
        let result = result_for(
            &prepared.request,
            OperationStatus::Succeeded {
                payload: ToolPayload::Text("private worker output".to_owned()),
            },
        );

        let (state, storage_revision, ledger) =
            persist_recovery_observation(&mut engine, &plan, &mut storage, &key, prepared, &result)
                .unwrap();

        assert_eq!(state, WorkflowOperationState::Succeeded);
        assert_eq!(storage_revision, 2);
        assert_eq!(ledger.revision(), 2);
        assert_eq!(
            ledger.operation("release-2026-1").unwrap().state(),
            WorkflowOperationState::Succeeded
        );
        let stored = storage.load(&key).unwrap().unwrap();
        let encoded = str::from_utf8(stored.payload()).unwrap();
        assert!(!encoded.contains("private worker output"));
        assert_eq!(WorkflowOperationLedger::from_json(encoded).unwrap(), ledger);
    }

    #[test]
    fn a_new_recovery_fence_rejects_the_superseded_writer() {
        let (mut engine, plan, mut storage, key) = fixture();
        let first = prepare_recovery_ledger(
            &engine,
            &plan,
            &mut storage,
            &key,
            "release-2026-1",
            b"request",
            &recovery_manifest("fresh-session-1"),
            "fresh-session-1",
            "reconcile-1",
        )
        .unwrap();
        let first_result = result_for(&first.request, OperationStatus::Running);
        let second = prepare_recovery_ledger(
            &engine,
            &plan,
            &mut storage,
            &key,
            "release-2026-1",
            b"request",
            &recovery_manifest("fresh-session-2"),
            "fresh-session-2",
            "reconcile-2",
        )
        .unwrap();
        let second_result = result_for(&second.request, OperationStatus::Running);
        assert_eq!(storage.current_fence(&key).unwrap(), 2);
        let events_before_stale_write = engine.events().len();

        let stale = persist_recovery_observation(
            &mut engine,
            &plan,
            &mut storage,
            &key,
            first,
            &first_result,
        )
        .unwrap_err();
        assert!(matches!(
            stale,
            BubblewrapPostStopRecoveryError::Storage(AuthenticatedStoreError::Backend(
                VolatileMemoryStoreError::FencingTokenRejected {
                    supplied: 1,
                    current: 2
                }
            ))
        ));
        assert_eq!(engine.events().len(), events_before_stale_write);

        let (_, storage_revision, ledger) = persist_recovery_observation(
            &mut engine,
            &plan,
            &mut storage,
            &key,
            second,
            &second_result,
        )
        .unwrap();
        assert_eq!(storage_revision, 2);
        assert_eq!(engine.events().len(), events_before_stale_write + 1);
        assert_eq!(
            ledger.operation("release-2026-1").unwrap().state(),
            WorkflowOperationState::Running
        );

        let third = prepare_recovery_ledger(
            &engine,
            &plan,
            &mut storage,
            &key,
            "release-2026-1",
            b"request",
            &recovery_manifest("fresh-session-3"),
            "fresh-session-3",
            "reconcile-3",
        )
        .unwrap();
        let repeated_running = result_for(&third.request, OperationStatus::Running);
        let (_, storage_revision, ledger) = persist_recovery_observation(
            &mut engine,
            &plan,
            &mut storage,
            &key,
            third,
            &repeated_running,
        )
        .unwrap();
        assert_eq!(storage_revision, 3);
        assert_eq!(ledger.revision(), 2);
    }

    #[test]
    fn mismatched_or_terminal_recovery_never_replays_an_effect() {
        let (mut engine, plan, mut storage, key) = fixture();
        let prepared = prepare_recovery_ledger(
            &engine,
            &plan,
            &mut storage,
            &key,
            "release-2026-1",
            b"request",
            &recovery_manifest("fresh-session"),
            "fresh-session",
            "reconcile-1",
        )
        .unwrap();
        let mut mismatched = result_for(&prepared.request, OperationStatus::Running);
        mismatched.request_id = "different-request".to_owned();
        assert!(matches!(
            persist_recovery_observation(
                &mut engine,
                &plan,
                &mut storage,
                &key,
                prepared,
                &mismatched,
            ),
            Err(BubblewrapPostStopRecoveryError::Ledger(
                WorkflowOperationLedgerError::ReconciliationMismatch
            ))
        ));
        assert_eq!(storage.load(&key).unwrap().unwrap().revision(), 1);

        let prepared = prepare_recovery_ledger(
            &engine,
            &plan,
            &mut storage,
            &key,
            "release-2026-1",
            b"request",
            &recovery_manifest("fresh-session-2"),
            "fresh-session-2",
            "reconcile-2",
        )
        .unwrap();
        let terminal = result_for(&prepared.request, OperationStatus::Cancelled);
        persist_recovery_observation(&mut engine, &plan, &mut storage, &key, prepared, &terminal)
            .unwrap();

        assert!(matches!(
            prepare_recovery_ledger(
                &engine,
                &plan,
                &mut storage,
                &key,
                "release-2026-1",
                b"request",
                &recovery_manifest("fresh-session-3"),
                "fresh-session-3",
                "reconcile-3",
            ),
            Err(BubblewrapPostStopRecoveryError::RecoveryNotRequired(
                WorkflowOperationState::Cancelled
            ))
        ));
        assert_eq!(storage.current_fence(&key).unwrap(), 2);
    }

    #[test]
    fn recovery_preparation_rejects_input_drift_before_worker_launch() {
        let (engine, plan, mut storage, key) = fixture();

        assert!(matches!(
            prepare_recovery_ledger(
                &engine,
                &plan,
                &mut storage,
                &key,
                "release-2026-1",
                b"changed request",
                &recovery_manifest("fresh-session"),
                "fresh-session",
                "reconcile-1",
            ),
            Err(BubblewrapPostStopRecoveryError::Workflow(
                WorkflowError::OperationLedger(
                    WorkflowOperationLedgerError::InputFingerprintMismatch(operation_key)
                )
            )) if operation_key == "release-2026-1"
        ));
        assert_eq!(storage.current_fence(&key).unwrap(), 0);
        assert_eq!(storage.load(&key).unwrap().unwrap().revision(), 1);
    }

    #[test]
    fn recovery_manifest_is_bound_to_one_exact_operation_tool() {
        let (engine, plan, mut storage, key) = fixture();
        let broad = CapabilityManifest::new(
            "fresh-session",
            vec![
                CapabilityGrant::text("release.publish"),
                CapabilityGrant::text("workspace.write"),
            ],
        )
        .unwrap();
        assert!(matches!(
            prepare_recovery_ledger(
                &engine,
                &plan,
                &mut storage,
                &key,
                "release-2026-1",
                b"request",
                &broad,
                "fresh-session",
                "reconcile-1",
            ),
            Err(BubblewrapPostStopRecoveryError::RecoveryManifestMustContainOneGrant { actual: 2 })
        ));

        let wrong_tool = CapabilityManifest::new(
            "fresh-session-2",
            vec![CapabilityGrant::text("workspace.write")],
        )
        .unwrap();
        assert!(matches!(
            prepare_recovery_ledger(
                &engine,
                &plan,
                &mut storage,
                &key,
                "release-2026-1",
                b"request",
                &wrong_tool,
                "fresh-session-2",
                "reconcile-2",
            ),
            Err(BubblewrapPostStopRecoveryError::RecoveryManifestToolMismatch)
        ));

        assert!(matches!(
            prepare_recovery_ledger(
                &engine,
                &plan,
                &mut storage,
                &key,
                "release-2026-1",
                b"request",
                &recovery_manifest("fresh-session-3"),
                "different-session",
                "reconcile-3",
            ),
            Err(BubblewrapPostStopRecoveryError::RecoveryManifestSessionMismatch)
        ));
        assert_eq!(storage.current_fence(&key).unwrap(), 0);
    }
}
