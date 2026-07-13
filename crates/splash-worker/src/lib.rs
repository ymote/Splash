#![forbid(unsafe_code)]

//! Capability-scoped worker runtime for Splash Rust adapters.
//!
//! This crate executes no ambient operating-system action. It authenticates
//! worker frames, applies the active capability manifest, and dispatches only
//! explicitly registered Rust adapters. The embedding platform remains
//! responsible for process containment, session-key provisioning, resource
//! selector resolution, and durable journal storage.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

use splash_protocol::{
    AuthenticatedWorkerMessage, CapabilityGrant, CapabilityManifest, OperationCompensationRequest,
    OperationCompensationResult, OperationDispatchRequest, OperationReconcileRequest,
    OperationReconcileResult, OperationStatus, ProtocolError, SessionAuthenticator,
    SessionAuthorizer, SessionRole, ToolInvocation, ToolPayload, ToolResult,
    WorkerCompensationAdmission, WorkerMessage, WorkerOperationAdmission, WorkerOperationJournal,
};

/// Default maximum reconciliation requests one worker accepts for one tool in
/// a session.
pub const DEFAULT_MAX_RECONCILIATIONS_PER_TOOL: u32 = 16;
/// Default maximum reconciliation requests one worker accepts across all tools
/// in a session.
pub const DEFAULT_MAX_RECONCILIATIONS_PER_SESSION: u32 = 64;

/// Bounded worker-side limits that are independent of effectful-call grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerSessionLimits {
    /// Reconciliation can trigger adapter-side status lookup, so it has its
    /// own bound instead of becoming an unbounded recovery oracle.
    max_reconciliations_per_tool: u32,
    max_reconciliations_per_session: u32,
}

impl WorkerSessionLimits {
    pub fn new(max_reconciliations_per_tool: u32) -> Result<Self, WorkerSessionLimitsError> {
        Self::with_limits(
            max_reconciliations_per_tool,
            DEFAULT_MAX_RECONCILIATIONS_PER_SESSION,
        )
    }

    /// Creates independent per-tool and whole-session reconciliation bounds.
    pub fn with_limits(
        max_reconciliations_per_tool: u32,
        max_reconciliations_per_session: u32,
    ) -> Result<Self, WorkerSessionLimitsError> {
        if max_reconciliations_per_tool == 0 {
            return Err(WorkerSessionLimitsError::ZeroPerToolReconciliationLimit);
        }
        if max_reconciliations_per_session == 0 {
            return Err(WorkerSessionLimitsError::ZeroSessionReconciliationLimit);
        }
        Ok(Self {
            max_reconciliations_per_tool,
            max_reconciliations_per_session,
        })
    }

    pub const fn max_reconciliations_per_tool(self) -> u32 {
        self.max_reconciliations_per_tool
    }

    pub const fn max_reconciliations_per_session(self) -> u32 {
        self.max_reconciliations_per_session
    }
}

impl Default for WorkerSessionLimits {
    fn default() -> Self {
        Self {
            max_reconciliations_per_tool: DEFAULT_MAX_RECONCILIATIONS_PER_TOOL,
            max_reconciliations_per_session: DEFAULT_MAX_RECONCILIATIONS_PER_SESSION,
        }
    }
}

/// Rejection from [`WorkerSessionLimits::new`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerSessionLimitsError {
    ZeroPerToolReconciliationLimit,
    ZeroSessionReconciliationLimit,
}

impl Display for WorkerSessionLimitsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPerToolReconciliationLimit => formatter
                .write_str("worker per-tool reconciliation limit must be greater than zero"),
            Self::ZeroSessionReconciliationLimit => {
                formatter.write_str("worker session reconciliation limit must be greater than zero")
            }
        }
    }
}

impl std::error::Error for WorkerSessionLimitsError {}

/// Host-owned monotonic revision for one worker journal scope.
///
/// A revision is loaded atomically with the journal before a session opens and
/// is advanced by every successful journal compare-and-swap. It is not an
/// operation key, capability, or script-visible value.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkerJournalRevision(u64);

impl WorkerJournalRevision {
    /// Creates a revision returned by the host's trusted journal store.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the host storage revision for compare-and-swap integration.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Host-issued fencing lease for one active writer of a journal scope.
///
/// The admission policy assigns a newer lease whenever it supersedes a worker
/// for the same tenant scope. The journal store must reject writes from a
/// lease that is no longer current. It is opaque worker metadata, never a
/// capability or script-visible value.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkerJournalLease(u64);

impl WorkerJournalLease {
    /// Creates the host's opaque monotonic lease value for one journal scope.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the lease value for the trusted journal-store integration.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Trusted host policy that admits one newly opened worker session.
///
/// The implementation must atomically bind the authenticated manifest session
/// ID and host-selected journal scope to the intended tenant, reject stale or
/// replayed session IDs, and issue the current single-writer fencing lease for
/// that scope. The scope never comes from a worker frame or Splash source. A
/// fresh session key alone is not sufficient proof that a captured
/// `open_session` frame was not replayed into a new worker process.
pub trait WorkerSessionAdmission {
    type Error;

    fn admit(
        &mut self,
        manifest: &CapabilityManifest,
        journal_scope: &str,
    ) -> Result<WorkerJournalLease, Self::Error>;
}

/// Durable storage boundary for one worker operation journal.
///
/// `persist` must atomically compare `expected_revision` with the currently
/// loaded journal revision and current fencing lease, durably commit the
/// supplied journal, and advance the revision to a strictly greater value. It
/// must return that new revision only after authenticated, rollback-resistant
/// persistence completes. A buffered write or process-local cache does not
/// satisfy this contract.
///
/// An error must leave the supplied candidate uncommitted. If a backend cannot
/// know whether a failed call committed, it must make the worker discard its
/// session and reload an authenticated snapshot before it permits another
/// compare-and-swap. The runtime poisons its session after any persistence
/// failure so a caller cannot continue from an ambiguous in-memory view.
pub trait WorkerJournalStore {
    type Error;

    fn persist(
        &mut self,
        journal: &WorkerOperationJournal,
        expected_revision: WorkerJournalRevision,
        journal_lease: WorkerJournalLease,
    ) -> Result<WorkerJournalRevision, Self::Error>;
}

/// Adapter failure that leaves durable effects in their prior state.
///
/// An adapter must return an explicit [`OperationStatus::Failed`] only when it
/// knows the external effect did not succeed. `Indeterminate` deliberately
/// leaves a durable operation pending so recovery uses a bounded reconciliation
/// or operator policy rather than blindly running it again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerAdapterError {
    Unsupported(&'static str),
    Indeterminate,
}

impl Display for WorkerAdapterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(operation) => {
                write!(formatter, "worker adapter does not implement {operation}")
            }
            Self::Indeterminate => {
                formatter.write_str("worker adapter could not determine external effect state")
            }
        }
    }
}

impl std::error::Error for WorkerAdapterError {}

/// Explicit safety declaration required before an adapter receives a
/// non-durable [`WorkerAdapter::invoke`] request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerInvocationSafety {
    /// The invocation only reads state or transforms data.
    ReadOnly,
    /// The adapter's external operation is independently idempotent.
    IndependentlyIdempotent,
}

/// Explicit recovery contract required before an adapter receives a durable
/// dispatch or compensation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerDurableOperationContract {
    /// The adapter implements bounded status recovery by `operation_key`.
    Reconciliation,
    /// The adapter propagates `operation_key` to its provider as an
    /// idempotency key and also implements bounded status recovery.
    ProviderIdempotencyAndReconciliation,
}

/// Explicit Rust implementation for one registered worker tool.
///
/// Every method receives the active attenuated grant. Adapters may resolve only
/// its opaque resource selectors through the embedding platform; they must not
/// use script-provided paths, commands, credentials, or ambient authority.
/// [`Self::invoke`] has no durable journal entry and is therefore for
/// read-only or independently idempotent work only. A crash-sensitive external
/// effect must use [`Self::dispatch_operation`] instead. The runtime rejects a
/// request until the corresponding explicit safety contract below is declared.
pub trait WorkerAdapter {
    /// Declares the safety property that permits non-durable invocation.
    fn invocation_safety(&self) -> Option<WorkerInvocationSafety> {
        None
    }

    /// Declares recovery support for durable dispatch and compensation.
    ///
    /// Both variants require a bounded [`Self::reconcile_operation`] handler
    /// keyed by the exact host-provided `operation_key` for durable dispatch.
    /// Compensation additionally needs the adapter-specific or manual recovery
    /// policy documented by the host. The stronger variant also requires
    /// forwarding that key unchanged to the external provider's idempotency
    /// mechanism whenever the provider offers one.
    fn durable_operation_contract(&self) -> Option<WorkerDurableOperationContract> {
        None
    }

    fn invoke(
        &mut self,
        _request: &ToolInvocation,
        _grant: &CapabilityGrant,
    ) -> Result<ToolPayload, WorkerAdapterError> {
        Err(WorkerAdapterError::Unsupported("invoke"))
    }

    fn dispatch_operation(
        &mut self,
        _request: &OperationDispatchRequest,
        _grant: &CapabilityGrant,
    ) -> Result<OperationStatus, WorkerAdapterError> {
        Err(WorkerAdapterError::Unsupported("dispatch_operation"))
    }

    fn compensate_operation(
        &mut self,
        _request: &OperationCompensationRequest,
        _grant: &CapabilityGrant,
    ) -> Result<OperationStatus, WorkerAdapterError> {
        Err(WorkerAdapterError::Unsupported("compensate_operation"))
    }

    fn reconcile_operation(
        &mut self,
        _request: &OperationReconcileRequest,
        _grant: &CapabilityGrant,
    ) -> Result<OperationStatus, WorkerAdapterError> {
        Err(WorkerAdapterError::Unsupported("reconcile_operation"))
    }
}

/// Explicit mapping from a capability name to a trusted Rust adapter.
#[derive(Default)]
pub struct WorkerAdapterRegistry {
    adapters: BTreeMap<String, Box<dyn WorkerAdapter>>,
}

impl WorkerAdapterRegistry {
    pub fn register<A>(
        &mut self,
        tool: impl Into<String>,
        adapter: A,
    ) -> Result<(), WorkerAdapterRegistryError>
    where
        A: WorkerAdapter + 'static,
    {
        self.register_boxed(tool, Box::new(adapter))
    }

    pub fn register_boxed(
        &mut self,
        tool: impl Into<String>,
        adapter: Box<dyn WorkerAdapter>,
    ) -> Result<(), WorkerAdapterRegistryError> {
        let tool = tool.into();
        if !is_valid_tool_name(&tool) {
            return Err(WorkerAdapterRegistryError::InvalidTool(tool));
        }
        if self.adapters.contains_key(&tool) {
            return Err(WorkerAdapterRegistryError::DuplicateTool(tool));
        }
        self.adapters.insert(tool, adapter);
        Ok(())
    }

    pub fn contains(&self, tool: &str) -> bool {
        self.adapters.contains_key(tool)
    }

    fn adapter_mut(&mut self, tool: &str) -> Option<&mut (dyn WorkerAdapter + '_)> {
        let adapter = self.adapters.get_mut(tool)?;
        Some(adapter.as_mut())
    }
}

impl fmt::Debug for WorkerAdapterRegistry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerAdapterRegistry")
            .field("tools", &self.adapters.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Rejection from [`WorkerAdapterRegistry::register`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerAdapterRegistryError {
    InvalidTool(String),
    DuplicateTool(String),
}

impl Display for WorkerAdapterRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTool(tool) => write!(formatter, "invalid worker adapter tool: {tool}"),
            Self::DuplicateTool(tool) => write!(formatter, "duplicate worker adapter tool: {tool}"),
        }
    }
}

impl std::error::Error for WorkerAdapterRegistryError {}

/// Authenticated worker session that owns one manifest, adapter registry, and
/// tenant-scoped durable operation journal.
pub struct WorkerSession {
    authenticator: SessionAuthenticator,
    authorizer: SessionAuthorizer,
    journal: WorkerOperationJournal,
    journal_revision: WorkerJournalRevision,
    journal_lease: WorkerJournalLease,
    adapters: WorkerAdapterRegistry,
    limits: WorkerSessionLimits,
    reconciliations_by_tool: BTreeMap<String, u32>,
    reconciliations_total: u32,
    poisoned: bool,
}

impl WorkerSession {
    /// Opens one worker session from the authenticated host `open_session`
    /// frame.
    ///
    /// The supplied admission policy is the required freshness and tenant
    /// binding check. Load a restored journal with
    /// `WorkerOperationJournal::from_json_for_scope` together with the atomic
    /// storage revision before passing them here.
    pub fn open<A>(
        mut authenticator: SessionAuthenticator,
        opening_frame: AuthenticatedWorkerMessage,
        journal: WorkerOperationJournal,
        journal_revision: WorkerJournalRevision,
        adapters: WorkerAdapterRegistry,
        limits: WorkerSessionLimits,
        admission: &mut A,
    ) -> Result<Self, WorkerSessionOpenError<A::Error>>
    where
        A: WorkerSessionAdmission,
    {
        if authenticator.role() != SessionRole::Worker {
            return Err(WorkerSessionOpenError::RequiresWorkerAuthenticator);
        }
        let message = authenticator
            .open(opening_frame)
            .map_err(WorkerSessionOpenError::Protocol)?;
        let WorkerMessage::OpenSession { manifest } = message else {
            return Err(WorkerSessionOpenError::UnexpectedOpeningMessage);
        };
        let authorizer =
            SessionAuthorizer::new(manifest).map_err(WorkerSessionOpenError::Protocol)?;
        for grant in &authorizer.manifest().grants {
            if !adapters.contains(&grant.tool) {
                return Err(WorkerSessionOpenError::MissingAdapter(grant.tool.clone()));
            }
        }
        let journal_lease = admission
            .admit(authorizer.manifest(), journal.scope())
            .map_err(WorkerSessionOpenError::Admission)?;
        Ok(Self {
            authenticator,
            authorizer,
            journal,
            journal_revision,
            journal_lease,
            adapters,
            limits,
            reconciliations_by_tool: BTreeMap::new(),
            reconciliations_total: 0,
            poisoned: false,
        })
    }

    pub fn manifest(&self) -> &CapabilityManifest {
        self.authorizer.manifest()
    }

    pub fn journal(&self) -> &WorkerOperationJournal {
        &self.journal
    }

    /// Returns the revision expected by the next journal compare-and-swap.
    pub fn journal_revision(&self) -> WorkerJournalRevision {
        self.journal_revision
    }

    /// Returns whether a journal persistence result made this session unsafe
    /// to continue. Discard it and reopen from a fresh authenticated snapshot.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn adapters(&self) -> &WorkerAdapterRegistry {
        &self.adapters
    }

    pub fn into_parts(
        self,
    ) -> (
        SessionAuthenticator,
        WorkerOperationJournal,
        WorkerJournalRevision,
        WorkerJournalLease,
        WorkerAdapterRegistry,
    ) {
        (
            self.authenticator,
            self.journal,
            self.journal_revision,
            self.journal_lease,
            self.adapters,
        )
    }

    /// Opens an authenticated host frame, enforces worker policy, and seals the
    /// matching response. Effectful paths persist journal intent before an
    /// adapter call and persist the observed state before a response.
    pub fn handle<S>(
        &mut self,
        frame: AuthenticatedWorkerMessage,
        journal_store: &mut S,
    ) -> Result<AuthenticatedWorkerMessage, WorkerSessionError<S::Error>>
    where
        S: WorkerJournalStore,
    {
        if self.poisoned {
            return Err(WorkerSessionError::SessionPoisoned);
        }
        let message = self
            .authenticator
            .open(frame)
            .map_err(WorkerSessionError::Protocol)?;
        match message {
            WorkerMessage::Invoke { invocation } => self.handle_invoke::<S::Error>(invocation),
            WorkerMessage::DispatchOperation { request } => {
                self.handle_operation_dispatch(request, journal_store)
            }
            WorkerMessage::CompensateOperation { request } => {
                self.handle_compensation(request, journal_store)
            }
            WorkerMessage::ReconcileOperation { request } => {
                self.handle_reconciliation(request, journal_store)
            }
            WorkerMessage::OpenSession { .. } => {
                Err(WorkerSessionError::UnexpectedMessage("open_session"))
            }
            WorkerMessage::Result { .. } => Err(WorkerSessionError::UnexpectedMessage("result")),
            WorkerMessage::OperationResult { .. } => {
                Err(WorkerSessionError::UnexpectedMessage("operation_result"))
            }
            WorkerMessage::CompensationResult { .. } => {
                Err(WorkerSessionError::UnexpectedMessage("compensation_result"))
            }
            WorkerMessage::ReconciledOperation { .. } => Err(
                WorkerSessionError::UnexpectedMessage("reconciled_operation"),
            ),
            WorkerMessage::Cancel { .. } => Err(WorkerSessionError::UnexpectedMessage("cancel")),
            WorkerMessage::CloseSession { .. } => {
                Err(WorkerSessionError::UnexpectedMessage("close_session"))
            }
        }
    }

    fn handle_invoke<E>(
        &mut self,
        invocation: ToolInvocation,
    ) -> Result<AuthenticatedWorkerMessage, WorkerSessionError<E>> {
        let authorized = self
            .authorizer
            .authorize(invocation)
            .map_err(WorkerSessionError::Protocol)?;
        let request = authorized.invocation().clone();
        let adapter = self
            .adapters
            .adapter_mut(&request.tool)
            .ok_or_else(|| WorkerSessionError::MissingAdapter(request.tool.clone()))?;
        if adapter.invocation_safety().is_none() {
            return Err(WorkerSessionError::InvocationSafetyNotDeclared(
                request.tool.clone(),
            ));
        }
        let payload = adapter
            .invoke(&request, authorized.grant())
            .map_err(|error| WorkerSessionError::Adapter {
                tool: request.tool.clone(),
                error,
            })?;
        let result = ToolResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            payload,
        )
        .map_err(WorkerSessionError::Protocol)?;
        self.authorizer
            .validate_result(&authorized, &result)
            .map_err(WorkerSessionError::Protocol)?;
        self.seal_response(WorkerMessage::Result { result })
    }

    fn handle_operation_dispatch<S>(
        &mut self,
        request: OperationDispatchRequest,
        journal_store: &mut S,
    ) -> Result<AuthenticatedWorkerMessage, WorkerSessionError<S::Error>>
    where
        S: WorkerJournalStore,
    {
        let authorized = self
            .authorizer
            .authorize_operation(request)
            .map_err(WorkerSessionError::Protocol)?;
        let request = authorized.request().clone();
        if self
            .adapters
            .adapter_mut(&request.tool)
            .ok_or_else(|| WorkerSessionError::MissingAdapter(request.tool.clone()))?
            .durable_operation_contract()
            .is_none()
        {
            return Err(WorkerSessionError::DurableOperationContractNotDeclared(
                request.tool.clone(),
            ));
        }
        let journal_before_admission = self.journal.clone();
        let status = match self
            .journal
            .admit(&authorized)
            .map_err(WorkerSessionError::Protocol)?
        {
            WorkerOperationAdmission::Dispatch => {
                self.persist_admission(journal_before_admission, journal_store)?;
                let status = match self
                    .adapters
                    .adapter_mut(&request.tool)
                    .ok_or_else(|| WorkerSessionError::MissingAdapter(request.tool.clone()))?
                    .dispatch_operation(&request, authorized.grant())
                {
                    Ok(status) => status,
                    Err(WorkerAdapterError::Indeterminate) => {
                        return Err(WorkerSessionError::IndeterminateOperation {
                            operation_key: request.operation_key.clone(),
                            cause: WorkerIndeterminateCause::Adapter(
                                WorkerAdapterError::Indeterminate,
                            ),
                        });
                    }
                    Err(error) => {
                        return Err(WorkerSessionError::Adapter {
                            tool: request.tool.clone(),
                            error,
                        });
                    }
                };
                let journal_before_observation = self.journal.clone();
                self.journal
                    .observe(&authorized, status.clone())
                    .map_err(|error| WorkerSessionError::IndeterminateOperation {
                        operation_key: request.operation_key.clone(),
                        cause: WorkerIndeterminateCause::Protocol(error),
                    })?;
                self.persist_observation(journal_before_observation, journal_store)
                    .map_err(|error| WorkerSessionError::IndeterminateOperation {
                        operation_key: request.operation_key.clone(),
                        cause: WorkerIndeterminateCause::from_persistence_failure(error),
                    })?;
                status
            }
            WorkerOperationAdmission::Existing { state } => state.as_status().ok_or_else(|| {
                WorkerSessionError::PendingOperation(request.operation_key.clone())
            })?,
        };
        let result = OperationReconcileResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            request.tool.clone(),
            request.operation_key.clone(),
            status,
        )
        .map_err(WorkerSessionError::Protocol)?;
        self.authorizer
            .validate_operation_result(&authorized, &result)
            .map_err(WorkerSessionError::Protocol)?;
        self.seal_response(WorkerMessage::OperationResult { result })
    }

    fn handle_compensation<S>(
        &mut self,
        request: OperationCompensationRequest,
        journal_store: &mut S,
    ) -> Result<AuthenticatedWorkerMessage, WorkerSessionError<S::Error>>
    where
        S: WorkerJournalStore,
    {
        let authorized = self
            .authorizer
            .authorize_compensation(request)
            .map_err(WorkerSessionError::Protocol)?;
        let request = authorized.request().clone();
        if self
            .adapters
            .adapter_mut(&request.tool)
            .ok_or_else(|| WorkerSessionError::MissingAdapter(request.tool.clone()))?
            .durable_operation_contract()
            .is_none()
        {
            return Err(WorkerSessionError::DurableOperationContractNotDeclared(
                request.tool.clone(),
            ));
        }
        let journal_before_admission = self.journal.clone();
        let status = match self
            .journal
            .admit_compensation(&authorized)
            .map_err(WorkerSessionError::Protocol)?
        {
            WorkerCompensationAdmission::Dispatch => {
                self.persist_admission(journal_before_admission, journal_store)?;
                let status = match self
                    .adapters
                    .adapter_mut(&request.tool)
                    .ok_or_else(|| WorkerSessionError::MissingAdapter(request.tool.clone()))?
                    .compensate_operation(&request, authorized.grant())
                {
                    Ok(status) => status,
                    Err(WorkerAdapterError::Indeterminate) => {
                        return Err(WorkerSessionError::IndeterminateCompensation {
                            operation_key: request.operation_key.clone(),
                            compensation_key: request.compensation_key.clone(),
                            cause: WorkerIndeterminateCause::Adapter(
                                WorkerAdapterError::Indeterminate,
                            ),
                        });
                    }
                    Err(error) => {
                        return Err(WorkerSessionError::Adapter {
                            tool: request.tool.clone(),
                            error,
                        });
                    }
                };
                let journal_before_observation = self.journal.clone();
                self.journal
                    .observe_compensation(&authorized, status.clone())
                    .map_err(|error| WorkerSessionError::IndeterminateCompensation {
                        operation_key: request.operation_key.clone(),
                        compensation_key: request.compensation_key.clone(),
                        cause: WorkerIndeterminateCause::Protocol(error),
                    })?;
                self.persist_observation(journal_before_observation, journal_store)
                    .map_err(|error| WorkerSessionError::IndeterminateCompensation {
                        operation_key: request.operation_key.clone(),
                        compensation_key: request.compensation_key.clone(),
                        cause: WorkerIndeterminateCause::from_persistence_failure(error),
                    })?;
                status
            }
            WorkerCompensationAdmission::Existing { state } => {
                state.as_status().ok_or_else(|| {
                    WorkerSessionError::PendingCompensation(request.operation_key.clone())
                })?
            }
        };
        let binding = splash_protocol::OperationCompensationBinding::new(
            request.tool.clone(),
            request.operation_key.clone(),
            request.compensation_key.clone(),
            request.tenant_scope.clone(),
            request.grant_fingerprint.clone(),
        )
        .map_err(WorkerSessionError::Protocol)?;
        let result = OperationCompensationResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            binding,
            status,
        )
        .map_err(WorkerSessionError::Protocol)?;
        self.authorizer
            .validate_compensation_result(&authorized, &result)
            .map_err(WorkerSessionError::Protocol)?;
        self.seal_response(WorkerMessage::CompensationResult { result })
    }

    fn handle_reconciliation<S>(
        &mut self,
        request: OperationReconcileRequest,
        journal_store: &mut S,
    ) -> Result<AuthenticatedWorkerMessage, WorkerSessionError<S::Error>>
    where
        S: WorkerJournalStore,
    {
        let authorized = self
            .authorizer
            .authorize_reconciliation(request)
            .map_err(WorkerSessionError::Protocol)?;
        let request = authorized.request().clone();
        self.journal
            .validate_reconciliation(&authorized)
            .map_err(WorkerSessionError::Protocol)?;
        self.reserve_reconciliation(&request.tool)?;
        let status = self
            .adapters
            .adapter_mut(&request.tool)
            .ok_or_else(|| WorkerSessionError::MissingAdapter(request.tool.clone()))?
            .reconcile_operation(&request, authorized.grant())
            .map_err(|error| WorkerSessionError::Adapter {
                tool: request.tool.clone(),
                error,
            })?;
        let journal_before_observation = self.journal.clone();
        self.journal
            .observe_reconciliation(&authorized, status.clone())
            .map_err(WorkerSessionError::Protocol)?;
        self.persist_observation(journal_before_observation, journal_store)
            .map_err(WorkerSessionError::from_persistence_failure)?;
        let result = OperationReconcileResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            request.tool.clone(),
            request.operation_key.clone(),
            status,
        )
        .map_err(WorkerSessionError::Protocol)?;
        self.authorizer
            .validate_reconciliation_result(&authorized, &result)
            .map_err(WorkerSessionError::Protocol)?;
        self.seal_response(WorkerMessage::ReconciledOperation { result })
    }

    fn persist_admission<S>(
        &mut self,
        journal_before_admission: WorkerOperationJournal,
        journal_store: &mut S,
    ) -> Result<(), WorkerSessionError<S::Error>>
    where
        S: WorkerJournalStore,
    {
        self.persist_journal(journal_before_admission, journal_store)
            .map_err(WorkerSessionError::from_persistence_failure)
    }

    fn persist_observation<S>(
        &mut self,
        journal_before_observation: WorkerOperationJournal,
        journal_store: &mut S,
    ) -> Result<(), JournalPersistenceFailure<S::Error>>
    where
        S: WorkerJournalStore,
    {
        self.persist_journal(journal_before_observation, journal_store)
    }

    fn persist_journal<S>(
        &mut self,
        journal_before_persistence: WorkerOperationJournal,
        journal_store: &mut S,
    ) -> Result<(), JournalPersistenceFailure<S::Error>>
    where
        S: WorkerJournalStore,
    {
        let expected_revision = self.journal_revision;
        match journal_store.persist(&self.journal, expected_revision, self.journal_lease) {
            Ok(actual_revision) if actual_revision > expected_revision => {
                self.journal_revision = actual_revision;
                Ok(())
            }
            Ok(actual_revision) => {
                self.journal = journal_before_persistence;
                self.poisoned = true;
                Err(JournalPersistenceFailure::InvalidRevision {
                    expected: expected_revision,
                    actual: actual_revision,
                })
            }
            Err(error) => {
                self.journal = journal_before_persistence;
                self.poisoned = true;
                Err(JournalPersistenceFailure::Store(error))
            }
        }
    }

    fn reserve_reconciliation<E>(&mut self, tool: &str) -> Result<(), WorkerSessionError<E>> {
        if self.reconciliations_total >= self.limits.max_reconciliations_per_session() {
            return Err(WorkerSessionError::ReconciliationSessionBudgetExhausted {
                maximum: self.limits.max_reconciliations_per_session(),
            });
        }
        let reconciliations = self
            .reconciliations_by_tool
            .entry(tool.to_owned())
            .or_default();
        if *reconciliations >= self.limits.max_reconciliations_per_tool() {
            return Err(WorkerSessionError::ReconciliationBudgetExhausted {
                tool: tool.to_owned(),
                maximum: self.limits.max_reconciliations_per_tool(),
            });
        }
        *reconciliations = reconciliations.saturating_add(1);
        self.reconciliations_total = self.reconciliations_total.saturating_add(1);
        Ok(())
    }

    fn seal_response<E>(
        &mut self,
        response: WorkerMessage,
    ) -> Result<AuthenticatedWorkerMessage, WorkerSessionError<E>> {
        self.authenticator
            .seal(response)
            .map_err(WorkerSessionError::Protocol)
    }
}

impl fmt::Debug for WorkerSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerSession")
            .field("session_id", &self.authenticator.session_id())
            .field("journal_scope", &self.journal.scope())
            .field("journal_revision", &self.journal_revision)
            .field("journal_lease", &self.journal_lease)
            .field("adapter_count", &self.adapters.adapters.len())
            .field(
                "max_reconciliations_per_tool",
                &self.limits.max_reconciliations_per_tool(),
            )
            .field(
                "max_reconciliations_per_session",
                &self.limits.max_reconciliations_per_session(),
            )
            .field("reconciliations_total", &self.reconciliations_total)
            .field("poisoned", &self.poisoned)
            .finish()
    }
}

/// Error while opening a worker session.
#[derive(Debug)]
pub enum WorkerSessionOpenError<E> {
    RequiresWorkerAuthenticator,
    Protocol(ProtocolError),
    UnexpectedOpeningMessage,
    MissingAdapter(String),
    Admission(E),
}

impl<E: Display> Display for WorkerSessionOpenError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiresWorkerAuthenticator => {
                formatter.write_str("worker session requires a worker-role authenticator")
            }
            Self::Protocol(error) => {
                write!(formatter, "worker protocol rejected session open: {error}")
            }
            Self::UnexpectedOpeningMessage => {
                formatter.write_str("worker session must begin with an open_session frame")
            }
            Self::MissingAdapter(tool) => {
                write!(
                    formatter,
                    "worker session manifest grants unregistered adapter {tool}"
                )
            }
            Self::Admission(error) => write!(formatter, "worker session admission denied: {error}"),
        }
    }
}

impl<E> std::error::Error for WorkerSessionOpenError<E> where E: std::error::Error + 'static {}

/// Error while processing one authenticated host frame.
#[derive(Debug)]
pub enum WorkerSessionError<E> {
    Protocol(ProtocolError),
    Journal(E),
    InvalidJournalRevision {
        expected: WorkerJournalRevision,
        actual: WorkerJournalRevision,
    },
    SessionPoisoned,
    MissingAdapter(String),
    InvocationSafetyNotDeclared(String),
    DurableOperationContractNotDeclared(String),
    Adapter {
        tool: String,
        error: WorkerAdapterError,
    },
    IndeterminateOperation {
        operation_key: String,
        cause: WorkerIndeterminateCause<E>,
    },
    IndeterminateCompensation {
        operation_key: String,
        compensation_key: String,
        cause: WorkerIndeterminateCause<E>,
    },
    PendingOperation(String),
    PendingCompensation(String),
    ReconciliationBudgetExhausted {
        tool: String,
        maximum: u32,
    },
    ReconciliationSessionBudgetExhausted {
        maximum: u32,
    },
    UnexpectedMessage(&'static str),
}

impl<E: Display> Display for WorkerSessionError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "worker protocol rejected frame: {error}"),
            Self::Journal(error) => write!(formatter, "worker journal persistence failed: {error}"),
            Self::InvalidJournalRevision { expected, actual } => write!(
                formatter,
                "worker journal store returned non-incrementing revision {} after {}",
                actual.get(),
                expected.get()
            ),
            Self::SessionPoisoned => formatter.write_str(
                "worker session is poisoned after journal persistence failure and must be reopened"
            ),
            Self::MissingAdapter(tool) => {
                write!(formatter, "no worker adapter registered for {tool}")
            }
            Self::InvocationSafetyNotDeclared(tool) => write!(
                formatter,
                "worker adapter {tool} did not declare non-durable invocation safety"
            ),
            Self::DurableOperationContractNotDeclared(tool) => write!(
                formatter,
                "worker adapter {tool} did not declare a durable operation recovery contract"
            ),
            Self::Adapter { tool, error } => {
                write!(formatter, "worker adapter {tool} failed: {error}")
            }
            Self::IndeterminateOperation {
                operation_key,
                cause,
            } => write!(
                formatter,
                "worker operation {operation_key} may have completed and requires reconciliation: {cause}"
            ),
            Self::IndeterminateCompensation {
                operation_key,
                compensation_key,
                cause,
            } => write!(
                formatter,
                "worker compensation {compensation_key} for {operation_key} may have completed and requires adapter-specific recovery: {cause}"
            ),
            Self::PendingOperation(operation_key) => write!(
                formatter,
                "worker operation {operation_key} is pending and requires reconciliation"
            ),
            Self::PendingCompensation(operation_key) => write!(
                formatter,
                "worker compensation for {operation_key} is pending and requires reconciliation"
            ),
            Self::ReconciliationBudgetExhausted { tool, maximum } => write!(
                formatter,
                "worker tool {tool} exhausted its {maximum} reconciliation budget"
            ),
            Self::ReconciliationSessionBudgetExhausted { maximum } => write!(
                formatter,
                "worker session exhausted its {maximum} reconciliation budget"
            ),
            Self::UnexpectedMessage(message) => {
                write!(formatter, "worker cannot accept incoming {message} message")
            }
        }
    }
}

impl<E> std::error::Error for WorkerSessionError<E> where E: std::error::Error + 'static {}

/// Cause retained when an adapter may have acted but the worker cannot safely
/// report a durable terminal observation.
#[derive(Debug)]
pub enum WorkerIndeterminateCause<E> {
    Adapter(WorkerAdapterError),
    Protocol(ProtocolError),
    Journal(E),
    InvalidJournalRevision {
        expected: WorkerJournalRevision,
        actual: WorkerJournalRevision,
    },
}

impl<E: Display> Display for WorkerIndeterminateCause<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adapter(error) => {
                write!(formatter, "adapter reported indeterminate state: {error}")
            }
            Self::Protocol(error) => write!(
                formatter,
                "worker could not validate the observed state: {error}"
            ),
            Self::Journal(error) => write!(
                formatter,
                "worker could not persist the observed state: {error}"
            ),
            Self::InvalidJournalRevision { expected, actual } => write!(
                formatter,
                "worker journal store returned non-incrementing revision {} after {}",
                actual.get(),
                expected.get()
            ),
        }
    }
}

impl<E> std::error::Error for WorkerIndeterminateCause<E> where E: std::error::Error + 'static {}

enum JournalPersistenceFailure<E> {
    Store(E),
    InvalidRevision {
        expected: WorkerJournalRevision,
        actual: WorkerJournalRevision,
    },
}

impl<E> WorkerSessionError<E> {
    fn from_persistence_failure(failure: JournalPersistenceFailure<E>) -> Self {
        match failure {
            JournalPersistenceFailure::Store(error) => Self::Journal(error),
            JournalPersistenceFailure::InvalidRevision { expected, actual } => {
                Self::InvalidJournalRevision { expected, actual }
            }
        }
    }
}

impl<E> WorkerIndeterminateCause<E> {
    fn from_persistence_failure(failure: JournalPersistenceFailure<E>) -> Self {
        match failure {
            JournalPersistenceFailure::Store(error) => Self::Journal(error),
            JournalPersistenceFailure::InvalidRevision { expected, actual } => {
                Self::InvalidJournalRevision { expected, actual }
            }
        }
    }
}

fn is_valid_tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::rc::Rc;

    use super::*;
    use splash_protocol::{
        OperationCompensationBinding, SessionKey, WorkerOperationState, AUTH_TAG_BYTES,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AdmissionError {
        Replay,
    }

    impl Display for AdmissionError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("replayed session")
        }
    }

    impl std::error::Error for AdmissionError {}

    #[derive(Default)]
    struct OneTimeAdmission {
        admitted: BTreeSet<(String, String)>,
        next_lease: u64,
    }

    impl WorkerSessionAdmission for OneTimeAdmission {
        type Error = AdmissionError;

        fn admit(
            &mut self,
            manifest: &CapabilityManifest,
            journal_scope: &str,
        ) -> Result<WorkerJournalLease, Self::Error> {
            if self
                .admitted
                .insert((manifest.session_id.clone(), journal_scope.to_owned()))
            {
                self.next_lease = self.next_lease.saturating_add(1);
                Ok(WorkerJournalLease::new(self.next_lease))
            } else {
                Err(AdmissionError::Replay)
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum JournalError {
        Unavailable,
        RevisionConflict,
        LeaseExpired,
    }

    impl Display for JournalError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            match self {
                Self::Unavailable => formatter.write_str("journal store unavailable"),
                Self::RevisionConflict => formatter.write_str("journal revision conflict"),
                Self::LeaseExpired => formatter.write_str("journal lease expired"),
            }
        }
    }

    impl std::error::Error for JournalError {}

    struct MemoryJournalStore {
        snapshots: Vec<WorkerOperationJournal>,
        fail_on_attempt: Option<usize>,
        persist_attempts: usize,
        revision: WorkerJournalRevision,
        reported_revision: Option<WorkerJournalRevision>,
        active_lease: WorkerJournalLease,
    }

    impl Default for MemoryJournalStore {
        fn default() -> Self {
            Self {
                snapshots: Vec::new(),
                fail_on_attempt: None,
                persist_attempts: 0,
                revision: WorkerJournalRevision::default(),
                reported_revision: None,
                active_lease: WorkerJournalLease::new(1),
            }
        }
    }

    impl WorkerJournalStore for MemoryJournalStore {
        type Error = JournalError;

        fn persist(
            &mut self,
            journal: &WorkerOperationJournal,
            expected_revision: WorkerJournalRevision,
            journal_lease: WorkerJournalLease,
        ) -> Result<WorkerJournalRevision, Self::Error> {
            if journal_lease != self.active_lease {
                return Err(JournalError::LeaseExpired);
            }
            if expected_revision != self.revision {
                return Err(JournalError::RevisionConflict);
            }
            self.persist_attempts = self.persist_attempts.saturating_add(1);
            if self.fail_on_attempt == Some(self.persist_attempts) {
                return Err(JournalError::Unavailable);
            }
            self.snapshots.push(journal.clone());
            self.revision = WorkerJournalRevision::new(self.revision.get().saturating_add(1));
            Ok(self.reported_revision.unwrap_or(self.revision))
        }
    }

    #[derive(Default)]
    struct AdapterCounts {
        invokes: usize,
        dispatches: usize,
        compensations: usize,
        reconciliations: usize,
        dispatch_status: Option<OperationStatus>,
        dispatch_error: Option<WorkerAdapterError>,
    }

    struct TestAdapter {
        counts: Rc<RefCell<AdapterCounts>>,
    }

    struct UnqualifiedAdapter;

    impl WorkerAdapter for UnqualifiedAdapter {}

    impl WorkerAdapter for TestAdapter {
        fn invocation_safety(&self) -> Option<WorkerInvocationSafety> {
            Some(WorkerInvocationSafety::ReadOnly)
        }

        fn durable_operation_contract(&self) -> Option<WorkerDurableOperationContract> {
            Some(WorkerDurableOperationContract::Reconciliation)
        }

        fn invoke(
            &mut self,
            request: &ToolInvocation,
            _grant: &CapabilityGrant,
        ) -> Result<ToolPayload, WorkerAdapterError> {
            self.counts.borrow_mut().invokes += 1;
            Ok(request.payload.clone())
        }

        fn dispatch_operation(
            &mut self,
            _request: &OperationDispatchRequest,
            _grant: &CapabilityGrant,
        ) -> Result<OperationStatus, WorkerAdapterError> {
            let mut counts = self.counts.borrow_mut();
            counts.dispatches += 1;
            if let Some(error) = counts.dispatch_error {
                return Err(error);
            }
            Ok(counts
                .dispatch_status
                .clone()
                .unwrap_or(OperationStatus::Succeeded {
                    payload: ToolPayload::Text("done".to_owned()),
                }))
        }

        fn compensate_operation(
            &mut self,
            _request: &OperationCompensationRequest,
            _grant: &CapabilityGrant,
        ) -> Result<OperationStatus, WorkerAdapterError> {
            self.counts.borrow_mut().compensations += 1;
            Ok(OperationStatus::Succeeded {
                payload: ToolPayload::Text("undone".to_owned()),
            })
        }

        fn reconcile_operation(
            &mut self,
            _request: &OperationReconcileRequest,
            _grant: &CapabilityGrant,
        ) -> Result<OperationStatus, WorkerAdapterError> {
            self.counts.borrow_mut().reconciliations += 1;
            Ok(OperationStatus::Running)
        }
    }

    fn grant() -> CapabilityGrant {
        let mut grant = CapabilityGrant::text("text.echo").with_compensation_limit(1);
        grant.max_calls = 4;
        grant
    }

    fn open_worker(
        grant: CapabilityGrant,
        limits: WorkerSessionLimits,
        counts: Rc<RefCell<AdapterCounts>>,
    ) -> (WorkerSession, SessionAuthenticator) {
        let key = SessionKey::from_bytes([31; AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let worker_auth = SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();
        let manifest = CapabilityManifest::new("worker-1", vec![grant]).unwrap();
        let opening = host.seal(WorkerMessage::OpenSession { manifest }).unwrap();
        let mut adapters = WorkerAdapterRegistry::default();
        adapters
            .register("text.echo", TestAdapter { counts })
            .unwrap();
        let mut admission = OneTimeAdmission::default();
        let worker = WorkerSession::open(
            worker_auth,
            opening,
            WorkerOperationJournal::new("tenant-release").unwrap(),
            WorkerJournalRevision::default(),
            adapters,
            limits,
            &mut admission,
        )
        .unwrap();
        (worker, host)
    }

    fn dispatch_request(request_id: &str) -> OperationDispatchRequest {
        OperationDispatchRequest::new(
            "worker-1",
            request_id,
            "text.echo",
            "op-release-42",
            ToolPayload::Text("release".to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn durable_dispatch_persists_before_execution_and_deduplicates_terminal_replays() {
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let (mut worker, mut host) =
            open_worker(grant(), WorkerSessionLimits::default(), counts.clone());
        let mut store = MemoryJournalStore::default();

        let first = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        let response = worker.handle(first, &mut store).unwrap();
        let WorkerMessage::OperationResult { result } = host.open(response).unwrap() else {
            panic!("worker must return an operation result");
        };
        assert!(matches!(result.status, OperationStatus::Succeeded { .. }));
        assert_eq!(counts.borrow().dispatches, 1);
        assert_eq!(store.snapshots.len(), 2);
        assert_eq!(
            store.snapshots[0]
                .operation("op-release-42")
                .unwrap()
                .state(),
            &WorkerOperationState::Pending
        );
        assert!(matches!(
            store.snapshots[1]
                .operation("op-release-42")
                .unwrap()
                .state(),
            WorkerOperationState::Succeeded { .. }
        ));

        let replay = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-2"),
            })
            .unwrap();
        let response = worker.handle(replay, &mut store).unwrap();
        let WorkerMessage::OperationResult { result } = host.open(response).unwrap() else {
            panic!("worker must return an operation result");
        };
        assert!(matches!(result.status, OperationStatus::Succeeded { .. }));
        assert_eq!(counts.borrow().dispatches, 1);
        assert_eq!(store.snapshots.len(), 2);
    }

    #[test]
    fn failed_admission_persistence_restores_memory_before_an_adapter_runs() {
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let (mut worker, mut host) =
            open_worker(grant(), WorkerSessionLimits::default(), counts.clone());
        let mut store = MemoryJournalStore {
            fail_on_attempt: Some(1),
            ..Default::default()
        };

        let frame = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(frame, &mut store),
            Err(WorkerSessionError::Journal(JournalError::Unavailable))
        ));
        assert!(worker.journal().operation("op-release-42").is_none());
        assert_eq!(counts.borrow().dispatches, 0);
        assert!(worker.is_poisoned());
    }

    #[test]
    fn nonincrementing_journal_revisions_poison_before_an_adapter_runs() {
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let (mut worker, mut host) =
            open_worker(grant(), WorkerSessionLimits::default(), counts.clone());
        let mut store = MemoryJournalStore {
            reported_revision: Some(WorkerJournalRevision::default()),
            ..Default::default()
        };

        let frame = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(frame, &mut store),
            Err(WorkerSessionError::InvalidJournalRevision { expected, actual })
                if expected == WorkerJournalRevision::default()
                    && actual == WorkerJournalRevision::default()
        ));
        assert!(worker.journal().operation("op-release-42").is_none());
        assert_eq!(counts.borrow().dispatches, 0);
        assert!(worker.is_poisoned());
    }

    #[test]
    fn stale_journal_revisions_poison_before_an_adapter_runs() {
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let (mut worker, mut host) =
            open_worker(grant(), WorkerSessionLimits::default(), counts.clone());
        let mut store = MemoryJournalStore {
            revision: WorkerJournalRevision::new(1),
            ..Default::default()
        };

        let frame = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(frame, &mut store),
            Err(WorkerSessionError::Journal(JournalError::RevisionConflict))
        ));
        assert!(worker.journal().operation("op-release-42").is_none());
        assert_eq!(counts.borrow().dispatches, 0);
        assert!(worker.is_poisoned());
    }

    #[test]
    fn expired_journal_lease_poison_before_an_adapter_runs() {
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let (mut worker, mut host) =
            open_worker(grant(), WorkerSessionLimits::default(), counts.clone());
        let mut store = MemoryJournalStore {
            active_lease: WorkerJournalLease::new(2),
            ..Default::default()
        };

        let frame = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(frame, &mut store),
            Err(WorkerSessionError::Journal(JournalError::LeaseExpired))
        ));
        assert!(worker.journal().operation("op-release-42").is_none());
        assert_eq!(counts.borrow().dispatches, 0);
        assert!(worker.is_poisoned());
    }

    #[test]
    fn failed_post_effect_persistence_keeps_the_operation_pending_for_reconciliation() {
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let (mut worker, mut host) =
            open_worker(grant(), WorkerSessionLimits::default(), counts.clone());
        let mut store = MemoryJournalStore {
            fail_on_attempt: Some(2),
            ..Default::default()
        };

        let dispatch = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(dispatch, &mut store),
            Err(WorkerSessionError::IndeterminateOperation {
                operation_key,
                cause: WorkerIndeterminateCause::Journal(JournalError::Unavailable),
            }) if operation_key == "op-release-42"
        ));
        assert_eq!(counts.borrow().dispatches, 1);
        assert_eq!(
            worker.journal().operation("op-release-42").unwrap().state(),
            &WorkerOperationState::Pending
        );
        assert_eq!(store.snapshots.len(), 1);
        assert!(worker.is_poisoned());
        let reconciliation = host
            .seal(WorkerMessage::ReconcileOperation {
                request: OperationReconcileRequest::new(
                    "worker-1",
                    "reconcile-1",
                    "text.echo",
                    "op-release-42",
                )
                .unwrap(),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(reconciliation, &mut store),
            Err(WorkerSessionError::SessionPoisoned)
        ));
        assert_eq!(counts.borrow().reconciliations, 0);
    }

    #[test]
    fn indeterminate_adapter_result_leaves_the_persisted_operation_pending() {
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let (mut worker, mut host) =
            open_worker(grant(), WorkerSessionLimits::default(), counts.clone());
        counts.borrow_mut().dispatch_error = Some(WorkerAdapterError::Indeterminate);
        let mut store = MemoryJournalStore::default();

        let dispatch = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(dispatch, &mut store),
            Err(WorkerSessionError::IndeterminateOperation {
                operation_key,
                cause: WorkerIndeterminateCause::Adapter(WorkerAdapterError::Indeterminate),
            }) if operation_key == "op-release-42"
        ));
        assert_eq!(counts.borrow().dispatches, 1);
        assert_eq!(
            worker.journal().operation("op-release-42").unwrap().state(),
            &WorkerOperationState::Pending
        );
        assert_eq!(store.snapshots.len(), 1);
    }

    #[test]
    fn exact_compensation_retransmission_uses_one_effect_budget_and_one_adapter_call() {
        let grant = grant();
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let (mut worker, mut host) = open_worker(
            grant.clone(),
            WorkerSessionLimits::default(),
            counts.clone(),
        );
        let mut store = MemoryJournalStore::default();
        let dispatch = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        let dispatch_response = worker.handle(dispatch, &mut store).unwrap();
        host.open(dispatch_response).unwrap();

        let binding = OperationCompensationBinding::new(
            "text.echo",
            "op-release-42",
            "cmp-release-42-undo",
            "tenant-release",
            grant.compensation_fingerprint().unwrap(),
        )
        .unwrap();
        let first_request = OperationCompensationRequest::new(
            "worker-1",
            "compensation-1",
            binding.clone(),
            ToolPayload::Text("undo".to_owned()),
        )
        .unwrap();
        let first = host
            .seal(WorkerMessage::CompensateOperation {
                request: first_request,
            })
            .unwrap();
        let response = worker.handle(first, &mut store).unwrap();
        let WorkerMessage::CompensationResult { result } = host.open(response).unwrap() else {
            panic!("worker must return a compensation result");
        };
        assert!(matches!(result.status, OperationStatus::Succeeded { .. }));

        let replay_request = OperationCompensationRequest::new(
            "worker-1",
            "compensation-2",
            binding,
            ToolPayload::Text("undo".to_owned()),
        )
        .unwrap();
        let replay = host
            .seal(WorkerMessage::CompensateOperation {
                request: replay_request,
            })
            .unwrap();
        let response = worker.handle(replay, &mut store).unwrap();
        let WorkerMessage::CompensationResult { result } = host.open(response).unwrap() else {
            panic!("worker must return a compensation result");
        };
        assert!(matches!(result.status, OperationStatus::Succeeded { .. }));
        assert_eq!(counts.borrow().compensations, 1);
    }

    #[test]
    fn reconciliation_is_rate_limited_and_authenticated() {
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let limits = WorkerSessionLimits::new(1).unwrap();
        let (mut worker, mut host) = open_worker(grant(), limits, counts.clone());
        let mut store = MemoryJournalStore::default();
        counts.borrow_mut().dispatch_status = Some(OperationStatus::Running);
        let dispatch = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        let dispatch_response = worker.handle(dispatch, &mut store).unwrap();
        host.open(dispatch_response).unwrap();
        let first_request =
            OperationReconcileRequest::new("worker-1", "reconcile-1", "text.echo", "op-release-42")
                .unwrap();
        let first = host
            .seal(WorkerMessage::ReconcileOperation {
                request: first_request,
            })
            .unwrap();
        let response = worker.handle(first, &mut store).unwrap();
        let WorkerMessage::ReconciledOperation { result } = host.open(response).unwrap() else {
            panic!("worker must return a reconciliation result");
        };
        assert_eq!(result.status, OperationStatus::Running);

        let second_request =
            OperationReconcileRequest::new("worker-1", "reconcile-2", "text.echo", "op-release-42")
                .unwrap();
        let second = host
            .seal(WorkerMessage::ReconcileOperation {
                request: second_request,
            })
            .unwrap();
        assert!(matches!(
            worker.handle(second, &mut store),
            Err(WorkerSessionError::ReconciliationBudgetExhausted {
                tool,
                maximum: 1,
            }) if tool == "text.echo"
        ));
        assert_eq!(counts.borrow().reconciliations, 1);
    }

    #[test]
    fn reconciliation_has_a_separate_session_wide_budget() {
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let limits = WorkerSessionLimits::with_limits(2, 1).unwrap();
        let (mut worker, mut host) = open_worker(grant(), limits, counts.clone());
        let mut store = MemoryJournalStore::default();
        counts.borrow_mut().dispatch_status = Some(OperationStatus::Running);
        let dispatch = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        let dispatch_response = worker.handle(dispatch, &mut store).unwrap();
        host.open(dispatch_response).unwrap();

        let first = host
            .seal(WorkerMessage::ReconcileOperation {
                request: OperationReconcileRequest::new(
                    "worker-1",
                    "reconcile-1",
                    "text.echo",
                    "op-release-42",
                )
                .unwrap(),
            })
            .unwrap();
        let response = worker.handle(first, &mut store).unwrap();
        host.open(response).unwrap();

        let second = host
            .seal(WorkerMessage::ReconcileOperation {
                request: OperationReconcileRequest::new(
                    "worker-1",
                    "reconcile-2",
                    "text.echo",
                    "op-release-42",
                )
                .unwrap(),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(second, &mut store),
            Err(WorkerSessionError::ReconciliationSessionBudgetExhausted { maximum: 1 })
        ));
        assert_eq!(counts.borrow().reconciliations, 1);
    }

    #[test]
    fn session_admission_rejects_a_replayed_opening_frame() {
        let key = SessionKey::from_bytes([37; AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let manifest = CapabilityManifest::new("worker-1", vec![grant()]).unwrap();
        let opening = host.seal(WorkerMessage::OpenSession { manifest }).unwrap();
        let counts = Rc::new(RefCell::new(AdapterCounts::default()));
        let mut adapters = WorkerAdapterRegistry::default();
        adapters
            .register(
                "text.echo",
                TestAdapter {
                    counts: counts.clone(),
                },
            )
            .unwrap();
        let mut admission = OneTimeAdmission::default();
        let first_worker =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Worker).unwrap();
        WorkerSession::open(
            first_worker,
            opening.clone(),
            WorkerOperationJournal::new("tenant-release").unwrap(),
            WorkerJournalRevision::default(),
            adapters,
            WorkerSessionLimits::default(),
            &mut admission,
        )
        .unwrap();

        let mut replay_adapters = WorkerAdapterRegistry::default();
        replay_adapters
            .register("text.echo", TestAdapter { counts })
            .unwrap();
        let replay_worker =
            SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();
        assert!(matches!(
            WorkerSession::open(
                replay_worker,
                opening,
                WorkerOperationJournal::new("tenant-release").unwrap(),
                WorkerJournalRevision::default(),
                replay_adapters,
                WorkerSessionLimits::default(),
                &mut admission,
            ),
            Err(WorkerSessionOpenError::Admission(AdmissionError::Replay))
        ));
    }

    #[test]
    fn session_open_rejects_a_grant_without_a_registered_adapter() {
        let key = SessionKey::from_bytes([41; AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let worker = SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();
        let manifest = CapabilityManifest::new("worker-1", vec![grant()]).unwrap();
        let opening = host.seal(WorkerMessage::OpenSession { manifest }).unwrap();
        let mut admission = OneTimeAdmission::default();

        assert!(matches!(
            WorkerSession::open(
                worker,
                opening,
                WorkerOperationJournal::new("tenant-release").unwrap(),
                WorkerJournalRevision::default(),
                WorkerAdapterRegistry::default(),
                WorkerSessionLimits::default(),
                &mut admission,
            ),
            Err(WorkerSessionOpenError::MissingAdapter(tool)) if tool == "text.echo"
        ));
    }

    #[test]
    fn adapters_must_declare_invocation_and_durable_recovery_contracts() {
        let key = SessionKey::from_bytes([43; AUTH_TAG_BYTES]).unwrap();
        let mut host =
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap();
        let worker_auth = SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap();
        let manifest = CapabilityManifest::new("worker-1", vec![grant()]).unwrap();
        let opening = host.seal(WorkerMessage::OpenSession { manifest }).unwrap();
        let mut adapters = WorkerAdapterRegistry::default();
        adapters.register("text.echo", UnqualifiedAdapter).unwrap();
        let mut admission = OneTimeAdmission::default();
        let mut worker = WorkerSession::open(
            worker_auth,
            opening,
            WorkerOperationJournal::new("tenant-release").unwrap(),
            WorkerJournalRevision::default(),
            adapters,
            WorkerSessionLimits::default(),
            &mut admission,
        )
        .unwrap();
        let mut store = MemoryJournalStore::default();

        let invoke = host
            .seal(WorkerMessage::Invoke {
                invocation: ToolInvocation::new(
                    "worker-1",
                    "invoke-1",
                    "text.echo",
                    ToolPayload::Text("read".to_owned()),
                )
                .unwrap(),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(invoke, &mut store),
            Err(WorkerSessionError::InvocationSafetyNotDeclared(tool)) if tool == "text.echo"
        ));

        let dispatch = host
            .seal(WorkerMessage::DispatchOperation {
                request: dispatch_request("dispatch-1"),
            })
            .unwrap();
        assert!(matches!(
            worker.handle(dispatch, &mut store),
            Err(WorkerSessionError::DurableOperationContractNotDeclared(tool))
                if tool == "text.echo"
        ));
        assert!(worker.journal().operation("op-release-42").is_none());
    }
}
