#![forbid(unsafe_code)]

//! Host-owned workflow state for Splash.
//!
//! Scripts evaluate individual steps, but they cannot mint approval or skip
//! host policy. The event log remains in-memory, while bounded data-only
//! checkpoints let a host persist an explicitly attested completed prefix and
//! require fresh approval before a restart can execute the remaining steps.

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use splash_capabilities::CapabilityRuntime;
use splash_core::RuntimeError;
use splash_protocol::{
    AuthenticatedWorkerMessage, OperationDispatchRequest, OperationReconcileRequest,
    OperationReconcileResult, OperationStatus, ProtocolError, SessionAuthenticator, SessionRole,
    ToolPayload, WorkerMessage,
};

static NEXT_ENGINE_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum serialized checkpoint size accepted from durable storage.
pub const MAX_WORKFLOW_CHECKPOINT_BYTES: usize = 16 * 1024;
/// Maximum number of completed step IDs a checkpoint may contain.
pub const MAX_WORKFLOW_CHECKPOINT_STEPS: usize = 1024;
/// Maximum UTF-8 byte length of a workflow step ID.
pub const MAX_WORKFLOW_STEP_ID_BYTES: usize = 128;
/// Current serialized checkpoint format version.
pub const WORKFLOW_CHECKPOINT_FORMAT_VERSION: u8 = 1;
/// Maximum serialized operation ledger size accepted from durable storage.
pub const MAX_WORKFLOW_OPERATION_LEDGER_BYTES: usize = 64 * 1024;
/// Maximum operation intents retained in one durable ledger.
pub const MAX_WORKFLOW_OPERATIONS: usize = 64;
/// Maximum input size hashed into one durable operation intent.
pub const MAX_WORKFLOW_OPERATION_INPUT_BYTES: usize = 256 * 1024;
/// Maximum host-supplied nonce size used to derive a durable operation key.
pub const MAX_WORKFLOW_OPERATION_NONCE_BYTES: usize = 128;
/// Current serialized operation ledger format version.
pub const WORKFLOW_OPERATION_LEDGER_FORMAT_VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowStep {
    pub id: String,
    pub source: String,
}

impl WorkflowStep {
    pub fn new(id: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            source: source.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowPlan {
    engine_id: u64,
    id: u64,
    fingerprint: String,
    steps: Vec<WorkflowStep>,
}

impl WorkflowPlan {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn steps(&self) -> &[WorkflowStep] {
        &self.steps
    }

    /// Stable BLAKE3 binding of the ordered step IDs and source text.
    ///
    /// The local plan ID is intentionally excluded so a plan recreated after
    /// a process restart can validate a durable checkpoint.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Durable, data-only record of a completed workflow-step prefix.
///
/// A checkpoint never includes an approval, capability grant, tool result,
/// runtime state, or opaque external operation ID. Loading one does not grant
/// permission to execute anything: resuming always requires a fresh,
/// checkpoint-bound [`Approval`] from the current host engine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCheckpoint {
    format_version: u8,
    plan_fingerprint: String,
    completed_step_ids: Vec<String>,
}

impl WorkflowCheckpoint {
    pub fn plan_fingerprint(&self) -> &str {
        &self.plan_fingerprint
    }

    pub fn completed_step_ids(&self) -> &[String] {
        &self.completed_step_ids
    }

    pub fn completed_step_count(&self) -> usize {
        self.completed_step_ids.len()
    }

    /// Encodes the checkpoint for host-owned durable storage.
    pub fn to_json(&self) -> Result<String, WorkflowCheckpointError> {
        self.validate_syntax()?;
        let Some(upper_bound) = self.encoded_size_upper_bound() else {
            return Err(WorkflowCheckpointError::TooLarge);
        };
        if upper_bound > MAX_WORKFLOW_CHECKPOINT_BYTES {
            return Err(WorkflowCheckpointError::TooLarge);
        }
        let encoded = serde_json::to_string(self).map_err(|_| WorkflowCheckpointError::Encoding)?;
        if encoded.len() > MAX_WORKFLOW_CHECKPOINT_BYTES {
            return Err(WorkflowCheckpointError::TooLarge);
        }
        Ok(encoded)
    }

    /// Decodes a bounded checkpoint from host-owned durable storage.
    ///
    /// Decoding checks format and structural bounds only. Use
    /// [`WorkflowEngine::approve_resume`] to bind the checkpoint to a trusted
    /// plan and create a fresh approval before it can be resumed.
    pub fn from_json(encoded: &str) -> Result<Self, WorkflowCheckpointError> {
        if encoded.len() > MAX_WORKFLOW_CHECKPOINT_BYTES {
            return Err(WorkflowCheckpointError::TooLarge);
        }
        let checkpoint: Self =
            serde_json::from_str(encoded).map_err(|_| WorkflowCheckpointError::InvalidEncoding)?;
        checkpoint.validate_syntax()?;
        Ok(checkpoint)
    }

    fn for_plan(
        plan: &WorkflowPlan,
        completed_step_count: usize,
    ) -> Result<Self, WorkflowCheckpointError> {
        if completed_step_count > plan.steps.len() {
            return Err(WorkflowCheckpointError::CompletedStepCountOutOfRange {
                completed: completed_step_count,
                total: plan.steps.len(),
            });
        }
        let checkpoint = Self {
            format_version: WORKFLOW_CHECKPOINT_FORMAT_VERSION,
            plan_fingerprint: plan.fingerprint.clone(),
            completed_step_ids: plan.steps[..completed_step_count]
                .iter()
                .map(|step| step.id.clone())
                .collect(),
        };
        checkpoint.validate_syntax()?;
        Ok(checkpoint)
    }

    fn validate_for(&self, plan: &WorkflowPlan) -> Result<(), WorkflowCheckpointError> {
        self.validate_syntax()?;
        if self.plan_fingerprint != plan.fingerprint {
            return Err(WorkflowCheckpointError::PlanMismatch);
        }
        if self.completed_step_ids.len() > plan.steps.len() {
            return Err(WorkflowCheckpointError::CompletedStepCountOutOfRange {
                completed: self.completed_step_ids.len(),
                total: plan.steps.len(),
            });
        }
        if self
            .completed_step_ids
            .iter()
            .zip(&plan.steps)
            .any(|(completed, step)| completed != &step.id)
        {
            return Err(WorkflowCheckpointError::StepPrefixMismatch);
        }
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), WorkflowCheckpointError> {
        if self.format_version != WORKFLOW_CHECKPOINT_FORMAT_VERSION {
            return Err(WorkflowCheckpointError::UnsupportedVersion(
                self.format_version,
            ));
        }
        if !is_plan_fingerprint(&self.plan_fingerprint) {
            return Err(WorkflowCheckpointError::InvalidPlanFingerprint);
        }
        if self.completed_step_ids.len() > MAX_WORKFLOW_CHECKPOINT_STEPS {
            return Err(WorkflowCheckpointError::TooManyCompletedSteps);
        }
        let mut seen = BTreeSet::new();
        for step_id in &self.completed_step_ids {
            if !is_valid_step_id(step_id) {
                return Err(WorkflowCheckpointError::InvalidStepId(step_id.clone()));
            }
            if !seen.insert(step_id) {
                return Err(WorkflowCheckpointError::DuplicateStepId(step_id.clone()));
            }
        }
        Ok(())
    }

    fn encoded_size_upper_bound(&self) -> Option<usize> {
        // IDs are restricted to ASCII by `is_valid_step_id`, so JSON does not
        // need to escape them. Reserve generous fixed structural overhead.
        let mut bytes = 128usize;
        for step_id in &self.completed_step_ids {
            bytes = bytes.checked_add(step_id.len().checked_add(3)?)?;
        }
        Some(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowCheckpointError {
    TooLarge,
    Encoding,
    InvalidEncoding,
    UnsupportedVersion(u8),
    InvalidPlanFingerprint,
    TooManyCompletedSteps,
    InvalidStepId(String),
    DuplicateStepId(String),
    CompletedStepCountOutOfRange { completed: usize, total: usize },
    PlanMismatch,
    StepPrefixMismatch,
}

impl Display for WorkflowCheckpointError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("workflow checkpoint exceeds its byte limit"),
            Self::Encoding => formatter.write_str("workflow checkpoint could not be encoded"),
            Self::InvalidEncoding => formatter.write_str("workflow checkpoint is not valid JSON"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported workflow checkpoint version: {version}"
                )
            }
            Self::InvalidPlanFingerprint => {
                formatter.write_str("workflow checkpoint has an invalid plan fingerprint")
            }
            Self::TooManyCompletedSteps => {
                formatter.write_str("workflow checkpoint has too many completed steps")
            }
            Self::InvalidStepId(step_id) => {
                write!(formatter, "invalid completed workflow step id: {step_id}")
            }
            Self::DuplicateStepId(step_id) => {
                write!(formatter, "duplicate completed workflow step id: {step_id}")
            }
            Self::CompletedStepCountOutOfRange { completed, total } => write!(
                formatter,
                "workflow checkpoint records {completed} completed steps for a {total}-step plan"
            ),
            Self::PlanMismatch => {
                formatter.write_str("workflow checkpoint belongs to another plan")
            }
            Self::StepPrefixMismatch => {
                formatter.write_str("workflow checkpoint does not match the plan step prefix")
            }
        }
    }
}

impl std::error::Error for WorkflowCheckpointError {}

/// A worker-observed lifecycle state for one durable external operation.
///
/// This is not proof that an effect completed. The host must authenticate the
/// worker response, validate any terminal output against the active capability
/// policy, and decide its own retry, compensation, or resume policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowOperationState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl WorkflowOperationState {
    fn accepts(self, observed: Self) -> bool {
        match self {
            Self::Pending => matches!(
                observed,
                Self::Running | Self::Succeeded | Self::Failed | Self::Cancelled
            ),
            Self::Running => matches!(
                observed,
                Self::Running | Self::Succeeded | Self::Failed | Self::Cancelled
            ),
            Self::Succeeded | Self::Failed | Self::Cancelled => self == observed,
        }
    }
}

/// A bounded, data-only record of one host-dispatched external operation.
///
/// It intentionally stores an input fingerprint rather than raw input, and
/// never contains output, raw secret values, a capability grant, an approval,
/// a VM promise, or an opaque runtime operation handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowOperation {
    step_id: String,
    tool: String,
    operation_key: String,
    input_fingerprint: String,
    state: WorkflowOperationState,
}

impl WorkflowOperation {
    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }

    pub fn operation_key(&self) -> &str {
        &self.operation_key
    }

    pub fn input_fingerprint(&self) -> &str {
        &self.input_fingerprint
    }

    pub fn state(&self) -> WorkflowOperationState {
        self.state
    }

    /// Returns whether this record was created for exactly these input bytes.
    pub fn matches_input(&self, input: &[u8]) -> bool {
        input.len() <= MAX_WORKFLOW_OPERATION_INPUT_BYTES
            && self.input_fingerprint == workflow_operation_input_fingerprint(input)
    }

    fn verify_input(&self, input: &[u8]) -> Result<(), WorkflowOperationLedgerError> {
        if input.len() > MAX_WORKFLOW_OPERATION_INPUT_BYTES {
            return Err(WorkflowOperationLedgerError::InputTooLarge {
                actual: input.len(),
                maximum: MAX_WORKFLOW_OPERATION_INPUT_BYTES,
            });
        }
        if !self.matches_input(input) {
            return Err(WorkflowOperationLedgerError::InputFingerprintMismatch(
                self.operation_key.clone(),
            ));
        }
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), WorkflowOperationLedgerError> {
        if !is_valid_step_id(&self.step_id) {
            return Err(WorkflowOperationLedgerError::InvalidStepId(
                self.step_id.clone(),
            ));
        }
        if !is_valid_operation_token(&self.tool) {
            return Err(WorkflowOperationLedgerError::InvalidTool(self.tool.clone()));
        }
        if !is_valid_operation_token(&self.operation_key) {
            return Err(WorkflowOperationLedgerError::InvalidOperationKey(
                self.operation_key.clone(),
            ));
        }
        if !is_plan_fingerprint(&self.input_fingerprint) {
            return Err(WorkflowOperationLedgerError::InvalidInputFingerprint);
        }
        Ok(())
    }
}

/// Bounded, data-only durable intent records for external workflow operations.
///
/// A ledger is bound to a trusted workflow plan fingerprint. It can survive a
/// process restart, but it cannot resume a Splash promise or prove that an
/// external effect happened. Hosts must recreate their plan and capability
/// policy, authenticate durable storage and worker messages, then apply an
/// explicit restart policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowOperationLedger {
    format_version: u8,
    revision: u64,
    plan_fingerprint: String,
    operations: Vec<WorkflowOperation>,
}

/// A keyed worker frame for a durable operation reconciliation request.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedWorkflowReconciliationRequest {
    pub request: OperationReconcileRequest,
    pub frame: AuthenticatedWorkerMessage,
}

/// A keyed worker frame for a durable operation dispatch request.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedWorkflowOperationDispatch {
    pub request: OperationDispatchRequest,
    pub frame: AuthenticatedWorkerMessage,
}

impl WorkflowOperationLedger {
    /// Monotonic revision incremented by every non-idempotent ledger mutation.
    ///
    /// Persist this value in authenticated durable storage or use it as a
    /// compare-and-swap version. The value alone does not prevent storage
    /// rollback; a host must retain an authenticated watermark separately.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn plan_fingerprint(&self) -> &str {
        &self.plan_fingerprint
    }

    pub fn operations(&self) -> &[WorkflowOperation] {
        &self.operations
    }

    pub fn operation(&self, operation_key: &str) -> Option<&WorkflowOperation> {
        self.operations
            .iter()
            .find(|operation| operation.operation_key == operation_key)
    }

    /// Rejects a syntactically valid ledger older than a host-retained
    /// authenticated revision watermark.
    pub fn validate_minimum_revision(
        &self,
        minimum_revision: u64,
    ) -> Result<(), WorkflowOperationLedgerError> {
        self.validate_syntax()?;
        if self.revision < minimum_revision {
            return Err(WorkflowOperationLedgerError::StaleRevision {
                actual: self.revision,
                minimum: minimum_revision,
            });
        }
        Ok(())
    }

    /// Encodes this ledger for host-owned durable storage.
    pub fn to_json(&self) -> Result<String, WorkflowOperationLedgerError> {
        self.validate_syntax()?;
        let Some(upper_bound) = self.encoded_size_upper_bound() else {
            return Err(WorkflowOperationLedgerError::TooLarge);
        };
        if upper_bound > MAX_WORKFLOW_OPERATION_LEDGER_BYTES {
            return Err(WorkflowOperationLedgerError::TooLarge);
        }
        let encoded =
            serde_json::to_string(self).map_err(|_| WorkflowOperationLedgerError::Encoding)?;
        if encoded.len() > MAX_WORKFLOW_OPERATION_LEDGER_BYTES {
            return Err(WorkflowOperationLedgerError::TooLarge);
        }
        Ok(encoded)
    }

    /// Decodes bounded data from host-owned durable storage.
    ///
    /// Decoding validates syntax and resource bounds only. Call
    /// [`WorkflowEngine::validate_operation_ledger`] before using it with a
    /// recreated plan, and authenticate storage outside this crate.
    pub fn from_json(encoded: &str) -> Result<Self, WorkflowOperationLedgerError> {
        if encoded.len() > MAX_WORKFLOW_OPERATION_LEDGER_BYTES {
            return Err(WorkflowOperationLedgerError::TooLarge);
        }
        let ledger: Self = serde_json::from_str(encoded)
            .map_err(|_| WorkflowOperationLedgerError::InvalidEncoding)?;
        ledger.validate_syntax()?;
        Ok(ledger)
    }

    /// Records durable intent before the host dispatches an external effect.
    ///
    /// Raw input is never retained; only a BLAKE3 digest is stored. The key
    /// must be stable for worker-side deduplication and unique within this
    /// ledger.
    pub fn record(
        &mut self,
        step_id: impl Into<String>,
        tool: impl Into<String>,
        operation_key: impl Into<String>,
        input: &[u8],
    ) -> Result<(), WorkflowOperationLedgerError> {
        self.validate_syntax()?;
        if input.len() > MAX_WORKFLOW_OPERATION_INPUT_BYTES {
            return Err(WorkflowOperationLedgerError::InputTooLarge {
                actual: input.len(),
                maximum: MAX_WORKFLOW_OPERATION_INPUT_BYTES,
            });
        }
        if self.operations.len() >= MAX_WORKFLOW_OPERATIONS {
            return Err(WorkflowOperationLedgerError::TooManyOperations);
        }
        let next_revision = self.next_revision()?;

        let operation = WorkflowOperation {
            step_id: step_id.into(),
            tool: tool.into(),
            operation_key: operation_key.into(),
            input_fingerprint: workflow_operation_input_fingerprint(input),
            state: WorkflowOperationState::Pending,
        };
        operation.validate_syntax()?;
        if self
            .operations
            .iter()
            .any(|existing| existing.operation_key == operation.operation_key)
        {
            return Err(WorkflowOperationLedgerError::DuplicateOperationKey(
                operation.operation_key,
            ));
        }
        self.operations.push(operation);
        self.revision = next_revision;
        Ok(())
    }

    /// Builds a protocol reconciliation request for a recorded operation.
    ///
    /// This only constructs data. The caller must authenticate the frame with
    /// `SessionAuthenticator` before sending it to a worker.
    pub fn reconcile_request(
        &self,
        operation_key: &str,
        input: &[u8],
        session_id: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Result<OperationReconcileRequest, WorkflowOperationLedgerError> {
        self.validate_syntax()?;
        if !is_valid_operation_token(operation_key) {
            return Err(WorkflowOperationLedgerError::InvalidOperationKey(
                operation_key.to_owned(),
            ));
        }
        let operation = self.operation(operation_key).ok_or_else(|| {
            WorkflowOperationLedgerError::UnknownOperation(operation_key.to_owned())
        })?;
        operation.verify_input(input)?;
        OperationReconcileRequest::new(
            session_id,
            request_id,
            operation.tool.clone(),
            operation.operation_key.clone(),
        )
        .map_err(WorkflowOperationLedgerError::Protocol)
    }

    /// Applies a worker observation after transport authentication.
    ///
    /// The ledger retains only the state, not any worker output or error text.
    /// A terminal `succeeded` observation is not host approval to resume a
    /// workflow; validate active tool contracts and apply host policy first.
    pub fn apply_verified_reconciliation(
        &mut self,
        request: &OperationReconcileRequest,
        result: &OperationReconcileResult,
    ) -> Result<WorkflowOperationState, WorkflowOperationLedgerError> {
        self.validate_syntax()?;
        request
            .validate()
            .map_err(WorkflowOperationLedgerError::Protocol)?;
        result
            .validate()
            .map_err(WorkflowOperationLedgerError::Protocol)?;
        if !result.matches_request(request) {
            return Err(WorkflowOperationLedgerError::ReconciliationMismatch);
        }

        let observed = match &result.status {
            OperationStatus::Running => WorkflowOperationState::Running,
            OperationStatus::Succeeded { .. } => WorkflowOperationState::Succeeded,
            OperationStatus::Failed { .. } => WorkflowOperationState::Failed,
            OperationStatus::Cancelled => WorkflowOperationState::Cancelled,
        };
        let operation_index = self
            .operations
            .iter()
            .position(|operation| operation.operation_key == request.operation_key)
            .ok_or_else(|| {
                WorkflowOperationLedgerError::UnknownOperation(request.operation_key.clone())
            })?;
        let operation = &self.operations[operation_index];
        if operation.tool != request.tool {
            return Err(WorkflowOperationLedgerError::ReconciliationMismatch);
        }
        if !operation.state.accepts(observed) {
            return Err(WorkflowOperationLedgerError::InvalidStateTransition {
                current: operation.state,
                observed,
            });
        }
        if operation.state != observed {
            let next_revision = self.next_revision()?;
            self.operations[operation_index].state = observed;
            self.revision = next_revision;
        }
        Ok(observed)
    }

    fn for_plan(plan: &WorkflowPlan) -> Self {
        Self {
            format_version: WORKFLOW_OPERATION_LEDGER_FORMAT_VERSION,
            revision: 0,
            plan_fingerprint: plan.fingerprint.clone(),
            operations: Vec::new(),
        }
    }

    fn validate_for(&self, plan: &WorkflowPlan) -> Result<(), WorkflowOperationLedgerError> {
        self.validate_syntax()?;
        if self.plan_fingerprint != plan.fingerprint {
            return Err(WorkflowOperationLedgerError::PlanMismatch);
        }
        for operation in &self.operations {
            if !plan.steps.iter().any(|step| step.id == operation.step_id) {
                return Err(WorkflowOperationLedgerError::UnknownStep(
                    operation.step_id.clone(),
                ));
            }
        }
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), WorkflowOperationLedgerError> {
        if self.format_version != WORKFLOW_OPERATION_LEDGER_FORMAT_VERSION {
            return Err(WorkflowOperationLedgerError::UnsupportedVersion(
                self.format_version,
            ));
        }
        if !is_plan_fingerprint(&self.plan_fingerprint) {
            return Err(WorkflowOperationLedgerError::InvalidPlanFingerprint);
        }
        if self.operations.len() > MAX_WORKFLOW_OPERATIONS {
            return Err(WorkflowOperationLedgerError::TooManyOperations);
        }
        let mut seen_operation_keys = BTreeSet::new();
        for operation in &self.operations {
            operation.validate_syntax()?;
            if !seen_operation_keys.insert(&operation.operation_key) {
                return Err(WorkflowOperationLedgerError::DuplicateOperationKey(
                    operation.operation_key.clone(),
                ));
            }
        }
        Ok(())
    }

    fn encoded_size_upper_bound(&self) -> Option<usize> {
        // All persisted fields are ASCII-constrained, so JSON does not need
        // escape expansion. Reserve conservative structural overhead.
        let mut bytes = 192usize;
        bytes = bytes.checked_add(32)?;
        for operation in &self.operations {
            bytes = bytes.checked_add(256)?;
            bytes = bytes.checked_add(operation.step_id.len())?;
            bytes = bytes.checked_add(operation.tool.len())?;
            bytes = bytes.checked_add(operation.operation_key.len())?;
            bytes = bytes.checked_add(operation.input_fingerprint.len())?;
        }
        Some(bytes)
    }

    fn next_revision(&self) -> Result<u64, WorkflowOperationLedgerError> {
        self.revision
            .checked_add(1)
            .ok_or(WorkflowOperationLedgerError::RevisionExhausted)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowOperationLedgerError {
    TooLarge,
    Encoding,
    InvalidEncoding,
    UnsupportedVersion(u8),
    InvalidPlanFingerprint,
    TooManyOperations,
    RevisionExhausted,
    StaleRevision {
        actual: u64,
        minimum: u64,
    },
    InputTooLarge {
        actual: usize,
        maximum: usize,
    },
    EmptyOperationNonce,
    OperationNonceTooLarge {
        actual: usize,
        maximum: usize,
    },
    InvalidStepId(String),
    InvalidTool(String),
    InvalidOperationKey(String),
    InvalidInputFingerprint,
    InputFingerprintMismatch(String),
    DuplicateOperationKey(String),
    PlanMismatch,
    UnknownStep(String),
    UnknownOperation(String),
    ReconciliationMismatch,
    ReconciliationRequiresHostAuthenticator,
    OperationDispatchRequiresHostAuthenticator,
    UnexpectedReconciliationMessage,
    InvalidStateTransition {
        current: WorkflowOperationState,
        observed: WorkflowOperationState,
    },
    Protocol(ProtocolError),
}

impl Display for WorkflowOperationLedgerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("workflow operation ledger exceeds its byte limit"),
            Self::Encoding => formatter.write_str("workflow operation ledger could not be encoded"),
            Self::InvalidEncoding => {
                formatter.write_str("workflow operation ledger is not valid JSON")
            }
            Self::UnsupportedVersion(version) => write!(
                formatter,
                "unsupported workflow operation ledger version: {version}"
            ),
            Self::InvalidPlanFingerprint => {
                formatter.write_str("workflow operation ledger has an invalid plan fingerprint")
            }
            Self::TooManyOperations => {
                formatter.write_str("workflow operation ledger has too many operations")
            }
            Self::RevisionExhausted => {
                formatter.write_str("workflow operation ledger revision is exhausted")
            }
            Self::StaleRevision { actual, minimum } => write!(
                formatter,
                "workflow operation ledger revision {actual} is older than required revision {minimum}"
            ),
            Self::InputTooLarge { actual, maximum } => write!(
                formatter,
                "workflow operation input is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::EmptyOperationNonce => {
                formatter.write_str("workflow operation nonce must not be empty")
            }
            Self::OperationNonceTooLarge { actual, maximum } => write!(
                formatter,
                "workflow operation nonce is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::InvalidStepId(step_id) => {
                write!(formatter, "invalid workflow operation step id: {step_id}")
            }
            Self::InvalidTool(tool) => write!(formatter, "invalid workflow operation tool: {tool}"),
            Self::InvalidOperationKey(key) => {
                write!(formatter, "invalid workflow operation key: {key}")
            }
            Self::InvalidInputFingerprint => {
                formatter.write_str("workflow operation has an invalid input fingerprint")
            }
            Self::InputFingerprintMismatch(key) => {
                write!(formatter, "workflow operation input does not match record: {key}")
            }
            Self::DuplicateOperationKey(key) => {
                write!(formatter, "duplicate workflow operation key: {key}")
            }
            Self::PlanMismatch => {
                formatter.write_str("workflow operation ledger belongs to another plan")
            }
            Self::UnknownStep(step_id) => {
                write!(formatter, "workflow operation refers to unknown step: {step_id}")
            }
            Self::UnknownOperation(key) => {
                write!(formatter, "unknown workflow operation: {key}")
            }
            Self::ReconciliationMismatch => {
                formatter.write_str("worker reconciliation does not match the durable operation")
            }
            Self::ReconciliationRequiresHostAuthenticator => {
                formatter.write_str("durable reconciliation requires a host session authenticator")
            }
            Self::OperationDispatchRequiresHostAuthenticator => {
                formatter.write_str("durable operation dispatch requires a host session authenticator")
            }
            Self::UnexpectedReconciliationMessage => {
                formatter.write_str("authenticated worker frame is not an operation reconciliation")
            }
            Self::InvalidStateTransition { current, observed } => write!(
                formatter,
                "worker observation cannot change durable operation from {current:?} to {observed:?}"
            ),
            Self::Protocol(error) => write!(formatter, "worker protocol rejected: {error}"),
        }
    }
}

impl std::error::Error for WorkflowOperationLedgerError {}

/// An approval can only be produced by [`WorkflowEngine::approve`] or
/// [`WorkflowEngine::approve_resume`] and is consumed by one execution call.
#[derive(Debug)]
pub struct Approval {
    engine_id: u64,
    plan_id: u64,
    nonce: u64,
    kind: ApprovalKind,
}

#[derive(Debug)]
enum ApprovalKind {
    Plan,
    Checkpoint(WorkflowCheckpoint),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowEvent {
    Planned {
        plan_id: u64,
        step_count: usize,
    },
    Approved {
        plan_id: u64,
    },
    Checkpointed {
        plan_id: u64,
        completed_steps: usize,
    },
    OperationLedgerCreated {
        plan_id: u64,
    },
    OperationRecorded {
        plan_id: u64,
        step_id: String,
        tool: String,
    },
    OperationObserved {
        plan_id: u64,
        step_id: String,
        tool: String,
        state: WorkflowOperationState,
    },
    ResumeApproved {
        plan_id: u64,
        completed_steps: usize,
    },
    Started {
        plan_id: u64,
    },
    Resumed {
        plan_id: u64,
        completed_steps: usize,
    },
    StepSucceeded {
        plan_id: u64,
        step_id: String,
    },
    StepSuspended {
        plan_id: u64,
        step_id: String,
        completed_steps: usize,
    },
    StepFailed {
        plan_id: u64,
        step_id: String,
        diagnostics: Vec<String>,
        completed_steps: usize,
    },
    Completed {
        plan_id: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowError {
    EmptyPlan,
    InvalidStepId(String),
    DuplicateStepId(String),
    PlanOwnershipMismatch,
    ApprovalMismatch,
    Checkpoint(WorkflowCheckpointError),
    OperationLedger(WorkflowOperationLedgerError),
    Runtime(String),
    StepSuspended {
        step_id: String,
        completed_steps: usize,
    },
    StepFailed {
        step_id: String,
        diagnostics: Vec<String>,
        completed_steps: usize,
    },
}

impl Display for WorkflowError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPlan => formatter.write_str("workflow must have at least one step"),
            Self::InvalidStepId(id) => write!(formatter, "invalid workflow step id: {id}"),
            Self::DuplicateStepId(id) => write!(formatter, "duplicate workflow step id: {id}"),
            Self::PlanOwnershipMismatch => {
                formatter.write_str("workflow plan is not owned by this engine")
            }
            Self::ApprovalMismatch => {
                formatter.write_str("approval is not valid for this workflow")
            }
            Self::Checkpoint(error) => write!(formatter, "workflow checkpoint error: {error}"),
            Self::OperationLedger(error) => {
                write!(formatter, "workflow operation ledger error: {error}")
            }
            Self::Runtime(message) => write!(formatter, "runtime error: {message}"),
            Self::StepSuspended { step_id, .. } => {
                write!(
                    formatter,
                    "workflow step suspended without runnable tool work: {step_id}"
                )
            }
            Self::StepFailed { step_id, .. } => {
                write!(formatter, "workflow step failed: {step_id}")
            }
        }
    }
}

impl std::error::Error for WorkflowError {}

impl From<RuntimeError> for WorkflowError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error.to_string())
    }
}

pub struct WorkflowEngine {
    engine_id: u64,
    runtime: CapabilityRuntime,
    events: Vec<WorkflowEvent>,
    next_plan_id: u64,
    next_approval_nonce: u64,
}

impl WorkflowEngine {
    pub fn new(runtime: CapabilityRuntime) -> Self {
        Self {
            engine_id: NEXT_ENGINE_ID.fetch_add(1, Ordering::Relaxed),
            runtime,
            events: Vec::new(),
            next_plan_id: 1,
            next_approval_nonce: 1,
        }
    }

    pub fn runtime(&self) -> &CapabilityRuntime {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut CapabilityRuntime {
        &mut self.runtime
    }

    pub fn events(&self) -> &[WorkflowEvent] {
        &self.events
    }

    pub fn plan(&mut self, steps: Vec<WorkflowStep>) -> Result<WorkflowPlan, WorkflowError> {
        validate_steps(&steps)?;

        let plan = WorkflowPlan {
            engine_id: self.engine_id,
            id: self.next_plan_id,
            fingerprint: plan_fingerprint(&steps),
            steps,
        };
        self.next_plan_id = self.next_plan_id.saturating_add(1);
        self.events.push(WorkflowEvent::Planned {
            plan_id: plan.id,
            step_count: plan.steps.len(),
        });
        Ok(plan)
    }

    pub fn approve(&mut self, plan: &WorkflowPlan) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        let approval = self.issue_approval(plan, ApprovalKind::Plan);
        self.events
            .push(WorkflowEvent::Approved { plan_id: plan.id });
        Ok(approval)
    }

    /// Builds a serializable, data-only checkpoint after a host-attested
    /// completed prefix. This does not persist or grant any capability.
    pub fn checkpoint_after(
        &mut self,
        plan: &WorkflowPlan,
        completed_step_count: usize,
    ) -> Result<WorkflowCheckpoint, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        let checkpoint = WorkflowCheckpoint::for_plan(plan, completed_step_count)
            .map_err(WorkflowError::Checkpoint)?;
        self.events.push(WorkflowEvent::Checkpointed {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        Ok(checkpoint)
    }

    /// Creates an empty durable operation ledger bound to this trusted plan.
    ///
    /// The ledger is data only. It does not grant a capability or permit a
    /// workflow to execute after a restart.
    pub fn operation_ledger(
        &mut self,
        plan: &WorkflowPlan,
    ) -> Result<WorkflowOperationLedger, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        let ledger = WorkflowOperationLedger::for_plan(plan);
        self.events
            .push(WorkflowEvent::OperationLedgerCreated { plan_id: plan.id });
        Ok(ledger)
    }

    /// Validates data loaded from durable storage against a trusted plan.
    pub fn validate_operation_ledger(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
    ) -> Result<(), WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        ledger
            .validate_for(plan)
            .map_err(WorkflowError::OperationLedger)
    }

    /// Validates a ledger and rejects it if it predates a host-retained
    /// authenticated revision watermark.
    ///
    /// Use this when durable storage supports a monotonic counter or
    /// compare-and-swap version. The ledger cannot detect storage rollback by
    /// itself.
    pub fn validate_operation_ledger_at_or_after(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        minimum_revision: u64,
    ) -> Result<(), WorkflowError> {
        self.validate_operation_ledger(plan, ledger)?;
        ledger
            .validate_minimum_revision(minimum_revision)
            .map_err(WorkflowError::OperationLedger)
    }

    /// Records external operation intent before a host dispatches its effect.
    ///
    /// The caller supplies a durable worker-deduplication key. The input is
    /// reduced to a BLAKE3 digest before it enters the ledger.
    pub fn record_operation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        step_id: impl Into<String>,
        tool: impl Into<String>,
        operation_key: impl Into<String>,
        input: &[u8],
    ) -> Result<(), WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        ledger
            .validate_for(plan)
            .map_err(WorkflowError::OperationLedger)?;
        let step_id = step_id.into();
        let tool = tool.into();
        if !plan.steps.iter().any(|step| step.id == step_id) {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::UnknownStep(step_id),
            ));
        }
        ledger
            .record(step_id.clone(), tool.clone(), operation_key, input)
            .map_err(WorkflowError::OperationLedger)?;
        self.events.push(WorkflowEvent::OperationRecorded {
            plan_id: plan.id,
            step_id,
            tool,
        });
        Ok(())
    }

    /// Derives a plan-bound durable operation key from the complete input.
    ///
    /// Supply a non-empty durable nonce that is unique for each logical effect,
    /// such as a persisted workflow-run ID plus operation ordinal. The derived
    /// key binds the plan fingerprint, step, tool, input digest, and nonce into
    /// the non-authorizing key forwarded to the worker.
    pub fn derive_operation_key(
        &self,
        plan: &WorkflowPlan,
        step_id: &str,
        tool: &str,
        input: &[u8],
        operation_nonce: &[u8],
    ) -> Result<String, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        if !plan.steps.iter().any(|step| step.id == step_id) {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::UnknownStep(step_id.to_owned()),
            ));
        }
        if !is_valid_operation_token(tool) {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::InvalidTool(tool.to_owned()),
            ));
        }
        if input.len() > MAX_WORKFLOW_OPERATION_INPUT_BYTES {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::InputTooLarge {
                    actual: input.len(),
                    maximum: MAX_WORKFLOW_OPERATION_INPUT_BYTES,
                },
            ));
        }
        if operation_nonce.is_empty() {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::EmptyOperationNonce,
            ));
        }
        if operation_nonce.len() > MAX_WORKFLOW_OPERATION_NONCE_BYTES {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationNonceTooLarge {
                    actual: operation_nonce.len(),
                    maximum: MAX_WORKFLOW_OPERATION_NONCE_BYTES,
                },
            ));
        }
        Ok(derived_workflow_operation_key(
            plan.fingerprint(),
            step_id,
            tool,
            input,
            operation_nonce,
        ))
    }

    /// Derives and records a plan-bound durable operation key before dispatch.
    ///
    /// Prefer this over [`Self::record_operation`] when a host does not need a
    /// pre-existing worker key. It returns the key to send to the worker and
    /// retain in authenticated durable storage.
    pub fn record_derived_operation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        step_id: impl Into<String>,
        tool: impl Into<String>,
        input: &[u8],
        operation_nonce: &[u8],
    ) -> Result<String, WorkflowError> {
        let step_id = step_id.into();
        let tool = tool.into();
        let operation_key =
            self.derive_operation_key(plan, &step_id, &tool, input, operation_nonce)?;
        self.record_operation(plan, ledger, step_id, tool, operation_key.clone(), input)?;
        Ok(operation_key)
    }

    /// Builds a worker operation-dispatch request for a persisted durable
    /// intent.
    ///
    /// Record the request's [`OperationDispatchRequest::canonical_input_bytes`]
    /// in the ledger before dispatch. This method reconstructs those same bytes
    /// and fails closed if the current payload differs from the durable intent.
    pub fn operation_dispatch_request(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        operation_key: &str,
        payload: ToolPayload,
        session_id: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Result<OperationDispatchRequest, WorkflowError> {
        self.validate_operation_ledger(plan, ledger)?;
        let operation = ledger.operation(operation_key).ok_or_else(|| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownOperation(
                operation_key.to_owned(),
            ))
        })?;
        let request = OperationDispatchRequest::new(
            session_id,
            request_id,
            operation.tool.clone(),
            operation.operation_key.clone(),
            payload,
        )
        .map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        let input = request.canonical_input_bytes().map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        operation
            .verify_input(&input)
            .map_err(WorkflowError::OperationLedger)?;
        Ok(request)
    }

    /// Creates an authenticated v3 worker dispatch frame for a persisted
    /// durable operation.
    ///
    /// This is the preferred bridge for a contained worker's
    /// `WorkerOperationJournal`. The host must persist its ledger before it
    /// sends this frame, and the worker must persist its own journal before it
    /// runs the effect.
    pub fn prepare_authenticated_operation_dispatch(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        operation_key: &str,
        payload: ToolPayload,
        request_id: impl Into<String>,
        authenticator: &mut SessionAuthenticator,
    ) -> Result<AuthenticatedWorkflowOperationDispatch, WorkflowError> {
        if authenticator.role() != SessionRole::Host {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationDispatchRequiresHostAuthenticator,
            ));
        }
        let request = self.operation_dispatch_request(
            plan,
            ledger,
            operation_key,
            payload,
            authenticator.session_id().to_owned(),
            request_id,
        )?;
        let frame = authenticator
            .seal(WorkerMessage::DispatchOperation {
                request: request.clone(),
            })
            .map_err(|error| {
                WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
            })?;
        Ok(AuthenticatedWorkflowOperationDispatch { request, frame })
    }

    /// Builds a reconciliation request for a durable operation in this plan.
    ///
    /// This returns only protocol data; callers must authenticate the outgoing
    /// and incoming frames with `SessionAuthenticator`.
    pub fn operation_reconcile_request(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        operation_key: &str,
        input: &[u8],
        session_id: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Result<OperationReconcileRequest, WorkflowError> {
        self.validate_operation_ledger(plan, ledger)?;
        ledger
            .reconcile_request(operation_key, input, session_id, request_id)
            .map_err(WorkflowError::OperationLedger)
    }

    /// Creates an authenticated reconciliation frame for a durable operation.
    ///
    /// This is the preferred bridge for `splash-protocol` workers. It requires
    /// the host side of the session and never serializes a runtime operation
    /// handle into the frame.
    pub fn prepare_authenticated_operation_reconciliation(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        operation_key: &str,
        input: &[u8],
        request_id: impl Into<String>,
        authenticator: &mut SessionAuthenticator,
    ) -> Result<AuthenticatedWorkflowReconciliationRequest, WorkflowError> {
        if authenticator.role() != SessionRole::Host {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::ReconciliationRequiresHostAuthenticator,
            ));
        }
        let session_id = authenticator.session_id().to_owned();
        let request = self.operation_reconcile_request(
            plan,
            ledger,
            operation_key,
            input,
            session_id,
            request_id,
        )?;
        let frame = authenticator
            .seal(WorkerMessage::ReconcileOperation {
                request: request.clone(),
            })
            .map_err(|error| {
                WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
            })?;
        Ok(AuthenticatedWorkflowReconciliationRequest { request, frame })
    }

    /// Applies an authenticated worker observation to a durable operation.
    ///
    /// `result` must have originated from `SessionAuthenticator::open` or an
    /// equivalent authenticated transport. This method stores no result bytes
    /// and never resumes a VM promise or executes a workflow step.
    pub fn apply_verified_operation_reconciliation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        request: &OperationReconcileRequest,
        result: &OperationReconcileResult,
    ) -> Result<WorkflowOperationState, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        ledger
            .validate_for(plan)
            .map_err(WorkflowError::OperationLedger)?;
        let state = ledger
            .apply_verified_reconciliation(request, result)
            .map_err(WorkflowError::OperationLedger)?;
        let operation = ledger.operation(&request.operation_key).ok_or_else(|| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownOperation(
                request.operation_key.clone(),
            ))
        })?;
        self.events.push(WorkflowEvent::OperationObserved {
            plan_id: plan.id,
            step_id: operation.step_id.clone(),
            tool: operation.tool.clone(),
            state,
        });
        Ok(state)
    }

    /// Opens an authenticated worker frame and records its durable observation.
    ///
    /// Tampered, reflected, replayed, or incorrectly sequenced frames fail
    /// before the ledger state changes. This still records only an observation;
    /// it does not restore a VM promise or approve a workflow restart.
    pub fn apply_authenticated_operation_reconciliation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        request: &OperationReconcileRequest,
        authenticator: &mut SessionAuthenticator,
        frame: AuthenticatedWorkerMessage,
    ) -> Result<WorkflowOperationState, WorkflowError> {
        if authenticator.role() != SessionRole::Host {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::ReconciliationRequiresHostAuthenticator,
            ));
        }
        let message = authenticator.open(frame).map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        let WorkerMessage::ReconciledOperation { result } = message else {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::UnexpectedReconciliationMessage,
            ));
        };
        self.apply_verified_operation_reconciliation(plan, ledger, request, &result)
    }

    /// Validates a durable checkpoint against a trusted plan and creates an
    /// approval that is bound to that exact checkpoint instance.
    pub fn approve_resume(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_for(plan)
            .map_err(WorkflowError::Checkpoint)?;
        let approval = self.issue_approval(plan, ApprovalKind::Checkpoint(checkpoint.clone()));
        self.events.push(WorkflowEvent::ResumeApproved {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        Ok(approval)
    }

    pub fn execute(
        &mut self,
        plan: &WorkflowPlan,
        approval: Approval,
    ) -> Result<(), WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        if !self.approval_matches(plan, &approval) || !matches!(approval.kind, ApprovalKind::Plan) {
            return Err(WorkflowError::ApprovalMismatch);
        }

        self.events
            .push(WorkflowEvent::Started { plan_id: plan.id });
        self.execute_from(plan, 0)
    }

    /// Executes only the remaining step suffix after a freshly approved,
    /// validated checkpoint. A checkpoint alone cannot invoke this method.
    pub fn resume(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        approval: Approval,
    ) -> Result<(), WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_for(plan)
            .map_err(WorkflowError::Checkpoint)?;
        if !self.approval_matches(plan, &approval) {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let ApprovalKind::Checkpoint(bound_checkpoint) = &approval.kind else {
            return Err(WorkflowError::ApprovalMismatch);
        };
        if bound_checkpoint != checkpoint {
            return Err(WorkflowError::ApprovalMismatch);
        }

        self.events.push(WorkflowEvent::Resumed {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        self.execute_from(plan, checkpoint.completed_step_count())
    }

    fn issue_approval(&mut self, plan: &WorkflowPlan, kind: ApprovalKind) -> Approval {
        let approval = Approval {
            engine_id: self.engine_id,
            plan_id: plan.id,
            nonce: self.next_approval_nonce,
            kind,
        };
        self.next_approval_nonce = self.next_approval_nonce.saturating_add(1);
        approval
    }

    fn approval_matches(&self, plan: &WorkflowPlan, approval: &Approval) -> bool {
        self.owns_plan(plan)
            && approval.engine_id == self.engine_id
            && approval.plan_id == plan.id
            && approval.nonce != 0
    }

    fn owns_plan(&self, plan: &WorkflowPlan) -> bool {
        plan.engine_id == self.engine_id
    }

    fn execute_from(
        &mut self,
        plan: &WorkflowPlan,
        completed_step_count: usize,
    ) -> Result<(), WorkflowError> {
        for (step_index, step) in plan.steps.iter().enumerate().skip(completed_step_count) {
            let mut report = self.runtime.eval(&step.source)?;
            while report.succeeded() && report.suspended {
                let pumped = self.runtime.pump()?;
                let Some(resumed) = pumped.resumed.into_iter().last() else {
                    self.events.push(WorkflowEvent::StepSuspended {
                        plan_id: plan.id,
                        step_id: step.id.clone(),
                        completed_steps: step_index,
                    });
                    return Err(WorkflowError::StepSuspended {
                        step_id: step.id.clone(),
                        completed_steps: step_index,
                    });
                };
                report = resumed;
            }
            if !report.succeeded() {
                self.events.push(WorkflowEvent::StepFailed {
                    plan_id: plan.id,
                    step_id: step.id.clone(),
                    diagnostics: report.diagnostics.clone(),
                    completed_steps: step_index,
                });
                return Err(WorkflowError::StepFailed {
                    step_id: step.id.clone(),
                    diagnostics: report.diagnostics,
                    completed_steps: step_index,
                });
            }
            self.events.push(WorkflowEvent::StepSucceeded {
                plan_id: plan.id,
                step_id: step.id.clone(),
            });
        }
        self.events
            .push(WorkflowEvent::Completed { plan_id: plan.id });
        Ok(())
    }
}

fn plan_fingerprint(steps: &[WorkflowStep]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"splash-workflow-plan-v1");
    hasher.update(&(steps.len() as u64).to_be_bytes());
    for step in steps {
        update_plan_fingerprint_component(&mut hasher, step.id.as_bytes());
        update_plan_fingerprint_component(&mut hasher, step.source.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn update_plan_fingerprint_component(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn is_plan_fingerprint(value: &str) -> bool {
    value.len() == blake3::OUT_LEN * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn workflow_operation_input_fingerprint(input: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"splash-workflow-operation-input-v1");
    hasher.update(&(input.len() as u64).to_be_bytes());
    hasher.update(input);
    hasher.finalize().to_hex().to_string()
}

fn derived_workflow_operation_key(
    plan_fingerprint: &str,
    step_id: &str,
    tool: &str,
    input: &[u8],
    operation_nonce: &[u8],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"splash-workflow-operation-key-v1");
    update_plan_fingerprint_component(&mut hasher, plan_fingerprint.as_bytes());
    update_plan_fingerprint_component(&mut hasher, step_id.as_bytes());
    update_plan_fingerprint_component(&mut hasher, tool.as_bytes());
    update_plan_fingerprint_component(&mut hasher, input);
    update_plan_fingerprint_component(&mut hasher, operation_nonce);
    format!("op-{}", hasher.finalize().to_hex())
}

fn is_valid_operation_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_valid_step_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_WORKFLOW_STEP_ID_BYTES
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn validate_steps(steps: &[WorkflowStep]) -> Result<(), WorkflowError> {
    if steps.is_empty() {
        return Err(WorkflowError::EmptyPlan);
    }

    let mut seen = BTreeSet::new();
    for step in steps {
        if !is_valid_step_id(&step.id) {
            return Err(WorkflowError::InvalidStepId(step.id.clone()));
        }
        if !seen.insert(&step.id) {
            return Err(WorkflowError::DuplicateStepId(step.id.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use splash_capabilities::ToolPolicy;
    use splash_protocol::{canonical_operation_input_bytes, SessionKey, AUTH_TAG_BYTES};
    use splash_storage::{
        AuthenticatedStore, StorageKey, StorageKeyId, StorageKeyring, StorageRecordKey,
        VolatileMemoryStore, STORAGE_KEY_BYTES,
    };

    fn operation_reconciliation_authenticators() -> (SessionAuthenticator, SessionAuthenticator) {
        let key = SessionKey::from_bytes([13; AUTH_TAG_BYTES]).unwrap();
        (
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap(),
            SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap(),
        )
    }

    #[test]
    fn approved_plan_executes_steps_and_records_events() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "summarize",
                "use mod.tool\ntool.call(\"text.echo\", \"release notes\")",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        engine.execute(&plan, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn checkpoint_round_trips_as_bounded_data_without_plan_source() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![
                WorkflowStep::new("prepare", "let release = \"internal release data\""),
                WorkflowStep::new("publish", "let published = true"),
            ])
            .unwrap();

        let checkpoint = engine.checkpoint_after(&plan, 1).unwrap();
        let encoded = checkpoint.to_json().unwrap();
        let decoded = WorkflowCheckpoint::from_json(&encoded).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(decoded, checkpoint);
        assert_eq!(checkpoint.plan_fingerprint(), plan.fingerprint());
        assert_eq!(checkpoint.completed_step_ids(), ["prepare"]);
        assert_eq!(object.len(), 3);
        assert!(object.contains_key("format_version"));
        assert!(object.contains_key("plan_fingerprint"));
        assert!(object.contains_key("completed_step_ids"));
        assert!(!encoded.contains("internal release data"));
        assert!(!encoded.contains("approval"));
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Checkpointed {
                plan_id,
                completed_steps: 1,
            }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn checkpoint_resume_requires_a_fresh_checkpoint_bound_approval() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("first", "use mod.tool\ntool.call(\"text.echo\", \"one\")"),
                WorkflowStep::new("second", "use mod.tool\ntool.call(\"text.echo\", \"two\")"),
            ])
            .unwrap();
        let checkpoint = engine.checkpoint_after(&plan, 1).unwrap();

        let full_approval = engine.approve(&plan).unwrap();
        assert_eq!(
            engine
                .resume(&plan, &checkpoint, full_approval)
                .unwrap_err(),
            WorkflowError::ApprovalMismatch
        );

        let resume_approval = engine.approve_resume(&plan, &checkpoint).unwrap();
        engine.resume(&plan, &checkpoint, resume_approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert!(matches!(
            engine.events().iter().rev().nth(2),
            Some(WorkflowEvent::Resumed {
                plan_id,
                completed_steps: 1,
            }) if *plan_id == plan.id()
        ));
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn durable_checkpoint_validates_a_recreated_plan_with_fresh_capabilities() {
        let steps = vec![
            WorkflowStep::new("first", "let first = 1"),
            WorkflowStep::new("second", "use mod.tool\ntool.call(\"text.echo\", \"two\")"),
        ];
        let mut original_engine = WorkflowEngine::new(CapabilityRuntime::default());
        original_engine
            .plan(vec![WorkflowStep::new("unrelated", "let unrelated = true")])
            .unwrap();
        let original_plan = original_engine.plan(steps.clone()).unwrap();
        let encoded = original_engine
            .checkpoint_after(&original_plan, 1)
            .unwrap()
            .to_json()
            .unwrap();

        let mut restarted_runtime = CapabilityRuntime::default();
        restarted_runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut restarted_engine = WorkflowEngine::new(restarted_runtime);
        let restarted_plan = restarted_engine.plan(steps).unwrap();
        let restored = WorkflowCheckpoint::from_json(&encoded).unwrap();

        assert_ne!(original_plan.id(), restarted_plan.id());
        assert_eq!(original_plan.fingerprint(), restarted_plan.fingerprint());
        let approval = restarted_engine
            .approve_resume(&restarted_plan, &restored)
            .unwrap();
        restarted_engine
            .resume(&restarted_plan, &restored, approval)
            .unwrap();

        assert_eq!(restarted_engine.runtime().audit().len(), 1);
    }

    #[test]
    fn operation_ledger_persists_metadata_without_raw_input_or_source() {
        let steps = vec![WorkflowStep::new(
            "publish",
            "use mod.tool\ntool.start(\"release.publish\", \"private source\").await()",
        )];
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine.plan(steps.clone()).unwrap();
        let mut ledger = engine.operation_ledger(&plan).unwrap();

        engine
            .record_operation(
                &plan,
                &mut ledger,
                "publish",
                "release.publish",
                "release-2026-1",
                b"private request payload",
            )
            .unwrap();
        let encoded = ledger.to_json().unwrap();
        let decoded = WorkflowOperationLedger::from_json(&encoded).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(decoded, ledger);
        assert_eq!(decoded.plan_fingerprint(), plan.fingerprint());
        assert_eq!(decoded.revision(), 1);
        assert_eq!(decoded.operations().len(), 1);
        let operation = decoded.operation("release-2026-1").unwrap();
        assert_eq!(operation.step_id(), "publish");
        assert_eq!(operation.tool(), "release.publish");
        assert_eq!(operation.state(), WorkflowOperationState::Pending);
        assert!(operation.matches_input(b"private request payload"));
        assert!(!operation.matches_input(b"another payload"));
        assert_eq!(object.len(), 4);
        assert!(object.contains_key("format_version"));
        assert!(object.contains_key("revision"));
        assert!(object.contains_key("plan_fingerprint"));
        assert!(object.contains_key("operations"));
        assert!(!encoded.contains("private request payload"));
        assert!(!encoded.contains("private source"));
        assert!(!encoded.contains("approval"));

        let mut restarted_engine = WorkflowEngine::new(CapabilityRuntime::default());
        let recreated_plan = restarted_engine.plan(steps).unwrap();
        restarted_engine
            .validate_operation_ledger(&recreated_plan, &decoded)
            .unwrap();
        assert_eq!(
            restarted_engine
                .validate_operation_ledger_at_or_after(&recreated_plan, &decoded, 2)
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::StaleRevision {
                actual: 1,
                minimum: 2,
            })
        );
        let changed_plan = restarted_engine
            .plan(vec![WorkflowStep::new("publish", "let release = false")])
            .unwrap();
        assert_eq!(
            restarted_engine
                .validate_operation_ledger(&changed_plan, &decoded)
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::PlanMismatch)
        );
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::OperationRecorded {
                plan_id,
                step_id,
                tool,
            }) if *plan_id == plan.id() && step_id == "publish" && tool == "release.publish"
        ));
    }

    #[test]
    fn authenticated_storage_restores_a_durable_operation_ledger() {
        let steps = vec![WorkflowStep::new("publish", "let release = true")];
        let mut original_engine = WorkflowEngine::new(CapabilityRuntime::default());
        let original_plan = original_engine.plan(steps.clone()).unwrap();
        let mut ledger = original_engine.operation_ledger(&original_plan).unwrap();
        original_engine
            .record_derived_operation(
                &original_plan,
                &mut ledger,
                "publish",
                "release.publish",
                b"{\"version\":\"1.2.3\"}",
                b"release-42:publish:1",
            )
            .unwrap();

        let record_key = StorageRecordKey::new("workflow-ledger", "release-42").unwrap();
        let keyring = StorageKeyring::new(
            StorageKeyId::new("storage-v1").unwrap(),
            StorageKey::from_bytes([21; STORAGE_KEY_BYTES]),
        );
        let mut store = AuthenticatedStore::new(VolatileMemoryStore::default(), keyring);
        let encoded = ledger.to_json().unwrap();
        let persisted = store.create(&record_key, encoded.as_bytes()).unwrap();
        assert_eq!(persisted.revision(), 1);

        let restored_record = store.load(&record_key).unwrap().unwrap();
        let restored_json = std::str::from_utf8(restored_record.payload()).unwrap();
        let restored_ledger = WorkflowOperationLedger::from_json(restored_json).unwrap();

        let mut restarted_engine = WorkflowEngine::new(CapabilityRuntime::default());
        let restarted_plan = restarted_engine.plan(steps).unwrap();
        restarted_engine
            .validate_operation_ledger_at_or_after(&restarted_plan, &restored_ledger, 1)
            .unwrap();
        assert_eq!(restored_ledger, ledger);
        assert_eq!(original_plan.fingerprint(), restarted_plan.fingerprint());
    }

    #[test]
    fn workflow_operation_dispatch_requires_the_persisted_canonical_input() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new("publish", "let release = true")])
            .unwrap();
        let mut ledger = engine.operation_ledger(&plan).unwrap();
        let payload = ToolPayload::Json(serde_json::json!({
            "version": "1.2.3",
            "channel": "stable",
        }));
        let input = canonical_operation_input_bytes(&payload).unwrap();
        let operation_key = engine
            .record_derived_operation(
                &plan,
                &mut ledger,
                "publish",
                "release.publish",
                &input,
                b"release-42:publish:1",
            )
            .unwrap();

        let request = engine
            .operation_dispatch_request(
                &plan,
                &ledger,
                &operation_key,
                payload.clone(),
                "session-1",
                "operation-request-1",
            )
            .unwrap();
        assert_eq!(request.tool, "release.publish");
        assert_eq!(request.operation_key, operation_key);

        let (mut host, mut worker) = operation_reconciliation_authenticators();
        let outbound = engine
            .prepare_authenticated_operation_dispatch(
                &plan,
                &ledger,
                &operation_key,
                payload.clone(),
                "operation-request-2",
                &mut host,
            )
            .unwrap();
        assert_eq!(
            worker.open(outbound.frame).unwrap(),
            WorkerMessage::DispatchOperation {
                request: outbound.request.clone(),
            }
        );
        let (_, mut worker_role) = operation_reconciliation_authenticators();
        assert_eq!(
            engine
                .prepare_authenticated_operation_dispatch(
                    &plan,
                    &ledger,
                    &operation_key,
                    payload.clone(),
                    "operation-request-3",
                    &mut worker_role,
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationDispatchRequiresHostAuthenticator,
            )
        );

        assert_eq!(
            engine
                .operation_dispatch_request(
                    &plan,
                    &ledger,
                    &operation_key,
                    ToolPayload::Json(serde_json::json!({
                        "version": "1.2.4",
                        "channel": "stable",
                    })),
                    "session-1",
                    "operation-request-4",
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::InputFingerprintMismatch(
                operation_key,
            ))
        );
    }

    #[test]
    fn derived_operation_keys_bind_plan_input_and_nonce() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new("publish", "let release = true")])
            .unwrap();
        let key = engine
            .derive_operation_key(
                &plan,
                "publish",
                "release.publish",
                b"request",
                b"run-1:operation-1",
            )
            .unwrap();
        assert!(key.starts_with("op-"));
        assert_eq!(key.len(), 3 + blake3::OUT_LEN * 2);
        assert_eq!(
            key,
            engine
                .derive_operation_key(
                    &plan,
                    "publish",
                    "release.publish",
                    b"request",
                    b"run-1:operation-1",
                )
                .unwrap()
        );
        assert_ne!(
            key,
            engine
                .derive_operation_key(
                    &plan,
                    "publish",
                    "release.publish",
                    b"different request",
                    b"run-1:operation-1",
                )
                .unwrap()
        );
        assert_ne!(
            key,
            engine
                .derive_operation_key(
                    &plan,
                    "publish",
                    "release.publish",
                    b"request",
                    b"run-1:operation-2",
                )
                .unwrap()
        );
        let changed_plan = engine
            .plan(vec![WorkflowStep::new("publish", "let release = false")])
            .unwrap();
        assert_ne!(
            key,
            engine
                .derive_operation_key(
                    &changed_plan,
                    "publish",
                    "release.publish",
                    b"request",
                    b"run-1:operation-1",
                )
                .unwrap()
        );
        assert_eq!(
            engine
                .derive_operation_key(&plan, "publish", "release.publish", b"request", b"",)
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::EmptyOperationNonce)
        );
        assert_eq!(
            engine
                .derive_operation_key(
                    &plan,
                    "publish",
                    "release.publish",
                    b"request",
                    &[0; MAX_WORKFLOW_OPERATION_NONCE_BYTES + 1],
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::OperationNonceTooLarge {
                actual: MAX_WORKFLOW_OPERATION_NONCE_BYTES + 1,
                maximum: MAX_WORKFLOW_OPERATION_NONCE_BYTES,
            })
        );

        let mut ledger = engine.operation_ledger(&plan).unwrap();
        let recorded = engine
            .record_derived_operation(
                &plan,
                &mut ledger,
                "publish",
                "release.publish",
                b"request",
                b"run-1:operation-1",
            )
            .unwrap();
        assert_eq!(recorded, key);
        assert!(ledger.operation(&key).is_some());
    }

    #[test]
    fn operation_ledger_reconciles_bound_observations_without_retaining_output() {
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

        let request = engine
            .operation_reconcile_request(
                &plan,
                &ledger,
                "release-2026-1",
                b"request",
                "session-1",
                "reconcile-1",
            )
            .unwrap();
        let running = OperationReconcileResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            request.tool.clone(),
            request.operation_key.clone(),
            OperationStatus::Running,
        )
        .unwrap();
        assert_eq!(
            engine
                .apply_verified_operation_reconciliation(&plan, &mut ledger, &request, &running)
                .unwrap(),
            WorkflowOperationState::Running
        );
        assert_eq!(ledger.revision(), 2);

        let succeeded = OperationReconcileResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            request.tool.clone(),
            request.operation_key.clone(),
            OperationStatus::Succeeded {
                payload: ToolPayload::Json(serde_json::json!({"output": "private result"})),
            },
        )
        .unwrap();
        assert_eq!(
            engine
                .apply_verified_operation_reconciliation(&plan, &mut ledger, &request, &succeeded,)
                .unwrap(),
            WorkflowOperationState::Succeeded
        );
        assert_eq!(
            engine
                .apply_verified_operation_reconciliation(&plan, &mut ledger, &request, &succeeded,)
                .unwrap(),
            WorkflowOperationState::Succeeded
        );
        assert_eq!(
            ledger.operation("release-2026-1").unwrap().state(),
            WorkflowOperationState::Succeeded
        );
        assert_eq!(ledger.revision(), 3);
        assert!(!ledger.to_json().unwrap().contains("private result"));

        let failed = OperationReconcileResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            request.tool.clone(),
            request.operation_key.clone(),
            OperationStatus::Failed {
                message: "private worker error".to_owned(),
            },
        )
        .unwrap();
        assert_eq!(
            engine
                .apply_verified_operation_reconciliation(&plan, &mut ledger, &request, &failed)
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::InvalidStateTransition {
                current: WorkflowOperationState::Succeeded,
                observed: WorkflowOperationState::Failed,
            })
        );
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::OperationObserved {
                plan_id,
                step_id,
                tool,
                state: WorkflowOperationState::Succeeded,
            }) if *plan_id == plan.id() && step_id == "publish" && tool == "release.publish"
        ));
    }

    #[test]
    fn authenticated_operation_ledger_reconciliation_rejects_tampering() {
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
        let (mut host, mut worker) = operation_reconciliation_authenticators();

        let outbound = engine
            .prepare_authenticated_operation_reconciliation(
                &plan,
                &ledger,
                "release-2026-1",
                b"request",
                "reconcile-1",
                &mut host,
            )
            .unwrap();
        assert_eq!(
            worker.open(outbound.frame).unwrap(),
            WorkerMessage::ReconcileOperation {
                request: outbound.request.clone(),
            }
        );
        let result = OperationReconcileResult::new(
            outbound.request.session_id.clone(),
            outbound.request.request_id.clone(),
            outbound.request.tool.clone(),
            outbound.request.operation_key.clone(),
            OperationStatus::Succeeded {
                payload: ToolPayload::Text("private output".to_owned()),
            },
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::ReconciledOperation { result })
            .unwrap();
        let mut tampered = response.clone();
        let replacement = if tampered.auth_tag.starts_with('0') {
            "1"
        } else {
            "0"
        };
        tampered.auth_tag.replace_range(0..1, replacement);

        assert_eq!(
            engine
                .apply_authenticated_operation_reconciliation(
                    &plan,
                    &mut ledger,
                    &outbound.request,
                    &mut host,
                    tampered,
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(
                ProtocolError::InvalidAuthenticationTag,
            ))
        );
        assert_eq!(
            ledger.operation("release-2026-1").unwrap().state(),
            WorkflowOperationState::Pending
        );
        assert_eq!(ledger.revision(), 1);

        assert_eq!(
            engine
                .apply_authenticated_operation_reconciliation(
                    &plan,
                    &mut ledger,
                    &outbound.request,
                    &mut host,
                    response,
                )
                .unwrap(),
            WorkflowOperationState::Succeeded
        );
        assert_eq!(ledger.revision(), 2);
        assert!(!ledger.to_json().unwrap().contains("private output"));
    }

    #[test]
    fn operation_ledger_rejects_mismatched_records_and_storage_bounds() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new("publish", "let release = true")])
            .unwrap();
        let mut ledger = engine.operation_ledger(&plan).unwrap();

        assert_eq!(
            engine
                .record_operation(
                    &plan,
                    &mut ledger,
                    "unknown",
                    "release.publish",
                    "release-2026-1",
                    b"request",
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownStep(
                "unknown".to_owned()
            ))
        );
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
        assert_eq!(
            engine
                .operation_reconcile_request(
                    &plan,
                    &ledger,
                    "release-2026-1",
                    b"different request",
                    "session-1",
                    "reconcile-1",
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::InputFingerprintMismatch(
                "release-2026-1".to_owned(),
            ))
        );
        assert_eq!(
            engine
                .record_operation(
                    &plan,
                    &mut ledger,
                    "publish",
                    "release.publish",
                    "release-2026-1",
                    b"request",
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::DuplicateOperationKey(
                "release-2026-1".to_owned()
            ))
        );
        assert_eq!(
            ledger
                .record(
                    "publish",
                    "release.publish",
                    "large-input",
                    &[0; MAX_WORKFLOW_OPERATION_INPUT_BYTES + 1],
                )
                .unwrap_err(),
            WorkflowOperationLedgerError::InputTooLarge {
                actual: MAX_WORKFLOW_OPERATION_INPUT_BYTES + 1,
                maximum: MAX_WORKFLOW_OPERATION_INPUT_BYTES,
            }
        );
        assert_eq!(
            WorkflowOperationLedger::from_json(
                &"x".repeat(MAX_WORKFLOW_OPERATION_LEDGER_BYTES + 1)
            )
            .unwrap_err(),
            WorkflowOperationLedgerError::TooLarge
        );

        let mut encoded: serde_json::Value =
            serde_json::from_str(&ledger.to_json().unwrap()).unwrap();
        encoded["operations"][0]["tool"] = serde_json::json!("bad tool");
        assert_eq!(
            WorkflowOperationLedger::from_json(&encoded.to_string()).unwrap_err(),
            WorkflowOperationLedgerError::InvalidTool("bad tool".to_owned())
        );
    }

    #[test]
    fn checkpoint_approval_binds_the_exact_prefix_and_plan() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![
                WorkflowStep::new("first", "let first = 1"),
                WorkflowStep::new("second", "let second = 2"),
            ])
            .unwrap();
        let no_steps = engine.checkpoint_after(&plan, 0).unwrap();
        let first_step = engine.checkpoint_after(&plan, 1).unwrap();
        let approval = engine.approve_resume(&plan, &no_steps).unwrap();

        assert_eq!(
            engine.resume(&plan, &first_step, approval).unwrap_err(),
            WorkflowError::ApprovalMismatch
        );

        let changed_plan = engine
            .plan(vec![
                WorkflowStep::new("first", "let first = 1"),
                WorkflowStep::new("second", "let second = 3"),
            ])
            .unwrap();
        assert_eq!(
            engine.approve_resume(&changed_plan, &no_steps).unwrap_err(),
            WorkflowError::Checkpoint(WorkflowCheckpointError::PlanMismatch)
        );
    }

    #[test]
    fn checkpoint_decoder_enforces_its_input_boundary() {
        let oversized = "x".repeat(MAX_WORKFLOW_CHECKPOINT_BYTES + 1);
        assert_eq!(
            WorkflowCheckpoint::from_json(&oversized).unwrap_err(),
            WorkflowCheckpointError::TooLarge
        );

        let invalid = r#"{
            "format_version": 1,
            "plan_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "completed_step_ids": [],
            "unexpected": true
        }"#;
        assert_eq!(
            WorkflowCheckpoint::from_json(invalid).unwrap_err(),
            WorkflowCheckpointError::InvalidEncoding
        );

        let long_step_id = "a".repeat(MAX_WORKFLOW_STEP_ID_BYTES + 1);
        let invalid_step_id = serde_json::json!({
            "format_version": WORKFLOW_CHECKPOINT_FORMAT_VERSION,
            "plan_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "completed_step_ids": [long_step_id],
        })
        .to_string();
        assert_eq!(
            WorkflowCheckpoint::from_json(&invalid_step_id).unwrap_err(),
            WorkflowCheckpointError::InvalidStepId("a".repeat(MAX_WORKFLOW_STEP_ID_BYTES + 1))
        );

        let long_step_id = "a".repeat(MAX_WORKFLOW_STEP_ID_BYTES + 1);
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        assert_eq!(
            engine
                .plan(vec![WorkflowStep::new(
                    long_step_id.clone(),
                    "let value = 1"
                )])
                .unwrap_err(),
            WorkflowError::InvalidStepId(long_step_id)
        );
    }

    #[test]
    fn failed_runs_report_a_checkpointable_completed_prefix() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("first", "use mod.tool\ntool.call(\"text.echo\", \"one\")"),
                WorkflowStep::new("fail", "use mod.tool\ntool.call(\"shell.exec\", \"two\")"),
            ])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        let error = engine.execute(&plan, approval).unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 1,
                ..
            } if step_id == "fail"
        ));
        let checkpoint = engine.checkpoint_after(&plan, 1).unwrap();
        assert_eq!(checkpoint.completed_step_ids(), ["first"]);
    }

    #[test]
    fn approval_cannot_execute_a_different_plan() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let first = engine
            .plan(vec![WorkflowStep::new("first", "let value = 1")])
            .unwrap();
        let second = engine
            .plan(vec![WorkflowStep::new("second", "let value = 2")])
            .unwrap();
        let approval = engine.approve(&first).unwrap();

        assert_eq!(
            engine.execute(&second, approval).unwrap_err(),
            WorkflowError::ApprovalMismatch
        );
    }

    #[test]
    fn approval_cannot_cross_workflow_engines() {
        let mut first_engine = WorkflowEngine::new(CapabilityRuntime::default());
        let first_plan = first_engine
            .plan(vec![WorkflowStep::new("first", "let value = 1")])
            .unwrap();
        let approval = first_engine.approve(&first_plan).unwrap();

        let mut second_engine = WorkflowEngine::new(CapabilityRuntime::default());
        let second_plan = second_engine
            .plan(vec![WorkflowStep::new("second", "let value = 2")])
            .unwrap();

        assert_eq!(
            second_engine.execute(&second_plan, approval).unwrap_err(),
            WorkflowError::ApprovalMismatch
        );
    }

    #[test]
    fn foreign_plans_cannot_be_approved_or_checkpointed() {
        let mut first_engine = WorkflowEngine::new(CapabilityRuntime::default());
        let first_plan = first_engine
            .plan(vec![WorkflowStep::new("first", "let value = 1")])
            .unwrap();
        let first_approval = first_engine.approve(&first_plan).unwrap();
        let mut second_engine = WorkflowEngine::new(CapabilityRuntime::default());

        assert_eq!(
            second_engine
                .execute(&first_plan, first_approval)
                .unwrap_err(),
            WorkflowError::PlanOwnershipMismatch
        );
        assert_eq!(
            second_engine.approve(&first_plan).unwrap_err(),
            WorkflowError::PlanOwnershipMismatch
        );
        assert_eq!(
            second_engine.checkpoint_after(&first_plan, 0).unwrap_err(),
            WorkflowError::PlanOwnershipMismatch
        );
    }

    #[test]
    fn failed_step_stops_the_remaining_plan() {
        let mut runtime = CapabilityRuntime::default();
        let mut policy = ToolPolicy::new("text.echo");
        policy.max_calls = 2;
        runtime
            .register_tool(policy, |request| Ok(request.input.clone()))
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("first", "use mod.tool\ntool.call(\"text.echo\", \"one\")"),
                WorkflowStep::new(
                    "deny",
                    "use mod.tool\ntool.call(\"shell.exec\", \"whoami\")",
                ),
                WorkflowStep::new("not-run", "use mod.tool\ntool.call(\"text.echo\", \"two\")"),
            ])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        let error = engine.execute(&plan, approval).unwrap_err();

        assert!(matches!(error, WorkflowError::StepFailed { .. }));
        assert_eq!(engine.runtime().audit().len(), 2);
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::StepFailed { step_id, .. }) if step_id == "deny"
        ));
    }

    #[test]
    fn approved_plan_drives_a_deferred_capability_to_completion() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "deferred-echo",
                "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.echo\", \"release notes\").await()\nassert(output == \"release notes\")",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        engine.execute(&plan, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Allowed
        );
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn approved_plan_drives_a_deferred_json_capability_to_completion() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_json_tool(ToolPolicy::json("math.add"), |request| {
                let left = request.input["left"].as_i64().unwrap();
                let right = request.input["right"].as_i64().unwrap();
                Ok(splash_capabilities::json!({"total": left + right}))
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "deferred-json-add",
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.start_json(\"math.add\", {left: 20 right: 22}).await()\nlet response = raw.parse_json()\nassert(response.total == 42)",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        engine.execute(&plan, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Allowed
        );
    }
}
