#![forbid(unsafe_code)]

//! Host-owned workflow state for Splash.
//!
//! Scripts evaluate individual steps, but they cannot mint approval or skip
//! host policy. The event log remains in-memory, while bounded data-only
//! checkpoints let a host persist an explicitly attested completed prefix and
//! require fresh approval before a restart can execute the remaining steps.

/// Sealed mobile and embedded workflow profile with static local adapters.
pub mod mobile;

/// Authenticated, bounded workflow-event persistence and replay support.
///
/// Durable event records are telemetry. They never restore an approval,
/// capability lease, suspended promise, or external operation.
pub mod durable_events;

/// Fenced, reconciliation-only recovery for a reaped Linux Bubblewrap worker.
///
/// This integration is host-only and feature gated because it owns process
/// lifecycle, authenticated JSON-line transport, and rollback-protected
/// workflow-ledger persistence.
#[cfg(feature = "bubblewrap-recovery")]
pub mod bubblewrap_recovery;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::ops::Index;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use splash_capabilities::{
    CapabilityLease, CapabilityLeaseError, CapabilityLeaseEvaluationError, CapabilityLeaseGrant,
    CapabilityRuntime, ExternalToolCancellationRequest, ExternalToolError, ExternalToolId,
    ExternalToolInvocation, JsonValue, ToolError,
};
use splash_core::{
    check_syntax_named, parse_bounded_json, serialize_bounded_json, tool_call_hint_report_named,
    Evaluation, ExecutionLimits, RuntimeError, RuntimeJsonError, SyntaxReport, ToolCallHint,
    MAX_SYNTAX_DIAGNOSTICS,
};
use splash_protocol::{
    canonical_operation_input_bytes, AuthenticatedWorkerMessage, CapabilityGrant,
    OperationCompensationBinding, OperationCompensationRequest, OperationCompensationResult,
    OperationDispatchRequest, OperationReconcileRequest, OperationReconcileResult, OperationStatus,
    ProtocolError, SessionAuthenticator, SessionRole, ToolPayload, WorkerMessage,
};
use splash_schema::{JsonSchema, SchemaViolation};

static NEXT_ENGINE_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum serialized checkpoint size accepted from durable storage.
pub const MAX_WORKFLOW_CHECKPOINT_BYTES: usize = 16 * 1024;
/// Maximum trusted steps retained in one workflow plan.
///
/// This bounds plan review, approval state, checkpoint prefixes, and
/// per-step capability queues. Hosts that need a larger orchestration graph
/// should compose independently approved plans rather than retain an
/// unbounded generated plan in one engine.
pub const MAX_WORKFLOW_STEPS: usize = 1_024;
/// Maximum number of completed step IDs a checkpoint may contain.
pub const MAX_WORKFLOW_CHECKPOINT_STEPS: usize = MAX_WORKFLOW_STEPS;
/// Maximum UTF-8 byte length of a workflow step ID.
pub const MAX_WORKFLOW_STEP_ID_BYTES: usize = 128;
/// Maximum aggregate source bytes retained in one workflow plan.
///
/// The per-step evaluator limits still apply at execution. This separate plan
/// bound prevents a generated plan from multiplying review and approval memory
/// before any step reaches the runtime.
pub const MAX_WORKFLOW_PLAN_SOURCE_BYTES: usize = 1_048_576;
/// Maximum direct tool-call hints retained across one workflow review.
///
/// This is separate from source and per-step syntax limits so an LLM-generated
/// workflow cannot turn bounded source into an unbounded operator/LLM review
/// response. Each [`WorkflowStepReview`] reports whether its own hints were
/// truncated by either this aggregate limit or the core per-source limit.
pub const MAX_WORKFLOW_REVIEW_TOOL_CALL_HINTS: usize = 4_096;
/// Current serialized LLM workflow-draft format version.
pub const WORKFLOW_DRAFT_FORMAT_VERSION: u8 = 1;
/// Maximum JSON bytes accepted for one untrusted workflow draft.
///
/// This is separate from the aggregate decoded source limit. The wire format
/// can expand source through JSON escaping, while a bounded envelope keeps a
/// malformed or generated draft from causing unbounded decode work.
pub const MAX_WORKFLOW_DRAFT_BYTES: usize = 2 * 1024 * 1024;
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
pub const WORKFLOW_OPERATION_LEDGER_FORMAT_VERSION: u8 = 2;
/// Default number of recent in-memory workflow events retained by an engine.
///
/// This event view is operational telemetry, not a durable replay record. A
/// host must persist its own authenticated checkpoints and operation ledgers
/// before effectful recovery decisions.
pub const DEFAULT_MAX_WORKFLOW_EVENTS: usize = 1_024;
/// Absolute maximum capacity accepted for an in-memory workflow event view.
///
/// Hosts that need longer retention must export selected telemetry into a
/// separate authenticated store. Workflow events are never restart authority.
pub const MAX_WORKFLOW_EVENTS: usize = 8_192;
/// Format version for persisted workflow-event journals.
pub const WORKFLOW_EVENT_JOURNAL_FORMAT_VERSION: u8 = 1;
/// Maximum events retained by one durable workflow-event journal.
///
/// The journal also has a serialized-byte cap so a full capacity may retain
/// fewer events when identifiers make the encoded record larger.
pub const MAX_DURABLE_WORKFLOW_EVENTS: usize = 1_024;
/// Maximum serialized payload for one durable workflow-event journal.
///
/// This deliberately leaves authenticated-envelope headroom below the storage
/// payload boundary and prevents telemetry from consuming a workflow record's
/// whole durable slot.
pub const MAX_DURABLE_WORKFLOW_EVENT_JOURNAL_BYTES: usize = 192 * 1024;
/// Bounded optimistic compare-and-swap retries used by the event recorder.
pub const MAX_DURABLE_WORKFLOW_EVENT_STORE_RETRIES: usize = 4;
/// Maximum serialized bytes retained in one dataflow input-and-output context.
///
/// This is a host-memory and approval-review bound, separate from source,
/// tool payload, and checkpoint limits. A workflow checkpoint records only a
/// fingerprint of this context, never the context itself.
pub const MAX_WORKFLOW_DATA_BYTES: usize = 64 * 1024;
/// Maximum JSON nesting depth retained in one dataflow context.
pub const MAX_WORKFLOW_DATA_DEPTH: usize = 64;
/// Maximum aggregate schema-source bytes retained in one dataflow contract.
///
/// The limit applies to the host-owned input schema, output schemas, and
/// bound step IDs. It is separate from the 64 KiB data context so a large
/// generated plan cannot multiply the per-schema limit into an impractical
/// embedded-memory policy object.
pub const MAX_WORKFLOW_DATA_CONTRACT_BYTES: usize = 256 * 1024;
/// Current serialized host-dataflow context format version.
pub const WORKFLOW_DATA_FORMAT_VERSION: u8 = 1;
/// Host-injected Splash identifier containing the current dataflow context.
pub const WORKFLOW_DATA_GLOBAL: &str = "workflow";

const WORKFLOW_DATA_FINGERPRINT_DOMAIN: &[u8] = b"splash-workflow-data-v1";
const WORKFLOW_DATA_CONTRACT_FINGERPRINT_DOMAIN: &[u8] = b"splash-workflow-data-contract-v1";

/// Maximum untrusted bytes included in a workflow error message.
///
/// Workflow drafts, checkpoints, and durable ledgers can originate outside the
/// current process. Error rendering must therefore avoid reflecting arbitrary
/// control bytes or an attacker-sized value into a terminal or log.
const MAX_WORKFLOW_ERROR_TEXT_PREVIEW_BYTES: usize = 96;

struct WorkflowErrorText<'value>(&'value str);

impl Display for WorkflowErrorText<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("`")?;
        for byte in self
            .0
            .as_bytes()
            .iter()
            .take(MAX_WORKFLOW_ERROR_TEXT_PREVIEW_BYTES)
        {
            match byte {
                b'\\' => formatter.write_str("\\\\")?,
                b'`' => formatter.write_str("\\`")?,
                b' '..=b'~' => write!(formatter, "{}", char::from(*byte))?,
                _ => write!(formatter, "\\x{byte:02x}")?,
            }
        }
        formatter.write_str("`")?;
        if self.0.len() > MAX_WORKFLOW_ERROR_TEXT_PREVIEW_BYTES {
            write!(formatter, " ({} bytes; preview truncated)", self.0.len())?;
        }
        Ok(())
    }
}

fn workflow_error_text(value: &str) -> WorkflowErrorText<'_> {
    WorkflowErrorText(value)
}

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

/// Bounded, data-only context passed between trusted workflow steps.
///
/// The script-visible shape is always `{ input, outputs }`. `input` is set
/// by the host before approval; `outputs` is filled only from completed step
/// results that can be represented as bounded JSON. This type carries no
/// capability, approval, tool handle, or external-operation identity. It can
/// retain a non-authorizing host contract digest so checkpoint creation cannot
/// silently drop an already-bound schema policy.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkflowData {
    input: JsonValue,
    outputs: BTreeMap<String, JsonValue>,
    contract_fingerprint: Option<String>,
}

impl WorkflowData {
    /// Creates a fresh, bounded dataflow context with no completed outputs.
    pub fn new(input: JsonValue) -> Result<Self, WorkflowDataError> {
        let data = Self {
            input,
            outputs: BTreeMap::new(),
            contract_fingerprint: None,
        };
        data.validate()?;
        Ok(data)
    }

    /// Parses a bounded JSON value suitable for use as fresh workflow input.
    pub fn from_input_json(document: &str) -> Result<Self, WorkflowDataError> {
        let input = parse_bounded_json(document, MAX_WORKFLOW_DATA_BYTES, MAX_WORKFLOW_DATA_DEPTH)
            .map_err(WorkflowDataError::Json)?;
        Self::new(input)
    }

    /// Decodes a host-owned persisted versioned dataflow context.
    ///
    /// This is data transport only. Decoding does not approve a workflow,
    /// issue a lease, restore a promise, or dispatch a tool.
    pub fn from_json(document: &str) -> Result<Self, WorkflowDataError> {
        let value = parse_bounded_json(document, MAX_WORKFLOW_DATA_BYTES, MAX_WORKFLOW_DATA_DEPTH)
            .map_err(WorkflowDataError::Json)?;
        let JsonValue::Object(mut fields) = value else {
            return Err(WorkflowDataError::InvalidDocument);
        };
        let Some(JsonValue::Number(format_version)) = fields.remove("format_version") else {
            return Err(WorkflowDataError::InvalidDocument);
        };
        let Some(format_version) = format_version
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
        else {
            return Err(WorkflowDataError::InvalidDocument);
        };
        if format_version != WORKFLOW_DATA_FORMAT_VERSION {
            return Err(WorkflowDataError::UnsupportedFormatVersion {
                actual: format_version,
                expected: WORKFLOW_DATA_FORMAT_VERSION,
            });
        }
        let Some(input) = fields.remove("input") else {
            return Err(WorkflowDataError::InvalidDocument);
        };
        let Some(JsonValue::Object(outputs)) = fields.remove("outputs") else {
            return Err(WorkflowDataError::InvalidDocument);
        };
        let contract_fingerprint = match fields.remove("contract_fingerprint") {
            None => None,
            Some(JsonValue::String(fingerprint)) if is_plan_fingerprint(&fingerprint) => {
                Some(fingerprint)
            }
            Some(_) => return Err(WorkflowDataError::InvalidContractFingerprint),
        };
        if !fields.is_empty() {
            return Err(WorkflowDataError::InvalidDocument);
        }

        let mut data = Self {
            input,
            outputs: BTreeMap::new(),
            contract_fingerprint,
        };
        for (step_id, output) in outputs {
            if !is_valid_step_id(&step_id) {
                return Err(WorkflowDataError::InvalidOutputStepId(step_id));
            }
            data.outputs.insert(step_id, output);
        }
        data.validate()?;
        Ok(data)
    }

    /// Encodes this context for host-owned persistence or review.
    pub fn to_json(&self) -> Result<String, WorkflowDataError> {
        self.encode_persistence_document()
    }

    /// Returns the immutable host-provided initial input.
    pub fn input(&self) -> &JsonValue {
        &self.input
    }

    /// Returns outputs by completed trusted step ID in stable key order.
    pub fn outputs(&self) -> &BTreeMap<String, JsonValue> {
        &self.outputs
    }

    /// Returns the JSON result retained for one completed trusted step.
    pub fn output(&self, step_id: &str) -> Option<&JsonValue> {
        self.outputs.get(step_id)
    }

    /// Returns the optional host policy digest retained with this context.
    ///
    /// The digest is not script-visible authority and is excluded from the
    /// data-only [`Self::fingerprint`] used to bind raw input and outputs.
    pub fn contract_fingerprint(&self) -> Option<&str> {
        self.contract_fingerprint.as_deref()
    }

    /// Returns a stable digest binding this exact data-only context.
    pub fn fingerprint(&self) -> Result<String, WorkflowDataError> {
        let encoded = self.encode_script_context()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(WORKFLOW_DATA_FINGERPRINT_DOMAIN);
        update_plan_fingerprint_component(&mut hasher, encoded.as_bytes());
        Ok(hasher.finalize().to_hex().to_string())
    }

    fn script_context(&self) -> JsonValue {
        let outputs = self
            .outputs
            .iter()
            .map(|(step_id, output)| (step_id.clone(), output.clone()))
            .collect();
        let mut context = serde_json::Map::new();
        context.insert("input".to_owned(), self.input.clone());
        context.insert("outputs".to_owned(), JsonValue::Object(outputs));
        JsonValue::Object(context)
    }

    fn persistence_document(&self) -> JsonValue {
        let JsonValue::Object(mut document) = self.script_context() else {
            unreachable!("workflow data script context is always an object");
        };
        document.insert(
            "format_version".to_owned(),
            JsonValue::from(WORKFLOW_DATA_FORMAT_VERSION),
        );
        if let Some(contract_fingerprint) = &self.contract_fingerprint {
            document.insert(
                "contract_fingerprint".to_owned(),
                JsonValue::String(contract_fingerprint.clone()),
            );
        }
        JsonValue::Object(document)
    }

    fn encode_script_context(&self) -> Result<String, WorkflowDataError> {
        serialize_bounded_json(
            &self.script_context(),
            MAX_WORKFLOW_DATA_BYTES,
            MAX_WORKFLOW_DATA_DEPTH,
        )
        .map_err(WorkflowDataError::Json)
    }

    fn encode_persistence_document(&self) -> Result<String, WorkflowDataError> {
        serialize_bounded_json(
            &self.persistence_document(),
            MAX_WORKFLOW_DATA_BYTES,
            MAX_WORKFLOW_DATA_DEPTH,
        )
        .map_err(WorkflowDataError::Json)
    }

    fn validate(&self) -> Result<(), WorkflowDataError> {
        if self
            .contract_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| !is_plan_fingerprint(fingerprint))
        {
            return Err(WorkflowDataError::InvalidContractFingerprint);
        }
        let _ = self.encode_persistence_document()?;
        Ok(())
    }

    fn bind_contract(
        &mut self,
        data_contract: &WorkflowDataContract,
    ) -> Result<(), WorkflowDataError> {
        let fingerprint = data_contract.fingerprint();
        if self
            .contract_fingerprint
            .as_deref()
            .is_some_and(|existing| existing != fingerprint)
        {
            return Err(WorkflowDataError::ContractMismatch);
        }
        let previous = self.contract_fingerprint.replace(fingerprint);
        if let Err(error) = self.validate() {
            self.contract_fingerprint = previous;
            return Err(error);
        }
        Ok(())
    }

    fn insert_output(&mut self, step_id: &str, output: JsonValue) -> Result<(), WorkflowDataError> {
        if !is_valid_step_id(step_id) {
            return Err(WorkflowDataError::InvalidOutputStepId(step_id.to_owned()));
        }
        if self.outputs.contains_key(step_id) {
            return Err(WorkflowDataError::DuplicateOutputStepId(step_id.to_owned()));
        }
        self.outputs.insert(step_id.to_owned(), output);
        if let Err(error) = self.validate() {
            self.outputs.remove(step_id);
            return Err(error);
        }
        Ok(())
    }

    fn validate_for_completed_prefix(
        &self,
        plan: &WorkflowPlan,
        completed_step_count: usize,
    ) -> Result<(), WorkflowDataError> {
        self.validate()?;
        let Some(prefix) = plan.steps.get(..completed_step_count) else {
            return Err(WorkflowDataError::CompletedStepCountOutOfRange {
                completed: completed_step_count,
                total: plan.steps.len(),
            });
        };
        if self.outputs.len() != prefix.len()
            || prefix
                .iter()
                .any(|step| !self.outputs.contains_key(&step.id))
        {
            return Err(WorkflowDataError::OutputPrefixMismatch);
        }
        Ok(())
    }
}

/// Rejection while creating, decoding, binding, or extending workflow data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowDataError {
    Json(RuntimeJsonError),
    InvalidDocument,
    UnsupportedFormatVersion { actual: u8, expected: u8 },
    InvalidContractFingerprint,
    ContractMismatch,
    InvalidOutputStepId(String),
    DuplicateOutputStepId(String),
    CompletedStepCountOutOfRange { completed: usize, total: usize },
    OutputPrefixMismatch,
}

impl Display for WorkflowDataError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "workflow data is invalid: {error}"),
            Self::InvalidDocument => formatter.write_str(
                "workflow data must be a versioned object with input and outputs fields",
            ),
            Self::UnsupportedFormatVersion { actual, expected } => write!(
                formatter,
                "workflow data format version {actual} is not supported; expected {expected}"
            ),
            Self::InvalidContractFingerprint => {
                formatter.write_str("workflow data has an invalid contract fingerprint")
            }
            Self::ContractMismatch => {
                formatter.write_str("workflow data is bound to a different dataflow contract")
            }
            Self::InvalidOutputStepId(step_id) => write!(
                formatter,
                "workflow data has an invalid output step id: {}",
                workflow_error_text(step_id)
            ),
            Self::DuplicateOutputStepId(step_id) => write!(
                formatter,
                "workflow data already has an output for step: {}",
                workflow_error_text(step_id)
            ),
            Self::CompletedStepCountOutOfRange { completed, total } => write!(
                formatter,
                "workflow data records {completed} completed steps for a {total}-step plan"
            ),
            Self::OutputPrefixMismatch => {
                formatter.write_str("workflow data outputs do not match the completed step prefix")
            }
        }
    }
}

impl std::error::Error for WorkflowDataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

/// Bounded, data-only workflow input suitable for an LLM or operator review
/// boundary.
///
/// A draft holds only ordered step IDs and Splash source. It has no runtime
/// identity, approval, capability grant, checkpoint, tool result, or external
/// operation handle. Parsing or reviewing one never creates authority; a host
/// must pass it to [`WorkflowEngine::plan_draft`] and explicitly approve the
/// resulting trusted plan before anything can execute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowDraft {
    steps: Vec<WorkflowStep>,
}

impl WorkflowDraft {
    /// Creates a bounded data-only draft from host-provided steps.
    pub fn new(steps: Vec<WorkflowStep>) -> Result<Self, WorkflowDraftError> {
        validate_steps(&steps).map_err(WorkflowDraftError::InvalidPlan)?;
        Ok(Self { steps })
    }

    /// Decodes a bounded versioned JSON workflow draft.
    pub fn from_json(document: &str) -> Result<Self, WorkflowDraftError> {
        Self::from_json_with_max_bytes(document, MAX_WORKFLOW_DRAFT_BYTES)
    }

    /// Decodes a draft with a host-selected wire-byte limit.
    ///
    /// The requested limit can only narrow the absolute draft limit. This is
    /// useful for mobile or embedded ingress paths with a smaller allocation
    /// budget; it never permits a larger document than
    /// [`MAX_WORKFLOW_DRAFT_BYTES`].
    pub fn from_json_with_max_bytes(
        document: &str,
        max_bytes: usize,
    ) -> Result<Self, WorkflowDraftError> {
        let maximum = max_bytes.min(MAX_WORKFLOW_DRAFT_BYTES);
        if document.len() > maximum {
            return Err(WorkflowDraftError::InputTooLarge {
                actual: document.len(),
                maximum,
            });
        }
        let wire: WorkflowDraftWire =
            serde_json::from_str(document).map_err(|_| WorkflowDraftError::InvalidEncoding)?;
        if wire.format_version != WORKFLOW_DRAFT_FORMAT_VERSION {
            return Err(WorkflowDraftError::UnsupportedFormatVersion {
                actual: wire.format_version,
                expected: WORKFLOW_DRAFT_FORMAT_VERSION,
            });
        }
        if wire.steps.too_many {
            return Err(WorkflowDraftError::InvalidPlan(
                WorkflowError::TooManySteps {
                    maximum: MAX_WORKFLOW_STEPS,
                },
            ));
        }
        Self::new(
            wire.steps
                .steps
                .into_iter()
                .map(|step| WorkflowStep::new(step.id, step.source))
                .collect(),
        )
    }

    /// Serializes this data-only draft in the current versioned wire format.
    pub fn to_json(&self) -> Result<String, WorkflowDraftError> {
        let document = WorkflowDraftDocumentRef {
            format_version: WORKFLOW_DRAFT_FORMAT_VERSION,
            steps: self
                .steps
                .iter()
                .map(|step| WorkflowDraftStepRef {
                    id: &step.id,
                    source: &step.source,
                })
                .collect(),
        };
        let encoded = serde_json::to_string(&document)
            .map_err(|_| WorkflowDraftError::SerializationFailed)?;
        if encoded.len() > MAX_WORKFLOW_DRAFT_BYTES {
            return Err(WorkflowDraftError::OutputTooLarge {
                actual: encoded.len(),
                maximum: MAX_WORKFLOW_DRAFT_BYTES,
            });
        }
        Ok(encoded)
    }

    /// Returns the ordered data-only steps retained by this draft.
    pub fn steps(&self) -> &[WorkflowStep] {
        &self.steps
    }

    /// Performs effect-free syntax and direct-tool-call review on every step.
    pub fn review(&self) -> Result<Vec<WorkflowStepReview>, WorkflowError> {
        self.review_with_limits(ExecutionLimits::default())
    }

    /// Performs effect-free review using host-selected canonical limits.
    pub fn review_with_limits(
        &self,
        limits: ExecutionLimits,
    ) -> Result<Vec<WorkflowStepReview>, WorkflowError> {
        review_workflow_steps(&self.steps, limits)
    }

    fn into_steps(self) -> Vec<WorkflowStep> {
        self.steps
    }
}

/// Host-owned capability grant configuration for one trusted workflow step.
///
/// This is configuration, not authority: constructing it creates no lease and
/// cannot invoke a tool. [`WorkflowEngine`] validates its ordered binding to a
/// plan, then issues process-local leases from the current runtime only when a
/// trusted host explicitly requests approval. It intentionally has no Serde
/// implementation and no dynamic authorizer hook; hosts that need custom
/// per-invocation authorization should issue [`CapabilityLease`] values and
/// use the manual lease APIs instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowStepCapabilityPolicy {
    pub step_id: String,
    pub grants: Vec<CapabilityLeaseGrant>,
}

impl WorkflowStepCapabilityPolicy {
    pub fn new<I>(step_id: impl Into<String>, grants: I) -> Self
    where
        I: IntoIterator<Item = CapabilityLeaseGrant>,
    {
        Self {
            step_id: step_id.into(),
            grants: grants.into_iter().collect(),
        }
    }
}

/// Host-owned executable JSON-shape contract for approval-bound workflow data.
///
/// The input schema and one output schema for every trusted plan step are
/// compiled by the host. This configuration is deliberately not serializable:
/// an LLM draft, Splash source, or checkpoint cannot select, weaken, or
/// reconstruct a contract. Use it with one of the explicit
/// `approve_dataflow_with_contract...` APIs.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkflowDataContract {
    input_schema: JsonSchema,
    output_contracts: Vec<WorkflowStepOutputContract>,
}

impl WorkflowDataContract {
    /// Creates a host-owned contract from a compiled input schema and ordered
    /// step-output schemas. Plan binding is checked at approval time.
    pub fn new<I>(
        input_schema: JsonSchema,
        output_contracts: I,
    ) -> Result<Self, WorkflowDataContractError>
    where
        I: IntoIterator<Item = WorkflowStepOutputContract>,
    {
        let output_contracts: Vec<_> = output_contracts.into_iter().collect();
        let bytes = workflow_data_contract_bytes(&input_schema, &output_contracts);
        if bytes > MAX_WORKFLOW_DATA_CONTRACT_BYTES {
            return Err(WorkflowDataContractError::TooLarge {
                actual: bytes,
                maximum: MAX_WORKFLOW_DATA_CONTRACT_BYTES,
            });
        }
        Ok(Self {
            input_schema,
            output_contracts,
        })
    }

    /// Returns the compiled schema applied to the immutable workflow input.
    pub fn input_schema(&self) -> &JsonSchema {
        &self.input_schema
    }

    /// Returns the ordered host-owned output contracts.
    pub fn output_contracts(&self) -> &[WorkflowStepOutputContract] {
        &self.output_contracts
    }

    /// Returns a stable BLAKE3 binding of this exact host-owned schema policy.
    ///
    /// The digest contains no schema source. It can therefore bind a durable
    /// dataflow checkpoint to reviewed contract configuration without making
    /// the contract itself checkpoint data.
    pub fn fingerprint(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(WORKFLOW_DATA_CONTRACT_FINGERPRINT_DOMAIN);
        hasher.update(&(self.output_contracts.len() as u64).to_be_bytes());
        let input_schema = self.input_schema.source().to_string();
        update_plan_fingerprint_component(&mut hasher, input_schema.as_bytes());
        for output_contract in &self.output_contracts {
            update_plan_fingerprint_component(&mut hasher, output_contract.step_id.as_bytes());
            let output_schema = output_contract.schema.source().to_string();
            update_plan_fingerprint_component(&mut hasher, output_schema.as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Checks this contract against a trusted plan and a completed dataflow
    /// prefix without approving execution or issuing a lease.
    pub fn validate_for(
        &self,
        plan: &WorkflowPlan,
        data: &WorkflowData,
        completed_step_count: usize,
    ) -> Result<(), WorkflowDataContractError> {
        self.validate_plan_binding(plan)?;
        data.validate_for_completed_prefix(plan, completed_step_count)
            .map_err(WorkflowDataContractError::Data)?;
        self.input_schema
            .validate(data.input())
            .map_err(WorkflowDataContractError::Input)?;

        for (step, output_contract) in plan
            .steps
            .iter()
            .zip(&self.output_contracts)
            .take(completed_step_count)
        {
            let Some(output) = data.output(&step.id) else {
                return Err(WorkflowDataContractError::Data(
                    WorkflowDataError::OutputPrefixMismatch,
                ));
            };
            output_contract
                .schema
                .validate(output)
                .map_err(|violation| WorkflowDataContractError::Output {
                    step_id: step.id.clone(),
                    violation,
                })?;
        }
        Ok(())
    }

    fn validate_plan_binding(&self, plan: &WorkflowPlan) -> Result<(), WorkflowDataContractError> {
        if self.output_contracts.len() != plan.steps.len() {
            return Err(WorkflowDataContractError::OutputContractCount {
                expected: plan.steps.len(),
                actual: self.output_contracts.len(),
            });
        }
        for (step, output_contract) in plan.steps.iter().zip(&self.output_contracts) {
            if step.id != output_contract.step_id {
                return Err(WorkflowDataContractError::OutputContractStepMismatch {
                    expected: step.id.clone(),
                    actual: output_contract.step_id.clone(),
                });
            }
        }
        Ok(())
    }

    fn validate_step_output(
        &self,
        step: &WorkflowStep,
        step_index: usize,
        output: &JsonValue,
    ) -> Result<(), WorkflowDataContractError> {
        let Some(output_contract) = self.output_contracts.get(step_index) else {
            return Err(WorkflowDataContractError::OutputContractCount {
                expected: step_index.saturating_add(1),
                actual: self.output_contracts.len(),
            });
        };
        if output_contract.step_id != step.id {
            return Err(WorkflowDataContractError::OutputContractStepMismatch {
                expected: step.id.clone(),
                actual: output_contract.step_id.clone(),
            });
        }
        output_contract
            .schema
            .validate(output)
            .map_err(|violation| WorkflowDataContractError::Output {
                step_id: step.id.clone(),
                violation,
            })
    }
}

/// One host-selected JSON output schema bound to a trusted workflow step.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkflowStepOutputContract {
    step_id: String,
    schema: JsonSchema,
}

impl WorkflowStepOutputContract {
    pub fn new(step_id: impl Into<String>, schema: JsonSchema) -> Self {
        Self {
            step_id: step_id.into(),
            schema,
        }
    }

    /// Returns the trusted step ID this schema must bind at approval time.
    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    /// Returns the compiled schema applied to this step's final JSON value.
    pub fn schema(&self) -> &JsonSchema {
        &self.schema
    }
}

/// Rejection while binding or applying a host-owned workflow-data contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowDataContractError {
    TooLarge {
        actual: usize,
        maximum: usize,
    },
    OutputContractCount {
        expected: usize,
        actual: usize,
    },
    OutputContractStepMismatch {
        expected: String,
        actual: String,
    },
    Data(WorkflowDataError),
    Input(SchemaViolation),
    Output {
        step_id: String,
        violation: SchemaViolation,
    },
}

impl Display for WorkflowDataContractError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { actual, maximum } => write!(
                formatter,
                "workflow data contract is {actual} bytes but may retain at most {maximum} bytes"
            ),
            Self::OutputContractCount { expected, actual } => write!(
                formatter,
                "workflow data contract requires {expected} output schemas but received {actual}"
            ),
            Self::OutputContractStepMismatch { expected, actual } => write!(
                formatter,
                "workflow output schema step {} does not match expected step {}",
                workflow_error_text(actual),
                workflow_error_text(expected)
            ),
            Self::Data(error) => write!(
                formatter,
                "workflow data does not satisfy contract binding: {error}"
            ),
            Self::Input(violation) => write!(
                formatter,
                "workflow input does not satisfy its contract at {}: {}",
                workflow_error_text(&violation.path),
                workflow_error_text(&violation.message)
            ),
            Self::Output { step_id, violation } => write!(
                formatter,
                "workflow output for step {} does not satisfy its contract at {}: {}",
                workflow_error_text(step_id),
                workflow_error_text(&violation.path),
                workflow_error_text(&violation.message)
            ),
        }
    }
}

impl std::error::Error for WorkflowDataContractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Data(error) => Some(error),
            Self::Input(error)
            | Self::Output {
                violation: error, ..
            } => Some(error),
            _ => None,
        }
    }
}

fn workflow_data_contract_bytes(
    input_schema: &JsonSchema,
    output_contracts: &[WorkflowStepOutputContract],
) -> usize {
    let mut bytes = input_schema.source().to_string().len();
    for output_contract in output_contracts {
        bytes = bytes.saturating_add(output_contract.step_id.len());
        bytes = bytes.saturating_add(output_contract.schema.source().to_string().len());
    }
    bytes
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

    /// Reviews every step with the default canonical Splash limits.
    ///
    /// This is an effect-free operator or LLM-review aid. It never evaluates
    /// a step, constructs a capability host, issues a lease, or approves the
    /// plan. Direct tool-call hints are deliberately incomplete and must not
    /// be turned into authority without explicit host policy.
    pub fn review(&self) -> Result<Vec<WorkflowStepReview>, WorkflowError> {
        self.review_with_limits(ExecutionLimits::default())
    }

    /// Reviews every step with host-selected canonical syntax limits.
    ///
    /// An invalid step has its structured syntax report and no tool hints, so
    /// an empty hint list never means that an invalid step is pure. Valid
    /// hints recognize only direct `mod.tool` spellings and remain
    /// non-authoritative.
    pub fn review_with_limits(
        &self,
        limits: ExecutionLimits,
    ) -> Result<Vec<WorkflowStepReview>, WorkflowError> {
        review_workflow_steps(&self.steps, limits)
    }
}

/// Effect-free syntax and direct-call review data for one workflow step.
///
/// This is not an approval, a capability grant, or a proof that a dynamic
/// name cannot reach another tool. The host must review the result and issue
/// the relevant step capability lease explicitly. `tool_calls` is bounded;
/// `tool_calls_truncated` records whether one or more direct sites were
/// omitted from this step's review output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowStepReview {
    pub step_id: String,
    pub syntax: SyntaxReport,
    pub tool_calls: Vec<ToolCallHint>,
    pub tool_calls_truncated: bool,
}

/// Durable, data-only record of a completed workflow-step prefix.
///
/// A checkpoint never includes an approval, capability grant, tool result,
/// runtime state, raw dataflow value, or opaque external operation ID. A
/// dataflow checkpoint carries only a digest binding separately retained
/// workflow data to the completed prefix. Loading one does not grant
/// permission to execute anything: resuming always requires a fresh,
/// checkpoint-bound [`Approval`] from the current host engine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCheckpoint {
    format_version: u8,
    plan_fingerprint: String,
    completed_step_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data_contract_fingerprint: Option<String>,
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

    /// Returns the optional digest binding this checkpoint to separately
    /// retained dataflow context. It never exposes that raw context.
    pub fn data_fingerprint(&self) -> Option<&str> {
        self.data_fingerprint.as_deref()
    }

    /// Returns the optional digest binding a dataflow checkpoint to its
    /// host-owned schema contract. It never exposes schema source.
    pub fn data_contract_fingerprint(&self) -> Option<&str> {
        self.data_contract_fingerprint.as_deref()
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
            data_fingerprint: None,
            data_contract_fingerprint: None,
        };
        checkpoint.validate_syntax()?;
        Ok(checkpoint)
    }

    fn for_dataflow(
        plan: &WorkflowPlan,
        data: &WorkflowData,
        completed_step_count: usize,
    ) -> Result<Self, WorkflowCheckpointError> {
        data.validate_for_completed_prefix(plan, completed_step_count)
            .map_err(WorkflowCheckpointError::Dataflow)?;
        let checkpoint = Self {
            format_version: WORKFLOW_CHECKPOINT_FORMAT_VERSION,
            plan_fingerprint: plan.fingerprint.clone(),
            completed_step_ids: plan.steps[..completed_step_count]
                .iter()
                .map(|step| step.id.clone())
                .collect(),
            data_fingerprint: Some(
                data.fingerprint()
                    .map_err(WorkflowCheckpointError::Dataflow)?,
            ),
            data_contract_fingerprint: data.contract_fingerprint.clone(),
        };
        checkpoint.validate_syntax()?;
        Ok(checkpoint)
    }

    fn for_dataflow_with_contract(
        plan: &WorkflowPlan,
        data: &WorkflowData,
        data_contract: &WorkflowDataContract,
        completed_step_count: usize,
    ) -> Result<Self, WorkflowCheckpointError> {
        data_contract
            .validate_for(plan, data, completed_step_count)
            .map_err(WorkflowCheckpointError::DataflowContract)?;
        let mut checkpoint = Self::for_dataflow(plan, data, completed_step_count)?;
        checkpoint.data_contract_fingerprint = Some(data_contract.fingerprint());
        checkpoint.validate_syntax()?;
        Ok(checkpoint)
    }

    fn validate_for(&self, plan: &WorkflowPlan) -> Result<(), WorkflowCheckpointError> {
        self.validate_plan_binding(plan)?;
        if self.data_fingerprint.is_some() {
            return Err(WorkflowCheckpointError::DataflowContextRequired);
        }
        Ok(())
    }

    fn validate_dataflow_for(
        &self,
        plan: &WorkflowPlan,
        data: &WorkflowData,
    ) -> Result<(), WorkflowCheckpointError> {
        self.validate_plan_binding(plan)?;
        let Some(expected_fingerprint) = &self.data_fingerprint else {
            return Err(WorkflowCheckpointError::DataflowContextRequired);
        };
        if self.data_contract_fingerprint.is_some() {
            return Err(WorkflowCheckpointError::DataflowContractRequired);
        }
        data.validate_for_completed_prefix(plan, self.completed_step_ids.len())
            .map_err(WorkflowCheckpointError::Dataflow)?;
        let actual_fingerprint = data
            .fingerprint()
            .map_err(WorkflowCheckpointError::Dataflow)?;
        if &actual_fingerprint != expected_fingerprint {
            return Err(WorkflowCheckpointError::DataflowContextMismatch);
        }
        Ok(())
    }

    fn validate_dataflow_contract_for(
        &self,
        plan: &WorkflowPlan,
        data: &WorkflowData,
        data_contract: &WorkflowDataContract,
    ) -> Result<(), WorkflowCheckpointError> {
        self.validate_plan_binding(plan)?;
        let Some(expected_data_fingerprint) = &self.data_fingerprint else {
            return Err(WorkflowCheckpointError::DataflowContextRequired);
        };
        let Some(expected_contract_fingerprint) = &self.data_contract_fingerprint else {
            return Err(WorkflowCheckpointError::DataflowContractMissing);
        };
        data.validate_for_completed_prefix(plan, self.completed_step_ids.len())
            .map_err(WorkflowCheckpointError::Dataflow)?;
        let actual_data_fingerprint = data
            .fingerprint()
            .map_err(WorkflowCheckpointError::Dataflow)?;
        if &actual_data_fingerprint != expected_data_fingerprint {
            return Err(WorkflowCheckpointError::DataflowContextMismatch);
        }
        if data_contract.fingerprint() != *expected_contract_fingerprint {
            return Err(WorkflowCheckpointError::DataflowContractMismatch);
        }
        if data
            .contract_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| fingerprint != expected_contract_fingerprint)
        {
            return Err(WorkflowCheckpointError::DataflowContractMismatch);
        }
        Ok(())
    }

    fn validate_plan_binding(&self, plan: &WorkflowPlan) -> Result<(), WorkflowCheckpointError> {
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
        if self
            .data_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| !is_plan_fingerprint(fingerprint))
        {
            return Err(WorkflowCheckpointError::InvalidDataFingerprint);
        }
        if self
            .data_contract_fingerprint
            .as_deref()
            .is_some_and(|fingerprint| !is_plan_fingerprint(fingerprint))
        {
            return Err(WorkflowCheckpointError::InvalidDataContractFingerprint);
        }
        if self.data_contract_fingerprint.is_some() && self.data_fingerprint.is_none() {
            return Err(WorkflowCheckpointError::DataflowContractWithoutContext);
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
        if let Some(fingerprint) = &self.data_fingerprint {
            bytes = bytes.checked_add(fingerprint.len().checked_add(32)?)?;
        }
        if let Some(fingerprint) = &self.data_contract_fingerprint {
            bytes = bytes.checked_add(fingerprint.len().checked_add(40)?)?;
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
    InvalidDataFingerprint,
    InvalidDataContractFingerprint,
    TooManyCompletedSteps,
    InvalidStepId(String),
    DuplicateStepId(String),
    CompletedStepCountOutOfRange { completed: usize, total: usize },
    PlanMismatch,
    StepPrefixMismatch,
    DataflowContextRequired,
    DataflowContextMismatch,
    DataflowContractRequired,
    DataflowContractMissing,
    DataflowContractMismatch,
    DataflowContractWithoutContext,
    Dataflow(WorkflowDataError),
    DataflowContract(WorkflowDataContractError),
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
            Self::InvalidDataFingerprint => {
                formatter.write_str("workflow checkpoint has an invalid dataflow fingerprint")
            }
            Self::InvalidDataContractFingerprint => formatter
                .write_str("workflow checkpoint has an invalid dataflow contract fingerprint"),
            Self::TooManyCompletedSteps => {
                formatter.write_str("workflow checkpoint has too many completed steps")
            }
            Self::InvalidStepId(step_id) => {
                write!(
                    formatter,
                    "invalid completed workflow step id: {}",
                    workflow_error_text(step_id)
                )
            }
            Self::DuplicateStepId(step_id) => {
                write!(
                    formatter,
                    "duplicate completed workflow step id: {}",
                    workflow_error_text(step_id)
                )
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
            Self::DataflowContextRequired => {
                formatter.write_str("workflow checkpoint requires a matching dataflow context")
            }
            Self::DataflowContextMismatch => {
                formatter.write_str("workflow dataflow context does not match the checkpoint")
            }
            Self::DataflowContractRequired => formatter.write_str(
                "workflow checkpoint requires its matching dataflow contract for resume",
            ),
            Self::DataflowContractMissing => {
                formatter.write_str("workflow checkpoint does not bind a dataflow contract")
            }
            Self::DataflowContractMismatch => {
                formatter.write_str("workflow dataflow contract does not match the checkpoint")
            }
            Self::DataflowContractWithoutContext => formatter.write_str(
                "workflow checkpoint cannot bind a dataflow contract without dataflow context",
            ),
            Self::Dataflow(error) => write!(formatter, "workflow checkpoint data error: {error}"),
            Self::DataflowContract(error) => {
                write!(
                    formatter,
                    "workflow checkpoint data contract error: {error}"
                )
            }
        }
    }
}

impl std::error::Error for WorkflowCheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Dataflow(error) => Some(error),
            Self::DataflowContract(error) => Some(error),
            _ => None,
        }
    }
}

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

/// Host-selected worker policy binding for one compensation intent.
///
/// The policy is derived from the exact active worker grant. A changed grant,
/// tenant, or tool cannot silently reuse a durable compensation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowCompensationPolicy {
    tool: String,
    tenant_scope: String,
    grant_fingerprint: String,
}

impl WorkflowCompensationPolicy {
    pub fn new(
        tenant_scope: impl Into<String>,
        grant: &CapabilityGrant,
    ) -> Result<Self, WorkflowOperationLedgerError> {
        let tenant_scope = tenant_scope.into();
        if !is_valid_operation_token(&tenant_scope) {
            return Err(WorkflowOperationLedgerError::InvalidCompensationTenantScope(tenant_scope));
        }
        grant
            .validate()
            .map_err(WorkflowOperationLedgerError::Protocol)?;
        if grant.max_compensations == 0 {
            return Err(WorkflowOperationLedgerError::CompensationNotGranted(
                grant.tool.clone(),
            ));
        }
        let grant_fingerprint = grant
            .compensation_fingerprint()
            .map_err(WorkflowOperationLedgerError::Protocol)?;
        Ok(Self {
            tool: grant.tool.clone(),
            tenant_scope,
            grant_fingerprint,
        })
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }

    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }

    pub fn grant_fingerprint(&self) -> &str {
        &self.grant_fingerprint
    }

    fn matches_grant(&self, grant: &CapabilityGrant) -> Result<bool, WorkflowOperationLedgerError> {
        Ok(grant.tool == self.tool
            && grant.max_compensations > 0
            && grant
                .compensation_fingerprint()
                .map_err(WorkflowOperationLedgerError::Protocol)?
                == self.grant_fingerprint)
    }

    fn validate_syntax(&self) -> Result<(), WorkflowOperationLedgerError> {
        if !is_valid_operation_token(&self.tool) {
            return Err(WorkflowOperationLedgerError::InvalidTool(self.tool.clone()));
        }
        if !is_valid_operation_token(&self.tenant_scope) {
            return Err(
                WorkflowOperationLedgerError::InvalidCompensationTenantScope(
                    self.tenant_scope.clone(),
                ),
            );
        }
        if !is_plan_fingerprint(&self.grant_fingerprint) {
            return Err(WorkflowOperationLedgerError::InvalidCompensationGrantFingerprint);
        }
        Ok(())
    }
}

/// Trusted host policy hook used to reauthorize a compensation grant when the
/// host approves and when it seals an execution frame.
///
/// Implementations should consult current tenant policy, revocation state, and
/// any platform-specific grant lease. A stored grant fingerprint establishes
/// durable identity; it is not a revocation mechanism by itself.
pub trait CompensationGrantVerifier {
    fn verify_compensation_grant(
        &self,
        tenant_scope: &str,
        grant: &CapabilityGrant,
    ) -> Result<(), WorkflowOperationLedgerError>;
}

/// The operation, policy, and current grant that a host is considering for
/// compensation.
///
/// The engine validates the complete binding before it issues an approval or
/// creates a worker frame. Keeping these values together prevents a caller
/// from accidentally pairing an operation with another tool's grant.
#[derive(Clone, Copy)]
pub struct WorkflowCompensationTarget<'a> {
    operation_key: &'a str,
    policy: &'a WorkflowCompensationPolicy,
    grant: &'a CapabilityGrant,
    verifier: &'a dyn CompensationGrantVerifier,
}

impl fmt::Debug for WorkflowCompensationTarget<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowCompensationTarget")
            .field("operation_key", &self.operation_key)
            .field("policy", &self.policy)
            .field("grant", &self.grant)
            .field("verifier", &"[trusted host policy]")
            .finish()
    }
}

impl<'a> WorkflowCompensationTarget<'a> {
    pub fn new(
        operation_key: &'a str,
        policy: &'a WorkflowCompensationPolicy,
        grant: &'a CapabilityGrant,
        verifier: &'a dyn CompensationGrantVerifier,
    ) -> Self {
        Self {
            operation_key,
            policy,
            grant,
            verifier,
        }
    }

    pub fn operation_key(self) -> &'a str {
        self.operation_key
    }

    pub fn policy(self) -> &'a WorkflowCompensationPolicy {
        self.policy
    }

    pub fn grant(self) -> &'a CapabilityGrant {
        self.grant
    }

    fn verify_current(self) -> Result<(), WorkflowOperationLedgerError> {
        self.policy.validate_syntax()?;
        if !self.policy.matches_grant(self.grant)? {
            return Err(WorkflowOperationLedgerError::CompensationPolicyMismatch(
                self.operation_key.to_owned(),
            ));
        }
        self.verifier
            .verify_compensation_grant(self.policy.tenant_scope(), self.grant)
    }
}

/// Data that becomes one authenticated compensation request.
///
/// Construction does not grant authority. `WorkflowEngine` validates the
/// payload, request ID, and durable input fingerprint before sealing a frame.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkflowCompensationDispatch {
    request_id: String,
    payload: ToolPayload,
}

impl WorkflowCompensationDispatch {
    pub fn new(request_id: impl Into<String>, payload: ToolPayload) -> Self {
        Self {
            request_id: request_id.into(),
            payload,
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn payload(&self) -> &ToolPayload {
        &self.payload
    }
}

/// Bounded durable intent for the inverse of one succeeded operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCompensation {
    compensation_key: String,
    input_fingerprint: String,
    tenant_scope: String,
    grant_fingerprint: String,
    state: WorkflowOperationState,
}

impl WorkflowCompensation {
    pub fn compensation_key(&self) -> &str {
        &self.compensation_key
    }

    pub fn input_fingerprint(&self) -> &str {
        &self.input_fingerprint
    }

    pub fn tenant_scope(&self) -> &str {
        &self.tenant_scope
    }

    pub fn grant_fingerprint(&self) -> &str {
        &self.grant_fingerprint
    }

    pub fn state(&self) -> WorkflowOperationState {
        self.state
    }

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
            return Err(
                WorkflowOperationLedgerError::CompensationInputFingerprintMismatch(
                    self.compensation_key.clone(),
                ),
            );
        }
        Ok(())
    }

    fn matches_policy(&self, policy: &WorkflowCompensationPolicy) -> bool {
        self.tenant_scope == policy.tenant_scope
            && self.grant_fingerprint == policy.grant_fingerprint
    }

    fn validate_syntax(&self) -> Result<(), WorkflowOperationLedgerError> {
        if !is_valid_compensation_key(&self.compensation_key) {
            return Err(WorkflowOperationLedgerError::InvalidCompensationKey(
                self.compensation_key.clone(),
            ));
        }
        if !is_plan_fingerprint(&self.input_fingerprint) {
            return Err(WorkflowOperationLedgerError::InvalidInputFingerprint);
        }
        if !is_valid_operation_token(&self.tenant_scope) {
            return Err(
                WorkflowOperationLedgerError::InvalidCompensationTenantScope(
                    self.tenant_scope.clone(),
                ),
            );
        }
        if !is_plan_fingerprint(&self.grant_fingerprint) {
            return Err(WorkflowOperationLedgerError::InvalidCompensationGrantFingerprint);
        }
        Ok(())
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
    #[serde(default)]
    compensation: Option<WorkflowCompensation>,
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

    pub fn compensation(&self) -> Option<&WorkflowCompensation> {
        self.compensation.as_ref()
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
        if let Some(compensation) = &self.compensation {
            if self.state != WorkflowOperationState::Succeeded {
                return Err(
                    WorkflowOperationLedgerError::CompensationRequiresSucceededOperation {
                        operation_key: self.operation_key.clone(),
                        state: self.state,
                    },
                );
            }
            compensation.validate_syntax()?;
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

/// A keyed worker frame for a host-approved compensation request.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedWorkflowOperationCompensation {
    pub request: OperationCompensationRequest,
    pub frame: AuthenticatedWorkerMessage,
}

/// A queued external workflow operation whose durable ledger identity has been
/// recorded but which has not yet been claimed for dispatch.
///
/// This value is process-local and intentionally non-serializable. Persist
/// the updated [`WorkflowOperationLedger`] before passing it to
/// [`WorkflowEngine::claim_prepared_external_operation`]. The payload remains
/// available only to the trusted host that is about to construct a worker
/// dispatch request.
pub struct PreparedWorkflowExternalOperation {
    engine_id: u64,
    plan_id: u64,
    external_tool_id: ExternalToolId,
    step_id: String,
    completed_steps: usize,
    operation_key: String,
    payload: ToolPayload,
    canonical_input: Vec<u8>,
}

impl fmt::Debug for PreparedWorkflowExternalOperation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedWorkflowExternalOperation")
            .field("engine_id", &self.engine_id)
            .field("plan_id", &self.plan_id)
            .field("external_tool_id", &self.external_tool_id)
            .field("step_id", &self.step_id)
            .field("completed_steps", &self.completed_steps)
            .field("operation_key", &self.operation_key)
            .field("payload", &"[redacted]")
            .field("canonical_input", &"[redacted]")
            .finish()
    }
}

impl PreparedWorkflowExternalOperation {
    /// Returns the trusted plan step currently waiting for this operation.
    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    /// Returns the completed workflow prefix before the waiting step.
    pub fn completed_steps(&self) -> usize {
        self.completed_steps
    }

    /// Returns the non-authorizing durable worker-operation key.
    pub fn operation_key(&self) -> &str {
        &self.operation_key
    }

    /// Returns the exact text or JSON envelope to send to the worker.
    pub fn payload(&self) -> &ToolPayload {
        &self.payload
    }
}

/// A durable external workflow operation that was claimed after its ledger
/// record was prepared and persisted by the host.
///
/// The opaque runtime ID stays process-local. A restart must rebuild the plan,
/// restore and validate the ledger, and reconcile the durable operation before
/// it decides whether to rerun a workflow step.
pub struct ClaimedWorkflowExternalOperation {
    engine_id: u64,
    plan_id: u64,
    step_id: String,
    completed_steps: usize,
    operation_key: String,
    payload: ToolPayload,
    canonical_input: Vec<u8>,
    invocation: ExternalToolInvocation,
}

impl fmt::Debug for ClaimedWorkflowExternalOperation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedWorkflowExternalOperation")
            .field("engine_id", &self.engine_id)
            .field("plan_id", &self.plan_id)
            .field("step_id", &self.step_id)
            .field("completed_steps", &self.completed_steps)
            .field("operation_key", &self.operation_key)
            .field("payload", &"[redacted]")
            .field("canonical_input", &"[redacted]")
            .field("invocation", &"[redacted]")
            .finish()
    }
}

impl ClaimedWorkflowExternalOperation {
    /// Returns the trusted plan step currently waiting for this operation.
    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    /// Returns the completed workflow prefix before the waiting step.
    pub fn completed_steps(&self) -> usize {
        self.completed_steps
    }

    /// Returns the non-authorizing durable worker-operation key.
    pub fn operation_key(&self) -> &str {
        &self.operation_key
    }

    /// Returns the exact text or JSON envelope to send to the worker.
    pub fn payload(&self) -> &ToolPayload {
        &self.payload
    }

    /// Returns the claimed runtime invocation for host dispatch and completion.
    pub fn invocation(&self) -> &ExternalToolInvocation {
        &self.invocation
    }
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
            compensation: None,
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

    /// Records one host-approved compensation intent for a succeeded operation.
    ///
    /// The compensation key is deliberately separate from the original
    /// operation key and can be recorded only once per original operation.
    /// Persist this mutation through authenticated compare-and-swap storage
    /// before a host issues a compensation approval or sends a worker frame.
    pub fn record_compensation(
        &mut self,
        operation_key: &str,
        policy: &WorkflowCompensationPolicy,
        compensation_key: impl Into<String>,
        input: &[u8],
    ) -> Result<(), WorkflowOperationLedgerError> {
        self.validate_syntax()?;
        policy.validate_syntax()?;
        if input.len() > MAX_WORKFLOW_OPERATION_INPUT_BYTES {
            return Err(WorkflowOperationLedgerError::InputTooLarge {
                actual: input.len(),
                maximum: MAX_WORKFLOW_OPERATION_INPUT_BYTES,
            });
        }
        let operation_index = self
            .operations
            .iter()
            .position(|operation| operation.operation_key == operation_key)
            .ok_or_else(|| {
                WorkflowOperationLedgerError::UnknownOperation(operation_key.to_owned())
            })?;
        let operation = &self.operations[operation_index];
        if operation.state != WorkflowOperationState::Succeeded {
            return Err(
                WorkflowOperationLedgerError::CompensationRequiresSucceededOperation {
                    operation_key: operation.operation_key.clone(),
                    state: operation.state,
                },
            );
        }
        if operation.tool != policy.tool {
            return Err(WorkflowOperationLedgerError::CompensationPolicyMismatch(
                operation.operation_key.clone(),
            ));
        }
        if operation.compensation.is_some() {
            return Err(WorkflowOperationLedgerError::CompensationAlreadyRecorded(
                operation.operation_key.clone(),
            ));
        }
        let compensation_key = compensation_key.into();
        if !is_valid_compensation_key(&compensation_key) {
            return Err(WorkflowOperationLedgerError::InvalidCompensationKey(
                compensation_key,
            ));
        }
        let next_revision = self.next_revision()?;
        self.operations[operation_index].compensation = Some(WorkflowCompensation {
            compensation_key,
            input_fingerprint: workflow_operation_input_fingerprint(input),
            tenant_scope: policy.tenant_scope.clone(),
            grant_fingerprint: policy.grant_fingerprint.clone(),
            state: WorkflowOperationState::Pending,
        });
        self.revision = next_revision;
        Ok(())
    }

    /// Applies a worker compensation observation after transport authentication.
    ///
    /// The ledger retains only the compensation state, never terminal output or
    /// error text. A terminal observation does not authorize workflow resume.
    pub fn apply_verified_compensation(
        &mut self,
        request: &OperationCompensationRequest,
        result: &OperationCompensationResult,
    ) -> Result<WorkflowOperationState, WorkflowOperationLedgerError> {
        self.validate_syntax()?;
        request
            .validate()
            .map_err(WorkflowOperationLedgerError::Protocol)?;
        result
            .validate()
            .map_err(WorkflowOperationLedgerError::Protocol)?;
        if !result.matches_request(request) {
            return Err(WorkflowOperationLedgerError::CompensationRequestMismatch);
        }
        let operation_index = self
            .operations
            .iter()
            .position(|operation| operation.operation_key == request.operation_key)
            .ok_or_else(|| {
                WorkflowOperationLedgerError::UnknownOperation(request.operation_key.clone())
            })?;
        let operation = &self.operations[operation_index];
        if operation.tool != request.tool {
            return Err(WorkflowOperationLedgerError::CompensationRequestMismatch);
        }
        let compensation = operation.compensation.as_ref().ok_or_else(|| {
            WorkflowOperationLedgerError::UnknownCompensation(request.operation_key.clone())
        })?;
        let input = request
            .canonical_input_bytes()
            .map_err(WorkflowOperationLedgerError::Protocol)?;
        compensation.verify_input(&input)?;
        if compensation.compensation_key != request.compensation_key
            || compensation.tenant_scope != request.tenant_scope
            || compensation.grant_fingerprint != request.grant_fingerprint
        {
            return Err(WorkflowOperationLedgerError::CompensationRequestMismatch);
        }
        let observed = match &result.status {
            OperationStatus::Running => WorkflowOperationState::Running,
            OperationStatus::Succeeded { .. } => WorkflowOperationState::Succeeded,
            OperationStatus::Failed { .. } => WorkflowOperationState::Failed,
            OperationStatus::Cancelled => WorkflowOperationState::Cancelled,
        };
        if !compensation.state.accepts(observed) {
            return Err(
                WorkflowOperationLedgerError::InvalidCompensationStateTransition {
                    compensation_key: compensation.compensation_key.clone(),
                    current: compensation.state,
                    observed,
                },
            );
        }
        if compensation.state != observed {
            let next_revision = self.next_revision()?;
            let persisted_compensation = self.operations[operation_index]
                .compensation
                .as_mut()
                .ok_or_else(|| {
                    WorkflowOperationLedgerError::UnknownCompensation(request.operation_key.clone())
                })?;
            persisted_compensation.state = observed;
            self.revision = next_revision;
        }
        Ok(observed)
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
            if let Some(compensation) = &operation.compensation {
                bytes = bytes.checked_add(320)?;
                bytes = bytes.checked_add(compensation.compensation_key.len())?;
                bytes = bytes.checked_add(compensation.input_fingerprint.len())?;
                bytes = bytes.checked_add(compensation.tenant_scope.len())?;
                bytes = bytes.checked_add(compensation.grant_fingerprint.len())?;
            }
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
    OperationBindingMismatch(String),
    InvalidCompensationKey(String),
    InvalidCompensationTenantScope(String),
    InvalidCompensationGrantFingerprint,
    CompensationGrantDenied {
        tool: String,
        tenant_scope: String,
    },
    CompensationNotGranted(String),
    CompensationInputFingerprintMismatch(String),
    CompensationAlreadyRecorded(String),
    CompensationRequiresSucceededOperation {
        operation_key: String,
        state: WorkflowOperationState,
    },
    CompensationPolicyMismatch(String),
    UnknownCompensation(String),
    CompensationRequestMismatch,
    CompensationDispatchRequiresHostAuthenticator,
    UnexpectedCompensationMessage,
    InvalidCompensationStateTransition {
        compensation_key: String,
        current: WorkflowOperationState,
        observed: WorkflowOperationState,
    },
    DuplicateOperationKey(String),
    PlanMismatch,
    UnknownStep(String),
    UnknownOperation(String),
    ReconciliationMismatch,
    ReconciliationRequiresHostAuthenticator,
    OperationDispatchRequiresHostAuthenticator,
    UnexpectedOperationDispatchMessage,
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
                write!(
                    formatter,
                    "invalid workflow operation step id: {}",
                    workflow_error_text(step_id)
                )
            }
            Self::InvalidTool(tool) => write!(
                formatter,
                "invalid workflow operation tool: {}",
                workflow_error_text(tool)
            ),
            Self::InvalidOperationKey(key) => {
                write!(
                    formatter,
                    "invalid workflow operation key: {}",
                    workflow_error_text(key)
                )
            }
            Self::InvalidInputFingerprint => {
                formatter.write_str("workflow operation has an invalid input fingerprint")
            }
            Self::InputFingerprintMismatch(key) => {
                write!(
                    formatter,
                    "workflow operation input does not match record: {}",
                    workflow_error_text(key)
                )
            }
            Self::OperationBindingMismatch(key) => {
                write!(
                    formatter,
                    "workflow operation binding does not match record: {}",
                    workflow_error_text(key)
                )
            }
            Self::InvalidCompensationKey(key) => {
                write!(
                    formatter,
                    "invalid workflow compensation key: {}",
                    workflow_error_text(key)
                )
            }
            Self::InvalidCompensationTenantScope(scope) => {
                write!(
                    formatter,
                    "invalid workflow compensation tenant scope: {}",
                    workflow_error_text(scope)
                )
            }
            Self::InvalidCompensationGrantFingerprint => {
                formatter.write_str("workflow compensation has an invalid grant fingerprint")
            }
            Self::CompensationGrantDenied { tool, tenant_scope } => write!(
                formatter,
                "current host policy denied compensation grant {} for tenant {}",
                workflow_error_text(tool),
                workflow_error_text(tenant_scope)
            ),
            Self::CompensationNotGranted(tool) => {
                write!(
                    formatter,
                    "workflow tool has no compensation grant: {}",
                    workflow_error_text(tool)
                )
            }
            Self::CompensationInputFingerprintMismatch(key) => {
                write!(
                    formatter,
                    "workflow compensation input does not match record: {}",
                    workflow_error_text(key)
                )
            }
            Self::CompensationAlreadyRecorded(key) => {
                write!(
                    formatter,
                    "workflow compensation is already recorded: {}",
                    workflow_error_text(key)
                )
            }
            Self::CompensationRequiresSucceededOperation {
                operation_key,
                state,
            } => write!(
                formatter,
                "workflow compensation requires succeeded operation {}; observed {state:?}",
                workflow_error_text(operation_key)
            ),
            Self::CompensationPolicyMismatch(key) => {
                write!(
                    formatter,
                    "workflow compensation policy does not match record: {}",
                    workflow_error_text(key)
                )
            }
            Self::UnknownCompensation(key) => {
                write!(
                    formatter,
                    "unknown workflow compensation: {}",
                    workflow_error_text(key)
                )
            }
            Self::CompensationRequestMismatch => {
                formatter.write_str("worker compensation does not match the durable record")
            }
            Self::CompensationDispatchRequiresHostAuthenticator => {
                formatter.write_str("durable compensation dispatch requires a host session authenticator")
            }
            Self::UnexpectedCompensationMessage => {
                formatter.write_str("authenticated worker frame is not a compensation result")
            }
            Self::InvalidCompensationStateTransition {
                compensation_key,
                current,
                observed,
            } => write!(
                formatter,
                "worker observation cannot change compensation {} from {current:?} to {observed:?}",
                workflow_error_text(compensation_key)
            ),
            Self::DuplicateOperationKey(key) => {
                write!(
                    formatter,
                    "duplicate workflow operation key: {}",
                    workflow_error_text(key)
                )
            }
            Self::PlanMismatch => {
                formatter.write_str("workflow operation ledger belongs to another plan")
            }
            Self::UnknownStep(step_id) => {
                write!(
                    formatter,
                    "workflow operation refers to unknown step: {}",
                    workflow_error_text(step_id)
                )
            }
            Self::UnknownOperation(key) => {
                write!(
                    formatter,
                    "unknown workflow operation: {}",
                    workflow_error_text(key)
                )
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
            Self::UnexpectedOperationDispatchMessage => {
                formatter.write_str("authenticated worker frame is not an operation dispatch result")
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

/// Process-local capability authority retained for an approved workflow.
///
/// A shared lease deliberately remains available to every step for the
/// backwards-compatible approval APIs. Per-step authority removes only the
/// current lease from the front of the queue, so a later step's authority is
/// never active while an earlier step is evaluating or suspended.
#[derive(Debug)]
enum WorkflowCapabilityLeases {
    Shared(Option<CapabilityLease>),
    PerStep(VecDeque<CapabilityLease>),
}

impl WorkflowCapabilityLeases {
    fn shared(lease: CapabilityLease) -> Self {
        Self::Shared(Some(lease))
    }

    fn per_step(leases: Vec<CapabilityLease>) -> Self {
        Self::PerStep(leases.into())
    }

    fn validate(&self, runtime: &CapabilityRuntime) -> Result<(), WorkflowError> {
        match self {
            Self::Shared(Some(lease)) => runtime
                .validate_capability_lease(lease)
                .map_err(WorkflowError::CapabilityLease),
            Self::Shared(None) => Err(WorkflowError::ApprovalMismatch),
            Self::PerStep(leases) => {
                for lease in leases {
                    runtime
                        .validate_capability_lease(lease)
                        .map_err(WorkflowError::CapabilityLease)?;
                }
                Ok(())
            }
        }
    }

    fn take_for_step(&mut self) -> Option<CapabilityLease> {
        match self {
            Self::Shared(lease) => lease.take(),
            Self::PerStep(leases) => leases.pop_front(),
        }
    }

    fn complete_step(&mut self, lease: CapabilityLease) -> Result<(), WorkflowError> {
        match self {
            Self::Shared(slot) => {
                if slot.is_some() {
                    return Err(WorkflowError::ApprovalMismatch);
                }
                *slot = Some(lease);
            }
            Self::PerStep(_) => drop(lease),
        }
        Ok(())
    }
}

#[derive(Debug)]
enum ApprovalKind {
    Plan(WorkflowCapabilityLeases),
    Checkpoint {
        checkpoint: WorkflowCheckpoint,
        leases: WorkflowCapabilityLeases,
    },
    Dataflow {
        data: WorkflowData,
        data_contract: Option<WorkflowDataContract>,
        leases: WorkflowCapabilityLeases,
    },
    DataflowCheckpoint {
        checkpoint: WorkflowCheckpoint,
        data: WorkflowData,
        data_contract: Option<WorkflowDataContract>,
        leases: WorkflowCapabilityLeases,
    },
    Compensation(CompensationApproval),
}

#[derive(Debug)]
struct CompensationApproval {
    ledger_revision: u64,
    operation_key: String,
    compensation_key: String,
    input_fingerprint: String,
    tenant_scope: String,
    grant_fingerprint: String,
    session_id: String,
}

/// A bounded, in-process workflow telemetry event.
///
/// Event fields contain only plan IDs, validated identifiers, lifecycle data,
/// and diagnostic counts. The event view intentionally never retains raw
/// source, tool input/output, or diagnostic text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
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
    CompensationRecorded {
        plan_id: u64,
        operation_key: String,
        compensation_key: String,
    },
    CompensationApproved {
        plan_id: u64,
        operation_key: String,
        compensation_key: String,
    },
    CompensationObserved {
        plan_id: u64,
        operation_key: String,
        compensation_key: String,
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
    StepRejected {
        plan_id: u64,
        step_id: String,
        diagnostic_count: usize,
        diagnostics_truncated: bool,
        completed_steps: usize,
    },
    StepFailed {
        plan_id: u64,
        step_id: String,
        diagnostic_count: usize,
        completed_steps: usize,
    },
    Completed {
        plan_id: u64,
    },
}

impl WorkflowEvent {
    fn validate_for_durable_replay(&self) -> Result<(), WorkflowEventValidationError> {
        match self {
            Self::Planned {
                plan_id,
                step_count,
            } => {
                validate_event_plan_id(*plan_id)?;
                if *step_count == 0 || *step_count > MAX_WORKFLOW_STEPS {
                    return Err(WorkflowEventValidationError::InvalidStepCount);
                }
            }
            Self::Approved { plan_id }
            | Self::OperationLedgerCreated { plan_id }
            | Self::Started { plan_id }
            | Self::Completed { plan_id } => validate_event_plan_id(*plan_id)?,
            Self::Checkpointed {
                plan_id,
                completed_steps,
            }
            | Self::ResumeApproved {
                plan_id,
                completed_steps,
            }
            | Self::Resumed {
                plan_id,
                completed_steps,
            } => {
                validate_event_plan_id(*plan_id)?;
                validate_event_completed_steps(*completed_steps)?;
            }
            Self::OperationRecorded {
                plan_id,
                step_id,
                tool,
            }
            | Self::OperationObserved {
                plan_id,
                step_id,
                tool,
                ..
            } => {
                validate_event_plan_id(*plan_id)?;
                if !is_valid_step_id(step_id) {
                    return Err(WorkflowEventValidationError::InvalidStepId);
                }
                if !is_valid_operation_token(tool) {
                    return Err(WorkflowEventValidationError::InvalidTool);
                }
            }
            Self::CompensationRecorded {
                plan_id,
                operation_key,
                compensation_key,
            }
            | Self::CompensationApproved {
                plan_id,
                operation_key,
                compensation_key,
            }
            | Self::CompensationObserved {
                plan_id,
                operation_key,
                compensation_key,
                ..
            } => {
                validate_event_plan_id(*plan_id)?;
                if !is_valid_operation_token(operation_key) {
                    return Err(WorkflowEventValidationError::InvalidOperationKey);
                }
                if !is_valid_compensation_key(compensation_key) {
                    return Err(WorkflowEventValidationError::InvalidCompensationKey);
                }
            }
            Self::StepSucceeded { plan_id, step_id } => {
                validate_event_plan_id(*plan_id)?;
                if !is_valid_step_id(step_id) {
                    return Err(WorkflowEventValidationError::InvalidStepId);
                }
            }
            Self::StepSuspended {
                plan_id,
                step_id,
                completed_steps,
            } => {
                validate_event_plan_id(*plan_id)?;
                if !is_valid_step_id(step_id) {
                    return Err(WorkflowEventValidationError::InvalidStepId);
                }
                validate_event_completed_steps(*completed_steps)?;
            }
            Self::StepRejected {
                plan_id,
                step_id,
                diagnostic_count,
                completed_steps,
                ..
            }
            | Self::StepFailed {
                plan_id,
                step_id,
                diagnostic_count,
                completed_steps,
            } => {
                validate_event_plan_id(*plan_id)?;
                if !is_valid_step_id(step_id) {
                    return Err(WorkflowEventValidationError::InvalidStepId);
                }
                if *diagnostic_count > MAX_SYNTAX_DIAGNOSTICS {
                    return Err(WorkflowEventValidationError::InvalidDiagnosticCount);
                }
                validate_event_completed_steps(*completed_steps)?;
            }
        }
        Ok(())
    }
}

fn validate_event_plan_id(plan_id: u64) -> Result<(), WorkflowEventValidationError> {
    if plan_id == 0 {
        return Err(WorkflowEventValidationError::InvalidPlanId);
    }
    Ok(())
}

fn validate_event_completed_steps(
    completed_steps: usize,
) -> Result<(), WorkflowEventValidationError> {
    if completed_steps > MAX_WORKFLOW_STEPS {
        return Err(WorkflowEventValidationError::InvalidCompletedSteps);
    }
    Ok(())
}

/// Validation failure for a persisted workflow telemetry event.
///
/// The error deliberately identifies only the invalid field category, never a
/// potentially hostile value decoded from storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowEventValidationError {
    InvalidPlanId,
    InvalidStepCount,
    InvalidCompletedSteps,
    InvalidDiagnosticCount,
    InvalidStepId,
    InvalidTool,
    InvalidOperationKey,
    InvalidCompensationKey,
}

impl Display for WorkflowEventValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlanId => formatter.write_str("workflow event has an invalid plan ID"),
            Self::InvalidStepCount => {
                formatter.write_str("workflow event has an invalid planned step count")
            }
            Self::InvalidCompletedSteps => {
                formatter.write_str("workflow event has an invalid completed-step count")
            }
            Self::InvalidDiagnosticCount => {
                formatter.write_str("workflow event has an invalid diagnostic count")
            }
            Self::InvalidStepId => formatter.write_str("workflow event has an invalid step ID"),
            Self::InvalidTool => formatter.write_str("workflow event has an invalid tool ID"),
            Self::InvalidOperationKey => {
                formatter.write_str("workflow event has an invalid operation key")
            }
            Self::InvalidCompensationKey => {
                formatter.write_str("workflow event has an invalid compensation key")
            }
        }
    }
}

impl std::error::Error for WorkflowEventValidationError {}

/// One sequenced event exported from a workflow engine.
///
/// The sequence identifies telemetry ordering only. It is not an approval,
/// fencing token, durable operation key, or effect-recovery decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowEventRecord {
    sequence: u64,
    event: WorkflowEvent,
}

impl WorkflowEventRecord {
    /// Creates a validated sequenced event record.
    pub fn new(sequence: u64, event: WorkflowEvent) -> Result<Self, WorkflowEventBatchError> {
        if sequence == 0 || sequence == u64::MAX {
            return Err(WorkflowEventBatchError::InvalidSequence);
        }
        event
            .validate_for_durable_replay()
            .map_err(WorkflowEventBatchError::InvalidEvent)?;
        Ok(Self { sequence, event })
    }

    /// Returns the source-local sequence number.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the telemetry event.
    pub fn event(&self) -> &WorkflowEvent {
        &self.event
    }
}

/// A contiguous exported range of workflow telemetry events.
///
/// Hosts persist batches under a stable host-selected stream identity. A batch
/// neither carries capability authority nor authorizes replaying a workflow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowEventBatch {
    records: Vec<WorkflowEventRecord>,
    next_sequence: u64,
}

impl WorkflowEventBatch {
    /// Creates a validated contiguous event batch.
    pub fn new(
        records: Vec<WorkflowEventRecord>,
        next_sequence: u64,
    ) -> Result<Self, WorkflowEventBatchError> {
        let batch = Self {
            records,
            next_sequence,
        };
        batch.validate()?;
        Ok(batch)
    }

    /// Returns the ordered records in this batch.
    pub fn records(&self) -> &[WorkflowEventRecord] {
        &self.records
    }

    /// Returns the first source sequence in this batch, or the cursor after
    /// the batch when it is empty.
    pub fn first_sequence(&self) -> u64 {
        match self.records.first() {
            Some(record) => record.sequence,
            None => self.next_sequence,
        }
    }

    /// Returns the source cursor immediately after this batch.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Returns whether the batch contains no telemetry events.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn validate(&self) -> Result<(), WorkflowEventBatchError> {
        if self.next_sequence == 0 {
            return Err(WorkflowEventBatchError::InvalidNextSequence);
        }
        let Some(first) = self.records.first() else {
            return Ok(());
        };
        if first.sequence == 0 || first.sequence == u64::MAX {
            return Err(WorkflowEventBatchError::InvalidSequence);
        }

        let mut expected = first.sequence;
        for record in &self.records {
            if record.sequence != expected || record.sequence == u64::MAX {
                return Err(WorkflowEventBatchError::NonContiguousSequence);
            }
            record
                .event
                .validate_for_durable_replay()
                .map_err(WorkflowEventBatchError::InvalidEvent)?;
            expected = expected
                .checked_add(1)
                .ok_or(WorkflowEventBatchError::InvalidNextSequence)?;
        }
        if expected != self.next_sequence {
            return Err(WorkflowEventBatchError::InvalidNextSequence);
        }
        Ok(())
    }
}

/// Rejection while building or validating a workflow-event export batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowEventBatchError {
    InvalidSequence,
    InvalidNextSequence,
    NonContiguousSequence,
    InvalidEvent(WorkflowEventValidationError),
}

impl Display for WorkflowEventBatchError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSequence => formatter.write_str("workflow event sequence is invalid"),
            Self::InvalidNextSequence => {
                formatter.write_str("workflow event batch has an invalid next sequence")
            }
            Self::NonContiguousSequence => {
                formatter.write_str("workflow event batch sequences are not contiguous")
            }
            Self::InvalidEvent(error) => write!(formatter, "invalid workflow event: {error}"),
        }
    }
}

impl std::error::Error for WorkflowEventBatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEvent(error) => Some(error),
            _ => None,
        }
    }
}

/// Rejection while exporting events after a host-maintained cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowEventCursorError {
    InvalidCursor,
    Evicted {
        requested: u64,
        earliest_available: u64,
    },
    Ahead {
        requested: u64,
        next_available: u64,
    },
}

impl Display for WorkflowEventCursorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCursor => formatter.write_str("workflow event cursor is invalid"),
            Self::Evicted {
                requested,
                earliest_available,
            } => write!(
                formatter,
                "workflow event cursor {requested} was evicted; earliest available is {earliest_available}"
            ),
            Self::Ahead {
                requested,
                next_available,
            } => write!(
                formatter,
                "workflow event cursor {requested} is ahead of the next available sequence {next_available}"
            ),
        }
    }
}

impl std::error::Error for WorkflowEventCursorError {}

/// Ordered, read-only view of the recent in-memory workflow events.
///
/// Entries are ordered oldest to newest but may wrap internally. Use
/// [`Self::as_slices`] when a host needs zero-copy access to both contiguous
/// portions. This is telemetry only: loading, inspecting, or exporting a view
/// cannot create an approval, resume a promise, or execute a workflow.
#[derive(Clone, Copy, Debug)]
pub struct WorkflowEventLog<'a> {
    entries: &'a VecDeque<WorkflowEvent>,
}

impl<'a> WorkflowEventLog<'a> {
    pub fn len(self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(self, index: usize) -> Option<&'a WorkflowEvent> {
        self.entries.get(index)
    }

    pub fn first(self) -> Option<&'a WorkflowEvent> {
        self.entries.front()
    }

    pub fn last(self) -> Option<&'a WorkflowEvent> {
        self.entries.back()
    }

    pub fn iter(self) -> std::collections::vec_deque::Iter<'a, WorkflowEvent> {
        self.entries.iter()
    }

    pub fn as_slices(self) -> (&'a [WorkflowEvent], &'a [WorkflowEvent]) {
        self.entries.as_slices()
    }
}

impl<'a> IntoIterator for WorkflowEventLog<'a> {
    type Item = &'a WorkflowEvent;
    type IntoIter = std::collections::vec_deque::Iter<'a, WorkflowEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl Index<usize> for WorkflowEventLog<'_> {
    type Output = WorkflowEvent;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

/// Rejection returned when a host requests an unsafe workflow event capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowEventHistoryError {
    CapacityTooLarge { requested: usize, maximum: usize },
}

impl Display for WorkflowEventHistoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityTooLarge { requested, maximum } => write!(
                formatter,
                "workflow event capacity {requested} exceeds the hard limit of {maximum}"
            ),
        }
    }
}

impl std::error::Error for WorkflowEventHistoryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowError {
    EmptyPlan,
    TooManySteps {
        maximum: usize,
    },
    PlanSourceTooLarge {
        actual: usize,
        maximum: usize,
    },
    InvalidStepId(String),
    DuplicateStepId(String),
    PlanOwnershipMismatch,
    ApprovalMismatch,
    StepCapabilityLeaseCount {
        expected: usize,
        actual: usize,
    },
    StepCapabilityPolicyCount {
        expected: usize,
        actual: usize,
    },
    StepCapabilityPolicyMismatch {
        expected: String,
        actual: String,
    },
    ExecutionInProgress,
    NoSuspendedExecution,
    CapabilityLease(CapabilityLeaseError),
    ExternalTool(ExternalToolError),
    Checkpoint(WorkflowCheckpointError),
    Data(WorkflowDataError),
    DataContract(WorkflowDataContractError),
    OperationLedger(WorkflowOperationLedgerError),
    Runtime(RuntimeError),
    StepSuspended {
        step_id: String,
        completed_steps: usize,
    },
    StepRejected {
        step_id: String,
        report: SyntaxReport,
        completed_steps: usize,
    },
    StepFailed {
        step_id: String,
        diagnostics: Vec<String>,
        completed_steps: usize,
    },
    DataflowOutput {
        step_id: String,
        error: WorkflowDataError,
        completed_steps: usize,
    },
    DataflowContractOutput {
        step_id: String,
        error: WorkflowDataContractError,
        completed_steps: usize,
    },
}

impl Display for WorkflowError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPlan => formatter.write_str("workflow must have at least one step"),
            Self::TooManySteps { maximum } => {
                write!(formatter, "workflow exceeds the maximum of {maximum} steps")
            }
            Self::PlanSourceTooLarge { actual, maximum } => write!(
                formatter,
                "workflow source is {actual} bytes but may retain at most {maximum} bytes"
            ),
            Self::InvalidStepId(id) => write!(
                formatter,
                "invalid workflow step id: {}",
                workflow_error_text(id)
            ),
            Self::DuplicateStepId(id) => write!(
                formatter,
                "duplicate workflow step id: {}",
                workflow_error_text(id)
            ),
            Self::PlanOwnershipMismatch => {
                formatter.write_str("workflow plan is not owned by this engine")
            }
            Self::ApprovalMismatch => {
                formatter.write_str("approval is not valid for this workflow")
            }
            Self::StepCapabilityLeaseCount { expected, actual } => write!(
                formatter,
                "workflow requires {expected} step capability leases but received {actual}"
            ),
            Self::StepCapabilityPolicyCount { expected, actual } => write!(
                formatter,
                "workflow requires {expected} step capability policies but received {actual}"
            ),
            Self::StepCapabilityPolicyMismatch { expected, actual } => write!(
                formatter,
                "workflow step capability policy {} does not match expected step {}",
                workflow_error_text(actual),
                workflow_error_text(expected)
            ),
            Self::ExecutionInProgress => {
                formatter.write_str("a workflow execution is already suspended")
            }
            Self::NoSuspendedExecution => {
                formatter.write_str("no suspended workflow execution is available to resume")
            }
            Self::CapabilityLease(error) => write!(formatter, "capability lease error: {error}"),
            Self::ExternalTool(error) => write!(formatter, "external tool error: {error}"),
            Self::Checkpoint(error) => write!(formatter, "workflow checkpoint error: {error}"),
            Self::Data(error) => write!(formatter, "workflow data error: {error}"),
            Self::DataContract(error) => write!(formatter, "workflow data contract error: {error}"),
            Self::OperationLedger(error) => {
                write!(formatter, "workflow operation ledger error: {error}")
            }
            Self::Runtime(error) => write!(formatter, "runtime error: {error}"),
            Self::StepSuspended { step_id, .. } => {
                write!(
                    formatter,
                    "workflow step suspended without runnable tool work: {step_id}"
                )
            }
            Self::StepRejected { step_id, .. } => {
                write!(
                    formatter,
                    "workflow step rejected by the Splash profile: {step_id}"
                )
            }
            Self::StepFailed { step_id, .. } => {
                write!(formatter, "workflow step failed: {step_id}")
            }
            Self::DataflowOutput { step_id, error, .. } => {
                write!(
                    formatter,
                    "workflow dataflow output rejected for step {step_id}: {error}"
                )
            }
            Self::DataflowContractOutput { step_id, error, .. } => {
                write!(
                    formatter,
                    "workflow dataflow output rejected by contract for step {step_id}: {error}"
                )
            }
        }
    }
}

impl std::error::Error for WorkflowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CapabilityLease(error) => Some(error),
            Self::ExternalTool(error) => Some(error),
            Self::Checkpoint(error) => Some(error),
            Self::Data(error) => Some(error),
            Self::DataContract(error) => Some(error),
            Self::OperationLedger(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::DataflowOutput { error, .. } => Some(error),
            Self::DataflowContractOutput { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Rejection while decoding, validating, or encoding a data-only workflow
/// draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowDraftError {
    InputTooLarge { actual: usize, maximum: usize },
    OutputTooLarge { actual: usize, maximum: usize },
    InvalidEncoding,
    UnsupportedFormatVersion { actual: u8, expected: u8 },
    InvalidPlan(WorkflowError),
    SerializationFailed,
}

impl Display for WorkflowDraftError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => write!(
                formatter,
                "workflow draft is {actual} bytes but may accept at most {maximum} bytes"
            ),
            Self::OutputTooLarge { actual, maximum } => write!(
                formatter,
                "workflow draft is {actual} bytes but may encode at most {maximum} bytes"
            ),
            Self::InvalidEncoding => formatter.write_str("workflow draft is not valid JSON"),
            Self::UnsupportedFormatVersion { actual, expected } => write!(
                formatter,
                "workflow draft format version {actual} is not supported; expected {expected}"
            ),
            Self::InvalidPlan(error) => write!(formatter, "invalid workflow draft: {error}"),
            Self::SerializationFailed => {
                formatter.write_str("workflow draft could not be encoded as JSON")
            }
        }
    }
}

impl std::error::Error for WorkflowDraftError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPlan(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RuntimeError> for WorkflowError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

struct DataflowExecutionState {
    data: WorkflowData,
    data_contract: Option<WorkflowDataContract>,
}

struct SuspendedWorkflowExecution {
    plan: WorkflowPlan,
    step_index: usize,
    lease: CapabilityLease,
    leases: WorkflowCapabilityLeases,
    dataflow: Option<DataflowExecutionState>,
}

pub struct WorkflowEngine {
    engine_id: u64,
    runtime: CapabilityRuntime,
    events: VecDeque<WorkflowEvent>,
    max_events: NonZeroUsize,
    dropped_events: u64,
    first_event_sequence: u64,
    next_event_sequence: u64,
    next_plan_id: u64,
    next_approval_nonce: u64,
    suspended_execution: Option<SuspendedWorkflowExecution>,
    last_dataflow: Option<WorkflowData>,
}

impl WorkflowEngine {
    pub fn new(runtime: CapabilityRuntime) -> Self {
        Self::with_event_history_capacity(
            runtime,
            NonZeroUsize::new(DEFAULT_MAX_WORKFLOW_EVENTS)
                .expect("default workflow event limit is nonzero"),
        )
        .expect("default workflow event limit is within the hard limit")
    }

    /// Creates an engine with a host-selected bounded in-memory event view.
    ///
    /// Event eviction affects observability only. Checkpoints, operation
    /// ledgers, approvals, and the active capability lease remain separate
    /// authority boundaries. Values above [`MAX_WORKFLOW_EVENTS`] are rejected.
    pub fn with_event_history_capacity(
        runtime: CapabilityRuntime,
        max_events: NonZeroUsize,
    ) -> Result<Self, WorkflowEventHistoryError> {
        if max_events.get() > MAX_WORKFLOW_EVENTS {
            return Err(WorkflowEventHistoryError::CapacityTooLarge {
                requested: max_events.get(),
                maximum: MAX_WORKFLOW_EVENTS,
            });
        }
        Ok(Self {
            engine_id: NEXT_ENGINE_ID.fetch_add(1, Ordering::Relaxed),
            runtime,
            events: VecDeque::new(),
            max_events,
            dropped_events: 0,
            first_event_sequence: 1,
            next_event_sequence: 1,
            next_plan_id: 1,
            next_approval_nonce: 1,
            suspended_execution: None,
            last_dataflow: None,
        })
    }

    pub fn runtime(&self) -> &CapabilityRuntime {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut CapabilityRuntime {
        &mut self.runtime
    }

    /// Returns whether this engine is waiting for a claimed external tool to
    /// resume an approved workflow step.
    pub fn has_suspended_execution(&self) -> bool {
        self.suspended_execution.is_some()
    }

    /// Returns the current or most recently terminal bounded dataflow state.
    ///
    /// This host-facing view may contain application data, so it is separate
    /// from [`Self::events`], whose entries never retain raw input or output.
    /// While an external step is suspended, the returned context is the exact
    /// approval-bound context retained for that continuation.
    pub fn dataflow_snapshot(&self) -> Option<&WorkflowData> {
        self.suspended_execution
            .as_ref()
            .and_then(|execution| execution.dataflow.as_ref())
            .map(|dataflow| &dataflow.data)
            .or(self.last_dataflow.as_ref())
    }

    /// Takes the most recent terminal dataflow state.
    ///
    /// A suspended workflow retains its context internally and therefore does
    /// not expose ownership until it reaches a terminal state.
    pub fn take_dataflow_snapshot(&mut self) -> Option<WorkflowData> {
        if self.suspended_execution.is_some() {
            return None;
        }
        self.last_dataflow.take()
    }

    /// Claims the next external operation belonging to a suspended workflow.
    ///
    /// Hosts should complete or cancel it through the matching workflow method
    /// so the engine can continue the retained approval state.
    pub fn claim_next_external_tool(&mut self) -> Option<ExternalToolInvocation> {
        self.suspended_execution
            .is_some()
            .then(|| self.runtime.claim_next_external_tool())
            .flatten()
    }

    /// Marks one claimed workflow operation as cancellation-requested without
    /// resolving its suspended step.
    ///
    /// The host must pass the returned identity to the adapter that owns the
    /// operation. Only an adapter acknowledgement should be followed by
    /// [`Self::confirm_external_tool_cancellation`]; forceful termination is
    /// indeterminate and requires durable reconciliation instead.
    pub fn request_external_tool_cancellation(
        &mut self,
        id: ExternalToolId,
    ) -> Result<ExternalToolCancellationRequest, WorkflowError> {
        if self.suspended_execution.is_none() {
            return Err(WorkflowError::NoSuspendedExecution);
        }
        self.runtime
            .request_external_tool_cancellation(id)
            .map_err(WorkflowError::ExternalTool)
    }

    /// Records or verifies a durable identity for the next queued external
    /// operation without claiming it for dispatch.
    ///
    /// The host must persist the updated [`WorkflowOperationLedger`] before it
    /// calls [`Self::claim_prepared_external_operation`]. This order records
    /// the exact plan step, tool, and canonical input before any effect can be
    /// sent to a worker. The nonce is host-owned, durable, and unique for one
    /// logical external effect; it must not be derived from Splash source or a
    /// runtime-local call index.
    pub fn prepare_next_external_operation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        operation_nonce: &[u8],
    ) -> Result<Option<PreparedWorkflowExternalOperation>, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        let (step_index, step_id) = self.suspended_step_for_plan(plan)?;
        let Some(invocation) = self.runtime.peek_next_external_tool() else {
            return Ok(None);
        };
        let payload = invocation
            .worker_payload()
            .map_err(WorkflowError::ExternalTool)?;
        let canonical_input = canonical_operation_input_bytes(&payload).map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        let operation_key = self.derive_operation_key(
            plan,
            &step_id,
            &invocation.name,
            &canonical_input,
            operation_nonce,
        )?;

        self.validate_operation_ledger(plan, ledger)?;
        if ledger.operation(&operation_key).is_some() {
            self.validate_external_operation_binding(
                plan,
                ledger,
                &step_id,
                &invocation.name,
                &operation_key,
                &canonical_input,
            )?;
        } else {
            self.record_operation(
                plan,
                ledger,
                step_id.clone(),
                invocation.name.clone(),
                operation_key.clone(),
                &canonical_input,
            )?;
        }

        Ok(Some(PreparedWorkflowExternalOperation {
            engine_id: self.engine_id,
            plan_id: plan.id,
            external_tool_id: invocation.id,
            step_id,
            completed_steps: step_index,
            operation_key,
            payload,
            canonical_input,
        }))
    }

    /// Claims one exact external operation after its durable ledger record was
    /// persisted by the host.
    ///
    /// The prepared value is process-local and bound to this engine, plan,
    /// current suspended step, worker ledger record, and queued external ID.
    /// A stale value fails without claiming another queued operation.
    pub fn claim_prepared_external_operation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        prepared: PreparedWorkflowExternalOperation,
    ) -> Result<ClaimedWorkflowExternalOperation, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        if prepared.engine_id != self.engine_id || prepared.plan_id != plan.id {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let (step_index, step_id) = self.suspended_step_for_plan(plan)?;
        if prepared.step_id != step_id || prepared.completed_steps != step_index {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationBindingMismatch(prepared.operation_key),
            ));
        }
        self.validate_external_operation_binding(
            plan,
            ledger,
            &prepared.step_id,
            ledger
                .operation(&prepared.operation_key)
                .ok_or_else(|| {
                    WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownOperation(
                        prepared.operation_key.clone(),
                    ))
                })?
                .tool(),
            &prepared.operation_key,
            &prepared.canonical_input,
        )?;

        let invocation = self
            .runtime
            .claim_external_tool(prepared.external_tool_id)
            .map_err(WorkflowError::ExternalTool)?;
        let payload = invocation
            .worker_payload()
            .map_err(WorkflowError::ExternalTool)?;
        let canonical_input = canonical_operation_input_bytes(&payload).map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        if payload != prepared.payload || canonical_input != prepared.canonical_input {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationBindingMismatch(prepared.operation_key),
            ));
        }
        self.validate_external_operation_binding(
            plan,
            ledger,
            &prepared.step_id,
            &invocation.name,
            &prepared.operation_key,
            &canonical_input,
        )?;

        Ok(ClaimedWorkflowExternalOperation {
            engine_id: prepared.engine_id,
            plan_id: prepared.plan_id,
            step_id: prepared.step_id,
            completed_steps: prepared.completed_steps,
            operation_key: prepared.operation_key,
            payload,
            canonical_input,
            invocation,
        })
    }

    /// Completes a claimed external operation and drives its suspended
    /// workflow forward. A later external `await` returns
    /// [`WorkflowError::StepSuspended`] again with the same retained approval.
    pub fn complete_external_tool(
        &mut self,
        id: ExternalToolId,
        result: Result<String, ToolError>,
    ) -> Result<(), WorkflowError> {
        if self.suspended_execution.is_none() {
            return Err(WorkflowError::NoSuspendedExecution);
        }
        match self.runtime.complete_external_tool(id, result) {
            Ok(Some(report)) => self.continue_suspended_execution(report),
            Ok(None) => Ok(()),
            Err(error) => {
                if matches!(error, ExternalToolError::Runtime(_)) {
                    self.suspended_execution = None;
                }
                Err(WorkflowError::ExternalTool(error))
            }
        }
    }

    /// Confirms an adapter's acknowledgement of a prior cancellation request
    /// and drives the suspended workflow forward with the resulting failure.
    pub fn confirm_external_tool_cancellation(
        &mut self,
        id: ExternalToolId,
    ) -> Result<(), WorkflowError> {
        if self.suspended_execution.is_none() {
            return Err(WorkflowError::NoSuspendedExecution);
        }
        match self.runtime.confirm_external_tool_cancellation(id) {
            Ok(Some(report)) => self.continue_suspended_execution(report),
            Ok(None) => Ok(()),
            Err(error) => {
                if matches!(error, ExternalToolError::Runtime(_)) {
                    self.suspended_execution = None;
                }
                Err(WorkflowError::ExternalTool(error))
            }
        }
    }

    /// Records a trusted terminal cancellation assertion for a claimed
    /// external operation and drives its suspended workflow forward.
    ///
    /// This does not request cancellation from an adapter. Prefer the
    /// request/confirm pair unless the host already knows the operation never
    /// started or has separate trustworthy terminal evidence.
    pub fn cancel_external_tool(&mut self, id: ExternalToolId) -> Result<(), WorkflowError> {
        if self.suspended_execution.is_none() {
            return Err(WorkflowError::NoSuspendedExecution);
        }
        match self.runtime.cancel_external_tool(id) {
            Ok(Some(report)) => self.continue_suspended_execution(report),
            Ok(None) => Ok(()),
            Err(error) => {
                if matches!(error, ExternalToolError::Runtime(_)) {
                    self.suspended_execution = None;
                }
                Err(WorkflowError::ExternalTool(error))
            }
        }
    }

    /// Continues the retained workflow after a host used a lower-level
    /// `CapabilityRuntime` external completion, timeout, or reconciliation API.
    ///
    /// Prefer [`Self::complete_external_tool`] or the cooperative
    /// cancellation request/confirm pair for ordinary external lifecycle work.
    pub fn continue_suspended_execution(
        &mut self,
        report: Evaluation,
    ) -> Result<(), WorkflowError> {
        let Some(SuspendedWorkflowExecution {
            plan,
            step_index,
            lease,
            leases,
            dataflow,
        }) = self.suspended_execution.take()
        else {
            return Err(WorkflowError::NoSuspendedExecution);
        };
        if let Some(mut dataflow) = dataflow {
            match self.drive_dataflow_step(&plan, step_index, report, lease, leases, &mut dataflow)
            {
                Ok(leases) => self.execute_dataflow_from(
                    &plan,
                    step_index.saturating_add(1),
                    leases,
                    dataflow,
                ),
                Err(error) => {
                    if self.suspended_execution.is_none() {
                        self.last_dataflow = Some(dataflow.data);
                    }
                    Err(error)
                }
            }
        } else {
            let leases = self.drive_step(&plan, step_index, report, lease, leases)?;
            self.execute_from(&plan, step_index.saturating_add(1), leases)
        }
    }

    /// Returns the bounded ordered in-memory workflow event view.
    pub fn events(&self) -> WorkflowEventLog<'_> {
        WorkflowEventLog {
            entries: &self.events,
        }
    }

    /// Exports retained telemetry after `next_sequence` in source order.
    ///
    /// A host that persists events should begin with cursor `1`, append each
    /// nonempty batch through `durable_events::WorkflowEventStore`, and retain
    /// the returned [`WorkflowEventBatch::next_sequence`] as its next cursor.
    /// If an in-memory eviction or [`Self::clear_events`] overtakes that
    /// cursor, this method fails instead of silently exporting an incomplete
    /// history. Event export is observability only: it does not create a
    /// checkpoint, approval, lease, or restart decision.
    pub fn events_since(
        &self,
        next_sequence: u64,
    ) -> Result<WorkflowEventBatch, WorkflowEventCursorError> {
        if next_sequence == 0 {
            return Err(WorkflowEventCursorError::InvalidCursor);
        }
        if next_sequence < self.first_event_sequence {
            return Err(WorkflowEventCursorError::Evicted {
                requested: next_sequence,
                earliest_available: self.first_event_sequence,
            });
        }
        if next_sequence > self.next_event_sequence {
            return Err(WorkflowEventCursorError::Ahead {
                requested: next_sequence,
                next_available: self.next_event_sequence,
            });
        }

        let skipped = usize::try_from(next_sequence - self.first_event_sequence)
            .map_err(|_| WorkflowEventCursorError::InvalidCursor)?;
        let records = self
            .events
            .iter()
            .skip(skipped)
            .enumerate()
            .map(|(offset, event)| WorkflowEventRecord {
                sequence: next_sequence.saturating_add(offset as u64),
                event: event.clone(),
            })
            .collect();
        let batch = WorkflowEventBatch {
            records,
            next_sequence: self.next_event_sequence,
        };
        debug_assert!(batch.validate().is_ok());
        Ok(batch)
    }

    /// Returns the configured capacity of the in-memory event view.
    pub const fn max_events(&self) -> usize {
        self.max_events.get()
    }

    /// Returns how many oldest events have been evicted from this engine.
    ///
    /// A nonzero result means the in-memory telemetry is incomplete. It is not
    /// a durable audit result and must never drive automatic workflow replay.
    pub const fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Clears the retained in-memory event view and its eviction counter.
    ///
    /// This does not alter plans, approvals, capability leases, checkpoints,
    /// operation ledgers, or suspended execution state.
    pub fn clear_events(&mut self) {
        self.events.clear();
        self.dropped_events = 0;
        self.first_event_sequence = self.next_event_sequence;
    }

    fn record_event(&mut self, event: WorkflowEvent) {
        // `u64::MAX` is a cursor-only sentinel. At that theoretical limit,
        // preserve sequence uniqueness by dropping further telemetry instead
        // of wrapping a durable replay identity.
        if self.next_event_sequence == u64::MAX {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return;
        }
        if self.events.len() == self.max_events.get() {
            self.events.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
            self.first_event_sequence = self.first_event_sequence.saturating_add(1);
        }
        self.events.push_back(event);
        self.next_event_sequence = self.next_event_sequence.saturating_add(1);
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
        self.record_event(WorkflowEvent::Planned {
            plan_id: plan.id,
            step_count: plan.steps.len(),
        });
        Ok(plan)
    }

    /// Converts a prevalidated, data-only draft into this engine's trusted
    /// plan object.
    ///
    /// This records planning telemetry but does not inspect a capability
    /// catalog, issue a lease, review source, or approve execution. A host
    /// must still review the resulting plan and make a separate approval
    /// decision before it can run.
    pub fn plan_draft(&mut self, draft: WorkflowDraft) -> Result<WorkflowPlan, WorkflowError> {
        self.plan(draft.into_steps())
    }

    /// Approves a plan against the full current capability catalog.
    ///
    /// This preserves the simple approval API while binding execution to the
    /// exact catalog visible at approval time. Hosts presenting a narrower
    /// operator-approved tool set should issue a lease explicitly and call
    /// [`Self::approve_with_capability_lease`].
    pub fn approve(&mut self, plan: &WorkflowPlan) -> Result<Approval, WorkflowError> {
        let lease = self
            .runtime
            .issue_full_capability_lease()
            .map_err(WorkflowError::CapabilityLease)?;
        self.approve_with_capability_lease(plan, lease)
    }

    /// Approves a plan under a host-issued attenuated capability lease.
    ///
    /// The lease is process-local and validates the originating runtime and
    /// complete catalog fingerprint before approval. It remains active across
    /// tool-promise continuation so dynamic tool names cannot exceed the
    /// approved name and call-budget set.
    pub fn approve_with_capability_lease(
        &mut self,
        plan: &WorkflowPlan,
        lease: CapabilityLease,
    ) -> Result<Approval, WorkflowError> {
        self.approve_with_workflow_capability_leases(plan, WorkflowCapabilityLeases::shared(lease))
    }

    /// Approves a plan with one independently attenuated lease per step.
    ///
    /// The vector order is the trusted plan order. An early step can therefore
    /// never activate authority issued for a later step, including while it is
    /// suspended on an external `await`. Empty leases are valid for pure
    /// steps. Every lease must belong to this runtime's unchanged catalog.
    pub fn approve_with_step_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        leases: Vec<CapabilityLease>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        self.validate_step_capability_lease_count(plan.steps.len(), leases.len())?;
        self.approve_with_workflow_capability_leases(
            plan,
            WorkflowCapabilityLeases::per_step(leases),
        )
    }

    /// Approves a plan with host-owned grant policies bound to each step.
    ///
    /// Policies must have the same count and order as the trusted plan. Their
    /// step IDs are checked before the runtime issues any lease, so an LLM or
    /// review hint cannot accidentally shift a later step's authority forward.
    /// This convenience API has no custom authorizer hook; use
    /// [`Self::approve_with_step_capability_leases`] when a host needs to
    /// attach one to a manually issued lease.
    pub fn approve_with_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        let leases = self.issue_step_capability_policy_leases(&plan.steps, policies)?;
        self.approve_with_step_capability_leases(plan, leases)
    }

    /// Approves a workflow together with one exact bounded JSON context.
    ///
    /// The context is copied into the process-local approval and is injected
    /// as the data-only `workflow` global for each step. It cannot add a
    /// capability; tool calls remain constrained by the lease selected here.
    pub fn approve_dataflow(
        &mut self,
        plan: &WorkflowPlan,
        data: WorkflowData,
    ) -> Result<Approval, WorkflowError> {
        let lease = self
            .runtime
            .issue_full_capability_lease()
            .map_err(WorkflowError::CapabilityLease)?;
        self.approve_dataflow_with_capability_lease(plan, data, lease)
    }

    /// Approves a dataflow workflow under a host-issued attenuated lease.
    pub fn approve_dataflow_with_capability_lease(
        &mut self,
        plan: &WorkflowPlan,
        data: WorkflowData,
        lease: CapabilityLease,
    ) -> Result<Approval, WorkflowError> {
        self.approve_dataflow_with_workflow_capability_leases(
            plan,
            data,
            None,
            WorkflowCapabilityLeases::shared(lease),
        )
    }

    /// Approves a dataflow workflow with independently attenuated authority
    /// for each trusted step.
    pub fn approve_dataflow_with_step_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        data: WorkflowData,
        leases: Vec<CapabilityLease>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        data.validate_for_completed_prefix(plan, 0)
            .map_err(WorkflowError::Data)?;
        self.validate_step_capability_lease_count(plan.steps.len(), leases.len())?;
        self.approve_dataflow_with_workflow_capability_leases(
            plan,
            data,
            None,
            WorkflowCapabilityLeases::per_step(leases),
        )
    }

    /// Approves a dataflow workflow using named, host-owned policy bindings.
    ///
    /// This is the preferred entry point for generated plans: the initial
    /// JSON context and every capability grant are bound to the same trusted
    /// plan before source can execute.
    pub fn approve_dataflow_with_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        data: WorkflowData,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        data.validate_for_completed_prefix(plan, 0)
            .map_err(WorkflowError::Data)?;
        let leases = self.issue_step_capability_policy_leases(&plan.steps, policies)?;
        self.approve_dataflow_with_step_capability_leases(plan, data, leases)
    }

    /// Approves bounded workflow data under a complete host-owned schema
    /// contract and the current catalog's full lease.
    ///
    /// Prefer one of the narrower contract-and-lease variants for generated
    /// workflows. The contract is validated before this convenience method
    /// issues a full lease.
    pub fn approve_dataflow_with_contract(
        &mut self,
        plan: &WorkflowPlan,
        mut data: WorkflowData,
        data_contract: WorkflowDataContract,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        self.validate_dataflow_contract(plan, &data, 0, &data_contract)?;
        data.bind_contract(&data_contract)
            .map_err(WorkflowError::Data)?;
        let lease = self
            .runtime
            .issue_full_capability_lease()
            .map_err(WorkflowError::CapabilityLease)?;
        self.approve_dataflow_with_contract_and_capability_lease(plan, data, data_contract, lease)
    }

    /// Approves bounded workflow data under a host-owned schema contract and
    /// one explicit attenuated lease.
    pub fn approve_dataflow_with_contract_and_capability_lease(
        &mut self,
        plan: &WorkflowPlan,
        data: WorkflowData,
        data_contract: WorkflowDataContract,
        lease: CapabilityLease,
    ) -> Result<Approval, WorkflowError> {
        self.approve_dataflow_with_workflow_capability_leases(
            plan,
            data,
            Some(data_contract),
            WorkflowCapabilityLeases::shared(lease),
        )
    }

    /// Approves bounded workflow data under a host-owned schema contract and
    /// one independently attenuated lease for each trusted step.
    pub fn approve_dataflow_with_contract_and_step_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        mut data: WorkflowData,
        data_contract: WorkflowDataContract,
        leases: Vec<CapabilityLease>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        self.validate_dataflow_contract(plan, &data, 0, &data_contract)?;
        data.bind_contract(&data_contract)
            .map_err(WorkflowError::Data)?;
        self.validate_step_capability_lease_count(plan.steps.len(), leases.len())?;
        self.approve_dataflow_with_workflow_capability_leases(
            plan,
            data,
            Some(data_contract),
            WorkflowCapabilityLeases::per_step(leases),
        )
    }

    /// Approves bounded workflow data under a host-owned schema contract and
    /// ordered named capability policies.
    ///
    /// The contract and context are validated before the runtime issues any
    /// policy-derived lease.
    pub fn approve_dataflow_with_contract_and_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        mut data: WorkflowData,
        data_contract: WorkflowDataContract,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        self.validate_dataflow_contract(plan, &data, 0, &data_contract)?;
        data.bind_contract(&data_contract)
            .map_err(WorkflowError::Data)?;
        let leases = self.issue_step_capability_policy_leases(&plan.steps, policies)?;
        self.approve_dataflow_with_contract_and_step_capability_leases(
            plan,
            data,
            data_contract,
            leases,
        )
    }

    fn approve_dataflow_with_workflow_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        mut data: WorkflowData,
        data_contract: Option<WorkflowDataContract>,
        leases: WorkflowCapabilityLeases,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        data.validate_for_completed_prefix(plan, 0)
            .map_err(WorkflowError::Data)?;
        if let Some(data_contract) = &data_contract {
            data_contract
                .validate_for(plan, &data, 0)
                .map_err(WorkflowError::DataContract)?;
            data.bind_contract(data_contract)
                .map_err(WorkflowError::Data)?;
        }
        leases.validate(&self.runtime)?;
        let approval = self.issue_approval(
            plan,
            ApprovalKind::Dataflow {
                data,
                data_contract,
                leases,
            },
        );
        self.record_event(WorkflowEvent::Approved { plan_id: plan.id });
        Ok(approval)
    }

    fn approve_with_workflow_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        leases: WorkflowCapabilityLeases,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        leases.validate(&self.runtime)?;
        let approval = self.issue_approval(plan, ApprovalKind::Plan(leases));
        self.record_event(WorkflowEvent::Approved { plan_id: plan.id });
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
        self.record_event(WorkflowEvent::Checkpointed {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        Ok(checkpoint)
    }

    /// Builds a checkpoint for a dataflow prefix without serializing raw input
    /// or prior step outputs into the checkpoint itself.
    ///
    /// The supplied context must contain exactly the outputs for the completed
    /// plan prefix. The checkpoint retains only its stable digest, so a later
    /// resume requires a separately retained matching [`WorkflowData`] value.
    pub fn dataflow_checkpoint_after(
        &mut self,
        plan: &WorkflowPlan,
        data: &WorkflowData,
        completed_step_count: usize,
    ) -> Result<WorkflowCheckpoint, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        let checkpoint = WorkflowCheckpoint::for_dataflow(plan, data, completed_step_count)
            .map_err(WorkflowError::Checkpoint)?;
        self.record_event(WorkflowEvent::Checkpointed {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        Ok(checkpoint)
    }

    /// Builds a dataflow checkpoint bound to the exact host-owned schema
    /// contract that validated the completed prefix.
    ///
    /// Checkpoint JSON retains only a stable contract digest, never schema
    /// source or raw data. A later resume must supply the same contract before
    /// the remaining step leases can be issued.
    pub fn dataflow_checkpoint_after_with_contract(
        &mut self,
        plan: &WorkflowPlan,
        data: &mut WorkflowData,
        data_contract: &WorkflowDataContract,
        completed_step_count: usize,
    ) -> Result<WorkflowCheckpoint, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        data_contract
            .validate_for(plan, data, completed_step_count)
            .map_err(|error| {
                WorkflowError::Checkpoint(WorkflowCheckpointError::DataflowContract(error))
            })?;
        data.bind_contract(data_contract)
            .map_err(WorkflowError::Data)?;
        let checkpoint = WorkflowCheckpoint::for_dataflow_with_contract(
            plan,
            data,
            data_contract,
            completed_step_count,
        )
        .map_err(WorkflowError::Checkpoint)?;
        self.record_event(WorkflowEvent::Checkpointed {
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
        self.record_event(WorkflowEvent::OperationLedgerCreated { plan_id: plan.id });
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
        self.record_event(WorkflowEvent::OperationRecorded {
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

    /// Derives a tenant-scoped durable compensation key for one succeeded
    /// operation. Compensation keys are deliberately in the `cmp-` namespace
    /// so they cannot collide with normal `op-` operation identities.
    pub fn derive_compensation_key(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        operation_key: &str,
        policy: &WorkflowCompensationPolicy,
        input: &[u8],
        compensation_nonce: &[u8],
    ) -> Result<String, WorkflowError> {
        self.validate_operation_ledger(plan, ledger)?;
        policy
            .validate_syntax()
            .map_err(WorkflowError::OperationLedger)?;
        let operation = ledger.operation(operation_key).ok_or_else(|| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownOperation(
                operation_key.to_owned(),
            ))
        })?;
        if operation.state != WorkflowOperationState::Succeeded {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationRequiresSucceededOperation {
                    operation_key: operation.operation_key.clone(),
                    state: operation.state,
                },
            ));
        }
        if operation.tool != policy.tool {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationPolicyMismatch(
                    operation.operation_key.clone(),
                ),
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
        if compensation_nonce.is_empty() {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::EmptyOperationNonce,
            ));
        }
        if compensation_nonce.len() > MAX_WORKFLOW_OPERATION_NONCE_BYTES {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationNonceTooLarge {
                    actual: compensation_nonce.len(),
                    maximum: MAX_WORKFLOW_OPERATION_NONCE_BYTES,
                },
            ));
        }
        Ok(derived_workflow_compensation_key(
            plan.fingerprint(),
            &operation.operation_key,
            &operation.tool,
            &policy.tenant_scope,
            &policy.grant_fingerprint,
            input,
            compensation_nonce,
        ))
    }

    /// Records the one durable compensation intent permitted for a succeeded
    /// operation. Persist the ledger through compare-and-swap storage before
    /// creating an approval or sending the resulting worker frame.
    pub fn record_compensation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        operation_key: &str,
        policy: &WorkflowCompensationPolicy,
        compensation_key: impl Into<String>,
        input: &[u8],
    ) -> Result<(), WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        ledger
            .validate_for(plan)
            .map_err(WorkflowError::OperationLedger)?;
        let compensation_key = compensation_key.into();
        ledger
            .record_compensation(operation_key, policy, compensation_key.clone(), input)
            .map_err(WorkflowError::OperationLedger)?;
        self.record_event(WorkflowEvent::CompensationRecorded {
            plan_id: plan.id,
            operation_key: operation_key.to_owned(),
            compensation_key,
        });
        Ok(())
    }

    /// Derives and records a durable compensation intent for a succeeded
    /// operation.
    pub fn record_derived_compensation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        operation_key: &str,
        policy: &WorkflowCompensationPolicy,
        input: &[u8],
        compensation_nonce: &[u8],
    ) -> Result<String, WorkflowError> {
        let compensation_key = self.derive_compensation_key(
            plan,
            ledger,
            operation_key,
            policy,
            input,
            compensation_nonce,
        )?;
        self.record_compensation(
            plan,
            ledger,
            operation_key,
            policy,
            compensation_key.clone(),
            input,
        )?;
        Ok(compensation_key)
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

    /// Creates an authenticated v4 worker dispatch frame for a persisted
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

    /// Creates an authenticated worker dispatch frame from one exact claimed
    /// external workflow operation.
    ///
    /// This prevents a host from accidentally pairing the current suspended
    /// step with another operation's key or payload. It does not persist the
    /// ledger: persist the prepared record before calling this method.
    pub fn prepare_authenticated_claimed_external_operation_dispatch(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        claimed: &ClaimedWorkflowExternalOperation,
        request_id: impl Into<String>,
        authenticator: &mut SessionAuthenticator,
    ) -> Result<AuthenticatedWorkflowOperationDispatch, WorkflowError> {
        self.validate_claimed_external_operation(plan, ledger, claimed)?;
        self.prepare_authenticated_operation_dispatch(
            plan,
            ledger,
            claimed.operation_key(),
            claimed.payload().clone(),
            request_id,
            authenticator,
        )
    }

    /// Issues a one-use, session-bound host approval for an already persisted
    /// compensation intent.
    ///
    /// A fresh approval may be issued after a crash, but only for the same
    /// ledger record, tenant scope, grant fingerprint, and compensation key.
    /// The worker journal then returns the existing pending or terminal state
    /// instead of executing a second inverse effect.
    pub fn approve_compensation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        target: WorkflowCompensationTarget<'_>,
        input: &[u8],
        authenticator: &SessionAuthenticator,
    ) -> Result<Approval, WorkflowError> {
        let operation_key = target.operation_key();
        let policy = target.policy();
        if authenticator.role() != SessionRole::Host {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationDispatchRequiresHostAuthenticator,
            ));
        }
        self.validate_operation_ledger(plan, ledger)?;
        target
            .verify_current()
            .map_err(WorkflowError::OperationLedger)?;
        let operation = ledger.operation(operation_key).ok_or_else(|| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownOperation(
                operation_key.to_owned(),
            ))
        })?;
        if operation.state != WorkflowOperationState::Succeeded {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationRequiresSucceededOperation {
                    operation_key: operation.operation_key.clone(),
                    state: operation.state,
                },
            ));
        }
        if operation.tool != policy.tool {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationPolicyMismatch(
                    operation.operation_key.clone(),
                ),
            ));
        }
        let compensation = operation.compensation.as_ref().ok_or_else(|| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownCompensation(
                operation.operation_key.clone(),
            ))
        })?;
        if !compensation.matches_policy(policy) {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationPolicyMismatch(
                    operation.operation_key.clone(),
                ),
            ));
        }
        compensation
            .verify_input(input)
            .map_err(WorkflowError::OperationLedger)?;

        let approval = self.issue_approval(
            plan,
            ApprovalKind::Compensation(CompensationApproval {
                ledger_revision: ledger.revision,
                operation_key: operation.operation_key.clone(),
                compensation_key: compensation.compensation_key.clone(),
                input_fingerprint: compensation.input_fingerprint.clone(),
                tenant_scope: compensation.tenant_scope.clone(),
                grant_fingerprint: compensation.grant_fingerprint.clone(),
                session_id: authenticator.session_id().to_owned(),
            }),
        );
        self.record_event(WorkflowEvent::CompensationApproved {
            plan_id: plan.id,
            operation_key: operation.operation_key.clone(),
            compensation_key: compensation.compensation_key.clone(),
        });
        Ok(approval)
    }

    /// Creates an authenticated v4 compensation frame from a persisted intent
    /// and one-use host approval.
    pub fn prepare_authenticated_operation_compensation(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        target: WorkflowCompensationTarget<'_>,
        dispatch: WorkflowCompensationDispatch,
        approval: Approval,
        authenticator: &mut SessionAuthenticator,
    ) -> Result<AuthenticatedWorkflowOperationCompensation, WorkflowError> {
        let operation_key = target.operation_key();
        let policy = target.policy();
        if authenticator.role() != SessionRole::Host {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationDispatchRequiresHostAuthenticator,
            ));
        }
        self.validate_operation_ledger(plan, ledger)?;
        target
            .verify_current()
            .map_err(WorkflowError::OperationLedger)?;
        if !self.approval_matches(plan, &approval) {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let ApprovalKind::Compensation(bound) = &approval.kind else {
            return Err(WorkflowError::ApprovalMismatch);
        };
        if bound.ledger_revision != ledger.revision
            || bound.operation_key != operation_key
            || bound.tenant_scope != policy.tenant_scope
            || bound.grant_fingerprint != policy.grant_fingerprint
            || bound.session_id != authenticator.session_id()
        {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let operation = ledger.operation(operation_key).ok_or_else(|| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownOperation(
                operation_key.to_owned(),
            ))
        })?;
        if operation.state != WorkflowOperationState::Succeeded || operation.tool != policy.tool {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let compensation = operation.compensation.as_ref().ok_or_else(|| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownCompensation(
                operation.operation_key.clone(),
            ))
        })?;
        if compensation.compensation_key != bound.compensation_key
            || compensation.input_fingerprint != bound.input_fingerprint
            || !compensation.matches_policy(policy)
        {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let binding = OperationCompensationBinding::new(
            operation.tool.clone(),
            operation.operation_key.clone(),
            compensation.compensation_key.clone(),
            compensation.tenant_scope.clone(),
            compensation.grant_fingerprint.clone(),
        )
        .map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        let request = OperationCompensationRequest::new(
            authenticator.session_id().to_owned(),
            dispatch.request_id,
            binding,
            dispatch.payload,
        )
        .map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        let input = request.canonical_input_bytes().map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        compensation
            .verify_input(&input)
            .map_err(WorkflowError::OperationLedger)?;
        let frame = authenticator
            .seal(WorkerMessage::CompensateOperation {
                request: request.clone(),
            })
            .map_err(|error| {
                WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
            })?;
        Ok(AuthenticatedWorkflowOperationCompensation { request, frame })
    }

    /// Applies a verified worker compensation observation to the host ledger.
    pub fn apply_verified_operation_compensation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        request: &OperationCompensationRequest,
        result: &OperationCompensationResult,
    ) -> Result<WorkflowOperationState, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        ledger
            .validate_for(plan)
            .map_err(WorkflowError::OperationLedger)?;
        let state = ledger
            .apply_verified_compensation(request, result)
            .map_err(WorkflowError::OperationLedger)?;
        self.record_event(WorkflowEvent::CompensationObserved {
            plan_id: plan.id,
            operation_key: request.operation_key.clone(),
            compensation_key: request.compensation_key.clone(),
            state,
        });
        Ok(state)
    }

    /// Opens an authenticated worker compensation frame and records its state.
    pub fn apply_authenticated_operation_compensation(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        request: &OperationCompensationRequest,
        authenticator: &mut SessionAuthenticator,
        frame: AuthenticatedWorkerMessage,
    ) -> Result<WorkflowOperationState, WorkflowError> {
        if authenticator.role() != SessionRole::Host {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationDispatchRequiresHostAuthenticator,
            ));
        }
        let message = authenticator.open(frame).map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        let WorkerMessage::CompensationResult { result } = message else {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::UnexpectedCompensationMessage,
            ));
        };
        self.apply_verified_operation_compensation(plan, ledger, request, &result)
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
        self.record_event(WorkflowEvent::OperationObserved {
            plan_id: plan.id,
            step_id: operation.step_id.clone(),
            tool: operation.tool.clone(),
            state,
        });
        Ok(state)
    }

    /// Applies an authenticated worker response to an initial durable dispatch.
    ///
    /// This records only the durable lifecycle state. Persist the resulting
    /// ledger mutation before completing a matching external Splash promise or
    /// allowing any later workflow step to run.
    pub fn apply_verified_operation_dispatch_result(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        request: &OperationDispatchRequest,
        result: &OperationReconcileResult,
    ) -> Result<WorkflowOperationState, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        self.validate_operation_ledger(plan, ledger)?;
        let expected = self.operation_dispatch_request(
            plan,
            ledger,
            &request.operation_key,
            request.payload.clone(),
            request.session_id.clone(),
            request.request_id.clone(),
        )?;
        if expected != *request || !result.matches_dispatch(request) {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::ReconciliationMismatch,
            ));
        }
        let reconciliation = OperationReconcileRequest::new(
            request.session_id.clone(),
            request.request_id.clone(),
            request.tool.clone(),
            request.operation_key.clone(),
        )
        .map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        self.apply_verified_operation_reconciliation(plan, ledger, &reconciliation, result)
    }

    /// Opens an authenticated worker dispatch-result frame and records its
    /// durable lifecycle observation.
    ///
    /// Authentication, message kind, request identity, plan, tool, canonical
    /// input, and state transition all validate before the ledger changes. The
    /// host must persist the updated ledger before resolving the associated
    /// external tool promise.
    pub fn apply_authenticated_operation_dispatch_result(
        &mut self,
        plan: &WorkflowPlan,
        ledger: &mut WorkflowOperationLedger,
        request: &OperationDispatchRequest,
        authenticator: &mut SessionAuthenticator,
        frame: AuthenticatedWorkerMessage,
    ) -> Result<(WorkflowOperationState, OperationReconcileResult), WorkflowError> {
        if authenticator.role() != SessionRole::Host {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationDispatchRequiresHostAuthenticator,
            ));
        }
        let message = authenticator.open(frame).map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        let WorkerMessage::OperationResult { result } = message else {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::UnexpectedOperationDispatchMessage,
            ));
        };
        let state =
            self.apply_verified_operation_dispatch_result(plan, ledger, request, &result)?;
        Ok((state, result))
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
        let lease = self
            .runtime
            .issue_full_capability_lease()
            .map_err(WorkflowError::CapabilityLease)?;
        self.approve_resume_with_capability_lease(plan, checkpoint, lease)
    }

    /// Creates a checkpoint-bound approval under an explicit attenuated lease.
    ///
    /// A resumed suffix receives fresh authority. The caller must therefore
    /// issue a new lease from the current runtime policy rather than carrying
    /// an earlier approval across a restart.
    pub fn approve_resume_with_capability_lease(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        lease: CapabilityLease,
    ) -> Result<Approval, WorkflowError> {
        self.approve_resume_with_workflow_capability_leases(
            plan,
            checkpoint,
            WorkflowCapabilityLeases::shared(lease),
        )
    }

    /// Creates a checkpoint-bound approval with one fresh lease for every
    /// unexecuted step in the trusted suffix.
    ///
    /// The vector begins at `checkpoint.completed_step_count()`, not at the
    /// first plan step. Completed steps receive no renewed authority after a
    /// restart. The queue is retained across a live external suspension, so
    /// the current suffix step keeps its own lease until it completes.
    pub fn approve_resume_with_step_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        leases: Vec<CapabilityLease>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_for(plan)
            .map_err(WorkflowError::Checkpoint)?;
        let expected = plan.steps.len() - checkpoint.completed_step_count();
        self.validate_step_capability_lease_count(expected, leases.len())?;
        self.approve_resume_with_workflow_capability_leases(
            plan,
            checkpoint,
            WorkflowCapabilityLeases::per_step(leases),
        )
    }

    /// Creates a checkpoint-bound approval from host-owned policies for the
    /// unexecuted trusted suffix.
    ///
    /// The first policy must name the first unfinished step, not the first
    /// plan step. Completed steps are deliberately not re-authorized on a
    /// restart. This convenience API has no custom authorizer hook; use
    /// [`Self::approve_resume_with_step_capability_leases`] when a host needs
    /// to attach one to a manually issued lease.
    pub fn approve_resume_with_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_for(plan)
            .map_err(WorkflowError::Checkpoint)?;
        let suffix = &plan.steps[checkpoint.completed_step_count()..];
        let leases = self.issue_step_capability_policy_leases(suffix, policies)?;
        self.approve_resume_with_step_capability_leases(plan, checkpoint, leases)
    }

    /// Approves a dataflow checkpoint suffix against its separately retained
    /// exact context.
    pub fn approve_dataflow_resume(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        data: WorkflowData,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_dataflow_for(plan, &data)
            .map_err(WorkflowError::Checkpoint)?;
        let lease = self
            .runtime
            .issue_full_capability_lease()
            .map_err(WorkflowError::CapabilityLease)?;
        self.approve_dataflow_resume_with_capability_lease(plan, checkpoint, data, lease)
    }

    /// Creates a dataflow checkpoint approval under an explicit attenuated
    /// lease. The approval retains the exact matching data context in memory.
    pub fn approve_dataflow_resume_with_capability_lease(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        data: WorkflowData,
        lease: CapabilityLease,
    ) -> Result<Approval, WorkflowError> {
        self.approve_dataflow_resume_with_workflow_capability_leases(
            plan,
            checkpoint,
            data,
            None,
            WorkflowCapabilityLeases::shared(lease),
        )
    }

    /// Creates a dataflow checkpoint approval with fresh authority only for
    /// the unexecuted suffix.
    pub fn approve_dataflow_resume_with_step_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        data: WorkflowData,
        leases: Vec<CapabilityLease>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_dataflow_for(plan, &data)
            .map_err(WorkflowError::Checkpoint)?;
        let expected = plan.steps.len() - checkpoint.completed_step_count();
        self.validate_step_capability_lease_count(expected, leases.len())?;
        self.approve_dataflow_resume_with_workflow_capability_leases(
            plan,
            checkpoint,
            data,
            None,
            WorkflowCapabilityLeases::per_step(leases),
        )
    }

    /// Creates a dataflow checkpoint approval using named policies for only
    /// the remaining trusted suffix.
    pub fn approve_dataflow_resume_with_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        data: WorkflowData,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_dataflow_for(plan, &data)
            .map_err(WorkflowError::Checkpoint)?;
        let suffix = &plan.steps[checkpoint.completed_step_count()..];
        let leases = self.issue_step_capability_policy_leases(suffix, policies)?;
        self.approve_dataflow_resume_with_step_capability_leases(plan, checkpoint, data, leases)
    }

    /// Approves a dataflow checkpoint suffix under a complete host-owned
    /// schema contract and the current catalog's full lease.
    ///
    /// The separately retained context, completed prefix, and contract are
    /// all validated before this convenience method issues a full lease.
    pub fn approve_dataflow_resume_with_contract(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        mut data: WorkflowData,
        data_contract: WorkflowDataContract,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        self.validate_dataflow_contract_checkpoint(plan, checkpoint, &data, &data_contract)?;
        data.bind_contract(&data_contract)
            .map_err(WorkflowError::Data)?;
        let lease = self
            .runtime
            .issue_full_capability_lease()
            .map_err(WorkflowError::CapabilityLease)?;
        self.approve_dataflow_resume_with_contract_and_capability_lease(
            plan,
            checkpoint,
            data,
            data_contract,
            lease,
        )
    }

    /// Approves a dataflow checkpoint suffix under a host-owned schema
    /// contract and one explicit attenuated lease.
    pub fn approve_dataflow_resume_with_contract_and_capability_lease(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        data: WorkflowData,
        data_contract: WorkflowDataContract,
        lease: CapabilityLease,
    ) -> Result<Approval, WorkflowError> {
        self.approve_dataflow_resume_with_workflow_capability_leases(
            plan,
            checkpoint,
            data,
            Some(data_contract),
            WorkflowCapabilityLeases::shared(lease),
        )
    }

    /// Approves a dataflow checkpoint suffix under a host-owned schema
    /// contract and one lease for every unexecuted trusted step.
    pub fn approve_dataflow_resume_with_contract_and_step_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        mut data: WorkflowData,
        data_contract: WorkflowDataContract,
        leases: Vec<CapabilityLease>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        self.validate_dataflow_contract_checkpoint(plan, checkpoint, &data, &data_contract)?;
        data.bind_contract(&data_contract)
            .map_err(WorkflowError::Data)?;
        let expected = plan.steps.len() - checkpoint.completed_step_count();
        self.validate_step_capability_lease_count(expected, leases.len())?;
        self.approve_dataflow_resume_with_workflow_capability_leases(
            plan,
            checkpoint,
            data,
            Some(data_contract),
            WorkflowCapabilityLeases::per_step(leases),
        )
    }

    /// Approves a dataflow checkpoint suffix under a host-owned schema
    /// contract and ordered named capability policies.
    ///
    /// The contract and retained prefix are checked before policy-derived
    /// leases are issued for the remaining steps.
    pub fn approve_dataflow_resume_with_contract_and_step_capability_policies(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        mut data: WorkflowData,
        data_contract: WorkflowDataContract,
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        self.validate_dataflow_contract_checkpoint(plan, checkpoint, &data, &data_contract)?;
        data.bind_contract(&data_contract)
            .map_err(WorkflowError::Data)?;
        let suffix = &plan.steps[checkpoint.completed_step_count()..];
        let leases = self.issue_step_capability_policy_leases(suffix, policies)?;
        self.approve_dataflow_resume_with_contract_and_step_capability_leases(
            plan,
            checkpoint,
            data,
            data_contract,
            leases,
        )
    }

    fn approve_dataflow_resume_with_workflow_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        mut data: WorkflowData,
        data_contract: Option<WorkflowDataContract>,
        leases: WorkflowCapabilityLeases,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        if let Some(data_contract) = &data_contract {
            self.validate_dataflow_contract_checkpoint(plan, checkpoint, &data, data_contract)?;
            data.bind_contract(data_contract)
                .map_err(WorkflowError::Data)?;
        } else {
            checkpoint
                .validate_dataflow_for(plan, &data)
                .map_err(WorkflowError::Checkpoint)?;
        }
        leases.validate(&self.runtime)?;
        let approval = self.issue_approval(
            plan,
            ApprovalKind::DataflowCheckpoint {
                checkpoint: checkpoint.clone(),
                data,
                data_contract,
                leases,
            },
        );
        self.record_event(WorkflowEvent::ResumeApproved {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        Ok(approval)
    }

    fn approve_resume_with_workflow_capability_leases(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        leases: WorkflowCapabilityLeases,
    ) -> Result<Approval, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        checkpoint
            .validate_for(plan)
            .map_err(WorkflowError::Checkpoint)?;
        leases.validate(&self.runtime)?;
        let approval = self.issue_approval(
            plan,
            ApprovalKind::Checkpoint {
                checkpoint: checkpoint.clone(),
                leases,
            },
        );
        self.record_event(WorkflowEvent::ResumeApproved {
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
        if self.suspended_execution.is_some() {
            return Err(WorkflowError::ExecutionInProgress);
        }
        if !self.approval_matches(plan, &approval) {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let ApprovalKind::Plan(leases) = approval.kind else {
            return Err(WorkflowError::ApprovalMismatch);
        };
        leases.validate(&self.runtime)?;

        self.last_dataflow = None;
        self.record_event(WorkflowEvent::Started { plan_id: plan.id });
        self.execute_from(plan, 0, leases)
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
        if self.suspended_execution.is_some() {
            return Err(WorkflowError::ExecutionInProgress);
        }
        checkpoint
            .validate_for(plan)
            .map_err(WorkflowError::Checkpoint)?;
        if !self.approval_matches(plan, &approval) {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let ApprovalKind::Checkpoint {
            checkpoint: bound_checkpoint,
            leases,
        } = approval.kind
        else {
            return Err(WorkflowError::ApprovalMismatch);
        };
        if bound_checkpoint != *checkpoint {
            return Err(WorkflowError::ApprovalMismatch);
        }
        leases.validate(&self.runtime)?;

        self.last_dataflow = None;
        self.record_event(WorkflowEvent::Resumed {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        self.execute_from(plan, checkpoint.completed_step_count(), leases)
    }

    /// Executes an approval-bound bounded dataflow context.
    ///
    /// Every step receives the host-provided `workflow` JSON global with the
    /// same `input` and only completed trusted-prefix values in `outputs`.
    /// The global is cleared after each terminal step. A suspended external
    /// continuation retains the exact data context until it completes.
    pub fn execute_dataflow(
        &mut self,
        plan: &WorkflowPlan,
        approval: Approval,
    ) -> Result<WorkflowData, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        if self.suspended_execution.is_some() {
            return Err(WorkflowError::ExecutionInProgress);
        }
        if !self.approval_matches(plan, &approval) {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let ApprovalKind::Dataflow {
            data,
            data_contract,
            leases,
        } = approval.kind
        else {
            return Err(WorkflowError::ApprovalMismatch);
        };
        data.validate_for_completed_prefix(plan, 0)
            .map_err(WorkflowError::Data)?;
        if let Some(data_contract) = &data_contract {
            data_contract
                .validate_for(plan, &data, 0)
                .map_err(WorkflowError::DataContract)?;
        }
        leases.validate(&self.runtime)?;

        self.last_dataflow = None;
        self.record_event(WorkflowEvent::Started { plan_id: plan.id });
        self.execute_dataflow_from(
            plan,
            0,
            leases,
            DataflowExecutionState {
                data,
                data_contract,
            },
        )?;
        self.last_dataflow
            .clone()
            .ok_or(WorkflowError::ApprovalMismatch)
    }

    /// Executes a dataflow checkpoint suffix after fresh approval bound to the
    /// exact separately retained context.
    pub fn resume_dataflow(
        &mut self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        approval: Approval,
    ) -> Result<WorkflowData, WorkflowError> {
        if !self.owns_plan(plan) {
            return Err(WorkflowError::PlanOwnershipMismatch);
        }
        if self.suspended_execution.is_some() {
            return Err(WorkflowError::ExecutionInProgress);
        }
        if !self.approval_matches(plan, &approval) {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let ApprovalKind::DataflowCheckpoint {
            checkpoint: bound_checkpoint,
            data,
            data_contract,
            leases,
        } = approval.kind
        else {
            return Err(WorkflowError::ApprovalMismatch);
        };
        if bound_checkpoint != *checkpoint {
            return Err(WorkflowError::ApprovalMismatch);
        }
        if let Some(data_contract) = &data_contract {
            self.validate_dataflow_contract_checkpoint(plan, checkpoint, &data, data_contract)?;
        } else {
            checkpoint
                .validate_dataflow_for(plan, &data)
                .map_err(WorkflowError::Checkpoint)?;
        }
        leases.validate(&self.runtime)?;

        self.last_dataflow = None;
        self.record_event(WorkflowEvent::Resumed {
            plan_id: plan.id,
            completed_steps: checkpoint.completed_step_count(),
        });
        self.execute_dataflow_from(
            plan,
            checkpoint.completed_step_count(),
            leases,
            DataflowExecutionState {
                data,
                data_contract,
            },
        )?;
        self.last_dataflow
            .clone()
            .ok_or(WorkflowError::ApprovalMismatch)
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

    fn suspended_step_for_plan(
        &self,
        plan: &WorkflowPlan,
    ) -> Result<(usize, String), WorkflowError> {
        let execution = self
            .suspended_execution
            .as_ref()
            .ok_or(WorkflowError::NoSuspendedExecution)?;
        if execution.plan.id != plan.id || execution.plan.fingerprint != plan.fingerprint {
            return Err(WorkflowError::ApprovalMismatch);
        }
        let step = plan
            .steps
            .get(execution.step_index)
            .ok_or(WorkflowError::ApprovalMismatch)?;
        Ok((execution.step_index, step.id.clone()))
    }

    fn validate_external_operation_binding(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        step_id: &str,
        tool: &str,
        operation_key: &str,
        canonical_input: &[u8],
    ) -> Result<(), WorkflowError> {
        self.validate_operation_ledger(plan, ledger)?;
        let operation = ledger.operation(operation_key).ok_or_else(|| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::UnknownOperation(
                operation_key.to_owned(),
            ))
        })?;
        if operation.step_id != step_id || operation.tool != tool {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationBindingMismatch(operation_key.to_owned()),
            ));
        }
        operation
            .verify_input(canonical_input)
            .map_err(WorkflowError::OperationLedger)
    }

    fn validate_claimed_external_operation(
        &self,
        plan: &WorkflowPlan,
        ledger: &WorkflowOperationLedger,
        claimed: &ClaimedWorkflowExternalOperation,
    ) -> Result<(), WorkflowError> {
        if claimed.engine_id != self.engine_id || claimed.plan_id != plan.id {
            return Err(WorkflowError::ApprovalMismatch);
        }
        self.runtime
            .validate_claimed_external_tool(claimed.invocation.id)
            .map_err(WorkflowError::ExternalTool)?;
        let (step_index, step_id) = self.suspended_step_for_plan(plan)?;
        if claimed.step_id != step_id || claimed.completed_steps != step_index {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationBindingMismatch(
                    claimed.operation_key.clone(),
                ),
            ));
        }
        let payload = claimed
            .invocation
            .worker_payload()
            .map_err(WorkflowError::ExternalTool)?;
        let canonical_input = canonical_operation_input_bytes(&payload).map_err(|error| {
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::Protocol(error))
        })?;
        if payload != claimed.payload || canonical_input != claimed.canonical_input {
            return Err(WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::OperationBindingMismatch(
                    claimed.operation_key.clone(),
                ),
            ));
        }
        self.validate_external_operation_binding(
            plan,
            ledger,
            &claimed.step_id,
            &claimed.invocation.name,
            &claimed.operation_key,
            &canonical_input,
        )
    }

    fn validate_step_capability_lease_count(
        &self,
        expected: usize,
        actual: usize,
    ) -> Result<(), WorkflowError> {
        if expected != actual {
            return Err(WorkflowError::StepCapabilityLeaseCount { expected, actual });
        }
        Ok(())
    }

    fn validate_dataflow_contract(
        &self,
        plan: &WorkflowPlan,
        data: &WorkflowData,
        completed_step_count: usize,
        data_contract: &WorkflowDataContract,
    ) -> Result<(), WorkflowError> {
        data.validate_for_completed_prefix(plan, completed_step_count)
            .map_err(WorkflowError::Data)?;
        data_contract
            .validate_for(plan, data, completed_step_count)
            .map_err(WorkflowError::DataContract)
    }

    fn validate_dataflow_contract_checkpoint(
        &self,
        plan: &WorkflowPlan,
        checkpoint: &WorkflowCheckpoint,
        data: &WorkflowData,
        data_contract: &WorkflowDataContract,
    ) -> Result<(), WorkflowError> {
        checkpoint
            .validate_dataflow_contract_for(plan, data, data_contract)
            .map_err(WorkflowError::Checkpoint)?;
        self.validate_dataflow_contract(
            plan,
            data,
            checkpoint.completed_step_count(),
            data_contract,
        )
    }

    fn issue_step_capability_policy_leases(
        &self,
        steps: &[WorkflowStep],
        policies: Vec<WorkflowStepCapabilityPolicy>,
    ) -> Result<Vec<CapabilityLease>, WorkflowError> {
        self.validate_step_capability_policy_bindings(steps, &policies)?;
        policies
            .into_iter()
            .map(|policy| {
                self.runtime
                    .issue_capability_lease(policy.grants)
                    .map_err(WorkflowError::CapabilityLease)
            })
            .collect()
    }

    fn validate_step_capability_policy_bindings(
        &self,
        steps: &[WorkflowStep],
        policies: &[WorkflowStepCapabilityPolicy],
    ) -> Result<(), WorkflowError> {
        if steps.len() != policies.len() {
            return Err(WorkflowError::StepCapabilityPolicyCount {
                expected: steps.len(),
                actual: policies.len(),
            });
        }
        for (step, policy) in steps.iter().zip(policies) {
            if step.id != policy.step_id {
                return Err(WorkflowError::StepCapabilityPolicyMismatch {
                    expected: step.id.clone(),
                    actual: policy.step_id.clone(),
                });
            }
        }
        Ok(())
    }

    fn execute_from(
        &mut self,
        plan: &WorkflowPlan,
        completed_step_count: usize,
        mut leases: WorkflowCapabilityLeases,
    ) -> Result<(), WorkflowError> {
        for (step_index, step) in plan.steps.iter().enumerate().skip(completed_step_count) {
            let Some(lease) = leases.take_for_step() else {
                return Err(WorkflowError::ApprovalMismatch);
            };
            let report = match self
                .runtime
                .eval_with_capability_lease(&step.source, &lease)
            {
                Ok(report) => report,
                Err(CapabilityLeaseEvaluationError::Runtime(RuntimeError::SyntaxRejected(
                    report,
                ))) => {
                    self.record_event(WorkflowEvent::StepRejected {
                        plan_id: plan.id,
                        step_id: step.id.clone(),
                        diagnostic_count: report.diagnostics.len(),
                        diagnostics_truncated: report.diagnostics_truncated,
                        completed_steps: step_index,
                    });
                    return Err(WorkflowError::StepRejected {
                        step_id: step.id.clone(),
                        report,
                        completed_steps: step_index,
                    });
                }
                Err(CapabilityLeaseEvaluationError::Runtime(error)) => {
                    return Err(WorkflowError::Runtime(error));
                }
                Err(CapabilityLeaseEvaluationError::Lease(error)) => {
                    return Err(WorkflowError::CapabilityLease(error));
                }
            };
            leases = self.drive_step(plan, step_index, report, lease, leases)?;
        }
        self.record_event(WorkflowEvent::Completed { plan_id: plan.id });
        Ok(())
    }

    fn execute_dataflow_from(
        &mut self,
        plan: &WorkflowPlan,
        completed_step_count: usize,
        mut leases: WorkflowCapabilityLeases,
        mut dataflow: DataflowExecutionState,
    ) -> Result<(), WorkflowError> {
        for (step_index, step) in plan.steps.iter().enumerate().skip(completed_step_count) {
            let Some(lease) = leases.take_for_step() else {
                self.last_dataflow = Some(dataflow.data);
                return Err(WorkflowError::ApprovalMismatch);
            };
            let context = dataflow.data.script_context();
            if let Err(error) = self.runtime.set_json_global(
                WORKFLOW_DATA_GLOBAL,
                &context,
                MAX_WORKFLOW_DATA_BYTES,
                MAX_WORKFLOW_DATA_DEPTH,
            ) {
                self.last_dataflow = Some(dataflow.data);
                return Err(WorkflowError::Runtime(error));
            }

            let report = match self
                .runtime
                .eval_with_capability_lease(&step.source, &lease)
            {
                Ok(report) => report,
                Err(CapabilityLeaseEvaluationError::Runtime(RuntimeError::SyntaxRejected(
                    report,
                ))) => {
                    self.record_event(WorkflowEvent::StepRejected {
                        plan_id: plan.id,
                        step_id: step.id.clone(),
                        diagnostic_count: report.diagnostics.len(),
                        diagnostics_truncated: report.diagnostics_truncated,
                        completed_steps: step_index,
                    });
                    self.last_dataflow = Some(dataflow.data);
                    self.clear_dataflow_context()?;
                    return Err(WorkflowError::StepRejected {
                        step_id: step.id.clone(),
                        report,
                        completed_steps: step_index,
                    });
                }
                Err(CapabilityLeaseEvaluationError::Runtime(error)) => {
                    self.last_dataflow = Some(dataflow.data);
                    self.clear_dataflow_context()?;
                    return Err(WorkflowError::Runtime(error));
                }
                Err(CapabilityLeaseEvaluationError::Lease(error)) => {
                    self.last_dataflow = Some(dataflow.data);
                    self.clear_dataflow_context()?;
                    return Err(WorkflowError::CapabilityLease(error));
                }
            };

            match self.drive_dataflow_step(plan, step_index, report, lease, leases, &mut dataflow) {
                Ok(next_leases) => leases = next_leases,
                Err(error) => {
                    if self.suspended_execution.is_none() {
                        self.last_dataflow = Some(dataflow.data);
                    }
                    return Err(error);
                }
            }
        }
        self.last_dataflow = Some(dataflow.data);
        self.record_event(WorkflowEvent::Completed { plan_id: plan.id });
        Ok(())
    }

    fn drive_dataflow_step(
        &mut self,
        plan: &WorkflowPlan,
        step_index: usize,
        mut report: Evaluation,
        lease: CapabilityLease,
        mut leases: WorkflowCapabilityLeases,
        dataflow: &mut DataflowExecutionState,
    ) -> Result<WorkflowCapabilityLeases, WorkflowError> {
        let step = &plan.steps[step_index];
        while report.succeeded() && report.suspended {
            let pumped = self.runtime.pump()?;
            if let Some(resumed) = pumped.resumed.into_iter().last() {
                report = resumed;
                continue;
            }
            if pumped.completed != 0 {
                continue;
            }

            self.suspended_execution = Some(SuspendedWorkflowExecution {
                plan: plan.clone(),
                step_index,
                lease,
                leases,
                dataflow: Some(DataflowExecutionState {
                    data: dataflow.data.clone(),
                    data_contract: dataflow.data_contract.clone(),
                }),
            });
            self.record_event(WorkflowEvent::StepSuspended {
                plan_id: plan.id,
                step_id: step.id.clone(),
                completed_steps: step_index,
            });
            return Err(WorkflowError::StepSuspended {
                step_id: step.id.clone(),
                completed_steps: step_index,
            });
        }

        if !report.succeeded() {
            self.cancel_unawaited_external_work()?;
            self.drain_unawaited_local_work()?;
            self.clear_dataflow_context()?;
            self.record_event(WorkflowEvent::StepFailed {
                plan_id: plan.id,
                step_id: step.id.clone(),
                diagnostic_count: report.diagnostics.len(),
                completed_steps: step_index,
            });
            return Err(WorkflowError::StepFailed {
                step_id: step.id.clone(),
                diagnostics: report.diagnostics,
                completed_steps: step_index,
            });
        }

        self.cancel_unawaited_external_work()?;
        self.drain_unawaited_local_work()?;
        let output = self.runtime.script_value_as_json(
            report.value,
            MAX_WORKFLOW_DATA_BYTES,
            MAX_WORKFLOW_DATA_DEPTH,
        );
        self.clear_dataflow_context()?;
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                self.record_event(WorkflowEvent::StepFailed {
                    plan_id: plan.id,
                    step_id: step.id.clone(),
                    diagnostic_count: 1,
                    completed_steps: step_index,
                });
                return Err(WorkflowError::Runtime(error));
            }
        };
        if let Some(data_contract) = &dataflow.data_contract {
            if let Err(error) = data_contract.validate_step_output(step, step_index, &output) {
                self.record_event(WorkflowEvent::StepFailed {
                    plan_id: plan.id,
                    step_id: step.id.clone(),
                    diagnostic_count: 1,
                    completed_steps: step_index,
                });
                return Err(WorkflowError::DataflowContractOutput {
                    step_id: step.id.clone(),
                    error,
                    completed_steps: step_index,
                });
            }
        }
        if let Err(error) = dataflow.data.insert_output(&step.id, output) {
            self.record_event(WorkflowEvent::StepFailed {
                plan_id: plan.id,
                step_id: step.id.clone(),
                diagnostic_count: 1,
                completed_steps: step_index,
            });
            return Err(WorkflowError::DataflowOutput {
                step_id: step.id.clone(),
                error,
                completed_steps: step_index,
            });
        }

        self.record_event(WorkflowEvent::StepSucceeded {
            plan_id: plan.id,
            step_id: step.id.clone(),
        });
        leases.complete_step(lease)?;
        Ok(leases)
    }

    fn drive_step(
        &mut self,
        plan: &WorkflowPlan,
        step_index: usize,
        mut report: Evaluation,
        lease: CapabilityLease,
        mut leases: WorkflowCapabilityLeases,
    ) -> Result<WorkflowCapabilityLeases, WorkflowError> {
        let step = &plan.steps[step_index];
        while report.succeeded() && report.suspended {
            let pumped = self.runtime.pump()?;
            if let Some(resumed) = pumped.resumed.into_iter().last() {
                report = resumed;
                continue;
            }
            if pumped.completed != 0 {
                continue;
            }

            self.suspended_execution = Some(SuspendedWorkflowExecution {
                plan: plan.clone(),
                step_index,
                lease,
                leases,
                dataflow: None,
            });
            self.record_event(WorkflowEvent::StepSuspended {
                plan_id: plan.id,
                step_id: step.id.clone(),
                completed_steps: step_index,
            });
            return Err(WorkflowError::StepSuspended {
                step_id: step.id.clone(),
                completed_steps: step_index,
            });
        }
        if !report.succeeded() {
            self.cancel_unawaited_external_work()?;
            self.drain_unawaited_local_work()?;
            self.runtime.collect_garbage();
            self.record_event(WorkflowEvent::StepFailed {
                plan_id: plan.id,
                step_id: step.id.clone(),
                diagnostic_count: report.diagnostics.len(),
                completed_steps: step_index,
            });
            return Err(WorkflowError::StepFailed {
                step_id: step.id.clone(),
                diagnostics: report.diagnostics,
                completed_steps: step_index,
            });
        }
        self.cancel_unawaited_external_work()?;
        self.drain_unawaited_local_work()?;
        self.runtime.collect_garbage();
        self.record_event(WorkflowEvent::StepSucceeded {
            plan_id: plan.id,
            step_id: step.id.clone(),
        });
        leases.complete_step(lease)?;
        Ok(leases)
    }

    fn drain_unawaited_local_work(&mut self) -> Result<(), WorkflowError> {
        let max_pending = self.runtime.max_pending_tools();
        let _ = self.runtime.pump_up_to(max_pending)?;
        Ok(())
    }

    fn cancel_unawaited_external_work(&mut self) -> Result<(), WorkflowError> {
        while let Some(invocation) = self.runtime.claim_next_external_tool() {
            let resumed = self
                .runtime
                .cancel_external_tool(invocation.id)
                .map_err(WorkflowError::ExternalTool)?;
            debug_assert!(resumed.is_none());
        }
        Ok(())
    }

    fn clear_dataflow_context(&mut self) -> Result<(), WorkflowError> {
        self.runtime
            .clear_json_global(WORKFLOW_DATA_GLOBAL)
            .map_err(WorkflowError::Runtime)?;
        self.runtime.collect_garbage();
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

fn derived_workflow_compensation_key(
    plan_fingerprint: &str,
    operation_key: &str,
    tool: &str,
    tenant_scope: &str,
    grant_fingerprint: &str,
    input: &[u8],
    compensation_nonce: &[u8],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"splash-workflow-compensation-key-v1");
    update_plan_fingerprint_component(&mut hasher, plan_fingerprint.as_bytes());
    update_plan_fingerprint_component(&mut hasher, operation_key.as_bytes());
    update_plan_fingerprint_component(&mut hasher, tool.as_bytes());
    update_plan_fingerprint_component(&mut hasher, tenant_scope.as_bytes());
    update_plan_fingerprint_component(&mut hasher, grant_fingerprint.as_bytes());
    update_plan_fingerprint_component(&mut hasher, input);
    update_plan_fingerprint_component(&mut hasher, compensation_nonce);
    format!("cmp-{}", hasher.finalize().to_hex())
}

fn is_valid_operation_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_valid_compensation_key(value: &str) -> bool {
    value.starts_with("cmp-") && is_valid_operation_token(value)
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
    if steps.len() > MAX_WORKFLOW_STEPS {
        return Err(WorkflowError::TooManySteps {
            maximum: MAX_WORKFLOW_STEPS,
        });
    }

    let source_bytes = steps.iter().fold(0usize, |total, step| {
        total.saturating_add(step.source.len())
    });
    if source_bytes > MAX_WORKFLOW_PLAN_SOURCE_BYTES {
        return Err(WorkflowError::PlanSourceTooLarge {
            actual: source_bytes,
            maximum: MAX_WORKFLOW_PLAN_SOURCE_BYTES,
        });
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

fn review_workflow_steps(
    steps: &[WorkflowStep],
    limits: ExecutionLimits,
) -> Result<Vec<WorkflowStepReview>, WorkflowError> {
    let limits = limits.validate()?;
    let mut review = Vec::with_capacity(steps.len());
    let mut retained_tool_calls = 0_usize;
    for step in steps {
        let file = format!("workflow-step-{}.splash", step.id);
        let syntax = check_syntax_named(&file, &step.source, limits)?;
        let (mut tool_calls, mut tool_calls_truncated) = if syntax.valid {
            let report = tool_call_hint_report_named(&file, &step.source, limits)?;
            (report.hints, report.truncated)
        } else {
            (Vec::new(), false)
        };
        let remaining = MAX_WORKFLOW_REVIEW_TOOL_CALL_HINTS.saturating_sub(retained_tool_calls);
        if tool_calls.len() > remaining {
            tool_calls.truncate(remaining);
            tool_calls_truncated = true;
        }
        retained_tool_calls = retained_tool_calls.saturating_add(tool_calls.len());
        review.push(WorkflowStepReview {
            step_id: step.id.clone(),
            syntax,
            tool_calls,
            tool_calls_truncated,
        });
    }
    Ok(review)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowDraftWire {
    format_version: u8,
    steps: BoundedWorkflowDraftSteps,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowDraftWireStep {
    id: String,
    source: String,
}

struct BoundedWorkflowDraftSteps {
    steps: Vec<WorkflowDraftWireStep>,
    too_many: bool,
}

impl<'de> Deserialize<'de> for BoundedWorkflowDraftSteps {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedWorkflowDraftStepsVisitor)
    }
}

struct BoundedWorkflowDraftStepsVisitor;

impl<'de> Visitor<'de> for BoundedWorkflowDraftStepsVisitor {
    type Value = BoundedWorkflowDraftSteps;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a workflow draft step array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut steps = Vec::new();
        while steps.len() < MAX_WORKFLOW_STEPS {
            let Some(step) = sequence.next_element::<WorkflowDraftWireStep>()? else {
                return Ok(BoundedWorkflowDraftSteps {
                    steps,
                    too_many: false,
                });
            };
            steps.push(step);
        }

        let mut too_many = false;
        while sequence.next_element::<de::IgnoredAny>()?.is_some() {
            too_many = true;
        }
        Ok(BoundedWorkflowDraftSteps { steps, too_many })
    }
}

#[derive(Serialize)]
struct WorkflowDraftDocumentRef<'a> {
    format_version: u8,
    steps: Vec<WorkflowDraftStepRef<'a>>,
}

#[derive(Serialize)]
struct WorkflowDraftStepRef<'a> {
    id: &'a str,
    source: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use splash_capabilities::{CapabilityLeaseError, CapabilityLeaseGrant, ToolPolicy};
    use splash_protocol::{canonical_operation_input_bytes, SessionKey, AUTH_TAG_BYTES};
    use splash_schema::JsonSchema;
    use splash_storage::{
        AuthenticatedStore, StorageKey, StorageKeyId, StorageKeyring, StorageRecordKey,
        VolatileMemoryStore, STORAGE_KEY_BYTES,
    };

    fn compiled_schema(source: JsonValue) -> JsonSchema {
        JsonSchema::compile(source).expect("test schema is valid")
    }

    fn workflow_data_contract(
        input_schema: JsonValue,
        output_schemas: Vec<(&str, JsonValue)>,
    ) -> WorkflowDataContract {
        WorkflowDataContract::new(
            compiled_schema(input_schema),
            output_schemas.into_iter().map(|(step_id, schema)| {
                WorkflowStepOutputContract::new(step_id, compiled_schema(schema))
            }),
        )
        .expect("test data contract is within bounds")
    }

    fn operation_reconciliation_authenticators() -> (SessionAuthenticator, SessionAuthenticator) {
        let key = SessionKey::from_bytes([13; AUTH_TAG_BYTES]).unwrap();
        (
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap(),
            SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap(),
        )
    }

    struct AllowCompensationGrantVerifier;

    impl CompensationGrantVerifier for AllowCompensationGrantVerifier {
        fn verify_compensation_grant(
            &self,
            _tenant_scope: &str,
            _grant: &CapabilityGrant,
        ) -> Result<(), WorkflowOperationLedgerError> {
            Ok(())
        }
    }

    struct DenyCompensationGrantVerifier;

    impl CompensationGrantVerifier for DenyCompensationGrantVerifier {
        fn verify_compensation_grant(
            &self,
            tenant_scope: &str,
            grant: &CapabilityGrant,
        ) -> Result<(), WorkflowOperationLedgerError> {
            Err(WorkflowOperationLedgerError::CompensationGrantDenied {
                tool: grant.tool.clone(),
                tenant_scope: tenant_scope.to_owned(),
            })
        }
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
    fn plan_review_is_effect_free_and_distinguishes_invalid_source_from_pure_source() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), move |request| {
                calls.set(calls.get() + 1);
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "literal",
                    "use mod.tool\ntool.call(\"text.echo\", \"review only\")",
                ),
                WorkflowStep::new(
                    "dynamic",
                    "use mod.tool\nlet selected = \"shell.exec\"\ntool.start(selected, \"review only\")",
                ),
                WorkflowStep::new("invalid", "var legacy = true"),
            ])
            .unwrap();

        let review = plan.review().unwrap();

        assert_eq!(observed_calls.get(), 0);
        assert!(engine.runtime().audit().is_empty());
        assert_eq!(review.len(), 3);
        assert_eq!(review[0].step_id, "literal");
        assert!(review[0].syntax.valid);
        assert_eq!(review[0].tool_calls.len(), 1);
        assert!(!review[0].tool_calls_truncated);
        assert_eq!(
            review[0].tool_calls[0].kind,
            splash_core::ToolCallKind::Call
        );
        assert_eq!(
            review[0].tool_calls[0].literal_name.as_deref(),
            Some("text.echo")
        );
        assert_eq!(review[1].step_id, "dynamic");
        assert!(review[1].syntax.valid);
        assert_eq!(review[1].tool_calls.len(), 1);
        assert!(!review[1].tool_calls_truncated);
        assert_eq!(
            review[1].tool_calls[0].kind,
            splash_core::ToolCallKind::Start
        );
        assert!(review[1].tool_calls[0].literal_name.is_none());
        assert_eq!(review[2].step_id, "invalid");
        assert!(!review[2].syntax.valid);
        assert!(review[2].tool_calls.is_empty());
        assert!(!review[2].tool_calls_truncated);
        assert!(!engine
            .events()
            .iter()
            .any(|event| matches!(event, WorkflowEvent::Approved { .. })));
    }

    #[test]
    fn workflow_review_bounds_aggregate_tool_call_hints() {
        let mut source = String::from("use mod.tool\n");
        for index in 0..splash_core::MAX_TOOL_CALL_HINTS {
            source.push_str(&format!("tool.call(\"tool.{index}\", \"\")\n"));
        }
        let steps = (0..5)
            .map(|index| WorkflowStep::new(format!("step-{index}"), source.clone()))
            .collect();
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine.plan(steps).unwrap();

        let review = plan.review().unwrap();

        assert_eq!(review.len(), 5);
        for step in &review[..4] {
            assert_eq!(
                step.tool_calls.len(),
                splash_core::MAX_TOOL_CALL_HINTS,
                "{}",
                step.step_id
            );
            assert!(!step.tool_calls_truncated, "{}", step.step_id);
        }
        assert!(review[4].tool_calls.is_empty());
        assert!(review[4].tool_calls_truncated);
        assert_eq!(
            review
                .iter()
                .map(|step| step.tool_calls.len())
                .sum::<usize>(),
            MAX_WORKFLOW_REVIEW_TOOL_CALL_HINTS
        );
    }

    #[test]
    fn workflow_draft_round_trips_and_reviews_without_authority() {
        let draft = WorkflowDraft::new(vec![
            WorkflowStep::new(
                "prepare",
                "use mod.tool\ntool.call(\"text.echo\", \"review only\")",
            ),
            WorkflowStep::new("invalid", "var legacy = true"),
        ])
        .unwrap();

        let encoded = draft.to_json().unwrap();
        let decoded = WorkflowDraft::from_json(&encoded).unwrap();
        let document: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        let review = decoded.review().unwrap();

        assert_eq!(decoded, draft);
        assert_eq!(document["format_version"], WORKFLOW_DRAFT_FORMAT_VERSION);
        assert_eq!(document["steps"].as_array().unwrap().len(), 2);
        assert!(!encoded.contains("approval"));
        assert!(!encoded.contains("checkpoint"));
        assert!(!encoded.contains("grant"));
        assert_eq!(review.len(), 2);
        assert!(review[0].syntax.valid);
        assert_eq!(review[0].tool_calls.len(), 1);
        assert!(!review[0].tool_calls_truncated);
        assert_eq!(
            review[0].tool_calls[0].literal_name.as_deref(),
            Some("text.echo")
        );
        assert!(!review[1].syntax.valid);
        assert!(review[1].tool_calls.is_empty());
        assert!(!review[1].tool_calls_truncated);

        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine.plan_draft(decoded).unwrap();
        assert_eq!(plan.steps(), draft.steps());
        assert!(engine.runtime().audit().is_empty());
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Planned {
                plan_id,
                step_count: 2,
            }) if *plan_id == plan.id()
        ));
        assert!(!engine.events().iter().any(|event| matches!(
            event,
            WorkflowEvent::Approved { .. } | WorkflowEvent::ResumeApproved { .. }
        )));
    }

    #[test]
    fn workflow_draft_rejects_oversized_or_untrusted_wire_data() {
        let malformed = "{not-json}";
        assert_eq!(
            WorkflowDraft::from_json_with_max_bytes(malformed, 4).unwrap_err(),
            WorkflowDraftError::InputTooLarge {
                actual: malformed.len(),
                maximum: 4,
            }
        );
        assert_eq!(
            WorkflowDraft::from_json(
                r#"{"format_version":1,"steps":[{"id":"prepare","source":"let done = true","grant":"shell.exec"}]}"#,
            )
            .unwrap_err(),
            WorkflowDraftError::InvalidEncoding
        );
        assert_eq!(
            WorkflowDraft::from_json(r#"{"format_version":2,"steps":[]}"#).unwrap_err(),
            WorkflowDraftError::UnsupportedFormatVersion {
                actual: 2,
                expected: WORKFLOW_DRAFT_FORMAT_VERSION,
            }
        );
        assert_eq!(
            WorkflowDraft::from_json(
                r#"{"format_version":1,"steps":[{"id":"Not-Trusted","source":"let done = true"}]}"#,
            )
            .unwrap_err(),
            WorkflowDraftError::InvalidPlan(WorkflowError::InvalidStepId("Not-Trusted".to_owned()))
        );

        let steps = (0..=MAX_WORKFLOW_STEPS)
            .map(|index| {
                serde_json::json!({
                    "id": format!("step-{index}"),
                    "source": "let done = true",
                })
            })
            .collect::<Vec<_>>();
        let too_many = serde_json::json!({
            "format_version": WORKFLOW_DRAFT_FORMAT_VERSION,
            "steps": steps,
        })
        .to_string();
        assert_eq!(
            WorkflowDraft::from_json(&too_many).unwrap_err(),
            WorkflowDraftError::InvalidPlan(WorkflowError::TooManySteps {
                maximum: MAX_WORKFLOW_STEPS,
            })
        );
        assert_eq!(
            WorkflowDraft::new(Vec::new()).unwrap_err(),
            WorkflowDraftError::InvalidPlan(WorkflowError::EmptyPlan)
        );
    }

    #[test]
    fn untrusted_workflow_error_text_is_escaped_and_bounded() {
        let invalid = format!("\u{001b}[2J{}", "x".repeat(512));
        let encoded = serde_json::json!({
            "format_version": WORKFLOW_DRAFT_FORMAT_VERSION,
            "steps": [{"id": invalid.clone(), "source": "let done = true"}],
        })
        .to_string();
        let message = WorkflowDraft::from_json(&encoded).unwrap_err().to_string();

        assert!(message.contains("\\x1b[2J"), "{message}");
        assert!(message.contains("preview truncated"), "{message}");
        assert!(!message.contains('\u{001b}'));
        assert!(message.len() < 512, "unexpectedly large error: {message}");

        for message in [
            WorkflowCheckpointError::InvalidStepId(invalid.clone()).to_string(),
            WorkflowOperationLedgerError::InvalidTool(invalid.clone()).to_string(),
            WorkflowError::StepCapabilityPolicyMismatch {
                expected: invalid.clone(),
                actual: invalid.clone(),
            }
            .to_string(),
        ] {
            assert!(message.contains("\\x1b[2J"), "{message}");
            assert!(!message.contains('\u{001b}'));
            assert!(message.len() < 768, "unexpectedly large error: {message}");
        }
    }

    #[test]
    fn workflow_plan_rejects_excess_steps_and_aggregate_source() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let too_many_steps = (0..=MAX_WORKFLOW_STEPS)
            .map(|index| WorkflowStep::new(format!("step-{index}"), "let done = true"))
            .collect();

        assert_eq!(
            engine.plan(too_many_steps).unwrap_err(),
            WorkflowError::TooManySteps {
                maximum: MAX_WORKFLOW_STEPS,
            }
        );

        let source = "x".repeat(MAX_WORKFLOW_PLAN_SOURCE_BYTES + 1);
        assert_eq!(
            engine
                .plan(vec![WorkflowStep::new("oversized", source)])
                .unwrap_err(),
            WorkflowError::PlanSourceTooLarge {
                actual: MAX_WORKFLOW_PLAN_SOURCE_BYTES + 1,
                maximum: MAX_WORKFLOW_PLAN_SOURCE_BYTES,
            }
        );
    }

    #[test]
    fn bounded_event_view_evicts_oldest_entries_and_reports_loss() {
        let mut engine = WorkflowEngine::with_event_history_capacity(
            CapabilityRuntime::default(),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();

        for suffix in ["one", "two", "three"] {
            engine
                .plan(vec![WorkflowStep::new(
                    format!("step-{suffix}"),
                    "let completed = true",
                )])
                .unwrap();
        }

        assert_eq!(engine.max_events(), 2);
        assert_eq!(engine.events().len(), 2);
        assert_eq!(engine.dropped_events(), 1);
        assert!(matches!(
            engine.events()[0],
            WorkflowEvent::Planned { plan_id: 2, .. }
        ));
        assert!(matches!(
            engine.events()[1],
            WorkflowEvent::Planned { plan_id: 3, .. }
        ));

        engine.clear_events();
        assert!(engine.events().is_empty());
        assert_eq!(engine.dropped_events(), 0);

        let error = match WorkflowEngine::with_event_history_capacity(
            CapabilityRuntime::default(),
            NonZeroUsize::new(MAX_WORKFLOW_EVENTS + 1).unwrap(),
        ) {
            Ok(_) => panic!("an event capacity over the hard limit must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            WorkflowEventHistoryError::CapacityTooLarge {
                requested: MAX_WORKFLOW_EVENTS + 1,
                maximum: MAX_WORKFLOW_EVENTS,
            }
        );
    }

    #[test]
    fn event_export_uses_contiguous_cursors_and_rejects_evicted_history() {
        let mut engine = WorkflowEngine::with_event_history_capacity(
            CapabilityRuntime::default(),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        for suffix in ["one", "two", "three"] {
            engine
                .plan(vec![WorkflowStep::new(
                    format!("step-{suffix}"),
                    "let completed = true",
                )])
                .unwrap();
        }

        assert_eq!(
            engine.events_since(1).unwrap_err(),
            WorkflowEventCursorError::Evicted {
                requested: 1,
                earliest_available: 2,
            }
        );
        let batch = engine.events_since(2).unwrap();
        assert_eq!(batch.first_sequence(), 2);
        assert_eq!(batch.next_sequence(), 4);
        assert_eq!(
            batch
                .records()
                .iter()
                .map(WorkflowEventRecord::sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(matches!(
            batch.records()[0].event(),
            WorkflowEvent::Planned { plan_id: 2, .. }
        ));
        assert!(engine.events_since(4).unwrap().is_empty());

        engine.clear_events();
        assert!(engine.events_since(4).unwrap().is_empty());
        engine
            .plan(vec![WorkflowStep::new("step-four", "let completed = true")])
            .unwrap();
        let resumed = engine.events_since(4).unwrap();
        assert_eq!(resumed.records()[0].sequence(), 4);
        assert_eq!(resumed.next_sequence(), 5);
    }

    #[test]
    fn approval_fails_closed_when_the_catalog_changes_before_execution() {
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
        engine
            .runtime_mut()
            .register_tool(ToolPolicy::new("text.other"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();

        assert_eq!(
            engine.execute(&plan, approval).unwrap_err(),
            WorkflowError::CapabilityLease(CapabilityLeaseError::CatalogChanged)
        );
        assert!(engine.runtime().audit().is_empty());
        assert!(!engine
            .events()
            .iter()
            .any(|event| matches!(event, WorkflowEvent::Started { .. })));
    }

    #[test]
    fn explicit_workflow_lease_rejects_a_dynamically_selected_catalog_tool() {
        let shell_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_shell_calls = shell_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("shell.exec"), move |_| {
                shell_calls.set(shell_calls.get() + 1);
                Ok("must not run".to_owned())
            })
            .unwrap();
        let lease = runtime
            .issue_capability_lease([CapabilityLeaseGrant::new("text.echo", 1)])
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "dynamic-call",
                "use mod.tool\nlet selected = \"shell.exec\"\ntool.call(selected, \"whoami\")",
            )])
            .unwrap();
        let approval = engine.approve_with_capability_lease(&plan, lease).unwrap();

        let error = engine.execute(&plan, approval).unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 0,
                ..
            } if step_id == "dynamic-call"
        ));
        assert_eq!(observed_shell_calls.get(), 0);
        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(engine.runtime().audit()[0].tool, "shell.exec");
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Denied
        );
    }

    #[test]
    fn step_capability_leases_do_not_expose_later_step_authority() {
        let shell_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_shell_calls = shell_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("shell.exec"), move |_| {
                shell_calls.set(shell_calls.get() + 1);
                Ok("must not run".to_owned())
            })
            .unwrap();
        let first_lease = runtime
            .issue_capability_lease([CapabilityLeaseGrant::new("text.echo", 1)])
            .unwrap();
        let second_lease = runtime
            .issue_capability_lease([CapabilityLeaseGrant::new("shell.exec", 1)])
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "prepare",
                    "use mod.tool\nlet selected = \"shell.exec\"\ntool.call(selected, \"whoami\")",
                ),
                WorkflowStep::new(
                    "publish",
                    "use mod.tool\ntool.call(\"shell.exec\", \"release\")",
                ),
            ])
            .unwrap();
        let approval = engine
            .approve_with_step_capability_leases(&plan, vec![first_lease, second_lease])
            .unwrap();

        let error = engine.execute(&plan, approval).unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 0,
                ..
            } if step_id == "prepare"
        ));
        assert_eq!(observed_shell_calls.get(), 0);
        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(engine.runtime().audit()[0].tool, "shell.exec");
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Denied
        );
    }

    #[test]
    fn step_capability_leases_retain_the_current_authority_across_external_await() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("text.current"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("text.next"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let current_step_lease = runtime
            .issue_capability_lease([
                CapabilityLeaseGrant::new("text.remote", 1),
                CapabilityLeaseGrant::new("text.current", 1),
            ])
            .unwrap();
        let next_step_lease = runtime
            .issue_capability_lease([CapabilityLeaseGrant::new("text.next", 1)])
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "remote",
                    "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.remote\", \"release\").await()\nassert(output == \"done\")\ntool.call(\"text.current\", \"after-await\")",
                ),
                WorkflowStep::new(
                    "next",
                    "use mod.tool\ntool.call(\"text.next\", \"after-remote\")",
                ),
            ])
            .unwrap();
        let approval = engine
            .approve_with_step_capability_leases(&plan, vec![current_step_lease, next_step_lease])
            .unwrap();

        assert!(matches!(
            engine.execute(&plan, approval),
            Err(WorkflowError::StepSuspended {
                ref step_id,
                completed_steps: 0,
            }) if step_id == "remote"
        ));
        let invocation = engine.claim_next_external_tool().unwrap();
        engine
            .complete_external_tool(invocation.id, Ok("done".to_owned()))
            .unwrap();

        assert!(!engine.has_suspended_execution());
        let tools = engine
            .runtime()
            .audit()
            .iter()
            .map(|event| event.tool.as_str())
            .collect::<Vec<_>>();
        assert_eq!(tools, ["text.remote", "text.current", "text.next"]);
        assert!(engine
            .runtime()
            .audit()
            .iter()
            .all(|event| event.outcome == splash_capabilities::AuditOutcome::Allowed));
    }

    #[test]
    fn step_capability_policies_issue_ordered_host_authority() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("shell.exec"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "prepare",
                    "use mod.tool\ntool.call(\"text.echo\", \"release notes\")",
                ),
                WorkflowStep::new(
                    "publish",
                    "use mod.tool\ntool.call(\"shell.exec\", \"publish release\")",
                ),
            ])
            .unwrap();
        let approval = engine
            .approve_with_step_capability_policies(
                &plan,
                vec![
                    WorkflowStepCapabilityPolicy::new(
                        "prepare",
                        [CapabilityLeaseGrant::new("text.echo", 1)],
                    ),
                    WorkflowStepCapabilityPolicy::new(
                        "publish",
                        [CapabilityLeaseGrant::new("shell.exec", 1)],
                    ),
                ],
            )
            .unwrap();

        engine.execute(&plan, approval).unwrap();

        let tools = engine
            .runtime()
            .audit()
            .iter()
            .map(|event| event.tool.as_str())
            .collect::<Vec<_>>();
        assert_eq!(tools, ["text.echo", "shell.exec"]);
        assert!(engine
            .runtime()
            .audit()
            .iter()
            .all(|event| event.outcome == splash_capabilities::AuditOutcome::Allowed));
    }

    #[test]
    fn step_capability_policies_do_not_expose_later_step_authority() {
        let shell_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_shell_calls = shell_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("shell.exec"), move |_| {
                shell_calls.set(shell_calls.get() + 1);
                Ok("must not run".to_owned())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "prepare",
                    "use mod.tool\nlet selected = \"shell.exec\"\ntool.call(selected, \"whoami\")",
                ),
                WorkflowStep::new(
                    "publish",
                    "use mod.tool\ntool.call(\"shell.exec\", \"publish release\")",
                ),
            ])
            .unwrap();
        let approval = engine
            .approve_with_step_capability_policies(
                &plan,
                vec![
                    WorkflowStepCapabilityPolicy::new(
                        "prepare",
                        [CapabilityLeaseGrant::new("text.echo", 1)],
                    ),
                    WorkflowStepCapabilityPolicy::new(
                        "publish",
                        [CapabilityLeaseGrant::new("shell.exec", 1)],
                    ),
                ],
            )
            .unwrap();

        let error = engine.execute(&plan, approval).unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 0,
                ..
            } if step_id == "prepare"
        ));
        assert_eq!(observed_shell_calls.get(), 0);
        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(engine.runtime().audit()[0].tool, "shell.exec");
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Denied
        );
    }

    #[test]
    fn step_capability_policies_reject_unbound_or_unknown_authority_before_approval() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("prepare", "let prepared = true"),
                WorkflowStep::new("publish", "let published = true"),
            ])
            .unwrap();

        assert_eq!(
            engine
                .approve_with_step_capability_policies(
                    &plan,
                    vec![WorkflowStepCapabilityPolicy::new(
                        "prepare",
                        std::iter::empty::<CapabilityLeaseGrant>(),
                    )],
                )
                .unwrap_err(),
            WorkflowError::StepCapabilityPolicyCount {
                expected: 2,
                actual: 1,
            }
        );
        assert_eq!(
            engine
                .approve_with_step_capability_policies(
                    &plan,
                    vec![
                        WorkflowStepCapabilityPolicy::new(
                            "publish",
                            std::iter::empty::<CapabilityLeaseGrant>(),
                        ),
                        WorkflowStepCapabilityPolicy::new(
                            "prepare",
                            std::iter::empty::<CapabilityLeaseGrant>(),
                        ),
                    ],
                )
                .unwrap_err(),
            WorkflowError::StepCapabilityPolicyMismatch {
                expected: "prepare".to_owned(),
                actual: "publish".to_owned(),
            }
        );
        assert_eq!(
            engine
                .approve_with_step_capability_policies(
                    &plan,
                    vec![
                        WorkflowStepCapabilityPolicy::new(
                            "prepare",
                            [CapabilityLeaseGrant::new("shell.exec", 1)],
                        ),
                        WorkflowStepCapabilityPolicy::new(
                            "publish",
                            std::iter::empty::<CapabilityLeaseGrant>(),
                        ),
                    ],
                )
                .unwrap_err(),
            WorkflowError::CapabilityLease(CapabilityLeaseError::UnknownTool(
                "shell.exec".to_owned()
            ))
        );
        assert!(!engine.events().iter().any(|event| matches!(
            event,
            WorkflowEvent::Approved { .. } | WorkflowEvent::ResumeApproved { .. }
        )));
    }

    #[test]
    fn step_capability_lease_approvals_require_an_exact_validated_vector() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let short_lease = runtime
            .issue_capability_lease(std::iter::empty::<CapabilityLeaseGrant>())
            .unwrap();
        let too_many_first = runtime
            .issue_capability_lease(std::iter::empty::<CapabilityLeaseGrant>())
            .unwrap();
        let too_many_second = runtime
            .issue_capability_lease(std::iter::empty::<CapabilityLeaseGrant>())
            .unwrap();
        let too_many_third = runtime
            .issue_capability_lease(std::iter::empty::<CapabilityLeaseGrant>())
            .unwrap();
        let stale_lease = runtime
            .issue_capability_lease(std::iter::empty::<CapabilityLeaseGrant>())
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("first", "let first = true"),
                WorkflowStep::new("second", "let second = true"),
            ])
            .unwrap();

        assert_eq!(
            engine
                .approve_with_step_capability_leases(&plan, vec![short_lease])
                .unwrap_err(),
            WorkflowError::StepCapabilityLeaseCount {
                expected: 2,
                actual: 1,
            }
        );
        assert_eq!(
            engine
                .approve_with_step_capability_leases(
                    &plan,
                    vec![too_many_first, too_many_second, too_many_third],
                )
                .unwrap_err(),
            WorkflowError::StepCapabilityLeaseCount {
                expected: 2,
                actual: 3,
            }
        );
        engine
            .runtime_mut()
            .register_tool(ToolPolicy::new("text.other"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        assert_eq!(
            engine
                .approve_with_step_capability_leases(
                    &plan,
                    vec![
                        stale_lease,
                        engine
                            .runtime()
                            .issue_capability_lease(std::iter::empty::<CapabilityLeaseGrant>())
                            .unwrap(),
                    ],
                )
                .unwrap_err(),
            WorkflowError::CapabilityLease(CapabilityLeaseError::CatalogChanged)
        );
        assert!(!engine
            .events()
            .iter()
            .any(|event| matches!(event, WorkflowEvent::Approved { .. })));
    }

    #[test]
    fn step_capability_lease_rejects_foreign_runtime_authority() {
        let foreign_lease = CapabilityRuntime::default()
            .issue_capability_lease(std::iter::empty::<CapabilityLeaseGrant>())
            .unwrap();
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new("pure", "let completed = true")])
            .unwrap();

        assert_eq!(
            engine
                .approve_with_step_capability_leases(&plan, vec![foreign_lease])
                .unwrap_err(),
            WorkflowError::CapabilityLease(CapabilityLeaseError::RuntimeMismatch)
        );
        assert!(!engine
            .events()
            .iter()
            .any(|event| matches!(event, WorkflowEvent::Approved { .. })));
    }

    #[test]
    fn step_capability_call_budget_does_not_reset_after_external_await() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("text.current"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let current_step_lease = runtime
            .issue_capability_lease([
                CapabilityLeaseGrant::new("text.remote", 1),
                CapabilityLeaseGrant::new("text.current", 1),
            ])
            .unwrap();
        let pure_next_step_lease = runtime
            .issue_capability_lease(std::iter::empty::<CapabilityLeaseGrant>())
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "remote",
                    "use mod.tool\nlet output = tool.start(\"text.remote\", \"release\").await()\ntool.call(\"text.current\", output)\ntool.call(\"text.current\", \"second\")",
                ),
                WorkflowStep::new("next", "let must_not_run = true"),
            ])
            .unwrap();
        let approval = engine
            .approve_with_step_capability_leases(
                &plan,
                vec![current_step_lease, pure_next_step_lease],
            )
            .unwrap();

        assert!(matches!(
            engine.execute(&plan, approval),
            Err(WorkflowError::StepSuspended {
                ref step_id,
                completed_steps: 0,
            }) if step_id == "remote"
        ));
        let invocation = engine.claim_next_external_tool().unwrap();
        let error = engine
            .complete_external_tool(invocation.id, Ok("done".to_owned()))
            .unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 0,
                ..
            } if step_id == "remote"
        ));
        let audit = engine.runtime().audit();
        assert_eq!(audit.len(), 3);
        assert_eq!(audit[0].outcome, splash_capabilities::AuditOutcome::Allowed);
        assert_eq!(audit[1].outcome, splash_capabilities::AuditOutcome::Allowed);
        assert_eq!(audit[2].tool, "text.current");
        assert_eq!(audit[2].outcome, splash_capabilities::AuditOutcome::Denied);
    }

    #[test]
    fn resumed_step_capability_leases_cover_only_the_unexecuted_suffix() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.prefix"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("text.suffix"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let suffix_lease = runtime
            .issue_capability_lease([CapabilityLeaseGrant::new("text.suffix", 1)])
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "prefix",
                    "use mod.tool\ntool.call(\"text.prefix\", \"already-complete\")",
                ),
                WorkflowStep::new(
                    "suffix",
                    "use mod.tool\ntool.call(\"text.suffix\", \"resume\")",
                ),
            ])
            .unwrap();
        let checkpoint = engine.checkpoint_after(&plan, 1).unwrap();
        let approval = engine
            .approve_resume_with_step_capability_leases(&plan, &checkpoint, vec![suffix_lease])
            .unwrap();

        engine.resume(&plan, &checkpoint, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(engine.runtime().audit()[0].tool, "text.suffix");
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn resumed_step_capability_policies_cover_only_the_unexecuted_suffix() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.prefix"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("text.suffix"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "prefix",
                    "use mod.tool\ntool.call(\"text.prefix\", \"already-complete\")",
                ),
                WorkflowStep::new(
                    "suffix",
                    "use mod.tool\ntool.call(\"text.suffix\", \"resume\")",
                ),
            ])
            .unwrap();
        let checkpoint = engine.checkpoint_after(&plan, 1).unwrap();

        assert_eq!(
            engine
                .approve_resume_with_step_capability_policies(&plan, &checkpoint, Vec::new())
                .unwrap_err(),
            WorkflowError::StepCapabilityPolicyCount {
                expected: 1,
                actual: 0,
            }
        );
        assert_eq!(
            engine
                .approve_resume_with_step_capability_policies(
                    &plan,
                    &checkpoint,
                    vec![WorkflowStepCapabilityPolicy::new(
                        "prefix",
                        [CapabilityLeaseGrant::new("text.prefix", 1)],
                    )],
                )
                .unwrap_err(),
            WorkflowError::StepCapabilityPolicyMismatch {
                expected: "suffix".to_owned(),
                actual: "prefix".to_owned(),
            }
        );
        assert!(!engine
            .events()
            .iter()
            .any(|event| matches!(event, WorkflowEvent::ResumeApproved { .. })));

        let approval = engine
            .approve_resume_with_step_capability_policies(
                &plan,
                &checkpoint,
                vec![WorkflowStepCapabilityPolicy::new(
                    "suffix",
                    [CapabilityLeaseGrant::new("text.suffix", 1)],
                )],
            )
            .unwrap();

        engine.resume(&plan, &checkpoint, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(engine.runtime().audit()[0].tool, "text.suffix");
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
    fn resume_approval_fails_closed_when_the_catalog_changes() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![
                WorkflowStep::new("prepare", "let prepared = true"),
                WorkflowStep::new("publish", "let published = true"),
            ])
            .unwrap();
        let checkpoint = engine.checkpoint_after(&plan, 1).unwrap();
        let approval = engine.approve_resume(&plan, &checkpoint).unwrap();
        engine
            .runtime_mut()
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();

        assert_eq!(
            engine.resume(&plan, &checkpoint, approval).unwrap_err(),
            WorkflowError::CapabilityLease(CapabilityLeaseError::CatalogChanged)
        );
        assert!(!engine
            .events()
            .iter()
            .any(|event| matches!(event, WorkflowEvent::Resumed { .. })));
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
    fn authenticated_dispatch_result_rejects_a_wrong_message_before_ledger_mutation() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new("publish", "let release = true")])
            .unwrap();
        let mut ledger = engine.operation_ledger(&plan).unwrap();
        let payload = ToolPayload::Text("release-1.2.3".to_owned());
        let input = canonical_operation_input_bytes(&payload).unwrap();
        let operation_key = engine
            .record_derived_operation(
                &plan,
                &mut ledger,
                "publish",
                "release.publish",
                &input,
                b"release-42:publish:operation-0",
            )
            .unwrap();
        let (mut host, mut worker) = operation_reconciliation_authenticators();
        let outbound = engine
            .prepare_authenticated_operation_dispatch(
                &plan,
                &ledger,
                &operation_key,
                payload,
                "publish-dispatch-1",
                &mut host,
            )
            .unwrap();
        assert!(matches!(
            worker.open(outbound.frame).unwrap(),
            WorkerMessage::DispatchOperation { .. }
        ));
        let result = OperationReconcileResult::new(
            outbound.request.session_id.clone(),
            outbound.request.request_id.clone(),
            outbound.request.tool.clone(),
            outbound.request.operation_key.clone(),
            OperationStatus::Succeeded {
                payload: ToolPayload::Text("done".to_owned()),
            },
        )
        .unwrap();
        let wrong_frame = worker
            .seal(WorkerMessage::ReconciledOperation { result })
            .unwrap();

        assert_eq!(
            engine
                .apply_authenticated_operation_dispatch_result(
                    &plan,
                    &mut ledger,
                    &outbound.request,
                    &mut host,
                    wrong_frame,
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::UnexpectedOperationDispatchMessage,
            )
        );
        assert_eq!(ledger.revision(), 1);
        assert_eq!(
            ledger.operation(&operation_key).unwrap().state(),
            WorkflowOperationState::Pending
        );
    }

    #[test]
    fn suspended_external_workflow_operation_is_durable_before_exact_dispatch() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::json("release.publish"))
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "publish",
                "use mod.tool\n\
                 let response = tool.start_json(\"release.publish\", {version: \"1.2.3\"}).await()\n\
                 response",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        assert!(matches!(
            engine.execute(&plan, approval),
            Err(WorkflowError::StepSuspended {
                ref step_id,
                completed_steps: 0,
            }) if step_id == "publish"
        ));

        let mut ledger = engine.operation_ledger(&plan).unwrap();
        let prepared = engine
            .prepare_next_external_operation(&plan, &mut ledger, b"release-42:publish:operation-0")
            .unwrap()
            .unwrap();
        assert_eq!(prepared.step_id(), "publish");
        assert_eq!(prepared.completed_steps(), 0);
        assert_eq!(ledger.revision(), 1);
        let operation_key = prepared.operation_key().to_owned();
        assert_eq!(
            ledger.operation(&operation_key).unwrap().tool(),
            "release.publish"
        );

        // A repeated prepare is idempotent, so a host can retry its storage
        // write without creating another durable worker identity.
        let repeated = engine
            .prepare_next_external_operation(&plan, &mut ledger, b"release-42:publish:operation-0")
            .unwrap()
            .unwrap();
        assert_eq!(repeated.operation_key(), operation_key);
        assert_eq!(ledger.revision(), 1);

        let persisted = ledger.to_json().unwrap();
        assert!(!persisted.contains("1.2.3"));
        let mut restored_ledger = WorkflowOperationLedger::from_json(&persisted).unwrap();
        let claimed = engine
            .claim_prepared_external_operation(&plan, &restored_ledger, prepared)
            .unwrap();
        assert_eq!(claimed.operation_key(), operation_key);
        assert_eq!(claimed.payload(), repeated.payload());

        let (mut host, mut worker) = operation_reconciliation_authenticators();
        let outbound = engine
            .prepare_authenticated_claimed_external_operation_dispatch(
                &plan,
                &restored_ledger,
                &claimed,
                "publish-dispatch-1",
                &mut host,
            )
            .unwrap();
        assert_eq!(
            worker.open(outbound.frame.clone()).unwrap(),
            WorkerMessage::DispatchOperation {
                request: outbound.request.clone(),
            }
        );
        let result = OperationReconcileResult::new(
            outbound.request.session_id.clone(),
            outbound.request.request_id.clone(),
            outbound.request.tool.clone(),
            outbound.request.operation_key.clone(),
            OperationStatus::Succeeded {
                payload: ToolPayload::Json(serde_json::json!({"published": true})),
            },
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::OperationResult { result })
            .unwrap();
        let (state, verified_result) = engine
            .apply_authenticated_operation_dispatch_result(
                &plan,
                &mut restored_ledger,
                &outbound.request,
                &mut host,
                response,
            )
            .unwrap();
        assert_eq!(state, WorkflowOperationState::Succeeded);
        assert!(matches!(
            verified_result.status,
            OperationStatus::Succeeded {
                payload: ToolPayload::Json(ref payload),
            } if payload == &serde_json::json!({"published": true})
        ));
        assert_eq!(restored_ledger.revision(), 2);
        let terminal = restored_ledger.to_json().unwrap();
        assert!(!terminal.contains("published"));

        engine
            .complete_external_tool(
                claimed.invocation().id,
                Ok("{\"published\":true}".to_owned()),
            )
            .unwrap();
        assert!(!engine.has_suspended_execution());
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn compensation_is_host_approved_bound_and_applied_once() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new("publish", "let release = true")])
            .unwrap();
        let mut ledger = engine.operation_ledger(&plan).unwrap();
        let operation_payload = ToolPayload::Json(serde_json::json!({"version": "1.2.3"}));
        let operation_input = canonical_operation_input_bytes(&operation_payload).unwrap();
        let operation_key = engine
            .record_derived_operation(
                &plan,
                &mut ledger,
                "publish",
                "release.publish",
                &operation_input,
                b"release-42:publish:1",
            )
            .unwrap();
        let original_request = OperationReconcileRequest::new(
            "worker-1",
            "original-status-1",
            "release.publish",
            operation_key.clone(),
        )
        .unwrap();
        let original_result = OperationReconcileResult::new(
            "worker-1",
            "original-status-1",
            "release.publish",
            operation_key.clone(),
            OperationStatus::Succeeded {
                payload: ToolPayload::Json(serde_json::json!({"published": true})),
            },
        )
        .unwrap();
        engine
            .apply_verified_operation_reconciliation(
                &plan,
                &mut ledger,
                &original_request,
                &original_result,
            )
            .unwrap();

        let grant = CapabilityGrant::json("release.publish").with_compensation_limit(1);
        let policy = WorkflowCompensationPolicy::new("tenant-release", &grant).unwrap();
        let verifier = AllowCompensationGrantVerifier;
        let target = WorkflowCompensationTarget::new(&operation_key, &policy, &grant, &verifier);
        let compensation_payload = ToolPayload::Json(serde_json::json!({"undo": "release"}));
        let compensation_input = canonical_operation_input_bytes(&compensation_payload).unwrap();
        let (mut host, mut worker) = operation_reconciliation_authenticators();

        let compensation_key = engine
            .record_derived_compensation(
                &plan,
                &mut ledger,
                &operation_key,
                &policy,
                &compensation_input,
                b"release-42:publish:undo:1",
            )
            .unwrap();
        let drift_approval = engine
            .approve_compensation(&plan, &ledger, target, &compensation_input, &host)
            .unwrap();
        assert_eq!(
            engine
                .prepare_authenticated_operation_compensation(
                    &plan,
                    &ledger,
                    target,
                    WorkflowCompensationDispatch::new(
                        "compensation-request-drift",
                        ToolPayload::Json(serde_json::json!({"undo": "different"})),
                    ),
                    drift_approval,
                    &mut host,
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationInputFingerprintMismatch(
                    compensation_key.clone(),
                ),
            )
        );
        let approval = engine
            .approve_compensation(&plan, &ledger, target, &compensation_input, &host)
            .unwrap();
        let outbound = engine
            .prepare_authenticated_operation_compensation(
                &plan,
                &ledger,
                target,
                WorkflowCompensationDispatch::new(
                    "compensation-request-1",
                    compensation_payload.clone(),
                ),
                approval,
                &mut host,
            )
            .unwrap();
        let WorkerMessage::CompensateOperation { request } = worker.open(outbound.frame).unwrap()
        else {
            panic!("host must send a compensation request");
        };
        assert_eq!(request.compensation_key, compensation_key);
        let binding = OperationCompensationBinding::new(
            request.tool.clone(),
            request.operation_key.clone(),
            request.compensation_key.clone(),
            request.tenant_scope.clone(),
            request.grant_fingerprint.clone(),
        )
        .unwrap();
        let result = OperationCompensationResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            binding,
            OperationStatus::Succeeded {
                payload: ToolPayload::Json(serde_json::json!({"undone": true})),
            },
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::CompensationResult { result })
            .unwrap();
        assert_eq!(
            engine
                .apply_authenticated_operation_compensation(
                    &plan,
                    &mut ledger,
                    &outbound.request,
                    &mut host,
                    response,
                )
                .unwrap(),
            WorkflowOperationState::Succeeded
        );
        assert_eq!(
            ledger
                .operation(&operation_key)
                .unwrap()
                .compensation()
                .unwrap()
                .state(),
            WorkflowOperationState::Succeeded
        );
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::CompensationObserved {
                plan_id,
                operation_key: observed_operation_key,
                compensation_key: observed_compensation_key,
                state: WorkflowOperationState::Succeeded,
            }) if *plan_id == plan.id()
                && observed_operation_key == &operation_key
                && observed_compensation_key == &compensation_key
        ));

        let mut persisted: serde_json::Value =
            serde_json::from_str(&ledger.to_json().unwrap()).unwrap();
        persisted["operations"][0]["state"] = serde_json::json!("running");
        let malformed = serde_json::to_string(&persisted).unwrap();
        assert_eq!(
            WorkflowOperationLedger::from_json(&malformed).unwrap_err(),
            WorkflowOperationLedgerError::CompensationRequiresSucceededOperation {
                operation_key,
                state: WorkflowOperationState::Running,
            }
        );
    }

    #[test]
    fn compensation_cannot_be_recorded_before_original_success() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new("publish", "let release = true")])
            .unwrap();
        let mut ledger = engine.operation_ledger(&plan).unwrap();
        let payload = ToolPayload::Json(serde_json::json!({"version": "1.2.3"}));
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
        let grant = CapabilityGrant::json("release.publish").with_compensation_limit(1);
        let policy = WorkflowCompensationPolicy::new("tenant-release", &grant).unwrap();
        let compensation_input = canonical_operation_input_bytes(&ToolPayload::Json(
            serde_json::json!({"undo": "release"}),
        ))
        .unwrap();

        assert_eq!(
            engine
                .record_derived_compensation(
                    &plan,
                    &mut ledger,
                    &operation_key,
                    &policy,
                    &compensation_input,
                    b"release-42:publish:undo:1",
                )
                .unwrap_err(),
            WorkflowError::OperationLedger(
                WorkflowOperationLedgerError::CompensationRequiresSucceededOperation {
                    operation_key,
                    state: WorkflowOperationState::Pending,
                },
            )
        );
    }

    #[test]
    fn compensation_rechecks_current_grant_policy_before_approval_and_dispatch() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new("publish", "let release = true")])
            .unwrap();
        let ledger = engine.operation_ledger(&plan).unwrap();
        let grant = CapabilityGrant::json("release.publish").with_compensation_limit(1);
        let policy = WorkflowCompensationPolicy::new("tenant-release", &grant).unwrap();
        let verifier = DenyCompensationGrantVerifier;
        let target = WorkflowCompensationTarget::new("op-release-42", &policy, &grant, &verifier);
        let (mut host, _) = operation_reconciliation_authenticators();
        let expected =
            WorkflowError::OperationLedger(WorkflowOperationLedgerError::CompensationGrantDenied {
                tool: "release.publish".to_owned(),
                tenant_scope: "tenant-release".to_owned(),
            });

        assert_eq!(
            engine
                .approve_compensation(&plan, &ledger, target, b"undo", &host)
                .unwrap_err(),
            expected
        );
        let approval = engine.approve(&plan).unwrap();
        assert_eq!(
            engine
                .prepare_authenticated_operation_compensation(
                    &plan,
                    &ledger,
                    target,
                    WorkflowCompensationDispatch::new(
                        "compensation-request-1",
                        ToolPayload::Json(serde_json::json!({"undo": "release"})),
                    ),
                    approval,
                    &mut host,
                )
                .unwrap_err(),
            expected
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

        let contract_without_dataflow_context = serde_json::json!({
            "format_version": WORKFLOW_CHECKPOINT_FORMAT_VERSION,
            "plan_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "completed_step_ids": [],
            "data_contract_fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        })
        .to_string();
        assert_eq!(
            WorkflowCheckpoint::from_json(&contract_without_dataflow_context).unwrap_err(),
            WorkflowCheckpointError::DataflowContractWithoutContext
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
    fn rejects_noncanonical_source_with_step_context_before_a_workflow_tool_runs() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "reject",
                    "var value = tool.call(\"text.echo\", \"must not run\")",
                ),
                WorkflowStep::new(
                    "not-run",
                    "use mod.tool\ntool.call(\"text.echo\", \"also must not run\")",
                ),
            ])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        let error = engine.execute(&plan, approval).unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::StepRejected {
                ref step_id,
                ref report,
                completed_steps: 0,
            } if step_id == "reject" && !report.valid && !report.diagnostics.is_empty()
        ));
        assert!(engine.runtime().audit().is_empty());
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::StepRejected {
                step_id,
                diagnostic_count,
                diagnostics_truncated: false,
                completed_steps: 0,
                ..
            }) if step_id == "reject" && *diagnostic_count > 0
        ));
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
            Some(WorkflowEvent::StepFailed {
                step_id,
                diagnostic_count,
                ..
            }) if step_id == "deny" && *diagnostic_count > 0
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
    fn workflow_pumps_nonawaited_local_work_before_its_waiting_promise() {
        let first_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_first_calls = first_calls.clone();
        let second_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_second_calls = second_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.first"), move |request| {
                first_calls.set(first_calls.get() + 1);
                Ok(request.input.clone())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("text.second"), move |request| {
                second_calls.set(second_calls.get() + 1);
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "parallel-local",
                "use mod.tool\nuse mod.std.assert\nlet first = tool.start(\"text.first\", \"first\")\nlet second = tool.start(\"text.second\", \"second\")\nassert(second.await() == \"second\")",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        engine.execute(&plan, approval).unwrap();

        assert_eq!(observed_first_calls.get(), 1);
        assert_eq!(observed_second_calls.get(), 1);
        assert_eq!(engine.runtime().audit().len(), 2);
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Completed { plan_id }) if *plan_id == plan.id()
        ));
    }

    #[test]
    fn workflow_drains_unawaited_local_work_before_the_next_step() {
        let calls = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let observed_calls = calls.clone();
        let ignored_completed = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed_ignored_completed = ignored_completed.clone();
        let mut policy = ToolPolicy::new("text.echo");
        policy.max_calls = 2;
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(policy, move |request| {
                calls.borrow_mut().push(request.input.clone());
                if request.input == "ignored" {
                    ignored_completed.set(true);
                } else {
                    assert!(ignored_completed.get());
                }
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "prepare",
                    "use mod.tool\nlet ignored = tool.start(\"text.echo\", \"ignored\")",
                ),
                WorkflowStep::new(
                    "await-needed",
                    "use mod.tool\nuse mod.std.assert\nlet needed = tool.start(\"text.echo\", \"needed\")\nassert(needed.await() == \"needed\")",
                ),
            ])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        engine.execute(&plan, approval).unwrap();

        assert!(observed_ignored_completed.get());
        assert_eq!(observed_calls.borrow().as_slice(), ["ignored", "needed"]);
        assert_eq!(engine.runtime().audit().len(), 2);
    }

    #[test]
    fn workflow_cancels_unawaited_external_work_before_the_next_step() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "start-unawaited",
                    "use mod.tool\nlet ignored = tool.start(\"text.remote\", \"ignored\")",
                ),
                WorkflowStep::new("next", "let completed = true"),
            ])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        engine.execute(&plan, approval).unwrap();

        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Cancelled
        );
        assert!(engine.runtime_mut().claim_next_external_tool().is_none());
    }

    #[test]
    fn external_workflow_completion_continues_the_retained_approval() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "remote-release",
                "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.remote\", \"release\").await()\nassert(output == \"done\")",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();

        let suspended = engine.execute(&plan, approval).unwrap_err();

        assert!(matches!(
            suspended,
            WorkflowError::StepSuspended {
                ref step_id,
                completed_steps: 0,
            } if step_id == "remote-release"
        ));
        assert!(engine.has_suspended_execution());
        let invocation = engine.claim_next_external_tool().unwrap();
        engine
            .complete_external_tool(invocation.id, Ok("done".to_owned()))
            .unwrap();

        assert!(!engine.has_suspended_execution());
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
    fn cooperative_cancellation_keeps_workflow_suspended_until_confirmation() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "remote-release",
                "use mod.tool\ntool.start(\"text.remote\", \"release\").await()",
            )])
            .unwrap();
        let approval = engine.approve(&plan).unwrap();
        assert!(matches!(
            engine.execute(&plan, approval),
            Err(WorkflowError::StepSuspended { .. })
        ));
        let invocation = engine.claim_next_external_tool().unwrap();

        let request = engine
            .request_external_tool_cancellation(invocation.id)
            .unwrap();
        assert_eq!(request.id, invocation.id);
        assert!(engine.has_suspended_execution());
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::CancellationRequested
        );

        assert!(matches!(
            engine.confirm_external_tool_cancellation(invocation.id),
            Err(WorkflowError::StepFailed { .. })
        ));
        assert!(!engine.has_suspended_execution());
        assert_eq!(
            engine.runtime().audit()[1].outcome,
            splash_capabilities::AuditOutcome::Cancelled
        );
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
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.start_json(\"math.add\", {left: 20, right: 22}).await()\nlet response = raw.parse_json()\nassert(response.total == 42)",
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

    #[test]
    fn workflow_data_round_trips_as_bounded_data_only_context() {
        let data = WorkflowData::new(serde_json::json!({
            "request": {"title": "release"},
            "dry_run": true
        }))
        .unwrap();

        let encoded = data.to_json().unwrap();
        let decoded = WorkflowData::from_json(&encoded).unwrap();
        let document: serde_json::Value = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded, data);
        assert_eq!(decoded.fingerprint().unwrap(), data.fingerprint().unwrap());
        assert_eq!(document["format_version"], WORKFLOW_DATA_FORMAT_VERSION);
        assert!(encoded.contains("input"));
        assert!(encoded.contains("outputs"));
        assert!(!encoded.contains("approval"));
        assert!(!encoded.contains("capability"));
        assert_eq!(
            WorkflowData::from_json(r#"{"input":{},"outputs":{}}"#).unwrap_err(),
            WorkflowDataError::InvalidDocument
        );
        assert_eq!(
            WorkflowData::from_json(r#"{"format_version":2,"input":{},"outputs":{}}"#).unwrap_err(),
            WorkflowDataError::UnsupportedFormatVersion {
                actual: 2,
                expected: WORKFLOW_DATA_FORMAT_VERSION,
            }
        );
        assert_eq!(
            WorkflowData::from_json(
                r#"{"format_version":1,"input":{},"outputs":{},"contract_fingerprint":"not-a-blake3-digest"}"#,
            )
            .unwrap_err(),
            WorkflowDataError::InvalidContractFingerprint
        );
    }

    #[test]
    fn workflow_data_contract_enforces_an_aggregate_schema_bound() {
        let large_schema = serde_json::json!({
            "type": "null",
            "description": "x".repeat(30 * 1024)
        });
        let output_contracts = (0..9)
            .map(|index| {
                WorkflowStepOutputContract::new(
                    format!("step{index}"),
                    compiled_schema(large_schema.clone()),
                )
            })
            .collect::<Vec<_>>();

        let error = WorkflowDataContract::new(
            compiled_schema(serde_json::json!({"type": "null"})),
            output_contracts,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            WorkflowDataContractError::TooLarge { actual, maximum }
                if actual > maximum && maximum == MAX_WORKFLOW_DATA_CONTRACT_BYTES
        ));
    }

    #[test]
    fn dataflow_contract_rejects_invalid_input_before_policy_leases_are_issued() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "dispatch",
                "let result = 1\nresult",
            )])
            .unwrap();
        let contract = workflow_data_contract(
            serde_json::json!({
                "type": "object",
                "properties": {"count": {"type": "integer"}},
                "required": ["count"],
                "additionalProperties": false
            }),
            vec![("dispatch", serde_json::json!({"type": "number"}))],
        );

        let error = engine
            .approve_dataflow_with_contract_and_step_capability_policies(
                &plan,
                WorkflowData::new(serde_json::json!({"count": "not-an-integer"})).unwrap(),
                contract,
                vec![WorkflowStepCapabilityPolicy::new(
                    "dispatch",
                    [CapabilityLeaseGrant::new("absent.tool", 1)],
                )],
            )
            .unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::DataContract(WorkflowDataContractError::Input(_))
        ));
        assert_eq!(engine.events().len(), 1);
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::Planned { plan_id, step_count: 1 }) if *plan_id == plan.id()
        ));
        assert!(engine.runtime().audit().is_empty());
    }

    #[test]
    fn dataflow_contract_rejects_output_before_later_authorized_tool_runs() {
        let later_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_later_calls = later_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), move |_| {
                later_calls.set(later_calls.get() + 1);
                Ok("must not run".to_owned())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "transform",
                    "let result = {unexpected: workflow.input.value}\nresult",
                ),
                WorkflowStep::new(
                    "dispatch",
                    "use mod.tool\ntool.call(\"text.echo\", \"must not run\")",
                ),
            ])
            .unwrap();
        let contract = workflow_data_contract(
            serde_json::json!({
                "type": "object",
                "properties": {"value": {"type": "integer"}},
                "required": ["value"],
                "additionalProperties": false
            }),
            vec![
                (
                    "transform",
                    serde_json::json!({
                        "type": "object",
                        "properties": {"total": {"type": "integer"}},
                        "required": ["total"],
                        "additionalProperties": false
                    }),
                ),
                ("dispatch", serde_json::json!({"type": "string"})),
            ],
        );
        let approval = engine
            .approve_dataflow_with_contract_and_step_capability_policies(
                &plan,
                WorkflowData::new(serde_json::json!({"value": 7})).unwrap(),
                contract,
                vec![
                    WorkflowStepCapabilityPolicy::new(
                        "transform",
                        Vec::<CapabilityLeaseGrant>::new(),
                    ),
                    WorkflowStepCapabilityPolicy::new(
                        "dispatch",
                        [CapabilityLeaseGrant::new("text.echo", 1)],
                    ),
                ],
            )
            .unwrap();

        let error = engine.execute_dataflow(&plan, approval).unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::DataflowContractOutput {
                ref step_id,
                completed_steps: 0,
                ..
            } if step_id == "transform"
        ));
        assert_eq!(observed_later_calls.get(), 0);
        assert!(engine.runtime().audit().is_empty());
        assert!(engine.dataflow_snapshot().unwrap().outputs().is_empty());
        assert!(matches!(
            engine.events().last(),
            Some(WorkflowEvent::StepFailed {
                step_id,
                diagnostic_count: 1,
                completed_steps: 0,
                ..
            }) if step_id == "transform"
        ));
    }

    #[test]
    fn dataflow_binds_initial_input_and_prior_step_outputs() {
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
            .plan(vec![
                WorkflowStep::new(
                    "prepare",
                    "use mod.tool\n\
                     let raw = tool.call_json(\"math.add\", workflow.input)\n\
                     let result = raw.parse_json()\n\
                     result",
                ),
                WorkflowStep::new(
                    "summarize",
                    "let result = {next: workflow.outputs.prepare.total + 1}\nresult",
                ),
            ])
            .unwrap();
        let input = serde_json::json!({"left": 20, "right": 22});
        let contract = workflow_data_contract(
            serde_json::json!({
                "type": "object",
                "properties": {
                    "left": {"type": "integer"},
                    "right": {"type": "integer"}
                },
                "required": ["left", "right"],
                "additionalProperties": false
            }),
            vec![
                (
                    "prepare",
                    serde_json::json!({
                        "type": "object",
                        "properties": {"total": {"type": "integer"}},
                        "required": ["total"],
                        "additionalProperties": false
                    }),
                ),
                (
                    "summarize",
                    serde_json::json!({
                        "type": "object",
                        "properties": {"next": {"type": "integer"}},
                        "required": ["next"],
                        "additionalProperties": false
                    }),
                ),
            ],
        );
        let approval = engine
            .approve_dataflow_with_contract_and_step_capability_policies(
                &plan,
                WorkflowData::new(input.clone()).unwrap(),
                contract,
                vec![
                    WorkflowStepCapabilityPolicy::new(
                        "prepare",
                        [CapabilityLeaseGrant::new("math.add", 1)],
                    ),
                    WorkflowStepCapabilityPolicy::new(
                        "summarize",
                        Vec::<CapabilityLeaseGrant>::new(),
                    ),
                ],
            )
            .unwrap();

        let data = engine.execute_dataflow(&plan, approval).unwrap();

        assert_eq!(data.input(), &input);
        assert_eq!(
            data.output("prepare"),
            Some(&serde_json::json!({"total": 42}))
        );
        assert_eq!(
            data.output("summarize"),
            Some(&serde_json::json!({"next": 43}))
        );
        assert_eq!(engine.dataflow_snapshot(), Some(&data));
        assert_eq!(engine.runtime().audit().len(), 1);
    }

    #[test]
    fn dataflow_json_cannot_select_an_ungranted_dynamic_capability() {
        let shell_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_shell_calls = shell_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("shell.exec"), move |_| {
                shell_calls.set(shell_calls.get() + 1);
                Ok("must not run".to_owned())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "dynamic-call",
                "use mod.tool\n\
                 let selected = workflow.input.selected\n\
                 tool.call(selected, \"whoami\")",
            )])
            .unwrap();
        let approval = engine
            .approve_dataflow_with_step_capability_policies(
                &plan,
                WorkflowData::new(serde_json::json!({"selected": "shell.exec"})).unwrap(),
                vec![WorkflowStepCapabilityPolicy::new(
                    "dynamic-call",
                    [CapabilityLeaseGrant::new("text.echo", 1)],
                )],
            )
            .unwrap();

        let error = engine.execute_dataflow(&plan, approval).unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 0,
                ..
            } if step_id == "dynamic-call"
        ));
        assert_eq!(observed_shell_calls.get(), 0);
        assert_eq!(engine.runtime().audit().len(), 1);
        assert_eq!(engine.runtime().audit()[0].tool, "shell.exec");
        assert_eq!(
            engine.runtime().audit()[0].outcome,
            splash_capabilities::AuditOutcome::Denied
        );
        assert!(engine.dataflow_snapshot().unwrap().outputs().is_empty());
    }

    #[test]
    fn dataflow_rejects_aggregate_output_growth_before_later_steps_run() {
        let later_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_later_calls = later_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), move |_| {
                later_calls.set(later_calls.get() + 1);
                Ok("must not run".to_owned())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("copy", "let result = workflow.input\nresult"),
                WorkflowStep::new(
                    "later",
                    "use mod.tool\ntool.call(\"text.echo\", \"must not run\")",
                ),
            ])
            .unwrap();
        let approval = engine
            .approve_dataflow_with_step_capability_policies(
                &plan,
                WorkflowData::new(serde_json::json!({"payload": "x".repeat(40 * 1024)})).unwrap(),
                vec![
                    WorkflowStepCapabilityPolicy::new("copy", Vec::<CapabilityLeaseGrant>::new()),
                    WorkflowStepCapabilityPolicy::new(
                        "later",
                        [CapabilityLeaseGrant::new("text.echo", 1)],
                    ),
                ],
            )
            .unwrap();

        let error = engine.execute_dataflow(&plan, approval).unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::DataflowOutput {
                ref step_id,
                completed_steps: 0,
                ..
            } if step_id == "copy"
        ));
        assert_eq!(observed_later_calls.get(), 0);
        assert!(engine.runtime().audit().is_empty());
        assert!(engine.dataflow_snapshot().unwrap().outputs().is_empty());
    }

    #[test]
    fn dataflow_checkpoint_binds_context_without_persisting_raw_values() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "first",
                    "let result = {value: workflow.input.value}\nresult",
                ),
                WorkflowStep::new(
                    "second",
                    "use mod.tool\nlet result = tool.call(\"text.echo\", \"suffix\")\nresult",
                ),
            ])
            .unwrap();
        let approval = engine
            .approve_dataflow_with_step_capability_policies(
                &plan,
                WorkflowData::new(serde_json::json!({
                    "value": 7,
                    "secret": "do-not-persist"
                }))
                .unwrap(),
                vec![
                    WorkflowStepCapabilityPolicy::new("first", Vec::<CapabilityLeaseGrant>::new()),
                    WorkflowStepCapabilityPolicy::new("second", Vec::<CapabilityLeaseGrant>::new()),
                ],
            )
            .unwrap();

        let error = engine.execute_dataflow(&plan, approval).unwrap_err();
        assert!(matches!(
            error,
            WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 1,
                ..
            } if step_id == "second"
        ));
        let partial = engine.take_dataflow_snapshot().unwrap();
        assert_eq!(
            partial.output("first"),
            Some(&serde_json::json!({"value": 7}))
        );

        let checkpoint = engine
            .dataflow_checkpoint_after(&plan, &partial, 1)
            .unwrap();
        let encoded = checkpoint.to_json().unwrap();
        let decoded = WorkflowCheckpoint::from_json(&encoded).unwrap();

        assert_eq!(decoded, checkpoint);
        assert!(checkpoint.data_fingerprint().is_some());
        assert!(encoded.contains("data_fingerprint"));
        assert!(!encoded.contains("do-not-persist"));
        assert!(!encoded.contains("\"value\":7"));
        assert_eq!(
            engine.approve_resume(&plan, &checkpoint).unwrap_err(),
            WorkflowError::Checkpoint(WorkflowCheckpointError::DataflowContextRequired)
        );

        let mut tampered_value: serde_json::Value =
            serde_json::from_str(&partial.to_json().unwrap()).unwrap();
        tampered_value["input"]["value"] = serde_json::json!(8);
        let tampered =
            WorkflowData::from_json(&serde_json::to_string(&tampered_value).unwrap()).unwrap();
        assert_eq!(
            engine
                .approve_dataflow_resume(&plan, &checkpoint, tampered)
                .unwrap_err(),
            WorkflowError::Checkpoint(WorkflowCheckpointError::DataflowContextMismatch)
        );

        let resume_approval = engine
            .approve_dataflow_resume_with_step_capability_policies(
                &plan,
                &checkpoint,
                partial,
                vec![WorkflowStepCapabilityPolicy::new(
                    "second",
                    [CapabilityLeaseGrant::new("text.echo", 1)],
                )],
            )
            .unwrap();
        let resumed = engine
            .resume_dataflow(&plan, &checkpoint, resume_approval)
            .unwrap();

        assert_eq!(resumed.output("second"), Some(&serde_json::json!("suffix")));
        assert_eq!(engine.runtime().audit().len(), 2);
    }

    #[test]
    fn dataflow_contract_checkpoint_prevents_resume_downgrade_and_policy_drift() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new("prepare", "let result = {actual: 1}\nresult"),
                WorkflowStep::new(
                    "dispatch",
                    "use mod.tool\ntool.call(\"text.echo\", \"not granted\")",
                ),
            ])
            .unwrap();
        let approval = engine
            .approve_dataflow_with_step_capability_policies(
                &plan,
                WorkflowData::new(serde_json::json!({"value": 7})).unwrap(),
                vec![
                    WorkflowStepCapabilityPolicy::new(
                        "prepare",
                        Vec::<CapabilityLeaseGrant>::new(),
                    ),
                    WorkflowStepCapabilityPolicy::new(
                        "dispatch",
                        Vec::<CapabilityLeaseGrant>::new(),
                    ),
                ],
            )
            .unwrap();

        assert!(matches!(
            engine.execute_dataflow(&plan, approval),
            Err(WorkflowError::StepFailed {
                ref step_id,
                completed_steps: 1,
                ..
            }) if step_id == "dispatch"
        ));
        let mut partial = engine.take_dataflow_snapshot().unwrap();
        let contract = workflow_data_contract(
            serde_json::json!({
                "type": "object",
                "properties": {"value": {"type": "integer"}},
                "required": ["value"],
                "additionalProperties": false
            }),
            vec![
                (
                    "prepare",
                    serde_json::json!({
                        "type": "object",
                        "properties": {"actual": {"type": "integer"}},
                        "required": ["actual"],
                        "additionalProperties": false
                    }),
                ),
                ("dispatch", serde_json::json!({"type": "string"})),
            ],
        );
        let contract_fingerprint = contract.fingerprint();
        let checkpoint = engine
            .dataflow_checkpoint_after_with_contract(&plan, &mut partial, &contract, 1)
            .unwrap();
        let encoded = checkpoint.to_json().unwrap();

        assert_eq!(
            checkpoint.data_contract_fingerprint(),
            Some(contract_fingerprint.as_str())
        );
        assert!(encoded.contains("data_contract_fingerprint"));
        assert!(!encoded.contains("\"properties\""));
        assert_eq!(
            engine
                .approve_dataflow_resume(&plan, &checkpoint, partial.clone())
                .unwrap_err(),
            WorkflowError::Checkpoint(WorkflowCheckpointError::DataflowContractRequired)
        );

        let changed_contract = workflow_data_contract(
            serde_json::json!({
                "type": "object",
                "description": "new host policy revision",
                "properties": {"value": {"type": "integer"}},
                "required": ["value"],
                "additionalProperties": false
            }),
            vec![
                (
                    "prepare",
                    serde_json::json!({
                        "type": "object",
                        "properties": {"actual": {"type": "integer"}},
                        "required": ["actual"],
                        "additionalProperties": false
                    }),
                ),
                ("dispatch", serde_json::json!({"type": "string"})),
            ],
        );

        let error = engine
            .approve_dataflow_resume_with_contract_and_step_capability_policies(
                &plan,
                &checkpoint,
                partial.clone(),
                changed_contract,
                vec![WorkflowStepCapabilityPolicy::new(
                    "dispatch",
                    [CapabilityLeaseGrant::new("absent.tool", 1)],
                )],
            )
            .unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::Checkpoint(WorkflowCheckpointError::DataflowContractMismatch)
        ));

        let approval = engine
            .approve_dataflow_resume_with_contract_and_step_capability_policies(
                &plan,
                &checkpoint,
                partial,
                contract,
                vec![WorkflowStepCapabilityPolicy::new(
                    "dispatch",
                    [CapabilityLeaseGrant::new("text.echo", 1)],
                )],
            )
            .unwrap();
        let resumed = engine
            .resume_dataflow(&plan, &checkpoint, approval)
            .unwrap();

        assert_eq!(
            resumed.output("dispatch"),
            Some(&serde_json::json!("not granted"))
        );
    }

    #[test]
    fn ordinary_checkpoint_inherits_a_contract_digest_from_bound_workflow_data() {
        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![WorkflowStep::new(
                "copy",
                "let result = workflow.input\nresult",
            )])
            .unwrap();
        let contract = workflow_data_contract(
            serde_json::json!({
                "type": "object",
                "properties": {"value": {"type": "integer"}},
                "required": ["value"],
                "additionalProperties": false
            }),
            vec![(
                "copy",
                serde_json::json!({
                    "type": "object",
                    "properties": {"value": {"type": "integer"}},
                    "required": ["value"],
                    "additionalProperties": false
                }),
            )],
        );
        let contract_fingerprint = contract.fingerprint();
        let approval = engine
            .approve_dataflow_with_contract_and_step_capability_policies(
                &plan,
                WorkflowData::new(serde_json::json!({"value": 7})).unwrap(),
                contract,
                vec![WorkflowStepCapabilityPolicy::new(
                    "copy",
                    Vec::<CapabilityLeaseGrant>::new(),
                )],
            )
            .unwrap();
        let data = engine.execute_dataflow(&plan, approval).unwrap();
        let persisted = data.to_json().unwrap();
        let restored = WorkflowData::from_json(&persisted).unwrap();
        let checkpoint = engine
            .dataflow_checkpoint_after(&plan, &restored, 1)
            .unwrap();

        assert_eq!(
            data.contract_fingerprint(),
            Some(contract_fingerprint.as_str())
        );
        assert!(persisted.contains("contract_fingerprint"));
        assert!(!persisted.contains("\"properties\""));
        assert_eq!(
            restored.contract_fingerprint(),
            Some(contract_fingerprint.as_str())
        );
        assert_eq!(
            checkpoint.data_contract_fingerprint(),
            Some(contract_fingerprint.as_str())
        );
        assert_eq!(
            engine
                .approve_dataflow_resume(&plan, &checkpoint, restored)
                .unwrap_err(),
            WorkflowError::Checkpoint(WorkflowCheckpointError::DataflowContractRequired)
        );
    }

    #[test]
    fn dataflow_context_survives_local_and_external_awaits() {
        let mut local_runtime = CapabilityRuntime::default();
        local_runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let mut local_engine = WorkflowEngine::new(local_runtime);
        let local_plan = local_engine
            .plan(vec![WorkflowStep::new(
                "local-await",
                "use mod.tool\n\
                 let text = tool.start(\"text.echo\", workflow.input.message).await()\n\
                 let result = {message: text}\n\
                 result",
            )])
            .unwrap();
        let local_approval = local_engine
            .approve_dataflow_with_step_capability_policies(
                &local_plan,
                WorkflowData::new(serde_json::json!({"message": "local"})).unwrap(),
                vec![WorkflowStepCapabilityPolicy::new(
                    "local-await",
                    [CapabilityLeaseGrant::new("text.echo", 1)],
                )],
            )
            .unwrap();
        let local_data = local_engine
            .execute_dataflow(&local_plan, local_approval)
            .unwrap();
        assert_eq!(
            local_data.output("local-await"),
            Some(&serde_json::json!({"message": "local"}))
        );

        let mut external_runtime = CapabilityRuntime::default();
        external_runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let mut external_engine = WorkflowEngine::new(external_runtime);
        let external_plan = external_engine
            .plan(vec![WorkflowStep::new(
                "remote-await",
                "use mod.tool\n\
                 let text = tool.start(\"text.remote\", workflow.input.message).await()\n\
                 let result = {message: text}\n\
                 result",
            )])
            .unwrap();
        let external_approval = external_engine
            .approve_dataflow_with_step_capability_policies(
                &external_plan,
                WorkflowData::new(serde_json::json!({"message": "remote"})).unwrap(),
                vec![WorkflowStepCapabilityPolicy::new(
                    "remote-await",
                    [CapabilityLeaseGrant::new("text.remote", 1)],
                )],
            )
            .unwrap();

        let suspended = external_engine
            .execute_dataflow(&external_plan, external_approval)
            .unwrap_err();
        assert!(matches!(suspended, WorkflowError::StepSuspended { .. }));
        assert_eq!(
            external_engine.dataflow_snapshot().unwrap().input(),
            &serde_json::json!({"message": "remote"})
        );
        let invocation = external_engine.claim_next_external_tool().unwrap();
        external_engine
            .complete_external_tool(invocation.id, Ok("finished".to_owned()))
            .unwrap();

        assert_eq!(
            external_engine
                .dataflow_snapshot()
                .unwrap()
                .output("remote-await"),
            Some(&serde_json::json!({"message": "finished"}))
        );
    }

    #[test]
    fn dataflow_contract_survives_external_await_and_blocks_later_step() {
        let later_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_later_calls = later_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), move |_| {
                later_calls.set(later_calls.get() + 1);
                Ok("must not run".to_owned())
            })
            .unwrap();
        let mut engine = WorkflowEngine::new(runtime);
        let plan = engine
            .plan(vec![
                WorkflowStep::new(
                    "remote-await",
                    "use mod.tool\n\
                     let text = tool.start(\"text.remote\", workflow.input.message).await()\n\
                     let result = {message: text}\n\
                     result",
                ),
                WorkflowStep::new(
                    "later",
                    "use mod.tool\ntool.call(\"text.echo\", \"must not run\")",
                ),
            ])
            .unwrap();
        let contract = workflow_data_contract(
            serde_json::json!({
                "type": "object",
                "properties": {"message": {"type": "string"}},
                "required": ["message"],
                "additionalProperties": false
            }),
            vec![
                (
                    "remote-await",
                    serde_json::json!({
                        "type": "object",
                        "properties": {"total": {"type": "integer"}},
                        "required": ["total"],
                        "additionalProperties": false
                    }),
                ),
                ("later", serde_json::json!({"type": "string"})),
            ],
        );
        let approval = engine
            .approve_dataflow_with_contract_and_step_capability_policies(
                &plan,
                WorkflowData::new(serde_json::json!({"message": "remote"})).unwrap(),
                contract,
                vec![
                    WorkflowStepCapabilityPolicy::new(
                        "remote-await",
                        [CapabilityLeaseGrant::new("text.remote", 1)],
                    ),
                    WorkflowStepCapabilityPolicy::new(
                        "later",
                        [CapabilityLeaseGrant::new("text.echo", 1)],
                    ),
                ],
            )
            .unwrap();

        assert!(matches!(
            engine.execute_dataflow(&plan, approval),
            Err(WorkflowError::StepSuspended {
                ref step_id,
                completed_steps: 0,
            }) if step_id == "remote-await"
        ));
        let invocation = engine.claim_next_external_tool().unwrap();
        let error = engine
            .complete_external_tool(invocation.id, Ok("finished".to_owned()))
            .unwrap_err();

        assert!(matches!(
            error,
            WorkflowError::DataflowContractOutput {
                ref step_id,
                completed_steps: 0,
                ..
            } if step_id == "remote-await"
        ));
        assert!(!engine.has_suspended_execution());
        assert_eq!(observed_later_calls.get(), 0);
        assert_eq!(engine.runtime().audit().len(), 1);
        assert!(engine.dataflow_snapshot().unwrap().outputs().is_empty());
    }
}
