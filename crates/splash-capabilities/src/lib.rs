#![forbid(unsafe_code)]

//! A deny-by-default, auditable bridge from Splash to trusted Rust tools.
//!
//! A tool is registered for one runtime instance. A script receives no native
//! access by naming a tool: the host must register it with an explicit policy.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::ops::Index;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use makepad_script::{
    id, id_lut, script_args_def, script_err_not_allowed, script_err_unexpected, script_value,
    LiveId, ScriptHandle, ScriptHandleGc, ScriptHandleType, ScriptIp, ScriptThreadId, ScriptValue,
    NIL,
};
use serde::{de::DeserializeOwned, Serialize};
pub use serde_json::{json, Value as JsonValue};
use splash_core::{vm, Evaluation, ExecutionLimits, Runtime, RuntimeError};
pub use splash_protocol::{
    canonical_operation_input_bytes, AuthenticatedWorkerMessage, CapabilityManifest,
    OperationCompensationBinding, OperationCompensationRequest, OperationCompensationResult,
    OperationDispatchRequest, OperationReconcileRequest, OperationReconcileResult, OperationStatus,
    ProtocolError, SessionAuthenticator, SessionKey, SessionRole,
    ToolInvocation as WorkerInvocation, ToolPayload as WorkerPayload, ToolResult as WorkerResult,
    WorkerCancellationOutcome, WorkerCancellationRequest, WorkerCancellationResult,
    WorkerCompensationAdmission, WorkerCompensationRecord, WorkerMessage, WorkerOperationAdmission,
    WorkerOperationJournal, WorkerOperationState, WorkerOperationStateKind,
};
use splash_protocol::{EnvelopeFormat, SessionAuthorizer};
pub use splash_schema::{JsonSchema, SchemaError};

/// Host-enforced deadline and termination wrapper for worker transports.
///
/// The wrapper is transport-agnostic so platform containment backends can
/// supply their own lifecycle supervisor.
pub mod bounded_worker;

/// Bounded host-owned text files exposed only through opaque identifiers.
pub mod fixed_file_catalog;

/// Bounded host-owned HTTP endpoints exposed only through opaque identifiers.
#[cfg(feature = "http-endpoint-catalog")]
pub mod http_endpoint_catalog;

/// Read-only native credential-store resolver for endpoint-bound HTTPS secrets.
///
/// This optional integration uses explicit native macOS, iOS, and Windows
/// credential implementations. It never falls back to keyring-rs's
/// process-local mock store on unsupported targets.
#[cfg(feature = "platform-keyring-secret-resolver")]
pub mod platform_keyring_secret_resolver;

/// Sealed static-catalog runtime profile for mobile and embedded hosts.
///
/// It accepts only app-provided local adapters during setup, then exposes
/// canonical Splash evaluation and bounded host pumping without an API for
/// registering tools or dispatching external work.
pub mod mobile;

/// Connects the generic bounded worker transport to the Linux Bubblewrap
/// watchdog lifecycle.
#[cfg(feature = "bubblewrap-watchdog")]
pub mod bubblewrap_watchdog;

/// Authenticated in-process worker transport for app-provided adapters.
///
/// This optional module is useful for mobile and embedded hosts that run a
/// static adapter catalog inside their application. It is not OS containment.
#[cfg(feature = "in-process-worker")]
pub mod in_process_worker;

/// Bounded JSON-line worker transport for host-provided pipe or socket I/O.
///
/// This optional module authenticates ordinary worker frames and one-shot
/// durable-operation exchanges, but does not create or contain a process.
#[cfg(feature = "json-line-worker")]
pub mod json_line_worker;

/// Concurrent authenticated JSON-line transport for cancellable ordinary
/// worker invocations.
#[cfg(feature = "json-line-worker")]
pub mod multiplexed_worker;

/// Maximum number of tool promises a runtime may retain at once.
///
/// Hosts that need a lower bound for a constrained device can choose one with
/// [`CapabilityRuntime::with_limits_and_pending`].
pub const DEFAULT_MAX_PENDING_TOOLS: usize = 64;
/// Default maximum number of host-visible capabilities in one runtime catalog.
pub const DEFAULT_MAX_REGISTERED_TOOLS: usize = 128;
/// Default maximum byte length of the serialized host-visible tool catalog.
pub const DEFAULT_MAX_TOOL_CATALOG_BYTES: usize = 512 * 1024;
/// Maximum UTF-8 byte length of a registered capability name.
pub const MAX_TOOL_NAME_BYTES: usize = 128;
/// Default number of recent capability audit events retained in memory.
///
/// Hosts that require complete audit retention must export events to their own
/// authenticated storage or sink. This in-process view intentionally bounds
/// memory instead of acting as a durable audit log.
pub const DEFAULT_MAX_AUDIT_EVENTS: usize = 1_024;
/// Absolute maximum capacity accepted for the in-memory capability audit view.
///
/// Use a smaller host-selected value on constrained targets and export entries
/// to durable storage when retention beyond this in-process window is needed.
pub const MAX_AUDIT_EVENTS: usize = 8_192;
pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 4 * 1024;
pub const MAX_TOOL_SCHEMA_BYTES: usize = 32 * 1024;
pub const DEFAULT_MAX_STREAM_CHUNKS: usize = 64;
pub const DEFAULT_MAX_STREAM_CHUNK_BYTES: usize = 8 * 1024;
pub const DEFAULT_MAX_STREAM_TOTAL_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_STREAM_EMITTED_BYTES: usize = 64 * 1024;

const CAPABILITY_CATALOG_FINGERPRINT_DOMAIN: &[u8] = b"splash-capability-catalog-v1";
const CAPABILITY_SESSION_NONCE_DOMAIN: &[u8] = b"splash-capability-session-nonce-v1";
const CAPABILITY_AUDIT_LABEL_DOMAIN: &[u8] = b"splash-capability-audit-label-v1";
const UNRECOGNIZED_AUDIT_TOOL_PREFIX: &str = "unrecognized:";

static NEXT_CAPABILITY_SESSION: AtomicU64 = AtomicU64::new(1);

fn capability_session_nonce(session_id: u64) -> String {
    let mut entropy = [0_u8; 32];
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_SESSION_NONCE_DOMAIN);
    hasher.update(&session_id.to_be_bytes());
    if getrandom::fill(&mut entropy).is_ok() {
        hasher.update(&entropy);
    } else {
        // Keep distinct live runtimes separate when a constrained target has
        // no OS entropy source. Durable hosts should still use their own
        // workflow operation key across a process restart.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&std::process::id().to_be_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn is_valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOOL_NAME_BYTES
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Serialization contract for a capability's input and output envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDataFormat {
    /// UTF-8 text passed directly to the registered handler.
    Text,
    /// A JSON object or array validated at the capability boundary.
    Json,
}

fn envelope_format(format: ToolDataFormat) -> EnvelopeFormat {
    match format {
        ToolDataFormat::Text => EnvelopeFormat::Text,
        ToolDataFormat::Json => EnvelopeFormat::Json,
    }
}

/// Where a deferred tool's work is permitted to run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDispatch {
    /// The trusted runtime invokes its registered Rust handler during a pump.
    HostPump,
    /// The host must explicitly claim and complete the work outside the VM.
    External,
}

/// Host-side classification for a failure that may be retried externally.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    /// A temporary transport or service failure.
    Transient,
    /// The downstream service requested backoff before another attempt.
    RateLimited,
}

/// Bounded host-visible output streaming for an external deferred operation.
///
/// Source bytes are supplied by the external worker. Emitted bytes are the
/// redacted chunks returned to the trusted host by
/// [`CapabilityRuntime::push_external_tool_chunk`]. Neither is exposed to
/// Splash source before terminal completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolStreamPolicy {
    /// Maximum accepted chunks across every attempt of one operation.
    pub max_chunks: usize,
    /// Maximum source bytes in any individual worker chunk.
    pub max_chunk_bytes: usize,
    /// Maximum aggregate source bytes accepted from the worker.
    pub max_total_bytes: usize,
    /// Maximum aggregate bytes released after redaction.
    pub max_emitted_bytes: usize,
}

impl ToolStreamPolicy {
    pub fn new(
        max_chunks: usize,
        max_chunk_bytes: usize,
        max_total_bytes: usize,
        max_emitted_bytes: usize,
    ) -> Self {
        Self {
            max_chunks,
            max_chunk_bytes,
            max_total_bytes,
            max_emitted_bytes,
        }
    }

    fn validate(&self) -> Result<(), ToolRegistrationError> {
        if self.max_chunks == 0
            || self.max_chunk_bytes == 0
            || self.max_total_bytes == 0
            || self.max_emitted_bytes == 0
        {
            return Err(ToolRegistrationError::InvalidPolicy(
                "stream limits must be greater than zero",
            ));
        }
        if self.max_chunk_bytes > self.max_total_bytes {
            return Err(ToolRegistrationError::InvalidPolicy(
                "max stream chunk bytes cannot exceed the total stream byte limit",
            ));
        }
        Ok(())
    }
}

impl Default for ToolStreamPolicy {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_STREAM_CHUNKS,
            DEFAULT_MAX_STREAM_CHUNK_BYTES,
            DEFAULT_MAX_STREAM_TOTAL_BYTES,
            DEFAULT_MAX_STREAM_EMITTED_BYTES,
        )
    }
}

/// Trusted host metadata supplied to an LLM orchestrator or operator UI.
///
/// Metadata is never installed as a script module and conveys no authority.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ToolMetadata {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<JsonValue>,
}

impl ToolMetadata {
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            ..Self::default()
        }
    }

    pub fn with_input_schema(mut self, schema: JsonValue) -> Self {
        self.input_schema = Some(schema);
        self
    }

    pub fn with_output_schema(mut self, schema: JsonValue) -> Self {
        self.output_schema = Some(schema);
        self
    }

    fn validate_for(&self, format: ToolDataFormat) -> Result<(), ToolRegistrationError> {
        if self.description.len() > MAX_TOOL_DESCRIPTION_BYTES {
            return Err(ToolRegistrationError::InvalidMetadata(
                "tool description exceeds the byte limit",
            ));
        }
        if format != ToolDataFormat::Json
            && (self.input_schema.is_some() || self.output_schema.is_some())
        {
            return Err(ToolRegistrationError::InvalidMetadata(
                "schemas require a JSON tool policy",
            ));
        }
        for schema in [&self.input_schema, &self.output_schema]
            .into_iter()
            .flatten()
        {
            if !schema.is_object() {
                return Err(ToolRegistrationError::InvalidMetadata(
                    "tool schemas must be JSON objects",
                ));
            }
            let byte_len = serde_json::to_vec(schema)
                .map_err(|_| ToolRegistrationError::InvalidMetadata("tool schema is invalid"))?
                .len();
            if byte_len > MAX_TOOL_SCHEMA_BYTES {
                return Err(ToolRegistrationError::InvalidMetadata(
                    "tool schema exceeds the byte limit",
                ));
            }
        }
        Ok(())
    }
}

/// Aggregate bounds for the host-visible capability catalog.
///
/// These limits complement the per-tool metadata and schema bounds. They keep
/// a dynamic registration path from growing an LLM prompt or embedded host
/// allocation without a deliberate host configuration change. They do not
/// grant any capability and are not visible to Splash source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityCatalogLimits {
    pub max_tools: usize,
    pub max_serialized_bytes: usize,
}

impl CapabilityCatalogLimits {
    fn validate(self) -> Result<Self, RuntimeError> {
        if self.max_tools == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_catalog_tools must be greater than zero",
            ));
        }
        if self.max_serialized_bytes == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_catalog_serialized_bytes must be greater than zero",
            ));
        }
        Ok(self)
    }
}

impl Default for CapabilityCatalogLimits {
    fn default() -> Self {
        Self {
            max_tools: DEFAULT_MAX_REGISTERED_TOOLS,
            max_serialized_bytes: DEFAULT_MAX_TOOL_CATALOG_BYTES,
        }
    }
}

/// Stable, serializable description of a currently granted capability.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub format: ToolDataFormat,
    pub dispatch: ToolDispatch,
    /// Whether the published JSON schemas are executed at the tool boundary.
    ///
    /// `false` means any schemas are prompt metadata only. Text tools always
    /// report `false` because they have no JSON envelope contract.
    pub contract_enforced: bool,
    pub max_calls: usize,
    pub max_attempts: u32,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_deferred_millis: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<ToolStreamPolicy>,
    #[serde(flatten)]
    pub metadata: ToolMetadata,
}

/// Stable BLAKE3 identity of the complete host-visible capability catalog.
///
/// This is process-local policy identity, not a credential. It includes every
/// published descriptor field, including executable-contract status, and is
/// used to invalidate an approval when a runtime catalog changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityCatalogFingerprint(String);

impl CapabilityCatalogFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for CapabilityCatalogFingerprint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Executable input/output schemas for a JSON capability.
#[derive(Clone, Debug, PartialEq)]
pub struct JsonToolContract {
    input_schema: JsonValue,
    output_schema: JsonValue,
    input: JsonSchema,
    output: JsonSchema,
}

impl JsonToolContract {
    /// Compiles the input and output schemas before the tool becomes visible
    /// to a Splash script.
    pub fn new(input_schema: JsonValue, output_schema: JsonValue) -> Result<Self, SchemaError> {
        let input = JsonSchema::compile(input_schema.clone())?;
        let output = JsonSchema::compile(output_schema.clone())?;
        Ok(Self {
            input_schema,
            output_schema,
            input,
            output,
        })
    }

    /// Returns the exact input schema published in the host-side catalog.
    pub fn input_schema(&self) -> &JsonValue {
        &self.input_schema
    }

    /// Returns the exact output schema published in the host-side catalog.
    pub fn output_schema(&self) -> &JsonValue {
        &self.output_schema
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolPolicy {
    pub name: String,
    pub max_calls: usize,
    /// Maximum external dispatch attempts for one deferred operation.
    pub max_attempts: u32,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    /// Maximum lifetime of one deferred operation after tool.start reserves it.
    pub max_deferred_duration: Option<Duration>,
    /// Optional host-visible streaming limits for an external deferred tool.
    pub stream: Option<ToolStreamPolicy>,
    pub data_format: ToolDataFormat,
}

impl ToolPolicy {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            max_calls: 1,
            max_attempts: 1,
            max_input_bytes: 16 * 1024,
            max_output_bytes: 64 * 1024,
            max_deferred_duration: None,
            stream: None,
            data_format: ToolDataFormat::Text,
        }
    }

    /// Creates a policy for JSON object/array input and output envelopes.
    pub fn json(name: impl Into<String>) -> Self {
        let mut policy = Self::new(name);
        policy.data_format = ToolDataFormat::Json;
        policy
    }

    /// Enables bounded host-visible streaming for a deferred external tool.
    pub fn with_stream(mut self, stream: ToolStreamPolicy) -> Self {
        self.stream = Some(stream);
        self
    }

    fn validate(&self) -> Result<(), ToolRegistrationError> {
        if !is_valid_tool_name(&self.name) {
            return Err(ToolRegistrationError::InvalidName(self.name.clone()));
        }
        if self.max_calls == 0 {
            return Err(ToolRegistrationError::InvalidPolicy(
                "max_calls must be greater than zero",
            ));
        }
        if self.max_attempts == 0 {
            return Err(ToolRegistrationError::InvalidPolicy(
                "max_attempts must be greater than zero",
            ));
        }
        if self.max_input_bytes == 0 || self.max_output_bytes == 0 {
            return Err(ToolRegistrationError::InvalidPolicy(
                "tool byte limits must be greater than zero",
            ));
        }
        if let Some(stream) = &self.stream {
            stream.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolRequest {
    pub name: String,
    pub input: String,
    pub call_index: usize,
}

/// JSON-decoded request passed to [`CapabilityHost::register_json_tool`].
#[derive(Clone, Debug, PartialEq)]
pub struct JsonToolRequest {
    pub name: String,
    pub input: JsonValue,
    pub call_index: usize,
}

/// One named capability and the call budget granted to a process-local lease.
///
/// The runtime validates this request against the current registered tool
/// policy when it creates the lease. A lease may only narrow a registered
/// capability; it can never add a name or widen its call budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityLeaseGrant {
    pub name: String,
    pub max_calls: usize,
}

impl CapabilityLeaseGrant {
    pub fn new(name: impl Into<String>, max_calls: usize) -> Self {
        Self {
            name: name.into(),
            max_calls,
        }
    }
}

/// Trusted host hook evaluated immediately before a lease permits one tool
/// invocation.
///
/// The hook can only deny a call that the immutable lease has already
/// authorized. It is synchronous by design: hosts that need asynchronous user
/// confirmation should use a deferred external tool and claim it through their
/// own lifecycle rather than blocking the VM inside this callback.
pub trait ToolCallAuthorizer {
    fn authorize(
        &mut self,
        request: &ToolRequest,
        descriptor: &ToolDescriptor,
    ) -> Result<(), ToolError>;
}

impl<F> ToolCallAuthorizer for F
where
    F: FnMut(&ToolRequest, &ToolDescriptor) -> Result<(), ToolError>,
{
    fn authorize(
        &mut self,
        request: &ToolRequest,
        descriptor: &ToolDescriptor,
    ) -> Result<(), ToolError> {
        self(request, descriptor)
    }
}

/// Rejection while issuing, activating, or using a capability lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityLeaseError {
    UnknownTool(String),
    DuplicateTool(String),
    ZeroCallLimit(String),
    CallLimitExceedsPolicy {
        tool: String,
        requested: usize,
        maximum: usize,
    },
    RuntimeMismatch,
    CatalogChanged,
    LeaseAlreadyActive,
    CatalogEncoding,
}

impl Display for CapabilityLeaseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTool(tool) => write!(formatter, "unknown capability lease tool: {tool}"),
            Self::DuplicateTool(tool) => {
                write!(formatter, "duplicate capability lease tool: {tool}")
            }
            Self::ZeroCallLimit(tool) => {
                write!(
                    formatter,
                    "capability lease call limit must be greater than zero: {tool}"
                )
            }
            Self::CallLimitExceedsPolicy {
                tool,
                requested,
                maximum,
            } => write!(
                formatter,
                "capability lease for {tool} requests {requested} calls but policy allows {maximum}"
            ),
            Self::RuntimeMismatch => {
                formatter.write_str("capability lease belongs to a different runtime")
            }
            Self::CatalogChanged => {
                formatter.write_str("capability catalog changed after the lease was issued")
            }
            Self::LeaseAlreadyActive => formatter.write_str("a capability lease is already active"),
            Self::CatalogEncoding => formatter.write_str("capability catalog could not be encoded"),
        }
    }
}

impl std::error::Error for CapabilityLeaseError {}

/// Execution failure returned when a lease cannot be activated or Splash
/// evaluation itself fails.
#[derive(Debug)]
pub enum CapabilityLeaseEvaluationError {
    Lease(CapabilityLeaseError),
    Runtime(RuntimeError),
}

impl Display for CapabilityLeaseEvaluationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lease(error) => write!(formatter, "capability lease error: {error}"),
            Self::Runtime(error) => write!(formatter, "Splash evaluation error: {error}"),
        }
    }
}

impl std::error::Error for CapabilityLeaseEvaluationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lease(error) => Some(error),
            Self::Runtime(error) => Some(error),
        }
    }
}

struct CapabilityLeaseState {
    runtime_id: u64,
    catalog_fingerprint: CapabilityCatalogFingerprint,
    grants: BTreeMap<String, usize>,
    calls: BTreeMap<String, usize>,
    authorizer: Option<Box<dyn ToolCallAuthorizer>>,
}

impl CapabilityLeaseState {
    fn validate_for(
        &self,
        runtime_id: u64,
        catalog_fingerprint: &CapabilityCatalogFingerprint,
    ) -> Result<(), CapabilityLeaseError> {
        if self.runtime_id != runtime_id {
            return Err(CapabilityLeaseError::RuntimeMismatch);
        }
        if self.catalog_fingerprint != *catalog_fingerprint {
            return Err(CapabilityLeaseError::CatalogChanged);
        }
        Ok(())
    }

    fn authorize(
        &mut self,
        request: &ToolRequest,
        descriptor: &ToolDescriptor,
    ) -> Result<(), ToolError> {
        let Some(maximum) = self.grants.get(&request.name).copied() else {
            return Err(ToolError::Denied(format!(
                "{} is not granted by the active capability lease",
                request.name
            )));
        };
        let calls = self.calls.get(&request.name).copied().unwrap_or_default();
        if calls >= maximum {
            return Err(ToolError::Denied(format!(
                "{} exhausted its capability lease call budget of {maximum}",
                request.name
            )));
        }
        if let Some(authorizer) = self.authorizer.as_mut() {
            authorizer.authorize(request, descriptor)?;
        }
        self.calls
            .insert(request.name.clone(), calls.saturating_add(1));
        Ok(())
    }
}

/// A process-local, immutable capability policy with stateful call accounting.
///
/// A lease is issued by one `CapabilityRuntime`, bound to that runtime's exact
/// catalog fingerprint, and normally moved into a workflow approval. The
/// runtime holds its state across `await`/resume so a continuation cannot
/// escape its approved tool set or reset its lease-local call budget.
pub struct CapabilityLease {
    state: Rc<RefCell<CapabilityLeaseState>>,
}

impl fmt::Debug for CapabilityLease {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let state = self.state.borrow();
        formatter
            .debug_struct("CapabilityLease")
            .field("catalog_fingerprint", &state.catalog_fingerprint)
            .field("grants", &state.grants)
            .field("calls", &state.calls)
            .field("has_authorizer", &state.authorizer.is_some())
            .finish()
    }
}

impl CapabilityLease {
    /// Returns the catalog fingerprint that this lease was issued against.
    pub fn catalog_fingerprint(&self) -> CapabilityCatalogFingerprint {
        self.state.borrow().catalog_fingerprint.clone()
    }

    /// Returns the attenuated call grants in stable name order.
    pub fn grants(&self) -> Vec<CapabilityLeaseGrant> {
        self.state
            .borrow()
            .grants
            .iter()
            .map(|(name, max_calls)| CapabilityLeaseGrant::new(name.clone(), *max_calls))
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolError {
    Denied(String),
    Failed(String),
    Cancelled(String),
    TimedOut(String),
}

impl Display for ToolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(message) => write!(formatter, "tool call denied: {message}"),
            Self::Failed(message) => write!(formatter, "tool call failed: {message}"),
            Self::Cancelled(message) => write!(formatter, "tool call cancelled: {message}"),
            Self::TimedOut(message) => write!(formatter, "tool call timed out: {message}"),
        }
    }
}

impl std::error::Error for ToolError {}

/// Opaque host-side identifier for a claimed external tool operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExternalToolId(u64);

/// A deferred tool invocation that the host has explicitly claimed for
/// external execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalToolInvocation {
    pub id: ExternalToolId,
    pub name: String,
    pub input: String,
    pub call_index: usize,
    pub attempt: u32,
    pub max_attempts: u32,
    pub idempotency_key: String,
    pub stream: Option<ToolStreamPolicy>,
    pub format: ToolDataFormat,
    pub max_output_bytes: usize,
    pub remaining_deadline_millis: Option<u64>,
}

impl ExternalToolInvocation {
    /// Converts this host-visible invocation into the exact worker payload.
    ///
    /// JSON input is parsed back into its validated object-or-array envelope
    /// rather than forwarded as an ad hoc display string. This lets a host
    /// bind a durable worker operation to the same canonical bytes used by
    /// [`canonical_operation_input_bytes`].
    pub fn worker_payload(&self) -> Result<WorkerPayload, ExternalToolError> {
        match self.format {
            ToolDataFormat::Text => Ok(WorkerPayload::Text(self.input.clone())),
            ToolDataFormat::Json => {
                let payload = serde_json::from_str(&self.input)
                    .map_err(|_| ExternalToolError::InvalidPayload(self.id))?;
                let payload = WorkerPayload::Json(payload);
                payload
                    .validate_for(EnvelopeFormat::Json)
                    .map_err(|_| ExternalToolError::InvalidPayload(self.id))?;
                Ok(payload)
            }
        }
    }

    /// Returns the stable durable-operation input bytes for this invocation.
    ///
    /// The result is suitable for a host-owned operation ledger. It is not an
    /// authorization credential and must not be logged when input may contain
    /// sensitive application data.
    pub fn canonical_input_bytes(&self) -> Result<Vec<u8>, ExternalToolError> {
        canonical_operation_input_bytes(&self.worker_payload()?)
            .map_err(ExternalToolError::Protocol)
    }
}

/// Host-only request to cooperatively cancel one claimed external operation.
///
/// This value identifies the already-dispatched work without repeating its
/// input. It is neither authority nor proof of cancellation. The host must
/// pass it to the adapter that owns the operation and wait for that adapter's
/// acknowledgement before confirming cancellation in the runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalToolCancellationRequest {
    pub id: ExternalToolId,
    pub name: String,
    pub call_index: usize,
    pub attempt: u32,
    pub idempotency_key: String,
}

/// A redacted text chunk emitted by a claimed external tool operation.
///
/// It is returned only to the trusted host that owns the runtime. Splash code
/// cannot poll or subscribe to these chunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalToolStreamChunk {
    pub id: ExternalToolId,
    pub name: String,
    pub call_index: usize,
    pub attempt: u32,
    pub chunk_index: usize,
    pub idempotency_key: String,
    pub text: String,
}

/// A keyed worker frame for an external operation reconciliation request.
///
/// The contained request identifies work by the non-authorizing operation key,
/// never by [`ExternalToolId`]. Send `frame` through the host's worker
/// transport and keep `request` for
/// [`CapabilityRuntime::reconcile_authenticated_external_tool`].
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedReconciliationRequest {
    pub request: OperationReconcileRequest,
    pub frame: AuthenticatedWorkerMessage,
}

/// Outcome of reconciling an externally dispatched operation.
#[derive(Debug)]
pub enum ExternalReconciliation {
    /// The authenticated worker reports that the operation is still running.
    Running,
    /// The operation reached a terminal state and its promise was resolved.
    Resolved(Option<Evaluation>),
}

/// Lifecycle errors returned when a host completes or cancels external work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExternalToolError {
    Unknown(ExternalToolId),
    NotExternal(ExternalToolId),
    NotClaimed(ExternalToolId),
    AlreadyClaimed(ExternalToolId),
    AlreadyCompleted(ExternalToolId),
    InvalidPayload(ExternalToolId),
    RetryLimitReached(ExternalToolId),
    DeadlineElapsed(ExternalToolId),
    StreamingDisabled(ExternalToolId),
    StreamLimitExceeded(ExternalToolId),
    ToolUnavailable(ExternalToolId),
    ReconciliationMismatch(ExternalToolId),
    CancellationRequested(ExternalToolId),
    CancellationNotRequested(ExternalToolId),
    ReconciliationRequiresHostAuthenticator,
    UnexpectedReconciliationMessage,
    Protocol(ProtocolError),
    Runtime(RuntimeError),
}

impl Display for ExternalToolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(_) => formatter.write_str("unknown external tool operation"),
            Self::NotExternal(_) => {
                formatter.write_str("tool operation is not externally dispatched")
            }
            Self::NotClaimed(_) => {
                formatter.write_str("external tool operation has not been claimed")
            }
            Self::AlreadyClaimed(_) => {
                formatter.write_str("external tool operation is already claimed")
            }
            Self::AlreadyCompleted(_) => {
                formatter.write_str("external tool operation is already complete")
            }
            Self::InvalidPayload(_) => {
                formatter.write_str("external tool operation has an invalid worker payload")
            }
            Self::RetryLimitReached(_) => {
                formatter.write_str("external tool operation exhausted its retry limit")
            }
            Self::DeadlineElapsed(_) => {
                formatter.write_str("external tool operation deadline has elapsed")
            }
            Self::StreamingDisabled(_) => {
                formatter.write_str("external tool operation does not permit streaming")
            }
            Self::StreamLimitExceeded(_) => {
                formatter.write_str("external tool operation exceeded a stream limit")
            }
            Self::ToolUnavailable(_) => {
                formatter.write_str("registered tool for external operation is unavailable")
            }
            Self::ReconciliationMismatch(_) => {
                formatter.write_str("worker reconciliation does not match the claimed operation")
            }
            Self::CancellationRequested(_) => {
                formatter.write_str("external tool cancellation has already been requested")
            }
            Self::CancellationNotRequested(_) => {
                formatter.write_str("external tool cancellation has not been requested")
            }
            Self::ReconciliationRequiresHostAuthenticator => {
                formatter.write_str("external reconciliation requires a host session authenticator")
            }
            Self::UnexpectedReconciliationMessage => {
                formatter.write_str("authenticated worker frame is not an operation reconciliation")
            }
            Self::Protocol(error) => write!(formatter, "worker protocol rejected: {error}"),
            Self::Runtime(error) => write!(formatter, "could not resume tool operation: {error}"),
        }
    }
}

impl std::error::Error for ExternalToolError {}

/// Errors returned when a host configures an external streaming redactor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamConfigurationError {
    UnknownTool(String),
    NotExternal(String),
    StreamingDisabled(String),
    AlreadyReserved(String),
}

impl Display for StreamConfigurationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTool(name) => write!(formatter, "unknown tool: {name}"),
            Self::NotExternal(name) => write!(formatter, "tool is not external: {name}"),
            Self::StreamingDisabled(name) => {
                write!(formatter, "tool does not permit streaming: {name}")
            }
            Self::AlreadyReserved(name) => {
                write!(
                    formatter,
                    "stream redactor must be set before the tool is reserved: {name}"
                )
            }
        }
    }
}

impl std::error::Error for StreamConfigurationError {}

/// Transport owned by the trusted host for dispatching a validated worker call.
///
/// Implementations may use a contained child process, a platform IPC service,
/// or an embedded app-provided adapter. Scripts never receive this transport.
/// The implementation owns its error type so it can retain transport-specific
/// failure details for trusted host handling.
pub trait WorkerTransport {
    type Error: Display;

    fn dispatch(&mut self, invocation: WorkerInvocation) -> Result<WorkerResult, Self::Error>;

    /// Discards the current worker session after a host-side validation or
    /// lifecycle failure.
    ///
    /// The default is appropriate only for transports with no reusable
    /// session state. Contained transports should poison their channel and
    /// terminate the worker through their platform supervisor.
    fn discard(&mut self) {}
}

/// Host-side client for a capability-attenuated worker session.
pub struct ProtocolWorkerClient<T> {
    authorizer: SessionAuthorizer,
    transport: T,
    next_request_sequence: u64,
}

impl<T: WorkerTransport> ProtocolWorkerClient<T> {
    pub fn new(manifest: CapabilityManifest, transport: T) -> Result<Self, ProtocolError> {
        Ok(Self {
            authorizer: SessionAuthorizer::new(manifest)?,
            transport,
            next_request_sequence: 1,
        })
    }

    pub fn manifest(&self) -> &CapabilityManifest {
        self.authorizer.manifest()
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn supports_json_policy(&self, policy: &ToolPolicy) -> bool {
        policy.data_format == ToolDataFormat::Json
            && self.manifest().grants.iter().any(|grant| {
                grant.tool == policy.name
                    && grant.format == EnvelopeFormat::Json
                    && policy.max_calls <= grant.max_calls as usize
                    && policy.max_input_bytes <= grant.max_input_bytes as usize
                    && policy.max_output_bytes <= grant.max_output_bytes as usize
            })
    }

    pub fn dispatch_json(&mut self, request: &JsonToolRequest) -> Result<JsonValue, ToolError> {
        if self.next_request_sequence == u64::MAX {
            return Err(ToolError::Failed(
                "worker request sequence exhausted".to_owned(),
            ));
        }
        let request_id = format!("request-{}", self.next_request_sequence);
        self.next_request_sequence = self.next_request_sequence.saturating_add(1);
        let invocation = WorkerInvocation::new(
            self.manifest().session_id.clone(),
            request_id,
            request.name.clone(),
            WorkerPayload::Json(request.input.clone()),
        )
        .map_err(worker_protocol_failed)?;
        let authorized = self
            .authorizer
            .authorize(invocation)
            .map_err(worker_denied)?;
        let result = match self.transport.dispatch(authorized.invocation().clone()) {
            Ok(result) => result,
            Err(_) => {
                self.transport.discard();
                return Err(worker_transport_failed());
            }
        };
        if let Err(error) = self.authorizer.validate_result(&authorized, &result) {
            self.transport.discard();
            return Err(worker_protocol_failed(error));
        }

        match result.payload {
            WorkerPayload::Json(value) => Ok(value),
            WorkerPayload::Text(_) => {
                self.transport.discard();
                Err(ToolError::Failed(
                    "worker returned text for a JSON capability".to_owned(),
                ))
            }
        }
    }
}

fn worker_denied(error: ProtocolError) -> ToolError {
    ToolError::Denied(format!("worker capability denied: {error}"))
}

fn worker_protocol_failed(error: ProtocolError) -> ToolError {
    ToolError::Failed(format!("worker protocol failed: {error}"))
}

fn worker_transport_failed() -> ToolError {
    ToolError::Failed("worker transport failed".to_owned())
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn timeout_error(ticket: &ToolTicket) -> ToolError {
    ToolError::TimedOut(format!("{} exceeded its deferred deadline", ticket.name))
}

fn validate_json_envelope(json: &str, tool_name: &str, direction: &str) -> Result<(), ToolError> {
    let value = serde_json::from_str::<JsonValue>(json)
        .map_err(|_| ToolError::Denied(format!("{tool_name} {direction} is not valid JSON")))?;
    if value.is_object() || value.is_array() {
        Ok(())
    } else {
        Err(ToolError::Denied(format!(
            "{tool_name} {direction} must be a JSON object or array"
        )))
    }
}

fn schema_validator(schema: JsonSchema, direction: &'static str) -> ToolValidator {
    Box::new(move |encoded| {
        let value = serde_json::from_str(encoded).map_err(|_| {
            ToolError::Denied(format!("{direction} is not valid JSON for its schema"))
        })?;
        schema.validate(&value).map_err(|violation| {
            ToolError::Denied(format!(
                "{direction} does not match its schema: {violation}"
            ))
        })
    })
}

#[cfg(feature = "http-endpoint-catalog")]
fn redacted_schema_validator(schema: JsonSchema, error: ToolError) -> ToolValidator {
    Box::new(move |encoded| {
        let value = serde_json::from_str(encoded).map_err(|_| error.clone())?;
        schema.validate(&value).map_err(|_| error.clone())
    })
}

/// Compiles the Rust-side half of a typed JSON capability into an input
/// validator. The JSON Schema remains the authoritative wire contract, so it
/// is checked before Serde sees the value.
fn typed_input_validator<I>(schema: JsonSchema) -> ToolValidator
where
    I: DeserializeOwned + 'static,
{
    Box::new(move |encoded| {
        let value = serde_json::from_str(encoded)
            .map_err(|_| ToolError::Denied("input is not valid JSON for its schema".to_owned()))?;
        schema.validate(&value).map_err(|violation| {
            ToolError::Denied(format!("input does not match its schema: {violation}"))
        })?;
        serde_json::from_value::<I>(value).map(|_| ()).map_err(|_| {
            ToolError::Denied("input does not match its registered Rust type".to_owned())
        })
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolRegistrationError {
    Duplicate(String),
    InvalidName(String),
    InvalidPolicy(&'static str),
    InvalidMetadata(&'static str),
    CatalogToolLimitExceeded { maximum: usize },
    CatalogByteLimitExceeded { actual: usize, maximum: usize },
    IncompatibleWorkerGrant(String),
    ActiveCapabilityLease,
}

impl Display for ToolRegistrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(name) => write!(formatter, "tool already registered: {name}"),
            Self::InvalidName(name) => write!(formatter, "invalid tool name: {name}"),
            Self::InvalidPolicy(message) => formatter.write_str(message),
            Self::InvalidMetadata(message) => formatter.write_str(message),
            Self::CatalogToolLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "tool catalog exceeds its maximum of {maximum} tools"
                )
            }
            Self::CatalogByteLimitExceeded { actual, maximum } => write!(
                formatter,
                "tool catalog is {actual} bytes but its maximum is {maximum} bytes"
            ),
            Self::IncompatibleWorkerGrant(name) => {
                write!(formatter, "worker manifest cannot safely back tool: {name}")
            }
            Self::ActiveCapabilityLease => formatter
                .write_str("cannot change the tool catalog while a capability lease is active"),
        }
    }
}

impl std::error::Error for ToolRegistrationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Allowed,
    Denied,
    Failed,
    Cancelled,
    TimedOut,
    CancellationRequested,
    RetryScheduled,
    Streamed,
    StreamDenied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    /// Source-local ordering sequence for this audit record.
    ///
    /// It begins at one for each capability runtime and never wraps. It is
    /// distinct from [`Self::sequence`], which correlates multiple lifecycle
    /// records for one capability invocation. This sequence is telemetry only;
    /// it is not a capability grant, idempotency key, fencing token, or durable
    /// operation identity.
    pub event_sequence: u64,
    /// Source-local sequence of the capability invocation that produced this
    /// record. Retry, cancellation, and stream records for one invocation can
    /// share this value.
    pub sequence: u64,
    /// Registered tool name, or a fixed-length digest label for an oversized
    /// or invalid unrecognized request name.
    pub tool: String,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_class: Option<RetryClass>,
}

/// A contiguous source-local range of exported capability audit events.
///
/// Hosts persist a batch under a stable host-selected stream identity. The
/// batch is telemetry only: it neither grants a capability nor proves an
/// adapter effect, cancellation, or rollback.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditEventBatch {
    events: Vec<AuditEvent>,
    next_event_sequence: u64,
}

impl AuditEventBatch {
    /// Returns the ordered audit events in this exported range.
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Returns the first source event sequence in this batch, or the cursor
    /// after the batch when it is empty.
    pub fn first_event_sequence(&self) -> u64 {
        self.events
            .first()
            .map(|event| event.event_sequence)
            .unwrap_or(self.next_event_sequence)
    }

    /// Returns the source cursor immediately after this batch.
    pub const fn next_event_sequence(&self) -> u64 {
        self.next_event_sequence
    }

    /// Returns whether this batch contains no audit events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn is_contiguous(&self) -> bool {
        if self.next_event_sequence == 0 {
            return false;
        }
        let Some(first) = self.events.first() else {
            return true;
        };
        if first.event_sequence == 0 || first.event_sequence == u64::MAX {
            return false;
        }
        let mut expected = first.event_sequence;
        for event in &self.events {
            if event.event_sequence != expected || event.event_sequence == u64::MAX {
                return false;
            }
            let Some(next) = expected.checked_add(1) else {
                return false;
            };
            expected = next;
        }
        expected == self.next_event_sequence
    }
}

/// Rejection while exporting capability audit events after a host-maintained
/// source cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditEventCursorError {
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

impl Display for AuditEventCursorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCursor => formatter.write_str("capability audit cursor is invalid"),
            Self::Evicted {
                requested,
                earliest_available,
            } => write!(
                formatter,
                "capability audit cursor {requested} was evicted; earliest available is {earliest_available}"
            ),
            Self::Ahead {
                requested,
                next_available,
            } => write!(
                formatter,
                "capability audit cursor {requested} is ahead of the next available sequence {next_available}"
            ),
        }
    }
}

impl std::error::Error for AuditEventCursorError {}

/// Ordered, read-only view of the recent in-memory capability audit events.
///
/// The view is backed by a bounded ring buffer. Entries are ordered from
/// oldest to newest, but can wrap internally; use [`Self::as_slices`] when a
/// host needs zero-copy access to both contiguous portions. This is not a
/// durable audit record and does not itself grant or prove authority.
#[derive(Clone, Copy, Debug)]
pub struct AuditLog<'a> {
    entries: &'a VecDeque<AuditEvent>,
}

impl<'a> AuditLog<'a> {
    pub fn len(self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(self, index: usize) -> Option<&'a AuditEvent> {
        self.entries.get(index)
    }

    pub fn first(self) -> Option<&'a AuditEvent> {
        self.entries.front()
    }

    pub fn last(self) -> Option<&'a AuditEvent> {
        self.entries.back()
    }

    pub fn iter(self) -> std::collections::vec_deque::Iter<'a, AuditEvent> {
        self.entries.iter()
    }

    pub fn as_slices(self) -> (&'a [AuditEvent], &'a [AuditEvent]) {
        self.entries.as_slices()
    }
}

impl<'a> IntoIterator for AuditLog<'a> {
    type Item = &'a AuditEvent;
    type IntoIter = std::collections::vec_deque::Iter<'a, AuditEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl Index<usize> for AuditLog<'_> {
    type Output = AuditEvent;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

pub type ToolHandler = Box<dyn FnMut(&ToolRequest) -> Result<String, ToolError> + 'static>;
type ToolValidator = Box<dyn Fn(&str) -> Result<(), ToolError> + 'static>;
type StreamRedactor = Box<dyn FnMut(&str) -> String + 'static>;

enum ToolImplementation {
    HostPump(ToolHandler),
    External,
}

struct RegisteredTool {
    policy: ToolPolicy,
    metadata: ToolMetadata,
    dispatch: ToolDispatch,
    contract_enforced: bool,
    calls: usize,
    input_validator: Option<ToolValidator>,
    output_validator: Option<ToolValidator>,
    stream_redactor: Option<StreamRedactor>,
    implementation: ToolImplementation,
}

impl RegisteredTool {
    fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.policy.name.clone(),
            format: self.policy.data_format,
            dispatch: self.dispatch,
            contract_enforced: self.contract_enforced,
            max_calls: self.policy.max_calls,
            max_attempts: self.policy.max_attempts,
            max_input_bytes: self.policy.max_input_bytes,
            max_output_bytes: self.policy.max_output_bytes,
            max_deferred_millis: self.policy.max_deferred_duration.map(duration_millis),
            stream: self.policy.stream.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct DeferredDeadline {
    started_at: Instant,
    maximum: Duration,
}

impl DeferredDeadline {
    fn expired_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.started_at) >= self.maximum
    }

    fn remaining_at(&self, now: Instant) -> Duration {
        self.maximum
            .saturating_sub(now.saturating_duration_since(self.started_at))
    }
}

#[derive(Clone, Debug)]
struct ToolTicket {
    sequence: u64,
    name: String,
    input: String,
    input_bytes: usize,
    call_index: usize,
    max_output_bytes: usize,
    max_attempts: u32,
    stream: Option<ToolStreamPolicy>,
    data_format: ToolDataFormat,
    dispatch: ToolDispatch,
    deadline: Option<DeferredDeadline>,
}

impl ToolTicket {
    fn expired_at(&self, now: Instant) -> bool {
        self.deadline
            .as_ref()
            .is_some_and(|deadline| deadline.expired_at(now))
    }

    fn remaining_deadline_millis(&self, now: Instant) -> Option<u64> {
        self.deadline
            .as_ref()
            .map(|deadline| duration_millis(deadline.remaining_at(now)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ToolInvocationKind {
    Synchronous,
    Deferred,
}

#[derive(Clone, Debug)]
enum PendingDispatch {
    HostPump,
    ExternalQueued,
    ExternalClaimed,
    ExternalCancellationRequested,
}

#[derive(Clone, Debug)]
enum PendingToolState {
    Pending {
        dispatch: PendingDispatch,
        waiting_thread: Option<ScriptThreadId>,
    },
    Ready(Result<String, ToolError>),
}

#[derive(Debug, Default)]
struct StreamAccounting {
    chunks: usize,
    source_bytes: usize,
    emitted_bytes: usize,
}

#[derive(Debug)]
struct PendingTool {
    id: ExternalToolId,
    ticket: ToolTicket,
    attempt: u32,
    idempotency_key: String,
    streamed: StreamAccounting,
    state: PendingToolState,
    orphaned: bool,
}

type PendingTools = Rc<RefCell<BTreeMap<ScriptHandle, PendingTool>>>;

struct PendingCompletion {
    waiting_thread: Option<ScriptThreadId>,
}

enum ExternalReconcileCompletion {
    Running,
    Resolved(PendingCompletion),
}

struct ToolPromiseGc {
    pending: PendingTools,
    handle: ScriptHandle,
}

impl ScriptHandleGc for ToolPromiseGc {
    fn gc(&mut self) {
        let mut pending = self.pending.borrow_mut();
        let Some(entry) = pending.get_mut(&self.handle) else {
            return;
        };
        if matches!(
            &entry.state,
            PendingToolState::Pending {
                dispatch: PendingDispatch::ExternalClaimed
                    | PendingDispatch::ExternalCancellationRequested,
                ..
            }
        ) {
            entry.orphaned = true;
        } else {
            pending.remove(&self.handle);
        }
    }

    fn set_handle(&mut self, handle: ScriptHandle) {
        self.handle = handle;
    }
}

pub struct CapabilityHost {
    session_id: u64,
    session_nonce: String,
    catalog_limits: CapabilityCatalogLimits,
    tools: BTreeMap<String, RegisteredTool>,
    active_lease: Option<Rc<RefCell<CapabilityLeaseState>>>,
    audit: VecDeque<AuditEvent>,
    max_audit_events: NonZeroUsize,
    dropped_audit_events: u64,
    first_audit_event_sequence: u64,
    next_audit_event_sequence: u64,
    next_sequence: u64,
    next_pending_id: u64,
    pending: PendingTools,
}

impl Default for CapabilityHost {
    fn default() -> Self {
        Self::with_catalog_limits(CapabilityCatalogLimits::default())
            .expect("default catalog limits are valid")
    }
}

impl CapabilityHost {
    /// Creates a host with explicit aggregate bounds for its capability
    /// catalog. Individual tool registration still validates each policy,
    /// description, and schema independently.
    pub fn with_catalog_limits(
        catalog_limits: CapabilityCatalogLimits,
    ) -> Result<Self, RuntimeError> {
        let catalog_limits = catalog_limits.validate()?;
        let session_id = NEXT_CAPABILITY_SESSION.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            session_id,
            session_nonce: capability_session_nonce(session_id),
            catalog_limits,
            tools: BTreeMap::new(),
            active_lease: None,
            audit: VecDeque::new(),
            max_audit_events: NonZeroUsize::new(DEFAULT_MAX_AUDIT_EVENTS)
                .expect("default audit limit is nonzero"),
            dropped_audit_events: 0,
            first_audit_event_sequence: 1,
            next_audit_event_sequence: 1,
            next_sequence: 0,
            next_pending_id: 0,
            pending: Rc::new(RefCell::new(BTreeMap::new())),
        })
    }

    /// Returns the immutable aggregate catalog limits selected at host setup.
    pub const fn catalog_limits(&self) -> CapabilityCatalogLimits {
        self.catalog_limits
    }

    /// Returns the current capacity of the bounded in-memory audit view.
    pub const fn max_audit_events(&self) -> usize {
        self.max_audit_events.get()
    }

    /// Returns how many oldest audit events were evicted since the last clear.
    ///
    /// This count saturates at `u64::MAX`. A nonzero result means this
    /// in-process view is incomplete and must not be treated as a durable
    /// audit record.
    pub const fn dropped_audit_events(&self) -> u64 {
        self.dropped_audit_events
    }

    /// Changes the capacity of the bounded in-memory audit view.
    ///
    /// Shrinking the capacity immediately evicts oldest entries and increments
    /// [`Self::dropped_audit_events`]. This affects observability only; it
    /// does not alter tool policy, leases, or pending operations. Values above
    /// [`MAX_AUDIT_EVENTS`] are rejected.
    pub fn set_max_audit_events(
        &mut self,
        max_audit_events: NonZeroUsize,
    ) -> Result<(), RuntimeError> {
        if max_audit_events.get() > MAX_AUDIT_EVENTS {
            return Err(RuntimeError::InvalidLimits(
                "max_audit_events exceeds the hard limit",
            ));
        }
        self.max_audit_events = max_audit_events;
        self.trim_audit_to_capacity();
        Ok(())
    }

    pub fn register<F>(
        &mut self,
        policy: ToolPolicy,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&ToolRequest) -> Result<String, ToolError> + 'static,
    {
        self.register_with_metadata(policy, ToolMetadata::default(), handler)
    }

    pub fn register_with_metadata<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&ToolRequest) -> Result<String, ToolError> + 'static,
    {
        self.register_with_validators(
            policy,
            metadata,
            None,
            None,
            ToolDispatch::HostPump,
            ToolImplementation::HostPump(Box::new(handler)),
        )
    }

    /// Registers a bounded catalog of descriptor-pinned regular files as one
    /// text capability.
    ///
    /// The catalog accepts only host-selected opaque identifiers. It exposes
    /// no script-selected paths, directory traversal, file enumeration, or
    /// write access. The returned text is bounded by both the catalog and the
    /// tool policy. This is not operating-system containment.
    pub fn register_fixed_file_catalog_tool(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        catalog: fixed_file_catalog::FixedFileCatalog,
    ) -> Result<(), ToolRegistrationError> {
        catalog.validate_tool_policy(&policy)?;
        let max_output_bytes = policy.max_output_bytes;
        self.register_with_metadata(
            policy,
            metadata,
            catalog.into_tool_handler(max_output_bytes),
        )
    }

    /// Registers a bounded catalog of setup-selected HTTP endpoints as one
    /// JSON capability.
    ///
    /// The catalog accepts only opaque endpoint identifiers and bounded JSON
    /// request bodies. It never accepts a script-selected URL, method, header,
    /// query, or redirect target. See [`http_endpoint_catalog::HttpEndpointCatalog`]
    /// for the network and containment boundary.
    #[cfg(feature = "http-endpoint-catalog")]
    pub fn register_http_endpoint_catalog_tool(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        catalog: http_endpoint_catalog::HttpEndpointCatalog,
    ) -> Result<(), ToolRegistrationError> {
        if catalog.requires_secret_resolver() {
            return Err(ToolRegistrationError::InvalidPolicy(
                "HTTP endpoint catalog secret bindings require an explicit secret resolver",
            ));
        }
        catalog.validate_tool_policy(&policy)?;
        let max_output_bytes = policy.max_output_bytes;
        let contract = catalog.tool_contract()?;
        self.register_http_endpoint_catalog_contract(
            policy,
            metadata,
            contract,
            catalog.into_tool_handler(max_output_bytes),
        )
    }

    /// Registers a bounded catalog of setup-selected HTTPS endpoints whose
    /// reviewed credential bindings resolve only at invocation time.
    ///
    /// Splash can still select only the catalog's opaque endpoint identifier.
    /// It cannot choose a secret, header, URL, method, or redirect target. The
    /// resolver is consumed with the tool and is never exposed through the
    /// tool descriptor, audit view, or dynamic runtime API.
    #[cfg(feature = "http-endpoint-catalog")]
    pub fn register_http_endpoint_catalog_tool_with_secret_resolver<R>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        catalog: http_endpoint_catalog::HttpEndpointCatalog,
        secret_resolver: R,
    ) -> Result<(), ToolRegistrationError>
    where
        R: http_endpoint_catalog::HttpEndpointSecretResolver + 'static,
    {
        catalog.validate_tool_policy(&policy)?;
        let max_output_bytes = policy.max_output_bytes;
        let contract = catalog.tool_contract()?;
        self.register_http_endpoint_catalog_contract(
            policy,
            metadata,
            contract,
            catalog.into_tool_handler_with_secret_resolver(max_output_bytes, secret_resolver),
        )
    }

    #[cfg(feature = "http-endpoint-catalog")]
    fn register_http_endpoint_catalog_contract<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        let JsonToolContract {
            input_schema,
            output_schema,
            input,
            output,
        } = contract;
        let metadata = metadata
            .with_input_schema(input_schema)
            .with_output_schema(output_schema);
        self.register_json_tool_with_validators(
            policy,
            metadata,
            Some(redacted_schema_validator(
                input,
                ToolError::Denied("HTTP endpoint access was denied".to_owned()),
            )),
            Some(redacted_schema_validator(
                output,
                ToolError::Failed("HTTP endpoint request failed".to_owned()),
            )),
            handler,
        )
    }

    /// Registers a deferred-only capability that has no in-process handler.
    ///
    /// The host must claim its invocation and complete or cancel it through
    /// the external completion API.
    pub fn register_external(&mut self, policy: ToolPolicy) -> Result<(), ToolRegistrationError> {
        self.register_external_with_metadata(policy, ToolMetadata::default())
    }

    pub fn register_external_with_metadata(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
    ) -> Result<(), ToolRegistrationError> {
        self.register_with_validators(
            policy,
            metadata,
            None,
            None,
            ToolDispatch::External,
            ToolImplementation::External,
        )
    }

    /// Installs a trusted redactor for chunks emitted by an external tool.
    ///
    /// The hook receives worker text and returns the only text released back
    /// to the host by the streaming API. It is never visible to Splash source.
    pub fn set_external_stream_redactor<F>(
        &mut self,
        name: &str,
        redactor: F,
    ) -> Result<(), StreamConfigurationError>
    where
        F: FnMut(&str) -> String + 'static,
    {
        let Some(registered) = self.tools.get_mut(name) else {
            return Err(StreamConfigurationError::UnknownTool(name.to_owned()));
        };
        if registered.dispatch != ToolDispatch::External {
            return Err(StreamConfigurationError::NotExternal(name.to_owned()));
        }
        if registered.policy.stream.is_none() {
            return Err(StreamConfigurationError::StreamingDisabled(name.to_owned()));
        }
        if registered.calls != 0 {
            return Err(StreamConfigurationError::AlreadyReserved(name.to_owned()));
        }
        registered.stream_redactor = Some(Box::new(redactor));
        Ok(())
    }

    fn register_with_validators(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        input_validator: Option<ToolValidator>,
        output_validator: Option<ToolValidator>,
        dispatch: ToolDispatch,
        implementation: ToolImplementation,
    ) -> Result<(), ToolRegistrationError> {
        if self.active_lease.is_some() {
            return Err(ToolRegistrationError::ActiveCapabilityLease);
        }
        if dispatch != ToolDispatch::External && policy.stream.is_some() {
            return Err(ToolRegistrationError::InvalidPolicy(
                "stream policy requires an external tool",
            ));
        }
        policy.validate()?;
        metadata.validate_for(policy.data_format)?;
        if self.tools.contains_key(&policy.name) {
            return Err(ToolRegistrationError::Duplicate(policy.name));
        }
        let contract_enforced = input_validator.is_some() && output_validator.is_some();
        let name = policy.name.clone();
        let registered = RegisteredTool {
            policy,
            metadata,
            dispatch,
            contract_enforced,
            calls: 0,
            input_validator,
            output_validator,
            stream_redactor: None,
            implementation,
        };
        self.ensure_catalog_capacity(&registered)?;
        self.tools.insert(name, registered);
        Ok(())
    }

    pub fn register_json_tool<F>(
        &mut self,
        policy: ToolPolicy,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        self.register_json_tool_with_metadata(policy, ToolMetadata::default(), handler)
    }

    pub fn register_json_tool_with_metadata<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        self.register_json_tool_with_validators(policy, metadata, None, None, handler)
    }

    pub fn register_validated_json_tool<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        let metadata = metadata
            .with_input_schema(contract.input_schema.clone())
            .with_output_schema(contract.output_schema.clone());
        self.register_json_tool_with_validators(
            policy,
            metadata,
            Some(schema_validator(contract.input, "input")),
            Some(schema_validator(contract.output, "output")),
            handler,
        )
    }

    /// Registers a JSON capability that converts its contract-validated wire
    /// envelope into Rust input and output types through Serde.
    ///
    /// The [`JsonToolContract`] remains authoritative: its input schema is
    /// checked before deserialization and its output schema is checked after
    /// serialization. This prevents Rust type defaults or unknown-field
    /// behavior from widening the script-visible capability boundary.
    pub fn register_typed_json_tool<I, O, F>(
        &mut self,
        policy: ToolPolicy,
        contract: JsonToolContract,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        I: DeserializeOwned + 'static,
        O: Serialize + 'static,
        F: FnMut(I) -> Result<O, ToolError> + 'static,
    {
        self.register_typed_json_tool_with_metadata(
            policy,
            ToolMetadata::default(),
            contract,
            handler,
        )
    }

    /// Registers a documented typed JSON capability backed by trusted Rust
    /// code. Use [`Self::register_typed_json_tool`] when no description or
    /// additional metadata is needed.
    pub fn register_typed_json_tool_with_metadata<I, O, F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
        mut handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        I: DeserializeOwned + 'static,
        O: Serialize + 'static,
        F: FnMut(I) -> Result<O, ToolError> + 'static,
    {
        let metadata = metadata
            .with_input_schema(contract.input_schema.clone())
            .with_output_schema(contract.output_schema.clone());
        self.register_json_tool_with_validators(
            policy,
            metadata,
            Some(typed_input_validator::<I>(contract.input)),
            Some(schema_validator(contract.output, "output")),
            move |request| {
                let input = serde_json::from_value(request.input.clone()).map_err(|_| {
                    ToolError::Failed(
                        "validated typed JSON input could not be deserialized".to_owned(),
                    )
                })?;
                let output = handler(input)?;
                serde_json::to_value(output).map_err(|_| {
                    ToolError::Failed(
                        "typed Rust output could not be serialized as JSON".to_owned(),
                    )
                })
            },
        )
    }

    pub fn register_external_json_tool(
        &mut self,
        policy: ToolPolicy,
    ) -> Result<(), ToolRegistrationError> {
        self.register_external_json_tool_with_metadata(policy, ToolMetadata::default())
    }

    pub fn register_external_json_tool_with_metadata(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
    ) -> Result<(), ToolRegistrationError> {
        self.register_external_json_tool_with_validators(policy, metadata, None, None)
    }

    pub fn register_validated_external_json_tool(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
    ) -> Result<(), ToolRegistrationError> {
        let metadata = metadata
            .with_input_schema(contract.input_schema.clone())
            .with_output_schema(contract.output_schema.clone());
        self.register_external_json_tool_with_validators(
            policy,
            metadata,
            Some(schema_validator(contract.input, "input")),
            Some(schema_validator(contract.output, "output")),
        )
    }

    fn register_external_json_tool_with_validators(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        input_validator: Option<ToolValidator>,
        output_validator: Option<ToolValidator>,
    ) -> Result<(), ToolRegistrationError> {
        if policy.data_format != ToolDataFormat::Json {
            return Err(ToolRegistrationError::InvalidPolicy(
                "register_external_json_tool requires ToolPolicy::json",
            ));
        }
        self.register_with_validators(
            policy,
            metadata,
            input_validator,
            output_validator,
            ToolDispatch::External,
            ToolImplementation::External,
        )
    }

    fn register_json_tool_with_validators<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        input_validator: Option<ToolValidator>,
        output_validator: Option<ToolValidator>,
        mut handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        if policy.data_format != ToolDataFormat::Json {
            return Err(ToolRegistrationError::InvalidPolicy(
                "register_json_tool requires ToolPolicy::json",
            ));
        }
        self.register_with_validators(
            policy,
            metadata,
            input_validator,
            output_validator,
            ToolDispatch::HostPump,
            ToolImplementation::HostPump(Box::new(move |request| {
                let input = serde_json::from_str(&request.input).map_err(|error| {
                    ToolError::Failed(format!(
                        "{} JSON input failed host validation: {error}",
                        request.name
                    ))
                })?;
                let output = handler(&JsonToolRequest {
                    name: request.name.clone(),
                    input,
                    call_index: request.call_index,
                })?;
                serde_json::to_string(&output).map_err(|error| {
                    ToolError::Failed(format!(
                        "{} JSON output could not be serialized: {error}",
                        request.name
                    ))
                })
            })),
        )
    }

    pub fn audit(&self) -> AuditLog<'_> {
        AuditLog {
            entries: &self.audit,
        }
    }

    /// Exports retained capability audit telemetry after `next_event_sequence`
    /// in source order.
    ///
    /// A host that persists audit telemetry should begin with cursor `1` and
    /// retain [`AuditEventBatch::next_event_sequence`] only after its own sink
    /// has accepted the batch. If in-memory eviction or [`Self::clear_audit`]
    /// overtakes that cursor, this method fails rather than silently exporting
    /// an incomplete history. Export remains observability only: it cannot
    /// authorize a tool, recreate an external operation, or prove an effect.
    pub fn audit_since(
        &self,
        next_event_sequence: u64,
    ) -> Result<AuditEventBatch, AuditEventCursorError> {
        if next_event_sequence == 0 {
            return Err(AuditEventCursorError::InvalidCursor);
        }
        if next_event_sequence < self.first_audit_event_sequence {
            return Err(AuditEventCursorError::Evicted {
                requested: next_event_sequence,
                earliest_available: self.first_audit_event_sequence,
            });
        }
        if next_event_sequence > self.next_audit_event_sequence {
            return Err(AuditEventCursorError::Ahead {
                requested: next_event_sequence,
                next_available: self.next_audit_event_sequence,
            });
        }

        let skipped = usize::try_from(next_event_sequence - self.first_audit_event_sequence)
            .map_err(|_| AuditEventCursorError::InvalidCursor)?;
        let batch = AuditEventBatch {
            events: self.audit.iter().skip(skipped).cloned().collect(),
            next_event_sequence: self.next_audit_event_sequence,
        };
        debug_assert!(batch.is_contiguous());
        Ok(batch)
    }

    pub fn clear_audit(&mut self) {
        self.audit.clear();
        self.dropped_audit_events = 0;
        self.first_audit_event_sequence = self.next_audit_event_sequence;
    }

    fn record_audit(&mut self, mut event: AuditEvent) {
        // `u64::MAX` is a cursor-only sentinel. Preserve contiguous source
        // identities by dropping later telemetry rather than wrapping.
        if self.next_audit_event_sequence == u64::MAX {
            self.dropped_audit_events = self.dropped_audit_events.saturating_add(1);
            return;
        }
        event.event_sequence = self.next_audit_event_sequence;
        if self.audit.len() == self.max_audit_events.get() {
            self.audit.pop_front();
            self.dropped_audit_events = self.dropped_audit_events.saturating_add(1);
            self.first_audit_event_sequence = self.first_audit_event_sequence.saturating_add(1);
        }
        self.audit.push_back(event);
        self.next_audit_event_sequence = self.next_audit_event_sequence.saturating_add(1);
    }

    fn audit_tool_label(&self, name: &str) -> String {
        if is_valid_tool_name(name) {
            return name.to_owned();
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(CAPABILITY_AUDIT_LABEL_DOMAIN);
        hasher.update(self.session_nonce.as_bytes());
        hasher.update(&(name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        format!(
            "{UNRECOGNIZED_AUDIT_TOOL_PREFIX}{}",
            hasher.finalize().to_hex()
        )
    }

    fn trim_audit_to_capacity(&mut self) {
        while self.audit.len() > self.max_audit_events.get() {
            self.audit.pop_front();
            self.dropped_audit_events = self.dropped_audit_events.saturating_add(1);
            self.first_audit_event_sequence = self.first_audit_event_sequence.saturating_add(1);
        }
    }

    fn ensure_catalog_capacity(
        &self,
        candidate: &RegisteredTool,
    ) -> Result<(), ToolRegistrationError> {
        if self.tools.len() >= self.catalog_limits.max_tools {
            return Err(ToolRegistrationError::CatalogToolLimitExceeded {
                maximum: self.catalog_limits.max_tools,
            });
        }

        let mut descriptors = self.tool_catalog();
        descriptors.push(candidate.descriptor());
        let actual = serde_json::to_vec(&descriptors)
            .map_err(|_| ToolRegistrationError::InvalidMetadata("tool catalog is invalid"))?
            .len();
        if actual > self.catalog_limits.max_serialized_bytes {
            return Err(ToolRegistrationError::CatalogByteLimitExceeded {
                actual,
                maximum: self.catalog_limits.max_serialized_bytes,
            });
        }
        Ok(())
    }

    pub fn tool_catalog(&self) -> Vec<ToolDescriptor> {
        self.tools
            .values()
            .map(RegisteredTool::descriptor)
            .collect()
    }

    pub fn tool_catalog_json(&self) -> Result<String, ToolError> {
        serde_json::to_string(&self.tool_catalog()).map_err(|error| {
            ToolError::Failed(format!("tool catalog serialization failed: {error}"))
        })
    }

    fn catalog_fingerprint(&self) -> Result<CapabilityCatalogFingerprint, CapabilityLeaseError> {
        let catalog = serde_json::to_vec(&self.tool_catalog())
            .map_err(|_| CapabilityLeaseError::CatalogEncoding)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(CAPABILITY_CATALOG_FINGERPRINT_DOMAIN);
        hasher.update(&(catalog.len() as u64).to_be_bytes());
        hasher.update(&catalog);
        Ok(CapabilityCatalogFingerprint(
            hasher.finalize().to_hex().to_string(),
        ))
    }

    fn issue_capability_lease<I>(
        &self,
        grants: I,
        authorizer: Option<Box<dyn ToolCallAuthorizer>>,
    ) -> Result<CapabilityLease, CapabilityLeaseError>
    where
        I: IntoIterator<Item = CapabilityLeaseGrant>,
    {
        if self.active_lease.is_some() {
            return Err(CapabilityLeaseError::LeaseAlreadyActive);
        }

        let mut granted_calls = BTreeMap::new();
        for grant in grants {
            if grant.max_calls == 0 {
                return Err(CapabilityLeaseError::ZeroCallLimit(grant.name));
            }
            let Some(registered) = self.tools.get(&grant.name) else {
                return Err(CapabilityLeaseError::UnknownTool(grant.name));
            };
            if grant.max_calls > registered.policy.max_calls {
                return Err(CapabilityLeaseError::CallLimitExceedsPolicy {
                    tool: grant.name,
                    requested: grant.max_calls,
                    maximum: registered.policy.max_calls,
                });
            }
            if granted_calls
                .insert(grant.name.clone(), grant.max_calls)
                .is_some()
            {
                return Err(CapabilityLeaseError::DuplicateTool(grant.name));
            }
        }

        Ok(CapabilityLease {
            state: Rc::new(RefCell::new(CapabilityLeaseState {
                runtime_id: self.session_id,
                catalog_fingerprint: self.catalog_fingerprint()?,
                grants: granted_calls,
                calls: BTreeMap::new(),
                authorizer,
            })),
        })
    }

    fn issue_full_capability_lease(&self) -> Result<CapabilityLease, CapabilityLeaseError> {
        self.issue_capability_lease(
            self.tools.values().map(|registered| {
                CapabilityLeaseGrant::new(
                    registered.policy.name.clone(),
                    registered.policy.max_calls,
                )
            }),
            None,
        )
    }

    fn validate_capability_lease(
        &self,
        lease: &CapabilityLease,
    ) -> Result<(), CapabilityLeaseError> {
        let fingerprint = self.catalog_fingerprint()?;
        lease
            .state
            .borrow()
            .validate_for(self.session_id, &fingerprint)
    }

    fn activate_capability_lease(
        &mut self,
        lease: &CapabilityLease,
    ) -> Result<(), CapabilityLeaseError> {
        if self.active_lease.is_some() {
            return Err(CapabilityLeaseError::LeaseAlreadyActive);
        }
        self.validate_capability_lease(lease)?;
        self.active_lease = Some(Rc::clone(&lease.state));
        Ok(())
    }

    fn clear_active_capability_lease(&mut self) {
        self.active_lease = None;
    }

    fn call(&mut self, name: &str, input: &str) -> Result<String, ToolError> {
        let ticket = self.reserve(name, input, None, ToolInvocationKind::Synchronous)?;
        self.execute(ticket)
    }

    fn call_json(&mut self, name: &str, input: &str) -> Result<String, ToolError> {
        let ticket = self.reserve(
            name,
            input,
            Some(ToolDataFormat::Json),
            ToolInvocationKind::Synchronous,
        )?;
        self.execute(ticket)
    }

    fn reserve(
        &mut self,
        name: &str,
        input: &str,
        expected_format: Option<ToolDataFormat>,
        invocation_kind: ToolInvocationKind,
    ) -> Result<ToolTicket, ToolError> {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let input_bytes = input.len();
        let active_lease = self.active_lease.clone();

        let result = match self.tools.get_mut(name) {
            None => Err(ToolError::Denied(format!("no capability grants {name}"))),
            Some(registered) => {
                if expected_format.is_some_and(|format| format != registered.policy.data_format) {
                    Err(ToolError::Denied(format!(
                        "{name} is not registered for JSON envelopes"
                    )))
                } else if invocation_kind == ToolInvocationKind::Synchronous
                    && registered.dispatch == ToolDispatch::External
                {
                    Err(ToolError::Denied(format!(
                        "{name} is available only through tool.start"
                    )))
                } else if input_bytes > registered.policy.max_input_bytes {
                    Err(ToolError::Denied(format!(
                        "{name} input exceeds {} bytes",
                        registered.policy.max_input_bytes
                    )))
                } else {
                    let envelope_result = if registered.policy.data_format == ToolDataFormat::Json {
                        validate_json_envelope(input, name, "input")
                    } else {
                        Ok(())
                    };
                    envelope_result.and_then(|()| {
                        Self::reserve_registered(
                            sequence,
                            name,
                            input,
                            input_bytes,
                            invocation_kind,
                            registered,
                            active_lease.as_ref(),
                        )
                    })
                }
            }
        };

        if let Err(error) = &result {
            self.record_result(sequence, name, input_bytes, error);
        }
        result
    }

    fn reserve_registered(
        sequence: u64,
        name: &str,
        input: &str,
        input_bytes: usize,
        invocation_kind: ToolInvocationKind,
        registered: &mut RegisteredTool,
        active_lease: Option<&Rc<RefCell<CapabilityLeaseState>>>,
    ) -> Result<ToolTicket, ToolError> {
        if let Some(validator) = registered.input_validator.as_ref() {
            validator(input)?;
        }
        if registered.calls >= registered.policy.max_calls {
            return Err(ToolError::Denied(format!(
                "{name} exhausted its {} call budget",
                registered.policy.max_calls
            )));
        }

        let call_index = registered.calls.saturating_add(1);
        if let Some(lease) = active_lease {
            let request = ToolRequest {
                name: name.to_owned(),
                input: input.to_owned(),
                call_index,
            };
            let descriptor = registered.descriptor();
            lease.borrow_mut().authorize(&request, &descriptor)?;
        }

        registered.calls = call_index;
        let deadline = if invocation_kind == ToolInvocationKind::Deferred {
            registered
                .policy
                .max_deferred_duration
                .map(|maximum| DeferredDeadline {
                    started_at: Instant::now(),
                    maximum,
                })
        } else {
            None
        };
        Ok(ToolTicket {
            sequence,
            name: name.to_owned(),
            input: input.to_owned(),
            input_bytes,
            call_index,
            max_output_bytes: registered.policy.max_output_bytes,
            max_attempts: registered.policy.max_attempts,
            stream: registered.policy.stream.clone(),
            data_format: registered.policy.data_format,
            dispatch: registered.dispatch,
            deadline,
        })
    }

    fn execute(&mut self, ticket: ToolTicket) -> Result<String, ToolError> {
        let handler_result = match self.tools.get_mut(&ticket.name) {
            Some(registered) => {
                let request = ToolRequest {
                    name: ticket.name.clone(),
                    input: ticket.input.clone(),
                    call_index: ticket.call_index,
                };
                match &mut registered.implementation {
                    ToolImplementation::HostPump(handler) => handler(&request),
                    ToolImplementation::External => Err(ToolError::Failed(format!(
                        "{} is registered for external completion",
                        ticket.name
                    ))),
                }
            }
            None => Err(ToolError::Failed(format!(
                "registered capability disappeared: {}",
                ticket.name
            ))),
        };
        self.complete_ticket(&ticket, handler_result)
    }

    fn complete_ticket(
        &mut self,
        ticket: &ToolTicket,
        result: Result<String, ToolError>,
    ) -> Result<String, ToolError> {
        let result = if ticket.expired_at(Instant::now()) {
            Err(timeout_error(ticket))
        } else {
            result.and_then(|output| self.validate_output(ticket, output))
        };
        self.record_ticket_result(ticket, &result);
        result
    }

    fn validate_output(&self, ticket: &ToolTicket, output: String) -> Result<String, ToolError> {
        if output.len() > ticket.max_output_bytes {
            return Err(ToolError::Denied(format!(
                "{} output exceeds {} bytes",
                ticket.name, ticket.max_output_bytes
            )));
        }
        if ticket.data_format == ToolDataFormat::Json {
            validate_json_envelope(&output, &ticket.name, "output")?;
            match self.tools.get(&ticket.name) {
                Some(registered) => match registered.output_validator.as_ref() {
                    Some(validator) => validator(&output).map(|()| output),
                    None => Ok(output),
                },
                None => Err(ToolError::Failed(format!(
                    "registered capability disappeared: {}",
                    ticket.name
                ))),
            }
        } else {
            Ok(output)
        }
    }

    fn record_ticket_result(&mut self, ticket: &ToolTicket, result: &Result<String, ToolError>) {
        let (output_bytes, outcome) = match result {
            Ok(output) => (output.len(), AuditOutcome::Allowed),
            Err(ToolError::Denied(_)) => (0, AuditOutcome::Denied),
            Err(ToolError::Failed(_)) => (0, AuditOutcome::Failed),
            Err(ToolError::Cancelled(_)) => (0, AuditOutcome::Cancelled),
            Err(ToolError::TimedOut(_)) => (0, AuditOutcome::TimedOut),
        };
        self.record_audit(AuditEvent {
            event_sequence: 0,
            sequence: ticket.sequence,
            tool: self.audit_tool_label(&ticket.name),
            input_bytes: ticket.input_bytes,
            output_bytes,
            outcome,
            retry_class: None,
        });
    }

    fn record_result(&mut self, sequence: u64, name: &str, input_bytes: usize, error: &ToolError) {
        let outcome = match error {
            ToolError::Denied(_) => AuditOutcome::Denied,
            ToolError::Failed(_) => AuditOutcome::Failed,
            ToolError::Cancelled(_) => AuditOutcome::Cancelled,
            ToolError::TimedOut(_) => AuditOutcome::TimedOut,
        };
        self.record_audit(AuditEvent {
            event_sequence: 0,
            sequence,
            tool: self.audit_tool_label(name),
            input_bytes,
            output_bytes: 0,
            outcome,
            retry_class: None,
        });
    }

    fn record_retry(&mut self, ticket: &ToolTicket, retry_class: RetryClass) {
        self.record_audit(AuditEvent {
            event_sequence: 0,
            sequence: ticket.sequence,
            tool: self.audit_tool_label(&ticket.name),
            input_bytes: ticket.input_bytes,
            output_bytes: 0,
            outcome: AuditOutcome::RetryScheduled,
            retry_class: Some(retry_class),
        });
    }

    fn record_cancellation_requested(&mut self, ticket: &ToolTicket) {
        self.record_audit(AuditEvent {
            event_sequence: 0,
            sequence: ticket.sequence,
            tool: self.audit_tool_label(&ticket.name),
            input_bytes: ticket.input_bytes,
            output_bytes: 0,
            outcome: AuditOutcome::CancellationRequested,
            retry_class: None,
        });
    }

    fn record_stream(
        &mut self,
        ticket: &ToolTicket,
        source_bytes: usize,
        emitted_bytes: usize,
        outcome: AuditOutcome,
    ) {
        self.record_audit(AuditEvent {
            event_sequence: 0,
            sequence: ticket.sequence,
            tool: self.audit_tool_label(&ticket.name),
            input_bytes: source_bytes,
            output_bytes: emitted_bytes,
            outcome,
            retry_class: None,
        });
    }

    fn begin_async(
        &mut self,
        name: &str,
        input: &str,
        max_pending: usize,
    ) -> Result<(ToolTicket, PendingTools, ExternalToolId, String), ToolError> {
        self.begin_async_with_format(name, input, max_pending, None)
    }

    fn begin_async_json(
        &mut self,
        name: &str,
        input: &str,
        max_pending: usize,
    ) -> Result<(ToolTicket, PendingTools, ExternalToolId, String), ToolError> {
        self.begin_async_with_format(name, input, max_pending, Some(ToolDataFormat::Json))
    }

    fn begin_async_with_format(
        &mut self,
        name: &str,
        input: &str,
        max_pending: usize,
        expected_format: Option<ToolDataFormat>,
    ) -> Result<(ToolTicket, PendingTools, ExternalToolId, String), ToolError> {
        if self.pending.borrow().len() >= max_pending {
            let sequence = self.next_sequence;
            self.next_sequence = self.next_sequence.saturating_add(1);
            let error =
                ToolError::Denied(format!("pending tool budget of {max_pending} exhausted"));
            self.record_result(sequence, name, input.len(), &error);
            return Err(error);
        }

        let id = self.allocate_pending_id(name, input.len())?;
        let ticket = self.reserve(name, input, expected_format, ToolInvocationKind::Deferred)?;
        let idempotency_key = self.idempotency_key(&ticket);
        Ok((ticket, self.pending.clone(), id, idempotency_key))
    }

    fn idempotency_key(&self, ticket: &ToolTicket) -> String {
        format!("splash-{}-{}", self.session_nonce, ticket.sequence)
    }

    fn allocate_pending_id(
        &mut self,
        name: &str,
        input_bytes: usize,
    ) -> Result<ExternalToolId, ToolError> {
        if self.next_pending_id == u64::MAX {
            let sequence = self.next_sequence;
            self.next_sequence = self.next_sequence.saturating_add(1);
            let error = ToolError::Failed("deferred tool identifier space exhausted".to_owned());
            self.record_result(sequence, name, input_bytes, &error);
            return Err(error);
        }
        self.next_pending_id = self.next_pending_id.saturating_add(1);
        Ok(ExternalToolId(self.next_pending_id))
    }

    fn pending(&self) -> PendingTools {
        self.pending.clone()
    }

    fn pending_len(&self) -> usize {
        self.pending.borrow().len()
    }

    fn expire_due_pending(
        &mut self,
        now: Instant,
        max_expirations: usize,
    ) -> Vec<PendingCompletion> {
        let due = {
            let pending = self.pending.borrow();
            pending
                .iter()
                .filter_map(|(handle, entry)| match &entry.state {
                    PendingToolState::Pending { waiting_thread, .. }
                        if entry.ticket.expired_at(now) =>
                    {
                        Some((*handle, entry.ticket.clone(), *waiting_thread))
                    }
                    PendingToolState::Pending { .. } | PendingToolState::Ready(_) => None,
                })
                .take(max_expirations)
                .collect::<Vec<_>>()
        };

        due.into_iter()
            .filter_map(|(handle, ticket, waiting_thread)| {
                let result = self.complete_ticket(&ticket, Err(timeout_error(&ticket)));
                let mut pending = self.pending.borrow_mut();
                let entry = pending.get_mut(&handle)?;
                let orphaned = entry.orphaned;
                entry.state = PendingToolState::Ready(result);
                if orphaned {
                    pending.remove(&handle);
                }
                Some(PendingCompletion { waiting_thread })
            })
            .collect()
    }

    fn external_invocation(entry: &PendingTool, now: Instant) -> ExternalToolInvocation {
        let ticket = &entry.ticket;
        ExternalToolInvocation {
            id: entry.id,
            name: ticket.name.clone(),
            input: ticket.input.clone(),
            call_index: ticket.call_index,
            attempt: entry.attempt,
            max_attempts: ticket.max_attempts,
            idempotency_key: entry.idempotency_key.clone(),
            stream: ticket.stream.clone(),
            format: ticket.data_format,
            max_output_bytes: ticket.max_output_bytes,
            remaining_deadline_millis: ticket.remaining_deadline_millis(now),
        }
    }

    fn external_cancellation_request(entry: &PendingTool) -> ExternalToolCancellationRequest {
        ExternalToolCancellationRequest {
            id: entry.id,
            name: entry.ticket.name.clone(),
            call_index: entry.ticket.call_index,
            attempt: entry.attempt,
            idempotency_key: entry.idempotency_key.clone(),
        }
    }

    fn claimed_external_ticket(
        &self,
        id: ExternalToolId,
    ) -> Result<(ToolTicket, String, bool), ExternalToolError> {
        let pending = self.pending.borrow();
        let Some(entry) = pending.values().find(|entry| entry.id == id) else {
            return Err(ExternalToolError::Unknown(id));
        };
        match &entry.state {
            PendingToolState::Pending {
                dispatch: PendingDispatch::ExternalClaimed,
                ..
            } => Ok((entry.ticket.clone(), entry.idempotency_key.clone(), false)),
            PendingToolState::Pending {
                dispatch: PendingDispatch::ExternalCancellationRequested,
                ..
            } => Ok((entry.ticket.clone(), entry.idempotency_key.clone(), true)),
            PendingToolState::Pending {
                dispatch: PendingDispatch::ExternalQueued,
                ..
            } => Err(ExternalToolError::NotClaimed(id)),
            PendingToolState::Pending {
                dispatch: PendingDispatch::HostPump,
                ..
            } => Err(ExternalToolError::NotExternal(id)),
            PendingToolState::Ready(_) => Err(ExternalToolError::AlreadyCompleted(id)),
        }
    }

    fn validate_claimed_external(&self, id: ExternalToolId) -> Result<(), ExternalToolError> {
        let (ticket, _, cancellation_requested) = self.claimed_external_ticket(id)?;
        if cancellation_requested {
            return Err(ExternalToolError::CancellationRequested(id));
        }
        if ticket.expired_at(Instant::now()) {
            return Err(ExternalToolError::DeadlineElapsed(id));
        }
        Ok(())
    }

    fn request_external_cancellation(
        &mut self,
        id: ExternalToolId,
    ) -> Result<ExternalToolCancellationRequest, ExternalToolError> {
        let (request, ticket, newly_requested) = {
            let mut pending = self.pending.borrow_mut();
            let Some(entry) = pending.values_mut().find(|entry| entry.id == id) else {
                return Err(ExternalToolError::Unknown(id));
            };
            let (waiting_thread, newly_requested) = match &entry.state {
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalClaimed,
                    waiting_thread,
                } => (*waiting_thread, true),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalCancellationRequested,
                    waiting_thread,
                } => (*waiting_thread, false),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalQueued,
                    ..
                } => return Err(ExternalToolError::NotClaimed(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::HostPump,
                    ..
                } => return Err(ExternalToolError::NotExternal(id)),
                PendingToolState::Ready(_) => {
                    return Err(ExternalToolError::AlreadyCompleted(id));
                }
            };
            let request = Self::external_cancellation_request(entry);
            let ticket = entry.ticket.clone();
            if newly_requested {
                entry.state = PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalCancellationRequested,
                    waiting_thread,
                };
            }
            (request, ticket, newly_requested)
        };
        if newly_requested {
            self.record_cancellation_requested(&ticket);
        }
        Ok(request)
    }

    fn external_reconcile_request(
        &self,
        id: ExternalToolId,
        session_id: String,
        request_id: String,
    ) -> Result<OperationReconcileRequest, ExternalToolError> {
        let (ticket, operation_key, _) = self.claimed_external_ticket(id)?;
        if ticket.expired_at(Instant::now()) {
            return Err(ExternalToolError::DeadlineElapsed(id));
        }
        OperationReconcileRequest::new(session_id, request_id, ticket.name, operation_key)
            .map_err(ExternalToolError::Protocol)
    }

    fn reconcile_external(
        &mut self,
        id: ExternalToolId,
        request: &OperationReconcileRequest,
        result: OperationReconcileResult,
    ) -> Result<ExternalReconcileCompletion, ExternalToolError> {
        request.validate().map_err(ExternalToolError::Protocol)?;
        result.validate().map_err(ExternalToolError::Protocol)?;

        let (ticket, operation_key, _) = self.claimed_external_ticket(id)?;
        if request.tool != ticket.name || request.operation_key != operation_key {
            return Err(ExternalToolError::ReconciliationMismatch(id));
        }
        if !result.matches_request(request) {
            return Err(ExternalToolError::ReconciliationMismatch(id));
        }

        match result.status {
            OperationStatus::Running => {
                if ticket.expired_at(Instant::now()) {
                    return Err(ExternalToolError::DeadlineElapsed(id));
                }
                Ok(ExternalReconcileCompletion::Running)
            }
            OperationStatus::Succeeded { payload } => {
                let expected = envelope_format(ticket.data_format);
                let actual = payload.format();
                if actual != expected {
                    return Err(ExternalToolError::Protocol(
                        ProtocolError::PayloadFormatMismatch { expected, actual },
                    ));
                }
                let output = match payload {
                    WorkerPayload::Text(value) => value,
                    WorkerPayload::Json(value) => {
                        serde_json::to_string(&value).map_err(|error| {
                            ExternalToolError::Protocol(ProtocolError::Serialization(
                                error.to_string(),
                            ))
                        })?
                    }
                };
                self.complete_external(id, Ok(output))
                    .map(ExternalReconcileCompletion::Resolved)
            }
            OperationStatus::Failed { message } => self
                .complete_external(id, Err(ToolError::Failed(message)))
                .map(ExternalReconcileCompletion::Resolved),
            OperationStatus::Cancelled => self
                .cancel_external(id)
                .map(ExternalReconcileCompletion::Resolved),
        }
    }

    fn claim_next_external(&mut self) -> Option<ExternalToolInvocation> {
        let id = self.peek_next_external()?.id;
        self.claim_external(id).ok()
    }

    fn peek_next_external(&self) -> Option<ExternalToolInvocation> {
        let pending = self.pending.borrow();
        let entry = pending.values().find(|entry| {
            matches!(
                &entry.state,
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalQueued,
                    ..
                }
            )
        })?;
        Some(Self::external_invocation(entry, Instant::now()))
    }

    fn claim_external(
        &mut self,
        id: ExternalToolId,
    ) -> Result<ExternalToolInvocation, ExternalToolError> {
        let mut pending = self.pending.borrow_mut();
        let Some(entry) = pending.values_mut().find(|entry| entry.id == id) else {
            return Err(ExternalToolError::Unknown(id));
        };
        let waiting_thread = match &entry.state {
            PendingToolState::Pending {
                dispatch: PendingDispatch::ExternalQueued,
                waiting_thread,
            } => *waiting_thread,
            PendingToolState::Pending {
                dispatch:
                    PendingDispatch::ExternalClaimed | PendingDispatch::ExternalCancellationRequested,
                ..
            } => return Err(ExternalToolError::AlreadyClaimed(id)),
            PendingToolState::Pending {
                dispatch: PendingDispatch::HostPump,
                ..
            } => return Err(ExternalToolError::NotExternal(id)),
            PendingToolState::Ready(_) => return Err(ExternalToolError::AlreadyCompleted(id)),
        };
        let invocation = Self::external_invocation(entry, Instant::now());
        entry.state = PendingToolState::Pending {
            dispatch: PendingDispatch::ExternalClaimed,
            waiting_thread,
        };
        Ok(invocation)
    }

    fn retry_external(
        &mut self,
        id: ExternalToolId,
        retry_class: RetryClass,
    ) -> Result<ExternalToolInvocation, ExternalToolError> {
        let now = Instant::now();
        let (ticket, invocation) = {
            let mut pending = self.pending.borrow_mut();
            let Some((_, entry)) = pending.iter_mut().find(|(_, entry)| entry.id == id) else {
                return Err(ExternalToolError::Unknown(id));
            };
            match &entry.state {
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalClaimed,
                    ..
                } => {}
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalCancellationRequested,
                    ..
                } => return Err(ExternalToolError::CancellationRequested(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalQueued,
                    ..
                } => return Err(ExternalToolError::NotClaimed(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::HostPump,
                    ..
                } => return Err(ExternalToolError::NotExternal(id)),
                PendingToolState::Ready(_) => return Err(ExternalToolError::AlreadyCompleted(id)),
            }
            if entry.ticket.expired_at(now) {
                return Err(ExternalToolError::DeadlineElapsed(id));
            }
            if entry.attempt >= entry.ticket.max_attempts {
                return Err(ExternalToolError::RetryLimitReached(id));
            }

            entry.attempt += 1;
            let ticket = entry.ticket.clone();
            let invocation = Self::external_invocation(entry, now);
            (ticket, invocation)
        };
        self.record_retry(&ticket, retry_class);
        Ok(invocation)
    }

    fn push_external_stream_chunk(
        &mut self,
        id: ExternalToolId,
        chunk: &str,
    ) -> Result<ExternalToolStreamChunk, ExternalToolError> {
        let now = Instant::now();
        let source_bytes = chunk.len();
        let prepared = {
            let pending = self.pending.borrow();
            let Some((_, entry)) = pending.iter().find(|(_, entry)| entry.id == id) else {
                return Err(ExternalToolError::Unknown(id));
            };
            match &entry.state {
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalClaimed,
                    ..
                } => {}
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalCancellationRequested,
                    ..
                } => return Err(ExternalToolError::CancellationRequested(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalQueued,
                    ..
                } => return Err(ExternalToolError::NotClaimed(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::HostPump,
                    ..
                } => return Err(ExternalToolError::NotExternal(id)),
                PendingToolState::Ready(_) => return Err(ExternalToolError::AlreadyCompleted(id)),
            }
            if entry.ticket.expired_at(now) {
                return Err(ExternalToolError::DeadlineElapsed(id));
            }

            let ticket = entry.ticket.clone();
            match ticket.stream.clone() {
                None => Err((ticket, ExternalToolError::StreamingDisabled(id))),
                Some(stream)
                    if entry.streamed.chunks >= stream.max_chunks
                        || source_bytes > stream.max_chunk_bytes
                        || source_bytes
                            > stream
                                .max_total_bytes
                                .saturating_sub(entry.streamed.source_bytes) =>
                {
                    Err((ticket, ExternalToolError::StreamLimitExceeded(id)))
                }
                Some(stream) => Ok((
                    ticket,
                    entry.attempt,
                    entry.idempotency_key.clone(),
                    stream,
                    entry.streamed.emitted_bytes,
                )),
            }
        };

        let (ticket, attempt, idempotency_key, stream, emitted_so_far) = match prepared {
            Ok(prepared) => prepared,
            Err((ticket, error)) => return self.reject_stream(ticket, source_bytes, error),
        };
        let text = match self.tools.get_mut(&ticket.name) {
            Some(registered) => match registered.stream_redactor.as_mut() {
                Some(redactor) => redactor(chunk),
                None => chunk.to_owned(),
            },
            None => {
                return self.reject_stream(
                    ticket,
                    source_bytes,
                    ExternalToolError::ToolUnavailable(id),
                );
            }
        };
        let emitted_bytes = text.len();
        if emitted_bytes > stream.max_emitted_bytes.saturating_sub(emitted_so_far) {
            return self.reject_stream(
                ticket,
                source_bytes,
                ExternalToolError::StreamLimitExceeded(id),
            );
        }

        let chunk_index = {
            let mut pending = self.pending.borrow_mut();
            let Some((_, entry)) = pending.iter_mut().find(|(_, entry)| entry.id == id) else {
                return Err(ExternalToolError::Unknown(id));
            };
            match &entry.state {
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalClaimed,
                    ..
                } => {}
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalCancellationRequested,
                    ..
                } => return Err(ExternalToolError::CancellationRequested(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalQueued,
                    ..
                } => return Err(ExternalToolError::NotClaimed(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::HostPump,
                    ..
                } => return Err(ExternalToolError::NotExternal(id)),
                PendingToolState::Ready(_) => return Err(ExternalToolError::AlreadyCompleted(id)),
            }
            if entry.ticket.expired_at(Instant::now()) {
                return Err(ExternalToolError::DeadlineElapsed(id));
            }
            entry.streamed.chunks = entry.streamed.chunks.saturating_add(1);
            entry.streamed.source_bytes = entry.streamed.source_bytes.saturating_add(source_bytes);
            entry.streamed.emitted_bytes =
                entry.streamed.emitted_bytes.saturating_add(emitted_bytes);
            entry.streamed.chunks
        };
        self.record_stream(&ticket, source_bytes, emitted_bytes, AuditOutcome::Streamed);
        Ok(ExternalToolStreamChunk {
            id,
            name: ticket.name,
            call_index: ticket.call_index,
            attempt,
            chunk_index,
            idempotency_key,
            text,
        })
    }

    fn reject_stream<T>(
        &mut self,
        ticket: ToolTicket,
        source_bytes: usize,
        error: ExternalToolError,
    ) -> Result<T, ExternalToolError> {
        self.record_stream(&ticket, source_bytes, 0, AuditOutcome::StreamDenied);
        Err(error)
    }

    fn complete_external(
        &mut self,
        id: ExternalToolId,
        result: Result<String, ToolError>,
    ) -> Result<PendingCompletion, ExternalToolError> {
        let (handle, ticket, waiting_thread) = {
            let pending = self.pending.borrow();
            let Some((handle, entry)) = pending.iter().find(|(_, entry)| entry.id == id) else {
                return Err(ExternalToolError::Unknown(id));
            };
            match &entry.state {
                PendingToolState::Pending {
                    dispatch:
                        PendingDispatch::ExternalClaimed
                        | PendingDispatch::ExternalCancellationRequested,
                    waiting_thread,
                } => (*handle, entry.ticket.clone(), *waiting_thread),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalQueued,
                    ..
                } => return Err(ExternalToolError::NotClaimed(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::HostPump,
                    ..
                } => return Err(ExternalToolError::NotExternal(id)),
                PendingToolState::Ready(_) => return Err(ExternalToolError::AlreadyCompleted(id)),
            }
        };

        let result = self.complete_ticket(&ticket, result);
        let mut pending = self.pending.borrow_mut();
        let Some(entry) = pending.get_mut(&handle) else {
            return Err(ExternalToolError::Unknown(id));
        };
        let orphaned = entry.orphaned;
        entry.state = PendingToolState::Ready(result);
        if orphaned {
            pending.remove(&handle);
        }
        Ok(PendingCompletion { waiting_thread })
    }

    fn cancel_external(
        &mut self,
        id: ExternalToolId,
    ) -> Result<PendingCompletion, ExternalToolError> {
        self.complete_external(
            id,
            Err(ToolError::Cancelled(
                "external operation was reported cancelled".to_owned(),
            )),
        )
    }

    fn confirm_external_cancellation(
        &mut self,
        id: ExternalToolId,
    ) -> Result<PendingCompletion, ExternalToolError> {
        {
            let pending = self.pending.borrow();
            let Some(entry) = pending.values().find(|entry| entry.id == id) else {
                return Err(ExternalToolError::Unknown(id));
            };
            match &entry.state {
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalCancellationRequested,
                    ..
                } => {}
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalClaimed,
                    ..
                } => return Err(ExternalToolError::CancellationNotRequested(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalQueued,
                    ..
                } => return Err(ExternalToolError::NotClaimed(id)),
                PendingToolState::Pending {
                    dispatch: PendingDispatch::HostPump,
                    ..
                } => return Err(ExternalToolError::NotExternal(id)),
                PendingToolState::Ready(_) => {
                    return Err(ExternalToolError::AlreadyCompleted(id));
                }
            }
        }
        self.cancel_external(id)
    }

    fn run_next_pending(&mut self) -> Option<PendingCompletion> {
        let (handle, ticket, waiting_thread) = {
            let pending = self.pending.borrow();
            pending
                .iter()
                .find_map(|(handle, entry)| match &entry.state {
                    PendingToolState::Pending {
                        dispatch: PendingDispatch::HostPump,
                        waiting_thread,
                    } => Some((*handle, entry.ticket.clone(), *waiting_thread)),
                    PendingToolState::Pending { .. } | PendingToolState::Ready(_) => None,
                })?
        };

        let result = if ticket.expired_at(Instant::now()) {
            self.complete_ticket(&ticket, Err(timeout_error(&ticket)))
        } else {
            self.execute(ticket)
        };
        if let Some(entry) = self.pending.borrow_mut().get_mut(&handle) {
            entry.state = PendingToolState::Ready(result);
        }
        Some(PendingCompletion { waiting_thread })
    }
}

/// Summary of completed tool work and scripts resumed by [`CapabilityRuntime::pump`].
#[derive(Debug, Default)]
pub struct PumpReport {
    /// Number of queued local operations resolved during this pump.
    pub completed: usize,
    /// Evaluations resumed after their corresponding tool result became ready.
    pub resumed: Vec<Evaluation>,
}

/// Summary of deferred operations resolved because their deadline elapsed.
#[derive(Debug, Default)]
pub struct DeadlineReport {
    pub expired: usize,
    pub resumed: Vec<Evaluation>,
}

/// Runtime with only a single script-visible effect surface: `mod.tool`.
///
/// `tool.call` executes synchronously. `tool.start` creates an opaque promise
/// and `promise.await()` suspends the script until a trusted host pump or
/// external completion supplies its result. No worker, filesystem, process, or
/// network API is installed by this crate.
pub struct CapabilityRuntime {
    runtime: Runtime<CapabilityHost, ()>,
    max_pending_tools: usize,
}

impl CapabilityRuntime {
    pub fn new() -> Result<Self, RuntimeError> {
        Self::with_limits(ExecutionLimits::default())
    }

    pub fn with_limits(limits: ExecutionLimits) -> Result<Self, RuntimeError> {
        Self::with_limits_and_pending(limits, DEFAULT_MAX_PENDING_TOOLS)
    }

    pub fn with_limits_and_pending(
        limits: ExecutionLimits,
        max_pending_tools: usize,
    ) -> Result<Self, RuntimeError> {
        Self::with_limits_pending_and_catalog(
            limits,
            max_pending_tools,
            CapabilityCatalogLimits::default(),
        )
    }

    /// Creates a runtime with explicit pending-promise and aggregate catalog
    /// bounds. Use this when a host needs a tighter embedded profile or a
    /// deliberate larger reviewed catalog.
    pub fn with_limits_pending_and_catalog(
        limits: ExecutionLimits,
        max_pending_tools: usize,
        catalog_limits: CapabilityCatalogLimits,
    ) -> Result<Self, RuntimeError> {
        if max_pending_tools == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_pending_tools must be greater than zero",
            ));
        }
        let host = CapabilityHost::with_catalog_limits(catalog_limits)?;
        let mut runtime = Runtime::with_limits(host, (), limits)?;
        install_tool_module(&mut runtime, max_pending_tools);
        Ok(Self {
            runtime,
            max_pending_tools,
        })
    }

    /// Returns the immutable aggregate catalog limits selected at runtime
    /// setup. Splash source cannot read or alter these host limits.
    pub fn catalog_limits(&self) -> CapabilityCatalogLimits {
        self.runtime.host().catalog_limits()
    }

    /// Returns a stable identity for the complete current capability catalog.
    ///
    /// The fingerprint is suitable for binding host approvals to one runtime's
    /// exact names, limits, dispatch modes, metadata, and contract status. It
    /// is not an authorization token.
    pub fn capability_catalog_fingerprint(
        &self,
    ) -> Result<CapabilityCatalogFingerprint, CapabilityLeaseError> {
        self.runtime.host().catalog_fingerprint()
    }

    /// Issues an attenuated, process-local capability lease for this runtime.
    ///
    /// Each requested name must already be registered, and its call budget may
    /// only be equal to or smaller than the registered policy. An empty grant
    /// list is valid for a pure workflow.
    pub fn issue_capability_lease<I>(
        &self,
        grants: I,
    ) -> Result<CapabilityLease, CapabilityLeaseError>
    where
        I: IntoIterator<Item = CapabilityLeaseGrant>,
    {
        self.runtime.host().issue_capability_lease(grants, None)
    }

    /// Issues an attenuated lease with a trusted per-invocation authorization
    /// hook.
    ///
    /// The hook can only deny a call already present in `grants`; it cannot
    /// grant an unlisted capability or widen a call budget.
    pub fn issue_capability_lease_with_authorizer<I, A>(
        &self,
        grants: I,
        authorizer: A,
    ) -> Result<CapabilityLease, CapabilityLeaseError>
    where
        I: IntoIterator<Item = CapabilityLeaseGrant>,
        A: ToolCallAuthorizer + 'static,
    {
        self.runtime
            .host()
            .issue_capability_lease(grants, Some(Box::new(authorizer)))
    }

    /// Issues a lease that covers every currently registered capability at its
    /// current call limit. Prefer [`Self::issue_capability_lease`] for an
    /// operator-reviewed subset.
    pub fn issue_full_capability_lease(&self) -> Result<CapabilityLease, CapabilityLeaseError> {
        self.runtime.host().issue_full_capability_lease()
    }

    /// Verifies that a lease belongs to this runtime and its catalog has not
    /// changed since the lease was issued.
    pub fn validate_capability_lease(
        &self,
        lease: &CapabilityLease,
    ) -> Result<(), CapabilityLeaseError> {
        self.runtime.host().validate_capability_lease(lease)
    }

    /// Evaluates source under an immutable capability lease.
    ///
    /// When `source` suspends on `await`, the lease remains active until the
    /// resumed evaluation completes. Normal `pump`, external completion,
    /// cancellation, and deadline APIs preserve that same lease while they
    /// resume the single-flight VM.
    pub fn eval_with_capability_lease(
        &mut self,
        source: &str,
        lease: &CapabilityLease,
    ) -> Result<Evaluation, CapabilityLeaseEvaluationError> {
        self.runtime
            .host_mut()
            .activate_capability_lease(lease)
            .map_err(CapabilityLeaseEvaluationError::Lease)?;
        let evaluation = self.runtime.eval(source);
        let clear_lease = evaluation.as_ref().map_or(true, |report| !report.suspended);
        if clear_lease {
            self.runtime.host_mut().clear_active_capability_lease();
        }
        evaluation.map_err(CapabilityLeaseEvaluationError::Runtime)
    }

    /// Injects bounded, host-owned JSON under one identifier for a later
    /// Splash evaluation.
    ///
    /// This value is data only. It does not add a capability, alter the
    /// active lease, or let source select Rust bindings. Hosts must retain
    /// responsibility for clearing transient context once an evaluation has
    /// completed. The underlying runtime rejects changes while an evaluation
    /// is suspended so a resumed continuation observes its original context.
    pub fn set_json_global(
        &mut self,
        name: &str,
        value: &JsonValue,
        max_bytes: usize,
        max_depth: usize,
    ) -> Result<(), RuntimeError> {
        self.runtime
            .set_json_global(name, value, max_bytes, max_depth)
    }

    /// Clears a host-injected JSON global after a completed evaluation.
    ///
    /// The identifier remains present with a `nil` value so its prior data can
    /// be reclaimed at the next host-selected garbage-collection point.
    pub fn clear_json_global(&mut self, name: &str) -> Result<(), RuntimeError> {
        self.runtime.clear_json_global(name)
    }

    /// Converts one completed Splash value into bounded JSON for trusted host
    /// orchestration state.
    ///
    /// Script functions, handles, cycles, non-string object keys, non-finite
    /// numbers, and values exceeding either bound are rejected rather than
    /// being coerced into an ambiguous transport representation.
    pub fn script_value_as_json(
        &mut self,
        value: ScriptValue,
        max_bytes: usize,
        max_depth: usize,
    ) -> Result<JsonValue, RuntimeError> {
        self.runtime
            .script_value_as_json(value, max_bytes, max_depth)
    }

    pub fn register_tool<F>(
        &mut self,
        policy: ToolPolicy,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&ToolRequest) -> Result<String, ToolError> + 'static,
    {
        self.runtime.host_mut().register(policy, handler)
    }

    pub fn register_tool_with_metadata<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&ToolRequest) -> Result<String, ToolError> + 'static,
    {
        self.runtime
            .host_mut()
            .register_with_metadata(policy, metadata, handler)
    }

    /// Registers a bounded catalog of descriptor-pinned regular files as one
    /// text capability. See [`CapabilityHost::register_fixed_file_catalog_tool`]
    /// for the authority and containment boundary.
    pub fn register_fixed_file_catalog_tool(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        catalog: fixed_file_catalog::FixedFileCatalog,
    ) -> Result<(), ToolRegistrationError> {
        self.runtime
            .host_mut()
            .register_fixed_file_catalog_tool(policy, metadata, catalog)
    }

    /// Registers a bounded catalog of setup-selected HTTP endpoints as one
    /// JSON capability. See [`CapabilityHost::register_http_endpoint_catalog_tool`]
    /// for the authority and containment boundary.
    #[cfg(feature = "http-endpoint-catalog")]
    pub fn register_http_endpoint_catalog_tool(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        catalog: http_endpoint_catalog::HttpEndpointCatalog,
    ) -> Result<(), ToolRegistrationError> {
        self.runtime
            .host_mut()
            .register_http_endpoint_catalog_tool(policy, metadata, catalog)
    }

    /// Registers a setup-selected HTTPS endpoint catalog with a host-owned
    /// secret resolver. See
    /// [`CapabilityHost::register_http_endpoint_catalog_tool_with_secret_resolver`]
    /// for the authority and disclosure boundary.
    #[cfg(feature = "http-endpoint-catalog")]
    pub fn register_http_endpoint_catalog_tool_with_secret_resolver<R>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        catalog: http_endpoint_catalog::HttpEndpointCatalog,
        secret_resolver: R,
    ) -> Result<(), ToolRegistrationError>
    where
        R: http_endpoint_catalog::HttpEndpointSecretResolver + 'static,
    {
        self.runtime
            .host_mut()
            .register_http_endpoint_catalog_tool_with_secret_resolver(
                policy,
                metadata,
                catalog,
                secret_resolver,
            )
    }

    /// Registers a deferred-only text capability with no in-process handler.
    pub fn register_external_tool(
        &mut self,
        policy: ToolPolicy,
    ) -> Result<(), ToolRegistrationError> {
        self.runtime.host_mut().register_external(policy)
    }

    /// Registers a documented deferred-only text capability with no
    /// in-process handler.
    pub fn register_external_tool_with_metadata(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
    ) -> Result<(), ToolRegistrationError> {
        self.runtime
            .host_mut()
            .register_external_with_metadata(policy, metadata)
    }

    /// Installs a trusted redactor for one streaming external capability.
    pub fn set_external_stream_redactor<F>(
        &mut self,
        name: &str,
        redactor: F,
    ) -> Result<(), StreamConfigurationError>
    where
        F: FnMut(&str) -> String + 'static,
    {
        self.runtime
            .host_mut()
            .set_external_stream_redactor(name, redactor)
    }

    /// Registers a JSON envelope capability backed by trusted Rust code.
    ///
    /// The policy must come from [`ToolPolicy::json`]. Splash scripts use
    /// `tool.call_json` or `tool.start_json`; the handler receives a parsed
    /// [`JsonToolRequest`] and returns a [`JsonValue`].
    pub fn register_json_tool<F>(
        &mut self,
        policy: ToolPolicy,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        self.runtime.host_mut().register_json_tool(policy, handler)
    }

    /// Registers a documented JSON capability. Metadata schemas are prompt
    /// information only; use [`Self::register_validated_json_tool`] when a
    /// bounded executable contract is required.
    pub fn register_json_tool_with_metadata<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        self.runtime
            .host_mut()
            .register_json_tool_with_metadata(policy, metadata, handler)
    }

    /// Registers a JSON capability with executable input and output contracts.
    ///
    /// The contract is checked before the handler runs and before its result
    /// returns to Splash. A rejected input does not consume the call budget.
    pub fn register_validated_json_tool<F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        F: FnMut(&JsonToolRequest) -> Result<JsonValue, ToolError> + 'static,
    {
        self.runtime
            .host_mut()
            .register_validated_json_tool(policy, metadata, contract, handler)
    }

    /// Registers a JSON capability that receives and returns Rust types
    /// through Serde while preserving an executable wire contract.
    pub fn register_typed_json_tool<I, O, F>(
        &mut self,
        policy: ToolPolicy,
        contract: JsonToolContract,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        I: DeserializeOwned + 'static,
        O: Serialize + 'static,
        F: FnMut(I) -> Result<O, ToolError> + 'static,
    {
        self.runtime
            .host_mut()
            .register_typed_json_tool(policy, contract, handler)
    }

    /// Registers a documented typed JSON capability. The JSON contract is
    /// validated before deserialization and after serialization.
    pub fn register_typed_json_tool_with_metadata<I, O, F>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
        handler: F,
    ) -> Result<(), ToolRegistrationError>
    where
        I: DeserializeOwned + 'static,
        O: Serialize + 'static,
        F: FnMut(I) -> Result<O, ToolError> + 'static,
    {
        self.runtime
            .host_mut()
            .register_typed_json_tool_with_metadata(policy, metadata, contract, handler)
    }

    /// Registers a deferred-only JSON capability with no in-process handler.
    pub fn register_external_json_tool(
        &mut self,
        policy: ToolPolicy,
    ) -> Result<(), ToolRegistrationError> {
        self.runtime.host_mut().register_external_json_tool(policy)
    }

    /// Registers a documented deferred-only JSON capability with no
    /// in-process handler.
    pub fn register_external_json_tool_with_metadata(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
    ) -> Result<(), ToolRegistrationError> {
        self.runtime
            .host_mut()
            .register_external_json_tool_with_metadata(policy, metadata)
    }

    /// Registers a deferred-only JSON capability with executable contracts.
    pub fn register_validated_external_json_tool(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
    ) -> Result<(), ToolRegistrationError> {
        self.runtime
            .host_mut()
            .register_validated_external_json_tool(policy, metadata, contract)
    }

    /// Registers a JSON tool whose implementation runs behind a validated
    /// [`ProtocolWorkerClient`] transport.
    ///
    /// The local policy must be an attenuation of the matching worker grant;
    /// a broader policy is rejected before the tool becomes script-visible.
    pub fn register_protocol_json_tool<T>(
        &mut self,
        policy: ToolPolicy,
        client: Rc<RefCell<ProtocolWorkerClient<T>>>,
    ) -> Result<(), ToolRegistrationError>
    where
        T: WorkerTransport + 'static,
    {
        self.register_protocol_json_tool_with_metadata(policy, ToolMetadata::default(), client)
    }

    /// Registers a documented JSON tool whose implementation runs behind a
    /// validated [`ProtocolWorkerClient`] transport.
    pub fn register_protocol_json_tool_with_metadata<T>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        client: Rc<RefCell<ProtocolWorkerClient<T>>>,
    ) -> Result<(), ToolRegistrationError>
    where
        T: WorkerTransport + 'static,
    {
        if !client.borrow().supports_json_policy(&policy) {
            return Err(ToolRegistrationError::IncompatibleWorkerGrant(
                policy.name.clone(),
            ));
        }
        self.register_json_tool_with_metadata(policy, metadata, move |request| {
            client.borrow_mut().dispatch_json(request)
        })
    }

    /// Registers an attenuated worker capability with executable JSON input
    /// and output contracts at the host boundary.
    pub fn register_validated_protocol_json_tool<T>(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        contract: JsonToolContract,
        client: Rc<RefCell<ProtocolWorkerClient<T>>>,
    ) -> Result<(), ToolRegistrationError>
    where
        T: WorkerTransport + 'static,
    {
        if !client.borrow().supports_json_policy(&policy) {
            return Err(ToolRegistrationError::IncompatibleWorkerGrant(
                policy.name.clone(),
            ));
        }
        self.register_validated_json_tool(policy, metadata, contract, move |request| {
            client.borrow_mut().dispatch_json(request)
        })
    }

    /// Evaluates canonical Splash source against this runtime's explicit tool
    /// catalog. Noncanonical Makepad compatibility syntax is rejected before a
    /// capability can be invoked.
    pub fn eval(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        self.runtime.eval(source)
    }

    /// Returns the bounded, ordered in-memory capability audit view.
    ///
    /// The view is not durable. Use [`Self::dropped_audit_events`] to detect
    /// eviction and export events through a host-owned durable sink when full
    /// retention is required.
    pub fn audit(&self) -> AuditLog<'_> {
        self.runtime.host().audit()
    }

    /// Exports retained audit telemetry after a host-maintained source cursor.
    ///
    /// Start with cursor `1` and retain the returned
    /// [`AuditEventBatch::next_event_sequence`] only after a host-owned sink
    /// accepts the batch. A cursor overtaken by eviction fails rather than
    /// silently returning a partial history. This does not create authority or
    /// prove a capability effect.
    pub fn audit_since(
        &self,
        next_event_sequence: u64,
    ) -> Result<AuditEventBatch, AuditEventCursorError> {
        self.runtime.host().audit_since(next_event_sequence)
    }

    /// Returns the current in-memory audit capacity.
    pub fn max_audit_events(&self) -> usize {
        self.runtime.host().max_audit_events()
    }

    /// Returns the number of oldest audit events evicted since the last clear.
    pub fn dropped_audit_events(&self) -> u64 {
        self.runtime.host().dropped_audit_events()
    }

    /// Changes the capacity of the in-memory audit view.
    ///
    /// This host-only observability setting has no effect on capability policy
    /// or on the current lease. Values above [`MAX_AUDIT_EVENTS`] are rejected.
    pub fn set_max_audit_events(
        &mut self,
        max_audit_events: NonZeroUsize,
    ) -> Result<(), RuntimeError> {
        self.runtime
            .host_mut()
            .set_max_audit_events(max_audit_events)
    }

    /// Clears the retained audit view and its eviction counter.
    pub fn clear_audit(&mut self) {
        self.runtime.host_mut().clear_audit();
    }

    /// Returns host-facing capability descriptions in stable name order.
    /// This catalog is not exposed to Splash source by default.
    pub fn tool_catalog(&self) -> Vec<ToolDescriptor> {
        self.runtime.host().tool_catalog()
    }

    pub fn tool_catalog_json(&self) -> Result<String, ToolError> {
        self.runtime.host().tool_catalog_json()
    }

    /// Returns the number of retained deferred-promise records.
    ///
    /// This includes settled records until their VM handles become
    /// unreachable and [`Self::collect_garbage`] runs. It is therefore a
    /// bounded retention count, not an executing-adapter count.
    pub fn pending_tools(&self) -> usize {
        self.runtime.host().pending_len()
    }

    /// Reclaims settled promise records after the VM no longer references
    /// them. Hosts should schedule collection at an appropriate idle point.
    pub fn collect_garbage(&mut self) {
        self.runtime.collect_garbage();
    }

    /// Inspects the next queued external-only invocation without claiming it.
    ///
    /// This is useful when a host must first write a durable operation record.
    /// The returned value grants no authority and remains queued until the host
    /// calls a claim method. It can become stale after another mutable runtime
    /// operation, so prefer [`Self::claim_external_tool`] when an exact ID was
    /// prepared for durable dispatch.
    pub fn peek_next_external_tool(&self) -> Option<ExternalToolInvocation> {
        self.runtime.host().peek_next_external()
    }

    /// Claims one external-only deferred invocation for host dispatch.
    ///
    /// Claimed work is never executed by a pump. The host must finish it with
    /// the external completion or cancellation API.
    pub fn claim_next_external_tool(&mut self) -> Option<ExternalToolInvocation> {
        self.runtime.host_mut().claim_next_external()
    }

    /// Claims one exact queued external-only invocation for host dispatch.
    ///
    /// A stale ID, a local promise, or an already claimed operation fails
    /// without claiming another queued operation. This preserves the durable
    /// binding a host established before dispatch.
    pub fn claim_external_tool(
        &mut self,
        id: ExternalToolId,
    ) -> Result<ExternalToolInvocation, ExternalToolError> {
        self.runtime.host_mut().claim_external(id)
    }

    /// Verifies that an exact external invocation remains claimed and within
    /// its configured deadline, with no cancellation request pending, without
    /// changing its lifecycle state.
    ///
    /// Hosts can use this before dispatching work after a durable persistence
    /// boundary. It never claims, retries, completes, or cancels an operation.
    pub fn validate_claimed_external_tool(
        &self,
        id: ExternalToolId,
    ) -> Result<(), ExternalToolError> {
        self.runtime.host().validate_claimed_external(id)
    }

    /// Creates the worker protocol request for one claimed external operation.
    ///
    /// The request carries the operation's stable idempotency key rather than
    /// its opaque [`ExternalToolId`]. Callers using a custom worker transport
    /// must authenticate the request and matching result before passing the
    /// result to [`Self::reconcile_external_tool`].
    pub fn external_reconcile_request(
        &self,
        id: ExternalToolId,
        session_id: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Result<OperationReconcileRequest, ExternalToolError> {
        self.runtime
            .host()
            .external_reconcile_request(id, session_id.into(), request_id.into())
    }

    /// Creates and authenticates a reconciliation request for a claimed tool.
    ///
    /// This is the preferred bridge for `splash-protocol` workers. The host
    /// sends the returned frame, then passes the worker's returned frame to
    /// [`Self::reconcile_authenticated_external_tool`].
    pub fn prepare_authenticated_external_reconciliation(
        &mut self,
        id: ExternalToolId,
        request_id: impl Into<String>,
        authenticator: &mut SessionAuthenticator,
    ) -> Result<AuthenticatedReconciliationRequest, ExternalToolError> {
        if authenticator.role() != SessionRole::Host {
            return Err(ExternalToolError::ReconciliationRequiresHostAuthenticator);
        }
        let session_id = authenticator.session_id().to_owned();
        let request = self.external_reconcile_request(id, session_id, request_id)?;
        let frame = authenticator
            .seal(WorkerMessage::ReconcileOperation {
                request: request.clone(),
            })
            .map_err(ExternalToolError::Protocol)?;
        Ok(AuthenticatedReconciliationRequest { request, frame })
    }

    /// Applies a validated worker operation state to a claimed external tool.
    ///
    /// The result must have passed transport authentication and sequence
    /// validation. Prefer [`Self::reconcile_authenticated_external_tool`] for
    /// the built-in protocol framing. A `Running` state leaves the promise
    /// pending; every terminal state passes through the normal output contract
    /// and audit boundary before a waiting script is resumed.
    pub fn reconcile_external_tool(
        &mut self,
        id: ExternalToolId,
        request: &OperationReconcileRequest,
        result: OperationReconcileResult,
    ) -> Result<ExternalReconciliation, ExternalToolError> {
        match self
            .runtime
            .host_mut()
            .reconcile_external(id, request, result)?
        {
            ExternalReconcileCompletion::Running => Ok(ExternalReconciliation::Running),
            ExternalReconcileCompletion::Resolved(completion) => self
                .resume_external_completion(completion)
                .map(ExternalReconciliation::Resolved),
        }
    }

    /// Opens an authenticated worker frame and applies its reconciliation
    /// result to a claimed external tool.
    ///
    /// The supplied authenticator must be the host side of the same keyed
    /// session used to prepare the request. Tampered, reflected, replayed, or
    /// incorrectly sequenced frames fail before the pending promise changes.
    pub fn reconcile_authenticated_external_tool(
        &mut self,
        id: ExternalToolId,
        request: &OperationReconcileRequest,
        authenticator: &mut SessionAuthenticator,
        frame: AuthenticatedWorkerMessage,
    ) -> Result<ExternalReconciliation, ExternalToolError> {
        if authenticator.role() != SessionRole::Host {
            return Err(ExternalToolError::ReconciliationRequiresHostAuthenticator);
        }
        let message = authenticator
            .open(frame)
            .map_err(ExternalToolError::Protocol)?;
        let WorkerMessage::ReconciledOperation { result } = message else {
            return Err(ExternalToolError::UnexpectedReconciliationMessage);
        };
        self.reconcile_external_tool(id, request, result)
    }

    /// Marks a claimed operation as cancellation-requested and returns the
    /// stable identity the host should pass to its external adapter.
    ///
    /// Repeating the request is idempotent. This does not resolve the Splash
    /// promise, stop a process, or prove that the adapter stopped. While the
    /// request is pending, the runtime rejects retries, pre-dispatch
    /// validation, and further stream chunks. A terminal result may still win
    /// the race and complete normally.
    pub fn request_external_tool_cancellation(
        &mut self,
        id: ExternalToolId,
    ) -> Result<ExternalToolCancellationRequest, ExternalToolError> {
        self.runtime.host_mut().request_external_cancellation(id)
    }

    /// Schedules another host-owned attempt for a claimed external tool.
    ///
    /// The retry preserves the operation's idempotency key and does not create
    /// another script-visible call or consume additional call budget. Scripts
    /// cannot invoke this API. A pending cancellation request blocks retries.
    pub fn retry_external_tool(
        &mut self,
        id: ExternalToolId,
        retry_class: RetryClass,
    ) -> Result<ExternalToolInvocation, ExternalToolError> {
        self.runtime.host_mut().retry_external(id, retry_class)
    }

    /// Validates, redacts, and returns one host-visible external output chunk.
    ///
    /// The operation must be claimed and registered with a stream policy. The
    /// returned chunk is not delivered to Splash source; call
    /// [`Self::complete_external_tool`] to resolve the script promise.
    pub fn push_external_tool_chunk(
        &mut self,
        id: ExternalToolId,
        chunk: &str,
    ) -> Result<ExternalToolStreamChunk, ExternalToolError> {
        self.runtime
            .host_mut()
            .push_external_stream_chunk(id, chunk)
    }

    /// Delivers a host-produced result for a previously claimed external tool.
    ///
    /// The same byte, JSON envelope, and optional schema checks used by local
    /// handlers are applied before a suspended script is resumed. A terminal
    /// result may complete while cooperative cancellation is still pending.
    pub fn complete_external_tool(
        &mut self,
        id: ExternalToolId,
        result: Result<String, ToolError>,
    ) -> Result<Option<Evaluation>, ExternalToolError> {
        let completion = self.runtime.host_mut().complete_external(id, result)?;
        self.resume_external_completion(completion)
    }

    /// Confirms that an adapter acknowledged a prior cancellation request.
    ///
    /// This is the terminal half of
    /// [`Self::request_external_tool_cancellation`]. A process kill, transport
    /// loss, or deadline is indeterminate and must not call this method unless
    /// a separately trusted adapter contract proves that no effect can remain.
    pub fn confirm_external_tool_cancellation(
        &mut self,
        id: ExternalToolId,
    ) -> Result<Option<Evaluation>, ExternalToolError> {
        let completion = self.runtime.host_mut().confirm_external_cancellation(id)?;
        self.resume_external_completion(completion)
    }

    /// Records a trusted host's terminal assertion that a claimed external
    /// tool is cancelled and resumes its waiter with a cancellation error.
    ///
    /// This compatibility API does not send or stage a cancellation request.
    /// Prefer the request/confirm pair for cooperative adapters. Call this
    /// directly only when the host already has trustworthy terminal evidence.
    pub fn cancel_external_tool(
        &mut self,
        id: ExternalToolId,
    ) -> Result<Option<Evaluation>, ExternalToolError> {
        let completion = self.runtime.host_mut().cancel_external(id)?;
        self.resume_external_completion(completion)
    }

    /// Resolves every currently due deferred operation up to the pending bound.
    ///
    /// Hosts should call this from their event loop when the next deferred
    /// deadline fires. It covers both host-pump and external operations.
    pub fn expire_timed_out_tools(&mut self) -> Result<DeadlineReport, RuntimeError> {
        self.expire_timed_out_tools_up_to(self.max_pending_tools)
    }

    /// Resolves no more than max_expirations due deferred operations.
    pub fn expire_timed_out_tools_up_to(
        &mut self,
        max_expirations: usize,
    ) -> Result<DeadlineReport, RuntimeError> {
        let completions = self
            .runtime
            .host_mut()
            .expire_due_pending(Instant::now(), max_expirations);
        let mut report = DeadlineReport::default();
        for completion in completions {
            report.expired = report.expired.saturating_add(1);
            if let Some(waiting_thread) = completion.waiting_thread {
                let resumed = self.resume_pending_evaluation(waiting_thread)?;
                report.resumed.push(resumed);
            }
        }
        Ok(report)
    }

    pub fn max_pending_tools(&self) -> usize {
        self.max_pending_tools
    }

    /// Runs at most one queued tool, then resumes its awaiting script if any.
    ///
    /// A single-tool default keeps one event-loop tick bounded even when a
    /// script has reserved several granted capabilities.
    pub fn pump(&mut self) -> Result<PumpReport, RuntimeError> {
        self.pump_up_to(1)
    }

    /// Runs no more than `max_completions` queued tools.
    ///
    /// The caller owns both the scheduling point and the batch size. Tool
    /// handlers themselves must still apply their own I/O and CPU deadlines.
    pub fn pump_up_to(&mut self, max_completions: usize) -> Result<PumpReport, RuntimeError> {
        let mut report = PumpReport::default();

        while report.completed < max_completions {
            let Some(completion) = self.runtime.host_mut().run_next_pending() else {
                break;
            };
            report.completed = report.completed.saturating_add(1);
            if let Some(waiting_thread) = completion.waiting_thread {
                let resumed = self.resume_pending_evaluation(waiting_thread)?;
                report.resumed.push(resumed);
            }
        }

        Ok(report)
    }

    fn resume_external_completion(
        &mut self,
        completion: PendingCompletion,
    ) -> Result<Option<Evaluation>, ExternalToolError> {
        let Some(waiting_thread) = completion.waiting_thread else {
            return Ok(None);
        };
        self.resume_pending_evaluation(waiting_thread)
            .map(Some)
            .map_err(ExternalToolError::Runtime)
    }

    fn resume_pending_evaluation(
        &mut self,
        waiting_thread: ScriptThreadId,
    ) -> Result<Evaluation, RuntimeError> {
        match self.runtime.resume(waiting_thread) {
            Ok(resumed) => {
                self.clear_capability_lease_after(&resumed);
                Ok(resumed)
            }
            Err(error) => {
                // Runtime::resume rejects an unknown thread before it can run
                // a continuation. Do not leave its lease freezing this host.
                self.runtime.host_mut().clear_active_capability_lease();
                Err(error)
            }
        }
    }

    fn clear_capability_lease_after(&mut self, evaluation: &Evaluation) {
        if !evaluation.suspended {
            self.runtime.host_mut().clear_active_capability_lease();
        }
    }
}

impl Default for CapabilityRuntime {
    fn default() -> Self {
        Self::new().expect("default execution limits are valid")
    }
}

fn install_tool_module(runtime: &mut Runtime<CapabilityHost, ()>, max_pending_tools: usize) {
    runtime.configure(|vm| {
        let tool = vm.new_module(id!(tool));
        let promise_type = vm.new_handle_type(id_lut!(tool_promise));

        vm.add_handle_method(
            promise_type,
            id_lut!(await),
            script_args_def!(),
            |vm, args| {
                let Some(handle) = script_value!(vm, args.self).as_handle() else {
                    return script_err_not_allowed!(
                        vm.bx.threads.cur_ref().trap,
                        "tool promise expected"
                    );
                };
                let pending = match vm.host.downcast_ref::<CapabilityHost>() {
                    Some(host) => host.pending(),
                    None => {
                        return script_err_unexpected!(
                            vm.bx.threads.cur_ref().trap,
                            "invalid Splash capability host"
                        )
                    }
                };

                let ready = {
                    let mut pending = pending.borrow_mut();
                    let Some(entry) = pending.get_mut(&handle) else {
                        return script_err_not_allowed!(
                            vm.bx.threads.cur_ref().trap,
                            "unknown tool promise"
                        );
                    };

                    match entry.state.clone() {
                        PendingToolState::Ready(result) => Some(result),
                        PendingToolState::Pending {
                            dispatch,
                            waiting_thread: None,
                        } => {
                            let waiting_thread = vm.bx.threads.cur().pause();
                            entry.state = PendingToolState::Pending {
                                dispatch,
                                waiting_thread: Some(waiting_thread),
                            };
                            None
                        }
                        PendingToolState::Pending {
                            waiting_thread: Some(_),
                            ..
                        } => {
                            return script_err_not_allowed!(
                                vm.bx.threads.cur_ref().trap,
                                "tool promise is already awaited"
                            );
                        }
                    }
                };

                match ready {
                    Some(Ok(output)) => {
                        vm.new_string_with(|_, destination| destination.push_str(&output))
                    }
                    Some(Err(error)) => {
                        script_err_not_allowed!(vm.bx.threads.cur_ref().trap, "{}", error)
                    }
                    None => NIL,
                }
            },
        );

        vm.add_method(
            tool,
            id!(call),
            script_args_def!(name = NIL, input = NIL),
            |vm, args| {
                let name = script_text(vm, script_value!(vm, args.name));
                let input = script_text(vm, script_value!(vm, args.input));
                let result = match (name, input) {
                    (Ok(name), Ok(input)) => match vm.host.downcast_mut::<CapabilityHost>() {
                        Some(host) => host.call(&name, &input),
                        None => {
                            return script_err_unexpected!(
                                vm.bx.threads.cur_ref().trap,
                                "invalid Splash capability host"
                            )
                        }
                    },
                    (Err(error), _) | (_, Err(error)) => Err(error),
                };

                match result {
                    Ok(output) => {
                        vm.new_string_with(|_, destination| destination.push_str(&output))
                    }
                    Err(error) => {
                        script_err_not_allowed!(vm.bx.threads.cur_ref().trap, "{}", error)
                    }
                }
            },
        );

        vm.add_method(
            tool,
            id!(call_json),
            script_args_def!(name = NIL, input = NIL),
            |vm, args| {
                let name = script_text(vm, script_value!(vm, args.name));
                let input = script_json(vm, script_value!(vm, args.input));
                let result = match (name, input) {
                    (Ok(name), Ok(input)) => match vm.host.downcast_mut::<CapabilityHost>() {
                        Some(host) => host.call_json(&name, &input),
                        None => {
                            return script_err_unexpected!(
                                vm.bx.threads.cur_ref().trap,
                                "invalid Splash capability host"
                            )
                        }
                    },
                    (Err(error), _) | (_, Err(error)) => Err(error),
                };

                match result {
                    Ok(output) => {
                        vm.new_string_with(|_, destination| destination.push_str(&output))
                    }
                    Err(error) => {
                        script_err_not_allowed!(vm.bx.threads.cur_ref().trap, "{}", error)
                    }
                }
            },
        );

        vm.add_method(
            tool,
            id!(start),
            script_args_def!(name = NIL, input = NIL),
            move |vm, args| {
                let name = script_text(vm, script_value!(vm, args.name));
                let input = script_text(vm, script_value!(vm, args.input));
                let result = match (name, input) {
                    (Ok(name), Ok(input)) => match vm.host.downcast_mut::<CapabilityHost>() {
                        Some(host) => host.begin_async(&name, &input, max_pending_tools),
                        None => {
                            return script_err_unexpected!(
                                vm.bx.threads.cur_ref().trap,
                                "invalid Splash capability host"
                            )
                        }
                    },
                    (Err(error), _) | (_, Err(error)) => Err(error),
                };

                match result {
                    Ok((ticket, pending, id, idempotency_key)) => {
                        new_tool_promise(vm, promise_type, id, ticket, pending, idempotency_key)
                    }
                    Err(error) => {
                        script_err_not_allowed!(vm.bx.threads.cur_ref().trap, "{}", error)
                    }
                }
            },
        );

        vm.add_method(
            tool,
            id!(start_json),
            script_args_def!(name = NIL, input = NIL),
            move |vm, args| {
                let name = script_text(vm, script_value!(vm, args.name));
                let input = script_json(vm, script_value!(vm, args.input));
                let result = match (name, input) {
                    (Ok(name), Ok(input)) => match vm.host.downcast_mut::<CapabilityHost>() {
                        Some(host) => host.begin_async_json(&name, &input, max_pending_tools),
                        None => {
                            return script_err_unexpected!(
                                vm.bx.threads.cur_ref().trap,
                                "invalid Splash capability host"
                            )
                        }
                    },
                    (Err(error), _) | (_, Err(error)) => Err(error),
                };

                match result {
                    Ok((ticket, pending, id, idempotency_key)) => {
                        new_tool_promise(vm, promise_type, id, ticket, pending, idempotency_key)
                    }
                    Err(error) => {
                        script_err_not_allowed!(vm.bx.threads.cur_ref().trap, "{}", error)
                    }
                }
            },
        );
    });
}

fn script_text(vm: &mut vm::ScriptVm, value: ScriptValue) -> Result<String, ToolError> {
    vm.string_with(value, |_, text| text.to_owned())
        .ok_or_else(|| ToolError::Denied("tool API expects a string value".to_owned()))
}

fn script_json(vm: &mut vm::ScriptVm, value: ScriptValue) -> Result<String, ToolError> {
    let serialized = vm.bx.heap.to_json(value);
    script_text(vm, serialized)
}

fn new_tool_promise(
    vm: &mut vm::ScriptVm,
    promise_type: ScriptHandleType,
    id: ExternalToolId,
    ticket: ToolTicket,
    pending: PendingTools,
    idempotency_key: String,
) -> ScriptValue {
    let handle = vm.bx.heap.new_handle(
        promise_type,
        Box::new(ToolPromiseGc {
            pending: pending.clone(),
            handle: ScriptHandle::ZERO,
        }),
    );
    let dispatch = match ticket.dispatch {
        ToolDispatch::HostPump => PendingDispatch::HostPump,
        ToolDispatch::External => PendingDispatch::ExternalQueued,
    };
    pending.borrow_mut().insert(
        handle,
        PendingTool {
            id,
            ticket,
            attempt: 1,
            idempotency_key,
            streamed: StreamAccounting::default(),
            state: PendingToolState::Pending {
                dispatch,
                waiting_thread: None,
            },
            orphaned: false,
        },
    );
    handle.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use splash_protocol::CapabilityGrant;

    struct AddWorker;

    impl WorkerTransport for AddWorker {
        type Error = ProtocolError;

        fn dispatch(
            &mut self,
            invocation: WorkerInvocation,
        ) -> Result<WorkerResult, ProtocolError> {
            let session_id = invocation.session_id;
            let request_id = invocation.request_id;
            let WorkerPayload::Json(input) = invocation.payload else {
                return Err(ProtocolError::InvalidJsonEnvelope);
            };
            let left = input["left"]
                .as_i64()
                .ok_or(ProtocolError::InvalidJsonEnvelope)?;
            let right = input["right"]
                .as_i64()
                .ok_or(ProtocolError::InvalidJsonEnvelope)?;
            WorkerResult::new(
                session_id,
                request_id,
                WorkerPayload::Json(serde_json::json!({"total": left + right})),
            )
        }
    }

    struct LeakyWorker;

    impl WorkerTransport for LeakyWorker {
        type Error = &'static str;

        fn dispatch(&mut self, _invocation: WorkerInvocation) -> Result<WorkerResult, Self::Error> {
            Err("adapter connection secret: production-token")
        }
    }

    struct MismatchedResultWorker {
        discarded: bool,
    }

    impl WorkerTransport for MismatchedResultWorker {
        type Error = ProtocolError;

        fn dispatch(&mut self, invocation: WorkerInvocation) -> Result<WorkerResult, Self::Error> {
            WorkerResult::new(
                "other-worker",
                invocation.request_id,
                WorkerPayload::Json(serde_json::json!({"total": 42})),
            )
        }

        fn discard(&mut self) {
            self.discarded = true;
        }
    }

    fn add_contract() -> JsonToolContract {
        JsonToolContract::new(
            serde_json::json!({
                "type": "object",
                "properties": {
                    "left": {"type": "integer"},
                    "right": {"type": "integer"}
                },
                "required": ["left", "right"],
                "additionalProperties": false
            }),
            serde_json::json!({
                "type": "object",
                "properties": {"total": {"type": "integer"}},
                "required": ["total"],
                "additionalProperties": false
            }),
        )
        .unwrap()
    }

    #[derive(serde::Deserialize)]
    struct AddInput {
        left: i64,
        right: i64,
    }

    #[derive(serde::Serialize)]
    struct AddOutput {
        total: i64,
    }

    #[derive(serde::Deserialize)]
    struct StringAddInput {
        left: String,
        right: String,
    }

    #[derive(serde::Serialize)]
    struct StringAddOutput {
        total: String,
    }

    #[test]
    fn calls_only_a_registered_tool() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();

        let report = runtime
            .eval("use mod.tool\ntool.call(\"text.echo\", \"hello\")")
            .unwrap();

        assert!(report.succeeded(), "{:?}", report.diagnostics);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
        assert_eq!(runtime.audit()[0].tool, "text.echo");
    }

    #[test]
    fn try_catch_recovers_from_a_denied_tool_without_erasing_the_audit() {
        let mut runtime = CapabilityRuntime::default();
        let report = runtime
            .eval(
                "use mod.tool\n\
                 try {\n\
                     tool.call(\"shell.exec\", \"whoami\")\n\
                 } catch {\n\
                     \"denied\"\n\
                 }",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert!(report.diagnostics.is_empty());
        assert_eq!(
            runtime.script_value_as_json(report.value, 64, 4).unwrap(),
            serde_json::json!("denied")
        );
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].tool, "shell.exec");
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn loop_continue_cannot_reenter_an_abandoned_tool_fallback() {
        let handler_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_handler_calls = handler_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), move |request| {
                handler_calls.set(handler_calls.get() + 1);
                Ok(request.input.clone())
            })
            .unwrap();

        let report = runtime
            .eval(
                "use mod.std.assert\n\
                 use mod.tool\n\
                 for index in 2 {\n\
                     if index == 0 {\n\
                         try {\n\
                             continue\n\
                             nil\n\
                         } catch {\n\
                             tool.call(\"text.echo\", \"must not run\")\n\
                         }\n\
                     }\n\
                     assert(false)\n\
                 }",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("assertion failed")));
        assert_eq!(observed_handler_calls.get(), 0);
        assert!(runtime.audit().is_empty());
    }

    #[test]
    fn try_catch_cannot_widen_a_lease_and_can_use_its_granted_fallback() {
        let shell_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_shell_calls = shell_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("shell.exec"), move |_| {
                shell_calls.set(shell_calls.get() + 1);
                Ok("must not run".to_owned())
            })
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let lease = runtime
            .issue_capability_lease([CapabilityLeaseGrant::new("text.echo", 1)])
            .unwrap();

        let report = runtime
            .eval_with_capability_lease(
                "use mod.tool\n\
                 try {\n\
                     tool.call(\"shell.exec\", \"whoami\")\n\
                 } catch {\n\
                     tool.call(\"text.echo\", \"fallback\")\n\
                 }",
                &lease,
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(observed_shell_calls.get(), 0);
        assert_eq!(
            runtime.script_value_as_json(report.value, 64, 4).unwrap(),
            serde_json::json!("fallback")
        );
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn try_catch_does_not_refund_a_failed_tool_call_budget() {
        let handler_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_handler_calls = handler_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.flaky"), move |_| {
                handler_calls.set(handler_calls.get() + 1);
                Err(ToolError::Failed("private adapter detail".to_owned()))
            })
            .unwrap();

        let report = runtime
            .eval(
                "use mod.tool\n\
                 let recovered = try {\n\
                     tool.call(\"text.flaky\", \"first\")\n\
                 } catch {\n\
                     \"fallback\"\n\
                 }\n\
                 tool.call(\"text.flaky\", recovered)",
            )
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(observed_handler_calls.get(), 1);
        assert!(report
            .diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.contains("private adapter detail")));
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Failed);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn try_catch_recovers_from_an_external_failure_after_await() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let initial = runtime
            .eval(
                "use mod.tool\n\
                 fn fetch() {\n\
                     return tool.start(\"text.remote\", \"release\").await()\n\
                 }\n\
                 try {\n\
                     fetch()\n\
                 } catch {\n\
                     \"offline\"\n\
                 }",
            )
            .unwrap();

        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        let resumed = runtime
            .complete_external_tool(
                invocation.id,
                Err(ToolError::Failed("private worker detail".to_owned())),
            )
            .unwrap()
            .unwrap();

        assert!(resumed.completed(), "{:?}", resumed.diagnostics);
        assert!(resumed.diagnostics.is_empty());
        assert_eq!(
            runtime.script_value_as_json(resumed.value, 64, 4).unwrap(),
            serde_json::json!("offline")
        );
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Failed);
    }

    #[test]
    fn calls_json_tools_with_splash_records() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_json_tool(ToolPolicy::json("math.add"), |request| {
                let left = request.input["left"].as_i64().unwrap();
                let right = request.input["right"].as_i64().unwrap();
                Ok(serde_json::json!({"total": left + right}))
            })
            .unwrap();

        let report = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet response_json = tool.call_json(\"math.add\", {left: 20, right: 22})\nlet response = response_json.parse_json()\nassert(response.total == 42)",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn typed_json_tools_validate_before_and_after_serde_conversion() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_typed_json_tool_with_metadata(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds two integer fields through a Rust type."),
                add_contract(),
                |input: AddInput| {
                    Ok(AddOutput {
                        total: input.left + input.right,
                    })
                },
            )
            .unwrap();

        let report = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.call_json(\"math.add\", {left: 20, right: 22})\nlet response = raw.parse_json()\nassert(response.total == 42)",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn typed_json_tools_reject_rust_input_type_mismatches_before_spending_budget() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_typed_json_tool(
                ToolPolicy::json("math.add"),
                add_contract(),
                move |input: StringAddInput| {
                    calls.set(calls.get() + 1);
                    let StringAddInput { left, right } = input;
                    let _ = (left, right);
                    Ok(AddOutput { total: 42 })
                },
            )
            .unwrap();

        let report = runtime
            .eval("use mod.tool\ntool.call_json(\"math.add\", {left: 20, right: 22})")
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(observed_calls.get(), 0);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn typed_json_tools_reject_serialized_output_outside_the_wire_contract() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_typed_json_tool(
                ToolPolicy::json("math.add"),
                add_contract(),
                |_input: AddInput| {
                    Ok(StringAddOutput {
                        total: "forty-two".to_owned(),
                    })
                },
            )
            .unwrap();

        let report = runtime
            .eval("use mod.tool\ntool.call_json(\"math.add\", {left: 20, right: 22})")
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn external_tool_completion_resumes_a_waiting_script_without_host_pump() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool_with_metadata(
                ToolPolicy::new("text.remote"),
                ToolMetadata::new("Completes outside the interpreter process."),
            )
            .unwrap();

        let initial = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.remote\", \"hello\").await()\nassert(output == \"world\")",
            )
            .unwrap();

        assert!(initial.suspended);
        assert_eq!(runtime.pump().unwrap().completed, 0);
        let invocation = runtime.claim_next_external_tool().unwrap();
        assert_eq!(invocation.name, "text.remote");
        assert_eq!(invocation.input, "hello");
        assert_eq!(invocation.format, ToolDataFormat::Text);
        assert_eq!(invocation.remaining_deadline_millis, None);
        assert_eq!(runtime.tool_catalog()[0].dispatch, ToolDispatch::External);

        let resumed = runtime
            .complete_external_tool(invocation.id, Ok("world".to_owned()))
            .unwrap()
            .unwrap();

        assert!(resumed.completed(), "{:?}", resumed.diagnostics);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
        assert!(runtime.claim_next_external_tool().is_none());
    }

    #[test]
    fn external_retries_preserve_one_call_and_a_stable_idempotency_key() {
        let mut policy = ToolPolicy::new("text.remote");
        policy.max_attempts = 2;
        let mut runtime = CapabilityRuntime::default();
        runtime.register_external_tool(policy).unwrap();

        let initial = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.remote\", \"hello\").await()\nassert(output == \"world\")",
            )
            .unwrap();
        assert!(initial.suspended);

        let first = runtime.claim_next_external_tool().unwrap();
        assert_eq!(first.attempt, 1);
        assert_eq!(first.max_attempts, 2);
        assert_eq!(first.call_index, 1);
        assert!(first.idempotency_key.starts_with("splash-"));
        assert_eq!(runtime.tool_catalog()[0].max_attempts, 2);

        let retried = runtime
            .retry_external_tool(first.id, RetryClass::Transient)
            .unwrap();
        assert_eq!(retried.id, first.id);
        assert_eq!(retried.attempt, 2);
        assert_eq!(retried.max_attempts, first.max_attempts);
        assert_eq!(retried.call_index, first.call_index);
        assert_eq!(retried.idempotency_key, first.idempotency_key);
        assert!(runtime.claim_next_external_tool().is_none());
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].event_sequence, 1);
        assert_eq!(runtime.audit()[0].sequence, 0);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::RetryScheduled);
        assert_eq!(runtime.audit()[0].retry_class, Some(RetryClass::Transient));

        let resumed = runtime
            .complete_external_tool(retried.id, Ok("world".to_owned()))
            .unwrap()
            .unwrap();

        assert!(resumed.completed(), "{:?}", resumed.diagnostics);
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(runtime.audit()[1].event_sequence, 2);
        assert_eq!(runtime.audit()[1].sequence, 0);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Allowed);
        assert_eq!(runtime.audit()[1].retry_class, None);

        let batch = runtime.audit_since(1).unwrap();
        assert_eq!(batch.next_event_sequence(), 3);
        assert_eq!(
            batch
                .events()
                .iter()
                .map(|event| event.event_sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            batch
                .events()
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![0, 0]
        );
    }

    #[test]
    fn external_idempotency_keys_are_distinct_across_runtime_sessions() {
        let mut first_runtime = CapabilityRuntime::default();
        first_runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let first_initial = first_runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"first\").await()")
            .unwrap();
        assert!(first_initial.suspended);
        let first_key = first_runtime
            .claim_next_external_tool()
            .unwrap()
            .idempotency_key;

        let mut second_runtime = CapabilityRuntime::default();
        second_runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let second_initial = second_runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"second\").await()")
            .unwrap();
        assert!(second_initial.suspended);
        let second_key = second_runtime
            .claim_next_external_tool()
            .unwrap()
            .idempotency_key;

        assert!(first_key.starts_with("splash-"));
        assert!(second_key.starts_with("splash-"));
        assert_ne!(first_key, second_key);
    }

    #[test]
    fn external_streams_are_redacted_bounded_and_audited() {
        let stream = ToolStreamPolicy::new(3, 8, 12, 12);
        let policy = ToolPolicy::new("text.remote").with_stream(stream.clone());
        let mut runtime = CapabilityRuntime::default();
        runtime.register_external_tool(policy).unwrap();
        runtime
            .set_external_stream_redactor("text.remote", |chunk| {
                chunk.replace("secret", "[redacted]")
            })
            .unwrap();

        let initial = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.remote\", \"hello\").await()\nassert(output == \"done\")",
            )
            .unwrap();
        assert!(initial.suspended);
        assert_eq!(
            runtime
                .set_external_stream_redactor("text.remote", |chunk| chunk.to_owned())
                .unwrap_err(),
            StreamConfigurationError::AlreadyReserved("text.remote".to_owned())
        );
        let invocation = runtime.claim_next_external_tool().unwrap();
        assert_eq!(runtime.tool_catalog()[0].stream, Some(stream.clone()));
        assert_eq!(invocation.stream, Some(stream));

        let first = runtime
            .push_external_tool_chunk(invocation.id, "secret")
            .unwrap();
        assert_eq!(first.text, "[redacted]");
        assert_eq!(first.chunk_index, 1);
        assert_eq!(first.idempotency_key, invocation.idempotency_key);

        let second = runtime
            .push_external_tool_chunk(invocation.id, "ok")
            .unwrap();
        assert_eq!(second.text, "ok");
        assert_eq!(second.chunk_index, 2);
        assert_eq!(
            runtime
                .push_external_tool_chunk(invocation.id, "x")
                .unwrap_err(),
            ExternalToolError::StreamLimitExceeded(invocation.id)
        );
        assert_eq!(
            runtime
                .push_external_tool_chunk(invocation.id, "1234567")
                .unwrap_err(),
            ExternalToolError::StreamLimitExceeded(invocation.id)
        );
        assert_eq!(
            runtime
                .audit()
                .iter()
                .map(|event| event.outcome)
                .collect::<Vec<_>>(),
            vec![
                AuditOutcome::Streamed,
                AuditOutcome::Streamed,
                AuditOutcome::StreamDenied,
                AuditOutcome::StreamDenied,
            ]
        );
        assert_eq!(runtime.audit()[0].input_bytes, 6);
        assert_eq!(runtime.audit()[0].output_bytes, 10);

        let resumed = runtime
            .complete_external_tool(invocation.id, Ok("done".to_owned()))
            .unwrap()
            .unwrap();
        assert!(resumed.completed(), "{:?}", resumed.diagnostics);
        assert_eq!(runtime.audit()[4].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn external_stream_limits_span_retry_attempts() {
        let stream = ToolStreamPolicy::new(1, 8, 8, 8);
        let mut policy = ToolPolicy::new("text.remote").with_stream(stream);
        policy.max_attempts = 2;
        let mut runtime = CapabilityRuntime::default();
        runtime.register_external_tool(policy).unwrap();

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"hello\").await()")
            .unwrap();
        assert!(initial.suspended);
        let first = runtime.claim_next_external_tool().unwrap();
        runtime.push_external_tool_chunk(first.id, "one").unwrap();

        let retry = runtime
            .retry_external_tool(first.id, RetryClass::Transient)
            .unwrap();
        assert_eq!(retry.attempt, 2);
        assert_eq!(
            runtime
                .push_external_tool_chunk(retry.id, "two")
                .unwrap_err(),
            ExternalToolError::StreamLimitExceeded(retry.id)
        );
        assert_eq!(
            runtime
                .audit()
                .iter()
                .map(|event| event.outcome)
                .collect::<Vec<_>>(),
            vec![
                AuditOutcome::Streamed,
                AuditOutcome::RetryScheduled,
                AuditOutcome::StreamDenied,
            ]
        );

        let resumed = runtime
            .complete_external_tool(retry.id, Ok("done".to_owned()))
            .unwrap()
            .unwrap();
        assert!(resumed.succeeded(), "{:?}", resumed.diagnostics);
        assert_eq!(runtime.audit()[3].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn external_streaming_requires_an_explicit_policy() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        assert_eq!(
            runtime
                .set_external_stream_redactor("text.remote", |chunk| chunk.to_owned())
                .unwrap_err(),
            StreamConfigurationError::StreamingDisabled("text.remote".to_owned())
        );

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"hello\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();

        assert_eq!(
            runtime
                .push_external_tool_chunk(invocation.id, "not allowed")
                .unwrap_err(),
            ExternalToolError::StreamingDisabled(invocation.id)
        );
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::StreamDenied);
    }

    #[test]
    fn expired_external_tools_cannot_release_stream_chunks() {
        let mut policy = ToolPolicy::new("text.remote").with_stream(ToolStreamPolicy::default());
        policy.max_deferred_duration = Some(Duration::ZERO);
        let mut runtime = CapabilityRuntime::default();
        runtime.register_external_tool(policy).unwrap();

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"hello\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();

        assert_eq!(
            runtime
                .push_external_tool_chunk(invocation.id, "late output")
                .unwrap_err(),
            ExternalToolError::DeadlineElapsed(invocation.id)
        );
        assert!(runtime.audit().is_empty());

        let report = runtime.expire_timed_out_tools().unwrap();
        assert_eq!(report.expired, 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::TimedOut);
    }

    #[test]
    fn stream_policy_is_rejected_for_local_tools_and_invalid_limits() {
        let stream = ToolStreamPolicy::default();
        let mut runtime = CapabilityRuntime::default();
        let local_error = runtime
            .register_tool(
                ToolPolicy::new("text.echo").with_stream(stream),
                |request| Ok(request.input.clone()),
            )
            .unwrap_err();
        assert_eq!(
            local_error,
            ToolRegistrationError::InvalidPolicy("stream policy requires an external tool")
        );

        let invalid_stream = ToolStreamPolicy {
            max_chunks: 0,
            ..ToolStreamPolicy::default()
        };
        let external_error = runtime
            .register_external_tool(ToolPolicy::new("text.remote").with_stream(invalid_stream))
            .unwrap_err();
        assert_eq!(
            external_error,
            ToolRegistrationError::InvalidPolicy("stream limits must be greater than zero")
        );
    }

    #[test]
    fn exhausted_retry_limit_requires_a_terminal_external_completion() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"hello\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();

        assert_eq!(
            runtime
                .retry_external_tool(invocation.id, RetryClass::RateLimited)
                .unwrap_err(),
            ExternalToolError::RetryLimitReached(invocation.id)
        );
        assert!(runtime.audit().is_empty());

        let resumed = runtime
            .complete_external_tool(
                invocation.id,
                Err(ToolError::Failed("remote worker failed".to_owned())),
            )
            .unwrap()
            .unwrap();

        assert!(!resumed.succeeded());
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Failed);
    }

    #[test]
    fn elapsed_external_deadlines_cannot_be_retried() {
        let mut policy = ToolPolicy::new("text.remote");
        policy.max_attempts = 2;
        policy.max_deferred_duration = Some(Duration::ZERO);
        let mut runtime = CapabilityRuntime::default();
        runtime.register_external_tool(policy).unwrap();

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"hello\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();

        assert_eq!(
            runtime
                .retry_external_tool(invocation.id, RetryClass::Transient)
                .unwrap_err(),
            ExternalToolError::DeadlineElapsed(invocation.id)
        );
        assert!(runtime.audit().is_empty());

        let report = runtime.expire_timed_out_tools().unwrap();
        assert_eq!(report.expired, 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::TimedOut);
    }

    #[test]
    fn external_tools_are_deferred_only_without_consuming_a_call_for_sync_denial() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();

        let denied = runtime
            .eval("use mod.tool\ntool.call(\"text.remote\", \"sync\")")
            .unwrap();

        assert!(!denied.succeeded());
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"deferred\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        let resumed = runtime
            .complete_external_tool(invocation.id, Ok("done".to_owned()))
            .unwrap()
            .unwrap();

        assert!(resumed.completed(), "{:?}", resumed.diagnostics);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn external_invocations_can_be_prepared_before_an_exact_claim() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::json("math.remote"))
            .unwrap();

        let initial = runtime
            .eval(
                "use mod.tool\nlet value = tool.start_json(\"math.remote\", {right: 22, left: 20}).await()\nvalue",
            )
            .unwrap();
        assert!(initial.suspended);

        let prepared = runtime.peek_next_external_tool().unwrap();
        let expected_payload = WorkerPayload::Json(serde_json::json!({"left": 20, "right": 22}));
        assert_eq!(prepared.worker_payload().unwrap(), expected_payload);
        assert_eq!(
            prepared.canonical_input_bytes().unwrap(),
            canonical_operation_input_bytes(&expected_payload).unwrap()
        );
        assert_eq!(runtime.peek_next_external_tool().unwrap(), prepared);

        let claimed = runtime.claim_external_tool(prepared.id).unwrap();
        assert_eq!(claimed, prepared);
        assert!(runtime.peek_next_external_tool().is_none());
        runtime.validate_claimed_external_tool(claimed.id).unwrap();
        assert_eq!(
            runtime.claim_external_tool(claimed.id).unwrap_err(),
            ExternalToolError::AlreadyClaimed(claimed.id)
        );

        let resumed = runtime
            .complete_external_tool(claimed.id, Ok("{\"total\":42}".to_owned()))
            .unwrap()
            .unwrap();
        assert!(resumed.completed(), "{:?}", resumed.diagnostics);
        assert_eq!(
            runtime
                .validate_claimed_external_tool(claimed.id)
                .unwrap_err(),
            ExternalToolError::AlreadyCompleted(claimed.id)
        );
    }

    #[test]
    fn stale_exact_external_claim_does_not_consume_another_queued_operation() {
        let mut policy = ToolPolicy::new("text.remote");
        policy.max_calls = 2;
        let mut runtime = CapabilityRuntime::default();
        runtime.register_external_tool(policy).unwrap();
        let initial = runtime
            .eval(
                "use mod.tool\n\
                 let first = tool.start(\"text.remote\", \"first\")\n\
                 let second = tool.start(\"text.remote\", \"second\")\n\
                 second.await()",
            )
            .unwrap();
        assert!(initial.suspended);

        let first = runtime.peek_next_external_tool().unwrap();
        assert_eq!(first.input, "first");
        runtime.claim_external_tool(first.id).unwrap();
        let second = runtime.peek_next_external_tool().unwrap();
        assert_eq!(second.input, "second");

        assert_eq!(
            runtime.claim_external_tool(first.id).unwrap_err(),
            ExternalToolError::AlreadyClaimed(first.id)
        );
        assert_eq!(runtime.peek_next_external_tool(), Some(second));
    }

    #[test]
    fn cancellation_is_audited_and_cannot_be_completed_twice() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"wait\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();

        let resumed = runtime
            .cancel_external_tool(invocation.id)
            .unwrap()
            .unwrap();

        assert!(!resumed.succeeded());
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Cancelled);
        assert_eq!(
            runtime
                .complete_external_tool(invocation.id, Ok("late".to_owned()))
                .unwrap_err(),
            ExternalToolError::AlreadyCompleted(invocation.id)
        );
    }

    #[test]
    fn cooperative_cancellation_waits_for_acknowledgement_and_is_idempotent() {
        let mut policy = ToolPolicy::new("text.remote");
        policy.max_attempts = 2;
        let mut runtime = CapabilityRuntime::default();
        runtime.register_external_tool(policy).unwrap();

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"wait\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();

        let request = runtime
            .request_external_tool_cancellation(invocation.id)
            .unwrap();
        assert_eq!(request.id, invocation.id);
        assert_eq!(request.name, invocation.name);
        assert_eq!(request.call_index, invocation.call_index);
        assert_eq!(request.attempt, invocation.attempt);
        assert_eq!(request.idempotency_key, invocation.idempotency_key);
        assert_eq!(runtime.pending_tools(), 1);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(
            runtime.audit()[0].outcome,
            AuditOutcome::CancellationRequested
        );
        assert_eq!(
            runtime
                .validate_claimed_external_tool(invocation.id)
                .unwrap_err(),
            ExternalToolError::CancellationRequested(invocation.id)
        );
        assert_eq!(
            runtime
                .retry_external_tool(invocation.id, RetryClass::Transient)
                .unwrap_err(),
            ExternalToolError::CancellationRequested(invocation.id)
        );

        assert_eq!(
            runtime
                .request_external_tool_cancellation(invocation.id)
                .unwrap(),
            request
        );
        assert_eq!(runtime.audit().len(), 1);

        let resumed = runtime
            .confirm_external_tool_cancellation(invocation.id)
            .unwrap()
            .unwrap();
        assert!(!resumed.succeeded());
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Cancelled);
        assert_eq!(
            runtime
                .confirm_external_tool_cancellation(invocation.id)
                .unwrap_err(),
            ExternalToolError::AlreadyCompleted(invocation.id)
        );
    }

    #[test]
    fn cancellation_confirmation_requires_a_prior_request() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"wait\").await()")
            .unwrap();
        let invocation = runtime.claim_next_external_tool().unwrap();

        assert_eq!(
            runtime
                .confirm_external_tool_cancellation(invocation.id)
                .unwrap_err(),
            ExternalToolError::CancellationNotRequested(invocation.id)
        );
        assert_eq!(runtime.pending_tools(), 1);

        let resumed = runtime
            .complete_external_tool(invocation.id, Ok("done".to_owned()))
            .unwrap()
            .unwrap();
        assert!(resumed.succeeded());
    }

    #[test]
    fn terminal_result_can_win_a_cooperative_cancellation_race() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"wait\").await()")
            .unwrap();
        let invocation = runtime.claim_next_external_tool().unwrap();
        runtime
            .request_external_tool_cancellation(invocation.id)
            .unwrap();

        let resumed = runtime
            .complete_external_tool(invocation.id, Ok("done".to_owned()))
            .unwrap()
            .unwrap();
        assert!(resumed.succeeded());
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(
            runtime.audit()[0].outcome,
            AuditOutcome::CancellationRequested
        );
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Allowed);
        assert_eq!(
            runtime
                .confirm_external_tool_cancellation(invocation.id)
                .unwrap_err(),
            ExternalToolError::AlreadyCompleted(invocation.id)
        );
    }

    #[test]
    fn external_deadline_expires_a_claimed_operation_and_resumes_its_waiter() {
        let mut policy = ToolPolicy::new("text.remote");
        policy.max_deferred_duration = Some(Duration::ZERO);
        let mut runtime = CapabilityRuntime::default();
        runtime.register_external_tool(policy).unwrap();

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"wait\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        assert_eq!(invocation.remaining_deadline_millis, Some(0));

        let report = runtime.expire_timed_out_tools().unwrap();

        assert_eq!(report.expired, 1);
        assert_eq!(report.resumed.len(), 1);
        assert!(!report.resumed[0].succeeded());
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::TimedOut);
        assert_eq!(runtime.tool_catalog()[0].max_deferred_millis, Some(0));
        assert_eq!(
            runtime
                .complete_external_tool(invocation.id, Ok("late".to_owned()))
                .unwrap_err(),
            ExternalToolError::AlreadyCompleted(invocation.id)
        );
    }

    #[test]
    fn a_late_external_completion_is_converted_to_a_timeout() {
        let mut policy = ToolPolicy::new("text.remote");
        policy.max_deferred_duration = Some(Duration::ZERO);
        let mut runtime = CapabilityRuntime::default();
        runtime.register_external_tool(policy).unwrap();

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"wait\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();

        let resumed = runtime
            .complete_external_tool(invocation.id, Ok("late".to_owned()))
            .unwrap()
            .unwrap();

        assert!(!resumed.succeeded());
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::TimedOut);
    }

    #[test]
    fn a_host_pump_deadline_prevents_the_local_handler_from_running() {
        let calls = Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        let mut policy = ToolPolicy::new("text.echo");
        policy.max_deferred_duration = Some(Duration::ZERO);
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(policy, move |request| {
                calls.set(calls.get() + 1);
                Ok(request.input.clone())
            })
            .unwrap();

        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.echo\", \"wait\").await()")
            .unwrap();
        assert!(initial.suspended);

        let report = runtime.pump().unwrap();

        assert_eq!(report.completed, 1);
        assert_eq!(report.resumed.len(), 1);
        assert!(!report.resumed[0].succeeded());
        assert_eq!(observed_calls.get(), 0);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::TimedOut);
    }

    #[test]
    fn a_claimed_operation_survives_promise_gc_until_its_audit_is_recorded() {
        let pending = Rc::new(RefCell::new(BTreeMap::new()));
        let handle = ScriptHandle::ZERO;
        let id = ExternalToolId(7);
        pending.borrow_mut().insert(
            handle,
            PendingTool {
                id,
                ticket: ToolTicket {
                    sequence: 0,
                    name: "text.remote".to_owned(),
                    input: "work".to_owned(),
                    input_bytes: 4,
                    call_index: 1,
                    max_output_bytes: 64,
                    max_attempts: 1,
                    stream: None,
                    data_format: ToolDataFormat::Text,
                    dispatch: ToolDispatch::External,
                    deadline: None,
                },
                attempt: 1,
                idempotency_key: "splash-test-0".to_owned(),
                streamed: StreamAccounting::default(),
                state: PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalClaimed,
                    waiting_thread: None,
                },
                orphaned: false,
            },
        );
        let mut gc = ToolPromiseGc {
            pending: pending.clone(),
            handle,
        };

        gc.gc();

        assert!(pending.borrow().contains_key(&handle));
        assert!(pending.borrow()[&handle].orphaned);

        let mut host = CapabilityHost {
            pending: pending.clone(),
            ..CapabilityHost::default()
        };
        host.register_external(ToolPolicy::new("text.remote"))
            .unwrap();
        let completion = host.complete_external(id, Ok("done".to_owned())).unwrap();

        assert!(completion.waiting_thread.is_none());
        assert!(!pending.borrow().contains_key(&handle));
        assert_eq!(host.audit()[0].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn external_json_completion_uses_the_registered_contract() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_validated_external_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds two integer values outside the VM."),
                add_contract(),
            )
            .unwrap();

        let rejected = runtime
            .eval("use mod.tool\ntool.start_json(\"math.add\", {left: 20}).await()")
            .unwrap();
        assert!(!rejected.succeeded());
        assert!(!rejected.suspended);
        assert_eq!(runtime.pending_tools(), 0);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);

        let initial = runtime
            .eval("use mod.tool\ntool.start_json(\"math.add\", {left: 20, right: 22}).await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();

        let resumed = runtime
            .complete_external_tool(invocation.id, Ok("{\"unexpected\":true}".to_owned()))
            .unwrap()
            .unwrap();

        assert!(!resumed.succeeded());
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Denied);
    }

    fn reconciliation_authenticators() -> (SessionAuthenticator, SessionAuthenticator) {
        let key = SessionKey::from_bytes([7; splash_protocol::AUTH_TAG_BYTES]).unwrap();
        (
            SessionAuthenticator::new("worker-1", key.clone(), SessionRole::Host).unwrap(),
            SessionAuthenticator::new("worker-1", key, SessionRole::Worker).unwrap(),
        )
    }

    #[test]
    fn authenticated_reconciliation_resolves_a_claimed_text_operation() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let initial = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.remote\", \"release\").await()\nassert(output == \"done\")",
            )
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        let (mut host, mut worker) = reconciliation_authenticators();

        let outbound = runtime
            .prepare_authenticated_external_reconciliation(invocation.id, "reconcile-1", &mut host)
            .unwrap();
        assert_eq!(
            worker.open(outbound.frame.clone()).unwrap(),
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
                payload: WorkerPayload::Text("done".to_owned()),
            },
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::ReconciledOperation { result })
            .unwrap();

        let reconciliation = runtime
            .reconcile_authenticated_external_tool(
                invocation.id,
                &outbound.request,
                &mut host,
                response,
            )
            .unwrap();
        let ExternalReconciliation::Resolved(Some(resumed)) = reconciliation else {
            panic!("expected the pending script to resume");
        };
        assert!(resumed.completed(), "{:?}", resumed.diagnostics);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn authenticated_reconciliation_rejects_tampering_without_resolving() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"release\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        let (mut host, mut worker) = reconciliation_authenticators();
        let outbound = runtime
            .prepare_authenticated_external_reconciliation(invocation.id, "reconcile-1", &mut host)
            .unwrap();
        worker.open(outbound.frame).unwrap();
        let result = OperationReconcileResult::new(
            outbound.request.session_id.clone(),
            outbound.request.request_id.clone(),
            outbound.request.tool.clone(),
            outbound.request.operation_key.clone(),
            OperationStatus::Succeeded {
                payload: WorkerPayload::Text("done".to_owned()),
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
            runtime
                .reconcile_authenticated_external_tool(
                    invocation.id,
                    &outbound.request,
                    &mut host,
                    tampered,
                )
                .unwrap_err(),
            ExternalToolError::Protocol(ProtocolError::InvalidAuthenticationTag)
        );
        assert_eq!(runtime.pending_tools(), 1);
        assert!(runtime.audit().is_empty());

        assert!(matches!(
            runtime
                .reconcile_authenticated_external_tool(
                    invocation.id,
                    &outbound.request,
                    &mut host,
                    response,
                )
                .unwrap(),
            ExternalReconciliation::Resolved(Some(_))
        ));
    }

    #[test]
    fn authenticated_reconciliation_keeps_running_operations_pending() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"release\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        let (mut host, mut worker) = reconciliation_authenticators();

        let first = runtime
            .prepare_authenticated_external_reconciliation(invocation.id, "reconcile-1", &mut host)
            .unwrap();
        worker.open(first.frame).unwrap();
        let running = OperationReconcileResult::new(
            first.request.session_id.clone(),
            first.request.request_id.clone(),
            first.request.tool.clone(),
            first.request.operation_key.clone(),
            OperationStatus::Running,
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::ReconciledOperation { result: running })
            .unwrap();
        assert!(matches!(
            runtime
                .reconcile_authenticated_external_tool(
                    invocation.id,
                    &first.request,
                    &mut host,
                    response,
                )
                .unwrap(),
            ExternalReconciliation::Running
        ));
        assert_eq!(runtime.pending_tools(), 1);
        assert!(runtime.audit().is_empty());

        let second = runtime
            .prepare_authenticated_external_reconciliation(invocation.id, "reconcile-2", &mut host)
            .unwrap();
        worker.open(second.frame).unwrap();
        let completed = OperationReconcileResult::new(
            second.request.session_id.clone(),
            second.request.request_id.clone(),
            second.request.tool.clone(),
            second.request.operation_key.clone(),
            OperationStatus::Succeeded {
                payload: WorkerPayload::Text("done".to_owned()),
            },
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::ReconciledOperation { result: completed })
            .unwrap();
        assert!(matches!(
            runtime
                .reconcile_authenticated_external_tool(
                    invocation.id,
                    &second.request,
                    &mut host,
                    response,
                )
                .unwrap(),
            ExternalReconciliation::Resolved(Some(_))
        ));
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn authenticated_reconciliation_can_confirm_requested_cancellation() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"release\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        runtime
            .request_external_tool_cancellation(invocation.id)
            .unwrap();
        let (mut host, mut worker) = reconciliation_authenticators();

        let outbound = runtime
            .prepare_authenticated_external_reconciliation(invocation.id, "reconcile-1", &mut host)
            .unwrap();
        worker.open(outbound.frame).unwrap();
        let cancelled = OperationReconcileResult::new(
            outbound.request.session_id.clone(),
            outbound.request.request_id.clone(),
            outbound.request.tool.clone(),
            outbound.request.operation_key.clone(),
            OperationStatus::Cancelled,
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::ReconciledOperation { result: cancelled })
            .unwrap();

        assert!(matches!(
            runtime
                .reconcile_authenticated_external_tool(
                    invocation.id,
                    &outbound.request,
                    &mut host,
                    response,
                )
                .unwrap(),
            ExternalReconciliation::Resolved(Some(_))
        ));
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(
            runtime.audit()[0].outcome,
            AuditOutcome::CancellationRequested
        );
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Cancelled);
    }

    #[test]
    fn reconciliation_rejects_mismatched_bindings_and_payload_formats() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        let initial = runtime
            .eval("use mod.tool\ntool.start(\"text.remote\", \"release\").await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        let request = runtime
            .external_reconcile_request(invocation.id, "worker-1", "reconcile-1")
            .unwrap();

        let mut wrong_request = request.clone();
        wrong_request.operation_key = "other-operation".to_owned();
        let wrong_result = OperationReconcileResult::new(
            wrong_request.session_id.clone(),
            wrong_request.request_id.clone(),
            wrong_request.tool.clone(),
            wrong_request.operation_key.clone(),
            OperationStatus::Succeeded {
                payload: WorkerPayload::Text("done".to_owned()),
            },
        )
        .unwrap();
        assert_eq!(
            runtime
                .reconcile_external_tool(invocation.id, &wrong_request, wrong_result)
                .unwrap_err(),
            ExternalToolError::ReconciliationMismatch(invocation.id)
        );

        let wrong_format = OperationReconcileResult::new(
            request.session_id.clone(),
            request.request_id.clone(),
            request.tool.clone(),
            request.operation_key.clone(),
            OperationStatus::Succeeded {
                payload: WorkerPayload::Json(serde_json::json!({"output": "done"})),
            },
        )
        .unwrap();
        assert_eq!(
            runtime
                .reconcile_external_tool(invocation.id, &request, wrong_format)
                .unwrap_err(),
            ExternalToolError::Protocol(ProtocolError::PayloadFormatMismatch {
                expected: EnvelopeFormat::Text,
                actual: EnvelopeFormat::Json,
            })
        );
        assert_eq!(runtime.pending_tools(), 1);
        assert!(runtime.audit().is_empty());
    }

    #[test]
    fn authenticated_reconciliation_uses_json_output_contracts() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_validated_external_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds two integer values outside the VM."),
                add_contract(),
            )
            .unwrap();
        let initial = runtime
            .eval("use mod.tool\ntool.start_json(\"math.add\", {left: 20, right: 22}).await()")
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();
        let (mut host, mut worker) = reconciliation_authenticators();
        let outbound = runtime
            .prepare_authenticated_external_reconciliation(invocation.id, "reconcile-1", &mut host)
            .unwrap();
        worker.open(outbound.frame).unwrap();
        let result = OperationReconcileResult::new(
            outbound.request.session_id.clone(),
            outbound.request.request_id.clone(),
            outbound.request.tool.clone(),
            outbound.request.operation_key.clone(),
            OperationStatus::Succeeded {
                payload: WorkerPayload::Json(serde_json::json!({"unexpected": true})),
            },
        )
        .unwrap();
        let response = worker
            .seal(WorkerMessage::ReconciledOperation { result })
            .unwrap();

        let reconciliation = runtime
            .reconcile_authenticated_external_tool(
                invocation.id,
                &outbound.request,
                &mut host,
                response,
            )
            .unwrap();
        assert!(matches!(
            reconciliation,
            ExternalReconciliation::Resolved(Some(_))
        ));
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn claimed_external_tools_can_complete_concurrently_within_the_pending_bound() {
        let mut policy = ToolPolicy::new("text.remote");
        policy.max_calls = 2;
        let mut runtime =
            CapabilityRuntime::with_limits_and_pending(ExecutionLimits::default(), 2).unwrap();
        runtime.register_external_tool(policy).unwrap();

        let initial = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet first = tool.start(\"text.remote\", \"first\")\nlet second = tool.start(\"text.remote\", \"second\")\nassert(first.await() == \"first-result\")\nassert(second.await() == \"second-result\")",
            )
            .unwrap();
        assert!(initial.suspended);

        let first_claim = runtime.claim_next_external_tool().unwrap();
        let second_claim = runtime.claim_next_external_tool().unwrap();
        assert_ne!(first_claim.id, second_claim.id);
        assert_ne!(first_claim.idempotency_key, second_claim.idempotency_key);
        let (first, second) = if first_claim.input == "first" {
            (first_claim, second_claim)
        } else {
            (second_claim, first_claim)
        };

        assert!(runtime
            .complete_external_tool(second.id, Ok("second-result".to_owned()))
            .unwrap()
            .is_none());
        let resumed = runtime
            .complete_external_tool(first.id, Ok("first-result".to_owned()))
            .unwrap()
            .unwrap();

        assert!(resumed.completed(), "{:?}", resumed.diagnostics);
        assert_eq!(runtime.audit().len(), 2);
        assert!(runtime
            .audit()
            .iter()
            .all(|event| event.outcome == AuditOutcome::Allowed));
    }

    #[test]
    fn rejects_schema_invalid_input_before_the_handler_without_spending_its_budget() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_validated_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds two integer values."),
                add_contract(),
                move |request| {
                    calls.set(calls.get() + 1);
                    let left = request.input["left"].as_i64().unwrap();
                    let right = request.input["right"].as_i64().unwrap();
                    Ok(serde_json::json!({"total": left + right}))
                },
            )
            .unwrap();

        let rejected = runtime
            .eval("use mod.tool\ntool.call_json(\"math.add\", {left: 20})")
            .unwrap();

        assert!(!rejected.succeeded());
        assert_eq!(observed_calls.get(), 0);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);

        let allowed = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.call_json(\"math.add\", {left: 20, right: 22})\nlet response = raw.parse_json()\nassert(response.total == 42)",
            )
            .unwrap();

        assert!(allowed.completed(), "{:?}", allowed.diagnostics);
        assert_eq!(observed_calls.get(), 1);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn rejects_schema_invalid_output_before_returning_to_splash() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_validated_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds two integer values."),
                add_contract(),
                |_| Ok(serde_json::json!({"unexpected": true})),
            )
            .unwrap();

        let report = runtime
            .eval("use mod.tool\ntool.call_json(\"math.add\", {left: 20, right: 22})")
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn validated_contracts_are_published_in_the_host_catalog() {
        let contract = add_contract();
        let input_schema = contract.input_schema().clone();
        let output_schema = contract.output_schema().clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_validated_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds two integer values."),
                contract,
                |_| Ok(serde_json::json!({"total": 42})),
            )
            .unwrap();

        let catalog = runtime.tool_catalog();

        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].metadata.input_schema, Some(input_schema));
        assert_eq!(catalog[0].metadata.output_schema, Some(output_schema));
        assert!(catalog[0].contract_enforced);
    }

    #[test]
    fn catalog_marks_advisory_json_schemas_as_not_enforced() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_json_tool_with_metadata(
                ToolPolicy::json("math.advisory"),
                ToolMetadata::new("Adds values with schemas supplied for prompting.")
                    .with_input_schema(serde_json::json!({"type": "object"}))
                    .with_output_schema(serde_json::json!({"type": "object"})),
                |_| Ok(serde_json::json!({"total": 42})),
            )
            .unwrap();
        runtime
            .register_validated_json_tool(
                ToolPolicy::json("math.checked"),
                ToolMetadata::new("Adds values under an executable contract."),
                add_contract(),
                |_| Ok(serde_json::json!({"total": 42})),
            )
            .unwrap();

        let catalog = runtime.tool_catalog();
        let advisory = catalog
            .iter()
            .find(|descriptor| descriptor.name == "math.advisory")
            .unwrap();
        let checked = catalog
            .iter()
            .find(|descriptor| descriptor.name == "math.checked")
            .unwrap();

        assert!(!advisory.contract_enforced);
        assert!(checked.contract_enforced);
    }

    #[test]
    fn exposes_a_stable_host_side_tool_catalog() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool_with_metadata(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("Returns the supplied text unchanged."),
                |request| Ok(request.input.clone()),
            )
            .unwrap();
        runtime
            .register_json_tool_with_metadata(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds two integer fields.")
                    .with_input_schema(serde_json::json!({"type": "object"}))
                    .with_output_schema(serde_json::json!({"type": "object"})),
                |_| Ok(serde_json::json!({"total": 42})),
            )
            .unwrap();

        let catalog = runtime.tool_catalog();

        assert_eq!(catalog.len(), 2);
        assert_eq!(catalog[0].name, "math.add");
        assert_eq!(catalog[0].format, ToolDataFormat::Json);
        assert_eq!(catalog[0].metadata.description, "Adds two integer fields.");
        assert_eq!(catalog[1].name, "text.echo");
        assert_eq!(catalog[1].format, ToolDataFormat::Text);
        assert!(catalog[1].metadata.input_schema.is_none());
        let encoded = serde_json::to_value(&catalog).unwrap();
        assert!(encoded.is_array());
        let catalog_json = runtime.tool_catalog_json().unwrap();
        assert!(catalog_json.contains("math.add"));
    }

    #[test]
    fn capability_lease_denies_dynamic_ungranted_tool_names_before_handler_runs() {
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

        let report = runtime
            .eval_with_capability_lease(
                "use mod.tool\nlet selected = \"shell.exec\"\ntool.call(selected, \"whoami\")",
                &lease,
            )
            .unwrap();

        assert!(!report.succeeded(), "{:?}", report.diagnostics);
        assert_eq!(observed_shell_calls.get(), 0);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].tool, "shell.exec");
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn capability_lease_authorizer_can_deny_without_consuming_its_call_budget() {
        let handler_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_handler_calls = handler_calls.clone();
        let allow = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed_allow = allow.clone();
        let authorizer_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_authorizer_calls = authorizer_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), move |request| {
                handler_calls.set(handler_calls.get() + 1);
                Ok(request.input.clone())
            })
            .unwrap();
        let lease = runtime
            .issue_capability_lease_with_authorizer(
                [CapabilityLeaseGrant::new("text.echo", 1)],
                move |request: &ToolRequest, descriptor: &ToolDescriptor| {
                    authorizer_calls.set(authorizer_calls.get() + 1);
                    assert_eq!(request.name, "text.echo");
                    assert_eq!(descriptor.name, "text.echo");
                    if observed_allow.get() {
                        Ok(())
                    } else {
                        Err(ToolError::Denied("operator denied this call".to_owned()))
                    }
                },
            )
            .unwrap();

        let denied = runtime
            .eval_with_capability_lease("use mod.tool\ntool.call(\"text.echo\", \"first\")", &lease)
            .unwrap();
        assert!(!denied.succeeded(), "{:?}", denied.diagnostics);
        assert_eq!(observed_handler_calls.get(), 0);

        allow.set(true);
        let allowed = runtime
            .eval_with_capability_lease(
                "use mod.tool\ntool.call(\"text.echo\", \"second\")",
                &lease,
            )
            .unwrap();
        assert!(allowed.succeeded(), "{:?}", allowed.diagnostics);
        assert_eq!(observed_authorizer_calls.get(), 2);
        assert_eq!(observed_handler_calls.get(), 1);
    }

    #[test]
    fn capability_lease_is_invalidated_when_the_catalog_changes() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let fingerprint = runtime.capability_catalog_fingerprint().unwrap();
        let lease = runtime.issue_full_capability_lease().unwrap();

        runtime
            .register_tool(ToolPolicy::new("text.other"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();

        assert_ne!(
            fingerprint,
            runtime.capability_catalog_fingerprint().unwrap()
        );
        assert_eq!(
            runtime.validate_capability_lease(&lease),
            Err(CapabilityLeaseError::CatalogChanged)
        );
        assert!(matches!(
            runtime.eval_with_capability_lease("let result = 1", &lease),
            Err(CapabilityLeaseEvaluationError::Lease(
                CapabilityLeaseError::CatalogChanged
            ))
        ));
    }

    #[test]
    fn rejects_invalid_tool_metadata() {
        let mut runtime = CapabilityRuntime::default();
        let text_error = runtime
            .register_tool_with_metadata(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("text").with_input_schema(serde_json::json!({})),
                |request| Ok(request.input.clone()),
            )
            .unwrap_err();
        assert_eq!(
            text_error,
            ToolRegistrationError::InvalidMetadata("schemas require a JSON tool policy")
        );

        let schema_error = runtime
            .register_json_tool_with_metadata(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("math").with_input_schema(serde_json::json!([])),
                |_| Ok(serde_json::json!({})),
            )
            .unwrap_err();
        assert_eq!(
            schema_error,
            ToolRegistrationError::InvalidMetadata("tool schemas must be JSON objects")
        );
    }

    #[test]
    fn dispatches_json_capabilities_through_an_attenuated_worker_manifest() {
        let manifest =
            CapabilityManifest::new("worker-1", vec![CapabilityGrant::json("math.add")]).unwrap();
        let client = std::rc::Rc::new(std::cell::RefCell::new(
            ProtocolWorkerClient::new(manifest, AddWorker).unwrap(),
        ));
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_validated_protocol_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds two integer values in an attenuated worker."),
                add_contract(),
                client,
            )
            .unwrap();

        let report = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.call_json(\"math.add\", {left: 20, right: 22})\nlet response = raw.parse_json()\nassert(response.total == 42)",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn protocol_worker_client_hides_transport_error_details_from_splash() {
        let manifest =
            CapabilityManifest::new("worker-1", vec![CapabilityGrant::json("math.add")]).unwrap();
        let mut client = ProtocolWorkerClient::new(manifest, LeakyWorker).unwrap();

        let error = client
            .dispatch_json(&JsonToolRequest {
                name: "math.add".to_owned(),
                input: serde_json::json!({"left": 20, "right": 22}),
                call_index: 1,
            })
            .unwrap_err();

        assert_eq!(
            error,
            ToolError::Failed("worker transport failed".to_owned())
        );
        assert!(!error.to_string().contains("production-token"));
    }

    #[test]
    fn protocol_worker_client_discards_a_session_after_result_validation_fails() {
        let manifest =
            CapabilityManifest::new("worker-1", vec![CapabilityGrant::json("math.add")]).unwrap();
        let mut client =
            ProtocolWorkerClient::new(manifest, MismatchedResultWorker { discarded: false })
                .unwrap();

        assert!(matches!(
            client.dispatch_json(&JsonToolRequest {
                name: "math.add".to_owned(),
                input: serde_json::json!({"left": 20, "right": 22}),
                call_index: 1,
            }),
            Err(ToolError::Failed(message)) if message.starts_with("worker protocol failed:")
        ));
        assert!(client.transport_mut().discarded);
    }

    #[test]
    fn deferred_json_capabilities_dispatch_through_the_worker_manifest() {
        let manifest =
            CapabilityManifest::new("worker-1", vec![CapabilityGrant::json("math.add")]).unwrap();
        let client = std::rc::Rc::new(std::cell::RefCell::new(
            ProtocolWorkerClient::new(manifest, AddWorker).unwrap(),
        ));
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_protocol_json_tool(ToolPolicy::json("math.add"), client)
            .unwrap();

        let initial = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.start_json(\"math.add\", {left: 20, right: 22}).await()\nlet response = raw.parse_json()\nassert(response.total == 42)",
            )
            .unwrap();

        assert!(initial.suspended);
        let pumped = runtime.pump().unwrap();

        assert_eq!(pumped.completed, 1);
        assert_eq!(pumped.resumed.len(), 1);
        assert!(
            pumped.resumed[0].completed(),
            "{:?}",
            pumped.resumed[0].diagnostics
        );
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn rejects_a_local_policy_that_is_broader_than_its_worker_grant() {
        let mut worker_grant = CapabilityGrant::json("math.add");
        worker_grant.max_output_bytes = 32;
        let manifest = CapabilityManifest::new("worker-1", vec![worker_grant]).unwrap();
        let client = std::rc::Rc::new(std::cell::RefCell::new(
            ProtocolWorkerClient::new(manifest, AddWorker).unwrap(),
        ));
        let mut runtime = CapabilityRuntime::default();

        let error = runtime
            .register_protocol_json_tool(ToolPolicy::json("math.add"), client)
            .unwrap_err();

        assert_eq!(
            error,
            ToolRegistrationError::IncompatibleWorkerGrant("math.add".to_owned())
        );
    }

    #[test]
    fn rejects_malformed_json_before_a_json_handler_runs() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_json_tool(ToolPolicy::json("math.add"), move |_| {
                calls.set(calls.get() + 1);
                Ok(serde_json::json!({"total": 42}))
            })
            .unwrap();

        let report = runtime
            .eval("use mod.tool\ntool.call(\"math.add\", \"not-json\")")
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(observed_calls.get(), 0);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn rejects_scalar_json_envelopes_before_a_json_handler_runs() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_json_tool(ToolPolicy::json("math.add"), move |_| {
                calls.set(calls.get() + 1);
                Ok(serde_json::json!({"total": 42}))
            })
            .unwrap();

        let report = runtime
            .eval("use mod.tool\ntool.call_json(\"math.add\", 42)")
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(observed_calls.get(), 0);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn rejects_scalar_json_output_before_returning_it_to_a_script() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_json_tool(ToolPolicy::json("math.add"), |_| Ok(JsonValue::from(42)))
            .unwrap();

        let report = runtime
            .eval("use mod.tool\ntool.call_json(\"math.add\", {left: 20, right: 22})")
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn json_handlers_require_a_json_policy() {
        let mut runtime = CapabilityRuntime::default();
        let error = runtime
            .register_json_tool(ToolPolicy::new("math.add"), |_| Ok(serde_json::json!({})))
            .unwrap_err();

        assert_eq!(
            error,
            ToolRegistrationError::InvalidPolicy("register_json_tool requires ToolPolicy::json")
        );
    }

    #[test]
    fn deferred_json_tools_resume_with_a_json_envelope() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_json_tool(ToolPolicy::json("math.add"), |request| {
                let left = request.input["left"].as_i64().unwrap();
                let right = request.input["right"].as_i64().unwrap();
                Ok(serde_json::json!({"total": left + right}))
            })
            .unwrap();

        let initial = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet response_json = tool.start_json(\"math.add\", {left: 20, right: 22}).await()\nlet response = response_json.parse_json()\nassert(response.total == 42)",
            )
            .unwrap();

        assert!(initial.suspended);
        let pumped = runtime.pump().unwrap();

        assert_eq!(pumped.completed, 1);
        assert_eq!(pumped.resumed.len(), 1);
        assert!(
            pumped.resumed[0].completed(),
            "{:?}",
            pumped.resumed[0].diagnostics
        );
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn denies_unregistered_tools_before_they_run() {
        let mut runtime = CapabilityRuntime::default();
        let report = runtime
            .eval("use mod.tool\ntool.call(\"shell.exec\", \"whoami\")")
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn enforces_the_per_tool_call_budget() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();

        let report = runtime
            .eval(
                "use mod.tool\nlet first = tool.call(\"text.echo\", \"one\")\ntool.call(\"text.echo\", \"two\")",
            )
            .unwrap();

        assert!(!report.succeeded());
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn invalid_tool_names_cannot_be_registered() {
        let mut runtime = CapabilityRuntime::default();
        let error = runtime
            .register_tool(ToolPolicy::new("shell exec"), |_| Ok(String::new()))
            .unwrap_err();

        assert_eq!(
            error,
            ToolRegistrationError::InvalidName("shell exec".to_owned())
        );

        let too_long = "a".repeat(MAX_TOOL_NAME_BYTES + 1);
        let error = runtime
            .register_tool(ToolPolicy::new(too_long.clone()), |_| Ok(String::new()))
            .unwrap_err();
        assert!(matches!(
            error,
            ToolRegistrationError::InvalidName(name) if name == too_long
        ));
    }

    #[test]
    fn audit_replaces_oversized_unrecognized_tool_names_with_a_digest_label() {
        let unrecognized = "a".repeat(MAX_TOOL_NAME_BYTES + 1);
        let source = format!("use mod.tool\ntool.call(\"{unrecognized}\", \"input\")");
        let mut runtime = CapabilityRuntime::default();

        let report = runtime.eval(&source).unwrap();

        assert!(!report.succeeded());
        let event = runtime.audit()[0].clone();
        assert_eq!(event.outcome, AuditOutcome::Denied);
        assert!(event.tool.starts_with(UNRECOGNIZED_AUDIT_TOOL_PREFIX));
        assert!(!event.tool.contains(&unrecognized));
        assert_eq!(
            event.tool.len(),
            UNRECOGNIZED_AUDIT_TOOL_PREFIX.len() + blake3::OUT_LEN * 2
        );
    }

    #[test]
    fn tool_policy_requires_at_least_one_external_attempt() {
        let mut policy = ToolPolicy::new("text.remote");
        policy.max_attempts = 0;
        let mut runtime = CapabilityRuntime::default();

        let error = runtime.register_external_tool(policy).unwrap_err();

        assert_eq!(
            error,
            ToolRegistrationError::InvalidPolicy("max_attempts must be greater than zero")
        );
    }

    #[test]
    fn async_tool_promises_suspend_then_resume_when_the_host_pumps() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), move |request| {
                calls.set(calls.get() + 1);
                Ok(request.input.clone())
            })
            .unwrap();

        let initial = runtime
            .eval(
                "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.echo\", \"hello\").await()\nassert(output == \"hello\")",
            )
            .unwrap();

        assert!(initial.succeeded(), "{:?}", initial.diagnostics);
        assert!(initial.suspended);
        assert_eq!(runtime.pending_tools(), 1);
        assert_eq!(observed_calls.get(), 0);
        assert!(runtime.audit().is_empty());

        let pumped = runtime.pump().unwrap();

        assert_eq!(pumped.completed, 1);
        assert_eq!(pumped.resumed.len(), 1);
        assert!(
            pumped.resumed[0].completed(),
            "{:?}",
            pumped.resumed[0].diagnostics
        );
        assert_eq!(observed_calls.get(), 1);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
    }

    #[test]
    fn capability_lease_survives_await_and_freezes_registration_until_completion() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_calls = calls.clone();
        let mut policy = ToolPolicy::new("text.echo");
        policy.max_calls = 2;
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(policy, move |request| {
                calls.set(calls.get() + 1);
                Ok(request.input.clone())
            })
            .unwrap();
        let lease = runtime
            .issue_capability_lease([CapabilityLeaseGrant::new("text.echo", 1)])
            .unwrap();

        let initial = runtime
            .eval_with_capability_lease(
                "use mod.tool\nlet first = tool.start(\"text.echo\", \"first\")\nfirst.await()\ntool.call(\"text.echo\", \"second\")",
                &lease,
            )
            .unwrap();

        assert!(initial.succeeded(), "{:?}", initial.diagnostics);
        assert!(initial.suspended);
        assert_eq!(
            runtime.eval("let unrelated = 1").unwrap_err(),
            RuntimeError::EvaluationInProgress
        );
        assert_eq!(
            runtime
                .register_tool(ToolPolicy::new("text.other"), |request| {
                    Ok(request.input.clone())
                })
                .unwrap_err(),
            ToolRegistrationError::ActiveCapabilityLease
        );

        let pumped = runtime.pump().unwrap();

        assert_eq!(pumped.completed, 1);
        assert_eq!(pumped.resumed.len(), 1);
        assert!(!pumped.resumed[0].succeeded());
        assert_eq!(observed_calls.get(), 1);
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Denied);
        runtime
            .register_tool(ToolPolicy::new("text.other"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
    }

    #[test]
    fn capability_lease_survives_external_completion_and_checks_the_continuation() {
        let shell_calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed_shell_calls = shell_calls.clone();
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_external_tool(ToolPolicy::new("text.remote"))
            .unwrap();
        runtime
            .register_tool(ToolPolicy::new("shell.exec"), move |_| {
                shell_calls.set(shell_calls.get() + 1);
                Ok("must not run".to_owned())
            })
            .unwrap();
        let lease = runtime
            .issue_capability_lease([CapabilityLeaseGrant::new("text.remote", 1)])
            .unwrap();

        let initial = runtime
            .eval_with_capability_lease(
                "use mod.tool\nlet output = tool.start(\"text.remote\", \"release\").await()\nlet selected = \"shell.exec\"\ntool.call(selected, output)",
                &lease,
            )
            .unwrap();
        assert!(initial.suspended);
        let invocation = runtime.claim_next_external_tool().unwrap();

        let resumed = runtime
            .complete_external_tool(invocation.id, Ok("done".to_owned()))
            .unwrap()
            .unwrap();

        assert!(!resumed.succeeded(), "{:?}", resumed.diagnostics);
        assert_eq!(observed_shell_calls.get(), 0);
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn async_tool_calls_are_denied_before_they_can_suspend() {
        let mut runtime = CapabilityRuntime::default();

        let report = runtime
            .eval("use mod.tool\ntool.start(\"shell.exec\", \"whoami\").await()")
            .unwrap();

        assert!(!report.succeeded());
        assert!(!report.suspended);
        assert_eq!(runtime.pending_tools(), 0);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn rejects_makepad_compatibility_syntax_before_a_capability_can_run() {
        let mut runtime = CapabilityRuntime::default();
        let error = runtime.eval("var value = tool.call(\"shell.exec\", \"whoami\")");

        assert!(matches!(error, Err(RuntimeError::SyntaxRejected(_))));
        assert!(runtime.audit().is_empty());
    }

    #[test]
    fn rejects_a_second_evaluation_while_a_tool_promise_is_suspended() {
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();

        let first = runtime
            .eval("use mod.tool\ntool.start(\"text.echo\", \"hello\").await()")
            .unwrap();

        assert!(first.suspended);
        assert_eq!(
            runtime.eval("let another = 1").unwrap_err(),
            RuntimeError::EvaluationInProgress
        );
    }

    #[test]
    fn requires_a_nonzero_pending_tool_limit() {
        let error = match CapabilityRuntime::with_limits_and_pending(ExecutionLimits::default(), 0)
        {
            Ok(_) => panic!("zero pending-tool limit must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            RuntimeError::InvalidLimits("max_pending_tools must be greater than zero")
        );
    }

    #[test]
    fn bounded_audit_view_evicts_oldest_entries_and_reports_loss() {
        let mut policy = ToolPolicy::new("text.echo");
        policy.max_calls = 4;
        let mut runtime = CapabilityRuntime::default();
        runtime
            .set_max_audit_events(NonZeroUsize::new(2).unwrap())
            .unwrap();
        runtime
            .register_tool(policy, |request| Ok(request.input.clone()))
            .unwrap();

        for input in ["one", "two", "three"] {
            let source = format!("use mod.tool\ntool.call(\"text.echo\", \"{input}\")");
            assert!(runtime.eval(&source).unwrap().completed());
        }

        assert_eq!(runtime.max_audit_events(), 2);
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(runtime.dropped_audit_events(), 1);
        assert_eq!(
            runtime
                .audit()
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );

        runtime
            .set_max_audit_events(NonZeroUsize::new(1).unwrap())
            .unwrap();
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].event_sequence, 3);
        assert_eq!(runtime.audit()[0].sequence, 2);
        assert_eq!(runtime.dropped_audit_events(), 2);
        assert_eq!(
            runtime.audit_since(2).unwrap_err(),
            AuditEventCursorError::Evicted {
                requested: 2,
                earliest_available: 3,
            }
        );
        let batch = runtime.audit_since(3).unwrap();
        assert_eq!(batch.events()[0].event_sequence, 3);
        assert_eq!(batch.next_event_sequence(), 4);

        runtime.clear_audit();
        assert!(runtime.audit().is_empty());
        assert_eq!(runtime.dropped_audit_events(), 0);

        assert_eq!(
            runtime
                .set_max_audit_events(NonZeroUsize::new(MAX_AUDIT_EVENTS + 1).unwrap())
                .unwrap_err(),
            RuntimeError::InvalidLimits("max_audit_events exceeds the hard limit")
        );
    }

    #[test]
    fn audit_export_uses_contiguous_cursors_and_rejects_evicted_history() {
        let mut policy = ToolPolicy::new("text.echo");
        policy.max_calls = 4;
        let mut runtime = CapabilityRuntime::default();
        runtime
            .set_max_audit_events(NonZeroUsize::new(2).unwrap())
            .unwrap();
        runtime
            .register_tool(policy, |request| Ok(request.input.clone()))
            .unwrap();

        for input in ["one", "two", "three"] {
            let source = format!("use mod.tool\ntool.call(\"text.echo\", \"{input}\")");
            assert!(runtime.eval(&source).unwrap().completed());
        }

        assert_eq!(
            runtime.audit_since(0).unwrap_err(),
            AuditEventCursorError::InvalidCursor
        );
        assert_eq!(
            runtime.audit_since(1).unwrap_err(),
            AuditEventCursorError::Evicted {
                requested: 1,
                earliest_available: 2,
            }
        );
        let batch = runtime.audit_since(2).unwrap();
        assert_eq!(batch.first_event_sequence(), 2);
        assert_eq!(batch.next_event_sequence(), 4);
        assert_eq!(
            batch
                .events()
                .iter()
                .map(|event| event.event_sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(
            batch
                .events()
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert!(runtime.audit_since(4).unwrap().is_empty());
        assert_eq!(
            runtime.audit_since(5).unwrap_err(),
            AuditEventCursorError::Ahead {
                requested: 5,
                next_available: 4,
            }
        );

        runtime.clear_audit();
        assert_eq!(
            runtime.audit_since(3).unwrap_err(),
            AuditEventCursorError::Evicted {
                requested: 3,
                earliest_available: 4,
            }
        );
        assert!(runtime.audit_since(4).unwrap().is_empty());

        assert!(runtime
            .eval("use mod.tool\ntool.call(\"text.echo\", \"four\")")
            .unwrap()
            .completed());
        let resumed = runtime.audit_since(4).unwrap();
        assert_eq!(resumed.events()[0].event_sequence, 4);
        assert_eq!(resumed.next_event_sequence(), 5);
    }

    #[test]
    fn catalog_limits_reject_excess_tools_before_mutating_the_catalog() {
        let catalog_limits = CapabilityCatalogLimits {
            max_tools: 1,
            max_serialized_bytes: 8 * 1024,
        };
        let mut runtime = CapabilityRuntime::with_limits_pending_and_catalog(
            ExecutionLimits::default(),
            1,
            catalog_limits,
        )
        .unwrap();
        assert_eq!(runtime.catalog_limits(), catalog_limits);

        runtime
            .register_tool(ToolPolicy::new("text.first"), |request| {
                Ok(request.input.clone())
            })
            .unwrap();
        let error = runtime
            .register_tool(ToolPolicy::new("text.second"), |request| {
                Ok(request.input.clone())
            })
            .unwrap_err();

        assert_eq!(
            error,
            ToolRegistrationError::CatalogToolLimitExceeded { maximum: 1 }
        );
        assert_eq!(
            runtime
                .tool_catalog()
                .iter()
                .map(|descriptor| descriptor.name.as_str())
                .collect::<Vec<_>>(),
            vec!["text.first"]
        );
    }

    #[test]
    fn catalog_limits_reject_excess_serialized_metadata_before_mutating_the_catalog() {
        let mut runtime = CapabilityRuntime::with_limits_pending_and_catalog(
            ExecutionLimits::default(),
            1,
            CapabilityCatalogLimits {
                max_tools: 2,
                max_serialized_bytes: 1,
            },
        )
        .unwrap();
        let error = runtime
            .register_tool_with_metadata(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("Returns text to the caller."),
                |request| Ok(request.input.clone()),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ToolRegistrationError::CatalogByteLimitExceeded {
                actual,
                maximum: 1,
            } if actual > 1
        ));
        assert!(runtime.tool_catalog().is_empty());
    }

    #[test]
    fn rejects_zero_catalog_limits() {
        let error = match CapabilityRuntime::with_limits_pending_and_catalog(
            ExecutionLimits::default(),
            1,
            CapabilityCatalogLimits {
                max_tools: 0,
                max_serialized_bytes: 1,
            },
        ) {
            Ok(_) => panic!("zero catalog tool limit must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            RuntimeError::InvalidLimits("max_catalog_tools must be greater than zero")
        );
    }

    #[test]
    fn default_pump_processes_only_one_capability_per_tick() {
        let mut policy = ToolPolicy::new("text.echo");
        policy.max_calls = 2;
        let mut runtime = CapabilityRuntime::default();
        runtime
            .register_tool(policy, |request| Ok(request.input.clone()))
            .unwrap();

        let initial = runtime
            .eval(
                "use mod.tool\nlet first = tool.start(\"text.echo\", \"one\")\nlet second = tool.start(\"text.echo\", \"two\")\nfirst.await()",
            )
            .unwrap();

        assert!(initial.suspended);
        let pumped = runtime.pump().unwrap();

        assert_eq!(pumped.completed, 1);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].tool, "text.echo");
    }
}
