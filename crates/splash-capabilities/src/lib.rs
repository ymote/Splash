#![forbid(unsafe_code)]

//! A deny-by-default, auditable bridge from Splash to trusted Rust tools.
//!
//! A tool is registered for one runtime instance. A script receives no native
//! access by naming a tool: the host must register it with an explicit policy.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use makepad_script::{
    id, id_lut, script_args_def, script_err_not_allowed, script_err_unexpected, script_value,
    LiveId, ScriptHandle, ScriptHandleGc, ScriptHandleType, ScriptIp, ScriptThreadId, ScriptValue,
    NIL,
};
use serde::Serialize;
pub use serde_json::{json, Value as JsonValue};
use splash_core::{vm, Evaluation, ExecutionLimits, Runtime, RuntimeError};
pub use splash_protocol::{
    canonical_operation_input_bytes, AuthenticatedWorkerMessage, CapabilityManifest,
    OperationCompensationBinding, OperationCompensationRequest, OperationCompensationResult,
    OperationDispatchRequest, OperationReconcileRequest, OperationReconcileResult, OperationStatus,
    ProtocolError, SessionAuthenticator, SessionKey, SessionRole,
    ToolInvocation as WorkerInvocation, ToolPayload as WorkerPayload, ToolResult as WorkerResult,
    WorkerCompensationAdmission, WorkerCompensationRecord, WorkerMessage, WorkerOperationAdmission,
    WorkerOperationJournal, WorkerOperationState, WorkerOperationStateKind,
};
use splash_protocol::{EnvelopeFormat, SessionAuthorizer};
pub use splash_schema::{JsonSchema, SchemaError};

/// Authenticated in-process worker transport for app-provided adapters.
///
/// This optional module is useful for mobile and embedded hosts that run a
/// static adapter catalog inside their application. It is not OS containment.
#[cfg(feature = "in-process-worker")]
pub mod in_process_worker;

/// Bounded JSON-line worker transport for host-provided pipe or socket I/O.
///
/// This optional module authenticates ordinary worker frames but does not
/// create or contain a process.
#[cfg(feature = "json-line-worker")]
pub mod json_line_worker;

/// Maximum number of tool promises a runtime may retain at once.
///
/// Hosts that need a lower bound for a constrained device can choose one with
/// [`CapabilityRuntime::with_limits_and_pending`].
pub const DEFAULT_MAX_PENDING_TOOLS: usize = 64;
pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 4 * 1024;
pub const MAX_TOOL_SCHEMA_BYTES: usize = 32 * 1024;
pub const DEFAULT_MAX_STREAM_CHUNKS: usize = 64;
pub const DEFAULT_MAX_STREAM_CHUNK_BYTES: usize = 8 * 1024;
pub const DEFAULT_MAX_STREAM_TOTAL_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_STREAM_EMITTED_BYTES: usize = 64 * 1024;

static NEXT_CAPABILITY_SESSION: AtomicU64 = AtomicU64::new(1);

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

/// Stable, serializable description of a currently granted capability.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ToolDescriptor {
    pub name: String,
    pub format: ToolDataFormat,
    pub dispatch: ToolDispatch,
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
        if self.name.is_empty()
            || !self.name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
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
    AlreadyCompleted(ExternalToolId),
    RetryLimitReached(ExternalToolId),
    DeadlineElapsed(ExternalToolId),
    StreamingDisabled(ExternalToolId),
    StreamLimitExceeded(ExternalToolId),
    ToolUnavailable(ExternalToolId),
    ReconciliationMismatch(ExternalToolId),
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
            Self::AlreadyCompleted(_) => {
                formatter.write_str("external tool operation is already complete")
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
        let result = self
            .transport
            .dispatch(authorized.invocation().clone())
            .map_err(|_| worker_transport_failed())?;
        self.authorizer
            .validate_result(&authorized, &result)
            .map_err(worker_protocol_failed)?;

        match result.payload {
            WorkerPayload::Json(value) => Ok(value),
            WorkerPayload::Text(_) => Err(ToolError::Failed(
                "worker returned text for a JSON capability".to_owned(),
            )),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolRegistrationError {
    Duplicate(String),
    InvalidName(String),
    InvalidPolicy(&'static str),
    InvalidMetadata(&'static str),
    IncompatibleWorkerGrant(String),
}

impl Display for ToolRegistrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(name) => write!(formatter, "tool already registered: {name}"),
            Self::InvalidName(name) => write!(formatter, "invalid tool name: {name}"),
            Self::InvalidPolicy(message) => formatter.write_str(message),
            Self::InvalidMetadata(message) => formatter.write_str(message),
            Self::IncompatibleWorkerGrant(name) => {
                write!(formatter, "worker manifest cannot safely back tool: {name}")
            }
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
    RetryScheduled,
    Streamed,
    StreamDenied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub tool: String,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub outcome: AuditOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_class: Option<RetryClass>,
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
    calls: usize,
    input_validator: Option<ToolValidator>,
    output_validator: Option<ToolValidator>,
    stream_redactor: Option<StreamRedactor>,
    implementation: ToolImplementation,
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
                dispatch: PendingDispatch::ExternalClaimed,
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
    tools: BTreeMap<String, RegisteredTool>,
    audit: Vec<AuditEvent>,
    next_sequence: u64,
    next_pending_id: u64,
    pending: PendingTools,
}

impl Default for CapabilityHost {
    fn default() -> Self {
        Self {
            session_id: NEXT_CAPABILITY_SESSION.fetch_add(1, Ordering::Relaxed),
            tools: BTreeMap::new(),
            audit: Vec::new(),
            next_sequence: 0,
            next_pending_id: 0,
            pending: Rc::new(RefCell::new(BTreeMap::new())),
        }
    }
}

impl CapabilityHost {
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
        self.tools.insert(
            policy.name.clone(),
            RegisteredTool {
                policy,
                metadata,
                dispatch,
                calls: 0,
                input_validator,
                output_validator,
                stream_redactor: None,
                implementation,
            },
        );
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

    pub fn audit(&self) -> &[AuditEvent] {
        &self.audit
    }

    pub fn clear_audit(&mut self) {
        self.audit.clear();
    }

    pub fn tool_catalog(&self) -> Vec<ToolDescriptor> {
        self.tools
            .values()
            .map(|registered| ToolDescriptor {
                name: registered.policy.name.clone(),
                format: registered.policy.data_format,
                dispatch: registered.dispatch,
                max_calls: registered.policy.max_calls,
                max_attempts: registered.policy.max_attempts,
                max_input_bytes: registered.policy.max_input_bytes,
                max_output_bytes: registered.policy.max_output_bytes,
                max_deferred_millis: registered.policy.max_deferred_duration.map(duration_millis),
                stream: registered.policy.stream.clone(),
                metadata: registered.metadata.clone(),
            })
            .collect()
    }

    pub fn tool_catalog_json(&self) -> Result<String, ToolError> {
        serde_json::to_string(&self.tool_catalog()).map_err(|error| {
            ToolError::Failed(format!("tool catalog serialization failed: {error}"))
        })
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

        registered.calls = registered.calls.saturating_add(1);
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
            call_index: registered.calls,
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
        self.audit.push(AuditEvent {
            sequence: ticket.sequence,
            tool: ticket.name.clone(),
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
        self.audit.push(AuditEvent {
            sequence,
            tool: name.to_owned(),
            input_bytes,
            output_bytes: 0,
            outcome,
            retry_class: None,
        });
    }

    fn record_retry(&mut self, ticket: &ToolTicket, retry_class: RetryClass) {
        self.audit.push(AuditEvent {
            sequence: ticket.sequence,
            tool: ticket.name.clone(),
            input_bytes: ticket.input_bytes,
            output_bytes: 0,
            outcome: AuditOutcome::RetryScheduled,
            retry_class: Some(retry_class),
        });
    }

    fn record_stream(
        &mut self,
        ticket: &ToolTicket,
        source_bytes: usize,
        emitted_bytes: usize,
        outcome: AuditOutcome,
    ) {
        self.audit.push(AuditEvent {
            sequence: ticket.sequence,
            tool: ticket.name.clone(),
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
        format!("splash-{}-{}", self.session_id, ticket.sequence)
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

    fn claimed_external_ticket(
        &self,
        id: ExternalToolId,
    ) -> Result<(ToolTicket, String), ExternalToolError> {
        let pending = self.pending.borrow();
        let Some(entry) = pending.values().find(|entry| entry.id == id) else {
            return Err(ExternalToolError::Unknown(id));
        };
        match &entry.state {
            PendingToolState::Pending {
                dispatch: PendingDispatch::ExternalClaimed,
                ..
            } => Ok((entry.ticket.clone(), entry.idempotency_key.clone())),
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

    fn external_reconcile_request(
        &self,
        id: ExternalToolId,
        session_id: String,
        request_id: String,
    ) -> Result<OperationReconcileRequest, ExternalToolError> {
        let (ticket, operation_key) = self.claimed_external_ticket(id)?;
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

        let (ticket, operation_key) = self.claimed_external_ticket(id)?;
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
        let mut pending = self.pending.borrow_mut();
        let handle = pending.iter().find_map(|(handle, entry)| {
            matches!(
                &entry.state,
                PendingToolState::Pending {
                    dispatch: PendingDispatch::ExternalQueued,
                    ..
                }
            )
            .then_some(*handle)
        })?;
        let entry = pending.get_mut(&handle)?;
        let waiting_thread = match &entry.state {
            PendingToolState::Pending {
                dispatch: PendingDispatch::ExternalQueued,
                waiting_thread,
            } => *waiting_thread,
            _ => return None,
        };
        let invocation = Self::external_invocation(entry, Instant::now());
        entry.state = PendingToolState::Pending {
            dispatch: PendingDispatch::ExternalClaimed,
            waiting_thread,
        };
        Some(invocation)
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
                    dispatch: PendingDispatch::ExternalClaimed,
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
                "cancelled by the trusted host".to_owned(),
            )),
        )
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
        if max_pending_tools == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_pending_tools must be greater than zero",
            ));
        }
        let mut runtime = Runtime::with_limits(CapabilityHost::default(), (), limits)?;
        install_tool_module(&mut runtime, max_pending_tools);
        Ok(Self {
            runtime,
            max_pending_tools,
        })
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

    pub fn eval(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        self.runtime.eval(source)
    }

    pub fn audit(&self) -> &[AuditEvent] {
        self.runtime.host().audit()
    }

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

    pub fn pending_tools(&self) -> usize {
        self.runtime.host().pending_len()
    }

    /// Claims one external-only deferred invocation for host dispatch.
    ///
    /// Claimed work is never executed by a pump. The host must finish it with
    /// the external completion or cancellation API.
    pub fn claim_next_external_tool(&mut self) -> Option<ExternalToolInvocation> {
        self.runtime.host_mut().claim_next_external()
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

    /// Schedules another host-owned attempt for a claimed external tool.
    ///
    /// The retry preserves the operation's idempotency key and does not create
    /// another script-visible call or consume additional call budget. Scripts
    /// cannot invoke this API.
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
    /// handlers are applied before a suspended script is resumed.
    pub fn complete_external_tool(
        &mut self,
        id: ExternalToolId,
        result: Result<String, ToolError>,
    ) -> Result<Option<Evaluation>, ExternalToolError> {
        let completion = self.runtime.host_mut().complete_external(id, result)?;
        self.resume_external_completion(completion)
    }

    /// Cancels a claimed external tool and resumes its waiter with a
    /// cancellation error when applicable.
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
                report.resumed.push(self.runtime.resume(waiting_thread)?);
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
                report.resumed.push(self.runtime.resume(waiting_thread)?);
            }
        }

        Ok(report)
    }

    fn resume_external_completion(
        &mut self,
        completion: PendingCompletion,
    ) -> Result<Option<Evaluation>, ExternalToolError> {
        completion
            .waiting_thread
            .map(|thread| {
                self.runtime
                    .resume(thread)
                    .map_err(ExternalToolError::Runtime)
            })
            .transpose()
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
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::RetryScheduled);
        assert_eq!(runtime.audit()[0].retry_class, Some(RetryClass::Transient));

        let resumed = runtime
            .complete_external_tool(retried.id, Ok("world".to_owned()))
            .unwrap()
            .unwrap();

        assert!(resumed.completed(), "{:?}", resumed.diagnostics);
        assert_eq!(runtime.audit().len(), 2);
        assert_eq!(runtime.audit()[1].outcome, AuditOutcome::Allowed);
        assert_eq!(runtime.audit()[1].retry_class, None);
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
