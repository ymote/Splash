#![forbid(unsafe_code)]

//! A deny-by-default, auditable bridge from Splash to trusted Rust tools.
//!
//! A tool is registered for one runtime instance. A script receives no native
//! access by naming a tool: the host must register it with an explicit policy.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::rc::Rc;

use makepad_script::{
    id, id_lut, script_args_def, script_err_not_allowed, script_err_unexpected, script_value,
    LiveId, ScriptHandle, ScriptHandleGc, ScriptHandleType, ScriptIp, ScriptThreadId, ScriptValue,
    NIL,
};
use serde::Serialize;
pub use serde_json::{json, Value as JsonValue};
use splash_core::{vm, Evaluation, ExecutionLimits, Runtime, RuntimeError};
pub use splash_protocol::{
    CapabilityManifest, ProtocolError, ToolInvocation as WorkerInvocation,
    ToolPayload as WorkerPayload, ToolResult as WorkerResult,
};
use splash_protocol::{EnvelopeFormat, SessionAuthorizer};
pub use splash_schema::{JsonSchema, SchemaError};

/// Maximum number of tool promises a runtime may retain at once.
///
/// Hosts that need a lower bound for a constrained device can choose one with
/// [`CapabilityRuntime::with_limits_and_pending`].
pub const DEFAULT_MAX_PENDING_TOOLS: usize = 64;
pub const MAX_TOOL_DESCRIPTION_BYTES: usize = 4 * 1024;
pub const MAX_TOOL_SCHEMA_BYTES: usize = 32 * 1024;

/// Serialization contract for a capability's input and output envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolDataFormat {
    /// UTF-8 text passed directly to the registered handler.
    Text,
    /// A JSON object or array validated at the capability boundary.
    Json,
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
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
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
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub data_format: ToolDataFormat,
}

impl ToolPolicy {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            max_calls: 1,
            max_input_bytes: 16 * 1024,
            max_output_bytes: 64 * 1024,
            data_format: ToolDataFormat::Text,
        }
    }

    /// Creates a policy for JSON object/array input and output envelopes.
    pub fn json(name: impl Into<String>) -> Self {
        let mut policy = Self::new(name);
        policy.data_format = ToolDataFormat::Json;
        policy
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
        if self.max_input_bytes == 0 || self.max_output_bytes == 0 {
            return Err(ToolRegistrationError::InvalidPolicy(
                "tool byte limits must be greater than zero",
            ));
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
}

impl Display for ToolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(message) => write!(formatter, "tool call denied: {message}"),
            Self::Failed(message) => write!(formatter, "tool call failed: {message}"),
            Self::Cancelled(message) => write!(formatter, "tool call cancelled: {message}"),
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
    pub format: ToolDataFormat,
    pub max_output_bytes: usize,
}

/// Lifecycle errors returned when a host completes or cancels external work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExternalToolError {
    Unknown(ExternalToolId),
    NotExternal(ExternalToolId),
    NotClaimed(ExternalToolId),
    AlreadyCompleted(ExternalToolId),
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
            Self::Runtime(error) => write!(formatter, "could not resume tool operation: {error}"),
        }
    }
}

impl std::error::Error for ExternalToolError {}

/// Transport owned by the trusted host for dispatching a validated worker call.
///
/// Implementations may use a contained child process, a platform IPC service,
/// or an embedded app-provided adapter. Scripts never receive this transport.
pub trait WorkerTransport {
    fn dispatch(&mut self, invocation: WorkerInvocation) -> Result<WorkerResult, ProtocolError>;
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
        .map_err(worker_failed)?;
        let authorized = self
            .authorizer
            .authorize(invocation)
            .map_err(worker_denied)?;
        let result = self
            .transport
            .dispatch(authorized.invocation().clone())
            .map_err(worker_failed)?;
        self.authorizer
            .validate_result(&authorized, &result)
            .map_err(worker_failed)?;

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

fn worker_failed(error: ProtocolError) -> ToolError {
    ToolError::Failed(format!("worker protocol failed: {error}"))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    Allowed,
    Denied,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub tool: String,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub outcome: AuditOutcome,
}

pub type ToolHandler = Box<dyn FnMut(&ToolRequest) -> Result<String, ToolError> + 'static>;
type ToolValidator = Box<dyn Fn(&str) -> Result<(), ToolError> + 'static>;

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
    implementation: ToolImplementation,
}

#[derive(Clone, Debug)]
struct ToolTicket {
    sequence: u64,
    name: String,
    input: String,
    input_bytes: usize,
    call_index: usize,
    max_output_bytes: usize,
    data_format: ToolDataFormat,
    dispatch: ToolDispatch,
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

#[derive(Debug)]
struct PendingTool {
    id: ExternalToolId,
    ticket: ToolTicket,
    state: PendingToolState,
    orphaned: bool,
}

type PendingTools = Rc<RefCell<BTreeMap<ScriptHandle, PendingTool>>>;

struct PendingCompletion {
    waiting_thread: Option<ScriptThreadId>,
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

#[derive(Default)]
pub struct CapabilityHost {
    tools: BTreeMap<String, RegisteredTool>,
    audit: Vec<AuditEvent>,
    next_sequence: u64,
    next_pending_id: u64,
    pending: PendingTools,
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

    fn register_with_validators(
        &mut self,
        policy: ToolPolicy,
        metadata: ToolMetadata,
        input_validator: Option<ToolValidator>,
        output_validator: Option<ToolValidator>,
        dispatch: ToolDispatch,
        implementation: ToolImplementation,
    ) -> Result<(), ToolRegistrationError> {
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
                max_input_bytes: registered.policy.max_input_bytes,
                max_output_bytes: registered.policy.max_output_bytes,
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
                        Self::reserve_registered(sequence, name, input, input_bytes, registered)
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
        Ok(ToolTicket {
            sequence,
            name: name.to_owned(),
            input: input.to_owned(),
            input_bytes,
            call_index: registered.calls,
            max_output_bytes: registered.policy.max_output_bytes,
            data_format: registered.policy.data_format,
            dispatch: registered.dispatch,
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
        let result = result.and_then(|output| self.validate_output(ticket, output));
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
        };
        self.audit.push(AuditEvent {
            sequence: ticket.sequence,
            tool: ticket.name.clone(),
            input_bytes: ticket.input_bytes,
            output_bytes,
            outcome,
        });
    }

    fn record_result(&mut self, sequence: u64, name: &str, input_bytes: usize, error: &ToolError) {
        let outcome = match error {
            ToolError::Denied(_) => AuditOutcome::Denied,
            ToolError::Failed(_) => AuditOutcome::Failed,
            ToolError::Cancelled(_) => AuditOutcome::Cancelled,
        };
        self.audit.push(AuditEvent {
            sequence,
            tool: name.to_owned(),
            input_bytes,
            output_bytes: 0,
            outcome,
        });
    }

    fn begin_async(
        &mut self,
        name: &str,
        input: &str,
        max_pending: usize,
    ) -> Result<(ToolTicket, PendingTools, ExternalToolId), ToolError> {
        self.begin_async_with_format(name, input, max_pending, None)
    }

    fn begin_async_json(
        &mut self,
        name: &str,
        input: &str,
        max_pending: usize,
    ) -> Result<(ToolTicket, PendingTools, ExternalToolId), ToolError> {
        self.begin_async_with_format(name, input, max_pending, Some(ToolDataFormat::Json))
    }

    fn begin_async_with_format(
        &mut self,
        name: &str,
        input: &str,
        max_pending: usize,
        expected_format: Option<ToolDataFormat>,
    ) -> Result<(ToolTicket, PendingTools, ExternalToolId), ToolError> {
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
        Ok((ticket, self.pending.clone(), id))
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
        let (id, ticket, waiting_thread) = match &entry.state {
            PendingToolState::Pending {
                dispatch: PendingDispatch::ExternalQueued,
                waiting_thread,
            } => (entry.id, entry.ticket.clone(), *waiting_thread),
            _ => return None,
        };
        entry.state = PendingToolState::Pending {
            dispatch: PendingDispatch::ExternalClaimed,
            waiting_thread,
        };
        Some(ExternalToolInvocation {
            id,
            name: ticket.name,
            input: ticket.input,
            call_index: ticket.call_index,
            format: ticket.data_format,
            max_output_bytes: ticket.max_output_bytes,
        })
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

        let result = self.execute(ticket);
        if let Some(entry) = self.pending.borrow_mut().get_mut(&handle) {
            entry.state = PendingToolState::Ready(result);
        }
        Some(PendingCompletion { waiting_thread })
    }
}

/// Summary of completed tool work and scripts resumed by [`CapabilityRuntime::pump`].
#[derive(Debug, Default)]
pub struct PumpReport {
    /// Number of queued tool handlers that completed during this pump.
    pub completed: usize,
    /// Evaluations resumed after their corresponding tool result became ready.
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
                    Ok((ticket, pending, id)) => {
                        new_tool_promise(vm, promise_type, id, ticket, pending)
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
                    Ok((ticket, pending, id)) => {
                        new_tool_promise(vm, promise_type, id, ticket, pending)
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
                "use mod.tool\nuse mod.std.assert\nlet response_json = tool.call_json(\"math.add\", {left: 20 right: 22})\nlet response = response_json.parse_json()\nassert(response.total == 42)",
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
                    data_format: ToolDataFormat::Text,
                    dispatch: ToolDispatch::External,
                },
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

        let mut host = CapabilityHost::default();
        host.pending = pending.clone();
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
            .eval("use mod.tool\ntool.start_json(\"math.add\", {left: 20 right: 22}).await()")
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
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.call_json(\"math.add\", {left: 20 right: 22})\nlet response = raw.parse_json()\nassert(response.total == 42)",
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
            .eval("use mod.tool\ntool.call_json(\"math.add\", {left: 20 right: 22})")
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
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.call_json(\"math.add\", {left: 20 right: 22})\nlet response = raw.parse_json()\nassert(response.total == 42)",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(runtime.audit().len(), 1);
        assert_eq!(runtime.audit()[0].outcome, AuditOutcome::Allowed);
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
                "use mod.tool\nuse mod.std.assert\nlet raw = tool.start_json(\"math.add\", {left: 20 right: 22}).await()\nlet response = raw.parse_json()\nassert(response.total == 42)",
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
            .eval("use mod.tool\ntool.call_json(\"math.add\", {left: 20 right: 22})")
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
                "use mod.tool\nuse mod.std.assert\nlet response_json = tool.start_json(\"math.add\", {left: 20 right: 22}).await()\nlet response = response_json.parse_json()\nassert(response.total == 42)",
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
