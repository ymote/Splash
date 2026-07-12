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
    pub max_calls: usize,
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    #[serde(flatten)]
    pub metadata: ToolMetadata,
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
}

impl Display for ToolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(message) => write!(formatter, "tool call denied: {message}"),
            Self::Failed(message) => write!(formatter, "tool call failed: {message}"),
        }
    }
}

impl std::error::Error for ToolError {}

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

struct RegisteredTool {
    policy: ToolPolicy,
    metadata: ToolMetadata,
    calls: usize,
    handler: ToolHandler,
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
}

#[derive(Clone, Debug)]
enum PendingToolState {
    Queued,
    Waiting(ScriptThreadId),
    Ready(Result<String, ToolError>),
}

#[derive(Debug)]
struct PendingTool {
    ticket: ToolTicket,
    state: PendingToolState,
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
        self.pending.borrow_mut().remove(&self.handle);
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
                calls: 0,
                handler: Box::new(handler),
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
        self.register_with_metadata(policy, metadata, move |request| {
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
        })
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
        let ticket = self.reserve(name, input, None)?;
        self.execute(ticket)
    }

    fn call_json(&mut self, name: &str, input: &str) -> Result<String, ToolError> {
        let ticket = self.reserve(name, input, Some(ToolDataFormat::Json))?;
        self.execute(ticket)
    }

    fn reserve(
        &mut self,
        name: &str,
        input: &str,
        expected_format: Option<ToolDataFormat>,
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
                } else if input_bytes > registered.policy.max_input_bytes {
                    Err(ToolError::Denied(format!(
                        "{name} input exceeds {} bytes",
                        registered.policy.max_input_bytes
                    )))
                } else if registered.policy.data_format == ToolDataFormat::Json {
                    match validate_json_envelope(input, name, "input") {
                        Err(error) => Err(error),
                        Ok(()) if registered.calls >= registered.policy.max_calls => {
                            Err(ToolError::Denied(format!(
                                "{name} exhausted its {} call budget",
                                registered.policy.max_calls
                            )))
                        }
                        Ok(()) => {
                            registered.calls = registered.calls.saturating_add(1);
                            Ok(ToolTicket {
                                sequence,
                                name: name.to_owned(),
                                input: input.to_owned(),
                                input_bytes,
                                call_index: registered.calls,
                                max_output_bytes: registered.policy.max_output_bytes,
                                data_format: registered.policy.data_format,
                            })
                        }
                    }
                } else if registered.calls >= registered.policy.max_calls {
                    Err(ToolError::Denied(format!(
                        "{name} exhausted its {} call budget",
                        registered.policy.max_calls
                    )))
                } else {
                    registered.calls = registered.calls.saturating_add(1);
                    Ok(ToolTicket {
                        sequence,
                        name: name.to_owned(),
                        input: input.to_owned(),
                        input_bytes,
                        call_index: registered.calls,
                        max_output_bytes: registered.policy.max_output_bytes,
                        data_format: registered.policy.data_format,
                    })
                }
            }
        };

        if let Err(error) = &result {
            self.record_result(sequence, name, input_bytes, error);
        }
        result
    }

    fn execute(&mut self, ticket: ToolTicket) -> Result<String, ToolError> {
        let result = match self.tools.get_mut(&ticket.name) {
            Some(registered) => {
                let request = ToolRequest {
                    name: ticket.name.clone(),
                    input: ticket.input.clone(),
                    call_index: ticket.call_index,
                };
                match (registered.handler)(&request) {
                    Ok(output) if output.len() <= ticket.max_output_bytes => Ok(output),
                    Ok(_) => Err(ToolError::Denied(format!(
                        "{} output exceeds {} bytes",
                        ticket.name, ticket.max_output_bytes
                    ))),
                    Err(error) => Err(error),
                }
            }
            None => Err(ToolError::Failed(format!(
                "registered capability disappeared: {}",
                ticket.name
            ))),
        };

        let result = match result {
            Ok(output) if ticket.data_format == ToolDataFormat::Json => {
                validate_json_envelope(&output, &ticket.name, "output").map(|()| output)
            }
            other => other,
        };

        self.record_ticket_result(&ticket, &result);
        result
    }

    fn record_ticket_result(&mut self, ticket: &ToolTicket, result: &Result<String, ToolError>) {
        let (output_bytes, outcome) = match result {
            Ok(output) => (output.len(), AuditOutcome::Allowed),
            Err(ToolError::Denied(_)) => (0, AuditOutcome::Denied),
            Err(ToolError::Failed(_)) => (0, AuditOutcome::Failed),
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
    ) -> Result<(ToolTicket, PendingTools), ToolError> {
        self.begin_async_with_format(name, input, max_pending, None)
    }

    fn begin_async_json(
        &mut self,
        name: &str,
        input: &str,
        max_pending: usize,
    ) -> Result<(ToolTicket, PendingTools), ToolError> {
        self.begin_async_with_format(name, input, max_pending, Some(ToolDataFormat::Json))
    }

    fn begin_async_with_format(
        &mut self,
        name: &str,
        input: &str,
        max_pending: usize,
        expected_format: Option<ToolDataFormat>,
    ) -> Result<(ToolTicket, PendingTools), ToolError> {
        if self.pending.borrow().len() >= max_pending {
            let sequence = self.next_sequence;
            self.next_sequence = self.next_sequence.saturating_add(1);
            let error =
                ToolError::Denied(format!("pending tool budget of {max_pending} exhausted"));
            self.record_result(sequence, name, input.len(), &error);
            return Err(error);
        }

        let ticket = self.reserve(name, input, expected_format)?;
        Ok((ticket, self.pending.clone()))
    }

    fn pending(&self) -> PendingTools {
        self.pending.clone()
    }

    fn pending_len(&self) -> usize {
        self.pending.borrow().len()
    }

    fn run_next_pending(&mut self) -> Option<PendingCompletion> {
        let (handle, ticket, waiting_thread) = {
            let pending = self.pending.borrow();
            pending
                .iter()
                .find_map(|(handle, pending)| match &pending.state {
                    PendingToolState::Queued => Some((*handle, pending.ticket.clone(), None)),
                    PendingToolState::Waiting(thread) => {
                        Some((*handle, pending.ticket.clone(), Some(*thread)))
                    }
                    PendingToolState::Ready(_) => None,
                })?
        };

        let result = self.execute(ticket);
        if let Some(pending) = self.pending.borrow_mut().get_mut(&handle) {
            pending.state = PendingToolState::Ready(result);
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
/// and `promise.await()` suspends the script until the trusted host calls
/// [`Self::pump`]. No worker, filesystem, process, or network API is installed
/// by this crate.
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

    /// Registers a documented JSON capability. Schemas are catalog metadata;
    /// they do not replace host-side validation in an adapter.
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

                    match &entry.state {
                        PendingToolState::Ready(result) => Some(result.clone()),
                        PendingToolState::Queued => {
                            let waiting_thread = vm.bx.threads.cur().pause();
                            entry.state = PendingToolState::Waiting(waiting_thread);
                            None
                        }
                        PendingToolState::Waiting(_) => {
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
                    Ok((ticket, pending)) => new_tool_promise(vm, promise_type, ticket, pending),
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
                    Ok((ticket, pending)) => new_tool_promise(vm, promise_type, ticket, pending),
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
    pending.borrow_mut().insert(
        handle,
        PendingTool {
            ticket,
            state: PendingToolState::Queued,
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
            .register_protocol_json_tool(ToolPolicy::json("math.add"), client)
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
