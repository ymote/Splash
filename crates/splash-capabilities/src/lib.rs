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
pub use serde_json::{json, Value as JsonValue};
use splash_core::{vm, Evaluation, ExecutionLimits, Runtime, RuntimeError};

/// Maximum number of tool promises a runtime may retain at once.
///
/// Hosts that need a lower bound for a constrained device can choose one with
/// [`CapabilityRuntime::with_limits_and_pending`].
pub const DEFAULT_MAX_PENDING_TOOLS: usize = 64;

/// Serialization contract for a capability's input and output envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolDataFormat {
    /// UTF-8 text passed directly to the registered handler.
    Text,
    /// A JSON object or array validated at the capability boundary.
    Json,
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
}

impl Display for ToolRegistrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(name) => write!(formatter, "tool already registered: {name}"),
            Self::InvalidName(name) => write!(formatter, "invalid tool name: {name}"),
            Self::InvalidPolicy(message) => formatter.write_str(message),
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
        policy.validate()?;
        if self.tools.contains_key(&policy.name) {
            return Err(ToolRegistrationError::Duplicate(policy.name));
        }
        self.tools.insert(
            policy.name.clone(),
            RegisteredTool {
                policy,
                calls: 0,
                handler: Box::new(handler),
            },
        );
        Ok(())
    }

    pub fn register_json_tool<F>(
        &mut self,
        policy: ToolPolicy,
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
        self.register(policy, move |request| {
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

    pub fn eval(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        self.runtime.eval(source)
    }

    pub fn audit(&self) -> &[AuditEvent] {
        self.runtime.host().audit()
    }

    pub fn clear_audit(&mut self) {
        self.runtime.host_mut().clear_audit();
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
