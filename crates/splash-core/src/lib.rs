#![forbid(unsafe_code)]

//! Host-neutral execution primitives for Splash.
//!
//! The vendored VM exposes pure language modules only. This crate owns runtime
//! limits and diagnostic capture; effectful APIs belong to a separate host
//! crate and must be explicitly installed by trusted Rust code.

mod profile;

use std::any::Any;
use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::time::Duration;

pub use makepad_script as vm;
use profile::{
    check_canonical_profile, collect_lexical_completions, collect_lexical_symbols,
    collect_tool_call_hints, collect_top_level_declarations, format_canonical_source,
    is_canonical_identifier as profile_is_canonical_identifier, ProfileFormatError,
};
pub use serde_json::Value as JsonValue;
use vm::parser::ScriptParser;
use vm::tokenizer::{ScriptToken, ScriptTokenizer};

/// Stable identifier for the portable source contract enforced before normal
/// Splash evaluation.
pub const CANONICAL_PROFILE_ID: &str = "splash-v0.2";
/// Version of the portable source grammar named by [`CANONICAL_PROFILE_ID`].
pub const CANONICAL_PROFILE_VERSION: &str = "0.2";
/// Repository-relative location of the normative portable grammar.
pub const CANONICAL_PROFILE_GRAMMAR_PATH: &str = "docs/grammar.md";
pub const DEFAULT_MAX_SOURCE_BYTES: usize = 256 * 1024;
const FORMAT_OUTPUT_MULTIPLIER: usize = 4;
/// Maximum formatted output size under the default source budget.
pub const DEFAULT_MAX_FORMATTED_SOURCE_BYTES: usize =
    DEFAULT_MAX_SOURCE_BYTES * FORMAT_OUTPUT_MULTIPLIER;
/// Maximum canonical lexical tokens accepted by default during syntax preflight.
pub const DEFAULT_MAX_SYNTAX_TOKENS: usize = 32 * 1024;
/// Maximum syntactic nesting accepted by default during syntax preflight.
///
/// Canonical Splash applies this to grammar nesting. The trusted Makepad
/// compatibility preflight applies it to delimiter nesting before it invokes
/// the vendored parser.
pub const DEFAULT_MAX_SYNTAX_NESTING: usize = 128;
pub const DEFAULT_INSTRUCTION_LIMIT: usize = 200_000;
pub const DEFAULT_SOFT_TIMEOUT: Duration = Duration::from_millis(32);
pub const DEFAULT_HARD_TIMEOUT: Duration = Duration::from_millis(64);
pub const DEFAULT_BUDGET_SAMPLE_INTERVAL: u32 = 1_024;
/// Default maximum encoded size of JSON injected into or extracted from a
/// Splash runtime.
pub const DEFAULT_MAX_JSON_DATA_BYTES: usize = 64 * 1024;
/// Default maximum JSON container nesting accepted at a host-data boundary.
pub const DEFAULT_MAX_JSON_DATA_DEPTH: usize = 64;
/// Maximum byte length of a host-selected injected-global identifier.
pub const MAX_JSON_GLOBAL_NAME_BYTES: usize = 64;
/// Maximum structured syntax diagnostics returned for one source check.
pub const MAX_SYNTAX_DIAGNOSTICS: usize = 32;
/// Maximum direct tool-call hints retained for one canonical source document.
///
/// This bounds review-memory and operator/LLM output growth independently of
/// source and token limits. Use [`ToolCallHintReport::truncated`] to detect
/// when a source contains additional direct call sites.
pub const MAX_TOOL_CALL_HINTS: usize = 1_024;
/// Maximum retained lexical definition and reference occurrences per source.
///
/// The symbol index counts each definition and each resolved reference toward
/// this fixed bound. [`LexicalSymbolReport::truncated`] is set when later
/// occurrences are omitted.
pub const MAX_LEXICAL_SYMBOL_OCCURRENCES: usize = 4_096;
/// Maximum expression-identifier sites retained for lexical completion.
///
/// This is independent of the resolved definition/reference occurrence bound:
/// unresolved identifier prefixes remain useful completion sites.
pub const MAX_LEXICAL_COMPLETION_SITES: usize = 4_096;

/// Bounds applied to one source evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLimits {
    pub max_source_bytes: usize,
    pub max_syntax_tokens: usize,
    pub max_syntax_nesting: usize,
    pub instruction_limit: usize,
    pub soft_timeout: Duration,
    pub hard_timeout: Duration,
    pub budget_sample_interval: u32,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
            max_syntax_tokens: DEFAULT_MAX_SYNTAX_TOKENS,
            max_syntax_nesting: DEFAULT_MAX_SYNTAX_NESTING,
            instruction_limit: DEFAULT_INSTRUCTION_LIMIT,
            soft_timeout: DEFAULT_SOFT_TIMEOUT,
            hard_timeout: DEFAULT_HARD_TIMEOUT,
            budget_sample_interval: DEFAULT_BUDGET_SAMPLE_INTERVAL,
        }
    }
}

impl ExecutionLimits {
    pub fn validate(self) -> Result<Self, RuntimeError> {
        if self.max_source_bytes == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_source_bytes must be greater than zero",
            ));
        }
        if self.max_syntax_tokens == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_syntax_tokens must be greater than zero",
            ));
        }
        if self.max_syntax_nesting == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_syntax_nesting must be greater than zero",
            ));
        }
        if self.instruction_limit == 0 {
            return Err(RuntimeError::InvalidLimits(
                "instruction_limit must be greater than zero",
            ));
        }
        if self.soft_timeout.is_zero() || self.hard_timeout.is_zero() {
            return Err(RuntimeError::InvalidLimits(
                "execution deadlines must be greater than zero",
            ));
        }
        if self.soft_timeout > self.hard_timeout {
            return Err(RuntimeError::InvalidLimits(
                "soft_timeout cannot exceed hard_timeout",
            ));
        }
        if self.budget_sample_interval == 0 {
            return Err(RuntimeError::InvalidLimits(
                "budget_sample_interval must be greater than zero",
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    SourceTooLarge { actual: usize, maximum: usize },
    FormattedSourceTooLarge { actual: usize, maximum: usize },
    InvalidLimits(&'static str),
    SyntaxRejected(SyntaxReport),
    JsonData(RuntimeJsonError),
    EvaluationInProgress,
    UnknownThread { thread_index: usize },
}

impl Display for RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "source is {actual} bytes; maximum is {maximum} bytes"
                )
            }
            Self::FormattedSourceTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "formatted source is {actual} bytes; maximum is {maximum} bytes"
                )
            }
            Self::InvalidLimits(message) => formatter.write_str(message),
            Self::SyntaxRejected(report) => {
                let detail = report.diagnostics.first().map_or_else(
                    || "source is not valid canonical Splash".to_owned(),
                    |diagnostic| {
                        format!(
                            "line {}, column {}: {}",
                            diagnostic.line, diagnostic.column, diagnostic.message
                        )
                    },
                );
                write!(formatter, "canonical Splash syntax rejected: {detail}")
            }
            Self::JsonData(error) => write!(formatter, "JSON data boundary rejected: {error}"),
            Self::EvaluationInProgress => {
                formatter.write_str("a suspended Splash evaluation must be resumed first")
            }
            Self::UnknownThread { thread_index } => {
                write!(formatter, "unknown suspended script thread: {thread_index}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

/// Rejection at a bounded JSON boundary between a Rust host and Splash.
///
/// These checks are intentionally separate from capability authorization:
/// JSON data can influence a permitted script's computation, but it cannot add
/// tools, alter a lease, or bypass the runtime's source and execution limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeJsonError {
    InvalidGlobalName,
    InvalidLimit,
    TooLarge { actual: usize, maximum: usize },
    TooDeep { maximum: usize },
    InvalidEncoding,
    NonFiniteNumber,
    UnsupportedScriptValue,
    NonStringObjectKey,
    UnknownObjectKey,
    DuplicateObjectKey,
    CyclicScriptValue,
}

impl Display for RuntimeJsonError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGlobalName => {
                formatter.write_str("JSON global name must be a bounded ASCII identifier")
            }
            Self::InvalidLimit => {
                formatter.write_str("JSON data byte and depth limits must be greater than zero")
            }
            Self::TooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "JSON data is {actual} bytes; maximum is {maximum} bytes"
                )
            }
            Self::TooDeep { maximum } => {
                write!(
                    formatter,
                    "JSON data exceeds the maximum nesting depth of {maximum}"
                )
            }
            Self::InvalidEncoding => formatter.write_str("JSON data is not valid JSON"),
            Self::NonFiniteNumber => {
                formatter.write_str("a Splash non-finite number cannot cross a JSON boundary")
            }
            Self::UnsupportedScriptValue => {
                formatter.write_str("a Splash value cannot be represented as JSON")
            }
            Self::NonStringObjectKey => {
                formatter.write_str("a Splash object has a non-string JSON key")
            }
            Self::UnknownObjectKey => {
                formatter.write_str("a Splash object key has no stable string spelling")
            }
            Self::DuplicateObjectKey => {
                formatter.write_str("a Splash object has duplicate JSON keys")
            }
            Self::CyclicScriptValue => {
                formatter.write_str("a cyclic Splash value cannot cross a JSON boundary")
            }
        }
    }
}

impl std::error::Error for RuntimeJsonError {}

/// Result of a single evaluation. `value` remains valid for the lifetime of
/// its owning [`Runtime`].
#[derive(Debug)]
pub struct Evaluation {
    pub value: vm::ScriptValue,
    pub diagnostics: Vec<String>,
    pub suspended: bool,
}

/// One one-based location returned by the effect-free syntax checker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntaxDiagnostic {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

/// Result of validating canonical Splash source without executing opcodes or
/// tools.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntaxReport {
    pub valid: bool,
    pub diagnostics: Vec<SyntaxDiagnostic>,
    pub diagnostics_truncated: bool,
}

/// The syntactic kind of one top-level canonical declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopLevelDeclarationKind {
    /// A `fn` declaration.
    Function,
    /// A `let` declaration.
    Let,
}

/// A bounded, effect-free outline item for valid canonical Splash source.
///
/// Byte offsets are valid UTF-8 boundaries in the supplied source. The
/// declaration span begins at `fn` or `let`; the selection span covers only
/// the declared identifier. Invalid or VM-incompatible source produces no
/// declarations through [`top_level_declarations`] or
/// [`top_level_declarations_named`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopLevelDeclaration {
    pub kind: TopLevelDeclarationKind,
    pub name: String,
    pub declaration_start_byte: usize,
    pub declaration_end_byte: usize,
    pub selection_start_byte: usize,
    pub selection_end_byte: usize,
}

/// The grammar role that introduced one lexical Splash binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LexicalSymbolKind {
    /// The final identifier in a `use mod.<path>` import.
    Import,
    /// A named `fn` declaration.
    Function,
    /// A `let` declaration.
    Let,
    /// A named function parameter.
    Parameter,
    /// A binding introduced by `for ... in ...`.
    LoopBinding,
    /// A named lambda parameter.
    LambdaParameter,
}

/// One half-open UTF-8 byte span in canonical Splash source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSpan {
    pub start_byte: usize,
    pub end_byte: usize,
}

/// One lexical binding and the source references resolved to it.
///
/// The index is intentionally conservative and source ordered. It resolves
/// imports, functions, `let` declarations, function parameters, loop bindings,
/// and lambda parameters already introduced in the visible runtime scope. It
/// does not infer types, fields, record keys, imports across documents, or
/// forward references. Every span is a valid UTF-8 boundary in the supplied
/// source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LexicalSymbol {
    pub kind: LexicalSymbolKind,
    pub name: String,
    pub definition: SourceSpan,
    pub references: Vec<SourceSpan>,
    /// First byte at which this binding participates in lexical resolution.
    pub visibility_start_byte: usize,
    /// Exclusive scope or same-scope-shadow boundary for this binding.
    pub visibility_end_byte: usize,
}

/// Bounded, effect-free lexical symbol output for one canonical source.
///
/// `symbols` is sorted by definition byte position. A truncated report is
/// incomplete and must not be presented as an exhaustive reference result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LexicalSymbolReport {
    pub symbols: Vec<LexicalSymbol>,
    pub truncated: bool,
}

/// Bounded, effect-free lexical completion metadata for one source snapshot.
///
/// `sites` contains only identifiers parsed in expression position, including
/// unresolved names. Declarations, import paths, record keys, and member names
/// are excluded. A site is usable only when its end is at or before
/// `valid_prefix_end_byte`; this permits conservative completion before the
/// first syntax error without treating the rest of an invalid document as
/// semantically analyzed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LexicalCompletionReport {
    pub symbols: Vec<LexicalSymbol>,
    pub sites: Vec<SourceSpan>,
    /// Whether later definitions or resolved references were omitted.
    ///
    /// Consumers must not derive candidates from a truncated symbol set: an
    /// omitted inner definition may shadow a retained outer binding.
    pub symbols_truncated: bool,
    pub sites_truncated: bool,
    pub valid_prefix_end_byte: usize,
}

/// The direct `mod.tool` method named by one source-level tool-call hint.
///
/// This is a syntactic classification only. It does not resolve bindings,
/// control flow, or the value of a dynamically computed tool name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolCallKind {
    /// `tool.call(name, input)`.
    Call,
    /// `tool.start(name, input)`.
    Start,
    /// `tool.call_json(name, input)`.
    CallJson,
    /// `tool.start_json(name, input)`.
    StartJson,
}

impl ToolCallKind {
    /// Stable lowercase spelling used by host tools and the development CLI.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Start => "start",
            Self::CallJson => "call_json",
            Self::StartJson => "start_json",
        }
    }
}

/// A bounded, effect-free hint for a direct source-level `mod.tool` call.
///
/// The callee span covers `tool.<method>`. A literal-name span is present when
/// the first argument is syntactically a string literal; `literal_name` is
/// present when that literal can be decoded under the canonical escape rules.
/// Any other first argument is dynamic. These hints are intentionally not a
/// capability analysis: aliases, shadowing, control flow, expression values,
/// imports, and runtime dispatch are not resolved. Hosts must still authorize
/// every tool reservation through their capability catalog and lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCallHint {
    pub kind: ToolCallKind,
    pub literal_name: Option<String>,
    pub line: usize,
    pub column: usize,
    pub callee_start_byte: usize,
    pub callee_end_byte: usize,
    pub literal_name_start_byte: Option<usize>,
    pub literal_name_end_byte: Option<usize>,
}

/// Bounded effect-free direct tool-call review output.
///
/// `hints` retains source-order entries up to [`MAX_TOOL_CALL_HINTS`]. When
/// `truncated` is true, the source contains one or more additional direct
/// `mod.tool` call sites that were intentionally omitted from this review
/// output. This is not an authorization decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolCallHintReport {
    pub hints: Vec<ToolCallHint>,
    pub truncated: bool,
}

impl Evaluation {
    pub fn succeeded(&self) -> bool {
        !self.value.is_err()
    }

    pub fn completed(&self) -> bool {
        self.succeeded() && !self.suspended
    }
}

/// A single-threaded Splash VM with owned host and standard-library state.
///
/// The generic host is intentionally opaque to scripts. Trusted Rust code can
/// install native bindings through [`Runtime::configure`]; scripts only see
/// the bindings that configuration creates.
pub struct Runtime<H: Any = (), S: Any = ()> {
    host: H,
    std: S,
    vm: Box<vm::ScriptVmBase>,
    limits: ExecutionLimits,
}

impl<H: Any, S: Any> Runtime<H, S> {
    pub fn new(host: H, std: S) -> Result<Self, RuntimeError> {
        Self::with_limits(host, std, ExecutionLimits::default())
    }

    pub fn with_limits(host: H, std: S, limits: ExecutionLimits) -> Result<Self, RuntimeError> {
        Ok(Self {
            host,
            std,
            vm: Box::new(vm::ScriptVmBase::new()),
            limits: limits.validate()?,
        })
    }

    pub fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    pub fn set_limits(&mut self, limits: ExecutionLimits) -> Result<(), RuntimeError> {
        self.limits = limits.validate()?;
        Ok(())
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Installs trusted native bindings. Do not expose ambient OS APIs here;
    /// effectful bindings must apply their own capability policy.
    pub fn configure(&mut self, configure: impl FnOnce(&mut vm::ScriptVm)) {
        self.with_vm(configure);
    }

    /// Injects a host-owned JSON value under one identifier for later Splash
    /// evaluations. The value is copied into the VM; Splash code cannot retain
    /// a Rust handle to it or use it to acquire capability authority.
    ///
    /// The global cannot be changed while an evaluation is suspended because a
    /// resumed continuation must observe the exact context it started with.
    pub fn set_json_global(
        &mut self,
        name: &str,
        value: &JsonValue,
        max_bytes: usize,
        max_depth: usize,
    ) -> Result<(), RuntimeError> {
        if !is_valid_json_global_name(name) {
            return Err(RuntimeError::JsonData(RuntimeJsonError::InvalidGlobalName));
        }
        let encoded =
            serialize_bounded_json(value, max_bytes, max_depth).map_err(RuntimeError::JsonData)?;
        self.with_vm(|vm| {
            if has_paused_thread(vm) {
                return Err(RuntimeError::EvaluationInProgress);
            }
            let mut parser = vm::json::JsonParserThread::default();
            let value = parser.read_json(&encoded, &mut vm.bx.heap);
            vm.set_injected_global(vm::LiveId::from_str(name), value);
            Ok(())
        })
    }

    /// Drops the current JSON value from a host-injected global without
    /// deleting the identifier itself. Replacing it with `nil` lets the VM
    /// collect prior context after the next host-selected garbage collection.
    pub fn clear_json_global(&mut self, name: &str) -> Result<(), RuntimeError> {
        if !is_valid_json_global_name(name) {
            return Err(RuntimeError::JsonData(RuntimeJsonError::InvalidGlobalName));
        }
        self.with_vm(|vm| {
            if has_paused_thread(vm) {
                return Err(RuntimeError::EvaluationInProgress);
            }
            vm.set_injected_global(vm::LiveId::from_str(name), vm::ScriptValue::NIL);
            Ok(())
        })
    }

    /// Converts a completed Splash value to bounded JSON without constructing
    /// an unbounded intermediate serialization. Functions, handles, cyclic
    /// objects, non-string object keys, and non-finite numbers are rejected.
    pub fn script_value_as_json(
        &mut self,
        value: vm::ScriptValue,
        max_bytes: usize,
        max_depth: usize,
    ) -> Result<JsonValue, RuntimeError> {
        if max_bytes == 0 || max_depth == 0 {
            return Err(RuntimeError::JsonData(RuntimeJsonError::InvalidLimit));
        }
        let encoded = self
            .with_vm(|vm| {
                let mut writer = BoundedJsonWriter::new(max_bytes);
                write_script_json(vm, value, max_depth, &mut Vec::new(), &mut writer)?;
                Ok::<_, RuntimeJsonError>(writer.into_string())
            })
            .map_err(RuntimeError::JsonData)?;
        parse_bounded_json(&encoded, max_bytes, max_depth).map_err(RuntimeError::JsonData)
    }

    /// Validates canonical Splash source without evaluating it or entering any
    /// host binding.
    ///
    /// This is suitable for LLM preflight and editor validation. It checks the
    /// portable Splash v0.2 grammar, then confirms VM compatibility. Imports,
    /// capability grants, schemas, and tool names remain host-policy decisions
    /// that are validated at execution time.
    pub fn check_syntax(&self, source: &str) -> Result<SyntaxReport, RuntimeError> {
        check_syntax_named("inline.splash", source, self.limits)
    }

    /// Validates the vendored Makepad parser's broader compatibility syntax
    /// without executing bytecode or entering a host binding.
    ///
    /// This accepts syntax outside the portable Splash v0.2 profile and is
    /// intended only for trusted migration or UI-host integration code. It
    /// applies the configured source, inherited-VM token, and delimiter-nesting
    /// bounds, but it does not resolve modules, prove host bindings exist, or
    /// grant authority.
    /// Normal generated source must use [`Self::check_syntax`].
    pub fn check_vm_compatibility(&self, source: &str) -> Result<SyntaxReport, RuntimeError> {
        check_vm_compatibility_named("inline.splash", source, self.limits)
    }

    /// Formats canonical Splash source without evaluating it or entering any
    /// host binding.
    ///
    /// Formatting validates both the portable profile and VM compatibility
    /// first. Unsupported Makepad compatibility syntax is rejected instead of
    /// being silently rewritten into a different language contract.
    pub fn format_source(&self, source: &str) -> Result<String, RuntimeError> {
        format_source_named("inline.splash", source, self.limits)
    }

    /// Lists direct source-level `mod.tool` call hints without evaluating
    /// bytecode or entering any host binding.
    ///
    /// The result is useful for an LLM or operator review surface, but it is
    /// not an authority decision. See [`tool_call_hints_named`] for the full
    /// syntactic limitations.
    pub fn tool_call_hints(&self, source: &str) -> Result<Vec<ToolCallHint>, RuntimeError> {
        Ok(self.tool_call_hint_report(source)?.hints)
    }

    /// Lists bounded direct source-level `mod.tool` call hints without
    /// evaluating bytecode or entering any host binding.
    ///
    /// Unlike [`Self::tool_call_hints`], this reports whether additional
    /// direct call sites were omitted at the fixed review limit.
    pub fn tool_call_hint_report(&self, source: &str) -> Result<ToolCallHintReport, RuntimeError> {
        tool_call_hint_report_named("inline.splash", source, self.limits)
    }

    /// Builds a bounded lexical symbol index without evaluating bytecode or
    /// entering any host binding.
    pub fn lexical_symbol_report(&self, source: &str) -> Result<LexicalSymbolReport, RuntimeError> {
        lexical_symbol_report_named("inline.splash", source, self.limits)
    }

    /// Builds bounded lexical completion metadata without evaluating bytecode
    /// or entering any host binding.
    pub fn lexical_completion_report(
        &self,
        source: &str,
    ) -> Result<LexicalCompletionReport, RuntimeError> {
        lexical_completion_report_named("inline.splash", source, self.limits)
    }

    /// Evaluates source only after it passes the canonical Splash v0.2 profile.
    ///
    /// This is the normal execution entry point for generated and user-authored
    /// source. Use [`Self::eval_vm_compatibility`] only for a trusted host that
    /// deliberately needs a Makepad compatibility construct outside Splash.
    pub fn eval(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        let report = self.check_syntax(source)?;
        if !report.valid {
            return Err(RuntimeError::SyntaxRejected(report));
        }
        self.eval_preflighted(source)
    }

    /// Evaluates the vendored Makepad parser's broader compatibility syntax.
    ///
    /// This bypasses Splash's portable grammar contract and must not receive
    /// LLM-generated or otherwise untrusted source. Prefer [`Self::eval`] for
    /// all normal Splash execution. It still applies the bounded, effect-free
    /// [`Self::check_vm_compatibility`] preflight before it evaluates code.
    pub fn eval_vm_compatibility(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        let report = self.check_vm_compatibility(source)?;
        if !report.valid {
            return Err(RuntimeError::SyntaxRejected(report));
        }

        self.eval_preflighted(source)
    }

    fn eval_preflighted(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        let limits = self.limits;
        self.with_vm(|vm| {
            if has_paused_thread(vm) {
                return Err(RuntimeError::EvaluationInProgress);
            }
            // Keep the public runtime single-flight. The underlying VM can
            // manage several threads, but evaluating new source into a paused
            // frame would make its module/body lifecycle ambiguous.
            vm.bx.threads.set_current_to_first_unpaused_thread();
            Ok(evaluate_with_limits(vm, limits, |vm| {
                vm.eval(vm::ScriptMod {
                    file: "inline.splash".to_owned(),
                    // The Makepad streaming hosts append this marker before
                    // execution. Keep it internal so CLI and embedded users
                    // provide normal Splash source rather than host syntax.
                    code: format!("{source}\n;"),
                    ..Default::default()
                })
            }))
        })
    }

    /// Resume a thread previously suspended by a trusted host binding.
    ///
    /// The thread identifier is only expected to originate from the VM. The
    /// bounds check prevents an invalid host-provided identifier from reaching
    /// the VM's internal current-thread pointer.
    pub fn resume(&mut self, thread_id: vm::ScriptThreadId) -> Result<Evaluation, RuntimeError> {
        let limits = self.limits;
        self.with_vm(|vm| {
            let thread_index = thread_id.to_index();
            if thread_index >= vm.bx.threads.len() {
                return Err(RuntimeError::UnknownThread { thread_index });
            }
            vm.bx.threads.set_current_thread_id(thread_id);
            Ok(evaluate_with_limits(vm, limits, |vm| vm.resume()))
        })
    }

    /// Reclaims unreachable VM values at a host-selected scheduling point.
    ///
    /// This may take time proportional to the live VM heap, so callers should
    /// schedule it outside latency-sensitive work. Paused script threads remain
    /// GC roots and are safe to collect around.
    pub fn collect_garbage(&mut self) {
        self.with_vm(|vm| vm.gc());
    }

    fn with_vm<R>(&mut self, operation: impl FnOnce(&mut vm::ScriptVm) -> R) -> R {
        let previous_vm = std::mem::replace(&mut self.vm, Box::new(vm::ScriptVmBase::new()));
        let mut vm = vm::ScriptVm {
            host: &mut self.host,
            std: &mut self.std,
            bx: previous_vm,
        };
        let result = operation(&mut vm);
        self.vm = vm.bx;
        result
    }
}

/// Validates canonical Splash source with the default source-size limit without
/// executing it.
pub fn check_syntax(source: &str) -> Result<SyntaxReport, RuntimeError> {
    check_syntax_named("inline.splash", source, ExecutionLimits::default())
}

/// Validates inherited Makepad compatibility syntax with default bounds,
/// without executing it.
///
/// This is deliberately distinct from [`check_syntax`]: it accepts the
/// broader vendored parser language, including constructs that canonical
/// Splash rejects. It does not resolve imports or establish that a host has
/// installed the referenced module. Use it only for trusted migration or UI
/// host integration tooling, never as LLM-source admission.
pub fn check_vm_compatibility(source: &str) -> Result<SyntaxReport, RuntimeError> {
    check_vm_compatibility_named("inline.splash", source, ExecutionLimits::default())
}

/// Returns whether `name` is exactly one non-reserved canonical Splash
/// identifier.
///
/// This uses the same lexer and reserved-word table as canonical source
/// preflight. It does not accept surrounding whitespace, comments, literals,
/// punctuation, or compatibility-only identifier spellings.
pub fn is_canonical_identifier(name: &str) -> bool {
    profile_is_canonical_identifier(name)
}

/// Lists top-level declarations in valid canonical source without evaluating
/// it, resolving imports, or creating a capability host.
///
/// Invalid or VM-incompatible source produces an empty outline. Call
/// [`check_syntax`] to obtain the corresponding diagnostics.
pub fn top_level_declarations(source: &str) -> Result<Vec<TopLevelDeclaration>, RuntimeError> {
    top_level_declarations_named("inline.splash", source, ExecutionLimits::default())
}

/// Builds a bounded lexical symbol index for valid canonical source without
/// evaluating it, resolving imports, or creating a capability host.
///
/// Invalid or VM-incompatible source produces an empty report. The result is
/// source ordered and conservative; see [`LexicalSymbol`] for the supported
/// binding and reference semantics.
pub fn lexical_symbol_report(source: &str) -> Result<LexicalSymbolReport, RuntimeError> {
    lexical_symbol_report_named("inline.splash", source, ExecutionLimits::default())
}

/// Builds bounded lexical completion metadata without evaluating source,
/// resolving imports, or creating a capability host.
///
/// Completion sites are expression identifiers. For invalid source, only
/// sites ending before the first syntax diagnostic are usable; see
/// [`LexicalCompletionReport::valid_prefix_end_byte`].
pub fn lexical_completion_report(source: &str) -> Result<LexicalCompletionReport, RuntimeError> {
    lexical_completion_report_named("inline.splash", source, ExecutionLimits::default())
}

/// Lists direct source-level `mod.tool` call hints in valid canonical Splash
/// without evaluating source, resolving imports, or creating a capability
/// host.
///
/// This is an LLM and operator-review aid, not static authorization. It sees
/// only a literal `tool.call`, `tool.start`, `tool.call_json`, or
/// `tool.start_json` token sequence. It deliberately does not infer aliases,
/// control flow, runtime string values, imports, or whether a call is
/// reachable. Invalid or VM-incompatible source produces no hints. A host must
/// issue an explicit capability lease and rely on runtime reservation checks
/// for every actual effect. This compatibility helper returns the retained
/// prefix only; use [`tool_call_hint_report`] when a host needs to detect
/// truncation.
pub fn tool_call_hints(source: &str) -> Result<Vec<ToolCallHint>, RuntimeError> {
    Ok(tool_call_hint_report(source)?.hints)
}

/// Lists bounded direct source-level `mod.tool` call hints with an explicit
/// truncation signal.
///
/// This applies the same syntax checks and non-authoritative semantics as
/// [`tool_call_hints`]. `hints` retains at most [`MAX_TOOL_CALL_HINTS`] source
/// sites; `truncated` records whether later direct sites were omitted.
pub fn tool_call_hint_report(source: &str) -> Result<ToolCallHintReport, RuntimeError> {
    tool_call_hint_report_named("inline.splash", source, ExecutionLimits::default())
}

/// Formats canonical Splash source with default bounds without evaluating it.
///
/// This preserves strings and comments while normalizing token spacing,
/// indentation, line endings, and trailing whitespace. It rejects invalid or
/// Makepad-compatibility-only source rather than attempting error recovery.
pub fn format_source(source: &str) -> Result<String, RuntimeError> {
    format_source_named("inline.splash", source, ExecutionLimits::default())
}

#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    use super::{check_profile_named, ExecutionLimits, RuntimeError, SyntaxReport};

    /// Runs only the canonical Splash preflight for differential fuzzing.
    pub fn check_canonical_profile(
        source: &str,
        limits: ExecutionLimits,
    ) -> Result<SyntaxReport, RuntimeError> {
        check_profile_named(source, limits)
    }
}

/// Validates named canonical Splash source without executing it.
///
/// This function rejects Makepad compatibility syntax outside the documented
/// Splash v0.2 grammar. Only source accepted by that profile reaches the
/// same bounded vendored-VM preflight used by
/// [`check_vm_compatibility_named`]. `file` appears only in VM-parser
/// diagnostics. It never loads a module, resolves an import, runs bytecode,
/// or invokes a host tool.
pub fn check_syntax_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<SyntaxReport, RuntimeError> {
    let limits = limits.validate()?;
    validate_source_length(source, limits)?;
    let profile = check_profile_with_validated_limits(source, limits);
    if !profile.valid {
        return Ok(profile);
    }

    Ok(check_vm_syntax_with_validated_limits(file, source, limits))
}

/// Validates named inherited Makepad compatibility syntax without executing
/// bytecode or entering a host binding.
///
/// Unlike [`check_syntax_named`], this does not apply the canonical Splash
/// grammar. It bounds source bytes, source tokens, and delimiter nesting from
/// the inherited VM tokenizer before handing the token stream to the vendored
/// parser. `file` appears only in parser diagnostics. It never resolves
/// imports, installs a module, invokes a tool, or evaluates source. Makepad
/// `@(index)` values are rejected because this standalone API does not accept
/// a host value table.
///
/// This is a trusted-host migration and UI-integration utility. It must not
/// replace canonical syntax admission for LLM-generated or otherwise
/// untrusted source.
pub fn check_vm_compatibility_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<SyntaxReport, RuntimeError> {
    let limits = limits.validate()?;
    validate_source_length(source, limits)?;

    Ok(check_vm_syntax_with_validated_limits(file, source, limits))
}

fn check_vm_syntax_with_validated_limits(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> SyntaxReport {
    let mut base = vm::ScriptVmBase::new();
    let mut tokenizer = ScriptTokenizer::default();
    match tokenize_vm_source_bounded(
        &mut tokenizer,
        source,
        &mut base.heap,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
    ) {
        Ok(()) => {}
        Err(VmCompatibilityPreflightLimit::Tokens) => {
            return vm_token_limit_report(&tokenizer, limits.max_syntax_tokens);
        }
        Err(VmCompatibilityPreflightLimit::Nesting { token_index }) => {
            return vm_nesting_limit_report(&tokenizer, token_index, limits.max_syntax_nesting);
        }
    }

    parse_vm_syntax(file, &tokenizer)
}

enum VmCompatibilityPreflightLimit {
    Tokens,
    Nesting { token_index: usize },
}

/// Tokenizes source with the same terminal marker that the embedded VM sees.
/// Tokenization stops as soon as the accumulated source token stream crosses
/// either caller-configured structural limit. The terminal marker is excluded
/// from those limits, so they measure only caller-provided source.
fn tokenize_vm_source_bounded(
    tokenizer: &mut ScriptTokenizer,
    source: &str,
    heap: &mut vm::ScriptHeap,
    maximum_source_tokens: usize,
    maximum_nesting: usize,
) -> Result<(), VmCompatibilityPreflightLimit> {
    let mut delimiters = Vec::new();
    let mut checked_tokens = 0_usize;

    for character in source.chars().chain(std::iter::once('\n')) {
        let mut encoded = [0_u8; 4];
        tokenizer.tokenize(character.encode_utf8(&mut encoded), heap);
        if tokenizer.tokens.len() > maximum_source_tokens {
            return Err(VmCompatibilityPreflightLimit::Tokens);
        }
        if let Some(token_index) = advance_vm_compatibility_nesting(
            tokenizer,
            &mut checked_tokens,
            &mut delimiters,
            maximum_nesting,
        ) {
            return Err(VmCompatibilityPreflightLimit::Nesting { token_index });
        }
    }

    tokenizer.tokenize(";", heap);
    Ok(())
}

fn vm_token_limit_report(
    tokenizer: &ScriptTokenizer,
    maximum_source_tokens: usize,
) -> SyntaxReport {
    let (line, column) = token_location(tokenizer, maximum_source_tokens);
    SyntaxReport {
        valid: false,
        diagnostics: vec![SyntaxDiagnostic {
            line,
            column,
            message: format!(
                "VM compatibility token count exceeds the maximum of {maximum_source_tokens}"
            ),
        }],
        diagnostics_truncated: false,
    }
}

fn vm_nesting_limit_report(
    tokenizer: &ScriptTokenizer,
    token_index: usize,
    maximum_nesting: usize,
) -> SyntaxReport {
    let (line, column) = token_location(tokenizer, token_index);
    SyntaxReport {
        valid: false,
        diagnostics: vec![SyntaxDiagnostic {
            line,
            column,
            message: format!("VM compatibility nesting exceeds the maximum of {maximum_nesting}"),
        }],
        diagnostics_truncated: false,
    }
}

fn parse_vm_syntax(file: &str, tokenizer: &ScriptTokenizer) -> SyntaxReport {
    let mut diagnostics = Vec::new();
    let mut diagnostics_truncated = false;

    let mut parser = ScriptParser::default();
    parser.set_emit_errors(false);
    parser.parse(tokenizer, file, (0, 0), &[]);

    let (delimiter_diagnostics, delimiter_diagnostics_truncated) = delimiter_diagnostics(tokenizer);
    for diagnostic in delimiter_diagnostics {
        push_syntax_diagnostic(&mut diagnostics, &mut diagnostics_truncated, diagnostic);
    }
    diagnostics_truncated |= delimiter_diagnostics_truncated;
    for diagnostic in parser.diagnostics {
        push_syntax_diagnostic(
            &mut diagnostics,
            &mut diagnostics_truncated,
            SyntaxDiagnostic {
                line: diagnostic.line as usize + 1,
                column: diagnostic.column as usize + 1,
                message: diagnostic.message,
            },
        );
    }
    diagnostics_truncated |= parser.diagnostics_truncated;

    SyntaxReport {
        valid: !parser.had_error && diagnostics.is_empty(),
        diagnostics,
        diagnostics_truncated,
    }
}

/// Lists top-level declarations in named canonical source without evaluating
/// it, resolving imports, or creating a capability host.
///
/// This applies the same source, token, nesting, canonical-profile, and
/// vendored parser-compatibility checks as [`check_syntax_named`]. `file`
/// appears only in VM-parser diagnostics. Invalid source produces an empty
/// outline; callers that need diagnostics should call [`check_syntax_named`]
/// separately.
pub fn top_level_declarations_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<Vec<TopLevelDeclaration>, RuntimeError> {
    let report = check_syntax_named(file, source, limits)?;
    if !report.valid {
        return Ok(Vec::new());
    }

    Ok(collect_top_level_declarations(
        source,
        limits.max_syntax_tokens,
    ))
}

/// Builds a bounded lexical symbol index for named canonical source without
/// evaluating it, resolving document URIs, or creating a capability host.
///
/// This applies the same source, token, nesting, canonical-profile, and
/// vendored parser compatibility checks as [`check_syntax_named`]. Invalid
/// source returns an empty report; callers that need diagnostics should call
/// [`check_syntax_named`] separately.
pub fn lexical_symbol_report_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<LexicalSymbolReport, RuntimeError> {
    let report = check_syntax_named(file, source, limits)?;
    if !report.valid {
        return Ok(LexicalSymbolReport::default());
    }

    Ok(collect_lexical_symbols(
        source,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
    ))
}

/// Builds bounded lexical completion metadata for one named source snapshot.
///
/// The collector is effect-free and never resolves imports or runtime values.
/// Unlike navigation, it retains expression-identifier sites from the valid
/// prefix of incomplete source so an editor can complete the token immediately
/// before an end-of-file diagnostic. Sites after the first diagnostic are not
/// semantically usable.
pub fn lexical_completion_report_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<LexicalCompletionReport, RuntimeError> {
    let syntax = check_syntax_named(file, source, limits)?;
    let valid_prefix_end_byte = if syntax.valid {
        source.len()
    } else if syntax.diagnostics.is_empty() {
        0
    } else {
        syntax
            .diagnostics
            .iter()
            .try_fold(source.len(), |first_byte, diagnostic| {
                source_byte_at_position(source, diagnostic.line, diagnostic.column)
                    .map(|byte| first_byte.min(byte))
            })
            .unwrap_or(0)
    };

    Ok(collect_lexical_completions(
        source,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
        valid_prefix_end_byte,
    ))
}

/// Lists direct source-level `mod.tool` call hints in named canonical source
/// without evaluating it, resolving imports, or creating a capability host.
///
/// This applies the same source, token, nesting, canonical-profile, and
/// vendored parser-compatibility checks as [`check_syntax_named`]. It reports
/// no hints for invalid source. The result is intentionally incomplete and
/// non-authoritative; use it only to present a review summary before the host
/// issues a lease and evaluates the source. This compatibility helper returns
/// the retained prefix only; use [`tool_call_hint_report_named`] when a host
/// needs to detect truncation.
pub fn tool_call_hints_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<Vec<ToolCallHint>, RuntimeError> {
    Ok(tool_call_hint_report_named(file, source, limits)?.hints)
}

/// Lists bounded direct source-level `mod.tool` call hints in named canonical
/// source with an explicit truncation signal.
///
/// This applies the same source, token, nesting, canonical-profile, and
/// vendored parser-compatibility checks as [`check_syntax_named`]. It reports
/// no hints for invalid source. The result is intentionally incomplete and
/// non-authoritative; use it only to present a review summary before the host
/// issues a lease and evaluates the source.
pub fn tool_call_hint_report_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<ToolCallHintReport, RuntimeError> {
    let report = check_syntax_named(file, source, limits)?;
    if !report.valid {
        return Ok(ToolCallHintReport {
            hints: Vec::new(),
            truncated: false,
        });
    }

    Ok(collect_tool_call_hints(source, limits.max_syntax_tokens))
}

/// Formats named canonical Splash source without evaluating it.
///
/// `file` is used only while confirming compatibility with the vendored VM
/// parser. A rejected source is returned as [`RuntimeError::SyntaxRejected`]
/// with the same structured diagnostics exposed by [`check_syntax_named`].
pub fn format_source_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<String, RuntimeError> {
    let limits = limits.validate()?;
    let report = check_syntax_named(file, source, limits)?;
    if !report.valid {
        return Err(RuntimeError::SyntaxRejected(report));
    }

    match format_canonical_source(
        source,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
        max_formatted_source_bytes(limits),
    ) {
        Ok(formatted) => Ok(formatted),
        Err(ProfileFormatError::Profile(profile)) => {
            Err(RuntimeError::SyntaxRejected(SyntaxReport {
                valid: false,
                diagnostics: profile.diagnostics,
                diagnostics_truncated: profile.diagnostics_truncated,
            }))
        }
        Err(ProfileFormatError::OutputTooLarge { actual, maximum }) => {
            Err(RuntimeError::FormattedSourceTooLarge { actual, maximum })
        }
    }
}

fn max_formatted_source_bytes(limits: ExecutionLimits) -> usize {
    limits
        .max_source_bytes
        .saturating_mul(FORMAT_OUTPUT_MULTIPLIER)
}

#[cfg(fuzzing)]
fn check_profile_named(
    source: &str,
    limits: ExecutionLimits,
) -> Result<SyntaxReport, RuntimeError> {
    let limits = limits.validate()?;
    validate_source_length(source, limits)?;

    Ok(check_profile_with_validated_limits(source, limits))
}

fn check_profile_with_validated_limits(source: &str, limits: ExecutionLimits) -> SyntaxReport {
    let profile =
        check_canonical_profile(source, limits.max_syntax_tokens, limits.max_syntax_nesting);
    if !profile.diagnostics.is_empty() || profile.diagnostics_truncated {
        return SyntaxReport {
            valid: false,
            diagnostics: profile.diagnostics,
            diagnostics_truncated: profile.diagnostics_truncated,
        };
    }

    SyntaxReport {
        valid: true,
        diagnostics: Vec::new(),
        diagnostics_truncated: false,
    }
}

fn validate_source_length(source: &str, limits: ExecutionLimits) -> Result<(), RuntimeError> {
    if source.len() > limits.max_source_bytes {
        return Err(RuntimeError::SourceTooLarge {
            actual: source.len(),
            maximum: limits.max_source_bytes,
        });
    }
    Ok(())
}

fn source_byte_at_position(source: &str, line: usize, column: usize) -> Option<usize> {
    if line == 0 || column == 0 {
        return None;
    }

    let mut current_line = 1;
    let mut current_column = 1;
    let mut characters = source.char_indices().peekable();
    while let Some((byte, character)) = characters.next() {
        if current_line == line && current_column == column {
            return Some(byte);
        }

        match character {
            '\n' => {
                current_line += 1;
                current_column = 1;
            }
            '\r' if characters.peek().is_none_or(|(_, next)| *next != '\n') => {
                current_line += 1;
                current_column = 1;
            }
            _ => current_column += 1,
        }
    }

    (current_line == line && current_column == column).then_some(source.len())
}

/// Parses JSON after enforcing raw-byte and container-depth bounds.
///
/// Hosts can use this before handing external data to [`Runtime::set_json_global`]
/// or a higher-level workflow API. Parsing creates data only; it never loads a
/// module, creates a capability, or executes Splash source.
pub fn parse_bounded_json(
    document: &str,
    max_bytes: usize,
    max_depth: usize,
) -> Result<JsonValue, RuntimeJsonError> {
    if max_bytes == 0 || max_depth == 0 {
        return Err(RuntimeJsonError::InvalidLimit);
    }
    if document.len() > max_bytes {
        return Err(RuntimeJsonError::TooLarge {
            actual: document.len(),
            maximum: max_bytes,
        });
    }
    let value = serde_json::from_str(document).map_err(|_| RuntimeJsonError::InvalidEncoding)?;
    validate_json_depth(&value, 0, max_depth)?;
    Ok(value)
}

/// Encodes a host-owned JSON value after enforcing JSON container-depth and
/// serialized-byte bounds.
pub fn serialize_bounded_json(
    value: &JsonValue,
    max_bytes: usize,
    max_depth: usize,
) -> Result<String, RuntimeJsonError> {
    if max_bytes == 0 || max_depth == 0 {
        return Err(RuntimeJsonError::InvalidLimit);
    }
    validate_json_depth(value, 0, max_depth)?;
    let encoded = serde_json::to_string(value).map_err(|_| RuntimeJsonError::InvalidEncoding)?;
    if encoded.len() > max_bytes {
        return Err(RuntimeJsonError::TooLarge {
            actual: encoded.len(),
            maximum: max_bytes,
        });
    }
    Ok(encoded)
}

fn validate_json_depth(
    value: &JsonValue,
    container_depth: usize,
    maximum: usize,
) -> Result<(), RuntimeJsonError> {
    match value {
        JsonValue::Array(values) => {
            if container_depth >= maximum {
                return Err(RuntimeJsonError::TooDeep { maximum });
            }
            for value in values {
                validate_json_depth(value, container_depth.saturating_add(1), maximum)?;
            }
        }
        JsonValue::Object(values) => {
            if container_depth >= maximum {
                return Err(RuntimeJsonError::TooDeep { maximum });
            }
            for value in values.values() {
                validate_json_depth(value, container_depth.saturating_add(1), maximum)?;
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
    }
    Ok(())
}

fn is_valid_json_global_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_JSON_GLOBAL_NAME_BYTES
        && name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || byte == b'_' || (index != 0 && byte.is_ascii_digit())
        })
}

struct BoundedJsonWriter {
    output: String,
    maximum: usize,
}

impl BoundedJsonWriter {
    fn new(maximum: usize) -> Self {
        Self {
            output: String::new(),
            maximum,
        }
    }

    fn append(&mut self, text: &str) -> Result<(), RuntimeJsonError> {
        let actual = self.output.len().saturating_add(text.len());
        if actual > self.maximum {
            return Err(RuntimeJsonError::TooLarge {
                actual,
                maximum: self.maximum,
            });
        }
        self.output.push_str(text);
        Ok(())
    }

    fn append_char(&mut self, character: char) -> Result<(), RuntimeJsonError> {
        let mut encoded = [0_u8; 4];
        self.append(character.encode_utf8(&mut encoded))
    }

    fn append_string(&mut self, value: &str) -> Result<(), RuntimeJsonError> {
        self.append("\"")?;
        for character in value.chars() {
            match character {
                '"' => self.append("\\\"")?,
                '\\' => self.append("\\\\")?,
                '\u{0008}' => self.append("\\b")?,
                '\u{000C}' => self.append("\\f")?,
                '\n' => self.append("\\n")?,
                '\r' => self.append("\\r")?,
                '\t' => self.append("\\t")?,
                character if character <= '\u{001F}' => {
                    let escaped = format!("\\u{:04x}", character as u32);
                    self.append(&escaped)?;
                }
                character => self.append_char(character)?,
            }
        }
        self.append("\"")
    }

    fn into_string(self) -> String {
        self.output
    }
}

fn write_script_json(
    vm: &mut vm::ScriptVm,
    value: vm::ScriptValue,
    maximum_depth: usize,
    path: &mut Vec<vm::ScriptValue>,
    writer: &mut BoundedJsonWriter,
) -> Result<(), RuntimeJsonError> {
    if value.is_nil() {
        return writer.append("null");
    }
    if let Some(value) = value.as_bool() {
        return writer.append(if value { "true" } else { "false" });
    }
    if let Some(value) = value.as_number() {
        if !value.is_finite() {
            return Err(RuntimeJsonError::NonFiniteNumber);
        }
        if value.fract() == 0.0 {
            return writer.append(&value.to_string());
        }
        let Some(number) = serde_json::Number::from_f64(value) else {
            return Err(RuntimeJsonError::NonFiniteNumber);
        };
        return writer.append(&number.to_string());
    }
    if let Some(identifier) = value.as_id() {
        let value = identifier
            .as_string(|value| value.map(str::to_owned))
            .ok_or(RuntimeJsonError::UnknownObjectKey)?;
        return writer.append_string(&value);
    }
    if let Some(value) = vm.bx.heap.string_with(value, |_, value| value.to_owned()) {
        return writer.append_string(&value);
    }
    if let Some(object) = value.as_object() {
        if vm.bx.heap.is_fn(object) {
            return Err(RuntimeJsonError::UnsupportedScriptValue);
        }
        if path.len() >= maximum_depth {
            return Err(RuntimeJsonError::TooDeep {
                maximum: maximum_depth,
            });
        }
        if path.contains(&value) {
            return Err(RuntimeJsonError::CyclicScriptValue);
        }
        path.push(value);
        let result = (|| {
            let entries = {
                let object = vm.bx.heap.object_data(object);
                let mut entries = Vec::with_capacity(object.map_len() + object.vec.len());
                object.map_iter(|key, value| entries.push((key, value)));
                entries.extend(object.vec.iter().map(|entry| (entry.key, entry.value)));
                entries
            };
            writer.append("{")?;
            let mut seen = BTreeSet::new();
            for (index, (key, value)) in entries.into_iter().enumerate() {
                let key = script_json_key(vm, key)?;
                if !seen.insert(key.clone()) {
                    return Err(RuntimeJsonError::DuplicateObjectKey);
                }
                if index != 0 {
                    writer.append(",")?;
                }
                writer.append_string(&key)?;
                writer.append(":")?;
                write_script_json(vm, value, maximum_depth, path, writer)?;
            }
            writer.append("}")
        })();
        path.pop();
        return result;
    }
    if let Some(array) = value.as_array() {
        if path.len() >= maximum_depth {
            return Err(RuntimeJsonError::TooDeep {
                maximum: maximum_depth,
            });
        }
        if path.contains(&value) {
            return Err(RuntimeJsonError::CyclicScriptValue);
        }
        path.push(value);
        let result = (|| {
            let values = {
                let storage = vm.bx.heap.array_storage(array);
                (0..storage.len())
                    .filter_map(|index| storage.index(index))
                    .collect::<Vec<_>>()
            };
            writer.append("[")?;
            for (index, value) in values.into_iter().enumerate() {
                if index != 0 {
                    writer.append(",")?;
                }
                write_script_json(vm, value, maximum_depth, path, writer)?;
            }
            writer.append("]")
        })();
        path.pop();
        return result;
    }
    Err(RuntimeJsonError::UnsupportedScriptValue)
}

fn script_json_key(
    vm: &mut vm::ScriptVm,
    value: vm::ScriptValue,
) -> Result<String, RuntimeJsonError> {
    if let Some(identifier) = value.as_id() {
        return identifier
            .as_string(|value| value.map(str::to_owned))
            .ok_or(RuntimeJsonError::UnknownObjectKey);
    }
    vm.bx
        .heap
        .string_with(value, |_, value| value.to_owned())
        .ok_or(RuntimeJsonError::NonStringObjectKey)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Delimiter {
    Curly,
    Round,
    Square,
}

impl Delimiter {
    fn from_opening_token(token: ScriptToken) -> Option<Self> {
        match token {
            ScriptToken::OpenCurly => Some(Self::Curly),
            ScriptToken::OpenRound => Some(Self::Round),
            ScriptToken::OpenSquare => Some(Self::Square),
            _ => None,
        }
    }

    fn from_closing_token(token: ScriptToken) -> Option<Self> {
        match token {
            ScriptToken::CloseCurly => Some(Self::Curly),
            ScriptToken::CloseRound => Some(Self::Round),
            ScriptToken::CloseSquare => Some(Self::Square),
            _ => None,
        }
    }

    const fn opening(self) -> char {
        match self {
            Self::Curly => '{',
            Self::Round => '(',
            Self::Square => '[',
        }
    }

    const fn closing(self) -> char {
        match self {
            Self::Curly => '}',
            Self::Round => ')',
            Self::Square => ']',
        }
    }
}

fn advance_vm_compatibility_nesting(
    tokenizer: &ScriptTokenizer,
    checked_tokens: &mut usize,
    delimiters: &mut Vec<Delimiter>,
    maximum_nesting: usize,
) -> Option<usize> {
    for (offset, token_position) in tokenizer.tokens[*checked_tokens..].iter().enumerate() {
        let token_index = *checked_tokens + offset;
        if let Some(opening) = Delimiter::from_opening_token(token_position.token) {
            if delimiters.len() >= maximum_nesting {
                return Some(token_index);
            }
            delimiters.push(opening);
            continue;
        }

        if let Some(closing) = Delimiter::from_closing_token(token_position.token) {
            if delimiters.last().is_some_and(|opening| *opening == closing) {
                delimiters.pop();
            }
        }
    }
    *checked_tokens = tokenizer.tokens.len();
    None
}

fn delimiter_diagnostics(tokenizer: &ScriptTokenizer) -> (Vec<SyntaxDiagnostic>, bool) {
    let mut diagnostics = Vec::new();
    let mut truncated = false;
    let mut openings = Vec::new();

    for (index, token_position) in tokenizer.tokens.iter().enumerate() {
        let opening = Delimiter::from_opening_token(token_position.token);
        if let Some(opening) = opening {
            openings.push((opening, index));
            continue;
        }

        let closing = if let Some(closing) = Delimiter::from_closing_token(token_position.token) {
            Some(closing)
        } else if matches!(token_position.token, ScriptToken::StringUnfinished) {
            let (line, column) = token_location(tokenizer, index);
            push_syntax_diagnostic(
                &mut diagnostics,
                &mut truncated,
                SyntaxDiagnostic {
                    line,
                    column,
                    message: "unterminated string literal".to_owned(),
                },
            );
            None
        } else {
            None
        };
        let Some(closing) = closing else {
            continue;
        };
        if openings
            .last()
            .is_some_and(|(opening, _)| *opening == closing)
        {
            openings.pop();
            continue;
        }
        let (line, column) = token_location(tokenizer, index);
        let message = openings.last().map_or_else(
            || format!("unexpected `{}`", closing.closing()),
            |(opening, _)| {
                format!(
                    "expected `{}` before `{}`",
                    opening.closing(),
                    closing.closing()
                )
            },
        );
        push_syntax_diagnostic(
            &mut diagnostics,
            &mut truncated,
            SyntaxDiagnostic {
                line,
                column,
                message,
            },
        );
    }

    for (opening, index) in openings.into_iter().rev() {
        let (line, column) = token_location(tokenizer, index);
        push_syntax_diagnostic(
            &mut diagnostics,
            &mut truncated,
            SyntaxDiagnostic {
                line,
                column,
                message: format!("unclosed `{}`", opening.opening()),
            },
        );
    }

    (diagnostics, truncated)
}

fn token_location(tokenizer: &ScriptTokenizer, index: usize) -> (usize, usize) {
    tokenizer
        .token_index_to_row_col(index as u32)
        .map(|(line, column)| (line as usize + 1, column as usize + 1))
        .unwrap_or((1, 1))
}

fn push_syntax_diagnostic(
    diagnostics: &mut Vec<SyntaxDiagnostic>,
    truncated: &mut bool,
    diagnostic: SyntaxDiagnostic,
) {
    if diagnostics.len() < MAX_SYNTAX_DIAGNOSTICS {
        diagnostics.push(diagnostic);
    } else {
        *truncated = true;
    }
}

fn evaluate_with_limits(
    vm: &mut vm::ScriptVm,
    limits: ExecutionLimits,
    operation: impl FnOnce(&mut vm::ScriptVm) -> vm::ScriptValue,
) -> Evaluation {
    vm.bx.captured_errors = Some(Vec::new());
    vm.bx.run_budget = Some(vm::ScriptRunBudget::from_durations(
        limits.soft_timeout,
        limits.hard_timeout,
        limits.budget_sample_interval,
    ));

    let value = vm.with_instruction_limit(limits.instruction_limit, operation);
    let diagnostics = vm.take_errors();
    let suspended = vm.bx.threads.cur_ref().is_paused();
    vm.bx.run_budget = None;

    Evaluation {
        value,
        diagnostics,
        suspended,
    }
}

fn has_paused_thread(vm: &vm::ScriptVm) -> bool {
    (0..vm.bx.threads.len()).any(|index| {
        vm.bx
            .threads
            .get(index)
            .is_some_and(vm::ScriptThread::is_paused)
    })
}

impl Default for Runtime<(), ()> {
    fn default() -> Self {
        Self::new((), ()).expect("default execution limits are valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_pure_script_with_diagnostics_enabled() {
        let mut runtime = Runtime::default();
        let report = runtime.eval("let total = 40 + 2\ntotal").unwrap();

        assert!(report.succeeded(), "{:?}", report.diagnostics);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn collection_preserves_an_evaluation_value() {
        let mut runtime = Runtime::default();
        let report = runtime
            .eval("let reply = {message: \"hello\"}\nreply")
            .unwrap();

        runtime.collect_garbage();

        let value = runtime.with_vm(|vm| {
            let serialized = vm.bx.heap.to_json(report.value);
            vm.string_with(serialized, |_, text| text.to_owned())
        });
        assert_eq!(value.as_deref(), Some("{\"message\":\"hello\"}"));
    }

    #[test]
    fn injects_bounded_json_and_extracts_a_script_result() {
        let mut runtime = Runtime::default();
        runtime
            .set_json_global(
                "workflow",
                &serde_json::json!({"input": {"left": 20, "right": 22}}),
                DEFAULT_MAX_JSON_DATA_BYTES,
                DEFAULT_MAX_JSON_DATA_DEPTH,
            )
            .unwrap();
        let report = runtime
            .eval(
                "let total = workflow.input.left + workflow.input.right\n\
                 let result = {total: total}\n\
                 result",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    report.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!({"total": 42})
        );
        runtime.clear_json_global("workflow").unwrap();
    }

    #[test]
    fn bounded_json_rejects_excess_depth_and_non_json_script_values() {
        assert_eq!(
            parse_bounded_json("[[[0]]]", 64, 2).unwrap_err(),
            RuntimeJsonError::TooDeep { maximum: 2 }
        );

        let mut runtime = Runtime::default();
        let report = runtime.eval("let callback = || 1\ncallback").unwrap();
        assert_eq!(
            runtime
                .script_value_as_json(report.value, 64, DEFAULT_MAX_JSON_DATA_DEPTH)
                .unwrap_err(),
            RuntimeError::JsonData(RuntimeJsonError::UnsupportedScriptValue)
        );
    }

    #[test]
    fn bounded_json_output_stops_at_its_serialized_byte_limit() {
        let mut runtime = Runtime::default();
        let report = runtime.eval("\"this value is too large\"").unwrap();

        assert!(matches!(
            runtime.script_value_as_json(report.value, 8, DEFAULT_MAX_JSON_DATA_DEPTH),
            Err(RuntimeError::JsonData(RuntimeJsonError::TooLarge {
                maximum: 8,
                ..
            }))
        ));
    }

    #[test]
    fn default_evaluation_rejects_makepad_compatibility_syntax() {
        let mut runtime = Runtime::default();
        let error = runtime.eval("var value = 42").unwrap_err();

        assert!(matches!(
            error,
            RuntimeError::SyntaxRejected(report)
                if report.diagnostics.iter().any(|diagnostic| {
                    diagnostic
                        .message
                        .contains("reserved words cannot be used as expressions")
                })
        ));
    }

    #[test]
    fn trusted_hosts_can_explicitly_opt_into_vm_compatibility() {
        let mut runtime = Runtime::default();
        let report = runtime
            .eval_vm_compatibility("var value = 42\nvalue")
            .unwrap();

        assert!(report.succeeded(), "{:?}", report.diagnostics);
    }

    #[test]
    fn vm_compatibility_try_recovers_from_a_script_error() {
        let mut runtime = Runtime::default();
        let report = runtime
            .eval_vm_compatibility(
                "use mod.std.assert\n\
                 try {\n\
                     assert(false)\n\
                 } {\n\
                     42\n\
                 }",
            )
            .unwrap();

        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    report.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(42)
        );

        let succeeded = runtime
            .eval_vm_compatibility(
                "use mod.std.assert\n\
                 let value = try { 7 } { assert(false) }\n\
                 value",
            )
            .unwrap();
        assert!(succeeded.completed(), "{:?}", succeeded.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    succeeded.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(7)
        );

        let ok_after_success = runtime
            .eval_vm_compatibility(
                "let marker = 0\n\
                 try { 7 } { marker = 1 } ok { marker = 2 }\n\
                 marker",
            )
            .unwrap();
        assert!(
            ok_after_success.completed(),
            "{:?}",
            ok_after_success.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    ok_after_success.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(2)
        );

        let fallback_after_error = runtime
            .eval_vm_compatibility(
                "use mod.std.assert\n\
                 let marker = 0\n\
                 try { assert(false) } { marker = 1 } ok { marker = 2 }\n\
                 marker",
            )
            .unwrap();
        assert!(
            fallback_after_error.completed(),
            "{:?}",
            fallback_after_error.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    fallback_after_error.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(1)
        );
    }

    #[test]
    fn canonical_try_catch_returns_the_protected_or_fallback_value() {
        let mut runtime = Runtime::default();
        let recovered = runtime
            .eval(
                "use mod.std.assert\n\
                 try {\n\
                     assert(false)\n\
                 } catch {\n\
                     42\n\
                 }",
            )
            .unwrap();

        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert!(recovered.diagnostics.is_empty());
        assert_eq!(
            runtime
                .script_value_as_json(
                    recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(42)
        );

        let succeeded = runtime
            .eval(
                "use mod.std.assert\n\
                 let value = try {\n\
                     7\n\
                 } catch {\n\
                     assert(false)\n\
                 }\n\
                 value",
            )
            .unwrap();
        assert!(succeeded.completed(), "{:?}", succeeded.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    succeeded.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(7)
        );

        let expression = runtime
            .eval("use mod.std.assert\ntry assert(false) catch 9")
            .unwrap();
        assert!(expression.completed(), "{:?}", expression.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    expression.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(9)
        );

        let record = runtime
            .eval(
                "let value = try ({answer: 42}) catch ({answer: 0})\n\
                 value.answer",
            )
            .unwrap();
        assert!(record.completed(), "{:?}", record.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    record.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(42)
        );
    }

    #[test]
    fn canonical_try_catch_does_not_swallow_a_fallback_error() {
        let mut runtime = Runtime::default();
        let evaluation = runtime
            .eval(
                "use mod.std.assert\n\
                 try {\n\
                     assert(false)\n\
                 } catch {\n\
                     assert(false)\n\
                 }",
            )
            .unwrap();

        assert!(!evaluation.succeeded());
        assert!(evaluation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("assertion failed")));
    }

    #[test]
    fn canonical_try_catch_unwinds_across_script_function_calls() {
        let mut runtime = Runtime::default();
        let outer = runtime
            .eval(
                "use mod.std.assert\n\
                 fn fail() {\n\
                     assert(false)\n\
                 }\n\
                 fn middle() {\n\
                     return fail()\n\
                 }\n\
                 let recovered = try {\n\
                     middle()\n\
                     0\n\
                 } catch {\n\
                     42\n\
                 }\n\
                 recovered",
            )
            .unwrap();
        assert!(outer.completed(), "{:?}", outer.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    outer.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(42)
        );

        let inner = runtime
            .eval(
                "use mod.std.assert\n\
                 fn fail() {\n\
                     assert(false)\n\
                 }\n\
                 fn recover() {\n\
                     return try {\n\
                         fail()\n\
                     } catch {\n\
                         7\n\
                     }\n\
                 }\n\
                 recover()",
            )
            .unwrap();
        assert!(inner.completed(), "{:?}", inner.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    inner.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(7)
        );
    }

    #[test]
    fn canonical_nested_try_catch_can_recover_from_an_inner_fallback_error() {
        let mut runtime = Runtime::default();
        let evaluation = runtime
            .eval(
                "use mod.std.assert\n\
                 try {\n\
                     try {\n\
                         assert(false)\n\
                     } catch {\n\
                         assert(false)\n\
                     }\n\
                 } catch {\n\
                     42\n\
                 }",
            )
            .unwrap();

        assert!(evaluation.completed(), "{:?}", evaluation.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    evaluation.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(42)
        );
    }

    #[test]
    fn canonical_catch_marker_is_consumed_only_once() {
        let mut runtime = Runtime::default();
        let evaluation = runtime
            .eval(
                "use mod.std.assert\n\
                 let catch = 2\n\
                 try {\n\
                     assert(false)\n\
                 } catch catch + 1",
            )
            .unwrap();

        assert!(evaluation.completed(), "{:?}", evaluation.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    evaluation.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(3)
        );

        let protected_identifier = runtime
            .eval(
                "let catch = 2\n\
                 try (catch) catch catch + 1",
            )
            .unwrap();
        assert!(
            protected_identifier.completed(),
            "{:?}",
            protected_identifier.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    protected_identifier.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(2)
        );
    }

    #[test]
    fn canonical_try_catch_cannot_recover_from_instruction_exhaustion() {
        let limits = ExecutionLimits {
            instruction_limit: 128,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), limits).unwrap();
        let evaluation = runtime
            .eval("try {\nloop {}\nnil\n} catch {\n42\n}")
            .unwrap();

        assert!(!evaluation.succeeded());
        assert!(evaluation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("instruction limit exceeded")));
    }

    #[test]
    fn canonical_try_catch_cannot_recover_from_a_hard_time_budget() {
        let limits = ExecutionLimits {
            instruction_limit: 100_000,
            soft_timeout: Duration::from_nanos(1),
            hard_timeout: Duration::from_nanos(1),
            budget_sample_interval: 64,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), limits).unwrap();
        let evaluation = runtime
            .eval("try {\nloop {}\nnil\n} catch {\n42\n}")
            .unwrap();

        assert!(!evaluation.succeeded());
        assert!(evaluation
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("script time budget exceeded")));
    }

    #[test]
    fn canonical_try_requires_an_explicit_catch_branch() {
        let report = check_syntax("try {\n42\n}\n").unwrap();

        assert!(!report.valid);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("expected `catch` after the protected expression or block")
        }));
    }

    #[test]
    fn canonical_try_blocks_require_an_explicit_result_expression() {
        for (source, expected) in [
            (
                "try {\nlet value = 42\n} catch {\n0\n}",
                "try protected block must end with a value-producing expression",
            ),
            (
                "try {\n42\n} catch {\nlet value = 0\n}",
                "try fallback block must end with a value-producing expression",
            ),
            (
                "try {\n42\n} catch {\n}",
                "try fallback block must end with a value-producing expression",
            ),
            (
                "try {\nloop {\nbreak\n}\n} catch {\n0\n}",
                "try protected block must end with a value-producing expression",
            ),
        ] {
            let report = check_syntax(source).unwrap();

            assert!(!report.valid, "unexpectedly accepted: {source}");
            assert!(
                report
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains(expected)),
                "missing `{expected}` for {source}: {:?}",
                report.diagnostics
            );
        }
    }

    #[test]
    fn loop_control_flow_discards_iteration_local_try_frames() {
        for (name, source) in [
            (
                "plain loop continue",
                "use mod.std.assert\n\
                 let state = {caught: 0}\n\
                 let first = true\n\
                 loop {\n\
                     if first {\n\
                         first = false\n\
                         try {\n\
                             continue\n\
                             nil\n\
                         } catch {\n\
                             state.caught += 1\n\
                         }\n\
                     }\n\
                     assert(false)\n\
                     break\n\
                 }\n\
                 state.caught",
            ),
            (
                "while continue",
                "use mod.std.assert\n\
                 let state = {caught: 0}\n\
                 let index = 0\n\
                 while index < 2 {\n\
                     index += 1\n\
                     if index == 1 {\n\
                         try {\n\
                             continue\n\
                             nil\n\
                         } catch {\n\
                             state.caught += 1\n\
                         }\n\
                     }\n\
                     assert(false)\n\
                     break\n\
                 }\n\
                 state.caught",
            ),
            (
                "loop break",
                "use mod.std.assert\n\
                 let state = {caught: 0}\n\
                 loop {\n\
                     try {\n\
                         break\n\
                         nil\n\
                     } catch {\n\
                         state.caught += 1\n\
                     }\n\
                 }\n\
                 assert(false)\n\
                 state.caught",
            ),
        ] {
            let mut runtime = Runtime::default();
            let evaluation = runtime.eval(source).unwrap();

            assert!(
                evaluation.completed(),
                "{name} did not complete: {:?}",
                evaluation.diagnostics
            );
            assert!(
                evaluation
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.contains("assertion failed")),
                "{name}: {:?}",
                evaluation.diagnostics
            );
            assert_eq!(
                runtime
                    .script_value_as_json(
                        evaluation.value,
                        DEFAULT_MAX_JSON_DATA_BYTES,
                        DEFAULT_MAX_JSON_DATA_DEPTH,
                    )
                    .unwrap(),
                serde_json::json!(0),
                "{name} re-entered an abandoned fallback"
            );
        }
    }

    #[test]
    fn rejects_sources_above_the_configured_limit() {
        let limits = ExecutionLimits {
            max_source_bytes: 4,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), limits).unwrap();

        assert_eq!(
            runtime.eval("hello").unwrap_err(),
            RuntimeError::SourceTooLarge {
                actual: 5,
                maximum: 4,
            }
        );
    }

    #[test]
    fn checks_syntax_without_executing_source() {
        let report = check_syntax("loop {}").unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn checks_vm_compatibility_without_executing_source() {
        let report = check_vm_compatibility("var value = 42\nloop {}").unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn canonical_preflight_shares_the_bounded_vm_validation_result() {
        let limits = ExecutionLimits {
            max_syntax_tokens: 16,
            max_syntax_nesting: 4,
            ..ExecutionLimits::default()
        };
        let source = "let value = [1]\nvalue[0]";

        let canonical = check_syntax_named("canonical.splash", source, limits).unwrap();
        let compatibility =
            check_vm_compatibility_named("canonical.splash", source, limits).unwrap();

        assert!(canonical.valid, "{:?}", canonical.diagnostics);
        assert_eq!(canonical, compatibility);
    }

    #[test]
    fn vm_compatibility_preflight_handles_unicode_identifiers() {
        let report = check_vm_compatibility_named(
            "legacy.splash",
            "var \u{540d}\u{79f0} = 42",
            ExecutionLimits::default(),
        )
        .unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn vm_compatibility_preflight_rejects_unavailable_rust_values() {
        let report =
            check_vm_compatibility_named("legacy.splash", "@(+", ExecutionLimits::default())
                .unwrap();

        assert!(!report.valid);
        assert!(report.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("Rust value index 0 is unavailable")));
    }

    #[test]
    fn vm_compatibility_preflight_accepts_legacy_source_at_the_exact_token_limit() {
        let limits = ExecutionLimits {
            max_syntax_tokens: 4,
            ..ExecutionLimits::default()
        };
        let report =
            check_vm_compatibility_named("legacy.splash", "var value = 42", limits).unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn vm_compatibility_preflight_rejects_excess_tokens_before_evaluation() {
        let limits = ExecutionLimits {
            max_syntax_tokens: 3,
            ..ExecutionLimits::default()
        };
        let report =
            check_vm_compatibility_named("legacy.splash", "var value = 42", limits).unwrap();

        assert!(!report.valid);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0]
            .message
            .contains("VM compatibility token count exceeds the maximum of 3"));

        let mut runtime = Runtime::with_limits((), (), limits).unwrap();
        assert!(matches!(
            runtime.eval_vm_compatibility("var value = 42"),
            Err(RuntimeError::SyntaxRejected(rejected))
                if rejected == report
        ));
    }

    #[test]
    fn vm_compatibility_preflight_respects_the_configured_nesting_limit() {
        let limits = ExecutionLimits {
            max_syntax_nesting: 3,
            ..ExecutionLimits::default()
        };
        let accepted =
            check_vm_compatibility_named("legacy.splash", "var value = (((42)))", limits).unwrap();
        assert!(accepted.valid, "{:?}", accepted.diagnostics);

        let rejected =
            check_vm_compatibility_named("legacy.splash", "var value = ((((42))))", limits)
                .unwrap();
        assert!(!rejected.valid);
        assert_eq!(rejected.diagnostics.len(), 1);
        assert!(rejected.diagnostics[0]
            .message
            .contains("VM compatibility nesting exceeds the maximum of 3"));

        let mut runtime = Runtime::with_limits((), (), limits).unwrap();
        assert!(matches!(
            runtime.eval_vm_compatibility("var value = ((((42))))"),
            Err(RuntimeError::SyntaxRejected(report)) if report == rejected
        ));
    }

    #[test]
    fn checks_tool_syntax_without_a_capability_host() {
        let report = check_syntax("use mod.tool\ntool.call(\"text.echo\", \"hello\")").unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn outlines_direct_tool_calls_without_resolving_runtime_values() {
        let source = r#"use mod.tool
let plain = tool.call("text.echo", "hello")
let delayed = tool.start("text.remote", "hello")
let structured = tool.call_json("math.add", {left: 20, right: 22})
let selected = "shell.exec"
let deferred = tool.start_json(selected, {command: "id"})
let escaped = tool.call("text.\u0065cho", "escaped")
let wrapper = {tool: tool}
wrapper.tool.call("must.not.appear", "x")
let alias = tool
alias.call("also.not.direct", "x")
let noise = "tool.call(\"also.ignored\", \"x\")"
// tool.start("comment.ignored", "x")
"#;

        let hints = tool_call_hints(source).expect("canonical source has tool-call hints");

        assert_eq!(hints.len(), 5);
        assert_eq!(hints[0].kind, ToolCallKind::Call);
        assert_eq!(hints[0].literal_name.as_deref(), Some("text.echo"));
        assert_eq!(hints[1].kind, ToolCallKind::Start);
        assert_eq!(hints[1].literal_name.as_deref(), Some("text.remote"));
        assert_eq!(hints[2].kind, ToolCallKind::CallJson);
        assert_eq!(hints[2].literal_name.as_deref(), Some("math.add"));
        assert_eq!(hints[3].kind, ToolCallKind::StartJson);
        assert_eq!(hints[3].literal_name, None);
        assert_eq!(hints[3].literal_name_start_byte, None);
        assert_eq!(hints[4].kind, ToolCallKind::Call);
        assert_eq!(hints[4].literal_name.as_deref(), Some("text.echo"));

        for hint in &hints {
            assert_eq!(
                &source[hint.callee_start_byte..hint.callee_end_byte],
                format!("tool.{}", hint.kind.as_str()),
            );
            assert!(source.is_char_boundary(hint.callee_start_byte));
            assert!(source.is_char_boundary(hint.callee_end_byte));
            assert!(hint.line >= 1 && hint.column >= 1);
        }
        assert_eq!(
            &source[hints[4].literal_name_start_byte.unwrap()
                ..hints[4].literal_name_end_byte.unwrap()],
            "\"text.\\u0065cho\"",
        );

        let runtime = Runtime::default();
        assert_eq!(runtime.tool_call_hints(source).unwrap(), hints);
    }

    #[test]
    fn try_catch_tool_calls_remain_visible_in_review_hints() {
        let source = "use mod.tool\n\
                      try {\n\
                          tool.call(\"text.primary\", \"input\")\n\
                      } catch {\n\
                          tool.call(\"text.fallback\", \"input\")\n\
                      }";

        let hints = tool_call_hints(source).unwrap();

        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].literal_name.as_deref(), Some("text.primary"));
        assert_eq!(hints[1].literal_name.as_deref(), Some("text.fallback"));
    }

    #[test]
    fn bounds_direct_tool_call_hint_reports_with_a_truncation_signal() {
        let mut source = String::from("use mod.tool\n");
        for index in 0..=MAX_TOOL_CALL_HINTS {
            source.push_str(&format!("tool.call(\"tool.{index}\", \"\")\n"));
        }

        let report = tool_call_hint_report(&source).expect("generated source is canonical");

        assert_eq!(report.hints.len(), MAX_TOOL_CALL_HINTS);
        assert!(report.truncated);
        assert_eq!(
            report
                .hints
                .first()
                .and_then(|hint| hint.literal_name.as_deref()),
            Some("tool.0")
        );
        assert_eq!(
            report
                .hints
                .last()
                .and_then(|hint| hint.literal_name.as_deref()),
            Some("tool.1023")
        );
        assert_eq!(tool_call_hints(&source).unwrap(), report.hints);

        let runtime = Runtime::default();
        assert_eq!(runtime.tool_call_hint_report(&source).unwrap(), report);
    }

    #[test]
    fn tool_call_hints_are_empty_for_invalid_or_compatibility_source() {
        assert!(tool_call_hints("var tool = {call: |name, value| value}")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn outlines_valid_top_level_declarations_with_byte_spans() {
        let source = "let config = {\n\
                      label: \"fn hidden() {}\"\n\
                      }\n\
                      fn greet(name) {\n\
                          let local = name\n\
                          local\n\
                      }\n\
                      let emoji = \"\u{1f642}\"\n\
                      // let ignored = 0\n";

        let declarations = top_level_declarations(source).expect("source is within default limits");

        assert_eq!(
            declarations
                .iter()
                .map(|declaration| (declaration.name.as_str(), declaration.kind))
                .collect::<Vec<_>>(),
            [
                ("config", TopLevelDeclarationKind::Let),
                ("greet", TopLevelDeclarationKind::Function),
                ("emoji", TopLevelDeclarationKind::Let),
            ]
        );
        assert_eq!(declarations[0].declaration_start_byte, 0);
        assert_eq!(
            declarations[0].declaration_end_byte,
            source
                .find("}\nfn greet")
                .expect("record closes before function")
                + 1
        );
        assert_eq!(
            declarations[1].declaration_end_byte,
            source
                .find("}\nlet emoji")
                .expect("function closes before declaration")
                + 1
        );
        assert_eq!(
            &source[declarations[2].selection_start_byte..declarations[2].selection_end_byte],
            "emoji"
        );
        assert_eq!(
            &source[declarations[2].declaration_start_byte..declarations[2].declaration_end_byte],
            "let emoji = \"\u{1f642}\""
        );
        assert!(top_level_declarations("fn broken(")
            .expect("invalid source is still bounded")
            .is_empty());
    }

    #[test]
    fn indexes_lexical_bindings_with_grammar_aware_scopes() {
        let source = r#"use mod.std.assert
let outer = 1
fn compute(outer, input) {
    let before = outer
    let record = {input: input}
    record.input
    if true {
        let branch = before
        branch
    } else 0
    let transform = |outer| outer + input
    for index, value in [outer] {
        let nested = value
        assert(nested + index)
    }
    branch + outer + before + input
}
compute(outer, 2)
"#;

        let report = lexical_symbol_report(source).expect("canonical source has a symbol index");

        assert!(!report.truncated);
        let summary = report
            .symbols
            .iter()
            .map(|symbol| (symbol.name.as_str(), symbol.kind, symbol.references.len()))
            .collect::<Vec<_>>();
        assert_eq!(
            summary,
            [
                ("assert", LexicalSymbolKind::Import, 1),
                ("outer", LexicalSymbolKind::Let, 1),
                ("compute", LexicalSymbolKind::Function, 1),
                ("outer", LexicalSymbolKind::Parameter, 3),
                ("input", LexicalSymbolKind::Parameter, 3),
                ("before", LexicalSymbolKind::Let, 2),
                ("record", LexicalSymbolKind::Let, 1),
                ("branch", LexicalSymbolKind::Let, 2),
                ("transform", LexicalSymbolKind::Let, 0),
                ("outer", LexicalSymbolKind::LambdaParameter, 1),
                ("index", LexicalSymbolKind::LoopBinding, 1),
                ("value", LexicalSymbolKind::LoopBinding, 1),
                ("nested", LexicalSymbolKind::Let, 1),
            ]
        );

        for symbol in &report.symbols {
            assert_eq!(
                &source[symbol.definition.start_byte..symbol.definition.end_byte],
                symbol.name
            );
            for reference in &symbol.references {
                assert_eq!(
                    &source[reference.start_byte..reference.end_byte],
                    symbol.name
                );
            }
        }
    }

    #[test]
    fn lexical_index_is_source_ordered_and_ignores_keys_and_members() {
        let source = "value\n\
                      let value = 1\n\
                      let record = {value: value}\n\
                      record.value\n\
                      let value = 2\n\
                      value";

        let report = lexical_symbol_report(source).unwrap();
        let values = report
            .symbols
            .iter()
            .filter(|symbol| symbol.name == "value")
            .collect::<Vec<_>>();

        assert_eq!(values.len(), 2);
        assert_eq!(values[0].references.len(), 1);
        assert_eq!(values[1].references.len(), 1);
        assert_eq!(
            &source[values[0].references[0].start_byte..values[0].references[0].end_byte],
            "value"
        );
        assert_eq!(
            report
                .symbols
                .iter()
                .find(|symbol| symbol.name == "record")
                .expect("record declaration is indexed")
                .references
                .len(),
            1
        );
    }

    #[test]
    fn for_iterable_resolves_before_its_binding_shadows_the_outer_name() {
        let source = "let item = [1]\n\
                      for item in item {\n\
                          item\n\
                      }\n\
                      item";

        let report = lexical_symbol_report(source).unwrap();
        let items = report
            .symbols
            .iter()
            .filter(|symbol| symbol.name == "item")
            .collect::<Vec<_>>();

        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind, LexicalSymbolKind::Let);
        assert_eq!(items[0].references.len(), 2);
        assert_eq!(items[1].kind, LexicalSymbolKind::LoopBinding);
        assert_eq!(items[1].references.len(), 1);
        let occurrences = source
            .match_indices("item")
            .map(|(start_byte, _)| start_byte)
            .collect::<Vec<_>>();
        assert_eq!(
            items[0]
                .references
                .iter()
                .map(|span| span.start_byte)
                .collect::<Vec<_>>(),
            [occurrences[2], occurrences[4]]
        );
        assert_eq!(items[1].references[0].start_byte, occurrences[3]);
    }

    #[test]
    fn lexical_index_spans_remain_utf8_boundaries_after_unicode() {
        let source = "let marker = \"\u{1f642}\"\nlet value = marker\nvalue";
        let report = lexical_symbol_report(source).unwrap();

        for symbol in &report.symbols {
            for span in std::iter::once(&symbol.definition).chain(&symbol.references) {
                assert!(source.is_char_boundary(span.start_byte));
                assert!(source.is_char_boundary(span.end_byte));
                assert_eq!(&source[span.start_byte..span.end_byte], symbol.name);
            }
        }
    }

    #[test]
    fn lexical_index_is_empty_for_invalid_source_and_bounded_for_large_source() {
        assert_eq!(
            lexical_symbol_report("fn broken(").unwrap(),
            LexicalSymbolReport::default()
        );

        let mut source = String::new();
        for index in 0..=MAX_LEXICAL_SYMBOL_OCCURRENCES {
            source.push_str(&format!("let binding{index} = 0\n"));
        }
        let report = lexical_symbol_report(&source).unwrap();

        assert_eq!(report.symbols.len(), MAX_LEXICAL_SYMBOL_OCCURRENCES);
        assert!(report.truncated);
        assert!(report
            .symbols
            .iter()
            .all(|symbol| symbol.references.is_empty()));
    }

    #[test]
    fn completion_metadata_tracks_expression_sites_and_half_open_visibility() {
        let source = "use mod.std.assert\n\
                      let outer = 1\n\
                      let value = outer\n\
                      let value = value\n\
                      fn work(param) {\n\
                          let local = param\n\
                          local\n\
                      }\n\
                      value";

        let report = lexical_completion_report(source).unwrap();

        assert_eq!(report.valid_prefix_end_byte, source.len());
        assert!(!report.symbols_truncated);
        assert!(!report.sites_truncated);
        assert_eq!(
            report
                .sites
                .iter()
                .map(|site| &source[site.start_byte..site.end_byte])
                .collect::<Vec<_>>(),
            ["outer", "value", "param", "local", "value"]
        );

        let values = report
            .symbols
            .iter()
            .filter(|symbol| symbol.name == "value")
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        let initializer = report.sites[1];
        let final_reference = report.sites[4];
        assert!(values[0].visibility_start_byte <= initializer.start_byte);
        assert_eq!(
            values[0].visibility_end_byte,
            values[1].visibility_start_byte
        );
        assert!(initializer.start_byte < values[0].visibility_end_byte);
        assert!(values[1].visibility_start_byte <= final_reference.start_byte);
        assert_eq!(values[1].visibility_end_byte, source.len());
    }

    #[test]
    fn declaration_is_not_visible_in_its_own_initializer() {
        let source = "let value = value\nvalue";
        let report = lexical_completion_report(source).unwrap();
        let symbol = report
            .symbols
            .iter()
            .find(|symbol| symbol.name == "value")
            .unwrap();

        assert_eq!(report.sites.len(), 2);
        assert!(report.sites[0].end_byte <= symbol.visibility_start_byte);
        assert_eq!(symbol.references, vec![report.sites[1]]);
    }

    #[test]
    fn scoped_binding_visibility_ends_before_the_next_identifier() {
        let source = "for item in [1] {\nitem\n}\nitem";
        let report = lexical_completion_report(source).unwrap();
        let item = report
            .symbols
            .iter()
            .find(|symbol| symbol.name == "item")
            .unwrap();
        let item_sites = report
            .sites
            .iter()
            .copied()
            .filter(|site| &source[site.start_byte..site.end_byte] == "item")
            .collect::<Vec<_>>();

        assert_eq!(item_sites.len(), 2);
        assert_eq!(item.references, vec![item_sites[0]]);
        assert!(item.visibility_end_byte <= item_sites[1].start_byte);
        assert!(item_sites[1].start_byte >= item.visibility_end_byte);
    }

    #[test]
    fn member_names_record_keys_and_literal_keywords_are_not_completion_sites() {
        let source = "let record = {key: 1}\nrecord.key\ntrue\nfalse\nnil";
        let report = lexical_completion_report(source).unwrap();

        assert_eq!(
            report
                .sites
                .iter()
                .map(|site| &source[site.start_byte..site.end_byte])
                .collect::<Vec<_>>(),
            ["record"]
        );
    }

    #[test]
    fn completion_metadata_retains_only_sites_in_the_valid_prefix() {
        let incomplete = "let marker = \"🙂\"\r\nlet alpha = 1\r\nalpha(";
        let report = lexical_completion_report(incomplete).unwrap();
        let alpha_site = report
            .sites
            .iter()
            .copied()
            .find(|site| &incomplete[site.start_byte..site.end_byte] == "alpha")
            .unwrap();

        assert_eq!(report.valid_prefix_end_byte, incomplete.len());
        assert!(alpha_site.end_byte <= report.valid_prefix_end_byte);
        assert!(incomplete.is_char_boundary(alpha_site.start_byte));

        let invalid_middle = "let marker = \"🙂\"\rlet alpha = 1\ralpha\r@\ralpha";
        let invalid_report = lexical_completion_report(invalid_middle).unwrap();
        assert_eq!(
            invalid_report.valid_prefix_end_byte,
            invalid_middle.find('@').unwrap()
        );
        let alpha_sites = invalid_report
            .sites
            .iter()
            .filter(|site| &invalid_middle[site.start_byte..site.end_byte] == "alpha")
            .collect::<Vec<_>>();
        assert_eq!(alpha_sites.len(), 2);
        assert!(alpha_sites[0].end_byte <= invalid_report.valid_prefix_end_byte);
        assert!(alpha_sites[1].end_byte > invalid_report.valid_prefix_end_byte);

        let invalid_prefix_report = lexical_completion_report("@\nalpha").unwrap();
        assert_eq!(invalid_prefix_report.valid_prefix_end_byte, 0);

        let unicode_column = "let marker = \"🙂\" @";
        assert_eq!(
            lexical_completion_report(unicode_column)
                .unwrap()
                .valid_prefix_end_byte,
            unicode_column.find('@').unwrap()
        );

        let runtime = Runtime::default();
        assert_eq!(
            runtime.lexical_completion_report(incomplete).unwrap(),
            report
        );
    }

    #[test]
    fn completion_sites_have_an_independent_fixed_bound() {
        let mut source = String::from("let value = 0\n");
        for _ in 0..=MAX_LEXICAL_COMPLETION_SITES {
            source.push_str("value\n");
        }

        let report = lexical_completion_report(&source).unwrap();

        assert_eq!(report.sites.len(), MAX_LEXICAL_COMPLETION_SITES);
        assert!(report.sites_truncated);
        assert!(report.symbols_truncated);
        assert!(report.sites.iter().all(|site| {
            source.is_char_boundary(site.start_byte)
                && source.is_char_boundary(site.end_byte)
                && &source[site.start_byte..site.end_byte] == "value"
        }));
    }

    #[test]
    fn completion_visibility_uses_source_end_when_the_token_stream_is_capped() {
        let source = "let value = 0\nvalue\nvalue";
        let limits = ExecutionLimits {
            max_syntax_tokens: 6,
            ..ExecutionLimits::default()
        };

        let report = lexical_completion_report_named("capped.splash", source, limits).unwrap();
        let symbol = report.symbols.first().unwrap();

        assert_eq!(report.sites.len(), 1);
        assert_eq!(symbol.references, report.sites);
        assert_eq!(symbol.visibility_end_byte, source.len());
        assert_eq!(report.valid_prefix_end_byte, report.sites[0].end_byte);
    }

    #[test]
    fn canonical_identifier_validation_reuses_the_profile_lexer() {
        for accepted in ["value", "_private", "Value42"] {
            assert!(is_canonical_identifier(accepted), "{accepted}");
        }
        for rejected in [
            "",
            "try",
            "true",
            "two words",
            "value ",
            "value/*comment*/",
            "value.name",
            "\u{1f642}",
        ] {
            assert!(!is_canonical_identifier(rejected), "{rejected}");
        }
    }

    #[test]
    fn formats_canonical_source_idempotently() {
        let source = "fn add(left,right){\nreturn left+right\n}\nlet record={left:1,right:2}\nadd(record.left,record.right)";

        let formatted = format_source(source).unwrap();
        assert_eq!(
            formatted,
            "fn add(left, right) {\n    return left + right\n}\nlet record = {left: 1, right: 2}\nadd(record.left, record.right)\n"
        );
        assert!(check_syntax(&formatted).unwrap().valid);
        assert_eq!(format_source(&formatted).unwrap(), formatted);
    }

    #[test]
    fn formatter_preserves_comments_literals_and_block_comment_newlines() {
        let source = "fn describe(){/* opening note\nstill note */\nlet text=\"// literal\"\n// line note\nreturn text\n}";

        let formatted = format_source(source).unwrap();

        assert!(formatted.contains("/* opening note\n    still note */"));
        assert!(formatted.contains("    // line note\n"));
        assert!(formatted.contains("let text = \"// literal\""));
        assert!(check_syntax(&formatted).unwrap().valid);
        assert_eq!(format_source(&formatted).unwrap(), formatted);
    }

    #[test]
    fn formatter_distinguishes_literals_indexes_and_lambda_delimiters() {
        let source = "let values=[1,2]\r\nlet transform = |value| value*2\r\nlet first=values[0]";

        assert_eq!(
            format_source(source).unwrap(),
            "let values = [1, 2]\nlet transform = |value| value * 2\nlet first = values[0]\n"
        );
    }

    #[test]
    fn formatter_normalizes_canonical_try_catch() {
        let source = "try{\n42\n}catch{\n0\n}";
        let formatted = format_source(source).unwrap();

        assert_eq!(formatted, "try {\n    42\n} catch {\n    0\n}\n");
        assert!(check_syntax(&formatted).unwrap().valid);
        assert_eq!(format_source(&formatted).unwrap(), formatted);
    }

    #[test]
    fn formatter_rejects_noncanonical_source_without_recovery() {
        assert!(matches!(
            format_source("var value = 42"),
            Err(RuntimeError::SyntaxRejected(report)) if !report.valid
        ));
    }

    #[test]
    fn formatter_obeys_source_and_token_limits() {
        let limits = ExecutionLimits {
            max_source_bytes: 4,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            format_source_named("limited.splash", "hello", limits).unwrap_err(),
            RuntimeError::SourceTooLarge {
                actual: 5,
                maximum: 4,
            }
        );

        let limits = ExecutionLimits {
            max_syntax_tokens: 3,
            ..ExecutionLimits::default()
        };
        assert!(matches!(
            format_source_named("tokens.splash", "let value = 1", limits),
            Err(RuntimeError::SyntaxRejected(report)) if !report.valid
        ));

        let limits = ExecutionLimits {
            max_syntax_tokens: 4,
            ..ExecutionLimits::default()
        };
        let formatted = format_source_named("tokens.splash", "let value=1", limits).unwrap();
        assert_eq!(formatted, "let value = 1");
        assert!(
            check_syntax_named("tokens.splash", &formatted, limits)
                .unwrap()
                .valid
        );
    }

    #[test]
    fn formatter_bounds_indentation_expansion() {
        let mut source = "fn nested() {\n".to_owned();
        for _ in 0..20 {
            source.push_str("if true {\n");
        }
        for _ in 0..200 {
            source.push_str("let value = 0\n");
        }
        for _ in 0..20 {
            source.push_str("}\n");
        }
        source.push('}');

        let limits = ExecutionLimits {
            max_source_bytes: source.len(),
            ..ExecutionLimits::default()
        };
        assert!(
            check_syntax_named("nested.splash", &source, limits)
                .unwrap()
                .valid
        );
        assert!(matches!(
            format_source_named("nested.splash", &source, limits),
            Err(RuntimeError::FormattedSourceTooLarge { maximum, .. })
                if maximum == source.len() * FORMAT_OUTPUT_MULTIPLIER
        ));
    }

    #[test]
    fn checks_canonical_record_member_separators() {
        let report = check_syntax(
            "let values = [20, 22]\nlet request = {left: values[0], right: values[1]}",
        )
        .unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn accepts_the_canonical_control_and_dataflow_profile() {
        let report = check_syntax(
            "let values = [20, 22]\n\
             let request = {\n\
                 left: values[0]\n\
                 right: values[1]\n\
             }\n\
             let result = if request.left < request.right {\n\
                 request.right\n\
             } else {\n\
                 request.left\n\
             }\n\
             let doubled = |value| value * 2\n\
             doubled(result)",
        )
        .unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn generated_canonical_corpus_remains_vm_parse_compatible() {
        const ATOMS: [&str; 14] = [
            "nil",
            "true",
            "false",
            "0",
            "42",
            "1.25e+2",
            "\"line\\n\\u{0041}\"",
            "value",
            "[1, 2]",
            "{left: 1, right: 2}",
            "(1 + 2)",
            "if true { 1 } else { 2 }",
            "|| 0",
            "|value| value + 1",
        ];

        let mut sources = Vec::new();
        for atom in ATOMS {
            sources.extend([
                format!("let value = {atom}\nvalue"),
                format!("let value = ({atom})\nvalue"),
                format!("let value = !{atom}\nvalue"),
                format!("let value = {atom} + 1\nvalue"),
                format!("let value = {atom} == {atom}\nvalue"),
                format!("let value = {atom}.field\nvalue"),
                format!("let value = {atom}[0]\nvalue"),
            ]);
        }
        sources.extend([
            "fn add(left, right) {\n    return left + right\n}\nadd(1, 2)".to_owned(),
            "let values = [1, 2]\nfor value in values {\n    let copy = value\n}".to_owned(),
            "let values = [1, 2]\nfor index, value in values {\n    if index == 0 {\n        continue\n    } else {\n        break\n    }\n}".to_owned(),
            "let values = [1, 2]\nfor first, second, third in values {\n    break\n}".to_owned(),
            "while false {\n    break\n}".to_owned(),
            "loop {\n    break\n}".to_owned(),
            "let record = {\n    left: 1\n    right: 2\n}\nrecord.left".to_owned(),
            "let callback = |value| {\n    return value + 1\n}\ncallback(1)".to_owned(),
            "use mod.std.assert\nassert(true)".to_owned(),
            "use mod.tool\ntool.call(\"text.echo\", \"hello\")".to_owned(),
            "use mod.tool\ntool.start(\"text.echo\", \"hello\").await()".to_owned(),
        ]);

        let limits = ExecutionLimits::default();
        let mut profile_accepted = 0;
        for source in sources {
            let profile = check_canonical_profile(
                &source,
                limits.max_syntax_tokens,
                limits.max_syntax_nesting,
            );
            if !profile.diagnostics.is_empty() || profile.diagnostics_truncated {
                continue;
            }

            profile_accepted += 1;
            let report = check_syntax_named("generated.splash", &source, limits).unwrap();
            assert!(
                report.valid,
                "canonical profile accepted source that the VM parser rejected: {source:?}\n{:?}",
                report.diagnostics
            );
        }

        assert!(
            profile_accepted >= 90,
            "generated corpus lost canonical coverage: {profile_accepted} sources accepted"
        );
    }

    #[test]
    fn preserves_field_access_after_numeric_literals_and_comment_newlines() {
        let report = check_syntax(
            "let field = 1.value\n\
             let first = 1 /* a block comment\n\
             */\n\
             let second = 2",
        )
        .unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn bounds_canonical_profile_nesting() {
        let source = format!(
            "let value = {}0{}",
            "(".repeat(DEFAULT_MAX_SYNTAX_NESTING + 1),
            ")".repeat(DEFAULT_MAX_SYNTAX_NESTING + 1)
        );
        let report = check_syntax(&source).unwrap();

        assert!(!report.valid);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("canonical Splash nesting exceeds the maximum")
        }));
    }

    #[test]
    fn canonical_profile_respects_the_configured_nesting_limit() {
        let limits = ExecutionLimits {
            max_syntax_nesting: 2,
            ..ExecutionLimits::default()
        };
        let accepted = check_syntax_named("nesting.splash", "let value = (0)", limits).unwrap();
        assert!(accepted.valid, "{:?}", accepted.diagnostics);

        let rejected = check_syntax_named("nesting.splash", "let value = ((0))", limits).unwrap();
        assert!(!rejected.valid);
        assert!(rejected.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("canonical Splash nesting exceeds the maximum of 2")
        }));
    }

    #[test]
    fn bounds_canonical_profile_token_count_before_vm_parsing() {
        let limits = ExecutionLimits {
            max_syntax_tokens: 3,
            ..ExecutionLimits::default()
        };
        let report = check_syntax_named("tokens.splash", ";;;;", limits).unwrap();

        assert!(!report.valid);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].line, 1);
        assert_eq!(report.diagnostics[0].column, 4);
        assert!(report.diagnostics[0]
            .message
            .contains("canonical Splash token count exceeds the maximum of 3"));
    }

    #[test]
    fn accepts_the_exact_token_limit_with_trailing_non_tokens() {
        let limits = ExecutionLimits {
            max_syntax_tokens: 4,
            ..ExecutionLimits::default()
        };
        let report = check_syntax_named(
            "tokens.splash",
            "let value = 1 /* trailing comment */",
            limits,
        )
        .unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn bounds_newline_tokens_emitted_from_block_comments() {
        let limits = ExecutionLimits {
            max_syntax_tokens: 3,
            ..ExecutionLimits::default()
        };
        let report = check_syntax_named("comment.splash", "/*\n\n\n\n*/", limits).unwrap();

        assert!(!report.valid);
        assert_eq!(report.diagnostics.len(), 1);
        assert_eq!(report.diagnostics[0].line, 4);
        assert_eq!(report.diagnostics[0].column, 1);
        assert!(report.diagnostics[0]
            .message
            .contains("canonical Splash token count exceeds the maximum of 3"));
    }

    #[test]
    fn rejects_makepad_compatibility_syntax_outside_the_profile() {
        for (source, expected) in [
            (
                "let request = {left: 20 right: 22}",
                "expected `,`, a newline, or `}` after a record member",
            ),
            (
                "var value = 42",
                "reserved words cannot be used as expressions here",
            ),
            (
                "let value: Number = 42",
                "expected `=` or a statement end after a `let` declaration",
            ),
            (
                "let [left, right] = [20, 22]",
                "expected an identifier after `let`",
            ),
            (
                "let value = 'single quoted'",
                "only double-quoted strings are part of the canonical Splash profile",
            ),
            (
                "let value = 42u32",
                "numeric literal suffixes are not part of the canonical Splash profile",
            ),
            (
                "let values = 1..3",
                "operator `..` is not part of the canonical Splash profile",
            ),
            ("let value = ! !false", "expected an expression"),
            (
                "for value, in [1] {}",
                "trailing commas are not part of the canonical `for` binding grammar",
            ),
        ] {
            let report = check_syntax(source).unwrap();

            assert!(!report.valid, "unexpectedly accepted: {source}");
            assert!(
                report
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains(expected)),
                "missing `{expected}` for {source}: {:?}",
                report.diagnostics
            );
        }
    }

    #[test]
    fn reports_canonical_profile_locations() {
        let report = check_syntax("let first = 1\nlet record = {first: first second: 2}").unwrap();

        assert!(!report.valid);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.line == 2
                && diagnostic.column == 28
                && diagnostic
                    .message
                    .contains("expected `,`, a newline, or `}`")
        }));
    }

    #[test]
    fn reports_unclosed_blocks_from_the_canonical_profile() {
        let report = check_syntax("fn work() {\n    return 42").unwrap();

        assert!(!report.valid);
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("expected `}` to close a block")));
    }

    #[test]
    fn reports_unterminated_strings() {
        let report = check_syntax("let value = \"unterminated").unwrap();

        assert!(!report.valid);
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("unterminated string")));
    }

    #[test]
    fn rejects_unicode_escapes_that_are_not_unicode_scalars() {
        for source in [
            r#"let value = "\uD800""#,
            r#"let value = "\u{D800}""#,
            r#"let value = "\u{110000}""#,
        ] {
            let report = check_syntax(source).unwrap();

            assert!(!report.valid, "unexpectedly accepted: {source}");
            assert!(report.diagnostics.iter().any(|diagnostic| {
                diagnostic
                    .message
                    .contains("must encode a valid Unicode scalar value")
            }));
        }

        let report = check_syntax(r#"let value = "\u{10FFFF}""#).unwrap();
        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn profile_rejections_do_not_invoke_the_inherited_parser() {
        let report = check_syntax("let = 42").unwrap();

        assert!(!report.valid);
        assert_eq!(report.diagnostics.len(), 1);
        assert!(report.diagnostics[0]
            .message
            .contains("expected an identifier after `let`"));
        assert!(report
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.line >= 1 && diagnostic.column >= 1));
    }

    #[test]
    fn syntax_checks_respect_the_configured_source_limit() {
        let limits = ExecutionLimits {
            max_source_bytes: 4,
            ..ExecutionLimits::default()
        };

        assert_eq!(
            check_syntax_named("limited.splash", "hello", limits).unwrap_err(),
            RuntimeError::SourceTooLarge {
                actual: 5,
                maximum: 4,
            }
        );
    }

    #[test]
    fn rejects_zero_syntax_token_limit() {
        let limits = ExecutionLimits {
            max_syntax_tokens: 0,
            ..ExecutionLimits::default()
        };

        assert_eq!(
            check_syntax_named("tokens.splash", "let value = 1", limits).unwrap_err(),
            RuntimeError::InvalidLimits("max_syntax_tokens must be greater than zero")
        );
    }

    #[test]
    fn rejects_zero_syntax_nesting_limit() {
        let limits = ExecutionLimits {
            max_syntax_nesting: 0,
            ..ExecutionLimits::default()
        };

        assert_eq!(
            check_syntax_named("nesting.splash", "let value = 1", limits).unwrap_err(),
            RuntimeError::InvalidLimits("max_syntax_nesting must be greater than zero")
        );
    }

    #[test]
    fn stops_runaway_code_at_the_instruction_limit() {
        let limits = ExecutionLimits {
            instruction_limit: 128,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), limits).unwrap();
        let report = runtime.eval("loop {}").unwrap();

        assert!(!report.succeeded());
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("instruction")));
    }

    #[test]
    fn does_not_load_makepad_effect_modules() {
        for source in [
            "use mod.fs\nfs.read(\"/etc/passwd\")",
            "use mod.run\nrun.child({cmd:\"whoami\"})",
            "use mod.net\nnet.socket_stream(\"example.com\", 443)",
        ] {
            let mut runtime = Runtime::default();
            let report = runtime.eval(source).unwrap();

            assert!(!report.succeeded(), "unexpectedly evaluated: {source}");
            assert!(!report.diagnostics.is_empty());
        }
    }

    #[test]
    fn preserves_the_llm_workflow_language_fixture() {
        let mut runtime = Runtime::default();
        let report = runtime
            .eval(include_str!("../tests/fixtures/workflow_language.splash"))
            .unwrap();

        assert!(report.succeeded(), "{:?}", report.diagnostics);
    }
}
