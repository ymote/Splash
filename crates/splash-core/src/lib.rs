#![forbid(unsafe_code)]

//! Host-neutral execution primitives for Splash.
//!
//! This crate masks the vendored VM down to the standalone Splash source
//! surface, then owns runtime limits and diagnostic capture. Effectful APIs
//! belong to a separate host crate and must be explicitly installed by trusted
//! Rust code.

mod profile;

use std::any::Any;
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap};
use std::fmt::{self, Display, Formatter};
use std::rc::Rc;
use std::time::Duration;

pub use makepad_script as vm;
#[cfg(any(fuzzing, test))]
use profile::check_canonical_profile;
use profile::{
    canonical_parser_prefix_end_byte, collect_imported_module_call_hints,
    collect_lexical_completions, collect_lexical_symbols, collect_module_imports,
    collect_static_record_shapes, collect_tool_call_hints, collect_top_level_declarations,
    format_canonical_source, is_canonical_identifier as profile_is_canonical_identifier,
    lower_canonical_source_for_vm, ProfileFormatError, ProfileReport,
};
pub use serde_json::Value as JsonValue;
use vm::parser::ScriptParser;
use vm::tokenizer::{ScriptToken, ScriptTokenizer};
use vm::{
    id, id_lut, script_args_def, script_err_invalid_args, script_err_limit,
    script_err_type_mismatch, script_err_unexpected, script_value, LiveId, ScriptIp, ScriptObject,
    ScriptStringSink, ScriptValue, NIL,
};

/// Stable identifier for the portable source contract enforced before normal
/// Splash evaluation.
pub const CANONICAL_PROFILE_ID: &str = "splash-v0.2";
/// Version of the portable source grammar named by [`CANONICAL_PROFILE_ID`].
pub const CANONICAL_PROFILE_VERSION: &str = "0.2";
/// Repository-relative location of the normative portable grammar.
pub const CANONICAL_PROFILE_GRAMMAR_PATH: &str = "docs/grammar.md";
pub const DEFAULT_MAX_SOURCE_BYTES: usize = 256 * 1024;
/// Default maximum byte length for one newly constructed Splash string.
///
/// This is an individual-string limit, not a complete VM heap accounting
/// limit. Hosts with smaller memory budgets should lower it explicitly.
pub const DEFAULT_MAX_SCRIPT_STRING_BYTES: usize = 256 * 1024;
/// Default retained-capacity budget for Splash-owned VM heap data.
///
/// This accounts for script strings, arrays, object storage, slot tables, and
/// intern tables. It is not an operating-system process memory limit and does
/// not account for opaque trusted Rust adapter allocations.
pub const DEFAULT_MAX_SCRIPT_HEAP_BYTES: usize = 8 * 1024 * 1024;
/// Default maximum live operand values in one Splash VM thread.
///
/// This bounds the VM execution stack independently from retained heap data.
pub const DEFAULT_MAX_SCRIPT_STACK_VALUES: usize = 32 * 1024;
/// Default maximum active Splash VM call frames, including the root frame.
///
/// This bounds recursive execution state independently from instruction fuel.
pub const DEFAULT_MAX_SCRIPT_CALL_FRAMES: usize = 1_024;
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
/// Maximum source array items processed by one transforming standard
/// collection helper.
///
/// The VM heap bounds retained array storage, while this independent ceiling
/// bounds native helper work over a script-provided array. `array.len` is
/// constant-time and does not use this ceiling; `text.join` applies it before
/// traversing its string input array.
pub const MAX_STANDARD_ARRAY_ITEMS: usize = 4_096;
/// Maximum own fields processed by one transforming `mod.std.object` helper.
///
/// This independently bounds native traversal over a plain script record.
/// `object.len` is constant-time and does not use this ceiling.
pub const MAX_STANDARD_OBJECT_FIELDS: usize = 4_096;
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
/// Maximum scope-resolved imported-module member-call hints retained for one
/// canonical source document.
///
/// This is independent of [`MAX_TOOL_CALL_HINTS`] because a host may present
/// direct `mod.tool` and reviewed direct-module calls as separate advisory
/// review surfaces. Use [`ImportedModuleCallHintReport::truncated`] to detect
/// omitted sites or a lexical/import index that could not resolve every site.
pub const MAX_IMPORTED_MODULE_CALL_HINTS: usize = 1_024;
/// Maximum exact local root-alias hops followed while resolving one imported
/// module receiver for advisory review.
///
/// This permits ergonomic `let alias = imported_module` chains without
/// treating computed values, field selections, or arbitrary runtime values as
/// module bindings.
pub const MAX_IMPORTED_MODULE_ALIAS_DEPTH: usize = 16;
/// Maximum complete `use mod.<path>` declarations retained in one
/// source-only import report.
///
/// This is separate from lexical definition/reference and completion-site
/// bounds so editor metadata cannot grow with a generated import list.
pub const MAX_MODULE_IMPORTS: usize = 1_024;
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
/// Maximum direct literal-record bindings retained for one source snapshot.
///
/// This is independent of lexical symbol and completion-site bounds. It keeps
/// static editor metadata bounded even for generated documents with many
/// records.
pub const MAX_STATIC_RECORD_SHAPES: usize = 1_024;
/// Maximum exact literal-record child levels retained below a static root.
///
/// This keeps advisory member-path traversal fixed while covering direct
/// `root.child.grandchild` paths. It does not authorize broader type inference
/// or arbitrary runtime member resolution.
pub const MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH: usize = 2;
/// Maximum retained direct root, child, or grandchild aliases of a static
/// record binding per source snapshot.
///
/// This is independent of the direct-shape and aggregate-field bounds. It
/// prevents source-only alias metadata from growing with generated documents.
pub const MAX_STATIC_RECORD_ALIASES: usize = 1_024;
/// Maximum direct literal-record fields retained across one source snapshot.
///
/// This includes fields from every retained exact nested child literal. When
/// this aggregate cap is reached, later complete record shapes are omitted
/// instead of returning a partial field list for a binding.
pub const MAX_STATIC_RECORD_FIELDS: usize = 4_096;

/// Bounds applied to one source evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLimits {
    pub max_source_bytes: usize,
    /// Maximum byte length for one newly constructed script string.
    ///
    /// This is not aggregate VM heap accounting.
    pub max_string_bytes: usize,
    /// Maximum retained capacity tracked for Splash-owned VM heap data.
    ///
    /// This is not a process allocator quota and excludes opaque trusted Rust
    /// adapters. The VM's bootstrap storage counts against this value, so
    /// construction fails when it is below the required baseline. Hosts that
    /// need OS-level containment must layer it separately.
    pub max_heap_bytes: usize,
    /// Maximum live operand values in the VM execution stack.
    ///
    /// This does not bound native Rust stacks or opaque host adapter state.
    pub max_stack_values: usize,
    /// Maximum active VM call frames, including the root evaluation frame.
    ///
    /// This limits recursive script calls but does not bound host recursion.
    pub max_call_frames: usize,
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
            max_string_bytes: DEFAULT_MAX_SCRIPT_STRING_BYTES,
            max_heap_bytes: DEFAULT_MAX_SCRIPT_HEAP_BYTES,
            max_stack_values: DEFAULT_MAX_SCRIPT_STACK_VALUES,
            max_call_frames: DEFAULT_MAX_SCRIPT_CALL_FRAMES,
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
        if self.max_string_bytes == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_string_bytes must be greater than zero",
            ));
        }
        if self.max_heap_bytes == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_heap_bytes must be greater than zero",
            ));
        }
        if self.max_stack_values == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_stack_values must be greater than zero",
            ));
        }
        if self.max_call_frames == 0 {
            return Err(RuntimeError::InvalidLimits(
                "max_call_frames must be greater than zero",
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
        if u32::try_from(self.instruction_limit)
            .is_ok_and(|instruction_limit| self.budget_sample_interval >= instruction_limit)
        {
            return Err(RuntimeError::InvalidLimits(
                "budget_sample_interval must be less than instruction_limit",
            ));
        }
        Ok(self)
    }
}

/// Bounds applied to direct Splash [`Runtime`] JSON methods.
///
/// The inherited Makepad JSON methods are appropriate for trusted UI hosts but
/// do not apply Splash's byte, depth, or cycle rules. The Splash runtime
/// replaces their dispatch with the same bounded JSON reader and writer used
/// at the Rust data boundary. A host can lower these limits by lowering its
/// normal source or syntax-nesting limits; they never exceed the standalone
/// JSON defaults.
#[derive(Clone, Copy)]
struct ScriptJsonMethodLimits {
    max_bytes: usize,
    max_depth: usize,
}

impl ScriptJsonMethodLimits {
    fn from_execution_limits(limits: ExecutionLimits) -> Self {
        Self {
            max_bytes: limits.max_source_bytes.min(DEFAULT_MAX_JSON_DATA_BYTES),
            max_depth: limits.max_syntax_nesting.min(DEFAULT_MAX_JSON_DATA_DEPTH),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    SourceTooLarge { actual: usize, maximum: usize },
    StringLimitExceeded { maximum: usize },
    HeapLimitExceeded { actual: usize, maximum: usize },
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
            Self::StringLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "script string allocation exceeds {maximum} bytes"
                )
            }
            Self::HeapLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "script heap retains {actual} accounted bytes; maximum is {maximum} bytes"
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

/// One complete canonical `use mod.<path>` declaration.
///
/// `path` always begins with `"mod"`, contains at least one following
/// identifier, and is ordered as it appeared in source. `path_span` covers
/// the complete `mod.<path>` source region, including any permitted whitespace
/// or comments between path tokens; `binding` covers its final identifier.
/// This is source metadata only. It neither loads a module nor proves that a
/// corresponding host binding, capability, or adapter exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleImport {
    pub path: Vec<String>,
    pub path_span: SourceSpan,
    pub binding: SourceSpan,
}

/// Bounded source-only import metadata for one canonical source snapshot.
///
/// Imports are retained in source order only when their complete path ends at
/// or before `valid_prefix_end_byte`. This allows an editor to retain imports
/// established before an incomplete trailing expression without assigning
/// meaning to recovery tokens after the first diagnostic. `truncated` means
/// one or more imports in that safe prefix were omitted at
/// [`MAX_MODULE_IMPORTS`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModuleImportReport {
    pub imports: Vec<ModuleImport>,
    pub truncated: bool,
    pub valid_prefix_end_byte: usize,
}

/// One field declared directly by a statically recognized record literal.
///
/// This is advisory editor metadata only. It does not establish a runtime
/// field type, evaluate its value, or prove that a later mutation preserves
/// the field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticRecordField {
    pub name: String,
    pub definition: SourceSpan,
}

/// Fields and child shapes of one exact nested literal-record field.
///
/// `field` identifies the outer field whose entire source value is a record
/// literal. `direct_field_shapes` retains the next literal level only while the
/// fixed [`MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH`] budget remains. This does
/// not model computed values, parenthesized records, or deeper paths beyond
/// that bound. Exact child aliases are represented separately by
/// [`StaticRecordAlias`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticRecordNestedShape {
    pub field: StaticRecordField,
    pub fields: Vec<StaticRecordField>,
    pub direct_field_shapes: Vec<StaticRecordNestedShape>,
}

/// One direct `let name = { ... }` literal-record shape.
///
/// `binding` is the exact declaration identifier span. Shapes are collected
/// only for a whole direct literal initializer, never aliases, expressions,
/// function returns, imported values, or runtime results. `direct_field_shapes`
/// retains exact nested child-literal levels only through
/// [`MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH`] when every represented parent
/// record has unique field names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticRecordShape {
    pub binding: SourceSpan,
    pub fields: Vec<StaticRecordField>,
    pub direct_field_shapes: Vec<StaticRecordNestedShape>,
}

/// One exact direct `let alias = target`, `let alias = target.child`, or
/// `let alias = target.child.grandchild` source alias edge.
///
/// `binding` and `target` identify canonical identifiers in one complete
/// initializer. When present, `direct_child` identifies the first direct member
/// selected from `target`; `direct_grandchild` is present only with that first
/// selector and identifies its exact second direct member. They never represent
/// a computed or deeper path. This is source-only metadata: it does not resolve
/// the target, prove that it is a record, infer a value type, or authorize any
/// runtime behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticRecordAlias {
    pub binding: SourceSpan,
    pub target: SourceSpan,
    pub direct_child: Option<SourceSpan>,
    pub direct_grandchild: Option<SourceSpan>,
}

/// Bounded static literal-record metadata for one source snapshot.
///
/// The report is intentionally not general type inference. It retains completed
/// direct record literals, their bounded exact nested child literals, and exact
/// direct root, child, or grandchild alias edges ending at or before
/// `valid_prefix_end_byte`,
/// allowing editor features to remain useful before a trailing syntax diagnostic
/// without assigning meaning to later recovery tokens. `truncated` means one or
/// more complete shapes were omitted at the fixed shape or aggregate-field
/// bound.
/// `aliases_truncated` means one or more direct alias edges were omitted at
/// [`MAX_STATIC_RECORD_ALIASES`]; consumers that need whole-alias-group
/// stability must fail closed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StaticRecordShapeReport {
    pub shapes: Vec<StaticRecordShape>,
    pub aliases: Vec<StaticRecordAlias>,
    pub truncated: bool,
    pub aliases_truncated: bool,
    pub valid_prefix_end_byte: usize,
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

/// A bounded, scope-resolved hint for an exact direct member call on a visible
/// `use mod.<path>` binding or its bounded exact local root-alias chain.
///
/// `module_path` is the source import path, including its initial `"mod"`
/// segment. The callee span covers the direct `binding.method` spelling. This
/// is source metadata only: it does not load the import, prove the module is
/// installed, or grant the method any authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedModuleCallHint {
    pub module_path: Vec<String>,
    pub method: String,
    pub line: usize,
    pub column: usize,
    pub callee_start_byte: usize,
    pub callee_end_byte: usize,
}

/// Bounded direct imported-module member-call review output.
///
/// `truncated` is true when additional matching sites were omitted or when
/// the bounded lexical/import/alias metadata cannot resolve the complete
/// source.
/// Callers must treat that state as incomplete. The report is advisory and is
/// never an authorization decision.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportedModuleCallHintReport {
    pub hints: Vec<ImportedModuleCallHint>,
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
    json_method_limits: Rc<Cell<ScriptJsonMethodLimits>>,
}

impl<H: Any, S: Any> Runtime<H, S> {
    pub fn new(host: H, std: S) -> Result<Self, RuntimeError> {
        Self::with_limits(host, std, ExecutionLimits::default())
    }

    pub fn with_limits(host: H, std: S, limits: ExecutionLimits) -> Result<Self, RuntimeError> {
        let limits = limits.validate()?;
        let json_method_limits = Rc::new(Cell::new(ScriptJsonMethodLimits::from_execution_limits(
            limits,
        )));
        let installed_limits = json_method_limits.clone();
        let mut runtime = Self {
            host,
            std,
            vm: Box::new(vm::ScriptVmBase::new()),
            limits,
            json_method_limits,
        };
        runtime.with_vm(|vm| {
            vm.bx
                .heap
                .set_max_string_bytes(Some(limits.max_string_bytes));
            restrict_vendored_module_surface(vm, installed_limits.clone());
            install_bounded_json_methods(vm, installed_limits);
            // This fixed, trusted setup must complete before an exact retained
            // heap cap is enabled. Otherwise a temporary collection growth can
            // make a cap equal to the final bootstrap baseline fail and leave
            // the VM partially configured. No generated source runs before
            // the cap is installed below.
            vm.bx.heap.set_max_heap_bytes(Some(limits.max_heap_bytes));
            let actual = vm.bx.heap.accounted_heap_bytes();
            let heap_limit_exceeded = vm.bx.heap.take_heap_limit_exceeded();
            let string_limit_exceeded = vm.bx.heap.take_string_limit_exceeded();
            if heap_limit_exceeded || actual > limits.max_heap_bytes {
                return Err(RuntimeError::HeapLimitExceeded {
                    actual,
                    maximum: limits.max_heap_bytes,
                });
            }
            if string_limit_exceeded {
                return Err(RuntimeError::StringLimitExceeded {
                    maximum: limits.max_string_bytes,
                });
            }
            Ok(())
        })?;
        Ok(runtime)
    }

    pub fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    /// Replaces the host-selected execution bounds for later evaluations.
    ///
    /// A paused continuation retains the limits it started with. Changing
    /// them while it waits could widen or weaken the resource contract after
    /// an `await` or cooperative time-budget yield, so the update is refused
    /// until that continuation reaches a terminal state.
    pub fn set_limits(&mut self, limits: ExecutionLimits) -> Result<(), RuntimeError> {
        let limits = limits.validate()?;
        if self.with_vm(|vm| has_paused_thread(vm)) {
            return Err(RuntimeError::EvaluationInProgress);
        }
        let actual = self.with_vm(|vm| {
            vm.bx.heap.reconcile_heap_bytes();
            vm.bx.heap.accounted_heap_bytes()
        });
        if actual > limits.max_heap_bytes {
            return Err(RuntimeError::HeapLimitExceeded {
                actual,
                maximum: limits.max_heap_bytes,
            });
        }
        self.with_vm(|vm| {
            vm.bx
                .heap
                .set_max_string_bytes(Some(limits.max_string_bytes));
            vm.bx.heap.set_max_heap_bytes(Some(limits.max_heap_bytes));
        });
        self.limits = limits;
        self.json_method_limits
            .set(ScriptJsonMethodLimits::from_execution_limits(limits));
        Ok(())
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// Installs trusted native bindings. The standalone `std` module is frozen,
    /// so setup code should use a distinct host-owned module rather than
    /// extending the core surface. Do not expose ambient OS APIs here;
    /// effectful bindings must apply their own capability policy.
    pub fn configure(&mut self, configure: impl FnOnce(&mut vm::ScriptVm)) {
        self.with_vm(configure);
        let max_string_bytes = self.limits.max_string_bytes;
        let max_heap_bytes = self.limits.max_heap_bytes;
        self.with_vm(|vm| {
            vm.bx.heap.set_max_string_bytes(Some(max_string_bytes));
            vm.bx.heap.set_max_heap_bytes(Some(max_heap_bytes));
        });
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
        let max_string_bytes = self.limits.max_string_bytes;
        let max_heap_bytes = self.limits.max_heap_bytes;
        self.with_vm(|vm| {
            if has_paused_thread(vm) {
                return Err(RuntimeError::EvaluationInProgress);
            }
            let mut parser = vm::json::JsonParserThread::default();
            let value = parser.read_json(&encoded, &mut vm.bx.heap);
            vm.bx.heap.reconcile_heap_bytes();
            let actual = vm.bx.heap.accounted_heap_bytes();
            let heap_limit_exceeded = vm.bx.heap.take_heap_limit_exceeded();
            let string_limit_exceeded = vm.bx.heap.take_string_limit_exceeded();
            if heap_limit_exceeded || actual > max_heap_bytes {
                return Err(RuntimeError::HeapLimitExceeded {
                    actual,
                    maximum: max_heap_bytes,
                });
            }
            if string_limit_exceeded {
                return Err(RuntimeError::StringLimitExceeded {
                    maximum: max_string_bytes,
                });
            }
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
            .with_vm(|vm| encode_bounded_script_json(vm, value, max_bytes, max_depth))
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

    /// Lists bounded exact member calls on visible `use mod.<path>` bindings
    /// without evaluating bytecode, loading a module, or entering a host
    /// binding. This is advisory source metadata only.
    pub fn imported_module_call_hint_report(
        &self,
        source: &str,
    ) -> Result<ImportedModuleCallHintReport, RuntimeError> {
        imported_module_call_hint_report_named("inline.splash", source, self.limits)
    }

    /// Builds bounded source-only import metadata without evaluating bytecode,
    /// loading a module, or entering any host binding.
    pub fn module_import_report(&self, source: &str) -> Result<ModuleImportReport, RuntimeError> {
        module_import_report_named("inline.splash", source, self.limits)
    }

    /// Builds bounded direct literal-record and direct alias metadata without
    /// evaluating bytecode, resolving imports, or entering any host binding.
    ///
    /// This is advisory editor metadata only. It reports exact direct
    /// `let binding = { ... }` initializers plus `let alias = target`,
    /// `let alias = target.child`, or `let alias = target.child.grandchild`
    /// source edges, but never resolves an alias or infers mutation, types, or
    /// runtime values.
    pub fn static_record_shape_report(
        &self,
        source: &str,
    ) -> Result<StaticRecordShapeReport, RuntimeError> {
        static_record_shape_report_named("inline.splash", source, self.limits)
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
    /// Canonical statement-ending newlines are lowered to explicit VM
    /// separators before evaluation, preserving the portable grammar even
    /// though the inherited streaming tokenizer treats newlines as whitespace.
    ///
    /// This is the normal execution entry point for generated and user-authored
    /// source. Use [`Self::eval_vm_compatibility`] only for a trusted host that
    /// deliberately needs a Makepad compatibility construct outside Splash.
    pub fn eval(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        let report = self.check_syntax(source)?;
        if !report.valid {
            return Err(RuntimeError::SyntaxRejected(report));
        }
        let vm_source = lower_canonical_source_with_validated_limits(source, self.limits)?;
        self.eval_preflighted(&vm_source)
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
            vm.bx.heap.reconcile_heap_bytes();
            let actual = vm.bx.heap.accounted_heap_bytes();
            if actual > limits.max_heap_bytes {
                return Err(RuntimeError::HeapLimitExceeded {
                    actual,
                    maximum: limits.max_heap_bytes,
                });
            }
            // A new evaluation has no active VM instruction that could own a
            // previously raised flag. Once retained storage fits the current
            // limit, discard stale resource signals before starting fresh code.
            vm.bx.heap.take_heap_limit_exceeded();
            vm.bx.heap.take_string_limit_exceeded();
            // Keep the public runtime single-flight. The underlying VM can
            // manage several threads, but evaluating new source into a paused
            // frame would make its module/body lifecycle ambiguous.
            vm.bx.threads.set_current_to_first_unpaused_thread();
            vm.clear_execution_limit_failures();
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
    /// GC roots and are safe to collect around. When collection reduces tracked
    /// retained storage below the configured limit, it also clears a stale
    /// heap-limit signal from the completed evaluation that exceeded it.
    pub fn collect_garbage(&mut self) {
        let max_heap_bytes = self.limits.max_heap_bytes;
        self.with_vm(|vm| {
            vm.gc();
            vm.bx.heap.reconcile_heap_bytes();
            if vm.bx.heap.accounted_heap_bytes() <= max_heap_bytes {
                // A heap-cap failure is uncatchable inside the evaluation that
                // raised it. GC is a host scheduling boundary, so once the
                // retained state fits again the next evaluation may proceed.
                vm.bx.heap.take_heap_limit_exceeded();
            }
        });
    }

    /// Returns the currently accounted retained capacity of Splash-owned VM
    /// heap data. This is useful for host telemetry and choosing a target
    /// budget; it is not a process-wide allocator measurement.
    pub fn accounted_heap_bytes(&mut self) -> usize {
        self.with_vm(|vm| {
            vm.bx.heap.reconcile_heap_bytes();
            vm.bx.heap.accounted_heap_bytes()
        })
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

/// Builds bounded source-only import metadata without evaluating source,
/// loading a module, or creating a capability host.
///
/// Complete imports before the first diagnostic remain available to support
/// conservative editor completion on an incomplete trailing expression. This
/// is not module resolution: a reported path does not imply that a module,
/// capability, or Rust adapter exists.
pub fn module_import_report(source: &str) -> Result<ModuleImportReport, RuntimeError> {
    module_import_report_named("inline.splash", source, ExecutionLimits::default())
}

/// Builds bounded advisory shapes for direct literal-record bindings and exact
/// direct alias edges without evaluating source, resolving imports, or creating
/// a capability host.
///
/// Only a complete `let name = { ... }` initializer and exact
/// `let alias = target`, `let alias = target.child`, or
/// `let alias = target.child.grandchild` edge are retained. This is not general
/// type inference and never resolves an alias or follows parenthesized/computed
/// aliases, assignments, function returns, imported values, or runtime data.
/// For invalid source, only metadata ending before the first syntax diagnostic
/// is retained.
pub fn static_record_shape_report(source: &str) -> Result<StaticRecordShapeReport, RuntimeError> {
    static_record_shape_report_named("inline.splash", source, ExecutionLimits::default())
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

/// Lists bounded exact member calls on visible `use mod.<path>` bindings and
/// their bounded exact local root-alias chains in valid canonical Splash
/// without evaluating source, loading a module, or creating a capability host.
///
/// This is an LLM and operator-review aid, not static authorization. It
/// resolves only a visible lexical import binding or an exact
/// `let alias = binding` chain of at most [`MAX_IMPORTED_MODULE_ALIAS_DEPTH`]
/// hops. It rejects aliases after writes or other potential escapes and never
/// infers computed receivers, member aliases, module exports, method types,
/// control flow, reachability, or runtime values. Invalid or VM-incompatible
/// source produces no hints. `truncated` means the result is incomplete,
/// either because matching sites exceeded [`MAX_IMPORTED_MODULE_CALL_HINTS`]
/// or the bounded lexical/import/alias metadata could not resolve every site.
pub fn imported_module_call_hint_report(
    source: &str,
) -> Result<ImportedModuleCallHintReport, RuntimeError> {
    imported_module_call_hint_report_named("inline.splash", source, ExecutionLimits::default())
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
/// Splash v0.2 grammar. It lowers validated canonical statement-ending
/// newlines to explicit VM separators before the same bounded vendored-VM
/// preflight used by [`check_vm_compatibility_named`]. `file` appears only in
/// VM-parser diagnostics. It never loads a module, resolves an import, runs
/// bytecode, or invokes a host tool.
pub fn check_syntax_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<SyntaxReport, RuntimeError> {
    let limits = limits.validate()?;
    validate_source_length(source, limits)?;
    let lowered = match lower_canonical_source_for_vm(
        source,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
    ) {
        Ok(lowered) => lowered,
        Err(profile) => return Ok(syntax_report_from_profile(profile)),
    };

    Ok(check_vm_syntax_with_validated_limits(
        file,
        &lowered.source,
        vm_limits_after_canonical_lowering(limits, lowered.inserted_statement_separators),
    ))
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
    let valid_prefix_end_byte = source_metadata_prefix_end_byte(source, &syntax, limits);

    Ok(collect_lexical_completions(
        source,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
        valid_prefix_end_byte,
    ))
}

/// Builds bounded source-only import metadata for one named source snapshot.
///
/// The collector applies the same source, token, nesting, canonical-profile,
/// and vendored-parser checks as [`check_syntax_named`] but never evaluates
/// source, loads an import, or creates a capability host. For incomplete
/// source it retains only complete imports ending at or before the first
/// syntax diagnostic, as recorded by [`ModuleImportReport::valid_prefix_end_byte`].
/// A reported `use mod.<path>` declaration is not proof that the path exists
/// or is permitted at runtime.
pub fn module_import_report_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<ModuleImportReport, RuntimeError> {
    let syntax = check_syntax_named(file, source, limits)?;
    let valid_prefix_end_byte = source_metadata_prefix_end_byte(source, &syntax, limits);

    Ok(collect_module_imports(
        source,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
        valid_prefix_end_byte,
    ))
}

/// Builds bounded static metadata for complete direct literal-record bindings
/// and exact direct alias edges in named canonical source without evaluating
/// it, resolving document URIs, or loading an import.
///
/// A retained shape proves only that the source directly initialized that
/// binding with a record literal before `valid_prefix_end_byte`. An optional
/// retained child shape proves only that one direct field's whole value was a
/// record literal. A retained alias proves only the exact source spelling
/// `let alias = target`, `let alias = target.child`, or
/// `let alias = target.child.grandchild`; it does not resolve the target.
/// Neither metadata kind infers a field value type, mutation, function return,
/// or runtime value, and neither can authorize an effect or module access.
pub fn static_record_shape_report_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<StaticRecordShapeReport, RuntimeError> {
    let syntax = check_syntax_named(file, source, limits)?;
    let valid_prefix_end_byte = source_metadata_prefix_end_byte(source, &syntax, limits);

    Ok(collect_static_record_shapes(
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

/// Lists bounded exact member calls on visible `use mod.<path>` bindings in
/// named canonical Splash source.
///
/// This applies the same source, token, nesting, canonical-profile, and
/// vendored parser-compatibility checks as [`check_syntax_named`]. It reports
/// no hints for invalid source, never loads an import or resolves a runtime
/// module, and cannot grant authority. Hosts must still validate every actual
/// operation at their capability boundary.
pub fn imported_module_call_hint_report_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<ImportedModuleCallHintReport, RuntimeError> {
    let limits = limits.validate()?;
    let syntax = check_syntax_named(file, source, limits)?;
    if !syntax.valid {
        return Ok(ImportedModuleCallHintReport::default());
    }

    let imports = collect_module_imports(
        source,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
        source.len(),
    );
    let symbols =
        collect_lexical_symbols(source, limits.max_syntax_tokens, limits.max_syntax_nesting);
    let aliases = collect_static_record_shapes(
        source,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
        source.len(),
    );
    Ok(collect_imported_module_call_hints(
        source,
        limits.max_syntax_tokens,
        &symbols,
        &imports,
        &aliases,
    ))
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

#[cfg(fuzzing)]
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

fn lower_canonical_source_with_validated_limits(
    source: &str,
    limits: ExecutionLimits,
) -> Result<String, RuntimeError> {
    match lower_canonical_source_for_vm(source, limits.max_syntax_tokens, limits.max_syntax_nesting)
    {
        Ok(lowered) => Ok(lowered.source),
        Err(profile) => Err(RuntimeError::SyntaxRejected(syntax_report_from_profile(
            profile,
        ))),
    }
}

fn syntax_report_from_profile(profile: ProfileReport) -> SyntaxReport {
    SyntaxReport {
        valid: false,
        diagnostics: profile.diagnostics,
        diagnostics_truncated: profile.diagnostics_truncated,
    }
}

fn vm_limits_after_canonical_lowering(
    limits: ExecutionLimits,
    inserted_statement_separators: usize,
) -> ExecutionLimits {
    ExecutionLimits {
        max_syntax_tokens: limits
            .max_syntax_tokens
            .saturating_add(inserted_statement_separators),
        ..limits
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

fn valid_prefix_end_byte(source: &str, syntax: &SyntaxReport) -> usize {
    if syntax.valid {
        return source.len();
    }
    if syntax.diagnostics.is_empty() {
        return 0;
    }

    syntax
        .diagnostics
        .iter()
        .try_fold(source.len(), |first_byte, diagnostic| {
            source_byte_at_position(source, diagnostic.line, diagnostic.column)
                .map(|byte| first_byte.min(byte))
        })
        .unwrap_or(0)
}

fn source_metadata_prefix_end_byte(
    source: &str,
    syntax: &SyntaxReport,
    limits: ExecutionLimits,
) -> usize {
    if syntax.valid {
        return source.len();
    }

    let syntax_prefix_end_byte = valid_prefix_end_byte(source, syntax);
    if syntax_prefix_end_byte == 0 {
        return 0;
    }

    syntax_prefix_end_byte.min(canonical_parser_prefix_end_byte(
        source,
        limits.max_syntax_tokens,
        limits.max_syntax_nesting,
    ))
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

/// Encodes a Splash value as bounded JSON for a trusted native binding.
///
/// This uses the same finite-number, object-key, cycle, depth, and byte
/// checks as [`Runtime::script_value_as_json`] without exposing an unbounded
/// VM serializer. It is data conversion only: callers must still apply their
/// own capability policy before they use the result for an effect.
pub fn encode_bounded_script_json(
    vm: &mut vm::ScriptVm,
    value: vm::ScriptValue,
    max_bytes: usize,
    max_depth: usize,
) -> Result<String, RuntimeJsonError> {
    if max_bytes == 0 || max_depth == 0 {
        return Err(RuntimeJsonError::InvalidLimit);
    }
    let mut writer = BoundedJsonWriter::new(max_bytes);
    write_script_json(vm, value, max_depth, &mut Vec::new(), &mut writer)?;
    Ok(writer.into_string())
}

/// Decodes bounded JSON into a Splash value for a trusted native binding.
///
/// The JSON is parsed and re-encoded through Splash's bounded host-data
/// boundary before the vendored VM materializes it. This prevents a native
/// binding from bypassing the runtime's JSON byte or nesting limits. Decoding
/// data does not load a module or grant a capability.
pub fn decode_bounded_script_json(
    vm: &mut vm::ScriptVm,
    document: &str,
    max_bytes: usize,
    max_depth: usize,
) -> Result<vm::ScriptValue, RuntimeJsonError> {
    let value = parse_bounded_json(document, max_bytes, max_depth)?;
    let encoded = serialize_bounded_json(&value, max_bytes, max_depth)?;
    let mut parser = vm::json::JsonParserThread::default();
    Ok(parser.read_json(&encoded, &mut vm.bx.heap))
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

    let value = vm.with_stack_value_limit(limits.max_stack_values, |vm| {
        vm.with_call_frame_limit(limits.max_call_frames, |vm| {
            vm.with_instruction_limit(limits.instruction_limit, operation)
        })
    });
    let diagnostics = vm.take_errors();
    let suspended = vm.bx.threads.cur_ref().is_paused();
    vm.bx.run_budget = None;

    Evaluation {
        value,
        diagnostics,
        suspended,
    }
}

/// Removes inherited Makepad UI, debug, and unbounded native entry points from
/// the standalone Splash source surface. The VM still constructs its upstream
/// bootstrap objects, but generated Splash can reach only the retained core and
/// modules installed by trusted Rust setup code.
fn restrict_vendored_module_surface(
    vm: &mut vm::ScriptVm,
    json_method_limits: Rc<Cell<ScriptJsonMethodLimits>>,
) {
    let modules = vm.bx.heap.modules;
    for module in [id!(math), id!(gc), id!(pod), id!(shader)] {
        vm.bx
            .heap
            .set_value_def(modules, module.into(), ScriptValue::NIL);
    }

    let std = vm.bx.heap.module(id!(std));
    for member in [
        id!(log),
        id!(print),
        id!(println),
        id!(regex),
        id!(set_type_default),
    ] {
        vm.bx
            .heap
            .set_value_def(std, member.into(), ScriptValue::NIL);
    }
    restrict_vendored_primitive_method_surface(vm);
    install_standard_math_module(vm, std);
    install_standard_json_module(vm, std, json_method_limits);
    install_standard_text_module(vm, std);
    install_standard_array_module(vm, std);
    install_standard_object_module(vm, std);
    // Retained Splash core values and the VM-internal `Range` prototype are
    // setup-owned language primitives, not mutable cross-evaluation points.
    vm.bx.heap.freeze(std);
    vm.bx.heap.freeze(vm.bx.code.builtins.range);
}

/// Clears every primitive type method inherited from Makepad before Splash
/// installs its own documented data boundary. This is an allowlist boundary:
/// upstream additions cannot become source-reachable merely because the VM
/// bootstrap registered them.
fn restrict_vendored_primitive_method_surface(vm: &mut vm::ScriptVm) {
    let primitive_types = [
        vm::ScriptValueType::REDUX_NUMBER,
        vm::ScriptValueType::REDUX_NAN,
        vm::ScriptValueType::REDUX_BOOL,
        vm::ScriptValueType::REDUX_NIL,
        vm::ScriptValueType::REDUX_COLOR,
        vm::ScriptValueType::REDUX_STRING,
        vm::ScriptValueType::REDUX_OBJECT,
        vm::ScriptValueType::REDUX_ARRAY,
        vm::ScriptValueType::REDUX_POD,
        vm::ScriptValueType::REDUX_POD_TYPE,
        vm::ScriptValueType::REDUX_REGEX,
        vm::ScriptValueType::REDUX_OPCODE,
        vm::ScriptValueType::REDUX_ERR,
        vm::ScriptValueType::REDUX_ID,
    ];
    let mut native = vm.bx.code.native.borrow_mut();
    for value_type in primitive_types {
        native.clear_type_methods(value_type);
    }
}

/// Installs a small Splash-owned scalar math module without restoring the
/// broader Makepad shader module that used the same root name.
fn install_standard_math_module(vm: &mut vm::ScriptVm, std_module: ScriptObject) {
    let math = vm.bx.heap.new_with_proto(NIL);
    vm.add_method(math, id!(abs), script_args_def!(value = NIL), |vm, args| {
        standard_math_unary(vm, args, "abs", f64::abs)
    });
    vm.add_method(
        math,
        id!(ceil),
        script_args_def!(value = NIL),
        |vm, args| standard_math_unary(vm, args, "ceil", f64::ceil),
    );
    vm.add_method(
        math,
        id!(floor),
        script_args_def!(value = NIL),
        |vm, args| standard_math_unary(vm, args, "floor", f64::floor),
    );
    vm.add_method(
        math,
        id!(round),
        script_args_def!(value = NIL),
        |vm, args| standard_math_unary(vm, args, "round", f64::round),
    );
    vm.add_method(
        math,
        id!(sqrt),
        script_args_def!(value = NIL),
        |vm, args| standard_math_unary(vm, args, "sqrt", f64::sqrt),
    );
    vm.add_method(math, id!(sin), script_args_def!(value = NIL), |vm, args| {
        standard_math_unary(vm, args, "sin", f64::sin)
    });
    vm.add_method(math, id!(cos), script_args_def!(value = NIL), |vm, args| {
        standard_math_unary(vm, args, "cos", f64::cos)
    });
    vm.add_method(math, id!(tan), script_args_def!(value = NIL), |vm, args| {
        standard_math_unary(vm, args, "tan", f64::tan)
    });
    vm.add_method(math, id!(exp), script_args_def!(value = NIL), |vm, args| {
        standard_math_unary(vm, args, "exp", f64::exp)
    });
    vm.add_method(math, id!(ln), script_args_def!(value = NIL), |vm, args| {
        standard_math_unary(vm, args, "ln", f64::ln)
    });
    vm.add_method(
        math,
        id!(log10),
        script_args_def!(value = NIL),
        |vm, args| standard_math_unary(vm, args, "log10", f64::log10),
    );
    vm.add_method(
        math,
        id!(pow),
        script_args_def!(base = NIL, exponent = NIL),
        |vm, args| {
            standard_math_binary(
                vm,
                args,
                "pow",
                StandardMathBinaryParameters {
                    left: (id!(base), "base"),
                    right: (id!(exponent), "exponent"),
                },
                f64::powf,
            )
        },
    );
    vm.add_method(
        math,
        id!(min),
        script_args_def!(left = NIL, right = NIL),
        |vm, args| {
            standard_math_binary(
                vm,
                args,
                "min",
                StandardMathBinaryParameters {
                    left: (id!(left), "left"),
                    right: (id!(right), "right"),
                },
                f64::min,
            )
        },
    );
    vm.add_method(
        math,
        id!(max),
        script_args_def!(left = NIL, right = NIL),
        |vm, args| {
            standard_math_binary(
                vm,
                args,
                "max",
                StandardMathBinaryParameters {
                    left: (id!(left), "left"),
                    right: (id!(right), "right"),
                },
                f64::max,
            )
        },
    );
    vm.add_method(
        math,
        id!(atan2),
        script_args_def!(y = NIL, x = NIL),
        |vm, args| {
            standard_math_binary(
                vm,
                args,
                "atan2",
                StandardMathBinaryParameters {
                    left: (id!(y), "y"),
                    right: (id!(x), "x"),
                },
                f64::atan2,
            )
        },
    );
    vm.add_method(
        math,
        id!(clamp),
        script_args_def!(value = NIL, minimum = NIL, maximum = NIL),
        standard_math_clamp,
    );

    vm.bx.heap.set_value_def(
        math,
        id!(pi).into(),
        ScriptValue::from_f64(std::f64::consts::PI),
    );
    vm.bx.heap.set_value_def(
        math,
        id!(e).into(),
        ScriptValue::from_f64(std::f64::consts::E),
    );
    vm.bx
        .heap
        .set_value_def(std_module, id!(math).into(), math.into());
    vm.bx.heap.freeze(math);
}

/// Installs a small Splash-owned JSON module that reuses the same bounded
/// reader and writer as the existing `parse_json()` and `to_json()` methods.
/// It adds no host lookup, filesystem, network, or adapter access.
fn install_standard_json_module(
    vm: &mut vm::ScriptVm,
    std_module: ScriptObject,
    limits: Rc<Cell<ScriptJsonMethodLimits>>,
) {
    let json = vm.bx.heap.new_with_proto(NIL);
    let parse_limits = limits.clone();
    vm.add_method(
        json,
        id!(parse),
        script_args_def!(document = NIL),
        move |vm, args| {
            bounded_json_parse_value(vm, script_value!(vm, args.document), parse_limits.get())
        },
    );
    vm.add_method(
        json,
        id!(stringify),
        script_args_def!(value = NIL),
        move |vm, args| {
            bounded_json_stringify_value(vm, script_value!(vm, args.value), limits.get())
        },
    );
    vm.bx
        .heap
        .set_value_def(std_module, id!(json).into(), json.into());
    vm.bx.heap.freeze(json);
}

/// Installs the compact, pure text surface for local workflow data shaping.
/// Every constructed result uses the VM's bounded string builder, and this
/// module has no regex, host, filesystem, network, or adapter access.
fn install_standard_text_module(vm: &mut vm::ScriptVm, std_module: ScriptObject) {
    let text = vm.bx.heap.new_with_proto(NIL);
    vm.add_method(
        text,
        id!(trim),
        script_args_def!(value = NIL),
        standard_text_trim,
    );
    vm.add_method(
        text,
        id!(lower),
        script_args_def!(value = NIL),
        standard_text_lower,
    );
    vm.add_method(
        text,
        id!(upper),
        script_args_def!(value = NIL),
        standard_text_upper,
    );
    vm.add_method(
        text,
        id!(len),
        script_args_def!(value = NIL),
        standard_text_len,
    );
    vm.add_method(
        text,
        id!(slice),
        script_args_def!(value = NIL, start = NIL, end = NIL),
        standard_text_slice,
    );
    vm.add_method(
        text,
        id!(index_of),
        script_args_def!(value = NIL, needle = NIL),
        standard_text_index_of,
    );
    vm.add_method(
        text,
        id!(last_index_of),
        script_args_def!(value = NIL, needle = NIL),
        standard_text_last_index_of,
    );
    vm.add_method(
        text,
        id!(contains),
        script_args_def!(value = NIL, needle = NIL),
        |vm, args| {
            let needle = script_value!(vm, args.needle);
            standard_text_binary_predicate(
                vm,
                args,
                "contains",
                needle,
                "needle",
                |value, needle| value.contains(needle),
            )
        },
    );
    vm.add_method(
        text,
        id!(starts_with),
        script_args_def!(value = NIL, prefix = NIL),
        |vm, args| {
            let prefix = script_value!(vm, args.prefix);
            standard_text_binary_predicate(
                vm,
                args,
                "starts_with",
                prefix,
                "prefix",
                |value, prefix| value.starts_with(prefix),
            )
        },
    );
    vm.add_method(
        text,
        id!(ends_with),
        script_args_def!(value = NIL, suffix = NIL),
        |vm, args| {
            let suffix = script_value!(vm, args.suffix);
            standard_text_binary_predicate(
                vm,
                args,
                "ends_with",
                suffix,
                "suffix",
                |value, suffix| value.ends_with(suffix),
            )
        },
    );
    vm.add_method(
        text,
        id!(replace_all),
        script_args_def!(value = NIL, from = NIL, to = NIL),
        standard_text_replace_all,
    );
    vm.add_method(
        text,
        id!(split),
        script_args_def!(value = NIL, delimiter = NIL),
        standard_text_split,
    );
    vm.add_method(
        text,
        id!(join),
        script_args_def!(values = NIL, separator = NIL),
        standard_text_join,
    );
    vm.bx
        .heap
        .set_value_def(std_module, id!(text).into(), text.into());
    vm.bx.heap.freeze(text);
}

fn standard_text_trim(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    match vm.string_with(value, |vm, value| {
        vm.bx.heap.new_string_from_str(value.trim())
    }) {
        Some(result) => result,
        None => standard_text_expected_string(vm, "trim", "value"),
    }
}

fn standard_text_lower(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    standard_text_case(vm, args, "lower", char::to_lowercase)
}

fn standard_text_upper(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    standard_text_case(vm, args, "upper", char::to_uppercase)
}

fn standard_text_case<I>(
    vm: &mut vm::ScriptVm,
    args: ScriptObject,
    function: &'static str,
    map: impl Fn(char) -> I,
) -> ScriptValue
where
    I: IntoIterator<Item = char>,
{
    let value = script_value!(vm, args.value);
    match vm.string_with(value, |vm, value| {
        vm.bx.heap.new_bounded_string_with(|_, output| {
            'characters: for character in value.chars() {
                for mapped in map(character) {
                    output.append_char(mapped);
                    if output.is_full() {
                        break 'characters;
                    }
                }
            }
        })
    }) {
        Some(result) => result,
        None => standard_text_expected_string(vm, function, "value"),
    }
}

fn standard_text_len(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    match vm.string_with(value, |_, value| value.chars().count()) {
        Some(length) => ScriptValue::from_f64(length as f64),
        None => standard_text_expected_string(vm, "len", "value"),
    }
}

fn standard_text_slice(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let start = script_value!(vm, args.start);
    let end = script_value!(vm, args.end);
    if vm.string_with(value, |_, _| ()).is_none() {
        return standard_text_expected_string(vm, "slice", "value");
    }
    let start = match standard_text_scalar_index(vm, start, "slice", "start") {
        Ok(index) => index,
        Err(error) => return error,
    };
    let end = match standard_text_scalar_index(vm, end, "slice", "end") {
        Ok(index) => index,
        Err(error) => return error,
    };

    match vm.string_with(value, |vm, value| {
        let length = value.chars().count();
        if start > end || end > length {
            return None;
        }
        let start_byte = standard_text_scalar_byte_index(value, start, length)?;
        let end_byte = standard_text_scalar_byte_index(value, end, length)?;
        Some(vm.bx.heap.new_string_from_str(&value[start_byte..end_byte]))
    }) {
        Some(Some(result)) => result,
        Some(None) => standard_text_slice_range(vm),
        None => standard_text_expected_string(vm, "slice", "value"),
    }
}

fn standard_text_index_of(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    standard_text_literal_index(vm, args, "index_of", |value, needle| value.find(needle))
}

fn standard_text_last_index_of(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    standard_text_literal_index(vm, args, "last_index_of", |value, needle| {
        value.rfind(needle)
    })
}

fn standard_text_literal_index(
    vm: &mut vm::ScriptVm,
    args: ScriptObject,
    function: &'static str,
    search: impl FnOnce(&str, &str) -> Option<usize>,
) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let needle = script_value!(vm, args.needle);
    match vm.string_with(value, |vm, value| {
        vm.string_with(needle, |_, needle| {
            search(value, needle)
                .map(|byte_index| value[..byte_index].chars().count() as f64)
                .unwrap_or(-1.0)
        })
    }) {
        Some(Some(index)) => ScriptValue::from_f64(index),
        Some(None) => standard_text_expected_string(vm, function, "needle"),
        None => standard_text_expected_string(vm, function, "value"),
    }
}

fn standard_text_scalar_index(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
    function: &'static str,
    parameter: &'static str,
) -> Result<usize, ScriptValue> {
    let Some(value) = value.as_number() else {
        return Err(standard_text_expected_scalar_index(vm, function, parameter));
    };
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > usize::MAX as f64 {
        return Err(standard_text_expected_scalar_index(vm, function, parameter));
    }
    Ok(value as usize)
}

fn standard_text_scalar_byte_index(value: &str, index: usize, length: usize) -> Option<usize> {
    if index == length {
        return Some(value.len());
    }
    value.char_indices().nth(index).map(|(offset, _)| offset)
}

fn standard_text_expected_scalar_index(
    vm: &mut vm::ScriptVm,
    function: &'static str,
    parameter: &'static str,
) -> ScriptValue {
    script_err_invalid_args!(
        vm.bx.threads.cur_ref().trap,
        "std.text.{function} expects `{parameter}` to be a non-negative integer"
    )
}

fn standard_text_slice_range(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_invalid_args!(
        vm.bx.threads.cur_ref().trap,
        "std.text.slice requires `start` <= `end` <= text length"
    )
}

fn standard_text_binary_predicate(
    vm: &mut vm::ScriptVm,
    args: ScriptObject,
    function: &'static str,
    pattern: ScriptValue,
    pattern_name: &'static str,
    predicate: impl FnOnce(&str, &str) -> bool,
) -> ScriptValue {
    let value = script_value!(vm, args.value);
    match vm.string_with(value, |vm, value| {
        vm.string_with(pattern, |_, pattern| predicate(value, pattern))
    }) {
        Some(Some(result)) => result.into(),
        Some(None) => standard_text_expected_string(vm, function, pattern_name),
        None => standard_text_expected_string(vm, function, "value"),
    }
}

fn standard_text_replace_all(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let from = script_value!(vm, args.from);
    let to = script_value!(vm, args.to);
    match vm.string_with(value, |vm, value| {
        vm.string_with(from, |vm, from| {
            vm.string_with(to, |vm, to| {
                vm.bx.heap.new_bounded_string_with(|_, output| {
                    let mut first = true;
                    for segment in value.split(from) {
                        if !first {
                            output.append_str(to);
                            if output.is_full() {
                                break;
                            }
                        }
                        output.append_str(segment);
                        if output.is_full() {
                            break;
                        }
                        first = false;
                    }
                })
            })
        })
    }) {
        Some(Some(Some(result))) => result,
        _ => standard_text_expected_string(vm, "replace_all", "value, from, and to"),
    }
}

fn standard_text_split(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let delimiter = script_value!(vm, args.delimiter);
    match vm.string_with(value, |vm, value| {
        vm.string_with(delimiter, |vm, delimiter| {
            if delimiter.is_empty() {
                return script_err_invalid_args!(
                    vm.bx.threads.cur_ref().trap,
                    "std.text.split requires a non-empty `delimiter`"
                );
            }
            if value
                .split(delimiter)
                .take(MAX_STANDARD_ARRAY_ITEMS + 1)
                .count()
                > MAX_STANDARD_ARRAY_ITEMS
            {
                return standard_text_segment_limit(vm);
            }

            let output = vm.bx.heap.new_array();
            let trap = vm.bx.threads.cur_ref().trap.pass();
            for segment in value.split(delimiter) {
                let segment = vm.bx.heap.new_string_from_str(segment);
                vm.bx.heap.array_push(output, segment, trap);
            }
            output.into()
        })
    }) {
        Some(Some(result)) => result,
        Some(None) => standard_text_expected_string(vm, "split", "delimiter"),
        None => standard_text_expected_string(vm, "split", "value"),
    }
}

fn standard_text_join(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let values = script_value!(vm, args.values);
    let separator = script_value!(vm, args.separator);
    let Some(values) = values.as_array() else {
        return standard_text_join_expected_array(vm);
    };
    let length = vm.bx.heap.array_len(values);
    if length > MAX_STANDARD_ARRAY_ITEMS {
        return standard_text_join_value_limit(vm);
    }

    match vm.string_with(separator, |vm, separator| {
        for index in 0..length {
            let value = vm.bx.heap.array_index_unchecked(values, index);
            vm.bx.heap.string_with(value, |_, _| ())?;
        }

        Some(vm.bx.heap.new_bounded_string_with(|heap, output| {
            for index in 0..length {
                if index != 0 {
                    output.append_str(separator);
                    if output.is_full() {
                        break;
                    }
                }
                let value = heap.array_index_unchecked(values, index);
                let _ = heap.string_with(value, |_, value| output.append_str(value));
                if output.is_full() {
                    break;
                }
            }
        }))
    }) {
        Some(Some(result)) => result,
        Some(None) => standard_text_join_expected_string_item(vm),
        None => standard_text_expected_string(vm, "join", "separator"),
    }
}

fn standard_text_segment_limit(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_limit!(
        vm.bx.threads.cur_ref().trap,
        "std.text.split supports at most {MAX_STANDARD_ARRAY_ITEMS} segments"
    )
}

fn standard_text_join_value_limit(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_limit!(
        vm.bx.threads.cur_ref().trap,
        "std.text.join supports at most {MAX_STANDARD_ARRAY_ITEMS} values"
    )
}

fn standard_text_join_expected_array(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.text.join expects `values` to be an array"
    )
}

fn standard_text_join_expected_string_item(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.text.join expects `values` to contain only strings"
    )
}

fn standard_text_expected_string(
    vm: &mut vm::ScriptVm,
    function: &'static str,
    parameter: &'static str,
) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.text.{function} expects `{parameter}` to be a string"
    )
}

/// Installs bounded, callback-free array transformations for local dataflow.
/// The module never introspects host data or grants authority.
fn install_standard_array_module(vm: &mut vm::ScriptVm, std_module: ScriptObject) {
    let array = vm.bx.heap.new_with_proto(NIL);
    vm.add_method(
        array,
        id!(len),
        script_args_def!(value = NIL),
        standard_array_len,
    );
    vm.add_method(
        array,
        id!(has_index),
        script_args_def!(value = NIL, index = NIL),
        standard_array_has_index,
    );
    vm.add_method(
        array,
        id!(get),
        script_args_def!(value = NIL, index = NIL, fallback = NIL),
        standard_array_get,
    );
    vm.add_method(
        array,
        id!(slice),
        script_args_def!(value = NIL, start = NIL, end = NIL),
        standard_array_slice,
    );
    vm.add_method(
        array,
        id!(concat),
        script_args_def!(left = NIL, right = NIL),
        standard_array_concat,
    );
    vm.add_method(
        array,
        id!(compact),
        script_args_def!(value = NIL),
        standard_array_compact,
    );
    vm.add_method(
        array,
        id!(flatten),
        script_args_def!(value = NIL),
        standard_array_flatten,
    );
    vm.add_method(
        array,
        id!(reverse),
        script_args_def!(value = NIL),
        standard_array_reverse,
    );
    vm.add_method(
        array,
        id!(push),
        script_args_def!(value = NIL, item = NIL),
        standard_array_push,
    );
    vm.bx
        .heap
        .set_value_def(std_module, id!(array).into(), array.into());
    vm.bx.heap.freeze(array);
}

fn standard_array_len(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let (_, length) = match standard_array_unbounded_input(vm, value, "len", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };
    length.into()
}

fn standard_array_has_index(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let index = script_value!(vm, args.index);
    let (_, length) = match standard_array_unbounded_input(vm, value, "has_index", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };
    let index = match standard_array_index(vm, index, "has_index", "index") {
        Ok(index) => index,
        Err(error) => return error,
    };
    (index < length).into()
}

fn standard_array_get(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let index = script_value!(vm, args.index);
    let fallback = script_value!(vm, args.fallback);
    let (array, length) = match standard_array_unbounded_input(vm, value, "get", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };
    let index = match standard_array_index(vm, index, "get", "index") {
        Ok(index) => index,
        Err(error) => return error,
    };
    if index < length {
        vm.bx.heap.array_index_unchecked(array, index)
    } else {
        fallback
    }
}

fn standard_array_slice(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let start = script_value!(vm, args.start);
    let end = script_value!(vm, args.end);
    let (array, length) = match standard_array_input(vm, value, "slice", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };
    let start = match standard_array_index(vm, start, "slice", "start") {
        Ok(index) => index,
        Err(error) => return error,
    };
    let end = match standard_array_index(vm, end, "slice", "end") {
        Ok(index) => index,
        Err(error) => return error,
    };
    if start > end || end > length {
        return script_err_invalid_args!(
            vm.bx.threads.cur_ref().trap,
            "std.array.slice requires `start` <= `end` <= array length"
        );
    }

    standard_array_copy_indices(vm, array, start..end)
}

fn standard_array_concat(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let left = script_value!(vm, args.left);
    let right = script_value!(vm, args.right);
    let (left, left_length) = match standard_array_input(vm, left, "concat", "left") {
        Ok(input) => input,
        Err(error) => return error,
    };
    let (right, right_length) = match standard_array_input(vm, right, "concat", "right") {
        Ok(input) => input,
        Err(error) => return error,
    };
    let Some(total_length) = left_length.checked_add(right_length) else {
        return standard_array_item_limit(vm, "concat");
    };
    if total_length > MAX_STANDARD_ARRAY_ITEMS {
        return standard_array_item_limit(vm, "concat");
    }

    let output = vm.bx.heap.new_array();
    standard_array_append_indices(vm, output, left, 0..left_length);
    standard_array_append_indices(vm, output, right, 0..right_length);
    output.into()
}

fn standard_array_compact(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let (array, length) = match standard_array_input(vm, value, "compact", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };

    let output = vm.bx.heap.new_array();
    let trap = vm.bx.threads.cur_ref().trap.pass();
    for index in 0..length {
        let value = vm.bx.heap.array_index_unchecked(array, index);
        if value != NIL {
            vm.bx.heap.array_push(output, value, trap);
        }
    }
    output.into()
}

fn standard_array_flatten(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let (outer, outer_length) = match standard_array_input(vm, value, "flatten", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };

    let mut output_length = 0usize;
    for index in 0..outer_length {
        let value = vm.bx.heap.array_index_unchecked(outer, index);
        let Some(inner) = value.as_array() else {
            return standard_array_expected_nested_array(vm, "flatten");
        };
        let inner_length = vm.bx.heap.array_len(inner);
        if inner_length > MAX_STANDARD_ARRAY_ITEMS {
            return standard_array_item_limit(vm, "flatten");
        }
        let Some(next_length) = output_length.checked_add(inner_length) else {
            return standard_array_item_limit(vm, "flatten");
        };
        if next_length > MAX_STANDARD_ARRAY_ITEMS {
            return standard_array_item_limit(vm, "flatten");
        }
        output_length = next_length;
    }

    let output = vm.bx.heap.new_array();
    for index in 0..outer_length {
        let value = vm.bx.heap.array_index_unchecked(outer, index);
        let Some(inner) = value.as_array() else {
            return standard_array_expected_nested_array(vm, "flatten");
        };
        let inner_length = vm.bx.heap.array_len(inner);
        standard_array_append_indices(vm, output, inner, 0..inner_length);
    }
    output.into()
}

fn standard_array_reverse(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let (array, length) = match standard_array_input(vm, value, "reverse", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };

    standard_array_copy_indices(vm, array, (0..length).rev())
}

fn standard_array_push(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let item = script_value!(vm, args.item);
    let (array, length) = match standard_array_input(vm, value, "push", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };
    if length == MAX_STANDARD_ARRAY_ITEMS {
        return standard_array_item_limit(vm, "push");
    }

    let trap = vm.bx.threads.cur_ref().trap.pass();
    vm.bx.heap.array_push(array, item, trap);
    NIL
}

fn standard_array_input(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
    function: &'static str,
    parameter: &'static str,
) -> Result<(vm::ScriptArray, usize), ScriptValue> {
    let (array, length) = standard_array_unbounded_input(vm, value, function, parameter)?;
    if length > MAX_STANDARD_ARRAY_ITEMS {
        return Err(standard_array_item_limit(vm, function));
    }
    Ok((array, length))
}

/// Returns one array and its length without iterating, copying, or allocating.
/// Lookup helpers use this path so a single indexed read remains bounded even
/// when a host-provided array is larger than the transformation ceiling.
fn standard_array_unbounded_input(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
    function: &'static str,
    parameter: &'static str,
) -> Result<(vm::ScriptArray, usize), ScriptValue> {
    let Some(array) = value.as_array() else {
        return Err(standard_array_expected_array(vm, function, parameter));
    };
    Ok((array, vm.bx.heap.array_len(array)))
}

fn standard_array_index(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
    function: &'static str,
    parameter: &'static str,
) -> Result<usize, ScriptValue> {
    let Some(value) = value.as_number() else {
        return Err(standard_array_expected_index(vm, function, parameter));
    };
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > usize::MAX as f64 {
        return Err(standard_array_expected_index(vm, function, parameter));
    }
    Ok(value as usize)
}

fn standard_array_copy_indices(
    vm: &mut vm::ScriptVm,
    source: vm::ScriptArray,
    indices: impl Iterator<Item = usize>,
) -> ScriptValue {
    let output = vm.bx.heap.new_array();
    standard_array_append_indices(vm, output, source, indices);
    output.into()
}

fn standard_array_append_indices(
    vm: &mut vm::ScriptVm,
    output: vm::ScriptArray,
    source: vm::ScriptArray,
    indices: impl Iterator<Item = usize>,
) {
    let trap = vm.bx.threads.cur_ref().trap.pass();
    for index in indices {
        let value = vm.bx.heap.array_index_unchecked(source, index);
        vm.bx.heap.array_push(output, value, trap);
    }
}

fn standard_array_expected_array(
    vm: &mut vm::ScriptVm,
    function: &'static str,
    parameter: &'static str,
) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.array.{function} expects `{parameter}` to be an array"
    )
}

fn standard_array_expected_index(
    vm: &mut vm::ScriptVm,
    function: &'static str,
    parameter: &'static str,
) -> ScriptValue {
    script_err_invalid_args!(
        vm.bx.threads.cur_ref().trap,
        "std.array.{function} expects `{parameter}` to be a non-negative integer"
    )
}

fn standard_array_expected_nested_array(
    vm: &mut vm::ScriptVm,
    function: &'static str,
) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.array.{function} expects every `value` item to be an array"
    )
}

fn standard_array_item_limit(vm: &mut vm::ScriptVm, function: &'static str) -> ScriptValue {
    script_err_limit!(
        vm.bx.threads.cur_ref().trap,
        "std.array.{function} supports at most {MAX_STANDARD_ARRAY_ITEMS} items"
    )
}

/// Installs own-field-only record operations for bounded local dataflow. This
/// module does not traverse prototypes, invoke callbacks, or expose host state.
fn install_standard_object_module(vm: &mut vm::ScriptVm, std_module: ScriptObject) {
    let object = vm.bx.heap.new_with_proto(NIL);
    vm.add_method(
        object,
        id!(len),
        script_args_def!(value = NIL),
        standard_object_len,
    );
    vm.add_method(
        object,
        id!(has),
        script_args_def!(value = NIL, key = NIL),
        standard_object_has,
    );
    vm.add_method(
        object,
        id!(get),
        script_args_def!(value = NIL, key = NIL, fallback = NIL),
        standard_object_get,
    );
    vm.add_method(
        object,
        id!(pick),
        script_args_def!(value = NIL, keys = NIL),
        standard_object_pick,
    );
    vm.add_method(
        object,
        id!(from_entries),
        script_args_def!(entries = NIL),
        standard_object_from_entries,
    );
    vm.add_method(
        object,
        id!(keys),
        script_args_def!(value = NIL),
        standard_object_keys,
    );
    vm.add_method(
        object,
        id!(entries),
        script_args_def!(value = NIL),
        standard_object_entry_pairs,
    );
    vm.add_method(
        object,
        id!(values),
        script_args_def!(value = NIL),
        standard_object_values,
    );
    vm.add_method(
        object,
        id!(merge),
        script_args_def!(left = NIL, right = NIL),
        standard_object_merge,
    );
    vm.bx
        .heap
        .set_value_def(std_module, id!(object).into(), object.into());
    vm.bx.heap.freeze(object);
}

fn standard_object_len(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let (_, length) = match standard_object_input(vm, value, "len", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };
    ScriptValue::from_f64(length as f64)
}

fn standard_object_has(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let key = script_value!(vm, args.key);
    let (object, _) = match standard_object_input(vm, value, "has", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };
    match standard_object_own_text_field(vm, object, key, "has") {
        Ok(value) => value.is_some().into(),
        Err(error) => error,
    }
}

fn standard_object_get(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let key = script_value!(vm, args.key);
    let fallback = script_value!(vm, args.fallback);
    let (object, _) = match standard_object_input(vm, value, "get", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };
    match standard_object_own_text_field(vm, object, key, "get") {
        Ok(Some(value)) => value,
        Ok(None) => fallback,
        Err(error) => error,
    }
}

fn standard_object_pick(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let keys = script_value!(vm, args.keys);
    let (object, _) = match standard_object_input(vm, value, "pick", "value") {
        Ok(input) => input,
        Err(error) => return error,
    };
    let (keys, key_count) = match standard_object_pick_keys(vm, keys) {
        Ok(input) => input,
        Err(error) => return error,
    };

    for index in 0..key_count {
        let key = vm.bx.heap.array_index_unchecked(keys, index);
        if vm.string_with(key, |_, _| ()).is_none() {
            return standard_object_expected_pick_text_key(vm);
        }
    }

    let output = vm.bx.heap.new_object();
    vm.bx.heap.set_string_keys(output);
    for index in 0..key_count {
        let key = vm.bx.heap.array_index_unchecked(keys, index);
        let value = match standard_object_own_text_field(vm, object, key, "pick") {
            Ok(value) => value,
            Err(error) => return error,
        };
        if let Some(value) = value {
            let trap = vm.bx.threads.cur_ref().trap.pass();
            vm.bx.heap.set_value(output, key, value, trap);
        }
    }
    output.into()
}

fn standard_object_from_entries(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let entries = script_value!(vm, args.entries);
    let (entries, entry_count) = match standard_object_from_entries_input(vm, entries) {
        Ok(input) => input,
        Err(error) => return error,
    };

    for index in 0..entry_count {
        let entry = vm.bx.heap.array_index_unchecked(entries, index);
        let pair = match standard_object_from_entries_pair(vm, entry) {
            Ok(pair) => pair,
            Err(error) => return error,
        };
        let key = vm.bx.heap.array_index_unchecked(pair, 0);
        if vm.string_with(key, |_, _| ()).is_none() {
            return standard_object_expected_entry_key(vm);
        }
    }

    let output = vm.bx.heap.new_object();
    vm.bx.heap.set_string_keys(output);
    for index in 0..entry_count {
        let entry = vm.bx.heap.array_index_unchecked(entries, index);
        let pair = match standard_object_from_entries_pair(vm, entry) {
            Ok(pair) => pair,
            Err(error) => return error,
        };
        let key = vm.bx.heap.array_index_unchecked(pair, 0);
        let value = vm.bx.heap.array_index_unchecked(pair, 1);
        let trap = vm.bx.threads.cur_ref().trap.pass();
        vm.bx.heap.set_value(output, key, value, trap);
    }
    output.into()
}

fn standard_object_keys(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let entries = match standard_object_entries(vm, value, "keys", "value") {
        Ok(entries) => entries,
        Err(error) => return error,
    };
    standard_object_values_array(vm, entries.into_iter().map(|(key, _)| key))
}

fn standard_object_entry_pairs(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let entries = match standard_object_entries(vm, value, "entries", "value") {
        Ok(entries) => entries,
        Err(error) => return error,
    };

    let output = vm.bx.heap.new_array();
    let trap = vm.bx.threads.cur_ref().trap.pass();
    for (key, value) in entries {
        let pair = vm.bx.heap.new_array();
        vm.bx.heap.array_push(pair, key, trap);
        vm.bx.heap.array_push(pair, value, trap);
        vm.bx.heap.array_push(output, pair.into(), trap);
    }
    output.into()
}

fn standard_object_values(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = script_value!(vm, args.value);
    let entries = match standard_object_entries(vm, value, "values", "value") {
        Ok(entries) => entries,
        Err(error) => return error,
    };
    standard_object_values_array(vm, entries.into_iter().map(|(_, value)| value))
}

fn standard_object_merge(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let left = script_value!(vm, args.left);
    let right = script_value!(vm, args.right);
    let left_entries = match standard_object_entries(vm, left, "merge", "left") {
        Ok(entries) => entries,
        Err(error) => return error,
    };
    let right_entries = match standard_object_entries(vm, right, "merge", "right") {
        Ok(entries) => entries,
        Err(error) => return error,
    };
    let Some(total_fields) = left_entries.len().checked_add(right_entries.len()) else {
        return standard_object_field_limit(vm, "merge");
    };
    if total_fields > MAX_STANDARD_OBJECT_FIELDS {
        return standard_object_field_limit(vm, "merge");
    }

    let entries = standard_object_merged_entries(left_entries, right_entries, total_fields);
    let output = vm.bx.heap.new_object();
    vm.bx.heap.set_string_keys(output);
    let trap = vm.bx.threads.cur_ref().trap.pass();
    for (key, value) in entries {
        vm.bx.heap.set_value(output, key, value, trap);
    }
    output.into()
}

fn standard_object_input(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
    function: &'static str,
    parameter: &'static str,
) -> Result<(ScriptObject, usize), ScriptValue> {
    let Some(object) = value.as_object() else {
        return Err(standard_object_expected_record(vm, function, parameter));
    };
    let data = vm.bx.heap.object_data(object);
    if vm.bx.heap.is_fn(object)
        || vm.bx.heap.proto(object) != id!(object).into()
        || !data.vec.is_empty()
    {
        return Err(standard_object_expected_record(vm, function, parameter));
    }
    Ok((object, data.map_len()))
}

fn standard_object_pick_keys(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
) -> Result<(vm::ScriptArray, usize), ScriptValue> {
    let Some(keys) = value.as_array() else {
        return Err(script_err_type_mismatch!(
            vm.bx.threads.cur_ref().trap,
            "std.object.pick expects `keys` to be an array"
        ));
    };
    let key_count = vm.bx.heap.array_len(keys);
    if key_count > MAX_STANDARD_OBJECT_FIELDS {
        return Err(standard_object_pick_key_limit(vm));
    }
    Ok((keys, key_count))
}

fn standard_object_from_entries_input(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
) -> Result<(vm::ScriptArray, usize), ScriptValue> {
    let Some(entries) = value.as_array() else {
        return Err(script_err_type_mismatch!(
            vm.bx.threads.cur_ref().trap,
            "std.object.from_entries expects `entries` to be an array"
        ));
    };
    let entry_count = vm.bx.heap.array_len(entries);
    if entry_count > MAX_STANDARD_OBJECT_FIELDS {
        return Err(standard_object_entry_limit(vm));
    }
    Ok((entries, entry_count))
}

fn standard_object_from_entries_pair(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
) -> Result<vm::ScriptArray, ScriptValue> {
    let Some(pair) = value.as_array() else {
        return Err(standard_object_expected_entry_pair(vm));
    };
    if vm.bx.heap.array_len(pair) != 2 {
        return Err(standard_object_expected_entry_pair(vm));
    }
    Ok(pair)
}

/// Resolves an own text field without using the VM's prototype-chain lookup.
/// Records can store identifier or string keys, so check both representations.
fn standard_object_own_text_field(
    vm: &mut vm::ScriptVm,
    object: ScriptObject,
    key: ScriptValue,
    function: &'static str,
) -> Result<Option<ScriptValue>, ScriptValue> {
    let Some(value) = vm.string_with(key, |vm, key_text| {
        let canonical_key = vm.bx.heap.check_intern_string(key_text);
        let identifier_key: ScriptValue = LiveId::from_str(key_text).into();
        let data = vm.bx.heap.object_data(object);
        data.map_get(&key)
            .or_else(|| canonical_key.and_then(|key| data.map_get(&key)))
            .or_else(|| data.map_get(&identifier_key))
    }) else {
        return Err(standard_object_expected_lookup_key(vm, function));
    };
    Ok(value)
}

fn standard_object_entries(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
    function: &'static str,
    parameter: &'static str,
) -> Result<Vec<(ScriptValue, ScriptValue)>, ScriptValue> {
    let (object, length) = standard_object_input(vm, value, function, parameter)?;
    if length > MAX_STANDARD_OBJECT_FIELDS {
        return Err(standard_object_field_limit(vm, function));
    }
    let mut entries = Vec::with_capacity(length);
    vm.bx
        .heap
        .object_data(object)
        .map_iter_ordered(|key, value| entries.push((key, value)));
    for (key, _) in &mut entries {
        *key = standard_object_text_key(vm, *key, function)?;
    }
    Ok(entries)
}

fn standard_object_text_key(
    vm: &mut vm::ScriptVm,
    key: ScriptValue,
    function: &'static str,
) -> Result<ScriptValue, ScriptValue> {
    if let Some(identifier) = key.as_id() {
        return identifier
            .as_string(|name| name.map(|name| vm.bx.heap.new_string_from_str(name)))
            .ok_or_else(|| standard_object_expected_text_key(vm, function));
    }
    vm.bx
        .heap
        .string_mut_self_with(key, |heap, value| heap.new_string_from_str(value))
        .ok_or_else(|| standard_object_expected_text_key(vm, function))
}

fn standard_object_merged_entries(
    left: Vec<(ScriptValue, ScriptValue)>,
    right: Vec<(ScriptValue, ScriptValue)>,
    capacity: usize,
) -> Vec<(ScriptValue, ScriptValue)> {
    let mut entries: Vec<(ScriptValue, ScriptValue)> = Vec::with_capacity(capacity);
    let mut indices: HashMap<ScriptValue, usize> = HashMap::with_capacity(capacity);
    for (key, value) in left.into_iter().chain(right) {
        if let Some(index) = indices.get(&key).copied() {
            entries[index].1 = value;
        } else {
            indices.insert(key, entries.len());
            entries.push((key, value));
        }
    }
    entries
}

fn standard_object_values_array(
    vm: &mut vm::ScriptVm,
    values: impl IntoIterator<Item = ScriptValue>,
) -> ScriptValue {
    let output = vm.bx.heap.new_array();
    let trap = vm.bx.threads.cur_ref().trap.pass();
    for value in values {
        vm.bx.heap.array_push(output, value, trap);
    }
    output.into()
}

fn standard_object_expected_record(
    vm: &mut vm::ScriptVm,
    function: &'static str,
    parameter: &'static str,
) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.object.{function} expects `{parameter}` to be a plain record"
    )
}

fn standard_object_expected_lookup_key(
    vm: &mut vm::ScriptVm,
    function: &'static str,
) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.object.{function} expects `key` to be a string"
    )
}

fn standard_object_expected_pick_text_key(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.object.pick expects every `keys` item to be a string"
    )
}

fn standard_object_expected_entry_pair(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.object.from_entries expects every `entries` item to be a two-item array"
    )
}

fn standard_object_expected_entry_key(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.object.from_entries expects every entry key to be a string"
    )
}

fn standard_object_expected_text_key(vm: &mut vm::ScriptVm, function: &'static str) -> ScriptValue {
    script_err_type_mismatch!(
        vm.bx.threads.cur_ref().trap,
        "std.object.{function} only supports text field keys"
    )
}

fn standard_object_field_limit(vm: &mut vm::ScriptVm, function: &'static str) -> ScriptValue {
    script_err_limit!(
        vm.bx.threads.cur_ref().trap,
        "std.object.{function} supports at most {MAX_STANDARD_OBJECT_FIELDS} fields"
    )
}

fn standard_object_pick_key_limit(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_limit!(
        vm.bx.threads.cur_ref().trap,
        "std.object.pick supports at most {MAX_STANDARD_OBJECT_FIELDS} keys"
    )
}

fn standard_object_entry_limit(vm: &mut vm::ScriptVm) -> ScriptValue {
    script_err_limit!(
        vm.bx.threads.cur_ref().trap,
        "std.object.from_entries supports at most {MAX_STANDARD_OBJECT_FIELDS} entries"
    )
}

fn standard_math_unary(
    vm: &mut vm::ScriptVm,
    args: ScriptObject,
    function: &'static str,
    operation: impl FnOnce(f64) -> f64,
) -> ScriptValue {
    match standard_math_number(vm, args, id!(value), function, "value") {
        Ok(value) => standard_math_result(vm, operation(value)),
        Err(error) => error,
    }
}

struct StandardMathBinaryParameters {
    left: (LiveId, &'static str),
    right: (LiveId, &'static str),
}

fn standard_math_binary(
    vm: &mut vm::ScriptVm,
    args: ScriptObject,
    function: &'static str,
    parameters: StandardMathBinaryParameters,
    operation: impl FnOnce(f64, f64) -> f64,
) -> ScriptValue {
    let left = match standard_math_number(vm, args, parameters.left.0, function, parameters.left.1)
    {
        Ok(value) => value,
        Err(error) => return error,
    };
    match standard_math_number(vm, args, parameters.right.0, function, parameters.right.1) {
        Ok(right) => standard_math_result(vm, operation(left, right)),
        Err(error) => error,
    }
}

fn standard_math_clamp(vm: &mut vm::ScriptVm, args: ScriptObject) -> ScriptValue {
    let value = match standard_math_number(vm, args, id!(value), "clamp", "value") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let minimum = match standard_math_number(vm, args, id!(minimum), "clamp", "minimum") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let maximum = match standard_math_number(vm, args, id!(maximum), "clamp", "maximum") {
        Ok(value) => value,
        Err(error) => return error,
    };
    if minimum > maximum {
        return script_err_invalid_args!(
            vm.bx.threads.cur_ref().trap,
            "std.math.clamp requires minimum to be less than or equal to maximum"
        );
    }
    standard_math_result(vm, value.clamp(minimum, maximum))
}

fn standard_math_number(
    vm: &mut vm::ScriptVm,
    args: ScriptObject,
    parameter: LiveId,
    function: &'static str,
    parameter_name: &'static str,
) -> Result<f64, ScriptValue> {
    vm.bx
        .heap
        .value(args, parameter.into(), vm.bx.threads.cur_ref().trap.pass())
        .as_number()
        .ok_or_else(|| {
            script_err_type_mismatch!(
                vm.bx.threads.cur_ref().trap,
                "std.math.{function} expects `{parameter_name}` to be a number"
            )
        })
}

fn standard_math_result(vm: &mut vm::ScriptVm, value: f64) -> ScriptValue {
    ScriptValue::from_f64_traced_nan(value, vm.bx.threads.cur_ref().trap.ip)
}

fn install_bounded_json_methods(vm: &mut vm::ScriptVm, limits: Rc<Cell<ScriptJsonMethodLimits>>) {
    let types = [
        vm::ScriptValueType::REDUX_NUMBER,
        vm::ScriptValueType::REDUX_NAN,
        vm::ScriptValueType::REDUX_BOOL,
        vm::ScriptValueType::REDUX_NIL,
        vm::ScriptValueType::REDUX_COLOR,
        vm::ScriptValueType::REDUX_STRING,
        vm::ScriptValueType::REDUX_OBJECT,
        vm::ScriptValueType::REDUX_ARRAY,
        vm::ScriptValueType::REDUX_REGEX,
        vm::ScriptValueType::REDUX_OPCODE,
        vm::ScriptValueType::REDUX_ERR,
        vm::ScriptValueType::REDUX_ID,
    ];

    let mut native = vm.bx.code.native.borrow_mut();
    for value_type in types {
        let limits = limits.clone();
        native.add_type_method(
            &mut vm.bx.heap,
            value_type,
            id!(to_json),
            &[],
            move |vm, args| {
                let value = script_value!(vm, args.self);
                bounded_json_stringify_value(vm, value, limits.get())
            },
        );
    }

    native.add_type_method(
        &mut vm.bx.heap,
        vm::ScriptValueType::REDUX_STRING,
        id!(to_bytes),
        &[],
        |vm, args| {
            let value = script_value!(vm, args.self);
            vm.bx.heap.string_to_bytes_array(value).into()
        },
    );

    let string_limits = limits.clone();
    native.add_type_method(
        &mut vm.bx.heap,
        vm::ScriptValueType::REDUX_STRING,
        id!(parse_json),
        &[],
        move |vm, args| {
            let value = script_value!(vm, args.self);
            bounded_json_parse_value(vm, value, string_limits.get())
        },
    );

    native.add_type_method(
        &mut vm.bx.heap,
        vm::ScriptValueType::REDUX_ARRAY,
        id!(parse_json),
        &[],
        move |vm, args| {
            let value = script_value!(vm, args.self);
            bounded_json_parse_value(vm, value, limits.get())
        },
    );
}

fn bounded_json_stringify_value(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
    limits: ScriptJsonMethodLimits,
) -> ScriptValue {
    let mut writer = BoundedJsonWriter::new(limits.max_bytes);
    match write_script_json(vm, value, limits.max_depth, &mut Vec::new(), &mut writer) {
        Ok(()) => vm.bx.heap.new_string_from_str(&writer.into_string()),
        Err(error) => bounded_json_method_error(vm, error),
    }
}

fn bounded_json_parse_value(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
    limits: ScriptJsonMethodLimits,
) -> ScriptValue {
    match script_json_document(vm, value, limits)
        .and_then(|document| parse_bounded_script_json(vm, &document, limits))
    {
        Ok(value) => value,
        Err(error) => bounded_json_method_error(vm, error),
    }
}

fn script_json_document(
    vm: &mut vm::ScriptVm,
    value: ScriptValue,
    limits: ScriptJsonMethodLimits,
) -> Result<String, RuntimeJsonError> {
    if let Some(document) = vm.bx.heap.string_with(value, |_, document| {
        if document.len() > limits.max_bytes {
            Err(RuntimeJsonError::TooLarge {
                actual: document.len(),
                maximum: limits.max_bytes,
            })
        } else {
            Ok(document.to_owned())
        }
    }) {
        return document;
    }

    match value.as_array() {
        Some(array) => match vm.bx.heap.array_storage(array) {
            vm::ScriptArrayStorage::U8(bytes) => {
                if bytes.len() > limits.max_bytes {
                    Err(RuntimeJsonError::TooLarge {
                        actual: bytes.len(),
                        maximum: limits.max_bytes,
                    })
                } else {
                    String::from_utf8(bytes.clone()).map_err(|_| RuntimeJsonError::InvalidEncoding)
                }
            }
            _ => Err(RuntimeJsonError::UnsupportedScriptValue),
        },
        None => Err(RuntimeJsonError::UnsupportedScriptValue),
    }
}

fn parse_bounded_script_json(
    vm: &mut vm::ScriptVm,
    document: &str,
    limits: ScriptJsonMethodLimits,
) -> Result<vm::ScriptValue, RuntimeJsonError> {
    decode_bounded_script_json(vm, document, limits.max_bytes, limits.max_depth)
}

fn bounded_json_method_error(vm: &mut vm::ScriptVm, error: RuntimeJsonError) -> vm::ScriptValue {
    match error {
        RuntimeJsonError::TooLarge { .. } | RuntimeJsonError::TooDeep { .. } => {
            script_err_limit!(
                vm.bx.threads.cur_ref().trap,
                "JSON operation exceeded Splash runtime limits"
            )
        }
        _ => script_err_unexpected!(
            vm.bx.threads.cur_ref().trap,
            "value cannot cross Splash's bounded JSON boundary"
        ),
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
    fn direct_to_json_uses_bounded_cycle_aware_serialization() {
        let mut runtime = Runtime::default();
        let encoded = runtime
            .eval("let value = {answer: 42}\nvalue.to_json()")
            .unwrap();

        assert!(encoded.completed(), "{:?}", encoded.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    encoded.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("{\"answer\":42}")
        );

        let recovered = runtime
            .eval(
                "let value = {}\n\
                 value.self = value\n\
                 try value.to_json() catch \"cycle rejected\"",
            )
            .unwrap();

        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("cycle rejected")
        );
    }

    #[test]
    fn direct_to_json_rejects_excess_runtime_depth_and_output() {
        let mut depth_source = String::from("let value = 0\n");
        for _ in 0..=DEFAULT_MAX_JSON_DATA_DEPTH {
            depth_source.push_str("value = [value]\n");
        }
        depth_source.push_str("try value.to_json() catch \"depth rejected\"");

        let mut runtime = Runtime::default();
        let depth_recovered = runtime.eval(&depth_source).unwrap();
        assert!(
            depth_recovered.completed(),
            "{:?}",
            depth_recovered.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    depth_recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("depth rejected")
        );

        let mut output_source = String::from("let value = \"x\"\n");
        for _ in 0..17 {
            output_source.push_str("value += value\n");
        }
        output_source.push_str("try value.to_json() catch \"output rejected\"");

        let output_recovered = runtime.eval(&output_source).unwrap();
        assert!(
            output_recovered.completed(),
            "{:?}",
            output_recovered.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    output_recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("output rejected")
        );
    }

    #[test]
    fn direct_to_json_tracks_lowered_runtime_limits() {
        let mut source = String::from("let value = \"x\"\n");
        for _ in 0..9 {
            source.push_str("value += value\n");
        }
        source.push_str("try value.to_json() catch \"lowered limit applied\"");

        let mut runtime = Runtime::default();
        let mut limits = runtime.limits();
        limits.max_source_bytes = source.len();
        runtime.set_limits(limits).unwrap();

        let recovered = runtime.eval(&source).unwrap();
        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("lowered limit applied")
        );
    }

    #[test]
    fn direct_to_json_is_bounded_for_compatibility_evaluation() {
        let mut runtime = Runtime::default();
        let recovered = runtime
            .eval_vm_compatibility(
                "var value = {}\n\
                 value.self = value\n\
                 var recovered = try { value.to_json() } { \"cycle rejected\" }\n\
                 recovered",
            )
            .unwrap();

        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("cycle rejected")
        );
    }

    #[test]
    fn direct_parse_json_uses_bounded_standard_json() {
        let mut runtime = Runtime::default();
        let parsed_string = runtime
            .eval("let value = \"{\\\"answer\\\":42}\".parse_json()\nvalue.answer")
            .unwrap();

        assert!(parsed_string.completed(), "{:?}", parsed_string.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    parsed_string.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(42)
        );

        let parsed_bytes = runtime
            .eval(
                "let value = \"{\\\"answer\\\":42}\".to_bytes().parse_json()\n\
                 value.answer",
            )
            .unwrap();

        assert!(parsed_bytes.completed(), "{:?}", parsed_bytes.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    parsed_bytes.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(42)
        );

        let invalid = runtime
            .eval("try \"{unquoted: true}\".parse_json() catch \"invalid JSON\"")
            .unwrap();

        assert!(invalid.completed(), "{:?}", invalid.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid JSON")
        );

        let invalid_bytes = runtime
            .eval(
                "let bytes = \"x\".to_bytes()\n\
                 bytes[0] = 255\n\
                 try bytes.parse_json() catch \"invalid UTF-8\"",
            )
            .unwrap();

        assert!(invalid_bytes.completed(), "{:?}", invalid_bytes.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_bytes.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid UTF-8")
        );
    }

    #[test]
    fn direct_parse_json_rejects_excess_runtime_depth_and_input() {
        let mut depth_source = String::from("let document = \"0\"\nlet index = 0\n");
        depth_source.push_str("while (index < 65) {\n");
        depth_source.push_str("document = \"[\" + document + \"]\"\n");
        depth_source.push_str("index += 1\n}\n");
        depth_source.push_str("try document.parse_json() catch \"depth rejected\"");

        let mut runtime = Runtime::default();
        let depth_recovered = runtime.eval(&depth_source).unwrap();
        assert!(
            depth_recovered.completed(),
            "{:?}",
            depth_recovered.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    depth_recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("depth rejected")
        );

        let mut input_source = String::from("let payload = \"x\"\n");
        for _ in 0..17 {
            input_source.push_str("payload += payload\n");
        }
        input_source.push_str("let document = \"\\\"\" + payload + \"\\\"\"\n");
        input_source.push_str("try document.parse_json() catch \"input rejected\"");

        let input_recovered = runtime.eval(&input_source).unwrap();
        assert!(
            input_recovered.completed(),
            "{:?}",
            input_recovered.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    input_recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("input rejected")
        );
    }

    #[test]
    fn direct_parse_json_tracks_lowered_runtime_limits() {
        let mut source = String::from("let payload = \"x\"\n");
        for _ in 0..9 {
            source.push_str("payload += payload\n");
        }
        source.push_str("let document = \"\\\"\" + payload + \"\\\"\"\n");
        source.push_str("try document.parse_json() catch \"lowered limit applied\"");

        let mut runtime = Runtime::default();
        let mut limits = runtime.limits();
        limits.max_source_bytes = source.len();
        runtime.set_limits(limits).unwrap();

        let recovered = runtime.eval(&source).unwrap();
        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("lowered limit applied")
        );
    }

    #[test]
    fn direct_parse_json_is_bounded_for_compatibility_evaluation() {
        let mut runtime = Runtime::default();
        let recovered = runtime
            .eval_vm_compatibility(
                "var recovered = try { \"{unquoted: true}\".parse_json() } { \"invalid JSON\" }\n\
                 recovered",
            )
            .unwrap();

        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    recovered.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid JSON")
        );
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
    fn canonical_newline_boundaries_are_lowered_for_vm_compatibility() {
        // The inherited tokenizer sees the newline as whitespace and would
        // otherwise parse `(42)` as a call on the imported module field.
        let source = "use mod.std.a\n(42)\n";
        let compatibility = check_vm_compatibility(source).unwrap();
        let canonical = check_syntax(source).unwrap();

        assert!(!compatibility.valid);
        assert!(canonical.valid, "{:?}", canonical.diagnostics);
    }

    #[test]
    fn canonical_newline_boundaries_do_not_become_vm_postfix_operations() {
        for source in [
            "let first = 1\n(42)",
            "let first = 1 /* comment crosses a newline\n*/\n(42)",
        ] {
            let mut runtime = Runtime::default();
            let report = runtime.eval(source).unwrap();

            assert!(report.succeeded(), "{:?}", report.diagnostics);
            assert_eq!(
                runtime
                    .script_value_as_json(
                        report.value,
                        DEFAULT_MAX_JSON_DATA_BYTES,
                        DEFAULT_MAX_JSON_DATA_DEPTH,
                    )
                    .unwrap(),
                serde_json::json!(42),
                "source: {source:?}"
            );
        }
    }

    #[test]
    fn canonical_lowering_reserves_vm_tokens_for_compiled_boundaries() {
        let limits = ExecutionLimits {
            max_syntax_tokens: 6,
            ..ExecutionLimits::default()
        };
        let report = check_syntax_named("boundary.splash", "let value = 1\nvalue", limits).unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
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
    fn vm_compatibility_preflight_rejects_a_partial_field_assignment_without_panicking() {
        let report =
            check_vm_compatibility_named("legacy.splash", "@.b-=", ExecutionLimits::default())
                .unwrap();

        assert!(!report.valid);
        assert!(!report.diagnostics.is_empty());
    }

    #[test]
    fn vm_compatibility_preflight_accepts_numeric_separators_without_panicking() {
        let report =
            check_vm_compatibility_named("legacy.splash", "1_000", ExecutionLimits::default())
                .unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn vm_compatibility_preflight_accepts_proto_field_assignments() {
        let report = check_vm_compatibility_named(
            "legacy.splash",
            "draw_bg.color: 1",
            ExecutionLimits::default(),
        )
        .unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn vm_compatibility_preflight_rejects_a_malformed_proto_field_assignment_without_panicking() {
        let source = concat!(
            "H.-",
            "\x17\x17\x17\x17\x0e",
            "\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17",
            "m: ",
            "\x17\x17\x17\x17\x17\x17\x17\x17\x17",
            "return ",
            "\x17\x17\x17\x17\x17\x17\x17\x17\x17\x17",
            "=!"
        );
        let report =
            check_vm_compatibility_named("legacy.splash", source, ExecutionLimits::default())
                .unwrap();

        assert!(!report.valid);
        assert!(!report.diagnostics.is_empty());
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
    fn outlines_scope_resolved_imported_module_calls() {
        let source = "use mod.arithmetic\n\
                      use mod.tool\n\
                      arithmetic.add({left: 20, right: 22})\n\
                      tool.call(\"text.echo\", \"review\")\n\
                      let arithmetic = {}\n\
                      arithmetic.add({})\n\
                      fn nested() {\n\
                          use mod.catalog.client\n\
                          client.lookup({id: 42})\n\
                      }";

        let report = imported_module_call_hint_report(source)
            .expect("canonical source has imported-module call hints");

        assert!(!report.truncated);
        assert_eq!(report.hints.len(), 3);
        assert_eq!(report.hints[0].module_path, ["mod", "arithmetic"]);
        assert_eq!(report.hints[0].method, "add");
        assert_eq!(report.hints[1].module_path, ["mod", "tool"]);
        assert_eq!(report.hints[1].method, "call");
        assert_eq!(report.hints[2].module_path, ["mod", "catalog", "client"]);
        assert_eq!(report.hints[2].method, "lookup");
        assert_eq!(
            report
                .hints
                .iter()
                .map(|hint| &source[hint.callee_start_byte..hint.callee_end_byte])
                .collect::<Vec<_>>(),
            ["arithmetic.add", "tool.call", "client.lookup"]
        );

        let runtime = Runtime::default();
        assert_eq!(
            runtime.imported_module_call_hint_report(source).unwrap(),
            report
        );
    }

    #[test]
    fn imported_module_call_hints_follow_bounded_stable_root_aliases() {
        let source = concat!(
            "use mod.arithmetic\n",
            "let math = arithmetic\n",
            "math.add({left: 20, right: 22})\n",
            "let calculator = math\n",
            "calculator.add({left: 21, right: 21})\n",
            "arithmetic.add({left: 19, right: 23})"
        );

        let report = imported_module_call_hint_report(source)
            .expect("canonical source resolves stable direct import aliases");
        assert!(!report.truncated);
        assert_eq!(report.hints.len(), 3);
        assert!(report
            .hints
            .iter()
            .all(|hint| hint.module_path == ["mod", "arithmetic"] && hint.method == "add"));
        assert_eq!(
            report
                .hints
                .iter()
                .map(|hint| &source[hint.callee_start_byte..hint.callee_end_byte])
                .collect::<Vec<_>>(),
            ["math.add", "calculator.add", "arithmetic.add"]
        );

        for unstable_source in [
            "use mod.arithmetic\narithmetic = {}\narithmetic.add({})",
            "use mod.arithmetic\nlet math = arithmetic\nmath = {}\nmath.add({})",
            "use mod.arithmetic\nlet math = arithmetic\nconsume(math)\nmath.add({})",
            "use mod.arithmetic\nlet math = arithmetic\nlet sibling = math\nsibling.add = nil\nmath.add({})",
            "use mod.arithmetic\nlet math = arithmetic\nlet method = math.add\nmath.add({})",
            "use mod.arithmetic\nlet math = arithmetic\nlet parenthesized = (math)\nmath.add({})",
            concat!(
                "use mod.arithmetic\n",
                "let math = arithmetic\n",
                "fn run() { math.add({}) }\n",
                "math = {}\n",
                "run()"
            ),
        ] {
            let report = imported_module_call_hint_report(unstable_source)
                .expect("canonical source remains reviewable");
            assert!(
                report.hints.is_empty(),
                "module alias hint must fail closed for {unstable_source:?}"
            );
        }

        let preserved_alias_source = concat!(
            "use mod.arithmetic\n",
            "let math = arithmetic\n",
            "let arithmetic = {}\n",
            "math.add({left: 20, right: 22})"
        );
        let preserved_alias = imported_module_call_hint_report(preserved_alias_source)
            .expect("a later shadow must not rewrite an earlier exact alias");
        assert_eq!(preserved_alias.hints.len(), 1);
        assert_eq!(
            &preserved_alias_source[preserved_alias.hints[0].callee_start_byte
                ..preserved_alias.hints[0].callee_end_byte],
            "math.add"
        );

        let mut bounded_source = String::from("use mod.arithmetic\n");
        let mut previous = "arithmetic".to_owned();
        for index in 0..MAX_IMPORTED_MODULE_ALIAS_DEPTH {
            let alias = format!("alias_{index}");
            bounded_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        bounded_source.push_str(&format!("{previous}.add({{}})"));
        let bounded = imported_module_call_hint_report(&bounded_source)
            .expect("bounded direct import alias chain is canonical");
        assert_eq!(bounded.hints.len(), 1);
        assert_eq!(bounded.hints[0].module_path, ["mod", "arithmetic"]);

        let mut too_deep_source = String::from("use mod.arithmetic\n");
        let mut previous = "arithmetic".to_owned();
        for index in 0..=MAX_IMPORTED_MODULE_ALIAS_DEPTH {
            let alias = format!("alias_{index}");
            too_deep_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        too_deep_source.push_str(&format!("{previous}.add({{}})"));
        assert!(imported_module_call_hint_report(&too_deep_source)
            .expect("too-deep direct import alias chain is canonical")
            .hints
            .is_empty());

        let mut truncated_source = String::from("use mod.arithmetic\n");
        for index in 0..=MAX_STATIC_RECORD_ALIASES {
            truncated_source.push_str(&format!("let alias_{index} = arithmetic\n"));
        }
        truncated_source.push_str("arithmetic.add({})");
        let truncated = imported_module_call_hint_report(&truncated_source)
            .expect("alias-truncated source is canonical");
        assert!(truncated.hints.is_empty());
        assert!(truncated.truncated);

        let runtime = Runtime::default();
        assert_eq!(
            runtime.imported_module_call_hint_report(source).unwrap(),
            report
        );
    }

    #[test]
    fn imported_module_call_hints_fail_closed_when_the_lexical_index_is_truncated() {
        let mut source = String::from("use mod.target\n");
        for _ in 0..MAX_LEXICAL_SYMBOL_OCCURRENCES {
            source.push_str("target.call()\n");
        }

        let report = imported_module_call_hint_report(&source)
            .expect("generated source remains within canonical bounds");

        assert!(report.hints.is_empty());
        assert!(report.truncated);
    }

    #[test]
    fn imported_module_call_hints_fail_closed_when_the_import_index_is_truncated() {
        let mut source = String::new();
        for index in 0..=MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }
        source.push_str("module_0.call()\n");

        let report = imported_module_call_hint_report(&source)
            .expect("generated source remains within canonical bounds");

        assert!(report.hints.is_empty());
        assert!(report.truncated);
    }

    #[test]
    fn bounds_imported_module_call_hints_with_a_truncation_signal() {
        let mut source = String::from("use mod.target\n");
        for _ in 0..=MAX_IMPORTED_MODULE_CALL_HINTS {
            source.push_str("target.call()\n");
        }

        let report = imported_module_call_hint_report(&source)
            .expect("generated source remains within canonical bounds");

        assert_eq!(report.hints.len(), MAX_IMPORTED_MODULE_CALL_HINTS);
        assert!(report.truncated);
        assert!(report
            .hints
            .iter()
            .all(|hint| hint.module_path == ["mod", "target"] && hint.method == "call"));
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
    fn reports_complete_import_paths_with_exact_spans() {
        let source = "use mod.tool\n\
                      use mod.std.assert\n\
                      fn run() {\n\
                          use mod.custom.client\n\
                          client\n\
                      }";

        let report = module_import_report(source).expect("source is within default limits");

        assert_eq!(report.valid_prefix_end_byte, source.len());
        assert!(!report.truncated);
        assert_eq!(
            report
                .imports
                .iter()
                .map(|import| { import.path.iter().map(String::as_str).collect::<Vec<_>>() })
                .collect::<Vec<_>>(),
            [
                vec!["mod", "tool"],
                vec!["mod", "std", "assert"],
                vec!["mod", "custom", "client"],
            ]
        );
        for import in &report.imports {
            assert_eq!(
                &source[import.path_span.start_byte..import.path_span.end_byte],
                import.path.join(".")
            );
            assert_eq!(
                &source[import.binding.start_byte..import.binding.end_byte],
                import.path.last().expect("every import has a binding")
            );
        }

        let runtime = Runtime::default();
        assert_eq!(runtime.module_import_report(source).unwrap(), report);
    }

    #[test]
    fn import_path_spans_retain_permitted_spacing_between_path_tokens() {
        let source = "use mod. /* selected by host */ worker";
        let report = module_import_report(source).expect("source is within default limits");

        assert_eq!(report.imports.len(), 1);
        let import = &report.imports[0];
        assert_eq!(import.path, ["mod", "worker"]);
        assert_eq!(
            &source[import.path_span.start_byte..import.path_span.end_byte],
            "mod. /* selected by host */ worker"
        );
        assert_eq!(
            &source[import.binding.start_byte..import.binding.end_byte],
            "worker"
        );
    }

    #[test]
    fn source_metadata_stops_at_parser_diagnostics_masked_by_later_lexer_errors() {
        let source = "let before = {value: 1}\n\
                      use mod.before\n\
                      use mod. . worker\n\
                      let after = {value: 2}\n\
                      \u{001d}";
        let expected_prefix = source
            .find(". .")
            .expect("source contains the malformed path")
            + 2;

        let completions =
            lexical_completion_report(source).expect("source is within default limits");
        assert_eq!(completions.valid_prefix_end_byte, expected_prefix);

        let imports = module_import_report(source).expect("source is within default limits");
        assert_eq!(imports.valid_prefix_end_byte, expected_prefix);
        assert_eq!(imports.imports.len(), 1);
        assert_eq!(imports.imports[0].path, ["mod", "before"]);

        let shapes = static_record_shape_report(source).expect("source is within default limits");
        assert_eq!(shapes.valid_prefix_end_byte, expected_prefix);
        assert_eq!(shapes.shapes.len(), 1);
        assert_eq!(
            &source[shapes.shapes[0].binding.start_byte..shapes.shapes[0].binding.end_byte],
            "before"
        );
    }

    #[test]
    fn static_record_metadata_retains_only_direct_literal_and_alias_initializers() {
        let source = "let settings = {\n\
                      title: \"Splash\",\n\
                      nested: {enabled: true},\n\
                      items: [1, 2]\n\
                      }\n\
                      let alias = settings\n\
                      let nested_alias = settings.nested\n\
                      let deeper_alias = settings.nested.enabled\n\
                      let too_deep_alias = settings.nested.enabled.value\n\
                      let selected = {value: 1}.value\n\
                      let parenthesized = (settings)\n\
                      settings.";
        let report = static_record_shape_report(source).expect("source is within default limits");

        assert_eq!(report.valid_prefix_end_byte, source.len());
        assert!(!report.truncated);
        assert!(!report.aliases_truncated);
        assert_eq!(report.shapes.len(), 1);
        let shape = &report.shapes[0];
        assert_eq!(
            &source[shape.binding.start_byte..shape.binding.end_byte],
            "settings"
        );
        assert_eq!(
            shape
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["title", "nested", "items"]
        );
        for field in &shape.fields {
            assert_eq!(
                &source[field.definition.start_byte..field.definition.end_byte],
                field.name
            );
        }
        assert_eq!(shape.direct_field_shapes.len(), 1);
        let nested_shape = &shape.direct_field_shapes[0];
        assert_eq!(nested_shape.field.name, "nested");
        assert_eq!(
            &source
                [nested_shape.field.definition.start_byte..nested_shape.field.definition.end_byte],
            "nested"
        );
        assert_eq!(
            nested_shape
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["enabled"]
        );
        assert_eq!(report.aliases.len(), 3);
        let alias = report.aliases[0];
        assert_eq!(
            &source[alias.binding.start_byte..alias.binding.end_byte],
            "alias"
        );
        assert_eq!(
            &source[alias.target.start_byte..alias.target.end_byte],
            "settings"
        );
        assert_eq!(alias.direct_child, None);
        assert_eq!(alias.direct_grandchild, None);

        let nested_alias = report.aliases[1];
        assert_eq!(
            &source[nested_alias.binding.start_byte..nested_alias.binding.end_byte],
            "nested_alias"
        );
        assert_eq!(
            &source[nested_alias.target.start_byte..nested_alias.target.end_byte],
            "settings"
        );
        assert_eq!(
            nested_alias
                .direct_child
                .map(|span| &source[span.start_byte..span.end_byte]),
            Some("nested")
        );
        assert_eq!(nested_alias.direct_grandchild, None);

        let deeper_alias = report.aliases[2];
        assert_eq!(
            &source[deeper_alias.binding.start_byte..deeper_alias.binding.end_byte],
            "deeper_alias"
        );
        assert_eq!(
            &source[deeper_alias.target.start_byte..deeper_alias.target.end_byte],
            "settings"
        );
        assert_eq!(
            deeper_alias
                .direct_child
                .map(|span| &source[span.start_byte..span.end_byte]),
            Some("nested")
        );
        assert_eq!(
            deeper_alias
                .direct_grandchild
                .map(|span| &source[span.start_byte..span.end_byte]),
            Some("enabled")
        );
        assert!(report.aliases.iter().all(|alias| {
            &source[alias.binding.start_byte..alias.binding.end_byte] != "too_deep_alias"
        }));

        let runtime = Runtime::default();
        assert_eq!(runtime.static_record_shape_report(source).unwrap(), report);
    }

    #[test]
    fn static_record_metadata_retains_only_exact_unambiguous_direct_nested_literals() {
        let source = "let exact = {\n\
                      child: {value: 1, nested: {ignored: {too_deep: true}}},\n\
                      parenthesized: ({value: 1}),\n\
                      computed: {value: 1}.value\n\
                      }\n\
                      let duplicate = {child: {first: true}, child: {second: true}}\n\
                      let scalar = {value: true}\n\
                      let child_duplicate = {child: {first: true, first: false}}\n\
                      let grandchild_duplicate = {child: {nested: {first: true, first: false}}}";
        let report = static_record_shape_report(source).expect("source is within default limits");

        assert_eq!(report.shapes.len(), 5);
        let exact = &report.shapes[0];
        assert_eq!(exact.direct_field_shapes.len(), 1);
        let child = &exact.direct_field_shapes[0];
        assert_eq!(child.field.name, "child");
        assert_eq!(
            child
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["value", "nested"]
        );
        assert_eq!(child.direct_field_shapes.len(), 1);
        let nested = &child.direct_field_shapes[0];
        assert_eq!(nested.field.name, "nested");
        assert_eq!(
            nested
                .fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["ignored"]
        );
        assert!(
            nested.direct_field_shapes.is_empty(),
            "static record metadata must stop after two direct child levels"
        );
        assert!(exact
            .direct_field_shapes
            .iter()
            .all(|child| child.field.name != "parenthesized" && child.field.name != "computed"));
        assert!(report.shapes[1].direct_field_shapes.is_empty());
        assert!(report.shapes[2].direct_field_shapes.is_empty());
        assert!(report.shapes[3].direct_field_shapes.is_empty());
        assert_eq!(report.shapes[4].direct_field_shapes.len(), 1);
        assert!(report.shapes[4].direct_field_shapes[0]
            .direct_field_shapes
            .is_empty());
    }

    #[test]
    fn static_record_shapes_stop_before_a_syntax_diagnostic_and_signal_bounds() {
        let invalid = "let before = {value: 1}\n@\nlet after = {value: 2}";
        let invalid_report = static_record_shape_report(invalid).unwrap();
        assert_eq!(
            invalid_report.valid_prefix_end_byte,
            invalid.find('@').unwrap()
        );
        assert_eq!(invalid_report.shapes.len(), 1);
        assert_eq!(
            &invalid[invalid_report.shapes[0].binding.start_byte
                ..invalid_report.shapes[0].binding.end_byte],
            "before"
        );

        let mut bounded = String::new();
        for index in 0..=MAX_STATIC_RECORD_SHAPES {
            bounded.push_str(&format!("let record_{index} = {{field: {index}}}\n"));
        }
        let bounded_report = static_record_shape_report(&bounded).unwrap();
        assert_eq!(bounded_report.shapes.len(), MAX_STATIC_RECORD_SHAPES);
        assert!(bounded_report.truncated);
        assert_eq!(bounded_report.shapes[0].fields.len(), 1);
        assert_eq!(
            bounded_report.shapes.last().unwrap().fields[0].name,
            "field"
        );

        let mut too_many_aliases = String::from("let root = {field: 0}\n");
        for index in 0..=MAX_STATIC_RECORD_ALIASES {
            too_many_aliases.push_str(&format!("let alias_{index} = root\n"));
        }
        let alias_bounded_report = static_record_shape_report(&too_many_aliases).unwrap();
        assert_eq!(alias_bounded_report.shapes.len(), 1);
        assert_eq!(
            alias_bounded_report.aliases.len(),
            MAX_STATIC_RECORD_ALIASES
        );
        assert!(alias_bounded_report.aliases_truncated);
        assert_eq!(
            &too_many_aliases[alias_bounded_report.aliases[0].binding.start_byte
                ..alias_bounded_report.aliases[0].binding.end_byte],
            "alias_0"
        );
        assert_eq!(
            &too_many_aliases[alias_bounded_report
                .aliases
                .last()
                .unwrap()
                .target
                .start_byte
                ..alias_bounded_report.aliases.last().unwrap().target.end_byte],
            "root"
        );

        let mut too_many_fields = String::from("let oversized = {");
        for index in 0..=MAX_STATIC_RECORD_FIELDS {
            if index > 0 {
                too_many_fields.push_str(", ");
            }
            too_many_fields.push_str(&format!("field_{index}: {index}"));
        }
        too_many_fields.push('}');
        let field_bounded_report = static_record_shape_report(&too_many_fields).unwrap();
        assert!(field_bounded_report.shapes.is_empty());
        assert!(field_bounded_report.truncated);

        let mut too_many_child_fields = String::from("let oversized_child = {child: {");
        for index in 0..MAX_STATIC_RECORD_FIELDS {
            if index > 0 {
                too_many_child_fields.push_str(", ");
            }
            too_many_child_fields.push_str(&format!("field_{index}: {index}"));
        }
        too_many_child_fields.push_str("}}");
        let child_field_bounded_report =
            static_record_shape_report(&too_many_child_fields).unwrap();
        assert!(child_field_bounded_report.shapes.is_empty());
        assert!(child_field_bounded_report.truncated);

        let mut too_many_grandchild_fields =
            String::from("let oversized_grandchild = {child: {grandchild: {");
        for index in 0..MAX_STATIC_RECORD_FIELDS {
            if index > 0 {
                too_many_grandchild_fields.push_str(", ");
            }
            too_many_grandchild_fields.push_str(&format!("field_{index}: {index}"));
        }
        too_many_grandchild_fields.push_str("}}}");
        let grandchild_field_bounded_report =
            static_record_shape_report(&too_many_grandchild_fields).unwrap();
        assert!(grandchild_field_bounded_report.shapes.is_empty());
        assert!(grandchild_field_bounded_report.truncated);
    }

    #[test]
    fn import_reports_stop_at_the_first_syntax_diagnostic() {
        let source = "use mod.tool\n@\nuse mod.std.assert";

        let report = module_import_report(source).expect("source is within default limits");

        assert_eq!(report.valid_prefix_end_byte, source.find('@').unwrap());
        assert_eq!(report.imports.len(), 1);
        assert_eq!(report.imports[0].path, ["mod", "tool"]);
        assert!(!report.truncated);
    }

    #[test]
    fn import_reports_reject_a_path_with_trailing_statement_tokens() {
        let source = "use mod.tool unexpected";

        let report = module_import_report(source).expect("source is within default limits");

        assert_eq!(
            report.valid_prefix_end_byte,
            source.find("unexpected").unwrap()
        );
        assert!(report.imports.is_empty());
        assert!(!report.truncated);
    }

    #[test]
    fn import_reports_have_a_fixed_bound_and_truncation_signal() {
        let mut source = String::new();
        for index in 0..=MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }

        let report = module_import_report(&source).expect("generated source is canonical");

        assert_eq!(report.imports.len(), MAX_MODULE_IMPORTS);
        assert!(report.truncated);
        assert_eq!(report.imports[0].path, ["mod", "module_0"]);
        assert_eq!(report.imports.last().unwrap().path, ["mod", "module_1023"]);
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

        let invalid_middle = "let marker = \"🙂\"\r\nlet alpha = 1\r\nalpha\r\n@\r\nalpha";
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
            "and",
            "or",
            "is",
            "mut",
            "me",
            "scope",
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
    fn formatter_preserves_numeric_field_access_separator() {
        let source = "let value = 1 .field";
        let formatted = format_source(source).unwrap();

        assert_eq!(formatted, "let value = 1 .field\n");
        assert!(check_syntax(&formatted).unwrap().valid);
        assert_eq!(format_source(&formatted).unwrap(), formatted);
    }

    #[test]
    fn canonical_profile_rejects_bare_carriage_returns_before_vm_preflight() {
        let source = "true\r[]";

        let canonical =
            check_syntax_named("line-endings.splash", source, ExecutionLimits::default()).unwrap();
        assert!(!canonical.valid);
        assert_eq!(canonical.diagnostics.len(), 1);
        assert!(canonical.diagnostics[0]
            .message
            .contains("bare carriage returns are not supported"));

        let compatibility =
            check_vm_compatibility_named("line-endings.splash", source, ExecutionLimits::default())
                .unwrap();
        assert!(!compatibility.valid);
    }

    #[test]
    fn canonical_profile_matches_vm_block_comment_terminators() {
        // The Makepad streaming tokenizer does not let the second `*` in
        // `**/` form an overlapping block-comment terminator.
        let source = "/*//**///*//";

        let profile =
            check_syntax_named("comment.splash", source, ExecutionLimits::default()).unwrap();
        let compatibility =
            check_vm_compatibility_named("comment.splash", source, ExecutionLimits::default())
                .unwrap();

        assert!(!profile.valid);
        assert!(!compatibility.valid);
    }

    #[test]
    fn canonical_profile_rejects_adjacent_numeric_field_access() {
        let source = "(5.ci)";
        let profile =
            check_syntax_named("numeric-field.splash", source, ExecutionLimits::default()).unwrap();
        let compatibility = check_vm_compatibility_named(
            "numeric-field.splash",
            source,
            ExecutionLimits::default(),
        )
        .unwrap();

        assert!(!profile.valid);
        assert!(profile.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("numeric literal decimal points must be followed by a digit")
        }));
        assert!(!compatibility.valid);
    }

    #[test]
    fn canonical_conditions_require_parenthesized_control_expressions() {
        let source = "if if t trute{}\n";
        let report =
            check_syntax_named("condition.splash", source, ExecutionLimits::default()).unwrap();

        assert!(!report.valid);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.message.contains(
                "control expression used as an `if` condition or iterable must be parenthesized",
            )
        }));
    }

    #[test]
    fn canonical_conditions_require_parenthesized_lambdas() {
        let unparenthesized = "if || nil {\n0\n}";
        let report = check_syntax(unparenthesized).unwrap();

        assert!(!report.valid);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("lambda used as an `if` condition or iterable must be parenthesized")
        }));

        let parenthesized = "if (|| nil) {\n0\n}";
        let report = check_syntax(parenthesized).unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn canonical_conditional_branches_require_lambda_blocks() {
        let unparenthesized = "if true |value| value";
        let report = check_syntax(unparenthesized).unwrap();

        assert!(!report.valid);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("a lambda used as a conditional branch must be written in a block")
        }));

        let block = "if true {\n|value| value\n}";
        let report = check_syntax(block).unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
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
            "let field = 1 .value\n\
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
    fn rejects_contextual_makepad_words_that_would_change_vm_parsing() {
        let report = check_syntax("or\nor\n").unwrap();
        assert!(!report.valid);
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("reserved words")));

        for source in [
            "let and = 1",
            "let is = 1",
            "let mut = 1",
            "let me = 1",
            "let scope = 1",
        ] {
            let report = check_syntax(source).unwrap();

            assert!(!report.valid, "unexpectedly accepted: {source}");
            assert!(!report.diagnostics.is_empty());
        }
    }

    #[test]
    fn canonical_catch_remains_an_identifier_outside_try() {
        let report = check_syntax("let catch = 1\ncatch").unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
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
    fn rejects_zero_string_limit() {
        let limits = ExecutionLimits {
            max_string_bytes: 0,
            ..ExecutionLimits::default()
        };

        assert_eq!(
            check_syntax_named("strings.splash", "true", limits).unwrap_err(),
            RuntimeError::InvalidLimits("max_string_bytes must be greater than zero")
        );
    }

    #[test]
    fn rejects_zero_heap_limit() {
        let limits = ExecutionLimits {
            max_heap_bytes: 0,
            ..ExecutionLimits::default()
        };

        assert_eq!(
            check_syntax_named("heap.splash", "true", limits).unwrap_err(),
            RuntimeError::InvalidLimits("max_heap_bytes must be greater than zero")
        );
    }

    #[test]
    fn rejects_zero_stack_value_limit() {
        let limits = ExecutionLimits {
            max_stack_values: 0,
            ..ExecutionLimits::default()
        };

        assert_eq!(
            check_syntax_named("stack.splash", "true", limits).unwrap_err(),
            RuntimeError::InvalidLimits("max_stack_values must be greater than zero")
        );
    }

    #[test]
    fn rejects_zero_call_frame_limit() {
        let limits = ExecutionLimits {
            max_call_frames: 0,
            ..ExecutionLimits::default()
        };

        assert_eq!(
            check_syntax_named("frames.splash", "true", limits).unwrap_err(),
            RuntimeError::InvalidLimits("max_call_frames must be greater than zero")
        );
    }

    #[test]
    fn runtime_rejects_a_heap_limit_below_live_vm_storage() {
        let mut runtime = Runtime::default();
        let actual = runtime.accounted_heap_bytes();
        assert!(actual > 0);

        let mut limits = runtime.limits();
        limits.max_heap_bytes = actual - 1;
        assert_eq!(
            runtime.set_limits(limits),
            Err(RuntimeError::HeapLimitExceeded {
                actual,
                maximum: actual - 1,
            })
        );
    }

    #[test]
    fn runtime_rejects_a_heap_limit_below_bootstrap_storage() {
        let mut baseline_runtime = Runtime::default();
        let baseline = baseline_runtime.accounted_heap_bytes();
        assert!(baseline > 0);

        let limits = ExecutionLimits {
            max_heap_bytes: baseline - 1,
            ..ExecutionLimits::default()
        };
        let error = match Runtime::with_limits((), (), limits) {
            Ok(_) => panic!("a cap below the runtime baseline must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            RuntimeError::HeapLimitExceeded {
                actual: baseline,
                maximum: baseline - 1,
            }
        );
    }

    #[test]
    fn runtime_accepts_its_bootstrap_heap_baseline() {
        let mut baseline_runtime = Runtime::default();
        let baseline = baseline_runtime.accounted_heap_bytes();
        let limits = ExecutionLimits {
            max_heap_bytes: baseline,
            ..ExecutionLimits::default()
        };

        assert!(Runtime::with_limits((), (), limits).is_ok());
    }

    #[test]
    fn runtime_bounds_sparse_array_growth_without_catch_recovery() {
        let mut runtime = Runtime::default();
        let baseline = runtime.accounted_heap_bytes();
        let mut limits = runtime.limits();
        limits.max_heap_bytes = baseline + 256 * 1024;
        runtime.set_limits(limits).unwrap();

        let exceeded = runtime
            .eval("let values = []\ntry values[268435456] = 1 catch \"recovered\"")
            .unwrap();

        assert!(!exceeded.completed());
        assert!(exceeded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("heap allocation limit")));
        assert!(runtime.accounted_heap_bytes() <= limits.max_heap_bytes);

        let recovered = runtime.eval("2").unwrap();
        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(recovered.value.as_u40(), Some(2));
    }

    #[test]
    fn runtime_bounds_sparse_object_growth_without_catch_recovery() {
        let mut runtime = Runtime::default();
        let baseline = runtime.accounted_heap_bytes();
        let mut limits = runtime.limits();
        limits.max_heap_bytes = baseline + 256 * 1024;
        runtime.set_limits(limits).unwrap();

        let exceeded = runtime
            .eval("let values = {}\ntry values[268435456] = 1 catch \"recovered\"")
            .unwrap();

        assert!(!exceeded.completed());
        assert!(exceeded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("heap allocation limit")));
        assert!(runtime.accounted_heap_bytes() <= limits.max_heap_bytes);

        let recovered = runtime.eval("2").unwrap();
        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(recovered.value.as_u40(), Some(2));
    }

    #[test]
    fn runtime_bounds_operand_stack_growth_without_catch_recovery() {
        let limits = ExecutionLimits {
            max_stack_values: 1,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), limits).unwrap();

        let exceeded = runtime.eval("try (1 + 2) catch 99").unwrap();

        assert!(!exceeded.completed());
        assert!(exceeded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("operand stack limit exceeded")));

        let recovered = runtime.eval("2").unwrap();
        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(recovered.value.as_u40(), Some(2));
    }

    #[test]
    fn runtime_bounds_recursive_call_frames_without_catch_recovery() {
        let limits = ExecutionLimits {
            max_call_frames: 4,
            instruction_limit: 1_024,
            budget_sample_interval: 64,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), limits).unwrap();

        let exceeded = runtime
            .eval(
                "fn recurse(value) {\n\
                 recurse(value + 1)\n\
                 }\n\
                 try recurse(0) catch 99",
            )
            .unwrap();

        assert!(!exceeded.completed());
        assert!(exceeded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("call frame limit exceeded")));

        let recovered = runtime.eval("2").unwrap();
        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(recovered.value.as_u40(), Some(2));
    }

    #[test]
    fn call_frame_limit_includes_the_root_evaluation_frame() {
        let limits = ExecutionLimits {
            max_call_frames: 1,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), limits).unwrap();

        let root_only = runtime.eval("2").unwrap();
        assert!(root_only.completed(), "{:?}", root_only.diagnostics);

        let exceeded = runtime
            .eval("fn one() {\n1\n}\ntry one() catch 99")
            .unwrap();
        assert!(!exceeded.completed());
        assert!(exceeded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("call frame limit exceeded")));
    }

    #[test]
    fn fresh_evaluation_discards_stale_vm_execution_limit_signals() {
        let mut runtime = Runtime::default();
        runtime.configure(|vm| {
            vm.with_stack_value_limit(1, |vm| {
                vm.thread_mut().push_stack_unchecked(1.into());
                vm.thread_mut().push_stack_unchecked(2.into());
                vm.thread_mut().pop_stack_value();
            });
        });

        let evaluation = runtime.eval("2").unwrap();
        assert!(evaluation.completed(), "{:?}", evaluation.diagnostics);
        assert_eq!(evaluation.value.as_u40(), Some(2));
    }

    #[test]
    fn heap_limit_bounds_total_string_storage_after_individual_strings_pass() {
        let mut runtime = Runtime::default();
        let baseline = runtime.accounted_heap_bytes();
        let mut limits = runtime.limits();
        limits.max_heap_bytes = baseline + 8 * 1024;
        runtime.set_limits(limits).unwrap();

        let exceeded = runtime
            .eval(
                "let payload = \"x\"\n\
                 let index = 0\n\
                 while (index < 14) {\n\
                     payload += payload\n\
                     index += 1\n\
                 }\n\
                 payload",
            )
            .unwrap();

        assert!(!exceeded.completed());
        assert!(exceeded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("heap allocation limit")));

        assert!(matches!(
            runtime.eval("2"),
            Err(RuntimeError::HeapLimitExceeded { maximum, .. }) if maximum == limits.max_heap_bytes
        ));
    }

    #[test]
    fn collection_recovers_after_a_heap_limit_failure() {
        let mut runtime = Runtime::default();
        let baseline = runtime.accounted_heap_bytes();
        let mut limits = runtime.limits();
        limits.max_heap_bytes = baseline + 8 * 1024;
        runtime.set_limits(limits).unwrap();

        let exceeded = runtime
            .eval(
                "let payload = \"x\"\n\
                 let index = 0\n\
                 while (index < 14) {\n\
                     payload += payload\n\
                     index += 1\n\
                 }\n\
                 payload",
            )
            .unwrap();
        assert!(!exceeded.completed());

        runtime.collect_garbage();
        assert!(runtime.accounted_heap_bytes() <= limits.max_heap_bytes);

        let recovered = runtime.eval("2").unwrap();
        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(recovered.value.as_u40(), Some(2));
    }

    #[test]
    fn heap_limit_bounds_host_json_globals() {
        let mut runtime = Runtime::default();
        let baseline = runtime.accounted_heap_bytes();
        let mut limits = runtime.limits();
        limits.max_heap_bytes = baseline + 4 * 1024;
        runtime.set_limits(limits).unwrap();

        let values = JsonValue::Array((0..2_048).map(JsonValue::from).collect());
        let error = runtime
            .set_json_global(
                "workflow",
                &values,
                DEFAULT_MAX_JSON_DATA_BYTES,
                DEFAULT_MAX_JSON_DATA_DEPTH,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::HeapLimitExceeded { maximum, .. } if maximum == limits.max_heap_bytes
        ));
    }

    #[test]
    fn json_global_drains_a_string_failure_when_heap_failure_takes_precedence() {
        let mut runtime = Runtime::default();
        let baseline = runtime.accounted_heap_bytes();
        let mut limits = runtime.limits();
        limits.max_string_bytes = 1;
        limits.max_heap_bytes = baseline + 1;
        runtime.set_limits(limits).unwrap();

        let error = runtime
            .set_json_global(
                "workflow",
                &JsonValue::Array(vec![JsonValue::String("payload".to_owned())]),
                DEFAULT_MAX_JSON_DATA_BYTES,
                DEFAULT_MAX_JSON_DATA_DEPTH,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::HeapLimitExceeded { maximum, .. } if maximum == limits.max_heap_bytes
        ));

        runtime.collect_garbage();
        runtime
            .set_json_global(
                "workflow",
                &JsonValue::Null,
                DEFAULT_MAX_JSON_DATA_BYTES,
                DEFAULT_MAX_JSON_DATA_DEPTH,
            )
            .unwrap();
    }

    #[test]
    fn runtime_bounds_new_string_values_without_catch_recovery() {
        let limits = ExecutionLimits {
            max_string_bytes: 32,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), limits).unwrap();
        let exact_limit = runtime
            .eval(
                "let payload = \"x\"\n\
                 let index = 0\n\
                 while (index < 5) {\n\
                     payload += payload\n\
                     index += 1\n\
                 }\n\
                 payload",
            )
            .unwrap();

        assert!(exact_limit.completed(), "{:?}", exact_limit.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    exact_limit.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        );

        let exceeded = runtime
            .eval(
                "let payload = \"x\"\n\
                 let index = 0\n\
                 while (index < 5) {\n\
                     payload += payload\n\
                     index += 1\n\
                 }\n\
                 try payload + payload catch \"recovered\"",
            )
            .unwrap();

        assert!(!exceeded.completed());
        assert!(exceeded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("string allocation limit")));
    }

    #[test]
    fn runtime_bounds_literal_strings_before_execution() {
        let limits = ExecutionLimits {
            max_string_bytes: 4,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), limits).unwrap();
        let exceeded = runtime.eval("\"fives\"").unwrap();

        assert!(!exceeded.completed());
        assert!(exceeded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("string allocation limit")));
    }

    #[test]
    fn string_limit_updates_and_bounds_host_json_globals() {
        let mut runtime = Runtime::default();
        let mut limits = runtime.limits();
        limits.max_string_bytes = 4;
        runtime.set_limits(limits).unwrap();

        runtime
            .set_json_global(
                "workflow",
                &serde_json::json!({"v": "four"}),
                DEFAULT_MAX_JSON_DATA_BYTES,
                DEFAULT_MAX_JSON_DATA_DEPTH,
            )
            .unwrap();
        let injected = runtime.eval("workflow.v").unwrap();
        assert!(injected.completed(), "{:?}", injected.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    injected.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("four")
        );

        assert_eq!(
            runtime
                .set_json_global(
                    "workflow",
                    &serde_json::json!({"v": "fives"}),
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap_err(),
            RuntimeError::StringLimitExceeded { maximum: 4 }
        );

        runtime.configure(|vm| {
            let encoded = vm.bx.heap.new_array_from_vec_u8(b"\"fives\"".to_vec());
            vm.set_injected_global(vm::LiveId::from_str("encoded"), encoded.into());
        });
        let parsed = runtime.eval("encoded.parse_json()").unwrap();
        assert!(!parsed.completed());
        assert!(
            parsed
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("string allocation limit")),
            "{:?}",
            parsed.diagnostics
        );

        let exceeded = runtime
            .eval(
                "let payload = \"x\"\n\
                 let index = 0\n\
                 while (index < 3) {\n\
                     payload += payload\n\
                     index += 1\n\
                 }\n\
                 payload",
            )
            .unwrap();
        assert!(!exceeded.completed());
        assert!(exceeded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("string allocation limit")));

        let recovered = runtime.eval("2").unwrap();
        assert!(recovered.completed(), "{:?}", recovered.diagnostics);
        assert_eq!(recovered.value.as_u40(), Some(2));
    }

    #[test]
    fn rejects_a_time_budget_interval_that_cannot_sample_before_instruction_limit() {
        let limits = ExecutionLimits {
            instruction_limit: 64,
            budget_sample_interval: 64,
            ..ExecutionLimits::default()
        };

        assert_eq!(
            check_syntax_named("limits.splash", "true", limits).unwrap_err(),
            RuntimeError::InvalidLimits(
                "budget_sample_interval must be less than instruction_limit"
            )
        );
    }

    #[test]
    fn stops_runaway_code_at_the_instruction_limit() {
        let limits = ExecutionLimits {
            instruction_limit: 128,
            budget_sample_interval: 64,
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
    fn refuses_limit_changes_while_a_time_budget_yield_is_paused() {
        let original = ExecutionLimits {
            instruction_limit: 100_000,
            soft_timeout: Duration::from_nanos(1),
            hard_timeout: Duration::from_secs(1),
            budget_sample_interval: 1,
            ..ExecutionLimits::default()
        };
        let mut runtime = Runtime::with_limits((), (), original).unwrap();
        let evaluation = runtime.eval("loop {}").unwrap();
        assert!(evaluation.suspended);

        let replacement = ExecutionLimits {
            instruction_limit: 64,
            budget_sample_interval: 1,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            runtime.set_limits(replacement),
            Err(RuntimeError::EvaluationInProgress)
        );
        assert_eq!(runtime.limits(), original);
    }

    #[test]
    fn does_not_expose_unreviewed_makepad_platform_or_primitive_apis() {
        for source in [
            "use mod.fs\nfs.read(\"/etc/passwd\")",
            "use mod.run\nrun.child({cmd:\"whoami\"})",
            "use mod.net\nnet.socket_stream(\"example.com\", 443)",
            "use mod.std.print\nprint(\"blocked\")",
            "use mod.std.println\nprintln(\"blocked\")",
            "use mod.std.log\nlog(\"blocked\")",
            "use mod.std.regex\nregex(\".\").test(\"blocked\")",
            "use mod.std.set_type_default\nset_type_default({})",
            "use mod.std\nstd.assert = || nil",
            "use mod.std\nstd.Range.blocked = true",
            "\"<p>blocked</p>\".parse_html()",
            "\"a,b\".split(\",\")",
            "\"abc\".to_chars()",
            "let value = 1\nvalue.to_string()",
            "let value = 1\nvalue.to_number()",
            "let value = 1\nvalue.ty()",
            "let values = [1, 2]\nvalues.push(3)",
            "let values = [1, 2]\nvalues.retain(|value| value > 1)",
            "let record = {first: 1}\nrecord.proto()",
            "let record = {first: 1}\nrecord.gc_id()",
            "let record = {first: 1}\nrecord.freeze_api()",
            "use mod.gc\ngc.run()",
            "use mod.math\nmath.sin(0)",
            "use mod.shader\nshader.instance(0)",
            "use mod.pod\npod.f32",
        ] {
            let mut runtime = Runtime::default();
            let report = runtime.eval(source).unwrap();

            assert!(!report.succeeded(), "unexpectedly evaluated: {source}");
            assert!(!report.diagnostics.is_empty());
        }

        let mut runtime = Runtime::default();
        let report = runtime
            .eval("use mod.std.assert\nassert(true)\nlet result = {total: 42}\nresult")
            .unwrap();
        assert!(report.completed(), "{:?}", report.diagnostics);

        let mut runtime = Runtime::default();
        let report = runtime
            .eval_vm_compatibility("use mod.std.print\nprint(\"blocked\")")
            .unwrap();
        assert!(!report.succeeded());
        assert!(!report.diagnostics.is_empty());
    }

    #[test]
    fn exposes_frozen_bounded_standard_json() {
        let mut runtime = Runtime::default();
        let report = runtime
            .eval(
                "use mod.std.assert\n\
                 use mod.std.json\n\
                 let parsed = json.parse(\"{\\\"answer\\\":42}\")\n\
                 assert(parsed.answer == 42)\n\
                 json.stringify(parsed)",
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
            serde_json::json!("{\"answer\":42}")
        );

        let bytes = runtime
            .eval("use mod.std.json\njson.parse(\"{\\\"bytes\\\":true}\".to_bytes()).bytes")
            .unwrap();
        assert!(bytes.completed(), "{:?}", bytes.diagnostics);
        assert_eq!(bytes.value.as_bool(), Some(true));

        let mut namespace_runtime = Runtime::default();
        let namespace = namespace_runtime
            .eval("use mod.std\nstd.json.parse(\"{\\\"total\\\":42}\").total")
            .unwrap();
        assert!(namespace.completed(), "{:?}", namespace.diagnostics);
        assert_eq!(namespace.value.as_number(), Some(42.0));

        let mutation = runtime
            .eval("use mod.std.json\njson.parse = || nil")
            .unwrap();
        assert!(!mutation.succeeded());
        assert!(!mutation.diagnostics.is_empty());

        let preserved = runtime
            .eval("use mod.std.json\njson.stringify({preserved: true})")
            .unwrap();
        assert!(preserved.completed(), "{:?}", preserved.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    preserved.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("{\"preserved\":true}")
        );

        let mut bounded_source = String::from("use mod.std.json\nlet value = \"x\"\n");
        for _ in 0..8 {
            bounded_source.push_str("value += value\n");
        }
        bounded_source.push_str("try json.stringify(value) catch \"bounded\"");
        let mut bounded_runtime = Runtime::default();
        let mut limits = bounded_runtime.limits();
        limits.max_source_bytes = bounded_source.len();
        bounded_runtime.set_limits(limits).unwrap();
        let bounded = bounded_runtime.eval(&bounded_source).unwrap();
        assert!(bounded.completed(), "{:?}", bounded.diagnostics);
        assert_eq!(
            bounded_runtime
                .script_value_as_json(
                    bounded.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("bounded")
        );
    }

    #[test]
    fn exposes_frozen_bounded_standard_text() {
        let mut runtime = Runtime::default();
        let report = runtime
            .eval(
                "use mod.std.assert\n\
                 use mod.std.text\n\
                 let value = text.trim(\"  MiXeD  \")\n\
                 assert(value == \"MiXeD\")\n\
                 assert(text.lower(value) == \"mixed\")\n\
                 assert(text.upper(\"abc\") == \"ABC\")\n\
                 assert(text.len(\"🙂\") == 1)\n\
                 assert(text.slice(\"a🙂b\", 1, 2) == \"🙂\")\n\
                 assert(text.slice(\"a🙂b\", 3, 3) == \"\")\n\
                 assert(text.index_of(\"a🙂b🙂\", \"🙂\") == 1)\n\
                 assert(text.index_of(\"a🙂b🙂\", \"b\") == 2)\n\
                 assert(text.index_of(\"splash\", \"z\") == -1)\n\
                 assert(text.index_of(\"splash\", \"\") == 0)\n\
                 assert(text.last_index_of(\"a🙂b🙂\", \"🙂\") == 3)\n\
                 assert(text.last_index_of(\"a🙂b🙂\", \"b\") == 2)\n\
                 assert(text.last_index_of(\"splash\", \"z\") == -1)\n\
                 assert(text.last_index_of(\"a🙂b\", \"\") == 3)\n\
                 assert(text.contains(value, \"Xe\"))\n\
                 assert(text.starts_with(value, \"Mi\"))\n\
                 assert(text.ends_with(value, \"eD\"))\n\
                 assert(text.split(\"a,,b,\", \",\") == [\"a\", \"\", \"b\", \"\"])\n\
                 assert(text.join([\"a\", \"\", \"b\", \"\"], \",\") == \"a,,b,\")\n\
                 assert(text.join(text.split(\"a,,b,\", \",\"), \",\") == \"a,,b,\")\n\
                 assert(text.join([\"a\", \"b\", \"c\"], \"\") == \"abc\")\n\
                 text.replace_all(\"a-b-a\", \"a\", \"x\")",
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
            serde_json::json!("x-b-x")
        );

        let mut namespace_runtime = Runtime::default();
        let namespace = namespace_runtime
            .eval("use mod.std\nstd.text.last_index_of(\"a🙂b🙂\", \"🙂\")")
            .unwrap();
        assert!(namespace.completed(), "{:?}", namespace.diagnostics);
        assert_eq!(namespace.value.as_number(), Some(3.0));

        let mutation = runtime
            .eval("use mod.std.text\ntext.last_index_of = || nil")
            .unwrap();
        assert!(!mutation.succeeded());
        assert!(!mutation.diagnostics.is_empty());

        let preserved = runtime
            .eval("use mod.std.text\ntext.last_index_of(\"a-b-a\", \"a\")")
            .unwrap();
        assert!(preserved.completed(), "{:?}", preserved.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    preserved.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(4)
        );

        let invalid_predicate = runtime
            .eval("use mod.std.text\ntext.starts_with(\"splash\", 1)")
            .unwrap();
        assert!(!invalid_predicate.succeeded());
        assert!(invalid_predicate
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("`prefix`")));

        let invalid_index_of = runtime
            .eval("use mod.std.text\ntry text.index_of(\"splash\", 1) catch \"invalid\"")
            .unwrap();
        assert!(
            invalid_index_of.completed(),
            "{:?}",
            invalid_index_of.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_index_of.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid")
        );

        let invalid_index_of_value = runtime
            .eval("use mod.std.text\ntry text.index_of(1, \"splash\") catch \"invalid\"")
            .unwrap();
        assert!(
            invalid_index_of_value.completed(),
            "{:?}",
            invalid_index_of_value.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_index_of_value.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid")
        );

        let invalid_last_index_of = runtime
            .eval("use mod.std.text\ntry text.last_index_of(\"splash\", 1) catch \"invalid\"")
            .unwrap();
        assert!(
            invalid_last_index_of.completed(),
            "{:?}",
            invalid_last_index_of.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_last_index_of.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid")
        );

        let invalid_delimiter_type = runtime
            .eval("use mod.std.text\ntext.split(\"splash\", 1)")
            .unwrap();
        assert!(!invalid_delimiter_type.succeeded());
        assert!(invalid_delimiter_type
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("`delimiter`")));

        let invalid_slice_index = runtime
            .eval("use mod.std.text\ntry text.slice(\"splash\", -1, 1) catch \"invalid\"")
            .unwrap();
        assert!(
            invalid_slice_index.completed(),
            "{:?}",
            invalid_slice_index.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_slice_index.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid")
        );

        let invalid_slice_range = runtime
            .eval("use mod.std.text\ntry text.slice(\"splash\", 3, 2) catch \"range\"")
            .unwrap();
        assert!(
            invalid_slice_range.completed(),
            "{:?}",
            invalid_slice_range.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_slice_range.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("range")
        );

        let invalid_slice_value = runtime
            .eval("use mod.std.text\ntext.slice(1, -1, 1)")
            .unwrap();
        assert!(!invalid_slice_value.succeeded());
        assert!(invalid_slice_value
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("`value`")));

        let invalid_join_values = runtime
            .eval("use mod.std.text\ntext.join(\"splash\", \",\")")
            .unwrap();
        assert!(!invalid_join_values.succeeded());
        assert!(invalid_join_values
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("`values` to be an array")));

        let invalid_join_item = runtime
            .eval("use mod.std.text\ntext.join([\"splash\", 1], \",\")")
            .unwrap();
        assert!(!invalid_join_item.succeeded());
        assert!(invalid_join_item
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("contain only strings")));

        let invalid_join_separator = runtime
            .eval("use mod.std.text\ntext.join([\"splash\"], 1)")
            .unwrap();
        assert!(!invalid_join_separator.succeeded());
        assert!(invalid_join_separator
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("`separator`")));

        let invalid_delimiter = runtime
            .eval("use mod.std.text\ntry text.split(\"splash\", \"\") catch \"empty\"")
            .unwrap();
        assert!(
            invalid_delimiter.completed(),
            "{:?}",
            invalid_delimiter.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_delimiter.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("empty")
        );

        let too_many_segments = format!("{}x", "x,".repeat(MAX_STANDARD_ARRAY_ITEMS));
        let mut segment_limit_runtime = Runtime::default();
        let segment_limit = segment_limit_runtime
            .eval(&format!(
                "use mod.std.text\ntry text.split(\"{too_many_segments}\", \",\") catch \"limit\""
            ))
            .unwrap();
        assert!(segment_limit.completed(), "{:?}", segment_limit.diagnostics);
        assert_eq!(
            segment_limit_runtime
                .script_value_as_json(
                    segment_limit.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("limit")
        );

        let mut join_limit_runtime = Runtime::default();
        let join_limit = join_limit_runtime
            .eval(&format!(
                "use mod.std.text\nlet values = []\nvalues[{MAX_STANDARD_ARRAY_ITEMS}] = \"x\"\ntry text.join(values, \",\") catch \"limit\""
            ))
            .unwrap();
        assert!(join_limit.completed(), "{:?}", join_limit.diagnostics);
        assert_eq!(
            join_limit_runtime
                .script_value_as_json(
                    join_limit.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("limit")
        );

        let limits = ExecutionLimits {
            max_string_bytes: 4,
            ..ExecutionLimits::default()
        };
        let mut bounded_runtime = Runtime::with_limits((), (), limits).unwrap();
        let bounded = bounded_runtime
            .eval("use mod.std.text\ntext.replace_all(\"aa\", \"a\", \"xxxx\")")
            .unwrap();
        assert!(!bounded.completed());
        assert!(bounded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("string allocation limit")));

        let mut bounded_join_runtime = Runtime::with_limits((), (), limits).unwrap();
        let bounded_join = bounded_join_runtime
            .eval("use mod.std.text\ntext.join([\"aa\", \"aa\"], \"x\")")
            .unwrap();
        assert!(!bounded_join.completed());
        assert!(bounded_join
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("string allocation limit")));

        let mut bounded_slice_runtime = Runtime::default();
        bounded_slice_runtime
            .set_json_global(
                "input",
                &serde_json::json!("slice"),
                DEFAULT_MAX_JSON_DATA_BYTES,
                DEFAULT_MAX_JSON_DATA_DEPTH,
            )
            .unwrap();
        let mut slice_limits = bounded_slice_runtime.limits();
        slice_limits.max_string_bytes = 4;
        bounded_slice_runtime.set_limits(slice_limits).unwrap();
        let bounded_slice = bounded_slice_runtime
            .eval("use mod.std.text\ntext.slice(input, 0, 5)")
            .unwrap();
        assert!(!bounded_slice.completed());
        assert!(bounded_slice
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("string allocation limit")));
    }

    #[test]
    fn exposes_frozen_bounded_standard_array() {
        let mut runtime = Runtime::default();
        let report = runtime
            .eval(
                "use mod.std.assert\n\
                 use mod.std.array\n\
                 let input = [1, 2, 3]\n\
                 assert(array.len(input) == 3)\n\
                 assert(array.has_index(input, 0))\n\
                 assert(!array.has_index(input, 3))\n\
                 assert(array.get(input, 1, -1) == 2)\n\
                 assert(array.get(input, 3, \"fallback\") == \"fallback\")\n\
                 let present_nil = [nil]\n\
                 assert(array.has_index(present_nil, 0))\n\
                 assert(array.get(present_nil, 0, \"fallback\") == nil)\n\
                 assert(array.slice(input, 1, 3) == [2, 3])\n\
                 assert(array.concat([1, 2], [3, 4]) == [1, 2, 3, 4])\n\
                 let optional_nested = {answer: 1}\n\
                 let optional = [nil, false, 0, \"\", optional_nested, nil]\n\
                 let compacted = array.compact(optional)\n\
                 assert(array.len(compacted) == 4)\n\
                 assert(compacted[0] == false)\n\
                 assert(compacted[1] == 0)\n\
                 assert(compacted[2] == \"\")\n\
                 assert(array.len(optional) == 6)\n\
                 assert(optional[0] == nil)\n\
                 compacted[3].answer = 2\n\
                 assert(optional_nested.answer == 2)\n\
                 assert(array.flatten([[1, 2], [], [3]]) == [1, 2, 3])\n\
                 let reversed = array.reverse(input)\n\
                 assert(reversed == [3, 2, 1])\n\
                 assert(input == [1, 2, 3])\n\
                 let appended = []\n\
                 assert(array.push(appended, 1) == nil)\n\
                 array.push(appended, 2)\n\
                 assert(appended == [1, 2])\n\
                 let nested = {answer: 1}\n\
                 let copied = array.slice([nested], 0, 1)\n\
                 copied[0].answer = 2\n\
                 assert(nested.answer == 2)\n\
                 let groups = [[1], [2]]\n\
                 let flattened = array.flatten(groups)\n\
                 array.push(flattened, 3)\n\
                 assert(groups == [[1], [2]])\n\
                 let flattened_nested = array.flatten([[nested]])\n\
                 flattened_nested[0].answer = 3\n\
                 assert(nested.answer == 3)\n\
                 reversed",
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
            serde_json::json!([3, 2, 1])
        );

        let mut namespace_runtime = Runtime::default();
        let namespace = namespace_runtime
            .eval(
                "use mod.std\nlet compacted = std.array.compact([nil, [2], nil])\ncompacted[0][0]",
            )
            .unwrap();
        assert!(namespace.completed(), "{:?}", namespace.diagnostics);
        assert_eq!(
            namespace_runtime
                .script_value_as_json(
                    namespace.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(2)
        );

        let mutation = runtime
            .eval("use mod.std.array\narray.compact = || nil")
            .unwrap();
        assert!(!mutation.succeeded());
        assert!(!mutation.diagnostics.is_empty());

        let preserved = runtime
            .eval("use mod.std.array\narray.compact([nil, 1, nil])")
            .unwrap();
        assert!(preserved.completed(), "{:?}", preserved.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    preserved.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!([1])
        );

        let invalid_compact = runtime
            .eval("use mod.std.array\ntry array.compact(\"items\") catch \"invalid\"")
            .unwrap();
        assert!(
            invalid_compact.completed(),
            "{:?}",
            invalid_compact.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_compact.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid")
        );

        let invalid_index = runtime
            .eval("use mod.std.array\ntry array.slice([1], -1, 1) catch \"invalid\"")
            .unwrap();
        assert!(invalid_index.completed(), "{:?}", invalid_index.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_index.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid")
        );

        let invalid_lookup_index = runtime
            .eval("use mod.std.array\ntry array.has_index([1], -1) catch \"invalid\"")
            .unwrap();
        assert!(
            invalid_lookup_index.completed(),
            "{:?}",
            invalid_lookup_index.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_lookup_index.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid")
        );

        let invalid_flatten = runtime
            .eval("use mod.std.array\ntry array.flatten([[1], 2]) catch \"invalid\"")
            .unwrap();
        assert!(
            invalid_flatten.completed(),
            "{:?}",
            invalid_flatten.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_flatten.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid")
        );

        let oversized_len = Runtime::default()
            .eval(&format!(
                "use mod.std.array\n\
                 let values = []\n\
                 values[{MAX_STANDARD_ARRAY_ITEMS}] = 0\n\
                 assert(array.len(values) == {})\n\
                 assert(array.has_index(values, {MAX_STANDARD_ARRAY_ITEMS}))\n\
                 assert(!array.has_index(values, {}))\n\
                 assert(array.get(values, {MAX_STANDARD_ARRAY_ITEMS}, -1) == 0)\n\
                 array.get(values, {}, -1)",
                MAX_STANDARD_ARRAY_ITEMS + 1,
                MAX_STANDARD_ARRAY_ITEMS + 1,
                MAX_STANDARD_ARRAY_ITEMS + 1,
            ))
            .unwrap();
        assert!(oversized_len.completed(), "{:?}", oversized_len.diagnostics);
        assert_eq!(oversized_len.value.as_number(), Some(-1.0));

        let oversized = Runtime::default()
            .eval(&format!(
                "use mod.std.array\n\
                 let values = []\n\
                 values[{MAX_STANDARD_ARRAY_ITEMS}] = 0\n\
                 array.reverse(values)"
            ))
            .unwrap();
        assert!(!oversized.completed());
        assert!(oversized
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("supports at most")));

        let mut compact_limit_runtime = Runtime::default();
        let compact_limit = compact_limit_runtime
            .eval(&format!(
                "use mod.std.array\n\
                 let values = []\n\
                 values[{MAX_STANDARD_ARRAY_ITEMS}] = 0\n\
                 try array.compact(values) catch \"limit\""
            ))
            .unwrap();
        assert!(compact_limit.completed(), "{:?}", compact_limit.diagnostics);
        assert_eq!(
            compact_limit_runtime
                .script_value_as_json(
                    compact_limit.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("limit")
        );

        let oversized_concat = Runtime::default()
            .eval(&format!(
                "use mod.std.array\n\
                 let values = []\n\
                 values[{}] = 0\n\
                 array.concat(values, [1])",
                MAX_STANDARD_ARRAY_ITEMS - 1
            ))
            .unwrap();
        assert!(!oversized_concat.completed());
        assert!(oversized_concat
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("std.array.concat supports at most")));

        let oversized_inner = Runtime::default()
            .eval(&format!(
                "use mod.std.array\n\
                 let inner = []\n\
                 inner[{MAX_STANDARD_ARRAY_ITEMS}] = 0\n\
                 array.flatten([inner])"
            ))
            .unwrap();
        assert!(!oversized_inner.completed());
        assert!(oversized_inner
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("std.array.flatten supports at most")));

        let mut flatten_limit_runtime = Runtime::default();
        let flatten_limit = flatten_limit_runtime
            .eval(&format!(
                "use mod.std.array\n\
                 let left = []\n\
                 left[{}] = 0\n\
                 let right = []\n\
                 right[{}] = 0\n\
                 try array.flatten([left, right]) catch \"limit\"",
                MAX_STANDARD_ARRAY_ITEMS / 2,
                MAX_STANDARD_ARRAY_ITEMS / 2,
            ))
            .unwrap();
        assert!(flatten_limit.completed(), "{:?}", flatten_limit.diagnostics);
        assert_eq!(
            flatten_limit_runtime
                .script_value_as_json(
                    flatten_limit.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("limit")
        );

        let mut push_limit_runtime = Runtime::default();
        let push_limit = push_limit_runtime
            .eval(&format!(
                "use mod.std.array\n\
                 let values = []\n\
                 values[{}] = 0\n\
                 try array.push(values, 1) catch \"limit\"",
                MAX_STANDARD_ARRAY_ITEMS - 1
            ))
            .unwrap();
        assert!(push_limit.completed(), "{:?}", push_limit.diagnostics);
        assert_eq!(
            push_limit_runtime
                .script_value_as_json(
                    push_limit.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("limit")
        );
    }

    #[test]
    fn exposes_frozen_bounded_standard_object() {
        let mut runtime = Runtime::default();
        let report = runtime
            .eval(
                "use mod.std.assert\n\
                 use mod.std.json\n\
                 use mod.std.object\n\
                 let record = {first: 1, second: 2}\n\
                 assert(object.len(record) == 2)\n\
                 assert(object.has(record, \"first\"))\n\
                 assert(!object.has(record, \"missing\"))\n\
                 assert(object.get(record, \"first\", -1) == 1)\n\
                 assert(object.get(record, \"missing\", \"fallback\") == \"fallback\")\n\
                 let present_nil = {value: nil}\n\
                 assert(object.has(present_nil, \"value\"))\n\
                 assert(object.get(present_nil, \"value\", \"fallback\") == nil)\n\
                 let picked_nil = object.pick(present_nil, [\"value\", \"missing\"])\n\
                 assert(object.has(picked_nil, \"value\"))\n\
                 assert(!object.has(picked_nil, \"missing\"))\n\
                 assert(object.get(picked_nil, \"value\", \"fallback\") == nil)\n\
                 assert(object.len(object.pick(record, [])) == 0)\n\
                 assert(object.keys(record) == [\"first\", \"second\"])\n\
                 let pairs = object.entries(record)\n\
                 assert(pairs[0][0] == \"first\")\n\
                 assert(pairs[0][1] == 1)\n\
                 assert(pairs[1][0] == \"second\")\n\
                 assert(pairs[1][1] == 2)\n\
                 assert(object.values(record) == [1, 2])\n\
                 let rebuilt = object.from_entries([[\"third\", 3], [\"first\", 1], [\"third\", 30]])\n\
                 assert(object.keys(rebuilt) == [\"third\", \"first\"])\n\
                 assert(rebuilt.third == 30)\n\
                 let rebuilt_nil = object.from_entries([[\"value\", nil]])\n\
                 assert(object.has(rebuilt_nil, \"value\"))\n\
                 assert(object.get(rebuilt_nil, \"value\", \"fallback\") == nil)\n\
                 assert(object.len(object.from_entries([])) == 0)\n\
                 let merged = object.merge(record, {second: 20, third: 3})\n\
                 assert(merged.first == 1)\n\
                 assert(merged.second == 20)\n\
                 assert(merged.third == 3)\n\
                 let json_record = json.parse(\"{\\\"second\\\":30,\\\"fourth\\\":4}\")\n\
                 assert(object.has(json_record, \"second\"))\n\
                 assert(object.get(json_record, \"second\", -1) == 30)\n\
                 let mixed = object.merge(merged, json_record)\n\
                 assert(mixed.second == 30)\n\
                 assert(mixed.fourth == 4)\n\
                 let mixed_pairs = object.entries(mixed)\n\
                 assert(mixed_pairs[3][0] == \"fourth\")\n\
                 assert(mixed_pairs[3][1] == 4)\n\
                 let picked = object.pick(mixed, [\"third\", \"missing\", \"first\", \"third\"])\n\
                 assert(object.keys(picked) == [\"third\", \"first\"])\n\
                 assert(picked.third == 3)\n\
                 assert(!object.has(picked, \"missing\"))\n\
                 let nested = {answer: 1}\n\
                 let rebuilt_nested = object.from_entries([[\"nested\", nested]])\n\
                 rebuilt_nested.nested.answer = 2\n\
                 assert(nested.answer == 2)\n\
                 let picked_nested = object.pick({nested: nested, ignored: 0}, [\"nested\"])\n\
                 picked_nested.nested.answer = 3\n\
                 assert(nested.answer == 3)\n\
                 let copied = object.merge({nested: nested}, {})\n\
                 copied.nested.answer = 4\n\
                 assert(nested.answer == 4)\n\
                 let entry_pairs = object.entries({nested: nested})\n\
                 entry_pairs[0][1].answer = 5\n\
                 assert(nested.answer == 5)\n\
                 object.keys(mixed)",
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
            serde_json::json!(["first", "second", "third", "fourth"])
        );

        let mut namespace_runtime = Runtime::default();
        let namespace = namespace_runtime
            .eval("use mod.std\nlet picked = std.object.pick({first: 1, second: 2}, [\"second\"])\nstd.object.from_entries([[\"second\", picked.second]]).second")
            .unwrap();
        assert!(namespace.completed(), "{:?}", namespace.diagnostics);
        assert_eq!(
            namespace_runtime
                .script_value_as_json(
                    namespace.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!(2)
        );

        let mutation = runtime
            .eval("use mod.std.object\nobject.from_entries = || nil")
            .unwrap();
        assert!(!mutation.succeeded());
        assert!(!mutation.diagnostics.is_empty());

        let preserved = runtime
            .eval("use mod.std.object\nobject.from_entries([[\"left\", 1], [\"right\", 2]])")
            .unwrap();
        assert!(preserved.completed(), "{:?}", preserved.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    preserved.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!({"left": 1, "right": 2})
        );

        let invalid = runtime
            .eval("use mod.std.object\ntry object.keys([1]) catch \"invalid\"")
            .unwrap();
        assert!(invalid.completed(), "{:?}", invalid.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid")
        );

        let invalid_lookup_key = runtime
            .eval("use mod.std.object\ntry object.has({first: 1}, 1) catch \"invalid-key\"")
            .unwrap();
        assert!(
            invalid_lookup_key.completed(),
            "{:?}",
            invalid_lookup_key.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_lookup_key.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid-key")
        );

        let invalid_pick_keys = runtime
            .eval(
                "use mod.std.object\ntry object.pick({first: 1}, \"first\") catch \"invalid-keys\"",
            )
            .unwrap();
        assert!(
            invalid_pick_keys.completed(),
            "{:?}",
            invalid_pick_keys.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_pick_keys.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid-keys")
        );

        let invalid_pick_key = runtime
            .eval("use mod.std.object\ntry object.pick({first: 1}, [1]) catch \"invalid-key\"")
            .unwrap();
        assert!(
            invalid_pick_key.completed(),
            "{:?}",
            invalid_pick_key.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_pick_key.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid-key")
        );

        let invalid_entries = runtime
            .eval("use mod.std.object\ntry object.from_entries(\"entries\") catch \"invalid-entries\"")
            .unwrap();
        assert!(
            invalid_entries.completed(),
            "{:?}",
            invalid_entries.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_entries.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid-entries")
        );

        let invalid_entry_pair = runtime
            .eval("use mod.std.object\ntry object.from_entries([[\"first\", 1, 2]]) catch \"invalid-pair\"")
            .unwrap();
        assert!(
            invalid_entry_pair.completed(),
            "{:?}",
            invalid_entry_pair.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_entry_pair.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid-pair")
        );

        let invalid_entry_key = runtime
            .eval("use mod.std.object\ntry object.from_entries([[1, 2]]) catch \"invalid-key\"")
            .unwrap();
        assert!(
            invalid_entry_key.completed(),
            "{:?}",
            invalid_entry_key.diagnostics
        );
        assert_eq!(
            runtime
                .script_value_as_json(
                    invalid_entry_key.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid-key")
        );

        let non_text_key = runtime
            .eval(
                "use mod.std.object\n\
                 let record = {}\n\
                 record[true] = 1\n\
                 try object.entries(record) catch \"invalid-key\"",
            )
            .unwrap();
        assert!(non_text_key.completed(), "{:?}", non_text_key.diagnostics);
        assert_eq!(
            runtime
                .script_value_as_json(
                    non_text_key.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("invalid-key")
        );

        let mut oversized_source =
            String::from("use mod.std.assert\nuse mod.std.object\nlet values = {");
        for index in 0..=MAX_STANDARD_OBJECT_FIELDS {
            if index > 0 {
                oversized_source.push_str(", ");
            }
            oversized_source.push_str(&format!("field_{index}: 0"));
        }
        oversized_source.push_str(&format!(
            "}}\nassert(object.len(values) == {})\nassert(object.has(values, \"field_0\"))\nassert(object.get(values, \"missing\", -1) == -1)\nlet selected = object.pick(values, [\"field_0\"])\nassert(object.get(selected, \"field_0\", -1) == 0)\nobject.entries(values)",
            MAX_STANDARD_OBJECT_FIELDS + 1
        ));
        let limits = ExecutionLimits {
            instruction_limit: 1_000_000,
            soft_timeout: Duration::from_secs(1),
            hard_timeout: Duration::from_secs(2),
            ..ExecutionLimits::default()
        };
        let mut oversized_runtime = Runtime::with_limits((), (), limits).unwrap();
        let oversized = oversized_runtime.eval(&oversized_source).unwrap();
        assert!(!oversized.completed());
        assert!(oversized
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("std.object.entries supports at most")));

        let mut pick_limit_runtime = Runtime::default();
        let pick_limit = pick_limit_runtime
            .eval(&format!(
                "use mod.std.object\n\
                 let keys = []\n\
                 keys[{MAX_STANDARD_OBJECT_FIELDS}] = \"first\"\n\
                 try object.pick({{first: 1}}, keys) catch \"limit\""
            ))
            .unwrap();
        assert!(pick_limit.completed(), "{:?}", pick_limit.diagnostics);
        assert_eq!(
            pick_limit_runtime
                .script_value_as_json(
                    pick_limit.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("limit")
        );

        let mut entry_limit_runtime = Runtime::default();
        let entry_limit = entry_limit_runtime
            .eval(&format!(
                "use mod.std.object\n\
                 let entries = []\n\
                 entries[{MAX_STANDARD_OBJECT_FIELDS}] = [\"first\", 1]\n\
                 try object.from_entries(entries) catch \"limit\""
            ))
            .unwrap();
        assert!(entry_limit.completed(), "{:?}", entry_limit.diagnostics);
        assert_eq!(
            entry_limit_runtime
                .script_value_as_json(
                    entry_limit.value,
                    DEFAULT_MAX_JSON_DATA_BYTES,
                    DEFAULT_MAX_JSON_DATA_DEPTH,
                )
                .unwrap(),
            serde_json::json!("limit")
        );
    }

    #[test]
    fn exposes_frozen_effect_free_standard_math() {
        let mut runtime = Runtime::default();
        let report = runtime
            .eval(
                "use mod.std.assert\n\
                 use mod.std.math\n\
                 assert(math.abs(-3) == 3)\n\
                 assert(math.ceil(1.2) == 2)\n\
                 assert(math.floor(1.8) == 1)\n\
                 assert(math.round(1.5) == 2)\n\
                 assert(math.sqrt(81) == 9)\n\
                 assert(math.pow(2, 3) == 8)\n\
                 assert(math.min(2, 3) == 2)\n\
                 assert(math.max(2, 3) == 3)\n\
                 assert(math.clamp(9, 0, 8) == 8)\n\
                 assert(math.sin(0) == 0)\n\
                 assert(math.cos(0) == 1)\n\
                 assert(math.tan(0) == 0)\n\
                 assert(math.atan2(0, 1) == 0)\n\
                 assert(math.exp(0) == 1)\n\
                 assert(math.log10(100) == 2)\n\
                 assert(math.pi > 3)\n\
                 assert(math.e > 2)\n\
                 math.clamp(math.pow(3, 2), 0, 8) + math.sqrt(16)",
            )
            .unwrap();
        assert!(report.completed(), "{:?}", report.diagnostics);
        assert_eq!(report.value.as_number(), Some(12.0));

        let mut namespace_runtime = Runtime::default();
        let namespace_report = namespace_runtime
            .eval("use mod.std\nstd.assert(std.math.sqrt(81) == 9)\nstd.math.sqrt(81)")
            .unwrap();
        assert!(
            namespace_report.completed(),
            "{:?}",
            namespace_report.diagnostics
        );
        assert_eq!(namespace_report.value.as_number(), Some(9.0));

        let mutation = runtime.eval("use mod.std.math\nmath.sqrt = || 0").unwrap();
        assert!(!mutation.succeeded());
        assert!(!mutation.diagnostics.is_empty());

        let preserved = runtime.eval("use mod.std.math\nmath.sqrt(81)").unwrap();
        assert!(preserved.completed(), "{:?}", preserved.diagnostics);
        assert_eq!(preserved.value.as_number(), Some(9.0));

        let mut invalid_arguments_runtime = Runtime::default();
        let invalid_range = invalid_arguments_runtime
            .eval("use mod.std.math\ntry math.clamp(1, 2, 0) catch 42")
            .unwrap();
        assert!(invalid_range.completed(), "{:?}", invalid_range.diagnostics);
        assert_eq!(invalid_range.value.as_u40(), Some(42));

        let wrong_type = invalid_arguments_runtime
            .eval("use mod.std.math\ntry math.abs(\"blocked\") catch 7")
            .unwrap();
        assert!(wrong_type.completed(), "{:?}", wrong_type.diagnostics);
        assert_eq!(wrong_type.value.as_u40(), Some(7));

        let mut compatibility_runtime = Runtime::default();
        let compatibility = compatibility_runtime
            .eval_vm_compatibility("use mod.std.math\nmath.sqrt(9)")
            .unwrap();
        assert!(compatibility.completed(), "{:?}", compatibility.diagnostics);
        assert_eq!(compatibility.value.as_number(), Some(3.0));

        let mut undefined_domain_runtime = Runtime::default();
        let undefined_domain = undefined_domain_runtime
            .eval("use mod.std.math\nmath.sqrt(-1)")
            .unwrap();
        assert!(
            undefined_domain.completed(),
            "{:?}",
            undefined_domain.diagnostics
        );
        assert!(undefined_domain.value.is_nan());
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
