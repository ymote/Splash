#![forbid(unsafe_code)]

//! Stdio language server for the canonical Splash v0.2 source profile.
//!
//! The server receives client-provided document text plus optional bounded,
//! advisory initialization metadata and calls effect-free syntax, formatting,
//! outline, and lexical symbol helpers. It never reads document URIs, evaluates
//! Splash code, creates a capability host, or loads an adapter.

use std::{
    cell::OnceCell,
    collections::{HashMap, HashSet},
    error::Error,
    io,
    process::ExitCode,
};

use lsp_server::{Connection, ErrorCode, Message, Notification, Request, Response};
use lsp_types::{
    notification::{
        DidChangeConfiguration, DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument,
        Exit, Notification as LspNotification, PublishDiagnostics,
    },
    request::{
        Completion, DocumentHighlightRequest, DocumentSymbolRequest, Formatting, GotoDefinition,
        HoverRequest, PrepareRenameRequest, References, Rename, Request as LspRequest,
        SignatureHelpRequest,
    },
    CompletionItem, CompletionItemKind, CompletionList, CompletionOptions, CompletionParams,
    CompletionResponse, CompletionTextEdit, Diagnostic, DiagnosticSeverity,
    DidChangeConfigurationParams, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DocumentChanges, DocumentFormattingParams, DocumentHighlight,
    DocumentHighlightKind, DocumentHighlightParams, DocumentSymbol, DocumentSymbolParams,
    DocumentSymbolResponse, Documentation, GotoDefinitionParams, GotoDefinitionResponse, Hover,
    HoverContents, HoverParams, InitializeParams, Location, MarkupContent, MarkupKind, OneOf,
    OptionalVersionedTextDocumentIdentifier, ParameterInformation, ParameterLabel, Position,
    PositionEncodingKind, PrepareRenameResponse, PublishDiagnosticsParams, Range, ReferenceParams,
    RenameOptions, RenameParams, ServerCapabilities, SignatureHelp, SignatureHelpOptions,
    SignatureHelpParams, SignatureInformation, SymbolKind, TextDocumentEdit, TextDocumentItem,
    TextDocumentPositionParams, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Uri,
    WorkspaceEdit,
};
use splash_core::{
    check_syntax_named, format_source_named, is_canonical_identifier,
    lexical_completion_report_named, lexical_symbol_report_named, module_import_report_named,
    static_record_shape_report_named, top_level_declarations_named, ExecutionLimits,
    LexicalCompletionReport, LexicalSymbol, LexicalSymbolKind, LexicalSymbolReport, ModuleImport,
    ModuleImportReport, SourceSpan, StaticRecordField, StaticRecordNestedShape, StaticRecordShape,
    StaticRecordShapeReport, SyntaxDiagnostic, TopLevelDeclaration, TopLevelDeclarationKind,
    DEFAULT_MAX_SOURCE_BYTES, DEFAULT_MAX_SYNTAX_NESTING, MAX_IMPORTED_MODULE_ALIAS_DEPTH,
    MAX_LEXICAL_SYMBOL_OCCURRENCES, MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH, MAX_SYNTAX_DIAGNOSTICS,
};

const MAX_OPEN_DOCUMENTS: usize = 128;
const DIAGNOSTIC_SOURCE: &str = "splash";
/// Maximum direct source alias hops considered for static record editor metadata.
///
/// This is intentionally much smaller than the independently capped alias
/// report, so one member request has a fixed traversal bound.
const MAX_STATIC_RECORD_ALIAS_DEPTH: usize = 16;
/// Maximum exact local aliases followed for advisory direct-module result
/// fields. This is intentionally separate from general value resolution.
const MAX_DIRECT_MODULE_OUTPUT_ALIAS_DEPTH: usize = 16;
/// Maximum retained metadata entries in the optional LSP tool-catalog projection.
///
/// This intentionally matches the default host catalog count but remains local
/// to the editor process. The projection is never a capability grant.
const MAX_LSP_TOOL_CATALOG_TOOLS: usize = 128;
/// Maximum retained name and description bytes in the optional LSP tool-catalog
/// projection.
const MAX_LSP_TOOL_CATALOG_BYTES: usize = 512 * 1024;
const MAX_LSP_TOOL_NAME_BYTES: usize = 128;
const MAX_LSP_TOOL_DESCRIPTION_BYTES: usize = 4 * 1024;
/// Maximum retained descriptors in the optional LSP module-interface
/// projection. This is metadata for authoring only, never a module registry.
const MAX_LSP_MODULE_CATALOG_ENTRIES: usize = 256;
/// Maximum retained path and description bytes in the optional LSP
/// module-interface projection.
const MAX_LSP_MODULE_CATALOG_BYTES: usize = 512 * 1024;
const MAX_LSP_MODULE_PATH_BYTES: usize = 256;
const MAX_LSP_MODULE_PATH_SEGMENTS: usize = 16;
const MAX_LSP_MODULE_DESCRIPTION_BYTES: usize = 4 * 1024;
/// Maximum schema-derived record fields retained in each direction across an
/// advisory module projection. This is presentation metadata only, never a
/// schema loader.
const MAX_LSP_MODULE_RECORD_FIELDS: usize = 1_024;
const MAX_LSP_MODULE_RECORD_FIELD_NAME_BYTES: usize = 128;
const MAX_LSP_MODULE_RECORD_FIELD_DESCRIPTION_BYTES: usize = 4 * 1024;
/// Maximum nested object-field levels retained below one direct-module input
/// field. This permits `{filters: {category: "news"}}`, but not deeper input
/// paths.
const MAX_LSP_MODULE_INPUT_FIELD_CHILD_DEPTH: usize = 1;
/// Maximum nested object-field levels retained below one direct-module output
/// field. This permits `result.summary.total`, but not deeper result paths.
const MAX_LSP_MODULE_OUTPUT_FIELD_CHILD_DEPTH: usize = 1;
/// Signature help scans only the current bounded source document and keeps its
/// delimiter stack no larger than the canonical grammar nesting budget.
const MAX_SIGNATURE_HELP_DELIMITER_DEPTH: usize = DEFAULT_MAX_SYNTAX_NESTING;
/// More arguments than this make the small fixed capability call signatures
/// unhelpful, so the source-only scanner stops rather than tracking unbounded
/// comma state for one editor request.
const MAX_SIGNATURE_HELP_ARGUMENTS: usize = 64;
/// A direct module-result initializer is deliberately recognized from a small
/// source window rather than by general expression parsing or type inference.
/// This keeps one completion or hover request bounded even when a document is
/// otherwise near its source limit.
const MAX_LSP_DIRECT_MODULE_OUTPUT_INITIALIZER_BYTES: usize = 64 * 1024;
/// Maximum projected workflow outputs retained in the advisory dataflow
/// catalog. This stays far below the workflow-plan hard cap so editor metadata
/// remains inexpensive on mobile and embedded hosts.
const MAX_LSP_WORKFLOW_DATA_OUTPUTS: usize = 128;
/// Maximum input and output fields retained across one advisory dataflow
/// projection.
const MAX_LSP_WORKFLOW_DATA_FIELDS: usize = 1_024;
/// Maximum aggregate retained bytes in the advisory workflow-data projection.
const MAX_LSP_WORKFLOW_DATA_BYTES: usize = 512 * 1024;
const MAX_LSP_WORKFLOW_DATA_FIELD_NAME_BYTES: usize = 128;
const MAX_LSP_WORKFLOW_DATA_FIELD_DESCRIPTION_BYTES: usize = 4 * 1024;

type ServerResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ToolCatalogFormat {
    Text,
    Json,
}

impl ToolCatalogFormat {
    fn from_catalog_value(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    const fn accepts_call_format(self, call_format: ToolCallFormat) -> bool {
        matches!(
            (self, call_format),
            (Self::Text, ToolCallFormat::Text) | (Self::Json, ToolCallFormat::Json)
        )
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "JSON",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ToolCallFormat {
    Text,
    Json,
}

/// One fixed function in Splash's core scalar-math module.
///
/// This table is intentionally compiled into the LSP instead of being derived
/// from an advisory module catalog. The documented core surface is stable,
/// source-only editor metadata and carries no host authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StandardMathFunction {
    name: &'static str,
    parameters: &'static [&'static str],
    description: &'static str,
}

/// One fixed scalar constant in Splash's core math module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StandardMathConstant {
    name: &'static str,
    description: &'static str,
}

/// One fixed function in Splash's core bounded-JSON module.
///
/// Like core math, this table is compiled into the LSP and never derived from
/// a host module catalog, adapter, or capability runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StandardJsonFunction {
    name: &'static str,
    parameters: &'static [&'static str],
    result: &'static str,
    description: &'static str,
}

/// One fixed function in Splash's core bounded-text module.
///
/// Like the other core tables, this is static editor metadata rather than a
/// host module catalog or a capability declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StandardTextFunction {
    name: &'static str,
    parameters: &'static [&'static str],
    result: &'static str,
    description: &'static str,
}

/// One fixed function in Splash's core bounded-array module.
///
/// Like the other core tables, this is static editor metadata rather than a
/// host module catalog or a capability declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StandardArrayFunction {
    name: &'static str,
    parameters: &'static [&'static str],
    result: &'static str,
    description: &'static str,
}

/// One fixed function in Splash's core bounded-object module.
///
/// Like the other core tables, this is static editor metadata rather than a
/// host module catalog or a capability declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StandardObjectFunction {
    name: &'static str,
    parameters: &'static [&'static str],
    result: &'static str,
    description: &'static str,
}

const STANDARD_MATH_FUNCTIONS: &[StandardMathFunction] = &[
    StandardMathFunction {
        name: "abs",
        parameters: &["value"],
        description: "Returns the absolute value of a scalar number.",
    },
    StandardMathFunction {
        name: "ceil",
        parameters: &["value"],
        description: "Rounds a scalar number upward.",
    },
    StandardMathFunction {
        name: "floor",
        parameters: &["value"],
        description: "Rounds a scalar number downward.",
    },
    StandardMathFunction {
        name: "round",
        parameters: &["value"],
        description: "Rounds a scalar number to the nearest integer-valued number.",
    },
    StandardMathFunction {
        name: "sqrt",
        parameters: &["value"],
        description: "Returns a scalar square root.",
    },
    StandardMathFunction {
        name: "sin",
        parameters: &["value"],
        description: "Returns a scalar sine.",
    },
    StandardMathFunction {
        name: "cos",
        parameters: &["value"],
        description: "Returns a scalar cosine.",
    },
    StandardMathFunction {
        name: "tan",
        parameters: &["value"],
        description: "Returns a scalar tangent.",
    },
    StandardMathFunction {
        name: "exp",
        parameters: &["value"],
        description: "Returns the scalar natural exponential.",
    },
    StandardMathFunction {
        name: "ln",
        parameters: &["value"],
        description: "Returns the scalar natural logarithm.",
    },
    StandardMathFunction {
        name: "log10",
        parameters: &["value"],
        description: "Returns the scalar base-10 logarithm.",
    },
    StandardMathFunction {
        name: "pow",
        parameters: &["base", "exponent"],
        description: "Raises a scalar base to a scalar exponent.",
    },
    StandardMathFunction {
        name: "min",
        parameters: &["left", "right"],
        description: "Returns the smaller scalar value.",
    },
    StandardMathFunction {
        name: "max",
        parameters: &["left", "right"],
        description: "Returns the larger scalar value.",
    },
    StandardMathFunction {
        name: "atan2",
        parameters: &["y", "x"],
        description: "Returns the scalar two-argument arctangent.",
    },
    StandardMathFunction {
        name: "clamp",
        parameters: &["value", "minimum", "maximum"],
        description: "Clamps a value to inclusive scalar bounds; minimum must not exceed maximum.",
    },
];

const STANDARD_MATH_CONSTANTS: &[StandardMathConstant] = &[
    StandardMathConstant {
        name: "pi",
        description: "The scalar ratio of a circle's circumference to its diameter.",
    },
    StandardMathConstant {
        name: "e",
        description: "The scalar base of natural logarithms.",
    },
];

const STANDARD_JSON_FUNCTIONS: &[StandardJsonFunction] = &[
    StandardJsonFunction {
        name: "parse",
        parameters: &["document"],
        result: "JSON value",
        description:
            "Parses strict JSON from a string or UTF-8 byte array through Splash's configured byte and nesting limits.",
    },
    StandardJsonFunction {
        name: "stringify",
        parameters: &["value"],
        result: "string",
        description:
            "Serializes a JSON-safe value through Splash's configured byte, nesting, and cycle limits.",
    },
];

const STANDARD_TEXT_FUNCTIONS: &[StandardTextFunction] = &[
    StandardTextFunction {
        name: "trim",
        parameters: &["value"],
        result: "string",
        description: "Removes leading and trailing Unicode whitespace.",
    },
    StandardTextFunction {
        name: "lower",
        parameters: &["value"],
        result: "string",
        description: "Converts Unicode scalar values to lowercase.",
    },
    StandardTextFunction {
        name: "upper",
        parameters: &["value"],
        result: "string",
        description: "Converts Unicode scalar values to uppercase.",
    },
    StandardTextFunction {
        name: "len",
        parameters: &["value"],
        result: "number",
        description: "Returns the count of Unicode scalar values.",
    },
    StandardTextFunction {
        name: "slice",
        parameters: &["value", "start", "end"],
        result: "string",
        description: "Returns the Unicode-scalar half-open [start, end) slice.",
    },
    StandardTextFunction {
        name: "index_of",
        parameters: &["value", "needle"],
        result: "number",
        description:
            "Returns the Unicode-scalar index of a literal match, or -1; an empty needle is 0.",
    },
    StandardTextFunction {
        name: "join",
        parameters: &["values", "separator"],
        result: "string",
        description: "Joins at most 4,096 strings with a string separator.",
    },
    StandardTextFunction {
        name: "contains",
        parameters: &["value", "needle"],
        result: "boolean",
        description: "Tests whether a string contains a literal substring.",
    },
    StandardTextFunction {
        name: "starts_with",
        parameters: &["value", "prefix"],
        result: "boolean",
        description: "Tests whether a string starts with a literal prefix.",
    },
    StandardTextFunction {
        name: "ends_with",
        parameters: &["value", "suffix"],
        result: "boolean",
        description: "Tests whether a string ends with a literal suffix.",
    },
    StandardTextFunction {
        name: "replace_all",
        parameters: &["value", "from", "to"],
        result: "string",
        description: "Replaces every non-overlapping literal substring match.",
    },
    StandardTextFunction {
        name: "split",
        parameters: &["value", "delimiter"],
        result: "array",
        description:
            "Splits on a non-empty delimiter using literal matching and preserves empty fields.",
    },
];

const STANDARD_ARRAY_FUNCTIONS: &[StandardArrayFunction] = &[
    StandardArrayFunction {
        name: "len",
        parameters: &["value"],
        result: "number",
        description: "Returns an array length without traversing its items.",
    },
    StandardArrayFunction {
        name: "has_index",
        parameters: &["value", "index"],
        result: "boolean",
        description: "Tests whether a non-negative index is present without traversing the array.",
    },
    StandardArrayFunction {
        name: "get",
        parameters: &["value", "index", "fallback"],
        result: "value",
        description: "Returns an indexed item or the fallback without traversing the array.",
    },
    StandardArrayFunction {
        name: "slice",
        parameters: &["value", "start", "end"],
        result: "array",
        description: "Returns a shallow copy of the half-open [start, end) range.",
    },
    StandardArrayFunction {
        name: "concat",
        parameters: &["left", "right"],
        result: "array",
        description: "Returns a shallow concatenation of two arrays.",
    },
    StandardArrayFunction {
        name: "flatten",
        parameters: &["value"],
        result: "array",
        description:
            "Flattens one level when every outer item is an array, with a 4,096-item total limit.",
    },
    StandardArrayFunction {
        name: "reverse",
        parameters: &["value"],
        result: "array",
        description: "Returns a shallow reversed copy of an array.",
    },
    StandardArrayFunction {
        name: "push",
        parameters: &["value", "item"],
        result: "nil",
        description: "Appends one item in place and returns nil.",
    },
];

const STANDARD_OBJECT_FUNCTIONS: &[StandardObjectFunction] = &[
    StandardObjectFunction {
        name: "len",
        parameters: &["value"],
        result: "number",
        description: "Returns an own-field count without traversing the record.",
    },
    StandardObjectFunction {
        name: "has",
        parameters: &["value", "key"],
        result: "boolean",
        description: "Tests whether an own text field is present, including a nil value.",
    },
    StandardObjectFunction {
        name: "get",
        parameters: &["value", "key", "fallback"],
        result: "value",
        description: "Returns an own text field or the fallback.",
    },
    StandardObjectFunction {
        name: "pick",
        parameters: &["value", "keys"],
        result: "object",
        description: "Returns a shallow record of requested existing own text fields; missing keys are omitted.",
    },
    StandardObjectFunction {
        name: "from_entries",
        parameters: &["entries"],
        result: "object",
        description: "Builds a shallow plain record from two-item [text key, value] entries; later duplicates replace values.",
    },
    StandardObjectFunction {
        name: "keys",
        parameters: &["value"],
        result: "array",
        description: "Returns own text field names in stored field order.",
    },
    StandardObjectFunction {
        name: "entries",
        parameters: &["value"],
        result: "array",
        description: "Returns shallow [text key, value] pairs in stored field order.",
    },
    StandardObjectFunction {
        name: "values",
        parameters: &["value"],
        result: "array",
        description: "Returns shallow own field values in stored field order.",
    },
    StandardObjectFunction {
        name: "merge",
        parameters: &["left", "right"],
        result: "object",
        description:
            "Returns a shallow merge that preserves first field positions and applies right-side values.",
    },
];

const STANDARD_MATH_AUTHORITY_NOTE: &str =
    "Effect-free Splash core helper; it does not access the host or grant authority.";
const STANDARD_JSON_AUTHORITY_NOTE: &str =
    "Bounded Splash core data helper; it does not access the host or grant authority.";
const STANDARD_TEXT_AUTHORITY_NOTE: &str =
    "Bounded Splash core text helper; it does not access the host or grant authority.";
const STANDARD_ARRAY_AUTHORITY_NOTE: &str =
    "Bounded Splash core array helper; it does not access the host or grant authority.";
const STANDARD_OBJECT_AUTHORITY_NOTE: &str =
    "Bounded Splash core object helper; it does not access the host or grant authority.";

const STANDARD_ASSERT_DESCRIPTION: &str = "Raises a script error when the condition is false.";
const STANDARD_ASSERT_AUTHORITY_NOTE: &str =
    "Fixed Splash core helper; it does not access the host or grant authority.";
const STANDARD_ASSERT_DOCUMENTATION: &str = concat!(
    "assert(condition)\n\n",
    "Raises a script error when the condition is false.\n\n",
    "Fixed Splash core helper; it does not access the host or grant authority."
);

/// One fixed path child in Splash's documented core import tree.
///
/// This is intentionally separate from the host-owned advisory module catalog.
/// It lets an editor discover the core language without treating that discovery
/// as module resolution, adapter availability, or a capability grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedCoreModulePathChild {
    name: &'static str,
    detail: &'static str,
    documentation: &'static str,
}

const FIXED_ROOT_MODULE_PATH_CHILDREN: &[FixedCoreModulePathChild] = &[FixedCoreModulePathChild {
    name: "std",
    detail: "Splash core namespace; fixed and effect-free",
    documentation:
        "Fixed Splash core namespace. Its presence does not resolve a host module or grant authority.",
}];

const FIXED_STANDARD_MODULE_PATH_CHILDREN: &[FixedCoreModulePathChild] = &[
    FixedCoreModulePathChild {
        name: "array",
        detail: "Splash core module; bounded array helpers",
        documentation:
            "Fixed Splash core array helpers. They perform bounded local array operations and do not access the host or grant authority.",
    },
    FixedCoreModulePathChild {
        name: "assert",
        detail: "Splash core function; fixed assertion helper",
        documentation: STANDARD_ASSERT_DOCUMENTATION,
    },
    FixedCoreModulePathChild {
        name: "json",
        detail: "Splash core module; bounded JSON helpers",
        documentation:
            "Fixed Splash core JSON helpers. They use the runtime's bounded JSON boundary and do not access the host or grant authority.",
    },
    FixedCoreModulePathChild {
        name: "math",
        detail: "Splash core module; effect-free scalar helpers",
        documentation:
            "Fixed Splash core scalar helpers. They do not resolve a host module or grant authority.",
    },
    FixedCoreModulePathChild {
        name: "object",
        detail: "Splash core module; bounded own-field helpers",
        documentation:
            "Fixed Splash core object helpers. They inspect bounded own record fields and do not access the host or grant authority.",
    },
    FixedCoreModulePathChild {
        name: "text",
        detail: "Splash core module; bounded text helpers",
        documentation:
            "Fixed Splash core text helpers. They use bounded string construction and do not access the host or grant authority.",
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct ToolCatalogCompletion {
    name: String,
    format: ToolCatalogFormat,
    description: String,
}

/// A bounded, advisory projection of the host's current tool catalog.
///
/// The server receives this through LSP initialization options or a later
/// configuration refresh. It does not connect to a runtime, read a catalog
/// from disk, or use catalog metadata to authorize source. A malformed or
/// oversized projection is discarded in full so the editor cannot present an
/// arbitrary partial set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ToolCompletionCatalog {
    tools: Vec<ToolCatalogCompletion>,
    unavailable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleCatalogCompletion {
    path: Vec<String>,
    description: String,
    call_mode: Option<ModuleCatalogCallMode>,
    call_shape: Option<ModuleCatalogCallShape>,
    input_fields: Option<Vec<ModuleCatalogRecordFieldCompletion>>,
    output_fields: Option<Vec<ModuleCatalogOutputFieldCompletion>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModuleCatalogCallMode {
    Synchronous,
    Deferred,
}

impl ModuleCatalogCallMode {
    fn from_catalog_value(value: &str) -> Option<Self> {
        match value {
            "synchronous" => Some(Self::Synchronous),
            "deferred" => Some(Self::Deferred),
            _ => None,
        }
    }

    const fn as_catalog_value(self) -> &'static str {
        match self {
            Self::Synchronous => "synchronous",
            Self::Deferred => "deferred",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModuleCatalogCallShape {
    SingleJson,
}

impl ModuleCatalogCallShape {
    fn from_catalog_value(value: &str) -> Option<Self> {
        match value {
            "single_json" => Some(Self::SingleJson),
            _ => None,
        }
    }

    const fn as_catalog_value(self) -> &'static str {
        match self {
            Self::SingleJson => "single_json",
        }
    }
}

/// A compact source-compatible JSON input field supplied by the host for one
/// exact direct-module method. It is intentionally narrower than JSON Schema:
/// the LSP only uses it for bounded key completion plus plain-text hover and
/// signature documentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModuleCatalogRecordFieldType {
    Any,
    Null,
    Boolean,
    Number,
    Integer,
    String,
    Array,
    Object,
}

impl ModuleCatalogRecordFieldType {
    fn from_catalog_value(value: &str) -> Option<Self> {
        match value {
            "any" => Some(Self::Any),
            "null" => Some(Self::Null),
            "boolean" => Some(Self::Boolean),
            "number" => Some(Self::Number),
            "integer" => Some(Self::Integer),
            "string" => Some(Self::String),
            "array" => Some(Self::Array),
            "object" => Some(Self::Object),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Null => "null",
            Self::Boolean => "boolean",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::String => "string",
            Self::Array => "array",
            Self::Object => "object",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleCatalogRecordFieldCompletion {
    name: String,
    field_type: ModuleCatalogRecordFieldType,
    required: bool,
    description: String,
    fields: Option<Vec<ModuleCatalogRecordFieldCompletion>>,
}

/// One compact, source-compatible output field supplied by the host for one
/// exact direct-module method. It retains at most one explicit object-child
/// level; it is presentation metadata, not a general type or schema model.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleCatalogOutputFieldCompletion {
    name: String,
    field_type: ModuleCatalogRecordFieldType,
    required: bool,
    description: String,
    fields: Option<Vec<ModuleCatalogOutputFieldCompletion>>,
}

/// A bounded, advisory projection of a host's known `mod.*` interface.
///
/// Like the tool projection, this stays inside the editor process and can only
/// be replaced by host configuration. It cannot load, resolve, install, or
/// authorize a module.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ModuleCompletionCatalog {
    modules: Vec<ModuleCatalogCompletion>,
    unavailable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkflowDataFieldType {
    Any,
    Null,
    Boolean,
    Number,
    Integer,
    String,
    Array,
    Object,
}

impl WorkflowDataFieldType {
    fn from_catalog_value(value: &str) -> Option<Self> {
        match value {
            "any" => Some(Self::Any),
            "null" => Some(Self::Null),
            "boolean" => Some(Self::Boolean),
            "number" => Some(Self::Number),
            "integer" => Some(Self::Integer),
            "string" => Some(Self::String),
            "array" => Some(Self::Array),
            "object" => Some(Self::Object),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Null => "null",
            Self::Boolean => "boolean",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::String => "string",
            Self::Array => "array",
            Self::Object => "object",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkflowDataFieldCompletion {
    name: String,
    field_type: WorkflowDataFieldType,
    description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkflowDataOutputCompletion {
    step_id: String,
    fields: Vec<WorkflowDataFieldCompletion>,
}

/// A bounded, static projection of host-owned workflow data contracts.
///
/// This is authoring metadata only. It neither validates a workflow value,
/// constructs a dataflow approval, issues a lease, nor makes an output
/// available at runtime.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct WorkflowDataCompletionCatalog {
    input_fields: Vec<WorkflowDataFieldCompletion>,
    outputs: Vec<WorkflowDataOutputCompletion>,
    /// Distinguishes an absent advisory projection from an explicitly supplied
    /// empty projection. The former must not invent a `workflow` namespace.
    configured: bool,
    unavailable: bool,
}

/// A static, host-supplied view of the projected workflow position currently
/// being authored. It narrows output metadata only; it is never a runtime
/// completion proof or authority boundary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct WorkflowDataStepContext {
    /// Number of catalog outputs in the host-declared completed projected
    /// prefix. Parsing proves it is no greater than `catalog.outputs.len()`.
    completed_output_count: usize,
    configured: bool,
    unavailable: bool,
}

/// One workflow-data metadata transition received through
/// `workspace/didChangeConfiguration`. A host must provide a complete catalog
/// and a structurally valid current-step context together, or explicitly clear
/// both with `null`; partial or malformed relevant settings poison only this
/// advisory projection.
enum WorkflowDataConfigurationUpdate {
    Keep,
    Clear,
    Replace {
        catalog: WorkflowDataCompletionCatalog,
        step_context: WorkflowDataStepContext,
    },
}

/// One independent tool or module catalog transition received through
/// `workspace/didChangeConfiguration`. `null` is an explicit clear; malformed
/// metadata also clears that advisory catalog rather than retaining stale
/// suggestions.
enum AdvisoryCatalogConfigurationUpdate<Catalog> {
    Keep,
    Clear,
    Replace(Catalog),
}

#[derive(Debug)]
struct DocumentState {
    source: Option<String>,
    version: i32,
    lexical_report: OnceCell<Result<LexicalSymbolReport, String>>,
    completion_report: OnceCell<Result<LexicalCompletionReport, String>>,
    module_import_report: OnceCell<Result<ModuleImportReport, String>>,
    static_record_shape_report: OnceCell<Result<StaticRecordShapeReport, String>>,
}

#[derive(Debug, Eq, PartialEq)]
struct VersionedRenameEdits {
    uri: Uri,
    version: i32,
    edits: Vec<TextEdit>,
}

impl VersionedRenameEdits {
    fn into_workspace_edit(self) -> WorkspaceEdit {
        WorkspaceEdit {
            changes: None,
            document_changes: Some(DocumentChanges::Edits(vec![TextDocumentEdit {
                text_document: OptionalVersionedTextDocumentIdentifier::new(self.uri, self.version),
                edits: self.edits.into_iter().map(OneOf::Left).collect(),
            }])),
            change_annotations: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpanReplacement {
    original: SourceSpan,
    replacement: SourceSpan,
}

#[derive(Default)]
struct SplashLanguageServer {
    documents: HashMap<Uri, DocumentState>,
    tool_catalog: ToolCompletionCatalog,
    module_catalog: ModuleCompletionCatalog,
    workflow_data_catalog: WorkflowDataCompletionCatalog,
    workflow_data_step_context: WorkflowDataStepContext,
}

impl SplashLanguageServer {
    #[cfg(test)]
    fn with_tool_catalog(tool_catalog: ToolCompletionCatalog) -> Self {
        Self::with_completion_catalogs(tool_catalog, ModuleCompletionCatalog::default())
    }

    #[cfg(test)]
    fn with_workflow_data_catalog(workflow_data_catalog: WorkflowDataCompletionCatalog) -> Self {
        Self::with_completion_catalogs_and_workflow_data(
            ToolCompletionCatalog::default(),
            ModuleCompletionCatalog::default(),
            workflow_data_catalog,
            WorkflowDataStepContext::default(),
        )
    }

    #[cfg(test)]
    fn with_workflow_data_catalog_and_step_context(
        workflow_data_catalog: WorkflowDataCompletionCatalog,
        workflow_data_step_context: WorkflowDataStepContext,
    ) -> Self {
        Self::with_completion_catalogs_and_workflow_data(
            ToolCompletionCatalog::default(),
            ModuleCompletionCatalog::default(),
            workflow_data_catalog,
            workflow_data_step_context,
        )
    }

    #[cfg(test)]
    fn with_completion_catalogs(
        tool_catalog: ToolCompletionCatalog,
        module_catalog: ModuleCompletionCatalog,
    ) -> Self {
        Self::with_completion_catalogs_and_workflow_data(
            tool_catalog,
            module_catalog,
            WorkflowDataCompletionCatalog::default(),
            WorkflowDataStepContext::default(),
        )
    }

    fn with_completion_catalogs_and_workflow_data(
        tool_catalog: ToolCompletionCatalog,
        module_catalog: ModuleCompletionCatalog,
        workflow_data_catalog: WorkflowDataCompletionCatalog,
        workflow_data_step_context: WorkflowDataStepContext,
    ) -> Self {
        Self {
            documents: HashMap::new(),
            tool_catalog,
            module_catalog,
            workflow_data_catalog,
            workflow_data_step_context,
        }
    }

    /// Refreshes all advisory editor metadata after a host configuration
    /// update. Each catalog has an independent replacement boundary; the
    /// workflow catalog/context pair remains atomic.
    fn refresh_advisory_configuration(&mut self, settings: &serde_json::Value) {
        self.refresh_tool_catalog_configuration(settings);
        self.refresh_module_catalog_configuration(settings);
        self.refresh_workflow_data_configuration(settings);
    }

    /// Refreshes the advisory tool catalog without consulting a capability
    /// runtime or granting source authority.
    fn refresh_tool_catalog_configuration(&mut self, settings: &serde_json::Value) {
        match tool_catalog_configuration_update_from_settings(settings) {
            AdvisoryCatalogConfigurationUpdate::Keep => {}
            AdvisoryCatalogConfigurationUpdate::Clear => {
                self.tool_catalog = unavailable_tool_completion_catalog();
            }
            AdvisoryCatalogConfigurationUpdate::Replace(catalog) => {
                self.tool_catalog = catalog;
            }
        }
    }

    /// Refreshes the advisory module catalog without loading or resolving a
    /// module.
    fn refresh_module_catalog_configuration(&mut self, settings: &serde_json::Value) {
        match module_catalog_configuration_update_from_settings(settings) {
            AdvisoryCatalogConfigurationUpdate::Keep => {}
            AdvisoryCatalogConfigurationUpdate::Clear => {
                self.module_catalog = unavailable_module_completion_catalog();
            }
            AdvisoryCatalogConfigurationUpdate::Replace(catalog) => {
                self.module_catalog = catalog;
            }
        }
    }

    /// Refreshes workflow-only editor metadata after a host configuration
    /// update. The parsed value is fully validated before either field changes,
    /// so a reader never observes a mixed catalog/context pair.
    fn refresh_workflow_data_configuration(&mut self, settings: &serde_json::Value) {
        match workflow_data_configuration_update_from_settings(settings) {
            WorkflowDataConfigurationUpdate::Keep => {}
            WorkflowDataConfigurationUpdate::Clear => self.invalidate_workflow_data_configuration(),
            WorkflowDataConfigurationUpdate::Replace {
                catalog,
                step_context,
            } => {
                self.workflow_data_catalog = catalog;
                self.workflow_data_step_context = step_context;
            }
        }
    }

    /// A malformed configuration notification must not leave potentially stale
    /// workflow metadata available to the editor.
    fn invalidate_workflow_data_configuration(&mut self) {
        self.workflow_data_catalog = unavailable_workflow_data_completion_catalog();
        self.workflow_data_step_context = unavailable_workflow_data_step_context();
    }

    /// A malformed configuration notification must not leave potentially stale
    /// advisory metadata available to the editor.
    fn invalidate_advisory_configuration(&mut self) {
        self.tool_catalog = unavailable_tool_completion_catalog();
        self.module_catalog = unavailable_module_completion_catalog();
        self.invalidate_workflow_data_configuration();
    }

    fn open_document(&mut self, item: TextDocumentItem) -> PublishDiagnosticsParams {
        self.replace_document(item.uri, item.version, item.text)
    }

    fn change_document(
        &mut self,
        params: DidChangeTextDocumentParams,
    ) -> Option<PublishDiagnosticsParams> {
        let uri = params.text_document.uri;
        let version = params.text_document.version;
        let current = self.documents.get(&uri)?;

        if version <= current.version || params.content_changes.len() != 1 {
            return None;
        }

        let change = params.content_changes.into_iter().next()?;
        if change.range.is_some() || change.range_length.is_some() {
            return None;
        }

        Some(self.replace_document(uri, version, change.text))
    }

    fn close_document(&mut self, params: DidCloseTextDocumentParams) -> PublishDiagnosticsParams {
        let uri = params.text_document.uri;
        self.documents.remove(&uri);
        PublishDiagnosticsParams::new(uri, Vec::new(), None)
    }

    fn format_document(&self, uri: &Uri) -> Result<Vec<TextEdit>, String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let formatted = format_source_named(uri.as_str(), source, ExecutionLimits::default())
            .map_err(|error| format!("cannot format canonical Splash source: {error}"))?;

        if formatted == source {
            return Ok(Vec::new());
        }

        Ok(vec![TextEdit::new(
            Range::new(Position::new(0, 0), document_end_position(source)),
            formatted,
        )])
    }

    fn document_symbols(&self, uri: &Uri) -> Result<Vec<DocumentSymbol>, String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let declarations =
            top_level_declarations_named(uri.as_str(), source, ExecutionLimits::default())
                .map_err(|error| format!("cannot outline canonical Splash source: {error}"))?;

        Ok(declarations
            .iter()
            .map(|declaration| outline_symbol(source, declaration))
            .collect())
    }

    fn definition(&self, uri: &Uri, position: Position) -> Result<Option<Location>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(None);
        };
        let shapes = self.static_record_shapes(uri)?;
        if !report.truncated {
            if let Some(site) = direct_module_member_completion_site(source, byte_offset) {
                if let Some(field) = static_record_field_for_member(
                    source,
                    &report.symbols,
                    source.len(),
                    shapes,
                    site,
                ) {
                    return Ok(Some(symbol_location(uri, source, field.definition)));
                }
            }
        }
        let Some(symbol) = symbol_at_byte(report, byte_offset) else {
            return Ok(None);
        };

        Ok(Some(symbol_location(uri, source, symbol.definition)))
    }

    fn hover(&self, uri: &Uri, position: Position) -> Result<Option<Hover>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(None);
        };
        let shapes = self.static_record_shapes(uri)?;
        if !report.truncated {
            if !self.module_catalog.modules.is_empty() {
                if let Some(site) = direct_module_input_record_completion_site(source, byte_offset)
                {
                    let (_, lexical) = self.lexical_completions(uri)?;
                    let imports = self.module_imports(uri)?;
                    if let Some(field) = module_catalog_input_field_for_site(
                        source,
                        lexical,
                        imports,
                        shapes,
                        &self.module_catalog,
                        &site,
                    ) {
                        return Ok(Some(Hover {
                            contents: HoverContents::Markup(MarkupContent {
                                // Host-supplied descriptions stay plain text.
                                kind: MarkupKind::PlainText,
                                value: module_catalog_input_field_text(field),
                            }),
                            range: Some(span_range(source, site.field)),
                        }));
                    }
                }
            }
            if let Some(site) = direct_module_member_completion_site(source, byte_offset) {
                if let Some((field, context)) = workflow_data_field_for_member(
                    source,
                    &report.symbols,
                    source.len(),
                    &self.workflow_data_catalog,
                    &self.workflow_data_step_context,
                    site,
                ) {
                    return Ok(Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                            // Contract descriptions are host supplied. Keep them plain text so
                            // metadata cannot inject markup into the editor.
                            kind: MarkupKind::PlainText,
                            value: workflow_data_field_hover_text(field, context),
                        }),
                        range: Some(span_range(source, site.member)),
                    }));
                }
                if let Some(field) = static_record_field_for_member(
                    source,
                    &report.symbols,
                    source.len(),
                    shapes,
                    site,
                ) {
                    return Ok(Some(Hover {
                        contents: HoverContents::Markup(MarkupContent {
                            kind: MarkupKind::Markdown,
                            value: format!("**static record field** `{}`", field.name),
                        }),
                        range: Some(span_range(source, site.member)),
                    }));
                }
                let (_, lexical) = self.lexical_completions(uri)?;
                let imports = self.module_imports(uri)?;
                if site.has_direct_receiver()
                    && is_visible_builtin_standard_array_receiver(
                        source,
                        lexical,
                        imports,
                        site.receiver,
                    )
                {
                    return Ok(standard_array_member_hover(source, site));
                }
                if site.has_direct_receiver()
                    && is_visible_builtin_standard_object_receiver(
                        source,
                        lexical,
                        imports,
                        site.receiver,
                    )
                {
                    return Ok(standard_object_member_hover(source, site));
                }
                if site.has_direct_receiver()
                    && is_visible_builtin_standard_math_receiver(
                        source,
                        lexical,
                        imports,
                        site.receiver,
                    )
                {
                    return Ok(standard_math_member_hover(source, site));
                }
                if site.has_direct_receiver()
                    && is_visible_builtin_standard_json_receiver(
                        source,
                        lexical,
                        imports,
                        site.receiver,
                    )
                {
                    return Ok(standard_json_member_hover(source, site));
                }
                if site.has_direct_receiver()
                    && is_visible_builtin_standard_text_receiver(
                        source,
                        lexical,
                        imports,
                        site.receiver,
                    )
                {
                    return Ok(standard_text_member_hover(source, site));
                }
                if let Some(hover) = fixed_core_module_member_hover(source, lexical, imports, site)
                {
                    return Ok(hover);
                }
                if !self.module_catalog.modules.is_empty() {
                    if let Some(field) = module_catalog_output_field_for_member(
                        source,
                        lexical,
                        imports,
                        &self.module_catalog,
                        shapes,
                        site,
                    ) {
                        return Ok(Some(Hover {
                            contents: HoverContents::Markup(MarkupContent {
                                // Host-supplied descriptions stay plain text.
                                kind: MarkupKind::PlainText,
                                value: module_catalog_output_field_text(field),
                            }),
                            range: Some(span_range(source, site.member)),
                        }));
                    }
                    if let Some(hover) = module_catalog_member_hover(
                        source,
                        report,
                        lexical,
                        imports,
                        shapes,
                        &self.module_catalog,
                        site,
                    ) {
                        return Ok(Some(hover));
                    }
                }
            }
        }
        let Some((symbol, occurrence)) = symbol_occurrence_at_byte(report, byte_offset) else {
            return Ok(None);
        };

        if !report.truncated && symbol.kind == LexicalSymbolKind::Import {
            let (_, lexical) = self.lexical_completions(uri)?;
            let imports = self.module_imports(uri)?;
            if is_visible_builtin_standard_assert_receiver(source, lexical, imports, occurrence) {
                return Ok(Some(Hover {
                    contents: HoverContents::Markup(MarkupContent {
                        kind: MarkupKind::PlainText,
                        value: standard_assert_documentation("assert"),
                    }),
                    range: Some(span_range(source, occurrence)),
                }));
            }
        }

        Ok(Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: format!(
                    "**{}** `{}`",
                    lexical_symbol_kind_label(symbol.kind),
                    symbol.name
                ),
            }),
            range: Some(span_range(source, occurrence)),
        }))
    }

    fn references(
        &self,
        uri: &Uri,
        position: Position,
        include_declaration: bool,
    ) -> Result<Vec<Location>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        if report.truncated {
            return Err(format!(
                "the lexical index exceeds Splash's {MAX_LEXICAL_SYMBOL_OCCURRENCES}-occurrence limit"
            ));
        }
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(Vec::new());
        };
        let Some(symbol) = symbol_at_byte(report, byte_offset) else {
            return Ok(Vec::new());
        };

        let mut locations =
            Vec::with_capacity(symbol.references.len() + usize::from(include_declaration));
        if include_declaration {
            locations.push(symbol_location(uri, source, symbol.definition));
        }
        locations.extend(
            symbol
                .references
                .iter()
                .copied()
                .map(|span| symbol_location(uri, source, span)),
        );
        Ok(locations)
    }

    fn document_highlights(
        &self,
        uri: &Uri,
        position: Position,
    ) -> Result<Vec<DocumentHighlight>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        if report.truncated {
            return Err(format!(
                "the lexical index exceeds Splash's {MAX_LEXICAL_SYMBOL_OCCURRENCES}-occurrence limit"
            ));
        }
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(Vec::new());
        };
        let Some(symbol) = symbol_at_byte(report, byte_offset) else {
            return Ok(Vec::new());
        };

        Ok(std::iter::once(symbol.definition)
            .chain(symbol.references.iter().copied())
            .map(|span| DocumentHighlight {
                range: span_range(source, span),
                kind: Some(DocumentHighlightKind::TEXT),
            })
            .collect())
    }

    fn completion(&self, uri: &Uri, position: Position) -> Result<CompletionList, String> {
        let (source, report) = self.lexical_completions(uri)?;
        let lexical_incomplete = report.symbols_truncated || report.sites_truncated;
        let empty = || CompletionList {
            is_incomplete: lexical_incomplete,
            items: Vec::new(),
        };
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(empty());
        };
        if report.symbols_truncated {
            return Ok(empty());
        }

        if let Some(import_site) = direct_import_path_completion_site(source, byte_offset) {
            return Ok(module_catalog_path_completion(
                source,
                report,
                &self.module_catalog,
                import_site,
                lexical_incomplete,
            ));
        }

        if let Some(tool_name_site) = direct_tool_name_completion_site(source, byte_offset) {
            let imports = self.module_imports(uri)?;
            return Ok(tool_catalog_name_completion(
                source,
                report,
                imports,
                &self.tool_catalog,
                tool_name_site,
                lexical_incomplete || imports.truncated,
            ));
        }

        if let Some(member_site) = direct_module_member_completion_site(source, byte_offset) {
            if let Some(completion) = workflow_data_member_completion(
                source,
                report,
                &self.workflow_data_catalog,
                &self.workflow_data_step_context,
                member_site,
                lexical_incomplete,
            ) {
                return Ok(completion);
            }
            let imports = self.module_imports(uri)?;
            let is_incomplete = lexical_incomplete || imports.truncated;
            if member_site.has_direct_receiver()
                && is_visible_builtin_tool_receiver(source, report, imports, member_site.receiver)
            {
                return Ok(tool_module_member_completion(
                    source,
                    report,
                    imports,
                    member_site,
                    is_incomplete,
                ));
            }
            if member_site.has_direct_receiver()
                && is_visible_builtin_standard_array_receiver(
                    source,
                    report,
                    imports,
                    member_site.receiver,
                )
            {
                return Ok(standard_array_module_member_completion(
                    source,
                    report,
                    imports,
                    member_site,
                    is_incomplete,
                ));
            }
            if member_site.has_direct_receiver()
                && is_visible_builtin_standard_object_receiver(
                    source,
                    report,
                    imports,
                    member_site.receiver,
                )
            {
                return Ok(standard_object_module_member_completion(
                    source,
                    report,
                    imports,
                    member_site,
                    is_incomplete,
                ));
            }
            if member_site.has_direct_receiver()
                && is_visible_builtin_standard_math_receiver(
                    source,
                    report,
                    imports,
                    member_site.receiver,
                )
            {
                return Ok(standard_math_module_member_completion(
                    source,
                    report,
                    imports,
                    member_site,
                    is_incomplete,
                ));
            }
            if member_site.has_direct_receiver()
                && is_visible_builtin_standard_json_receiver(
                    source,
                    report,
                    imports,
                    member_site.receiver,
                )
            {
                return Ok(standard_json_module_member_completion(
                    source,
                    report,
                    imports,
                    member_site,
                    is_incomplete,
                ));
            }
            if member_site.has_direct_receiver()
                && is_visible_builtin_standard_text_receiver(
                    source,
                    report,
                    imports,
                    member_site.receiver,
                )
            {
                return Ok(standard_text_module_member_completion(
                    source,
                    report,
                    imports,
                    member_site,
                    is_incomplete,
                ));
            }
            if let Some(completion) = fixed_core_module_member_completion(
                source,
                report,
                imports,
                member_site,
                is_incomplete,
            ) {
                return Ok(completion);
            }
            let shapes = self.static_record_shapes(uri)?;
            if let Some(fields) = visible_static_record_fields(
                source,
                &report.symbols,
                report.valid_prefix_end_byte,
                shapes,
                member_site,
            ) {
                return Ok(static_record_member_completion(
                    source,
                    report,
                    shapes,
                    fields,
                    member_site,
                    lexical_incomplete,
                ));
            }
            if let Some(completion) = module_catalog_output_field_completion(
                source,
                report,
                imports,
                &self.module_catalog,
                shapes,
                member_site,
                is_incomplete,
            ) {
                return Ok(completion);
            }
            return Ok(module_catalog_member_completion(
                source,
                report,
                imports,
                shapes,
                &self.module_catalog,
                member_site,
                is_incomplete,
            ));
        }

        if let Some(record_site) = direct_module_input_record_completion_site(source, byte_offset) {
            let imports = self.module_imports(uri)?;
            let shapes = self.static_record_shapes(uri)?;
            return Ok(module_catalog_input_field_completion(
                source,
                report,
                imports,
                shapes,
                &self.module_catalog,
                record_site,
                lexical_incomplete || imports.truncated,
            ));
        }

        let Some(site) = report.sites.iter().copied().find(|site| {
            site.start_byte <= byte_offset
                && byte_offset <= site.end_byte
                && site.end_byte <= report.valid_prefix_end_byte
        }) else {
            return Ok(empty());
        };

        let mut visible_by_name = HashMap::<&str, &LexicalSymbol>::new();
        for symbol in &report.symbols {
            if symbol.visibility_start_byte <= site.start_byte
                && site.start_byte < symbol.visibility_end_byte
            {
                let replace = visible_by_name
                    .get(symbol.name.as_str())
                    .is_none_or(|current| {
                        (symbol.visibility_start_byte, symbol.definition.start_byte)
                            > (current.visibility_start_byte, current.definition.start_byte)
                    });
                if replace {
                    visible_by_name.insert(symbol.name.as_str(), symbol);
                }
            }
        }

        let edit_range = span_range(source, site);
        let mut items = visible_by_name
            .into_values()
            .map(|symbol| CompletionItem {
                label: symbol.name.clone(),
                kind: Some(completion_item_kind(symbol.kind)),
                detail: Some(lexical_symbol_kind_label(symbol.kind).to_owned()),
                text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                    edit_range,
                    symbol.name.clone(),
                ))),
                ..CompletionItem::default()
            })
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.label.cmp(&right.label));

        Ok(CompletionList {
            is_incomplete: lexical_incomplete,
            items,
        })
    }

    /// Returns only fixed language signatures or exact visible advisory module
    /// leaves. This is source-only editor metadata, never a module lookup or
    /// capability decision.
    fn signature_help(
        &self,
        uri: &Uri,
        position: Position,
    ) -> Result<Option<SignatureHelp>, String> {
        let (source, lexical) = self.lexical_completions(uri)?;
        if lexical.symbols_truncated {
            return Ok(None);
        }
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(None);
        };
        if let Some(context) = direct_function_signature_help_call_context(source, byte_offset) {
            let imports = self.module_imports(uri)?;
            if imports.truncated
                || context.callee.end_byte > lexical.valid_prefix_end_byte
                || context.callee.end_byte > imports.valid_prefix_end_byte
            {
                return Ok(None);
            }
            if is_visible_builtin_standard_assert_receiver(source, lexical, imports, context.callee)
            {
                let callee = source
                    .get(context.callee.start_byte..context.callee.end_byte)
                    .ok_or_else(|| {
                        "the direct signature-help callee has an invalid source span".to_owned()
                    })?;
                return Ok(Some(standard_assert_signature_help(
                    callee,
                    context.active_argument,
                )));
            }
            return Ok(None);
        }
        let Some(context) = signature_help_call_context(source, byte_offset) else {
            return Ok(None);
        };
        let imports = self.module_imports(uri)?;
        if imports.truncated
            || context.callee.member.end_byte > lexical.valid_prefix_end_byte
            || context.callee.member.end_byte > imports.valid_prefix_end_byte
        {
            return Ok(None);
        }

        let method = source
            .get(context.callee.member.start_byte..context.callee.member.end_byte)
            .ok_or_else(|| "the signature-help callee has an invalid source span".to_owned())?;
        if context.callee.has_direct_receiver()
            && is_visible_builtin_tool_receiver(source, lexical, imports, context.callee.receiver)
        {
            return Ok(builtin_tool_signature_help(method, context.active_argument));
        }
        if context.callee.has_direct_receiver()
            && is_visible_builtin_standard_array_receiver(
                source,
                lexical,
                imports,
                context.callee.receiver,
            )
        {
            return Ok(standard_array_signature_help(source, context));
        }
        if context.callee.has_direct_receiver()
            && is_visible_builtin_standard_object_receiver(
                source,
                lexical,
                imports,
                context.callee.receiver,
            )
        {
            return Ok(standard_object_signature_help(source, context));
        }
        if context.callee.has_direct_receiver()
            && is_visible_builtin_standard_math_receiver(
                source,
                lexical,
                imports,
                context.callee.receiver,
            )
        {
            return Ok(standard_math_signature_help(source, context));
        }
        if context.callee.has_direct_receiver()
            && is_visible_builtin_standard_json_receiver(
                source,
                lexical,
                imports,
                context.callee.receiver,
            )
        {
            return Ok(standard_json_signature_help(source, context));
        }
        if context.callee.has_direct_receiver()
            && is_visible_builtin_standard_text_receiver(
                source,
                lexical,
                imports,
                context.callee.receiver,
            )
        {
            return Ok(standard_text_signature_help(source, context));
        }
        if is_visible_builtin_standard_assert_member(source, lexical, imports, context.callee) {
            return Ok(standard_assert_member_signature_help(source, context));
        }
        if self.module_catalog.unavailable {
            return Ok(None);
        }
        let shapes = self.static_record_shapes(uri)?;
        let Some(module) = module_catalog_direct_member(
            source,
            lexical,
            imports,
            shapes,
            &self.module_catalog,
            context.callee,
        ) else {
            return Ok(None);
        };
        let Some(call_mode) = module.call_mode else {
            return Ok(None);
        };
        if module.call_shape != Some(ModuleCatalogCallShape::SingleJson) {
            return Ok(None);
        }

        Ok(module_catalog_signature_help(
            source, module, call_mode, context,
        ))
    }

    fn prepare_rename(
        &self,
        uri: &Uri,
        position: Position,
    ) -> Result<Option<PrepareRenameResponse>, String> {
        let (source, _, report) = self.lexical_symbols(uri)?;
        require_complete_lexical_report(report)?;
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(None);
        };
        let Some((symbol_index, occurrence)) =
            rename_symbol_occurrence_at_byte(report, byte_offset)
        else {
            return Ok(None);
        };
        let symbol = &report.symbols[symbol_index];
        if symbol.kind == LexicalSymbolKind::Import {
            return Ok(None);
        }

        Ok(Some(PrepareRenameResponse::RangeWithPlaceholder {
            range: span_range(source, occurrence),
            placeholder: symbol.name.clone(),
        }))
    }

    fn rename(
        &self,
        uri: &Uri,
        position: Position,
        new_name: &str,
    ) -> Result<Option<VersionedRenameEdits>, String> {
        let (source, version, report) = self.lexical_symbols(uri)?;
        require_complete_lexical_report(report)?;
        let Some(byte_offset) = byte_at_position(source, position) else {
            return Ok(None);
        };
        let Some((symbol_index, _)) = rename_symbol_occurrence_at_byte(report, byte_offset) else {
            return Ok(None);
        };
        let symbol = &report.symbols[symbol_index];
        if symbol.kind == LexicalSymbolKind::Import {
            return Err(
                "Splash cannot rename an import binding without changing its module path"
                    .to_owned(),
            );
        }
        if new_name == symbol.name {
            return Ok(None);
        }
        if new_name.len() > DEFAULT_MAX_SOURCE_BYTES {
            return Err(format!(
                "the rename identifier exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit"
            ));
        }
        if !is_canonical_identifier(new_name) {
            return Err(
                "the requested name is not a non-reserved canonical Splash identifier".to_owned(),
            );
        }

        let (renamed_source, replacements) = rewrite_symbol_occurrences(source, symbol, new_name)?;
        let syntax = check_syntax_named(uri.as_str(), &renamed_source, ExecutionLimits::default())
            .map_err(|error| format!("cannot validate renamed Splash source: {error}"))?;
        if !syntax.valid {
            return Err("the requested rename does not produce canonical Splash source".to_owned());
        }

        let renamed_report =
            lexical_symbol_report_named(uri.as_str(), &renamed_source, ExecutionLimits::default())
                .map_err(|error| format!("cannot index renamed Splash source: {error}"))?;
        let expected_report = remap_lexical_report(report, symbol_index, new_name, &replacements)?;
        if renamed_report != expected_report {
            return Err(
                "the requested rename would change indexed lexical binding resolution".to_owned(),
            );
        }

        Ok(Some(VersionedRenameEdits {
            uri: uri.clone(),
            version,
            edits: replacements
                .iter()
                .map(|replacement| {
                    TextEdit::new(
                        span_range(source, replacement.original),
                        new_name.to_owned(),
                    )
                })
                .collect(),
        }))
    }

    fn lexical_symbols(&self, uri: &Uri) -> Result<(&str, i32, &LexicalSymbolReport), String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let report = state.lexical_report.get_or_init(|| {
            lexical_symbol_report_named(uri.as_str(), source, ExecutionLimits::default())
                .map_err(|error| format!("cannot index canonical Splash source: {error}"))
        });
        match report {
            Ok(report) => Ok((source, state.version, report)),
            Err(message) => Err(message.clone()),
        }
    }

    fn lexical_completions(&self, uri: &Uri) -> Result<(&str, &LexicalCompletionReport), String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let report = state.completion_report.get_or_init(|| {
            lexical_completion_report_named(uri.as_str(), source, ExecutionLimits::default())
                .map_err(|error| format!("cannot complete canonical Splash source: {error}"))
        });
        match report {
            Ok(report) => Ok((source, report)),
            Err(message) => Err(message.clone()),
        }
    }

    fn module_imports(&self, uri: &Uri) -> Result<&ModuleImportReport, String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let report = state.module_import_report.get_or_init(|| {
            module_import_report_named(uri.as_str(), source, ExecutionLimits::default())
                .map_err(|error| format!("cannot inspect canonical Splash imports: {error}"))
        });
        match report {
            Ok(report) => Ok(report),
            Err(message) => Err(message.clone()),
        }
    }

    fn static_record_shapes(&self, uri: &Uri) -> Result<&StaticRecordShapeReport, String> {
        let state = self
            .documents
            .get(uri)
            .ok_or_else(|| "the document is not open in this Splash session".to_owned())?;
        let source = state.source.as_deref().ok_or_else(|| {
            format!("the document exceeds Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit")
        })?;
        let report = state.static_record_shape_report.get_or_init(|| {
            static_record_shape_report_named(uri.as_str(), source, ExecutionLimits::default())
                .map_err(|error| format!("cannot inspect static record shapes: {error}"))
        });
        match report {
            Ok(report) => Ok(report),
            Err(message) => Err(message.clone()),
        }
    }

    fn replace_document(
        &mut self,
        uri: Uri,
        version: i32,
        source: String,
    ) -> PublishDiagnosticsParams {
        if !self.documents.contains_key(&uri) && self.documents.len() >= MAX_OPEN_DOCUMENTS {
            return resource_diagnostics(
                uri,
                version,
                format!(
                    "Splash LSP tracks at most {MAX_OPEN_DOCUMENTS} open documents per session"
                ),
            );
        }

        if source.len() > DEFAULT_MAX_SOURCE_BYTES {
            self.documents.insert(
                uri.clone(),
                DocumentState {
                    source: None,
                    version,
                    lexical_report: OnceCell::new(),
                    completion_report: OnceCell::new(),
                    module_import_report: OnceCell::new(),
                    static_record_shape_report: OnceCell::new(),
                },
            );
            return resource_diagnostics(
                uri,
                version,
                format!(
                    "source is {} bytes; Splash accepts at most {DEFAULT_MAX_SOURCE_BYTES} bytes",
                    source.len()
                ),
            );
        }

        let diagnostics = syntax_diagnostics(&uri, &source);
        self.documents.insert(
            uri.clone(),
            DocumentState {
                source: Some(source),
                version,
                lexical_report: OnceCell::new(),
                completion_report: OnceCell::new(),
                module_import_report: OnceCell::new(),
                static_record_shape_report: OnceCell::new(),
            },
        );
        PublishDiagnosticsParams::new(uri, diagnostics, Some(version))
    }
}

/// Maximum input bytes accepted by the LSP libFuzzer exercise hook.
///
/// This stays well below the editor's ordinary source limit so each generated
/// case can issue several semantic requests with a predictable cost.
#[cfg(fuzzing)]
const MAX_FUZZ_LSP_SOURCE_BYTES: usize = 16 * 1024;
/// Number of evenly spaced source positions sampled by the LSP fuzz hook.
///
/// The inclusive sampling range produces at most 33 UTF-8 boundary positions.
#[cfg(fuzzing)]
const MAX_FUZZ_LSP_POSITION_SAMPLES: usize = 32;
/// Fixed source used to exercise arbitrary advisory catalog configuration.
///
/// Its names cover direct tool, fixed core modules, direct-module input/result,
/// and workflow-data metadata without giving the fuzzer a capability host or
/// runtime authority.
#[cfg(fuzzing)]
const FUZZ_ADVISORY_CONFIGURATION_SOURCE: &str = concat!(
    "use mod.tool\n",
    "use mod.fuzz.inspect\n",
    "use mod.std\n",
    "use mod.std.assert\n",
    "use mod.std.array\n",
    "use mod.std.json\n",
    "use mod.std.math\n",
    "use mod.std.object\n",
    "use mod.std.text\n",
    "let result = inspect.remote_add({left: 20, filters: {category: \"news\"}, right: 22}).await()\n",
    "let alias = result\n",
    "alias.summary.total\n",
    "let bounded = math.clamp(math.sqrt(81), 0, 8)\n",
    "math.pi\n",
    "let parsed = json.parse(\"{\\\"answer\\\":42}\")\n",
    "json.stringify(parsed)\n",
    "let sliced = array.slice([1, 2, 3], 1, 3)\n",
    "array.has_index(sliced, 0)\n",
    "array.get(sliced, 2, 0)\n",
    "let flattened = array.flatten([sliced, [4]])\n",
    "array.reverse(sliced)\n",
    "let collected = []\n",
    "array.push(collected, 4)\n",
    "let merged = object.merge({left: 1}, {right: 2})\n",
    "let rebuilt = object.from_entries([[\"left\", 1]])\n",
    "object.has(merged, \"left\")\n",
    "object.get(merged, \"missing\", 0)\n",
    "let picked = object.pick(merged, [\"left\"])\n",
    "object.keys(merged)\n",
    "object.entries(merged)\n",
    "let normalized = text.trim(\"  splash  \")\n",
    "text.replace_all(normalized, \"splash\", \"Splash\")\n",
    "text.slice(normalized, 0, text.len(normalized))\n",
    "text.index_of(normalized, \"splash\")\n",
    "let parts = text.split(normalized, \"-\")\n",
    "text.join(parts, \"-\")\n",
    "assert(true)\n",
    "std.assert(true)\n",
    "tool.call(\"\", \"\")\n",
    "workflow.input.request\n",
    "workflow.outputs.prepare.total"
);

#[cfg(fuzzing)]
const FUZZ_FIXED_CORE_IMPORT_PATH_SOURCES: &[&str] = &[
    "use mod.",
    "use mod.std.",
    "use mod.std.array.",
    "use mod.std.json.",
    "use mod.std.math.",
    "use mod.std.object.",
    "use mod.std.text.",
];

/// Fixed no-authority metadata used to exercise advisory module completion and
/// hover through the production document lifecycle.
#[cfg(fuzzing)]
fn fuzz_module_completion_catalog() -> ModuleCompletionCatalog {
    ModuleCompletionCatalog {
        modules: vec![
            ModuleCatalogCompletion {
                path: vec!["mod".to_owned(), "fuzz".to_owned()],
                description: "Fuzz-only advisory module.".to_owned(),
                call_mode: None,
                call_shape: None,
                input_fields: None,
                output_fields: None,
            },
            ModuleCatalogCompletion {
                path: vec![
                    "mod".to_owned(),
                    "fuzz".to_owned(),
                    "inspect".to_owned(),
                    "remote_add".to_owned(),
                ],
                description: "Fuzz-only deferred adapter.".to_owned(),
                call_mode: Some(ModuleCatalogCallMode::Deferred),
                call_shape: Some(ModuleCatalogCallShape::SingleJson),
                input_fields: Some(vec![
                    ModuleCatalogRecordFieldCompletion {
                        name: "left".to_owned(),
                        field_type: ModuleCatalogRecordFieldType::Integer,
                        required: true,
                        description: "Fuzz-only left operand.".to_owned(),
                        fields: None,
                    },
                    ModuleCatalogRecordFieldCompletion {
                        name: "right".to_owned(),
                        field_type: ModuleCatalogRecordFieldType::Integer,
                        required: true,
                        description: "Fuzz-only right operand.".to_owned(),
                        fields: None,
                    },
                    ModuleCatalogRecordFieldCompletion {
                        name: "filters".to_owned(),
                        field_type: ModuleCatalogRecordFieldType::Object,
                        required: false,
                        description: "Fuzz-only nested input filters.".to_owned(),
                        fields: Some(vec![
                            ModuleCatalogRecordFieldCompletion {
                                name: "category".to_owned(),
                                field_type: ModuleCatalogRecordFieldType::String,
                                required: true,
                                description: "Fuzz-only input category.".to_owned(),
                                fields: None,
                            },
                            ModuleCatalogRecordFieldCompletion {
                                name: "limit".to_owned(),
                                field_type: ModuleCatalogRecordFieldType::Integer,
                                required: false,
                                description: String::new(),
                                fields: None,
                            },
                        ]),
                    },
                ]),
                output_fields: Some(vec![ModuleCatalogOutputFieldCompletion {
                    name: "summary".to_owned(),
                    field_type: ModuleCatalogRecordFieldType::Object,
                    required: true,
                    description: "Fuzz-only result summary.".to_owned(),
                    fields: Some(vec![ModuleCatalogOutputFieldCompletion {
                        name: "total".to_owned(),
                        field_type: ModuleCatalogRecordFieldType::Integer,
                        required: true,
                        description: "Fuzz-only nested total result.".to_owned(),
                        fields: None,
                    }]),
                }]),
            },
            ModuleCatalogCompletion {
                path: vec![
                    "mod".to_owned(),
                    "fuzz".to_owned(),
                    "inspect".to_owned(),
                    "status".to_owned(),
                ],
                description: "Fuzz-only synchronous adapter.".to_owned(),
                call_mode: Some(ModuleCatalogCallMode::Synchronous),
                call_shape: Some(ModuleCatalogCallShape::SingleJson),
                input_fields: Some(Vec::new()),
                output_fields: None,
            },
        ],
        unavailable: false,
    }
}

/// Exercises the source-only LSP document lifecycle for libFuzzer.
///
/// This hook creates a fixed local URI, opens and replaces one bounded source
/// document, calls the effect-free semantic requests, then closes the
/// document. It does not start stdio, read a URI, resolve modules, evaluate
/// Splash, or construct a capability host.
#[cfg(fuzzing)]
pub fn fuzz_exercise_document(source: &str) {
    use std::str::FromStr;

    if source.len() > MAX_FUZZ_LSP_SOURCE_BYTES {
        return;
    }
    let Ok(uri) = Uri::from_str("file:///splash-fuzz/document.splash") else {
        return;
    };

    let mut server = SplashLanguageServer::with_completion_catalogs_and_workflow_data(
        ToolCompletionCatalog::default(),
        fuzz_module_completion_catalog(),
        WorkflowDataCompletionCatalog::default(),
        WorkflowDataStepContext::default(),
    );
    let _ = server.open_document(TextDocumentItem::new(
        uri.clone(),
        "splash".to_owned(),
        1,
        source.to_owned(),
    ));
    fuzz_exercise_semantic_requests(&server, &uri, source);

    // A distinct full-document replacement invalidates every lazy semantic
    // report before the second request pass.
    let mut replacement = source.to_owned();
    replacement.push('\n');
    let _ = server.replace_document(uri.clone(), 2, replacement.clone());
    fuzz_exercise_semantic_requests(&server, &uri, &replacement);

    // Exercise exact root and direct-child input field sites independently of
    // the arbitrary source offsets above, so the fixed advisory catalog keeps
    // this bounded hover and completion path under sanitizer coverage.
    let _ = server.replace_document(
        uri.clone(),
        3,
        FUZZ_ADVISORY_CONFIGURATION_SOURCE.to_owned(),
    );
    fuzz_exercise_advisory_input_field_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_array_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_object_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_math_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_json_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_text_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_assert_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_core_import_path_requests(&mut server, &uri, 4);

    let _ = server.close_document(DidCloseTextDocumentParams {
        text_document: lsp_types::TextDocumentIdentifier::new(uri.clone()),
    });
    let _ = server.completion(&uri, Position::new(u32::MAX, u32::MAX));
}

/// Exercises advisory initialization and configuration parsing using one
/// already-decoded JSON value. The projection remains editor-local: this hook
/// does not connect to a runtime, load a module, or grant a capability.
#[cfg(fuzzing)]
pub fn fuzz_exercise_advisory_configuration(settings: &serde_json::Value) {
    use std::str::FromStr;

    let params = InitializeParams {
        initialization_options: Some(settings.clone()),
        ..InitializeParams::default()
    };
    let (tool_catalog, module_catalog, workflow_data_catalog, workflow_data_step_context) =
        completion_catalogs_from_initialize_options(&params);
    let Ok(uri) = Uri::from_str("file:///splash-fuzz/configuration.splash") else {
        return;
    };

    let mut server = SplashLanguageServer::with_completion_catalogs_and_workflow_data(
        tool_catalog,
        module_catalog,
        workflow_data_catalog,
        workflow_data_step_context,
    );
    let _ = server.open_document(TextDocumentItem::new(
        uri.clone(),
        "splash".to_owned(),
        1,
        FUZZ_ADVISORY_CONFIGURATION_SOURCE.to_owned(),
    ));
    fuzz_exercise_semantic_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_array_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_object_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_math_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_text_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);

    // The same untrusted value crosses the independent refresh boundary after
    // initialization, so malformed and over-limit replacements cannot leave
    // stale catalog state available to semantic requests.
    server.refresh_advisory_configuration(settings);
    fuzz_exercise_semantic_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_array_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_object_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_math_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_json_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_text_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_standard_assert_requests(&server, &uri, FUZZ_ADVISORY_CONFIGURATION_SOURCE);
    fuzz_exercise_fixed_core_import_path_requests(&mut server, &uri, 2);

    let _ = server.close_document(DidCloseTextDocumentParams {
        text_document: lsp_types::TextDocumentIdentifier::new(uri.clone()),
    });
    let _ = server.completion(&uri, Position::new(u32::MAX, u32::MAX));
}

#[cfg(fuzzing)]
fn fuzz_exercise_semantic_requests(server: &SplashLanguageServer, uri: &Uri, source: &str) {
    let _ = server.format_document(uri);
    let _ = server.document_symbols(uri);

    let mut attempted_rename = false;
    for byte_offset in bounded_fuzz_document_offsets(source) {
        let position = position_at_byte(source, byte_offset);
        let _ = server.completion(uri, position);
        let _ = server.hover(uri, position);
        let _ = server.signature_help(uri, position);
        let _ = server.definition(uri, position);
        let _ = server.references(uri, position, true);
        let _ = server.document_highlights(uri, position);
        if !attempted_rename && matches!(server.prepare_rename(uri, position), Ok(Some(_))) {
            let _ = server.rename(uri, position, "fuzz_renamed");
            attempted_rename = true;
        }
    }

    let invalid_position = Position::new(u32::MAX, u32::MAX);
    let _ = server.completion(uri, invalid_position);
    let _ = server.hover(uri, invalid_position);
    let _ = server.signature_help(uri, invalid_position);
    let _ = server.definition(uri, invalid_position);
    let _ = server.references(uri, invalid_position, true);
    let _ = server.document_highlights(uri, invalid_position);
    let _ = server.prepare_rename(uri, invalid_position);
}

#[cfg(fuzzing)]
fn fuzz_exercise_advisory_input_field_requests(
    server: &SplashLanguageServer,
    uri: &Uri,
    source: &str,
) {
    for field_name in ["filters", "category"] {
        let Some(start_byte) = source.find(field_name) else {
            return;
        };
        let position = position_at_byte(source, start_byte + 1);
        let _ = server.completion(uri, position);
        let _ = server.hover(uri, position);
        let _ = server.signature_help(uri, position);
    }
}

#[cfg(fuzzing)]
fn fuzz_exercise_fixed_standard_math_requests(
    server: &SplashLanguageServer,
    uri: &Uri,
    source: &str,
) {
    let Some(completion_start) = source.find("math.clamp") else {
        return;
    };
    let completion_byte = completion_start + "math.clamp".len();
    let _ = server.completion(uri, position_at_byte(source, completion_byte));

    let Some(sqrt_start) = source.find("sqrt") else {
        return;
    };
    let _ = server.hover(uri, position_at_byte(source, sqrt_start + 1));

    let Some(pi_start) = source.rfind("pi") else {
        return;
    };
    let _ = server.hover(uri, position_at_byte(source, pi_start + 1));

    let Some(minimum_start) = source.find("0, 8") else {
        return;
    };
    let _ = server.signature_help(uri, position_at_byte(source, minimum_start + 1));
}

#[cfg(fuzzing)]
fn fuzz_exercise_fixed_standard_json_requests(
    server: &SplashLanguageServer,
    uri: &Uri,
    source: &str,
) {
    let Some(parse_start) = source.find("json.parse") else {
        return;
    };
    let parse_argument = parse_start + "json.parse(\"".len();
    let _ = server.completion(
        uri,
        position_at_byte(source, parse_start + "json.parse".len()),
    );
    let _ = server.hover(
        uri,
        position_at_byte(source, parse_start + "json.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, parse_argument));

    let Some(stringify_start) = source.find("json.stringify") else {
        return;
    };
    let _ = server.hover(
        uri,
        position_at_byte(source, stringify_start + "json.".len() + 1),
    );
}

#[cfg(fuzzing)]
fn fuzz_exercise_fixed_standard_array_requests(
    server: &SplashLanguageServer,
    uri: &Uri,
    source: &str,
) {
    let Some(slice_start) = source.find("array.slice") else {
        return;
    };
    let slice_argument = slice_start + "array.slice([".len();
    let _ = server.completion(
        uri,
        position_at_byte(source, slice_start + "array.slice".len()),
    );
    let _ = server.hover(
        uri,
        position_at_byte(source, slice_start + "array.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, slice_argument));

    let Some(has_index_start) = source.find("array.has_index") else {
        return;
    };
    let has_index_argument = has_index_start + "array.has_index(sliced, ".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, has_index_start + "array.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, has_index_argument));

    let Some(get_start) = source.find("array.get") else {
        return;
    };
    let get_argument = get_start + "array.get(sliced, 2, ".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, get_start + "array.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, get_argument));

    let Some(flatten_start) = source.find("array.flatten") else {
        return;
    };
    let flatten_argument = flatten_start + "array.flatten([".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, flatten_start + "array.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, flatten_argument));

    let Some(reverse_start) = source.find("array.reverse") else {
        return;
    };
    let _ = server.hover(
        uri,
        position_at_byte(source, reverse_start + "array.".len() + 1),
    );

    let Some(push_start) = source.find("array.push") else {
        return;
    };
    let push_argument = push_start + "array.push(".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, push_start + "array.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, push_argument));
}

#[cfg(fuzzing)]
fn fuzz_exercise_fixed_standard_object_requests(
    server: &SplashLanguageServer,
    uri: &Uri,
    source: &str,
) {
    let Some(merge_start) = source.find("object.merge") else {
        return;
    };
    let merge_argument = merge_start + "object.merge({".len();
    let _ = server.completion(
        uri,
        position_at_byte(source, merge_start + "object.merge".len()),
    );
    let _ = server.hover(
        uri,
        position_at_byte(source, merge_start + "object.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, merge_argument));

    let Some(from_entries_start) = source.find("object.from_entries") else {
        return;
    };
    let from_entries_argument = from_entries_start + "object.from_entries(".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, from_entries_start + "object.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, from_entries_argument));

    let Some(has_start) = source.find("object.has") else {
        return;
    };
    let has_argument = has_start + "object.has(merged, ".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, has_start + "object.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, has_argument));

    let Some(get_start) = source.find("object.get") else {
        return;
    };
    let get_argument = get_start + "object.get(merged, \"missing\", ".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, get_start + "object.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, get_argument));

    let Some(pick_start) = source.find("object.pick") else {
        return;
    };
    let pick_argument = pick_start + "object.pick(merged, [".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, pick_start + "object.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, pick_argument));

    let Some(keys_start) = source.find("object.keys") else {
        return;
    };
    let _ = server.hover(
        uri,
        position_at_byte(source, keys_start + "object.".len() + 1),
    );

    let Some(entries_start) = source.find("object.entries") else {
        return;
    };
    let entries_argument = entries_start + "object.entries(".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, entries_start + "object.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, entries_argument));
}

#[cfg(fuzzing)]
fn fuzz_exercise_fixed_standard_text_requests(
    server: &SplashLanguageServer,
    uri: &Uri,
    source: &str,
) {
    let Some(trim_start) = source.find("text.trim") else {
        return;
    };
    let trim_argument = trim_start + "text.trim(\"".len();
    let _ = server.completion(
        uri,
        position_at_byte(source, trim_start + "text.trim".len()),
    );
    let _ = server.hover(
        uri,
        position_at_byte(source, trim_start + "text.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, trim_argument));

    let Some(slice_start) = source.find("text.slice") else {
        return;
    };
    let slice_argument = slice_start + "text.slice(normalized, ".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, slice_start + "text.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, slice_argument));

    let Some(index_of_start) = source.find("text.index_of") else {
        return;
    };
    let index_of_argument = index_of_start + "text.index_of(normalized, \"".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, index_of_start + "text.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, index_of_argument));

    let Some(replace_start) = source.find("text.replace_all") else {
        return;
    };
    let _ = server.hover(
        uri,
        position_at_byte(source, replace_start + "text.".len() + 1),
    );

    let Some(split_start) = source.find("text.split") else {
        return;
    };
    let split_argument = split_start + "text.split(".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, split_start + "text.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, split_argument));

    let Some(join_start) = source.find("text.join") else {
        return;
    };
    let join_argument = join_start + "text.join(parts, ".len();
    let _ = server.hover(
        uri,
        position_at_byte(source, join_start + "text.".len() + 1),
    );
    let _ = server.signature_help(uri, position_at_byte(source, join_argument));
}

#[cfg(fuzzing)]
fn fuzz_exercise_fixed_standard_assert_requests(
    server: &SplashLanguageServer,
    uri: &Uri,
    source: &str,
) {
    let Some(direct_start) = source.find("assert(true)") else {
        return;
    };
    let direct_argument = direct_start + "assert(".len();
    let _ = server.hover(uri, position_at_byte(source, direct_start + 1));
    let _ = server.signature_help(uri, position_at_byte(source, direct_argument));

    let Some(member_start) = source.find("std.assert(true)") else {
        return;
    };
    let member_assert_start = member_start + "std.".len();
    let member_argument = member_start + "std.assert(".len();
    let _ = server.hover(uri, position_at_byte(source, member_assert_start + 1));
    let _ = server.signature_help(uri, position_at_byte(source, member_argument));
}

#[cfg(fuzzing)]
fn fuzz_exercise_fixed_core_import_path_requests(
    server: &mut SplashLanguageServer,
    uri: &Uri,
    first_version: i32,
) {
    for (index, source) in FUZZ_FIXED_CORE_IMPORT_PATH_SOURCES.iter().enumerate() {
        let Ok(version_offset) = i32::try_from(index) else {
            return;
        };
        let Some(version) = first_version.checked_add(version_offset) else {
            return;
        };
        let _ = server.replace_document(uri.clone(), version, (*source).to_owned());
        let _ = server.completion(uri, position_at_byte(source, source.len()));
    }
}

#[cfg(fuzzing)]
fn bounded_fuzz_document_offsets(source: &str) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(MAX_FUZZ_LSP_POSITION_SAMPLES + 1);
    for sample in 0..=MAX_FUZZ_LSP_POSITION_SAMPLES {
        let mut offset = source.len() * sample / MAX_FUZZ_LSP_POSITION_SAMPLES;
        while offset > 0 && !source.is_char_boundary(offset) {
            offset -= 1;
        }
        offsets.push(offset);
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn main() -> ExitCode {
    match run_stdio() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("splash-lsp: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_stdio() -> ServerResult<()> {
    let (connection, io_threads) = Connection::stdio();
    let result = run_connection(&connection);
    drop(connection);
    io_threads.join()?;
    result
}

fn run_connection(connection: &Connection) -> ServerResult<()> {
    let (initialize_id, initialize_value) = connection.initialize_start()?;
    let initialize_params =
        serde_json::from_value::<InitializeParams>(initialize_value).unwrap_or_default();
    let versioned_document_edits = supports_versioned_document_edits(&initialize_params);
    let (tool_catalog, module_catalog, workflow_data_catalog, workflow_data_step_context) =
        completion_catalogs_from_initialize_options(&initialize_params);
    connection.initialize_finish(
        initialize_id,
        serde_json::json!({
            "capabilities": server_capabilities(versioned_document_edits),
        }),
    )?;

    let mut server = SplashLanguageServer::with_completion_catalogs_and_workflow_data(
        tool_catalog,
        module_catalog,
        workflow_data_catalog,
        workflow_data_step_context,
    );
    while let Ok(message) = connection.receiver.recv() {
        match message {
            Message::Request(request) => {
                if connection.handle_shutdown(&request)? {
                    return Ok(());
                }
                handle_request(connection, &server, versioned_document_edits, request)?;
            }
            Message::Notification(notification) => {
                if notification.method == Exit::METHOD {
                    return Err(io::Error::other(
                        "received an LSP exit notification before shutdown",
                    )
                    .into());
                }
                handle_notification(connection, &mut server, notification)?;
            }
            Message::Response(_) => {}
        }
    }

    Ok(())
}

fn supports_versioned_document_edits(params: &InitializeParams) -> bool {
    params
        .capabilities
        .workspace
        .as_ref()
        .and_then(|workspace| workspace.workspace_edit.as_ref())
        .and_then(|workspace_edit| workspace_edit.document_changes)
        == Some(true)
}

fn completion_catalogs_from_initialize_options(
    params: &InitializeParams,
) -> (
    ToolCompletionCatalog,
    ModuleCompletionCatalog,
    WorkflowDataCompletionCatalog,
    WorkflowDataStepContext,
) {
    let Some(options) = params.initialization_options.as_ref() else {
        return (
            ToolCompletionCatalog::default(),
            ModuleCompletionCatalog::default(),
            WorkflowDataCompletionCatalog::default(),
            WorkflowDataStepContext::default(),
        );
    };
    let Some(options) = options.as_object() else {
        return (
            ToolCompletionCatalog::default(),
            ModuleCompletionCatalog::default(),
            WorkflowDataCompletionCatalog::default(),
            WorkflowDataStepContext::default(),
        );
    };
    let Some(splash) = options.get("splash") else {
        return (
            ToolCompletionCatalog::default(),
            ModuleCompletionCatalog::default(),
            WorkflowDataCompletionCatalog::default(),
            WorkflowDataStepContext::default(),
        );
    };
    let Some(splash) = splash.as_object() else {
        return (
            unavailable_tool_completion_catalog(),
            unavailable_module_completion_catalog(),
            unavailable_workflow_data_completion_catalog(),
            unavailable_workflow_data_step_context(),
        );
    };

    let tool_catalog = match splash.get("toolCatalog") {
        Some(catalog) => parse_tool_completion_catalog(catalog)
            .unwrap_or_else(unavailable_tool_completion_catalog),
        None => ToolCompletionCatalog::default(),
    };
    let module_catalog = match splash.get("moduleCatalog") {
        Some(catalog) => parse_module_completion_catalog(catalog)
            .unwrap_or_else(unavailable_module_completion_catalog),
        None => ModuleCompletionCatalog::default(),
    };
    let mut workflow_data_catalog = match splash.get("workflowDataCatalog") {
        Some(catalog) => parse_workflow_data_completion_catalog(catalog)
            .unwrap_or_else(unavailable_workflow_data_completion_catalog),
        None => WorkflowDataCompletionCatalog::default(),
    };
    let workflow_data_step_context = match splash.get("workflowDataStepContext") {
        Some(context) => parse_workflow_data_step_context(context, &workflow_data_catalog)
            .unwrap_or_else(unavailable_workflow_data_step_context),
        None => WorkflowDataStepContext::default(),
    };
    if workflow_data_step_context.unavailable {
        workflow_data_catalog = unavailable_workflow_data_completion_catalog();
    }
    (
        tool_catalog,
        module_catalog,
        workflow_data_catalog,
        workflow_data_step_context,
    )
}

#[cfg(test)]
fn tool_completion_catalog_from_initialize_options(
    params: &InitializeParams,
) -> ToolCompletionCatalog {
    completion_catalogs_from_initialize_options(params).0
}

#[cfg(test)]
fn module_completion_catalog_from_initialize_options(
    params: &InitializeParams,
) -> ModuleCompletionCatalog {
    completion_catalogs_from_initialize_options(params).1
}

#[cfg(test)]
fn workflow_data_completion_catalog_from_initialize_options(
    params: &InitializeParams,
) -> WorkflowDataCompletionCatalog {
    completion_catalogs_from_initialize_options(params).2
}

#[cfg(test)]
fn workflow_data_step_context_from_initialize_options(
    params: &InitializeParams,
) -> WorkflowDataStepContext {
    completion_catalogs_from_initialize_options(params).3
}

fn unavailable_tool_completion_catalog() -> ToolCompletionCatalog {
    ToolCompletionCatalog {
        tools: Vec::new(),
        unavailable: true,
    }
}

fn unavailable_module_completion_catalog() -> ModuleCompletionCatalog {
    ModuleCompletionCatalog {
        modules: Vec::new(),
        unavailable: true,
    }
}

fn unavailable_workflow_data_completion_catalog() -> WorkflowDataCompletionCatalog {
    WorkflowDataCompletionCatalog {
        input_fields: Vec::new(),
        outputs: Vec::new(),
        configured: true,
        unavailable: true,
    }
}

fn unavailable_workflow_data_step_context() -> WorkflowDataStepContext {
    WorkflowDataStepContext {
        completed_output_count: 0,
        configured: true,
        unavailable: true,
    }
}

/// Reads the name, format, and description fields from a serialized
/// `CapabilityRuntime::tool_catalog()` response without taking a dependency on
/// the effectful capability crate. Unknown descriptor fields are intentionally
/// ignored; the retained projection remains bounded and non-authoritative.
fn parse_tool_completion_catalog(value: &serde_json::Value) -> Option<ToolCompletionCatalog> {
    let entries = value.as_array()?;
    if entries.len() > MAX_LSP_TOOL_CATALOG_TOOLS {
        return None;
    }

    let mut retained_bytes = 0_usize;
    let mut tools = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry.as_object()?;
        let name = object.get("name")?.as_str()?;
        if !is_valid_catalog_tool_name(name) {
            return None;
        }
        let format = ToolCatalogFormat::from_catalog_value(object.get("format")?.as_str()?)?;
        let description = match object.get("description") {
            Some(value) => value.as_str()?,
            None => "",
        };
        if description.len() > MAX_LSP_TOOL_DESCRIPTION_BYTES {
            return None;
        }
        let entry_bytes = name.len().checked_add(description.len())?.checked_add(1)?;
        retained_bytes = retained_bytes.checked_add(entry_bytes)?;
        if retained_bytes > MAX_LSP_TOOL_CATALOG_BYTES
            || tools
                .iter()
                .any(|tool: &ToolCatalogCompletion| tool.name == name)
        {
            return None;
        }
        tools.push(ToolCatalogCompletion {
            name: name.to_owned(),
            format,
            description: description.to_owned(),
        });
    }
    tools.sort_by(|left, right| left.name.cmp(&right.name));

    Some(ToolCompletionCatalog {
        tools,
        unavailable: false,
    })
}

fn is_valid_catalog_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_LSP_TOOL_NAME_BYTES
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Reads a tiny static `mod.*` interface projection without treating it as a
/// module registry. Each path must be canonical source spelling rooted at
/// `mod`; unknown descriptor fields remain intentionally ignored. Optional
/// `callMode` and `callShape` values are advisory metadata for an exact
/// callable path only.
fn parse_module_completion_catalog(value: &serde_json::Value) -> Option<ModuleCompletionCatalog> {
    let entries = value.as_array()?;
    if entries.len() > MAX_LSP_MODULE_CATALOG_ENTRIES {
        return None;
    }

    let mut retained_bytes = 0_usize;
    let mut retained_input_fields = 0_usize;
    let mut retained_output_fields = 0_usize;
    let mut modules = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry.as_object()?;
        let path = parse_module_catalog_path(object.get("path")?.as_str()?)?;
        let description = match object.get("description") {
            Some(value) => value.as_str()?,
            None => "",
        };
        let call_mode = match object.get("callMode") {
            Some(value) => Some(ModuleCatalogCallMode::from_catalog_value(value.as_str()?)?),
            None => None,
        };
        let call_shape = match object.get("callShape") {
            Some(value) => Some(ModuleCatalogCallShape::from_catalog_value(value.as_str()?)?),
            None => None,
        };
        // Direct capability methods live below an import target (`mod.<module>.<method>`).
        // Do not present promise semantics for a bare import target.
        if call_mode.is_some() && path.len() < 3 {
            return None;
        }
        // A shape says more than presentation mode, so do not accept it on a
        // path that does not identify a callable method.
        if call_shape.is_some() && call_mode.is_none() {
            return None;
        }
        let input_fields = match object.get("inputFields") {
            Some(value) => Some(parse_module_catalog_record_fields(
                value,
                &mut retained_bytes,
                &mut retained_input_fields,
            )?),
            None => None,
        };
        let output_fields = match object.get("outputFields") {
            Some(value) => Some(parse_module_catalog_output_fields(
                value,
                &mut retained_bytes,
                &mut retained_output_fields,
            )?),
            None => None,
        };
        // Record fields are meaningful only for a fully explicit one-JSON-value
        // direct method shape. Never infer record structure from a mode alone.
        if (input_fields.is_some() || output_fields.is_some())
            && call_shape != Some(ModuleCatalogCallShape::SingleJson)
        {
            return None;
        }
        if description.len() > MAX_LSP_MODULE_DESCRIPTION_BYTES {
            return None;
        }
        let path_bytes = path
            .iter()
            .try_fold(0_usize, |total, segment| total.checked_add(segment.len()))?
            .checked_add(path.len().saturating_sub(1))?;
        let entry_bytes = path_bytes
            .checked_add(description.len())?
            .checked_add(call_mode.map_or(0, |mode| mode.as_catalog_value().len()))?
            .checked_add(call_shape.map_or(0, |shape| shape.as_catalog_value().len()))?
            .checked_add(1)?;
        retained_bytes = retained_bytes.checked_add(entry_bytes)?;
        if retained_bytes > MAX_LSP_MODULE_CATALOG_BYTES
            || modules
                .iter()
                .any(|module: &ModuleCatalogCompletion| module.path == path)
        {
            return None;
        }
        modules.push(ModuleCatalogCompletion {
            path,
            description: description.to_owned(),
            call_mode,
            call_shape,
            input_fields,
            output_fields,
        });
    }
    if modules.iter().any(|module| {
        module.call_mode.is_some()
            && modules.iter().any(|other| {
                other.path.len() > module.path.len() && other.path.starts_with(&module.path)
            })
    }) {
        return None;
    }
    modules.sort_by(|left, right| left.path.cmp(&right.path));

    Some(ModuleCompletionCatalog {
        modules,
        unavailable: false,
    })
}

/// Retains one bounded nested-input record projection. A child `fields` list
/// is allowed only on an explicit object field and only through the fixed
/// direct-child depth, keeping this distinct from JSON Schema evaluation.
fn parse_module_catalog_record_fields(
    value: &serde_json::Value,
    retained_bytes: &mut usize,
    retained_fields: &mut usize,
) -> Option<Vec<ModuleCatalogRecordFieldCompletion>> {
    parse_module_catalog_record_fields_at_depth(
        value,
        retained_bytes,
        retained_fields,
        MAX_LSP_MODULE_INPUT_FIELD_CHILD_DEPTH,
    )
}

fn parse_module_catalog_record_fields_at_depth(
    value: &serde_json::Value,
    retained_bytes: &mut usize,
    retained_fields: &mut usize,
    remaining_child_depth: usize,
) -> Option<Vec<ModuleCatalogRecordFieldCompletion>> {
    let entries = value.as_array()?;
    if entries.len() > MAX_LSP_MODULE_RECORD_FIELDS {
        return None;
    }

    let mut fields = Vec::with_capacity(entries.len());
    for entry in entries {
        let field = entry.as_object()?;
        let name = field.get("name")?.as_str()?;
        let field_type =
            ModuleCatalogRecordFieldType::from_catalog_value(field.get("type")?.as_str()?)?;
        let required = field.get("required")?.as_bool()?;
        let description = match field.get("description") {
            Some(value) => value.as_str()?,
            None => "",
        };
        if name.len() > MAX_LSP_MODULE_RECORD_FIELD_NAME_BYTES
            || !is_canonical_identifier(name)
            || description.len() > MAX_LSP_MODULE_RECORD_FIELD_DESCRIPTION_BYTES
            || fields
                .iter()
                .any(|existing: &ModuleCatalogRecordFieldCompletion| existing.name == name)
        {
            return None;
        }
        *retained_fields = retained_fields.checked_add(1)?;
        if *retained_fields > MAX_LSP_MODULE_RECORD_FIELDS {
            return None;
        }
        let entry_bytes = name
            .len()
            .checked_add(field_type.label().len())?
            .checked_add(description.len())?
            .checked_add(1)?;
        *retained_bytes = retained_bytes.checked_add(entry_bytes)?;
        if *retained_bytes > MAX_LSP_MODULE_CATALOG_BYTES {
            return None;
        }
        let child_fields = match field.get("fields") {
            Some(value)
                if field_type == ModuleCatalogRecordFieldType::Object
                    && remaining_child_depth > 0 =>
            {
                Some(parse_module_catalog_record_fields_at_depth(
                    value,
                    retained_bytes,
                    retained_fields,
                    remaining_child_depth - 1,
                )?)
            }
            Some(_) => return None,
            None => None,
        };
        fields.push(ModuleCatalogRecordFieldCompletion {
            name: name.to_owned(),
            field_type,
            required,
            description: description.to_owned(),
            fields: child_fields,
        });
    }
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    Some(fields)
}

/// Retains one bounded nested-output record projection. A child `fields` list
/// is allowed only on an explicit object field and only through the fixed
/// direct-child depth, keeping this distinct from JSON Schema evaluation.
fn parse_module_catalog_output_fields(
    value: &serde_json::Value,
    retained_bytes: &mut usize,
    retained_fields: &mut usize,
) -> Option<Vec<ModuleCatalogOutputFieldCompletion>> {
    parse_module_catalog_output_fields_at_depth(
        value,
        retained_bytes,
        retained_fields,
        MAX_LSP_MODULE_OUTPUT_FIELD_CHILD_DEPTH,
    )
}

fn parse_module_catalog_output_fields_at_depth(
    value: &serde_json::Value,
    retained_bytes: &mut usize,
    retained_fields: &mut usize,
    remaining_child_depth: usize,
) -> Option<Vec<ModuleCatalogOutputFieldCompletion>> {
    let entries = value.as_array()?;
    if entries.len() > MAX_LSP_MODULE_RECORD_FIELDS {
        return None;
    }

    let mut fields = Vec::with_capacity(entries.len());
    for entry in entries {
        let field = entry.as_object()?;
        let name = field.get("name")?.as_str()?;
        let field_type =
            ModuleCatalogRecordFieldType::from_catalog_value(field.get("type")?.as_str()?)?;
        let required = field.get("required")?.as_bool()?;
        let description = match field.get("description") {
            Some(value) => value.as_str()?,
            None => "",
        };
        if name.len() > MAX_LSP_MODULE_RECORD_FIELD_NAME_BYTES
            || !is_canonical_identifier(name)
            || description.len() > MAX_LSP_MODULE_RECORD_FIELD_DESCRIPTION_BYTES
            || fields
                .iter()
                .any(|existing: &ModuleCatalogOutputFieldCompletion| existing.name == name)
        {
            return None;
        }
        *retained_fields = retained_fields.checked_add(1)?;
        if *retained_fields > MAX_LSP_MODULE_RECORD_FIELDS {
            return None;
        }
        let entry_bytes = name
            .len()
            .checked_add(field_type.label().len())?
            .checked_add(description.len())?
            .checked_add(1)?;
        *retained_bytes = retained_bytes.checked_add(entry_bytes)?;
        if *retained_bytes > MAX_LSP_MODULE_CATALOG_BYTES {
            return None;
        }
        let child_fields = match field.get("fields") {
            Some(value)
                if field_type == ModuleCatalogRecordFieldType::Object
                    && remaining_child_depth > 0 =>
            {
                Some(parse_module_catalog_output_fields_at_depth(
                    value,
                    retained_bytes,
                    retained_fields,
                    remaining_child_depth - 1,
                )?)
            }
            Some(_) => return None,
            None => None,
        };
        fields.push(ModuleCatalogOutputFieldCompletion {
            name: name.to_owned(),
            field_type,
            required,
            description: description.to_owned(),
            fields: child_fields,
        });
    }
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    Some(fields)
}

fn parse_module_catalog_path(path: &str) -> Option<Vec<String>> {
    if path.len() > MAX_LSP_MODULE_PATH_BYTES {
        return None;
    }
    let segments = path.split('.').map(str::to_owned).collect::<Vec<_>>();
    if segments.len() < 2
        || segments.len() > MAX_LSP_MODULE_PATH_SEGMENTS
        || segments.first().is_none_or(|segment| segment != "mod")
        || segments.get(1).is_some_and(|segment| segment == "tool")
        || !segments
            .iter()
            .skip(1)
            .all(|segment| is_canonical_identifier(segment))
    {
        return None;
    }
    Some(segments)
}

/// Reads a normalized, static projection of host-owned workflow data schemas.
///
/// The projection intentionally contains only identifier-addressable object
/// fields. Hosts must derive it from their own executable contracts; this
/// parser never accepts source schemas, follows references, or infers a
/// runtime value. Any malformed, duplicate, or over-limit entry discards the
/// complete projection.
fn parse_workflow_data_completion_catalog(
    value: &serde_json::Value,
) -> Option<WorkflowDataCompletionCatalog> {
    let object = value.as_object()?;
    let mut retained_bytes = 0_usize;
    let mut retained_fields = 0_usize;
    let input_fields = parse_workflow_data_fields(
        object.get("inputFields")?,
        &mut retained_bytes,
        &mut retained_fields,
    )?;
    let output_entries = object.get("outputs")?.as_array()?;
    if output_entries.len() > MAX_LSP_WORKFLOW_DATA_OUTPUTS {
        return None;
    }

    let mut outputs = Vec::with_capacity(output_entries.len());
    for entry in output_entries {
        let output = entry.as_object()?;
        let step_id = output.get("stepId")?.as_str()?;
        if !is_valid_workflow_data_path_segment(step_id)
            || outputs
                .iter()
                .any(|existing: &WorkflowDataOutputCompletion| existing.step_id == step_id)
        {
            return None;
        }
        retained_bytes = retained_bytes.checked_add(step_id.len())?.checked_add(1)?;
        if retained_bytes > MAX_LSP_WORKFLOW_DATA_BYTES {
            return None;
        }
        let fields = parse_workflow_data_fields(
            output.get("fields")?,
            &mut retained_bytes,
            &mut retained_fields,
        )?;
        outputs.push(WorkflowDataOutputCompletion {
            step_id: step_id.to_owned(),
            fields,
        });
    }
    // Preserve host order so an optional step context can prove a completed
    // projected prefix. Completion presentation remains sorted separately.

    Some(WorkflowDataCompletionCatalog {
        input_fields,
        outputs,
        configured: true,
        unavailable: false,
    })
}

/// Reads a bounded advisory workflow position against one already-valid static
/// projection. The current step must be exactly the catalog entry after the
/// declared completed prefix, which rejects skipped, reordered, and future
/// projected outputs without consulting a runtime or plan.
fn parse_workflow_data_step_context(
    value: &serde_json::Value,
    catalog: &WorkflowDataCompletionCatalog,
) -> Option<WorkflowDataStepContext> {
    if !catalog.configured || catalog.unavailable {
        return None;
    }
    let object = value.as_object()?;
    let current_step_id = object.get("currentStepId")?.as_str()?;
    let completed_step_ids = object.get("completedOutputStepIds")?.as_array()?;
    let current = catalog.outputs.get(completed_step_ids.len())?;
    if current.step_id != current_step_id
        || !catalog
            .outputs
            .iter()
            .zip(completed_step_ids)
            .all(|(output, step_id)| step_id.as_str() == Some(output.step_id.as_str()))
    {
        return None;
    }

    Some(WorkflowDataStepContext {
        completed_output_count: completed_step_ids.len(),
        configured: true,
        unavailable: false,
    })
}

/// Extracts the optional `settings.splash` object from a standard LSP
/// configuration notification. An absent object leaves existing metadata
/// alone; malformed configuration invalidates the affected advisory catalog.
fn splash_settings_from_configuration(
    settings: &serde_json::Value,
) -> Result<Option<&serde_json::Map<String, serde_json::Value>>, ()> {
    let Some(settings) = settings.as_object() else {
        return Err(());
    };
    let Some(splash) = settings.get("splash") else {
        return Ok(None);
    };
    splash.as_object().map(Some).ok_or(())
}

/// Parses one independent advisory catalog configuration value. A host may
/// omit the key to retain a prior projection, send `null` to clear it, or send
/// one complete replacement. A malformed configuration fails closed.
fn advisory_catalog_configuration_update_from_settings<Catalog>(
    settings: &serde_json::Value,
    key: &str,
    parse: impl FnOnce(&serde_json::Value) -> Option<Catalog>,
) -> AdvisoryCatalogConfigurationUpdate<Catalog> {
    let splash = match splash_settings_from_configuration(settings) {
        Ok(Some(splash)) => splash,
        Ok(None) => return AdvisoryCatalogConfigurationUpdate::Keep,
        Err(()) => return AdvisoryCatalogConfigurationUpdate::Clear,
    };
    let Some(value) = splash.get(key) else {
        return AdvisoryCatalogConfigurationUpdate::Keep;
    };
    if value.is_null() {
        return AdvisoryCatalogConfigurationUpdate::Clear;
    }
    parse(value)
        .map(AdvisoryCatalogConfigurationUpdate::Replace)
        .unwrap_or(AdvisoryCatalogConfigurationUpdate::Clear)
}

fn tool_catalog_configuration_update_from_settings(
    settings: &serde_json::Value,
) -> AdvisoryCatalogConfigurationUpdate<ToolCompletionCatalog> {
    advisory_catalog_configuration_update_from_settings(
        settings,
        "toolCatalog",
        parse_tool_completion_catalog,
    )
}

fn module_catalog_configuration_update_from_settings(
    settings: &serde_json::Value,
) -> AdvisoryCatalogConfigurationUpdate<ModuleCompletionCatalog> {
    advisory_catalog_configuration_update_from_settings(
        settings,
        "moduleCatalog",
        parse_module_completion_catalog,
    )
}

/// Parses the workflow-specific portion of a standard LSP configuration
/// update. The update deliberately requires both catalog and context: merging
/// a new position into an old schema, or retaining an old position after a
/// malformed replacement, could present stale dataflow suggestions.
fn workflow_data_configuration_update_from_settings(
    settings: &serde_json::Value,
) -> WorkflowDataConfigurationUpdate {
    let splash = match splash_settings_from_configuration(settings) {
        Ok(Some(splash)) => splash,
        Ok(None) => return WorkflowDataConfigurationUpdate::Keep,
        Err(()) => return unavailable_workflow_data_configuration_update(),
    };
    let (Some(catalog), Some(context)) = (
        splash.get("workflowDataCatalog"),
        splash.get("workflowDataStepContext"),
    ) else {
        return if splash.contains_key("workflowDataCatalog")
            || splash.contains_key("workflowDataStepContext")
        {
            unavailable_workflow_data_configuration_update()
        } else {
            WorkflowDataConfigurationUpdate::Keep
        };
    };
    if catalog.is_null() && context.is_null() {
        return WorkflowDataConfigurationUpdate::Clear;
    }
    if catalog.is_null() || context.is_null() {
        return unavailable_workflow_data_configuration_update();
    }

    let mut catalog = parse_workflow_data_completion_catalog(catalog)
        .unwrap_or_else(unavailable_workflow_data_completion_catalog);
    let step_context = parse_workflow_data_step_context(context, &catalog)
        .unwrap_or_else(unavailable_workflow_data_step_context);
    if step_context.unavailable {
        catalog = unavailable_workflow_data_completion_catalog();
    }
    WorkflowDataConfigurationUpdate::Replace {
        catalog,
        step_context,
    }
}

fn unavailable_workflow_data_configuration_update() -> WorkflowDataConfigurationUpdate {
    WorkflowDataConfigurationUpdate::Replace {
        catalog: unavailable_workflow_data_completion_catalog(),
        step_context: unavailable_workflow_data_step_context(),
    }
}

fn parse_workflow_data_fields(
    value: &serde_json::Value,
    retained_bytes: &mut usize,
    retained_fields: &mut usize,
) -> Option<Vec<WorkflowDataFieldCompletion>> {
    let entries = value.as_array()?;
    if entries.len() > MAX_LSP_WORKFLOW_DATA_FIELDS {
        return None;
    }

    let mut fields = Vec::with_capacity(entries.len());
    for entry in entries {
        let field = entry.as_object()?;
        let name = field.get("name")?.as_str()?;
        let field_type = WorkflowDataFieldType::from_catalog_value(field.get("type")?.as_str()?)?;
        let description = match field.get("description") {
            Some(value) => value.as_str()?,
            None => "",
        };
        if !is_valid_workflow_data_path_segment(name)
            || description.len() > MAX_LSP_WORKFLOW_DATA_FIELD_DESCRIPTION_BYTES
            || fields
                .iter()
                .any(|existing: &WorkflowDataFieldCompletion| existing.name == name)
        {
            return None;
        }
        *retained_fields = retained_fields.checked_add(1)?;
        if *retained_fields > MAX_LSP_WORKFLOW_DATA_FIELDS {
            return None;
        }
        let entry_bytes = name
            .len()
            .checked_add(field_type.label().len())?
            .checked_add(description.len())?
            .checked_add(1)?;
        *retained_bytes = retained_bytes.checked_add(entry_bytes)?;
        if *retained_bytes > MAX_LSP_WORKFLOW_DATA_BYTES {
            return None;
        }
        fields.push(WorkflowDataFieldCompletion {
            name: name.to_owned(),
            field_type,
            description: description.to_owned(),
        });
    }
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    Some(fields)
}

fn is_valid_workflow_data_path_segment(value: &str) -> bool {
    value.len() <= MAX_LSP_WORKFLOW_DATA_FIELD_NAME_BYTES && is_canonical_identifier(value)
}

fn server_capabilities(versioned_document_edits: bool) -> ServerCapabilities {
    ServerCapabilities {
        position_encoding: Some(PositionEncodingKind::UTF16),
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        document_formatting_provider: Some(OneOf::Left(true)),
        document_symbol_provider: Some(OneOf::Left(true)),
        definition_provider: Some(OneOf::Left(true)),
        references_provider: Some(OneOf::Left(true)),
        hover_provider: Some(true.into()),
        document_highlight_provider: Some(OneOf::Left(true)),
        completion_provider: Some(CompletionOptions {
            resolve_provider: Some(false),
            trigger_characters: Some(vec![".".to_owned()]),
            ..CompletionOptions::default()
        }),
        signature_help_provider: Some(SignatureHelpOptions {
            trigger_characters: Some(vec!["(".to_owned()]),
            retrigger_characters: Some(vec![",".to_owned()]),
            ..SignatureHelpOptions::default()
        }),
        rename_provider: versioned_document_edits.then(|| {
            OneOf::Right(RenameOptions {
                prepare_provider: Some(true),
                work_done_progress_options: Default::default(),
            })
        }),
        ..ServerCapabilities::default()
    }
}

fn handle_request(
    connection: &Connection,
    server: &SplashLanguageServer,
    versioned_document_edits: bool,
    request: Request,
) -> ServerResult<()> {
    let response = if request.method == Formatting::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<DocumentFormattingParams>(request.params) {
            Ok(params) => match server.format_document(&params.text_document.uri) {
                Ok(edits) => Response::new_ok(id, edits),
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/formatting parameters: {error}"),
            ),
        }
    } else if request.method == DocumentSymbolRequest::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<DocumentSymbolParams>(request.params) {
            Ok(params) => match server.document_symbols(&params.text_document.uri) {
                Ok(symbols) => Response::new_ok(id, DocumentSymbolResponse::Nested(symbols)),
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/documentSymbol parameters: {error}"),
            ),
        }
    } else if request.method == GotoDefinition::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<GotoDefinitionParams>(request.params) {
            Ok(params) => {
                let text_document_position = params.text_document_position_params;
                match server.definition(
                    &text_document_position.text_document.uri,
                    text_document_position.position,
                ) {
                    Ok(location) => {
                        Response::new_ok(id, location.map(GotoDefinitionResponse::Scalar))
                    }
                    Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
                }
            }
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/definition parameters: {error}"),
            ),
        }
    } else if request.method == HoverRequest::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<HoverParams>(request.params) {
            Ok(params) => {
                let text_document_position = params.text_document_position_params;
                match server.hover(
                    &text_document_position.text_document.uri,
                    text_document_position.position,
                ) {
                    Ok(hover) => Response::new_ok(id, hover),
                    Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
                }
            }
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/hover parameters: {error}"),
            ),
        }
    } else if request.method == SignatureHelpRequest::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<SignatureHelpParams>(request.params) {
            Ok(params) => {
                let text_document_position = params.text_document_position_params;
                match server.signature_help(
                    &text_document_position.text_document.uri,
                    text_document_position.position,
                ) {
                    Ok(signature_help) => Response::new_ok(id, signature_help),
                    Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
                }
            }
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/signatureHelp parameters: {error}"),
            ),
        }
    } else if request.method == References::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<ReferenceParams>(request.params) {
            Ok(params) => match server.references(
                &params.text_document_position.text_document.uri,
                params.text_document_position.position,
                params.context.include_declaration,
            ) {
                Ok(locations) => Response::new_ok(id, Some(locations)),
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/references parameters: {error}"),
            ),
        }
    } else if request.method == DocumentHighlightRequest::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<DocumentHighlightParams>(request.params) {
            Ok(params) => {
                let text_document_position = params.text_document_position_params;
                match server.document_highlights(
                    &text_document_position.text_document.uri,
                    text_document_position.position,
                ) {
                    Ok(highlights) => Response::new_ok(id, Some(highlights)),
                    Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
                }
            }
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/documentHighlight parameters: {error}"),
            ),
        }
    } else if request.method == Completion::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<CompletionParams>(request.params) {
            Ok(params) => {
                let text_document_position = params.text_document_position;
                match server.completion(
                    &text_document_position.text_document.uri,
                    text_document_position.position,
                ) {
                    Ok(completion) => Response::new_ok(id, CompletionResponse::List(completion)),
                    Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
                }
            }
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/completion parameters: {error}"),
            ),
        }
    } else if versioned_document_edits && request.method == PrepareRenameRequest::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<TextDocumentPositionParams>(request.params) {
            Ok(params) => match server.prepare_rename(&params.text_document.uri, params.position) {
                Ok(prepared) => Response::new_ok(id, prepared),
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/prepareRename parameters: {error}"),
            ),
        }
    } else if versioned_document_edits && request.method == Rename::METHOD {
        let id = request.id.clone();
        match serde_json::from_value::<RenameParams>(request.params) {
            Ok(params) => match server.rename(
                &params.text_document_position.text_document.uri,
                params.text_document_position.position,
                &params.new_name,
            ) {
                Ok(rename) => {
                    Response::new_ok(id, rename.map(VersionedRenameEdits::into_workspace_edit))
                }
                Err(message) => Response::new_err(id, ErrorCode::RequestFailed as i32, message),
            },
            Err(error) => Response::new_err(
                id,
                ErrorCode::InvalidParams as i32,
                format!("invalid textDocument/rename parameters: {error}"),
            ),
        }
    } else {
        Response::new_err(
            request.id,
            ErrorCode::MethodNotFound as i32,
            format!("unsupported Splash LSP request `{}`", request.method),
        )
    };

    send_message(connection, response.into())
}

fn handle_notification(
    connection: &Connection,
    server: &mut SplashLanguageServer,
    notification: Notification,
) -> ServerResult<()> {
    let diagnostics = match notification.method.as_str() {
        DidChangeConfiguration::METHOD => {
            match serde_json::from_value::<DidChangeConfigurationParams>(notification.params) {
                Ok(params) => server.refresh_advisory_configuration(&params.settings),
                Err(_) => server.invalidate_advisory_configuration(),
            }
            None
        }
        DidOpenTextDocument::METHOD => {
            serde_json::from_value::<DidOpenTextDocumentParams>(notification.params)
                .ok()
                .map(|params| server.open_document(params.text_document))
        }
        DidChangeTextDocument::METHOD => {
            serde_json::from_value::<DidChangeTextDocumentParams>(notification.params)
                .ok()
                .and_then(|params| server.change_document(params))
        }
        DidCloseTextDocument::METHOD => {
            serde_json::from_value::<DidCloseTextDocumentParams>(notification.params)
                .ok()
                .map(|params| server.close_document(params))
        }
        _ => None,
    };

    if let Some(diagnostics) = diagnostics {
        send_message(
            connection,
            Notification::new(PublishDiagnostics::METHOD.to_owned(), diagnostics).into(),
        )?;
    }

    Ok(())
}

fn send_message(connection: &Connection, message: Message) -> ServerResult<()> {
    connection.sender.send(message)?;
    Ok(())
}

fn syntax_diagnostics(uri: &Uri, source: &str) -> Vec<Diagnostic> {
    match check_syntax_named(uri.as_str(), source, ExecutionLimits::default()) {
        Ok(report) => {
            let mut diagnostics = report
                .diagnostics
                .iter()
                .map(|diagnostic| syntax_diagnostic(source, diagnostic))
                .collect::<Vec<_>>();
            if report.diagnostics_truncated {
                diagnostics.push(Diagnostic::new(
                    Range::new(Position::new(0, 0), Position::new(0, 0)),
                    Some(DiagnosticSeverity::WARNING),
                    None,
                    Some(DIAGNOSTIC_SOURCE.to_owned()),
                    format!("Splash stopped after {MAX_SYNTAX_DIAGNOSTICS} syntax diagnostics"),
                    None,
                    None,
                ));
            }
            diagnostics
        }
        Err(error) => vec![Diagnostic::new(
            Range::new(Position::new(0, 0), Position::new(0, 0)),
            Some(DiagnosticSeverity::ERROR),
            None,
            Some(DIAGNOSTIC_SOURCE.to_owned()),
            format!("Splash syntax check failed: {error}"),
            None,
            None,
        )],
    }
}

fn resource_diagnostics(uri: Uri, version: i32, message: String) -> PublishDiagnosticsParams {
    PublishDiagnosticsParams::new(
        uri,
        vec![Diagnostic::new(
            Range::new(Position::new(0, 0), Position::new(0, 0)),
            Some(DiagnosticSeverity::ERROR),
            None,
            Some(DIAGNOSTIC_SOURCE.to_owned()),
            message,
            None,
            None,
        )],
        Some(version),
    )
}

fn syntax_diagnostic(source: &str, diagnostic: &SyntaxDiagnostic) -> Diagnostic {
    let position = diagnostic_position(source, diagnostic.line, diagnostic.column);
    Diagnostic::new(
        Range::new(position, position),
        Some(DiagnosticSeverity::ERROR),
        None,
        Some(DIAGNOSTIC_SOURCE.to_owned()),
        diagnostic.message.clone(),
        None,
        None,
    )
}

fn diagnostic_position(source: &str, line: usize, column: usize) -> Position {
    let requested_line = line.saturating_sub(1);
    let mut line_index = 0;
    let mut source_line = "";

    for (index, candidate) in source.split('\n').enumerate() {
        line_index = index;
        source_line = candidate;
        if index >= requested_line {
            break;
        }
    }

    let character = source_line
        .chars()
        .take(column.saturating_sub(1))
        .fold(0_u32, |offset, character| {
            offset.saturating_add(character.len_utf16() as u32)
        });
    Position::new(to_u32(line_index), character)
}

fn document_end_position(source: &str) -> Position {
    position_at_byte(source, source.len())
}

#[allow(deprecated)]
fn outline_symbol(source: &str, declaration: &TopLevelDeclaration) -> DocumentSymbol {
    let selection_range = Range::new(
        position_at_byte(source, declaration.selection_start_byte),
        position_at_byte(source, declaration.selection_end_byte),
    );
    DocumentSymbol {
        name: declaration.name.clone(),
        detail: None,
        kind: match declaration.kind {
            TopLevelDeclarationKind::Function => SymbolKind::FUNCTION,
            TopLevelDeclarationKind::Let => SymbolKind::VARIABLE,
        },
        tags: None,
        deprecated: None,
        range: Range::new(
            position_at_byte(source, declaration.declaration_start_byte),
            position_at_byte(source, declaration.declaration_end_byte),
        ),
        selection_range,
        children: None,
    }
}

fn symbol_at_byte(report: &LexicalSymbolReport, byte_offset: usize) -> Option<&LexicalSymbol> {
    symbol_occurrence_at_byte(report, byte_offset).map(|(symbol, _)| symbol)
}

fn symbol_occurrence_at_byte(
    report: &LexicalSymbolReport,
    byte_offset: usize,
) -> Option<(&LexicalSymbol, SourceSpan)> {
    report.symbols.iter().find_map(|symbol| {
        if span_contains(symbol.definition, byte_offset) {
            return Some((symbol, symbol.definition));
        }
        symbol
            .references
            .iter()
            .copied()
            .find(|span| span_contains(*span, byte_offset))
            .map(|span| (symbol, span))
    })
}

fn span_contains(span: SourceSpan, byte_offset: usize) -> bool {
    span.start_byte <= byte_offset && byte_offset < span.end_byte
}

fn symbol_location(uri: &Uri, source: &str, span: SourceSpan) -> Location {
    Location::new(uri.clone(), span_range(source, span))
}

fn span_range(source: &str, span: SourceSpan) -> Range {
    Range::new(
        position_at_byte(source, span.start_byte),
        position_at_byte(source, span.end_byte),
    )
}

fn lexical_symbol_kind_label(kind: LexicalSymbolKind) -> &'static str {
    match kind {
        LexicalSymbolKind::Import => "import binding",
        LexicalSymbolKind::Function => "function",
        LexicalSymbolKind::Let => "binding",
        LexicalSymbolKind::Parameter => "function parameter",
        LexicalSymbolKind::LoopBinding => "loop binding",
        LexicalSymbolKind::LambdaParameter => "lambda parameter",
    }
}

fn completion_item_kind(kind: LexicalSymbolKind) -> CompletionItemKind {
    match kind {
        LexicalSymbolKind::Import => CompletionItemKind::MODULE,
        LexicalSymbolKind::Function => CompletionItemKind::FUNCTION,
        LexicalSymbolKind::Let
        | LexicalSymbolKind::Parameter
        | LexicalSymbolKind::LoopBinding
        | LexicalSymbolKind::LambdaParameter => CompletionItemKind::VARIABLE,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MemberCompletionSite {
    /// The first receiver identifier. Built-in tool and static-record
    /// completion intentionally accept only this direct form.
    receiver: SourceSpan,
    /// The complete contiguous identifier path from `receiver` to the member
    /// being completed. The module catalog may resolve its nested segments.
    receiver_chain: SourceSpan,
    member: SourceSpan,
}

impl MemberCompletionSite {
    fn has_direct_receiver(self) -> bool {
        self.receiver == self.receiver_chain
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignatureHelpCallContext {
    callee: MemberCompletionSite,
    opening_byte: usize,
    active_argument: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectFunctionSignatureHelpCallContext {
    callee: SourceSpan,
    active_argument: usize,
}

/// An exact root or direct child key position in the first literal-record
/// argument to a direct module method. The scanner retains only prior key
/// names so it can avoid proposing duplicate metadata fields without assigning
/// meaning to values or arbitrary expressions.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectModuleInputRecordCompletionSite {
    context: SignatureHelpCallContext,
    field: SourceSpan,
    parent_field: Option<String>,
    declared_fields: HashSet<String>,
}

/// A completed, exact direct-module initializer assigned to one local `let`
/// binding. The source scanner never follows aliases or arbitrary expressions;
/// it records only the one visible imported member call and whether the exact
/// deferred suffix was present.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectModuleOutputBinding {
    call: MemberCompletionSite,
    awaited: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectRecordDelimiterKind {
    Round,
    Square,
    Curly,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DirectRecordFieldState {
    Field,
    AfterField { start_byte: usize },
    Value { field_name: String, started: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectRecordInputScope {
    parent_field: Option<String>,
    declared_fields: HashSet<String>,
    state: DirectRecordFieldState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignatureHelpDelimiterKind {
    Round,
    Square,
    Curly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignatureHelpDelimiter {
    kind: SignatureHelpDelimiterKind,
    opening_byte: usize,
    argument_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImportPathCompletionSite {
    prefix: Vec<String>,
    segment: SourceSpan,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ToolNameCompletionSite {
    receiver: SourceSpan,
    name: SourceSpan,
    call_format: ToolCallFormat,
}

fn direct_module_member_completion_site(
    source: &str,
    byte_offset: usize,
) -> Option<MemberCompletionSite> {
    if byte_offset > source.len() || !source.is_char_boundary(byte_offset) {
        return None;
    }
    if string_content_span_at(source, byte_offset).is_some()
        || cursor_is_inside_comment(source, byte_offset)
    {
        return None;
    }

    let bytes = source.as_bytes();
    let mut member_start = byte_offset;
    while member_start > 0 && is_identifier_byte(bytes[member_start - 1]) {
        member_start -= 1;
    }
    let mut member_end = byte_offset;
    while member_end < bytes.len() && is_identifier_byte(bytes[member_end]) {
        member_end += 1;
    }
    if member_start == 0 || bytes[member_start - 1] != b'.' {
        return None;
    }
    if member_start < member_end && !is_identifier_start_byte(bytes[member_start]) {
        return None;
    }

    let receiver_chain_end = member_start - 1;
    let mut receiver_end = receiver_chain_end;
    let mut receiver_segments = 0_usize;
    let receiver = loop {
        if receiver_segments == MAX_LSP_MODULE_PATH_SEGMENTS {
            return None;
        }
        let receiver_start = identifier_start_before(source, receiver_end);
        if receiver_start == receiver_end || !is_identifier_start_byte(bytes[receiver_start]) {
            return None;
        }
        let receiver_name = source.get(receiver_start..receiver_end)?;
        if !is_canonical_identifier(receiver_name) {
            return None;
        }
        receiver_segments += 1;
        let receiver = SourceSpan {
            start_byte: receiver_start,
            end_byte: receiver_end,
        };
        if receiver_start == 0 || bytes[receiver_start - 1] != b'.' {
            break receiver;
        }
        receiver_end = receiver_start - 1;
    };

    Some(MemberCompletionSite {
        receiver,
        receiver_chain: SourceSpan {
            start_byte: receiver.start_byte,
            end_byte: receiver_chain_end,
        },
        member: SourceSpan {
            start_byte: member_start,
            end_byte: member_end,
        },
    })
}

/// Recognizes only `let result = imported.method(input)` and the exact
/// deferred form `let result = imported.method(input).await()`. This is a
/// bounded syntactic projection for advisory editor metadata, not expression
/// parsing, evaluation, or result-type inference.
fn direct_module_output_binding(
    source: &str,
    symbol: &LexicalSymbol,
    valid_prefix_end_byte: usize,
) -> Option<DirectModuleOutputBinding> {
    if symbol.kind != LexicalSymbolKind::Let
        || symbol.definition.end_byte > valid_prefix_end_byte
        || valid_prefix_end_byte > source.len()
    {
        return None;
    }

    let initializer_limit_byte = symbol
        .definition
        .end_byte
        .checked_add(MAX_LSP_DIRECT_MODULE_OUTPUT_INITIALIZER_BYTES)?
        .min(valid_prefix_end_byte);
    let assignment =
        skip_splash_trivia_before(source, symbol.definition.end_byte, initializer_limit_byte)?;
    let after_assignment = assignment.checked_add(1)?;
    if source.as_bytes().get(assignment) != Some(&b'=')
        || (after_assignment < initializer_limit_byte
            && source.as_bytes().get(after_assignment) == Some(&b'='))
    {
        return None;
    }
    let initializer_start =
        skip_splash_trivia_before(source, after_assignment, initializer_limit_byte)?;
    let (call, call_end_byte) =
        direct_module_output_call_at(source, initializer_start, initializer_limit_byte)?;

    let await_end_byte = call_end_byte.checked_add(b".await()".len())?;
    let (awaited, initializer_end_byte) = if await_end_byte <= initializer_limit_byte
        && source.get(call_end_byte..await_end_byte) == Some(".await()")
    {
        (true, await_end_byte)
    } else {
        (false, call_end_byte)
    };
    direct_module_output_statement_boundary(source, initializer_end_byte, initializer_limit_byte)
        .then_some(DirectModuleOutputBinding { call, awaited })
}

/// Parses the exact direct callee spelling and a completed one-argument call.
/// The input itself remains opaque: strings, comments, and balanced delimiters
/// are retained solely to find the call boundary safely.
fn direct_module_output_call_at(
    source: &str,
    start_byte: usize,
    valid_prefix_end_byte: usize,
) -> Option<(MemberCompletionSite, usize)> {
    if start_byte >= valid_prefix_end_byte || valid_prefix_end_byte > source.len() {
        return None;
    }
    let maximum_end_byte = start_byte
        .checked_add(MAX_LSP_DIRECT_MODULE_OUTPUT_INITIALIZER_BYTES)?
        .min(valid_prefix_end_byte);
    let bytes = source.as_bytes();
    let receiver_end_byte =
        direct_module_output_identifier_end(source, start_byte, maximum_end_byte)?;
    if receiver_end_byte >= maximum_end_byte || bytes.get(receiver_end_byte) != Some(&b'.') {
        return None;
    }
    let member_start_byte = receiver_end_byte.checked_add(1)?;
    let member_end_byte =
        direct_module_output_identifier_end(source, member_start_byte, maximum_end_byte)?;
    if member_end_byte >= maximum_end_byte || bytes.get(member_end_byte) != Some(&b'(') {
        return None;
    }
    let call_end_byte =
        direct_module_output_single_argument_call_end(source, member_end_byte, maximum_end_byte)?;

    Some((
        MemberCompletionSite {
            receiver: SourceSpan {
                start_byte,
                end_byte: receiver_end_byte,
            },
            receiver_chain: SourceSpan {
                start_byte,
                end_byte: receiver_end_byte,
            },
            member: SourceSpan {
                start_byte: member_start_byte,
                end_byte: member_end_byte,
            },
        },
        call_end_byte,
    ))
}

fn direct_module_output_identifier_end(
    source: &str,
    start_byte: usize,
    maximum_end_byte: usize,
) -> Option<usize> {
    let bytes = source.as_bytes();
    if start_byte >= maximum_end_byte
        || !source.is_char_boundary(start_byte)
        || !is_identifier_start_byte(*bytes.get(start_byte)?)
    {
        return None;
    }
    let mut end_byte = start_byte + 1;
    while end_byte < maximum_end_byte
        && bytes
            .get(end_byte)
            .is_some_and(|byte| is_identifier_byte(*byte))
    {
        end_byte += 1;
    }
    let name = source.get(start_byte..end_byte)?;
    is_canonical_identifier(name).then_some(end_byte)
}

/// Finds the closing parenthesis for one non-empty, single-argument direct
/// call. A top-level comma, mismatched delimiter, unterminated string/comment,
/// or nesting beyond the language limit refuses the result binding entirely.
fn direct_module_output_single_argument_call_end(
    source: &str,
    opening_byte: usize,
    maximum_end_byte: usize,
) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(opening_byte) != Some(&b'(') || opening_byte >= maximum_end_byte {
        return None;
    }

    let mut delimiters = vec![SignatureHelpDelimiterKind::Round];
    let mut argument_started = false;
    let mut index = opening_byte + 1;
    while index < maximum_end_byte {
        match bytes[index] {
            b'"' => {
                argument_started = true;
                index = direct_module_output_string_end(source, index, maximum_end_byte)?;
            }
            b'/' if index + 1 < maximum_end_byte && bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < maximum_end_byte && !matches!(bytes[index], b'\n' | b'\r') {
                    index = advance_utf8_character(source, index);
                }
            }
            b'/' if index + 1 < maximum_end_byte && bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut terminated = false;
                while index < maximum_end_byte {
                    if index + 1 < maximum_end_byte
                        && bytes[index] == b'*'
                        && bytes.get(index + 1) == Some(&b'/')
                    {
                        index += 2;
                        terminated = true;
                        break;
                    }
                    index = advance_utf8_character(source, index);
                }
                if !terminated {
                    return None;
                }
            }
            b'(' => {
                if delimiters.len() == MAX_SIGNATURE_HELP_DELIMITER_DEPTH {
                    return None;
                }
                argument_started = true;
                delimiters.push(SignatureHelpDelimiterKind::Round);
                index += 1;
            }
            b'[' => {
                if delimiters.len() == MAX_SIGNATURE_HELP_DELIMITER_DEPTH {
                    return None;
                }
                argument_started = true;
                delimiters.push(SignatureHelpDelimiterKind::Square);
                index += 1;
            }
            b'{' => {
                if delimiters.len() == MAX_SIGNATURE_HELP_DELIMITER_DEPTH {
                    return None;
                }
                argument_started = true;
                delimiters.push(SignatureHelpDelimiterKind::Curly);
                index += 1;
            }
            b')' => {
                let delimiter = delimiters.pop()?;
                if delimiter != SignatureHelpDelimiterKind::Round {
                    return None;
                }
                index += 1;
                if delimiters.is_empty() {
                    return argument_started.then_some(index);
                }
            }
            b']' => {
                let delimiter = delimiters.pop()?;
                if delimiter != SignatureHelpDelimiterKind::Square {
                    return None;
                }
                index += 1;
            }
            b'}' => {
                let delimiter = delimiters.pop()?;
                if delimiter != SignatureHelpDelimiterKind::Curly {
                    return None;
                }
                index += 1;
            }
            b',' if delimiters.len() == 1 => return None,
            b';' if delimiters.len() == 1 => return None,
            byte if byte.is_ascii_whitespace() => index += 1,
            _ => {
                argument_started = true;
                index = advance_utf8_character(source, index);
            }
        }
    }
    None
}

fn direct_module_output_string_end(
    source: &str,
    opening_byte: usize,
    maximum_end_byte: usize,
) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(opening_byte) != Some(&b'"') {
        return None;
    }
    let mut index = opening_byte + 1;
    while index < maximum_end_byte {
        match bytes[index] {
            b'"' => return Some(index + 1),
            b'\\' => {
                index = advance_utf8_character(source, index);
                if index < maximum_end_byte {
                    index = advance_utf8_character(source, index);
                }
            }
            b'\n' | b'\r' => return None,
            _ => index = advance_utf8_character(source, index),
        }
    }
    None
}

/// Requires that the direct call is the whole initializer. Horizontal trivia
/// and comments are allowed, but another postfix/operator/expression is not.
/// A newline in either ordinary or comment trivia is a canonical statement
/// boundary; a `}` is accepted for a completed enclosing block.
fn direct_module_output_statement_boundary(
    source: &str,
    mut index: usize,
    valid_prefix_end_byte: usize,
) -> bool {
    if index > valid_prefix_end_byte || valid_prefix_end_byte > source.len() {
        return false;
    }

    let bytes = source.as_bytes();
    while index < valid_prefix_end_byte {
        match bytes[index] {
            b';' | b'}' | b'\n' => return true,
            b'\r' => {
                return index + 1 < valid_prefix_end_byte && bytes.get(index + 1) == Some(&b'\n')
            }
            byte if byte.is_ascii_whitespace() => index += 1,
            b'/' if index + 1 < valid_prefix_end_byte && bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < valid_prefix_end_byte && !matches!(bytes[index], b'\n' | b'\r') {
                    index = advance_utf8_character(source, index);
                }
            }
            b'/' if index + 1 < valid_prefix_end_byte && bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut contains_line_break = false;
                let mut terminated = false;
                while index < valid_prefix_end_byte {
                    if index + 1 < valid_prefix_end_byte
                        && bytes[index] == b'*'
                        && bytes.get(index + 1) == Some(&b'/')
                    {
                        index += 2;
                        terminated = true;
                        break;
                    }
                    contains_line_break |= matches!(bytes[index], b'\n' | b'\r');
                    index = advance_utf8_character(source, index);
                }
                if contains_line_break {
                    return true;
                }
                if !terminated {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// Bounded variant of the LSP's trivia skipper. It never scans beyond the
/// lexical report's valid source prefix while recognizing a result initializer.
fn skip_splash_trivia_before(source: &str, mut index: usize, end_byte: usize) -> Option<usize> {
    if index > end_byte || end_byte > source.len() {
        return None;
    }

    let bytes = source.as_bytes();
    loop {
        while index < end_byte
            && bytes
                .get(index)
                .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            index += 1;
        }
        if index == end_byte || bytes.get(index) != Some(&b'/') {
            return Some(index);
        }
        match bytes.get(index + 1) {
            Some(b'/') if index + 1 < end_byte => {
                index += 2;
                while index < end_byte && !matches!(bytes[index], b'\n' | b'\r') {
                    index = advance_utf8_character(source, index);
                }
            }
            Some(b'*') if index + 1 < end_byte => {
                index += 2;
                while index < end_byte
                    && !(index + 1 < end_byte
                        && bytes[index] == b'*'
                        && bytes.get(index + 1) == Some(&b'/'))
                {
                    index = advance_utf8_character(source, index);
                }
                if index == end_byte {
                    return None;
                }
                index += 2;
            }
            _ => return Some(index),
        }
    }
}

/// Finds the enclosing direct member call at a cursor without parsing or
/// evaluating source. An in-progress string argument is allowed so signature
/// help remains useful while a user types; a cursor inside a comment fails
/// closed.
fn signature_help_call_context(
    source: &str,
    byte_offset: usize,
) -> Option<SignatureHelpCallContext> {
    let opening = signature_help_opening_delimiter_before(source, byte_offset)?;
    let callee_end = skip_ascii_whitespace_backward(source, opening.opening_byte);
    let callee = direct_module_member_completion_site(source, callee_end)?;
    (callee.member.end_byte == callee_end).then_some(SignatureHelpCallContext {
        callee,
        opening_byte: opening.opening_byte,
        active_argument: opening.argument_count,
    })
}

/// Finds the enclosing direct identifier call at a cursor without treating a
/// member call, alias, or computed expression as a fixed core function.
fn direct_function_signature_help_call_context(
    source: &str,
    byte_offset: usize,
) -> Option<DirectFunctionSignatureHelpCallContext> {
    let opening = signature_help_opening_delimiter_before(source, byte_offset)?;
    let callee_end = skip_ascii_whitespace_backward(source, opening.opening_byte);
    let callee_start = identifier_start_before(source, callee_end);
    if callee_start == callee_end {
        return None;
    }
    let prefix_end = skip_ascii_whitespace_backward(source, callee_start);
    if prefix_end > 0 && source.as_bytes()[prefix_end - 1] == b'.' {
        return None;
    }
    let callee = source.get(callee_start..callee_end)?;
    if !is_canonical_identifier(callee) {
        return None;
    }
    Some(DirectFunctionSignatureHelpCallContext {
        callee: SourceSpan {
            start_byte: callee_start,
            end_byte: callee_end,
        },
        active_argument: opening.argument_count,
    })
}

fn signature_help_opening_delimiter_before(
    source: &str,
    byte_offset: usize,
) -> Option<SignatureHelpDelimiter> {
    signature_help_delimiters_before(source, byte_offset)?
        .iter()
        .rev()
        .find(|delimiter| delimiter.kind == SignatureHelpDelimiterKind::Round)
        .copied()
}

/// Scans one bounded source prefix while preserving only delimiter state and
/// top-level call commas. It intentionally recognizes just comments and
/// strings needed to keep punctuation inside them from becoming source syntax.
fn signature_help_delimiters_before(
    source: &str,
    byte_offset: usize,
) -> Option<Vec<SignatureHelpDelimiter>> {
    if byte_offset > source.len() || !source.is_char_boundary(byte_offset) {
        return None;
    }

    let bytes = source.as_bytes();
    let mut delimiters = Vec::new();
    let mut index = 0_usize;
    while index < byte_offset {
        match bytes[index] {
            b'"' => {
                index += 1;
                let mut terminated = false;
                while index < byte_offset {
                    match bytes[index] {
                        b'"' => {
                            index += 1;
                            terminated = true;
                            break;
                        }
                        b'\\' => {
                            index = advance_utf8_character(source, index);
                            if index < byte_offset {
                                index = advance_utf8_character(source, index);
                            }
                        }
                        b'\n' | b'\r' => return None,
                        _ => index = advance_utf8_character(source, index),
                    }
                }
                if !terminated {
                    // The cursor is inside a string argument. Delimiters before
                    // it remain valid, while punctuation in the string is not.
                    break;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < byte_offset && !matches!(bytes[index], b'\n' | b'\r') {
                    index = advance_utf8_character(source, index);
                }
                if index == byte_offset {
                    return None;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut terminated = false;
                while index < byte_offset {
                    if bytes[index] == b'*'
                        && bytes.get(index + 1) == Some(&b'/')
                        && index + 1 < byte_offset
                    {
                        index += 2;
                        terminated = true;
                        break;
                    }
                    index = advance_utf8_character(source, index);
                }
                if !terminated {
                    return None;
                }
            }
            b'(' => {
                if delimiters.len() == MAX_SIGNATURE_HELP_DELIMITER_DEPTH {
                    return None;
                }
                delimiters.push(SignatureHelpDelimiter {
                    kind: SignatureHelpDelimiterKind::Round,
                    opening_byte: index,
                    argument_count: 0,
                });
                index += 1;
            }
            b'[' => {
                if delimiters.len() == MAX_SIGNATURE_HELP_DELIMITER_DEPTH {
                    return None;
                }
                delimiters.push(SignatureHelpDelimiter {
                    kind: SignatureHelpDelimiterKind::Square,
                    opening_byte: index,
                    argument_count: 0,
                });
                index += 1;
            }
            b'{' => {
                if delimiters.len() == MAX_SIGNATURE_HELP_DELIMITER_DEPTH {
                    return None;
                }
                delimiters.push(SignatureHelpDelimiter {
                    kind: SignatureHelpDelimiterKind::Curly,
                    opening_byte: index,
                    argument_count: 0,
                });
                index += 1;
            }
            b')' => {
                let delimiter = delimiters.pop()?;
                if delimiter.kind != SignatureHelpDelimiterKind::Round {
                    return None;
                }
                index += 1;
            }
            b']' => {
                let delimiter = delimiters.pop()?;
                if delimiter.kind != SignatureHelpDelimiterKind::Square {
                    return None;
                }
                index += 1;
            }
            b'}' => {
                let delimiter = delimiters.pop()?;
                if delimiter.kind != SignatureHelpDelimiterKind::Curly {
                    return None;
                }
                index += 1;
            }
            b',' => {
                let delimiter = delimiters.last_mut()?;
                if delimiter.kind == SignatureHelpDelimiterKind::Round {
                    delimiter.argument_count = delimiter.argument_count.checked_add(1)?;
                    if delimiter.argument_count >= MAX_SIGNATURE_HELP_ARGUMENTS {
                        return None;
                    }
                }
                index += 1;
            }
            _ => index = advance_utf8_character(source, index),
        }
    }
    Some(delimiters)
}

/// Recognizes only a root or direct object-child source key in the first direct
/// literal-record argument to a member call. The catalog and visible-import
/// checks happen later; this recognizer deliberately does not resolve a
/// module, evaluate a value, or interpret JSON Schema.
fn direct_module_input_record_completion_site(
    source: &str,
    byte_offset: usize,
) -> Option<DirectModuleInputRecordCompletionSite> {
    let context = signature_help_call_context(source, byte_offset)?;
    if context.active_argument != 0 {
        return None;
    }
    let record_opening =
        skip_ascii_whitespace_forward(source, context.opening_byte.checked_add(1)?);
    if source.as_bytes().get(record_opening) != Some(&b'{') {
        return None;
    }
    let (field, parent_field, declared_fields) =
        direct_record_input_field_site(source, record_opening, byte_offset)?;
    Some(DirectModuleInputRecordCompletionSite {
        context,
        field,
        parent_field,
        declared_fields,
    })
}

/// Scans the source prefix of one direct record without retaining values. At
/// most one direct object child can become a completion target; a malformed
/// key/value separator, duplicate key, deeper nested key position,
/// unterminated string/comment, or oversized key fails closed.
fn direct_record_input_field_site(
    source: &str,
    record_opening: usize,
    byte_offset: usize,
) -> Option<(SourceSpan, Option<String>, HashSet<String>)> {
    if record_opening.checked_add(1)? > byte_offset
        || byte_offset > source.len()
        || !source.is_char_boundary(byte_offset)
    {
        return None;
    }

    let bytes = source.as_bytes();
    let mut index = record_opening + 1;
    let mut delimiters = Vec::<DirectRecordDelimiterKind>::new();
    let mut scopes = vec![DirectRecordInputScope {
        parent_field: None,
        declared_fields: HashSet::new(),
        state: DirectRecordFieldState::Field,
    }];

    while index < byte_offset {
        let byte = bytes[index];
        if is_identifier_start_byte(byte) {
            let scope = scopes.last_mut()?;
            if scope.state != DirectRecordFieldState::Field {
                if let DirectRecordFieldState::Value { started, .. } = &mut scope.state {
                    *started = true;
                }
                index = advance_utf8_character(source, index);
                continue;
            }
            let start_byte = index;
            while index < byte_offset && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            let name = source.get(start_byte..index)?;
            if name.len() > MAX_LSP_MODULE_RECORD_FIELD_NAME_BYTES || !is_canonical_identifier(name)
            {
                return None;
            }
            scope.state = DirectRecordFieldState::AfterField { start_byte };
            continue;
        }

        match byte {
            b' ' | b'\t' => index += 1,
            b'\n' | b'\r' => {
                if delimiters.is_empty()
                    && matches!(&scopes.last()?.state, DirectRecordFieldState::Value { .. })
                {
                    scopes.last_mut()?.state = DirectRecordFieldState::Field;
                }
                index += 1;
                if byte == b'\r' && index < byte_offset && bytes[index] == b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < byte_offset && !matches!(bytes[index], b'\n' | b'\r') {
                    index = advance_utf8_character(source, index);
                }
                if index == byte_offset {
                    return None;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut contains_line_break = false;
                let mut terminated = false;
                while index < byte_offset {
                    if bytes[index] == b'*'
                        && bytes.get(index + 1) == Some(&b'/')
                        && index + 1 < byte_offset
                    {
                        index += 2;
                        terminated = true;
                        break;
                    }
                    contains_line_break |= matches!(bytes[index], b'\n' | b'\r');
                    index = advance_utf8_character(source, index);
                }
                if !terminated {
                    return None;
                }
                if contains_line_break
                    && delimiters.is_empty()
                    && matches!(&scopes.last()?.state, DirectRecordFieldState::Value { .. })
                {
                    scopes.last_mut()?.state = DirectRecordFieldState::Field;
                }
            }
            b'"' => {
                let scope = scopes.last_mut()?;
                let DirectRecordFieldState::Value { started, .. } = &mut scope.state else {
                    return None;
                };
                *started = true;
                index += 1;
                let mut terminated = false;
                while index < byte_offset {
                    match bytes[index] {
                        b'"' => {
                            index += 1;
                            terminated = true;
                            break;
                        }
                        b'\\' => {
                            index = advance_utf8_character(source, index);
                            if index < byte_offset {
                                index = advance_utf8_character(source, index);
                            }
                        }
                        b'\n' | b'\r' => return None,
                        _ => index = advance_utf8_character(source, index),
                    }
                }
                if !terminated {
                    return None;
                }
            }
            b':' => match scopes.last()?.state.clone() {
                DirectRecordFieldState::AfterField { start_byte } => {
                    let name = source.get(start_byte..index)?;
                    let scope = scopes.last_mut()?;
                    if scope.declared_fields.len() == MAX_LSP_MODULE_RECORD_FIELDS
                        || !scope.declared_fields.insert(name.to_owned())
                    {
                        return None;
                    }
                    scope.state = DirectRecordFieldState::Value {
                        field_name: name.to_owned(),
                        started: false,
                    };
                    index += 1;
                }
                DirectRecordFieldState::Value { .. } => {
                    if let DirectRecordFieldState::Value { started, .. } =
                        &mut scopes.last_mut()?.state
                    {
                        *started = true;
                    }
                    index += 1;
                }
                DirectRecordFieldState::Field => return None,
            },
            b',' => {
                if delimiters.is_empty() {
                    match &scopes.last()?.state {
                        DirectRecordFieldState::Field => {}
                        DirectRecordFieldState::AfterField { .. } => return None,
                        DirectRecordFieldState::Value { .. } => {
                            scopes.last_mut()?.state = DirectRecordFieldState::Field;
                        }
                    }
                }
                index += 1;
            }
            b'{' => {
                let direct_child_parent = match scopes.last()?.state.clone() {
                    DirectRecordFieldState::Value {
                        field_name,
                        started: false,
                    } if scopes.len().saturating_sub(1)
                        < MAX_LSP_MODULE_INPUT_FIELD_CHILD_DEPTH =>
                    {
                        Some(field_name)
                    }
                    _ => None,
                };
                if let Some(parent_field) = direct_child_parent {
                    if let DirectRecordFieldState::Value { started, .. } =
                        &mut scopes.last_mut()?.state
                    {
                        *started = true;
                    }
                    scopes.push(DirectRecordInputScope {
                        parent_field: Some(parent_field),
                        declared_fields: HashSet::new(),
                        state: DirectRecordFieldState::Field,
                    });
                    index += 1;
                    continue;
                }
                let scope = scopes.last_mut()?;
                let DirectRecordFieldState::Value { started, .. } = &mut scope.state else {
                    return None;
                };
                if delimiters.len() == MAX_SIGNATURE_HELP_DELIMITER_DEPTH {
                    return None;
                }
                *started = true;
                delimiters.push(DirectRecordDelimiterKind::Curly);
                index += 1;
            }
            b'(' | b'[' => {
                let scope = scopes.last_mut()?;
                let DirectRecordFieldState::Value { started, .. } = &mut scope.state else {
                    return None;
                };
                if delimiters.len() == MAX_SIGNATURE_HELP_DELIMITER_DEPTH {
                    return None;
                }
                *started = true;
                delimiters.push(match byte {
                    b'(' => DirectRecordDelimiterKind::Round,
                    b'[' => DirectRecordDelimiterKind::Square,
                    _ => unreachable!("matched opening delimiter"),
                });
                index += 1;
            }
            b')' | b']' => {
                let expected = match byte {
                    b')' => DirectRecordDelimiterKind::Round,
                    b']' => DirectRecordDelimiterKind::Square,
                    _ => unreachable!("matched closing delimiter"),
                };
                if delimiters.pop()? != expected {
                    return None;
                }
                if let DirectRecordFieldState::Value { started, .. } = &mut scopes.last_mut()?.state
                {
                    *started = true;
                }
                index += 1;
            }
            b'}' => match delimiters.last().copied() {
                Some(DirectRecordDelimiterKind::Curly) => {
                    delimiters.pop();
                    if let DirectRecordFieldState::Value { started, .. } =
                        &mut scopes.last_mut()?.state
                    {
                        *started = true;
                    }
                    index += 1;
                }
                Some(_) => return None,
                None => {
                    if scopes.len() == 1
                        || matches!(
                            &scopes.last()?.state,
                            DirectRecordFieldState::AfterField { .. }
                        )
                    {
                        return None;
                    }
                    scopes.pop();
                    index += 1;
                }
            },
            _ => {
                let scope = scopes.last_mut()?;
                let DirectRecordFieldState::Value { started, .. } = &mut scope.state else {
                    return None;
                };
                *started = true;
                index = advance_utf8_character(source, index);
            }
        }
    }

    let field = direct_record_input_field_span_at(source, byte_offset)?;
    let scope = scopes.last()?;
    match &scope.state {
        DirectRecordFieldState::Field => Some((
            field,
            scope.parent_field.clone(),
            scope.declared_fields.clone(),
        )),
        DirectRecordFieldState::AfterField { start_byte } if field.start_byte == *start_byte => {
            Some((
                field,
                scope.parent_field.clone(),
                scope.declared_fields.clone(),
            ))
        }
        DirectRecordFieldState::AfterField { .. } | DirectRecordFieldState::Value { .. } => None,
    }
}

fn direct_record_input_field_span_at(source: &str, byte_offset: usize) -> Option<SourceSpan> {
    if byte_offset > source.len() || !source.is_char_boundary(byte_offset) {
        return None;
    }
    let bytes = source.as_bytes();
    let mut start_byte = byte_offset;
    while start_byte > 0 && is_identifier_byte(bytes[start_byte - 1]) {
        start_byte -= 1;
    }
    let mut end_byte = byte_offset;
    while end_byte < bytes.len() && is_identifier_byte(bytes[end_byte]) {
        end_byte += 1;
    }
    if start_byte == end_byte {
        let next = bytes.get(byte_offset).copied();
        if next.is_some_and(|byte| !byte.is_ascii_whitespace() && byte != b'}') {
            return None;
        }
        return Some(SourceSpan {
            start_byte,
            end_byte,
        });
    }
    let name = source.get(start_byte..end_byte)?;
    (name.len() <= MAX_LSP_MODULE_RECORD_FIELD_NAME_BYTES && is_canonical_identifier(name))
        .then_some(SourceSpan {
            start_byte,
            end_byte,
        })
}

/// Recognizes one direct, statement-position `use mod.<path>` segment.
///
/// This is deliberately lexical and only accepts a `use` following the start
/// of source, a statement separator, or a block boundary. It does not resolve
/// source files or module paths; its sole purpose is to replace the current
/// path segment with bounded advisory metadata while an import is being typed.
fn direct_import_path_completion_site(
    source: &str,
    byte_offset: usize,
) -> Option<ImportPathCompletionSite> {
    if byte_offset > source.len()
        || !source.is_char_boundary(byte_offset)
        || string_content_span_at(source, byte_offset).is_some()
        || cursor_is_inside_comment(source, byte_offset)
    {
        return None;
    }

    let bytes = source.as_bytes();
    let mut segment_start = byte_offset;
    while segment_start > 0 && is_identifier_byte(bytes[segment_start - 1]) {
        segment_start -= 1;
    }
    let mut segment_end = byte_offset;
    while segment_end < bytes.len() && is_identifier_byte(bytes[segment_end]) {
        segment_end += 1;
    }
    if segment_start < segment_end && !is_identifier_start_byte(bytes[segment_start]) {
        return None;
    }

    let mut before_segment = skip_ascii_whitespace_backward(source, segment_start);
    let mut reversed_prefix = Vec::new();
    let module_start;
    loop {
        if before_segment == 0 || bytes[before_segment - 1] != b'.' {
            return None;
        }
        let before_dot = skip_ascii_whitespace_backward(source, before_segment - 1);
        let previous_start = identifier_start_before(source, before_dot);
        if previous_start == before_dot || !is_identifier_start_byte(bytes[previous_start]) {
            return None;
        }
        let previous = source.get(previous_start..before_dot)?;
        if !is_canonical_identifier(previous) {
            return None;
        }
        reversed_prefix.push(previous.to_owned());
        before_segment = skip_ascii_whitespace_backward(source, previous_start);
        if previous == "mod" {
            module_start = previous_start;
            break;
        }
    }
    reversed_prefix.reverse();
    if reversed_prefix
        .first()
        .is_none_or(|segment| segment != "mod")
    {
        return None;
    }

    let use_end = before_segment;
    let use_start = identifier_start_before(source, use_end);
    if source.get(use_start..use_end)? != "use"
        || module_start <= use_end
        || !source[use_end..module_start]
            .bytes()
            .all(|byte| byte.is_ascii_whitespace())
        || !is_import_statement_start(source, use_start)
    {
        return None;
    }

    Some(ImportPathCompletionSite {
        prefix: reversed_prefix,
        segment: SourceSpan {
            start_byte: segment_start,
            end_byte: segment_end,
        },
    })
}

fn is_import_statement_start(source: &str, use_start: usize) -> bool {
    let mut cursor = use_start;
    while cursor > 0 && source.as_bytes()[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
        if matches!(source.as_bytes()[cursor], b'\n' | b'\r') {
            return true;
        }
    }
    cursor == 0 || matches!(source.as_bytes()[cursor - 1], b';' | b'{')
}

/// Recognizes the first literal argument to one direct `mod.tool` call.
///
/// This is intentionally a small lexical recognizer rather than a general
/// expression parser. It accepts only `tool.call("...")`,
/// `tool.start("...")`, and their JSON variants, with ordinary whitespace
/// before the opening parenthesis or literal. The caller still proves that the
/// receiver is the visible `use mod.tool` binding before exposing metadata.
fn direct_tool_name_completion_site(
    source: &str,
    byte_offset: usize,
) -> Option<ToolNameCompletionSite> {
    let name = string_content_span_at(source, byte_offset)?;
    let opening_quote = name.start_byte.checked_sub(1)?;
    let open_paren_end = skip_ascii_whitespace_backward(source, opening_quote);
    if open_paren_end == 0 || source.as_bytes()[open_paren_end - 1] != b'(' {
        return None;
    }

    let method_end = skip_ascii_whitespace_backward(source, open_paren_end - 1);
    let method_start = identifier_start_before(source, method_end);
    if method_start == method_end
        || method_start == 0
        || source.as_bytes()[method_start - 1] != b'.'
    {
        return None;
    }
    let call_format = match source.get(method_start..method_end)? {
        "call" | "start" => ToolCallFormat::Text,
        "call_json" | "start_json" => ToolCallFormat::Json,
        _ => return None,
    };

    let receiver_end = method_start - 1;
    let receiver_start = identifier_start_before(source, receiver_end);
    if receiver_start == receiver_end
        || !is_identifier_start_byte(source.as_bytes()[receiver_start])
        || (receiver_start > 0 && source.as_bytes()[receiver_start - 1] == b'.')
    {
        return None;
    }
    let receiver_name = source.get(receiver_start..receiver_end)?;
    if !is_canonical_identifier(receiver_name) {
        return None;
    }

    Some(ToolNameCompletionSite {
        receiver: SourceSpan {
            start_byte: receiver_start,
            end_byte: receiver_end,
        },
        name,
        call_format,
    })
}

/// Returns the raw contents of the string literal under a cursor. An
/// unterminated current-line string remains eligible through end-of-file so an
/// editor can complete while the user is typing. Comments and strings after an
/// unterminated block comment are never scanned as code.
fn string_content_span_at(source: &str, byte_offset: usize) -> Option<SourceSpan> {
    if byte_offset > source.len() || !source.is_char_boundary(byte_offset) {
        return None;
    }

    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                    index = advance_utf8_character(source, index);
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index < bytes.len()
                    && !(bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/'))
                {
                    index = advance_utf8_character(source, index);
                }
                if index == bytes.len() {
                    return None;
                }
                index += 2;
            }
            b'"' => {
                let start_byte = index + 1;
                index = start_byte;
                let mut terminated = false;
                while index < bytes.len() {
                    match bytes[index] {
                        b'"' => {
                            terminated = true;
                            break;
                        }
                        b'\\' => {
                            index = advance_utf8_character(source, index);
                            if index < bytes.len() {
                                index = advance_utf8_character(source, index);
                            }
                        }
                        b'\n' | b'\r' => break,
                        _ => index = advance_utf8_character(source, index),
                    }
                }
                let end_byte = index;
                let cursor_in_string = start_byte <= byte_offset
                    && if terminated {
                        byte_offset <= end_byte
                    } else {
                        byte_offset < end_byte || end_byte == source.len()
                    };
                if cursor_in_string {
                    return Some(SourceSpan {
                        start_byte,
                        end_byte,
                    });
                }
                if terminated {
                    index += 1;
                }
            }
            _ => index = advance_utf8_character(source, index),
        }
    }
    None
}

fn cursor_is_inside_comment(source: &str, byte_offset: usize) -> bool {
    if byte_offset > source.len() || !source.is_char_boundary(byte_offset) {
        return false;
    }

    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => index = skip_string_literal(source, index),
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                let start_byte = index;
                index += 2;
                while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                    index = advance_utf8_character(source, index);
                }
                if start_byte <= byte_offset && byte_offset <= index {
                    return true;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let start_byte = index;
                index += 2;
                while index < bytes.len()
                    && !(bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/'))
                {
                    index = advance_utf8_character(source, index);
                }
                if index < bytes.len() {
                    index += 2;
                }
                if start_byte <= byte_offset && byte_offset <= index {
                    return true;
                }
            }
            _ => index = advance_utf8_character(source, index),
        }
    }
    false
}

fn skip_string_literal(source: &str, mut index: usize) -> usize {
    let bytes = source.as_bytes();
    index += 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return index + 1,
            b'\\' => {
                index = advance_utf8_character(source, index);
                if index < bytes.len() {
                    index = advance_utf8_character(source, index);
                }
            }
            b'\n' | b'\r' => return index,
            _ => index = advance_utf8_character(source, index),
        }
    }
    index
}

fn advance_utf8_character(source: &str, index: usize) -> usize {
    source[index..]
        .chars()
        .next()
        .map_or(source.len(), |character| index + character.len_utf8())
}

fn skip_ascii_whitespace_backward(source: &str, mut end_byte: usize) -> usize {
    while end_byte > 0 && source.as_bytes()[end_byte - 1].is_ascii_whitespace() {
        end_byte -= 1;
    }
    end_byte
}

fn skip_ascii_whitespace_forward(source: &str, mut start_byte: usize) -> usize {
    while start_byte < source.len() && source.as_bytes()[start_byte].is_ascii_whitespace() {
        start_byte += 1;
    }
    start_byte
}

fn identifier_start_before(source: &str, mut end_byte: usize) -> usize {
    while end_byte > 0 && is_identifier_byte(source.as_bytes()[end_byte - 1]) {
        end_byte -= 1;
    }
    end_byte
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_identifier_start_byte(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn tool_module_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > imports.valid_prefix_end_byte
    {
        return empty();
    }
    if !is_visible_builtin_tool_receiver(source, lexical, imports, site.receiver) {
        return empty();
    }

    let edit_range = span_range(source, site.member);
    let items = ["call", "call_json", "start", "start_json"]
        .into_iter()
        .map(|method| CompletionItem {
            label: method.to_owned(),
            kind: Some(CompletionItemKind::METHOD),
            detail: Some("mod.tool method; host capability required".to_owned()),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                method.to_owned(),
            ))),
            ..CompletionItem::default()
        })
        .collect();

    CompletionList {
        is_incomplete,
        items,
    }
}

/// Completes only the fixed, documented core math module. This does not use
/// module-catalog metadata, so a completion is neither a module lookup nor an
/// indication that a host capability exists.
fn standard_math_module_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if !site.has_direct_receiver()
        || site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > imports.valid_prefix_end_byte
        || !is_visible_builtin_standard_math_receiver(source, lexical, imports, site.receiver)
    {
        return empty();
    }

    let edit_range = span_range(source, site.member);
    let mut items =
        Vec::with_capacity(STANDARD_MATH_FUNCTIONS.len() + STANDARD_MATH_CONSTANTS.len());
    for function in STANDARD_MATH_FUNCTIONS {
        items.push(CompletionItem {
            label: function.name.to_owned(),
            kind: Some(CompletionItemKind::FUNCTION),
            detail: Some("mod.std.math function; effect-free scalar helper".to_owned()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: standard_math_function_documentation(function, "math"),
            })),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                function.name.to_owned(),
            ))),
            ..CompletionItem::default()
        });
    }
    for constant in STANDARD_MATH_CONSTANTS {
        items.push(CompletionItem {
            label: constant.name.to_owned(),
            kind: Some(CompletionItemKind::CONSTANT),
            detail: Some("mod.std.math constant; effect-free scalar value".to_owned()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: standard_math_constant_documentation(constant, "math"),
            })),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                constant.name.to_owned(),
            ))),
            ..CompletionItem::default()
        });
    }
    items.sort_by(|left, right| left.label.cmp(&right.label));

    CompletionList {
        is_incomplete,
        items,
    }
}

/// Completes only the fixed, documented core JSON module. It reuses no host
/// module-catalog metadata, so these descriptions cannot imply JSON adapter
/// availability or any capability authority.
fn standard_json_module_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if !site.has_direct_receiver()
        || site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > imports.valid_prefix_end_byte
        || !is_visible_builtin_standard_json_receiver(source, lexical, imports, site.receiver)
    {
        return empty();
    }

    let edit_range = span_range(source, site.member);
    let mut items = STANDARD_JSON_FUNCTIONS
        .iter()
        .map(|function| CompletionItem {
            label: function.name.to_owned(),
            kind: Some(CompletionItemKind::FUNCTION),
            detail: Some("mod.std.json function; bounded core data helper".to_owned()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: standard_json_function_documentation(function, "json"),
            })),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                function.name.to_owned(),
            ))),
            ..CompletionItem::default()
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.label.cmp(&right.label));

    CompletionList {
        is_incomplete,
        items,
    }
}

/// Completes only the fixed, documented core array module. This does not use
/// advisory catalog metadata, so its local data helpers cannot imply host
/// adapter availability or capability authority.
fn standard_array_module_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if !site.has_direct_receiver()
        || site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > imports.valid_prefix_end_byte
        || !is_visible_builtin_standard_array_receiver(source, lexical, imports, site.receiver)
    {
        return empty();
    }

    let edit_range = span_range(source, site.member);
    let mut items = STANDARD_ARRAY_FUNCTIONS
        .iter()
        .map(|function| CompletionItem {
            label: function.name.to_owned(),
            kind: Some(CompletionItemKind::FUNCTION),
            detail: Some("mod.std.array function; bounded core array helper".to_owned()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: standard_array_function_documentation(function, "array"),
            })),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                function.name.to_owned(),
            ))),
            ..CompletionItem::default()
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.label.cmp(&right.label));

    CompletionList {
        is_incomplete,
        items,
    }
}

/// Completes only the fixed, documented core object module. This does not use
/// advisory catalog metadata, so its local data helpers cannot imply host
/// adapter availability or capability authority.
fn standard_object_module_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if !site.has_direct_receiver()
        || site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > imports.valid_prefix_end_byte
        || !is_visible_builtin_standard_object_receiver(source, lexical, imports, site.receiver)
    {
        return empty();
    }

    let edit_range = span_range(source, site.member);
    let mut items = STANDARD_OBJECT_FUNCTIONS
        .iter()
        .map(|function| CompletionItem {
            label: function.name.to_owned(),
            kind: Some(CompletionItemKind::FUNCTION),
            detail: Some("mod.std.object function; bounded core object helper".to_owned()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: standard_object_function_documentation(function, "object"),
            })),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                function.name.to_owned(),
            ))),
            ..CompletionItem::default()
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.label.cmp(&right.label));

    CompletionList {
        is_incomplete,
        items,
    }
}

/// Completes only the fixed, documented core text module. This does not use
/// advisory catalog metadata, so its local data helpers cannot imply host
/// adapter availability or capability authority.
fn standard_text_module_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if !site.has_direct_receiver()
        || site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > imports.valid_prefix_end_byte
        || !is_visible_builtin_standard_text_receiver(source, lexical, imports, site.receiver)
    {
        return empty();
    }

    let edit_range = span_range(source, site.member);
    let mut items = STANDARD_TEXT_FUNCTIONS
        .iter()
        .map(|function| CompletionItem {
            label: function.name.to_owned(),
            kind: Some(CompletionItemKind::FUNCTION),
            detail: Some("mod.std.text function; bounded core text helper".to_owned()),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: standard_text_function_documentation(function, "text"),
            })),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                function.name.to_owned(),
            ))),
            ..CompletionItem::default()
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.label.cmp(&right.label));

    CompletionList {
        is_incomplete,
        items,
    }
}

/// Completes only the direct, frozen `mod.std` tree. This is placed before
/// advisory output-field recognition so retained fixed imports remain useful
/// when a later oversized import list marks that advisory metadata incomplete.
fn fixed_core_module_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> Option<CompletionList> {
    let path = fixed_core_direct_import_path_for_member(source, lexical, imports, site)?;
    if !fixed_core_module_path_blocks_advisory_children(&path) {
        return None;
    }
    let edit_range = span_range(source, site.member);
    let mut items = fixed_core_module_path_children(&path)
        .unwrap_or_default()
        .iter()
        .map(|child| {
            fixed_core_module_completion_item(child, CompletionItemKind::FIELD, edit_range)
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.label.cmp(&right.label));
    Some(CompletionList {
        is_incomplete,
        items,
    })
}

fn standard_math_member_hover(source: &str, site: MemberCompletionSite) -> Option<Hover> {
    if !site.has_direct_receiver() {
        return None;
    }
    let member = source.get(site.member.start_byte..site.member.end_byte)?;
    let value = if let Some(function) = standard_math_function(member) {
        standard_math_function_documentation(function, "math")
    } else if let Some(constant) = standard_math_constant(member) {
        standard_math_constant_documentation(constant, "math")
    } else {
        return None;
    };
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::PlainText,
            value,
        }),
        range: Some(span_range(source, site.member)),
    })
}

fn standard_json_member_hover(source: &str, site: MemberCompletionSite) -> Option<Hover> {
    if !site.has_direct_receiver() {
        return None;
    }
    let member = source.get(site.member.start_byte..site.member.end_byte)?;
    let function = standard_json_function(member)?;
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::PlainText,
            value: standard_json_function_documentation(function, "json"),
        }),
        range: Some(span_range(source, site.member)),
    })
}

fn standard_array_member_hover(source: &str, site: MemberCompletionSite) -> Option<Hover> {
    if !site.has_direct_receiver() {
        return None;
    }
    let member = source.get(site.member.start_byte..site.member.end_byte)?;
    let function = standard_array_function(member)?;
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::PlainText,
            value: standard_array_function_documentation(function, "array"),
        }),
        range: Some(span_range(source, site.member)),
    })
}

fn standard_object_member_hover(source: &str, site: MemberCompletionSite) -> Option<Hover> {
    if !site.has_direct_receiver() {
        return None;
    }
    let member = source.get(site.member.start_byte..site.member.end_byte)?;
    let function = standard_object_function(member)?;
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::PlainText,
            value: standard_object_function_documentation(function, "object"),
        }),
        range: Some(span_range(source, site.member)),
    })
}

fn standard_text_member_hover(source: &str, site: MemberCompletionSite) -> Option<Hover> {
    if !site.has_direct_receiver() {
        return None;
    }
    let member = source.get(site.member.start_byte..site.member.end_byte)?;
    let function = standard_text_function(member)?;
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::PlainText,
            value: standard_text_function_documentation(function, "text"),
        }),
        range: Some(span_range(source, site.member)),
    })
}

fn standard_math_function(name: &str) -> Option<&'static StandardMathFunction> {
    STANDARD_MATH_FUNCTIONS
        .iter()
        .find(|function| function.name == name)
}

fn standard_math_constant(name: &str) -> Option<&'static StandardMathConstant> {
    STANDARD_MATH_CONSTANTS
        .iter()
        .find(|constant| constant.name == name)
}

fn standard_json_function(name: &str) -> Option<&'static StandardJsonFunction> {
    STANDARD_JSON_FUNCTIONS
        .iter()
        .find(|function| function.name == name)
}

fn standard_array_function(name: &str) -> Option<&'static StandardArrayFunction> {
    STANDARD_ARRAY_FUNCTIONS
        .iter()
        .find(|function| function.name == name)
}

fn standard_object_function(name: &str) -> Option<&'static StandardObjectFunction> {
    STANDARD_OBJECT_FUNCTIONS
        .iter()
        .find(|function| function.name == name)
}

fn standard_text_function(name: &str) -> Option<&'static StandardTextFunction> {
    STANDARD_TEXT_FUNCTIONS
        .iter()
        .find(|function| function.name == name)
}

fn standard_assert_documentation(callee: &str) -> String {
    format!(
        "{callee}(condition)\n\n{STANDARD_ASSERT_DESCRIPTION}\n\n{STANDARD_ASSERT_AUTHORITY_NOTE}"
    )
}

fn standard_math_function_documentation(function: &StandardMathFunction, receiver: &str) -> String {
    format!(
        "{receiver}.{}({}) -> number\n\n{}\n\n{STANDARD_MATH_AUTHORITY_NOTE}",
        function.name,
        function.parameters.join(", "),
        function.description,
    )
}

fn standard_math_constant_documentation(constant: &StandardMathConstant, receiver: &str) -> String {
    format!(
        "{receiver}.{} -> number\n\n{}\n\n{STANDARD_MATH_AUTHORITY_NOTE}",
        constant.name, constant.description,
    )
}

fn standard_json_function_documentation(function: &StandardJsonFunction, receiver: &str) -> String {
    format!(
        "{receiver}.{}({}) -> {}\n\n{}\n\n{STANDARD_JSON_AUTHORITY_NOTE}",
        function.name,
        function.parameters.join(", "),
        function.result,
        function.description,
    )
}

fn standard_array_function_documentation(
    function: &StandardArrayFunction,
    receiver: &str,
) -> String {
    format!(
        "{receiver}.{}({}) -> {}\n\n{}\n\n{STANDARD_ARRAY_AUTHORITY_NOTE}",
        function.name,
        function.parameters.join(", "),
        function.result,
        function.description,
    )
}

fn standard_object_function_documentation(
    function: &StandardObjectFunction,
    receiver: &str,
) -> String {
    format!(
        "{receiver}.{}({}) -> {}\n\n{}\n\n{STANDARD_OBJECT_AUTHORITY_NOTE}",
        function.name,
        function.parameters.join(", "),
        function.result,
        function.description,
    )
}

fn standard_text_function_documentation(function: &StandardTextFunction, receiver: &str) -> String {
    format!(
        "{receiver}.{}({}) -> {}\n\n{}\n\n{STANDARD_TEXT_AUTHORITY_NOTE}",
        function.name,
        function.parameters.join(", "),
        function.result,
        function.description,
    )
}

fn static_record_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    shapes: &StaticRecordShapeReport,
    fields: &[StaticRecordField],
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let is_incomplete = is_incomplete || shapes.truncated || shapes.aliases_truncated;
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if shapes.aliases_truncated {
        return empty();
    }
    if site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > shapes.valid_prefix_end_byte
    {
        return empty();
    }

    let edit_range = span_range(source, site.member);
    let mut items = fields
        .iter()
        .map(|field| CompletionItem {
            label: field.name.clone(),
            kind: Some(CompletionItemKind::FIELD),
            detail: Some("static record field; direct literal, child literal, or alias".to_owned()),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                field.name.clone(),
            ))),
            ..CompletionItem::default()
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.label.cmp(&right.label));

    CompletionList {
        is_incomplete,
        items,
    }
}

/// Completes compact host-projected fields only at one exact root or direct
/// object-child input key in a direct visible module call. The source scanner
/// provides no value semantics, and this function only looks up advisory
/// catalog metadata after the existing visible-import-or-alias checks succeed.
fn module_catalog_input_field_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    shapes: &StaticRecordShapeReport,
    catalog: &ModuleCompletionCatalog,
    site: DirectModuleInputRecordCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let is_incomplete = is_incomplete
        || catalog.unavailable
        || module_catalog_alias_metadata_is_truncated_at_receiver(
            source,
            lexical,
            shapes,
            site.context.callee.receiver,
        );
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    let Some(fields) =
        module_catalog_input_fields_for_site(source, lexical, imports, shapes, catalog, &site)
    else {
        return empty();
    };

    let edit_range = span_range(source, site.field);
    let items = fields
        .iter()
        .filter(|field| !site.declared_fields.contains(&field.name))
        .map(|field| CompletionItem {
            label: field.name.clone(),
            kind: Some(CompletionItemKind::FIELD),
            detail: Some(
                if field.required {
                    "advisory direct-module input field; required"
                } else {
                    "advisory direct-module input field; optional"
                }
                .to_owned(),
            ),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: module_catalog_input_field_text(field),
            })),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                field.name.clone(),
            ))),
            ..CompletionItem::default()
        })
        .collect();

    CompletionList {
        is_incomplete,
        items,
    }
}

fn module_catalog_input_field_text(field: &ModuleCatalogRecordFieldCompletion) -> String {
    let mut value = format!(
        "Advisory direct-module input field `{}`.\nType: {}\nRequired: {}",
        field.name,
        field.field_type.label(),
        if field.required { "yes" } else { "no" }
    );
    if !field.description.is_empty() {
        value.push_str("\n\n");
        value.push_str(&field.description);
    }
    value.push_str(
        "\n\nAdvisory metadata only; host module binding and any required capability authorization remain host-owned.",
    );
    value
}

/// Finds the retained input-field list at one exact direct literal-record
/// source site. Both completion and hover use this narrow advisory lookup so
/// neither can resolve modules, interpret a schema, or diverge on alias and
/// safe-prefix checks.
fn module_catalog_input_fields_for_site<'catalog>(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    shapes: &StaticRecordShapeReport,
    catalog: &'catalog ModuleCompletionCatalog,
    site: &DirectModuleInputRecordCompletionSite,
) -> Option<&'catalog [ModuleCatalogRecordFieldCompletion]> {
    if imports.truncated
        || catalog.unavailable
        || site.context.callee.member.end_byte > lexical.valid_prefix_end_byte
        || site.field.end_byte > lexical.valid_prefix_end_byte
        || site.context.callee.member.end_byte > imports.valid_prefix_end_byte
    {
        return None;
    }
    let module = module_catalog_direct_member(
        source,
        lexical,
        imports,
        shapes,
        catalog,
        site.context.callee,
    )?;
    if module.call_mode.is_none() || module.call_shape != Some(ModuleCatalogCallShape::SingleJson) {
        return None;
    }
    let root_fields = module.input_fields.as_deref()?;
    module_catalog_input_fields_at_parent(root_fields, site.parent_field.as_deref())
}

/// Finds the one exact host-projected input field named by a complete source
/// key. A duplicate prior source key is deliberately not hoverable: no
/// advisory type should appear for a malformed retained record prefix.
fn module_catalog_input_field_for_site<'catalog>(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    shapes: &StaticRecordShapeReport,
    catalog: &'catalog ModuleCompletionCatalog,
    site: &DirectModuleInputRecordCompletionSite,
) -> Option<&'catalog ModuleCatalogRecordFieldCompletion> {
    if lexical.symbols_truncated || lexical.sites_truncated {
        return None;
    }
    let field_name = source.get(site.field.start_byte..site.field.end_byte)?;
    if !is_canonical_identifier(field_name) || site.declared_fields.contains(field_name) {
        return None;
    }
    module_catalog_input_fields_for_site(source, lexical, imports, shapes, catalog, site)?
        .iter()
        .find(|field| field.name == field_name)
}

fn module_catalog_input_fields_at_parent<'catalog>(
    fields: &'catalog [ModuleCatalogRecordFieldCompletion],
    parent_field: Option<&str>,
) -> Option<&'catalog [ModuleCatalogRecordFieldCompletion]> {
    let Some(parent_field) = parent_field else {
        return Some(fields);
    };
    fields
        .iter()
        .find(|field| field.name == parent_field)?
        .fields
        .as_deref()
}

/// Completes host-projected output fields on one exact direct-module result
/// binding or its bounded exact local alias chain. This remains narrower than
/// record shape support: only one direct object-child path is recognized, and
/// mutations and escapes still refuse the advisory output view.
fn module_catalog_output_field_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    catalog: &ModuleCompletionCatalog,
    shapes: &StaticRecordShapeReport,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> Option<CompletionList> {
    let aliases_truncated = module_catalog_alias_metadata_is_truncated_at_receiver(
        source,
        lexical,
        shapes,
        site.receiver,
    );
    let is_incomplete =
        is_incomplete || imports.truncated || catalog.unavailable || aliases_truncated;
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if imports.truncated || catalog.unavailable || aliases_truncated {
        return Some(empty());
    }
    let parent_path = direct_module_output_member_parent_path(source, site)?;
    let output_binding = direct_module_output_binding_for_member(source, lexical, shapes, site)?;
    let Some(root_fields) = module_catalog_output_fields_for_binding(
        source,
        lexical,
        imports,
        shapes,
        catalog,
        output_binding,
    ) else {
        return Some(empty());
    };
    let Some(fields) = module_catalog_output_fields_at_path(root_fields, &parent_path) else {
        return Some(empty());
    };
    let edit_range = span_range(source, site.member);
    let mut items = fields
        .iter()
        .map(|field| CompletionItem {
            label: field.name.clone(),
            kind: Some(CompletionItemKind::FIELD),
            detail: Some(
                if field.required {
                    "advisory direct-module output field; required"
                } else {
                    "advisory direct-module output field; optional"
                }
                .to_owned(),
            ),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: module_catalog_output_field_text(field),
            })),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                field.name.clone(),
            ))),
            ..CompletionItem::default()
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| left.label.cmp(&right.label));

    Some(CompletionList {
        is_incomplete,
        items,
    })
}

fn module_catalog_output_field_text(field: &ModuleCatalogOutputFieldCompletion) -> String {
    let mut value = format!(
        "Advisory direct-module output field `{}`.\nType: {}\nRequired: {}",
        field.name,
        field.field_type.label(),
        if field.required { "yes" } else { "no" }
    );
    if !field.description.is_empty() {
        value.push_str("\n\n");
        value.push_str(&field.description);
    }
    value.push_str(
        "\n\nAdvisory metadata only; it does not inspect a runtime result or grant a capability.",
    );
    value
}

/// Identifies a direct, unshadowed advisory workflow-data member path.
///
/// `workflow` is intentionally not a Splash binding. A host must supply a
/// catalog before completion recognizes this lexical root, and any visible
/// local or imported binding named `workflow` wins over the advisory view.
fn workflow_data_member_path<'source>(
    source: &'source str,
    symbols: &[LexicalSymbol],
    site: MemberCompletionSite,
) -> Option<Vec<&'source str>> {
    let receiver_name = source.get(site.receiver.start_byte..site.receiver.end_byte)?;
    if receiver_name != "workflow"
        || visible_symbol_in(symbols, "workflow", site.receiver.start_byte).is_some()
    {
        return None;
    }

    let receiver_chain =
        source.get(site.receiver_chain.start_byte..site.receiver_chain.end_byte)?;
    let path = receiver_chain.split('.').collect::<Vec<_>>();
    (path.first() == Some(&"workflow")
        && path.iter().all(|segment| is_canonical_identifier(segment)))
    .then_some(path)
}

fn workflow_data_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    catalog: &WorkflowDataCompletionCatalog,
    step_context: &WorkflowDataStepContext,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> Option<CompletionList> {
    if !catalog.configured {
        return None;
    }
    let path = workflow_data_member_path(source, &lexical.symbols, site)?;
    let is_incomplete = is_incomplete || catalog.unavailable || step_context.unavailable;
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if site.member.end_byte > lexical.valid_prefix_end_byte
        || catalog.unavailable
        || step_context.unavailable
    {
        return Some(empty());
    }

    let edit_range = span_range(source, site.member);
    let items = match path.as_slice() {
        ["workflow"] => ["input", "outputs"]
            .into_iter()
            .map(|name| CompletionItem {
                label: name.to_owned(),
                kind: Some(CompletionItemKind::FIELD),
                detail: Some("workflow data namespace; advisory host data contract".to_owned()),
                text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                    edit_range,
                    name.to_owned(),
                ))),
                ..CompletionItem::default()
            })
            .collect(),
        ["workflow", "input"] => workflow_data_field_completion_items(
            &catalog.input_fields,
            edit_range,
            "workflow input",
        ),
        ["workflow", "outputs"] => {
            let Some(outputs) = workflow_data_visible_outputs(catalog, step_context) else {
                return Some(empty());
            };
            let detail = if step_context.configured {
                "completed workflow output; advisory host data contract"
            } else {
                "workflow output; advisory host data contract"
            };
            let mut items = outputs
                .iter()
                .map(|output| CompletionItem {
                    label: output.step_id.clone(),
                    kind: Some(CompletionItemKind::FIELD),
                    detail: Some(detail.to_owned()),
                    text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                        edit_range,
                        output.step_id.clone(),
                    ))),
                    ..CompletionItem::default()
                })
                .collect::<Vec<_>>();
            items.sort_by(|left, right| left.label.cmp(&right.label));
            items
        }
        ["workflow", "outputs", step_id] => {
            let Some(output) = workflow_data_visible_outputs(catalog, step_context)
                .and_then(|outputs| outputs.iter().find(|output| output.step_id == *step_id))
            else {
                return Some(empty());
            };
            let context = if step_context.configured {
                "completed workflow output"
            } else {
                "workflow output"
            };
            workflow_data_field_completion_items(&output.fields, edit_range, context)
        }
        _ => return Some(empty()),
    };

    Some(CompletionList {
        is_incomplete,
        items,
    })
}

fn workflow_data_visible_outputs<'catalog>(
    catalog: &'catalog WorkflowDataCompletionCatalog,
    step_context: &WorkflowDataStepContext,
) -> Option<&'catalog [WorkflowDataOutputCompletion]> {
    if step_context.unavailable {
        return None;
    }
    let count = if step_context.configured {
        step_context.completed_output_count
    } else {
        catalog.outputs.len()
    };
    catalog.outputs.get(..count)
}

fn workflow_data_field_completion_items(
    fields: &[WorkflowDataFieldCompletion],
    edit_range: Range,
    context: &str,
) -> Vec<CompletionItem> {
    fields
        .iter()
        .map(|field| CompletionItem {
            label: field.name.clone(),
            kind: Some(CompletionItemKind::FIELD),
            detail: Some(format!("{context} field; advisory host data contract")),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: workflow_data_field_hover_text(field, context),
            })),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                field.name.clone(),
            ))),
            ..CompletionItem::default()
        })
        .collect()
}

fn workflow_data_field_for_member<'field>(
    source: &str,
    symbols: &[LexicalSymbol],
    valid_prefix_end_byte: usize,
    catalog: &'field WorkflowDataCompletionCatalog,
    step_context: &WorkflowDataStepContext,
    site: MemberCompletionSite,
) -> Option<(&'field WorkflowDataFieldCompletion, &'static str)> {
    if !catalog.configured
        || catalog.unavailable
        || step_context.unavailable
        || site.member.end_byte > valid_prefix_end_byte
    {
        return None;
    }
    let path = workflow_data_member_path(source, symbols, site)?;
    let member_name = source.get(site.member.start_byte..site.member.end_byte)?;
    match path.as_slice() {
        ["workflow", "input"] => catalog
            .input_fields
            .iter()
            .find(|field| field.name == member_name)
            .map(|field| (field, "workflow input")),
        ["workflow", "outputs", step_id] => workflow_data_visible_outputs(catalog, step_context)
            .and_then(|outputs| outputs.iter().find(|output| output.step_id == *step_id))
            .and_then(|output| output.fields.iter().find(|field| field.name == member_name))
            .map(|field| {
                let context = if step_context.configured {
                    "completed workflow output"
                } else {
                    "workflow output"
                };
                (field, context)
            }),
        _ => None,
    }
}

fn workflow_data_field_hover_text(field: &WorkflowDataFieldCompletion, context: &str) -> String {
    let mut text = format!(
        "{context} field {}\nType: {}",
        field.name,
        field.field_type.label()
    );
    if !field.description.is_empty() {
        text.push_str("\n\n");
        text.push_str(&field.description);
    }
    text.push_str("\n\nAdvisory host data contract; not runtime authority.");
    text
}

/// Returns compiled-in children for a prefix of the documented core import
/// tree. An empty child list marks a fixed leaf, which deliberately prevents
/// advisory catalog metadata from inventing descendants below that leaf.
fn fixed_core_module_path_children(
    prefix: &[String],
) -> Option<&'static [FixedCoreModulePathChild]> {
    if module_path_matches(prefix, &["mod"]) {
        Some(FIXED_ROOT_MODULE_PATH_CHILDREN)
    } else if module_path_matches(prefix, &["mod", "std"]) {
        Some(FIXED_STANDARD_MODULE_PATH_CHILDREN)
    } else if module_path_starts_with(prefix, &["mod", "std", "array"])
        || module_path_starts_with(prefix, &["mod", "std", "assert"])
        || module_path_starts_with(prefix, &["mod", "std", "json"])
        || module_path_starts_with(prefix, &["mod", "std", "math"])
        || module_path_starts_with(prefix, &["mod", "std", "object"])
        || module_path_starts_with(prefix, &["mod", "std", "text"])
    {
        Some(&[])
    } else {
        None
    }
}

fn fixed_core_module_path_child(
    parent: &[String],
    name: &str,
) -> Option<&'static FixedCoreModulePathChild> {
    fixed_core_module_path_children(parent)?
        .iter()
        .find(|child| child.name == name)
}

fn fixed_core_module_path_blocks_advisory_children(path: &[String]) -> bool {
    module_path_starts_with(path, &["mod", "std"])
}

fn fixed_core_module_completion_item(
    child: &FixedCoreModulePathChild,
    kind: CompletionItemKind,
    edit_range: Range,
) -> CompletionItem {
    CompletionItem {
        label: child.name.to_owned(),
        kind: Some(kind),
        detail: Some(child.detail.to_owned()),
        documentation: Some(Documentation::MarkupContent(MarkupContent {
            kind: MarkupKind::PlainText,
            value: child.documentation.to_owned(),
        })),
        text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
            edit_range,
            child.name.to_owned(),
        ))),
        ..CompletionItem::default()
    }
}

/// Returns `Some(None)` for an unknown member below a fixed core leaf so a
/// similarly named advisory descriptor cannot extend that leaf in hover.
fn fixed_core_module_member_hover(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
) -> Option<Option<Hover>> {
    let path = fixed_core_direct_import_path_for_member(source, lexical, imports, site)?;
    let member = source.get(site.member.start_byte..site.member.end_byte)?;
    if let Some(child) = fixed_core_module_path_child(&path, member) {
        return Some(Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: child.documentation.to_owned(),
            }),
            range: Some(span_range(source, site.member)),
        }));
    }
    fixed_core_module_path_blocks_advisory_children(&path).then_some(None)
}

fn module_path_matches(path: &[String], expected: &[&str]) -> bool {
    path.len() == expected.len()
        && path
            .iter()
            .map(String::as_str)
            .zip(expected.iter().copied())
            .all(|(actual, expected)| actual == expected)
}

fn module_path_starts_with(path: &[String], expected: &[&str]) -> bool {
    path.len() >= expected.len()
        && path
            .iter()
            .map(String::as_str)
            .zip(expected.iter().copied())
            .all(|(actual, expected)| actual == expected)
}

fn module_catalog_path_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    catalog: &ModuleCompletionCatalog,
    site: ImportPathCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let fixed_children = fixed_core_module_path_children(&site.prefix);
    let fixed_core_path = fixed_core_module_path_blocks_advisory_children(&site.prefix);
    let fixed_children = fixed_children.unwrap_or_default();
    let is_incomplete = is_incomplete || (!fixed_core_path && catalog.unavailable);
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if site.segment.end_byte > lexical.valid_prefix_end_byte {
        return empty();
    }

    let edit_range = span_range(source, site.segment);
    let mut items = fixed_children
        .iter()
        .map(|child| {
            fixed_core_module_completion_item(child, CompletionItemKind::MODULE, edit_range)
        })
        .collect::<Vec<_>>();
    if !fixed_core_path {
        items.extend(
            module_catalog_children(catalog, &site.prefix)
                .into_iter()
                .filter(|child| !fixed_children.iter().any(|fixed| fixed.name == child.name))
                .map(|child| CompletionItem {
                    label: child.name.clone(),
                    kind: Some(CompletionItemKind::MODULE),
                    detail: Some(module_catalog_path_detail(child.call_mode).to_owned()),
                    documentation: module_catalog_documentation(
                        child.description.as_deref(),
                        child.call_mode,
                    ),
                    text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                        edit_range, child.name,
                    ))),
                    ..CompletionItem::default()
                }),
        );
    }
    items.sort_by(|left, right| left.label.cmp(&right.label));

    CompletionList {
        is_incomplete,
        items,
    }
}

fn module_catalog_member_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    shapes: &StaticRecordShapeReport,
    catalog: &ModuleCompletionCatalog,
    site: MemberCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let is_incomplete = is_incomplete
        || module_catalog_alias_metadata_is_truncated_at_receiver(
            source,
            lexical,
            shapes,
            site.receiver,
        );
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    let fixed_path = fixed_core_direct_import_path_for_member(source, lexical, imports, site);
    let fixed_children = fixed_path
        .as_deref()
        .and_then(fixed_core_module_path_children);
    let fixed_core_path = fixed_path
        .as_deref()
        .is_some_and(fixed_core_module_path_blocks_advisory_children);
    let resolved_path = module_catalog_member_parent_path(source, lexical, imports, shapes, site)
        .or_else(|| fixed_core_path.then(|| fixed_path.clone()).flatten());
    let Some(resolved_path) = resolved_path else {
        return empty();
    };
    let fixed_children = fixed_children.unwrap_or_default();
    let is_incomplete = is_incomplete || (!fixed_core_path && catalog.unavailable);
    let edit_range = span_range(source, site.member);
    let mut items = fixed_children
        .iter()
        .map(|child| {
            fixed_core_module_completion_item(child, CompletionItemKind::FIELD, edit_range)
        })
        .collect::<Vec<_>>();
    if !fixed_core_path {
        items.extend(
            module_catalog_children(catalog, &resolved_path)
                .into_iter()
                .filter(|child| !fixed_children.iter().any(|fixed| fixed.name == child.name))
                .map(|child| CompletionItem {
                    label: child.name.clone(),
                    kind: Some(CompletionItemKind::FIELD),
                    detail: Some(module_catalog_member_detail(child.call_mode).to_owned()),
                    documentation: module_catalog_documentation(
                        child.description.as_deref(),
                        child.call_mode,
                    ),
                    text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                        edit_range, child.name,
                    ))),
                    ..CompletionItem::default()
                }),
        );
    }
    items.sort_by(|left, right| left.label.cmp(&right.label));

    CompletionList {
        is_incomplete,
        items,
    }
}

/// Resolves the catalog parent path for one member only when the receiver is
/// an exact visible import or a stable exact root alias. It never loads or
/// validates a module.
fn module_catalog_member_parent_path(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    shapes: &StaticRecordShapeReport,
    site: MemberCompletionSite,
) -> Option<Vec<String>> {
    if site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > imports.valid_prefix_end_byte
    {
        return None;
    }
    let import = visible_module_import_or_alias_for_catalog_receiver(
        source,
        lexical,
        imports,
        shapes,
        site.receiver,
    )?;
    let mut resolved_path = import.path.clone();
    if site.has_direct_receiver() {
        return Some(resolved_path);
    }
    let suffix = source
        .get(site.receiver.end_byte..site.receiver_chain.end_byte)?
        .strip_prefix('.')?;
    for segment in suffix.split('.') {
        if !is_canonical_identifier(segment) || resolved_path.len() == MAX_LSP_MODULE_PATH_SEGMENTS
        {
            return None;
        }
        resolved_path.push(segment.to_owned());
    }
    Some(resolved_path)
}

/// Resolves the direct source import path for a fixed core member projection.
/// Unlike advisory catalog completion, fixed core metadata does not follow
/// aliases: an alias could be reassigned or intentionally model another value.
fn fixed_core_direct_import_path_for_member(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
) -> Option<Vec<String>> {
    if site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > imports.valid_prefix_end_byte
    {
        return None;
    }
    let import = visible_module_import_for_receiver(source, lexical, imports, site.receiver)?;
    let mut path = import.path.clone();
    if site.has_direct_receiver() {
        return Some(path);
    }
    let suffix = source
        .get(site.receiver.end_byte..site.receiver_chain.end_byte)?
        .strip_prefix('.')?;
    for segment in suffix.split('.') {
        if !is_canonical_identifier(segment) || path.len() == MAX_LSP_MODULE_PATH_SEGMENTS {
            return None;
        }
        path.push(segment.to_owned());
    }
    Some(path)
}

/// Finds an exact advisory leaf only through the same visible import-or-alias
/// path used by member completion and signature help. It never resolves a
/// module or consults a capability runtime.
fn module_catalog_direct_member<'catalog>(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    shapes: &StaticRecordShapeReport,
    catalog: &'catalog ModuleCompletionCatalog,
    site: MemberCompletionSite,
) -> Option<&'catalog ModuleCatalogCompletion> {
    if catalog.unavailable {
        return None;
    }
    let method = source.get(site.member.start_byte..site.member.end_byte)?;
    if !is_canonical_identifier(method) {
        return None;
    }
    if let Some(path) = fixed_core_direct_import_path_for_member(source, lexical, imports, site) {
        if fixed_core_module_path_blocks_advisory_children(&path)
            || fixed_core_module_path_child(&path, method).is_some()
        {
            return None;
        }
    }
    let mut path = module_catalog_member_parent_path(source, lexical, imports, shapes, site)?;
    path.push(method.to_owned());
    catalog
        .modules
        .iter()
        .find(|module| module.path.as_slice() == path.as_slice())
}

/// Finds the compact output-field projection for one exact direct-module local
/// result binding or its bounded exact alias group. It relies on the same
/// visible-import-or-alias lookup as direct module completion and never resolves
/// general expressions.
fn module_catalog_output_fields_for_member<'catalog>(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    catalog: &'catalog ModuleCompletionCatalog,
    shapes: &StaticRecordShapeReport,
    site: MemberCompletionSite,
) -> Option<&'catalog [ModuleCatalogOutputFieldCompletion]> {
    let parent_path = direct_module_output_member_parent_path(source, site)?;
    let output_binding = direct_module_output_binding_for_member(source, lexical, shapes, site)?;
    let fields = module_catalog_output_fields_for_binding(
        source,
        lexical,
        imports,
        shapes,
        catalog,
        output_binding,
    )?;
    module_catalog_output_fields_at_path(fields, &parent_path)
}

/// Extracts the direct retained object-field path between a result binding and
/// the member being completed. The root result itself is represented by an
/// empty path; only one explicit object child is retained.
fn direct_module_output_member_parent_path(
    source: &str,
    site: MemberCompletionSite,
) -> Option<Vec<&str>> {
    let receiver = source.get(site.receiver.start_byte..site.receiver.end_byte)?;
    let receiver_chain =
        source.get(site.receiver_chain.start_byte..site.receiver_chain.end_byte)?;
    if receiver_chain == receiver {
        return Some(Vec::new());
    }
    let suffix = receiver_chain.strip_prefix(receiver)?.strip_prefix('.')?;
    let mut path = Vec::with_capacity(MAX_LSP_MODULE_OUTPUT_FIELD_CHILD_DEPTH);
    for segment in suffix.split('.') {
        if path.len() == MAX_LSP_MODULE_OUTPUT_FIELD_CHILD_DEPTH
            || !is_canonical_identifier(segment)
        {
            return None;
        }
        path.push(segment);
    }
    Some(path)
}

fn direct_module_output_binding_for_member(
    source: &str,
    lexical: &LexicalCompletionReport,
    shapes: &StaticRecordShapeReport,
    site: MemberCompletionSite,
) -> Option<DirectModuleOutputBinding> {
    if lexical.symbols_truncated
        || direct_module_output_member_parent_path(source, site).is_none()
        || site.member.end_byte > lexical.valid_prefix_end_byte
        || site.member.end_byte > shapes.valid_prefix_end_byte
    {
        return None;
    }
    let receiver_name = source.get(site.receiver.start_byte..site.receiver.end_byte)?;
    let initial = visible_symbol_at(lexical, receiver_name, site.receiver.start_byte)?;
    if initial.kind != LexicalSymbolKind::Let {
        return None;
    }

    if shapes.aliases_truncated {
        return None;
    }

    let aliases = StaticRecordAliasIndex::new(source, &lexical.symbols, shapes);
    let root = direct_module_output_alias_root(&aliases, initial)?;
    let output_binding = direct_module_output_binding(source, root, lexical.valid_prefix_end_byte)?;
    let group = direct_module_output_alias_group(shapes, &aliases, root)?;
    direct_module_output_alias_group_is_stable(source, shapes, &aliases, &group, site.receiver)
        .then_some(output_binding)
}

/// Follows only exact source aliases from the static alias report. The root is
/// intentionally just a `let` binding; callers still prove that its initializer
/// is an exact direct module call before exposing output metadata.
fn direct_module_output_alias_root<'symbol>(
    aliases: &StaticRecordAliasIndex<'symbol>,
    initial: &'symbol LexicalSymbol,
) -> Option<&'symbol LexicalSymbol> {
    let mut current = initial;
    let mut visited = HashSet::with_capacity(MAX_DIRECT_MODULE_OUTPUT_ALIAS_DEPTH + 1);
    for depth in 0..=MAX_DIRECT_MODULE_OUTPUT_ALIAS_DEPTH {
        let binding_start_byte = current.definition.start_byte;
        if !visited.insert(binding_start_byte) {
            return None;
        }
        let target_start_byte = match aliases.alias_targets.get(&binding_start_byte).copied() {
            Some(StaticRecordAliasTarget::Let(target_start_byte)) => target_start_byte,
            Some(StaticRecordAliasTarget::DirectPath { .. })
            | Some(StaticRecordAliasTarget::NotStatic)
            | None => return Some(current),
            Some(StaticRecordAliasTarget::Uncertain) => return None,
        };
        if depth == MAX_DIRECT_MODULE_OUTPUT_ALIAS_DEPTH {
            return None;
        }
        let target = aliases
            .symbols_by_definition
            .get(&target_start_byte)
            .copied()?;
        if target.kind != LexicalSymbolKind::Let {
            return None;
        }
        current = target;
    }
    None
}

/// Builds every exact alias that reaches the direct result root. It refuses a
/// chain beyond the fixed alias depth instead of retaining a partial group.
///
/// Unlike ordinary lexical completion, output metadata describes a value that
/// can be captured by a function or lambda and consumed after a later source
/// statement. The complete alias group therefore participates even when an
/// alias is declared after the member site.
fn direct_module_output_alias_group(
    shapes: &StaticRecordShapeReport,
    aliases: &StaticRecordAliasIndex<'_>,
    root: &LexicalSymbol,
) -> Option<HashSet<usize>> {
    let root_start_byte = root.definition.start_byte;
    let mut depths = HashMap::with_capacity(shapes.aliases.len() + 1);
    depths.insert(root_start_byte, 0_usize);

    let mut changed = true;
    while changed {
        changed = false;
        for alias in &shapes.aliases {
            let binding_start_byte = alias.binding.start_byte;
            let target_start_byte = match aliases.alias_targets.get(&binding_start_byte).copied() {
                Some(StaticRecordAliasTarget::Let(target_start_byte)) => target_start_byte,
                Some(StaticRecordAliasTarget::DirectPath {
                    target_start_byte, ..
                }) => {
                    if depths.contains_key(&target_start_byte) {
                        return None;
                    }
                    continue;
                }
                Some(StaticRecordAliasTarget::NotStatic)
                | Some(StaticRecordAliasTarget::Uncertain)
                | None => continue,
            };
            let Some(target_depth) = depths.get(&target_start_byte).copied() else {
                continue;
            };
            if target_depth == MAX_DIRECT_MODULE_OUTPUT_ALIAS_DEPTH {
                return None;
            }
            let next_depth = target_depth.checked_add(1)?;
            if let std::collections::hash_map::Entry::Vacant(entry) =
                depths.entry(binding_start_byte)
            {
                entry.insert(next_depth);
                changed = true;
            }
        }
    }

    Some(depths.into_keys().collect())
}

/// Every direct alias of a result participates in one whole-document stability
/// group. An exact `let alias = binding` target read is allowed only for
/// another member of that same group; all other bare reads remain possible
/// value escapes.
fn direct_module_output_alias_group_is_stable(
    source: &str,
    shapes: &StaticRecordShapeReport,
    aliases: &StaticRecordAliasIndex<'_>,
    group: &HashSet<usize>,
    requested_receiver: SourceSpan,
) -> bool {
    group.iter().all(|binding_start_byte| {
        let Some(symbol) = aliases
            .symbols_by_definition
            .get(binding_start_byte)
            .copied()
        else {
            return false;
        };
        symbol.references.iter().copied().all(|reference| {
            reference == requested_receiver
                || direct_module_output_reference_is_stable_read(source, reference)
                || direct_module_output_reference_is_group_alias_target(shapes, group, reference)
        })
    })
}

fn direct_module_output_reference_is_group_alias_target(
    shapes: &StaticRecordShapeReport,
    group: &HashSet<usize>,
    reference: SourceSpan,
) -> bool {
    shapes
        .aliases
        .iter()
        .any(|alias| alias.target == reference && group.contains(&alias.binding.start_byte))
}

fn module_catalog_output_fields_for_binding<'catalog>(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    shapes: &StaticRecordShapeReport,
    catalog: &'catalog ModuleCompletionCatalog,
    output_binding: DirectModuleOutputBinding,
) -> Option<&'catalog [ModuleCatalogOutputFieldCompletion]> {
    if imports.truncated || catalog.unavailable {
        return None;
    }
    let module = module_catalog_direct_member(
        source,
        lexical,
        imports,
        shapes,
        catalog,
        output_binding.call,
    )?;
    if module.call_shape != Some(ModuleCatalogCallShape::SingleJson)
        || !matches!(
            (module.call_mode, output_binding.awaited),
            (Some(ModuleCatalogCallMode::Synchronous), false)
                | (Some(ModuleCatalogCallMode::Deferred), true)
        )
    {
        return None;
    }
    module.output_fields.as_deref()
}

fn module_catalog_output_fields_at_path<'catalog>(
    fields: &'catalog [ModuleCatalogOutputFieldCompletion],
    path: &[&str],
) -> Option<&'catalog [ModuleCatalogOutputFieldCompletion]> {
    let Some((segment, remaining)) = path.split_first() else {
        return Some(fields);
    };
    let field = fields.iter().find(|field| field.name == *segment)?;
    module_catalog_output_fields_at_path(field.fields.as_deref()?, remaining)
}

fn module_catalog_output_field_for_member<'catalog>(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    catalog: &'catalog ModuleCompletionCatalog,
    shapes: &StaticRecordShapeReport,
    site: MemberCompletionSite,
) -> Option<&'catalog ModuleCatalogOutputFieldCompletion> {
    let member_name = source.get(site.member.start_byte..site.member.end_byte)?;
    module_catalog_output_fields_for_member(source, lexical, imports, catalog, shapes, site)?
        .iter()
        .find(|field| field.name == member_name)
}

fn direct_module_output_reference_is_stable_read(source: &str, reference: SourceSpan) -> bool {
    let Some(next) = skip_splash_trivia(source, reference.end_byte) else {
        return false;
    };
    source.as_bytes().get(next) == Some(&b'.') && !reference_may_mutate_binding(source, reference)
}

/// Returns plain-text advisory hover metadata for an exact catalog leaf. This
/// path is deliberately separate from module resolution and runtime authority.
fn module_catalog_member_hover(
    source: &str,
    symbols: &LexicalSymbolReport,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    shapes: &StaticRecordShapeReport,
    catalog: &ModuleCompletionCatalog,
    site: MemberCompletionSite,
) -> Option<Hover> {
    let receiver_name = source.get(site.receiver.start_byte..site.receiver.end_byte)?;
    visible_symbol_in(&symbols.symbols, receiver_name, site.receiver.start_byte)?;
    let member = source.get(site.member.start_byte..site.member.end_byte)?;
    if !is_canonical_identifier(member) {
        return None;
    }
    if let Some(hover) = fixed_core_module_member_hover(source, lexical, imports, site) {
        return hover;
    }
    if catalog.unavailable {
        return None;
    }
    let mut path = module_catalog_member_parent_path(source, lexical, imports, shapes, site)?;
    path.push(member.to_owned());
    let module = catalog
        .modules
        .iter()
        .find(|module| module.path.as_slice() == path.as_slice())?;
    Some(Hover {
        // Host-supplied descriptions remain plain text to prevent markup injection.
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::PlainText,
            value: module_catalog_member_hover_text(module),
        }),
        range: Some(span_range(source, site.member)),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleCatalogChild {
    name: String,
    description: Option<String>,
    call_mode: Option<ModuleCatalogCallMode>,
}

/// Returns only immediate descriptors below one static path. Intermediate
/// namespaces are inferred from their descendants but deliberately have no
/// borrowed leaf description.
fn module_catalog_children(
    catalog: &ModuleCompletionCatalog,
    parent: &[String],
) -> Vec<ModuleCatalogChild> {
    let mut children: Vec<ModuleCatalogChild> = Vec::new();
    for module in &catalog.modules {
        if module.path.len() <= parent.len() || !module.path.starts_with(parent) {
            continue;
        }
        let name = module.path[parent.len()].clone();
        let is_direct_child = module.path.len() == parent.len() + 1;
        let description =
            (is_direct_child && !module.description.is_empty()).then(|| module.description.clone());
        let call_mode = is_direct_child.then_some(module.call_mode).flatten();
        if let Some(existing) = children.iter_mut().find(|child| child.name == name) {
            if existing.description.is_none() && description.is_some() {
                existing.description = description;
            }
            if existing.call_mode.is_none() && call_mode.is_some() {
                existing.call_mode = call_mode;
            }
        } else {
            children.push(ModuleCatalogChild {
                name,
                description,
                call_mode,
            });
        }
    }
    children.sort_by(|left, right| left.name.cmp(&right.name));
    children
}

fn module_catalog_path_detail(call_mode: Option<ModuleCatalogCallMode>) -> &'static str {
    match call_mode {
        Some(ModuleCatalogCallMode::Synchronous) => {
            "advisory synchronous module path; host module binding required"
        }
        Some(ModuleCatalogCallMode::Deferred) => {
            "advisory deferred module path; host module binding required"
        }
        None => "advisory module path; host module binding required",
    }
}

fn module_catalog_member_detail(call_mode: Option<ModuleCatalogCallMode>) -> &'static str {
    match call_mode {
        Some(ModuleCatalogCallMode::Synchronous) => {
            "advisory synchronous imported-module member; host module binding required"
        }
        Some(ModuleCatalogCallMode::Deferred) => {
            "advisory deferred imported-module member; call returns a promise; host module binding required"
        }
        None => "advisory imported-module member; host module binding required",
    }
}

fn module_catalog_advisory_text(
    description: Option<&str>,
    call_mode: Option<ModuleCatalogCallMode>,
) -> Option<String> {
    let mut value = description.unwrap_or_default().to_owned();
    let mode_note = match call_mode {
        Some(ModuleCatalogCallMode::Synchronous) => "Advisory synchronous method.",
        Some(ModuleCatalogCallMode::Deferred) => {
            "Advisory deferred method; call returns a promise and must use await()."
        }
        None => "",
    };
    if !value.is_empty() && !mode_note.is_empty() {
        value.push_str("\n\n");
    }
    value.push_str(mode_note);
    (!value.is_empty()).then_some(value)
}

fn module_catalog_documentation(
    description: Option<&str>,
    call_mode: Option<ModuleCatalogCallMode>,
) -> Option<Documentation> {
    module_catalog_advisory_text(description, call_mode).map(|value| {
        Documentation::MarkupContent(MarkupContent {
            kind: MarkupKind::PlainText,
            value,
        })
    })
}

fn module_catalog_member_hover_text(module: &ModuleCatalogCompletion) -> String {
    let mut value = format!(
        "Advisory imported-module member `{}`.",
        module.path.join(".")
    );
    if let Some(details) = module_catalog_advisory_text(
        (!module.description.is_empty()).then_some(module.description.as_str()),
        module.call_mode,
    ) {
        value.push_str("\n\n");
        value.push_str(&details);
    }
    if let Some(fields) = &module.input_fields {
        append_module_catalog_input_fields(&mut value, fields);
    }
    if let Some(fields) = &module.output_fields {
        append_module_catalog_output_fields(&mut value, fields);
    }
    value.push_str(
        "\n\nAdvisory metadata only; host module binding and any required capability authorization remain host-owned.",
    );
    value
}

/// Adds compact, host-supplied record metadata to a plain-text module hover.
/// The parser already bounded and validated every field, and this formatting
/// remains presentation-only rather than a schema interpreter.
fn append_module_catalog_input_fields(
    value: &mut String,
    fields: &[ModuleCatalogRecordFieldCompletion],
) {
    value.push_str("\n\nAdvisory input record fields:");
    if fields.is_empty() {
        value.push_str(" no source-compatible fields are projected.");
        return;
    }
    for field in fields {
        append_module_catalog_input_field(value, field, "", 0);
    }
}

fn append_module_catalog_input_field(
    value: &mut String,
    field: &ModuleCatalogRecordFieldCompletion,
    parent_path: &str,
    depth: usize,
) {
    value.push('\n');
    for _ in 0..depth {
        value.push_str("  ");
    }
    value.push_str("- ");
    let path = if parent_path.is_empty() {
        field.name.clone()
    } else {
        format!("{parent_path}.{}", field.name)
    };
    value.push_str(&path);
    value.push_str(": ");
    value.push_str(field.field_type.label());
    value.push_str(if field.required {
        " (required)"
    } else {
        " (optional)"
    });
    if !field.description.is_empty() {
        value.push_str("; ");
        value.push_str(&field.description);
    }
    if let Some(fields) = &field.fields {
        for field in fields {
            append_module_catalog_input_field(value, field, &path, depth + 1);
        }
    }
}

fn append_module_catalog_output_fields(
    value: &mut String,
    fields: &[ModuleCatalogOutputFieldCompletion],
) {
    value.push_str("\n\nAdvisory output record fields:");
    if fields.is_empty() {
        value.push_str(" no source-compatible fields are projected.");
        return;
    }
    for field in fields {
        append_module_catalog_output_field(value, field, "", 0);
    }
}

fn append_module_catalog_output_field(
    value: &mut String,
    field: &ModuleCatalogOutputFieldCompletion,
    parent_path: &str,
    depth: usize,
) {
    value.push('\n');
    for _ in 0..depth {
        value.push_str("  ");
    }
    value.push_str("- ");
    let path = if parent_path.is_empty() {
        field.name.clone()
    } else {
        format!("{parent_path}.{}", field.name)
    };
    value.push_str(&path);
    value.push_str(": ");
    value.push_str(field.field_type.label());
    value.push_str(if field.required {
        " (required)"
    } else {
        " (optional)"
    });
    if !field.description.is_empty() {
        value.push_str("; ");
        value.push_str(&field.description);
    }
    if let Some(fields) = &field.fields {
        for field in fields {
            append_module_catalog_output_field(value, field, &path, depth + 1);
        }
    }
}

fn builtin_tool_signature_help(method: &str, active_argument: usize) -> Option<SignatureHelp> {
    let (label, documentation, value_parameter) = match method {
        "call" => (
            "tool.call(name, input) -> string",
            "Calls a reviewed text capability synchronously. The host validates the requested name and active capability lease at runtime; signature help does not grant a capability.",
            "input",
        ),
        "start" => (
            "tool.start(name, input) -> promise<string>",
            "Starts a reviewed text capability. Await the returned promise before using its string result. The host validates the requested name and active capability lease at runtime; signature help does not grant a capability.",
            "input",
        ),
        "call_json" => (
            "tool.call_json(name, value) -> string",
            "Calls a reviewed JSON capability synchronously. Value must cross the bounded JSON bridge, and the returned string can be decoded with parse_json(). The host validates the requested name and active capability lease at runtime; signature help does not grant a capability.",
            "value",
        ),
        "start_json" => (
            "tool.start_json(name, value) -> promise<string>",
            "Starts a reviewed JSON capability. Value must cross the bounded JSON bridge; await the promise, then decode its string result with parse_json(). The host validates the requested name and active capability lease at runtime; signature help does not grant a capability.",
            "value",
        ),
        _ => return None,
    };
    Some(signature_help_with_parameters(
        label,
        documentation,
        &["name", value_parameter],
        active_argument,
    ))
}

fn standard_math_signature_help(
    source: &str,
    context: SignatureHelpCallContext,
) -> Option<SignatureHelp> {
    let member = source.get(context.callee.member.start_byte..context.callee.member.end_byte)?;
    let function = standard_math_function(member)?;
    let callee = source.get(context.callee.receiver.start_byte..context.callee.member.end_byte)?;
    Some(signature_help_with_parameters(
        format!("{callee}({}) -> number", function.parameters.join(", ")),
        standard_math_function_documentation(function, callee),
        function.parameters,
        context.active_argument,
    ))
}

fn standard_json_signature_help(
    source: &str,
    context: SignatureHelpCallContext,
) -> Option<SignatureHelp> {
    let member = source.get(context.callee.member.start_byte..context.callee.member.end_byte)?;
    let function = standard_json_function(member)?;
    let callee = source.get(context.callee.receiver.start_byte..context.callee.member.end_byte)?;
    Some(signature_help_with_parameters(
        format!(
            "{callee}({}) -> {}",
            function.parameters.join(", "),
            function.result
        ),
        standard_json_function_documentation(function, callee),
        function.parameters,
        context.active_argument,
    ))
}

fn standard_array_signature_help(
    source: &str,
    context: SignatureHelpCallContext,
) -> Option<SignatureHelp> {
    let member = source.get(context.callee.member.start_byte..context.callee.member.end_byte)?;
    let function = standard_array_function(member)?;
    let callee = source.get(context.callee.receiver.start_byte..context.callee.member.end_byte)?;
    Some(signature_help_with_parameters(
        format!(
            "{callee}({}) -> {}",
            function.parameters.join(", "),
            function.result
        ),
        standard_array_function_documentation(function, callee),
        function.parameters,
        context.active_argument,
    ))
}

fn standard_object_signature_help(
    source: &str,
    context: SignatureHelpCallContext,
) -> Option<SignatureHelp> {
    let member = source.get(context.callee.member.start_byte..context.callee.member.end_byte)?;
    let function = standard_object_function(member)?;
    let callee = source.get(context.callee.receiver.start_byte..context.callee.member.end_byte)?;
    Some(signature_help_with_parameters(
        format!(
            "{callee}({}) -> {}",
            function.parameters.join(", "),
            function.result
        ),
        standard_object_function_documentation(function, callee),
        function.parameters,
        context.active_argument,
    ))
}

fn standard_text_signature_help(
    source: &str,
    context: SignatureHelpCallContext,
) -> Option<SignatureHelp> {
    let member = source.get(context.callee.member.start_byte..context.callee.member.end_byte)?;
    let function = standard_text_function(member)?;
    let callee = source.get(context.callee.receiver.start_byte..context.callee.member.end_byte)?;
    Some(signature_help_with_parameters(
        format!(
            "{callee}({}) -> {}",
            function.parameters.join(", "),
            function.result
        ),
        standard_text_function_documentation(function, callee),
        function.parameters,
        context.active_argument,
    ))
}

fn standard_assert_signature_help(callee: &str, active_argument: usize) -> SignatureHelp {
    signature_help_with_parameters(
        format!("{callee}(condition)"),
        standard_assert_documentation(callee),
        &["condition"],
        active_argument,
    )
}

fn standard_assert_member_signature_help(
    source: &str,
    context: SignatureHelpCallContext,
) -> Option<SignatureHelp> {
    let callee = source.get(context.callee.receiver.start_byte..context.callee.member.end_byte)?;
    Some(standard_assert_signature_help(
        callee,
        context.active_argument,
    ))
}

fn module_catalog_signature_help(
    source: &str,
    module: &ModuleCatalogCompletion,
    call_mode: ModuleCatalogCallMode,
    context: SignatureHelpCallContext,
) -> Option<SignatureHelp> {
    let callee = source.get(context.callee.receiver.start_byte..context.callee.member.end_byte)?;
    let label = match call_mode {
        ModuleCatalogCallMode::Synchronous => format!("{callee}(input) -> JSON value"),
        ModuleCatalogCallMode::Deferred => format!("{callee}(input) -> promise<JSON value>"),
    };
    Some(signature_help_with_parameters(
        label,
        module_catalog_member_hover_text(module),
        &["input"],
        context.active_argument,
    ))
}

fn signature_help_with_parameters(
    label: impl Into<String>,
    documentation: impl Into<String>,
    parameter_names: &[&str],
    active_argument: usize,
) -> SignatureHelp {
    let active_parameter =
        (active_argument < parameter_names.len()).then(|| to_u32(active_argument));
    SignatureHelp {
        signatures: vec![SignatureInformation {
            label: label.into(),
            documentation: Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: documentation.into(),
            })),
            parameters: Some(
                parameter_names
                    .iter()
                    .map(|name| ParameterInformation {
                        label: ParameterLabel::Simple((*name).to_owned()),
                        documentation: None,
                    })
                    .collect(),
            ),
            active_parameter: None,
        }],
        active_signature: Some(0),
        active_parameter,
    }
}

fn tool_catalog_name_completion(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    catalog: &ToolCompletionCatalog,
    site: ToolNameCompletionSite,
    is_incomplete: bool,
) -> CompletionList {
    let is_incomplete = is_incomplete || catalog.unavailable;
    let empty = || CompletionList {
        is_incomplete,
        items: Vec::new(),
    };
    if !is_visible_builtin_tool_receiver(source, lexical, imports, site.receiver) {
        return empty();
    }

    let edit_range = span_range(source, site.name);
    let items = catalog
        .tools
        .iter()
        .filter(|tool| tool.format.accepts_call_format(site.call_format))
        .map(|tool| CompletionItem {
            label: tool.name.clone(),
            kind: Some(CompletionItemKind::VALUE),
            detail: Some(format!(
                "{} capability name; host approval required",
                tool.format.label()
            )),
            documentation: (!tool.description.is_empty()).then(|| {
                Documentation::MarkupContent(MarkupContent {
                    kind: MarkupKind::PlainText,
                    value: tool.description.clone(),
                })
            }),
            text_edit: Some(CompletionTextEdit::Edit(TextEdit::new(
                edit_range,
                tool.name.clone(),
            ))),
            ..CompletionItem::default()
        })
        .collect();

    CompletionList {
        is_incomplete,
        items,
    }
}

fn is_visible_builtin_tool_receiver(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    receiver: SourceSpan,
) -> bool {
    visible_module_import_for_receiver(source, lexical, imports, receiver)
        .is_some_and(is_builtin_tool_module_import)
}

fn is_visible_builtin_standard_math_receiver(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    receiver: SourceSpan,
) -> bool {
    visible_module_import_for_receiver(source, lexical, imports, receiver)
        .is_some_and(is_builtin_standard_math_module_import)
}

fn is_visible_builtin_standard_json_receiver(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    receiver: SourceSpan,
) -> bool {
    visible_module_import_for_receiver(source, lexical, imports, receiver)
        .is_some_and(is_builtin_standard_json_module_import)
}

fn is_visible_builtin_standard_array_receiver(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    receiver: SourceSpan,
) -> bool {
    visible_module_import_for_receiver(source, lexical, imports, receiver)
        .is_some_and(is_builtin_standard_array_module_import)
}

fn is_visible_builtin_standard_object_receiver(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    receiver: SourceSpan,
) -> bool {
    visible_module_import_for_receiver(source, lexical, imports, receiver)
        .is_some_and(is_builtin_standard_object_module_import)
}

fn is_visible_builtin_standard_text_receiver(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    receiver: SourceSpan,
) -> bool {
    visible_module_import_for_receiver(source, lexical, imports, receiver)
        .is_some_and(is_builtin_standard_text_module_import)
}

fn is_visible_builtin_standard_assert_receiver(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    receiver: SourceSpan,
) -> bool {
    visible_module_import_for_receiver(source, lexical, imports, receiver)
        .is_some_and(is_builtin_standard_assert_module_import)
}

fn is_visible_builtin_standard_assert_member(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &ModuleImportReport,
    site: MemberCompletionSite,
) -> bool {
    if source.get(site.member.start_byte..site.member.end_byte) != Some("assert") {
        return false;
    }
    fixed_core_direct_import_path_for_member(source, lexical, imports, site)
        .is_some_and(|path| module_path_matches(&path, &["mod", "std"]))
}

fn visible_module_import_for_receiver<'imports>(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &'imports ModuleImportReport,
    receiver: SourceSpan,
) -> Option<&'imports ModuleImport> {
    if receiver.end_byte > lexical.valid_prefix_end_byte
        || receiver.end_byte > imports.valid_prefix_end_byte
    {
        return None;
    }
    let receiver_name = source.get(receiver.start_byte..receiver.end_byte)?;
    let symbol = visible_symbol_at(lexical, receiver_name, receiver.start_byte)?;
    (symbol.kind == LexicalSymbolKind::Import)
        .then(|| {
            imports
                .imports
                .iter()
                .find(|import| import.binding == symbol.definition)
        })
        .flatten()
}

/// Resolves an exact local root alias only for advisory module-catalog
/// metadata. It shares the review boundary's fixed hop limit, but remains
/// source-only and never creates a module binding or authority.
struct ImportedModuleAliasIndex<'imports, 'symbol> {
    imports_by_binding: HashMap<usize, &'imports ModuleImport>,
    symbols_by_definition: HashMap<usize, &'symbol LexicalSymbol>,
    imported_binding_by_alias: HashMap<usize, usize>,
    alias_binding_by_target: HashMap<(usize, usize), usize>,
}

impl<'imports, 'symbol> ImportedModuleAliasIndex<'imports, 'symbol> {
    fn new(
        source: &str,
        symbols: &'symbol [LexicalSymbol],
        imports: &'imports [ModuleImport],
        shapes: &StaticRecordShapeReport,
    ) -> Self {
        let imports_by_binding = imports
            .iter()
            .map(|import| (import.binding.start_byte, import))
            .collect::<HashMap<_, _>>();
        let symbols_by_definition = symbols
            .iter()
            .map(|symbol| (symbol.definition.start_byte, symbol))
            .collect::<HashMap<_, _>>();
        let mut alias_targets = HashMap::with_capacity(shapes.aliases.len());
        let mut alias_binding_by_target = HashMap::with_capacity(shapes.aliases.len());

        for alias in shapes
            .aliases
            .iter()
            .filter(|alias| alias.direct_child.is_none() && alias.direct_grandchild.is_none())
        {
            let Some(target_name) = source.get(alias.target.start_byte..alias.target.end_byte)
            else {
                continue;
            };
            let Some(target) = visible_symbol_in(symbols, target_name, alias.target.start_byte)
            else {
                continue;
            };
            alias_targets.insert(alias.binding.start_byte, target.definition.start_byte);
            alias_binding_by_target.insert(
                (alias.target.start_byte, alias.target.end_byte),
                alias.binding.start_byte,
            );
        }

        let mut imported_binding_by_alias = HashMap::with_capacity(alias_targets.len());
        for alias_binding in alias_targets.keys().copied() {
            if let Some(import_binding) = imported_module_binding_for_alias(
                alias_binding,
                &symbols_by_definition,
                &imports_by_binding,
                &alias_targets,
            ) {
                imported_binding_by_alias.insert(alias_binding, import_binding);
            }
        }

        Self {
            imports_by_binding,
            symbols_by_definition,
            imported_binding_by_alias,
            alias_binding_by_target,
        }
    }

    fn imported_module_for_symbol(&self, symbol: &LexicalSymbol) -> Option<&'imports ModuleImport> {
        let import_binding = match symbol.kind {
            LexicalSymbolKind::Import => symbol.definition.start_byte,
            LexicalSymbolKind::Let => *self
                .imported_binding_by_alias
                .get(&symbol.definition.start_byte)?,
            LexicalSymbolKind::Function
            | LexicalSymbolKind::Parameter
            | LexicalSymbolKind::LoopBinding
            | LexicalSymbolKind::LambdaParameter => return None,
        };
        self.imports_by_binding.get(&import_binding).copied()
    }

    fn alias_group(&self, import_binding: usize) -> HashSet<usize> {
        let mut group = HashSet::with_capacity(self.imported_binding_by_alias.len() + 1);
        group.insert(import_binding);
        group.extend(self.imported_binding_by_alias.iter().filter_map(
            |(&alias_binding, &resolved_import)| {
                (resolved_import == import_binding).then_some(alias_binding)
            },
        ));
        group
    }
}

fn imported_module_binding_for_alias(
    initial_binding: usize,
    symbols_by_definition: &HashMap<usize, &LexicalSymbol>,
    imports_by_binding: &HashMap<usize, &ModuleImport>,
    alias_targets: &HashMap<usize, usize>,
) -> Option<usize> {
    let mut current_binding = initial_binding;
    let mut visited = HashSet::with_capacity(MAX_IMPORTED_MODULE_ALIAS_DEPTH + 1);

    for depth in 0..=MAX_IMPORTED_MODULE_ALIAS_DEPTH {
        if !visited.insert(current_binding) {
            return None;
        }
        if imports_by_binding.contains_key(&current_binding) {
            return Some(current_binding);
        }
        if depth == MAX_IMPORTED_MODULE_ALIAS_DEPTH
            || symbols_by_definition
                .get(&current_binding)
                .is_none_or(|symbol| symbol.kind != LexicalSymbolKind::Let)
        {
            return None;
        }
        current_binding = *alias_targets.get(&current_binding)?;
    }

    None
}

fn visible_module_import_or_alias_for_catalog_receiver<'imports>(
    source: &str,
    lexical: &LexicalCompletionReport,
    imports: &'imports ModuleImportReport,
    shapes: &StaticRecordShapeReport,
    receiver: SourceSpan,
) -> Option<&'imports ModuleImport> {
    if receiver.end_byte > lexical.valid_prefix_end_byte
        || receiver.end_byte > imports.valid_prefix_end_byte
    {
        return None;
    }
    let receiver_name = source.get(receiver.start_byte..receiver.end_byte)?;
    let initial = visible_symbol_at(lexical, receiver_name, receiver.start_byte)?;
    if initial.kind == LexicalSymbolKind::Import {
        return imports
            .imports
            .iter()
            .find(|import| import.binding == initial.definition);
    }
    if initial.kind != LexicalSymbolKind::Let
        || lexical.symbols_truncated
        || imports.truncated
        || shapes.aliases_truncated
        || receiver.end_byte > shapes.valid_prefix_end_byte
    {
        return None;
    }

    let aliases = ImportedModuleAliasIndex::new(source, &lexical.symbols, &imports.imports, shapes);
    let import = aliases.imported_module_for_symbol(initial)?;
    let group = aliases.alias_group(import.binding.start_byte);
    imported_module_alias_group_is_stable(source, &aliases, &group, receiver).then_some(import)
}

/// Reports only the missing source metadata that can affect a local module
/// alias. Direct imports do not depend on the static alias report, so their
/// advisory completion remains complete when unrelated alias edges are capped.
fn module_catalog_alias_metadata_is_truncated_at_receiver(
    source: &str,
    lexical: &LexicalCompletionReport,
    shapes: &StaticRecordShapeReport,
    receiver: SourceSpan,
) -> bool {
    if !shapes.aliases_truncated || receiver.end_byte > lexical.valid_prefix_end_byte {
        return false;
    }
    let Some(receiver_name) = source.get(receiver.start_byte..receiver.end_byte) else {
        return false;
    };
    visible_symbol_at(lexical, receiver_name, receiver.start_byte)
        .is_some_and(|symbol| symbol.kind == LexicalSymbolKind::Let)
}

fn imported_module_alias_group_is_stable(
    source: &str,
    aliases: &ImportedModuleAliasIndex<'_, '_>,
    group: &HashSet<usize>,
    requested_receiver: SourceSpan,
) -> bool {
    group.iter().all(|binding_start_byte| {
        let Some(symbol) = aliases
            .symbols_by_definition
            .get(binding_start_byte)
            .copied()
        else {
            return false;
        };
        symbol.references.iter().copied().all(|reference| {
            reference == requested_receiver
                || aliases
                    .alias_binding_by_target
                    .get(&(reference.start_byte, reference.end_byte))
                    .is_some_and(|alias_binding| group.contains(alias_binding))
                || imported_module_alias_reference_is_direct_member_call(source, reference)
        })
    })
}

fn imported_module_alias_reference_is_direct_member_call(
    source: &str,
    reference: SourceSpan,
) -> bool {
    let bytes = source.as_bytes();
    let mut index = reference.end_byte;
    let mut member_count = 0_usize;

    loop {
        let Some(separator) = skip_splash_trivia(source, index) else {
            return false;
        };
        if bytes.get(separator) != Some(&b'.') {
            return false;
        }
        let Some(member_start) = skip_splash_trivia(source, separator + 1) else {
            return false;
        };
        if !bytes
            .get(member_start)
            .is_some_and(|byte| is_identifier_start_byte(*byte))
        {
            return false;
        }
        member_count += 1;
        if member_count > MAX_LSP_MODULE_PATH_SEGMENTS {
            return false;
        }
        index = member_start + 1;
        while bytes
            .get(index)
            .is_some_and(|byte| is_identifier_byte(*byte))
        {
            index += 1;
        }

        let Some(next) = skip_splash_trivia(source, index) else {
            return false;
        };
        match bytes.get(next) {
            Some(b'(') => return true,
            Some(b'.') => index = next,
            _ => return false,
        }
    }
}

fn visible_symbol_at<'symbol>(
    report: &'symbol LexicalCompletionReport,
    name: &str,
    byte_offset: usize,
) -> Option<&'symbol LexicalSymbol> {
    visible_symbol_in(&report.symbols, name, byte_offset)
}

fn visible_symbol_in<'symbol>(
    symbols: &'symbol [LexicalSymbol],
    name: &str,
    byte_offset: usize,
) -> Option<&'symbol LexicalSymbol> {
    symbols
        .iter()
        .filter(|symbol| {
            symbol.name == name
                && symbol.visibility_start_byte <= byte_offset
                && byte_offset < symbol.visibility_end_byte
        })
        .max_by_key(|symbol| (symbol.visibility_start_byte, symbol.definition.start_byte))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaticRecordAliasTarget {
    Let(usize),
    DirectPath {
        target_start_byte: usize,
        children: [Option<SourceSpan>; MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH],
        child_count: usize,
    },
    NotStatic,
    Uncertain,
}

fn static_record_alias_child_path(
    source: &str,
    target: SourceSpan,
    direct_child: Option<SourceSpan>,
    direct_grandchild: Option<SourceSpan>,
) -> Option<(
    [Option<SourceSpan>; MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH],
    usize,
)> {
    let children = [direct_child, direct_grandchild];
    let child_count = match (direct_child, direct_grandchild) {
        (None, None) => 0,
        (Some(_), None) => 1,
        (Some(_), Some(_)) => 2,
        (None, Some(_)) => return None,
    };
    if child_count > MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH {
        return None;
    }

    let mut previous_end_byte = target.end_byte;
    for child in children[..child_count].iter().copied() {
        let child = child?;
        if child.start_byte < previous_end_byte
            || !source
                .get(child.start_byte..child.end_byte)
                .is_some_and(is_canonical_identifier)
        {
            return None;
        }
        previous_end_byte = child.end_byte;
    }

    Some((children, child_count))
}

/// One root literal-record view reached through an exact local alias chain.
/// A view can retain a bounded direct child path selected by an exact alias
/// initializer such as `let alias = root.child.grandchild`; it never follows a
/// computed member expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StaticRecordView {
    root_binding: SourceSpan,
    direct_children: [Option<SourceSpan>; MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH],
    direct_child_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaticRecordViewResolution {
    Found(StaticRecordView),
    Escaped(SourceSpan),
    NotStatic,
    Uncertain,
}

struct StaticRecordAliasIndex<'symbol> {
    symbols_by_definition: HashMap<usize, &'symbol LexicalSymbol>,
    alias_targets: HashMap<usize, StaticRecordAliasTarget>,
    static_shape_bindings: HashSet<usize>,
}

impl<'symbol> StaticRecordAliasIndex<'symbol> {
    fn new(
        source: &str,
        symbols: &'symbol [LexicalSymbol],
        shapes: &StaticRecordShapeReport,
    ) -> Self {
        let symbols_by_definition = symbols
            .iter()
            .map(|symbol| (symbol.definition.start_byte, symbol))
            .collect();
        let static_shape_bindings = shapes
            .shapes
            .iter()
            .map(|shape| shape.binding.start_byte)
            .collect();
        let mut alias_targets = HashMap::with_capacity(shapes.aliases.len());
        for alias in &shapes.aliases {
            let target = match source.get(alias.target.start_byte..alias.target.end_byte) {
                Some(name) => match visible_symbol_in(symbols, name, alias.target.start_byte) {
                    Some(symbol) if symbol.kind == LexicalSymbolKind::Let => {
                        match static_record_alias_child_path(
                            source,
                            alias.target,
                            alias.direct_child,
                            alias.direct_grandchild,
                        ) {
                            Some((_, 0)) => {
                                StaticRecordAliasTarget::Let(symbol.definition.start_byte)
                            }
                            Some((children, child_count)) => StaticRecordAliasTarget::DirectPath {
                                target_start_byte: symbol.definition.start_byte,
                                children,
                                child_count,
                            },
                            None => StaticRecordAliasTarget::Uncertain,
                        }
                    }
                    _ => StaticRecordAliasTarget::NotStatic,
                },
                None => StaticRecordAliasTarget::Uncertain,
            };
            alias_targets.insert(alias.binding.start_byte, target);
        }

        Self {
            symbols_by_definition,
            alias_targets,
            static_shape_bindings,
        }
    }

    fn view_for(&self, initial: &'symbol LexicalSymbol) -> StaticRecordViewResolution {
        if initial.kind != LexicalSymbolKind::Let {
            return StaticRecordViewResolution::NotStatic;
        }

        let mut current = initial;
        let mut direct_children = [None; MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH];
        let mut direct_child_count = 0_usize;
        let mut escaped = false;
        let mut visited = Vec::with_capacity(MAX_STATIC_RECORD_ALIAS_DEPTH + 1);
        for depth in 0..=MAX_STATIC_RECORD_ALIAS_DEPTH {
            let binding_start_byte = current.definition.start_byte;
            if self.static_shape_bindings.contains(&binding_start_byte) {
                if escaped {
                    return StaticRecordViewResolution::Escaped(current.definition);
                }
                return StaticRecordViewResolution::Found(StaticRecordView {
                    root_binding: current.definition,
                    direct_children,
                    direct_child_count,
                });
            }
            if visited.contains(&binding_start_byte) || depth == MAX_STATIC_RECORD_ALIAS_DEPTH {
                return StaticRecordViewResolution::Uncertain;
            }
            visited.push(binding_start_byte);

            let target_start_byte = match self.alias_targets.get(&binding_start_byte).copied() {
                Some(StaticRecordAliasTarget::Let(target_start_byte)) => target_start_byte,
                Some(StaticRecordAliasTarget::DirectPath {
                    target_start_byte,
                    children,
                    child_count,
                }) => {
                    if child_count > MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH
                        || direct_child_count.saturating_add(child_count)
                            > MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH
                    {
                        // A deeper child selector is unsupported, but it still
                        // escapes the retained view. Keep following the bounded
                        // root chain so callers can fail closed only for that
                        // root.
                        escaped = true;
                    } else {
                        // Alias traversal proceeds from the use site toward
                        // the root. Insert each selected child path at the
                        // front so the retained path remains root-to-leaf.
                        direct_children.copy_within(0..direct_child_count, child_count);
                        direct_children[..child_count].copy_from_slice(&children[..child_count]);
                        direct_child_count += child_count;
                    }
                    target_start_byte
                }
                Some(StaticRecordAliasTarget::NotStatic) | None => {
                    return StaticRecordViewResolution::NotStatic
                }
                Some(StaticRecordAliasTarget::Uncertain) => {
                    return StaticRecordViewResolution::Uncertain
                }
            };
            let Some(target) = self.symbols_by_definition.get(&target_start_byte).copied() else {
                return StaticRecordViewResolution::Uncertain;
            };
            if target.kind != LexicalSymbolKind::Let {
                return StaticRecordViewResolution::Uncertain;
            }
            current = target;
        }

        StaticRecordViewResolution::Uncertain
    }
}

fn visible_static_record_view<'shape>(
    source: &str,
    symbols: &[LexicalSymbol],
    valid_prefix_end_byte: usize,
    shapes: &'shape StaticRecordShapeReport,
    receiver: SourceSpan,
) -> Option<(&'shape StaticRecordShape, StaticRecordView)> {
    if receiver.end_byte > valid_prefix_end_byte || receiver.end_byte > shapes.valid_prefix_end_byte
    {
        return None;
    }
    let receiver_name = source.get(receiver.start_byte..receiver.end_byte)?;
    let symbol = visible_symbol_in(symbols, receiver_name, receiver.start_byte)?;
    if symbol.kind != LexicalSymbolKind::Let {
        return None;
    }
    let aliases = StaticRecordAliasIndex::new(source, symbols, shapes);
    let StaticRecordViewResolution::Found(view) = aliases.view_for(symbol) else {
        return None;
    };
    if !shapes.aliases_truncated
        && !static_record_alias_group_is_stable(
            source,
            shapes,
            &aliases,
            view.root_binding,
            receiver.start_byte,
        )
    {
        return None;
    }
    shapes
        .shapes
        .iter()
        .find(|shape| shape.binding == view.root_binding)
        .map(|shape| (shape, view))
}

/// Returns static fields for the root literal or a bounded direct nested path.
/// Exact aliases can carry one or two direct selectors through an alias chain;
/// a following direct member path may use the remaining literal-depth budget.
/// Computed paths and deeper alias chains beyond that budget have no static
/// metadata.
fn visible_static_record_fields<'shape>(
    source: &str,
    symbols: &[LexicalSymbol],
    valid_prefix_end_byte: usize,
    shapes: &'shape StaticRecordShapeReport,
    site: MemberCompletionSite,
) -> Option<&'shape [StaticRecordField]> {
    let (shape, view) = visible_static_record_view(
        source,
        symbols,
        valid_prefix_end_byte,
        shapes,
        site.receiver,
    )?;
    let site_path = static_record_direct_child_path(source, site)?;
    let mut path = Vec::with_capacity(MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH);
    for child in view.direct_children[..view.direct_child_count]
        .iter()
        .copied()
    {
        let child = child?;
        path.push(source.get(child.start_byte..child.end_byte)?);
    }
    if path.len().saturating_add(site_path.len()) > MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH {
        return None;
    }
    path.extend(site_path);
    static_record_fields_at_path(shape, &path)
}

/// Extracts the bounded direct child identifiers between a root binding and a
/// member being completed. The lexical member recognizer has already rejected
/// strings, comments, indexes, calls, and non-identifier segments.
fn static_record_direct_child_path(source: &str, site: MemberCompletionSite) -> Option<Vec<&str>> {
    let root = source.get(site.receiver.start_byte..site.receiver.end_byte)?;
    let chain = source.get(site.receiver_chain.start_byte..site.receiver_chain.end_byte)?;
    if chain == root {
        return Some(Vec::new());
    }

    let suffix = chain.strip_prefix(root)?.strip_prefix('.')?;
    let mut path = Vec::with_capacity(MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH);
    for child in suffix.split('.') {
        if path.len() == MAX_STATIC_RECORD_LITERAL_CHILD_DEPTH || !is_canonical_identifier(child) {
            return None;
        }
        path.push(child);
    }
    Some(path)
}

fn static_record_fields_at_path<'shape>(
    shape: &'shape StaticRecordShape,
    path: &[&str],
) -> Option<&'shape [StaticRecordField]> {
    if path.is_empty() {
        return Some(&shape.fields);
    }
    static_record_nested_fields_at_path(&shape.direct_field_shapes, path)
}

fn static_record_nested_fields_at_path<'shape>(
    shapes: &'shape [StaticRecordNestedShape],
    path: &[&str],
) -> Option<&'shape [StaticRecordField]> {
    let (name, remaining) = path.split_first()?;
    let shape = shapes.iter().find(|shape| shape.field.name == *name)?;
    if remaining.is_empty() {
        Some(&shape.fields)
    } else {
        static_record_nested_fields_at_path(&shape.direct_field_shapes, remaining)
    }
}

fn static_record_alias_group_is_stable(
    source: &str,
    shapes: &StaticRecordShapeReport,
    aliases: &StaticRecordAliasIndex<'_>,
    root_binding: SourceSpan,
    site_start_byte: usize,
) -> bool {
    let Some(root) = aliases
        .symbols_by_definition
        .get(&root_binding.start_byte)
        .copied()
    else {
        return false;
    };
    if root.definition != root_binding || !binding_is_stable_at(source, root, site_start_byte) {
        return false;
    }

    for alias in shapes
        .aliases
        .iter()
        .filter(|alias| alias.binding.start_byte < site_start_byte)
    {
        let Some(alias_symbol) = aliases
            .symbols_by_definition
            .get(&alias.binding.start_byte)
            .copied()
        else {
            return false;
        };
        match aliases.view_for(alias_symbol) {
            StaticRecordViewResolution::Found(alias_view)
                if alias_view.root_binding == root_binding =>
            {
                if !binding_is_stable_at(source, alias_symbol, site_start_byte) {
                    return false;
                }
            }
            StaticRecordViewResolution::Escaped(alias_root) if alias_root == root_binding => {
                return false;
            }
            StaticRecordViewResolution::Found(_)
            | StaticRecordViewResolution::Escaped(_)
            | StaticRecordViewResolution::NotStatic => {}
            StaticRecordViewResolution::Uncertain => return false,
        }
    }

    true
}

fn binding_is_stable_at(source: &str, symbol: &LexicalSymbol, site_start_byte: usize) -> bool {
    symbol
        .references
        .iter()
        .copied()
        .filter(|reference| reference.start_byte < site_start_byte)
        .all(|reference| !reference_may_mutate_binding(source, reference))
}

/// Detects writes to a binding or one of its direct member paths. Indexing,
/// calls, and delimiter-terminated values fail closed because this lightweight
/// advisory feature does not model their possible mutation or escape behavior.
fn reference_may_mutate_binding(source: &str, reference: SourceSpan) -> bool {
    let bytes = source.as_bytes();
    let Some(mut index) = skip_splash_trivia(source, reference.end_byte) else {
        return true;
    };

    loop {
        if is_assignment_operator_at(bytes, index) {
            return true;
        }
        if bytes.get(index) != Some(&b'.') {
            return matches!(
                bytes.get(index),
                Some(b'[' | b'(' | b',' | b')' | b']' | b'}')
            );
        }

        index += 1;
        let Some(next) = skip_splash_trivia(source, index) else {
            return true;
        };
        if !bytes
            .get(next)
            .is_some_and(|byte| is_identifier_start_byte(*byte))
        {
            return true;
        }
        index = next + 1;
        while bytes
            .get(index)
            .is_some_and(|byte| is_identifier_byte(*byte))
        {
            index += 1;
        }
        let Some(next) = skip_splash_trivia(source, index) else {
            return true;
        };
        index = next;
    }
}

fn skip_splash_trivia(source: &str, mut index: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    loop {
        while bytes
            .get(index)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            index += 1;
        }
        if bytes.get(index) != Some(&b'/') {
            return Some(index);
        }
        match bytes.get(index + 1) {
            Some(b'/') => {
                index += 2;
                while bytes
                    .get(index)
                    .is_some_and(|byte| !matches!(byte, b'\n' | b'\r'))
                {
                    index = advance_utf8_character(source, index);
                }
            }
            Some(b'*') => {
                index += 2;
                while !(bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/')) {
                    if index == bytes.len() {
                        return None;
                    }
                    index = advance_utf8_character(source, index);
                }
                index += 2;
            }
            _ => return Some(index),
        }
    }
}

fn is_assignment_operator_at(bytes: &[u8], index: usize) -> bool {
    match bytes.get(index) {
        Some(b'=') => bytes.get(index + 1) != Some(&b'='),
        Some(b'+' | b'-' | b'*' | b'/' | b'%') => bytes.get(index + 1) == Some(&b'='),
        _ => false,
    }
}

fn static_record_field_for_member<'field>(
    source: &str,
    symbols: &[LexicalSymbol],
    valid_prefix_end_byte: usize,
    shapes: &'field StaticRecordShapeReport,
    site: MemberCompletionSite,
) -> Option<&'field StaticRecordField> {
    if shapes.aliases_truncated
        || site.member.end_byte > valid_prefix_end_byte
        || site.member.end_byte > shapes.valid_prefix_end_byte
    {
        return None;
    }
    let member_name = source.get(site.member.start_byte..site.member.end_byte)?;
    let fields =
        visible_static_record_fields(source, symbols, valid_prefix_end_byte, shapes, site)?;
    fields.iter().find(|field| field.name == member_name)
}

fn is_builtin_tool_module_import(import: &ModuleImport) -> bool {
    import.path.iter().map(String::as_str).eq(["mod", "tool"])
}

fn is_builtin_standard_math_module_import(import: &ModuleImport) -> bool {
    import
        .path
        .iter()
        .map(String::as_str)
        .eq(["mod", "std", "math"])
}

fn is_builtin_standard_json_module_import(import: &ModuleImport) -> bool {
    import
        .path
        .iter()
        .map(String::as_str)
        .eq(["mod", "std", "json"])
}

fn is_builtin_standard_array_module_import(import: &ModuleImport) -> bool {
    import
        .path
        .iter()
        .map(String::as_str)
        .eq(["mod", "std", "array"])
}

fn is_builtin_standard_object_module_import(import: &ModuleImport) -> bool {
    import
        .path
        .iter()
        .map(String::as_str)
        .eq(["mod", "std", "object"])
}

fn is_builtin_standard_text_module_import(import: &ModuleImport) -> bool {
    import
        .path
        .iter()
        .map(String::as_str)
        .eq(["mod", "std", "text"])
}

fn is_builtin_standard_assert_module_import(import: &ModuleImport) -> bool {
    import
        .path
        .iter()
        .map(String::as_str)
        .eq(["mod", "std", "assert"])
}

fn require_complete_lexical_report(report: &LexicalSymbolReport) -> Result<(), String> {
    if report.truncated {
        Err(format!(
            "the lexical index exceeds Splash's {MAX_LEXICAL_SYMBOL_OCCURRENCES}-occurrence limit"
        ))
    } else {
        Ok(())
    }
}

fn rename_symbol_occurrence_at_byte(
    report: &LexicalSymbolReport,
    byte_offset: usize,
) -> Option<(usize, SourceSpan)> {
    symbol_occurrence_index_at_byte(report, byte_offset).or_else(|| {
        report
            .symbols
            .iter()
            .enumerate()
            .find_map(|(index, symbol)| {
                std::iter::once(symbol.definition)
                    .chain(symbol.references.iter().copied())
                    .find(|span| span.end_byte == byte_offset)
                    .map(|span| (index, span))
            })
    })
}

fn symbol_occurrence_index_at_byte(
    report: &LexicalSymbolReport,
    byte_offset: usize,
) -> Option<(usize, SourceSpan)> {
    report
        .symbols
        .iter()
        .enumerate()
        .find_map(|(index, symbol)| {
            if span_contains(symbol.definition, byte_offset) {
                return Some((index, symbol.definition));
            }
            symbol
                .references
                .iter()
                .copied()
                .find(|span| span_contains(*span, byte_offset))
                .map(|span| (index, span))
        })
}

fn rewrite_symbol_occurrences(
    source: &str,
    symbol: &LexicalSymbol,
    new_name: &str,
) -> Result<(String, Vec<SpanReplacement>), String> {
    let mut spans = std::iter::once(symbol.definition)
        .chain(symbol.references.iter().copied())
        .collect::<Vec<_>>();
    spans.sort_by_key(|span| (span.start_byte, span.end_byte));
    spans.dedup();

    let removed_bytes = spans.iter().try_fold(0_usize, |total, span| {
        span.end_byte
            .checked_sub(span.start_byte)
            .and_then(|width| total.checked_add(width))
    });
    let replacement_bytes = new_name.len().checked_mul(spans.len());
    let rewritten_len = removed_bytes
        .and_then(|removed| source.len().checked_sub(removed))
        .and_then(|retained| replacement_bytes.and_then(|added| retained.checked_add(added)))
        .ok_or_else(|| "the requested rename exceeds Splash's source-size arithmetic".to_owned())?;
    if rewritten_len > DEFAULT_MAX_SOURCE_BYTES {
        return Err(format!(
            "the renamed document would exceed Splash's {DEFAULT_MAX_SOURCE_BYTES}-byte source limit"
        ));
    }

    let mut rewritten = String::with_capacity(rewritten_len);
    let mut replacements = Vec::with_capacity(spans.len());
    let mut cursor = 0_usize;
    for span in spans {
        if span.start_byte < cursor || span.end_byte < span.start_byte {
            return Err("the lexical index contains overlapping rename occurrences".to_owned());
        }
        let prefix = source
            .get(cursor..span.start_byte)
            .ok_or_else(|| "the lexical index contains an invalid source span".to_owned())?;
        let occurrence = source
            .get(span.start_byte..span.end_byte)
            .ok_or_else(|| "the lexical index contains an invalid source span".to_owned())?;
        if occurrence != symbol.name {
            return Err("the lexical index occurrence does not match its symbol name".to_owned());
        }
        rewritten.push_str(prefix);
        let replacement_start = rewritten.len();
        rewritten.push_str(new_name);
        replacements.push(SpanReplacement {
            original: span,
            replacement: SourceSpan {
                start_byte: replacement_start,
                end_byte: rewritten.len(),
            },
        });
        cursor = span.end_byte;
    }
    rewritten.push_str(
        source
            .get(cursor..)
            .ok_or_else(|| "the lexical index contains an invalid source span".to_owned())?,
    );
    if rewritten.len() != rewritten_len {
        return Err("the renamed document did not match its bounded size calculation".to_owned());
    }
    Ok((rewritten, replacements))
}

fn remap_lexical_report(
    report: &LexicalSymbolReport,
    renamed_symbol_index: usize,
    new_name: &str,
    replacements: &[SpanReplacement],
) -> Result<LexicalSymbolReport, String> {
    let mut expected = report.clone();
    let symbol = expected
        .symbols
        .get_mut(renamed_symbol_index)
        .ok_or_else(|| "the rename target is absent from the lexical index".to_owned())?;
    symbol.name = new_name.to_owned();

    for symbol in &mut expected.symbols {
        symbol.definition = remap_source_span(symbol.definition, replacements)?;
        for reference in &mut symbol.references {
            *reference = remap_source_span(*reference, replacements)?;
        }
        symbol.visibility_start_byte =
            remap_source_offset(symbol.visibility_start_byte, replacements)?;
        symbol.visibility_end_byte = remap_source_offset(symbol.visibility_end_byte, replacements)?;
    }
    Ok(expected)
}

fn remap_source_offset(offset: usize, replacements: &[SpanReplacement]) -> Result<usize, String> {
    let mut removed_before = 0_usize;
    let mut added_before = 0_usize;
    for replacement in replacements {
        if offset < replacement.original.start_byte {
            continue;
        }
        if offset == replacement.original.start_byte {
            return Ok(replacement.replacement.start_byte);
        }
        if offset < replacement.original.end_byte {
            return Err("a lexical visibility boundary falls inside a rename edit".to_owned());
        }

        let original_width = replacement
            .original
            .end_byte
            .checked_sub(replacement.original.start_byte)
            .ok_or_else(|| "rename offset remapping underflowed".to_owned())?;
        let replacement_width = replacement
            .replacement
            .end_byte
            .checked_sub(replacement.replacement.start_byte)
            .ok_or_else(|| "rename offset remapping underflowed".to_owned())?;
        removed_before = removed_before
            .checked_add(original_width)
            .ok_or_else(|| "rename offset remapping overflowed".to_owned())?;
        added_before = added_before
            .checked_add(replacement_width)
            .ok_or_else(|| "rename offset remapping overflowed".to_owned())?;
        if offset == replacement.original.end_byte {
            return Ok(replacement.replacement.end_byte);
        }
    }

    offset
        .checked_sub(removed_before)
        .and_then(|value| value.checked_add(added_before))
        .ok_or_else(|| "rename offset remapping overflowed".to_owned())
}

fn remap_source_span(
    span: SourceSpan,
    replacements: &[SpanReplacement],
) -> Result<SourceSpan, String> {
    let mut removed_before = 0_usize;
    let mut added_before = 0_usize;
    for replacement in replacements {
        if replacement.original == span {
            return Ok(replacement.replacement);
        }
        if replacement.original.end_byte <= span.start_byte {
            let original_width = replacement
                .original
                .end_byte
                .checked_sub(replacement.original.start_byte)
                .ok_or_else(|| "rename span remapping underflowed".to_owned())?;
            let replacement_width = replacement
                .replacement
                .end_byte
                .checked_sub(replacement.replacement.start_byte)
                .ok_or_else(|| "rename span remapping underflowed".to_owned())?;
            removed_before = removed_before
                .checked_add(original_width)
                .ok_or_else(|| "rename span remapping overflowed".to_owned())?;
            added_before = added_before
                .checked_add(replacement_width)
                .ok_or_else(|| "rename span remapping overflowed".to_owned())?;
            continue;
        }
        if replacement.original.start_byte >= span.end_byte {
            continue;
        }
        return Err("a rename edit partially overlaps another lexical occurrence".to_owned());
    }

    let remap_offset = |offset: usize| {
        offset
            .checked_sub(removed_before)
            .and_then(|value| value.checked_add(added_before))
            .ok_or_else(|| "rename span remapping overflowed".to_owned())
    };
    Ok(SourceSpan {
        start_byte: remap_offset(span.start_byte)?,
        end_byte: remap_offset(span.end_byte)?,
    })
}

fn byte_at_position(source: &str, position: Position) -> Option<usize> {
    let mut line = 0_u32;
    let mut line_start = 0_usize;
    let mut offset = 0_usize;
    let bytes = source.as_bytes();

    while offset < bytes.len() {
        let line_end = match bytes[offset] {
            b'\r' | b'\n' => Some(offset),
            _ => None,
        };
        if let Some(line_end) = line_end {
            if line == position.line {
                return byte_at_utf16_column(&source[line_start..line_end], position.character)
                    .map(|column| line_start + column);
            }

            if bytes[offset] == b'\r' && bytes.get(offset + 1) == Some(&b'\n') {
                offset += 2;
            } else {
                offset += 1;
            }
            line = line.saturating_add(1);
            line_start = offset;
            continue;
        }

        offset += source[offset..].chars().next()?.len_utf8();
    }

    (line == position.line)
        .then(|| byte_at_utf16_column(&source[line_start..], position.character))
        .flatten()
        .map(|column| line_start + column)
}

fn byte_at_utf16_column(line: &str, character: u32) -> Option<usize> {
    let mut utf16_column = 0_u32;
    for (byte_offset, value) in line.char_indices() {
        if utf16_column == character {
            return Some(byte_offset);
        }
        utf16_column = utf16_column.checked_add(value.len_utf16() as u32)?;
        if utf16_column > character {
            return None;
        }
    }
    (utf16_column == character).then_some(line.len())
}

fn position_at_byte(source: &str, byte_offset: usize) -> Position {
    let mut line = 0_u32;
    let mut character = 0_u32;
    let mut previous_was_carriage_return = false;

    for value in source[..byte_offset].chars() {
        match value {
            '\r' => {
                line = line.saturating_add(1);
                character = 0;
                previous_was_carriage_return = true;
            }
            '\n' if previous_was_carriage_return => {
                previous_was_carriage_return = false;
            }
            '\n' => {
                line = line.saturating_add(1);
                character = 0;
                previous_was_carriage_return = false;
            }
            _ => {
                character = character.saturating_add(value.len_utf16() as u32);
                previous_was_carriage_return = false;
            }
        }
    }

    Position::new(line, character)
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use lsp_types::{
        notification::{DidChangeConfiguration, Initialized, Notification as LspNotification},
        DidChangeConfigurationParams, FormattingOptions, TextDocumentContentChangeEvent,
        VersionedTextDocumentIdentifier,
    };
    use splash_core::MAX_STATIC_RECORD_ALIASES;

    use super::*;

    fn test_uri() -> Uri {
        Uri::from_str("file:///workspace/example.splash").expect("valid file URI")
    }

    fn document(version: i32, text: &str) -> TextDocumentItem {
        TextDocumentItem::new(test_uri(), "splash".to_owned(), version, text.to_owned())
    }

    fn tool_catalog(value: serde_json::Value) -> ToolCompletionCatalog {
        parse_tool_completion_catalog(&value).expect("tool catalog projection is valid")
    }

    fn module_catalog(value: serde_json::Value) -> ModuleCompletionCatalog {
        parse_module_completion_catalog(&value).expect("module catalog projection is valid")
    }

    fn workflow_data_catalog(value: serde_json::Value) -> WorkflowDataCompletionCatalog {
        parse_workflow_data_completion_catalog(&value)
            .expect("workflow data catalog projection is valid")
    }

    fn workflow_data_step_context_for(
        value: serde_json::Value,
        catalog: &WorkflowDataCompletionCatalog,
    ) -> WorkflowDataStepContext {
        parse_workflow_data_step_context(&value, catalog)
            .expect("workflow data step context projection is valid")
    }

    fn apply_text_edits(source: &str, edits: &[TextEdit]) -> String {
        let mut byte_edits = edits
            .iter()
            .map(|edit| {
                let start = byte_at_position(source, edit.range.start)
                    .expect("edit start is a valid source position");
                let end = byte_at_position(source, edit.range.end)
                    .expect("edit end is a valid source position");
                (start, end, edit.new_text.as_str())
            })
            .collect::<Vec<_>>();
        byte_edits.sort_by_key(|(start, end, _)| (*start, *end));
        for pair in byte_edits.windows(2) {
            assert!(pair[0].1 <= pair[1].0, "rename edits do not overlap");
        }

        let mut edited = source.to_owned();
        for (start, end, replacement) in byte_edits.into_iter().rev() {
            edited.replace_range(start..end, replacement);
        }
        edited
    }

    #[test]
    fn lexical_hover_labels_cover_every_binding_kind() {
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::Import),
            "import binding"
        );
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::Function),
            "function"
        );
        assert_eq!(lexical_symbol_kind_label(LexicalSymbolKind::Let), "binding");
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::Parameter),
            "function parameter"
        );
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::LoopBinding),
            "loop binding"
        );
        assert_eq!(
            lexical_symbol_kind_label(LexicalSymbolKind::LambdaParameter),
            "lambda parameter"
        );
    }

    #[test]
    fn rename_offset_remapping_handles_boundaries_eof_and_unsorted_edits() {
        let replacements = [
            SpanReplacement {
                original: SourceSpan {
                    start_byte: 10,
                    end_byte: 12,
                },
                replacement: SourceSpan {
                    start_byte: 13,
                    end_byte: 14,
                },
            },
            SpanReplacement {
                original: SourceSpan {
                    start_byte: 2,
                    end_byte: 5,
                },
                replacement: SourceSpan {
                    start_byte: 2,
                    end_byte: 8,
                },
            },
        ];

        for (original, remapped) in [(0, 0), (2, 2), (5, 8), (10, 13), (12, 14), (20, 22)] {
            assert_eq!(
                remap_source_offset(original, &replacements).unwrap(),
                remapped
            );
        }
        assert!(remap_source_offset(3, &replacements).is_err());
        assert_eq!(
            remap_source_span(
                SourceSpan {
                    start_byte: 15,
                    end_byte: 17,
                },
                &replacements,
            )
            .unwrap(),
            SourceSpan {
                start_byte: 17,
                end_byte: 19,
            }
        );

        let shorter = [SpanReplacement {
            original: SourceSpan {
                start_byte: 2,
                end_byte: 7,
            },
            replacement: SourceSpan {
                start_byte: 2,
                end_byte: 3,
            },
        }];
        assert_eq!(remap_source_offset(2, &shorter).unwrap(), 2);
        assert_eq!(remap_source_offset(7, &shorter).unwrap(), 3);
        assert_eq!(remap_source_offset(10, &shorter).unwrap(), 6);
    }

    #[test]
    fn reports_syntax_diagnostics_without_executing_source() {
        let mut server = SplashLanguageServer::default();
        let diagnostics = server.open_document(document(1, "var value = 42"));

        assert_eq!(diagnostics.version, Some(1));
        assert!(!diagnostics.diagnostics.is_empty());
        assert_eq!(
            diagnostics.diagnostics[0].source.as_deref(),
            Some(DIAGNOSTIC_SOURCE)
        );
        assert_eq!(
            diagnostics.diagnostics[0].severity,
            Some(DiagnosticSeverity::ERROR)
        );
    }

    #[test]
    fn outlines_top_level_declarations_without_reading_or_executing_source() {
        let source = "let config = {label: \"fn hidden() {}\", nested: {count: 1}}\n\
                      fn greet(name) {\n\
                          let local = name\n\
                          local\n\
                      }\n\
                      let emoji = \"\u{1f642}\"\n\
                      // let ignored = 0\n";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let symbols = server
            .document_symbols(&test_uri())
            .expect("document is open and valid");

        assert_eq!(
            symbols
                .iter()
                .map(|symbol| symbol.name.as_str())
                .collect::<Vec<_>>(),
            ["config", "greet", "emoji"]
        );
        assert_eq!(symbols[0].kind, SymbolKind::VARIABLE);
        assert_eq!(symbols[1].kind, SymbolKind::FUNCTION);
        assert_eq!(symbols[1].selection_range.start, Position::new(1, 3));
        assert_eq!(symbols[1].selection_range.end, Position::new(1, 8));
        assert_eq!(symbols[1].range.start, Position::new(1, 0));
        assert_eq!(symbols[1].range.end, Position::new(4, 1));
        assert_eq!(
            symbols[2].selection_range,
            Range::new(Position::new(5, 4), Position::new(5, 9))
        );
        assert_eq!(
            symbols[2].range,
            Range::new(Position::new(5, 0), Position::new(5, 16))
        );
    }

    #[test]
    fn suppresses_symbols_for_invalid_source_and_normalizes_crlf_positions() {
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, "fn broken("));
        assert!(server
            .document_symbols(&test_uri())
            .expect("invalid source still has an outline response")
            .is_empty());

        server.open_document(document(2, "fn crlf() {\r\n}\r\n"));
        let symbols = server
            .document_symbols(&test_uri())
            .expect("valid CRLF source has an outline response");
        assert_eq!(
            symbols[0].selection_range,
            Range::new(Position::new(0, 3), Position::new(0, 7))
        );
        assert_eq!(
            symbols[0].range,
            Range::new(Position::new(0, 0), Position::new(1, 1))
        );

        assert_eq!(
            document_end_position("let value = 1\r\n"),
            Position::new(1, 0)
        );
    }

    #[test]
    fn resolves_same_document_lexical_editor_features() {
        let source = "let marker = \"\u{1f642}\"\r\n\
                      fn echo(value) {\r\n\
                          let local = value\r\n\
                          local + value\r\n\
                      }\r\n\
                      echo(marker)";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let local_reference = source.rfind("local").expect("local reference exists");
        let definition = server
            .definition(&test_uri(), position_at_byte(source, local_reference))
            .expect("symbol index succeeds")
            .expect("local reference resolves");
        let local_definition = source.find("local").expect("local definition exists");
        assert_eq!(
            definition.range,
            Range::new(
                position_at_byte(source, local_definition),
                position_at_byte(source, local_definition + "local".len()),
            )
        );
        assert_eq!(
            server
                .definition(&test_uri(), position_at_byte(source, local_definition))
                .expect("symbol index succeeds")
                .expect("a definition resolves to itself"),
            definition
        );

        let hover = server
            .hover(&test_uri(), position_at_byte(source, local_reference))
            .expect("hover index succeeds")
            .expect("local reference has hover information");
        assert_eq!(
            hover.range,
            Some(Range::new(
                position_at_byte(source, local_reference),
                position_at_byte(source, local_reference + "local".len()),
            ))
        );
        assert_eq!(
            hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: "**binding** `local`".to_owned(),
            })
        );

        let highlights = server
            .document_highlights(&test_uri(), position_at_byte(source, local_reference))
            .expect("highlight index succeeds");
        assert_eq!(highlights.len(), 2);
        assert_eq!(
            highlights
                .iter()
                .map(|highlight| highlight.kind)
                .collect::<Vec<_>>(),
            [
                Some(DocumentHighlightKind::TEXT),
                Some(DocumentHighlightKind::TEXT),
            ]
        );
        assert_eq!(
            highlights[0].range,
            Range::new(
                position_at_byte(source, local_definition),
                position_at_byte(source, local_definition + "local".len()),
            )
        );
        assert_eq!(
            highlights[1].range,
            hover.range.expect("hover range exists")
        );

        let value_reference = source.rfind("value").expect("value reference exists");
        let without_declaration = server
            .references(
                &test_uri(),
                position_at_byte(source, value_reference),
                false,
            )
            .expect("reference index succeeds");
        assert_eq!(without_declaration.len(), 2);
        let with_declaration = server
            .references(&test_uri(), position_at_byte(source, value_reference), true)
            .expect("reference index succeeds");
        assert_eq!(with_declaration.len(), 3);
        assert_eq!(
            with_declaration[0].range,
            Range::new(Position::new(1, 8), Position::new(1, 13))
        );
    }

    #[test]
    fn prepares_and_applies_versioned_semantics_preserving_renames() {
        let source = "let value = 1\r\n\
                      fn read() {\r\n\
                          \"\u{1f642}\" + value\r\n\
                      }\r\n\
                      read() + value";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(7, source));

        let unicode_reference = source
            .find("\"\u{1f642}\" + value")
            .expect("Unicode reference line exists")
            + "\"\u{1f642}\" + ".len();
        let reference_end = unicode_reference + "value".len();
        assert_eq!(
            position_at_byte(source, unicode_reference),
            Position::new(2, 7)
        );
        let prepared = server
            .prepare_rename(&test_uri(), position_at_byte(source, reference_end))
            .expect("prepare rename succeeds")
            .expect("cursor at the identifier end remains renameable");
        assert_eq!(
            prepared,
            PrepareRenameResponse::RangeWithPlaceholder {
                range: Range::new(Position::new(2, 7), Position::new(2, 12)),
                placeholder: "value".to_owned(),
            }
        );
        let final_reference = source.rfind("value").expect("final reference exists");
        let prepared_at_eof = server
            .prepare_rename(&test_uri(), position_at_byte(source, source.len()))
            .expect("prepare at end of file succeeds")
            .expect("the final identifier remains renameable at its end");
        assert_eq!(
            prepared_at_eof,
            PrepareRenameResponse::RangeWithPlaceholder {
                range: Range::new(
                    position_at_byte(source, final_reference),
                    position_at_byte(source, source.len()),
                ),
                placeholder: "value".to_owned(),
            }
        );

        let rename = server
            .rename(
                &test_uri(),
                position_at_byte(source, reference_end),
                "renamed",
            )
            .expect("rename analysis succeeds")
            .expect("the lexical reference is renameable");
        assert_eq!(rename.uri, test_uri());
        assert_eq!(rename.version, 7);
        assert_eq!(rename.edits.len(), 3);
        assert!(rename.edits.iter().all(|edit| edit.new_text == "renamed"));
        assert_eq!(
            rename.edits[1].range,
            Range::new(Position::new(2, 7), Position::new(2, 12))
        );
        assert_eq!(
            apply_text_edits(source, &rename.edits),
            "let renamed = 1\r\nfn read() {\r\n\"\u{1f642}\" + renamed\r\n}\r\nread() + renamed"
        );

        let shortened = server
            .rename(
                &test_uri(),
                position_at_byte(source, unicode_reference),
                "v",
            )
            .expect("shortening rename analysis succeeds")
            .expect("the lexical reference is renameable");
        assert_eq!(
            apply_text_edits(source, &shortened.edits),
            "let v = 1\r\nfn read() {\r\n\"\u{1f642}\" + v\r\n}\r\nread() + v"
        );

        let function_reference = source.rfind("read").expect("function reference exists");
        let function_rename = server
            .rename(
                &test_uri(),
                position_at_byte(source, function_reference),
                "read_value",
            )
            .expect("function rename analysis succeeds")
            .expect("function reference is renameable");
        assert_eq!(function_rename.edits.len(), 2);

        assert_eq!(
            server
                .rename(
                    &test_uri(),
                    position_at_byte(source, unicode_reference),
                    "value",
                )
                .expect("an identical rename succeeds"),
            None
        );
    }

    #[test]
    fn completes_visible_lexical_bindings_with_exact_unfiltered_edits() {
        let source = "use mod.std.assert\n\
                      let apple = 1\n\
                      let apricot = 2\n\
                      fn choose(apple) {\n\
                          let local = \"🙂\" + apple\n\
                          ap\n\
                      }\n\
                      apple";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));
        let site_start = source.find("\nap\n").unwrap() + 1;
        let expected_range = Range::new(
            position_at_byte(source, site_start),
            position_at_byte(source, site_start + 2),
        );

        for cursor in [site_start, site_start + 2] {
            let completion = server
                .completion(&test_uri(), position_at_byte(source, cursor))
                .unwrap();
            assert!(!completion.is_incomplete);
            assert_eq!(
                completion
                    .items
                    .iter()
                    .map(|item| item.label.as_str())
                    .collect::<Vec<_>>(),
                ["apple", "apricot", "assert", "choose", "local"]
            );
            assert!(completion.items.iter().all(|item| {
                matches!(
                    item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                        if range == expected_range
                )
            }));
        }

        let assert_item = server
            .completion(&test_uri(), position_at_byte(source, site_start + 1))
            .unwrap()
            .items
            .into_iter()
            .find(|item| item.label == "assert")
            .unwrap();
        assert_eq!(assert_item.kind, Some(CompletionItemKind::MODULE));
        let choose_item = server
            .completion(&test_uri(), position_at_byte(source, site_start + 1))
            .unwrap()
            .items
            .into_iter()
            .find(|item| item.label == "choose")
            .unwrap();
        assert_eq!(choose_item.kind, Some(CompletionItemKind::FUNCTION));

        let final_site = source.rfind("apple").unwrap();
        let outside = server
            .completion(&test_uri(), position_at_byte(source, final_site + 1))
            .unwrap();
        assert!(outside.items.iter().all(|item| item.label != "local"));
        assert_eq!(
            outside
                .items
                .iter()
                .filter(|item| item.label == "apple")
                .count(),
            1
        );
    }

    #[test]
    fn completion_handles_incomplete_source_and_rejects_invalid_utf16_positions() {
        let source = "let marker = \"🙂\"\nlet alpha = 1\nal(";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let completion = server.completion(&test_uri(), Position::new(2, 2)).unwrap();
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "marker"]
        );
        assert!(!completion.is_incomplete);

        let mid_surrogate = server
            .completion(&test_uri(), Position::new(0, 15))
            .unwrap();
        assert!(mid_surrogate.items.is_empty());
        assert!(!mid_surrogate.is_incomplete);
        assert!(server
            .completion(&test_uri(), Position::new(99, 0))
            .unwrap()
            .items
            .is_empty());
    }

    #[test]
    fn completes_exact_visible_mod_tool_members_with_replacement_edits() {
        let source = "use mod.tool\nlet output = tool.";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));
        let member_start = source.len();
        let expected_empty_range = Range::new(
            position_at_byte(source, member_start),
            position_at_byte(source, member_start),
        );

        let completion = server
            .completion(&test_uri(), position_at_byte(source, member_start))
            .unwrap();
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["call", "call_json", "start", "start_json"]
        );
        assert!(completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::METHOD)
                && item.detail.as_deref() == Some("mod.tool method; host capability required")
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                        if *range == expected_empty_range
                )
        }));

        let partial_source = "use mod.tool\nlet output = tool.ca";
        let mut partial_server = SplashLanguageServer::default();
        partial_server.open_document(document(1, partial_source));
        let partial_start = partial_source.rfind("ca").unwrap();
        let partial_end = partial_source.len();
        let expected_partial_range = Range::new(
            position_at_byte(partial_source, partial_start),
            position_at_byte(partial_source, partial_end),
        );

        let partial = partial_server
            .completion(&test_uri(), position_at_byte(partial_source, partial_end))
            .unwrap();
        assert_eq!(partial.items.len(), 4);
        assert!(partial.items.iter().all(|item| {
            matches!(
                &item.text_edit,
                Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                    if *range == expected_partial_range
            )
        }));
    }

    #[test]
    fn completes_fixed_standard_math_members_without_host_metadata() {
        let source = "use mod.std.math\nlet output = math.";
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.std.math.untrusted",
                    "description": "Must not extend the fixed core module."
                }
            ])),
        );
        server.open_document(document(1, source));
        let member_start = source.len();
        let expected_empty_range = Range::new(
            position_at_byte(source, member_start),
            position_at_byte(source, member_start),
        );

        let completion = server
            .completion(&test_uri(), position_at_byte(source, member_start))
            .expect("core math completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            [
                "abs", "atan2", "ceil", "clamp", "cos", "e", "exp", "floor", "ln", "log10", "max",
                "min", "pi", "pow", "round", "sin", "sqrt", "tan",
            ]
        );
        assert!(completion.items.iter().all(|item| {
            matches!(
                &item.text_edit,
                Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_empty_range
            )
        }));

        let sqrt = completion
            .items
            .iter()
            .find(|item| item.label == "sqrt")
            .expect("sqrt is a fixed core helper");
        assert_eq!(sqrt.kind, Some(CompletionItemKind::FUNCTION));
        assert_eq!(
            sqrt.detail.as_deref(),
            Some("mod.std.math function; effect-free scalar helper")
        );
        assert_eq!(
            sqrt.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "math.sqrt(value) -> number\n\nReturns a scalar square root.\n\nEffect-free Splash core helper; it does not access the host or grant authority.".to_owned(),
            }))
        );

        let pi = completion
            .items
            .iter()
            .find(|item| item.label == "pi")
            .expect("pi is a fixed core constant");
        assert_eq!(pi.kind, Some(CompletionItemKind::CONSTANT));
        assert_eq!(
            pi.detail.as_deref(),
            Some("mod.std.math constant; effect-free scalar value")
        );

        let partial_source = "use mod.std.math\nlet output = math.cl";
        let mut partial_server = SplashLanguageServer::default();
        partial_server.open_document(document(1, partial_source));
        let partial_start = partial_source.rfind("cl").expect("partial member exists");
        let partial_end = partial_source.len();
        let expected_partial_range = Range::new(
            position_at_byte(partial_source, partial_start),
            position_at_byte(partial_source, partial_end),
        );
        let partial = partial_server
            .completion(&test_uri(), position_at_byte(partial_source, partial_end))
            .expect("partial core math completion succeeds");
        assert_eq!(partial.items.len(), 18);
        assert!(partial.items.iter().all(|item| {
            matches!(
                &item.text_edit,
                Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_partial_range
            )
        }));
    }

    #[test]
    fn completes_fixed_standard_json_members_without_host_metadata() {
        let source = "use mod.std.json\nlet parsed = json.";
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.std.json.untrusted",
                    "description": "Must not extend the fixed core module."
                }
            ])),
        );
        server.open_document(document(1, source));
        let member_start = source.len();
        let expected_empty_range = Range::new(
            position_at_byte(source, member_start),
            position_at_byte(source, member_start),
        );

        let completion = server
            .completion(&test_uri(), position_at_byte(source, member_start))
            .expect("core JSON completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["parse", "stringify"]
        );
        assert!(completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::FUNCTION)
                && item.detail.as_deref()
                    == Some("mod.std.json function; bounded core data helper")
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_empty_range
                )
        }));
        let parse = completion
            .items
            .iter()
            .find(|item| item.label == "parse")
            .expect("parse is a fixed core helper");
        assert_eq!(
            parse.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "json.parse(document) -> JSON value\n\nParses strict JSON from a string or UTF-8 byte array through Splash's configured byte and nesting limits.\n\nBounded Splash core data helper; it does not access the host or grant authority.".to_owned(),
            }))
        );

        let partial_source = "use mod.std.json\nlet parsed = json.st";
        let mut partial_server = SplashLanguageServer::default();
        partial_server.open_document(document(1, partial_source));
        let partial_start = partial_source.rfind("st").expect("partial member exists");
        let partial_end = partial_source.len();
        let expected_partial_range = Range::new(
            position_at_byte(partial_source, partial_start),
            position_at_byte(partial_source, partial_end),
        );
        let partial = partial_server
            .completion(&test_uri(), position_at_byte(partial_source, partial_end))
            .expect("partial core JSON completion succeeds");
        assert_eq!(partial.items.len(), 2);
        assert!(partial.items.iter().all(|item| {
            matches!(
                &item.text_edit,
                Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_partial_range
            )
        }));
    }

    #[test]
    fn presents_fixed_standard_json_hover_and_signature_help_without_authority() {
        let source = concat!(
            "use mod.std.json\n",
            "let parsed = json.parse(\"{\\\"answer\\\":42}\")\n",
            "json.stringify(parsed)"
        );
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let parse_start = source.find("json.parse").expect("parse member exists") + "json.".len();
        let parse_hover = server
            .hover(&test_uri(), position_at_byte(source, parse_start + 1))
            .expect("core JSON parse hover succeeds")
            .expect("parse has fixed hover metadata");
        assert_eq!(
            parse_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "json.parse(document) -> JSON value\n\nParses strict JSON from a string or UTF-8 byte array through Splash's configured byte and nesting limits.\n\nBounded Splash core data helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let stringify_start = source.find("stringify").expect("stringify member exists");
        let stringify_hover = server
            .hover(&test_uri(), position_at_byte(source, stringify_start + 1))
            .expect("core JSON stringify hover succeeds")
            .expect("stringify has fixed hover metadata");
        assert_eq!(
            stringify_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "json.stringify(value) -> string\n\nSerializes a JSON-safe value through Splash's configured byte, nesting, and cycle limits.\n\nBounded Splash core data helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let parse_cursor = source.find("answer").expect("JSON document exists") + 1;
        let parse_help = server
            .signature_help(&test_uri(), position_at_byte(source, parse_cursor))
            .expect("core JSON parse signature help succeeds")
            .expect("parse has a fixed signature");
        assert_eq!(parse_help.signatures.len(), 1);
        assert_eq!(
            parse_help.signatures[0].label,
            "json.parse(document) -> JSON value"
        );
        assert_eq!(parse_help.active_signature, Some(0));
        assert_eq!(parse_help.active_parameter, Some(0));
        assert_eq!(
            parse_help.signatures[0].parameters,
            Some(vec![ParameterInformation {
                label: ParameterLabel::Simple("document".to_owned()),
                documentation: None,
            }])
        );

        let stringify_cursor = source.rfind("parsed").expect("JSON value exists") + 1;
        let stringify_help = server
            .signature_help(&test_uri(), position_at_byte(source, stringify_cursor))
            .expect("core JSON stringify signature help succeeds")
            .expect("stringify has a fixed signature");
        assert_eq!(
            stringify_help.signatures[0].label,
            "json.stringify(value) -> string"
        );
        assert_eq!(stringify_help.active_parameter, Some(0));

        let hostile_catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.std.json.untrusted",
                "description": "Must not extend the fixed core module.",
                "callMode": "synchronous",
                "callShape": "single_json"
            }
        ]));
        let hostile_source = "use mod.std.json\njson.untrusted({})";
        let mut hostile_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            hostile_catalog,
        );
        hostile_server.open_document(document(1, hostile_source));
        let untrusted_start = hostile_source.find("untrusted").expect("member exists");
        assert!(hostile_server
            .hover(
                &test_uri(),
                position_at_byte(hostile_source, untrusted_start + 1),
            )
            .expect("fixed JSON hover request succeeds")
            .is_none());
        let argument = hostile_source.find("{}").expect("call input exists") + 1;
        assert!(hostile_server
            .signature_help(&test_uri(), position_at_byte(hostile_source, argument))
            .expect("fixed JSON signature request succeeds")
            .is_none());

        for source in [
            "use mod.custom.json\njson.",
            "use mod.std.json\nlet json = 1\njson.",
            "use mod.std.json\nlet alias = json\nalias.",
            "use mod.std.json\njson.parse.",
            "use mod.std.json\nlet note = \"json.\"",
            "use mod.std.json\n// json.",
        ] {
            let mut server = SplashLanguageServer::default();
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .expect("completion request succeeds");
            assert!(
                completion.items.is_empty(),
                "unexpected fixed JSON completion for {source:?}"
            );
        }
    }

    #[test]
    fn completes_fixed_standard_array_members_without_host_metadata() {
        let source = "use mod.std.array\nlet selected = array.";
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.std.array.untrusted",
                    "description": "Must not extend the fixed core module."
                }
            ])),
        );
        server.open_document(document(1, source));
        let member_start = source.len();
        let expected_empty_range = Range::new(
            position_at_byte(source, member_start),
            position_at_byte(source, member_start),
        );

        let completion = server
            .completion(&test_uri(), position_at_byte(source, member_start))
            .expect("core array completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            [
                "concat",
                "flatten",
                "get",
                "has_index",
                "len",
                "push",
                "reverse",
                "slice"
            ]
        );
        assert!(completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::FUNCTION)
                && item.detail.as_deref()
                    == Some("mod.std.array function; bounded core array helper")
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_empty_range
                )
        }));
        let slice = completion
            .items
            .iter()
            .find(|item| item.label == "slice")
            .expect("slice is a fixed core helper");
        assert_eq!(
            slice.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "array.slice(value, start, end) -> array\n\nReturns a shallow copy of the half-open [start, end) range.\n\nBounded Splash core array helper; it does not access the host or grant authority.".to_owned(),
            }))
        );

        let partial_source = "use mod.std.array\nlet selected = array.re";
        let mut partial_server = SplashLanguageServer::default();
        partial_server.open_document(document(1, partial_source));
        let partial_start = partial_source.rfind("re").expect("partial member exists");
        let partial_end = partial_source.len();
        let expected_partial_range = Range::new(
            position_at_byte(partial_source, partial_start),
            position_at_byte(partial_source, partial_end),
        );
        let partial = partial_server
            .completion(&test_uri(), position_at_byte(partial_source, partial_end))
            .expect("partial core array completion succeeds");
        assert_eq!(partial.items.len(), 8);
        assert!(partial.items.iter().all(|item| {
            matches!(
                &item.text_edit,
                Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_partial_range
            )
        }));
    }

    #[test]
    fn presents_fixed_standard_array_hover_and_signature_help_without_authority() {
        let source = concat!(
            "use mod.std.array\n",
            "let selected = array.slice([1, 2, 3], 1, 3)\n",
            "let first = array.get(selected, 0, -1)\n",
            "array.has_index(selected, 1)\n",
            "let flattened = array.flatten([selected, [4]])\n",
            "array.reverse(selected)\n",
            "let collected = []\n",
            "array.push(collected, 4)"
        );
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let slice_start = source.find("array.slice").expect("slice member exists") + "array.".len();
        let slice_hover = server
            .hover(&test_uri(), position_at_byte(source, slice_start + 1))
            .expect("core array slice hover succeeds")
            .expect("slice has fixed hover metadata");
        assert_eq!(
            slice_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "array.slice(value, start, end) -> array\n\nReturns a shallow copy of the half-open [start, end) range.\n\nBounded Splash core array helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let get_start = source.find("array.get").expect("get member exists") + "array.".len();
        let get_hover = server
            .hover(&test_uri(), position_at_byte(source, get_start + 1))
            .expect("core array get hover succeeds")
            .expect("get has fixed hover metadata");
        assert_eq!(
            get_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "array.get(value, index, fallback) -> value\n\nReturns an indexed item or the fallback without traversing the array.\n\nBounded Splash core array helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let has_index_start = source
            .find("array.has_index")
            .expect("has_index member exists")
            + "array.".len();
        let has_index_hover = server
            .hover(&test_uri(), position_at_byte(source, has_index_start + 1))
            .expect("core array has_index hover succeeds")
            .expect("has_index has fixed hover metadata");
        assert_eq!(
            has_index_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "array.has_index(value, index) -> boolean\n\nTests whether a non-negative index is present without traversing the array.\n\nBounded Splash core array helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let reverse_start = source.find("reverse").expect("reverse member exists");
        let reverse_hover = server
            .hover(&test_uri(), position_at_byte(source, reverse_start + 1))
            .expect("core array reverse hover succeeds")
            .expect("reverse has fixed hover metadata");
        assert_eq!(
            reverse_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "array.reverse(value) -> array\n\nReturns a shallow reversed copy of an array.\n\nBounded Splash core array helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let slice_cursor = source.find(", 3)").expect("slice end exists") + 2;
        let slice_help = server
            .signature_help(&test_uri(), position_at_byte(source, slice_cursor))
            .expect("core array slice signature help succeeds")
            .expect("slice has a fixed signature");
        assert_eq!(slice_help.signatures.len(), 1);
        assert_eq!(
            slice_help.signatures[0].label,
            "array.slice(value, start, end) -> array"
        );
        assert_eq!(slice_help.active_signature, Some(0));
        assert_eq!(slice_help.active_parameter, Some(2));
        assert_eq!(
            slice_help.signatures[0].parameters,
            Some(vec![
                ParameterInformation {
                    label: ParameterLabel::Simple("value".to_owned()),
                    documentation: None,
                },
                ParameterInformation {
                    label: ParameterLabel::Simple("start".to_owned()),
                    documentation: None,
                },
                ParameterInformation {
                    label: ParameterLabel::Simple("end".to_owned()),
                    documentation: None,
                },
            ])
        );

        let get_cursor = source
            .find("array.get(selected, 0, -1)")
            .expect("get call exists")
            + "array.get(selected, 0, ".len()
            + 1;
        let get_help = server
            .signature_help(&test_uri(), position_at_byte(source, get_cursor))
            .expect("core array get signature help succeeds")
            .expect("get has a fixed signature");
        assert_eq!(
            get_help.signatures[0].label,
            "array.get(value, index, fallback) -> value"
        );
        assert_eq!(get_help.active_parameter, Some(2));

        let has_index_cursor = source
            .find("array.has_index(selected, 1)")
            .expect("has_index call exists")
            + "array.has_index(selected, ".len()
            + 1;
        let has_index_help = server
            .signature_help(&test_uri(), position_at_byte(source, has_index_cursor))
            .expect("core array has_index signature help succeeds")
            .expect("has_index has a fixed signature");
        assert_eq!(
            has_index_help.signatures[0].label,
            "array.has_index(value, index) -> boolean"
        );
        assert_eq!(has_index_help.active_parameter, Some(1));

        let flatten_start =
            source.find("array.flatten").expect("flatten member exists") + "array.".len();
        let flatten_hover = server
            .hover(&test_uri(), position_at_byte(source, flatten_start + 1))
            .expect("core array flatten hover succeeds")
            .expect("flatten has fixed hover metadata");
        assert_eq!(
            flatten_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "array.flatten(value) -> array\n\nFlattens one level when every outer item is an array, with a 4,096-item total limit.\n\nBounded Splash core array helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let flatten_cursor = source
            .find("array.flatten([selected, [4]])")
            .expect("flatten call exists")
            + "array.flatten([".len()
            + 1;
        let flatten_help = server
            .signature_help(&test_uri(), position_at_byte(source, flatten_cursor))
            .expect("core array flatten signature help succeeds")
            .expect("flatten has a fixed signature");
        assert_eq!(
            flatten_help.signatures[0].label,
            "array.flatten(value) -> array"
        );
        assert_eq!(flatten_help.active_parameter, Some(0));

        let reverse_cursor = source
            .find("array.reverse(selected)")
            .expect("reverse input exists")
            + "array.reverse(".len()
            + 1;
        let reverse_help = server
            .signature_help(&test_uri(), position_at_byte(source, reverse_cursor))
            .expect("core array reverse signature help succeeds")
            .expect("reverse has a fixed signature");
        assert_eq!(
            reverse_help.signatures[0].label,
            "array.reverse(value) -> array"
        );
        assert_eq!(reverse_help.active_parameter, Some(0));

        let push_start = source.find("array.push").expect("push member exists") + "array.".len();
        let push_hover = server
            .hover(&test_uri(), position_at_byte(source, push_start + 1))
            .expect("core array push hover succeeds")
            .expect("push has fixed hover metadata");
        assert_eq!(
            push_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "array.push(value, item) -> nil\n\nAppends one item in place and returns nil.\n\nBounded Splash core array helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let push_cursor = source
            .find("array.push(collected, 4)")
            .expect("push call exists")
            + "array.push(collected, ".len()
            + 1;
        let push_help = server
            .signature_help(&test_uri(), position_at_byte(source, push_cursor))
            .expect("core array push signature help succeeds")
            .expect("push has a fixed signature");
        assert_eq!(
            push_help.signatures[0].label,
            "array.push(value, item) -> nil"
        );
        assert_eq!(push_help.active_parameter, Some(1));

        let hostile_catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.std.array.untrusted",
                "description": "Must not extend the fixed core module.",
                "callMode": "synchronous",
                "callShape": "single_json"
            }
        ]));
        let hostile_source = "use mod.std.array\narray.untrusted({})";
        let mut hostile_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            hostile_catalog,
        );
        hostile_server.open_document(document(1, hostile_source));
        let untrusted_start = hostile_source.find("untrusted").expect("member exists");
        assert!(hostile_server
            .hover(
                &test_uri(),
                position_at_byte(hostile_source, untrusted_start + 1),
            )
            .expect("fixed array hover request succeeds")
            .is_none());
        let argument = hostile_source.find("{}").expect("call input exists") + 1;
        assert!(hostile_server
            .signature_help(&test_uri(), position_at_byte(hostile_source, argument))
            .expect("fixed array signature request succeeds")
            .is_none());

        for source in [
            "use mod.custom.array\narray.",
            "use mod.std.array\nlet array = 1\narray.",
            "use mod.std.array\nlet alias = array\nalias.",
            "use mod.std.array\narray.slice.",
            "use mod.std.array\nlet note = \"array.\"",
            "use mod.std.array\n// array.",
        ] {
            let mut server = SplashLanguageServer::default();
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .expect("completion request succeeds");
            assert!(
                completion.items.is_empty(),
                "unexpected fixed array completion for {source:?}"
            );
        }
    }

    #[test]
    fn completes_fixed_standard_object_members_without_host_metadata() {
        let source = "use mod.std.object\nlet selected = object.";
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.std.object.untrusted",
                    "description": "Must not extend the fixed core module."
                }
            ])),
        );
        server.open_document(document(1, source));
        let member_start = source.len();
        let expected_empty_range = Range::new(
            position_at_byte(source, member_start),
            position_at_byte(source, member_start),
        );

        let completion = server
            .completion(&test_uri(), position_at_byte(source, member_start))
            .expect("core object completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            [
                "entries",
                "from_entries",
                "get",
                "has",
                "keys",
                "len",
                "merge",
                "pick",
                "values"
            ]
        );
        assert!(completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::FUNCTION)
                && item.detail.as_deref()
                    == Some("mod.std.object function; bounded core object helper")
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_empty_range
                )
        }));
        let merge = completion
            .items
            .iter()
            .find(|item| item.label == "merge")
            .expect("merge is a fixed core helper");
        assert_eq!(
            merge.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "object.merge(left, right) -> object\n\nReturns a shallow merge that preserves first field positions and applies right-side values.\n\nBounded Splash core object helper; it does not access the host or grant authority.".to_owned(),
            }))
        );

        let partial_source = "use mod.std.object\nlet selected = object.mer";
        let mut partial_server = SplashLanguageServer::default();
        partial_server.open_document(document(1, partial_source));
        let partial_start = partial_source.rfind("mer").expect("partial member exists");
        let partial_end = partial_source.len();
        let expected_partial_range = Range::new(
            position_at_byte(partial_source, partial_start),
            position_at_byte(partial_source, partial_end),
        );
        let partial = partial_server
            .completion(&test_uri(), position_at_byte(partial_source, partial_end))
            .expect("partial core object completion succeeds");
        assert_eq!(partial.items.len(), 9);
        assert!(partial.items.iter().all(|item| {
            matches!(
                &item.text_edit,
                Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_partial_range
            )
        }));
    }

    #[test]
    fn presents_fixed_standard_object_hover_and_signature_help_without_authority() {
        let source = concat!(
            "use mod.std.object\n",
            "let merged = object.merge({left: 1}, {right: 2})\n",
            "object.from_entries([[\"left\", 1]])\n",
            "object.has(merged, \"left\")\n",
            "object.get(merged, \"missing\", 0)\n",
            "object.pick(merged, [\"left\"])\n",
            "object.keys(merged)\n",
            "object.entries(merged)"
        );
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let merge_start =
            source.find("object.merge").expect("merge member exists") + "object.".len();
        let merge_hover = server
            .hover(&test_uri(), position_at_byte(source, merge_start + 1))
            .expect("core object merge hover succeeds")
            .expect("merge has fixed hover metadata");
        assert_eq!(
            merge_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "object.merge(left, right) -> object\n\nReturns a shallow merge that preserves first field positions and applies right-side values.\n\nBounded Splash core object helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let keys_start = source.rfind("keys").expect("keys member exists");
        let keys_hover = server
            .hover(&test_uri(), position_at_byte(source, keys_start + 1))
            .expect("core object keys hover succeeds")
            .expect("keys has fixed hover metadata");
        assert_eq!(
            keys_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "object.keys(value) -> array\n\nReturns own text field names in stored field order.\n\nBounded Splash core object helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let entries_start = source.rfind("entries").expect("entries member exists");
        let entries_hover = server
            .hover(&test_uri(), position_at_byte(source, entries_start + 1))
            .expect("core object entries hover succeeds")
            .expect("entries has fixed hover metadata");
        assert_eq!(
            entries_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "object.entries(value) -> array\n\nReturns shallow [text key, value] pairs in stored field order.\n\nBounded Splash core object helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let has_start = source.find("object.has").expect("has member exists") + "object.".len();
        let has_hover = server
            .hover(&test_uri(), position_at_byte(source, has_start + 1))
            .expect("core object has hover succeeds")
            .expect("has has fixed hover metadata");
        assert_eq!(
            has_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "object.has(value, key) -> boolean\n\nTests whether an own text field is present, including a nil value.\n\nBounded Splash core object helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let get_start = source.find("object.get").expect("get member exists") + "object.".len();
        let get_hover = server
            .hover(&test_uri(), position_at_byte(source, get_start + 1))
            .expect("core object get hover succeeds")
            .expect("get has fixed hover metadata");
        assert_eq!(
            get_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "object.get(value, key, fallback) -> value\n\nReturns an own text field or the fallback.\n\nBounded Splash core object helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let pick_start = source.find("object.pick").expect("pick member exists") + "object.".len();
        let pick_hover = server
            .hover(&test_uri(), position_at_byte(source, pick_start + 1))
            .expect("core object pick hover succeeds")
            .expect("pick has fixed hover metadata");
        assert_eq!(
            pick_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "object.pick(value, keys) -> object\n\nReturns a shallow record of requested existing own text fields; missing keys are omitted.\n\nBounded Splash core object helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let from_entries_start = source
            .find("object.from_entries")
            .expect("from_entries member exists")
            + "object.".len();
        let from_entries_hover = server
            .hover(
                &test_uri(),
                position_at_byte(source, from_entries_start + 1),
            )
            .expect("core object from_entries hover succeeds")
            .expect("from_entries has fixed hover metadata");
        assert_eq!(
            from_entries_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "object.from_entries(entries) -> object\n\nBuilds a shallow plain record from two-item [text key, value] entries; later duplicates replace values.\n\nBounded Splash core object helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let merge_cursor = source.find("{right").expect("merge right input exists") + 2;
        let merge_help = server
            .signature_help(&test_uri(), position_at_byte(source, merge_cursor))
            .expect("core object merge signature help succeeds")
            .expect("merge has a fixed signature");
        assert_eq!(merge_help.signatures.len(), 1);
        assert_eq!(
            merge_help.signatures[0].label,
            "object.merge(left, right) -> object"
        );
        assert_eq!(merge_help.active_signature, Some(0));
        assert_eq!(merge_help.active_parameter, Some(1));
        assert_eq!(
            merge_help.signatures[0].parameters,
            Some(vec![
                ParameterInformation {
                    label: ParameterLabel::Simple("left".to_owned()),
                    documentation: None,
                },
                ParameterInformation {
                    label: ParameterLabel::Simple("right".to_owned()),
                    documentation: None,
                },
            ])
        );

        let keys_cursor = source
            .find("object.keys(merged)")
            .expect("keys input exists")
            + "object.keys(".len()
            + 1;
        let keys_help = server
            .signature_help(&test_uri(), position_at_byte(source, keys_cursor))
            .expect("core object keys signature help succeeds")
            .expect("keys has a fixed signature");
        assert_eq!(keys_help.signatures[0].label, "object.keys(value) -> array");
        assert_eq!(keys_help.active_parameter, Some(0));

        let entries_cursor = source
            .find("object.entries(merged)")
            .expect("entries input exists")
            + "object.entries(".len()
            + 1;
        let entries_help = server
            .signature_help(&test_uri(), position_at_byte(source, entries_cursor))
            .expect("core object entries signature help succeeds")
            .expect("entries has a fixed signature");
        assert_eq!(
            entries_help.signatures[0].label,
            "object.entries(value) -> array"
        );
        assert_eq!(entries_help.active_parameter, Some(0));

        let has_cursor = source
            .find("object.has(merged, \"left\")")
            .expect("has input exists")
            + "object.has(merged, ".len()
            + 1;
        let has_help = server
            .signature_help(&test_uri(), position_at_byte(source, has_cursor))
            .expect("core object has signature help succeeds")
            .expect("has has a fixed signature");
        assert_eq!(
            has_help.signatures[0].label,
            "object.has(value, key) -> boolean"
        );
        assert_eq!(has_help.active_parameter, Some(1));

        let get_cursor = source
            .find("object.get(merged, \"missing\", 0)")
            .expect("get input exists")
            + "object.get(merged, \"missing\", ".len()
            + 1;
        let get_help = server
            .signature_help(&test_uri(), position_at_byte(source, get_cursor))
            .expect("core object get signature help succeeds")
            .expect("get has a fixed signature");
        assert_eq!(
            get_help.signatures[0].label,
            "object.get(value, key, fallback) -> value"
        );
        assert_eq!(get_help.active_parameter, Some(2));

        let pick_cursor = source
            .find("object.pick(merged, [\"left\"])")
            .expect("pick input exists")
            + "object.pick(merged, ".len()
            + 1;
        let pick_help = server
            .signature_help(&test_uri(), position_at_byte(source, pick_cursor))
            .expect("core object pick signature help succeeds")
            .expect("pick has a fixed signature");
        assert_eq!(
            pick_help.signatures[0].label,
            "object.pick(value, keys) -> object"
        );
        assert_eq!(pick_help.active_parameter, Some(1));

        let from_entries_cursor = source
            .find("object.from_entries([[\"left\", 1]])")
            .expect("from_entries input exists")
            + "object.from_entries(".len()
            + 1;
        let from_entries_help = server
            .signature_help(&test_uri(), position_at_byte(source, from_entries_cursor))
            .expect("core object from_entries signature help succeeds")
            .expect("from_entries has a fixed signature");
        assert_eq!(
            from_entries_help.signatures[0].label,
            "object.from_entries(entries) -> object"
        );
        assert_eq!(from_entries_help.active_parameter, Some(0));

        let hostile_catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.std.object.untrusted",
                "description": "Must not extend the fixed core module.",
                "callMode": "synchronous",
                "callShape": "single_json"
            }
        ]));
        let hostile_source = "use mod.std.object\nobject.untrusted({})";
        let mut hostile_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            hostile_catalog,
        );
        hostile_server.open_document(document(1, hostile_source));
        let untrusted_start = hostile_source.find("untrusted").expect("member exists");
        assert!(hostile_server
            .hover(
                &test_uri(),
                position_at_byte(hostile_source, untrusted_start + 1),
            )
            .expect("fixed object hover request succeeds")
            .is_none());
        let argument = hostile_source.find("{}").expect("call input exists") + 1;
        assert!(hostile_server
            .signature_help(&test_uri(), position_at_byte(hostile_source, argument))
            .expect("fixed object signature request succeeds")
            .is_none());

        for source in [
            "use mod.custom.object\nobject.",
            "use mod.std.object\nlet object = 1\nobject.",
            "use mod.std.object\nlet alias = object\nalias.",
            "use mod.std.object\nobject.merge.",
            "use mod.std.object\nlet note = \"object.\"",
            "use mod.std.object\n// object.",
        ] {
            let mut server = SplashLanguageServer::default();
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .expect("completion request succeeds");
            assert!(
                completion.items.is_empty(),
                "unexpected fixed object completion for {source:?}"
            );
        }
    }

    #[test]
    fn completes_fixed_standard_text_members_without_host_metadata() {
        let source = "use mod.std.text\nlet normalized = text.";
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.std.text.untrusted",
                    "description": "Must not extend the fixed core module."
                }
            ])),
        );
        server.open_document(document(1, source));
        let member_start = source.len();
        let expected_empty_range = Range::new(
            position_at_byte(source, member_start),
            position_at_byte(source, member_start),
        );

        let completion = server
            .completion(&test_uri(), position_at_byte(source, member_start))
            .expect("core text completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            [
                "contains",
                "ends_with",
                "index_of",
                "join",
                "len",
                "lower",
                "replace_all",
                "slice",
                "split",
                "starts_with",
                "trim",
                "upper",
            ]
        );
        assert!(completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::FUNCTION)
                && item.detail.as_deref()
                    == Some("mod.std.text function; bounded core text helper")
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_empty_range
                )
        }));
        let trim = completion
            .items
            .iter()
            .find(|item| item.label == "trim")
            .expect("trim is a fixed core helper");
        assert_eq!(
            trim.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "text.trim(value) -> string\n\nRemoves leading and trailing Unicode whitespace.\n\nBounded Splash core text helper; it does not access the host or grant authority.".to_owned(),
            }))
        );

        let partial_source = "use mod.std.text\nlet normalized = text.re";
        let mut partial_server = SplashLanguageServer::default();
        partial_server.open_document(document(1, partial_source));
        let partial_start = partial_source.rfind("re").expect("partial member exists");
        let partial_end = partial_source.len();
        let expected_partial_range = Range::new(
            position_at_byte(partial_source, partial_start),
            position_at_byte(partial_source, partial_end),
        );
        let partial = partial_server
            .completion(&test_uri(), position_at_byte(partial_source, partial_end))
            .expect("partial core text completion succeeds");
        assert_eq!(partial.items.len(), 12);
        assert!(partial.items.iter().all(|item| {
            matches!(
                &item.text_edit,
                Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_partial_range
            )
        }));
    }

    #[test]
    fn presents_fixed_standard_text_hover_and_signature_help_without_authority() {
        let source = concat!(
            "use mod.std.text\n",
            "let value = text.trim(\"  Splash  \")\n",
            "text.slice(value, 1, 4)\n",
            "text.index_of(value, \"la\")\n",
            "text.replace_all(value, \"S\", \"s\")\n",
            "text.split(\"a,,b,\", \",\")\n",
            "text.join([\"a\", \"\", \"b\", \"\"], \",\")"
        );
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let trim_start = source.find("text.trim").expect("trim member exists") + "text.".len();
        let trim_hover = server
            .hover(&test_uri(), position_at_byte(source, trim_start + 1))
            .expect("core text trim hover succeeds")
            .expect("trim has fixed hover metadata");
        assert_eq!(
            trim_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "text.trim(value) -> string\n\nRemoves leading and trailing Unicode whitespace.\n\nBounded Splash core text helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let replace_start = source.find("replace_all").expect("replace member exists");
        let replace_hover = server
            .hover(&test_uri(), position_at_byte(source, replace_start + 1))
            .expect("core text replace hover succeeds")
            .expect("replace has fixed hover metadata");
        assert_eq!(
            replace_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "text.replace_all(value, from, to) -> string\n\nReplaces every non-overlapping literal substring match.\n\nBounded Splash core text helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let trim_cursor = source.find("Splash").expect("trim input exists") + 1;
        let trim_help = server
            .signature_help(&test_uri(), position_at_byte(source, trim_cursor))
            .expect("core text trim signature help succeeds")
            .expect("trim has a fixed signature");
        assert_eq!(trim_help.signatures.len(), 1);
        assert_eq!(trim_help.signatures[0].label, "text.trim(value) -> string");
        assert_eq!(trim_help.active_signature, Some(0));
        assert_eq!(trim_help.active_parameter, Some(0));
        assert_eq!(
            trim_help.signatures[0].parameters,
            Some(vec![ParameterInformation {
                label: ParameterLabel::Simple("value".to_owned()),
                documentation: None,
            }])
        );

        let slice_start = source.find("text.slice").expect("slice member exists") + "text.".len();
        let slice_hover = server
            .hover(&test_uri(), position_at_byte(source, slice_start + 1))
            .expect("core text slice hover succeeds")
            .expect("slice has fixed hover metadata");
        assert_eq!(
            slice_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "text.slice(value, start, end) -> string\n\nReturns the Unicode-scalar half-open [start, end) slice.\n\nBounded Splash core text helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let index_of_start = source
            .find("text.index_of")
            .expect("index_of member exists")
            + "text.".len();
        let index_of_hover = server
            .hover(&test_uri(), position_at_byte(source, index_of_start + 1))
            .expect("core text index_of hover succeeds")
            .expect("index_of has fixed hover metadata");
        assert_eq!(
            index_of_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "text.index_of(value, needle) -> number\n\nReturns the Unicode-scalar index of a literal match, or -1; an empty needle is 0.\n\nBounded Splash core text helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let slice_cursor = source
            .find("text.slice(value, 1, 4)")
            .expect("slice call exists")
            + "text.slice(value, 1, ".len()
            + 1;
        let slice_help = server
            .signature_help(&test_uri(), position_at_byte(source, slice_cursor))
            .expect("core text slice signature help succeeds")
            .expect("slice has a fixed signature");
        assert_eq!(
            slice_help.signatures[0].label,
            "text.slice(value, start, end) -> string"
        );
        assert_eq!(slice_help.active_parameter, Some(2));

        let index_of_cursor = source
            .find("text.index_of(value, \"la\")")
            .expect("index_of call exists")
            + "text.index_of(value, ".len()
            + 1;
        let index_of_help = server
            .signature_help(&test_uri(), position_at_byte(source, index_of_cursor))
            .expect("core text index_of signature help succeeds")
            .expect("index_of has a fixed signature");
        assert_eq!(
            index_of_help.signatures[0].label,
            "text.index_of(value, needle) -> number"
        );
        assert_eq!(index_of_help.active_parameter, Some(1));

        let replace_cursor = source.rfind("\"s\"").expect("replacement exists") + 1;
        let replace_help = server
            .signature_help(&test_uri(), position_at_byte(source, replace_cursor))
            .expect("core text replace signature help succeeds")
            .expect("replace has a fixed signature");
        assert_eq!(
            replace_help.signatures[0].label,
            "text.replace_all(value, from, to) -> string"
        );
        assert_eq!(replace_help.active_parameter, Some(2));
        assert_eq!(
            replace_help.signatures[0].parameters,
            Some(vec![
                ParameterInformation {
                    label: ParameterLabel::Simple("value".to_owned()),
                    documentation: None,
                },
                ParameterInformation {
                    label: ParameterLabel::Simple("from".to_owned()),
                    documentation: None,
                },
                ParameterInformation {
                    label: ParameterLabel::Simple("to".to_owned()),
                    documentation: None,
                },
            ])
        );

        let split_start = source.find("text.split").expect("split member exists") + "text.".len();
        let split_hover = server
            .hover(&test_uri(), position_at_byte(source, split_start + 1))
            .expect("core text split hover succeeds")
            .expect("split has fixed hover metadata");
        assert_eq!(
            split_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "text.split(value, delimiter) -> array\n\nSplits on a non-empty delimiter using literal matching and preserves empty fields.\n\nBounded Splash core text helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let split_cursor = source
            .find("text.split(\"a,,b,\", \",\")")
            .expect("split call exists")
            + "text.split(\"a,,b,\", ".len()
            + 1;
        let split_help = server
            .signature_help(&test_uri(), position_at_byte(source, split_cursor))
            .expect("core text split signature help succeeds")
            .expect("split has a fixed signature");
        assert_eq!(
            split_help.signatures[0].label,
            "text.split(value, delimiter) -> array"
        );
        assert_eq!(split_help.active_parameter, Some(1));

        let join_start = source.find("text.join").expect("join member exists") + "text.".len();
        let join_hover = server
            .hover(&test_uri(), position_at_byte(source, join_start + 1))
            .expect("core text join hover succeeds")
            .expect("join has fixed hover metadata");
        assert_eq!(
            join_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "text.join(values, separator) -> string\n\nJoins at most 4,096 strings with a string separator.\n\nBounded Splash core text helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let join_cursor = source
            .find("text.join([\"a\", \"\", \"b\", \"\"], \",\")")
            .expect("join call exists")
            + "text.join([\"a\", \"\", \"b\", \"\"], ".len()
            + 1;
        let join_help = server
            .signature_help(&test_uri(), position_at_byte(source, join_cursor))
            .expect("core text join signature help succeeds")
            .expect("join has a fixed signature");
        assert_eq!(
            join_help.signatures[0].label,
            "text.join(values, separator) -> string"
        );
        assert_eq!(join_help.active_parameter, Some(1));

        let hostile_catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.std.text.untrusted",
                "description": "Must not extend the fixed core module.",
                "callMode": "synchronous",
                "callShape": "single_json"
            }
        ]));
        let hostile_source = "use mod.std.text\ntext.untrusted({})";
        let mut hostile_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            hostile_catalog,
        );
        hostile_server.open_document(document(1, hostile_source));
        let untrusted_start = hostile_source.find("untrusted").expect("member exists");
        assert!(hostile_server
            .hover(
                &test_uri(),
                position_at_byte(hostile_source, untrusted_start + 1),
            )
            .expect("fixed text hover request succeeds")
            .is_none());
        let argument = hostile_source.find("{}").expect("call input exists") + 1;
        assert!(hostile_server
            .signature_help(&test_uri(), position_at_byte(hostile_source, argument))
            .expect("fixed text signature request succeeds")
            .is_none());

        for source in [
            "use mod.custom.text\ntext.",
            "use mod.std.text\nlet text = 1\ntext.",
            "use mod.std.text\nlet alias = text\nalias.",
            "use mod.std.text\ntext.trim.",
            "use mod.std.text\nlet note = \"text.\"",
            "use mod.std.text\n// text.",
        ] {
            let mut server = SplashLanguageServer::default();
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .expect("completion request succeeds");
            assert!(
                completion.items.is_empty(),
                "unexpected fixed text completion for {source:?}"
            );
        }
    }

    #[test]
    fn presents_fixed_standard_math_hover_and_signature_help_without_authority() {
        let source = concat!(
            "use mod.std.math\n",
            "let root = math.sqrt(81)\n",
            "let bounded = math.clamp(4, 0, 8)\n",
            "math.pi"
        );
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let sqrt_start = source.find("sqrt").expect("sqrt member exists");
        let sqrt_hover = server
            .hover(&test_uri(), position_at_byte(source, sqrt_start + 1))
            .expect("core math hover succeeds")
            .expect("sqrt has fixed hover metadata");
        assert_eq!(
            sqrt_hover.range,
            Some(Range::new(
                position_at_byte(source, sqrt_start),
                position_at_byte(source, sqrt_start + "sqrt".len()),
            ))
        );
        assert_eq!(
            sqrt_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "math.sqrt(value) -> number\n\nReturns a scalar square root.\n\nEffect-free Splash core helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let pi_start = source.rfind("pi").expect("pi member exists");
        let pi_hover = server
            .hover(&test_uri(), position_at_byte(source, pi_start + 1))
            .expect("core math constant hover succeeds")
            .expect("pi has fixed hover metadata");
        assert_eq!(
            pi_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "math.pi -> number\n\nThe scalar ratio of a circle's circumference to its diameter.\n\nEffect-free Splash core helper; it does not access the host or grant authority.".to_owned(),
            })
        );

        let clamp_cursor = source.find("0, 8").expect("clamp minimum exists") + 1;
        let clamp_help = server
            .signature_help(&test_uri(), position_at_byte(source, clamp_cursor))
            .expect("core math signature help succeeds")
            .expect("clamp has a fixed signature");
        assert_eq!(clamp_help.signatures.len(), 1);
        assert_eq!(
            clamp_help.signatures[0].label,
            "math.clamp(value, minimum, maximum) -> number"
        );
        assert_eq!(clamp_help.active_signature, Some(0));
        assert_eq!(clamp_help.active_parameter, Some(1));
        assert_eq!(
            clamp_help.signatures[0].parameters,
            Some(vec![
                ParameterInformation {
                    label: ParameterLabel::Simple("value".to_owned()),
                    documentation: None,
                },
                ParameterInformation {
                    label: ParameterLabel::Simple("minimum".to_owned()),
                    documentation: None,
                },
                ParameterInformation {
                    label: ParameterLabel::Simple("maximum".to_owned()),
                    documentation: None,
                },
            ])
        );
    }

    #[test]
    fn presents_fixed_standard_assert_hover_and_signature_help_without_authority() {
        let direct_source = "use mod.std.assert\nassert(true)";
        let mut direct_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.std.assert",
                    "description": "Host metadata must not replace core assertions.",
                    "callMode": "deferred",
                    "callShape": "single_json"
                }
            ])),
        );
        direct_server.open_document(document(1, direct_source));
        let direct_assert_start = direct_source.rfind("assert").expect("assert call exists");
        let direct_hover = direct_server
            .hover(
                &test_uri(),
                position_at_byte(direct_source, direct_assert_start + 1),
            )
            .expect("direct assertion hover succeeds")
            .expect("direct assertion has fixed hover metadata");
        assert_eq!(
            direct_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: STANDARD_ASSERT_DOCUMENTATION.to_owned(),
            })
        );

        let direct_argument = direct_source.find("true").expect("condition exists") + 1;
        let direct_signature = direct_server
            .signature_help(
                &test_uri(),
                position_at_byte(direct_source, direct_argument),
            )
            .expect("direct assertion signature help succeeds")
            .expect("direct assertion has a fixed signature");
        assert_eq!(direct_signature.signatures.len(), 1);
        assert_eq!(direct_signature.signatures[0].label, "assert(condition)");
        assert_eq!(direct_signature.active_signature, Some(0));
        assert_eq!(direct_signature.active_parameter, Some(0));
        assert_eq!(
            direct_signature.signatures[0].parameters,
            Some(vec![ParameterInformation {
                label: ParameterLabel::Simple("condition".to_owned()),
                documentation: None,
            }])
        );

        let namespace_source = "use mod.std\nstd.assert(true)";
        let mut namespace_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.std.assert",
                    "description": "Host metadata must not replace core assertions.",
                    "callMode": "deferred",
                    "callShape": "single_json"
                }
            ])),
        );
        namespace_server.open_document(document(1, namespace_source));
        let member_start = namespace_source.rfind("assert").expect("member exists");
        let member_hover = namespace_server
            .hover(
                &test_uri(),
                position_at_byte(namespace_source, member_start + 1),
            )
            .expect("namespace assertion hover succeeds")
            .expect("namespace assertion has fixed hover metadata");
        assert_eq!(
            member_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: STANDARD_ASSERT_DOCUMENTATION.to_owned(),
            })
        );
        let member_argument = namespace_source.find("true").expect("condition exists") + 1;
        let member_signature = namespace_server
            .signature_help(
                &test_uri(),
                position_at_byte(namespace_source, member_argument),
            )
            .expect("namespace assertion signature help succeeds")
            .expect("namespace assertion has a fixed signature");
        assert_eq!(
            member_signature.signatures[0].label,
            "std.assert(condition)"
        );
        let Some(Documentation::MarkupContent(MarkupContent { value, .. })) =
            member_signature.signatures[0].documentation.as_ref()
        else {
            panic!("fixed assertion signature has plain-text documentation");
        };
        assert_eq!(value, &standard_assert_documentation("std.assert"));

        let alias_source = "use mod.std.assert\nlet check = assert\ncheck(true)";
        let mut alias_server = SplashLanguageServer::default();
        alias_server.open_document(document(1, alias_source));
        let alias_argument = alias_source.find("true").expect("condition exists") + 1;
        assert!(alias_server
            .signature_help(&test_uri(), position_at_byte(alias_source, alias_argument))
            .expect("alias assertion signature request succeeds")
            .is_none());

        let shadowed_source = "use mod.std.assert\nlet assert = true\nassert(true)";
        let mut shadowed_server = SplashLanguageServer::default();
        shadowed_server.open_document(document(1, shadowed_source));
        let shadowed_argument = shadowed_source.find("true)").expect("condition exists") + 1;
        assert!(shadowed_server
            .signature_help(
                &test_uri(),
                position_at_byte(shadowed_source, shadowed_argument),
            )
            .expect("shadowed assertion signature request succeeds")
            .is_none());

        let unrelated_source = "use mod.custom.assert\nassert(true)";
        let mut unrelated_server = SplashLanguageServer::default();
        unrelated_server.open_document(document(1, unrelated_source));
        let unrelated_argument = unrelated_source.find("true").expect("condition exists") + 1;
        assert!(unrelated_server
            .signature_help(
                &test_uri(),
                position_at_byte(unrelated_source, unrelated_argument),
            )
            .expect("unrelated assertion signature request succeeds")
            .is_none());

        for source in [
            "use mod.std.assert\nlet note = \"assert(true)\"",
            "use mod.std.assert\n// assert(true)",
        ] {
            let mut server = SplashLanguageServer::default();
            server.open_document(document(1, source));
            let argument = source.find("true").expect("non-code condition exists") + 1;
            assert!(server
                .signature_help(&test_uri(), position_at_byte(source, argument))
                .expect("non-code assertion signature request succeeds")
                .is_none());
        }
    }

    #[test]
    fn refuses_standard_math_projection_outside_exact_visible_imports() {
        for source in [
            "use mod.custom.math\nmath.",
            "use mod.std.math\nlet math = 1\nmath.",
            "use mod.std.math\nlet alias = math\nalias.",
            "use mod.std.math\nmath.sqrt.",
            "use mod.std.math\nlet note = \"math.\"",
            "use mod.std.math\n// math.",
        ] {
            let mut server = SplashLanguageServer::default();
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .expect("completion request succeeds");
            assert!(
                completion.items.is_empty(),
                "unexpected fixed math completion for {source:?}"
            );
        }

        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.std.math.untrusted",
                "description": "Must not extend the fixed core module.",
                "callMode": "synchronous",
                "callShape": "single_json"
            }
        ]));
        let source = "use mod.std.math\nmath.untrusted({})";
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        server.open_document(document(1, source));
        let untrusted_start = source.find("untrusted").expect("member exists");
        assert!(server
            .hover(
                &test_uri(),
                position_at_byte(source, untrusted_start + "untrusted".len()),
            )
            .expect("fixed math hover request succeeds")
            .is_none());
        let argument = source.find("{}").expect("call argument exists") + 1;
        assert!(server
            .signature_help(&test_uri(), position_at_byte(source, argument))
            .expect("fixed math signature request succeeds")
            .is_none());
    }

    #[test]
    fn completes_and_navigates_direct_static_record_fields() {
        let source = "let profile = {name: \"Ada\", active: true}\nprofile.name";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let member_start = source.rfind("name").unwrap();
        let completion = server
            .completion(
                &test_uri(),
                position_at_byte(source, member_start + "name".len()),
            )
            .expect("static record completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["active", "name"]
        );
        assert!(completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::FIELD)
                && item.detail.as_deref()
                    == Some("static record field; direct literal, child literal, or alias")
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                        if *range == Range::new(
                            position_at_byte(source, member_start),
                            position_at_byte(source, member_start + "name".len()),
                        )
                )
        }));

        let field_definition = source.find("name:").unwrap();
        let definition = server
            .definition(&test_uri(), position_at_byte(source, member_start + 1))
            .expect("static record definition succeeds")
            .expect("known static field has a definition");
        assert_eq!(
            definition.range,
            Range::new(
                position_at_byte(source, field_definition),
                position_at_byte(source, field_definition + "name".len()),
            )
        );

        let hover = server
            .hover(&test_uri(), position_at_byte(source, member_start + 1))
            .expect("static record hover succeeds")
            .expect("known static field has hover information");
        assert_eq!(
            hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: "**static record field** `name`".to_owned(),
            })
        );
        assert_eq!(
            hover.range,
            Some(Range::new(
                position_at_byte(source, member_start),
                position_at_byte(source, member_start + "name".len()),
            ))
        );

        let alias_source = "let profile = {name: \"Ada\"}\nlet alias = profile\nalias.name";
        let mut alias_server = SplashLanguageServer::default();
        alias_server.open_document(document(1, alias_source));
        let alias_completion = alias_server
            .completion(
                &test_uri(),
                position_at_byte(alias_source, alias_source.len()),
            )
            .unwrap();
        assert_eq!(
            alias_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["name"]
        );
        let alias_member = alias_source.rfind("name").unwrap();
        let alias_definition = alias_server
            .definition(
                &test_uri(),
                position_at_byte(alias_source, alias_member + 1),
            )
            .unwrap()
            .expect("alias static record field has a definition");
        assert_eq!(
            alias_definition.range,
            Range::new(
                position_at_byte(alias_source, alias_source.find("name:").unwrap()),
                position_at_byte(
                    alias_source,
                    alias_source.find("name:").unwrap() + "name".len()
                ),
            )
        );
        assert!(alias_server
            .hover(
                &test_uri(),
                position_at_byte(alias_source, alias_member + 1),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn completes_and_navigates_bounded_static_record_nested_fields() {
        let source = "let profile = {user: {name: \"Ada\", active: true}}\nprofile.user.name";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let member_start = source.rfind("name").unwrap();
        let completion = server
            .completion(
                &test_uri(),
                position_at_byte(source, member_start + "name".len()),
            )
            .expect("direct child static record completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["active", "name"]
        );

        let field_definition = source.find("name:").unwrap();
        let definition = server
            .definition(&test_uri(), position_at_byte(source, member_start + 1))
            .expect("direct child static field definition succeeds")
            .expect("known direct child static field has a definition");
        assert_eq!(
            definition.range,
            Range::new(
                position_at_byte(source, field_definition),
                position_at_byte(source, field_definition + "name".len()),
            )
        );
        assert_eq!(
            server
                .hover(&test_uri(), position_at_byte(source, member_start + 1))
                .expect("direct child static field hover succeeds")
                .expect("known direct child static field has hover information")
                .contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: "**static record field** `name`".to_owned(),
            })
        );

        let nested_source = concat!(
            "let profile = {user: {address: {city: \"Paris\", zip: \"75000\"}}}\n",
            "profile.user.address.city"
        );
        let mut nested_server = SplashLanguageServer::default();
        nested_server.open_document(document(1, nested_source));
        let nested_member = nested_source
            .rfind("city")
            .expect("nested static field exists");
        assert_eq!(
            nested_server
                .completion(
                    &test_uri(),
                    position_at_byte(nested_source, nested_source.len()),
                )
                .expect("nested static record completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["city", "zip"]
        );
        assert_eq!(
            nested_server
                .definition(
                    &test_uri(),
                    position_at_byte(nested_source, nested_member + 1),
                )
                .expect("nested static field definition succeeds")
                .expect("known nested static field has a definition")
                .range,
            Range::new(
                position_at_byte(nested_source, nested_source.find("city:").unwrap()),
                position_at_byte(
                    nested_source,
                    nested_source.find("city:").unwrap() + "city".len(),
                ),
            )
        );
        assert!(nested_server
            .hover(
                &test_uri(),
                position_at_byte(nested_source, nested_member + 1),
            )
            .expect("nested static field hover succeeds")
            .is_some());

        let alias_source = "let profile = {user: {name: \"Ada\"}}\n\
                            let alias = profile\n\
                            alias.user.";
        let mut alias_server = SplashLanguageServer::default();
        alias_server.open_document(document(1, alias_source));
        assert_eq!(
            alias_server
                .completion(
                    &test_uri(),
                    position_at_byte(alias_source, alias_source.len()),
                )
                .expect("direct alias child completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["name"]
        );

        let child_alias_source = concat!(
            "let profile = {user: {name: \"Ada\", active: true}}\n",
            "let selected = profile.user\n",
            "let alias = selected\n",
            "alias.name"
        );
        let mut child_alias_server = SplashLanguageServer::default();
        child_alias_server.open_document(document(1, child_alias_source));
        let child_alias_member = child_alias_source
            .rfind("name")
            .expect("child alias field exists");
        assert_eq!(
            child_alias_server
                .completion(
                    &test_uri(),
                    position_at_byte(child_alias_source, child_alias_source.len()),
                )
                .expect("direct child alias completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["active", "name"]
        );
        assert_eq!(
            child_alias_server
                .definition(
                    &test_uri(),
                    position_at_byte(child_alias_source, child_alias_member + 1),
                )
                .expect("direct child alias definition succeeds")
                .expect("known direct child alias field has a definition")
                .range,
            Range::new(
                position_at_byte(
                    child_alias_source,
                    child_alias_source.find("name:").unwrap()
                ),
                position_at_byte(
                    child_alias_source,
                    child_alias_source.find("name:").unwrap() + "name".len(),
                ),
            )
        );
        assert!(child_alias_server
            .hover(
                &test_uri(),
                position_at_byte(child_alias_source, child_alias_member + 1),
            )
            .expect("direct child alias hover succeeds")
            .is_some());

        let nested_child_alias_source = concat!(
            "let profile = {user: {address: {city: \"Paris\", zip: \"75000\"}}}\n",
            "let selected = profile.user\n",
            "selected.address.city"
        );
        let mut nested_child_alias_server = SplashLanguageServer::default();
        nested_child_alias_server.open_document(document(1, nested_child_alias_source));
        assert_eq!(
            nested_child_alias_server
                .completion(
                    &test_uri(),
                    position_at_byte(nested_child_alias_source, nested_child_alias_source.len(),),
                )
                .expect("nested child alias completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["city", "zip"]
        );

        let nested_child_alias_chain_source = concat!(
            "let profile = {user: {address: {city: \"Paris\", zip: \"75000\"}}}\n",
            "let selected = profile.user\n",
            "let address = selected.address\n",
            "address.city"
        );
        let mut nested_child_alias_chain_server = SplashLanguageServer::default();
        nested_child_alias_chain_server.open_document(document(1, nested_child_alias_chain_source));
        let nested_child_alias_chain_member = nested_child_alias_chain_source
            .rfind("city")
            .expect("nested alias-chain field exists");
        assert_eq!(
            nested_child_alias_chain_server
                .completion(
                    &test_uri(),
                    position_at_byte(
                        nested_child_alias_chain_source,
                        nested_child_alias_chain_source.len(),
                    ),
                )
                .expect("nested child alias-chain completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["city", "zip"]
        );
        assert!(nested_child_alias_chain_server
            .hover(
                &test_uri(),
                position_at_byte(
                    nested_child_alias_chain_source,
                    nested_child_alias_chain_member + 1,
                ),
            )
            .expect("nested child alias-chain hover succeeds")
            .is_some());
        assert_eq!(
            nested_child_alias_chain_server
                .definition(
                    &test_uri(),
                    position_at_byte(
                        nested_child_alias_chain_source,
                        nested_child_alias_chain_member + 1,
                    ),
                )
                .expect("nested child alias-chain definition succeeds")
                .expect("known nested alias-chain field has a definition")
                .range,
            Range::new(
                position_at_byte(
                    nested_child_alias_chain_source,
                    nested_child_alias_chain_source.find("city:").unwrap(),
                ),
                position_at_byte(
                    nested_child_alias_chain_source,
                    nested_child_alias_chain_source.find("city:").unwrap() + "city".len(),
                ),
            )
        );

        let compact_nested_alias_source = concat!(
            "let profile = {user: {address: {city: \"Paris\", zip: \"75000\"}}}\n",
            "let address = profile.user.address\n",
            "address.city"
        );
        let mut compact_nested_alias_server = SplashLanguageServer::default();
        compact_nested_alias_server.open_document(document(1, compact_nested_alias_source));
        let compact_nested_alias_member = compact_nested_alias_source
            .rfind("city")
            .expect("compact nested alias field exists");
        assert_eq!(
            compact_nested_alias_server
                .completion(
                    &test_uri(),
                    position_at_byte(
                        compact_nested_alias_source,
                        compact_nested_alias_source.len(),
                    ),
                )
                .expect("compact nested alias completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["city", "zip"]
        );
        assert!(compact_nested_alias_server
            .hover(
                &test_uri(),
                position_at_byte(compact_nested_alias_source, compact_nested_alias_member + 1,),
            )
            .expect("compact nested alias hover succeeds")
            .is_some());
        assert_eq!(
            compact_nested_alias_server
                .definition(
                    &test_uri(),
                    position_at_byte(compact_nested_alias_source, compact_nested_alias_member + 1,),
                )
                .expect("compact nested alias definition succeeds")
                .expect("known compact nested alias field has a definition")
                .range,
            Range::new(
                position_at_byte(
                    compact_nested_alias_source,
                    compact_nested_alias_source.find("city:").unwrap(),
                ),
                position_at_byte(
                    compact_nested_alias_source,
                    compact_nested_alias_source.find("city:").unwrap() + "city".len(),
                ),
            )
        );

        for unsupported_source in [
            "let profile = {user: ({name: \"Ada\"})}\nprofile.user.",
            "let profile = {user: {name: \"Ada\"}.name}\nprofile.user.",
            "let profile = {user: {name: \"Ada\"}, user: {other: true}}\nprofile.user.",
            "let profile = {user: {name: \"Ada\"}}\nlet selected = (profile.user)\nselected.",
            "let profile = {user: {name: \"Ada\"}}\nlet selected = profile.user.name\nselected.",
            "let profile = {user: {name: \"Ada\"}}\nlet selected = profile[\"user\"]\nselected.",
            "let profile = {user: {name: \"Ada\"}}\nlet selected = profile.user\nselected.name.",
            "let profile = {user: {address: {city: \"Paris\", city: \"Lyon\"}}}\nprofile.user.address.",
            "let profile = {user: {address: {city: {name: \"Ada\"}}}}\nprofile.user.address.city.",
            "let profile = {user: {address: {city: \"Paris\"}}}\nlet selected = profile.user\nlet address = selected.address\nlet city = address.city\nprofile.user.address.",
        ] {
            let mut unsupported_server = SplashLanguageServer::default();
            unsupported_server.open_document(document(1, unsupported_source));
            assert!(
                unsupported_server
                    .completion(
                        &test_uri(),
                        position_at_byte(unsupported_source, unsupported_source.len()),
                    )
                    .expect("unsupported nested completion request succeeds")
                    .items
                    .is_empty(),
                "static child metadata must fail closed for {unsupported_source:?}"
            );
        }

        let unrelated_source = concat!(
            "let profile = {user: {name: \"Ada\"}}\n",
            "let selected = profile.user\n",
            "let detail = selected.name\n",
            "let settings = {theme: \"dark\"}\n",
            "settings."
        );
        let mut unrelated_server = SplashLanguageServer::default();
        unrelated_server.open_document(document(1, unrelated_source));
        assert_eq!(
            unrelated_server
                .completion(
                    &test_uri(),
                    position_at_byte(unrelated_source, unrelated_source.len()),
                )
                .expect("unrelated root completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["theme"]
        );

        let duplicate_child_source =
            "let profile = {user: {name: \"Ada\", name: \"Grace\"}}\nprofile.user.name";
        let mut duplicate_child_server = SplashLanguageServer::default();
        duplicate_child_server.open_document(document(1, duplicate_child_source));
        let duplicate_member = duplicate_child_source.rfind("name").unwrap();
        assert!(duplicate_child_server
            .completion(
                &test_uri(),
                position_at_byte(duplicate_child_source, duplicate_member + "name".len(),),
            )
            .expect("duplicate child completion request succeeds")
            .items
            .is_empty());
        assert!(duplicate_child_server
            .definition(
                &test_uri(),
                position_at_byte(duplicate_child_source, duplicate_member + 1),
            )
            .expect("duplicate child definition request succeeds")
            .is_none());
        assert!(duplicate_child_server
            .hover(
                &test_uri(),
                position_at_byte(duplicate_child_source, duplicate_member + 1),
            )
            .expect("duplicate child hover request succeeds")
            .is_none());
    }

    #[test]
    fn follows_bounded_direct_static_record_alias_chains_with_lexical_shadowing() {
        let transitive_source = "let profile = {name: \"Ada\"}\n\
                                 let first = profile\n\
                                 let second = first\n\
                                 second.name";
        let mut transitive_server = SplashLanguageServer::default();
        transitive_server.open_document(document(1, transitive_source));
        let transitive_completion = transitive_server
            .completion(
                &test_uri(),
                position_at_byte(transitive_source, transitive_source.len()),
            )
            .unwrap();
        assert_eq!(
            transitive_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["name"]
        );

        let shadowed_source = "let profile = {outer: true}\n\
                               fn inspect() {\n\
                                   let profile = {inner: true}\n\
                                   let alias = profile\n\
                                   alias.inner\n\
                               }";
        let mut shadowed_server = SplashLanguageServer::default();
        shadowed_server.open_document(document(1, shadowed_source));
        let inner_member = shadowed_source.rfind("inner").unwrap();
        let shadowed_completion = shadowed_server
            .completion(
                &test_uri(),
                position_at_byte(shadowed_source, inner_member + "inner".len()),
            )
            .unwrap();
        assert_eq!(
            shadowed_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["inner"]
        );

        let shadowed_child_source = "let profile = {user: {address: {outer: true}}}\n\
                                    fn inspect() {\n\
                                        let profile = {user: {address: {inner: true}}}\n\
                                        let selected = profile.user\n\
                                        let address = selected.address\n\
                                        address.inner\n\
                                    }";
        let mut shadowed_child_server = SplashLanguageServer::default();
        shadowed_child_server.open_document(document(1, shadowed_child_source));
        let inner_member = shadowed_child_source.rfind("inner").unwrap();
        assert_eq!(
            shadowed_child_server
                .completion(
                    &test_uri(),
                    position_at_byte(shadowed_child_source, inner_member + "inner".len()),
                )
                .unwrap()
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["inner"]
        );

        let indirect_source = "let profile = {name: \"Ada\"}\nlet alias = (profile)\nalias.name";
        let mut indirect_server = SplashLanguageServer::default();
        indirect_server.open_document(document(1, indirect_source));
        assert!(indirect_server
            .completion(
                &test_uri(),
                position_at_byte(indirect_source, indirect_source.len()),
            )
            .unwrap()
            .items
            .is_empty());

        let mut depth_source = String::from("let profile = {name: \"Ada\"}\n");
        let mut previous = "profile".to_owned();
        for index in 0..MAX_STATIC_RECORD_ALIAS_DEPTH {
            let alias = format!("alias_{index}");
            depth_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        depth_source.push_str(&format!("{previous}.name"));
        let mut depth_server = SplashLanguageServer::default();
        depth_server.open_document(document(1, &depth_source));
        assert_eq!(
            depth_server
                .completion(
                    &test_uri(),
                    position_at_byte(&depth_source, depth_source.len()),
                )
                .unwrap()
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["name"]
        );

        let mut too_deep_source = String::from("let profile = {name: \"Ada\"}\n");
        let mut previous = "profile".to_owned();
        for index in 0..=MAX_STATIC_RECORD_ALIAS_DEPTH {
            let alias = format!("alias_{index}");
            too_deep_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        too_deep_source.push_str(&format!("{previous}.name"));
        let mut too_deep_server = SplashLanguageServer::default();
        too_deep_server.open_document(document(1, &too_deep_source));
        assert!(too_deep_server
            .completion(
                &test_uri(),
                position_at_byte(&too_deep_source, too_deep_source.len()),
            )
            .unwrap()
            .items
            .is_empty());
    }

    #[test]
    fn suppresses_static_record_fields_after_a_mutation_but_not_a_read() {
        let read_source =
            "let profile = {name: \"Ada\"}\nlet label = profile.name == \"Ada\"\nprofile.";
        let mut read_server = SplashLanguageServer::default();
        read_server.open_document(document(1, read_source));
        assert_eq!(
            read_server
                .completion(
                    &test_uri(),
                    position_at_byte(read_source, read_source.len())
                )
                .unwrap()
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["name"]
        );

        for source in [
            "let profile = {name: \"Ada\"}\nprofile = {active: true}\nprofile.",
            "let profile = {name: \"Ada\"}\nprofile /* write */ = {active: true}\nprofile.",
            "let profile = {name: \"Ada\"}\nprofile.name = \"Grace\"\nprofile.",
            "let profile = {name: \"Ada\"}\nprofile[\"name\"]\nprofile.",
            "let profile = {name: \"Ada\"}\nprofile.refresh()\nprofile.",
            "let profile = {name: \"Ada\"}\nmutate(profile)\nprofile.",
            "let profile = {name: \"Ada\"}\nlet alias = profile\nalias.name = \"Grace\"\nprofile.",
            "let profile = {name: \"Ada\"}\nlet first = profile\nlet second = first\nsecond[\"name\"]\nprofile.",
            "let profile = {name: \"Ada\"}\nlet alias = profile\nalias.refresh()\nprofile.",
            "let profile = {name: \"Ada\"}\nlet alias = profile\nmutate(alias)\nprofile.",
            "let profile = {user: {name: \"Ada\"}}\nprofile.user.name = \"Grace\"\nprofile.user.",
            "let profile = {user: {name: \"Ada\"}}\nlet selected = profile.user\nselected.name = \"Grace\"\nprofile.user.",
            "let profile = {user: {name: \"Ada\"}}\nlet selected = profile.user\nmutate(selected)\nprofile.user.",
            "let profile = {user: {name: \"Ada\"}}\nlet selected = profile.user\nlet alias = selected\nalias[\"name\"]\nprofile.user.",
            "let profile = {user: {address: {city: \"Paris\"}}}\nprofile.user.address.city = \"Lyon\"\nprofile.user.address.",
            "let profile = {user: {address: {city: \"Paris\"}}}\nlet selected = profile.user\nlet address = selected.address\naddress.city = \"Lyon\"\nprofile.user.address.",
        ] {
            let mut server = SplashLanguageServer::default();
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .unwrap();
            assert!(
                completion.items.is_empty(),
                "static record fields must be suppressed after a potentially mutating path: {source:?}"
            );
        }
    }

    #[test]
    fn fails_closed_when_static_record_alias_metadata_is_truncated() {
        let mut source = String::from("let profile = {name: \"Ada\"}\n");
        for index in 0..=MAX_STATIC_RECORD_ALIASES {
            source.push_str(&format!("let alias_{index} = profile\n"));
        }
        source.push_str("profile.name");
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));
        let member = source.rfind("name").unwrap();

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, source.len()))
            .unwrap();
        assert!(completion.is_incomplete);
        assert!(completion.items.is_empty());
        assert!(server
            .definition(&test_uri(), position_at_byte(&source, member + 1))
            .unwrap()
            .is_none());
        assert!(server
            .hover(&test_uri(), position_at_byte(&source, member + 1))
            .unwrap()
            .is_none());
    }

    #[test]
    fn refuses_static_record_navigation_from_a_truncated_lexical_index() {
        let mut source = String::from("let profile = {name: \"Ada\"}\n");
        for _ in 0..MAX_LEXICAL_SYMBOL_OCCURRENCES {
            source.push_str("profile\n");
        }
        source.push_str("profile.name");
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let member = source.rfind("name").unwrap();
        assert!(server
            .definition(&test_uri(), position_at_byte(&source, member))
            .unwrap()
            .is_none());
        assert!(server
            .hover(&test_uri(), position_at_byte(&source, member))
            .unwrap()
            .is_none());
    }

    #[test]
    fn completes_and_hovers_bounded_advisory_workflow_data() {
        let catalog = workflow_data_catalog(serde_json::json!({
            "inputFields": [
                {"name": "verbose", "type": "boolean"},
                {"name": "left", "type": "integer", "description": "Left *literal* operand."}
            ],
            "outputs": [{
                "stepId": "prepare",
                "fields": [{"name": "total", "type": "integer", "description": "Calculated total."}]
            }, {
                "stepId": "publish",
                "fields": [{"name": "receipt", "type": "string"}]
            }]
        }));

        for (source, expected) in [
            ("workflow.", vec!["input", "outputs"]),
            ("workflow.input.le", vec!["left", "verbose"]),
            ("workflow.outputs.", vec!["prepare", "publish"]),
            ("workflow.outputs.prepare.to", vec!["total"]),
        ] {
            let mut server = SplashLanguageServer::with_workflow_data_catalog(catalog.clone());
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .expect("workflow completion succeeds");
            assert!(!completion.is_incomplete);
            assert_eq!(
                completion
                    .items
                    .iter()
                    .map(|item| item.label.as_str())
                    .collect::<Vec<_>>(),
                expected,
                "unexpected workflow completion for {source:?}"
            );
        }

        let input_source = "workflow.input.le";
        let mut input_server = SplashLanguageServer::with_workflow_data_catalog(catalog.clone());
        input_server.open_document(document(1, input_source));
        let input_completion = input_server
            .completion(
                &test_uri(),
                position_at_byte(input_source, input_source.len()),
            )
            .expect("workflow input completion succeeds");
        let left = input_completion
            .items
            .iter()
            .find(|item| item.label == "left")
            .expect("known input field is completed");
        assert_eq!(left.kind, Some(CompletionItemKind::FIELD));
        assert_eq!(
            left.detail.as_deref(),
            Some("workflow input field; advisory host data contract")
        );
        assert_eq!(
            left.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "workflow input field left\nType: integer\n\nLeft *literal* operand.\n\nAdvisory host data contract; not runtime authority.".to_owned(),
            }))
        );
        assert!(matches!(
            &left.text_edit,
            Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                if *range == Range::new(
                    position_at_byte(input_source, input_source.rfind("le").unwrap()),
                    position_at_byte(input_source, input_source.len()),
                )
        ));

        let hover_source = "workflow.input.left\nworkflow.outputs.prepare.total";
        let mut hover_server = SplashLanguageServer::with_workflow_data_catalog(catalog);
        hover_server.open_document(document(1, hover_source));
        let input_member = hover_source.find("left").expect("input member exists");
        let input_hover = hover_server
            .hover(
                &test_uri(),
                position_at_byte(hover_source, input_member + 1),
            )
            .expect("workflow input hover succeeds")
            .expect("known workflow input field has hover information");
        assert_eq!(
            input_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "workflow input field left\nType: integer\n\nLeft *literal* operand.\n\nAdvisory host data contract; not runtime authority.".to_owned(),
            })
        );
        assert_eq!(
            input_hover.range,
            Some(Range::new(
                position_at_byte(hover_source, input_member),
                position_at_byte(hover_source, input_member + "left".len()),
            ))
        );
        assert!(hover_server
            .definition(
                &test_uri(),
                position_at_byte(hover_source, input_member + 1)
            )
            .expect("workflow input definition request succeeds")
            .is_none());

        let output_member = hover_source.rfind("total").expect("output member exists");
        let output_hover = hover_server
            .hover(
                &test_uri(),
                position_at_byte(hover_source, output_member + 1),
            )
            .expect("workflow output hover succeeds")
            .expect("known workflow output field has hover information");
        assert_eq!(
            output_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "workflow output field total\nType: integer\n\nCalculated total.\n\nAdvisory host data contract; not runtime authority.".to_owned(),
            })
        );

        let deeper_source = "workflow.input.left.";
        let mut deeper_server = SplashLanguageServer::with_workflow_data_catalog(
            workflow_data_catalog(serde_json::json!({
                "inputFields": [{"name": "left", "type": "integer"}],
                "outputs": []
            })),
        );
        deeper_server.open_document(document(1, deeper_source));
        assert!(deeper_server
            .completion(
                &test_uri(),
                position_at_byte(deeper_source, deeper_source.len())
            )
            .expect("non-schema member completion succeeds")
            .items
            .is_empty());
    }

    #[test]
    fn limits_workflow_outputs_to_a_completed_projected_prefix() {
        let catalog = workflow_data_catalog(serde_json::json!({
            "inputFields": [{"name": "left", "type": "integer"}],
            "outputs": [{
                "stepId": "prepare",
                "fields": [{"name": "total", "type": "integer", "description": "Prepared total."}]
            }, {
                "stepId": "calculate",
                "fields": [{"name": "sum", "type": "integer", "description": "Calculated sum."}]
            }, {
                "stepId": "publish",
                "fields": [{"name": "receipt", "type": "string"}]
            }]
        }));
        let step_context = workflow_data_step_context_for(
            serde_json::json!({
                "currentStepId": "calculate",
                "completedOutputStepIds": ["prepare"]
            }),
            &catalog,
        );
        assert!(step_context.configured);
        assert!(!step_context.unavailable);
        assert_eq!(step_context.completed_output_count, 1);

        let outputs_source = "workflow.outputs.";
        let mut outputs_server = SplashLanguageServer::with_workflow_data_catalog_and_step_context(
            catalog.clone(),
            step_context.clone(),
        );
        outputs_server.open_document(document(1, outputs_source));
        let outputs_completion = outputs_server
            .completion(
                &test_uri(),
                position_at_byte(outputs_source, outputs_source.len()),
            )
            .expect("completed-prefix output completion succeeds");
        assert!(!outputs_completion.is_incomplete);
        assert_eq!(
            outputs_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["prepare"]
        );
        assert_eq!(
            outputs_completion.items[0].detail.as_deref(),
            Some("completed workflow output; advisory host data contract")
        );

        let first_step_context = workflow_data_step_context_for(
            serde_json::json!({
                "currentStepId": "prepare",
                "completedOutputStepIds": []
            }),
            &catalog,
        );
        let mut first_step_server =
            SplashLanguageServer::with_workflow_data_catalog_and_step_context(
                catalog.clone(),
                first_step_context,
            );
        first_step_server.open_document(document(1, outputs_source));
        assert!(first_step_server
            .completion(
                &test_uri(),
                position_at_byte(outputs_source, outputs_source.len()),
            )
            .expect("empty completed-prefix completion succeeds")
            .items
            .is_empty());

        let completed_field_source = "workflow.outputs.prepare.to";
        let mut completed_field_server =
            SplashLanguageServer::with_workflow_data_catalog_and_step_context(
                catalog.clone(),
                step_context.clone(),
            );
        completed_field_server.open_document(document(1, completed_field_source));
        let completed_field_completion = completed_field_server
            .completion(
                &test_uri(),
                position_at_byte(completed_field_source, completed_field_source.len()),
            )
            .expect("completed output field completion succeeds");
        assert_eq!(
            completed_field_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );
        assert_eq!(
            completed_field_completion.items[0].detail.as_deref(),
            Some("completed workflow output field; advisory host data contract")
        );

        let future_field_source = "workflow.outputs.calculate.su";
        let mut future_field_server =
            SplashLanguageServer::with_workflow_data_catalog_and_step_context(
                catalog.clone(),
                step_context.clone(),
            );
        future_field_server.open_document(document(1, future_field_source));
        assert!(future_field_server
            .completion(
                &test_uri(),
                position_at_byte(future_field_source, future_field_source.len()),
            )
            .expect("future output field completion request succeeds")
            .items
            .is_empty());

        let hover_source = "workflow.outputs.prepare.total\nworkflow.outputs.calculate.sum";
        let mut hover_server = SplashLanguageServer::with_workflow_data_catalog_and_step_context(
            catalog,
            step_context,
        );
        hover_server.open_document(document(1, hover_source));
        let completed_member = hover_source.find("total").expect("completed member exists");
        let completed_hover = hover_server
            .hover(
                &test_uri(),
                position_at_byte(hover_source, completed_member + 1),
            )
            .expect("completed output hover succeeds")
            .expect("completed output field has hover information");
        assert_eq!(
            completed_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "completed workflow output field total\nType: integer\n\nPrepared total.\n\nAdvisory host data contract; not runtime authority.".to_owned(),
            })
        );
        let future_member = hover_source.rfind("sum").expect("future member exists");
        assert!(hover_server
            .hover(
                &test_uri(),
                position_at_byte(hover_source, future_member + 1),
            )
            .expect("future output hover request succeeds")
            .is_none());

        let params = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "workflowDataCatalog": {
                        "inputFields": [],
                        "outputs": [
                            {"stepId": "prepare", "fields": []},
                            {"stepId": "calculate", "fields": []},
                            {"stepId": "publish", "fields": []}
                        ]
                    },
                    "workflowDataStepContext": {
                        "currentStepId": "calculate",
                        "completedOutputStepIds": ["prepare"]
                    }
                }
            })),
            ..InitializeParams::default()
        };
        let parsed_catalog = workflow_data_completion_catalog_from_initialize_options(&params);
        assert_eq!(
            parsed_catalog
                .outputs
                .iter()
                .map(|output| output.step_id.as_str())
                .collect::<Vec<_>>(),
            ["prepare", "calculate", "publish"]
        );
        let parsed_context = workflow_data_step_context_from_initialize_options(&params);
        assert!(parsed_context.configured);
        assert_eq!(parsed_context.completed_output_count, 1);
    }

    #[test]
    fn accepts_the_workflow_crates_runtime_confirmed_dataflow_projection() {
        use splash_capabilities::CapabilityRuntime;
        use splash_schema::JsonSchema;
        use splash_workflow::{
            WorkflowData, WorkflowDataContract, WorkflowDataLspProjection, WorkflowEngine,
            WorkflowStep, WorkflowStepOutputContract, MAX_WORKFLOW_DATA_LSP_BYTES,
            MAX_WORKFLOW_DATA_LSP_DESCRIPTION_BYTES, MAX_WORKFLOW_DATA_LSP_FIELDS,
            MAX_WORKFLOW_DATA_LSP_NAME_BYTES, MAX_WORKFLOW_DATA_LSP_OUTPUTS,
        };

        assert_eq!(MAX_WORKFLOW_DATA_LSP_OUTPUTS, MAX_LSP_WORKFLOW_DATA_OUTPUTS);
        assert_eq!(MAX_WORKFLOW_DATA_LSP_FIELDS, MAX_LSP_WORKFLOW_DATA_FIELDS);
        assert_eq!(MAX_WORKFLOW_DATA_LSP_BYTES, MAX_LSP_WORKFLOW_DATA_BYTES);
        assert_eq!(
            MAX_WORKFLOW_DATA_LSP_NAME_BYTES,
            MAX_LSP_WORKFLOW_DATA_FIELD_NAME_BYTES
        );
        assert_eq!(
            MAX_WORKFLOW_DATA_LSP_DESCRIPTION_BYTES,
            MAX_LSP_WORKFLOW_DATA_FIELD_DESCRIPTION_BYTES
        );

        let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
        let plan = engine
            .plan(vec![
                WorkflowStep::new("prepare", "1"),
                WorkflowStep::new("calculate", "2"),
            ])
            .expect("workflow plan is valid");
        let contract = WorkflowDataContract::new(
            JsonSchema::compile(serde_json::json!({
                "type": "object",
                "properties": {
                    "left": {"type": "integer", "description": "Left operand."}
                },
                "required": ["left"],
                "additionalProperties": false
            }))
            .expect("input schema is valid"),
            vec![
                WorkflowStepOutputContract::new(
                    "prepare",
                    JsonSchema::compile(serde_json::json!({
                        "type": "object",
                        "properties": {"total": {"type": "integer"}},
                        "required": ["total"],
                        "additionalProperties": false
                    }))
                    .expect("prepare schema is valid"),
                ),
                WorkflowStepOutputContract::new(
                    "calculate",
                    JsonSchema::compile(serde_json::json!({"type": "number"}))
                        .expect("calculate schema is valid"),
                ),
            ],
        )
        .expect("dataflow contract is within bounds");
        let mut data =
            WorkflowData::new(serde_json::json!({"left": 3})).expect("workflow input is bounded");
        let checkpoint = engine
            .dataflow_checkpoint_after_with_contract(&plan, &mut data, &contract, 0)
            .expect("initial dataflow checkpoint is valid");
        let projection =
            WorkflowDataLspProjection::from_checkpoint(&plan, &checkpoint, &data, &contract)
                .expect("bound workflow state produces an LSP projection");
        let splash = serde_json::to_value(&projection).expect("projection serializes");

        let params = InitializeParams {
            initialization_options: Some(serde_json::json!({"splash": splash})),
            ..InitializeParams::default()
        };
        let catalog = workflow_data_completion_catalog_from_initialize_options(&params);
        let step_context = workflow_data_step_context_from_initialize_options(&params);
        assert!(catalog.configured);
        assert!(!catalog.unavailable);
        assert_eq!(
            catalog
                .input_fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["left"]
        );
        assert_eq!(
            catalog
                .outputs
                .iter()
                .map(|output| output.step_id.as_str())
                .collect::<Vec<_>>(),
            ["prepare"]
        );
        assert!(step_context.configured);
        assert!(!step_context.unavailable);
        assert_eq!(step_context.completed_output_count, 0);

        let source = "workflow.input.";
        let mut server = SplashLanguageServer::with_workflow_data_catalog_and_step_context(
            catalog,
            step_context,
        );
        server.open_document(document(1, source));
        let completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("workflow projection completion succeeds");
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["left"]
        );
    }

    #[test]
    fn workflow_data_step_context_fails_closed_when_not_an_exact_catalog_prefix() {
        let catalog = workflow_data_catalog(serde_json::json!({
            "inputFields": [],
            "outputs": [
                {"stepId": "prepare", "fields": []},
                {"stepId": "calculate", "fields": []}
            ]
        }));
        assert!(parse_workflow_data_step_context(
            &serde_json::json!({
                "currentStepId": "calculate",
                "completedOutputStepIds": ["calculate"]
            }),
            &catalog,
        )
        .is_none());
        assert!(parse_workflow_data_step_context(
            &serde_json::json!({
                "currentStepId": "calculate",
                "completedOutputStepIds": ["prepare", "calculate"]
            }),
            &catalog,
        )
        .is_none());

        let invalid_params = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "workflowDataCatalog": {
                        "inputFields": [],
                        "outputs": [
                            {"stepId": "prepare", "fields": []},
                            {"stepId": "calculate", "fields": []}
                        ]
                    },
                    "workflowDataStepContext": {
                        "currentStepId": "calculate",
                        "completedOutputStepIds": ["calculate"]
                    }
                }
            })),
            ..InitializeParams::default()
        };
        let invalid_catalog =
            workflow_data_completion_catalog_from_initialize_options(&invalid_params);
        let invalid_context = workflow_data_step_context_from_initialize_options(&invalid_params);
        assert!(invalid_catalog.unavailable);
        assert!(invalid_context.unavailable);
        let source = "workflow.outputs.";
        let mut invalid_server = SplashLanguageServer::with_workflow_data_catalog_and_step_context(
            invalid_catalog,
            invalid_context,
        );
        invalid_server.open_document(document(1, source));
        let completion = invalid_server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("invalid context completion request succeeds");
        assert!(completion.is_incomplete);
        assert!(completion.items.is_empty());

        let context_without_catalog = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "workflowDataStepContext": {
                        "currentStepId": "prepare",
                        "completedOutputStepIds": []
                    }
                }
            })),
            ..InitializeParams::default()
        };
        assert!(
            workflow_data_completion_catalog_from_initialize_options(&context_without_catalog)
                .unavailable
        );
        assert!(
            workflow_data_step_context_from_initialize_options(&context_without_catalog)
                .unavailable
        );
    }

    #[test]
    fn refreshes_workflow_data_configuration_atomically_and_fails_closed() {
        let initial_catalog = workflow_data_catalog(serde_json::json!({
            "inputFields": [{"name": "old_input", "type": "integer"}],
            "outputs": [
                {"stepId": "prepare", "fields": [{"name": "total", "type": "integer"}]},
                {"stepId": "calculate", "fields": [{"name": "sum", "type": "integer"}]}
            ]
        }));
        let initial_context = workflow_data_step_context_for(
            serde_json::json!({
                "currentStepId": "calculate",
                "completedOutputStepIds": ["prepare"]
            }),
            &initial_catalog,
        );
        let mut server = SplashLanguageServer::with_workflow_data_catalog_and_step_context(
            initial_catalog,
            initial_context,
        );
        let source = "workflow.outputs.";
        server.open_document(document(1, source));
        let initial_completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("initial workflow output completion succeeds");
        assert_eq!(
            initial_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["prepare"]
        );

        let (server_connection, _client_connection) = Connection::memory();
        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: serde_json::json!({
                        "splash": {
                            "workflowDataCatalog": {
                                "inputFields": [{"name": "new_input", "type": "string"}],
                                "outputs": [
                                    {"stepId": "ingest", "fields": [{"name": "value", "type": "string"}]},
                                    {"stepId": "publish", "fields": [{"name": "receipt", "type": "string"}]}
                                ]
                            },
                            "workflowDataStepContext": {
                                "currentStepId": "publish",
                                "completedOutputStepIds": ["ingest"]
                            }
                        }
                    }),
                },
            ),
        )
        .expect("valid workflow configuration refresh succeeds");
        assert_eq!(
            server
                .workflow_data_catalog
                .input_fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["new_input"]
        );
        assert_eq!(
            server
                .workflow_data_catalog
                .outputs
                .iter()
                .map(|output| output.step_id.as_str())
                .collect::<Vec<_>>(),
            ["ingest", "publish"]
        );
        assert!(server.workflow_data_step_context.configured);
        assert_eq!(server.workflow_data_step_context.completed_output_count, 1);

        let refreshed_completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("refreshed workflow output completion succeeds");
        assert!(!refreshed_completion.is_incomplete);
        assert_eq!(
            refreshed_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["ingest"]
        );

        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: serde_json::json!({"editor": {"tabSize": 4}}),
                },
            ),
        )
        .expect("unrelated configuration update succeeds");
        assert_eq!(
            server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .expect("unrelated configuration retains workflow completion")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["ingest"]
        );

        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: serde_json::json!({
                        "splash": {
                            "workflowDataCatalog": {
                                "inputFields": [],
                                "outputs": []
                            }
                        }
                    }),
                },
            ),
        )
        .expect("partial workflow configuration notification is handled");
        assert!(server.workflow_data_catalog.unavailable);
        assert!(server.workflow_data_step_context.unavailable);
        let unavailable_completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("unavailable workflow completion request succeeds");
        assert!(unavailable_completion.is_incomplete);
        assert!(unavailable_completion.items.is_empty());

        let replacement_catalog = workflow_data_catalog(serde_json::json!({
            "inputFields": [],
            "outputs": [{"stepId": "prepare", "fields": []}, {"stepId": "calculate", "fields": []}]
        }));
        let replacement_context = workflow_data_step_context_for(
            serde_json::json!({
                "currentStepId": "calculate",
                "completedOutputStepIds": ["prepare"]
            }),
            &replacement_catalog,
        );
        let mut malformed_params_server =
            SplashLanguageServer::with_completion_catalogs_and_workflow_data(
                tool_catalog(serde_json::json!([
                    {"name": "text.echo", "format": "text"}
                ])),
                module_catalog(serde_json::json!([
                    {"path": "mod.app.inspect"}
                ])),
                replacement_catalog,
                replacement_context,
            );
        malformed_params_server.open_document(document(1, source));
        handle_notification(
            &server_connection,
            &mut malformed_params_server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                serde_json::json!({"unexpected": true}),
            ),
        )
        .expect("malformed configuration notification is handled");
        assert!(malformed_params_server.tool_catalog.unavailable);
        assert!(malformed_params_server.module_catalog.unavailable);
        assert!(malformed_params_server.workflow_data_catalog.unavailable);
        assert!(
            malformed_params_server
                .workflow_data_step_context
                .unavailable
        );
    }

    #[test]
    fn explicit_workflow_data_configuration_clear_is_atomic() {
        let catalog = workflow_data_catalog(serde_json::json!({
            "inputFields": [{"name": "left", "type": "integer"}],
            "outputs": [{"stepId": "prepare", "fields": []}]
        }));
        let step_context = workflow_data_step_context_for(
            serde_json::json!({
                "currentStepId": "prepare",
                "completedOutputStepIds": []
            }),
            &catalog,
        );
        let clear_settings = serde_json::json!({
            "splash": {
                "workflowDataCatalog": null,
                "workflowDataStepContext": null
            }
        });
        assert!(matches!(
            workflow_data_configuration_update_from_settings(&clear_settings),
            WorkflowDataConfigurationUpdate::Clear
        ));

        let partial_clear_settings = serde_json::json!({
            "splash": {
                "workflowDataCatalog": null,
                "workflowDataStepContext": {
                    "currentStepId": "prepare",
                    "completedOutputStepIds": []
                }
            }
        });
        let WorkflowDataConfigurationUpdate::Replace {
            catalog: partial_catalog,
            step_context: partial_context,
        } = workflow_data_configuration_update_from_settings(&partial_clear_settings)
        else {
            panic!("a partial clear must fail closed");
        };
        assert!(partial_catalog.unavailable);
        assert!(partial_context.unavailable);

        let source = "workflow.input.";
        let mut server = SplashLanguageServer::with_workflow_data_catalog_and_step_context(
            catalog,
            step_context,
        );
        server.open_document(document(1, source));
        assert_eq!(
            server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .expect("configured workflow completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["left"]
        );

        let (server_connection, _client_connection) = Connection::memory();
        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: clear_settings,
                },
            ),
        )
        .expect("explicit workflow clear notification is handled");
        assert!(server.workflow_data_catalog.unavailable);
        assert!(server.workflow_data_step_context.unavailable);
        let completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("cleared workflow completion succeeds");
        assert!(completion.is_incomplete);
        assert!(completion.items.is_empty());

        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: serde_json::json!({
                        "splash": {
                            "workflowDataCatalog": {
                                "inputFields": [{"name": "right", "type": "integer"}],
                                "outputs": [{"stepId": "calculate", "fields": []}]
                            },
                            "workflowDataStepContext": {
                                "currentStepId": "calculate",
                                "completedOutputStepIds": []
                            }
                        }
                    }),
                },
            ),
        )
        .expect("replacement after workflow clear is handled");
        let recovered_completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("recovered workflow completion succeeds");
        assert!(!recovered_completion.is_incomplete);
        assert_eq!(
            recovered_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["right"]
        );
    }

    #[test]
    fn workflow_data_projection_fails_closed_and_respects_shadowing() {
        let params = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "workflowDataCatalog": {
                        "inputFields": [
                            {"name": "right", "type": "integer"},
                            {"name": "left", "type": "integer"}
                        ],
                        "outputs": [{
                            "stepId": "prepare",
                            "fields": [{"name": "total", "type": "integer"}]
                        }]
                    }
                }
            })),
            ..InitializeParams::default()
        };
        let parsed = workflow_data_completion_catalog_from_initialize_options(&params);
        assert!(parsed.configured);
        assert!(!parsed.unavailable);
        assert_eq!(
            parsed
                .input_fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["left", "right"]
        );

        let invalid_params = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "workflowDataCatalog": {
                        "inputFields": [
                            {"name": "left", "type": "integer"},
                            {"name": "left", "type": "number"}
                        ],
                        "outputs": []
                    }
                }
            })),
            ..InitializeParams::default()
        };
        let invalid = workflow_data_completion_catalog_from_initialize_options(&invalid_params);
        assert!(invalid.configured);
        assert!(invalid.unavailable);
        let source = "workflow.input.";
        let mut invalid_server = SplashLanguageServer::with_workflow_data_catalog(invalid);
        invalid_server.open_document(document(1, source));
        let invalid_completion = invalid_server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("malformed workflow projection completion succeeds");
        assert!(invalid_completion.is_incomplete);
        assert!(invalid_completion.items.is_empty());

        let mut absent_server = SplashLanguageServer::default();
        absent_server.open_document(document(1, source));
        let absent_completion = absent_server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("absent workflow projection completion succeeds");
        assert!(!absent_completion.is_incomplete);
        assert!(absent_completion.items.is_empty());

        let catalog = workflow_data_catalog(serde_json::json!({
            "inputFields": [{"name": "left", "type": "integer"}],
            "outputs": []
        }));
        for (shadowed_source, expected) in [
            (
                "let workflow = {input: {local: true}}\nworkflow.input.",
                &["local"][..],
            ),
            ("use mod.workflow\nworkflow.input.", &[][..]),
        ] {
            let mut server = SplashLanguageServer::with_workflow_data_catalog(catalog.clone());
            server.open_document(document(1, shadowed_source));
            let completion = server
                .completion(
                    &test_uri(),
                    position_at_byte(shadowed_source, shadowed_source.len()),
                )
                .expect("shadowed workflow completion succeeds");
            let labels = completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>();
            assert_eq!(
                labels, expected,
                "workflow projection must not override {shadowed_source:?}"
            );
        }

        assert!(parse_workflow_data_completion_catalog(&serde_json::json!({
            "inputFields": [{"name": "valid", "type": "unsupported"}],
            "outputs": []
        }))
        .is_none());
        assert!(parse_workflow_data_completion_catalog(&serde_json::json!({
            "inputFields": [],
            "outputs": [{"stepId": "release-publish", "fields": []}]
        }))
        .is_none());
        assert!(parse_workflow_data_completion_catalog(&serde_json::json!({
            "inputFields": [{
                "name": "valid",
                "type": "string",
                "description": "x".repeat(MAX_LSP_WORKFLOW_DATA_FIELD_DESCRIPTION_BYTES + 1)
            }],
            "outputs": []
        }))
        .is_none());

        let too_many_outputs = serde_json::Value::Array(
            (0..=MAX_LSP_WORKFLOW_DATA_OUTPUTS)
                .map(|index| serde_json::json!({"stepId": format!("step_{index}"), "fields": []}))
                .collect(),
        );
        assert!(parse_workflow_data_completion_catalog(&serde_json::json!({
            "inputFields": [],
            "outputs": too_many_outputs
        }))
        .is_none());

        let too_many_fields = serde_json::Value::Array(
            (0..=MAX_LSP_WORKFLOW_DATA_FIELDS)
                .map(|index| serde_json::json!({"name": format!("field_{index}"), "type": "any"}))
                .collect(),
        );
        assert!(parse_workflow_data_completion_catalog(&serde_json::json!({
            "inputFields": too_many_fields,
            "outputs": []
        }))
        .is_none());
    }

    #[test]
    fn completes_bounded_catalog_names_for_direct_visible_tool_calls() {
        let catalog = tool_catalog(serde_json::json!([
            {
                "name": "text.echo",
                "format": "text",
                "description": "Returns text unchanged.",
                "ignored": {"nested": true}
            },
            {
                "name": "math.add",
                "format": "json",
                "description": "Adds two integer fields."
            },
            {
                "name": "text.hidden",
                "format": "text",
                "description": "Another text tool."
            }
        ]));
        let source = "use mod.tool\n\
                      let text_result = tool.call(\"text.\")\n\
                      let json_result = tool.call_json(\"math.\", {})";
        let mut server = SplashLanguageServer::with_tool_catalog(catalog);
        server.open_document(document(1, source));

        let text_start = source.find("text.\"").unwrap();
        let text_completion = server
            .completion(
                &test_uri(),
                position_at_byte(source, text_start + "text.".len()),
            )
            .expect("text tool completion succeeds");
        assert!(!text_completion.is_incomplete);
        assert_eq!(
            text_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["text.echo", "text.hidden"]
        );
        assert!(text_completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::VALUE)
                && item.detail.as_deref() == Some("text capability name; host approval required")
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                        if *range == Range::new(
                            position_at_byte(source, text_start),
                            position_at_byte(source, text_start + "text.".len()),
                        )
                )
        }));
        assert_eq!(
            text_completion.items[0].documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Returns text unchanged.".to_owned(),
            }))
        );

        let json_start = source.rfind("math.\"").unwrap();
        let json_completion = server
            .completion(
                &test_uri(),
                position_at_byte(source, json_start + "math.".len()),
            )
            .expect("JSON tool completion succeeds");
        assert!(!json_completion.is_incomplete);
        assert_eq!(
            json_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["math.add"]
        );
        assert_eq!(
            json_completion.items[0].detail.as_deref(),
            Some("JSON capability name; host approval required")
        );
    }

    #[test]
    fn completes_catalog_names_while_a_direct_tool_literal_is_unterminated() {
        let catalog = tool_catalog(serde_json::json!([
            {"name": "text.echo", "format": "text", "description": "text"}
        ]));
        let source = "use mod.tool\nlet result = tool.call(\"tex";
        let mut server = SplashLanguageServer::with_tool_catalog(catalog);
        server.open_document(document(1, source));

        let completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("unterminated literal remains a completion site");
        assert!(!completion.is_incomplete);
        assert_eq!(completion.items.len(), 1);
        assert_eq!(completion.items[0].label, "text.echo");
        assert!(matches!(
            &completion.items[0].text_edit,
            Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                if *range == Range::new(
                    position_at_byte(source, source.rfind("tex").unwrap()),
                    position_at_byte(source, source.len()),
                )
        ));
    }

    #[test]
    fn refuses_catalog_names_outside_a_direct_visible_tool_literal() {
        let catalog = tool_catalog(serde_json::json!([
            {"name": "text.echo", "format": "text", "description": "text"}
        ]));
        for source in [
            "use mod.custom.tool\nlet result = tool.call(\"text.\")",
            "use mod.tool\nlet tool = {call: 1}\ntool.call(\"text.\")",
            "use mod.tool\nlet result = tool.call(prefix, \"text.\")",
            "use mod.tool\n// tool.call(\"text.\")",
            "use mod.tool\nlet note = \"tool.call(\\\"text.\\\")\"",
        ] {
            let cursor = source.rfind("text.").unwrap() + "text.".len();
            let mut server = SplashLanguageServer::with_tool_catalog(catalog.clone());
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, cursor))
                .expect("completion request succeeds");
            assert!(
                completion.items.is_empty(),
                "unexpected catalog completion for {source:?}"
            );
        }
    }

    #[test]
    fn catalog_projection_is_bounded_and_fails_closed_when_malformed() {
        let params = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "toolCatalog": [
                        {"name": "text.z", "format": "text", "description": "z"},
                        {"name": "math.a", "format": "json", "description": "a"}
                    ]
                }
            })),
            ..InitializeParams::default()
        };
        let catalog = tool_completion_catalog_from_initialize_options(&params);
        assert!(!catalog.unavailable);
        assert_eq!(
            catalog
                .tools
                .iter()
                .map(|tool| tool.name.as_str())
                .collect::<Vec<_>>(),
            ["math.a", "text.z"]
        );

        let invalid_params = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "toolCatalog": [
                        {"name": "TEXT.ECHO", "format": "text", "description": "invalid"}
                    ]
                }
            })),
            ..InitializeParams::default()
        };
        let invalid = tool_completion_catalog_from_initialize_options(&invalid_params);
        assert!(invalid.unavailable);
        assert!(invalid.tools.is_empty());
        let source = "use mod.tool\nlet result = tool.call(\"text.\")";
        let mut server = SplashLanguageServer::with_tool_catalog(invalid);
        server.open_document(document(1, source));
        let completion = server
            .completion(
                &test_uri(),
                position_at_byte(source, source.rfind("text.").unwrap() + "text.".len()),
            )
            .expect("malformed catalog completion request succeeds");
        assert!(completion.is_incomplete);
        assert!(completion.items.is_empty());

        let oversized = serde_json::Value::Array(
            (0..=MAX_LSP_TOOL_CATALOG_TOOLS)
                .map(|index| {
                    serde_json::json!({
                        "name": format!("text.{index}"),
                        "format": "text",
                        "description": "text"
                    })
                })
                .collect(),
        );
        assert!(parse_tool_completion_catalog(&oversized).is_none());

        let oversized_description = serde_json::json!([{
            "name": "text.echo",
            "format": "text",
            "description": "x".repeat(MAX_LSP_TOOL_DESCRIPTION_BYTES + 1)
        }]);
        assert!(parse_tool_completion_catalog(&oversized_description).is_none());

        let oversized_retained_bytes = serde_json::Value::Array(
            (0..MAX_LSP_TOOL_CATALOG_TOOLS)
                .map(|index| {
                    serde_json::json!({
                        "name": format!("text.{index}"),
                        "format": "text",
                        "description": "x".repeat(MAX_LSP_TOOL_DESCRIPTION_BYTES)
                    })
                })
                .collect(),
        );
        assert!(parse_tool_completion_catalog(&oversized_retained_bytes).is_none());
    }

    #[test]
    fn refreshes_tool_and_module_catalogs_independently_and_fails_closed() {
        let mut server = SplashLanguageServer::with_completion_catalogs(
            tool_catalog(serde_json::json!([
                {"name": "text.old", "format": "text", "description": "old tool"}
            ])),
            module_catalog(serde_json::json!([
                {"path": "mod.app.old", "description": "old module"}
            ])),
        );
        let tool_source = "use mod.tool\nlet result = tool.call(\"text.";
        server.open_document(document(1, tool_source));
        assert_eq!(
            server
                .completion(
                    &test_uri(),
                    position_at_byte(tool_source, tool_source.len())
                )
                .expect("initial tool completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["text.old"]
        );

        let module_source = "use mod.app\napp.";
        server.open_document(document(2, module_source));
        assert_eq!(
            server
                .completion(
                    &test_uri(),
                    position_at_byte(module_source, module_source.len()),
                )
                .expect("initial module completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["old"]
        );

        let (server_connection, _client_connection) = Connection::memory();
        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: serde_json::json!({
                        "splash": {
                            "toolCatalog": [
                                {"name": "text.next", "format": "text", "description": "next tool"}
                            ],
                            "moduleCatalog": [
                                {"path": "mod.app.next", "description": "next module"}
                            ]
                        }
                    }),
                },
            ),
        )
        .expect("complete tool and module replacement is handled");

        server.open_document(document(3, tool_source));
        assert_eq!(
            server
                .completion(
                    &test_uri(),
                    position_at_byte(tool_source, tool_source.len())
                )
                .expect("refreshed tool completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["text.next"]
        );
        server.open_document(document(4, module_source));
        assert_eq!(
            server
                .completion(
                    &test_uri(),
                    position_at_byte(module_source, module_source.len()),
                )
                .expect("refreshed module completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["next"]
        );

        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: serde_json::json!({
                        "splash": {"moduleCatalog": null}
                    }),
                },
            ),
        )
        .expect("explicit module clear is handled");
        assert!(server.module_catalog.unavailable);
        server.open_document(document(5, module_source));
        let cleared_module_completion = server
            .completion(
                &test_uri(),
                position_at_byte(module_source, module_source.len()),
            )
            .expect("cleared module completion succeeds");
        assert!(cleared_module_completion.is_incomplete);
        assert!(cleared_module_completion.items.is_empty());
        server.open_document(document(6, tool_source));
        assert_eq!(
            server
                .completion(
                    &test_uri(),
                    position_at_byte(tool_source, tool_source.len())
                )
                .expect("module clear retains tool catalog")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["text.next"]
        );

        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: serde_json::json!({
                        "splash": {
                            "toolCatalog": {},
                            "moduleCatalog": [
                                {"path": "mod.app.final", "description": "final module"}
                            ]
                        }
                    }),
                },
            ),
        )
        .expect("malformed tool projection and valid module replacement are handled");
        assert!(server.tool_catalog.unavailable);
        assert!(!server.workflow_data_catalog.unavailable);
        assert!(!server.workflow_data_step_context.unavailable);
        server.open_document(document(7, tool_source));
        let unavailable_tool_completion = server
            .completion(
                &test_uri(),
                position_at_byte(tool_source, tool_source.len()),
            )
            .expect("unavailable tool completion succeeds");
        assert!(unavailable_tool_completion.is_incomplete);
        assert!(unavailable_tool_completion.items.is_empty());
        server.open_document(document(8, module_source));
        assert_eq!(
            server
                .completion(
                    &test_uri(),
                    position_at_byte(module_source, module_source.len()),
                )
                .expect("independent module recovery succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["final"]
        );

        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: serde_json::json!({
                        "splash": {
                            "toolCatalog": [
                                {"name": "text.recovered", "format": "text", "description": "recovered tool"}
                            ]
                        }
                    }),
                },
            ),
        )
        .expect("tool recovery is handled");
        server.open_document(document(9, tool_source));
        assert_eq!(
            server
                .completion(
                    &test_uri(),
                    position_at_byte(tool_source, tool_source.len())
                )
                .expect("recovered tool completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["text.recovered"]
        );
        assert_eq!(
            server
                .module_catalog
                .modules
                .iter()
                .map(|module| module.path.join("."))
                .collect::<Vec<_>>(),
            ["mod.app.final"]
        );

        handle_notification(
            &server_connection,
            &mut server,
            Notification::new(
                DidChangeConfiguration::METHOD.to_owned(),
                DidChangeConfigurationParams {
                    settings: serde_json::json!({"splash": []}),
                },
            ),
        )
        .expect("malformed splash configuration is handled");
        assert!(server.tool_catalog.unavailable);
        assert!(server.module_catalog.unavailable);
        assert!(server.workflow_data_catalog.unavailable);
        assert!(server.workflow_data_step_context.unavailable);
    }

    #[test]
    fn completes_bounded_advisory_module_paths_and_direct_imported_members() {
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.std",
                "description": "Standard helpers.",
                "ignored": {"nested": true}
            },
            {
                "path": "mod.std.assert",
                "description": "Stops when a condition is false."
            },
            {
                "path": "mod.std.log",
                "description": "Writes a host-defined log message."
            },
            {
                "path": "mod.math.sin",
                "description": "Computes a sine."
            }
        ]));

        let import_source = "use mod.st";
        let mut import_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        import_server.open_document(document(1, import_source));
        let import_start = import_source.rfind("st").unwrap();
        let import_completion = import_server
            .completion(
                &test_uri(),
                position_at_byte(import_source, import_source.len()),
            )
            .expect("import-path completion succeeds");
        assert!(!import_completion.is_incomplete);
        assert_eq!(
            import_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["math", "std"]
        );
        let expected_import_range = Range::new(
            position_at_byte(import_source, import_start),
            position_at_byte(import_source, import_source.len()),
        );
        assert!(import_completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::MODULE)
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. })) if *range == expected_import_range
                )
        }));
        let math_import = import_completion
            .items
            .iter()
            .find(|item| item.label == "math")
            .expect("advisory module descriptor is present");
        assert_eq!(
            math_import.detail.as_deref(),
            Some("advisory module path; host module binding required")
        );
        let std_import = import_completion
            .items
            .iter()
            .find(|item| item.label == "std")
            .expect("fixed core namespace is present");
        assert_eq!(
            std_import.detail.as_deref(),
            Some("Splash core namespace; fixed and effect-free")
        );
        assert_eq!(
            std_import.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Fixed Splash core namespace. Its presence does not resolve a host module or grant authority.".to_owned(),
            }))
        );

        let nested_import_source = "use mod.std.";
        let mut nested_import_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        nested_import_server.open_document(document(1, nested_import_source));
        let nested_import_completion = nested_import_server
            .completion(
                &test_uri(),
                position_at_byte(nested_import_source, nested_import_source.len()),
            )
            .expect("nested import-path completion succeeds");
        assert_eq!(
            nested_import_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["array", "assert", "json", "math", "object", "text"]
        );
        let nested_assert = nested_import_completion
            .items
            .iter()
            .find(|item| item.label == "assert")
            .expect("fixed assertion module is present");
        assert_eq!(
            nested_assert.detail.as_deref(),
            Some("Splash core function; fixed assertion helper")
        );

        let member_source = "use mod.std\nstd.";
        let mut member_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        member_server.open_document(document(1, member_source));
        let member_completion = member_server
            .completion(
                &test_uri(),
                position_at_byte(member_source, member_source.len()),
            )
            .expect("imported-module member completion succeeds");
        assert!(!member_completion.is_incomplete);
        assert_eq!(
            member_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["array", "assert", "json", "math", "object", "text"]
        );
        assert!(member_completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::FIELD)
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                        if *range == Range::new(
                            position_at_byte(member_source, member_source.len()),
                            position_at_byte(member_source, member_source.len()),
                        )
                )
        }));
        let assert_member = member_completion
            .items
            .iter()
            .find(|item| item.label == "assert")
            .expect("fixed assertion member is present");
        assert_eq!(
            assert_member.detail.as_deref(),
            Some("Splash core function; fixed assertion helper")
        );
        assert_eq!(
            assert_member.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: STANDARD_ASSERT_DOCUMENTATION.to_owned(),
            }))
        );
        let chained_member_source = "use mod.service\nservice.inspect.";
        let chained_catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.service.inspect.config",
                "description": "Reads static inspector configuration."
            },
            {
                "path": "mod.service.inspect.status",
                "description": "Returns inspector status."
            }
        ]));
        let mut chained_member_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            chained_catalog,
        );
        chained_member_server.open_document(document(1, chained_member_source));
        let chained_completion = chained_member_server
            .completion(
                &test_uri(),
                position_at_byte(chained_member_source, chained_member_source.len()),
            )
            .expect("nested imported-module completion succeeds");
        assert!(!chained_completion.is_incomplete);
        assert_eq!(
            chained_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["config", "status"]
        );
        assert!(chained_completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::FIELD)
                && matches!(
                    &item.text_edit,
                    Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                        if *range == Range::new(
                            position_at_byte(chained_member_source, chained_member_source.len()),
                            position_at_byte(chained_member_source, chained_member_source.len()),
                        )
                )
        }));

        let tool_source = "use mod.tool\ntool.";
        let mut tool_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {"path": "mod.service.log", "description": "Does not affect mod.tool."}
            ])),
        );
        tool_server.open_document(document(1, tool_source));
        let tool_completion = tool_server
            .completion(
                &test_uri(),
                position_at_byte(tool_source, tool_source.len()),
            )
            .expect("fixed tool completion succeeds");
        assert_eq!(
            tool_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["call", "call_json", "start", "start_json"]
        );
    }

    #[test]
    fn completes_fixed_core_import_paths_without_host_metadata_and_masks_fixed_leaves() {
        let root_source = "use mod.";
        let mut root_server = SplashLanguageServer::default();
        root_server.open_document(document(1, root_source));
        let root_completion = root_server
            .completion(
                &test_uri(),
                position_at_byte(root_source, root_source.len()),
            )
            .expect("fixed root import completion succeeds");
        assert!(!root_completion.is_incomplete);
        assert_eq!(root_completion.items.len(), 1);
        let std = &root_completion.items[0];
        assert_eq!(std.label, "std");
        assert_eq!(std.kind, Some(CompletionItemKind::MODULE));
        assert_eq!(
            std.detail.as_deref(),
            Some("Splash core namespace; fixed and effect-free")
        );
        assert_eq!(
            std.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Fixed Splash core namespace. Its presence does not resolve a host module or grant authority.".to_owned(),
            }))
        );

        let standard_source = "use mod.std.";
        let mut standard_server = SplashLanguageServer::default();
        standard_server.open_document(document(1, standard_source));
        let standard_completion = standard_server
            .completion(
                &test_uri(),
                position_at_byte(standard_source, standard_source.len()),
            )
            .expect("fixed standard import completion succeeds");
        assert!(!standard_completion.is_incomplete);
        assert_eq!(
            standard_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["array", "assert", "json", "math", "object", "text"]
        );
        assert!(standard_completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::MODULE)
                && item
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.starts_with("Splash core"))
        }));

        let direct_standard_source = "use mod.std\nstd.";
        let mut direct_standard_server = SplashLanguageServer::default();
        direct_standard_server.open_document(document(1, direct_standard_source));
        let direct_standard_completion = direct_standard_server
            .completion(
                &test_uri(),
                position_at_byte(direct_standard_source, direct_standard_source.len()),
            )
            .expect("direct fixed standard member completion succeeds");
        assert_eq!(
            direct_standard_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["array", "assert", "json", "math", "object", "text"]
        );
        assert!(direct_standard_completion.items.iter().all(|item| {
            item.kind == Some(CompletionItemKind::FIELD)
                && item
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.starts_with("Splash core"))
        }));

        let direct_standard_hover_source = "use mod.std\nstd.math";
        let mut direct_standard_hover_server = SplashLanguageServer::default();
        direct_standard_hover_server.open_document(document(1, direct_standard_hover_source));
        let math_start = direct_standard_hover_source
            .rfind("math")
            .expect("core math member exists");
        let math_hover = direct_standard_hover_server
            .hover(
                &test_uri(),
                position_at_byte(direct_standard_hover_source, math_start + 1),
            )
            .expect("direct fixed standard hover succeeds")
            .expect("core math member has static hover");
        assert_eq!(
            math_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Fixed Splash core scalar helpers. They do not resolve a host module or grant authority.".to_owned(),
            })
        );

        let extension_catalog = module_catalog(serde_json::json!([
            {"path": "mod.std.array.untrusted", "description": "Must stay hidden."},
            {"path": "mod.std.math.untrusted", "description": "Must stay hidden."},
            {"path": "mod.std.assert.untrusted", "description": "Must stay hidden."},
            {"path": "mod.std.json.untrusted", "description": "Must stay hidden."},
            {"path": "mod.std.text.untrusted", "description": "Must stay hidden."},
            {"path": "mod.std.object.untrusted", "description": "Must stay hidden."},
            {
                "path": "mod.std.log",
                "description": "Must stay hidden.",
                "callMode": "synchronous",
                "callShape": "single_json"
            },
            {"path": "mod.extra.value", "description": "Unrelated advisory module."}
        ]));
        for source in [
            "use mod.std.array.",
            "use mod.std.math.",
            "use mod.std.assert.",
            "use mod.std.json.",
            "use mod.std.object.",
            "use mod.std.text.",
            "use mod.std\nstd.array.",
            "use mod.std\nstd.math.",
            "use mod.std\nstd.assert.",
            "use mod.std\nstd.json.",
            "use mod.std\nstd.object.",
            "use mod.std\nstd.text.",
            "use mod.std\nstd.log.",
        ] {
            let mut server = SplashLanguageServer::with_completion_catalogs(
                ToolCompletionCatalog::default(),
                extension_catalog.clone(),
            );
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .expect("fixed leaf import completion succeeds");
            assert!(!completion.is_incomplete);
            assert!(
                completion.items.is_empty(),
                "advisory metadata extended a fixed core leaf for {source:?}"
            );
        }

        let hostile_member_source = "use mod.std\nstd.log({})";
        let mut hostile_member_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            extension_catalog,
        );
        hostile_member_server.open_document(document(1, hostile_member_source));
        let log_start = hostile_member_source
            .rfind("log")
            .expect("hostile member exists");
        assert!(hostile_member_server
            .hover(
                &test_uri(),
                position_at_byte(hostile_member_source, log_start + 1),
            )
            .expect("fixed leaf hover succeeds")
            .is_none());
        let argument = hostile_member_source.find("{}").expect("call input exists") + 1;
        assert!(hostile_member_server
            .signature_help(
                &test_uri(),
                position_at_byte(hostile_member_source, argument)
            )
            .expect("fixed leaf signature help succeeds")
            .is_none());

        let alias_source = "use mod.std\nlet alias = std\nalias.";
        let mut alias_server = SplashLanguageServer::default();
        alias_server.open_document(document(1, alias_source));
        assert!(alias_server
            .completion(
                &test_uri(),
                position_at_byte(alias_source, alias_source.len())
            )
            .expect("core alias completion request succeeds")
            .items
            .is_empty());

        let unavailable = ModuleCompletionCatalog {
            modules: Vec::new(),
            unavailable: true,
        };
        let mut unavailable_root = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            unavailable.clone(),
        );
        unavailable_root.open_document(document(1, root_source));
        let root_completion = unavailable_root
            .completion(
                &test_uri(),
                position_at_byte(root_source, root_source.len()),
            )
            .expect("unavailable root catalog completion succeeds");
        assert!(root_completion.is_incomplete);
        assert_eq!(root_completion.items.len(), 1);
        assert_eq!(root_completion.items[0].label, "std");

        let mut unavailable_standard = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            unavailable.clone(),
        );
        unavailable_standard.open_document(document(1, standard_source));
        let standard_completion = unavailable_standard
            .completion(
                &test_uri(),
                position_at_byte(standard_source, standard_source.len()),
            )
            .expect("unavailable standard catalog completion succeeds");
        assert!(!standard_completion.is_incomplete);
        assert_eq!(standard_completion.items.len(), 6);

        let leaf_source = "use mod.std.math.";
        let mut unavailable_leaf = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            unavailable,
        );
        unavailable_leaf.open_document(document(1, leaf_source));
        let leaf_completion = unavailable_leaf
            .completion(
                &test_uri(),
                position_at_byte(leaf_source, leaf_source.len()),
            )
            .expect("unavailable fixed leaf completion succeeds");
        assert!(!leaf_completion.is_incomplete);
        assert!(leaf_completion.items.is_empty());
    }

    #[test]
    fn presents_advisory_direct_module_call_modes_without_authority() {
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic",
                "description": "Reviewed arithmetic facade."
            },
            {
                "path": "mod.arithmetic.add",
                "description": "Adds two integers.",
                "callMode": "synchronous"
            },
            {
                "path": "mod.arithmetic.remote_add",
                "description": "Adds two integers through a reviewed remote adapter.",
                "callMode": "deferred"
            }
        ]));
        let source = "use mod.arithmetic\narithmetic.";
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        server.open_document(document(1, source));

        let completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("direct module completion succeeds");
        let synchronous = completion
            .items
            .iter()
            .find(|item| item.label == "add")
            .expect("synchronous method is present");
        assert_eq!(
            synchronous.detail.as_deref(),
            Some("advisory synchronous imported-module member; host module binding required")
        );
        assert_eq!(
            synchronous.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Adds two integers.\n\nAdvisory synchronous method.".to_owned(),
            }))
        );

        let deferred = completion
            .items
            .iter()
            .find(|item| item.label == "remote_add")
            .expect("deferred method is present");
        assert_eq!(
            deferred.detail.as_deref(),
            Some(
                "advisory deferred imported-module member; call returns a promise; host module binding required"
            )
        );
        assert_eq!(
            deferred.documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Adds two integers through a reviewed remote adapter.\n\nAdvisory deferred method; call returns a promise and must use await().".to_owned(),
            }))
        );
        assert!(matches!(
            deferred.text_edit.as_ref(),
            Some(CompletionTextEdit::Edit(TextEdit { new_text, .. })) if new_text == "remote_add"
        ));
        assert!(completion.items.iter().all(|item| {
            item.detail
                .as_deref()
                .is_some_and(|detail| detail.contains("host module binding required"))
        }));
    }

    #[test]
    fn hovers_advisory_direct_module_leaves_without_authority() {
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.remote_add",
                "description": "Adds two integers through a reviewed remote adapter.",
                "callMode": "deferred"
            },
            {
                "path": "mod.arithmetic.metrics.count",
                "description": "Returns a reviewed metric count."
            }
        ]));
        let source = "use mod.arithmetic\narithmetic.remote_add\narithmetic.metrics.count";
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        server.open_document(document(1, source));

        let deferred_member = source.find("remote_add").expect("deferred member exists");
        let deferred_hover = server
            .hover(&test_uri(), position_at_byte(source, deferred_member + 1))
            .expect("direct module hover succeeds")
            .expect("exact deferred catalog leaf has hover metadata");
        assert_eq!(
            deferred_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Advisory imported-module member `mod.arithmetic.remote_add`.\n\nAdds two integers through a reviewed remote adapter.\n\nAdvisory deferred method; call returns a promise and must use await().\n\nAdvisory metadata only; host module binding and any required capability authorization remain host-owned.".to_owned(),
            })
        );
        assert_eq!(
            deferred_hover.range,
            Some(Range::new(
                position_at_byte(source, deferred_member),
                position_at_byte(source, deferred_member + "remote_add".len()),
            ))
        );

        let namespace = source.rfind("metrics").expect("namespace exists");
        assert!(server
            .hover(&test_uri(), position_at_byte(source, namespace + 1))
            .expect("namespace hover request succeeds")
            .is_none());
        let nested_member = source.rfind("count").expect("nested member exists");
        assert_eq!(
            server
                .hover(&test_uri(), position_at_byte(source, nested_member + 1))
                .expect("nested direct module hover succeeds")
                .expect("exact nested catalog leaf has hover metadata")
                .contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Advisory imported-module member `mod.arithmetic.metrics.count`.\n\nReturns a reviewed metric count.\n\nAdvisory metadata only; host module binding and any required capability authorization remain host-owned.".to_owned(),
            })
        );

        let shadowed_source = "use mod.arithmetic\nlet arithmetic = 1\narithmetic.remote_add";
        let mut shadowed_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.arithmetic.remote_add",
                    "callMode": "deferred"
                }
            ])),
        );
        shadowed_server.open_document(document(1, shadowed_source));
        let shadowed_member = shadowed_source.rfind("remote_add").unwrap();
        assert!(shadowed_server
            .hover(
                &test_uri(),
                position_at_byte(shadowed_source, shadowed_member + 1),
            )
            .expect("shadowed hover request succeeds")
            .is_none());

        let invalid_source = "use mod.arithmetic\narithmetic.remote_add\n@";
        let mut invalid_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.arithmetic.remote_add",
                    "callMode": "deferred"
                }
            ])),
        );
        invalid_server.open_document(document(1, invalid_source));
        let invalid_member = invalid_source.find("remote_add").unwrap();
        assert!(invalid_server
            .hover(
                &test_uri(),
                position_at_byte(invalid_source, invalid_member + 1)
            )
            .expect("invalid-source hover request succeeds")
            .is_none());
    }

    #[test]
    fn presents_bounded_capability_signature_help_without_authority() {
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.remote_add",
                "description": "Adds two integers through a reviewed remote adapter.",
                "callMode": "deferred",
                "callShape": "single_json"
            }
        ]));
        let source = concat!(
            "use mod.tool\n",
            "use mod.arithmetic\n",
            "let text = tool.call(\"text.echo\", \"hello\")\n",
            "let result = arithmetic.remote_add({left: 20, right: 22})"
        );
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        server.open_document(document(1, source));

        let text_cursor = source.find("hello").expect("text argument exists") + 1;
        let text_help = server
            .signature_help(&test_uri(), position_at_byte(source, text_cursor))
            .expect("text signature help succeeds")
            .expect("visible mod.tool call has a fixed signature");
        assert_eq!(text_help.signatures.len(), 1);
        assert_eq!(
            text_help.signatures[0].label,
            "tool.call(name, input) -> string"
        );
        assert_eq!(text_help.active_signature, Some(0));
        assert_eq!(text_help.active_parameter, Some(1));
        assert_eq!(
            text_help.signatures[0]
                .parameters
                .as_ref()
                .expect("tool signature has parameters")[1]
                .label,
            ParameterLabel::Simple("input".to_owned())
        );

        let record_cursor = source.find("right:").expect("record field exists") + 1;
        let module_help = server
            .signature_help(&test_uri(), position_at_byte(source, record_cursor))
            .expect("module signature help succeeds")
            .expect("visible advisory module leaf has a signature");
        assert_eq!(module_help.signatures.len(), 1);
        assert_eq!(
            module_help.signatures[0].label,
            "arithmetic.remote_add(input) -> promise<JSON value>"
        );
        // The comma inside the record is not a second direct-module argument.
        assert_eq!(module_help.active_parameter, Some(0));
        assert_eq!(
            module_help.signatures[0].documentation,
            Some(Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Advisory imported-module member `mod.arithmetic.remote_add`.\n\nAdds two integers through a reviewed remote adapter.\n\nAdvisory deferred method; call returns a promise and must use await().\n\nAdvisory metadata only; host module binding and any required capability authorization remain host-owned.".to_owned(),
            }))
        );

        let mode_only_source = "use mod.arithmetic\narithmetic.remote_add({})";
        let mut mode_only_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {"path": "mod.arithmetic.remote_add", "callMode": "deferred"}
            ])),
        );
        mode_only_server.open_document(document(1, mode_only_source));
        assert!(mode_only_server
            .signature_help(
                &test_uri(),
                position_at_byte(mode_only_source, mode_only_source.len() - 1),
            )
            .expect("mode-only signature request succeeds")
            .is_none());

        let incomplete_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.remote_add(",
            "\"",
        );
        let mut incomplete_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.arithmetic.remote_add",
                    "callMode": "deferred",
                    "callShape": "single_json"
                }
            ])),
        );
        incomplete_server.open_document(document(1, incomplete_source));
        assert_eq!(
            incomplete_server
                .signature_help(
                    &test_uri(),
                    position_at_byte(incomplete_source, incomplete_source.len()),
                )
                .expect("incomplete signature request succeeds")
                .expect("in-progress direct call keeps its advisory signature")
                .signatures[0]
                .label,
            "arithmetic.remote_add(input) -> promise<JSON value>"
        );

        let comment_source =
            "use mod.arithmetic\nlet result = arithmetic.remote_add(/* editing */ {})";
        let mut comment_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.arithmetic.remote_add",
                    "callMode": "deferred",
                    "callShape": "single_json"
                }
            ])),
        );
        comment_server.open_document(document(1, comment_source));
        let comment_cursor = comment_source.find("editing").expect("comment exists") + 1;
        assert!(comment_server
            .signature_help(
                &test_uri(),
                position_at_byte(comment_source, comment_cursor)
            )
            .expect("comment signature request succeeds")
            .is_none());

        let shadowed_source = concat!(
            "use mod.arithmetic\n",
            "let arithmetic = {remote_add: || nil}\n",
            "arithmetic.remote_add({})"
        );
        let mut shadowed_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.arithmetic.remote_add",
                    "callMode": "deferred",
                    "callShape": "single_json"
                }
            ])),
        );
        shadowed_server.open_document(document(1, shadowed_source));
        let shadowed_cursor = shadowed_source.rfind("{}").expect("call argument exists") + 1;
        assert!(shadowed_server
            .signature_help(
                &test_uri(),
                position_at_byte(shadowed_source, shadowed_cursor),
            )
            .expect("shadowed signature request succeeds")
            .is_none());
    }

    #[test]
    fn catalog_metadata_follows_stable_exact_root_module_aliases() {
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.add",
                "description": "Adds reviewed integers.",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [
                    {
                        "name": "left",
                        "type": "integer",
                        "required": true
                    },
                    {
                        "name": "right",
                        "type": "integer",
                        "required": false
                    }
                ],
                "outputFields": [
                    {
                        "name": "total",
                        "type": "integer",
                        "required": true
                    }
                ]
            },
            {
                "path": "mod.arithmetic.metrics.count",
                "description": "Returns a reviewed metric count."
            }
        ]));
        let source = concat!(
            "use mod.arithmetic\n",
            "let math = arithmetic\n",
            "let calculator = math\n",
            "let result = calculator.add({left: 20, ri: 22})\n",
            "result.to"
        );
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        server.open_document(document(1, source));

        let input_start = source.find("ri:").expect("partial input field exists");
        assert_eq!(
            server
                .completion(
                    &test_uri(),
                    position_at_byte(source, input_start + "ri".len()),
                )
                .expect("aliased input-field completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["right"]
        );

        let method_start = source.find("add").expect("aliased method exists");
        let hover = server
            .hover(&test_uri(), position_at_byte(source, method_start + 1))
            .expect("aliased module hover succeeds")
            .expect("stable exact alias has advisory hover metadata");
        let HoverContents::Markup(MarkupContent { value, .. }) = hover.contents else {
            panic!("aliased module hover should use markup");
        };
        assert!(value.contains("`mod.arithmetic.add`"));

        let signature = server
            .signature_help(
                &test_uri(),
                position_at_byte(source, input_start + "ri".len()),
            )
            .expect("aliased signature help succeeds")
            .expect("stable exact alias has an advisory signature");
        assert_eq!(
            signature.signatures[0].label,
            "calculator.add(input) -> JSON value"
        );

        let output_start = source.rfind("to").expect("partial output field exists");
        assert_eq!(
            server
                .completion(
                    &test_uri(),
                    position_at_byte(source, output_start + "to".len()),
                )
                .expect("aliased output-field completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );

        let member_source = concat!(
            "use mod.arithmetic\n",
            "let math = arithmetic\n",
            "let calculator = math\n",
            "calculator."
        );
        let mut member_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        member_server.open_document(document(1, member_source));
        assert_eq!(
            member_server
                .completion(
                    &test_uri(),
                    position_at_byte(member_source, member_source.len()),
                )
                .expect("aliased member completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["add", "metrics"]
        );

        let shadowed_import_source = concat!(
            "use mod.arithmetic\n",
            "let math = arithmetic\n",
            "let arithmetic = {}\n",
            "math."
        );
        let mut shadowed_import_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        shadowed_import_server.open_document(document(1, shadowed_import_source));
        assert_eq!(
            shadowed_import_server
                .completion(
                    &test_uri(),
                    position_at_byte(shadowed_import_source, shadowed_import_source.len()),
                )
                .expect("source-position-aware alias completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["add", "metrics"]
        );

        let nested_source = concat!(
            "use mod.arithmetic\n",
            "let math = arithmetic\n",
            "let calculator = math\n",
            "calculator.metrics."
        );
        let mut nested_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        nested_server.open_document(document(1, nested_source));
        assert_eq!(
            nested_server
                .completion(
                    &test_uri(),
                    position_at_byte(nested_source, nested_source.len()),
                )
                .expect("aliased nested member completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["count"]
        );

        let mut bounded_source = String::from("use mod.arithmetic\n");
        let mut previous = "arithmetic".to_owned();
        for index in 0..splash_core::MAX_IMPORTED_MODULE_ALIAS_DEPTH {
            let alias = format!("alias_{index}");
            bounded_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        bounded_source.push_str(&format!("{previous}."));
        let mut bounded_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        bounded_server.open_document(document(1, &bounded_source));
        assert_eq!(
            bounded_server
                .completion(
                    &test_uri(),
                    position_at_byte(&bounded_source, bounded_source.len()),
                )
                .expect("bounded alias completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["add", "metrics"]
        );
    }

    #[test]
    fn catalog_module_aliases_fail_closed_and_never_alias_mod_tool() {
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [
                    {
                        "name": "right",
                        "type": "integer",
                        "required": false
                    }
                ],
                "outputFields": [
                    {
                        "name": "total",
                        "type": "integer",
                        "required": true
                    }
                ]
            }
        ]));

        for source in [
            concat!(
                "use mod.arithmetic\n",
                "let math = arithmetic\n",
                "math = {}\n",
                "math."
            ),
            concat!(
                "use mod.arithmetic\n",
                "let math = arithmetic\n",
                "let sibling = math\n",
                "sibling.add = nil\n",
                "math."
            ),
            concat!(
                "use mod.arithmetic\n",
                "let math = arithmetic\n",
                "let method = math.add\n",
                "math."
            ),
            concat!(
                "use mod.arithmetic\n",
                "let math = arithmetic\n",
                "let parenthesized = (math)\n",
                "math."
            ),
            concat!(
                "use mod.arithmetic\n",
                "let math = arithmetic.metrics\n",
                "math."
            ),
        ] {
            let mut server = SplashLanguageServer::with_completion_catalogs(
                ToolCompletionCatalog::default(),
                catalog.clone(),
            );
            server.open_document(document(1, source));
            assert!(
                server
                    .completion(&test_uri(), position_at_byte(source, source.len()))
                    .expect("unsafe alias completion request succeeds")
                    .items
                    .is_empty(),
                "catalog metadata must fail closed for {source:?}"
            );
        }

        let mut over_depth_source = String::from("use mod.arithmetic\n");
        let mut previous = "arithmetic".to_owned();
        for index in 0..=splash_core::MAX_IMPORTED_MODULE_ALIAS_DEPTH {
            let alias = format!("alias_{index}");
            over_depth_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        over_depth_source.push_str(&format!("{previous}."));
        let mut over_depth_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        over_depth_server.open_document(document(1, &over_depth_source));
        assert!(over_depth_server
            .completion(
                &test_uri(),
                position_at_byte(&over_depth_source, over_depth_source.len()),
            )
            .expect("over-depth alias completion request succeeds")
            .items
            .is_empty());

        let mut truncated_import_source = String::from("use mod.arithmetic\n");
        for index in 0..=splash_core::MAX_MODULE_IMPORTS {
            truncated_import_source.push_str(&format!("use mod.module_{index}\n"));
        }
        truncated_import_source.push_str("let math = arithmetic\nmath.");
        let mut truncated_import_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        truncated_import_server.open_document(document(1, &truncated_import_source));
        let truncated_import_completion = truncated_import_server
            .completion(
                &test_uri(),
                position_at_byte(&truncated_import_source, truncated_import_source.len()),
            )
            .expect("truncated import alias completion request succeeds");
        assert!(truncated_import_completion.is_incomplete);
        assert!(truncated_import_completion.items.is_empty());

        let mut truncated_alias_prefix = String::from("use mod.arithmetic\n");
        for index in 0..=MAX_STATIC_RECORD_ALIASES {
            truncated_alias_prefix.push_str(&format!("let alias_{index} = arithmetic\n"));
        }

        let mut direct_import_source = truncated_alias_prefix.clone();
        direct_import_source.push_str("arithmetic.");
        let mut direct_import_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        direct_import_server.open_document(document(1, &direct_import_source));
        let direct_import_completion = direct_import_server
            .completion(
                &test_uri(),
                position_at_byte(&direct_import_source, direct_import_source.len()),
            )
            .expect("truncated alias direct-import completion request succeeds");
        assert!(!direct_import_completion.is_incomplete);
        assert_eq!(
            direct_import_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["add"]
        );

        let mut truncated_alias_source = truncated_alias_prefix.clone();
        truncated_alias_source.push_str("alias_0.");
        let mut truncated_alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        truncated_alias_server.open_document(document(1, &truncated_alias_source));
        let truncated_alias_completion = truncated_alias_server
            .completion(
                &test_uri(),
                position_at_byte(&truncated_alias_source, truncated_alias_source.len()),
            )
            .expect("truncated alias completion request succeeds");
        assert!(truncated_alias_completion.is_incomplete);
        assert!(truncated_alias_completion.items.is_empty());

        let mut truncated_input_source = truncated_alias_prefix.clone();
        truncated_input_source.push_str("let result = alias_0.add({ri: 22})");
        let mut truncated_input_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        truncated_input_server.open_document(document(1, &truncated_input_source));
        let input_start = truncated_input_source
            .rfind("ri:")
            .expect("truncated input field exists");
        let truncated_input_completion = truncated_input_server
            .completion(
                &test_uri(),
                position_at_byte(&truncated_input_source, input_start + "ri".len()),
            )
            .expect("truncated input alias completion request succeeds");
        assert!(truncated_input_completion.is_incomplete);
        assert!(truncated_input_completion.items.is_empty());

        let mut truncated_output_source = truncated_alias_prefix;
        truncated_output_source.push_str("let result = alias_0.add({})\nresult.to");
        let mut truncated_output_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        truncated_output_server.open_document(document(1, &truncated_output_source));
        let output_start = truncated_output_source
            .rfind("to")
            .expect("truncated output field exists");
        let truncated_output_completion = truncated_output_server
            .completion(
                &test_uri(),
                position_at_byte(&truncated_output_source, output_start + "to".len()),
            )
            .expect("truncated output alias completion request succeeds");
        assert!(truncated_output_completion.is_incomplete);
        assert!(truncated_output_completion.items.is_empty());

        let tool_alias_source = concat!("use mod.tool\n", "let tool_alias = tool\n", "tool_alias.");
        let mut tool_alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            ModuleCompletionCatalog::default(),
        );
        tool_alias_server.open_document(document(1, tool_alias_source));
        assert!(tool_alias_server
            .completion(
                &test_uri(),
                position_at_byte(tool_alias_source, tool_alias_source.len()),
            )
            .expect("tool alias completion request succeeds")
            .items
            .is_empty());

        let tool_alias_signature_source = concat!(
            "use mod.tool\n",
            "let tool_alias = tool\n",
            "tool_alias.call(\"text.echo\", \"hello\")"
        );
        let mut tool_alias_signature_server = SplashLanguageServer::default();
        tool_alias_signature_server.open_document(document(1, tool_alias_signature_source));
        let tool_alias_argument = tool_alias_signature_source
            .find("hello")
            .expect("tool alias argument exists");
        assert!(tool_alias_signature_server
            .signature_help(
                &test_uri(),
                position_at_byte(tool_alias_signature_source, tool_alias_argument + 1),
            )
            .expect("tool alias signature request succeeds")
            .is_none());
    }

    #[test]
    fn presents_advisory_direct_module_record_fields_in_hover_and_signature_help() {
        let source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, right: 22})"
        );
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {
                    "path": "mod.arithmetic.add",
                    "description": "Adds reviewed integers.",
                    "callMode": "synchronous",
                    "callShape": "single_json",
                    "inputFields": [
                        {
                            "name": "left",
                            "type": "integer",
                            "required": true,
                            "description": "First addend."
                        },
                        {
                            "name": "right",
                            "type": "integer",
                            "required": false
                        },
                        {
                            "name": "filters",
                            "type": "object",
                            "required": false,
                            "description": "Reviewed filters.",
                            "fields": [
                                {
                                    "name": "category",
                                    "type": "string",
                                    "required": true,
                                    "description": "Requested category."
                                }
                            ]
                        }
                    ],
                    "outputFields": [
                        {
                            "name": "total",
                            "type": "integer",
                            "required": true,
                            "description": "Sum of both addends."
                        }
                    ]
                }
            ])),
        );
        server.open_document(document(1, source));

        let member_start = source.find("add").expect("direct method exists");
        let hover = server
            .hover(&test_uri(), position_at_byte(source, member_start + 1))
            .expect("module hover succeeds")
            .expect("visible shaped module method has hover metadata");
        let HoverContents::Markup(MarkupContent { value, .. }) = hover.contents else {
            panic!("module hover should use plain-text markup");
        };
        assert!(value.contains("Advisory input record fields:"));
        assert!(value.contains("- left: integer (required); First addend."));
        assert!(value.contains("- right: integer (optional)"));
        assert!(value.contains("- filters: object (optional); Reviewed filters."));
        assert!(value.contains("- filters.category: string (required); Requested category."));
        assert!(value.contains("Advisory output record fields:"));
        assert!(value.contains("- total: integer (required); Sum of both addends."));
        assert!(value.contains("capability authorization remain host-owned"));

        let field_cursor = source.find("right:").expect("second field exists") + 1;
        let signature = server
            .signature_help(&test_uri(), position_at_byte(source, field_cursor))
            .expect("module signature help succeeds")
            .expect("visible shaped module method has a signature");
        assert_eq!(
            signature.signatures[0].label,
            "arithmetic.add(input) -> JSON value"
        );
        let Some(Documentation::MarkupContent(MarkupContent { value, .. })) =
            signature.signatures[0].documentation.as_ref()
        else {
            panic!("module signature should carry plain-text documentation");
        };
        assert!(value.contains("- left: integer (required); First addend."));
        assert!(value.contains("- right: integer (optional)"));
        assert!(value.contains("- filters.category: string (required); Requested category."));
        assert!(value.contains("- total: integer (required); Sum of both addends."));
    }

    #[test]
    fn completes_advisory_direct_module_input_record_fields_without_authority() {
        let source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, ri: 22})"
        );
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [
                    {
                        "name": "left",
                        "type": "integer",
                        "required": true,
                        "description": "First addend."
                    },
                    {
                        "name": "right",
                        "type": "integer",
                        "required": false,
                        "description": "Second addend."
                    }
                ]
            }
        ]));
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        server.open_document(document(1, source));

        let field_start = source.find("ri:").expect("partial record field exists");
        let completion = server
            .completion(
                &test_uri(),
                position_at_byte(source, field_start + "ri".len()),
            )
            .expect("direct input field completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["right"]
        );
        let item = completion
            .items
            .first()
            .expect("one undeclared field remains");
        assert_eq!(
            item.detail.as_deref(),
            Some("advisory direct-module input field; optional")
        );
        assert!(matches!(
            &item.text_edit,
            Some(CompletionTextEdit::Edit(TextEdit { range, new_text }))
                if *range == Range::new(
                    position_at_byte(source, field_start),
                    position_at_byte(source, field_start + "ri".len()),
                ) && new_text == "right"
        ));
        let Some(Documentation::MarkupContent(MarkupContent { value, .. })) =
            item.documentation.as_ref()
        else {
            panic!("direct input field documentation should be plain text");
        };
        assert!(value.contains("Type: integer"));
        assert!(value.contains("Required: no"));
        assert!(value.contains("Second addend."));
        assert!(value.contains("capability authorization remain host-owned"));

        let empty_source = concat!("use mod.arithmetic\n", "let result = arithmetic.add({})");
        let mut empty_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        empty_server.open_document(document(1, empty_source));
        let empty_cursor = empty_source.find("{}").expect("empty record exists") + 1;
        let empty_completion = empty_server
            .completion(&test_uri(), position_at_byte(empty_source, empty_cursor))
            .expect("empty direct record completion succeeds");
        assert_eq!(
            empty_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["left", "right"]
        );
        assert!(empty_completion.items.iter().all(|item| {
            matches!(
                &item.text_edit,
                Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                    if *range == Range::new(
                        position_at_byte(empty_source, empty_cursor),
                        position_at_byte(empty_source, empty_cursor),
                    )
            )
        }));

        let duplicate_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, left: 21, ri: 22})"
        );
        let mut duplicate_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        duplicate_server.open_document(document(1, duplicate_source));
        let duplicate_cursor = duplicate_source
            .rfind("ri:")
            .expect("partial duplicate-record field exists")
            + "ri".len();
        assert!(duplicate_server
            .completion(
                &test_uri(),
                position_at_byte(duplicate_source, duplicate_cursor),
            )
            .expect("duplicate record completion request succeeds")
            .items
            .is_empty());

        let malformed_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: , ri: 22})"
        );
        let mut malformed_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        malformed_server.open_document(document(1, malformed_source));
        let malformed_cursor = malformed_source
            .find("ri:")
            .expect("field after malformed prefix exists")
            + "ri".len();
        assert!(malformed_server
            .completion(
                &test_uri(),
                position_at_byte(malformed_source, malformed_cursor),
            )
            .expect("malformed record completion request succeeds")
            .items
            .is_empty());

        let nested_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: {ri: 22}})"
        );
        let nested_cursor = nested_source.find("ri:").expect("nested field exists") + "ri".len();
        let nested_site = direct_module_input_record_completion_site(nested_source, nested_cursor)
            .expect("direct child record completion site is recognized");
        assert_eq!(nested_site.parent_field.as_deref(), Some("left"));
        assert!(nested_site.declared_fields.is_empty());

        let shadowed_source = concat!(
            "use mod.arithmetic\n",
            "let arithmetic = {add: || nil}\n",
            "let result = arithmetic.add({ri: 22})"
        );
        let mut shadowed_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        shadowed_server.open_document(document(1, shadowed_source));
        let shadowed_cursor =
            shadowed_source.find("ri:").expect("shadowed field exists") + "ri".len();
        assert!(shadowed_server
            .completion(
                &test_uri(),
                position_at_byte(shadowed_source, shadowed_cursor),
            )
            .expect("shadowed record completion request succeeds")
            .items
            .is_empty());
    }

    #[test]
    fn completes_one_nested_advisory_direct_module_input_field_level() {
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.inspect",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [
                    {
                        "name": "filters",
                        "type": "object",
                        "required": true,
                        "description": "Reviewed filters.",
                        "fields": [
                            {
                                "name": "category",
                                "type": "string",
                                "required": true,
                                "description": "Requested category."
                            },
                            {
                                "name": "limit",
                                "type": "integer",
                                "required": false
                            },
                            {
                                "name": "range",
                                "type": "object",
                                "required": false
                            }
                        ]
                    },
                    {
                        "name": "verbose",
                        "type": "boolean",
                        "required": false
                    }
                ]
            }
        ]));
        let source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({filters: {ca: \"news\"}})"
        );
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        server.open_document(document(1, source));
        let field_start = source.find("ca:").expect("partial child field exists");
        let completion = server
            .completion(
                &test_uri(),
                position_at_byte(source, field_start + "ca".len()),
            )
            .expect("nested input field completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["category", "limit", "range"]
        );
        let category = completion
            .items
            .iter()
            .find(|item| item.label == "category")
            .expect("nested category is completed");
        assert_eq!(
            category.detail.as_deref(),
            Some("advisory direct-module input field; required")
        );
        assert!(matches!(
            &category.text_edit,
            Some(CompletionTextEdit::Edit(TextEdit { range, new_text }))
                if *range == Range::new(
                    position_at_byte(source, field_start),
                    position_at_byte(source, field_start + "ca".len()),
                ) && new_text == "category"
        ));
        let Some(Documentation::MarkupContent(MarkupContent { value, .. })) =
            category.documentation.as_ref()
        else {
            panic!("nested input field documentation should be plain text");
        };
        assert!(value.contains("Requested category."));
        assert!(value.contains("capability authorization remain host-owned"));

        let hover_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({filters: {category: \"news\"}})"
        );
        let mut hover_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        hover_server.open_document(document(1, hover_source));
        let filters_start = hover_source.find("filters:").expect("root field exists");
        let filters_hover = hover_server
            .hover(
                &test_uri(),
                position_at_byte(hover_source, filters_start + 1),
            )
            .expect("root input-field hover succeeds")
            .expect("reviewed root input field has hover metadata");
        assert_eq!(
            filters_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Advisory direct-module input field `filters`.\nType: object\nRequired: yes\n\nReviewed filters.\n\nAdvisory metadata only; host module binding and any required capability authorization remain host-owned.".to_owned(),
            })
        );
        assert_eq!(
            filters_hover.range,
            Some(Range::new(
                position_at_byte(hover_source, filters_start),
                position_at_byte(hover_source, filters_start + "filters".len()),
            ))
        );

        let category_start = hover_source.find("category:").expect("child field exists");
        let category_hover = hover_server
            .hover(
                &test_uri(),
                position_at_byte(hover_source, category_start + 1),
            )
            .expect("child input-field hover succeeds")
            .expect("reviewed child input field has hover metadata");
        assert_eq!(
            category_hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Advisory direct-module input field `category`.\nType: string\nRequired: yes\n\nRequested category.\n\nAdvisory metadata only; host module binding and any required capability authorization remain host-owned.".to_owned(),
            })
        );
        assert_eq!(
            category_hover.range,
            Some(Range::new(
                position_at_byte(hover_source, category_start),
                position_at_byte(hover_source, category_start + "category".len()),
            ))
        );

        let empty_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({filters: {}})"
        );
        let mut empty_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        empty_server.open_document(document(1, empty_source));
        let empty_cursor = empty_source.find("{}").expect("empty child record exists") + 1;
        assert_eq!(
            empty_server
                .completion(&test_uri(), position_at_byte(empty_source, empty_cursor))
                .expect("empty child record completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["category", "limit", "range"]
        );

        let sibling_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({filters: {}, ve: true})"
        );
        let mut sibling_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        sibling_server.open_document(document(1, sibling_source));
        let sibling_cursor = sibling_source.find("ve:").expect("root sibling exists") + "ve".len();
        assert_eq!(
            sibling_server
                .completion(
                    &test_uri(),
                    position_at_byte(sibling_source, sibling_cursor)
                )
                .expect("root field after child record completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["verbose"]
        );

        let alias_source = concat!(
            "use mod.arithmetic\n",
            "let math = arithmetic\n",
            "let result = math.inspect({filters: {}})"
        );
        let mut alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        alias_server.open_document(document(1, alias_source));
        let alias_cursor = alias_source.find("{}").expect("empty child record exists") + 1;
        assert_eq!(
            alias_server
                .completion(&test_uri(), position_at_byte(alias_source, alias_cursor))
                .expect("aliased child record completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["category", "limit", "range"]
        );

        let duplicate_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({filters: {category: \"news\", category: \"sports\", li: 2}})"
        );
        let mut duplicate_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        duplicate_server.open_document(document(1, duplicate_source));
        let duplicate_cursor = duplicate_source
            .rfind("li:")
            .expect("partial child field exists")
            + "li".len();
        assert!(duplicate_server
            .completion(
                &test_uri(),
                position_at_byte(duplicate_source, duplicate_cursor),
            )
            .expect("duplicate child record completion request succeeds")
            .items
            .is_empty());
        let duplicate_key_start = duplicate_source
            .rfind("category:")
            .expect("second duplicate child field exists");
        assert!(duplicate_server
            .hover(
                &test_uri(),
                position_at_byte(duplicate_source, duplicate_key_start + 1),
            )
            .expect("duplicate child hover request succeeds")
            .is_none());

        let deeper_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({filters: {range: {mi: 1}}})"
        );
        let deeper_cursor = deeper_source.find("mi:").expect("deeper field exists") + "mi".len();
        assert!(direct_module_input_record_completion_site(deeper_source, deeper_cursor).is_none());

        let scalar_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({verbose: {va: true}})"
        );
        let mut scalar_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        scalar_server.open_document(document(1, scalar_source));
        let scalar_cursor = scalar_source
            .find("va:")
            .expect("scalar child field exists")
            + "va".len();
        assert!(scalar_server
            .completion(&test_uri(), position_at_byte(scalar_source, scalar_cursor))
            .expect("scalar input child completion request succeeds")
            .items
            .is_empty());
    }

    #[test]
    fn completes_and_hovers_advisory_direct_module_output_fields_without_authority() {
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": [
                    {
                        "name": "total",
                        "type": "integer",
                        "required": true,
                        "description": "Reviewed sum."
                    }
                ]
            },
            {
                "path": "mod.arithmetic.remote_add",
                "callMode": "deferred",
                "callShape": "single_json",
                "outputFields": [
                    {
                        "name": "total",
                        "type": "integer",
                        "required": true
                    }
                ]
            }
        ]));
        let source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, right: 22})\n",
            "result.to"
        );
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        server.open_document(document(1, source));

        let field_start = source.rfind("to").expect("partial output field exists");
        let completion = server
            .completion(
                &test_uri(),
                position_at_byte(source, field_start + "to".len()),
            )
            .expect("direct output field completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );
        let item = completion
            .items
            .first()
            .expect("one projected output field remains");
        assert_eq!(
            item.detail.as_deref(),
            Some("advisory direct-module output field; required")
        );
        assert!(matches!(
            &item.text_edit,
            Some(CompletionTextEdit::Edit(TextEdit { range, new_text }))
                if *range == Range::new(
                    position_at_byte(source, field_start),
                    position_at_byte(source, field_start + "to".len()),
                ) && new_text == "total"
        ));
        let Some(Documentation::MarkupContent(MarkupContent { value, .. })) =
            item.documentation.as_ref()
        else {
            panic!("direct output field documentation should be plain text");
        };
        assert!(value.contains("Advisory direct-module output field `total`."));
        assert!(value.contains("Type: integer"));
        assert!(value.contains("Required: yes"));
        assert!(value.contains("Reviewed sum."));
        assert!(value.contains("does not inspect a runtime result"));

        let empty_member_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, right: 22})\n",
            "result."
        );
        let mut empty_member_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        empty_member_server.open_document(document(1, empty_member_source));
        let empty_member_completion = empty_member_server
            .completion(
                &test_uri(),
                position_at_byte(empty_member_source, empty_member_source.len()),
            )
            .expect("empty output member completion succeeds");
        assert_eq!(
            empty_member_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );
        assert!(matches!(
            &empty_member_completion.items[0].text_edit,
            Some(CompletionTextEdit::Edit(TextEdit { range, .. }))
                if *range == Range::new(
                    position_at_byte(empty_member_source, empty_member_source.len()),
                    position_at_byte(empty_member_source, empty_member_source.len()),
                )
        ));

        let mut unavailable_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            unavailable_module_completion_catalog(),
        );
        unavailable_server.open_document(document(1, source));
        let unavailable_completion = unavailable_server
            .completion(
                &test_uri(),
                position_at_byte(source, field_start + "to".len()),
            )
            .expect("unavailable output catalog completion succeeds");
        assert!(unavailable_completion.is_incomplete);
        assert!(unavailable_completion.items.is_empty());

        let hover_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, right: 22})\n",
            "result.total"
        );
        let mut hover_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        hover_server.open_document(document(1, hover_source));
        let total_start = hover_source.rfind("total").expect("output field exists");
        let hover = hover_server
            .hover(&test_uri(), position_at_byte(hover_source, total_start + 1))
            .expect("direct output field hover succeeds")
            .expect("known output field has hover metadata");
        assert_eq!(
            hover.range,
            Some(Range::new(
                position_at_byte(hover_source, total_start),
                position_at_byte(hover_source, total_start + "total".len()),
            ))
        );
        assert_eq!(
            hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Advisory direct-module output field `total`.\nType: integer\nRequired: yes\n\nReviewed sum.\n\nAdvisory metadata only; it does not inspect a runtime result or grant a capability.".to_owned(),
            })
        );

        let deferred_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.remote_add({left: 20, right: 22}).await()\n",
            "result.to"
        );
        let mut deferred_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        deferred_server.open_document(document(1, deferred_source));
        let deferred_cursor = deferred_source.rfind("to").expect("output field exists") + 2;
        assert_eq!(
            deferred_server
                .completion(
                    &test_uri(),
                    position_at_byte(deferred_source, deferred_cursor),
                )
                .expect("deferred output completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );

        let deferred_alias_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.remote_add({left: 20, right: 22}).await()\n",
            "let alias = result\n",
            "alias.to"
        );
        let mut deferred_alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        deferred_alias_server.open_document(document(1, deferred_alias_source));
        let deferred_alias_cursor = deferred_alias_source
            .rfind("to")
            .expect("aliased output field exists")
            + "to".len();
        assert_eq!(
            deferred_alias_server
                .completion(
                    &test_uri(),
                    position_at_byte(deferred_alias_source, deferred_alias_cursor),
                )
                .expect("deferred aliased output completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );

        let alias_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, right: 22})\n",
            "let first = result\n",
            "let second = first\n",
            "second.to"
        );
        let mut alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        alias_server.open_document(document(1, alias_source));
        let alias_cursor = alias_source.rfind("to").expect("aliased field exists") + 2;
        assert_eq!(
            alias_server
                .completion(&test_uri(), position_at_byte(alias_source, alias_cursor))
                .expect("aliased output completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );

        let alias_hover_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, right: 22})\n",
            "let alias = result\n",
            "alias.total"
        );
        let mut alias_hover_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        alias_hover_server.open_document(document(1, alias_hover_source));
        let alias_total_start = alias_hover_source
            .rfind("total")
            .expect("aliased output field exists");
        assert!(alias_hover_server
            .hover(
                &test_uri(),
                position_at_byte(alias_hover_source, alias_total_start + 1),
            )
            .expect("aliased output hover succeeds")
            .is_some());

        let root_after_alias_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, right: 22})\n",
            "let alias = result\n",
            "result.to"
        );
        let mut root_after_alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        root_after_alias_server.open_document(document(1, root_after_alias_source));
        assert_eq!(
            root_after_alias_server
                .completion(
                    &test_uri(),
                    position_at_byte(root_after_alias_source, root_after_alias_source.len()),
                )
                .expect("root output completion after exact alias succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );

        let mut later_alias_source = String::from(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, right: 22})\n",
            "result.to\n"
        ));
        let root_cursor = later_alias_source.rfind("to").expect("output field exists") + "to".len();
        let mut previous = "result".to_owned();
        for index in 0..=MAX_DIRECT_MODULE_OUTPUT_ALIAS_DEPTH {
            let alias = format!("later_alias_{index}");
            later_alias_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        let mut later_alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        later_alias_server.open_document(document(1, &later_alias_source));
        assert!(later_alias_server
            .completion(
                &test_uri(),
                position_at_byte(&later_alias_source, root_cursor),
            )
            .expect("over-depth later aliases suppress root output metadata")
            .items
            .is_empty());

        let mut bounded_later_alias_source = String::from(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20, right: 22})\n",
            "result.to\n"
        ));
        let bounded_root_cursor = bounded_later_alias_source
            .rfind("to")
            .expect("output field exists")
            + "to".len();
        let mut previous = "result".to_owned();
        for index in 0..MAX_DIRECT_MODULE_OUTPUT_ALIAS_DEPTH {
            let alias = format!("bounded_later_alias_{index}");
            bounded_later_alias_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        let mut bounded_later_alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        bounded_later_alias_server.open_document(document(1, &bounded_later_alias_source));
        assert_eq!(
            bounded_later_alias_server
                .completion(
                    &test_uri(),
                    position_at_byte(&bounded_later_alias_source, bounded_root_cursor),
                )
                .expect("bounded later aliases preserve root output metadata")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );

        let assert_no_output_completion = |source: &str| {
            let mut server = SplashLanguageServer::with_completion_catalogs(
                ToolCompletionCatalog::default(),
                catalog.clone(),
            );
            server.open_document(document(1, source));
            let field_start = source.rfind("to").expect("test source has output member");
            assert!(server
                .completion(
                    &test_uri(),
                    position_at_byte(source, field_start + "to".len()),
                )
                .expect("refused output completion request succeeds")
                .items
                .is_empty());
        };
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.remote_add({left: 20})\n",
            "result.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20}).await()\n",
            "result.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = (arithmetic.add({left: 20}))\n",
            "result.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20}).parse_json()\n",
            "result.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20}, {right: 22})\n",
            "result.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "let alias = (result)\n",
            "alias.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "let alias = result\n",
            "alias.extra = 1\n",
            "alias.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "let alias = result\n",
            "send(alias)\n",
            "alias.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "fn inspect() {\n",
            "    result.to\n",
            "}\n",
            "result.extra = 1\n",
            "inspect()"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "result.extra = 1\n",
            "result.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "result.total.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "let selected = result.total\n",
            "result.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "let selected = result.total.extra\n",
            "result.to"
        ));
        assert_no_output_completion(concat!(
            "use mod.arithmetic\n",
            "let arithmetic = {add: || nil}\n",
            "let result = arithmetic.add({left: 20})\n",
            "result.to"
        ));
        let oversized_trivia_source = format!(
            "use mod.arithmetic\nlet result = {}arithmetic.add({{left: 20}})\nresult.to",
            " ".repeat(MAX_LSP_DIRECT_MODULE_OUTPUT_INITIALIZER_BYTES + 1),
        );
        assert_no_output_completion(&oversized_trivia_source);

        let mut bounded_alias_source =
            String::from("use mod.arithmetic\nlet result = arithmetic.add({left: 20})\n");
        let mut previous = "result".to_owned();
        for index in 0..MAX_DIRECT_MODULE_OUTPUT_ALIAS_DEPTH {
            let alias = format!("alias_{index}");
            bounded_alias_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        bounded_alias_source.push_str(&format!("{previous}.to"));
        let mut bounded_alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        bounded_alias_server.open_document(document(1, &bounded_alias_source));
        assert_eq!(
            bounded_alias_server
                .completion(
                    &test_uri(),
                    position_at_byte(&bounded_alias_source, bounded_alias_source.len()),
                )
                .expect("bounded output alias completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["total"]
        );

        let mut too_deep_alias_source =
            String::from("use mod.arithmetic\nlet result = arithmetic.add({left: 20})\n");
        let mut previous = "result".to_owned();
        for index in 0..=MAX_DIRECT_MODULE_OUTPUT_ALIAS_DEPTH {
            let alias = format!("alias_{index}");
            too_deep_alias_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        too_deep_alias_source.push_str(&format!("{previous}.to"));
        assert_no_output_completion(&too_deep_alias_source);

        let mut truncated_alias_source =
            String::from("use mod.arithmetic\nlet result = arithmetic.add({left: 20})\n");
        let mut previous = "result".to_owned();
        for index in 0..=MAX_STATIC_RECORD_ALIASES {
            let alias = format!("truncated_alias_{index}");
            truncated_alias_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        truncated_alias_source.push_str(&format!("{previous}.to"));
        assert_no_output_completion(&truncated_alias_source);

        let mut truncated_root_source = String::from(concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "result.to\n"
        ));
        let truncated_root_cursor = truncated_root_source
            .rfind("to")
            .expect("output field exists")
            + "to".len();
        let mut previous = "result".to_owned();
        for index in 0..=MAX_STATIC_RECORD_ALIASES {
            let alias = format!("truncated_root_alias_{index}");
            truncated_root_source.push_str(&format!("let {alias} = {previous}\n"));
            previous = alias;
        }
        let mut truncated_root_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        truncated_root_server.open_document(document(1, &truncated_root_source));
        let truncated_root_completion = truncated_root_server
            .completion(
                &test_uri(),
                position_at_byte(&truncated_root_source, truncated_root_cursor),
            )
            .expect("truncated root alias output completion request succeeds");
        assert!(truncated_root_completion.is_incomplete);
        assert!(truncated_root_completion.items.is_empty());

        let no_output_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.add({left: 20})\n",
            "result.to"
        );
        let no_output_catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.add",
                "callMode": "synchronous",
                "callShape": "single_json"
            }
        ]));
        let mut no_output_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            no_output_catalog,
        );
        no_output_server.open_document(document(1, no_output_source));
        let no_output_cursor = no_output_source.rfind("to").expect("output member exists") + 2;
        assert!(no_output_server
            .completion(
                &test_uri(),
                position_at_byte(no_output_source, no_output_cursor),
            )
            .expect("missing output projection completion succeeds")
            .items
            .is_empty());
    }

    #[test]
    fn completes_and_hovers_one_nested_advisory_direct_module_output_field_level() {
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.inspect",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": [
                    {
                        "name": "summary",
                        "type": "object",
                        "required": true,
                        "description": "Reviewed aggregate.",
                        "fields": [
                            {
                                "name": "origin",
                                "type": "string",
                                "required": false
                            },
                            {
                                "name": "total",
                                "type": "integer",
                                "required": true,
                                "description": "Nested total."
                            }
                        ]
                    }
                ]
            }
        ]));
        let source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({left: 20})\n",
            "result.summary."
        );
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        server.open_document(document(1, source));
        let completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("nested output completion succeeds");
        assert!(!completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["origin", "total"]
        );
        assert!(completion.items.iter().all(|item| {
            item.detail.as_deref() == Some("advisory direct-module output field; optional")
                || item.detail.as_deref() == Some("advisory direct-module output field; required")
        }));

        let alias_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({left: 20})\n",
            "let alias = result\n",
            "alias.summary."
        );
        let mut alias_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        alias_server.open_document(document(1, alias_source));
        assert_eq!(
            alias_server
                .completion(
                    &test_uri(),
                    position_at_byte(alias_source, alias_source.len())
                )
                .expect("nested aliased output completion succeeds")
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["origin", "total"]
        );

        let hover_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({left: 20})\n",
            "result.summary.total"
        );
        let mut hover_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog.clone(),
        );
        hover_server.open_document(document(1, hover_source));
        let total_start = hover_source.rfind("total").expect("nested field exists");
        let hover = hover_server
            .hover(&test_uri(), position_at_byte(hover_source, total_start + 1))
            .expect("nested output hover succeeds")
            .expect("nested output field has hover metadata");
        assert_eq!(
            hover.contents,
            HoverContents::Markup(MarkupContent {
                kind: MarkupKind::PlainText,
                value: "Advisory direct-module output field `total`.\nType: integer\nRequired: yes\n\nNested total.\n\nAdvisory metadata only; it does not inspect a runtime result or grant a capability.".to_owned(),
            })
        );

        let deeper_source = concat!(
            "use mod.arithmetic\n",
            "let result = arithmetic.inspect({left: 20})\n",
            "result.summary.total."
        );
        let mut deeper_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        deeper_server.open_document(document(1, deeper_source));
        assert!(deeper_server
            .completion(
                &test_uri(),
                position_at_byte(deeper_source, deeper_source.len()),
            )
            .expect("unsupported nested output completion request succeeds")
            .items
            .is_empty());
    }

    #[test]
    fn module_catalog_projection_is_bounded_and_fails_closed_when_malformed() {
        let params = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "moduleCatalog": [
                        {"path": "mod.std.log", "description": "log"},
                        {"path": "mod.math.sin", "description": "sine"}
                    ]
                }
            })),
            ..InitializeParams::default()
        };
        let catalog = module_completion_catalog_from_initialize_options(&params);
        assert!(!catalog.unavailable);
        assert_eq!(
            catalog
                .modules
                .iter()
                .map(|module| module.path.join("."))
                .collect::<Vec<_>>(),
            ["mod.math.sin", "mod.std.log"]
        );

        let invalid_params = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "moduleCatalog": [
                        {"path": "mod.std.123", "description": "invalid"}
                    ]
                }
            })),
            ..InitializeParams::default()
        };
        let invalid = module_completion_catalog_from_initialize_options(&invalid_params);
        assert!(invalid.unavailable);
        assert!(invalid.modules.is_empty());

        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.std.log", "callMode": "unknown"}
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.std.log", "callMode": 42}
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.std.log", "callMode": "deferred", "callShape": "unknown"}
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.std.log", "callMode": "deferred", "callShape": 42}
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.std.log", "callShape": "single_json"}
        ]))
        .is_none());
        let mode_only = parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.std.log", "callMode": "deferred"}
        ]))
        .expect("mode-only catalog entry remains valid");
        assert_eq!(mode_only.modules[0].call_shape, None);
        let shaped = parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.std.log",
                "callMode": "deferred",
                "callShape": "single_json"
            }
        ]))
        .expect("recognized call shape is retained");
        assert_eq!(
            shaped.modules[0].call_shape,
            Some(ModuleCatalogCallShape::SingleJson)
        );
        let shaped_with_fields = parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [
                    {
                        "name": "left",
                        "type": "integer",
                        "required": true,
                        "description": "Left addend."
                    },
                    {"name": "right", "type": "integer", "required": false}
                ],
                "outputFields": [
                    {
                        "name": "total",
                        "type": "integer",
                        "required": true,
                        "description": "Reviewed sum."
                    }
                ]
            }
        ]))
        .expect("shaped input fields are retained");
        assert_eq!(
            shaped_with_fields.modules[0].input_fields,
            Some(vec![
                ModuleCatalogRecordFieldCompletion {
                    name: "left".to_owned(),
                    field_type: ModuleCatalogRecordFieldType::Integer,
                    required: true,
                    description: "Left addend.".to_owned(),
                    fields: None,
                },
                ModuleCatalogRecordFieldCompletion {
                    name: "right".to_owned(),
                    field_type: ModuleCatalogRecordFieldType::Integer,
                    required: false,
                    description: String::new(),
                    fields: None,
                },
            ])
        );
        assert_eq!(
            shaped_with_fields.modules[0].output_fields,
            Some(vec![ModuleCatalogOutputFieldCompletion {
                name: "total".to_owned(),
                field_type: ModuleCatalogRecordFieldType::Integer,
                required: true,
                description: "Reviewed sum.".to_owned(),
                fields: None,
            }])
        );
        let nested_input_fields = parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.inspect",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [
                    {
                        "name": "filters",
                        "type": "object",
                        "required": true,
                        "description": "Reviewed filters.",
                        "fields": [
                            {"name": "category", "type": "string", "required": true},
                            {
                                "name": "limit",
                                "type": "integer",
                                "required": false,
                                "description": "Result limit."
                            }
                        ]
                    }
                ]
            }
        ]))
        .expect("one nested input field level is retained");
        assert_eq!(
            nested_input_fields.modules[0].input_fields,
            Some(vec![ModuleCatalogRecordFieldCompletion {
                name: "filters".to_owned(),
                field_type: ModuleCatalogRecordFieldType::Object,
                required: true,
                description: "Reviewed filters.".to_owned(),
                fields: Some(vec![
                    ModuleCatalogRecordFieldCompletion {
                        name: "category".to_owned(),
                        field_type: ModuleCatalogRecordFieldType::String,
                        required: true,
                        description: String::new(),
                        fields: None,
                    },
                    ModuleCatalogRecordFieldCompletion {
                        name: "limit".to_owned(),
                        field_type: ModuleCatalogRecordFieldType::Integer,
                        required: false,
                        description: "Result limit.".to_owned(),
                        fields: None,
                    },
                ]),
            }])
        );
        assert!(
            module_catalog_member_hover_text(&nested_input_fields.modules[0])
                .contains("- filters.category: string (required)")
        );
        let nested_output_fields = parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.inspect",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": [
                    {
                        "name": "summary",
                        "type": "object",
                        "required": true,
                        "description": "Reviewed aggregate.",
                        "fields": [
                            {"name": "origin", "type": "string", "required": false},
                            {
                                "name": "total",
                                "type": "integer",
                                "required": true,
                                "description": "Nested total."
                            }
                        ]
                    }
                ]
            }
        ]))
        .expect("one nested output field level is retained");
        assert_eq!(
            nested_output_fields.modules[0].output_fields,
            Some(vec![ModuleCatalogOutputFieldCompletion {
                name: "summary".to_owned(),
                field_type: ModuleCatalogRecordFieldType::Object,
                required: true,
                description: "Reviewed aggregate.".to_owned(),
                fields: Some(vec![
                    ModuleCatalogOutputFieldCompletion {
                        name: "origin".to_owned(),
                        field_type: ModuleCatalogRecordFieldType::String,
                        required: false,
                        description: String::new(),
                        fields: None,
                    },
                    ModuleCatalogOutputFieldCompletion {
                        name: "total".to_owned(),
                        field_type: ModuleCatalogRecordFieldType::Integer,
                        required: true,
                        description: "Nested total.".to_owned(),
                        fields: None,
                    },
                ]),
            }])
        );
        assert!(
            module_catalog_member_hover_text(&nested_output_fields.modules[0])
                .contains("- summary.total: integer (required); Nested total.")
        );
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "inputFields": []
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": [{
                    "name": "summary",
                    "type": "object",
                    "required": true,
                    "fields": [
                        {"name": "total", "type": "integer", "required": true},
                        {"name": "total", "type": "integer", "required": false}
                    ]
                }]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [{
                    "name": "input",
                    "type": "integer",
                    "required": true,
                    "fields": []
                }]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [{
                    "name": "input",
                    "type": "object",
                    "required": true,
                    "fields": [{
                        "name": "detail",
                        "type": "object",
                        "required": false,
                        "fields": []
                    }]
                }]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "outputFields": []
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [{"name": "not-valid", "type": "integer", "required": true}]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [{"name": "left", "type": "unknown", "required": true}]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [{"name": "left", "type": "integer"}]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": [{"name": "total", "type": "unknown", "required": true}]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": [{
                    "name": "total",
                    "type": "integer",
                    "required": true,
                    "fields": []
                }]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": [{
                    "name": "summary",
                    "type": "object",
                    "required": true,
                    "fields": [{
                        "name": "detail",
                        "type": "object",
                        "required": false,
                        "fields": []
                    }]
                }]
            }
        ]))
        .is_none());
        let record_fields = |start: usize, count: usize| {
            serde_json::Value::Array(
                (start..start + count)
                    .map(|index| {
                        serde_json::json!({
                            "name": format!("field_{index}"),
                            "type": "integer",
                            "required": false
                        })
                    })
                    .collect(),
            )
        };
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.left",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": record_fields(0, MAX_LSP_MODULE_RECORD_FIELDS / 2)
            },
            {
                "path": "mod.math.right",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": record_fields(
                    MAX_LSP_MODULE_RECORD_FIELDS / 2,
                    MAX_LSP_MODULE_RECORD_FIELDS / 2 + 1
                )
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.nested_input",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [{
                    "name": "filters",
                    "type": "object",
                    "required": false,
                    "fields": record_fields(0, MAX_LSP_MODULE_RECORD_FIELDS)
                }]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.nested_output",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": [{
                    "name": "summary",
                    "type": "object",
                    "required": false,
                    "fields": record_fields(0, MAX_LSP_MODULE_RECORD_FIELDS)
                }]
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {
                "path": "mod.math.output_left",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": record_fields(0, MAX_LSP_MODULE_RECORD_FIELDS / 2)
            },
            {
                "path": "mod.math.output_right",
                "callMode": "synchronous",
                "callShape": "single_json",
                "outputFields": record_fields(
                    MAX_LSP_MODULE_RECORD_FIELDS / 2,
                    MAX_LSP_MODULE_RECORD_FIELDS / 2 + 1
                )
            }
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.std", "callMode": "deferred"}
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.std", "callMode": "deferred"},
            {"path": "mod.std.log", "description": "log"}
        ]))
        .is_none());
        let source = "use mod.";
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            invalid,
        );
        server.open_document(document(1, source));
        let completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("malformed module-catalog completion request succeeds");
        assert!(completion.is_incomplete);
        assert_eq!(completion.items.len(), 1);
        assert_eq!(completion.items[0].label, "std");
        assert_eq!(
            completion.items[0].detail.as_deref(),
            Some("Splash core namespace; fixed and effect-free")
        );

        let independent_params = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "toolCatalog": [
                        {"name": "TEXT.ECHO", "format": "text", "description": "invalid"}
                    ],
                    "moduleCatalog": [
                        {"path": "mod.std.log", "description": "still usable"}
                    ]
                }
            })),
            ..InitializeParams::default()
        };
        let (invalid_tools, valid_modules, _, _) =
            completion_catalogs_from_initialize_options(&independent_params);
        assert!(invalid_tools.unavailable);
        assert!(!valid_modules.unavailable);

        let oversized = serde_json::Value::Array(
            (0..=MAX_LSP_MODULE_CATALOG_ENTRIES)
                .map(|index| {
                    serde_json::json!({
                        "path": format!("mod.module_{index}"),
                        "description": "module"
                    })
                })
                .collect(),
        );
        assert!(parse_module_completion_catalog(&oversized).is_none());

        let oversized_description = serde_json::json!([{
            "path": "mod.std.log",
            "description": "x".repeat(MAX_LSP_MODULE_DESCRIPTION_BYTES + 1)
        }]);
        assert!(parse_module_completion_catalog(&oversized_description).is_none());

        let oversized_retained_bytes = serde_json::Value::Array(
            (0..MAX_LSP_MODULE_CATALOG_ENTRIES)
                .map(|index| {
                    serde_json::json!({
                        "path": format!("mod.module_{index}"),
                        "description": "x".repeat(MAX_LSP_MODULE_DESCRIPTION_BYTES)
                    })
                })
                .collect(),
        );
        assert!(parse_module_completion_catalog(&oversized_retained_bytes).is_none());

        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod", "description": "missing member"}
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.tool.inspect", "description": "fixed surface"}
        ]))
        .is_none());
        let too_many_segments = std::iter::once("mod")
            .chain(std::iter::repeat_n("part", MAX_LSP_MODULE_PATH_SEGMENTS))
            .collect::<Vec<_>>()
            .join(".");
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": too_many_segments, "description": "too deep"}
        ]))
        .is_none());
        let too_long_path = format!("mod.{}", "a".repeat(MAX_LSP_MODULE_PATH_BYTES));
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": too_long_path, "description": "too long"}
        ]))
        .is_none());
        assert!(parse_module_completion_catalog(&serde_json::json!([
            {"path": "mod.std.log", "description": "one"},
            {"path": "mod.std.log", "description": "two"}
        ]))
        .is_none());

        let valid_tool_invalid_modules = InitializeParams {
            initialization_options: Some(serde_json::json!({
                "splash": {
                    "toolCatalog": [
                        {"name": "text.echo", "format": "text", "description": "valid"}
                    ],
                    "moduleCatalog": [
                        {"path": "mod.tool.inspect", "description": "invalid"}
                    ]
                }
            })),
            ..InitializeParams::default()
        };
        let (valid_tools, invalid_modules, _, _) =
            completion_catalogs_from_initialize_options(&valid_tool_invalid_modules);
        assert!(!valid_tools.unavailable);
        assert!(invalid_modules.unavailable);
    }

    #[test]
    fn refuses_advisory_module_completion_outside_direct_visible_contexts() {
        let catalog = module_catalog(serde_json::json!([
            {"path": "mod.std.log", "description": "log"}
        ]));
        for source in [
            "let note = \"use mod.\"",
            "// use mod.",
            "value use mod.",
            "fn run() {}use mod.",
            "@\nuse mod.",
            "use mod.other.std\nstd.",
            "use mod.std\nlet note = \"std.\"",
        ] {
            let cursor = if source.ends_with("std.\"") {
                source.rfind("std.").unwrap() + "std.".len()
            } else if source.ends_with("std.") {
                source.len()
            } else if source.contains("use mod.") {
                source.rfind("mod.").unwrap() + "mod.".len()
            } else {
                source.len()
            };
            let mut server = SplashLanguageServer::with_completion_catalogs(
                ToolCompletionCatalog::default(),
                catalog.clone(),
            );
            server.open_document(document(1, source));
            let completion = server
                .completion(&test_uri(), position_at_byte(source, cursor))
                .expect("completion request succeeds");
            assert!(
                completion.items.is_empty(),
                "unexpected advisory module completion for {source:?}: {:?}",
                completion
                    .items
                    .iter()
                    .map(|item| (&item.label, &item.detail))
                    .collect::<Vec<_>>()
            );
        }

        let shadowed_source = "use mod.std\nlet std = 1\nstd.";
        let mut shadowed_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        shadowed_server.open_document(document(1, shadowed_source));
        let receiver = shadowed_source.rfind("std.").unwrap();
        let (_, lexical) = shadowed_server
            .lexical_completions(&test_uri())
            .expect("shadowed source has lexical completion metadata");
        assert_eq!(
            visible_symbol_at(lexical, "std", receiver).map(|symbol| symbol.kind),
            Some(LexicalSymbolKind::Let)
        );
        let completion = shadowed_server
            .completion(
                &test_uri(),
                position_at_byte(shadowed_source, shadowed_source.len()),
            )
            .expect("shadowed member completion request succeeds");
        assert!(completion.items.is_empty());

        let chained_shadowed_source = "use mod.std\nlet std = 1\nstd.inspect.";
        let mut chained_shadowed_server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            module_catalog(serde_json::json!([
                {"path": "mod.std.inspect.config", "description": "config"}
            ])),
        );
        chained_shadowed_server.open_document(document(1, chained_shadowed_source));
        let chained_completion = chained_shadowed_server
            .completion(
                &test_uri(),
                position_at_byte(chained_shadowed_source, chained_shadowed_source.len()),
            )
            .expect("shadowed chained completion request succeeds");
        assert!(chained_completion.items.is_empty());
    }

    #[test]
    fn refuses_module_member_completion_for_shadowed_or_non_direct_bindings() {
        for source in [
            "use mod.custom.tool\nlet output = tool.",
            "use mod.tool\nlet tool = 1\ntool.",
            "use mod.tool\nlet object = {tool: tool}\nobject.tool.",
            "use mod.tool\ntool.call.",
            "use mod.tool\n@\ntool.",
        ] {
            let mut server = SplashLanguageServer::default();
            server.open_document(document(1, source));

            let completion = server
                .completion(&test_uri(), position_at_byte(source, source.len()))
                .unwrap();
            assert!(
                completion.items.is_empty(),
                "unexpected members for {source:?}"
            );
        }
    }

    #[test]
    fn refuses_chained_static_record_field_completion() {
        let source = "let profile = {name: \"Ada\"}\nprofile.name.";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let completion = server
            .completion(&test_uri(), position_at_byte(source, source.len()))
            .expect("chained static record completion request succeeds");
        assert!(completion.items.is_empty());
    }

    #[test]
    fn refuses_tool_member_completion_inside_strings_and_comments() {
        for source in [
            "use mod.tool\nlet note = \"tool.\"",
            "use mod.tool\n// tool.",
            "use mod.tool\n/* tool. */",
        ] {
            let mut server = SplashLanguageServer::default();
            server.open_document(document(1, source));
            let cursor = source.find("tool.").unwrap() + "tool.".len();

            let completion = server
                .completion(&test_uri(), position_at_byte(source, cursor))
                .expect("completion request succeeds");
            assert!(
                completion.items.is_empty(),
                "unexpected module completion for {source:?}"
            );
        }
    }

    #[test]
    fn invalidates_cached_module_imports_on_a_full_document_change() {
        let initial = "use mod.tool\nlet output = tool.";
        let replacement = "use mod.custom.tool\nlet output = tool.";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, initial));

        let initial_completion = server
            .completion(&test_uri(), position_at_byte(initial, initial.len()))
            .unwrap();
        assert_eq!(initial_completion.items.len(), 4);

        let diagnostics = server
            .change_document(DidChangeTextDocumentParams {
                text_document: VersionedTextDocumentIdentifier::new(test_uri(), 2),
                content_changes: vec![TextDocumentContentChangeEvent {
                    range: None,
                    range_length: None,
                    text: replacement.to_owned(),
                }],
            })
            .expect("a newer full document replaces the cached snapshot");
        assert!(!diagnostics.diagnostics.is_empty());

        let replacement_completion = server
            .completion(
                &test_uri(),
                position_at_byte(replacement, replacement.len()),
            )
            .unwrap();
        assert!(replacement_completion.items.is_empty());
    }

    #[test]
    fn invalidates_cached_static_record_shapes_on_a_full_document_change() {
        let initial = "let profile = {name: \"Ada\"}\nprofile.";
        let replacement = "let profile = {active: true}\nprofile.";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, initial));

        let initial_completion = server
            .completion(&test_uri(), position_at_byte(initial, initial.len()))
            .expect("the initial static record shape is cached");
        assert_eq!(
            initial_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["name"]
        );

        let diagnostics = server
            .change_document(DidChangeTextDocumentParams {
                text_document: VersionedTextDocumentIdentifier::new(test_uri(), 2),
                content_changes: vec![TextDocumentContentChangeEvent {
                    range: None,
                    range_length: None,
                    text: replacement.to_owned(),
                }],
            })
            .expect("a newer full document replaces the cached static record shape");
        assert!(!diagnostics.diagnostics.is_empty());

        let replacement_completion = server
            .completion(
                &test_uri(),
                position_at_byte(replacement, replacement.len()),
            )
            .expect("the replacement static record shape is fresh");
        assert_eq!(
            replacement_completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["active"]
        );
    }

    #[test]
    fn marks_tool_member_completion_incomplete_when_imports_are_truncated() {
        let mut source = String::from("use mod.tool\n");
        for index in 0..=splash_core::MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }
        source.push_str("let output = tool.");
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, source.len()))
            .unwrap();

        assert!(completion.is_incomplete);
        assert_eq!(completion.items.len(), 4);
    }

    #[test]
    fn marks_standard_math_completion_incomplete_when_imports_are_truncated() {
        let mut source = String::from("use mod.std.math\n");
        for index in 0..=splash_core::MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }
        source.push_str("let output = math.");
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, source.len()))
            .expect("truncated core math completion succeeds");

        assert!(completion.is_incomplete);
        assert_eq!(completion.items.len(), 18);
    }

    #[test]
    fn marks_standard_json_completion_incomplete_when_imports_are_truncated() {
        let mut source = String::from("use mod.std.json\n");
        for index in 0..=splash_core::MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }
        source.push_str("let output = json.");
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, source.len()))
            .expect("truncated core JSON completion succeeds");

        assert!(completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["parse", "stringify"]
        );
    }

    #[test]
    fn marks_standard_array_completion_incomplete_when_imports_are_truncated() {
        let mut source = String::from("use mod.std.array\n");
        for index in 0..=splash_core::MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }
        source.push_str("let output = array.");
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, source.len()))
            .expect("truncated core array completion succeeds");

        assert!(completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            [
                "concat",
                "flatten",
                "get",
                "has_index",
                "len",
                "push",
                "reverse",
                "slice"
            ]
        );
    }

    #[test]
    fn marks_standard_object_completion_incomplete_when_imports_are_truncated() {
        let mut source = String::from("use mod.std.object\n");
        for index in 0..=splash_core::MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }
        source.push_str("let output = object.");
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, source.len()))
            .expect("truncated core object completion succeeds");

        assert!(completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            [
                "entries",
                "from_entries",
                "get",
                "has",
                "keys",
                "len",
                "merge",
                "pick",
                "values"
            ]
        );
    }

    #[test]
    fn marks_standard_text_completion_incomplete_when_imports_are_truncated() {
        let mut source = String::from("use mod.std.text\n");
        for index in 0..=splash_core::MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }
        source.push_str("let output = text.");
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, source.len()))
            .expect("truncated core text completion succeeds");

        assert!(completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            [
                "contains",
                "ends_with",
                "index_of",
                "join",
                "len",
                "lower",
                "replace_all",
                "slice",
                "split",
                "starts_with",
                "trim",
                "upper",
            ]
        );
    }

    #[test]
    fn marks_fixed_standard_namespace_completion_incomplete_when_imports_are_truncated() {
        let mut source = String::from("use mod.std\n");
        for index in 0..=splash_core::MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }
        source.push_str("std.");
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, source.len()))
            .expect("truncated fixed standard completion succeeds");

        assert!(completion.is_incomplete);
        assert_eq!(
            completion
                .items
                .iter()
                .map(|item| item.label.as_str())
                .collect::<Vec<_>>(),
            ["array", "assert", "json", "math", "object", "text"]
        );
    }

    #[test]
    fn refuses_direct_module_input_fields_when_imports_are_truncated() {
        let mut source = String::from("use mod.arithmetic\n");
        for index in 0..=splash_core::MAX_MODULE_IMPORTS {
            source.push_str(&format!("use mod.module_{index}\n"));
        }
        source.push_str("let result = arithmetic.add({ri: 22})");
        let catalog = module_catalog(serde_json::json!([
            {
                "path": "mod.arithmetic.add",
                "callMode": "synchronous",
                "callShape": "single_json",
                "inputFields": [
                    {"name": "left", "type": "integer", "required": true},
                    {"name": "right", "type": "integer", "required": true}
                ]
            }
        ]));
        let mut server = SplashLanguageServer::with_completion_catalogs(
            ToolCompletionCatalog::default(),
            catalog,
        );
        server.open_document(document(1, &source));
        let cursor = source.rfind("ri:").expect("input field exists") + "ri".len();

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, cursor))
            .expect("truncated direct input completion request succeeds");
        assert!(completion.is_incomplete);
        assert!(completion.items.is_empty());
    }

    #[test]
    fn completion_excludes_sites_after_the_first_mid_document_error() {
        let source = "let alpha = 1\nalpha\n@\nlet beta = 2\nbeta";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));
        let alpha_site = source.find("\nalpha").unwrap() + 1;
        let beta_site = source.rfind("beta").unwrap();

        let before_error = server
            .completion(&test_uri(), position_at_byte(source, alpha_site + 2))
            .unwrap();
        assert_eq!(before_error.items.len(), 1);
        assert_eq!(before_error.items[0].label, "alpha");

        let after_error = server
            .completion(&test_uri(), position_at_byte(source, beta_site + 2))
            .unwrap();
        assert!(after_error.items.is_empty());
        assert!(!after_error.is_incomplete);
    }

    #[test]
    fn completion_reports_independent_truncation_to_the_client() {
        let mut source = String::from("let value = 0\n");
        for _ in 0..=splash_core::MAX_LEXICAL_COMPLETION_SITES {
            source.push_str("missing\n");
        }
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        let first_site = source.find("\nmissing").unwrap() + 1;
        let completion = server
            .completion(&test_uri(), position_at_byte(&source, first_site))
            .unwrap();

        assert!(completion.is_incomplete);
        assert_eq!(completion.items.len(), 1);
        assert_eq!(completion.items[0].label, "value");
    }

    #[test]
    fn completion_returns_no_candidates_from_a_truncated_symbol_index() {
        let mut source = String::from("let value = 0\n");
        for _ in 0..MAX_LEXICAL_SYMBOL_OCCURRENCES {
            source.push_str("value\n");
        }
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));
        let first_site = source.find("\nvalue").unwrap() + 1;

        let completion = server
            .completion(&test_uri(), position_at_byte(&source, first_site))
            .unwrap();

        assert!(completion.is_incomplete);
        assert!(completion.items.is_empty());
    }

    #[test]
    fn rejects_renames_that_are_invalid_ambiguous_or_change_binding_resolution() {
        let source = "use mod.std.assert\n\
                      let outer = 1\n\
                      fn compute() {\n\
                          let inner = 2\n\
                          assert(inner + outer)\n\
                      }";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let inner = source.find("inner").expect("inner definition exists");
        let collision = server
            .rename(&test_uri(), position_at_byte(source, inner), "outer")
            .expect_err("capturing an outer reference must be rejected");
        assert!(collision.contains("binding resolution"));

        let local = source.find("outer").expect("outer definition exists");
        let builtin_capture = server
            .rename(&test_uri(), position_at_byte(source, local), "assert")
            .expect_err("capturing an imported call must be rejected");
        assert!(builtin_capture.contains("binding resolution"));

        for invalid in [
            "try",
            "false",
            "nil",
            "two words",
            "name/*comment*/",
            "name\nnext",
            "name\rnext",
            "name\0next",
            "\u{feff}name",
            "\u{1f642}",
        ] {
            let error = server
                .rename(&test_uri(), position_at_byte(source, inner), invalid)
                .expect_err("invalid identifier spelling must be rejected");
            assert!(error.contains("canonical Splash identifier"), "{error}");
        }

        let import = source.find("assert").expect("import binding exists");
        assert_eq!(
            server
                .prepare_rename(&test_uri(), position_at_byte(source, import))
                .expect("import prepare is bounded"),
            None
        );
        let error = server
            .rename(&test_uri(), position_at_byte(source, import), "verify")
            .expect_err("renaming an import path is not a local binding rename");
        assert!(error.contains("module path"));

        let oversized_name = "a".repeat(DEFAULT_MAX_SOURCE_BYTES);
        let error = server
            .rename(
                &test_uri(),
                position_at_byte(source, inner),
                &oversized_name,
            )
            .expect_err("renamed source remains bounded");
        assert!(error.contains("source limit"));
    }

    #[test]
    fn allows_a_rename_that_preserves_safe_lexical_shadowing() {
        let source = "let value = 1\n\
                      fn compute() {\n\
                          let inner = 2\n\
                          inner\n\
                      }\n\
                      value";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));
        let inner = source.find("inner").expect("inner definition exists");

        let rename = server
            .rename(&test_uri(), position_at_byte(source, inner), "value")
            .expect("safe shadowing analysis succeeds")
            .expect("safe local shadowing remains renameable");
        assert_eq!(rename.edits.len(), 2);
        assert_eq!(
            apply_text_edits(source, &rename.edits),
            "let value = 1\nfn compute() {\nlet value = 2\nvalue\n}\nvalue"
        );
    }

    #[test]
    fn resolves_imports_and_loop_bindings_without_cross_document_leakage() {
        let source = "use mod.std.assert\n\
                      for index in [1] {\n\
                          assert(index)\n\
                      }";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        for name in ["assert", "index"] {
            let definition_start = source.find(name).expect("definition exists");
            let reference_start = source.rfind(name).expect("reference exists");
            let location = server
                .definition(&test_uri(), position_at_byte(source, reference_start))
                .expect("symbol index succeeds")
                .expect("reference resolves");
            assert_eq!(location.uri, test_uri());
            assert_eq!(
                location.range,
                Range::new(
                    position_at_byte(source, definition_start),
                    position_at_byte(source, definition_start + name.len()),
                )
            );
        }

        let other_uri = Uri::from_str("file:///workspace/other.splash").expect("valid file URI");
        let other_source = "let index = 9\nindex";
        server.open_document(TextDocumentItem::new(
            other_uri.clone(),
            "splash".to_owned(),
            1,
            other_source.to_owned(),
        ));
        let other_location = server
            .definition(&other_uri, Position::new(1, 1))
            .expect("other document index succeeds")
            .expect("other document reference resolves");
        assert_eq!(other_location.uri, other_uri);
        assert_eq!(
            other_location.range,
            Range::new(Position::new(0, 4), Position::new(0, 9))
        );
    }

    #[test]
    fn lexical_requests_return_no_result_for_invalid_source_or_position() {
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, "fn broken("));

        assert_eq!(
            server
                .definition(&test_uri(), Position::new(0, 3))
                .expect("invalid source produces an empty index"),
            None
        );
        assert!(server
            .references(&test_uri(), Position::new(0, 3), true)
            .expect("invalid source produces an empty index")
            .is_empty());
        assert_eq!(
            server
                .hover(&test_uri(), Position::new(0, 3))
                .expect("invalid source produces an empty index"),
            None
        );
        assert!(server
            .document_highlights(&test_uri(), Position::new(0, 3))
            .expect("invalid source produces an empty index")
            .is_empty());
        assert_eq!(
            server
                .prepare_rename(&test_uri(), Position::new(0, 3))
                .expect("invalid source produces an empty index"),
            None
        );
        assert_eq!(
            server
                .rename(&test_uri(), Position::new(0, 3), "valid")
                .expect("invalid source produces an empty index"),
            None
        );

        server.open_document(document(2, "let value = 1"));
        assert_eq!(
            server
                .definition(&test_uri(), Position::new(4, 0))
                .expect("an out-of-range position has no symbol"),
            None
        );
    }

    #[test]
    fn serves_retained_definitions_but_rejects_truncated_reference_indexes() {
        let mut source = String::new();
        for index in 0..=MAX_LEXICAL_SYMBOL_OCCURRENCES {
            source.push_str(&format!("let binding{index} = 0\n"));
        }
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, &source));

        assert!(server
            .definition(&test_uri(), Position::new(0, 4))
            .expect("retained definitions remain sound")
            .is_some());
        assert!(server
            .hover(&test_uri(), Position::new(0, 4))
            .expect("retained hover information remains sound")
            .is_some());
        let omitted_position = Position::new(to_u32(MAX_LEXICAL_SYMBOL_OCCURRENCES), 4);
        assert_eq!(
            server
                .definition(&test_uri(), omitted_position)
                .expect("an omitted definition produces no location"),
            None
        );
        assert_eq!(
            server
                .hover(&test_uri(), omitted_position)
                .expect("an omitted definition produces no hover"),
            None
        );
        let error = server
            .references(&test_uri(), Position::new(0, 4), true)
            .expect_err("truncated reference sets are not returned as complete results");
        assert!(error.contains("occurrence limit"));
        let error = server
            .document_highlights(&test_uri(), Position::new(0, 4))
            .expect_err("truncated highlight sets are not returned as complete results");
        assert!(error.contains("occurrence limit"));
        let error = server
            .prepare_rename(&test_uri(), Position::new(0, 4))
            .expect_err("truncated indexes cannot prepare an exhaustive rename");
        assert!(error.contains("occurrence limit"));
        let error = server
            .rename(&test_uri(), Position::new(0, 4), "renamed")
            .expect_err("truncated indexes cannot produce an exhaustive rename");
        assert!(error.contains("occurrence limit"));
    }

    #[test]
    fn converts_core_positions_to_zero_based_utf16() {
        assert_eq!(
            diagnostic_position("\u{1f642}x", 1, 3),
            Position::new(0, 3),
            "the first two Unicode scalar values occupy three UTF-16 code units"
        );
        assert_eq!(
            diagnostic_position("first\nlast", 9, 9),
            Position::new(1, 4)
        );
        assert_eq!(
            byte_at_position("\u{1f642}x\r\ny", Position::new(0, 2)),
            Some(4)
        );
        assert_eq!(
            byte_at_position("\u{1f642}x\r\ny", Position::new(0, 1)),
            None
        );
        assert_eq!(
            byte_at_position("\u{1f642}x\r\ny", Position::new(1, 0)),
            Some(7)
        );
        assert_eq!(
            byte_at_position("\u{1f642}x\r\ny", Position::new(1, 1)),
            Some(8)
        );
    }

    #[test]
    fn formats_with_one_full_document_edit() {
        let source = "fn add(left,right){\nreturn left+right\n}\nlet record={left:1,right:2}\nadd(record.left,record.right)";
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, source));

        let edits = server
            .format_document(&test_uri())
            .expect("format succeeds");

        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].range.start, Position::new(0, 0));
        assert_eq!(edits[0].range.end, document_end_position(source));
        assert_eq!(
            edits[0].new_text,
            "fn add(left, right) {\n    return left + right\n}\nlet record = {left: 1, right: 2}\nadd(record.left, record.right)\n"
        );
    }

    #[test]
    fn ignores_incremental_and_stale_changes_under_full_sync() {
        let mut server = SplashLanguageServer::default();
        server.open_document(document(3, "let value = 1"));

        let stale = DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier::new(test_uri(), 3),
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "let value = 2".to_owned(),
            }],
        };
        assert!(server.change_document(stale).is_none());

        let incremental = DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier::new(test_uri(), 4),
            content_changes: vec![TextDocumentContentChangeEvent {
                range: Some(Range::new(Position::new(0, 12), Position::new(0, 13))),
                range_length: None,
                text: "3".to_owned(),
            }],
        };
        assert!(server.change_document(incremental).is_none());
        let rename = server
            .rename(&test_uri(), Position::new(0, 5), "renamed")
            .expect("rename uses the last accepted full snapshot")
            .expect("the retained binding is renameable");
        assert_eq!(rename.version, 3);
        let edits = server
            .format_document(&test_uri())
            .expect("original document remains available");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].new_text, "let value = 1\n");
    }

    #[test]
    fn invalidates_the_cached_lexical_report_on_a_full_document_change() {
        let mut server = SplashLanguageServer::default();
        server.open_document(document(1, "let first = 1\nfirst"));
        assert!(server
            .definition(&test_uri(), Position::new(1, 1))
            .expect("the first lexical report is cached")
            .is_some());

        let diagnostics = server
            .change_document(DidChangeTextDocumentParams {
                text_document: VersionedTextDocumentIdentifier::new(test_uri(), 2),
                content_changes: vec![TextDocumentContentChangeEvent {
                    range: None,
                    range_length: None,
                    text: "let second = 2\nsecond".to_owned(),
                }],
            })
            .expect("a newer full document replaces the cached snapshot");
        assert!(diagnostics.diagnostics.is_empty());

        let prepared = server
            .prepare_rename(&test_uri(), Position::new(1, 1))
            .expect("the replacement document builds a fresh lexical report")
            .expect("the replacement binding is renameable");
        assert_eq!(
            prepared,
            PrepareRenameResponse::RangeWithPlaceholder {
                range: Range::new(Position::new(1, 0), Position::new(1, 6)),
                placeholder: "second".to_owned(),
            }
        );
        let rename = server
            .rename(&test_uri(), Position::new(1, 1), "updated")
            .expect("rename uses the replacement lexical report")
            .expect("the replacement binding is renameable");
        assert_eq!(rename.version, 2);
        assert_eq!(rename.edits.len(), 2);
    }

    #[test]
    fn oversized_document_can_recover_on_a_later_full_change() {
        let mut server = SplashLanguageServer::default();
        let oversized = "x".repeat(DEFAULT_MAX_SOURCE_BYTES + 1);
        let diagnostics = server.open_document(document(1, &oversized));
        assert_eq!(diagnostics.diagnostics.len(), 1);
        assert!(server.format_document(&test_uri()).is_err());
        assert!(server.document_symbols(&test_uri()).is_err());
        assert!(server.hover(&test_uri(), Position::new(0, 0)).is_err());
        assert!(server
            .document_highlights(&test_uri(), Position::new(0, 0))
            .is_err());
        assert!(server
            .prepare_rename(&test_uri(), Position::new(0, 0))
            .is_err());
        assert!(server
            .rename(&test_uri(), Position::new(0, 0), "valid")
            .is_err());

        let update = DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier::new(test_uri(), 2),
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "let value = 1".to_owned(),
            }],
        };
        let diagnostics = server
            .change_document(update)
            .expect("full replacement is accepted");
        assert!(diagnostics.diagnostics.is_empty());
        assert!(server.format_document(&test_uri()).is_ok());
        assert!(server.hover(&test_uri(), Position::new(0, 5)).is_ok());
        assert!(server
            .prepare_rename(&test_uri(), Position::new(0, 5))
            .expect("replacement source has a fresh lexical cache")
            .is_some());
    }

    #[test]
    fn announces_and_serves_bounded_editor_features_over_stdio_protocol() {
        let (server_connection, client_connection) = Connection::memory();
        let server_thread = std::thread::spawn(move || run_connection(&server_connection));

        client_connection
            .sender
            .send(
                Request::new(
                    1.into(),
                    "initialize".to_owned(),
                    serde_json::json!({
                        "capabilities": {
                            "workspace": {
                                "workspaceEdit": {"documentChanges": true}
                            }
                        },
                        "initializationOptions": {
                            "splash": {
                                "toolCatalog": [
                                    {
                                        "name": "text.echo",
                                        "format": "text",
                                        "description": "Returns text unchanged."
                                    },
                                    {
                                        "name": "math.add",
                                        "format": "json",
                                        "description": "Adds two integer fields."
                                    }
                                ],
                                "moduleCatalog": [
                                    {
                                        "path": "mod.app.weather",
                                        "description": "Reads a host-defined forecast."
                                    }
                                ]
                            }
                        }
                    }),
                )
                .into(),
            )
            .expect("initialize send succeeds");
        let initialize_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("initialize response arrives");
        let Message::Response(response) = initialize_response else {
            panic!("expected initialize response");
        };
        let capabilities = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result["capabilities"].clone(),
            lsp_server::ResponseKind::Err { error } => {
                panic!("initialize failed: {}", error.message)
            }
        };
        assert_eq!(capabilities["positionEncoding"], "utf-16");
        assert_eq!(capabilities["textDocumentSync"], 1);
        assert_eq!(capabilities["documentFormattingProvider"], true);
        assert_eq!(capabilities["documentSymbolProvider"], true);
        assert_eq!(capabilities["definitionProvider"], true);
        assert_eq!(capabilities["referencesProvider"], true);
        assert_eq!(capabilities["hoverProvider"], true);
        assert_eq!(capabilities["documentHighlightProvider"], true);
        assert_eq!(
            capabilities["signatureHelpProvider"]["triggerCharacters"],
            serde_json::json!(["("])
        );
        assert_eq!(
            capabilities["signatureHelpProvider"]["retriggerCharacters"],
            serde_json::json!([","])
        );
        assert_eq!(capabilities["completionProvider"]["resolveProvider"], false);
        assert_eq!(
            capabilities["completionProvider"]["triggerCharacters"],
            serde_json::json!(["."])
        );
        assert_eq!(capabilities["renameProvider"]["prepareProvider"], true);

        client_connection
            .sender
            .send(Notification::new(Initialized::METHOD.to_owned(), ()).into())
            .expect("initialized send succeeds");
        client_connection
            .sender
            .send(
                Notification::new(
                    DidOpenTextDocument::METHOD.to_owned(),
                    DidOpenTextDocumentParams {
                        text_document: document(1, "let value=1\nvalue"),
                    },
                )
                .into(),
            )
            .expect("open send succeeds");

        let _diagnostics = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("diagnostics arrive after open");
        client_connection
            .sender
            .send(
                Request::new(
                    2.into(),
                    Formatting::METHOD.to_owned(),
                    DocumentFormattingParams {
                        text_document: lsp_types::TextDocumentIdentifier::new(test_uri()),
                        options: FormattingOptions::default(),
                        work_done_progress_params: lsp_types::WorkDoneProgressParams::default(),
                    },
                )
                .into(),
            )
            .expect("format send succeeds");
        let format_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("format response arrives");
        let Message::Response(response) = format_response else {
            panic!("expected formatting response");
        };
        let edits = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("format failed: {}", error.message)
            }
        };
        assert_eq!(edits[0]["newText"], "let value = 1\nvalue\n");

        client_connection
            .sender
            .send(
                Request::new(
                    3.into(),
                    DocumentSymbolRequest::METHOD.to_owned(),
                    serde_json::json!({"textDocument": {"uri": test_uri()}}),
                )
                .into(),
            )
            .expect("document symbol request send succeeds");
        let symbol_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("document symbol response arrives");
        let Message::Response(response) = symbol_response else {
            panic!("expected document symbol response");
        };
        let symbols = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("document symbol request failed: {}", error.message)
            }
        };
        assert_eq!(symbols[0]["name"], "value");
        assert_eq!(symbols[0]["kind"], 13);

        client_connection
            .sender
            .send(
                Request::new(
                    4.into(),
                    GotoDefinition::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1}
                    }),
                )
                .into(),
            )
            .expect("definition request send succeeds");
        let definition_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("definition response arrives");
        let Message::Response(response) = definition_response else {
            panic!("expected definition response");
        };
        let definition = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("definition request failed: {}", error.message)
            }
        };
        assert_eq!(
            definition["range"]["start"],
            serde_json::json!({"line": 0, "character": 4})
        );
        assert_eq!(
            definition["range"]["end"],
            serde_json::json!({"line": 0, "character": 9})
        );

        client_connection
            .sender
            .send(
                Request::new(
                    5.into(),
                    References::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1},
                        "context": {"includeDeclaration": true}
                    }),
                )
                .into(),
            )
            .expect("references request send succeeds");
        let references_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("references response arrives");
        let Message::Response(response) = references_response else {
            panic!("expected references response");
        };
        let references = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("references request failed: {}", error.message)
            }
        };
        assert_eq!(references.as_array().map(Vec::len), Some(2));

        client_connection
            .sender
            .send(
                Request::new(
                    6.into(),
                    HoverRequest::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1}
                    }),
                )
                .into(),
            )
            .expect("hover request send succeeds");
        let hover_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("hover response arrives");
        let Message::Response(response) = hover_response else {
            panic!("expected hover response");
        };
        let hover = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("hover request failed: {}", error.message)
            }
        };
        assert_eq!(hover["contents"]["kind"], "markdown");
        assert_eq!(hover["contents"]["value"], "**binding** `value`");
        assert_eq!(
            hover["range"],
            serde_json::json!({
                "start": {"line": 1, "character": 0},
                "end": {"line": 1, "character": 5}
            })
        );

        client_connection
            .sender
            .send(
                Request::new(
                    7.into(),
                    DocumentHighlightRequest::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1}
                    }),
                )
                .into(),
            )
            .expect("document highlight request send succeeds");
        let highlight_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("document highlight response arrives");
        let Message::Response(response) = highlight_response else {
            panic!("expected document highlight response");
        };
        let highlights = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("document highlight request failed: {}", error.message)
            }
        };
        assert_eq!(highlights.as_array().map(Vec::len), Some(2));
        assert_eq!(highlights[0]["kind"], 1);
        assert_eq!(highlights[1]["kind"], 1);

        client_connection
            .sender
            .send(
                Request::new(
                    70.into(),
                    Completion::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 5}
                    }),
                )
                .into(),
            )
            .expect("completion request send succeeds");
        let completion_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("completion response arrives");
        let Message::Response(response) = completion_response else {
            panic!("expected completion response");
        };
        let completion = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("completion request failed: {}", error.message)
            }
        };
        assert_eq!(completion["isIncomplete"], false);
        assert_eq!(completion["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(completion["items"][0]["label"], "value");
        assert_eq!(
            completion["items"][0]["textEdit"]["range"],
            serde_json::json!({
                "start": {"line": 1, "character": 0},
                "end": {"line": 1, "character": 5}
            })
        );
        assert_eq!(completion["items"][0]["textEdit"]["newText"], "value");

        client_connection
            .sender
            .send(
                Request::new(
                    8.into(),
                    PrepareRenameRequest::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 5}
                    }),
                )
                .into(),
            )
            .expect("prepare rename request send succeeds");
        let prepare_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("prepare rename response arrives");
        let Message::Response(response) = prepare_response else {
            panic!("expected prepare rename response");
        };
        let prepared = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("prepare rename request failed: {}", error.message)
            }
        };
        assert_eq!(prepared["placeholder"], "value");
        assert_eq!(
            prepared["range"],
            serde_json::json!({
                "start": {"line": 1, "character": 0},
                "end": {"line": 1, "character": 5}
            })
        );

        client_connection
            .sender
            .send(
                Request::new(
                    9.into(),
                    Rename::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 1},
                        "newName": "renamed"
                    }),
                )
                .into(),
            )
            .expect("rename request send succeeds");
        let rename_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("rename response arrives");
        let Message::Response(response) = rename_response else {
            panic!("expected rename response");
        };
        let rename = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("rename request failed: {}", error.message)
            }
        };
        assert!(rename.get("changes").is_none());
        assert_eq!(rename["documentChanges"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            rename["documentChanges"][0]["textDocument"],
            serde_json::json!({"uri": test_uri(), "version": 1})
        );
        assert_eq!(
            rename["documentChanges"][0]["edits"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            rename["documentChanges"][0]["edits"][0]["newText"],
            "renamed"
        );

        let tool_source = "use mod.tool\nlet result = tool.call(\"text.\")";
        client_connection
            .sender
            .send(
                Notification::new(
                    DidChangeTextDocument::METHOD.to_owned(),
                    DidChangeTextDocumentParams {
                        text_document: VersionedTextDocumentIdentifier::new(test_uri(), 2),
                        content_changes: vec![TextDocumentContentChangeEvent {
                            range: None,
                            range_length: None,
                            text: tool_source.to_owned(),
                        }],
                    },
                )
                .into(),
            )
            .expect("tool completion source change succeeds");
        let _diagnostics = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("diagnostics arrive after tool source change");
        client_connection
            .sender
            .send(
                Request::new(
                    10.into(),
                    SignatureHelpRequest::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 27}
                    }),
                )
                .into(),
            )
            .expect("signature help request send succeeds");
        let signature_help_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("signature help response arrives");
        let Message::Response(response) = signature_help_response else {
            panic!("expected signature help response");
        };
        let signature_help = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("signature help request failed: {}", error.message)
            }
        };
        assert_eq!(
            signature_help["signatures"][0]["label"],
            "tool.call(name, input) -> string"
        );
        assert_eq!(signature_help["activeParameter"], 0);
        client_connection
            .sender
            .send(
                Request::new(
                    11.into(),
                    Completion::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 1, "character": 29}
                    }),
                )
                .into(),
            )
            .expect("catalog completion request send succeeds");
        let catalog_completion_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("catalog completion response arrives");
        let Message::Response(response) = catalog_completion_response else {
            panic!("expected catalog completion response");
        };
        let catalog_completion = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("catalog completion request failed: {}", error.message)
            }
        };
        assert_eq!(catalog_completion["isIncomplete"], false);
        assert_eq!(
            catalog_completion["items"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(catalog_completion["items"][0]["label"], "text.echo");
        assert_eq!(
            catalog_completion["items"][0]["detail"],
            "text capability name; host approval required"
        );

        let module_source = "use mod.app.";
        client_connection
            .sender
            .send(
                Notification::new(
                    DidChangeTextDocument::METHOD.to_owned(),
                    DidChangeTextDocumentParams {
                        text_document: VersionedTextDocumentIdentifier::new(test_uri(), 3),
                        content_changes: vec![TextDocumentContentChangeEvent {
                            range: None,
                            range_length: None,
                            text: module_source.to_owned(),
                        }],
                    },
                )
                .into(),
            )
            .expect("module completion source change succeeds");
        let _diagnostics = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("diagnostics arrive after module source change");
        client_connection
            .sender
            .send(
                Request::new(
                    12.into(),
                    Completion::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 0, "character": 12}
                    }),
                )
                .into(),
            )
            .expect("module completion request send succeeds");
        let module_completion_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("module completion response arrives");
        let Message::Response(response) = module_completion_response else {
            panic!("expected module completion response");
        };
        let module_completion = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result,
            lsp_server::ResponseKind::Err { error } => {
                panic!("module completion request failed: {}", error.message)
            }
        };
        assert_eq!(module_completion["isIncomplete"], false);
        assert_eq!(module_completion["items"].as_array().map(Vec::len), Some(1));
        assert_eq!(module_completion["items"][0]["label"], "weather");
        assert_eq!(
            module_completion["items"][0]["detail"],
            "advisory module path; host module binding required"
        );

        client_connection
            .sender
            .send(Request::new(10.into(), "shutdown".to_owned(), ()).into())
            .expect("shutdown send succeeds");
        let shutdown_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown response arrives");
        assert!(matches!(shutdown_response, Message::Response(_)));
        client_connection
            .sender
            .send(Notification::new("exit".to_owned(), ()).into())
            .expect("exit send succeeds");

        server_thread
            .join()
            .expect("server thread does not panic")
            .expect("server shuts down cleanly");
    }

    #[test]
    fn malformed_or_legacy_initialization_fails_closed_without_rename() {
        let (server_connection, client_connection) = Connection::memory();
        let server_thread = std::thread::spawn(move || run_connection(&server_connection));

        client_connection
            .sender
            .send(Request::new(1.into(), "initialize".to_owned(), serde_json::json!({})).into())
            .expect("malformed initialize send succeeds");
        let initialize_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("malformed initialize still receives a response");
        let Message::Response(response) = initialize_response else {
            panic!("expected initialize response");
        };
        let capabilities = match response.response_kind {
            lsp_server::ResponseKind::Ok { result } => result["capabilities"].clone(),
            lsp_server::ResponseKind::Err { error } => {
                panic!("initialize failed: {}", error.message)
            }
        };
        assert!(capabilities.get("renameProvider").is_none());

        client_connection
            .sender
            .send(Notification::new(Initialized::METHOD.to_owned(), ()).into())
            .expect("initialized send succeeds");
        client_connection
            .sender
            .send(
                Request::new(
                    2.into(),
                    Rename::METHOD.to_owned(),
                    serde_json::json!({
                        "textDocument": {"uri": test_uri()},
                        "position": {"line": 0, "character": 0},
                        "newName": "renamed"
                    }),
                )
                .into(),
            )
            .expect("unadvertised rename request send succeeds");
        let rename_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("unadvertised rename response arrives");
        let Message::Response(response) = rename_response else {
            panic!("expected rename response");
        };
        match response.response_kind {
            lsp_server::ResponseKind::Err { error } => {
                assert_eq!(error.code, ErrorCode::MethodNotFound as i32);
            }
            lsp_server::ResponseKind::Ok { result } => {
                panic!("unadvertised rename unexpectedly succeeded: {result}")
            }
        }

        client_connection
            .sender
            .send(Request::new(3.into(), "shutdown".to_owned(), ()).into())
            .expect("shutdown send succeeds");
        let shutdown_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("shutdown response arrives");
        assert!(matches!(shutdown_response, Message::Response(_)));
        client_connection
            .sender
            .send(Notification::new(Exit::METHOD.to_owned(), ()).into())
            .expect("exit send succeeds");
        server_thread
            .join()
            .expect("server thread does not panic")
            .expect("server shuts down cleanly");
    }

    #[test]
    fn rejects_exit_without_shutdown() {
        let (server_connection, client_connection) = Connection::memory();
        let server_thread = std::thread::spawn(move || run_connection(&server_connection));

        client_connection
            .sender
            .send(
                Request::new(
                    1.into(),
                    "initialize".to_owned(),
                    serde_json::json!({"capabilities": {}}),
                )
                .into(),
            )
            .expect("initialize send succeeds");
        let _initialize_response = client_connection
            .receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("initialize response arrives");
        client_connection
            .sender
            .send(Notification::new(Initialized::METHOD.to_owned(), ()).into())
            .expect("initialized send succeeds");
        client_connection
            .sender
            .send(Notification::new(Exit::METHOD.to_owned(), ()).into())
            .expect("exit send succeeds");

        assert!(server_thread
            .join()
            .expect("server thread does not panic")
            .is_err());
    }

    #[test]
    fn declares_utf16_position_encoding() {
        assert_eq!(
            server_capabilities(false).position_encoding,
            Some(PositionEncodingKind::UTF16)
        );
        assert!(server_capabilities(false).rename_provider.is_none());
        assert!(matches!(
            server_capabilities(true).rename_provider,
            Some(OneOf::Right(RenameOptions {
                prepare_provider: Some(true),
                ..
            }))
        ));
    }
}
