#![forbid(unsafe_code)]

//! Host-neutral execution primitives for Splash.
//!
//! The vendored VM exposes pure language modules only. This crate owns runtime
//! limits and diagnostic capture; effectful APIs belong to a separate host
//! crate and must be explicitly installed by trusted Rust code.

mod profile;

use std::any::Any;
use std::fmt::{self, Display, Formatter};
use std::time::Duration;

pub use makepad_script as vm;
use profile::check_canonical_profile;
use vm::parser::ScriptParser;
use vm::tokenizer::{ScriptToken, ScriptTokenizer};

pub const DEFAULT_MAX_SOURCE_BYTES: usize = 256 * 1024;
/// Maximum canonical lexical tokens accepted by default during syntax preflight.
pub const DEFAULT_MAX_SYNTAX_TOKENS: usize = 32 * 1024;
pub const DEFAULT_INSTRUCTION_LIMIT: usize = 200_000;
pub const DEFAULT_SOFT_TIMEOUT: Duration = Duration::from_millis(32);
pub const DEFAULT_HARD_TIMEOUT: Duration = Duration::from_millis(64);
pub const DEFAULT_BUDGET_SAMPLE_INTERVAL: u32 = 1_024;
/// Maximum structured syntax diagnostics returned for one source check.
pub const MAX_SYNTAX_DIAGNOSTICS: usize = 32;

/// Bounds applied to one source evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLimits {
    pub max_source_bytes: usize,
    pub max_syntax_tokens: usize,
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
    InvalidLimits(&'static str),
    SyntaxRejected(SyntaxReport),
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

    /// Validates canonical Splash source without evaluating it or entering any
    /// host binding.
    ///
    /// This is suitable for LLM preflight and editor validation. It checks the
    /// portable Splash v0.1 grammar, then confirms VM compatibility. Imports,
    /// capability grants, schemas, and tool names remain host-policy decisions
    /// that are validated at execution time.
    pub fn check_syntax(&self, source: &str) -> Result<SyntaxReport, RuntimeError> {
        check_syntax_named("inline.splash", source, self.limits)
    }

    /// Evaluates source only after it passes the canonical Splash v0.1 profile.
    ///
    /// This is the normal execution entry point for generated and user-authored
    /// source. Use [`Self::eval_vm_compatibility`] only for a trusted host that
    /// deliberately needs a Makepad compatibility construct outside Splash.
    pub fn eval(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        let report = self.check_syntax(source)?;
        if !report.valid {
            return Err(RuntimeError::SyntaxRejected(report));
        }
        self.eval_vm_compatibility(source)
    }

    /// Evaluates the vendored Makepad parser's broader compatibility syntax.
    ///
    /// This bypasses Splash's portable grammar contract and must not receive
    /// LLM-generated or otherwise untrusted source. Prefer [`Self::eval`] for
    /// all normal Splash execution.
    pub fn eval_vm_compatibility(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        validate_source_length(source, self.limits)?;

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
/// Splash v0.1 grammar. Only source accepted by that profile reaches the
/// vendored VM parser for a compatibility check. `file` appears only in
/// VM-parser diagnostics. It never loads a module, resolves an import, runs
/// bytecode, or invokes a host tool.
pub fn check_syntax_named(
    file: &str,
    source: &str,
    limits: ExecutionLimits,
) -> Result<SyntaxReport, RuntimeError> {
    let profile = check_profile_named(source, limits)?;
    if !profile.valid {
        return Ok(profile);
    }

    let mut diagnostics = Vec::new();
    let mut diagnostics_truncated = false;

    let mut base = vm::ScriptVmBase::new();
    let mut tokenizer = ScriptTokenizer::default();
    tokenizer.tokenize(&format!("{source}\n;"), &mut base.heap);
    let mut parser = ScriptParser::default();
    parser.set_emit_errors(false);
    parser.parse(&tokenizer, file, (0, 0), &[]);

    let (delimiter_diagnostics, delimiter_diagnostics_truncated) =
        delimiter_diagnostics(&tokenizer);
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

    Ok(SyntaxReport {
        valid: !parser.had_error && diagnostics.is_empty(),
        diagnostics,
        diagnostics_truncated,
    })
}

fn check_profile_named(
    source: &str,
    limits: ExecutionLimits,
) -> Result<SyntaxReport, RuntimeError> {
    let limits = limits.validate()?;
    validate_source_length(source, limits)?;

    let profile = check_canonical_profile(source, limits.max_syntax_tokens);
    if !profile.diagnostics.is_empty() || profile.diagnostics_truncated {
        return Ok(SyntaxReport {
            valid: false,
            diagnostics: profile.diagnostics,
            diagnostics_truncated: profile.diagnostics_truncated,
        });
    }

    Ok(SyntaxReport {
        valid: true,
        diagnostics: Vec::new(),
        diagnostics_truncated: false,
    })
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum Delimiter {
    Curly,
    Round,
    Square,
}

impl Delimiter {
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

fn delimiter_diagnostics(tokenizer: &ScriptTokenizer) -> (Vec<SyntaxDiagnostic>, bool) {
    let mut diagnostics = Vec::new();
    let mut truncated = false;
    let mut openings = Vec::new();

    for (index, token_position) in tokenizer.tokens.iter().enumerate() {
        let opening = match token_position.token {
            ScriptToken::OpenCurly => Some(Delimiter::Curly),
            ScriptToken::OpenRound => Some(Delimiter::Round),
            ScriptToken::OpenSquare => Some(Delimiter::Square),
            _ => None,
        };
        if let Some(opening) = opening {
            openings.push((opening, index));
            continue;
        }

        let closing = match token_position.token {
            ScriptToken::CloseCurly => Some(Delimiter::Curly),
            ScriptToken::CloseRound => Some(Delimiter::Round),
            ScriptToken::CloseSquare => Some(Delimiter::Square),
            ScriptToken::StringUnfinished => {
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
            }
            _ => None,
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
    fn checks_tool_syntax_without_a_capability_host() {
        let report = check_syntax("use mod.tool\ntool.call(\"text.echo\", \"hello\")").unwrap();

        assert!(report.valid, "{:?}", report.diagnostics);
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
            let profile = check_canonical_profile(&source, limits.max_syntax_tokens);
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
        let source = format!("let value = {}0{}", "(".repeat(129), ")".repeat(129));
        let report = check_syntax(&source).unwrap();

        assert!(!report.valid);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("canonical Splash nesting exceeds the maximum")
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
