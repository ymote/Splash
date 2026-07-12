#![forbid(unsafe_code)]

//! Host-neutral execution primitives for Splash.
//!
//! The vendored VM exposes pure language modules only. This crate owns runtime
//! limits and diagnostic capture; effectful APIs belong to a separate host
//! crate and must be explicitly installed by trusted Rust code.

use std::any::Any;
use std::fmt::{self, Display, Formatter};
use std::time::Duration;

pub use makepad_script as vm;

pub const DEFAULT_MAX_SOURCE_BYTES: usize = 256 * 1024;
pub const DEFAULT_INSTRUCTION_LIMIT: usize = 200_000;
pub const DEFAULT_SOFT_TIMEOUT: Duration = Duration::from_millis(32);
pub const DEFAULT_HARD_TIMEOUT: Duration = Duration::from_millis(64);
pub const DEFAULT_BUDGET_SAMPLE_INTERVAL: u32 = 1_024;

/// Bounds applied to one source evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLimits {
    pub max_source_bytes: usize,
    pub instruction_limit: usize,
    pub soft_timeout: Duration,
    pub hard_timeout: Duration,
    pub budget_sample_interval: u32,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
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

    pub fn eval(&mut self, source: &str) -> Result<Evaluation, RuntimeError> {
        if source.len() > self.limits.max_source_bytes {
            return Err(RuntimeError::SourceTooLarge {
                actual: source.len(),
                maximum: self.limits.max_source_bytes,
            });
        }

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
