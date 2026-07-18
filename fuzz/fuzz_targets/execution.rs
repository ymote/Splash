#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use splash_core::{check_syntax_named, ExecutionLimits, Runtime, DEFAULT_MAX_SCRIPT_HEAP_BYTES};

const MAX_FUZZ_SOURCE_BYTES: usize = 8 * 1024;
const MAX_FUZZ_SYNTAX_TOKENS: usize = 1_024;
const MAX_FUZZ_SYNTAX_NESTING: usize = 64;
const FUZZ_INSTRUCTION_LIMIT: usize = 4_096;
const FUZZ_EXECUTION_DEADLINE: Duration = Duration::from_millis(32);

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    if source.len() > MAX_FUZZ_SOURCE_BYTES {
        return;
    }

    let limits = ExecutionLimits {
        max_source_bytes: MAX_FUZZ_SOURCE_BYTES,
        max_string_bytes: MAX_FUZZ_SOURCE_BYTES,
        max_heap_bytes: DEFAULT_MAX_SCRIPT_HEAP_BYTES,
        max_stack_values: MAX_FUZZ_SYNTAX_TOKENS,
        max_call_frames: MAX_FUZZ_SYNTAX_NESTING * 4,
        max_syntax_tokens: MAX_FUZZ_SYNTAX_TOKENS,
        max_syntax_nesting: MAX_FUZZ_SYNTAX_NESTING,
        instruction_limit: FUZZ_INSTRUCTION_LIMIT,
        // Equal deadlines turn an elapsed sample into a terminal bounded
        // failure instead of leaving a time-yielded thread to resume.
        soft_timeout: FUZZ_EXECUTION_DEADLINE,
        hard_timeout: FUZZ_EXECUTION_DEADLINE,
        budget_sample_interval: 1,
    };
    let syntax = check_syntax_named("fuzz-execution.splash", source, limits)
        .expect("the fuzz limits are always valid for syntax checking");
    if !syntax.valid {
        return;
    }

    // The empty host installs no capabilities or Rust adapters. Valid source
    // may report a script-level error for an unavailable module, but it must
    // always return through the bounded evaluator rather than panic or hang.
    let mut runtime = Runtime::with_limits((), (), limits)
        .expect("the fuzz limits are always valid for execution");
    let report = runtime
        .eval(source)
        .expect("syntax-accepted source must enter the evaluator");
    assert!(
        !report.suspended,
        "equal fuzz deadlines must not leave a resumable evaluation"
    );
    drop(report);
    runtime.collect_garbage();
});
