#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use splash_core::{
    check_syntax_named, ExecutionLimits, Runtime, RuntimeError, DEFAULT_MAX_SCRIPT_HEAP_BYTES,
};

const MAX_FUZZ_SOURCE_BYTES: usize = 8 * 1024;
const MAX_FUZZ_SYNTAX_TOKENS: usize = 1_024;
const MAX_FUZZ_SYNTAX_NESTING: usize = 64;
const FUZZ_INSTRUCTION_LIMIT: usize = 4_096;
const FUZZ_EXECUTION_DEADLINE: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq)]
struct ReplayObservation {
    succeeded: bool,
    suspended: bool,
    diagnostics: Vec<String>,
    result: Option<Result<serde_json::Value, RuntimeError>>,
}

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
        // The instruction limit bounds interpreter progress. The long equal
        // deadlines avoid scheduling-dependent soft yields while preserving a
        // terminal wall-clock bound for native helper work.
        soft_timeout: FUZZ_EXECUTION_DEADLINE,
        hard_timeout: FUZZ_EXECUTION_DEADLINE,
        budget_sample_interval: 1,
    };
    let syntax = check_syntax_named("fuzz-execution-replay.splash", source, limits)
        .expect("the fuzz limits are always valid for syntax checking");
    if !syntax.valid {
        return;
    }

    // Fresh runtimes have the same frozen standard library but no adapters,
    // globals, capabilities, or promises. Replay therefore covers only the
    // canonical evaluator's deterministic observable result, not host effects.
    let mut first_runtime = Runtime::with_limits((), (), limits)
        .expect("the fuzz limits are always valid for execution");
    let mut second_runtime = Runtime::with_limits((), (), limits)
        .expect("the fuzz limits are always valid for execution");
    let first = observe(&mut first_runtime, source);
    let second = observe(&mut second_runtime, source);

    assert!(
        !first.suspended && !second.suspended,
        "equal replay deadlines must not leave a resumable evaluation"
    );
    assert_eq!(
        first, second,
        "independent capability-free evaluator runs diverged for {source:?}"
    );

    first_runtime.collect_garbage();
    second_runtime.collect_garbage();
});

fn observe(runtime: &mut Runtime, source: &str) -> ReplayObservation {
    let evaluation = runtime
        .eval(source)
        .expect("syntax-accepted source must enter the evaluator");
    let succeeded = evaluation.succeeded();
    let suspended = evaluation.suspended;
    let result = if succeeded && !suspended {
        Some(runtime.script_value_as_json(
            evaluation.value,
            MAX_FUZZ_SOURCE_BYTES,
            MAX_FUZZ_SYNTAX_NESTING,
        ))
    } else {
        None
    };

    ReplayObservation {
        succeeded,
        suspended,
        diagnostics: evaluation.diagnostics,
        result,
    }
}
