#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use splash_core::{
    check_syntax_named, ExecutionLimits, Runtime, RuntimeError, DEFAULT_MAX_SCRIPT_HEAP_BYTES,
};

const MAX_FUZZ_SOURCE_BYTES: usize = 8 * 1024;
const MAX_FUZZ_SYNTAX_TOKENS: usize = 1_024;
const MAX_FUZZ_SYNTAX_NESTING: usize = 64;
const MIN_FUZZ_HEAP_BYTES: usize = 2 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let Ok(unbounded_source) = std::str::from_utf8(data) else {
        return;
    };
    if unbounded_source.len() > MAX_FUZZ_SOURCE_BYTES {
        return;
    }

    let limits = fuzz_limits(data);
    let source = bounded_prefix(unbounded_source, limits.max_source_bytes);
    let syntax = check_syntax_named("fuzz-execution-limits.splash", source, limits)
        .expect("the fuzz limits are always valid for syntax checking");
    if !syntax.valid {
        return;
    }

    // Start at the default and install each derived profile through the public
    // setter so valid updates remain covered as well as construction.
    let mut runtime = Runtime::new((), ()).expect("the default execution limits are valid");
    runtime
        .set_limits(limits)
        .expect("a fresh runtime accepts valid fuzz limits");
    assert_eq!(runtime.limits(), limits);

    // No adapters or capabilities are installed. A script-level failure is
    // expected for unavailable modules, but all profiles must return through
    // the bounded evaluator without a panic or a hang.
    let report = runtime
        .eval(source)
        .expect("syntax-accepted source must enter the evaluator");
    if limits.soft_timeout == limits.hard_timeout {
        assert!(
            !report.suspended,
            "equal fuzz deadlines must not leave a resumable evaluation"
        );
    }
    let suspended = report.suspended;
    drop(report);

    let replacement = replacement_limits();
    if suspended {
        // A cooperative time budget can pause the VM. Its original execution
        // contract must remain intact until the trusted host resumes it.
        assert_eq!(
            runtime.set_limits(replacement),
            Err(RuntimeError::EvaluationInProgress)
        );
        assert_eq!(runtime.limits(), limits);
    } else {
        runtime
            .set_limits(replacement)
            .expect("a completed evaluation accepts a later valid limit profile");
        assert_eq!(runtime.limits(), replacement);
    }
    runtime.collect_garbage();
});

fn fuzz_limits(data: &[u8]) -> ExecutionLimits {
    match data.first().copied().unwrap_or_default() % 5 {
        0 => ExecutionLimits {
            max_source_bytes: 64,
            max_string_bytes: 64,
            max_heap_bytes: MIN_FUZZ_HEAP_BYTES,
            max_syntax_tokens: 8,
            max_syntax_nesting: 2,
            instruction_limit: 16,
            soft_timeout: Duration::from_millis(8),
            hard_timeout: Duration::from_millis(8),
            budget_sample_interval: 1,
        },
        1 => ExecutionLimits {
            max_source_bytes: 512,
            max_string_bytes: 512,
            max_heap_bytes: MIN_FUZZ_HEAP_BYTES,
            max_syntax_tokens: 64,
            max_syntax_nesting: 4,
            instruction_limit: 64,
            soft_timeout: Duration::from_millis(8),
            hard_timeout: Duration::from_millis(8),
            budget_sample_interval: 2,
        },
        2 => ExecutionLimits {
            max_source_bytes: 4 * 1024,
            max_string_bytes: 4 * 1024,
            max_heap_bytes: 4 * 1024 * 1024,
            max_syntax_tokens: 512,
            max_syntax_nesting: 16,
            instruction_limit: 256,
            soft_timeout: Duration::from_millis(16),
            hard_timeout: Duration::from_millis(16),
            budget_sample_interval: 8,
        },
        3 => ExecutionLimits {
            max_source_bytes: MAX_FUZZ_SOURCE_BYTES,
            max_string_bytes: MAX_FUZZ_SOURCE_BYTES,
            max_heap_bytes: 4 * 1024 * 1024,
            max_syntax_tokens: MAX_FUZZ_SYNTAX_TOKENS,
            max_syntax_nesting: MAX_FUZZ_SYNTAX_NESTING,
            instruction_limit: 4_096,
            soft_timeout: Duration::from_nanos(1),
            hard_timeout: Duration::from_millis(32),
            budget_sample_interval: 1,
        },
        _ => ExecutionLimits {
            max_source_bytes: MAX_FUZZ_SOURCE_BYTES,
            max_string_bytes: MAX_FUZZ_SOURCE_BYTES,
            max_heap_bytes: DEFAULT_MAX_SCRIPT_HEAP_BYTES,
            max_syntax_tokens: MAX_FUZZ_SYNTAX_TOKENS,
            max_syntax_nesting: MAX_FUZZ_SYNTAX_NESTING,
            instruction_limit: 4_096,
            soft_timeout: Duration::from_millis(32),
            hard_timeout: Duration::from_millis(32),
            budget_sample_interval: 64,
        },
    }
}

fn replacement_limits() -> ExecutionLimits {
    ExecutionLimits {
        max_source_bytes: MAX_FUZZ_SOURCE_BYTES,
        max_string_bytes: MAX_FUZZ_SOURCE_BYTES,
        max_heap_bytes: DEFAULT_MAX_SCRIPT_HEAP_BYTES,
        max_syntax_tokens: MAX_FUZZ_SYNTAX_TOKENS,
        max_syntax_nesting: MAX_FUZZ_SYNTAX_NESTING,
        instruction_limit: 512,
        soft_timeout: Duration::from_millis(16),
        hard_timeout: Duration::from_millis(16),
        budget_sample_interval: 4,
    }
}

fn bounded_prefix(source: &str, maximum_bytes: usize) -> &str {
    let mut end = source.len().min(maximum_bytes);
    while end > 0 && !source.is_char_boundary(end) {
        end -= 1;
    }
    &source[..end]
}
