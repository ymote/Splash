#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};
use splash_capabilities::mobile::MobileRuntimeBuilder;
use splash_core::{ExecutionLimits, DEFAULT_MAX_SCRIPT_HEAP_BYTES};

const MAX_FUZZ_CASE_BYTES: usize = 16 * 1024;
const MAX_FUZZ_SOURCE_BYTES: usize = 8 * 1024;
const MIN_FUZZ_SOURCE_BYTES: usize = 64;
const MAX_FUZZ_SYNTAX_NESTING: usize = 64;
const MIN_FUZZ_SYNTAX_NESTING: usize = 2;
const FUZZ_INSTRUCTION_LIMIT: usize = 4_096;
const FUZZ_EXECUTION_DEADLINE: Duration = Duration::from_millis(32);

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_CASE_BYTES {
        return;
    }
    let Ok(case) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let Some(case) = case.as_object() else {
        return;
    };
    let Some(source) = case.get("source").and_then(Value::as_str) else {
        return;
    };
    if source.len() > MAX_FUZZ_SOURCE_BYTES {
        return;
    }

    let name = case
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("workflow");
    let input = case.get("input").unwrap_or(&Value::Null);
    let limits = fuzz_limits(case);
    let mut runtime = MobileRuntimeBuilder::with_limits(limits, 1)
        .expect("the bounded mobile fuzz limits are always valid")
        .build();

    // The sealed facade owns the only host-data crossing. An invalid name or
    // oversized/deep value is a normal rejected boundary, never a reason to
    // construct a capability host or evaluate source.
    if runtime.set_json_global(name, input).is_err() {
        return;
    }

    let Ok(report) = runtime.eval(source) else {
        return;
    };
    assert!(
        !report.suspended,
        "an empty sealed mobile catalog must not leave a resumable evaluation"
    );
    if report.completed() {
        let _ = runtime.script_value_as_json(report.value);
    }
    drop(report);

    runtime
        .clear_json_global(name)
        .expect("a terminal mobile evaluation permits host-data cleanup");
    runtime.collect_garbage();
});

fn fuzz_limits(case: &Map<String, Value>) -> ExecutionLimits {
    let mut limits = ExecutionLimits {
        max_source_bytes: MAX_FUZZ_SOURCE_BYTES,
        max_string_bytes: MAX_FUZZ_SOURCE_BYTES,
        max_heap_bytes: DEFAULT_MAX_SCRIPT_HEAP_BYTES,
        max_stack_values: 1_024,
        max_call_frames: MAX_FUZZ_SYNTAX_NESTING * 4,
        max_syntax_tokens: 1_024,
        max_syntax_nesting: MAX_FUZZ_SYNTAX_NESTING,
        instruction_limit: FUZZ_INSTRUCTION_LIMIT,
        // Equal deadlines turn an elapsed sample into a terminal bounded
        // failure instead of leaving a resumable thread to resume.
        soft_timeout: FUZZ_EXECUTION_DEADLINE,
        hard_timeout: FUZZ_EXECUTION_DEADLINE,
        budget_sample_interval: 1,
    };
    if let Some(max_source_bytes) = case.get("maxSourceBytes").and_then(Value::as_u64) {
        limits.max_source_bytes = usize::try_from(max_source_bytes)
            .unwrap_or(MAX_FUZZ_SOURCE_BYTES)
            .clamp(MIN_FUZZ_SOURCE_BYTES, MAX_FUZZ_SOURCE_BYTES);
    }
    if let Some(max_syntax_nesting) = case.get("maxSyntaxNesting").and_then(Value::as_u64) {
        limits.max_syntax_nesting = usize::try_from(max_syntax_nesting)
            .unwrap_or(MAX_FUZZ_SYNTAX_NESTING)
            .clamp(MIN_FUZZ_SYNTAX_NESTING, MAX_FUZZ_SYNTAX_NESTING);
    }
    limits
}
