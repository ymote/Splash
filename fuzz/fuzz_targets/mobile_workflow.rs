#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};
use splash_capabilities::CapabilityLeaseGrant;
use splash_core::{ExecutionLimits, DEFAULT_MAX_SCRIPT_HEAP_BYTES};
use splash_workflow::{
    mobile::MobileWorkflowBuilder, WorkflowData, WorkflowStep, WorkflowStepCapabilityPolicy,
};

const MAX_FUZZ_CASE_BYTES: usize = 16 * 1024;
const MAX_FUZZ_SOURCE_BYTES: usize = 8 * 1024;
const MIN_FUZZ_SOURCE_BYTES: usize = 64;
const MAX_FUZZ_SYNTAX_NESTING: usize = 64;
const MIN_FUZZ_SYNTAX_NESTING: usize = 2;
const FUZZ_INSTRUCTION_LIMIT: usize = 4_096;
const FUZZ_EXECUTION_DEADLINE: Duration = Duration::from_millis(32);
const FUZZ_STEP_ID: &str = "transform";

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
    let input = case.get("input").cloned().unwrap_or(Value::Null);
    let Ok(dataflow) = WorkflowData::new(input) else {
        return;
    };

    let mut runtime = MobileWorkflowBuilder::with_limits(fuzz_limits(case), 1)
        .expect("the bounded mobile workflow fuzz limits are always valid")
        .build();
    let Ok(plan) = runtime.plan(vec![WorkflowStep::new(FUZZ_STEP_ID, source)]) else {
        return;
    };
    let Ok(approval) = runtime.approve_dataflow_with_step_capability_policies(
        &plan,
        dataflow,
        vec![WorkflowStepCapabilityPolicy::new(
            FUZZ_STEP_ID,
            Vec::<CapabilityLeaseGrant>::new(),
        )],
    ) else {
        return;
    };

    if let Ok(completed) = runtime.execute_dataflow(&plan, approval) {
        assert!(
            completed.output(FUZZ_STEP_ID).is_some(),
            "a completed one-step dataflow retains exactly one output"
        );
        assert_eq!(runtime.dataflow_snapshot(), Some(&completed));
        let encoded = completed
            .to_json()
            .expect("a completed bounded workflow context encodes");
        assert_eq!(
            WorkflowData::from_json(&encoded)
                .expect("a completed workflow context decodes from its own encoding"),
            completed
        );
    }

    assert!(
        !runtime.has_suspended_execution(),
        "an empty sealed mobile catalog must not suspend workflow execution"
    );
    assert_eq!(runtime.pending_tools(), 0);
    assert!(runtime.tool_catalog().is_empty());
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
        // failure instead of leaving a resumable workflow continuation.
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
