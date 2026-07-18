#![no_main]

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use splash_capabilities::{CapabilityLeaseGrant, CapabilityRuntime, ToolPolicy};
use splash_core::{ExecutionLimits, DEFAULT_MAX_SCRIPT_HEAP_BYTES};

const MAX_FUZZ_SOURCE_BYTES: usize = 8 * 1024;
const MAX_FUZZ_SYNTAX_TOKENS: usize = 1_024;
const MAX_FUZZ_SYNTAX_NESTING: usize = 64;
const FUZZ_INSTRUCTION_LIMIT: usize = 4_096;
const FUZZ_EXECUTION_DEADLINE: Duration = Duration::from_millis(32);
const MAX_PENDING_TOOLS: usize = 2;
const MAX_PUMP_TICKS: usize = 4;

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
        // Equal deadlines turn an elapsed sample into a terminal failure.
        soft_timeout: FUZZ_EXECUTION_DEADLINE,
        hard_timeout: FUZZ_EXECUTION_DEADLINE,
        budget_sample_interval: 1,
    };
    let permitted_calls = Rc::new(Cell::new(0));
    let observed_permitted_calls = permitted_calls.clone();
    let restricted_calls = Rc::new(Cell::new(0));
    let observed_restricted_calls = restricted_calls.clone();
    let mut runtime = CapabilityRuntime::with_limits_and_pending(limits, MAX_PENDING_TOOLS)
        .expect("the fuzz limits are always valid");
    runtime
        .register_tool(ToolPolicy::new("text.echo"), move |request| {
            permitted_calls.set(permitted_calls.get() + 1);
            Ok(request.input.clone())
        })
        .expect("fixed permitted tool registers");
    runtime
        .register_tool(ToolPolicy::new("admin.secret"), move |_| {
            restricted_calls.set(restricted_calls.get() + 1);
            Ok("must not run".to_owned())
        })
        .expect("fixed restricted tool registers");
    let lease = runtime
        .issue_capability_lease([CapabilityLeaseGrant::new("text.echo", 1)])
        .expect("fixed narrow lease issues");

    let Ok(mut report) = runtime.eval_with_capability_lease(source, &lease) else {
        return;
    };
    for _ in 0..MAX_PUMP_TICKS {
        if !report.succeeded() || !report.suspended {
            break;
        }
        let pumped = runtime
            .pump()
            .expect("local host-pump work must resume a valid waiting thread");
        let Some(resumed) = pumped.resumed.into_iter().last() else {
            break;
        };
        report = resumed;
    }

    assert!(
        !(report.succeeded() && report.suspended),
        "a catalog containing only local host-pump tools must not remain suspended"
    );
    runtime
        .pump_up_to(MAX_PENDING_TOOLS)
        .expect("unawaited local work must not resume an unknown thread");
    assert_eq!(
        observed_restricted_calls.get(),
        0,
        "an ungranted registered capability reached its Rust adapter"
    );
    assert!(
        observed_permitted_calls.get() <= 1,
        "a one-call lease exceeded its host-side budget"
    );
    assert!(
        runtime.pending_tools() <= MAX_PENDING_TOOLS,
        "pending capability work exceeded its configured cap"
    );
    runtime.collect_garbage();
});
