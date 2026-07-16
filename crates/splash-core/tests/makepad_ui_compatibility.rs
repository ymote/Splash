use splash_core::{check_syntax, check_vm_compatibility_named, ExecutionLimits};

const MAKEPAD_UI_COUNTER: &str = include_str!("../../../examples/makepad_ui_counter.splash");

#[test]
fn makepad_ui_counter_is_accepted_by_the_bounded_vm_compatibility_check() {
    let report = check_vm_compatibility_named(
        "examples/makepad_ui_counter.splash",
        MAKEPAD_UI_COUNTER,
        ExecutionLimits::default(),
    )
    .unwrap();

    assert!(report.valid, "{:?}", report.diagnostics);
}

#[test]
fn makepad_ui_counter_remains_outside_the_canonical_workflow_profile() {
    let report = check_syntax(MAKEPAD_UI_COUNTER).unwrap();

    assert!(!report.valid, "unexpectedly accepted Makepad UI source");
}
