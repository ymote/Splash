use splash_core::{check_syntax, Runtime};

#[test]
fn workflow_language_fixture_is_compatible_with_the_runtime_profile() {
    let mut runtime = Runtime::default();
    let report = runtime
        .eval(include_str!("fixtures/workflow_language.splash"))
        .unwrap();

    assert!(report.succeeded(), "{:?}", report.diagnostics);
}

#[test]
fn grammar_v0_1_fixture_is_accepted_without_capabilities_or_execution() {
    let report = check_syntax(include_str!("fixtures/grammar_v0_1.splash")).unwrap();

    assert!(report.valid, "{:?}", report.diagnostics);
}

#[test]
fn grammar_v0_2_fixture_is_accepted_without_capabilities_or_execution() {
    let report = check_syntax(include_str!("fixtures/grammar_v0_2.splash")).unwrap();

    assert!(report.valid, "{:?}", report.diagnostics);
}

#[test]
fn canonical_construct_fixture_is_accepted_without_execution() {
    let report = check_syntax(include_str!("fixtures/canonical_constructs.splash")).unwrap();

    assert!(report.valid, "{:?}", report.diagnostics);
}

#[test]
fn shipped_workflow_examples_follow_the_canonical_profile() {
    for (name, source) in [
        (
            "deferred_tool_workflow.splash",
            include_str!("../../../examples/deferred_tool_workflow.splash"),
        ),
        (
            "json_tool_workflow.splash",
            include_str!("../../../examples/json_tool_workflow.splash"),
        ),
        (
            "tool_workflow.splash",
            include_str!("../../../examples/tool_workflow.splash"),
        ),
    ] {
        let report = check_syntax(source).unwrap();

        assert!(report.valid, "{name}: {:?}", report.diagnostics);
    }
}
