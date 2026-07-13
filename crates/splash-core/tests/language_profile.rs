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
