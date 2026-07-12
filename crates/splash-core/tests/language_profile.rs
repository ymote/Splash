use splash_core::Runtime;

#[test]
fn workflow_language_fixture_is_compatible_with_the_runtime_profile() {
    let mut runtime = Runtime::default();
    let report = runtime
        .eval(include_str!("fixtures/workflow_language.splash"))
        .unwrap();

    assert!(report.succeeded(), "{:?}", report.diagnostics);
}
