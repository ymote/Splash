use splash_capabilities::{AuditOutcome, CapabilityRuntime, ToolPolicy};

#[test]
fn executes_shipped_canonical_fixtures_through_real_capability_bindings() {
    let mut runtime = CapabilityRuntime::default();
    runtime
        .register_tool(ToolPolicy::new("text.echo"), |request| {
            Ok(request.input.clone())
        })
        .unwrap();
    runtime
        .register_json_tool(ToolPolicy::json("math.add"), |request| {
            let left = request.input["left"]
                .as_i64()
                .expect("canonical fixture supplies a left integer");
            let right = request.input["right"]
                .as_i64()
                .expect("canonical fixture supplies a right integer");
            Ok(serde_json::json!({"total": left + right}))
        })
        .unwrap();

    for (name, source) in [
        (
            "workflow_language.splash",
            include_str!("../../splash-core/tests/fixtures/workflow_language.splash"),
        ),
        (
            "grammar_v0_1.splash",
            include_str!("../../splash-core/tests/fixtures/grammar_v0_1.splash"),
        ),
        (
            "grammar_v0_2.splash",
            include_str!("../../splash-core/tests/fixtures/grammar_v0_2.splash"),
        ),
    ] {
        let evaluation = runtime.eval(source).unwrap();
        assert!(
            evaluation.completed(),
            "{name}: {:?}",
            evaluation.diagnostics
        );
    }

    let initial = runtime
        .eval(include_str!(
            "../../splash-core/tests/fixtures/canonical_constructs.splash"
        ))
        .unwrap();
    assert!(initial.suspended);

    let pump = runtime.pump().unwrap();
    assert_eq!(pump.completed, 1);
    assert_eq!(pump.resumed.len(), 1);
    assert!(
        pump.resumed[0].completed(),
        "{:?}",
        pump.resumed[0].diagnostics
    );

    // The grammar and construct fixtures assert their registered-tool results.
    assert_eq!(
        runtime
            .audit()
            .iter()
            .map(|event| event.tool.as_str())
            .collect::<Vec<_>>(),
        vec!["math.add", "text.echo"]
    );
    assert!(runtime
        .audit()
        .iter()
        .all(|event| event.outcome == AuditOutcome::Allowed));
}
