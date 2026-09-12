use serde_json::json;
use splash_ui_l0::{approval::ArtifactApproval, *};

fn tree(source: &str, data: serde_json::Value, store: &InstanceStore) -> UiNode {
    realize_with_state(source, &data, store, RealizeLimits::default())
        .complete_root()
        .unwrap()
        .clone()
}
fn value(node: &UiNode) -> &NodeValue {
    &node.args.iter().find(|(n, _)| n == "value").unwrap().1
}

const FORM: &str = r#"
state amount { shape: text, initial: "1547" }
event input { amount: set($value) }
event reset { amount: clear }
view root Surface {
  Field(text: amount, on_commit: input, on_change: input)
  TextHero(value: amount)
  Row(on_tap: input, value: "1547") { TextRow(text: "Use default") }
}
"#;

#[test]
fn defaults_remain_editable_but_cannot_become_data_through_a_tap() {
    let mut store = InstanceStore::default();
    let root = tree(FORM, json!({}), &store);
    assert_eq!(*value(&root.children[1]), NodeValue::Missing);
    assert!(root.children[0]
        .args
        .contains(&("text".into(), NodeValue::Text("1547".into()))));
    let row = &root.children[2];
    let origin = event_payload_origin(&root, &row.key, "input").unwrap();
    assert_eq!(origin, ValueOrigin::Authored);
    dispatch_reporting_with_origin(
        FORM,
        &mut store,
        &row.key,
        "input",
        Some(&json!("1547")),
        &json!({}),
        origin,
    );
    assert_eq!(
        *value(&tree(FORM, json!({}), &store).children[1]),
        NodeValue::Missing
    );
    assert_eq!(event_payload_origin(&root, &row.key, "invented"), None);
}

#[test]
fn typing_the_same_default_is_a_change_of_origin_and_reset_revokes_it() {
    let mut store = InstanceStore::default();
    let root = tree(FORM, json!({}), &store);
    let field = &root.children[0];
    let origin = event_payload_origin(&root, &field.key, "input").unwrap();
    let outcome = dispatch_reporting_with_origin(
        FORM,
        &mut store,
        &field.key,
        "input",
        Some(&json!("1547")),
        &json!({}),
        origin,
    );
    assert!(outcome.applied);
    assert_eq!(
        store.origin(CARD_STATE_KEY, "amount"),
        Some(ValueOrigin::UserInput)
    );
    assert_eq!(
        *value(&tree(FORM, json!({}), &store).children[1]),
        NodeValue::Text("1547".into())
    );
    assert!(dispatch(FORM, &mut store, "root", "reset"));
    assert_eq!(
        *value(&tree(FORM, json!({}), &store).children[1]),
        NodeValue::Missing
    );
}

#[test]
fn origin_survives_nested_props_and_l1_formulas_without_live_bypass() {
    let source = "# level: L1\nstate n { shape: number, initial: 1547 }\ncomponent Inner(v: number) { view TextHero(value: v) }\ncomponent Outer(v: number) { view Inner(v: v * 2) }\nview root Surface { Outer(v: n) }";
    let mut store = InstanceStore::default();
    let root = tree(source, json!({}), &store);
    let hero = &root.children[0];
    assert_eq!(*value(hero), NodeValue::Missing);
    assert!(hero.exprs.is_empty() && hero.bindings.is_empty());
    assert!(!kit::lower(&root).contains("1547"));
    store.set_cell(CARD_STATE_KEY, "n", json!(3));
    assert_eq!(
        *value(&tree(source, json!({}), &store).children[0]),
        NodeValue::Number(6.0)
    );
}

#[test]
fn source_captures_and_loop_props_keep_their_origin() {
    let source = "source q sys.quote(ticker: \"N\", fields: [last])\nstate n { shape: number, initial: q.last }\nview root Surface { TextHero(value: n) }";
    let mut store = InstanceStore::default();
    assert_eq!(
        *value(&tree(source, json!({}), &store).children[0]),
        NodeValue::Missing
    );
    let report = realize_with_state(
        source,
        &json!({"q":{"last":5}}),
        &store,
        RealizeLimits::default(),
    );
    assert_eq!(
        *value(&report.complete_root().unwrap().children[0]),
        NodeValue::Number(5.0)
    );
    for (path, value) in report.captured {
        store.set_cell_with_origin(CARD_STATE_KEY, &path, value, ValueOrigin::Source);
    }
    assert_eq!(
        *value(&tree(source, json!({"q":{"last":9}}), &store).children[0]),
        NodeValue::Number(5.0)
    );
    let source = "source rows sys.movers(fields: [name, last])\ncomponent Hero(row: record) { view TextHero(value: row.last) }\nview root Surface { for row in rows key row.name { Hero(row: row) } }";
    let root = tree(
        source,
        json!({"rows":[{"name":"N","last":7}]}),
        &InstanceStore::default(),
    );
    assert_eq!(*value(&root.children[0]), NodeValue::Number(7.0));
}

#[test]
fn approval_pins_source_level_kit_and_runtime() {
    let source = "view root Surface { Rule() }";
    let approval = ArtifactApproval::admit(source, "runtime-a", "kit-a").unwrap();
    let restored = ArtifactApproval::from_json(&approval.to_json()).unwrap();
    restored.verify(source, "runtime-a", "kit-a").unwrap();
    for (source, runtime, kit) in [
        ("view root Surface { Gap(size: 2) }", "runtime-a", "kit-a"),
        (source, "runtime-b", "kit-a"),
        (source, "runtime-a", "kit-b"),
        (
            "# level: L1\nview root Surface { Rule() }",
            "runtime-a",
            "kit-a",
        ),
    ] {
        assert!(restored.verify(source, runtime, kit).is_err());
    }
    assert!(ArtifactApproval::admit(
        "# level: L2\nview root Surface { Rule() }",
        "runtime-a",
        "kit-a"
    )
    .is_err());
    let mut bad = approval.to_json();
    bad["version"] = json!(2);
    assert!(ArtifactApproval::from_json(&bad).is_err());
}
