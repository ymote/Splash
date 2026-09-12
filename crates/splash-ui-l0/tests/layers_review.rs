//! Regressions for the completed L0–L3 boundary review.
use serde_json::json;
use splash_ui_l0::*;

fn card(expr: &str) -> String {
    format!("# level: L1\nsource q sys.quote(ticker: \"N\", fields: [last, open])\nview root Surface {{ TextHero(value: {expr}) }}")
}

#[test]
fn flat_expression_trees_are_bounded_before_all_consumers() {
    for op in ["+", "*"] {
        let src = card(&vec!["q.last"; 20_000].join(op));
        let check = check_ui_l0(&src);
        assert!(!check.valid);
        assert!(check.diagnostics.iter().any(|d| d.message.contains("deep")));
        assert!(
            realize(&src, &json!({"q":{"last":3}}), RealizeLimits::default())
                .complete_root()
                .is_err()
        );
    }
}

#[test]
fn constant_analysis_does_not_sample_inputs() {
    assert!(check_ui_l0(&card("(q.last - 2) * (q.last - 5) * (q.last - 11)")).valid);
    assert!(!check_ui_l0(&card("(q.last - 2) / (q.last - 2) * 1547")).valid);
    assert!(check_ui_l0(&card("q.last - q.open")).valid);
}

#[test]
fn component_arguments_preserve_values_and_live_arithmetic() {
    let inline = card("q.last * 2");
    let component = inline
        .replace(
            "view root",
            "component Hero(v: number) { view TextHero(value: v) }\nview root",
        )
        .replace("TextHero(value: q.last * 2)", "Hero(v: q.last * 2)");
    let data = json!({"q":{"last":4}});
    let a = realize(&inline, &data, RealizeLimits::default());
    let b = realize(&component, &data, RealizeLimits::default());
    let a = &a.complete_root().unwrap().children[0];
    let b = &b.complete_root().unwrap().children[0];
    assert_eq!(a.args, b.args);
    assert_eq!(a.exprs, b.exprs);
    assert_eq!(kit::lower(a), kit::lower(b));
}

#[test]
fn component_predicates_resolve_both_operands() {
    let src = "state n { shape: number, initial: 2 }\ncomponent Flag(v: bool) { view Surface { when v { Rule() } } }\nview root Surface { Flag(v: n == 2) }";
    let report = realize(src, &json!({}), RealizeLimits::default());
    assert_eq!(
        report.complete_root().unwrap().children[0].children[0].kind,
        "Rule"
    );
    let report = realize(
        &src.replace("n == 2", "n == 3"),
        &json!({}),
        RealizeLimits::default(),
    );
    assert!(report.complete_root().unwrap().children[0]
        .children
        .is_empty());
}

#[test]
fn duplicates_never_collide_with_authored_suffixes() {
    let src = "source q sys.movers(fields: [name, last])\ncomponent Item(v: number) { state expanded { shape: bool, initial: false } event toggle { expanded: toggle } view Surface { TextRow(text: v) when expanded { Rule() } } }\nview root Surface { for x in q key x.name { Item(v: x.last) } }";
    let report = realize(
        src,
        &json!({"q":[{"name":"A","last":1},{"name":"A","last":2},{"name":"A#1","last":3}]}),
        RealizeLimits::default(),
    );
    assert!(report.complete_root().is_err());
    let children = &report.root.as_ref().unwrap().children;
    assert_eq!(children.len(), 2);
    assert_ne!(children[0].key, children[1].key);
}

#[test]
fn patch_cannot_restore_a_tree_past_its_budget_or_overwrite_edits() {
    let src = "view root Surface { Rule() Rule() Rule() }";
    let previous = realize(src, &json!({}), RealizeLimits::default());
    let previous = previous.complete_root().unwrap();
    let patch = realize_patch(
        src,
        &json!({}),
        None,
        previous,
        &[],
        RealizeLimits {
            max_nodes: 1,
            ..RealizeLimits::default()
        },
    );
    assert!(patch.complete_root().is_err());
    assert_eq!(patch.reused, 0);
    assert!(patch.root.as_ref().is_none_or(|n| n.children.is_empty()));
    let patch = realize_patch(
        "view root Surface { TextRow(text: \"changed\") }",
        &json!({}),
        None,
        previous,
        &[],
        RealizeLimits::default(),
    );
    assert_eq!(patch.complete_root().unwrap().children[0].kind, "TextRow");
}

#[test]
fn fingerprints_cover_keys_and_transitive_definitions() {
    let src = "source q sys.movers(fields: [ticker, name, last])\ncomponent Items() { view Surface { for x in q key x.ticker { TextRow(text: x.last) } } }\nview root Items()";
    let digest = |s: &str| {
        let r = check_ui_l0(s);
        assert!(r.valid, "{:?}", r.diagnostics);
        r.closure
    };
    assert_ne!(
        digest(src),
        digest(&src.replace("key x.ticker", "key x.name"))
    );
    let src = "view leaf TextRow(text: \"a\")\ncomponent Child() { view leaf }\ncomponent Parent() { view Child() }\nview root Parent()";
    assert_ne!(
        digest(src),
        digest(&src.replace("text: \"a\"", "text: \"b\""))
    );
    assert_eq!(digest(src), digest(&format!("\n\n{src}\n")));
}

#[test]
fn component_expression_substitution_charges_its_expansion() {
    let mut src = String::from("# level: L1\nsource q sys.quote(ticker: \"N\", fields: [last])\n");
    for i in 0..24 {
        src.push_str(&format!(
            "component C{i}(v: number) {{ view C{}(v: v + v) }}\n",
            i + 1
        ));
    }
    src.push_str("component C24(v: number) { view TextHero(value: v) }\nview root C0(v: q.last)\n");
    assert!(check_ui_l0(&src).valid);
    let report = realize(&src, &json!({"q":{"last":1}}), RealizeLimits::default());
    assert!(report.truncated);
    assert!(report.complete_root().is_err());
}
