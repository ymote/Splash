use splash_ui_l0::{check_ui_l0_named, makepad, SourceBinding};

#[test]
fn live_news_card_is_l0_and_query_changes_invalidate_both_sources() {
    let card = include_str!("../../../../tools/splash-research/live-news.card");
    let report = check_ui_l0_named("live-news", card);
    assert!(report.valid, "{:?}", report.diagnostics);
    for field in ["query", "language"] {
        assert_eq!(splash_ui_l0::stale_sources(card, &[field]), vec!["stories", "progress"]);
    }
    assert!(!check_ui_l0_named("live-news", &card.replace("count: 3,", "endpoint: \"https://untrusted.invalid\", count: 3,")).valid);
}

#[test]
fn news_binding_quotes_user_text_and_bounds_rows_and_fields() {
    let mut binding = SourceBinding {
        helper: "sys.news_digest".into(), field: "0.summary".into(), nested: vec![],
        args: vec![("query".into(), "Apple \" OR sys.stock(1)".into()), ("language".into(), "zh-CN".into())],
    };
    let call = makepad::vm_call(&binding).unwrap();
    assert_eq!(call, "sys.news_digest(\"Apple \\\" OR sys.stock(1)\", \"zh-CN\", \"items.0.summary\")");
    for field in ["3.summary", "0.password", "../../url"] {
        binding.field = field.into();
        assert!(makepad::vm_call(&binding).is_none());
    }
}

#[test]
fn chinese_search_uses_the_real_field_and_preserves_news_sources() {
    use splash_ui_l0::{NodeValue, UiNode, InstanceStore, RealizeLimits, ValueOrigin};
    fn find<'a>(node: &'a UiNode, prop: &str, event: &str) -> Option<&'a UiNode> {
        if node.args.iter().any(|(p,v)| p==prop && matches!(v, NodeValue::Event(e) if e==event)) { return Some(node); }
        node.children.iter().find_map(|c| find(c, prop, event))
    }
    let card = include_str!("../../../../tools/splash-research/live-news.card");
    let mut store = InstanceStore::default();
    let data = serde_json::json!({});
    for (prop, event, value) in [("on_tap", "edit_search", ""), ("on_commit", "search", "美国伊朗最新冲突")] {
        let report = splash_ui_l0::realize_with_state(card, &data, &store, RealizeLimits::default());
        let root = report.complete_root().unwrap();
        let control = find(root, prop, event).unwrap();
        let origin = splash_ui_l0::event_payload_origin(root, &control.key, event).unwrap();
        if event == "search" { assert_eq!(origin, ValueOrigin::UserInput); }
        let outcome = splash_ui_l0::dispatch_reporting_with_origin(card, &mut store, &control.key,
            event, Some(&serde_json::json!(value)), &data, origin);
        assert!(outcome.applied);
        if event == "search" { assert!(outcome.stale.iter().any(|s| s == "stories")); }
    }
    let report = splash_ui_l0::realize_with_state(card, &data, &store, RealizeLimits::default());
    assert!(report.complete_root().is_ok());
    assert!(splash_ui_l0::source_plan(card).requests.iter().any(|s| s.helper == "sys.news_digest"));
}
