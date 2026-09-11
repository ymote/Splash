//! The L0 profile checked against the reference cards.
//!
//! These three cards are the evidence for the profile: any construct they need
//! that the grammar lacks is a defect in `docs/ui-profile-l0.md`, not in the
//! cards. They are the same files as `octos-one/docs/l0/*.card`.

use octoscript_ui_l0::{catalog, check_ui_l0_named, Level};

const WEATHER: &str = include_str!("fixtures/weather.card");
const NEWS: &str = include_str!("fixtures/news.card");
const STOCK: &str = include_str!("fixtures/stock.card");

fn accepts(name: &str, source: &str) {
    let report = check_ui_l0_named(name, source);
    assert!(
        report.valid,
        "{name} should be L0, but: {:#?}",
        report.diagnostics
    );
    assert_eq!(report.level, Level::L0);
}

fn rejects_at(name: &str, source: &str, level: Level) -> String {
    let report = check_ui_l0_named(name, source);
    assert!(!report.valid, "{name} should have been rejected");
    assert_eq!(
        report.level, level,
        "wrong level for {name}: {:#?}",
        report.diagnostics
    );
    report
        .diagnostics
        .first()
        .map(|d| d.message.clone())
        .unwrap_or_default()
}

// ─────────────────────────────────────────────────────────── the reference cards ──

#[test]
fn the_three_reference_cards_are_l0() {
    accepts("weather", WEATHER);
    accepts("news", NEWS);
    accepts("stock", STOCK);
}

/// Every constructor the cards use must be catalogued, or the checker is
/// accepting names it cannot check the arguments of.
#[test]
fn every_constructor_the_cards_use_is_catalogued_or_declared() {
    for (name, source) in [("weather", WEATHER), ("news", NEWS), ("stock", STOCK)] {
        let declared: Vec<&str> = source
            .lines()
            .filter_map(|l| l.trim().strip_prefix("component "))
            .filter_map(|l| l.split(['(', ' ']).next())
            .collect();

        for line in source.lines() {
            let line = line.split('#').next().unwrap_or("");
            for word in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
                let is_ctor = word.chars().next().is_some_and(|c| c.is_uppercase())
                    && line.contains(&format!("{word}("));
                if is_ctor && catalog::lookup(word).is_none() && !declared.contains(&word) {
                    panic!("{name}: {word:?} is neither catalogued nor declared");
                }
            }
        }
    }
}

// ──────────────────────────────────────────────────────────── level classification ──

#[test]
fn a_function_is_l2() {
    let msg = rejects_at("fn", "fn tick() { }\nview root Panel", Level::L2);
    assert!(msg.contains("unbounded work"), "{msg}");
}

#[test]
fn an_imperative_widget_command_is_l2() {
    let msg = rejects_at(
        "ui",
        "view root Panel { Row(on_tap: go) }\nevent go { ui.map.set_text(1) }",
        Level::L2,
    );
    assert!(msg.contains("imperative"), "{msg}");
}

#[test]
fn module_access_is_l2() {
    let msg = rejects_at("mod", "source x mod.fs.read(\"/etc/passwd\")", Level::L2);
    assert!(msg.contains("host surface is empty"), "{msg}");
}

#[test]
fn arithmetic_is_l1() {
    let msg = rejects_at(
        "arith",
        "view hero TextHero(value: now.temp * 2)",
        Level::L1,
    );
    assert!(msg.contains("fabricated fact"), "{msg}");
}

/// The correction that mattered: `expanded: !expanded` is computation, however
/// small, and L0 has `toggle` precisely so it need not be written.
#[test]
fn negation_in_a_transition_is_l1() {
    let msg = rejects_at(
        "neg",
        "state open { shape: bool, initial: false }\nevent t { open: !open }",
        Level::L1,
    );
    assert!(msg.contains("toggle"), "{msg}");
}

#[test]
fn a_ternary_is_l1() {
    rejects_at(
        "ternary",
        "state u { shape: enum[c, f], initial: .c }\nevent t { u: u == .c ? .f : .c }",
        Level::L1,
    );
}

// ────────────────────────────────────────────────────────────────── grammar rules ──

/// Identity may never come from position — profile §6.3.
#[test]
fn a_loop_without_a_key_is_rejected() {
    let report = check_ui_l0_named(
        "nokey",
        "source week sys.weather()\nview f Panel { for d in week { Row() } }",
    );
    assert!(!report.valid);
    assert!(
        report.diagnostics.iter().any(|d| d.message.contains("key")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn an_unknown_constructor_is_rejected() {
    let report = check_ui_l0_named("unknown", "view root Blockchain(hype: 11)");
    assert!(!report.valid);
    assert!(
        report.diagnostics[0]
            .message
            .contains("not an L0 constructor"),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn an_unknown_argument_is_rejected() {
    let report = check_ui_l0_named("badarg", "view root Panel { Rule(sparkle: 3) }");
    assert!(!report.valid);
    assert!(
        report.diagnostics[0].message.contains("no argument"),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn an_illegal_token_is_rejected_with_the_legal_set() {
    let report = check_ui_l0_named("badtoken", "view root Surface(pad: .enormous)");
    assert!(!report.valid);
    let m = &report.diagnostics[0].message;
    assert!(
        m.contains(".page"),
        "the diagnostic should name the legal tokens: {m}"
    );
}

/// The distinction lexical marking exists to make: a bare name is a path, and a
/// path cannot stand in for a token.
#[test]
fn a_bare_name_where_a_token_belongs_is_rejected() {
    let report = check_ui_l0_named("bare", "view root Surface(pad: page)");
    assert!(!report.valid);
    let m = &report.diagnostics[0].message;
    assert!(m.contains("leading dot"), "{m}");
}

#[test]
fn an_undeclared_name_is_rejected() {
    let report = check_ui_l0_named("undeclared", "view root TextTitle(text: nowhere.name)");
    assert!(!report.valid);
    assert!(
        report.diagnostics[0]
            .message
            .contains("not a declared name"),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn an_undeclared_event_is_rejected() {
    let report = check_ui_l0_named("noevent", "view root Card(on_tap: nope)");
    assert!(!report.valid);
    assert!(
        report.diagnostics[0]
            .message
            .contains("not a declared event"),
        "{:#?}",
        report.diagnostics
    );
}

// ──────────────────────────────────────────────────────────── component contracts ──

/// Profile §5.3: card state must arrive as a prop, or the dependency is
/// invisible to the tracker.
#[test]
fn a_component_may_not_read_card_state() {
    let report = check_ui_l0_named(
        "scope",
        "state units { shape: enum[c, f], initial: .c }\n\
         component Row2(item: record) { view TextValue(value: item.hi, unit: units) }\n\
         view root Panel { }",
    );
    assert!(!report.valid);
    let m = &report.diagnostics[0].message;
    assert!(m.contains("pass it as a prop"), "{m}");
}

/// A component reading a card-scope source is fine — sources are immutable and
/// already declared dependencies.
#[test]
fn a_component_may_read_a_card_source() {
    let report = check_ui_l0_named(
        "srcread",
        "source week sys.weather()\n\
         component Bar(item: record) { view TempBar(lo: item.lo, hi: item.hi, min: week.min, max: week.max) }\n\
         view root Panel { }",
    );
    assert!(report.valid, "{:#?}", report.diagnostics);
}

/// Profile §6, condition 1. Without it an L0 realization need not terminate.
#[test]
fn a_recursive_component_is_rejected() {
    let report = check_ui_l0_named(
        "rec",
        "component Node(item: record) { view Col { Node(item: item) } }\nview root Panel { }",
    );
    assert!(!report.valid);
    assert!(
        report.diagnostics[0].message.contains("recursive"),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn mutual_recursion_is_rejected_too() {
    let report = check_ui_l0_named(
        "mutual",
        "component A(x: record) { view Col { B(x: x) } }\n\
         component B(x: record) { view Col { A(x: x) } }\n\
         view root Panel { }",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("recursive")),
        "{:#?}",
        report.diagnostics
    );
}

// ────────────────────────────────────────────────────────────────────── bounds ──

#[test]
fn diagnostics_are_bounded() {
    let mut source = String::from("view root Panel {\n");
    for _ in 0..500 {
        source.push_str("  Blockchain()\n");
    }
    source.push('}');
    let report = check_ui_l0_named("many", &source);
    assert!(!report.valid);
    assert!(report.diagnostics.len() <= octoscript_ui_l0::MAX_UI_L0_DIAGNOSTICS);
    assert!(report.diagnostics_truncated);
}

#[test]
fn deeply_nested_source_terminates() {
    let depth = 4_000;
    let mut source = String::from("view root ");
    for _ in 0..depth {
        source.push_str("Panel { ");
    }
    for _ in 0..depth {
        source.push('}');
    }
    // The contract is that it returns, bounded, rather than overflowing.
    let report = check_ui_l0_named("deep", &source);
    assert!(!report.valid);
}

#[test]
fn a_truncated_card_terminates() {
    for source in [
        "view root Panel {",
        "component A(",
        "state x {",
        "view root Row(align:",
        "for d in",
    ] {
        let _ = check_ui_l0_named("partial", source);
    }
}

// ─────────────────────────────────────────────────────────── the negative fixture ──

/// The shipping nav card. It is the reason the level model exists: 127
/// conditionals that L0 could express, and a `fn tick()` plus 65 imperative
/// widget commands that it cannot. Level is the MAXIMUM any construct requires,
/// so this must classify L2 rather than stopping at the first arithmetic it hits.
const NAV: &str = include_str!("fixtures/trip_planner.octoscript");

#[test]
fn the_nav_card_is_l2() {
    let report = check_ui_l0_named("trip-planner", NAV);
    assert!(!report.valid);
    assert_eq!(
        report.level,
        Level::L2,
        "expected L2, got {:?}: {:#?}",
        report.level,
        report.diagnostics.first()
    );
}

// ─────────────────────────────────────────────────────────────────── transitions ──

#[test]
fn a_transition_must_name_a_declared_state() {
    let report = check_ui_l0_named("nostate", "event go { nowhere: clear }\nview root Panel");
    assert!(!report.valid);
    assert!(
        report.diagnostics[0]
            .message
            .contains("not a state declared"),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn toggle_requires_a_bool() {
    let report = check_ui_l0_named(
        "toggle",
        "state u { shape: enum[c, f], initial: .c }\nevent t { u: toggle }\nview root Panel",
    );
    assert!(!report.valid);
    assert!(
        report.diagnostics[0].message.contains("needs a bool"),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn cycle_members_must_be_declared_in_the_shape() {
    let report = check_ui_l0_named(
        "cycle",
        "state u { shape: enum[c, f], initial: .c }\nevent t { u: cycle(.c, .kelvin) }\nview root Panel",
    );
    assert!(!report.valid);
    assert!(
        report.diagnostics[0].message.contains("not a member"),
        "{:#?}",
        report.diagnostics
    );
}

/// Enum members are tokens. A bare name is a path and cannot stand in for one.
#[test]
fn cycle_rejects_bare_names() {
    let report = check_ui_l0_named(
        "cyclebare",
        "state u { shape: enum[c, f], initial: .c }\nevent t { u: cycle(c, f) }\nview root Panel",
    );
    assert!(!report.valid);
    assert!(
        report.diagnostics[0].message.contains("leading dot"),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn an_untotal_transition_form_is_rejected() {
    let report = check_ui_l0_named(
        "untotal",
        "state n { shape: number, initial: 0 }\nevent t { n: increment }\nview root Panel",
    );
    assert!(!report.valid);
    assert!(
        report.diagnostics[0]
            .message
            .contains("total transition form"),
        "{:#?}",
        report.diagnostics
    );
}

// ────────────────────────────────────────────────────────────────── realization ──

use octoscript_ui_l0::{realize, NodeValue, RealizeLimits};

fn weather_data() -> serde_json::Value {
    serde_json::json!({
        "place": { "name": "Kyoto" },
        "now":   { "temp": 18.0, "feels": 16.0, "hi": 21.0, "lo": 12.0, "cond": "cloudy",
                   "humidity": 61.0, "wind": 9.0, "pressure": 1013.0, "uv": 3.0,
                   "visibility": 10.0 },
        // `week` is a record: the days plus the bounds every bar scales against.
        // An array could not carry both, which is what the first data snapshot
        // got wrong and silently zeroed every TempBar.
        "week":  { "days": [ { "dayname": "Mon", "hi": 21.0, "lo": 12.0, "cond": 2.0 },
                             { "dayname": "Tue", "hi": 23.0, "lo": 13.0, "cond": 0.0 },
                             { "dayname": "Wed", "hi": 19.0, "lo": 11.0, "cond": 3.0 } ],
                   "min_lo": 11.0, "max_hi": 23.0 },
        "sun":   { "rise": 5.1, "set": 18.9, "now": 12.0 },
        "moon":  { "phase": 0.5, "illumination": 0.5 },
        "aqi":   { "grid": [1, 2], "index": 42.0, "band": "good" },
        "scene": "https://example.invalid/kyoto.jpg",
        "units": "c",
        "days":  7.0,
        "city":  "Kyoto",
        "env":   { "locale": { "temp_unit": "c" } },
        "copy":  { "feels": "Feels like", "humidity": "Humidity", "wind": "Wind",
                   "pressure": "Pressure", "uv": "UV Index", "visibility": "Visibility",
                   "air": "Air Quality", "sunrise": "Sunrise", "sunset": "Sunset" }
    })
}

fn find<'a>(node: &'a octoscript_ui_l0::UiNode, kind: &str, out: &mut Vec<&'a octoscript_ui_l0::UiNode>) {
    if node.kind == kind {
        out.push(node);
    }
    for c in &node.children {
        find(c, kind, out);
    }
}

#[test]
fn a_card_realizes_to_a_node_tree() {
    let report = realize(WEATHER, &weather_data(), RealizeLimits::default());
    assert!(report.diagnostics.is_empty(), "{:#?}", report.diagnostics);
    let root = report.root.expect("a root node");
    assert_eq!(root.kind, "Photo");
    assert!(
        report.nodes > 20,
        "expected a populated tree, got {}",
        report.nodes
    );
}

/// Bindings resolve against injected data — the card names a question, the
/// runtime supplied the answer.
#[test]
fn bindings_resolve_from_injected_data() {
    let report = realize(WEATHER, &weather_data(), RealizeLimits::default());
    let root = report.root.unwrap();
    let mut titles = Vec::new();
    find(&root, "TextTitle", &mut titles);
    let (_, place) = titles[0].args.iter().find(|(n, _)| n == "text").unwrap();
    assert_eq!(*place, NodeValue::Text("Kyoto".into()));
}

/// One row per item, keyed by the declared key expression rather than position.
#[test]
fn a_loop_produces_one_instance_per_item_keyed_by_its_key() {
    let report = realize(WEATHER, &weather_data(), RealizeLimits::default());
    let root = report.root.unwrap();
    let mut bars = Vec::new();
    find(&root, "TempBar", &mut bars);
    assert_eq!(bars.len(), 3, "three days of data, three rows");
    for (bar, day) in bars.iter().zip(["Mon", "Tue", "Wed"]) {
        assert!(
            bar.key.contains(day),
            "key {:?} should carry {day}",
            bar.key
        );
    }
}

/// Identity must survive an edit that inserts a sibling above — that is why keys
/// come from the declaration path and loop key, not position.
#[test]
fn keys_are_stable_when_a_sibling_is_inserted_above() {
    let before = realize(WEATHER, &weather_data(), RealizeLimits::default())
        .root
        .unwrap();
    let edited = WEATHER.replace(
        "view current  Col(align: .center) {",
        "view current  Col(align: .center) {\n                Rule()",
    );
    let after = realize(&edited, &weather_data(), RealizeLimits::default())
        .root
        .unwrap();

    let (mut a, mut b) = (Vec::new(), Vec::new());
    find(&before, "TempBar", &mut a);
    find(&after, "TempBar", &mut b);
    let keys_a: Vec<&str> = a.iter().map(|n| n.key.as_str()).collect();
    let keys_b: Vec<&str> = b.iter().map(|n| n.key.as_str()).collect();
    assert_eq!(
        keys_a, keys_b,
        "inserting a node above must not rebind the forecast rows"
    );
}

/// A bare boolean guard — amendment #10 — and it must actually gate.
#[test]
fn a_guard_includes_children_only_when_it_holds() {
    let mut data = weather_data();
    let report = realize(WEATHER, &data, RealizeLimits::default());
    let root = report.root.unwrap();
    let mut captions = Vec::new();
    find(&root, "TextCaption", &mut captions);
    let collapsed = captions.len();

    // `expanded` is component-local state the runtime holds; with none supplied
    // the guard is false and the detail row is absent.
    data["expanded"] = serde_json::Value::Bool(true);
    let expanded = realize(WEATHER, &data, RealizeLimits::default())
        .root
        .unwrap();
    let mut captions2 = Vec::new();
    find(&expanded, "TextCaption", &mut captions2);
    assert!(
        captions2.len() >= collapsed,
        "an open guard must not remove nodes"
    );
}

/// A missing binding is surfaced, not defaulted. A silently empty field is how a
/// card renders an em dash and still looks correct.
#[test]
fn an_unresolved_binding_is_reported_as_missing() {
    let mut data = weather_data();
    data["now"]["humidity"] = serde_json::Value::Null;
    let report = realize(WEATHER, &data, RealizeLimits::default());
    let root = report.root.unwrap();
    let mut tiles = Vec::new();
    find(&root, "Tile", &mut tiles);
    assert!(
        tiles.iter().any(|t| t
            .args
            .iter()
            .any(|(n, v)| n == "value" && *v == NodeValue::Missing)),
        "a null source field should realize as Missing"
    );
}

#[test]
fn events_carry_their_declared_name_rather_than_a_constructed_string() {
    let report = realize(WEATHER, &weather_data(), RealizeLimits::default());
    let root = report.root.unwrap();
    let mut heroes = Vec::new();
    find(&root, "TextHero", &mut heroes);
    let (_, ev) = heroes[0].args.iter().find(|(n, _)| n == "on_tap").unwrap();
    assert_eq!(*ev, NodeValue::Event("toggle_units".into()));
}

#[test]
fn realization_is_bounded() {
    let limits = RealizeLimits {
        max_nodes: 10,
        ..RealizeLimits::default()
    };
    let report = realize(WEATHER, &weather_data(), limits);
    assert!(report.truncated);
    assert!(report.nodes <= 10);
}

#[test]
fn a_long_collection_is_truncated_rather_than_unbounded() {
    let mut data = weather_data();
    let week: Vec<serde_json::Value> = (0..5_000)
        .map(|i| serde_json::json!({ "dayname": format!("d{i}"), "hi": 1.0, "lo": 0.0, "cond": "x" }))
        .collect();
    data["week"] = serde_json::json!({ "days": week, "min_lo": 0.0, "max_hi": 1.0 });
    let limits = RealizeLimits {
        max_collection: 8,
        ..RealizeLimits::default()
    };
    let report = realize(WEATHER, &data, limits);
    let root = report.root.unwrap();
    let mut bars = Vec::new();
    find(&root, "TempBar", &mut bars);
    assert_eq!(bars.len(), 8);
    assert!(report.truncated);
}

#[test]
fn the_other_two_cards_realize_too() {
    let news = serde_json::json!({
        "lead": [{ "id": "1", "title": "T", "author": "A", "points": 9.0, "comments": 3.0, "url": "u" }],
        "feed": [{ "id": "2", "title": "U", "author": "B", "points": 4.0 }],
        "article": { "title": "T", "author": "A", "points": 9.0, "comments": 3.0, "url": "u" },
        "selected": "",
        "env": { "locale": {} },
        "copy": { "masthead": "Top Stories", "latest": "LATEST", "lead": "LEAD",
                  "pts": "pts", "comments": "comments", "by": "by" }
    });
    let report = realize(NEWS, &news, RealizeLimits::default());
    assert!(report.diagnostics.is_empty(), "{:#?}", report.diagnostics);
    assert!(report.root.is_some());

    let stock = serde_json::json!({
        "movers": [{ "ticker": "AAA", "name": "A", "last": 1.0, "change": 0.5, "pct": 2.0 }],
        "quote": { "name": "A", "last": 1.0, "change": 0.5, "pct": 2.0, "open": 1.0,
                   "high": 2.0, "low": 0.5, "volume": 10.0, "mktcap": 99.0, "pe": 12.0 },
        "series": { "points": [1, 2], "min": 0.5, "max": 2.0 },
        "selected": "", "range": "m1", "env": { "locale": {} },
        "copy": { "movers": "Top Movers", "open": "Open", "high": "High", "low": "Low",
                  "volume": "Volume", "mktcap": "Mkt Cap", "pe": "P/E" }
    });
    let report = realize(STOCK, &stock, RealizeLimits::default());
    assert!(report.diagnostics.is_empty(), "{:#?}", report.diagnostics);
    assert!(report.root.is_some());
}

// ───────────────────────────────────────────────────────────── makepad lowering ──

use octoscript_ui_l0::makepad;

#[test]
fn a_realized_card_lowers_to_renderable_dsl() {
    let report = realize(WEATHER, &weather_data(), RealizeLimits::default());
    let dsl = makepad::lower(&report.root.unwrap());

    // Exactly one top-level node. Siblings at top level lay out SIDE BY SIDE and
    // squeeze the card into half the width — a real generated-card bug.
    let tops = dsl
        .lines()
        .filter(|l| !l.starts_with("//") && !l.starts_with(' ') && !l.trim().is_empty())
        .filter(|l| l.contains('{'))
        .count();
    assert_eq!(tops, 1, "expected one root node:\n{dsl}");

    assert!(
        dsl.contains("http_resource"),
        "the photo should be a resource"
    );
    assert!(
        dsl.contains("TempBar{"),
        "forecast bars should survive lowering"
    );
    assert!(
        dsl.contains("MoonPhase{"),
        "the moon phase should survive lowering"
    );
    assert!(
        dsl.contains("\"Kyoto\""),
        "the bound city should be concrete"
    );
    // Sources the backend can answer lower to LIVE calls. This asserted the
    // opposite — that realization had resolved everything from the seeded blob —
    // which was true only while `weather` and `photo` had no translation. A card
    // that renders the seed is a card that shows what the host happened to hand
    // it, not what is true now.
    assert!(
        dsl.contains("sys.weather("),
        "the forecast must be live, not seeded: {dsl}"
    );
}

/// Nothing may be silently dropped: an unmapped constructor renders a visible
/// warning instead of vanishing.
#[test]
fn an_unmapped_constructor_is_visible_rather_than_dropped() {
    let node = octoscript_ui_l0::UiNode {
        kind: "Hologram".into(),
        key: "root".into(),
        args: vec![],
        children: vec![],
        bindings: vec![],
        exprs: vec![],
    };
    let dsl = makepad::lower(&node);
    assert!(dsl.contains("no makepad lowering for Hologram"), "{dsl}");
}

/// A missing binding reaches the screen as an em dash rather than a blank.
#[test]
fn a_missing_binding_lowers_to_a_visible_dash() {
    let mut data = weather_data();
    data["now"]["humidity"] = serde_json::Value::Null;
    let report = realize(WEATHER, &data, RealizeLimits::default());
    let dsl = makepad::lower(&report.root.unwrap());
    assert!(dsl.contains('—'), "an unresolved field should be visible");
}

// ────────────────────────────────────────────────────────────── instance state ──

const TWO_ROWS: &str = r#"
source items sys.movers()
component Rowy(item: record) {
  state open { shape: bool, initial: false }
  event flip { open: toggle }
  view Col {
    Row(on_tap: flip) { TextRow(text: item.name) }
    when open { TextCaption(text: item.name) }
  }
}
view root Panel { for it in items key it.id { Rowy(item: it) } }
"#;

fn two_rows_data() -> serde_json::Value {
    serde_json::json!({ "items": [ {"id": "a", "name": "A"}, {"id": "b", "name": "B"} ] })
}

/// Each instance must own its `open` cell. Opening one row may not open the
/// other — the property the whole component model exists to provide.
#[test]
fn local_state_is_per_instance() {
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let data = two_rows_data();

    let first = octoscript_ui_l0::realize_with_state(TWO_ROWS, &data, &store, RealizeLimits::default());
    let root = first.root.expect("root");
    let mut rows = Vec::new();
    find(&root, "Row", &mut rows);
    assert_eq!(rows.len(), 2);

    // Open only the first row.
    let key = rows[0].key.clone();
    let applied = octoscript_ui_l0::dispatch(TWO_ROWS, &mut store, &key, "flip");
    assert!(applied, "flip should have applied at {key}");

    let second =
        octoscript_ui_l0::realize_with_state(TWO_ROWS, &data, &store, RealizeLimits::default());
    let root = second.root.expect("root");
    let mut captions = Vec::new();
    find(&root, "TextCaption", &mut captions);
    assert_eq!(
        captions.len(),
        1,
        "exactly one row should be open, not {}",
        captions.len()
    );
    let (_, shown) = captions[0].args.iter().find(|(n, _)| n == "text").unwrap();
    assert_eq!(
        *shown,
        NodeValue::Text("A".into()),
        "the row that was tapped"
    );
}

/// Profile §5.8: a state schema change resets instances rather than guessing
/// that old values still fit.
#[test]
fn a_schema_change_resets_instance_state() {
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let data = two_rows_data();
    let first = octoscript_ui_l0::realize_with_state(TWO_ROWS, &data, &store, RealizeLimits::default());
    let mut rows = Vec::new();
    let first_root = first.root.unwrap();
    find(&first_root, "Row", &mut rows);
    octoscript_ui_l0::dispatch(TWO_ROWS, &mut store, &rows[0].key, "flip");

    // The component gains a field: same name, different state schema.
    let edited = TWO_ROWS.replace(
        "state open { shape: bool, initial: false }",
        "state open { shape: bool, initial: false }\n  state seen { shape: bool, initial: false }",
    );
    let after = octoscript_ui_l0::realize_with_state(&edited, &data, &store, RealizeLimits::default());
    let mut captions = Vec::new();
    let after_root = after.root.unwrap();
    find(&after_root, "TextCaption", &mut captions);
    assert_eq!(
        captions.len(),
        0,
        "a schema change resets, it does not migrate"
    );
}

// ─────────────────────────────────────────────────────── declared-but-missing ──

const SETTER: &str = r#"
source items sys.movers()
state picked { shape: text, initial: "" }
event choose { picked: set($value) }
event home   { picked: clear }
view root Panel {
  when picked == "" { for it in items key it.id { Row(on_tap: choose, value: it.id) { TextRow(text: it.name) } } }
  when picked != "" { Col { TextTitle(text: picked) Row(on_tap: home) { TextCaption(glyph: "‹") } } }
}
"#;

/// `set($value)` carries the payload from the element that raised the event.
/// Without it a list cannot select anything — the interaction stock and news
/// both depend on.
#[test]
fn set_applies_the_event_payload() {
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let data = serde_json::json!({ "items": [{"id":"a","name":"A"},{"id":"b","name":"B"}] });

    let before = octoscript_ui_l0::realize_with_state(SETTER, &data, &store, RealizeLimits::default());
    let root = before.root.unwrap();
    let mut rows = Vec::new();
    find(&root, "Row", &mut rows);
    assert_eq!(rows.len(), 2, "the list should show both items");

    let payload = serde_json::json!("b");
    let applied = octoscript_ui_l0::dispatch_with(SETTER, &mut store, "root", "choose", Some(&payload));
    assert!(applied, "choose should apply");

    let after = octoscript_ui_l0::realize_with_state(SETTER, &data, &store, RealizeLimits::default());
    let root = after.root.unwrap();
    let mut titles = Vec::new();
    find(&root, "TextTitle", &mut titles);
    assert_eq!(
        titles.len(),
        1,
        "selecting should switch to the detail view"
    );
    let (_, shown) = titles[0].args.iter().find(|(n, _)| n == "text").unwrap();
    assert_eq!(
        *shown,
        NodeValue::Text("b".into()),
        "the item that was tapped"
    );
}

const SLOTTED: &str = r#"
component Framed(title: text) {
  view Col { TextCaption(text: title) slot }
}
view root Panel { Framed(title: "Details") { TextRow(text: "inner") Rule() } }
"#;

/// A component's children are realized where `slot` appears. Dropping them
/// silently is how a card renders a frame with nothing in it and still looks
/// deliberate.
#[test]
fn slot_realizes_the_children_passed_at_the_call_site() {
    let report = realize(SLOTTED, &serde_json::json!({}), RealizeLimits::default());
    assert!(report.diagnostics.is_empty(), "{:#?}", report.diagnostics);
    let root = report.root.unwrap();
    let mut rows = Vec::new();
    find(&root, "TextRow", &mut rows);
    assert_eq!(
        rows.len(),
        1,
        "the child passed at the call site must appear"
    );
    let mut rules = Vec::new();
    find(&root, "Rule", &mut rules);
    assert_eq!(rules.len(), 1);
}

/// Profile §5.7: an instance that disappears loses its state. Without pruning
/// the store grows for the life of the app and a key that reappears inherits a
/// stale value.
#[test]
fn unmounted_instances_are_pruned() {
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let two = serde_json::json!({ "items": [{"id":"a","name":"A"},{"id":"b","name":"B"}] });

    let report = octoscript_ui_l0::realize_with_state(TWO_ROWS, &two, &store, RealizeLimits::default());
    let root = report.root.unwrap();
    let mut rows = Vec::new();
    find(&root, "Row", &mut rows);
    for row in &rows {
        octoscript_ui_l0::dispatch(TWO_ROWS, &mut store, &row.key, "flip");
    }
    assert_eq!(store.len(), 2, "both rows hold state");

    // `b` goes away.
    let one = serde_json::json!({ "items": [{"id":"a","name":"A"}] });
    let report = octoscript_ui_l0::realize_with_state(TWO_ROWS, &one, &store, RealizeLimits::default());
    store.prune(&report.live_keys);
    assert_eq!(store.len(), 1, "the departed instance's cell is dropped");
}

/// Formatting is the runtime's job, not the card's. A card that wrote "$" or
/// "41.2M" itself would be authoring a fact — and currency, grouping and
/// compaction are locale-dependent besides.
#[test]
fn declared_formats_are_applied_by_the_runtime() {
    let data = serde_json::json!({
        "movers": [], "selected": "NVDA", "range": "m1", "env": {"locale":{}},
        "quote": {"name":"NVIDIA","last":184.2,"change":3.1,"pct":1.7,"open":181.0,
                  "high":185.6,"low":180.2,"volume":41200000.0,
                  "mktcap":4520000000000.0,"pe":58.3},
        "series": {"points":[1,2],"min":180.2,"max":185.6},
        "copy": {"movers":"Top Movers","open":"Open","high":"High","low":"Low",
                 "volume":"Volume","mktcap":"Mkt Cap","pe":"P/E"}
    });
    let report = realize(STOCK, &data, RealizeLimits::default());
    let dsl = makepad::lower(&report.root.expect("root"));

    // A format that needs the NUMBER is applied here, because it cannot be
    // applied around a call the backend will make later.
    for (expect, why) in [
        ("41.2M", "compact scales volume"),
        ("4.5T", "compact scales market cap"),
        ("58.3", "a ratio is plain"),
    ] {
        assert!(dsl.contains(expect), "{why}: {expect} missing from\n{dsl}");
    }
    assert!(
        !dsl.contains("41200000"),
        "the raw number should not survive"
    );

    // A format that is a literal prefix, or that the backend already applies,
    // survives — so these lower to a LIVE call rather than to the seeded value.
    // The card then shows the price now, not the price when the blob was made.
    assert!(
        dsl.contains(r#""$" + sys.stock("NVDA", "price")"#),
        "money should prefix a live call:\n{dsl}"
    );
    assert!(
        dsl.contains(r#"sys.stock("NVDA", "changepct")"#),
        "signed_pct is what the VM already returns, so the call stands alone:\n{dsl}"
    );
    // And the seeded values they replaced must be GONE, or the card would show
    // a stale number beside a live one.
    assert!(
        !dsl.contains("$184.20") && !dsl.contains("+1.7%"),
        "a live call must replace the seeded literal, not sit beside it:\n{dsl}"
    );
}

/// The fallback is not a failure mode to be minimised — it is what keeps a
/// wrong number off the screen.
///
/// `sys.stock` exposes no market cap and no P/E, and `compact`/`ratio` need the
/// number itself. Emitting a call for those would render an em dash where a real
/// value was available, so they stay seeded and this asserts they do.
#[test]
fn a_capability_the_backend_cannot_answer_keeps_its_seeded_value() {
    let data = serde_json::json!({
        "movers": [], "selected": "NVDA", "range": "m1", "env": {"locale":{}},
        "quote": {"name":"NVIDIA","last":184.2,"change":3.1,"pct":1.7,"open":181.0,
                  "high":185.6,"low":180.2,"volume":41200000.0,
                  "mktcap":4520000000000.0,"pe":58.3},
        "copy": {"movers":"Top Movers","open":"Open","high":"High","low":"Low",
                 "volume":"Volume","mktcap":"Mkt Cap","pe":"P/E"}
    });
    let report = realize(STOCK, &data, RealizeLimits::default());
    let dsl = makepad::lower(&report.root.expect("root"));

    assert!(
        !dsl.contains("sys.stock(\"NVDA\", \"mktcap\")") && !dsl.contains("\"pe\")"),
        "no call may be emitted for a field the helper does not expose:\n{dsl}"
    );
    assert!(
        dsl.contains("4.5T"),
        "market cap keeps its seeded value:\n{dsl}"
    );
    assert!(dsl.contains("58.3"), "P/E keeps its seeded value:\n{dsl}");

    // `open` USED to be in this test, as the case the fallback existed for.
    // That was the wrong lesson. `sys.stock` accepted the key and resolved
    // `regularMarketOpen`, which the Yahoo chart response does not carry — so
    // the call drew `$—`, and excluding it left a SEEDED opening price sitting
    // under a live one: $181 open beneath a $207 price on a +3% day, arithmetic
    // that does not work and was the only thing on screen that said so.
    //
    // Falling back is right when nothing upstream can answer. It is not a way to
    // paper over a helper reading the wrong key. The open IS in the response,
    // under `indicators.quote.0.open.0`, so the helper was fixed and the call is
    // emitted like any other.
    assert!(
        dsl.contains(r#"sys.stock("NVDA", "open")"#),
        "open resolves upstream now and must be live:\n{dsl}"
    );
    assert!(
        !dsl.contains("$181"),
        "the seeded opening price must be gone, not sitting beside a live one:\n{dsl}"
    );
    // High and low must still be live too — otherwise a regression here could
    // pass by quietly emitting no calls at all.
    assert!(
        dsl.contains(r#"sys.stock("NVDA", "high")"#) && dsl.contains(r#"sys.stock("NVDA", "low")"#),
        "high and low resolve upstream and must stay live:\n{dsl}"
    );
}

/// A float hour is a time, not a decimal: 18.9 is 18:54.
#[test]
fn a_time_format_renders_as_a_clock() {
    let report = realize(WEATHER, &weather_data(), RealizeLimits::default());
    let dsl = makepad::lower(&report.root.unwrap());
    assert!(
        dsl.contains("5:06"),
        "sunrise 5.1 should render 5:06:\n{dsl}"
    );
}

// ──────────────────────────────────────────────────────────── catalog agreement ──

/// The module doc claims a test asserts the Rust catalog and the TOML spec
/// agree. It said so for two commits before this test existed — a documented
/// check that was never written is worse than no check, because a reader stops
/// looking.
#[test]
fn the_rust_catalog_matches_the_toml_spec() {
    const TOML: &str = include_str!("../../../docs/ui-l0-constructors.toml");

    // Constructor headers are `[Name]`; `[kinds.x]` are shared token sets.
    let documented: Vec<&str> = TOML
        .lines()
        .filter_map(|l| l.trim().strip_prefix('['))
        .filter_map(|l| l.strip_suffix(']'))
        .filter(|n| !n.contains('.'))
        .collect();

    let implemented: Vec<&str> = catalog::CONSTRUCTORS.iter().map(|(n, _)| *n).collect();

    for name in &documented {
        assert!(
            implemented.contains(name),
            "{name:?} is in the TOML spec but not in the Rust catalog"
        );
    }
    for name in &implemented {
        assert!(
            documented.contains(name),
            "{name:?} is in the Rust catalog but not in the TOML spec"
        );
    }

    // Token sets must agree too, or a card legal by the spec is rejected by the
    // implementation.
    for (set_name, tokens) in [
        ("unit", catalog::UNIT),
        ("format", catalog::FORMAT),
        ("width", catalog::WIDTH),
    ] {
        let header = format!("[kinds.{set_name}]");
        let block = TOML
            .split(&header)
            .nth(1)
            .unwrap_or_else(|| panic!("{header} missing from the TOML"));
        let line = block
            .lines()
            .find(|l| l.trim_start().starts_with("tokens"))
            .unwrap_or_else(|| panic!("{set_name} has no tokens line"));
        for token in tokens {
            assert!(
                line.contains(&format!("\"{token}\"")),
                "{set_name}: {token:?} is in the Rust catalog but not the TOML"
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────── copy locale ──

/// `copy` is authored in the ledger, so it resolves from the CARD rather than
/// the injected data. Carrying it in both duplicated what the card already said,
/// and the two drifted — a card gained a `copy` the data blob lacked, and the
/// eyebrow rendered as an em dash on device.
#[test]
fn copy_resolves_from_the_card_not_the_data() {
    let data = serde_json::json!({
        "lead": [{"id":"1","title":"T","author":"A","points":1.0,"comments":2.0,"url":"u"}],
        "feed": [], "article": {}, "selected": "",
        "env": {"locale": {"lang": "en"}}
        // note: no "copy" key at all
    });
    let report = realize(NEWS, &data, RealizeLimits::default());
    let dsl = makepad::lower(&report.root.expect("root"));
    assert!(
        dsl.contains("Top Stories"),
        "card-declared copy should resolve:\n{dsl}"
    );
    assert!(
        dsl.contains("HACKER NEWS"),
        "the eyebrow should resolve too"
    );
}

/// A tap must be RECEIVABLE, not merely described.
///
/// Lowering emitted `l0_event`/`l0_key`/`l0_value` as attributes and nothing
/// read them — the VM does not hit-test an arbitrary attribute — so every card
/// that declared `on_tap` rendered inert on device while these tests passed.
/// The mechanism that works is the one hand-written cards use: a transparent
/// `Button` over the content calling `agent.notify`, which the host receives.
#[test]
fn a_tappable_node_lowers_to_a_reachable_notify() {
    let data = serde_json::json!({
        "movers": [{ "ticker": "NVDA", "name": "Nvidia", "last": 1.0, "change": 0.5, "pct": 2.0 }],
        "quote": { "name": "Nvidia", "last": 1.0, "change": 0.5, "pct": 2.0, "open": 1.0,
                   "high": 2.0, "low": 0.5, "volume": 10.0, "mktcap": 99.0, "pe": 12.0 },
        "selected": "", "range": "m1", "env": { "locale": {} },
        "copy": { "movers": "Top Movers", "open": "Open", "high": "High", "low": "Low",
                  "volume": "Volume", "mktcap": "Mkt Cap", "pe": "P/E" }
    });
    let report = realize(STOCK, &data, RealizeLimits::default());
    let dsl = makepad::lower(&report.root.expect("root"));

    // The row that opens a quote must carry all three: which event, which
    // instance, and what payload. Missing the key means a tap cannot say WHICH
    // row was hit, which is the whole basis of §5.1 identity.
    let notify = dsl
        .lines()
        .find(|l| l.contains("agent.notify") && l.contains("open_quote"))
        .unwrap_or_else(|| panic!("no reachable tap for open_quote:\n{dsl}"));
    assert!(notify.contains("event: \"open_quote\""), "event:\n{notify}");
    assert!(notify.contains("value: \"NVDA\""), "payload:\n{notify}");
    // A mover row is a single tap: movers are the market's recommendations,
    // so there is no per-row menu — Add lives on the quote page.
    assert!(
        notify.contains("key: \"root/when#0/w:list#0/list/Panel#0/for#0[NVDA]/Row#0\""),
        "instance key:\n{notify}"
    );

    // `agent.notify`'s first argument must stay a LITERAL. The host's
    // `tag_notify_calls` only rewrites literals, and an untagged event is
    // discarded as unattributable — so a computed channel name would render the
    // card inert again, silently and in exactly the same way.
    assert!(
        notify.contains("agent.notify(\"l0\","),
        "the channel must be a literal:\n{notify}"
    );

    // The discriminating half: buttons appear ONLY where a tap was declared.
    // Wrapping every node would make the whole card a hit target, and the
    // assertions above would still pass.
    let buttons = dsl.matches("agent.notify").count();
    let taps = dsl.matches("l0_event:").count();
    assert_eq!(
        buttons, taps,
        "one hit target per declared tap, no more:\n{dsl}"
    );
    assert!(taps > 0, "the stock card declares taps");
}

/// The declared language is chosen when the runtime reports one.
#[test]
fn copy_selects_the_reported_locale() {
    let mut data = serde_json::json!({
        "lead": [{"id":"1","title":"T","author":"A","points":1.0,"comments":2.0,"url":"u"}],
        "feed": [], "article": {}, "selected": "",
        "env": {"locale": {"lang": "zh"}}
    });
    let dsl = makepad::lower(&realize(NEWS, &data, RealizeLimits::default()).root.unwrap());
    assert!(dsl.contains("头条"), "zh text should be selected:\n{dsl}");

    // A card shipping zh text must not render an em dash on an en device.
    data["env"]["locale"]["lang"] = serde_json::Value::String("fr".into());
    let dsl = makepad::lower(&realize(NEWS, &data, RealizeLimits::default()).root.unwrap());
    assert!(
        dsl.contains("Top Stories"),
        "an unknown locale falls back to en"
    );
}

// ───────────────────────────────────────────────────────────────── source plan ──

use octoscript_ui_l0::{source_plan, SourceArg};

/// A card declares what data it needs; the plan is what a host fetches. Without
/// it the declaration was inert — the parser skipped the helper and every
/// argument, so nothing could act on `source now sys.weather(…)`.
#[test]
fn the_plan_reports_helpers_and_arguments() {
    let plan = source_plan(WEATHER);
    assert!(plan.diagnostics.is_empty(), "{:#?}", plan.diagnostics);

    let now = plan.requests.iter().find(|r| r.name == "now").expect("now");
    assert_eq!(now.helper, "sys.weather");

    let (_, lat) = now.args.iter().find(|(n, _)| n == "lat").expect("lat");
    assert_eq!(*lat, SourceArg::Path("place.lat".into()));

    let (_, fields) = now
        .args
        .iter()
        .find(|(n, _)| n == "fields")
        .expect("fields");
    match fields {
        SourceArg::List(items) => {
            assert!(items.contains(&"temp".to_string()), "{items:?}");
            assert!(items.contains(&"humidity".to_string()), "{items:?}");
        }
        other => panic!("fields should be a list, got {other:?}"),
    }
}

/// `now` reads `place.lat`, so `place` must be fetched first. A host walking the
/// list in order always has what the next request refers to.
#[test]
fn the_plan_orders_dependencies_before_dependents() {
    let plan = source_plan(WEATHER);
    let at = |name: &str| plan.requests.iter().position(|r| r.name == name).unwrap();
    assert!(at("place") < at("now"), "place must precede now");
    assert!(at("place") < at("week"), "place must precede week");
    // `scene`, not `aqi`: the air-quality source went away when `AqiContour`
    // began fetching its own field, and a source nothing reads is now refused.
    // `scene` reads `place.name`, so it makes the same point.
    assert!(at("place") < at("scene"), "place must precede scene");

    let now = &plan.requests[at("now")];
    assert_eq!(now.depends_on, vec!["place".to_string()]);

    // A source reading only card state depends on no other fetch.
    let place = &plan.requests[at("place")];
    assert!(place.depends_on.is_empty(), "{:?}", place.depends_on);
}

/// Two sources that read each other cannot both go first. Picking one silently
/// would fetch against a value that does not exist yet.
#[test]
fn a_dependency_cycle_is_reported_rather_than_resolved() {
    let plan = source_plan(
        "source a sys.geocode(name: b.value)\nsource b sys.photo(query: a.value)\nview root Panel",
    );
    assert!(
        plan.diagnostics.iter().any(|d| d.message.contains("cycle")),
        "{:#?}",
        plan.diagnostics
    );
}

#[test]
fn every_reference_card_yields_a_resolvable_plan() {
    for (name, card) in [("weather", WEATHER), ("news", NEWS), ("stock", STOCK)] {
        let plan = source_plan(card);
        assert!(
            plan.diagnostics.is_empty(),
            "{name}: {:#?}",
            plan.diagnostics
        );
        assert!(!plan.requests.is_empty(), "{name} declares no sources");
        for request in &plan.requests {
            assert!(
                request.helper.starts_with("sys."),
                "{name}: {:?} has no helper",
                request.name
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────── reconciliation ──

use octoscript_ui_l0::{dirty_records, record_dependencies};

/// L0 needs no dynamic read-tracking: no expression form means every binding is
/// structurally visible, so the dependency set is computable without evaluating
/// anything.
#[test]
fn dependencies_are_computed_without_evaluation() {
    let deps = record_dependencies(WEATHER);
    let of = |name: &str| {
        deps.iter()
            .find(|d| d.record == name)
            .unwrap_or_else(|| panic!("no deps for {name}"))
            .reads
            .clone()
    };

    assert!(
        of("current").contains(&"now".to_string()),
        "{:?}",
        of("current")
    );
    assert!(of("current").contains(&"units".to_string()));
    assert!(of("details").contains(&"now".to_string()));
    // The forecast reads the week and, through ForecastRow, the bounds.
    assert!(
        of("forecast").contains(&"week".to_string()),
        "{:?}",
        of("forecast")
    );
    // `sunmoon` reads sun and moon, and must NOT read the stock of the card.
    let sunmoon = of("sunmoon");
    assert!(sunmoon.contains(&"sun".to_string()) && sunmoon.contains(&"moon".to_string()));
    assert!(!sunmoon.contains(&"week".to_string()), "{sunmoon:?}");
}

/// A loop binder is local. `for d in week` must not make `d` a dependency, or
/// every record with a loop would look like it reads everything.
#[test]
fn a_loop_binder_is_not_a_dependency() {
    let deps = record_dependencies(WEATHER);
    let forecast = &deps.iter().find(|d| d.record == "forecast").unwrap().reads;
    assert!(!forecast.contains(&"d".to_string()), "{forecast:?}");
}

/// The measurable claim behind "one event, one state change, one reconciliation
/// pass" — toggling a unit touches the records that read it, not the tree.
#[test]
fn a_state_write_dirties_only_its_dependents() {
    let all: Vec<String> = record_dependencies(WEATHER)
        .into_iter()
        .map(|d| d.record)
        .collect();
    let dirty = dirty_records(WEATHER, &["units"]);

    assert!(!dirty.is_empty(), "toggling units must dirty something");
    assert!(
        dirty.len() < all.len(),
        "it must not dirty everything: {dirty:?}"
    );

    // The sun/moon panel does not read units and must survive untouched — it is
    // the panel whose rebuild would be most visible.
    assert!(!dirty.contains(&"sunmoon".to_string()), "{dirty:?}");
    assert!(!dirty.contains(&"airfield".to_string()), "{dirty:?}");
    // The hero and the detail tiles do read it.
    assert!(dirty.contains(&"current".to_string()), "{dirty:?}");
    assert!(dirty.contains(&"details".to_string()), "{dirty:?}");
}

/// A component's own state dirties that component, so an expanded row
/// re-realizes and its neighbours do not.
#[test]
fn component_local_state_dirties_its_component() {
    let dirty = dirty_records(WEATHER, &["expanded"]);
    assert!(
        dirty.contains(&"ForecastRow".to_string()),
        "local state must dirty its component: {dirty:?}"
    );
    assert!(!dirty.contains(&"details".to_string()), "{dirty:?}");
}

/// Over-approximation is the safe direction: re-realizing too much is slow,
/// re-realizing too little shows stale data.
#[test]
fn an_unrelated_write_dirties_nothing() {
    assert!(dirty_records(WEATHER, &["nothing_reads_this"]).is_empty());
}

use octoscript_ui_l0::patch_points;

/// `dirty_records` is transitive, so `root` appears for almost any write — it
/// splices everything, so it reads everything. Patching root rebuilds the tree,
/// which is what reconciliation exists to avoid.
#[test]
fn patch_points_exclude_ancestors_that_merely_contain_the_change() {
    let dirty = dirty_records(WEATHER, &["units"]);
    let minimal = patch_points(WEATHER, &["units"]);
    assert!(
        dirty.contains(&"root".to_string()),
        "root is transitively dirty"
    );
    assert!(
        !minimal.contains(&"root".to_string()),
        "but patching a descendant suffices: {minimal:?}"
    );
    assert!(minimal.len() < dirty.len());
}

/// The claim, at its sharpest: toggling one row's own state re-realizes that
/// component and nothing else.
#[test]
fn local_state_patches_exactly_one_record() {
    let minimal = patch_points(WEATHER, &["expanded"]);
    assert_eq!(minimal, vec!["ForecastRow".to_string()], "{minimal:?}");
}

/// A write that a SOURCE reads invalidates the fetch, and everything binding its
/// result. Changing the city re-geocodes, so every source downstream of `place`
/// is stale — a genuine full rebuild, and the graph should say so rather than
/// reporting nothing.
#[test]
fn a_write_a_source_reads_invalidates_its_dependents() {
    let minimal = patch_points(WEATHER, &["city"]);
    for record in ["current", "forecast", "airfield", "sunmoon", "details"] {
        assert!(
            minimal.contains(&record.to_string()),
            "changing the city must invalidate {record}: {minimal:?}"
        );
    }
}

/// Under-approximating shows stale data; over-approximating is merely slow.
#[test]
fn an_unrelated_write_patches_nothing() {
    assert!(patch_points(WEATHER, &["nothing_reads_this"]).is_empty());
}

// ─── named slots (§5.5, open question 5) ─────────────────────────────────────

/// Every `text` argument in the tree, in render order.
fn texts(root: &octoscript_ui_l0::UiNode) -> Vec<String> {
    fn walk(n: &octoscript_ui_l0::UiNode, out: &mut Vec<String>) {
        for (name, v) in &n.args {
            if name == "text" {
                if let NodeValue::Text(t) = v {
                    out.push(t.clone());
                }
            }
        }
        for c in &n.children {
            walk(c, out);
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

const TWO_SLOTS: &str = r#"
component Framed(title: text) {
  view Col {
         TextCaption(text: title)
         slot header
         Rule()
         slot
       }
}
view root Panel {
  Framed(title: "Today") {
    into header { TextRow(text: "in the header") }
    TextRow(text: "in the body")
  }
}
"#;

#[test]
fn a_named_slot_card_is_l0() {
    accepts("two-slots", TWO_SLOTS);
}

#[test]
fn named_slot_routes_children_to_the_matching_slot() {
    let report = realize(TWO_SLOTS, &serde_json::json!({}), RealizeLimits::default());
    assert!(report.diagnostics.is_empty(), "{:#?}", report.diagnostics);

    // Order is what proves routing: the `into header` child is written first at
    // the call site but the component places that slot above the anonymous one,
    // so the two must come out in component order, not call-site order.
    assert_eq!(
        texts(&report.root.unwrap()),
        vec!["Today", "in the header", "in the body"],
        "each group should land at its own slot"
    );
}

#[test]
fn a_slot_with_no_matching_group_renders_nothing() {
    // Not an error: a component may offer a slot that a call site declines to
    // fill. Children with nowhere to go are dropped rather than misplaced.
    let source = r#"
component Framed() { view Panel { slot aside } }
view root Panel { Framed() { TextRow(text: "loose") } }
"#;
    let report = realize(source, &serde_json::json!({}), RealizeLimits::default());
    assert!(
        texts(&report.root.unwrap()).is_empty(),
        "the anonymous group has no matching slot in this component"
    );
}

#[test]
fn an_anonymous_slot_still_needs_no_ceremony() {
    // The common case must stay as it was — no `into` required, and every
    // existing card keeps working.
    let source = r#"
component Framed() { view Panel { slot } }
view root Panel { Framed() { TextRow(text: "plain") } }
"#;
    let report = realize(source, &serde_json::json!({}), RealizeLimits::default());
    assert_eq!(texts(&report.root.unwrap()), vec!["plain"]);
}

// ─── source lifecycle (§5.9, open question 3) ────────────────────────────────

const LIFECYCLE: &str = r#"
source now sys.weather(lat: 35.0, lon: 135.0)
view root Col {
  when now.$state == .pending { TextRow(text: "Loading") }
  when now.$state == .failed  { TextRow(text: "Unavailable") }
  when now.$state == .ready   { TextRow(text: "Live") }
}
"#;

#[test]
fn a_source_lifecycle_card_is_l0() {
    accepts("lifecycle", LIFECYCLE);
}

#[test]
fn source_state_defaults_to_pending_when_no_value_arrived() {
    let report = realize(LIFECYCLE, &serde_json::json!({}), RealizeLimits::default());
    assert_eq!(
        texts(&report.root.unwrap()),
        vec!["Loading"],
        "a source with no value and no report is pending, so a card can say so \
         rather than rendering an em dash that looks like real data"
    );
}

#[test]
fn source_state_is_ready_once_a_value_arrives() {
    let data = serde_json::json!({"now": {"temp": 21.0}});
    let report = realize(LIFECYCLE, &data, RealizeLimits::default());
    assert_eq!(texts(&report.root.unwrap()), vec!["Live"]);
}

#[test]
fn the_host_can_report_failure_explicitly() {
    // The distinction that matters: a fetch that FAILED is not the same as one
    // that has not happened yet, and only the host knows which.
    let data = serde_json::json!({"$status": {"now": "failed"}});
    let report = realize(LIFECYCLE, &data, RealizeLimits::default());
    assert_eq!(
        texts(&report.root.unwrap()),
        vec!["Unavailable"],
        "failure must be distinguishable from pending"
    );
}

#[test]
fn a_stale_source_is_neither_pending_nor_failed() {
    // Stale means old, not wrong: the card keeps its last good value rather
    // than blanking a number that is merely a few minutes behind.
    let data = serde_json::json!({"now": {"temp": 21.0}, "$status": {"now": "stale"}});
    let report = realize(LIFECYCLE, &data, RealizeLimits::default());
    assert!(
        texts(&report.root.unwrap()).is_empty(),
        "this card guards three states; stale is a fourth and matches none"
    );
}

#[test]
fn state_is_rejected_on_something_that_is_not_a_source() {
    let report = check_ui_l0_named(
        "not-a-source",
        "state units { shape: enum[c, f], initial: .c }\n\
         view root Col { when units.$state == .pending { Rule() } }",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("only available on a source")),
        "local state has no fetch lifecycle: {:#?}",
        report.diagnostics
    );
}

/// A literal prop must survive the call. This failed for the life of the
/// component feature and no test caught it: the reference cards pass paths
/// (`story: s`, `position: i`), so the literal arm was never exercised and
/// `Framed(title: "Details")` rendered an em dash. Same shape as every other
/// "specified but not retained" bug — the parser kept the value and the
/// realizer dropped it on a catch-all arm.
#[test]
fn a_literal_prop_reaches_the_component() {
    let source = r#"
component Framed(title: text, rank: number) {
  view Col { TextCaption(text: title) TextRow(text: rank) }
}
view root Panel { Framed(title: "Details", rank: 3) }
"#;
    let report = realize(source, &serde_json::json!({}), RealizeLimits::default());
    assert!(report.diagnostics.is_empty(), "{:#?}", report.diagnostics);
    let root = report.root.unwrap();

    let mut caps = Vec::new();
    find(&root, "TextCaption", &mut caps);
    assert_eq!(
        caps[0].args.iter().find(|(n, _)| n == "text").unwrap().1,
        NodeValue::Text("Details".into()),
        "a string literal prop must arrive, not become Missing"
    );

    let mut rows = Vec::new();
    find(&root, "TextRow", &mut rows);
    assert_eq!(
        rows[0].args.iter().find(|(n, _)| n == "text").unwrap().1,
        NodeValue::Number(3.0),
        "a number literal prop must arrive too"
    );
}

#[test]
fn an_into_naming_an_absent_slot_is_rejected() {
    // Children with nowhere to go vanish. Silent is the wrong failure mode:
    // this is the same class as a binding that resolves to nothing.
    let report = check_ui_l0_named(
        "bad-slot",
        "component Framed() { view Panel { slot body } }\n\
         view root Panel { Framed() { into headr { Rule() } } }",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("has no slot named") && d.message.contains("body")),
        "the message should name the slots that do exist: {:#?}",
        report.diagnostics
    );
}

// ─── §6 condition 4: event cascades ──────────────────────────────────────────

/// Profile §6.4 prohibits event cascades — a transition may not trigger another
/// event. There is no check for this because there is nothing to check: the four
/// total forms (`set`, `toggle`, `cycle`, `clear`) all name a STATE, and a
/// transition target is validated against declared state. A cascade is therefore
/// unrepresentable rather than merely rejected.
///
/// This test pins that. It enumerates every syntax that could plausibly express
/// "and then fire another event" and asserts each is rejected. If someone later
/// adds a form that can raise one, termination stops being structural and this
/// test is where that shows up.
#[test]
fn an_event_cannot_trigger_another_event() {
    const PRELUDE: &str = "state n { shape: number, initial: 0 }\n\
                           state flag { shape: bool, initial: false }\n\
                           event bump { n: set(1) }\n";

    for (shape, body) in [
        (
            "a transition targeting an event name",
            "event c { bump: toggle }",
        ),
        ("a transition setting an event", "event c { bump: set(1) }"),
        (
            "an event named as a payload target",
            "event c { n: set(bump) }",
        ),
        ("an emit form", "event c { emit bump }"),
        ("a call form", "event c { bump() }"),
        ("a then form", "event c { n: set(1) then bump }"),
    ] {
        let source = format!("{PRELUDE}{body}\nview root Panel {{ Rule() }}");
        let report = check_ui_l0_named("cascade", &source);
        assert!(
            !report.valid,
            "{shape} would be a cascade and must not be accepted: {body:?}"
        );
    }

    // The control: the same prelude with a legal transition IS accepted, so the
    // rejections above are about cascades and not about the prelude.
    let ok = check_ui_l0_named(
        "no-cascade",
        &format!("{PRELUDE}event c {{ flag: toggle }}\nview root Panel {{ Rule() }}"),
    );
    assert!(ok.valid, "{:#?}", ok.diagnostics);
}

// ─── §5.8 opt-in migration (open question 6) ─────────────────────────────────

/// `keep: true` opts one cell out of the §5.8 reset. Reset stays the default;
/// this makes preservation expressible rather than impossible.
#[test]
fn a_keep_cell_survives_a_schema_change() {
    const KEPT: &str = r#"
source items sys.movers()
component Rowy(item: record) {
  state open { shape: bool, initial: false, keep: true }
  event flip { open: toggle }
  view Col {
    Row(on_tap: flip) { TextRow(text: item.name) }
    when open { TextCaption(text: item.name) }
  }
}
view root Panel { for it in items key it.id { Rowy(item: it) } }
"#;
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let data = two_rows_data();
    let first = octoscript_ui_l0::realize_with_state(KEPT, &data, &store, RealizeLimits::default());
    let mut rows = Vec::new();
    let first_root = first.root.unwrap();
    find(&first_root, "Row", &mut rows);
    octoscript_ui_l0::dispatch(KEPT, &mut store, &rows[0].key, "flip");

    // An unrelated field is added: the schema id changes, but `open` itself is
    // untouched and asked to survive.
    let edited = KEPT.replace(
        "event flip",
        "state seen { shape: bool, initial: false }\n  event flip",
    );
    let after = octoscript_ui_l0::realize_with_state(&edited, &data, &store, RealizeLimits::default());
    let mut captions = Vec::new();
    let after_root = after.root.unwrap();
    find(&after_root, "TextCaption", &mut captions);
    assert_eq!(
        captions.len(),
        1,
        "a cell that opted in and did not change shape should survive"
    );
}

/// The limit of the opt-in: `keep` is a claim about a field, not a promise that
/// any value fits. Retyping the field resets it anyway — otherwise `keep` would
/// be exactly the "guess it still fits" that §5.8 exists to prevent.
#[test]
fn keep_does_not_survive_a_change_to_that_field_itself() {
    const KEPT: &str = r#"
source items sys.movers()
component Rowy(item: record) {
  state open { shape: bool, initial: false, keep: true }
  event flip { open: toggle }
  view Col {
    Row(on_tap: flip) { TextRow(text: item.name) }
    when open { TextCaption(text: item.name) }
  }
}
view root Panel { for it in items key it.id { Rowy(item: it) } }
"#;
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let data = two_rows_data();
    let first = octoscript_ui_l0::realize_with_state(KEPT, &data, &store, RealizeLimits::default());
    let mut rows = Vec::new();
    let first_root = first.root.unwrap();
    find(&first_root, "Row", &mut rows);
    octoscript_ui_l0::dispatch(KEPT, &mut store, &rows[0].key, "flip");

    // `open` is retyped bool → enum. The opt-in does not apply to a field whose
    // own shape moved.
    let edited = KEPT
        .replace(
            "state open { shape: bool, initial: false, keep: true }",
            "state open { shape: enum[shut, ajar], initial: .shut, keep: true }",
        )
        .replace(
            "event flip { open: toggle }",
            "event flip { open: cycle(.shut, .ajar) }",
        );
    let after = octoscript_ui_l0::realize_with_state(&edited, &data, &store, RealizeLimits::default());
    let mut captions = Vec::new();
    let after_root = after.root.unwrap();
    find(&after_root, "TextCaption", &mut captions);
    assert_eq!(
        captions.len(),
        0,
        "a retyped field resets even with keep: true"
    );
}

/// Reset remains the default: without `keep`, nothing changes.
#[test]
fn without_keep_a_schema_change_still_resets() {
    // This is `a_schema_change_resets_instance_state` restated as the control
    // for the two tests above — the opt-in must not have become the default.
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let data = two_rows_data();
    let first = octoscript_ui_l0::realize_with_state(TWO_ROWS, &data, &store, RealizeLimits::default());
    let mut rows = Vec::new();
    let first_root = first.root.unwrap();
    find(&first_root, "Row", &mut rows);
    octoscript_ui_l0::dispatch(TWO_ROWS, &mut store, &rows[0].key, "flip");

    let edited = TWO_ROWS.replace(
        "event flip",
        "state seen { shape: bool, initial: false }\n  event flip",
    );
    let after = octoscript_ui_l0::realize_with_state(&edited, &data, &store, RealizeLimits::default());
    let mut captions = Vec::new();
    let after_root = after.root.unwrap();
    find(&after_root, "TextCaption", &mut captions);
    assert_eq!(captions.len(), 0, "reset is still the default");
}

// ─── §7 component version pinning ────────────────────────────────────────────

/// §7 requires component versions to be pinned, "or an L0 card can be moved to
/// L2 by a definition it references being replaced". The report carries a digest
/// per component so a host can store it beside the approved level and notice.
#[test]
fn the_report_carries_a_digest_per_component() {
    let report = check_ui_l0_named("weather", WEATHER);
    assert!(report.valid);
    assert!(
        !report.closure.is_empty(),
        "the weather card declares a component, so the closure cannot be empty"
    );
    let names: Vec<&str> = report.closure.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"ForecastRow"), "got {names:?}");

    // Sorted, so a host comparing two closures does not have to.
    let mut sorted = report.closure.clone();
    sorted.sort();
    assert_eq!(sorted, report.closure);
}

#[test]
fn replacing_a_component_body_changes_its_digest() {
    let before = check_ui_l0_named("weather", WEATHER).closure;

    // The change that motivates §7: a component gains a construct outside L0.
    // The card text is otherwise identical, so a host that pinned only the
    // card's level would carry the old L0 verdict onto a definition that no
    // longer earns it.
    let edited = WEATHER.replace(
        "component ForecastRow(",
        "component ForecastRow(extra: number, ",
    );
    assert_ne!(edited, WEATHER, "the replacement must actually apply");
    let after = check_ui_l0_named("weather", &edited).closure;

    let digest = |c: &[(String, u64)]| {
        c.iter()
            .find(|(n, _)| n == "ForecastRow")
            .map(|(_, d)| *d)
            .unwrap()
    };
    assert_ne!(
        digest(&before),
        digest(&after),
        "a changed definition must produce a changed digest"
    );
}

#[test]
fn reordering_declarations_is_not_a_version_change() {
    // A digest that moved on a cosmetic edit would make pinning useless: every
    // reformat would look like a replacement and hosts would learn to ignore it.
    let source = "\
component A(x: number) { view Panel { TextRow(text: x) } }\n\
component B(y: number) { view Panel { TextRow(text: y) } }\n\
view root Panel { A(x: 1) B(y: 2) }\n";
    let swapped = "\
component B(y: number) { view Panel { TextRow(text: y) } }\n\
component A(x: number) { view Panel { TextRow(text: x) } }\n\
view root Panel { A(x: 1) B(y: 2) }\n";

    let a = check_ui_l0_named("a", source);
    let b = check_ui_l0_named("b", swapped);
    assert!(
        a.valid && b.valid,
        "{:#?} {:#?}",
        a.diagnostics,
        b.diagnostics
    );
    assert_eq!(a.closure, b.closure);
}

// ─── §3 cycle ordering (open question 2) ─────────────────────────────────────

/// `cycle` advances in the ENUM's declaration order. That is the guarantee
/// question 2 asked for, and it is what makes the transition total and O(1) —
/// there is no comparison to run, only a successor.
#[test]
fn cycle_advances_in_declaration_order() {
    const TRI: &str = "\
state mode { shape: enum[low, mid, high], initial: .low }\n\
event step { mode: cycle(.low, .mid, .high) }\n\
view root Panel { Row(on_tap: step) { Rule() } }\n";

    let mut store = octoscript_ui_l0::InstanceStore::default();
    let report = realize(TRI, &serde_json::json!({}), RealizeLimits::default());
    let mut rows = Vec::new();
    let root = report.root.unwrap();
    find(&root, "Row", &mut rows);
    let key = rows[0].key.clone();

    for expected in ["mid", "high", "low"] {
        octoscript_ui_l0::dispatch(TRI, &mut store, &key, "step");
        assert_eq!(
            store.get("@card", "mode").and_then(|v| v.as_str()),
            Some(expected),
            "cycle should wrap through declaration order"
        );
    }
}

/// The corollary: a `cycle` that lists a different order is rejected rather
/// than quietly running the declared one. Accepting it would mean the card says
/// one order and the runtime performs another.
#[test]
fn a_cycle_listing_a_different_order_is_rejected() {
    let report = check_ui_l0_named(
        "reordered",
        "state mode { shape: enum[low, mid, high], initial: .low }\n\
         event step { mode: cycle(.high, .mid, .low) }\n\
         view root Panel { Rule() }\n",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("declaration order")),
        "{:#?}",
        report.diagnostics
    );
}

// ─── §5.1 identity is a path, not a position ─────────────────────────────────

const TOGGLY: &str = r#"
component Toggly() {
  state open { shape: bool, initial: false }
  event flip { open: toggle }
  view Col {
    Row(on_tap: flip) { TextRow(text: "hdr") }
    when open { TextCaption(text: "OPEN") }
  }
}
view root Panel { Toggly() }
"#;

/// §5.1: "L0 binds to a declared path so that identity survives a ledger edit
/// that inserts an element above." This is the profile's stated difference from
/// React, and it went untested — the implementation keyed children by their raw
/// index, so it was in fact using React's rule while the spec said it was not.
///
/// The scenario is not hypothetical for a ledger: appending a record that adds
/// a rule above a list is an ordinary edit, and it should not collapse every
/// expanded row on screen.
#[test]
fn state_survives_an_element_inserted_above() {
    let data = serde_json::json!({});
    let mut store = octoscript_ui_l0::InstanceStore::default();

    let first = octoscript_ui_l0::realize_with_state(TOGGLY, &data, &store, RealizeLimits::default());
    let root = first.root.unwrap();
    let mut rows = Vec::new();
    find(&root, "Row", &mut rows);
    let key = rows[0].key.clone();
    octoscript_ui_l0::dispatch(TOGGLY, &mut store, &key, "flip");

    // The same card with a Rule inserted ABOVE the component.
    let edited = TOGGLY.replace(
        "view root Panel { Toggly() }",
        "view root Panel { Rule() Toggly() }",
    );
    assert_ne!(edited, TOGGLY, "the edit must actually apply");

    let after = octoscript_ui_l0::realize_with_state(&edited, &data, &store, RealizeLimits::default());
    let after_root = after.root.unwrap();
    let mut rows_after = Vec::new();
    find(&after_root, "Row", &mut rows_after);
    assert_eq!(
        rows_after[0].key, key,
        "the instance key must not depend on how many siblings precede it"
    );

    let mut caps = Vec::new();
    find(&after_root, "TextCaption", &mut caps);
    assert_eq!(
        caps.len(),
        1,
        "the toggled state must survive an insertion above (profile §5.1)"
    );
}

/// The other half: sibling instances of the same component stay distinct, so
/// making keys insertion-stable must not make two of them collide.
#[test]
fn sibling_instances_of_one_component_keep_separate_state() {
    let two = TOGGLY.replace(
        "view root Panel { Toggly() }",
        "view root Panel { Toggly() Toggly() }",
    );
    let data = serde_json::json!({});
    let mut store = octoscript_ui_l0::InstanceStore::default();

    let first = octoscript_ui_l0::realize_with_state(&two, &data, &store, RealizeLimits::default());
    let root = first.root.unwrap();
    let mut rows = Vec::new();
    find(&root, "Row", &mut rows);
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].key, rows[1].key, "two instances need two keys");

    // Flip only the first.
    octoscript_ui_l0::dispatch(&two, &mut store, &rows[0].key.clone(), "flip");
    let after = octoscript_ui_l0::realize_with_state(&two, &data, &store, RealizeLimits::default());
    let after_root = after.root.unwrap();
    let mut caps = Vec::new();
    find(&after_root, "TextCaption", &mut caps);
    assert_eq!(caps.len(), 1, "exactly one instance should be expanded");
}

// ─── §4 source capabilities are a closed set ─────────────────────────────────

/// The finding that motivated this: `source_plan` handed an arbitrary dotted
/// name to the host as the function to resolve, so a card could NAME a
/// capability it was never granted and produce a clean, well-formed request.
/// Confinement then rested on the host keeping its own allowlist — the policy
/// boundary §1 claims L0 removes.
#[test]
fn an_uncatalogued_source_helper_is_rejected() {
    let report = check_ui_l0_named(
        "leak",
        "source leak sys.shell(command: \"cat /etc/passwd\")\nview root Rule()",
    );
    assert!(!report.valid, "a card must not be able to name sys.shell");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not a source capability")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn an_uncatalogued_helper_produces_no_source_request() {
    // Belt and braces: even if a caller skips checking, the plan must not carry
    // the request onward to a host that trusts it.
    let plan = octoscript_ui_l0::source_plan(
        "source leak sys.shell(command: \"cat /etc/passwd\")\nview root Rule()",
    );
    assert!(
        !plan.requests.iter().any(|r| r.helper == "sys.shell"),
        "an uncatalogued helper must not reach the host: {:?}",
        plan.requests.iter().map(|r| &r.helper).collect::<Vec<_>>()
    );
    assert!(!plan.diagnostics.is_empty(), "and it must say why");
}

#[test]
fn a_catalogued_helper_rejects_an_argument_it_does_not_accept() {
    // A helper that silently ignores an unknown argument is how a card asks for
    // something it did not get and renders as though it did.
    let report = check_ui_l0_named(
        "badarg",
        "source w sys.weather(lat: 1.0, lon: 2.0, shell: \"rm -rf /\")\nview root Rule()",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("does not accept an argument named")),
        "{:#?}",
        report.diagnostics
    );
}

/// The catalog in the TOML and the one in Rust must list the same capabilities
/// with the same arguments — in both directions, and this time actually.
#[test]
fn the_source_catalog_matches_the_toml_spec() {
    const TOML: &str = include_str!("../../../docs/ui-l0-constructors.toml");

    let mut documented: Vec<(String, Vec<String>)> = Vec::new();
    let mut current: Option<String> = None;
    for line in TOML.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("[sources.\"") {
            current = rest.strip_suffix("\"]").map(|s| s.to_string());
            if let Some(name) = &current {
                documented.push((name.clone(), Vec::new()));
            }
        } else if line.starts_with('[') {
            current = None;
        } else if current.is_some() {
            if let Some(rest) = line.strip_prefix("args = [") {
                let args: Vec<String> = rest
                    .trim_end_matches(']')
                    .split(',')
                    .map(|a| a.trim().trim_matches('"').to_string())
                    .filter(|a| !a.is_empty())
                    .collect();
                documented.last_mut().unwrap().1 = args;
            }
        }
    }

    assert!(!documented.is_empty(), "the TOML must declare [sources.*]");

    for (name, args) in &documented {
        let implemented = catalog::source(name)
            .unwrap_or_else(|| panic!("{name:?} is in the TOML but not in the Rust catalog"));
        assert_eq!(
            implemented,
            args.as_slice(),
            "arguments for {name:?} disagree between the TOML and Rust"
        );
    }
    for (name, args) in catalog::SOURCES {
        let (_, doc_args) = documented
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("{name:?} is in the Rust catalog but not in the TOML"));
        assert_eq!(
            *args,
            doc_args.as_slice(),
            "arguments for {name:?} disagree between Rust and the TOML"
        );
    }
}

/// The field vocabularies must agree between Rust and the TOML too.
///
/// The TOML is what the agent-facing catalog is GENERATED from, so a vocabulary
/// that lives only in Rust is one the model writing cards never sees — it would
/// be refused for naming a field the documentation never offered it. The
/// arguments have been checked both ways since they existed; the fields are new
/// and need the same discipline or they drift the first time one is added.
#[test]
fn the_field_vocabularies_match_the_toml_spec() {
    const TOML: &str = include_str!("../../../docs/ui-l0-constructors.toml");

    let mut documented: Vec<(String, String, Vec<String>)> = Vec::new();
    let mut current: Option<String> = None;
    for line in TOML.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("[sources.\"") {
            current = rest.strip_suffix("\"]").map(|s| s.to_string());
        } else if line.starts_with('[') {
            current = None;
        } else if let Some(name) = &current {
            for (key, label) in [
                ("answers = [", "answers"),
                ("aggregates = [", "aggregates"),
                ("writes = [", "writes"),
            ] {
                if let Some(rest) = line.strip_prefix(key) {
                    documented.push((
                        name.clone(),
                        label.to_string(),
                        rest.trim_end_matches(']')
                            .split(',')
                            .map(|f| f.trim().trim_matches('"').to_string())
                            .filter(|f| !f.is_empty())
                            .collect(),
                    ));
                }
            }
        }
    }

    // Every capability declares a vocabulary, even an empty one: silence would
    // be indistinguishable from "not written down yet", and the checker treats
    // an absent vocabulary as "do not check".
    assert_eq!(
        documented.iter().filter(|(_, k, _)| k == "answers").count(),
        catalog::ANSWERS.len(),
        "every capability must document its answerable fields"
    );

    for (name, kind, fields) in &documented {
        let rust: &[&str] = match kind.as_str() {
            "answers" => catalog::answers(name)
                .unwrap_or_else(|| panic!("{name:?} documents fields but Rust declares none")),
            // Which transitions a store-backed capability accepts (§5.12). A
            // capability the TOML says is writable and Rust does not would be a
            // card refused for doing what the documentation offered.
            "writes" => catalog::mutable(name)
                .unwrap_or_else(|| panic!("{name:?} documents writes but Rust says read-only")),
            _ => catalog::aggregates(name),
        };
        assert_eq!(
            rust,
            fields.as_slice(),
            "{kind} for {name:?} disagree between Rust and the TOML"
        );
    }
    for (name, fields) in catalog::ANSWERS {
        assert!(
            documented
                .iter()
                .any(|(n, k, f)| n == name && k == "answers" && f == fields),
            "{name:?} answers {fields:?} in Rust and the TOML does not say so"
        );
    }
    // The other direction for writes. A capability that is writable in Rust and
    // silent in the TOML grants a power the documentation never mentions, which
    // is the worse half of a drift — the agent never learns it exists.
    for (name, verbs) in catalog::MUTABLE {
        assert!(
            documented
                .iter()
                .any(|(n, k, v)| n == name && k == "writes" && v == verbs),
            "{name:?} accepts {verbs:?} in Rust and the TOML does not say so"
        );
    }
}

// ─── parse-then-discard: forms recognised but whose values were dropped ──────
//
// Every one of these parsed cleanly and then lost the value. That is the single
// most common defect in this work, and each of these was found by the codex
// review rather than by a failing test — which is the point of writing them.

/// `active: range == .d1` realized as the VALUE of `range` rather than a
/// boolean, because the parser kept the left path and dropped the comparator
/// and right operand. Live in stock.card, and the device golden recorded the
/// wrong rendering as correct.
#[test]
fn a_predicate_argument_evaluates_to_a_boolean() {
    let source = "state range { shape: enum[d1, w1], initial: .d1 }\n\
                  view root Col { Chip(text: \"1D\", active: range == .d1) \
                                  Chip(text: \"1W\", active: range == .w1) }";
    let report = realize(source, &serde_json::json!({}), RealizeLimits::default());
    let root = report.root.unwrap();
    let mut chips = Vec::new();
    find(&root, "Chip", &mut chips);
    assert_eq!(chips.len(), 2);
    let active = |c: &octoscript_ui_l0::UiNode| {
        c.args
            .iter()
            .find(|(n, _)| n == "active")
            .map(|(_, v)| v.clone())
    };
    assert_eq!(active(chips[0]), Some(NodeValue::Bool(true)));
    assert_eq!(active(chips[1]), Some(NodeValue::Bool(false)));
}

/// A guard's right operand is a binding too. Unchecked, `when x != absent`
/// resolved `absent` to nothing and the comparison decided the branch on that
/// absence — so the branch rendered with an undeclared name in it.
#[test]
fn a_guard_right_operand_must_be_declared() {
    let report = check_ui_l0_named(
        "rhs",
        "state selected { shape: text, initial: \"\" }\n\
         view root Col { when selected != absent { Rule() } }",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("absent")),
        "{:#?}",
        report.diagnostics
    );
}

/// `initial: env.locale.temp_unit` was recognised and dropped, so the state
/// fell back to the enum's first member — a phone set to Fahrenheit rendered
/// Celsius, which is weather.card's actual declaration.
#[test]
fn a_path_valued_initial_resolves_against_data() {
    let source = "source env.locale sys.locale()\n\
                  state units { shape: enum[c, f], initial: env.locale.temp_unit }\n\
                  view root TextRow(text: units)";
    for locale in ["f", "c"] {
        let data = serde_json::json!({"env": {"locale": {"temp_unit": locale}}});
        let report = realize(source, &data, RealizeLimits::default());
        let root = report.root.unwrap();
        assert_eq!(
            root.args.iter().find(|(n, _)| n == "text").unwrap().1,
            NodeValue::Text(locale.into()),
            "the declared initial must follow the host's locale"
        );
    }
}

/// `stories[selected].title` became `stories.title` — the index was parsed and
/// thrown away, so it resolved to nothing.
#[test]
fn a_dynamic_index_resolves_through_its_inner_path() {
    let source = "source movers sys.movers()\n\
                  state selected { shape: text, initial: \"b\" }\n\
                  view root TextRow(text: movers[selected].title)";
    let data = serde_json::json!({"movers": {"a": {"title": "FIRST"}, "b": {"title": "SECOND"}}});
    let report = realize(source, &data, RealizeLimits::default());
    let root = report.root.unwrap();
    assert_eq!(
        root.args.iter().find(|(n, _)| n == "text").unwrap().1,
        NodeValue::Text("SECOND".into())
    );
}

#[test]
fn a_dynamic_index_path_is_itself_checked() {
    let report = check_ui_l0_named(
        "idx",
        "source movers sys.movers()\nview root TextRow(text: movers[typo].title)",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("typo")),
        "{:#?}",
        report.diagnostics
    );
}

/// `set` had no numeric or boolean variant, so `set(1)` fell through to the
/// payload form and did nothing at all when no payload was present. And
/// `SetSource::Path` was treated exactly like `$value`, so `set(config.answer)`
/// wrote whatever the tap carried rather than what it named.
#[test]
fn every_set_form_writes_what_it_names() {
    let card = "state n { shape: number, initial: 0 }\n\
                state ok { shape: bool, initial: false }\n\
                source movers sys.movers(count: 1)\n\
                event bump { n: set(1) }\n\
                event frompath { n: set(movers.answer) }\n\
                event yes { ok: set(true) }\n\
                view root Row(on_tap: bump) { Rule() }";
    let data = serde_json::json!({"movers": {"answer": 7}});
    let mut store = octoscript_ui_l0::InstanceStore::default();

    octoscript_ui_l0::dispatch_with_data(card, &mut store, "root", "bump", None, &data);
    assert_eq!(store.get("@card", "n").and_then(|v| v.as_f64()), Some(1.0));

    octoscript_ui_l0::dispatch_with_data(card, &mut store, "root", "frompath", None, &data);
    assert_eq!(store.get("@card", "n").and_then(|v| v.as_f64()), Some(7.0));

    octoscript_ui_l0::dispatch_with_data(card, &mut store, "root", "yes", None, &data);
    assert_eq!(
        store.get("@card", "ok").and_then(|v| v.as_bool()),
        Some(true)
    );

    // A payload must not hijack a transition that names a path to read.
    let stray = serde_json::json!("STRAY");
    octoscript_ui_l0::dispatch_with_data(card, &mut store, "root", "frompath", Some(&stray), &data);
    assert_eq!(
        store.get("@card", "n").and_then(|v| v.as_f64()),
        Some(7.0),
        "set(path) reads its path, not the payload"
    );
}

#[test]
fn only_dollar_value_names_the_payload() {
    // `$anything` was accepted as a synonym, so a typo silently became $value.
    let report = check_ui_l0_named(
        "typo",
        "state n { shape: number, initial: 0 }\nevent e { n: set($valu) }\nview root Rule()",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("$value")),
        "{:#?}",
        report.diagnostics
    );
}

// ─── the Makepad backend must carry interaction, not just appearance ─────────

/// `UiNode` carried the event name and instance key all along and lowering
/// emitted neither, so every tappable node rendered inert — the stock range
/// controls could not reach `dispatch` at all. The cards looked right and did
/// nothing, which no golden image could detect.
#[test]
fn lowering_emits_the_event_and_the_instance_key() {
    let data = serde_json::json!({
        "movers": [{ "ticker": "NVDA", "name": "NVIDIA", "last": 184.2,
                     "change": 3.1, "pct": 1.7 }],
        "quote": {}, "series": {}, "selected": "", "range": "m1",
        "env": { "locale": {} }, "copy": { "movers": "Top Movers" }
    });
    let dsl = octoscript_ui_l0::makepad::lower(
        &realize(STOCK, &data, RealizeLimits::default())
            .root
            .unwrap(),
    );
    assert!(
        dsl.contains("l0_event: \"open_quote\""),
        "a tappable row must carry its event"
    );
    assert!(
        dsl.contains("l0_key:"),
        "and the key naming WHICH instance was tapped"
    );
    assert!(
        dsl.contains("l0_value: \"NVDA\""),
        "and the payload, or a tap says what happened but not to what"
    );
}

/// `active` selected nothing, so every range chip rendered identically and the
/// card could not show which was selected.
#[test]
fn lowering_distinguishes_an_active_chip() {
    let source = "state range { shape: enum[d1, w1], initial: .d1 }\n\
                  view root Col { Chip(text: \"1D\", active: range == .d1) \
                                  Chip(text: \"1W\", active: range == .w1) }";
    let dsl = octoscript_ui_l0::makepad::lower(
        &realize(source, &serde_json::json!({}), RealizeLimits::default())
            .root
            .unwrap(),
    );
    let fills: Vec<&str> = dsl
        .lines()
        .filter(|l| l.contains("RoundedView"))
        .filter_map(|l| l.split("draw_bg.color: ").nth(1))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert_eq!(fills.len(), 2, "two chips");
    assert_ne!(
        fills[0], fills[1],
        "the selected chip must not look like the unselected one"
    );
}

// ─── §7 the header is checked, not decorated ─────────────────────────────────

#[test]
fn the_header_is_read_from_a_real_card() {
    let report = check_ui_l0_named("weather", WEATHER);
    let header = report.header.expect("weather.card declares a header");
    assert_eq!(header.ledger.as_deref(), Some("weather"));
    assert_eq!(header.version.as_deref(), Some("1.0.0"));
    assert_eq!(header.level.as_deref(), Some("L0"));
    assert_eq!(header.profile.as_deref(), Some("ui/l0"));
}

/// §7: "Level is declared in the header and checked at append." Nothing read
/// it — every `#` line lexed as a comment — so a card could declare L2 and be
/// accepted and realized as L0. A declaration never compared to the derived
/// level is a comment, not a check.
#[test]
fn a_header_declaring_the_wrong_level_is_rejected() {
    let report = check_ui_l0_named("evil", "# ledger evil@1.0.0\n# level: L2\nview root Rule()");
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("declares level L2")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_header_declaring_an_unknown_profile_is_rejected() {
    let report = check_ui_l0_named(
        "wrong",
        "# ledger x@1.0.0\n# profile: nonsense/v9\nview root Rule()",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("ui/l0")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_card_without_a_header_is_still_accepted() {
    // The header is optional; only a header that CONTRADICTS the card is an
    // error. Requiring one would reject every inline fragment in these tests.
    let report = check_ui_l0_named("bare", "view root Rule()");
    assert!(report.valid, "{:#?}", report.diagnostics);
    assert!(report.header.is_none());
}

// ─── §4 the no-facts rule ────────────────────────────────────────────────────

/// §4 calls a model-authored literal in a data position "a structural
/// violation, not a judgement call". It was neither — `kind = "path"` was
/// declared in the catalog and never enforced, so every drawing widget accepted
/// invented values.
#[test]
fn a_literal_in_a_data_position_is_rejected() {
    for source in [
        "view root TextHero(value: \"34 mph\")",
        "view root TextStat(value: 41.2)",
        "view root TempBar(lo: 5, hi: 9, min: 0, max: 10)",
        "view root WeatherIcon(cond: \"sunny\")",
    ] {
        let report = check_ui_l0_named("facts", source);
        assert!(!report.valid, "should be rejected: {source}");
        assert!(
            report.diagnostics.iter().any(|d| d.message.contains("§4")),
            "the diagnostic should cite the rule: {:#?}",
            report.diagnostics
        );
    }
}

/// The line the rule actually draws: a card MAY choose its own layout, and may
/// not invent a measurement. Without this distinction the check either rejects
/// `gap: 6` or permits `value: 41.2`.
#[test]
fn a_layout_literal_is_not_a_fact() {
    for source in [
        "view root Row(gap: 6) { Rule() }",
        "view root Grid(cols: 2) { Rule() }",
        "view root Col(gap: 3) { Rule() }",
    ] {
        let report = check_ui_l0_named("layout", source);
        assert!(report.valid, "{source} — {:#?}", report.diagnostics);
    }
}

#[test]
fn a_bound_value_is_accepted() {
    let report = check_ui_l0_named(
        "bound",
        "source now sys.weather(lat: 1.0, lon: 2.0)\nview root TextStat(value: now.temp)",
    );
    assert!(report.valid, "{:#?}", report.diagnostics);
}

/// The constructor catalog compared NAMES and three token sets, so changing
/// `TextHero.value` from `number` to `data` in the TOML left it green — and §8
/// claimed on that basis that the two agreed "in both directions". They must
/// agree on every ARGUMENT and its kind, which is what the checker actually
/// consults.
#[test]
fn every_constructor_argument_agrees_with_the_toml() {
    const TOML: &str = include_str!("../../../docs/ui-l0-constructors.toml");

    // [Ctor] followed by `name = { kind = "…" }` lines, until the next header.
    let mut documented: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for line in TOML.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if !name.contains('.') && !name.starts_with("kinds") {
                documented.push((name.to_string(), Vec::new()));
            } else {
                // A [kinds.*] or [sources."…"] section ends the constructor run.
                documented.push((String::new(), Vec::new()));
            }
            continue;
        }
        let Some((arg, rest)) = line.split_once('=') else {
            continue;
        };
        let Some(kind) = rest
            .split("kind = \"")
            .nth(1)
            .and_then(|k| k.split('"').next())
        else {
            continue;
        };
        if let Some((name, args)) = documented.last_mut() {
            if !name.is_empty() {
                args.push((arg.trim().to_string(), kind.to_string()));
            }
        }
    }
    let documented: Vec<_> = documented
        .into_iter()
        .filter(|(n, _)| !n.is_empty())
        .collect();
    assert!(
        documented.len() > 15,
        "parsed {} constructors",
        documented.len()
    );

    // The TOML's kind names, mapped onto what the Rust catalog stores.
    let agrees = |kind: &str, actual: &catalog::ArgKind| -> bool {
        use catalog::ArgKind::*;
        match (kind, actual) {
            ("path", Path) | ("event", Event) | ("any", Any) => true,
            ("data", Data) | ("number", Number) | ("text", Text) | ("bool", Bool) => true,
            ("token", Token(_)) => true,
            ("unit", TokenOrPath(set)) => *set == catalog::UNIT,
            ("format", Token(set)) => *set == catalog::FORMAT,
            ("width", TokenOrPath(set)) => *set == catalog::WIDTH,
            ("mapview", TokenOrPath(set)) => *set == catalog::MAP_VIEW,
            _ => false,
        }
    };

    for (ctor, args) in &documented {
        let implemented = catalog::lookup(ctor)
            .unwrap_or_else(|| panic!("{ctor:?} is in the TOML but not in the Rust catalog"));
        for (arg, kind) in args {
            let (_, actual) = implemented
                .iter()
                .find(|(n, _)| n == arg)
                .unwrap_or_else(|| panic!("{ctor}.{arg} is in the TOML but not in Rust"));
            assert!(
                agrees(kind, actual),
                "{ctor}.{arg}: TOML says {kind:?}, Rust has {actual:?}"
            );
        }
        assert_eq!(
            implemented.len(),
            args.len(),
            "{ctor} has {} arguments in Rust and {} in the TOML",
            implemented.len(),
            args.len()
        );
    }
}

// ─── §6.1 the declaration graph, including views ─────────────────────────────

/// Acyclicity walked components only, so two shapes recursed at realization and
/// were caught — if at all — by the node cap, which is a resource bound
/// standing in for a structural check.
#[test]
fn mutually_recursive_views_are_rejected() {
    let report = check_ui_l0_named("mutual", "view a b\nview b a\nview root a");
    assert!(!report.valid, "view a -> b -> a must be rejected");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("recursive")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_component_recursing_through_a_view_is_rejected() {
    let report = check_ui_l0_named(
        "via-view",
        "component A() { view Panel { v } }\nview v Panel { A() }\nview root A()",
    );
    assert!(!report.valid, "A -> v -> A must be rejected");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("recursive")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn an_acyclic_view_chain_is_still_accepted() {
    // The check must not reject ordinary splicing, which the cards rely on.
    let report = check_ui_l0_named(
        "chain",
        "view leaf Rule()\nview mid Panel { leaf }\nview root Panel { mid }",
    );
    assert!(report.valid, "{:#?}", report.diagnostics);
}

/// Depth was approximated by the instance key's LENGTH, which bounds neither
/// direction: a long loop key truncated a shallow tree, and short view names
/// recursed far past max_depth. It is now an actual recursion counter.
#[test]
fn depth_is_counted_not_inferred_from_key_length() {
    // A shallow tree whose keys are long must NOT truncate.
    let long_key = "a_very_long_item_identifier_that_makes_instance_keys_lengthy";
    let source = format!(
        "source movers sys.movers()\nview root Panel {{ for m in movers key m.{long_key} {{ Rule() }} }}"
    );
    let data = serde_json::json!({
        "movers": [{ long_key: "x".repeat(120) }, { long_key: "y".repeat(120) }]
    });
    let report = realize(&source, &data, RealizeLimits::default());
    assert!(
        !report.truncated,
        "a shallow tree must not truncate because its keys are long"
    );
    let mut rules = Vec::new();
    let root = report.root.unwrap();
    find(&root, "Rule", &mut rules);
    assert_eq!(rules.len(), 2, "both rows should realize");
}

// ─── §5.2 component props carry their declared shape ────────────────────────
//
// The shape was parsed and discarded, which cost three separate defects. They
// looked unrelated in the review and shared one cause.

/// An argument the component does not declare was accepted and then silently
/// dropped at realization, so `Framed(titel: "x")` rendered an em dash and
/// looked deliberate.
#[test]
fn an_undeclared_prop_is_rejected() {
    let report = check_ui_l0_named(
        "typo",
        "component F(title: text) { view Panel { TextRow(text: title) } }\n\
         view root F(titel: \"x\")",
    );
    assert!(!report.valid);
    let message = &report.diagnostics[0].message;
    assert!(
        message.contains("no prop") && message.contains("title"),
        "the message should name the props that exist: {message}"
    );
}

/// `set(out)` where `out` is an event prop was accepted, because no param's
/// shape was known so none could be excluded from the readable set.
#[test]
fn an_event_prop_cannot_be_read_by_set() {
    let report = check_ui_l0_named(
        "setevent",
        "component F(out: event) { state n { shape: number, initial: 0 } \
         event e { n: set(out) } view Panel { Row(on_tap: e) { Rule() } } }\n\
         event go { }\nview root F(out: go)",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("is an event, not a value")),
        "{:#?}",
        report.diagnostics
    );
}

/// Every param used to be added to the component's event names, so a `text`
/// prop could be handed to `on_tap` — and a runtime string that happened to
/// equal a declared event would route it. Event routing became data-selected.
#[test]
fn a_value_prop_cannot_be_used_as_an_event() {
    let report = check_ui_l0_named(
        "asevent",
        "component F(label: text) { view Panel { Row(on_tap: label) { Rule() } } }\n\
         view root F(label: \"x\")",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not a declared event")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_token_outside_an_enum_prop_is_rejected() {
    // Now possible because the prop's members survive parsing.
    let report = check_ui_l0_named(
        "enumprop",
        "component F(unit: enum[c, f]) { view Panel { TextValue(value: unit) } }\n\
         view root F(unit: .kelvin)",
    );
    assert!(!report.valid);
    assert!(
        report.diagnostics[0].message.contains(".c, .f"),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_correct_call_site_is_still_accepted() {
    let report = check_ui_l0_named(
        "ok",
        "component F(title: text, unit: enum[c, f], on_go: event) { \
           view Panel { Row(on_tap: on_go) { TextRow(text: title) TextValue(value: unit) } } }\n\
         event go { }\nview root F(title: \"x\", unit: .c, on_go: go)",
    );
    assert!(report.valid, "{:#?}", report.diagnostics);
}

/// Retyping between `text` and `number` moved neither the schema id nor the
/// closure digest, because both parsed to the same unclassified shape — so a
/// live string survived into number-shaped state, and a host pinning the digest
/// saw no change.
#[test]
fn retyping_between_text_and_number_is_visible() {
    let base = "component F(x: text) { state s { shape: text, initial: \"\" } \
                view Panel { TextRow(text: s) } }\nview root F(x: \"a\")";

    let retyped_state = base
        .replace("shape: text", "shape: number")
        .replace("initial: \"\"", "initial: 0");
    assert_ne!(
        check_ui_l0_named("p", base).closure,
        check_ui_l0_named("p", &retyped_state).closure,
        "retyping state between text and number must move the digest"
    );

    let retyped_param = base.replace("F(x: text)", "F(x: number)");
    assert_ne!(
        check_ui_l0_named("p", base).closure,
        check_ui_l0_named("p", &retyped_param).closure,
        "retyping a prop must move the digest"
    );
}

// ─── second codex round ──────────────────────────────────────────────────────

#[test]
fn a_contradictory_duplicate_header_field_is_rejected() {
    // Last-wins meant a card could declare what it needed and then declare the
    // truth after it: `# level: L2` followed by `# level: L0` was accepted.
    //
    // The FIRST value must be one that passes on its own, or this test proves
    // nothing. An earlier version used `L2` then `L0`: the retained `L2` failed
    // the level-vs-derived check, so the card was rejected by a different rule
    // and the test passed even with the contradiction check disabled entirely.
    // Mutation testing is what surfaced that.
    let report = check_ui_l0_named(
        "dup-profile",
        "# ledger x@1.0.0\n# profile: ui/l0\n# profile: nonsense/v9\nview root Rule()",
    );
    assert!(!report.valid, "a contradictory header must be refused");
    assert_eq!(
        report.diagnostics.len(),
        1,
        "exactly one rule should fire, or this does not isolate it: {:#?}",
        report.diagnostics
    );
    assert!(
        report.diagnostics[0]
            .message
            .contains("declares profile twice"),
        "{:#?}",
        report.diagnostics
    );

    // And the level form, which is the one the defect was found in.
    let level = check_ui_l0_named(
        "dup-level",
        "# ledger x@1.0.0\n# level: L0\n# level: L2\nview root Rule()",
    );
    assert!(!level.valid);
    assert!(
        level
            .diagnostics
            .iter()
            .any(|d| d.message.contains("declares level twice")),
        "{:#?}",
        level.diagnostics
    );
}

#[test]
fn a_token_in_a_data_position_is_rejected() {
    // `Data` rejected strings and numbers and let tokens through.
    let report = check_ui_l0_named("tok", "view root TextHero(value: .money)");
    assert!(!report.valid);
    assert!(
        report.diagnostics[0].message.contains("token"),
        "{:#?}",
        report.diagnostics
    );
}

/// `set` wrote whatever it was given regardless of what the state could hold.
#[test]
fn set_must_fit_the_target_shape() {
    for (source, expect) in [
        (
            "state ok { shape: bool, initial: false }\nevent e { ok: set(1) }\nview root Rule()",
            "writes a number",
        ),
        (
            "state m { shape: enum[a, b], initial: .a }\nevent e { m: set(true) }\nview root Rule()",
            "writes a bool",
        ),
        (
            "state n { shape: number, initial: 0 }\nevent e { n: set(\"x\") }\nview root Rule()",
            "writes text",
        ),
        (
            "state m { shape: enum[a, b], initial: .a }\nevent e { m: set(.c) }\nview root Rule()",
            "not a member",
        ),
    ] {
        let report = check_ui_l0_named("shape", source);
        assert!(!report.valid, "should be rejected: {source}");
        assert!(
            report.diagnostics.iter().any(|d| d.message.contains(expect)),
            "expected {expect:?}: {:#?}",
            report.diagnostics
        );
    }
}

/// A dotted source name registered only its ROOT, so the lifecycle of
/// `source env.locale` could not be asked for, while `env.$state` — which names
/// no source at all — was accepted.
#[test]
fn a_dotted_source_reports_its_own_lifecycle() {
    let source = "source env.locale sys.locale()\n\
                  view root Col { when env.locale.$state == .ready { TextRow(text: \"READY\") } \
                                  when env.locale.$state == .pending { TextRow(text: \"WAIT\") } }";
    assert!(check_ui_l0_named("dotted", source).valid);

    let ready = realize(
        source,
        &serde_json::json!({"env": {"locale": {"lang": "en"}}}),
        RealizeLimits::default(),
    );
    assert_eq!(texts(&ready.root.unwrap()), vec!["READY"]);

    let pending = realize(source, &serde_json::json!({}), RealizeLimits::default());
    assert_eq!(texts(&pending.root.unwrap()), vec!["WAIT"]);

    let bogus = check_ui_l0_named(
        "aggregate",
        "source env.locale sys.locale()\nview root Col { when env.$state == .ready { Rule() } }",
    );
    assert!(
        !bogus.valid,
        "`env` names no source, so it has no lifecycle to report"
    );
}

/// §5.8 says the schema id covers "names, shapes and initials". It hashed only
/// path and shape, so changing an initial did not reset live state.
#[test]
fn changing_an_initial_changes_the_schema() {
    let base = "component F() { state s { shape: number, initial: 0 } \
                view Panel { TextRow(text: s) } }\nview root F()";
    let changed = base.replace("initial: 0", "initial: 7");
    assert_ne!(
        check_ui_l0_named("p", base).closure,
        check_ui_l0_named("p", &changed).closure,
        "an initial is part of the state schema (§5.8)"
    );
}

// ─── §4 copy provenance ──────────────────────────────────────────────────────

/// §4 requires a rendered literal to be "vocabulary or source-derived". That
/// was undecidable, not merely unenforced: `parse_locale_map` kept only entries
/// whose value was a STRING, and `class: vocabulary` is an identifier — so the
/// provenance was discarded before anything could read it.
#[test]
fn provenance_survives_parsing_and_model_copy_is_refused() {
    let vocabulary = check_ui_l0_named(
        "vocab",
        "copy hi { class: vocabulary, en: \"Top Stories\" }\nview root TextTitle(text: copy.hi)",
    );
    assert!(vocabulary.valid, "{:#?}", vocabulary.diagnostics);

    let user = check_ui_l0_named(
        "user",
        "copy note { class: user-copy, en: \"my note\" }\nview root TextTitle(text: copy.note)",
    );
    assert!(
        user.valid,
        "the user may write their own text: {:#?}",
        user.diagnostics
    );

    let model = check_ui_l0_named(
        "model",
        "copy claim { class: model-copy, en: \"Revenue: $41.2M\" }\n\
         view root TextTitle(text: copy.claim)",
    );
    assert!(
        !model.valid,
        "model-authored text must not reach the screen"
    );
    assert!(
        model
            .diagnostics
            .iter()
            .any(|d| d.message.contains("model-copy")),
        "{:#?}",
        model.diagnostics
    );
}

/// The hyphen in `user-copy` lexes as a minus, and the level classifier read it
/// as arithmetic — so the two spellings §4 depends on could not appear in a card
/// at all. The rule was unstatable in its own language.
#[test]
fn a_hyphenated_copy_class_is_not_arithmetic() {
    for class in ["vocabulary", "user-copy"] {
        let report = check_ui_l0_named(
            "class",
            &format!("copy c {{ class: {class}, en: \"x\" }}\nview root TextTitle(text: copy.c)"),
        );
        assert_eq!(report.level, Level::L0, "{class} should not classify as L1");
        assert!(report.valid, "{class}: {:#?}", report.diagnostics);
    }
}

#[test]
fn an_unknown_copy_class_is_rejected() {
    let report = check_ui_l0_named(
        "bogus",
        "copy c { class: whatever, en: \"x\" }\nview root TextTitle(text: copy.c)",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not a copy class")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn an_undeclared_copy_reference_is_rejected() {
    // Previously `copy` was a known root and any name under it resolved to
    // nothing, so a typo rendered an em dash.
    let report = check_ui_l0_named("missing", "view root TextTitle(text: copy.nope)");
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not declared")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn the_reference_cards_declare_their_copy_provenance() {
    // All 23 copy declarations across the three cards are `vocabulary`, which
    // is the discipline the profile assumes and could not previously verify.
    for (name, source) in [("weather", WEATHER), ("news", NEWS), ("stock", STOCK)] {
        let report = check_ui_l0_named(name, source);
        assert!(report.valid, "{name}: {:#?}", report.diagnostics);
    }
}

// ─── rules the validator enforces that no test was holding ───────────────────
//
// Found by mutation-testing the validator (mutate.py): suppress one diagnostic,
// run the suite, see whether anything goes red. These nine did not. Each was
// enforced and unprotected — free to regress silently, which is exactly how the
// `initial` fix ended up with a regression test that checked the wrong artifact
// and could not fail.

#[test]
fn state_must_be_the_last_segment_of_a_path() {
    let report = check_ui_l0_named(
        "midstate",
        "source now sys.weather(lat: 1.0, lon: 2.0)\nview root TextRow(text: now.$state.x)",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("last segment")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn cycle_requires_an_enum_state() {
    let report = check_ui_l0_named(
        "cyclebool",
        "state flag { shape: bool, initial: false }\n\
         event e { flag: cycle(.a, .b) }\nview root Rule()",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("needs an enum state")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_loop_over_something_that_is_not_a_collection_is_reported() {
    // A REALIZATION diagnostic, not a validation one: whether a source's value
    // is an array is the host's answer, not the card's declaration. Writing
    // this against check_ui_l0 first is how I learned that.
    let report = realize(
        "source movers sys.movers()\nview root Panel { for x in movers key x.id { Rule() } }",
        &serde_json::json!({"movers": 7}),
        RealizeLimits::default(),
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not a collection")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_reference_to_an_undeclared_view_is_rejected() {
    let report = check_ui_l0_named("noview", "view root Panel { missing_view }");
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("is not a declared view")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn set_from_an_unreadable_name_is_rejected() {
    let report = check_ui_l0_named(
        "unreadable",
        "state n { shape: number, initial: 0 }\n\
         event e { n: set(nowhere.value) }\nview root Rule()",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not a readable name")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn an_into_on_a_component_with_only_an_anonymous_slot_is_rejected() {
    // The complement of `an_into_naming_an_absent_slot_is_rejected`, which
    // exercised the branch where the component DOES offer named slots. This is
    // the other message, and it was unheld.
    let report = check_ui_l0_named(
        "onlyanon",
        "component F() { view Panel { slot } }\n\
         view root Panel { F() { into header { Rule() } } }",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("only an anonymous slot")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_token_where_a_path_belongs_is_rejected() {
    let report = check_ui_l0_named("tokpath", "view root WeatherIcon(cond: .sunny)");
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("takes a bound path")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_literal_where_an_event_prop_belongs_is_rejected() {
    let report = check_ui_l0_named(
        "litevent",
        "component F(on_go: event) { view Panel { Row(on_tap: on_go) { Rule() } } }\n\
         view root F(on_go: \"nope\")",
    );
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("takes an event, not a literal")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn a_card_without_a_root_view_is_rejected() {
    let report = check_ui_l0_named("noroot", "view sidebar Panel { Rule() }");
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("view root")),
        "{:#?}",
        report.diagnostics
    );
}

/// The level-classified rules (`let`, `while`, arithmetic, `fn`, module access)
/// are held by the LEVEL a card is assigned, not by their diagnostic text — so
/// suppressing the message changes nothing and mutation testing reports them as
/// unprotected. Assert on the level itself, which is the thing §7 actually
/// promises: escalation is never silent.
#[test]
fn every_construct_outside_l0_raises_the_level() {
    for (source, expected, what) in [
        // L2, not L1: an imperative binding is not a pure expression, so it
        // sits with the widget commands rather than with arithmetic.
        ("view root Panel { }\nlet x = 1", Level::L2, "let"),
        ("view root Panel { }\nwhile true { }", Level::L2, "while"),
        (
            "state n { shape: number, initial: 0 }\nview root TextStat(value: n + 1)",
            Level::L1,
            "arithmetic",
        ),
        ("view root Panel { }\nfn tick() { }", Level::L2, "fn"),
    ] {
        let report = check_ui_l0_named("level", source);
        assert!(!report.valid, "{what} must not be L0-valid");
        assert_eq!(
            report.level, expected,
            "{what} should classify as {expected:?}: {:#?}",
            report.diagnostics
        );
    }
}

// ─── codex round three ───────────────────────────────────────────────────────
// Written BEFORE the fixes, and each confirmed failing first.

/// #6: `parse_state` scanned every token in the body for a shape word instead
/// of reading the one after `shape:`. So an enum whose members include a shape
/// name was silently retyped by its own member.
#[test]
fn an_enum_member_named_like_a_shape_does_not_retype_the_state() {
    let report = check_ui_l0_named(
        "shadow",
        "state mode { shape: enum[a, text], initial: .a }\n\
         event e { mode: set(\"arbitrary\") }\nview root Rule()",
    );
    assert!(
        !report.valid,
        "`mode` is an enum; a member happening to be called `text` must not \
         turn it into text and let any string be written"
    );
}

/// #7: a misspelled shape produced `Other` with no diagnostic, and the `set`
/// checks treat `Other` as "accepts anything" — so the typo disabled them.
#[test]
fn a_misspelled_shape_is_rejected_rather_than_silently_permissive() {
    let report = check_ui_l0_named(
        "typo-shape",
        "state n { shape: nubmer, initial: 0 }\nevent e { n: set(\"oops\") }\nview root Rule()",
    );
    assert!(!report.valid, "`nubmer` is not a shape");
}

/// #8: a token was checked only when the target was an enum; every other shape
/// fell through, so `set(.c)` into a number wrote the string "c".
#[test]
fn a_token_set_into_a_non_enum_is_rejected() {
    let report = check_ui_l0_named(
        "toknum",
        "state n { shape: number, initial: 0 }\nevent e { n: set(.c) }\nview root Rule()",
    );
    assert!(!report.valid);
}

/// #7 (second half): a declared initial was never checked against the shape it
/// was declared alongside.
#[test]
fn an_initial_must_fit_its_declared_shape() {
    let report = check_ui_l0_named(
        "badinit",
        "state n { shape: number, initial: \"oops\" }\nview root Rule()",
    );
    assert!(!report.valid);
}

/// #3: this falsifies §4's claim that "a fabricated number cannot reach a
/// numeric position" — which I wrote into the spec the same day. A literal
/// launders through a prop into the drawing widgets, which exist to render
/// live data and hold no authored values.
#[test]
fn a_literal_cannot_launder_through_a_prop_into_a_data_position() {
    let report = check_ui_l0_named(
        "launder",
        "component Bar(n: number) { view TempBar(lo: n, hi: n, min: n, max: n) }\n\
         view root Bar(n: 41.2)",
    );
    assert!(
        !report.valid,
        "an authored number must not reach TempBar by way of a prop"
    );
}

/// #4: prop shapes were retained at parse and discarded again at realization,
/// so an enum token bound with its leading dot and every comparison against it
/// inside the component was false.
#[test]
fn an_enum_token_prop_binds_its_bare_member() {
    let source = "component F(unit: enum[c, f]) { \
                    view Col { when unit == .c { TextRow(text: \"MATCHED\") } } }\n\
                  view root F(unit: .c)";
    let report = realize(source, &serde_json::json!({}), RealizeLimits::default());
    assert_eq!(
        texts(&report.root.unwrap()),
        vec!["MATCHED"],
        "`.c` must bind as `c`, or the component cannot compare against its own prop"
    );
}

/// #4 (second half): an event prop was looked up as DATA at realization, so a
/// state whose name collided with an event name hijacked the routing.
#[test]
fn an_event_prop_binds_the_event_not_same_named_state() {
    let source = "state go { shape: text, initial: \"wrong\" }\n\
                  event go { go: set(\"x\") }\n\
                  event wrong { go: set(\"y\") }\n\
                  component F(out: event) { view Panel { Row(on_tap: out) { Rule() } } }\n\
                  view root F(out: go)";
    let report = realize(source, &serde_json::json!({}), RealizeLimits::default());
    let root = report.root.unwrap();
    let mut rows = Vec::new();
    find(&root, "Row", &mut rows);
    let on_tap = rows[0]
        .args
        .iter()
        .find(|(n, _)| n == "on_tap")
        .map(|(_, v)| v.clone());
    assert_eq!(
        on_tap,
        Some(NodeValue::Event("go".into())),
        "the event named at the call site must be the event that fires"
    );
}

/// #5: a declared default was parsed and dropped, an omitted argument created
/// no binding, and lookup then fell through to top-level injected data — so an
/// unfilled prop could capture whatever the host happened to supply.
#[test]
fn a_prop_default_is_used_and_injected_data_cannot_capture_it() {
    let source = "component Banner(title: text = \"Safe\") { view TextRow(text: title) }\n\
                  view root Banner()";

    let empty = realize(source, &serde_json::json!({}), RealizeLimits::default());
    assert_eq!(
        texts(&empty.root.unwrap()),
        vec!["Safe"],
        "an omitted prop must fall back to its declared default"
    );

    let hostile = realize(
        source,
        &serde_json::json!({"title": "attacker"}),
        RealizeLimits::default(),
    );
    assert_eq!(
        texts(&hostile.root.unwrap()),
        vec!["Safe"],
        "and must not be captured by same-named data the host injected"
    );
}

#[test]
fn laundering_a_literal_through_a_chain_of_props_is_also_refused() {
    // One hop would be a spot fix. The check runs to a fixpoint, so a longer
    // chain is no better a hiding place than a short one.
    let bar = "component Bar(n: number) { view TempBar(lo: n, hi: n, min: n, max: n) }\n";
    for depth in [
        format!("{bar}view root Bar(n: 41.2)"),
        format!("{bar}component Outer(v: number) {{ view Panel {{ Bar(n: v) }} }}\nview root Outer(v: 41.2)"),
        format!(
            "{bar}component Mid(m: number) {{ view Panel {{ Bar(n: m) }} }}\n\
             component Outer(v: number) {{ view Panel {{ Mid(m: v) }} }}\nview root Outer(v: 41.2)"
        ),
    ] {
        assert!(
            !check_ui_l0_named("chain", &depth).valid,
            "an authored number must not reach a data position at any depth"
        );
    }

    // And the two things that must stay legal: a BOUND value through the same
    // chain, and a literal in a position that renders no fact.
    let bound = format!(
        "source now sys.weather(lat: 1.0, lon: 2.0)\n{bar}\
         component Outer(v: number) {{ view Panel {{ Bar(n: v) }} }}\nview root Outer(v: now.temp)"
    );
    assert!(check_ui_l0_named("bound", &bound).valid);
    assert!(
        check_ui_l0_named(
            "label",
            "component Lbl(t: text) { view TextTitle(text: t) }\nview root Lbl(t: \"Heading\")"
        )
        .valid,
        "a literal label renders no fact and must stay legal"
    );
}

/// #1: provenance failed OPEN. A declaration with no `class` at all defaulted
/// to trusted, so the check only bit when a card volunteered the label — which
/// a model with something to hide would not.
#[test]
fn copy_without_a_class_is_refused_rather_than_trusted() {
    let report = check_ui_l0_named(
        "noclass",
        "copy claim { en: \"Revenue: $41.2M\" }\nview root TextTitle(text: copy.claim)",
    );
    assert!(
        !report.valid,
        "undeclared provenance must not default to vocabulary"
    );
}

/// #2: even correctly-marked model-copy laundered through a state initial,
/// because provenance was checked only where an element referenced copy.x
/// directly.
#[test]
fn model_copy_cannot_launder_through_a_state_initial() {
    let report = check_ui_l0_named(
        "via-state",
        "copy claim { class: model-copy, en: \"Revenue: $41.2M\" }\n\
         component F() { state s { shape: text, initial: copy.claim } view TextTitle(text: s) }\n\
         view root F()",
    );
    assert!(!report.valid);
}

// ─── parser and resource bounds ──────────────────────────────────────────────
//
// Found by the second mutation run, after fixing the harness's own blind spot:
// it had been selecting diagnostics by keyword and silently missing newer ones.
// Four of these are §6's termination bounds, which the profile claims outright.

#[test]
fn a_source_over_the_size_limit_is_rejected() {
    let huge = format!("view root Panel {{ }}\n# {}", "x".repeat(300_000));
    let report = check_ui_l0_named("huge", &huge);
    assert!(!report.valid);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("byte limit")),
        "{:#?}",
        report.diagnostics
    );
}

#[test]
fn malformed_input_is_rejected_rather_than_parsed_loosely() {
    for (source, expect, what) in [
        (
            "state n { shape: number, initial: 0 }\nbanana root Rule()",
            "expected a declaration",
            "unknown declaration",
        ),
        (
            "view root Panel { 42 }",
            "expected an element",
            "a literal where an element belongs",
        ),
        (
            "component F() { banana }",
            "expected state, event or view",
            "junk in a component body",
        ),
        (
            "view root TextRow(text: \"unterminated)",
            "unterminated string",
            "an unterminated string",
        ),
        (
            "view root Panel { } \u{0007}",
            "unexpected character",
            "a character outside the grammar",
        ),
    ] {
        let report = check_ui_l0_named("malformed", source);
        assert!(!report.valid, "{what} must be rejected");
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.message.contains(expect)),
            "{what}: {:#?}",
            report.diagnostics
        );
    }
}

/// The two malformations live generation actually produced — a `when` guard
/// nested inside a constructor's argument list, and a comma where an
/// argument's `:` belongs — must refuse with diagnostics that TEACH, because
/// the diagnostic text is fed back verbatim as the repair prompt. A bare
/// `expected ")", found "when"` sent the model in circles; the teaching text
/// names the construct and the fix.
#[test]
fn syntax_the_model_gets_wrong_is_refused_with_a_teaching_diagnostic() {
    // (a) A `when` guard inside an argument list — both the no-comma form
    // (the live `line 75: expected ")", found "when"` refusal) and the
    // comma form, where `ident()` used to eat `when` as an argument name.
    for (source, what) in [
        (
            "view root Col(gap: 8\n  when count > 0 { Rule() }\n)",
            "when guard after the last argument, no comma",
        ),
        (
            "view root Col(gap: 8, when count > 0 { Rule() })",
            "when guard in argument position after a comma",
        ),
        (
            "view root Col(gap: 8, for m in movers key m.id { Rule() })",
            "for loop in argument position",
        ),
    ] {
        let report = check_ui_l0_named("malformed", source);
        assert!(!report.valid, "{what} must be rejected");
        assert!(
            report.diagnostics.iter().any(|d| d
                .message
                .contains("cannot appear inside an argument list")
                && d.message.contains("wrap elements")),
            "{what} should produce the teaching diagnostic: {:#?}",
            report.diagnostics
        );
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("expected \")\", found \"when\"")
                    || d.message.contains("expected \")\", found \"for\"")),
            "{what}: the bare expected/found must be replaced, not joined: {:#?}",
            report.diagnostics
        );
    }

    // (b) A comma where the argument's `:` belongs (the live `line 124:
    // expected ":", found ","` refusal). The diagnostic must name the
    // argument, state the `name: value` form, and not cascade.
    let report = check_ui_l0_named("malformed", "view root TextRow(text, value)");
    assert!(!report.valid, "a bare-value argument must be rejected");
    assert!(
        report.diagnostics.iter().any(|d| d
            .message
            .contains("expected \":\" after argument name `text`")
            && d.message.contains("`name: value`")),
        "comma-for-colon should produce the teaching diagnostic: {:#?}",
        report.diagnostics
    );
    assert_eq!(
        report.diagnostics.len(),
        1,
        "one mistake, one diagnostic — the old cascade buried the line that \
         mattered: {:#?}",
        report.diagnostics
    );
}

/// §6, condition 5: node count and nesting depth are capped, and the
/// declaration count with them. These are the bounds that make realization
/// terminate on input the grammar alone does not bound.
#[test]
fn the_resource_bounds_hold() {
    let deep = format!(
        "view root {}Rule(){}",
        "Panel { ".repeat(200),
        " }".repeat(200)
    );
    let report = check_ui_l0_named("deep", &deep);
    assert!(!report.valid, "nesting must be bounded");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("too deep")),
        "{:#?}",
        report.diagnostics
    );

    let many = format!(
        "{}view root Rule()",
        (0..2_000)
            .map(|i| format!("state s{i} {{ shape: number, initial: 0 }}\n"))
            .collect::<String>()
    );
    let report = check_ui_l0_named("many", &many);
    assert!(!report.valid, "declaration count must be bounded");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("too many declarations")),
        "{:#?}",
        report.diagnostics
    );

    let wide = format!("view root Panel {{ {} }}", "Rule() ".repeat(3_000));
    let report = check_ui_l0_named("wide", &wide);
    assert!(!report.valid, "block width must be bounded");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("too many elements")),
        "{:#?}",
        report.diagnostics
    );
}

/// #9: `source_roots` was fixed to hold full names, but ordinary `Scope.roots`
/// still held the ROOT — so declaring one source authorised reading everything
/// beside it. The card then renders an undeclared dependency, which is exactly
/// what §4's "anything reachable without a declared source is a defect by
/// construction" says cannot happen.
#[test]
fn a_dotted_source_does_not_authorise_its_whole_root() {
    let report = check_ui_l0_named(
        "sibling",
        "source env.locale sys.locale()\nview root TextRow(text: env.theme.secret)",
    );
    assert!(
        !report.valid,
        "declaring env.locale must not grant env.theme"
    );

    // The declared one still works.
    assert!(
        check_ui_l0_named(
            "ok",
            "source env.locale sys.locale()\nview root TextRow(text: env.locale.lang)"
        )
        .valid
    );
}

/// #10: a dotted source's dependency edge was lost, because the argument was
/// reduced to its root and compared against the full declared name. The plan
/// then emitted the dependent BEFORE the thing it depends on.
#[test]
fn a_dotted_source_dependency_is_ordered_correctly() {
    let plan = octoscript_ui_l0::source_plan(
        "source env.locale sys.locale()\n\
         source scene sys.photo(query: env.locale.lang)\n\
         view root Rule()",
    );
    let order: Vec<&str> = plan.requests.iter().map(|r| r.name.as_str()).collect();
    // Unwrap both: `None < Some(_)` is true in Rust, so comparing the Options
    // directly would let an ABSENT prerequisite satisfy the ordering assertion.
    let locale = order
        .iter()
        .position(|n| *n == "env.locale")
        .expect("env.locale must be planned");
    let scene = order
        .iter()
        .position(|n| *n == "scene")
        .expect("scene must be planned");
    assert!(
        locale < scene,
        "a source must be fetched before the one that reads it: {order:?}"
    );
    let scene_req = plan.requests.iter().find(|r| r.name == "scene").unwrap();
    assert!(
        scene_req.depends_on.iter().any(|d| d == "env.locale"),
        "the edge must be recorded: {:?}",
        scene_req.depends_on
    );
}

/// #11: only `level` and `profile` were checked for contradictory duplicates.
/// A card could declare two different ledger identities and the last one won.
#[test]
fn a_contradictory_duplicate_ledger_is_rejected() {
    let report = check_ui_l0_named(
        "twoledgers",
        "# ledger real@1.0.0\n# ledger impostor@9.9.9\nview root Rule()",
    );
    assert!(!report.valid, "a card has one identity");
}

/// #13: the regression test for §5.8's schema id compared `report.closure`,
/// which the definition digest already made sensitive to initials — so it
/// passed with the schema fix reverted. It must exercise the store.
#[test]
fn changing_an_initial_resets_live_component_state() {
    const BEFORE: &str = "source items sys.movers()\n\
        component Rowy(item: record) { state n { shape: number, initial: 0 } \
          event bump { n: set(1) } \
          view Col { Row(on_tap: bump) { TextRow(text: item.name) } \
                     when n == 1 { TextCaption(text: item.name) } } }\n\
        view root Panel { for it in items key it.id { Rowy(item: it) } }";

    let data = serde_json::json!({"items": [{"id": "a", "name": "A"}]});
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let first = octoscript_ui_l0::realize_with_state(BEFORE, &data, &store, RealizeLimits::default());
    let root = first.root.unwrap();
    let mut rows = Vec::new();
    find(&root, "Row", &mut rows);
    let applied = octoscript_ui_l0::dispatch(BEFORE, &mut store, &rows[0].key.clone(), "bump");
    assert!(
        applied,
        "the event must actually apply, or this proves nothing"
    );

    // Prove the caption is PRESENT before the edit. Without this, a dispatch
    // regression alone satisfies the assertion below and masks the schema
    // regression the test is named for.
    let live = octoscript_ui_l0::realize_with_state(BEFORE, &data, &store, RealizeLimits::default());
    let live_root = live.root.unwrap();
    let mut before_caps = Vec::new();
    find(&live_root, "TextCaption", &mut before_caps);
    assert_eq!(
        before_caps.len(),
        1,
        "state must be live before the schema change"
    );

    let after = BEFORE.replace("initial: 0", "initial: 7");
    let out = octoscript_ui_l0::realize_with_state(&after, &data, &store, RealizeLimits::default());
    let out_root = out.root.unwrap();
    let mut caps = Vec::new();
    find(&out_root, "TextCaption", &mut caps);
    assert_eq!(
        caps.len(),
        0,
        "a changed initial is a schema change (§5.8), so live state must reset"
    );
}

// ─── codex round four: merge blockers ────────────────────────────────────────

/// A 60 KB card — well under the 256 KiB byte limit — overflowed the parser's
/// stack and ABORTED the process. `dotted_name` recursed once per nested
/// dynamic index with only a local guard, and predicate right-hand sides had
/// the same shape.
///
/// This is a crash on untrusted input in the component whose entire purpose is
/// accepting untrusted input, so a documented limit would not do.
#[test]
fn deeply_nested_paths_do_not_overflow_the_stack() {
    for depth in [2_000, 20_000, 60_000] {
        let source = format!(
            "source a sys.movers()\nview root TextRow(text: {}a{})",
            "a[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(
            source.len() < 262_144,
            "the probe must stay under the byte limit, or it proves nothing"
        );
        // Reaching the assertion at all is the test: an overflow aborts the
        // whole binary rather than failing this case.
        let report = check_ui_l0_named("deep-path", &source);
        assert!(
            !report.valid,
            "nesting past the bound must be refused, not accepted"
        );
    }
}

/// The same shape on the other recursive path: a predicate's right-hand side.
#[test]
fn deeply_nested_predicates_do_not_overflow_the_stack() {
    let depth = 20_000;
    let source = format!(
        "state n {{ shape: number, initial: 0 }}\nview root Col {{ when n == {}n{} {{ Rule() }} }}",
        "n[".repeat(depth),
        "]".repeat(depth)
    );
    assert!(source.len() < 262_144);
    let report = check_ui_l0_named("deep-pred", &source);
    assert!(!report.valid);
}

/// §5.7 says duplicate keys are an error at realization. Nothing tracked them,
/// so two items with the same id produced IDENTICAL instance keys — one cell
/// shared by two rows, and tapping either toggled both.
#[test]
fn duplicate_loop_keys_are_reported_and_do_not_share_state() {
    const CARD: &str = "source items sys.movers()\n\
        component R(it: record) { state n { shape: bool, initial: false } \
          event f { n: toggle } \
          view Col { Row(on_tap: f) { TextRow(text: it.name) } \
                     when n { TextCaption(text: it.name) } } }\n\
        view root Panel { for i in items key i.id { R(it: i) } }";

    let data = serde_json::json!({
        "items": [{"id": "same", "name": "A"}, {"id": "same", "name": "B"}]
    });
    let report = realize(CARD, &data, RealizeLimits::default());
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("duplicate")),
        "a duplicate key must be reported: {:#?}",
        report.diagnostics
    );

    let root = report.root.unwrap();
    let mut rows = Vec::new();
    find(&root, "Row", &mut rows);
    assert_eq!(rows.len(), 2, "both rows still render");
    assert_ne!(
        rows[0].key, rows[1].key,
        "two instances must not share one state cell"
    );
}

/// The key expression itself was never validated: its first segment was
/// discarded unconditionally, so `key typo.id` behaved exactly like
/// `key item.id` — which also means changing a key does not reliably move
/// identity, contrary to §5.1.
#[test]
fn a_loop_key_must_name_the_loop_binder() {
    let report = check_ui_l0_named(
        "badkey",
        "source items sys.movers()\nview root Panel { for it in items key typo.id { Rule() } }",
    );
    assert!(!report.valid, "`typo` is not the binder `it`");
}

/// `validate_sources` checked the helper name and its argument NAMES, never the
/// paths those arguments carry. So a card could reference anything and the
/// value went to the host inside a well-formed request — which is precisely
/// the undeclared dependency §4 says is "a defect by construction".
#[test]
fn a_source_argument_path_must_be_declared() {
    let report = check_ui_l0_named(
        "leak-arg",
        "source photo sys.photo(query: secrets.token)\nview root Photo(src: photo.url)",
    );
    assert!(!report.valid, "`secrets` is not declared");

    // The plan must not carry it either, for a caller that skips checking.
    let plan = octoscript_ui_l0::source_plan(
        "source photo sys.photo(query: secrets.token)\nview root Photo(src: photo.url)",
    );
    assert!(
        !plan.diagnostics.is_empty(),
        "the plan must report it rather than hand the host an undeclared path"
    );

    // A declared one still works.
    assert!(
        check_ui_l0_named(
            "ok",
            // The view reads `place`. A source nothing reads is refused now, and
            // this assertion proved a DECLARED argument path is accepted only by
            // accident while the source it declared reached no view at all.
            "state city { shape: text, initial: \"\" }\n\
             source place sys.geocode(name: city)\n\
             view root TextRow(text: place.name)"
        )
        .valid
    );
}

/// The acyclicity walk counted every popped name against one budget, and
/// `collect_constructors` yields ordinary catalog constructors, not just graph
/// nodes. So padding a component with enough `Rule()`s exhausts the budget
/// before the traversal reaches the recursive edge, and the card is reported
/// acyclic — which means §6's first termination condition is not enforced.
#[test]
fn padding_cannot_hide_a_cycle_from_the_acyclicity_check() {
    let padding = "Rule() ".repeat(600);
    let source = format!(
        "component A() {{ view Col {{ A() Panel {{ {padding} }} Panel {{ {padding} }} }} }}\n\
         view root A()"
    );
    let report = check_ui_l0_named("padded", &source);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("recursive")),
        "a recursive component must be caught however much noise surrounds it: {:#?}",
        report
            .diagnostics
            .iter()
            .map(|d| &d.message)
            .collect::<Vec<_>>()
    );
}

/// A header containing ONLY duplicate `model:` lines never set `saw_any`, so
/// `parse_header` returned None and the contradiction vanished with it.
#[test]
fn a_model_only_duplicate_header_is_still_caught() {
    let report = check_ui_l0_named(
        "dupmodel",
        "# model: first\n# model: second\nview root Rule()",
    );
    assert!(!report.valid, "a card names one model");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("model twice")),
        "{:#?}",
        report.diagnostics
    );
}

/// A parameter default was accepted regardless of the shape declared beside it,
/// and the spec's own `enum[c, f] = c` spelling was not parsed at all.
#[test]
fn a_parameter_default_must_fit_its_declared_shape() {
    for source in [
        "component F(n: number = \"oops\") { view TextRow(text: n) }\nview root F()",
        "component G(m: enum[a, b] = .missing) { view TextRow(text: m) }\nview root G()",
        "component H(b: bool = 3) { view Col { when b { Rule() } } }\nview root H()",
    ] {
        let report = check_ui_l0_named("baddefault", source);
        assert!(!report.valid, "should be rejected: {source}");
    }
}

#[test]
fn a_bare_enum_member_is_a_valid_default() {
    // §5.2's own example spells it without the dot. It parsed as nothing, so
    // the documented form silently produced no default at all.
    let report = check_ui_l0_named(
        "bare",
        "component F(unit: enum[c, f] = c) { view TextValue(value: unit) }\nview root F()",
    );
    assert!(report.valid, "{:#?}", report.diagnostics);

    let out = realize(
        "component F(unit: enum[c, f] = c) { view TextRow(text: unit) }\nview root F()",
        &serde_json::json!({}),
        RealizeLimits::default(),
    );
    assert_eq!(
        texts(&out.root.unwrap()),
        vec!["c"],
        "the default must bind"
    );
}

// ─── phase 3: the three claims the spec makes and did not keep ───────────────

/// §3: "an event names several transitions, applied atomically". They were
/// applied sequentially straight to the store, so a batch that fails partway
/// leaves the earlier writes standing — a half-applied event.
#[test]
fn a_transition_batch_is_atomic() {
    const CARD: &str = "state a { shape: number, initial: 0 }\n\
                        state b { shape: number, initial: 0 }\n\
                        source cfg sys.movers()\n\
                        event both { a: set(1), b: set(cfg.missing) }\n\
                        view root Row(on_tap: both) { Rule() }";

    let mut store = octoscript_ui_l0::InstanceStore::default();
    // `cfg.missing` does not resolve, so the batch cannot complete.
    let applied = octoscript_ui_l0::dispatch_with_data(
        CARD,
        &mut store,
        "root",
        "both",
        None,
        &serde_json::json!({"cfg": {}}),
    );
    assert!(
        !applied,
        "a batch that cannot complete must not report success"
    );
    assert_eq!(
        store.get("@card", "a"),
        None,
        "the first write must not survive a batch that failed on the second"
    );
}

/// §3: `set($value)` performed no shape check at dispatch, so a string payload
/// entered a number cell — the transition type system stops at the boundary.
#[test]
fn a_payload_must_fit_the_state_it_is_written_to() {
    const CARD: &str = "state n { shape: number, initial: 0 }\n\
                        event pick { n: set($value) }\n\
                        view root Row(on_tap: pick, value: \"x\") { Rule() }";
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let payload = serde_json::json!("not a number");
    let applied = octoscript_ui_l0::dispatch_with(CARD, &mut store, "root", "pick", Some(&payload));
    assert!(!applied, "a payload of the wrong shape must be refused");
    assert_eq!(store.get("@card", "n"), None);
}

/// §3: `clear` restores "the declared initial". It ignored a path-valued one and
/// fell back to the shape default, and `cycle` started from the shape default
/// too — so a card whose initial comes from the host began in the wrong state.
#[test]
fn clear_restores_a_path_valued_initial() {
    const CARD: &str = "source env.locale sys.locale()\n\
                        state units { shape: enum[c, f], initial: env.locale.temp_unit }\n\
                        event reset { units: clear }\n\
                        event flip { units: cycle(.c, .f) }\n\
                        view root Row(on_tap: flip) { Rule() }";
    let data = serde_json::json!({"env": {"locale": {"temp_unit": "f"}}});
    let mut store = octoscript_ui_l0::InstanceStore::default();

    octoscript_ui_l0::dispatch_with_data(CARD, &mut store, "root", "flip", None, &data);
    assert_eq!(
        store.get("@card", "units").and_then(|v| v.as_str()),
        Some("c"),
        "cycle must advance from the host-supplied initial `f`, not from the shape default"
    );

    octoscript_ui_l0::dispatch_with_data(CARD, &mut store, "root", "reset", None, &data);
    assert_eq!(
        store.get("@card", "units").and_then(|v| v.as_str()),
        Some("f"),
        "clear must restore the declared initial, path-valued or not"
    );
}

/// §4 refuses model-authored text in a rendering position. It was enforced only
/// where an element named `copy.x` directly, so any indirection defeated it.
/// These are the routes: through a component prop, through a prop default, and
/// through a transition that writes it into state.
#[test]
fn model_copy_cannot_reach_the_screen_by_any_route() {
    const DECL: &str = "copy claim { class: model-copy, en: \"Revenue: $41.2M\" }\n";

    for (route, source) in [
        (
            "directly",
            format!("{DECL}view root TextTitle(text: copy.claim)"),
        ),
        (
            "through a prop",
            format!(
                "{DECL}component F(t: text) {{ view TextTitle(text: t) }}\n\
                 view root F(t: copy.claim)"
            ),
        ),
        (
            "through a state initial",
            format!(
                "{DECL}component F() {{ state s {{ shape: text, initial: copy.claim }} \
                 view TextTitle(text: s) }}\nview root F()"
            ),
        ),
        (
            "through a transition",
            format!(
                "{DECL}state s {{ shape: text, initial: \"\" }}\n\
                 event e {{ s: set(copy.claim) }}\nview root Row(on_tap: e) {{ Rule() }}"
            ),
        ),
    ] {
        assert!(
            !check_ui_l0_named("route", &source).valid,
            "model-copy must not reach the screen {route}"
        );
    }

    // Vocabulary still travels every one of those routes.
    let ok = "copy label { class: vocabulary, en: \"Top Stories\" }\n\
              component F(t: text) { view TextTitle(text: t) }\n\
              view root F(t: copy.label)";
    assert!(check_ui_l0_named("vocab", ok).valid);
}

/// §6, condition 5 caps nesting depth AND node count, and they are different
/// bounds. The existing deep-source test builds a tree that trips the node cap
/// on the way down, so removing the depth check entirely left it green — the
/// rebuilt mutation harness caught that.
///
/// This isolates depth: a tree deeper than `max_depth` but far short of
/// `max_nodes`, so only the depth bound can stop it.
#[test]
fn realization_depth_is_bounded_independently_of_node_count() {
    // Between the two bounds: under the parser's 128-deep limit so it parses,
    // over the realizer's default 64 so only the realization bound can stop it.
    let depth = 100;
    let source = format!(
        "view root {}Rule(){}",
        "Col { ".repeat(depth),
        " }".repeat(depth)
    );
    let limits = RealizeLimits {
        max_nodes: 100_000, // far above what this tree needs
        max_depth: 64,
        max_collection: 512,
        ..RealizeLimits::default()
    };
    let report = realize(&source, &serde_json::json!({}), limits);
    assert!(
        report.truncated,
        "a tree deeper than max_depth must truncate even when node count is fine \
         ({} nodes realized)",
        report.nodes
    );
    assert!(
        report.nodes < 100_000,
        "and it must stop well short of the node cap, or this proves nothing"
    );
}

#[test]
fn empty_nested_expansion_consumes_aggregate_work() {
    let source = "source movers sys.movers()\nstate show {shape: bool, initial: false}\nview root Panel {for a in movers key a.id {for b in movers key b.id {for c in movers key c.id {for d in movers key d.id {when show {Rule()}}}}}}";
    assert!(check_ui_l0_named("bounded", source).valid);
    let rows: Vec<_> = (0..128).map(|id| serde_json::json!({"id":id})).collect();
    let report = realize(
        source,
        &serde_json::json!({"movers":rows}),
        RealizeLimits {
            max_work: 100,
            ..Default::default()
        },
    );
    assert!(
        report.truncated,
        "empty expansion must exhaust work even without emitted nodes"
    );
    assert_eq!(report.nodes, 1);
    let small = realize(
        source,
        &serde_json::json!({"movers":[{"id":0}]}),
        RealizeLimits {
            max_work: 100,
            ..Default::default()
        },
    );
    assert!(!small.truncated);
    assert_eq!(small.nodes, 1);
}

/// §1.1 as a check rather than a paragraph: a card must have no way to state a
/// colour, a size in pixels, or a font. The principle survives the revert of the
/// lowering that was meant to implement it — a card naming roles rather than
/// appearance is right regardless of what consumes the result.
#[test]
fn no_role_accepts_presentation() {
    for (ctor, args) in catalog::CONSTRUCTORS {
        for (arg, _) in *args {
            assert!(
                !matches!(
                    *arg,
                    "color"
                        | "colour"
                        | "bg"
                        | "fill"
                        | "font"
                        | "font_size"
                        | "weight"
                        | "radius"
                        | "elevation"
                        | "shadow"
                        | "padding"
                        | "margin"
                ),
                "{ctor}.{arg} is presentation; §1.1 says a card names roles and the theme \
                 decides appearance"
            );
        }
    }
}

// ─── reconciliation, applied ─────────────────────────────────────────────────

/// `patch_points` computes which SOURCES a change invalidates and then throws
/// that away, returning only the records to re-realize. Re-fetching is the
/// expensive half — realization is a tree walk over ~90 nodes, a source is a
/// network round trip — so the invalidation set is what a host actually needs.
#[test]
fn a_state_change_names_the_sources_that_must_be_refetched() {
    const CARD: &str = r#"
state city  { shape: text, initial: "" }
state units { shape: enum[c, f], initial: .c }
source place sys.geocode(name: state.city)
source now   sys.weather(lat: place.lat, lon: place.lon)
source moon  sys.moonphase()
view root Col { TextRow(text: place.name) TextValue(value: now.temp, unit: units) }
"#;

    // `city` feeds `place`, and `place` feeds `now` — the cascade must be
    // followed, or a host refetches a coordinate and reads a stale forecast.
    let stale = octoscript_ui_l0::stale_sources(CARD, &["city"]);
    assert!(stale.contains(&"place".to_string()), "{stale:?}");
    assert!(
        stale.contains(&"now".to_string()),
        "the cascade must be followed: {stale:?}"
    );
    assert!(
        !stale.contains(&"moon".to_string()),
        "the moon does not depend on the city: {stale:?}"
    );

    // A display-only unit change costs no fetch at all. This is the case the
    // whole mechanism exists for.
    assert!(
        octoscript_ui_l0::stale_sources(CARD, &["units"]).is_empty(),
        "changing a display unit must not refetch anything"
    );
}

/// The second half: realization reuses the subtrees a change cannot have
/// touched, instead of rebuilding the card.
#[test]
fn realization_reuses_the_records_a_change_did_not_touch() {
    const CARD: &str = r#"
state units { shape: enum[c, f], initial: .c }
source now  sys.weather(lat: 1.0, lon: 2.0)
source news sys.news(count: 1, fields: [title])
view root Col { temps headline }
view temps    Col { TextValue(value: now.temp, unit: units) }
view headline Col { TextRow(text: news.0.title) }
"#;
    let data = serde_json::json!({
        "now": {"temp": 21.0}, "news": [{"title": "unchanged"}], "units": "c"
    });

    let full = realize(CARD, &data, RealizeLimits::default());
    let before = full.root.expect("a tree");

    let patched = octoscript_ui_l0::realize_patch(
        CARD,
        &data,
        None,
        &before,
        &["units"],
        RealizeLimits::default(),
    );
    let after = patched.root.expect("a tree");

    assert_eq!(
        shape_signature(&before),
        shape_signature(&after),
        "a patch must produce the same tree as a full realize"
    );
    assert!(
        patched.reused > 0,
        "the headline reads no changed path and should have been reused"
    );
    assert!(
        patched.reused < patched.nodes,
        "and the temperature record must have been rebuilt, not reused"
    );
}

fn shape_signature(n: &octoscript_ui_l0::UiNode) -> String {
    let kids: Vec<String> = n.children.iter().map(shape_signature).collect();
    format!("{}[{}]", n.kind, kids.join(","))
}

/// §5.10.1's premise, on the real weather card rather than a synthetic one.
///
/// The argument there is that component-local state cannot simply be moved down
/// to the component kit, because L0 keeps deciding when a subtree is rebuilt and
/// would no longer know the state exists. That argument is only worth making if
/// the rebuild actually happens — so this asserts the premise, not the
/// conclusion: a source refresh really does replace the subtrees that read it.
///
/// If this ever goes green in the other direction — forecast rows surviving a
/// `week` refresh — then §5.10.1 is wrong and the move is cheaper than stated.
#[test]
fn a_source_refresh_replaces_the_subtrees_that_read_it() {
    let data = weather_data();
    let store = octoscript_ui_l0::InstanceStore::default();
    let limits = RealizeLimits::default();

    let before = octoscript_ui_l0::realize_with_state(WEATHER, &data, &store, limits)
        .root
        .expect("the reference card realizes");

    let patch = |changed: &str| {
        octoscript_ui_l0::realize_patch(WEATHER, &data, Some(&store), &before, &[changed], limits)
    };

    // `week` feeds the forecast rows, which is where `ForecastRow.expanded`
    // lives. Rebuilding them is what would discard a kit-owned flag.
    let week = patch("week");
    assert!(
        week.reused < week.nodes,
        "a week refresh must rebuild the records that read it, not reuse everything"
    );

    // The counterpart: a name no source or state declares dirties nothing, so
    // the whole tree carries over. Without this, the assertion above would also
    // pass for an implementation that never reuses anything at all.
    let untouched = patch("no_such_record");
    assert_eq!(
        untouched.reused, untouched.nodes,
        "a change touching no declared record must reuse the entire tree"
    );
}

/// The catalog described an interface these widgets abandoned. `AqiContour`
/// took `field`/`index`/`band` and `StockPlot` took `points`/`min`/`max` — but
/// both fetch their own data now, and the widget's own comment says why:
/// supplying the field meant sixteen scalar uniforms, and "that put a GPU
/// uniform layout into the authoring language — it is not a widget contract, it
/// is an ABI."
///
/// So a card names a LOCATION or a SERIES, and the arguments it names must
/// reach the widget.
#[test]
fn a_contour_carries_the_location_it_was_given() {
    let dsl = octoscript_ui_l0::makepad::lower(
        &realize(
            "source p sys.geocode(name: \"Kyoto\")\n\
             view root Col { AqiContour(lat: p.lat, lon: p.lon, span: 1.6) }",
            &serde_json::json!({"p": {"lat": 35.0, "lon": 135.7}}),
            RealizeLimits::default(),
        )
        .root
        .unwrap(),
    );
    assert!(dsl.contains("AqiContour"), "{dsl}");
    for v in ["35", "135.7", "1.6"] {
        assert!(
            dsl.contains(v),
            "the bound {v} must reach the widget, or it samples the wrong place: {dsl}"
        );
    }
}

#[test]
fn a_plot_carries_the_series_it_was_given() {
    let dsl = octoscript_ui_l0::makepad::lower(
        &realize(
            "state sel { shape: text, initial: \"NVDA\" }\n\
             view root Col { StockPlot(symbol: sel, range: .money) }",
            &serde_json::json!({}),
            RealizeLimits::default(),
        )
        .root
        .unwrap(),
    );
    assert!(dsl.contains("StockPlot"), "{dsl}");
    assert!(
        dsl.contains("NVDA"),
        "the symbol must reach the widget, or it plots nothing: {dsl}"
    );
}

// ─── DSL lowering, verified against the real consumer ────────────────────────

/// A previous attempt at this was reverted because it asserted a contract with
/// `octoscript-render` that nobody had opened: five of 23 kinds did not exist, the
/// consumer reads `variant` where it emitted `role`, and its `Attrs` is a fixed
/// 37-field struct rather than an open bag, so about twenty attributes were
/// unread. All of that was one `grep` away.
///
/// So this lowering emits ONLY what the consumer accepts, and refuses loudly
/// where it cannot. The constraints below were found by running
/// `octoscript_render::build`, not by reading about it:
///
/// - the root must be a literal object; a function call there fails
/// - an unknown kind at the root rejects the document, and as a child is
///   dropped without a diagnostic
#[test]
fn dsl_lowering_emits_only_kinds_the_consumer_accepts() {
    const ACCEPTED: &[&str] = &[
        "column",
        "row",
        "stack",
        "scroll",
        "list",
        "grid",
        "text",
        "image",
        "button",
        "card",
        "listitem",
        "divider",
        "spacer",
        "chip",
        "weathericon",
    ];
    let dsl = octoscript_ui_l0::lower_dsl(
        &realize(NEWS, &news_fixture(), RealizeLimits::default())
            .root
            .unwrap(),
    );
    for kind in dsl
        .split("{t: \"")
        .skip(1)
        .filter_map(|s| s.split('"').next())
    {
        assert!(
            ACCEPTED.contains(&kind),
            "{kind:?} is not in octoscript-render's tag table; as a child it would be \
             dropped without a diagnostic and as a root it would reject the card"
        );
    }
}

/// A role with no accepted kind must produce a DIAGNOSTIC, not a node the
/// consumer silently discards. Silent dropping is how a card renders with four
/// of its five visualisations missing and still looks finished.
#[test]
fn an_unmappable_role_is_reported_rather_than_dropped() {
    let report = octoscript_ui_l0::lower_dsl_checked(
        &realize(
            "source w sys.weather(lat: 1.0, lon: 2.0)\n\
             view root Col { TempBar(lo: w.lo, hi: w.hi, min: w.min, max: w.max) }",
            &serde_json::json!({"w": {"lo": 1.0, "hi": 2.0, "min": 0.0, "max": 3.0}}),
            RealizeLimits::default(),
        )
        .root
        .unwrap(),
    );
    assert!(
        !report.diagnostics.is_empty(),
        "TempBar has no kind in octoscript-render, so lowering it must say so"
    );
    assert!(
        report.diagnostics[0].message.contains("TempBar"),
        "{:#?}",
        report.diagnostics
    );
}

fn news_fixture() -> serde_json::Value {
    serde_json::json!({
        "lead": [{"id": "a", "title": "T", "author": "A", "points": 1, "comments": 2}],
        "feed": [{"id": "b", "title": "U", "author": "B", "points": 3}],
        "article": {}, "selected": "", "env": {"locale": {}}
    })
}

// ─── the three defects the state-ownership review found ──────────────────────
// Each was recorded in §8 of the profile as "found and not fixed". These are
// the tests that make them fixable rather than merely known.

/// §5.3 keeps card state out of a component, and a name collision walks around
/// the check: `check_path` asks `scope.knows(path)` BEFORE asking whether the
/// path names forbidden card state, so a source with the same name satisfies
/// the first question and the second is never reached.
///
/// The component ends up reading the SOURCE, which §5.3 permits — so this is
/// not a confinement breach and card state does not leak. It is worse in a
/// quieter way: the card says `state selected` and `source selected` and the
/// runtime silently picks one. Two namespaces that must be disjoint are not
/// checked for overlap at all.
#[test]
fn a_source_may_not_share_a_name_with_card_state() {
    const CARD: &str = r#"
source selected sys.locale()
state selected { shape: text, initial: "" }
view root TextTitle(text: selected)
"#;
    let report = check_ui_l0_named("t", CARD);
    assert!(
        !report.valid,
        "a source and a state sharing a name must be refused:\n{:#?}",
        report.diagnostics
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("selected")),
        "the diagnostic must name the colliding name:\n{:#?}",
        report.diagnostics
    );
}

/// A declared source nothing reads is a fetch the host performs for nothing.
///
/// `stock.card` shipped one and no test noticed: `series` became unread the
/// moment `StockPlot` started fetching its own data, and the card kept asking
/// for it. On device that is a network round trip, a parse, and a cache entry
/// per refresh, for data that reaches no pixel.
#[test]
fn a_source_nothing_reads_is_reported() {
    const CARD: &str = r#"
source used   sys.locale()
source unused sys.movers(count: 1, fields: [ticker])
view root TextTitle(text: used.lang)
"#;
    let report = check_ui_l0_named("t", CARD);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unused")),
        "an unread source must be reported:\n{:#?}",
        report.diagnostics
    );
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("used.")
                || (d.message.contains("used") && !d.message.contains("unused"))),
        "and a source that IS read must not be:\n{:#?}",
        report.diagnostics
    );
}

/// §5.9's invalidation story exists in pieces that nothing joins.
///
/// `stale_sources` computes what a change invalidates and `source_plan` lists
/// what to request, and both are called only from tests. `dispatch_with_data`
/// returns a bare `bool` and discards WHICH fields it wrote — so a host holding
/// the result cannot tell what to refetch, and the stock card's detail view
/// works only because the test data already contains a quote it never asked
/// for.
#[test]
fn a_dispatch_reports_what_it_invalidated() {
    let data = serde_json::json!({
        "movers": [{ "ticker": "NVDA", "name": "Nvidia", "last": 1.0, "change": 0.5, "pct": 2.0 }],
        "quote": {}, "selected": "", "range": "m1", "env": { "locale": {} },
        "copy": { "movers": "Top Movers" }
    });
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let outcome = octoscript_ui_l0::dispatch_reporting(
        STOCK,
        &mut store,
        "root",
        "open_quote",
        Some(&serde_json::Value::String("NVDA".into())),
        &data,
    );
    assert!(outcome.applied, "the event applies");
    assert!(
        outcome.changed.iter().any(|f| f == "selected"),
        "it must report WHICH state it wrote: {:?}",
        outcome.changed
    );
    // `quote` and `series` both take `ticker: state.selected`, so both are now
    // stale. This is the fact a host needs and could not previously obtain.
    assert!(
        outcome.stale.iter().any(|s| s == "quote"),
        "and which sources that invalidates: {:?}",
        outcome.stale
    );
}

/// A layout decision must measure what is DRAWN, not what is emitted.
///
/// The two are the same string until a value goes live, and then they diverge
/// completely: `"$" + sys.stock("NVDA", "price")` is 33 characters of source
/// that render as six. Sizing the hero by counting the emitted form dropped it
/// from 40pt to 24pt and shifted the whole card up — a layout bug with no
/// layout cause, and invisible to every test that only checked the text.
#[test]
fn a_hero_is_sized_by_what_it_draws_not_by_what_it_emits() {
    let data = serde_json::json!({
        "movers": [], "selected": "NVDA", "range": "m1", "env": {"locale":{}},
        "quote": {"name":"NVIDIA","last":184.2,"change":3.1,"pct":1.7,"open":181.0,
                  "high":185.6,"low":180.2,"volume":41200000.0,
                  "mktcap":4520000000000.0,"pe":58.3},
        "copy": {"movers":"Top Movers","open":"Open","high":"High","low":"Low",
                 "volume":"Volume","mktcap":"Mkt Cap","pe":"P/E"}
    });
    let report = realize(STOCK, &data, RealizeLimits::default());
    let dsl = makepad::lower(&report.root.expect("root"));

    let hero = dsl
        .lines()
        .find(|l| l.contains("TextHero"))
        .unwrap_or_else(|| panic!("no hero:\n{dsl}"));

    // The hero IS live — otherwise this test would pass for the wrong reason,
    // since a seeded hero measures its own text correctly by construction.
    assert!(
        hero.contains("sys.stock"),
        "the hero must be live for this test to mean anything:\n{hero}"
    );
    // "$184.20" is 7 glyphs, which is the 28pt bucket. The emitted expression is
    // 33 characters, which is the 17pt one. The two numbers moved when the theme
    // came down to 70%; what the test asserts did not — the hero must be sized by
    // what it DRAWS, and the gap between the buckets is what proves it.
    assert!(
        hero.contains("font_size: 28"),
        "sized by the drawn value (7 glyphs -> 28pt), not the emitted 33:\n{hero}"
    );
}

/// A decoration applies to `text:`, not only to `value:`.
///
/// FOUND BY THE FIRST CARD OUTSIDE THE CORPUS. `activity.card` writes
/// `TextCaption(text: p.distance, suffix: copy.park_why)` — the distance is
/// already a formatted string from the host, so it arrives as text — and both
/// lowerings dropped the suffix on the floor. Every row read "300 m" where the
/// card said "300 m away · quiet green space".
///
/// Nothing caught it because every use of `suffix` in weather, news and stock
/// pairs it with `value:`, and that path applies the decoration. The catalog
/// declared `suffix` on the role and one of its two argument paths ignored it —
/// "specified but not retained", once more.
#[test]
fn a_suffix_applies_to_text_as_well_as_value() {
    const CARD: &str = r#"
copy why { class: vocabulary, en: "away" }
source parks sys.places(lat: 1.0, lon: 2.0, category: "park", count: 1, fields: [id, name, distance])
view root Surface { for p, i in parks key p.id { TextCaption(text: p.distance, suffix: copy.why) } }
"#;
    let data = serde_json::json!({
        "parks": [{"id": "a", "name": "N", "distance": "300 m"}],
        "env": {"locale": {"lang": "en"}}
    });
    let report = realize(CARD, &data, RealizeLimits::default());
    assert!(report.diagnostics.is_empty(), "{:#?}", report.diagnostics);
    let root = report.root.expect("root");

    for (name, dsl) in [
        ("makepad", makepad::lower(&root)),
        ("kit", octoscript_ui_l0::kit::lower(&root)),
    ] {
        // `sys.places` is answered live now, so the caption is the CALL plus
        // the suffix rather than the seeded literal plus the suffix. What this
        // test guards is that the suffix survives on a text-valued caption at
        // all — it was silently dropped there while working on `value:`.
        assert!(
            dsl.contains(r#"+ " away""#),
            "{name} dropped the suffix from a text-valued caption:\n{dsl}"
        );
    }
}

/// The boundary §1.0 draws, asserted rather than described.
///
/// `nav`'s shipping card is a program: 30 `let` bindings, 83 assignments, 128
/// conditionals, 606 arithmetic operators and a `fn tick()` that recomputes
/// route geometry every frame. The classifier must place it at L2 and refuse it,
/// and it must do so for the RIGHT reason — a profile that accepted it, or that
/// rejected it as unparseable, would be wrong in opposite directions.
#[test]
fn a_card_that_computes_is_classified_beyond_l0() {
    const NAV: &str = include_str!("fixtures/nav-excerpt.octoscript");
    let report = check_ui_l0_named("nav", NAV);
    assert!(!report.valid, "a program must not pass as a card");
    assert_eq!(
        report.level,
        Level::L2,
        "`fn` and `let` put this at L2, not merely 'invalid'"
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("`let`")),
        "the diagnostic must name what is beyond L0: {:#?}",
        report.diagnostics
    );
}

/// And `activity` — the first card L0 was NOT designed against — is L0.
///
/// Weather, news and stock shaped every role and capability the profile has, so
/// their acceptance proves little. This one came from a spec written for another
/// framework and needed one catalog entry.
#[test]
fn a_card_from_outside_the_corpus_is_admitted() {
    const ACTIVITY: &str = include_str!("fixtures/activity.card");
    let report = check_ui_l0_named("activity", ACTIVITY);
    assert!(
        report.valid,
        "activity must be admissible: {:#?}",
        report.diagnostics
    );
    assert_eq!(report.level, Level::L0);
}

/// `Map` and `Field` — the two roles nav needed — are admissible and behave.
///
/// Added after looking at what the shipping nav card actually does with its map:
/// it calls `sys.navroute` itself, hand-builds a marker string, and pushes both
/// in through imperative setters. That is the card doing the WIDGET's job, and
/// the identical mistake `AqiContour` and `StockPlot` were corrected for. `Map`
/// takes a TRIP; the widget fetches the route.
///
/// `Field` is the other half: a card with no way to receive typed text cannot
/// have a search box. The typed value goes to declared state through a declared
/// transition, so it arrives by the same total path a tap does.
#[test]
fn a_card_can_name_a_trip_and_take_typed_text() {
    const CARD: &str = r#"
state dest  { shape: text, initial: "" }
state query { shape: text, initial: "" }
event set_dest { dest: set($value) }
source place sys.geocode(name: query)
copy find { class: vocabulary, en: "Where to?" }
view root Surface {
  Field(text: query, placeholder: copy.find, on_commit: set_dest)
  Map(mode: .drive, from: place, to: place, zoom: 16)
}
"#;
    let report = check_ui_l0_named("trip", CARD);
    assert!(report.valid, "{:#?}", report.diagnostics);
    assert_eq!(report.level, Level::L0, "neither role needs an expression");

    // A mode outside the declared set is refused — the token set is closed, so a
    // card cannot invent a camera behaviour the widget has no answer for.
    let bad = CARD.replace("mode: .drive", "mode: .helicopter");
    assert!(
        !check_ui_l0_named("trip", &bad).valid,
        "an uncatalogued map mode must be refused"
    );

    // And the trip reaches the realized tree, so a backend can act on it.
    let data = serde_json::json!({
        "place": {"lat": 37.3, "lon": -121.9, "name": "San Jose"},
        "query": "", "dest": "", "env": {"locale": {"lang": "en"}}
    });
    let root = realize(CARD, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);
    assert!(
        dsl.contains("l0_unsupported(\"Map\")") || dsl.contains("l0_map"),
        "Map must reach the lowering as itself or as a named marker:\n{dsl}"
    );
}

/// A declared `width` must REACH the kit — the profile's recurring defect.
///
/// The catalog admits `width` on five text roles, `check_ui_l0` accepted it, and
/// the kit lowering dropped it: every text role went through one arm that
/// emitted `f(body)` and nothing else. The news list asked for
/// `TextRow(text: story.title, width: .fill)` and got a non-wrapping row, so
/// every story title clipped mid-word — "A new approach to incremental c" — while
/// the same card through `makepad::lower` wrapped correctly.
///
/// That is what makes this class hard to see: the card is right, the profile
/// accepts it, one backend honours it, and the screen looks like a card whose
/// titles are simply short.
#[test]
fn a_declared_width_must_reach_the_kit() {
    const CARD: &str = r#"
# level: L0
# model: news
source feed sys.news(count: 2, fields: [title, points])
view root Surface {
  Panel {
    for s, i in feed key s.title {
      Row {
        TextRow(text: i, width: .rank)
        TextRow(text: s.title, width: .fill)
        TextCaption(value: s.points)
      }
    }
  }
}
"#;
    let data = serde_json::json!({
        "feed": [{"title": "A new approach to incremental compilation", "points": 288}]
    });
    let root = realize(CARD, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);

    // `.fill` is what lets a long headline wrap rather than run off the edge.
    assert!(
        dsl.contains("l0_wide(l0_row_text("),
        "width: .fill must wrap the role in the kit's filling helper:\n{dsl}"
    );
    // A fixed column passes the TOKEN — the theme owns how wide "rank" is, and a
    // lowering that emitted a pixel count would be styling.
    assert!(
        dsl.contains("l0_colw(l0_row_text(") && dsl.contains(", \"rank\")"),
        "a fixed-width token must reach the kit as the token:\n{dsl}"
    );
    // The caption declared no width, so it must not be wrapped at all: a
    // default restated on every node is a default nobody can change.
    let caption = dsl
        .lines()
        .find(|l| l.contains("l0_caption("))
        .expect("the caption lowers");
    assert!(
        !caption.contains("l0_wide") && !caption.contains("l0_colw"),
        "an undeclared width must emit no wrapper:\n{caption}"
    );
}

/// `align` and a numeric `cond` must reach the kit — the same defect twice more.
///
/// Both were found by looking at the screen rather than at the tests, which is
/// the point: the profile ACCEPTS an attribute it lists, so a lowering that
/// drops one produces a card that is valid, renders, and is wrong. The weather
/// card centres its header and draws a different icon per day; without these it
/// rendered hard left with seven identical suns, and nothing failed.
#[test]
fn align_and_a_numeric_condition_must_reach_the_kit() {
    const CARD: &str = r#"
# level: L0
# model: weather
source now  sys.weather(lat: 35, lon: 135, fields: [temp, cond])
source week sys.weather(lat: 35, lon: 135, days: 2, fields: [dayname, cond])
view root Surface {
  Col(align: .center) {
    WeatherIcon(cond: now.cond, size: .hero)
    TextHero(value: now.temp)
  }
  for d, i in week.days key d.dayname {
    Row(align: .center) {
      TextRow(text: d.dayname, width: .day)
      WeatherIcon(cond: d.cond, size: .row)
    }
  }
}
"#;
    let data = serde_json::json!({
        "now": {"temp": 18, "cond": 2},
        "week": {"days": [{"dayname": "Mon", "cond": 3}, {"dayname": "Tue", "cond": 0}]}
    });
    let root = realize(CARD, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);

    assert!(
        dsl.contains("l0_aligned(l0_col(") && dsl.contains(", \"center\")"),
        "align: .center must reach the kit:\n{dsl}"
    );
    // The hero's condition is LIVE. This asserted `l0_weathericon(2, "hero")` —
    // the realized number — which was right while no scalar consulted its
    // binding. A `cond` the backend can answer now lowers to the call, so the
    // icon is the code that is true when the card draws rather than the one the
    // host happened to seed. The size must still travel with it: that half was
    // the original defect and is unrelated to where the value comes from.
    assert!(
        dsl.contains("l0_weathericon(sys.weatherword(") && dsl.contains(", \"hero\")"),
        "the hero's cond must go live and keep its size:\n{dsl}"
    );
    // And the per-item conditions must DIFFER — one shared value for every row
    // is exactly what the bug produced, and a test that only checked "a number
    // arrives" would have passed on it.
    //
    // They are LIVE CALLS at their own row index now, not literals. This
    // asserted `l0_weathericon(3, "row")` and `l0_weathericon(0, "row")` — the
    // realized codes — which was right while a row's binding could not translate:
    // the collection's own name was left in the field handed to the helper, so
    // every forecast row fell back to its default and seven days drew one icon.
    for row in 0..2 {
        assert!(
            dsl.contains(&format!("daily.weather_code.{row}")),
            "row {row} must ask for its OWN day:\n{dsl}"
        );
    }
}

/// The nav card §1.0 said to write instead of argue about.
///
/// The shipping trip planner is 664 lines of Octoscript DSL and classifies at L2.
/// This is the same screen — origin, destination, live search results, route and
/// ETA — in 54 lines of L0, and it is admitted.
///
/// That settles the question the earlier §1.0 got wrong. nav's complexity was
/// mostly compensation: a `tick()` re-resolving values because a top-level `let`
/// freezes before the fetch lands, a hand-built URL parameter, a `-9999` sentinel
/// meaning loading *or* failed, and a polyline the card fetched and pushed into
/// the widget. Declared sources, `$state`, source arguments and a `Map` that
/// takes a trip remove all four.
#[test]
fn the_nav_trip_planner_is_expressible_at_l0() {
    const NAV: &str = include_str!("fixtures/nav.card");
    let report = check_ui_l0_named("nav", NAV);
    assert!(report.valid, "{:#?}", report.diagnostics);
    assert_eq!(report.level, Level::L0);

    // It must actually use the two roles that made it possible — otherwise this
    // passes for a card that quietly dropped the map and the search box.
    assert!(NAV.contains("Map(mode:"), "the card must name a trip");
    assert!(NAV.contains("Field(text:"), "the card must take typed text");

    // Every requirement of the shipping app that is the CARD's to meet.
    //
    // The bound below is only worth anything next to this list: a small card that
    // does less is not the claim. These are R4.3 (a stop the route goes through),
    // R6.2 (per-leg times), R7.1 (mode chips), R8.2 (turn guidance) and R2.5 (the
    // drive screen) — each a thing the 54-line version did not do.
    for (what, needle) in [
        ("a stop the trip routes through", "via: [stop_place"),
        ("per-leg times", "source leg_a"),
        ("travel modes", "mode: state.mode"),
        ("mode chips", "active: mode == .walk"),
        ("turn guidance", "step.instruction"),
        ("the drive screen", "when screen == .drive"),
    ] {
        assert!(NAV.contains(needle), "the card must have {what}");
    }

    // And it must stay SMALL. The claim is not merely that L0 can express this
    // screen but that most of the original was working around missing machinery —
    // a 600-line L0 card would disprove that as surely as a rejection would.
    //
    // The bound was 100 and is 200. The card grew from 54 lines by GAINING function,
    // not by working around anything: a travel mode, a waypoint the route passes
    // through, per-leg times, turn-by-turn, and a preview screen. Each cost
    // declarations rather than machinery — a stop is two route sources because a
    // source's arguments are fixed at declaration, so a trip with one is a different
    // trip and the card says so. That is the price of a total form and it is
    // visible, which is the point.
    //
    // It is 230, for an origin that defaults to the device (R11.3): two route
    // sources, a step source and eight guarded branches, because a source arguments
    // are fixed at declaration and "from a place you named" is a different trip from
    // "from here". It went to 260 and back to 200 twice before that, for the same
    // feature written two ways that could not work — the bound follows the feature,
    // or it measures nothing.
    //
    // The comparison it exists to make: 664 lines at L2 against 242 here, at close
    // to the same function. If an increment ever needs 400, that is the signal to add
    // machinery instead of declarations — this whole exercise rests on the original
    // being mostly compensation, and a card that grew like the original did would be
    // evidence against it.
    let lines = NAV
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .count();
    // 300, RAISED FROM 250, and the raise is recorded rather than quietly applied.
    //
    // What bought the 44 lines: both endpoints became tappable rows that open a find
    // state, because a permanently-live `Field` cannot be focused on this renderer
    // and both endpoints were therefore inert. That is a capability the card did not
    // have, not a refactor — and it is the shape the L2 card uses, so the comparison
    // this number exists to make is still like for like: 664 lines there against 286
    // here, both with reachable endpoints.
    //
    // The cost is duplication rather than machinery: each endpoint states its own
    // edited and resting rows, and its own pick list. A `component` taking the label,
    // the value and the two events would collapse all four into one definition used
    // twice, which is what §5 is for and is the way back under 250. The threshold the
    // comment above names is 400 — the point at which declarations stop being the
    // cheaper answer — and this is well inside it.
    assert!(
        lines < 300,
        "the point is that it is small; this is {lines} lines"
    );
}

/// A source answered by the backend must survive a loop.
///
/// Inside a `for`, a path is rooted at the BINDER — `m.ticker`, not
/// `movers.0.ticker` — so the binding logic did not recognise it and every row
/// of the stock list fell back to the seeded value while the detail view beside
/// it went live. On screen that reads as a stale list, not as a missing feature.
///
/// The loop frame records which collection it iterates and at what index, which
/// is what lets the lowering rewrite the path and emit the call.
#[test]
fn a_live_source_survives_a_loop() {
    let data = serde_json::json!({
        "movers": [{ "ticker": "NVDA", "name": "Nvidia", "last": 1.0, "change": 0.5, "pct": 2.0 },
                   { "ticker": "AAPL", "name": "Apple", "last": 2.0, "change": -0.5, "pct": -1.0 }],
        "quote": {}, "selected": "", "range": "m1", "env": { "locale": {} },
        "copy": { "movers": "Top Movers" }
    });
    let root = realize(STOCK, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);

    // Row 0 and row 1 must each call for their OWN index — one call reused, or
    // an index that does not advance, is the failure this catches.
    assert!(
        dsl.contains(r#"sys.movers(0, "symbol", "")"#),
        "the first row must be live:\n{dsl}"
    );
    assert!(
        dsl.contains(r#"sys.movers(1, "symbol", "")"#),
        "and the second must ask for index 1:\n{dsl}"
    );
    // The seeded tickers must be GONE, or the card shows a stale value beside a
    // live one and nothing says which is which.
    assert!(
        !dsl.contains("\"NVDA\"") && !dsl.contains("\"AAPL\""),
        "a live call must replace the seeded literal:\n{dsl}"
    );
}

/// A read must name a field the card ASKED FOR.
///
/// A source answers `fields:` and nothing else, so a view that names anything
/// outside that list renders an em dash — which on screen is indistinguishable
/// from a value still in flight. Two ways to get there and both used to pass:
/// misspell a field, or read one that is real but was never requested.
///
/// This needs no per-capability schema. The card already says what it needs;
/// nothing compared the two halves of the card against each other.
#[test]
fn a_read_must_name_a_field_the_source_was_asked_for() {
    let card = |body: &str| {
        format!(
            "# level: L0\n# model: stock\n\
             source movers sys.movers(count: 3, fields: [ticker, name, last])\n\
             view root Surface {{\n  for m, i in movers key m.ticker {{\n    Row {{ {body} }}\n  }}\n}}\n"
        )
    };
    let why = |src: &str| -> String {
        check_ui_l0_named("card", src)
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    };

    // The honest case still passes.
    assert!(
        check_ui_l0_named("card", &card("TextRow(text: m.ticker)")).valid,
        "a requested field must be readable"
    );

    // A typo. The field does not exist anywhere.
    let typo = why(&card("TextRow(text: m.tickr)"));
    assert!(
        typo.contains("tickr") && typo.contains("ticker"),
        "a misspelled field must be refused and the alternatives offered: {typo}"
    );

    // Real field, never requested — the subtler half, and the one a spell-check
    // would miss. `sys.movers` can answer `marketcap`; this card did not ask.
    let unasked = why(&card("TextValue(value: m.marketcap)"));
    assert!(
        unasked.contains("marketcap"),
        "a field the card never requested must be refused: {unasked}"
    );

    // An INDEX is not a field. `lead.0.title` takes the first story and reads
    // its title, and treating `0` as a field rejected every indexed read in the
    // news card — a false positive that would have made the rule unshippable.
    const INDEXED: &str = "# level: L0\n# model: news\n\
        source lead sys.news(count: 1, fields: [title, author])\n\
        view root Surface { TextTitle(text: lead.0.title) }\n";
    assert!(
        check_ui_l0_named("card", INDEXED).valid,
        "an indexed read must survive: {}",
        why(INDEXED)
    );

    // A source that takes no field list is not checked as if it had an empty
    // one — `sys.locale` has no `fields:` argument at all.
    const NO_FIELDS: &str = "# level: L0\n# model: weather\n\
        source env.locale sys.locale()\n\
        state u { shape: text, initial: env.locale.temp_unit }\n\
        view root Surface { TextRow(text: u) }\n";
    assert!(
        check_ui_l0_named("card", NO_FIELDS).valid,
        "a capability with no field list must stay unchecked: {}",
        why(NO_FIELDS)
    );
}

/// §5.12: a transition may target a source backed by a durable store.
///
/// The card that motivates it — tap a mover, keep it. Every earlier attempt at
/// this had to put the list in card state, where `check_card` accepted it,
/// dispatch reported success, and the list rendered empty: `set($value)` wrote a
/// string into a collection-shaped cell. Worse, a card is regenerated per
/// request, so even a working list-shaped cell would have been empty the next
/// time the user asked — which is why this is a source and not a longer-lived
/// kind of state.
#[test]
fn a_durable_collection_is_written_through_a_source() {
    const CARD: &str = r#"
# level: L0
# model: stock
source movers sys.movers(count: 5, fields: [ticker, name, last])
source watch  sys.watchlist(fields: [ticker, name, last, pct])

event keep { watch: append($value) }
event drop { watch: remove($value) }

view root Surface {
  Panel {
    for m, i in movers key m.ticker {
      Row(on_tap: keep, value: m.ticker) { TextRow(text: m.ticker) }
    }
  }
  Panel {
    for w, i in watch key w.ticker {
      Row(on_tap: drop, value: w.ticker) { TextRow(text: w.ticker) }
    }
  }
}
"#;
    let why = |src: &str| -> String {
        check_ui_l0_named("card", src)
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    };
    assert!(
        check_ui_l0_named("card", CARD).valid,
        "a watchlist card must be admitted: {}",
        why(CARD)
    );

    // A source NOT backed by a store is read-only. Binding a fetch is not
    // permission to write it, and the default has to be refusal.
    let readonly = CARD.replace("watch: append($value)", "movers: append($value)");
    let msg = why(&readonly);
    assert!(
        msg.contains("read-only") && msg.contains("sys.movers"),
        "writing a fetched source must be refused: {msg}"
    );

    // A store-backed capability accepts only the transitions it declares.
    // `sys.watchlist` is a list — `toggle` is meaningless on one.
    let wrong_verb = CARD.replace("watch: append($value)", "watch: toggle");
    let msg = why(&wrong_verb);
    assert!(
        msg.contains("does not accept") && msg.contains("append"),
        "an unaccepted transition must be refused and the accepted ones named: {msg}"
    );

    // And the reverse: a collection form on a STATE is refused with the reason,
    // not reported as a malformed `set`.
    const ON_STATE: &str = r#"
# level: L0
# model: stock
source movers sys.movers(count: 3, fields: [ticker])
state watch { shape: collection, initial: [] }
event keep { watch: append($value) }
view root Surface {
  for m, i in movers key m.ticker { Row(on_tap: keep, value: m.ticker) { TextRow(text: m.ticker) } }
}
"#;
    let msg = why(ON_STATE);
    assert!(
        msg.contains("durable collection") && msg.contains("source"),
        "a collection form on card state must say where the list belongs: {msg}"
    );

    // `remove` takes the payload and nothing else. A predicate here would be an
    // expression, which is the one thing L0 does not have.
    let predicate = CARD.replace("watch: remove($value)", "watch: remove(w.pct < 0)");
    assert!(
        !check_ui_l0_named("card", &predicate).valid,
        "remove must not accept a predicate"
    );
}

/// A tap on a durable collection reports the write and invalidates the source.
///
/// The write is REPORTED, never performed — the same separation `source_plan`
/// keeps. L0 has no store and must not acquire one: the host owns durability,
/// and a card that could write directly would be a card that could persist a
/// fact (§4).
#[test]
fn a_durable_write_is_reported_and_makes_its_source_stale() {
    const CARD: &str = r#"
# level: L0
# model: stock
source movers sys.movers(count: 5, fields: [ticker, name])
source watch  sys.watchlist(fields: [ticker, name, last])
event keep { watch: append($value) }
view root Surface {
  for m, i in movers key m.ticker {
    Row(on_tap: keep, value: m.ticker) { TextRow(text: m.ticker) }
  }
  for w, i in watch key w.ticker { TextRow(text: w.ticker) }
}
"#;
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let out = octoscript_ui_l0::dispatch_reporting(
        CARD,
        &mut store,
        "root",
        "keep",
        Some(&serde_json::Value::String("NVDA".into())),
        &serde_json::Value::Null,
    );

    assert!(out.applied, "a durable write is an applied event");
    assert_eq!(out.writes.len(), 1, "exactly one write: {:?}", out.writes);
    let w = &out.writes[0];
    assert_eq!((w.op.as_str(), w.value.as_str()), ("append", "NVDA"));
    assert_eq!(
        (w.source.as_str(), w.helper.as_str()),
        ("watch", "sys.watchlist"),
        "the host needs both the bound name and the capability behind it"
    );

    // Nothing went into the card's own store. If it had, the list would be
    // per-card again and every regenerated card would start empty.
    assert!(
        out.changed.is_empty(),
        "a durable write writes no cell: {:?}",
        out.changed
    );

    // And the source must be refetched, or the row the user just added does not
    // appear until something else happens to invalidate it.
    assert!(
        out.stale.contains(&"watch".to_string()),
        "the written source must go stale: {:?}",
        out.stale
    );
}

/// §5.12 in the weather card: looking is not keeping. Tapping a result only
/// PREVIEWS (a state write, no store write); the explicit Add is the one
/// composed event that stores durably beside re-pointing; the explicit close
/// stores nothing. Driven as the user drives it, asserting what MOVED.
#[test]
fn previewing_stores_nothing_and_adding_stores_once() {
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let dispatch = |store: &mut octoscript_ui_l0::InstanceStore, event: &str, payload: &str| {
        octoscript_ui_l0::dispatch_reporting(
            WEATHER,
            store,
            "root",
            event,
            Some(&serde_json::Value::String(payload.into())),
            &serde_json::Value::Null,
        )
    };

    // Tap "add a city": the row becomes a Field and the query opens empty.
    let out = dispatch(&mut store, "add_city", "1");
    assert!(out.applied, "add_city must apply");
    assert_eq!(out.changed, vec!["editing"], "the editor opens: {out:?}");
    assert!(out.writes.is_empty(), "opening the editor writes no store");

    // Type: the query moves, and the search source parameterised by it goes
    // stale — that is what makes results-as-you-type refetch.
    let out = dispatch(&mut store, "typing", "berk");
    assert_eq!(
        out.changed,
        vec!["query"],
        "typing writes the query: {out:?}"
    );
    assert!(
        out.stale.contains(&"found".to_string()),
        "the search must refetch: {:?}",
        out.stale
    );

    // Tap a result: the card re-points and NOTHING is stored — the whole
    // point of the redesign. A preview that appended was the bug class where
    // browsing the search results polluted the record.
    let city = "Berkeley, California, United States";
    let out = dispatch(&mut store, "preview", city);
    assert!(out.applied, "preview must apply");
    assert_eq!(out.changed, vec!["city"], "preview moves the city: {out:?}");
    assert!(out.writes.is_empty(), "looking is not keeping: {out:?}");
    assert!(out.stale.contains(&"place".to_string()), "{:?}", out.stale);

    // Close without adding: the editor and query reset, and still no write.
    let out = dispatch(&mut store, "close_add", "1");
    assert!(out.applied, "close_add must apply");
    assert_eq!(
        out.changed,
        vec!["editing", "query"],
        "closing resets the editor: {out:?}"
    );
    assert!(out.writes.is_empty(), "closing adds nothing: {out:?}");

    // Reopen and ADD: the one composed event — the city on screen, the
    // durable append, the query cleared, the editor closed.
    dispatch(&mut store, "add_city", "1");
    dispatch(&mut store, "typing", "berk");
    let out = dispatch(&mut store, "confirm_add", city);
    assert!(out.applied, "the composed event must apply");
    assert_eq!(
        out.changed,
        vec!["query", "editing"],
        "city was already previewed to this value; the reset writes commit: {out:?}"
    );
    assert_eq!(out.writes.len(), 1, "exactly one durable write: {out:?}");
    let w = &out.writes[0];
    assert_eq!(
        (
            w.source.as_str(),
            w.helper.as_str(),
            w.op.as_str(),
            w.value.as_str()
        ),
        ("cities", "sys.cities", "append", city),
        "the host is told the bound name, the capability, the op and the value"
    );
    assert!(out.stale.contains(&"cities".to_string()), "{:?}", out.stale);
    assert_eq!(
        store.get(octoscript_ui_l0::CARD_STATE_KEY, "city"),
        Some(serde_json::Value::String(city.into())).as_ref(),
        "the card is looking at the added city"
    );
}

/// `signed_money` reaches the screen live, beside its own percentage.
///
/// The two describe ONE move. The percentage was live and the money was not, so
/// the stock header rendered a fixture's `+$3.10` next to a live `+3.55%` —
/// numbers that cannot both be true, on the same line, in the same colour.
///
/// The cause was a formatting one: `signed_money` puts the currency inside the
/// sign (`+$7.13`) and a lowering can only PREPEND, so `"$" + "+7.13"` would
/// have rendered `$+7.13`. Giving up and keeping the seeded value looked like
/// the safe choice and was the wrong one — a stale number that still looks live
/// is exactly what §4 exists to prevent.
#[test]
fn a_signed_money_change_is_live_not_seeded() {
    let data = serde_json::json!({
        "movers": [], "selected": "NVDA", "range": "m1", "env": {"locale":{}},
        "quote": {"name":"NVIDIA","last":184.2,"change":3.1,"pct":1.7,"open":181.0,
                  "high":185.6,"low":180.2,"volume":41200000.0,
                  "mktcap":4520000000000.0,"pe":58.3},
        "copy": {"movers":"Top Movers","open":"Open","high":"High","low":"Low",
                 "volume":"Volume","mktcap":"Mkt Cap","pe":"P/E"}
    });
    let report = realize(STOCK, &data, RealizeLimits::default());
    let dsl = makepad::lower(&report.root.expect("root"));

    assert!(
        dsl.contains(r#"sys.stock("NVDA", "changemoney")"#),
        "the money change must be a live call:\n{dsl}"
    );
    // And nothing prepends a second currency symbol — the helper already put it
    // where it belongs.
    assert!(
        !dsl.contains(r#""$" + sys.stock("NVDA", "changemoney")"#),
        "the sign is inside the symbol; a prefix would render `$+7.13`:\n{dsl}"
    );
    // The seeded figure must be gone rather than sitting beside the live one.
    assert!(
        !dsl.contains("+$3.10"),
        "the seeded money change must not survive:\n{dsl}"
    );
    // Its percentage stays live too — a regression that stopped emitting calls
    // entirely would otherwise satisfy the assertions above.
    assert!(
        dsl.contains(r#"sys.stock("NVDA", "changepct")"#),
        "the percentage beside it must stay live:\n{dsl}"
    );
}

/// A `format:` survives the TICK, not just the first draw.
///
/// The kit's tick stamp (`l0_live`) composed only glyph/unit/suffix around the
/// call, never the `format:` — so every `.money` price drew as `$184.20` and
/// then lost its `$` on the first tick; a `.signed_money` change ticked the
/// raw `change` field the changemoney redirect exists to avoid; and a
/// `.compact` value, which cannot go live at all, was stamped with the raw
/// call, so the tick overwrote "41.2M" with 41200000. Found in review.
///
/// Differential against the DRAWN form: the stamp must quote exactly what
/// `live_valued` emitted, and must be absent exactly where the draw kept the
/// seeded value. (Inside the stamp the call is debug-quoted, so its quotes
/// appear escaped — that is what distinguishes stamp from draw below.)
#[test]
fn a_money_format_survives_the_tick() {
    let data = serde_json::json!({
        "movers": [], "selected": "NVDA", "range": "m1", "env": {"locale":{}},
        "quote": {"name":"NVIDIA","last":184.2,"change":3.1,"pct":1.7,"open":181.0,
                  "high":185.6,"low":180.2,"volume":41200000.0,
                  "mktcap":4520000000000.0,"pe":58.3},
        "copy": {"movers":"Top Movers","open":"Open","high":"High","low":"Low",
                 "volume":"Volume","mktcap":"Mkt Cap","pe":"P/E",
                 "loading":"Fetching the quote…","offline":"Can't reach the market feed"}
    });
    let report = realize(STOCK, &data, RealizeLimits::default());
    let dsl = octoscript_ui_l0::kit::lower(&report.root.expect("root"));

    // Baseline: the DRAW went live with the `$` prefix at all.
    assert!(
        dsl.contains(r#""$" + sys.stock("NVDA", "price")"#),
        "the drawn price must be live with its currency prefix:\n{dsl}"
    );
    // The stamp carries the same composition — `$` included.
    assert!(
        dsl.contains(r#"\"$\" + sys.stock(\"NVDA\", \"price\")"#),
        "the tick stamp must keep the `$` the draw had:\n{dsl}"
    );
    // `.signed_money` ticks the field that returns sign and symbol already
    // ordered — never the raw `change` the redirect exists to avoid.
    assert!(
        dsl.contains(r#"sys.stock(\"NVDA\", \"changemoney\")"#),
        "the tick stamp must keep the changemoney redirect:\n{dsl}"
    );
    assert!(
        !dsl.contains(r#"sys.stock(\"NVDA\", \"change\")"#),
        "a signed_money tick of the raw change field drops sign and symbol:\n{dsl}"
    );
    // `.compact` cannot go live: the draw kept the seeded "41.2M", so the tick
    // must not stamp the raw call and overwrite it with 41200000.
    assert!(
        dsl.contains("41.2M"),
        "the compact volume stays seeded and formatted:\n{dsl}"
    );
    assert!(
        !dsl.contains(r#"\"vol\""#) && !dsl.contains(r#"sys.stock("NVDA", "vol")"#),
        "no tick stamp may bypass a format the draw could not take live:\n{dsl}"
    );
}

/// A list factored into a COMPONENT still lowers to live calls, at its own index.
///
/// `for s in feed { StoryRow(story: s) }` is the idiomatic way to write a list,
/// and passing the binder into a component dropped the provenance that makes a
/// row live — so every row rendered the seeded blob (an em dash, on a live card)
/// while the lead story beside it, read directly, went live.
#[test]
fn a_list_through_a_component_stays_live() {
    let data = serde_json::json!({"env": {"locale": {"lang": "en"}}, "selected": "",
        "feed": [{"id":"a","title":"T","author":"x","points":1},
                 {"id":"b","title":"U","author":"y","points":2}]});
    let root = realize(NEWS, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);
    // `feed` declares offset: 1, so its first row is story 1 — not the lead.
    assert!(
        dsl.contains(r#"sys.news(1, "title")"#),
        "row 0 of the feed is story 1:\n{dsl}"
    );
    assert!(
        dsl.contains(r#"sys.news(2, "title")"#),
        "and row 1 is story 2:\n{dsl}"
    );
}

// ─────────────────────────────────────────────────────────────────────── L1 ──

/// An L1 card is ADMITTED when it declares its level.
///
/// §7: "a record needing a wider grammar is rejected until the level is
/// explicitly raised" — so raising it explicitly must work. Before this the
/// classifier could name L1 and never accept one.
#[test]
fn a_declared_l1_card_is_admitted() {
    const CARD: &str = r#"# level: L1
source quote sys.quote(ticker: state.sym, fields: [last])
state sym    { shape: text, initial: "NVDA" }
state shares { shape: number, initial: 10 }
view root Surface { TextHero(value: shares * quote.last) }
"#;
    let report = check_ui_l0_named("portfolio", CARD);
    assert!(report.valid, "must be admitted: {:#?}", report.diagnostics);
    assert_eq!(report.level, Level::L1);
}

/// The same card WITHOUT the header is still refused — escalation is never silent.
#[test]
fn the_same_card_at_l0_is_refused() {
    const CARD: &str = r#"# level: L0
source quote sys.quote(ticker: state.sym, fields: [last])
state sym    { shape: text, initial: "NVDA" }
state shares { shape: number, initial: 10 }
view root Surface { TextHero(value: shares * quote.last) }
"#;
    let report = check_ui_l0_named("portfolio", CARD);
    assert!(!report.valid, "arithmetic is not in L0");
}

/// §4 one level up: an expression must READ something. A coefficient is fine;
/// an expression made only of literals states a fact rather than computing one.
#[test]
fn an_expression_of_only_literals_is_refused() {
    const CARD: &str = r#"# level: L1
state shares { shape: number, initial: 10 }
view root Surface { TextHero(value: 1547 * 3.2) }
"#;
    let report = check_ui_l0_named("fabricator", CARD);
    assert!(
        !report.valid,
        "a literal-only expression is a fabricated fact"
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("must read a declared")),
        "{:#?}",
        report.diagnostics
    );
}

/// A coefficient IS allowed — `temp * 9 / 5 + 32` is a formula, not a fact.
#[test]
fn a_coefficient_is_not_a_fabricated_fact() {
    const CARD: &str = r#"# level: L1
source now sys.weather(lat: 1.0, lon: 2.0, fields: [temp])
view root Surface { TextHero(value: now.temp * 9 / 5 + 32) }
"#;
    let report = check_ui_l0_named("converter", CARD);
    assert!(report.valid, "{:#?}", report.diagnostics);
}

/// An expression over a LIVE source lowers to arithmetic the backend evaluates —
/// not to the number realization happened to compute from seeded data.
#[test]
fn an_expression_over_a_live_source_lowers_live() {
    const CARD: &str = r#"# level: L1
source quote sys.quote(ticker: state.sym, fields: [last])
state sym    { shape: text, initial: "NVDA" }
state shares { shape: number, initial: 10 }
view root Surface { TextHero(value: shares * quote.last) }
"#;
    let data = serde_json::json!({"sym": "NVDA", "shares": 10, "quote": {"last": 5.0}});
    let root = realize(CARD, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);
    assert!(
        dsl.contains("sys.stock(") && dsl.contains('*'),
        "the price must stay live and the multiply must reach the backend:\n{dsl}"
    );
}

/// A transition that writes the value already there is not a change.
///
/// A host rebuilds a card on any non-empty outcome, so reporting a no-op cost a
/// full realize, a full lowering, a full VM pass over every live call, and a
/// widget rebuild — to arrive at the identical screen. Tapping the chip that is
/// already selected is the ordinary way to hit it, and it happens on every card
/// with a range or filter row.
///
/// The comparison is against the EFFECTIVE current value — an earlier write in
/// the same batch, else the stored cell, else the declared initial — so
/// selecting what was already the initial is a no-op on the FIRST tap too,
/// before any cell exists to compare against.
#[test]
fn writing_the_value_already_there_is_not_a_change() {
    const CARD: &str = r#"
# level: L0
# model: t
state range { shape: enum[d1, w1], initial: .d1 }
event set_range { range: set($value) }
view root Surface {
  Chip(text: "1D", active: range == .d1, on_tap: set_range, value: "d1")
  Chip(text: "1W", active: range == .w1, on_tap: set_range, value: "w1")
}
"#;
    let data = serde_json::json!({ "env": { "locale": {} } });
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let tap = |store: &mut octoscript_ui_l0::InstanceStore, v: &str| {
        octoscript_ui_l0::dispatch_reporting(
            CARD,
            store,
            "root",
            "set_range",
            Some(&serde_json::Value::String(v.into())),
            &data,
        )
    };

    // `d1` IS the declared initial and no cell exists yet, so the first tap on
    // the already-selected chip changes nothing.
    let out = tap(&mut store, "d1");
    assert!(
        !out.applied && out.changed.is_empty(),
        "selecting the initial is a no-op: {out:?}"
    );
    // A real move still reports, and still invalidates.
    let out = tap(&mut store, "w1");
    assert!(
        out.applied && out.changed.iter().any(|c| c == "range"),
        "a real change must still report: {out:?}"
    );
    // And the same tap repeated is a no-op against the STORED cell.
    let out = tap(&mut store, "w1");
    assert!(
        !out.applied && out.changed.is_empty(),
        "re-tapping the selected chip is a no-op: {out:?}"
    );
    // The cell still holds `w1` — what changed is REPORTING, not storage. Asked
    // behaviourally rather than by reading the store, because card state lives
    // under its own fixed key (§5.1) and this is the property that matters:
    // going back to `d1` is a real change, which it could not be if the no-op
    // tap had reset or dropped the cell.
    let out = tap(&mut store, "d1");
    assert!(
        out.applied && out.changed.iter().any(|c| c == "range"),
        "the cell must still hold w1, so d1 is a move: {out:?}"
    );
}

/// Every path an operand reads is a dependency, however it is nested.
///
/// Reconciliation is only safe if this set is complete: over-approximating
/// re-realizes too much, under-approximating shows a stale screen, and the
/// second is the one that ships a wrong number. Two shapes were missed because
/// the scan matched operand forms one at a time — a comparison's RIGHT operand,
/// and a guard's right operand beyond a bare path.
#[test]
fn every_operand_a_record_reads_is_a_dependency() {
    // `active: a == b` reads `b`. It reported nothing, so a chip's selected
    // state never re-realized when the thing it compares against moved.
    const PREDICATE: &str = r#"
state a { shape: text, initial: "x" }
state b { shape: text, initial: "y" }
view root Surface { Chip(text: "c", active: a == b) }
"#;
    assert!(
        dirty_records(PREDICATE, &["b"]).contains(&"root".to_string()),
        "a comparison's right operand is read: {:?}",
        dirty_records(PREDICATE, &["b"])
    );

    // The same, one level up: a guard whose right operand is an expression.
    const GUARD_EXPR: &str = r#"# level: L1
state a { shape: number, initial: 1 }
state b { shape: number, initial: 2 }
view root Surface { when a == b * 2 { Rule() } }
"#;
    assert!(
        dirty_records(GUARD_EXPR, &["b"]).contains(&"root".to_string()),
        "a guard's expression operands are read: {:?}",
        dirty_records(GUARD_EXPR, &["b"])
    );

    // A binder still shadows — `it` is loop-local, not a card dependency.
    const LOOP: &str = r#"
source items sys.news(count: 3, fields: [title])
view root Surface { for it, i in items key it.title { TextRow(text: it.title) } }
"#;
    assert!(
        dirty_records(LOOP, &["it"]).is_empty(),
        "a loop binder is not a dependency"
    );
}

/// A state that reaches a view only THROUGH a source argument is a dependency
/// of that view.
///
/// `dirty_records` filtered on the changed names alone, so `sel` dirtied nothing
/// here: no record reads `sel`, they read `q`. That is the stock card's exact
/// shape — `sys.quote(ticker: state.selected)` — and the coarse function is the
/// one a host reaches for first. `patch_points` already followed the cascade,
/// and two functions answering one question differently is worse than either.
#[test]
fn a_state_a_source_reads_dirties_that_sources_readers() {
    const CARD: &str = r#"
source q sys.quote(ticker: sel, fields: [last])
state sel { shape: text, initial: "NVDA" }
view root Surface { TextHero(value: q.last) }
"#;
    assert!(
        dirty_records(CARD, &["sel"]).contains(&"root".to_string()),
        "changing the ticker must dirty the view that shows the quote: {:?}",
        dirty_records(CARD, &["sel"])
    );
    // And the two functions now agree about it.
    assert!(patch_points(CARD, &["sel"]).contains(&"root".to_string()));
}

/// A guard's right-hand side is checked like any other operand.
///
/// §9.8 recorded this as a defect: an expression there was matched only as a
/// bare path, so an undeclared name reached evaluation through the one position
/// that did not look inside its operand, and §4's must-read rule was skipped
/// with it.
#[test]
fn a_guards_right_operand_is_checked_like_any_other() {
    let why = |c: &str| {
        check_ui_l0_named("g", c)
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join("; ")
    };
    const UNDECLARED: &str = r#"# level: L1
state n { shape: number, initial: 2 }
view root Surface { when n == nosuch * 2 { Rule() } }
"#;
    assert!(
        why(UNDECLARED).contains("not a declared name"),
        "an undeclared name in a guard expression: {}",
        why(UNDECLARED)
    );
    const FABRICATED: &str = r#"# level: L1
state n { shape: number, initial: 2 }
view root Surface { when n == 3 * 4 { Rule() } }
"#;
    assert!(
        why(FABRICATED).contains("must read a declared"),
        "§4 applies in a guard too: {}",
        why(FABRICATED)
    );
    const HONEST: &str = r#"# level: L1
state n { shape: number, initial: 2 }
state m { shape: number, initial: 1 }
view root Surface { when n == m * 2 { Rule() } }
"#;
    assert!(check_ui_l0_named("g", HONEST).valid, "{}", why(HONEST));
}

/// A tint must be as live as the number it tints.
///
/// FOUND ON A PHONE, not in a test. The top-movers list drew four positive
/// rows and coloured two of them red: `+29.45%` red, `+29.20%` green,
/// `+26.47%` red. The percentages were live calls and the tints were resolved
/// from the seeded blob, whose signs happened to run `+ - + -`. Two numbers
/// describing one move, side by side, contradicting each other — which is the
/// failure §4 exists to prevent.
///
/// This was not introduced by making values live; it was REVEALED by it. Before
/// that both were seeded, so both were stale together and agreed. Half a fix is
/// what turned a hidden staleness into a visible contradiction, and that is the
/// general lesson: a value and its decoration must resolve from the same place.
#[test]
fn a_tint_is_as_live_as_the_value_it_tints() {
    let data = serde_json::json!({
        "movers": [
            {"ticker":"NVDA","name":"Nvidia","last":1.0,"change":0.5,"pct":2.0},
            {"ticker":"AAPL","name":"Apple","last":2.0,"change":-0.5,"pct":-1.0}],
        "quote": {}, "series": {}, "selected": "", "range": "m1",
        "env": {"locale": {}}, "copy": {"movers": "Top Movers"}
    });
    let root = realize(STOCK, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);

    // The tint is a CALL, at the row's own index — not the seeded sign.
    for row in 0..2 {
        let want = format!(r#"sys.movers({row}, "change""#);
        assert!(
            dsl.contains(&want),
            "row {row} must tint from a live call:\n{dsl}"
        );
    }
    // And the seeded signs must be gone. `-1` was what the second row lowered
    // to, and it is exactly what made a rising stock render red.
    assert!(
        !dsl.contains("l0_tinted(l0_value(sys.movers(1, \"changepct\", \"\")), -1)"),
        "a seeded tint beside a live value is the defect:\n{dsl}"
    );
    // A row's tint and its value must read the SAME row. One shared index, or
    // an index that does not advance, is how they disagree in the first place.
    let first =
        dsl.find(r#"l0_tinted(l0_value(sys.movers(1, "changepct", "")), sys.movers(1, "change""#);
    assert!(
        first.is_some(),
        "value and tint must come from one row:\n{dsl}"
    );
}

/// An L1 operand that is a live call is COERCED to a number.
///
/// FOUND ON A PHONE. Every `sys.*` helper answers with a string — that is what a
/// card renders and what concatenation composes, so `"$" + sys.stock(…)` is how
/// every live value reaches the screen. Arithmetic needs the other thing, and
/// string subtraction evaluates to NaN: the composed city card drew `≈NaN°` in
/// every row while the temperature and humidity beside it were correct.
///
/// So §9.5's claim — that a backend receives the shape and evaluates the
/// arithmetic against data arriving later — was true of the shape and false of
/// the arithmetic, and nothing in the crate could have caught it: the DSL was
/// well-formed and the operands were the right calls.
#[test]
fn an_l1_operand_that_is_a_live_call_is_coerced_to_a_number() {
    const CARD: &str = r#"# level: L1
source q sys.quote(ticker: "NVDA", fields: [last, open])
view root Surface { TextHero(value: q.last - q.open) }
"#;
    let data = serde_json::json!({ "q": { "last": 5.0, "open": 4.0 }, "env": { "locale": {} } });
    let root = realize(CARD, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);
    assert!(
        dsl.contains("sys.num(sys.stock("),
        "a live operand must be coerced, or the VM subtracts strings:\n{dsl}"
    );
    // Both sides, and the tree's shape preserved around them.
    assert_eq!(
        dsl.matches("sys.num(").count(),
        2,
        "each live operand is coerced once:\n{dsl}"
    );
    // A constant needs no coercion — it is already a number in the DSL.
    const COEFF: &str = r#"# level: L1
source now sys.weather(lat: 1.0, lon: 2.0, fields: [temp])
view root Surface { TextHero(value: now.temp * 9) }
"#;
    let d2 = serde_json::json!({ "now": { "temp": 10.0 }, "env": { "locale": {} } });
    let r2 = realize(COEFF, &d2, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl2 = octoscript_ui_l0::kit::lower(&r2);
    assert_eq!(
        dsl2.matches("sys.num(").count(),
        1,
        "only the call is coerced, not the coefficient:\n{dsl2}"
    );
}

// ─── the catalog, made executable ─────────────────────────────────────────────
//
// The catalog says what a card MAY say. Nothing connected it to what a backend
// DOES with what was said, so "the profile accepts it" and "the screen shows it"
// were independent facts — and the gap was invisible, because a test asserts
// what the code does, and the code was the thing dropping the attribute.
//
// Measured cost of relying on discipline instead: `width`, `align`, a numeric
// `cond`, `tint`, every scalar argument, and the whole `Map` role were each
// admitted by the catalog and then silently dropped or frozen by a lowering.
// Six were found by looking at a phone rather than by any test.
//
// The check is DIFFERENTIAL rather than by marker: build two cards that differ
// only in one attribute's value and require the lowered output to differ. That
// asks the only question worth asking — "does changing this change the screen?"
// — and needs no knowledge of how each attribute renders. A marker-based version
// of this test reported nine false positives, because `unit: .money` reaches the
// output as `$` and `tint:` as a direction rather than as the value.

/// Every distinct value worth trying for one attribute, as written in a card.
///
/// ALL of a token set, not a chosen pair. The first token is usually the default
/// and a default legitimately emits nothing, and two different tokens can
/// legitimately lower to the same thing — `.plan` and `.drive` both mean the
/// static route preview, because a chase camera needs a per-frame position L0
/// cannot supply. The caller requires only that SOME pair differs.
fn probe_values(kind: &octoscript_ui_l0::catalog::ArgKind) -> Option<Vec<String>> {
    use octoscript_ui_l0::catalog::ArgKind::*;
    Some(match kind {
        Token(set) | TokenOrPath(set) => {
            if set.len() < 2 {
                return None;
            }
            set.iter().map(|t| format!(".{t}")).collect()
        }
        // Small and adjacent: a column count only shows up against a child
        // count, so 11-vs-4242 chunked four children into one row either way and
        // reported a working `cols:` as inert.
        Number => vec!["1".into(), "3".into()],
        Text | Any => vec!["\"P1\"".into(), "\"P4242\"".into()],
        // Bound paths, so §4 is satisfied. The two differ in SIGN as well as
        // magnitude: `tint` lowers to a DIRECTION, so two positive values are
        // indistinguishable and the probe would call a working tint inert.
        Path | Data => vec!["sa".into(), "sc".into()],
        Event => vec!["ev_a".into(), "ev_b".into()],
        // A predicate has no second form to vary that is not also a different
        // shape; `a_predicate_argument_evaluates_to_a_boolean` covers it.
        Bool => return None,
    })
}

/// Attributes the catalog admits whose value changes NOTHING in either lowering.
///
/// This list may only shrink, and shrinking it is a deliberate edit. A new entry
/// means an attribute was added to the catalog and to no lowering — a card that
/// is accepted, renders, and is wrong.
const INERT: &[(&str, &str)] = &[
    // Dropped by both. Every card in the corpus passes `.page`, which is also
    // the hardcoded default, so this is invisible today and wrong the first time
    // a card asks for `.tight`.
    ("Surface", "pad"),
    ("Photo", "pad"),
    // `from`/`to`/`via`/`via2` name SOURCES, and this check varies a state-bound
    // value — which a `Map` correctly ignores, because a trip endpoint is a place
    // and not a number. Their liveness is asserted by
    // `a_bound_attribute_must_lower_to_a_live_call` instead, which binds a real
    // capability, and by `a_map_routes_through_both_of_its_stops` for the two
    // waypoint slots.
    //
    // The note that used to sit here — "`via` is additionally not emitted yet" —
    // was stale: it reaches both the polyline and the pins, and a trip through a
    // stop has been verified on device.
    ("Map", "from"),
    ("Map", "to"),
    ("Map", "via"),
    ("Map", "via2"),
    // `summary` names the SOURCE whose cost labels the route, so a state-bound
    // number is correctly ignored — a trip's duration is not a number a card holds.
    // Asserted live by `a_map_labels_the_route_with_what_it_costs`.
    ("Map", "summary"),
    // `at` is the same: a live POSITION, so a state cell holding a number is
    // correctly ignored. Its liveness — that it centres the map on the fix and
    // turns `.drive` into the follow camera — is asserted by
    // `a_map_lowers_a_live_route`, in the two `at:` cases at its end.
    ("Map", "at"),
    // `view` only means anything WITH `at:`, which this probe cannot bind — a
    // preview has no camera to tilt, so both tokens correctly lower to the same
    // static mode. The tilted case is asserted in `a_map_lowers_a_live_route`,
    // where a real position is declared.
    ("Map", "view"),
    // `dock` places a panel in a MAP card's top band or bottom sheet, and this probe
    // builds neither — a card with no map simply stacks its panels, where docking
    // correctly means nothing. Asserted in
    // `a_card_holding_a_map_floats_its_content_over_it`, which builds the real thing.
    ("Panel", "dock"),
    // `Field.width` used to sit here: "a text input is not wrapped by the width
    // composer — the `Field` branch returns before it". That was true of both
    // backends because neither lowered `Field` AT ALL in one of them: the makepad
    // lowering admitted the role and emitted a red warning where the input goes,
    // which is how the nav card's two editable rows — the entire fix for "the map
    // planner cannot change its origin or destination" — reached the screen as
    // two apologies. The role is lowered in both now and honours its width, so the
    // entry is gone rather than reworded.
];

#[test]
fn changing_a_declared_attribute_must_change_the_lowering() {
    const CONTAINERS: &[&str] = &["Surface", "Photo", "Panel", "Card", "Col", "Row", "Grid"];
    let mut inert: Vec<(String, String)> = Vec::new();

    for (role, args) in octoscript_ui_l0::catalog::CONSTRUCTORS {
        for (attr, kind) in *args {
            let Some(candidates) = probe_values(kind) else {
                continue;
            };
            // Every OTHER attribute is filled too, so the role is instantiated
            // the way a card would instantiate it — several roles refuse a
            // partial argument set, and a probe that omits them tests nothing.
            let has_value = args.iter().any(|(n, _)| *n == "value");
            let others: Vec<String> = args
                .iter()
                .filter(|(n, _)| n != attr)
                // `valued()` prefers `value:` over `text:` deliberately, so a
                // probe that fills both is asking which one wins, not whether
                // `text` reaches anything.
                .filter(|(n, _)| !(has_value && *n == "text"))
                // and the converse: probing `text` while `value` is filled asks
                // which wins, not whether `text` reaches anything.
                .filter(|(n, _)| !(*attr == "text" && *n == "value"))
                .filter_map(|(n, k)| {
                    probe_values(k).and_then(|v| v.first().map(|f| format!("{n}: {f}")))
                })
                .collect();
            let build = |value: &str| {
                let mut all = vec![format!("{attr}: {value}")];
                all.extend(others.iter().cloned());
                let arglist = format!("({})", all.join(", "));
                // Four children, because a column count is only observable
                // against something to divide: one child chunks into one row
                // whatever `cols:` says, which reported a working `cols` inert.
                let body = if CONTAINERS.contains(role) {
                    " { Rule() Rule() Rule() Rule() }"
                } else {
                    ""
                };
                let head = "state sa { shape: number, initial: 11 }\n\
                            state sb { shape: number, initial: 4242 }\n\
                            state sc { shape: number, initial: -7 }\n\
                            event ev_a { sa: set(1) }\n\
                            event ev_b { sa: set(2) }\n";
                if *role == "Surface" || *role == "Photo" {
                    format!("{head}view root {role}{arglist} {{ Rule() Rule() Rule() Rule() }}\n")
                } else {
                    format!("{head}view root Surface {{ {role}{arglist}{body} }}\n")
                }
            };
            let data = serde_json::json!({ "env": { "locale": {} }, "copy": {} });
            let lower = |card: &str| -> Option<String> {
                if !check_ui_l0_named("probe", card).valid {
                    return None;
                }
                let root = realize(card, &data, RealizeLimits::default()).root?;
                Some(format!(
                    "{}\n{}",
                    octoscript_ui_l0::kit::lower(&root),
                    makepad::lower(&root)
                ))
            };
            // A probe the checker refuses proves nothing about the lowering, so
            // it contributes no output rather than a failure: several roles
            // constrain their arguments against each other in ways this
            // generator does not model, and a false failure would train people
            // to ignore the list.
            let outputs: Vec<String> = candidates.iter().filter_map(|v| lower(&build(v))).collect();
            if outputs.len() < 2 {
                continue;
            }
            if outputs.iter().all(|o| *o == outputs[0]) {
                inert.push((role.to_string(), attr.to_string()));
            }
        }
    }

    let known: Vec<(String, String)> = INERT
        .iter()
        .map(|(r, a)| (r.to_string(), a.to_string()))
        .collect();
    let mut fresh: Vec<_> = inert.iter().filter(|p| !known.contains(p)).collect();
    fresh.sort();
    assert!(
        fresh.is_empty(),
        "changing these attributes changed NOTHING in either lowering — the \
         catalog admits them, the checker accepts them, and the screen ignores \
         them: {fresh:#?}"
    );
    let mut fixed: Vec<_> = known.iter().filter(|p| !inert.contains(p)).collect();
    fixed.sort();
    assert!(
        fixed.is_empty(),
        "these now reach a lowering — delete them from INERT: {fixed:#?}"
    );
}

/// A bound attribute must lower to a LIVE CALL where the backend can answer it.
///
/// The companion to the reachability check, and the half that caught more. An
/// attribute can reach a lowering and still be wrong: `tint`, every scalar, a
/// `value:` and a tap payload all reached the output as the number REALIZATION
/// happened to see — right by accident against a seed blob, and on a live card,
/// which carries no blob, frozen or empty.
///
/// That failure is worse than a drop, because a drop leaves a gap and this
/// leaves a plausible number. It is what put a stale `$181` open under a live
/// `$207` price, and a red `+29.45%` beside a green `+29.20%`.
///
/// DIFFERENTIAL, and it has to be: the same attribute is bound once to a source
/// the backend answers and once to a state cell holding the same number. A
/// lowering that emits the call distinguishes them; one that reaches for the
/// realized value cannot, and produces identical output. An earlier version of
/// this test asserted only that SOME call appeared anywhere in the output — with
/// every argument bound, that passed even with `tint` deliberately broken.
#[test]
fn a_bound_attribute_must_lower_to_a_live_call() {
    use octoscript_ui_l0::catalog::ArgKind;
    const CONTAINERS: &[&str] = &["Surface", "Photo", "Panel", "Card", "Col", "Row", "Grid"];
    // `Map` is checked by `a_map_lowers_a_live_route` instead. This generator
    // binds every argument to one capability, and a trip endpoint is a PLACE —
    // asking `sys.quote` for a latitude answers nothing, so the generic probe
    // would report a working `Map` as stale.
    const SKIP_ROLES: &[&str] = &["Map"];

    let mut stale: Vec<(String, String)> = Vec::new();
    let mut checked = 0usize;
    for (role, args) in octoscript_ui_l0::catalog::CONSTRUCTORS {
        if SKIP_ROLES.contains(role) {
            continue;
        }
        for (attr, kind) in *args {
            if !matches!(kind, ArgKind::Path | ArgKind::Data) {
                continue;
            }
            // `one` is what varies: the attribute under test binds a SOURCE in
            // the first card and a STATE in the second. Everything else stays
            // source-bound in both, so any difference is this attribute's.
            let build = |one: &str| {
                let all: Vec<String> = args
                    .iter()
                    .filter_map(|(n, k)| match k {
                        ArgKind::Path | ArgKind::Data if n == attr => Some(format!("{n}: {one}")),
                        ArgKind::Path | ArgKind::Data => Some(format!("{n}: q.last")),
                        ArgKind::Text => Some(format!("{n}: q.name")),
                        ArgKind::Token(set) | ArgKind::TokenOrPath(set) => {
                            Some(format!("{n}: .{}", set[0]))
                        }
                        ArgKind::Number => Some(format!("{n}: 2")),
                        _ => None,
                    })
                    .collect();
                let arglist = format!("({})", all.join(", "));
                let body = if CONTAINERS.contains(role) {
                    " { Rule() }"
                } else {
                    ""
                };
                let head = "source q sys.quote(ticker: \"NVDA\", fields: [last, name])\n\
                            state held { shape: number, initial: 1 }\n";
                if *role == "Surface" || *role == "Photo" {
                    format!("{head}view root {role}{arglist} {{ Rule() }}\n")
                } else {
                    format!("{head}view root Surface {{ {role}{arglist}{body} }}\n")
                }
            };
            // The state's initial IS the seeded source value, so the two cards
            // realize to the same number and only the LOWERING can tell them
            // apart.
            let data = serde_json::json!({
                "q": { "last": 1.0, "name": "seeded" }, "held": 1.0,
                "env": { "locale": {} }, "copy": {}
            });
            let lower = |card: &str| -> Option<String> {
                if !check_ui_l0_named("probe", card).valid {
                    return None;
                }
                let root = realize(card, &data, RealizeLimits::default()).root?;
                Some(format!(
                    "{}\n{}",
                    octoscript_ui_l0::kit::lower(&root),
                    makepad::lower(&root)
                ))
            };
            let (Some(live), Some(from_state)) = (lower(&build("q.last")), lower(&build("held")))
            else {
                continue;
            };
            checked += 1;
            if live == from_state {
                stale.push((role.to_string(), attr.to_string()));
            }
        }
    }
    assert!(
        checked >= 20,
        "the probe generator built almost nothing ({checked} attributes) — a \
         vacuous pass here is worse than a failure"
    );

    let known: Vec<(String, String)> = STALE
        .iter()
        .map(|(r, a)| (r.to_string(), a.to_string()))
        .collect();
    let mut fresh: Vec<_> = stale.iter().filter(|p| !known.contains(p)).collect();
    fresh.sort();
    assert!(
        fresh.is_empty(),
        "these are bound to a capability the backend ANSWERS and still lower to \
         the realized value — on a live card, which carries no seed blob, they \
         render frozen or empty: {fresh:#?}"
    );
    let mut fixed: Vec<_> = known.iter().filter(|p| !stale.contains(p)).collect();
    fixed.sort();
    assert!(
        fixed.is_empty(),
        "these now lower to a call — delete them from STALE: {fixed:#?}"
    );
}

/// Bound attributes that still lower to the realized value. Must only shrink.
const STALE: &[(&str, &str)] = &[];

/// A `Map` draws a LIVE route between two declared places.
///
/// `Map` was admitted by the catalog and lowered by neither backend, so
/// `nav.card` — which §1.0 cites as settling its central argument, "the same
/// screen as the 664-line L2 exemplar in **54 lines**" — drew an error box where
/// the map goes. Admitted at L0 was true; the same screen was not.
///
/// The catalog note said the widget fetches its own route. It does not:
/// `nav_polyline` is a live field `MapView` renders and never populates. So the
/// fetch is the card's declared source resolved into a call, which is the shape
/// every other live value already takes — and the pairing the helper's own
/// comment prescribes.
#[test]
fn a_map_lowers_a_live_route() {
    const CARD: &str = r#"
source here sys.gps()
source dest sys.search(query: state.q, count: 1, fields: [name, lat, lon])
state q { shape: text, initial: "SFO" }
view root Surface {
  TextRow(text: dest.0.name)
  Map(mode: .drive, from: here, to: dest, zoom: 16)
}
"#;
    let report = check_ui_l0_named("nav", CARD);
    assert!(report.valid, "{:#?}", report.diagnostics);
    // Seeded coordinates the lowering COULD fall back to. Reaching for them
    // instead of emitting the calls is the defect.
    let data = serde_json::json!({
        "here": { "lat": 37.3, "lon": -122.0, "ok": 1 },
        "dest": { "0": { "name": "X", "lat": 37.4, "lon": -121.9 } },
        "q": "SFO", "env": { "locale": {} }, "copy": {}
    });
    let root = realize(CARD, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let mk = makepad::lower(&root);

    assert!(
        !mk.contains("no makepad lowering for Map"),
        "the role must lower at all:\n{mk}"
    );
    // The camera is the widget's own vocabulary, not L0's token — and `.drive`
    // lowers to the STATIC preview. A chase camera follows a vehicle, following
    // needs a position updated every frame, and L0 has no loop to supply one; the
    // widget handed a route and no position animates along it on a timer, drawing
    // motion the user is not making. §4 does not stop applying because the
    // invented value is a camera pose.
    assert!(
        mk.contains("nav_mode: \"plan\"") && mk.contains("zoom: 16"),
        "the declared mode and zoom must reach the widget:\n{mk}"
    );
    // The settings a `MapView` does not work without, from the shipping nav card.
    //
    // `use_local_mbtiles: false` is the one that was missing. The widget defaults
    // to a local `.mbtiles` file for offline development and an L0 card cannot ship
    // one, so its absence draws the land fill and nothing else — measured on device
    // as a correct route ribbon and a correct duration over a blank beige
    // rectangle, with `local mbtiles source missing` in logcat and nothing on
    // screen saying so. A map with no map is the failure this asserts against.
    for required in [
        "use_network: true",
        "use_local_mbtiles: false",
        "min_zoom: 3.0",
        "nav_route_width:",
    ] {
        assert!(
            mk.contains(required),
            "{required:?} is mandatory for a MapView and is missing:\n{mk}"
        );
    }
    // Capped at 16 for a whole-route preview, as the shipping card caps it.
    assert!(
        mk.contains("max_zoom: 16.0"),
        "a route preview caps its zoom:\n{mk}"
    );
    // Every coordinate LIVE, from the source each endpoint names — a device fix
    // for the origin and a place search for the destination.
    assert!(
        mk.contains("center_lat: sys.gps(\"lat\")") && mk.contains("center_lon: sys.gps(\"lon\")"),
        "the origin must centre the map on the live fix:\n{mk}"
    );
    assert!(
        mk.contains("nav_polyline: sys.navroute("),
        "the route must be fetched, not seeded:\n{mk}"
    );
    assert!(
        mk.contains("sys.searchnum(\"SFO\", 0, \"lat\")"),
        "the destination's coordinates come from the search that found it:\n{mk}"
    );
    // THE KIT TOO, because the device renders through it. Fixing only
    // `makepad::lower` left the error box exactly where it was on a phone, which
    // is the half that matters and the half a green test suite would have hidden.
    let kit = octoscript_ui_l0::kit::lower(&root);
    assert!(
        !kit.contains("l0_unsupported(\"Map\")"),
        "the kit must lower the role, not report it unsupported:\n{kit}"
    );
    assert!(
        kit.contains("l0_map(\"plan\", 16, sys.gps(\"lat\"), sys.gps(\"lon\"), sys.navroute("),
        "the kit passes the mode, the zoom, the centre and the live route:\n{kit}"
    );
    // And none of the seeded numbers may appear as a literal.
    for seeded in ["37.3", "-122", "37.4", "-121.9"] {
        assert!(
            !mk.contains(seeded),
            "{seeded} is the seeded coordinate and must not be lowered:\n{mk}"
        );
    }

    // ── `at:` — the declaration that makes `.drive` mean what it says ────────
    //
    // Above, `.drive` lowered to `"plan"`, and that is correct WITHOUT a declared
    // position: a follow camera handed a route and no position animates along the
    // polyline on a timer, drawing motion the user is not making. §4 does not stop
    // applying because the invented value is a camera pose.
    //
    // `at:` supplies the missing measurement, so the two cards below differ in
    // exactly one thing — whether the card said where the user is — and the
    // camera mode must follow that and nothing else.
    const DRIVING: &str = r#"
source here sys.gps()
source orig sys.search(query: state.o, count: 1, fields: [name, lat, lon])
source dest sys.search(query: state.q, count: 1, fields: [name, lat, lon])
state o { shape: text, initial: "HOME" }
state q { shape: text, initial: "SFO" }
view root Surface {
  TextRow(text: dest.0.name)
  Map(mode: .drive, from: orig, to: dest, at: here, zoom: 16)
}
"#;
    let report = check_ui_l0_named("nav", DRIVING);
    assert!(report.valid, "{:#?}", report.diagnostics);
    let data = serde_json::json!({
        "here": { "lat": 37.3, "lon": -122.0, "ok": 1 },
        "orig": { "0": { "name": "H", "lat": 37.2, "lon": -122.1 } },
        "dest": { "0": { "name": "X", "lat": 37.4, "lon": -121.9 } },
        "o": "HOME", "q": "SFO", "env": { "locale": {} }, "copy": {}
    });
    let driving = octoscript_ui_l0::kit::lower(
        &realize(DRIVING, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );
    // The camera follows, because there is now something real to follow.
    assert!(
        driving.contains("l0_map(\"follow\","),
        "a declared position must turn `.drive` into the follow camera:\n{driving}"
    );
    // Centred on the DRIVER — the live fix, not the trip's start.
    assert!(
        driving.contains("l0_map(\"follow\", 16, sys.gps(\"lat\"), sys.gps(\"lon\")"),
        "the follow camera centres on the live fix:\n{driving}"
    );
    // TILTED is the shipping app's driving view (its R8.1), and it follows the
    // same declared position — the widget's own `3d` mode drives a SIMULATED
    // vehicle, so pointing this at it would reintroduce the fabrication `map_mode`
    // exists to refuse. Flat and tilted must therefore differ in the mode and in
    // nothing else.
    let tilted = octoscript_ui_l0::kit::lower(
        &realize(
            &DRIVING.replace("at: here,", "at: here, view: .tilted,"),
            &data,
            RealizeLimits::default(),
        )
        .root
        .expect("realizes"),
    );
    assert!(
        tilted.contains("l0_map(\"follow3d\", 16, sys.gps(\"lat\"), sys.gps(\"lon\")"),
        "a tilted driving view follows the same declared fix:\n{tilted}"
    );
    assert!(
        !tilted.contains("l0_map(\"3d\""),
        "and must NOT be the widget's simulated drive:\n{tilted}"
    );

    // And the route is still the declared TRIP. Centring on the fix without
    // keeping the endpoints would redraw the route from wherever the user happens
    // to be, which is a different trip from the one the card states.
    assert!(
        driving.contains("sys.navroute(sys.searchnum(\"HOME\", 0, \"lat\")")
            && driving.contains("sys.searchnum(\"SFO\", 0, \"lat\")"),
        "the route stays the trip the card declared:\n{driving}"
    );
}

/// Navigation's live half: an instruction that advances because the DEVICE did.
///
/// This is the one place a fabricated number was load-bearing in the app L0
/// replaces. `sys.navstep` needs a progress-along-the-route in metres, and the
/// 664-line exemplar supplied `sys.navsecs(period) * 15.2` — a looping clock
/// times an assumed 34 mph. The card announced turns for a vehicle that was
/// moving whether or not anything was; it read as a demo because it was one.
///
/// `sys.step` takes the trip's four coordinates AND the device's two, so progress
/// is a projection of a real fix onto the route. Every argument is a measurement.
#[test]
fn a_navigation_instruction_advances_only_when_the_device_does() {
    const CARD: &str = r#"
source here sys.gps()
source orig sys.search(query: state.o, count: 1, fields: [name, lat, lon])
source dest sys.search(query: state.q, count: 1, fields: [name, lat, lon])
source step sys.step(from_lat: orig.0.lat, from_lon: orig.0.lon,
                     to_lat: dest.0.lat,   to_lon: dest.0.lon,
                     at_lat: here.lat,     at_lon: here.lon,
                     fields: [instruction, remaining])
state o { shape: text, initial: "HOME" }
state q { shape: text, initial: "SFO" }
view root Surface {
  TextRow(text: step.instruction)
  TextCaption(value: step.remaining)
  Map(mode: .drive, from: orig, to: dest, at: here, zoom: 16)
}
"#;
    let report = check_ui_l0_named("nav", CARD);
    assert!(report.valid, "{:#?}", report.diagnostics);
    let data = serde_json::json!({
        "here": { "lat": 37.3, "lon": -122.0, "ok": 1 },
        "orig": { "0": { "name": "H", "lat": 37.2, "lon": -122.1 } },
        "dest": { "0": { "name": "X", "lat": 37.4, "lon": -121.9 } },
        "step": { "instruction": "seeded turn", "remaining": "999 km" },
        "o": "HOME", "q": "SFO", "env": { "locale": {} }, "copy": {}
    });
    let kit = octoscript_ui_l0::kit::lower(
        &realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );
    // The instruction is fetched for THIS trip, at THIS position.
    assert!(
        kit.contains("sys.navstep(") && kit.contains("sys.navprog("),
        "the instruction must be asked for, and its progress measured:\n{kit}"
    );
    // The progress argument reads the device's fix — the whole point.
    assert!(
        kit.contains("sys.gps(\"lat\"), sys.gps(\"lon\"))"),
        "progress along the route must come from the device's own fix:\n{kit}"
    );
    // And no clock anywhere. `sys.navsecs` is what the L2 exemplar used, and its
    // appearance here would mean the timer came back wearing a source's clothes.
    assert!(
        !kit.contains("navsecs") && !kit.contains("simsecs"),
        "progress must be measured, never clocked:\n{kit}"
    );
    // Nor the seeded strings the lowering could have reached for instead.
    assert!(
        !kit.contains("seeded turn") && !kit.contains("999 km"),
        "the seeded instruction must not be lowered:\n{kit}"
    );
}

/// Every catalog-legal `unit:` token that claims a dimension must RENDER it.
///
/// `.speed` and `.pressure` were catalog-legal and `decoration_of` mapped only
/// c/f/pct/duration — so the weather detail tiles drew "12.5" and "1013"
/// beside their labels, bare numbers in whatever unit the reader assumed. The
/// suffixes are what the backend actually answers (open-meteo serves km/h and
/// hPa, no override in any fetch) and what the L2 reference showed. `.index`
/// went the other way: an index is dimensionless, there is no honest suffix,
/// so the token left the catalog rather than staying legal and inert.
#[test]
fn a_dimensioned_unit_token_renders_its_dimension() {
    let card = |unit: &str| {
        format!(
            "source now sys.weather(lat: 1, lon: 2, fields: [wind, pressure])\n\
             view root Surface {{ TextValue(value: now.wind, unit: {unit}) }}"
        )
    };
    let data = serde_json::json!({
        "now": { "wind": 12.5, "pressure": 1013.0 }, "env": { "locale": {} }, "copy": {}
    });
    // Differential: the token must CHANGE the lowering, to its own suffix.
    for (token, suffix) in [(".speed", " km/h"), (".pressure", " hPa")] {
        let report = check_ui_l0_named("unit", &card(token));
        assert!(report.valid, "{token}: {:#?}", report.diagnostics);
        let root = realize(&card(token), &data, RealizeLimits::default())
            .root
            .expect("realizes");
        for (backend, dsl) in [
            ("makepad", makepad::lower(&root)),
            ("kit", octoscript_ui_l0::kit::lower(&root)),
        ] {
            assert!(
                dsl.contains(suffix),
                "{backend}: `unit: {token}` must render {suffix:?}:\n{dsl}"
            );
        }
    }
    // And `.index` is refused, not silently ignored: the checker names the
    // legal set instead of accepting a token nothing decorates.
    let report = check_ui_l0_named("unit", &card(".index"));
    assert!(!report.valid, "unit: .index must be off the catalog");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.message.contains("index") && d.message.contains("expected one of")),
        "the refusal names the legal tokens: {:#?}",
        report.diagnostics
    );
}

/// Token pairs a card TOGGLES between must be distinguishable in the lowering.
///
/// `changing_a_declared_attribute_must_change_the_lowering` asks whether SOME
/// pair of an attribute's tokens differs, which is the right question for
/// "does this attribute reach a backend at all" and the wrong one for a pair a
/// card cycles. `unit` passes that check because `.pct` lowers to `%` and
/// `.money` to `$` — while `.c` and `.f`, the two a weather card actually
/// toggles, are byte-identical.
///
/// The general test got STRONGER and lost this case. Both are needed.
#[test]
fn a_token_pair_a_card_toggles_must_change_the_lowering() {
    // (role, attribute, first, second). Each pair is one a shipping card cycles.
    const PAIRS: &[(&str, &str, &str, &str)] = &[("TextHero", "unit", "c", "f")];
    // Pairs that are still indistinguishable. May only shrink.
    //
    // `.c` vs `.f`: both lower to `value + "°"`, so the weather card's units
    // toggle — the one interaction it advertises, wired through state, dispatch
    // and a re-render — changes nothing on screen, and every temperature is
    // Celsius because the live call asks open-meteo for `current.temperature_2m`
    // with no unit at all.
    //
    // The weather spec says "do not convert: the runtime formats by the unit
    // token". The runtime never receives the token. Closing it is a DESIGN
    // decision rather than a patch: either the unit travels to the helper, so the
    // fetch asks for the right one, or the card converts — and converting is
    // exactly what L0 has no expression form for.
    const IDENTICAL: &[(&str, &str)] = &[("TextHero", "unit")];

    let mut same: Vec<(String, String)> = Vec::new();
    for (role, attr, first, second) in PAIRS {
        let card = |tok: &str| {
            format!(
                "state held {{ shape: number, initial: 21 }}\n\
                 view root Surface {{ {role}(value: held, {attr}: .{tok}) }}\n"
            )
        };
        let data = serde_json::json!({ "held": 21.0, "env": { "locale": {} }, "copy": {} });
        let lower = |src: &str| -> String {
            let root = realize(src, &data, RealizeLimits::default())
                .root
                .expect("the probe realizes");
            format!(
                "{}\n{}",
                octoscript_ui_l0::kit::lower(&root),
                makepad::lower(&root)
            )
        };
        if lower(&card(first)) == lower(&card(second)) {
            same.push((role.to_string(), attr.to_string()));
        }
    }
    let known: Vec<(String, String)> = IDENTICAL
        .iter()
        .map(|(r, a)| (r.to_string(), a.to_string()))
        .collect();
    let mut fresh: Vec<_> = same.iter().filter(|p| !known.contains(p)).collect();
    fresh.sort();
    assert!(
        fresh.is_empty(),
        "a card toggles between these tokens and the lowering cannot tell them \
         apart, so the toggle changes nothing on screen: {fresh:#?}"
    );
    let mut fixed: Vec<_> = known.iter().filter(|p| !same.contains(p)).collect();
    fixed.sort();
    assert!(
        fixed.is_empty(),
        "these are distinguishable now — delete them from IDENTICAL: {fixed:#?}"
    );
}

/// A comparison is the LOOSEST thing in an operand, so `x == a + b` means what
/// it reads as.
///
/// A comparison's right side took a TERM, so it bound tighter than `+`: at L1
/// `active: x == a + b` parsed as `(x == a) + b` — arithmetic over a boolean. It
/// evaluated to missing and nothing rejected it, so the card was accepted, drew
/// blank, and gave no diagnostic. That is the worst failure shape available: a
/// card that is wrong, valid, and silent.
#[test]
fn a_comparison_binds_looser_than_arithmetic() {
    const CARD: &str = r#"# level: L1
state k { shape: number, initial: 5 }
state a { shape: number, initial: 2 }
state b { shape: number, initial: 3 }
copy yes { class: vocabulary, en: "MATCHED" }
view root Surface {
  when k == a + b { TextRow(text: copy.yes) }
}
"#;
    assert!(
        check_ui_l0_named("c", CARD).valid,
        "{:#?}",
        check_ui_l0_named("c", CARD).diagnostics
    );
    // The comparison is against the SUM, so the branch turns on 5 == 2 + 3.
    for (k, taken) in [(5.0, true), (6.0, false)] {
        let data = serde_json::json!({
            "k": k, "a": 2.0, "b": 3.0,
            "env": { "locale": {} }, "copy": { "yes": "MATCHED" }
        });
        let root = realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes");
        let dsl = octoscript_ui_l0::kit::lower(&root);
        assert_eq!(
            dsl.contains("MATCHED"),
            taken,
            "k={k} compared against a + b:\n{dsl}"
        );
    }

    // And the right side is CHECKED like any other operand, now that it can hold
    // arithmetic: an undeclared name in it is refused rather than resolving to
    // nothing and deciding the branch on that absence.
    let why = |c: &str| {
        check_ui_l0_named("c", c)
            .diagnostics
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join("; ")
    };
    const UNDECLARED: &str = r#"# level: L1
source q sys.quote(ticker: "N", fields: [last])
state k { shape: number, initial: 2 }
view root Surface { Chip(text: "c", active: k == nope + q.last) }
"#;
    assert!(
        why(UNDECLARED).contains("not a declared name"),
        "{}",
        why(UNDECLARED)
    );
    // §9.3 reaches here too: a comparison against a computed literal compares
    // against a fabricated number.
    const FABRICATED: &str = r#"# level: L1
source q sys.quote(ticker: "N", fields: [last])
state k { shape: number, initial: 2 }
view root Surface { Chip(text: "c", active: k == 3 * 4) TextRow(text: q.last) }
"#;
    assert!(
        why(FABRICATED).contains("must read a declared"),
        "{}",
        why(FABRICATED)
    );
}

/// L1's remaining holes, closed: grouping, a negative coefficient, and an
/// expression that reads values and ignores them.
///
/// The third is the one that needed an argument rather than a patch. §9.3 asked
/// an expression to READ something, which stops `1547 * 3.2` and does not stop
/// `quote.last * 0 + 1547` — one real reading laundering a fabricated number.
/// The argument: a formula is a formula because its answer MOVES when its inputs
/// move, so evaluate it under several assignments and refuse an answer that never
/// changes.
#[test]
fn an_expression_must_depend_on_what_it_reads() {
    let ok = |body: &str| {
        let card = format!(
            "# level: L1\nsource q sys.quote(ticker: \"N\", fields: [last, open])\n\
             state k {{ shape: number, initial: 2 }}\nview root Surface {{ {body} }}\n"
        );
        check_ui_l0_named("x", &card).valid
    };

    // GROUPING. Precedence was fixed and unoverridable.
    assert!(ok("TextHero(value: (q.last + q.open) * k)"), "grouping");
    assert!(
        ok("TextHero(value: ((q.last + 1) * (k + 2)) / q.open)"),
        "nested grouping"
    );
    // A NEGATIVE COEFFICIENT — the ordinary way to subtract a scaled reading.
    assert!(ok("TextHero(value: q.last * -1)"), "negative coefficient");
    // A bare negative literal is still refused, by §4's original rule: a
    // measurement the model wrote, in a position that renders one.
    assert!(!ok("TextHero(value: -1)"), "a bare literal is still a fact");

    // DEGENERATE. Each reads something real and ignores it.
    for fake in [
        "q.last * 0 + 1547",
        "q.last - q.last + 99",
        "(q.last - q.last) * k + 5",
        "q.last * 0.0",
    ] {
        assert!(
            !ok(&format!("TextHero(value: {fake})")),
            "{fake} is a constant with extra steps and must be refused"
        );
    }
    // HONEST. Each answer moves with its inputs.
    for real in [
        "q.last - q.open",
        "q.last * 9 / 5 + 32",
        "(q.last + q.open) * k",
        "q.last / q.open",
        "q.last * -1",
    ] {
        assert!(
            ok(&format!("TextHero(value: {real})")),
            "{real} is a formula and must be admitted"
        );
    }

    // The probe must not condemn a difference. Binding every read to the SAME
    // number would make `a - b` constant, which is why the assignments differ
    // per path as well as per round.
    assert!(
        ok("TextHero(value: q.last - q.open)"),
        "a - b is not constant"
    );

    // And it reaches a comparison's right side, which can hold arithmetic now.
    const GUARD: &str = r#"# level: L1
source q sys.quote(ticker: "N", fields: [last])
state k { shape: number, initial: 2 }
view root Surface { when k == q.last * 0 + 7 { Rule() } TextRow(text: q.last) }
"#;
    assert!(
        !check_ui_l0_named("g", GUARD).valid,
        "a guard comparing against a fabricated constant must be refused"
    );
}

/// Grouping changes the ANSWER, not just the parse.
#[test]
fn grouping_overrides_precedence() {
    let tree = |expr: &str| {
        let card = format!(
            "# level: L1\nstate a {{ shape: number, initial: 2 }}\n\
             state b {{ shape: number, initial: 3 }}\nstate c {{ shape: number, initial: 4 }}\n\
             view root Surface {{ TextHero(value: {expr}) }}\n"
        );
        let data = serde_json::json!({
            "a": 2.0, "b": 3.0, "c": 4.0, "env": { "locale": {} }, "copy": {}
        });
        let root = realize(&card, &data, RealizeLimits::default())
            .root
            .expect("realizes");
        octoscript_ui_l0::kit::lower(&root)
    };
    // The DSL carries the EXPRESSION, so the tree's shape is the evidence: the
    // backend evaluates it against data that arrives later.
    assert!(
        tree("a + b * c").contains("(2 + (3 * 4))"),
        "multiplication binds tighter"
    );
    assert!(
        tree("(a + b) * c").contains("((2 + 3) * 4)"),
        "and grouping overrides that"
    );
}

/// Two numbers compare numerically, whatever JSON shape they arrived in.
///
/// `==` was `serde_json::Value` equality, which distinguishes `1` from `1.0`. So
/// `when here.ok == 1` took its branch when the host injected a float and
/// silently did not when it injected an integer — the same guard, the same card,
/// the same value, deciding differently on a representation the card cannot see.
///
/// It cost the nav map. The card was correct, the checker accepted it, the
/// destination was live, and the `Map` was simply not in the realized tree. The
/// ordering operators already coerced through `as_f64`; only equality did not,
/// which is the half nobody tested.
#[test]
fn a_number_compares_numerically_whatever_shape_it_arrived_in() {
    const CARD: &str = r#"
source here sys.gps()
copy yes { class: vocabulary, en: "SHOWN" }
view root Surface {
  when here.ok == 1 { TextRow(text: copy.yes) }
  TextCaption(value: here.lat)
}
"#;
    for shape in [
        serde_json::json!(1),
        serde_json::json!(1.0),
        serde_json::json!(1.00),
    ] {
        let data = serde_json::json!({
            "here": { "lat": 34.9, "lon": 135.7, "ok": shape },
            "env": { "locale": {} }, "copy": { "yes": "SHOWN" }
        });
        let root = realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes");
        let dsl = octoscript_ui_l0::kit::lower(&root);
        assert!(
            dsl.contains("SHOWN"),
            "ok={shape} must satisfy `== 1`:\n{dsl}"
        );
    }
    // And a genuine mismatch still fails, in both shapes.
    for shape in [serde_json::json!(0), serde_json::json!(0.0)] {
        let data = serde_json::json!({
            "here": { "lat": 34.9, "lon": 135.7, "ok": shape },
            "env": { "locale": {} }, "copy": { "yes": "SHOWN" }
        });
        let root = realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes");
        assert!(
            !octoscript_ui_l0::kit::lower(&root).contains("SHOWN"),
            "ok={shape} must not satisfy `== 1`"
        );
    }
}

/// A week forecast realizes SEVEN days, each asking for its own.
///
/// "Beijing week weather" gave one day. Two independent defects, both between a
/// correct card and a correct screen:
///
/// - **The declared count was not found.** It matched an argument named `count`
///   holding a bare literal, and the weather card asks
///   `sys.weather(days: state.days)` with `state days { initial: 7 }` — the wrong
///   name, and a path rather than a literal. It also matched the source name
///   only, and the loop is over `week.days`. So a seven-day forecast realized
///   ZERO rows and the card drew current conditions and nothing else.
/// - **A row could not translate.** With rows realized, each one's binding
///   carried the collection's own name into the field handed to the helper —
///   `days.3.cond` where it wanted `3.cond` — so every row fell back to its
///   realized default: seven identical icons and an em dash for every high.
#[test]
fn a_week_forecast_realizes_seven_days_each_its_own() {
    // NO data. A live card carries none, which is the case that ships.
    let data = serde_json::json!({ "env": { "locale": {} }, "copy": {} });
    let root = realize(WEATHER, &data, RealizeLimits::default())
        .root
        .expect("realizes");

    fn count(n: &octoscript_ui_l0::UiNode, kind: &str) -> usize {
        (n.kind == kind) as usize + n.children.iter().map(|c| count(c, kind)).sum::<usize>()
    }
    assert_eq!(
        count(&root, "TempBar"),
        7,
        "the declared `days: state.days` is the row count"
    );

    let dsl = octoscript_ui_l0::kit::lower(&root);
    // Each row asks for ITS day, not day 0 seven times.
    for day in 0..7 {
        assert!(
            dsl.contains(&format!("daily.temperature_2m_max.{day}")),
            "day {day}'s high must be live:\n{dsl}"
        );
        assert!(
            dsl.contains(&format!("daily.weather_code.{day}")),
            "day {day}'s condition must be live:\n{dsl}"
        );
    }
    // An aggregate on the source itself has no row and must not be rewritten
    // into one — `week.min_lo` is a property of the WEEK.
    assert!(
        !dsl.contains("min_lo.0") && !dsl.contains("0.min_lo"),
        "an aggregate is not a row:\n{dsl}"
    );
}

/// A forecast row's LABEL and the week's range reach their helpers.
///
/// Two more between a correct card and a correct screen, both found by looking at
/// a phone rather than at a test.
///
/// `sys.dayname(lat, lon, n, locale)` takes FOUR arguments and this emitted
/// three, putting `"en"` in the lat slot and the row in the lon slot — so `n`
/// coerced to 0 and every row said "Today". Seven of them, under seven different
/// temperatures, which made it read as a labelling choice rather than a bug.
///
/// `min_lo` and `max_hi` are §5.11 aggregates — properties of the WEEK, and what
/// tells a `TempBar` how long its bar should be. Neither was translated, so both
/// fell back to zero and every bar drew against a range of nothing: seven
/// different days, seven identical flat lines.
#[test]
fn a_forecast_rows_label_and_the_weeks_range_go_live() {
    let data = serde_json::json!({ "env": { "locale": {} }, "copy": {} });
    let root = realize(WEATHER, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);

    // Every row asks for ITS weekday, with the coordinates the helper needs.
    for day in 0..7 {
        assert!(
            dsl.contains(&format!("\"lon\"), {day}, \"en\")")),
            "row {day} must ask for its own weekday:\n{dsl}"
        );
    }
    // A four-argument call, so the row can never land in the locale slot.
    assert!(
        !dsl.contains("sys.dayname(\"en\""),
        "the row must not be passed as a coordinate:\n{dsl}"
    );
    // The week's range, so a bar has something to be a fraction of.
    assert!(
        dsl.contains("sys.weekmin("),
        "min_lo must translate:\n{dsl}"
    );
    assert!(
        dsl.contains("sys.weekmax("),
        "max_hi must translate:\n{dsl}"
    );
}

/// The satellite pane, and a row that can stop filling.
///
/// Both were things a card could not SAY. The shipping weather app has two map
/// panes — 卫星云图 then 空气质量图 — and L0 had a role for the second and none for
/// the first, so every generated weather card was missing its sky.
///
/// And `align: .center` on a column had no effect on a row child, because
/// `l0_row` fills by default (a list row must) and a filling child ignores its
/// parent's alignment — while `align` on a ROW means the cross axis, which is
/// vertical. So the weather card's `↑37° ↓28° ≈37°` sat hard left under a centred
/// name, icon and hero, and no attribute the card could write changed it.
#[test]
fn a_satellite_pane_and_a_row_that_can_stop_filling() {
    let data = serde_json::json!({ "env": { "locale": {} }, "copy": {} });
    let root = realize(WEATHER, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let kit = octoscript_ui_l0::kit::lower(&root);
    let mk = makepad::lower(&root);

    // The pane names WHERE and the helper answers the image — in both backends,
    // with LIVE coordinates, so the card never carries an observation.
    // Coerced, because `sys.satellite` takes coordinates as NUMBERS and every
    // helper answers with a string.
    assert!(
        kit.contains("l0_satellite(sys.num(sys.geocodenum("),
        "the kit must ask for the sky at the resolved place:\n{kit}"
    );
    assert!(
        mk.contains("sys.satellite(sys.geocodenum("),
        "and so must makepad:\n{mk}"
    );

    // `width: .fit` is NOT a no-op on a row, whatever it is on a text role.
    assert!(
        kit.contains("l0_fit("),
        "a row must be able to stop filling:\n{kit}"
    );
    // And it is inside the centred column, which is the point.
    assert!(
        kit.contains("l0_aligned("),
        "the current block is still centred:\n{kit}"
    );
}

/// A visualisation's parameters are NUMBERS, and a grid is rows.
///
/// Both were the same shape as everything else this session: the card was right,
/// the checker accepted it, and the screen was confidently wrong.
///
/// Every `sys.*` helper answers with a STRING, because a string is what a card
/// renders. A visualisation's parameters are not rendered — they drive shader
/// uniforms typed as numbers — so all four of a `TempBar`'s arrived as `None` and
/// the uniform got 0: seven days of different temperatures, seven identical flat
/// bars. `AqiContour` was worse than flat. Its latitude and longitude were 0, so
/// it drew a real air-quality contour for 0°N 0°E, the Gulf of Guinea, under a
/// caption naming the user's city.
///
/// And a `Grid(cols: 2)` drew one tile per line, because the kit took a flat
/// child list and the node model renders a grid as a column. `cols` was honoured
/// only by `makepad::lower`, which is not the path the device renders through.
#[test]
fn a_visualisations_parameters_are_numbers_and_a_grid_is_rows() {
    let data = serde_json::json!({ "env": { "locale": {} }, "copy": {} });
    let root = realize(WEATHER, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let kit = octoscript_ui_l0::kit::lower(&root);

    // All seven bars, and the week's range they are a fraction of.
    assert_eq!(
        kit.matches("l0_tempbar(sys.num(").count(),
        7,
        "every bar's low must arrive as a number:\n{kit}"
    );
    assert!(
        kit.contains("sys.num(sys.weekmin(") && kit.contains("sys.num(sys.weekmax("),
        "so must the range:\n{kit}"
    );
    // The contour's location, or it draws a real reading for the wrong place.
    assert!(
        kit.contains("l0_aqicontour(sys.num("),
        "the contour must be located by numbers:\n{kit}"
    );

    // A grid is rows now, not a flat list the theme renders as a column.
    assert!(
        !kit.contains("l0_grid("),
        "the flat grid call must be gone:\n{kit}"
    );
    assert_eq!(
        kit.matches("l0_tile(").count(),
        6,
        "the six detail tiles are still all there:\n{kit}"
    );
}

/// Every field the vocabulary offers must be one a backend can ANSWER.
///
/// §4 predicted this and left it: "a field can be declared here, accepted by the
/// checker, and still unanswerable by a given backend… Closing that needs a
/// conformance test per backend asserting it answers everything declared here.
/// This table is what such a test would check against; it is not the test."
///
/// This is the test. It compares the vocabulary against the TRANSLATION rather
/// than against the TOML — the two existing catalog tests both compare Octoscript
/// with itself, which is why every defect of this shape got through: `dayname`
/// called with three of four arguments, `min_lo`/`max_hi` with no arm at all,
/// `sys.search` demanding an index, `visibility` offered by the vocabulary and
/// requested by no URL. A card asks for it, the checker accepts, and the screen
/// shows an em dash indistinguishable from data still in flight.
#[test]
fn every_offered_field_has_a_translation() {
    use octoscript_ui_l0::catalog;
    // Fields the vocabulary offers that THIS backend cannot answer. May only
    // shrink, and each needs a reason.
    const UNANSWERED: &[(&str, &str)] = &[
        // ── the helper genuinely cannot answer ────────────────────────────────
        // open-meteo serves visibility as an HOURLY variable only; there is no
        // `current.visibility`, so answering means requesting the hourly series
        // and indexing the current hour, which the helper does not do.
        ("sys.weather", "visibility"),
        // `sys.stock` fetches the CHART endpoint, which carries neither market
        // cap nor P/E. The existing arm says so in a comment; this makes it a
        // fact the build checks rather than a note someone may read.
        ("sys.quote", "mktcap"),
        ("sys.quote", "pe"),
        ("sys.movers", "pe"),
        ("sys.watchlist", "pe"),
        // ── a capability with NO translation at all ───────────────────────────
        // Every one of these renders an em dash today. `sys.route` is why the
        // nav card's duration and distance row is `— —`, and `sys.locale` is why
        // `state units { initial: env.locale.temp_unit }` seeds from nothing —
        // which is half of why the units toggle appears to do nothing.
        // A route's step LIST is a collection a card loops over, not a scalar a
        // call answers. Duration and distance used to sit here beside it and no
        // longer do: both are answered, and the probe now supplies the
        // coordinates that prove it.
        //
        // `sys.locale`, `sys.news_item`, `sys.prefs` and `sys.series` sat here too,
        // and that is the shape of the mistake: FOUR WHOLE CAPABILITIES parked in an
        // allowlist under a comment saying they render an em dash, while the catalog
        // went on documenting them and the checker went on accepting them. Six of the
        // seven exemplars reach for `sys.locale`. A list of known gaps is only worth
        // keeping if it is drained; this one recorded the defect and then held it
        // still. All four are answered now.
        ("sys.route", "steps"),
        // ── a field the arm forgot ────────────────────────────────────────────
        // Each of these sits beside fields the same arm answers, so the
        // capability works and one value on the card does not.
        ("sys.geocode", "population"),
        ("sys.quote", "ticker"),
        ("sys.quote", "prev"),
        ("sys.quote", "currency"),
        ("sys.quote", "exchange"),
        ("sys.movers", "prev"),
        ("sys.movers", "currency"),
        ("sys.movers", "exchange"),
        ("sys.watchlist", "prev"),
        ("sys.watchlist", "currency"),
        ("sys.watchlist", "exchange"),
        ("sys.places", "id"),
        ("sys.search", "id"),
        ("sys.search", "distance"),
        // `days` is the COLLECTION a forecast loops over, not a value read off
        // it, so no single call answers it. The loop is what consumes it.
        ("sys.weather", "days"),
    ];

    let mut missing: Vec<(String, String)> = Vec::new();
    for (capability, fields) in catalog::ANSWERS {
        for field in *fields {
            // A collection is addressed by row; ask for row 0.
            let answered = [field.to_string(), format!("0.{field}")].iter().any(|f| {
                octoscript_ui_l0::makepad::vm_call(&octoscript_ui_l0::SourceBinding {
                    helper: (*capability).to_string(),
                    // Arguments every helper of this shape needs. A missing
                    // one makes the arm bail for the wrong reason, so they
                    // are all supplied.
                    args: vec![
                        ("lat".into(), "1".into()),
                        ("lon".into(), "2".into()),
                        ("ticker".into(), "N".into()),
                        ("query".into(), "q".into()),
                        ("countries".into(), "CHN".into()),
                        ("indicator".into(), "NY.GDP.MKTP.KD.ZG".into()),
                        ("name".into(), "n".into()),
                        ("id".into(), "1".into()),
                        ("category".into(), "c".into()),
                        // A trip's four coordinates, and the device's two.
                        //
                        // These were missing, and their absence put `sys.route`
                        // on the allowlist below as an em dash the card could not
                        // avoid — for two releases AFTER the arm that answers it
                        // was written. The arm bailed on `arg("from_lat")?`, the
                        // probe read that as "no translation exists", and the
                        // allowlist recorded a defect that had been fixed. An
                        // allowlist that accumulates entries nothing verifies is
                        // worse than no allowlist: it reports the codebase as
                        // more broken than it is, which is the one direction that
                        // stops anyone acting on it.
                        ("from_lat".into(), "1".into()),
                        ("from_lon".into(), "2".into()),
                        ("to_lat".into(), "3".into()),
                        ("to_lon".into(), "4".into()),
                        ("at_lat".into(), "5".into()),
                        ("at_lon".into(), "6".into()),
                    ],
                    field: f.clone(),
                })
                .is_some()
            });
            if !answered {
                missing.push(((*capability).to_string(), (*field).to_string()));
            }
        }
    }

    let known: Vec<(String, String)> = UNANSWERED
        .iter()
        .map(|(c, f)| (c.to_string(), f.to_string()))
        .collect();
    let mut fresh: Vec<_> = missing.iter().filter(|p| !known.contains(p)).collect();
    fresh.sort();
    // And the list may only SHRINK, exactly as `INERT` and `STALE` may.
    //
    // This assertion was missing here alone, and a review caught it: an entry whose
    // gap has since been closed stays forever, so the list reads as 35 known holes
    // when some number of them are already fixed. That is the direction that stops
    // anyone acting on it — the same rot that kept `sys.route` listed as unanswered
    // for releases after its translation was written.
    let mut fixed: Vec<_> = known.iter().filter(|p| !missing.contains(p)).collect();
    fixed.sort();
    assert!(
        fixed.is_empty(),
        "these are answered now — delete them from UNANSWERED: {fixed:#?}"
    );
    assert!(
        fresh.is_empty(),
        "the vocabulary offers these and no backend call answers them, so a card \
         that asks renders an em dash the checker cannot warn about: {fresh:#?}"
    );
}

/// The nav card routes between two EDITABLE places, and says how far.
///
/// Three things were wrong at once and each hid the next.
///
/// The `Field` sat behind `when dest == ""`, so a card opening with the trip
/// already known — which is every card whose request named the places — had no
/// input at all. Measured on device: the model generated a card containing only a
/// `Map`, and there was no way to change where you were going.
///
/// `sys.route` had no translation, because its `from`/`to` were PLACES: a route
/// needs four numbers and an argument carries one value, so a place name had
/// nothing to resolve into. Duration and distance rendered `— —` beneath a route
/// that drew correctly — the map resolved its endpoints and the text beside it
/// could not.
///
/// And the map routed from `sys.gps` while the user edited a FROM field the map
/// ignored.
#[test]
fn the_nav_card_routes_between_two_editable_places() {
    const NAV: &str = include_str!("fixtures/nav.card");
    let report = check_ui_l0_named("nav", NAV);
    assert!(report.valid, "{:#?}", report.diagnostics);

    let data = serde_json::json!({
        "origin": "Saratoga High", "dest": "Stanford University", "query": "",
        "found": [], "env": { "locale": {} },
        "copy": { "from": "FROM", "to": "TO", "where": "Where to?",
                  "here_now": "Starting from…", "away": " away", "seeking": "…",
                  "eta": "ETA", "nostop": "stop" }
    });
    let root = realize(NAV, &data, RealizeLimits::default())
        .root
        .expect("realizes");
    let kit = octoscript_ui_l0::kit::lower(&root);

    // NO field on the resting sheet, and a TAP TARGET on each endpoint.
    //
    // This asserted two fields, always on screen — the design that made both
    // endpoints permanently live inputs. It is the wrong design on this renderer and
    // the assertion is what made that look correct: a `TextInput` inside a card never
    // receives the draw that presents the keyboard, so both fields were inert, and a
    // test counting `l0_field(` cannot tell a reachable field from a dead one.
    // Measured on a OnePlus 6 — the tap arrives, `set_key_focus` runs, no draw
    // follows, and the IME call inside `draw_walk` is never reached.
    //
    // So a name row is a ROW that opens the find state, exactly as the L2 card does,
    // and only the row being edited is a field. What this asserts now is the property
    // that failed on the phone: from the resting sheet, each endpoint can be REACHED.
    assert_eq!(
        kit.matches("l0_field(").count(),
        0,
        "a resting sheet has no live field, only tappable rows:\n{kit}"
    );
    for event in ["edit_origin", "edit_dest"] {
        assert!(
            kit.contains(event),
            "the resting sheet offers {event}:\n{kit}"
        );
    }
    // And opening one turns THAT row into a field, so a keyboard-capable renderer
    // still gets one — and picking a result works without one either way.
    for (event, target) in [
        ("edit_origin", "choose_origin"),
        ("edit_dest", "choose_dest"),
    ] {
        let mut store = octoscript_ui_l0::InstanceStore::default();
        octoscript_ui_l0::dispatch_reporting(NAV, &mut store, "root", event, None, &data);
        let open = octoscript_ui_l0::kit::lower(
            &octoscript_ui_l0::realize_with_state(NAV, &data, &store, RealizeLimits::default())
                .root
                .expect("realizes"),
        );
        assert_eq!(
            open.matches("l0_field(").count(),
            1,
            "{event} makes exactly the row it opened a field:\n{open}"
        );
        assert!(
            open.contains(target),
            "{event} offers a pickable place through {target}:\n{open}"
        );
    }
    let opened = {
        let mut store = octoscript_ui_l0::InstanceStore::default();
        octoscript_ui_l0::dispatch_reporting(NAV, &mut store, "root", "add_stop", None, &data);
        octoscript_ui_l0::kit::lower(
            &octoscript_ui_l0::realize_with_state(NAV, &data, &store, RealizeLimits::default())
                .root
                .expect("realizes"),
        )
    };
    assert_eq!(
        opened.matches("l0_field(").count(),
        1,
        "and a stop, one tap away:\n{opened}"
    );
    // The trip's facts, live, from the coordinates of the places that were found.
    assert!(
        kit.contains("sys.navroute(sys.searchnum(\"Saratoga High\", 0, \"lat\")"),
        "duration and distance must be fetched for THIS trip:\n{kit}"
    );
    // And the map routes from the origin the user can edit.
    assert!(
        kit.contains("l0_map(") && kit.contains("sys.searchnum(\"Stanford University\""),
        "the map must route between the same two places:\n{kit}"
    );
}

/// A role admitted once must be lowered TWICE.
///
/// This is the third time one backend had a role the other did not, and each time
/// the card was accepted, rendered, and wrong in one of the two places it can
/// render. `Map` was lowered by neither and drew an error box; `Grid.cols` was
/// honoured by the kit and ignored by makepad, so a two-column grid was a column;
/// `Field` was lowered by the kit and by makepad not at all, so the nav card's two
/// editable rows — the whole of "the map planner cannot change where it is going"
/// — came out as two red warnings reading "no makepad lowering for Field".
///
/// The pattern is structural rather than careless: the catalog is one table and
/// the lowerings are two functions, so nothing makes adding to the first add to
/// both. This is what makes it, for every role the catalog admits.
#[test]
fn every_admitted_role_is_lowered_by_both_backends() {
    const CONTAINERS: &[&str] = &["Surface", "Photo", "Panel", "Card", "Col", "Row", "Grid"];
    let mut missing: Vec<String> = Vec::new();

    for (role, args) in octoscript_ui_l0::catalog::CONSTRUCTORS {
        // Instantiate the way a card would: several roles refuse a partial
        // argument set, and a probe that omits them tests nothing.
        let arglist: Vec<String> = args
            .iter()
            .filter_map(|(n, k)| {
                use octoscript_ui_l0::catalog::ArgKind::*;
                match k {
                    Path | Data | Text => Some(format!("{n}: q.name")),
                    Number => Some(format!("{n}: 2")),
                    Token(set) | TokenOrPath(set) => Some(format!("{n}: .{}", set[0])),
                    Event => Some(format!("{n}: ev")),
                    Any => Some(format!("{n}: \"x\"")),
                    Bool => None,
                }
            })
            .collect();
        let body = if CONTAINERS.contains(role) {
            " { Rule() }"
        } else {
            ""
        };
        let head = "source q sys.quote(ticker: \"NVDA\", fields: [last, name])\n\
                    state held { shape: text, initial: \"\" }\n\
                    event ev { held: set($value) }\n";
        let card = if *role == "Surface" || *role == "Photo" {
            format!(
                "{head}view root {role}({}) {{ Rule() }}\n",
                arglist.join(", ")
            )
        } else {
            format!(
                "{head}view root Surface {{ {role}({}){body} }}\n",
                arglist.join(", ")
            )
        };
        if !check_ui_l0_named("probe", &card).valid {
            continue; // covered by the catalog-agreement tests
        }
        let data = serde_json::json!({
            "q": { "last": 1.0, "name": "n" }, "held": "",
            "env": { "locale": {} }, "copy": {}
        });
        let Some(root) = realize(&card, &data, RealizeLimits::default()).root else {
            continue;
        };
        // Each backend says so in its own words, and both say the role's name.
        let mk = makepad::lower(&root);
        if mk.contains(&format!("no makepad lowering for {role}")) {
            missing.push(format!("makepad: {role}"));
        }
        let kit = octoscript_ui_l0::kit::lower(&root);
        if kit.contains(&format!("l0_unsupported({role:?})")) {
            missing.push(format!("kit: {role}"));
        }
    }

    missing.sort();
    assert!(
        missing.is_empty(),
        "the catalog admits these and a backend cannot draw them, so the card is \
         accepted and renders an apology where the role goes: {missing:#?}"
    );
}

/// A card holding a map is laid out the way the SHIPPING nav card lays one out.
///
/// Every value in this test came off `a2app/apps/nav` rather than out of a guess,
/// and the reason is a run of four device screenshots that each looked like a
/// different bug and were all this one.
///
/// `MapView` is a fixed-pixel full-bleed surface that paints its route through the
/// GPU nav projection rather than inside a laid-out rect. Stacked in a column it
/// draws straight over the card: the plan screen's map covered the FROM/TO fields,
/// the duration and the Go button completely, and the drive screen's ribbon painted
/// across the turn banner and cut a street name in half.
///
/// So the map is the bottom layer of an overlay and the card's content floats over
/// it, which is what all four of the shipping card's maps do. The three values that
/// each cost a screenshot to learn:
///
///   - the root is a FIXED 812, not `Fill` — `Fill` in a `Fit` parent resolves to
///     0, and a card is an item in a chat list, so the whole screen came out empty
///   - the sheet is OPAQUE — the theme's 7%-white panel over a map is a window,
///     and the map's own labels read straight through the trip
///   - the sheet sits at the BOTTOM — `update_plan_preview_camera` frames the route
///     into the band above the sheet, so a sheet at the top lands exactly on the
///     route it was making room for
#[test]
fn a_card_holding_a_map_floats_its_content_over_it() {
    const NAV: &str = include_str!("fixtures/nav.card");
    let data = serde_json::json!({
        "origin": "Saratoga High", "dest": "Stanford", "query": "", "screen": "plan",
        "found": [], "here": { "lat": -9999, "lon": -9999, "ok": 0 },
        "step": { "instruction": "s", "remaining": "s" },
        "env": { "locale": {} },
        "copy": { "from": "FROM", "to": "TO", "where": "?", "here_now": "…",
                  "away": "away", "seeking": "…", "start": "Go", "stop": "End",
                  "left": "left" }
    });
    let mk = makepad::lower(
        &realize(NAV, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );

    // An overlay at a FIXED height, because `Fill` resolves to 0 in a `Fit` parent.
    assert!(
        mk.contains("height: 812 flow: Overlay"),
        "the root must be a fixed-height overlay:\n{mk}"
    );
    // The map FIRST — it is the layer everything else sits on.
    let map_at = mk.find("MapView{").expect("a map");
    let sheet_at = mk
        .find("RoundedView{ width: Fill height: Fit")
        .expect("a sheet");
    assert!(
        map_at < sheet_at,
        "the map must be the bottom layer, not drawn over the card:\n{mk}"
    );
    // Opaque, and at the bottom where the preview camera leaves room for it.
    assert!(
        mk.contains("draw_bg.color: #0f1620") && mk.contains("Align{x: 0.5 y: 1.0}"),
        "the sheet must be opaque and bottom-aligned:\n{mk}"
    );
    // A `.top` panel goes in its own band ABOVE the sheet, which is where a turn
    // instruction belongs and where the app this replaces puts it.
    const DOCKED: &str = concat!(
        "copy a { class: vocabulary, en: \"turn left\" }\n",
        "copy b { class: vocabulary, en: \"2 km\" }\n",
        "source o sys.search(query: state.q, count: 1, fields: [id, name, lat, lon])\n",
        "state q { shape: text, initial: \"A\" }\n",
        "view root Surface {\n",
        "  Panel(dock: .top) { TextRow(text: copy.a) }\n",
        "  Panel(dock: .bottom) { TextRow(text: copy.b) Reveal { Rule() } }\n",
        "  Map(mode: .plan, from: o, to: o, zoom: 14)\n",
        "}\n"
    );
    let docked_report = check_ui_l0_named("nav", DOCKED);
    assert!(docked_report.valid, "{:#?}", docked_report.diagnostics);
    let docked = octoscript_ui_l0::kit::lower(
        &realize(
            DOCKED,
            &serde_json::json!({
                "o": [{ "id": "1", "name": "n", "lat": 1.0, "lon": 2.0 }], "q": "A",
                "env": { "locale": {} }, "copy": { "a": "turn left", "b": "2 km" }
            }),
            RealizeLimits::default(),
        )
        .root
        .expect("realizes"),
    );
    // Three slots: the map, then the top band, then the sheet — in that order, so
    // the top panel's content precedes the bottom panel's.
    let top_at = docked.find("turn left").expect("the top panel");
    let bottom_at = docked.find("2 km").expect("the sheet");
    assert!(
        top_at < bottom_at,
        "a .top panel must be emitted into the top band, before the sheet:\n{docked}"
    );
    assert!(
        docked.contains("l0_reveal("),
        "a Reveal must lower to the kit's hidden container:\n{docked}"
    );

    // And a card with NO map keeps the ordinary column — this is a map's rule.
    const PLAIN: &str = "copy a { class: vocabulary, en: \"x\" }\n                         view root Surface { TextRow(text: copy.a) }\n";
    let plain = makepad::lower(
        &realize(
            PLAIN,
            &serde_json::json!({ "copy": { "a": "x" }, "env": { "locale": {} } }),
            RealizeLimits::default(),
        )
        .root
        .expect("realizes"),
    );
    assert!(
        plain.contains("flow: Down") && !plain.contains("flow: Overlay"),
        "a card without a map is still a column:\n{plain}"
    );
}

/// BOTH backends float a map card's content over the map.
///
/// The kit is the backend the DEVICE renders through — the app's chain is
/// `kit::lower` -> `_kit.octoscript` -> its VM -> `l0_widgets` — and `makepad::lower` is
/// what the other host renders. So a layout fix in one of them is verified in
/// neither.
///
/// This test exists because that happened. The map-card overlay was written into
/// both, screenshot-verified through `makepad::lower` on a real phone, and the kit
/// arm was DEAD CODE: an earlier `"Surface" =>` arm matched first, so `l0_surface`
/// still built a column and a generated card on the device still had its map drawn
/// over its content. `rustc` said `unreachable pattern` and pointed at the line; the
/// clippy filter in use grepped for `^error` and dropped it.
///
/// A shadowed match arm is invisible at runtime — the code is there, reads
/// correctly, and never runs. Asserting on the OUTPUT is the only thing that
/// notices.
#[test]
fn both_backends_float_a_map_cards_content_over_the_map() {
    const NAV: &str = include_str!("fixtures/nav.card");
    let data = serde_json::json!({
        "origin": "A", "dest": "B", "query": "", "screen": "plan", "found": [],
        "here": { "lat": -9999, "lon": -9999, "ok": 0 },
        "step": { "instruction": "s", "remaining": "s" },
        "env": { "locale": {} },
        "copy": { "from": "F", "to": "T", "where": "?", "here_now": "…",
                  "away": "away", "seeking": "…", "start": "Go", "stop": "End",
                  "left": "left" }
    });
    let root = realize(NAV, &data, RealizeLimits::default())
        .root
        .expect("realizes");

    // The kit composes the overlay through its own role, not the plain surface.
    let kit = octoscript_ui_l0::kit::lower(&root);
    assert!(
        kit.contains("l0_surface_map("),
        "the kit must build the map card, not a column:\n{kit}"
    );
    assert!(
        !kit.contains("l0_surface(") || kit.matches("l0_surface(").count() == 0,
        "and must not ALSO emit the column surface:\n{kit}"
    );
    // The map is the first argument, so it is the bottom layer.
    let head = &kit[kit.find("l0_surface_map(").unwrap()..];
    assert!(
        head[..40.min(head.len())].contains("l0_map("),
        "the map must be the overlay's first layer:\n{head}"
    );

    // And the other backend, which a different host renders.
    let mk = makepad::lower(&root);
    assert!(
        mk.contains("flow: Overlay") && mk.find("MapView{") < mk.find("RoundedView{ width: Fill"),
        "makepad must float the content over the map too:\n{mk}"
    );
}

/// The travel mode decides the duration, and it used to be dropped.
///
/// `sys.route(mode:)` was accepted by the catalog, documented, and never emitted —
/// so a card asking how long a trip takes on foot was answered with how long it
/// takes by car. The same number under a lit "Walk" chip: accepted, rendered,
/// confidently wrong, which is this profile's whole defect class.
///
/// Walk and bike are the HOST's estimates from the measured distance, because the
/// public OSRM server serves the driving graph whatever profile it is asked for —
/// verified against it: `foot`, `bike` and `cycling` all return the driving answer.
/// The estimate is the host's to make; the card still states no duration.
#[test]
fn the_travel_mode_decides_the_duration() {
    const CARD: &str = concat!(
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "source trip sys.route(from_lat: o.0.lat, from_lon: o.0.lon,\n",
        "                      to_lat: d.0.lat, to_lon: d.0.lon,\n",
        "                      mode: state.mode, fields: [duration, distance])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "state mode   { shape: enum[drive, walk, bike], initial: .drive }\n",
        "event pick_mode { mode: set($value) }\n",
        "copy dr { class: vocabulary, en: \"Drive\" }\n",
        "view root Surface {\n",
        "  Chip(text: copy.dr, on_tap: pick_mode, value: .walk, active: mode == .walk)\n",
        "  TextValue(value: trip.duration)\n",
        "  TextCaption(value: trip.distance)\n",
        "}\n"
    );
    assert!(
        check_ui_l0_named("nav", CARD).valid,
        "{:#?}",
        check_ui_l0_named("nav", CARD).diagnostics
    );

    // Each mode must pick a DIFFERENT field off the helper. Asserting they differ
    // is the point: a dropped argument makes all three identical, and all three
    // plausible.
    let mut seen = Vec::new();
    for mode in ["drive", "walk", "bike"] {
        let data = serde_json::json!({
            "origin": "A", "dest": "B", "mode": mode,
            "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
            "trip": { "duration": "SEEDED", "distance": "SEEDED" },
            "env": { "locale": {} }, "copy": { "dr": "Drive" }
        });
        let kit = octoscript_ui_l0::kit::lower(
            &realize(CARD, &data, RealizeLimits::default())
                .root
                .expect("realizes"),
        );
        let key = ["\"min\")", "\"walk\")", "\"bike\")"]
            .iter()
            .find(|k| kit.contains(*k))
            .unwrap_or_else(|| panic!("no duration field for {mode}:\n{kit}"));
        seen.push((mode, *key));
        // Distance is the same geometry either way and must not vary with mode.
        assert!(
            kit.contains("\"km\")"),
            "{mode}: distance is the same geometry whatever the mode:\n{kit}"
        );
    }
    assert_eq!(
        seen,
        vec![
            ("drive", "\"min\")"),
            ("walk", "\"walk\")"),
            ("bike", "\"bike\")")
        ],
        "each mode must ask the helper for its own duration"
    );
}

/// A trip with a stop routes THROUGH it, and the map draws the same trip.
///
/// `via:` was accepted by the catalog and emitted by nothing. So a card could offer
/// "add a stop", accept a place, show it in the list — and route straight past it:
/// the line went origin to destination, and the duration beside it was the direct
/// trip's. Everything on screen agreed with everything else and none of it was the
/// journey the user asked for.
///
/// Two bugs had to be fixed to get here, and both were silent. The list parser took
/// every token as its own item, so `[stop.0.lat, stop.0.lon]` became six items —
/// `stop`, `0`, `lat`, … — and resolved to nothing. And a source read from inside a
/// list argument did not count as a read, so the stop's own `sys.search` was
/// reported as declared and never used.
#[test]
fn a_trip_through_a_stop_routes_through_it() {
    const CARD: &str = concat!(
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source s sys.search(query: state.stop, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "source trip sys.route(from_lat: o.0.lat, from_lon: o.0.lon,\n",
        "                      to_lat: d.0.lat, to_lon: d.0.lon,\n",
        "                      via: [s.0.lat, s.0.lon],\n",
        "                      mode: .drive, fields: [duration, distance])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state stop   { shape: text, initial: \"S\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "view root Surface {\n",
        "  TextValue(value: trip.duration)\n",
        "  Map(mode: .plan, from: o, to: d, via: s, zoom: 14)\n",
        "}\n"
    );
    let report = check_ui_l0_named("nav", CARD);
    assert!(report.valid, "{:#?}", report.diagnostics);

    let data = serde_json::json!({
        "origin": "A", "stop": "S", "dest": "B",
        "o": [{ "lat": 1.0, "lon": 2.0 }], "s": [{ "lat": 5.0, "lon": 6.0 }],
        "d": [{ "lat": 3.0, "lon": 4.0 }],
        "trip": { "duration": "SEEDED", "distance": "SEEDED" },
        "env": { "locale": {} }, "copy": {}
    });
    let root = realize(CARD, &data, RealizeLimits::default())
        .root
        .expect("realizes");

    for (which, lowered) in [
        ("kit", octoscript_ui_l0::kit::lower(&root)),
        ("makepad", makepad::lower(&root)),
    ] {
        // The waypoint reaches the helper's sixth argument, assembled from the
        // stop's own coordinate calls rather than baked as a literal.
        let vias =
            "\"\" + sys.searchnum(\"S\", 0, \"lat\") + \",\" + sys.searchnum(\"S\", 0, \"lon\")";
        assert!(
            lowered.contains(vias),
            "{which}: the trip must be routed through the stop:\n{lowered}"
        );
        // BOTH the reported trip and the drawn one. A map that omits the vias
        // draws a different journey from the numbers printed beside it.
        assert_eq!(
            lowered.matches(vias).count(),
            2,
            "{which}: the duration and the polyline must both go via the stop:\n{lowered}"
        );
        // And the seeded coordinates never appear as literals.
        for seeded in ["5", "6"] {
            assert!(
                !lowered.contains(&format!("\"{seeded}\"")),
                "{which}: {seeded} is the seeded stop coordinate:\n{lowered}"
            );
        }
    }
}

/// The card stays L0 while the LOWERING emits `fn tick()` on its behalf.
///
/// This is the load-bearing distinction, and worth asserting because the performance
/// work looks like it crossed the line and does not.
///
/// A driving card cannot be re-resolved without a visible stall — measured on a
/// OnePlus 6, frame hitches and card re-resolves correlate 1:1, up to 327 ms — so its
/// live values update in place from a generated `fn tick()`, exactly as the 664-line
/// L2 exemplar does with `ui.instr.set_text()`.
///
/// The difference is WHO WROTE IT. That exemplar is L2 because its own source contains
/// `fn tick()`, 30 `let` bindings and 606 operators, written by its author. This card
/// contains none: it says `TextRow(text: step.instruction)`, and the tick is derived
/// mechanically from that declaration. §7 classifies a CARD, and the profile constrains
/// what a card may say — not what a compiler may emit for it, any more than
/// `sys.navroute(...)` in the output makes a card that wrote `sys.route` into L2.
#[test]
fn the_card_holds_no_tick_however_much_the_lowering_emits() {
    const NAV: &str = include_str!("fixtures/nav.card");
    assert_eq!(check_ui_l0_named("nav", NAV).level, Level::L0);

    // Not one L2 construct in the card's own declarations. The comments discuss the
    // tick at length, which is why they are stripped rather than searched.
    let code: String = NAV
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for construct in ["fn ", "let ", "ui.", ".set_"] {
        assert!(
            !code.contains(construct),
            "the card must not contain {construct:?} — that is what would make it L2"
        );
    }
}

/// A lowering with every string literal removed — the code it would run.
fn strip_literals(src: &str) -> String {
    let mut out = String::new();
    let mut chars = src.chars();
    let mut in_str = false;
    while let Some(c) = chars.next() {
        match c {
            // An escape consumes its partner, so `\"` never ends the literal.
            '\\' if in_str => {
                chars.next();
            }
            '"' => in_str = !in_str,
            _ if !in_str => out.push(c),
            _ => {}
        }
    }
    out
}

/// Card state may change what a LITERAL contains, and nothing else.
///
/// State reaches generated code as an argument — a place name becomes
/// `sys.searchnum("Saratoga High School", 0, "lat")` — and that generated code is now
/// also the body of a `fn tick()` the VM runs every frame. So the quoting is a
/// confinement boundary rather than a formatting detail: state that could close its own
/// quote would be writing script into the tick.
///
/// Two earlier versions of this test were wrong in instructive ways. Asserting the
/// hostile text was simply absent failed, correctly — `ui.evil` DOES appear in the
/// output, escaped, inside a quoted argument, and is inert there. Asserting the
/// literal-stripped skeleton held no `let ` failed too, because the kit emits its own
/// `let node = …`. The claim is that state cannot MOVE the boundary, and a diff of the
/// skeletons says exactly that. Verified by removing the quoting in `source_binding`:
/// every case below then differs from the benign skeleton and the test fails.
#[test]
fn card_state_cannot_write_script_into_the_lowering() {
    const CARD: &str = concat!(
        "source found sys.search(query: state.q, count: 1, fields: [id, name, lat, lon])\n",
        "state q { shape: text, initial: \"\" }\n",
        "view root Surface { TextRow(text: found.0.name) }\n"
    );
    let lower_with = |q: &str| {
        let data = serde_json::json!({
            "q": q,
            "found": [{ "id": "1", "name": "n", "lat": 1.0, "lon": 2.0 }],
            "env": { "locale": {} }, "copy": {}
        });
        let kit = octoscript_ui_l0::kit::lower(
            &realize(CARD, &data, RealizeLimits::default())
                .root
                .expect("realizes"),
        );
        strip_literals(&kit)
    };
    let benign = lower_with("Saratoga");

    for hostile in [
        "x\") ui.evil.set_text(\"owned",
        "x\", 0, \"lat\") + sys.gps(\"lat",
        "x\") } fn tick() { ui.a.set_text(\"",
        "x\nlet escaped = 1",
    ] {
        assert_eq!(
            lower_with(hostile),
            benign,
            "card state changed the CODE, not just a literal, for {hostile:?}"
        );
    }
}

/// A numeric argument may be a number or a call this lowering made. Nothing else.
///
/// A numeric slot is interpolated UNQUOTED — `sys.weather({lat}, {lon}, …)` — so
/// whatever lands there is code. String slots are safe by construction because `{:?}`
/// quotes them; this is the other half, and it was missing.
///
/// `source now sys.weather(lat: "1 + sys.navsecs(1)", …)` passed the checker as an
/// ordinary L0 card and lowered to `sys.weather(1 + sys.navsecs(1), 2, …)`: arithmetic
/// and a host call the card never declared, in a language whose defining property is
/// that it has no expression form. Found in an external review of the refactoring.
///
/// The card is still ACCEPTED — a quoted string is a legitimate thing to write, and
/// the profile does not type source arguments — but it translates to nothing, so the
/// value stays seeded instead of becoming an injection site.
#[test]
fn a_numeric_argument_cannot_carry_an_expression() {
    const HOSTILE: &str = concat!(
        "source now sys.weather(lat: \"1 + sys.navsecs(1)\", lon: 2, days: 1, fields: [temp])\n",
        "view root Surface { TextValue(value: now.temp) }\n"
    );
    let data = serde_json::json!({
        "now": { "temp": 1.0 }, "env": { "locale": {} }, "copy": {}
    });
    let kit = octoscript_ui_l0::kit::lower(
        &realize(HOSTILE, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );
    assert!(
        !kit.contains("navsecs"),
        "an expression reached a numeric slot:\n{kit}"
    );
    assert!(
        !kit.contains("sys.weather("),
        "a rejected argument must yield NO translation, not a partial one:\n{kit}"
    );

    // And the honest case still lowers, or the guard would be a denial of service.
    const GOOD: &str = concat!(
        "source place sys.geocode(name: state.city)\n",
        "source now sys.weather(lat: place.lat, lon: place.lon, days: 1, fields: [temp])\n",
        "state city { shape: text, initial: \"Kyoto\" }\n",
        "view root Surface { TextValue(value: now.temp) }\n"
    );
    let good = octoscript_ui_l0::kit::lower(
        &realize(
            GOOD,
            &serde_json::json!({
                "place": { "lat": 35.0, "lon": 135.8 }, "now": { "temp": 21.0 },
                "city": "Kyoto", "env": { "locale": {} }, "copy": {}
            }),
            RealizeLimits::default(),
        )
        .root
        .expect("realizes"),
    );
    assert!(
        good.contains("sys.weather(sys.geocodenum("),
        "a generated call is ours and must pass through:\n{good}"
    );
}

/// The sheet's two numbers must be two DIFFERENT questions.
///
/// A driver reads "how long" and "how far", and the helper answers them from
/// separate fields — `remmin` and `rem`. The failure this guards is the one this
/// profile keeps producing: `eta` falling through to the distance's field, so the
/// sheet shows the same measurement twice, once big and once small, both correct
/// and neither the arrival time. Nothing on such a screen looks wrong.
///
/// Both backends, because the device renders the kit one and the desk renders the
/// other, and a field mapped in one is not mapped in both.
#[test]
fn how_long_is_left_and_how_far_is_left_are_different_questions() {
    const CARD: &str = concat!(
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "source here sys.gps()\n",
        "source step sys.step(from_lat: o.0.lat, from_lon: o.0.lon,\n",
        "                     to_lat: d.0.lat, to_lon: d.0.lon,\n",
        "                     at_lat: here.lat, at_lon: here.lon,\n",
        "                     fields: [instruction, remaining, eta])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "view root Surface {\n",
        "  TextHero(value: step.eta, unit: .duration)\n",
        "  TextCaption(value: step.remaining)\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let data = serde_json::json!({
        "origin": "A", "dest": "B",
        "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
        "here": { "lat": 1.5, "lon": 2.5 },
        "step": { "instruction": "SEEDED", "remaining": "SEEDED", "eta": "SEEDED" },
        "env": { "locale": {} }
    });
    let root = realize(CARD, &data, RealizeLimits::default())
        .root
        .expect("realizes");

    for (backend, dsl) in [
        ("kit", octoscript_ui_l0::kit::lower(&root)),
        ("makepad", octoscript_ui_l0::makepad::lower(&root)),
    ] {
        assert!(
            dsl.contains("\"remmin\")"),
            "{backend}: the hero must ask how many minutes are left:\n{dsl}"
        );
        assert!(
            dsl.contains("\"rem\")"),
            "{backend}: the caption must ask how far is left:\n{dsl}"
        );
        // The unit is the theme's word, and without it "34" beside "26.8 km"
        // is a second distance.
        assert!(
            dsl.contains("\"remmin\") + \" min\""),
            "{backend}: a bare minute count reads as a distance:\n{dsl}"
        );
    }
}

/// A docked panel's content sits IN the dock, not in a box inside it.
///
/// `l0_surface_map` draws the band and the sheet itself. Emitting the `Panel` as
/// well nested an `l0_panel` inside each — a second rounded fill, and because that
/// wrapper is full-width the sheet's centring applied to the wrapper rather than
/// to the number in it, so the hero left-aligned and the caption under it was
/// pushed off the bottom of the screen by the wrapper's own margin.
///
/// The second half of the test is the part that would otherwise rot: an UNdocked
/// child must still be emitted whole. Unwrapping everything would emit a chip's
/// children and silently drop the chip.
#[test]
fn a_docked_panel_does_not_draw_a_second_panel_inside_the_dock() {
    const CARD: &str = concat!(
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "copy go { class: vocabulary, en: \"Go\" }\n",
        "event start { origin: set(\"A\") }\n",
        "view root Surface {\n",
        "  Panel(dock: .top) { TextBody(text: copy.go) }\n",
        "  Panel(dock: .bottom) { TextHero(text: copy.go) }\n",
        "  Chip(text: copy.go, on_tap: start)\n",
        "  Map(mode: .plan, from: o, to: d)\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let data = serde_json::json!({
        "origin": "A", "dest": "B",
        "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
        "env": { "locale": {} }, "copy": { "go": "Go" }
    });
    let dsl = octoscript_ui_l0::kit::lower(
        &realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );
    assert!(
        dsl.contains("l0_surface_map("),
        "a card with a Map lowers to the map surface:\n{dsl}"
    );
    assert!(
        !dsl.contains("l0_panel("),
        "the surface already draws the dock; a panel inside it is a second box:\n{dsl}"
    );
    // The undocked chip is still there, chip and all.
    assert!(
        dsl.contains("l0_chip("),
        "an undocked child is emitted whole, not unwrapped:\n{dsl}"
    );

    // The other backend draws the same two docks with its own boxes, and had the
    // same nested wrapper. Both, or the desk and the device disagree about a
    // driving screen — which is how this one survived being looked at.
    let mp = octoscript_ui_l0::makepad::lower(
        &realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );
    let sheet = mp
        .lines()
        .position(|l| l.contains("draw_bg.border_radius: 22"))
        .expect("the sheet is the rounded box at the bottom");
    // The line after the sheet opens is its content, not another box.
    assert!(
        !mp.lines()
            .nth(sheet + 1)
            .unwrap_or("")
            .contains("RoundedView{"),
        "a second box inside the sheet:\n{mp}"
    );
    assert!(
        mp.lines()
            .nth(sheet)
            .unwrap_or("")
            .contains("align: Align{x: 0.5}"),
        "the sheet centres what is in it:\n{mp}"
    );
}

/// A transition reads the value that is ON SCREEN, not the one the card declared.
///
/// Card state resolves store → data → initial when the card is drawn, so a host that
/// seeds `screen: "drive"` gets the drive screen. A transition resolved store →
/// initial and skipped the middle, which made every cycle on a seeded state advance
/// from a value nobody was looking at.
///
/// Concretely, and this is how it was found: `End` on the nav card is
/// `cycle(.plan, .drive)`. Seeded onto the drive screen, it read the declared initial
/// `.plan` and advanced to `.drive` — the screen it was already on. The tap applied,
/// the store changed, the card re-resolved and nothing moved. Three layers reported
/// success and the button was inert.
#[test]
fn a_cycle_advances_from_the_state_the_card_is_showing() {
    const CARD: &str = concat!(
        "state screen { shape: enum[plan, drive], initial: .plan }\n",
        "event go { screen: cycle(.plan, .drive) }\n",
        "copy end { class: vocabulary, en: \"End\" }\n",
        "view root Surface {\n",
        "  when screen == .plan  { TextTitle(text: copy.end) }\n",
        "  when screen == .drive { Chip(text: copy.end, on_tap: go) }\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    // Seeded onto the SECOND member, which is the case that was broken: from the
    // first, a cycle that ignores the seed and one that honours it agree.
    for (seed, after_one_tap) in [("drive", "plan"), ("plan", "drive")] {
        let data = serde_json::json!({
            "screen": seed, "env": { "locale": {} }, "copy": { "end": "End" }
        });
        let mut store = octoscript_ui_l0::InstanceStore::default();
        octoscript_ui_l0::dispatch_reporting(CARD, &mut store, "root", "go", None, &data);
        let dsl = octoscript_ui_l0::kit::lower(
            &octoscript_ui_l0::realize_with_state(CARD, &data, &store, RealizeLimits::default())
                .root
                .expect("realizes"),
        );
        // The drive branch is the one with the tap on it.
        let now = if dsl.contains("l0_chip") {
            "drive"
        } else {
            "plan"
        };
        assert_eq!(
            now, after_one_tap,
            "seeded on {seed:?}, one tap must reach {after_one_tap:?}, not {now:?}:\n{dsl}"
        );
    }
}

/// A map stands pins on the trip it draws, from the SAME coordinates as the line.
///
/// The widget draws pins from `nav_markers`, which was reachable only through
/// `ui.<id>.set_route_markers(…)` — a method call, and a declarative backend sets
/// properties. So the L0 card drew a correct route with no origin or destination pin
/// at all, and `draw_nav_route_pins` returned on its first line. Nothing looked
/// broken; the route was simply less legible than the card it replaced.
///
/// The pins are derived here rather than composed by the card, which is what stops
/// them disagreeing with the line: one set of resolved endpoints feeds both.
#[test]
fn a_map_pins_the_trip_it_draws() {
    const CARD: &str = concat!(
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "source s sys.search(query: state.stop, count: 1, fields: [id, name, lat, lon])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "state stop   { shape: text, initial: \"\" }\n",
        "view root Surface {\n",
        "  when stop == \"\" { Map(mode: .plan, from: o, to: d) }\n",
        "  when stop != \"\" { Map(mode: .plan, from: o, to: d, via: s) }\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let lower = |stop: &str| {
        let data = serde_json::json!({
            "origin": "A", "dest": "B", "stop": stop,
            "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
            "s": [{ "lat": 5.0, "lon": 6.0 }], "env": { "locale": {} }
        });
        octoscript_ui_l0::kit::lower(
            &realize(CARD, &data, RealizeLimits::default())
                .root
                .expect("realizes"),
        )
    };

    // Direct: origin (kind 0) and destination (kind 2), and no stop pin to place.
    let direct = lower("");
    assert!(
        direct.contains("\",0\"") && direct.contains("\",2\""),
        "a direct trip pins both ends:\n{direct}"
    );
    assert!(
        !direct.contains("\",1\""),
        "and has no stop to pin:\n{direct}"
    );

    // Through a stop: a third pin, and it must be the SAME place the route detours
    // through — so the pin's coordinates also appear in the polyline's vias.
    let via = lower("C");
    assert!(via.contains("\",1\""), "a stop is pinned:\n{via}");
    let stop_lat = "sys.searchnum(\"C\", 0, \"lat\")";
    assert!(
        via.matches(stop_lat).count() >= 2,
        "the pinned stop must be the one the line detours through:\n{via}"
    );
}

/// A card's map must survive a data blob that has not answered yet.
///
/// I guarded the drive map on `here.ok` to handle a missing GPS fix, and that is the
/// one mistake this card already carries a note about: a guard is evaluated at
/// REALIZE time, so it can only test what realization can see — declared state, or a
/// source's `$state`. A live value reads NOTHING on a freshly generated card, so
/// BOTH branches were false and the drive screen lowered with no map at all.
///
/// The test that let it through seeded `here` in the blob, which is precisely the
/// case where the bug is invisible. So this one does the opposite: it omits `here`
/// entirely, which is what a card looks like before its first fix lands.
///
/// The sentinel is refused in the widget instead, where the fix and the route are
/// both known — see `is_a_place`.
#[test]
fn a_map_survives_a_source_that_has_not_answered() {
    const CARD: &str = concat!(
        "source here sys.gps()\n",
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "view root Surface {\n",
        "  Map(mode: .drive, from: o, to: d, at: here, view: .tilted, zoom: 17)\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    // NO `here` — the state every generated card starts in.
    let data = serde_json::json!({
        "origin": "A", "dest": "B",
        "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
        "env": { "locale": {} }
    });
    let dsl = octoscript_ui_l0::kit::lower(
        &realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );
    assert_eq!(
        dsl.matches("l0_map(").count(),
        1,
        "a map whose position has not arrived is still a map:\n{dsl}"
    );
    assert!(
        dsl.contains("sys.gps(\"lat\")"),
        "and it still follows the declared position:\n{dsl}"
    );
}

/// Search has to be REACHABLE, not merely present.
///
/// The nav card rendered a search field, a results panel and five tappable rows and
/// could not search: every event cleared `query` and nothing set it, so
/// `sys.search(query: state.query)` always ran on `""`. A review caught it, and
/// nothing on screen could have — an empty results list looks exactly like a query
/// with no matches.
///
/// Worse, the panel was guarded on `dest == ""` while the field that fills it binds
/// to `dest`, so the only state in which results could appear was the one before
/// anything had been typed. Two guards fighting: one waiting for a query, the other
/// requiring that nothing had been asked for.
///
/// So this walks the whole interaction, because each step passes on its own: commit
/// a query, see the candidates, pick one, see the list close.
#[test]
fn typing_a_destination_produces_candidates_and_picking_one_closes_them() {
    const CARD: &str = concat!(
        "source found sys.search(query: state.query, count: 5, fields: [id, name, lat, lon])\n",
        "state dest  { shape: text, initial: \"\" }\n",
        "state query { shape: text, initial: \"\" }\n",
        "event set_dest    { dest: set($value), query: set($value) }\n",
        "event choose_dest { dest: set($value), query: clear }\n",
        "copy to { class: vocabulary, en: \"TO\" }\n",
        "view root Surface {\n",
        "  Field(text: dest, placeholder: copy.to, on_commit: set_dest, width: .fill)\n",
        "  when query != \"\" {\n",
        "    for f, i in found key f.id {\n",
        "      Row(align: .center, gap: 10, on_tap: choose_dest, value: f.id) {\n",
        "        TextRow(text: f.name)\n",
        "      }\n",
        "    }\n",
        "  }\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let data = serde_json::json!({
        "dest": "", "query": "",
        "found": [
            { "id": "a", "name": "Stanford University", "lat": 37.43, "lon": -122.17 },
            { "id": "b", "name": "Stanford Shopping Center", "lat": 37.44, "lon": -122.17 },
            { "id": "c", "name": "Stanford Stadium", "lat": 37.43, "lon": -122.16 }
        ],
        "env": { "locale": {} }, "copy": { "to": "TO" }
    });
    let rows = |store: &octoscript_ui_l0::InstanceStore| {
        let dsl = octoscript_ui_l0::kit::lower(
            &octoscript_ui_l0::realize_with_state(CARD, &data, store, RealizeLimits::default())
                .root
                .expect("realizes"),
        );
        dsl.matches("l0_row_text(").count()
    };

    let mut store = octoscript_ui_l0::InstanceStore::default();
    assert_eq!(rows(&store), 0, "nothing asked for, nothing listed");

    // Commit a query: the candidates appear. This is the step that was impossible.
    octoscript_ui_l0::dispatch_reporting(
        CARD,
        &mut store,
        "root",
        "set_dest",
        Some(&serde_json::Value::String("Stanford".into())),
        &data,
    );
    assert_eq!(
        rows(&store),
        3,
        "committing a query must list what the search found"
    );

    // Pick one: the list closes, because `choose_dest` clears the query.
    octoscript_ui_l0::dispatch_reporting(
        CARD,
        &mut store,
        "root",
        "choose_dest",
        Some(&serde_json::Value::String("a".into())),
        &data,
    );
    assert_eq!(rows(&store), 0, "picking a candidate closes the list");
}

/// A card NAMES a map control; only the backend may call the widget.
///
/// This is the split §1.1 asks for, on the one requirement that most obviously
/// tempts a card to break it. The L2 card draws its own zoom pill and writes
/// `on_click: || ui.themap.nav_zoom_by("0.7")` — a method call on a named widget,
/// which is the imperative wiring L0 exists to exclude. "This map can be zoomed" is
/// a capability; the button, the glyph and the call are presentation.
///
/// So the test has two halves and the second is the one that matters: the control
/// must appear when asked for, and the CARD must still contain no call.
#[test]
fn a_card_names_a_map_control_and_never_calls_the_widget() {
    let card = |controls: &str| {
        format!(
            concat!(
                "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
                "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
                "state origin {{ shape: text, initial: \"A\" }}\n",
                "state dest   {{ shape: text, initial: \"B\" }}\n",
                "view root Surface {{\n",
                "  Map(mode: .plan, from: o, to: d, zoom: 14{})\n",
                "}}\n"
            ),
            controls
        )
    };
    let data = serde_json::json!({
        "origin": "A", "dest": "B",
        "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
        "env": { "locale": {} }
    });
    let lower = |src: &str| {
        let checked = check_ui_l0_named("nav", src);
        assert!(checked.valid, "{:#?}", checked.diagnostics);
        octoscript_ui_l0::kit::lower(
            &realize(src, &data, RealizeLimits::default())
                .root
                .expect("realizes"),
        )
    };

    // Unasked-for: a map that grows buttons a card never mentioned would be the
    // theme deciding what a screen OFFERS, not how it looks.
    let bare = lower(&card(""));
    assert!(
        bare.contains("\"none\""),
        "no controls unless the card says so:\n{bare}"
    );
    // Asked for: the theme is told, and told which.
    let zoom = lower(&card(", controls: .zoom"));
    assert!(
        zoom.contains("\"zoom\""),
        "a zoom pill was asked for:\n{zoom}"
    );
    let all = lower(&card(", controls: .all"));
    assert!(all.contains("\"all\""), "recenter too:\n{all}");

    // THE HALF THAT MATTERS. Whatever the theme goes on to draw, no lowering of a
    // card may contain a call on a widget — that is the L2 form this replaces.
    for (name, dsl) in [("none", &bare), ("zoom", &zoom), ("all", &all)] {
        assert!(
            !dsl.contains("nav_zoom_by") && !dsl.contains("set_nav_recenter"),
            "{name}: a card must not call the widget:\n{dsl}"
        );
        assert!(
            !dsl.contains("ui."),
            "{name}: a card must not reach a widget at all:\n{dsl}"
        );
    }
}

/// §5.13: an `initial:` names a value to CAPTURE, and never computes one.
///
/// The parser scanned the dotted path and stopped, so everything after it was
/// discarded without a word: `initial: here.lat * 2` became `here.lat`, and at L1 —
/// where arithmetic is admitted in an argument value — the card was accepted. A card
/// that asks for one number and is silently given another is the failure this
/// profile's §4 exists for, arriving through the declaration rather than the value.
///
/// It is also the third position the implementation parsed an expression in. §9.2
/// admits exactly one, and §9.8 records a guard as a known second; this one nobody
/// had noticed, because it did not evaluate the expression — it dropped it.
#[test]
fn an_initial_captures_a_value_and_never_computes_one() {
    let card = |initial: &str, header: &str| {
        format!(
            "{header}source here sys.gps()\n\
             state a {{ shape: number, initial: {initial} }}\n\
             view root Surface {{ TextHero(value: a) }}\n"
        )
    };
    // A capture is admitted, which is the whole point of §5.13.
    let ok = check_ui_l0_named("probe", &card("here.lat", ""));
    assert!(ok.valid, "a captured initial is L0: {:#?}", ok.diagnostics);
    // A literal still is too. Its own card, because a card that captures nothing
    // has no reason to declare the source and is refused for leaving it unread.
    let literal = check_ui_l0_named(
        "probe",
        "state a { shape: number, initial: 0 }\n\
         view root Surface { TextHero(value: a) }\n",
    );
    assert!(literal.valid, "{:#?}", literal.diagnostics);

    // And an expression is refused AT BOTH LEVELS. L0 refuses it as arithmetic; the
    // one that mattered is L1, where arithmetic is otherwise legal and this was
    // accepted and thrown away.
    for header in ["", "# level: L1\n"] {
        let report = check_ui_l0_named("probe", &card("here.lat * 2", header));
        assert!(
            !report.valid,
            "an expression in `initial:` is refused (header {header:?})"
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.message.contains("expression")),
            "and says so: {:#?}",
            report.diagnostics
        );
    }
}

/// A `TokenOrPath` argument works BOTH ways, or it works in neither.
///
/// R8.3's on-map 2D/3D switch is a `view:` the card states and a guard on the same
/// state — no widget call. Written `view: .tilted` it lowered to the tilted camera;
/// written `view: view`, following card state, it lowered to the FLAT one on both
/// settings. Realize erases the difference between the two forms — a fixed token
/// stays `Token("tilted")`, a followed state arrives as `Text("tilted")` — and every
/// reader in the lowering matched `Token` alone.
///
/// On the phone the chip relabelled 3D→2D on every tap, because its label comes from
/// a guard that reads the state directly. The toggle looked live and the camera never
/// moved: a control that responds and changes nothing, asserting a view the map is
/// not in. Both spellings are asserted here, for `view` and for the `width` and
/// `unit` that share the shape.
#[test]
fn a_token_argument_may_be_written_or_followed() {
    let card = |view: &str, unit: &str, span: &str| {
        format!(
            concat!(
                "source g sys.gps()\n",
                "state view {{ shape: enum[tilted, flat], initial: .tilted }}\n",
                "state pace {{ shape: enum[c, f], initial: .c }}\n",
                "state span {{ shape: enum[fill, fit], initial: .fill }}\n",
                "view root Surface {{\n",
                "  Map(mode: .drive, at: g, view: {}, zoom: 15)\n",
                "  TextHero(value: g.accuracy{})\n",
                "  TextBody(text: \"x\"{})\n",
                "}}\n"
            ),
            view, unit, span
        )
    };
    let data = serde_json::json!({
        "view": "tilted", "pace": "c", "span": "fill",
        "g": { "lat": 1.0, "lon": 2.0, "accuracy": 5.0, "ok": 1 },
        "env": { "locale": {} }
    });
    let lower = |src: &str| {
        let checked = check_ui_l0_named("nav", src);
        assert!(checked.valid, "{:#?}", checked.diagnostics);
        let root = realize(src, &data, RealizeLimits::default())
            .root
            .expect("realizes");
        (
            octoscript_ui_l0::kit::lower(&root),
            octoscript_ui_l0::makepad::lower(&root),
        )
    };

    // The camera, both ways. `state.view` reads `.tilted` out of the same data.
    for spelling in [".tilted", "view"] {
        let (kit, desk) = lower(&card(spelling, "", ""));
        assert!(
            kit.contains("follow3d"),
            "{spelling}: the tilted camera:\n{kit}"
        );
        assert!(
            desk.contains("follow3d"),
            "{spelling}: the tilted camera on the desk too:\n{desk}"
        );
    }
    // And the flat one is still reachable, or the fix would be "always tilted".
    let flat = serde_json::json!({
        "view": "flat", "pace": "c", "span": "fill",
        "g": { "lat": 1.0, "lon": 2.0, "accuracy": 5.0, "ok": 1 },
        "env": { "locale": {} }
    });
    let src = card("view", "", "");
    let root = realize(&src, &flat, RealizeLimits::default())
        .root
        .expect("realizes");
    let dsl = octoscript_ui_l0::kit::lower(&root);
    assert!(
        !dsl.contains("follow3d") && dsl.contains("\"follow\""),
        "a followed state can still choose flat:\n{dsl}"
    );

    // `unit` and `width` share the shape, so they share the test.
    for spelling in [".c", "pace"] {
        let (_, desk) = lower(&card(".tilted", &format!(", unit: {spelling}"), ""));
        assert!(
            desk.contains('\u{b0}'),
            "unit as `{spelling}` still decorates:\n{desk}"
        );
    }
    for spelling in [".fill", "span"] {
        let (kit, _) = lower(&card(".tilted", "", &format!(", width: {spelling}")));
        assert!(
            kit.contains("l0_wide("),
            "width as `{spelling}` still fills:\n{kit}"
        );
    }
}

/// Pins belong to a map you are LOOKING at, not one that is chasing you.
///
/// R3.12 is a plan-screen requirement. A follow camera already draws the driver's
/// puck, and in 3D the widget appends pin geometry to the route ribbon rather than
/// drawing it separately — measured on a OnePlus 6, a `follow3d` map handed markers
/// rendered no route and no tiles at all, a blank beige screen.
///
/// It went unnoticed for a build because I verified the pins on the screen the
/// requirement names and not on the other one. So this asserts BOTH screens.
#[test]
fn a_chase_map_carries_no_pins() {
    const CARD: &str = concat!(
        "source here sys.gps()\n",
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "state screen { shape: enum[plan, drive], initial: .plan }\n",
        "view root Surface {\n",
        "  when screen == .plan  { Map(mode: .plan, from: o, to: d, zoom: 14) }\n",
        "  when screen == .drive { Map(mode: .drive, from: o, to: d, at: here, view: .tilted, zoom: 17) }\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let lower = |screen: &str| {
        let data = serde_json::json!({
            "origin": "A", "dest": "B", "screen": screen,
            "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
            "here": { "lat": 1.5, "lon": 2.5, "ok": 1 }, "env": { "locale": {} }
        });
        octoscript_ui_l0::kit::lower(
            &realize(CARD, &data, RealizeLimits::default())
                .root
                .expect("realizes"),
        )
    };
    // The overview pins both ends — that is the requirement.
    let plan = lower("plan");
    assert!(
        plan.contains("\",0\"") && plan.contains("\",2\""),
        "plan pins:\n{plan}"
    );
    // The chase map passes an EMPTY marker string, which the widget reads as
    // "no pins" — not a missing argument, which would be an arity error.
    let drive = lower("drive");
    assert!(
        drive.contains("follow3d"),
        "drive is the chase camera:\n{drive}"
    );
    assert!(
        !drive.contains("\",0\"") && !drive.contains("\",2\""),
        "a chase map must carry no pins:\n{drive}"
    );
}

/// Three screens, one transition, and a map on every one of them.
///
/// R2.2's preview is a SCREEN rather than a state of the planning one: the chosen
/// trip, the two numbers that decide whether to take it, and one button that
/// commits. Everything on it was already on the plan screen; what was missing was
/// it being a separate step.
///
/// `cycle` names an order and the order IS the flow, so "Go", "Start" and "End" are
/// one transition seen from three places. Three separate events would have been
/// three chances to disagree about which screen follows which — so the test walks
/// the whole loop rather than checking a single hop.
///
/// The map count is the other half. Adding a screen is the easiest way to end up
/// with one that draws no map at all, which is a failure the checker cannot see and
/// a screenshot of the WRONG screen would not show.
#[test]
fn the_journey_through_the_card_is_one_transition_and_never_loses_the_map() {
    const CARD: &str = concat!(
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "source here sys.gps()\n",
        "source trip sys.route(from_lat: o.0.lat, from_lon: o.0.lon,\n",
        "                      to_lat: d.0.lat, to_lon: d.0.lon,\n",
        "                      mode: state.mode, fields: [duration, distance])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "state mode   { shape: enum[drive, walk, bike], initial: .drive }\n",
        "state screen { shape: enum[plan, preview, drive], initial: .plan }\n",
        "event go { screen: cycle(.plan, .preview, .drive) }\n",
        "copy begin { class: vocabulary, en: \"Start\" }\n",
        "view root Surface {\n",
        "  when screen == .plan {\n",
        "    Field(text: dest, placeholder: copy.begin, on_commit: go, width: .fill)\n",
        "    Map(mode: .plan, from: o, to: d, zoom: 14)\n",
        "  }\n",
        "  when screen == .preview {\n",
        "    Panel(dock: .bottom) { TextHero(value: trip.duration) Chip(text: copy.begin, on_tap: go) }\n",
        "    Map(mode: .plan, from: o, to: d, zoom: 16)\n",
        "  }\n",
        "  when screen == .drive {\n",
        "    Map(mode: .drive, from: o, to: d, at: here, view: .tilted, zoom: 17)\n",
        "  }\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let data = serde_json::json!({
        "origin": "A", "dest": "B", "mode": "drive", "screen": "plan",
        "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
        "here": { "lat": 1.5, "lon": 2.5, "ok": 1 },
        "trip": { "duration": "30 min", "distance": "27 km" },
        "env": { "locale": {} }, "copy": { "begin": "Start" }
    });
    let mut store = octoscript_ui_l0::InstanceStore::default();
    let screen = |store: &octoscript_ui_l0::InstanceStore| {
        let dsl = octoscript_ui_l0::kit::lower(
            &octoscript_ui_l0::realize_with_state(CARD, &data, store, RealizeLimits::default())
                .root
                .expect("realizes"),
        );
        // EVERY screen draws exactly one map. A screen that lost its map is the
        // failure a screenshot of a different screen would never show.
        assert_eq!(
            dsl.matches("l0_map(").count(),
            1,
            "every screen draws one map:\n{dsl}"
        );
        if dsl.contains("follow") {
            "drive"
        } else if dsl.contains("l0_field(") {
            "plan"
        } else {
            "preview"
        }
    };

    assert_eq!(screen(&store), "plan");
    let mut seen = Vec::new();
    for _ in 0..4 {
        octoscript_ui_l0::dispatch_reporting(CARD, &mut store, "root", "go", None, &data);
        seen.push(screen(&store));
    }
    assert_eq!(
        seen,
        vec!["preview", "drive", "plan", "preview"],
        "one transition walks the whole journey and comes back round"
    );
}

/// A trip that starts where you are must CAPTURE the fix, not reference it.
///
/// R11.3. The obvious form — `sys.route(from_lat: here.lat, …)` — is wrong in a way
/// that renders perfectly: `here` is a source, so the route is re-fetched every time
/// the fix changes, and `sys.step` then compares the route's start against the
/// device's position when they are the SAME expression. Progress along the route is
/// always zero and the banner holds the first manoeuvre for the whole drive.
///
/// `initial:` reads a path from the data once at realize and the store owns it
/// after, so the start lowers to a LITERAL while the position stays a live call.
/// That is R9.5's freeze — the L2 card's top-level `let` — said declaratively.
///
/// The test asserts the asymmetry directly, because both forms lower to something
/// that looks like a working route.
///
/// **This is not yet a recommendation.** The nav card used it and it was backed out:
/// realize happens before the first fix lands, so the capture froze `sys.gps`'s
/// -9999 sentinel permanently — which is the SAME "freezes at build, before the
/// fetch lands" defect that the card's own header cites as the reason the L2
/// version needed `tick()`. Capturing is the right shape and realize is the wrong
/// moment; what is missing is the host writing fetched values into a card's data, so
/// that there is a fix to capture at all. Kept as a test because the mechanism and
/// the precision rule are both real and both worth pinning.
#[test]
fn a_trip_from_here_freezes_its_start_and_not_its_position() {
    const CARD: &str = concat!(
        "source here sys.gps()\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "state from_lat { shape: number, initial: here.lat }\n",
        "state from_lon { shape: number, initial: here.lon }\n",
        "state dest { shape: text, initial: \"B\" }\n",
        "state mode { shape: enum[drive, walk, bike], initial: .drive }\n",
        "source step sys.step(from_lat: state.from_lat, from_lon: state.from_lon,\n",
        "                     to_lat: d.0.lat, to_lon: d.0.lon,\n",
        "                     at_lat: here.lat, at_lon: here.lon,\n",
        "                     fields: [instruction, remaining])\n",
        "view root Surface {\n",
        "  TextBody(text: step.instruction)\n",
        "  Map(mode: .drive, from_lat: from_lat, from_lon: from_lon, to: d, at: here,\n",
        "      view: .tilted, zoom: 17)\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let data = serde_json::json!({
        "dest": "B", "mode": "drive",
        "here": { "lat": 37.2656, "lon": -122.0294, "ok": 1 },
        "d": [{ "id": "x", "name": "B", "lat": 37.4275, "lon": -122.1697 }],
        "env": { "locale": {} }
    });
    let dsl = octoscript_ui_l0::kit::lower(
        &realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );

    // The START is a literal — captured, so it stays where the trip began.
    assert!(
        dsl.contains("37.2656") && dsl.contains("-122.0294"),
        "the route's start must be captured, not called:\n{dsl}"
    );
    // FULL PRECISION. Formatted the way sizes are, 37.2656 becomes 37.3 — about
    // 11 km at this latitude, and a route from there looks entirely plausible.
    assert!(
        !dsl.contains("37.3,") && !dsl.contains("(37.3"),
        "a coordinate is not a display size:\n{dsl}"
    );
    // The POSITION stays live, or nothing moves as the device does.
    assert!(
        dsl.contains("sys.gps(\"lat\")"),
        "the device's position must stay a live call:\n{dsl}"
    );
    // And the two must not be the same expression, which is the defect this
    // guards: progress measured from yourself is always zero.
    let prog = dsl
        .find("sys.navprog(")
        .map(|i| dsl[i..].chars().take(120).collect::<String>())
        .expect("a step lowers through navprog");
    assert!(
        prog.starts_with("sys.navprog(37.2656"),
        "progress must be measured from the captured start:\n{prog}"
    );
}

/// A field has TWO moments, and they mean different things.
///
/// `on_commit` is the return key: this is my destination. `on_change` is every
/// keystroke: this is what I am asking about. A search box needs both — results
/// while you type, a trip when you commit — and collapsing them loses one or the
/// other: commit-only means no results until you press return, change-only means
/// every character sets a destination and routes to it.
///
/// The test checks they stay SEPARATE and that a field asking for neither gets
/// neither, because an unasked-for keystroke event is a fetch per character.
#[test]
fn a_field_can_answer_a_keystroke_and_a_commit_differently() {
    const CARD: &str = concat!(
        "state dest  { shape: text, initial: \"\" }\n",
        "state query { shape: text, initial: \"\" }\n",
        "event set_dest { dest: set($value), query: set($value) }\n",
        "event typing   { query: set($value) }\n",
        "copy to { class: vocabulary, en: \"TO\" }\n",
        "view root Surface {\n",
        "  Field(text: dest, placeholder: copy.to, on_commit: set_dest, on_change: typing, width: .fill)\n",
        "  Field(text: query, placeholder: copy.to, on_commit: set_dest, width: .fill)\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let data = serde_json::json!({
        "dest": "", "query": "", "env": { "locale": {} }, "copy": { "to": "TO" }
    });
    let dsl = octoscript_ui_l0::kit::lower(
        &realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );
    let fields: Vec<&str> = dsl.lines().filter(|l| l.contains("l0_field(")).collect();
    let joined = fields.join("\n");
    // The first field carries BOTH, and they are different events.
    assert!(
        joined.contains("\\\"e\\\":\\\"typing\\\"")
            && joined.contains("\\\"e\\\":\\\"set_dest\\\""),
        "a field may answer both moments:\n{joined}"
    );
    // The second asked for no keystroke event and must not have acquired one: a
    // change target it never declared is a search on every character.
    let second = fields
        .iter()
        .find(|l| !l.contains("typing"))
        .unwrap_or_else(|| panic!("a field with no on_change:\n{joined}"));
    assert!(
        second.ends_with("\"\")") || second.contains(", \"\")"),
        "a field that asked for no keystroke event gets none:\n{second}"
    );
}

/// A map routes through BOTH stops, or it draws a different trip from the one
/// reported beside it.
///
/// R4.5. The first attempt at a second stop was reverted for exactly this: the route
/// line went through one waypoint while the duration next to it was for a trip
/// through two — the drawn-versus-reported mismatch this profile exists to catch, and
/// invisible in a screenshot where both are plausible lines.
///
/// It is two named slots rather than a list because role arguments route through the
/// expression grammar, so admitting `[a, b]` there is a change to the whole grammar
/// for one argument. The app being replaced has exactly two waypoint slots.
///
/// The test counts SEPARATORS. Both stops appearing somewhere is not the claim; the
/// claim is that the helper is handed two waypoints, and `;` is how it is told.
#[test]
fn a_map_routes_through_both_of_its_stops() {
    const CARD: &str = concat!(
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "source s1 sys.search(query: state.stop1, count: 1, fields: [id, name, lat, lon])\n",
        "source s2 sys.search(query: state.stop2, count: 1, fields: [id, name, lat, lon])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "state stop1  { shape: text, initial: \"C\" }\n",
        "state stop2  { shape: text, initial: \"D\" }\n",
        "view root Surface {\n",
        "  Map(mode: .plan, from: o, to: d, via: s1, via2: s2, zoom: 14)\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let data = serde_json::json!({
        "origin": "A", "dest": "B", "stop1": "C", "stop2": "D",
        "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
        "s1": [{ "lat": 5.0, "lon": 6.0 }], "s2": [{ "lat": 7.0, "lon": 8.0 }],
        "env": { "locale": {} }
    });
    let dsl = octoscript_ui_l0::kit::lower(
        &realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );

    // The polyline's waypoint argument: two pairs are joined by ONE separator.
    // The route call ALONE. A fixed-width window swept in the pin string, which
    // legitimately carries three separators — origin, two stops, destination — and
    // made a correct lowering look like four waypoints.
    let start = dsl
        .find("sys.navroute(")
        .expect("a map with a trip lowers a route");
    let mut depth = 0usize;
    let mut end = start;
    for (i, c) in dsl[start..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = start + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    let route = &dsl[start..end];
    assert!(
        route.contains("sys.searchnum(\"C\"") && route.contains("sys.searchnum(\"D\""),
        "both stops must reach the route:\n{route}"
    );
    assert_eq!(
        route.matches("\";\"").count(),
        1,
        "two waypoints are one separator — a missing one is a trip through the first \
         stop only, reported as a trip through both:\n{route}"
    );
    // And both are PINNED, or the map marks one stop on a line through two.
    let pins = dsl.matches("\",1\"").count();
    assert_eq!(pins, 2, "both stops are pinned:\n{dsl}");
}

/// An `initial:` from a SOURCE is a capture, and the realizer says so.
///
/// The difference between an initial value and a value that follows its source is
/// whether anyone writes it down. Left in the data it re-resolves on every
/// realization: an origin declared as "where I am" then chases the device, and a
/// route from it is re-fetched before it can answer — measured, three times, in
/// three different disguises.
///
/// So realization REPORTS what it took from a source, and a host writes it once. The
/// realizer owns the precedence; only the host owns the store. This asserts the
/// report, which is the part the profile is responsible for.
#[test]
fn an_initial_taken_from_a_source_is_reported_as_captured() {
    const CARD: &str = concat!(
        "source here sys.gps()\n",
        "state from_lat { shape: number, initial: here.lat }\n",
        "state mode { shape: enum[drive, walk, bike], initial: .drive }\n",
        "copy m { class: vocabulary, en: \"m\" }\n",
        "view root Surface {\n",
        "  TextValue(value: from_lat)\n",
        "  TextCaption(text: copy.m)\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    // A source that has answered: the value is taken, and reported.
    let data = serde_json::json!({
        "here": { "lat": 37.2656, "lon": -122.0294, "ok": 1 },
        "env": { "locale": {} }, "copy": { "m": "m" }
    });
    let report = realize(CARD, &data, RealizeLimits::default());
    assert_eq!(
        report.captured,
        vec![("from_lat".to_string(), serde_json::json!(37.2656))],
        "a value taken from a source must be reported for the host to freeze"
    );
    // A literal initial is NOT a capture — there is nothing to freeze, and reporting
    // it would have the host write a cell the card can never change.
    assert!(
        !report.captured.iter().any(|(p, _)| p == "mode"),
        "a literal initial needs no capturing: {:?}",
        report.captured
    );

    // A source that has NOT answered: nothing to capture, and the state falls to its
    // shape default rather than freezing an absence.
    let empty = serde_json::json!({ "env": { "locale": {} }, "copy": { "m": "m" } });
    assert!(
        realize(CARD, &empty, RealizeLimits::default())
            .captured
            .is_empty(),
        "a source with no answer captures nothing"
    );

    // And once the store HOLDS it, the capture does not repeat — that is what makes
    // it a capture rather than a re-read.
    let mut store = octoscript_ui_l0::InstanceStore::default();
    store.set_cell(
        octoscript_ui_l0::CARD_STATE_KEY,
        "from_lat",
        serde_json::json!(1.5),
    );
    let held = octoscript_ui_l0::realize_with_state(CARD, &data, &store, RealizeLimits::default());
    assert!(
        held.captured.is_empty(),
        "a stored value is already captured: {:?}",
        held.captured
    );
}

/// A route says what it costs ON the route.
///
/// iOS Maps labels each line it draws with the time that line takes; a sheet can only
/// name one. So `Map(summary: trip)` puts the duration and distance on the path, and
/// it names the SAME source the sheet reads — which is the point: the bubble and the
/// line have to describe one journey, and two separately-bound numbers are two
/// chances to disagree.
#[test]
fn a_map_labels_the_route_with_what_it_costs() {
    const CARD: &str = concat!(
        "source o sys.search(query: state.origin, count: 1, fields: [id, name, lat, lon])\n",
        "source d sys.search(query: state.dest, count: 1, fields: [id, name, lat, lon])\n",
        "source trip sys.route(from_lat: o.0.lat, from_lon: o.0.lon,\n",
        "                      to_lat: d.0.lat, to_lon: d.0.lon,\n",
        "                      mode: state.mode, fields: [duration, distance])\n",
        "state origin { shape: text, initial: \"A\" }\n",
        "state dest   { shape: text, initial: \"B\" }\n",
        "state mode   { shape: enum[drive, walk, bike], initial: .drive }\n",
        "view root Surface {\n",
        "  TextValue(value: trip.duration)\n",
        "  Map(mode: .plan, from: o, to: d, zoom: 14, summary: trip)\n",
        "}\n"
    );
    let checked = check_ui_l0_named("nav", CARD);
    assert!(checked.valid, "{:#?}", checked.diagnostics);

    let data = serde_json::json!({
        "origin": "A", "dest": "B", "mode": "drive",
        "o": [{ "lat": 1.0, "lon": 2.0 }], "d": [{ "lat": 3.0, "lon": 4.0 }],
        "trip": { "duration": "SEEDED", "distance": "SEEDED" },
        "env": { "locale": {} }
    });
    let dsl = octoscript_ui_l0::kit::lower(
        &realize(CARD, &data, RealizeLimits::default())
            .root
            .expect("realizes"),
    );

    // Both halves reach the badge, joined for the widget to split. Two lines,
    // because a duration and a distance are two facts and stacking them is the
    // theme's business, not a string the card wrote.
    assert!(
        dsl.contains(" + \"|\" + "),
        "a badge is emitted, two facts joined for the widget to split:\n{dsl}"
    );
    // Both facts, and the SAME source the text reads — one journey, described once.
    // The duration appears twice: on the path and in the sheet, from one call.
    assert!(
        dsl.contains("\"min\") + \"|\" + ") && dsl.contains("\"km\")"),
        "the badge carries the duration and the distance:\n{dsl}"
    );
    assert!(
        dsl.matches("\"min\")").count() >= 2,
        "the badge and the summary must come from one trip:\n{dsl}"
    );
}
