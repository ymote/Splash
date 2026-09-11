//! Lower a card to calls on the L0 theme kit.
//!
//! Usage: lower_kit <card> <data.json> [event] [payload]
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let card = std::fs::read_to_string(&a[0]).expect("card");
    let data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&a[1]).expect("data")).expect("json");
    let mut store = octoscript_ui_l0::InstanceStore::default();
    if let Some(event) = a.get(2) {
        let payload = a.get(3).map(|v| serde_json::Value::String(v.clone()));
        octoscript_ui_l0::dispatch_with(&card, &mut store, "root", event, payload.as_ref());
    }
    let r = octoscript_ui_l0::realize_with_state(&card, &data, &store, Default::default());
    print!("{}", octoscript_ui_l0::kit::lower(&r.root.expect("root")));
}
