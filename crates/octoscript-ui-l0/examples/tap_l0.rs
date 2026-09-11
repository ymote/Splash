//! Realize a card, dispatch one event, realize again — the interaction loop.
//!
//! Usage: tap_l0 <card> <data.json> <event> [payload]
//!
//! Proves the loop end to end without a UI: state lives in the store, the event
//! is a declared name, and the second realization reflects the write.

use octoscript_ui_l0::{dispatch_with, makepad, realize_with_state, InstanceStore, RealizeLimits};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (card_path, data_path, event) = (&a[0], &a[1], &a[2]);
    let payload = a.get(3).map(|v| serde_json::Value::String(v.clone()));

    let card = std::fs::read_to_string(card_path).expect("card");
    let data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(data_path).expect("data")).expect("json");
    let mut store = InstanceStore::default();

    let before = realize_with_state(&card, &data, &store, RealizeLimits::default());
    eprintln!("before: {} nodes", before.nodes);

    let applied = dispatch_with(&card, &mut store, "root", event, payload.as_ref());
    eprintln!("dispatch {event:?} -> {applied}");

    let after = realize_with_state(&card, &data, &store, RealizeLimits::default());
    eprintln!("after:  {} nodes", after.nodes);
    // Forget instances that went away, so the store tracks the live tree.
    store.prune(&after.live_keys);
    eprintln!("store:  {} live cells", store.len());

    print!("{}", makepad::lower(&after.root.expect("root")));
}
