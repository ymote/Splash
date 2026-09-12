//! TEMP soak-test validator (delete after use). `l0validate <card.splash>` →
//! JSON {ok, root, diagnostics[]} from the real realize() gate, so a correction
//! loop can feed the diagnostic messages back to the model.
use splash_ui_l0::{realize, RealizeLimits};

fn main() {
    let path = std::env::args().nth(1).expect("usage: l0validate <path>");
    let src = std::fs::read_to_string(&path).expect("read card");
    let data_path = std::path::Path::new(&path).with_extension("data.json");
    let data = if data_path.exists() {
        serde_json::from_str(&std::fs::read_to_string(data_path).expect("read fixture data"))
            .expect("valid fixture JSON")
    } else { serde_json::json!({}) };
    let report = realize(&src, &data, RealizeLimits::default());
    let msgs: Vec<String> = report
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    let ok = report.complete_root().is_ok();
    println!(
        "{}",
        serde_json::json!({"ok": ok, "root": report.root.is_some(), "diagnostics": msgs,
            "state_initials": splash_ui_l0::state_initials(&src)})
    );
    if !ok { std::process::exit(1); }
}
