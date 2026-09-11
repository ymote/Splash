//! Realize an L0 card against a data snapshot and print the Makepad DSL.
//!
//! Usage: cargo run -p octoscript-core --example lower_l0 -- <card> <data.json>
//!
//! The data stands in for what the runtime would have fetched. Realization is a
//! tree walk, so this never evaluates anything and reaches nothing.

use octoscript_ui_l0::{makepad, realize, RealizeLimits};

fn main() {
    let mut args = std::env::args().skip(1);
    let card_path = args.next().expect("usage: lower_l0 <card> <data.json>");
    let data_path = args.next().expect("usage: lower_l0 <card> <data.json>");

    let card = std::fs::read_to_string(&card_path).expect("card");
    let data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&data_path).expect("data")).expect("json");

    let report = realize(&card, &data, RealizeLimits::default());
    for d in &report.diagnostics {
        eprintln!("{}:{}:{}: {}", card_path, d.line, d.column, d.message);
    }
    match report.root {
        Some(root) => {
            eprintln!(
                "realized {} nodes{}",
                report.nodes,
                if report.truncated { " (truncated)" } else { "" }
            );
            print!("{}", makepad::lower(&root));
        }
        None => std::process::exit(1),
    }
}
