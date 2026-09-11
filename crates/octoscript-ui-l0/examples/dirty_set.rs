//! How much of a card a state write actually touches.
//!
//! Usage: dirty_set <card> <path>…

use octoscript_ui_l0::{dirty_records, patch_points, record_dependencies};

fn main() {
    let mut a = std::env::args().skip(1);
    let path = a.next().expect("usage: dirty_set <card> <path>…");
    let changed: Vec<String> = a.collect();
    let card = std::fs::read_to_string(&path).expect("card");

    let all = record_dependencies(&card);
    println!("{} records", all.len());
    for d in &all {
        println!("  {:<14} reads {}", d.record, d.reads.join(", "));
    }
    for c in &changed {
        let dirty = dirty_records(&card, &[c.as_str()]);
        println!(
            "\nwriting {c:?} dirties {}/{} records: {}",
            dirty.len(),
            all.len(),
            dirty.join(", ")
        );
        let minimal = patch_points(&card, &[c.as_str()]);
        println!(
            "  minimal patch points: {}/{} -> {}",
            minimal.len(),
            all.len(),
            if minimal.is_empty() {
                "(none)".into()
            } else {
                minimal.join(", ")
            }
        );
    }
}
