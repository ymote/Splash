//! Print a card's source plan as JSON, for a host to fulfil.
//!
//! Usage: source_plan <card>
//!
//! octoscript-core says WHAT to fetch and in what order; it never fetches. Only a
//! host knows what answers `sys.weather`.

use octoscript_ui_l0::{source_plan, SourceArg};

fn arg_json(a: &SourceArg) -> String {
    match a {
        SourceArg::Path(p) => format!(r#"{{"kind":"path","value":{p:?}}}"#),
        SourceArg::Text(t) => format!(r#"{{"kind":"text","value":{t:?}}}"#),
        SourceArg::Number(n) => format!(r#"{{"kind":"number","value":{n}}}"#),
        SourceArg::List(items) => format!(
            r#"{{"kind":"list","value":[{}]}}"#,
            items
                .iter()
                .map(|i| format!("{i:?}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: source_plan <card>");
    let plan = source_plan(&std::fs::read_to_string(&path).expect("card"));

    let requests: Vec<String> = plan
        .requests
        .iter()
        .map(|r| {
            let args: Vec<String> = r
                .args
                .iter()
                .map(|(n, a)| format!("[{n:?},{}]", arg_json(a)))
                .collect();
            let deps: Vec<String> = r.depends_on.iter().map(|d| format!("{d:?}")).collect();
            format!(
                r#"{{"name":{:?},"helper":{:?},"args":[{}],"depends_on":[{}]}}"#,
                r.name,
                r.helper,
                args.join(","),
                deps.join(",")
            )
        })
        .collect();

    let diags: Vec<String> = plan
        .diagnostics
        .iter()
        .map(|d| format!(r#"{{"line":{},"message":{:?}}}"#, d.line, d.message))
        .collect();

    println!(
        r#"{{"requests":[{}],"diagnostics":[{}]}}"#,
        requests.join(","),
        diags.join(",")
    );
}
