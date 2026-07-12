#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::process::ExitCode;

use splash_capabilities::{json, CapabilityRuntime, ToolError, ToolPolicy};

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let (source, allow_echo, allow_json_add) = parse_args(args)?;
    let mut runtime = CapabilityRuntime::default();
    if allow_echo {
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .map_err(|error| error.to_string())?;
    }
    if allow_json_add {
        runtime
            .register_json_tool(ToolPolicy::json("math.add"), |request| {
                let left = request.input["left"].as_i64().ok_or_else(|| {
                    ToolError::Denied("math.add expects an integer left field".to_owned())
                })?;
                let right = request.input["right"].as_i64().ok_or_else(|| {
                    ToolError::Denied("math.add expects an integer right field".to_owned())
                })?;
                let total = left.checked_add(right).ok_or_else(|| {
                    ToolError::Denied("math.add result exceeds the i64 range".to_owned())
                })?;
                Ok(json!({"total": total}))
            })
            .map_err(|error| error.to_string())?;
    }

    let mut report = runtime.eval(&source).map_err(|error| error.to_string())?;
    let mut stalled = false;
    while report.succeeded() && report.suspended {
        let pumped = runtime.pump().map_err(|error| error.to_string())?;
        let Some(resumed) = pumped.resumed.into_iter().last() else {
            stalled = true;
            break;
        };
        report = resumed;
    }

    for diagnostic in &report.diagnostics {
        eprintln!("diagnostic: {diagnostic}");
    }
    for event in runtime.audit() {
        println!(
            "tool sequence={} name={} outcome={:?} input_bytes={} output_bytes={}",
            event.sequence, event.tool, event.outcome, event.input_bytes, event.output_bytes
        );
    }

    if stalled {
        Err("script suspended without runnable capability work".to_owned())
    } else if report.succeeded() {
        Ok(())
    } else {
        Err("script evaluation failed".to_owned())
    }
}

fn parse_args(args: Vec<String>) -> Result<(String, bool, bool), String> {
    let mut allow_echo = false;
    let mut allow_json_add = false;
    let mut positional = Vec::new();

    for argument in args {
        match argument.as_str() {
            "--allow-echo" => allow_echo = true,
            "--allow-json-add" => allow_json_add = true,
            "eval" | "run" => positional.push(argument),
            _ => positional.push(argument),
        }
    }

    match positional.as_slice() {
        [command, source] if command == "eval" => {
            Ok((source.clone(), allow_echo, allow_json_add))
        }
        [command, path] if command == "run" => fs::read_to_string(path)
            .map(|source| (source, allow_echo, allow_json_add))
            .map_err(|error| format!("cannot read {path}: {error}")),
        _ => Err(
            "usage: splash eval [--allow-echo] [--allow-json-add] '<source>' | splash run [--allow-echo] [--allow-json-add] <file>".to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_eval_invocation() {
        assert_eq!(
            parse_args(vec![
                "eval".to_owned(),
                "let value = 1".to_owned(),
                "--allow-echo".to_owned(),
            ])
            .unwrap(),
            ("let value = 1".to_owned(), true, false)
        );
    }

    #[test]
    fn runs_a_deferred_tool_when_the_capability_is_granted() {
        run(vec![
            "eval".to_owned(),
            "use mod.tool\nuse mod.std.assert\nlet output = tool.start(\"text.echo\", \"hello\").await()\nassert(output == \"hello\")".to_owned(),
            "--allow-echo".to_owned(),
        ])
        .unwrap();
    }

    #[test]
    fn runs_a_json_tool_when_the_capability_is_granted() {
        run(vec![
            "eval".to_owned(),
            "use mod.tool\nuse mod.std.assert\nlet raw = tool.call_json(\"math.add\", {left: 20 right: 22})\nlet response = raw.parse_json()\nassert(response.total == 42)".to_owned(),
            "--allow-json-add".to_owned(),
        ])
        .unwrap();
    }
}
