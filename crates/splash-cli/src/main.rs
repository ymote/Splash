#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::process::ExitCode;

use splash_capabilities::{
    json, CapabilityRuntime, JsonToolContract, ToolError, ToolMetadata, ToolPolicy,
};
use splash_core::{check_syntax_named, ExecutionLimits};

#[derive(Debug, Eq, PartialEq)]
enum CliCommand {
    Evaluate(String),
    Catalog,
    Check { file: String, source: String },
}

#[derive(Debug, Eq, PartialEq)]
struct CliOptions {
    command: CliCommand,
    allow_echo: bool,
    allow_json_add: bool,
}

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
    run_options(parse_args(args)?)
}

fn run_options(options: CliOptions) -> Result<(), String> {
    if let CliCommand::Check { file, source } = &options.command {
        let report = check_syntax_named(file, source, ExecutionLimits::default())
            .map_err(|error| error.to_string())?;
        let diagnostics = report
            .diagnostics
            .iter()
            .map(|diagnostic| {
                json!({
                    "line": diagnostic.line,
                    "column": diagnostic.column,
                    "message": diagnostic.message,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            json!({
                "valid": report.valid,
                "diagnostics_truncated": report.diagnostics_truncated,
                "diagnostics": diagnostics,
            })
        );
        return report
            .valid
            .then_some(())
            .ok_or_else(|| "syntax check failed".to_owned());
    }

    let mut runtime = CapabilityRuntime::default();
    if options.allow_echo {
        runtime
            .register_tool_with_metadata(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("Returns the supplied text unchanged."),
                |request| Ok(request.input.clone()),
            )
            .map_err(|error| error.to_string())?;
    }
    if options.allow_json_add {
        let contract = JsonToolContract::new(
            json!({
                "type": "object",
                "properties": {
                    "left": {"type": "integer"},
                    "right": {"type": "integer"}
                },
                "required": ["left", "right"],
                "additionalProperties": false
            }),
            json!({
                "type": "object",
                "properties": {"total": {"type": "integer"}},
                "required": ["total"],
                "additionalProperties": false
            }),
        )
        .map_err(|error| error.to_string())?;
        runtime
            .register_validated_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds the integer left and right fields."),
                contract,
                |request| {
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
                },
            )
            .map_err(|error| error.to_string())?;
    }

    let source = match options.command {
        CliCommand::Evaluate(source) => source,
        CliCommand::Catalog => {
            println!(
                "{}",
                runtime
                    .tool_catalog_json()
                    .map_err(|error| error.to_string())?
            );
            return Ok(());
        }
        CliCommand::Check { .. } => unreachable!("syntax checks return before creating a host"),
    };

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

fn parse_args(args: Vec<String>) -> Result<CliOptions, String> {
    let mut allow_echo = false;
    let mut allow_json_add = false;
    let mut positional = Vec::new();

    for argument in args {
        match argument.as_str() {
            "--allow-echo" => allow_echo = true,
            "--allow-json-add" => allow_json_add = true,
            "check" | "eval" | "run" | "catalog" => positional.push(argument),
            _ => positional.push(argument),
        }
    }

    match positional.as_slice() {
        [command, source] if command == "eval" => Ok(CliOptions {
            command: CliCommand::Evaluate(source.clone()),
            allow_echo,
            allow_json_add,
        }),
        [command, path] if command == "run" => fs::read_to_string(path)
            .map(|source| CliOptions {
                command: CliCommand::Evaluate(source),
                allow_echo,
                allow_json_add,
            })
            .map_err(|error| format!("cannot read {path}: {error}")),
        [command, path] if command == "check" => fs::read_to_string(path)
            .map(|source| CliOptions {
                command: CliCommand::Check {
                    file: path.clone(),
                    source,
                },
                allow_echo,
                allow_json_add,
            })
            .map_err(|error| format!("cannot read {path}: {error}")),
        [command] if command == "catalog" => Ok(CliOptions {
            command: CliCommand::Catalog,
            allow_echo,
            allow_json_add,
        }),
        _ => Err(
            "usage: splash check <file> | splash eval [--allow-echo] [--allow-json-add] '<source>' | splash run [--allow-echo] [--allow-json-add] <file> | splash catalog [--allow-echo] [--allow-json-add]".to_owned(),
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
            CliOptions {
                command: CliCommand::Evaluate("let value = 1".to_owned()),
                allow_echo: true,
                allow_json_add: false,
            }
        );
    }

    #[test]
    fn parses_a_catalog_invocation() {
        assert_eq!(
            parse_args(vec!["catalog".to_owned(), "--allow-json-add".to_owned()]).unwrap(),
            CliOptions {
                command: CliCommand::Catalog,
                allow_echo: false,
                allow_json_add: true,
            }
        );
    }

    #[test]
    fn parses_a_check_invocation() {
        let path = format!(
            "{}/../splash-core/tests/fixtures/workflow_language.splash",
            env!("CARGO_MANIFEST_DIR")
        );
        assert_eq!(
            parse_args(vec!["check".to_owned(), path.clone()]).unwrap(),
            CliOptions {
                command: CliCommand::Check {
                    file: path,
                    source: include_str!(
                        "../../splash-core/tests/fixtures/workflow_language.splash"
                    )
                    .to_owned(),
                },
                allow_echo: false,
                allow_json_add: false,
            }
        );
    }

    #[test]
    fn checks_source_without_creating_a_capability_host() {
        run_options(CliOptions {
            command: CliCommand::Check {
                file: "generated.splash".to_owned(),
                source: "loop {}".to_owned(),
            },
            allow_echo: false,
            allow_json_add: false,
        })
        .unwrap();
    }

    #[test]
    fn rejects_invalid_source_during_a_syntax_check() {
        let error = run_options(CliOptions {
            command: CliCommand::Check {
                file: "generated.splash".to_owned(),
                source: "fn work() {".to_owned(),
            },
            allow_echo: false,
            allow_json_add: false,
        })
        .unwrap_err();

        assert_eq!(error, "syntax check failed");
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

    #[test]
    fn prints_a_catalog_for_granted_demo_tools() {
        run(vec![
            "catalog".to_owned(),
            "--allow-echo".to_owned(),
            "--allow-json-add".to_owned(),
        ])
        .unwrap();
    }
}
