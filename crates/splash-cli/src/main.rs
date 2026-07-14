#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::process::ExitCode;

use splash_capabilities::{
    json, CapabilityRuntime, JsonToolContract, JsonValue, ToolError, ToolMetadata, ToolPolicy,
};
use splash_core::{
    check_syntax_named, format_source_named, top_level_declarations_named, ExecutionLimits,
    SyntaxReport, TopLevelDeclarationKind,
};

#[derive(Debug, Eq, PartialEq)]
enum CliCommand {
    Evaluate(String),
    Catalog,
    Check {
        file: String,
        source: String,
    },
    Outline {
        file: String,
        source: String,
    },
    Format {
        file: String,
        source: String,
        check: bool,
    },
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
        return run_syntax_check(file, source);
    }
    if let CliCommand::Outline { file, source } = &options.command {
        return run_outline(file, source);
    }
    if let CliCommand::Format {
        file,
        source,
        check,
    } = &options.command
    {
        return run_formatter(file, source, *check);
    }

    if let CliCommand::Evaluate(source) = &options.command {
        validate_evaluation_source(source)?;
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
        CliCommand::Check { .. } | CliCommand::Outline { .. } | CliCommand::Format { .. } => {
            unreachable!("source-only commands return before creating a host")
        }
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

fn run_syntax_check(file: &str, source: &str) -> Result<(), String> {
    let report = check_syntax_named(file, source, ExecutionLimits::default())
        .map_err(|error| error.to_string())?;
    println!(
        "{}",
        json!({
            "valid": report.valid,
            "diagnostics_truncated": report.diagnostics_truncated,
            "diagnostics": syntax_diagnostics_json(&report),
        })
    );
    report
        .valid
        .then_some(())
        .ok_or_else(|| "syntax check failed".to_owned())
}

fn run_outline(file: &str, source: &str) -> Result<(), String> {
    let (output, valid) = outline_output(file, source)?;
    println!("{output}");
    valid
        .then_some(())
        .ok_or_else(|| "syntax check failed".to_owned())
}

fn outline_output(file: &str, source: &str) -> Result<(JsonValue, bool), String> {
    let report = check_syntax_named(file, source, ExecutionLimits::default())
        .map_err(|error| error.to_string())?;
    let declarations = if report.valid {
        top_level_declarations_named(file, source, ExecutionLimits::default())
            .map_err(|error| error.to_string())?
            .iter()
            .map(|declaration| {
                let kind = match declaration.kind {
                    TopLevelDeclarationKind::Function => "function",
                    TopLevelDeclarationKind::Let => "let",
                };
                json!({
                    "kind": kind,
                    "name": declaration.name,
                    "declaration": {
                        "start_byte": declaration.declaration_start_byte,
                        "end_byte": declaration.declaration_end_byte,
                    },
                    "selection": {
                        "start_byte": declaration.selection_start_byte,
                        "end_byte": declaration.selection_end_byte,
                    },
                })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let valid = report.valid;
    Ok((
        json!({
            "valid": valid,
            "diagnostics_truncated": report.diagnostics_truncated,
            "diagnostics": syntax_diagnostics_json(&report),
            "declarations": declarations,
        }),
        valid,
    ))
}

fn syntax_diagnostics_json(report: &SyntaxReport) -> Vec<JsonValue> {
    report
        .diagnostics
        .iter()
        .map(|diagnostic| {
            json!({
                "line": diagnostic.line,
                "column": diagnostic.column,
                "message": diagnostic.message,
            })
        })
        .collect()
}

fn run_formatter(file: &str, source: &str, check: bool) -> Result<(), String> {
    let formatted = format_source_named(file, source, ExecutionLimits::default())
        .map_err(|error| error.to_string())?;
    if check {
        return (formatted == source)
            .then_some(())
            .ok_or_else(|| "source is not formatted".to_owned());
    }

    print!("{formatted}");
    Ok(())
}

fn validate_evaluation_source(source: &str) -> Result<(), String> {
    let report = check_syntax_named("inline.splash", source, ExecutionLimits::default())
        .map_err(|error| error.to_string())?;
    if report.valid {
        return Ok(());
    }

    let detail = report.diagnostics.first().map_or_else(
        || "invalid source".to_owned(),
        |diagnostic| {
            format!(
                "line {}, column {}: {}",
                diagnostic.line, diagnostic.column, diagnostic.message
            )
        },
    );
    Err(format!("canonical Splash preflight failed: {detail}"))
}

fn parse_args(args: Vec<String>) -> Result<CliOptions, String> {
    let mut allow_echo = false;
    let mut allow_json_add = false;
    let mut format_check = false;
    let mut positional = Vec::new();

    for argument in args {
        match argument.as_str() {
            "--allow-echo" => allow_echo = true,
            "--allow-json-add" => allow_json_add = true,
            "--check" => format_check = true,
            "check" | "outline" | "eval" | "run" | "format" | "catalog" => {
                positional.push(argument)
            }
            _ => positional.push(argument),
        }
    }

    if format_check && positional.first().is_none_or(|command| command != "format") {
        return Err("--check is only valid with splash format".to_owned());
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
        [command, path] if command == "outline" => fs::read_to_string(path)
            .map(|source| CliOptions {
                command: CliCommand::Outline {
                    file: path.clone(),
                    source,
                },
                allow_echo,
                allow_json_add,
            })
            .map_err(|error| format!("cannot read {path}: {error}")),
        [command, path] if command == "format" => fs::read_to_string(path)
            .map(|source| CliOptions {
                command: CliCommand::Format {
                    file: path.clone(),
                    source,
                    check: format_check,
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
            "usage: splash check <file> | splash outline <file> | splash format [--check] <file> | splash eval [--allow-echo] [--allow-json-add] '<source>' | splash run [--allow-echo] [--allow-json-add] <file> | splash catalog [--allow-echo] [--allow-json-add]".to_owned(),
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
    fn check_rejects_makepad_compatibility_syntax() {
        let error = run_options(CliOptions {
            command: CliCommand::Check {
                file: "generated.splash".to_owned(),
                source: "let request = {left: 20 right: 22}".to_owned(),
            },
            allow_echo: false,
            allow_json_add: false,
        })
        .unwrap_err();

        assert_eq!(error, "syntax check failed");
    }

    #[test]
    fn eval_rejects_makepad_compatibility_syntax() {
        let error = run(vec![
            "eval".to_owned(),
            "let request = {left: 20 right: 22}".to_owned(),
        ])
        .unwrap_err();

        assert!(error.starts_with("canonical Splash preflight failed:"));
        assert!(error.contains("expected `,`, a newline, or `}`"));
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
    fn parses_an_outline_invocation() {
        let path = format!(
            "{}/../splash-core/tests/fixtures/workflow_language.splash",
            env!("CARGO_MANIFEST_DIR")
        );
        assert_eq!(
            parse_args(vec!["outline".to_owned(), path.clone()]).unwrap(),
            CliOptions {
                command: CliCommand::Outline {
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
    fn emits_an_effect_free_top_level_outline() {
        let (output, valid) = outline_output(
            "generated.splash",
            "let config = {label: \"fn hidden() {}\"}\n\
             fn greet() {\n\
                 let local = 1\n\
             }\n",
        )
        .expect("canonical source has a bounded outline");

        assert!(valid);
        assert_eq!(output["valid"], json!(true));
        let declarations = output["declarations"]
            .as_array()
            .expect("outline uses an array");
        assert_eq!(declarations.len(), 2);
        assert_eq!(declarations[0]["kind"], json!("let"));
        assert_eq!(declarations[0]["name"], json!("config"));
        assert_eq!(declarations[0]["declaration"]["start_byte"], json!(0));
        assert_eq!(declarations[1]["kind"], json!("function"));
        assert_eq!(declarations[1]["name"], json!("greet"));
    }

    #[test]
    fn outline_keeps_diagnostics_and_rejects_invalid_source() {
        let (output, valid) = outline_output("generated.splash", "var value = 1")
            .expect("invalid source still has structured output");

        assert!(!valid);
        assert_eq!(output["declarations"], json!([]));
        assert!(output["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| !diagnostics.is_empty()));
    }

    #[test]
    fn parses_a_format_check_invocation() {
        let path = format!(
            "{}/../splash-core/tests/fixtures/workflow_language.splash",
            env!("CARGO_MANIFEST_DIR")
        );
        assert_eq!(
            parse_args(vec![
                "format".to_owned(),
                "--check".to_owned(),
                path.clone()
            ])
            .unwrap(),
            CliOptions {
                command: CliCommand::Format {
                    file: path,
                    source: include_str!(
                        "../../splash-core/tests/fixtures/workflow_language.splash"
                    )
                    .to_owned(),
                    check: true,
                },
                allow_echo: false,
                allow_json_add: false,
            }
        );
        assert_eq!(
            parse_args(vec![
                "eval".to_owned(),
                "--check".to_owned(),
                "1".to_owned()
            ])
            .unwrap_err(),
            "--check is only valid with splash format"
        );
    }

    #[test]
    fn format_check_rejects_noncanonical_whitespace() {
        let error = run_options(CliOptions {
            command: CliCommand::Format {
                file: "generated.splash".to_owned(),
                source: "let value=1".to_owned(),
                check: true,
            },
            allow_echo: false,
            allow_json_add: false,
        })
        .unwrap_err();

        assert_eq!(error, "source is not formatted");
        run_options(CliOptions {
            command: CliCommand::Format {
                file: "generated.splash".to_owned(),
                source: "let value = 1\n".to_owned(),
                check: true,
            },
            allow_echo: false,
            allow_json_add: false,
        })
        .unwrap();
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
            "use mod.tool\nuse mod.std.assert\nlet raw = tool.call_json(\"math.add\", {left: 20, right: 22})\nlet response = raw.parse_json()\nassert(response.total == 42)".to_owned(),
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
