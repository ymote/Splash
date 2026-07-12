#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::process::ExitCode;

use splash_capabilities::{CapabilityRuntime, ToolPolicy};

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
    let (source, allow_echo) = parse_args(args)?;
    let mut runtime = CapabilityRuntime::default();
    if allow_echo {
        runtime
            .register_tool(ToolPolicy::new("text.echo"), |request| {
                Ok(request.input.clone())
            })
            .map_err(|error| error.to_string())?;
    }

    let report = runtime.eval(&source).map_err(|error| error.to_string())?;
    for diagnostic in &report.diagnostics {
        eprintln!("diagnostic: {diagnostic}");
    }
    for event in runtime.audit() {
        println!(
            "tool sequence={} name={} outcome={:?} input_bytes={} output_bytes={}",
            event.sequence, event.tool, event.outcome, event.input_bytes, event.output_bytes
        );
    }

    if report.succeeded() {
        Ok(())
    } else {
        Err("script evaluation failed".to_owned())
    }
}

fn parse_args(args: Vec<String>) -> Result<(String, bool), String> {
    let mut allow_echo = false;
    let mut positional = Vec::new();

    for argument in args {
        match argument.as_str() {
            "--allow-echo" => allow_echo = true,
            "eval" | "run" => positional.push(argument),
            _ => positional.push(argument),
        }
    }

    match positional.as_slice() {
        [command, source] if command == "eval" => Ok((source.clone(), allow_echo)),
        [command, path] if command == "run" => fs::read_to_string(path)
            .map(|source| (source, allow_echo))
            .map_err(|error| format!("cannot read {path}: {error}")),
        _ => Err(
            "usage: splash eval [--allow-echo] '<source>' | splash run [--allow-echo] <file>"
                .to_owned(),
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
            ("let value = 1".to_owned(), true)
        );
    }
}
