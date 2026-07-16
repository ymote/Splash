#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::Read;
use std::process::ExitCode;

use splash_capabilities::{
    json, CapabilityLeaseGrant, CapabilityRuntime, JsonToolContract, JsonToolRequest, JsonValue,
    ToolDescriptor, ToolError, ToolMetadata, ToolPolicy, ToolRequest,
};
use splash_core::{
    check_syntax_named, format_source_named, tool_call_hint_report_named,
    top_level_declarations_named, ExecutionLimits, SyntaxReport, ToolCallHint,
    TopLevelDeclarationKind, CANONICAL_PROFILE_GRAMMAR_PATH, CANONICAL_PROFILE_ID,
    CANONICAL_PROFILE_VERSION, DEFAULT_MAX_FORMATTED_SOURCE_BYTES, MAX_LEXICAL_COMPLETION_SITES,
    MAX_LEXICAL_SYMBOL_OCCURRENCES, MAX_SYNTAX_DIAGNOSTICS, MAX_TOOL_CALL_HINTS,
};
use splash_workflow::{
    mobile::{MobileWorkflowBuilder, MobileWorkflowRuntime},
    WorkflowData, WorkflowDraft, WorkflowEvent, WorkflowPlan, WorkflowStepCapabilityPolicy,
    MAX_WORKFLOW_DATA_BYTES, MAX_WORKFLOW_DRAFT_BYTES, MAX_WORKFLOW_STEP_ID_BYTES,
};

const MAX_WORKFLOW_CLI_GRANTS: usize = 4_096;

#[derive(Debug, Eq, PartialEq)]
enum CliCommand {
    Evaluate(String),
    Catalog,
    Profile,
    Check {
        file: String,
        source: String,
    },
    Outline {
        file: String,
        source: String,
    },
    ToolCalls {
        file: String,
        source: String,
    },
    WorkflowReview {
        file: String,
        source: String,
    },
    WorkflowRun {
        file: String,
        source: String,
        grants: Vec<CliWorkflowGrant>,
        input_path: Option<String>,
    },
    Format {
        file: String,
        source: String,
        check: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliWorkflowGrant {
    step_id: String,
    tool: String,
    max_calls: usize,
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
    if matches!(&options.command, CliCommand::Profile) {
        return run_profile();
    }
    if let CliCommand::Check { file, source } = &options.command {
        return run_syntax_check(file, source);
    }
    if let CliCommand::Outline { file, source } = &options.command {
        return run_outline(file, source);
    }
    if let CliCommand::ToolCalls { file, source } = &options.command {
        return run_tool_calls(file, source);
    }
    if let CliCommand::WorkflowReview { file, source } = &options.command {
        return run_workflow_review(file, source);
    }
    if let CliCommand::WorkflowRun {
        source,
        grants,
        input_path,
        ..
    } = &options.command
    {
        return run_workflow_execution(
            source,
            grants,
            input_path.as_deref(),
            options.allow_echo,
            options.allow_json_add,
        );
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
    register_demo_tools(&mut runtime, options.allow_echo, options.allow_json_add)?;

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
        CliCommand::Profile => {
            unreachable!("profile returns before creating a host")
        }
        CliCommand::Check { .. }
        | CliCommand::Outline { .. }
        | CliCommand::ToolCalls { .. }
        | CliCommand::WorkflowReview { .. }
        | CliCommand::WorkflowRun { .. }
        | CliCommand::Format { .. } => {
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

fn run_profile() -> Result<(), String> {
    println!("{}", profile_output());
    Ok(())
}

/// Versioned, host-free metadata for generated-source and workflow tooling.
///
/// This describes the standalone language boundary only. In particular, it
/// never reports a host's tool catalog or conveys authority to invoke a tool.
fn profile_output() -> JsonValue {
    let limits = ExecutionLimits::default();
    let soft_timeout_ms = u64::try_from(limits.soft_timeout.as_millis()).unwrap_or(u64::MAX);
    let hard_timeout_ms = u64::try_from(limits.hard_timeout.as_millis()).unwrap_or(u64::MAX);

    json!({
        "schema_version": 1,
        "language": "Splash",
        "profile": {
            "id": CANONICAL_PROFILE_ID,
            "version": CANONICAL_PROFILE_VERSION,
            "grammar_path": CANONICAL_PROFILE_GRAMMAR_PATH,
            "canonical_only": true,
        },
        "preflight_limits": {
            "source_bytes": limits.max_source_bytes,
            "syntax_tokens": limits.max_syntax_tokens,
            "syntax_nesting": limits.max_syntax_nesting,
            "formatted_source_bytes": DEFAULT_MAX_FORMATTED_SOURCE_BYTES,
            "syntax_diagnostics": MAX_SYNTAX_DIAGNOSTICS,
        },
        "tooling_limits": {
            "tool_call_hints": MAX_TOOL_CALL_HINTS,
            "lexical_symbol_occurrences": MAX_LEXICAL_SYMBOL_OCCURRENCES,
            "lexical_completion_sites": MAX_LEXICAL_COMPLETION_SITES,
        },
        "evaluation_limits": {
            "instruction_limit": limits.instruction_limit,
            "soft_timeout_ms": soft_timeout_ms,
            "hard_timeout_ms": hard_timeout_ms,
            "budget_sample_interval": limits.budget_sample_interval,
        },
        "effect_free_commands": {
            "profile": "splash profile",
            "format": "splash format [--check] <file>",
            "check": "splash check <file>",
            "outline": "splash outline <file>",
            "tool_calls": "splash tool-calls <file>",
            "workflow_review": "splash workflow-review <draft.json>",
        },
        "tool_api": {
            "import": "use mod.tool",
            "await_method": ".await()",
            "catalog_source": "host",
            "calls": [
                {
                    "method": "tool.call",
                    "input": "text",
                    "returns": "text",
                },
                {
                    "method": "tool.start",
                    "input": "text",
                    "returns": "promise",
                    "await_result": "text",
                },
                {
                    "method": "tool.call_json",
                    "input": "record_or_array_json_envelope",
                    "returns": "json_text",
                    "decode_result": "parse_json",
                },
                {
                    "method": "tool.start_json",
                    "input": "record_or_array_json_envelope",
                    "returns": "promise",
                    "await_result": "json_text",
                    "decode_await_result": "parse_json",
                },
            ],
        },
        "authority": {
            "ambient_os_apis": false,
            "ambient_rust_crate_access": false,
            "imports_grant_authority": false,
            "tool_registration": "host_only",
            "tool_authorization": "runtime_host_policy",
            "operator_approval": "optional_host_owned_capability_lease",
            "static_tool_call_hints_authorize": false,
            "workflow_drafts_grant_authority": false,
            "workflow_approvals": "host_owned",
        },
    })
}

fn register_demo_tools(
    runtime: &mut CapabilityRuntime,
    allow_echo: bool,
    allow_json_add: bool,
) -> Result<(), String> {
    if allow_echo {
        runtime
            .register_tool_with_metadata(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("Returns the supplied text unchanged."),
                demo_echo_handler,
            )
            .map_err(|error| error.to_string())?;
    }
    if allow_json_add {
        runtime
            .register_validated_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds the integer left and right fields."),
                json_add_contract()?,
                demo_json_add_handler,
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn build_demo_mobile_workflow(
    allow_echo: bool,
    allow_json_add: bool,
) -> Result<MobileWorkflowRuntime, String> {
    let mut builder = MobileWorkflowBuilder::new().map_err(|error| error.to_string())?;
    if allow_echo {
        builder
            .register_text_tool(
                ToolPolicy::new("text.echo"),
                ToolMetadata::new("Returns the supplied text unchanged."),
                demo_echo_handler,
            )
            .map_err(|error| error.to_string())?;
    }
    if allow_json_add {
        builder
            .register_json_tool(
                ToolPolicy::json("math.add"),
                ToolMetadata::new("Adds the integer left and right fields."),
                json_add_contract()?,
                demo_json_add_handler,
            )
            .map_err(|error| error.to_string())?;
    }
    Ok(builder.build())
}

fn json_add_contract() -> Result<JsonToolContract, String> {
    JsonToolContract::new(
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
    .map_err(|error| error.to_string())
}

fn demo_echo_handler(request: &ToolRequest) -> Result<String, ToolError> {
    Ok(request.input.clone())
}

fn demo_json_add_handler(request: &JsonToolRequest) -> Result<JsonValue, ToolError> {
    let left = request.input["left"]
        .as_i64()
        .ok_or_else(|| ToolError::Denied("math.add expects an integer left field".to_owned()))?;
    let right = request.input["right"]
        .as_i64()
        .ok_or_else(|| ToolError::Denied("math.add expects an integer right field".to_owned()))?;
    let total = left
        .checked_add(right)
        .ok_or_else(|| ToolError::Denied("math.add result exceeds the i64 range".to_owned()))?;
    Ok(json!({"total": total}))
}

fn run_workflow_execution(
    source: &str,
    grants: &[CliWorkflowGrant],
    input_path: Option<&str>,
    allow_echo: bool,
    allow_json_add: bool,
) -> Result<(), String> {
    let input = input_path.map(read_workflow_input).transpose()?;
    let (output, completed) =
        workflow_execution_output_with_input(source, grants, input, allow_echo, allow_json_add)?;
    println!("{output}");
    completed
        .then_some(())
        .ok_or_else(|| "workflow execution failed".to_owned())
}

#[cfg(test)]
fn workflow_execution_output(
    source: &str,
    grants: &[CliWorkflowGrant],
    allow_echo: bool,
    allow_json_add: bool,
) -> Result<(JsonValue, bool), String> {
    workflow_execution_output_with_input(source, grants, None, allow_echo, allow_json_add)
}

fn workflow_execution_output_with_input(
    source: &str,
    grants: &[CliWorkflowGrant],
    input: Option<WorkflowData>,
    allow_echo: bool,
    allow_json_add: bool,
) -> Result<(JsonValue, bool), String> {
    let draft = WorkflowDraft::from_json(source).map_err(|error| error.to_string())?;
    let (review, valid) = workflow_review_json(&draft)?;
    if !valid {
        return Ok((json!({"status": "rejected", "review": review}), false));
    }

    let mut workflow = build_demo_mobile_workflow(allow_echo, allow_json_add)?;
    let plan = workflow
        .plan_draft(draft)
        .map_err(|error| error.to_string())?;
    let policies = workflow_policies(&plan, &workflow.tool_catalog(), grants)?;
    let (execution_error, dataflow) = if let Some(input) = input {
        let approval = workflow
            .approve_dataflow_with_step_capability_policies(&plan, input, policies)
            .map_err(|error| error.to_string())?;
        match workflow.execute_dataflow(&plan, approval) {
            Ok(data) => (None, Some(data)),
            Err(error) => (
                Some(error.to_string()),
                workflow.dataflow_snapshot().cloned(),
            ),
        }
    } else {
        let approval = workflow
            .approve_with_step_capability_policies(&plan, policies)
            .map_err(|error| error.to_string())?;
        (
            workflow
                .execute(&plan, approval)
                .err()
                .map(|error| error.to_string()),
            None,
        )
    };
    let completed = execution_error.is_none();
    let audit = workflow
        .audit()
        .iter()
        .map(|event| {
            json!({
                "sequence": event.sequence,
                "tool": event.tool,
                "input_bytes": event.input_bytes,
                "output_bytes": event.output_bytes,
                "outcome": event.outcome,
                "retry_class": event.retry_class,
            })
        })
        .collect::<Vec<_>>();
    let dataflow = dataflow.as_ref().map(workflow_data_output).transpose()?;

    Ok((
        json!({
            "status": if completed { "completed" } else { "failed" },
            "plan": {
                "id": plan.id(),
                "fingerprint": plan.fingerprint(),
                "step_count": plan.steps().len(),
            },
            "steps": workflow_step_statuses(&workflow, &plan),
            "audit": audit,
            "dropped_audit_events": workflow.dropped_audit_events(),
            "dropped_workflow_events": workflow.dropped_events(),
            "dataflow": dataflow,
            "error": execution_error,
        }),
        completed,
    ))
}

fn read_workflow_input(path: &str) -> Result<WorkflowData, String> {
    let document = read_utf8_file_with_max_bytes(path, MAX_WORKFLOW_DATA_BYTES)?;
    WorkflowData::from_input_json(&document).map_err(|error| error.to_string())
}

fn workflow_data_output(data: &WorkflowData) -> Result<JsonValue, String> {
    Ok(json!({
        "fingerprint": data.fingerprint().map_err(|error| error.to_string())?,
        "input": data.input(),
        "outputs": data.outputs(),
    }))
}

fn workflow_policies(
    plan: &WorkflowPlan,
    catalog: &[ToolDescriptor],
    grants: &[CliWorkflowGrant],
) -> Result<Vec<WorkflowStepCapabilityPolicy>, String> {
    for grant in grants {
        if !plan.steps().iter().any(|step| step.id == grant.step_id) {
            return Err("--grant references a step absent from the workflow draft".to_owned());
        }
        if !catalog
            .iter()
            .any(|descriptor| descriptor.name == grant.tool)
        {
            return Err(
                "--grant names a capability absent from the enabled demo catalog".to_owned(),
            );
        }
    }

    Ok(plan
        .steps()
        .iter()
        .map(|step| {
            WorkflowStepCapabilityPolicy::new(
                step.id.clone(),
                grants
                    .iter()
                    .filter(|grant| grant.step_id == step.id)
                    .map(|grant| CapabilityLeaseGrant::new(grant.tool.clone(), grant.max_calls)),
            )
        })
        .collect())
}

fn workflow_step_statuses(workflow: &MobileWorkflowRuntime, plan: &WorkflowPlan) -> Vec<JsonValue> {
    plan.steps()
        .iter()
        .map(|step| {
            let mut status = "pending";
            let mut diagnostic_count = None;
            for event in workflow.events() {
                match event {
                    WorkflowEvent::StepSucceeded { step_id, .. } if step_id == &step.id => {
                        status = "succeeded";
                    }
                    WorkflowEvent::StepFailed {
                        step_id,
                        diagnostic_count: count,
                        ..
                    } if step_id == &step.id => {
                        status = "failed";
                        diagnostic_count = Some(*count);
                    }
                    WorkflowEvent::StepRejected {
                        step_id,
                        diagnostic_count: count,
                        ..
                    } if step_id == &step.id => {
                        status = "rejected";
                        diagnostic_count = Some(*count);
                    }
                    WorkflowEvent::StepSuspended { step_id, .. } if step_id == &step.id => {
                        status = "suspended";
                    }
                    _ => {}
                }
            }
            json!({
                "id": step.id,
                "status": status,
                "diagnostic_count": diagnostic_count,
            })
        })
        .collect()
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

fn run_tool_calls(file: &str, source: &str) -> Result<(), String> {
    let (output, valid) = tool_calls_output(file, source)?;
    println!("{output}");
    valid
        .then_some(())
        .ok_or_else(|| "syntax check failed".to_owned())
}

fn run_workflow_review(_file: &str, source: &str) -> Result<(), String> {
    let (output, valid) = workflow_review_output(source)?;
    println!("{output}");
    valid
        .then_some(())
        .ok_or_else(|| "workflow syntax review failed".to_owned())
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

fn tool_calls_output(file: &str, source: &str) -> Result<(JsonValue, bool), String> {
    let report = check_syntax_named(file, source, ExecutionLimits::default())
        .map_err(|error| error.to_string())?;
    let (tool_calls, tool_calls_truncated) = if report.valid {
        let hint_report = tool_call_hint_report_named(file, source, ExecutionLimits::default())
            .map_err(|error| error.to_string())?;
        (
            hint_report
                .hints
                .iter()
                .map(tool_call_hint_json)
                .collect::<Vec<_>>(),
            hint_report.truncated,
        )
    } else {
        (Vec::new(), false)
    };
    let valid = report.valid;
    Ok((
        json!({
            "valid": valid,
            "diagnostics_truncated": report.diagnostics_truncated,
            "diagnostics": syntax_diagnostics_json(&report),
            "tool_calls": tool_calls,
            "tool_calls_truncated": tool_calls_truncated,
        }),
        valid,
    ))
}

fn workflow_review_output(source: &str) -> Result<(JsonValue, bool), String> {
    let draft = WorkflowDraft::from_json(source).map_err(|error| error.to_string())?;
    workflow_review_json(&draft)
}

fn workflow_review_json(draft: &WorkflowDraft) -> Result<(JsonValue, bool), String> {
    let review = draft.review().map_err(|error| error.to_string())?;
    let valid = review.iter().all(|step| step.syntax.valid);
    let steps = review
        .iter()
        .map(|step| {
            json!({
                "id": step.step_id,
                "valid": step.syntax.valid,
                "diagnostics_truncated": step.syntax.diagnostics_truncated,
                "diagnostics": syntax_diagnostics_json(&step.syntax),
                "tool_calls": step.tool_calls.iter().map(tool_call_hint_json).collect::<Vec<_>>(),
                "tool_calls_truncated": step.tool_calls_truncated,
            })
        })
        .collect::<Vec<_>>();
    Ok((json!({"valid": valid, "steps": steps}), valid))
}

fn tool_call_hint_json(hint: &ToolCallHint) -> JsonValue {
    let name = hint
        .literal_name_start_byte
        .zip(hint.literal_name_end_byte)
        .map_or_else(
            || json!({"kind": "dynamic"}),
            |(start_byte, end_byte)| {
                json!({
                    "kind": "literal",
                    "value": hint.literal_name,
                    "start_byte": start_byte,
                    "end_byte": end_byte,
                })
            },
        );
    json!({
        "kind": hint.kind.as_str(),
        "callee": {
            "line": hint.line,
            "column": hint.column,
            "start_byte": hint.callee_start_byte,
            "end_byte": hint.callee_end_byte,
        },
        "name": name,
    })
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

fn read_utf8_file_with_max_bytes(path: &str, max_bytes: usize) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let mut bytes = Vec::new();
    let sentinel_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    file.by_ref()
        .take(sentinel_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {path}: {error}"))?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "cannot read {path}: input exceeds {max_bytes} bytes"
        ));
    }
    String::from_utf8(bytes).map_err(|_| format!("cannot read {path}: input is not valid UTF-8"))
}

fn parse_workflow_grant(value: &str) -> Result<CliWorkflowGrant, String> {
    let mut parts = value.split(':');
    let (Some(step_id), Some(tool), Some(max_calls), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("--grant must use step-id:tool-name:max-calls".to_owned());
    };
    if !is_cli_grant_identifier(step_id, MAX_WORKFLOW_STEP_ID_BYTES)
        || !is_cli_grant_identifier(tool, splash_capabilities::MAX_TOOL_NAME_BYTES)
    {
        return Err("--grant must use validated lowercase ASCII identifiers".to_owned());
    }
    let max_calls = max_calls
        .parse::<usize>()
        .map_err(|_| "--grant max-calls must be a positive integer".to_owned())?;
    if max_calls == 0 {
        return Err("--grant max-calls must be a positive integer".to_owned());
    }
    Ok(CliWorkflowGrant {
        step_id: step_id.to_owned(),
        tool: tool.to_owned(),
        max_calls,
    })
}

fn is_cli_grant_identifier(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn parse_args(args: Vec<String>) -> Result<CliOptions, String> {
    let mut allow_echo = false;
    let mut allow_json_add = false;
    let mut format_check = false;
    let mut workflow_grants = Vec::new();
    let mut workflow_input_path = None;
    let mut positional = Vec::new();

    let mut arguments = args.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--allow-echo" => allow_echo = true,
            "--allow-json-add" => allow_json_add = true,
            "--check" => format_check = true,
            "--grant" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--grant requires step-id:tool-name:max-calls".to_owned())?;
                if workflow_grants.len() == MAX_WORKFLOW_CLI_GRANTS {
                    return Err(format!(
                        "workflow-run accepts at most {MAX_WORKFLOW_CLI_GRANTS} explicit grants"
                    ));
                }
                workflow_grants.push(parse_workflow_grant(&value)?);
            }
            "--input" => {
                let path = arguments
                    .next()
                    .ok_or_else(|| "--input requires a JSON file path".to_owned())?;
                if workflow_input_path.replace(path).is_some() {
                    return Err("workflow-run accepts at most one --input file".to_owned());
                }
            }
            "check" | "outline" | "tool-calls" | "workflow-review" | "workflow-run" | "eval"
            | "run" | "format" | "catalog" | "profile" => positional.push(argument),
            _ => positional.push(argument),
        }
    }

    if format_check && positional.first().is_none_or(|command| command != "format") {
        return Err("--check is only valid with splash format".to_owned());
    }
    if !workflow_grants.is_empty()
        && positional
            .first()
            .is_none_or(|command| command != "workflow-run")
    {
        return Err("--grant is only valid with splash workflow-run".to_owned());
    }
    if workflow_input_path.is_some()
        && positional
            .first()
            .is_none_or(|command| command != "workflow-run")
    {
        return Err("--input is only valid with splash workflow-run".to_owned());
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
        [command, path] if command == "tool-calls" => fs::read_to_string(path)
            .map(|source| CliOptions {
                command: CliCommand::ToolCalls {
                    file: path.clone(),
                    source,
                },
                allow_echo,
                allow_json_add,
            })
            .map_err(|error| format!("cannot read {path}: {error}")),
        [command, path] if command == "workflow-review" => {
            read_utf8_file_with_max_bytes(path, MAX_WORKFLOW_DRAFT_BYTES)
            .map(|source| CliOptions {
                command: CliCommand::WorkflowReview {
                    file: path.clone(),
                    source,
                },
                allow_echo,
                allow_json_add,
            })
        }
        [command, path] if command == "workflow-run" => {
            read_utf8_file_with_max_bytes(path, MAX_WORKFLOW_DRAFT_BYTES).map(|source| {
                CliOptions {
                    command: CliCommand::WorkflowRun {
                        file: path.clone(),
                        source,
                        grants: workflow_grants,
                        input_path: workflow_input_path,
                    },
                    allow_echo,
                    allow_json_add,
                }
            })
        }
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
        [command] if command == "profile" => Ok(CliOptions {
            command: CliCommand::Profile,
            allow_echo,
            allow_json_add,
        }),
        _ => Err(
            "usage: splash profile | splash check <file> | splash outline <file> | splash tool-calls <file> | splash workflow-review <draft.json> | splash workflow-run [--allow-echo] [--allow-json-add] [--input input.json] [--grant step-id:tool-name:max-calls] <draft.json> | splash format [--check] <file> | splash eval [--allow-echo] [--allow-json-add] '<source>' | splash run [--allow-echo] [--allow-json-add] <file> | splash catalog [--allow-echo] [--allow-json-add]".to_owned(),
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
    fn parses_a_profile_invocation() {
        assert_eq!(
            parse_args(vec!["profile".to_owned()]).unwrap(),
            CliOptions {
                command: CliCommand::Profile,
                allow_echo: false,
                allow_json_add: false,
            }
        );
    }

    #[test]
    fn profile_output_matches_the_canonical_runtime_contract() {
        let output = profile_output();
        let limits = ExecutionLimits::default();

        assert_eq!(output["schema_version"], json!(1));
        assert_eq!(output["language"], json!("Splash"));
        assert_eq!(output["profile"]["id"], json!(CANONICAL_PROFILE_ID));
        assert_eq!(
            output["profile"]["version"],
            json!(CANONICAL_PROFILE_VERSION)
        );
        assert_eq!(
            output["profile"]["grammar_path"],
            json!(CANONICAL_PROFILE_GRAMMAR_PATH)
        );
        assert_eq!(output["profile"]["canonical_only"], json!(true));
        assert_eq!(
            output["preflight_limits"]["source_bytes"],
            json!(limits.max_source_bytes)
        );
        assert_eq!(
            output["preflight_limits"]["syntax_tokens"],
            json!(limits.max_syntax_tokens)
        );
        assert_eq!(
            output["preflight_limits"]["syntax_nesting"],
            json!(limits.max_syntax_nesting)
        );
        assert_eq!(
            output["preflight_limits"]["formatted_source_bytes"],
            json!(DEFAULT_MAX_FORMATTED_SOURCE_BYTES)
        );
        assert_eq!(
            output["preflight_limits"]["syntax_diagnostics"],
            json!(MAX_SYNTAX_DIAGNOSTICS)
        );
        assert_eq!(
            output["tooling_limits"]["tool_call_hints"],
            json!(MAX_TOOL_CALL_HINTS)
        );
        assert_eq!(
            output["tooling_limits"]["lexical_symbol_occurrences"],
            json!(MAX_LEXICAL_SYMBOL_OCCURRENCES)
        );
        assert_eq!(
            output["tooling_limits"]["lexical_completion_sites"],
            json!(MAX_LEXICAL_COMPLETION_SITES)
        );
        assert_eq!(
            output["evaluation_limits"]["instruction_limit"],
            json!(limits.instruction_limit)
        );
        assert_eq!(
            output["evaluation_limits"]["soft_timeout_ms"],
            json!(u64::try_from(limits.soft_timeout.as_millis()).unwrap())
        );
        assert_eq!(
            output["evaluation_limits"]["hard_timeout_ms"],
            json!(u64::try_from(limits.hard_timeout.as_millis()).unwrap())
        );
        assert_eq!(
            output["evaluation_limits"]["budget_sample_interval"],
            json!(limits.budget_sample_interval)
        );
        assert_eq!(
            output["effect_free_commands"]["profile"],
            json!("splash profile")
        );
        assert_eq!(output["authority"]["ambient_os_apis"], json!(false));
        assert_eq!(output["authority"]["imports_grant_authority"], json!(false));
        assert_eq!(
            output["authority"]["static_tool_call_hints_authorize"],
            json!(false)
        );
        assert_eq!(
            output["authority"]["workflow_drafts_grant_authority"],
            json!(false)
        );
        assert_eq!(
            output["tool_api"]["calls"].as_array().map(Vec::len),
            Some(4)
        );
        assert_eq!(output["tool_api"]["await_method"], json!(".await()"));
    }

    #[test]
    fn bounded_utf8_reader_rejects_excess_bytes_before_decoding() {
        let unique = format!(
            "splash-cli-bounded-reader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::write(&path, b"12345\xff").unwrap();
        let display = path.display().to_string();

        let error = read_utf8_file_with_max_bytes(&display, 4).unwrap_err();

        fs::remove_file(&path).unwrap();
        assert_eq!(
            error,
            format!("cannot read {display}: input exceeds 4 bytes")
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
    fn parses_a_tool_call_outline_invocation() {
        let path = format!(
            "{}/../splash-core/tests/fixtures/workflow_language.splash",
            env!("CARGO_MANIFEST_DIR")
        );
        assert_eq!(
            parse_args(vec!["tool-calls".to_owned(), path.clone()]).unwrap(),
            CliOptions {
                command: CliCommand::ToolCalls {
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
    fn parses_a_workflow_review_invocation() {
        let path = format!(
            "{}/../../examples/release_workflow_draft.json",
            env!("CARGO_MANIFEST_DIR")
        );
        assert_eq!(
            parse_args(vec!["workflow-review".to_owned(), path.clone()]).unwrap(),
            CliOptions {
                command: CliCommand::WorkflowReview {
                    file: path,
                    source: include_str!("../../../examples/release_workflow_draft.json")
                        .to_owned(),
                },
                allow_echo: false,
                allow_json_add: false,
            }
        );
    }

    #[test]
    fn parses_a_workflow_run_with_explicit_grants_only() {
        let path = format!(
            "{}/../../examples/release_workflow_draft.json",
            env!("CARGO_MANIFEST_DIR")
        );
        assert_eq!(
            parse_args(vec![
                "workflow-run".to_owned(),
                "--allow-echo".to_owned(),
                "--grant".to_owned(),
                "prepare:text.echo:1".to_owned(),
                path.clone(),
            ])
            .unwrap(),
            CliOptions {
                command: CliCommand::WorkflowRun {
                    file: path,
                    source: include_str!("../../../examples/release_workflow_draft.json")
                        .to_owned(),
                    grants: vec![CliWorkflowGrant {
                        step_id: "prepare".to_owned(),
                        tool: "text.echo".to_owned(),
                        max_calls: 1,
                    }],
                    input_path: None,
                },
                allow_echo: true,
                allow_json_add: false,
            }
        );
        assert_eq!(
            parse_args(vec![
                "eval".to_owned(),
                "let value = 1".to_owned(),
                "--grant".to_owned(),
                "prepare:text.echo:1".to_owned(),
            ])
            .unwrap_err(),
            "--grant is only valid with splash workflow-run"
        );
        assert_eq!(
            parse_args(vec![
                "workflow-run".to_owned(),
                "--grant".to_owned(),
                "prepare:text.echo:0".to_owned(),
                "missing.json".to_owned(),
            ])
            .unwrap_err(),
            "--grant max-calls must be a positive integer"
        );
    }

    #[test]
    fn parses_a_workflow_run_dataflow_input_only_for_workflow_execution() {
        let path = format!(
            "{}/../../examples/release_workflow_draft.json",
            env!("CARGO_MANIFEST_DIR")
        );

        let options = parse_args(vec![
            "workflow-run".to_owned(),
            "--input".to_owned(),
            "request.json".to_owned(),
            path,
        ])
        .unwrap();

        assert!(matches!(
            options.command,
            CliCommand::WorkflowRun {
                input_path: Some(ref input_path),
                ..
            } if input_path == "request.json"
        ));
        assert_eq!(
            parse_args(vec![
                "eval".to_owned(),
                "let value = 1".to_owned(),
                "--input".to_owned(),
                "request.json".to_owned(),
            ])
            .unwrap_err(),
            "--input is only valid with splash workflow-run"
        );
        assert_eq!(
            parse_args(vec![
                "workflow-run".to_owned(),
                "--input".to_owned(),
                "one.json".to_owned(),
                "--input".to_owned(),
                "two.json".to_owned(),
                "missing.json".to_owned(),
            ])
            .unwrap_err(),
            "workflow-run accepts at most one --input file"
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
    fn emits_a_non_authoritative_tool_call_outline() {
        let (output, valid) = tool_calls_output(
            "generated.splash",
            "use mod.tool\n\
             let plain = tool.call(\"text.echo\", \"hello\")\n\
             let selected = \"shell.exec\"\n\
             tool.start(selected, \"whoami\")\n\
             let wrapper = {tool: tool}\n\
             wrapper.tool.call(\"ignored.member\", \"x\")\n\
             // tool.call(\"ignored.comment\", \"x\")\n",
        )
        .expect("canonical source has a tool-call outline");

        assert!(valid);
        assert_eq!(output["valid"], json!(true));
        let tool_calls = output["tool_calls"]
            .as_array()
            .expect("tool-call outline uses an array");
        assert_eq!(tool_calls.len(), 2);
        assert_eq!(tool_calls[0]["kind"], json!("call"));
        assert_eq!(tool_calls[0]["name"]["kind"], json!("literal"));
        assert_eq!(tool_calls[0]["name"]["value"], json!("text.echo"));
        assert_eq!(tool_calls[1]["kind"], json!("start"));
        assert_eq!(tool_calls[1]["name"], json!({"kind": "dynamic"}));
        assert_eq!(output["tool_calls_truncated"], json!(false));
    }

    #[test]
    fn tool_call_outline_marks_omitted_hints_as_truncated() {
        let mut source = String::from("use mod.tool\n");
        for index in 0..=splash_core::MAX_TOOL_CALL_HINTS {
            source.push_str(&format!("tool.call(\"tool.{index}\", \"\")\n"));
        }

        let (output, valid) = tool_calls_output("generated.splash", &source).unwrap();

        assert!(valid);
        assert_eq!(
            output["tool_calls"].as_array().map(Vec::len),
            Some(splash_core::MAX_TOOL_CALL_HINTS)
        );
        assert_eq!(output["tool_calls_truncated"], json!(true));
    }

    #[test]
    fn tool_call_outline_keeps_diagnostics_and_rejects_invalid_source() {
        let (output, valid) = tool_calls_output("generated.splash", "var value = 1")
            .expect("invalid source still has structured output");

        assert!(!valid);
        assert_eq!(output["tool_calls"], json!([]));
        assert!(output["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| !diagnostics.is_empty()));
    }

    #[test]
    fn workflow_review_is_effect_free_and_returns_per_step_hints() {
        let (output, valid) = workflow_review_output(
            r#"{
                "format_version": 1,
                "steps": [
                    {
                        "id": "prepare",
                        "source": "use mod.tool\nlet notes = tool.call(\"text.echo\", \"review only\")"
                    },
                    {
                        "id": "publish",
                        "source": "use mod.tool\nlet selected = \"release.publish\"\ntool.start(selected, \"v1.0.0\")"
                    }
                ]
            }"#,
        )
        .unwrap();

        assert!(valid);
        assert_eq!(output["valid"], json!(true));
        let steps = output["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0]["id"], json!("prepare"));
        assert_eq!(steps[0]["tool_calls_truncated"], json!(false));
        assert_eq!(
            steps[0]["tool_calls"][0]["name"]["value"],
            json!("text.echo")
        );
        assert_eq!(steps[1]["id"], json!("publish"));
        assert_eq!(steps[1]["tool_calls_truncated"], json!(false));
        assert_eq!(
            steps[1]["tool_calls"][0]["name"],
            json!({"kind": "dynamic"})
        );
    }

    #[test]
    fn workflow_review_keeps_invalid_step_diagnostics_without_running_source() {
        let (output, valid) = workflow_review_output(
            r#"{
                "format_version": 1,
                "steps": [{"id": "invalid", "source": "var legacy = true"}]
            }"#,
        )
        .unwrap();

        assert!(!valid);
        assert_eq!(output["valid"], json!(false));
        assert_eq!(output["steps"][0]["id"], json!("invalid"));
        assert_eq!(output["steps"][0]["tool_calls"], json!([]));
        assert_eq!(output["steps"][0]["tool_calls_truncated"], json!(false));
        assert!(output["steps"][0]["diagnostics"]
            .as_array()
            .is_some_and(|diagnostics| !diagnostics.is_empty()));
    }

    #[test]
    fn workflow_run_executes_a_bounded_draft_with_explicit_step_grants() {
        let (output, completed) = workflow_execution_output(
            r#"{
                "format_version": 1,
                "steps": [
                    {
                        "id": "prepare",
                        "source": "use mod.tool\nlet notes = tool.start(\"text.echo\", \"draft release notes\").await()\nnotes"
                    },
                    {
                        "id": "calculate",
                        "source": "use mod.tool\nuse mod.std.assert\nlet raw = tool.call_json(\"math.add\", {left: 20, right: 22})\nlet result = raw.parse_json()\nassert(result.total == 42)"
                    }
                ]
            }"#,
            &[
                CliWorkflowGrant {
                    step_id: "prepare".to_owned(),
                    tool: "text.echo".to_owned(),
                    max_calls: 1,
                },
                CliWorkflowGrant {
                    step_id: "calculate".to_owned(),
                    tool: "math.add".to_owned(),
                    max_calls: 1,
                },
            ],
            true,
            true,
        )
        .expect("bounded draft executes through the sealed demo catalog");

        assert!(completed);
        assert_eq!(output["status"], json!("completed"));
        assert_eq!(output["steps"][0]["status"], json!("succeeded"));
        assert_eq!(output["steps"][1]["status"], json!("succeeded"));
        assert_eq!(output["audit"].as_array().map(Vec::len), Some(2));
        assert_eq!(output["audit"][0]["tool"], json!("text.echo"));
        assert_eq!(output["audit"][1]["tool"], json!("math.add"));
        assert_eq!(output["audit"][0]["outcome"], json!("allowed"));
        assert_eq!(output["audit"][1]["outcome"], json!("allowed"));
    }

    #[test]
    fn workflow_run_dataflow_uses_an_explicit_bounded_json_input() {
        let (output, completed) = workflow_execution_output_with_input(
            r#"{
                "format_version": 1,
                "steps": [
                    {
                        "id": "prepare",
                        "source": "use mod.tool\nlet raw = tool.call_json(\"math.add\", workflow.input)\nlet result = raw.parse_json()\nresult"
                    },
                    {
                        "id": "summarize",
                        "source": "let result = {next: workflow.outputs.prepare.total + 1}\nresult"
                    }
                ]
            }"#,
            &[CliWorkflowGrant {
                step_id: "prepare".to_owned(),
                tool: "math.add".to_owned(),
                max_calls: 1,
            }],
            Some(WorkflowData::new(json!({"left": 20, "right": 22})).unwrap()),
            false,
            true,
        )
        .expect("bounded dataflow runs through the sealed demo catalog");

        assert!(completed);
        assert_eq!(output["status"], json!("completed"));
        assert_eq!(
            output["dataflow"]["input"],
            json!({"left": 20, "right": 22})
        );
        assert_eq!(
            output["dataflow"]["outputs"]["prepare"],
            json!({"total": 42})
        );
        assert_eq!(
            output["dataflow"]["outputs"]["summarize"],
            json!({"next": 43})
        );
        assert!(output["dataflow"]["fingerprint"].is_string());
    }

    #[test]
    fn workflow_run_denies_an_omitted_grant_before_the_demo_adapter_runs() {
        let (output, completed) = workflow_execution_output(
            r#"{
                "format_version": 1,
                "steps": [{
                    "id": "prepare",
                    "source": "use mod.tool\ntool.call(\"text.echo\", \"draft release notes\")"
                }]
            }"#,
            &[],
            true,
            false,
        )
        .expect("denial is reported as workflow output");

        assert!(!completed);
        assert_eq!(output["status"], json!("failed"));
        assert_eq!(output["steps"][0]["status"], json!("failed"));
        assert_eq!(output["audit"].as_array().map(Vec::len), Some(1));
        assert_eq!(output["audit"][0]["tool"], json!("text.echo"));
        assert_eq!(output["audit"][0]["outcome"], json!("denied"));
    }

    #[test]
    fn workflow_run_rejects_grants_for_steps_absent_from_the_draft() {
        let error = workflow_execution_output(
            r#"{
                "format_version": 1,
                "steps": [{"id": "prepare", "source": "let done = true"}]
            }"#,
            &[CliWorkflowGrant {
                step_id: "other".to_owned(),
                tool: "text.echo".to_owned(),
                max_calls: 1,
            }],
            true,
            false,
        )
        .unwrap_err();

        assert_eq!(
            error,
            "--grant references a step absent from the workflow draft"
        );
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
