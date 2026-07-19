#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

fn example_path(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn run_splash(arguments: Vec<String>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_splash"))
        .args(arguments)
        .output()
        .expect("the Splash CLI binary should run")
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("the Splash CLI should emit JSON stdout")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("the Splash CLI should emit UTF-8 stderr")
}

#[test]
fn profile_contract_discloses_no_ambient_authority() {
    let output = run_splash(vec!["profile".to_owned()]);

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let output = json_stdout(&output);
    assert_eq!(output["language"], "Splash");
    assert_eq!(output["profile"]["canonical_only"], true);
    assert_eq!(output["authority"]["ambient_os_apis"], false);
    assert_eq!(output["authority"]["ambient_rust_crate_access"], false);
    assert_eq!(
        output["authority"]["workflow_drafts_grant_authority"],
        false
    );
}

#[test]
fn reviewed_dataflow_executes_only_with_an_explicit_step_grant() {
    let draft = example_path("dataflow_workflow_draft.json");
    let input = example_path("dataflow_input.json");

    let review = run_splash(vec!["workflow-review".to_owned(), draft.clone()]);
    assert!(review.status.success(), "stderr: {}", stderr(&review));
    let review = json_stdout(&review);
    assert_eq!(review["valid"], true);
    assert_eq!(
        review["steps"][0]["tool_calls"][0]["name"]["value"],
        "math.add"
    );

    let allowed = run_splash(vec![
        "workflow-run".to_owned(),
        "--allow-json-add".to_owned(),
        "--input".to_owned(),
        input.clone(),
        "--grant".to_owned(),
        "prepare:math.add:1".to_owned(),
        draft.clone(),
    ]);
    assert!(allowed.status.success(), "stderr: {}", stderr(&allowed));
    let allowed = json_stdout(&allowed);
    assert_eq!(allowed["status"], "completed");
    assert_eq!(allowed["audit"][0]["outcome"], "allowed");
    assert_eq!(allowed["dataflow"]["outputs"]["prepare"]["total"], 42);
    assert_eq!(allowed["dataflow"]["outputs"]["summarize"]["total"], 42);

    let denied = run_splash(vec![
        "workflow-run".to_owned(),
        "--allow-json-add".to_owned(),
        "--input".to_owned(),
        input,
        draft,
    ]);
    assert!(!denied.status.success());
    let denied_stdout = json_stdout(&denied);
    assert_eq!(denied_stdout["status"], "failed");
    assert_eq!(denied_stdout["audit"][0]["outcome"], "denied");
    assert_eq!(denied_stdout["dataflow"]["outputs"], serde_json::json!({}));
    assert!(stderr(&denied).contains("workflow execution failed"));
}

#[test]
fn direct_module_catalog_is_explicit_and_the_demo_source_runs() {
    let unavailable = run_splash(vec!["module-catalog".to_owned()]);
    assert!(
        unavailable.status.success(),
        "stderr: {}",
        stderr(&unavailable)
    );
    assert_eq!(json_stdout(&unavailable), serde_json::json!([]));

    let catalog = run_splash(vec![
        "module-catalog".to_owned(),
        "--allow-json-add".to_owned(),
    ]);
    assert!(catalog.status.success(), "stderr: {}", stderr(&catalog));
    let catalog = json_stdout(&catalog);
    assert_eq!(catalog.as_array().map(Vec::len), Some(1));
    assert_eq!(catalog[0]["name"], "arithmetic");
    assert_eq!(catalog[0]["methods"][0]["name"], "add");
    assert_eq!(catalog[0]["methods"][0]["tool"], "math.add");

    let source = example_path("direct_module_workflow.splash");
    let execution = run_splash(vec![
        "run".to_owned(),
        "--allow-json-add".to_owned(),
        source,
    ]);
    assert!(execution.status.success(), "stderr: {}", stderr(&execution));
}
