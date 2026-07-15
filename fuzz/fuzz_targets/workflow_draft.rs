#![no_main]

use libfuzzer_sys::fuzz_target;
use splash_capabilities::{CapabilityLeaseGrant, CapabilityRuntime, JsonSchema};
use splash_core::ExecutionLimits;
use splash_workflow::{
    WorkflowData, WorkflowDataContract, WorkflowDraft, WorkflowEngine, WorkflowStep,
    WorkflowStepCapabilityPolicy, WorkflowStepOutputContract, MAX_WORKFLOW_DATA_BYTES,
    MAX_WORKFLOW_DRAFT_BYTES, MAX_WORKFLOW_REVIEW_TOOL_CALL_HINTS,
};

const MAX_FUZZ_DRAFT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let Ok(document) = std::str::from_utf8(data) else {
        return;
    };
    if document.len() > MAX_FUZZ_DRAFT_BYTES {
        return;
    }

    if let Ok(dataflow) = WorkflowData::from_input_json(document) {
        assert_dataflow_round_trip(&dataflow);
    }
    if let Ok(dataflow) = WorkflowData::from_json(document) {
        assert_dataflow_round_trip(&dataflow);
    }
    if let (Ok(schema_source), Ok(dataflow)) = (
        serde_json::from_str(document),
        WorkflowData::from_input_json(document),
    ) {
        assert_contract_bound_pure_dataflow(schema_source, dataflow);
    }

    let Ok(draft) = WorkflowDraft::from_json_with_max_bytes(document, MAX_FUZZ_DRAFT_BYTES) else {
        return;
    };
    let encoded = draft
        .to_json()
        .expect("a bounded decoded workflow draft must re-encode");
    assert!(encoded.len() <= MAX_WORKFLOW_DRAFT_BYTES);
    let decoded = WorkflowDraft::from_json(&encoded)
        .expect("a workflow draft's own current-format encoding must decode");
    assert_eq!(decoded, draft);

    let review = draft
        .review_with_limits(ExecutionLimits {
            max_source_bytes: MAX_FUZZ_DRAFT_BYTES,
            ..ExecutionLimits::default()
        })
        .expect("bounded draft review uses valid limits");
    assert_eq!(review.len(), draft.steps().len());
    assert!(
        review
            .iter()
            .all(|step| !step.tool_calls_truncated || step.syntax.valid),
        "invalid source must not claim omitted tool-call hints"
    );
    assert!(
        review
            .iter()
            .map(|step| step.tool_calls.len())
            .sum::<usize>()
            <= MAX_WORKFLOW_REVIEW_TOOL_CALL_HINTS,
        "workflow review retained more tool-call hints than its aggregate cap"
    );
});

fn assert_dataflow_round_trip(dataflow: &WorkflowData) {
    let encoded = dataflow
        .to_json()
        .expect("a bounded decoded dataflow context must re-encode");
    assert!(encoded.len() <= MAX_WORKFLOW_DATA_BYTES);
    let decoded = WorkflowData::from_json(&encoded)
        .expect("a dataflow context's own current-format encoding must decode");
    assert_eq!(decoded, *dataflow);
    assert_eq!(
        decoded.fingerprint().unwrap(),
        dataflow.fingerprint().unwrap()
    );
}

fn assert_contract_bound_pure_dataflow(schema_source: serde_json::Value, dataflow: WorkflowData) {
    let Ok(input_schema) = JsonSchema::compile(schema_source) else {
        return;
    };
    let contract = WorkflowDataContract::new(
        input_schema.clone(),
        [WorkflowStepOutputContract::new("copy", input_schema)],
    )
    .expect("two bounded compiled schemas fit the workflow contract cap");
    let checkpoint_contract = contract.clone();
    let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
    let plan = engine
        .plan(vec![WorkflowStep::new(
            "copy",
            "let result = workflow.input\nresult",
        )])
        .expect("static one-step plan is valid");
    if contract.validate_for(&plan, &dataflow, 0).is_err() {
        return;
    }
    let expected_input = dataflow.input().clone();
    let approval = engine
        .approve_dataflow_with_contract_and_step_capability_policies(
            &plan,
            dataflow,
            contract,
            vec![WorkflowStepCapabilityPolicy::new(
                "copy",
                Vec::<CapabilityLeaseGrant>::new(),
            )],
        )
        .expect("validated data and contract approve under an empty pure-step lease");
    let mut completed = engine
        .execute_dataflow(&plan, approval)
        .expect("pure copy preserves an accepted JSON value under the same schema");
    assert_eq!(completed.output("copy"), Some(&expected_input));
    let checkpoint = engine
        .dataflow_checkpoint_after_with_contract(&plan, &mut completed, &checkpoint_contract, 1)
        .expect("completed contract-bound dataflow checkpoint is valid");
    let contract_fingerprint = checkpoint_contract.fingerprint();
    assert_eq!(
        checkpoint.data_contract_fingerprint(),
        Some(contract_fingerprint.as_str())
    );
}
