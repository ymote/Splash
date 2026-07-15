#![no_main]

use libfuzzer_sys::fuzz_target;
use splash_capabilities::{
    CapabilityRuntime, OperationReconcileResult, OperationStatus, SessionAuthenticator, SessionKey,
    SessionRole, ToolPolicy, WorkerMessage, WorkerPayload,
};
use splash_workflow::{
    WorkflowEngine, WorkflowError, WorkflowOperationLedger, WorkflowStep,
    MAX_WORKFLOW_OPERATION_LEDGER_BYTES, MAX_WORKFLOW_OPERATION_NONCE_BYTES,
};

const MAX_FUZZ_INPUT_BYTES: usize = MAX_WORKFLOW_OPERATION_LEDGER_BYTES;
const MAX_FUZZ_PAYLOAD_BYTES: usize = 4 * 1024;
const SENSITIVE_MARKER: &str = "splash-fuzz-secret:";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    fuzz_ledger_document(data);
    fuzz_external_operation_bridge(data);
});

fn fuzz_ledger_document(data: &[u8]) {
    let Ok(document) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(ledger) = WorkflowOperationLedger::from_json(document) else {
        return;
    };
    let encoded = ledger
        .to_json()
        .expect("a bounded decoded operation ledger must re-encode");
    assert!(encoded.len() <= MAX_WORKFLOW_OPERATION_LEDGER_BYTES);
    let decoded = WorkflowOperationLedger::from_json(&encoded)
        .expect("an operation ledger's current-format encoding must decode");
    assert_eq!(decoded, ledger);
}

fn fuzz_external_operation_bridge(data: &[u8]) {
    let control = data.first().copied().unwrap_or_default();
    let payload_bytes = data.get(1..).unwrap_or_default();
    let payload_bytes = &payload_bytes[..payload_bytes.len().min(MAX_FUZZ_PAYLOAD_BYTES)];
    let secret = format!("{SENSITIVE_MARKER}{}", hex_payload(payload_bytes));
    let use_json = control & 1 != 0;

    let mut policy = if use_json {
        ToolPolicy::json("fuzz.external")
    } else {
        ToolPolicy::new("fuzz.external")
    };
    // Start two deferred calls so a stale exact claim must not consume the
    // second queued invocation.
    policy.max_calls = 2;

    let secret_literal = serde_json::to_string(&secret)
        .expect("a Rust string always encodes as a Splash-compatible literal");
    let source = if use_json {
        format!(
            "use mod.tool\n\
             let first = tool.start_json(\"fuzz.external\", {{secret: {secret_literal}}})\n\
             let second = tool.start_json(\"fuzz.external\", {{sequence: 2}})\n\
             second.await()"
        )
    } else {
        format!(
            "use mod.tool\n\
             let first = tool.start(\"fuzz.external\", {secret_literal})\n\
             let second = tool.start(\"fuzz.external\", \"fuzz-secondary\")\n\
             second.await()"
        )
    };

    let mut runtime = CapabilityRuntime::default();
    runtime
        .register_external_tool(policy)
        .expect("the fixed external fuzz policy registers");
    let mut engine = WorkflowEngine::new(runtime);
    let plan = engine
        .plan(vec![WorkflowStep::new("dispatch", source)])
        .expect("the fixed external workflow plan is valid");
    let approval = engine
        .approve(&plan)
        .expect("the registered external tool receives a full lease");
    assert!(
        matches!(
            engine.execute(&plan, approval),
            Err(WorkflowError::StepSuspended {
                step_id,
                completed_steps: 0,
            }) if step_id == "dispatch"
        ),
        "the fixed external workflow must suspend at its awaiting step"
    );
    assert!(engine.has_suspended_execution());

    let mut ledger = engine
        .operation_ledger(&plan)
        .expect("a trusted plan creates an empty operation ledger");
    if control & 2 != 0 {
        let oversized_nonce = [0_u8; MAX_WORKFLOW_OPERATION_NONCE_BYTES + 1];
        let revision = ledger.revision();
        assert!(
            engine
                .prepare_next_external_operation(&plan, &mut ledger, &oversized_nonce)
                .is_err(),
            "an oversized host nonce must not create a durable operation"
        );
        assert_eq!(ledger.revision(), revision);
    }

    let nonce = if payload_bytes.is_empty() {
        b"fuzz-external-operation".as_slice()
    } else {
        &payload_bytes[..payload_bytes.len().min(MAX_WORKFLOW_OPERATION_NONCE_BYTES)]
    };
    let prepared = engine
        .prepare_next_external_operation(&plan, &mut ledger, nonce)
        .expect("a bounded nonce prepares the fixed queued operation")
        .expect("the fixed workflow has a queued external operation");
    let operation_key = prepared.operation_key().to_owned();
    assert_eq!(ledger.revision(), 1);
    let persisted = ledger
        .to_json()
        .expect("a prepared operation ledger is persistable");
    assert!(
        !persisted.contains(SENSITIVE_MARKER),
        "the durable ledger must not retain raw external input"
    );
    let mut restored = WorkflowOperationLedger::from_json(&persisted)
        .expect("a persisted prepared ledger must restore");
    assert_eq!(restored, ledger);

    let repeated = engine
        .prepare_next_external_operation(&plan, &mut ledger, nonce)
        .expect("repeating a prepared operation is valid")
        .expect("the operation remains queued until exact claim");
    assert_eq!(repeated.operation_key(), operation_key);
    assert_eq!(ledger.revision(), 1);

    if control & 4 != 0 {
        let directly_claimed = engine
            .claim_next_external_tool()
            .expect("the first fixed external operation is queued");
        assert!(
            engine
                .claim_prepared_external_operation(&plan, &restored, prepared)
                .is_err(),
            "a stale prepared ID must not claim another external operation"
        );
        let next = engine
            .runtime()
            .peek_next_external_tool()
            .expect("the second fixed external operation remains queued");
        assert_eq!(next.name, "fuzz.external");
        assert_ne!(next.id, directly_claimed.id);
        assert_ne!(next.input, directly_claimed.input);
        return;
    }

    let claimed = engine
        .claim_prepared_external_operation(&plan, &restored, prepared)
        .expect("a persisted exact operation claims its matching queued invocation");
    assert_eq!(claimed.operation_key(), operation_key);
    assert_eq!(claimed.payload(), repeated.payload());

    let (mut host, mut worker) = operation_authenticators();
    let outbound = engine
        .prepare_authenticated_claimed_external_operation_dispatch(
            &plan,
            &restored,
            &claimed,
            "fuzz-dispatch",
            &mut host,
        )
        .expect("a claimed persisted operation creates a worker dispatch frame");
    assert_eq!(
        worker
            .open(outbound.frame.clone())
            .expect("the paired worker authenticates the host dispatch"),
        WorkerMessage::DispatchOperation {
            request: outbound.request.clone(),
        }
    );

    let status = operation_status(control, use_json);
    let result = OperationReconcileResult::new(
        outbound.request.session_id.clone(),
        outbound.request.request_id.clone(),
        outbound.request.tool.clone(),
        outbound.request.operation_key.clone(),
        status,
    )
    .expect("the fixed authenticated worker result is valid");

    if control & 8 != 0 {
        let wrong_kind = worker
            .seal(WorkerMessage::ReconciledOperation {
                result: result.clone(),
            })
            .expect("the paired worker seals a valid non-dispatch frame");
        let revision = restored.revision();
        assert!(
            engine
                .apply_authenticated_operation_dispatch_result(
                    &plan,
                    &mut restored,
                    &outbound.request,
                    &mut host,
                    wrong_kind,
                )
                .is_err(),
            "a non-dispatch worker frame must not mutate the operation ledger"
        );
        assert_eq!(restored.revision(), revision);
    }

    let response = worker
        .seal(WorkerMessage::OperationResult { result })
        .expect("the paired worker seals a valid dispatch result");
    let replay = response.clone();
    let revision = restored.revision();
    let (state, _) = engine
        .apply_authenticated_operation_dispatch_result(
            &plan,
            &mut restored,
            &outbound.request,
            &mut host,
            response,
        )
        .expect("an authenticated matching result transitions the durable operation");
    assert_eq!(restored.revision(), revision + 1);
    assert_eq!(
        restored
            .operation(&operation_key)
            .expect("the dispatched operation remains recorded")
            .state(),
        state
    );
    let post_result = restored
        .to_json()
        .expect("a transitioned operation ledger remains persistable");
    assert!(!post_result.contains(SENSITIVE_MARKER));

    let revision = restored.revision();
    assert!(
        engine
            .apply_authenticated_operation_dispatch_result(
                &plan,
                &mut restored,
                &outbound.request,
                &mut host,
                replay,
            )
            .is_err(),
        "a replayed authenticated worker response must not mutate the ledger"
    );
    assert_eq!(restored.revision(), revision);
}

fn hex_payload(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 15) as usize] as char);
    }
    encoded
}

fn operation_authenticators() -> (SessionAuthenticator, SessionAuthenticator) {
    let key = SessionKey::from_bytes([13; 32]).expect("the fixed nonzero session key is valid");
    (
        SessionAuthenticator::new("fuzz-worker", key.clone(), SessionRole::Host)
            .expect("the fixed host session is valid"),
        SessionAuthenticator::new("fuzz-worker", key, SessionRole::Worker)
            .expect("the fixed worker session is valid"),
    )
}

fn operation_status(control: u8, use_json: bool) -> OperationStatus {
    match (control >> 4) & 3 {
        0 => OperationStatus::Running,
        1 => OperationStatus::Succeeded {
            payload: if use_json {
                WorkerPayload::Json(serde_json::json!({"completed": true}))
            } else {
                WorkerPayload::Text("fuzz-result".to_owned())
            },
        },
        2 => OperationStatus::Failed {
            message: "fuzz worker failure".to_owned(),
        },
        _ => OperationStatus::Cancelled,
    }
}
