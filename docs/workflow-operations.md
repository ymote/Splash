# Durable Operation Ledgers

`splash-workflow` provides `WorkflowOperationLedger` for the host-owned
durable intent of an external effect. It is complementary to a workflow
checkpoint: a checkpoint describes a completed step prefix, while a ledger
describes an operation that may still be uncertain around a crash or worker
disconnect.

The ledger contains only bounded metadata:

- a format version and monotonic revision;
- the BLAKE3 fingerprint of the trusted workflow plan;
- for each operation: its step ID, tool name, durable operation key, BLAKE3
  input fingerprint, worker-observed state, and at most one separately bound
  compensation intent.

It never stores raw input, output, error text, raw secret values, source, an approval,
capability grant, VM state, promise, stream chunk, or `ExternalToolId`.

## Record Before Dispatch

Create and persist an operation record before sending an effectful request to
a worker. Prefer `record_derived_operation`: it derives a non-authorizing
operation key from the plan fingerprint, step ID, tool, complete input bytes,
and a host-supplied durable nonce.

~~~rust
use splash_capabilities::CapabilityRuntime;
use splash_protocol::{canonical_operation_input_bytes, ToolPayload};
use splash_workflow::{WorkflowEngine, WorkflowStep};

let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
let plan = engine.plan(vec![WorkflowStep::new(
    "publish",
    "let release = true",
)])?;
let mut ledger = engine.operation_ledger(&plan)?;

let payload = ToolPayload::Json(serde_json::json!({"version": "1.2.3"}));
let input = canonical_operation_input_bytes(&payload)?;
let operation_key = engine.record_derived_operation(
    &plan,
    &mut ledger,
    "publish",
    "release.publish",
    &input,
    b"run-42:publish:1",
)?;
let stored_ledger = ledger.to_json()?;

let dispatch = engine.operation_dispatch_request(
    &plan,
    &ledger,
    &operation_key,
    payload,
    "worker-1",
    "dispatch-1",
)?;
~~~

The nonce must be non-empty and unique for every logical effect, for example a
persisted workflow-run ID plus an operation ordinal. Reusing a nonce for a
different logical operation defeats downstream deduplication. The input must
be the exact canonical bytes supplied to the worker; do not hash a display
form, partial request, or a value that omits context affecting the effect.

The input fingerprint is an unkeyed BLAKE3 correlation digest, not encrypted
secret storage or a MAC. Keep credentials and secret values out of the input
identity: pass opaque secret selectors or handles to the worker policy instead.
Authenticated durable storage remains required even when no raw secret appears
in the ledger.

When dispatching through worker protocol v5, record
`canonical_operation_input_bytes(&payload)` rather than an ad hoc JSON string.
`operation_dispatch_request` recreates those same bytes and rejects a payload
whose durable identity differs from the ledger entry.

The derived key is not a credential. Its purpose is to bind the host's plan,
input, and operation identity into the durable worker-deduplication key. Hosts
with an existing durable worker key may use `record_operation`, but then they
must ensure the key is unique across workflow plans and input revisions.

## Bridge A Live External Await

For a workflow step that is already suspended on an external `await`, prefer
the two-stage bridge below instead of manually combining
`claim_next_external_tool` and `record_derived_operation`.

1. Call `prepare_next_external_operation`. It inspects the next queued
   external invocation without claiming it, converts its exact text or JSON
   envelope to canonical worker input, and records or verifies the plan-bound
   durable key in the ledger.
2. Persist the changed ledger through authenticated compare-and-swap storage.
   This must finish before the host claims or dispatches the operation.
3. Call `claim_prepared_external_operation` with that same ledger. It claims
   only the prepared opaque runtime ID; a stale preparation fails rather than
   consuming a different queued tool invocation.
4. Use `prepare_authenticated_claimed_external_operation_dispatch` to create
   the worker frame from the bound key and exact payload. Send the frame only
   after the ledger persistence in step 2.
5. When the worker responds, call
   `apply_authenticated_operation_dispatch_result`. It authenticates the
   frame and updates only the ledger state while returning the verified result.
   Persist that updated ledger before resolving the Splash promise with
   `complete_external_tool` or recording the authenticated terminal
   `cancelled` observation with `cancel_external_tool`. A host-originated
   cooperative stop instead uses the separate request/confirm cancellation
   pair and must not treat process termination as acknowledgement.

~~~rust
let mut ledger = engine.operation_ledger(&plan)?;
let prepared = engine
    .prepare_next_external_operation(
        &plan,
        &mut ledger,
        b"workflow-run-42:publish:operation-0",
    )?
    .expect("queued external operation");

persist_ledger_compare_and_swap(ledger.to_json()?)?; // before claim or dispatch

let claimed = engine.claim_prepared_external_operation(&plan, &ledger, prepared)?;
let outbound = engine.prepare_authenticated_claimed_external_operation_dispatch(
    &plan,
    &ledger,
    &claimed,
    "publish-dispatch-1",
    &mut host_authenticator,
)?;
send_to_worker(outbound.frame)?;

let (state, result) = engine.apply_authenticated_operation_dispatch_result(
    &plan,
    &mut ledger,
    &outbound.request,
    &mut host_authenticator,
    worker_frame,
)?;
persist_ledger_compare_and_swap(ledger.to_json()?)?; // before promise completion

match result.status {
    OperationStatus::Succeeded {
        payload: ToolPayload::Text(output),
    } => engine.complete_external_tool(claimed.invocation().id, Ok(output))?,
    OperationStatus::Succeeded {
        payload: ToolPayload::Json(output),
    } => engine.complete_external_tool(
        claimed.invocation().id,
        Ok(serde_json::to_string(&output)?),
    )?,
    OperationStatus::Failed { message } => engine.complete_external_tool(
        claimed.invocation().id,
        Err(ToolError::Failed(message)),
    )?,
    OperationStatus::Cancelled => engine.cancel_external_tool(claimed.invocation().id)?,
    OperationStatus::Running => {}
}
~~~

The nonce is host-owned and durable. Use a persisted workflow-run identifier
and a host-defined operation ordinal; do not derive it from Splash source,
the runtime-local `call_index`, or the external runtime's idempotency key.
Those values can change when a process or resumed suffix is recreated.

The bridge does not serialize a VM continuation, `ExternalToolId`, payload,
approval, or worker session. After a process restart, rebuild the trusted plan
and capability policy, restore and validate the ledger, reconcile the durable
operation, then choose an explicit policy for a new workflow execution. A
terminal ledger state alone is not permission to skip or resume a Splash step.

## Live Ordinary Cancellation

Protocol v5 also has a non-durable cooperative path for an external workflow
step dispatched as an ordinary `invoke`. Enable
`splash-workflow/multiplexed-worker`, start the claimed invocation through a
`SupervisedMultiplexedWorkerSession`, and use the workflow module's helpers:

~~~rust
use splash_workflow::multiplexed_worker::{
    poll_external_tool, request_external_tool_cancellation,
};

worker_session.start_external_tool(&invocation, "invoke-1")?;
let request = request_external_tool_cancellation(
    &mut worker_session,
    &mut engine,
    invocation.id,
    "cancel-1",
)?;
let event = poll_external_tool(&mut worker_session, &mut engine)?;
~~~

The request helper verifies that the workflow ID matches the active worker
binding before it changes engine state, then records the runtime's two-phase
cancellation request before sending the frame. If delivery fails afterward,
the workflow remains cancellation-requested and the operation is
indeterminate; it is not silently made dispatchable again.

The poll helper applies ordinary completion through
`WorkflowEngine::complete_external_tool` and a positive acknowledgement
through `WorkflowEngine::confirm_external_tool_cancellation`. It never mutates
`engine.runtime_mut()` directly. `too_late` leaves the ordinary result as the
winner, `unsupported` leaves the step suspended, and a watchdog or process
termination produces an indeterminate event without advancing the workflow.

This live path supplies no durable operation identity. Use the ledgered
dispatch and fresh-session reconciliation sequence above for an effect that
must survive a crash. Do not send ordinary `cancel` for `dispatch_operation`,
compensation, or reconciliation frames.

## Reconcile After Restart

After a restart, rebuild the trusted plan and active capability policy, load
the ledger from authenticated storage, and validate it against the recreated
plan. If the storage system has a compare-and-swap version or authenticated
watermark, use the revision-aware validation method to reject an older record.

~~~rust
use splash_workflow::WorkflowOperationLedger;

let restored = WorkflowOperationLedger::from_json(&stored_ledger)?;
engine.validate_operation_ledger_at_or_after(
    &recreated_plan,
    &restored,
    authenticated_revision_watermark,
)?;
~~~

`revision` increments for every new operation and state transition. It is not
a signature or anti-rollback mechanism by itself: durable storage must
authenticate the ledger and retain its watermark atomically or through a
compare-and-swap policy. Key rotation, storage encryption, retention, and
rollback protection are platform responsibilities.

[`splash-storage`](durable-storage.md) supplies the host-only authenticated
envelope and backend contract for this persistence boundary. Its included
memory backend is development-only; choose a platform backend that meets the
documented atomic revision-floor contract before treating a workflow ledger as
durable across restarts.

Before creating a reconciliation request, the engine requires the current
input bytes and fails closed with `InputFingerprintMismatch` if they differ
from the persisted operation. The host must choose an explicit policy for that
mismatch, such as recording a new operation key, compensating, or failing the
workflow. It must not reuse an old worker result for different input.

## Authenticated Observations

Use `prepare_authenticated_operation_reconciliation` with the host side of a
`SessionAuthenticator` to create a keyed worker frame. The matching
`apply_authenticated_operation_reconciliation` method verifies the worker
frame's tag, role, and sequence before updating the ledger state.

The worker-observed states are `pending`, `running`, `succeeded`, `failed`, and
`cancelled`. Terminal states are monotonic; a duplicate observation of the
same terminal state is idempotent, but a contradictory later state is
rejected.

An authenticated `succeeded` observation is still not workflow approval and
does not restore a Splash promise or VM. The host must separately validate any
terminal payload against the current tool contract, decide whether the effect
is sufficient to advance the plan, and issue fresh workflow approval before it
runs a suffix. The ledger intentionally retains no worker output with which to
make that decision automatically.

### Fresh-session pipe transport

For a contained worker using the optional `json-line-worker` feature,
`OneShotAuthenticatedOperationWorkerTransport` can carry one verified durable
operation exchange over a freshly opened host-owned channel. It is intended for
the recovery sequence after the old worker has been discarded: restore the
ledger and worker journal, create a fresh contained worker session, then ask
that worker to reconcile the existing key. It must not be used to replay an
ambiguous dispatch.

The one-shot transport seals and opens frames itself. Build the plain request
with `operation_reconcile_request`, not
`prepare_authenticated_operation_reconciliation`, and apply the returned
verified result before persisting the new ledger revision:

~~~rust
let request = engine.operation_reconcile_request(
    &recreated_plan,
    &restored_ledger,
    &operation_key,
    &current_input,
    host_authenticator.session_id(),
    "reconcile-after-stop-1",
)?;
let result = recovery_transport.reconcile_operation(request.clone())?;
let observed = engine.apply_verified_operation_reconciliation(
    &recreated_plan,
    &mut restored_ledger,
    &request,
    &result,
)?;
persist_ledger_compare_and_swap(restored_ledger.to_json()?)?;
~~~

The transport is consumed after this one call and poisons itself on any error.
It does not provide automatic process restart, cancellation, output approval,
or workflow resumption. The host must choose how to handle `running`, an
indeterminate transport failure, or a policy/input mismatch before it creates a
fresh runtime or invokes compensation.

On Linux, the optional `splash-workflow/bubblewrap-recovery` feature provides a
reconciliation-only host composition around this transport. It requires an old
worker reaping proof, a differently keyed exact-tool Bubblewrap manifest, a
watchdog deadline, and `FencedRollbackProtectedStore`, then persists the
observation only after the fresh worker is also reaped. See
[Bubblewrap post-stop recovery](bubblewrap-recovery.md). It retains the same
rule that a terminal observation cannot resume a workflow by itself.

## Explicit Compensation

Compensation is an optional, separate effect. A host can record it only after
the original operation is durably `succeeded`; `pending`, `running`, `failed`,
and `cancelled` originals are deliberately ineligible. Each original operation
holds at most one compensation record, whose `cmp-` key, input fingerprint,
tenant scope, active-grant fingerprint, and lifecycle state are retained
without raw input, output, or error text.

The host derives a `WorkflowCompensationPolicy` from an active
`CapabilityGrant` with a nonzero `max_compensations`, records the intent with
`record_derived_compensation`, and persists the ledger with authenticated
compare-and-swap storage before issuing any approval. A
`WorkflowCompensationTarget` binds the original operation, policy, active
grant, and a trusted `CompensationGrantVerifier`; the verifier must check the
current tenant policy, revocation state, and any grant lease. It runs before
both approval and frame sealing. `WorkflowCompensationDispatch` carries the
bounded payload and request ID. `approve_compensation` creates a one-use,
session-bound approval that also binds the ledger revision.
`prepare_authenticated_operation_compensation` rejects policy, tenant, grant,
key, input, session, or revision drift before it seals a worker frame.

After a crash, create a fresh session and fresh approval only for the existing
durable compensation intent. Reuse the same `cmp-` key and exact input; do not
generate a second intent. A lost response is reconciled by the worker journal,
which returns the existing compensation state rather than rerunning the
adapter. A changed grant fingerprint, tenant scope, original state, or input
is a stop condition that requires an explicit host recovery decision.

The ledger cannot prove that an inverse effect is semantically correct or that
it reached the outside world. It never resumes a VM promise or workflow suffix
automatically. See [durable worker compensation](worker-compensation.md) for
the complete worker ordering and failure policy.

## Security Boundary

The ledger is durable data, not authority. It binds to the plan fingerprint,
but the worker protocol does not turn that binding into a storage signature.
Authenticate storage, provision worker session keys through a trusted channel,
use unique session IDs, and prevent rollback with a durable versioning policy.
For non-idempotent effects, define compensation or manual recovery before
dispatch; neither a checkpoint nor a ledger can prove that an interrupted
effect did or did not reach the outside world.
