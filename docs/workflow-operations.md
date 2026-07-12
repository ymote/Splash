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
  input fingerprint, and worker-observed state.

It never stores raw input, output, error text, raw secret values, source, an approval,
capability grant, VM state, promise, stream chunk, or `ExternalToolId`.

## Record Before Dispatch

Create and persist an operation record before sending an effectful request to
a worker. Prefer `record_derived_operation`: it derives a non-authorizing
operation key from the plan fingerprint, step ID, tool, complete input bytes,
and a host-supplied durable nonce.

~~~rust
use splash_capabilities::CapabilityRuntime;
use splash_workflow::{WorkflowEngine, WorkflowStep};

let mut engine = WorkflowEngine::new(CapabilityRuntime::default());
let plan = engine.plan(vec![WorkflowStep::new(
    "publish",
    "let release = true",
)])?;
let mut ledger = engine.operation_ledger(&plan)?;

let input = br#"{"version":"1.2.3"}"#;
let operation_key = engine.record_derived_operation(
    &plan,
    &mut ledger,
    "publish",
    "release.publish",
    input,
    b"run-42:publish:1",
)?;
let stored_ledger = ledger.to_json()?;
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

The derived key is not a credential. Its purpose is to bind the host's plan,
input, and operation identity into the durable worker-deduplication key. Hosts
with an existing durable worker key may use `record_operation`, but then they
must ensure the key is unique across workflow plans and input revisions.

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

## Security Boundary

The ledger is durable data, not authority. It binds to the plan fingerprint,
but the worker protocol does not turn that binding into a storage signature.
Authenticate storage, provision worker session keys through a trusted channel,
use unique session IDs, and prevent rollback with a durable versioning policy.
For non-idempotent effects, define compensation or manual recovery before
dispatch; neither a checkpoint nor a ledger can prove that an interrupted
effect did or did not reach the outside world.
