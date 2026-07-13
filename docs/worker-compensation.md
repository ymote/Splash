# Durable Worker Compensation

Worker protocol v4 adds a narrow, host-controlled path for one compensating
effect of a previously succeeded durable operation. It is deliberately not a
Splash language feature: generated source cannot create a compensation key,
approve one, select a tenant, change a grant, or call a worker compensation
handler directly.

Compensation is not proof that the original effect can be undone. It is a
bounded delivery and recovery protocol around an inverse action whose meaning
is defined by a trusted adapter.

## Preconditions

A compensation request is valid only when every boundary agrees on the same
original operation:

- the host workflow ledger records the original as `succeeded`;
- the ledger has one persisted compensation intent for that operation;
- the intent uses a `cmp-` key, exact canonical compensation input, tenant
  scope, and BLAKE3 fingerprint of the active grant;
- the active `CapabilityGrant` names the same tool and has a nonzero
  `max_compensations` limit; and
- the worker journal has the original operation in the same tenant scope,
  using the same tool, with durable state `succeeded`.

`max_compensations` is independent of the ordinary call budget and defaults to
zero. Attenuation may lower it, including to zero, but never raise it. The
grant fingerprint binds the full active grant, so changed resource selectors,
byte limits, call limits, or compensation budget stop recovery rather than
silently applying a different policy.

The requirement that the compensation use the original tool limits authority
to the same adapter boundary. It does not make arbitrary input an inverse.
Every effectful adapter must expose a dedicated compensation handler and
validate that handler's payload against its own explicit inverse-operation
contract.

## Host Sequence

The host must persist the intent before it can approve or send the inverse
effect. A typical flow is:

```rust
use splash_protocol::{canonical_operation_input_bytes, CapabilityGrant, ToolPayload};
use splash_workflow::{
    CompensationGrantVerifier, WorkflowCompensationDispatch,
    WorkflowCompensationPolicy, WorkflowCompensationTarget,
};

let grant = CapabilityGrant::json("release.publish").with_compensation_limit(1);
let policy = WorkflowCompensationPolicy::new("tenant-release", &grant)?;
let payload = ToolPayload::Json(serde_json::json!({"undo": "release"}));
let input = canonical_operation_input_bytes(&payload)?;

let compensation_key = engine.record_derived_compensation(
    &plan,
    &mut ledger,
    &operation_key,
    &policy,
    &input,
    b"release-42:publish:undo:1",
)?;
persist_ledger_compare_and_swap(&ledger)?;

// `current_grant_verifier` implements CompensationGrantVerifier and checks
// the tenant's current policy, revocations, and any grant lease.
let target = WorkflowCompensationTarget::new(
    &operation_key,
    &policy,
    &grant,
    &current_grant_verifier,
);
let approval = engine.approve_compensation(
    &plan,
    &ledger,
    target,
    &input,
    &host_authenticator,
)?;
let outbound = engine.prepare_authenticated_operation_compensation(
    &plan,
    &ledger,
    target,
    WorkflowCompensationDispatch::new("compensate-1", payload),
    approval,
    &mut host_authenticator,
)?;
```

`record_derived_compensation` derives the stable key from the plan, original
operation key, tool, tenant scope, grant fingerprint, full compensation input,
and a host-supplied durable nonce. It records only a fingerprint of the input,
not raw input, output, or error text. A ledger permits exactly one compensation
record per original operation.

The `Approval` is process-local and one-use. It binds the workflow engine,
plan, ledger revision, original operation key, compensation key, input
fingerprint, tenant scope, grant fingerprint, and session ID. Do not store it.
After a restart, recreate the plan and active policy, load and validate the
ledger through authenticated rollback-protected storage, then issue a fresh
approval for the existing intent.

`CompensationGrantVerifier` runs both when the host issues approval and again
immediately before it seals the frame. It is the host's explicit revocation
and current-tenant-policy boundary: the implementation must resolve current
state rather than accept a cached grant simply because its historical
fingerprint matches. The contained worker independently reauthorizes the
request against its current session manifest before it admits the effect.

The host sends `outbound.frame` only after the ledger write is durable. It
opens the worker's authenticated `CompensationResult`, calls
`apply_authenticated_operation_compensation`, and persists the resulting
ledger revision before any follow-on workflow decision. The result changes
only the compensation state; it does not resume a VM promise, execute another
workflow step, or decide that a failure is safe to retry.

## Worker Sequence

The contained worker must keep its journal in authenticated,
rollback-resistant storage scoped to the same tenant or policy domain. Its
execution order is non-negotiable:

1. Open the host-authenticated `CompensateOperation` frame.
2. Validate it with `SessionAuthorizer::authorize_compensation` against the
   active manifest and separate compensation budget.
3. Call `WorkerOperationJournal::admit_compensation`.
4. Persist a `Dispatch` admission before the adapter performs any inverse
   effect.
5. Persist `running`, `succeeded`, `failed`, or `cancelled` after the adapter
   reports it, then send `CompensationResult`.

`splash-worker::WorkerSession` restores its in-memory journal to the last
successful persistence point and poisons its session when the adapter may have
acted but the observed state cannot be made durable. It returns an
indeterminate-compensation error; reopen from an atomic journal-and-revision
snapshot with a fresh current fencing lease before the adapter-specific or
manual recovery policy described below. That error is never permission to
create another compensation key or rerun the inverse effect.

For an exact duplicate, `admit_compensation` returns `Existing` with the
stored state. The worker must report or reconcile that state; it must not run
the adapter a second time. The journal rejects a second compensation key,
changed canonical input, stale grant fingerprint, wrong scope, changed tool,
or a contradictory terminal state.

## Crash and Recovery Policy

Treat every uncertain state conservatively:

| Condition | Required host/worker action |
| --- | --- |
| Original `pending`, `running`, `failed`, or `cancelled` | Do not create compensation. Reconcile the original with adapter-specific status lookup or escalate to an operator. |
| Original `succeeded`, no compensation intent | The trusted host may record one intent after its own policy or operator approval. Persist it before sending any worker frame. |
| Compensation `pending` or `running` after a crash | Recreate a session, revalidate the same grant and tenant, issue a fresh approval, and send the same `cmp-` key and input. The worker returns `Existing`; use adapter-specific status recovery or manual escalation. Do not execute a new inverse blindly. |
| Compensation `succeeded` | Persist and report completion. Do not create another compensation for that original operation. |
| Compensation `failed` or `cancelled` | Persist the state and require an explicit adapter or operator recovery policy. There is no automatic retry or new compensation key. |
| Grant, tenant, tool, key, or input drift | Fail closed. A policy change cannot reuse the stored intent automatically. |
| Lost worker response | Reuse the existing durable intent under a fresh host approval; never infer that the inverse did or did not happen from transport loss alone. |

Version 4 does not define a universal inverse-status API because external
systems differ. A worker adapter must implement bounded status lookup or
manual escalation for ambiguous `pending` and `running` compensation records.
It must not convert an `Existing` record into a second execution merely to make
progress.

## Security Boundaries

The compensation protocol protects identity, authority, sequencing, and
durable deduplication. It does not provide any of the following:

- semantic proof that an action is reversible;
- a universal rollback command or automatic compensation policy;
- process containment, secure key bootstrap, encrypted transport, or worker
  attestation;
- storage encryption; the worker journal may retain terminal payloads and must
  be encrypted when those payloads are sensitive; or
- atomic persistence across a host ledger and a worker journal. Each side must
  persist its own mutation before the corresponding external effect or
  follow-on decision.

See [worker protocol](worker-protocol.md), [worker durable
operations](worker-operations.md), [durable operation
ledgers](workflow-operations.md), and [authenticated durable
storage](durable-storage.md) for the surrounding boundaries.
