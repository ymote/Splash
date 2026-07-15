# Workflow Checkpoints

`splash-workflow` provides a bounded JSON checkpoint for a host-attested
completed prefix of a workflow plan. It is intended for host-owned durable
storage and restart orchestration, not as a VM snapshot.

For an LLM's proposed pre-approval step list, use the separate data-only
[workflow draft](workflow-drafts.md) format. A draft has no fingerprint or
restart authority; only a trusted plan can create a checkpoint.

The checkpoint contains only:

- A format version.
- A BLAKE3 fingerprint of the ordered trusted step IDs and source text.
- The IDs of the completed prefix steps.
- For a dataflow checkpoint only, a BLAKE3 digest of separately retained
  bounded workflow data.
- For a contract-bound dataflow checkpoint only, a BLAKE3 digest of the
  separately retained host schema policy.

It does not contain an `Approval`, capability grant, tool result, variable,
raw dataflow input/output, promise, external operation ID, stream chunk, or
tool catalog.

## Create And Resume

The host creates a checkpoint only after it has independently attested that a
prefix completed. On restart, it recreates the trusted plan and tool policy,
then asks for a new checkpoint-bound approval before it runs the suffix.

~~~rust
use splash_workflow::{WorkflowCheckpoint, WorkflowEngine, WorkflowStep};

let plan = engine.plan(vec![
    WorkflowStep::new("prepare", "let release = 1"),
    WorkflowStep::new("publish", "use mod.tool\ntool.call(\"text.echo\", \"release\")"),
])?;

// The host has recorded that `prepare` completed successfully.
let checkpoint = engine.checkpoint_after(&plan, 1)?;
let stored_json = checkpoint.to_json()?;

// After a restart, build a new CapabilityRuntime, register its allowed tools,
// and recreate the exact trusted plan before loading the checkpoint.
let restored = WorkflowCheckpoint::from_json(&stored_json)?;
let recreated_plan = restarted_engine.plan(trusted_steps)?;
let approval = restarted_engine.approve_resume(&recreated_plan, &restored)?;
restarted_engine.resume(&recreated_plan, &restored, approval)?;
~~~

`approve_resume` rejects a checkpoint when the reconstructed plan fingerprint
or completed-step prefix differs. The resulting `Approval` retains an internal
copy of the exact checkpoint, so replacing the checkpoint after approval is
rejected. A regular `approve` result cannot be used with `resume`.

Every workflow approval also owns a process-local `CapabilityLease` issued by
the current `CapabilityRuntime`. `approve` and `approve_resume` use the full
current catalog for convenience. A host that has reviewed a narrower set can
issue `CapabilityLeaseGrant` values and call
`approve_with_capability_lease` or `approve_resume_with_capability_lease`.
The lease binds the runtime identity, complete catalog fingerprint, approved
tool names, and per-tool call limits. It remains active through every deferred
`await` and continuation in the approved run, so a computed tool name is still
checked at reservation time. A catalog change between approval and execution
fails closed with `WorkflowError::CapabilityLease(CatalogChanged)`; a lease is
not serializable and must never be persisted with a checkpoint.

For an LLM-generated multi-step plan, use
`approve_with_step_capability_leases` with exactly one lease for every plan
step in trusted plan order. The engine activates only the current step's
lease; a later lease is unavailable while an earlier step evaluates or waits
for an external result. Empty leases are valid for pure steps. On restart,
`approve_resume_with_step_capability_leases` instead takes exactly one fresh
lease for each unexecuted suffix step, beginning at
`checkpoint.completed_step_count()`. Count mismatches fail before an approval
or approval event is created. The host still chooses each step's grants; the
queue enforces that reviewed ordering rather than inferring authority from
source text or tool-call hints.

For trusted host policy that needs only named grant lists,
`WorkflowStepCapabilityPolicy` and
`approve_with_step_capability_policies` issue that ordered lease queue inside
the engine. Every policy must name the corresponding trusted plan step; both
the count and ordered IDs are checked before any lease is issued. The resume
counterpart accepts policies only for the unexecuted suffix. A policy is
non-serializable host configuration, not a lease or credential, and must not
be assembled from Splash source or review hints. Use the explicit lease APIs
when a step needs a custom `ToolCallAuthorizer`.

For a static mobile or embedded adapter catalog,
`splash_workflow::mobile::MobileWorkflowBuilder` exposes this named-policy
approval path without exposing `WorkflowEngine::runtime_mut`, manual leases,
full-catalog approval, or external-operation APIs. Its local adapters are
still trusted app code, not contained workers; see [worker runtime](worker-runtime.md).

Before the host presents that approval, it can call `plan.review()` (or
`review_with_limits`) to obtain a `WorkflowStepReview` for every step. The
review returns canonical syntax status and direct tool-call hints without
evaluating source, constructing a capability host, or issuing authority. An
invalid step has no hints, so an empty list alone never establishes that a
step is pure. Hint output is capped at 1,024 per step and 4,096 per review;
`tool_calls_truncated` marks any omitted direct sites. Plans retain at most
1,024 steps and 1 MiB of aggregate source, which bounds review and per-step
lease state; use independently approved plans for a larger orchestration graph.

## Dataflow Checkpoints

`WorkflowData` is a separate, bounded host-owned value. Its persisted envelope
is versioned and contains `format_version`, `input`, and `outputs`; a
contract-bound context also carries only the contract digest. Scripts still
see only `{ input, outputs }`. It carries no authority, but prior outputs can
affect the arguments to a later authorized call. A dataflow checkpoint
therefore binds a digest of the exact context to the completed prefix without
serializing raw input, tool results, or schema source into checkpoint JSON.

```rust
use splash_workflow::WorkflowData;

let data = engine.take_dataflow_snapshot().expect("terminal dataflow state");
let checkpoint = engine.dataflow_checkpoint_after(&plan, &data, 1)?;
let stored_checkpoint = checkpoint.to_json()?;

// On restart, restore the context through the host's own protected data path.
let restored_data = WorkflowData::from_json(&stored_data_json)?;
let restored_checkpoint = WorkflowCheckpoint::from_json(&stored_checkpoint)?;
let approval = restarted_engine.approve_dataflow_resume_with_step_capability_policies(
    &recreated_plan,
    &restored_checkpoint,
    restored_data,
    suffix_policies,
)?;
let completed = restarted_engine.resume_dataflow(&recreated_plan, &restored_checkpoint, approval)?;
```

`dataflow_checkpoint_after` requires outputs for exactly the completed plan
prefix. `approve_dataflow_resume...` checks the plan, prefix, data bounds, and
context digest before issuing a fresh suffix lease. Ordinary `approve_resume`
and `resume` reject a dataflow checkpoint, and dataflow resume rejects an
ordinary checkpoint, so a host cannot accidentally run a suffix without the
matching output context. The data cap is 64 KiB and 64 nesting levels across
the complete context.

When a host uses `WorkflowDataContract`, completed execution retains only its
contract digest with `WorkflowData`, and `dataflow_checkpoint_after` carries
that digest automatically. For a manually reconstructed context that lacks
the digest, call `dataflow_checkpoint_after_with_contract` with mutable data.
The host then rebuilds the exact reviewed contract from its own application
policy after restart and calls
`approve_dataflow_resume_with_contract_and_step_capability_policies`. That
approval checks the plan, context digest, contract digest, restored input, and
every completed-prefix output before it issues any suffix lease. An ordinary
dataflow-resume API rejects a checkpoint carrying a contract digest, so a
restart cannot silently drop the earlier output policy. A changed contract
fails closed with `DataflowContractMismatch`; create a new reviewed workflow
and checkpoint when policy migration is intended.

The contract itself remains non-serialized host configuration. Checkpoint JSON
stores only its BLAKE3 digest, never schema source: accepting a schema selected
by a stored record, draft, or generated script would turn data transport into
policy selection.

The digest is a binding check, not storage authentication or secrecy. Persist
raw `WorkflowData` only in a host-controlled store with the retention,
confidentiality, and rollback policy appropriate to the application.

## Live External Suspension

When an approved step awaits an external tool, `execute` or `resume` returns
`WorkflowError::StepSuspended` and retains the plan, current step, and current
lease in the same `WorkflowEngine`. This is a live-process suspension, not a
durable checkpoint. The host calls `claim_next_external_tool`, dispatches the
returned invocation, then calls `complete_external_tool` or uses the engine's
`request_external_tool_cancellation` and
`confirm_external_tool_cancellation` pair. The engine resumes that exact step
under the retained lease only after a terminal result or acknowledged
cancellation, and only then advances to a later per-step lease. If the
continuation awaits another external tool, it returns `StepSuspended` again
with the same retained execution.

`execute_dataflow` and `resume_dataflow` retain the approval-bound
`WorkflowData` and any bound `WorkflowDataContract` in that same live state.
The host can inspect the data with `dataflow_snapshot`, but neither the raw
context nor contract schema source is encoded into a live external operation,
checkpoint, audit entry, or workflow event. A contract-aware checkpoint adds
only its digest.

Hosts using lower-level runtime reconciliation or timeout APIs must pass the
resulting `Evaluation` to `continue_suspended_execution`. Do not start another
workflow on that engine while `has_suspended_execution()` is true. Local
host-pumped operations that a completed step did not await are drained before
the engine starts its next step, so their effects cannot be postponed into an
unrelated workflow. External workflow tools must be awaited; the engine
cancels an unclaimed external promise at its completed-step boundary rather
than letting it become a later workflow's raw lifecycle obligation.

When `execute` or `resume` returns `WorkflowError::StepRejected`,
`WorkflowError::StepFailed`, or `WorkflowError::StepSuspended`, its
`completed_steps` value identifies the completed prefix before the unfinished
step. `WorkflowError::StepRejected` carries the bounded, structured
canonical-Splash syntax report and records no tool call; its corresponding
in-memory event retains only diagnostic count and truncation metadata. A host
may use the count with
`checkpoint_after` only after it has applied its own durable-success policy;
the rejected, failing, or suspended step is intentionally excluded.

## In-Memory Events

`WorkflowEngine::events` exposes an ordered, bounded in-memory event view for
the current process. The default capacity is 1,024 entries; hosts with tighter
embedded budgets can construct an engine with
`with_event_history_capacity(NonZeroUsize)`, up to 8,192 entries. The view
reports how many oldest entries have been evicted, and exposes `as_slices` for
zero-copy wrapped-buffer inspection.

`events_since(cursor)` additionally exports contiguous sequenced telemetry for
a host-owned authenticated event journal. It reports an evicted cursor rather
than silently exporting a partial history. The optional durable journal is a
bounded operator/audit timeline, not serializable recovery state: its entries
may contain diagnostic counts but never diagnostic text, and neither reading
nor exporting it authorizes a plan, resumes a promise, or proves a tool effect
completed. See [durable workflow events](workflow-events.md). Persist
checkpoints and operation ledgers for recovery authority, not event telemetry.

## Security Boundary

Checkpoint JSON is data, not authority. `from_json` enforces a 16 KiB input
limit, a 1,024-completed-step limit, a fixed format version, known fields, and
valid step IDs. It does not authenticate the storage record or prove that the
listed steps truly completed. The host must authenticate and authorize its
storage before it calls `approve_resume`; it must never auto-approve an
arbitrary checkpoint received from an untrusted worker or user.

The lease controls only which registered script-visible tools may run. It does
not contain the process, filesystem, network, or Rust crate authority of the
adapter behind a permitted tool. Untrusted local effects still require a
platform-contained worker and a narrowly reviewed adapter boundary.

An interrupted or suspended step is deliberately not marked complete. Resuming
from a checkpoint restarts the first unfinished step, so hosts must use tool
idempotency, worker reconciliation, or compensation where retrying an effect
could be unsafe. External tool handles and in-flight VM promises cannot cross
a process boundary through this format.

For a bounded durable record of an uncertain external effect, use a separate
[durable operation ledger](workflow-operations.md). It records plan-bound
operation metadata and worker observations, but it also does not restore a
promise or authorize a restart.

The fingerprint binds checkpoint data to a plan without storing source code in
the checkpoint. It is not a replacement for authenticated durable storage.
