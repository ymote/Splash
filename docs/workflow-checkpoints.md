# Workflow Checkpoints

`splash-workflow` provides a bounded JSON checkpoint for a host-attested
completed prefix of a workflow plan. It is intended for host-owned durable
storage and restart orchestration, not as a VM snapshot.

The checkpoint contains only:

- A format version.
- A BLAKE3 fingerprint of the ordered trusted step IDs and source text.
- The IDs of the completed prefix steps.

It does not contain an `Approval`, capability grant, tool result, variable,
promise, external operation ID, stream chunk, or tool catalog.

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

When `execute` or `resume` returns `WorkflowError::StepFailed` or
`WorkflowError::StepSuspended`, its `completed_steps` value identifies the
completed prefix before the unfinished step. A host may use that number with
`checkpoint_after` only after it has applied its own durable-success policy;
the failing or suspended step is intentionally excluded.

## Security Boundary

Checkpoint JSON is data, not authority. `from_json` enforces a 16 KiB input
limit, a 1,024-completed-step limit, a fixed format version, known fields, and
valid step IDs. It does not authenticate the storage record or prove that the
listed steps truly completed. The host must authenticate and authorize its
storage before it calls `approve_resume`; it must never auto-approve an
arbitrary checkpoint received from an untrusted worker or user.

An interrupted or suspended step is deliberately not marked complete. Resuming
from a checkpoint restarts the first unfinished step, so hosts must use tool
idempotency, worker reconciliation, or compensation where retrying an effect
could be unsafe. External tool handles and in-flight VM promises cannot cross
a process boundary through this format.

The fingerprint binds checkpoint data to a plan without storing source code in
the checkpoint. It is not a replacement for authenticated durable storage.
