# Bubblewrap Post-Stop Recovery

The optional `splash-workflow/bubblewrap-recovery` feature automates one narrow
recovery path for an ambiguous durable operation after a Linux Bubblewrap
worker stops. It composes the existing containment, authenticated worker
protocol, durable operation ledger, watchdog, and fenced storage boundaries.

It does not automate retry, compensation, or workflow resume.

## Enforced Sequence

`recover_bubblewrap_operation` performs these steps in order:

1. Require a `BubblewrapWorkerReaped` proof produced by consuming the old
   worker lifecycle or closing its watchdog.
2. Reject reuse of the stopped worker's authenticated session ID.
3. Load the host ledger through `AuthenticatedStore<B>` where
   `B: FencedRollbackProtectedStore`.
4. Validate the ledger against the recreated trusted plan, require the exact
   current input bytes, and reject an already terminal operation.
5. Require the fresh containment manifest to contain exactly one grant for the
   operation's tool, then reserve a fresh durable writer fence.
6. Start a fresh Bubblewrap worker with a new operating-system-generated
   session key and the exact manifest retained by `BubblewrapCommand`.
7. Arm a spawn-anchored session deadline and send only one authenticated
   `reconcile_operation` exchange.
8. Force-stop and reap the fresh worker before accepting its result.
9. Apply the bound observation and write the ledger through fenced
   compare-and-swap, even when the worker repeated the current state.

The final compare-and-swap is also the concurrency check. If another recovery
writer reserved a newer fence or changed the record, the observation is not
reported as persisted. Retry with the same reaping proof, a new session ID, a
new `FreshBubblewrapRecoverySession`, and a fresh contained worker.

## Host Integration

Enable the integration on the trusted Linux host:

```toml
splash-workflow = { version = "0.1.0", features = ["bubblewrap-recovery"] }
```

First convert the stopped lifecycle into a proof. Reaping proves only that the
old process session cannot continue; it does not prove that its adapter effect
was cancelled.

```rust
let stopped_worker = watchdog.close_reaped()?;
// Or, before pipes move to a watchdog:
// let stopped_worker = spawned_worker.into_reaped()?;
```

Recreate a least-privilege manifest with a different session ID and exactly one
grant for the operation being reconciled. Compile the containment policy from
that manifest. The command retains the complete manifest, preventing session
startup from being paired with a containment plan compiled for different
authority under the same ID.

```rust
use std::time::Duration;

use splash_protocol::{CapabilityGrant, CapabilityManifest};
use splash_sandbox::bubblewrap::BubblewrapWorkerSessionDeadline;
use splash_workflow::bubblewrap_recovery::{
    recover_bubblewrap_operation, BubblewrapPostStopRecoveryRequest,
    FreshBubblewrapRecoverySession,
};

let recovery_manifest = CapabilityManifest::new(
    "release-42-recovery-1",
    vec![CapabilityGrant::json("release.publish")],
)?;
let command = trusted_bubblewrap_policy.compile(&recovery_manifest)?;
let fresh_session = FreshBubblewrapRecoverySession::generate(command)?;
let deadline = BubblewrapWorkerSessionDeadline::new(Duration::from_secs(30))?;
let request = BubblewrapPostStopRecoveryRequest::new(
    &stopped_worker,
    fresh_session,
    &ledger_record_key,
    &operation_key,
    &current_canonical_input,
    "reconcile-1",
    deadline,
);
let recovered = recover_bubblewrap_operation(
    &mut recreated_engine,
    &recreated_plan,
    &mut authenticated_store,
    request,
)?;
```

For a deployment using cgroup-v2 limits, preserve that boundary explicitly:

```rust
let fresh_session = FreshBubblewrapRecoverySession::generate_in_cgroup(
    command,
    cgroup_policy,
)?;
```

The fresh worker executable must read its private-pipe bootstrap, load the same
tenant-scoped durable worker journal through a current fenced lease, and open
the authenticated session before processing JSON-line frames. The coordinator
owns the host ledger and process exchange; it cannot supply or infer the
worker's journal backend.

`recovered.ledger()` is the exact ledger committed by authenticated
compare-and-swap. `recovered.sensitive_result()` explicitly exposes the
authenticated worker result to trusted host code, but its output payload is
redacted from `Debug` and is never stored in the ledger. Do not log or persist
this result by default. A successful payload still needs current output contract
and product policy checks before use.

## Failure Semantics

- Entropy failure has no deterministic or process-local fallback.
- A missing, rolled-back, malformed, wrong-plan, wrong-input, or terminal
  ledger fails before a writer fence is reserved or a worker is launched.
- A broad or wrong-tool recovery manifest also fails before fence reservation
  or launch.
- Spawn, bootstrap, framing, authentication, deadline, and watchdog failures
  produce no persisted observation.
- If the deadline or lifecycle stop races a worker response, the response is
  discarded as interrupted.
- If the fresh worker cannot be reaped, an otherwise authenticated response is
  discarded.
- A storage fence or revision conflict discards the observation; the caller
  must query again in another fresh session.

The old `BubblewrapWorkerReaped` proof is cloneable and reusable because
reaping is a permanent fact and a failed fresh launch must be recoverable. It
cannot be constructed without consuming a Splash-owned worker lifecycle.

## Explicit Non-Guarantees

This coordinator does not:

- report process termination as cancellation;
- send `dispatch_operation`, retry an effect, or choose an idempotency policy;
- issue or execute compensation;
- restore a VM continuation, resolve an external promise, or resume a workflow;
- turn a worker `succeeded` status into product-level proof or approval;
- implement the worker journal, rollback anchor, storage-key provisioning, or
  platform containment outside Linux; or
- add an aggregate quota for persistent host-backed storage, in-band
  cancellation, network-origin mediation, executable policy, or a secret
  broker. Bounded ephemeral roots are launch policy retained by the compiled
  command, not durable recovery storage.

Use a production `RollbackAnchor` and fenced backend for both host and worker
records. `VolatileMemoryStore` and `VolatileRollbackAnchor` remain tests and
local-development aids only.
