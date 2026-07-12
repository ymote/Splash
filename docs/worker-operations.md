# Worker Durable Operations

Worker protocol v3 gives a contained adapter a durable operation identity
without exposing worker state, a journal, or a storage key to Splash source.
It complements the host-side [workflow operation ledger](workflow-operations.md):
the host decides whether an effect is allowed, while the worker makes an exact
retry replay-safe within its own tenant and policy domain.

## Dispatch Sequence

1. The host derives and persists a workflow operation key before dispatch,
   using `canonical_operation_input_bytes(&payload)` as the ledger input.
2. It creates `OperationDispatchRequest` with the key, exact tool, and bounded
   text or JSON payload, then sends `WorkerMessage::DispatchOperation` in a
   host-authenticated frame.
3. The contained worker opens the frame, authorizes the request against its
   manifest, and calls `WorkerOperationJournal::admit`.
4. The worker persists the updated journal through authenticated,
   rollback-resistant storage before it lets an adapter perform the effect.
5. A `Dispatch` admission allows one adapter invocation. `Existing` means the
   same key, tool, and canonical input already exist, so the adapter must not
   run again.
6. The worker records `running` or a terminal result, persists that mutation,
   and returns `WorkerMessage::OperationResult`. The host reconciles ambiguous
   transport outcomes with `reconcile_operation` instead of blindly sending a
   second effectful dispatch.

~~~rust
let authorized = authorizer.authorize_operation(request)?;
match journal.admit(&authorized)? {
    WorkerOperationAdmission::Dispatch => {
        persist_journal(&journal)?; // must complete before the adapter effect
        let status = adapter.run(authorized.request())?;
        journal.observe(&authorized, status.clone())?;
        persist_journal(&journal)?;
        send_operation_result(status)?;
    }
    WorkerOperationAdmission::Existing { state } => {
        recover_or_report_existing(state)?;
    }
}
~~~

`SessionAuthorizer` still charges a capability call for an operation-dispatch
request. A journal prevents a duplicated external effect; it is not a way to
avoid host call budgets. When a response is lost, use an authenticated
reconciliation request first. Retrying a new dispatch is a host recovery
decision, not a script operation.

## Exact Identity

An entry stores the tool name, operation key, and a BLAKE3 fingerprint of the
input. It does not retain raw input. Text uses its exact UTF-8 bytes. JSON uses
canonical JSON with object keys sorted recursively, so equivalent object key
ordering does not produce a different operation identity. Credentials must
remain opaque secret selectors or worker handles rather than request fields.

The operation key alone is not a multi-tenant namespace. Construct a journal
with a host-controlled opaque scope such as a worker tenant or policy-domain
identifier, and restore it with `from_json_for_scope`. Never share one journal
scope between principals that must not deduplicate each other's effects.

## State and Persistence

New entries start as `pending`; the worker can then report `running`,
`succeeded`, `failed`, or `cancelled`. A terminal state can be written again
only when it is exactly identical. A contradictory later result is rejected.
`pending` after a crash is deliberately ambiguous: the host must reconcile,
compensate, or escalate according to the adapter's recovery policy rather than
assuming the effect did or did not happen.

The journal retains a terminal success payload or failure message to answer an
idempotent duplicate. That data is bounded, but it can still be sensitive.
`WorkerOperationJournal::to_json` is only a serialization format; wrap it in a
host-selected authenticated store and add encryption where the data requires
it. The included `splash-storage` memory backend remains development-only and
is not durable worker storage. On an exact duplicate, the journal rechecks the
stored state against the active grant's output format and byte limit; a
policy-tightened worker fails closed instead of replaying an older broader
result.

## Compensation Boundary

This version supplies idempotency and recovery state only. It intentionally
does not make compensation automatic: compensation is another effect and must
be an explicit host-approved capability with its own adapter policy, audit, and
durable record. A future protocol revision will add that narrow handler
boundary rather than treating a failed operation as authorization to run an
arbitrary rollback command.
