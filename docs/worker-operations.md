# Worker Durable Operations

Worker protocol v4 gives a contained adapter a durable operation identity
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

The fingerprint is the full 256-bit BLAKE3 digest with a protocol domain tag.
Canonical JSON preserves parsed string and number values, emits no whitespace,
and sorts object keys by Rust string ordering. It does not apply Unicode
normalization or coerce `1` and `1.0`; such a difference deliberately fails
closed as changed input rather than silently treating distinct data as one
effect.

The operation key alone is not a multi-tenant namespace. Construct a journal
with a host-controlled opaque scope such as a worker tenant or policy-domain
identifier, and restore it with `from_json_for_scope`. Never share one journal
scope between principals that must not deduplicate each other's effects.
`splash-worker::WorkerSessionAdmission` must validate the authenticated session
ID and that host-selected scope together, then issue a current fencing lease;
the journal store rejects writes from a superseded lease. The scope is never
accepted from Splash source or a worker request.

All admission implementations sharing a scope must obtain leases from one
monotonic authority, such as a transactional durable store, trusted lease
service, or platform monotonic counter. A per-process counter is insufficient
when more than one worker host can admit the same scope.

## State and Persistence

New entries start as `pending`; the worker can then report `running`,
`succeeded`, `failed`, or `cancelled`. A terminal state can be written again
only when it is exactly identical. A contradictory later result is rejected.
`pending` after a crash is deliberately ambiguous: the host must reconcile,
compensate, or escalate according to the adapter's recovery policy rather than
assuming the effect did or did not happen.

An exact duplicate in `pending` returns an explicit pending error and does not
run the adapter or manufacture a terminal result. A duplicate in `running` or
a terminal state is only returned after its stored state passes the active
grant's format and output bounds.

`splash-worker::WorkerSession` restores its in-memory journal to the last
successfully persisted version when it cannot persist an adapter observation.
It poisons that session and returns an indeterminate-operation error instead
of a terminal worker result. The host must discard it, reopen from an atomic
journal-and-revision snapshot, then use the same operation key with bounded
reconciliation. The runtime persists a valid reconciliation observation before
returning it. This prevents a successful in-memory adapter result from
bypassing durable recovery semantics.

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

Compensation is a separate worker operation, never an automatic follow-up to a
failure. A worker admits it only after the original journal entry is
`succeeded`, with the same tool, exact tenant scope, exact grant fingerprint,
and a single `cmp-` key. `max_compensations` is a separate capability budget;
it defaults to zero and cannot be increased through attenuation.

Persist the compensation admission before invoking a dedicated adapter
compensation handler, then persist each state observation before responding:

~~~rust
let authorized = authorizer.authorize_compensation(request)?;
match journal.admit_compensation(&authorized)? {
    WorkerCompensationAdmission::Dispatch => {
        persist_journal(&journal)?; // must complete before the inverse effect
        let status = adapter.compensate(authorized.request())?;
        journal.observe_compensation(&authorized, status.clone())?;
        persist_journal(&journal)?;
        send_compensation_result(status)?;
    }
    WorkerCompensationAdmission::Existing { state } => {
        recover_or_report_existing_compensation(state)?;
    }
}
~~~

An exact replay after a transport loss returns `Existing`; it does not rerun
the adapter. A new compensation key, changed input, stale grant fingerprint,
wrong tenant, or contradictory terminal result fails closed. The adapter must
define what its compensation payload means and how it validates that payload;
the protocol cannot infer a semantic inverse from a normal tool request. See
[durable worker compensation](worker-compensation.md) for the host approval
and restart policy.
