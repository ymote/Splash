# Durable Workflow Events

`WorkflowEngine` retains a bounded in-memory `WorkflowEvent` view for the
current process. `durable_events::WorkflowEventStore` lets a host export that
telemetry into one authenticated, rollback-protected storage record without
turning the event stream into workflow authority.

The journal contains only bounded lifecycle metadata: plan IDs, validated step
and tool identifiers, operation or compensation keys, state enums, completed
step counts, and diagnostic counts. It never contains Splash source, tool
input/output, schema data, approvals, grants, worker session keys, VM promises,
or secrets.

## Host Lifecycle

Choose a fresh bounded `WorkflowEventStreamId` for each engine event-history
segment. A process restart normally needs a new stream ID because a new engine
starts its local event sequence at one. Store it in a separate host-owned
`StorageRecordKey`; do not mix unrelated runs in one journal.

Start with cursor `1`, export nonempty batches through
`WorkflowEngine::events_since`, then persist each batch through
`WorkflowEventStore::append_batch`. Retain the journal's `next_sequence` as
the next cursor. A duplicate retained batch is idempotent. A missing source
sequence, contradictory overlap, changed stream ID, or export cursor overtaken
by in-memory eviction fails closed rather than silently creating a partial or
duplicated record.

The recorder validates input, bounds retention to at most 1,024 events and
192 KiB, and uses bounded optimistic authenticated compare-and-swap retries.
Retention eviction increments `dropped_events`. A final contention, source
gap, or retention gap is an observability failure that a host must surface or
export separately; it is never permission to infer workflow state.

Use a production `RollbackProtectedStore` with a genuine rollback-resistant
anchor. `VolatileMemoryStore` is only for tests and local development. A
database or platform credential store by itself does not provide the required
anti-rollback guarantee.

## Replay Boundary

Reading a durable event journal is useful for operator timelines and audit
export. It cannot recreate a plan approval, capability lease, dataflow
context, suspended promise, worker session, or an external effect. It cannot
prove that a tool completed, was cancelled, or was rolled back.

Use a [workflow checkpoint](workflow-checkpoints.md) for an attested completed
prefix, a [durable operation ledger](workflow-operations.md) plus authenticated
worker reconciliation for uncertain effects, and a fresh host approval before
any resumed step executes. Event retention is intentionally separate from all
of those authority decisions.
