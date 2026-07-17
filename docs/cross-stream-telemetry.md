# Cross-Stream Telemetry

`splash_workflow::telemetry::CrossStreamTelemetryAggregator` is a bounded,
in-memory host helper that combines retained capability-audit and workflow-event
batches into one local timeline. `telemetry::durable::CrossStreamTelemetryStore`
persists the same kind of source batches through a host-owned authenticated
storage record. In either form, an aggregate sequence means only **the order in
which that host accepted source batches**. It does not establish wall-clock
order, causal order, transaction order, or an adapter-effect outcome.

The in-memory aggregator is useful for a local operator view or for feeding a
host-owned sink. The durable store is useful for an authenticated aggregate
operator timeline. Neither is a source of capability or workflow authority, a
recovery log, or a compensation policy. Source journals described in
[capability audit export](capability-audits.md) and
[durable workflow events](workflow-events.md) remain the appropriate records
when a host needs independently retained source telemetry.

## Source Identity And Cursors

Each `CrossStreamTelemetrySource` has a telemetry family and a bounded
lowercase token identity (`[a-z0-9._-]`, at most 128 UTF-8 bytes). The host,
not Splash source, chooses it. Treat it as non-secret metadata.

Assign a fresh identity to every capability-runtime or workflow-engine history
segment. Both source families begin their own sequence at one, so two recreated
runtimes must never be merged under one source identity. The aggregator tracks
at most 128 source segments and accepts at most 8,192 events per input batch.

An unregistered ordinary source can first ingest only a batch beginning at
source cursor `1`. The aggregator then requires every later batch from that
source to begin exactly at the cursor returned by the prior batch. Replay and
gaps fail closed. If a source export reports retention loss, surface that gap in
host policy, choose a fresh source identity, and call `register_source_at` with
the first retained source cursor before ingesting the new segment. This records
the skipped range as an explicit segment boundary instead of silently treating
it as a continuous history.

`CrossStreamTelemetrySourceState::segment_start_sequence` and
`next_source_sequence` expose the boundary and the next required source cursor.
They are observability metadata only.

## In-Memory Host Lifecycle

Export each source with its normal cursor, ingest the exact batch once, then
advance that source cursor only after ingestion succeeds. Separately export the
aggregate timeline after its aggregate cursor and advance that cursor only after
the host sink accepts it:

```rust
use splash_workflow::telemetry::{
    CrossStreamTelemetryAggregator, CrossStreamTelemetryKind,
    CrossStreamTelemetrySource,
};

let audit_source = CrossStreamTelemetrySource::new(
    CrossStreamTelemetryKind::CapabilityAudit,
    "audit.runtime_42",
)?;
let workflow_source = CrossStreamTelemetrySource::new(
    CrossStreamTelemetryKind::Workflow,
    "workflow.run_42",
)?;
let mut telemetry = CrossStreamTelemetryAggregator::default();

let audit_batch = capability_runtime.audit_since(audit_cursor)?;
telemetry.ingest_audit_batch(&audit_source, &audit_batch)?;
audit_cursor = audit_batch.next_event_sequence();

let workflow_batch = workflow_engine.events_since(workflow_cursor)?;
telemetry.ingest_workflow_batch(&workflow_source, &workflow_batch)?;
workflow_cursor = workflow_batch.next_sequence();

let aggregate_batch = telemetry.events_since(aggregate_cursor)?;
if !aggregate_batch.is_empty() {
    append_to_host_sink(aggregate_batch.records())?;
    aggregate_cursor = aggregate_batch.next_aggregate_sequence();
}
```

The record order above is host receipt order: the audit batch appears before
the workflow batch because it was ingested first. The aggregator does not inspect
timestamps or reorder events.

For a sealed mobile or embedded workflow host,
`mobile::MobileWorkflowRuntime::audit_since` and
`mobile::MobileWorkflowRuntime::events_since` expose the same read-only batch
exports. They do not expose mutable adapter registration, plan approval,
external dispatch, or capability escalation.

The in-memory aggregator has no durable state and no transactional link to
source cursors or the host sink. A process restart needs new in-memory
aggregation state and a host-defined reconciliation strategy. A host that needs
complete retained source telemetry should persist the independent authenticated
source journals; do not use aggregate retention as recovery evidence.

## Durable Aggregate Journal

`telemetry::durable::CrossStreamTelemetryStore` persists the aggregate receipt
order and each source segment's exact next cursor in one authenticated record.
It accepts `AuditEventBatch` and `WorkflowEventBatch` directly, assigning its
own aggregate sequence when the host commits a mutation. Do not persist output
from `CrossStreamTelemetryAggregator` as though its aggregate cursor survived a
restart: that in-memory cursor starts from one for every new aggregator.

Choose one bounded non-secret `CrossStreamTelemetryStreamId` and
`StorageRecordKey` for each durable aggregate timeline. A host also owns the
rollback-protected storage backend and the retention capacity. The journal
retains at most 1,024 aggregate records, 128 source segments, and 192 KiB of
encoded telemetry. Writes use authenticated compare-and-swap with four bounded
retries.

```rust
use std::num::NonZeroUsize;

use splash_storage::StorageRecordKey;
use splash_workflow::telemetry::{
    durable::{CrossStreamTelemetryStore, CrossStreamTelemetryStreamId},
    CrossStreamTelemetryKind, CrossStreamTelemetrySource,
};

let stream_id = CrossStreamTelemetryStreamId::new("release-42-attempt-1")?;
let mut telemetry = CrossStreamTelemetryStore::new(
    authenticated_store,
    StorageRecordKey::new("cross-stream-telemetry", "release-42-attempt-1")?,
    stream_id,
    NonZeroUsize::new(1_024).unwrap(),
)?;

let audit_source = CrossStreamTelemetrySource::new(
    CrossStreamTelemetryKind::CapabilityAudit,
    "audit.runtime_42",
)?;
let audit_batch = capability_runtime.audit_since(audit_cursor)?;
if !audit_batch.is_empty() {
    let persisted = telemetry.ingest_audit_batch(&audit_source, &audit_batch)?;
    audit_cursor = persisted
        .journal()
        .source_state(&audit_source)
        .expect("accepted source state")
        .next_source_sequence();
}
```

An exact retained source replay is a no-op, so a host may retry after an
ambiguous caller-side storage result. A source gap, contradictory overlap, or a
replay that predates aggregate retention fails closed. When a source's own
export reports a known preexisting gap, persist
`register_source_at(source, first_retained_source_cursor)` before ingesting the
first batch. This explicit source-segment boundary survives restart; it does
not infer or hide omitted events. A source identity must still be fresh when a
runtime or engine begins a new source-local history at cursor one.

`PersistedCrossStreamTelemetryJournal::journal().events_since(cursor)` exports
the durable aggregate view. Advance an external sink cursor only after that
sink accepts the returned records. An aggregate cursor overtaken by retention
returns `CrossStreamTelemetryCursorError::Evicted` rather than a partial
timeline.

Use an `AuthenticatedStore<B>` whose `B` genuinely satisfies the
rollback-protected storage contract. `VolatileMemoryStore` is for tests and
local development only. Authentication does not provide confidentiality, and
the journal does not contain raw Splash source, tool input/output, credentials,
approvals, leases, worker keys, promises, or dataflow values. Encrypt retained
metadata separately when it needs confidentiality.

## Retention And Failure Semantics

The in-memory aggregate retention defaults to 1,024 records and is capped at
8,192. Once the view fills, the oldest record is evicted and `dropped_events()`
increases. The durable journal has a separately bounded 1,024-record maximum
and also records its aggregate evictions in `dropped_events()`. In both cases,
`events_since` rejects an evicted aggregate cursor rather than returning a
partial timeline. `clear_events` applies only to the in-memory aggregator and
creates an explicit aggregate observability gap while retaining the per-source
expected cursors.

An aggregate cursor, a source cursor, a source identity, or an event record
cannot prove that a local or remote effect happened. None may grant a tool,
approve or resume a workflow, acknowledge cancellation, select a retry,
reconcile an external operation, or choose compensation. This remains true
after the aggregate journal is authenticated and restored. Use fresh host
approval, workflow checkpoints, durable operation ledgers, and authenticated
worker reconciliation for those decisions.
