# Capability Audit Export

`CapabilityHost` and `CapabilityRuntime` retain a bounded in-memory audit
view. `audit_since(cursor)` exports a contiguous owned
`AuditEventBatch` without making telemetry part of capability or workflow
authority.

Every `AuditEvent` has two different identifiers:

- `event_sequence` is the source-local ordering identity of one audit record.
  It starts at one for each runtime and is suitable for a host export cursor.
- `sequence` correlates the underlying capability invocation. Retry,
  cancellation, and streaming records for one invocation can have the same
  value, so it is not an audit-record ordering cursor.

The batch is serializable for a host-owned sink, but it is intentionally not a
deserializable authority object. It carries only telemetry and cannot grant a
tool, recreate a pending operation, prove an adapter effect, or acknowledge a
cancellation.

## Host Lifecycle

Assign a fresh host-owned stream identity to each capability runtime. A new
runtime starts `event_sequence` at one, so do not merge two runtimes under one
stream identity. Start with cursor `1` and advance it only after the host sink
has accepted the batch:

```rust
let batch = runtime.audit_since(cursor)?;
if !batch.is_empty() {
    append_to_host_sink(stream_id, batch.events())?;
    cursor = batch.next_event_sequence();
}
```

An exact retry by the host can safely export the same batch again when its own
sink supports idempotency. The opt-in
`splash-capabilities/durable-audit-journal` feature supplies
`durable_audits::CapabilityAuditStore` for one authenticated, host-owned
stream. The host still selects the rollback-protected storage backend, record
key, stream identity, and retention capacity. A host enabling this feature
also declares a direct `splash-storage` dependency; the storage backend and
keys are intentionally not re-exported through the scripting crate.

```rust
use std::num::NonZeroUsize;

use splash_capabilities::durable_audits::{
    CapabilityAuditStore, CapabilityAuditStreamId,
};
use splash_storage::StorageRecordKey;

let stream_id = CapabilityAuditStreamId::new("release-42-attempt-1")?;
let mut audits = CapabilityAuditStore::new(
    authenticated_store,
    StorageRecordKey::new("capability-audits", "release-42-attempt-1")?,
    stream_id,
    NonZeroUsize::new(1_024).unwrap(),
)?;
let mut cursor = audits
    .load()?
    .map_or(1, |persisted| persisted.journal().next_event_sequence());

let batch = runtime.audit_since(cursor)?;
if !batch.is_empty() {
    let persisted = audits.append_batch(&batch)?;
    cursor = persisted.journal().next_event_sequence();
}
```

`CapabilityAuditStore` accepts only a nonempty contiguous `AuditEventBatch`.
It compares a retained exact overlap before writing, so an exact retry is
idempotent; a source gap, a replay older than its retention window, or a
contradictory overlap fails closed. Writes use the configured authenticated
store's compare-and-swap boundary with four bounded retries. Retention is
bounded to the smaller host-selected event capacity (at most 1,024) and a
192 KiB serialized document. Store the returned `next_event_sequence` only
after `append_batch` succeeds.

Use an `AuthenticatedStore<B>` whose `B` genuinely implements the
rollback-protected storage contract. `VolatileMemoryStore` is only suitable
for tests and local development. Authentication proves neither that a record
is secret nor that an external effect completed; encrypt telemetry separately
when its metadata needs confidentiality.

`AuditEventCursorError::Evicted` means the requested history is no longer
retained, including after `clear_audit`. Treat that as an observability gap:
record or surface it in host policy, and begin a clearly separate host segment
if retention needs to continue. Do not silently advance to the reported
`earliest_available` value. `AuditEventCursorError::Ahead` means the host
cursor does not describe the current runtime history; it is not permission to
invent records. Cursor zero is invalid.

When a fresh durable segment begins at an explicit post-eviction source cursor,
give it a fresh stream identity and record key, then construct the store with
`CapabilityAuditStore::new_from_event_sequence` and that nonzero cursor. The
journal persists this `segment_start_event_sequence` separately from
`dropped_audit_events`, so missing source history is visible as a segment gap
rather than being misreported as journal retention eviction. Do not use this
constructor to skip records in an existing stream.

The bounded `audit()` view and `dropped_audit_events()` remain useful for
local inspection. They cannot repair an export gap, and neither counter nor
sequence numbers are durable storage or authorization state.

## Data and Boundaries

Audit records retain a registered tool identifier, or a fixed-length BLAKE3
digest label for an invalid dynamic name, along with input and output byte
counts, a finite outcome, and an optional retry class. The label is scoped to a
live runtime session when operating-system entropy or a host-supplied capability
session nonce is available. In a no-entropy local-only runtime it uses only a
process-local session counter, so it can repeat after restart and must not be
treated as confidential or cross-restart unlinkable. Audit records do not retain
Splash source, tool input/output, external stream chunks, credentials, approval
objects, leases, worker keys, or VM promise state.

An `allowed` audit outcome is not proof that a remote effect completed or can
be replayed. Hosts still need idempotency, authenticated worker reconciliation,
durable operation ledgers, and fresh approval where those properties matter.
Audit export must never decide a capability grant, workflow resume, rollback,
or compensation action.

## Sealed Profiles

`mobile::MobileRuntime::audit_since` and
`splash_workflow::mobile::MobileWorkflowRuntime::audit_since` forward the
same read-only export after setup. They do not expose mutable catalog
registration, external operation control, or an adapter escape hatch. The
embedding application may persist the exported batch through the optional
journal outside the sealed runtime API, and remains responsible for storage,
I/O, and platform containment policy.
