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
sink supports idempotency. Splash does not supply a generic durable audit
store because authenticating storage, selecting retention, and binding an
operator-visible stream identity are host policy.

`AuditEventCursorError::Evicted` means the requested history is no longer
retained, including after `clear_audit`. Treat that as an observability gap:
record or surface it in host policy, and begin a clearly separate host segment
if retention needs to continue. Do not silently advance to the reported
`earliest_available` value. `AuditEventCursorError::Ahead` means the host
cursor does not describe the current runtime history; it is not permission to
invent records. Cursor zero is invalid.

The bounded `audit()` view and `dropped_audit_events()` remain useful for
local inspection. They cannot repair an export gap, and neither counter nor
sequence numbers are durable storage or authorization state.

## Data and Boundaries

Audit records retain a registered tool identifier, or a fixed-length
session-scoped digest label for an invalid dynamic name, along with input and
output byte counts, a finite outcome, and an optional retry class. They do not
retain Splash source, tool input/output, external stream chunks, credentials,
approval objects, leases, worker keys, or VM promise state.

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
embedding application remains responsible for its storage, I/O, and platform
containment policy.
