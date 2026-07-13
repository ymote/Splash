# Worker Protocol v4

`splash-protocol` is the portable data contract between a trusted Splash host
and a platform-contained worker. It defines capability attenuation, bounded
JSON frames, and keyed message authentication. `splash-worker` implements the
worker-side dispatch and journal sequencing atop this contract. Neither crate
creates a process, establishes a session key, applies an OS sandbox, or
supplies rollback-resistant persistence. A host must select the containment
backend and provision its key through a trusted platform channel before it
sends an effectful invocation.

Version 4 is a breaking wire and durable-journal revision. Version 3 frames
and version 1 worker journals are rejected rather than silently interpreted
under the new compensation rules. A host upgrading a live system must make an
explicit migration or recovery decision for any unfinished v3 operation.

## Capability manifest

A `CapabilityManifest` binds one `session_id` to named `CapabilityGrant`s. A
grant defines:

- its tool name and `text` or `json` envelope format;
- call, input-byte, and output-byte limits;
- a separate maximum for explicitly host-approved compensation effects; and
- opaque resource selectors.

Resource selectors have a kind (`file_root`, `executable`, `network_origin`,
or `secret`) plus an opaque identifier. They are not paths, command lines, DNS
names, or secret values. The policy host maps each selector to a real resource
only inside its chosen worker backend.

```json
{
  "protocol_version": 4,
  "session_id": "release-42",
  "grants": [
    {
      "tool": "release.publish",
      "format": "json",
      "max_calls": 1,
      "max_input_bytes": 16384,
      "max_output_bytes": 65536,
      "max_compensations": 1,
      "resources": [
        {"kind": "network_origin", "id": "release-api"},
        {"kind": "secret", "id": "release-token"}
      ]
    }
  ]
}
```

JSON payloads must be objects or arrays. The protocol rejects scalar JSON at
both input and result boundaries, matching Splash's portable JSON tool
contract. It also bounds JSON nesting to 32 levels, including the root object
or array, before authorization, canonicalization, or adapter dispatch.

`max_compensations` defaults to zero. A normal tool grant therefore does not
authorize a compensating effect unless the host opts in explicitly.

## Attenuation

`CapabilityGrant::attenuate` can lower byte, call, or compensation limits and
select a subset of resources. It may reduce `max_compensations` to zero, but
can never increase it. `CapabilityManifest::attenuate` can also remove tools
entirely. It rejects any attempt to increase a limit, add a selector, or name
a tool the parent did not grant. An empty allowed-tool set produces a valid
zero-capability session.

## Authenticated framing

The host and worker each construct a `SessionAuthenticator` with the same
fresh `SessionKey`, session ID, and opposite `SessionRole`. A host calls
`seal` before transport and `open` after receiving a frame; the worker does
the inverse. The frame binds its full `WorkerMessage`, session, sender role,
and directional sequence number to a BLAKE3 keyed tag.

`open` rejects tampering, a wrong key, reflected host frames, replayed frames,
and any non-next sequence number before it returns the message. Incoming and
outgoing sequences are independent. `SessionKey` is intentionally neither
serializable nor displayable, and must never appear in a Splash script,
manifest, audit event, or worker command line.

The key is a 32-byte symmetric secret. Generate and transfer it through an
OS-provided CSPRNG and a platform-specific trusted bootstrap channel. The
protocol provides no key exchange, worker identity attestation, key rotation,
or confidentiality. It also cannot stop a peer that already holds the key;
that peer must be contained by the selected worker backend.

`AuthenticatedWorkerMessage::to_json_line` and `from_json_line` cap each
frame at 1 MiB. Decoding only validates wire syntax. Call
`SessionAuthenticator::open` before acting on any decoded frame.

## Dispatch lifecycle

1. The trusted host validates a manifest and creates `SessionAuthorizer`.
2. The host provisions a fresh session key to the selected contained worker,
   then creates host and worker `SessionAuthenticator` instances with opposite
   roles.
3. The host sends an authenticated `open_session` frame. Before dispatching
   `invoke`, it calls `authorize`; this checks the session, request ID
   uniqueness, envelope format, byte limit, and call budget. Call budget is
   consumed before dispatch.
4. The worker resolves opaque selectors through its backend policy and runs
   the adapter.
5. The host opens the authenticated matching `result` frame and validates it
   against the authorized invocation before exposing it to Splash. A
   successful result is accepted once; replayed results are rejected.

Transport framing, worker lifecycle, cancellation delivery, durable replay,
and OS policy remain backend responsibilities.

## Rust Adapter Runtime

`splash-worker::WorkerSession` is the baseline implementation for a trusted
Rust adapter catalog. It opens only a host-authenticated `open_session` frame,
requires `WorkerSessionAdmission` to bind the session ID and journal scope to
the intended tenant and replay policy, issue a current single-writer fencing
lease for that scope, and accepts only capability names explicitly registered
in `WorkerAdapterRegistry`. The journal scope is host-selected state, not a
field in an authenticated worker frame or a script input. The runtime
reauthorizes every frame against the live manifest, validates every output
against the corresponding grant, and owns bounded per-tool and whole-session
reconciliation budgets.

Before dispatching a request, the runtime also requires the registered adapter
to declare its path-specific contract. `invoke` needs a read-only or
independently-idempotent declaration. Durable dispatch and compensation need a
bounded durable-recovery declaration; dispatch recovery is by `operation_key`,
while compensation recovery remains adapter-specific. A provider-idempotency
declaration means the adapter must pass the exact `operation_key` to the
external provider as its idempotency key. These are trusted Rust adapter
contracts, not properties a Splash script can claim.

The runtime enforces worker journal ordering but runs with the privileges of
its embedding process. A production host must place it in the selected
contained worker and give it a `WorkerJournalStore` that meets the authenticated
rollback-resistant compare-and-swap storage contract. The host loads the
journal and its monotonic revision atomically, and each runtime persistence
must advance that revision under the current scope fencing lease. The store
rejects older leases, so a superseded session cannot write after a newer worker
has been admitted. See [worker adapter runtime](worker-runtime.md).

## Durable Operation Dispatch

`dispatch_operation` is the v4 path for an effect whose idempotency must
survive a worker restart. It carries the normal session, request ID, tool, and
bounded text or JSON payload plus a host-owned non-authorizing `operation_key`.
The worker returns `operation_result` using the existing operation status
shape: `running`, `succeeded`, `failed`, or `cancelled`.

Both messages must travel through `SessionAuthenticator`. A contained worker
first validates the request through `SessionAuthorizer`, then calls
`WorkerOperationJournal::admit` and persists that journal before it lets an
adapter run an effect. A new admission permits one dispatch. An exact duplicate
returns its existing `pending`, `running`, or terminal state and must not run
the adapter again. Reusing the same key with a different tool or canonical
input is rejected.

`splash-worker` returns `PendingOperation` for an existing `pending` record;
it never turns an unconfirmed effect into success. A `running` or terminal
state can be returned only after it is revalidated against the active grant.

The ordinary `invoke` message has no durable journal identity. Its adapter
handler is for read-only or independently idempotent work; use
`dispatch_operation` for a crash-sensitive external effect.

The baseline `splash-worker` runtime restores its in-memory journal to the
last successfully persisted state if recording an adapter observation fails.
It poisons that session and returns an indeterminate operation error rather
than a terminal response; the host must reopen from a fresh atomically loaded
journal and revision before it reconciles the same durable key. Its
reconciliation path only queries an operation already admitted in that journal
and persists a valid observation before replying.

For a host workflow ledger, derive and record the input with
`canonical_operation_input_bytes(&payload)` before it creates the dispatch
request. `WorkflowEngine::operation_dispatch_request` verifies that exact
canonical input binding before returning the frame data.

The journal has no ambient storage or tenant identity. Its host creates it for
one opaque worker scope, serializes it through authenticated rollback-resistant
storage, and validates that scope on load. A terminal result is retained so a
duplicate can receive the same output; use encryption if that output is
sensitive. See [worker durable operations](worker-operations.md) for the
complete state machine and restart sequence.

## Explicit Compensation

`compensate_operation` is the narrow v4 path for one inverse effect of a
previously succeeded durable operation. It is not exposed to Splash source and
it is not a generic retry or rollback command. The trusted host must first
persist a compensation intent in its workflow ledger, then issue a one-use,
session-bound approval before it seals an authenticated request. The host must
also reauthorize current tenant policy and grant revocation immediately before
approval and frame sealing; a durable grant fingerprint establishes identity,
not a perpetual authorization lease.

An `OperationCompensationRequest` repeats the original tool and operation key,
adds a `cmp-` compensation key, opaque tenant scope, and the BLAKE3 fingerprint
of the exact active `CapabilityGrant`. A contained worker accepts it only when
all of the following hold:

- the grant has a nonzero `max_compensations` budget and the request consumes
  that separate session budget;
- the request fingerprint exactly matches the active grant;
- the worker journal scope equals the request tenant scope;
- the original operation exists, uses the same tool, and is durably
  `succeeded`; and
- the compensation key and canonical input exactly match any existing
  compensation record for that original operation.

The worker calls `SessionAuthorizer::authorize_compensation`, then
`WorkerOperationJournal::admit_compensation`, and persists a new admission
before its adapter performs the inverse effect. A duplicate exact request
returns the existing `pending`, `running`, or terminal compensation state;
the adapter must not run again. It persists each observed compensation state
before returning `compensation_result`. Contradictory terminal observations,
input drift, grant drift, tenant drift, a second compensation key, and a
non-succeeded original are rejected.

The protocol ensures bounded, capability-scoped delivery and replay behavior;
it cannot prove that an adapter payload is a valid semantic inverse. A worker
adapter must expose a dedicated compensation handler for the tool and define
its own validation, audit, I/O deadline, and manual-recovery behavior. A host
must reconcile ambiguous delivery by reusing the same durable compensation key
under a fresh session and approval, never by inventing a second compensation
or automatically replaying an unknown effect. See
[durable worker compensation](worker-compensation.md) for the full recovery
sequence.

## External operation reconciliation

`reconcile_operation` asks a worker about one externally dispatched operation.
It contains a session ID, request ID, tool name, and non-authorizing
`operation_key`; it deliberately contains no process-local
`ExternalToolId`. The worker responds with `reconciled_operation`, repeating
those binding fields and one of these states:

- `running`;
- `succeeded` with a `text` or structured `json` payload;
- `failed` with a bounded non-empty message; or
- `cancelled`.

Both messages must travel in authenticated frames. The trusted host must check
that the result exactly matches the request before it changes a local
operation. A payload's envelope format still has to match the capability's
registered format and goes through the normal output byte and JSON-contract
checks.

For a live `CapabilityRuntime`,
`prepare_authenticated_external_reconciliation` creates the keyed request
frame from a claimed operation and
`reconcile_authenticated_external_tool` opens and applies the response. A
`running` observation leaves the Splash promise pending. A terminal state is
resolved through the same audit and output-validation boundary as a direct
external completion.

The v0.1 runtime's `operation_key` is a per-process idempotency key. It helps
an authenticated worker correlate retries while that runtime is alive, but it
does not make an `ExternalToolId`, promise, or VM state durable. Hosts that
need restart recovery must persist a durable operation identity and policy,
authenticate the storage and worker response, then decide whether to retry,
reconcile, compensate, or fail the workflow before creating a fresh runtime.
`splash-workflow` can create a plan-bound durable operation key and ledger for
that host policy; see [durable operation ledgers](workflow-operations.md).

## Splash integration

`splash-capabilities::ProtocolWorkerClient` owns a `SessionAuthorizer` and a
host-provided `WorkerTransport`. Register it with
`CapabilityRuntime::register_protocol_json_tool`; registration rejects a local
`ToolPolicy` that exceeds the matching worker grant. Each Splash JSON tool
call then passes through both the local capability policy and the worker
manifest before the transport is invoked.

`ProtocolWorkerClient` is an in-process adapter boundary, not a containment
implementation. Production local-tool adapters still need a separately
contained worker and authenticated transport.
