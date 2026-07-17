# Worker Protocol v5

`splash-protocol` is the portable data contract between a trusted Splash host
and a platform-contained worker. It defines capability attenuation, bounded
JSON frames, and keyed message authentication. `splash-worker` implements the
worker-side dispatch and journal sequencing atop this contract. Neither crate
creates a process, generates a session key, establishes trust in a worker,
applies an OS sandbox, or supplies rollback-resistant persistence. A host must
select the containment backend and provision its key through a trusted platform
channel before it sends an effectful invocation.

Version 5 is a breaking wire revision for authenticated cooperative
cancellation. Version 4 and earlier frames are rejected, and the keyed-frame
domain is distinct, so an upgrade must create a fresh session and key rather
than reuse an active v4 stream. The durable worker-journal format remains at
version 2, introduced with protocol v4; version 1 journals are still rejected.
An unfinished durable operation therefore keeps its journal identity and must
be reconciled under a fresh v5 session rather than redispatched.

## Capability manifest

A `CapabilityManifest` binds one `session_id` to named `CapabilityGrant`s. A
grant defines:

- its tool name and `text` or `json` envelope format;
- call, input-byte, and output-byte limits;
- a separate maximum for explicitly host-approved compensation effects; and
- opaque resource selectors.

A manifest contains at most 128 distinct grants, and each grant contains at
most 64 resource selectors. These fixed structural limits bound manifest
validation, authorization state, and worker policy planning independently of
the 1 MiB authenticated-frame limit. A host that needs fewer capabilities must
attenuate the manifest before opening the worker session; a zero-grant manifest
remains valid and grants no tool authority. A host that needs more must split
work across separately approved worker sessions rather than expand one session
manifest.

Resource selectors have a kind (`file_root`, `executable`, `network_origin`,
or `secret`) plus an opaque identifier. They are not paths, command lines, DNS
names, or secret values. The policy host maps each selector to a real resource
only inside its chosen worker backend.

```json
{
  "protocol_version": 5,
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
serializable nor displayable, and each owned copy is zeroized on drop. This
reduces residual key lifetime but is not a memory-locking or crash-dump
guarantee. The key must never appear in a Splash script, manifest, audit event,
or worker command line.

The key is a 32-byte symmetric secret. Generate and transfer it through an
OS-provided CSPRNG and a platform-specific trusted bootstrap channel. The
protocol provides no key exchange, worker identity attestation, key rotation,
or confidentiality. It also cannot stop a peer that already holds the key;
that peer must be contained by the selected worker backend.

### Private-pipe bootstrap

`PrivatePipeWorkerBootstrap` is a bounded, versioned binary preamble for a
private host-to-worker pipe. It carries a validated session ID and an existing
host-generated `SessionKey`, allowing the worker to call `read_from`, construct
its worker-side authenticator with `into_worker_authenticator`, then verify the
first authenticated `open_session` frame through `WorkerSession::open` or
`SessionAuthenticator::open`. It rejects an invalid header or version, invalid
session ID, invalid UTF-8, weak key, and truncation.

It is not key generation, key exchange, encrypted transport, worker
attestation, or secret storage. Use it only on a one-way private pipe before
the JSON-line channel begins; do not put it in a socket, ordinary JSON frame,
Splash value, log, manifest, command line, environment variable, or capability
selector. When using a `BufReader`, retain that same reader for JSON frames so
any bytes it prefetched are not lost. A bootstrap failure means the host and
worker must discard the session rather than reuse the stream.

`AuthenticatedWorkerMessage::to_json_line` and `from_json_line` cap each
frame at 1 MiB. Decoding only validates wire syntax. Call
`SessionAuthenticator::open` before acting on any decoded frame.

## Dispatch lifecycle

1. The trusted host validates a manifest and creates `SessionAuthorizer`.
2. The host provisions a fresh session key to the selected contained worker,
   then creates host and worker `SessionAuthenticator` instances with opposite
   roles. The Linux Bubblewrap launcher can write a matching private-pipe
   bootstrap before it returns the worker pipes.
3. The host sends an authenticated `open_session` frame. Before dispatching
   `invoke`, it calls `authorize`; this checks the session, request ID
   uniqueness, envelope format, byte limit, and call budget. Call budget is
   consumed before dispatch.
4. The worker resolves opaque selectors through its backend policy and runs
   the adapter.
5. The host opens the authenticated matching `result` frame and validates it
   against the authorized invocation before exposing it to Splash. A
   successful result is accepted once; replayed results are rejected.

Transport framing, worker lifecycle, durable replay, and OS policy remain
backend responsibilities.

## Cooperative Cancellation

Protocol v5 defines `cancel` and `cancellation_result` for one active ordinary
`invoke`. A `WorkerCancellationRequest` has its own unique cancellation ID and
repeats the exact session, target request ID, and tool. It contains no tool
input, `ExternalToolId`, path, executable, origin, secret, or new capability.
The host and worker independently bind it to the already authorized invocation.
Only one cancellation request is admitted for a target.

The worker returns one of three dispositions:

- `acknowledged`: the reviewed adapter has stopped the operation and guarantees
  that no ordinary result will follow;
- `too_late`: the ordinary result won and must appear first in authenticated
  worker-to-host frame order; or
- `unsupported`: the adapter cannot make the cooperative guarantee, so the
  invocation remains active and may still return a result.

An acknowledgement after a result, a result after an acknowledgement,
`too_late` before a result, `unsupported` after a result, a second cancellation,
and any identity mismatch are rejected. A process exit, pipe EOF, transport
error, watchdog deadline, or host kill is not an acknowledgement.

`splash-worker::cancellable::CancellableWorkerSessionDriver` keeps the
authenticated frame loop responsive while one explicitly registered
`CancellableWorkerAdapter` executes on an owned thread. Its cancellation token
is set only after the request frame authenticates and reauthorizes. The adapter
may return `CancellationAcknowledged` only after its effect and downstream I/O
are stopped. The driver refuses manifests containing a normal synchronous
adapter; the baseline `WorkerSession` continues to reject cancellation frames.
On a fatal session error, the driver requests adapter cancellation and joins
the thread instead of returning a detached effect. An adapter that ignores the
token can therefore block worker teardown and must be bounded by the host
process watchdog.

On the host, `MultiplexedAuthenticatedWorkerTransport` owns one directional
sealer, one directional opener, and one active ordinary invocation. It can send
`cancel` while a result is pending and buffers a result-wins race until the
matching `too_late` disposition has also validated. `ExternalToolWorkerBinding`
keeps the runtime's opaque identity and input local, and maps only a positive
acknowledgement to `confirm_external_tool_cancellation`.

`SupervisedMultiplexedWorkerSession` additionally binds the transport to a
`SessionBoundWorkerExecutionSupervisor`, arms its deadline before `invoke`, and
resolves the watchdog race before exposing a terminal worker event. The Linux
`BubblewrapWorkerWatchdog` implements this contract. If lifecycle control wins,
the session is poisoned and the external operation remains pending for
reconciliation. `splash-workflow/multiplexed-worker` applies successful events
through `WorkflowEngine`, preserving suspended-step bookkeeping instead of
mutating its underlying runtime directly.

This path is deliberately limited to ordinary invocations whose adapter has a
reviewed cooperative contract. `dispatch_operation`, compensation, and
reconciliation keep their journaled one-shot semantics. An ambiguous stop of a
durable effect must use the existing fresh-session reconciliation path.

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
has been admitted. `AuthenticatedWorkerJournalStore` connects that runtime
contract to `AuthenticatedStore` only when its backend implements the fenced
rollback-protected storage extension. A fresh admission must issue a nonzero
lease from an atomic per-scope reservation, such as
`FencedRollbackProtectedStore::reserve_fence`, or an equivalent trusted lease
service. It must not calculate `current_fence + 1` from a separate read. See
[worker adapter runtime](worker-runtime.md).

## Durable Operation Dispatch

`dispatch_operation` is the v5 path for an effect whose idempotency must
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

`compensate_operation` is the narrow v5 path for one inverse effect of a
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
contained worker and authenticated transport. It maps a transport failure to a
generic Splash error, so transport, adapter, persistence, or authentication
details stay on the trusted host side.

For a fixed, app-provided mobile or embedded adapter catalog, the optional
`splash-capabilities/in-process-worker` feature supplies
`InProcessAuthenticatedWorkerTransport`. It exercises the authenticated
ordinary `invoke`/`result` host-to-worker-to-host frames in one process,
including session ID, role, sequence, and key-tag verification. It supplies no
process, memory, syscall, or resource isolation and must not be described as a
sandbox. See [worker adapter runtime](worker-runtime.md#authenticated-in-process-transport).

For a separately started worker, the optional
`splash-capabilities/json-line-worker` feature provides
`JsonLineWorkerChannel` over host-supplied buffered input/output handles and
`AuthenticatedFrameWorkerTransport` for ordinary calls and
`OneShotAuthenticatedOperationWorkerTransport` for one durable dispatch,
reconciliation, or compensation exchange. The host first sends the one-way
authenticated `open_session` frame, then moves the same advanced host
authenticator and channel into the selected transport. It writes exactly one
JSON frame plus `\n` per outbound message and reads exactly one bounded frame
per response. The channel rejects a line longer than 1 MiB before decoding and
poisons itself on any I/O, decoding, or framing failure; both authenticated
transports poison themselves on an invalid or unexpected response. The durable
transport is consumed after one exchange, so a host recovering a stopped worker
must start a fresh session from the durable journal rather than replaying an
effect on an interrupted stream.

The same feature also provides `MultiplexedAuthenticatedWorkerTransport` for
one cancellable ordinary invocation at a time. Unlike the synchronous channel
wrapper, it keeps authenticated reads and writes independently owned so a
trusted event loop can send cancellation during a running adapter. Pair it
with `CancellableWorkerSessionDriver` on the worker and a session-bound process
supervisor on the host. Do not mix it with durable dispatch frames or adapters
registered only through the synchronous worker contract.

The JSON-line adapter is not a process launcher, sandbox, timeout mechanism,
key-exchange protocol, or worker attestation scheme. A host using the Linux
Bubblewrap private-pipe helper must bootstrap its worker before it creates this
JSON channel. Every host must still apply its platform's process, filesystem,
executable, network, resource, and cancellation policy before it sends an
effectful call. See [worker adapter runtime](worker-runtime.md#bounded-json-line-transport).
