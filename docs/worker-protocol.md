# Worker Protocol v2

`splash-protocol` is the portable data contract between a trusted Splash host
and a platform-contained worker. It defines capability attenuation, bounded
JSON frames, and keyed message authentication. It does not create a process,
establish a session key, apply an OS sandbox, or persist worker state. A host
must select the containment backend and provision its key through a trusted
platform channel before it sends an effectful invocation.

## Capability manifest

A `CapabilityManifest` binds one `session_id` to named `CapabilityGrant`s. A
grant defines:

- its tool name and `text` or `json` envelope format;
- call, input-byte, and output-byte limits;
- opaque resource selectors.

Resource selectors have a kind (`file_root`, `executable`, `network_origin`,
or `secret`) plus an opaque identifier. They are not paths, command lines, DNS
names, or secret values. The policy host maps each selector to a real resource
only inside its chosen worker backend.

```json
{
  "protocol_version": 2,
  "session_id": "release-42",
  "grants": [
    {
      "tool": "release.publish",
      "format": "json",
      "max_calls": 1,
      "max_input_bytes": 16384,
      "max_output_bytes": 65536,
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
contract.

## Attenuation

`CapabilityGrant::attenuate` can lower byte or call limits and select a subset
of resources. `CapabilityManifest::attenuate` can also remove tools entirely.
It rejects any attempt to increase a limit, add a selector, or name a tool the
parent did not grant. An empty allowed-tool set produces a valid
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
