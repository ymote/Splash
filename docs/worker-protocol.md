# Worker Protocol v1

`splash-protocol` is the portable data contract between a trusted Splash host
and a future platform-contained worker. It does not create a process, apply an
OS sandbox, or authenticate a peer. A host must establish an authenticated
local transport and select a containment backend before it sends an effectful
invocation.

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
  "protocol_version": 1,
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

## Dispatch lifecycle

1. The trusted host validates a manifest and creates `SessionAuthorizer`.
2. The host sends `open_session` to a contained worker over an authenticated
   transport.
3. Before dispatching `invoke`, the host calls `authorize`; this checks the
   session, request ID uniqueness, envelope format, byte limit, and call
   budget. Call budget is consumed before dispatch.
4. The worker resolves opaque selectors through its backend policy and runs the
   adapter.
5. The host validates the matching `result` against the authorized invocation
   before exposing it to Splash. A successful result is accepted once; replayed
   results are rejected.

`WorkerMessage::to_json_line` and `from_json_line` validate headers and cap an
individual wire frame at 1 MiB. Transport framing, peer authentication,
timeouts, cancellation delivery, durable replay, and worker lifecycle remain
backend responsibilities.

## Splash integration

`splash-capabilities::ProtocolWorkerClient` owns a `SessionAuthorizer` and a
host-provided `WorkerTransport`. Register it with
`CapabilityRuntime::register_protocol_json_tool`; registration rejects a local
`ToolPolicy` that exceeds the matching worker grant. Each Splash JSON tool call
then passes through both the local capability policy and the worker manifest
before the transport is invoked.
