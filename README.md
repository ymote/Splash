# Splash

Splash is a capability-first scripting runtime for dynamic workflows, tool
orchestration, and data transformation. It starts from the Makepad Splash VM
and keeps UI support optional rather than making UI the language boundary.

## Current baseline

- A standalone, vendored VM and parser with upstream provenance.
- An effect-free, bounded canonical-language preflight with structured
  diagnostics for generated source and editor tooling.
- A bounded evaluator with source, instruction, and deadline limits.
- A deny-by-default tool host: scripts can call only explicitly registered
  tools through `mod.tool`.
- Audited tool calls with input/output and call-count limits.
- Bounded executable JSON contracts for structured tool inputs and outputs.
- Bounded, host-pumped deferred tool promises for cooperative mobile and
  embedded event loops.
- Deferred-only external tools that hosts claim, complete, or cancel without
  installing an in-process handler.
- Per-tool deferred deadlines with host-driven expiry and auditable timeout
  outcomes.
- Host-only bounded retries for external tools, with stable non-authorizing
  idempotency keys for each deferred operation.
- Bounded, optionally redacted external output chunks released only to the
  trusted host, never directly to Splash source.
- Keyed, directional, replay-checked worker protocol frames and authenticated
  reconciliation for live external operations.
- Authenticated durable-operation dispatch frames and a bounded worker journal
  for replay-safe idempotency across a worker restart.
- A capability-scoped worker runtime that dispatches only explicitly
  registered Rust adapters and enforces durable operation ordering.
- Host-approved, current-policy-revalidated durable compensation intents with
  one inverse effect per succeeded operation and replay-safe worker recovery.
- Bounded, data-only workflow checkpoints with fresh host approval required
  for a restart to run the remaining plan suffix.
- Plan-bound durable external-operation ledgers with input fingerprints,
  derived worker keys, and revision-watermark hooks for host storage policy.
- Host-only authenticated storage envelopes with key rotation and a strict
  rollback-protected compare-and-swap backend contract.
- Optional SQLite payload storage paired with an explicit trusted rollback
  anchor, including durable revision and fencing commitments.
- Fenced authenticated worker-journal storage that binds durable worker state
  to a host-selected record, revision, and current writer lease.
- Feature-gated authenticated in-process worker transport for app-provided
  mobile and embedded adapters; it preserves ordinary invocation framing but
  is not OS containment.
- Feature-gated bounded JSON-line worker channel and authenticated transport
  for host-provided contained-worker pipes; process creation, deadlines, and
  containment remain host policy.
- Linux Bubblewrap worker-policy compiler and launcher for a fixed,
  host-selected worker and manifest-selected file roots; it rejects network,
  executable, and secret selectors rather than claiming unsupported policy.
- A one-shot, versioned private-pipe session bootstrap for Linux Bubblewrap
  workers that is bound to the compiled manifest and precedes JSON worker
  frames without exposing the key through argv or environment variables.
- Optional bounded private `/tmp` capacity and a host lifecycle handle that
  force-terminates and reaps a Bubblewrap worker without treating termination
  as an adapter-effect result.
- A small `splash` CLI for local evaluation and the workflow example.

No filesystem, subprocess, raw socket, HTTP server, or Makepad platform
module is loaded by default. A capability check in the VM is not an OS
sandbox; adapters that execute local tools must run in a separately contained
worker before they are suitable for untrusted workloads.

## Example

```splash
use mod.tool

let summary = tool.call("text.echo", "plan the release")
summary
```

The host, not the script, decides whether `text.echo` exists and what it can
access.

For work that should yield back to the host event loop, use an explicit
promise. The host runs at most one granted tool when it calls `pump()` (or a
bounded batch with `pump_up_to`).

```splash
use mod.tool

let summary = tool.start("text.echo", "plan the release").await()
summary
```

Rust applications integrate their existing crate ecosystem by registering a
narrow, policy-bound adapter for each effect. Splash does not import crates or
ambient OS APIs directly.

JSON capabilities use object or array envelopes. Rust adapters receive and
return `serde_json::Value`; Splash turns records and arrays into JSON with
`tool.call_json` or `tool.start_json`.

```splash
use mod.tool
use mod.std.assert

let response_json = tool.call_json("math.add", {left: 20, right: 22})
let response = response_json.parse_json()
assert(response.total == 42)
```

```sh
cargo run -p splash-cli -- eval --allow-echo 'use mod.tool; tool.call("text.echo", "hello")'
```

The deferred example is runnable with:

```sh
cargo run -p splash-cli -- run --allow-echo examples/deferred_tool_workflow.splash
```

The JSON dataflow example is runnable with:

```sh
cargo run -p splash-cli -- run --allow-json-add examples/json_tool_workflow.splash
```

Inspect the exact demo-tool catalog supplied to an LLM host with:

```sh
cargo run -p splash-cli -- catalog --allow-echo --allow-json-add
```

Validate generated source against the canonical Splash v0.1 profile without
creating a capability host or running any bytecode:

```sh
cargo run -p splash-cli -- check examples/deferred_tool_workflow.splash
```

The command emits JSON diagnostics and exits nonzero for invalid source,
including Makepad compatibility syntax outside the portable contract. The
portable source contract is [Splash Grammar v0.1](docs/grammar.md).

## Workspace

- `splash-core`: bounded VM wrapper and diagnostics.
- `splash-capabilities`: explicit tool policy, audit log, deferred promises,
  LLM-facing host catalog, JSON contracts, and safe host bridge.
- `splash-schema`: bounded executable JSON-schema subset for tool contracts.
- `splash-storage`: host-only authenticated records, rollback protection, and
  fenced compare-and-swap backend boundary, plus an optional anchored SQLite
  payload adapter that requires a platform trust anchor.
- `splash-protocol`: portable worker messages, capability attenuation,
  keyed session framing, and host-side invocation/result validation.
- `splash-worker`: worker-side session runtime, explicit Rust adapter registry,
  and authenticated journal-store bridge; it is not an OS sandbox or platform
  storage backend.
- `splash-sandbox`: target-specific worker containment policy; its initial
  Bubblewrap backend is Linux-only and deliberately narrow.
- `splash-workflow`: host-owned planning, approval, checkpointing, durable
  operation records, and sequential execution.
- `splash-cli`: local development CLI.
- `vendor/makepad`: provenance-preserving compatibility import.

See [SECURITY.md](SECURITY.md) for the current threat model and [UPSTREAM.md](UPSTREAM.md)
for the import boundary. The [worker protocol](docs/worker-protocol.md)
defines the handoff to contained adapters. The [host tool catalog](docs/tool-catalog.md)
defines safe discovery for an LLM orchestrator. [JSON tool contracts](docs/schema-contracts.md)
define the executable structured-data boundary. [External tools](docs/external-tools.md)
define the host-managed async boundary.

[Worker protocol v4](docs/worker-protocol.md) also defines keyed worker frames
and the live-operation reconciliation boundary.

[Workflow checkpoints](docs/workflow-checkpoints.md) define the durable
host-orchestration boundary.

[Durable operation ledgers](docs/workflow-operations.md) define how a host
records and safely reconciles uncertain external effects across a restart.

[Authenticated storage](docs/durable-storage.md) defines the trusted durable
record boundary used to persist those host-owned records.

[Worker durable operations](docs/worker-operations.md) define the contained
worker-side replay and persistence boundary for effectful operation keys.

[Durable worker compensation](docs/worker-compensation.md) defines the
host-approval, worker-journal, and crash-recovery rules for one explicit
inverse effect.

[Worker adapter runtime](docs/worker-runtime.md) defines the worker-side Rust
adapter boundary and the integration requirements for a contained backend.

[Linux Bubblewrap workers](docs/linux-bubblewrap.md) define the first contained
worker launcher, its capability mapping, and its explicit non-guarantees.
