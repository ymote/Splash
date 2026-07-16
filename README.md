# Splash

Splash is a capability-first scripting runtime for dynamic workflows, tool
orchestration, and data transformation. It starts from the Makepad Splash VM
and keeps UI support optional rather than making UI the language boundary.

## Current baseline

- A standalone, vendored VM and parser with upstream provenance.
- An effect-free, bounded canonical-language preflight with structured
  diagnostics for generated source and editor tooling.
- An effect-free canonical formatter that preserves comments and literal
  spellings while normalizing valid Splash source for LLM and editor workflows.
- A bounded, grammar-aware lexical symbol index for imports, functions, local
  bindings, parameters, and loop bindings without evaluating source.
- Bounded same-document lexical completion at expression identifiers, with
  scope-aware candidates and exact-token replacement edits.
- An effect-free per-step workflow review that pairs syntax status with direct
  tool-call hints before a host issues ordered capability leases.
- A bounded, data-only workflow-draft JSON format and CLI review path for LLM
  plans before a host creates a trusted plan or issues authority.
- Approval-bound bounded JSON workflow dataflow: host input and completed step
  outputs are injected as data only, remain lease-constrained, and are never
  copied into workflow telemetry.
- Optional host-owned dataflow schema contracts that validate input and every
  completed step output before a later step's authority can become active, and
  bind their digest into contract-aware dataflow checkpoints.
- A host-only stdio language server that publishes canonical syntax diagnostics,
  full-document formatting edits, top-level declaration symbols, and
  same-document lexical definitions, references, binding-kind hover, and symbol
  highlights, lexical completion, and version-bound guarded rename without
  reading files or evaluating code.
- Default runtime and capability-host evaluation that rejects noncanonical
  Makepad compatibility syntax before a tool can run.
- A bounded evaluator with source, instruction, and deadline limits.
- Recoverable `try ... catch ...` control flow across Splash function calls,
  with hard resource stops kept uncatchable and no implicit effect rollback.
- A deny-by-default tool host: scripts can call only explicitly registered
  tools through `mod.tool`.
- A bounded LLM-facing tool catalog with aggregate descriptor-count and
  serialized-byte limits in addition to per-tool metadata and schema bounds.
- Bounded capability audit and workflow-event views with explicit eviction
  counters, plus an authenticated durable workflow-event journal for
  host-owned operator/audit replay that remains separate from workflow
  authority.
- Audited tool calls with input/output and call-count limits.
- Bounded executable JSON contracts for structured tool inputs and outputs.
- Schema-required Serde bridges for reviewed Rust input and output types.
- Bounded, host-pumped deferred tool promises for cooperative mobile and
  embedded event loops.
- A sealed static-catalog mobile and embedded profile for reviewed local Rust
  adapters, with executable JSON contracts for structured script-visible data.
- A sealed mobile and embedded workflow profile that exposes data-only drafts,
  bounded JSON dataflow and schema contracts, host-owned plans, named per-step
  policies, checkpoints, and execution without exposing mutable capability
  registration.
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
- Approval-bound, catalog-fingerprinted capability leases that attenuate
  dynamic workflow tool calls across `await` and resume, including one
  least-privilege lease per trusted workflow step.
- Host-owned, ordered per-step capability policies that bind named trusted
  steps to grants before issuing those leases; they are configuration, not
  serialized or script-visible authority.
- Bounded, data-only workflow checkpoints with fresh host approval required
  for a restart to run the remaining plan suffix, with dataflow checkpoints
  retaining only a context digest rather than raw input or prior outputs.
- Resumable live external workflow steps that retain the approved capability
  lease through host completion or a two-phase cooperative adapter
  cancellation request and acknowledgement.
- Plan-bound durable external-operation ledgers with input fingerprints,
  derived worker keys, revision-watermark hooks, and a two-stage
  prepare/persist/exact-claim bridge for suspended external workflow steps.
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
- Feature-gated multiplexed JSON-line transport and worker driver for one
  authenticated ordinary invocation, with exact request-bound cooperative
  cancellation, explicit cancellable-adapter opt-in, and no false
  acknowledgement on process termination.
- A session-bound supervisor bridge that resolves watchdog races before it
  applies worker completion or cancellation to `CapabilityRuntime`, plus a
  workflow adapter that advances suspended steps through `WorkflowEngine`.
- Feature-gated one-shot authenticated durable-operation transport for a fresh
  contained-worker session; it validates one dispatch, reconciliation, or
  compensation result but does not automate recovery policy.
- Feature-gated Bubblewrap post-stop recovery coordinator that requires a
  session-bound reaping proof, starts a differently keyed least-privilege
  contained worker, performs one watchdog-bounded reconciliation, and commits
  the observation through fenced authenticated compare-and-swap storage.
- Linux Bubblewrap worker-policy compiler and launcher for a fixed,
  host-selected worker and manifest-selected file roots; it rejects network,
  executable, and secret selectors rather than claiming unsupported policy,
  and drops every Linux capability before worker execution.
- A one-shot, versioned private-pipe session bootstrap for Linux Bubblewrap
  workers that is bound to the exact manifest retained by the compiled command
  and precedes JSON worker frames without exposing the key through argv or
  environment variables.
- Optional bounded private `/tmp` capacity and a host lifecycle handle that
  force-terminates and reaps a Bubblewrap worker without treating termination
  as an adapter-effect result.
- Manifest-selected bounded ephemeral `file_root` mounts at host-chosen worker
  paths, with an opt-in policy that rejects active writable host binds and an
  unbounded private `/tmp`, requires further-user-namespace lockdown, and
  remounts the base namespace filesystems read-only. Each root has its own
  `tmpfs` allocation ceiling; this does not independently cap inodes and is not
  persistent storage, a `noexec` guarantee, or a host-filesystem quota.
- Optional Linux cgroup-v2 worker sessions with host-delegated CPU bandwidth,
  memory, swap, task, and per-device I/O limits; a fixed runner joins the
  cgroup before Bubblewrap starts, and managed lifecycle teardown kills the
  whole worker process tree.
- Optional Linux Bubblewrap seccomp profiles: a compatibility-oriented fixed
  deny set and a bounded host-selected strict syscall allowlist that kills
  unlisted syscalls. Neither mediates executable paths or capability grants.
- Optional Bubblewrap watchdog and generic bounded worker transport with
  host-selected per-invocation and total-session wall-clock deadlines; expiry
  or host termination poisons the session and remains indeterminate.
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

For a recovery-safe fallback, use canonical `try/catch`. Recovery does not
refund the call or imply that an adapter effect was rolled back.

```splash
use mod.tool

let summary = try {
    tool.start("text.echo", "plan the release").await()
} catch {
    "summary unavailable"
}
summary
```

Rust applications integrate their existing crate ecosystem by registering a
narrow, policy-bound adapter for each effect. Splash does not import crates or
ambient OS APIs directly.

JSON capabilities use object or array envelopes. Rust adapters can receive and
return `serde_json::Value`, or use the schema-required typed Serde bridge for
reviewed structs; Splash turns records and arrays into JSON with
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

## Makepad UI compatibility

[`examples/makepad_ui_counter.splash`](examples/makepad_ui_counter.splash) is a
small current-style Makepad UI body retained as a parser compatibility fixture.
It is deliberately not runnable through `splash-cli`: the standalone runtime
does not install Makepad widget modules, an event loop, or the `ui` handle.
The canonical workflow profile continues to reject it; trusted UI hosts can
use `splash_core::check_vm_compatibility_named`, which enforces source, token,
and delimiter-nesting bounds, before they install their own bindings. See
[Makepad UI compatibility](docs/makepad-ui-compatibility.md) for the current
upstream example distinction and the exact boundary.

Inspect the exact demo-tool catalog supplied to an LLM host with:

```sh
cargo run -p splash-cli -- catalog --allow-echo --allow-json-add
```

Validate generated source against the canonical Splash v0.2 profile without
creating a capability host or running any bytecode:

```sh
cargo run -p splash-cli -- check examples/deferred_tool_workflow.splash
```

The command emits JSON diagnostics and exits nonzero for invalid source,
including Makepad compatibility syntax outside the portable contract. The
portable source contract is [Splash Grammar v0.2](docs/grammar.md).

Inspect valid top-level declarations without evaluating source or constructing
a capability host:

```sh
cargo run -p splash-cli -- outline examples/json_tool_workflow.splash
```

The command emits JSON with `function` and `let` declarations plus UTF-8 byte
spans for each declaration and identifier. Invalid source still emits the
structured syntax diagnostics and exits nonzero with an empty declaration list.

Inspect direct source-level `tool.call`, `tool.start`, `tool.call_json`, and
`tool.start_json` sites before requesting approval:

```sh
cargo run -p splash-cli -- tool-calls examples/json_tool_workflow.splash
```

The command emits JSON locations plus a literal tool name when the first
argument is directly written as a string. It never evaluates source or creates
a capability host. It is a review aid only: aliases, shadowing, control flow,
and computed names remain unresolved, so the host must still issue a lease and
the runtime must authorize every actual call. The output retains at most 1,024
direct sites and sets `tool_calls_truncated` when later sites were omitted.

Review an LLM-generated multi-step draft before it becomes a host-owned plan:

```sh
cargo run -p splash-cli -- workflow-review examples/release_workflow_draft.json
```

The versioned JSON draft contains only step IDs and source. Review output
includes per-step syntax status and direct tool-call hints, never grants or
approvals. Each step reports `tool_calls_truncated` when its direct-call review
was capped; a workflow retains at most 4,096 hints across all steps. See
[workflow drafts](docs/workflow-drafts.md) for its bounds and host lifecycle.

Run the bounded local demonstration catalog only with explicit host-selected
per-step grants:

```sh
cargo run -p splash-cli -- workflow-run --allow-echo --allow-json-add \
  --grant prepare:text.echo:1 --grant calculate:math.add:1 \
  examples/local_workflow_draft.json
```

Run the bounded dataflow example with explicit input and one reviewed grant:

```sh
cargo run -p splash-cli -- workflow-run --allow-json-add \
  --input examples/dataflow_input.json \
  --grant prepare:math.add:1 \
  examples/dataflow_workflow_draft.json
```

`workflow-run` accepts only the two opt-in local demo adapters and prints a
structured execution/audit summary. It never derives grants from source hints,
opens filesystem/network/process authority, or supports external workers. A
production host must construct its own reviewed catalog and policy. With
`--input`, the direct result also contains raw dataflow input and outputs for
local inspection; the audit and workflow event views never do.

For production dataflow, a host can additionally bind compiled input and
per-step output schemas through `WorkflowDataContract`. Those schemas are
trusted application configuration, not draft or checkpoint fields; a failed
output contract stops the workflow before a later authorized step runs. Use the
paired contract-aware checkpoint/resume APIs to keep that policy across a
restart. See
[workflow drafts](docs/workflow-drafts.md) and
[workflow checkpoints](docs/workflow-checkpoints.md).

Format valid canonical source without creating a capability host or rewriting
the input file:

```sh
cargo run -p splash-cli -- format examples/deferred_tool_workflow.splash
```

Use `--check` in an editor or CI workflow to require the canonical formatting
result without printing it:

```sh
cargo run -p splash-cli -- format --check examples/deferred_tool_workflow.splash
```

Run the language server from an LSP-compatible editor with:

```sh
cargo run -p splash-lsp
```

It accepts only client-provided open-document text, retains at most 128
document states and no document text above the standard 256 KiB source cap,
and provides full-sync diagnostics, whole-document formatting, and top-level
declaration symbols plus bounded same-document lexical definition/reference
requests, binding-kind hover, symbol highlights, lexical completion, and
guarded rename. Completion is offered only while the cursor is within or at the
end of an expression-position identifier. It returns the complete retained set
of bindings visible at that token, lets the client filter it, and supplies an
exact replacement edit for the identifier. Invalid source is eligible only at
a site ending before the first syntax diagnostic. Candidate occurrences and
completion sites have independent 4,096-entry bounds; either truncation marks
the LSP result incomplete. A truncated site list can still serve a retained
site, but a truncated symbol set returns no candidates because an omitted inner
definition could shadow a retained outer binding. Rename is advertised only
when the client supports
versioned `documentChanges`; every edit is bound to the exact open-document
version. It rejects truncated indexes, import path changes, invalid identifiers,
and rewrites that change the complete indexed lexical binding report. It never
reads a document URI, evaluates source, resolves an imported module, creates a
capability host, or loads a Rust adapter. The lexical service is conservative:
it does not infer forward references, types, record keys, member fields,
builtins, tool catalogs, or imported-module exports. A truncated lexical index
can still serve retained, sound definitions and hover, but exhaustive
reference, highlight, and rename requests fail instead of returning a partial
set.

## Workspace

- `splash-core`: bounded VM wrapper and diagnostics.
- `splash-capabilities`: explicit tool policy, bounded audit view, deferred promises,
  LLM-facing host catalog, approval-bound capability leases, JSON contracts,
  aggregate catalog limits, safe host bridge, and a sealed static-catalog
  mobile/embedded profile.
- `splash-schema`: bounded executable JSON-schema subset for tool contracts.
- `splash-storage`: host-only authenticated records, rollback protection, and
  fenced compare-and-swap backend boundary, plus an optional anchored SQLite
  payload adapter that requires a platform trust anchor.
- `splash-protocol`: portable worker messages, capability attenuation,
  keyed session framing, strict ordinary-call cancellation, and host-side
  invocation/result validation.
- `splash-worker`: worker-side session runtime, explicit Rust adapter registry,
  cancellable ordinary-invocation driver, and authenticated journal-store
  bridge; it is not an OS sandbox or platform storage backend.
- `splash-sandbox`: target-specific worker containment policy; its initial
  Bubblewrap backend is Linux-only and deliberately narrow, with bounded
  manifest-selected ephemeral file roots for scratch data.
- `splash-workflow`: host-owned planning, lease-bound approval, bounded JSON
  dataflow, bounded in-memory and authenticated durable event replay,
  checkpointing, durable operation records, optional fenced Bubblewrap
  post-stop reconciliation, a multiplexed-worker completion sink, sequential
  execution, and a sealed mobile/embedded workflow facade for static local
  adapters.
- `splash-cli`: local development CLI.
- `splash-lsp`: host-only stdio diagnostics, canonical formatting, top-level
  declaration symbols, and bounded same-document lexical navigation, hover, and
  highlights plus lexical completion and version-bound guarded rename for open
  editor documents.
- `vendor/makepad`: provenance-preserving compatibility import.

See [SECURITY.md](SECURITY.md) for the current threat model and [UPSTREAM.md](UPSTREAM.md)
for the import boundary. The [worker protocol](docs/worker-protocol.md)
defines the handoff to contained adapters. The [host tool catalog](docs/tool-catalog.md)
defines safe discovery for an LLM orchestrator. [JSON tool contracts](docs/schema-contracts.md)
define the executable structured-data boundary. [External tools](docs/external-tools.md)
define the host-managed async boundary.

[Worker protocol v5](docs/worker-protocol.md) also defines keyed worker frames
and the live-operation reconciliation boundary.

[Workflow checkpoints](docs/workflow-checkpoints.md) define the durable
host-orchestration boundary.

[Durable workflow events](docs/workflow-events.md) define the authenticated
telemetry replay boundary, which deliberately remains separate from recovery
authority.

[Workflow drafts](docs/workflow-drafts.md) define the untrusted LLM-plan
interchange and review boundary before a host-owned approval.

[Positioning and feasibility](docs/positioning.md) compares Splash with its
Makepad substrate and defines the realistic boundary for Python/JavaScript
replacement claims.

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

[Bubblewrap post-stop recovery](docs/bubblewrap-recovery.md) defines the
reaping, fresh-session reconciliation, and fenced host-ledger commit sequence.
