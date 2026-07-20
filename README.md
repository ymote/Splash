# Splash

Splash is a capability-first scripting runtime for dynamic workflows, tool
orchestration, and data transformation. It starts from the Makepad Splash VM
and keeps UI support optional rather than making UI the language boundary.

## Current baseline

- A standalone, vendored VM and parser with upstream provenance.
- An effect-free, bounded canonical-language preflight with structured
  diagnostics for generated source and editor tooling, plus token-aware
  lowering of canonical newline statement boundaries for the inherited VM.
- An effect-free canonical formatter that preserves comments and literal
  spellings while normalizing valid Splash source for LLM and editor workflows.
- A bounded, grammar-aware lexical symbol index for imports, functions, local
  bindings, parameters, and loop bindings without evaluating source.
- Bounded same-document lexical completion at expression identifiers, with
  scope-aware candidates, exact-token replacement edits, fixed `mod.tool`
  member suggestions for an exact visible `use mod.tool` binding, an optional
  bounded refreshable advisory tool-catalog projection for direct tool-name
  literals, and an optional refreshable module-interface projection for direct
  import paths and bounded chained imported-module members, plus bounded
  direct-literal record-field completion, hover, and definition through exact
  direct child literals and bounded alias paths without runtime type inference.
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
  highlights, lexical completion including the fixed `mod.tool` API and optional
  advisory tool and module metadata, bounded fixed/advisory capability signature
  help, one bounded direct-module output-object child level, and version-bound
  guarded rename without reading files or evaluating code.
- Default runtime and capability-host evaluation that rejects noncanonical
  Makepad compatibility syntax before a tool can run.
- Standalone runtime initialization that masks inherited Makepad UI/debug and
  unbounded native entry points before source evaluation, leaving only the
  documented core plus trusted host-installed modules reachable from Splash.
- Frozen no-authority `mod.std.math` scalar helpers, `mod.std.json` bounded
  JSON helpers, `mod.std.text` bounded text helpers, and `mod.std.array`
  bounded shallow-array helpers, plus `mod.std.object` bounded own-field record
  helpers for common dataflow without restoring Makepad's broader
  shader-oriented `mod.math` surface or granting host authority.
- A bounded evaluator with source, individual-string, tracked Splash-owned
  retained-heap, VM operand-stack, active-call-frame, instruction, and deadline
  limits. These VM ceilings are not an OS process-memory quota and exclude
  opaque trusted Rust adapter allocations.
- Direct `Runtime` JSON conversion through `.parse_json()`/`.to_json()`, the
  bounded `string.to_bytes()` bridge, and frozen `mod.std.json`: strict,
  byte- and depth-bounded input plus
  cycle-aware, byte- and depth-bounded output, with ordinary script errors
  rather than unbounded VM work.
- Recoverable `try ... catch ...` control flow across Splash function calls,
  with hard resource stops kept uncatchable and no implicit effect rollback.
- A deny-by-default tool host: scripts can call only explicitly registered
  tools through `mod.tool`.
- A bounded LLM-facing tool catalog with aggregate descriptor-count and
  serialized-byte limits in addition to per-tool metadata and schema bounds.
- Cursor-safe bounded capability-audit export and workflow-event views with
  explicit eviction counters, plus an opt-in authenticated durable
  capability-audit journal and authenticated workflow-event journal for
  host-owned operator/audit replay that remain separate from workflow
  authority.
- Bounded host-receipt-order cross-stream telemetry for named capability-audit
  and workflow-event source segments, including an in-memory aggregator and an
  authenticated durable aggregate journal with exact source and aggregate
  cursors, explicit loss detection, and no recovery or capability authority.
- Audited tool calls with input/output and call-count limits.
- Bounded executable JSON contracts for structured tool inputs and outputs.
- Schema-required Serde bridges for reviewed Rust input and output types.
- Bounded, host-pumped deferred tool promises for cooperative mobile and
  embedded event loops.
- A sealed static-catalog mobile and embedded profile for reviewed local Rust
  adapters, with executable JSON contracts for structured script-visible data.
- A bounded host-owned fixed-file catalog adapter for reviewed regular UTF-8
  files, addressed only by opaque identifiers and pinned at setup rather than
  by script-selected filesystem paths.
- A feature-gated host-owned fixed HTTP endpoint catalog and exact-origin
  policy catalog for reviewed JSON GET and POST calls. Fixed endpoints accept
  only opaque IDs; origin policies admit a bounded script URL only after exact
  scheme, host, and effective-port matching. Both use HTTPS by default, bound
  request/response data, disable proxies and redirects, and keep methods,
  headers, and credential bindings host controlled. A host can inject a
  resolved credential into one fixed HTTPS endpoint or intentionally across
  every accepted route at one exact HTTPS origin. An optional native resolver
  performs read-only exact credential lookup on macOS, iOS, and Windows
  without a mock fallback; this is API-level mediation, not egress containment
  or a general secret API.
- An optional Linux-only private Unix-socket HTTP broker for an isolated
  Bubblewrap worker. It binds exactly the manifest's opaque `network_origin`
  IDs to one reviewed endpoint or origin catalog, retains Bubblewrap's isolated
  network namespace, and adds a descriptor-pinned private directory containing
  one socket. It is aggregate per worker session, HTTP-only, and not a portable
  firewall,
  raw network API, per-tool process boundary, or durable-effect protocol.
- A bounded worker-side capability secret-broker contract for reviewed Rust
  adapters: a host-owned provider can release a zeroizing binary secret only
  to one exact preconfigured `(tool, secret-id)` binding whose active worker
  grant carries that same opaque `Secret` resource. It has no Splash lookup or
  enumeration API and is not itself a platform credential store or OS secret
  boundary.
- A sealed mobile and embedded workflow profile that exposes data-only drafts,
  bounded JSON dataflow and schema contracts, host-owned plans, named per-step
  policies, checkpoints, and execution, including setup-only fixed-file and
  fixed-endpoint/origin catalog adapters and direct capability modules, without
  exposing mutable capability registration.
- Deferred-only external tools that hosts claim, complete, or cancel without
  installing an in-process handler.
- Per-tool deferred deadlines with host-driven expiry and auditable timeout
  outcomes.
- Host-only bounded retries for external tools, with stable non-authorizing
  idempotency keys for each deferred operation. External registration fails
  closed when OS entropy is unavailable unless the host supplies a bounded
  session nonce with a documented uniqueness scope.
- Bounded, optionally redacted external output chunks released only to the
  trusted host, never directly to Splash source.
- Keyed, directional, replay-checked worker protocol frames and authenticated
  reconciliation for live external operations.
- Authenticated durable-operation dispatch frames and a bounded worker journal
  for replay-safe idempotency across a worker restart.
- A capability-scoped worker runtime that dispatches only explicitly
  registered Rust adapters and enforces durable operation ordering.
- Host-approved, current-policy- and product-action-revalidated durable
  compensation intents with one inverse effect per succeeded operation and
  replay-safe worker recovery.
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
- Bounded transactional rollback-anchor service protocol with an embeddable
  server-side dispatcher, optional exact caller/operation/record authorization
  gate, and optional fixed HTTPS client transport. It rejects malformed or
  regressing protocol data and disables client redirects and proxies, but the
  separately deployed service remains the rollback-resistant CAS authority.
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
  host-selected worker and manifest-selected file roots, plus an optional exact
  brokered HTTP `network_origin` path; it rejects executable and secret
  selectors and every network-origin grant without that broker rather than
  claiming unsupported policy,
  denies persistent writable host roots unless they carry a verified,
  descriptor-pinned Linux project quota with a configured aggregate hard byte
  and inode bound plus mandatory further-user-namespace lockdown, or host code
  explicitly selects the weaker external-quota escape hatch, and drops every
  Linux capability before worker execution.
- Optional Linux descriptor-pinned executable identity for the fixed
  Bubblewrap, worker, pre-exec runners, and explicit Landlock executable
  targets, with no path-launch fallback. It requires descriptor-pinned runtime
  roots and does not replace immutable runtime ownership or complete
  code-execution mediation.
- A one-shot, versioned private-pipe session bootstrap for Linux Bubblewrap
  workers that is bound to the exact manifest retained by the compiled command
  and precedes JSON worker frames without exposing the key through argv or
  environment variables.
- Optional bounded private `/tmp` capacity and a host lifecycle handle that
  force-terminates and reaps a Bubblewrap worker without treating termination
  as an adapter-effect result.
- Manifest-selected bounded ephemeral `file_root` mounts at host-chosen worker
  paths. Active persistent host-backed writable roots fail closed unless they
  use a verified Linux generic project quota on the exact descriptor-pinned
  root, with configured aggregate hard byte and inode bounds and mandatory
  further-user-namespace lockdown, or host code explicitly acknowledges an
  independently enforced quota. An opt-in stricter
  policy rejects unverified persistent roots and an unbounded private `/tmp`,
  requires further-user-namespace lockdown, and remounts the base namespace
  filesystems read-only. Each ephemeral root has its own `tmpfs` allocation
  ceiling, and hosts can reject a configured aggregate potential capacity
  before launch. This remains independent per-mount tmpfs accounting, not a
  shared tmpfs runtime quota; it does not independently cap inodes and is not
  persistent storage, a `noexec` guarantee, or a portable host-filesystem
  quota. A worker plan also defaults to at most 64 unique active `file_root`
  selections; a host can lower that bound, including to zero, or explicitly
  raise it only to the fixed 256-root maximum, bounding mount-plan expansion
  rather than disk use.
- Optional Linux cgroup-v2 worker sessions with host-delegated CPU bandwidth,
  memory, swap, task, and per-device I/O limits; a fixed runner joins the
  cgroup before Bubblewrap starts, and managed lifecycle teardown kills the
  whole worker process tree.
- Optional Linux Bubblewrap seccomp profiles: a compatibility-oriented fixed
  deny set and a bounded host-selected strict syscall allowlist that kills
  unlisted syscalls. With a Landlock executable runner, strict filtering is
  staged after Landlock setup and immediately before the fixed inner exec.
  Neither mediates executable paths or capability grants.
- Optional Linux Landlock filesystem-backed executable allowlist for exact
  worker-visible files, installed by a fixed pre-exec runner with no
  unsupported-kernel fallback. It is not a complete code-loading, network,
  secret, or capability boundary.
- Optional Bubblewrap watchdog and generic bounded worker transport with
  host-selected per-invocation and total-session wall-clock deadlines; expiry
  or host termination poisons the session and remains indeterminate.
- A small `splash` CLI for local evaluation and the workflow example.

No ambient filesystem, subprocess, raw socket, HTTP client/server, or Makepad
platform/debug module is source-reachable by default. The vendored VM bootstrap
retains compatibility objects internally, but `Runtime` masks their source
entry points before either canonical or compatibility evaluation. The optional
fixed-file and fixed-endpoint catalogs are explicit, bounded tools rather than
general filesystem or network APIs. A capability check in the VM is not an OS
sandbox; adapters that execute local tools or need egress isolation must run
behind an appropriate target-specific containment boundary before they are
suitable for untrusted workloads.

For ordinary numeric dataflow, `use mod.std.math` provides a small frozen
Splash-owned scalar library. It is separate from the masked Makepad
`mod.math` shader module and cannot access files, processes, networking,
clocks, entropy, or Rust crates.

For strict local JSON conversion, `use mod.std.json` provides only
`json.parse(document)` and `json.stringify(value)`. They reuse the same
byte/depth/cycle-bounded boundary as `.parse_json()` and `.to_json()` and have
no host, adapter, filesystem, process, network, clock, entropy, or crate
access.

For local text shaping, `use mod.std.text` provides `trim`, `lower`, `upper`,
Unicode-scalar `len`, Unicode-scalar `slice`, literal predicates, literal
`replace_all`, `split` with literal matching, and `join`. `slice` uses a
half-open scalar range with `0 <= start <= end <= text.len(value)`. `split`
matches a non-empty delimiter literally, preserves empty fields, and returns at
most 4,096 segments. `join` accepts an array of at most 4,096 strings,
preserves their order, and permits an empty string separator. Results use
Splash's configured string bound; the module does not expose regexes, host
state, filesystem, process, network, clock, entropy, or crate access.

For local collection shaping, `use mod.std.array` provides `array.len(value)`,
`array.has_index(value, index)`, `array.get(value, index, fallback)`,
`array.slice(value, start, end)`, `array.concat(left, right)`,
`array.reverse(value)`, `array.flatten(value)`, and `array.push(value, item)`.
`has_index` distinguishes an in-range `nil` item from an absent index, while
`get` returns its fallback only when the index is absent. Neither traverses the
array. `slice` uses a half-open range with non-negative integer indexes.
`flatten` is one level only: every outer item must be an array, and it rejects
any source or result over 4,096 items before copying. `push` mutates its array,
returns `nil`, and rejects a result over 4,096 items. The transforming helpers
are callback-free and shallow; `len`, `has_index`, and `get` are constant-time
and uncapped. The module does not expose host state, filesystem, process,
network, clock, entropy, or crate access.

For bounded record shaping, `use mod.std.object` provides `object.len(value)`,
`object.has(value, key)`, `object.get(value, key, fallback)`,
`object.keys(value)`, `object.entries(value)`, `object.values(value)`, and
`object.merge(left, right)`. It accepts plain record or JSON-object data only,
never follows prototypes, and never invokes callbacks. `has` distinguishes a
present `nil` own text field from an absent one; `get` returns its fallback only
when that own text field is absent. Neither traverses record fields. `keys`,
`entries`, `values`, and `merge` shallowly process at most 4,096 own text-keyed
fields; `entries` returns fresh `[text_key, value]` pairs in stored field order,
and `merge` also rejects a combined source count over that bound. `len` is
constant-time and uncapped. The module does not expose host state, filesystem,
process, network, clock, entropy, or crate access.

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

For a fixed reviewed adapter, a Rust host can instead register a bounded direct
capability module and generated source can use decoded data directly:

```splash
use mod.arithmetic
use mod.std.assert

let math = arithmetic
let response = math.add({left: 20, right: 22})
assert(response.total == 42)
```

This is host-configured syntax over the same contract-enforced capability, not
general module loading or direct crate access. It retains the target tool's
policy, audit, and capability-lease checks. See [Host Tool Catalog](docs/tool-catalog.md).

The development CLI registers this reviewed facade together with its `math.add`
demo capability:

```sh
cargo run -p splash-cli -- run --allow-json-add examples/direct_module_workflow.splash
cargo run -p splash-cli -- module-catalog --allow-json-add
cargo run -p splash-cli -- tool-calls --allow-json-add examples/direct_module_workflow.splash
cargo run -p splash-cli -- workflow-review --allow-json-add examples/direct_module_workflow_draft.json
cargo run -p splash-cli -- workflow-run --allow-json-add --grant calculate:math.add:1 examples/direct_module_workflow_draft.json
```

The catalog maps the `arithmetic.add` facade to `math.add`; workflow policies
and leases continue to grant the underlying `math.add` capability, never the
facade name. Review can preserve that mapping through a bounded exact local
root alias such as `let math = arithmetic`; it never treats an alias as a new
module, target tool, or grant.
Hosts can also register a `with_deferred_method` facade over a reviewed JSON
tool; its explicit `mode: "deferred"` returns the existing bounded promise and
`await()` yields decoded JSON while preserving the same underlying grant.
When the reviewed module catalog is configured, `tool-calls` and
`workflow-review` add advisory `direct_module_calls` entries that expose this
mapping for LLM and operator review. Those entries do not grant a tool or
replace the explicit `calculate:math.add:1` workflow policy above.

```sh
cargo run -p splash-cli -- run --allow-echo examples/tool_workflow.splash
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

Before generating source, an LLM host can query the versioned canonical
language contract without creating a runtime or registering a tool:

```sh
cargo run -p splash-cli -- profile
```

The JSON response identifies the profile and grammar path, reports the active
default bounds, and states the tool and workflow authority boundary. It is not
a tool catalog, capability grant, or substitute for the normative
[Splash Grammar v0.2](docs/grammar.md). Query the host's separate catalog
before proposing effectful calls.

For an LLM-generated ordered workflow, query the bounded draft producer schema
before writing its JSON envelope:

```sh
cargo run -p splash-cli -- workflow-schema
```

The schema describes only `format_version` and ordered `id`/`source` steps,
including the decoder's limits. It deliberately has no fields for capabilities,
approvals, contracts, checkpoints, results, or external-operation handles;
review the resulting file with `splash workflow-review` before the host plans
or approves anything.

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
direct sites and sets `tool_calls_truncated` when later sites were omitted. A
host can additionally expose its reviewed direct-module mapping; the
development demonstration does so only when `--allow-json-add` is present and
emits a separate advisory `direct_module_calls` list. That mapping can follow a
bounded exact local root alias of a visible direct import, but never computed
receivers, member aliases, or source-derived authority.

Review an LLM-generated multi-step draft before it becomes a host-owned plan:

```sh
cargo run -p splash-cli -- workflow-review examples/release_workflow_draft.json
```

The versioned JSON draft contains only step IDs and source. Review output
includes per-step syntax status and direct tool-call hints, never grants or
approvals. Each step reports `tool_calls_truncated` when its direct-call review
was capped; a workflow retains at most 4,096 hints across all steps. See
[workflow drafts](docs/workflow-drafts.md) for its bounds and host lifecycle.
With an explicitly configured host module catalog, a separate advisory
`direct_module_calls` list can map a direct facade call, including a bounded
exact local root alias, to its underlying tool; it has the same 4,096
workflow-wide cap and never selects a grant.

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

The `prepare` step explicitly narrows the host input to the reviewed
`math.add` envelope. The pure `summarize` step then uses a dynamic own-field
fallback lookup, bounded indexed-array lookup with an empty-input fallback, a
bounded array transformation and loop, text normalization, own-field record
merging, and a bounded JSON round trip. It receives no tool grant; only
`prepare` can issue the reviewed effect.

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

It accepts client-provided open-document text plus optional bounded advisory
initialization metadata and configuration refreshes, retains at most 128
document states and no document text above the standard 256 KiB source cap,
and provides full-sync diagnostics,
whole-document formatting, and top-level declaration symbols plus bounded
same-document lexical definition/reference requests, binding-kind hover, symbol
highlights, lexical completion, and guarded rename. Ordinary lexical completion
is offered only while the cursor is within or at the end of an expression-position
identifier. It returns the complete retained set of bindings visible at that
token, lets the client filter it, and supplies an exact replacement edit for the
identifier. Invalid source is eligible only at a site ending before the first
syntax diagnostic. Candidate occurrences and completion sites have independent
4,096-entry bounds; either truncation marks the LSP result incomplete. A
truncated site list can still serve a retained site, but a truncated symbol set
returns no candidates because an omitted inner definition could shadow a
retained outer binding. Rename is advertised only when the client supports
versioned `documentChanges`; every edit is bound to the exact open-document
version. It rejects truncated indexes, import path changes, invalid identifiers,
and rewrites that change the complete indexed lexical binding report. It never
reads a document URI, evaluates source, loads or resolves arbitrary imported
modules, creates a capability host, or loads a Rust adapter. For an exact,
lexically visible `use mod.tool` binding, it additionally suggests only the
fixed `call`, `call_json`, `start`, and `start_json` methods at a direct
`tool.` member site. For an exact visible `use mod.std.math` binding, it also
completes the documented fixed scalar functions and `pi`/`e` constants at a
direct `math.` member site, with plain-text hover and function signature help.
For an exact visible `use mod.std.assert` binding, it also provides fixed
plain-text hover and signature help for `assert(condition)`; `use mod.std`
supports the same fixed signature at direct `std.assert(...)`. These fixed
surfaces use no tool-catalog or adapter lookup, do not follow local aliases,
and do not imply a capability grant. For an exact visible `use mod.std.json`
binding, it completes `parse` and `stringify` with fixed plain-text hover and
signature help. For an exact visible `use mod.std.text` binding, it completes
the fixed text functions, including Unicode-scalar `slice`, literal `split`,
and string-array `join`, with plain-text hover and signature help. For an
exact visible `use mod.std.array` binding, it completes `len`, `has_index`,
`get`, `slice`, `concat`, `reverse`, `flatten`, and `push` with the same fixed
plain-text hover and signature help.
For an exact visible `use mod.std.object` binding, it completes `len`, `has`,
`get`, `keys`, `entries`, `values`, and `merge` with the same fixed plain-text
hover and signature help. At a statement-position `use mod.` path, the same
static projection completes `std`;
below `use mod.std.` it completes `array`, `assert`, `json`, `math`, `object`,
and `text`.
The frozen `mod.std` subtree cannot be extended by advisory catalog metadata. An
integration may additionally supply a
advisory tool-catalog projection through
`initializationOptions.splash.toolCatalog` or a later
`workspace/didChangeConfiguration` update; it accepts the `name`, `format`,
and `description` fields from the host catalog JSON. For an exact visible
`mod.tool` binding, the LSP completes the first string literal in direct
`call`/`start` calls from text entries and direct `call_json`/`start_json`
calls from JSON entries. It never connects to a capability runtime, reads a
catalog file, or derives a grant from this metadata. The projection is bounded
to 128 entries, 512 KiB of retained names and descriptions, 128-byte names,
and 4 KiB descriptions; malformed, duplicate, or oversized input is discarded
as a whole and marks that completion result incomplete. The lexical service
also recognizes an exact visible direct `let binding = { ... }` initializer.
At `binding.field`, a direct two-level literal path such as
`binding.child.grandchild.field`, or through an exact
`let alias = binding`, `let alias = binding.child`, or
`let alias = binding.child.grandchild` chain of at most 16 hops with at most
two alias child selections in total, whether carried by one edge or spread
across a chain, it offers the literal field names and supports hover and
definition to the field key. Alias targets resolve at their source position, so
lexical shadowing remains intact. This metadata has
1,024-shape, 4,096-field, and 1,024-direct-alias bounds. An omitted alias edge
makes retained record completion empty and incomplete and disables static field
hover and definition. The LSP suppresses a shape after an earlier direct write
or potentially mutating member, index, call, or escape path through the root or
any retained root, child, or grandchild alias that resolves to it. It does not infer
parenthesized or computed aliases, parenthesized or computed child values,
alias or member paths beyond that two-level budget, assignments, control flow,
function returns, imported values, or runtime data.
It otherwise remains conservative: it does not infer forward references,
general types, arbitrary record fields, builtins, arbitrary catalog data, or
runtime-derived imported-module exports.

An editor may also supply a separate advisory module-interface projection
through `initializationOptions.splash.moduleCatalog` or a later
`workspace/didChangeConfiguration` update. It completes the current segment in
a direct statement-position `use mod.*` path and bounded catalog paths after a
direct, visible imported module binding or a stable exact local root-alias
chain, and gives an exact catalog leaf a
plain-text advisory hover. An exact leaf that explicitly declares both a mode
and `single_json` call shape also receives a bounded one-value signature; the
server never infers a signature from a mode alone. It does not load a source
file, resolve a module, inspect a runtime export, or override the fixed
`mod.tool` API. Tool and module catalog keys refresh independently: an omitted
key keeps its prior value, JSON `null` explicitly clears it, and a malformed or
over-limit key value makes only that catalog unavailable. A malformed `settings`
value or non-object `settings.splash` clears all advisory catalogs. Neither
projection authorizes source. Module aliases must be exact `let alias = binding`
chains of at most 16 hops with complete source metadata and no write, member
extraction, parenthesized/computed edge, or other value escape in their resolved
group; otherwise catalog metadata fails closed. This does not extend the fixed
`mod.tool` API, whose editor support remains direct-import-only. See [editor
module-interface projection](docs/module-catalog.md) for its exact format and bounds. A
truncated lexical index can still serve retained, sound definitions and hover,
but exhaustive reference, highlight, and rename requests fail instead of
returning a partial set.

For a host-managed dataflow authoring session, an editor can also supply a
separate `initializationOptions.splash.workflowDataCatalog` projection. It
completes direct unshadowed `workflow.input.*` and
`workflow.outputs.<stepId>.*` paths and hovers known field metadata. A host
using `splash-workflow` can generate a validated current-prefix update from a
suspended contract-bound continuation or checkpoint; the LSP itself still does
not load schemas or runtime state. It does not validate data, approve a
workflow, issue a lease, or make an adapter callable;
missing metadata does not create a `workflow` namespace, and malformed input
fails closed. A host may provide `workflowDataStepContext` to structurally bind
one projected current step and its prior projected output prefix, which filters
output completion and hover. It may later replace a complete catalog/context
pair through `workspace/didChangeConfiguration`; a relevant malformed or
partial refresh makes workflow metadata unavailable rather than retaining a
stale projection. A terminal or unavailable runtime state can atomically clear
both keys with JSON `null`. See [editor workflow-data projection](docs/workflow-data-catalog.md).

## Workspace

- `splash-core`: bounded VM wrapper and diagnostics.
- `splash-capabilities`: explicit tool policy, cursor-safe bounded audit export
  with a feature-gated authenticated durable journal, deferred promises,
  LLM-facing host catalog, approval-bound capability leases, JSON contracts,
  fixed-file and feature-gated HTTP endpoint/origin catalogs, aggregate catalog
  limits, safe host bridge, and a sealed static-catalog mobile/embedded profile.
- `splash-schema`: bounded executable JSON-schema subset for tool contracts.
- `splash-storage`: host-only authenticated records, rollback protection, and
  fenced compare-and-swap backend boundary, plus an optional anchored SQLite
  payload adapter that requires a platform trust anchor and a bounded
  transactional-service anchor client; neither substitutes for the deployed
  trust authority.
- `splash-protocol`: portable worker messages, capability attenuation, fixed
  128-grant manifest and 1,024 retained-request-identity session bounds, keyed
  session framing, instance-bound in-process authorization tokens, strict
  ordinary-call cancellation, and host-side invocation/result validation.
- `splash-worker`: worker-side session runtime, explicit Rust adapter registry,
  cancellable ordinary-invocation driver, capability-bound secret-broker
  contract, and authenticated journal-store bridge; it is not an OS sandbox
  or platform storage backend.
- `splash-sandbox`: target-specific worker containment policy; its initial
  Bubblewrap backend is Linux-only and deliberately narrow, with bounded
  manifest-selected ephemeral file roots for scratch data.
- `splash-workflow`: host-owned planning, lease-bound approval, bounded JSON
  dataflow, bounded in-memory and authenticated durable event and cross-stream
  telemetry journals, host-receipt-order aggregation,
  checkpointing, durable operation records, optional fenced Bubblewrap
  post-stop reconciliation, a multiplexed-worker completion sink, sequential
  execution, and a sealed mobile/embedded workflow facade for static local
  adapters and direct capability modules.
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

[Fixed-file catalogs](docs/fixed-file-catalog.md) define the narrow
descriptor-pinned local text-file boundary.

[HTTP endpoint and origin catalogs](docs/http-endpoint-catalog.md) define the
narrow host-selected outbound JSON boundary, endpoint- and origin-bound
credential injection, and their explicit non-guarantees.

[Editor module-interface projection](docs/module-catalog.md) defines bounded
refreshable authoring metadata for host-defined `mod.*` interfaces.

[Worker protocol v5](docs/worker-protocol.md) also defines keyed worker frames
and the live-operation reconciliation boundary.

[Workflow checkpoints](docs/workflow-checkpoints.md) define the durable
host-orchestration boundary.

[Durable workflow events](docs/workflow-events.md) define the authenticated
telemetry replay boundary, which deliberately remains separate from recovery
authority.

[Capability audit export](docs/capability-audits.md) defines the contiguous
host-export cursor, optional authenticated durable journal, and explicit
observability-gap behavior.

[Cross-stream telemetry](docs/cross-stream-telemetry.md) defines bounded
in-memory and authenticated durable host-receipt-order aggregation of source
telemetry without creating recovery or capability authority.

[Workflow drafts](docs/workflow-drafts.md) define the untrusted LLM-plan
interchange and review boundary before a host-owned approval.

[Positioning and feasibility](docs/positioning.md) compares Splash with its
Makepad substrate and defines the realistic boundary for Python/JavaScript
replacement claims.

[Durable operation ledgers](docs/workflow-operations.md) define how a host
records and safely reconciles uncertain external effects across a restart.

[Authenticated storage](docs/durable-storage.md) defines the trusted durable
record boundary used to persist those host-owned records.

[Transactional rollback-anchor service](docs/rollback-anchor-service.md)
defines the bounded client protocol and embeddable server dispatcher for a
separately trusted durable CAS authority.

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
