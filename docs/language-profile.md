# Splash Language Profile v0.1

This profile defines the portable, LLM-oriented subset exercised by the
standalone runtime. The fixture at
`crates/splash-core/tests/fixtures/workflow_language.splash` is normative for
this first release; parser features outside the fixture remain compatibility
features inherited from the upstream VM until separately specified.

## Source contract

Provide normal Splash source. The runtime adds its own internal terminal
marker, so generated code must not depend on Makepad widget-host framing.

The current profile supports:

- `let` declarations and mutation.
- Functions with `fn`, arguments, `return`, and lexical closures.
- Numbers, strings, booleans, arrays, and record literals.
- Field access, array operations, conditionals, loops, and assertions.
- Module imports through `use mod.<name>`.
- Host-defined tools through `use mod.tool`, `tool.call(name, input)`, and
  `tool.start(name, input).await()`.
- JSON envelope tools through `tool.call_json(name, value)` and
  `tool.start_json(name, value).await()`.

Example:

```splash
use mod.tool

let summary = tool.call("text.echo", "summarize the release notes")
summary
```

## Effect rules

The core runtime does not install `mod.fs`, `mod.run`, or `mod.net`. A script
cannot acquire authority by importing a name. The host must create a runtime
with a registered tool policy before `tool.call` or `tool.start` can succeed.

The v0.1 tool contract accepts string input and returns string output.
`tool.call` is synchronous. `tool.start` reserves the same capability and
returns an opaque promise; `await()` pauses the current script until the
trusted host delivers its result. For host-pump tools, one default
`CapabilityRuntime::pump` tick runs at most one tool; `pump_up_to` is
available for an explicitly bounded batch. The default pending-promise cap is
64 and may be lowered by an embedded host.

`ToolPolicy::json` opts a capability into a structured boundary. The input and
output must each be a JSON object or array. `call_json` and `start_json`
serialize the supplied Splash record or array, while their results remain JSON
strings that generated code must turn back into values with `parse_json()`.
This preserves a simple Rust bridge through `serde_json::Value` without
allowing scripts to import crates directly.

Hosts can register a `JsonToolContract` to enforce bounded schemas for those
JSON envelopes. Contract checks run before the handler and before output
returns to Splash; metadata-only schemas in the catalog do not enforce input
or output. The exact supported subset is defined in
[JSON tool contracts](schema-contracts.md).

The promise API is cooperative. It does not grant a script a thread, a task
runtime, or a way to invoke an adapter without the host's pump. Structured
values and streaming dataflow remain additive, versioned host APIs rather than
implicit VM effects.

An external-only tool is a separate deferred mode selected by the host. It
cannot be called synchronously and has no in-process handler. The host claims
the pending invocation, dispatches it through its own adapter, and completes
or cancels it later. This does not expose an external API to Splash source;
the script still sees only its promise. See [External tools](external-tools.md).

A host may configure a maximum deferred duration per tool. The duration starts
when start reserves the operation. The host uses expire_timed_out_tools from
its event loop to resolve due external work; pump also rejects expired local
queued work before its handler runs. This does not interrupt a Rust handler
that is already executing.

For external tools, retry policy is also owned by the host. Splash source has
no retry primitive: a host may make a bounded retry of an already claimed
operation, preserving its idempotency key, but that does not create another
script-visible call or grant new authority.

An external tool may also emit bounded progress chunks to the host after it is
claimed. Those chunks are optionally redacted by trusted Rust code and never
become a Splash value or a script-level stream; `await()` still resolves only
the terminal result. See [External tools](external-tools.md) for the host
streaming contract.

For a live claimed external operation, the host may use an authenticated worker
reconciliation request to observe `running` or apply a terminal result. This
is entirely outside the language: Splash source cannot see the operation key,
worker frame, status poll, or progress state. The host still validates a
terminal payload against the registered text/JSON contract before it resumes
`await()`. A reconciliation result does not restore a promise after a process
restart; durable workflow policy remains host-owned.

A runtime evaluates one script at a time. A host must resume a paused script
before evaluating new source on that runtime; independent workflows should use
separate runtime instances.

Workflow restart state is also host-owned. Splash source cannot create or load
a checkpoint, and a persisted checkpoint never restores variables, promises,
or tool authority. The host reconstructs a trusted plan and explicitly approves
the remaining suffix; see [Workflow checkpoints](workflow-checkpoints.md).
For uncertain external effects, a host may additionally keep a
[durable operation ledger](workflow-operations.md), but the script cannot read
or mutate its keys, input digest, worker observation, or restart policy.

## LLM generation rules

- Generate source only; do not add Makepad widget wrappers or `runsplash`
  fences when targeting the CLI/runtime.
- Import `mod.tool` before calling a tool.
- Treat a denied tool call as a runtime error. Do not retry by attempting
  filesystem, process, or network imports.
- Do not generate retry loops for external tools; the host applies its bounded
  retry policy and reports the final result through the existing promise.
- Do not assume external progress output is readable from Splash source; use
  the terminal promise result supplied by the host.
- Keep effectful work in named tools and pure transformations in Splash code.
- Generate against the host-supplied tool catalog only; descriptions and
  schemas do not grant access to unlisted tools.
- Await a deferred tool result before using it; do not assume `start` performs
  an effect until a host pump or external completion has delivered its result.
- Use record or array envelopes for JSON tools, then call `parse_json()` on
  their returned strings before reading fields.
