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
trusted host calls `CapabilityRuntime::pump`. One default pump tick runs at
most one tool; `pump_up_to` is available for an explicitly bounded batch. The
default pending-promise cap is 64 and may be lowered by an embedded host.

The promise API is cooperative. It does not grant a script a thread, a task
runtime, or a way to invoke an adapter without the host's pump. Structured
values, cancellation, external completion, and streaming dataflow are planned
as additive, versioned host APIs rather than implicit VM effects.

A runtime evaluates one script at a time. A host must resume a paused script
before evaluating new source on that runtime; independent workflows should use
separate runtime instances.

## LLM generation rules

- Generate source only; do not add Makepad widget wrappers or `runsplash`
  fences when targeting the CLI/runtime.
- Import `mod.tool` before calling a tool.
- Treat a denied tool call as a runtime error. Do not retry by attempting
  filesystem, process, or network imports.
- Keep effectful work in named tools and pure transformations in Splash code.
- Await a deferred tool result before using it; do not assume `start` performs
  an effect until the host has pumped the runtime.
