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
- Host-defined tools through `use mod.tool` and `tool.call(name, input)`.

Example:

```splash
use mod.tool

let summary = tool.call("text.echo", "summarize the release notes")
summary
```

## Effect rules

The core runtime does not install `mod.fs`, `mod.run`, or `mod.net`. A script
cannot acquire authority by importing a name. The host must create a runtime
with a registered tool policy before `tool.call` can succeed.

The v0.1 tool contract accepts string input and returns string output. It is
synchronous by design. Structured values, cancellable promises, and streaming
dataflow are planned as additive, versioned host APIs rather than implicit VM
effects.

## LLM generation rules

- Generate source only; do not add Makepad widget wrappers or `runsplash`
  fences when targeting the CLI/runtime.
- Import `mod.tool` before calling a tool.
- Treat a denied tool call as a runtime error. Do not retry by attempting
  filesystem, process, or network imports.
- Keep effectful work in named tools and pure transformations in Splash code.
