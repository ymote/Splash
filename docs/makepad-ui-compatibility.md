# Makepad UI Compatibility

This repository keeps one small Makepad UI fixture at
[`examples/makepad_ui_counter.octoscript`](../examples/makepad_ui_counter.octoscript).
It is intentionally separate from the runnable workflow examples.

## Upstream examples

The current Makepad `dev` tree still has an `examples/octoscript` directory, but
that directory is a Rust Makepad application showcase rather than a standalone
Octoscript source file. A current substantive Octoscript source example is
[`examples/ddgo/app.octoscript`](https://github.com/makepad/makepad/blob/dev/examples/ddgo/app.octoscript).
Makepad's `Octoscript` widget evaluates a script body, supplies widget modules and
the `ui` handle, and renders the resulting widget tree; see its
[`widgets/src/octoscript.rs`](https://github.com/makepad/makepad/blob/dev/widgets/src/octoscript.rs)
host implementation.

The local counter fixture uses the same current UI conventions: declarations
before a `View`, `width: Fill`, `height: Fit`, named children, and `on_click`
closures that update a host-provided `ui` handle.

## What This Verifies

`makepad_ui_compatibility.rs` accepts the fixture through
`octoscript_core::check_vm_compatibility_named`, which applies the vendored parser
under explicit source, VM-token, and delimiter-nesting bounds without
evaluating it. It also asserts that normal `octoscript_core::check_syntax` rejects
the fixture. That is
intentional: the canonical v0.2 language is the narrow, bounded workflow
contract used by `octoscript-cli`, the capability runtime, and the language server.

The fixture is not a promise that this repository implements a Makepad UI
runtime. It does not execute through `octoscript-cli`, render widgets, install
`mod.prelude.widgets`, inject `ui`, or provide Makepad event-loop semantics.
Use it only with a Makepad UI host that supplies those bindings. The fixture
also is not an assertion of compatibility with every upstream Octoscript feature;
the vendored VM is intentionally smaller than a full Makepad checkout. In
particular, the standalone compatibility check rejects Makepad `@(index)`
host-value tokens because it does not accept a host value table.

## Boundary

Do not relax the canonical workflow grammar merely to accept UI syntax. Doing
so would make LLM-generated workflow source depend on an unbounded, host-owned
widget surface and blur the capability boundary. A future Makepad integration
should expose a distinct, trusted UI profile with its own host bindings,
resource limits, and integration tests.
