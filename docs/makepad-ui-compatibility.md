# Makepad UI Compatibility

This repository keeps one small Makepad UI fixture at
[`examples/makepad_ui_counter.splash`](../examples/makepad_ui_counter.splash).
It is intentionally separate from the runnable workflow examples.

## Upstream examples

The current Makepad `dev` tree still has an `examples/splash` directory, but
that directory is a Rust Makepad application showcase rather than a standalone
Splash source file. A current substantive Splash source example is
[`examples/ddgo/app.splash`](https://github.com/makepad/makepad/blob/dev/examples/ddgo/app.splash).
Makepad's `Splash` widget evaluates a script body, supplies widget modules and
the `ui` handle, and renders the resulting widget tree; see its
[`widgets/src/splash.rs`](https://github.com/makepad/makepad/blob/dev/widgets/src/splash.rs)
host implementation.

The local counter fixture uses the same current UI conventions: declarations
before a `View`, `width: Fill`, `height: Fit`, named children, and `on_click`
closures that update a host-provided `ui` handle.

## What This Verifies

`makepad_ui_compatibility.rs` parses the fixture with the vendored
`makepad-script` parser. It also asserts that normal `splash_core::check_syntax`
rejects it. That is intentional: the canonical v0.2 language is the narrow,
bounded workflow contract used by `splash-cli`, the capability runtime, and the
language server.

The fixture is not a promise that this repository implements a Makepad UI
runtime. It does not execute through `splash-cli`, render widgets, install
`mod.prelude.widgets`, inject `ui`, or provide Makepad event-loop semantics.
Use it only with a Makepad UI host that supplies those bindings. The fixture
also is not an assertion of compatibility with every upstream Splash feature;
the vendored VM is intentionally smaller than a full Makepad checkout.

## Boundary

Do not relax the canonical workflow grammar merely to accept UI syntax. Doing
so would make LLM-generated workflow source depend on an unbounded, host-owned
widget surface and blur the capability boundary. A future Makepad integration
should expose a distinct, trusted UI profile with its own host bindings,
resource limits, and integration tests.
