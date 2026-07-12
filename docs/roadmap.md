# Roadmap

## Baseline complete

- Standalone VM workspace with upstream provenance.
- Bounded evaluation and structured diagnostics.
- Deny-by-default, audited string-tool bridge.
- Bounded, host-pumped deferred tool promises.
- Host-owned plan, approval, and sequential workflow execution.

## Next: structured and externally asynchronous tools

- Typed input/output schemas and JSON-compatible values.
- Cancellable promise handles, external completion, and bounded concurrent
  work.
- Per-tool deadlines, retry classification, and idempotency keys.
- Streaming output with byte limits and redaction hooks.

## Next: contained local effects

- A worker protocol with capability attenuation.
- Per-platform containment backends for desktop and embedded Linux.
- Filesystem-root, executable, and network-origin policies.
- Mobile profile with app-provided tools only.

## Before a stable language release

- Published grammar and formatter/LSP support.
- Fuzzing and resource-exhaustion coverage.
- Durable event storage, replay, checkpoints, and compensation actions.
- Independent security review of effectful adapters.
