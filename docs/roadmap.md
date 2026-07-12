# Roadmap

## Baseline complete

- Standalone VM workspace with upstream provenance.
- Bounded evaluation and structured diagnostics.
- Deny-by-default, audited string-tool bridge.
- Bounded, host-pumped deferred tool promises.
- Host-owned plan, approval, and sequential workflow execution.
- Portable worker protocol with capability attenuation and bounded wire
  messages.

## Next: schema-validated and externally asynchronous tools

- JSON Schema or equivalent typed input/output contracts.
- Cancellable promise handles, external completion, and bounded concurrent
  work.
- Per-tool deadlines, retry classification, and idempotency keys.
- Streaming output with byte limits and redaction hooks.

## Next: contained local effects

- Per-platform containment backends for desktop and embedded Linux.
- Authenticated worker transports and contained-worker implementations.
- Filesystem-root, executable, and network-origin policies.
- Mobile profile with app-provided tools only.

## Before a stable language release

- Published grammar and formatter/LSP support.
- Fuzzing and resource-exhaustion coverage.
- Durable event storage, replay, checkpoints, and compensation actions.
- Independent security review of effectful adapters.
