# Roadmap

## Baseline complete

- Standalone VM workspace with upstream provenance.
- Bounded evaluation and structured diagnostics.
- Deny-by-default, audited string-tool bridge.
- Bounded, host-pumped deferred tool promises.
- Host-owned plan, approval, and sequential workflow execution.
- Portable worker protocol with capability attenuation and bounded wire
  messages.
- Stable host-side tool catalog with bounded LLM metadata.
- Bounded executable JSON input/output contracts for local and worker tools.
- External-only deferred tools with host claim, completion, cancellation, and
  bounded concurrent pending work.
- Per-tool deferred deadlines with host-driven expiration.
- Host-only bounded external retries with stable idempotency keys.
- Bounded, redactor-hooked external output streaming outside Splash source.
- Keyed, replay-checked worker frames and authenticated live-operation
  reconciliation.
- Bounded data-only workflow checkpoints with fresh host approval on resume.
- Plan-bound durable operation ledgers with input fingerprint checks, derived
  worker keys, and revision-watermark hooks.

## Next: durable external operations

- Authenticated durable storage adapters with compare-and-swap and rollback
  protection.
- Durable worker-side idempotency and compensation hooks.

## Next: contained local effects

- Per-platform containment backends for desktop and embedded Linux.
- Authenticated worker transports and contained-worker implementations.
- Filesystem-root, executable, and network-origin policies.
- Mobile profile with app-provided tools only.

## Before a stable language release

- Published grammar and formatter/LSP support.
- Fuzzing and resource-exhaustion coverage.
- Durable event storage, replay, and compensation actions.
- Independent security review of effectful adapters.
