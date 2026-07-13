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
- Host-only authenticated storage envelopes, key rotation, and a strict
  rollback-protected storage backend contract.
- Authenticated durable-operation dispatch frames and a bounded worker journal
  with input-drift rejection and tenant scope validation.
- Explicit, host-approved worker compensation intents with a separate bounded
  grant, exact grant fingerprint, one inverse effect per succeeded operation,
  and crash-safe worker-journal recovery.
- Worker-side capability runtime with explicit Rust adapter registration,
  fresh-session admission, durable journal ordering, bounded reconciliation,
  and indeterminate-effect recovery.
- Fenced rollback-protected storage extension and an authenticated worker
  journal-store bridge with scope, revision, and lease enforcement.
- Feature-gated anchored SQLite payload backend with bounded recovery of
  uncommitted candidates; it requires a host-provided rollback anchor.
- Feature-gated authenticated in-process worker transport for a fixed mobile
  or embedded adapter catalog, with authenticated ordinary-invocation framing
  but no containment.
- Feature-gated bounded JSON-line frame channel and authenticated ordinary-call
  transport for host-provided contained-worker I/O; it does not launch or
  sandbox a process.
- Linux Bubblewrap policy compiler and launcher for fixed workers and
  manifest-selected file roots. It fails closed for network-origin,
  executable, and secret selectors, and does not fall back to unrestricted
  process launch.

## Next: durable external operations

- Platform `RollbackAnchor` implementations with compare-and-swap and
  rollback protection, plus target-specific storage-key provisioning.

## Next: contained local effects

- Resource quota, seccomp, target-specific key-bootstrap, and cancellation
  policy around the Linux Bubblewrap launcher.
- Per-platform containment backends for macOS, Windows, mobile, and embedded
  Linux.
- A mediated origin-aware network policy, secret broker, and audited executable
  policy; they must remain denied until each can be enforced.
- Mobile profile with app-provided tools only.

## Before a stable language release

- Published grammar and formatter/LSP support.
- Fuzzing and resource-exhaustion coverage.
- Durable event storage, replay, and compensation actions.
- Independent security review of effectful adapters.
