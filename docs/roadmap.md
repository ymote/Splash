# Roadmap

## Baseline complete

- Standalone VM workspace with upstream provenance.
- Bounded evaluation and canonical grammar diagnostics.
- Canonical source formatting that preserves comments and literal spellings.
- Host-only LSP diagnostics and full-document canonical formatting for the
  published v0.1 grammar.
- Effect-free top-level LSP document symbols derived from valid client source.
- Effect-free CLI top-level declaration outline for LLM and editor tooling.
- Bounded effect-free direct tool-call outline for LLM and operator
  pre-approval review; it is explicitly non-authoritative and backed by
  runtime leases.
- Bounded effect-free per-step workflow review that pairs syntax status with
  direct tool-call hints before ordered capability approval.
- Bounded, data-only versioned workflow-draft interchange and CLI review for
  LLM-generated step lists before a host creates a plan or issues authority.
- Approval-bound bounded JSON workflow dataflow with completed-prefix output
  binding, host-owned input/per-step output schema contracts, context and
  contract digest-only checkpoints, and a sealed mobile/embedded facade.
- Deny-by-default, audited string-tool bridge with a bounded in-memory audit
  view and explicit eviction count.
- Bounded, host-pumped deferred tool promises.
- Sealed static-catalog mobile and embedded profile for app-provided local
  adapters, with no post-build registration or external-dispatch API.
- Sealed mobile and embedded workflow facade for static local adapters, with
  named per-step policy approval and no mutable runtime escape.
- Host-owned plan, approval, and sequential workflow execution.
- Approval-bound, catalog-fingerprinted capability leases with dynamic-call
  enforcement across deferred continuation and workflow resume, including
  ordered per-step attenuation for LLM-generated plans and host-owned named
  policy bindings that issue those leases only at approval time.
- Portable worker protocol with capability attenuation and bounded wire
  messages.
- Stable host-side tool catalog with bounded LLM metadata and configurable
  aggregate descriptor-count and serialized-byte limits.
- Bounded executable JSON input/output contracts for local and worker tools.
- External-only deferred tools with host claim, completion, bounded concurrent
  pending work, and two-phase cooperative adapter cancellation that keeps the
  promise pending until host-confirmed acknowledgement.
- Per-tool deferred deadlines with host-driven expiration.
- Host-only bounded external retries with stable idempotency keys.
- Bounded, redactor-hooked external output streaming outside Splash source.
- Keyed, replay-checked worker frames and authenticated live-operation
  reconciliation.
- Bounded data-only workflow checkpoints with fresh host approval on resume.
- Bounded in-memory workflow event view with explicit eviction count; it is
  telemetry, never durable replay authority.
- Bounded authenticated durable workflow-event journals with sequenced export,
  exact retained replay checks, explicit retention loss, and optimistic-CAS
  persistence; they remain telemetry and cannot resume a workflow or prove an
  external effect.
- Plan-bound durable operation ledgers with input fingerprint checks, derived
  worker keys, revision-watermark hooks, and a two-stage
  prepare/persist/exact-claim bridge for live external workflow steps.
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
- Schema-required Serde host and worker bridges for statically linked,
  reviewed Rust adapters; JSON Schema remains the script-visible wire policy.
- Fenced rollback-protected storage extension and an authenticated worker
  journal-store bridge with scope, revision, and lease enforcement.
- Feature-gated anchored SQLite payload backend with bounded recovery of
  uncommitted candidates; it requires a host-provided rollback anchor.
- Feature-gated read-only native credential-store loading for pre-provisioned
  storage keys on macOS, iOS, and Windows; it never falls back to an
  in-process mock store or claims rollback protection.
- Feature-gated authenticated in-process worker transport for a fixed mobile
  or embedded adapter catalog, with authenticated ordinary-invocation framing
  but no containment.
- Feature-gated bounded JSON-line frame channel and authenticated ordinary-call
  transport for host-provided contained-worker I/O; it does not launch or
  sandbox a process.
- Feature-gated one-shot authenticated durable-operation transport for one
  fresh-session dispatch, reconciliation, or compensation exchange; it is
  bounded and verified but does not provide automatic recovery policy.
- Linux Bubblewrap policy compiler and launcher for fixed workers and
  manifest-selected file roots. It fails closed for network-origin,
  executable, and secret selectors, and does not fall back to unrestricted
  process launch.
- Versioned private-pipe session bootstrap for a compiled Linux Bubblewrap
  worker. It checks the manifest session before launch and never places the
  host-generated key in command-line arguments or environment variables.
- Optional bounded private `/tmp` capacity for Bubblewrap workers and a
  lifecycle handle that force-terminates and reaps a worker. Neither is a
  general resource quota or proof that an adapter effect was cancelled.
- Optional Bubblewrap user-namespace hardening that requires a usable user
  namespace and prevents further user namespace creation, with no compatibility
  fallback to a weaker worker policy.
- Optional fixed pre-exec Linux rlimit runner for worker CPU time, virtual
  address space, per-real-UID process threads, open file descriptors, and
  individual file size. It is not a cgroup quota or full containment policy.
- Optional Linux cgroup-v2 sessions for fixed Bubblewrap workers. A host-owned
  delegated parent supplies CPU bandwidth, memory, swap, task, and per-device
  I/O controllers; a fixed runner joins the fresh child before Bubblewrap
  starts, and managed lifecycle teardown uses `cgroup.kill` for the complete
  worker subtree.
- Optional Linux Bubblewrap `DenyKnownEscapeSurface` seccomp hardening profile
  with trusted cBPF transport, ABI/x32 checks, and a fixed default-allow deny
  set. It is defense in depth, not a worker-specific syscall allowlist.
- Optional host-selected Linux Bubblewrap strict seccomp allowlist with a
  bounded deterministic cBPF program, fixed escape-surface guards, and
  default-kill behavior for every unlisted syscall. It remains a
  target-specific syscall boundary, not executable-path or capability policy.
- Optional host-owned Bubblewrap watchdog plus generic bounded worker transport
  for nonzero per-invocation and spawn-anchored session-wide wall-clock
  deadlines. A timeout or trusted force-stop poisons the session and is
  indeterminate, never a cancellation acknowledgement or durable recovery
  result.

## Next: durable external operations

- Platform `RollbackAnchor` implementations with compare-and-swap and
  rollback protection. Native credential stores can protect storage keys but
  do not satisfy this anchor contract.

## Next: contained local effects

- Aggregate-disk quotas; authenticated in-band cancellation; and automatic
  durable post-stop recovery policy around the Linux Bubblewrap launcher.
- Per-platform containment backends for macOS, Windows, mobile, and embedded
  Linux.
- A mediated origin-aware network policy, secret broker, and audited executable
  policy; they must remain denied until each can be enforced.

## Before a stable language release

- Richer semantic editor features beyond top-level document symbols.
- Sustained parser/VM differential fuzzing, expanded resource-exhaustion
  coverage, and corpus triage.
- Centralized event retention/aggregation and product-specific compensation
  action policies.
- Independent security review of effectful adapters.
