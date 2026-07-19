# Roadmap

## Baseline complete

- Standalone VM workspace with upstream provenance.
- Bounded evaluation and canonical grammar diagnostics, including
  host-configurable per-string, tracked Splash-owned aggregate-heap,
  operand-stack, and active-call-frame ceilings.
- Canonical source formatting that preserves comments and literal spellings.
- Host-only LSP diagnostics and full-document canonical formatting for the
  published v0.2 grammar.
- Canonical cross-function `try/catch` recovery with contextual syntax, no
  script-visible error details, and uncatchable hard resource termination.
- Effect-free top-level LSP document symbols derived from valid client source.
- Bounded grammar-aware same-document lexical definition/reference navigation
  for imports and runtime-scope bindings, with explicit truncation and no URI
  reads, evaluation, type inference, or authority.
- Binding-kind hover and neutral same-document symbol highlights over the same
  bounded lexical index.
- Bounded scope-aware lexical completion at expression identifiers, including
  exact-token edits, conservative invalid-prefix support, independent site
  truncation, and fixed `mod.tool` method suggestions only for an exact visible
  import binding. A bounded, initialization-time or configuration-refresh
  advisory catalog projection can complete literal names in direct tool calls
  without a runtime/catalog lookup or authority inference; it performs no
  arbitrary module, type, or field inference. A separate bounded,
  initialization-time or configuration-refresh advisory module interface
  projection can complete direct `use mod.*` path segments and bounded catalog
  paths below a direct visible imported-module binding, and plainly hover an
  exact visible catalog leaf, without module loading, resolution, runtime
  export inspection, or authority inference.
- A bounded initialization-time or explicit configuration-refresh advisory
  workflow-data projection for direct, unshadowed `workflow.input.*` and
  `workflow.outputs.<stepId>.*` completion and hover. Its ordered step context
  filters outputs to a projected completed prefix and next projected step. The
  `splash-workflow` API can derive that complete pair from contract-bound data,
  a validated checkpoint, or exact suspended engine state without serializing
  values, source, approvals, leases, or schema source. The LSP itself remains
  advisory: it does not load schemas/checkpoints, validate values, approve a
  plan, or grant a capability. A complete JSON-null pair atomically clears
  terminal or unavailable metadata instead of retaining stale fields.
- Bounded direct literal-record field metadata for exact visible
  `let binding = { ... }` initializers, one exact direct `child: { ... }`
  literal level, and lexical exact `let alias = binding` chains of at most 16
  hops, with same-document completion, hover, and definition. It is advisory
  and does not infer parenthesized or computed aliases, parenthesized or
  computed child values, child aliases, deeper paths, assignments, control
  flow, imported values, function returns, or runtime types. Duplicate parent
  fields discard every child shape, and duplicate child fields discard that
  child shape. An earlier direct write or potentially mutating member, index,
  call, or escape path through the root or any retained direct alias suppresses
  it. Independent 1,024-root-shape and 4,096-aggregate-field caps mark retained
  completion incomplete; the 1,024-alias cap fails closed for omitted alias
  edges.
- Version-bound same-document rename with canonical identifier validation,
  import-path refusal, truncation refusal, and whole-report lexical drift
  detection.
- Effect-free CLI top-level declaration outline for LLM and editor tooling.
- Bounded effect-free direct tool-call outline for LLM and operator
  pre-approval review; it is explicitly non-authoritative and backed by
  runtime leases.
- Bounded effect-free per-step workflow review that pairs syntax status with
  direct tool-call hints before ordered capability approval.
- Bounded, data-only versioned workflow-draft interchange and CLI review for
  LLM-generated step lists before a host creates a plan or issues authority.
- Machine-readable JSON Schema producer contract for the data-only workflow
  draft envelope, with explicit wire, aggregate-source, and unique-step-ID
  limits and no policy-bearing fields.
- Approval-bound bounded JSON workflow dataflow with completed-prefix output
  binding, host-owned input/per-step output schema contracts, context and
  contract digest-only checkpoints, and a sealed mobile/embedded facade.
- Deny-by-default, audited string-tool bridge with a bounded in-memory audit
  view, contiguous cursor-safe host export, explicit eviction count, and an
  opt-in authenticated durable audit journal for host-owned replay.
- Bounded, host-pumped deferred tool promises.
- Bounded host-owned fixed-file catalog capability for descriptor-pinned,
  regular UTF-8 text files selected at setup and addressed only by opaque IDs;
  it is not an ambient filesystem API or operating-system containment.
- Feature-gated bounded fixed HTTP endpoint catalog for host-selected JSON GET
  and POST calls addressed by opaque IDs, with executable request-shape
  validation, HTTPS by default, disabled proxies and redirects, and bounded
  request input, headers, response bodies, and deadlines. Host-held bounded
  credentials can be resolved only into one fixed HTTPS endpoint through an
  opaque setup-selected reference. A separate feature-gated resolver can read
  one exact pre-provisioned value per binding from explicit native macOS, iOS,
  or Windows credential stores without an in-process mock fallback. It is
  API-level mediation only, not a general secret broker, dynamic origin
  policy, or operating-system egress boundary.
- Feature-gated bounded exact-origin HTTP catalog for host-selected JSON GET
  and POST methods. Script source can supply a bounded complete URL only after
  exact scheme, host, and effective-port matching against an opaque configured
  origin; proxies and redirects remain disabled, and host-selected credentials
  resolve only after matching. Dynamic paths and queries are intentional data,
  not path-prefix authorization. It is API-level mediation only, not DNS
  pinning or operating-system egress containment.
- Bounded worker-side capability secret-broker contract. A host-owned provider
  can release a bounded zeroizing binary secret only to one exact configured
  `(tool, secret-id)` binding whose active worker grant includes that opaque
  `Secret` resource; generated source has no lookup or enumeration API. It is
  not a platform credential store, secret-delivery sandbox, or OS boundary.
- Sealed static-catalog mobile and embedded profile for app-provided local
  adapters, with no post-build registration or external-dispatch API.
- Sealed mobile and embedded workflow facade for static local adapters and
  setup-only direct capability modules, with named per-step policy approval
  and no mutable runtime escape.
- Host-owned plan, approval, and sequential workflow execution.
- Approval-bound, catalog-fingerprinted capability leases with dynamic-call
  enforcement across deferred continuation and workflow resume, including
  ordered per-step attenuation for LLM-generated plans and host-owned named
  policy bindings that issue those leases only at approval time.
- Portable worker protocol with capability attenuation, fixed 128-grant
  session-manifest and 1,024 retained-request-identity ceilings, and bounded
  wire messages plus instance-bound in-process authorization tokens.
- Stable host-side tool catalog with bounded LLM metadata and configurable
  aggregate descriptor-count and serialized-byte limits.
- Bounded executable JSON input/output contracts for local and worker tools.
- External-only deferred tools with host claim, completion, bounded concurrent
  pending work, and two-phase cooperative adapter cancellation that keeps the
  promise pending until host-confirmed acknowledgement.
- Per-tool deferred deadlines with host-driven expiration.
- Host-only bounded external retries with stable idempotency keys.
- External deferred-tool registration fails closed when operating-system
  entropy is unavailable. A host may explicitly provide a bounded session
  nonce with a documented cross-restart uniqueness scope; Splash never falls
  back to time/PID-derived downstream idempotency keys.
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
- Bounded host-receipt-order cross-stream aggregation of named capability-audit
  and workflow-event source segments, with exact cursors, explicit source and
  aggregate retention gaps, plus an authenticated durable aggregate journal
  that persists source-segment state and receipt order without creating
  recovery or capability authority.
- Plan-bound durable operation ledgers with input fingerprint checks, derived
  worker keys, revision-watermark hooks, and a two-stage
  prepare/persist/exact-claim bridge for live external workflow steps.
- Host-only authenticated storage envelopes, key rotation, and a strict
  rollback-protected storage backend contract.
- Authenticated durable-operation dispatch frames and a bounded worker journal
  with input-drift rejection and tenant scope validation.
- Explicit, host-approved worker compensation intents with a separate bounded
  grant, exact grant fingerprint, one inverse effect per succeeded operation,
  crash-safe worker-journal recovery, and a product-owned action verifier that
  rechecks the exact inverse payload before hardened intent recording,
  approval, and worker-frame sealing. It does not define a universal inverse
  action or automatic rollback policy.
- Worker-side capability runtime with explicit Rust adapter registration,
  fresh-session admission, durable journal ordering, bounded reconciliation,
  and indeterminate-effect recovery.
- Schema-required Serde host and worker bridges for statically linked,
  reviewed Rust adapters; JSON Schema remains the script-visible wire policy.
- Setup-only bounded flat direct capability modules for existing
  contract-enforced JSON tools. A host chooses each method as synchronous over
  a host-pump adapter or deferred through the existing bounded promise path;
  either form routes through the same target-tool policy, audit, JSON boundary,
  and capability lease, returning decoded bounded JSON immediately or from
  `await()`. A bounded scope-resolved advisory review projection can map an
  exact visible direct facade call back to its underlying target tool and mode
  without issuing authority. Its advisory LSP interface projection carries the
  same mode as an exact-leaf `callMode` label without inserting source or
  authorizing a call. The reviewed module-to-tool mapping and method mode are
  part of the catalog fingerprint recorded by each lease, and the interface
  seals before lease issuance or evaluation. It does not add module loading,
  dynamic Rust crate access, or ambient operating-system authority.
- Fenced rollback-protected storage extension and an authenticated worker
  journal-store bridge with scope, revision, and lease enforcement.
- Feature-gated anchored SQLite payload backend with bounded recovery of
  uncommitted candidates; it requires a host-provided rollback anchor.
- Bounded transactional rollback-anchor service protocol with an embeddable
  server-side dispatcher, bounded exact caller/operation/record authorization
  gate, and optional fixed HTTPS client transport, canonical `u64` wire values,
  bounded exchange, generic diagnostics, and process-lifetime state-regression
  detection. The separately deployed service remains the rollback-resistant CAS
  authority.
- Feature-gated read-only native credential-store loading for pre-provisioned
  storage keys on macOS, iOS, and Windows; it never falls back to an
  in-process mock store or claims rollback protection.
- Feature-gated authenticated in-process worker transport for a fixed mobile
  or embedded adapter catalog, with authenticated ordinary-invocation framing
  but no containment.
- Feature-gated bounded JSON-line frame channel and authenticated ordinary-call
  transport for host-provided contained-worker I/O; it does not launch or
  sandbox a process.
- Protocol v5 authenticated cooperative cancellation for one active ordinary
  invocation, with strict request/target identity, directional ordering,
  positive acknowledgement, result-wins `too_late`, and nonterminal
  `unsupported` semantics.
- Feature-gated cancellable worker driver and multiplexed host JSON-line
  transport. Only explicitly registered cancellable Rust adapters can use the
  path; normal synchronous and durable adapters remain excluded.
- Session-bound process-supervision bridge that arms before dispatch and
  resolves deadline/termination races before applying worker events, plus a
  workflow completion sink that preserves suspended-step state.
- Feature-gated one-shot authenticated durable-operation transport for one
  fresh-session dispatch, reconciliation, or compensation exchange; it is
  bounded and verified but does not provide automatic recovery policy.
- Linux Bubblewrap policy compiler and launcher for fixed workers and
  manifest-selected file roots. It fails closed for executable and secret
  selectors, and for network-origin selectors unless an exact private Linux
  HTTP broker is configured; it does not fall back to unrestricted process
  launch. It unconditionally drops every Linux capability before the worker
  executes, including when the host invokes Bubblewrap as root.
- Optional Linux host-owned Unix-socket HTTP broker for an isolated Bubblewrap
  worker. It derives a bounded exact network-origin ID set from the manifest,
  requires a reviewed fixed-endpoint or exact-origin catalog with exactly that
  set, creates one CSPRNG-named private socket directory, and mounts it
  descriptor-pinned and read-only while retaining Bubblewrap's isolated network
  namespace. It is HTTP-only aggregate per session authority, not a general
  proxy, per-tool OS isolation, durable-effect mechanism, or portable network
  backend.
- Optional per-policy launch requirements for a typed resource-limit runner
  and a cgroup-v2-backed launch. A missing required runner rejects compilation,
  and a cgroup-required compiled command rejects uncgrouped launch APIs rather
  than silently dropping its selected controller boundary.
- Optional Linux descriptor-pinned Bubblewrap mount roots. After successful
  compilation, runtime and host-backed file-root bindings use launch-only
  `--ro-bind-fd` or `--bind-fd` handles with no path-bind fallback, preventing
  replacement of the selected mount root. This does not freeze mutable
  descendants, runtime contents, or the Bubblewrap executable.
- Optional Linux descriptor-pinned fixed executable identity. Together with
  descriptor-pinned runtime roots, Bubblewrap is executed through its retained
  launch-only descriptor; fixed worker, resource-limit-runner, Landlock runner,
  and explicit Landlock executable targets are retained and overlaid at their
  exact worker paths; and a cgroup runner is pinned immediately after fresh
  cgroup preparation. It does not freeze shared libraries, runtime contents, or
  provide complete code-loading mediation.
- Versioned private-pipe session bootstrap for a compiled Linux Bubblewrap
  worker. It checks the manifest session before launch and never places the
  host-generated key in command-line arguments or environment variables.
- Optional bounded private `/tmp` capacity for Bubblewrap workers and a
  lifecycle handle that force-terminates and reaps a worker. Neither is a
  general resource quota or proof that an adapter effect was cancelled.
- Manifest-selected bounded ephemeral `file_root` mounts at arbitrary
  host-configured worker paths, with common overlap validation. Active
  persistent host-backed writable roots fail closed by default. On Linux, a
  host can attach a verified generic filesystem project quota to a
  descriptor-pinned root and set an aggregate hard byte and inode maximum;
  Splash validates the project ID, inheritance flag, nonzero hard limits,
  current usage, configured ceilings, and distinct `(filesystem, project ID)`
  aggregate before Bubblewrap receives the same retained root descriptor. A
  selected verified quota root also requires mandatory further-user-namespace
  lockdown so an owning worker cannot retag its directory in the initial user
  namespace. The host provisions and retains control of the quota. The old explicit
  unbounded-write acknowledgement remains only as a visible weaker escape
  hatch for an external boundary Splash cannot inspect. An opt-in stricter
  policy rejects unverified persistent roots and an unbounded private `/tmp`,
  requires further-user-namespace lockdown, and remounts the namespace root,
  `/proc`, and `/dev` read-only; it accepts verified project-quota roots. Each
  ephemeral mount has a kernel-enforced `tmpfs` data-block ceiling; an optional
  policy rejects a selected set of bounded tmpfs mounts whose potential
  aggregate capacity exceeds a host maximum. The mounts still have independent
  runtime ceilings rather than a shared tmpfs quota, have no independent inode
  cap, and are neither durable storage nor an executable-path policy. A worker
  plan defaults to 64 unique active file-root selectors; trusted configuration
  can lower that bound, including to zero, or explicitly raise it only to the
  fixed 256-root maximum, constraining mount-plan expansion before source
  resolution.
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
- Optional Linux Landlock filesystem-backed executable allowlist runner. It
  hard-requires a fully enforced `LANDLOCK_ACCESS_FS_EXECUTE` ruleset for exact
  host-reviewed worker-visible files, has no unsupported-kernel or direct-worker
  fallback, and inherits to worker descendants. It does not control dynamic
  loader reads, plugin/JIT code loading, special filesystems, networking,
  credentials, or capability grants. A strict seccomp allowlist is staged by
  this fixed runner after Landlock setup and descriptor cleanup, immediately
  before its fixed inner exec.
- Optional host-selected Linux Bubblewrap strict seccomp allowlist with a
  bounded deterministic cBPF program, fixed escape-surface guards, and
  default-kill behavior for every unlisted syscall. It remains a
  target-specific syscall boundary, not executable-path or capability policy.
- Optional host-owned Bubblewrap watchdog plus generic bounded worker transport
  for nonzero per-invocation and spawn-anchored session-wide wall-clock
  deadlines. A timeout or trusted force-stop poisons the session and is
  indeterminate, never a cancellation acknowledgement or durable recovery
  result.
- Feature-gated Bubblewrap post-stop recovery coordinator with exact compiled
  manifest binding, a session-bound reaping proof, fresh OS-generated session
  key, optional preserved cgroup-v2 policy, one watchdog-bounded authenticated
  reconciliation, and fenced authenticated host-ledger compare-and-swap. It
  never redispatches an ambiguous effect, selects compensation, or resumes a
  workflow.

## Next: durable external operations

- Platform and offline `RollbackAnchor` implementations with compare-and-swap
  and rollback protection, plus a deployment of the transactional service
  protocol. Native credential stores can protect storage keys but do not
  satisfy this anchor contract.

## Next: contained local effects

- Persistent-storage quota coverage beyond verified Linux generic project
  quotas: other filesystems, macOS, Windows, mobile, embedded Linux, and
  device-level quotas. Bounded ephemeral file roots cover scratch output beyond
  `/tmp`, with an optional aggregate potential-capacity check, but still do not
  provide a shared tmpfs runtime quota or portable durable-storage boundary.
- Per-platform containment backends for macOS, Windows, mobile, and embedded
  Linux.
- Network containment beyond the Linux broker-backed HTTP catalogs: per-tool
  OS separation, arbitrary non-HTTP protocols, DNS/firewall policy, macOS,
  Windows, mobile, and embedded implementations. Target-specific
  credential-provider and secret-delivery backends, plus a complete audited
  code-execution policy beyond Landlock's filesystem-execute action, also
  remain. The exact-origin catalog alone still mediates only Splash-initiated
  HTTP requests, and the worker secret broker deliberately mediates only a
  reviewed adapter's host-owned resolver; broader selectors must remain denied
  until each is enforced.

## Before a stable language release

- Additional semantic editor features beyond lexical completion, fixed
  `mod.tool`, bounded direct literal/direct-alias record fields,
  catalog-backed chained lookup from a visible imported-module binding, and
  direct advisory workflow-data fields. General module resolution and broader
  type-aware field semantics remain open.
- Sustained parser/VM differential fuzzing, LSP document lifecycle fuzzing,
  expanded resource-exhaustion coverage, and corpus triage.
- Independent security review of effectful adapters.
