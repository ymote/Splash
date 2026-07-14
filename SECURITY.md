# Security Model

Splash treats generated scripts, tool descriptions, and tool inputs as
untrusted. The runtime has two separate security boundaries:

1. The language boundary exposes no ambient filesystem, process, network, or
   platform APIs. Scripts can reach a tool only through `tool.call` or an
   explicitly host-controlled `tool.start(...).await()` promise.
2. The execution boundary must contain any adapter with OS effects. The current
   Linux Bubblewrap backend launches a dedicated worker with a narrowly scoped
   filesystem policy; other desktop, mobile, and embedded targets still need
   their own platform-specific containment backend.

The canonical Splash profile is an effect-free preflight in front of the
vendored Makepad parser. A profile rejection never reaches that parser or a
host binding; a profile acceptance is then independently parsed by the VM
before evaluation. The runtime carries executable canonical-fixture regression
coverage, but the two parsers are not formally proven equivalent. Parser/VM
differential fuzzing is required before a stable language release.

`splash-lsp` is a host-only helper for a trusted local editor client. It never
reads a document URI, evaluates source, creates a capability host, or loads an
adapter. It retains at most 128 document states and no source text larger than
the canonical 256 KiB limit, but the underlying LSP framing layer decodes an
inbound message before that retention limit applies. Do not expose its stdio
transport to a hostile peer or describe it as an IPC resource sandbox; place a
separate bounded transport or operating-system boundary in front of such a
peer.

`splash-protocol` defines the portable, attenuated handoff from a policy host
to a contained worker. It validates manifests, request uniqueness, formats,
byte limits, and call budgets. Its `SessionAuthenticator` can also bind each
worker frame to a host-provisioned BLAKE3 session key, directional role, and
strict sequence number, rejecting tampering, reflection, and replay before a
message is used. Its private-pipe bootstrap can carry that already-generated
key and session ID once to a newly launched worker, but it does not generate or
protect the key, establish an exchange, attest a worker, encrypt transport, or
enforce an operating-system policy itself. The host must provide a trusted
bootstrap channel and containment backend before an effectful adapter is
considered contained.

`splash-worker` is the worker-side implementation of that protocol boundary.
It accepts only an explicitly registered Rust adapter for a granted capability,
requires host admission to bind a fresh authenticated session to its tenant
journal scope, and persists durable intent before an adapter effect through a
monotonic compare-and-swap journal revision and a current host-issued fencing
lease. The scope is host-selected and the admission boundary must validate the
session/scope tenant binding together; a store rejects leases from superseded
workers. It restores its in-memory journal and poisons the session when
persistence fails; a post-effect failure also returns an indeterminate error
and requires a fresh authenticated reload before bounded reconciliation or
adapter-specific recovery. A duplicate pending operation remains pending and
an exact durable key is bound to its canonical tool input, so changed input
fails closed. It does not isolate adapters: embedding it in the interpreter
process, a mobile app, or an unrestricted service leaves it with that process's
ambient authority. Its journal-store trait is a contract, not a file/database
implementation or anti-rollback mechanism.

`AuthenticatedWorkerJournalStore` connects the runtime to
`AuthenticatedStore` plus `FencedRollbackProtectedStore`. It authenticates the
journal bytes and binds each write to a record key, current revision, scope,
and fencing token, but it inherits the backend's durability and anti-rollback
guarantees. `VolatileMemoryStore` covers integration tests only and must never
be treated as a production worker journal backend.

The bridge derives its record key from a host-owned namespace and journal
scope. A new admission must atomically reserve a nonzero token through the
backend or an equivalently durable lease service; never calculate a token from
`current_fence + 1` after a separate read. Fence state and data must share the
same record key, and the backend must revalidate exact token equality in its
atomic compare-and-swap. Provision an `AuthenticatedStore` key only to the
trusted storage coordinator or a narrowly scoped storage client. Do not place
a general storage key in an untrusted contained adapter process merely because
that process hosts a worker session. The bridge intentionally exposes no
general-purpose authenticated-store handle or caller-selected record key. The
host admission authority must reserve a fence for this exact bridge record;
the runtime cannot infer a record binding from a raw `u64` token.

The optional `AnchoredSqliteStore` persists payload candidates locally but
accepts them only when a host `RollbackAnchor` has committed their revision,
content hash, and fence. SQLite is not that anchor and does not become one by
being opened with durable settings. A real anchor must be linearizable and
survive both its own failover and local-database rollback. All writers must
share that anchor and one SQLite file. Host recovery after an anchor outage
must stop new admissions, reserve a fresh opaque recovery fence, then discard
only unanchored candidates through the backend API. Never recover by deleting
the SQLite file or by rebuilding anchor state from it.

Worker adapters must explicitly declare read-only/idempotent safety before the
non-durable `invoke` path is enabled, and a bounded reconciliation contract
before durable dispatch or compensation is enabled. A declaration is a trusted
Rust-code review obligation, not proof of external exactly-once behavior. A
durable adapter must recover status by the host operation key and pass that key
to a provider idempotency mechanism when one exists. The runtime's ordering
prevents a duplicate adapter invocation for an existing journal key, but it
cannot make an external provider idempotent or queryable.

`ProtocolWorkerClient` connects that validation layer to a host-owned
`WorkerTransport`; its registration rejects a local policy that is broader than
the worker grant. This still does not make an in-process transport isolated.
The optional `InProcessAuthenticatedWorkerTransport` authenticates every
ordinary worker invocation in-process, but it is only suitable for a static,
trusted mobile or embedded adapter catalog. It confers no OS, memory, process,
or resource containment; the adapter retains all authority of the embedding
application. Do not use it to run untrusted local-tool workloads.

`mobile::MobileRuntimeBuilder` is a narrower direct-adapter profile for mobile
and embedded hosts. It accepts only app-provided local adapters during setup;
consuming `build()` yields a runtime with no registration, external claim,
external completion, or worker-transport API. JSON adapters must carry an
executable input/output `JsonToolContract`, so structured script data remains
validated at the Rust boundary. This seals the catalog exposed through that
profile, not the embedding application's Rust authority: a host can still
choose a lower-level runtime, and every registered adapter retains the app's
ambient authority. It must not expose an arbitrary executable, filesystem,
network-origin, plugin, or crate selector. `collect_garbage()` is host-scheduled
and may cost time proportional to the live VM heap; it is not a per-pump
resource limit or containment mechanism.

The optional JSON-line worker channel carries one bounded authenticated frame
at a time over host-provided I/O. It limits a line to 1 MiB before decoding and
poisons the channel after any write, flush, read, decode, size, or framing
failure; the authenticated call transport likewise poisons itself after an
invalid or unexpected worker response. A host must discard that session rather
than retrying on the stream. This is protocol robustness, not containment: the
host still owns trusted key provisioning, cancellation semantics, child
lifecycle, and the platform sandbox that restricts the worker's OS authority.
The optional Bubblewrap watchdog can enforce host-selected wall-clock force
stops for one synchronous transport invocation and for a whole worker session
measured from spawn, but it is not an authenticated cancellation
acknowledgement or effect-recovery decision.

`splash-sandbox::bubblewrap` is the first such platform sandbox integration.
It accepts only a fixed host-selected worker executable and fixed arguments,
constructs a fresh Bubblewrap mount namespace, clears the worker environment,
creates a new session, binds the worker to its parent lifecycle, and mounts
only read-only runtime paths plus active manifest-selected `file_root`
directories. It uses `--unshare-all` and never emits `--share-net`, so it does
not retain the host network namespace. It rejects `network_origin`,
`executable`, and `secret` selectors because this backend cannot correctly
enforce them. It also rejects overlapping or root mounts and requires the
worker program to live in a read-only runtime mount, avoiding a writable grant
as an executable source. Hosts that explicitly select
`require_no_further_user_namespaces` also get Bubblewrap's mandatory
`--unshare-user --disable-userns` sequence, which prevents the worker from
creating further user namespaces. That mode has no compatibility fallback and
will fail on unsupported, setuid, or user-namespace-restricted hosts; it does
not mean Bubblewrap never created an internal nested namespace.

`BubblewrapCommand::spawn_with_bootstrap` additionally checks that the private
bootstrap session matches the compiled manifest before launch, then writes the
versioned preamble to the dedicated child stdin pipe. A failed write kills and
reaps the child. This avoids exposing the key in argv or environment variables,
but it is transfer only: it does not provide key exchange, encryption,
attestation, or key storage.

For Linux deployments with a host-owned delegated cgroup-v2 parent,
`CgroupV2Policy` can be used with `BubblewrapCommand::spawn_in_cgroup` or
`spawn_with_bootstrap_in_cgroup`. The policy creates a fresh child, applies
selected `cpu.max`, `memory.max`, `memory.swap.max`, `pids.max`, and per-device
`io.max` controls, and starts a fixed host-side runner. The runner moves itself
into that child before it executes Bubblewrap. Splash observes the direct child
in `cgroup.procs` before it returns a managed worker handle, so lifecycle
teardown cannot race a runner that has not yet joined the cgroup. The cgroup
path and I/O device identifiers are never Splash values, worker protocol
fields, or Bubblewrap arguments.

The host must enable and delegate the required controllers under a dedicated
parent before launch. Splash verifies the parent is mounted from cgroup v2 and
deliberately does not modify
`cgroup.subtree_control`, because changing a shared parent can affect unrelated
workloads. The policy fails before launch when a selected controller or
`cgroup.kill` is unavailable. The runner is trusted host code, must remain
immutable to untrusted actors, and is not mounted into the worker runtime.

For a managed cgroup-backed worker, explicit termination, watchdog expiry, and
bootstrap failure call `cgroup.kill` before reaping the direct Bubblewrap
process. This covers the worker cgroup subtree, including descendant forks,
where `Child::kill` alone would not. A cgroup cleanup or kill failure is a
containment failure, not a successful cancellation result. `memory.max` is a
memory-cgroup boundary rather than an RSS-only metric; Splash additionally sets
`memory.oom.group=1` when it selects that control. `memory.swap.max=0` prevents
anonymous memory in the worker cgroup from being swapped out. `io.max` bounds
selected BPS and IOPS classes for one trusted block-device `major:minor`
identity, but it is not a filesystem quota. `pids.max` counts tasks, including
threads, and `cpu.max` is CPU
bandwidth rather than a wall-clock deadline. The [Linux cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
defines the kernel semantics.

Hosts may additionally select the typed
`WorkerSeccompProfile::DenyKnownEscapeSurface`. Splash generates a fixed cBPF
program and transfers it over an anonymous launch-only descriptor to
Bubblewrap, which consumes and closes that descriptor before it attaches the
filter immediately before worker execution. The profile verifies the syscall
ABI, kills an x86-64 x32 ABI attempt, rejects mount and namespace construction,
known kernel-control interfaces, tracing/cross-process-memory calls, keyrings,
`personality`, and `TIOCSTI`. Bubblewrap requires `no_new_privs` before it
installs this filter, so a worker can add only stricter seccomp constraints. It
is intentionally default-allow for dynamic-worker
compatibility: it permits `execve`, does not constrain arbitrary future or
unlisted syscalls, and is neither a capability mechanism nor a complete
syscall sandbox. The profile can return `ENOSYS` for `clone3` to force a legacy
`clone` fallback with namespace flags checked, which may be incompatible with
a particular worker. See [`docs/linux-bubblewrap.md`](docs/linux-bubblewrap.md)
for the exact supported architectures, denied operations, and limitations.

An optional host-configured `splash-limit-runner` can execute the fixed worker
only after applying selected Linux rlimits and disabling core dumps. The runner,
limits, worker target, and worker arguments are all compiled from trusted Rust
policy; Splash source and tool data cannot control any of them. It must be a
distinct executable in a read-only runtime mount, and a setup or `exec` failure
does not fall back to direct worker execution. The host still must reject a
failed authenticated worker startup because Bubblewrap spawn alone does not
prove that the runner applied its limits.

Before it executes the worker, the bundled runner marks every descriptor from
3 onward close-on-exec. The launcher's standard streams are explicitly
configured as private input/output pipes and null stderr, so this prevents a
nonstandard host descriptor inherited through Bubblewrap from becoming worker
authority. It does not make the standard streams secret: the worker protocol
and host logging policy must still treat their contents as sensitive.

The optional rlimits remain narrow per-process controls, not a replacement for
the cgroup profile: CPU is cumulative time, address space is virtual memory,
open files are file descriptors, and file size is per created file.
`RLIMIT_NPROC` is per-real-UID thread accounting, can include unrelated
processes, and is not enforced for real UID 0 or a process with
`CAP_SYS_ADMIN` or `CAP_SYS_RESOURCE`. Hard limits prevent an unprivileged
worker from raising them, but a process with `CAP_SYS_RESOURCE` in the initial
user namespace can do so. Do not describe rlimits as a worker-tree process
limit, RSS ceiling, aggregate disk quota, wall-clock deadline, seccomp policy,
cancellation mechanism, or complete sandbox. Use a cgroup policy and dedicated
non-root sandbox identity where the available cgroup properties are required.

`RLIMIT_CPU` does not bound a sleeping or blocked worker. A host using the
optional `BubblewrapWorkerWatchdog` through `BoundedWorkerTransport` can arm a
nonzero trusted wall-clock deadline for one synchronous transport invocation.
`BubblewrapWorkerSessionDeadline` can separately force-stop a whole worker
session from its spawn time, including idle time. The watchdog owns the child
in a separate host thread, force-stops and reaps it on either expiry, and
treats a response race as indeterminate. It is not authenticated in-band
cancellation and does not establish whether an adapter effect occurred. A host
that does not use the watchdog must independently schedule lifecycle
termination on a monotonic timer, discard the session, and reconcile any
durable effect. The runner does not implement that timer or a worker
cancellation acknowledgement.

An explicit private `/tmp` can have a Bubblewrap `--size` allocation ceiling.
That bounds only this tmpfs mount and must not be described as a process-memory,
CPU, process-count, or general disk quota. After transport pipes move out of
the startup handle, `BubblewrapWorkerLifecycle::terminate` force-terminates and
reaps the worker. It is process control only: the host must drop the session and
reconcile a durable effect rather than infer that process termination cancelled
or rolled it back.

Bubblewrap is a low-level sandbox constructor, not a complete security policy.
This backend has no worker-specific syscall allowlist, aggregate-disk or device
quota, per-origin network proxy, D-Bus mediation, secret broker, authenticated
cancellation delivery, or post-exit recovery. Its optional watchdog supplies
only trusted wall-clock process stops described above, its optional runner
provides only the narrow rlimits described above, and its cgroup profile
supplies only the CPU, memory, swap, task, and selected per-device I/O controls
described above. The per-device I/O control is neither a filesystem quota nor a
guarantee that buffered writeback will be attributed to the worker on every
filesystem.
`DenyKnownEscapeSurface` provides only the fixed default-allow hardening
described above. A private `/tmp` is opt-in and unbounded unless the host
selects its explicit Bubblewrap size limit; that limit does not replace a
memory or disk policy. Its filesystem boundary is per worker session, not per
individual invocation: an attenuated manifest should be narrowed before launch
when per-call filesystem isolation is required.
Policy source paths must be host-owned and immutable to untrusted actors from
compilation through worker exit, including their executable and symlink
targets; the current path-based launcher cannot eliminate that race. A fixed
worker program also does not prevent a compromised worker from executing or
reading other files deliberately exposed through a runtime mount; runtime
mounts must remain minimal and immutable. On a failure it does not fall back to
an unrestricted worker. See
[`docs/linux-bubblewrap.md`](docs/linux-bubblewrap.md) before enabling it for
untrusted local effects.

Each registered tool declares a stable identifier and limits for calls, input
bytes, and output bytes. Calls are recorded in an ordered audit log. Unknown,
over-budget, over-depth, or malformed calls fail before a tool handler is
invoked.

JSON capabilities are an explicit policy type. They accept only JSON object or
array envelopes: envelope validation happens before the Rust handler is called,
and before a result is returned to Splash. `JsonToolContract` adds an
executable, bounded schema subset at the same boundary. Input contract failure
does not invoke a handler or consume a call; output contract failure does not
reach Splash. This is a data contract, not a way to deserialize arbitrary Rust
types or grant a script access to a crate. The typed Serde bridge requires a
`JsonToolContract` and validates that contract before input deserialization and
after output serialization; a Rust struct is never the authoritative policy.

Host-pump deferred tool promises are bounded per runtime and run only when the
trusted host calls `CapabilityRuntime::pump`; one default pump tick processes
at most one tool. Hosts may choose a bounded batch with `pump_up_to`. They
are cooperative scheduling, not a threading or isolation mechanism. A paused
script with no runnable capability work must be resumed by a host that
understands the relevant suspension source. A settled promise record remains
until it is unreachable and the trusted host calls
`CapabilityRuntime::collect_garbage()` at a suitable idle point. Collection is
not implicit in `pump()` because a full VM sweep can take time proportional to
the live heap.

External-only tools add a host-managed completion path. They have no
in-process handler and are denied to synchronous calls. A trusted host claims
each operation, then explicitly completes or cancels it; the runtime reuses
the normal output validation and audit boundary. This does not terminate a
worker or enforce an operating-system policy. The host must bind cancellation
to its transport and enforce containment outside this process.

External retries are also host-only. A script receives no retry API and cannot
spend another capability call by requesting another attempt. For each claimed
operation, the host may use its stable `idempotency_key` when forwarding an
attempt to a worker. That key is a correlation and deduplication value, not a
capability token or authorization credential; the opaque `ExternalToolId`
must remain owned by the host. Hosts that need replay across restarts must
persist their own workflow identity and authenticate every worker request with
the keyed protocol frame or an equivalent transport mechanism. An adapter must
not retry a non-idempotent effect unless its worker performs deduplication
using that key or an equivalent durable identity.

Authenticated reconciliation can query a live claimed operation without
serializing its `ExternalToolId`. `CapabilityRuntime` creates an authenticated
request carrying only the session, tool, request ID, and operation key, then
opens a matching worker response before it applies `running`, `succeeded`,
`failed`, or `cancelled`. The result must match both that request and the
currently claimed operation; a successful payload also passes through the
existing output limit and JSON-contract boundary. This does not make a
promise, operation handle, or VM state restartable. A durable host workflow
must persist and authenticate its own operation identity, then decide whether
to reconcile, retry, compensate, or fail before it constructs a fresh runtime.

An external tool may opt into bounded host-visible output chunks. The runtime
accepts chunks only for a claimed operation, applies source-byte, aggregate,
and post-redaction limits, and returns only the redacted text to the host.
Chunks are not installed as a Splash API or buffered as script-visible state.
A redactor is trusted host Rust code, not generated script code; it must remain
small and non-blocking, and it cannot substitute for a contained worker or
output validation by the receiving UI, log, or LLM adapter. Stream limits span
all retries of the same operation, so a retry cannot reset an output budget.
The redactor is frozen once the tool reserves its first call, preventing a
mid-operation configuration change from altering the release policy.

Hosts can set a deferred deadline on each tool policy. Expiration is enforced
before a queued host-pump handler begins and through
CapabilityRuntime::expire_timed_out_tools for external work. It cannot stop a
Rust handler that is already blocking; effectful adapters still need their own
I/O deadline and containment policy. A result delivered after the deferred
deadline is rejected as timed out.

One v0.1 runtime is single-flight: a host must resume or discard a suspended
evaluation before submitting new source to that runtime instance. Hosts that
need independent concurrent workflows should use separate runtime instances.

Workflow plans are approved by the Rust host. An approval is bound to one plan
and consumed by execution, so a script cannot manufacture approval for another
workflow or resume a rejected plan by mutating its own state. Plans are also
bound to their creating workflow engine; another engine cannot approve,
checkpoint, or execute a foreign plan object.

Workflow checkpoints are bounded data-only records of a completed step prefix.
They bind to the ordered trusted plan through a BLAKE3 fingerprint, but include
no approval, grant, VM state, output, promise, or external operation handle.
Loading one cannot run a workflow: the host must recreate the plan and current
capability policy, authenticate its durable storage, and explicitly issue a
fresh checkpoint-bound approval. A checkpoint is not proof that its prefix ran
or that an interrupted step is safe to replay; hosts must use idempotency,
reconciliation, or compensation for effects around the restart boundary.

`WorkflowOperationLedger` records durable external-operation intent separately
from a checkpoint. Each record is bound to the trusted plan and retains only a
tool, step, non-authorizing operation key, input digest, and worker-observed
state. Reconciliation request construction requires the exact current input
bytes and fails closed when their digest differs. The preferred derived key
also binds the plan, step, tool, input, and host-supplied durable nonce, so a
host should not reuse it for a different logical effect. A ledger revision is
only a host-facing compare-and-swap or watermark hook: it does not authenticate
storage, prevent rollback by itself, validate a worker output, restore a VM
promise, or authorize a workflow restart. Those decisions remain with an
authenticated storage backend and fresh host policy.
The persisted input fingerprint is an unkeyed correlation digest, not encrypted
secret storage; hosts must pass opaque secret selectors rather than credential
values into the ledger identity.

An operation ledger may hold one compensation intent only after its original
operation is durably `succeeded`. That intent binds a separate `cmp-` key,
canonical-input digest, tenant scope, and active capability-grant fingerprint;
it never stores raw compensation input, output, an approval, or a grant.
Compensation approvals are process-local, one-use, session-bound host values.
They must be issued only after the intent is durably persisted and must be
reissued after a restart for the exact same record. A changed tenant, key,
input, or grant fails closed. The ledger cannot prove an inverse effect is
semantically correct or automatically restart a workflow.
`CompensationGrantVerifier` is invoked by the workflow host before approval
and again before frame sealing, so a production host must connect it to current
tenant policy, revocation, and any grant-lease state rather than treating a
stored fingerprint as a still-valid capability.

`splash-storage` authenticates host-owned record bytes with a provisioned
BLAKE3 key and binds them to an opaque record namespace, name, revision, and
key ID. It supports verification-key rotation, but it does not encrypt payloads
or generate, transfer, or protect storage keys. Its `RollbackProtectedStore`
trait is deliberately strict: an implementation must atomically return a
record with its durable revision floor, and atomically advance that floor with
a successful compare-and-swap. The included `VolatileMemoryStore` is only a
process-local test/development implementation, not a durable backend. A file,
database, or mobile key-value adapter must not claim rollback protection unless
it has a separate platform trust anchor and the required atomic semantics.
Generated Splash source receives neither a store nor a key.

Worker protocol v4 adds authenticated operation-dispatch and explicit
compensation frames. A contained worker's `WorkerOperationJournal` records
the tool, key, canonical-input digest, state, and at most one compensation
record before its adapter runs an effect. A compensation is admitted only for
a succeeded original operation under the same tool and tenant scope, with an
exact active-grant fingerprint and a separately bounded nonzero compensation
grant. An exact duplicate returns the stored compensation state; a changed
tool, key, input, grant, scope, or contradictory terminal result is rejected.
The host should reconcile an ambiguous response rather than blindly
re-dispatching or creating another inverse effect. This remains a worker
idempotency primitive, not semantic rollback, key exchange, process
containment, or authorization granted to Splash source. The journal retains
terminal result data for idempotent replies, so its storage may need encryption
in addition to authentication. The canonical-input digest is an unkeyed
correlation value, so operation payloads must contain opaque secret selectors
rather than credential values.

This baseline does not yet provide filesystem or network tool adapters, a
secret broker, signed packages, full JSON Schema, mobile policy backends, or
general-purpose process containment. The Linux Bubblewrap launcher is a
deliberately narrow worker policy, not a substitute for those missing
boundaries. Those features must not be inferred from the presence of the VM.

Tool descriptions and schemas are available only through the host-side
catalog. They are not script-visible authority. Schemas registered solely as
`ToolMetadata` remain prompt metadata; only `JsonToolContract` is executable.
