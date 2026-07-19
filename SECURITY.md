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

`fixed_file_catalog::FixedFileCatalog` is the supplied narrow local-file
adapter. During trusted setup, a host registers a bounded set of already-opened
regular files under canonical opaque identifiers. A script can request only an
identifier through an explicitly registered text tool; it cannot provide a
path, enumerate the catalog, traverse directories, or write a file. The
catalog retains a descriptor rather than a path, so a later path replacement
does not redirect that entry. Reads remain bounded by both the catalog and tool
policy, require UTF-8, and convert all adapter errors to generic script-facing
messages. File identity is pinned, not file content: a host must either select
immutable files or treat mutable content as untrusted data. This adapter is not
a general filesystem API, symlink policy, or OS containment boundary. A grant
to one catalog tool covers every entry in that catalog; hosts needing a narrower
file scope must use separate tools/catalogs or an input-aware authorization
hook. A successful read necessarily reveals that its requested identifier was
granted, so opaque identifiers should be unguessable when that matters.
The adapter's byte bound is not a wall-clock I/O bound; a slow or remote
host-selected file can still block the local handler. Hosts must select files
with acceptable latency or use a contained worker with a deadline for broader
or potentially blocking effects.

When its explicit feature is enabled, HttpEndpointCatalog supplies a similarly
narrow outbound JSON adapter. Trusted setup fixes each full endpoint URL,
method, opaque identifier, and optional endpoint-bound credential reference.
The executable request contract accepts only a catalog identifier and, for POST,
a bounded JSON object or array body; it rejects URL, method, header, query,
secret, and redirect selectors before the adapter runs. The contract publishes
opaque endpoint identifiers to the host-side catalog but not URLs or credential
references. HTTPS is required by default; the explicitly named insecure HTTP
constructor is for trusted local or development services only and cannot carry
a credential binding. The adapter disables environment proxies and redirect
following, exposes no cookie API, bounds script request input, response headers,
bodies, and total request time, and requires a 2xx JSON object or array response.
An explicit trusted `HttpEndpointSecretResolver` can inject a bounded sensitive
header into one configured HTTPS endpoint only after input checks. Splash cannot
name, read, enumerate, serialize, or receive a secret. Script-facing failures
are generic and do not disclose endpoint membership, URLs, credential references,
secret values, status codes, headers, response bodies, or transport details.
This is endpoint-bound injection, not a general secret broker; host metadata and
endpoint URLs must not contain credentials, and POST body semantics need a
separate reviewed schema or adapter when broad input is not safe.

The optional `platform-keyring-secret-resolver` feature maps only setup-selected
opaque endpoint-secret IDs to exact service/account locations in explicit native
macOS, iOS, or Windows credential stores. It reads existing values only at
invocation time, never exposes those mappings through accessors or `Debug`, and
never creates, updates, rotates, or deletes credentials. Unsupported Linux and
embedded targets fail closed instead of using keyring-rs's in-process mock
store. This is still not a general credential broker, rollback anchor, or OS
network boundary; resolver latency and native-store behavior remain host
responsibility.

This endpoint catalog mediates one registered API surface only. It does not
pin DNS, enforce a firewall or per-origin egress rule, contain a blocking
request after it starts, reduce the embedding process's network authority, or
restrict another trusted adapter. A fixed URL is still trusted host policy.
Effects requiring real network isolation need a target-specific containment or
network backend.

The canonical Splash profile is an effect-free preflight in front of the
vendored Makepad parser. A profile rejection never reaches that parser or a
host binding; a profile acceptance is then independently parsed by the VM
before evaluation. The runtime carries executable canonical-fixture regression
coverage, but the two parsers are not formally proven equivalent. Parser/VM
differential fuzzing is required before a stable language release.

Standalone `Runtime` masks inherited Makepad platform/debug entry points before
canonical and compatibility evaluation. The source surface cannot reach the
vendored math, GC, pod, shader, regex, HTML, or direct standard-output APIs;
`std.log`, `std.print`, `std.println`, `std.regex`, and `String.parse_html()`
are specifically unavailable. `mod.std.assert`, the frozen no-authority
`mod.std.math`, `mod.std.json`, `mod.std.text`, and `mod.std.array` modules,
ordinary bounded language operations, and explicitly installed host modules
remain available.
This avoids unreviewed native output and native allocations outside Splash's
tracked heap from becoming generated-source behavior. It does not alter a host
that embeds the raw Makepad VM, and a trusted host can still install a reviewed
capability under any otherwise-masked module name through the normal policy
boundary.

The only built-in numeric module added by Splash itself is frozen,
effect-free `mod.std.math`. It provides bounded-arity scalar `f64` operations
and constants, not the vendored shader-oriented `mod.math` module. It cannot
perform I/O, access host state, read time or entropy, or load a Rust crate.
Its floating-point results are ordinary script data rather than a portable
bit-for-bit cross-platform numeric guarantee; non-finite results remain
ineligible for the JSON capability boundary.

The frozen `mod.std.json` module exposes only `json.parse(document)` and
`json.stringify(value)`. Both reuse the runtime's strict byte-, nesting-, and
cycle-bounded JSON boundary; they do not inspect adapters, host state, files,
processes, networks, clocks, entropy, or Rust crates. A JSON helper therefore
does not grant authority beyond pure bounded data conversion.

The frozen `mod.std.text` module exposes a small literal string-shaping
surface. Its casing and replacement functions stream output through the VM's
configured string bound, while predicates only inspect supplied strings. It
does not expose regex matching, adapters, host state, files, processes,
networks, clocks, entropy, or Rust crates; it grants no authority beyond local
bounded data conversion.

The frozen `mod.std.array` module exposes only `array.len(value)`,
`array.slice(value, start, end)`, `array.concat(left, right)`, and
`array.reverse(value)`. Its transforms have no callbacks or host hooks, produce
shallow arrays, and reject source arrays over 4,096 items before native
traversal; `concat` also rejects a combined result over that bound. `len` is
constant-time and does not traverse the array. The module cannot inspect
adapters or host state, and cannot access files, processes, networks, clocks,
entropy, or Rust crates.

`Runtime` replaces inherited direct `value.to_json()` and
`document.parse_json()` dispatches with bounded JSON methods. The default
direct-conversion ceiling is 64 KiB and 64 container levels, and a host may
lower it through execution limits. Parsing accepts only strict JSON strings or
UTF-8 byte arrays; it is bounded before the value is copied into the VM.
Cycles, unsupported values, non-finite numbers, and duplicate object keys are
rejected on serialization; malformed or non-UTF-8 input is rejected on parsing.
Either direction rejects depth exhaustion and input or output exhaustion as
ordinary native errors rather than unbounded parser or serializer work. This
protects Splash `Runtime` evaluation, including the explicit
compatibility-evaluation entry point; it does not alter a host that directly
embeds the raw Makepad VM.

`Runtime` also caps every newly constructed script string at 256 KiB by
default through `ExecutionLimits::max_string_bytes`; a host can lower that
limit for its target. An attempted overflow terminates the current evaluation
as an uncatchable hard resource failure, including during compatibility
evaluation and bounded JSON reconstruction.

`ExecutionLimits::max_heap_bytes` additionally caps tracked retained capacity
in the Splash-owned VM heap. Its default is 8 MiB and it accounts for script
strings, arrays, object storage, slot tables, and intern tables. Sparse array
and object writes, plus conservative object-map rehashes, are rejected before
they request their backing allocation; other normal script allocations raise
the same uncatchable hard resource failure when retained storage crosses the
cap. This heap-only accounting is not a process allocator quota: VM parser/code
storage, other VM control vectors, allocator metadata, compiled regex internals,
and opaque trusted Rust adapter allocations remain outside it.

`ExecutionLimits::max_stack_values` caps live VM operand values at 32,768 by
default, and `ExecutionLimits::max_call_frames` caps active VM call frames,
including the root frame, at 1,024 by default. Both terminate the current
evaluation as uncatchable hard resource failures. They do not account for
native Rust stacks, parser or code storage, other VM control vectors, allocator
metadata, or opaque trusted adapter allocations.
Targets that need process-wide memory or effect containment must layer an
operating-system boundary around the worker.

Canonical `try/catch` handles ordinary script and native-binding errors and
unwinds Splash function calls, but it is not a sandbox or transaction. It
cannot catch string-allocation, heap-allocation, operand-stack, call-frame,
instruction-limit, or hard-deadline termination, inspect an error object, widen a
capability lease, refund a call,
erase an audit outcome, or bypass a workflow data contract. A caught error is
discarded before the fallback runs and does not appear in the evaluation
diagnostics. An uncaught native error is host-facing and may contain
adapter-provided text, so adapters must return disclosure-safe messages and
keep private detail in trusted logs.

`splash-lsp` is a host-only helper for a trusted local editor client. It never
reads a document URI, evaluates source, creates a capability host, resolves an
imported module, or loads an adapter. Its top-level `fn`/`let` outline and
same-document lexical definition/reference index are derived only from valid
client-provided canonical source and grant no tool authority. Binding-kind hover
and neutral symbol highlights use that same index; they do not expose runtime
values or claim read/write analysis. Lexical completion uses only
expression-identifier sites and binding visibility metadata from the supplied
snapshot. It may retain a site from incomplete source only when the site ends
before or at the first syntax diagnostic. It never queries runtime values,
module exports, a live tool catalog, or adapter metadata, and completion
candidates do not grant or predict authority. A local editor integration may
supply bounded static projections in initialization options: a tool projection
uses only names, formats, and descriptions to complete a direct visible
`mod.tool` literal, while a separate module-interface projection uses canonical
`mod.*` paths and descriptions for direct import-path or imported-module member
spelling. The LSP never queries or authenticates either projection, loads or
validates a referenced module, presents no partial projection after malformed or
over-limit input, or lets module metadata replace the fixed `mod.tool` methods.
It also carries a compiled-in projection of the frozen standalone `mod.std`
namespace: `use mod.` can suggest `std`, and `use mod.std.` can suggest only
the documented `array`, `assert`, `json`, `math`, and `text` core modules. The
server
suppresses advisory children below that namespace, matching the runtime's
frozen `std` object; an integration must use a distinct host-owned `mod.*`
namespace for capabilities.
For an exact visible `use mod.std.assert` binding, and direct `std.assert(...)`
after `use mod.std`, assertion hover and signature help are likewise compiled
in and carry no catalog lookup, host access, or authority. The same holds for
fixed completion, hover, and signature help for direct `use mod.std.json`
bindings, `use mod.std.text` bindings, and `use mod.std.array` bindings.
Suggested names remain subject to runtime module binding, catalog, and lease
checks. Guarded rename is advertised only to a client that supports versioned
document edits. It never renames an
import path, never operates on a truncated index, validates the replacement with
the canonical lexer and parser, and returns edits only when the complete remapped
lexical report is unchanged apart from the selected name and byte offsets. This
is indexed lexical preservation, not proof about unindexed forward references,
fields, reflection, or other name-coupled runtime semantics. Every returned edit
is bound to the source version used for analysis.

The lexical index is source-local, conservative, bounded to 4,096 retained
definitions and resolved references, and lazily cached only for the current
document version. Completion sites have a separate 4,096-entry bound and cache;
either truncation is exposed to the client as `isIncomplete`. Symbol truncation
also suppresses all completion candidates because an omitted inner definition
could shadow a retained outer binding. A definition or hover is returned only
when its retained occurrence has an exact binding. The index is not a type
checker, module resolver, capability analysis, or authorization decision. The
server retains at most 128 document states and no source text larger than the
canonical 256 KiB limit, but the underlying LSP framing layer decodes an inbound
message before that retention limit applies. The optional tool projection is
separately bounded to 128 entries and 512 KiB of retained names/descriptions;
the optional module-interface projection is bounded to 256 entries and 512 KiB
of retained paths/descriptions. Their inbound LSP messages are likewise decoded
first. Do not expose its stdio
transport to a hostile peer or describe it as an IPC resource sandbox; place a
separate bounded transport or operating-system boundary in front of such a peer.

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

`RollbackAnchorService<A>` is only a bounded, canonical protocol dispatcher
around a host-owned `RollbackAnchor`. `AuthorizedRollbackAnchorService<A, Z>`
can require `Z` to authorize an already authenticated caller's exact operation
and record before the backend runs; its fixed policy has no wildcard or
implicit write grants. Neither type authenticates a caller, listens on a
socket, serializes concurrent callers, selects tenant scope, or improves `A`'s
durability. A network service must enforce those boundaries outside the handler
and return generic failures without backend details. A volatile or rollbackable
backend remains unsuitable after being wrapped by either dispatcher.

The optional `splash-storage` `keyring` feature retrieves a host-provisioned
32-byte storage key from native credential stores on macOS, iOS, and Windows.
It reads an existing binary credential only, rejects unsupported targets rather
than using an in-process mock, and never creates, rotates, or deletes platform
credentials. On supported targets it invokes the explicit native credential
implementation rather than keyring-rs's process-configurable default builder.
Credential storage protects key material; it does not provide the linearizable,
rollback-resistant compare-and-swap required by `RollbackAnchor`. Do not use it
as evidence that local payload storage is rollback protected.

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
resource limit or containment mechanism. An HttpEndpointCatalog registered
through the feature-gated builder is consumed before sealing, so generated
source cannot add an endpoint, change its URL, method, headers, query, or
redirect behavior, or select an endpoint credential. It remains in-process API
mediation, not mobile or embedded operating-system containment. A `FixedFileCatalog` registered
through the builder is consumed before sealing and has the same opaque-ID,
descriptor-pinning, and mutable-content limitations described above.

`splash_workflow::mobile::MobileWorkflowBuilder` applies the same static local
adapter rule to host-owned workflow execution. Its sealed result can create
plans from trusted steps or data-only drafts, approve only named per-step
policies, checkpoint, and execute. It intentionally does not expose the
underlying `CapabilityRuntime`, manual lease issuance, full-catalog approval,
external-operation APIs, or mutable registration. This prevents the facade
from widening its own catalog after setup; it does not constrain a host that
deliberately chooses lower-level APIs or reduce the ambient authority of a
registered Rust adapter.

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

Protocol v5's optional multiplexed JSON-line path is separate from that
synchronous transport. It admits one active ordinary invocation and one exact
authenticated cancellation request, with independently owned directional
authentication state. The worker path accepts only adapters explicitly
registered as `CancellableWorkerAdapter`; it keeps frame processing outside the
adapter thread and sets a cancellation token only after request authentication
and reauthorization. A positive acknowledgement is valid only when the adapter
has stopped its effect and guarantees no result follows. `too_late` requires a
validated ordinary result first, while `unsupported` keeps the call active.
These are trusted Rust adapter contracts, not properties asserted by Splash
source or inferred from a process exit.

`SupervisedMultiplexedWorkerSession` additionally requires its transport and
lifecycle supervisor to name the same session, arms the deadline before
dispatch, and resolves the watchdog race before exposing a terminal event. A
deadline, forced stop, EOF, authentication failure, or transport error poisons
the session and remains indeterminate. Only an authenticated positive
acknowledgement whose supervision completed normally may drive the runtime's
two-phase cancellation confirmation. The workflow integration applies events
through `WorkflowEngine`, not `runtime_mut()`, so retained-step state cannot be
bypassed accidentally.

`splash-sandbox::bubblewrap` is the first such platform sandbox integration.
It accepts only a fixed host-selected worker executable and fixed arguments,
constructs a fresh Bubblewrap mount namespace, clears the worker environment,
creates a new session, binds the worker to its parent lifecycle, and mounts
only read-only runtime paths plus active manifest-selected host-backed or
bounded ephemeral `file_root` entries. It uses `--unshare-all` and never emits
`--share-net`, so it does not retain the host network namespace. It also emits
`--cap-drop ALL` unconditionally, including when Bubblewrap is launched by
root, so the worker cannot retain Linux capabilities needed to undo mount or
namespace policy. It rejects `executable` and `secret` selectors, and rejects
every `network_origin` selector unless trusted host setup supplies the optional
exact Linux network broker described below. It also rejects overlapping or root
mounts and requires the worker program to live in a read-only runtime mount,
avoiding a writable grant as an executable source.
Hosts that explicitly select
`require_no_further_user_namespaces` also get Bubblewrap's mandatory
`--unshare-user --disable-userns` sequence, which prevents the worker from
creating further user namespaces. That mode has no compatibility fallback and
will fail on unsupported, setuid, or user-namespace-restricted hosts; it does
not mean Bubblewrap never created an internal nested namespace.

With the Linux-only `splash-capabilities/linux-network-broker` feature, the
host can derive one exact `NetworkOriginAccess` set from the compiled manifest,
bind a reviewed fixed-endpoint or exact-origin HTTP catalog to it, and install
the returned `LinuxNetworkBrokerMount` into that same policy. The broker creates
a CSPRNG-named `0700` directory containing exactly one `0600` Unix socket. The
policy requires descriptor-pinned mount sources, checks that exact directory
shape and that the socket and directory share an owner, requires the catalog
authority to match the manifest's distinct opaque IDs exactly, and mounts that
directory read-only into the worker. The worker still receives no host network
namespace; within this broker path, the host broker outside the sandbox is the
only component that resolves a configured secret or opens the reviewed HTTP
connection.

The private socket is not a general local authorization protocol. Its
filesystem ownership and parent directory remain trusted host setup, and any
process that can legitimately access the socket can issue requests within its
aggregate session catalog. Descriptor pinning retains the selected directory
identity through launch but cannot freeze mutable descendants, so trusted host
setup must retain exclusive control of that directory. Separately selected
runtime and file-root mounts are independent trusted policy decisions and can
expose their own Unix sockets; hosts requiring broker-only IPC must exclude
them. A reviewed `LinuxNetworkBrokerClient` rechecks the active worker grant
before connecting, and the host catalog rechecks its exact identifier set, but
those are not OS per-tool separation. A worker process has the union of its
manifest's network origins. Hosts needing finer isolation must run separate
attenuated sessions with separate broker directories. The broker does not
expose raw TCP/UDP/DNS, arbitrary Unix sockets, catalog discovery, credentials,
or a general proxy; it only carries one bounded catalog request per connection.
It also does not make a POST durable or idempotent.

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

For a fixed worker whose target ABI and runtime have been independently
reviewed, a host can instead provide a bounded `WorkerSeccompAllowlist` through
`set_seccomp_allowlist`. This selects `WorkerSeccompProfile::StrictAllowlist`:
Splash keeps the ABI/x32 and fixed escape-surface guards, returns `ALLOW` only
for listed syscall numbers, and kills every other syscall. An empty, duplicate,
oversized, or missing list is rejected rather than falling back to default-allow
filtering. The list is trusted host configuration, never Splash source, worker
input, LLM output, or caller-provided cBPF. Policy compilation rejects a list
without the required `execve`; the host must additionally cover any fixed
resource-limit runner and the exact worker runtime. With
`LandlockExecutableRunner`, Splash does not give the strict program to
Bubblewrap: it gives the fixed runner a bounded compiler-generated encoding,
which the runner installs only after its fully enforced Landlock ruleset and
descriptor cleanup, immediately before the fixed inner exec. This internal
handoff is not Splash source, worker input, manifest data, or caller-provided
cBPF in the Bubblewrap policy API, and launch has no direct-worker or
unfiltered fallback. It is still a
syscall boundary only: because execution must normally remain available, it
does not mediate an executable path, a network origin, device access, secrets,
or capability grants.

`LandlockExecutableRunner` is an optional Linux-only defense-in-depth boundary
for exact filesystem-backed executable targets. The host configures a distinct
read-only runtime runner path; Splash adds the fixed worker, an optional limit
runner, and bounded explicit additional paths, then the bundled
`splash-landlock-runner` installs `LANDLOCK_ACCESS_FS_EXECUTE` rules with a
hard Landlock compatibility requirement before it starts the inner command. It
rejects unsupported platforms at compilation and unsupported or incomplete
kernel enforcement at startup rather than falling back to direct worker
execution. A dynamically linked inner worker or resource-limit runner also
needs its resolved regular ELF loader listed as an explicit target. Its rules
are inherited by worker descendants. In descriptor-pinned mode Splash also overlays the Landlock runner
and every explicit allowed target from retained descriptors, preventing path
replacement after compilation from changing those selected files.

Do not describe this as a complete executable or code-loading sandbox. It does
not control dynamic-loader reads, shared libraries, plugins, bytecode engines,
JITs, networking, device access, secrets, capability grants, special
filesystems, or already-open descriptors. An allowed interpreter can run code
it reads. Treat the [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
as the source of kernel semantics and layer immutable runtime ownership,
mount/descriptor isolation, cgroups, and a suitable syscall policy around it.

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

The optional multiplexed ordinary-call transport can send a protocol v5
cooperative request while this same watchdog remains armed. This does not
change watchdog semantics: only the worker adapter's exact authenticated
`acknowledged` disposition is cancellation proof. A deadline or process-tree
kill without that disposition is still indeterminate. Durable operation,
compensation, and reconciliation frames do not acquire in-band cancellation
through this path.

An explicit private `/tmp` and each active `EphemeralFileRoot` can have a
Bubblewrap `--size` allocation ceiling. Each ceiling bounds aggregate
data-block allocation in that one `tmpfs` mount, not its independent inode or
directory-entry count. Ephemeral roots are empty on worker startup, disappear
with the mount namespace, and may consume memory or swap; they must not hold a
durable journal or effect record. Multiple roots have independent ceilings,
not a shared session budget. None of these limits is a process-memory, CPU,
process-count, or persistent-filesystem quota.
The tmpfs mounts are `nosuid,nodev`, but Splash does not claim they are
`noexec`: a compromised worker can write executable content into an ephemeral
root and invoke it when the runtime and syscall policy allow. Denying an
`executable` capability selector prevents generated source from selecting a
host command; it does not mediate native `execve` calls inside the worker.
Active host-backed read-write roots are rejected by default. Host code can
explicitly allow one only when it already enforces an independent persistent
storage quota; Splash cannot validate that quota.
`require_bounded_file_root_writes` adds rejection of an enabled unbounded
private `/tmp`, non-recursive read-only remounts of the empty namespace root,
`/proc`, and `/dev` after all selected submounts are created, and mandatory
further-user-namespace lockdown. It overrides the explicit unbounded-write
acknowledgement. Without that lockdown, a worker could reacquire
namespace-scoped mount authority after capabilities were dropped. Device and
proc interfaces retain their kernel-defined semantics, and the mode does not
constrain downstream adapter effects. After transport
pipes move out of the startup handle,
`BubblewrapWorkerLifecycle::terminate` force-terminates and reaps the worker. It
is process control only: the host must drop the session and reconcile a durable
effect rather than infer that process termination cancelled or rolled it back.

Bubblewrap is a low-level sandbox constructor, not a complete security policy.
This backend has no portable aggregate quota for persistent host-backed storage,
no device quota, per-origin network proxy, D-Bus mediation, complete executable
or code-loading policy, direct secret-selector handling, or universal
cancellation for arbitrary or durable adapters. Linux generic project quotas
are an opt-in exception only for a descriptor-pinned directory on a supporting
filesystem and Linux 5.14-or-later kernel. A selected quota root requires the
mandatory further-user-namespace lockdown, which prevents a worker that owns
the root from changing the project ID or inheritance state through Linux
filesystem-attribute ioctls in the initial user namespace. Splash checks the
provisioned project ID, inheritance bit, nonzero hard block and inode limits,
current usage, configured per-root ceilings, and aggregate distinct
`(filesystem, project ID)` hard limits before launch. The filesystem, not
Splash, enforces those limits after launch. The host must prevent a privileged
quota administrator from raising, disabling, or retagging the project while
the worker is active.
Project quotas do not constrain process memory, device access, network,
execution, data outside that project, adapter effects, or non-Linux targets.
Its separate endpoint-bound secret broker is not a general credential or
worker-secret delivery mechanism. Protocol v5 can
layer an exact ordinary-call request over its private pipes only for reviewed
cancellable adapters. Its optional strict allowlist is a target-specific
syscall boundary, not a replacement for those missing controls. The optional
`splash-workflow/bubblewrap-recovery` coordinator adds a narrow post-exit path:
it requires a session-bound reaping proof, reloads a fenced authenticated host
ledger, uses a differently keyed least-privilege contained session for one
bounded reconciliation, reaps that session, and compare-and-swap persists the
observation. It does not report cancellation, redispatch an effect, choose
compensation, implement the worker journal, or resume a workflow. The optional
watchdog supplies only trusted wall-clock process stops
described above, its optional runner provides only the narrow rlimits described
above, and its cgroup profile supplies only the CPU, memory, swap, task, and
selected per-device I/O controls described above. The per-device I/O control is
neither a filesystem quota nor a guarantee that buffered writeback will be
attributed to the worker on every filesystem.
`DenyKnownEscapeSurface` provides only the fixed default-allow hardening
described above. `StrictAllowlist` kills unlisted syscalls but does not replace
an executable-path or capability policy, and normally has to retain the
worker's initial execution syscall. A private `/tmp` is opt-in and
unbounded unless the host selects its explicit Bubblewrap size limit; active
ephemeral file roots are always bounded individually. Those ceilings do not
replace a cgroup memory policy or persistent-filesystem quota. The filesystem
boundary is per worker session, not per individual invocation: an attenuated
manifest should be narrowed before launch when per-call filesystem isolation
is required.
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

The in-process audit view retains only its configured recent entries (1,024 by
default, 8,192 maximum) and exposes an eviction counter. It is deliberately
bounded so a long-lived untrusted-script host cannot grow memory through
observability alone. `audit_since(cursor)` exports only a contiguous retained
range, ordered by a distinct per-record `event_sequence`; it rejects a cursor
overtaken by eviction or `clear_audit` rather than silently returning a partial
history. The older `sequence` field correlates one invocation and can repeat
across retries, cancellation, or streaming, so it is not an export cursor.
Hosts that need complete retention must surface an export gap and use a
separate authenticated durable sink. The optional
`splash_capabilities::durable_audits::CapabilityAuditStore` supplies one
bounded sink for runtime-exported batches: it validates the data-only audit
shape, requires contiguous source sequences, deduplicates exact retained
overlap, rejects retention gaps and conflicts, and writes through the supplied
rollback-protected store's compare-and-swap boundary. Its 1,024-event and
192 KiB limits are independent of the in-memory view. `VolatileMemoryStore`
is development-only; an ordinary key-value store that cannot prevent rollback
does not meet this contract. A retained view, its sequences, its loss counter,
and a successful export are not an authorization decision, durable record,
effect proof, or permission to resume a workflow. See [capability audit
export](docs/capability-audits.md).

`splash_workflow::durable_events::WorkflowEventStore` provides one bounded
authenticated workflow-telemetry journal for host-owned operator/audit replay.
It accepts only contiguous engine-exported sequences, rejects source gaps and
contradictory retained overlaps, records retention eviction explicitly, and
uses the supplied rollback-protected store's compare-and-swap boundary. The
journal includes no source, tool payload, approval, grant, worker key, or VM
promise. It is not a workflow checkpoint, operation ledger, effect proof,
cancellation acknowledgement, or permission to resume a workflow. A host must
still use fresh approval, idempotency, and authenticated reconciliation for an
external effect.

Registered tool names are restricted to 128-byte lowercase ASCII capability
identifiers. A denied call can still carry an arbitrary dynamic Splash string,
so the audit view preserves only a fixed-length, session-scoped BLAKE3 label
for invalid or oversized unrecognized names. It does not retain that raw
script value. The label is a correlation aid, not a credential or a secrecy
guarantee against a host that already knows the candidate value.

A denied or failed tool call can transfer control to a script `catch` branch,
but reservation, budget, and audit decisions remain final. A fallback tool call
is separately authorized and charged. Handler failure is not evidence that an
effect was rolled back; ambiguous or durable effects still require host-owned
idempotency, reconciliation, and compensation policy.

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
each operation, then explicitly completes it or uses a two-phase
cancellation-request/adapter-acknowledgement path; the runtime reuses the normal
output validation and audit boundary. A request leaves the promise pending and
blocks retries and stream forwarding. Confirmation is rejected until a request
exists, but the trusted host remains responsible for deciding whether an
adapter acknowledgement is credible. This does not terminate a worker or
enforce an operating-system policy. A force-stop is indeterminate and must not
be reported as cooperative cancellation without separate proof.

The multiplexed worker bridge keeps `ExternalToolId`, external input, and the
runtime cancellation identity on the host. The wire request repeats only its
own control ID and the exact already-authorized session, invocation request,
and tool. `ExternalToolWorkerBinding` rejects drift in host ID, tool, call
index, attempt, or idempotency key before sending. It accepts only one request
per target. A result-wins race is not exposed until `result` and `too_late`
have both authenticated in required order. An acknowledged race suppresses the
ordinary result. The host must still treat the contained worker and reviewed
adapter implementation as part of the trusted cancellation contract; keyed
framing authenticates the session and ordering, not semantic honesty.

External retries are also host-only. A script receives no retry API and cannot
spend another capability call by requesting another attempt. For each claimed
operation, the host may use its stable `idempotency_key` when forwarding an
attempt to a worker. The key includes a runtime-session nonce sourced from
operating-system entropy when available, with a process-local time/PID fallback
otherwise, so normal new host processes do not reuse the old counter-only value.
It is a correlation and deduplication value, not a capability token, authorization
credential, or durable operation identity; the opaque `ExternalToolId` must
remain owned by the host. Hosts that need replay across restarts must persist
their own workflow identity and authenticate every worker request with the
keyed protocol frame or an equivalent transport mechanism. An adapter must not
retry a non-idempotent effect unless its worker performs deduplication using
that key or an equivalent durable identity.

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

The optional JSON-line `OneShotAuthenticatedOperationWorkerTransport` provides
one separately authenticated durable dispatch, reconciliation, or compensation
exchange after a host has opened a fresh contained-worker session. It validates
the active manifest, request identity, and result before returning, then is
consumed; a failure poisons it. This bounds the transport-level recovery
attempt, but it does not restart a worker, provide durable storage, prove an
effect's outcome, acknowledge cancellation, approve output, or resume a
workflow. The host must restore and authenticate both its ledger and the
worker journal, choose recovery policy, persist the verified observation, and
issue fresh approval before it can run any later workflow work.

The optional `splash-workflow/bubblewrap-recovery` integration owns the narrow
Linux composition of those steps for reconciliation only. It accepts a proof
that the old Bubblewrap session was reaped, generates a new session key without
fallback, requires one exact-tool manifest, reserves a durable writer fence,
starts and later reaps a watchdog-bounded fresh worker, and persists the bound
observation through authenticated fenced compare-and-swap. It returns the
authenticated result only to trusted host code and redacts it from `Debug`; the
ledger stores only lifecycle state. A terminal result is still not approval to
resume, and any transport, deadline, cleanup, fence, or compare-and-swap race
discards the observation.

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
checkpoint, or execute a foreign plan object. Each plan or resume approval
also carries process-local `CapabilityLease` authority tied to the originating
runtime and its exact serialized tool-catalog fingerprint. A lease lists
allowed tool names and non-widening call budgets; every `tool.call`,
`tool.start`, JSON variant, and dynamically computed name is checked when the
host reserves it. The lease remains active across `await` and continuation,
and the host rejects tool registration while it is active. A catalog change
after approval causes the lease to fail closed before execution or resume.

For least-privilege LLM workflows, the host can instead approve an ordered
lease queue with `approve_with_step_capability_leases`. It supplies exactly one
lease per trusted step, and the engine activates only the current lease. An
early step therefore cannot use authority assigned to a later step, including
while it is waiting on an external operation; the current lease is retained
until that step resolves. The checkpoint-resume variant accepts exactly the
remaining suffix, so completed-prefix authority is not renewed after restart.
This queue enforces host-reviewed ordering only: it does not infer correct
grants from generated source, tool-call hints, or step names. The optional
synchronous `ToolCallAuthorizer` can further deny an already leased invocation,
but cannot add authority. This is script-level authority control, not adapter
containment: a permitted Rust adapter still needs an appropriate
contained-worker boundary before it can safely process untrusted local-tool
work.

`WorkflowStepCapabilityPolicy` is a host-only convenience for the common case
without a custom authorizer. Its ordered step IDs and grant lists are checked
against the trusted plan before `approve_with_step_capability_policies` or its
resume counterpart issue any current-runtime lease. A policy intentionally has
no serialized form and cannot invoke a tool; it is configuration, not
authority. Hosts must build it from their own policy decision, never directly
from generated source, a checkpoint, or review hints. A host that needs a
`ToolCallAuthorizer` issues a manual lease instead.

`WorkflowPlan::review` is an effect-free presentation aid for that host
approval flow. It returns per-step canonical syntax reports and direct tool
call hints, but creates no runtime, lease, or approval. An empty hint list is
not authority and does not prove a step is pure: invalid source, aliases,
control flow, and computed names deliberately remain outside its scope.
Workflow plans are capped at 1,024 steps and 1 MiB of aggregate source before
the engine retains them, limiting generated-plan review and lease-queue growth.

`WorkflowDraft` is a separate bounded untrusted input format for an LLM's
proposed step list. Its JSON envelope accepts only a format version plus step
IDs and source, rejects unknown fields, caps wire data at 2 MiB, and bounds
the decoded step collection before it can become a plan. Parsing and reviewing
it do not create a capability runtime, grant, lease, approval, checkpoint, or
operation handle. `plan_draft` records planning only; the host must still
select grants from trusted policy and separately approve execution. Review
hints remain non-authoritative, including for dynamic names.

`WorkflowEngine` likewise retains only a configured recent in-memory event
view (1,024 by default, 8,192 maximum) and exposes its eviction count. Those events are
operational telemetry only; failure events retain diagnostic counts but never
diagnostic text. They must not be used to replay a workflow. Checkpoints and
operation ledgers remain the separate bounded data-only recovery records, each
requiring fresh host approval and authenticated storage.

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

Worker protocol v5 provides authenticated ordinary-call cancellation,
operation-dispatch, and explicit compensation frames. Cancellation is an
ephemeral adapter contract; durable effects still rely on the journal. A
contained worker's `WorkerOperationJournal` records
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

This baseline does not yet provide an arbitrary filesystem or network tool
adapter, dynamic origin policy, a general secret broker, signed packages, full
JSON Schema, mobile policy backends, or general-purpose process containment.
The supplied fixed-file and feature-gated fixed-endpoint catalogs are
intentionally narrower than general filesystem or network adapters. The Linux
Bubblewrap launcher is a deliberately narrow worker policy, not a substitute
for those missing boundaries. Those features must not be inferred from the
presence of the VM.

Tool descriptions and schemas are available only through the host-side
catalog. They are not script-visible authority. Schemas registered solely as
`ToolMetadata` remain prompt metadata; only `JsonToolContract` is executable.
The catalog publishes this distinction as `contract_enforced`, so a host or
LLM prompt builder does not need to infer enforcement from the presence of a
schema field.

`splash_core::tool_call_hints` and the `splash tool-calls` CLI command are
effect-free source-review aids, not static authorization. They recognize only
direct `tool` method syntax and deliberately do not resolve aliases,
shadowing, runtime string values, reachability, or imports. A host must never
derive a capability grant from that output alone; every actual call remains
subject to lease and reservation-time checks.

`CapabilityCatalogLimits` bounds both the number of registered descriptors and
the complete serialized host catalog before a new handler is retained. This
limits catalog-driven prompt and allocation growth, but a trusted host must
still select a suitable bound and review the metadata it registers. A catalog
limit is not an authorization rule, input validator, or containment boundary.
