# Linux Bubblewrap Workers

`splash-sandbox::bubblewrap` builds and launches a Linux Bubblewrap worker from
trusted host Rust configuration. It is the first execution-boundary backend for
Splash. The policy accepts a fixed worker program, fixed worker arguments,
read-only runtime mounts, and opaque `file_root` bindings selected by an active
`CapabilityManifest`.

It is deliberately not a general command runner. Splash source, tool payloads,
and resource selector IDs never become a host path, command line, origin, or
session key.

## Policy Construction

The host provides every worker-visible runtime path and file root. The worker
program must live in a read-only runtime mount; a file-root binding cannot
provide it.

```rust
use splash_sandbox::bubblewrap::{
    BubblewrapWorkerPolicy, FileRootAccess, FileRootBinding, ReadOnlyMount,
    ResourceLimitRunner, WorkerResourceLimits, WorkerSeccompProfile,
};
use splash_protocol::{PrivatePipeWorkerBootstrap, SessionAuthenticator, SessionRole};

let mut policy = BubblewrapWorkerPolicy::new(
    "/usr/bin/bwrap",
    "/opt/splash/bin/worker",
)?
.with_worker_arguments(["--json-lines"]);

policy.add_runtime_mount(ReadOnlyMount::new(
    "/opt/splash/runtime",
    "/opt/splash",
)?);
policy.add_file_root(
    "project-read",
    FileRootBinding::new(
        "/srv/splash/project",
        "/workspace/project",
        FileRootAccess::ReadOnly,
    )?,
)?;
policy.require_no_further_user_namespaces();
policy.set_seccomp_profile(WorkerSeccompProfile::DenyKnownEscapeSurface);
policy.enable_private_tmpfs_with_maximum_bytes(64 * 1024 * 1024)?;

let mut limits = WorkerResourceLimits::default();
limits.set_cpu_seconds(30)?;
limits.set_address_space_bytes(512 * 1024 * 1024)?;
limits.set_open_files(64)?;
limits.set_file_size_bytes(16 * 1024 * 1024)?;
policy.set_resource_limit_runner(ResourceLimitRunner::new(
    "/opt/splash/bin/splash-limit-runner",
    limits,
)?);

let command = policy.compile(&attenuated_manifest)?;
// `trusted_session_key` comes from the host's CSPRNG/key authority.
let host_authenticator = SessionAuthenticator::new(
    attenuated_manifest.session_id.clone(),
    trusted_session_key.clone(),
    SessionRole::Host,
)?;
let bootstrap = PrivatePipeWorkerBootstrap::new(
    attenuated_manifest.session_id.clone(),
    trusted_session_key,
)?;
let worker = command.spawn_with_bootstrap(&bootstrap)?;
let (mut lifecycle, worker_stdin, worker_stdout) = worker.into_lifecycle_parts();
```

`spawn_with_bootstrap` binds the bootstrap session ID to the manifest used at
`compile` before it launches Bubblewrap. It then writes and flushes a versioned,
non-JSON preamble to the private worker stdin pipe. A mismatch fails before
launch; a write failure kills and reaps the child. The session key never appears
in command-line arguments, environment variables, mount paths, Splash values,
capability selectors, or ordinary JSON frames.

The worker must read that preamble exactly once before it creates its JSON-line
reader, construct its worker `SessionAuthenticator`, and use it to verify the
one-way authenticated `open_session` frame. The host then wraps the returned
pipes in the bounded JSON-line transport, sends that frame with
`host_authenticator`, and enforces its own deadlines and cancellation. This is
only delivery of a key that the host already generated and trusts; it is not key
exchange, encrypted transport, worker attestation, or key storage.

`enable_private_tmpfs_with_maximum_bytes` emits `--size BYTES` immediately
before `--tmpfs /tmp`. Bubblewrap enforces that maximum only for allocations in
this private `/tmp`; it is not a general process-memory, CPU, process-count, or
disk quota. Zero and sizes above Bubblewrap's supported maximum are rejected
rather than silently requesting an unbounded or launch-failing policy. Hosts
that enable it must use a Bubblewrap version that
supports `--size`; an unsupported option is a launch failure, never a fallback
to an unbounded worker.

`require_no_further_user_namespaces` is an opt-in hardening mode for Linux
deployments that require it. It emits `--unshare-user --disable-userns` after
`--unshare-all`: Bubblewrap's default `--unshare-all` requests a user namespace
only on a best-effort basis, while `--disable-userns` requires a real user
namespace and prevents the worker from creating further ones. The mode has no
fallback. It will refuse to start the worker when Bubblewrap lacks
`--disable-userns`, when Bubblewrap is installed setuid, or when the host does
not permit the required user namespace. Bubblewrap may create a nested user
namespace internally to establish this restriction, so the mode does not claim
that the worker is never inside one. It is not a seccomp, resource-limit, or
general containment policy.

`WorkerSeccompProfile::DenyKnownEscapeSurface` is a second, independent,
opt-in hardening mode. Splash generates its fixed cBPF program itself and sends
it through an anonymous launch-only descriptor to Bubblewrap's `--seccomp`
option. The descriptor is never part of `BubblewrapCommand::arguments`, is not
caller-supplied, and Bubblewrap consumes and closes it before applying the
filter immediately before it executes the fixed worker. A selected profile has
no direct-launch or unfiltered fallback. It currently supports little-endian
Linux `x86_64`, `aarch64`, and `riscv64`; selecting it on another target fails
policy compilation.

The profile validates `seccomp_data.arch`, kills an ABI mismatch, and also
kills x86-64 x32 syscall attempts. It otherwise defaults to `ALLOW` for broad
dynamic-worker compatibility, returning `EPERM` for a reviewed set of common
escape-surface operations:

- legacy and modern mount APIs, filesystem-handle APIs, `unshare`, and
  `setns`;
- legacy `clone` with any namespace-creation flag;
- `bpf`, `perf_event_open`, `userfaultfd`, and all `io_uring` entry points;
- module loading, kexec, reboot, tracing, cross-process memory access, and
  kernel keyring calls;
- `personality`, which could disable process hardening such as ASLR; and
- the `TIOCSTI` terminal-input-injection ioctl.

`clone3` carries its flags in a pointed-to structure that cBPF cannot inspect.
The profile returns `ENOSYS` for it so common libc implementations fall back to
legacy `clone`, where the namespace flags are checked. This can break a worker
that requires `clone3` semantics; validate the exact worker and its runtime
before selecting the profile.

This is defense in depth, not a general syscall sandbox. It deliberately
allows `execve`, because Bubblewrap applies the filter before the optional
trusted pre-exec runner must execute the fixed worker. It also permits every
syscall outside the fixed deny set, including future kernel interfaces. It
therefore cannot constrain arbitrary executable chaining from exposed runtime
mounts, replace a worker-specific syscall allowlist, mediate networking, or
make a capability decision. Keep runtime mounts minimal and immutable, retain
the no-host-network namespace, and treat a dedicated worker-specific allowlist
as future work. Bubblewrap requires `no_new_privs` before it installs the
filter, so a worker cannot weaken it by adding another seccomp program; a
worker may still add a stricter filter of its own.

`splash-limit-runner` is an optional Linux-only, fixed pre-exec runner. Build
the bundled binary on the target Linux platform with:

```sh
cargo build --locked -p splash-sandbox --bin splash-limit-runner --release
```

Deploy that binary and every runtime dependency it needs in a read-only runtime
mount, then configure its worker-visible path with `ResourceLimitRunner`. The
compiler requires distinct worker-visible runner and worker paths, each
resolving to an executable through a read-only runtime mount. It emits the
runner, policy-generated limit flags,
`--`, and then the fixed worker and fixed arguments. Splash source, tool
payloads, selectors, and manifest data cannot select the runner, alter a limit,
or add target arguments.

Before its `exec`, the bundled runner rejects malformed, repeated, zero, and
unbounded limits; sets every selected limit as both soft and hard; and disables
core dumps. It also marks every inherited file descriptor from 3 onward
close-on-exec, preserving only the host-configured standard-input/output/error
streams when it replaces itself with the worker. This prevents a nonstandard
host descriptor that Bubblewrap inherited from becoming worker authority. A
setup or `exec` failure prevents the worker from starting. The host still must
complete authenticated worker startup: spawning Bubblewrap only proves that the
outer process was created, not that the runner applied limits or that the worker
is healthy.

The runner applies Linux `RLIMIT_*` ceilings to the worker process and its
descendants, not cgroup quotas to the entire Bubblewrap session:

- `cpu_seconds` is cumulative CPU seconds, not a wall-clock deadline or a CPU
  share;
- `address_space_bytes` is virtual address space, not resident memory;
- `process_count` is `RLIMIT_NPROC`, a thread count for the real UID that can
  include unrelated processes and is not enforced for real UID 0 or a process
  with `CAP_SYS_ADMIN` or `CAP_SYS_RESOURCE`;
- `open_files` is the process's file-descriptor ceiling; and
- `file_size_bytes` limits one created file, not total writable storage.

An unprivileged worker cannot raise the selected hard limits, but a process
with `CAP_SYS_RESOURCE` in the initial user namespace can. Do not treat these
limits as a cgroup replacement, process-tree guarantee, memory-RSS ceiling,
aggregate disk quota, seccomp policy, cancellation mechanism, or deadline.
Use a dedicated non-root sandbox identity and cgroups when isolation needs any
of those guarantees. See the Linux [`getrlimit(2)` manual](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
for exact kernel semantics.

`RLIMIT_CPU` does not terminate a sleeping or blocked worker. A host that needs
a wall-clock deadline must independently schedule
`BubblewrapWorkerLifecycle::terminate()` on a monotonic timer, discard the
session afterward, and reconcile any durable effect. The runner does not create
that timer or turn process termination into in-band cancellation.

After the pipes move into the JSON-line transport, retain `lifecycle` and call
`lifecycle.terminate()` after a host deadline, cancellation decision, or
poisoned transport. It force-kills and reaps the host-side Bubblewrap child, returning
whether it was already exited or killed. This is not authenticated in-band
cancellation and cannot establish whether an adapter effect began or completed.
Discard the session and use the durable reconciliation or compensation path for
any effectful operation.

`compile` canonicalizes the source paths and fails closed when a source is
missing, is the wrong type, resolves to `/`, overlaps another worker-visible
destination, or conflicts with `/proc`, `/dev`, or an enabled private `/tmp`.
The resulting command uses:

- `--unshare-all`, so it does not retain the host network namespace;
- optional `--unshare-user --disable-userns` immediately after
  `--unshare-all`, requiring a usable user namespace and preventing the worker
  from creating further user namespaces;
- optional host-generated `--seccomp FD` immediately before launch; Bubblewrap
  consumes the anonymous descriptor and attaches the selected fixed profile
  before it executes the worker;
- `--clearenv`, so worker startup does not inherit host environment variables;
- `--new-session` and `--die-with-parent` for terminal isolation and parent
  lifecycle binding;
- `--chdir /`, so worker startup does not inherit the host process's current
  directory;
- explicit `--ro-bind` runtime and read-only file roots, or explicit `--bind`
  read-write file roots; and
- optional `--size BYTES` immediately before a private `--tmpfs /tmp`, limiting
  only allocations in that mount; and
- optional `splash-limit-runner` invocation before the fixed worker, with only
  host-selected rlimit flags and no script-controlled target or arguments; and
- private stdin/stdout pipes, with stderr sent to `/dev/null` to prevent an
  undrained diagnostic pipe from blocking the worker.

The plan never emits `--share-net`, never mounts host `/`, and mounts no policy
binding that is absent from the manifest. Bubblewrap itself is a low-level tool:
the protection it provides depends on the arguments supplied by its caller.
See the [Bubblewrap security model](https://github.com/containers/bubblewrap/blob/main/README.md)
for the underlying constraints.

## Capability Semantics

The backend implements only file-root visibility at the operating-system
boundary:

- `file_root`: allowed only when its opaque ID is registered in the trusted
  policy. The bound source must be a directory. Access mode is selected by the
  host binding, so hosts should use distinct opaque IDs for read-only and
  read-write views of the same source.
- `executable`: rejected. The worker program is fixed by host configuration;
  scripts cannot choose a second executable.
- `network_origin`: rejected. The worker has no host network namespace, and
  this backend does not pretend that an IP or DNS allowlist is an origin policy.
- `secret`: rejected. Secret provisioning needs a dedicated target-specific
  broker and is not implemented here.

Mount visibility is session-scoped. A worker receives the union of file roots
in its attenuated manifest, while the authenticated worker runtime still checks
which capability grant applies to each invocation. Hosts needing filesystem
isolation for each individual call must launch a separate worker using a
narrower manifest, rather than relying on one multi-tool worker process.

The fixed worker program is not an executable syscall policy. A trusted adapter
cannot receive a script-selected executable through this backend, but a
compromised worker can still execute or read any file deliberately exposed in a
runtime mount. `DenyKnownEscapeSurface` protects only its explicit
default-allow deny set and intentionally permits `execve`; hosts must keep
runtime mounts minimal and immutable. Preventing unexpected executable chaining
requires a separately designed worker-specific syscall allowlist.

## Non-Guarantees

This backend is Linux-only and fails rather than falling back to an unrestricted
process on every other target. It is not available for mobile or embedded
profiles; those profiles currently use static, app-provided in-process adapters
under their platform's own application sandbox.

It does not yet provide:

- worker attestation, authenticated key exchange, encrypted transport, or
  session-key storage. The private-pipe preamble only transfers a
  host-generated key to a newly launched worker;
- cgroup CPU, memory/RSS, process-tree, aggregate-disk, or wall-clock quotas.
  An optional runner adds the narrower rlimits described above, and a configured
  private `/tmp` size limits only that Bubblewrap `tmpfs`;
- a worker-specific syscall allowlist, D-Bus mediation, device-specific policy,
  or a network proxy. `DenyKnownEscapeSurface` is a narrow default-allow
  hardening filter, not a replacement for any of these;
- a safe per-origin network allowlist, arbitrary executable selection, secret
  broker, or filesystem access outside registered directory roots;
- authenticated in-band cancellation delivery, I/O deadlines, post-exit
  reconciliation, or durable operation storage. `lifecycle.terminate()` is a
  forceful process stop that the host must schedule for a wall-clock deadline,
  not proof that an adapter effect was cancelled; and
- protection from a trusted host changing a policy source path between plan
  compilation and worker exit. Policy sources and their contents, including
  executable and symlink targets, must be owned and immutable to untrusted
  actors for that whole interval, or a future descriptor-based launcher must be
  used.

The default user-namespace policy retains Bubblewrap's best-effort
`--unshare-all` behavior. Hosts requiring prevention of further user namespace
creation must select `require_no_further_user_namespaces` and treat a failed
worker or authenticated-session startup as a hard failure, never as a reason
to run the worker outside Bubblewrap.

Do not expose plan paths or launch errors to a script or LLM. A host must treat
any launch, transport, authentication, or worker failure as a reason to discard
the worker session and use the existing replay/reconciliation protocol rather
than reusing the same stream.
