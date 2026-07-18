# Linux Bubblewrap Workers

`splash-sandbox::bubblewrap` builds and launches a Linux Bubblewrap worker from
trusted host Rust configuration. It is the first execution-boundary backend for
Splash. The policy accepts a fixed worker program, fixed worker arguments,
read-only runtime mounts, and opaque host-backed or bounded ephemeral
`file_root` entries selected by an active `CapabilityManifest`.

An active host-backed read-write root is denied by default. On Linux, a host
can instead attach a verified `LinuxProjectQuota` to a descriptor-pinned root
and configure an aggregate hard byte and inode limit. Splash then checks the
same directory descriptor that Bubblewrap will mount before launch. For a
legacy deployment with a separately managed quota that Splash cannot inspect,
host code may still call `allow_unbounded_host_file_root_writes`; that is an
explicit weaker escape hatch, not quota enforcement. This default does not
bound an explicitly enabled private `/tmp`, which remains an ephemeral mount
with its own selected policy.

It is deliberately not a general command runner. Splash source, tool payloads,
and resource selector IDs never become a host path, command line, origin, or
session key.

## Policy Construction

The host provides every worker-visible runtime path and file root. The worker
program must live in a read-only runtime mount; a file-root binding cannot
provide it.

```rust
use splash_sandbox::bubblewrap::{
    BubblewrapWorkerPolicy, EphemeralFileRoot, ExecutableSourceBinding,
    FileRootAccess, FileRootBinding, LandlockExecutableRunner, LinuxProjectQuota,
    MountSourceBinding, ReadOnlyMount, ResourceLimitRunner, WorkerResourceLimits,
    WorkerSeccompProfile,
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
policy.add_ephemeral_file_root(
    "scratch",
    EphemeralFileRoot::new("/workspace/scratch", 32 * 1024 * 1024)?,
)?;
policy.require_bounded_file_root_writes();
policy.require_no_further_user_namespaces();
policy.set_mount_source_binding(MountSourceBinding::DescriptorPinned);
policy.set_executable_source_binding(ExecutableSourceBinding::DescriptorPinned);
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
policy.require_resource_limit_runner();

let mut executable_runner =
    LandlockExecutableRunner::new("/opt/splash/bin/splash-landlock-runner")?;
// The actual resolved regular ELF loader is deployment and ABI specific. Add
// it for any dynamically linked inner worker or resource-limit runner, plus
// any fixed intermediary that will itself call execve.
let deployed_elf_loader = "/opt/splash/lib/ld-linux-aarch64.so.1";
executable_runner.add_allowed_executable(deployed_elf_loader)?;
executable_runner.add_allowed_executable("/opt/splash/bin/reviewed-interpreter")?;
policy.set_landlock_executable_runner(executable_runner);

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
let (lifecycle, worker_stdin, worker_stdout) = worker.into_lifecycle_parts();
```

`require_resource_limit_runner` makes a missing runner a compile-time policy
failure. It is useful when an application treats its selected `RLIMIT_*`
ceilings as required defense in depth rather than a best-effort deployment
choice. It does not turn those per-process limits into a cgroup, disk quota, or
wall-clock deadline.

`MountSourceBinding::DescriptorPinned` is optional Linux hardening for host
paths selected by this policy. At `compile`, Splash opens each selected runtime
and host-backed file-root source, retains that root descriptor in the immutable
command, and passes a fresh launch-only duplicate to Bubblewrap through
`--ro-bind-fd` or `--bind-fd`. After compilation, replacing the configured
source path cannot substitute a different mount root. A Bubblewrap build that
lacks those options fails the worker launch; Splash never retries with a
path-based bind. This mode alone does not freeze mutable descendants of a
pinned directory, the contents of a runtime tree, the Bubblewrap executable
selected by the host, or an already-open writable file. Those still require
immutable host ownership or a target-specific design.

## Verified Persistent Storage

`LinuxProjectQuota` is the supported persistent-storage boundary for a Linux
filesystem that implements generic project quotas and runs a kernel with
`quotactl_fd` (Linux 5.14 or later). The host provisions that filesystem before
it compiles a worker policy: assign a nonzero project ID to the exact root,
enable its project-inheritance flag, and set nonzero hard block and inode
limits. Splash does not create, resize, or repair the quota.

```rust
let durable_output = LinuxProjectQuota::new(
    42,                 // Host-provisioned filesystem project ID.
    256 * 1024 * 1024,  // Maximum accepted hard allocation limit in bytes.
    16_384,             // Maximum accepted hard inode limit.
)?;

policy.pin_mount_sources();
policy.require_no_further_user_namespaces();
policy.set_maximum_aggregate_linux_project_quota(
    256 * 1024 * 1024,
    16_384,
)?;
policy.add_file_root(
    "durable-output",
    FileRootBinding::new(
        "/srv/splash/worker-output",
        "/workspace/output",
        FileRootAccess::ReadWrite,
    )?
    .with_linux_project_quota(durable_output),
)?;
```

At `compile`, Splash opens a read-only directory descriptor relative to the
retained `O_PATH` mount descriptor, reads `FS_IOC_FSGETXATTR`, and calls
`quotactl_fd(Q_GETQUOTA, PRJQUOTA)` on that same filesystem. It fails closed
when the kernel or filesystem does not support either interface, permission is
missing, the project ID differs, inheritance is absent, a hard byte or inode
limit is zero or above the binding ceiling, usage already exceeds a hard limit,
or the kernel does not return complete quota accounting. Bubblewrap receives a
fresh duplicate of the retained mount descriptor, not the checked pathname.

Every active quota root needs `MountSourceBinding::DescriptorPinned`,
`require_no_further_user_namespaces`, and an aggregate maximum. The mandatory
user namespace prevents a worker that owns a mounted directory from changing
the project ID or inheritance state through the Linux filesystem-attribute
ioctls. Splash sums the hard limits of distinct `(filesystem, project ID)`
pairs exactly once, so several worker-visible directories under one project
consume one shared quota budget. A raw read-write host root is rejected while
this aggregate policy is enabled, even when
`allow_unbounded_host_file_root_writes` was called. `require_bounded_file_root_writes`
also accepts these verified roots when its user-namespace and private-`/tmp`
requirements are met.

This is filesystem enforcement after launch, but quota administration remains
trusted host responsibility. A separate privileged actor that can raise,
disable, or retag the project quota can weaken the boundary after compilation.
Project quotas are allocation and inode ceilings; they do not limit CPU,
memory, device access, process creation, network access, code execution,
downstream tool effects, or data written outside the selected project.

`ExecutableSourceBinding::DescriptorPinned` is a separate Linux opt-in for
the fixed launch chain. It requires `MountSourceBinding::DescriptorPinned`.
At `compile`, Splash retains the host Bubblewrap executable descriptor and
launches it through a fresh private `/proc/self/fd/N` path rather than the
configured pathname. It also retains each fixed worker and optional
`splash-limit-runner`, `splash-landlock-runner`, and each explicit Landlock
allowlist target file descriptor, then inserts a read-only `--ro-bind-fd` file
overlay at each exact worker-visible path after the runtime root mount. In
cgroup-v2 mode, Splash additionally opens and pins the selected cgroup runner
immediately after preparing the fresh child cgroup, and the runner preserves
the retained Bubblewrap descriptor while it `exec`s it. Replacing those selected
executable paths after their descriptors are retained cannot substitute a
different Bubblewrap, worker, pre-exec runner, explicit executable target, or
prepared cgroup runner. Unsupported descriptor bind or `/proc/self/fd`
execution fails the launch; there is no path-based retry.

This pins only the selected executable files. It does not pin shared libraries,
configuration, or any other mutable runtime descendant. It is not complete
code-loading or executable-path mediation: without the optional Landlock policy,
a compromised worker can still chain to another executable deliberately exposed
by its runtime mounts, and a worker that can write an executable into an
exposed writable mount can still invoke it. Hosts must keep runtime trees
minimal and immutable when that stronger property matters.

`spawn_with_bootstrap` binds the bootstrap session ID to the manifest used at
`compile` before it launches Bubblewrap. It then writes and flushes a versioned,
non-JSON preamble to the private worker stdin pipe. A mismatch fails before
launch; a write failure kills and reaps the child. The session key never appears
in command-line arguments, environment variables, mount paths, Splash values,
capability selectors, or ordinary JSON frames.

The worker must read that preamble exactly once before it creates its JSON-line
reader, construct its worker `SessionAuthenticator`, and use it to verify the
one-way authenticated `open_session` frame. The host then wraps the returned
pipes in the bounded JSON-line transport and sends that frame with
`host_authenticator`. This is only delivery of a key that the host already
generated and trusts; it is not key exchange, encrypted transport, worker
attestation, or key storage.

## Cgroup-v2 Resource Boundary

For a Linux deployment that has a host-owned delegated cgroup-v2 parent, the
host can add controller limits to the complete Bubblewrap worker tree. The
parent and the runner are host paths: neither is a worker-visible runtime mount
or a Splash value.

```rust
use splash_sandbox::cgroup_v2::{
    CgroupV2IoDevice, CgroupV2IoMax, CgroupV2Limits, CgroupV2Policy,
};

let mut cgroup_limits = CgroupV2Limits::default();
cgroup_limits.set_cpu_quota_micros(50_000)?; // 50 ms per 100 ms period.
cgroup_limits.set_memory_max_bytes(512 * 1024 * 1024)?;
cgroup_limits.set_memory_swap_max_bytes(0)?; // Do not swap worker memory.
cgroup_limits.set_pids_max(64)?;
let mut io = CgroupV2IoMax::new(CgroupV2IoDevice::new(8, 16));
io.set_read_bytes_per_second(2 * 1024 * 1024)?;
io.set_write_operations_per_second(120)?;
cgroup_limits.add_io_max(io)?;

let cgroup_policy = CgroupV2Policy::new(
    "/sys/fs/cgroup/splash-workers",
    "/opt/splash/host-bin/splash-cgroup-runner",
    cgroup_limits,
)?;
let worker = command.spawn_with_bootstrap_in_cgroup(&cgroup_policy, &bootstrap)?;
let (lifecycle, worker_stdin, worker_stdout) = worker.into_lifecycle_parts();
```

When a deployment requires this launch path, set
`policy.require_cgroup_v2()` before `compile`. The resulting command rejects
the uncgrouped `spawn` and `spawn_with_bootstrap` methods on Linux; only
`spawn_in_cgroup` and `spawn_with_bootstrap_in_cgroup` can start it. The
requirement does not select limits itself: the trusted `CgroupV2Policy` above
must still contain at least one finite controller limit.

Build the bundled host-side runner on the target Linux platform with:

```sh
cargo build --locked -p splash-sandbox --bin splash-cgroup-runner --release
```

`CgroupV2Policy` verifies that its parent is mounted from cgroup v2 and exposes
the required core controls. It requires an existing cgroup-v2 parent owned by
the host. The host must delegate and enable every selected controller for its
children before launch. Splash intentionally does not write the parent's
`cgroup.subtree_control`, because changing that parent could alter resource
policy for unrelated workloads. Preparation creates a fresh child, writes the
selected controller values, and fails before launch if a control file or
`cgroup.kill` is unavailable. The runner must be an immutable, host-trusted
regular executable; it is not mounted into the worker.

The fixed runner writes its own PID to the fresh child's `cgroup.procs` before
it `exec`s Bubblewrap. Bubblewrap and every later descendant therefore inherit
the cgroup without a post-spawn migration race. Before it executes Bubblewrap,
the runner marks every inherited descriptor from 3 onward close-on-exec,
preserving only selected launch-only seccomp and descriptor-pinned mount
descriptors. The cgroup path is not present in the Bubblewrap command line,
environment, Splash source, or worker protocol.

Before `spawn_in_cgroup` or `spawn_with_bootstrap_in_cgroup` returns a worker
handle, Splash observes the direct child PID in the fresh `cgroup.procs`. The
default bounded wait is five seconds and can be changed with
`CgroupV2Policy::set_join_timeout`; a runner that exits or does not join in time
is killed along with the prepared cgroup and the launch fails. This confirmation
prevents a host lifecycle operation from racing a runner that has not entered
the cgroup yet.

The current controller profile provides:

- `cpu.max` bandwidth with a fixed 100 ms period. A 50,000 microsecond quota
  permits up to half of one fair-scheduler CPU worth of bandwidth in each
  period; it is not a wall-clock deadline.
- `memory.max`, a memory-cgroup limit rather than an RSS-only metric. When this
  limit is selected Splash also writes `memory.oom.group=1`, so a cgroup OOM is
  handled as one worker-tree failure rather than leaving a partial tree.
- `memory.swap.max`, an independent swap hard limit. A value of zero prevents
  worker anonymous memory from being swapped out. Selecting it fails before
  launch on kernels or delegated memory controllers that do not expose the
  control.
- `pids.max`, a task limit for the subtree that includes threads.
- `io.max`, finite BPS and IOPS ceilings for an explicit trusted `major:minor`
  block device. The host can configure `rbps`, `wbps`, `riops`, and `wiops` in
  one policy; a zero value prohibits that class of I/O. The kernel may allow
  short bursts. Buffered-write attribution requires cgroup writeback support in
  the underlying filesystem; without it, writeback I/O is attributed to the
  root cgroup.

Managed `BubblewrapWorkerLifecycle::terminate` and the watchdog call
`cgroup.kill` before reaping the direct Bubblewrap child, closing the descendant
fork race that `Child::kill` alone cannot cover. They then remove the empty
cgroup. A cgroup kill or cleanup failure is returned as a lifecycle error and
must be treated as a containment failure. Keep cgroup-backed workers in their
managed lifecycle; `SpawnedBubblewrapWorker::into_parts` and
`BubblewrapWorkerLifecycle::into_child` deliberately relinquish that
process-tree teardown and cleanup handle.

This is not an aggregate-disk, device, or network policy. Per-device `io.max`
is not a filesystem quota, and neither controller proves an adapter effect was
cancelled or rolled back. A Bubblewrap watchdog can separately enforce a
host-selected session-wide wall-clock deadline. See the Linux [cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
for the kernel controller semantics.

## Host Wall-Clock Watchdog

For a synchronous JSON-line worker, enable both
`splash-capabilities/json-line-worker` and
`splash-capabilities/bubblewrap-watchdog`. Move the spawned worker directly
into the watchdog before sending effectful work, then wrap the authenticated
transport:

```rust
use std::io::BufReader;
use std::time::Duration;

use splash_capabilities::bounded_worker::{
    BoundedWorkerTransport, WorkerInvocationDeadline,
};
use splash_capabilities::json_line_worker::{
    AuthenticatedFrameWorkerTransport, JsonLineWorkerChannel, WorkerFrameChannel,
};
use splash_capabilities::WorkerMessage;
use splash_sandbox::bubblewrap::BubblewrapWorkerSessionDeadline;

let session_deadline = BubblewrapWorkerSessionDeadline::new(Duration::from_secs(300))?;
let (watchdog, worker_stdin, worker_stdout) =
    worker.into_session_watchdog_parts(session_deadline)?;
let stop = watchdog.control(); // Trusted host lifecycle control only.
let mut channel = JsonLineWorkerChannel::new(BufReader::new(worker_stdout), worker_stdin);
let opening = host_authenticator.seal(WorkerMessage::OpenSession {
    manifest: attenuated_manifest.clone(),
})?;
channel.send_frame(opening)?;
let transport = AuthenticatedFrameWorkerTransport::new(host_authenticator, channel)?;
let deadline = WorkerInvocationDeadline::new(Duration::from_secs(30))?;
let transport = BoundedWorkerTransport::new(transport, watchdog, deadline);
```

`BoundedWorkerTransport` arms the watchdog before it sends each synchronous
`invoke` frame and disarms it only after the frame transport has returned. The
session deadline starts when the worker process is spawned, remains active
while the worker is idle or serving an invocation, and the direct handoff above
starts the watchdog before either pipe is returned. On either deadline expiry,
the watchdog force-stops and reaps Bubblewrap while the caller can still be
blocked reading a pipe. `stop.terminate()` performs the same process operation
for a host cancellation decision. Neither path writes `WorkerMessage::Cancel`,
waits for a worker acknowledgement, or establishes that an adapter effect did
not happen. A per-call timeout, session expiry, or force-stop always poisons
the session and produces an indeterminate transport error, even when a result
races with termination. Discard the session; use the durable reconciliation or
compensation path before deciding how to recover an effect.

The watchdog bounds host wall-clock time, not the worker's aggregate disk or
device use or an adapter's downstream I/O. Keep cgroup-backed workers in their
managed lifecycle when process-tree teardown is required. Both deadlines are
trusted host configuration and are never Splash values.

## Authenticated Cooperative Cancellation

For one explicitly cancellable ordinary invocation, enable
`splash-capabilities/json-line-worker` and
`splash-capabilities/bubblewrap-watchdog`. The worker must read the private
bootstrap, authenticate `open_session`, and run
`CancellableWorkerSessionDriver` with a manifest whose adapters were all
registered through `register_cancellable`.

The host hands the same watchdog and private pipes to the multiplexed
transport. Unlike the synchronous wrapper above, the transport retains a
single authenticated writer owner and a single authenticated reader owner, so
the event loop can send `cancel` while the adapter thread runs:

```rust
use std::io::BufReader;
use std::time::Duration;

use splash_capabilities::bounded_worker::WorkerInvocationDeadline;
use splash_capabilities::bubblewrap_watchdog::BubblewrapMultiplexedWorkerSession;
use splash_capabilities::multiplexed_worker::MultiplexedAuthenticatedWorkerTransport;
use splash_sandbox::bubblewrap::BubblewrapWorkerSessionDeadline;

let session_deadline =
    BubblewrapWorkerSessionDeadline::new(Duration::from_secs(300))?;
let (watchdog, worker_stdin, worker_stdout) =
    worker.into_session_watchdog_parts(session_deadline)?;
let transport = MultiplexedAuthenticatedWorkerTransport::new(
    attenuated_manifest,
    host_authenticator,
    BufReader::new(worker_stdout),
    worker_stdin,
)?;
let call_deadline = WorkerInvocationDeadline::new(Duration::from_secs(30))?;
let mut session =
    BubblewrapMultiplexedWorkerSession::new(transport, watchdog, call_deadline)?;

session.start_external_tool(&claimed_invocation, "invoke-1")?;
let request = runtime.request_external_tool_cancellation(claimed_invocation.id)?;
session.request_external_tool_cancellation(&request, "cancel-1")?;
// Poll `session.poll_external_tool(&mut runtime)` from the trusted event loop.
```

For an external workflow step, enable `splash-workflow/multiplexed-worker` and
use its `request_external_tool_cancellation` and `poll_external_tool` helpers.
They apply terminal events through `WorkflowEngine`; calling
`engine.runtime_mut()` would bypass retained-step bookkeeping.

The call deadline is armed before `invoke` is written and disarmed before a
result or positive acknowledgement reaches the runtime. The transport and
watchdog session IDs must match. A valid `acknowledged` disposition is accepted
only from the exact authenticated request and only when the watchdog reports
that lifecycle termination did not win. `too_late` requires the ordinary
result first; `unsupported` leaves the invocation active.

Bubblewrap containment does not make an adapter honestly cancellable. The
reviewed Rust adapter may acknowledge only after it has stopped its own effect
and downstream I/O and can guarantee no normal result follows. A watchdog
deadline, `cgroup.kill`, pipe EOF, worker crash, transport error, or explicit
host termination remains indeterminate and poisons the session. Durable
dispatch, compensation, and reconciliation continue to use their journaled
fresh-session recovery path.

## Durable Post-Stop Reconciliation

The optional `splash-workflow/bubblewrap-recovery` feature composes the
launcher, private bootstrap, watchdog, one-shot durable transport, workflow
ledger, and fenced authenticated store for one recovery attempt. It requires a
`BubblewrapWorkerReaped` proof from the old lifecycle, refuses the old session
ID and broad recovery manifests, launches a fresh contained worker, sends only
one reconciliation request, reaps that worker, and commits the observation by
fenced compare-and-swap.

Use `FreshBubblewrapRecoverySession::generate_in_cgroup` when the deployment
requires cgroup-v2 limits; the coordinator never silently replaces that choice
with an uncgrouped launch. See
[Bubblewrap post-stop recovery](bubblewrap-recovery.md) for the complete API,
ordering, retry behavior, and non-guarantees.

`enable_private_tmpfs_with_maximum_bytes` emits `--size BYTES` immediately
before `--tmpfs /tmp`. Bubblewrap enforces that maximum only for allocations in
this private `/tmp`; it is not a general process-memory, CPU, process-count, or
disk quota. Zero and sizes above Bubblewrap's supported maximum are rejected
rather than silently requesting an unbounded or launch-failing policy. Hosts
that enable it must use a Bubblewrap version that
supports `--size`; an unsupported option is a launch failure, never a fallback
to an unbounded worker.

`EphemeralFileRoot` applies the same bounded `tmpfs` primitive to an opaque,
manifest-selected `file_root` at any valid host-configured worker destination.
The compiler emits one contiguous `--size BYTES --tmpfs DESTINATION` sequence
for each active root. It validates that destination in the same mount layout as
runtime mounts, host-backed roots, `/proc`, `/dev`, and an optional private
`/tmp`, so a scratch mount cannot shadow another selected path. The root starts
empty and disappears with the worker mount namespace. Its ceiling is aggregate
for data blocks in that mount, but it does not independently cap inode count or
directory-entry metadata. Separate active roots retain independent Bubblewrap
ceilings. A host can opt into
`set_maximum_aggregate_ephemeral_tmpfs_bytes`, which rejects compilation when
the sum of active selected ephemeral-root ceilings and a bounded private `/tmp`
would exceed the configured maximum; it also rejects an unbounded private
`/tmp`. This is a compile-time bound on potential data-block capacity, not a
shared runtime disk quota: unused capacity is not pooled and no filesystem
quota mediates concurrent writers. A tmpfs can consume memory or swap, so use
cgroup memory and swap controls when those resources and metadata also need a
hard limit. Never use an ephemeral root for a durable worker journal or effect
record. Bubblewrap's tmpfs mount is `nosuid,nodev`, but it is not an
executable-path policy or a guaranteed `noexec` mount. A compromised worker can
write an executable file there and invoke it when the exposed runtime and
syscall policy permit. Keep the fixed worker free of subprocess behavior or add
a separately reviewed execution mediator; rejecting an `executable` selector
does not prevent a native worker from calling `execve`.

`BubblewrapWorkerPolicy` also bounds mount-plan expansion to 64 unique active
`file_root` selectors by default. It unions grants first, then rejects a plan
over that count before resolving any selected host source or constructing
Bubblewrap mount arguments. A host can lower the bound, including to zero, or
explicitly raise it with `set_maximum_active_file_roots`, but never above 256.
This does not limit inactive registered roots, trusted runtime mounts, manifest
or wire size, filesystem data blocks, inode use, or persistent storage.

`require_bounded_file_root_writes` is an additional compile-time hardening
mode. The default already rejects active host-backed read-write roots; this
mode also rejects every unverified persistent root and an enabled unbounded
private `/tmp`, requires
`require_no_further_user_namespaces`, and non-recursively remounts `/proc`,
`/dev`, and `/` read-only after constructing the selected mounts. A disabled or
explicitly bounded `/tmp` remains valid, as does a verified Linux project-quota
root. The mode overrides `allow_unbounded_host_file_root_writes`, so it cannot
be weakened by a later host configuration call. Device and proc interfaces
remain available under their kernel semantics. The mode does not constrain
process memory or downstream adapter effects. Any unsupported Bubblewrap
lockdown option is a launch failure; there is no weaker fallback.

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

This compatibility profile is defense in depth, not a general syscall
sandbox. It deliberately allows `execve`, because Bubblewrap applies the
filter before the optional trusted pre-exec runner must execute the fixed
worker. It also permits every syscall outside the fixed deny set, including
future kernel interfaces. It cannot mediate networking or make a capability
decision. Keep runtime mounts minimal and immutable and retain the
no-host-network namespace. Bubblewrap requires `no_new_privs` before it
installs the filter, so a worker cannot weaken it by adding another seccomp
program; a worker may still add a stricter filter of its own.

### Landlock Filesystem-Backed Executable Allowlist

`LandlockExecutableRunner` is an optional Linux-only pre-exec boundary for a
fixed worker launch chain. Build the bundled runner on the target platform:

```sh
cargo build --locked -p splash-sandbox --bin splash-landlock-runner --release
```

Deploy it in a read-only runtime mount at a path distinct from the worker and
any `splash-limit-runner`. At compilation, Splash requires the runner and every
explicit additional target to be a regular executable through that same
read-only mount. The final command starts `splash-landlock-runner` with a
deterministic list containing the fixed worker, an optional resource-limit
runner, and any host-configured additions. For each dynamically linked inner
worker or resource-limit runner, the host must also add its resolved regular
ELF loader path from the deployed runtime; the loader itself is executed during
that inner kernel launch chain.
Do not add a symlink path: use the resolved regular file that the read-only
runtime mount exposes. Splash source, tool payloads, selectors, manifests, and
worker input cannot add a path or choose the inner command. The runner repeats
the final-component regular-file and executable checks through an
`O_PATH | O_NOFOLLOW` descriptor before it creates rules.

The runner handles only `LANDLOCK_ACCESS_FS_EXECUTE` and adds one exact
filesystem object rule per allowed program. It requests Landlock as a hard
requirement, checks that the resulting ruleset is fully enforced with
`no_new_privs`, marks nonstandard inherited descriptors close-on-exec, then
replaces itself only with an allowed inner command. Unsupported or disabled
Landlock, an incomplete ruleset, a malformed invocation, or a setup failure
stops worker startup; there is no direct-worker fallback. Landlock rules are
inherited by descendants. The [Linux Landlock API documentation](https://docs.kernel.org/userspace-api/landlock.html)
defines this filesystem `EXECUTE` action and its kernel limitations.

With `ExecutableSourceBinding::DescriptorPinned`, Splash also overlays the
Landlock runner and every explicit allowed target from retained descriptors,
not merely the fixed worker. This prevents a host-path replacement after policy
compilation from changing the selected object. It does not freeze libraries or
other runtime files below a pinned directory, so production deployments still
need immutable runtime ownership.

This is deliberately narrower than a complete code-execution policy:

- It controls the Landlock filesystem-execute action, not arbitrary process
  behavior, networking, origin egress, devices, capability grants, or secret
  delivery.
- The resolved dynamic loader needs an explicit execute rule for each
  dynamically linked inner worker or resource-limit runner, but this policy
  does not restrict its library reads. It also does not restrict reads used by
  plugins, bytecode engines, or JITs. An allowed interpreter can execute code
  it reads, and an allowed binary can load code as data. Keep those inputs out
  of the runtime mount or control them with separate policies.
- It must not be treated as complete mediation for special filesystems,
  pre-opened descriptors, or future execution mechanisms; layer mount,
  descriptor, cgroup, and syscall controls appropriate to the deployment.
- It cannot currently be combined with
  `WorkerSeccompProfile::StrictAllowlist`. Bubblewrap attaches that filter
  before this runner runs, while the runner needs Landlock setup syscalls and a
  separate pre-exec syscall policy does not exist yet. Compilation rejects the
  combination. `DenyKnownEscapeSurface` remains compatible because it is
  default-allow outside its fixed escape-surface deny set.

### Strict Worker Syscall Allowlist

`WorkerSeccompAllowlist` is the independent strict profile for a particular
trusted worker runtime. A host constructs it from a bounded set of raw syscall
numbers for the current Linux ABI, then installs it atomically with
`BubblewrapWorkerPolicy::set_seccomp_allowlist`. It is not serializable Splash
configuration, LLM output, worker input, or caller-provided cBPF. Empty,
duplicate, and more-than-512-entry lists are rejected; selecting
`WorkerSeccompProfile::StrictAllowlist` without using that setter fails policy
compilation rather than falling back to the default-allow profile.

The strict filter performs the same ABI and x32 checks as the compatibility
profile, applies the fixed escape-surface guards first, then returns `ALLOW`
only for an entry in the host list. Every other syscall returns
`SECCOMP_RET_KILL_PROCESS`. Policy compilation rejects a list that contains an
unconditionally blocked x32 ABI number, `clone3`, or a fixed mount,
kernel-control, tracing, cross-process-memory, keyring, or `personality`
syscall. The remaining argument-sensitive fixed guards still take precedence:
namespace-creating legacy `clone` calls and `TIOCSTI` return `EPERM` even when
the host lists ordinary `clone` or `ioctl`.

A strict list must cover the entire post-filter execution path: Bubblewrap's
fixed `execve`, any selected `splash-limit-runner`, the dynamic loader, and the
exact fixed worker and libraries. It cannot currently select a
`splash-landlock-runner`; policy compilation rejects that ordering conflict.
Build and test it per target ABI with the same immutable runtime mounts deployed
to production. Splash does not infer a list from source, profile a worker at
runtime, or widen a list after launch. Policy compilation explicitly rejects a
list without Bubblewrap's required `execve`; any other incomplete list stops
the worker rather than weakening containment.

This is a syscall boundary, not executable-path mediation. A working strict
profile normally has to allow an execution syscall, so a compromised worker
can still chain to another executable deliberately exposed in a runtime mount.
Mount layout and a separately designed executable policy remain responsible for
that authority. The strict profile likewise does not mediate a network origin,
D-Bus, device access, secrets, or capability grants.

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

`RLIMIT_CPU` does not terminate a sleeping or blocked worker. The optional
watchdog above supplies a host wall-clock process deadline for the bounded
transport path. It force-stops and reaps the Bubblewrap child when its deadline
or trusted host control wins; that is not authenticated in-band cancellation
and cannot establish whether an adapter effect began or completed. Hosts that
do not use the watchdog must independently schedule
`BubblewrapWorkerLifecycle::terminate()` on a monotonic timer, discard the
session afterward, and reconcile any durable effect. The runner itself does
not create a timer or turn process termination into a worker acknowledgement.

`compile` canonicalizes the source paths and fails closed when a source is
missing, is the wrong type, resolves to `/`, overlaps another worker-visible
destination, or conflicts with `/proc`, `/dev`, or an enabled private `/tmp`.
The resulting command uses:

- `--unshare-all`, so it does not retain the host network namespace;
- unconditional `--cap-drop ALL`, so even a host that launches Bubblewrap as
  root does not pass Linux capabilities into the fixed worker;
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
  read-write file roots. With `DescriptorPinned`, the corresponding launch
  instead uses `--ro-bind-fd` or `--bind-fd` with a host-held descriptor; and
- optional descriptor-pinned Bubblewrap execution through a launch-only
  `/proc/self/fd/N` path. When selected together with descriptor-pinned mount
  roots, Splash also adds final read-only `--ro-bind-fd` overlays for the
  fixed worker and optional limit runner files; and
- optional `--size BYTES` immediately before a private `--tmpfs /tmp`, limiting
  only allocations in that mount; and
- manifest-selected `--size BYTES --tmpfs DESTINATION` pairs for bounded
  ephemeral file roots; and
- optional final `--remount-ro /proc`, `--remount-ro /dev`, and
  `--remount-ro /` operations in bounded-write mode, leaving selected
  submounts under their independently compiled access policies; and
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
  policy. A host-backed source must be a directory, and its access mode is
  selected by the host binding. An active read-write host binding is rejected
  unless it is a verified Linux project-quota root or host configuration
  explicitly acknowledges an independently enforced quota through the weaker
  escape hatch. A bounded ephemeral entry has no host source; it creates an
  empty writable `tmpfs` for that worker session. Both kinds share one selector
  namespace, so a duplicate ID is rejected rather than resolved ambiguously.
  Hosts should use distinct opaque IDs for read-only and read-write views of
  the same host source.
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

The fixed worker program is not an executable-path policy. A trusted adapter
cannot receive a script-selected executable through this backend, but a
compromised worker can still execute or read any file deliberately exposed in
a runtime mount and can create executable content in a writable ephemeral root.
The command drops every Linux capability before worker execution, including
when the host launches Bubblewrap as root; a worker that needs a privileged
operation must use a narrower separately mediated adapter, not regain an
ambient capability. `DenyKnownEscapeSurface` protects only its explicit
default-allow deny set; `StrictAllowlist` reduces the syscall surface but
normally needs an execution syscall itself. Hosts must keep runtime mounts
minimal and immutable and use a separately designed executable policy where
executable chaining must be mediated.

## Non-Guarantees

This backend is Linux-only and fails rather than falling back to an unrestricted
process on every other target. It is not available for mobile or embedded
profiles; those profiles currently use static, app-provided in-process adapters
under their platform's own application sandbox.

It does not yet provide:

- worker attestation, authenticated key exchange, encrypted transport, or
  session-key storage. The private-pipe preamble only transfers a
  host-generated key to a newly launched worker;
- portable aggregate quotas for persistent host-backed storage or device
  quotas. Linux generic project quotas provide the documented descriptor-pinned
  boundary only when the host provisions a supporting filesystem and protects
  quota administration. Other persistent filesystems and every non-Linux
  target remain without this boundary. An optional cgroup-v2 policy adds CPU
  bandwidth, memory, swap, task, and per-device I/O controls; it is not a
  filesystem quota. An optional runner adds the narrower rlimits. A configured
  private `/tmp` and each active ephemeral root have independent per-`tmpfs`
  allocation ceilings; a host can validate their aggregate potential capacity
  before launch, but there is no shared tmpfs runtime quota. The watchdog adds
  a process-lifetime wall-clock deadline;
- D-Bus mediation, device-specific policy, an executable-path policy, or a
  network proxy. `DenyKnownEscapeSurface` is a narrow default-allow hardening
  filter, while `StrictAllowlist` is a target-specific syscall boundary, not a
  replacement for any of these;
- a safe per-origin network allowlist, arbitrary executable selection, secret
  broker, or filesystem access outside registered directory roots;
- universal cancellation for synchronous, durable, or arbitrary adapters. The
  optional multiplexed protocol delivers one authenticated ordinary-call
  request only to explicitly cancellable adapters. The watchdog remains a
  force-stop, not proof of cancellation. The optional workflow recovery
  coordinator automates a narrow reconciliation-only post-stop sequence but
  does not supply durable worker journal storage, retry effects, select
  compensation, or resume a workflow; and
- protection from changes to files inside a mounted directory, an interpreter,
  dynamic loader, shared-library tree, runtime configuration, or the behavior
  of a writable host-backed root. `MountSourceBinding::DescriptorPinned`
  prevents replacement of selected mount roots. Combined with
  `ExecutableSourceBinding::DescriptorPinned`, Splash also pins the selected
  Bubblewrap, worker, optional limit-runner, and freshly prepared cgroup-runner
  executable files. Policy sources and runtime contents still need immutable
  host ownership when that is part of the product security model.

The default user-namespace policy retains Bubblewrap's best-effort
`--unshare-all` behavior. Hosts requiring prevention of further user namespace
creation must select `require_no_further_user_namespaces` and treat a failed
worker or authenticated-session startup as a hard failure, never as a reason
to run the worker outside Bubblewrap.

Do not expose plan paths or launch errors to a script or LLM. A host must treat
any launch, transport, authentication, or worker failure as a reason to discard
the worker session and use the existing replay/reconciliation protocol rather
than reusing the same stream.
