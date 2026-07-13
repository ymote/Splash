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
policy.enable_private_tmpfs_with_maximum_bytes(64 * 1024 * 1024)?;

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
- `--clearenv`, so worker startup does not inherit host environment variables;
- `--new-session` and `--die-with-parent` for terminal isolation and parent
  lifecycle binding;
- `--chdir /`, so worker startup does not inherit the host process's current
  directory;
- explicit `--ro-bind` runtime and read-only file roots, or explicit `--bind`
  read-write file roots; and
- optional `--size BYTES` immediately before a private `--tmpfs /tmp`, limiting
  only allocations in that mount; and
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
runtime mount. Hosts must keep runtime mounts minimal and immutable. Preventing
unexpected `execve` or other syscalls requires a separately designed seccomp
policy and remains future work.

## Non-Guarantees

This backend is Linux-only and fails rather than falling back to an unrestricted
process on every other target. It is not available for mobile or embedded
profiles; those profiles currently use static, app-provided in-process adapters
under their platform's own application sandbox.

It does not yet provide:

- worker attestation, authenticated key exchange, encrypted transport, or
  session-key storage. The private-pipe preamble only transfers a
  host-generated key to a newly launched worker;
- CPU, process-memory, process-count, or broader disk quotas. A configured
  private `/tmp` size limits only that Bubblewrap `tmpfs`; hosts still need
  cgroups, rlimits, or an equivalent platform policy for broader resources;
- seccomp policy, D-Bus mediation, device-specific policy, or a network proxy;
- a safe per-origin network allowlist, arbitrary executable selection, secret
  broker, or filesystem access outside registered directory roots;
- authenticated in-band cancellation delivery, I/O deadlines, post-exit
  reconciliation, or durable operation storage. `lifecycle.terminate()` is a
  forceful process stop, not proof that an adapter effect was cancelled; and
- protection from a trusted host changing a policy source path between plan
  compilation and process start. Policy sources must be owned and immutable to
  untrusted actors, or a future descriptor-based launcher must be used.

Do not expose plan paths or launch errors to a script or LLM. A host must treat
any launch, transport, authentication, or worker failure as a reason to discard
the worker session and use the existing replay/reconciliation protocol rather
than reusing the same stream.
