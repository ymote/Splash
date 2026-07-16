//! Linux Bubblewrap containment policy for a static Splash worker.
//!
//! This backend constructs a new mount namespace from an explicit allowlist.
//! It does not accept arbitrary script-provided paths, executables, origins,
//! secrets, or keys. A policy covers one whole worker session, so hosts that
//! need operating-system isolation per tool call must create a narrower
//! attenuated worker session for that call.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, ExitStatus};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::cgroup_v2::{
    CgroupV2Policy, CgroupV2PrepareError, CgroupV2Session, CgroupV2SessionError,
};

#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::process::{ChildStderr, Command, Stdio};

#[cfg(target_os = "linux")]
use rustix::{
    fs::{fstat, open, FileType, Mode, OFlags},
    io::{fcntl_dupfd_cloexec, fcntl_setfd, FdFlags},
};
use splash_protocol::{
    CapabilityManifest, PrivatePipeWorkerBootstrap, PrivatePipeWorkerBootstrapError, ProtocolError,
    ResourceKind, ResourceSelector,
};

const MAX_TMPFS_BYTES: usize = usize::MAX >> 1;
const MAX_FINITE_RESOURCE_LIMIT: u64 = u64::MAX - 1;
const MAX_LINUX_SECCOMP_FILTER_INSTRUCTIONS: usize = 4_096;

/// Upper bound for syscalls in one strict worker seccomp policy.
///
/// The cap keeps the generated cBPF program comfortably below Linux's 4,096
/// instruction limit even after Splash's fixed ABI and escape-surface guards.
pub const MAX_WORKER_SECCOMP_ALLOWLIST_SYSCALLS: usize = 512;

/// Access mode for a host-selected file-root binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRootAccess {
    ReadOnly,
    ReadWrite,
}

/// How Bubblewrap receives trusted host mount roots at launch.
///
/// This is host-only containment configuration. It is never serialized into a
/// Splash capability manifest or selected by generated source.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum MountSourceBinding {
    /// Pass canonicalized host paths to Bubblewrap at launch.
    #[default]
    Path,
    /// Retain each selected mount-root descriptor after compilation and pass a
    /// launch-only duplicate to Bubblewrap's `--bind-fd` or `--ro-bind-fd`.
    ///
    /// This is available only on Linux and requires a Bubblewrap build with
    /// those options. There is no fallback to path-based binds. It pins the
    /// mounted root's identity after compilation, but it does not freeze
    /// mutable descendants inside a mounted directory.
    DescriptorPinned,
}

/// How the fixed host and worker executables retain their identities between
/// policy compilation and process launch.
///
/// This is host-only containment configuration. It is never serialized into a
/// Splash capability manifest or selected by generated source.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExecutableSourceBinding {
    /// Resolve the configured executable paths during policy compilation and
    /// execute or mount those paths at launch.
    #[default]
    Path,
    /// On Linux, retain the Bubblewrap executable's descriptor at compilation,
    /// launch it through a private `/proc/self/fd` path, and bind retained
    /// worker and limit-runner file descriptors over their runtime paths.
    ///
    /// This requires [`MountSourceBinding::DescriptorPinned`] so the runtime
    /// root has the same launch-only binding. It pins the selected executable
    /// files after compilation, but it does not freeze dynamic libraries or
    /// other mutable descendants of a mounted runtime tree. There is no
    /// fallback to path-based executable launch or file binds.
    DescriptorPinned,
}

/// User-namespace hardening selected for a Bubblewrap worker.
///
/// [`Self::RequireNoFurtherUserNamespaces`] makes Bubblewrap require a new
/// user namespace and then prevents the worker from creating more user
/// namespaces. Bubblewrap may create a nested namespace internally while
/// establishing that restriction, so this is not a claim that the worker is
/// never inside a nested namespace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum UserNamespacePolicy {
    /// Retains Bubblewrap's `--unshare-all` best-effort user-namespace setup.
    #[default]
    BestEffort,
    /// Requires Bubblewrap to prevent further user namespaces for the worker.
    RequireNoFurtherUserNamespaces,
}

/// Seccomp hardening selected for a Bubblewrap worker.
///
/// This is trusted host configuration, not a script-facing policy language.
/// [`Self::DenyKnownEscapeSurface`] is intentionally a default-allow cBPF
/// filter: it denies a reviewed set of namespace, mount, kernel-control,
/// tracing, keyring, and terminal-injection operations while preserving the
/// broad syscall compatibility required by a dynamic worker.
/// [`Self::StrictAllowlist`] instead allows only a bounded, host-reviewed
/// [`WorkerSeccompAllowlist`] and kills every other syscall. Both profiles are
/// defense in depth, not a capability mechanism or a complete syscall sandbox.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum WorkerSeccompProfile {
    /// Do not pass a seccomp program to Bubblewrap.
    #[default]
    Disabled,
    /// Denies a fixed, Splash-owned set of common sandbox-escape operations.
    ///
    /// The profile verifies the syscall ABI, kills an x86-64 x32 ABI attempt,
    /// returns `EPERM` for its denied operations, and returns `ENOSYS` for
    /// `clone3` so common libc implementations can use legacy `clone`.
    /// Legacy `clone` remains available for processes and threads but is
    /// rejected when it requests any namespace-creation flag. Applications
    /// that require `clone3` must not enable this profile: its flags are
    /// indirect and cannot be inspected by the cBPF hardening layer.
    DenyKnownEscapeSurface,
    /// Allows only the host-configured [`WorkerSeccompAllowlist`].
    ///
    /// The filter still performs Splash's ABI/x32 checks and rejects the fixed
    /// namespace, kernel-control, tracing, keyring, and terminal-injection
    /// escape surface before it consults the selected allowlist. Every other
    /// syscall kills the worker. Use
    /// [`BubblewrapWorkerPolicy::set_seccomp_allowlist`] to select this mode;
    /// choosing it through [`BubblewrapWorkerPolicy::set_seccomp_profile`]
    /// without a list makes policy compilation fail closed.
    StrictAllowlist,
}

/// Trusted host-selected syscall numbers for a strict worker seccomp policy.
///
/// The numbers target the current Linux syscall ABI. They are intentionally
/// neither Splash values nor serializable policy: a host must construct and
/// review them alongside the exact Bubblewrap, optional pre-exec runner, and
/// fixed worker executable it will run. The list is sorted before compilation
/// so its cBPF representation is deterministic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerSeccompAllowlist {
    syscalls: BTreeSet<u32>,
}

impl WorkerSeccompAllowlist {
    /// Creates a bounded strict allowlist from raw Linux syscall numbers.
    ///
    /// Duplicate entries are rejected rather than silently deduplicated so a
    /// host review sees exactly the policy that will be installed. The list is
    /// never empty: an empty list can only produce a worker that dies before
    /// it can execute its fixed program.
    pub fn new<I>(syscalls: I) -> Result<Self, WorkerSeccompAllowlistError>
    where
        I: IntoIterator<Item = u32>,
    {
        let mut selected = BTreeSet::new();
        for syscall in syscalls {
            if selected.contains(&syscall) {
                return Err(WorkerSeccompAllowlistError::DuplicateSyscall { syscall });
            }
            if selected.len() == MAX_WORKER_SECCOMP_ALLOWLIST_SYSCALLS {
                return Err(WorkerSeccompAllowlistError::TooManySyscalls {
                    maximum: MAX_WORKER_SECCOMP_ALLOWLIST_SYSCALLS,
                });
            }
            selected.insert(syscall);
        }
        if selected.is_empty() {
            return Err(WorkerSeccompAllowlistError::Empty);
        }
        Ok(Self { syscalls: selected })
    }

    /// Returns the syscall count in this policy.
    pub fn len(&self) -> usize {
        self.syscalls.len()
    }

    /// Returns whether this policy contains no syscall numbers.
    ///
    /// Valid policies are never empty; this accessor exists for callers that
    /// retain a policy through a generic collection.
    pub fn is_empty(&self) -> bool {
        self.syscalls.is_empty()
    }

    /// Iterates the selected syscall numbers in ascending order.
    pub fn syscalls(&self) -> impl ExactSizeIterator<Item = u32> + '_ {
        self.syscalls.iter().copied()
    }
}

/// Rejection while constructing a strict worker seccomp allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WorkerSeccompAllowlistError {
    /// A strict worker policy needs at least one syscall.
    Empty,
    /// A syscall appeared more than once in the trusted configuration.
    DuplicateSyscall { syscall: u32 },
    /// The bounded cBPF policy would contain too many syscall entries.
    TooManySyscalls { maximum: usize },
}

impl Display for WorkerSeccompAllowlistError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("strict seccomp allowlist must not be empty"),
            Self::DuplicateSyscall { syscall } => {
                write!(
                    formatter,
                    "strict seccomp allowlist repeats syscall {syscall}"
                )
            }
            Self::TooManySyscalls { maximum } => write!(
                formatter,
                "strict seccomp allowlist exceeds its {maximum}-syscall limit"
            ),
        }
    }
}

impl std::error::Error for WorkerSeccompAllowlistError {}

/// One Linux resource controlled by [`WorkerResourceLimits`].
///
/// These names describe the corresponding `RLIMIT_*` resource, not a cgroup
/// policy. In particular, address space is not resident memory and process
/// count is not an isolated cgroup PID limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WorkerResourceLimit {
    CpuSeconds,
    AddressSpaceBytes,
    ProcessCount,
    OpenFiles,
    FileSizeBytes,
}

impl WorkerResourceLimit {
    const fn runner_option(self) -> &'static str {
        match self {
            Self::CpuSeconds => "--cpu-seconds",
            Self::AddressSpaceBytes => "--address-space-bytes",
            Self::ProcessCount => "--process-count",
            Self::OpenFiles => "--open-files",
            Self::FileSizeBytes => "--file-size-bytes",
        }
    }
}

impl Display for WorkerResourceLimit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.runner_option().trim_start_matches("--"))
    }
}

/// Rejection while configuring a finite worker resource limit.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WorkerResourceLimitError {
    InvalidMaximum {
        limit: WorkerResourceLimit,
        maximum: u64,
    },
}

impl Display for WorkerResourceLimitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaximum { limit, maximum } => write!(
                formatter,
                "{limit} maximum must be within 1..={MAX_FINITE_RESOURCE_LIMIT}; got {maximum}"
            ),
        }
    }
}

impl std::error::Error for WorkerResourceLimitError {}

/// Host-selected Linux rlimits applied by `splash-limit-runner` before worker
/// execution.
///
/// The runner installs each chosen value as both the soft and hard limit, and
/// disables core dumps. An unprivileged worker cannot raise its hard limits;
/// a process with `CAP_SYS_RESOURCE` in the initial user namespace can. Limits
/// are inherited across `exec` and child processes. They are deliberately
/// narrower than cgroups: CPU is cumulative CPU time, address space is virtual
/// address space, process count uses Linux's per-real-UID `RLIMIT_NPROC`, and
/// file size applies to individual files rather than aggregate writable
/// storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkerResourceLimits {
    cpu_seconds: Option<NonZeroU64>,
    address_space_bytes: Option<NonZeroU64>,
    process_count: Option<NonZeroU64>,
    open_files: Option<NonZeroU64>,
    file_size_bytes: Option<NonZeroU64>,
}

impl WorkerResourceLimits {
    /// Sets a cumulative CPU-time ceiling in seconds (`RLIMIT_CPU`).
    pub fn set_cpu_seconds(&mut self, maximum: u64) -> Result<&mut Self, WorkerResourceLimitError> {
        self.cpu_seconds = Some(validate_resource_limit(
            WorkerResourceLimit::CpuSeconds,
            maximum,
        )?);
        Ok(self)
    }

    /// Sets a virtual-address-space ceiling in bytes (`RLIMIT_AS`).
    pub fn set_address_space_bytes(
        &mut self,
        maximum: u64,
    ) -> Result<&mut Self, WorkerResourceLimitError> {
        self.address_space_bytes = Some(validate_resource_limit(
            WorkerResourceLimit::AddressSpaceBytes,
            maximum,
        )?);
        Ok(self)
    }

    /// Sets Linux's per-real-UID process-count ceiling (`RLIMIT_NPROC`).
    ///
    /// This counts threads for the real UID, can include processes outside the
    /// worker, and is not enforced for real UID 0 or processes with
    /// `CAP_SYS_ADMIN` or `CAP_SYS_RESOURCE`. It is not a per-sandbox process
    /// containment guarantee.
    pub fn set_process_count(
        &mut self,
        maximum: u64,
    ) -> Result<&mut Self, WorkerResourceLimitError> {
        self.process_count = Some(validate_resource_limit(
            WorkerResourceLimit::ProcessCount,
            maximum,
        )?);
        Ok(self)
    }

    /// Sets the maximum number of open file descriptors (`RLIMIT_NOFILE`).
    pub fn set_open_files(&mut self, maximum: u64) -> Result<&mut Self, WorkerResourceLimitError> {
        self.open_files = Some(validate_resource_limit(
            WorkerResourceLimit::OpenFiles,
            maximum,
        )?);
        Ok(self)
    }

    /// Sets the maximum size of one created file in bytes (`RLIMIT_FSIZE`).
    pub fn set_file_size_bytes(
        &mut self,
        maximum: u64,
    ) -> Result<&mut Self, WorkerResourceLimitError> {
        self.file_size_bytes = Some(validate_resource_limit(
            WorkerResourceLimit::FileSizeBytes,
            maximum,
        )?);
        Ok(self)
    }

    /// Returns the selected CPU-time ceiling.
    pub const fn cpu_seconds(&self) -> Option<NonZeroU64> {
        self.cpu_seconds
    }

    /// Returns the selected virtual-address-space ceiling.
    pub const fn address_space_bytes(&self) -> Option<NonZeroU64> {
        self.address_space_bytes
    }

    /// Returns the selected Linux per-real-UID process-count ceiling.
    pub const fn process_count(&self) -> Option<NonZeroU64> {
        self.process_count
    }

    /// Returns the selected open-file-descriptor ceiling.
    pub const fn open_files(&self) -> Option<NonZeroU64> {
        self.open_files
    }

    /// Returns the selected individual-file-size ceiling.
    pub const fn file_size_bytes(&self) -> Option<NonZeroU64> {
        self.file_size_bytes
    }

    fn is_empty(&self) -> bool {
        self.cpu_seconds.is_none()
            && self.address_space_bytes.is_none()
            && self.process_count.is_none()
            && self.open_files.is_none()
            && self.file_size_bytes.is_none()
    }

    fn append_runner_arguments(&self, arguments: &mut Vec<OsString>) {
        append_resource_limit(arguments, WorkerResourceLimit::CpuSeconds, self.cpu_seconds);
        append_resource_limit(
            arguments,
            WorkerResourceLimit::AddressSpaceBytes,
            self.address_space_bytes,
        );
        append_resource_limit(
            arguments,
            WorkerResourceLimit::ProcessCount,
            self.process_count,
        );
        append_resource_limit(arguments, WorkerResourceLimit::OpenFiles, self.open_files);
        append_resource_limit(
            arguments,
            WorkerResourceLimit::FileSizeBytes,
            self.file_size_bytes,
        );
    }
}

fn validate_resource_limit(
    limit: WorkerResourceLimit,
    maximum: u64,
) -> Result<NonZeroU64, WorkerResourceLimitError> {
    let Some(maximum) = NonZeroU64::new(maximum) else {
        return Err(WorkerResourceLimitError::InvalidMaximum { limit, maximum });
    };
    if maximum.get() > MAX_FINITE_RESOURCE_LIMIT {
        return Err(WorkerResourceLimitError::InvalidMaximum {
            limit,
            maximum: maximum.get(),
        });
    }
    Ok(maximum)
}

fn append_resource_limit(
    arguments: &mut Vec<OsString>,
    limit: WorkerResourceLimit,
    maximum: Option<NonZeroU64>,
) {
    let Some(maximum) = maximum else {
        return;
    };
    arguments.push(OsString::from(limit.runner_option()));
    arguments.push(OsString::from(maximum.get().to_string()));
}

/// A fixed executable inside the worker sandbox that installs
/// [`WorkerResourceLimits`] before it executes the configured worker.
///
/// Use the bundled `splash-limit-runner` binary or an equivalent reviewed
/// executable. The path is worker-visible, not a host source path; compilation
/// requires it to resolve through a read-only runtime mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceLimitRunner {
    program: PathBuf,
    limits: WorkerResourceLimits,
}

impl ResourceLimitRunner {
    /// Creates a typed resource-limit runner configuration.
    pub fn new(
        program: impl Into<PathBuf>,
        limits: WorkerResourceLimits,
    ) -> Result<Self, BubblewrapPolicyError> {
        let program = program.into();
        validate_sandbox_path("resource limit runner", &program)?;
        if limits.is_empty() {
            return Err(BubblewrapPolicyError::EmptyResourceLimits);
        }
        Ok(Self { program, limits })
    }

    /// Returns the worker-visible runner executable path.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Returns the typed limits the runner receives.
    pub fn limits(&self) -> &WorkerResourceLimits {
        &self.limits
    }
}

/// One trusted host path mounted read-only into a worker runtime.
///
/// Runtime mounts provide the fixed worker executable and the libraries it
/// needs. They are separate from capability-selected file roots so the worker
/// program can never be sourced from a writable grant. They must still be
/// minimal: the default-allow seccomp hardening profile intentionally permits
/// `execve`, so a compromised worker can execute or read files exposed by a
/// runtime mount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyMount {
    source: PathBuf,
    destination: PathBuf,
}

impl ReadOnlyMount {
    /// Creates a host-selected, read-only mount.
    pub fn new(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
    ) -> Result<Self, BubblewrapPolicyError> {
        let source = source.into();
        let destination = destination.into();
        validate_host_path("runtime mount source", &source)?;
        validate_sandbox_path("runtime mount destination", &destination)?;
        Ok(Self {
            source,
            destination,
        })
    }

    /// Returns the trusted host source path before canonicalization.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Returns the worker-visible absolute mount destination.
    pub fn destination(&self) -> &Path {
        &self.destination
    }
}

/// One host-selected directory exposed through a `file_root` selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileRootBinding {
    source: PathBuf,
    destination: PathBuf,
    access: FileRootAccess,
}

/// One empty, writable, manifest-selected `tmpfs` file root.
///
/// The root is private to one Bubblewrap worker mount namespace and disappears
/// with that worker. Its maximum is an aggregate data-block allocation ceiling
/// for this mount only; it is not an inode-count limit, persistent-filesystem
/// quota, or process-memory limit. The destination and maximum are trusted host
/// configuration, never Splash values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EphemeralFileRoot {
    destination: PathBuf,
    maximum_bytes: NonZeroUsize,
}

impl EphemeralFileRoot {
    /// Creates a bounded private file root at a worker-visible destination.
    pub fn new(
        destination: impl Into<PathBuf>,
        maximum_bytes: usize,
    ) -> Result<Self, BubblewrapPolicyError> {
        let destination = destination.into();
        validate_sandbox_path("ephemeral file-root destination", &destination)?;
        let Some(maximum_bytes) = NonZeroUsize::new(maximum_bytes) else {
            return Err(BubblewrapPolicyError::InvalidEphemeralFileRootSize { maximum_bytes });
        };
        if maximum_bytes.get() > MAX_TMPFS_BYTES {
            return Err(BubblewrapPolicyError::InvalidEphemeralFileRootSize {
                maximum_bytes: maximum_bytes.get(),
            });
        }
        Ok(Self {
            destination,
            maximum_bytes,
        })
    }

    /// Returns the worker-visible absolute mount destination.
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Returns the aggregate data-block allocation ceiling for this mount.
    pub const fn maximum_bytes(&self) -> usize {
        self.maximum_bytes.get()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RegisteredFileRoot {
    Host(FileRootBinding),
    Ephemeral(EphemeralFileRoot),
}

impl FileRootBinding {
    /// Creates a file-root binding for one opaque selector ID.
    pub fn new(
        source: impl Into<PathBuf>,
        destination: impl Into<PathBuf>,
        access: FileRootAccess,
    ) -> Result<Self, BubblewrapPolicyError> {
        let source = source.into();
        let destination = destination.into();
        validate_host_path("file-root source", &source)?;
        validate_sandbox_path("file-root destination", &destination)?;
        Ok(Self {
            source,
            destination,
            access,
        })
    }

    /// Returns the trusted host source path before canonicalization.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Returns the worker-visible absolute mount destination.
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Returns the mount access mode.
    pub const fn access(&self) -> FileRootAccess {
        self.access
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateTmpfs {
    Disabled,
    Unbounded,
    Bounded(NonZeroUsize),
}

impl PrivateTmpfs {
    const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    const fn maximum_bytes(self) -> Option<NonZeroUsize> {
        match self {
            Self::Bounded(maximum_bytes) => Some(maximum_bytes),
            Self::Disabled | Self::Unbounded => None,
        }
    }
}

/// Trusted configuration for one statically selected Bubblewrap worker.
///
/// This configuration is intentionally constructed by host Rust code. It is
/// not serializable configuration for generated Splash source. All executable
/// and host paths must be absolute. `compile` canonicalizes source paths and
/// requires their contents to exist. Path-bound sources still require immutable
/// host ownership between compilation and launch. Descriptor-bound sources fix
/// their selected inodes but do not freeze mutable runtime descendants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BubblewrapWorkerPolicy {
    bwrap_program: PathBuf,
    worker_program: PathBuf,
    worker_arguments: Vec<OsString>,
    runtime_mounts: Vec<ReadOnlyMount>,
    file_roots: BTreeMap<String, RegisteredFileRoot>,
    mount_source_binding: MountSourceBinding,
    executable_source_binding: ExecutableSourceBinding,
    private_tmpfs: PrivateTmpfs,
    bounded_file_root_writes_required: bool,
    user_namespace_policy: UserNamespacePolicy,
    resource_limit_runner: Option<ResourceLimitRunner>,
    seccomp_profile: WorkerSeccompProfile,
    seccomp_allowlist: Option<WorkerSeccompAllowlist>,
}

impl BubblewrapWorkerPolicy {
    /// Creates a policy for a fixed executable path inside the worker sandbox.
    ///
    /// `bwrap_program` is the host's absolute Bubblewrap executable. The
    /// `worker_program` is an absolute path in the new mount namespace and
    /// must be made visible by a read-only runtime mount before compilation.
    pub fn new(
        bwrap_program: impl Into<PathBuf>,
        worker_program: impl Into<PathBuf>,
    ) -> Result<Self, BubblewrapPolicyError> {
        let bwrap_program = bwrap_program.into();
        let worker_program = worker_program.into();
        validate_host_path("Bubblewrap program", &bwrap_program)?;
        validate_sandbox_path("worker program", &worker_program)?;
        Ok(Self {
            bwrap_program,
            worker_program,
            worker_arguments: Vec::new(),
            runtime_mounts: Vec::new(),
            file_roots: BTreeMap::new(),
            mount_source_binding: MountSourceBinding::Path,
            executable_source_binding: ExecutableSourceBinding::Path,
            private_tmpfs: PrivateTmpfs::Disabled,
            bounded_file_root_writes_required: false,
            user_namespace_policy: UserNamespacePolicy::BestEffort,
            resource_limit_runner: None,
            seccomp_profile: WorkerSeccompProfile::Disabled,
            seccomp_allowlist: None,
        })
    }

    /// Adds fixed arguments after the statically selected worker executable.
    ///
    /// Arguments are placed after Bubblewrap's `--` separator and are never
    /// derived from Splash source, a resource selector, or a tool payload.
    pub fn with_worker_arguments<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.worker_arguments = arguments.into_iter().map(Into::into).collect();
        self
    }

    /// Adds a trusted read-only runtime mount.
    pub fn add_runtime_mount(&mut self, mount: ReadOnlyMount) -> &mut Self {
        self.runtime_mounts.push(mount);
        self
    }

    /// Returns how this policy passes selected mount roots to Bubblewrap.
    pub const fn mount_source_binding(&self) -> MountSourceBinding {
        self.mount_source_binding
    }

    /// Selects how this policy passes selected mount roots to Bubblewrap.
    ///
    /// [`MountSourceBinding::DescriptorPinned`] is an opt-in Linux hardening
    /// mode. Compilation rejects it on other platforms, and launch never
    /// falls back to a path bind when Bubblewrap rejects a descriptor bind.
    pub fn set_mount_source_binding(&mut self, binding: MountSourceBinding) -> &mut Self {
        self.mount_source_binding = binding;
        self
    }

    /// Retains descriptor-pinned mount roots after a successful compilation.
    ///
    /// This is shorthand for selecting
    /// [`MountSourceBinding::DescriptorPinned`].
    pub fn pin_mount_sources(&mut self) -> &mut Self {
        self.set_mount_source_binding(MountSourceBinding::DescriptorPinned)
    }

    /// Returns how this policy retains fixed executable identities.
    pub const fn executable_source_binding(&self) -> ExecutableSourceBinding {
        self.executable_source_binding
    }

    /// Selects how this policy retains its fixed Bubblewrap, worker, and
    /// optional resource-limit-runner executables.
    ///
    /// [`ExecutableSourceBinding::DescriptorPinned`] is an opt-in Linux
    /// hardening mode. It requires [`MountSourceBinding::DescriptorPinned`]
    /// and fails closed when the required descriptor-based Bubblewrap options
    /// or `/proc/self/fd` execution are unavailable.
    pub fn set_executable_source_binding(&mut self, binding: ExecutableSourceBinding) -> &mut Self {
        self.executable_source_binding = binding;
        self
    }

    /// Retains descriptor-pinned fixed executable sources after successful
    /// compilation.
    ///
    /// This is shorthand for selecting
    /// [`ExecutableSourceBinding::DescriptorPinned`]. Call
    /// [`Self::pin_mount_sources`] as well; compilation rejects a policy that
    /// selects this mode without descriptor-pinned runtime roots.
    pub fn pin_executable_sources(&mut self) -> &mut Self {
        self.set_executable_source_binding(ExecutableSourceBinding::DescriptorPinned)
    }

    /// Registers one opaque `file_root` selector.
    ///
    /// Bindings absent from the active manifest are not mounted. Duplicate IDs
    /// are rejected so a policy cannot accidentally replace a prior binding.
    pub fn add_file_root(
        &mut self,
        id: impl Into<String>,
        binding: FileRootBinding,
    ) -> Result<&mut Self, BubblewrapPolicyError> {
        self.add_registered_file_root(id, RegisteredFileRoot::Host(binding))
    }

    /// Registers one bounded, empty `tmpfs` under an opaque `file_root` ID.
    ///
    /// The selector shares the same namespace as host-backed file roots, so a
    /// duplicate ID is rejected across both kinds. An absent selector creates
    /// no mount. An active root is writable, private to the worker session, and
    /// discarded when that mount namespace exits.
    pub fn add_ephemeral_file_root(
        &mut self,
        id: impl Into<String>,
        root: EphemeralFileRoot,
    ) -> Result<&mut Self, BubblewrapPolicyError> {
        self.add_registered_file_root(id, RegisteredFileRoot::Ephemeral(root))
    }

    fn add_registered_file_root(
        &mut self,
        id: impl Into<String>,
        root: RegisteredFileRoot,
    ) -> Result<&mut Self, BubblewrapPolicyError> {
        let id = id.into();
        ResourceSelector::new(ResourceKind::FileRoot, id.clone())
            .map_err(BubblewrapPolicyError::Protocol)?;
        if self.file_roots.contains_key(&id) {
            return Err(BubblewrapPolicyError::DuplicateFileRoot { id });
        }
        self.file_roots.insert(id, root);
        Ok(self)
    }

    /// Requires every active writable data mount configured by this policy to
    /// have an aggregate data-block allocation ceiling.
    ///
    /// Compilation then rejects host-backed read-write file roots and an
    /// unbounded private `/tmp`. Read-only host roots, bounded ephemeral roots,
    /// and a bounded private `/tmp` remain valid. Compilation also requires
    /// [`UserNamespacePolicy::RequireNoFurtherUserNamespaces`] so the worker
    /// cannot reacquire namespace-scoped mount authority. `/proc`, `/dev`, and
    /// the empty namespace root are remounted read-only after all selected
    /// mounts are created. This does not constrain process memory, device or
    /// proc semantics, or downstream effects performed by a trusted adapter.
    pub fn require_bounded_file_root_writes(&mut self) -> &mut Self {
        self.bounded_file_root_writes_required = true;
        self
    }

    /// Returns whether bounded writable data mounts are required.
    pub const fn bounded_file_root_writes_required(&self) -> bool {
        self.bounded_file_root_writes_required
    }

    /// Enables an empty private `tmpfs` at `/tmp` for the worker.
    ///
    /// It is disabled by default and remains unbounded when enabled through
    /// this method. Use [`Self::enable_private_tmpfs_with_maximum_bytes`] to
    /// set Bubblewrap's per-`tmpfs` allocation ceiling. Neither option limits
    /// process memory, CPU, process count, or writable mounts outside `/tmp`.
    pub fn enable_private_tmpfs(&mut self) -> &mut Self {
        self.private_tmpfs = PrivateTmpfs::Unbounded;
        self
    }

    /// Enables a private `/tmp` with a maximum Bubblewrap `tmpfs` allocation.
    ///
    /// The size is an OS-enforced ceiling only for this `tmpfs` mount. It does
    /// not create a general worker memory, CPU, process-count, or disk quota.
    /// Zero and values larger than Bubblewrap accepts are rejected rather than
    /// silently requesting an unbounded or launch-failing policy.
    pub fn enable_private_tmpfs_with_maximum_bytes(
        &mut self,
        maximum_bytes: usize,
    ) -> Result<&mut Self, BubblewrapPolicyError> {
        let Some(maximum_bytes) = NonZeroUsize::new(maximum_bytes) else {
            return Err(BubblewrapPolicyError::InvalidPrivateTmpfsSize { maximum_bytes });
        };
        if maximum_bytes.get() > MAX_TMPFS_BYTES {
            return Err(BubblewrapPolicyError::InvalidPrivateTmpfsSize {
                maximum_bytes: maximum_bytes.get(),
            });
        }
        self.private_tmpfs = PrivateTmpfs::Bounded(maximum_bytes);
        Ok(self)
    }

    /// Returns the requested user-namespace hardening mode.
    pub const fn user_namespace_policy(&self) -> UserNamespacePolicy {
        self.user_namespace_policy
    }

    /// Requires a new user namespace and prevents the worker from creating
    /// further user namespaces.
    ///
    /// The compiled command adds Bubblewrap's `--unshare-user` and
    /// `--disable-userns` after `--unshare-all`. The explicit first option is
    /// required because `--unshare-all` only requests user namespaces on a
    /// best-effort basis. There is no compatibility fallback: a Bubblewrap
    /// version without `--disable-userns`, a setuid Bubblewrap build, or a host
    /// that disallows the required user namespace will fail to start the
    /// worker. This mitigates further namespace manipulation only; it is not a
    /// seccomp, resource-limit, or general containment policy.
    pub fn require_no_further_user_namespaces(&mut self) -> &mut Self {
        self.user_namespace_policy = UserNamespacePolicy::RequireNoFurtherUserNamespaces;
        self
    }

    /// Runs the fixed worker through a typed resource-limit runner.
    ///
    /// Compilation requires both this runner and the worker to be executable
    /// through read-only runtime mounts. The runner receives only fixed
    /// policy-generated flags, then `--`, the fixed worker executable, and its
    /// fixed arguments. A runner setup or `exec` failure must therefore stop
    /// worker startup; hosts must never retry by launching the worker directly.
    pub fn set_resource_limit_runner(&mut self, runner: ResourceLimitRunner) -> &mut Self {
        self.resource_limit_runner = Some(runner);
        self
    }

    /// Returns the selected seccomp hardening profile.
    pub const fn seccomp_profile(&self) -> WorkerSeccompProfile {
        self.seccomp_profile
    }

    /// Returns the strict seccomp allowlist selected for this worker, if any.
    pub fn seccomp_allowlist(&self) -> Option<&WorkerSeccompAllowlist> {
        self.seccomp_allowlist.as_ref()
    }

    /// Selects a typed, Splash-owned seccomp hardening profile.
    ///
    /// A selected profile is compiled by Splash and transferred to Bubblewrap
    /// over an anonymous launch-only descriptor. Callers cannot provide raw
    /// cBPF or a descriptor. Unsupported platforms and architectures reject a
    /// selected profile during compilation; launch does not fall back to an
    /// unfiltered worker.
    ///
    /// Selecting [`WorkerSeccompProfile::StrictAllowlist`] through this method
    /// intentionally clears any old allowlist and makes compilation fail. Use
    /// [`Self::set_seccomp_allowlist`] to atomically select a new strict list.
    pub fn set_seccomp_profile(&mut self, profile: WorkerSeccompProfile) -> &mut Self {
        self.seccomp_profile = profile;
        self.seccomp_allowlist = None;
        self
    }

    /// Selects a strict, host-reviewed syscall allowlist for this worker.
    ///
    /// The raw syscall numbers remain trusted host configuration. Splash adds
    /// its fixed ABI and escape-surface guards before the list, then kills on
    /// every syscall the host did not select. The list must cover Bubblewrap's
    /// final execution path, any fixed pre-exec runner, and the worker's exact
    /// runtime; Linux policy compilation explicitly requires `execve`. It is
    /// never derived from Splash source or an LLM request.
    pub fn set_seccomp_allowlist(&mut self, allowlist: WorkerSeccompAllowlist) -> &mut Self {
        self.seccomp_profile = WorkerSeccompProfile::StrictAllowlist;
        self.seccomp_allowlist = Some(allowlist);
        self
    }

    /// Validates a manifest and creates an immutable Bubblewrap launch plan.
    ///
    /// `file_root` selectors map only through host-registered bindings. This
    /// backend rejects `executable`, `network_origin`, and `secret` selectors:
    /// it always creates a network namespace and has no correct enforcement
    /// mechanism for per-origin networking, arbitrary executables, or secret
    /// delivery.
    pub fn compile(
        &self,
        manifest: &CapabilityManifest,
    ) -> Result<BubblewrapCommand, BubblewrapPolicyError> {
        manifest
            .validate()
            .map_err(BubblewrapPolicyError::Protocol)?;
        ensure_mount_source_binding_supported(self.mount_source_binding)?;
        ensure_executable_source_binding_supported(self.executable_source_binding)?;
        if self.executable_source_binding == ExecutableSourceBinding::DescriptorPinned
            && self.mount_source_binding != MountSourceBinding::DescriptorPinned
        {
            return Err(
                BubblewrapPolicyError::DescriptorPinnedExecutablesRequirePinnedMountSources,
            );
        }
        if self.bounded_file_root_writes_required && self.private_tmpfs == PrivateTmpfs::Unbounded {
            return Err(BubblewrapPolicyError::UnboundedPrivateTmpfsForbidden);
        }
        if self.bounded_file_root_writes_required
            && self.user_namespace_policy != UserNamespacePolicy::RequireNoFurtherUserNamespaces
        {
            return Err(BubblewrapPolicyError::BoundedFileRootWritesRequireUserNamespaceLockdown);
        }
        let bwrap_program = compile_host_executable(
            "Bubblewrap program",
            &self.bwrap_program,
            self.executable_source_binding,
        )?;

        let mut mounts = self
            .runtime_mounts
            .iter()
            .map(|mount| resolve_runtime_mount(mount, self.mount_source_binding))
            .collect::<Result<Vec<_>, _>>()?;

        let resources = manifest
            .grants
            .iter()
            .flat_map(|grant| grant.resources.iter().cloned())
            .collect::<BTreeSet<_>>();
        for resource in resources {
            match resource.kind {
                ResourceKind::FileRoot => {
                    let root = self.file_roots.get(&resource.id).ok_or_else(|| {
                        BubblewrapPolicyError::MissingFileRoot {
                            id: resource.id.clone(),
                        }
                    })?;
                    match root {
                        RegisteredFileRoot::Host(binding) => {
                            if self.bounded_file_root_writes_required
                                && binding.access == FileRootAccess::ReadWrite
                            {
                                return Err(
                                    BubblewrapPolicyError::UnboundedFileRootWriteForbidden {
                                        id: resource.id,
                                    },
                                );
                            }
                            mounts.push(resolve_file_root(binding, self.mount_source_binding)?);
                        }
                        RegisteredFileRoot::Ephemeral(root) => {
                            mounts.push(resolve_ephemeral_file_root(root));
                        }
                    }
                }
                ResourceKind::Executable | ResourceKind::NetworkOrigin | ResourceKind::Secret => {
                    return Err(BubblewrapPolicyError::UnsupportedResource { resource });
                }
            }
        }

        validate_mount_layout(&mut mounts, self.private_tmpfs.is_enabled())?;
        let worker_program_source = validate_runtime_program(
            &mounts,
            &self.worker_program,
            |program| BubblewrapPolicyError::WorkerProgramNotMounted { program },
            |program| BubblewrapPolicyError::WorkerProgramNotExecutable { program },
            "worker program source",
        )?;
        let resource_limit_runner_source = if let Some(runner) = &self.resource_limit_runner {
            if runner.program == self.worker_program {
                return Err(BubblewrapPolicyError::ResourceLimitRunnerMatchesWorker {
                    program: runner.program.clone(),
                });
            }
            Some(validate_runtime_program(
                &mounts,
                &runner.program,
                |program| BubblewrapPolicyError::ResourceLimitRunnerNotMounted { program },
                |program| BubblewrapPolicyError::ResourceLimitRunnerNotExecutable { program },
                "resource limit runner source",
            )?)
        } else {
            None
        };
        let mut executable_overlays = Vec::new();
        if self.executable_source_binding == ExecutableSourceBinding::DescriptorPinned {
            if !worker_program_source.is_descriptor_pinned_file {
                executable_overlays.push(compile_pinned_program_overlay(
                    "worker program source",
                    worker_program_source.source,
                    self.worker_program.clone(),
                )?);
            }
            if let (Some(runner), Some(runner_source)) =
                (&self.resource_limit_runner, resource_limit_runner_source)
            {
                if !runner_source.is_descriptor_pinned_file {
                    executable_overlays.push(compile_pinned_program_overlay(
                        "resource limit runner source",
                        runner_source.source,
                        runner.program.clone(),
                    )?);
                }
            }
        }
        let seccomp_program =
            compile_seccomp_program(self.seccomp_profile, self.seccomp_allowlist.as_ref())?;

        let mut mount_prefix_arguments = vec![
            OsString::from("--die-with-parent"),
            OsString::from("--new-session"),
            OsString::from("--unshare-all"),
        ];
        if self.user_namespace_policy == UserNamespacePolicy::RequireNoFurtherUserNamespaces {
            mount_prefix_arguments.push(OsString::from("--unshare-user"));
            mount_prefix_arguments.push(OsString::from("--disable-userns"));
        }
        mount_prefix_arguments.extend([
            OsString::from("--clearenv"),
            OsString::from("--proc"),
            OsString::from("/proc"),
            OsString::from("--dev"),
            OsString::from("/dev"),
            OsString::from("--chdir"),
            OsString::from("/"),
        ]);
        mount_prefix_arguments.push(OsString::from("--cap-drop"));
        mount_prefix_arguments.push(OsString::from("ALL"));
        if let Some(maximum_bytes) = self.private_tmpfs.maximum_bytes() {
            mount_prefix_arguments.push(OsString::from("--size"));
            mount_prefix_arguments.push(OsString::from(maximum_bytes.get().to_string()));
        }
        if self.private_tmpfs.is_enabled() {
            mount_prefix_arguments.push(OsString::from("--tmpfs"));
            mount_prefix_arguments.push(OsString::from("/tmp"));
        }
        let mut mount_suffix_arguments = Vec::new();
        if self.bounded_file_root_writes_required {
            for destination in ["/proc", "/dev", "/"] {
                mount_suffix_arguments.push(OsString::from("--remount-ro"));
                mount_suffix_arguments.push(OsString::from(destination));
            }
        }
        mount_suffix_arguments.push(OsString::from("--"));
        if let Some(runner) = &self.resource_limit_runner {
            mount_suffix_arguments.push(runner.program.clone().into_os_string());
            runner
                .limits
                .append_runner_arguments(&mut mount_suffix_arguments);
            mount_suffix_arguments.push(OsString::from("--"));
        }
        mount_suffix_arguments.push(self.worker_program.clone().into_os_string());
        mount_suffix_arguments.extend(self.worker_arguments.iter().cloned());

        let arguments = display_arguments(
            &mount_prefix_arguments,
            &mounts,
            &executable_overlays,
            &mount_suffix_arguments,
        );

        Ok(BubblewrapCommand {
            bwrap_program,
            arguments,
            mount_prefix_arguments,
            mounts,
            executable_overlays,
            mount_suffix_arguments,
            manifest: manifest.clone(),
            seccomp_program,
        })
    }
}

/// An immutable Bubblewrap command assembled from a validated policy.
///
/// The plan contains host paths, so hosts should not expose its debug output
/// or errors to a script, LLM, or untrusted log sink. It contains no session
/// key. [`Self::spawn_with_bootstrap`] can transfer one host-generated key over
/// the new worker's private stdin pipe; other launch paths need their own
/// trusted target-specific provisioning path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BubblewrapCommand {
    bwrap_program: CompiledHostExecutable,
    arguments: Vec<OsString>,
    mount_prefix_arguments: Vec<OsString>,
    mounts: Vec<CompiledMount>,
    executable_overlays: Vec<CompiledMount>,
    mount_suffix_arguments: Vec<OsString>,
    manifest: CapabilityManifest,
    seccomp_program: Option<SeccompProgram>,
}

impl BubblewrapCommand {
    /// Returns the canonical host Bubblewrap executable path.
    pub fn bwrap_program(&self) -> &Path {
        self.bwrap_program.path()
    }

    /// Returns an inspectable representation of the fixed Bubblewrap arguments.
    ///
    /// A selected seccomp profile contributes a launch-only `--seccomp FD`
    /// pair that is intentionally omitted here because the anonymous descriptor
    /// exists only during [`Self::spawn`]. Descriptor-pinned mount roots and
    /// executable file overlays appear as `--bind-fd` or `--ro-bind-fd` with a
    /// non-numeric launch-only placeholder rather than exposing a host source
    /// path. The representation is not an executable command line when it
    /// contains a launch-only placeholder.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Returns the authenticated session ID bound to the compiled manifest.
    ///
    /// This value is retained only so [`Self::spawn_with_bootstrap`] can reject
    /// a host accidentally pairing the worker policy with another session.
    /// It is never added to the Bubblewrap command line.
    pub fn session_id(&self) -> &str {
        &self.manifest.session_id
    }

    /// Returns the exact capability manifest used to compile this command.
    ///
    /// Recovery hosts use this binding to prevent a fresh authenticated
    /// session from being paired with a containment plan compiled for broader
    /// or otherwise different authority under the same session ID.
    pub fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    /// Returns the selected host-owned seccomp hardening profile.
    ///
    /// The profile's descriptor is created only while spawning the worker, so
    /// it is intentionally absent from [`Self::arguments`].
    pub const fn seccomp_profile(&self) -> WorkerSeccompProfile {
        match self.seccomp_program {
            Some(ref program) => program.profile,
            None => WorkerSeccompProfile::Disabled,
        }
    }

    /// Starts a worker with piped JSON-line standard input and output.
    ///
    /// The backend is deliberately unavailable off Linux. On Linux, a failed
    /// `spawn` proves neither policy success nor worker health; the host must
    /// still perform authenticated session startup, enforce I/O deadlines,
    /// terminate on cancellation, and wait for the child.
    pub fn spawn(&self) -> Result<SpawnedBubblewrapWorker, BubblewrapSpawnError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            Err(BubblewrapSpawnError::UnsupportedPlatform)
        }

        #[cfg(target_os = "linux")]
        {
            self.spawn_with_stderr(Stdio::null(), None, None)
                .map(|(worker, _)| worker)
        }
    }

    /// Starts a worker through a fresh, limited cgroup-v2 child.
    ///
    /// The policy is trusted host configuration. Its fixed runner joins the
    /// prepared cgroup before it executes Bubblewrap, so Bubblewrap and every
    /// descendant inherit the configured controller limits. Keep the returned
    /// worker's lifecycle handle until termination and cleanup complete; raw
    /// child extraction cannot provide cgroup process-tree teardown.
    pub fn spawn_in_cgroup(
        &self,
        policy: &CgroupV2Policy,
    ) -> Result<SpawnedBubblewrapWorker, BubblewrapCgroupSpawnError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, policy);
            Err(BubblewrapCgroupSpawnError::Prepare(
                CgroupV2PrepareError::UnsupportedPlatform,
            ))
        }

        #[cfg(target_os = "linux")]
        {
            let join_timeout = policy.join_timeout();
            let session = policy
                .prepare()
                .map_err(BubblewrapCgroupSpawnError::Prepare)?;
            self.spawn_with_stderr(Stdio::null(), Some(session), Some(join_timeout))
                .map(|(worker, _)| worker)
                .map_err(BubblewrapCgroupSpawnError::Spawn)
        }
    }

    #[cfg(target_os = "linux")]
    fn spawn_with_stderr(
        &self,
        stderr: Stdio,
        cgroup: Option<CgroupV2Session>,
        cgroup_join_timeout: Option<Duration>,
    ) -> Result<(SpawnedBubblewrapWorker, Option<ChildStderr>), BubblewrapSpawnError> {
        let mut mount_descriptors = Vec::new();
        let arguments = self.spawn_arguments(&mut mount_descriptors)?;
        let (bwrap_program, bwrap_execution_descriptor) =
            self.bwrap_program.prepare_for_execution()?;
        let seccomp_descriptor = self
            .seccomp_program
            .as_ref()
            .map(SeccompProgram::open_for_bubblewrap)
            .transpose()?;
        let (cgroup_runner_program, cgroup_runner_descriptor) = if let Some(session) = &cgroup {
            if self.bwrap_program.is_descriptor_pinned() {
                let runner =
                    pin_host_executable_for_spawn("cgroup runner", session.runner_program())?;
                let (program, descriptor) = runner.prepare_for_execution()?;
                (Some(program), descriptor)
            } else {
                (Some(session.runner_program().to_path_buf()), None)
            }
        } else {
            (None, None)
        };
        let mut command = if let Some(session) = &cgroup {
            let runner_program = cgroup_runner_program
                .as_ref()
                .expect("cgroup-backed Bubblewrap spawn must select a runner program");
            let mut command = Command::new(runner_program);
            command
                .arg("--cgroup-procs")
                .arg(session.cgroup_procs_path());
            for descriptor in &mount_descriptors {
                command
                    .arg("--preserve-fd")
                    .arg(descriptor.as_raw_fd().to_string());
            }
            if let Some(descriptor) = &seccomp_descriptor {
                command
                    .arg("--preserve-fd")
                    .arg(descriptor.as_raw_fd().to_string());
            }
            if let Some(descriptor) = &bwrap_execution_descriptor {
                command
                    .arg("--preserve-fd")
                    .arg(descriptor.as_raw_fd().to_string());
            }
            command.arg("--").arg(&bwrap_program);
            command
        } else {
            Command::new(&bwrap_program)
        };
        if let Some(descriptor) = &seccomp_descriptor {
            command
                .arg("--seccomp")
                .arg(descriptor.as_raw_fd().to_string());
        }
        command
            .args(arguments)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr);
        // Start the lifetime immediately before process creation so a session
        // deadline never gains an unenforced launch-time extension.
        let started_at = Instant::now();
        let mut child = command.spawn().map_err(BubblewrapSpawnError::Spawn)?;
        // The worker-side copy is owned and closed by Bubblewrap while it
        // reads the program. Close our deliberately inherited copy before
        // any later host process launch can observe it.
        drop(seccomp_descriptor);
        drop(mount_descriptors);
        drop(cgroup_runner_descriptor);
        drop(bwrap_execution_descriptor);
        if let Some(session) = &cgroup {
            let join_timeout = cgroup_join_timeout
                .expect("cgroup-backed Bubblewrap spawn must carry its host-selected join timeout");
            if let Err(error) = wait_for_cgroup_join(&mut child, session, join_timeout) {
                discard_worker(&mut child, Some(session));
                return Err(error);
            }
        } else {
            debug_assert!(cgroup_join_timeout.is_none());
        }
        let Some(stdin) = child.stdin.take() else {
            discard_worker(&mut child, cgroup.as_ref());
            return Err(BubblewrapSpawnError::MissingStdin);
        };
        let Some(stdout) = child.stdout.take() else {
            discard_worker(&mut child, cgroup.as_ref());
            return Err(BubblewrapSpawnError::MissingStdout);
        };
        let stderr = child.stderr.take();
        Ok((
            SpawnedBubblewrapWorker {
                child,
                stdin,
                stdout,
                cgroup,
                started_at,
                session_id: self.manifest.session_id.clone(),
            },
            stderr,
        ))
    }

    #[cfg(target_os = "linux")]
    fn spawn_arguments(
        &self,
        mount_descriptors: &mut Vec<OwnedFd>,
    ) -> Result<Vec<OsString>, BubblewrapSpawnError> {
        let mut arguments = self.mount_prefix_arguments.clone();
        for mount in &self.mounts {
            mount.append_spawn_arguments(&mut arguments, mount_descriptors)?;
        }
        for executable_overlay in &self.executable_overlays {
            executable_overlay.append_spawn_arguments(&mut arguments, mount_descriptors)?;
        }
        arguments.extend(self.mount_suffix_arguments.iter().cloned());
        Ok(arguments)
    }

    #[cfg(all(target_os = "linux", test))]
    fn spawn_capturing_stderr(
        &self,
    ) -> Result<(SpawnedBubblewrapWorker, ChildStderr), BubblewrapSpawnError> {
        let (worker, stderr) = self.spawn_with_stderr(Stdio::piped(), None, None)?;
        let Some(stderr) = stderr else {
            unreachable!("a piped Bubblewrap standard-error stream must be available")
        };
        Ok((worker, stderr))
    }

    /// Starts a worker and writes its authenticated session bootstrap before
    /// any JSON worker frame can be sent.
    ///
    /// The bootstrap must be generated by trusted host code from a fresh
    /// session key. Its session ID must match the manifest used by
    /// [`BubblewrapWorkerPolicy::compile`]. The key is written only to the
    /// dedicated child stdin pipe; it never appears in arguments, environment
    /// variables, mount paths, or Splash values. If the write fails, this
    /// method kills and reaps the child instead of returning a possibly
    /// misaligned worker stream.
    pub fn spawn_with_bootstrap(
        &self,
        bootstrap: &PrivatePipeWorkerBootstrap,
    ) -> Result<SpawnedBubblewrapWorker, BubblewrapBootstrapError> {
        if bootstrap.session_id() != self.manifest.session_id {
            return Err(BubblewrapBootstrapError::SessionMismatch {
                expected: self.manifest.session_id.clone(),
                actual: bootstrap.session_id().to_owned(),
            });
        }

        let mut worker = self.spawn().map_err(BubblewrapBootstrapError::Spawn)?;
        if let Err(error) = bootstrap.write_to(&mut worker.stdin) {
            let _ = worker.terminate();
            return Err(BubblewrapBootstrapError::Bootstrap(error));
        }
        Ok(worker)
    }

    /// Starts a cgroup-v2-limited worker and writes its authenticated bootstrap
    /// before any JSON worker frame can be sent.
    ///
    /// This has the same key-delivery and recovery requirements as
    /// [`Self::spawn_with_bootstrap`]. A bootstrap write failure terminates the
    /// whole cgroup before this method returns the error.
    pub fn spawn_with_bootstrap_in_cgroup(
        &self,
        policy: &CgroupV2Policy,
        bootstrap: &PrivatePipeWorkerBootstrap,
    ) -> Result<SpawnedBubblewrapWorker, BubblewrapCgroupBootstrapError> {
        if bootstrap.session_id() != self.manifest.session_id {
            return Err(BubblewrapCgroupBootstrapError::SessionMismatch {
                expected: self.manifest.session_id.clone(),
                actual: bootstrap.session_id().to_owned(),
            });
        }

        let mut worker = self
            .spawn_in_cgroup(policy)
            .map_err(BubblewrapCgroupBootstrapError::Spawn)?;
        if let Err(error) = bootstrap.write_to(&mut worker.stdin) {
            let _ = worker.terminate();
            return Err(BubblewrapCgroupBootstrapError::Bootstrap(error));
        }
        Ok(worker)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeccompProgram {
    profile: WorkerSeccompProfile,
    bytes: Vec<u8>,
}

impl SeccompProgram {
    #[cfg(target_os = "linux")]
    fn open_for_bubblewrap(&self) -> Result<OwnedFd, BubblewrapSpawnError> {
        let (descriptor, mut producer) =
            UnixStream::pair().map_err(BubblewrapSpawnError::SeccompTransport)?;
        producer
            .write_all(&self.bytes)
            .map_err(BubblewrapSpawnError::SeccompTransport)?;
        drop(producer);

        // `Command` configures the child standard streams after this socket is
        // created. Duplicate it above descriptor 2 so a host with a closed
        // standard descriptor cannot have that setup replace the seccomp
        // transport before Bubblewrap reads it.
        let descriptor = fcntl_dupfd_cloexec(&descriptor, 3)
            .map_err(|source| BubblewrapSpawnError::SeccompTransport(source.into()))?;
        // Bubblewrap receives this descriptor through exec, reads the complete
        // cBPF program, and closes it before it enters the sandbox. The worker
        // never receives a descriptor selected by a caller.
        fcntl_setfd(&descriptor, FdFlags::empty())
            .map_err(|source| BubblewrapSpawnError::SeccompTransport(source.into()))?;
        Ok(descriptor)
    }
}

fn compile_seccomp_program(
    profile: WorkerSeccompProfile,
    allowlist: Option<&WorkerSeccompAllowlist>,
) -> Result<Option<SeccompProgram>, BubblewrapPolicyError> {
    if profile == WorkerSeccompProfile::Disabled {
        return Ok(None);
    }

    let allowlist = match profile {
        WorkerSeccompProfile::Disabled | WorkerSeccompProfile::DenyKnownEscapeSurface => None,
        WorkerSeccompProfile::StrictAllowlist => {
            Some(allowlist.ok_or(BubblewrapPolicyError::MissingSeccompAllowlist)?)
        }
    };

    #[cfg(target_os = "linux")]
    {
        linux_seccomp::compile(profile, allowlist).map(Some)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (profile, allowlist);
        Err(BubblewrapPolicyError::SeccompUnsupportedPlatform)
    }
}

/// One running worker and its dedicated JSON-line pipes.
#[derive(Debug)]
pub struct SpawnedBubblewrapWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    cgroup: Option<CgroupV2Session>,
    started_at: Instant,
    session_id: String,
}

impl SpawnedBubblewrapWorker {
    /// Returns the authenticated session ID compiled into this worker's
    /// containment plan.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the child process for host-controlled lifecycle management.
    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Force-terminates the host-side Bubblewrap child and reaps it before
    /// returning.
    ///
    /// This is process lifecycle control, not an in-band worker-protocol
    /// cancellation. A `Killed` result only means the Bubblewrap child was
    /// alive when the host requested termination; it does not prove that an
    /// adapter effect was not started or completed. Hosts must discard the
    /// session and reconcile any durable effect through the authenticated
    /// worker protocol.
    pub fn terminate(&mut self) -> Result<BubblewrapTermination, BubblewrapTerminationError> {
        terminate_and_reap(&mut self.child, &mut self.cgroup)
    }

    /// Consumes this worker after force-termination and reap, yielding a proof
    /// that can authorize post-stop recovery.
    ///
    /// The proof does not claim that an adapter effect was cancelled. It only
    /// establishes that this exact contained session can no longer race a
    /// fresh reconciliation session.
    pub fn into_reaped(
        mut self,
    ) -> Result<BubblewrapWorkerReaped, BubblewrapWorkerReapError<Self>> {
        match terminate_and_reap(&mut self.child, &mut self.cgroup) {
            Ok(termination) => Ok(BubblewrapWorkerReaped {
                session_id: self.session_id,
                termination,
            }),
            Err(source) => Err(BubblewrapWorkerReapError {
                source,
                worker: Box::new(self),
            }),
        }
    }

    /// Consumes the startup handle while retaining managed worker lifecycle
    /// control separately from the private JSON-line pipes.
    ///
    /// A host that gives the pipes to `JsonLineWorkerChannel` should keep the
    /// returned lifecycle handle so it can force-terminate and reap the worker
    /// after a deadline, transport failure, or host cancellation.
    pub fn into_lifecycle_parts(self) -> (BubblewrapWorkerLifecycle, ChildStdin, ChildStdout) {
        (
            BubblewrapWorkerLifecycle {
                child: self.child,
                cgroup: self.cgroup,
                started_at: self.started_at,
                session_id: self.session_id,
            },
            self.stdin,
            self.stdout,
        )
    }

    /// Transfers the worker lifecycle and private pipes to a watchdog with a
    /// session-wide deadline measured from worker spawn.
    ///
    /// This is the preferred handoff when a host needs a bounded worker
    /// lifetime: it starts the watchdog before returning either pipe. If the
    /// watchdog thread cannot start, the returned error retains the lifecycle
    /// so the host can terminate and reap the worker; the private pipes are
    /// dropped rather than returned without deadline enforcement.
    pub fn into_session_watchdog_parts(
        self,
        deadline: BubblewrapWorkerSessionDeadline,
    ) -> Result<
        (BubblewrapWorkerWatchdog, ChildStdin, ChildStdout),
        BubblewrapWorkerWatchdogStartError,
    > {
        let Self {
            child,
            stdin,
            stdout,
            cgroup,
            started_at,
            session_id,
        } = self;
        let lifecycle = BubblewrapWorkerLifecycle {
            child,
            cgroup,
            started_at,
            session_id,
        };
        let watchdog = lifecycle.into_watchdog_with_session_deadline(deadline)?;
        Ok((watchdog, stdin, stdout))
    }

    /// Consumes the handle and returns the child plus its private input/output
    /// pipes. The caller can wrap these in `JsonLineWorkerChannel`.
    ///
    /// For a worker started with [`BubblewrapCommand::spawn_in_cgroup`], this
    /// relinquishes the cgroup lifecycle handle. The cgroup limits remain in
    /// effect, but the host can no longer use this API to kill descendant
    /// processes or remove the cgroup. Use [`Self::into_lifecycle_parts`] for
    /// cgroup-backed workers.
    pub fn into_parts(self) -> (Child, ChildStdin, ChildStdout) {
        (self.child, self.stdin, self.stdout)
    }
}

/// Host-owned lifecycle control for a worker after its private pipes move to a
/// transport.
#[derive(Debug)]
pub struct BubblewrapWorkerLifecycle {
    child: Child,
    cgroup: Option<CgroupV2Session>,
    started_at: Instant,
    session_id: String,
}

impl BubblewrapWorkerLifecycle {
    /// Returns the authenticated session ID compiled into this worker's
    /// containment plan.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the worker process for host-controlled lifecycle integration.
    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Force-terminates the host-side Bubblewrap child and reaps it before
    /// returning.
    ///
    /// This has the same effect and recovery requirements as
    /// [`SpawnedBubblewrapWorker::terminate`].
    pub fn terminate(&mut self) -> Result<BubblewrapTermination, BubblewrapTerminationError> {
        terminate_and_reap(&mut self.child, &mut self.cgroup)
    }

    /// Consumes this lifecycle after force-termination and reap, yielding a
    /// session-bound post-stop recovery proof.
    pub fn into_reaped(
        mut self,
    ) -> Result<BubblewrapWorkerReaped, BubblewrapWorkerReapError<Self>> {
        match terminate_and_reap(&mut self.child, &mut self.cgroup) {
            Ok(termination) => Ok(BubblewrapWorkerReaped {
                session_id: self.session_id,
                termination,
            }),
            Err(source) => Err(BubblewrapWorkerReapError {
                source,
                worker: Box::new(self),
            }),
        }
    }

    /// Transfers this worker lifecycle to a host-owned watchdog thread.
    ///
    /// The watchdog can arm one wall-clock deadline at a time and force-stop
    /// and reap the Bubblewrap process when it expires. It is process control,
    /// not authenticated in-band cancellation: a host must treat a timeout or
    /// explicit stop as indeterminate and reconcile any durable effect.
    ///
    /// If the operating system refuses to start the watchdog thread, the
    /// returned error retains this lifecycle so the caller can terminate and
    /// reap the worker rather than accidentally continuing without a deadline.
    pub fn into_watchdog(
        self,
    ) -> Result<BubblewrapWorkerWatchdog, BubblewrapWorkerWatchdogStartError> {
        BubblewrapWorkerWatchdog::new(self, None)
    }

    /// Transfers this lifecycle to a watchdog with a fixed session-wide
    /// deadline measured from worker spawn.
    ///
    /// The deadline applies while the worker is idle as well as while one
    /// invocation is active. Expiry force-stops and reaps the worker; it is
    /// not a protocol cancellation acknowledgement and any active effect is
    /// indeterminate.
    pub fn into_watchdog_with_session_deadline(
        self,
        deadline: BubblewrapWorkerSessionDeadline,
    ) -> Result<BubblewrapWorkerWatchdog, BubblewrapWorkerWatchdogStartError> {
        let Some(session_deadline) = deadline.at(self.started_at) else {
            return Err(BubblewrapWorkerWatchdogStartError::deadline_overflow(self));
        };
        BubblewrapWorkerWatchdog::new(self, Some(session_deadline))
    }

    /// Consumes this lifecycle handle and returns the raw child process.
    ///
    /// For cgroup-backed workers, this relinquishes cgroup process-tree
    /// teardown and cleanup. Prefer [`Self::into_watchdog`] or
    /// [`Self::terminate`] for those workers.
    pub fn into_child(self) -> Child {
        self.child
    }
}

/// A nonzero host-selected upper bound for one Bubblewrap worker session.
///
/// A session deadline is measured from process spawn and remains active while
/// the worker is idle or serving a request. It is trusted host configuration:
/// Splash source cannot inspect, reset, or extend it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BubblewrapWorkerSessionDeadline {
    maximum: Duration,
}

impl BubblewrapWorkerSessionDeadline {
    /// Creates a session deadline that can be represented by the monotonic
    /// clock on this host.
    pub fn new(maximum: Duration) -> Result<Self, BubblewrapWorkerSessionDeadlineError> {
        if maximum.is_zero() {
            return Err(BubblewrapWorkerSessionDeadlineError::Zero);
        }
        if Instant::now().checked_add(maximum).is_none() {
            return Err(BubblewrapWorkerSessionDeadlineError::Unrepresentable);
        }
        Ok(Self { maximum })
    }

    /// Returns the host-selected maximum worker lifetime.
    pub const fn maximum(self) -> Duration {
        self.maximum
    }

    fn at(self, started_at: Instant) -> Option<Instant> {
        started_at.checked_add(self.maximum)
    }
}

/// Rejection while creating a [`BubblewrapWorkerSessionDeadline`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BubblewrapWorkerSessionDeadlineError {
    /// A zero-duration deadline cannot establish a usable worker session.
    Zero,
    /// The host monotonic clock cannot represent the requested deadline.
    Unrepresentable,
}

impl Display for BubblewrapWorkerSessionDeadlineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => {
                formatter.write_str("Bubblewrap worker session deadline must be greater than zero")
            }
            Self::Unrepresentable => formatter.write_str(
                "Bubblewrap worker session deadline cannot be represented by the monotonic clock",
            ),
        }
    }
}

impl std::error::Error for BubblewrapWorkerSessionDeadlineError {}

/// Outcome after a host force-terminates a Bubblewrap worker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BubblewrapTermination {
    /// The worker had already exited and was reaped by the status check.
    AlreadyExited(ExitStatus),
    /// The worker was alive, killed by the host, and then reaped.
    Killed(ExitStatus),
}

/// Unforgeable proof that one exact Bubblewrap worker session was reaped.
///
/// Only consuming lifecycle APIs construct this value. Recovery code can
/// therefore require process teardown before it loads durable state or starts
/// a fresh worker. The proof is cloneable because reaping is a permanent fact
/// and a failed fresh launch must remain retryable. It says nothing about
/// whether an adapter effect ran.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BubblewrapWorkerReaped {
    session_id: String,
    termination: BubblewrapTermination,
}

impl BubblewrapWorkerReaped {
    /// Returns the authenticated session ID of the reaped worker.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the process-level termination observation.
    pub fn termination(&self) -> &BubblewrapTermination {
        &self.termination
    }

    /// Consumes the proof into non-authorizing audit data.
    pub fn into_parts(self) -> (String, BubblewrapTermination) {
        (self.session_id, self.termination)
    }
}

/// Failed consuming transition from a worker lifecycle to a reaping proof.
///
/// The owned worker is returned so trusted host code can retry termination or
/// apply a platform-specific escalation without losing process control.
#[derive(Debug)]
pub struct BubblewrapWorkerReapError<T> {
    source: BubblewrapTerminationError,
    worker: Box<T>,
}

impl<T> BubblewrapWorkerReapError<T> {
    /// Returns the teardown failure that prevented a reaping proof.
    pub fn source_error(&self) -> &BubblewrapTerminationError {
        &self.source
    }

    /// Returns the still-owned worker or lifecycle handle.
    pub fn worker(&self) -> &T {
        &self.worker
    }

    /// Recovers ownership for another cleanup attempt.
    pub fn into_worker(self) -> T {
        *self.worker
    }
}

impl<T> Display for BubblewrapWorkerReapError<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "could not produce a worker reaping proof: {}",
            self.source
        )
    }
}

impl<T: fmt::Debug> std::error::Error for BubblewrapWorkerReapError<T> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl BubblewrapTermination {
    /// Returns the reaped child process exit status.
    pub fn exit_status(&self) -> &ExitStatus {
        match self {
            Self::AlreadyExited(status) | Self::Killed(status) => status,
        }
    }

    /// Returns whether this call killed a still-running worker process.
    pub const fn was_killed(&self) -> bool {
        matches!(self, Self::Killed(_))
    }
}

/// Host-owned watchdog for one Bubblewrap worker lifecycle.
///
/// A caller starts a deadline with [`Self::begin_call`] before it sends a
/// synchronous worker request and ends it with [`Self::finish_call`] after the
/// transport returns. The watchdog owns the child process in a dedicated
/// thread, so it can force-stop a blocked worker even while another host
/// thread is reading the worker's response pipe.
///
/// The optional [`Self::control`] is a trusted host lifecycle control. It does
/// not send `WorkerMessage::Cancel`, does not wait for a worker acknowledgement,
/// and does not prove that an adapter effect did not happen. A force-stop
/// outcome must therefore be treated as indeterminate.
pub struct BubblewrapWorkerWatchdog {
    sender: mpsc::Sender<WatchdogCommand>,
    join: Option<JoinHandle<()>>,
    session_id: String,
}

impl BubblewrapWorkerWatchdog {
    fn new(
        lifecycle: BubblewrapWorkerLifecycle,
        session_deadline: Option<Instant>,
    ) -> Result<Self, BubblewrapWorkerWatchdogStartError> {
        let session_id = lifecycle.session_id.clone();
        let (sender, receiver) = mpsc::channel();
        // Retain the lifecycle outside the closure until the OS confirms that
        // the watchdog thread exists. A failed thread spawn must not orphan a
        // process whose deadline enforcement was just requested.
        let pending_lifecycle = Arc::new(Mutex::new(Some(lifecycle)));
        let thread_lifecycle = Arc::clone(&pending_lifecycle);
        let join = match thread::Builder::new()
            .name("splash-bwrap-watchdog".to_owned())
            .spawn(move || {
                let lifecycle = take_pending_lifecycle(&thread_lifecycle);
                run_watchdog_thread(lifecycle, receiver, session_deadline);
            }) {
            Ok(join) => join,
            Err(source) => {
                return Err(BubblewrapWorkerWatchdogStartError {
                    source: Some(source),
                    lifecycle: Box::new(take_pending_lifecycle(&pending_lifecycle)),
                });
            }
        };
        Ok(Self {
            sender,
            join: Some(join),
            session_id,
        })
    }

    /// Returns the authenticated worker session controlled by this watchdog.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns a clonable trusted host control that can force-stop this worker.
    ///
    /// This is intentionally narrower than a worker protocol handle. It can
    /// only stop and reap the process; it cannot choose tools, send frames, or
    /// claim that a stopped adapter effect was cancelled.
    pub fn control(&self) -> BubblewrapWorkerControl {
        BubblewrapWorkerControl {
            sender: self.sender.clone(),
        }
    }

    /// Arms one nonzero host-selected wall-clock deadline.
    ///
    /// Only one call may be active. A second call is rejected rather than
    /// resetting or extending the existing deadline.
    pub fn begin_call(
        &mut self,
        maximum: Duration,
    ) -> Result<BubblewrapWorkerInvocation, BubblewrapWorkerWatchdogError> {
        if maximum.is_zero() {
            return Err(BubblewrapWorkerWatchdogError::InvalidDeadline);
        }
        self.request(|reply| WatchdogCommand::Arm { maximum, reply })
            .map(|sequence| BubblewrapWorkerInvocation { sequence })
    }

    /// Disarms a previously armed call or reports the force-stop that won its
    /// race with the transport response.
    pub fn finish_call(
        &mut self,
        invocation: BubblewrapWorkerInvocation,
    ) -> Result<BubblewrapWorkerInvocationOutcome, BubblewrapWorkerWatchdogError> {
        self.request(|reply| WatchdogCommand::Disarm {
            sequence: invocation.sequence,
            reply,
        })
    }

    /// Force-stops and reaps the worker through trusted host lifecycle control.
    ///
    /// This never means an adapter effect was cancelled. The caller must
    /// discard the session and use the durable reconciliation path for any
    /// effectful operation.
    pub fn terminate(&mut self) -> Result<BubblewrapTermination, BubblewrapWorkerWatchdogError> {
        request_termination(&self.sender)
    }

    /// Force-stops, reaps, and joins the watchdog thread.
    ///
    /// Drop performs the same best-effort cleanup. Prefer this method when a
    /// trusted host needs the reaped status for its own audit record.
    pub fn close(mut self) -> Result<BubblewrapTermination, BubblewrapWorkerWatchdogError> {
        self.shutdown()
    }

    /// Force-stops, reaps, and joins the watchdog thread, then returns a
    /// session-bound post-stop recovery proof for this exact session.
    pub fn close_reaped(mut self) -> Result<BubblewrapWorkerReaped, BubblewrapWorkerWatchdogError> {
        let termination = self.shutdown()?;
        Ok(BubblewrapWorkerReaped {
            session_id: self.session_id.clone(),
            termination,
        })
    }

    fn request<R>(
        &self,
        command: impl FnOnce(mpsc::Sender<Result<R, BubblewrapWorkerWatchdogError>>) -> WatchdogCommand,
    ) -> Result<R, BubblewrapWorkerWatchdogError> {
        let (reply_sender, reply_receiver) = mpsc::channel();
        self.sender
            .send(command(reply_sender))
            .map_err(|_| BubblewrapWorkerWatchdogError::Unavailable)?;
        reply_receiver
            .recv()
            .map_err(|_| BubblewrapWorkerWatchdogError::Unavailable)?
    }

    fn shutdown(&mut self) -> Result<BubblewrapTermination, BubblewrapWorkerWatchdogError> {
        let termination = self.request(|reply| WatchdogCommand::Shutdown { reply });
        let joined = self.join.take().map_or(Ok(()), |join| {
            join.join()
                .map_err(|_| BubblewrapWorkerWatchdogError::ThreadPanicked)
        });
        match (termination, joined) {
            (Ok(termination), Ok(())) => Ok(termination),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }
}

impl Drop for BubblewrapWorkerWatchdog {
    fn drop(&mut self) {
        if self.join.is_some() {
            let _ = self.shutdown();
        }
    }
}

/// A trusted host-only control for a running Bubblewrap worker.
#[derive(Clone)]
pub struct BubblewrapWorkerControl {
    sender: mpsc::Sender<WatchdogCommand>,
}

impl BubblewrapWorkerControl {
    /// Force-stops and reaps the worker.
    ///
    /// This is a process lifecycle operation, not an authenticated protocol
    /// cancellation acknowledgement. Any in-flight invocation is indeterminate.
    pub fn terminate(&self) -> Result<BubblewrapTermination, BubblewrapWorkerWatchdogError> {
        request_termination(&self.sender)
    }
}

/// Opaque binding between one watchdog begin/finish pair.
#[derive(Debug)]
pub struct BubblewrapWorkerInvocation {
    sequence: u64,
}

/// Result of ending a watched worker call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BubblewrapWorkerInvocationOutcome {
    /// The call completed before its host deadline elapsed.
    Completed,
    /// The deadline elapsed and the watchdog force-stopped the worker.
    DeadlineElapsed(BubblewrapTermination),
    /// The worker session lifetime elapsed and the watchdog force-stopped the
    /// worker. Any active adapter effect is indeterminate.
    SessionDeadlineElapsed(BubblewrapTermination),
    /// Trusted host lifecycle control force-stopped the worker.
    Terminated(BubblewrapTermination),
}

/// Failure while transferring a worker lifecycle into a watchdog thread.
#[derive(Debug)]
pub struct BubblewrapWorkerWatchdogStartError {
    source: Option<io::Error>,
    lifecycle: Box<BubblewrapWorkerLifecycle>,
}

impl BubblewrapWorkerWatchdogStartError {
    fn deadline_overflow(lifecycle: BubblewrapWorkerLifecycle) -> Self {
        Self {
            source: None,
            lifecycle: Box::new(lifecycle),
        }
    }

    /// Returns the worker lifecycle so the caller can terminate and reap it.
    pub fn into_lifecycle(self) -> BubblewrapWorkerLifecycle {
        *self.lifecycle
    }
}

impl Display for BubblewrapWorkerWatchdogStartError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(
                formatter,
                "could not start Bubblewrap worker watchdog: {source}",
            ),
            None => formatter.write_str(
                "Bubblewrap worker session deadline cannot be represented by the monotonic clock",
            ),
        }
    }
}

impl std::error::Error for BubblewrapWorkerWatchdogStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Failure while controlling a [`BubblewrapWorkerWatchdog`].
#[derive(Debug)]
pub enum BubblewrapWorkerWatchdogError {
    InvalidDeadline,
    DeadlineOverflow,
    InvocationAlreadyActive,
    InvocationMismatch,
    InvocationSequenceExhausted,
    NoActiveInvocation,
    SessionDeadlineElapsed(BubblewrapTermination),
    SessionTerminated(BubblewrapTermination),
    LifecycleFailed,
    Unavailable,
    ThreadPanicked,
    Termination(BubblewrapTerminationError),
}

impl Display for BubblewrapWorkerWatchdogError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeadline => {
                formatter.write_str("Bubblewrap worker deadline must be greater than zero")
            }
            Self::DeadlineOverflow => formatter.write_str(
                "Bubblewrap worker deadline cannot be represented by the monotonic clock",
            ),
            Self::InvocationAlreadyActive => {
                formatter.write_str("Bubblewrap worker already has an active invocation deadline")
            }
            Self::InvocationMismatch => formatter
                .write_str("Bubblewrap worker invocation does not match the active deadline"),
            Self::InvocationSequenceExhausted => {
                formatter.write_str("Bubblewrap worker invocation sequence is exhausted")
            }
            Self::NoActiveInvocation => {
                formatter.write_str("Bubblewrap worker has no active invocation deadline")
            }
            Self::SessionDeadlineElapsed(_) => {
                formatter.write_str("Bubblewrap worker session deadline elapsed")
            }
            Self::SessionTerminated(_) => {
                formatter.write_str("Bubblewrap worker process has already terminated")
            }
            Self::LifecycleFailed => formatter
                .write_str("Bubblewrap worker lifecycle previously failed and cannot be reused"),
            Self::Unavailable => formatter.write_str("Bubblewrap worker watchdog is unavailable"),
            Self::ThreadPanicked => {
                formatter.write_str("Bubblewrap worker watchdog thread panicked")
            }
            Self::Termination(error) => {
                write!(formatter, "Bubblewrap worker termination failed: {error}")
            }
        }
    }
}

impl std::error::Error for BubblewrapWorkerWatchdogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Termination(error) => Some(error),
            Self::InvalidDeadline
            | Self::DeadlineOverflow
            | Self::InvocationAlreadyActive
            | Self::InvocationMismatch
            | Self::InvocationSequenceExhausted
            | Self::NoActiveInvocation
            | Self::SessionDeadlineElapsed(_)
            | Self::SessionTerminated(_)
            | Self::LifecycleFailed
            | Self::Unavailable
            | Self::ThreadPanicked => None,
        }
    }
}

enum WatchdogCommand {
    Arm {
        maximum: Duration,
        reply: mpsc::Sender<Result<u64, BubblewrapWorkerWatchdogError>>,
    },
    Disarm {
        sequence: u64,
        reply:
            mpsc::Sender<Result<BubblewrapWorkerInvocationOutcome, BubblewrapWorkerWatchdogError>>,
    },
    Terminate {
        reply: mpsc::Sender<Result<BubblewrapTermination, BubblewrapWorkerWatchdogError>>,
    },
    Shutdown {
        reply: mpsc::Sender<Result<BubblewrapTermination, BubblewrapWorkerWatchdogError>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchdogTerminationReason {
    DeadlineElapsed,
    SessionDeadlineElapsed,
    HostTerminated,
    Shutdown,
    ProcessExited,
}

enum WatchdogState {
    Idle,
    Active {
        sequence: u64,
        deadline: Instant,
    },
    Terminated {
        reason: WatchdogTerminationReason,
        outcome: BubblewrapTermination,
    },
    Failed,
}

fn take_pending_lifecycle(
    pending_lifecycle: &Mutex<Option<BubblewrapWorkerLifecycle>>,
) -> BubblewrapWorkerLifecycle {
    pending_lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .expect("Bubblewrap watchdog lifecycle must be transferred exactly once")
}

fn request_termination(
    sender: &mpsc::Sender<WatchdogCommand>,
) -> Result<BubblewrapTermination, BubblewrapWorkerWatchdogError> {
    let (reply_sender, reply_receiver) = mpsc::channel();
    sender
        .send(WatchdogCommand::Terminate {
            reply: reply_sender,
        })
        .map_err(|_| BubblewrapWorkerWatchdogError::Unavailable)?;
    reply_receiver
        .recv()
        .map_err(|_| BubblewrapWorkerWatchdogError::Unavailable)?
}

fn run_watchdog_thread(
    mut lifecycle: BubblewrapWorkerLifecycle,
    receiver: mpsc::Receiver<WatchdogCommand>,
    session_deadline: Option<Instant>,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_watchdog_loop(&mut lifecycle, receiver, session_deadline);
    }));
    // A panic or disconnected controller must never leave the child behind.
    let _ = lifecycle.terminate();
}

fn run_watchdog_loop(
    lifecycle: &mut BubblewrapWorkerLifecycle,
    receiver: mpsc::Receiver<WatchdogCommand>,
    session_deadline: Option<Instant>,
) {
    let mut state = WatchdogState::Idle;
    let mut next_sequence = 1;
    loop {
        let deadline = next_watchdog_deadline(&state, session_deadline);
        let command = match expired_watchdog_reason(&state, session_deadline, Instant::now()) {
            Some(reason) => {
                let _ = terminate_watchdog_worker(lifecycle, &mut state, reason);
                continue;
            }
            None => match deadline {
                Some(deadline) => match receiver
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                {
                    Ok(command) => command,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let reason =
                            expired_watchdog_reason(&state, session_deadline, Instant::now())
                                .unwrap_or(WatchdogTerminationReason::DeadlineElapsed);
                        let _ = terminate_watchdog_worker(lifecycle, &mut state, reason);
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        let _ = terminate_watchdog_worker(
                            lifecycle,
                            &mut state,
                            WatchdogTerminationReason::Shutdown,
                        );
                        break;
                    }
                },
                None => match receiver.recv() {
                    Ok(command) => command,
                    Err(_) => {
                        let _ = terminate_watchdog_worker(
                            lifecycle,
                            &mut state,
                            WatchdogTerminationReason::Shutdown,
                        );
                        break;
                    }
                },
            },
        };

        if let Some(reason) = expired_watchdog_reason(&state, session_deadline, Instant::now()) {
            let _ = terminate_watchdog_worker(lifecycle, &mut state, reason);
        }

        if handle_watchdog_command(
            command,
            lifecycle,
            &mut state,
            &mut next_sequence,
            session_deadline,
        ) {
            break;
        }
    }
}

fn next_watchdog_deadline(
    state: &WatchdogState,
    session_deadline: Option<Instant>,
) -> Option<Instant> {
    let active_deadline = match state {
        WatchdogState::Active { deadline, .. } => Some(*deadline),
        WatchdogState::Idle | WatchdogState::Terminated { .. } | WatchdogState::Failed => None,
    };
    let session_deadline = match state {
        WatchdogState::Idle | WatchdogState::Active { .. } => session_deadline,
        WatchdogState::Terminated { .. } | WatchdogState::Failed => None,
    };
    match (active_deadline, session_deadline) {
        (Some(active), Some(session)) => Some(active.min(session)),
        (Some(active), None) => Some(active),
        (None, Some(session)) => Some(session),
        (None, None) => None,
    }
}

fn expired_watchdog_reason(
    state: &WatchdogState,
    session_deadline: Option<Instant>,
    now: Instant,
) -> Option<WatchdogTerminationReason> {
    match state {
        WatchdogState::Idle | WatchdogState::Active { .. } => {
            if session_deadline.is_some_and(|deadline| now >= deadline) {
                return Some(WatchdogTerminationReason::SessionDeadlineElapsed);
            }
        }
        WatchdogState::Terminated { .. } | WatchdogState::Failed => return None,
    }

    match state {
        WatchdogState::Active { deadline, .. } if now >= *deadline => {
            Some(WatchdogTerminationReason::DeadlineElapsed)
        }
        WatchdogState::Idle
        | WatchdogState::Active { .. }
        | WatchdogState::Terminated { .. }
        | WatchdogState::Failed => None,
    }
}

fn handle_watchdog_command(
    command: WatchdogCommand,
    lifecycle: &mut BubblewrapWorkerLifecycle,
    state: &mut WatchdogState,
    next_sequence: &mut u64,
    session_deadline: Option<Instant>,
) -> bool {
    match command {
        WatchdogCommand::Arm { maximum, reply } => {
            let _ = reply.send(arm_watchdog_call(
                lifecycle,
                state,
                next_sequence,
                maximum,
                session_deadline,
            ));
            false
        }
        WatchdogCommand::Disarm { sequence, reply } => {
            let _ = reply.send(finish_watchdog_call(
                lifecycle,
                state,
                sequence,
                session_deadline,
            ));
            false
        }
        WatchdogCommand::Terminate { reply } => {
            let _ = reply.send(terminate_watchdog_worker(
                lifecycle,
                state,
                WatchdogTerminationReason::HostTerminated,
            ));
            false
        }
        WatchdogCommand::Shutdown { reply } => {
            let _ = reply.send(terminate_watchdog_worker(
                lifecycle,
                state,
                WatchdogTerminationReason::Shutdown,
            ));
            true
        }
    }
}

fn arm_watchdog_call(
    lifecycle: &mut BubblewrapWorkerLifecycle,
    state: &mut WatchdogState,
    next_sequence: &mut u64,
    maximum: Duration,
    session_deadline: Option<Instant>,
) -> Result<u64, BubblewrapWorkerWatchdogError> {
    if maximum.is_zero() {
        return Err(BubblewrapWorkerWatchdogError::InvalidDeadline);
    }
    if let Some(reason) = expired_watchdog_reason(state, session_deadline, Instant::now()) {
        let _ = terminate_watchdog_worker(lifecycle, state, reason)?;
    }
    match state {
        WatchdogState::Idle => {
            if lifecycle
                .child_mut()
                .try_wait()
                .map_err(BubblewrapTerminationError::Inspect)
                .map_err(BubblewrapWorkerWatchdogError::Termination)?
                .is_some()
            {
                // A direct Bubblewrap exit does not prove that a cgroup
                // descendant has exited. Reuse managed termination so a
                // cgroup-backed lifecycle kills and cleans its full subtree.
                let outcome = lifecycle
                    .terminate()
                    .map_err(BubblewrapWorkerWatchdogError::Termination)?;
                *state = WatchdogState::Terminated {
                    reason: WatchdogTerminationReason::ProcessExited,
                    outcome: outcome.clone(),
                };
                return Err(BubblewrapWorkerWatchdogError::SessionTerminated(outcome));
            }
            if *next_sequence == u64::MAX {
                return Err(BubblewrapWorkerWatchdogError::InvocationSequenceExhausted);
            }
            let deadline = Instant::now()
                .checked_add(maximum)
                .ok_or(BubblewrapWorkerWatchdogError::DeadlineOverflow)?;
            let sequence = *next_sequence;
            *next_sequence = next_sequence.saturating_add(1);
            *state = WatchdogState::Active { sequence, deadline };
            Ok(sequence)
        }
        WatchdogState::Active { .. } => Err(BubblewrapWorkerWatchdogError::InvocationAlreadyActive),
        WatchdogState::Terminated {
            reason: WatchdogTerminationReason::SessionDeadlineElapsed,
            outcome,
        } => Err(BubblewrapWorkerWatchdogError::SessionDeadlineElapsed(
            outcome.clone(),
        )),
        WatchdogState::Terminated { outcome, .. } => Err(
            BubblewrapWorkerWatchdogError::SessionTerminated(outcome.clone()),
        ),
        WatchdogState::Failed => Err(BubblewrapWorkerWatchdogError::LifecycleFailed),
    }
}

fn finish_watchdog_call(
    lifecycle: &mut BubblewrapWorkerLifecycle,
    state: &mut WatchdogState,
    sequence: u64,
    session_deadline: Option<Instant>,
) -> Result<BubblewrapWorkerInvocationOutcome, BubblewrapWorkerWatchdogError> {
    if let Some(reason) = expired_watchdog_reason(state, session_deadline, Instant::now()) {
        let _ = terminate_watchdog_worker(lifecycle, state, reason)?;
    }
    match state {
        WatchdogState::Idle => Err(BubblewrapWorkerWatchdogError::NoActiveInvocation),
        WatchdogState::Active {
            sequence: active_sequence,
            deadline,
        } => {
            if *active_sequence != sequence {
                return Err(BubblewrapWorkerWatchdogError::InvocationMismatch);
            }
            if Instant::now() >= *deadline {
                let outcome = terminate_watchdog_worker(
                    lifecycle,
                    state,
                    WatchdogTerminationReason::DeadlineElapsed,
                )?;
                return Ok(BubblewrapWorkerInvocationOutcome::DeadlineElapsed(outcome));
            }
            *state = WatchdogState::Idle;
            Ok(BubblewrapWorkerInvocationOutcome::Completed)
        }
        WatchdogState::Terminated { reason, outcome } => {
            Ok(invocation_outcome(*reason, outcome.clone()))
        }
        WatchdogState::Failed => Err(BubblewrapWorkerWatchdogError::LifecycleFailed),
    }
}

fn terminate_watchdog_worker(
    lifecycle: &mut BubblewrapWorkerLifecycle,
    state: &mut WatchdogState,
    reason: WatchdogTerminationReason,
) -> Result<BubblewrapTermination, BubblewrapWorkerWatchdogError> {
    if let WatchdogState::Terminated { outcome, .. } = state {
        return Ok(outcome.clone());
    }
    match lifecycle.terminate() {
        Ok(outcome) => {
            *state = WatchdogState::Terminated {
                reason,
                outcome: outcome.clone(),
            };
            Ok(outcome)
        }
        Err(error) => {
            *state = WatchdogState::Failed;
            Err(BubblewrapWorkerWatchdogError::Termination(error))
        }
    }
}

fn invocation_outcome(
    reason: WatchdogTerminationReason,
    outcome: BubblewrapTermination,
) -> BubblewrapWorkerInvocationOutcome {
    match reason {
        WatchdogTerminationReason::DeadlineElapsed => {
            BubblewrapWorkerInvocationOutcome::DeadlineElapsed(outcome)
        }
        WatchdogTerminationReason::SessionDeadlineElapsed => {
            BubblewrapWorkerInvocationOutcome::SessionDeadlineElapsed(outcome)
        }
        WatchdogTerminationReason::HostTerminated
        | WatchdogTerminationReason::Shutdown
        | WatchdogTerminationReason::ProcessExited => {
            BubblewrapWorkerInvocationOutcome::Terminated(outcome)
        }
    }
}

/// Policy compilation failure.
#[derive(Debug)]
pub enum BubblewrapPolicyError {
    Protocol(ProtocolError),
    InvalidPrivateTmpfsSize {
        maximum_bytes: usize,
    },
    InvalidEphemeralFileRootSize {
        maximum_bytes: usize,
    },
    UnboundedFileRootWriteForbidden {
        id: String,
    },
    UnboundedPrivateTmpfsForbidden,
    BoundedFileRootWritesRequireUserNamespaceLockdown,
    DescriptorPinnedMountsUnsupportedPlatform,
    DescriptorPinnedExecutablesUnsupportedPlatform,
    DescriptorPinnedExecutablesRequirePinnedMountSources,
    EmptyResourceLimits,
    MissingSeccompAllowlist,
    MissingSeccompExecve,
    SeccompAllowlistConflictsWithHardening {
        syscall: u32,
    },
    SeccompProgramTooLarge {
        instructions: usize,
    },
    SeccompUnsupportedPlatform,
    SeccompUnsupportedArchitecture {
        architecture: &'static str,
    },
    InvalidPath {
        field: &'static str,
        path: PathBuf,
        reason: &'static str,
    },
    SourceIo {
        field: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    InvalidSourceType {
        field: &'static str,
        path: PathBuf,
        expected: &'static str,
    },
    RootMountForbidden {
        field: &'static str,
        path: PathBuf,
    },
    DuplicateFileRoot {
        id: String,
    },
    MissingFileRoot {
        id: String,
    },
    UnsupportedResource {
        resource: ResourceSelector,
    },
    ReservedMountDestination {
        destination: PathBuf,
        reserved: &'static str,
    },
    OverlappingMountDestinations {
        first: PathBuf,
        second: PathBuf,
    },
    WorkerProgramNotMounted {
        program: PathBuf,
    },
    ResourceLimitRunnerMatchesWorker {
        program: PathBuf,
    },
    ResourceLimitRunnerNotMounted {
        program: PathBuf,
    },
    SourceNotExecutable {
        field: &'static str,
        path: PathBuf,
    },
    WorkerProgramNotExecutable {
        program: PathBuf,
    },
    ResourceLimitRunnerNotExecutable {
        program: PathBuf,
    },
}

impl Display for BubblewrapPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "invalid capability manifest: {error}"),
            Self::InvalidPrivateTmpfsSize { maximum_bytes } => write!(
                formatter,
                "private tmpfs maximum must be within 1..={MAX_TMPFS_BYTES} bytes; got {maximum_bytes}"
            ),
            Self::InvalidEphemeralFileRootSize { maximum_bytes } => write!(
                formatter,
                "ephemeral file-root maximum must be within 1..={MAX_TMPFS_BYTES} bytes; got {maximum_bytes}"
            ),
            Self::UnboundedFileRootWriteForbidden { id } => write!(
                formatter,
                "file-root selector {id:?} is a host-backed writable mount, but bounded file-root writes are required"
            ),
            Self::UnboundedPrivateTmpfsForbidden => formatter.write_str(
                "private /tmp is unbounded, but bounded file-root writes are required",
            ),
            Self::BoundedFileRootWritesRequireUserNamespaceLockdown => formatter.write_str(
                "bounded file-root writes require mandatory further-user-namespace lockdown",
            ),
            Self::DescriptorPinnedMountsUnsupportedPlatform => formatter.write_str(
                "descriptor-pinned mount roots are supported only on Linux",
            ),
            Self::DescriptorPinnedExecutablesUnsupportedPlatform => formatter.write_str(
                "descriptor-pinned executable sources are supported only on Linux",
            ),
            Self::DescriptorPinnedExecutablesRequirePinnedMountSources => formatter.write_str(
                "descriptor-pinned executable sources require descriptor-pinned mount roots",
            ),
            Self::EmptyResourceLimits => {
                formatter.write_str("resource limit runner requires at least one finite limit")
            }
            Self::MissingSeccompAllowlist => formatter.write_str(
                "strict seccomp profile requires a host-selected syscall allowlist",
            ),
            Self::MissingSeccompExecve => formatter.write_str(
                "strict seccomp allowlist must include Bubblewrap's required execve syscall",
            ),
            Self::SeccompAllowlistConflictsWithHardening { syscall } => write!(
                formatter,
                "strict seccomp allowlist syscall {syscall} conflicts with Splash's fixed hardening"
            ),
            Self::SeccompProgramTooLarge { instructions } => write!(
                formatter,
                "generated seccomp program has {instructions} instructions, exceeding Linux's {MAX_LINUX_SECCOMP_FILTER_INSTRUCTIONS} instruction limit"
            ),
            Self::SeccompUnsupportedPlatform => {
                formatter.write_str("selected seccomp profile is supported only on Linux")
            }
            Self::SeccompUnsupportedArchitecture { architecture } => write!(
                formatter,
                "selected seccomp profile does not support Linux architecture {architecture}"
            ),
            Self::InvalidPath {
                field,
                path,
                reason,
            } => write!(formatter, "{field} path {} {reason}", path.display()),
            Self::SourceIo {
                field,
                path,
                source,
            } => write!(
                formatter,
                "cannot resolve {field} {}: {source}",
                path.display()
            ),
            Self::InvalidSourceType {
                field,
                path,
                expected,
            } => write!(formatter, "{field} {} must be a {expected}", path.display()),
            Self::RootMountForbidden { field, path } => {
                write!(
                    formatter,
                    "{field} {} must not resolve to /",
                    path.display()
                )
            }
            Self::DuplicateFileRoot { id } => {
                write!(
                    formatter,
                    "file-root selector {id:?} is registered more than once"
                )
            }
            Self::MissingFileRoot { id } => {
                write!(
                    formatter,
                    "no host registration exists for file-root selector {id:?}"
                )
            }
            Self::UnsupportedResource { resource } => write!(
                formatter,
                "Bubblewrap policy cannot enforce {:?} selector {:?}",
                resource.kind, resource.id
            ),
            Self::ReservedMountDestination {
                destination,
                reserved,
            } => write!(
                formatter,
                "mount destination {} overlaps Bubblewrap-managed {reserved}",
                destination.display()
            ),
            Self::OverlappingMountDestinations { first, second } => write!(
                formatter,
                "mount destinations {} and {} overlap",
                first.display(),
                second.display()
            ),
            Self::WorkerProgramNotMounted { program } => write!(
                formatter,
                "worker program {} is not visible through a read-only runtime mount",
                program.display()
            ),
            Self::ResourceLimitRunnerMatchesWorker { program } => write!(
                formatter,
                "resource limit runner {} must not be the worker program",
                program.display()
            ),
            Self::ResourceLimitRunnerNotMounted { program } => write!(
                formatter,
                "resource limit runner {} is not visible through a read-only runtime mount",
                program.display()
            ),
            Self::SourceNotExecutable { field, path } => {
                write!(formatter, "{field} {} must be executable", path.display())
            }
            Self::WorkerProgramNotExecutable { program } => write!(
                formatter,
                "worker program {} must be a regular executable file",
                program.display()
            ),
            Self::ResourceLimitRunnerNotExecutable { program } => write!(
                formatter,
                "resource limit runner {} must be a regular executable file",
                program.display()
            ),
        }
    }
}

impl std::error::Error for BubblewrapPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::SourceIo { source, .. } => Some(source),
            Self::InvalidPrivateTmpfsSize { .. }
            | Self::InvalidEphemeralFileRootSize { .. }
            | Self::UnboundedFileRootWriteForbidden { .. }
            | Self::UnboundedPrivateTmpfsForbidden
            | Self::BoundedFileRootWritesRequireUserNamespaceLockdown
            | Self::DescriptorPinnedMountsUnsupportedPlatform
            | Self::DescriptorPinnedExecutablesUnsupportedPlatform
            | Self::DescriptorPinnedExecutablesRequirePinnedMountSources
            | Self::EmptyResourceLimits
            | Self::MissingSeccompAllowlist
            | Self::MissingSeccompExecve
            | Self::SeccompAllowlistConflictsWithHardening { .. }
            | Self::SeccompProgramTooLarge { .. }
            | Self::SeccompUnsupportedPlatform
            | Self::SeccompUnsupportedArchitecture { .. }
            | Self::InvalidPath { .. }
            | Self::InvalidSourceType { .. }
            | Self::RootMountForbidden { .. }
            | Self::DuplicateFileRoot { .. }
            | Self::MissingFileRoot { .. }
            | Self::UnsupportedResource { .. }
            | Self::ReservedMountDestination { .. }
            | Self::OverlappingMountDestinations { .. }
            | Self::WorkerProgramNotMounted { .. }
            | Self::ResourceLimitRunnerMatchesWorker { .. }
            | Self::ResourceLimitRunnerNotMounted { .. }
            | Self::SourceNotExecutable { .. }
            | Self::WorkerProgramNotExecutable { .. }
            | Self::ResourceLimitRunnerNotExecutable { .. } => None,
        }
    }
}

/// Failure while starting a compiled Bubblewrap command.
#[derive(Debug)]
pub enum BubblewrapSpawnError {
    UnsupportedPlatform,
    SeccompTransport(io::Error),
    PinnedMountTransport(io::Error),
    PinnedExecutableTransport(io::Error),
    Spawn(io::Error),
    MissingStdin,
    MissingStdout,
    CgroupMembership(CgroupV2SessionError),
    CgroupJoinTimeout(Duration),
    CgroupRunnerExited(ExitStatus),
}

/// Failure while starting a Bubblewrap worker through a cgroup-v2 runner.
#[derive(Debug)]
pub enum BubblewrapCgroupSpawnError {
    /// The host cgroup policy could not create a fresh limited child.
    Prepare(CgroupV2PrepareError),
    /// Bubblewrap or the fixed cgroup runner could not be spawned.
    Spawn(BubblewrapSpawnError),
}

impl Display for BubblewrapCgroupSpawnError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prepare(error) => {
                write!(
                    formatter,
                    "could not prepare cgroup-v2 worker session: {error}"
                )
            }
            Self::Spawn(error) => write!(formatter, "could not start cgroup-v2 worker: {error}"),
        }
    }
}

impl std::error::Error for BubblewrapCgroupSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Prepare(error) => Some(error),
            Self::Spawn(error) => Some(error),
        }
    }
}

/// Failure while launching a worker with a private-pipe session bootstrap.
#[derive(Debug)]
pub enum BubblewrapBootstrapError {
    Spawn(BubblewrapSpawnError),
    SessionMismatch { expected: String, actual: String },
    Bootstrap(PrivatePipeWorkerBootstrapError),
}

impl Display for BubblewrapBootstrapError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "could not start Bubblewrap worker: {error}"),
            Self::SessionMismatch { .. } => {
                formatter.write_str("private worker bootstrap does not match the compiled session")
            }
            Self::Bootstrap(error) => {
                write!(formatter, "could not provision worker bootstrap: {error}")
            }
        }
    }
}

impl std::error::Error for BubblewrapBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::Bootstrap(error) => Some(error),
            Self::SessionMismatch { .. } => None,
        }
    }
}

/// Failure while bootstrapping a cgroup-v2-limited Bubblewrap worker.
#[derive(Debug)]
pub enum BubblewrapCgroupBootstrapError {
    Spawn(BubblewrapCgroupSpawnError),
    SessionMismatch { expected: String, actual: String },
    Bootstrap(PrivatePipeWorkerBootstrapError),
}

impl Display for BubblewrapCgroupBootstrapError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "could not start cgroup-v2 worker: {error}"),
            Self::SessionMismatch { .. } => {
                formatter.write_str("private worker bootstrap does not match the compiled session")
            }
            Self::Bootstrap(error) => {
                write!(
                    formatter,
                    "could not provision cgroup-v2 worker bootstrap: {error}"
                )
            }
        }
    }
}

impl std::error::Error for BubblewrapCgroupBootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::Bootstrap(error) => Some(error),
            Self::SessionMismatch { .. } => None,
        }
    }
}

/// Failure while force-terminating and reaping a Bubblewrap worker.
#[derive(Debug)]
pub enum BubblewrapTerminationError {
    Inspect(io::Error),
    Kill(io::Error),
    Wait(io::Error),
    Cgroup(CgroupV2SessionError),
}

impl Display for BubblewrapTerminationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect(error) => {
                write!(
                    formatter,
                    "could not inspect Bubblewrap worker status: {error}"
                )
            }
            Self::Kill(error) => {
                write!(formatter, "could not terminate Bubblewrap worker: {error}")
            }
            Self::Wait(error) => write!(formatter, "could not reap Bubblewrap worker: {error}"),
            Self::Cgroup(error) => {
                write!(
                    formatter,
                    "could not terminate or clean up worker cgroup: {error}"
                )
            }
        }
    }
}

impl std::error::Error for BubblewrapTerminationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspect(error) | Self::Kill(error) | Self::Wait(error) => Some(error),
            Self::Cgroup(error) => Some(error),
        }
    }
}

impl Display for BubblewrapSpawnError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("Bubblewrap workers are supported only on Linux")
            }
            Self::SeccompTransport(error) => {
                write!(
                    formatter,
                    "could not prepare Bubblewrap seccomp program: {error}"
                )
            }
            Self::PinnedMountTransport(error) => {
                write!(
                    formatter,
                    "could not prepare a descriptor-pinned Bubblewrap mount: {error}"
                )
            }
            Self::PinnedExecutableTransport(error) => write!(
                formatter,
                "could not prepare a descriptor-pinned Bubblewrap executable: {error}"
            ),
            Self::Spawn(error) => write!(formatter, "failed to spawn Bubblewrap worker: {error}"),
            Self::MissingStdin => formatter.write_str("Bubblewrap worker did not expose stdin"),
            Self::MissingStdout => formatter.write_str("Bubblewrap worker did not expose stdout"),
            Self::CgroupMembership(error) => {
                write!(
                    formatter,
                    "could not verify cgroup worker membership: {error}"
                )
            }
            Self::CgroupJoinTimeout(timeout) => write!(
                formatter,
                "cgroup runner did not join the worker cgroup within {timeout:?}"
            ),
            Self::CgroupRunnerExited(status) => write!(
                formatter,
                "cgroup runner exited before joining the worker cgroup: {status}"
            ),
        }
    }
}

impl std::error::Error for BubblewrapSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SeccompTransport(error)
            | Self::PinnedMountTransport(error)
            | Self::PinnedExecutableTransport(error)
            | Self::Spawn(error) => Some(error),
            Self::CgroupMembership(error) => Some(error),
            Self::UnsupportedPlatform | Self::MissingStdin | Self::MissingStdout => None,
            Self::CgroupJoinTimeout(_) | Self::CgroupRunnerExited(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MountSourceType {
    File,
    Directory,
}

#[cfg(target_os = "linux")]
const PINNED_MOUNT_DESCRIPTOR_PLACEHOLDER: &str = "<pinned-mount-source>";

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompiledMount {
    destination: PathBuf,
    kind: CompiledMountKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CompiledMountKind {
    Bind {
        source: CompiledBindSource,
        access: FileRootAccess,
        source_type: MountSourceType,
        is_runtime: bool,
    },
    BoundedTmpfs {
        maximum_bytes: NonZeroUsize,
    },
}

/// A canonical source path plus an optional Linux descriptor that fixes the
/// selected mount or executable file source at compilation time.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CompiledBindSource {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    pinned_descriptor: Option<PinnedSourceDescriptor>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct PinnedSourceDescriptor {
    descriptor: Arc<OwnedFd>,
}

#[cfg(target_os = "linux")]
impl PartialEq for PinnedSourceDescriptor {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.descriptor, &other.descriptor)
    }
}

#[cfg(target_os = "linux")]
impl Eq for PinnedSourceDescriptor {}

#[cfg(target_os = "linux")]
impl PinnedSourceDescriptor {
    fn duplicate_for_child(&self) -> io::Result<OwnedFd> {
        let descriptor = fcntl_dupfd_cloexec(self.descriptor.as_ref(), 3)?;
        fcntl_setfd(&descriptor, FdFlags::empty())?;
        Ok(descriptor)
    }
}

/// A fixed host executable plus an optional Linux descriptor that keeps the
/// selected executable inode alive until launch.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CompiledHostExecutable {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    pinned_descriptor: Option<PinnedSourceDescriptor>,
}

impl CompiledHostExecutable {
    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(target_os = "linux")]
    fn is_descriptor_pinned(&self) -> bool {
        self.pinned_descriptor.is_some()
    }

    #[cfg(target_os = "linux")]
    fn prepare_for_execution(&self) -> Result<(PathBuf, Option<OwnedFd>), BubblewrapSpawnError> {
        let Some(pinned) = &self.pinned_descriptor else {
            return Ok((self.path.clone(), None));
        };
        let descriptor = pinned
            .duplicate_for_child()
            .map_err(BubblewrapSpawnError::PinnedExecutableTransport)?;
        let program = PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd()));
        Ok((program, Some(descriptor)))
    }
}

impl CompiledBindSource {
    fn path(&self) -> &Path {
        &self.path
    }

    fn append_display_argument(&self, arguments: &mut Vec<OsString>) {
        #[cfg(target_os = "linux")]
        if self.pinned_descriptor.is_some() {
            arguments.push(OsString::from(PINNED_MOUNT_DESCRIPTOR_PLACEHOLDER));
            return;
        }

        arguments.push(self.path.clone().into_os_string());
    }

    #[cfg(target_os = "linux")]
    fn duplicate_for_bubblewrap(&self) -> Result<Option<OwnedFd>, BubblewrapSpawnError> {
        let Some(pinned) = &self.pinned_descriptor else {
            return Ok(None);
        };
        let descriptor = pinned
            .duplicate_for_child()
            .map_err(BubblewrapSpawnError::PinnedMountTransport)?;
        Ok(Some(descriptor))
    }
}

impl CompiledMount {
    fn exposes_program(&self, program: &Path) -> bool {
        match &self.kind {
            CompiledMountKind::Bind {
                source_type,
                is_runtime: true,
                ..
            } => match *source_type {
                MountSourceType::File => program == self.destination,
                MountSourceType::Directory => path_is_within(program, &self.destination),
            },
            CompiledMountKind::Bind {
                is_runtime: false, ..
            }
            | CompiledMountKind::BoundedTmpfs { .. } => false,
        }
    }

    fn program_source(&self, program: &Path) -> Option<PathBuf> {
        if !self.exposes_program(program) {
            return None;
        }
        match &self.kind {
            CompiledMountKind::Bind {
                source,
                source_type,
                ..
            } => match source_type {
                MountSourceType::File => Some(source.path.clone()),
                MountSourceType::Directory => program
                    .strip_prefix(&self.destination)
                    .ok()
                    .map(|relative| source.path().join(relative)),
            },
            CompiledMountKind::BoundedTmpfs { .. } => None,
        }
    }

    fn is_descriptor_pinned_file_for_program(&self, program: &Path) -> bool {
        match &self.kind {
            CompiledMountKind::Bind {
                source,
                source_type: MountSourceType::File,
                is_runtime: true,
                ..
            } if program == self.destination => {
                #[cfg(target_os = "linux")]
                {
                    source.pinned_descriptor.is_some()
                }

                #[cfg(not(target_os = "linux"))]
                {
                    false
                }
            }
            CompiledMountKind::Bind { .. } | CompiledMountKind::BoundedTmpfs { .. } => false,
        }
    }

    fn append_display_arguments(&self, arguments: &mut Vec<OsString>) {
        match &self.kind {
            CompiledMountKind::Bind { source, access, .. } => {
                arguments.push(OsString::from(match *access {
                    FileRootAccess::ReadOnly => {
                        #[cfg(target_os = "linux")]
                        if source.pinned_descriptor.is_some() {
                            "--ro-bind-fd"
                        } else {
                            "--ro-bind"
                        }
                        #[cfg(not(target_os = "linux"))]
                        "--ro-bind"
                    }
                    FileRootAccess::ReadWrite => {
                        #[cfg(target_os = "linux")]
                        if source.pinned_descriptor.is_some() {
                            "--bind-fd"
                        } else {
                            "--bind"
                        }
                        #[cfg(not(target_os = "linux"))]
                        "--bind"
                    }
                }));
                source.append_display_argument(arguments);
                arguments.push(self.destination.clone().into_os_string());
            }
            CompiledMountKind::BoundedTmpfs { maximum_bytes } => {
                arguments.push(OsString::from("--size"));
                arguments.push(OsString::from(maximum_bytes.get().to_string()));
                arguments.push(OsString::from("--tmpfs"));
                arguments.push(self.destination.clone().into_os_string());
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn append_spawn_arguments(
        &self,
        arguments: &mut Vec<OsString>,
        mount_descriptors: &mut Vec<OwnedFd>,
    ) -> Result<(), BubblewrapSpawnError> {
        match &self.kind {
            CompiledMountKind::Bind { source, access, .. } => {
                let descriptor = source.duplicate_for_bubblewrap()?;
                let option = match (access, descriptor.is_some()) {
                    (FileRootAccess::ReadOnly, true) => "--ro-bind-fd",
                    (FileRootAccess::ReadWrite, true) => "--bind-fd",
                    (FileRootAccess::ReadOnly, false) => "--ro-bind",
                    (FileRootAccess::ReadWrite, false) => "--bind",
                };
                arguments.push(OsString::from(option));
                if let Some(descriptor) = descriptor {
                    arguments.push(OsString::from(descriptor.as_raw_fd().to_string()));
                    mount_descriptors.push(descriptor);
                } else {
                    arguments.push(source.path.clone().into_os_string());
                }
                arguments.push(self.destination.clone().into_os_string());
            }
            CompiledMountKind::BoundedTmpfs { maximum_bytes } => {
                arguments.push(OsString::from("--size"));
                arguments.push(OsString::from(maximum_bytes.get().to_string()));
                arguments.push(OsString::from("--tmpfs"));
                arguments.push(self.destination.clone().into_os_string());
            }
        }
        Ok(())
    }
}

fn display_arguments(
    mount_prefix_arguments: &[OsString],
    mounts: &[CompiledMount],
    executable_overlays: &[CompiledMount],
    mount_suffix_arguments: &[OsString],
) -> Vec<OsString> {
    let mut arguments = mount_prefix_arguments.to_vec();
    for mount in mounts {
        mount.append_display_arguments(&mut arguments);
    }
    for executable_overlay in executable_overlays {
        executable_overlay.append_display_arguments(&mut arguments);
    }
    arguments.extend(mount_suffix_arguments.iter().cloned());
    arguments
}

fn validate_host_path(field: &'static str, path: &Path) -> Result<(), BubblewrapPolicyError> {
    validate_absolute_normal_path(field, path)
}

fn validate_sandbox_path(field: &'static str, path: &Path) -> Result<(), BubblewrapPolicyError> {
    validate_absolute_normal_path(field, path)
}

fn validate_absolute_normal_path(
    field: &'static str,
    path: &Path,
) -> Result<(), BubblewrapPolicyError> {
    if !path.is_absolute() {
        return Err(BubblewrapPolicyError::InvalidPath {
            field,
            path: path.to_path_buf(),
            reason: "must be absolute",
        });
    }
    if path == Path::new("/") {
        return Err(BubblewrapPolicyError::InvalidPath {
            field,
            path: path.to_path_buf(),
            reason: "must not be /",
        });
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(BubblewrapPolicyError::InvalidPath {
            field,
            path: path.to_path_buf(),
            reason: "must not contain . or .. components",
        });
    }
    Ok(())
}

fn resolve_regular_executable_file(
    field: &'static str,
    path: &Path,
) -> Result<PathBuf, BubblewrapPolicyError> {
    let path = canonical_existing_path(field, path)?;
    let metadata = fs::metadata(&path).map_err(|source| BubblewrapPolicyError::SourceIo {
        field,
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(BubblewrapPolicyError::InvalidSourceType {
            field,
            path,
            expected: "regular file",
        });
    }
    if !is_executable(&metadata) {
        return Err(BubblewrapPolicyError::SourceNotExecutable { field, path });
    }
    Ok(path)
}

fn compile_host_executable(
    field: &'static str,
    configured_path: &Path,
    binding: ExecutableSourceBinding,
) -> Result<CompiledHostExecutable, BubblewrapPolicyError> {
    let path = resolve_regular_executable_file(field, configured_path)?;
    #[cfg(target_os = "linux")]
    let pinned_descriptor = match binding {
        ExecutableSourceBinding::Path => None,
        ExecutableSourceBinding::DescriptorPinned => Some(pin_executable_source(field, &path)?),
    };
    #[cfg(not(target_os = "linux"))]
    let _ = binding;

    Ok(CompiledHostExecutable {
        path,
        #[cfg(target_os = "linux")]
        pinned_descriptor,
    })
}

fn resolve_runtime_mount(
    mount: &ReadOnlyMount,
    binding: MountSourceBinding,
) -> Result<CompiledMount, BubblewrapPolicyError> {
    let (source, source_type) =
        resolve_bind_source("runtime mount source", &mount.source, binding)?;
    Ok(CompiledMount {
        destination: mount.destination.clone(),
        kind: CompiledMountKind::Bind {
            source,
            access: FileRootAccess::ReadOnly,
            source_type,
            is_runtime: true,
        },
    })
}

fn resolve_file_root(
    binding: &FileRootBinding,
    mount_source_binding: MountSourceBinding,
) -> Result<CompiledMount, BubblewrapPolicyError> {
    let (source, source_type) =
        resolve_bind_source("file-root source", &binding.source, mount_source_binding)?;
    if source_type != MountSourceType::Directory {
        return Err(BubblewrapPolicyError::InvalidSourceType {
            field: "file-root source",
            path: source.path.clone(),
            expected: "directory",
        });
    }
    Ok(CompiledMount {
        destination: binding.destination.clone(),
        kind: CompiledMountKind::Bind {
            source,
            access: binding.access,
            source_type: MountSourceType::Directory,
            is_runtime: false,
        },
    })
}

fn compile_pinned_program_overlay(
    field: &'static str,
    source_path: PathBuf,
    destination: PathBuf,
) -> Result<CompiledMount, BubblewrapPolicyError> {
    let source = compile_bind_source(
        field,
        source_path,
        MountSourceType::File,
        MountSourceBinding::DescriptorPinned,
    )?;
    Ok(CompiledMount {
        destination,
        kind: CompiledMountKind::Bind {
            source,
            access: FileRootAccess::ReadOnly,
            source_type: MountSourceType::File,
            is_runtime: false,
        },
    })
}

fn resolve_bind_source(
    field: &'static str,
    configured_path: &Path,
    binding: MountSourceBinding,
) -> Result<(CompiledBindSource, MountSourceType), BubblewrapPolicyError> {
    let path = canonical_existing_path(field, configured_path)?;
    let metadata = fs::metadata(&path).map_err(|source| BubblewrapPolicyError::SourceIo {
        field,
        path: path.clone(),
        source,
    })?;
    let source_type = source_type(field, path.clone(), &metadata)?;
    let source = compile_bind_source(field, path, source_type, binding)?;
    Ok((source, source_type))
}

#[cfg(target_os = "linux")]
fn compile_bind_source(
    field: &'static str,
    path: PathBuf,
    source_type: MountSourceType,
    binding: MountSourceBinding,
) -> Result<CompiledBindSource, BubblewrapPolicyError> {
    let pinned_descriptor = match binding {
        MountSourceBinding::Path => None,
        MountSourceBinding::DescriptorPinned => Some(pin_mount_source(field, &path, source_type)?),
    };
    Ok(CompiledBindSource {
        path,
        pinned_descriptor,
    })
}

#[cfg(not(target_os = "linux"))]
fn compile_bind_source(
    _field: &'static str,
    path: PathBuf,
    _source_type: MountSourceType,
    binding: MountSourceBinding,
) -> Result<CompiledBindSource, BubblewrapPolicyError> {
    if binding == MountSourceBinding::DescriptorPinned {
        return Err(BubblewrapPolicyError::DescriptorPinnedMountsUnsupportedPlatform);
    }
    Ok(CompiledBindSource { path })
}

#[cfg(target_os = "linux")]
fn pin_mount_source(
    field: &'static str,
    path: &Path,
    expected_type: MountSourceType,
) -> Result<PinnedSourceDescriptor, BubblewrapPolicyError> {
    let (descriptor, file_type, _) =
        open_pinned_source(path).map_err(|source| BubblewrapPolicyError::SourceIo {
            field,
            path: path.to_path_buf(),
            source,
        })?;
    let expected = match expected_type {
        MountSourceType::File => file_type.is_file(),
        MountSourceType::Directory => file_type.is_dir(),
    };
    if !expected {
        return Err(BubblewrapPolicyError::InvalidSourceType {
            field,
            path: path.to_path_buf(),
            expected: match expected_type {
                MountSourceType::File => "regular file",
                MountSourceType::Directory => "directory",
            },
        });
    }
    Ok(descriptor)
}

#[cfg(target_os = "linux")]
fn pin_executable_source(
    field: &'static str,
    path: &Path,
) -> Result<PinnedSourceDescriptor, BubblewrapPolicyError> {
    let (descriptor, file_type, mode) =
        open_pinned_source(path).map_err(|source| BubblewrapPolicyError::SourceIo {
            field,
            path: path.to_path_buf(),
            source,
        })?;
    if !file_type.is_file() {
        return Err(BubblewrapPolicyError::InvalidSourceType {
            field,
            path: path.to_path_buf(),
            expected: "regular file",
        });
    }
    if !is_executable_mode(mode) {
        return Err(BubblewrapPolicyError::SourceNotExecutable {
            field,
            path: path.to_path_buf(),
        });
    }
    Ok(descriptor)
}

#[cfg(target_os = "linux")]
fn pin_host_executable_for_spawn(
    field: &'static str,
    path: &Path,
) -> Result<CompiledHostExecutable, BubblewrapSpawnError> {
    let (pinned_descriptor, file_type, mode) =
        open_pinned_source(path).map_err(BubblewrapSpawnError::PinnedExecutableTransport)?;
    if !file_type.is_file() || !is_executable_mode(mode) {
        return Err(BubblewrapSpawnError::PinnedExecutableTransport(
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{field} {} is not a regular executable file",
                    path.display()
                ),
            ),
        ));
    }
    Ok(CompiledHostExecutable {
        path: path.to_path_buf(),
        pinned_descriptor: Some(pinned_descriptor),
    })
}

#[cfg(target_os = "linux")]
fn open_pinned_source(path: &Path) -> io::Result<(PinnedSourceDescriptor, FileType, u32)> {
    let descriptor = open(
        path,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| -> io::Error { source.into() })?;
    let metadata = fstat(&descriptor).map_err(|source| -> io::Error { source.into() })?;
    let file_type = FileType::from_raw_mode(metadata.st_mode);
    Ok((
        PinnedSourceDescriptor {
            descriptor: Arc::new(descriptor),
        },
        file_type,
        metadata.st_mode,
    ))
}

#[cfg(target_os = "linux")]
fn is_executable_mode(mode: u32) -> bool {
    mode & 0o111 != 0
}

fn resolve_ephemeral_file_root(root: &EphemeralFileRoot) -> CompiledMount {
    CompiledMount {
        destination: root.destination.clone(),
        kind: CompiledMountKind::BoundedTmpfs {
            maximum_bytes: root.maximum_bytes,
        },
    }
}

#[cfg(target_os = "linux")]
fn ensure_mount_source_binding_supported(
    _binding: MountSourceBinding,
) -> Result<(), BubblewrapPolicyError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_executable_source_binding_supported(
    _binding: ExecutableSourceBinding,
) -> Result<(), BubblewrapPolicyError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_executable_source_binding_supported(
    binding: ExecutableSourceBinding,
) -> Result<(), BubblewrapPolicyError> {
    if binding == ExecutableSourceBinding::DescriptorPinned {
        return Err(BubblewrapPolicyError::DescriptorPinnedExecutablesUnsupportedPlatform);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_mount_source_binding_supported(
    binding: MountSourceBinding,
) -> Result<(), BubblewrapPolicyError> {
    if binding == MountSourceBinding::DescriptorPinned {
        return Err(BubblewrapPolicyError::DescriptorPinnedMountsUnsupportedPlatform);
    }
    Ok(())
}

fn canonical_existing_path(
    field: &'static str,
    path: &Path,
) -> Result<PathBuf, BubblewrapPolicyError> {
    let canonical = fs::canonicalize(path).map_err(|source| BubblewrapPolicyError::SourceIo {
        field,
        path: path.to_path_buf(),
        source,
    })?;
    if canonical == Path::new("/") {
        return Err(BubblewrapPolicyError::RootMountForbidden {
            field,
            path: canonical,
        });
    }
    Ok(canonical)
}

fn source_type(
    field: &'static str,
    path: PathBuf,
    metadata: &fs::Metadata,
) -> Result<MountSourceType, BubblewrapPolicyError> {
    if metadata.is_file() {
        Ok(MountSourceType::File)
    } else if metadata.is_dir() {
        Ok(MountSourceType::Directory)
    } else {
        Err(BubblewrapPolicyError::InvalidSourceType {
            field,
            path,
            expected: "regular file or directory",
        })
    }
}

fn validate_mount_layout(
    mounts: &mut [CompiledMount],
    private_tmpfs: bool,
) -> Result<(), BubblewrapPolicyError> {
    for mount in mounts.iter() {
        for (reserved_path, reserved_name) in reserved_destinations(private_tmpfs) {
            if paths_overlap(&mount.destination, reserved_path) {
                return Err(BubblewrapPolicyError::ReservedMountDestination {
                    destination: mount.destination.clone(),
                    reserved: reserved_name,
                });
            }
        }
    }

    mounts.sort_by(|left, right| left.destination.cmp(&right.destination));
    for (index, mount) in mounts.iter().enumerate() {
        for later_mount in &mounts[index + 1..] {
            if paths_overlap(&mount.destination, &later_mount.destination) {
                return Err(BubblewrapPolicyError::OverlappingMountDestinations {
                    first: mount.destination.clone(),
                    second: later_mount.destination.clone(),
                });
            }
        }
    }

    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeProgramSource {
    source: PathBuf,
    is_descriptor_pinned_file: bool,
}

fn validate_runtime_program(
    mounts: &[CompiledMount],
    program: &Path,
    not_mounted: fn(PathBuf) -> BubblewrapPolicyError,
    not_executable: fn(PathBuf) -> BubblewrapPolicyError,
    source_field: &'static str,
) -> Result<RuntimeProgramSource, BubblewrapPolicyError> {
    let program_mount = mounts.iter().find(|mount| mount.exposes_program(program));
    let Some(program_mount) = program_mount else {
        return Err(not_mounted(program.to_path_buf()));
    };
    let program_source = program_mount
        .program_source(program)
        .ok_or_else(|| not_mounted(program.to_path_buf()))?;
    let metadata = fs::symlink_metadata(&program_source).map_err(|source| {
        BubblewrapPolicyError::SourceIo {
            field: source_field,
            path: program_source.clone(),
            source,
        }
    })?;
    if !metadata.file_type().is_file() || !is_executable(&metadata) {
        return Err(not_executable(program.to_path_buf()));
    }
    Ok(RuntimeProgramSource {
        source: program_source,
        is_descriptor_pinned_file: program_mount.is_descriptor_pinned_file_for_program(program),
    })
}

fn reserved_destinations(private_tmpfs: bool) -> Vec<(&'static Path, &'static str)> {
    let mut destinations = vec![(Path::new("/proc"), "proc"), (Path::new("/dev"), "dev")];
    if private_tmpfs {
        destinations.push((Path::new("/tmp"), "private tmpfs"));
    }
    destinations
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    path_is_within(left, right) || path_is_within(right, left)
}

fn path_is_within(path: &Path, directory: &Path) -> bool {
    path.strip_prefix(directory).is_ok()
}

fn is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn terminate_and_reap(
    child: &mut Child,
    cgroup: &mut Option<CgroupV2Session>,
) -> Result<BubblewrapTermination, BubblewrapTerminationError> {
    let initial_status = child
        .try_wait()
        .map_err(BubblewrapTerminationError::Inspect)?;

    // A cgroup-backed launch has to terminate the full tree even when the
    // direct Bubblewrap process has already exited. `cgroup.kill` closes the
    // fork race that a direct `Child::kill` cannot cover.
    let cgroup_kill_error = cgroup.as_ref().and_then(|session| session.kill().err());

    let termination = match initial_status {
        Some(status) => Ok(BubblewrapTermination::AlreadyExited(status)),
        None => terminate_running_child(child),
    };

    let cgroup_cleanup_error = cgroup
        .as_ref()
        .and_then(|session| cleanup_cgroup_after_termination(session).err());
    if cgroup_cleanup_error.is_none() && cgroup.is_some() {
        let _ = cgroup.take();
    }

    if let Some(error) = cgroup_kill_error.or(cgroup_cleanup_error) {
        return Err(BubblewrapTerminationError::Cgroup(error));
    }
    termination
}

fn terminate_running_child(
    child: &mut Child,
) -> Result<BubblewrapTermination, BubblewrapTerminationError> {
    if let Err(error) = child.kill() {
        if let Ok(Some(status)) = child.try_wait() {
            return Ok(BubblewrapTermination::Killed(status));
        }
        return Err(BubblewrapTerminationError::Kill(error));
    }

    child
        .wait()
        .map(BubblewrapTermination::Killed)
        .map_err(BubblewrapTerminationError::Wait)
}

#[cfg(target_os = "linux")]
fn discard_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn discard_worker(child: &mut Child, cgroup: Option<&CgroupV2Session>) {
    if let Some(session) = cgroup {
        let _ = session.kill();
    }
    discard_child(child);
    if let Some(session) = cgroup {
        // The runner could join between the first cgroup kill and direct-child
        // reap on an early launch failure. A second kill after the runner PID
        // is gone covers any subtree it managed to create in that interval.
        let _ = session.kill();
        let _ = cleanup_cgroup_after_termination(session);
    }
}

fn cleanup_cgroup_after_termination(session: &CgroupV2Session) -> Result<(), CgroupV2SessionError> {
    #[cfg(not(target_os = "linux"))]
    {
        session.cleanup()
    }

    #[cfg(target_os = "linux")]
    {
        const MAX_RETRIES: usize = 50;
        const RETRY_DELAY: Duration = Duration::from_millis(10);

        for attempt in 0..=MAX_RETRIES {
            match session.cleanup() {
                Ok(()) => return Ok(()),
                Err(error) if should_retry_cgroup_cleanup(&error) && attempt < MAX_RETRIES => {
                    thread::sleep(RETRY_DELAY);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("the cgroup cleanup retry loop always returns")
    }
}

#[cfg(target_os = "linux")]
fn should_retry_cgroup_cleanup(error: &CgroupV2SessionError) -> bool {
    matches!(
        error,
        CgroupV2SessionError::Cleanup { source, .. }
            if matches!(
                source.kind(),
                io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::ResourceBusy
            )
    )
}

#[cfg(target_os = "linux")]
fn wait_for_cgroup_join(
    child: &mut Child,
    cgroup: &CgroupV2Session,
    maximum: Duration,
) -> Result<(), BubblewrapSpawnError> {
    let started = Instant::now();
    loop {
        if cgroup
            .contains_process(child.id())
            .map_err(BubblewrapSpawnError::CgroupMembership)?
        {
            return Ok(());
        }
        if let Some(status) = child.try_wait().map_err(BubblewrapSpawnError::Spawn)? {
            return Err(BubblewrapSpawnError::CgroupRunnerExited(status));
        }
        if started.elapsed() >= maximum {
            return Err(BubblewrapSpawnError::CgroupJoinTimeout(maximum));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(target_os = "linux")]
mod linux_seccomp {
    use super::{
        BubblewrapPolicyError, SeccompProgram, WorkerSeccompAllowlist, WorkerSeccompProfile,
        MAX_LINUX_SECCOMP_FILTER_INSTRUCTIONS,
    };
    use linux_raw_sys::{errno, general, ioctl, ptrace};

    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_DATA_ARGUMENTS_OFFSET: u32 = 16;
    const SECCOMP_DATA_ARGUMENT_SIZE: u32 = 8;
    const SECCOMP_FILTER_INSTRUCTION_BYTES: usize = 8;

    const BPF_LD_W_ABS: u16 = (ptrace::BPF_LD | ptrace::BPF_W | ptrace::BPF_ABS) as u16;
    const BPF_JEQ_K: u16 = (ptrace::BPF_JMP | ptrace::BPF_JEQ | ptrace::BPF_K) as u16;
    const BPF_JSET_K: u16 = (ptrace::BPF_JMP | ptrace::BPF_JSET | ptrace::BPF_K) as u16;
    const BPF_RET_K: u16 = (ptrace::BPF_RET | ptrace::BPF_K) as u16;
    const DENY_WITH_EPERM: u32 = ptrace::SECCOMP_RET_ERRNO | errno::EPERM;
    const DENY_WITH_ENOSYS: u32 = ptrace::SECCOMP_RET_ERRNO | errno::ENOSYS;
    const NAMESPACE_CLONE_FLAGS: u32 = general::CLONE_NEWNS
        | general::CLONE_NEWCGROUP
        | general::CLONE_NEWUTS
        | general::CLONE_NEWIPC
        | general::CLONE_NEWUSER
        | general::CLONE_NEWPID
        | general::CLONE_NEWNET
        | general::CLONE_NEWTIME;

    const DENIED_SYSCALLS: &[u32] = &[
        // Filesystem and namespace construction.
        general::__NR_mount,
        general::__NR_umount2,
        general::__NR_pivot_root,
        general::__NR_move_mount,
        general::__NR_open_tree,
        general::__NR_fsopen,
        general::__NR_fsconfig,
        general::__NR_fsmount,
        general::__NR_fspick,
        general::__NR_mount_setattr,
        general::__NR_unshare,
        general::__NR_setns,
        general::__NR_name_to_handle_at,
        general::__NR_open_by_handle_at,
        // Kernel-control and high-risk kernel interfaces.
        general::__NR_bpf,
        general::__NR_perf_event_open,
        general::__NR_userfaultfd,
        general::__NR_io_uring_setup,
        general::__NR_io_uring_enter,
        general::__NR_io_uring_register,
        general::__NR_init_module,
        general::__NR_finit_module,
        general::__NR_delete_module,
        general::__NR_kexec_load,
        general::__NR_kexec_file_load,
        general::__NR_reboot,
        // Cross-process inspection and keyrings.
        general::__NR_ptrace,
        general::__NR_process_vm_readv,
        general::__NR_process_vm_writev,
        general::__NR_add_key,
        general::__NR_request_key,
        general::__NR_keyctl,
        // Process hardening controls.
        general::__NR_personality,
    ];

    #[derive(Clone, Copy)]
    struct FilterInstruction {
        code: u16,
        jump_if_true: u8,
        jump_if_false: u8,
        value: u32,
    }

    impl FilterInstruction {
        const fn load_word(offset: u32) -> Self {
            Self {
                code: BPF_LD_W_ABS,
                jump_if_true: 0,
                jump_if_false: 0,
                value: offset,
            }
        }

        const fn jump_equal(value: u32, jump_if_true: u8, jump_if_false: u8) -> Self {
            Self {
                code: BPF_JEQ_K,
                jump_if_true,
                jump_if_false,
                value,
            }
        }

        const fn jump_set(value: u32, jump_if_true: u8, jump_if_false: u8) -> Self {
            Self {
                code: BPF_JSET_K,
                jump_if_true,
                jump_if_false,
                value,
            }
        }

        const fn return_value(value: u32) -> Self {
            Self {
                code: BPF_RET_K,
                jump_if_true: 0,
                jump_if_false: 0,
                value,
            }
        }

        fn append_to(self, output: &mut Vec<u8>) {
            output.extend_from_slice(&self.code.to_ne_bytes());
            output.push(self.jump_if_true);
            output.push(self.jump_if_false);
            output.extend_from_slice(&self.value.to_ne_bytes());
        }
    }

    struct ProgramBuilder {
        instructions: Vec<FilterInstruction>,
    }

    impl ProgramBuilder {
        fn new() -> Self {
            Self {
                instructions: Vec::new(),
            }
        }

        fn load_word(&mut self, offset: u32) {
            self.instructions.push(FilterInstruction::load_word(offset));
        }

        fn jump_equal(&mut self, value: u32, jump_if_true: u8, jump_if_false: u8) {
            self.instructions.push(FilterInstruction::jump_equal(
                value,
                jump_if_true,
                jump_if_false,
            ));
        }

        fn jump_set(&mut self, value: u32, jump_if_true: u8, jump_if_false: u8) {
            self.instructions.push(FilterInstruction::jump_set(
                value,
                jump_if_true,
                jump_if_false,
            ));
        }

        fn return_value(&mut self, value: u32) {
            self.instructions
                .push(FilterInstruction::return_value(value));
        }

        fn deny_syscall(&mut self, syscall: u32, action: u32) {
            self.jump_equal(syscall, 0, 1);
            self.return_value(action);
        }

        fn allow_syscall(&mut self, syscall: u32) {
            self.jump_equal(syscall, 0, 1);
            self.return_value(ptrace::SECCOMP_RET_ALLOW);
        }

        fn into_bytes(self) -> Result<Vec<u8>, BubblewrapPolicyError> {
            if self.instructions.len() > MAX_LINUX_SECCOMP_FILTER_INSTRUCTIONS {
                return Err(BubblewrapPolicyError::SeccompProgramTooLarge {
                    instructions: self.instructions.len(),
                });
            }
            let mut bytes =
                Vec::with_capacity(self.instructions.len() * SECCOMP_FILTER_INSTRUCTION_BYTES);
            for instruction in self.instructions {
                instruction.append_to(&mut bytes);
            }
            Ok(bytes)
        }
    }

    pub(super) fn compile(
        profile: WorkerSeccompProfile,
        allowlist: Option<&WorkerSeccompAllowlist>,
    ) -> Result<SeccompProgram, BubblewrapPolicyError> {
        let architecture = current_audit_architecture()?;
        let mut program = ProgramBuilder::new();

        // Linux recommends checking the ABI before interpreting syscall
        // numbers. A mismatch or x32 ABI attempt must not reach either
        // compatibility or strict allowlist policy.
        program.load_word(SECCOMP_DATA_ARCH_OFFSET);
        program.jump_equal(architecture, 1, 0);
        program.return_value(ptrace::SECCOMP_RET_KILL_PROCESS);
        program.load_word(SECCOMP_DATA_NR_OFFSET);
        #[cfg(target_arch = "x86_64")]
        {
            program.jump_set(general::__X32_SYSCALL_BIT, 0, 1);
            program.return_value(ptrace::SECCOMP_RET_KILL_PROCESS);
        }

        append_escape_surface_guards(&mut program);

        match profile {
            WorkerSeccompProfile::DenyKnownEscapeSurface => {
                program.return_value(ptrace::SECCOMP_RET_ALLOW);
            }
            WorkerSeccompProfile::StrictAllowlist => {
                let allowlist = allowlist.ok_or(BubblewrapPolicyError::MissingSeccompAllowlist)?;
                validate_strict_allowlist(allowlist)?;
                for syscall in allowlist.syscalls() {
                    program.allow_syscall(syscall);
                }
                program.return_value(ptrace::SECCOMP_RET_KILL_PROCESS);
            }
            WorkerSeccompProfile::Disabled => {
                unreachable!("disabled seccomp profiles are not compiled")
            }
        }

        Ok(SeccompProgram {
            profile,
            bytes: program.into_bytes()?,
        })
    }

    fn append_escape_surface_guards(program: &mut ProgramBuilder) {
        // Retain ordinary processes and threads through legacy clone, while
        // rejecting every namespace-creation flag. x86-64, AArch64, and
        // RISC-V all pass raw clone flags as argument 0. clone3 carries flags
        // through an indirect structure that cBPF cannot inspect, so return
        // ENOSYS to request a libc fallback rather than permit it unchecked.
        program.jump_equal(general::__NR_clone, 0, 4);
        program.load_word(SECCOMP_DATA_ARGUMENTS_OFFSET);
        program.jump_set(NAMESPACE_CLONE_FLAGS, 0, 1);
        program.return_value(DENY_WITH_EPERM);
        program.load_word(SECCOMP_DATA_NR_OFFSET);
        program.deny_syscall(general::__NR_clone3, DENY_WITH_ENOSYS);

        // TIOCSTI injects terminal input. Other ioctls remain available for
        // compatibility because a blanket ioctl denial is not a viable policy
        // for a general dynamic worker.
        program.jump_equal(general::__NR_ioctl, 0, 4);
        program.load_word(SECCOMP_DATA_ARGUMENTS_OFFSET + SECCOMP_DATA_ARGUMENT_SIZE);
        program.jump_equal(ioctl::TIOCSTI, 0, 1);
        program.return_value(DENY_WITH_EPERM);
        program.load_word(SECCOMP_DATA_NR_OFFSET);

        for &syscall in DENIED_SYSCALLS {
            program.deny_syscall(syscall, DENY_WITH_EPERM);
        }
    }

    fn validate_strict_allowlist(
        allowlist: &WorkerSeccompAllowlist,
    ) -> Result<(), BubblewrapPolicyError> {
        let mut has_execve = false;
        for syscall in allowlist.syscalls() {
            #[cfg(target_arch = "x86_64")]
            if syscall & general::__X32_SYSCALL_BIT != 0 {
                return Err(
                    BubblewrapPolicyError::SeccompAllowlistConflictsWithHardening { syscall },
                );
            }
            if syscall == general::__NR_clone3 || DENIED_SYSCALLS.contains(&syscall) {
                return Err(
                    BubblewrapPolicyError::SeccompAllowlistConflictsWithHardening { syscall },
                );
            }
            if syscall == general::__NR_execve {
                has_execve = true;
            }
        }
        if !has_execve {
            return Err(BubblewrapPolicyError::MissingSeccompExecve);
        }
        Ok(())
    }

    fn current_audit_architecture() -> Result<u32, BubblewrapPolicyError> {
        #[cfg(all(
            target_arch = "x86_64",
            target_pointer_width = "64",
            target_endian = "little"
        ))]
        {
            return Ok(ptrace::AUDIT_ARCH_X86_64);
        }
        #[cfg(all(
            target_arch = "aarch64",
            target_pointer_width = "64",
            target_endian = "little"
        ))]
        {
            return Ok(ptrace::AUDIT_ARCH_AARCH64);
        }
        #[cfg(all(
            target_arch = "riscv64",
            target_pointer_width = "64",
            target_endian = "little"
        ))]
        {
            return Ok(ptrace::AUDIT_ARCH_RISCV64);
        }
        #[allow(unreachable_code)]
        Err(BubblewrapPolicyError::SeccompUnsupportedArchitecture {
            architecture: std::env::consts::ARCH,
        })
    }

    #[cfg(test)]
    pub(super) fn evaluate_for_test(
        program: &SeccompProgram,
        architecture: u32,
        syscall: u32,
        arguments: [u64; 6],
    ) -> u32 {
        assert_eq!(
            program.bytes.len() % SECCOMP_FILTER_INSTRUCTION_BYTES,
            0,
            "cBPF program has a partial instruction"
        );

        let mut accumulator = 0;
        let mut index = 0;
        while index < program.bytes.len() / SECCOMP_FILTER_INSTRUCTION_BYTES {
            let offset = index * SECCOMP_FILTER_INSTRUCTION_BYTES;
            let code = u16::from_ne_bytes([program.bytes[offset], program.bytes[offset + 1]]);
            let jump_if_true = program.bytes[offset + 2];
            let jump_if_false = program.bytes[offset + 3];
            let value = u32::from_ne_bytes([
                program.bytes[offset + 4],
                program.bytes[offset + 5],
                program.bytes[offset + 6],
                program.bytes[offset + 7],
            ]);

            match code {
                BPF_LD_W_ABS => {
                    accumulator = seccomp_data_word(value, architecture, syscall, &arguments);
                    index += 1;
                }
                BPF_JEQ_K => {
                    let jump = if accumulator == value {
                        jump_if_true
                    } else {
                        jump_if_false
                    };
                    index += usize::from(jump) + 1;
                }
                BPF_JSET_K => {
                    let jump = if accumulator & value != 0 {
                        jump_if_true
                    } else {
                        jump_if_false
                    };
                    index += usize::from(jump) + 1;
                }
                BPF_RET_K => return value,
                _ => panic!("unexpected cBPF instruction {code:#x}"),
            }
        }

        panic!("cBPF program fell through without an action");
    }

    #[cfg(test)]
    fn seccomp_data_word(
        offset: u32,
        architecture: u32,
        syscall: u32,
        arguments: &[u64; 6],
    ) -> u32 {
        match offset {
            SECCOMP_DATA_NR_OFFSET => syscall,
            SECCOMP_DATA_ARCH_OFFSET => architecture,
            offset
                if offset >= SECCOMP_DATA_ARGUMENTS_OFFSET
                    && offset
                        < SECCOMP_DATA_ARGUMENTS_OFFSET
                            + SECCOMP_DATA_ARGUMENT_SIZE * arguments.len() as u32
                    && (offset - SECCOMP_DATA_ARGUMENTS_OFFSET)
                        .is_multiple_of(SECCOMP_DATA_ARGUMENT_SIZE) =>
            {
                arguments[((offset - SECCOMP_DATA_ARGUMENTS_OFFSET) / SECCOMP_DATA_ARGUMENT_SIZE)
                    as usize] as u32
            }
            _ => panic!("unexpected seccomp_data offset {offset}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    #[cfg(unix)]
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(unix)]
    use std::time::Duration;

    use splash_protocol::{
        CapabilityGrant, PrivatePipeWorkerBootstrap, ResourceSelector, SessionKey,
    };

    use super::*;

    fn manifest(resources: impl IntoIterator<Item = ResourceSelector>) -> CapabilityManifest {
        let mut grant = CapabilityGrant::json("tool.call");
        grant.resources = resources.into_iter().collect();
        CapabilityManifest::new("session-1", vec![grant]).unwrap()
    }

    fn selector(kind: ResourceKind, id: &str) -> ResourceSelector {
        ResourceSelector::new(kind, id).unwrap()
    }

    fn bootstrap(session_id: &str) -> PrivatePipeWorkerBootstrap {
        PrivatePipeWorkerBootstrap::new(
            session_id,
            SessionKey::from_bytes([23; splash_protocol::AUTH_TAG_BYTES]).unwrap(),
        )
        .unwrap()
    }

    fn base_policy(root: &TestDirectory) -> BubblewrapWorkerPolicy {
        let bwrap = root.path().join("bwrap");
        create_executable(&bwrap);
        let runtime = root.path().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        create_executable(&runtime.join("worker"));

        let mut policy = BubblewrapWorkerPolicy::new(bwrap, "/opt/splash/worker").unwrap();
        policy.add_runtime_mount(ReadOnlyMount::new(runtime, "/opt/splash").unwrap());
        policy
    }

    fn resource_limits() -> WorkerResourceLimits {
        let mut limits = WorkerResourceLimits::default();
        limits.set_cpu_seconds(30).unwrap();
        limits.set_address_space_bytes(8 * 1024 * 1024).unwrap();
        limits.set_process_count(4).unwrap();
        limits.set_open_files(16).unwrap();
        limits.set_file_size_bytes(64 * 1024).unwrap();
        limits
    }

    fn resource_limit_runner(root: &TestDirectory) -> ResourceLimitRunner {
        create_executable(&root.path().join("runtime/limit-runner"));
        ResourceLimitRunner::new("/opt/splash/limit-runner", resource_limits()).unwrap()
    }

    fn binding(
        root: &TestDirectory,
        source_name: &str,
        destination: &str,
        access: FileRootAccess,
    ) -> FileRootBinding {
        let source = root.path().join(source_name);
        fs::create_dir_all(&source).unwrap();
        FileRootBinding::new(source, destination, access).unwrap()
    }

    fn argument_strings(plan: &BubblewrapCommand) -> Vec<String> {
        plan.arguments()
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    fn has_arguments(arguments: &[String], expected: &[&str]) -> bool {
        arguments.windows(expected.len()).any(|actual| {
            actual
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
        })
    }

    #[test]
    fn compiles_a_networkless_allowlisted_worker_plan() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root).with_worker_arguments(["--json-lines"]);
        let input = binding(&root, "input", "/workspace/input", FileRootAccess::ReadOnly);
        let output = binding(
            &root,
            "output",
            "/workspace/output",
            FileRootAccess::ReadWrite,
        );
        policy.add_file_root("input", input).unwrap();
        policy.add_file_root("output", output).unwrap();

        let plan = policy
            .compile(&manifest([
                selector(ResourceKind::FileRoot, "input"),
                selector(ResourceKind::FileRoot, "output"),
            ]))
            .unwrap();
        let arguments = argument_strings(&plan);
        let runtime = fs::canonicalize(root.path().join("runtime")).unwrap();
        let input = fs::canonicalize(root.path().join("input")).unwrap();
        let output = fs::canonicalize(root.path().join("output")).unwrap();

        assert!(has_arguments(
            &arguments,
            &["--ro-bind", runtime.to_str().unwrap(), "/opt/splash"]
        ));
        assert!(has_arguments(
            &arguments,
            &["--ro-bind", input.to_str().unwrap(), "/workspace/input"]
        ));
        assert!(has_arguments(
            &arguments,
            &["--bind", output.to_str().unwrap(), "/workspace/output"]
        ));
        assert!(has_arguments(&arguments, &["--unshare-all"]));
        assert!(has_arguments(&arguments, &["--cap-drop", "ALL"]));
        assert!(has_arguments(&arguments, &["--new-session"]));
        assert!(has_arguments(&arguments, &["--clearenv"]));
        assert!(has_arguments(&arguments, &["--chdir", "/"]));
        assert!(!arguments
            .iter()
            .any(|argument| argument == "--unshare-user"));
        assert!(!arguments
            .iter()
            .any(|argument| argument == "--disable-userns"));
        assert!(!arguments.iter().any(|argument| argument == "--share-net"));
        assert!(!has_arguments(&arguments, &["--remount-ro", "/"]));
        assert!(has_arguments(
            &arguments,
            &["--", "/opt/splash/worker", "--json-lines"]
        ));
        assert_eq!(plan.session_id(), "session-1");
        assert!(!arguments.iter().any(|argument| argument == "session-1"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_pinned_mount_roots_render_launch_only_fd_binds() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy.pin_mount_sources();
        policy
            .add_file_root(
                "input",
                binding(&root, "input", "/workspace/input", FileRootAccess::ReadOnly),
            )
            .unwrap();
        policy
            .add_file_root(
                "output",
                binding(
                    &root,
                    "output",
                    "/workspace/output",
                    FileRootAccess::ReadWrite,
                ),
            )
            .unwrap();

        let plan = policy
            .compile(&manifest([
                selector(ResourceKind::FileRoot, "input"),
                selector(ResourceKind::FileRoot, "output"),
            ]))
            .unwrap();
        let arguments = argument_strings(&plan);
        let runtime = fs::canonicalize(root.path().join("runtime"))
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let input = fs::canonicalize(root.path().join("input"))
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let output = fs::canonicalize(root.path().join("output"))
            .unwrap()
            .to_string_lossy()
            .into_owned();

        assert_eq!(
            policy.mount_source_binding(),
            MountSourceBinding::DescriptorPinned
        );
        assert!(has_arguments(
            &arguments,
            &[
                "--ro-bind-fd",
                PINNED_MOUNT_DESCRIPTOR_PLACEHOLDER,
                "/opt/splash",
            ]
        ));
        assert!(has_arguments(
            &arguments,
            &[
                "--ro-bind-fd",
                PINNED_MOUNT_DESCRIPTOR_PLACEHOLDER,
                "/workspace/input",
            ]
        ));
        assert!(has_arguments(
            &arguments,
            &[
                "--bind-fd",
                PINNED_MOUNT_DESCRIPTOR_PLACEHOLDER,
                "/workspace/output",
            ]
        ));
        for source in [runtime, input, output] {
            assert!(
                !arguments.iter().any(|argument| argument == &source),
                "descriptor-pinned source leaked into display arguments: {source}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_pinned_executables_require_pinned_mount_roots() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        assert_eq!(
            policy.executable_source_binding(),
            ExecutableSourceBinding::Path
        );

        policy.pin_executable_sources();
        assert_eq!(
            policy.executable_source_binding(),
            ExecutableSourceBinding::DescriptorPinned
        );
        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::DescriptorPinnedExecutablesRequirePinnedMountSources)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_pinned_executables_overlay_fixed_worker_and_limit_runner() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy.pin_mount_sources();
        policy.pin_executable_sources();
        policy.set_resource_limit_runner(resource_limit_runner(&root));

        let plan = policy.compile(&manifest([])).unwrap();
        let arguments = argument_strings(&plan);

        assert!(plan.bwrap_program.is_descriptor_pinned());
        assert_eq!(plan.executable_overlays.len(), 2);
        assert!(has_arguments(
            &arguments,
            &[
                "--ro-bind-fd",
                PINNED_MOUNT_DESCRIPTOR_PLACEHOLDER,
                "/opt/splash/worker",
            ]
        ));
        assert!(has_arguments(
            &arguments,
            &[
                "--ro-bind-fd",
                PINNED_MOUNT_DESCRIPTOR_PLACEHOLDER,
                "/opt/splash/limit-runner",
            ]
        ));
        let runtime_mount_index = arguments
            .windows(3)
            .position(|window| {
                window.iter().map(String::as_str).eq([
                    "--ro-bind-fd",
                    PINNED_MOUNT_DESCRIPTOR_PLACEHOLDER,
                    "/opt/splash",
                ])
            })
            .unwrap();
        let worker_overlay_index = arguments
            .windows(3)
            .position(|window| {
                window.iter().map(String::as_str).eq([
                    "--ro-bind-fd",
                    PINNED_MOUNT_DESCRIPTOR_PLACEHOLDER,
                    "/opt/splash/worker",
                ])
            })
            .unwrap();
        assert!(runtime_mount_index < worker_overlay_index);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_pinned_host_executable_survives_path_replacement() {
        let root = TestDirectory::new();
        let program = root.path().join("program");
        create_script_executable(&program, "#!/bin/sh\nprintf 'compiled\\n'\n");

        let executable = compile_host_executable(
            "test program",
            &program,
            ExecutableSourceBinding::DescriptorPinned,
        )
        .unwrap();
        let retired = root.path().join("program-retired");
        fs::rename(&program, &retired).unwrap();
        create_script_executable(&program, "#!/bin/sh\nprintf 'replacement\\n'\n");

        let (command_path, descriptor) = executable.prepare_for_execution().unwrap();
        let output = Command::new(command_path).output().unwrap();
        drop(descriptor);

        assert!(output.status.success());
        assert_eq!(output.stdout, b"compiled\n");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn descriptor_pinned_mount_roots_fail_closed_off_linux() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy.pin_mount_sources();

        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::DescriptorPinnedMountsUnsupportedPlatform)
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn descriptor_pinned_executables_fail_closed_off_linux() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy.pin_executable_sources();

        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::DescriptorPinnedExecutablesUnsupportedPlatform)
        ));
    }

    #[test]
    fn further_user_namespace_lockdown_is_opt_in_and_requires_bubblewrap_flags() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        assert_eq!(
            policy.user_namespace_policy(),
            UserNamespacePolicy::BestEffort
        );

        policy.require_no_further_user_namespaces();
        let plan = policy.compile(&manifest([])).unwrap();
        let arguments = argument_strings(&plan);

        assert_eq!(
            policy.user_namespace_policy(),
            UserNamespacePolicy::RequireNoFurtherUserNamespaces
        );
        assert!(has_arguments(
            &arguments,
            &[
                "--unshare-all",
                "--unshare-user",
                "--disable-userns",
                "--clearenv",
            ]
        ));
        assert!(!arguments.iter().any(|argument| argument == "--share-net"));
    }

    #[test]
    fn strict_seccomp_allowlists_are_bounded_deterministic_and_selected_atomically() {
        let allowlist = WorkerSeccompAllowlist::new([91, 7, 28]).unwrap();
        assert_eq!(allowlist.len(), 3);
        assert!(!allowlist.is_empty());
        assert_eq!(allowlist.syscalls().collect::<Vec<_>>(), vec![7, 28, 91]);
        assert_eq!(
            WorkerSeccompAllowlist::new([7, 7]),
            Err(WorkerSeccompAllowlistError::DuplicateSyscall { syscall: 7 })
        );
        assert_eq!(
            WorkerSeccompAllowlist::new([]),
            Err(WorkerSeccompAllowlistError::Empty)
        );
        assert_eq!(
            WorkerSeccompAllowlist::new(0..=MAX_WORKER_SECCOMP_ALLOWLIST_SYSCALLS as u32),
            Err(WorkerSeccompAllowlistError::TooManySyscalls {
                maximum: MAX_WORKER_SECCOMP_ALLOWLIST_SYSCALLS,
            })
        );

        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy.set_seccomp_profile(WorkerSeccompProfile::StrictAllowlist);
        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::MissingSeccompAllowlist)
        ));

        policy.set_seccomp_allowlist(allowlist.clone());
        assert_eq!(
            policy.seccomp_profile(),
            WorkerSeccompProfile::StrictAllowlist
        );
        assert_eq!(policy.seccomp_allowlist(), Some(&allowlist));
        policy.set_seccomp_profile(WorkerSeccompProfile::DenyKnownEscapeSurface);
        assert!(policy.seccomp_allowlist().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_hardening_is_typed_and_rejects_its_documented_escape_surface() {
        use linux_raw_sys::{errno, general, ioctl, ptrace};

        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        assert_eq!(policy.seccomp_profile(), WorkerSeccompProfile::Disabled);

        policy.set_seccomp_profile(WorkerSeccompProfile::DenyKnownEscapeSurface);
        let plan = policy.compile(&manifest([])).unwrap();
        let arguments = argument_strings(&plan);
        let program = plan.seccomp_program.as_ref().unwrap();
        let architecture = u32::from_ne_bytes(program.bytes[12..16].try_into().unwrap());
        let denied_with_eperm = ptrace::SECCOMP_RET_ERRNO | errno::EPERM;
        let denied_with_enosys = ptrace::SECCOMP_RET_ERRNO | errno::ENOSYS;

        assert_eq!(
            plan.seccomp_profile(),
            WorkerSeccompProfile::DenyKnownEscapeSurface
        );
        assert!(!arguments.iter().any(|argument| argument == "--seccomp"));
        assert_eq!(program.bytes.len() % 8, 0);
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_mount, [0; 6],),
            denied_with_eperm
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(
                program,
                architecture,
                general::__NR_personality,
                [0; 6],
            ),
            denied_with_eperm
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_clone, [0; 6],),
            ptrace::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(
                program,
                architecture,
                general::__NR_clone,
                [u64::from(general::CLONE_NEWNET); 6],
            ),
            denied_with_eperm
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_clone3, [0; 6],),
            denied_with_enosys
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(
                program,
                architecture,
                general::__NR_ioctl,
                [0, u64::from(ioctl::TIOCSTI), 0, 0, 0, 0],
            ),
            denied_with_eperm
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_ioctl, [0; 6],),
            ptrace::SECCOMP_RET_ALLOW
        );
        // This synthetic syscall remains below the x32 marker.
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, 0x3fff_ffff, [0; 6]),
            ptrace::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(
                program,
                architecture ^ 1,
                general::__NR_mount,
                [0; 6]
            ),
            ptrace::SECCOMP_RET_KILL_PROCESS
        );

        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            linux_seccomp::evaluate_for_test(
                program,
                architecture,
                general::__NR_getpid | general::__X32_SYSCALL_BIT,
                [0; 6],
            ),
            ptrace::SECCOMP_RET_KILL_PROCESS
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_seccomp_allowlist_kills_unselected_syscalls_and_retains_fixed_guards() {
        use linux_raw_sys::{errno, general, ioctl, ptrace};

        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        let allowlist = WorkerSeccompAllowlist::new([
            general::__NR_read,
            general::__NR_execve,
            general::__NR_clone,
            general::__NR_ioctl,
        ])
        .unwrap();
        policy.set_seccomp_allowlist(allowlist);

        let plan = policy.compile(&manifest([])).unwrap();
        let program = plan.seccomp_program.as_ref().unwrap();
        let architecture = u32::from_ne_bytes(program.bytes[12..16].try_into().unwrap());
        let denied_with_eperm = ptrace::SECCOMP_RET_ERRNO | errno::EPERM;
        let denied_with_enosys = ptrace::SECCOMP_RET_ERRNO | errno::ENOSYS;

        assert_eq!(
            plan.seccomp_profile(),
            WorkerSeccompProfile::StrictAllowlist
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_read, [0; 6]),
            ptrace::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_execve, [0; 6],),
            ptrace::SECCOMP_RET_ALLOW
        );
        // Unconditionally guarded syscalls cannot be listed, and continue to
        // receive their fixed action when a worker attempts them.
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_mount, [0; 6]),
            denied_with_eperm
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_clone, [0; 6]),
            ptrace::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(
                program,
                architecture,
                general::__NR_clone,
                [u64::from(general::CLONE_NEWNET); 6],
            ),
            denied_with_eperm
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_clone3, [0; 6],),
            denied_with_enosys
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, general::__NR_ioctl, [0; 6],),
            ptrace::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(
                program,
                architecture,
                general::__NR_ioctl,
                [0, u64::from(ioctl::TIOCSTI), 0, 0, 0, 0],
            ),
            denied_with_eperm
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture, 0x3fff_ffff, [0; 6],),
            ptrace::SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(
            linux_seccomp::evaluate_for_test(program, architecture ^ 1, general::__NR_read, [0; 6],),
            ptrace::SECCOMP_RET_KILL_PROCESS
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_seccomp_allowlist_requires_execve_and_rejects_unconditional_guards() {
        use linux_raw_sys::general;

        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy.set_seccomp_allowlist(WorkerSeccompAllowlist::new([general::__NR_read]).unwrap());
        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::MissingSeccompExecve)
        ));

        for syscall in [general::__NR_mount, general::__NR_clone3] {
            let mut policy = base_policy(&root);
            policy.set_seccomp_allowlist(
                WorkerSeccompAllowlist::new([general::__NR_execve, syscall]).unwrap(),
            );
            assert!(matches!(
                policy.compile(&manifest([])),
                Err(BubblewrapPolicyError::SeccompAllowlistConflictsWithHardening {
                    syscall: rejected,
                }) if rejected == syscall
            ));
        }

        #[cfg(target_arch = "x86_64")]
        {
            let syscall = general::__NR_read | general::__X32_SYSCALL_BIT;
            let mut policy = base_policy(&root);
            policy.set_seccomp_allowlist(
                WorkerSeccompAllowlist::new([general::__NR_execve, syscall]).unwrap(),
            );
            assert!(matches!(
                policy.compile(&manifest([])),
                Err(BubblewrapPolicyError::SeccompAllowlistConflictsWithHardening {
                    syscall: rejected,
                }) if rejected == syscall
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn strict_seccomp_allowlist_capacity_stays_within_the_linux_c_bpf_limit() {
        use linux_raw_sys::general;

        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        let start = 10_000_u32;
        let allowlist = WorkerSeccompAllowlist::new(
            std::iter::once(general::__NR_execve)
                .chain(start..start + (MAX_WORKER_SECCOMP_ALLOWLIST_SYSCALLS - 1) as u32),
        )
        .unwrap();
        policy.set_seccomp_allowlist(allowlist);

        let plan = policy.compile(&manifest([])).unwrap();
        let program = plan.seccomp_program.as_ref().unwrap();
        assert!(
            program.bytes.len() / 8 <= MAX_LINUX_SECCOMP_FILTER_INSTRUCTIONS,
            "strict seccomp program exceeds the Linux cBPF instruction limit"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_launch_descriptor_is_never_a_standard_descriptor() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy.set_seccomp_profile(WorkerSeccompProfile::DenyKnownEscapeSurface);
        let plan = policy.compile(&manifest([])).unwrap();

        let descriptor = plan
            .seccomp_program
            .as_ref()
            .unwrap()
            .open_for_bubblewrap()
            .unwrap();

        assert!(descriptor.as_raw_fd() >= 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a runner that can configure Bubblewrap's isolated loopback device"]
    fn bubblewrap_attaches_the_host_owned_seccomp_filter_before_worker_exec() {
        use std::io::Read;

        let python = fs::canonicalize("/usr/bin/python3").unwrap();
        let mut policy = BubblewrapWorkerPolicy::new("/usr/bin/bwrap", python)
            .unwrap()
            .with_worker_arguments(["-c", seccomp_test_worker_script()]);
        policy.add_runtime_mount(ReadOnlyMount::new("/usr", "/usr").unwrap());
        add_linux_runtime_library_mounts(&mut policy);
        policy.set_seccomp_profile(WorkerSeccompProfile::DenyKnownEscapeSurface);

        let manifest =
            CapabilityManifest::new("seccomp-integration", vec![CapabilityGrant::json("tool")])
                .unwrap();
        let plan = policy.compile(&manifest).unwrap();
        let (worker, mut standard_error) = plan.spawn_capturing_stderr().unwrap();
        let (mut child, stdin, mut stdout) = worker.into_parts();
        drop(stdin);

        let status = child.wait().unwrap();
        let mut output = String::new();
        stdout.read_to_string(&mut output).unwrap();
        let mut standard_error_output = String::new();
        standard_error
            .read_to_string(&mut standard_error_output)
            .unwrap();

        assert!(
            status.success(),
            "worker failed: {status}; stdout: {output:?}; stderr: {standard_error_output:?}"
        );
        assert_eq!(output, "seccomp-active\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a runner that can configure Bubblewrap's isolated loopback device"]
    fn bubblewrap_watchdog_force_stops_a_real_contained_worker() {
        let sleep = fs::canonicalize("/usr/bin/sleep").unwrap();
        let mut policy = BubblewrapWorkerPolicy::new("/usr/bin/bwrap", sleep)
            .unwrap()
            .with_worker_arguments(["60"]);
        policy.add_runtime_mount(ReadOnlyMount::new("/usr", "/usr").unwrap());
        add_linux_runtime_library_mounts(&mut policy);

        let plan = policy.compile(&manifest([])).unwrap();
        let worker = plan.spawn().unwrap();
        let (lifecycle, stdin, stdout) = worker.into_lifecycle_parts();
        drop(stdin);
        drop(stdout);
        let mut watchdog = lifecycle.into_watchdog().unwrap();

        let call = watchdog.begin_call(Duration::from_millis(100)).unwrap();
        std::thread::sleep(Duration::from_millis(250));
        assert!(matches!(
            watchdog.finish_call(call).unwrap(),
            BubblewrapWorkerInvocationOutcome::DeadlineElapsed(termination)
                if termination.was_killed()
        ));
        assert!(watchdog.close().unwrap().was_killed());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a runner that can configure Bubblewrap's isolated loopback device"]
    fn descriptor_pinned_file_root_survives_host_path_replacement_after_compile() {
        use std::io::Read;

        let root = TestDirectory::new();
        let source = root.path().join("input");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("marker"), "compiled-root\n").unwrap();
        let secret = root.path().join("secret");
        fs::create_dir(&secret).unwrap();
        fs::write(secret.join("marker"), "host-only\n").unwrap();

        let python = fs::canonicalize("/usr/bin/python3").unwrap();
        let mut policy = BubblewrapWorkerPolicy::new("/usr/bin/bwrap", python)
            .unwrap()
            .with_worker_arguments([
                "-B",
                "-c",
                r#"
import os
from pathlib import Path

for raw_descriptor in os.listdir('/proc/self/fd'):
    descriptor = int(raw_descriptor)
    if descriptor <= 2:
        continue
    try:
        leaked = os.open('../secret/marker', os.O_RDONLY, dir_fd=descriptor)
    except OSError:
        continue
    else:
        os.close(leaked)
        raise RuntimeError('Bubblewrap retained a host mount descriptor')

print(Path('/workspace/input/marker').read_text(), end='')
"#,
            ]);
        policy.add_runtime_mount(ReadOnlyMount::new("/usr", "/usr").unwrap());
        add_linux_runtime_library_mounts(&mut policy);
        policy
            .add_file_root(
                "input",
                FileRootBinding::new(&source, "/workspace/input", FileRootAccess::ReadOnly)
                    .unwrap(),
            )
            .unwrap();
        policy.pin_mount_sources();

        let plan = policy
            .compile(&manifest([selector(ResourceKind::FileRoot, "input")]))
            .unwrap();

        let retired = root.path().join("input-retired");
        fs::rename(&source, &retired).unwrap();
        fs::create_dir(&source).unwrap();
        fs::write(source.join("marker"), "replacement-root\n").unwrap();

        let (worker, mut standard_error) = plan.spawn_capturing_stderr().unwrap();
        let (mut child, stdin, mut stdout) = worker.into_parts();
        drop(stdin);

        let status = child.wait().unwrap();
        let mut output = String::new();
        stdout.read_to_string(&mut output).unwrap();
        let mut standard_error_output = String::new();
        standard_error
            .read_to_string(&mut standard_error_output)
            .unwrap();

        assert!(
            status.success(),
            "worker failed: {status}; stdout: {output:?}; stderr: {standard_error_output:?}"
        );
        assert_eq!(output, "compiled-root\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a runner that can configure Bubblewrap's isolated loopback device"]
    fn bubblewrap_enforces_bounded_ephemeral_storage_and_readonly_root() {
        use std::io::Read;

        let python = fs::canonicalize("/usr/bin/python3").unwrap();
        let script = r#"
import errno

with open("/proc/self/status", encoding="utf-8") as status_file:
    status = status_file.read().splitlines()
capability_fields = {
    key: int(value, 16)
    for key, value in (line.split(":", 1) for line in status)
    if key in {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}
}
if len(capability_fields) != 5 or any(capability_fields.values()):
    raise RuntimeError(f"worker retained Linux capabilities: {capability_fields}")

try:
    with open("/outside", "wb") as outside:
        outside.write(b"unexpected")
except OSError as error:
    if error.errno != errno.EROFS:
        raise
else:
    raise RuntimeError("namespace root remained writable")

try:
    with open("/scratch/payload", "wb", buffering=0) as payload:
        while True:
            payload.write(b"x" * 4096)
except OSError as error:
    if error.errno != errno.ENOSPC:
        raise
else:
    raise RuntimeError("bounded scratch root did not fill")

print("bounded-storage-active")
"#;
        let mut policy = BubblewrapWorkerPolicy::new("/usr/bin/bwrap", python)
            .unwrap()
            .with_worker_arguments(["-B", "-c", script]);
        policy.add_runtime_mount(ReadOnlyMount::new("/usr", "/usr").unwrap());
        add_linux_runtime_library_mounts(&mut policy);
        policy
            .add_ephemeral_file_root(
                "scratch",
                EphemeralFileRoot::new("/scratch", 64 * 1024).unwrap(),
            )
            .unwrap();
        policy
            .require_no_further_user_namespaces()
            .require_bounded_file_root_writes();

        let plan = policy
            .compile(&manifest([selector(ResourceKind::FileRoot, "scratch")]))
            .unwrap();
        let (worker, mut standard_error) = plan.spawn_capturing_stderr().unwrap();
        let (mut child, stdin, mut stdout) = worker.into_parts();
        drop(stdin);

        let status = child.wait().unwrap();
        let mut output = String::new();
        stdout.read_to_string(&mut output).unwrap();
        let mut standard_error_output = String::new();
        standard_error
            .read_to_string(&mut standard_error_output)
            .unwrap();

        assert!(
            status.success(),
            "worker failed: {status}; stdout: {output:?}; stderr: {standard_error_output:?}"
        );
        assert_eq!(output, "bounded-storage-active\n");
    }

    #[cfg(target_os = "linux")]
    fn add_linux_runtime_library_mounts(policy: &mut BubblewrapWorkerPolicy) {
        for path in ["/lib", "/lib64"] {
            if Path::new(path).exists() {
                policy.add_runtime_mount(ReadOnlyMount::new(path, path).unwrap());
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn seccomp_test_worker_script() -> &'static str {
        r#"
import ctypes
import errno
import os
import sys

libc = ctypes.CDLL(None, use_errno=True)
if libc.unshare(0) != -1 or ctypes.get_errno() != errno.EPERM:
    print(f"unshare was not denied with EPERM: {ctypes.get_errno()}")
    sys.exit(67)

with open("/proc/self/status", encoding="utf-8") as status_file:
    status = status_file.read()
if "Seccomp:\t2" not in status:
    print("seccomp filter is not active")
    sys.exit(68)
if "NoNewPrivs:\t1" not in status:
    print("Bubblewrap did not set no_new_privs")
    sys.exit(69)

# Bubblewrap consumes and closes the launch-only Unix socket that carried the
# cBPF bytes. Any remaining socket descriptor would be unexpected worker
# authority.
for descriptor in os.listdir("/proc/self/fd"):
    try:
        target = os.readlink(f"/proc/self/fd/{descriptor}")
    except FileNotFoundError:
        continue
    if target.startswith("socket:"):
        print(f"unexpected socket descriptor: {descriptor}")
        sys.exit(70)

print("seccomp-active")
"#
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn selected_seccomp_profiles_fail_closed_off_linux() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy.set_seccomp_profile(WorkerSeccompProfile::DenyKnownEscapeSurface);

        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::SeccompUnsupportedPlatform)
        ));

        policy.set_seccomp_allowlist(WorkerSeccompAllowlist::new([1]).unwrap());
        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::SeccompUnsupportedPlatform)
        ));
    }

    #[test]
    fn resource_limit_runner_is_typed_and_precedes_the_fixed_worker() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root).with_worker_arguments(["--json-lines", "--fixed-mode"]);
        policy.set_resource_limit_runner(resource_limit_runner(&root));

        let plan = policy.compile(&manifest([])).unwrap();
        let arguments = argument_strings(&plan);

        assert!(has_arguments(
            &arguments,
            &[
                "--",
                "/opt/splash/limit-runner",
                "--cpu-seconds",
                "30",
                "--address-space-bytes",
                "8388608",
                "--process-count",
                "4",
                "--open-files",
                "16",
                "--file-size-bytes",
                "65536",
                "--",
                "/opt/splash/worker",
                "--json-lines",
                "--fixed-mode",
            ]
        ));
        assert!(!arguments.iter().any(|argument| argument == "--share-net"));
    }

    #[test]
    fn resource_limit_configuration_rejects_empty_or_unbounded_values() {
        assert!(matches!(
            ResourceLimitRunner::new("/opt/splash/limit-runner", WorkerResourceLimits::default()),
            Err(BubblewrapPolicyError::EmptyResourceLimits)
        ));

        let mut limits = WorkerResourceLimits::default();
        assert!(matches!(
            limits.set_cpu_seconds(0),
            Err(WorkerResourceLimitError::InvalidMaximum {
                limit: WorkerResourceLimit::CpuSeconds,
                maximum: 0,
            })
        ));
        assert!(matches!(
            limits.set_open_files(u64::MAX),
            Err(WorkerResourceLimitError::InvalidMaximum {
                limit: WorkerResourceLimit::OpenFiles,
                maximum,
            }) if maximum == u64::MAX
        ));
    }

    #[test]
    fn resource_limit_runner_must_be_distinct_and_readonly_mounted() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy.set_resource_limit_runner(
            ResourceLimitRunner::new("/opt/other/limit-runner", resource_limits()).unwrap(),
        );
        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::ResourceLimitRunnerNotMounted { program })
                if program == Path::new("/opt/other/limit-runner")
        ));

        let mut policy = base_policy(&root);
        policy.set_resource_limit_runner(
            ResourceLimitRunner::new("/opt/splash/worker", resource_limits()).unwrap(),
        );
        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::ResourceLimitRunnerMatchesWorker { program })
                if program == Path::new("/opt/splash/worker")
        ));

        let mut policy = base_policy(&root);
        File::create(root.path().join("runtime/not-executable")).unwrap();
        policy.set_resource_limit_runner(
            ResourceLimitRunner::new("/opt/splash/not-executable", resource_limits()).unwrap(),
        );
        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::ResourceLimitRunnerNotExecutable { program })
                if program == Path::new("/opt/splash/not-executable")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn resource_limit_runner_must_not_be_a_symlink() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        symlink("worker", root.path().join("runtime/limit-runner")).unwrap();
        policy.set_resource_limit_runner(
            ResourceLimitRunner::new("/opt/splash/limit-runner", resource_limits()).unwrap(),
        );

        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::ResourceLimitRunnerNotExecutable { program })
                if program == Path::new("/opt/splash/limit-runner")
        ));
    }

    #[test]
    fn mounts_only_file_roots_in_the_active_manifest() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy
            .add_file_root(
                "granted",
                binding(
                    &root,
                    "granted-source",
                    "/workspace/granted",
                    FileRootAccess::ReadOnly,
                ),
            )
            .unwrap();
        policy
            .add_file_root(
                "unused",
                binding(
                    &root,
                    "unused-source",
                    "/workspace/unused",
                    FileRootAccess::ReadOnly,
                ),
            )
            .unwrap();

        let plan = policy
            .compile(&manifest([selector(ResourceKind::FileRoot, "granted")]))
            .unwrap();
        let arguments = argument_strings(&plan);
        let unused = fs::canonicalize(root.path().join("unused-source")).unwrap();

        assert!(!arguments
            .iter()
            .any(|argument| argument == unused.to_str().unwrap()));
        assert!(!arguments
            .iter()
            .any(|argument| argument == "/workspace/unused"));
    }

    #[test]
    fn mounts_only_selected_ephemeral_file_roots_with_contiguous_size_policy() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        let scratch = EphemeralFileRoot::new("/workspace/scratch", 64 * 1024).unwrap();
        assert_eq!(scratch.destination(), Path::new("/workspace/scratch"));
        assert_eq!(scratch.maximum_bytes(), 64 * 1024);
        policy.add_ephemeral_file_root("scratch", scratch).unwrap();

        let inactive = policy.compile(&manifest([])).unwrap();
        let inactive_arguments = argument_strings(&inactive);
        assert!(!inactive_arguments
            .iter()
            .any(|argument| argument == "/workspace/scratch"));

        let active = policy
            .compile(&manifest([selector(ResourceKind::FileRoot, "scratch")]))
            .unwrap();
        let active_arguments = argument_strings(&active);
        assert!(has_arguments(
            &active_arguments,
            &["--size", "65536", "--tmpfs", "/workspace/scratch"]
        ));
        assert!(!active_arguments.iter().any(|argument| argument == "--bind"));
    }

    #[test]
    fn host_and_ephemeral_file_roots_share_one_selector_namespace() {
        let root = TestDirectory::new();
        let mut host_first = base_policy(&root);
        host_first
            .add_file_root(
                "scratch",
                binding(
                    &root,
                    "host-first",
                    "/workspace/host-first",
                    FileRootAccess::ReadOnly,
                ),
            )
            .unwrap();
        assert!(matches!(
            host_first.add_ephemeral_file_root(
                "scratch",
                EphemeralFileRoot::new("/workspace/scratch", 1024).unwrap(),
            ),
            Err(BubblewrapPolicyError::DuplicateFileRoot { id }) if id == "scratch"
        ));

        let mut ephemeral_first = base_policy(&root);
        ephemeral_first
            .add_ephemeral_file_root(
                "scratch",
                EphemeralFileRoot::new("/workspace/scratch", 1024).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            ephemeral_first.add_file_root(
                "scratch",
                binding(
                    &root,
                    "ephemeral-first",
                    "/workspace/ephemeral-first",
                    FileRootAccess::ReadOnly,
                ),
            ),
            Err(BubblewrapPolicyError::DuplicateFileRoot { id }) if id == "scratch"
        ));
    }

    #[test]
    fn rejects_invalid_ephemeral_file_root_configuration() {
        assert!(matches!(
            EphemeralFileRoot::new("scratch", 1024),
            Err(BubblewrapPolicyError::InvalidPath { .. })
        ));
        assert!(matches!(
            EphemeralFileRoot::new("/scratch", 0),
            Err(BubblewrapPolicyError::InvalidEphemeralFileRootSize { maximum_bytes: 0 })
        ));
        assert!(matches!(
            EphemeralFileRoot::new("/scratch", usize::MAX),
            Err(BubblewrapPolicyError::InvalidEphemeralFileRootSize { maximum_bytes })
                if maximum_bytes == usize::MAX
        ));
    }

    #[test]
    fn ephemeral_file_roots_share_all_mount_overlap_checks() {
        let root = TestDirectory::new();

        for destination in ["/proc/scratch", "/dev/scratch", "/opt/splash/scratch"] {
            let mut policy = base_policy(&root);
            policy
                .add_ephemeral_file_root(
                    "scratch",
                    EphemeralFileRoot::new(destination, 1024).unwrap(),
                )
                .unwrap();
            assert!(matches!(
                policy.compile(&manifest([selector(ResourceKind::FileRoot, "scratch")])),
                Err(BubblewrapPolicyError::ReservedMountDestination { .. })
                    | Err(BubblewrapPolicyError::OverlappingMountDestinations { .. })
            ));
        }

        let mut private_tmp = base_policy(&root);
        private_tmp.enable_private_tmpfs();
        private_tmp
            .add_ephemeral_file_root(
                "scratch",
                EphemeralFileRoot::new("/tmp/scratch", 1024).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            private_tmp.compile(&manifest([selector(ResourceKind::FileRoot, "scratch")])),
            Err(BubblewrapPolicyError::ReservedMountDestination { .. })
        ));

        let mut host_overlap = base_policy(&root);
        host_overlap
            .add_file_root(
                "workspace",
                binding(&root, "workspace", "/workspace", FileRootAccess::ReadOnly),
            )
            .unwrap();
        host_overlap
            .add_ephemeral_file_root(
                "scratch",
                EphemeralFileRoot::new("/workspace/scratch", 1024).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            host_overlap.compile(&manifest([
                selector(ResourceKind::FileRoot, "workspace"),
                selector(ResourceKind::FileRoot, "scratch"),
            ])),
            Err(BubblewrapPolicyError::OverlappingMountDestinations { .. })
        ));
    }

    #[test]
    fn bounded_file_root_mode_rejects_unbounded_active_writes() {
        let root = TestDirectory::new();
        let mut missing_lockdown = base_policy(&root);
        missing_lockdown.require_bounded_file_root_writes();
        assert!(matches!(
            missing_lockdown.compile(&manifest([])),
            Err(BubblewrapPolicyError::BoundedFileRootWritesRequireUserNamespaceLockdown)
        ));

        let mut policy = base_policy(&root);
        assert!(!policy.bounded_file_root_writes_required());
        policy
            .add_file_root(
                "output",
                binding(
                    &root,
                    "output",
                    "/workspace/output",
                    FileRootAccess::ReadWrite,
                ),
            )
            .unwrap();
        policy.require_no_further_user_namespaces();
        policy.require_bounded_file_root_writes();
        assert!(policy.bounded_file_root_writes_required());

        assert!(policy.compile(&manifest([])).is_ok());
        assert!(matches!(
            policy.compile(&manifest([selector(ResourceKind::FileRoot, "output")])),
            Err(BubblewrapPolicyError::UnboundedFileRootWriteForbidden { id })
                if id == "output"
        ));

        let mut private_tmp = base_policy(&root);
        private_tmp
            .enable_private_tmpfs()
            .require_no_further_user_namespaces()
            .require_bounded_file_root_writes();
        assert!(matches!(
            private_tmp.compile(&manifest([])),
            Err(BubblewrapPolicyError::UnboundedPrivateTmpfsForbidden)
        ));
    }

    #[test]
    fn bounded_file_root_mode_accepts_read_only_and_bounded_mounts() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy
            .add_file_root(
                "input",
                binding(&root, "input", "/workspace/input", FileRootAccess::ReadOnly),
            )
            .unwrap();
        policy
            .add_ephemeral_file_root(
                "scratch",
                EphemeralFileRoot::new("/workspace/scratch", 64 * 1024).unwrap(),
            )
            .unwrap();
        policy
            .enable_private_tmpfs_with_maximum_bytes(32 * 1024)
            .unwrap()
            .require_no_further_user_namespaces()
            .require_bounded_file_root_writes();

        let plan = policy
            .compile(&manifest([
                selector(ResourceKind::FileRoot, "input"),
                selector(ResourceKind::FileRoot, "scratch"),
            ]))
            .unwrap();
        let arguments = argument_strings(&plan);
        assert!(has_arguments(
            &arguments,
            &["--size", "32768", "--tmpfs", "/tmp"]
        ));
        assert!(has_arguments(
            &arguments,
            &["--size", "65536", "--tmpfs", "/workspace/scratch"]
        ));
        assert!(has_arguments(&arguments, &["--remount-ro", "/proc"]));
        assert!(has_arguments(&arguments, &["--remount-ro", "/dev"]));
        assert!(has_arguments(&arguments, &["--remount-ro", "/"]));
        let scratch_mount = arguments
            .windows(4)
            .position(|window| {
                window.iter().map(String::as_str).eq([
                    "--size",
                    "65536",
                    "--tmpfs",
                    "/workspace/scratch",
                ])
            })
            .unwrap();
        let root_lockdown = arguments
            .windows(2)
            .position(|window| window.iter().map(String::as_str).eq(["--remount-ro", "/"]))
            .unwrap();
        assert!(scratch_mount < root_lockdown);
    }

    #[test]
    fn ephemeral_file_root_cannot_supply_the_worker_program() {
        let root = TestDirectory::new();
        let bwrap = root.path().join("bwrap");
        create_executable(&bwrap);
        let mut policy = BubblewrapWorkerPolicy::new(bwrap, "/opt/splash/worker").unwrap();
        policy
            .add_ephemeral_file_root(
                "runtime",
                EphemeralFileRoot::new("/opt/splash", 1024).unwrap(),
            )
            .unwrap();

        assert!(matches!(
            policy.compile(&manifest([selector(ResourceKind::FileRoot, "runtime")])),
            Err(BubblewrapPolicyError::WorkerProgramNotMounted { program })
                if program == Path::new("/opt/splash/worker")
        ));
    }

    #[test]
    fn rejects_resource_kinds_without_an_enforcement_mechanism() {
        let root = TestDirectory::new();

        for kind in [
            ResourceKind::Executable,
            ResourceKind::NetworkOrigin,
            ResourceKind::Secret,
        ] {
            let policy = base_policy(&root);
            assert!(matches!(
                policy.compile(&manifest([selector(kind, "opaque")])) ,
                Err(BubblewrapPolicyError::UnsupportedResource { resource }) if resource.kind == kind
            ));
        }
    }

    #[test]
    fn rejects_missing_file_root_bindings() {
        let root = TestDirectory::new();
        let policy = base_policy(&root);

        assert!(matches!(
            policy.compile(&manifest([selector(ResourceKind::FileRoot, "missing")])),
            Err(BubblewrapPolicyError::MissingFileRoot { id }) if id == "missing"
        ));
    }

    #[test]
    fn rejects_overlapping_mount_destinations() {
        let root = TestDirectory::new();
        let mut policy = base_policy(&root);
        policy
            .add_file_root(
                "input",
                binding(
                    &root,
                    "input",
                    "/opt/splash/input",
                    FileRootAccess::ReadOnly,
                ),
            )
            .unwrap();

        assert!(matches!(
            policy.compile(&manifest([selector(ResourceKind::FileRoot, "input")])),
            Err(BubblewrapPolicyError::OverlappingMountDestinations { .. })
        ));
    }

    #[test]
    fn requires_the_worker_program_in_a_readonly_runtime_mount() {
        let root = TestDirectory::new();
        let bwrap = root.path().join("bwrap");
        create_executable(&bwrap);
        let policy = BubblewrapWorkerPolicy::new(bwrap, "/opt/splash/worker").unwrap();

        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::WorkerProgramNotMounted { program })
                if program == Path::new("/opt/splash/worker")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_non_executable_worker_program() {
        let root = TestDirectory::new();
        let bwrap = root.path().join("bwrap");
        create_executable(&bwrap);
        let runtime = root.path().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        File::create(runtime.join("worker")).unwrap();
        let mut policy = BubblewrapWorkerPolicy::new(bwrap, "/opt/splash/worker").unwrap();
        policy.add_runtime_mount(ReadOnlyMount::new(runtime, "/opt/splash").unwrap());

        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::WorkerProgramNotExecutable { program })
                if program == Path::new("/opt/splash/worker")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_non_executable_bubblewrap_program() {
        let root = TestDirectory::new();
        let bwrap = root.path().join("bwrap");
        File::create(&bwrap).unwrap();
        let runtime = root.path().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        create_executable(&runtime.join("worker"));
        let mut policy = BubblewrapWorkerPolicy::new(bwrap, "/opt/splash/worker").unwrap();
        policy.add_runtime_mount(ReadOnlyMount::new(runtime, "/opt/splash").unwrap());

        assert!(matches!(
            policy.compile(&manifest([])),
            Err(BubblewrapPolicyError::SourceNotExecutable { field, .. })
                if field == "Bubblewrap program"
        ));
    }

    #[test]
    fn private_tmpfs_is_explicit_and_can_be_bounded() {
        let root = TestDirectory::new();
        let policy = base_policy(&root);
        let plan = policy.compile(&manifest([])).unwrap();
        let arguments = argument_strings(&plan);
        assert!(!has_arguments(&arguments, &["--tmpfs", "/tmp"]));

        let mut policy = base_policy(&root);
        policy.enable_private_tmpfs();
        let plan = policy.compile(&manifest([])).unwrap();
        let arguments = argument_strings(&plan);
        assert!(has_arguments(&arguments, &["--tmpfs", "/tmp"]));
        assert!(!arguments.iter().any(|argument| argument == "--size"));

        let mut policy = base_policy(&root);
        policy
            .enable_private_tmpfs_with_maximum_bytes(64 * 1024)
            .unwrap();
        let plan = policy.compile(&manifest([])).unwrap();
        let arguments = argument_strings(&plan);
        assert!(has_arguments(
            &arguments,
            &["--size", "65536", "--tmpfs", "/tmp"]
        ));

        let mut policy = base_policy(&root);
        assert!(matches!(
            policy.enable_private_tmpfs_with_maximum_bytes(0),
            Err(BubblewrapPolicyError::InvalidPrivateTmpfsSize { maximum_bytes: 0 })
        ));
        assert!(matches!(
            policy.enable_private_tmpfs_with_maximum_bytes(usize::MAX),
            Err(BubblewrapPolicyError::InvalidPrivateTmpfsSize { maximum_bytes })
                if maximum_bytes == usize::MAX
        ));
    }

    #[test]
    fn rejects_root_mount_sources_at_configuration_time() {
        assert!(matches!(
            ReadOnlyMount::new("/", "/runtime"),
            Err(BubblewrapPolicyError::InvalidPath { .. })
        ));
        assert!(matches!(
            FileRootBinding::new("/source", "/", FileRootAccess::ReadOnly),
            Err(BubblewrapPolicyError::InvalidPath { .. })
        ));
    }

    #[test]
    fn rejects_a_bootstrap_for_a_different_compiled_session_before_spawning() {
        let root = TestDirectory::new();
        let plan = base_policy(&root).compile(&manifest([])).unwrap();
        let error = plan
            .spawn_with_bootstrap(&bootstrap("session-2"))
            .unwrap_err();

        assert!(matches!(
            error,
            BubblewrapBootstrapError::SessionMismatch { expected, actual }
                if expected == "session-1" && actual == "session-2"
        ));
    }

    #[test]
    fn compiled_command_retains_the_exact_manifest_binding() {
        let root = TestDirectory::new();
        let expected = manifest([selector(ResourceKind::FileRoot, "workspace")]);
        let mut policy = base_policy(&root);
        policy
            .add_file_root(
                "workspace",
                binding(&root, "workspace", "/workspace", FileRootAccess::ReadOnly),
            )
            .unwrap();

        let command = policy.compile(&expected).unwrap();

        assert_eq!(command.manifest(), &expected);
        assert_eq!(command.session_id(), expected.session_id);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn refuses_to_spawn_off_linux() {
        let root = TestDirectory::new();
        let plan = base_policy(&root).compile(&manifest([])).unwrap();
        assert!(matches!(
            plan.spawn(),
            Err(BubblewrapSpawnError::UnsupportedPlatform)
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn refuses_cgroup_spawn_off_linux() {
        let root = TestDirectory::new();
        let plan = base_policy(&root).compile(&manifest([])).unwrap();
        let mut limits = crate::cgroup_v2::CgroupV2Limits::default();
        limits.set_pids_max(8).unwrap();
        let policy =
            crate::cgroup_v2::CgroupV2Policy::new(root.path(), root.path().join("runner"), limits)
                .unwrap();

        assert!(matches!(
            plan.spawn_in_cgroup(&policy),
            Err(BubblewrapCgroupSpawnError::Prepare(
                CgroupV2PrepareError::UnsupportedPlatform
            ))
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn refuses_to_bootstrap_an_uncontained_worker_off_linux() {
        let root = TestDirectory::new();
        let plan = base_policy(&root).compile(&manifest([])).unwrap();
        assert!(matches!(
            plan.spawn_with_bootstrap(&bootstrap("session-1")),
            Err(BubblewrapBootstrapError::Spawn(
                BubblewrapSpawnError::UnsupportedPlatform
            ))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn force_termination_kills_and_reaps_a_running_worker() {
        let (mut lifecycle, stdin, stdout) = test_worker("exec sleep 60").into_lifecycle_parts();
        drop(stdin);
        drop(stdout);
        let outcome = lifecycle.terminate().unwrap();

        assert!(outcome.was_killed());
        assert!(!outcome.exit_status().success());
        assert!(lifecycle.child_mut().try_wait().unwrap().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn force_termination_reports_an_already_exited_worker() {
        let mut worker = test_worker("exit 0");
        let expected_status = worker.child_mut().wait().unwrap();

        let outcome = worker.terminate().unwrap();
        assert!(!outcome.was_killed());
        assert_eq!(outcome.exit_status(), &expected_status);
    }

    #[cfg(unix)]
    #[test]
    fn consuming_worker_lifecycle_yields_a_retryable_reaping_proof() {
        let proof = test_worker("exec sleep 60").into_reaped().unwrap();

        assert_eq!(proof.session_id(), "test-session");
        assert!(proof.termination().was_killed());
        assert_eq!(proof.clone(), proof);
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_disarms_a_completed_call_and_reaps_on_close() {
        let (lifecycle, stdin, stdout) = test_worker("exec sleep 60").into_lifecycle_parts();
        drop(stdin);
        drop(stdout);
        let mut watchdog = lifecycle.into_watchdog().unwrap();

        let call = watchdog.begin_call(Duration::from_secs(1)).unwrap();
        assert_eq!(
            watchdog.finish_call(call).unwrap(),
            BubblewrapWorkerInvocationOutcome::Completed
        );

        assert!(watchdog.close().unwrap().was_killed());
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_close_can_yield_a_session_bound_reaping_proof() {
        let (lifecycle, stdin, stdout) = test_worker("exec sleep 60").into_lifecycle_parts();
        drop(stdin);
        drop(stdout);
        let watchdog = lifecycle.into_watchdog().unwrap();

        let proof = watchdog.close_reaped().unwrap();

        assert_eq!(proof.session_id(), "test-session");
        assert!(proof.termination().was_killed());
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_deadline_force_stops_and_marks_the_call_indeterminate() {
        let (lifecycle, stdin, stdout) = test_worker("exec sleep 60").into_lifecycle_parts();
        drop(stdin);
        drop(stdout);
        let mut watchdog = lifecycle.into_watchdog().unwrap();

        let call = watchdog.begin_call(Duration::from_millis(10)).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let outcome = watchdog.finish_call(call).unwrap();
        assert!(matches!(
            outcome,
            BubblewrapWorkerInvocationOutcome::DeadlineElapsed(termination)
                if termination.was_killed()
        ));

        assert!(watchdog.close().unwrap().was_killed());
    }

    #[cfg(unix)]
    #[test]
    fn session_deadline_force_stops_an_idle_worker() {
        let deadline = BubblewrapWorkerSessionDeadline::new(Duration::from_millis(25)).unwrap();
        let (mut watchdog, stdin, stdout) = test_worker("exec sleep 60")
            .into_session_watchdog_parts(deadline)
            .unwrap();
        drop(stdin);
        drop(stdout);

        std::thread::sleep(Duration::from_millis(100));
        assert!(matches!(
            watchdog.begin_call(Duration::from_secs(1)),
            Err(BubblewrapWorkerWatchdogError::SessionDeadlineElapsed(termination))
                if termination.was_killed()
        ));
        assert!(watchdog.close().unwrap().was_killed());
    }

    #[cfg(unix)]
    #[test]
    fn session_deadline_marks_an_active_call_indeterminate() {
        let deadline = BubblewrapWorkerSessionDeadline::new(Duration::from_millis(25)).unwrap();
        let (mut watchdog, stdin, stdout) = test_worker("exec sleep 60")
            .into_session_watchdog_parts(deadline)
            .unwrap();
        drop(stdin);
        drop(stdout);

        let call = watchdog.begin_call(Duration::from_secs(1)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(matches!(
            watchdog.finish_call(call).unwrap(),
            BubblewrapWorkerInvocationOutcome::SessionDeadlineElapsed(termination)
                if termination.was_killed()
        ));
        assert!(watchdog.close().unwrap().was_killed());
    }

    #[cfg(unix)]
    #[test]
    fn invocation_deadline_wins_when_it_precedes_the_session_deadline() {
        let session_deadline =
            BubblewrapWorkerSessionDeadline::new(Duration::from_secs(1)).unwrap();
        let (mut watchdog, stdin, stdout) = test_worker("exec sleep 60")
            .into_session_watchdog_parts(session_deadline)
            .unwrap();
        drop(stdin);
        drop(stdout);

        let call = watchdog.begin_call(Duration::from_millis(25)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(matches!(
            watchdog.finish_call(call).unwrap(),
            BubblewrapWorkerInvocationOutcome::DeadlineElapsed(termination)
                if termination.was_killed()
        ));
        assert!(watchdog.close().unwrap().was_killed());
    }

    #[cfg(unix)]
    #[test]
    fn session_deadline_is_measured_from_spawn_not_watchdog_handoff() {
        let worker = test_worker("exec sleep 60");
        std::thread::sleep(Duration::from_millis(100));
        let deadline = BubblewrapWorkerSessionDeadline::new(Duration::from_millis(25)).unwrap();
        let (mut watchdog, stdin, stdout) = worker.into_session_watchdog_parts(deadline).unwrap();
        drop(stdin);
        drop(stdout);

        assert!(matches!(
            watchdog.begin_call(Duration::from_secs(1)),
            Err(BubblewrapWorkerWatchdogError::SessionDeadlineElapsed(termination))
                if termination.was_killed()
        ));
        assert!(watchdog.close().unwrap().was_killed());
    }

    #[test]
    fn session_deadline_rejects_zero_duration() {
        assert_eq!(
            BubblewrapWorkerSessionDeadline::new(Duration::ZERO),
            Err(BubblewrapWorkerSessionDeadlineError::Zero)
        );
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_control_force_stops_an_active_call() {
        let (lifecycle, stdin, stdout) = test_worker("exec sleep 60").into_lifecycle_parts();
        drop(stdin);
        drop(stdout);
        let mut watchdog = lifecycle.into_watchdog().unwrap();
        let control = watchdog.control();

        let call = watchdog.begin_call(Duration::from_secs(1)).unwrap();
        let termination = control.terminate().unwrap();
        assert!(termination.was_killed());
        assert_eq!(
            watchdog.finish_call(call).unwrap(),
            BubblewrapWorkerInvocationOutcome::Terminated(termination.clone())
        );
        assert_eq!(watchdog.close().unwrap(), termination);
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_rejects_zero_deadlines_without_leaking_the_worker() {
        let (lifecycle, stdin, stdout) = test_worker("exec sleep 60").into_lifecycle_parts();
        drop(stdin);
        drop(stdout);
        let mut watchdog = lifecycle.into_watchdog().unwrap();

        assert!(matches!(
            watchdog.begin_call(Duration::ZERO),
            Err(BubblewrapWorkerWatchdogError::InvalidDeadline)
        ));
        assert!(watchdog.close().unwrap().was_killed());
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "splash-sandbox-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn create_executable(path: &Path) {
        File::create(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    fn create_script_executable(path: &Path, source: &str) {
        fs::write(path, source).unwrap();
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    fn test_worker(command: &str) -> SpawnedBubblewrapWorker {
        let mut child = Command::new("sh")
            .args(["-c", command])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        SpawnedBubblewrapWorker {
            child,
            stdin,
            stdout,
            cgroup: None,
            started_at: Instant::now(),
            session_id: "test-session".to_owned(),
        }
    }
}
