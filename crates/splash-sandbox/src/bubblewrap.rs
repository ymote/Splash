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
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout};

#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

use splash_protocol::{CapabilityManifest, ProtocolError, ResourceKind, ResourceSelector};

/// Access mode for a host-selected file-root binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRootAccess {
    ReadOnly,
    ReadWrite,
}

/// One trusted host path mounted read-only into a worker runtime.
///
/// Runtime mounts provide the fixed worker executable and the libraries it
/// needs. They are separate from capability-selected file roots so the worker
/// program can never be sourced from a writable grant. They must still be
/// minimal: without a seccomp policy, a compromised worker can execute or read
/// any file exposed by a runtime mount.
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

/// Trusted configuration for one statically selected Bubblewrap worker.
///
/// This configuration is intentionally constructed by host Rust code. It is
/// not serializable configuration for generated Splash source. All executable
/// and host paths must be absolute. `compile` canonicalizes source paths and
/// requires their contents to exist, but a host must still keep its policy
/// paths immutable between compilation and process launch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BubblewrapWorkerPolicy {
    bwrap_program: PathBuf,
    worker_program: PathBuf,
    worker_arguments: Vec<OsString>,
    runtime_mounts: Vec<ReadOnlyMount>,
    file_roots: BTreeMap<String, FileRootBinding>,
    private_tmpfs: bool,
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
            private_tmpfs: false,
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

    /// Registers one opaque `file_root` selector.
    ///
    /// Bindings absent from the active manifest are not mounted. Duplicate IDs
    /// are rejected so a policy cannot accidentally replace a prior binding.
    pub fn add_file_root(
        &mut self,
        id: impl Into<String>,
        binding: FileRootBinding,
    ) -> Result<&mut Self, BubblewrapPolicyError> {
        let id = id.into();
        ResourceSelector::new(ResourceKind::FileRoot, id.clone())
            .map_err(BubblewrapPolicyError::Protocol)?;
        if self.file_roots.contains_key(&id) {
            return Err(BubblewrapPolicyError::DuplicateFileRoot { id });
        }
        self.file_roots.insert(id, binding);
        Ok(self)
    }

    /// Enables an empty private `tmpfs` at `/tmp` for the worker.
    ///
    /// It is disabled by default because Bubblewrap alone does not assign a
    /// memory quota. Hosts that enable it must supply an external resource
    /// limit appropriate to their platform.
    pub fn enable_private_tmpfs(&mut self) -> &mut Self {
        self.private_tmpfs = true;
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
        let bwrap_program =
            resolve_regular_executable_file("Bubblewrap program", &self.bwrap_program)?;

        let mut mounts = self
            .runtime_mounts
            .iter()
            .map(resolve_runtime_mount)
            .collect::<Result<Vec<_>, _>>()?;

        let resources = manifest
            .grants
            .iter()
            .flat_map(|grant| grant.resources.iter().cloned())
            .collect::<BTreeSet<_>>();
        for resource in resources {
            match resource.kind {
                ResourceKind::FileRoot => {
                    let binding = self.file_roots.get(&resource.id).ok_or_else(|| {
                        BubblewrapPolicyError::MissingFileRoot {
                            id: resource.id.clone(),
                        }
                    })?;
                    mounts.push(resolve_file_root(binding)?);
                }
                ResourceKind::Executable | ResourceKind::NetworkOrigin | ResourceKind::Secret => {
                    return Err(BubblewrapPolicyError::UnsupportedResource { resource });
                }
            }
        }

        validate_mount_layout(&mut mounts, &self.worker_program, self.private_tmpfs)?;

        let mut arguments = vec![
            OsString::from("--die-with-parent"),
            OsString::from("--new-session"),
            OsString::from("--unshare-all"),
            OsString::from("--clearenv"),
            OsString::from("--proc"),
            OsString::from("/proc"),
            OsString::from("--dev"),
            OsString::from("/dev"),
            OsString::from("--chdir"),
            OsString::from("/"),
        ];
        if self.private_tmpfs {
            arguments.push(OsString::from("--tmpfs"));
            arguments.push(OsString::from("/tmp"));
        }
        for mount in &mounts {
            arguments.push(OsString::from(match mount.access {
                FileRootAccess::ReadOnly => "--ro-bind",
                FileRootAccess::ReadWrite => "--bind",
            }));
            arguments.push(mount.source.clone().into_os_string());
            arguments.push(mount.destination.clone().into_os_string());
        }
        arguments.push(OsString::from("--"));
        arguments.push(self.worker_program.clone().into_os_string());
        arguments.extend(self.worker_arguments.iter().cloned());

        Ok(BubblewrapCommand {
            bwrap_program,
            arguments,
        })
    }
}

/// An immutable Bubblewrap command assembled from a validated policy.
///
/// The plan contains host paths, so hosts should not expose its debug output
/// or errors to a script, LLM, or untrusted log sink. It contains no session
/// key: key provisioning must use a separate trusted bootstrap channel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BubblewrapCommand {
    bwrap_program: PathBuf,
    arguments: Vec<OsString>,
}

impl BubblewrapCommand {
    /// Returns the canonical host Bubblewrap executable path.
    pub fn bwrap_program(&self) -> &Path {
        &self.bwrap_program
    }

    /// Returns the exact command-line arguments supplied to Bubblewrap.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
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
            let mut command = Command::new(&self.bwrap_program);
            command
                .args(&self.arguments)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            let mut child = command.spawn().map_err(BubblewrapSpawnError::Spawn)?;
            let Some(stdin) = child.stdin.take() else {
                terminate_child(&mut child);
                return Err(BubblewrapSpawnError::MissingStdin);
            };
            let Some(stdout) = child.stdout.take() else {
                terminate_child(&mut child);
                return Err(BubblewrapSpawnError::MissingStdout);
            };
            Ok(SpawnedBubblewrapWorker {
                child,
                stdin,
                stdout,
            })
        }
    }
}

/// One running worker and its dedicated JSON-line pipes.
#[derive(Debug)]
pub struct SpawnedBubblewrapWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

impl SpawnedBubblewrapWorker {
    /// Returns the child process for host-controlled lifecycle management.
    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Consumes the handle and returns the child plus its private input/output
    /// pipes. The caller can wrap these in `JsonLineWorkerChannel`.
    pub fn into_parts(self) -> (Child, ChildStdin, ChildStdout) {
        (self.child, self.stdin, self.stdout)
    }
}

/// Policy compilation failure.
#[derive(Debug)]
pub enum BubblewrapPolicyError {
    Protocol(ProtocolError),
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
    SourceNotExecutable {
        field: &'static str,
        path: PathBuf,
    },
    WorkerProgramNotExecutable {
        program: PathBuf,
    },
}

impl Display for BubblewrapPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "invalid capability manifest: {error}"),
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
                    "no host binding exists for file-root selector {id:?}"
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
            Self::SourceNotExecutable { field, path } => {
                write!(formatter, "{field} {} must be executable", path.display())
            }
            Self::WorkerProgramNotExecutable { program } => write!(
                formatter,
                "worker program {} must be a regular executable file",
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
            Self::InvalidPath { .. }
            | Self::InvalidSourceType { .. }
            | Self::RootMountForbidden { .. }
            | Self::DuplicateFileRoot { .. }
            | Self::MissingFileRoot { .. }
            | Self::UnsupportedResource { .. }
            | Self::ReservedMountDestination { .. }
            | Self::OverlappingMountDestinations { .. }
            | Self::WorkerProgramNotMounted { .. }
            | Self::SourceNotExecutable { .. }
            | Self::WorkerProgramNotExecutable { .. } => None,
        }
    }
}

/// Failure while starting a compiled Bubblewrap command.
#[derive(Debug)]
pub enum BubblewrapSpawnError {
    UnsupportedPlatform,
    Spawn(io::Error),
    MissingStdin,
    MissingStdout,
}

impl Display for BubblewrapSpawnError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("Bubblewrap workers are supported only on Linux")
            }
            Self::Spawn(error) => write!(formatter, "failed to spawn Bubblewrap worker: {error}"),
            Self::MissingStdin => formatter.write_str("Bubblewrap worker did not expose stdin"),
            Self::MissingStdout => formatter.write_str("Bubblewrap worker did not expose stdout"),
        }
    }
}

impl std::error::Error for BubblewrapSpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::UnsupportedPlatform | Self::MissingStdin | Self::MissingStdout => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MountSourceType {
    File,
    Directory,
}

#[derive(Clone, Debug)]
struct CompiledMount {
    source: PathBuf,
    destination: PathBuf,
    access: FileRootAccess,
    source_type: MountSourceType,
    is_runtime: bool,
}

impl CompiledMount {
    fn exposes_worker_program(&self, worker_program: &Path) -> bool {
        if !self.is_runtime {
            return false;
        }
        match self.source_type {
            MountSourceType::File => worker_program == self.destination,
            MountSourceType::Directory => path_is_within(worker_program, &self.destination),
        }
    }

    fn worker_program_source(&self, worker_program: &Path) -> Option<PathBuf> {
        if !self.exposes_worker_program(worker_program) {
            return None;
        }
        match self.source_type {
            MountSourceType::File => Some(self.source.clone()),
            MountSourceType::Directory => worker_program
                .strip_prefix(&self.destination)
                .ok()
                .map(|relative| self.source.join(relative)),
        }
    }
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

fn resolve_runtime_mount(mount: &ReadOnlyMount) -> Result<CompiledMount, BubblewrapPolicyError> {
    let source = canonical_existing_path("runtime mount source", &mount.source)?;
    let metadata =
        fs::metadata(&source).map_err(|source_error| BubblewrapPolicyError::SourceIo {
            field: "runtime mount source",
            path: source.clone(),
            source: source_error,
        })?;
    let source_type = source_type("runtime mount source", source.clone(), &metadata)?;
    Ok(CompiledMount {
        source,
        destination: mount.destination.clone(),
        access: FileRootAccess::ReadOnly,
        source_type,
        is_runtime: true,
    })
}

fn resolve_file_root(binding: &FileRootBinding) -> Result<CompiledMount, BubblewrapPolicyError> {
    let source = canonical_existing_path("file-root source", &binding.source)?;
    let metadata =
        fs::metadata(&source).map_err(|source_error| BubblewrapPolicyError::SourceIo {
            field: "file-root source",
            path: source.clone(),
            source: source_error,
        })?;
    if !metadata.is_dir() {
        return Err(BubblewrapPolicyError::InvalidSourceType {
            field: "file-root source",
            path: source,
            expected: "directory",
        });
    }
    Ok(CompiledMount {
        source,
        destination: binding.destination.clone(),
        access: binding.access,
        source_type: MountSourceType::Directory,
        is_runtime: false,
    })
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
    worker_program: &Path,
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

    mounts.sort_by(|left, right| {
        left.destination
            .cmp(&right.destination)
            .then_with(|| left.source.cmp(&right.source))
    });
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

    let worker_mount = mounts
        .iter()
        .find(|mount| mount.exposes_worker_program(worker_program));
    let Some(worker_mount) = worker_mount else {
        return Err(BubblewrapPolicyError::WorkerProgramNotMounted {
            program: worker_program.to_path_buf(),
        });
    };
    let worker_source = worker_mount
        .worker_program_source(worker_program)
        .ok_or_else(|| BubblewrapPolicyError::WorkerProgramNotMounted {
            program: worker_program.to_path_buf(),
        })?;
    let metadata =
        fs::symlink_metadata(&worker_source).map_err(|source| BubblewrapPolicyError::SourceIo {
            field: "worker program source",
            path: worker_source.clone(),
            source,
        })?;
    if !metadata.file_type().is_file() || !is_executable(&metadata) {
        return Err(BubblewrapPolicyError::WorkerProgramNotExecutable {
            program: worker_program.to_path_buf(),
        });
    }
    Ok(())
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

#[cfg(target_os = "linux")]
fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use splash_protocol::{CapabilityGrant, ResourceSelector};

    use super::*;

    fn manifest(resources: impl IntoIterator<Item = ResourceSelector>) -> CapabilityManifest {
        let mut grant = CapabilityGrant::json("tool.call");
        grant.resources = resources.into_iter().collect();
        CapabilityManifest::new("session-1", vec![grant]).unwrap()
    }

    fn selector(kind: ResourceKind, id: &str) -> ResourceSelector {
        ResourceSelector::new(kind, id).unwrap()
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
        assert!(has_arguments(&arguments, &["--new-session"]));
        assert!(has_arguments(&arguments, &["--clearenv"]));
        assert!(has_arguments(&arguments, &["--chdir", "/"]));
        assert!(!arguments.iter().any(|argument| argument == "--share-net"));
        assert!(has_arguments(
            &arguments,
            &["--", "/opt/splash/worker", "--json-lines"]
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
    fn private_tmpfs_is_explicit() {
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
}
