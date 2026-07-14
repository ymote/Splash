//! Linux cgroup-v2 resource policy for a fixed Splash worker launch.
//!
//! The policy is constructed by trusted host Rust code. It creates one child
//! beneath a host-owned delegated cgroup, configures its controller files, and
//! gives a fixed runner the path to `cgroup.procs`. That runner moves itself
//! before it `exec`s Bubblewrap, so the Bubblewrap process and every later
//! descendant inherit the cgroup rather than being moved after startup.

use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
use std::num::NonZeroU64;
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(target_os = "linux")]
const DEFAULT_CPU_PERIOD_MICROS: u64 = 100_000;
const DEFAULT_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_FINITE_LIMIT: u64 = u64::MAX - 1;
#[cfg(target_os = "linux")]
const MAX_CREATE_ATTEMPTS: u64 = 64;

#[cfg(target_os = "linux")]
static NEXT_CGROUP_NAME: AtomicU64 = AtomicU64::new(1);

/// One cgroup-v2 controller limit selected by [`CgroupV2Limits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CgroupV2Limit {
    /// Fair-scheduler CPU bandwidth in each fixed 100 ms period.
    CpuQuotaMicros,
    /// cgroup memory usage in bytes (`memory.max`).
    MemoryMaxBytes,
    /// cgroup swap usage in bytes (`memory.swap.max`).
    MemorySwapMaxBytes,
    /// Tasks in the cgroup subtree (`pids.max`), including threads.
    PidsMax,
    /// Per-device read bandwidth (`io.max` `rbps`).
    IoReadBytesPerSecond,
    /// Per-device write bandwidth (`io.max` `wbps`).
    IoWriteBytesPerSecond,
    /// Per-device read operations (`io.max` `riops`).
    IoReadOperationsPerSecond,
    /// Per-device write operations (`io.max` `wiops`).
    IoWriteOperationsPerSecond,
}

impl Display for CgroupV2Limit {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CpuQuotaMicros => formatter.write_str("cpu quota"),
            Self::MemoryMaxBytes => formatter.write_str("memory maximum"),
            Self::MemorySwapMaxBytes => formatter.write_str("memory swap maximum"),
            Self::PidsMax => formatter.write_str("PID maximum"),
            Self::IoReadBytesPerSecond => formatter.write_str("I/O read bandwidth"),
            Self::IoWriteBytesPerSecond => formatter.write_str("I/O write bandwidth"),
            Self::IoReadOperationsPerSecond => formatter.write_str("I/O read operation rate"),
            Self::IoWriteOperationsPerSecond => formatter.write_str("I/O write operation rate"),
        }
    }
}

/// Rejection while configuring one finite cgroup-v2 limit.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CgroupV2LimitError {
    InvalidMaximum { limit: CgroupV2Limit, maximum: u64 },
}

impl Display for CgroupV2LimitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMaximum { limit, maximum } => {
                let minimum = if limit_allows_zero(*limit) { 0 } else { 1 };
                write!(
                    formatter,
                    "{limit} must be within {minimum}..={MAX_FINITE_LIMIT}; got {maximum}"
                )
            }
        }
    }
}

impl std::error::Error for CgroupV2LimitError {}

/// A host-selected Linux block device addressed as `major:minor` for
/// cgroup-v2 `io.max` control.
///
/// The caller must obtain this pair from trusted host configuration. It is not
/// a script-visible path or a device-discovery API.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CgroupV2IoDevice {
    major: u32,
    minor: u32,
}

impl CgroupV2IoDevice {
    /// Creates one Linux block-device identifier.
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Returns the Linux device major number.
    pub const fn major(self) -> u32 {
        self.major
    }

    /// Returns the Linux device minor number.
    pub const fn minor(self) -> u32 {
        self.minor
    }
}

impl Display for CgroupV2IoDevice {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.major, self.minor)
    }
}

/// Finite `io.max` limits for one host-selected block device.
///
/// Omitted fields remain unlimited in this child, subject to any ancestor
/// policy. A value of zero is accepted for these I/O controls and prohibits
/// that direction or operation class. The kernel may permit short bursts even
/// when an I/O ceiling is configured.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupV2IoMax {
    device: CgroupV2IoDevice,
    read_bytes_per_second: Option<u64>,
    write_bytes_per_second: Option<u64>,
    read_operations_per_second: Option<u64>,
    write_operations_per_second: Option<u64>,
}

impl CgroupV2IoMax {
    /// Creates an empty I/O policy for `device`.
    ///
    /// Set at least one ceiling before adding it to [`CgroupV2Limits`].
    pub const fn new(device: CgroupV2IoDevice) -> Self {
        Self {
            device,
            read_bytes_per_second: None,
            write_bytes_per_second: None,
            read_operations_per_second: None,
            write_operations_per_second: None,
        }
    }

    /// Returns the host-selected block device.
    pub const fn device(&self) -> CgroupV2IoDevice {
        self.device
    }

    /// Sets the `io.max` `rbps` ceiling.
    pub fn set_read_bytes_per_second(
        &mut self,
        maximum: u64,
    ) -> Result<&mut Self, CgroupV2LimitError> {
        self.read_bytes_per_second = Some(validate_zero_allowed_limit(
            CgroupV2Limit::IoReadBytesPerSecond,
            maximum,
        )?);
        Ok(self)
    }

    /// Sets the `io.max` `wbps` ceiling.
    pub fn set_write_bytes_per_second(
        &mut self,
        maximum: u64,
    ) -> Result<&mut Self, CgroupV2LimitError> {
        self.write_bytes_per_second = Some(validate_zero_allowed_limit(
            CgroupV2Limit::IoWriteBytesPerSecond,
            maximum,
        )?);
        Ok(self)
    }

    /// Sets the `io.max` `riops` ceiling.
    pub fn set_read_operations_per_second(
        &mut self,
        maximum: u64,
    ) -> Result<&mut Self, CgroupV2LimitError> {
        self.read_operations_per_second = Some(validate_zero_allowed_limit(
            CgroupV2Limit::IoReadOperationsPerSecond,
            maximum,
        )?);
        Ok(self)
    }

    /// Sets the `io.max` `wiops` ceiling.
    pub fn set_write_operations_per_second(
        &mut self,
        maximum: u64,
    ) -> Result<&mut Self, CgroupV2LimitError> {
        self.write_operations_per_second = Some(validate_zero_allowed_limit(
            CgroupV2Limit::IoWriteOperationsPerSecond,
            maximum,
        )?);
        Ok(self)
    }

    /// Returns the configured `rbps` ceiling.
    pub const fn read_bytes_per_second(&self) -> Option<u64> {
        self.read_bytes_per_second
    }

    /// Returns the configured `wbps` ceiling.
    pub const fn write_bytes_per_second(&self) -> Option<u64> {
        self.write_bytes_per_second
    }

    /// Returns the configured `riops` ceiling.
    pub const fn read_operations_per_second(&self) -> Option<u64> {
        self.read_operations_per_second
    }

    /// Returns the configured `wiops` ceiling.
    pub const fn write_operations_per_second(&self) -> Option<u64> {
        self.write_operations_per_second
    }

    fn is_empty(&self) -> bool {
        self.read_bytes_per_second.is_none()
            && self.write_bytes_per_second.is_none()
            && self.read_operations_per_second.is_none()
            && self.write_operations_per_second.is_none()
    }

    #[cfg(target_os = "linux")]
    fn control_value(&self) -> String {
        let mut value = self.device.to_string();
        if let Some(maximum) = self.read_bytes_per_second {
            value.push_str(&format!(" rbps={maximum}"));
        }
        if let Some(maximum) = self.write_bytes_per_second {
            value.push_str(&format!(" wbps={maximum}"));
        }
        if let Some(maximum) = self.read_operations_per_second {
            value.push_str(&format!(" riops={maximum}"));
        }
        if let Some(maximum) = self.write_operations_per_second {
            value.push_str(&format!(" wiops={maximum}"));
        }
        value.push('\n');
        value
    }
}

/// Rejection while adding an I/O controller policy to [`CgroupV2Limits`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CgroupV2IoMaxError {
    Empty { device: CgroupV2IoDevice },
    DuplicateDevice { device: CgroupV2IoDevice },
}

impl Display for CgroupV2IoMaxError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { device } => {
                write!(
                    formatter,
                    "I/O policy for device {device} requires at least one limit"
                )
            }
            Self::DuplicateDevice { device } => {
                write!(formatter, "I/O policy already exists for device {device}")
            }
        }
    }
}

impl std::error::Error for CgroupV2IoMaxError {}

/// Trusted controller limits for one worker cgroup.
///
/// `cpu.max` uses a fixed 100 ms period, so a quota of 100,000 permits one
/// fair-scheduler CPU worth of bandwidth. A larger quota can permit multiple
/// CPUs. `memory.max` is a memory-cgroup hard limit rather than an RSS-only
/// limit. `memory.swap.max` can independently prohibit or bound swapping.
/// `pids.max` limits kernel task IDs, which includes threads. `io.max` limits
/// are always scoped to one explicit host-selected block device.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CgroupV2Limits {
    cpu_quota_micros: Option<NonZeroU64>,
    memory_max_bytes: Option<NonZeroU64>,
    memory_swap_max_bytes: Option<u64>,
    pids_max: Option<NonZeroU64>,
    io_max: Vec<CgroupV2IoMax>,
}

impl CgroupV2Limits {
    /// Sets fair-scheduler CPU bandwidth per fixed 100 ms period.
    pub fn set_cpu_quota_micros(&mut self, maximum: u64) -> Result<&mut Self, CgroupV2LimitError> {
        self.cpu_quota_micros = Some(validate_limit(CgroupV2Limit::CpuQuotaMicros, maximum)?);
        Ok(self)
    }

    /// Sets the `memory.max` ceiling in bytes.
    ///
    /// The configured session also sets `memory.oom.group=1` so a cgroup OOM
    /// terminates the whole worker tree instead of leaving a partial worker.
    pub fn set_memory_max_bytes(&mut self, maximum: u64) -> Result<&mut Self, CgroupV2LimitError> {
        self.memory_max_bytes = Some(validate_limit(CgroupV2Limit::MemoryMaxBytes, maximum)?);
        Ok(self)
    }

    /// Sets the `memory.swap.max` ceiling in bytes.
    ///
    /// A value of zero is valid and prohibits swapping for the worker cgroup.
    /// This is independent from `memory.max`; selecting it requires a kernel
    /// and delegated memory controller that expose `memory.swap.max`.
    pub fn set_memory_swap_max_bytes(
        &mut self,
        maximum: u64,
    ) -> Result<&mut Self, CgroupV2LimitError> {
        self.memory_swap_max_bytes = Some(validate_zero_allowed_limit(
            CgroupV2Limit::MemorySwapMaxBytes,
            maximum,
        )?);
        Ok(self)
    }

    /// Sets the `pids.max` ceiling for the worker subtree.
    pub fn set_pids_max(&mut self, maximum: u64) -> Result<&mut Self, CgroupV2LimitError> {
        self.pids_max = Some(validate_limit(CgroupV2Limit::PidsMax, maximum)?);
        Ok(self)
    }

    /// Adds one finite per-device `io.max` policy.
    ///
    /// At least one BPS or IOPS field must be configured. A device can occur
    /// only once so the host cannot accidentally rely on kernel-specific merge
    /// behavior for repeated `io.max` writes.
    pub fn add_io_max(&mut self, maximum: CgroupV2IoMax) -> Result<&mut Self, CgroupV2IoMaxError> {
        if maximum.is_empty() {
            return Err(CgroupV2IoMaxError::Empty {
                device: maximum.device(),
            });
        }
        if self
            .io_max
            .iter()
            .any(|configured| configured.device() == maximum.device())
        {
            return Err(CgroupV2IoMaxError::DuplicateDevice {
                device: maximum.device(),
            });
        }
        self.io_max.push(maximum);
        Ok(self)
    }

    /// Returns the CPU quota in microseconds per fixed 100 ms period.
    pub const fn cpu_quota_micros(&self) -> Option<NonZeroU64> {
        self.cpu_quota_micros
    }

    /// Returns the memory-cgroup maximum in bytes.
    pub const fn memory_max_bytes(&self) -> Option<NonZeroU64> {
        self.memory_max_bytes
    }

    /// Returns the swap ceiling in bytes, where zero prohibits swapping.
    pub const fn memory_swap_max_bytes(&self) -> Option<u64> {
        self.memory_swap_max_bytes
    }

    /// Returns the task ceiling for the worker subtree.
    pub const fn pids_max(&self) -> Option<NonZeroU64> {
        self.pids_max
    }

    /// Returns the configured per-device I/O ceilings in host insertion order.
    pub fn io_max(&self) -> &[CgroupV2IoMax] {
        &self.io_max
    }

    fn is_empty(&self) -> bool {
        self.cpu_quota_micros.is_none()
            && self.memory_max_bytes.is_none()
            && self.memory_swap_max_bytes.is_none()
            && self.pids_max.is_none()
            && self.io_max.is_empty()
    }

    #[cfg(target_os = "linux")]
    fn configure(&self, path: &Path) -> Result<(), CgroupV2PrepareError> {
        if let Some(quota) = self.cpu_quota_micros {
            write_control(
                path,
                "cpu.max",
                format!("{} {DEFAULT_CPU_PERIOD_MICROS}\n", quota.get()),
            )?;
        }
        if let Some(maximum) = self.memory_max_bytes {
            write_control(path, "memory.max", format!("{}\n", maximum.get()))?;
            write_control(path, "memory.oom.group", "1\n")?;
        }
        if let Some(maximum) = self.memory_swap_max_bytes {
            write_control(path, "memory.swap.max", format!("{maximum}\n"))?;
        }
        if let Some(maximum) = self.pids_max {
            write_control(path, "pids.max", format!("{}\n", maximum.get()))?;
        }
        for maximum in &self.io_max {
            write_control(path, "io.max", maximum.control_value())?;
        }
        Ok(())
    }
}

fn validate_limit(limit: CgroupV2Limit, maximum: u64) -> Result<NonZeroU64, CgroupV2LimitError> {
    let Some(maximum) = NonZeroU64::new(maximum) else {
        return Err(CgroupV2LimitError::InvalidMaximum { limit, maximum });
    };
    if maximum.get() > MAX_FINITE_LIMIT {
        return Err(CgroupV2LimitError::InvalidMaximum {
            limit,
            maximum: maximum.get(),
        });
    }
    Ok(maximum)
}

fn validate_zero_allowed_limit(
    limit: CgroupV2Limit,
    maximum: u64,
) -> Result<u64, CgroupV2LimitError> {
    if maximum > MAX_FINITE_LIMIT {
        return Err(CgroupV2LimitError::InvalidMaximum { limit, maximum });
    }
    Ok(maximum)
}

const fn limit_allows_zero(limit: CgroupV2Limit) -> bool {
    matches!(
        limit,
        CgroupV2Limit::MemorySwapMaxBytes
            | CgroupV2Limit::IoReadBytesPerSecond
            | CgroupV2Limit::IoWriteBytesPerSecond
            | CgroupV2Limit::IoReadOperationsPerSecond
            | CgroupV2Limit::IoWriteOperationsPerSecond
    )
}

/// Trusted host configuration for one delegated cgroup-v2 worker subtree.
///
/// `parent` must name a host-owned, delegated cgroup. Splash does not enable
/// controllers on that parent because doing so could change resource policy for
/// unrelated workloads; the host must delegate the required controllers before
/// launch. `runner_program` is a fixed host executable, normally the bundled
/// `splash-cgroup-runner`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupV2Policy {
    parent: PathBuf,
    runner_program: PathBuf,
    limits: CgroupV2Limits,
    join_timeout: Duration,
}

impl CgroupV2Policy {
    /// Creates a cgroup-v2 policy with at least one finite controller limit.
    pub fn new(
        parent: impl Into<PathBuf>,
        runner_program: impl Into<PathBuf>,
        limits: CgroupV2Limits,
    ) -> Result<Self, CgroupV2PolicyError> {
        let parent = parent.into();
        let runner_program = runner_program.into();
        validate_path("cgroup parent", &parent)?;
        validate_path("cgroup runner", &runner_program)?;
        if limits.is_empty() {
            return Err(CgroupV2PolicyError::EmptyLimits);
        }
        Ok(Self {
            parent,
            runner_program,
            limits,
            join_timeout: DEFAULT_JOIN_TIMEOUT,
        })
    }

    /// Returns the host-selected delegated cgroup parent path.
    pub fn parent(&self) -> &Path {
        &self.parent
    }

    /// Returns the fixed host runner program.
    pub fn runner_program(&self) -> &Path {
        &self.runner_program
    }

    /// Returns the selected finite controller limits.
    pub fn limits(&self) -> &CgroupV2Limits {
        &self.limits
    }

    /// Sets the bounded time allowed for the fixed runner to enter the child
    /// cgroup before a launch returns a managed worker handle.
    ///
    /// The host observes the direct child in `cgroup.procs` before it exposes
    /// lifecycle control, preventing teardown from racing a not-yet-joined
    /// runner.
    pub fn set_join_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<&mut Self, CgroupV2PolicyError> {
        if timeout.is_zero() {
            return Err(CgroupV2PolicyError::ZeroJoinTimeout);
        }
        self.join_timeout = timeout;
        Ok(self)
    }

    /// Returns the maximum wait for the fixed runner to join the fresh child.
    pub const fn join_timeout(&self) -> Duration {
        self.join_timeout
    }

    /// Creates and configures one fresh child cgroup.
    ///
    /// The operation fails closed unless the parent exposes cgroup-v2 core
    /// files, all selected controller files appear in the new child, and
    /// `cgroup.kill` is available for process-tree teardown.
    pub fn prepare(&self) -> Result<CgroupV2Session, CgroupV2PrepareError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            Err(CgroupV2PrepareError::UnsupportedPlatform)
        }

        #[cfg(target_os = "linux")]
        {
            self.prepare_linux()
        }
    }

    #[cfg(target_os = "linux")]
    fn prepare_linux(&self) -> Result<CgroupV2Session, CgroupV2PrepareError> {
        let parent =
            fs::canonicalize(&self.parent).map_err(|source| CgroupV2PrepareError::ParentIo {
                path: self.parent.clone(),
                source,
            })?;
        let metadata = fs::metadata(&parent).map_err(|source| CgroupV2PrepareError::ParentIo {
            path: parent.clone(),
            source,
        })?;
        if !metadata.is_dir() {
            return Err(CgroupV2PrepareError::ParentNotDirectory { path: parent });
        }
        ensure_cgroup_parent(&parent)?;
        let runner_program = resolve_runner_program(&self.runner_program)?;
        let path = create_child_cgroup(&parent)?;
        let session = CgroupV2Session {
            path,
            runner_program,
        };
        if let Err(error) = self.limits.configure(session.path()) {
            let _ = session.cleanup();
            return Err(error);
        }
        // The fresh child is empty, so this verifies that process-tree kill is
        // actually writable without affecting a worker. Merely checking for a
        // control-file name would defer a delegated-permission failure until a
        // live session needs containment teardown.
        let kill_path = session.path.join("cgroup.kill");
        if let Err(source) = fs::metadata(&kill_path).and_then(|_| fs::write(&kill_path, "1\n")) {
            let path = session.path.clone();
            let _ = session.cleanup();
            return Err(CgroupV2PrepareError::MissingKillInterface { path, source });
        }
        Ok(session)
    }
}

/// Rejection while constructing [`CgroupV2Policy`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CgroupV2PolicyError {
    EmptyLimits,
    ZeroJoinTimeout,
    InvalidPath {
        field: &'static str,
        path: PathBuf,
        reason: &'static str,
    },
}

impl Display for CgroupV2PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLimits => {
                formatter.write_str("cgroup policy requires at least one finite limit")
            }
            Self::ZeroJoinTimeout => {
                formatter.write_str("cgroup runner join timeout must be greater than zero")
            }
            Self::InvalidPath {
                field,
                path,
                reason,
            } => write!(formatter, "{field} path {} {reason}", path.display()),
        }
    }
}

impl std::error::Error for CgroupV2PolicyError {}

/// Failure while preparing one cgroup-v2 worker child.
#[derive(Debug)]
#[non_exhaustive]
pub enum CgroupV2PrepareError {
    UnsupportedPlatform,
    ParentIo {
        path: PathBuf,
        source: io::Error,
    },
    ParentNotDirectory {
        path: PathBuf,
    },
    ParentNotCgroup {
        path: PathBuf,
        source: io::Error,
    },
    ParentNotCgroupV2 {
        path: PathBuf,
        filesystem_type: u64,
    },
    RunnerIo {
        path: PathBuf,
        source: io::Error,
    },
    RunnerNotRegularExecutable {
        path: PathBuf,
    },
    Create {
        path: PathBuf,
        source: io::Error,
    },
    NameExhausted {
        parent: PathBuf,
    },
    Configure {
        path: PathBuf,
        file: &'static str,
        source: io::Error,
    },
    MissingKillInterface {
        path: PathBuf,
        source: io::Error,
    },
}

impl Display for CgroupV2PrepareError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str("cgroup-v2 workers require Linux"),
            Self::ParentIo { path, source } => {
                write!(
                    formatter,
                    "could not inspect cgroup parent {}: {source}",
                    path.display()
                )
            }
            Self::ParentNotDirectory { path } => {
                write!(
                    formatter,
                    "cgroup parent {} is not a directory",
                    path.display()
                )
            }
            Self::ParentNotCgroup { path, source } => write!(
                formatter,
                "cgroup parent {} does not expose cgroup-v2 core files: {source}",
                path.display()
            ),
            Self::ParentNotCgroupV2 {
                path,
                filesystem_type,
            } => write!(
                formatter,
                "cgroup parent {} is not mounted from cgroup-v2 (filesystem type {filesystem_type:#x})",
                path.display()
            ),
            Self::RunnerIo { path, source } => {
                write!(
                    formatter,
                    "could not inspect cgroup runner {}: {source}",
                    path.display()
                )
            }
            Self::RunnerNotRegularExecutable { path } => write!(
                formatter,
                "cgroup runner {} must be a regular executable file",
                path.display()
            ),
            Self::Create { path, source } => {
                write!(
                    formatter,
                    "could not create cgroup {}: {source}",
                    path.display()
                )
            }
            Self::NameExhausted { parent } => write!(
                formatter,
                "could not allocate a fresh worker cgroup beneath {}",
                parent.display()
            ),
            Self::Configure { path, file, source } => write!(
                formatter,
                "could not configure cgroup {} control {file}: {source}",
                path.display()
            ),
            Self::MissingKillInterface { path, source } => write!(
                formatter,
                "cgroup {} does not support process-tree kill: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for CgroupV2PrepareError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParentIo { source, .. }
            | Self::ParentNotCgroup { source, .. }
            | Self::RunnerIo { source, .. }
            | Self::Create { source, .. }
            | Self::Configure { source, .. }
            | Self::MissingKillInterface { source, .. } => Some(source),
            Self::UnsupportedPlatform
            | Self::ParentNotDirectory { .. }
            | Self::ParentNotCgroupV2 { .. }
            | Self::RunnerNotRegularExecutable { .. }
            | Self::NameExhausted { .. } => None,
        }
    }
}

/// One prepared cgroup-v2 worker session.
///
/// It owns only a fresh child beneath a host-owned delegated parent. The
/// cgroup runner receives its `cgroup.procs` path and joins it before it
/// executes Bubblewrap. [`Self::kill`] kills the complete cgroup subtree,
/// including concurrent forks, and [`Self::cleanup`] removes the empty child.
#[derive(Debug)]
pub struct CgroupV2Session {
    path: PathBuf,
    #[cfg(target_os = "linux")]
    runner_program: PathBuf,
}

impl CgroupV2Session {
    /// Returns the host-owned child cgroup path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the `cgroup.procs` control path passed only to the fixed runner.
    pub fn cgroup_procs_path(&self) -> PathBuf {
        self.path.join("cgroup.procs")
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn runner_program(&self) -> &Path {
        &self.runner_program
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn contains_process(&self, process_id: u32) -> Result<bool, CgroupV2SessionError> {
        let control_path = self.cgroup_procs_path();
        let processes =
            fs::read_to_string(&control_path).map_err(|source| CgroupV2SessionError::Inspect {
                path: self.path.clone(),
                source,
            })?;
        Ok(processes
            .lines()
            .any(|line| line.parse::<u32>().ok() == Some(process_id)))
    }

    /// Kills every process in this cgroup subtree with the cgroup-v2 kill
    /// operation. This is not worker-protocol cancellation or recovery.
    pub fn kill(&self) -> Result<(), CgroupV2SessionError> {
        fs::write(self.path.join("cgroup.kill"), "1\n").map_err(|source| {
            CgroupV2SessionError::Kill {
                path: self.path.clone(),
                source,
            }
        })
    }

    /// Removes the cgroup after every process in its subtree has exited.
    pub fn cleanup(&self) -> Result<(), CgroupV2SessionError> {
        fs::remove_dir(&self.path).map_err(|source| CgroupV2SessionError::Cleanup {
            path: self.path.clone(),
            source,
        })
    }
}

impl Drop for CgroupV2Session {
    fn drop(&mut self) {
        // A normal child exit makes the cgroup removable. Do not kill a live
        // workload on an accidental host-handle drop; lifecycle owners must
        // explicitly terminate it and handle any cleanup failure.
        let _ = fs::remove_dir(&self.path);
    }
}

/// Failure while killing or cleaning up a prepared cgroup session.
#[derive(Debug)]
#[non_exhaustive]
pub enum CgroupV2SessionError {
    Inspect { path: PathBuf, source: io::Error },
    Kill { path: PathBuf, source: io::Error },
    Cleanup { path: PathBuf, source: io::Error },
}

impl Display for CgroupV2SessionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspect { path, source } => {
                write!(
                    formatter,
                    "could not inspect cgroup {}: {source}",
                    path.display()
                )
            }
            Self::Kill { path, source } => {
                write!(
                    formatter,
                    "could not kill cgroup {}: {source}",
                    path.display()
                )
            }
            Self::Cleanup { path, source } => {
                write!(
                    formatter,
                    "could not remove cgroup {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for CgroupV2SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inspect { source, .. }
            | Self::Kill { source, .. }
            | Self::Cleanup { source, .. } => Some(source),
        }
    }
}

fn validate_path(field: &'static str, path: &Path) -> Result<(), CgroupV2PolicyError> {
    if !path.is_absolute() {
        return Err(CgroupV2PolicyError::InvalidPath {
            field,
            path: path.to_path_buf(),
            reason: "must be absolute",
        });
    }
    if path == Path::new("/") {
        return Err(CgroupV2PolicyError::InvalidPath {
            field,
            path: path.to_path_buf(),
            reason: "must not be /",
        });
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(CgroupV2PolicyError::InvalidPath {
            field,
            path: path.to_path_buf(),
            reason: "must not contain . or .. components",
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_cgroup_parent(path: &Path) -> Result<(), CgroupV2PrepareError> {
    let filesystem = rustix::fs::statfs(path).map_err(|source| CgroupV2PrepareError::ParentIo {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    if filesystem.f_type as u64 != u64::from(linux_raw_sys::general::CGROUP2_SUPER_MAGIC) {
        return Err(CgroupV2PrepareError::ParentNotCgroupV2 {
            path: path.to_path_buf(),
            filesystem_type: filesystem.f_type as u64,
        });
    }
    for file in [
        "cgroup.controllers",
        "cgroup.procs",
        "cgroup.subtree_control",
    ] {
        fs::metadata(path.join(file)).map_err(|source| CgroupV2PrepareError::ParentNotCgroup {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_runner_program(path: &Path) -> Result<PathBuf, CgroupV2PrepareError> {
    let path = fs::canonicalize(path).map_err(|source| CgroupV2PrepareError::RunnerIo {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = fs::metadata(&path).map_err(|source| CgroupV2PrepareError::RunnerIo {
        path: path.clone(),
        source,
    })?;
    if !metadata.is_file() || !is_executable(&metadata) {
        return Err(CgroupV2PrepareError::RunnerNotRegularExecutable { path });
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn create_child_cgroup(parent: &Path) -> Result<PathBuf, CgroupV2PrepareError> {
    for _ in 0..MAX_CREATE_ATTEMPTS {
        let sequence = NEXT_CGROUP_NAME.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("splash-{}-{sequence}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(CgroupV2PrepareError::Create { path, source }),
        }
    }
    Err(CgroupV2PrepareError::NameExhausted {
        parent: parent.to_path_buf(),
    })
}

#[cfg(target_os = "linux")]
fn write_control(
    path: &Path,
    file: &'static str,
    value: impl AsRef<[u8]>,
) -> Result<(), CgroupV2PrepareError> {
    let control_path = path.join(file);
    fs::metadata(&control_path)
        .and_then(|_| fs::write(&control_path, value))
        .map_err(|source| CgroupV2PrepareError::Configure {
            path: path.to_path_buf(),
            file,
            source,
        })
}

#[cfg(target_os = "linux")]
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicUsize = AtomicUsize::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "splash-cgroup-v2-test-{}-{}",
                std::process::id(),
                NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
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

    fn executable(path: &Path) {
        File::create(path).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn fake_parent(root: &TestDirectory) -> PathBuf {
        let parent = root.path().join("parent");
        fs::create_dir(&parent).unwrap();
        for file in [
            "cgroup.controllers",
            "cgroup.procs",
            "cgroup.subtree_control",
        ] {
            File::create(parent.join(file)).unwrap();
        }
        parent
    }

    fn limits() -> CgroupV2Limits {
        let mut limits = CgroupV2Limits::default();
        limits.set_cpu_quota_micros(50_000).unwrap();
        limits.set_memory_max_bytes(8 * 1024 * 1024).unwrap();
        limits.set_pids_max(8).unwrap();
        limits
    }

    #[test]
    fn rejects_empty_or_invalid_cgroup_policy_configuration() {
        let root = TestDirectory::new();
        let runner = root.path().join("runner");
        executable(&runner);

        assert!(matches!(
            CgroupV2Policy::new(root.path(), &runner, CgroupV2Limits::default()),
            Err(CgroupV2PolicyError::EmptyLimits)
        ));
        assert!(matches!(
            CgroupV2Policy::new("relative", &runner, limits()),
            Err(CgroupV2PolicyError::InvalidPath { .. })
        ));
        assert!(matches!(
            CgroupV2Policy::new(root.path(), "/", limits()),
            Err(CgroupV2PolicyError::InvalidPath { .. })
        ));
        let mut policy = CgroupV2Policy::new(root.path(), &runner, limits()).unwrap();
        assert!(matches!(
            policy.set_join_timeout(Duration::ZERO),
            Err(CgroupV2PolicyError::ZeroJoinTimeout)
        ));
    }

    #[test]
    fn rejects_zero_and_unbounded_controller_limits() {
        let mut limits = CgroupV2Limits::default();
        assert!(matches!(
            limits.set_cpu_quota_micros(0),
            Err(CgroupV2LimitError::InvalidMaximum {
                limit: CgroupV2Limit::CpuQuotaMicros,
                ..
            })
        ));
        assert!(matches!(
            limits.set_memory_max_bytes(u64::MAX),
            Err(CgroupV2LimitError::InvalidMaximum {
                limit: CgroupV2Limit::MemoryMaxBytes,
                ..
            })
        ));
        assert!(matches!(
            limits.set_pids_max(0),
            Err(CgroupV2LimitError::InvalidMaximum {
                limit: CgroupV2Limit::PidsMax,
                ..
            })
        ));
        assert!(matches!(
            limits.set_memory_swap_max_bytes(u64::MAX),
            Err(CgroupV2LimitError::InvalidMaximum {
                limit: CgroupV2Limit::MemorySwapMaxBytes,
                ..
            })
        ));
    }

    #[test]
    fn configures_finite_swap_and_per_device_io_limits() {
        let device = CgroupV2IoDevice::new(8, 16);
        let mut io = CgroupV2IoMax::new(device);
        io.set_read_bytes_per_second(2 * 1024 * 1024).unwrap();
        io.set_write_operations_per_second(120).unwrap();

        let mut limits = CgroupV2Limits::default();
        limits.set_memory_swap_max_bytes(0).unwrap();
        limits.add_io_max(io.clone()).unwrap();

        assert_eq!(limits.memory_swap_max_bytes(), Some(0));
        assert_eq!(limits.io_max(), &[io]);
        assert_eq!(
            limits.io_max()[0].control_value(),
            "8:16 rbps=2097152 wiops=120\n"
        );

        let duplicate = CgroupV2IoMax::new(device);
        assert!(matches!(
            limits.add_io_max(duplicate),
            Err(CgroupV2IoMaxError::Empty { device: actual }) if actual == device
        ));

        let mut duplicate = CgroupV2IoMax::new(device);
        duplicate.set_read_operations_per_second(0).unwrap();
        assert!(matches!(
            limits.add_io_max(duplicate),
            Err(CgroupV2IoMaxError::DuplicateDevice { device: actual }) if actual == device
        ));

        assert!(matches!(
            CgroupV2IoMax::new(CgroupV2IoDevice::new(8, 0)).set_write_bytes_per_second(u64::MAX),
            Err(CgroupV2LimitError::InvalidMaximum {
                limit: CgroupV2Limit::IoWriteBytesPerSecond,
                ..
            })
        ));
    }

    #[test]
    fn preparation_rejects_a_non_cgroup_parent() {
        let root = TestDirectory::new();
        let parent = fake_parent(&root);
        let runner = root.path().join("runner");
        executable(&runner);

        let error = CgroupV2Policy::new(parent, runner, limits())
            .unwrap()
            .prepare()
            .unwrap_err();

        assert!(matches!(
            error,
            CgroupV2PrepareError::ParentNotCgroupV2 { .. }
        ));
    }

    #[test]
    fn preparation_requires_a_regular_executable_runner() {
        let root = TestDirectory::new();
        let parent = fake_parent(&root);
        let runner = root.path().join("runner");
        File::create(&runner).unwrap();

        let _policy = CgroupV2Policy::new(parent, &runner, limits()).unwrap();
        let error = resolve_runner_program(&runner).unwrap_err();

        assert!(matches!(
            error,
            CgroupV2PrepareError::RunnerNotRegularExecutable { .. }
        ));
    }

    #[test]
    fn process_membership_matches_only_the_requested_pid() {
        let root = TestDirectory::new();
        let path = root.path().join("worker");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("cgroup.procs"), "17\n42\n").unwrap();
        let session = CgroupV2Session {
            path,
            runner_program: root.path().join("runner"),
        };

        assert!(session.contains_process(42).unwrap());
        assert!(!session.contains_process(43).unwrap());
    }

    #[test]
    fn session_cleanup_reports_a_nonempty_cgroup() {
        let root = TestDirectory::new();
        let path = root.path().join("worker");
        fs::create_dir(&path).unwrap();
        File::create(path.join("child")).unwrap();
        let session = CgroupV2Session {
            path,
            runner_program: root.path().join("runner"),
        };

        assert!(matches!(
            session.cleanup(),
            Err(CgroupV2SessionError::Cleanup { .. })
        ));
    }
}
