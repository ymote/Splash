#![no_main]

use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use splash_protocol::{CapabilityGrant, CapabilityManifest, ResourceKind, ResourceSelector};
use splash_sandbox::bubblewrap::{
    BubblewrapPolicyError, BubblewrapWorkerPolicy, EphemeralFileRoot, FileRootAccess,
    FileRootBinding, ReadOnlyMount, DEFAULT_MAX_BUBBLEWRAP_ACTIVE_FILE_ROOTS,
};

const MAX_FUZZ_INPUT_BYTES: usize = 64;
const KIBIBYTE: usize = 1024;
const FIRST_SCRATCH_BYTES: usize = 16 * KIBIBYTE;
const SECOND_SCRATCH_BYTES: usize = 32 * KIBIBYTE;
const SMALL_PRIVATE_TMPFS_BYTES: usize = 16 * KIBIBYTE;
const LARGE_PRIVATE_TMPFS_BYTES: usize = 64 * KIBIBYTE;
const LINUX_PROJECT_QUOTA_BYTES: u64 = 64 * KIBIBYTE as u64;
const LINUX_PROJECT_QUOTA_INODES: u64 = 16;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let control = FuzzControl::from_bytes(data);
    let (policy, manifest) = configured_policy(control);
    let result = policy.compile(&manifest);

    if control.select_active_file_root_limit_overflow && !control.policy_configuration_must_fail() {
        assert!(matches!(
            result,
            Err(BubblewrapPolicyError::ActiveFileRootLimitExceeded {
                maximum_file_roots: DEFAULT_MAX_BUBBLEWRAP_ACTIVE_FILE_ROOTS,
                active_file_roots,
            }) if active_file_roots > DEFAULT_MAX_BUBBLEWRAP_ACTIVE_FILE_ROOTS
        ));
        return;
    }

    if control.compile_must_fail() {
        assert!(
            result.is_err(),
            "the modeled fail-closed Bubblewrap policy compiled: {control:?}"
        );
        return;
    }

    let command = result.expect("modeled safe fuzz policy must compile");
    assert_eq!(command.manifest(), &manifest);
    assert_eq!(command.session_id(), "fuzz-session");

    let arguments = command
        .arguments()
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(has_arguments(&arguments, &["--unshare-all"]));
    assert!(has_arguments(&arguments, &["--clearenv"]));
    assert!(has_arguments(&arguments, &["--cap-drop", "ALL"]));

    assert_eq!(
        has_arguments(
            &arguments,
            &[
                "--size",
                &FIRST_SCRATCH_BYTES.to_string(),
                "--tmpfs",
                "/workspace/scratch-a",
            ],
        ),
        control.select_first_scratch,
        "the first ephemeral root must be selected only by its opaque manifest ID"
    );
    assert_eq!(
        has_arguments(
            &arguments,
            &[
                "--size",
                &SECOND_SCRATCH_BYTES.to_string(),
                "--tmpfs",
                "/workspace/scratch-b",
            ],
        ),
        control.select_second_scratch,
        "the second ephemeral root must be selected only by its opaque manifest ID"
    );
    assert_eq!(
        arguments
            .iter()
            .any(|argument| argument == "/workspace/readonly"),
        control.select_readonly,
        "the read-only root must be selected only by its opaque manifest ID"
    );
    assert_eq!(
        arguments
            .iter()
            .any(|argument| argument == "/workspace/writable"),
        control.select_writable,
        "the writable root must be selected only by its opaque manifest ID"
    );

    let private_tmpfs_enabled = has_arguments(&arguments, &["--tmpfs", "/tmp"]);
    assert_eq!(private_tmpfs_enabled, control.private_tmpfs.is_enabled());
    if let PrivateTmpfs::Bounded(maximum_bytes) = control.private_tmpfs {
        assert!(has_arguments(
            &arguments,
            &["--size", &maximum_bytes.to_string(), "--tmpfs", "/tmp",],
        ));
    }
    if control.require_bounded_writes {
        assert!(has_arguments(&arguments, &["--unshare-user"]));
        assert!(has_arguments(&arguments, &["--disable-userns"]));
        assert!(has_arguments(&arguments, &["--remount-ro", "/proc"]));
        assert!(has_arguments(&arguments, &["--remount-ro", "/dev"]));
        assert!(has_arguments(&arguments, &["--remount-ro", "/"]));
    }
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FuzzControl {
    select_readonly: bool,
    select_writable: bool,
    select_first_scratch: bool,
    select_second_scratch: bool,
    select_missing: bool,
    select_executable: bool,
    select_network_origin: bool,
    select_secret: bool,
    allow_unbounded_host_writes: bool,
    require_bounded_writes: bool,
    namespace_lockdown: bool,
    private_tmpfs: PrivateTmpfs,
    aggregate_limit: Option<usize>,
    try_invalid_aggregate_limit: bool,
    aggregate_before_private_tmpfs: bool,
    select_active_file_root_limit_overflow: bool,
    linux_project_quota_aggregate: bool,
    try_invalid_linux_project_quota_aggregate: bool,
}

impl FuzzControl {
    fn from_bytes(data: &[u8]) -> Self {
        let file_roots = byte(data, 0) % 32;
        let unsupported_resources = byte(data, 1) % 8;
        let policy = byte(data, 2);
        let aggregate = byte(data, 3);
        Self {
            select_readonly: file_roots & 1 != 0,
            select_writable: file_roots & 2 != 0,
            select_first_scratch: file_roots & 4 != 0,
            select_second_scratch: file_roots & 8 != 0,
            select_missing: file_roots & 16 != 0,
            select_executable: unsupported_resources & 1 != 0,
            select_network_origin: unsupported_resources & 2 != 0,
            select_secret: unsupported_resources & 4 != 0,
            allow_unbounded_host_writes: policy & 16 != 0,
            require_bounded_writes: policy & 1 != 0,
            namespace_lockdown: policy & 2 != 0,
            private_tmpfs: PrivateTmpfs::from_bits(policy >> 2),
            aggregate_limit: aggregate_limit(aggregate),
            try_invalid_aggregate_limit: !(aggregate / 9).is_multiple_of(2),
            aggregate_before_private_tmpfs: byte(data, 4) & 1 != 0,
            select_active_file_root_limit_overflow: byte(data, 5) & 1 != 0,
            linux_project_quota_aggregate: byte(data, 6) & 1 != 0,
            try_invalid_linux_project_quota_aggregate: byte(data, 7) & 1 != 0,
        }
    }

    fn aggregate_requested_bytes(self) -> usize {
        let mut requested_bytes = self.private_tmpfs.maximum_bytes().unwrap_or_default();
        if self.select_first_scratch {
            requested_bytes += FIRST_SCRATCH_BYTES;
        }
        if self.select_second_scratch {
            requested_bytes += SECOND_SCRATCH_BYTES;
        }
        requested_bytes
    }

    fn selects_unsupported_resource(self) -> bool {
        self.select_executable || self.select_network_origin || self.select_secret
    }

    fn compile_must_fail(self) -> bool {
        self.select_missing
            || self.selects_unsupported_resource()
            || self.select_active_file_root_limit_overflow
            || self.policy_configuration_must_fail()
            || (self.select_writable
                && (!self.allow_unbounded_host_writes
                    || self.require_bounded_writes
                    || self.linux_project_quota_aggregate))
            || self.aggregate_limit.is_some_and(|maximum_bytes| {
                self.private_tmpfs == PrivateTmpfs::Unbounded
                    || self.aggregate_requested_bytes() > maximum_bytes
            })
    }

    fn policy_configuration_must_fail(self) -> bool {
        self.require_bounded_writes
            && (!self.namespace_lockdown || self.private_tmpfs == PrivateTmpfs::Unbounded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateTmpfs {
    Disabled,
    Unbounded,
    Bounded(usize),
}

impl PrivateTmpfs {
    fn from_bits(bits: u8) -> Self {
        match bits & 3 {
            0 => Self::Disabled,
            1 => Self::Unbounded,
            2 => Self::Bounded(SMALL_PRIVATE_TMPFS_BYTES),
            _ => Self::Bounded(LARGE_PRIVATE_TMPFS_BYTES),
        }
    }

    const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    const fn maximum_bytes(self) -> Option<usize> {
        match self {
            Self::Bounded(maximum_bytes) => Some(maximum_bytes),
            Self::Disabled | Self::Unbounded => None,
        }
    }
}

fn aggregate_limit(input: u8) -> Option<usize> {
    match input % 9 {
        0 => None,
        1 => Some(1),
        2 => Some(FIRST_SCRATCH_BYTES),
        3 => Some(SECOND_SCRATCH_BYTES),
        4 => Some(FIRST_SCRATCH_BYTES + SECOND_SCRATCH_BYTES),
        5 => Some(LARGE_PRIVATE_TMPFS_BYTES),
        6 => Some(LARGE_PRIVATE_TMPFS_BYTES + SECOND_SCRATCH_BYTES),
        7 => Some(2 * LARGE_PRIVATE_TMPFS_BYTES),
        _ => Some(usize::MAX),
    }
}

fn configured_policy(control: FuzzControl) -> (BubblewrapWorkerPolicy, CapabilityManifest) {
    let (executable, runtime_source, worker_program) = fuzz_paths();
    let mut policy = BubblewrapWorkerPolicy::new(executable, worker_program)
        .expect("the host-derived Bubblewrap and worker paths are absolute");
    policy.add_runtime_mount(
        ReadOnlyMount::new(runtime_source.clone(), "/runtime")
            .expect("the host-derived runtime mount paths are absolute"),
    );
    policy
        .add_file_root(
            "readonly",
            FileRootBinding::new(
                runtime_source.clone(),
                "/workspace/readonly",
                FileRootAccess::ReadOnly,
            )
            .expect("the host-derived read-only root is valid"),
        )
        .expect("the fixed read-only root ID is unique");
    policy
        .add_file_root(
            "writable",
            FileRootBinding::new(
                runtime_source,
                "/workspace/writable",
                FileRootAccess::ReadWrite,
            )
            .expect("the host-derived writable root is valid"),
        )
        .expect("the fixed writable root ID is unique");
    policy
        .add_ephemeral_file_root(
            "scratch-a",
            EphemeralFileRoot::new("/workspace/scratch-a", FIRST_SCRATCH_BYTES)
                .expect("the fixed first scratch root is valid"),
        )
        .expect("the fixed first scratch root ID is unique");
    policy
        .add_ephemeral_file_root(
            "scratch-b",
            EphemeralFileRoot::new("/workspace/scratch-b", SECOND_SCRATCH_BYTES)
                .expect("the fixed second scratch root is valid"),
        )
        .expect("the fixed second scratch root ID is unique");

    if control.aggregate_before_private_tmpfs {
        configure_aggregate_limit(&mut policy, control);
    }
    configure_private_tmpfs(&mut policy, control.private_tmpfs);
    if !control.aggregate_before_private_tmpfs {
        configure_aggregate_limit(&mut policy, control);
    }
    configure_linux_project_quota_aggregate(&mut policy, control);
    if control.namespace_lockdown {
        policy.require_no_further_user_namespaces();
    }
    if control.allow_unbounded_host_writes {
        policy.allow_unbounded_host_file_root_writes();
    }
    if control.require_bounded_writes {
        policy.require_bounded_file_root_writes();
    }

    (policy, manifest(control))
}

fn fuzz_paths() -> (PathBuf, PathBuf, PathBuf) {
    let executable = std::env::current_exe().expect("the fuzz process has a current executable");
    let runtime_source = executable
        .parent()
        .expect("the fuzz executable has a parent directory")
        .to_path_buf();
    let worker_program = PathBuf::from("/runtime").join(
        executable
            .file_name()
            .expect("the fuzz executable has a file name"),
    );
    (executable, runtime_source, worker_program)
}

fn configure_aggregate_limit(policy: &mut BubblewrapWorkerPolicy, control: FuzzControl) {
    if control.try_invalid_aggregate_limit {
        assert!(matches!(
            policy.set_maximum_aggregate_ephemeral_tmpfs_bytes(0),
            Err(BubblewrapPolicyError::InvalidAggregateEphemeralTmpfsSize { maximum_bytes: 0 })
        ));
    }
    if let Some(maximum_bytes) = control.aggregate_limit {
        policy
            .set_maximum_aggregate_ephemeral_tmpfs_bytes(maximum_bytes)
            .expect("the finite fuzz aggregate limit is valid");
    }
}

fn configure_private_tmpfs(policy: &mut BubblewrapWorkerPolicy, private_tmpfs: PrivateTmpfs) {
    match private_tmpfs {
        PrivateTmpfs::Disabled => {}
        PrivateTmpfs::Unbounded => {
            policy.enable_private_tmpfs();
        }
        PrivateTmpfs::Bounded(maximum_bytes) => {
            policy
                .enable_private_tmpfs_with_maximum_bytes(maximum_bytes)
                .expect("the fixed bounded private tmpfs size is valid");
        }
    }
}

fn configure_linux_project_quota_aggregate(
    policy: &mut BubblewrapWorkerPolicy,
    control: FuzzControl,
) {
    if control.try_invalid_linux_project_quota_aggregate {
        assert!(matches!(
            policy.set_maximum_aggregate_linux_project_quota(0, LINUX_PROJECT_QUOTA_INODES),
            Err(
                BubblewrapPolicyError::InvalidAggregateLinuxProjectQuotaByteLimit {
                    maximum_bytes: 0,
                }
            )
        ));
        assert!(matches!(
            policy.set_maximum_aggregate_linux_project_quota(LINUX_PROJECT_QUOTA_BYTES, 0),
            Err(
                BubblewrapPolicyError::InvalidAggregateLinuxProjectQuotaInodeLimit {
                    maximum_inodes: 0,
                }
            )
        ));
    }
    if control.linux_project_quota_aggregate {
        policy
            .set_maximum_aggregate_linux_project_quota(
                LINUX_PROJECT_QUOTA_BYTES,
                LINUX_PROJECT_QUOTA_INODES,
            )
            .expect("the finite fuzz Linux project-quota aggregate limit is valid");
    }
}

fn manifest(control: FuzzControl) -> CapabilityManifest {
    let mut grant = CapabilityGrant::json("fuzz.policy");
    for (selected, kind, id) in [
        (control.select_readonly, ResourceKind::FileRoot, "readonly"),
        (control.select_writable, ResourceKind::FileRoot, "writable"),
        (
            control.select_first_scratch,
            ResourceKind::FileRoot,
            "scratch-a",
        ),
        (
            control.select_second_scratch,
            ResourceKind::FileRoot,
            "scratch-b",
        ),
        (control.select_missing, ResourceKind::FileRoot, "missing"),
        (
            control.select_executable,
            ResourceKind::Executable,
            "fixed-worker",
        ),
        (
            control.select_network_origin,
            ResourceKind::NetworkOrigin,
            "service-api",
        ),
        (control.select_secret, ResourceKind::Secret, "service-key"),
    ] {
        if selected {
            grant.resources.insert(
                ResourceSelector::new(kind, id).expect("the fixed fuzz resource selector is valid"),
            );
        }
    }
    let grants = if control.select_active_file_root_limit_overflow {
        let mut limit_grant = CapabilityGrant::json("fuzz.limit");
        for index in 0..DEFAULT_MAX_BUBBLEWRAP_ACTIVE_FILE_ROOTS {
            limit_grant.resources.insert(
                ResourceSelector::new(ResourceKind::FileRoot, format!("limit-{index}"))
                    .expect("the fixed limit resource selector is valid"),
            );
        }
        grant.resources.insert(
            ResourceSelector::new(ResourceKind::FileRoot, "limit-last")
                .expect("the fixed limit resource selector is valid"),
        );
        vec![limit_grant, grant]
    } else {
        vec![grant]
    };
    CapabilityManifest::new("fuzz-session", grants)
        .expect("the fixed fuzz capability manifest is valid")
}

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or_default()
}

fn has_arguments(arguments: &[String], expected: &[&str]) -> bool {
    arguments.windows(expected.len()).any(|actual| {
        actual
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
    })
}
