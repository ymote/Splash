#![cfg(target_os = "linux")]

use std::env;
use std::path::PathBuf;

use splash_protocol::{CapabilityGrant, CapabilityManifest, ResourceKind, ResourceSelector};
use splash_sandbox::bubblewrap::{
    BubblewrapWorkerPolicy, FileRootAccess, FileRootBinding, LinuxProjectQuota, ReadOnlyMount,
};

const ROOT_ENV: &str = "SPLASH_PROJECT_QUOTA_TEST_ROOT";
const PROJECT_ID_ENV: &str = "SPLASH_PROJECT_QUOTA_TEST_ID";
const MAXIMUM_BYTES_ENV: &str = "SPLASH_PROJECT_QUOTA_TEST_MAXIMUM_BYTES";
const MAXIMUM_INODES_ENV: &str = "SPLASH_PROJECT_QUOTA_TEST_MAXIMUM_INODES";

#[test]
#[ignore = "requires a host-provisioned Linux generic project-quota directory"]
fn compiles_a_verified_project_quota_root() {
    let root = required_path(ROOT_ENV);
    let project_id = required_u32(PROJECT_ID_ENV);
    let maximum_bytes = required_u64(MAXIMUM_BYTES_ENV);
    let maximum_inodes = required_u64(MAXIMUM_INODES_ENV);

    let quota = LinuxProjectQuota::new(project_id, maximum_bytes, maximum_inodes).unwrap();
    let mut policy = BubblewrapWorkerPolicy::new("/bin/true", "/runtime/true").unwrap();
    policy.add_runtime_mount(ReadOnlyMount::new("/bin", "/runtime").unwrap());
    policy.pin_mount_sources();
    policy.require_no_further_user_namespaces();
    policy
        .set_maximum_aggregate_linux_project_quota(maximum_bytes, maximum_inodes)
        .unwrap();
    policy
        .add_file_root(
            "output",
            FileRootBinding::new(root, "/workspace/output", FileRootAccess::ReadWrite)
                .unwrap()
                .with_linux_project_quota(quota),
        )
        .unwrap();

    assert!(policy.compile(&output_manifest()).is_ok());
}

fn required_path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{name} must name a host-provisioned project-quota root"))
}

fn required_u32(name: &str) -> u32 {
    env::var(name)
        .unwrap_or_else(|_| panic!("{name} must contain the provisioned project ID"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must contain a valid u32"))
}

fn required_u64(name: &str) -> u64 {
    env::var(name)
        .unwrap_or_else(|_| panic!("{name} must contain a provisioned quota limit"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must contain a valid u64"))
}

fn output_manifest() -> CapabilityManifest {
    let mut grant = CapabilityGrant::json("quota-test");
    grant
        .resources
        .insert(ResourceSelector::new(ResourceKind::FileRoot, "output").unwrap());
    CapabilityManifest::new("linux-project-quota-test", vec![grant]).unwrap()
}
