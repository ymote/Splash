#![cfg(target_os = "linux")]

use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use splash_protocol::{CapabilityGrant, CapabilityManifest};
use splash_sandbox::bubblewrap::{BubblewrapWorkerPolicy, ReadOnlyMount};
use splash_sandbox::cgroup_v2::{CgroupV2Limits, CgroupV2Policy};

static NEXT_TEST_CGROUP: AtomicUsize = AtomicUsize::new(1);

struct TestCgroupParent {
    path: PathBuf,
}

impl TestCgroupParent {
    fn create() -> io::Result<Self> {
        let root = Path::new("/sys/fs/cgroup");
        let controllers = fs::read_to_string(root.join("cgroup.controllers"))?;
        if !["cpu", "memory", "pids"].iter().all(|controller| {
            controllers
                .split_whitespace()
                .any(|item| item == *controller)
        }) {
            return Err(io::Error::other(
                "the cgroup-v2 root does not expose cpu, memory, and pids controllers",
            ));
        }

        let path = root.join(format!(
            "splash-cgroup-v2-integration-{}-{}",
            std::process::id(),
            NEXT_TEST_CGROUP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        if let Err(error) = fs::write(path.join("cgroup.subtree_control"), "+cpu +memory +pids\n") {
            let _ = fs::remove_dir(&path);
            return Err(error);
        }
        Ok(Self { path })
    }
}

impl Drop for TestCgroupParent {
    fn drop(&mut self) {
        let _ = fs::write(self.path.join("cgroup.kill"), "1\n");
        let _ = fs::remove_dir(&self.path);
    }
}

fn cgroup_contains(path: &Path, process_id: u32) -> bool {
    fs::read_to_string(path.join("cgroup.procs"))
        .unwrap()
        .lines()
        .any(|line| line.parse::<u32>().ok() == Some(process_id))
}

fn wait_until(maximum: Duration, condition: impl Fn() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(
            started.elapsed() < maximum,
            "condition was not met within {maximum:?}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn cgroup_limits() -> CgroupV2Limits {
    let mut limits = CgroupV2Limits::default();
    limits.set_cpu_quota_micros(20_000).unwrap();
    limits.set_memory_max_bytes(64 * 1024 * 1024).unwrap();
    limits.set_pids_max(32).unwrap();
    limits
}

fn cgroup_policy(parent: &TestCgroupParent) -> CgroupV2Policy {
    CgroupV2Policy::new(
        &parent.path,
        env!("CARGO_BIN_EXE_splash-cgroup-runner"),
        cgroup_limits(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires a writable delegated cgroup-v2 parent"]
fn applies_limits_before_exec_and_kills_the_runner_subtree() {
    let parent = TestCgroupParent::create().unwrap();
    let policy = cgroup_policy(&parent);
    let session = policy.prepare().unwrap();

    assert_eq!(
        fs::read_to_string(session.path().join("cpu.max"))
            .unwrap()
            .trim(),
        "20000 100000"
    );
    assert_eq!(
        fs::read_to_string(session.path().join("memory.max"))
            .unwrap()
            .trim(),
        "67108864"
    );
    assert_eq!(
        fs::read_to_string(session.path().join("pids.max"))
            .unwrap()
            .trim(),
        "32"
    );

    let mut worker = Command::new(env!("CARGO_BIN_EXE_splash-cgroup-runner"))
        .args([
            "--cgroup-procs",
            session.cgroup_procs_path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "sleep 60 & child=$!; printf '%s\\n' \"$child\"; wait \"$child\"",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let worker_process_id = worker.id();
    let mut worker_stdout = BufReader::new(worker.stdout.take().unwrap());
    let mut descendant_process_id = String::new();
    worker_stdout.read_line(&mut descendant_process_id).unwrap();
    let descendant_process_id = descendant_process_id.trim().parse::<u32>().unwrap();

    wait_until(Duration::from_secs(5), || {
        cgroup_contains(session.path(), worker_process_id)
            && cgroup_contains(session.path(), descendant_process_id)
    });

    session.kill().unwrap();
    assert!(!worker.wait().unwrap().success());
    wait_until(Duration::from_secs(5), || {
        fs::read_to_string(session.path().join("cgroup.procs"))
            .unwrap()
            .trim()
            .is_empty()
    });
    session.cleanup().unwrap();
}

#[test]
#[ignore = "requires Bubblewrap and a writable delegated cgroup-v2 parent"]
fn bubblewrap_launch_confirms_membership_and_lifecycle_removes_the_cgroup() {
    assert!(Path::new("/usr/bin/bwrap").exists());
    assert!(Path::new("/usr/bin/sleep").exists());
    let parent = TestCgroupParent::create().unwrap();
    let sleep = fs::canonicalize("/usr/bin/sleep").unwrap();
    let mut worker_policy = BubblewrapWorkerPolicy::new("/usr/bin/bwrap", sleep)
        .unwrap()
        .with_worker_arguments(["60"]);
    for path in ["/usr", "/lib", "/lib64"] {
        if Path::new(path).exists() {
            worker_policy.add_runtime_mount(ReadOnlyMount::new(path, path).unwrap());
        }
    }
    let manifest =
        CapabilityManifest::new("cgroup-v2-integration", vec![CapabilityGrant::json("tool")])
            .unwrap();
    let command = worker_policy.compile(&manifest).unwrap();
    let mut worker = command.spawn_in_cgroup(&cgroup_policy(&parent)).unwrap();
    let worker_process_id = worker.child_mut().id();
    let cgroup_path = fs::read_dir(&parent.path)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("cgroup.procs").exists())
        .unwrap();

    assert!(cgroup_contains(&cgroup_path, worker_process_id));
    let (mut lifecycle, stdin, stdout) = worker.into_lifecycle_parts();
    drop(stdin);
    drop(stdout);
    assert!(lifecycle.terminate().unwrap().was_killed());
    wait_until(Duration::from_secs(5), || !cgroup_path.exists());
}
