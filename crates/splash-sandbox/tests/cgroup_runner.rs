#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustix::io::{fcntl_setfd, FdFlags};

static NEXT_TEST_DIRECTORY: AtomicUsize = AtomicUsize::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "splash-cgroup-runner-test-{}-{}",
            std::process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn cgroup_procs_path(&self) -> PathBuf {
        self.0.join("cgroup.procs")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn prepare_cgroup_procs_path(directory: &TestDirectory) -> PathBuf {
    let path = directory.cgroup_procs_path();
    File::create(&path).unwrap();
    path
}

fn runner() -> Command {
    Command::new(env!("CARGO_BIN_EXE_splash-cgroup-runner"))
}

#[test]
fn joins_the_cgroup_before_executing_the_target() {
    let directory = TestDirectory::new();
    let cgroup_procs = prepare_cgroup_procs_path(&directory);
    let output = runner()
        .args([
            "--cgroup-procs",
            cgroup_procs.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "printf '%s\\n' \"$$\"",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(cgroup_procs).unwrap().trim(),
        String::from_utf8(output.stdout).unwrap().trim()
    );
}

#[test]
fn preserves_only_the_requested_nonstandard_descriptor() {
    let directory = TestDirectory::new();
    let cgroup_procs = prepare_cgroup_procs_path(&directory);
    let preserved = File::open("/dev/null").unwrap();
    let discarded = File::open("/dev/null").unwrap();
    fcntl_setfd(&preserved, FdFlags::empty()).unwrap();
    fcntl_setfd(&discarded, FdFlags::empty()).unwrap();
    let preserved_descriptor = preserved.as_raw_fd().to_string();
    let discarded_descriptor = discarded.as_raw_fd().to_string();

    let output = runner()
        .args([
            "--cgroup-procs",
            cgroup_procs.to_str().unwrap(),
            "--preserve-fd",
            &preserved_descriptor,
            "--",
            "/bin/sh",
            "-c",
            "test -e /proc/self/fd/$1 && test ! -e /proc/self/fd/$2",
            "sh",
            &preserved_descriptor,
            &discarded_descriptor,
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
}

#[test]
fn refuses_an_invalid_cgroup_path_before_executing_the_target() {
    let output = runner()
        .args([
            "--cgroup-procs",
            Path::new("/tmp/not-a-cgroup-control").to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "exit 42",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(64), "{output:?}");
}
