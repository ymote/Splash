#![cfg(target_os = "linux")]

use std::fs::File;
use std::os::fd::AsRawFd;
use std::process::Command;

use rustix::io::{fcntl_setfd, FdFlags};

#[test]
fn applies_open_file_limit_before_executing_the_worker() {
    let output = Command::new(env!("CARGO_BIN_EXE_splash-limit-runner"))
        .args([
            "--open-files",
            "8",
            "--",
            "/bin/sh",
            "-c",
            "ulimit -Sn; ulimit -Hn; ulimit -c",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        ["8", "8", "0"]
    );
}

#[test]
fn invalid_limit_prevents_target_execution() {
    let output = Command::new(env!("CARGO_BIN_EXE_splash-limit-runner"))
        .args(["--open-files", "0", "--", "/bin/sh", "-c", "exit 42"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(64), "{output:?}");
}

#[test]
fn prevents_nonstandard_inherited_descriptors_reaching_the_worker() {
    let inherited = File::open("/dev/null").unwrap();
    fcntl_setfd(&inherited, FdFlags::empty()).unwrap();
    let inherited_fd = inherited.as_raw_fd().to_string();

    let output = Command::new(env!("CARGO_BIN_EXE_splash-limit-runner"))
        .args([
            "--open-files",
            "16",
            "--",
            "/bin/sh",
            "-c",
            "test ! -e /proc/self/fd/$1",
            "sh",
            &inherited_fd,
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
}
