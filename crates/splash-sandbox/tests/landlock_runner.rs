#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn landlock_runner() -> &'static str {
    env!("CARGO_BIN_EXE_splash-landlock-runner")
}

fn cgroup_runner() -> PathBuf {
    fs::canonicalize(env!("CARGO_BIN_EXE_splash-cgroup-runner")).unwrap()
}

fn limit_runner() -> PathBuf {
    fs::canonicalize(env!("CARGO_BIN_EXE_splash-limit-runner")).unwrap()
}

fn dynamic_loader() -> Option<PathBuf> {
    fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .filter(|path| Path::new(path).is_absolute())
        .find_map(|path| {
            let file_name = Path::new(path).file_name()?.to_str()?;
            (file_name.starts_with("ld-linux") || file_name.starts_with("ld-musl"))
                .then(|| fs::canonicalize(path).ok())
                .flatten()
        })
}

fn invoke_allowing(target: &Path, arguments: &[&str]) -> Output {
    let mut command = Command::new(landlock_runner());
    command.arg("--allow-exec").arg(target);
    if let Some(loader) = dynamic_loader() {
        command.arg("--allow-exec").arg(loader);
    }
    command
        .arg("--")
        .arg(target)
        .args(arguments)
        .output()
        .unwrap()
}

fn landlock_is_available() -> bool {
    // The fixed cgroup runner immediately reports invalid usage after the
    // Landlock runner has successfully replaced itself. A 125 status instead
    // proves that this host cannot provide the hard-required Landlock layer.
    let output = invoke_allowing(&cgroup_runner(), &[]);
    match output.status.code() {
        Some(64) => true,
        Some(125) => false,
        status => panic!("unexpected Landlock probe result {status:?}: {output:?}"),
    }
}

#[test]
fn invalid_allowlist_configuration_prevents_target_execution() {
    let output = Command::new(landlock_runner())
        .args(["--", "/bin/sh", "-c", "exit 42"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(64), "{output:?}");
}

#[test]
fn only_an_explicitly_allowed_program_can_be_executed() {
    if !landlock_is_available() {
        return;
    }

    let limit_runner = limit_runner();
    let output = invoke_allowing(&limit_runner, &["--open-files", "16", "--", "/bin/true"]);

    // splash-limit-runner (and, when dynamically linked, its ELF loader) was
    // allowlisted and started, but its unlisted /bin/true target must be
    // denied by the inherited Landlock layer.
    assert_eq!(output.status.code(), Some(126), "{output:?}");
}

#[test]
fn command_must_be_one_of_the_exact_allowed_paths() {
    let allowed = cgroup_runner();
    let output = Command::new(landlock_runner())
        .arg("--allow-exec")
        .arg(&allowed)
        .args(["--", "/bin/true"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(64), "{output:?}");
}
