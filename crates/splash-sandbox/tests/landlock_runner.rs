#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use linux_raw_sys::ptrace;

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

fn allow_all_filter_hex() -> String {
    let code = (ptrace::BPF_RET | ptrace::BPF_K) as u16;
    let mut bytes = [0_u8; 8];
    bytes[..2].copy_from_slice(&code.to_ne_bytes());
    bytes[4..].copy_from_slice(&ptrace::SECCOMP_RET_ALLOW.to_ne_bytes());
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn status_field<'a>(status: &'a str, field: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| *name == field)
            .map(|(_, value)| value.trim())
    })
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

#[test]
fn staged_filter_is_installed_after_landlock_and_persists_to_the_fixed_target() {
    if !landlock_is_available() {
        return;
    }

    let shell = fs::canonicalize("/bin/sh").unwrap();
    let host_status = fs::read_to_string("/proc/self/status").unwrap();
    let host_filter_count = status_field(&host_status, "Seccomp_filters")
        .expect("Linux status must report a seccomp filter count")
        .parse::<u32>()
        .unwrap();

    let mut command = Command::new(landlock_runner());
    command
        .arg("--strict-seccomp-filter-hex")
        .arg(allow_all_filter_hex())
        .arg("--allow-exec")
        .arg(&shell);
    if let Some(loader) = dynamic_loader() {
        command.arg("--allow-exec").arg(loader);
    }
    let output = command
        .arg("--")
        .arg(&shell)
        .args([
            "-c",
            "while IFS=: read -r name value; do if [ \"$name\" = Seccomp_filters ]; then printf '%s\\n' \"$value\"; exit 0; fi; done < /proc/self/status; exit 1",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let target_filter_count = String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    assert_eq!(target_filter_count, host_filter_count + 1);
}
