#![cfg(target_os = "linux")]

use std::io::Read;
use std::path::Path;

use splash_protocol::{CapabilityGrant, CapabilityManifest};
use splash_sandbox::bubblewrap::{BubblewrapWorkerPolicy, ReadOnlyMount, WorkerSeccompProfile};

#[test]
fn bubblewrap_attaches_the_host_owned_seccomp_filter_before_worker_exec() {
    let python = std::fs::canonicalize("/usr/bin/python3").unwrap();
    let mut policy = BubblewrapWorkerPolicy::new("/usr/bin/bwrap", python)
        .unwrap()
        .with_worker_arguments(["-c", worker_script()]);
    policy.add_runtime_mount(ReadOnlyMount::new("/usr", "/usr").unwrap());
    add_runtime_library_mounts(&mut policy);
    policy.set_seccomp_profile(WorkerSeccompProfile::DenyKnownEscapeSurface);

    let manifest =
        CapabilityManifest::new("seccomp-integration", vec![CapabilityGrant::json("tool")])
            .unwrap();
    let worker = policy.compile(&manifest).unwrap().spawn().unwrap();
    let (mut child, stdin, mut stdout) = worker.into_parts();
    drop(stdin);

    let mut output = String::new();
    stdout.read_to_string(&mut output).unwrap();
    let status = child.wait().unwrap();

    assert!(
        status.success(),
        "worker failed: {status}; stdout: {output:?}"
    );
    assert_eq!(output, "seccomp-active\n");
}

fn add_runtime_library_mounts(policy: &mut BubblewrapWorkerPolicy) {
    for path in ["/lib", "/lib64"] {
        if Path::new(path).exists() {
            policy.add_runtime_mount(ReadOnlyMount::new(path, path).unwrap());
        }
    }
}

fn worker_script() -> &'static str {
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
# cBPF bytes. stdin/stdout/stderr are a pipe, pipe, and /dev/null respectively,
# so any remaining socket descriptor would be unexpected worker authority.
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
