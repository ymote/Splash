use std::fmt::{self, Display, Formatter};
use std::io;

use linux_raw_sys::{prctl, ptrace};

/// Linux's documented maximum number of classic BPF instructions in one
/// seccomp filter program.
pub const MAX_FILTER_INSTRUCTIONS: usize = 4_096;

/// The fixed Linux UAPI size of one classic BPF instruction.
pub const FILTER_INSTRUCTION_BYTES: usize = 8;

const _: [(); FILTER_INSTRUCTION_BYTES] = [(); std::mem::size_of::<ptrace::sock_filter>()];

/// A bounded native-endian Linux cBPF program that is safe to pass to the
/// `seccomp` syscall.
///
/// Construct this only with [`validate_filter`]. The filter's policy is still
/// defined by its caller; kernel verification remains authoritative for BPF
/// control-flow and return-action validity.
#[derive(Clone, Debug)]
pub struct ValidatedFilter {
    instructions: Vec<ptrace::sock_filter>,
}

impl ValidatedFilter {
    /// Returns the number of cBPF instructions in this program.
    pub const fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns whether the program contains no instructions.
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

/// Validates the byte framing required by Linux's `sock_fprog` ABI.
///
/// Bytes use the target's native endianness, matching the `sock_filter`
/// records emitted by Splash's target-specific compiler. This function does
/// not claim that the program is semantically safe or kernel-verifiable; the
/// kernel verifies that when [`install_filter`] is called.
pub fn validate_filter(bytes: &[u8]) -> Result<ValidatedFilter, SeccompInstallError> {
    if bytes.is_empty() {
        return Err(SeccompInstallError::EmptyFilter);
    }
    if !bytes.len().is_multiple_of(FILTER_INSTRUCTION_BYTES) {
        return Err(SeccompInstallError::PartialInstruction { bytes: bytes.len() });
    }

    let instruction_count = bytes.len() / FILTER_INSTRUCTION_BYTES;
    if instruction_count > MAX_FILTER_INSTRUCTIONS {
        return Err(SeccompInstallError::TooManyInstructions {
            instructions: instruction_count,
        });
    }

    let mut instructions = Vec::with_capacity(instruction_count);
    for instruction in bytes.chunks_exact(FILTER_INSTRUCTION_BYTES) {
        instructions.push(ptrace::sock_filter {
            code: u16::from_ne_bytes([instruction[0], instruction[1]]),
            jt: instruction[2],
            jf: instruction[3],
            k: u32::from_ne_bytes([
                instruction[4],
                instruction[5],
                instruction[6],
                instruction[7],
            ]),
        });
    }

    Ok(ValidatedFilter { instructions })
}

/// Sets `no_new_privs` and installs `filter` for the current thread.
///
/// The new filter persists across the next `execve` and can only be combined
/// with further restrictions. Callers must perform every required setup action
/// before this call, because a strict filter may intentionally deny all later
/// setup syscalls. An error means the caller must not execute an unrestricted
/// target as a fallback.
pub fn install_filter(filter: &ValidatedFilter) -> Result<(), SeccompInstallError> {
    let instruction_count = u16::try_from(filter.instructions.len())
        .expect("validated seccomp filter instruction count fits Linux sock_fprog");
    let program = ptrace::sock_fprog {
        len: instruction_count,
        filter: filter.instructions.as_ptr().cast_mut(),
    };

    // SAFETY: The option and four scalar arguments match the documented Linux
    // `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` ABI. No pointer is passed and
    // setting this irreversible flag only removes privilege gain paths.
    let no_new_privs = unsafe {
        libc::prctl(
            prctl::PR_SET_NO_NEW_PRIVS as libc::c_int,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if no_new_privs == -1 {
        return Err(SeccompInstallError::SetNoNewPrivs(
            io::Error::last_os_error(),
        ));
    }

    // SAFETY: `program` is a live stack value during the syscall, its
    // `filter` pointer refers to the owned, nonempty, ABI-sized instruction
    // vector in `filter`, and `len` was bounded to Linux's documented cBPF
    // maximum before construction. The kernel reads this data during the call
    // and does not retain the caller pointer after returning.
    let installed = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            ptrace::SECCOMP_SET_MODE_FILTER as libc::c_ulong,
            0 as libc::c_ulong,
            std::ptr::addr_of!(program),
        )
    };
    if installed == -1 {
        return Err(SeccompInstallError::InstallFilter(
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Failure while validating or installing a Linux seccomp filter.
#[derive(Debug)]
pub enum SeccompInstallError {
    EmptyFilter,
    PartialInstruction { bytes: usize },
    TooManyInstructions { instructions: usize },
    SetNoNewPrivs(io::Error),
    InstallFilter(io::Error),
}

impl Display for SeccompInstallError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFilter => formatter.write_str("a Linux seccomp filter must not be empty"),
            Self::PartialInstruction { bytes } => write!(
                formatter,
                "Linux seccomp filter has {bytes} bytes, not whole 8-byte cBPF instructions"
            ),
            Self::TooManyInstructions { instructions } => write!(
                formatter,
                "Linux seccomp filter has {instructions} instructions, exceeding the 4096-instruction limit"
            ),
            Self::SetNoNewPrivs(error) => {
                write!(formatter, "could not set Linux no_new_privs: {error}")
            }
            Self::InstallFilter(error) => {
                write!(formatter, "could not install Linux seccomp filter: {error}")
            }
        }
    }
}

impl std::error::Error for SeccompInstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SetNoNewPrivs(error) | Self::InstallFilter(error) => Some(error),
            Self::EmptyFilter
            | Self::PartialInstruction { .. }
            | Self::TooManyInstructions { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const INSTALL_HELPER_ENV: &str = "SPLASH_LINUX_SECCOMP_INSTALL_HELPER";
    const BPF_RET_K: u16 = (ptrace::BPF_RET | ptrace::BPF_K) as u16;

    fn allow_all_program() -> [u8; FILTER_INSTRUCTION_BYTES] {
        let mut program = [0_u8; FILTER_INSTRUCTION_BYTES];
        program[..2].copy_from_slice(&BPF_RET_K.to_ne_bytes());
        program[4..].copy_from_slice(&ptrace::SECCOMP_RET_ALLOW.to_ne_bytes());
        program
    }

    #[test]
    fn validates_the_linux_sock_filter_wire_shape() {
        let filter = validate_filter(&allow_all_program()).unwrap();
        assert_eq!(filter.len(), 1);
        assert!(!filter.is_empty());
        assert!(matches!(
            validate_filter(&[]),
            Err(SeccompInstallError::EmptyFilter)
        ));
        assert!(matches!(
            validate_filter(&[0; FILTER_INSTRUCTION_BYTES - 1]),
            Err(SeccompInstallError::PartialInstruction { .. })
        ));
        assert!(matches!(
            validate_filter(&vec![0; (MAX_FILTER_INSTRUCTIONS + 1) * FILTER_INSTRUCTION_BYTES]),
            Err(SeccompInstallError::TooManyInstructions { instructions })
                if instructions == MAX_FILTER_INSTRUCTIONS + 1
        ));
    }

    #[test]
    fn installs_a_kernel_verified_filter_in_a_child_process() {
        if std::env::var_os(INSTALL_HELPER_ENV).is_some() {
            let filter = validate_filter(&allow_all_program()).unwrap();
            install_filter(&filter).unwrap();
            // SAFETY: PR_GET_SECCOMP takes no pointer arguments and returns
            // the current process's seccomp mode without changing state.
            let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(mode, 2, "the kernel did not enter seccomp filter mode");
            return;
        }

        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("linux::tests::installs_a_kernel_verified_filter_in_a_child_process")
            .arg("--nocapture")
            .env(INSTALL_HELPER_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
