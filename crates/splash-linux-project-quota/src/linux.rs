use std::fmt::{self, Display, Formatter};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use linux_raw_sys::{general, ioctl};

const PROJECT_QUOTA_TYPE: u32 = 2;
const QUOTA_BLOCK_BYTES: u64 = 1 << 10;
const PROJECT_GET_QUOTA_COMMAND: libc::c_uint =
    ((libc::Q_GETQUOTA as u32) << 8) | PROJECT_QUOTA_TYPE;

/// Kernel-reported project quota status for one directory.
///
/// The hard byte limit is converted from the Linux quota ABI's 1 KiB block
/// units. A zero hard limit means the filesystem does not enforce a limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectQuotaStatus {
    project_id: u32,
    project_inheritance: bool,
    hard_limit_bytes: u64,
    current_bytes: u64,
    hard_limit_inodes: u64,
    current_inodes: u64,
}

impl ProjectQuotaStatus {
    /// Returns the directory's filesystem project ID.
    pub const fn project_id(self) -> u32 {
        self.project_id
    }

    /// Returns whether newly created descendants inherit this project ID.
    pub const fn project_inheritance(self) -> bool {
        self.project_inheritance
    }

    /// Returns the kernel-enforced hard disk-allocation limit in bytes.
    pub const fn hard_limit_bytes(self) -> u64 {
        self.hard_limit_bytes
    }

    /// Returns current quota-accounted disk usage in bytes.
    pub const fn current_bytes(self) -> u64 {
        self.current_bytes
    }

    /// Returns the kernel-enforced hard allocated-inode limit.
    pub const fn hard_limit_inodes(self) -> u64 {
        self.hard_limit_inodes
    }

    /// Returns the current quota-accounted allocated-inode count.
    pub const fn current_inodes(self) -> u64 {
        self.current_inodes
    }
}

/// Failure while querying a Linux directory's project quota.
#[derive(Debug)]
pub enum ProjectQuotaError {
    ReadAttributes(io::Error),
    ReadQuota(io::Error),
    IncompleteQuotaLimits { valid: u32 },
    BlockLimitOverflow { blocks: u64 },
}

impl Display for ProjectQuotaError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadAttributes(error) => {
                write!(formatter, "could not inspect Linux project attributes: {error}")
            }
            Self::ReadQuota(error) => write!(formatter, "could not inspect Linux project quota: {error}"),
            Self::IncompleteQuotaLimits { valid } => write!(
                formatter,
                "Linux project quota did not report hard limits and current usage (valid bits {valid:#x})"
            ),
            Self::BlockLimitOverflow { blocks } => write!(
                formatter,
                "Linux project quota block limit {blocks} cannot be represented in bytes"
            ),
        }
    }
}

impl std::error::Error for ProjectQuotaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadAttributes(error) | Self::ReadQuota(error) => Some(error),
            Self::IncompleteQuotaLimits { .. } | Self::BlockLimitOverflow { .. } => None,
        }
    }
}

/// Inspects the exact filesystem directory referred to by `directory`.
///
/// The kernel must support `FS_IOC_FSGETXATTR`, project quotas, and the Linux
/// 5.14 `quotactl_fd` syscall. This function changes no quota state. A caller
/// must reject a missing project-inheritance flag, an unlimited hard limit, or
/// any limit that exceeds its containment policy.
pub fn inspect_project_quota<Fd: AsFd>(
    directory: Fd,
) -> Result<ProjectQuotaStatus, ProjectQuotaError> {
    let directory = directory.as_fd();
    let attributes = read_attributes(directory)?;
    let quota = read_quota(directory, attributes.fsx_projid)?;
    let required = libc::QIF_BLIMITS | libc::QIF_ILIMITS | libc::QIF_SPACE | libc::QIF_INODES;
    if quota.dqb_valid & required != required {
        return Err(ProjectQuotaError::IncompleteQuotaLimits {
            valid: quota.dqb_valid,
        });
    }
    let hard_limit_bytes = quota.dqb_bhardlimit.checked_mul(QUOTA_BLOCK_BYTES).ok_or(
        ProjectQuotaError::BlockLimitOverflow {
            blocks: quota.dqb_bhardlimit,
        },
    )?;

    Ok(ProjectQuotaStatus {
        project_id: attributes.fsx_projid,
        project_inheritance: attributes.fsx_xflags & general::FS_XFLAG_PROJINHERIT != 0,
        hard_limit_bytes,
        current_bytes: quota.dqb_curspace,
        hard_limit_inodes: quota.dqb_ihardlimit,
        current_inodes: quota.dqb_curinodes,
    })
}

fn read_attributes(directory: BorrowedFd<'_>) -> Result<general::fsxattr, ProjectQuotaError> {
    let mut attributes = general::fsxattr {
        fsx_xflags: 0,
        fsx_extsize: 0,
        fsx_nextents: 0,
        fsx_projid: 0,
        fsx_cowextsize: 0,
        fsx_pad: [0; 8],
    };
    // SAFETY: `directory` is a live descriptor supplied through `AsFd`, the
    // request is the Linux UAPI's FS_IOC_FSGETXATTR opcode, and `attributes`
    // is a writable, correctly sized `fsxattr` value valid for this call.
    let result = unsafe {
        libc::ioctl(
            directory.as_raw_fd(),
            ioctl::FS_IOC_FSGETXATTR as libc::Ioctl,
            std::ptr::addr_of_mut!(attributes),
        )
    };
    if result == -1 {
        return Err(ProjectQuotaError::ReadAttributes(io::Error::last_os_error()));
    }
    Ok(attributes)
}

fn read_quota(
    directory: BorrowedFd<'_>,
    project_id: u32,
) -> Result<libc::dqblk, ProjectQuotaError> {
    let mut quota = libc::dqblk {
        dqb_bhardlimit: 0,
        dqb_bsoftlimit: 0,
        dqb_curspace: 0,
        dqb_ihardlimit: 0,
        dqb_isoftlimit: 0,
        dqb_curinodes: 0,
        dqb_btime: 0,
        dqb_itime: 0,
        dqb_valid: 0,
    };
    // SAFETY: `directory` is a live descriptor for the target filesystem,
    // PROJECT_GET_QUOTA_COMMAND is QCMD(Q_GETQUOTA, PRJQUOTA) from Linux's
    // UAPI, the project ID is passed in the syscall's `qid_t` slot, and
    // `quota` is a writable `dqblk` matching the kernel's documented output
    // ABI.
    let result = unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            directory.as_raw_fd(),
            PROJECT_GET_QUOTA_COMMAND,
            project_id as libc::c_uint,
            std::ptr::addr_of_mut!(quota),
        )
    };
    if result == -1 {
        return Err(ProjectQuotaError::ReadQuota(io::Error::last_os_error()));
    }
    Ok(quota)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_linux_project_get_quota_command() {
        assert_eq!(PROJECT_GET_QUOTA_COMMAND as u32, 0x8000_0702);
    }

    #[test]
    fn quota_block_conversion_is_checked() {
        assert_eq!(2_u64.checked_mul(QUOTA_BLOCK_BYTES), Some(2_048));
        assert_eq!(u64::MAX.checked_mul(QUOTA_BLOCK_BYTES), None);
    }
}
