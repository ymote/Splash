#![deny(unsafe_op_in_unsafe_fn)]

//! A deliberately small safe wrapper around Linux project-quota inspection.
//!
//! The only unsafe operations in this crate are the kernel's documented
//! `FS_IOC_FSGETXATTR` and `quotactl_fd` ABI calls. They are kept here so the
//! rest of Splash, including its containment policy crate, remains
//! `#![forbid(unsafe_code)]`.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{inspect_project_quota, ProjectQuotaError, ProjectQuotaStatus};
