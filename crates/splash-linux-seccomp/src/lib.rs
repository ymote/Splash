#![deny(unsafe_op_in_unsafe_fn)]

//! A deliberately small safe wrapper around Linux seccomp filter installation.
//!
//! The only unsafe operations in this crate are the Linux `prctl` and
//! `seccomp` syscall ABI calls. They are kept here so Splash's policy crate and
//! fixed pre-exec runners remain `#![forbid(unsafe_code)]`.

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{
    install_filter, validate_filter, SeccompInstallError, ValidatedFilter,
    FILTER_INSTRUCTION_BYTES, MAX_FILTER_INSTRUCTIONS,
};
