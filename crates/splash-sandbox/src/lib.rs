#![forbid(unsafe_code)]

//! Platform containment policies for Splash workers.
//!
//! The portable protocol and worker runtime intentionally do not create a
//! security boundary. This crate owns platform-specific launch policy, starting
//! with a Linux Bubblewrap backend that accepts only trusted host configuration.
//! It never turns Splash source, a resource selector, or a tool payload into an
//! executable path, mount path, network policy, or session key.

pub mod bubblewrap;
pub mod cgroup_v2;
