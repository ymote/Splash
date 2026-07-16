#![forbid(unsafe_code)]

//! Join one prepared cgroup-v2 child before replacing this process with Bubblewrap.
//!
//! This binary is selected only by trusted host launch policy. It is not a
//! script-facing cgroup manager: the parent creates and configures the cgroup,
//! then passes the exact `cgroup.procs` path and a fixed Bubblewrap command.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("splash-cgroup-runner is supported only on Linux");
    std::process::exit(64);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run(std::env::args_os().skip(1)) {
        eprintln!("splash-cgroup-runner: {error}");
        std::process::exit(error.exit_code());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::fmt::{self, Display, Formatter};
    use std::fs;
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::path::{Component, PathBuf};
    use std::process::Command;

    const EXIT_USAGE: i32 = 64;
    const EXIT_JOIN: i32 = 125;
    const EXIT_EXEC: i32 = 126;

    struct RunnerConfiguration {
        cgroup_procs: PathBuf,
        preserve_fds: Vec<i32>,
        command: OsString,
        arguments: Vec<OsString>,
    }

    impl RunnerConfiguration {
        fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, RunnerError> {
            let arguments = arguments.into_iter().collect::<Vec<_>>();
            let mut cgroup_procs = None;
            let mut preserve_fds = Vec::new();
            let mut index = 0;

            while let Some(argument) = arguments.get(index) {
                if argument == "--" {
                    let Some(command) = arguments.get(index + 1) else {
                        return Err(RunnerError::MissingCommand);
                    };
                    let cgroup_procs = cgroup_procs.ok_or(RunnerError::MissingCgroupProcs)?;
                    return Ok(Self {
                        cgroup_procs,
                        preserve_fds,
                        command: command.clone(),
                        arguments: arguments[index + 2..].to_vec(),
                    });
                }

                let option = argument.to_str().ok_or(RunnerError::InvalidOption)?;
                let Some(value) = arguments.get(index + 1) else {
                    return Err(RunnerError::MissingValue(option.to_owned()));
                };
                match option {
                    "--cgroup-procs" => {
                        let path = parse_cgroup_procs_path(value)?;
                        if cgroup_procs.replace(path).is_some() {
                            return Err(RunnerError::DuplicateOption(option.to_owned()));
                        }
                    }
                    "--preserve-fd" => {
                        let descriptor = parse_preserved_descriptor(value)?;
                        if preserve_fds.contains(&descriptor) {
                            return Err(RunnerError::DuplicatePreservedDescriptor(descriptor));
                        }
                        preserve_fds.push(descriptor);
                    }
                    _ => return Err(RunnerError::UnknownOption(option.to_owned())),
                }
                index += 2;
            }

            Err(RunnerError::MissingCommand)
        }
    }

    pub(super) fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), RunnerError> {
        let configuration = RunnerConfiguration::parse(arguments)?;
        fs::write(
            &configuration.cgroup_procs,
            format!("{}\n", std::process::id()),
        )
        .map_err(|source| RunnerError::Join {
            path: configuration.cgroup_procs.clone(),
            source,
        })?;
        mark_extra_file_descriptors_close_on_exec(&configuration.preserve_fds);
        let error = Command::new(configuration.command)
            .args(configuration.arguments)
            .exec();
        Err(RunnerError::Exec(error))
    }

    fn parse_cgroup_procs_path(value: &OsString) -> Result<PathBuf, RunnerError> {
        let path = PathBuf::from(value);
        if !path.is_absolute()
            || path.file_name() != Some(std::ffi::OsStr::new("cgroup.procs"))
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(RunnerError::InvalidCgroupProcsPath);
        }
        Ok(path)
    }

    fn parse_preserved_descriptor(value: &OsString) -> Result<i32, RunnerError> {
        let descriptor = value
            .to_str()
            .ok_or(RunnerError::InvalidPreservedDescriptor)?
            .parse::<i32>()
            .map_err(|_| RunnerError::InvalidPreservedDescriptor)?;
        if descriptor < 3 {
            return Err(RunnerError::InvalidPreservedDescriptor);
        }
        Ok(descriptor)
    }

    fn mark_extra_file_descriptors_close_on_exec(preserved: &[i32]) {
        // The runner has joined the cgroup and will perform no further file
        // descriptor operations before exec. Keep the optional seccomp program
        // descriptors for Bubblewrap and close every other nonstandard handle.
        close_fds::set_fds_cloexec(3, preserved);
    }

    #[derive(Debug)]
    pub(super) enum RunnerError {
        InvalidOption,
        UnknownOption(String),
        MissingValue(String),
        DuplicateOption(String),
        DuplicatePreservedDescriptor(i32),
        MissingCgroupProcs,
        InvalidCgroupProcsPath,
        InvalidPreservedDescriptor,
        MissingCommand,
        Join { path: PathBuf, source: io::Error },
        Exec(io::Error),
    }

    impl RunnerError {
        pub(super) fn exit_code(&self) -> i32 {
            match self {
                Self::InvalidOption
                | Self::UnknownOption(_)
                | Self::MissingValue(_)
                | Self::DuplicateOption(_)
                | Self::DuplicatePreservedDescriptor(_)
                | Self::MissingCgroupProcs
                | Self::InvalidCgroupProcsPath
                | Self::InvalidPreservedDescriptor
                | Self::MissingCommand => EXIT_USAGE,
                Self::Join { .. } => EXIT_JOIN,
                Self::Exec(_) => EXIT_EXEC,
            }
        }
    }

    impl Display for RunnerError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidOption => formatter.write_str("arguments must be valid UTF-8 options"),
                Self::UnknownOption(option) => write!(formatter, "unknown option {option}"),
                Self::MissingValue(option) => write!(formatter, "missing value for {option}"),
                Self::DuplicateOption(option) => write!(formatter, "duplicate option {option}"),
                Self::DuplicatePreservedDescriptor(descriptor) => {
                    write!(formatter, "duplicate preserved descriptor {descriptor}")
                }
                Self::MissingCgroupProcs => {
                    formatter.write_str("--cgroup-procs is required before the -- separator")
                }
                Self::InvalidCgroupProcsPath => formatter.write_str(
                    "--cgroup-procs must be an absolute normalized path ending in cgroup.procs",
                ),
                Self::InvalidPreservedDescriptor => {
                    formatter.write_str("--preserve-fd must be an integer file descriptor >= 3")
                }
                Self::MissingCommand => {
                    formatter.write_str("a command is required after the -- separator")
                }
                Self::Join { path, source } => write!(
                    formatter,
                    "could not join cgroup through {}: {source}",
                    path.display()
                ),
                Self::Exec(source) => write!(formatter, "could not execute Bubblewrap: {source}"),
            }
        }
    }

    impl std::error::Error for RunnerError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::Join { source, .. } | Self::Exec(source) => Some(source),
                Self::InvalidOption
                | Self::UnknownOption(_)
                | Self::MissingValue(_)
                | Self::DuplicateOption(_)
                | Self::DuplicatePreservedDescriptor(_)
                | Self::MissingCgroupProcs
                | Self::InvalidCgroupProcsPath
                | Self::InvalidPreservedDescriptor
                | Self::MissingCommand => None,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn arguments(values: &[&str]) -> Vec<OsString> {
            values.iter().map(OsString::from).collect()
        }

        #[test]
        fn parses_a_fixed_bubblewrap_command_with_preserved_descriptors() {
            let configuration = RunnerConfiguration::parse(arguments(&[
                "--cgroup-procs",
                "/sys/fs/cgroup/splash-1/cgroup.procs",
                "--preserve-fd",
                "9",
                "--preserve-fd",
                "11",
                "--",
                "/usr/bin/bwrap",
                "--unshare-all",
            ]))
            .unwrap();

            assert_eq!(
                configuration.cgroup_procs,
                std::path::Path::new("/sys/fs/cgroup/splash-1/cgroup.procs")
            );
            assert_eq!(configuration.preserve_fds, vec![9, 11]);
            assert_eq!(configuration.command, OsString::from("/usr/bin/bwrap"));
            assert_eq!(configuration.arguments, arguments(&["--unshare-all"]));
        }

        #[test]
        fn rejects_ambiguous_or_unsafe_runner_arguments() {
            for values in [
                arguments(&["--", "/usr/bin/bwrap"]),
                arguments(&[
                    "--cgroup-procs",
                    "/tmp/not-cgroup.procs",
                    "--",
                    "/usr/bin/bwrap",
                ]),
                arguments(&[
                    "--cgroup-procs",
                    "/sys/fs/cgroup/a/../cgroup.procs",
                    "--",
                    "/usr/bin/bwrap",
                ]),
                arguments(&[
                    "--cgroup-procs",
                    "/sys/fs/cgroup/a/cgroup.procs",
                    "--preserve-fd",
                    "2",
                    "--",
                    "/usr/bin/bwrap",
                ]),
                arguments(&[
                    "--cgroup-procs",
                    "/sys/fs/cgroup/a/cgroup.procs",
                    "--preserve-fd",
                    "9",
                    "--preserve-fd",
                    "9",
                    "--",
                    "/usr/bin/bwrap",
                ]),
            ] {
                assert!(RunnerConfiguration::parse(values).is_err());
            }
        }
    }
}
