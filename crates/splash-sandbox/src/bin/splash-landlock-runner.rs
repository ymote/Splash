#![forbid(unsafe_code)]

//! Apply a fixed Linux Landlock filesystem-backed executable allowlist before
//! replacing this process with a worker.
//!
//! This binary is selected only by trusted host launch policy inside a
//! contained runtime mount. It accepts exact absolute paths provided by the
//! host-side Bubblewrap compiler; it is not script-facing command parsing or
//! a general process, network, secret, or capability sandbox.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("splash-landlock-runner is supported only on Linux");
    std::process::exit(64);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run(std::env::args_os().skip(1)) {
        eprintln!("splash-landlock-runner: {error}");
        std::process::exit(error.exit_code());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::fmt::{self, Display, Formatter};
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::path::{Component, Path, PathBuf};
    use std::process::Command;

    use landlock::{
        AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus,
    };
    use rustix::fs::{fstat, open, FileType, Mode, OFlags};

    const EXIT_USAGE: i32 = 64;
    const EXIT_LANDLOCK: i32 = 125;
    const EXIT_EXEC: i32 = 126;
    const MAX_ALLOWED_EXECUTABLES: usize =
        splash_sandbox::bubblewrap::MAX_LANDLOCK_EXECUTABLE_RUNNER_EXECUTABLES;

    struct RunnerConfiguration {
        allowed_executables: BTreeSet<PathBuf>,
        command: PathBuf,
        arguments: Vec<OsString>,
    }

    impl RunnerConfiguration {
        fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, RunnerError> {
            let arguments = arguments.into_iter().collect::<Vec<_>>();
            let mut allowed_executables = BTreeSet::new();
            let mut index = 0;

            while let Some(argument) = arguments.get(index) {
                if argument == "--" {
                    let Some(command) = arguments.get(index + 1) else {
                        return Err(RunnerError::MissingCommand);
                    };
                    if allowed_executables.is_empty() {
                        return Err(RunnerError::MissingAllowedExecutable);
                    }
                    let command = parse_executable_path(command)?;
                    if !allowed_executables.contains(&command) {
                        return Err(RunnerError::CommandNotAllowed { command });
                    }
                    return Ok(Self {
                        allowed_executables,
                        command,
                        arguments: arguments[index + 2..].to_vec(),
                    });
                }

                let option = argument.to_str().ok_or(RunnerError::InvalidOption)?;
                let Some(value) = arguments.get(index + 1) else {
                    return Err(RunnerError::MissingValue(option.to_owned()));
                };
                if option != "--allow-exec" {
                    return Err(RunnerError::UnknownOption(option.to_owned()));
                }
                let executable = parse_executable_path(value)?;
                if !allowed_executables.insert(executable.clone()) {
                    return Err(RunnerError::DuplicateAllowedExecutable { executable });
                }
                if allowed_executables.len() > MAX_ALLOWED_EXECUTABLES {
                    return Err(RunnerError::TooManyAllowedExecutables {
                        maximum: MAX_ALLOWED_EXECUTABLES,
                    });
                }
                index += 2;
            }

            Err(RunnerError::MissingCommand)
        }
    }

    pub(super) fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), RunnerError> {
        let configuration = RunnerConfiguration::parse(arguments)?;
        install_executable_allowlist(&configuration.allowed_executables)?;
        mark_extra_file_descriptors_close_on_exec();
        let error = Command::new(configuration.command)
            .args(configuration.arguments)
            .exec();
        Err(RunnerError::Exec(error))
    }

    fn parse_executable_path(value: &OsString) -> Result<PathBuf, RunnerError> {
        let path = PathBuf::from(value);
        if !path.is_absolute()
            || path == Path::new("/")
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(RunnerError::InvalidExecutablePath);
        }
        Ok(path)
    }

    fn install_executable_allowlist(
        allowed_executables: &BTreeSet<PathBuf>,
    ) -> Result<(), RunnerError> {
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::Execute)
            .map_err(RunnerError::Landlock)?
            .create()
            .map_err(RunnerError::Landlock)?;

        for executable in allowed_executables {
            let descriptor = open_allowed_executable(executable)?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(descriptor, AccessFs::Execute))
                .map_err(RunnerError::Landlock)?;
        }

        let status = ruleset.restrict_self().map_err(RunnerError::Landlock)?;
        if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
            return Err(RunnerError::LandlockNotFullyEnforced);
        }
        Ok(())
    }

    fn open_allowed_executable(path: &Path) -> Result<std::os::fd::OwnedFd, RunnerError> {
        // Keep the descriptor tied to the rule. O_PATH and O_NOFOLLOW make the
        // final component race-free and reject a symlink or directory instead
        // of granting its descendants executable authority.
        let descriptor = open(
            path,
            OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| RunnerError::InspectAllowedExecutable {
            path: path.to_path_buf(),
            source,
        })?;
        let metadata =
            fstat(&descriptor).map_err(|source| RunnerError::InspectAllowedExecutable {
                path: path.to_path_buf(),
                source,
            })?;
        if !FileType::from_raw_mode(metadata.st_mode).is_file() {
            return Err(RunnerError::AllowedExecutableNotRegular {
                path: path.to_path_buf(),
            });
        }
        if !Mode::from_raw_mode(metadata.st_mode).intersects(Mode::XUSR | Mode::XGRP | Mode::XOTH) {
            return Err(RunnerError::AllowedExecutableNotExecutable {
                path: path.to_path_buf(),
            });
        }
        Ok(descriptor)
    }

    fn mark_extra_file_descriptors_close_on_exec() {
        // The Landlock ruleset is already installed and rule descriptors are
        // no longer needed. Preserve protocol stdio only, so a worker cannot
        // inherit host descriptors or the allowlist's file descriptors.
        close_fds::set_fds_cloexec(3, &[]);
    }

    #[derive(Debug)]
    pub(super) enum RunnerError {
        InvalidOption,
        UnknownOption(String),
        MissingValue(String),
        DuplicateAllowedExecutable {
            executable: PathBuf,
        },
        TooManyAllowedExecutables {
            maximum: usize,
        },
        MissingAllowedExecutable,
        MissingCommand,
        InvalidExecutablePath,
        CommandNotAllowed {
            command: PathBuf,
        },
        InspectAllowedExecutable {
            path: PathBuf,
            source: rustix::io::Errno,
        },
        AllowedExecutableNotRegular {
            path: PathBuf,
        },
        AllowedExecutableNotExecutable {
            path: PathBuf,
        },
        Landlock(landlock::RulesetError),
        LandlockNotFullyEnforced,
        Exec(io::Error),
    }

    impl RunnerError {
        pub(super) fn exit_code(&self) -> i32 {
            match self {
                Self::InvalidOption
                | Self::UnknownOption(_)
                | Self::MissingValue(_)
                | Self::DuplicateAllowedExecutable { .. }
                | Self::TooManyAllowedExecutables { .. }
                | Self::MissingAllowedExecutable
                | Self::MissingCommand
                | Self::InvalidExecutablePath
                | Self::CommandNotAllowed { .. } => EXIT_USAGE,
                Self::InspectAllowedExecutable { .. }
                | Self::AllowedExecutableNotRegular { .. }
                | Self::AllowedExecutableNotExecutable { .. }
                | Self::Landlock(_)
                | Self::LandlockNotFullyEnforced => EXIT_LANDLOCK,
                Self::Exec(_) => EXIT_EXEC,
            }
        }
    }

    impl Display for RunnerError {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidOption => formatter.write_str("arguments must use valid UTF-8 option names"),
                Self::UnknownOption(option) => write!(formatter, "unknown option {option}"),
                Self::MissingValue(option) => write!(formatter, "missing value for {option}"),
                Self::DuplicateAllowedExecutable { executable } => write!(
                    formatter,
                    "duplicate --allow-exec path {}",
                    executable.display()
                ),
                Self::TooManyAllowedExecutables { maximum } => write!(
                    formatter,
                    "--allow-exec supports at most {maximum} paths"
                ),
                Self::MissingAllowedExecutable => {
                    formatter.write_str("at least one --allow-exec path is required")
                }
                Self::MissingCommand => {
                    formatter.write_str("a command is required after the -- separator")
                }
                Self::InvalidExecutablePath => formatter.write_str(
                    "--allow-exec paths and the command must be absolute normalized paths",
                ),
                Self::CommandNotAllowed { command } => write!(
                    formatter,
                    "command {} is not listed by --allow-exec",
                    command.display()
                ),
                Self::InspectAllowedExecutable { path, source } => write!(
                    formatter,
                    "could not inspect allowed executable {}: {source}",
                    path.display()
                ),
                Self::AllowedExecutableNotRegular { path } => write!(
                    formatter,
                    "allowed executable {} must be a regular non-symlink file",
                    path.display()
                ),
                Self::AllowedExecutableNotExecutable { path } => write!(
                    formatter,
                    "allowed executable {} must have an execute permission bit",
                    path.display()
                ),
                Self::Landlock(source) => {
                    write!(formatter, "could not install Landlock executable policy: {source}")
                }
                Self::LandlockNotFullyEnforced => formatter.write_str(
                    "Landlock executable policy was not fully enforced; refusing to start the worker",
                ),
                Self::Exec(source) => write!(formatter, "could not execute allowed worker: {source}"),
            }
        }
    }

    impl std::error::Error for RunnerError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::InspectAllowedExecutable { source, .. } => Some(source),
                Self::Landlock(source) => Some(source),
                Self::Exec(source) => Some(source),
                Self::InvalidOption
                | Self::UnknownOption(_)
                | Self::MissingValue(_)
                | Self::DuplicateAllowedExecutable { .. }
                | Self::TooManyAllowedExecutables { .. }
                | Self::MissingAllowedExecutable
                | Self::MissingCommand
                | Self::InvalidExecutablePath
                | Self::CommandNotAllowed { .. }
                | Self::AllowedExecutableNotRegular { .. }
                | Self::AllowedExecutableNotExecutable { .. }
                | Self::LandlockNotFullyEnforced => None,
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
        fn parses_a_fixed_command_with_a_deterministic_allowlist() {
            let configuration = RunnerConfiguration::parse(arguments(&[
                "--allow-exec",
                "/opt/splash/worker",
                "--allow-exec",
                "/opt/splash/limit-runner",
                "--",
                "/opt/splash/limit-runner",
                "--open-files",
                "16",
                "--",
                "/opt/splash/worker",
            ]))
            .unwrap();

            assert_eq!(
                configuration.allowed_executables,
                BTreeSet::from([
                    PathBuf::from("/opt/splash/limit-runner"),
                    PathBuf::from("/opt/splash/worker"),
                ])
            );
            assert_eq!(configuration.command, Path::new("/opt/splash/limit-runner"));
            assert_eq!(
                configuration.arguments,
                arguments(&["--open-files", "16", "--", "/opt/splash/worker"])
            );
        }

        #[test]
        fn rejects_ambiguous_or_untrusted_execution_targets() {
            assert!(matches!(
                RunnerConfiguration::parse(arguments(&[
                    "--allow-exec",
                    "/opt/splash/worker",
                    "--allow-exec",
                    "/opt/splash/worker",
                    "--",
                    "/opt/splash/worker",
                ])),
                Err(RunnerError::DuplicateAllowedExecutable { executable })
                    if executable == Path::new("/opt/splash/worker")
            ));
            assert!(matches!(
                RunnerConfiguration::parse(arguments(&[
                    "--allow-exec",
                    "/opt/splash/worker",
                    "--",
                    "/opt/splash/other-worker",
                ])),
                Err(RunnerError::CommandNotAllowed { command })
                    if command == Path::new("/opt/splash/other-worker")
            ));
            assert!(matches!(
                RunnerConfiguration::parse(arguments(&[
                    "--allow-exec",
                    "/opt/splash/worker",
                    "--",
                    "./worker",
                ])),
                Err(RunnerError::InvalidExecutablePath)
            ));
            assert!(matches!(
                RunnerConfiguration::parse(arguments(&[
                    "--allow-exec",
                    "/opt/splash/../worker",
                    "--",
                    "/opt/splash/worker",
                ])),
                Err(RunnerError::InvalidExecutablePath)
            ));
        }

        #[test]
        fn bounds_the_complete_allowlist() {
            let mut values = Vec::new();
            for index in 0..=MAX_ALLOWED_EXECUTABLES {
                values.push(OsString::from("--allow-exec"));
                values.push(OsString::from(format!("/opt/splash/program-{index}")));
            }
            values.push(OsString::from("--"));
            values.push(OsString::from("/opt/splash/program-0"));

            assert!(matches!(
                RunnerConfiguration::parse(values),
                Err(RunnerError::TooManyAllowedExecutables { maximum })
                    if maximum == MAX_ALLOWED_EXECUTABLES
            ));
        }
    }
}
