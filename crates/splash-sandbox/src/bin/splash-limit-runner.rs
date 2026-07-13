#![forbid(unsafe_code)]

//! Apply fixed Linux rlimits before replacing this process with a worker.
//!
//! This binary is intended to be selected by trusted host launch policy inside
//! a contained runtime mount. It marks nonstandard inherited descriptors
//! close-on-exec before starting the worker. It is not a general sandbox or
//! command policy.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("splash-limit-runner is supported only on Linux");
    std::process::exit(64);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run(std::env::args_os().skip(1)) {
        eprintln!("splash-limit-runner: {error}");
        std::process::exit(error.exit_code());
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::fmt::{self, Display, Formatter};
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use rustix::process::{setrlimit, Resource, Rlimit};

    const EXIT_USAGE: i32 = 64;
    const EXIT_LIMIT: i32 = 125;
    const EXIT_EXEC: i32 = 126;

    #[derive(Default)]
    struct Limits {
        cpu_seconds: Option<u64>,
        address_space_bytes: Option<u64>,
        process_count: Option<u64>,
        open_files: Option<u64>,
        file_size_bytes: Option<u64>,
    }

    impl Limits {
        fn is_empty(&self) -> bool {
            self.cpu_seconds.is_none()
                && self.address_space_bytes.is_none()
                && self.process_count.is_none()
                && self.open_files.is_none()
                && self.file_size_bytes.is_none()
        }

        fn apply(&self) -> Result<(), RunnerError> {
            disable_core_dumps()?;
            apply_limit("--cpu-seconds", Resource::Cpu, self.cpu_seconds)?;
            apply_limit(
                "--address-space-bytes",
                Resource::As,
                self.address_space_bytes,
            )?;
            apply_limit("--process-count", Resource::Nproc, self.process_count)?;
            apply_limit("--open-files", Resource::Nofile, self.open_files)?;
            apply_limit("--file-size-bytes", Resource::Fsize, self.file_size_bytes)?;
            Ok(())
        }
    }

    fn disable_core_dumps() -> Result<(), RunnerError> {
        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .map_err(|source| RunnerError::SetLimit {
            option: "core dumps",
            source,
        })
    }

    struct RunnerConfiguration {
        limits: Limits,
        command: OsString,
        arguments: Vec<OsString>,
    }

    impl RunnerConfiguration {
        fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, RunnerError> {
            let arguments = arguments.into_iter().collect::<Vec<_>>();
            let mut limits = Limits::default();
            let mut index = 0;

            while let Some(argument) = arguments.get(index) {
                if argument == "--" {
                    let Some(command) = arguments.get(index + 1) else {
                        return Err(RunnerError::MissingCommand);
                    };
                    if limits.is_empty() {
                        return Err(RunnerError::MissingLimit);
                    }
                    return Ok(Self {
                        limits,
                        command: command.clone(),
                        arguments: arguments[index + 2..].to_vec(),
                    });
                }

                let option = argument.to_str().ok_or(RunnerError::InvalidOption)?;
                let Some(value) = arguments.get(index + 1) else {
                    return Err(RunnerError::MissingValue(option.to_owned()));
                };
                let limit = parse_limit(option, value)?;
                match option {
                    "--cpu-seconds" => set_once(&mut limits.cpu_seconds, option, limit)?,
                    "--address-space-bytes" => {
                        set_once(&mut limits.address_space_bytes, option, limit)?
                    }
                    "--process-count" => set_once(&mut limits.process_count, option, limit)?,
                    "--open-files" => set_once(&mut limits.open_files, option, limit)?,
                    "--file-size-bytes" => set_once(&mut limits.file_size_bytes, option, limit)?,
                    _ => return Err(RunnerError::UnknownOption(option.to_owned())),
                }
                index += 2;
            }

            Err(RunnerError::MissingCommand)
        }
    }

    pub(super) fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), RunnerError> {
        let configuration = RunnerConfiguration::parse(arguments)?;
        configuration.limits.apply()?;
        mark_extra_file_descriptors_close_on_exec();
        let error = Command::new(configuration.command)
            .args(configuration.arguments)
            .exec();
        Err(RunnerError::Exec(error))
    }

    fn mark_extra_file_descriptors_close_on_exec() {
        // The runner is a fresh trusted process. Setup before this only changes
        // rlimits, and Command construction after it performs no FD operations
        // before exec. This preserves protocol stdio while keeping
        // Bubblewrap-inherited host descriptors out of the worker.
        close_fds::set_fds_cloexec(3, &[]);
    }

    fn parse_limit(option: &str, value: &OsString) -> Result<u64, RunnerError> {
        let value = value
            .to_str()
            .ok_or_else(|| RunnerError::InvalidLimit(option.to_owned()))?
            .parse::<u64>()
            .map_err(|_| RunnerError::InvalidLimit(option.to_owned()))?;
        if value == 0 || value == u64::MAX {
            return Err(RunnerError::InvalidLimit(option.to_owned()));
        }
        Ok(value)
    }

    fn set_once(slot: &mut Option<u64>, option: &str, value: u64) -> Result<(), RunnerError> {
        if slot.replace(value).is_some() {
            return Err(RunnerError::DuplicateOption(option.to_owned()));
        }
        Ok(())
    }

    fn apply_limit(
        option: &'static str,
        resource: Resource,
        maximum: Option<u64>,
    ) -> Result<(), RunnerError> {
        let Some(maximum) = maximum else {
            return Ok(());
        };
        setrlimit(
            resource,
            Rlimit {
                current: Some(maximum),
                maximum: Some(maximum),
            },
        )
        .map_err(|source| RunnerError::SetLimit { option, source })
    }

    #[derive(Debug)]
    pub(super) enum RunnerError {
        InvalidOption,
        UnknownOption(String),
        MissingValue(String),
        InvalidLimit(String),
        DuplicateOption(String),
        MissingLimit,
        MissingCommand,
        SetLimit {
            option: &'static str,
            source: rustix::io::Errno,
        },
        Exec(io::Error),
    }

    impl RunnerError {
        pub(super) fn exit_code(&self) -> i32 {
            match self {
                Self::InvalidOption
                | Self::UnknownOption(_)
                | Self::MissingValue(_)
                | Self::InvalidLimit(_)
                | Self::DuplicateOption(_)
                | Self::MissingLimit
                | Self::MissingCommand => EXIT_USAGE,
                Self::SetLimit { .. } => EXIT_LIMIT,
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
                Self::InvalidLimit(option) => write!(
                    formatter,
                    "{option} must be a finite integer in 1..={}",
                    u64::MAX - 1
                ),
                Self::DuplicateOption(option) => write!(formatter, "duplicate option {option}"),
                Self::MissingLimit => {
                    formatter.write_str("at least one resource limit is required")
                }
                Self::MissingCommand => {
                    formatter.write_str("a command is required after the -- separator")
                }
                Self::SetLimit { option, source } => {
                    write!(formatter, "could not apply {option}: {source}")
                }
                Self::Exec(source) => write!(formatter, "could not execute worker: {source}"),
            }
        }
    }

    impl std::error::Error for RunnerError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::SetLimit { source, .. } => Some(source),
                Self::Exec(source) => Some(source),
                Self::InvalidOption
                | Self::UnknownOption(_)
                | Self::MissingValue(_)
                | Self::InvalidLimit(_)
                | Self::DuplicateOption(_)
                | Self::MissingLimit
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
        fn parses_each_supported_limit_before_a_fixed_command() {
            let configuration = RunnerConfiguration::parse(arguments(&[
                "--cpu-seconds",
                "30",
                "--address-space-bytes",
                "1048576",
                "--process-count",
                "4",
                "--open-files",
                "16",
                "--file-size-bytes",
                "4096",
                "--",
                "/opt/splash/worker",
                "--json-lines",
            ]))
            .unwrap();

            assert_eq!(configuration.limits.cpu_seconds, Some(30));
            assert_eq!(configuration.limits.address_space_bytes, Some(1_048_576));
            assert_eq!(configuration.limits.process_count, Some(4));
            assert_eq!(configuration.limits.open_files, Some(16));
            assert_eq!(configuration.limits.file_size_bytes, Some(4_096));
            assert_eq!(configuration.command, "/opt/splash/worker");
            assert_eq!(configuration.arguments, arguments(&["--json-lines"]));
        }

        #[test]
        fn rejects_ambiguous_or_unbounded_configuration() {
            let unbounded = u64::MAX.to_string();
            assert!(matches!(
                RunnerConfiguration::parse(arguments(&[
                    "--open-files",
                    "8",
                    "--open-files",
                    "9",
                    "--",
                    "/opt/splash/worker",
                ])),
                Err(RunnerError::DuplicateOption(option)) if option == "--open-files"
            ));
            assert!(matches!(
                RunnerConfiguration::parse(arguments(&[
                    "--open-files",
                    "0",
                    "--",
                    "/opt/splash/worker",
                ])),
                Err(RunnerError::InvalidLimit(option)) if option == "--open-files"
            ));
            assert!(matches!(
                RunnerConfiguration::parse(arguments(&[
                    "--open-files",
                    &unbounded,
                    "--",
                    "/opt/splash/worker",
                ])),
                Err(RunnerError::InvalidLimit(option)) if option == "--open-files"
            ));
            assert!(matches!(
                RunnerConfiguration::parse(arguments(&["--", "/opt/splash/worker"])),
                Err(RunnerError::MissingLimit)
            ));
        }
    }
}
