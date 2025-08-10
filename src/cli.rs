use clap::Parser;
use clap::Subcommand;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use std::ffi::{OsStr, OsString};
use std::str::FromStr;

use crate::log::{self, warn};
#[cfg(feature = "resolve-cli")]
use crate::resolver::ResolveCommand;

type LogLevelDefault = InfoLevel;

/// SmartDNS.
///
#[derive(Parser, Debug)]
#[command(author, version=build_version(), about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[command(flatten)]
    verbose: Verbosity<LogLevelDefault>,
}

impl Cli {
    pub fn parse() -> Self {
        #[cfg(feature = "resolve-cli")]
        if ResolveCommand::is_resolve_cli() {
            return ResolveCommand::parse().into();
        }

        if std::env::args().any(|arg| arg == "help" || arg == "--help") {
            Self::try_parse().unwrap_err().exit(); // Force clap to show help
        }

        match Self::try_parse() {
            Ok(cli) => cli,
            Err(e) => {
                #[cfg(feature = "resolve-cli")]
                if let Ok(resolve_command) = ResolveCommand::try_parse() {
                    return resolve_command.into();
                }

                if let Ok(cli) = CompatibleCli::try_parse() {
                    return cli.into();
                }
                // Since this is more of a development-time error, we aren't doing as fancy of a quit
                // as `get_matches`
                e.exit()
            }
        }
    }

    /// Parse from iterator, exit on error
    pub fn parse_from<I, T>(itr: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone + AsRef<OsStr>,
    {
        let itr = itr.into_iter().collect::<Vec<_>>();
        // New check for "help" argument
        if itr.iter().any(|arg| {
            arg.as_ref().to_string_lossy() == "help" || arg.as_ref().to_string_lossy() == "--help"
        }) {
            Self::try_parse_from(itr).unwrap_err().exit(); // Force clap to show help
        }

        match Self::try_parse_from(itr.clone()) {
            Ok(cli) => cli,
            Err(e) => {
                #[cfg(feature = "resolve-cli")]
                if let Ok(resolve_command) = ResolveCommand::try_parse_from(itr.clone()) {
                    return resolve_command.into();
                }

                if let Ok(cli) = CompatibleCli::try_parse_from(itr) {
                    return cli.into();
                }

                e.exit()
            }
        }
    }

    pub fn log_level(&self) -> Option<log::Level> {
        self.verbose
            .log_level()
            .map(|s| s.to_string())
            .and_then(|s| log::Level::from_str(&s).ok())
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run the SmartDNS server.
    Run {
        /// Configuration file
        #[arg(short = 'c', long)]
        conf: Option<std::path::PathBuf>,

        /// Configuration directory, default to `/etc/smartdns``
        #[arg(short = 'd', long)]
        directory: Option<std::path::PathBuf>,

        /// Pid file
        #[arg(short = 'p', long)]
        pid: Option<std::path::PathBuf>,
    },

    /// Download and install new version.
    #[cfg(feature = "self-update")]
    Update {
        /// Automatic yes to prompts
        #[arg(short = 'y', long)]
        yes: bool,

        /// The target version to update to
        version: Option<String>,
    },

    /// Manage the SmartDNS service (install, uninstall, start, stop, restart).
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },

    /// Perform DNS resolution.
    #[cfg(feature = "resolve-cli")]
    Resolve(ResolveCommand),

    /// Create a symbolic link to the SmartDNS binary (drop-in replacement for `dig`, `nslookup`, `resolve` etc.)
    #[cfg(feature = "resolve-cli")]
    Symlink {
        /// The path to the symlink to create.
        link: std::path::PathBuf,
    },

    /// Test configuration and exit
    Test {
        /// Config file
        #[arg(short = 'c', long)]
        conf: Option<std::path::PathBuf>,

        /// Configuration directory, default to `/etc/smartdns``
        #[arg(short = 'd', long)]
        direcory: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommands {
    /// Install the SmartDNS as service.
    Install,

    /// Uninstall the SmartDNS service.
    Uninstall {
        /// Purge both the binary and config files.
        #[arg(short = 'p', long)]
        purge: bool,
    },

    /// Start the SmartDNS service.
    Start,

    /// Stop the SmartDNS service.
    Stop,

    /// Restart the SmartDNS service.
    Restart,

    /// Print the service status of SmartDNS
    Status,
}

/// Cli Compatible with [](https://github.com/pymumu/smartdns)
#[derive(Parser, Debug)]
struct CompatibleCli {
    /// Config file
    #[arg(short = 'c', long)]
    conf: Option<std::path::PathBuf>,

    /// Pid file
    #[arg(short = 'p', long)]
    pid: Option<std::path::PathBuf>,

    /// Run foreground.
    #[arg(short = 'f', long)]
    foreground: bool,

    /// Verbose screen.
    #[arg(short = 'x', long)]
    verbose: bool,

    /// ignore segment fault signal
    #[arg(short = 'S')]
    segment_fault_signal: bool,
}

impl From<CompatibleCli> for Cli {
    fn from(
        CompatibleCli {
            conf,
            pid,
            verbose,
            foreground,
            segment_fault_signal: _,
        }: CompatibleCli,
    ) -> Self {
        if !foreground {
            warn!("not support running as a daemon, run foreground instead.")
        }

        let verbose0 = if verbose {
            Verbosity::new(10, 0)
        } else {
            Default::default()
        };
        Self {
            command: Commands::Run {
                conf,
                pid,
                directory: None,
            },
            verbose: verbose0,
        }
    }
}

#[cfg(feature = "resolve-cli")]
impl From<ResolveCommand> for Cli {
    fn from(value: ResolveCommand) -> Self {
        Self {
            command: Commands::Resolve(value),
            verbose: Default::default(),
        }
    }
}

fn build_version() -> &'static str {
    static VERSION: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!(
            "{} 🕙 {}",
            env!("CARGO_PKG_VERSION"),
            crate::BUILD_DATE.with_timezone(&chrono::Local)
        )
    });
    &VERSION
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_cli_args_parse_run() {
        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        let cli = Cli::parse_from(["smartdns", "run", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_run_verbose() {
        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf"]);
        assert_eq!(cli.log_level(), Some(log::Level::INFO));

        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-q"]);
        assert_eq!(cli.log_level(), Some(log::Level::WARN));

        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-v"]);
        assert_eq!(cli.log_level(), Some(log::Level::DEBUG));

        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-qqqqq"]);
        assert_eq!(cli.log_level(), None);
    }

    #[test]
    fn test_cli_args_parse_run_debug_on() {
        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-v"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        assert_eq!(cli.log_level(), Some(log::Level::DEBUG));
    }

    #[test]
    fn test_cli_args_parse_install() {
        let cli = Cli::parse_from(["smartdns", "service", "install"]);
        assert!(matches!(
            cli.command,
            Commands::Service {
                command: ServiceCommands::Install
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_uninstall() {
        let cli = Cli::parse_from(["smartdns", "service", "uninstall"]);
        assert!(matches!(
            cli.command,
            Commands::Service {
                command: ServiceCommands::Uninstall { purge: false }
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_compatible_run() {
        let cli = Cli::parse_from(["smartdns", "-c", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        let cli = Cli::parse_from(["smartdns", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_compatible_run_2() {
        let cli = Cli::parse_from(["smartdns", "-c", "/etc/smartdns.conf", "-x"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        assert_eq!(cli.log_level(), Some(log::Level::TRACE));

        let cli = Cli::parse_from(["smartdns", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_compatible_run_3() {
        let cli = Cli::parse_from(["smartdns", "-f", "-c", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        assert_eq!(cli.log_level(), Some(log::Level::INFO));
    }

    #[test]
    fn test_cli_args_parse_compatible_run_4() {
        let cli = Cli::parse_from(["smartdns", "-f", "-c", "/etc/smartdns.conf", "-S"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                directory: None
            }
        ));

        assert_eq!(cli.log_level(), Some(log::Level::INFO));
    }
}
