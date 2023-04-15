use std::ffi::OsString;

use clap::Parser;
use clap::Subcommand;

use crate::log::warn;

/// Smart-DNS.
///
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

impl Cli {
    pub fn parse() -> Self {
        match Self::try_parse() {
            Ok(cli) => cli,
            Err(e) => match CompatibleCli::try_parse() {
                Ok(cli) => cli.into(),
                Err(_) => {
                    // Since this is more of a development-time error, we aren't doing as fancy of a quit
                    // as `get_matches`
                    e.exit()
                }
            },
        }
    }

    /// Parse from iterator, exit on error
    pub fn parse_from<I, T>(itr: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let itr = itr.into_iter().collect::<Vec<_>>();
        match Self::try_parse_from(itr.clone()) {
            Ok(cli) => cli,
            Err(e) => match CompatibleCli::try_parse_from(itr) {
                Ok(cli) => cli.into(),
                Err(_) => e.exit(),
            },
        }
    }
}

#[derive(Subcommand, PartialEq, Eq, Debug)]
pub enum Commands {
    /// Run the Smart-DNS server.
    Run {
        /// Config file
        #[arg(short = 'c', long)]
        conf: Option<std::path::PathBuf>,

        /// Pid file
        #[arg(short = 'p', long)]
        pid: Option<std::path::PathBuf>,

        /// Turn debugging information on
        #[arg(short = 'd', long)]
        debug: bool,
    },

    /// Manage the Smart-DNS service (install, uninstall, start, stop, restart).
    Service {
        #[command(subcommand)]
        command: ServiceCommands,
    },
}

#[derive(Subcommand, PartialEq, Eq, Debug)]
pub enum ServiceCommands {
    /// Install the Smart-DNS as service.
    Install,

    /// Uninstall the Smart-DNS service.
    Uninstall {
        /// Purge both the binary and config files.
        #[arg(short = 'p', long)]
        purge: bool,
    },

    /// Start the Smart-DNS service.
    Start,

    /// Stop the Smart-DNS service.
    Stop,

    /// Restart the Smart-DNS service.
    Restart,

    /// Print the service status of Smart-DNS
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
}

impl From<CompatibleCli> for Cli {
    fn from(
        CompatibleCli {
            conf,
            pid,
            verbose,
            foreground,
        }: CompatibleCli,
    ) -> Self {
        if !foreground {
            warn!("not support running as a daemon, run foreground instead.")
        }
        Self {
            command: Commands::Run {
                conf,
                pid,
                debug: verbose,
            },
        }
    }
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
                debug: false
            }
        ));

        let cli = Cli::parse_from(["smartdns", "run", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                debug: false
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_run_debug_on() {
        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-d"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                debug: true
            }
        ));

        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "--debug"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                debug: true,
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_install() {
        let cli = Cli::parse_from(["smartdns", "service", "install"]);
        assert_eq!(
            cli.command,
            Commands::Service {
                command: ServiceCommands::Install
            }
        );
    }

    #[test]
    fn test_cli_args_parse_uninstall() {
        let cli = Cli::parse_from(["smartdns", "service", "uninstall"]);
        assert_eq!(
            cli.command,
            Commands::Service {
                command: ServiceCommands::Uninstall { purge: false }
            }
        );
    }

    #[test]
    fn test_cli_args_parse_compatible_run() {
        let cli = Cli::parse_from(["smartdns", "-c", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                debug: false
            }
        ));

        let cli = Cli::parse_from(["smartdns", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                debug: false
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
                debug: true
            }
        ));

        let cli = Cli::parse_from(["smartdns", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                pid: None,
                debug: false
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
                debug: false
            }
        ));
    }
}
