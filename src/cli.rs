use clap::Subcommand;

pub use clap::Parser;

/// Smart-DNS.
///
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, PartialEq, Eq, Debug)]
pub enum Commands {
    /// Run the Smart-DNS server.
    Run {
        /// Config file
        #[arg(short = 'c', long)]
        conf: Option<std::path::PathBuf>,

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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_cli_args_parse_start() {
        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                debug: false
            }
        ));

        let cli = Cli::parse_from(["smartdns", "run", "--conf", "/etc/smartdns.conf"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                debug: false
            }
        ));
    }

    #[test]
    fn test_cli_args_parse_start_debug_on() {
        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "-d"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                debug: true
            }
        ));

        let cli = Cli::parse_from(["smartdns", "run", "-c", "/etc/smartdns.conf", "--debug"]);
        assert!(matches!(
            cli.command,
            Commands::Run {
                conf: Some(_),
                debug: true
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
}
