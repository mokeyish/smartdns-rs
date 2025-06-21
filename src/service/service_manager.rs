use std::{
    ffi::OsString,
    fmt::Display,
    io,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

// use regex::Regex;

use super::installer::Installer;
use crate::log::{debug, error, info};

#[derive(Debug)]
pub struct ServiceDefinition {
    name: String,
    installer: Installer,
    commands: ServiceCommands,
}

impl ServiceDefinition {
    pub fn new(name: String, installer: Installer, commands: ServiceCommands) -> Self {
        Self {
            name,
            installer,
            commands,
        }
    }
}

#[derive(Debug)]
pub struct ServiceCommands {
    pub install: Option<ServiceCommand>,
    pub uninstall: Option<ServiceCommand>,
    pub status: Option<ServiceCommand>,
    pub start: ServiceCommand,
    pub stop: ServiceCommand,
    pub restart: Option<ServiceCommand>,
}

#[derive(Debug)]
pub struct ServiceManager {
    definition: ServiceDefinition,
}

impl From<ServiceDefinition> for ServiceManager {
    fn from(definition: ServiceDefinition) -> Self {
        Self { definition }
    }
}

impl ServiceManager {
    pub fn install(&self) -> io::Result<()> {
        let _ = self.uninstall(false, true);

        // install files.
        self.definition.installer.install()?;

        if let Some(install) = self.definition.commands.install.as_ref() {
            install.spawn()?;
        }

        info!("Service {} successfully installed", self.definition.name);
        self.start()?;
        Ok(())
    }

    pub fn uninstall(&self, purge: bool, quiet: bool) -> io::Result<()> {
        // try stopping an existing running service.
        self.try_stop().unwrap_or_default();

        if let Some(uninstall) = self.definition.commands.uninstall.as_ref() {
            if quiet {
                let _ = uninstall.output();
            } else {
                let _ = uninstall.spawn();
            }
        }

        if self.definition.installer.uninstall(purge)? > 0 {
            info!("Service {} successfully uninstalled", self.definition.name);
        }
        Ok(())
    }

    pub fn start(&self) -> io::Result<()> {
        if !matches!(self.status(), Ok(ServiceStatus::Running(_))) {
            self.definition.commands.start.spawn()?;
            info!("Successfully started service {}", self.definition.name);
        } else {
            info!("Service {} already started", self.definition.name);
        }
        Ok(())
    }

    pub fn stop(&self) -> io::Result<()> {
        self.try_stop()?;
        info!("Successfully stopped service {}", self.definition.name);
        Ok(())
    }

    pub fn try_stop(&self) -> io::Result<()> {
        if !matches!(self.status(), Ok(ServiceStatus::Dead(_))) {
            self.definition.commands.stop.spawn()?;
        }
        Ok(())
    }

    pub fn restart(&self) -> io::Result<()> {
        match self.definition.commands.restart.as_ref() {
            Some(restart) => {
                restart.spawn()?;
                info!("Successfully restarted service {}", self.definition.name);
            }
            None => {
                self.try_stop().unwrap_or_default();
                std::thread::sleep(Duration::from_millis(500));
                self.start()?;
            }
        }
        Ok(())
    }

    pub fn status(&self) -> io::Result<ServiceStatus> {
        let status = match self.definition.commands.status.as_ref() {
            Some(cmd) => {
                let output = cmd.output()?;
                if output.status.success() {
                    ServiceStatus::Running(output)
                } else {
                    ServiceStatus::Dead(output)
                }
            }
            None => ServiceStatus::Unknown,
        };
        Ok(status)
    }
}

#[derive(Debug)]
pub struct ServiceCommand {
    /// Path to the service manager program to run
    ///
    /// E.g. `/usr/local/bin/my-program`
    pub program: PathBuf,

    /// Arguments to use for the program
    ///
    /// E.g. `--arg`, `value`, `--another-arg`
    pub args: Vec<OsString>,
}

impl Display for ServiceCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.program.display())?;
        for arg in self.args.iter() {
            write!(f, " {}", arg.to_string_lossy())?
        }
        Ok(())
    }
}

impl ServiceCommand {
    #[inline]
    pub fn spawn(&self) -> io::Result<()> {
        let output = self.output()?;

        if output.status.success() {
            Ok(())
        } else {
            let msg = String::from_utf8(output.stderr)
                .ok()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    String::from_utf8(output.stdout)
                        .ok()
                        .filter(|s| !s.trim().is_empty())
                })
                .unwrap_or_else(|| "Failed".to_string());
            error!("{:?}, {}", self.program, msg);
            Err(io::Error::other(msg))
        }
    }

    #[inline]
    pub fn output(&self) -> io::Result<std::process::Output> {
        debug!("># {}", self);
        self.to_command().output()
    }

    fn to_command(&self) -> Command {
        let mut command: Command = self.into();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

impl From<&ServiceCommand> for Command {
    fn from(cmd: &ServiceCommand) -> Self {
        let mut command = Command::new(cmd.program.as_path());
        command.args(cmd.args.iter());
        command
    }
}

impl From<ServiceCommand> for Command {
    #[inline]
    fn from(cmd: ServiceCommand) -> Self {
        Self::from(&cmd)
    }
}

#[derive(Debug)]
pub enum ServiceStatus {
    Running(std::process::Output),
    Dead(std::process::Output),
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfg_if::cfg_if;

    #[test]
    fn test_service_command() {
        let cmd = {
            cfg_if! {
                if #[cfg(target_os="windows")] {
                    ServiceCommand {
                        program: "cmd.exe".into(),
                        args: vec![
                                "/C".into(),
                                "ver.exe".into()
                            ],
                    }
                } else {
                    ServiceCommand {
                        program: "uname".into(),
                        args: vec![
                            "-a".into(),
                        ],
                    }
                }
            }
        };

        let output = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(output.stdout.as_slice()).to_string();

        #[cfg(unix)]
        assert_eq!(format!("{}", cmd), "uname -a");

        cfg_if! {
            if #[cfg(target_os="windows")] {
                assert!(stdout.contains("Windows"));
            } else if #[cfg(target_os="linux")] {
                assert!(stdout.contains("Linux"));
            } else if #[cfg(target_os="macos")] {
                assert!(stdout.contains("Darwin"));
            } else if #[cfg(target_os="android")] {
                assert!(stdout.contains("Android"));
            } else {
                unimplemented!()
            }
        }
    }
}
