//!
//! Linux's [systemd](https://en.wikipedia.org/wiki/Systemd)

use std::{io, path::Path};

use super::*;

const SERVICE_FILE_PATH: &str = "/lib/systemd/system/smartdns-rs.service";
const SERVICE_FILE: &str = include_str!("files/lib/systemd/system/smartdns-rs.service");
const SERVICE_CTL: &str = "systemctl";
const SERVICE_RUN_DIR: &str = "/run/systemd/system";

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    let installer = Installer::builder()
        .install_current_exe_to(BIN_PATH)
        .add_item((CONF_DIR, RemoveIfEmpty))
        .add_item((CONF_PATH, crate::DEFAULT_CONF, 0o644, Preserve, Keep))
        .add_item((SERVICE_FILE_PATH, SERVICE_FILE, 0o644))
        .build();

    let service_name: &str = &[SERVICE_NAME, ".service"].concat();

    let commands = ServiceCommands {
        install: Some(ServiceCommand {
            program: SERVICE_CTL.into(),
            args: vec!["enable".into(), service_name.into()],
        }),
        uninstall: Some(ServiceCommand {
            program: SERVICE_CTL.into(),
            args: vec!["disable".into(), service_name.into()],
        }),
        start: ServiceCommand {
            program: SERVICE_CTL.into(),
            args: vec!["start".into(), service_name.into()],
        },
        stop: ServiceCommand {
            program: SERVICE_CTL.into(),
            args: vec!["stop".into(), service_name.into()],
        },
        restart: Some(ServiceCommand {
            program: SERVICE_CTL.into(),
            args: vec!["restart".into(), service_name.into()],
        }),
        status: Some(ServiceCommand {
            program: SERVICE_CTL.into(),
            args: vec!["status".into(), service_name.into()],
        }),
    };

    ServiceDefinition::new(crate::NAME.to_string(), installer, commands)
}

pub fn is_systemd() -> bool {
    match which::which(SERVICE_CTL) {
        Ok(_) => Ok(Path::new(SERVICE_RUN_DIR).exists()),
        Err(which::Error::CannotFindBinaryPath) => Ok(false),
        Err(x) => Err(io::Error::new(io::ErrorKind::Other, x)),
    }
    .unwrap_or_default()
}
