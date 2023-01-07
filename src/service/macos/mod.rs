use super::{
    installer::{InstallStrategy::*, Installer, UninstallStrategy::*},
    service_manager::{ServiceCommand, ServiceCommands, ServiceDefinition},
    SERVICE_NAME,
};

pub const BIN_PATH: &'static str = "/usr/local/bin/smartdns";
pub const CONF_DIR: &'static str = "/usr/local/etc/smartdns";
pub const CONF_PATH: &'static str = "/usr/local/etc/smartdns/smartdns.conf";

const SERVICE_FILE_PATH: &'static str = "/Library/LaunchDaemons/smartdns-rs.plist";
const SERVICE_FILE: &'static str = include_str!("files/Library/LaunchDaemons/smartdns-rs.plist");

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    let service_file_path = SERVICE_FILE_PATH;

    let installer = Installer::builder()
        .install_current_exe_to(BIN_PATH)
        .add_item((CONF_DIR, RemoveIfEmpty))
        .add_item((CONF_PATH, crate::DEFAULT_CONF, 0o644, Preserve, Keep))
        .add_item((SERVICE_FILE_PATH, SERVICE_FILE, 0o644))
        .build();

    let launch_ctl = "launchctl";

    let commands = ServiceCommands {
        install: None,
        uninstall: None,
        start: ServiceCommand {
            program: launch_ctl.into(),
            args: vec!["load".into(), service_file_path.into()],
        },
        stop: ServiceCommand {
            program: launch_ctl.into(),
            args: vec!["bootout".into(), ["system/", SERVICE_NAME].concat().into()],
        },
        restart: None,
        status: Some(ServiceCommand {
            program: launch_ctl.into(),
            args: vec!["list".into(), SERVICE_NAME.into()],
        }),
    };

    ServiceDefinition::new(crate::NAME.to_string(), installer, commands)
}
