//!
//! sysvinit

use std::path::Path;

use super::*;

mod debian;
mod openwrt;
mod others;

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    let (service_file_path, service_file) = {
        if openwrt::is_openwrt() {
            (openwrt::SERVICE_FILE_PATH, openwrt::SERVICE_FILE)
        } else if debian::is_debian() {
            (debian::SERVICE_FILE_PATH, debian::SERVICE_FILE)
        } else {
            (others::SERVICE_FILE_PATH, others::SERVICE_FILE)
        }
    };

    let installer = Installer::builder()
        .install_current_exe_to(BIN_PATH)
        .add_item((CONF_DIR, RemoveIfEmpty))
        .add_item((CONF_PATH, crate::DEFAULT_CONF, 0o644, Preserve, Keep))
        .add_item((service_file_path, service_file, 0o755))
        .build();

    let service_ctl = "service";

    let commands = ServiceCommands {
        install: Some(ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "enable".into()],
        }),
        uninstall: Some(ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "disable".into()],
        }),
        start: ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "start".into()],
        },
        stop: ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "stop".into()],
        },
        restart: Some(ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "restart".into()],
        }),
        status: Some(ServiceCommand {
            program: service_ctl.into(),
            args: vec![SERVICE_NAME.into(), "status".into()],
        }),
    };

    ServiceDefinition::new(crate::NAME.to_string(), installer, commands)
}

pub fn is_initd() -> bool {
    Path::new("/etc/init.d").exists()
}
