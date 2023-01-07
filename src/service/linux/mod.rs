use super::{
    installer::{InstallStrategy::*, Installer, UninstallStrategy::*},
    service_manager::{ServiceCommand, ServiceCommands, ServiceDefinition},
    SERVICE_NAME,
};

pub const BIN_PATH: &'static str = "/usr/sbin/smartdns";
pub const CONF_DIR: &'static str = "/etc/smartdns";
pub const CONF_PATH: &'static str = "/etc/smartdns/smartdns.conf";

mod initd;
mod runit;
mod systemd;

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    if detect::is_systemd() {
        systemd::create_service_definition()
    } else if detect::is_initd() {
        initd::create_service_definition()
    } else {
        unimplemented!()
    }
}

mod detect {
    pub use super::initd::is_initd;
    pub use super::systemd::is_systemd;
    pub use crate::infra::os_release;
}
