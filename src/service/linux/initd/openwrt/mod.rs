use super::*;
use std::io;

pub const SERVICE_FILE_PATH: &'static str = "/etc/init.d/smartdns-rs";
pub const SERVICE_FILE: &'static str = include_str!("files/etc/init.d/smartdns-rs");

const PROCD: &str = "procd";
pub fn is_openwrt() -> bool {
    match which::which(PROCD) {
        Ok(_) => Ok(true),
        Err(which::Error::CannotFindBinaryPath) => Ok(false),
        Err(x) => Err(io::Error::new(io::ErrorKind::Other, x)),
    }
    .unwrap_or_default()
        && detect::os_release::get()
            .map(|os| os.is_openwrt())
            .unwrap_or_default()
}
