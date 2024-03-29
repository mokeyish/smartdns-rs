use super::*;

pub const SERVICE_FILE_PATH: &str = "/etc/init.d/smartdns-rs";
pub const SERVICE_FILE: &str = include_str!("files/etc/init.d/smartdns-rs");

#[inline]
pub fn is_debian() -> bool {
    detect::os_release::get()
        .map(|os| os.is_debian())
        .unwrap_or_default()
}
