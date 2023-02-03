//!
//! Service Manager
//!
//! ref: https://rtc.datacentric.sg/docs/service.html

use self::{installer::InstallerBuilder, service_manager::ServiceManager};
use cfg_if::cfg_if;
use std::{env, path::Path};

pub const SERVICE_NAME: &'static str = "smartdns-rs";

mod installer;
mod service_manager;

pub use service_manager::ServiceStatus;

cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        mod linux;
        use linux::create_service_definition;
        pub use linux::{BIN_PATH, CONF_PATH};
    } else if #[cfg(target_os = "macos")] {
        mod macos;
        use self::macos::create_service_definition;
        pub use macos::{BIN_PATH, CONF_PATH};
    } else if #[cfg(target_os = "windows")] {
        pub mod windows;
        use self::windows::create_service_definition;
        pub use self::windows::{BIN_PATH, CONF_PATH};
    } else {
        unimplemented!();
    }
}

pub fn service_manager() -> ServiceManager {
    create_service_definition().into()
}

impl InstallerBuilder {
    fn install_current_exe_to<P: AsRef<Path>>(self, path: P) -> Self {
        let cmd_path = path.as_ref();
        let current_exe =
            env::current_exe().unwrap_or_else(|e| panic!("failed to get current exe path: {e}"));

        if current_exe != cmd_path {
            self.add_item((current_exe, cmd_path))
        } else {
            self
        }
    }
}
