use cfg_if::cfg_if;
use std::env;
use std::fs;
use std::path::Path;
use std::{ffi::OsString, path::PathBuf};

use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

#[inline]
pub fn install() {
    Service::new().install();
}

#[inline]
pub fn uninstall(purge: bool) {
    Service::new().uninstall(purge);
}

#[inline]
pub fn start() {
    Service::new().start();
}

#[inline]
pub fn stop() {
    Service::new().stop();
}

#[inline]
pub fn restart() {
    let service = Service::new();
    service.stop();
    service.start();
}

#[inline]
pub fn status(){
    Service::new();
}


struct Service {
    label: ServiceLabel,
    manager: Box<dyn ServiceManager>,
    cmd_path: PathBuf,
    conf_path: PathBuf,
}

impl Service {

    #[inline]
    fn new() -> Self {
        let label = "sys.dns.smartdns-rs".parse().unwrap();

        let cmd_path;
        let conf_path;
        
        let mut manager: Box<dyn ServiceManager> = {
            cfg_if! {
                if #[cfg(target_os = "macos")] {
                    use service_manager::LaunchdServiceManager;
                    cmd_path = "/usr/local/bin/smartdns";
                    conf_path = "/usr/local/etc/smartdns/smartdns.conf";
                    let manager = LaunchdServiceManager::system();

                    Box::new(manager)
                } else if #[cfg(target_os = "android")]  {
                    unimplemented!()
                } else if #[cfg(target_os = "linux")]  {
                    cmd_path = "/sbin/smartdns";
                    conf_path = "/etc/smartdns/smartdns.conf";
                    <dyn ServiceManager>::native().expect("")
                } else {
                    <dyn ServiceManager>::native().expect("")
                }
            }
        };


        manager
            .set_level(ServiceLevel::System)
            .expect("Service manager does not support system-level services");

        Self {
            label,
            manager,
            cmd_path: Path::new(cmd_path).to_owned(),
            conf_path: Path::new(conf_path).to_owned(),
        }
    }

    #[inline]
    fn install(&self) {
        let current_exe =
            env::current_exe().unwrap_or_else(|e| panic!("failed to get current exe path: {e}"));

        if current_exe != self.cmd_path {
            fs::copy(current_exe.as_path(), self.cmd_path.as_path()).unwrap_or_else(|e| {
                panic!("Install to {:?} failed. {e}", self.cmd_path);
            });
        }

        if !self.conf_path.exists() {
            if let Some(dir) = self.conf_path.parent() {
                fs::create_dir_all(dir).unwrap_or_else(|e| {
                    panic!("Create directory {:?} failed, {}", dir, e);
                });
            }
            fs::write(self.conf_path.as_path(), crate::DEFAULT_CONF).unwrap_or_else(|e| {
                panic!("Copy smartdns.conf to {:?} failed, {}", self.conf_path, e);
            })
        }

        // Install our service using the underlying service management platform
        self.manager
            .install(ServiceInstallCtx {
                label: self.label.clone(),
                program: self.cmd_path.clone(),
                args: vec![
                    OsString::from("run"),
                    OsString::from("-c"),
                    self.conf_path.as_os_str().to_os_string(),
                ],
            })
            .expect("Failed to install service");

        println!("Successfully installed service `{}`", crate::NAME);
    }

    #[inline]
    fn uninstall(&self, purge: bool) {
        // Uninstall our service using the underlying service management platform
        self.manager
            .uninstall(ServiceUninstallCtx {
                label: self.label.clone(),
            })
            .expect("Failed to uninstall service");
        
        if purge {
            fs::remove_file(self.cmd_path.as_path()).map(|_| {
                println!("Successfully removed `{:?}`", self.cmd_path);
            }).unwrap_or_else(|err| {
                println!("Failed to remove file: {:?}, {}", self.cmd_path, err);
            });
        }

        println!("Successfully uninstalled service `{}`", crate::NAME);
    }

    #[inline]
    fn start(&self) {
        // Start our service using the underlying service management platform
        self.manager
            .start(ServiceStartCtx {
                label: self.label.clone(),
            })
            .expect("Failed to start");

        println!("Successfully started `{}`", crate::NAME);
    }

    #[inline]
    fn stop(&self) {
        // Stop our service using the underlying service management platform
        self.manager
            .stop(ServiceStopCtx {
                label: self.label.clone(),
            })
            .expect("Failed to stop");

        println!("Successfully stopped `{}`", crate::NAME);
    }
}

