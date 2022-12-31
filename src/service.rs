use cfg_if::cfg_if;
use std::env;
use std::fs;
use std::path::Path;
use std::{ffi::OsString, path::PathBuf};

use service_manager::{
    ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx, ServiceStopCtx,
    ServiceUninstallCtx,
};

const SERVICE_NAME: &'static str = "smartdns-rs";

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
pub fn status() {
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
        let label = SERVICE_NAME.parse().unwrap();

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
                } else if #[cfg(target_os = "windows")]  {
                    cmd_path = "C:\\Windows\\System32\\smartdns.exe";
                    conf_path = "C:\\ProgramData\\smartdns\\smartdns.conf";
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
                    #[cfg(windows)]
                    OsString::from("--ws7642ea814a90496daaa54f2820254f12"),
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
            fs::remove_file(self.cmd_path.as_path())
                .map(|_| {
                    println!("Successfully removed `{:?}`", self.cmd_path);
                })
                .unwrap_or_else(|err| {
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

#[cfg(target_os = "windows")]
pub mod windows_service {
    use super::SERVICE_NAME;
    use crate::log::error;
    use std::{ffi::OsString, time::Duration};

    use windows_service::service::{
        ServiceControlAccept, ServiceExitCode, ServiceState, ServiceType,
    };
    use windows_service::{
        define_windows_service,
        service::{ServiceControl, ServiceStatus},
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher, Result,
    };

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(args: Vec<OsString>) {
        unsafe {
            // Windows services don't start with a console, so we have to
            // allocate one in order to send ctrl-C to children.
            if !windows::Win32::System::Console::AllocConsole().as_bool() {
                error!(
                    "winapi AllocConsole failed with code {:?}",
                    windows::Win32::Foundation::GetLastError()
                );
            };
        }
        let _ = run_service(args);
    }

    pub fn run() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn run_service(_args: Vec<OsString>) -> Result<()> {
        // Define system service event handler that will be receiving service events.
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                // Notifies a service to report its current status information to the service
                // control manager. Always return NoError even if not implemented.
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

                // Handle stop
                ServiceControl::Stop => {
                    unsafe {
                        windows::Win32::System::Console::GenerateConsoleCtrlEvent(
                            windows::Win32::System::Console::CTRL_C_EVENT,
                            0,
                        )
                        .as_bool();
                    }
                    ServiceControlHandlerResult::NoError
                }

                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        // Register system service event handler.
        // The returned status handle should be used to report service status changes to the system.
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        let service_type = ServiceType::OWN_PROCESS;

        // Tell the system that service is running
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        {
            use crate::cli::*;

            let args = std::env::args()
                .filter(|s| s != "--ws7642ea814a90496daaa54f2820254f12")
                .collect::<Vec<_>>();
                Cli::parse_from(args).run();
        }

        // Tell the system that service has stopped.
        status_handle.set_service_status(ServiceStatus {
            service_type,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }
}
