use super::SERVICE_NAME;
use crate::log::error;
use std::{ffi::OsString, time::Duration};

use windows_service::service::{ServiceControlAccept, ServiceExitCode, ServiceState, ServiceType};
use windows_service::{
    Result, define_windows_service,
    service::{ServiceControl, ServiceStatus},
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

define_windows_service!(ffi_service_main, service_main);

fn service_main(args: Vec<OsString>) {
    unsafe {
        // Windows services don't start with a console, so we have to
        // allocate one in order to send ctrl-C to children.
        if let Err(err) = windows::Win32::System::Console::AllocConsole() {
            error!("winapi AllocConsole failed with code {:?}", err);
        }
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
                    if let Err(err) = windows::Win32::System::Console::GenerateConsoleCtrlEvent(
                        windows::Win32::System::Console::CTRL_C_EVENT,
                        0,
                    ) {
                        error!("GenerateConsoleCtrlEvent failed {:?}", err);
                    }
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
