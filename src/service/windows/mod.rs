use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
};

// use regex::Regex;

use super::{
    installer::{InstallStrategy::*, Installer, UninstallStrategy::*},
    service_manager::{ServiceCommand, ServiceCommands, ServiceDefinition},
    SERVICE_NAME,
};

mod shell_escape;
mod windows_service;

pub const BIN_PATH: &'static str = "C:\\Windows\\System32\\smartdns.exe";
pub const CONF_DIR: &'static str = "C:\\ProgramData\\smartdns";
pub const CONF_PATH: &'static str = "C:\\ProgramData\\smartdns\\smartdns.conf";

pub use self::windows_service::run;

#[inline]
pub(super) fn create_service_definition() -> ServiceDefinition {
    let installer = Installer::builder()
        .install_current_exe_to(BIN_PATH)
        .add_item((CONF_DIR, RemoveIfEmpty))
        .add_item((CONF_PATH, crate::DEFAULT_CONF, Preserve, Keep))
        .build();

    let mut bin_path = OsString::new();

    bin_path.push(shell_escape::escape(Cow::Borrowed(OsStr::new(BIN_PATH))));

    for arg in &[
        OsString::from("run"),
        OsString::from("-c"),
        OsString::from(CONF_PATH),
        #[cfg(windows)]
        OsString::from("--ws7642ea814a90496daaa54f2820254f12"),
    ] {
        bin_path.push(" ");
        bin_path.push(shell_escape::escape(Cow::Borrowed(arg)));
    }

    let sc_exe = "sc.exe";
    let commands = ServiceCommands {
        install: Some(ServiceCommand {
            program: sc_exe.into(),
            args: vec![
                "create".into(),
                SERVICE_NAME.into(),
                // type
                "type=".into(),
                "own".into(),
                // start
                "start=".into(),
                "auto".into(),
                // program
                "binpath=".into(),
                bin_path,
                // displayname
                "displayname=".into(),
                crate::NAME.into(),
            ],
        }),
        uninstall: Some(ServiceCommand {
            program: sc_exe.into(),
            args: vec!["delete".into(), SERVICE_NAME.into()],
        }),
        start: ServiceCommand {
            program: sc_exe.into(),
            args: vec!["start".into(), SERVICE_NAME.into()],
        },
        stop: ServiceCommand {
            program: sc_exe.into(),
            args: vec!["stop".into(), SERVICE_NAME.into()],
        },
        restart: None,
        status: Some(ServiceCommand {
            program: "cmd.exe".into(),
            args: vec![
                "/C".into(), 
                ["sc query ", SERVICE_NAME," | findstr STATE.*:.*RUNNING > NUL && (sc query smartdns-rs && exit 0) || (sc query smartdns-rs && exit 1)"].concat().into()
                ],
        }),
    };

    ServiceDefinition::new(crate::NAME.to_string(), installer, commands)
}
