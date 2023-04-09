use super::super::{
    installer::Installer,
    service_manager::{ServiceCommand, ServiceCommands, ServiceDefinition},
};

pub const SERVICE_NAME: &str = "smartdns";

pub const CONF_PATH: &str = "/usr/local/etc/smartdns/smartdns.conf";

#[inline]
pub fn create_service_definition() -> ServiceDefinition {
    let installer = Installer::builder().build();

    let brew = "brew";

    let commands = ServiceCommands {
        install: Some(ServiceCommand {
            program: brew.into(),
            args: vec!["install".into(), SERVICE_NAME.into()],
        }),
        uninstall: Some(ServiceCommand {
            program: brew.into(),
            args: vec!["uninstall".into(), SERVICE_NAME.into()],
        }),
        start: ServiceCommand {
            program: brew.into(),
            args: vec!["services".into(), "start".into(), SERVICE_NAME.into()],
        },
        stop: ServiceCommand {
            program: brew.into(),
            args: vec!["services".into(), "stop".into(), SERVICE_NAME.into()],
        },
        restart: Some(ServiceCommand {
            program: brew.into(),
            args: vec!["services".into(), "restart".into(), SERVICE_NAME.into()],
        }),
        status: Some(ServiceCommand {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                format!(
                    r#"
                    O=$(brew services info {}) && echo "$O" | grep -q "Running: true" &&
                    (echo "$O" && exit 0) || (echo "$O" && exit 1) 
                    "#,
                    SERVICE_NAME
                )
                .lines()
                .collect::<String>()
                .into(),
            ],
        }),
    };

    ServiceDefinition::new(crate::NAME.to_string(), installer, commands)
}
