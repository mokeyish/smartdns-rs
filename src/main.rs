#![allow(dead_code)]
// #![feature(test)]

use cli::*;
use std::{io, net::SocketAddr, path::PathBuf};
use tokio::net::{TcpListener, UdpSocket};

mod api;
mod app;
mod cli;
mod collections;
mod config;
mod dns;
mod dns_client;
mod dns_conf;
mod dns_error;
mod dns_mw;
mod dns_mw_addr;
mod dns_mw_audit;
mod dns_mw_bogus;
mod dns_mw_cache;
mod dns_mw_cname;
mod dns_mw_dnsmasq;
mod dns_mw_dualstack;
#[cfg(target_os = "linux")]
mod dns_mw_nftset;
mod dns_mw_ns;
mod dns_mw_zone;
mod dns_rule;
mod dns_server;
mod dns_url;
mod dnsmasq;
mod error;
mod ffi;
mod infra;
mod libdns;
mod log;
mod preset_ns;
mod proxy;
mod rustls;
mod service;
mod third_ext;

use app::App;
use error::Error;
use infra::middleware;

use crate::{dns_client::DnsClient, dns_conf::SmartDnsConfig};

use crate::{
    infra::process_guard::ProcessGuardError,
    log::{debug, error, info, warn},
};

fn banner() {
    info!("");
    info!(r#"     _____                      _       _____  _   _  _____ "#);
    info!(r#"    / ____|                    | |     |  __ \| \ | |/ ____|"#);
    info!(r#"   | (___  _ __ ___   __ _ _ __| |_    | |  | |  \| | (___  "#);
    info!(r#"    \___ \| '_ ` _ \ / _` | '__| __|   | |  | | . ` |\___ \ "#);
    info!(r#"    ____) | | | | | | (_| | |  | |_    | |__| | |\  |____) |"#);
    info!(r#"   |_____/|_| |_| |_|\__,_|_|   \__|   |_____/|_| \_|_____/ "#);
    info!("");
}

/// The app name
const NAME: &str = "SmartDNS";

/// The default configuration.
const DEFAULT_CONF: &str = include_str!("../etc/smartdns/smartdns.conf");

/// Returns a version as specified in Cargo.toml
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(not(windows))]
fn main() {
    Cli::parse().run();
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    if matches!(std::env::args().last(), Some(flag) if flag == "--ws7642ea814a90496daaa54f2820254f12")
    {
        return service::windows::run();
    }

    Cli::parse().run();
    Ok(())
}

impl Cli {
    #[inline]
    pub fn run(self) {
        let _guard = log::default();

        match self.command {
            Commands::Run { conf, pid, .. } => {
                let _guard = pid
                    .map(|pid| {
                        use infra::process_guard;
                        match process_guard::create(pid) {
                            Ok(guard) => Some(guard),
                            Err(err @ ProcessGuardError::AlreadyRunning(_)) => {
                                panic!("{}", err)
                            }
                            Err(err) => {
                                error!("{}", err);
                                None
                            }
                        }
                    })
                    .unwrap_or_default();

                run_server(conf);
            }
            Commands::Service {
                command: service_command,
            } => {
                use ServiceCommands::*;
                let sm = crate::service::service_manager();
                match service_command {
                    Install => sm.install(),
                    Uninstall { purge } => sm.uninstall(purge),
                    Start => sm.start(),
                    Stop => sm.stop(),
                    Restart => sm.restart(),
                    Status => match sm.status() {
                        Ok(status) => {
                            let out = match status {
                                service::ServiceStatus::Running(out) => Some(out),
                                service::ServiceStatus::Dead(out) => Some(out),
                                service::ServiceStatus::Unknown => None,
                            };
                            if let Some(out) = out {
                                if let Ok(out) = String::from_utf8(out.stdout) {
                                    print!("{}", out);
                                } else {
                                    warn!("get service status failed.");
                                }
                            }
                            Ok(())
                        }
                        Err(err) => Err(err),
                    },
                }
                .unwrap();
            }
        }
    }
}

fn run_server(conf: Option<PathBuf>) {
    hello_starting();
    App::new(conf).bootstrap();
    log::info!("{} {} shutdown", crate::NAME, crate::version());
}

fn bind_to<T>(
    func: impl Fn(SocketAddr, Option<&str>, &str) -> io::Result<T>,
    sock_addr: SocketAddr,
    bind_device: Option<&str>,
    bind_type: &str,
) -> T {
    func(sock_addr, bind_device, bind_type).unwrap_or_else(|err| {
        panic!("cound not bind to {bind_type}: {sock_addr}, {err}");
    })
}

fn tcp(
    sock_addr: SocketAddr,
    bind_device: Option<&str>,
    bind_type: &str,
) -> io::Result<TcpListener> {
    let device_note = bind_device
        .map(|device| format!("@{device}"))
        .unwrap_or_default();

    debug!("binding {} to {:?}{}", bind_type, sock_addr, device_note);
    let tcp_listener = std::net::TcpListener::bind(sock_addr)?;

    {
        let sock_ref = socket2::SockRef::from(&tcp_listener);
        sock_ref.set_nonblocking(true)?;
        sock_ref.set_reuse_address(true)?;

        #[cfg(target_os = "macos")]
        sock_ref.set_reuse_port(true)?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(device) = bind_device {
            sock_ref.bind_device(Some(device.as_bytes()))?;
        }
    }

    let tcp_listener = TcpListener::from_std(tcp_listener)?;

    info!(
        "listening for {} on {:?}{}",
        bind_type,
        tcp_listener
            .local_addr()
            .expect("could not lookup local address"),
        device_note
    );

    Ok(tcp_listener)
}

fn udp(sock_addr: SocketAddr, bind_device: Option<&str>, bind_type: &str) -> io::Result<UdpSocket> {
    let device_note = bind_device
        .map(|device| format!("@{device}"))
        .unwrap_or_default();

    debug!("binding {} to {:?}{}", bind_type, sock_addr, device_note);
    let udp_socket = std::net::UdpSocket::bind(sock_addr)?;

    {
        let sock_ref = socket2::SockRef::from(&udp_socket);
        sock_ref.set_nonblocking(true)?;
        sock_ref.set_reuse_address(true)?;

        #[cfg(target_os = "macos")]
        sock_ref.set_reuse_port(true)?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(device) = bind_device {
            sock_ref.bind_device(Some(device.as_bytes()))?;
        }
    }

    let udp_socket = UdpSocket::from_std(udp_socket)?;

    info!(
        "listening for {} on {:?}{}",
        bind_type,
        udp_socket
            .local_addr()
            .expect("could not lookup local address"),
        device_note
    );
    Ok(udp_socket)
}

#[inline]
fn hello_starting() {
    info!("Smart-DNS 🐋 {} starting", version());
}

impl SmartDnsConfig {
    pub async fn create_dns_client(&self) -> DnsClient {
        let servers = self.servers();
        let ca_path = self.ca_path();
        let ca_file = self.ca_file();
        let proxies = self.proxies().clone();

        let mut builder = DnsClient::builder();
        builder = builder.add_servers(servers.to_vec());
        if let Some(path) = ca_path {
            builder = builder.with_ca_path(path.to_owned());
        }
        if let Some(file) = ca_file {
            builder = builder.with_ca_path(file.to_owned());
        }
        if let Some(subnet) = self.edns_client_subnet() {
            builder = builder.with_client_subnet(subnet);
        }
        builder = builder.with_proxies(proxies);
        builder.build().await
    }
}

mod signal {
    use std::sync::atomic::{AtomicBool, Ordering};

    static TERMINATING: AtomicBool = AtomicBool::new(false);

    pub async fn terminate() -> std::io::Result<()> {
        use tokio::signal::ctrl_c;

        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            match signal(SignalKind::terminate()) {
                Ok(mut terminate) => tokio::select! {
                    _ = terminate.recv() => SignalKind::terminate(),
                    _ = ctrl_c() => SignalKind::interrupt()
                },
                _ => {
                    ctrl_c().await?;
                    SignalKind::interrupt()
                }
            };
        }

        #[cfg(not(unix))]
        {
            ctrl_c().await?;
        }

        if !TERMINATING.load(Ordering::Relaxed) {
            TERMINATING.store(true, Ordering::Relaxed);
            super::info!("terminating...");
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod run_user {
    use std::{collections::HashSet, io};

    use caps::{CapSet, Capability};

    pub fn with(
        username: &str,
        groupname: Option<&str>,
    ) -> io::Result<users::switch::SwitchUserGuard> {
        let mut caps = HashSet::new();
        caps.insert(Capability::CAP_NET_ADMIN);
        caps.insert(Capability::CAP_NET_BIND_SERVICE);
        caps.insert(Capability::CAP_NET_RAW);
        switch_user(username, groupname, Some(&caps))
    }

    #[inline]
    fn switch_user(
        username: &str,
        groupname: Option<&str>,
        caps: Option<&HashSet<Capability>>,
    ) -> io::Result<users::switch::SwitchUserGuard> {
        use users::{get_group_by_name, get_user_by_name, switch::switch_user_group};

        let user = get_user_by_name(username);

        let group = groupname.map(get_group_by_name).unwrap_or_default();

        match (user, group) {
            (Some(user), None) => switch_user_group(user.uid(), user.primary_group_id()),
            (Some(user), Some(group)) => switch_user_group(user.uid(), group.gid()),
            _ => Err(io::ErrorKind::Other.into()),
        }
        .map(|guard| {
            if let Some(caps) = caps {
                caps::set(None, CapSet::Effective, caps).unwrap();
                caps::set(None, CapSet::Permitted, caps).unwrap();
            }
            guard
        })
    }
}
