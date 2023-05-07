#![allow(dead_code)]

use cli::*;
use dns_conf::BindServer;
use std::{io, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, UdpSocket},
    runtime,
};

mod cli;
mod collections;
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
mod dns_mw_ns;
mod dns_mw_zone;
mod dns_rule;
mod dns_server;
mod dns_url;
mod dnsmasq;
mod infra;
mod log;
mod preset_ns;
mod proxy;
mod rustls;
mod service;
mod third_ext;
mod trust_dns;

use dns_mw::DnsMiddlewareBuilder;
use dns_mw_addr::AddressMiddleware;
use dns_mw_audit::DnsAuditMiddleware;
use dns_mw_bogus::DnsBogusMiddleware;
use dns_mw_cache::DnsCacheMiddleware;
use dns_mw_cname::DnsCNameMiddleware;
use dns_mw_dnsmasq::DnsmasqMiddleware;
use dns_mw_dualstack::DnsDualStackIpSelectionMiddleware;
use dns_mw_ns::NameServerMiddleware;
use dns_mw_zone::DnsZoneMiddleware;
use infra::middleware;

use crate::{dns_client::DnsClient, dns_conf::SmartDnsConfig, dns_server::ServerRegistry};
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

    let cfg = SmartDnsConfig::load(conf);

    let _guard = if cfg.log_enabled() {
        Some(log::init_global_default(
            cfg.log_file(),
            cfg.log_level(),
            cfg.log_filter(),
            cfg.log_size(),
            cfg.log_num(),
            cfg.audit_file_mode().into(),
        ))
    } else {
        None
    };

    cfg.summary();

    #[cfg(target_os = "linux")]
    let _user_guard = {
        if let Some(user) = cfg.user() {
            run_user::with(user, None)
                .unwrap_or_else(|err| {
                    panic!("run with user {} failed. {}", user, err);
                })
                .into()
        } else {
            None
        }
    };

    let runtime = {
        let mut builder = runtime::Builder::new_multi_thread();
        builder.enable_all();
        if let Some(num_workers) = cfg.num_workers() {
            builder.worker_threads(num_workers);
        }
        builder
            .thread_name("smartdns-runtime")
            .build()
            .expect("failed to initialize Tokio Runtime")
    };

    // build handle pipeline.
    let middleware = {
        let _guard = runtime.enter();

        let mut middleware_builder = DnsMiddlewareBuilder::new();

        // check if audit enabled.
        if cfg.audit_enable() && cfg.audit_file().is_some() {
            middleware_builder = middleware_builder.with(DnsAuditMiddleware::new(
                cfg.audit_file().unwrap(),
                cfg.audit_size(),
                cfg.audit_num(),
                cfg.audit_file_mode().into(),
            ));
        }

        if !cfg.cnames().is_empty() {
            middleware_builder = middleware_builder.with(DnsCNameMiddleware);
        }

        middleware_builder = middleware_builder.with(DnsZoneMiddleware::new(&cfg));

        middleware_builder = middleware_builder.with(AddressMiddleware);

        if cfg
            .dnsmasq_lease_file()
            .map(|x| x.is_file())
            .unwrap_or_default()
        {
            middleware_builder = middleware_builder.with(DnsmasqMiddleware::new(
                cfg.dnsmasq_lease_file().unwrap(),
                cfg.domain().cloned(),
            ));
        }

        // check if cache enabled.
        if cfg.cache_size() > 0 {
            middleware_builder = middleware_builder.with(DnsCacheMiddleware::new());
        }

        middleware_builder = middleware_builder.with(DnsDualStackIpSelectionMiddleware);

        if !cfg.bogus_nxdomain().is_empty() {
            middleware_builder = middleware_builder.with(DnsBogusMiddleware);
        }

        middleware_builder = middleware_builder.with(NameServerMiddleware::new(
            runtime.block_on(cfg.create_dns_client()),
        ));

        Arc::new(middleware_builder.build(cfg.clone()))
    };

    let tcp_idle_time = cfg.tcp_idle_time();
    let mut server = ServerRegistry::new(middleware);

    // load udp the listeners
    for bind in cfg.binds() {
        let _guard = runtime.enter();
        let udp_socket = bind_to(udp, bind.sock_addr, bind.device(), "UDP");

        server
            .with_opts(bind.opts.clone())
            .register_socket(udp_socket);
    }

    // and TCP as necessary
    for bind in cfg.binds_tcp() {
        let _guard = runtime.enter();
        let tcp_listener = bind_to(tcp, bind.sock_addr, bind.device(), "TCP");

        server
            .with_opts(bind.opts.clone())
            .register_listener(tcp_listener, Duration::from_secs(tcp_idle_time));
    }

    #[cfg(feature = "dns-over-tls")]
    serve_tls(
        &mut server,
        cfg.binds_tls(),
        &runtime,
        tcp_idle_time,
        cfg.bind_cert_file(),
        cfg.bind_cert_key_file(),
    );
    #[cfg(feature = "dns-over-https")]
    serve_https(
        &mut server,
        cfg.binds_https(),
        &runtime,
        tcp_idle_time,
        cfg.bind_cert_file(),
        cfg.bind_cert_key_file(),
    );
    #[cfg(feature = "dns-over-quic")]
    serve_quic(
        &mut server,
        cfg.binds_quic(),
        &runtime,
        tcp_idle_time,
        cfg.bind_cert_file(),
        cfg.bind_cert_key_file(),
    );

    // config complete, starting!

    banner();

    info!("awaiting connections...");

    info!("server starting up");

    runtime.block_on(async move {
        let _ = signal::terminate().await;
        let _ = server.abort().await;
    });

    runtime.shutdown_timeout(Duration::from_secs(5));

    info!("{} {} shutdown", NAME, version());
}

#[cfg(feature = "dns-over-tls")]
fn serve_tls(
    server: &mut ServerRegistry,
    binds: &[BindServer],
    runtime: &runtime::Runtime,
    tcp_idle_time: u64,
    certificate: Option<&std::path::Path>,
    certificate_key: Option<&std::path::Path>,
) {
    use trust_dns_proto::rustls::tls_server::{read_cert, read_key};

    for bind in binds {
        if bind.ssl_config.is_none() {
            continue;
        }
        let ssl_config = bind.ssl_config.as_ref().unwrap();

        let certificate = ssl_config
            .certificate
            .as_deref()
            .or(certificate)
            .expect("A certificate file must be specified for binding TLS");
        let certificate_key = ssl_config
            .certificate_key
            .as_deref()
            .or(certificate_key)
            .expect("A certificate key file must be specified for binding TLS");

        if let Some(server_name) = ssl_config.server_name.as_deref() {
            info!(
                "loading cert for DNS over TLS named {} from {:?}",
                server_name, certificate
            );
        } else {
            info!("loading cert for DNS over TLS from {:?}", certificate);
        }

        let certificate = read_cert(certificate).expect("error loading tls certificate file");
        let certificate_key =
            read_key(certificate_key).expect("error loading tls certificate_key file");

        let _guard = runtime.enter();

        let tls_listener = bind_to(tcp, bind.sock_addr, bind.device(), "TLS");

        server
            .with_opts(bind.opts.clone())
            .register_tls_listener(
                tls_listener,
                Duration::from_secs(tcp_idle_time),
                (certificate.clone(), certificate_key.clone()),
            )
            .expect("could not register TLS listener");
    }
}

#[cfg(feature = "dns-over-https")]
fn serve_https(
    server: &mut ServerRegistry,
    binds: &[BindServer],
    runtime: &runtime::Runtime,
    tcp_idle_time: u64,
    certificate: Option<&std::path::Path>,
    certificate_key: Option<&std::path::Path>,
) {
    use trust_dns_proto::rustls::tls_server::{read_cert, read_key};

    for bind in binds {
        if bind.ssl_config.is_none() {
            continue;
        }
        let ssl_config = bind.ssl_config.as_ref().unwrap();

        let certificate = ssl_config
            .certificate
            .as_deref()
            .or(certificate)
            .expect("A certificate file must be specified for binding HTTPS");
        let certificate_key = ssl_config
            .certificate_key
            .as_deref()
            .or(certificate_key)
            .expect("A certificate key file must be specified for binding HTTPS");

        if let Some(server_name) = ssl_config.server_name.as_deref() {
            info!(
                "loading cert for DNS over HTTPS named {} from {:?}",
                server_name, certificate
            );
        } else {
            info!("loading cert for DNS over HTTPS from {:?}", certificate);
        }

        let certificate = read_cert(certificate).expect("error loading tls certificate file");
        let certificate_key =
            read_key(certificate_key).expect("error loading tls certificate_key file");

        let _guard = runtime.enter();

        let https_listener = bind_to(tcp, bind.sock_addr, bind.device(), "HTTPS");

        server
            .with_opts(bind.opts.clone())
            .register_https_listener(
                https_listener,
                Duration::from_secs(tcp_idle_time),
                (certificate.clone(), certificate_key.clone()),
                ssl_config.server_name.clone(),
            )
            .expect("could not register HTTPS listener");
    }
}

#[cfg(feature = "dns-over-quic")]
fn serve_quic(
    server: &mut ServerRegistry,
    binds: &[BindServer],
    runtime: &runtime::Runtime,
    tcp_idle_time: u64,
    certificate: Option<&std::path::Path>,
    certificate_key: Option<&std::path::Path>,
) {
    use trust_dns_proto::rustls::tls_server::{read_cert, read_key};

    for bind in binds {
        if bind.ssl_config.is_none() {
            continue;
        }
        let ssl_config = bind.ssl_config.as_ref().unwrap();

        let certificate = ssl_config
            .certificate
            .as_deref()
            .or(certificate)
            .expect("A certificate file must be specified for binding QUIC");
        let certificate_key = ssl_config
            .certificate_key
            .as_deref()
            .or(certificate_key)
            .expect("A certificate key file must be specified for binding QUIC");

        if let Some(server_name) = ssl_config.server_name.as_deref() {
            info!(
                "loading cert for DNS over QUIC named {} from {:?}",
                server_name, certificate
            );
        } else {
            info!("loading cert for DNS over QUIC from {:?}", certificate);
        }

        let certificate = read_cert(certificate).expect("error loading tls certificate file");
        let certificate_key =
            read_key(certificate_key).expect("error loading tls certificate_key file");

        let _guard = runtime.enter();
        let quic_listener = bind_to(udp, bind.sock_addr, bind.device(), "QUIC");

        server
            .with_opts(bind.opts.clone())
            .register_quic_listener(
                quic_listener,
                Duration::from_secs(tcp_idle_time),
                (certificate.clone(), certificate_key.clone()),
                ssl_config.server_name.clone(),
            )
            .expect("could not register QUIC listener");
    }
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
        let servers = self.servers().clone();
        let ca_path = self.ca_path();
        let ca_file = self.ca_file();
        let proxies = self.proxies().clone();

        let mut builder = DnsClient::builder();
        builder = builder.add_servers(servers.values().flat_map(|s| s.clone()).collect::<Vec<_>>());
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
