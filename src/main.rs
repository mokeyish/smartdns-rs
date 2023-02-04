#![allow(dead_code)]

use cli::*;
use dns_conf::BindServer;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, UdpSocket},
    runtime, signal,
};

mod cli;
mod dns;
mod dns_client;
mod dns_conf;
mod dns_mw;
mod dns_mw_addr;
mod dns_mw_audit;
mod dns_mw_cache;
mod dns_mw_ns;
mod dns_mw_spdt;
mod dns_mw_zone;
mod dns_server;
mod dns_url;
mod fast_ping;
mod infra;
mod log;
mod matcher;
mod preset_ns;
mod service;
mod third_ext;
mod trust_dns;

use dns_mw::DnsMiddlewareBuilder;
use dns_mw_addr::AddressMiddleware;
use dns_mw_audit::DnsAuditMiddleware;
use dns_mw_cache::DnsCacheMiddleware;
use dns_mw_ns::NameServerMiddleware;
use dns_mw_spdt::DnsSpeedTestMiddleware;
use dns_mw_zone::DnsZoneMiddleware;
use dns_server::{MiddlewareBasedRequestHandler, ServerFuture};
use infra::middleware;

use crate::{
    dns_client::DnsClient, dns_conf::SmartDnsConfig, matcher::DomainNameServerGroupMatcher,
};
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
const NAME: &'static str = "SmartDNS";

/// The default configuration.
const DEFAULT_CONF: &'static str = include_str!("../etc/smartdns/smartdns.conf");

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
                                    info!("\n{}", out);
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
            cfg.log_size(),
            cfg.log_num(),
        ))
    } else {
        None
    };

    cfg.summary();

    #[cfg(target_os = "linux")]
    let _user_guard = {
        if let Some(user) = cfg.user.as_ref() {
            run_user::with(user.as_str(), None)
                .unwrap_or_else(|err| {
                    panic!("run with user {} failed. {}", user.as_str(), err);
                })
                .into()
        } else {
            None
        }
    };

    let runtime = runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .thread_name("smartdns-runtime")
        .build()
        .expect("failed to initialize Tokio Runtime");

    let udp_socket_addrs = cfg.binds.clone().into_iter().map(|s| s.addr).flatten();
    let tcp_socket_addrs = cfg.binds_tcp.clone().into_iter().map(|s| s.addr).flatten();

    // build handle pipeline.
    let middleware = {
        let _guard = runtime.enter();
        let dns_client = Arc::new(DnsClient::new(
            DomainNameServerGroupMatcher::create(&cfg),
            cfg.servers.clone(),
            cfg.ca_path.clone(),
            cfg.ca_file.clone(),
        ));

        let mut middleware_builder = DnsMiddlewareBuilder::new();

        // check if audit enabled.
        if cfg.audit_enable && cfg.audit_file.is_some() {
            middleware_builder = middleware_builder.with(DnsAuditMiddleware::new(
                cfg.audit_file.as_ref().unwrap(),
                cfg.audit_size(),
                cfg.audit_num(),
            ));
        }

        middleware_builder = middleware_builder.with(DnsZoneMiddleware::new(&cfg));

        if cfg.address_rules.len() > 0 {
            middleware_builder = middleware_builder.with(AddressMiddleware::new(&cfg));
        }

        // check if cache enabled.
        if cfg.cache_size() > 0 {
            middleware_builder =
                middleware_builder.with(DnsCacheMiddleware::new(&cfg, dns_client.clone()));
        }

        // check if speed_check enabled.
        if !cfg.speed_check_mode.is_empty() {
            middleware_builder = middleware_builder.with(DnsSpeedTestMiddleware);
        }

        middleware_builder = middleware_builder.with(NameServerMiddleware::new(&cfg));

        MiddlewareBasedRequestHandler::new(
            middleware_builder.build(cfg.clone(), dns_client.clone()),
        )
    };

    let mut server = ServerFuture::new(middleware);

    // load udp the listeners
    for udp_socket in udp_socket_addrs {
        debug!("binding UDP to {:?}", udp_socket);
        let udp_socket = runtime
            .block_on(UdpSocket::bind(udp_socket))
            .unwrap_or_else(|_| panic!("could not bind to udp: {}", udp_socket));

        info!(
            "listening for UDP on {:?}",
            udp_socket
                .local_addr()
                .expect("could not lookup local address")
        );

        let _guard = runtime.enter();
        server.register_socket(udp_socket);
    }

    // and TCP as necessary
    for tcp_listener in tcp_socket_addrs {
        debug!("binding TCP to {:?}", tcp_listener);
        let tcp_listener = runtime
            .block_on(TcpListener::bind(tcp_listener))
            .unwrap_or_else(|_| panic!("could not bind to tcp: {}", tcp_listener));

        info!(
            "listening for TCP on {:?}",
            tcp_listener
                .local_addr()
                .expect("could not lookup local address")
        );

        let _guard = runtime.enter();
        server.register_listener(tcp_listener, Duration::from_secs(cfg.tcp_idle_time()));
    }

    #[cfg(feature = "dns-over-tls")]
    serve_tls(&cfg, &mut server, &cfg.binds_tls, &runtime);
    #[cfg(feature = "dns-over-https")]
    serve_https(&cfg, &mut server, &cfg.binds_https, &runtime);
    #[cfg(feature = "dns-over-quic")]
    serve_quic(&cfg, &mut server, &cfg.binds_quic, &runtime);

    // config complete, starting!

    banner();

    info!("awaiting connections...");

    info!("Server starting up");

    runtime.block_on(async {
        signal::ctrl_c().await.unwrap();
        // we're exiting for some reason...
        info!("{} {} shutdown", NAME, version());
    });

    drop(runtime);
}

#[cfg(feature = "dns-over-tls")]
fn serve_tls(
    cfg: &SmartDnsConfig,
    server: &mut ServerFuture<MiddlewareBasedRequestHandler>,
    binds: &[BindServer],
    runtime: &runtime::Runtime,
) {
    use futures::TryFutureExt;
    use trust_dns_proto::rustls::tls_server::{read_cert, read_key};

    for bind in binds {
        if bind.ssl_config.is_none() {
            continue;
        }
        let ssl_config = bind.ssl_config.as_ref().unwrap();

        info!(
            "loading cert for DNS over TLS named {} from {:?}",
            ssl_config.server_name, ssl_config.certificate
        );

        let certificate = read_cert(ssl_config.certificate.as_path())
            .expect("error loading tls certificate file");
        let certificate_key = read_key(ssl_config.certificate_key.as_path())
            .expect("error loading tls certificate_key file");

        for addr in &bind.addr {
            debug!("binding TLS to {:?}", addr);
            let tls_listener = runtime.block_on(
                TcpListener::bind(addr)
                    .unwrap_or_else(|_| panic!("could not bind to tls: {}", addr)),
            );

            info!(
                "listening for TLS on {:?}",
                tls_listener
                    .local_addr()
                    .expect("could not lookup local address")
            );

            let _guard = runtime.enter();
            server
                .register_tls_listener(
                    tls_listener,
                    Duration::from_secs(cfg.tcp_idle_time()),
                    (certificate.clone(), certificate_key.clone()),
                )
                .expect("could not register TLS listener");
        }
    }
}

#[cfg(feature = "dns-over-https")]
fn serve_https(
    cfg: &SmartDnsConfig,
    server: &mut ServerFuture<MiddlewareBasedRequestHandler>,
    binds: &[BindServer],
    runtime: &runtime::Runtime,
) {
    use futures::TryFutureExt;
    use trust_dns_proto::rustls::tls_server::{read_cert, read_key};

    for bind in binds {
        if bind.ssl_config.is_none() {
            continue;
        }
        let ssl_config = bind.ssl_config.as_ref().unwrap();

        info!(
            "loading cert for DNS over HTTPS named {} from {:?}",
            ssl_config.server_name, ssl_config.certificate
        );

        let server_name = ssl_config.server_name.as_str();

        let certificate = read_cert(ssl_config.certificate.as_path())
            .expect("error loading tls certificate file");
        let certificate_key = read_key(ssl_config.certificate_key.as_path())
            .expect("error loading tls certificate_key file");

        for addr in &bind.addr {
            debug!("binding HTTPS to {:?}", addr);
            let https_listener = runtime.block_on(
                TcpListener::bind(addr)
                    .unwrap_or_else(|_| panic!("could not bind to tls: {}", addr)),
            );

            info!(
                "listening for HTTPS on {:?}",
                https_listener
                    .local_addr()
                    .expect("could not lookup local address")
            );

            let _guard = runtime.enter();
            server
                .register_https_listener(
                    https_listener,
                    Duration::from_secs(cfg.tcp_idle_time()),
                    (certificate.clone(), certificate_key.clone()),
                    server_name.to_string(),
                )
                .expect("could not register HTTPS listener");
        }
    }
}

#[cfg(feature = "dns-over-quic")]
fn serve_quic(
    cfg: &SmartDnsConfig,
    server: &mut ServerFuture<MiddlewareBasedRequestHandler>,
    binds: &[BindServer],
    runtime: &runtime::Runtime,
) {
    use futures::TryFutureExt;
    use trust_dns_proto::rustls::tls_server::{read_cert, read_key};

    for bind in binds {
        if bind.ssl_config.is_none() {
            continue;
        }
        let ssl_config = bind.ssl_config.as_ref().unwrap();

        info!(
            "loading cert for DNS over QUIC named {} from {:?}",
            ssl_config.server_name, ssl_config.certificate
        );

        let server_name = ssl_config.server_name.as_str();

        let certificate = read_cert(ssl_config.certificate.as_path())
            .expect("error loading tls certificate file");
        let certificate_key = read_key(ssl_config.certificate_key.as_path())
            .expect("error loading tls certificate_key file");

        for addr in &bind.addr {
            debug!("binding QUIC to {:?}", addr);
            let quic_listener = runtime.block_on(
                UdpSocket::bind(addr).unwrap_or_else(|_| panic!("could not bind to tls: {}", addr)),
            );

            info!(
                "listening for QUIC on {:?}",
                quic_listener
                    .local_addr()
                    .expect("could not lookup local address")
            );

            let _guard = runtime.enter();
            server
                .register_quic_listener(
                    quic_listener,
                    Duration::from_secs(cfg.tcp_idle_time()),
                    (certificate.clone(), certificate_key.clone()),
                    server_name.to_string(),
                )
                .expect("could not register QUIC listener");
        }
    }
}

#[inline]
fn hello_starting() {
    info!("Smart-DNS 🐋 {} starting", version());
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
