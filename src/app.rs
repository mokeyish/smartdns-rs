use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustls::{Certificate, PrivateKey};
use tokio::{runtime::Runtime, sync::RwLock};

use crate::{
    config::{IListener, Listener},
    dns_conf::{SmartDnsConfig, SslConfig},
    dns_mw::DnsMiddlewareHandler,
    dns_server::DnsServerHandler,
    error::Error,
    libdns::{proto::error::ProtoError, server::ServerFuture},
    log,
    third_ext::FutureJoinAllExt,
};

pub struct App {
    cfg: RwLock<Arc<SmartDnsConfig>>,
    handler: RwLock<Arc<DnsMiddlewareHandler>>,
    listener_map: Arc<RwLock<HashMap<crate::config::Listener, ServerTasks>>>,
    runtime: Runtime,
    guard: AppGuard,
}

impl App {
    pub fn new(conf: Option<PathBuf>) -> Self {
        let cfg = SmartDnsConfig::load(conf);

        let guard = {
            let log_guard = if cfg.log_enabled() {
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

            #[cfg(target_os = "linux")]
            let user_guard = {
                if let Some(user) = cfg.user() {
                    use crate::run_user;
                    run_user::with(user, None)
                        .unwrap_or_else(|err| {
                            panic!("run with user {} failed. {}", user, err);
                        })
                        .into()
                } else {
                    None
                }
            };

            AppGuard {
                log_guard,
                #[cfg(target_os = "linux")]
                user_guard,
            }
        };

        cfg.summary();

        let runtime = {
            use tokio::runtime;
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

        let handler = create_middleware_handler(cfg.clone(), &runtime);

        Self {
            cfg: RwLock::new(cfg),
            handler: RwLock::new(Arc::new(handler)),
            runtime,
            listener_map: Default::default(),
            guard,
        }
    }

    pub fn bootstrap(self) {
        self.runtime.block_on(self.register_listeners());

        crate::banner();

        log::info!("awaiting connections...");

        log::info!("server starting up");

        let listeners = self.listener_map.clone();

        let shutdown_timeout = Duration::from_secs(5);

        self.runtime.block_on(async move {
            use crate::signal;
            let _ = signal::terminate().await;
            // close all servers.
            let mut listeners = listeners.write().await;
            let shutdown_tasks = listeners.iter_mut().map(|(_, server)| async move {
                match server.shutdown(shutdown_timeout).await {
                    Ok(_) => (),
                    Err(err) => log::warn!("{:?}", err),
                }
            });
            shutdown_tasks.join_all().await;
        });

        self.runtime.shutdown_timeout(shutdown_timeout);
    }

    async fn register_listeners(&self) {
        let cfg = self.cfg.read().await.clone();

        let listener_map = self.listener_map.clone();

        let listeners = {
            let listener_map = listener_map.read().await;
            cfg.listeners()
                .iter()
                .filter(|l| !listener_map.contains_key(l))
                .collect::<Vec<_>>()
        };

        for listener in listeners {
            match create_listener(self, listener).await {
                Ok(server) => {
                    if let Some(mut prev_server) =
                        listener_map.write().await.insert(listener.clone(), server)
                    {
                        tokio::spawn(async move {
                            let _ = prev_server.shutdown(Duration::from_secs(5)).await;
                        });
                    }
                }
                Err(err) => {
                    log::error!("{}", err)
                }
            }
        }
    }
}

async fn create_listener(
    app: &App,
    listener: &crate::config::Listener,
) -> Result<ServerTasks, crate::Error> {
    use crate::{bind_to, tcp, udp};
    let handler = app.handler.read().await.clone();

    let server_handler = DnsServerHandler::new(handler, listener.server_opts().clone());

    let cfg = app.cfg.read().await.clone();

    let tcp_idle_time = cfg.tcp_idle_time();

    let server = match listener {
        Listener::Udp(listener) => {
            let udp_socket = bind_to(udp, listener.sock_addr(), listener.device(), "UDP");
            let mut server = ServerFuture::new(server_handler);
            server.register_socket(udp_socket);
            ServerTasks::Future(server)
        }
        Listener::Tcp(listener) => {
            let tcp_listener = bind_to(tcp, listener.sock_addr(), listener.device(), "TCP");
            let mut server = ServerFuture::new(server_handler);
            server.register_listener(tcp_listener, Duration::from_secs(tcp_idle_time));

            ServerTasks::Future(server)
        }
        #[cfg(feature = "dns-over-tls")]
        Listener::Tls(listener) => {
            const LISTENER_TYPE: &str = "DNS over TLS";
            let ssl_config = &listener.ssl_config;

            let (certificate, certificate_key) = load_certificate_and_key(
                ssl_config,
                cfg.bind_cert_file(),
                cfg.bind_cert_key_file(),
                LISTENER_TYPE,
            )?;

            let tls_listener = bind_to(tcp, listener.sock_addr(), listener.device(), LISTENER_TYPE);

            let mut server = ServerFuture::new(server_handler);
            server
                .register_tls_listener(
                    tls_listener,
                    Duration::from_secs(tcp_idle_time),
                    (certificate.clone(), certificate_key.clone()),
                )
                .map_err(|err| {
                    crate::Error::RegisterListenerFailed(
                        LISTENER_TYPE,
                        listener.sock_addr(),
                        err.to_string(),
                    )
                })?;

            ServerTasks::Future(server)
        }
        #[cfg(feature = "dns-over-https")]
        Listener::Https(listener) => {
            const LISTENER_TYPE: &str = "DNS over HTTPS";
            let ssl_config = &listener.ssl_config;

            let (certificate, certificate_key) = load_certificate_and_key(
                ssl_config,
                cfg.bind_cert_file(),
                cfg.bind_cert_key_file(),
                LISTENER_TYPE,
            )?;

            let https_listener =
                bind_to(tcp, listener.sock_addr(), listener.device(), LISTENER_TYPE);

            let handle = axum_server::Handle::new();
            let handle_clone = handle.clone();

            let server_opts = listener.server_opts().clone();

            tokio::spawn(async move {
                let _ = crate::api::register_https(
                    https_listener,
                    server_handler,
                    server_opts,
                    certificate,
                    certificate_key,
                    handle_clone,
                )
                .await
                .map_err(crate::libdns::proto::error::ProtoError::from);
            });
            ServerTasks::Handle(handle)
        }
        #[cfg(feature = "dns-over-quic")]
        Listener::Quic(listener) => {
            const LISTENER_TYPE: &str = "DNS over QUIC";
            let ssl_config = &listener.ssl_config;

            let (certificate, certificate_key) = load_certificate_and_key(
                ssl_config,
                cfg.bind_cert_file(),
                cfg.bind_cert_key_file(),
                LISTENER_TYPE,
            )?;

            let quic_listener = bind_to(udp, listener.sock_addr(), listener.device(), "QUIC");

            let mut server = ServerFuture::new(server_handler);
            server
                .register_quic_listener(
                    quic_listener,
                    Duration::from_secs(tcp_idle_time),
                    (certificate.clone(), certificate_key.clone()),
                    ssl_config.server_name.clone(),
                )
                .map_err(|err| {
                    crate::Error::RegisterListenerFailed(
                        LISTENER_TYPE,
                        listener.sock_addr(),
                        err.to_string(),
                    )
                })?;

            ServerTasks::Future(server)
        }
        #[cfg(not(feature = "dns-over-tls"))]
        Listener::Tls(listener) => {
            warn!("Bind DoT not enabled")
        }
        #[cfg(not(feature = "dns-over-https"))]
        Listener::Https(listener) => {
            warn!("Bind DoH not enabled")
        }
        #[cfg(not(feature = "dns-over-quic"))]
        Listener::Quic(listener) => {
            warn!("Bind DoQ not enabled")
        }
    };

    fn load_certificate_and_key(
        ssl_config: &SslConfig,
        cert_file: Option<&Path>,
        key_file: Option<&Path>,
        typ: &'static str,
    ) -> Result<(Vec<Certificate>, PrivateKey), Error> {
        use crate::libdns::proto::rustls::tls_server::{read_cert, read_key};

        let certificate_path = ssl_config
            .certificate
            .as_deref()
            .or(cert_file)
            .ok_or_else(|| Error::CertificatePathNotDefined(typ))?;

        let certificate_key_path = ssl_config
            .certificate_key
            .as_deref()
            .or(key_file)
            .ok_or_else(|| Error::CertificateKeyPathNotDefined(typ))?;

        if let Some(server_name) = ssl_config.server_name.as_deref() {
            log::info!(
                "loading cert for DNS over Https named {} from {:?}",
                server_name,
                certificate_path
            );
        } else {
            log::info!(
                "loading cert for DNS over Https from {:?}",
                certificate_path
            );
        }

        let certificate = read_cert(certificate_path).map_err(|err| {
            Error::LoadCertificateFailed(certificate_path.to_path_buf(), err.to_string())
        })?;

        let certificate_key = read_key(certificate_key_path).map_err(|err| {
            Error::LoadCertificateKeyFailed(certificate_key_path.to_path_buf(), err.to_string())
        })?;

        Ok((certificate, certificate_key))
    }

    Ok(server)
}

fn create_middleware_handler(cfg: Arc<SmartDnsConfig>, runtime: &Runtime) -> DnsMiddlewareHandler {
    use crate::dns_mw::DnsMiddlewareBuilder;
    use crate::dns_mw_addr::AddressMiddleware;
    use crate::dns_mw_audit::DnsAuditMiddleware;
    use crate::dns_mw_bogus::DnsBogusMiddleware;
    use crate::dns_mw_cache::DnsCacheMiddleware;
    use crate::dns_mw_cname::DnsCNameMiddleware;
    use crate::dns_mw_dnsmasq::DnsmasqMiddleware;
    use crate::dns_mw_dualstack::DnsDualStackIpSelectionMiddleware;
    #[cfg(target_os = "linux")]
    use crate::dns_mw_nftset::DnsNftsetMiddleware;
    use crate::dns_mw_ns::NameServerMiddleware;
    use crate::dns_mw_zone::DnsZoneMiddleware;

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
        middleware_builder = middleware_builder.with(DnsCacheMiddleware::new(&cfg));
    }

    // nftset
    #[cfg(target_os = "linux")]
    {
        use crate::config::IpConfig;
        use crate::ffi::nft::Nft;
        let nftsets = cfg.valid_nftsets();
        if !nftsets.is_empty() {
            let nft = Nft::new();
            if nft.avaliable() {
                let mut success = true;
                for i in nftsets {
                    if let Err(err) = match i {
                        IpConfig::V4(c) => nft.add_ipv4_set(c.family, &c.table, &c.name),
                        IpConfig::V6(c) => nft.add_ipv6_set(c.family, &c.table, &c.name),
                        _ => Ok(()),
                    } {
                        log::warn!("nft add set failed, {:?}, skipped", err);
                        success = false;
                        break;
                    }
                }
                if success {
                    middleware_builder = middleware_builder.with(DnsNftsetMiddleware::new(nft));
                }
            } else {
                log::warn!("nft is not avaliable, skipped.",);
            }
        }
    }

    middleware_builder = middleware_builder.with(DnsDualStackIpSelectionMiddleware);

    if !cfg.bogus_nxdomain().is_empty() {
        middleware_builder = middleware_builder.with(DnsBogusMiddleware);
    }

    middleware_builder = middleware_builder.with(NameServerMiddleware::new(
        runtime.block_on(cfg.create_dns_client()),
    ));

    middleware_builder.build(cfg.clone())
}

struct AppGuard {
    log_guard: Option<tracing::dispatcher::DefaultGuard>,
    #[cfg(target_os = "linux")]
    user_guard: Option<users::switch::SwitchUserGuard>,
}

enum ServerTasks {
    Future(ServerFuture<DnsServerHandler>),
    Handle(axum_server::Handle),
}

impl ServerTasks {
    async fn shutdown(&mut self, shutdown_timeout: Duration) -> Result<(), ProtoError> {
        match self {
            ServerTasks::Future(s) => {
                let _ = s.block_until_done().await;
                Ok(())
            }
            ServerTasks::Handle(s) => {
                s.graceful_shutdown(Some(shutdown_timeout));
                Ok(())
            }
        }
    }
}
