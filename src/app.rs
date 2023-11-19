use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustls::{Certificate, PrivateKey};
use tokio::{
    runtime::{Handle, Runtime},
    sync::RwLock,
};

use crate::{
    config::{IListener, Listener, SslConfig},
    dns_conf::RuntimeConfig,
    dns_mw::{DnsMiddlewareBuilder, DnsMiddlewareHandler},
    dns_mw_cache::DnsCache,
    dns_server::DnsServerHandler,
    error::Error,
    libdns::{proto::error::ProtoError, server::ServerFuture},
    log,
    third_ext::FutureJoinAllExt,
};

pub struct App {
    cfg: RwLock<Arc<RuntimeConfig>>,
    handler: RwLock<Arc<DnsMiddlewareHandler>>,
    listener_map: Arc<RwLock<HashMap<crate::config::Listener, ServerTasks>>>,
    cache: RwLock<Option<Arc<DnsCache>>>,
    runtime: Handle,
    guard: AppGuard,
}

impl App {
    fn new(conf: Option<PathBuf>) -> (Runtime, Self) {
        let cfg = RuntimeConfig::load(conf);

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

        let handler = DnsMiddlewareBuilder::new().build(cfg.clone());

        let runtime_handle = runtime.handle().clone();

        (
            runtime,
            Self {
                cfg: RwLock::new(cfg),
                handler: RwLock::new(Arc::new(handler)),
                runtime: runtime_handle,
                listener_map: Default::default(),
                cache: RwLock::const_new(None),
                guard,
            },
        )
    }

    pub async fn get_dns_handler(&self) -> Arc<DnsMiddlewareHandler> {
        self.handler.read().await.clone()
    }

    pub async fn cache(&self) -> Option<Arc<DnsCache>> {
        self.cache.read().await.clone()
    }

    pub async fn cfg(&self) -> Arc<RuntimeConfig> {
        self.cfg.read().await.clone()
    }

    async fn update_middleware_handler(&self) {
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

        let cfg = self.cfg.read().await.clone();

        let middleware_handler = {
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
                let cache_middleware = DnsCacheMiddleware::new(&cfg);
                *self.cache.write().await = Some(cache_middleware.cache().clone());
                middleware_builder = middleware_builder.with(cache_middleware);
            }

            // nftset
            #[cfg(target_os = "linux")]
            {
                use crate::config::ConfigForIP;
                use crate::ffi::nft::Nft;
                let nftsets = cfg.valid_nftsets();
                if !nftsets.is_empty() {
                    let nft = Nft::new();
                    if nft.avaliable() {
                        let mut success = true;
                        for i in nftsets {
                            if let Err(err) = match i {
                                ConfigForIP::V4(c) => nft.add_ipv4_set(c.family, &c.table, &c.name),
                                ConfigForIP::V6(c) => nft.add_ipv6_set(c.family, &c.table, &c.name),
                                _ => Ok(()),
                            } {
                                log::warn!("nft add set failed, {:?}, skipped", err);
                                success = false;
                                break;
                            }
                        }
                        if success {
                            middleware_builder =
                                middleware_builder.with(DnsNftsetMiddleware::new(nft));
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

            middleware_builder =
                middleware_builder.with(NameServerMiddleware::new(cfg.create_dns_client().await));

            middleware_builder.build(cfg.clone())
        };

        *self.handler.write().await = Arc::new(middleware_handler);
    }
}

pub fn bootstrap(conf: Option<PathBuf>) {
    let (runtime, app) = App::new(conf);
    let app = Arc::new(app);

    let _guarad = runtime.enter();

    runtime.block_on(async {
        app.update_middleware_handler().await;
        register_listeners(&app).await
    });

    crate::banner();

    log::info!("awaiting connections...");

    log::info!("server starting up");

    let listeners = app.listener_map.clone();

    let shutdown_timeout = Duration::from_secs(5);

    runtime.block_on(async move {
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

    runtime.shutdown_timeout(shutdown_timeout);
}

async fn register_listeners(app: &Arc<App>) {
    let cfg = app.cfg.read().await.clone();

    let listener_map = app.listener_map.clone();

    let listeners = {
        let listener_map = listener_map.read().await;
        cfg.listeners()
            .iter()
            .filter(|l| !listener_map.contains_key(l))
            .collect::<Vec<_>>()
    };

    for listener in listeners {
        match create_listener(app, listener).await {
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

async fn create_listener(
    app: &Arc<App>,
    listener: &crate::config::Listener,
) -> Result<ServerTasks, crate::Error> {
    use crate::{bind_to, tcp, udp};

    let server_handler = DnsServerHandler::new(app.clone(), listener.server_opts().clone());

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
            {
                let handle = handle.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let _ = crate::api::register_https(
                        app,
                        server_handler,
                        https_listener,
                        certificate,
                        certificate_key,
                        handle,
                    )
                    .await
                    .map_err(crate::libdns::proto::error::ProtoError::from);
                });
            }
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
