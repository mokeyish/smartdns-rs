use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    runtime::{Handle, Runtime},
    sync::{RwLock, Semaphore},
    task::JoinSet,
};

use crate::{
    config::ServerOpts,
    dns::{DnsRequest, DnsResponse, SerialMessage},
    dns_conf::RuntimeConfig,
    dns_mw::{DnsMiddlewareBuilder, DnsMiddlewareHandler},
    dns_mw_cache::DnsCache,
    log,
    server::{DnsHandle, IncomingDnsRequest, ServerHandle},
    third_ext::FutureJoinAllExt as _,
};

pub struct App {
    cfg: RwLock<Arc<RuntimeConfig>>,
    mw_handler: RwLock<Arc<DnsMiddlewareHandler>>,
    dns_handle: DnsHandle,
    listener_map: Arc<RwLock<HashMap<crate::config::ListenerConfig, ServerHandle>>>,
    cache: RwLock<Option<Arc<DnsCache>>>,
    runtime: Handle,
    guard: AppGuard,
}

impl App {
    fn new(conf: Option<PathBuf>) -> (Runtime, IncomingDnsRequest, Self) {
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
                    cfg.log_config().console.unwrap_or_default(),
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

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(cfg.num_workers())
            .enable_all()
            .thread_name("smartdns-runtime")
            .build()
            .expect("failed to initialize Tokio Runtime");

        let handler = DnsMiddlewareBuilder::new().build(cfg.clone());

        let runtime_handle = runtime.handle().clone();
        let (rx, dns_server_handle) = DnsHandle::new(Default::default());

        (
            runtime,
            rx,
            Self {
                dns_handle: dns_server_handle,
                cfg: RwLock::new(cfg),
                mw_handler: RwLock::new(Arc::new(handler)),
                runtime: runtime_handle,
                listener_map: Default::default(),
                cache: RwLock::const_new(None),
                guard,
            },
        )
    }

    pub async fn get_dns_handler(&self) -> Arc<DnsMiddlewareHandler> {
        self.mw_handler.read().await.clone()
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
        use crate::dns_mw_hosts::DnsHostsMiddleware;
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

            if cfg.resolv_hostanme() {
                middleware_builder = middleware_builder.with(DnsHostsMiddleware::new());
            }

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

            // nftset
            #[cfg(all(feature = "nft", target_os = "linux"))]
            {
                use crate::dns_mw_nftset::DnsNftsetMiddleware;
                middleware_builder = middleware_builder.with(DnsNftsetMiddleware::new());
            }

            // check if cache enabled.
            if cfg.cache_size() > 0 {
                let cache_middleware = DnsCacheMiddleware::new(&cfg, self.dns_handle.clone());
                *self.cache.write().await = Some(cache_middleware.cache().clone());
                middleware_builder = middleware_builder.with(cache_middleware);
            }

            middleware_builder = middleware_builder.with(DnsDualStackIpSelectionMiddleware);

            if !cfg.bogus_nxdomain().is_empty() {
                middleware_builder = middleware_builder.with(DnsBogusMiddleware);
            }

            middleware_builder =
                middleware_builder.with(NameServerMiddleware::new(cfg.create_dns_client().await));

            middleware_builder.build(cfg.clone())
        };

        *self.mw_handler.write().await = Arc::new(middleware_handler);
    }
}

pub fn bootstrap(conf: Option<PathBuf>) {
    let (runtime, mut incoming_request, app) = App::new(conf);
    let app = Arc::new(app);

    let _guarad = runtime.enter();

    runtime.block_on(async {
        app.update_middleware_handler().await;
        register_listeners(&app).await
    });

    crate::banner();

    log::info!("awaiting connections...");

    log::info!("server starting up");

    {
        let app = app.clone();
        runtime.spawn(async move {
            use crate::server::reap_tasks;

            // todo:// manage concurrent requests.

            let mut inner_join_set = JoinSet::new();

            let mut last_activity = Instant::now();

            const MAX_IDLE: Duration = Duration::from_secs(30 * 60); // 30 min

            let background_concurrency = Arc::new(Semaphore::new(1));

            while let Some((message, server_opts, sender)) = incoming_request.recv().await {
                let handler = app.mw_handler.read().await.clone();

                if server_opts.is_background {
                    if Instant::now() - last_activity < MAX_IDLE {
                        let background_concurrency = background_concurrency.clone();
                        inner_join_set.spawn(async move {
                            if let Ok(permit) = background_concurrency.acquire_owned().await {
                                let _ = sender.send(process(handler, message, server_opts).await);
                                drop(permit);
                            }
                        });
                    }
                } else {
                    last_activity = Instant::now();
                    inner_join_set.spawn(async move {
                        let _ = sender.send(process(handler, message, server_opts).await);
                    });
                }

                reap_tasks(&mut inner_join_set);
            }
        });
    }

    let listeners = app.listener_map.clone();

    let shutdown_timeout = Duration::from_secs(5);

    runtime.block_on(async move {
        use crate::signal;
        let _ = signal::terminate().await;
        // close all servers.
        let mut shutdown_listeners = Default::default();
        std::mem::swap(listeners.write().await.deref_mut(), &mut shutdown_listeners);
        shutdown_listeners
            .into_values()
            .map(|server| server.shutdown())
            .join_all()
            .await;
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
        match serve(app, listener).await {
            Ok(server) => {
                if let Some(prev_server) =
                    listener_map.write().await.insert(listener.clone(), server)
                {
                    tokio::spawn(async move {
                        prev_server.shutdown().await;
                    });
                }
            }
            Err(err) => {
                log::error!("{}", err)
            }
        }
    }
}

async fn serve(
    app: &Arc<App>,
    listener: &crate::config::ListenerConfig,
) -> Result<ServerHandle, crate::Error> {
    use crate::server::serve;

    let dns_handle = &app.dns_handle;

    let cfg = app.cfg.read().await.clone();

    let idle_time = cfg.tcp_idle_time();
    let certificate_file = cfg.bind_cert_file();
    let certificate_key_file = cfg.bind_cert_key_file();

    serve(
        app,
        listener,
        dns_handle,
        idle_time,
        certificate_file,
        certificate_key_file,
    )
    .await
}

struct AppGuard {
    log_guard: Option<tracing::dispatcher::DefaultGuard>,
    #[cfg(target_os = "linux")]
    user_guard: Option<crate::run_user::SwitchUserGuard>,
}

async fn process(
    handler: Arc<DnsMiddlewareHandler>,
    message: SerialMessage,
    server_opts: ServerOpts,
) -> SerialMessage {
    use crate::libdns::proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
    use crate::libdns::proto::ProtoError;

    let addr = message.addr();
    let protocol = message.protocol();

    match DnsRequest::try_from(message) {
        Ok(request) => {
            match request.message_type() {
                MessageType::Query => {
                    match request.op_code() {
                        OpCode::Query => {
                            // start process
                            let request_header = request.header();
                            let mut response_header = Header::response_from_request(request_header);

                            response_header.set_recursion_available(true);
                            response_header.set_authoritative(false);

                            let response = {
                                let start = Instant::now();
                                let res = handler.search(&request, &server_opts).await;

                                log::debug!(
                                    "{}Request: {:?}",
                                    if server_opts.is_background {
                                        "Background"
                                    } else {
                                        ""
                                    },
                                    request
                                );
                                match res {
                                    Ok(lookup) => {
                                        log::debug!(
                                            "Response: {}, Duration: {:?}",
                                            lookup.deref(),
                                            start.elapsed()
                                        );
                                        lookup
                                    }
                                    Err(e) => {
                                        if e.is_nx_domain() {
                                            log::debug!("{}Response: error resolving: NXDomain, Duration: {:?}", if server_opts.is_background { "Background"} else { "" }, start.elapsed());
                                            response_header
                                                .set_response_code(ResponseCode::NXDomain);
                                        }
                                        match e.as_soa() {
                                            Some(soa) => soa,
                                            None => {
                                                log::debug!(
                                                    "{}Response: error resolving: {}, Duration: {:?}",
                                                    if server_opts.is_background { "Background"} else { "" },
                                                    e,
                                                    start.elapsed()
                                                );
                                                DnsResponse::empty()
                                            }
                                        }
                                    }
                                }
                            };

                            let response_message: Message =
                                response.into_message(Some(response_header));

                            SerialMessage::raw(response_message, addr, protocol)
                        }
                        OpCode::Status => todo!(),
                        OpCode::Notify => todo!(),
                        OpCode::Update => todo!(),
                        OpCode::Unknown(_) => todo!(),
                    }
                }
                MessageType::Response => todo!(),
            }
        }
        Err(ProtoError { kind, .. }) if kind.as_form_error().is_some() => {
            // We failed to parse the request due to some issue in the message, but the header is available, so we can respond
            let (request_header, error) = kind
                .into_form_error()
                .expect("as form_error already confirmed this is a FormError");

            // debug for more info on why the message parsing failed
            log::debug!(
                "request:{id} src:{proto}://{addr}#{port} type:{message_type} {op}:FormError:{error}",
                id = request_header.id(),
                proto = protocol,
                addr = addr.ip(),
                port = addr.port(),
                message_type= request_header.message_type(),
                op = request_header.op_code(),
                error = error,
            );

            let mut response_header = Header::response_from_request(&request_header);
            response_header.set_response_code(ResponseCode::FormErr);
            let mut response_message = Message::new();
            response_message.set_header(response_header);
            SerialMessage::raw(response_message, addr, protocol)
        }
        _ => SerialMessage::raw(Default::default(), addr, protocol),
    }
}
