use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{RwLock, Semaphore},
    task::JoinSet,
};

use crate::{
    config::ServerOpts,
    dns::{DnsRequest, DnsResponse, SerialMessage},
    dns_client::DnsClient,
    dns_conf::RuntimeConfig,
    dns_mw::{DnsMiddlewareBuilder, DnsMiddlewareHandler},
    dns_mw_cache::DnsCache,
    log,
    server::{DnsHandle, IncomingDnsRequest, ServerHandle},
    third_ext::FutureJoinAllExt as _,
};

#[derive(Clone)]
pub struct App(Arc<AppState>);

impl App {
    fn new(directory: Option<PathBuf>, conf: Option<PathBuf>) -> (IncomingDnsRequest, Self) {
        let cfg = RuntimeConfig::load(directory, conf);

        let guard = {
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
                #[cfg(target_os = "linux")]
                user_guard,
            }
        };

        let handler = DnsMiddlewareBuilder::new().build(cfg.clone());

        let (rx, dns_handle) = DnsHandle::new();

        (
            rx,
            Self(
                AppState {
                    dns_handle,
                    cfg: RwLock::new(cfg),
                    mw_handler: RwLock::new(Arc::new(handler)),
                    listeners: Default::default(),
                    cache: RwLock::const_new(None),
                    uptime: Instant::now(),
                    loaded_at: RwLock::const_new(Instant::now()),
                    active_queries: Default::default(),
                    guard,
                }
                .into(),
            ),
        )
    }

    pub async fn cache(&self) -> Option<Arc<DnsCache>> {
        self.cache.read().await.clone()
    }

    pub async fn cfg(&self) -> Arc<RuntimeConfig> {
        self.cfg.read().await.clone()
    }

    pub async fn reload(&self) -> anyhow::Result<()> {
        log::info!("reloading configuration...");
        let cfg = self.cfg().await;
        let cfg = cfg.reload_new()?;
        *self.cfg.write().await = cfg;
        self.update_middleware_handler().await;
        self.update_listeners().await;
        *self.loaded_at.write().await = Instant::now();
        log::info!("configuration reloaded");
        Ok(())
    }

    pub async fn loaded_at(&self) -> Duration {
        let now = Instant::now();
        now.duration_since(*self.loaded_at.read().await)
    }

    pub fn uptime(&self) -> Duration {
        let now = Instant::now();
        now.duration_since(self.uptime)
    }

    pub fn active_queries(&self) -> usize {
        self.active_queries.load(Ordering::Relaxed)
    }

    async fn init(&self) {
        self.cfg().await.summary();
        self.update_middleware_handler().await;
        self.update_listeners().await;
        crate::banner();
        log::info!("awaiting connections...");
        log::info!("server starting up");
    }

    async fn update_listeners(&self) {
        use crate::server;

        let cfg = self.cfg().await;

        let (new_bind_addrs, shutdowns) = {
            let listeners = self.listeners.read().await;
            let new_bind_addrs = cfg
                .binds()
                .iter()
                .filter(|l| !listeners.contains_key(l))
                .collect::<Vec<_>>();

            let shutdowns = listeners
                .keys()
                .filter(|l| !cfg.binds().contains(l))
                .cloned()
                .collect::<Vec<_>>();

            (new_bind_addrs, shutdowns)
        };

        if !shutdowns.is_empty() {
            let mut listeners = self.listeners.write().await;
            let shutdowns = shutdowns
                .iter()
                .flat_map(|k| listeners.remove(k))
                .collect::<Vec<_>>();
            tokio::spawn(async move {
                for shutdown in shutdowns {
                    shutdown.shutdown().await;
                }
            });
        }

        if !new_bind_addrs.is_empty() {
            let dns_handle = &self.dns_handle;

            let idle_time = cfg.tcp_idle_time();
            let certificate_file = cfg.bind_cert_file();
            let certificate_key_file = cfg.bind_cert_key_file();

            for bind_addr in new_bind_addrs {
                let serve_handle = server::serve(
                    self,
                    &cfg,
                    bind_addr,
                    dns_handle,
                    idle_time,
                    certificate_file,
                    certificate_key_file,
                );

                match serve_handle {
                    Ok(server) => {
                        if let Some(prev_server) = self
                            .listeners
                            .write()
                            .await
                            .insert(bind_addr.clone(), server)
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
    }

    async fn update_middleware_handler(&self) {
        let cfg = self.cfg.read().await.clone();
        let mut cache = self.cache.write().await;
        let middleware_handler = build_middleware(
            &cfg,
            &self.dns_handle,
            cfg.create_dns_client().await,
            &mut cache,
        );

        *self.mw_handler.write().await = middleware_handler;
    }
}

impl std::ops::Deref for App {
    type Target = AppState;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

pub struct AppState {
    cfg: RwLock<Arc<RuntimeConfig>>,
    mw_handler: RwLock<Arc<DnsMiddlewareHandler>>,
    dns_handle: DnsHandle,
    listeners: RwLock<HashMap<crate::config::BindAddrConfig, ServerHandle>>,
    cache: RwLock<Option<Arc<DnsCache>>>,
    uptime: Instant,
    loaded_at: RwLock<Instant>,
    active_queries: AtomicUsize,
    guard: AppGuard,
}

pub fn serve(directory: Option<PathBuf>, conf: Option<PathBuf>) {
    crate::hello_starting();
    let (mut incoming_request, app) = App::new(directory, conf);
    let app = Arc::new(app);

    let cfg = app.cfg.blocking_read().clone();

    let log_dispatch = log::make_dispatch(
        cfg.log_file(),
        cfg.log_enabled(),
        cfg.log_level(),
        cfg.log_filter(),
        cfg.log_size(),
        cfg.log_num(),
        cfg.log_file_mode().into(),
        cfg.log_config().console(),
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.num_workers())
        .enable_all()
        .thread_name("smartdns-runtime")
        .on_thread_start(move || {
            log::LOG_GUARD.replace(Some(log::set_default(&log_dispatch)));
        })
        .on_thread_stop(move || {
            log::LOG_GUARD.take();
        })
        .build()
        .expect("failed to initialize Tokio Runtime");

    let _guard = runtime.enter();

    runtime.block_on(app.init());

    {
        let app = app.clone();
        runtime.spawn(async move {
            use futures::{FutureExt, StreamExt, stream::FuturesUnordered};

            // todo:// manage concurrent requests.

            let mut inner_join_set = JoinSet::new();

            let mut last_activity = Instant::now();

            const MAX_IDLE: Duration = Duration::from_secs(30 * 60); // 30 min

            const BATCH_SIZE: usize = 256;

            let background_concurrency = Arc::new(Semaphore::new(1));
            let mut bg_batch = FuturesUnordered::new();
            let mut requests = Vec::with_capacity(BATCH_SIZE);

            loop {
                let count = incoming_request.recv_many(&mut requests, BATCH_SIZE).await;
                if count == 0 {
                    continue;
                }

                app.active_queries.fetch_add(count, Ordering::Relaxed);

                let handler = app.mw_handler.read().await.clone();

                let mut batch = FuturesUnordered::new();

                while let Some((message, server_opts, sender)) = requests.pop() {
                    let handler = handler.clone();
                    if server_opts.is_background {
                        if Instant::now() - last_activity < MAX_IDLE {
                            bg_batch.push(async move {
                                let _ = sender.send(process(handler, message, server_opts).await);
                            });
                        }
                    } else {
                        last_activity = Instant::now();
                        batch.push(async move {
                            let _ = sender.send(process(handler, message, server_opts).await);
                        });
                    }
                }

                if !bg_batch.is_empty() {
                    if let Ok(permit) = background_concurrency.clone().try_acquire_owned() {
                        let mut batch = FuturesUnordered::new();
                        std::mem::swap(&mut batch, &mut bg_batch);
                        inner_join_set.spawn(async move {
                            let count = batch.len();
                            while (batch.next().await).is_some() {}
                            drop(permit);
                            count
                        });
                    }
                }

                if !batch.is_empty() {
                    inner_join_set.spawn(async move {
                        let count = batch.len();
                        while (batch.next().await).is_some() {}
                        count
                    });
                }

                let finished = reap_tasks(&mut inner_join_set);
                app.active_queries.fetch_sub(finished, Ordering::Relaxed);
            }

            fn reap_tasks(join_set: &mut JoinSet<usize>) -> usize {
                let mut total = 0;
                while let Some(count) = join_set.join_next().now_or_never().flatten() {
                    if let Ok(count) = count {
                        total += count;
                    }
                }
                total
            }
        });
    }

    let shutdown_timeout = Duration::from_secs(5);

    runtime.block_on(async move {
        use crate::signal;
        let _ = signal::terminate().await;
        // close all servers.
        let mut shutdown_listeners = Default::default();
        std::mem::swap(
            app.listeners.write().await.deref_mut(),
            &mut shutdown_listeners,
        );
        shutdown_listeners
            .into_values()
            .map(|server| server.shutdown())
            .join_all()
            .await;
    });

    runtime.shutdown_timeout(shutdown_timeout);

    log::info!("{} {} shutdown", crate::NAME, crate::BUILD_VERSION);
}

struct AppGuard {
    #[cfg(target_os = "linux")]
    user_guard: Option<crate::run_user::SwitchUserGuard>,
}

async fn process(
    handler: Arc<DnsMiddlewareHandler>,
    message: SerialMessage,
    server_opts: ServerOpts,
) -> SerialMessage {
    use crate::libdns::proto::ProtoError;
    use crate::libdns::proto::op::{Header, Message, MessageType, OpCode, ResponseCode};

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
                                            log::debug!(
                                                "{}Response: error resolving: NXDomain, Duration: {:?}",
                                                if server_opts.is_background {
                                                    "Background"
                                                } else {
                                                    ""
                                                },
                                                start.elapsed()
                                            );
                                            response_header
                                                .set_response_code(ResponseCode::NXDomain);
                                        }
                                        let original = request.query().original();
                                        match e.as_soa(original) {
                                            Some(soa) => soa,
                                            None => {
                                                log::debug!(
                                                    "{}Response: error resolving: {}, Duration: {:?}",
                                                    if server_opts.is_background {
                                                        "Background"
                                                    } else {
                                                        ""
                                                    },
                                                    e,
                                                    start.elapsed()
                                                );
                                                response_header
                                                    .set_response_code(ResponseCode::ServFail);
                                                let mut res = DnsResponse::empty();
                                                res.add_query(original.to_owned());
                                                res
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
                message_type = request_header.message_type(),
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

fn build_middleware(
    cfg: &Arc<RuntimeConfig>,
    dns_handle: &DnsHandle,
    dns_client: DnsClient,
    dns_cache: &mut Option<Arc<DnsCache>>,
) -> Arc<DnsMiddlewareHandler> {
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

    let middleware_handler = {
        let mut builder = DnsMiddlewareBuilder::new();

        // check if audit enabled.
        if cfg.audit_enable() && cfg.audit_file().is_some() {
            builder = builder.with(DnsAuditMiddleware::new(
                cfg.audit_file().unwrap(),
                cfg.audit_size(),
                cfg.audit_num(),
                cfg.audit_file_mode().into(),
            ));
        }

        if cfg.rule_groups().values().all(|x| !x.cnames.is_empty()) {
            builder = builder.with(DnsCNameMiddleware);
        }

        builder = builder.with(DnsZoneMiddleware::new());

        builder = builder.with(AddressMiddleware);

        if cfg.resolv_hostanme() {
            builder = builder.with(DnsHostsMiddleware::new());
        }

        if cfg
            .dnsmasq_lease_file()
            .map(|x| x.is_file())
            .unwrap_or_default()
        {
            builder = builder.with(DnsmasqMiddleware::new(
                cfg.dnsmasq_lease_file().unwrap(),
                cfg.domain().cloned(),
            ));
        }

        // nftset
        #[cfg(all(feature = "nft", target_os = "linux"))]
        {
            use crate::dns_mw_nftset::DnsNftsetMiddleware;
            builder = builder.with(DnsNftsetMiddleware);
        }

        // check if cache enabled.
        if cfg.cache_size() > 0 {
            let cache_middleware = DnsCacheMiddleware::new(cfg, dns_handle.clone());
            dns_cache.replace(cache_middleware.cache().clone());
            builder = builder.with(cache_middleware);
        }

        builder = builder.with(DnsDualStackIpSelectionMiddleware);

        if !cfg.bogus_nxdomain().is_empty() {
            builder = builder.with(DnsBogusMiddleware);
        }

        builder = builder.with(NameServerMiddleware::new(dns_client));

        builder.build(cfg.clone())
    };

    Arc::new(middleware_handler)
}
