use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::{Deref, DerefMut},
    path::PathBuf,
    slice::Iter,
    sync::Arc,
    time::Duration,
};

use tokio::sync::RwLock;
use url::Host;

use crate::{
    dns::DnsResponse,
    dns_conf::NameServerInfo,
    dns_error::LookupError,
    dns_url::{DnsProtocol, DnsUrlParamExt},
    log::{self, debug, info, warn},
    proxy::ProxyConfig,
    rustls::TlsClientConfigBundle,
};

use crate::libdns::{
    Protocol,
    proto::{
        DnsHandle, ProtoError, ProtoErrorKind,
        op::{Edns, Message, MessageType, OpCode, Query},
        rr::{
            Record, RecordType,
            domain::{IntoName, Name},
            rdata::opt::{ClientSubnet, EdnsOption},
        },
        xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
    },
    resolver::{
        config::{ResolverOpts, ServerOrderingStrategy},
        name_server::GenericConnector,
    },
};

use bootstrap::BootstrapResolver;

use connection_provider::{
    Connection, ConnectionProvider, RawNameServerConfig, TokioRuntimeProvider,
};
use smallvec::SmallVec;

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
///   Setting this to a value of 1 day, in seconds
pub const MAX_TTL: u32 = 86400_u32;

static DEFAULT_QUERY: std::sync::LazyLock<Query> =
    std::sync::LazyLock::new(|| Query::query("example.com.".parse().unwrap(), RecordType::A));

#[derive(Default)]
pub struct DnsClientBuilder {
    server_infos: Vec<NameServerInfo>,
    ca_file: Option<PathBuf>,
    ca_path: Option<PathBuf>,
    proxies: Arc<HashMap<String, ProxyConfig>>,
    client_subnet: Option<ClientSubnet>,
}

impl DnsClientBuilder {
    pub fn add_servers<S: Into<NameServerInfo>>(self, servers: Vec<S>) -> Self {
        servers.into_iter().fold(self, |b, s| b.add_server(s))
    }

    pub fn add_server<S: Into<NameServerInfo>>(mut self, server: S) -> Self {
        self.server_infos.push(server.into());
        self
    }

    pub fn with_ca_file(mut self, file: PathBuf) -> Self {
        self.ca_file = Some(file);
        self
    }

    pub fn with_ca_path(mut self, file: PathBuf) -> Self {
        self.ca_path = Some(file);
        self
    }

    pub fn with_proxies(mut self, proxies: Arc<HashMap<String, ProxyConfig>>) -> Self {
        self.proxies = proxies;

        self
    }

    pub fn with_client_subnet<S: Into<ClientSubnet>>(mut self, subnet: S) -> Self {
        self.client_subnet = Some(subnet.into());
        self
    }

    pub async fn build(self) -> DnsClient {
        let DnsClientBuilder {
            server_infos,
            ca_file,
            ca_path,
            proxies,
            client_subnet,
        } = self;

        let tls_client_config = TlsClientConfigBundle::new(ca_path, ca_file);

        let boot = Arc::new(BootstrapResolver::from_system_conf());

        let mut server_instances = HashMap::<&NameServerInfo, _>::new();
        let mut make_server = |server_config, resolver, dedup| {
            let entry = server_instances.entry(server_config);
            if let std::collections::hash_map::Entry::Occupied(_) = entry {
                if dedup {
                    return SmallVec::new();
                }
            }
            let server = entry.or_insert_with(|| {
                let proxy = server_config
                    .proxy
                    .as_deref()
                    .map(|n| proxies.get(n))
                    .unwrap_or_default()
                    .cloned();
                NameServer::new(
                    server_config.clone(),
                    proxy,
                    Some(tls_client_config.clone()),
                    resolver,
                    client_subnet,
                )
                .unwrap_or_else(|err| {
                    let url = server_config.server.to_string();
                    log::error!("failed to create nameserver {url}, error: {err}");
                    SmallVec::new()
                })
            });
            server.clone()
        };

        let mut bootstrap_servers;
        let bootstrap = {
            bootstrap_servers = server_infos
                .iter()
                .filter(|info| info.bootstrap_dns)
                .filter(|info| {
                    if info.server.proto() != DnsProtocol::System && info.server.ip().is_none() {
                        warn!("bootstrap-dns must use ip addess, {:?}", info.server.host());
                        false
                    } else {
                        true
                    }
                })
                .cloned()
                .collect::<Vec<_>>();

            if bootstrap_servers.is_empty() {
                bootstrap_servers = server_infos
                    .iter()
                    .filter(|info| info.proxy.is_none())
                    .filter(|info| {
                        info.server.proto() == DnsProtocol::System || info.server.ip().is_some()
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            }

            if bootstrap_servers.is_empty() {
                warn!("not bootstrap-dns found, use system_conf instead.");
            }

            if !bootstrap_servers.is_empty() {
                for info in &bootstrap_servers {
                    info!("bootstrap-dns {}", info.server.to_string());
                }
            }

            let resolver: Arc<BootstrapResolver> = if !bootstrap_servers.is_empty() {
                let servers = bootstrap_servers
                    .iter()
                    .flat_map(|server_config| make_server(server_config, None, true))
                    .collect();

                let new_resolver = NameServerGroup {
                    resolver_opts: boot.as_ref().deref().options().clone(),
                    servers,
                };

                Arc::new(BootstrapResolver::new(new_resolver.into()))
            } else {
                boot.clone()
            };

            resolver
        };

        assert!(!bootstrap.is_empty(), "no bootstrap nameserver found.");

        let mut server_config_groups = HashMap::<Option<&str>, HashSet<&NameServerInfo>>::new();
        for (g, server_config) in server_infos.iter().flat_map(|serv_conf| {
            let group = serv_conf.group.iter().map(move |g| (Some(&**g), serv_conf));
            let default = (!serv_conf.exclude_default_group).then_some((None, serv_conf));
            group.chain(default)
        }) {
            server_config_groups
                .entry(g)
                .or_default()
                .insert(server_config);
        }

        let mut server_groups = HashMap::with_capacity(server_config_groups.len());
        let mut default_group_servers = (*bootstrap).clone();

        let resolver_opts = Arc::new(bootstrap.options().clone());

        for (group_name, group) in &server_config_groups {
            let servers = group
                .iter()
                .flat_map(|server_config| {
                    make_server(*server_config, Some(bootstrap.clone()), false)
                })
                .collect();

            let server_group = NameServerGroup {
                resolver_opts: resolver_opts.clone(),
                servers,
            };

            debug!(
                "create nameserver group {:?}, servers {}",
                group_name,
                server_group.len()
            );

            if let Some(group_name) = group_name {
                server_groups.insert(group_name.to_string(), Arc::new(server_group));
            } else {
                default_group_servers = Arc::new(server_group);
            }
        }

        for s in server_groups.values() {
            s.warmup().await;
        }

        DnsClient {
            default: default_group_servers,
            bootstrap,
            servers: server_groups,
        }
    }
}

pub struct DnsClient {
    default: Arc<NameServerGroup>,
    bootstrap: Arc<BootstrapResolver>,
    servers: HashMap<String, Arc<NameServerGroup>>,
}

impl DnsClient {
    pub fn builder() -> DnsClientBuilder {
        DnsClientBuilder::default()
    }

    pub async fn default(&self) -> Arc<NameServerGroup> {
        self.deref().clone()
    }

    pub async fn get_server_group(&self, name: &str) -> Option<Arc<NameServerGroup>> {
        if name.is_empty() || name.eq_ignore_ascii_case("default") {
            return Some(self.default.clone());
        }
        self.servers.get(name).cloned()
    }

    pub async fn lookup_nameserver(
        &self,
        name: Name,
        record_type: RecordType,
    ) -> Option<DnsResponse> {
        self.bootstrap.local_lookup(name, record_type).await
    }
}

impl std::ops::Deref for DnsClient {
    type Target = Arc<NameServerGroup>;

    fn deref(&self) -> &Self::Target {
        &self.default
    }
}

#[derive(Default)]
pub struct NameServerGroup {
    resolver_opts: Arc<ResolverOpts>,
    servers: Vec<Arc<NameServer>>,
}

impl NameServerGroup {
    pub async fn warmup(&self) {
        for server in self.servers.iter() {
            _ = server.client().await;
        }
    }
    #[inline]
    pub fn iter(&self) -> Iter<Arc<NameServer>> {
        self.servers.iter()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    fn options(&self) -> &Arc<ResolverOpts> {
        &self.resolver_opts
    }
}

#[async_trait::async_trait]
impl GenericResolver for NameServerGroup {
    fn options(&self) -> &ResolverOpts {
        &self.resolver_opts
    }

    async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
        &self,
        name: N,
        options: O,
    ) -> Result<DnsResponse, LookupError> {
        use futures_util::future::select_all;
        let name = name.into_name()?;
        let mut tasks = self
            .servers
            .iter()
            .map(|ns| GenericResolver::lookup(ns.as_ref(), name.clone(), options.clone()))
            .collect::<Vec<_>>();

        loop {
            let (res, _idx, rest) = select_all(tasks).await;

            if matches!(res.as_ref(), Ok(lookup) if !lookup.records().is_empty()) {
                return res;
            }

            if rest.is_empty() {
                return res;
            }
            tasks = rest;
        }
    }
}

pub struct NameServer {
    datagram_conns: Arc<RwLock<Option<Arc<Connection>>>>,

    server: Host,

    ip_addrs: RwLock<Arc<[IpAddr]>>,

    config: RawNameServerConfig,
    options: Arc<NameServerOpts>,
    connection_provider: ConnectionProvider,
    prefer_protocol: Option<Protocol>,

    resolver: Option<Arc<BootstrapResolver>>,
}

impl NameServer {
    pub fn new(
        config: NameServerInfo,
        proxy: Option<ProxyConfig>,
        tls_client_config: Option<TlsClientConfigBundle>,
        resolver: Option<Arc<BootstrapResolver>>,
        default_client_subnet: Option<ClientSubnet>,
    ) -> anyhow::Result<smallvec::SmallVec<[Arc<Self>; 1]>> {
        match config.server.proto() {
            DnsProtocol::System => {
                let conf = crate::libdns::resolver::system_conf::read_system_conf();
                let servers = match &conf {
                    Ok((r, _)) => r.name_servers(),
                    Err(err) => anyhow::bail!("read system conf failed: {}", err),
                };
                servers
                    .iter()
                    .map(|server| {
                        Self::make(
                            config.clone(),
                            proxy.clone(),
                            tls_client_config.clone(),
                            resolver.clone(),
                            default_client_subnet,
                            server.socket_addr,
                            Some(&match server.socket_addr.ip() {
                                IpAddr::V4(addr) => Host::Ipv4(addr),
                                IpAddr::V6(addr) => Host::Ipv6(addr),
                            }),
                            server.protocol,
                        )
                        .map(Arc::new)
                    })
                    .collect()
            }
            DnsProtocol::H(protocol) => {
                let socket_addr = {
                    let ip_addr = config.server.ip();
                    let port = config.server.port().unwrap();
                    SocketAddr::new(ip_addr.unwrap_or(Ipv4Addr::UNSPECIFIED.into()), port)
                };

                Ok(SmallVec::from_buf([Arc::new(Self::make(
                    config,
                    proxy,
                    tls_client_config,
                    resolver,
                    default_client_subnet,
                    socket_addr,
                    None,
                    protocol,
                )?)]))
            }
        }
    }

    fn make(
        config: NameServerInfo,
        proxy: Option<ProxyConfig>,
        tls_client_config: Option<TlsClientConfigBundle>,
        resolver: Option<Arc<BootstrapResolver>>,
        default_client_subnet: Option<ClientSubnet>,
        socket_addr: SocketAddr,
        host: Option<&Host>,
        protocol: Protocol,
    ) -> anyhow::Result<NameServer> {
        let url = config.server;
        let host = host.or(url.host()).unwrap();

        if socket_addr.ip().is_unspecified() && resolver.is_none() {
            anyhow::bail!("Parameter resolver is required for non-ip upstream");
        }

        let (tls_dns_name, tls_config) = if protocol.is_encrypted() {
            let Some(tls_client_config) = tls_client_config else {
                anyhow::bail!("Parameter tls_client_config is required for Encrypted upstream");
            };

            let config = if !url.ssl_verify() {
                tls_client_config.verify_off
            } else if url.sni_off() {
                tls_client_config.sni_off
            } else {
                tls_client_config.normal
            };

            (Some(host.to_string()), Some(config))
        } else {
            (None, None)
        };

        let mut options = NameServerOpts::new(
            config.blacklist_ip,
            config.whitelist_ip,
            config.check_edns,
            config.subnet.map(|x| x.into()).or(default_client_subnet),
            resolver
                .as_ref()
                .map(|r| r.options().clone())
                .unwrap_or_default(),
        );

        if let Some(tls_config) = tls_config.as_deref() {
            options.resolver_opts.tls_config = tls_config.clone();
        }

        options.resolver_opts.server_ordering_strategy = ServerOrderingStrategy::QueryStatistics;

        let so_mark = config.so_mark;
        let device = config.interface;

        let provider = GenericConnector::new(TokioRuntimeProvider::new(proxy, so_mark, device));

        let http_endpoint = url.path().map(|s| s.to_string());

        let config = RawNameServerConfig {
            socket_addr,
            protocol,
            trust_negative_responses: true,
            tls_dns_name,
            bind_addr: None,
            http_endpoint,
        };

        let prefer_protocol = if url.prefer_h3() {
            Some(Protocol::H3)
        } else {
            None
        };

        Ok(Self {
            server: host.to_owned(),
            ip_addrs: url
                .ip()
                .map(|ip| RwLock::new(Arc::from([ip])))
                .unwrap_or_default(),
            config,
            datagram_conns: Default::default(),
            options: options.into(),
            connection_provider: provider,
            resolver,
            prefer_protocol,
        })
    }

    async fn ip_addrs(&self) -> Result<Arc<[IpAddr]>, ProtoError> {
        let mut ip_addrs = self.ip_addrs.read().await.clone();
        if !ip_addrs.is_empty() {
            return Ok(ip_addrs);
        }
        match &self.server {
            Host::Domain(domain) => {
                let resolver = self
                    .resolver
                    .as_ref()
                    .expect("resolver must be set when using domain name");

                ip_addrs = match resolver.lookup_ip(domain).await {
                    Ok(lookup_ip) => lookup_ip.ip_addrs().into_iter().collect::<Vec<_>>(),
                    Err(err) => {
                        warn!("lookup ip: {domain} failed, {err}");
                        vec![]
                    }
                }
                .into();

                if ip_addrs.is_empty() {
                    return Err(ProtoErrorKind::NoConnections.into());
                } else {
                    *self.ip_addrs.write().await.deref_mut() = ip_addrs.clone();
                }
                Ok(ip_addrs)
            }
            Host::Ipv4(ip) => {
                ip_addrs = vec![IpAddr::V4(*ip)].into();
                *self.ip_addrs.write().await.deref_mut() = ip_addrs.clone();
                Ok(ip_addrs)
            }
            Host::Ipv6(ip) => {
                ip_addrs = vec![IpAddr::V6(*ip)].into();
                *self.ip_addrs.write().await.deref_mut() = ip_addrs.clone();
                Ok(ip_addrs)
            }
        }
    }

    async fn client(&self) -> Result<ClientHandle, ProtoError> {
        if let Some(conn) = self.datagram_conns.read().await.clone() {
            return Ok(ClientHandle { connection: conn });
        }

        let conn = {
            let config = self.config.clone();
            let options = self.options.as_ref().deref().clone();
            let provider = self.connection_provider.clone();
            let ip_addrs = self.ip_addrs().await?;

            let mut configs = ip_addrs
                .iter()
                .map(|ip| {
                    let mut config = config.clone();
                    config.socket_addr.set_ip(*ip);
                    config
                })
                .collect::<Vec<_>>();

            let alt_protocol = self.prefer_protocol.or_else(|| {
                if config.protocol == Protocol::Https {
                    Some(Protocol::H3)
                } else {
                    None
                }
            });

            if let Some(alt_protocol) = alt_protocol {
                configs.extend(
                    configs
                        .iter()
                        .map(|c| {
                            let mut config = c.clone();
                            config.protocol = alt_protocol;
                            config
                        })
                        .collect::<Vec<_>>(),
                );
            }

            if configs.is_empty() {
                return Err(ProtoErrorKind::NoConnections.into());
            }

            if configs.len() == 1 {
                Connection::new(config, options, provider)
            } else {
                let conns = configs
                    .into_iter()
                    .map(|c| {
                        (
                            c.protocol,
                            Connection::new(c, options.clone(), provider.clone()),
                        )
                    })
                    .map(|(protocol, conn)| {
                        let delay = matches!(self.prefer_protocol, Some(p) if p != protocol);

                        Box::pin(async move {
                            {
                                let fut = conn
                                    .lookup(DEFAULT_QUERY.clone(), Default::default())
                                    .first_answer();

                                if delay {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }

                                match fut.await {
                                    Ok(_) => Ok(conn),
                                    Err(err) if err.kind.is_no_records_found() => Ok(conn),
                                    Err(err) => Err(err),
                                }
                            }
                        })
                    });

                match futures::future::select_ok(conns).await {
                    Ok((conn, _)) => conn,
                    Err(err) => {
                        log::error!(
                            "Failed to connect to any nameserver: {} {}",
                            self.server,
                            err
                        );
                        return Err(err);
                    }
                }
            }
        };

        let conn = Arc::new(conn);

        self.datagram_conns.write().await.replace(conn.clone());

        Ok(ClientHandle { connection: conn })
    }

    #[inline]
    pub fn options(&self) -> &NameServerOpts {
        &self.options
    }
}

impl From<RawNameServerConfig> for NameServer {
    fn from(config: RawNameServerConfig) -> Self {
        Self {
            server: match config.socket_addr.ip() {
                IpAddr::V4(ipv4_addr) => Host::Ipv4(ipv4_addr),
                IpAddr::V6(ipv6_addr) => Host::Ipv6(ipv6_addr),
            },
            config,
            ip_addrs: Default::default(),
            datagram_conns: Default::default(),
            options: Default::default(),
            connection_provider: Default::default(),
            resolver: Default::default(),
            prefer_protocol: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl GenericResolver for NameServer {
    fn options(&self) -> &ResolverOpts {
        &self.options().resolver_opts
    }

    async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
        &self,
        name: N,
        options: O,
    ) -> Result<DnsResponse, LookupError> {
        let name = name.into_name()?;
        let options: LookupOptions = options.into();

        let query = Query::query(name, options.record_type);

        let client_subnet = options.client_subnet.or(self.options().client_subnet);

        if options.client_subnet.is_none() {
            if let Some(subnet) = client_subnet.as_ref() {
                log::debug!(
                    "query name: {} type: {} subnet: {}/{}",
                    query.name(),
                    query.query_type(),
                    subnet.addr(),
                    subnet.scope_prefix(),
                );
            }
        }

        let request_options = {
            let opts = &self.options();
            let mut request_opts = DnsRequestOptions::default();
            request_opts.recursion_desired = opts.recursion_desired;
            request_opts.use_edns = opts.edns0 || client_subnet.is_some();
            request_opts
        };

        let req = DnsRequest::new(
            build_message(query, request_options, client_subnet, options.is_dnssec),
            request_options,
        );

        let res = {
            let client = self.client().await?;
            let ns = client.connection;
            ns.send(req).first_answer().await?
        };

        Ok(From::<Message>::from(res.into()))
    }
}

struct ClientHandle {
    connection: Arc<Connection>,
}

#[derive(Clone)]
pub struct NameServerOpts {
    /// filter result with blacklist ip
    pub blacklist_ip: bool,

    /// filter result with whitelist ip,  result in whitelist-ip will be accepted.
    pub whitelist_ip: bool,

    /// result must exist edns RR, or discard result.
    pub check_edns: bool,

    pub client_subnet: Option<ClientSubnet>,

    resolver_opts: ResolverOpts,
}

impl NameServerOpts {
    #[inline]
    pub fn new(
        blacklist_ip: bool,
        whitelist_ip: bool,
        check_edns: bool,
        client_subnet: Option<ClientSubnet>,
        resolver_opts: ResolverOpts,
    ) -> Self {
        Self {
            blacklist_ip,
            whitelist_ip,
            check_edns,
            client_subnet,
            resolver_opts,
        }
    }

    pub fn with_resolver_opts(mut self, resolver_opts: ResolverOpts) -> Self {
        self.resolver_opts = resolver_opts;
        self
    }
}

impl Default for NameServerOpts {
    fn default() -> Self {
        let mut resolver_opts = ResolverOpts::default();
        resolver_opts.edns0 = true;

        Self {
            blacklist_ip: Default::default(),
            whitelist_ip: Default::default(),
            check_edns: Default::default(),
            client_subnet: Default::default(),
            resolver_opts,
        }
    }
}

impl Deref for NameServerOpts {
    type Target = ResolverOpts;

    fn deref(&self) -> &Self::Target {
        &self.resolver_opts
    }
}

#[async_trait::async_trait]
pub trait GenericResolver {
    fn options(&self) -> &ResolverOpts;

    /// Lookup any RecordType
    ///
    /// # Arguments
    ///
    /// * `name` - name of the record to lookup, if name is not a valid domain name, an error will be returned
    /// * `record_type` - type of record to lookup, all RecordData responses will be filtered to this type
    ///
    /// # Returns
    ///
    ///  A future for the returned Lookup RData
    async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
        &self,
        name: N,
        options: O,
    ) -> Result<DnsResponse, LookupError>;
}

#[async_trait::async_trait]
pub trait GenericResolverExt {
    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    async fn lookup_ip<N: IntoName + Send>(&self, host: N) -> Result<DnsResponse, LookupError>;
}

#[async_trait::async_trait]
impl<T> GenericResolverExt for T
where
    T: GenericResolver + Sync,
{
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    async fn lookup_ip<N: IntoName + Send>(&self, host: N) -> Result<DnsResponse, LookupError> {
        let mut finally_ip_addr: Option<Record> = None;
        let maybe_ip = host.to_ip();
        let maybe_name: Result<Name, ProtoError> = host.into_name();

        // if host is a ip address, return directly.
        if let Some(ip_addr) = maybe_ip {
            let ip_addr = ip_addr.into();
            let name = maybe_name.clone().unwrap_or_default();
            let record = Record::from_rdata(name.clone(), MAX_TTL, Clone::clone(&ip_addr));

            // if ndots are greater than 4, then we can't assume the name is an IpAddr
            //   this accepts IPv6 as well, b/c IPv6 can take the form: 2001:db8::198.51.100.35
            //   but `:` is not a valid DNS character, so technically this will fail parsing.
            //   TODO: should we always do search before returning this?
            if self.options().ndots > 4 {
                finally_ip_addr = Some(record);
            } else {
                let query = Query::query(name, ip_addr.record_type());
                let lookup = DnsResponse::new_with_max_ttl(query, vec![record]);
                return Ok(lookup);
            }
        }

        let name = match (maybe_name, finally_ip_addr.as_ref()) {
            (Ok(name), _) => name,
            (Err(_), Some(ip_addr)) => {
                // it was a valid IP, return that...
                let query = Query::query(ip_addr.name().clone(), ip_addr.record_type());
                let lookup = DnsResponse::new_with_max_ttl(query, vec![ip_addr.clone()]);
                return Ok(lookup);
            }
            (Err(err), None) => {
                return Err(err.into());
            }
        };

        let strategy = self.options().ip_strategy;
        use crate::libdns::resolver::config::LookupIpStrategy::*;

        match strategy {
            Ipv4Only => self.lookup(name.clone(), RecordType::A).await,
            Ipv6Only => self.lookup(name.clone(), RecordType::AAAA).await,
            Ipv4AndIpv6 => {
                use futures_util::future::{Either, select};
                match select(
                    self.lookup(name.clone(), RecordType::A),
                    self.lookup(name.clone(), RecordType::AAAA),
                )
                .await
                {
                    Either::Left((res, _)) => res,
                    Either::Right((res, _)) => res,
                }
            }
            Ipv6thenIpv4 => match self.lookup(name.clone(), RecordType::AAAA).await {
                Ok(lookup) => Ok(lookup),
                Err(_err) => self.lookup(name.clone(), RecordType::A).await,
            },
            Ipv4thenIpv6 => match self.lookup(name.clone(), RecordType::A).await {
                Ok(lookup) => Ok(lookup),
                Err(_err) => self.lookup(name.clone(), RecordType::AAAA).await,
            },
        }
    }
}

#[derive(Clone)]
pub struct LookupOptions {
    pub is_dnssec: bool,
    pub record_type: RecordType,
    pub client_subnet: Option<ClientSubnet>,
}

impl Default for LookupOptions {
    fn default() -> Self {
        Self {
            is_dnssec: false,
            record_type: RecordType::A,
            client_subnet: Default::default(),
        }
    }
}

impl From<RecordType> for LookupOptions {
    fn from(record_type: RecordType) -> Self {
        Self {
            record_type,
            ..Default::default()
        }
    }
}

/// > An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly all current networks.
/// > https://dnsflagday.net/2020/
const MAX_PAYLOAD_LEN: u16 = 1232;

fn build_message(
    query: Query,
    request_options: DnsRequestOptions,
    client_subnet: Option<ClientSubnet>,
    is_dnssec: bool,
) -> Message {
    // build the message
    let mut message: Message = Message::new();
    // TODO: This is not the final ID, it's actually set in the poll method of DNS future
    //  should we just remove this?
    let id: u16 = rand::random();
    message
        .add_query(query)
        .set_id(id)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(request_options.recursion_desired);

    // Extended dns
    if client_subnet.is_some() || request_options.use_edns || is_dnssec {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);

        if let (Some(client_subnet), Some(edns)) = (client_subnet, message.extensions_mut()) {
            edns.options_mut().insert(EdnsOption::Subnet(client_subnet));
        }

        if let (true, Some(edns)) = (is_dnssec, message.extensions_mut()) {
            edns.set_dnssec_ok(is_dnssec);
        }
    }
    message
}

mod connection_provider {
    use super::*;
    use crate::proxy;
    use crate::proxy::{TcpStream, UdpSocket};
    use crate::third_ext::FutureTimeoutExt;
    use async_trait::async_trait;

    use std::future::Future;
    use std::task::Poll;
    use std::task::ready;
    use std::time::Duration;
    use std::{io, net::SocketAddr, pin::Pin};

    use crate::libdns::proto::{
        self,
        runtime::{
            QuicSocketBinder, RuntimeProvider, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd,
        },
    };

    pub type RawNameServer =
        crate::libdns::resolver::name_server::NameServer<GenericConnector<TokioRuntimeProvider>>;
    pub type RawNameServerConfig = crate::libdns::resolver::config::NameServerConfig;
    pub type Connection = crate::libdns::resolver::name_server::GenericNameServer<
        connection_provider::TokioRuntimeProvider,
    >;
    pub type ConnectionProvider = GenericConnector<TokioRuntimeProvider>;

    /// The Tokio Runtime for async execution
    #[derive(Clone, Default)]
    pub struct TokioRuntimeProvider {
        proxy: Option<ProxyConfig>,
        so_mark: Option<u32>,
        device: Option<String>,
        handle: TokioHandle,
    }

    impl TokioRuntimeProvider {
        pub fn new(
            proxy: Option<ProxyConfig>,
            so_mark: Option<u32>,
            device: Option<String>,
        ) -> Self {
            Self {
                proxy,
                so_mark,
                device,
                handle: TokioHandle::default(),
            }
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    fn setup_socket<F: std::os::fd::AsFd, S: std::ops::Deref<Target = F> + Sized>(
        socket: S,
        bind_addr: Option<SocketAddr>,
        mark: Option<u32>,
        device: Option<String>,
    ) -> S {
        if mark.is_some() || device.is_some() || bind_addr.is_some() {
            use socket2::SockRef;
            let sock_ref = SockRef::from(socket.deref());
            if let Some(mark) = mark {
                sock_ref.set_mark(mark).unwrap_or_else(|err| {
                    warn!("set so_mark failed: {:?}", err);
                });
            }

            if let Some(device) = device {
                sock_ref
                    .bind_device(Some(device.as_bytes()))
                    .unwrap_or_else(|err| {
                        warn!("bind device failed: {:?}", err);
                    });
            }

            if let Some(bind_addr) = bind_addr {
                sock_ref.bind(&bind_addr.into()).unwrap_or_else(|err| {
                    warn!("bind addr failed: {:?}", err);
                });
            }
        }
        socket
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    #[inline]
    fn setup_socket<S>(
        socket: S,
        _bind_addr: Option<SocketAddr>,
        _mark: Option<u32>,
        _device: Option<String>,
    ) -> S {
        socket
    }

    impl RuntimeProvider for TokioRuntimeProvider {
        type Handle = TokioHandle;
        type Timer = TokioTime;
        type Udp = UdpSocket;
        type Tcp = AsyncIoTokioAsStd<TcpStream>;

        fn create_handle(&self) -> Self::Handle {
            self.handle.clone()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
            bind_addr: Option<SocketAddr>,
            timeout: Option<Duration>,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
            let proxy_config = self.proxy.clone();

            let so_mark = self.so_mark;
            let device = self.device.clone();
            let setup_socket = move |tcp| {
                setup_socket(&tcp, bind_addr, so_mark, device);
                tcp
            };
            let wait_for = timeout.unwrap_or_else(|| Duration::from_secs(5));

            Box::pin(async move {
                async move {
                    proxy::connect_tcp(server_addr, proxy_config.as_ref())
                        .await
                        .map(setup_socket)
                        .map(AsyncIoTokioAsStd)
                }
                .timeout(wait_for)
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                    ))
                })
            })
        }

        fn bind_udp(
            &self,
            local_addr: SocketAddr,
            server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
            let proxy_config = self.proxy.clone();

            let so_mark = self.so_mark;
            let device = self.device.clone();
            let setup_socket = move |udp| setup_socket(udp, None, so_mark, device);

            Box::pin(async move {
                proxy::connect_udp(server_addr, local_addr, proxy_config.as_ref())
                    .await
                    .map(setup_socket)
            })
        }

        #[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
        fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
            Some(&TokioQuicSocketBinder)
        }
    }

    #[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
    struct TokioQuicSocketBinder;

    #[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
    impl QuicSocketBinder for TokioQuicSocketBinder {
        fn bind_quic(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
            use quinn::Runtime;
            let socket = next_random_udp(local_addr)?;
            quinn::TokioRuntime.wrap_udp_socket(socket)
        }
    }

    #[async_trait]
    impl proto::udp::DnsUdpSocket for UdpSocket {
        type Time = TokioTime;

        fn poll_recv_from(
            &self,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<io::Result<(usize, SocketAddr)>> {
            match self {
                UdpSocket::Tokio(s) => {
                    let mut buf = tokio::io::ReadBuf::new(buf);
                    let addr = ready!(tokio::net::UdpSocket::poll_recv_from(s, cx, &mut buf))?;
                    let len = buf.filled().len();
                    Poll::Ready(Ok((len, addr)))
                }
                UdpSocket::Proxy(s) => {
                    let (len, addr) = ready!(s.poll_recv_from(cx, buf))
                        .map_err(|err| io::Error::other(err.to_string()))?;
                    let addr = match addr {
                        async_socks5::AddrKind::Ip(addr) => addr,
                        async_socks5::AddrKind::Domain(_, _) => {
                            Err(io::Error::other("Expect IP address"))?
                        }
                    };
                    Poll::Ready(Ok((len, addr)))
                }
            }
        }

        fn poll_send_to(
            &self,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
            target: SocketAddr,
        ) -> std::task::Poll<io::Result<usize>> {
            match self {
                UdpSocket::Tokio(s) => tokio::net::UdpSocket::poll_send_to(s, cx, buf, target),
                UdpSocket::Proxy(s) => {
                    let res = ready!(s.poll_send_to(cx, buf, target))
                        .map_err(|err| io::Error::other(err.to_string()));
                    Poll::Ready(res)
                }
            }
        }

        /// Receive data from the socket and returns the number of bytes read and the address from
        /// where the data came on success.
        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            use UdpSocket::*;
            let (len, addr) = match self {
                Tokio(s) => s.recv_from(buf).await,
                Proxy(s) => {
                    let (len, addr) = s
                        .recv_from(buf)
                        .await
                        .map_err(|err| io::Error::other(err.to_string()))?;

                    let addr = match addr {
                        async_socks5::AddrKind::Ip(addr) => addr,
                        async_socks5::AddrKind::Domain(_, _) => {
                            Err(io::Error::other("Expect IP address"))?
                        }
                    };
                    Ok((len, addr))
                }
            }?;
            Ok((len, addr))
        }

        /// Send data to the given address.
        async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
            use UdpSocket::*;
            match self {
                Tokio(s) => s.send_to(buf, target).await,
                Proxy(s) => s
                    .send_to(buf, target)
                    .await
                    .map_err(|err| io::Error::other(err.to_string())),
            }
        }
    }

    fn next_random_udp(bind_addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
        const ATTEMPT_RANDOM: usize = 10;
        if bind_addr.port() == 0 {
            for attempt in 0..ATTEMPT_RANDOM {
                // Per RFC 6056 Section 3.2:
                //
                // As mentioned in Section 2.1, the dynamic ports consist of the range
                // 49152-65535.  However, ephemeral port selection algorithms should use
                // the whole range 1024-65535.
                let port = rand::random_range(1024..=u16::MAX);

                let bind_addr = SocketAddr::new(bind_addr.ip(), port);

                match std::net::UdpSocket::bind(bind_addr) {
                    Ok(socket) => {
                        log::debug!("created socket successfully");
                        return Ok(socket);
                    }
                    Err(err) => {
                        log::debug!("unable to bind port, attempt: {}: {err}", attempt);
                    }
                }
            }
        }
        std::net::UdpSocket::bind(bind_addr)
    }
}

mod bootstrap {
    use super::*;
    use crate::libdns::resolver::config::{NameServerConfigGroup, ResolverConfig};

    pub struct BootstrapResolver<T: GenericResolver = NameServerGroup>
    where
        T: Send + Sync,
    {
        resolver: Arc<T>,
        ip_store: RwLock<HashMap<Query, Arc<[Record]>>>,
    }

    impl<T: GenericResolver + Sync + Send> BootstrapResolver<T> {
        pub fn new(resolver: Arc<T>) -> Self {
            Self {
                resolver,
                ip_store: Default::default(),
            }
        }

        pub fn with_new_resolver(self, resolver: Arc<T>) -> Self {
            Self {
                resolver,
                ip_store: self.ip_store,
            }
        }

        pub async fn local_lookup(
            &self,
            name: Name,
            record_type: RecordType,
        ) -> Option<DnsResponse> {
            let query = Query::query(name.clone(), record_type);
            let store = self.ip_store.read().await;

            let lookup = store.get(&query).cloned();

            lookup.map(|records| DnsResponse::new_with_max_ttl(query, records.to_vec()))
        }
    }

    impl BootstrapResolver<NameServerGroup> {
        pub fn from_system_conf() -> Self {
            let (resolv_config, resolv_opts) =
                crate::libdns::resolver::system_conf::read_system_conf().unwrap_or_else(|err| {
                    warn!("read system conf failed, {}", err);

                    use crate::preset_ns::{ALIDNS, ALIDNS_IPS, CLOUDFLARE, CLOUDFLARE_IPS};

                    let mut name_servers = NameServerConfigGroup::from_ips_https(
                        ALIDNS_IPS,
                        443,
                        ALIDNS.to_string(),
                        true,
                    );
                    name_servers.merge(NameServerConfigGroup::from_ips_https(
                        CLOUDFLARE_IPS,
                        443,
                        CLOUDFLARE.to_string(),
                        true,
                    ));

                    (
                        ResolverConfig::from_parts(None, vec![], name_servers),
                        ResolverOpts::default(),
                    )
                });
            let mut name_servers = vec![];

            for config in resolv_config.name_servers() {
                name_servers.push(Arc::new(config.clone().into()));
            }

            let resolv_opts = Arc::new(resolv_opts);

            Self::new(Arc::new(NameServerGroup {
                resolver_opts: resolv_opts.clone(),
                servers: name_servers,
            }))
        }
    }

    impl<T: GenericResolver + Sync + Send> std::ops::Deref for BootstrapResolver<T> {
        type Target = Arc<T>;

        fn deref(&self) -> &Self::Target {
            &self.resolver
        }
    }

    #[async_trait::async_trait]
    impl<T: GenericResolver + Sync + Send> GenericResolver for BootstrapResolver<T> {
        fn options(&self) -> &ResolverOpts {
            self.resolver.options()
        }

        #[inline]
        async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
            &self,
            name: N,
            options: O,
        ) -> Result<DnsResponse, LookupError> {
            let name = name.into_name()?;
            let options: LookupOptions = options.into();
            let record_type = options.record_type;
            if let Some(lookup) = self.local_lookup(name.clone(), record_type).await {
                return Ok(lookup);
            }

            match GenericResolver::lookup(self.resolver.as_ref(), name.clone(), options).await {
                Ok(lookup) => {
                    let records = lookup.records().to_vec();

                    debug!(
                        "lookup nameserver {} {}, {:?}",
                        name,
                        record_type,
                        records
                            .iter()
                            .flat_map(|r| r.data().ip_addr())
                            .collect::<Vec<_>>()
                    );

                    self.ip_store.write().await.insert(
                        Query::query(
                            {
                                let mut name = name.clone();
                                name.set_fqdn(true);
                                name
                            },
                            record_type,
                        ),
                        records.into(),
                    );

                    Ok(lookup)
                }
                err => err,
            }
        }
    }

    impl<T: GenericResolver + Sync + Send> From<Arc<T>> for BootstrapResolver<T> {
        fn from(resolver: Arc<T>) -> Self {
            Self::new(resolver)
        }
    }

    impl<T: GenericResolver + Sync + Send> From<&BootstrapResolver<T>> for Arc<T> {
        fn from(value: &BootstrapResolver<T>) -> Self {
            value.resolver.clone()
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        dns_url::DnsUrl,
        preset_ns::{ALIDNS_IPS, CLOUDFLARE_IPS},
        third_ext::{FutureJoinAllExt, FutureTimeoutExt},
    };
    use std::net::IpAddr;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_with_default() {
        let client = DnsClient::builder().build().await;
        let lookup_ip = client
            .lookup("dns.alidns.com", RecordType::A)
            .await
            .unwrap();
        assert!(
            lookup_ip
                .ip_addrs()
                .into_iter()
                .any(|i| i == "223.5.5.5".parse::<IpAddr>().unwrap()
                    || i == "223.6.6.6".parse::<IpAddr>().unwrap())
        );
    }

    async fn query_google(client: &DnsClient) -> bool {
        let name = "dns.google";
        let addrs = match client
            .lookup_ip(name)
            .timeout(std::time::Duration::from_secs(5))
            .await
        {
            Ok(Ok(lookup)) => lookup
                .ip_addrs()
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            Ok(Err(e)) => e.to_string(),
            Err(e) => e.to_string(),
        };
        // println!("name: {} addrs => {}", name, addrs);
        addrs.contains("8.8.8.8") || addrs.contains("8.8.4.4")
    }

    async fn query_alidns(client: &DnsClient) -> bool {
        let name = "dns.alidns.com";
        let addrs = match client
            .lookup_ip(name)
            .timeout(std::time::Duration::from_secs(5))
            .await
        {
            Ok(Ok(lookup)) => lookup
                .ip_addrs()
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(" "),
            Ok(Err(e)) => e.to_string(),
            Err(e) => e.to_string(),
        };

        // println!("name: {} addrs => {}", name, addrs);
        addrs.contains("223.5.5.5") || addrs.contains("223.6.6.6")
    }

    #[tokio::test]
    #[cfg(feature = "dns-over-tls")]
    async fn test_nameserver_tls_resolve() {
        let urls = [
            DnsUrl::from_str("tls://dns.google?enable_sni=false").unwrap(),
            DnsUrl::from_str("tls://dns.cloudflare.com?enable_sni=false").unwrap(),
            DnsUrl::from_str("tls://dns.quad9.net?enable_sni=false").unwrap(),
            DnsUrl::from_str("tls://dns.alidns.com").unwrap(),
            DnsUrl::from_str("tls://dot.pub").unwrap(),
        ];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        let total = results.len() as f32;
        let success = results.into_iter().filter(|r| *r).count();
        println!("test_nameserver_tls_resolve, success: {success}/{total}");
        assert!(success > 0);
    }

    #[tokio::test]
    #[cfg(feature = "dns-over-https")]
    async fn test_nameserver_https_resolve() {
        let urls = [
            DnsUrl::from_str("https://dns.cloudflare.com/dns-query").unwrap(),
            DnsUrl::from_str("https://dns.alidns.com/dns-query").unwrap(),
            DnsUrl::from_str("https://223.5.5.5/dns-query").unwrap(),
            DnsUrl::from_str("https://doh.pub/dns-query").unwrap(),
            DnsUrl::from_str("https://dns.adguard-dns.com/dns-query").unwrap(),
            DnsUrl::from_str("https://dns.quad9.net/dns-query").unwrap(),
        ];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        assert!(results.into_iter().any(|r| r));
    }

    #[tokio::test]
    #[cfg(feature = "dns-over-h3")]
    async fn test_nameserver_h3_resolve() {
        let urls = [DnsUrl::from_str("h3://dns.adguard-dns.com/dns-query").unwrap()];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        assert!(results.into_iter().all(|r| r));
    }

    #[tokio::test]
    #[cfg(feature = "dns-over-h3")]
    async fn test_nameserver_h3_with_ipv6_address_resolve() {
        // Skip the test if the IPv6 address is not reachable.
        if crate::infra::ping::ping(
            "https://2001:4860:4860::8888".parse().unwrap(),
            Default::default(),
        )
        .await
        .is_err()
        {
            return;
        }

        let urls = [DnsUrl::from_str("h3://[2001:4860:4860::8888]").unwrap()];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        assert!(results.into_iter().all(|r| r));
    }

    #[tokio::test]
    async fn test_nameserver_cloudflare_resolve() {
        let dns_urls = CLOUDFLARE_IPS.iter().map(DnsUrl::from).collect::<Vec<_>>();

        let client = DnsClient::builder().add_servers(dns_urls).build().await;
        assert!(query_google(&client).await);
        assert!(query_alidns(&client).await);
    }

    #[tokio::test]
    async fn test_nameserver_alidns_resolve() {
        let dns_urls = ALIDNS_IPS.iter().map(DnsUrl::from).collect::<Vec<_>>();
        let client = DnsClient::builder().add_servers(dns_urls).build().await;
        assert!(query_google(&client).await);
        assert!(query_alidns(&client).await);
    }

    #[tokio::test]
    #[cfg(feature = "dns-over-quic")]
    async fn test_nameserver_quic_resolve() {
        let urls = [
            DnsUrl::from_str("quic://dns.adguard-dns.com").unwrap(),
            DnsUrl::from_str("quic://unfiltered.adguard-dns.com?enable_sni=true").unwrap(),
        ];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        assert!(results.into_iter().all(|r| r));
    }

    #[tokio::test]
    #[cfg(feature = "dns-over-quic")]
    async fn test_nameserver_quic_over_proxy_resolve() {
        let urls = [
            DnsUrl::from_str("quic://dns.adguard-dns.com").unwrap(),
            DnsUrl::from_str("quic://unfiltered.adguard-dns.com?enable_sni=true").unwrap(),
        ];

        let results = urls
            .into_iter()
            .map(|url| async move {
                let client = DnsClient::builder().add_server(url).build().await;
                query_google(&client).await && query_alidns(&client).await
            })
            .join_all()
            .await;

        assert!(results.into_iter().all(|r| r));
    }

    // #[test]
    // fn test_bootstrap_resolver() {
    //     assert_eq!(bootstrap::RESOLVER.deref(), &99);
    //     *once_cell::sync::Lazy::force_mut(&mut lazy) = 88;
    //     assert_eq!(bootstrap::RESOLVER.deref(), &88);
    // }
}
