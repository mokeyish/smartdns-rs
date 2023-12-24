use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    slice::Iter,
    sync::Arc,
};

use crate::{
    dns::DnsResponse,
    libdns::proto::rr::rdata::opt::{ClientSubnet, EdnsOption},
};
use tokio::sync::RwLock;

use crate::{
    dns_url::DnsUrlParamExt,
    libdns::proto::{
        error::ProtoResult,
        op::{Edns, Message, MessageType, OpCode, Query},
        rr::{
            domain::{IntoName, Name},
            Record, RecordType,
        },
        xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
        DnsHandle,
    },
    proxy::ProxyConfig,
    rustls::TlsClientConfigBundle,
};

use crate::libdns::resolver::{
    config::{NameServerConfig, Protocol, ResolverOpts, TlsClientConfig},
    name_server::GenericConnector,
    TryParseIp,
};

use crate::{
    dns_conf::NameServerInfo,
    dns_error::LookupError,
    dns_url::DnsUrl,
    log::{debug, info, warn},
};

use bootstrap::BootstrapResolver;
use connection_provider::TokioRuntimeProvider;

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
///   Setting this to a value of 1 day, in seconds
pub const MAX_TTL: u32 = 86400_u32;

#[derive(Default)]
pub struct DnsClientBuilder {
    resolver_opts: ResolverOpts,
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
            resolver_opts,
            server_infos,
            ca_file,
            ca_path,
            proxies,
            client_subnet,
        } = self;

        let factory = NameServerFactory::new(TlsClientConfigBundle::new(ca_path, ca_file));

        bootstrap::set_resolver(
            async {
                let mut bootstrap_infos = server_infos
                    .iter()
                    .filter(|info| {
                        info.bootstrap_dns && {
                            if info.server.ip().is_none() {
                                warn!("bootstrap-dns must use ip addess, {:?}", info.server.host());
                                false
                            } else {
                                true
                            }
                        }
                    })
                    .cloned()
                    .collect::<Vec<_>>();

                if bootstrap_infos.is_empty() {
                    bootstrap_infos = server_infos
                        .iter()
                        .filter(|info| info.server.ip().is_some() && info.proxy.is_none())
                        .cloned()
                        .collect::<Vec<_>>()
                }

                if bootstrap_infos.is_empty() {
                    warn!("not bootstrap-dns found, use system_conf instead.");
                } else {
                    bootstrap_infos.dedup();
                }

                if !bootstrap_infos.is_empty() {
                    for info in &bootstrap_infos {
                        info!("bootstrap-dns {}", info.server.to_string());
                    }
                }

                let resolver: Arc<BootstrapResolver> = if !bootstrap_infos.is_empty() {
                    let new_resolver = factory
                        .create_name_server_group(
                            &bootstrap_infos,
                            &Default::default(),
                            client_subnet,
                        )
                        .await;
                    BootstrapResolver::new(new_resolver.into())
                } else {
                    BootstrapResolver::from_system_conf()
                }
                .into();

                resolver
            }
            .await,
        )
        .await;

        let server_groups: HashMap<NameServerGroupName, HashSet<NameServerInfo>> =
            server_infos.iter().fold(HashMap::new(), |mut map, info| {
                let mut group_names = info
                    .group
                    .iter()
                    .map(|s| s.deref())
                    .map(NameServerGroupName::from)
                    .collect::<Vec<_>>();

                if group_names.is_empty() {
                    group_names.push(NameServerGroupName::Default);
                }

                for name in group_names {
                    if name != NameServerGroupName::Default
                        && !info.exclude_default_group
                        && map
                            .entry(NameServerGroupName::Default)
                            .or_default()
                            .insert(info.clone())
                    {
                        debug!("append {} to default group.", info.server.to_string());
                    }

                    map.entry(name).or_default().insert(info.clone());
                }
                map
            });

        let mut servers = HashMap::with_capacity(server_groups.len());

        for (group_name, group) in server_groups {
            let group = group.into_iter().collect::<Vec<_>>();
            let resolver = Default::default();
            debug!(
                "create name server {:?}, servers {}",
                group_name,
                group.len()
            );
            servers.insert(group_name.clone(), (group, resolver));
        }

        DnsClient {
            resolver_opts,
            servers,
            factory,
            proxies,
            client_subnet,
        }
    }
}

pub struct DnsClient {
    resolver_opts: ResolverOpts,
    #[allow(clippy::type_complexity)]
    servers:
        HashMap<NameServerGroupName, (Vec<NameServerInfo>, RwLock<Option<Arc<NameServerGroup>>>)>,
    factory: NameServerFactory,
    proxies: Arc<HashMap<String, ProxyConfig>>,
    client_subnet: Option<ClientSubnet>,
}

impl DnsClient {
    pub fn builder() -> DnsClientBuilder {
        DnsClientBuilder::default()
    }

    pub async fn default(&self) -> Arc<NameServerGroup> {
        match self.get_server_group(NameServerGroupName::Default).await {
            Some(server) => server,
            None => bootstrap::resolver().await.as_ref().into(),
        }
    }

    pub async fn get_server_group<N: Into<NameServerGroupName>>(
        &self,
        name: N,
    ) -> Option<Arc<NameServerGroup>> {
        let name = name.into();
        match self.servers.get(&name) {
            Some((infos, entry_lock)) => {
                let entry = entry_lock.read().await;

                if entry.is_none() {
                    drop(entry);

                    debug!("initialize name server {:?}", name);
                    let ns = Arc::new(
                        self.factory
                            .create_name_server_group(infos, &self.proxies, self.client_subnet)
                            .await,
                    );
                    entry_lock.write().await.replace(ns.clone());
                    Some(ns)
                } else {
                    entry.as_ref().cloned()
                }
            }
            None => None,
        }
    }

    pub async fn lookup_nameserver(
        &self,
        name: Name,
        record_type: RecordType,
    ) -> Option<DnsResponse> {
        bootstrap::resolver()
            .await
            .local_lookup(name, record_type)
            .await
    }
}

#[async_trait::async_trait]
impl GenericResolver for DnsClient {
    fn options(&self) -> &ResolverOpts {
        &self.resolver_opts
    }

    #[inline]
    async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
        &self,
        name: N,
        options: O,
    ) -> Result<DnsResponse, LookupError> {
        let ns = self.default().await;
        GenericResolver::lookup(ns.as_ref(), name, options).await
    }
}

#[derive(Clone, Eq)]
pub enum NameServerGroupName {
    Bootstrap,
    Default,
    Name(String),
}

impl NameServerGroupName {
    pub fn new(name: &str) -> Self {
        match name.to_lowercase().as_str() {
            "bootstrap" => NameServerGroupName::Bootstrap,
            "default" => NameServerGroupName::Default,
            _ => NameServerGroupName::Name(name.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Default => "default",
            Self::Name(n) => n.as_str(),
        }
    }

    #[inline]
    pub fn is_default(&self) -> bool {
        self.as_str() == "default"
    }
}

impl std::hash::Hash for NameServerGroupName {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            NameServerGroupName::Bootstrap => "bootstrap".hash(state),
            NameServerGroupName::Default => "default".hash(state),
            NameServerGroupName::Name(n) => n.to_lowercase().as_str().hash(state),
        }
    }
}

impl std::fmt::Debug for NameServerGroupName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bootstrap => write!(f, "[Group: Bootstrap]"),
            Self::Default => write!(f, "[Group: Default]"),
            Self::Name(name) => write!(f, "[Group: {}]", name),
        }
    }
}

impl From<&str> for NameServerGroupName {
    #[inline]
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl Deref for NameServerGroupName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            NameServerGroupName::Bootstrap => "Bootstrap",
            NameServerGroupName::Default => "Default",
            NameServerGroupName::Name(s) => s.as_str(),
        }
    }
}

impl PartialEq for NameServerGroupName {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Name(l0), Self::Name(r0)) => l0.eq_ignore_ascii_case(r0),
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl Default for NameServerGroupName {
    fn default() -> Self {
        Self::Default
    }
}

#[derive(Default)]
pub struct NameServerGroup {
    resolver_opts: ResolverOpts,
    servers: Vec<Arc<NameServer>>,
}

impl NameServerGroup {
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

pub struct NameServerFactory {
    tls_client_config: TlsClientConfigBundle,
    cache: RwLock<HashMap<String, Arc<NameServer>>>,
}

impl NameServerFactory {
    pub fn new(tls_client_config: TlsClientConfigBundle) -> Self {
        Self {
            tls_client_config,
            cache: Default::default(),
        }
    }

    pub async fn create(
        &self,
        url: &VerifiedDnsUrl,
        proxy: Option<ProxyConfig>,
        so_mark: Option<u32>,
        resolver_opts: NameServerOpts,
    ) -> Arc<NameServer> {
        use crate::libdns::resolver::name_server::NameServer as N;

        let key = format!(
            "{}{:?}{}",
            url.to_string(),
            proxy.as_ref().map(|s| s.to_string()),
            so_mark.unwrap_or_default()
        );

        if let Some(ns) = self.cache.read().await.get(&key) {
            return ns.clone();
        }

        let config = Self::create_config_from_url(url, self.tls_client_config.clone());

        let inner = N::<GenericConnector<TokioRuntimeProvider>>::new(
            config,
            resolver_opts.deref().to_owned(),
            GenericConnector::new(TokioRuntimeProvider::new(proxy, so_mark)),
        );

        let ns = Arc::new(NameServer {
            opts: resolver_opts,
            inner,
        });
        self.cache.write().await.insert(key, ns.clone());
        ns
    }

    fn create_config_from_url(
        url: &VerifiedDnsUrl,
        tls_client_config: TlsClientConfigBundle,
    ) -> NameServerConfig {
        use crate::libdns::resolver::config::Protocol::*;

        let addr = url.addr();

        let tls_dns_name = Some(url.host().to_string());

        let tls_config = if url.proto().is_encrypted() {
            let config = if !url.ssl_verify() {
                tls_client_config.verify_off
            } else if url.sni_off() {
                tls_client_config.sni_off
            } else {
                tls_client_config.normal
            };

            Some(TlsClientConfig(config))
        } else {
            None
        };

        match url.proto() {
            Udp => NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                tls_config: None,
                trust_negative_responses: true,
                bind_addr: None,
            },
            Tcp => NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                tls_config: None,
                trust_negative_responses: true,
                bind_addr: None,
            },
            #[cfg(feature = "dns-over-https")]
            Https => NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Https,
                tls_dns_name,
                trust_negative_responses: true,
                bind_addr: None,
                tls_config,
            },
            #[cfg(feature = "dns-over-quic")]
            Quic => NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Quic,
                tls_dns_name,
                trust_negative_responses: true,
                bind_addr: None,
                tls_config,
            },
            #[cfg(feature = "dns-over-tls")]
            Tls => NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Tls,
                tls_dns_name,
                trust_negative_responses: true,
                bind_addr: None,
                tls_config,
            },
            #[cfg(feature = "dns-over-h3")]
            H3 => NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::H3,
                tls_dns_name,
                trust_negative_responses: true,
                bind_addr: None,
                tls_config,
            },
            _ => todo!(),
        }
    }

    async fn create_name_server_group(
        &self,
        infos: &[NameServerInfo],
        proxies: &HashMap<String, ProxyConfig>,
        default_client_subnet: Option<ClientSubnet>,
    ) -> NameServerGroup {
        let mut servers = vec![];

        let resolver = bootstrap::resolver().await;

        for info in infos {
            let url = info.server.clone();
            let verified_urls = match TryInto::<VerifiedDnsUrl>::try_into(url) {
                Ok(url) => vec![url],
                Err(url) => {
                    if let Some(domain) = url.domain() {
                        match resolver.lookup_ip(domain).await {
                            Ok(lookup_ip) => lookup_ip
                                .ips()
                                .into_iter()
                                .map_while(|ip| {
                                    let mut url = url.clone();
                                    url.set_ip(ip);
                                    TryInto::<VerifiedDnsUrl>::try_into(url).ok()
                                })
                                .collect::<Vec<_>>(),
                            Err(err) => {
                                warn!("lookup ip: {domain} failed, {err}");
                                vec![]
                            }
                        }
                    } else {
                        vec![]
                    }
                }
            };

            let nameserver_opts = NameServerOpts::new(
                info.blacklist_ip,
                info.whitelist_ip,
                info.check_edns,
                info.edns_client_subnet
                    .map(|x| x.into())
                    .or(default_client_subnet),
                resolver.options().clone(),
            );

            let proxy = info
                .proxy
                .as_deref()
                .map(|n| proxies.get(n))
                .unwrap_or_default()
                .cloned();

            for url in verified_urls {
                servers.push(
                    self.create(&url, proxy.clone(), info.so_mark, nameserver_opts.clone())
                        .await,
                )
            }
        }

        NameServerGroup {
            resolver_opts: resolver.options().to_owned(),
            servers,
        }
    }
}

pub struct NameServer {
    opts: NameServerOpts,
    inner: crate::libdns::resolver::name_server::NameServer<GenericConnector<TokioRuntimeProvider>>,
}

impl NameServer {
    fn new(
        config: NameServerConfig,
        opts: NameServerOpts,
        proxy: Option<ProxyConfig>,
        so_mark: Option<u32>,
    ) -> Self {
        use crate::libdns::resolver::name_server::NameServer as N;

        let inner = N::<GenericConnector<TokioRuntimeProvider>>::new(
            config,
            opts.resolver_opts.clone(),
            GenericConnector::new(TokioRuntimeProvider::new(proxy, so_mark)),
        );

        Self { opts, inner }
    }

    #[inline]
    pub fn options(&self) -> &NameServerOpts {
        &self.opts
    }
}

#[async_trait::async_trait]
impl GenericResolver for NameServer {
    fn options(&self) -> &ResolverOpts {
        &self.opts
    }

    async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
        &self,
        name: N,
        options: O,
    ) -> Result<DnsResponse, LookupError> {
        let name = name.into_name()?;
        let options: LookupOptions = options.into();

        let request_options = {
            let opts = &self.options();
            let mut request_opts = DnsRequestOptions::default();
            request_opts.recursion_desired = opts.recursion_desired;
            request_opts.use_edns = opts.edns0;
            request_opts
        };

        let query = Query::query(name, options.record_type);

        let client_subnet = options.client_subnet.or(self.opts.client_subnet);

        let req = DnsRequest::new(
            build_message(query, request_options, client_subnet, options.is_dnssec),
            request_options,
        );

        let ns = self.inner.clone();

        let res = ns.send(req).first_answer().await?;

        Ok(From::<Message>::from(res.into()))
    }
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
    /// Generic lookup for any RecordType
    ///
    /// # Arguments
    ///
    /// * `name` - name of the record to lookup, if name is not a valid domain name, an error will be returned
    /// * `record_type` - type of record to lookup, all RecordData responses will be filtered to this type
    ///
    /// # Returns
    ///
    //  A future for the returned Lookup RData
    // async fn lookup<N: IntoName + Send>(
    //     &self,
    //     name: N,
    //     record_type: RecordType,
    // ) -> Result<Lookup, ResolveError>;

    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    async fn lookup_ip<N: IntoName + TryParseIp + Send>(
        &self,
        host: N,
    ) -> Result<DnsResponse, LookupError>;
}

#[async_trait::async_trait]
impl<T> GenericResolverExt for T
where
    T: GenericResolver + Sync,
{
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    async fn lookup_ip<N: IntoName + TryParseIp + Send>(
        &self,
        host: N,
    ) -> Result<DnsResponse, LookupError> {
        let mut finally_ip_addr: Option<Record> = None;
        let maybe_ip = host.try_parse_ip();
        let maybe_name: ProtoResult<Name> = host.into_name();

        // if host is a ip address, return directly.
        if let Some(ip_addr) = maybe_ip {
            let name = maybe_name.clone().unwrap_or_default();
            let record = Record::from_rdata(name.clone(), MAX_TTL, ip_addr.clone());

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
                use futures_util::future::{select, Either};
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

pub struct VerifiedDnsUrl(DnsUrl);

impl VerifiedDnsUrl {
    pub fn ip(&self) -> IpAddr {
        self.0.ip().expect("VerifiedDnsUrl must have ip.")
    }

    pub fn addr(&self) -> SocketAddr {
        self.0
            .addr()
            .expect("VerifiedDnsUrl must have socket address.")
    }
}

impl Deref for VerifiedDnsUrl {
    type Target = DnsUrl;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::convert::TryFrom<DnsUrl> for VerifiedDnsUrl {
    type Error = DnsUrl;

    fn try_from(value: DnsUrl) -> Result<Self, Self::Error> {
        if value.ip().is_none() {
            return Err(value);
        }
        Ok(Self(value))
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
/// https://dnsflagday.net/2020/
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

    use std::{io, net::SocketAddr, pin::Pin};

    use crate::libdns::proto::{iocompat::AsyncIoTokioAsStd, TokioTime};
    use crate::libdns::resolver::{name_server::RuntimeProvider, TokioHandle};
    use futures::Future;
    use tokio::net::UdpSocket as TokioUdpSocket;

    /// The Tokio Runtime for async execution
    #[derive(Clone)]
    pub struct TokioRuntimeProvider {
        proxy: Option<ProxyConfig>,
        so_mark: Option<u32>,
        handle: TokioHandle,
    }

    impl TokioRuntimeProvider {
        pub fn new(proxy: Option<ProxyConfig>, so_mark: Option<u32>) -> Self {
            Self {
                proxy,
                so_mark,
                handle: TokioHandle::default(),
            }
        }
    }

    impl RuntimeProvider for TokioRuntimeProvider {
        type Handle = TokioHandle;
        type Timer = TokioTime;
        type Udp = TokioUdpSocket;
        type Tcp = AsyncIoTokioAsStd<proxy::TcpStream>;

        fn create_handle(&self) -> Self::Handle {
            self.handle.clone()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
            let proxy_config = self.proxy.clone();

            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            let so_mark = self.so_mark;
            let so_mark = move |tcp: proxy::TcpStream| {
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                if let Some(mark) = so_mark {
                    use socket2::SockRef;
                    let sock_ref = SockRef::from(tcp.deref());
                    sock_ref.set_mark(mark).unwrap_or_else(|err| {
                        warn!("set so_mark failed: {:?}", err);
                    });
                }
                tcp
            };

            Box::pin(async move {
                proxy::connect_tcp(server_addr, proxy_config.as_ref())
                    .await
                    .map(so_mark)
                    .map(AsyncIoTokioAsStd)
            })
        }

        fn bind_udp(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
            Box::pin(tokio::net::UdpSocket::bind(local_addr))
        }
    }
}

mod bootstrap {
    use crate::libdns::resolver::config::{NameServerConfigGroup, ResolverConfig};

    use super::*;

    static RESOLVER: RwLock<Option<Arc<BootstrapResolver>>> = RwLock::const_new(None);

    pub async fn resolver() -> Arc<BootstrapResolver> {
        let lock = RESOLVER.read().await;
        if lock.is_none() {
            drop(lock);
            let resolver = Arc::new(BootstrapResolver::from_system_conf());
            set_resolver(resolver.clone()).await;
            resolver
        } else {
            lock.as_ref().unwrap().clone()
        }
    }

    pub async fn set_resolver(resolver: Arc<BootstrapResolver>) {
        *(RESOLVER.write().await) = Some(resolver)
    }

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
                name_servers.push(Arc::new(super::NameServer::new(
                    config.clone(),
                    Default::default(),
                    None,
                    None,
                )));
            }

            Self::new(Arc::new(NameServerGroup {
                resolver_opts: resolv_opts.to_owned(),
                servers: name_servers,
            }))
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
                            .flat_map(|r| r.data().map(|d| d.ip_addr()))
                            .flatten()
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
        assert!(lookup_ip
            .ips()
            .into_iter()
            .any(|i| i == "223.5.5.5".parse::<IpAddr>().unwrap()
                || i == "223.6.6.6".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_name_server_group_name() {
        let a = NameServerGroupName::from("bootstrap");
        let b = NameServerGroupName::from("Bootstrap");
        assert_eq!(a, b);
        let a = NameServerGroupName::from("abc");
        let b = NameServerGroupName::from("Abc");
        assert_eq!(a, b);
    }

    async fn query_google(client: &DnsClient) -> bool {
        let name = "dns.google";
        let addrs = match client
            .lookup_ip(name)
            .timeout(std::time::Duration::from_secs(5))
            .await
        {
            Ok(Ok(lookup)) => lookup
                .ips()
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
                .ips()
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

        assert!(results.into_iter().all(|r| r));
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

    // #[test]
    // fn test_bootstrap_resolver() {
    //     assert_eq!(bootstrap::RESOLVER.deref(), &99);
    //     *once_cell::sync::Lazy::force_mut(&mut lazy) = 88;
    //     assert_eq!(bootstrap::RESOLVER.deref(), &88);
    // }
}
