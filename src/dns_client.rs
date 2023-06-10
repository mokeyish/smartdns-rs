use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
    path::PathBuf,
    slice::Iter,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::RwLock;
use trust_dns_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};

use crate::{
    dns_url::DnsUrlParamExt,
    proxy::ProxyConfig,
    rustls::TlsClientConfigBundle,
    trust_dns::proto::{
        error::ProtoResult,
        op::{Edns, Message, MessageType, OpCode, Query},
        rr::{
            domain::{IntoName, Name},
            Record, RecordType,
        },
        xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
        DnsHandle,
    },
};

use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverOpts, TlsClientConfig},
    lookup::Lookup,
    lookup_ip::LookupIp,
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

        let tls_client_config = TlsClientConfigBundle::new(ca_path, ca_file);

        bootstrap::set_resolver(
            async {
                let mut bootstrap_infos = server_infos
                    .iter()
                    .filter(|info| {
                        info.bootstrap_dns && {
                            if info.url.addrs().is_empty() {
                                warn!("bootstrap-dns must use ip addess, {:?}", info.url.host());
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
                        .filter(|info| !info.url.addrs().is_empty())
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
                        info!("bootstrap-dns {}", info.url.to_string());
                    }
                }

                let resolver = BootstrapResolver::from_system_conf();

                let resolver: Arc<BootstrapResolver> = if !bootstrap_infos.is_empty() {
                    let new_resolver = Self::create_name_server_group(
                        &bootstrap_infos,
                        tls_client_config.clone(),
                        &Default::default(),
                        client_subnet,
                    )
                    .await;
                    resolver.with_new_resolver(new_resolver.into())
                } else {
                    resolver
                }
                .into();
                resolver
            }
            .await,
        )
        .await;

        let name_server_info_groups =
            server_infos
                .into_iter()
                .fold(HashMap::new(), |mut map, info| {
                    let name = info
                        .group
                        .as_deref()
                        .map(NameServerGroupName::from)
                        .unwrap_or(NameServerGroupName::Default);
                    if name != NameServerGroupName::Default
                        && !info.exclude_default_group
                        && map
                            .entry(NameServerGroupName::Default)
                            .or_insert_with(HashSet::new)
                            .insert(info.clone())
                    {
                        debug!("append {} to default group.", info.url.to_string());
                    }

                    map.entry(name).or_insert_with(HashSet::new).insert(info);
                    map
                });

        let mut servers = HashMap::with_capacity(name_server_info_groups.len());

        for (group_name, group) in name_server_info_groups {
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
            tls_client_config,
            proxies,
            client_subnet,
        }
    }

    async fn create_name_server_group(
        infos: &[NameServerInfo],
        tls_client_config: TlsClientConfigBundle,
        proxies: &HashMap<String, ProxyConfig>,
        default_client_subnet: Option<ClientSubnet>,
    ) -> NameServerGroup {
        let mut servers = vec![];

        let resolver = bootstrap::resolver().await;

        for info in infos {
            let url = info.url.clone();
            let verified_url = match TryInto::<VerifiedDnsUrl>::try_into(url) {
                Ok(url) => url,
                Err(mut url) => {
                    if let Some(host) = url.domain() {
                        let ips = match resolver.lookup_ip(host).await {
                            Ok(lookup_ip) => lookup_ip.into_iter().collect::<Vec<_>>(),
                            Err(_) => vec![],
                        };
                        url.set_ip_addrs(ips);
                    }
                    match TryInto::<VerifiedDnsUrl>::try_into(url) {
                        Ok(url) => url,
                        _ => continue,
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
                *resolver.options(),
            );

            let name_server_configs =
                NameServer::create_config_from_url(&verified_url, tls_client_config.clone());

            let proxy = info
                .proxy
                .as_deref()
                .map(|n| proxies.get(n))
                .unwrap_or_default()
                .cloned();

            for name_server_config in name_server_configs {
                servers.push(NameServer::new(
                    name_server_config,
                    nameserver_opts.clone(),
                    proxy.clone(),
                    info.so_mark,
                ))
            }
        }

        NameServerGroup {
            resolver_opts: resolver.options().to_owned(),
            servers,
        }
    }
}

pub struct DnsClient {
    resolver_opts: ResolverOpts,
    #[allow(clippy::type_complexity)]
    servers:
        HashMap<NameServerGroupName, (Vec<NameServerInfo>, RwLock<Option<Arc<NameServerGroup>>>)>,
    tls_client_config: TlsClientConfigBundle,
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
                        DnsClientBuilder::create_name_server_group(
                            infos,
                            self.tls_client_config.clone(),
                            &self.proxies,
                            self.client_subnet,
                        )
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

    pub async fn lookup_nameserver(&self, name: Name, record_type: RecordType) -> Option<Lookup> {
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
    ) -> Result<Lookup, LookupError> {
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
    servers: Vec<NameServer>,
}

impl NameServerGroup {
    #[inline]
    pub fn iter(&self) -> Iter<NameServer> {
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
    ) -> Result<Lookup, LookupError> {
        use futures_util::future::select_all;
        let name = name.into_name()?;
        let mut tasks = self
            .servers
            .iter()
            .map(|ns| GenericResolver::lookup(ns, name.clone(), options.clone()))
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
    opts: NameServerOpts,
    inner: trust_dns_resolver::name_server::NameServer<TokioRuntimeProvider>,
}

impl NameServer {
    fn new(
        config: NameServerConfig,
        opts: NameServerOpts,
        proxy: Option<ProxyConfig>,
        so_mark: Option<u32>,
    ) -> Self {
        use trust_dns_resolver::name_server::NameServer as N;

        let inner = N::<TokioRuntimeProvider>::new(
            config,
            opts.resolver_opts,
            TokioRuntimeProvider::new(proxy, so_mark),
        );

        Self { opts, inner }
    }

    #[inline]
    pub fn options(&self) -> &NameServerOpts {
        &self.opts
    }

    fn create_config_from_url(
        url: &VerifiedDnsUrl,
        tls_client_config: TlsClientConfigBundle,
    ) -> Vec<NameServerConfig> {
        let host = url.domain();

        let tls_dns_name = host
            .map(|h| h.to_string())
            .unwrap_or_else(|| url.host().to_string());

        use trust_dns_resolver::config::Protocol::*;
        let sock_addrs = url.addrs().iter().cloned();

        let tls_config = |url: &VerifiedDnsUrl| {
            if url.proto().is_encrypted() {
                let config = if !url.ssl_verify() {
                    tls_client_config.verify_off.clone()
                } else if url.sni_off() {
                    tls_client_config.sni_off.clone()
                } else {
                    tls_client_config.normal.clone()
                };

                Some(TlsClientConfig(config))
            } else {
                None
            }
        };

        let cfgs = match url.proto() {
            Udp => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    tls_config: None,
                    trust_negative_responses: true,
                    bind_addr: None,
                })
                .collect::<Vec<_>>(),
            Tcp => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Tcp,
                    tls_dns_name: None,
                    tls_config: None,
                    trust_negative_responses: true,
                    bind_addr: None,
                })
                .collect::<Vec<_>>(),
            Https => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Https,
                    tls_dns_name: Some(tls_dns_name.clone()),
                    trust_negative_responses: true,
                    bind_addr: None,
                    tls_config: tls_config(url),
                })
                .collect::<Vec<_>>(),
            Quic => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Quic,
                    tls_dns_name: Some(tls_dns_name.clone()),
                    trust_negative_responses: true,
                    bind_addr: None,
                    tls_config: tls_config(url),
                })
                .collect::<Vec<_>>(),
            Protocol::Tls => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Tls,
                    tls_dns_name: Some(tls_dns_name.clone()),
                    trust_negative_responses: true,
                    bind_addr: None,
                    tls_config: tls_config(url),
                })
                .collect::<Vec<_>>(),
            _ => todo!(),
        };
        cfgs
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
    ) -> Result<Lookup, LookupError> {
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
            build_message(query, request_options, client_subnet),
            request_options,
        );

        let mut ns = self.inner.clone();

        let res = ns.send(req).first_answer().await?;

        let valid_until = Instant::now()
            + Duration::from_secs(
                res.answers()
                    .iter()
                    .map(|r| r.ttl())
                    .min()
                    .unwrap_or(MAX_TTL) as u64,
            );

        Ok(Lookup::new_with_deadline(
            res.query().unwrap().clone(),
            res.answers().into(),
            valid_until,
        ))
    }
}

#[derive(Default, Clone)]
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
    ) -> Result<Lookup, LookupError>;
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
    ) -> Result<LookupIp, LookupError>;
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
    ) -> Result<LookupIp, LookupError> {
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
                let lookup = Lookup::new_with_max_ttl(query, Arc::from([record]));
                return Ok(lookup.into());
            }
        }

        let name = match (maybe_name, finally_ip_addr.as_ref()) {
            (Ok(name), _) => name,
            (Err(_), Some(ip_addr)) => {
                // it was a valid IP, return that...
                let query = Query::query(ip_addr.name().clone(), ip_addr.record_type());
                let lookup = Lookup::new_with_max_ttl(query, Arc::from([ip_addr.clone()]));
                return Ok(lookup.into());
            }
            (Err(err), None) => {
                return Err(err.into());
            }
        };

        let strategy = self.options().ip_strategy;
        use trust_dns_resolver::config::LookupIpStrategy::*;

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
        .map(|lookup| lookup.into())
    }
}

pub struct VerifiedDnsUrl(DnsUrl);

impl Deref for VerifiedDnsUrl {
    type Target = DnsUrl;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::convert::TryFrom<DnsUrl> for VerifiedDnsUrl {
    type Error = DnsUrl;

    fn try_from(value: DnsUrl) -> Result<Self, Self::Error> {
        if value.addrs().is_empty() {
            return Err(value);
        }
        Ok(Self(value))
    }
}

#[derive(Clone)]
pub struct LookupOptions {
    pub record_type: RecordType,
    pub client_subnet: Option<ClientSubnet>,
}

impl Default for LookupOptions {
    fn default() -> Self {
        Self {
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
    if client_subnet.is_some() || request_options.use_edns {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);

        if let (Some(client_subnet), Some(edns)) = (client_subnet, message.extensions_mut()) {
            edns.options_mut().insert(EdnsOption::Subnet(client_subnet));
        }
    }
    message
}

mod connection_provider {

    use super::*;
    use crate::proxy;

    use std::{io, net::SocketAddr, pin::Pin};

    use futures::Future;
    use tokio::net::UdpSocket as TokioUdpSocket;
    use trust_dns_proto::{iocompat::AsyncIoTokioAsStd, TokioTime};
    use trust_dns_resolver::{name_server::RuntimeProvider, TokioHandle};

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
    use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig};

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

        pub async fn local_lookup(&self, name: Name, record_type: RecordType) -> Option<Lookup> {
            let query = Query::query(name.clone(), record_type);
            let store = self.ip_store.read().await;

            let lookup = store.get(&query).cloned();

            lookup.map(|records| Lookup::new_with_max_ttl(query, records))
        }
    }

    impl BootstrapResolver<NameServerGroup> {
        pub fn from_system_conf() -> Self {
            let (resolv_config, resolv_opts) = trust_dns_resolver::system_conf::read_system_conf()
                .unwrap_or_else(|err| {
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
                name_servers.push(super::NameServer::new(
                    config.clone(),
                    Default::default(),
                    None,
                    None,
                ));
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
        ) -> Result<Lookup, LookupError> {
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
    };
    use std::net::IpAddr;
    use std::str::FromStr;
    use tokio::runtime::Runtime;

    #[tokio::test]
    async fn test_with_default() {
        let client = DnsClient::builder().build().await;
        let lookup_ip = client
            .lookup("dns.alidns.com", RecordType::A)
            .await
            .unwrap();
        assert!(lookup_ip.into_iter().any(|i| i.ip_addr()
            == Some("223.5.5.5".parse::<IpAddr>().unwrap())
            || i.ip_addr() == Some("223.6.6.6".parse::<IpAddr>().unwrap())));
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

    async fn assert_google(client: &DnsClient) {
        let name = "dns.google";
        let addrs = client
            .lookup_ip(name)
            .await
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        // println!("name: {} addrs => {}", name, addrs);

        assert!(addrs.contains("8.8.8.8"));
    }

    async fn assert_alidns(client: &DnsClient) {
        let name = "dns.alidns.com";
        let addrs = client
            .lookup_ip(name)
            .await
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        // println!("name: {} addrs => {}", name, addrs);

        assert!(addrs.contains("223.5.5.5") || addrs.contains("223.6.6.6"));
    }

    #[test]
    fn test_nameserver_google_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dns.google?enable_sni=false").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_cloudflare_resolve() {
        // todo:// support alias.
        let dns_urls = CLOUDFLARE_IPS.iter().map(DnsUrl::from).collect::<Vec<_>>();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_servers(dns_urls).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_cloudflare_https_resolve() {
        let dns_url = DnsUrl::from_str("https://cloudflare-dns.com/dns-query").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    #[ignore = "reason"]
    fn test_nameserver_cloudflare_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dns.cloudflare.com?enable_sni=false").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_quad9_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dns.quad9.net?enable_sni=false").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_quad9_dns_url_https_resolve() {
        let dns_url = DnsUrl::from_str("https://dns.quad9.net/dns-query").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_resolve() {
        // todo:// support alias.
        let dns_urls = ALIDNS_IPS.iter().map(DnsUrl::from).collect::<Vec<_>>();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_servers(dns_urls).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_dns_url_https_resolve() {
        let dns_url = DnsUrl::from_str("https://dns.alidns.com/dns-query").unwrap();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_dns_url_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dns.alidns.com").unwrap();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_https_tls_name_with_ip_resolve() {
        let dns_url = DnsUrl::from_str("https://223.5.5.5/dns-query").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;

            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_dnspod_https_resolve() {
        let dns_url = DnsUrl::from_str("https://doh.pub/dns-query").unwrap();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_dnspod_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dot.pub").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;

            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_adguard_https_resolve() {
        let dns_url = DnsUrl::from_str("https://dns.adguard-dns.com/dns-query").unwrap();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    #[ignore = "not available now"]
    fn test_nameserver_adguard_quic_resolve() {
        let dns_url = DnsUrl::from_str("quic://dns.adguard-dns.com").unwrap();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build().await;
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    // #[test]
    // fn test_bootstrap_resolver() {
    //     assert_eq!(bootstrap::RESOLVER.deref(), &99);
    //     *once_cell::sync::Lazy::force_mut(&mut lazy) = 88;
    //     assert_eq!(bootstrap::RESOLVER.deref(), &88);
    // }
}
