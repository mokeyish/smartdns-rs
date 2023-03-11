use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
    path::PathBuf,
    slice::Iter,
    sync::Arc,
    time::{Duration, Instant},
};

use rustls::ClientConfig;
use tokio::sync::RwLock;

use crate::trust_dns::proto::{
    error::ProtoResult,
    op::{Edns, Message, MessageType, OpCode, Query},
    rr::{
        domain::{IntoName, Name},
        Record, RecordType,
    },
    xfer::{DnsRequest, DnsRequestOptions, FirstAnswer},
    DnsHandle,
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
    log::{debug, warn},
};

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
}

impl DnsClientBuilder {
    pub fn add_servers<S: Into<NameServerInfo>>(self, servers: Vec<S>) -> Self {
        servers.into_iter().fold(self, |b, s| b.add_server(s))
    }

    pub fn add_server<S: Into<NameServerInfo>>(mut self, server: S) -> Self {
        self.server_infos.push(server.into());
        self
    }

    pub fn set_ca_file(mut self, file: PathBuf) -> Self {
        self.ca_file = Some(file);
        self
    }

    pub fn set_ca_path(mut self, file: PathBuf) -> Self {
        self.ca_path = Some(file);
        self
    }

    pub async fn build(self) -> DnsClient {
        let DnsClientBuilder {
            resolver_opts,
            server_infos,
            ca_file,
            ca_path,
        } = self;

        let tls_client_config = Self::create_tls_client_config_pair(ca_path, ca_file);

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

        let bootstrap = BootstrapResolver::new(Self::create_bootstrap(resolver_opts).into());

        let bootstrap = async {
            let bootstrap_info = name_server_info_groups.get(&NameServerGroupName::Bootstrap);

            match bootstrap_info {
                Some(server_infos) => {
                    let resolver = Self::create_name_server_group(
                        NameServerGroupName::Bootstrap,
                        &server_infos.iter().cloned().collect::<Vec<_>>(),
                        tls_client_config.clone(),
                        &bootstrap,
                    )
                    .await;
                    if !resolver.is_empty() {
                        bootstrap.with_new_resolver(resolver.into())
                    } else {
                        bootstrap
                    }
                }
                None => bootstrap,
            }
        }
        .await;

        let mut servers = HashMap::with_capacity(name_server_info_groups.len());

        for (group_name, group) in name_server_info_groups {
            let group = group.into_iter().collect::<Vec<_>>();
            let resolver = if group_name == NameServerGroupName::Bootstrap {
                Some(bootstrap.resolver.clone()).into()
            } else {
                Default::default()
            };

            debug!(
                "create name server {:?}, servers {}",
                group_name,
                group.len()
            );
            servers.insert(group_name.clone(), (group, resolver));
        }

        DnsClient {
            resolver_opts,
            bootstrap,
            servers,
            tls_client_config,
        }
    }

    async fn create_name_server_group(
        name: NameServerGroupName,
        infos: &[NameServerInfo],
        tls_client_config: (Arc<ClientConfig>, Arc<ClientConfig>),
        resolver: &BootstrapResolver<impl GenericResolver + Sync + Send>,
    ) -> NameServerGroup {
        let mut servers = vec![];

        for info in infos {
            let mut url = info.url.clone();
            if url.domain().is_none() {
                use crate::preset_ns::find_dns_tls_name;
                for addr in url.addrs() {
                    if let Some(name) = find_dns_tls_name(&addr.ip()) {
                        url.set_host_name(name);
                        break;
                    }
                }
            }
            let mut verified_url = match TryInto::<VerifiedDnsUrl>::try_into(url) {
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

            // tls sni
            if let Some(n) = info.host_name.as_deref() {
                if n != "-" {
                    verified_url.set_host_name(n)
                } else {
                    verified_url.set_sni_verify(false)
                }
            }

            let nameserver_opts = NameServerOpts::new(
                info.blacklist_ip,
                info.whitelist_ip,
                info.check_edns,
                *resolver.options(),
            );

            let name_server_configs =
                NameServer::create_config_from_url(&verified_url, tls_client_config.clone());

            for name_server_config in name_server_configs {
                servers.push(NameServer::new(name_server_config, nameserver_opts.clone()))
            }
        }

        NameServerGroup {
            name,
            resolver_opts: resolver.options().to_owned(),
            servers,
        }
    }

    fn create_bootstrap(resolver_opts: ResolverOpts) -> NameServerGroup {
        let sys_cfgs = {
            #[cfg(unix)]
            {
                use trust_dns_resolver::system_conf::read_system_conf;
                // todo:// read running resolv.conf
                // let path = &[
                //     "/var/run/resolv.conf"   // macos
                // ];

                read_system_conf()
            }
            #[cfg(windows)]
            {
                use trust_dns_resolver::system_conf::read_system_conf;
                read_system_conf()
            }
        }
        .map(|(r, _)| r.name_servers().to_vec())
        .unwrap_or_default();

        use crate::preset_ns::{self, ALIDNS};
        use trust_dns_resolver::config::NameServerConfigGroup;

        let mut cfgs = NameServerConfigGroup::from_ips_https(
            preset_ns::find_dns_ips(ALIDNS).unwrap(),
            443,
            ALIDNS.to_string(),
            true,
        )
        .to_vec();

        cfgs.extend(sys_cfgs);

        let nameserver_opts = NameServerOpts {
            resolver_opts,
            ..Default::default()
        };

        let servers = cfgs
            .into_iter()
            .map(|cfg| NameServer::new(cfg, nameserver_opts.clone()))
            .collect::<Vec<_>>();

        NameServerGroup {
            name: NameServerGroupName::Bootstrap,
            resolver_opts,
            servers,
        }
    }

    fn create_tls_client_config_pair(
        ca_path: Option<PathBuf>,
        ca_file: Option<PathBuf>,
    ) -> (Arc<ClientConfig>, Arc<ClientConfig>) {
        let config = Self::create_tls_client_config(
            [ca_path, ca_file]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let mut config_sni_disable = config.clone();
        config_sni_disable.enable_sni = false;

        (Arc::new(config), Arc::new(config_sni_disable))
    }

    fn create_tls_client_config(paths: &[PathBuf]) -> ClientConfig {
        use rustls::{OwnedTrustAnchor, RootCertStore};

        const ALPN_H2: &[u8] = b"h2";

        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let certs = {
            let certs1 = rustls_native_certs::load_native_certs().unwrap_or_else(|err| {
                warn!("load native certs failed.{}", err);
                Default::default()
            });

            let certs2 = paths
                .iter()
                .filter_map(|path| {
                    match rustls_native_certs::load_certs_from_path(path.as_path()) {
                        Ok(certs) => Some(certs),
                        Err(err) => {
                            warn!("load certs from path failed.{}", err);
                            None
                        }
                    }
                })
                .flatten();

            certs1.into_iter().chain(certs2)
        };

        for cert in certs {
            root_store
                .add(&rustls::Certificate(cert.0))
                .unwrap_or_else(|err| {
                    warn!("load certs from path failed.{}", err);
                })
        }

        let mut client_config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        client_config
    }
}

pub struct DnsClient {
    resolver_opts: ResolverOpts,
    bootstrap: BootstrapResolver<NameServerGroup>,
    #[allow(clippy::type_complexity)]
    servers:
        HashMap<NameServerGroupName, (Vec<NameServerInfo>, RwLock<Option<Arc<NameServerGroup>>>)>,
    tls_client_config: (Arc<ClientConfig>, Arc<ClientConfig>),
}

impl DnsClient {
    pub fn builder() -> DnsClientBuilder {
        DnsClientBuilder::default()
    }

    pub async fn default(&self) -> Arc<NameServerGroup> {
        match self.get_server_group(NameServerGroupName::Default).await {
            Some(server) => server,
            None => self.bootstrap().resolver.clone(),
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
                            name,
                            infos,
                            self.tls_client_config.clone(),
                            self.bootstrap(),
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
        self.bootstrap().local_lookup(name, record_type).await
    }

    fn bootstrap(&self) -> &BootstrapResolver<NameServerGroup> {
        &self.bootstrap
    }
}

#[async_trait::async_trait]
impl GenericResolver for DnsClient {
    fn options(&self) -> &ResolverOpts {
        &self.resolver_opts
    }

    #[inline]
    async fn lookup(&self, name: Name, record_type: RecordType) -> Result<Lookup, LookupError> {
        let ns = self.default().await;
        GenericResolver::lookup(ns.as_ref(), name, record_type).await
    }
}

struct BootstrapResolver<T: GenericResolver>
where
    T: Send + Sync,
{
    resolver: Arc<T>,
    ip_store: RwLock<HashMap<Query, Arc<[Record]>>>,
}

impl<T: GenericResolver + Sync + Send> BootstrapResolver<T> {
    fn new(resolver: Arc<T>) -> Self {
        Self {
            resolver,
            ip_store: Default::default(),
        }
    }

    fn with_new_resolver(self, resolver: Arc<T>) -> Self {
        Self {
            resolver,
            ip_store: self.ip_store,
        }
    }

    async fn local_lookup(&self, name: Name, record_type: RecordType) -> Option<Lookup> {
        let query = Query::query(name.clone(), record_type);
        let store = self.ip_store.read().await;

        let lookup = store.get(&query).cloned();

        lookup.map(|records| Lookup::new_with_max_ttl(query, records))
    }
}

#[async_trait::async_trait]
impl<T: GenericResolver + Sync + Send> GenericResolver for BootstrapResolver<T> {
    fn options(&self) -> &ResolverOpts {
        self.resolver.options()
    }

    #[inline]
    async fn lookup(&self, name: Name, record_type: RecordType) -> Result<Lookup, LookupError> {
        debug!("lookup nameserver {} {}", name, record_type);

        if let Some(lookup) = self.local_lookup(name.clone(), record_type).await {
            return Ok(lookup);
        }

        match GenericResolver::lookup(self.resolver.as_ref(), name.clone(), record_type).await {
            Ok(lookup) => {
                self.ip_store.write().await.insert(
                    Query::query(
                        {
                            let mut name = name.clone();
                            name.set_fqdn(true);
                            name
                        },
                        record_type,
                    ),
                    lookup.records().to_vec().into(),
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
    name: NameServerGroupName,
    resolver_opts: ResolverOpts,
    servers: Vec<NameServer>,
}

impl NameServerGroup {
    #[inline]
    pub fn name(&self) -> &NameServerGroupName {
        &self.name
    }

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

    async fn lookup(&self, name: Name, record_type: RecordType) -> Result<Lookup, LookupError> {
        use futures_util::future::select_all;
        let mut tasks = self
            .servers
            .iter()
            .map(|ns| GenericResolver::lookup(ns, name.clone(), record_type))
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
    fn new(config: NameServerConfig, opts: NameServerOpts) -> Self {
        use trust_dns_resolver::name_server::NameServer as N;

        let inner =
            N::<TokioRuntimeProvider>::new(config, opts.resolver_opts, TokioRuntimeProvider::new());

        Self { opts, inner }
    }

    #[inline]
    pub fn options(&self) -> &NameServerOpts {
        &self.opts
    }

    fn create_config_from_url(
        url: &VerifiedDnsUrl,
        (tls_client_config_sni_on, tls_client_config_sni_off): (
            Arc<ClientConfig>,
            Arc<ClientConfig>,
        ),
    ) -> Vec<NameServerConfig> {
        let host = url.domain();

        let tls_dns_name = host
            .map(|h| h.to_string())
            .unwrap_or_else(|| url.host().to_string());

        use trust_dns_resolver::config::Protocol::*;
        let sock_addrs = url.addrs().iter().cloned();

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
                    tls_config: Some(TlsClientConfig(if url.enable_sni() {
                        tls_client_config_sni_on.clone()
                    } else {
                        tls_client_config_sni_off.clone()
                    })),
                })
                .collect::<Vec<_>>(),
            Protocol::Tls => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Tls,
                    tls_dns_name: Some(tls_dns_name.clone()),
                    trust_negative_responses: true,
                    bind_addr: None,
                    tls_config: Some(TlsClientConfig(if url.enable_sni() {
                        tls_client_config_sni_on.clone()
                    } else {
                        tls_client_config_sni_off.clone()
                    })),
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

    async fn lookup(&self, name: Name, record_type: RecordType) -> Result<Lookup, LookupError> {
        let request_options = {
            let opts = &self.options();
            let mut request_opts = DnsRequestOptions::default();
            request_opts.recursion_desired = opts.recursion_desired;
            request_opts.use_edns = opts.edns0;
            request_opts
        };

        let query = Query::query(name, record_type);

        let req = DnsRequest::new(build_message(query, request_options), request_options);

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

    resolver_opts: ResolverOpts,
}

impl NameServerOpts {
    #[inline]
    pub fn new(
        blacklist_ip: bool,
        whitelist_ip: bool,
        check_edns: bool,
        resolver_opts: ResolverOpts,
    ) -> Self {
        Self {
            blacklist_ip,
            whitelist_ip,
            check_edns,
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
    async fn lookup(&self, name: Name, record_type: RecordType) -> Result<Lookup, LookupError>;
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
    // async fn lookup<N: IntoName + Send>(
    //     &self,
    //     name: N,
    //     record_type: RecordType,
    // ) -> Result<Lookup, ResolveError> {
    //     let name = match name.into_name() {
    //         Ok(name) => name,
    //         Err(err) => return Err(err.into()),
    //     };
    //     GenericResolver::lookup(self, name, record_type).await
    // }

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
                let query = Query::query(name, ip_addr.to_record_type());
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

impl DerefMut for VerifiedDnsUrl {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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

/// > An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly all current networks.
/// https://dnsflagday.net/2020/
const MAX_PAYLOAD_LEN: u16 = 1232;

fn build_message(query: Query, options: DnsRequestOptions) -> Message {
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
        .set_recursion_desired(options.recursion_desired);

    // Extended dns
    if options.use_edns {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);
    }
    message
}


mod connection_provider{
    use std::io;
    use std::pin::Pin;
    use futures::Future;
    use tokio::net::UdpSocket as TokioUdpSocket;
    use tokio::net::TcpStream as TokioTcpStream;
    use trust_dns_proto::iocompat::AsyncIoTokioAsStd;

    use std::net::SocketAddr;

    use trust_dns_proto::TokioTime;
    use trust_dns_resolver::{name_server::RuntimeProvider, TokioHandle};


    /// The Tokio Runtime for async execution
    #[derive(Clone, Default)]
    pub struct TokioRuntimeProvider{
        handle : TokioHandle
    }

    impl TokioRuntimeProvider {
        pub fn new() -> Self {
            Self { handle: TokioHandle::default() }
        }
    }


    impl RuntimeProvider for TokioRuntimeProvider {
        type Handle = TokioHandle;
        type Timer = TokioTime;
        type Udp = TokioUdpSocket;
        type Tcp = AsyncIoTokioAsStd<TokioTcpStream>;

        fn create_handle(&self) -> Self::Handle {
            self.handle.clone()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
            Box::pin(async move {
                TokioTcpStream::connect(server_addr)
                    .await
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

#[cfg(test)]
mod tests {

    use super::{DnsClient, GenericResolver, NameServerGroupName, RecordType};
    use crate::{
        dns_client::GenericResolverExt,
        dns_url::DnsUrl,
        preset_ns::{ALIDNS_IPS, CLOUDFLARE_IPS},
    };
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use tokio::runtime::{self, Runtime};

    #[test]
    fn test_with_default() {
        runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let client = DnsClient::builder().build().await;
                let lookup_ip = client
                    .lookup("dns.alidns.com".parse().unwrap(), RecordType::A)
                    .await
                    .unwrap();
                assert!(lookup_ip
                    .into_iter()
                    .any(|i| i.as_a() == Some(&"223.5.5.5".parse::<Ipv4Addr>().unwrap())));
            });
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

        assert!(addrs.contains("223.5.5.5"));
    }

    #[test]
    fn test_nameserver_cloudflare_resolve() {
        // todo:// support alias.
        let dns_urls = CLOUDFLARE_IPS
            .iter()
            .map(|ip| DnsUrl::from(ip))
            .collect::<Vec<_>>();

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
        let dns_url = DnsUrl::from_str("tls://cloudflare-dns.com?enable_sni=false").unwrap();
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
        let dns_urls = ALIDNS_IPS
            .iter()
            .map(|ip| DnsUrl::from(ip))
            .collect::<Vec<_>>();

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
}
