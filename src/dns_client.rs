use crate::dns::op::Query;

use crate::dns::rr::RecordType;
use crate::dns::DnsError;
use crate::dns::Lookup;
use crate::dns::Name;
use crate::dns::Record;
use crate::dns_conf::DnsServer;
use crate::dns_url::DnsUrl;
use crate::log::{debug, warn};
use crate::matcher::DomainNameServerGroupMatcher;
use crate::preset_ns;
use crate::third_ext::FutureTimeoutExt;

use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use trust_dns_client::rr::{LowerName, RData};
use trust_dns_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
    TlsClientConfig,
};
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::lookup_ip::LookupIp;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::{IntoName, TokioHandle, TryParseIp};

const LOOKUP_TIMEOUT: u64 = 3;

fn create_resolver<T: IntoResolverConfig>(config: T) -> Result<TokioAsyncResolver, String> {
    let config = config.into();

    let mut options = {
        let mut opts = ResolverOpts::default();
        opts.cache_size = 0;
        opts
    };

    // See RFC 1034, Section 4.3.2:
    // "If the data at the node is a CNAME, and QTYPE doesn't match
    // CNAME, copy the CNAME RR into the answer section of the response,
    // change QNAME to the canonical name in the CNAME RR, and go
    // back to step 1."
    //
    // Essentially, it's saying that servers (including forwarders)
    // should emit any found CNAMEs in a response ("copy the CNAME
    // RR into the answer section"). This is the behavior that
    // preserve_intemediates enables when set to true, and disables
    // when set to false. So we set it to true.
    if !options.preserve_intermediates {
        warn!(
            "preserve_intermediates set to false, which is invalid \
            for a forwarder; switching to true"
        );
        options.preserve_intermediates = true;
    }

    let resolver = TokioAsyncResolver::new(config, options, TokioHandle)
        .map_err(|e| format!("error constructing new Resolver: {}", e))?;

    Ok(resolver)
}

pub trait IntoResolverConfig: Sized {
    fn into(self) -> ResolverConfig;
}

impl IntoResolverConfig for ResolverConfig {
    fn into(self) -> ResolverConfig {
        self
    }
}

impl IntoResolverConfig for NameServerConfigGroup {
    fn into(self) -> ResolverConfig {
        ResolverConfig::from_parts(None, vec![], self)
    }
}

pub struct DnsClientBuilder {
    matcher: Option<DomainNameServerGroupMatcher>,
    servers: HashMap<String, Vec<DnsServer>>,

    server_groups: HashMap<String, NameServerConfigGroup>,
}

impl DnsClientBuilder {
    pub fn add_server<S: Into<DnsServer>>(mut self, server: S) -> Self {
        use std::collections::hash_map::Entry::*;
        let server = server.into();

        let group_name = server
            .group
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or("default".to_string());

        match self.servers.entry(group_name) {
            Occupied(mut o) => {
                o.get_mut().push(server);
            }
            Vacant(v) => {
                v.insert(vec![server]);
            }
        };

        self
    }

    pub fn add_server_group(mut self, server_group: NameServerConfigGroup) -> Self {
        use std::collections::hash_map::Entry::*;

        match self.server_groups.entry("default".to_string()) {
            Occupied(mut o) => {
                *(o.get_mut()) = server_group;
            }
            Vacant(v) => {
                v.insert(server_group);
            }
        }

        self
    }

    pub fn build(self) -> DnsClient {
        DnsClient::new(
            self.matcher.unwrap_or_default(),
            self.servers,
            self.server_groups,
        )
    }
}

#[derive(Debug)]
pub struct DnsClient {
    bootstrap_resolver: TokioAsyncResolver,
    matcher: DomainNameServerGroupMatcher,
    servers: HashMap<String, Vec<DnsServer>>,
    server_groups: Mutex<HashMap<String, NameServerConfigGroup>>,
    resolvers: Mutex<HashMap<String, Arc<TokioAsyncResolver>>>,
    nameserver_ip_store: Mutex<HashMap<Name, Vec<IpAddr>>>,
}

impl DnsClient {
    pub fn builder() -> DnsClientBuilder {
        DnsClientBuilder {
            matcher: Default::default(),
            servers: Default::default(),
            server_groups: Default::default(),
        }
    }

    pub fn new(
        matcher: DomainNameServerGroupMatcher,
        servers: HashMap<String, Vec<DnsServer>>,
        server_groups: HashMap<String, NameServerConfigGroup>,
    ) -> Self {
        use crate::preset_ns::{ALIDNS, CLOUDFLARE, GOOGLE, QUAD9};

        let bootstrap_servers = NameServerConfigGroup::from_ips_https(
            preset_ns::find_dns_ips(ALIDNS).unwrap(),
            443,
            ALIDNS.to_string(),
            true,
        );

        let mut nameserver_ips: Mutex<HashMap<Name, Vec<IpAddr>>> = Default::default();

        let t = nameserver_ips.get_mut();

        for (name, ips) in [ALIDNS, CLOUDFLARE, GOOGLE, QUAD9].map(|name| {
            let mut domain_name = Name::from_str(name).unwrap();
            domain_name.set_fqdn(true);
            (domain_name, preset_ns::find_dns_ips(name).unwrap())
        }) {
            t.insert(name, ips.to_vec());
        }

        let bootstrap_resolver: TokioAsyncResolver =
            create_resolver(bootstrap_servers).expect("Create bootstrap resolver failed.");

        Self {
            bootstrap_resolver,
            matcher,
            servers,
            server_groups: Mutex::new(server_groups),
            resolvers: Default::default(),
            nameserver_ip_store: nameserver_ips,
        }
    }

    pub async fn lookup_nameserver_ip(
        &self,
        name: Name,
        record_type: RecordType,
    ) -> Option<Lookup> {
        if let Some(ips) = self.nameserver_ip_store.lock().await.get(&name) {
            let records = ips
                .iter()
                .filter(|ip| {
                    if record_type == RecordType::A {
                        ip.is_ipv4()
                    } else if record_type == RecordType::AAAA {
                        ip.is_ipv6()
                    } else {
                        false
                    }
                })
                .map(|ip| match ip {
                    IpAddr::V4(ip) => RData::A(*ip),
                    IpAddr::V6(ip) => RData::AAAA(*ip),
                })
                .map(|r| Record::from_rdata(name.clone(), 0, r))
                .collect();

            Some(Lookup::new_with_max_ttl(
                Query::query(name, record_type),
                records,
            ))
        } else {
            None
        }
    }

    /// Performs a dual-stack DNS lookup for the IP for the given hostname.
    ///
    /// See the configuration and options parameters for controlling the way in which A(Ipv4) and AAAA(Ipv6) lookups will be performed. For the least expensive query a fully-qualified-domain-name, FQDN, which ends in a final `.`, e.g. `www.example.com.`, will only issue one query. Anything else will always incur the cost of querying the `ResolverConfig::domain` and `ResolverConfig::search`.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be returned.
    pub async fn lookup_ip<N: IntoName + TryParseIp + Clone>(
        &self,
        host: N,
    ) -> Result<LookupIp, ResolveError> {
        if let Ok(name) = host.clone().into_name() {
            let group_name = self
                .matcher
                .find(&name.to_owned().into())
                .map(|s| s.as_str())
                .unwrap_or("default");

            self.get_or_create_resolver(group_name)
                .await
                .unwrap()
                .lookup_ip(host)
                .timeout(Duration::from_secs(LOOKUP_TIMEOUT))
                .await
                .unwrap_or(Err(ResolveErrorKind::Timeout.into()))
        } else {
            self.get_or_create_resolver("default")
                .await
                .unwrap()
                .lookup_ip(host)
                .timeout(Duration::from_secs(LOOKUP_TIMEOUT))
                .await
                .unwrap_or(Err(ResolveErrorKind::Timeout.into()))
        }
    }

    /// Lookup any RecordType
    ///
    /// *WARNING* this interface may change in the future, see if one of the specializations would be better.
    ///
    /// # Arguments
    ///
    /// * `name` - name of the record to lookup, if name is not a valid domain name, an error will be returned
    /// * `record_type` - type of record to lookup, all RecordData responses will be filtered to this type
    ///
    /// # Returns
    ///
    //  A future for the returned Lookup RData
    pub async fn lookup<N: IntoName>(
        &self,
        name: N,
        record_type: RecordType,
    ) -> Result<Lookup, DnsError> {
        let name = match name.into_name() {
            Ok(name) => name,
            Err(err) => return Err(err.into()),
        };

        let group_name = self
            .matcher
            .find(&name.to_owned().into())
            .map(|s| s.as_str())
            .unwrap_or("default");

        if let Some(resolver) = self.get_or_create_resolver(group_name).await {
            resolver
                .lookup(name, record_type)
                .timeout(Duration::from_secs(LOOKUP_TIMEOUT))
                .await
                .unwrap_or(Err(ResolveErrorKind::Timeout.into()))
        } else {
            Err(ResolveErrorKind::Message("").into())
        }
    }

    async fn get_or_create_resolver(&self, group_name: &str) -> Option<Arc<TokioAsyncResolver>> {
        let resolver = async {
            let resolvers = self.resolvers.lock().await;
            resolvers.get(group_name).map(|r| Arc::clone(r))
        }
        .await;

        if resolver.is_some() {
            return resolver;
        }

        let group_name = if self.servers.contains_key(group_name) {
            group_name
        } else {
            "default"
        };

        let nameservers = self.get_or_create_nameserver_group(group_name).await;

        if let Some(Ok(resolver)) = nameservers.map(|ss| create_resolver(ss)) {
            let resolver = Arc::new(resolver);
            let mut resolvers = self.resolvers.lock().await;

            resolvers.insert(group_name.to_string(), Arc::clone(&resolver));

            Some(resolver)
        } else {
            None
        }
    }

    async fn get_or_create_nameserver_group(
        &self,
        group_name: &str,
    ) -> Option<NameServerConfigGroup> {
        let config = async {
            let nameservers = self.server_groups.lock().await;
            nameservers.get(group_name).map(|n| n.clone())
        }
        .await;

        if config.is_some() {
            return config;
        }

        let mut name_server_cfg_group = NameServerConfigGroup::new();

        let ss = self
            .servers
            .get(group_name)
            .expect("default nameserver group not found!!!");

        for s in ss {
            if let Some(domain) = s.url.get_domain() {
                match Name::from_str(domain) {
                    Ok(domain_name) => {
                        //
                        let config = if let Some(g_name) =
                            self.matcher.find(&LowerName::from(domain_name.clone()))
                        {
                            use futures::future;

                            let config = self
                                .servers
                                .get(g_name)
                                .expect("default nameserver group not found!!!");

                            let config = future::join_all(
                                config
                                    .iter()
                                    .map(|c| self.create_nameserver_config_group(&c.url, None)),
                            )
                            .await
                            .into_iter()
                            .flat_map(|x| x.into_iter())
                            .reduce(|mut p, c| {
                                p.merge(c);
                                p
                            });

                            config
                        } else {
                            None
                        };

                        let addrs = match config {
                            Some(c) => {
                                if let Ok(resolver) = create_resolver(c) {
                                    resolver
                                        .lookup_ip(domain)
                                        .await
                                        .map(|r| r.into_iter().collect::<Vec<_>>())
                                        .unwrap_or_default()
                                } else {
                                    Default::default()
                                }
                            }
                            None => self
                                .bootstrap_resolver
                                .lookup_ip(domain)
                                .await
                                .map(|r| r.into_iter().collect::<Vec<_>>())
                                .unwrap_or_default(),
                        };

                        self.nameserver_ip_store
                            .lock()
                            .await
                            .entry(domain_name)
                            .and_modify(|v| *v = addrs.clone())
                            .or_insert(addrs.clone());

                        if let Some(s) = self
                            .create_nameserver_config_group(&s.url, Some(addrs))
                            .await
                        {
                            if !s.is_empty() {
                                name_server_cfg_group.merge(s);
                                continue;
                            }
                        }
                    }
                    Err(err) => {
                        warn!("{:?}", err);
                    }
                };
            }

            if let Some(s) = self.create_nameserver_config_group(&s.url, None).await {
                if !s.is_empty() {
                    name_server_cfg_group.merge(s);
                }
            }
        }

        let name_server_cfg_group = if let Some(Some(cfg)) = name_server_cfg_group
            .iter()
            .map(|n| n.tls_config.clone())
            .next()
        {
            name_server_cfg_group.with_client_config(cfg.0)
        } else {
            name_server_cfg_group
        };

        async {
            self.server_groups
                .lock()
                .await
                .insert(group_name.to_string(), name_server_cfg_group.clone());
        }
        .await;

        Some(name_server_cfg_group)
    }

    pub async fn create_nameserver_config_group(
        &self,
        url: &DnsUrl,
        addrs: Option<Vec<IpAddr>>,
    ) -> Option<NameServerConfigGroup> {
        use url::Host;

        let mut host = None;

        if url.proto().is_encrypted() {
            match url.host() {
                Host::Ipv4(ip) => {
                    host =
                        preset_ns::find_dns_tls_name(&ip.to_owned().into()).map(|s| s.to_string());
                }
                Host::Ipv6(ip) => {
                    host =
                        preset_ns::find_dns_tls_name(&ip.to_owned().into()).map(|s| s.to_string());
                }
                Host::Domain(domain) => host = Some(domain.to_string()),
            }

            if host.is_none() {
                warn!(
                    "Currently, encrypted dns {} with pure ip not supported!!!",
                    url.to_string()
                );
                return None;
            }
        }

        let sock_addrs = (if let Some(addrs) = addrs {
            addrs
        } else {
            match url.host() {
                Host::Domain(host) => match preset_ns::find_dns_ips(host) {
                    Some(ips) => ips.to_vec(),
                    None => self
                        .bootstrap_resolver
                        .lookup_ip(host)
                        .await
                        .map(|lo| lo.into_iter().collect::<Vec<IpAddr>>())
                        .unwrap_or_default(),
                },
                Host::Ipv4(ipv4) => vec![(*ipv4).into()],
                Host::Ipv6(ipv6) => vec![(*ipv6).into()],
            }
        })
        .into_iter()
        .map(|ip_addr| (ip_addr, url.port()).to_socket_addrs().ok())
        .flatten()
        .flatten()
        .collect::<Vec<_>>();

        debug!("nameserver {} => addrs: {:?}", url.to_string(), sock_addrs);

        let sock_addrs = sock_addrs.into_iter();

        let mut config: NameServerConfigGroup = match url.proto() {
            Protocol::Udp => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Udp,
                    tls_dns_name: None,
                    tls_config: None,
                    trust_nx_responses: true,
                    bind_addr: None,
                })
                .collect::<Vec<_>>(),
            Protocol::Tcp => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Tcp,
                    tls_dns_name: None,
                    tls_config: None,
                    trust_nx_responses: true,
                    bind_addr: None,
                })
                .collect::<Vec<_>>(),
            Protocol::Https => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Https,
                    tls_dns_name: host.to_owned(),
                    trust_nx_responses: true,
                    bind_addr: None,
                    tls_config: if let Some(false) = url.enable_sni() {
                        Some(TlsClientConfig(DOT_TLS_CONFIG.clone()))
                    } else {
                        None
                    },
                })
                .collect::<Vec<_>>(),
            Protocol::Tls => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Tls,
                    tls_dns_name: host.to_owned(),
                    trust_nx_responses: true,
                    bind_addr: None,
                    tls_config: if let Some(false) = url.enable_sni() {
                        Some(TlsClientConfig(DOT_TLS_CONFIG.clone()))
                    } else {
                        None
                    },
                })
                .collect::<Vec<_>>(),
            _ => todo!(),
        }
        .into();

        if let Some(ns) = config.get(0) {
            if ns.protocol == Protocol::Tls || ns.protocol == Protocol::Https {
                let client_cfg = ns.tls_config.as_ref().map(|x| x.0.clone());

                if let Some(x) = client_cfg {
                    config = config.with_client_config(x)
                }
            }
        }

        Some(config)
    }
}

static DOT_TLS_CONFIG: once_cell::sync::Lazy<Arc<ClientConfig>> =
    once_cell::sync::Lazy::new(|| {
        const ALPN_H2: &[u8] = b"h2";

        let mut root_store = RootCertStore::empty();

        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut client_config = ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        client_config.enable_sni = false;

        client_config.alpn_protocols.push(ALPN_H2.to_vec());

        Arc::new(client_config)
    });

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tokio::runtime::Runtime;

    use crate::dns_url::DnsUrl;

    use super::*;

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
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder()
                .add_server_group(NameServerConfigGroup::cloudflare())
                .build();
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_cloudflare_https_resolve() {
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder()
                .add_server_group(NameServerConfigGroup::cloudflare_https())
                .build();

            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    #[ignore = "reason"]
    fn test_nameserver_cloudflare_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://cloudflare-dns.com?enable_sni=false").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build();
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_quad9_tls_resolve() {
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder()
                .add_server_group(NameServerConfigGroup::quad9_tls())
                .build();
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_quad9_https_resolve() {
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder()
                .add_server_group(NameServerConfigGroup::quad9_https())
                .build();

            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_quad9_dns_url_https_resolve() {
        let dns_url = DnsUrl::from_str("https://dns.quad9.net/dns-query").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build();
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_resolve() {
        let server_ips = &[IpAddr::from_str("223.5.5.5").unwrap()];
        let config = NameServerConfigGroup::from_ips_clear(server_ips, 53, true);

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server_group(config).build();
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_https_resolve() {
        let server_ips = &[IpAddr::from_str("223.5.5.5").unwrap()];
        let config = NameServerConfigGroup::from_ips_https(
            server_ips,
            443,
            "dns.alidns.com".to_string(),
            true,
        );

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server_group(config).build();
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_dns_url_https_resolve() {
        let dns_url = DnsUrl::from_str("https://dns.alidns.com/dns-query").unwrap();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build();
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_dns_url_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dns.alidns.com").unwrap();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build();
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_https_tls_name_with_ip_resolve() {
        let dns_url = DnsUrl::from_str("https://223.5.5.5/dns-query").unwrap();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build();

            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_dnspod_https_resolve() {
        let dns_url = DnsUrl::from_str("https://doh.pub/dns-query").unwrap();

        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build();
            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }

    #[test]
    fn test_nameserver_dnspod_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dot.pub").unwrap();
        Runtime::new().unwrap().block_on(async {
            let client = DnsClient::builder().add_server(dns_url).build();

            assert_google(&client).await;
            assert_alidns(&client).await;
        })
    }
}
