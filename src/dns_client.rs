use crate::dns_conf::DnsServer;
use crate::log::warn;
use crate::matcher::DomainNameServerMatcher;
use crate::preset_ns::GetDnsHostName;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::{io, net::IpAddr};
use tokio::sync::Mutex;
use trust_dns_client::rr::LowerName;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::{IntoName, TokioHandle, TryParseIp};
use url::Host;

const ALIDNS_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
    IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x0001)),
    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x0001)),
];

static BOOTSTRAP_SERVERS: Lazy<Mutex<NameServerConfigGroup>> = Lazy::new(|| {
    let cfg = NameServerConfigGroup::from_ips_https(
        ALIDNS_IPS,
        443,
        ALIDNS_IPS.get_host_name().unwrap().to_string(),
        true,
    );

    Mutex::new(cfg)
});

pub async fn get_bootstrap_servers() -> NameServerConfigGroup {
    BOOTSTRAP_SERVERS.lock().await.to_owned()
}

pub fn set_bootstrap_servers(nameservers: NameServerConfigGroup) {
    (*BOOTSTRAP_SERVERS.blocking_lock()) = nameservers;
}

pub async fn resolve<N: IntoName + TryParseIp + std::fmt::Display + Copy>(
    name: N,
    nameservers: Option<NameServerConfigGroup>,
) -> io::Result<Vec<IpAddr>> {
    let nameservers = match nameservers {
        Some(s) => s,
        None => get_bootstrap_servers().await,
    };

    let resolver = create_resolver(
        nameservers,
        Some({
            let mut opts = ResolverOpts::default();

            opts.validate = false;

            opts
        }),
    )
    .expect("failed to create resolver");

    let result = resolver.lookup_ip(name).await;

    result
        .map_err(move |err| {
            // we transform the error into a standard IO error for convenience
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("dns resolution error for {}: {}", name, err),
            )
        })
        .map(move |lookup_ip| {
            // we take all the IPs returned, and then send back the set of IPs
            lookup_ip.iter().map(|ip| ip).collect::<Vec<_>>()
        })
}

pub fn create_resolver<T: IntoResolverConfig>(
    config: T,
    options: Option<ResolverOpts>,
) -> Result<TokioAsyncResolver, String> {
    let config = config.into();

    let mut options = options.unwrap_or_default();

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

use crate::dns::rr::RecordType;
use crate::dns::DnsError;
use crate::dns::Lookup;

#[derive(Debug)]
pub struct DnsClient {
    matcher: DomainNameServerMatcher,
    servers: HashMap<String, Vec<DnsServer>>,
    nameservers: Mutex<HashMap<String, NameServerConfigGroup>>,
    resolvers: Mutex<HashMap<String, Arc<TokioAsyncResolver>>>,
}

impl DnsClient {
    pub fn new(matcher: DomainNameServerMatcher, servers: HashMap<String, Vec<DnsServer>>) -> Self {
        Self {
            matcher,
            servers,
            nameservers: Default::default(),
            resolvers: Default::default(),
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

        if let Some(resolver) = self.get_resolver(group_name).await {
            resolver.lookup(name, record_type).await
        } else {
            Err(ResolveErrorKind::Message("").into())
        }
    }

    async fn get_resolver(&self, group_name: &str) -> Option<Arc<TokioAsyncResolver>> {
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

        let nameservers = self.get_nameservers(group_name).await;

        if let Some(Ok(resolver)) = nameservers.map(|ss| {
            create_resolver(
                ss,
                Some({
                    let mut opts = ResolverOpts::default();
                    opts.cache_size = 0;
                    opts
                }),
            )
        }) {
            let resolver = Arc::new(resolver);
            let mut resolvers = self.resolvers.lock().await;

            resolvers.insert(group_name.to_string(), Arc::clone(&resolver));

            Some(resolver)
        } else {
            None
        }
    }

    async fn get_nameservers(
        &self,
        // cfg: &SmartDnsConfig,
        group_name: &str,
    ) -> Option<NameServerConfigGroup> {
        let config = async {
            let nameservers = self.nameservers.lock().await;
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
            if let Host::Domain(domain) = s.url.host() {
                if let Ok(Some(g_name)) = LowerName::from_str(domain).map(|n| self.matcher.find(&n))
                {
                    use futures::future;

                    let config = self
                        .servers
                        .get(g_name)
                        .expect("default nameserver group not found!!!");

                    let tmp_config = future::join_all(
                        config
                            .iter()
                            .map(|c| c.url.to_nameserver_config_group(None)),
                    )
                    .await
                    .into_iter()
                    .flat_map(|x| x.into_iter())
                    .reduce(|mut p, c| {
                        p.merge(c);
                        p
                    });

                    if let Some(tmp_config) = tmp_config {
                        if let Ok(addrs) = resolve(domain, Some(tmp_config)).await {
                            if let Some(s) = s.url.to_nameserver_config_group(Some(addrs)).await {
                                if !s.is_empty() {
                                    name_server_cfg_group.merge(s);
                                    continue;
                                }
                            }
                        }
                    }
                }
            }

            if let Some(s) = s.url.to_nameserver_config_group(None).await {
                if !s.is_empty() {
                    name_server_cfg_group.merge(s);
                }
            }
        }

        async {
            let mut nameservers = self.nameservers.lock().await;

            nameservers.insert(group_name.to_string(), name_server_cfg_group.clone());
        }
        .await;

        Some(name_server_cfg_group)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use tokio::runtime::Runtime;

    use crate::dns_url::DnsUrl;

    use super::*;

    async fn assert_google(nameservers: NameServerConfigGroup) {
        let name = "dns.google";
        let addrs = resolve(name, Some(nameservers))
            .await
            .unwrap()
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        // println!("name: {} addrs => {}", name, addrs);

        assert!(addrs.contains("8.8.8.8"));
    }

    async fn assert_alidns(nameservers: NameServerConfigGroup) {
        let name = "dns.alidns.com";
        let addrs = resolve(name, Some(nameservers))
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
            assert_google(NameServerConfigGroup::cloudflare()).await;
            assert_alidns(NameServerConfigGroup::cloudflare()).await;
        })
    }

    #[test]
    fn test_nameserver_cloudflare_https_resolve() {
        Runtime::new().unwrap().block_on(async {
            assert_google(NameServerConfigGroup::cloudflare_https()).await;
            assert_alidns(NameServerConfigGroup::cloudflare_https()).await;
        })
    }

    #[test]
    fn test_nameserver_cloudflare_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://cloudflare-dns.com").unwrap();

        Runtime::new().unwrap().block_on(async {
            let config = dns_url.to_nameserver_config_group(None).await.unwrap();
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    fn test_nameserver_quad9_tls_resolve() {
        Runtime::new().unwrap().block_on(async {
            assert_google(NameServerConfigGroup::quad9_tls()).await;
            assert_alidns(NameServerConfigGroup::quad9_tls()).await;
        })
    }

    #[test]
    fn test_nameserver_quad9_https_resolve() {
        Runtime::new().unwrap().block_on(async {
            assert_google(NameServerConfigGroup::quad9_https()).await;
            assert_alidns(NameServerConfigGroup::quad9_https()).await;
        })
    }

    #[test]
    fn test_nameserver_quad9_dns_url_https_resolve() {
        let dns_url = DnsUrl::from_str("https://dns.quad9.net/dns-query").unwrap();
        Runtime::new().unwrap().block_on(async {
            let config = dns_url.to_nameserver_config_group(None).await.unwrap();
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_resolve() {
        let server_ips = &[IpAddr::from_str("223.5.5.5").unwrap()];
        let config = NameServerConfigGroup::from_ips_clear(server_ips, 53, true);

        Runtime::new().unwrap().block_on(async {
            assert_google(config.clone()).await;
            assert_alidns(config).await;
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
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_dns_url_https_resolve() {
        let dns_url = DnsUrl::from_str("https://dns.alidns.com/dns-query").unwrap();

        Runtime::new().unwrap().block_on(async {
            let config = dns_url.to_nameserver_config_group(None).await.unwrap();
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_dns_url_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dns.alidns.com").unwrap();

        Runtime::new().unwrap().block_on(async {
            let config = dns_url.to_nameserver_config_group(None).await.unwrap();
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_https_tls_name_with_ip_resolve() {
        Runtime::new().unwrap().block_on(async {
            let config = DnsUrl::from_str("https://223.5.5.5/dns-query")
                .unwrap()
                .to_nameserver_config_group(None)
                .await
                .unwrap();

            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    #[ignore = "reason"]
    fn test_nameserver_dnspod_https_resolve() {
        let dns_url = DnsUrl::from_str("https://doh.pub/dns-query").unwrap();

        Runtime::new().unwrap().block_on(async {
            let config = dns_url.to_nameserver_config_group(None).await.unwrap();
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    fn test_nameserver_dnspod_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dot.pub").unwrap();
        Runtime::new().unwrap().block_on(async {
            let config: NameServerConfigGroup = dns_url
                .to_nameserver_config_group(None)
                .await
                .unwrap()
                .into_inner()
                .into_iter()
                .filter(|ns| ns.socket_addr.ip().to_string() == "120.53.53.53")
                .collect::<Vec<_>>()
                .into();

            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }
}
