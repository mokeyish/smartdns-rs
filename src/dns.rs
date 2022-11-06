
use std::{net::ToSocketAddrs, str::FromStr, sync::Arc};
use trust_dns_resolver::{
    Name,
    config::{NameServerConfig, NameServerConfigGroup, Protocol},
    error::ResolveError,
};
use trust_dns_client::rr::{rdata::SOA, RData};
use url::Host;


use crate::{dns_client, dns_server::Request as OriginRequest, dns_url::DnsUrl};
use crate::log::{debug, warn};
use crate::dns_conf::SmartDnsConfig;
use crate::preset_ns;

pub use trust_dns_resolver::lookup::Lookup;

#[derive(Debug, Default)]
pub struct DnsContext {
    pub cfg: Arc<SmartDnsConfig>,
}

pub type DnsRequest = OriginRequest;
pub type DnsResponse = Lookup;
pub type DnsError = ResolveError;

impl SmartDnsConfig {
    pub fn rr_ttl(&self) -> u64 {
        self.rr_ttl.unwrap_or(300)
    }

    pub fn cache_size(&self) -> usize {
        self.cache_size.unwrap_or(512)
    }
}

impl DnsUrl {
    pub async fn to_nameserver_config_group(&self) -> Option<NameServerConfigGroup> {
        let url = self;

        let mut host = None;

        if url.proto().is_encrypted() {

            match url.host() {
                Host::Ipv4(ip) => {
                    host = preset_ns::find_dns_tls_name(&ip.to_owned().into()).map(|s| s.to_string());
                },
                Host::Ipv6(ip) => {
                    host = preset_ns::find_dns_tls_name(&ip.to_owned().into()).map(|s| s.to_string());
                }
                Host::Domain(domain) => {
                    host = Some(domain.to_string())
                },
            }

            if host.is_none() {
                warn!(
                    "Currently, encrypted dns {} with pure ip not supported!!!",
                    url.to_string()
                );
                return None;
            }
        }

        let sock_addrs = match url.host() {
            Host::Domain(host) => {
                match preset_ns::find_dns_ips(host) {
                    Some(ips) => ips.to_vec(),
                    None => dns_client::resolve(host, None).await.unwrap_or_default()
                }
            },
            Host::Ipv4(ipv4) => vec![(*ipv4).into()],
            Host::Ipv6(ipv6) => vec![(*ipv6).into()],
        }
        .into_iter()
        .map(|ip_addr| (ip_addr, url.port()).to_socket_addrs().ok())
        .flatten()
        .flatten()
        .collect::<Vec<_>>();

        debug!("nameserver {} => addrs: {:?}", url.to_string(), sock_addrs);

        let sock_addrs = sock_addrs.into_iter();

        let config: NameServerConfigGroup = match url.proto() {
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
                .map( |addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Https,
                    tls_dns_name: host.to_owned(),
                    tls_config: None,
                    trust_nx_responses: true,
                    bind_addr: None,
                })
                .collect::<Vec<_>>(),
            Protocol::Tls => sock_addrs
                .map(|addr| NameServerConfig {
                    socket_addr: addr,
                    protocol: Protocol::Tls,
                    tls_dns_name: host.to_owned(),
                    tls_config: None,
                    trust_nx_responses: true,
                    bind_addr: None,
                })
                .collect::<Vec<_>>(),
            _ => todo!(),
        }
        .into();

        Some(config)
    }
}

pub trait DefaultSOA {
    fn default_soa() -> Self;
}

impl DefaultSOA for SOA {
    #[inline]
    fn default_soa() -> Self {
        Self::new(
            Name::from_str("a.gtld-servers.net").unwrap(),
            Name::from_str("nstld.verisign-grs.com").unwrap(),
            1800,
            1800,
            900,
            604800,
            86400,
        )
    }
}

impl DefaultSOA for RData {
    #[inline]
    fn default_soa() -> Self {
        RData::SOA(SOA::default_soa())
    }
}
