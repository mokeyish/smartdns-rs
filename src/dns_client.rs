use once_cell::sync::Lazy;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{io, net::IpAddr};
use tokio::sync::Mutex;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::{IntoName, TokioHandle, TryParseIp};
use crate::log::warn;

const ALIDNS_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
    IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x0001)),
    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x0001)),
];


static BOOTSTRAP_SERVERS: Lazy<Mutex<NameServerConfigGroup>> = Lazy::new(|| {
    let cfg =
        NameServerConfigGroup::from_ips_https(ALIDNS_IPS, 443, "dns.alidns.com".to_string(), true);

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
    #[cfg(failed_tests)]
    fn test_nameserver_cloudflare_tls_resolve() {
        Runtime::new().unwrap().block_on(async {
            assert_google(NameServerConfigGroup::cloudflare_tls()).await;
            assert_alidns(NameServerConfigGroup::cloudflare_tls()).await;
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
            let config = dns_url.to_nameserver_config_group().await.unwrap();
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

            let config = dns_url.to_nameserver_config_group().await.unwrap();
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    fn test_nameserver_alidns_dns_url_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dns.alidns.com").unwrap();

        Runtime::new().unwrap().block_on(async {

            let config = dns_url.to_nameserver_config_group().await.unwrap();
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    #[cfg(failed_tests)]
    fn test_nameserver_alidns_https_tls_name_with_ip_resolve() {
        Runtime::new().unwrap().block_on(async {
            let config = DnsUrl::from_str("https://223.5.5.5/dns-query").unwrap()
            .to_nameserver_config_group().await;
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }

    #[test]
    fn test_nameserver_dnspod_https_resolve() {

        let dns_url = DnsUrl::from_str("https://doh.pub/dns-query").unwrap();

        Runtime::new().unwrap().block_on(async {
            let config = dns_url.to_nameserver_config_group().await.unwrap();
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }


    #[test]
    fn test_nameserver_dnspod_tls_resolve() {
        let dns_url = DnsUrl::from_str("tls://dot.pub").unwrap();
        Runtime::new().unwrap().block_on(async {
            let config = dns_url.to_nameserver_config_group().await.unwrap();
            assert_google(config.clone()).await;
            assert_alidns(config).await;
        })
    }


}
