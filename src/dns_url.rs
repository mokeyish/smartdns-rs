use std::collections::BTreeMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::string::ToString;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use trust_dns_resolver::config::Protocol;
use url::{Host, Url};

/// alias: system、google、cloudflare、quad9
/// udp://8.8.8.8 or 8.8.8.8 or [240e:1f:1::1]  => traditional dns server
/// tcp://8.8.8.8:53                            => dns over tcp
/// tls://8.8.8.8:853                           => DOT: dns over tls
/// https://1.1.1.1/dns-query                   => DOH: dns over https
#[derive(Debug, Clone, Eq)]
pub struct DnsUrl {
    proto: Protocol,
    host: Host,
    port: Option<u16>,
    path: Option<String>,
    addrs: Vec<SocketAddr>,

    params: BTreeMap<String, String>,
}

impl DnsUrl {
    pub fn addrs(&self) -> &[SocketAddr] {
        self.addrs.as_slice()
    }

    pub fn proto(&self) -> &Protocol {
        &self.proto
    }

    pub fn host(&self) -> &Host {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
            .unwrap_or_else(|| dns_proto_default_port(&self.proto))
    }

    pub fn is_default_port(&self) -> bool {
        self.port() == dns_proto_default_port(&self.proto)
    }

    pub fn path(&self) -> &str {
        match self.proto {
            Protocol::Https => match self.path.as_ref() {
                Some(p) => p,
                None => "/dns-query",
            },
            _ => "",
        }
    }

    pub fn domain(&self) -> Option<&str> {
        if let Host::Domain(domain) = &self.host {
            Some(domain.as_str())
        } else {
            None
        }
    }

    pub fn set_ip_addrs(&mut self, addrs: Vec<IpAddr>) {
        self.addrs = addrs
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port()))
            .collect();
    }

    pub fn set_host_name(&mut self, name: &str) {
        self.host = Host::Domain(name.to_string())
    }
}

#[derive(Debug)]
pub enum DnsUrlParseErr {
    ParseError(String),
    ProtocolNotSupport(String),
    HostUnspecified,
}

impl PartialEq for DnsUrl {
    fn eq(&self, other: &Self) -> bool {
        self.proto == other.proto
            && self.host == other.host
            && self.port == other.port
            && self.path == other.path
            && self.addrs == other.addrs
            && self.params() == other.params()
    }
}

impl Hash for DnsUrl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        format!("{:?}", self.proto).hash(state);
        self.host.hash(state);
        self.port.hash(state);
        self.path.hash(state);
        self.addrs.hash(state);
        self.params.hash(state);
    }
}

impl FromStr for DnsUrl {
    type Err = DnsUrlParseErr;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let mut url = url.to_lowercase();
        if !url.contains("://") {
            url.insert_str(0, "udp://")
        }

        let is_endwith_slash = url.ends_with('/');

        let url = Url::parse(url.as_str())?;

        let proto = match url.scheme() {
            "udp" => Protocol::Udp,
            "tcp" => Protocol::Tcp,
            "tls" => Protocol::Tls,
            "https" => Protocol::Https,
            "quic" => Protocol::Quic,
            schema => return Err(DnsUrlParseErr::ProtocolNotSupport(schema.to_string())),
        };

        let host = url.host();
        let port = url.port();

        if host.is_none() {
            return Err(DnsUrlParseErr::HostUnspecified);
        }

        let mut host = host.unwrap().to_owned();

        let addr_port = port.unwrap_or_else(|| dns_proto_default_port(&proto));

        let addrs = match host {
            Host::Domain(ref domain) => {
                if let Ok(ip) = IpAddr::from_str(domain) {
                    host = match ip {
                        IpAddr::V4(ip) => Host::Ipv4(ip),
                        IpAddr::V6(ip) => Host::Ipv6(ip),
                    };

                    vec![SocketAddr::new(ip, addr_port)]
                } else {
                    vec![]
                }
            }
            Host::Ipv4(ip) => vec![SocketAddr::new(IpAddr::V4(ip), addr_port)],
            Host::Ipv6(ip) => vec![SocketAddr::new(IpAddr::V6(ip), addr_port)],
        };

        let params = url
            .query_pairs()
            .into_iter()
            .map(|(n, v)| (n.into_owned(), v.into_owned()))
            .collect::<BTreeMap<_, _>>();

        Ok(Self {
            proto,
            host,
            port,
            path: if url.path() == "/" && !is_endwith_slash {
                None
            } else {
                Some(url.path().to_string())
            },
            addrs,
            params,
        })
    }
}

impl ToString for DnsUrl {
    fn to_string(&self) -> String {
        let mut out = String::new();

        // schema
        out += match self.proto {
            Protocol::Udp => "udp://",
            Protocol::Tcp => "tcp://",
            Protocol::Tls => "tls://",
            Protocol::Https => "https://",
            Protocol::Quic => "quic://",
            _ => todo!(),
        };

        // host
        out += &self.host().to_string();

        // port

        if !self.is_default_port() {
            out.push(':');
            out += &self.port().to_string();
        }

        // path
        if matches!(self.proto, Protocol::Https) {
            out += self.path();
        }

        // query
        if !self.params.is_empty() {
            for (i, (n, v)) in self.params.iter().enumerate() {
                out.push(if i == 0 { '?' } else { '&' });
                out.push_str(n);
                out.push('=');
                out.push_str(v);
            }
        }

        out
    }
}

impl From<url::ParseError> for DnsUrlParseErr {
    fn from(value: url::ParseError) -> Self {
        Self::ParseError(value.to_string())
    }
}

impl From<&Ipv4Addr> for DnsUrl {
    #[inline]
    fn from(ip: &Ipv4Addr) -> Self {
        ip.to_string().parse().unwrap()
    }
}

impl From<&Ipv6Addr> for DnsUrl {
    #[inline]
    fn from(ip: &Ipv6Addr) -> Self {
        format!("[{}]", ip).parse().unwrap()
    }
}

impl From<&IpAddr> for DnsUrl {
    #[inline]
    fn from(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => ip.into(),
            IpAddr::V6(ip) => ip.into(),
        }
    }
}

fn dns_proto_default_port(proto: &Protocol) -> u16 {
    use Protocol::*;
    match *proto {
        Udp => 53,
        Tcp => 53,
        Tls => 853,
        Https => 443,
        Quic => 443,
        #[cfg(feature = "mdns")]
        #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
        Mdns => 5353,
        _ => todo!(),
    }
}

pub trait DnsUrlParam {
    fn params(&self) -> &BTreeMap<String, String>;
    fn get_param<T: Default + FromStr>(&self, name: &str) -> Option<T>;

    fn get_param_or_default<T: Default + FromStr>(&self, name: &str) -> T {
        self.get_param(name).unwrap_or_default()
    }

    fn set_param<T: ToString>(&mut self, name: &str, value: T);
}

impl DnsUrlParam for DnsUrl {
    fn params(&self) -> &BTreeMap<String, String> {
        &self.params
    }

    fn get_param<T: Default + FromStr>(&self, name: &str) -> Option<T> {
        self.params
            .get(name)
            .map(|v| T::from_str(v).unwrap_or_default())
    }

    fn set_param<T: ToString>(&mut self, name: &str, value: T) {
        *(self.params.entry(name.to_string()).or_default()) = value.to_string()
    }
}

pub trait DnsUrlParamExt: DnsUrlParam {
    fn set_sni_on(&mut self, value: bool) {
        self.set_param("sni", value)
    }
    fn set_sni_off(&mut self, value: bool) {
        self.set_param("sni", !value)
    }

    fn sni_on(&self) -> bool {
        !self.sni_off()
    }

    fn sni_off(&self) -> bool {
        self.get_param::<bool>("sni")
            .map(|v| !v)
            .or_else(|| self.get_param::<bool>("enable_sni").map(|v| !v))
            .unwrap_or(false)
    }

    fn ssl_verify(&self) -> bool {
        self.get_param("ssl_verify").unwrap_or(true)
    }

    fn set_ssl_verify(&mut self, verify: bool) {
        self.set_param("ssl_verify", verify)
    }
}

impl DnsUrlParamExt for DnsUrl {}

#[cfg(test)]
mod tests {

    use crate::preset_ns::CLOUDFLARE_IPS;

    use super::*;

    #[test]
    fn test_parse_udp() {
        let url = DnsUrl::from_str("8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 53);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://8.8.8.8");
        assert!(!url.addrs().is_empty());
    }

    #[test]
    fn test_parse_udp_1() {
        let url = DnsUrl::from_str("udp://8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 53);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://8.8.8.8");
        assert!(!url.addrs().is_empty());
    }

    #[test]
    fn test_parse_udp_2() {
        let url = DnsUrl::from_str("udp://1.1.1.1:8053").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "1.1.1.1");
        assert_eq!(url.port(), 8053);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://1.1.1.1:8053");
        assert!(!url.addrs().is_empty());
    }

    #[test]
    fn test_parse_udp_ipv6() {
        for ip in CLOUDFLARE_IPS.iter().map(|ip| DnsUrl::from(ip)) {
            assert!(ip.proto.is_datagram());
        }
    }

    #[test]
    fn test_parse_tcp() {
        let url = DnsUrl::from_str("tcp://8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Tcp);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 53);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "tcp://8.8.8.8");
    }

    #[test]
    fn test_parse_tcp_1() {
        let url = DnsUrl::from_str("tcp://8.8.8.8:8053").unwrap();
        assert_eq!(url.proto, Protocol::Tcp);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 8053);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "tcp://8.8.8.8:8053");
    }

    #[test]
    fn test_parse_tls_1() {
        let url = DnsUrl::from_str("tls://8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Tls);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 853);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "tls://8.8.8.8");
    }

    #[test]
    fn test_parse_tls_2() {
        let url = DnsUrl::from_str("tls://8.8.8.8:953").unwrap();
        assert_eq!(url.proto, Protocol::Tls);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 953);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "tls://8.8.8.8:953");
    }

    #[test]
    fn test_parse_tls_3() {
        let mut url = DnsUrl::from_str("tls://8.8.8.8:953").unwrap();
        url.set_host_name("dns.google");
        assert_eq!(url.proto, Protocol::Tls);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 953);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "tls://dns.google:953");
    }

    #[test]
    fn test_parse_https() {
        let url = DnsUrl::from_str("https://dns.google/dns-query").unwrap();
        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.google/dns-query");
        assert!(url.addrs().is_empty());
    }

    #[test]
    fn test_parse_https_1() {
        let url = DnsUrl::from_str("https://dns.google/dns-query1").unwrap();
        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/dns-query1");
        assert_eq!(url.to_string(), "https://dns.google/dns-query1");
        assert!(url.addrs().is_empty());
    }

    #[test]
    fn test_parse_https_2() {
        let url = DnsUrl::from_str("https://dns.google").unwrap();

        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.google/dns-query");
        assert!(url.addrs().is_empty());
    }

    #[test]
    fn test_parse_quic() {
        let url = DnsUrl::from_str("quic://dns.adguard-dns.com").unwrap();

        assert_eq!(url.proto, Protocol::Quic);
        assert_eq!(url.host.to_string(), "dns.adguard-dns.com");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "quic://dns.adguard-dns.com");
        assert!(url.addrs().is_empty());
    }

    #[test]
    fn test_url_params_equal() {
        let url1 = DnsUrl::from_str("https://dns.adguard-dns.com?a=1&b=2&c=3").unwrap();
        let url2 = DnsUrl::from_str("https://dns.adguard-dns.com?b=2&a=1&c=3").unwrap();
        assert_eq!(url1, url2);
    }

    #[test]
    fn test_parse_misc_01() {
        let url = DnsUrl::from_str("127.0.0.1:1053").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "127.0.0.1");
        assert_eq!(url.port(), 1053);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://127.0.0.1:1053");
        assert!(!url.addrs().is_empty());
    }

    #[test]
    fn test_parse_misc_02() {
        let url = DnsUrl::from_str("[240e:1f:1::1]").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "[240e:1f:1::1]");
        assert_eq!(url.port(), 53);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://[240e:1f:1::1]");
        assert!(!url.addrs().is_empty());
    }

    #[test]
    fn test_parse_enable_sni_false() {
        let url = DnsUrl::from_str("tls://cloudflare-dns.com?enable_sni=false").unwrap();
        assert_eq!(url.sni_off(), true);
        assert!(url.addrs().is_empty());
    }

    #[test]
    fn test_parse_enable_sni_true() {
        let url = DnsUrl::from_str("tls://cloudflare-dns.com?enable_sni=false").unwrap();
        assert_eq!(url.sni_off(), true);
        assert!(url.addrs().is_empty());
    }
}
