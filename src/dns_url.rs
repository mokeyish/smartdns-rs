use crate::libdns::resolver::config::Protocol;
use std::collections::BTreeMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::string::ToString;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use url::{Host, Url};

/// alias: system、google、cloudflare、quad9
/// udp://8.8.8.8 or 8.8.8.8 or [240e:1f:1::1]  => DNS over UDP
/// tcp://8.8.8.8:53                            => DNS over TCP
/// tls://8.8.8.8:853                           => DoT:  DNS over TLS
/// quic://8.8.8.8:853                          => DoT:  DNS over QUIC
/// https://1.1.1.1/dns-query                   => DoH:  DNS over HTTPS
/// h3://1.1.1.1/dns-query                      => DoH3: DNS over HTTP/3
#[derive(Debug, Clone, Eq)]
pub struct DnsUrl {
    proto: Protocol,
    host: Host,
    port: Option<u16>,
    path: Option<String>,
    ip: Option<IpAddr>,
    params: BTreeMap<String, String>,
}

impl DnsUrl {
    #[inline]
    pub fn proto(&self) -> &Protocol {
        &self.proto
    }

    #[inline]
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
            Protocol::Https | Protocol::H3 => match self.path.as_ref() {
                Some(p) => p,
                None => "/dns-query",
            },
            _ => "",
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
            .or_else(|| match self.host() {
                Host::Domain(_) => None,
                Host::Ipv4(ip) => Some(ip.to_owned().into()),
                Host::Ipv6(ip) => Some(ip.to_owned().into()),
            })
            .or_else(|| self.get_param::<IpAddr>("ip"))
    }

    pub fn domain(&self) -> Option<&str> {
        if let Host::Domain(domain) = self.host() {
            Some(domain.as_str())
        } else {
            self.params.get("host").map(|s| s.as_str())
        }
    }

    #[inline]
    pub fn addr(&self) -> Option<SocketAddr> {
        self.ip().map(|ip| SocketAddr::new(ip, self.port()))
    }

    pub fn set_ip(&mut self, ip: IpAddr) {
        self.ip = Some(ip)
    }

    pub fn set_host(&mut self, name: &str) {
        match self.host() {
            Host::Ipv4(ip) => self.set_ip((*ip).into()),
            Host::Ipv6(ip) => self.set_ip((*ip).into()),
            _ => (),
        }
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
            && self.ip == other.ip
            && self.params() == other.params()
    }
}

impl Hash for DnsUrl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        format!("{:?}", self.proto).hash(state);
        self.host.hash(state);
        self.port.hash(state);
        self.path.hash(state);
        self.ip.hash(state);
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
            #[cfg(feature = "dns-over-https")]
            "https" => Protocol::Https,
            #[cfg(feature = "dns-over-quic")]
            "quic" => Protocol::Quic,
            #[cfg(feature = "dns-over-h3")]
            "h3" => Protocol::H3,
            schema => return Err(DnsUrlParseErr::ProtocolNotSupport(schema.to_string())),
        };

        let host = url.host();
        let port = url.port();

        if host.is_none() {
            return Err(DnsUrlParseErr::HostUnspecified);
        }

        let mut host = host.unwrap().to_owned();

        if let Host::Domain(ref domain) = host {
            if let Ok(ip) = IpAddr::from_str(domain) {
                host = match ip {
                    IpAddr::V4(ip) => Host::Ipv4(ip),
                    IpAddr::V6(ip) => Host::Ipv6(ip),
                };
            }
        }

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
            ip: None,
            params,
        })
    }
}

impl ToString for DnsUrl {
    fn to_string(&self) -> String {
        let mut out = String::new();
        use Protocol::*;
        // schema
        out += match self.proto {
            Udp => "udp://",
            Tcp => "tcp://",
            Tls => "tls://",
            #[cfg(feature = "dns-over-https")]
            Https => "https://",
            #[cfg(feature = "dns-over-quic")]
            Quic => "quic://",
            #[cfg(feature = "dns-over-h3")]
            H3 => "h3://",
            _ => unimplemented!(),
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
        #[cfg(feature = "dns-over-https")]
        Https => 443,
        #[cfg(feature = "dns-over-h3")]
        H3 => 443,
        #[cfg(feature = "dns-over-quic")]
        Quic => 853,
        #[cfg(feature = "mdns")]
        #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
        Mdns => 5353,
        _ => unimplemented!(),
    }
}

pub trait DnsUrlParam {
    fn params(&self) -> &BTreeMap<String, String>;
    fn get_param<T: FromStr>(&self, name: &str) -> Option<T>;

    fn get_param_or_default<T: Default + FromStr>(&self, name: &str) -> T {
        self.get_param(name).unwrap_or_default()
    }

    fn set_param<T: ToString>(&mut self, name: &str, value: T);
}

impl DnsUrlParam for DnsUrl {
    fn params(&self) -> &BTreeMap<String, String> {
        &self.params
    }

    fn get_param<T: FromStr>(&self, name: &str) -> Option<T> {
        self.params
            .get(name)
            .map(|v| T::from_str(v).ok())
            .unwrap_or_default()
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
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_udp_1() {
        let url = DnsUrl::from_str("udp://8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 53);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://8.8.8.8");
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_udp_2() {
        let url = DnsUrl::from_str("udp://1.1.1.1:8053").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "1.1.1.1");
        assert_eq!(url.port(), 8053);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://1.1.1.1:8053");
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_udp_ipv6() {
        for ip in CLOUDFLARE_IPS.iter().map(DnsUrl::from) {
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
    #[cfg(feature = "dns-over-tls")]
    fn test_parse_tls_1() {
        let url = DnsUrl::from_str("tls://8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Tls);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 853);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "tls://8.8.8.8");
    }

    #[test]
    #[cfg(feature = "dns-over-tls")]
    fn test_parse_tls_2() {
        let url = DnsUrl::from_str("tls://8.8.8.8:953").unwrap();
        assert_eq!(url.proto, Protocol::Tls);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 953);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "tls://8.8.8.8:953");
    }

    #[test]
    #[cfg(feature = "dns-over-tls")]
    fn test_parse_tls_3() {
        let mut url = DnsUrl::from_str("tls://8.8.8.8:953").unwrap();
        url.set_host("dns.google");
        assert_eq!(url.proto, Protocol::Tls);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 953);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "tls://dns.google:953");
        assert_eq!(url.ip(), "8.8.8.8".parse().ok())
    }

    #[test]
    #[cfg(feature = "dns-over-https")]
    fn test_parse_https() {
        let url = DnsUrl::from_str("https://dns.google/dns-query").unwrap();
        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.google/dns-query");
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-https")]
    fn test_parse_https_1() {
        let url = DnsUrl::from_str("https://dns.google/dns-query1").unwrap();
        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/dns-query1");
        assert_eq!(url.to_string(), "https://dns.google/dns-query1");
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-https")]
    fn test_parse_https_2() {
        let url = DnsUrl::from_str("https://dns.google").unwrap();

        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.google/dns-query");
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-quic")]
    fn test_parse_quic() {
        let url = DnsUrl::from_str("quic://dns.adguard-dns.com").unwrap();

        assert_eq!(url.proto, Protocol::Quic);
        assert_eq!(url.host.to_string(), "dns.adguard-dns.com");
        assert_eq!(url.port(), 853);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "quic://dns.adguard-dns.com");
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-h3")]
    fn test_parse_h3() {
        let url = DnsUrl::from_str("h3://dns.adguard-dns.com").unwrap();

        assert_eq!(url.proto, Protocol::H3);
        assert_eq!(url.host.to_string(), "dns.adguard-dns.com");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "h3://dns.adguard-dns.com");
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-https")]
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
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_misc_02() {
        let url = DnsUrl::from_str("[240e:1f:1::1]").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "[240e:1f:1::1]");
        assert_eq!(url.port(), 53);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://[240e:1f:1::1]");
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_enable_sni_false() {
        let url = DnsUrl::from_str("udp://cloudflare-dns.com?enable_sni=false").unwrap();
        assert!(url.sni_off());
        assert!(url.ip().is_none());
    }

    #[test]
    fn test_parse_enable_sni_true() {
        let url = DnsUrl::from_str("udp://cloudflare-dns.com?enable_sni=false").unwrap();
        assert!(url.sni_off());
        assert!(url.ip().is_none());
    }

    #[test]
    fn test_parse_params_ip() {
        let url = DnsUrl::from_str("udp://cloudflare-dns.com?ip=1.1.1.1").unwrap();
        assert_eq!(url.ip(), Some("1.1.1.1".parse().unwrap()));
    }
}
