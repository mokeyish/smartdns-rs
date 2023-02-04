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
#[derive(Debug, Clone)]
pub struct DnsUrl {
    proto: Protocol,
    host: Host,
    port: Option<u16>,
    path: Option<String>,
    enable_sni: Option<bool>,
}

impl DnsUrl {
    pub fn proto(&self) -> &Protocol {
        &self.proto
    }

    pub fn host(&self) -> &Host {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port.unwrap_or(dns_proto_default_port(&self.proto))
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

    pub fn get_domain(&self) -> Option<&str> {
        if let Host::Domain(domain) = &self.host {
            Some(domain.as_str())
        } else {
            None
        }
    }
    pub fn enable_sni(&self) -> bool {
        self.enable_sni.unwrap_or(true)
    }
}

#[derive(Debug)]
pub enum DnsUrlParseErr {
    ParseError(String),
    ProtocolNotSupport(String),
    HostUnspecified,
}

impl FromStr for DnsUrl {
    type Err = DnsUrlParseErr;

    fn from_str(url: &str) -> Result<Self, Self::Err> {
        let mut url = url.to_lowercase();
        if url.find("://").is_none() {
            url.insert_str(0, "udp://")
        }

        let is_endwith_slash = url.ends_with('/');

        let url = Url::parse(url.as_str())?;

        let proto = match url.scheme() {
            "udp" => Protocol::Udp,
            "tcp" => Protocol::Tcp,
            "tls" => Protocol::Tls,
            "https" => Protocol::Https,
            schema => return Err(DnsUrlParseErr::ProtocolNotSupport(schema.to_string())),
        };

        let host = url.host();
        let port = url.port();

        if host.is_none() {
            return Err(DnsUrlParseErr::HostUnspecified);
        }

        let host = host.unwrap();

        let enable_sni = url
            .query_pairs()
            .into_iter()
            .filter_map(|q| {
                if q.0 == "enable_sni" {
                    bool::from_str(q.1.to_string().as_str()).ok()
                } else {
                    None
                }
            })
            .next();

        Ok(Self {
            proto,
            host: host.to_owned(),
            port,
            path: if url.path() == "/" && !is_endwith_slash {
                None
            } else {
                Some(url.path().to_string())
            },
            enable_sni,
        })
    }
}

impl ToString for DnsUrl {
    fn to_string(&self) -> String {
        if self.is_default_port() {
            match self.proto {
                Protocol::Udp => format!("udp://{}", self.host),
                Protocol::Tcp => format!("tcp://{}", self.host),
                Protocol::Tls => format!("tls://{}", self.host),
                Protocol::Https => format!("https://{}{}", self.host, self.path()),
                _ => todo!(),
            }
        } else {
            match self.proto {
                Protocol::Udp => format!("udp://{}:{}", self.host, self.port()),
                Protocol::Tcp => format!("tcp://{}:{}", self.host, self.port()),
                Protocol::Tls => format!("tls://{}:{}", self.host, self.port()),
                Protocol::Https => format!("https://{}:{}{}", self.host, self.port(), self.path()),
                _ => todo!(),
            }
        }
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
        #[cfg(feature = "mdns")]
        #[cfg_attr(docsrs, doc(cfg(feature = "mdns")))]
        Mdns => 5353,
        _ => todo!(),
    }
}

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
    }

    #[test]
    fn test_parse_udp_1() {
        let url = DnsUrl::from_str("udp://8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 53);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://8.8.8.8");
    }

    #[test]
    fn test_parse_udp_2() {
        let url = DnsUrl::from_str("udp://8.8.8.8:8053").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 8053);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://8.8.8.8:8053");
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
    fn test_parse_https() {
        let url = DnsUrl::from_str("https://dns.google/dns-query").unwrap();
        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.google/dns-query");
    }

    #[test]
    fn test_parse_https_1() {
        let url = DnsUrl::from_str("https://dns.google/dns-query1").unwrap();
        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/dns-query1");
        assert_eq!(url.to_string(), "https://dns.google/dns-query1");
    }

    #[test]
    fn test_parse_https_2() {
        let url = DnsUrl::from_str("https://dns.google").unwrap();

        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        assert_eq!(url.path(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.google/dns-query");
    }

    #[test]
    fn test_parse_misc_01() {
        let url = DnsUrl::from_str("127.0.0.1:1053").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "127.0.0.1");
        assert_eq!(url.port(), 1053);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://127.0.0.1:1053");
    }

    #[test]
    fn test_parse_misc_02() {
        let url = DnsUrl::from_str("[240e:1f:1::1]").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "[240e:1f:1::1]");
        assert_eq!(url.port(), 53);
        assert_eq!(url.path(), "");
        assert_eq!(url.to_string(), "udp://[240e:1f:1::1]");
    }

    #[test]
    fn test_parse_enable_sni_false() {
        let url = DnsUrl::from_str("tls://cloudflare-dns.com?enable_sni=false").unwrap();
        assert_eq!(url.enable_sni(), false);
    }

    #[test]
    fn test_parse_enable_sni_true() {
        let url = DnsUrl::from_str("tls://cloudflare-dns.com?enable_sni=false").unwrap();
        assert_eq!(url.enable_sni(), false);
    }
}
