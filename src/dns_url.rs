#[cfg(feature = "mdns")]
use crate::libdns::proto::multicast::{MDNS_IPV4, MDNS_IPV6};
use crate::libdns::{
    Protocol::{self, *},
    ProtocolDefaultPort,
    proto::http::DEFAULT_DNS_QUERY_PATH,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "dns-over-tls")]
use std::sync::Arc;
use std::{collections::BTreeMap, ops::Deref};
use std::{net::SocketAddr, string::ToString};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use url::{Host, Url};

/// alias: google、cloudflare、quad9             => not support yet
/// udp://8.8.8.8 or 8.8.8.8 or [240e:1f:1::1]  => DNS over UDP
/// tcp://8.8.8.8:53                            => DNS over TCP
/// tls://8.8.8.8:853                           => DoT:  DNS over TLS
/// quic://8.8.8.8:853                          => DoT:  DNS over QUIC
/// https://1.1.1.1/dns-query                   => DoH:  DNS over HTTPS
/// h3://1.1.1.1/dns-query                      => DoH3: DNS over HTTP/3
/// system                                      => Use system nameservers
/// dhcp://system                               => Use system nameservers
/// dhcp                                        => Use nameservers from DHCP
/// dhcp://en0                                  => Use nameservers from DHCP on interface en0
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsUrl {
    proto: ProtocolConfig,
    host: Host,
    port: Option<u16>,
    params: Params,
}

impl DnsUrl {
    pub fn proto(&self) -> &ProtocolConfig {
        &self.proto
    }
    pub fn host(&self) -> &Host {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port.unwrap_or_else(|| self.proto.default_port())
    }

    pub fn path(&self) -> Option<&str> {
        match self.proto() {
            #[cfg(feature = "dns-over-https")]
            ProtocolConfig::Https { path, .. } => Some(path),
            #[cfg(feature = "dns-over-h3")]
            ProtocolConfig::H3 { path, .. } => Some(path),
            _ => None,
        }
    }

    pub fn server_name(&self) -> Option<&str> {
        match self.proto() {
            #[cfg(feature = "dns-over-tls")]
            ProtocolConfig::Tls { server_name, .. } => server_name.as_deref(),
            #[cfg(feature = "dns-over-quic")]
            ProtocolConfig::Quic { server_name, .. } => server_name.as_deref(),
            #[cfg(feature = "dns-over-https")]
            ProtocolConfig::Https { server_name, .. } => server_name.as_deref(),
            #[cfg(feature = "dns-over-h3")]
            ProtocolConfig::H3 { server_name, .. } => server_name.as_deref(),
            _ => None,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self.host() {
            Host::Domain(_) => None,
            Host::Ipv4(ip) => Some(ip.to_owned().into()),
            Host::Ipv6(ip) => Some(ip.to_owned().into()),
        }
        .or_else(|| self.get_param::<IpAddr>("ip"))
    }

    pub fn set_proto(&mut self, proto: Protocol) {
        self.proto = proto.into();
    }

    pub fn set_ip(&mut self, ip: IpAddr) {
        self.set_param("ip", ip);
    }

    pub fn set_port(&mut self, port: u16) {
        self.port = Some(port);
    }

    pub fn set_host(&mut self, host: &str) {
        match self.host {
            Host::Ipv4(ipv4_addr) => self.set_ip(ipv4_addr.into()),
            Host::Ipv6(ipv6_addr) => self.set_ip(ipv6_addr.into()),
            Host::Domain(_) => (),
        }
        self.host = Host::Domain(host.to_string());
        self.proto.set_server_name(host);
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
        match url.as_str() {
            "system" => {
                return Ok(Self {
                    proto: ProtocolConfig::System,
                    host: Host::Domain(url),
                    port: Default::default(),
                    params: Default::default(),
                });
            }
            "dhcp" => {
                return Ok(Self {
                    proto: ProtocolConfig::Dhcp {
                        interface: Default::default(),
                    },
                    host: Host::Domain(url),
                    port: Default::default(),
                    params: Default::default(),
                });
            }
            _ => (),
        }
        if !url.contains("://") {
            url.insert_str(0, "udp://")
        }

        let is_endwith_slash = url.ends_with('/');

        let url = Url::parse(url.as_str())?;

        let host = url.host();
        let port = url.port();

        let host = match host {
            Some(host) => {
                let mut host = host.to_owned();
                if let Host::Domain(ref domain) = host {
                    if let Ok(ip) = IpAddr::from_str(domain) {
                        host = match ip {
                            IpAddr::V4(ip) => Host::Ipv4(ip),
                            IpAddr::V6(ip) => Host::Ipv6(ip),
                        };
                    }
                }
                Some(host)
            }
            None => None,
        };

        let mut proto = match url.scheme() {
            proto @ "dhcp" => {
                return Ok(Self {
                    proto: ProtocolConfig::Dhcp {
                        interface: host.map(|s| s.to_string().into()),
                    },
                    host: Host::Domain(proto.to_string()),
                    port: Default::default(),
                    params: Default::default(),
                });
            }
            "udp" => Udp,
            "tcp" => Tcp,
            "tls" => Tls,
            #[cfg(feature = "dns-over-https")]
            "https" => Https,
            #[cfg(feature = "dns-over-quic")]
            "quic" => Quic,
            #[cfg(feature = "dns-over-h3")]
            "h3" => H3,
            #[cfg(feature = "mdns")]
            "mdns" => Mdns,
            schema => return Err(DnsUrlParseErr::ProtocolNotSupport(schema.to_string())),
        };

        let Some(mut host) = host else {
            return Err(DnsUrlParseErr::HostUnspecified);
        };

        let mut params = Params(
            url.query_pairs()
                .into_iter()
                .map(|(n, v)| (n.into(), v.into()))
                .collect(),
        );

        #[cfg(feature = "mdns")]
        if proto != Mdns
            && match port {
                Some(port) if port == Mdns.default_port() => true,
                None => true,
                _ => false,
            }
            && match &host {
                Host::Ipv4(ip) if MDNS_IPV4.ip().eq(ip) => true,
                Host::Ipv6(ip) if MDNS_IPV6.ip().eq(ip) => true,
                _ => false,
            }
        {
            proto = Mdns
        }

        let fragment = url.fragment();

        let server_name = if let Host::Domain(domain) = &host {
            Some(domain.to_string())
        } else {
            params.get("host").map(|s| s.to_string())
        }
        .unwrap_or_else(|| host.to_string());

        let path = if url.path() == "" || (url.path() == "/" && !is_endwith_slash) {
            None
        } else {
            Some(url.path().to_string())
        };

        if let Some(domain) = params.del_param::<String>("host") {
            match host {
                Host::Ipv4(ipv4_addr) => params.set_param("ip", ipv4_addr),
                Host::Ipv6(ipv6_addr) => params.set_param("ip", ipv6_addr),
                _ => (),
            };
            host = Host::Domain(domain);
        }

        Ok(Self {
            proto: match proto {
                Udp => ProtocolConfig::Udp,
                Tcp => ProtocolConfig::Tcp,
                #[cfg(feature = "dns-over-tls")]
                Tls => ProtocolConfig::Tls {
                    server_name: Some(server_name.into()),
                },
                #[cfg(feature = "dns-over-https")]
                Https => ProtocolConfig::Https {
                    server_name: Some(server_name.into()),
                    path: path
                        .unwrap_or_else(|| DEFAULT_DNS_QUERY_PATH.to_string())
                        .into(),
                    prefer: match fragment {
                        Some(fragment) if fragment.contains("h2") => HttpsPrefer::H2,
                        Some(fragment) if fragment.contains("h3") => HttpsPrefer::H3,
                        _ => HttpsPrefer::Auto,
                    },
                },
                #[cfg(feature = "dns-over-quic")]
                Quic => ProtocolConfig::Quic {
                    server_name: Some(server_name.into()),
                },
                #[cfg(feature = "dns-over-h3")]
                H3 => ProtocolConfig::H3 {
                    server_name: Some(server_name.into()),
                    path: path
                        .unwrap_or_else(|| DEFAULT_DNS_QUERY_PATH.to_string())
                        .into(),
                    disable_grease: matches!(fragment, Some(fragment) if fragment.contains("disable_grease")),
                },
                Mdns => ProtocolConfig::Mdns,
                _ => unimplemented!(),
            },
            host,
            port,
            params,
        })
    }
}

impl std::fmt::Display for DnsUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // schema
        write!(f, "{}", self.proto.to_str())?;

        match &self.proto {
            ProtocolConfig::System => return Ok(()),
            ProtocolConfig::Dhcp { interface } => {
                if let Some(interface) = interface {
                    write!(f, "://{interface}")?;
                }
                return Ok(());
            }
            _ => (),
        }

        // host
        write!(f, "://{}", self.host)?;

        // port

        if matches!(self.port, Some(port) if port != self.proto.default_port()) {
            write!(f, ":{}", self.port())?;
        }

        match &self.proto {
            ProtocolConfig::Https { path, prefer, .. } => {
                write!(f, "{path}")?;

                // fragment
                if !matches!(prefer, HttpsPrefer::Auto) {
                    write!(f, "#{prefer}")?;
                }
            }
            ProtocolConfig::H3 {
                path,
                disable_grease,
                ..
            } => {
                write!(f, "{path}")?;

                // fragment
                if *disable_grease {
                    write!(f, "#disable_grease")?;
                }
            }
            _ => (),
        }

        // query
        if !self.params.is_empty() {
            for (i, (n, v)) in self.params.iter().enumerate() {
                write!(f, "{}{}={}", if i == 0 { '?' } else { '&' }, n, v)?;
            }
        }

        Ok(())
    }
}

impl From<url::ParseError> for DnsUrlParseErr {
    fn from(value: url::ParseError) -> Self {
        Self::ParseError(value.to_string())
    }
}

impl From<Ipv4Addr> for DnsUrl {
    #[inline]
    fn from(ip: Ipv4Addr) -> Self {
        ip.to_string().parse().unwrap()
    }
}

impl From<Ipv6Addr> for DnsUrl {
    #[inline]
    fn from(ip: Ipv6Addr) -> Self {
        format!("[{ip}]").parse().unwrap()
    }
}

impl From<IpAddr> for DnsUrl {
    #[inline]
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => ip.into(),
            IpAddr::V6(ip) => ip.into(),
        }
    }
}

impl From<SocketAddr> for DnsUrl {
    #[inline]
    fn from(addr: SocketAddr) -> Self {
        let mut v = match addr.ip() {
            IpAddr::V4(ip) => Self::from(ip),
            IpAddr::V6(ip) => Self::from(ip),
        };
        v.set_port(addr.port());

        v
    }
}

impl std::ops::Deref for DnsUrl {
    type Target = Params;

    fn deref(&self) -> &Self::Target {
        &self.params
    }
}

impl std::ops::DerefMut for DnsUrl {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.params
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DnsUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(|_| serde::de::Error::custom(format!("{s:?}")))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DnsUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.to_string();
        serializer.serialize_str(&s)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(deny_unknown_fields, rename_all = "snake_case", tag = "type")
)]
pub enum ProtocolConfig {
    #[default]
    Udp,
    Tcp,
    #[cfg(feature = "dns-over-tls")]
    Tls {
        /// The server name to use in the TLS handshake.
        server_name: Option<Arc<str>>,
    },
    #[cfg(feature = "dns-over-https")]
    Https {
        /// The server name to use in the TLS handshake.
        server_name: Option<Arc<str>>,
        /// The path (or endpoint) to use for the DNS query.
        path: Arc<str>,
        prefer: HttpsPrefer,
    },
    #[cfg(feature = "dns-over-quic")]
    Quic {
        /// The server name to use in the TLS handshake.
        server_name: Option<Arc<str>>,
    },
    #[cfg(feature = "dns-over-h3")]
    H3 {
        /// The server name to use in the TLS handshake.
        server_name: Option<Arc<str>>,
        /// The path (or endpoint) to use for the DNS query.
        path: Arc<str>,
        /// Whether to disable sending "grease"
        #[cfg_attr(feature = "serde", serde(default))]
        disable_grease: bool,
    },
    #[cfg(feature = "mdns")]
    /// mDNS protocol for performing multicast lookups
    Mdns,
    System,
    Dhcp {
        interface: Option<Arc<str>>,
    },
}

impl ProtocolConfig {
    /// Get the [`Protocol`] for this [`ProtocolConfig`].
    pub fn to_protocol(&self) -> Option<Protocol> {
        match self {
            ProtocolConfig::Udp => Some(Protocol::Udp),
            ProtocolConfig::Tcp => Some(Protocol::Tcp),
            #[cfg(feature = "dns-over-tls")]
            ProtocolConfig::Tls { .. } => Some(Protocol::Tls),
            #[cfg(feature = "dns-over-https")]
            ProtocolConfig::Https { .. } => Some(Protocol::Https),
            #[cfg(feature = "dns-over-quic")]
            ProtocolConfig::Quic { .. } => Some(Protocol::Quic),
            #[cfg(feature = "dns-over-h3")]
            ProtocolConfig::H3 { .. } => Some(Protocol::H3),
            #[cfg(feature = "mdns")]
            ProtocolConfig::Mdns => Some(Protocol::Mdns),
            _ => None,
        }
    }

    /**
     * Returns true if this is a datagram oriented protocol, e.g. UDP
     */
    pub fn is_datagram(&self) -> bool {
        matches!(self.to_protocol(), Some(p) if p.is_datagram())
    }

    /**
     * Is this an encrypted protocol, i.e. TLS or HTTPS
     */
    pub fn is_encrypted(&self) -> bool {
        matches!(self.to_protocol(), Some(p) if p.is_encrypted())
    }

    /**
     * Returns true if this is a stream oriented protocol, e.g. TCP
     */
    pub fn is_stream(&self) -> bool {
        matches!(self.to_protocol(), Some(p) if p.is_stream())
    }

    pub fn set_server_name<N: Into<Arc<str>>>(&mut self, server_name: N) {
        let name = Some(server_name.into());
        match self {
            ProtocolConfig::Tls { server_name, .. } => {
                *server_name = name;
            }
            ProtocolConfig::Https { server_name, .. } => {
                *server_name = name;
            }
            ProtocolConfig::Quic { server_name, .. } => {
                *server_name = name;
            }
            ProtocolConfig::H3 { server_name, .. } => {
                *server_name = name;
            }
            _ => (),
        }
    }

    fn to_str(&self) -> &'static str {
        match self {
            ProtocolConfig::Udp => "udp",
            ProtocolConfig::Tcp => "tcp",
            #[cfg(feature = "dns-over-tls")]
            ProtocolConfig::Tls { .. } => "tls",
            #[cfg(feature = "dns-over-https")]
            ProtocolConfig::Https { .. } => "https",
            #[cfg(feature = "dns-over-quic")]
            ProtocolConfig::Quic { .. } => "quic",
            #[cfg(feature = "dns-over-h3")]
            ProtocolConfig::H3 { .. } => "h3",
            #[cfg(feature = "mdns")]
            ProtocolConfig::Mdns => "mdns",
            ProtocolConfig::System => "system",
            ProtocolConfig::Dhcp { .. } => "dhcp",
        }
    }
}

impl ProtocolDefaultPort for ProtocolConfig {
    fn default_port(&self) -> u16 {
        match self.to_protocol() {
            Some(p) => p.default_port(),
            None => 0,
        }
    }
}

impl PartialEq<Protocol> for ProtocolConfig {
    fn eq(&self, other: &Protocol) -> bool {
        matches!(self.to_protocol(), Some(p) if p == *other)
    }
}

impl From<Protocol> for ProtocolConfig {
    fn from(proto: Protocol) -> Self {
        match proto {
            Udp => Self::Udp,
            Tcp => Self::Tcp,
            #[cfg(feature = "dns-over-tls")]
            Tls => Self::Tls {
                server_name: Default::default(),
            },
            #[cfg(feature = "dns-over-quic")]
            Quic => Self::Quic { server_name: None },

            #[cfg(feature = "dns-over-https")]
            Https => Self::Https {
                server_name: None,
                path: DEFAULT_DNS_QUERY_PATH.into(),
                prefer: Default::default(),
            },
            #[cfg(feature = "dns-over-h3")]
            H3 => Self::H3 {
                server_name: None,
                path: DEFAULT_DNS_QUERY_PATH.into(),
                disable_grease: Default::default(),
            },
            #[cfg(feature = "mdns")]
            Mdns => Self::Mdns,
            _ => unimplemented!(),
        }
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(deny_unknown_fields, rename_all = "snake_case", tag = "type")
)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum HttpsPrefer {
    /// Automatically choose the best protocol available. This is the default.
    #[default]
    Auto,
    /// Prefer HTTP/2 over HTTP/3.
    H2,
    /// Prefer HTTP/3 over HTTP/2.
    H3,
}

impl std::fmt::Display for HttpsPrefer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            HttpsPrefer::Auto => "auto",
            HttpsPrefer::H2 => "h2",
            HttpsPrefer::H3 => "h3",
        };
        write!(f, "{s}",)?;
        Ok(())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Params(BTreeMap<Arc<str>, Arc<str>>);

impl Params {
    pub fn get_param<T: FromStr>(&self, name: &str) -> Option<T> {
        self.0
            .get(name)
            .map(|v| T::from_str(v).ok())
            .unwrap_or_default()
    }

    pub fn set_param<T: ToString, N: Into<Arc<str>>>(&mut self, name: N, value: T) {
        *(self.0.entry(name.into()).or_default()) = value.to_string().into()
    }

    pub fn del_param<T: FromStr>(&mut self, name: &str) -> Option<T> {
        self.0
            .remove(name)
            .map(|v| T::from_str(v.deref()).ok())
            .unwrap_or_default()
    }

    pub fn set_sni_on(&mut self, value: bool) {
        self.set_param("sni", value)
    }

    pub fn set_sni_off(&mut self, value: bool) {
        self.set_param("sni", !value)
    }

    pub fn sni_on(&self) -> bool {
        !self.sni_off()
    }

    pub fn sni_off(&self) -> bool {
        self.get_param::<bool>("sni")
            .map(|v| !v)
            .or_else(|| self.get_param::<bool>("enable_sni").map(|v| !v))
            .unwrap_or(false)
    }

    pub fn ssl_verify(&self) -> bool {
        self.get_param("ssl_verify").unwrap_or(true)
    }

    pub fn set_ssl_verify(&mut self, verify: bool) {
        self.set_param("ssl_verify", verify)
    }
}

impl std::ops::Deref for Params {
    type Target = BTreeMap<Arc<str>, Arc<str>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(test)]
mod tests {

    use super::DnsUrl;
    use super::*;
    use crate::preset_ns::CLOUDFLARE_IPS;
    use std::ops::Deref;

    #[test]
    fn test_parse_udp() {
        let url = DnsUrl::from_str("8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "8.8.8.8");
        assert_eq!(url.port(), 53);
        assert_eq!(url.to_string(), "udp://8.8.8.8");
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_udp_1() {
        let url = DnsUrl::from_str("udp://8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host().to_string(), "8.8.8.8");
        assert_eq!(url.port(), 53);
        assert_eq!(url.to_string(), "udp://8.8.8.8");
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_udp_2() {
        let url = DnsUrl::from_str("udp://1.1.1.1:8053").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host().to_string(), "1.1.1.1");
        assert_eq!(url.port(), 8053);
        assert_eq!(url.to_string(), "udp://1.1.1.1:8053");
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_udp_ipv6() {
        for ip in CLOUDFLARE_IPS.iter().copied().map(DnsUrl::from) {
            assert!(ip.proto.is_datagram());
        }
    }

    #[test]
    fn test_parse_tcp() {
        let url = DnsUrl::from_str("tcp://8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Tcp);
        assert_eq!(url.host().to_string(), "8.8.8.8");
        assert_eq!(url.port(), 53);
        assert_eq!(url.to_string(), "tcp://8.8.8.8");
    }

    #[test]
    fn test_parse_tcp_1() {
        let url = DnsUrl::from_str("tcp://8.8.8.8:8053").unwrap();
        assert_eq!(url.proto, Protocol::Tcp);
        assert_eq!(url.host().to_string(), "8.8.8.8");
        assert_eq!(url.port(), 8053);
        assert_eq!(url.to_string(), "tcp://8.8.8.8:8053");
    }

    #[test]
    #[cfg(feature = "dns-over-tls")]
    fn test_parse_tls_1() {
        let url = DnsUrl::from_str("tls://8.8.8.8").unwrap();
        assert_eq!(url.proto, Protocol::Tls);
        assert_eq!(url.host().to_string(), "8.8.8.8");
        assert_eq!(url.port(), 853);
        assert_eq!(url.to_string(), "tls://8.8.8.8");
    }

    #[test]
    #[cfg(feature = "dns-over-tls")]
    fn test_parse_tls_2() {
        let url = DnsUrl::from_str("tls://8.8.8.8:953").unwrap();
        assert_eq!(url.proto, Protocol::Tls);
        assert_eq!(url.host().to_string(), "8.8.8.8");
        assert_eq!(url.port(), 953);
        assert_eq!(url.to_string(), "tls://8.8.8.8:953");
    }

    #[test]
    #[cfg(feature = "dns-over-tls")]
    fn test_parse_tls_3() {
        let url = DnsUrl::from_str("tls://8.8.8.8:953?host=dns.google").unwrap();
        assert_eq!(url.proto, Protocol::Tls);
        assert_eq!(url.host.to_string(), "dns.google");
        assert_eq!(url.port(), 953);
        let ProtocolConfig::Tls { server_name } = &url.proto else {
            panic!("expected tls protocol config")
        };

        assert_eq!(server_name, &Some("dns.google".into()));

        assert_eq!(url.to_string(), "tls://dns.google:953?ip=8.8.8.8");
        assert_eq!(url.ip(), "8.8.8.8".parse().ok())
    }

    #[test]
    #[cfg(feature = "dns-over-https")]
    fn test_parse_https() {
        use std::ops::Deref;

        let url = DnsUrl::from_str("https://dns.google/dns-query").unwrap();
        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host().to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        let ProtocolConfig::Https {
            server_name,
            path,
            prefer,
        } = &url.proto
        else {
            panic!("expected https protocol config")
        };

        assert_eq!(server_name.as_deref(), Some("dns.google"));
        assert_eq!(path.deref(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.google/dns-query");
        assert_eq!(*prefer, HttpsPrefer::Auto);
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-https")]
    fn test_parse_https_1() {
        use std::ops::Deref;

        let url = DnsUrl::from_str("https://dns.google/dns-query1#h2").unwrap();
        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host().to_string(), "dns.google");
        assert_eq!(url.port(), 443);

        let ProtocolConfig::Https {
            server_name,
            path,
            prefer,
        } = &url.proto
        else {
            panic!("expected https protocol config")
        };

        assert_eq!(server_name.as_deref(), Some("dns.google"));
        assert_eq!(path.deref(), "/dns-query1");

        assert_eq!(url.to_string(), "https://dns.google/dns-query1#h2");
        assert_eq!(*prefer, HttpsPrefer::H2);
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-https")]
    fn test_parse_https_2() {
        let url = DnsUrl::from_str("https://dns.google").unwrap();

        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host().to_string(), "dns.google");
        assert_eq!(url.port(), 443);
        let ProtocolConfig::Https {
            server_name,
            path,
            prefer,
        } = &url.proto
        else {
            panic!("expected https protocol config")
        };

        assert_eq!(server_name.as_deref(), Some("dns.google"));
        assert_eq!(path.deref(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.google/dns-query");
        assert!(url.ip().is_none());
        assert_eq!(*prefer, HttpsPrefer::Auto);
    }

    #[test]
    #[cfg(feature = "dns-over-quic")]
    fn test_parse_quic() {
        let url = DnsUrl::from_str("quic://dns.adguard-dns.com").unwrap();

        assert_eq!(url.proto, Protocol::Quic);
        assert_eq!(url.host().to_string(), "dns.adguard-dns.com");
        assert_eq!(url.port(), 853);

        assert_eq!(url.to_string(), "quic://dns.adguard-dns.com");
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-h3")]
    fn test_parse_h3() {
        let url = DnsUrl::from_str("h3://dns.adguard-dns.com#disable_grease").unwrap();

        assert_eq!(url.proto, Protocol::H3);
        assert_eq!(url.host().to_string(), "dns.adguard-dns.com");
        assert_eq!(url.port(), 443);
        let ProtocolConfig::H3 {
            server_name,
            path,
            disable_grease,
        } = &url.proto
        else {
            panic!("expected https protocol config")
        };
        assert_eq!(server_name.as_deref(), Some("dns.adguard-dns.com"));

        assert_eq!(path.deref(), "/dns-query");
        assert_eq!(
            url.to_string(),
            "h3://dns.adguard-dns.com/dns-query#disable_grease"
        );
        assert!(url.ip().is_none());
        assert!(disable_grease);
    }

    #[test]
    #[cfg(feature = "dns-over-h3")]
    fn test_parse_h3_2() {
        let url = DnsUrl::from_str("https://dns.adguard-dns.com/dns-query#h3").unwrap();

        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host().to_string(), "dns.adguard-dns.com");
        assert_eq!(url.port(), 443);
        let ProtocolConfig::Https {
            server_name,
            path,
            prefer,
        } = &url.proto
        else {
            panic!("expected https protocol config")
        };

        assert_eq!(server_name.as_deref(), Some("dns.adguard-dns.com"));
        assert_eq!(path.deref(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.adguard-dns.com/dns-query#h3");
        assert_eq!(*prefer, HttpsPrefer::H3);
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-h3")]
    fn test_parse_h3_3() {
        use std::ops::Deref;

        let url = DnsUrl::from_str("https://dns.adguard-dns.com/#h3").unwrap();

        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.adguard-dns.com");
        assert_eq!(url.port(), 443);
        let ProtocolConfig::Https {
            server_name,
            path,
            prefer,
        } = &url.proto
        else {
            panic!("expected https protocol config")
        };

        assert_eq!(server_name.as_deref(), Some("dns.adguard-dns.com"));
        assert_eq!(path.deref(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.adguard-dns.com/dns-query#h3");
        assert_eq!(*prefer, HttpsPrefer::H3);
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-h3")]
    fn test_parse_h3_4() {
        let url = DnsUrl::from_str("https://dns.adguard-dns.com#h3").unwrap();

        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.adguard-dns.com");
        assert_eq!(url.port(), 443);

        let ProtocolConfig::Https {
            server_name,
            path,
            prefer,
        } = &url.proto
        else {
            panic!("expected https protocol config")
        };

        assert_eq!(*server_name, Some("dns.adguard-dns.com".into()));

        assert_eq!(path.deref(), "/dns-query");
        assert_eq!(url.to_string(), "https://dns.adguard-dns.com/dns-query#h3");
        assert_eq!(*prefer, HttpsPrefer::H3);
        assert!(url.ip().is_none());
    }

    #[test]
    #[cfg(feature = "dns-over-h3")]
    fn test_parse_h3_5() {
        let url = DnsUrl::from_str("https://dns.adguard-dns.com/2dns-query#h3").unwrap();

        assert_eq!(url.proto, Protocol::Https);
        assert_eq!(url.host.to_string(), "dns.adguard-dns.com");
        assert_eq!(url.port(), 443);
        let ProtocolConfig::Https {
            server_name,
            path,
            prefer,
        } = &url.proto
        else {
            panic!("expected https protocol config")
        };

        assert_eq!(*server_name, Some("dns.adguard-dns.com".into()));
        assert_eq!(path.deref(), "/2dns-query");
        assert_eq!(url.to_string(), "https://dns.adguard-dns.com/2dns-query#h3");
        assert_eq!(*prefer, HttpsPrefer::H3);
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
    #[cfg(feature = "mdns")]
    fn test_parse_mdns() {
        let url = DnsUrl::from_str("mdns://127.0.0.1").unwrap();
        assert_eq!(url.proto, Protocol::Mdns);
        assert_eq!(url.host.to_string(), "127.0.0.1");
        assert_eq!(url.port(), 5353);
        assert_eq!(url.to_string(), "mdns://127.0.0.1");
        assert!(url.ip().is_some());
    }

    #[test]
    #[cfg(feature = "mdns")]
    fn test_parse_mdns1() {
        let url = DnsUrl::from_str("224.0.0.251").unwrap();
        assert_eq!(url.proto, Protocol::Mdns);
        assert_eq!(url.host.to_string(), "224.0.0.251");
        assert_eq!(url.port(), 5353);
        assert_eq!(url.to_string(), "mdns://224.0.0.251");
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_misc_01() {
        let url = DnsUrl::from_str("127.0.0.1:1053").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "127.0.0.1");
        assert_eq!(url.port(), 1053);
        assert_eq!(url.to_string(), "udp://127.0.0.1:1053");
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_misc_02() {
        let url = DnsUrl::from_str("[240e:1f:1::1]").unwrap();
        assert_eq!(url.proto, Protocol::Udp);
        assert_eq!(url.host.to_string(), "[240e:1f:1::1]");
        assert_eq!(url.port(), 53);
        assert_eq!(url.to_string(), "udp://[240e:1f:1::1]");
        assert!(url.ip().is_some());
    }

    #[test]
    fn test_parse_enable_sni_false() {
        let url = DnsUrl::from_str("tls://cloudflare-dns.com?enable_sni=false").unwrap();
        assert!(url.sni_off());
        assert!(url.ip().is_none());
    }

    #[test]
    fn test_parse_enable_sni_true() {
        let url = DnsUrl::from_str("tls://cloudflare-dns.com?enable_sni=false").unwrap();
        assert!(url.sni_off());
        assert!(url.ip().is_none());
    }

    #[test]
    fn test_parse_params_ip() {
        let url = DnsUrl::from_str("udp://cloudflare-dns.com?ip=1.1.1.1").unwrap();
        assert_eq!(url.ip(), Some("1.1.1.1".parse().unwrap()));
    }
}
