use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use crate::libdns::{Protocol, ProtocolDefaultPort};
use crate::third_ext::serde_str;

use super::{ServerOpts, SslConfig};

#[enum_dispatch(NomParser, IBindConfig)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BindAddrConfig {
    #[serde(rename = "udp")]
    Udp(UdpBindAddrConfig),
    #[serde(rename = "tcp")]
    Tcp(TcpBindAddrConfig),
    #[serde(rename = "tls")]
    Tls(TlsBindAddrConfig),
    #[serde(rename = "http")]
    Http(HttpBindAddrConfig),
    #[serde(rename = "https")]
    Https(HttpsBindAddrConfig),
    #[serde(rename = "h3")]
    H3(H3BindAddrConfig),
    #[serde(rename = "quic")]
    Quic(QuicBindAddrConfig),
}

#[enum_dispatch]
pub trait IBindConfig {
    fn addr(&self) -> BindAddr;
    fn mut_addr(&mut self) -> &mut BindAddr;
    fn port(&self) -> u16;
    fn device(&self) -> Option<&str>;
    fn enabled(&self) -> bool;
    fn server_opts(&self) -> &ServerOpts;
    fn sock_addr(&self) -> SocketAddr {
        match self.addr() {
            BindAddr::Localhost => SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port()).into(),
            BindAddr::All => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.port()).into(),
            BindAddr::V4(ip) => (ip, self.port()).into(),
            BindAddr::V6(ip) => (ip, self.port()).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UdpBindAddrConfig {
    /// listen adress
    #[serde(with = "serde_str", alias = "address")]
    pub addr: BindAddr,
    /// listen port
    #[serde(default = "UdpBindAddrConfig::default_port")]
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// ssl config
    #[serde(flatten)]
    pub opts: ServerOpts,

    /// indicates whether this bind address is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl UdpBindAddrConfig {
    fn default_port() -> u16 {
        Protocol::Udp.default_port()
    }
}

impl Default for UdpBindAddrConfig {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            port: Self::default_port(),
            device: Default::default(),
            opts: Default::default(),
            enabled: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpBindAddrConfig {
    /// addr adress
    #[serde(with = "serde_str")]
    pub addr: BindAddr,
    /// addr port
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// ssl config
    #[serde(flatten)]
    pub opts: ServerOpts,

    /// indicates whether this bind address is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl TcpBindAddrConfig {
    fn default_port() -> u16 {
        Protocol::Tcp.default_port()
    }
}

impl Default for TcpBindAddrConfig {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            port: Self::default_port(),
            device: Default::default(),
            opts: Default::default(),
            enabled: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TlsBindAddrConfig {
    /// addr adress
    #[serde(with = "serde_str")]
    pub addr: BindAddr,
    /// addr port
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// the server options
    #[serde(flatten)]
    pub opts: ServerOpts,
    /// ssl config
    #[serde(flatten)]
    pub ssl_config: SslConfig,

    /// indicates whether this bind address is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl TlsBindAddrConfig {
    fn default_port() -> u16 {
        Protocol::Tls.default_port()
    }
}

impl Default for TlsBindAddrConfig {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            port: Self::default_port(),
            device: Default::default(),
            opts: Default::default(),
            enabled: Default::default(),
            ssl_config: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HttpBindAddrConfig {
    /// addr adress
    #[serde(with = "serde_str")]
    pub addr: BindAddr,
    /// addr port
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// the server options
    #[serde(flatten)]
    pub opts: ServerOpts,
    /// indicates whether this bind address is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl HttpBindAddrConfig {
    fn default_port() -> u16 {
        80
    }
}

impl Default for HttpBindAddrConfig {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            port: Self::default_port(),
            device: Default::default(),
            opts: Default::default(),
            enabled: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HttpsBindAddrConfig {
    /// addr adress
    #[serde(with = "serde_str")]
    pub addr: BindAddr,
    /// addr port
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// the server options
    #[serde(flatten)]
    pub opts: ServerOpts,
    /// ssl config
    #[serde(flatten)]
    pub ssl_config: SslConfig,

    /// indicates whether this bind address is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl HttpsBindAddrConfig {
    fn default_port() -> u16 {
        Protocol::Https.default_port()
    }
}

impl Default for HttpsBindAddrConfig {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            port: Self::default_port(),
            device: Default::default(),
            opts: Default::default(),
            enabled: Default::default(),
            ssl_config: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct H3BindAddrConfig {
    /// addr adress
    #[serde(with = "serde_str")]
    pub addr: BindAddr,
    /// addr port
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// the server options
    #[serde(flatten)]
    pub opts: ServerOpts,
    /// ssl config
    #[serde(flatten)]
    pub ssl_config: SslConfig,

    /// indicates whether this bind address is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl H3BindAddrConfig {
    fn default_port() -> u16 {
        Protocol::H3.default_port()
    }
}

impl Default for H3BindAddrConfig {
    fn default() -> Self {
        Self {
            addr: Default::default(),
            port: Self::default_port(),
            device: Default::default(),
            opts: Default::default(),
            enabled: Default::default(),
            ssl_config: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuicBindAddrConfig {
    /// addr adress
    #[serde(with = "serde_str")]
    pub addr: BindAddr,
    /// addr port
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// the server options
    #[serde(flatten)]
    pub opts: ServerOpts,
    /// ssl config
    #[serde(flatten)]
    pub ssl_config: SslConfig,

    /// indicates whether this bind address is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

macro_rules! impl_bind_addr {
    ($($name:ident),+) => {
        $(
            impl IBindConfig for $name {
                fn addr(&self) -> BindAddr {
                    self.addr
                }
                fn mut_addr(&mut self) -> &mut BindAddr {
                    &mut self.addr
                }

                fn port(&self) -> u16 {
                    self.port
                }
                fn device(&self) -> Option<&str> {
                    self.device.as_deref()
                }

                fn enabled(&self) -> bool {
                    self.enabled.unwrap_or(true)
                }

                fn server_opts(&self) -> &ServerOpts {
                    &self.opts
                }
            }
        )+
    }
}

impl_bind_addr!(
    UdpBindAddrConfig,
    TcpBindAddrConfig,
    TlsBindAddrConfig,
    HttpBindAddrConfig,
    HttpsBindAddrConfig,
    H3BindAddrConfig,
    QuicBindAddrConfig
);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum BindAddr {
    Localhost,
    All,
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl Default for BindAddr {
    fn default() -> Self {
        BindAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

impl std::fmt::Display for BindAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use BindAddr::*;

        match self {
            Localhost => write!(f, "localhost"),
            All => write!(f, "*"),
            V4(ip) => write!(f, "{ip}"),
            V6(ip) => write!(f, "[{ip}]"),
        }
    }
}

impl From<IpAddr> for BindAddr {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip) => BindAddr::V4(ip),
            IpAddr::V6(ip) => BindAddr::V6(ip),
        }
    }
}

impl BindAddr {
    /// Returns the ip addr of this [`ListenerAddress`].
    fn ip_addr(self) -> IpAddr {
        match self {
            BindAddr::Localhost => IpAddr::V4(Ipv4Addr::LOCALHOST),
            BindAddr::All => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            BindAddr::V4(ip) => ip.into(),
            BindAddr::V6(ip) => ip.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_deserialize_bind_addr_simple() {
        let json_str = r#"
        {
            "type": "udp",
            "address": "0.0.0.0",
            "device": null,
            "enabled": true
        }
        "#;

        let bind_addr: BindAddrConfig = serde_json::from_str(json_str).unwrap();

        assert_eq!(bind_addr.addr(), BindAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(bind_addr.port(), 53);
        assert!(bind_addr.device().is_none());
        assert!(bind_addr.enabled());

        let json_str = r#"
        {
            "type": "udp",
            "address": "127.0.0.1",
            "port": 53,
            "device": null,
            "enabled": false
        }
        "#;

        let bind_addr: BindAddrConfig = serde_json::from_str(json_str).unwrap();

        assert_eq!(bind_addr.addr(), BindAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(bind_addr.port(), 53);
        assert!(bind_addr.device().is_none());
        assert!(!bind_addr.enabled());
    }
}
