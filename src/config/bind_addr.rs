use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use crate::third_ext::serde_str;

use super::{ServerOpts, SslConfig};

#[enum_dispatch(NomParser, IBindConfig)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BindAddrConfig {
    Udp(UdpBindAddrConfig),
    Tcp(TcpBindAddrConfig),
    Tls(TlsBindAddrConfig),
    Https(HttpsBindAddrConfig),
    H3(H3BindAddrConfig),
    Quic(QuicBindAddrConfig),
}

#[enum_dispatch]
pub trait IBindConfig {
    fn addr(&self) -> BindAddr;
    fn mut_addr(&mut self) -> &mut BindAddr;
    fn port(&self) -> u16;
    fn device(&self) -> Option<&str>;
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
    #[serde(with = "serde_str")]
    pub addr: BindAddr,
    /// listen port
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// ssl config
    #[serde(flatten)]
    pub opts: ServerOpts,
}

impl Default for UdpBindAddrConfig {
    fn default() -> Self {
        Self {
            addr: BindAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 53,
            device: Default::default(),
            opts: Default::default(),
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
}

macro_rules! impl_listener {
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

                fn server_opts(&self) -> &ServerOpts {
                    &self.opts
                }
            }
        )+
    }
}

impl_listener!(
    UdpBindAddrConfig,
    TcpBindAddrConfig,
    TlsBindAddrConfig,
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
