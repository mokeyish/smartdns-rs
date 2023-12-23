use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use crate::third_ext::serde_str;

use super::{ServerOpts, SslConfig};

#[enum_dispatch(NomParser, IListenerConfig)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ListenerConfig {
    Udp(UdpListenerConfig),
    Tcp(TcpListenerConfig),
    Tls(TlsListenerConfig),
    Https(HttpsListenerConfig),
    Quic(QuicListenerConfig),
}

#[enum_dispatch]
pub trait IListenerConfig {
    fn listen(&self) -> ListenerAddress;
    fn mut_listen(&mut self) -> &mut ListenerAddress;
    fn port(&self) -> u16;
    fn device(&self) -> Option<&str>;
    fn server_opts(&self) -> &ServerOpts;
    fn sock_addr(&self) -> SocketAddr {
        match self.listen() {
            ListenerAddress::Localhost => {
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port()).into()
            }
            ListenerAddress::All => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.port()).into(),
            ListenerAddress::V4(ip) => (ip, self.port()).into(),
            ListenerAddress::V6(ip) => (ip, self.port()).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UdpListenerConfig {
    /// listen adress
    #[serde(with = "serde_str")]
    pub listen: ListenerAddress,
    /// listen port
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// ssl config
    #[serde(flatten)]
    pub opts: ServerOpts,
}

impl Default for UdpListenerConfig {
    fn default() -> Self {
        Self {
            listen: ListenerAddress::V4(Ipv4Addr::UNSPECIFIED),
            port: 53,
            device: Default::default(),
            opts: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpListenerConfig {
    /// listen adress
    #[serde(with = "serde_str")]
    pub listen: ListenerAddress,
    /// listen port
    pub port: u16,
    /// bind network device.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// ssl config
    #[serde(flatten)]
    pub opts: ServerOpts,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TlsListenerConfig {
    /// listen adress
    #[serde(with = "serde_str")]
    pub listen: ListenerAddress,
    /// listen port
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
pub struct HttpsListenerConfig {
    /// listen adress
    #[serde(with = "serde_str")]
    pub listen: ListenerAddress,
    /// listen port
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
pub struct QuicListenerConfig {
    /// listen adress
    #[serde(with = "serde_str")]
    pub listen: ListenerAddress,
    /// listen port
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
            impl IListenerConfig for $name {
                fn listen(&self) -> ListenerAddress {
                    self.listen
                }
                fn mut_listen(&mut self) -> &mut ListenerAddress {
                    &mut self.listen
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
    UdpListenerConfig,
    TcpListenerConfig,
    TlsListenerConfig,
    HttpsListenerConfig,
    QuicListenerConfig
);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ListenerAddress {
    Localhost,
    All,
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl ToString for ListenerAddress {
    fn to_string(&self) -> String {
        use ListenerAddress::*;

        match self {
            Localhost => "localhost".to_string(),
            All => "*".to_string(),
            V4(ip) => ip.to_string(),
            V6(ip) => format!("[{ip}]"),
        }
    }
}

impl From<IpAddr> for ListenerAddress {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ip) => ListenerAddress::V4(ip),
            IpAddr::V6(ip) => ListenerAddress::V6(ip),
        }
    }
}

impl ListenerAddress {
    /// Returns the ip addr of this [`ListenerAddress`].
    fn ip_addr(self) -> IpAddr {
        match self {
            ListenerAddress::Localhost => IpAddr::V4(Ipv4Addr::LOCALHOST),
            ListenerAddress::All => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ListenerAddress::V4(ip) => ip.into(),
            ListenerAddress::V6(ip) => ip.into(),
        }
    }
}
