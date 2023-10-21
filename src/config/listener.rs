use enum_dispatch::enum_dispatch;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

use super::{ServerOpts, SslConfig};

#[enum_dispatch(NomParser)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Listener {
    Udp(UdpListener),
    Tcp(TcpListener),
    Tls(TlsListener),
    Https(HttpsListener),
    Quic(QuicListener),
}

impl Listener {
    pub fn listen(&self) -> ListenerAddress {
        match self {
            Listener::Udp(v) => v.listen,
            Listener::Tcp(v) => v.listen,
            Listener::Tls(v) => v.listen,
            Listener::Https(v) => v.listen,
            Listener::Quic(v) => v.listen,
        }
    }
    pub fn mut_listen(&mut self) -> &mut ListenerAddress {
        match self {
            Listener::Udp(v) => &mut v.listen,
            Listener::Tcp(v) => &mut v.listen,
            Listener::Tls(v) => &mut v.listen,
            Listener::Https(v) => &mut v.listen,
            Listener::Quic(v) => &mut v.listen,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Listener::Udp(v) => v.port,
            Listener::Tcp(v) => v.port,
            Listener::Tls(v) => v.port,
            Listener::Https(v) => v.port,
            Listener::Quic(v) => v.port,
        }
    }
    pub fn sock_addr(&self) -> SocketAddr {
        match self.listen() {
            ListenerAddress::Localhost => {
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port()).into()
            }
            ListenerAddress::All => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.port()).into(),
            ListenerAddress::V4(ip) => (ip, self.port()).into(),
            ListenerAddress::V6(ip) => (ip, self.port()).into(),
        }
    }
    pub fn device(&self) -> Option<&str> {
        match self {
            Listener::Udp(v) => v.device.as_deref(),
            Listener::Tcp(v) => v.device.as_deref(),
            Listener::Tls(v) => v.device.as_deref(),
            Listener::Https(v) => v.device.as_deref(),
            Listener::Quic(v) => v.device.as_deref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpListener {
    /// listen adress
    pub listen: ListenerAddress,
    /// listen port
    pub port: u16,
    /// bind network device.
    pub device: Option<String>,
    /// ssl config
    pub opts: ServerOpts,
}

impl Default for UdpListener {
    fn default() -> Self {
        Self {
            listen: ListenerAddress::V4(Ipv4Addr::UNSPECIFIED),
            port: 53,
            device: Default::default(),
            opts: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpListener {
    /// listen adress
    pub listen: ListenerAddress,
    /// listen port
    pub port: u16,
    /// bind network device.
    pub device: Option<String>,
    /// ssl config
    pub opts: ServerOpts,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsListener {
    /// listen adress
    pub listen: ListenerAddress,
    /// listen port
    pub port: u16,
    /// bind network device.
    pub device: Option<String>,
    /// the server options
    pub opts: ServerOpts,
    /// ssl config
    pub ssl_config: Option<SslConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpsListener {
    /// listen adress
    pub listen: ListenerAddress,
    /// listen port
    pub port: u16,
    /// bind network device.
    pub device: Option<String>,
    /// the server options
    pub opts: ServerOpts,
    /// ssl config
    pub ssl_config: Option<SslConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuicListener {
    /// listen adress
    pub listen: ListenerAddress,
    /// listen port
    pub port: u16,
    /// bind network device.
    pub device: Option<String>,
    /// the server options
    pub opts: ServerOpts,
    /// ssl config
    pub ssl_config: Option<SslConfig>,
}

macro_rules! impl_listener {
    ($($name:ident),+) => {
        $(
            impl $name {
                pub fn listen(&self) -> ListenerAddress {
                    self.listen
                }
                pub fn mut_listen(&mut self) -> &mut ListenerAddress {
                    &mut self.listen
                }

                pub fn port(&self) -> u16 {
                    self.port
                }
                pub fn sock_addr(&self) -> SocketAddr {
                    match self.listen() {
                        ListenerAddress::Localhost => SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port()).into(),
                        ListenerAddress::All => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.port()).into(),
                        ListenerAddress::V4(ip) => (ip, self.port()).into(),
                        ListenerAddress::V6(ip) => (ip, self.port()).into(),
                    }
                }
                pub fn device(&self) -> Option<&str> {
                    self.device.as_deref()
                }
            }
        )+
    }
}

impl_listener!(
    UdpListener,
    TcpListener,
    TlsListener,
    HttpsListener,
    QuicListener
);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ListenerAddress {
    Localhost,
    All,
    V4(Ipv4Addr),
    V6(Ipv6Addr),
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
