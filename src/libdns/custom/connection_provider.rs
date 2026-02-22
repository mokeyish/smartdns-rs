use crate::dns_client::{BootstrapResolver, GenericResolverExt};
use crate::dns_url::{DnsUrl, Host, HttpsPrefer, ProtocolConfig};
use crate::libdns::custom::warmup::DnsHandleWarmpup;
use crate::libdns::net::{self, NetError};
use crate::log;
use crate::proxy::{self, ProxyConfig};
use crate::proxy::{TcpStream, UdpSocket};
use crate::third_ext::FutureTimeoutExt;
use async_trait::async_trait;
use futures::FutureExt;
use smallvec::{SmallVec, smallvec, smallvec_inline};
use std::future::Future;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::task::Poll;
use std::task::ready;
use std::time::Duration;
use std::{io, net::SocketAddr, pin::Pin};

use crate::libdns::{
    net::{
        runtime::{QuicSocketBinder, TokioHandle, TokioTime, iocompat::AsyncIoTokioAsStd},
        xfer::{self},
    },
    resolver::{
        ConnectionProvider as _, PoolContext,
        config::{ConnectionConfig, ResolverOpts},
    },
};
use std::borrow::Cow;

type NameServer = crate::libdns::resolver::NameServer<ConnectionProvider>;
type NameServerPool = crate::libdns::resolver::NameServerPool<ConnectionProvider>;
type DnsExchange = xfer::DnsExchange<RuntimeProvider>;
type RuntimeProvider = TokioRuntimeProvider;
type Handle = TokioHandle;
type Time = TokioTime;
type Tcp = AsyncIoTokioAsStd<TcpStream>;
type Udp = UdpSocket;
type ConnectionFuture = Pin<Box<dyn Send + Future<Output = Result<DnsExchange, NetError>>>>;

pub type Connection = NameServerPool;

#[derive(Clone)]
pub struct ConnectionProvider {
    cx: Arc<PoolContext>,
    server: DnsUrl,
    resolver: Option<Arc<BootstrapResolver>>,
    options: Arc<ResolverOpts>,
    runtime_provider: RuntimeProvider,
}

impl ConnectionProvider {
    pub fn new(
        server: DnsUrl,
        cx: Arc<PoolContext>,
        options: Arc<ResolverOpts>,
        resolver: Option<Arc<BootstrapResolver>>,
        proxy: Option<ProxyConfig>,
        so_mark: Option<u32>,
        device: Option<String>,
    ) -> Connection {
        let config = (&server).into();

        let conn_provider = Self {
            server,
            resolver,
            options: options.clone(),
            runtime_provider: TokioRuntimeProvider::new(proxy, so_mark, device),
            cx: cx.clone(),
        };

        NameServerPool::from_config([config], cx, conn_provider)
    }
}

impl crate::libdns::resolver::ConnectionProvider for ConnectionProvider {
    type Conn = DnsExchange;

    type FutureConn = ConnectionFuture;

    type RuntimeProvider = RuntimeProvider;

    fn new_connection(
        &self,
        _ip: IpAddr,
        _config: &ConnectionConfig,
        _cx: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let cx = self.cx.clone();
        let server = self.server.clone();
        let runtime_proviver = self.runtime_provider.clone();
        let resolver = self.resolver.clone();
        type StackVec<T> = SmallVec<[T; 2]>;
        type Stack2xVec<T> = SmallVec<[T; 4]>;

        Ok(async move {

            let ip_addrs: StackVec<(_, StackVec<_>)> = match (server.host(), server.proto()) {
                (_, ProtocolConfig::System) => {
                    let (resolv_conf, _) = crate::libdns::resolver::system_conf::read_system_conf()?;
                    if resolv_conf.name_servers.is_empty() {
                        return Err(NetError::NoConnections);
                    }
                    resolv_conf.name_servers.iter().map(|conf| {
                        let mut url = DnsUrl::from(conf);
                        *url = (*server).clone(); // params
                        (Cow::Owned(url), smallvec![conf.ip])
                    }).collect()
                },
                (_, ProtocolConfig::Dhcp { interface }) => {
                    use crate::infra::dhcp::{discover_v4, DhcpMessageExt};
                    let interface = interface.as_deref();

                    let msg = discover_v4(interface).await.map_err(|err| {
                        log::warn!("dhcp discover failed: {}", err);
                        io::Error::other("dhcp discover failed")
                    })?;

                    let nameservers = msg.nameservers();

                    if nameservers.is_empty() {
                        return Err(NetError::NoConnections);
                    }

                    nameservers.into_iter().map(|ip| {
                        (Cow::Owned(DnsUrl::from(ip)), smallvec![ip])
                    }).collect()
                },
                (Host::Domain(domain), _) => {
                    match server.get_param::<IpAddr>("ip") {
                        Some(ip) => smallvec![(Cow::Borrowed(&server), smallvec![ip])],
                        None => {
                            let Some(resolver) = resolver.as_ref() else {
                                log::warn!("resolver must be set when using domain name");
                                return Err(NetError::NoConnections);
                            };

                            let ip_addrs = match resolver.lookup_ip(domain).await {
                                Ok(lookup_ip) => lookup_ip.ip_addrs().into_iter().collect(),
                                Err(err) => {
                                    log::warn!("lookup ip: {domain} failed, {err}");
                                    smallvec![]
                                }
                            };

                            if ip_addrs.is_empty() {
                                return Err(NetError::NoConnections);
                            }
                            smallvec![(Cow::Borrowed(&server), ip_addrs)]
                        }
                    }
                }
                (Host::Ipv4(ipv4_addr), _) => {
                    smallvec![(Cow::Borrowed(&server), smallvec![(*ipv4_addr).into()])]
                }
                (Host::Ipv6(ipv6_addr), _) => {
                    smallvec![(Cow::Borrowed(&server), smallvec![(*ipv6_addr).into()])]
                }
            };

            let server_addrs: StackVec<(_, StackVec<_>)> = ip_addrs
                .into_iter()
                .map(|(server, ip)| {
                    let port = server.port();
                    (server, ip.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
                })
                .collect();

            if let [(server, server_addrs)] = &*server_addrs
                && let [server_addr] = &**server_addrs
                && !matches!(server.proto(), ProtocolConfig::Https { prefer, .. } if *prefer != HttpsPrefer::H2)
            {
                return new_connection(server, *server_addr, runtime_proviver, cx.deref()).await;
            }

            let mut h3_server_addrs = Stack2xVec::<(Cow<DnsUrl>, _, _)>::new();
            for (server, server_addrs) in &server_addrs {
                let server = Cow::Borrowed(&**server);
                match server.proto() {
                    ProtocolConfig::Https { prefer, path, .. } if *prefer != HttpsPrefer::H2 => {
                        let h3_proto = ProtocolConfig::H3 {
                            path: path.clone(),
                            disable_grease: server.is_set("disable_grease"),
                        };
                        let delay_h2 = *prefer == HttpsPrefer::H3;
                        h3_server_addrs.extend(server_addrs.iter().flat_map(|server_addr| {
                            let h2_server = server.clone();
                            let mut h3_server = server.clone();
                            h3_server.to_mut().set_proto(h3_proto.clone());
                            smallvec_inline![
                                (h3_server, server_addr, false),
                                (h2_server, server_addr, delay_h2),
                            ]
                        }));
                    },
                    _ => h3_server_addrs.extend(server_addrs.iter().map(|server_addr| (server.clone(), server_addr, false)))
                }
            }
            let server_addrs = h3_server_addrs;

            let conns = server_addrs.into_iter().map(|(server, server_addr, delay)| {
                let cx = cx.clone();
                let runtime_proviver = runtime_proviver.clone();
                async move {
                    let conn = new_connection(&server, *server_addr, runtime_proviver, cx.deref()).await?;

                    let ok = conn.warmup().await.is_ok();

                    if !ok || delay {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }

                    Ok(conn)
                }
                .boxed()
            });

            let conn = match futures::future::select_ok(conns).await {
                Ok((conn, _)) => conn,
                Err(err) => {
                    log::error!("Failed to connect to any nameserver: {} {}", server, err);
                    return Err(err);
                }
            };

            Ok(conn)
        }
        .boxed())
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        todo!()
    }
}

async fn new_connection(
    server: &DnsUrl,
    server_addr: SocketAddr,
    runtime_proviver: RuntimeProvider,
    cx: &PoolContext,
) -> Result<DnsExchange, NetError> {
    let config: ConnectionConfig = server.into();

    let conn = runtime_proviver
        .new_connection(server_addr.ip(), &config, cx)?
        .await?;

    Ok(conn)
}

/// The Tokio Runtime for async execution
#[derive(Clone, Default)]
pub struct TokioRuntimeProvider {
    proxy: Option<ProxyConfig>,
    so_mark: Option<u32>,
    device: Option<String>,
    handle: TokioHandle,
}

impl TokioRuntimeProvider {
    pub fn new(proxy: Option<ProxyConfig>, so_mark: Option<u32>, device: Option<String>) -> Self {
        Self {
            proxy,
            so_mark,
            device,
            handle: TokioHandle::default(),
        }
    }
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn setup_socket<F: std::os::fd::AsFd, S: std::ops::Deref<Target = F> + Sized>(
    socket: S,
    bind_addr: Option<SocketAddr>,
    mark: Option<u32>,
    device: Option<String>,
) -> S {
    if mark.is_some() || device.is_some() || bind_addr.is_some() {
        use socket2::SockRef;
        let sock_ref = SockRef::from(socket.deref());
        if let Some(mark) = mark {
            sock_ref.set_mark(mark).unwrap_or_else(|err| {
                log::warn!("set so_mark failed: {:?}", err);
            });
        }

        if let Some(device) = device {
            sock_ref
                .bind_device(Some(device.as_bytes()))
                .unwrap_or_else(|err| {
                    log::warn!("bind device failed: {:?}", err);
                });
        }

        if let Some(bind_addr) = bind_addr {
            sock_ref.bind(&bind_addr.into()).unwrap_or_else(|err| {
                log::warn!("bind addr failed: {:?}", err);
            });
        }
    }
    socket
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
#[inline]
fn setup_socket<S>(
    socket: S,
    _bind_addr: Option<SocketAddr>,
    _mark: Option<u32>,
    _device: Option<String>,
) -> S {
    socket
}

impl crate::libdns::net::runtime::RuntimeProvider for TokioRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let proxy_config = self.proxy.clone();

        let so_mark = self.so_mark;
        let device = self.device.clone();
        let setup_socket = move |tcp| {
            setup_socket(&tcp, bind_addr, so_mark, device);
            tcp
        };
        let wait_for = timeout.unwrap_or_else(|| Duration::from_secs(5));

        Box::pin(async move {
            async move {
                proxy::connect_tcp(server_addr, proxy_config.as_ref())
                    .await
                    .map(setup_socket)
                    .map(AsyncIoTokioAsStd)
            }
            .timeout(wait_for)
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                ))
            })
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let proxy_config = self.proxy.clone();

        let so_mark = self.so_mark;
        let device = self.device.clone();
        let setup_socket = move |udp| setup_socket(udp, None, so_mark, device);

        Box::pin(async move {
            proxy::connect_udp(server_addr, local_addr, proxy_config.as_ref())
                .await
                .map(setup_socket)
        })
    }

    #[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
    fn quic_binder(&self) -> Option<&dyn QuicSocketBinder> {
        Some(&TokioQuicSocketBinder)
    }
}

#[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
struct TokioQuicSocketBinder;

#[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
impl QuicSocketBinder for TokioQuicSocketBinder {
    fn bind_quic(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Result<Arc<dyn quinn::AsyncUdpSocket>, io::Error> {
        use quinn::Runtime;
        let socket = next_random_udp(local_addr)?;
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }
}

#[async_trait]
impl net::runtime::DnsUdpSocket for UdpSocket {
    type Time = TokioTime;

    fn poll_recv_from(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<(usize, SocketAddr)>> {
        match self {
            UdpSocket::Tokio(s) => {
                let mut buf = tokio::io::ReadBuf::new(buf);
                let addr = ready!(tokio::net::UdpSocket::poll_recv_from(s, cx, &mut buf))?;
                let len = buf.filled().len();
                Poll::Ready(Ok((len, addr)))
            }
            UdpSocket::Proxy(s) => {
                let (len, addr) = ready!(s.poll_recv_from(cx, buf))
                    .map_err(|err| io::Error::other(err.to_string()))?;
                let addr = match addr {
                    async_socks5::AddrKind::Ip(addr) => addr,
                    async_socks5::AddrKind::Domain(_, _) => {
                        Err(io::Error::other("Expect IP address"))?
                    }
                };
                Poll::Ready(Ok((len, addr)))
            }
        }
    }

    fn poll_send_to(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::task::Poll<io::Result<usize>> {
        match self {
            UdpSocket::Tokio(s) => tokio::net::UdpSocket::poll_send_to(s, cx, buf, target),
            UdpSocket::Proxy(s) => {
                let res = ready!(s.poll_send_to(cx, buf, target))
                    .map_err(|err| io::Error::other(err.to_string()));
                Poll::Ready(res)
            }
        }
    }

    /// Receive data from the socket and returns the number of bytes read and the address from
    /// where the data came on success.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use UdpSocket::*;
        let (len, addr) = match self {
            Tokio(s) => s.recv_from(buf).await,
            Proxy(s) => {
                let (len, addr) = s
                    .recv_from(buf)
                    .await
                    .map_err(|err| io::Error::other(err.to_string()))?;

                let addr = match addr {
                    async_socks5::AddrKind::Ip(addr) => addr,
                    async_socks5::AddrKind::Domain(_, _) => {
                        Err(io::Error::other("Expect IP address"))?
                    }
                };
                Ok((len, addr))
            }
        }?;
        Ok((len, addr))
    }

    /// Send data to the given address.
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        use UdpSocket::*;
        match self {
            Tokio(s) => s.send_to(buf, target).await,
            Proxy(s) => s
                .send_to(buf, target)
                .await
                .map_err(|err| io::Error::other(err.to_string())),
        }
    }
}

fn next_random_udp(bind_addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    const ATTEMPT_RANDOM: usize = 10;
    if bind_addr.port() == 0 {
        for attempt in 0..ATTEMPT_RANDOM {
            // Per RFC 6056 Section 3.2:
            //
            // As mentioned in Section 2.1, the dynamic ports consist of the range
            // 49152-65535.  However, ephemeral port selection algorithms should use
            // the whole range 1024-65535.
            let port = rand::random_range(1024..=u16::MAX);

            let bind_addr = SocketAddr::new(bind_addr.ip(), port);

            match std::net::UdpSocket::bind(bind_addr) {
                Ok(socket) => {
                    log::debug!("created socket successfully");
                    return Ok(socket);
                }
                Err(err) => {
                    log::debug!("unable to bind port, attempt: {}: {err}", attempt);
                }
            }
        }
    }
    std::net::UdpSocket::bind(bind_addr)
}
