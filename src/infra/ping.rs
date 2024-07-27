use futures::FutureExt;
use std::{
    fmt::Display,
    io,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};
use thiserror::Error;

pub async fn ping(dest: PingAddr, opts: PingOptions) -> Result<PingOutput, PingError> {
    match dest {
        PingAddr::Icmp(addr) => icmp::ping(addr, opts).await,
        PingAddr::Tcp(addr) => tcp::ping(addr, opts).await,
        PingAddr::Http(addr) => http::ping(addr, opts).await,
        PingAddr::Https(addr) => https::ping(addr, opts).await,
    }
}

pub async fn ping_batch(
    dests: &[PingAddr],
    opts: PingOptions,
) -> Vec<Result<PingOutput, PingError>> {
    let mut outs = Vec::new();

    for dest in dests.iter() {
        outs.push(match dest {
            PingAddr::Icmp(addr) => icmp::ping(*addr, opts).await,
            PingAddr::Tcp(addr) => tcp::ping(*addr, opts).await,
            PingAddr::Http(addr) => http::ping(*addr, opts).await,
            PingAddr::Https(addr) => https::ping(*addr, opts).await,
        })
    }
    outs
}

pub async fn ping_fastest(
    dests: Vec<PingAddr>,
    opts: PingOptions,
) -> Result<PingOutput, PingError> {
    use futures_util::future::select_ok;
    if dests.is_empty() {
        return Err(PingError::NoAddress);
    }

    let ping_tasks = dests.iter().map(|dst| match dst {
        PingAddr::Icmp(addr) => icmp::ping(*addr, opts).boxed(),
        PingAddr::Tcp(addr) => tcp::ping(*addr, opts).boxed(),
        PingAddr::Http(addr) => http::ping(*addr, opts).boxed(),
        PingAddr::Https(addr) => https::ping(*addr, opts).boxed(),
    });

    let res = select_ok(ping_tasks).await;

    match res {
        Ok((out, _rest)) => Ok(out),
        Err(err) => Err(err),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PingOptions {
    times: u16,
    timeout: Duration,
    all_success: bool,
    duration_agg: DurationAgg,
}

impl PingOptions {
    pub fn with_times(mut self, times: u16) -> Self {
        self.times = times;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub fn with_timeout_secs(mut self, timeout: u64) -> Self {
        self.timeout = Duration::from_secs(timeout);
        self
    }

    pub fn with_all_success(mut self, enable: bool) -> Self {
        self.all_success = enable;
        self
    }

    pub fn with_duration_agg(mut self, agg: DurationAgg) -> Self {
        self.duration_agg = agg;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DurationAgg {
    Min,
    Mean,
    Max,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            times: 1,
            timeout: Duration::from_secs(5),
            all_success: false,
            duration_agg: DurationAgg::Mean,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PingAddr {
    Icmp(IpAddr),
    Tcp(SocketAddr),
    Http(SocketAddr),
    Https(SocketAddr),
}

impl PingAddr {
    pub fn ip_addr(self) -> IpAddr {
        match self {
            PingAddr::Icmp(ip) => ip,
            PingAddr::Tcp(addr) => addr.ip(),
            PingAddr::Http(addr) => addr.ip(),
            PingAddr::Https(addr) => addr.ip(),
        }
    }
}

impl PartialEq<IpAddr> for PingAddr {
    fn eq(&self, other: &IpAddr) -> bool {
        self.ip_addr() == *other
    }
}
impl PartialEq<Ipv4Addr> for PingAddr {
    fn eq(&self, other: &Ipv4Addr) -> bool {
        self.eq(&IpAddr::V4(*other))
    }
}
impl PartialEq<Ipv6Addr> for PingAddr {
    fn eq(&self, other: &Ipv6Addr) -> bool {
        self.eq(&IpAddr::V6(*other))
    }
}

impl Display for PingAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PingAddr::Icmp(addr) => write!(f, "icmp://{}", addr),
            PingAddr::Tcp(addr) => write!(f, "tcp://{}", addr),
            PingAddr::Http(addr) => write!(f, "http://{}", addr),
            PingAddr::Https(addr) => write!(f, "https://{}", addr),
        }
    }
}

impl FromStr for PingAddr {
    type Err = PingError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl TryFrom<&str> for PingAddr {
    type Error = PingError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let s = s.trim();
        if let Some(sock_addr) = s.strip_prefix("tcp://") {
            let sock_addr = SocketAddr::from_str(sock_addr)?;
            Ok(Self::Tcp(sock_addr))
        } else if let Some(sock_addr) = s.strip_prefix("http://") {
            let sock_addr = SocketAddr::from_str(sock_addr)
                .or_else(|_| IpAddr::from_str(sock_addr).map(|ip| SocketAddr::new(ip, 80)))?;
            Ok(Self::Http(sock_addr))
        } else if let Some(sock_addr) = s.strip_prefix("https://") {
            let sock_addr = SocketAddr::from_str(sock_addr)
                .or_else(|_| IpAddr::from_str(sock_addr).map(|ip| SocketAddr::new(ip, 443)))?;
            Ok(Self::Https(sock_addr))
        } else {
            let s = s.strip_prefix("icmp://").unwrap_or(s);
            let ip_addr = IpAddr::from_str(s)?;
            Ok(Self::Icmp(ip_addr))
        }
    }
}

#[derive(Debug, Clone)]
pub struct PingOutput {
    seq: u16,
    duration: Duration,
    destination: PingAddr,
}

impl PingOutput {
    #[inline]
    pub fn seq(&self) -> u16 {
        self.seq
    }

    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.duration
    }

    #[inline]
    pub fn dest(&self) -> PingAddr {
        self.destination
    }
}

#[derive(Debug, Error)]
pub enum PingError {
    #[error("ping target parse error")]
    PingTargetParseError,
    #[error("addr parse error {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("addr parse error {0}")]
    AddrParseError2(String),
    #[error("Ping timeout")]
    Timeout,
    #[error("io error {0}")]
    IoError(io::Error),
    #[error("surge error")]
    SurgeError,
    #[error("No address")]
    NoAddress,
}

impl Clone for PingError {
    fn clone(&self) -> Self {
        match self {
            Self::PingTargetParseError => Self::PingTargetParseError,
            Self::AddrParseError(arg0) => Self::AddrParseError(arg0.clone()),
            Self::AddrParseError2(arg0) => Self::AddrParseError2(arg0.clone()),
            Self::Timeout => Self::Timeout,
            Self::IoError(err) => Self::IoError(err.kind().into()),
            Self::SurgeError => Self::SurgeError,
            Self::NoAddress => Self::SurgeError,
        }
    }
}

fn do_agg(durations: Vec<Duration>, agg: DurationAgg) -> Option<Duration> {
    use DurationAgg::*;

    match agg {
        Min => durations.into_iter().min(),
        Mean => {
            let count = durations.len();

            if count > 0 {
                let mut total = Duration::default();

                for duration in durations {
                    total += duration;
                }

                Some(total / (count as u32))
            } else {
                None
            }
        }
        Max => durations.into_iter().max(),
    }
}

#[cfg(feature = "disable_icmp_ping")]
mod icmp {
    //! ignore, Github actions not surpport icmp ping.

    use std::{net::IpAddr, time::Duration};

    use super::{PingError, PingOptions, PingOutput};
    pub async fn ping(ipaddr: IpAddr, _opts: PingOptions) -> Result<PingOutput, PingError> {
        Ok(PingOutput {
            seq: 0,
            duration: Duration::from_millis(1),
            destination: super::PingAddr::Icmp(ipaddr),
        })
    }
}

#[cfg(not(feature = "disable_icmp_ping"))]
mod icmp {
    use std::{net::IpAddr, time::Duration};

    use rand::random;
    use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, Pinger, ICMP};

    use super::{do_agg, PingAddr, PingError, PingOptions, PingOutput};

    mod auto_sock_type {
        use cfg_if::cfg_if;
        use socket2::Type;
        use surge_ping::ICMP;

        cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "android"))] {
                use once_cell::sync::Lazy;
                use socket2::{Domain, Protocol, Socket};
                use std::{io, net::IpAddr};

                pub trait CheckAllowUnprivilegedIcmp {
                    fn allow_unprivileged_icmp(&self) -> bool;
                }


                pub trait CheckAllowRawSocket {
                    fn allow_raw_socket(&self) -> bool;
                }

                impl CheckAllowUnprivilegedIcmp for ICMP {
                    fn allow_unprivileged_icmp(&self) -> bool {
                        match self {
                            ICMP::V4 => *ALLOW_IPV4_UNPRIVILEGED_ICMP,
                            ICMP::V6 => *ALLOW_IPV6_UNPRIVILEGED_ICMP
                        }
                    }
                }

                impl CheckAllowRawSocket for ICMP {
                    #[inline]
                    fn allow_raw_socket(&self) -> bool {
                        match self {
                            ICMP::V4 => *ALLOW_IPV4_RAW_SOCKET,
                            ICMP::V6 => *ALLOW_IPV6_RAW_SOCKET
                        }
                    }
                }

                impl CheckAllowUnprivilegedIcmp for IpAddr {
                    #[inline]
                    fn allow_unprivileged_icmp(&self) -> bool {
                        match self {
                            IpAddr::V4(_) => *ALLOW_IPV4_UNPRIVILEGED_ICMP,
                            IpAddr::V6(_) => *ALLOW_IPV6_UNPRIVILEGED_ICMP,
                        }
                    }
                }

                impl CheckAllowRawSocket for IpAddr {
                    #[inline]
                    fn allow_raw_socket(&self) -> bool {
                        match self {
                            IpAddr::V4(_) => *ALLOW_IPV4_RAW_SOCKET,
                            IpAddr::V6(_) => *ALLOW_IPV6_RAW_SOCKET,
                        }
                    }
                }




                pub static ALLOW_IPV4_UNPRIVILEGED_ICMP: Lazy<bool> = Lazy::new(|| {
                    allow_unprivileged_icmp(Domain::IPV4, Protocol::ICMPV4)
                });

                pub static ALLOW_IPV4_RAW_SOCKET: Lazy<bool> =
                    Lazy::new(|| allow_raw_socket(Domain::IPV4, Protocol::ICMPV4));


                pub static ALLOW_IPV6_UNPRIVILEGED_ICMP: Lazy<bool> = Lazy::new(|| {
                    allow_unprivileged_icmp(Domain::IPV6, Protocol::ICMPV6)
                });

                pub static ALLOW_IPV6_RAW_SOCKET: Lazy<bool> =
                    Lazy::new(|| allow_raw_socket(Domain::IPV6, Protocol::ICMPV6));


                fn allow_unprivileged_icmp(domain: Domain, proto: Protocol) -> bool {
                    !is_permission_denied(Socket::new(domain, Type::DGRAM, Some(proto)))
                }

                fn allow_raw_socket(domain: Domain, proto: Protocol) -> bool {
                    !is_permission_denied(Socket::new(domain, Type::RAW, Some(proto)))
                }

                #[inline]
                fn is_permission_denied(res: io::Result<Socket>) -> bool {
                    matches!(res, Err(err) if matches!(err.kind(), std::io::ErrorKind::PermissionDenied))
                }

            }


        }

        #[allow(unused_variables)]
        pub fn detect(kind: ICMP) -> Type {
            cfg_if! {
                if #[cfg(any(target_os = "linux", target_os = "android"))] {

                    if kind.allow_unprivileged_icmp() {
                        //  enable by running: `sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'`
                        Type::DGRAM
                    } else if kind.allow_raw_socket() {
                        // enable by running: `sudo setcap CAP_NET_RAW+eip /path/to/program`
                        Type::RAW
                    } else {
                        panic!("unpriviledged ping is disabled, please enable by setting `net.ipv4.ping_group_range` or setting `CAP_NET_RAW`")
                    }
                } else if #[cfg(any(target_os = "macos"))] {
                    // MacOS seems enable UNPRIVILEGED_ICMP by default.
                    Type::DGRAM
                } else if #[cfg(any(target_os = "windows"))] {
                    // Windows seems enable RAW_SOCKET by default.
                    Type::RAW
                } else {
                    Type::RAW
                }
            }
        }
    }

    pub async fn ping(ipaddr: IpAddr, opts: PingOptions) -> Result<PingOutput, PingError> {
        let PingOptions {
            times,
            timeout,
            all_success,
            duration_agg,
        } = opts;

        let mut durations = Vec::new();

        let client = match ipaddr {
            IpAddr::V4(_) => Client::new(
                &Config::builder()
                    .kind(ICMP::V4)
                    .sock_type_hint(auto_sock_type::detect(ICMP::V4))
                    .build(),
            ),
            IpAddr::V6(_) => Client::new(
                &Config::builder()
                    .kind(ICMP::V6)
                    .sock_type_hint(auto_sock_type::detect(ICMP::V6))
                    .build(),
            ),
        }?;

        let mut pinger = client.pinger(ipaddr, PingIdentifier(random())).await;
        pinger.timeout(timeout);
        let mut last_err = None;

        for seq in 0..times {
            let duration = ping_icmp(seq, &mut pinger).await;
            match duration {
                Ok(dur) => durations.push(dur),
                Err(err) => {
                    if all_success {
                        return Err(err);
                    } else {
                        last_err = Some(err);
                        continue;
                    }
                }
            }
        }

        let duration = do_agg(durations, duration_agg);

        match duration {
            Some(v) => Ok(PingOutput {
                seq: 0,
                duration: v,
                destination: PingAddr::Icmp(ipaddr),
            }),
            None => match last_err {
                Some(err) => Err(err),
                None => Err(PingError::NoAddress),
            },
        }
    }

    async fn ping_icmp(seq: u16, pinger: &mut Pinger) -> Result<Duration, PingError> {
        let payload = [0; 56];
        let duration = match pinger.ping(PingSequence(seq), &payload).await {
            Ok((IcmpPacket::V4(_), dur)) => dur,
            Ok((IcmpPacket::V6(_), dur)) => dur,
            Err(err) => return Err(err.into()),
        };
        Ok(duration)
    }

    impl From<surge_ping::SurgeError> for PingError {
        fn from(err: surge_ping::SurgeError) -> Self {
            match err {
                surge_ping::SurgeError::Timeout { seq: _ } => PingError::Timeout,
                surge_ping::SurgeError::IOError(err) => PingError::IoError(err),
                _ => PingError::SurgeError,
            }
        }
    }
}

mod tcp {
    use std::{
        io,
        net::SocketAddr,
        time::{Duration, Instant},
    };

    use tokio::{io::Interest, net::TcpSocket};

    use crate::third_ext::FutureTimeoutExt;

    use super::{do_agg, PingAddr, PingError, PingOptions, PingOutput};

    #[inline]
    pub async fn ping(sock_addr: SocketAddr, opts: PingOptions) -> Result<PingOutput, PingError> {
        let PingOptions {
            times,
            timeout,
            all_success,
            duration_agg,
        } = opts;

        let mut durations = Vec::new();

        let mut last_err = None;

        for _seq in 0..times {
            let duration = ping_tcp(sock_addr)
                .timeout(timeout)
                .await
                .unwrap_or(Err(PingError::Timeout));

            match duration {
                Ok(dur) => durations.push(dur),
                Err(err) => {
                    if all_success {
                        return Err(err);
                    } else {
                        last_err = Some(err);
                        continue;
                    }
                }
            }
        }

        let duration = do_agg(durations, duration_agg);

        match duration {
            Some(v) => Ok(PingOutput {
                seq: 0,
                duration: v,
                destination: PingAddr::Tcp(sock_addr),
            }),
            None => match last_err {
                Some(err) => Err(err),
                None => Err(PingError::NoAddress),
            },
        }
    }

    #[inline]
    async fn ping_tcp(addr: SocketAddr) -> Result<Duration, PingError> {
        let start = Instant::now();

        let sock = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }?;

        let stream = sock.connect(addr).await?;
        stream.ready(Interest::WRITABLE).await?;
        drop(stream);
        Ok(start.elapsed())
    }

    impl From<io::Error> for PingError {
        fn from(err: io::Error) -> Self {
            if matches!(err.kind(), io::ErrorKind::TimedOut) {
                PingError::Timeout
            } else {
                PingError::IoError(err)
            }
        }
    }

    impl From<tokio::time::error::Elapsed> for PingError {
        fn from(_: tokio::time::error::Elapsed) -> Self {
            PingError::Timeout
        }
    }
}

mod http {
    use super::{do_agg, PingAddr, PingError, PingOptions, PingOutput};
    use crate::third_ext::FutureTimeoutExt;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};
    use tokio::io::{self, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    #[inline]
    pub async fn ping(sock_addr: SocketAddr, opts: PingOptions) -> Result<PingOutput, PingError> {
        let PingOptions {
            times,
            timeout,
            all_success,
            duration_agg,
        } = opts;

        let mut durations = Vec::new();

        let mut last_err = None;

        for _seq in 0..times {
            let duration = ping_http(sock_addr)
                .timeout(timeout)
                .await
                .unwrap_or(Err(PingError::Timeout));

            match duration {
                Ok(dur) => durations.push(dur),
                Err(err) => {
                    if all_success {
                        return Err(err);
                    } else {
                        last_err = Some(err);
                        continue;
                    }
                }
            }
        }

        let duration = do_agg(durations, duration_agg);

        match duration {
            Some(v) => Ok(PingOutput {
                seq: 0,
                duration: v,
                destination: PingAddr::Http(sock_addr),
            }),
            None => match last_err {
                Some(err) => Err(err),
                None => Err(PingError::NoAddress),
            },
        }
    }

    #[inline]
    pub async fn ping_http(sock_addr: SocketAddr) -> Result<Duration, PingError> {
        let now = Instant::now();
        let mut stream = TcpStream::connect(sock_addr).await?;
        send_ping(&mut stream).await?;
        Ok(now.elapsed())
    }

    pub(super) async fn send_ping<S: AsyncRead + AsyncWrite + std::marker::Unpin>(
        stream: &mut S,
    ) -> io::Result<bool> {
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
        let mut plaintext = String::new();
        let mut reader = BufReader::new(stream);
        reader.read_line(&mut plaintext).await?;
        Ok(plaintext.starts_with("HTTP/"))
    }
}

mod https {
    use std::{
        net::SocketAddr,
        sync::Arc,
        time::{Duration, Instant},
    };

    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    use crate::third_ext::FutureTimeoutExt;

    use super::{do_agg, PingAddr, PingError, PingOptions, PingOutput};

    #[inline]
    pub async fn ping(sock_addr: SocketAddr, opts: PingOptions) -> Result<PingOutput, PingError> {
        let PingOptions {
            times,
            timeout,
            all_success,
            duration_agg,
        } = opts;

        let mut durations = Vec::new();

        let mut last_err = None;

        for _seq in 0..times {
            let duration = ping_https(sock_addr)
                .timeout(timeout)
                .await
                .unwrap_or(Err(PingError::Timeout));

            match duration {
                Ok(dur) => durations.push(dur),
                Err(err) => {
                    if all_success {
                        return Err(err);
                    } else {
                        last_err = Some(err);
                        continue;
                    }
                }
            }
        }

        let duration = do_agg(durations, duration_agg);

        match duration {
            Some(v) => Ok(PingOutput {
                seq: 0,
                duration: v,
                destination: PingAddr::Https(sock_addr),
            }),
            None => match last_err {
                Some(err) => Err(err),
                None => Err(PingError::NoAddress),
            },
        }
    }

    async fn ping_https(addr: SocketAddr) -> Result<Duration, PingError> {
        use rustls::pki_types::ServerName;
        let now = Instant::now();
        let config = Arc::new({
            let mut config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(
                    crate::rustls::NoCertificateVerification,
                ))
                .with_no_client_auth();
            config.enable_sni = false;
            config
        });

        let server_name = ServerName::IpAddress(addr.ip().into());

        let connector = TlsConnector::from(config);

        let sock = TcpStream::connect(addr).await?;
        let mut tls = connector.connect(server_name, sock).await?;

        super::http::send_ping(&mut tls).await?;
        Ok(now.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_addr_equation() {
        assert_eq!(
            PingAddr::from_str("127.0.0.1").unwrap(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            PingAddr::from_str("tcp://223.5.5.5:80").unwrap(),
            "223.5.5.5".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn test_parse_ping_addr_icmp() {
        let a = PingAddr::from_str("127.0.0.1").unwrap();
        assert!(matches!(a, PingAddr::Icmp(ip) if ip == "127.0.0.1".parse::<IpAddr>().unwrap() ));

        let b = PingAddr::from_str("icmp://127.0.0.1").unwrap();
        assert!(matches!(b, PingAddr::Icmp(ip) if ip == "127.0.0.1".parse::<IpAddr>().unwrap() ));
    }

    #[test]
    fn test_parse_ping_addr_icmp_ipv6() {
        let a = PingAddr::from_str("::1").unwrap();
        assert!(matches!(a, PingAddr::Icmp(ip) if ip == "::1".parse::<IpAddr>().unwrap() ));

        let b = PingAddr::from_str("icmp://::1").unwrap();
        assert!(matches!(b, PingAddr::Icmp(ip) if ip == "::1".parse::<IpAddr>().unwrap() ));
    }

    #[test]
    fn test_parse_ping_addr_tcp() {
        let c = PingAddr::from_str("tcp://223.5.5.5:80").unwrap();
        assert!(
            matches!(c, PingAddr::Tcp(ip) if ip == "223.5.5.5:80".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_parse_ping_addr_tcp_ipv6() {
        let c = PingAddr::from_str("tcp://[fe80::ec37:e7ff:fe56:bba7]:80").unwrap();
        assert!(
            matches!(c, PingAddr::Tcp(ip) if ip == "[fe80::ec37:e7ff:fe56:bba7]:80".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_parse_ping_addr_tcp_err() {
        let d = PingAddr::from_str("tcp://223.5.5.5");
        assert!(d.is_err());
    }

    #[test]
    fn test_parse_ping_addr_http() {
        let c = PingAddr::from_str("http://223.5.5.5:80").unwrap();
        assert!(
            matches!(c, PingAddr::Http(ip) if ip == "223.5.5.5:80".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_parse_ping_addr_http_omit_port() {
        let c = PingAddr::from_str("http://223.5.5.5").unwrap();
        assert!(
            matches!(c, PingAddr::Http(ip) if ip == "223.5.5.5:80".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_parse_ping_addr_https() {
        let c = PingAddr::from_str("https://223.5.5.5:4431").unwrap();
        assert!(
            matches!(c, PingAddr::Https(ip) if ip == "223.5.5.5:4431".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_parse_ping_addr_https_omit_port() {
        let c = PingAddr::from_str("https://223.5.5.5").unwrap();
        assert!(
            matches!(c, PingAddr::Https(ip) if ip == "223.5.5.5:443".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_ping_simple() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let results = ping_batch(
                &[
                    "127.0.0.1".parse().unwrap(),
                    "icmp://223.6.6.6".parse().unwrap(),
                    "tcp://223.5.5.5:443".parse().unwrap(),
                    "tcp://223.5.5.5:4446".parse().unwrap(),
                ],
                PingOptions::default()
                    .with_times(10)
                    .with_timeout(Duration::from_secs(3))
                    .with_all_success(true),
            )
            .await;

            assert!(matches!(results.last().unwrap(), Err(PingError::Timeout)));

            for item in results {
                println!("Ping {:?}", item);
            }
        })
    }

    #[test]
    fn test_ping_fatest() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let out = ping_fastest(
                    [
                        "127.0.0.1".parse().unwrap(),
                        "icmp://8.8.8.8".parse().unwrap(),
                        "icmp://223.6.6.6".parse().unwrap(),
                        "tcp://223.5.5.5:443".parse().unwrap(),
                        "tcp://223.5.5.5:4446".parse().unwrap(),
                    ]
                    .into(),
                    Default::default(),
                )
                .await
                .unwrap();
                assert_eq!(out.destination, "127.0.0.1".parse::<PingAddr>().unwrap());
            });
    }

    #[test]
    fn test_ping_https() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let res = ping("https://1.1.1.1:443".parse().unwrap(), Default::default())
                    .await
                    .unwrap();
                assert!(res.duration < Duration::from_secs(5))
            });
    }
}
