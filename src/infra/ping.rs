use futures::FutureExt;
use std::{
    fmt::Display,
    io,
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    time::Duration,
};
use thiserror::Error;

pub async fn ping(dests: &[PingAddr], opts: PingOptions) -> Vec<Result<PingOutput, PingError>> {
    let mut outs = Vec::new();

    for (_seq, dest) in dests.iter().enumerate() {
        outs.push(match dest {
            PingAddr::Icmp(addr) => icmp_ping::ping(*addr, opts).await,
            PingAddr::Tcp(addr) => tcp_ping::ping(*addr, opts).await,
        })
    }
    outs
}

pub async fn ping_fastest(
    dests: Vec<PingAddr>,
    opts: PingOptions,
) -> Result<PingOutput, PingError> {
    use futures_util::future::select_ok;

    let ping_tasks = dests.iter().map(|dst| match dst {
        PingAddr::Icmp(addr) => icmp_ping::ping(*addr, opts).boxed(),
        PingAddr::Tcp(addr) => tcp_ping::ping(*addr, opts).boxed(),
    });

    let res = select_ok(ping_tasks).await;

    match res {
        Ok((out, _rest)) => Ok(out),
        Err(err) => Err(err),
    }
}

// pub trait PingClient {

//     fn ping(dest: PingAddr, opts: PingOptions) -> Result<PingOutput, PingError>;

//     fn ping_batch(dests: &[PingAddr], opts: PingOptions) -> Vec<Result<PingOutput, PingError>>;

//     fn ping_fastest(dests: &[PingAddr], opts: PingOptions) -> Result<PingOutput, PingError>;
// }

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
}

impl PingAddr {
    pub fn ip(self) -> IpAddr {
        match self {
            PingAddr::Icmp(ip) => ip,
            PingAddr::Tcp(addr) => addr.ip(),
        }
    }
}

impl PartialEq<IpAddr> for PingAddr {
    fn eq(&self, other: &IpAddr) -> bool {
        self.ip() == *other
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
        }
    }
}

#[derive(Debug)]
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
    pub fn duration(&self) -> Duration {
        self.duration
    }

    #[inline]
    pub fn destination(&self) -> PingAddr {
        self.destination
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
        } else {
            let s = s.strip_prefix("icmp://").unwrap_or(s);
            let ip_addr = IpAddr::from_str(s)?;
            Ok(Self::Icmp(ip_addr))
        }
    }
}

#[derive(Debug, Error)]
pub enum PingError {
    #[error("ping target parse error")]
    PingTargetParseError,
    #[error("addr parse error {0}")]
    AddrParseError(#[from] AddrParseError),
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
mod icmp_ping {
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
mod icmp_ping {
    use std::{net::IpAddr, time::Duration};

    use rand::random;
    use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, Pinger, ICMP};

    use super::{do_agg, PingAddr, PingError, PingOptions, PingOutput};

    pub async fn ping(ipaddr: IpAddr, opts: PingOptions) -> Result<PingOutput, PingError> {
        let PingOptions {
            times,
            timeout,
            all_success,
            duration_agg,
        } = opts;

        let mut durations = Vec::new();

        let client = match ipaddr {
            IpAddr::V4(_) => Client::new(&Config::default()),
            IpAddr::V6(_) => Client::new(&Config::builder().kind(ICMP::V6).build()),
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

mod tcp_ping {
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
                .unwrap_or_else(|_| Err(PingError::Timeout));

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
    fn test_parse_ping_target() {
        let a = PingAddr::from_str("127.0.0.1").unwrap();
        assert!(matches!(a, PingAddr::Icmp(ip) if ip == "127.0.0.1".parse::<IpAddr>().unwrap() ));

        let b = PingAddr::from_str("icmp://127.0.0.1").unwrap();
        assert!(matches!(b, PingAddr::Icmp(ip) if ip == "127.0.0.1".parse::<IpAddr>().unwrap() ));

        let c = PingAddr::from_str("tcp://223.5.5.5:80").unwrap();
        assert!(
            matches!(c, PingAddr::Tcp(ip) if ip == "223.5.5.5:80".parse::<SocketAddr>().unwrap() )
        );

        let d = PingAddr::from_str("tcp://223.5.5.5");
        assert!(d.is_err());

        let a = PingAddr::from_str("::1").unwrap();
        assert!(matches!(a, PingAddr::Icmp(ip) if ip == "::1".parse::<IpAddr>().unwrap() ));

        let b = PingAddr::from_str("icmp://::1").unwrap();
        assert!(matches!(b, PingAddr::Icmp(ip) if ip == "::1".parse::<IpAddr>().unwrap() ));

        let c = PingAddr::from_str("tcp://[fe80::ec37:e7ff:fe56:bba7]:80").unwrap();
        assert!(
            matches!(c, PingAddr::Tcp(ip) if ip == "[fe80::ec37:e7ff:fe56:bba7]:80".parse::<SocketAddr>().unwrap() )
        );
    }

    #[test]
    fn test_ping_simple() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let results = ping(
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
}
