use std::{
    fmt::Display,
    io,
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};
use thiserror::Error;

pub async fn ping(dests: &[PingAddr], times: u16, timeout: Option<Duration>) -> Vec<PingOutput> {
    let timeout = timeout.unwrap_or(Duration::from_secs(5));

    let mut outs = Vec::new();

    for (seq, dest) in dests.iter().enumerate() {
        if let Ok(ping_outputs) = match dest {
            PingAddr::Icmp(addr) => icmp_ping::ping(*addr, times, timeout).await,
            PingAddr::Tcp(addr) => tcp_ping::ping(*addr, times, timeout).await,
        } {
            if let Some(mut output) = ping_outputs.as_slice().get_avg(seq as u16) {
                output.seq = seq as u16;
                outs.push(output);
            }
        }
    }

    outs
}

#[derive(Debug, Clone)]
pub enum PingAddr {
    Icmp(IpAddr),
    Tcp(SocketAddr),
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
    duration: Result<Duration, PingError>,
    destination: PingAddr,
}

impl PingOutput {
    #[inline]
    pub fn seq(&self) -> u16 {
        self.seq
    }

    #[inline]
    pub fn duration(&self) -> &Result<Duration, PingError> {
        &self.duration
    }

    #[inline]
    pub fn is_timeout(&self) -> bool {
        matches!(self.duration, Err(PingError::Timeout))
    }

    #[inline]
    pub fn has_err(&self) -> bool {
        self.duration.is_err()
    }
}

pub trait PingOutputIter {
    fn get_avg(&self, seq: u16) -> Option<PingOutput>;
}

impl PingOutputIter for &[PingOutput] {
    fn get_avg(&self, seq: u16) -> Option<PingOutput> {
        if self.is_empty() {
            return None;
        }

        let destination = self.iter().next().unwrap().destination.clone();

        let mut total = Duration::default();

        for output in self.iter() {
            if output.has_err() {
                let duration = output.duration.clone();
                return Some(PingOutput {
                    seq,
                    duration,
                    destination,
                });
            }
            total += *output.duration.as_ref().unwrap();
        }

        let duration = Ok(total / (self.len() as u32));

        Some(PingOutput {
            seq,
            duration,
            destination,
        })
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
        if s.starts_with("tcp://") {
            let sock_addr = SocketAddr::from_str(&s[6..])?;
            Ok(Self::Tcp(sock_addr))
        } else {
            let s = if s.starts_with("icmp://") { &s[7..] } else { s };
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
}

impl Clone for PingError {
    fn clone(&self) -> Self {
        match self {
            Self::PingTargetParseError => Self::PingTargetParseError,
            Self::AddrParseError(arg0) => Self::AddrParseError(arg0.clone()),
            Self::Timeout => Self::Timeout,
            Self::IoError(err) => Self::IoError(err.kind().into()),
            Self::SurgeError => Self::SurgeError,
        }
    }
}

#[cfg(feature = "disable_icmp_ping")]
mod icmp_ping {
    //! ignore, Github actions not surpport icmp ping.

    use std::{net::IpAddr, time::Duration};

    use super::{PingError, PingOutput};
    pub async fn ping(
        ipaddr: IpAddr,
        times: u16,
        _timeout: Duration,
    ) -> Result<Vec<PingOutput>, PingError> {
        Ok((0..times)
            .into_iter()
            .map(|seq| PingOutput {
                seq,
                duration: Ok(Duration::from_millis(1)),
                destination: super::PingAddr::Icmp(ipaddr),
            })
            .collect())
    }
}

#[cfg(not(feature = "disable_icmp_ping"))]
mod icmp_ping {
    use std::{net::IpAddr, time::Duration};

    use rand::random;
    use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, Pinger, ICMP};

    use super::{PingError, PingOutput};

    pub async fn ping(
        ipaddr: IpAddr,
        times: u16,
        timeout: Duration,
    ) -> Result<Vec<PingOutput>, PingError> {
        let mut outs = Vec::new();

        let client = match ipaddr {
            IpAddr::V4(_) => Client::new(&Config::default()),
            IpAddr::V6(_) => Client::new(&Config::builder().kind(ICMP::V6).build()),
        }?;

        let mut pinger = client.pinger(ipaddr, PingIdentifier(random())).await;
        pinger.timeout(timeout);

        for seq in 0..times {
            let duration = ping_icmp(seq, &mut pinger).await;
            outs.push(PingOutput {
                seq,
                duration,
                destination: super::PingAddr::Icmp(ipaddr),
            });

            if outs.last().unwrap().has_err() {
                break;
            }
        }
        Ok(outs)
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

    use super::{PingError, PingOutput};

    #[inline]
    pub async fn ping(
        sock_addr: SocketAddr,
        times: u16,
        timeout: Duration,
    ) -> Result<Vec<PingOutput>, PingError> {
        let mut outs = Vec::new();

        for seq in 0..times {
            let duration = ping_tcp(sock_addr)
                .timeout(timeout)
                .await
                .unwrap_or_else(|_| Err(PingError::Timeout));
            outs.push(PingOutput {
                seq,
                duration,
                destination: super::PingAddr::Tcp(sock_addr),
            });
            if outs.last().unwrap().has_err() {
                break;
            }
        }

        Ok(outs)
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
                10,
                Some(Duration::from_secs(3)),
            )
            .await;

            assert!(results.last().unwrap().is_timeout());

            for item in results {
                println!("Ping {:?}", item);
            }
        })
    }
}
