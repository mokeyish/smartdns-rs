use std::net::{IpAddr, SocketAddr};

use crate::infra::ping::PingAddr;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum SpeedCheckMode {
    None,
    Ping,
    Tcp(u16),
    Http(u16),
    Https(u16),
}

impl SpeedCheckMode {
    pub fn is_none(&self) -> bool {
        matches!(self, SpeedCheckMode::None)
    }

    pub fn to_ping_addr(self, ip_addr: IpAddr) -> Option<PingAddr> {
        use SpeedCheckMode::*;
        Some(match self {
            None => return Default::default(),
            Ping => PingAddr::Icmp(ip_addr),
            Tcp(port) => PingAddr::Tcp(SocketAddr::new(ip_addr, port)),
            Http(port) => PingAddr::Http(SocketAddr::new(ip_addr, port)),
            Https(port) => PingAddr::Https(SocketAddr::new(ip_addr, port)),
        })
    }

    pub fn to_ping_addrs(self, ip_addrs: &[IpAddr]) -> Vec<PingAddr> {
        ip_addrs
            .iter()
            .flat_map(|ip| self.to_ping_addr(*ip))
            .collect()
    }
}

impl std::fmt::Debug for SpeedCheckMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use SpeedCheckMode::*;
        match self {
            None => write!(f, "None"),
            Ping => write!(f, "ICMP"),
            Tcp(port) => write!(f, "TCP:{port}"),
            Http(port) => {
                if *port == 80 {
                    write!(f, "HTTP")
                } else {
                    write!(f, "HTTP:{port}")
                }
            }
            Https(port) => {
                if *port == 443 {
                    write!(f, "HTTPS")
                } else {
                    write!(f, "HTTPS:{port}")
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SpeedCheckModeList(pub Vec<SpeedCheckMode>);

impl SpeedCheckModeList {
    pub fn push(&mut self, mode: SpeedCheckMode) -> Option<SpeedCheckMode> {
        if self.0.iter().all(|m| m != &mode) {
            self.0.push(mode);
            None
        } else {
            Some(mode)
        }
    }
}

impl From<Vec<SpeedCheckMode>> for SpeedCheckModeList {
    fn from(value: Vec<SpeedCheckMode>) -> Self {
        let mut lst = Self(Vec::with_capacity(value.len()));
        for mode in value {
            lst.push(mode);
        }
        lst
    }
}

impl std::fmt::Debug for SpeedCheckModeList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, m) in self.0.iter().enumerate() {
            let last = i == self.len() - 1;
            write!(f, "{:?}{}", m, if !last { ", " } else { "" })?;
        }
        Ok(())
    }
}

impl std::ops::Deref for SpeedCheckModeList {
    type Target = Vec<SpeedCheckMode>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SpeedCheckModeList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::default::Default for SpeedCheckModeList {
    fn default() -> Self {
        Self(vec![
            SpeedCheckMode::Ping,
            SpeedCheckMode::Http(80),
            SpeedCheckMode::Https(443),
        ])
    }
}
