use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IpSet {
    v4: Vec<Ipv4Net>, // sorted
    v6: Vec<Ipv6Net>, // sorted
}

impl IpSet {
    pub fn new(nets: impl IntoIterator<Item = IpNet>) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        nets.into_iter().for_each(|n| match n {
            IpNet::V4(x) => v4.push(x),
            IpNet::V6(x) => v6.push(x),
        });

        v4 = Ipv4Net::aggregate(&v4);
        v6 = Ipv6Net::aggregate(&v6);
        v4.sort_unstable();
        v6.sort_unstable();

        Self { v4, v6 }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    fn search_v4(&self, addr: Ipv4Addr) -> Option<&Ipv4Net> {
        let idx = self.v4.partition_point(|x| x.broadcast() < addr);
        self.v4.get(idx)
    }

    fn search_v6(&self, addr: Ipv6Addr) -> Option<&Ipv6Net> {
        let idx = self.v6.partition_point(|x| x.broadcast() < addr);
        self.v6.get(idx)
    }

    pub fn contains<T>(&self, other: T) -> bool
    where
        Self: Contains<T>,
    {
        self.containment(other) == Some(true)
    }

    pub fn overlap<T>(&self, other: T) -> bool
    where
        Self: Contains<T>,
    {
        self.containment(other).is_some()
    }
}

impl<T: AsRef<[IpNet]>> From<T> for IpSet {
    #[inline]
    fn from(value: T) -> Self {
        Self::new(value.as_ref().iter().copied())
    }
}

pub trait Contains<T> {
    /// contains => Some(true)
    /// overlap => Some(_)
    /// else => None
    fn containment(&self, other: T) -> Option<bool>;
}

impl Contains<&IpNet> for IpSet {
    fn containment(&self, other: &IpNet) -> Option<bool> {
        match other {
            IpNet::V4(net) => self.containment(net),
            IpNet::V6(net) => self.containment(net),
        }
    }
}

impl Contains<&Ipv4Net> for IpSet {
    fn containment(&self, other: &Ipv4Net) -> Option<bool> {
        let net = self.search_v4(other.network())?;
        net.contains(other)
            .then_some(true)
            .or_else(|| other.contains(net).then_some(false))
    }
}

impl Contains<&Ipv6Net> for IpSet {
    fn containment(&self, other: &Ipv6Net) -> Option<bool> {
        let net = self.search_v6(other.network())?;
        net.contains(other)
            .then_some(true)
            .or_else(|| other.contains(net).then_some(false))
    }
}

impl Contains<&IpAddr> for IpSet {
    fn containment(&self, other: &IpAddr) -> Option<bool> {
        match other {
            IpAddr::V4(addr) => self.containment(addr),
            IpAddr::V6(addr) => self.containment(addr),
        }
    }
}

impl Contains<&Ipv4Addr> for IpSet {
    fn containment(&self, other: &Ipv4Addr) -> Option<bool> {
        self.search_v4(*other)?.contains(other).then_some(true)
    }
}

impl Contains<&Ipv6Addr> for IpSet {
    fn containment(&self, other: &Ipv6Addr) -> Option<bool> {
        self.search_v6(*other)?.contains(other).then_some(true)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use super::*;

    #[test]
    fn test_ipset() {
        let ipnet_a = IpNet::from_str("10.10.10.0/24").unwrap();
        let ipnet_b = IpNet::from_str("10.10.20.0/24").unwrap();

        assert!(ipnet_a.contains(&"10.10.10.20".parse::<IpAddr>().unwrap()));
        assert!(ipnet_b.contains(&"10.10.20.20".parse::<IpAddr>().unwrap()));

        let ipset = IpSet::new([ipnet_a, ipnet_b]);

        assert!(ipset.contains(&"10.10.10.20".parse::<IpAddr>().unwrap()));
        assert!(ipset.contains(&"10.10.10.0/24".parse::<IpNet>().unwrap()));
        assert!(!ipset.contains(&"10.10.11.20".parse::<IpAddr>().unwrap()));
        assert!(!ipset.contains(&"10.10.10.0/16".parse::<IpNet>().unwrap()));
        assert!(ipset.contains(&"10.10.20.20".parse::<IpAddr>().unwrap()));

        assert!(ipset.overlap(&"10.10.10.20".parse::<IpAddr>().unwrap()));
        assert!(ipset.overlap(&"10.10.10.0/24".parse::<IpNet>().unwrap()));
        assert!(!ipset.overlap(&"10.10.11.20".parse::<IpAddr>().unwrap()));
        assert!(ipset.overlap(&"10.10.10.0/16".parse::<IpNet>().unwrap()));
        assert!(!ipset.overlap(&"10.10.11.0/24".parse::<IpNet>().unwrap()));
    }
}
