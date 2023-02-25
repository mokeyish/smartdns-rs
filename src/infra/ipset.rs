use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{Deref, DerefMut},
};

use ipnet::IpNet;

#[derive(Debug, Default, Clone)]
pub struct IpSet(Vec<IpNet>);

impl IpSet {
    #[inline]
    pub fn new(nets: Vec<IpNet>) -> Self {
        Self(IpNet::aggregate(&nets))
    }

    pub fn contains<T>(&self, other: T) -> bool
    where
        Self: Contains<T>,
    {
        Contains::contains(self, other)
    }

    pub fn compact(&self) -> Self {
        Self(IpNet::aggregate(&self.0))
    }
}

impl std::ops::Add for IpSet {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut items = self.0;
        items.extend(rhs.0.iter().cloned());
        items.into()
    }
}

impl std::ops::Add<IpNet> for &IpSet {
    type Output = IpSet;

    fn add(self, rhs: IpNet) -> Self::Output {
        let mut items = self.0.clone();
        items.push(rhs);
        items.into()
    }
}

pub trait ToIpSet {
    fn to_ip_set(self) -> IpSet;
}

impl<T: Into<IpSet>> ToIpSet for T {
    fn to_ip_set(self) -> IpSet {
        self.into()
    }
}

impl From<Vec<IpNet>> for IpSet {
    #[inline]
    fn from(value: Vec<IpNet>) -> Self {
        Self::new(value)
    }
}

impl From<&[IpNet]> for IpSet {
    fn from(value: &[IpNet]) -> Self {
        Self::new(value.to_vec())
    }
}

impl Deref for IpSet {
    type Target = Vec<IpNet>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for IpSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub trait Contains<T> {
    fn contains(&self, other: T) -> bool;
}

impl<'a> Contains<&'a IpNet> for IpSet {
    fn contains(&self, other: &IpNet) -> bool {
        self.0.iter().any(|net| net.contains(other))
    }
}

impl<'a> Contains<&'a IpAddr> for IpSet {
    fn contains(&self, other: &IpAddr) -> bool {
        self.0.iter().any(|net| net.contains(other))
    }
}

impl<'a> Contains<&'a Ipv4Addr> for IpSet {
    fn contains(&self, other: &Ipv4Addr) -> bool {
        self.contains(&IpAddr::V4(*other))
    }
}

impl<'a> Contains<&'a Ipv6Addr> for IpSet {
    fn contains(&self, other: &Ipv6Addr) -> bool {
        self.contains(&IpAddr::V6(*other))
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

        let ipset = [ipnet_a, ipnet_b].to_ip_set();

        assert!(ipset.contains(&"10.10.10.20".parse::<IpAddr>().unwrap()));
        assert!(!ipset.contains(&"10.10.11.20".parse::<IpAddr>().unwrap()));
        assert!(ipset.contains(&"10.10.20.20".parse::<IpAddr>().unwrap()));
    }
}
