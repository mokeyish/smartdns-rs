use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{IpAdd, IpNet, IpSub, Ipv4Net, Ipv6Net};
use rangemap::{RangeInclusiveMap, StepLite};

pub type IpSet = IpMap<()>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpMap<T: Eq + Clone> {
    v4: RangeInclusiveMap<Key<Ipv4Addr>, T>,
    v6: RangeInclusiveMap<Key<Ipv6Addr>, T>,
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord)]
struct Key<T>(T);

impl StepLite for Key<Ipv4Addr> {
    fn add_one(&self) -> Self {
        Self(self.0.saturating_add(1))
    }

    fn sub_one(&self) -> Self {
        Self(self.0.saturating_sub(1))
    }
}

impl StepLite for Key<Ipv6Addr> {
    fn add_one(&self) -> Self {
        Self(self.0.saturating_add(1))
    }

    fn sub_one(&self) -> Self {
        Self(self.0.saturating_sub(1))
    }
}

impl IpSet {
    pub fn new(nets: impl IntoIterator<Item = IpNet>) -> Self {
        Self::from_iter(nets.into_iter().map(|v| (v, ())))
    }
}

impl<T: Eq + Clone> IpMap<T> {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn get<K>(&self, other: &K) -> Option<&T>
    where
        Self: IpIndexGet<T, K>,
    {
        IpIndex::get(self, other)
    }

    pub fn contains<K>(&self, other: &K) -> bool
    where
        Self: IpIndex<T, K>,
    {
        IpIndex::contains(self, other)
    }

    pub fn overlap<K>(&self, other: &K) -> bool
    where
        Self: IpIndex<T, K>,
    {
        IpIndex::overlap(self, other)
    }

    pub fn insert<K>(&mut self, other: K, value: T)
    where
        Self: IpIndex<T, K>,
    {
        IpIndex::insert(self, other, value);
    }
}

impl<T: Eq + Clone> Default for IpMap<T> {
    fn default() -> Self {
        Self {
            v4: RangeInclusiveMap::new(),
            v6: RangeInclusiveMap::new(),
        }
    }
}

impl<T: Eq + Clone, N> Extend<(N, T)> for IpMap<T>
where
    Self: IpIndex<T, N>,
{
    fn extend<I: IntoIterator<Item = (N, T)>>(&mut self, iter: I) {
        iter.into_iter().for_each(|(n, v)| self.insert(n, v));
    }
}

impl<T: Eq + Clone, N> FromIterator<(N, T)> for IpMap<T>
where
    Self: IpIndex<T, N>,
{
    fn from_iter<I: IntoIterator<Item = (N, T)>>(iter: I) -> Self {
        let mut map = IpMap::default();
        map.extend(iter);
        map
    }
}

pub trait IpIndex<T, N> {
    fn get(&self, _other: &N) -> Option<&T> {
        unimplemented!()
    }

    fn contains(&self, other: &N) -> bool {
        self.get(other).is_some()
    }

    fn overlap(&self, other: &N) -> bool {
        self.get(other).is_some()
    }

    fn insert(&mut self, other: N, value: T);
}

pub trait IpIndexGet<T, N>: IpIndex<T, N> {}

impl<T: Eq + Clone> IpIndexGet<T, IpAddr> for IpMap<T> {}
impl<T: Eq + Clone> IpIndex<T, IpAddr> for IpMap<T> {
    fn get(&self, other: &IpAddr) -> Option<&T> {
        match other {
            IpAddr::V4(addr) => self.get(addr),
            IpAddr::V6(addr) => self.get(addr),
        }
    }

    fn insert(&mut self, other: IpAddr, value: T) {
        match other {
            IpAddr::V4(addr) => self.insert(addr, value),
            IpAddr::V6(addr) => self.insert(addr, value),
        }
    }
}

impl<T: Eq + Clone> IpIndexGet<T, Ipv4Addr> for IpMap<T> {}
impl<T: Eq + Clone> IpIndex<T, Ipv4Addr> for IpMap<T> {
    fn get(&self, other: &Ipv4Addr) -> Option<&T> {
        self.v4.get(&Key(*other))
    }

    fn insert(&mut self, other: Ipv4Addr, value: T) {
        self.v4.insert(Key(other)..=Key(other), value);
    }
}

impl<T: Eq + Clone> IpIndexGet<T, Ipv6Addr> for IpMap<T> {}
impl<T: Eq + Clone> IpIndex<T, Ipv6Addr> for IpMap<T> {
    fn get(&self, other: &Ipv6Addr) -> Option<&T> {
        self.v6.get(&Key(*other))
    }

    fn insert(&mut self, other: Ipv6Addr, value: T) {
        self.v6.insert(Key(other)..=Key(other), value);
    }
}

impl<T: Eq + Clone> IpIndex<T, IpNet> for IpMap<T> {
    fn contains(&self, other: &IpNet) -> bool {
        match other {
            IpNet::V4(net) => self.contains(net),
            IpNet::V6(net) => self.contains(net),
        }
    }

    fn overlap(&self, other: &IpNet) -> bool {
        match other {
            IpNet::V4(net) => self.overlap(net),
            IpNet::V6(net) => self.overlap(net),
        }
    }

    fn insert(&mut self, other: IpNet, value: T) {
        match other {
            IpNet::V4(net) => self.insert(net, value),
            IpNet::V6(net) => self.insert(net, value),
        }
    }
}

impl<T: Eq + Clone> IpIndex<T, Ipv4Net> for IpMap<T> {
    fn contains(&self, other: &Ipv4Net) -> bool {
        let r = Key(other.network())..=Key(other.broadcast());
        self.v4.gaps(&r).next().is_none()
    }

    fn overlap(&self, other: &Ipv4Net) -> bool {
        let r = Key(other.network())..=Key(other.broadcast());
        self.v4.overlaps(&r)
    }

    fn insert(&mut self, other: Ipv4Net, value: T) {
        let r = Key(other.network())..=Key(other.broadcast());
        self.v4.insert(r, value);
    }
}

impl<T: Eq + Clone> IpIndex<T, Ipv6Net> for IpMap<T> {
    fn contains(&self, other: &Ipv6Net) -> bool {
        let r = Key(other.network())..=Key(other.broadcast());
        self.v6.gaps(&r).next().is_none()
    }

    fn overlap(&self, other: &Ipv6Net) -> bool {
        let r = Key(other.network())..=Key(other.broadcast());
        self.v6.overlaps(&r)
    }

    fn insert(&mut self, other: Ipv6Net, value: T) {
        let r = Key(other.network())..=Key(other.broadcast());
        self.v6.insert(r, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::IpAddr, str::FromStr};

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn test_ipset() {
        let ipnet_a = IpNet::from_str("10.10.10.0/24").unwrap();
        let ipnet_b = IpNet::from_str("10.10.20.0/24").unwrap();

        assert!(ipnet_a.contains(&addr("10.10.10.20")));
        assert!(ipnet_b.contains(&addr("10.10.20.20")));

        let ipset = IpSet::new([ipnet_a, ipnet_b]);

        assert!(ipset.contains(&addr("10.10.10.20")));
        assert!(ipset.contains(&net("10.10.10.0/24")));
        assert!(!ipset.contains(&addr("10.10.11.20")));
        assert!(!ipset.contains(&net("10.10.10.0/16")));
        assert!(ipset.contains(&addr("10.10.20.20")));

        assert!(ipset.overlap(&addr("10.10.10.20")));
        assert!(ipset.overlap(&net("10.10.10.0/24")));
        assert!(!ipset.overlap(&addr("10.10.11.20")));
        assert!(ipset.overlap(&net("10.10.10.0/16")));
        assert!(!ipset.overlap(&net("10.10.11.0/24")));
    }

    #[test]
    fn test_ipmap() {
        let ipmap = IpMap::from_iter([
            (IpNet::from_str("10.10.10.0/24").unwrap(), 0),
            (IpNet::from_str("10.10.20.0/24").unwrap(), 1),
            (IpNet::from_str("10.10.11.0/24").unwrap(), 2),
            (IpNet::from_str("10.10.11.0/32").unwrap(), 3),
        ]);

        assert!(ipmap.contains(&net("10.10.10.0/23")));
        assert!(!ipmap.contains(&net("10.10.10.0/22")));

        assert!(ipmap.overlap(&net("10.10.10.0/16")));
        assert!(!ipmap.overlap(&net("10.10.12.0/24")));

        assert_eq!(ipmap.get(&addr("10.10.10.10")), Some(&0));
        assert_eq!(ipmap.get(&addr("10.10.11.0")), Some(&3));
        assert_eq!(ipmap.get(&addr("10.10.11.10")), Some(&2));
        assert_eq!(ipmap.get(&addr("10.10.12.0")), None);
        assert_eq!(ipmap.get(&addr("10.10.20.0")), Some(&1));
    }
}
