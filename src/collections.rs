use std::{collections::HashMap, fmt::Debug};

use crate::libdns::proto::rr::Name;

#[derive(Debug)]
pub struct DomainMap<T: Debug>(HashMap<Name, T>);

impl<T: Debug> DomainMap<T> {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn find(&self, domain: &Name) -> Option<&T> {
        let mut domain = domain.to_owned();

        loop {
            if let Some(v) = self.0.get(&domain) {
                return Some(v);
            }

            if !domain.is_fqdn() {
                domain.set_fqdn(true);
                continue;
            }

            if domain.is_root() {
                break;
            }

            domain = domain.base_name();
        }

        None
    }

    #[inline]
    pub fn contains(&self, domain: &Name) -> bool {
        self.find(domain).is_some()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline]
    pub fn insert(&mut self, mut domain: Name, value: T) -> Option<T> {
        domain.set_fqdn(true);
        self.0.insert(domain, value)
    }

    #[inline]
    pub fn remove(&mut self, domain: &Name) -> Option<T> {
        self.0.remove(domain)
    }
}

impl<T: Debug> Default for DomainMap<T> {
    #[inline]
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<T: Debug> From<HashMap<Name, T>> for DomainMap<T> {
    #[inline]
    fn from(value: HashMap<Name, T>) -> Self {
        Self(value)
    }
}

#[derive(Default)]
pub struct DomainSet(DomainMap<()>);

impl DomainSet {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn contains(&self, domain: &Name) -> bool {
        self.0.contains(domain)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn insert(&mut self, domain: Name) -> bool {
        self.0.insert(domain, ()).is_none()
    }

    #[inline]
    pub fn remove(&mut self, domain: &Name) -> bool {
        self.0.remove(domain).is_some()
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_set_contains() {
        let mut set = DomainSet::new();

        set.insert(Name::from_str("example.com").unwrap());
        assert!(set.contains(&Name::from_str("example.com").unwrap()));
        assert!(set.contains(&Name::from_str("www.example.com").unwrap()));
    }
}
