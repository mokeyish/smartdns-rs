use crate::dns_conf::{DomainAddress, DomainOrDomainSet, SmartDnsConfig};
use std::collections::HashMap;
use std::fmt::Debug;
use trust_dns_client::rr::LowerName;

#[derive(Debug, Default)]
pub struct DomainMatcher<T: Debug>(HashMap<LowerName, T>);

impl<T: Debug> DomainMatcher<T> {
    pub fn find(&self, domain: &LowerName) -> Option<&T> {
        let mut domain = domain.to_owned();

        loop {
            if let Some(v) = self.0.get(&domain) {
                return Some(v);
            }
            if domain.is_root() {
                break;
            }

            domain = domain.base_name();
        }

        None
    }
}

pub type DomainAddressMatcher = DomainMatcher<DomainAddress>;

impl DomainMatcher<DomainAddress> {
    pub fn create(cfg: &SmartDnsConfig) -> DomainMatcher<DomainAddress> {
        let mut keys = vec![];
        let mut values = vec![];

        for rule in cfg.address_rules.iter() {
            match &rule.domain {
                DomainOrDomainSet::Domain(domain) => {
                    keys.push(domain.to_owned());
                    values.push(rule.address);
                }
                DomainOrDomainSet::DomainSet(set_name) => {
                    if let Some(set) = cfg.domain_sets.get(set_name) {
                        for domain in set.iter() {
                            keys.push(domain.to_owned());
                            values.push(rule.address);
                        }
                    }
                }
            }
        }

        DomainMatcher(create_map(keys, values))
    }
}

pub type DomainNameServerGroupMatcher = DomainMatcher<String>;

impl DomainMatcher<String> {
    pub fn create(cfg: &SmartDnsConfig) -> DomainMatcher<String> {
        let mut keys = vec![];
        let mut values = vec![];

        for rule in cfg.forward_rules.iter() {
            match &rule.domain {
                DomainOrDomainSet::Domain(domain) => {
                    keys.push(domain.to_owned());
                    values.push(rule.server_group.to_owned());
                }
                DomainOrDomainSet::DomainSet(set_name) => {
                    if let Some(set) = cfg.domain_sets.get(set_name) {
                        for domain in set.iter() {
                            keys.push(domain.to_owned());
                            values.push(rule.server_group.to_owned());
                        }
                    }
                }
            }
        }
        DomainMatcher(create_map(keys, values))
    }
}

fn create_map<K: std::hash::Hash + std::cmp::Eq, V>(keys: Vec<K>, values: Vec<V>) -> HashMap<K, V> {
    let mut map = HashMap::new();
    for (k, v) in keys.into_iter().zip(values) {
        map.insert(k, v);
    }
    map
}
