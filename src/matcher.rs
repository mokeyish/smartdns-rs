use crate::dns_conf::{DomainAddress, DomainId, DomainRule, SmartDnsConfig};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use trust_dns_proto::rr::Name;

#[derive(Debug, Default)]
pub struct DomainMatcher<T: Debug>(HashMap<Name, T>);

impl<T: Debug> DomainMatcher<T> {
    pub fn find(&self, domain: &Name) -> Option<&T> {
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

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

pub type DomainAddressMatcher = DomainMatcher<DomainAddress>;

impl DomainAddressMatcher {
    pub fn create(cfg: &SmartDnsConfig) -> DomainMatcher<DomainAddress> {
        let mut keys = vec![];
        let mut values = vec![];

        for rule in cfg.address_rules.iter() {
            match &rule.domain {
                DomainId::Domain(domain) => {
                    keys.push(domain.to_owned());
                    values.push(rule.address);
                }
                DomainId::DomainSet(set_name) => {
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

/// find the name of nameserver group by domain name.
pub type DomainNameServerGroupMatcher = DomainMatcher<String>;

impl DomainNameServerGroupMatcher {
    pub fn create(cfg: &SmartDnsConfig) -> Self {
        let mut keys = vec![];
        let mut values = vec![];

        for rule in cfg.forward_rules.iter() {
            match &rule.domain {
                DomainId::Domain(domain) => {
                    keys.push(domain.to_owned());
                    values.push(rule.server_group.to_owned());
                }
                DomainId::DomainSet(set_name) => {
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

/// find domain rule by domain name.
pub type DomainRuleMatcher = DomainMatcher<Arc<DomainRule>>;

impl DomainRuleMatcher {
    pub fn create(cfg: &SmartDnsConfig) -> Self {
        let mut keys = vec![];
        let mut values = vec![];

        for rule in cfg.domain_rules.iter() {
            let rule = Arc::new(rule.clone());
            match &rule.domain {
                DomainId::Domain(domain) => {
                    keys.push(domain.to_owned());
                    values.push(rule.clone());
                }
                DomainId::DomainSet(set_name) => {
                    if let Some(set) = cfg.domain_sets.get(set_name) {
                        for domain in set.iter() {
                            keys.push(domain.to_owned());
                            values.push(rule.clone());
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
