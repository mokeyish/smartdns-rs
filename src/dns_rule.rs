use std::{collections::HashMap, ops::Deref, sync::Arc};

use crate::config::WildcardName;

use crate::{
    collections::DomainMap,
    config::{
        AddressRules, CNameRules, ConfigForDomain, ConfigForIP, Domain, DomainRule, DomainRules,
        DomainSets, ForwardRules, HttpsRecords, NFTsetConfig, SrvRecords,
    },
};

#[derive(Default)]
pub struct DomainRuleMap {
    rules: DomainMap<Arc<DomainRuleTreeNode>>,
}

impl DomainRuleMap {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        domain_rules: &DomainRules,
        address_rules: &AddressRules,
        forward_rules: &ForwardRules,
        domain_sets: &DomainSets,
        cnames: &CNameRules,
        srv_records: &SrvRecords,
        https_records: &HttpsRecords,
        nftsets: &Vec<ConfigForDomain<Vec<ConfigForIP<NFTsetConfig>>>>,
    ) -> Self {
        let expand_domain = |domain: &Domain| match &domain {
            Domain::Name(name) => {
                vec![name.clone()]
            }
            Domain::Set(s) => domain_sets
                .get(s)
                .map(|v| v.iter().map(|n| n.to_owned()).collect::<Vec<_>>())
                .unwrap_or_default(),
        };

        let mut name_rule_map = HashMap::<WildcardName, DomainRule>::new();

        // append domain_rules
        for rule in domain_rules {
            for name in expand_domain(&rule.domain) {
                // overide
                *(name_rule_map.entry(name).or_default()) += rule.config.clone();
            }
        }

        // append address rule
        for rule in address_rules.iter() {
            for name in expand_domain(&rule.domain) {
                (name_rule_map.entry(name).or_default()).address = Some(rule.address);
            }
        }

        // append forward rule
        for rule in forward_rules.iter() {
            for name in expand_domain(&rule.domain) {
                name_rule_map.entry(name).or_default().nameserver = Some(rule.nameserver.clone())
            }
        }

        // set cname
        for rule in cnames {
            for name in expand_domain(&rule.domain) {
                name_rule_map.entry(name).or_default().cname = Some(rule.config.clone())
            }
        }

        // set srv
        for rule in srv_records {
            for name in expand_domain(&rule.domain) {
                name_rule_map.entry(name).or_default().srv = Some(rule.config.clone())
            }
        }

        // set https
        for rule in https_records {
            for name in expand_domain(&rule.domain) {
                name_rule_map.entry(name).or_default().https = Some(rule.config.clone())
            }
        }

        for rule in nftsets {
            for name in expand_domain(&rule.domain) {
                name_rule_map.entry(name).or_default().nftset = Some(rule.config.clone());
            }
        }

        let mut rule_items = name_rule_map.into_iter().collect::<Vec<_>>();
        rule_items.sort_by(|(a, ..), (b, ..)| a.cmp(b));

        let mut rules = DomainMap::default();
        let mut rule_pool = HashMap::<DomainRule, Arc<DomainRule>>::new();

        for (name, v) in rule_items {
            let rule = rule_pool
                .entry(v.clone())
                .or_insert_with(move || Arc::new(v))
                .to_owned();

            let zone = rules.find(&name.base_name()).cloned();

            let node = DomainRuleTreeNode { name, rule, zone };
            rules.insert(node.name.clone(), node.into());
        }

        Self { rules }
    }
}

impl Deref for DomainRuleMap {
    type Target = DomainMap<Arc<DomainRuleTreeNode>>;

    fn deref(&self) -> &Self::Target {
        &self.rules
    }
}

#[derive(Debug)]
pub struct DomainRuleTreeNode {
    name: WildcardName,                    // www.example.com
    rule: Arc<DomainRule>,                 // www.example.com
    zone: Option<Arc<DomainRuleTreeNode>>, // example.com
}

impl DomainRuleTreeNode {
    pub fn name(&self) -> &WildcardName {
        &self.name
    }

    pub fn zone(&self) -> Option<&Arc<DomainRuleTreeNode>> {
        self.zone.as_ref()
    }
}

pub trait DomainRuleGetter {
    fn get<T>(&self, f: impl Fn(&DomainRuleTreeNode) -> Option<T>) -> Option<T>;

    fn get_ref<T>(&self, f: impl Fn(&DomainRuleTreeNode) -> Option<&T>) -> Option<&T>;
}

impl DomainRuleGetter for DomainRuleTreeNode {
    fn get<T>(&self, f: impl Fn(&DomainRuleTreeNode) -> Option<T>) -> Option<T> {
        f(self).or_else(|| self.zone().and_then(|z| f(z)))
    }

    fn get_ref<T>(&self, f: impl Fn(&DomainRuleTreeNode) -> Option<&T>) -> Option<&T> {
        f(self).or_else(|| self.zone().and_then(|z| f(z)))
    }
}

impl<N: AsRef<DomainRuleTreeNode>> DomainRuleGetter for N {
    fn get<T>(&self, f: impl Fn(&DomainRuleTreeNode) -> Option<T>) -> Option<T> {
        self.as_ref().get(f)
    }

    fn get_ref<T>(&self, f: impl Fn(&DomainRuleTreeNode) -> Option<&T>) -> Option<&T> {
        self.as_ref().get_ref(f)
    }
}

impl DomainRuleGetter for Option<Arc<DomainRuleTreeNode>> {
    fn get<T>(&self, f: impl Fn(&DomainRuleTreeNode) -> Option<T>) -> Option<T> {
        self.as_deref().and_then(f)
    }

    fn get_ref<T>(&self, f: impl Fn(&DomainRuleTreeNode) -> Option<&T>) -> Option<&T> {
        self.as_deref().and_then(f)
    }
}

impl Deref for DomainRuleTreeNode {
    type Target = DomainRule;

    fn deref(&self) -> &Self::Target {
        self.rule.as_ref()
    }
}

#[cfg(feature = "experimental-trie")]
impl From<Name> for crate::collections::TrieKey<Name> {
    fn from(value: Name) -> Self {
        let mut keys = vec![];
        let labels = value.into_iter().collect::<Vec<_>>();
        for i in 0..labels.len() {
            keys.push(Name::from_labels(labels[i..].to_vec()).unwrap())
        }
        keys.push(Name::root());
        Self(keys)
    }
}

#[cfg(feature = "experimental-trie")]
impl From<&Name> for crate::collections::TrieKey<Name> {
    fn from(value: &Name) -> Self {
        let mut keys = vec![];
        let labels = value.into_iter().collect::<Vec<_>>();
        for i in 0..labels.len() {
            keys.push(Name::from_labels(labels[i..].to_vec()).unwrap())
        }
        keys.push(Name::root());
        Self(keys)
    }
}

#[cfg(test)]
mod tests {

    use crate::config::{AddressRule, DomainAddress};
    use std::{net::Ipv4Addr, ptr};

    use super::*;

    #[test]
    fn test_zone_rule() {
        let map = DomainRuleMap::create(
            &Default::default(),
            &vec![
                AddressRule {
                    domain: "a.b.c.www.example.com".parse().unwrap(),
                    address: DomainAddress::IPv4(Ipv4Addr::LOCALHOST),
                },
                AddressRule {
                    domain: "www.example.com".parse().unwrap(),
                    address: DomainAddress::IPv4(Ipv4Addr::LOCALHOST),
                },
                AddressRule {
                    domain: "example.com".parse().unwrap(),
                    address: DomainAddress::IPv4(Ipv4Addr::LOCALHOST),
                },
            ],
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
        );

        let rule1 = map.find(&"z.a.b.c.www.example.com".parse().unwrap());
        assert!(rule1.is_some());
        assert_eq!(
            rule1.map(|o| o.name()),
            Some(&"a.b.c.www.example.com".parse().unwrap())
        );

        let rule2 = map.find(&"www.example.com".parse().unwrap());

        assert_eq!(
            rule2.map(|o| o.name()),
            Some(&"www.example.com".parse().unwrap())
        );

        assert!(ptr::eq(
            rule1.as_ref().unwrap().zone().unwrap().as_ref(),
            rule2.unwrap().as_ref()
        ))
    }
}
