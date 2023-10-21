use std::{collections::HashMap, ops::Deref, sync::Arc};

use crate::libdns::proto::rr::Name;

use crate::{
    collections::DomainMap,
    config::{Domain, DomainConfigItem, IpConfig, NftsetConfig},
    dns_conf::{
        AddressRules, CNameRules, DomainAddress, DomainRules, DomainSets, ForwardRules,
        SpeedCheckModeList,
    },
};

#[derive(Default)]
pub struct DomainRuleMap {
    rules: DomainMap<Arc<DomainRuleTreeNode>>,
}

impl DomainRuleMap {
    pub fn create(
        domain_rules: &DomainRules,
        address_rules: &AddressRules,
        forward_rules: &ForwardRules,
        domain_sets: &DomainSets,
        cnames: &CNameRules,
        nftsets: &Vec<DomainConfigItem<Vec<IpConfig<NftsetConfig>>>>,
    ) -> Self {
        let mut name_rule_map = HashMap::<Name, DomainRule>::new();

        // append domain_rules

        for rule in domain_rules {
            let names = match &rule.name {
                Domain::Name(name) => {
                    vec![name.clone()]
                }
                Domain::Set(s) => domain_sets
                    .get(s)
                    .map(|v| v.iter().map(|n| n.to_owned()).collect::<Vec<_>>())
                    .unwrap_or_default(),
            };

            for name in names {
                // overide
                *(name_rule_map.entry(name).or_default()) += rule.value.clone();
            }
        }

        // append address rule
        for rule in address_rules.iter() {
            let names = match &rule.name {
                Domain::Name(name) => {
                    vec![name.clone()]
                }
                Domain::Set(s) => domain_sets
                    .get(s)
                    .map(|v| v.iter().map(|n| n.to_owned()).collect::<Vec<_>>())
                    .unwrap_or_default(),
            };

            for name in names {
                name_rule_map.entry(name).or_default().address = Some(rule.value);
            }
        }

        // append forward rule
        for rule in forward_rules.iter() {
            let names = match &rule.domain {
                Domain::Name(name) => {
                    vec![name.clone()]
                }
                Domain::Set(s) => domain_sets
                    .get(s)
                    .map(|v| v.iter().map(|n| n.to_owned()).collect::<Vec<_>>())
                    .unwrap_or_default(),
            };

            for name in names {
                name_rule_map.entry(name).or_default().nameserver = Some(rule.nameserver.clone())
            }
        }

        // set cname
        for rule in cnames {
            let names = match &rule.name {
                Domain::Name(name) => {
                    vec![name.clone()]
                }
                Domain::Set(s) => domain_sets
                    .get(s)
                    .map(|v| v.iter().map(|n| n.to_owned()).collect::<Vec<_>>())
                    .unwrap_or_default(),
            };
            for name in names {
                name_rule_map.entry(name).or_default().cname = Some(rule.value.clone())
            }
        }

        for rule in nftsets {
            let names = match &rule.domain {
                Domain::Name(name) => {
                    vec![name.clone()]
                }
                Domain::Set(s) => domain_sets
                    .get(s)
                    .map(|v| v.iter().map(|n| n.to_owned()).collect::<Vec<_>>())
                    .unwrap_or_default(),
            };

            for name in names {
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

#[derive(Debug, Clone, Default, Hash, PartialEq, Eq)]
pub struct DomainRule {
    /// The name of NameServer Group.
    pub nameserver: Option<String>,

    pub address: Option<DomainAddress>,

    pub cname: Option<CNameRule>,

    /// The mode of speed checking.
    pub speed_check_mode: SpeedCheckModeList,

    pub dualstack_ip_selection: Option<bool>,

    pub response_mode: Option<ResponseMode>,

    pub no_cache: Option<bool>,
    pub no_serve_expired: Option<bool>,
    pub nftset: Option<Vec<IpConfig<NftsetConfig>>>,

    pub rr_ttl: Option<u64>,
    pub rr_ttl_min: Option<u64>,
    pub rr_ttl_max: Option<u64>,
}

impl std::ops::AddAssign for DomainRule {
    fn add_assign(&mut self, rhs: Self) {
        if rhs.nameserver.is_some() {
            self.nameserver = rhs.nameserver;
        }

        if rhs.address.is_some() {
            self.address = rhs.address;
        }

        if !rhs.speed_check_mode.is_empty() {
            self.speed_check_mode = rhs.speed_check_mode;
        }
        if rhs.dualstack_ip_selection.is_some() {
            self.dualstack_ip_selection = rhs.dualstack_ip_selection;
        }
        if rhs.no_cache.is_some() {
            self.no_cache = rhs.no_cache;
        }
        if rhs.no_serve_expired.is_some() {
            self.no_serve_expired = rhs.no_serve_expired
        }

        if rhs.rr_ttl.is_some() {
            self.rr_ttl = rhs.rr_ttl;
        }
        if rhs.rr_ttl_min.is_some() {
            self.rr_ttl_min = rhs.rr_ttl_min;
        }

        self.rr_ttl_max = rhs.rr_ttl_min.or(self.rr_ttl_max);
    }
}

/// response mode
///
/// response-mode [first-ping|fastest-ip|fastest-response]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum ResponseMode {
    FirstPing,
    FastestIp,
    FastestResponse,
}

impl Default for ResponseMode {
    fn default() -> Self {
        Self::FirstPing
    }
}

#[derive(Debug)]
pub struct DomainRuleTreeNode {
    name: Name,                            // www.example.com
    rule: Arc<DomainRule>,                 // www.example.com
    zone: Option<Arc<DomainRuleTreeNode>>, // example.com
}

impl DomainRuleTreeNode {
    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn zone(&self) -> Option<&Arc<DomainRuleTreeNode>> {
        self.zone.as_ref()
    }

    pub fn get<T>(&self, f: impl Fn(&Self) -> Option<T>) -> Option<T> {
        f(self).or_else(|| self.zone().map(|z| f(z)).unwrap_or_default())
    }
}

impl Deref for DomainRuleTreeNode {
    type Target = DomainRule;

    fn deref(&self) -> &Self::Target {
        self.rule.as_ref()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub enum CNameRule {
    #[default]
    Ignore,
    Name(Name),
}

#[cfg(test)]
mod tests {

    use std::{net::Ipv4Addr, ptr, str::FromStr};

    use crate::dns_conf::ConfigItem;

    use super::*;

    #[test]
    fn test_zone_rule() {
        let map = DomainRuleMap::create(
            &Default::default(),
            &vec![
                ConfigItem::<Domain, DomainAddress> {
                    name: Name::from_str("a.b.c.www.example.com").unwrap().into(),
                    value: DomainAddress::IPv4(Ipv4Addr::LOCALHOST),
                },
                ConfigItem::<Domain, DomainAddress> {
                    name: Name::from_str("www.example.com").unwrap().into(),
                    value: DomainAddress::IPv4(Ipv4Addr::LOCALHOST),
                },
                ConfigItem::<Domain, DomainAddress> {
                    name: Name::from_str("example.com").unwrap().into(),
                    value: DomainAddress::IPv4(Ipv4Addr::LOCALHOST),
                },
            ],
            &Default::default(),
            &Default::default(),
            &Default::default(),
            &Default::default(),
        );

        let rule1 = map.find(&Name::from_str("z.a.b.c.www.example.com").unwrap());
        assert!(rule1.is_some());
        assert_eq!(
            rule1.map(|o| o.name()),
            Some(&Name::from_str("a.b.c.www.example.com").unwrap())
        );

        let rule2 = map.find(&Name::from_str("www.example.com").unwrap());

        assert_eq!(
            rule2.map(|o| o.name()),
            Some(&Name::from_str("www.example.com").unwrap())
        );

        assert!(ptr::eq(
            rule1.as_ref().unwrap().zone().unwrap().as_ref(),
            rule2.unwrap().as_ref()
        ))
    }
}
