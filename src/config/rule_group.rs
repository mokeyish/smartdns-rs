use std::sync::LazyLock;

use super::{AddressRules, CNameRules, DomainRules, ForwardRule, HttpsRecords, SrvRecords};

static EMPTY: LazyLock<RuleGroup> = LazyLock::new(RuleGroup::default);

#[derive(Default, Debug)]
pub struct RuleGroup {
    /// specific nameserver to domain
    ///
    /// nameserver /domain/[group|-]
    ///
    /// ```
    /// example:
    ///   nameserver /www.example.com/office, Set the domain name to use the appropriate server group.
    ///   nameserver /www.example.com/-, ignore this domain
    /// ```
    pub forward_rules: Vec<ForwardRule>,

    /// specific address to domain
    ///
    /// address /domain/[ip|-|-4|-6|#|#4|#6]
    ///
    /// ```
    /// example:
    ///   address /www.example.com/1.2.3.4, return ip 1.2.3.4 to client
    ///   address /www.example.com/-, ignore address, query from upstream, suffix 4, for ipv4, 6 for ipv6, none for all
    ///   address /www.example.com/#, return SOA to client, suffix 4, for ipv4, 6 for ipv6, none for all
    /// ```
    pub address_rules: AddressRules,

    /// set domain rules
    pub domain_rules: DomainRules,

    pub cnames: CNameRules,

    pub srv_records: SrvRecords,

    pub https_records: HttpsRecords,
}

impl RuleGroup {
    pub fn empty() -> &'static Self {
        &EMPTY
    }

    pub fn merge(&mut self, other: RuleGroup) {
        self.forward_rules.extend(other.forward_rules);
        self.address_rules.extend(other.address_rules);
        self.domain_rules.extend(other.domain_rules);
        self.cnames.extend(other.cnames);
        self.srv_records.extend(other.srv_records);
        self.https_records.extend(other.https_records);
    }
}
