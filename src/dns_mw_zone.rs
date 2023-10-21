use std::borrow::Borrow;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::str::FromStr;

use crate::libdns::proto::rr::rdata::PTR;
use crate::libdns::proto::rr::LowerName;
use crate::libdns::server::authority::{AuthorityObject, LookupOptions};
use ipnet::IpNet;

use crate::dns::*;
use crate::dns_conf::SmartDnsConfig;
use crate::infra::ipset::IpSet;
use crate::log::debug;
use crate::middleware::*;

pub struct DnsZoneMiddleware {
    catalog: Catalog,
    server_net: IpSet,
    server_names: BTreeSet<Name>,
}

impl DnsZoneMiddleware {
    pub fn new(_cfg: &SmartDnsConfig) -> Self {
        let catalog = Catalog::new();

        let server_net = {
            use local_ip_address::list_afinet_netifas;
            let mut ips = Vec::<IpAddr>::new();

            if let Ok(network_interfaces) = list_afinet_netifas() {
                for (_, ip) in network_interfaces.iter() {
                    ips.push(*ip);
                }
            }

            IpSet::new(
                ips.into_iter()
                    .map(|ip| match ip {
                        IpAddr::V4(_) => IpNet::new(ip, 32).unwrap(),
                        IpAddr::V6(_) => IpNet::new(ip, 128).unwrap(),
                    })
                    .collect(),
            )
        };

        let server_names = {
            let mut set = BTreeSet::new();
            set.insert(Name::from_str("smartdns.").unwrap());
            set.insert(Name::from_str("whoami.").unwrap());
            set
        };

        Self {
            catalog,
            server_net,
            server_names,
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsZoneMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query = req.query();
        let name = query.name();
        let rtype = query.query_type();

        if rtype == RecordType::PTR {
            let mut is_current_server = false;
            let name: &Name = name.borrow();

            if self.server_names.contains(name) {
                is_current_server = true;
            } else if let Ok(net) = name.parse_arpa_name() {
                is_current_server = self.server_net.iter().any(|ip| net.contains(ip));
            }

            if is_current_server {
                return Ok(Lookup::from_rdata(
                    req.query().original().to_owned(),
                    RData::PTR(PTR(ctx.cfg().server_name())),
                ));
            }
        };

        if let Some(authority) = self.catalog.find(name) {
            if let Ok(lookup) = authority
                .lookup(name, rtype, LookupOptions::default())
                .await
            {
                let records = lookup.iter().map(|r| r.to_owned()).collect::<Vec<_>>();
                if !records.is_empty() {
                    return Ok(DnsResponse::new_with_max_ttl(
                        query.original().to_owned(),
                        records.into(),
                    ));
                }
            }
        }

        next.run(ctx, req).await
    }
}

struct Catalog {
    authorities: HashMap<LowerName, Box<dyn AuthorityObject>>,
}

impl Catalog {
    /// Constructs a new Catalog
    pub fn new() -> Self {
        Self {
            authorities: Default::default(),
        }
    }

    /// Insert or update a zone authority
    ///
    /// # Arguments
    ///
    /// * `name` - zone name, e.g. example.com.
    /// * `authority` - the zone data
    pub fn upsert(&mut self, name: LowerName, authority: Box<dyn AuthorityObject>) {
        self.authorities.insert(name, authority);
    }

    /// Remove a zone from the catalog
    pub fn remove(&mut self, name: &LowerName) -> Option<Box<dyn AuthorityObject>> {
        self.authorities.remove(name)
    }

    /// Checks whether the `Catalog` contains DNS records for `name`
    ///
    /// Use this when you know the exact `LowerName` that was used when
    /// adding an authority and you don't care about the authority it
    /// contains. For public domain names, `LowerName` is usually the
    /// top level domain name like `example.com.`.
    ///
    /// If you do not know the exact domain name to use or you actually
    /// want to use the authority it contains, use `find` instead.
    pub fn contains(&self, name: &LowerName) -> bool {
        self.authorities.contains_key(name)
    }

    /// Recursively searches the catalog for a matching authority
    pub fn find(&self, name: &LowerName) -> Option<&(dyn AuthorityObject + 'static)> {
        if self.authorities.is_empty() {
            return None;
        }
        debug!("searching authorities for: {}", name);
        self.authorities
            .get(name)
            .map(|authority| &**authority)
            .or_else(|| {
                if !name.is_root() {
                    let name = name.base_name();
                    self.find(&name)
                } else {
                    None
                }
            })
    }
}

#[cfg(test)]
mod tests {

    use crate::infra::ipset::IpSet;

    use super::*;

    #[test]
    fn test_arpa() {
        let local_net = IpSet::new(vec![
            "::1/128".parse().unwrap(),
            "192.168.1.1/32".parse().unwrap(),
        ]);

        let name1: Name =
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
                .parse()
                .unwrap();

        let net1 = name1.parse_arpa_name().unwrap();

        assert!(local_net.contains(&net1));

        let name2: Name = "1.168.192.in-addr.arpa.".parse().unwrap();
        let net2 = name2.parse_arpa_name().unwrap();

        assert!(local_net.iter().any(|net| net2.contains(net)));
    }
}
