use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

use trust_dns_client::rr::LowerName;
use trust_dns_server::authority::{AuthorityObject, LookupOptions};

use crate::dns::*;
use crate::dns_conf::SmartDnsConfig;
use crate::log::debug;
use crate::middleware::*;

pub struct DnsZoneMiddleware {
    catalog: Catalog,
    ptr_set: BTreeSet<LowerName>,
}

impl DnsZoneMiddleware {
    pub fn new(_cfg: &SmartDnsConfig) -> Self {
        let catalog = Catalog::new();

        let ptr_set = {
            let mut set = BTreeSet::<LowerName>::new();
            set.insert(Name::from_str("whoami").unwrap().into());
            set.insert(Name::from_str("smartdns").unwrap().into());

            #[cfg(not(target_os = "android"))]
            {
                use crate::third_ext::IpAddrToArpa;
                use local_ip_address::list_afinet_netifas;
                if let Ok(network_interfaces) = list_afinet_netifas() {
                    for (_, ip) in network_interfaces.iter() {
                        if let Ok(n) = Name::from_str(ip.to_arpa().as_str()) {
                            set.insert(n.into());
                        }
                    }
                }
            }

            set
        };

        Self { catalog, ptr_set }
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

        if rtype == RecordType::PTR && self.ptr_set.contains(name) {
            return Ok(Lookup::from_rdata(
                req.query().original().to_owned(),
                RData::PTR(ctx.cfg.server_name()),
            ));
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
