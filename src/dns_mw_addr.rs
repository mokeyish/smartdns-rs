use std::str::FromStr;

use crate::matcher::DomainAddressMatcher;
use crate::dns::*;
use crate::dns_conf::SmartDnsConfig;
use crate::middleware::*;
use trust_dns_client::rr::{RData, RecordType};
use trust_dns_resolver::Name;


#[derive(Debug)]
pub struct AddressMiddleware {
    map: DomainAddressMatcher
}

impl AddressMiddleware {
    pub fn new(cfg: &SmartDnsConfig) -> Self {
        Self {
            map: DomainAddressMatcher::create(cfg)
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for AddressMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: crate::middleware::Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        match req.query().query_type() {
            // handle AAAA and A only.
            RecordType::AAAA | RecordType::A => {
                let name = req.query().name();
                if let Some(addr) = self.map.find(name) {
                    let rdata = match addr {
                        crate::dns_conf::DomainAddress::IPv4(ipv4) => Some(RData::A(*ipv4)),
                        crate::dns_conf::DomainAddress::IPv6(ipv6) => Some(RData::AAAA(*ipv6)),
                        crate::dns_conf::DomainAddress::SOA => Some(RData::default_soa()),
                        crate::dns_conf::DomainAddress::SOAv4
                            if req.query().query_type() == RecordType::A =>
                        {
                            Some(RData::default_soa())
                        }
                        crate::dns_conf::DomainAddress::SOAv6
                            if req.query().query_type() == RecordType::AAAA =>
                        {
                            Some(RData::default_soa())
                        }
                        crate::dns_conf::DomainAddress::IGN => None,
                        crate::dns_conf::DomainAddress::IGNv4 => None,
                        crate::dns_conf::DomainAddress::IGNv6 => None,
                        _ => None,
                    };

                    if let Some(rdata) = rdata {
                        let lookup = Lookup::from_rdata(req.query().original().to_owned(), rdata);
                        return Ok(lookup);
                    }
                }
            }
            RecordType::PTR
                if req.query().name() == &Name::from_str("whoami").unwrap().into()
                    || req.query().name() == &Name::from_str("smartdns").unwrap().into() =>
            {
                return Ok(Lookup::from_rdata(
                    req.query().original().to_owned(),
                    RData::PTR(ctx.cfg.server_name.clone()),
                ));
            }
            _ => (),
        }

        next.run(ctx, req).await
    }
}
