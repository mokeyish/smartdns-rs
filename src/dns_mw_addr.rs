use std::{
    borrow::Borrow,
    time::{Duration, Instant},
};

use crate::dns::*;
use crate::dns_conf::SmartDnsConfig;
use crate::matcher::DomainAddressMatcher;
use crate::middleware::*;
use trust_dns_proto::rr::{RData, RecordType};

#[derive(Debug)]
pub struct AddressMiddleware {
    map: DomainAddressMatcher,
}

impl AddressMiddleware {
    pub fn new(cfg: &SmartDnsConfig) -> Self {
        Self {
            map: DomainAddressMatcher::create(cfg),
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
        let query_type = req.query().query_type();

        let mut rdata = None;

        if !ctx.query_opts.no_rule_soa()
            && (matches!(ctx.cfg.force_aaaa_soa, Some(true) if query_type == RecordType::AAAA)
                || ctx.cfg.force_qtype_soa.contains(&query_type))
        {
            // force SOA
            rdata = Some(RData::default_soa());
        } else if self.map.len() > 0 && matches!(query_type, RecordType::AAAA | RecordType::A) {
            // address rule
            rdata = self
                .map
                .find(req.query().name().borrow())
                .map(|rule| {
                    match rule {
                        crate::dns_conf::DomainAddress::IPv4(ipv4)
                            if !ctx.query_opts.no_rule_addr() =>
                        {
                            Some(RData::A(*ipv4))
                        }
                        crate::dns_conf::DomainAddress::IPv6(ipv6)
                            if !ctx.query_opts.no_rule_addr() =>
                        {
                            Some(RData::AAAA(*ipv6))
                        }
                        crate::dns_conf::DomainAddress::SOA if !ctx.query_opts.no_rule_soa() => {
                            Some(RData::default_soa())
                        }
                        crate::dns_conf::DomainAddress::SOAv4
                            if !ctx.query_opts.no_rule_soa()
                                && req.query().query_type() == RecordType::A =>
                        {
                            Some(RData::default_soa())
                        }
                        crate::dns_conf::DomainAddress::SOAv6
                            if !ctx.query_opts.no_rule_soa()
                                && req.query().query_type() == RecordType::AAAA =>
                        {
                            Some(RData::default_soa())
                        }
                        crate::dns_conf::DomainAddress::IGN => None,
                        crate::dns_conf::DomainAddress::IGNv4 => None,
                        crate::dns_conf::DomainAddress::IGNv6 => None,
                        _ => None, // skip rules
                    }
                })
                .unwrap_or_default();
        }

        if let Some(rdata) = rdata {
            let local_ttl = ctx.cfg.local_ttl();

            let query = req.query().original().clone();
            let name = query.name().to_owned();
            let valid_until = Instant::now() + Duration::from_secs(local_ttl);

            let lookup = Lookup::new_with_deadline(
                query,
                vec![Record::from_rdata(name, local_ttl as u32, rdata)].into(),
                valid_until,
            );

            ctx.lookup_source = LookupSource::Static;
            return Ok(lookup);
        }

        next.run(ctx, req).await
    }
}
