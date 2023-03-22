use std::time::{Duration, Instant};

use crate::dns::*;
use crate::middleware::*;
use crate::trust_dns::proto::rr::{RData, RecordType};
use crate::trust_dns::resolver::LookupTtl;

#[derive(Debug)]
pub struct AddressMiddleware;

impl AddressMiddleware {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for AddressMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query_type = req.query().query_type();

        if let Some(rdata) = handle_rule_addr(query_type, ctx) {
            let local_ttl = ctx.cfg().local_ttl();

            let query = req.query().original().clone();
            let name = query.name().to_owned();
            let valid_until = Instant::now() + Duration::from_secs(local_ttl);

            let lookup = Lookup::new_with_deadline(
                query,
                vec![Record::from_rdata(name, local_ttl as u32, rdata)].into(),
                valid_until,
            );

            ctx.source = LookupFrom::Static;
            return Ok(lookup);
        }

        let res = next.run(ctx, req).await;

        match res {
            Ok(mut lookup) => Ok({
                if let Some(max_reply_ip_num) = ctx.cfg().max_reply_ip_num() {
                    let mut records = &lookup.records()[..];
                    if records.len() > max_reply_ip_num as usize {
                        records = &records[0..max_reply_ip_num as usize];
                    }
                    lookup = Lookup::new_with_deadline(
                        lookup.query().clone(),
                        records.to_vec().into(),
                        lookup.valid_until(),
                    )
                }

                if let Some(rr_ttl_reply_max) = ctx.cfg().rr_ttl_reply_max() {
                    lookup = lookup.with_max_ttl(rr_ttl_reply_max as u32)
                }

                lookup
            }),
            Err(err) => Err(err),
        }
    }
}

fn handle_rule_addr(query_type: RecordType, ctx: &DnsContext) -> Option<RData> {
    use RecordType::{A, AAAA};

    let cfg = ctx.cfg();
    let server_opts = ctx.server_opts();
    let rule = ctx.domain_rule.as_ref();

    let no_rule_soa = server_opts.no_rule_soa();

    if !no_rule_soa {
        // force AAAA query return SOA
        if query_type == AAAA && (server_opts.force_aaaa_soa() || cfg.force_aaaa_soa()) {
            return Some(RData::default_soa());
        }

        // force AAAA query return SOA
        if cfg.force_qtype_soa().contains(&query_type) {
            return Some(RData::default_soa());
        }
    }

    // skip address rule.
    if server_opts.no_rule_addr() || !query_type.is_ip_addr() {
        return None;
    }

    let mut node = rule;

    while let Some(rule) = node {
        use crate::dns_conf::DomainAddress::*;

        if let Some(address) = rule.address {
            match address {
                IPv4(ipv4) if query_type == A => return Some(RData::A(ipv4)),
                IPv6(ipv6) if query_type == AAAA => return Some(RData::AAAA(ipv6)),
                SOA if !no_rule_soa => return Some(RData::default_soa()),
                SOAv4 if !no_rule_soa && query_type == A => return Some(RData::default_soa()),
                SOAv6 if !no_rule_soa && query_type == AAAA => return Some(RData::default_soa()),
                IGN => return None, // ignore rule
                IGNv4 if query_type == A => return None,
                IGNv6 if query_type == AAAA => return None,
                _ => (),
            };
        }

        node = rule.zone(); // find parent rule
    }

    None
}
