use std::time::{Duration, Instant};

use crate::dns::*;
use crate::middleware::*;
use crate::trust_dns::proto::rr::{RData, RecordType};

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
        next: crate::middleware::Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query_type = req.query().query_type();

        let mut rdata = None;

        let no_rule_soa = ctx.server_opts.no_rule_soa();

        if !no_rule_soa
            && (ctx.cfg().force_aaaa_soa() && query_type == RecordType::AAAA
                || ctx.cfg().force_qtype_soa().contains(&query_type))
        {
            // force SOA
            rdata = Some(RData::default_soa());
        } else if matches!(query_type, RecordType::AAAA | RecordType::A if !ctx.server_opts.no_rule_addr())
        {
            let mut node = ctx.domain_rule.as_ref();

            while let Some(rule) = node {
                use crate::dns_conf::DomainAddress::*;

                if let Some(address) = rule.address {
                    rdata = match address {
                        IPv4(ipv4) => Some(RData::A(ipv4)),
                        IPv6(ipv6) => Some(RData::AAAA(ipv6)),
                        SOA if !no_rule_soa => Some(RData::default_soa()),
                        SOAv4 if !no_rule_soa && query_type == RecordType::A => {
                            Some(RData::default_soa())
                        }
                        SOAv6 if !no_rule_soa && query_type == RecordType::AAAA => {
                            Some(RData::default_soa())
                        }
                        IGN => {
                            node = rule.zone();
                            continue;
                        }
                        IGNv4 if query_type == RecordType::A => {
                            node = rule.zone();
                            continue;
                        }
                        IGNv6 if query_type == RecordType::AAAA => continue,
                        _ => None, // skip rules
                    };
                    break;
                } else {
                    node = rule.zone();
                    continue;
                }
            }
        }

        if let Some(rdata) = rdata {
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

        // handle max_reply_ip_num
        if let (Some(max_reply_ip_num), Ok(lookup)) = (ctx.cfg().max_reply_ip_num(), &res) {
            if lookup.records().len() > max_reply_ip_num as usize {
                let records = &lookup.records()[0..max_reply_ip_num as usize];
                Ok(Lookup::new_with_deadline(
                    lookup.query().clone(),
                    records.to_vec().into(),
                    lookup.valid_until(),
                ))
            } else {
                res
            }
        } else {
            res
        }
    }
}
