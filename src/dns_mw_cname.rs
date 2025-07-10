use std::time::{Duration, Instant};

use crate::libdns::proto::rr::rdata::CNAME;

use crate::config::CNameRule;
use crate::dns::*;
use crate::middleware::*;

pub struct DnsCNameMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsCNameMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let cname = match &ctx.domain_rule {
            Some(rule) => rule.get(|r| match &r.cname {
                Some(cname) => match cname {
                    CNameRule::IGN => None,
                    CNameRule::Value(n) => Some(n.clone()),
                },
                None => None,
            }),
            None => None,
        };

        match cname {
            Some(mut cname) => {
                if !cname.is_fqdn() {
                    cname.set_fqdn(true);
                }

                let local_ttl = ctx.cfg().local_ttl();

                let cname_record = Record::from_rdata(
                    req.query().original().name().clone(),
                    local_ttl as u32,
                    RData::CNAME(CNAME(cname.clone())),
                );

                if req.query().query_type() == RecordType::CNAME {
                    let query = req.query().original().clone();
                    let valid_until = Instant::now() + Duration::from_secs(local_ttl);

                    Ok(DnsResponse::new_with_deadline(
                        query,
                        vec![cname_record],
                        valid_until,
                    ))
                } else {
                    let mut ctx =
                        DnsContext::new(&cname, ctx.cfg().clone(), ctx.server_opts().clone());

                    let new_req = req.with_cname(cname.clone());
                    match next.run(&mut ctx, &new_req).await {
                        Ok(mut lookup) => {
                            *lookup.queries_mut() = vec![req.query().original().clone()];
                            lookup.answers_mut().insert(0, cname_record);
                            Ok(lookup)
                        }
                        Err(err) => Err(err),
                    }
                }
            }
            None => next.run(ctx, req).await,
        }
    }
}
