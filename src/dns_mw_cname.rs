use std::time::{Duration, Instant};

use crate::libdns::proto::rr::rdata::CNAME;

use crate::config::CName;
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
                    CName::IGN => None,
                    CName::Value(n) => Some(n.clone()),
                },
                None => None,
            }),
            None => None,
        };

        match cname {
            Some(cname) => {
                if req.query().query_type() == RecordType::CNAME {
                    let local_ttl = ctx.cfg().local_ttl();

                    let query = req.query().original().clone();
                    let name = query.name().to_owned();
                    let valid_until = Instant::now() + Duration::from_secs(local_ttl);

                    let records = vec![Record::from_rdata(
                        name,
                        local_ttl as u32,
                        RData::CNAME(CNAME(cname.clone())),
                    )];

                    Ok(DnsResponse::new_with_deadline(query, records, valid_until))
                } else {
                    let mut ctx =
                        DnsContext::new(&cname, ctx.cfg().clone(), ctx.server_opts().clone());
                    let req = req.with_cname(cname);
                    next.run(&mut ctx, &req).await
                }
            }
            None => next.run(ctx, req).await,
        }
    }
}
