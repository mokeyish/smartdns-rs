use trust_dns_client::op::ResponseCode;

use crate::dns::*;

use crate::middleware::*;

pub struct DnsBogusMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsBogusMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let res = next.run(ctx, req).await;

        let bogus_nxdomain = &ctx.cfg.bogus_nxdomain;

        if req.query().query_type().is_ip_addr() {
            if let Ok(lookup) = res.as_ref() {
                for record in lookup.records() {
                    if match record.data() {
                        Some(RData::A(ip)) if bogus_nxdomain.contains(ip) => true,
                        Some(RData::AAAA(ip)) if bogus_nxdomain.contains(ip) => true,
                        _ => false,
                    } {
                        return Err(ResponseCode::NXDomain.into());
                    }
                }
            }
        }
        res
    }
}
