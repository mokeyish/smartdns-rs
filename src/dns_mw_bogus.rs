use std::ops::Deref;

use crate::dns_error::LookupError;
use crate::libdns::proto::op::ResponseCode;

use crate::dns::*;

use crate::middleware::*;

pub struct DnsBogusMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, LookupError> for DnsBogusMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, LookupError>,
    ) -> Result<DnsResponse, LookupError> {
        let res = next.run(ctx, req).await;

        let bogus_nxdomain = ctx.cfg().bogus_nxdomain();

        if req.query().query_type().is_ip_addr()
            && let Ok(lookup) = res.as_ref()
        {
            for record in lookup.records() {
                if match record.data() {
                    RData::A(ip) if bogus_nxdomain.contains(ip.deref()) => true,
                    RData::AAAA(ip) if bogus_nxdomain.contains(ip.deref()) => true,
                    _ => false,
                } {
                    return Err(ResponseCode::NXDomain.into());
                }
            }
        }
        res
    }
}
