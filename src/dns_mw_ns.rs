use crate::dns_conf::SmartDnsConfig;

use crate::dns::*;

use crate::middleware::*;

#[derive(Debug)]
pub struct NameServerMiddleware;

impl NameServerMiddleware {
    pub fn new(_cfg: &SmartDnsConfig) -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for NameServerMiddleware {
    #[inline]
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        _next: crate::middleware::Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let name = req.query().name();
        let rtype = req.query().query_type();
        ctx.client.lookup(name, rtype).await
    }
}
