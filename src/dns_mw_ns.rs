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

        if let Some(lookup) = ctx
            .client
            .lookup_nameserver_ip(name.clone().into(), rtype)
            .await
        {
            ctx.no_cache = true;
            return Ok(lookup);
        }

        let group_name = ctx.client.find_server_group(name);
        ctx.lookup_source = LookupSource::Server(group_name.to_string());
        ctx.client.lookup(name, rtype, Some(group_name)).await
    }
}
