use crate::dns::*;
use crate::dnsmasq::LanClientStore;
use crate::middleware::*;
use std::borrow::Borrow;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct DnsmasqMiddleware {
    client_store: LanClientStore,
}

impl DnsmasqMiddleware {
    pub fn new<P: AsRef<Path>>(lease_file: P, domain: Option<Name>) -> Self {
        Self {
            client_store: LanClientStore::new(lease_file, domain),
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsmasqMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        if let Some(rdata) = self
            .client_store
            .lookup(req.query().name().borrow(), req.query().query_type())
        {
            let local_ttl = ctx.cfg().local_ttl();

            let query = req.query().original().clone();
            let name = query.name().to_owned();
            let valid_until = Instant::now() + Duration::from_secs(local_ttl);

            let lookup = DnsResponse::new_with_deadline(
                query,
                vec![Record::from_rdata(name, local_ttl as u32, rdata)],
                valid_until,
            );

            ctx.source = LookupFrom::Static;
            return Ok(lookup);
        }

        next.run(ctx, req).await
    }
}
