use crate::{
    dns::{DnsContext, DnsRequest, DnsResponse},
    dns_error::LookupError,
};

#[async_trait::async_trait]
pub trait ZoneProvider: Send + Sync {
    async fn lookup(
        &self,
        ctx: &DnsContext,
        req: &DnsRequest,
    ) -> Result<Option<DnsResponse>, LookupError>;
}
