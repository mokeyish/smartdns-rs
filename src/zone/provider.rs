use crate::dns::{DnsContext, DnsError, DnsRequest, DnsResponse};

#[async_trait::async_trait]
pub trait ZoneProvider: Send + Sync {
    async fn lookup(
        &self,
        ctx: &DnsContext,
        req: &DnsRequest,
    ) -> Result<Option<DnsResponse>, DnsError>;
}
