use crate::{
    dns::{DnsContext, DnsRequest, DnsResponse},
    dns_error::LookupError,
};

use super::ZoneProvider;

#[derive(Default)]
pub struct ZoneManager {
    providers: Vec<Box<dyn ZoneProvider>>,
}

impl ZoneManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_provider<P: ZoneProvider + 'static>(mut self, provider: P) -> Self {
        self.providers.push(Box::new(provider));
        self
    }

    pub async fn lookup(
        &self,
        ctx: &DnsContext,
        req: &DnsRequest,
    ) -> Result<Option<DnsResponse>, LookupError> {
        for provider in &self.providers {
            if let Some(response) = provider.lookup(ctx, req).await? {
                return Ok(Some(response));
            }
        }
        Ok(None)
    }
}
