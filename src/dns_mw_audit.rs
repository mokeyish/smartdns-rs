

use std::cell::Cell;
use std::sync::Arc;
use std::time::Instant;

use futures::lock::Mutex;

use crate::log::info;
use crate::dns::*;
use crate::middleware::*;

#[derive(Default)]
pub struct DnsAuditMiddleware {
    counter: Arc<Mutex<Cell<u32>>>
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsAuditMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        {

            let cell = self.counter.lock().await;
            let count = cell.get();
            cell.set(count + 1);
        }
        let start = Instant::now();
        let res = next.run(ctx, req).await;

        let duration = start.elapsed();

        info!("Time elapsed in {} is: {:?}", req.request_info().query.name(), duration);
        res
    }
}
