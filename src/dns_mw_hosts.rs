use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::Query;
use tokio::sync::RwLock;

use crate::dns::*;
use crate::libdns::resolver::Hosts;
use crate::middleware::*;

pub struct DnsHostsMiddleware(RwLock<Option<(Instant, Arc<Hosts>)>>);

impl DnsHostsMiddleware {
    pub fn new() -> Self {
        Self(Default::default())
    }
}

const EXPIRES: Duration = Duration::from_secs(5);

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsHostsMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query = req.query().original();

        if query.query_type().is_ip_addr() {
            let hosts = self.0.read().await.as_ref().and_then(|(read_time, hosts)| {
                if Instant::now() - *read_time < EXPIRES {
                    Some(hosts.clone())
                } else {
                    None
                }
            });

            let hosts = match hosts {
                Some(v) => v,
                None => {
                    let hosts = Arc::new(Hosts::new());
                    *self.0.write().await = Some((Instant::now(), hosts.clone()));
                    hosts
                }
            };

            if let Some(lookup) = hosts.lookup_static_host(query).or_else(|| {
                let mut name = query.name().clone();
                name.set_fqdn(!name.is_fqdn());
                hosts.lookup_static_host(&Query::query(name, query.query_type()))
            }) {
                return Ok(DnsResponse::new_with_deadline(
                    query.clone(),
                    lookup.records().to_vec(),
                    lookup.valid_until(),
                ));
            }
        }

        next.run(ctx, req).await
    }
}
