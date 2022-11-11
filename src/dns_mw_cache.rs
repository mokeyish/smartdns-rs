use std::time::Duration;
use std::time::Instant;

use crate::dns::*;
use crate::dns_conf::SmartDnsConfig;
use crate::log::debug;
use crate::middleware::*;

use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::dns_lru::DnsLru;
use trust_dns_resolver::dns_lru::TtlConfig;

pub struct DnsCacheMiddleware {
    cache: DnsLru,
}

impl DnsCacheMiddleware {
    pub fn new(cfg: &SmartDnsConfig) -> Self {
        let mut opts = ResolverOpts::default();
        opts.positive_min_ttl = Some(Duration::from_secs(cfg.rr_ttl_min.unwrap_or(cfg.rr_ttl())));
        opts.positive_max_ttl = Some(Duration::from_secs(cfg.rr_ttl_max.unwrap_or(cfg.rr_ttl())));

        Self {
            cache: DnsLru::new(cfg.cache_size(), TtlConfig::from_opts(&opts)),
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsCacheMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query = req.query();

        let cached_val = self.cache.get(query.original(), Instant::now());

        if cached_val.is_some() {
            debug!("name: {} using caching", query.name());
            return cached_val.unwrap();
        }

        let res = next.run(ctx, req).await;

        let res = match res {
            Ok(lookup) => {
                self.cache.insert_records(
                    query.original().to_owned(),
                    lookup.records().to_owned().into_iter(),
                    Instant::now(),
                );

                Ok(lookup)
            }
            Err(err) => Err(err),
        };

        res
    }
}
