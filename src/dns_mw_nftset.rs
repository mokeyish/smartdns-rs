use crate::config::ConfigForIP;
use crate::dns::*;
use crate::ffi::nftset;
use crate::middleware::*;

pub struct DnsNftsetMiddleware;

impl DnsNftsetMiddleware {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsNftsetMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let res = next.run(ctx, req).await;

        if let Ok(lookup) = res.as_ref() {
            if let Some(rule) = &ctx.domain_rule {
                let nftsets = rule.get(|n| n.nftset.as_ref().cloned());
                if let Some(nftsets) = nftsets {
                    let ip_addrs = lookup
                        .records()
                        .iter()
                        .filter_map(|r| r.data().ip_addr())
                        .collect::<Vec<_>>();

                    if !ip_addrs.is_empty() {
                        tokio::spawn(async move {
                            let (ipv4_addrs, ipv6_addrs): (Vec<_>, Vec<_>) =
                                ip_addrs.into_iter().partition(|ip| ip.is_ipv4());

                            if !ipv4_addrs.is_empty() {
                                for nftset in &nftsets {
                                    if let ConfigForIP::V4(cfg) = nftset {
                                        for ip in ipv4_addrs.iter() {
                                            let _ = nftset::add(
                                                cfg.family, &cfg.table, &cfg.name, *ip, 0,
                                            );
                                        }
                                    }
                                }
                            }

                            if !ipv6_addrs.is_empty() {
                                for nftset in &nftsets {
                                    if let ConfigForIP::V6(cfg) = nftset {
                                        for ip in ipv6_addrs.iter() {
                                            let _ = nftset::add(
                                                cfg.family, &cfg.table, &cfg.name, *ip, 0,
                                            );
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
        res
    }
}
