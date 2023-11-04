use std::sync::Arc;

use crate::config::ConfigForIP;
use crate::dns::*;
use crate::ffi::nft::Nft;
use crate::middleware::*;

pub struct DnsNftsetMiddleware {
    nft: Arc<Nft>,
}

impl DnsNftsetMiddleware {
    pub fn new<T: Into<Arc<Nft>>>(nft: T) -> Self {
        Self { nft: nft.into() }
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
                    let ips = lookup
                        .records()
                        .iter()
                        .filter_map(|r| r.data().and_then(|d| d.ip_addr()))
                        .collect::<Vec<_>>();
                    if !ips.is_empty() {
                        let nft = self.nft.clone();
                        tokio::spawn(async move {
                            use std::net::IpAddr::*;
                            let (ipv4s, ipv6s) = {
                                let mut ipv4s = vec![];
                                let mut ipv6s = vec![];
                                for ip in ips {
                                    match ip {
                                        V4(ip) => ipv4s.push(ip),
                                        V6(ip) => ipv6s.push(ip),
                                    }
                                }
                                (ipv4s, ipv6s)
                            };
                            if !ipv4s.is_empty() {
                                for nftset in &nftsets {
                                    if let ConfigForIP::V4(cfg) = nftset {
                                        let _ = nft.add_ip_element(
                                            cfg.family,
                                            &cfg.table,
                                            &cfg.name,
                                            ipv4s.as_slice(),
                                        );
                                    }
                                }
                            }

                            if !ipv6s.is_empty() {
                                for nftset in &nftsets {
                                    if let ConfigForIP::V6(cfg) = nftset {
                                        let _ = nft.add_ip_element(
                                            cfg.family,
                                            &cfg.table,
                                            &cfg.name,
                                            ipv6s.as_slice(),
                                        );
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
