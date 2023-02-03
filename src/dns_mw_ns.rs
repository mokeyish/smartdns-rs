use ipnet::IpNet;

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

        let group_name = ctx.client.find_server_group_name(name);

        ctx.lookup_source = LookupSource::Server(group_name.to_string());
        match ctx.client.lookup(name, rtype, Some(group_name)).await {
            Ok(lookup) => {
                if req.query().query_type().is_ip_addr()
                    && (!ctx.cfg.whitelist_ip.is_empty() || !ctx.cfg.whitelist_ip.is_empty())
                {
                    let (whitelist_ip_enabled, blacklist_ip_enabled) =
                        match ctx.client.find_server_group(name) {
                            Some(ss) => {
                                let whitelist_ip = ss.iter().any(|s| s.whitelist_ip);
                                let blacklist_ip = ss.iter().any(|s| s.blacklist_ip);
                                (whitelist_ip, blacklist_ip)
                            }
                            None => (false, false),
                        };

                    Ok(filter_by_whitelist_and_blacklist_ip(
                        lookup,
                        whitelist_ip_enabled,
                        blacklist_ip_enabled,
                        &ctx.cfg.whitelist_ip,
                        &ctx.cfg.blacklist_ip,
                    ))
                } else {
                    Ok(lookup)
                }
            }
            err @ _ => err,
        }
    }
}

fn filter_by_whitelist_and_blacklist_ip(
    lookup: Lookup,
    whitelist_ip_enabled: bool,
    blacklist_ip_enabled: bool,
    whitelist_ip: &[IpNet],
    blacklist_ip: &[IpNet],
) -> Lookup {
    let query = lookup.query().clone();
    let records = lookup
        .record_iter()
        .filter(|r| {
            let ip = r.data().map(|r| r.to_ip_addr()).unwrap_or_default();
            if ip.is_none() {
                return true;
            }
            let ip = ip.unwrap();

            // filter result whth whitelist ip,  result in whitelist-ip will be accepted.
            if whitelist_ip_enabled && !whitelist_ip.is_empty() {
                if whitelist_ip.iter().any(|net| net.contains(&ip)) {
                    return true;
                }
                return false;
            }

            // filter result with blacklist ip
            if blacklist_ip_enabled && !blacklist_ip.is_empty() {
                if blacklist_ip.iter().any(|net| net.contains(&ip)) {
                    return false;
                }
                return true;
            }

            true
        })
        .map(|r| r.clone())
        .collect::<Vec<_>>();

    Lookup::new_with_max_ttl(query, records.into())
}
