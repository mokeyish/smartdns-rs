use std::borrow::Borrow;

use crate::dns_client::{DnsClient, DnsResolver, FALLBACK_GROUP, LookupOptions};
use crate::dns_lookup::{LookupIpOptions, LookupStrategy};
use crate::{
    config::ResponseMode,
    dns::*,
    log::{debug, error},
    middleware::*,
};

use crate::libdns::proto::rr::domain::usage::LOCAL;
use crate::libdns::proto::rr::rdata::opt::EdnsCode;
use rr::rdata::opt::EdnsOption;

pub struct NameServerMiddleware {
    client: DnsClient,
}

impl NameServerMiddleware {
    pub fn new(client: DnsClient) -> Self {
        Self { client }
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
        let name: &Name = req.query().name().borrow();
        let rtype = req.query().query_type();

        let client = &self.client;

        if rtype.is_ip_addr()
            && let Some(lookup) = client.lookup_nameserver(name.clone(), rtype).await
        {
            debug!(
                "lookup nameserver {} {} ip {:?}",
                name,
                rtype,
                lookup
                    .answers()
                    .iter()
                    .filter_map(|record| record.data().ip_addr())
                    .collect::<Vec<_>>()
            );
            ctx.no_cache = true;
            return Ok(lookup);
        }

        let lookup_options = LookupOptions {
            is_dnssec: req.is_dnssec(),
            record_type: rtype,
            client_subnet: req
                .extensions()
                .as_ref()
                .and_then(|edns| {
                    edns.option(EdnsCode::Subnet).and_then(|opt| match opt {
                        EdnsOption::Subnet(subnet) => Some(*subnet),
                        _ => None,
                    })
                })
                .or_else(|| ctx.domain_rule.get_ref(|r| r.subnet.as_ref()).cloned()),
        };

        // skip nameserver rule
        if ctx.server_opts.no_rule_nameserver() {
            return client.lookup(name.clone(), lookup_options).await;
        }

        let group_name = ctx.server_group_name().to_string();

        let name_server = {
            let name_server = if ctx.cfg().mdns_lookup() && LOCAL.zone_of(name) {
                client.get_server_group("mdns").await
            } else {
                None
            };

            let name_server = match name_server {
                Some(ns) => Some(ns),
                None => client.get_server_group(group_name.as_ref()).await,
            };

            match name_server {
                Some(ns) => ns,
                None => {
                    error!("no available nameserver found for {}", name);
                    return Err(ProtoErrorKind::NoConnections.into());
                }
            }
        };

        debug!(
            "query name: {} type: {}{} via [Group: {}]",
            name,
            rtype,
            match lookup_options.client_subnet.as_ref() {
                Some(subnet) => format!("\tsubnet: {}/{}", subnet.addr(), subnet.scope_prefix()),
                None => String::with_capacity(0),
            },
            group_name
        );

        ctx.source = LookupFrom::Server(group_name.to_string());

        // IP lookups use the richer `LookupIpOptions` (response strategy,
        // speed-check mode, IP filters); non-IP lookups pass `None`.
        let mut ip_opts = rtype.is_ip_addr().then(|| {
            let cfg = ctx.cfg();
            let rule = ctx.domain_rule.as_ref();

            let response_strategy = rule
                .and_then(|r| r.get(|n| n.response_mode))
                .unwrap_or_else(|| cfg.response_mode());
            let speed_check_mode = match rule.and_then(|r| r.speed_check_mode.as_ref()) {
                Some(mode) => Some(mode.clone()),
                None => cfg.speed_check_mode().cloned(),
            };

            LookupIpOptions {
                response_strategy,
                speed_check_mode,
                no_speed_check: ctx.server_opts.no_speed_check(),
                ignore_ip: cfg.ignore_ip().clone(),
                blacklist_ip: cfg.blacklist_ip().clone(),
                whitelist_ip: cfg.whitelist_ip().clone(),
                ip_alias: cfg.ip_alias().clone(),
                lookup_options: lookup_options.clone(),
            }
        });
        if let Some(o) = ip_opts.as_mut()
            && ctx.server_opts.is_background
        {
            o.response_strategy = ResponseMode::FastestIp;
        }

        // The lookup strategy (see `dns_lookup::LookupStrategy`) applies both
        // fallback levels: per-server `-fallback` servers are only tried after
        // the group's primary servers fail, and if the whole round still fails
        // the query is retried once against the group named `fallback`.
        let strategy = LookupStrategy::new(
            name_server,
            client.fallback_group(),
            group_name == FALLBACK_GROUP,
            ip_opts,
        );
        strategy
            .lookup(name.clone(), lookup_options)
            .await
            .map(|res| res.with_name_server_group(group_name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::libdns::proto::rr::rdata::opt::ClientSubnet;

    use super::*;
    use crate::{dns_conf::RuntimeConfig, third_ext::FutureJoinAllExt};
    use futures::FutureExt;

    #[test]
    fn test_edns_client_subnet() {
        async fn inner_test(i: usize) -> bool {
            // https://lite.ip2location.com/ip-address-ranges-by-country

            let servers = [
                "server https://120.53.53.53/dns-query",
                "server https://223.5.5.5/dns-query",
            ];

            let server = servers[i % servers.len()];

            let cfg = RuntimeConfig::builder().with(server).build().unwrap();

            let domain = "www.bing.com";

            let client = cfg.create_dns_client().await;

            let subnets = ["113.65.29.0/24", "103.225.87.0/24", "113.65.29.0/24"];

            let results = subnets
                .into_iter()
                .map(|subnet| {
                    client.lookup(
                        domain,
                        LookupOptions {
                            is_dnssec: false,
                            record_type: RecordType::A,
                            client_subnet: Some(ClientSubnet::from_str(subnet).unwrap()),
                        },
                    )
                })
                .join_all()
                .await
                .into_iter()
                .flatten()
                .map(|lookup| {
                    let mut ips = lookup.ip_addrs();
                    ips.sort();
                    ips
                })
                .collect::<Vec<_>>();

            let t1 = results[0].clone();
            let t2 = results[1].clone();
            let t3 = results[2].clone();
            let success = t1 == t3 && t1 != t2;
            if !success {
                println!("{t1:?}");
                println!("{t2:?}");
                println!("{t3:?}");
            }
            success
        }

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use futures_util::future::select_all;
                let mut success = false;
                let mut tasks = (0..10).map(|i| inner_test(i).boxed()).collect::<Vec<_>>();

                loop {
                    let (res, _idx, rest) = select_all(tasks).await;

                    if res {
                        success = res;
                        break;
                    }

                    if rest.is_empty() {
                        break;
                    }

                    tasks = rest;
                }
                assert!(success);
            });
    }
}
