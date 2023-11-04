use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::{borrow::Borrow, net::IpAddr, pin::Pin, time::Duration};

use crate::dns_client::{LookupOptions, NameServer};
use crate::dns_conf::SpeedCheckModeList;
use crate::infra::ipset::IpSet;
use crate::{
    config::ResponseMode,
    dns::*,
    dns_client::GenericResolver,
    dns_client::{DnsClient, NameServerGroup},
    dns_conf::SpeedCheckMode,
    dns_error::LookupError,
    log::{debug, error},
    middleware::*,
};

use crate::libdns::proto::op::ResponseCode;
use crate::libdns::resolver::lookup_ip::LookupIp;
use futures::{Future, FutureExt};

pub struct NameServerMiddleware {
    client: DnsClient,
}

impl NameServerMiddleware {
    pub fn new(client: DnsClient) -> Self {
        Self { client }
    }

    async fn get_name_server_group<'s, 'c>(
        &self,
        ctx: &'c DnsContext,
    ) -> Option<(&'c str, Arc<NameServerGroup>)> {
        let client = &self.client;
        if let Some(name) = ctx.server_opts.group() {
            client.get_server_group(name).await.map(|ns| (name, ns))
        } else {
            let mut node = ctx.domain_rule.as_ref();

            while let Some(rule) = node {
                if let Some(name) = rule.nameserver.as_deref() {
                    return client.get_server_group(name).await.map(|ns| (name, ns));
                }

                node = rule.zone();
            }

            Some(("default", client.default().await))
        }
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

        if let Some(lookup) = client.lookup_nameserver(name.clone(), rtype).await {
            debug!(
                "lookup nameserver {} {} ip {:?}",
                name,
                rtype,
                lookup
                    .records()
                    .iter()
                    .filter_map(|record| record.data().map(|data| data.ip_addr()))
                    .flatten()
                    .collect::<Vec<_>>()
            );
            ctx.no_cache = true;
            return Ok(lookup);
        }

        let lookup_options = LookupOptions {
            record_type: rtype,
            client_subnet: None,
        };

        // skip nameserver rule
        if ctx.server_opts.no_rule_nameserver() {
            return client.lookup(name.clone(), lookup_options).await;
        }

        let (group_name, name_server_group) = match self.get_name_server_group(ctx).await {
            Some(ns) => ns,
            None => {
                error!("no available nameserver found for {}", name);
                return Err(ResolveErrorKind::NoConnections.into());
            }
        };

        debug!(
            "query name: {} type: {} via [Group: {}]",
            name, rtype, group_name
        );

        ctx.source = LookupFrom::Server(group_name.to_string());

        if rtype.is_ip_addr() {
            let cfg = ctx.cfg();

            let mut opts = match ctx.domain_rule.as_ref() {
                Some(rule) => LookupIpOptions {
                    response_strategy: rule
                        .get(|n| n.response_mode)
                        .unwrap_or_else(|| cfg.response_mode()),
                    speed_check_mode: if rule.speed_check_mode.is_empty() {
                        cfg.speed_check_mode().clone()
                    } else {
                        rule.speed_check_mode.clone()
                    },
                    no_speed_check: ctx.server_opts.no_speed_check(),
                    ignore_ip: cfg.ignore_ip().clone(),
                    blacklist_ip: cfg.blacklist_ip().clone(),
                    whitelist_ip: cfg.whitelist_ip().clone(),
                    lookup_options,
                },
                None => LookupIpOptions {
                    response_strategy: cfg.response_mode(),
                    speed_check_mode: cfg.speed_check_mode().clone(),
                    no_speed_check: ctx.server_opts.no_speed_check(),
                    ignore_ip: cfg.ignore_ip().clone(),
                    blacklist_ip: cfg.blacklist_ip().clone(),
                    whitelist_ip: cfg.whitelist_ip().clone(),
                    lookup_options,
                },
            };

            if ctx.background {
                opts.response_strategy = ResponseMode::FastestIp;
            }

            match lookup_ip(name_server_group.deref(), name.clone(), &opts).await {
                Ok(lookup_ip) => Ok(lookup_ip.into()),
                Err(err) => Err(err),
            }
        } else {
            name_server_group.lookup(name.clone(), lookup_options).await
        }
    }
}

struct LookupIpOptions {
    response_strategy: ResponseMode,
    speed_check_mode: SpeedCheckModeList,
    no_speed_check: bool,
    ignore_ip: Arc<IpSet>,
    whitelist_ip: Arc<IpSet>,
    blacklist_ip: Arc<IpSet>,
    lookup_options: LookupOptions,
}

impl Deref for LookupIpOptions {
    type Target = LookupOptions;

    fn deref(&self) -> &Self::Target {
        &self.lookup_options
    }
}

impl From<LookupIpOptions> for LookupOptions {
    fn from(value: LookupIpOptions) -> Self {
        value.lookup_options
    }
}

impl From<&LookupIpOptions> for LookupOptions {
    fn from(value: &LookupIpOptions) -> Self {
        value.lookup_options.clone()
    }
}

async fn lookup_ip(
    server: &NameServerGroup,
    name: Name,
    options: &LookupIpOptions,
) -> Result<LookupIp, LookupError> {
    use crate::third_ext::FutureJoinAllExt;
    use futures_util::future::{select_all, select_ok};

    assert!(matches!(
        options.record_type,
        RecordType::A | RecordType::AAAA
    ));

    let mut tasks = server
        .iter()
        .map(|ns| per_nameserver_lookup_ip(ns, name.clone(), options).boxed())
        .collect::<Vec<_>>();

    if tasks.is_empty() {
        return Err(ResolveErrorKind::NoConnections.into());
    }

    let ping_duration = |fut: Pin<
        Box<dyn Future<Output = Result<LookupIp, LookupError>> + Send>,
    >| async {
        let res = fut.await;
        let res2 = match res {
            Ok(lookup_ip) => {
                use crate::infra::ping::{ping_fastest, PingAddr, PingOptions};

                let ips = lookup_ip.iter().collect::<Vec<_>>();
                if ips.is_empty() {
                    return Ok((Default::default(), lookup_ip));
                }
                let ping_ops = PingOptions::default().with_timeout_secs(2);

                let mut ping_tasks = vec![];

                for mode in options.speed_check_mode.iter() {
                    let ping_dests = match mode {
                        SpeedCheckMode::None => panic!("unexpected"),
                        SpeedCheckMode::Ping => {
                            ips.iter().map(|ip| PingAddr::Icmp(*ip)).collect::<Vec<_>>()
                        }
                        SpeedCheckMode::Tcp(port) => {
                            debug!(
                                "Speed test {} tcp ping {:?} port {}",
                                lookup_ip.query().name(),
                                ips,
                                port
                            );
                            ips.iter()
                                .map(|ip| PingAddr::Tcp(SocketAddr::new(*ip, *port)))
                                .collect::<Vec<_>>()
                        }
                        SpeedCheckMode::Http(port) => {
                            debug!(
                                "Speed test {} http ping {:?} port {}",
                                lookup_ip.query().name(),
                                ips,
                                port
                            );
                            ips.iter()
                                .map(|ip| PingAddr::Http(SocketAddr::new(*ip, *port)))
                                .collect::<Vec<_>>()
                        }
                        SpeedCheckMode::Https(port) => {
                            debug!(
                                "Speed test {} https ping {:?} port {}",
                                lookup_ip.query().name(),
                                ips,
                                port
                            );
                            ips.iter()
                                .map(|ip| PingAddr::Https(SocketAddr::new(*ip, *port)))
                                .collect::<Vec<_>>()
                        }
                    };

                    ping_tasks.push(ping_fastest(ping_dests, ping_ops).boxed());
                }

                if ping_tasks.is_empty() {
                    return Ok((Default::default(), lookup_ip));
                }

                let ping_res = select_ok(ping_tasks).await;

                match ping_res {
                    Ok((out, _)) => {
                        let dura = out.duration();
                        let lookup = lookup_ip.as_lookup();
                        let query = lookup.query().clone();
                        let valid_until = lookup.valid_until();
                        let records = lookup
                            .records()
                            .iter()
                            .filter(|r| match r.data() {
                                Some(RData::A(ip))
                                    if out.destination() == IpAddr::V4(*ip.deref()) =>
                                {
                                    true
                                }
                                Some(RData::AAAA(ip))
                                    if out.destination() == IpAddr::V6(*ip.deref()) =>
                                {
                                    true
                                }
                                _ => false,
                            })
                            .map(|r| r.to_owned())
                            .collect::<Vec<_>>()
                            .into_boxed_slice();
                        debug!(
                            "The fastest ip of {} is {}",
                            query.name(),
                            out.destination().ip()
                        );
                        let lookup_ip: LookupIp =
                            Lookup::new_with_deadline(query, records.into(), valid_until).into();
                        Ok((dura, lookup_ip))
                    }
                    Err(_) => Ok((Default::default(), lookup_ip)),
                }
            }
            Err(err) => Err(err),
        };
        res2
    };

    use ResponseMode::*;

    // ignore
    let response_strategy = if options.no_speed_check
        || options.speed_check_mode.is_empty()
        || options
            .speed_check_mode
            .iter()
            .any(|m| *m == SpeedCheckMode::None)
    {
        FastestResponse
    } else {
        options.response_strategy
    };

    match response_strategy {
        FirstPing => {
            let mut tasks = tasks
                .into_iter()
                .map(ping_duration)
                .map(|fut| fut.boxed())
                .collect::<Vec<_>>();

            loop {
                let (res, _idx, rest) = select_all(tasks).await;

                if rest.is_empty() {
                    return res.map(|(_, lookup_ip)| lookup_ip);
                }

                match res {
                    Ok((duration, lookup_ip)) => {
                        if duration.as_nanos() > 0 {
                            return Ok(lookup_ip);
                        }
                    }
                    Err(_err) => (),
                }

                tasks = rest;
            }
        }
        FastestIp => {
            let tasks = tasks
                .into_iter()
                .map(ping_duration)
                .map(|fut| fut.boxed())
                .collect::<Vec<_>>();

            let mut min_dura = Duration::MAX;
            let mut fastest_res = None;
            let mut last_res = None;

            // Iterate all to get fastest ip.
            for res in tasks.join_all().await.into_iter() {
                match res {
                    Ok((dura, lookup)) => {
                        if dura < min_dura {
                            fastest_res = Some(Ok(lookup.clone()));
                            min_dura = dura;
                        } else {
                            last_res = Some(Ok(lookup.clone()));
                        }
                    }
                    Err(err) => last_res = Some(Err(err)),
                }
            }

            if let Some(res) = fastest_res {
                res
            } else {
                match last_res {
                    Some(res) => res,
                    None => panic!("no connections"),
                }
            }
        }
        FastestResponse => loop {
            let (res, _idx, rest) = select_all(tasks).await;
            if res.is_ok() {
                return res.map(LookupIp::from);
            }

            if rest.is_empty() {
                return res.map(LookupIp::from);
            }
            tasks = rest;
        },
    }
}

async fn per_nameserver_lookup_ip(
    server: &NameServer,
    name: Name,
    options: &LookupIpOptions,
) -> Result<LookupIp, LookupError> {
    assert!(matches!(
        options.lookup_options.record_type,
        RecordType::A | RecordType::AAAA
    ));

    let res = server.lookup(name.clone(), options).await;

    let ns_opts = server.options();
    let whitelist_on = ns_opts.whitelist_ip;
    let blacklist_on = ns_opts.blacklist_ip;

    let LookupIpOptions {
        whitelist_ip,
        blacklist_ip,
        ignore_ip,
        ..
    } = options;

    if !whitelist_on && !blacklist_on && ignore_ip.is_empty() {
        return res.map(LookupIp::from);
    }

    let ip_filter = |ip: &IpAddr| {
        // whitelist
        if whitelist_on && whitelist_ip.contains(ip) {
            return true;
        }

        if blacklist_on && blacklist_ip.contains(ip) {
            return false;
        }

        !ignore_ip.contains(ip)
    };

    match res {
        Ok(lookup) => {
            let query = lookup.query().clone();

            let records = lookup
                .records()
                .iter()
                .filter(|record| match record.data().map(|data| data.ip_addr()) {
                    Some(Some(ip)) => ip_filter(&ip),
                    _ => false,
                })
                .cloned()
                .collect::<Vec<_>>();

            if records.is_empty() {
                return Err(ResolveErrorKind::NoRecordsFound {
                    query: Box::new(query),
                    soa: None,
                    negative_ttl: None,
                    response_code: ResponseCode::NoError,
                    trusted: false,
                }
                .into());
            }

            Ok(Lookup::new_with_max_ttl(query, records.into()).into())
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::libdns::proto::rr::rdata::opt::ClientSubnet;

    use super::*;
    use crate::{dns_conf::SmartDnsConfig, third_ext::FutureJoinAllExt};

    #[test]
    fn test_edns_client_subnet() {
        async fn inner_test(i: usize) -> bool {
            // https://lite.ip2location.com/ip-address-ranges-by-country

            let servers = [
                "server https://120.53.53.53/dns-query",
                "server https://223.5.5.5/dns-query",
            ];

            let server = servers[i % servers.len()];

            let cfg = SmartDnsConfig::builder().with(server).build();

            let domain = "www.bing.com";

            let client = cfg.create_dns_client().await;

            let subnets = ["113.65.29.0/24", "103.225.87.0/24", "113.65.29.0/24"];

            let results = subnets
                .into_iter()
                .map(|subnet| {
                    client.lookup(
                        domain,
                        LookupOptions {
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
                    let mut ips = lookup.iter().flat_map(|r| r.ip_addr()).collect::<Vec<_>>();
                    ips.sort();
                    ips
                })
                .collect::<Vec<_>>();

            let t1 = results[0].clone();
            let t2 = results[1].clone();
            let t3 = results[2].clone();
            let success = t1 == t3 && t1 != t2;
            if !success {
                println!("{:?}", t1);
                println!("{:?}", t2);
                println!("{:?}", t3);
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
