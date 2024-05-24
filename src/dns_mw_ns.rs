use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::{borrow::Borrow, net::IpAddr, time::Duration};

use crate::dns_client::{LookupOptions, NameServer};

use crate::infra::ipset::IpSet;
use crate::infra::ping::PingAddr;
use crate::{
    config::{ResponseMode, SpeedCheckMode, SpeedCheckModeList},
    dns::*,
    dns_client::{DnsClient, GenericResolver, NameServerGroup},
    dns_error::LookupError,
    log::{debug, error},
    middleware::*,
};

use crate::libdns::proto::op::ResponseCode;
use futures::FutureExt;
use tokio::time::sleep;

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

        if rtype.is_ip_addr() {
            if let Some(lookup) = client.lookup_nameserver(name.clone(), rtype).await {
                debug!(
                    "lookup nameserver {} {} ip {:?}",
                    name,
                    rtype,
                    lookup
                        .answers()
                        .iter()
                        .filter_map(|record| record.data().map(|data| data.ip_addr()))
                        .flatten()
                        .collect::<Vec<_>>()
                );
                ctx.no_cache = true;
                return Ok(lookup);
            }
        }

        let lookup_options = LookupOptions {
            is_dnssec: req.is_dnssec(),
            record_type: rtype,
            client_subnet: None,
        };

        // skip nameserver rule
        if ctx.server_opts.no_rule_nameserver() {
            return client.lookup(name.clone(), lookup_options).await;
        }

        let group_name = ctx.server_group_name().to_string();

        let name_server = match client.get_server_group(group_name.as_ref()).await {
            Some(ns) => ns,
            None => {
                error!("no available nameserver found for {}", name);
                return Err(ProtoErrorKind::NoConnections.into());
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

            if ctx.server_opts.is_background {
                opts.response_strategy = ResponseMode::FastestIp;
            }

            lookup_ip(name_server.deref(), name.clone(), &opts).await
        } else {
            name_server.lookup(name.clone(), lookup_options).await
        }
        .map(|res| res.with_name_server_group(group_name.to_string()))
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
) -> Result<DnsResponse, LookupError> {
    use crate::third_ext::FutureJoinAllExt;
    use futures_util::future::{select, select_all, Either};

    assert!(options.record_type.is_ip_addr());

    let mut tasks = server
        .iter()
        .map(|ns| per_nameserver_lookup_ip(ns, name.clone(), options).boxed())
        .collect::<Vec<_>>();

    if tasks.is_empty() {
        return Err(ProtoErrorKind::NoConnections.into());
    }

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

    let mut ok_tasks = vec![];
    let mut err_tasks = vec![];
    let selected_ip = match response_strategy {
        FirstPing => {
            let mut tasks = tasks;
            let mut ping_tasks = vec![];
            let mut selected_ip = None;
            loop {
                let (fastest_ip, res) = match (tasks.len(), ping_tasks.len()) {
                    (0, 0) => break,
                    (0, _) => {
                        let (fastest_ip, _, rest) = select_all(ping_tasks).await;
                        ping_tasks = rest;
                        (fastest_ip, None)
                    }
                    (_, 0) => {
                        let (res, _idx, rest) = select_all(tasks).await;
                        tasks = rest;
                        (None, Some(res))
                    }
                    _ => {
                        let a = select_all(ping_tasks);
                        let b = select_all(tasks);
                        let c = select(a, b).await;
                        match c {
                            Either::Left(((fastest_ip, _, rest), other)) => {
                                ping_tasks = rest;
                                tasks = other.into_inner();
                                (fastest_ip, None)
                            }
                            Either::Right(((res, _, rest), other)) => {
                                tasks = rest;
                                ping_tasks = other.into_inner();
                                (None, Some(res))
                            }
                        }
                    }
                };

                if let Some(fastest_ip) = fastest_ip {
                    selected_ip = Some(fastest_ip);
                    break;
                }

                match res {
                    Some(v) => match v {
                        Ok(lookup) => {
                            let ip_addrs = lookup.ip_addrs();
                            if ip_addrs.len() == 1 {
                                return Ok(lookup);
                            }
                            ok_tasks.push(lookup);
                            ping_tasks.push(
                                multi_mode_ping_fastest(
                                    name.clone(),
                                    ip_addrs,
                                    options.speed_check_mode.to_vec(),
                                )
                                .boxed(),
                            );
                        }
                        Err(err) => {
                            err_tasks.push(err);
                        }
                    },
                    None => break,
                }
            }

            let selected_ip = match selected_ip {
                Some(selected_ip) => Some(selected_ip),
                None => {
                    let ip_addrs_map = ok_tasks.iter().flat_map(|r| r.ip_addrs()).fold(
                        HashMap::<IpAddr, usize>::new(),
                        |mut map, ip| {
                            map.entry(ip).and_modify(|n| *n += 1).or_insert(1);
                            map
                        },
                    );
                    ip_addrs_map
                        .into_iter()
                        .max_by_key(|(_, n)| *n)
                        .map(|(ip, _)| ip)
                }
            };

            selected_ip
        }
        FastestIp => {
            for res in tasks.join_all().await {
                match res {
                    Ok(v) => ok_tasks.push(v),
                    Err(e) => err_tasks.push(e),
                }
            }

            if ok_tasks.is_empty() {
                return Err(err_tasks.into_iter().next().unwrap()); // There is definitely one.
            }

            let ip_addrs_map = ok_tasks.iter().flat_map(|r| r.ip_addrs()).fold(
                HashMap::<IpAddr, usize>::new(),
                |mut map, ip| {
                    map.entry(ip).and_modify(|n| *n += 1).or_insert(1);
                    map
                },
            );

            let mut ip_addrs = ip_addrs_map.keys().cloned().collect::<Vec<_>>();

            match ip_addrs.len() {
                0 => None,
                1 => ip_addrs.pop(),
                _ => {
                    let fastest_ip = multi_mode_ping_fastest(
                        name.clone(),
                        ip_addrs,
                        options.speed_check_mode.to_vec(),
                    )
                    .await;

                    fastest_ip.or_else(|| {
                        ip_addrs_map
                            .into_iter()
                            .max_by_key(|(_, n)| *n)
                            .map(|(ip, _)| ip)
                    })
                }
            }
        }
        FastestResponse => loop {
            let (res, _idx, rest) = select_all(tasks).await;
            if rest.is_empty()
                || matches!(&res, Ok(res) if res.answers().iter().any(|r| r.record_type() == options.record_type))
            {
                return res;
            }
            tasks = rest;
        },
    };

    if let Some(selected_ip) = selected_ip {
        for mut res in ok_tasks {
            let record = res.take_answers().into_iter().find(
                |r| matches!(r.data().and_then(|d| d.ip_addr()), Some(ip) if ip == selected_ip),
            );
            if let Some(record) = record {
                res.add_answer(record);
                return Ok(res);
            }
        }
        unreachable!()
    }

    Ok(ok_tasks.into_iter().next().unwrap()) // There is definitely one.
}

async fn multi_mode_ping_fastest(
    name: Name,
    ip_addrs: Vec<IpAddr>,
    modes: Vec<SpeedCheckMode>,
) -> Option<IpAddr> {
    use crate::infra::ping::{ping_fastest, PingOptions};
    let duaration = Duration::from_millis(200);
    let ping_ops = PingOptions::default().with_timeout_secs(2);

    let mut fastest_ip = None;

    for mode in &modes {
        let dests = match mode {
            SpeedCheckMode::None => continue,
            SpeedCheckMode::Ping => {
                debug!("Speed test {} ping {:?}", name, ip_addrs);
                ip_addrs
                    .iter()
                    .map(|ip| PingAddr::Icmp(*ip))
                    .collect::<Vec<_>>()
            }
            SpeedCheckMode::Tcp(port) => {
                debug!("Speed test {} TCP ping {:?} port {}", name, ip_addrs, port);
                ip_addrs
                    .iter()
                    .map(|ip| PingAddr::Tcp(SocketAddr::new(*ip, *port)))
                    .collect::<Vec<_>>()
            }
            SpeedCheckMode::Http(port) => {
                debug!("Speed test {} HTTP ping {:?} port {}", name, ip_addrs, port);
                ip_addrs
                    .iter()
                    .map(|ip| PingAddr::Http(SocketAddr::new(*ip, *port)))
                    .collect::<Vec<_>>()
            }
            SpeedCheckMode::Https(port) => {
                debug!(
                    "Speed test {} HTTPS ping {:?} port {}",
                    name, ip_addrs, port
                );
                ip_addrs
                    .iter()
                    .map(|ip| PingAddr::Https(SocketAddr::new(*ip, *port)))
                    .collect::<Vec<_>>()
            }
        };

        let ping_task = ping_fastest(dests, ping_ops).boxed();
        let timeout_task = sleep(duaration).boxed();
        match futures_util::future::select(ping_task, timeout_task).await {
            futures::future::Either::Left((ping_res, _)) => {
                match ping_res {
                    Ok(ping_out) => {
                        // ping success
                        let ip = ping_out.destination().ip();
                        debug!(
                            "The fastest ip of {} is {}, delay: {:?}",
                            name,
                            ip,
                            ping_out.duration()
                        );
                        fastest_ip = Some(ip);
                        break;
                    }
                    Err(_) => continue,
                }
            }
            futures::future::Either::Right((_, _)) => {
                // timeout
                continue;
            }
        }
    }

    fastest_ip
}

async fn per_nameserver_lookup_ip(
    server: &NameServer,
    name: Name,
    options: &LookupIpOptions,
) -> Result<DnsResponse, LookupError> {
    assert!(options.lookup_options.record_type.is_ip_addr());

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
        return res;
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
        Ok(mut lookup) => {
            let query = lookup.query().clone();

            let answers = lookup
                .answers()
                .iter()
                .filter(|record| match record.data().map(|data| data.ip_addr()) {
                    Some(Some(ip)) => ip_filter(&ip),
                    _ => false,
                })
                .cloned()
                .collect::<Vec<_>>();

            if answers.is_empty() {
                return Err(ProtoErrorKind::NoRecordsFound {
                    query: Box::new(query),
                    soa: None,
                    negative_ttl: None,
                    response_code: ResponseCode::NoError,
                    trusted: false,
                }
                .into());
            }

            *lookup.answers_mut() = answers;
            lookup.set_valid_until_max();

            Ok(lookup)
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::libdns::proto::rr::rdata::opt::ClientSubnet;

    use super::*;
    use crate::{dns_conf::RuntimeConfig, third_ext::FutureJoinAllExt};

    #[test]
    fn test_edns_client_subnet() {
        async fn inner_test(i: usize) -> bool {
            // https://lite.ip2location.com/ip-address-ranges-by-country

            let servers = [
                "server https://120.53.53.53/dns-query",
                "server https://223.5.5.5/dns-query",
            ];

            let server = servers[i % servers.len()];

            let cfg = RuntimeConfig::builder().with(server).build();

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
