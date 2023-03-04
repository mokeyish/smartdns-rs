use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::{borrow::Borrow, net::IpAddr, pin::Pin, time::Duration};

use crate::dns_client::NameServer;
use crate::dns_conf::SpeedCheckModeList;
use crate::infra::ipset::IpSet;
use crate::{
    dns::*,
    dns_client::GenericResolver,
    dns_client::{DnsClient, NameServerGroup},
    dns_conf::SpeedCheckMode,
    dns_error::LookupError,
    dns_rule::ResponseMode,
    log::{debug, warn},
    middleware::*,
};

use futures::{Future, FutureExt};
use trust_dns_proto::op::ResponseCode;
use trust_dns_resolver::lookup_ip::LookupIp;

pub struct NameServerMiddleware {
    client: DnsClient,
}

impl NameServerMiddleware {
    pub fn new(client: DnsClient) -> Self {
        Self { client }
    }

    fn get_name_server_group(&self, ctx: &DnsContext) -> Arc<NameServerGroup> {
        let client = &self.client;
        if let Some(name) = ctx.server_opts.group() {
            match client.get_server_group(name) {
                Some(ns) => ns,
                None => {
                    warn!("nameserver group {} not found, fallback to default", name);
                    client.default()
                }
            }
        } else {
            let mut node = ctx.domain_rule.as_ref();

            while let Some(rule) = node {
                if let Some(name) = rule.nameserver.as_deref() {
                    match client.get_server_group(name) {
                        Some(ns) => return ns,
                        None => {
                            debug!("nameserver group {} not found, fallback to parent", name);
                        }
                    }
                }

                node = rule.zone();
            }
            client.default()
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

        // skip nameserver rule
        if ctx.server_opts.no_rule_nameserver() {
            return client.lookup(name.clone(), rtype).await;
        }

        let name_server_group = self.get_name_server_group(ctx);

        debug!(
            "query name: {} type: {} via [group:{}]",
            name,
            rtype,
            name_server_group.name().as_str()
        );

        ctx.source = LookupFrom::Server(name_server_group.name().to_string());

        if rtype.is_ip_addr() {
            let cfg = ctx.cfg();

            let opts = match ctx.domain_rule.as_ref() {
                Some(rule) => LookupIpOptions {
                    response_strategy: rule
                        .response_mode
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
                },
                None => LookupIpOptions {
                    response_strategy: cfg.response_mode(),
                    speed_check_mode: cfg.speed_check_mode().clone(),
                    no_speed_check: ctx.server_opts.no_speed_check(),
                    ignore_ip: cfg.ignore_ip().clone(),
                    blacklist_ip: cfg.blacklist_ip().clone(),
                    whitelist_ip: cfg.whitelist_ip().clone(),
                },
            };

            match lookup_ip(name_server_group.deref(), name.clone(), rtype, &opts).await {
                Ok(lookup_ip) => Ok(lookup_ip.into()),
                Err(_err) if !name_server_group.name().is_default() => {
                    // fallback to default
                    lookup_ip(client.default().as_ref(), name.clone(), rtype, &opts)
                        .await
                        .map(|lookup_ip| lookup_ip.into())
                }
                Err(err) => Err(err),
            }
        } else {
            name_server_group.lookup(name.clone(), rtype).await
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
}

async fn lookup_ip(
    server: &NameServerGroup,
    name: Name,
    record_type: RecordType,
    options: &LookupIpOptions,
) -> Result<LookupIp, LookupError> {
    use crate::third_ext::FutureJoinAllExt;
    use futures_util::future::{select_all, select_ok};

    assert!(matches!(record_type, RecordType::A | RecordType::AAAA));

    let mut tasks = server
        .iter()
        .map(|ns| per_nameserver_lookup_ip(ns, name.clone(), record_type, options).boxed())
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
                    };

                    ping_tasks.push(ping_fastest(ping_dests, ping_ops).boxed());
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
                                Some(RData::A(ip)) if out.destination() == IpAddr::V4(*ip) => true,
                                Some(RData::AAAA(ip)) if out.destination() == IpAddr::V6(*ip) => {
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
    record_type: RecordType,
    options: &LookupIpOptions,
) -> Result<LookupIp, LookupError> {
    assert!(matches!(record_type, RecordType::A | RecordType::AAAA));

    let res = server.lookup(name.clone(), record_type).await;

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
                .filter(|record| match record.data().map(|data| data.to_ip_addr()) {
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
