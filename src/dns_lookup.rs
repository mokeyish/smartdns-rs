use std::{collections::HashMap, net::IpAddr, ops::Deref, sync::Arc, time::Duration};

use futures::FutureExt;
use tokio::time::sleep;

use crate::{
    config::{ResponseMode, SpeedCheckMode, SpeedCheckModeList},
    dns::DnsResponse,
    dns_client::{DnsResolver, LookupOptions, NameServer, NameServerGroup, Splits},
    dns_error::LookupError,
    infra::ipset::{IpMap, IpSet},
    infra::ping::{PingError, PingOutput},
    log::debug,
    third_ext::FutureTimeoutExt,
};

use crate::libdns::{
    proto::{
        AuthorityData, ProtoErrorKind,
        op::ResponseCode,
        rr::{
            RecordType,
            domain::{IntoName, Name},
        },
    },
    resolver::config::ResolverOpts,
};

/// Strategy layer: orchestrates a lookup against a primary group plus the
/// optional `fallback` backup group, applying the IP speed-check strategy for
/// IP records. The low-level fan-out lives in `dns_client::NameServerGroup::
/// query_servers`; this type only decides *which* servers to fan out to and
/// *how* to combine the results.
pub struct LookupStrategy {
    group: Arc<NameServerGroup>,
    /// The group that backs up every other group (see `FALLBACK_GROUP`).
    fallback_group: Option<Arc<NameServerGroup>>,
    /// Whether `group` is already the `fallback` group (prevents a retry loop).
    is_fallback_group: bool,
    /// IP speed-check options; `None` for non-IP lookups.
    ip: Option<LookupIpOptions>,
}

impl LookupStrategy {
    pub fn new(
        group: Arc<NameServerGroup>,
        fallback_group: Option<Arc<NameServerGroup>>,
        is_fallback_group: bool,
        ip: Option<LookupIpOptions>,
    ) -> Self {
        Self {
            group,
            fallback_group,
            is_fallback_group,
            ip,
        }
    }

    /// One round against `group`: its primary servers first, then the group's
    /// own `-fallback` servers only if that round produced no usable answer. IP
    /// lookups apply the speed-check strategy; others use a plain fan-out.
    async fn query_round(
        &self,
        group: &NameServerGroup,
        name: Name,
        plain: LookupOptions,
    ) -> Result<DnsResponse, LookupError> {
        let build_round = |servers: Vec<Arc<NameServer>>| async {
            self.query_set(servers, &name, plain.clone()).await
        };
        with_fallback(group, build_round).await
    }

    /// Fan out a single query over `servers`: plain when there are no IP
    /// options, otherwise with the IP speed-check strategy.
    async fn query_set(
        &self,
        servers: Vec<Arc<NameServer>>,
        name: &Name,
        plain: LookupOptions,
    ) -> Result<DnsResponse, LookupError> {
        match self.ip.as_ref() {
            None => NameServerGroup::query_servers(servers, name.clone(), plain).await,
            Some(ip) => lookup_ip(servers, name.clone(), ip.clone()).await,
        }
    }
}

#[async_trait::async_trait]
impl DnsResolver for LookupStrategy {
    fn options(&self) -> &ResolverOpts {
        self.group.as_ref().options()
    }

    /// A round against the primary group; when that round fails and we are not
    /// already the `fallback` group itself, a single retry round against the
    /// `fallback` group. When both fail the primary result is kept.
    async fn lookup<N: IntoName + Send, O: Into<LookupOptions> + Send + Clone>(
        &self,
        name: N,
        options: O,
    ) -> Result<DnsResponse, LookupError> {
        let name = name.into_name()?;
        let plain: LookupOptions = options.into();

        let res = self
            .query_round(&self.group, name.clone(), plain.clone())
            .await;

        with_fallback_group(
            &res,
            self.is_fallback_group,
            self.fallback_group.as_deref(),
            || async move {
                self.query_round(self.fallback_group.as_ref().unwrap(), name, plain)
                    .await
            },
        )
        .await
    }
}

/// One lookup round against `group`: its primary servers first, then the
/// group's own `-fallback` servers only when the primary round produced no
/// usable answer.
///
/// `build_round` is called with the (owned) servers to query and returns a
/// future for that round.
///
/// - No fallback servers: a single round against all servers.
/// - All servers are fallback: a single round against them (degenerate case).
/// - Both kinds: a primary round first; if it failed, a fallback round runs.
///   The fallback's answer is returned when it is usable; otherwise the
///   primary's result is kept as the root cause.
async fn with_fallback<R, F>(
    group: &NameServerGroup,
    mut build_round: F,
) -> Result<DnsResponse, LookupError>
where
    R: std::future::Future<Output = Result<DnsResponse, LookupError>>,
    F: FnMut(Vec<Arc<NameServer>>) -> R,
{
    let Splits { primary, fallback } = group.split();

    // No fallback servers: plain lookup.
    if fallback.is_empty() {
        return build_round(primary).await;
    }

    // All servers are fallback: they are the only option, query once.
    if primary.is_empty() {
        return build_round(fallback).await;
    }

    // Primary first; fall back only when its server failed.
    let primary_result = build_round(primary).await;
    if is_usable(&primary_result) {
        return primary_result;
    }

    let fallback_result = build_round(fallback).await;
    if is_usable(&fallback_result) {
        fallback_result
    } else {
        // Neither round produced an answer: keep the primary result so the
        // caller sees the root cause.
        primary_result
    }
}

/// Applies group-level fallback to an already-finished round: when the round
/// failed and there is a non-empty `fallback` group (and we are not already
/// querying it), the query is retried once against that group.
///
/// `build_fallback` lazily builds the single fallback-group round, so the
/// backup group is only queried when actually needed. The fallback's answer is
/// returned when it is usable; otherwise `primary` is kept as the root cause.
async fn with_fallback_group<F, F2>(
    primary: &Result<DnsResponse, LookupError>,
    current_is_fallback: bool,
    fallback_group: Option<&NameServerGroup>,
    build_fallback: F,
) -> Result<DnsResponse, LookupError>
where
    F: FnOnce() -> F2,
    F2: std::future::Future<Output = Result<DnsResponse, LookupError>>,
{
    let fallback_available =
        !current_is_fallback && matches!(fallback_group, Some(g) if !g.is_empty());

    if is_usable(primary) || !fallback_available {
        return primary.clone();
    }

    let fallback_result = build_fallback().await;
    if is_usable(&fallback_result) {
        fallback_result
    } else {
        primary.clone()
    }
}

/// A round result is usable when it is `Ok` and not a server failure
/// (`ServFail`).
#[inline]
fn is_usable(res: &Result<DnsResponse, LookupError>) -> bool {
    res.as_ref().is_ok_and(|r| !r.is_failed())
}

#[derive(Clone)]
pub struct LookupIpOptions {
    pub response_strategy: ResponseMode,
    pub speed_check_mode: Option<SpeedCheckModeList>,
    pub no_speed_check: bool,
    pub ignore_ip: Arc<IpSet>,
    pub whitelist_ip: Arc<IpSet>,
    pub blacklist_ip: Arc<IpSet>,
    pub ip_alias: Arc<IpMap<Arc<[IpAddr]>>>,
    pub lookup_options: LookupOptions,
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

/// Resolves `name` against `servers` using the configured IP strategy:
/// pick the fastest IP by pinging, fall back to a majority-vote, or just the
/// fastest response.
async fn lookup_ip(
    servers: Vec<Arc<NameServer>>,
    name: Name,
    options: LookupIpOptions,
) -> Result<DnsResponse, LookupError> {
    use ResponseMode::*;
    use futures_util::future::{Either, select, select_all};

    assert!(options.record_type.is_ip_addr());

    let mut query_tasks = servers
        .iter()
        .map(|ns| query_one(ns, name.clone(), &options).boxed())
        .collect::<Vec<_>>();

    if query_tasks.is_empty() {
        return Err(ProtoErrorKind::NoConnections.into());
    }

    // ignore speed check
    let mut response_strategy = if options.no_speed_check || options.speed_check_mode.is_none() {
        FastestResponse
    } else {
        options.response_strategy
    };

    let mut speed_check_mode = options
        .speed_check_mode
        .as_ref()
        .map(|m| m.as_slice())
        .unwrap_or_default();

    if speed_check_mode.iter().any(|m| m.is_none()) {
        response_strategy = FastestResponse; // ignore speed check
        speed_check_mode = &[];
    }

    let mut ok_tasks = vec![];
    let mut err_tasks = vec![];

    let selected_ip = match response_strategy {
        FirstPing => {
            let mut ping_tasks = vec![];
            let mut fastest_ip = None;
            loop {
                let (ping_res, query_res) = match (query_tasks.len(), ping_tasks.len()) {
                    (0, 0) => break,
                    (0, _) => {
                        let (fastest_ip, _, rest) = select_all(ping_tasks).await;
                        ping_tasks = rest;
                        (fastest_ip, None)
                    }
                    (_, 0) => {
                        let (res, _idx, rest) = select_all(query_tasks).await;
                        query_tasks = rest;
                        (None, Some(res))
                    }
                    _ => {
                        let a = select_all(ping_tasks);
                        let b = select_all(query_tasks);
                        let c = select(a, b).await;
                        match c {
                            Either::Left(((fastest_ip, _, rest), other)) => {
                                ping_tasks = rest;
                                query_tasks = other.into_inner();
                                (fastest_ip, None)
                            }
                            Either::Right(((res, _, rest), other)) => {
                                query_tasks = rest;
                                ping_tasks = other.into_inner();
                                (None, Some(res))
                            }
                        }
                    }
                };

                if let Some(ip) = ping_res {
                    fastest_ip = Some(ip);
                    break;
                }

                match query_res {
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
                                    speed_check_mode.to_vec(),
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

            match fastest_ip {
                Some(ip) => Some(ip),
                None => {
                    let ip_addr_stats = ok_tasks.iter().flat_map(|r| r.ip_addrs()).fold(
                        HashMap::<IpAddr, usize>::new(),
                        |mut map, ip| {
                            map.entry(ip).and_modify(|n| *n += 1).or_insert(1);
                            map
                        },
                    );
                    ip_addr_stats
                        .into_iter()
                        .max_by_key(|(_, n)| *n)
                        .map(|(ip, _)| ip)
                }
            }
        }
        FastestIp => {
            let mut ping_tasks = vec![];

            let mut ip_addr_stats = HashMap::new();

            let mut fastest_ip: Option<PingOutput> = None;

            loop {
                #[allow(clippy::type_complexity)]
                let (ping_res, query_res): (
                    Option<Result<PingOutput, PingError>>,
                    Option<Result<DnsResponse, LookupError>>,
                ) = match (query_tasks.len(), ping_tasks.len()) {
                    (0, 0) => break,
                    (0, _) => {
                        let (res, _idx, rest) = select_all(ping_tasks).await;
                        ping_tasks = rest;
                        (Some(res), None)
                    }
                    (_, 0) => {
                        let (res, _idx, rest) = select_all(query_tasks).await;
                        query_tasks = rest;
                        (None, Some(res))
                    }
                    _ => {
                        let a = select_all(ping_tasks);
                        let b = select_all(query_tasks);
                        let c = select(a, b).await;
                        match c {
                            Either::Left(((res, _, rest), other)) => {
                                ping_tasks = rest;
                                query_tasks = other.into_inner();
                                (Some(res), None)
                            }
                            Either::Right(((res, _, rest), other)) => {
                                query_tasks = rest;
                                ping_tasks = other.into_inner();
                                (None, Some(res))
                            }
                        }
                    }
                };

                if let Some(Ok(out)) = ping_res
                    && match fastest_ip.as_ref() {
                        Some(t) => out.elapsed() < t.elapsed(),
                        None => {
                            // first get speed, add timeout
                            query_tasks = query_tasks
                                .into_iter()
                                .map(|q| {
                                    async {
                                        match q.timeout(Duration::from_millis(200)).await {
                                            Ok(t) => t,
                                            Err(_) => Err(ProtoErrorKind::Timeout.into()),
                                        }
                                    }
                                    .boxed()
                                })
                                .collect();

                            true
                        }
                    }
                {
                    fastest_ip = Some(out);
                }

                if let Some(res) = query_res {
                    match res {
                        Ok(lookup) => {
                            let ip_addrs = lookup.ip_addrs();

                            for ip_addr in &ip_addrs {
                                *ip_addr_stats.entry(*ip_addr).or_insert_with(|| {
                                    ping_tasks.push(
                                        multi_mode_ping(
                                            name.clone(),
                                            *ip_addr,
                                            speed_check_mode.to_vec(),
                                        )
                                        .boxed(),
                                    );
                                    0u8
                                }) += 1;
                            }
                            ok_tasks.push(lookup);
                        }
                        Err(err) => {
                            err_tasks.push(err);
                        }
                    }
                }
            }

            match fastest_ip {
                Some(fastest_ip) => Some(fastest_ip.dest().ip_addr()),
                None => ip_addr_stats
                    .into_iter()
                    .max_by_key(|(_, n)| *n)
                    .map(|(ip, _)| ip),
            }
        }
        FastestResponse => {
            let mut last_error = None;
            loop {
                let (res, _idx, rest) = select_all(query_tasks).await;
                if let Ok(response) = &res
                    && response.response_code() == ResponseCode::NoError
                {
                    return res;
                }

                if rest.is_empty() {
                    return res;
                }

                if let Err(err) = res {
                    if matches!(last_error, Some(e) if e == err) {
                        return Err(err);
                    } else {
                        last_error = Some(err);
                    }
                }
                query_tasks = rest;
            }
        }
    };

    if let Some(selected_ip) = selected_ip {
        for mut res in ok_tasks {
            let record = res
                .take_answers()
                .into_iter()
                .find(|r| matches!(r.data().ip_addr(), Some(ip) if ip == selected_ip));
            if let Some(record) = record {
                res.add_answer(record);
                return Ok(res);
            }
        }
        unreachable!()
    }

    match ok_tasks.into_iter().next() {
        Some(lookup) => Ok(lookup),
        None => match err_tasks.into_iter().next() {
            Some(err) => Err(err),
            None => unreachable!(),
        },
    }
}

/// Ping every `ip_addrs` with each speed-check mode until one succeeds; return
/// the IP it reached.
async fn multi_mode_ping_fastest(
    name: Name,
    ip_addrs: Vec<IpAddr>,
    modes: Vec<SpeedCheckMode>,
) -> Option<IpAddr> {
    use crate::infra::ping::{PingOptions, ping_fastest};
    let duration = Duration::from_millis(200);
    let ping_ops = PingOptions::default().with_timeout_secs(2);

    let mut fastest_ip = None;

    for mode in &modes {
        debug!("Speed test {} {:?} ping {:?}", name, mode, ip_addrs);
        let dests = mode.to_ping_addrs(&ip_addrs);

        let ping_task = ping_fastest(dests, ping_ops).boxed();
        let timeout_task = sleep(duration).boxed();
        match futures_util::future::select(ping_task, timeout_task).await {
            futures::future::Either::Left((ping_res, _)) => {
                match ping_res {
                    Ok(ping_out) => {
                        // ping success
                        let ip = ping_out.dest().ip_addr();
                        debug!(
                            "The fastest ip of {} is {}, delay: {:?}",
                            name,
                            ip,
                            ping_out.elapsed()
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

/// Ping `ip_addr` with each speed-check mode in turn; return the first one
/// that succeeds.
async fn multi_mode_ping(
    name: Name,
    ip_addr: IpAddr,
    modes: Vec<SpeedCheckMode>,
) -> Result<PingOutput, PingError> {
    use crate::infra::ping::{PingOptions, ping};
    let duration = Duration::from_millis(200);
    let ping_ops = PingOptions::default().with_timeout_secs(2);

    for mode in &modes {
        let dest = match mode.to_ping_addr(ip_addr) {
            Some(addr) => addr,
            None => return Err(PingError::NoAddress),
        };

        let ping_task = ping(dest, ping_ops).boxed();
        let timeout_task = sleep(duration).boxed();
        match futures_util::future::select(ping_task, timeout_task).await {
            futures::future::Either::Left((ping_res, _)) => match ping_res {
                Ok(ping_out) => {
                    debug!(
                        "Speed test {} {:?} ping {:?} elapsed {:?}",
                        name,
                        mode,
                        ip_addr,
                        ping_out.elapsed()
                    );
                    return Ok(ping_out);
                }
                Err(_) => continue,
            },
            futures::future::Either::Right((_, _)) => {
                // timeout
                continue;
            }
        }
    }

    Err(PingError::Timeout)
}

/// Query a single server and apply the IP filter/aliasing rules.
async fn query_one(
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
        ip_alias,
        ignore_ip,
        ..
    } = options;

    if !whitelist_on && !blacklist_on && ignore_ip.is_empty() && ip_alias.is_empty() {
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

            let answers = lookup.take_answers();
            let answers = {
                let mut new_ans = Vec::new();
                let mut alias_set = Vec::new(); // dedup
                for record in answers {
                    let Some(ip) = record.data().ip_addr().filter(ip_filter) else {
                        continue;
                    };
                    match ip_alias.get(&ip) {
                        None => new_ans.push(record),
                        Some(ip) if !alias_set.contains(&ip.as_ptr()) => {
                            alias_set.push(ip.as_ptr());
                            new_ans.extend(ip.iter().filter_map(|&ip| {
                                let mut record = record.clone();
                                record.set_data(ip.into());
                                match (options.record_type, ip) {
                                    (RecordType::A, IpAddr::V4(_))
                                    | (RecordType::AAAA, IpAddr::V6(_)) => Some(record),
                                    _ => {
                                        lookup.add_additional(record);
                                        None
                                    }
                                }
                            }));
                        }
                        Some(_) => continue,
                    }
                }
                new_ans
            };

            if answers.is_empty() {
                let no_records = AuthorityData::new(Box::new(query), None, true, true, None);
                return Err(ProtoErrorKind::NoRecordsFound(no_records.into()).into());
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
    use super::*;
    use crate::dns_conf::NameServerInfo;
    use crate::dns_url::DnsUrl;
    use crate::libdns::proto::op::ResponseCode;
    use crate::libdns::resolver::config::ResolverOpts;
    use std::str::FromStr;
    use std::sync::Mutex;

    /// Builds a `NameServer` from a plain IP URL, tagged as a fallback or not.
    fn make_server(url: &str, fallback: bool) -> Arc<NameServer> {
        let mut info: NameServerInfo = DnsUrl::from_str(url).unwrap().into();
        info.fallback = fallback;
        Arc::new(NameServer::new(info, None, None, None, None).unwrap())
    }

    fn make_group(servers: Vec<Arc<NameServer>>) -> NameServerGroup {
        NameServerGroup {
            resolver_opts: Arc::new(ResolverOpts::default()),
            servers,
        }
    }

    /// Builds an `Ok`-valued response carrying the given response code. A
    /// rate-limited public DNS provider answers with `ServFail`, which is still
    /// an `Ok` at this layer but must count as a "failed" round so the fallback
    /// runs.
    fn response_with_code(code: ResponseCode) -> DnsResponse {
        let mut res = DnsResponse::empty();
        res.set_response_code(code);
        res
    }

    // --- `with_fallback` (per-server `-fallback` split) tests ----------------
    //
    // Driven with a stub round that records which servers each round is given
    // and returns a canned result. No real DNS traffic is generated.

    #[tokio::test]
    async fn test_with_fallback_no_fallback_servers_single_round() {
        let group = make_group(vec![
            make_server("223.5.5.5", false),
            make_server("223.6.6.6", false),
        ]);

        let rounds: Mutex<Vec<Vec<bool>>> = Mutex::new(Vec::new());
        let result = with_fallback(&group, |servers| {
            let flags: Vec<bool> = servers.iter().map(|s| s.is_fallback()).collect();
            rounds.lock().unwrap().push(flags);
            async move { Ok(DnsResponse::empty()) }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(*rounds.lock().unwrap(), vec![vec![false, false]]);
    }

    #[tokio::test]
    async fn test_with_fallback_primary_fail_fallback_success() {
        let group = make_group(vec![
            make_server("223.5.5.5", false),
            make_server("223.6.6.6", true),
        ]);

        let rounds: Mutex<Vec<Vec<bool>>> = Mutex::new(Vec::new());
        let result = with_fallback(&group, |servers| {
            let is_fallback_round = servers.iter().all(|s| s.is_fallback());
            let flags: Vec<bool> = servers.iter().map(|s| s.is_fallback()).collect();
            rounds.lock().unwrap().push(flags);
            let outcome: Result<DnsResponse, LookupError> = if is_fallback_round {
                Ok(DnsResponse::empty())
            } else {
                Err(LookupError::NameExists)
            };
            async move { outcome }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(*rounds.lock().unwrap(), vec![vec![false], vec![true]]);
    }

    #[tokio::test]
    async fn test_with_fallback_primary_rate_limited_fallback_success() {
        // The #743 scenario: the primary answers `ServFail` (rate limiting) —
        // still an `Ok` — so the fallback round must run and its answer be
        // returned.
        let group = make_group(vec![
            make_server("223.5.5.5", false),
            make_server("223.6.6.6", true),
        ]);

        let rounds: Mutex<Vec<Vec<bool>>> = Mutex::new(Vec::new());
        let result = with_fallback(&group, |servers| {
            let is_fallback_round = servers.iter().all(|s| s.is_fallback());
            let flags: Vec<bool> = servers.iter().map(|s| s.is_fallback()).collect();
            rounds.lock().unwrap().push(flags);
            let outcome: Result<DnsResponse, LookupError> = if is_fallback_round {
                Ok(DnsResponse::empty()) // NoError: fallback works.
            } else {
                Ok(response_with_code(ResponseCode::ServFail)) // rate-limited.
            };
            async move { outcome }
        })
        .await;

        assert!(result.is_ok());
        assert!(!result.unwrap().is_failed());
        assert_eq!(*rounds.lock().unwrap(), vec![vec![false], vec![true]]);
    }

    #[tokio::test]
    async fn test_with_fallback_primary_success_does_not_fall_back() {
        let group = make_group(vec![
            make_server("223.5.5.5", false),
            make_server("223.6.6.6", true),
        ]);

        let rounds: Mutex<Vec<Vec<bool>>> = Mutex::new(Vec::new());
        let result = with_fallback(&group, |servers| {
            let flags: Vec<bool> = servers.iter().map(|s| s.is_fallback()).collect();
            rounds.lock().unwrap().push(flags);
            async move { Ok(DnsResponse::empty()) }
        })
        .await;

        assert!(result.is_ok());
        assert!(!result.as_ref().unwrap().is_failed());
        assert_eq!(*rounds.lock().unwrap(), vec![vec![false]]);
    }

    #[tokio::test]
    async fn test_with_fallback_both_rate_limited_keeps_primary_result() {
        let group = make_group(vec![
            make_server("223.5.5.5", false),
            make_server("223.6.6.6", true),
        ]);

        let rounds: Mutex<Vec<Vec<bool>>> = Mutex::new(Vec::new());
        let result = with_fallback(&group, |servers| {
            let flags: Vec<bool> = servers.iter().map(|s| s.is_fallback()).collect();
            rounds.lock().unwrap().push(flags);
            async move { Ok(response_with_code(ResponseCode::ServFail)) }
        })
        .await;

        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(res.is_failed());
        assert_eq!(res.response_code(), ResponseCode::ServFail);
        assert_eq!(*rounds.lock().unwrap(), vec![vec![false], vec![true]]);
    }

    #[tokio::test]
    async fn test_with_fallback_authoritative_nx_domain_does_not_fall_back() {
        let group = make_group(vec![
            make_server("223.5.5.5", false),
            make_server("223.6.6.6", true),
        ]);

        let rounds: Mutex<Vec<Vec<bool>>> = Mutex::new(Vec::new());
        let result = with_fallback(&group, |servers| {
            let flags: Vec<bool> = servers.iter().map(|s| s.is_fallback()).collect();
            rounds.lock().unwrap().push(flags);
            async move { Ok(response_with_code(ResponseCode::NXDomain)) }
        })
        .await;

        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.response_code(), ResponseCode::NXDomain);
        assert!(!res.is_failed());
        assert_eq!(*rounds.lock().unwrap(), vec![vec![false]]);
    }

    #[tokio::test]
    async fn test_with_fallback_all_fail_keeps_primary_error() {
        let group = make_group(vec![
            make_server("223.5.5.5", false),
            make_server("223.6.6.6", true),
        ]);

        let result = with_fallback(&group, |servers| {
            let is_fallback_round = servers.iter().all(|s| s.is_fallback());
            let outcome: Result<DnsResponse, LookupError> = if is_fallback_round {
                Err(LookupError::ResponseCode(ResponseCode::ServFail))
            } else {
                Err(LookupError::NameExists)
            };
            async move { outcome }
        })
        .await
        .unwrap_err();

        assert_eq!(result, LookupError::NameExists);
    }

    #[tokio::test]
    async fn test_with_fallback_only_fallback_single_round() {
        let group = make_group(vec![make_server("223.6.6.6", true)]);

        let rounds: Mutex<Vec<Vec<bool>>> = Mutex::new(Vec::new());
        let result = with_fallback(&group, |servers| {
            let flags: Vec<bool> = servers.iter().map(|s| s.is_fallback()).collect();
            rounds.lock().unwrap().push(flags);
            async move { Ok(DnsResponse::empty()) }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(*rounds.lock().unwrap(), vec![vec![true]]);
    }

    // --- `with_fallback_group` (group-level `fallback` backup) tests --------
    //
    // Driven with a canned primary result and a stubbed fallback round, so no
    // real DNS traffic is generated.

    /// A non-empty `fallback` group (one primary server).
    fn make_fallback_group() -> Arc<NameServerGroup> {
        Arc::new(make_group(vec![make_server("223.5.5.5", false)]))
    }

    /// Runs `with_fallback_group` and records whether the fallback round ran.
    async fn run_fallback_group(
        group: Option<&NameServerGroup>,
        current_is_fallback: bool,
        primary: Result<DnsResponse, LookupError>,
    ) -> (bool, Result<DnsResponse, LookupError>) {
        let ran = Mutex::new(false);
        let result = with_fallback_group(&primary, current_is_fallback, group, || {
            *ran.lock().unwrap() = true;
            async move { Ok(DnsResponse::empty()) }
        })
        .await;
        (*ran.lock().unwrap(), result)
    }

    #[tokio::test]
    async fn test_fallback_group_primary_succeeds_no_switch() {
        let group = make_fallback_group();
        let primary = Ok(response_with_code(ResponseCode::NoError));
        let (ran, result) = run_fallback_group(Some(group.as_ref()), false, primary).await;
        assert!(!ran, "fallback group must not be queried on success");
        assert!(result.is_ok());
        assert!(!result.as_ref().unwrap().is_failed());
    }

    #[tokio::test]
    async fn test_fallback_group_primary_servfail_switches() {
        let group = make_fallback_group();
        let primary = Ok(response_with_code(ResponseCode::ServFail));
        let (ran, _) = run_fallback_group(Some(group.as_ref()), false, primary).await;
        assert!(ran, "ServFail primary must trigger the fallback group");
    }

    #[tokio::test]
    async fn test_fallback_group_primary_transport_error_switches() {
        let group = make_fallback_group();
        let err = Err(LookupError::Proto(ProtoErrorKind::NoConnections.into()));
        let (ran, _) = run_fallback_group(Some(group.as_ref()), false, err).await;
        assert!(ran, "transport error must trigger the fallback group");
    }

    #[tokio::test]
    async fn test_fallback_group_no_fallback_group() {
        let primary = Err(LookupError::NameExists);
        let (ran, result) = run_fallback_group(None, false, primary.clone()).await;
        assert!(!ran, "no fallback group: nothing to retry against");
        assert_eq!(result, primary);
    }

    #[tokio::test]
    async fn test_fallback_group_empty_fallback_group() {
        let empty = Arc::new(make_group(Vec::new()));
        let primary = Err(LookupError::NameExists);
        let (ran, result) = run_fallback_group(Some(empty.as_ref()), false, primary.clone()).await;
        assert!(!ran, "an empty fallback group is not a usable backup");
        assert_eq!(result, primary);
    }

    #[tokio::test]
    async fn test_fallback_group_current_is_fallback_no_loop() {
        let group = make_fallback_group();
        let primary = Err(LookupError::NameExists);
        let (ran, result) = run_fallback_group(Some(group.as_ref()), true, primary.clone()).await;
        assert!(
            !ran,
            "a query against the fallback group must not retry itself"
        );
        assert_eq!(result, primary);
    }

    #[test]
    fn test_is_usable() {
        assert!(is_usable(&Ok(response_with_code(ResponseCode::NoError))));
        assert!(is_usable(&Ok(response_with_code(ResponseCode::NXDomain))));
        assert!(!is_usable(&Ok(response_with_code(ResponseCode::ServFail))));
        assert!(!is_usable(&Err(LookupError::NameExists)));
    }
}
