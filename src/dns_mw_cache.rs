use std::collections::HashMap;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::config::ServerOpts;
use crate::dns_conf::RuntimeConfig;
use crate::libdns::proto::error::ProtoResult;
use crate::server::DnsHandle;
use crate::{
    dns::*,
    libdns::proto::{
        op::{Message, Query},
        rr::DNSClass,
    },
    log::{debug, error, info},
    middleware::*,
};
use lru::LruCache;
use tokio::sync::Notify;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::sleep;

pub struct DnsCacheMiddleware {
    cfg: Arc<RuntimeConfig>,
    cache: Arc<DnsCache>,
    prefetch_notify: Arc<DomainPrefetchingNotify>,
    bg_client: DnsHandle,
}

impl DnsCacheMiddleware {
    pub fn new(cfg: &Arc<RuntimeConfig>, dns_handle: DnsHandle) -> Self {
        // create
        let mut ttl = TtlOpts::default();

        if let Some(positive_min_ttl) = cfg.rr_ttl_min().map(Duration::from_secs) {
            ttl.set_positive_min(positive_min_ttl);
        }

        if let Some(positive_max_ttl) = cfg.rr_ttl_max().map(Duration::from_secs) {
            ttl.set_positive_min(positive_max_ttl);
        }
        ttl.set_negative_max(Duration::from_secs(cfg.serve_expired_ttl()));
        ttl.set_negative_min(Duration::from_secs(cfg.serve_expired_reply_ttl()));

        let cache = DnsCache::new(cfg.cache_size(), ttl);

        if cfg.cache_persist() {
            let cache_file = cfg.cache_file();
            let cache = cache.cache();
            tokio::spawn(async move {
                if cache_file.exists() {
                    cache.lock().await.load(cache_file.as_path());
                }
                crate::signal::terminate()
                    .await
                    .expect("failed to wait ctrl_c for persist cache.");
                cache.lock().await.persist(cache_file.as_path());
            });
        }

        let mw = Self {
            cfg: cfg.clone(),
            cache: Arc::new(cache),
            prefetch_notify: Arc::new(DomainPrefetchingNotify::new()),
            bg_client: dns_handle.with_new_opt(ServerOpts {
                is_background: true,
                ..Default::default()
            }),
        };

        if cfg.prefetch_domain() {
            mw.start_prefetching();
        };

        mw
    }

    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }

    fn start_prefetching(&self) {
        let prefetch_notify = self.prefetch_notify.clone();

        let (tx, mut rx) = mpsc::channel::<Vec<Query>>(100);

        let client = self.bg_client.clone();

        let cache = self.cache.cache();

        {
            // prefetch domain.
            tokio::spawn(async move {
                let querying: Arc<Mutex<HashSet<Query>>> = Default::default();

                loop {
                    if let Some(queries) = rx.recv().await {
                        let client = client.clone();
                        let querying = querying.clone();

                        for query in queries {
                            if !querying.lock().await.insert(query.clone()) {
                                continue;
                            }
                            let querying = querying.clone();

                            let (client, name, typ) =
                                (client.clone(), query.name().to_owned(), query.query_type());
                            tokio::spawn(async move {
                                let now = Instant::now();
                                let mut message = Message::new();
                                message.add_query(query.clone());
                                client.send(message.into()).await;

                                debug!(
                                    "Prefetch domain {} {}, elapsed {:?}",
                                    name,
                                    typ,
                                    now.elapsed()
                                );
                                querying.lock().await.remove(&query);
                            });
                        }
                    }
                }
            });
        }

        {
            // check expired domain.
            let cache = cache.clone();
            let prefetch_notify = prefetch_notify.clone();

            tokio::spawn(async move {
                let min_interval = Duration::from_secs(
                    std::env::var("PREFETCH_MIN_INTERVAL")
                        .as_deref()
                        .unwrap_or("1")
                        .parse()
                        .unwrap_or(1),
                );
                let mut last_check = Instant::now();

                loop {
                    prefetch_notify.notified().await;

                    let now = Instant::now();
                    let mut most_recent;
                    if now - last_check > min_interval {
                        last_check = now;

                        most_recent = Duration::from_secs(MAX_TTL as u64);
                        let mut expired = vec![];

                        {
                            let mut cache = cache.lock().await;
                            let len = cache.len();
                            if len == 0 {
                                continue;
                            }

                            for (query, entry) in cache.iter_mut() {
                                if entry.is_in_prefetching {
                                    continue;
                                }
                                // only prefetch query type ip addr
                                if !query.query_type().is_ip_addr() {
                                    continue;
                                }

                                if entry.is_current(now) {
                                    most_recent = most_recent.min(entry.ttl(now));
                                    continue;
                                }

                                entry.is_in_prefetching = true;

                                expired.push(query.to_owned());
                            }
                            debug!(
                                "Domain prefetch check(total: {}), elapsed {:?}",
                                len,
                                now.elapsed()
                            );
                        }

                        if !expired.is_empty() && tx.send(expired).await.is_err() {
                            error!("Failed to send queries to prefetch domain!");
                        }
                    } else {
                        most_recent = Duration::ZERO;
                    }

                    // sleep and wait for next check.
                    let dura = most_recent.max(min_interval);
                    prefetch_notify.notify_after(dura).await;
                }
            });
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
        // skip cache
        if ctx.server_opts.no_cache() || ctx.no_cache || req.is_dnssec() {
            return next.run(ctx, req).await;
        }

        let query = req.query().original().to_owned();

        let cached_res = if ctx.server_opts.is_background {
            None
        } else {
            let cached_res = self.cache.get(&query, Instant::now()).await;

            if let Some((outdate, res)) = cached_res.as_ref() {
                match outdate {
                    OutOfDate::No => {
                        let name_server_group = ctx.server_group_name();
                        // check if it's the same nameserver group.
                        if matches!(res, Ok(r) if r.name_server_group() == Some(name_server_group))
                        {
                            debug!("name: {} using caching", query.name());
                            ctx.source = LookupFrom::Cache;
                            return res.clone();
                        }
                    }
                    OutOfDate::Yes => {
                        if self.cfg.serve_expired() {
                            if let Ok(res) = res {
                                if matches!(res.max_ttl(), Some(ttl) if ttl < self.cfg.serve_expired_ttl() as u32 )
                                {
                                    let mut res = res.clone();
                                    res.set_max_ttl(self.cfg.serve_expired_reply_ttl() as u32);
                                    return Ok(res);
                                }
                            }
                        }
                    }
                }
            }

            cached_res
        };

        let res = next.run(ctx, req).await;

        match res {
            Ok(lookup) => {
                if !ctx.no_cache {
                    let query = req.query().original().to_owned();
                    let server_group_name = ctx.server_group_name();

                    self.cache
                        .insert_records(
                            query,
                            lookup.records().iter().cloned(),
                            Instant::now(),
                            server_group_name,
                        )
                        .await;

                    if let Some(ttl) = lookup.min_ttl() {
                        self.prefetch_notify
                            .notify_after(Duration::from_secs(ttl as u64))
                            .await;
                    }
                }
                Ok(lookup)
            }
            Err(err) => {
                // try to return expired result.
                if ctx.cfg().serve_expired() {
                    if let Some((_, Ok(res))) = cached_res {
                        return Ok(res);
                    }
                }
                Err(err)
            }
        }
    }
}

struct DomainPrefetchingNotify {
    notity: Arc<Notify>,
    tick: RwLock<Instant>,
}

impl DomainPrefetchingNotify {
    pub fn new() -> Self {
        Self {
            notity: Default::default(),
            tick: RwLock::new(Instant::now()),
        }
    }

    async fn notify_after(&self, duration: Duration) {
        if duration.is_zero() {
            self.notity.notify_one()
        } else {
            let now = Instant::now();
            let tick = *(self.tick.read().await);
            let next_tick = now + duration;
            if tick > now && next_tick > tick {
                debug!(
                    "Domain prefetch check will be performed in {:?}.",
                    tick - now
                );
                return;
            }

            *self.tick.write().await.deref_mut() = next_tick;
            debug!("Domain prefetch check will be performed in {:?}.", duration);
            let notify = self.notity.clone();
            tokio::spawn(async move {
                sleep(duration).await;
                notify.notify_one();
            });
        }
    }
}

impl Deref for DomainPrefetchingNotify {
    type Target = Notify;

    fn deref(&self) -> &Self::Target {
        self.notity.as_ref()
    }
}

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
/// Setting this to a value of 1 day, in seconds
const MAX_TTL: u32 = 86400_u32;

/// An LRU eviction cache specifically for storing DNS records
pub struct DnsCache {
    cache: Arc<Mutex<LruCache<Query, DnsCacheEntry>>>,
    ttl: TtlOpts,
}

impl DnsCache {
    fn new(cache_size: usize, ttl: TtlOpts) -> Self {
        let cache = Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(cache_size).unwrap(),
        )));

        Self { cache, ttl }
    }

    fn cache(&self) -> Arc<Mutex<LruCache<Query, DnsCacheEntry>>> {
        self.cache.clone()
    }

    // fn insert

    pub async fn clear(&self) {
        self.cache.lock().await.clear();
    }

    pub async fn cached_records(&self) -> Vec<CachedQueryRecord> {
        self.cache
            .lock()
            .await
            .iter()
            .flat_map(|(query, v)| match &v.lookup {
                Ok(lookup) => Some(CachedQueryRecord {
                    name: query.name().clone(),
                    query_type: query.query_type(),
                    query_class: query.query_class(),
                    records: lookup.records().to_vec().into_boxed_slice(),
                }),
                Err(_) => None,
            })
            .collect()
    }

    async fn insert(
        &self,
        query: Query,
        records_and_ttl: Vec<(Record, u32)>,
        now: Instant,
        name_server_group: &str,
    ) -> DnsResponse {
        let len = records_and_ttl.len();
        // collapse the values, we're going to take the Minimum TTL as the correct one
        let (records, ttl): (Vec<Record>, Duration) = records_and_ttl.into_iter().fold(
            (Vec::with_capacity(len), self.ttl.positive_max),
            |(mut records, mut min_ttl), (record, ttl)| {
                records.push(record);
                let ttl = Duration::from_secs(u64::from(ttl));
                min_ttl = min_ttl.min(ttl);
                (records, min_ttl)
            },
        );

        // If the cache was configured with a minimum TTL, and that value is higher
        // than the minimum TTL in the values, use it instead.
        let ttl = self.ttl.positive_min.max(ttl);
        let ttl = self.ttl.positive_max.min(ttl);

        let valid_until = now + ttl;

        // insert into the LRU
        let lookup = DnsResponse::new_with_deadline(query.clone(), records, valid_until)
            .with_name_server_group(name_server_group.to_string());

        if let Ok(mut cache) = self.cache.try_lock() {
            cache.put(
                query,
                DnsCacheEntry {
                    lookup: Ok(lookup.clone()),
                    valid_until,
                    is_in_prefetching: false,
                },
            );
        } else {
            debug!("Get dns cache lock to write failed");
        }

        lookup
    }

    /// inserts a record based on the name and type.
    ///
    /// # Arguments
    ///
    /// * `original_query` - is used for matching the records that should be returned
    /// * `records` - the records will be partitioned by type and name for storage in the cache
    /// * `now` - current time for use in associating TTLs
    ///
    /// # Return
    ///
    /// This should always return some records, but will be None if there are no records or the original_query matches none
    async fn insert_records(
        &self,
        original_query: Query,
        records: impl Iterator<Item = Record>,
        now: Instant,
        name_server_group: &str,
    ) -> Option<DnsResponse> {
        let mut is_cname_query = false;
        // collect all records by name
        let records = records.fold(
            HashMap::<Query, Vec<(Record, u32)>>::new(),
            |mut map, record| {
                let mut query = Query::query(record.name().clone(), record.record_type());
                query.set_query_class(record.dns_class());

                let ttl = record.ttl();

                if original_query != query {
                    is_cname_query = true;
                }

                map.entry(query).or_default().push((record, ttl));

                map
            },
        );

        // now insert by record type and name
        let mut lookup = None;

        if is_cname_query {
            let records = records
                .clone()
                .into_iter()
                .flat_map(|(_, r)| r)
                .collect::<Vec<_>>();
            lookup = Some(
                self.insert(original_query.clone(), records, now, name_server_group)
                    .await,
            )
        }

        for (query, records_and_ttl) in records {
            let is_query = original_query == query;
            let inserted = self
                .insert(query, records_and_ttl, now, name_server_group)
                .await;

            if is_query {
                lookup = Some(inserted)
            }
        }

        lookup
    }

    /// This converts the ResolveError to set the inner negative_ttl value to be the
    ///  current expiration ttl.
    fn nx_error_with_ttl(_error: &mut DnsError, _new_ttl: Duration) {
        // if let ResolveError {
        //     kind:
        //         ResolveErrorKind::NoRecordsFound {
        //             ref mut negative_ttl,
        //             ..
        //         },
        //     ..
        // } = error
        // {
        //     *negative_ttl = Some(u32::try_from(new_ttl.as_secs()).unwrap_or(MAX_TTL));
        // }
    }

    /// Based on the query, see if there are any records available
    async fn get(
        &self,
        query: &Query,
        now: Instant,
    ) -> Option<(OutOfDate, Result<DnsResponse, DnsError>)> {
        let mut cache = match self.cache.try_lock() {
            Ok(t) => t,
            Err(err) => {
                debug!("Get dns cache lock to read failed, {:?}", err);
                return None;
            }
        };

        let mut should_pop = false;
        let lookup = cache.get_mut(query).and_then(|value| {
            if value.is_current(now) {
                let result = match value.lookup.clone() {
                    Ok(mut res) => {
                        res.set_max_ttl(value.ttl(now).as_secs() as u32);
                        Ok(res)
                    }
                    Err(mut err) => {
                        Self::nx_error_with_ttl(&mut err, value.ttl(now));
                        Err(err)
                    }
                };

                Some((OutOfDate::No, result))
            } else {
                let negative_ttl = now - value.valid_until;
                if negative_ttl < self.ttl.negative_max {
                    let result = value.lookup.clone();
                    if let Ok(ref mut lookup) = value.lookup {
                        lookup.set_new_ttl(negative_ttl.as_secs() as u32)
                    }
                    Some((OutOfDate::Yes, result))
                } else {
                    should_pop = true;
                    None
                }
            }
        });

        if should_pop {
            cache.pop(query).unwrap();
        }
        lookup
    }
}

#[derive(Deserialize, Serialize)]
pub struct CachedQueryRecord {
    name: Name,
    query_type: RecordType,
    query_class: DNSClass,
    records: Box<[Record]>,
}

struct TtlOpts {
    /// A minimum TTL value for positive responses.
    ///
    /// Positive responses with TTLs under `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    ///
    /// If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to 0.
    positive_min: Duration,

    /// A maximum TTL value for positive responses.
    ///
    /// Positive responses with TTLs over `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    ///
    ///  If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to [`MAX_TTL`] seconds.
    ///
    /// [`MAX_TTL`]: const.MAX_TTL.html
    positive_max: Duration,

    /// A minimum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs under `negative_min_ttl` will use
    /// `negative_min_ttl` instead.
    ///
    /// If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to 0.
    negative_min: Duration,

    /// A maximum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs over `negative_max_ttl` will use
    /// `negative_max_ttl` instead.
    ///
    ///  If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to [`MAX_TTL`] seconds.
    ///
    /// [`MAX_TTL`]: const.MAX_TTL.html
    negative_max: Duration,
}

impl TtlOpts {
    fn default() -> Self {
        Self {
            positive_min: Duration::from_secs(0),
            positive_max: Duration::from_secs(u64::from(MAX_TTL)),
            negative_min: Duration::from_secs(0),
            negative_max: Duration::from_secs(u64::from(MAX_TTL)),
        }
    }

    fn with_positive_min(mut self, ttl: Duration) -> Self {
        self.positive_min = ttl;
        self
    }

    fn with_positive_max(mut self, ttl: Duration) -> Self {
        self.positive_max = ttl;
        self
    }

    fn with_negative_min(mut self, ttl: Duration) -> Self {
        self.negative_min = ttl;
        self
    }
    fn with_negative_max(mut self, ttl: Duration) -> Self {
        self.negative_max = ttl;
        self
    }

    fn set_positive_min(&mut self, ttl: Duration) {
        self.positive_min = ttl;
    }

    fn set_positive_max(&mut self, ttl: Duration) {
        self.positive_max = ttl;
    }

    fn set_negative_min(&mut self, ttl: Duration) {
        self.negative_min = ttl;
    }
    fn set_negative_max(&mut self, ttl: Duration) {
        self.negative_max = ttl;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutOfDate {
    Yes,
    No,
}

struct DnsCacheEntry {
    lookup: Result<DnsResponse, DnsError>,
    valid_until: Instant,
    is_in_prefetching: bool,
}

impl DnsCacheEntry {
    /// Returns true if this set of ips is still valid
    fn is_current(&self, now: Instant) -> bool {
        now <= self.valid_until
    }

    /// Returns the ttl as a Duration of time remaining.
    fn ttl(&self, now: Instant) -> Duration {
        self.valid_until.saturating_duration_since(now)
    }
}

mod lookup {

    use crate::dns::DnsResponse;
    use std::ops::Deref;
    use std::time::Instant;

    use crate::libdns::proto::{
        error::ProtoResult,
        op::Message,
        serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
    };

    pub fn serialize(lookups: &[DnsResponse], writer: &mut impl std::io::Write) -> ProtoResult<()> {
        let mut buf = vec![];
        for lookup in lookups {
            {
                let mut encoder = BinEncoder::new(&mut buf);
                serialize_one(lookup, &mut encoder)?;
            }
            writer.write_all(&buf)?;
            buf.truncate(0);
        }

        Ok(())
    }

    pub fn deserialize(data: &[u8]) -> ProtoResult<Vec<DnsResponse>> {
        let mut lookups = vec![];
        let mut offset = 0;

        while offset < data.len() {
            let mut decoder = BinDecoder::new(&data[offset..]);
            lookups.push(deserialize_one(&mut decoder)?);
            offset += decoder.index();
        }

        Ok(lookups)
    }
    pub fn serialize_one(res: &DnsResponse, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        if let Some(group_name) = res.name_server_group().map(|n| n.as_bytes()) {
            encoder.emit_u16(group_name.len() as u16)?;
            encoder.emit_vec(&group_name[0..(group_name.len() as u16 as usize)])?;
        } else {
            encoder.emit_u16(0)?;
        }
        let valid_until_bytes = unsafe {
            std::slice::from_raw_parts(
                (&res.valid_until() as *const Instant) as *const u8,
                ::std::mem::size_of::<Instant>(),
            )
        };
        encoder.emit_vec(valid_until_bytes)?;
        res.deref().emit(encoder)?;
        Ok(())
    }

    pub fn deserialize_one(decoder: &mut BinDecoder<'_>) -> ProtoResult<DnsResponse> {
        let group_name = {
            let name_len = decoder.read_u16()?.unverified();
            if name_len > 0 {
                let name_bytes = decoder.read_slice(name_len as usize)?.unverified();
                String::from_utf8(name_bytes.to_vec()).ok()
            } else {
                None
            }
        };
        let valid_until_bytes = decoder
            .read_slice(std::mem::size_of::<Instant>())?
            .unverified();
        let valid_until = unsafe { std::ptr::read(valid_until_bytes.as_ptr() as *const Instant) };

        let message = Message::read(decoder)?;
        let mut res: DnsResponse = message.into();
        res = res.with_valid_until(valid_until);
        if let Some(g) = group_name {
            res = res.with_name_server_group(g);
        }

        Ok(res)
    }
}

trait PersistCache {
    fn persist<P: AsRef<Path>>(&self, path: P);

    fn load<P: AsRef<Path>>(&mut self, path: P);
}

impl PersistCache for LruCache<Query, DnsCacheEntry> {
    fn persist<P: AsRef<Path>>(&self, path: P) {
        let path = path.as_ref();
        fn cache_to_file(lookups: &[DnsResponse], path: &Path) -> ProtoResult<()> {
            let mut file = File::options()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)?;

            lookup::serialize(lookups, &mut file)?;
            Ok(())
        }

        let lookups = self
            .iter()
            .filter_map(|(_, entry)| entry.lookup.clone().ok())
            .collect::<Vec<_>>();

        match cache_to_file(&lookups, path) {
            Ok(_) => info!("save DNS cache to file {:?} successfully.", path),
            Err(err) => error!("failed to save DNS cache to file {}", err),
        }
    }

    fn load<P: AsRef<Path>>(&mut self, path: P) {
        let path = path.as_ref();
        info!("reading DNS cache from file: {:?}", path);
        let now = Instant::now();

        fn read_from_cache_file(path: &Path) -> ProtoResult<Vec<DnsResponse>> {
            let mut file = File::options().read(true).open(path)?;
            let mut data = vec![];
            file.read_to_end(&mut data)?;
            lookup::deserialize(&data)
        }
        match read_from_cache_file(path) {
            Ok(lookups) => {
                let count = lookups.len();
                let cache = self;
                for lookup in lookups {
                    let query = lookup.query().clone().clone();

                    cache.put(query, {
                        let valid_until = lookup.valid_until();

                        DnsCacheEntry {
                            lookup: Ok(lookup),
                            valid_until,
                            is_in_prefetching: false,
                        }
                    });
                }
                info!(
                    "DNS cache {} records loaded, elapsed {:?}",
                    count,
                    now.elapsed()
                );
            }
            Err(err) => error!("failed to read DNS cache file {:?} {}", path, err),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    fn create_lookup(name: &str, data: RData, ttl: u64) -> DnsResponse {
        let name: Name = name.parse().unwrap();
        let ttl = Duration::from_secs(ttl);
        let query = Query::query(name.clone(), data.record_type());
        let records = vec![Record::from_rdata(name, ttl.as_secs() as u32, data)];
        let valid_until = Instant::now() + ttl;
        DnsResponse::new_with_deadline(query, records, valid_until)
    }

    #[test]
    fn test_lookup_serde() {
        let lookups = vec![
            create_lookup(
                "abc.exmample.com",
                RData::A("127.0.0.1".parse().unwrap()),
                30,
            ),
            create_lookup("xyz.exmample.com.", RData::AAAA("::1".parse().unwrap()), 38),
        ];

        let mut data = vec![];
        lookup::serialize(&lookups, &mut data).unwrap();
        let lookup2 = lookup::deserialize(&data).unwrap();

        assert_eq!(lookup2.len(), lookups.len());

        assert_eq!(&lookups[0], &lookup2[0]);
        assert_eq!(&lookups[1], &lookup2[1]);
    }

    #[test]
    fn test_cache_persist() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let lookup1 = create_lookup(
                "abc.exmample.com.",
                RData::A("127.0.0.1".parse().unwrap()),
                3000,
            );
            let lookup2 = create_lookup(
                "xyz.exmample.com.",
                RData::AAAA("::1".parse().unwrap()),
                3000,
            );

            let cache = DnsCache::new(10, TtlOpts::default());

            let now = Instant::now();

            cache
                .insert_records(
                    lookup1.query().clone(),
                    lookup1.record_iter().cloned(),
                    now,
                    "default",
                )
                .await;

            cache
                .insert_records(
                    lookup2.query().clone(),
                    lookup2.record_iter().cloned(),
                    now,
                    "default",
                )
                .await;

            assert!(cache.get(lookup1.query(), now).await.is_some());

            {
                let lru_cache = cache.cache();
                let mut lru_cache = lru_cache.lock().await;
                assert_eq!(lru_cache.len(), 2);

                lru_cache.persist("./logs/smartdns-test.cache");

                assert!(lru_cache.get(lookup1.query()).is_some());

                lru_cache.clear();

                assert_eq!(lru_cache.len(), 0);

                lru_cache.load("./logs/smartdns-test.cache");

                assert_eq!(lru_cache.len(), 2);

                assert!(lru_cache
                    .iter()
                    .map(|(q, _)| q)
                    .any(|q| q == lookup1.query()));
                assert!(lru_cache
                    .iter()
                    .map(|(q, _)| q)
                    .any(|q| q == lookup2.query()));

                assert!(lru_cache.contains(lookup1.query()));
                assert!(lru_cache.contains(lookup2.query()));
            };

            let res = cache.get(lookup1.query(), now).await;

            assert!(res.is_some());

            let (out_of_date, res) = res.unwrap();

            assert_eq!(out_of_date, OutOfDate::No);

            let lookup = res.unwrap();
            assert_eq!(lookup.query(), lookup1.query());
            assert_eq!(lookup.records(), lookup1.records());
        })
    }
}
