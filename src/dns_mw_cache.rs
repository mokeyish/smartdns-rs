use std::collections::HashMap;
use std::collections::HashSet;

use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::num::NonZeroUsize;

use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::dns_conf::SmartDnsConfig;
use crate::dns_mw::DnsMiddlewareHost;
use crate::trust_dns::resolver::LookupTtl;
use crate::{
    dns::*,
    log::{debug, error, info},
    middleware::*,
    trust_dns::proto::op::Query,
};
use lru::LruCache;
use tokio::sync::MutexGuard;
use tokio::{
    sync::{mpsc, Mutex, Notify},
    time::sleep,
};
use trust_dns_proto::error::ProtoResult;

pub struct DnsCacheMiddleware {
    cache: Mutex<HybridDomainCache>,
}

impl DnsCacheMiddleware {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HybridDomainCache::None),
        }
    }

    async fn get_cache(
        &self,
        cfg: &Arc<SmartDnsConfig>,
        rest: Option<&Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>>,
    ) -> MutexGuard<HybridDomainCache> {
        let mut cache = self.cache.lock().await;

        if cache.is_none() {
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

            let new_cache = DnsLruCache::new(cfg.cache_size(), ttl);

            if cfg.cache_persist() {
                let cache_file = cfg.cache_file();
                let cache = new_cache.cache();
                if cache_file.exists() {
                    cache.lock().await.load(cache_file.as_path());
                }
                tokio::spawn(async move {
                    crate::signal::terminate()
                        .await
                        .expect("failed to wait ctrl_c for persist cache.");
                    cache.lock().await.persist(cache_file.as_path());
                });
            }

            let new_cache = if cfg.prefetch_domain() {
                let prefetcher =
                    DomainPrefetcher::new(new_cache, rest.unwrap().into(), cfg.clone());
                prefetcher.start();
                HybridDomainCache::Prefetch(prefetcher)
            } else {
                HybridDomainCache::Lru(new_cache)
            };
            *cache.deref_mut() = new_cache;
        }
        cache
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
        if ctx.server_opts.no_cache() {
            return next.run(ctx, req).await;
        }

        let query = req.query();

        let query = query.original().to_owned();

        let cached_res = self
            .get_cache(ctx.cfg(), Some(&next))
            .await
            .get(&query, Instant::now())
            .await;

        if let Some((OutOfDate::No, res)) = cached_res.as_ref() {
            debug!("name: {} using caching", query.name());
            ctx.source = LookupFrom::Cache;
            return res.clone();
        }

        let res = next.run(ctx, req).await;

        let res = match res {
            Ok(lookup) => {
                if !ctx.no_cache {
                    self.get_cache(ctx.cfg(), None)
                        .await
                        .insert_records(query, lookup.records().iter().cloned(), Instant::now())
                        .await;
                }

                if let Some(rr_ttl_reply_max) = ctx.cfg().rr_ttl_reply_max() {
                    Ok(lookup.with_new_ttl(rr_ttl_reply_max as u32))
                } else {
                    Ok(lookup)
                }
            }
            Err(err) => {
                // try to return expired result.
                if ctx.cfg().serve_expired() {
                    if let Some((OutOfDate::Yes, Ok(lookup))) = cached_res {
                        Ok(lookup)
                    } else {
                        Err(err)
                    }
                } else {
                    Err(err)
                }
            }
        };

        res
    }
}

enum HybridDomainCache {
    None,
    Prefetch(DomainPrefetcher),
    Lru(DnsLruCache),
}

impl HybridDomainCache {
    fn is_none(&self) -> bool {
        matches!(self, HybridDomainCache::None)
    }
}

impl Deref for HybridDomainCache {
    type Target = DnsLruCache;

    fn deref(&self) -> &Self::Target {
        use HybridDomainCache::*;

        match self {
            Prefetch(v) => &v.cache,
            Lru(v) => v,
            None => panic!("Cache not initialized."),
        }
    }
}

struct DomainPrefetcher {
    cfg: Arc<SmartDnsConfig>,
    cache: DnsLruCache,
    client: Arc<DnsMiddlewareHost>,
    prefetch_notify: Arc<Notify>,
}

impl DomainPrefetcher {
    fn new(cache: DnsLruCache, client: DnsMiddlewareHost, cfg: Arc<SmartDnsConfig>) -> Self {
        let prefetch_notify = cache.prefetch_notify.clone();

        Self {
            cache,
            prefetch_notify,
            client: Arc::new(client),
            cfg,
        }
    }

    fn cache(&self) -> &Arc<Mutex<LruCache<Query, DnsCacheEntry>>> {
        &self.cache.cache
    }

    fn start(&self) {
        let (tx, mut rx) = mpsc::channel::<Vec<Query>>(100);

        let client = self.client.clone();

        {
            // prefetch domain.
            let cache = self.cache().clone();
            let cfg = self.cfg.clone();

            tokio::spawn(async move {
                let querying: Arc<Mutex<HashSet<Query>>> = Default::default();

                loop {
                    if let Some(queries) = rx.recv().await {
                        let client = client.clone();
                        let cache = cache.clone();
                        let querying = querying.clone();

                        for query in queries {
                            if !querying.lock().await.insert(query.clone()) {
                                continue;
                            }

                            let querying = querying.clone();
                            let cache = cache.clone();

                            let (cfg, client, name, typ) = (
                                cfg.clone(),
                                client.clone(),
                                query.name().to_owned(),
                                query.query_type(),
                            );

                            tokio::spawn(async move {
                                let now = Instant::now();
                                let mut ctx =
                                    DnsContext::new(query.name(), cfg.clone(), Default::default());

                                if let Ok(lookup) =
                                    client.execute(&mut ctx, &query.clone().into()).await
                                {
                                    let min_ttl = lookup
                                        .records()
                                        .iter()
                                        .min_by_key(|r| r.ttl())
                                        .map(|r| Duration::from_secs(u64::from(r.ttl())));

                                    debug!(
                                        "prefetch domain {} {}, elapsed {:?}, ttl {:?}",
                                        name,
                                        typ,
                                        now.elapsed(),
                                        min_ttl.unwrap_or_default()
                                    );

                                    if let Some(min_ttl) = min_ttl {
                                        if let Some(entry) = cache.lock().await.peek_mut(&query) {
                                            entry.valid_until = now + min_ttl;
                                            entry.origin_ttl = min_ttl;
                                            entry.lookup = Ok(lookup);
                                        }
                                    }
                                }

                                querying.lock().await.remove(&query);
                            });
                        }
                    }
                }
            });
        }

        {
            // check expired domain.
            let cache = self.cache().clone();

            let prefetch_notify = self.prefetch_notify.clone();

            const MIN_INTERVAL: Duration = Duration::from_secs(1);
            const MIN_TTL: Duration = Duration::from_secs(5);

            tokio::spawn(async move {
                let mut last_check = Instant::now();

                loop {
                    prefetch_notify.notified().await;
                    let now = Instant::now();
                    if now - last_check < MIN_INTERVAL {
                        continue;
                    }

                    last_check = now;
                    let mut most_recent = Duration::from_secs(MAX_TTL as u64);

                    let mut expired = vec![];

                    {
                        let mut cache = cache.lock().await;
                        let len = cache.len();
                        if len == 0 {
                            continue;
                        }

                        for (query, entry) in cache.iter_mut() {
                            // only prefetch query type ip addr
                            if !query.query_type().is_ip_addr() {
                                continue;
                            }

                            // Prefetch the domain that ttl greater than 10s to reduce cpu usage.
                            if entry.origin_ttl() < MIN_TTL {
                                debug!(
                                    "skiping {} {}, ttl:{:?}",
                                    query.name(),
                                    query.query_type(),
                                    entry.origin_ttl()
                                );
                                continue;
                            }
                            if entry.is_current(now) {
                                let ttl = entry.ttl(now);
                                most_recent = most_recent.min(ttl);
                                continue;
                            }

                            expired.push(query.to_owned());
                        }
                        debug!(
                            "check prefetch domains(total: {}) elapsed {:?}",
                            len,
                            now.elapsed()
                        );
                    }

                    if !expired.is_empty() {
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            if tx.send(expired).await.is_err() {
                                error!("failed to send queries to prefetch domain!",);
                            }
                        });
                    }

                    let prefetch_notify = prefetch_notify.clone();
                    tokio::spawn(async move {
                        let dura = most_recent.max(MIN_INTERVAL);
                        debug!("Check domain prefetch after {:?} seconds", dura);
                        sleep(dura).await;
                        prefetch_notify.notify_one();
                    });
                }
            });
        }
    }
}

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
/// Setting this to a value of 1 day, in seconds
const MAX_TTL: u32 = 86400_u32;

/// An LRU eviction cache specifically for storing DNS records
struct DnsLruCache {
    cache: Arc<Mutex<LruCache<Query, DnsCacheEntry>>>,

    ttl: TtlOpts,

    prefetch_notify: Arc<Notify>,
}

impl DnsLruCache {
    fn new(cache_size: usize, ttl: TtlOpts) -> Self {
        let cache = Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(cache_size).unwrap(),
        )));

        Self {
            cache,
            ttl,
            prefetch_notify: Default::default(),
        }
    }

    fn cache(&self) -> Arc<Mutex<LruCache<Query, DnsCacheEntry>>> {
        self.cache.clone()
    }

    // fn insert

    async fn clear(&self) {
        self.cache.lock().await.clear();
    }

    async fn insert(
        &self,
        query: Query,
        records_and_ttl: Vec<(Record, u32)>,
        now: Instant,
    ) -> Lookup {
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
        let valid_until = now + ttl;

        // insert into the LRU
        let lookup = Lookup::new_with_deadline(query.clone(), Arc::from(records), valid_until);

        self.notify_prefetch_domain(ttl);

        if let Ok(mut cache) = self.cache.try_lock() {
            cache.put(
                query,
                DnsCacheEntry {
                    lookup: Ok(lookup.clone()),
                    valid_until,
                    origin_ttl: ttl,
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
    ) -> Option<Lookup> {
        // collect all records by name
        let records = records.fold(
            HashMap::<Query, Vec<(Record, u32)>>::new(),
            |mut map, record| {
                let mut query = Query::query(record.name().clone(), record.record_type());
                query.set_query_class(record.dns_class());

                let ttl = record.ttl();

                map.entry(query)
                    .or_insert_with(Vec::default)
                    .push((record, ttl));

                map
            },
        );

        // now insert by record type and name
        let mut lookup = None;
        for (query, records_and_ttl) in records {
            let is_query = original_query == query;
            let inserted = self.insert(query, records_and_ttl, now).await;

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
    ) -> Option<(OutOfDate, Result<Lookup, DnsError>)> {
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
                let mut result = value.lookup.clone();

                if let Err(ref mut err) = result {
                    Self::nx_error_with_ttl(err, value.ttl(now));
                }

                Some((OutOfDate::No, result))
            } else {
                let negative_ttl = value.valid_until - now;
                if negative_ttl < self.ttl.negative_max {
                    let result = value.lookup.clone();
                    if let Ok(ref mut lookup) = value.lookup {
                        *lookup = lookup.with_new_ttl(self.ttl.negative_min.as_secs() as u32)
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

    fn notify_prefetch_domain(&self, duration: Duration) {
        if duration.is_zero() {
            return;
        }

        let prefetch_notify = self.prefetch_notify.clone();
        tokio::spawn(async move {
            sleep(duration).await;
            prefetch_notify.notify_one();
        });
    }
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
    lookup: Result<Lookup, DnsError>,
    valid_until: Instant,
    origin_ttl: Duration,
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

    fn origin_ttl(&self) -> Duration {
        self.origin_ttl
    }
}

mod lookup {
    use std::time::Instant;

    use trust_dns_proto::error::ProtoResult;
    use trust_dns_proto::{
        op::Query,
        rr::Record,
        serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
    };
    use trust_dns_resolver::lookup::Lookup;

    pub fn serialize(lookups: &[Lookup]) -> ProtoResult<Vec<u8>> {
        let mut buf = vec![];

        let mut encoder = BinEncoder::new(&mut buf);

        encoder.emit_u32(lookups.len() as u32)?;

        for lookup in lookups {
            serialize_one(lookup, &mut encoder)?;
        }

        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> ProtoResult<Vec<Lookup>> {
        let mut lookups = vec![];
        let mut decoder = BinDecoder::new(data);
        let count = decoder.read_u32()?.unverified();

        for _ in 0..count {
            lookups.push(deserialize_one(&mut decoder)?)
        }

        Ok(lookups)
    }
    pub fn serialize_one(lookup: &Lookup, encoder: &mut BinEncoder<'_>) -> ProtoResult<()> {
        lookup.query().emit(encoder)?;

        let valid_until_bytes = unsafe {
            std::slice::from_raw_parts(
                (&lookup.valid_until() as *const Instant) as *const u8,
                ::std::mem::size_of::<Instant>(),
            )
        };
        encoder.emit_vec(valid_until_bytes)?;

        encoder.emit_u8(lookup.records().len() as u8)?;

        for record in lookup.records() {
            record.emit(encoder)?
        }

        Ok(())
    }

    pub fn deserialize_one(decoder: &mut BinDecoder<'_>) -> ProtoResult<Lookup> {
        let query = Query::read(decoder)?;

        let valid_until_bytes = decoder
            .read_slice(std::mem::size_of::<Instant>())?
            .unverified();

        let valid_until = unsafe { std::ptr::read(valid_until_bytes.as_ptr() as *const Instant) };

        let count = decoder.read_u8()?.unverified();
        let mut records = vec![];
        for _ in 0..count {
            records.push(Record::read(decoder)?);
        }
        Ok(Lookup::new_with_deadline(
            query,
            records.into(),
            valid_until,
        ))
    }
}

trait PersistCache {
    fn persist<P: AsRef<Path>>(&self, path: P);

    fn load<P: AsRef<Path>>(&mut self, path: P);
}

impl PersistCache for LruCache<Query, DnsCacheEntry> {
    fn persist<P: AsRef<Path>>(&self, path: P) {
        let path = path.as_ref();
        fn cache_to_file(lookups: &[Lookup], path: &Path) -> ProtoResult<()> {
            let data = lookup::serialize(lookups)?;
            let mut file = File::options()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)?;
            file.write_all(&data)?;
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

        fn read_from_cache_file(path: &Path) -> ProtoResult<Vec<Lookup>> {
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

                        let ttl = lookup
                            .max_ttl()
                            .map(|ttl| Duration::from_secs(ttl as u64))
                            .unwrap_or_default();

                        DnsCacheEntry {
                            lookup: Ok(lookup),
                            valid_until,
                            origin_ttl: ttl,
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

    fn create_lookup(name: &str, rr_type: RecordType, ttl: u64) -> Lookup {
        let name: Name = name.parse().unwrap();
        let ttl = Duration::from_secs(ttl);
        let query = Query::query(name.clone(), rr_type);
        let records = vec![Record::with(name.clone(), rr_type, ttl.as_secs() as u32)];
        let valid_until = Instant::now() + ttl;
        Lookup::new_with_deadline(query, records.into(), valid_until)
    }

    #[test]
    fn test_lookup_serde() {
        let lookups = vec![
            create_lookup("abc.exmample.com", RecordType::A, 30),
            create_lookup("xyz.exmample.com", RecordType::AAAA, 38),
        ];

        let data = lookup::serialize(&lookups).unwrap();

        let lookup2 = lookup::deserialize(&data).unwrap();

        assert_eq!(&lookups[0], &lookup2[0]);
        assert_eq!(&lookups[1], &lookup2[1]);
    }

    #[test]
    fn test_cache_persist() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let lookup1 = create_lookup("abc.exmample.com.", RecordType::A, 3000);
            let lookup2 = create_lookup("xyz.exmample.com.", RecordType::A, 3000);

            let cache = DnsLruCache::new(10, TtlOpts::default());

            let now = Instant::now();

            cache
                .insert_records(lookup1.query().clone(), lookup1.record_iter().cloned(), now)
                .await;

            cache
                .insert_records(lookup2.query().clone(), lookup2.record_iter().cloned(), now)
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
