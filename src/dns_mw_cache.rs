use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::dns::*;
use crate::dns_client::DnsClient;
use crate::dns_conf::SmartDnsConfig;
use crate::log::debug;
use crate::middleware::*;

use lru::LruCache;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tokio::time::sleep;
use trust_dns_proto::op::Query;

pub struct DnsCacheMiddleware {
    cache: Arc<DnsLruCache>,
}

impl DnsCacheMiddleware {
    pub fn new(rt: &Runtime, cfg: &SmartDnsConfig, client: Arc<DnsClient>) -> Self {
        let positive_min_ttl = Some(Duration::from_secs(cfg.rr_ttl_min.unwrap_or(cfg.rr_ttl())));
        let positive_max_ttl = Some(Duration::from_secs(cfg.rr_ttl_max.unwrap_or(cfg.rr_ttl())));

        let negative_min_ttl = None;
        let negative_max_ttl = None;

        let cache = Arc::new(DnsLruCache::new(
            cfg.cache_size(),
            positive_min_ttl,
            negative_min_ttl,
            positive_max_ttl,
            negative_max_ttl,
        ));

        if cfg.prefetch_domain {
            cache.prefetch_domain(rt, client);
        }

        Self { cache }
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
        let query = req.query();

        let cached_val = self.cache.get(query.original(), Instant::now()).await;

        if cached_val.is_some() {
            debug!("name: {} using caching", query.name());
            return cached_val.unwrap();
        }

        let res = next.run(ctx, req).await;

        let res = match res {
            Ok(lookup) => {
                self.cache
                    .insert_records(
                        query.original().to_owned(),
                        lookup.records().to_owned().into_iter(),
                        Instant::now(),
                    )
                    .await;

                Ok(lookup)
            }
            Err(err) => Err(err),
        };

        res
    }
}

/// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
/// Setting this to a value of 1 day, in seconds
const MAX_TTL: u32 = 86400_u32;

/// An LRU eviction cache specifically for storing DNS records
struct DnsLruCache {
    cache: Arc<Mutex<LruCache<Query, DnsCacheEntry>>>,
    /// A minimum TTL value for positive responses.
    ///
    /// Positive responses with TTLs under `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    ///
    /// If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to 0.
    positive_min_ttl: Duration,
    /// A minimum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs under `negative_min_ttl` will use
    /// `negative_min_ttl` instead.
    ///
    /// If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to 0.
    negative_min_ttl: Duration,
    /// A maximum TTL value for positive responses.
    ///
    /// Positive responses with TTLs over `positive_max_ttl` will use
    /// `positive_max_ttl` instead.
    ///
    ///  If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to [`MAX_TTL`] seconds.
    ///
    /// [`MAX_TTL`]: const.MAX_TTL.html
    positive_max_ttl: Duration,
    /// A maximum TTL value for negative (`NXDOMAIN`) responses.
    ///
    /// `NXDOMAIN` responses with TTLs over `negative_max_ttl` will use
    /// `negative_max_ttl` instead.
    ///
    ///  If this value is not set on the `TtlConfig` used to construct this
    /// `DnsLru`, it will default to [`MAX_TTL`] seconds.
    ///
    /// [`MAX_TTL`]: const.MAX_TTL.html
    negative_max_ttl: Duration,
}

impl DnsLruCache {
    fn new(
        cache_size: usize,
        positive_min_ttl: Option<Duration>,
        negative_min_ttl: Option<Duration>,
        positive_max_ttl: Option<Duration>,
        negative_max_ttl: Option<Duration>,
    ) -> Self {
        let cache = Arc::new(Mutex::new(LruCache::new(
            NonZeroUsize::new(cache_size).unwrap(),
        )));
        let positive_min_ttl = positive_min_ttl.unwrap_or_else(|| Duration::from_secs(0));
        let negative_min_ttl = negative_min_ttl.unwrap_or_else(|| Duration::from_secs(0));
        let positive_max_ttl =
            positive_max_ttl.unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL)));
        let negative_max_ttl =
            negative_max_ttl.unwrap_or_else(|| Duration::from_secs(u64::from(MAX_TTL)));

        Self {
            cache,
            positive_min_ttl,
            negative_min_ttl,
            positive_max_ttl,
            negative_max_ttl,
        }
    }

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
            (Vec::with_capacity(len), self.positive_max_ttl),
            |(mut records, mut min_ttl), (record, ttl)| {
                records.push(record);
                let ttl = Duration::from_secs(u64::from(ttl));
                min_ttl = min_ttl.min(ttl);
                (records, min_ttl)
            },
        );

        // If the cache was configured with a minimum TTL, and that value is higher
        // than the minimum TTL in the values, use it instead.
        let ttl = self.positive_min_ttl.max(ttl);
        let valid_until = now + ttl;

        // insert into the LRU
        let lookup = Lookup::new_with_deadline(query.clone(), Arc::from(records), valid_until);

        self.cache.lock().await.put(
            query,
            DnsCacheEntry {
                lookup: Ok(lookup.clone()),
                valid_until,
            },
        );

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
    async fn get(&self, query: &Query, now: Instant) -> Option<Result<Lookup, DnsError>> {
        let mut out_of_date = false;
        let mut cache = self.cache.lock().await;
        let lookup = cache.get_mut(query).and_then(|value| {
            if value.is_current(now) {
                out_of_date = false;
                let mut result = value.lookup.clone();

                if let Err(ref mut err) = result {
                    Self::nx_error_with_ttl(err, value.ttl(now));
                }
                Some(result)
            } else {
                out_of_date = true;
                None
            }
        });

        // in this case, we can preemptively remove out of data elements
        // this assumes time is always moving forward, this would only not be true in contrived situations where now
        //  is not current time, like tests...
        if out_of_date {
            cache.pop(query).unwrap();
        }

        lookup
    }

    fn prefetch_domain(&self, rt: &Runtime, client: Arc<DnsClient>) {
        let prefetch_cache = self.cache.clone();

        rt.spawn(async move {
            loop {
                sleep(Duration::from_secs(1)).await;

                let mut cache = prefetch_cache.lock().await;

                let mut now = Instant::now();

                for (query, entry) in cache.iter_mut() {
                    if entry.is_current(now) {
                        continue;
                    }
                    now = Instant::now();

                    debug!("Prefetch domain {}", query.name());

                    if let Ok(lookup) = client
                        .lookup(query.name().to_owned(), query.query_type())
                        .await
                    {
                        if let Some(record) = lookup.records().iter().min_by_key(|r| r.ttl()) {
                            let ttl = Duration::from_secs(u64::from(record.ttl()));
                            entry.valid_until = now + ttl;
                        }
                    }
                }

                // debug!("Prefetch domains elapsed {:?}", now.elapsed());
            }
        });
    }
}

struct DnsCacheEntry {
    lookup: Result<Lookup, DnsError>,
    valid_until: Instant,
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
