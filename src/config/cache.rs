use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CacheConfig {
    /// dns cache size
    ///
    /// ```
    /// cache-size [number]
    ///   0: for no cache
    /// ```
    pub size: Option<usize>,

    /// enable persist cache when restart
    pub persist: Option<bool>,

    /// cache persist file
    pub file: Option<PathBuf>,

    /// prefetch domain
    ///
    /// ```
    /// prefetch-domain [yes|no]
    ///
    /// example:
    ///   prefetch-domain yes
    /// ```
    pub prefetch_domain: Option<bool>,

    /// cache serve expired
    ///
    /// serve-expired [yes|no]
    /// ```
    /// example:
    ///   serve-expired yes
    /// ```
    pub serve_expired: Option<bool>,

    /// cache serve expired TTL
    ///
    /// serve-expired-ttl [num]
    /// ```
    /// example:
    ///   serve-expired-ttl 0
    /// ```
    pub serve_expired_ttl: Option<u64>,

    /// reply TTL value to use when replying with expired data
    ///
    /// serve-expired-reply-ttl [num]
    /// ```
    /// example:
    ///   serve-expired-reply-ttl 30
    /// ```
    pub serve_expired_reply_ttl: Option<u64>,

    /// cache save interval
    pub checkpoint_time: Option<u64>,
}
