use std::fmt::Debug;
use std::{str::FromStr, sync::Arc, time::Duration};

use trust_dns_proto::rr::rdata::SOA;
use trust_dns_resolver::error::ResolveError;

use crate::dns_server::Request as OriginRequest;
use crate::{dns_client::DnsClient, dns_conf::SmartDnsConfig};

pub use trust_dns_proto::{
    op,
    rr::{self, Name, RData, Record, RecordType},
};

pub use trust_dns_resolver::{
    config::{NameServerConfig, NameServerConfigGroup},
    error::ResolveErrorKind,
    lookup::Lookup,
};

#[derive(Debug)]
pub struct DnsContext {
    pub cfg: Arc<SmartDnsConfig>,
    pub client: Arc<DnsClient>,
    pub fastest_speed: Duration,
    pub lookup_source: LookupSource,
}

#[derive(Clone)]
pub enum LookupSource {
    None,
    Cache,
    Static,
    Zone(String),
    Server(String),
}

impl Debug for LookupSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Cache => write!(f, "Cache"),
            Self::Static => write!(f, "Static"),
            Self::Zone(arg0) => write!(f, "Zone: {}", arg0),
            Self::Server(arg0) => write!(f, "Server: {}", arg0),
        }
    }
}

impl Default for LookupSource {
    #[inline]
    fn default() -> Self {
        Self::None
    }
}

pub type DnsRequest = OriginRequest;
pub type DnsResponse = Lookup;
pub type DnsError = ResolveError;

impl SmartDnsConfig {
    pub fn rr_ttl(&self) -> u64 {
        self.rr_ttl.unwrap_or(300)
    }

    pub fn cache_size(&self) -> usize {
        self.cache_size.unwrap_or(512)
    }

    pub fn audit_size(&self) -> u64 {
        use byte_unit::n_kb_bytes;
        self.audit_size.unwrap_or(n_kb_bytes(128) as u64)
    }

    pub fn audit_num(&self) -> usize {
        self.audit_num.unwrap_or(2)
    }
}

pub trait DefaultSOA {
    fn default_soa() -> Self;
}

impl DefaultSOA for SOA {
    #[inline]
    fn default_soa() -> Self {
        Self::new(
            Name::from_str("a.gtld-servers.net").unwrap(),
            Name::from_str("nstld.verisign-grs.com").unwrap(),
            1800,
            1800,
            900,
            604800,
            86400,
        )
    }
}

impl DefaultSOA for RData {
    #[inline]
    fn default_soa() -> Self {
        RData::SOA(SOA::default_soa())
    }
}
