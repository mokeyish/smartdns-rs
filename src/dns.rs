use std::{str::FromStr, sync::Arc, time::Duration};

use trust_dns_proto::rr::rdata::SOA;
use trust_dns_resolver::error::ResolveError;

use crate::dns_server::Request as OriginRequest;
use crate::{dns_client::DnsClient, dns_conf::SmartDnsConfig};

pub use trust_dns_proto::{
    op,
    rr::{self, Name, RData, Record},
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
