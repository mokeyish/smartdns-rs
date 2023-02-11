use cfg_if::cfg_if;
use std::fmt::Debug;
use std::path::PathBuf;
use std::{str::FromStr, sync::Arc, time::Duration};

use crate::dns_conf::DomainRule;
use crate::dns_server::Request as OriginRequest;
use crate::log::info;
use crate::{
    dns_client::DnsClient,
    dns_conf::{QueryOpts, SmartDnsConfig},
};

pub use trust_dns_proto::{
    op,
    rr::{self, rdata::SOA, Name, RData, Record, RecordType},
};

pub use trust_dns_resolver::{
    config::{NameServerConfig, NameServerConfigGroup},
    error::{ResolveError, ResolveErrorKind},
    lookup::Lookup,
};

#[derive(Debug)]
pub struct DnsContext {
    pub cfg: Arc<SmartDnsConfig>,
    pub client: Arc<DnsClient>,
    pub fastest_speed: Duration,
    pub lookup_source: LookupSource,
    pub no_cache: bool,
    pub query_opts: QueryOpts,
    pub domain_rule: Option<Arc<DomainRule>>,
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
    pub fn summary(&self) {
        info!(r#"whoami 👉 {}"#, self.server_name());

        const DEFAULT_GROUP: &'static str = "default";
        for (group, servers) in self.servers.iter() {
            if group == DEFAULT_GROUP {
                continue;
            }
            for server in servers {
                info!(
                    "upstream server: {} [group: {}]",
                    server.url.to_string(),
                    group
                );
            }
        }

        if let Some(ss) = self.servers.get(DEFAULT_GROUP) {
            for s in ss {
                info!(
                    "upstream server: {} [group: {}]",
                    s.url.to_string(),
                    DEFAULT_GROUP
                );
            }
        }
    }

    pub fn server_name(&self) -> Name {
        match self.server_name {
            Some(ref server_name) => Some(server_name.clone()),
            None => match hostname::get() {
                Ok(name) => match name.to_str() {
                    Some(s) => Name::from_str(s).ok(),
                    None => None,
                },
                Err(_) => None,
            },
        }
        .unwrap_or_else(|| Name::from_str(crate::NAME).unwrap())
    }

    #[inline]
    pub fn tcp_idle_time(&self) -> u64 {
        self.tcp_idle_time.unwrap_or(120)
    }

    #[inline]
    pub fn rr_ttl_min(&self) -> u64 {
        self.rr_ttl_min.unwrap_or(60)
    }

    #[inline]
    pub fn rr_ttl(&self) -> u64 {
        self.rr_ttl.unwrap_or(300)
    }

    #[inline]
    pub fn local_ttl(&self) -> u64 {
        self.local_ttl.unwrap_or_else(|| self.rr_ttl_min())
    }

    pub fn cache_size(&self) -> usize {
        self.cache_size.unwrap_or(512)
    }

    pub fn cache_persist(&self) -> bool {
        self.cache_persist.unwrap_or(false)
    }

    pub fn audit_num(&self) -> usize {
        self.audit_num.unwrap_or(2)
    }

    pub fn audit_size(&self) -> u64 {
        use byte_unit::n_kb_bytes;
        self.audit_size.unwrap_or(n_kb_bytes(128) as u64)
    }

    pub fn audit_file_mode(&self) -> u32 {
        self.audit_file_mode.map(|m| *m).unwrap_or(0o640)
    }

    pub fn log_enabled(&self) -> bool {
        self.log_num() > 0
    }

    pub fn log_file(&self) -> PathBuf {
        match self.log_file.as_ref() {
            Some(e) => e.to_owned(),
            None => {
                cfg_if! {
                    if #[cfg(target_os="windows")] {
                        let mut path = std::env::temp_dir();
                        path.push("smartdns");
                        path.push("smartdns.log");
                        path
                    } else {
                        PathBuf::from(r"/var/log/smartdns/smartdns.log")
                    }

                }
            }
        }
    }

    pub fn log_level(&self) -> tracing::Level {
        use tracing::Level;
        match self
            .log_level
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("error")
        {
            "tarce" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" | "notice" => Level::INFO,
            "warn" => Level::WARN,
            "error" | "fatal" => Level::ERROR,
            _ => Level::ERROR,
        }
    }

    pub fn log_num(&self) -> u64 {
        self.log_num.unwrap_or(2)
    }
    pub fn log_size(&self) -> u64 {
        use byte_unit::n_kb_bytes;
        self.audit_size.unwrap_or(n_kb_bytes(128) as u64)
    }
    pub fn log_file_mode(&self) -> u32 {
        self.log_file_mode.map(|m| *m).unwrap_or(0o640)
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
