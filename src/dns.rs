use std::fmt::Debug;

use std::{str::FromStr, sync::Arc, time::Duration};

use crate::dns_error::LookupError;
use crate::dns_rule::DomainRuleTreeNode;

use crate::dns_conf::{ServerOpts, SmartDnsConfig};

pub use crate::trust_dns::proto::{
    op,
    rr::{self, rdata::SOA, Name, RData, Record, RecordType},
};

pub use trust_dns_resolver::{
    config::{NameServerConfig, NameServerConfigGroup},
    error::{ResolveError, ResolveErrorKind},
    lookup::Lookup,
};

#[derive(Clone)]
pub struct DnsContext {
    cfg: Arc<SmartDnsConfig>,
    pub server_opts: ServerOpts,
    pub domain_rule: Option<Arc<DomainRuleTreeNode>>,
    pub fastest_speed: Duration,
    pub source: LookupFrom,
    pub no_cache: bool,
    pub background: bool,
}

impl DnsContext {
    pub fn new(name: &Name, cfg: Arc<SmartDnsConfig>, server_opts: ServerOpts) -> Self {
        let domain_rule = cfg.find_domain_rule(name);

        let no_cache = domain_rule
            .as_ref()
            .and_then(|r| r.get(|n| n.no_cache))
            .unwrap_or_default();

        DnsContext {
            cfg,
            server_opts,
            domain_rule,
            fastest_speed: Default::default(),
            source: Default::default(),
            no_cache,
            background: false,
        }
    }

    #[inline]
    pub fn cfg(&self) -> &Arc<SmartDnsConfig> {
        &self.cfg
    }

    #[inline]
    pub fn server_opts(&self) -> &ServerOpts {
        &self.server_opts
    }
}

#[derive(Clone)]
pub enum LookupFrom {
    None,
    Cache,
    Static,
    Zone(String),
    Server(String),
}

impl Debug for LookupFrom {
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

impl Default for LookupFrom {
    #[inline]
    fn default() -> Self {
        Self::None
    }
}

mod request {

    use std::net::SocketAddr;

    use trust_dns_proto::{
        op::{LowerQuery, Query},
        rr::{Name, RecordType},
    };
    use trust_dns_server::server::Protocol;

    use crate::dns_server::Request as OriginRequest;

    #[derive(Clone)]
    pub struct Request {
        id: u16,
        /// Message with the associated query or update data
        query: LowerQuery,
        /// Source address of the Client
        src: SocketAddr,
        /// Protocol of the request
        protocol: Protocol,
    }

    impl From<&OriginRequest> for Request {
        fn from(req: &OriginRequest) -> Self {
            Self {
                id: req.id(),
                query: req.query().to_owned(),
                src: req.src(),
                protocol: req.protocol(),
            }
        }
    }

    impl Request {
        /// see `Header::id()`
        pub fn id(&self) -> u16 {
            self.id
        }

        /// ```text
        /// Question        Carries the query name and other query parameters.
        /// ```
        #[inline]
        pub fn query(&self) -> &LowerQuery {
            &self.query
        }

        /// The IP address from which the request originated.
        #[inline]
        pub fn src(&self) -> SocketAddr {
            self.src
        }

        /// The protocol that was used for the request
        #[inline]
        pub fn protocol(&self) -> Protocol {
            self.protocol
        }

        pub fn with_cname(&self, name: Name) -> Self {
            Self {
                id: self.id,
                query: LowerQuery::from(Query::query(name, self.query().query_type())),
                src: self.src,
                protocol: self.protocol,
            }
        }

        pub fn set_query_type(&mut self, query_type: RecordType) {
            let mut query = self.query.original().clone();
            query.set_query_type(query_type);
            self.query = LowerQuery::from(query)
        }
    }

    impl From<Query> for Request {
        fn from(query: Query) -> Self {
            use std::net::{Ipv4Addr, SocketAddrV4};

            Self {
                id: rand::random(),
                query: query.into(),
                src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
                protocol: Protocol::Udp,
            }
        }
    }
}

pub type DnsRequest = request::Request;
pub type DnsResponse = Lookup;
pub type DnsError = LookupError;

#[derive(Debug, Clone, Copy, Default)]
pub enum LookupResponseStrategy {
    #[default]
    FirstPing, // query + ping
    FastestIp,       // ping
    FastestResponse, // query
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
    fn default_soa() -> Self {
        Self::SOA(SOA::default_soa())
    }
}
