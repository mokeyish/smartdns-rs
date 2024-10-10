#![allow(unused_imports)]

use std::fmt::Debug;

use std::net::IpAddr;
use std::{str::FromStr, sync::Arc, time::Duration};

use crate::dns_error::LookupError;
use crate::dns_rule::DomainRuleTreeNode;

use crate::config::ServerOpts;
use crate::dns_conf::RuntimeConfig;

pub use crate::dns_rule::DomainRuleGetter;

pub use crate::libdns::proto::{
    error::ProtoErrorKind,
    op,
    rr::{self, rdata::SOA, Name, RData, Record, RecordType},
};

pub use crate::libdns::{
    proto::xfer::Protocol,
    resolver::{
        config::{NameServerConfig, NameServerConfigGroup},
        error::{ResolveError, ResolveErrorKind},
        lookup::Lookup,
    },
};

#[derive(Clone)]
pub struct DnsContext {
    cfg: Arc<RuntimeConfig>,
    pub server_opts: ServerOpts,
    pub domain_rule: Option<Arc<DomainRuleTreeNode>>,
    pub fastest_speed: Duration,
    pub source: LookupFrom,
    pub no_cache: bool,
}

impl DnsContext {
    pub fn new(name: &Name, cfg: Arc<RuntimeConfig>, server_opts: ServerOpts) -> Self {
        let domain_rule = cfg.find_domain_rule(name);

        let no_cache = domain_rule.get(|n| n.no_cache).unwrap_or_default();

        DnsContext {
            cfg,
            server_opts,
            domain_rule,
            fastest_speed: Default::default(),
            source: Default::default(),
            no_cache,
        }
    }

    #[inline]
    pub fn cfg(&self) -> &Arc<RuntimeConfig> {
        &self.cfg
    }

    #[inline]
    pub fn server_opts(&self) -> &ServerOpts {
        &self.server_opts
    }

    pub fn server_group_name(&self) -> &str {
        match self.server_opts().group() {
            Some(n) => n,
            None => {
                let mut node = self.domain_rule.as_ref();

                while let Some(rule) = node {
                    if let Some(name) = rule.nameserver.as_deref() {
                        return name;
                    }

                    node = rule.zone();
                }

                "default"
            }
        }
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

mod serial_message {

    use crate::dns_error::LookupError;
    use crate::libdns::proto::error::ProtoError;
    use crate::libdns::Protocol;
    use crate::{config::ServerOpts, libdns::proto::op::Message};
    use bytes::Bytes;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use super::{DnsRequest, DnsResponse};

    pub enum SerialMessage {
        Raw(Message, SocketAddr, Protocol),
        Bytes(Vec<u8>, SocketAddr, Protocol),
    }

    impl SerialMessage {
        pub fn binary(bytes: Vec<u8>, addr: SocketAddr, protocol: Protocol) -> Self {
            Self::Bytes(bytes, addr, protocol)
        }
        pub fn raw(message: Message, addr: SocketAddr, protocol: Protocol) -> Self {
            Self::Raw(message, addr, protocol)
        }

        pub fn is_binray(&self) -> bool {
            matches!(self, SerialMessage::Bytes(_, _, _))
        }

        pub fn protocol(&self) -> Protocol {
            match self {
                SerialMessage::Raw(_, _, p) => *p,
                SerialMessage::Bytes(_, _, p) => *p,
            }
        }

        pub fn addr(&self) -> SocketAddr {
            match self {
                SerialMessage::Raw(_, a, _) => *a,
                SerialMessage::Bytes(_, a, _) => *a,
            }
        }
    }

    impl From<Message> for SerialMessage {
        fn from(message: Message) -> Self {
            Self::raw(
                message,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0)),
                Protocol::Udp,
            )
        }
    }

    impl TryFrom<SerialMessage> for crate::libdns::proto::xfer::SerialMessage {
        type Error = ProtoError;
        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            Ok(match value {
                SerialMessage::Bytes(bytes, addr, _) => Self::new(bytes, addr),
                SerialMessage::Raw(message, addr, _) => Self::new(message.to_vec()?, addr),
            })
        }
    }

    impl TryFrom<SerialMessage> for Vec<u8> {
        type Error = ProtoError;
        #[inline]
        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            Ok(crate::libdns::proto::xfer::SerialMessage::try_from(value)?
                .into_parts()
                .0)
        }
    }

    impl TryFrom<SerialMessage> for Bytes {
        type Error = ProtoError;
        #[inline]
        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            Ok(crate::libdns::proto::xfer::SerialMessage::try_from(value)?
                .into_parts()
                .0
                .into())
        }
    }

    impl TryFrom<SerialMessage> for Message {
        type Error = ProtoError;

        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            match value {
                SerialMessage::Raw(message, _, _) => Ok(message),
                SerialMessage::Bytes(bytes, _, _) => Message::from_vec(&bytes),
            }
        }
    }
}

mod request {

    use std::{net::SocketAddr, ops::Deref, sync::Arc};

    use crate::libdns::{
        proto::{
            error::ProtoError,
            op::{LowerQuery, Message, Query},
            rr::{Name, RecordType},
        },
        Protocol,
    };

    use super::{DnsError, SerialMessage};

    #[derive(Clone)]
    pub struct DnsRequest {
        id: u16,
        /// Message with the associated query or update data
        query: LowerQuery,
        message: Arc<Message>,
        /// Source address of the Client
        src: SocketAddr,
        /// Protocol of the request
        protocol: Protocol,
    }

    impl DnsRequest {
        pub fn new(message: Message, src_addr: SocketAddr, protocol: Protocol) -> Self {
            let id = message.id();
            let query = message.query().cloned().unwrap_or_default();
            Self {
                id,
                query: query.into(),
                message: Arc::new(message),
                src: src_addr,
                protocol,
            }
        }

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
                message: self.message.clone(),
                src: self.src,
                protocol: self.protocol,
            }
        }

        pub fn set_query_type(&mut self, query_type: RecordType) {
            let mut query = self.query.original().clone();
            query.set_query_type(query_type);
            self.query = LowerQuery::from(query)
        }

        pub fn is_dnssec(&self) -> bool {
            let rtype = self.query().query_type();
            self.extensions()
                .as_ref()
                .map(|e| e.dnssec_ok())
                .unwrap_or(rtype.is_dnssec())
        }
    }

    impl std::ops::Deref for DnsRequest {
        type Target = Message;

        fn deref(&self) -> &Self::Target {
            self.message.as_ref()
        }
    }

    impl From<Query> for DnsRequest {
        fn from(query: Query) -> Self {
            use std::net::{Ipv4Addr, SocketAddrV4};

            let mut message = Message::new();
            message.add_query(query.clone());

            Self {
                id: rand::random(),
                query: query.into(),
                message: Arc::new(message),
                src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
                protocol: Protocol::Udp,
            }
        }
    }

    impl TryFrom<SerialMessage> for DnsRequest {
        type Error = ProtoError;

        fn try_from(value: SerialMessage) -> Result<Self, Self::Error> {
            match value {
                SerialMessage::Raw(message, src_addr, protocol) => {
                    Ok(DnsRequest::new(message, src_addr, protocol))
                }
                SerialMessage::Bytes(bytes, src_addr, protocol) => {
                    use crate::libdns::proto::serialize::binary::{BinDecodable, BinDecoder};
                    let mut decoder = BinDecoder::new(&bytes);
                    let message = Message::read(&mut decoder)?;
                    Ok(DnsRequest::new(message, src_addr, protocol))
                }
            }
        }
    }
}

mod response {

    use crate::dns_client::MAX_TTL;
    use crate::libdns::proto::{
        op::{self, Header, Message, Query},
        rr::{RData, Record},
    };
    use crate::libdns::resolver::TtlClip as _;

    use std::net::IpAddr;
    use std::ops::Deref;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::DnsRequest;

    static DEFAULT_QUERY: once_cell::sync::Lazy<Query> = once_cell::sync::Lazy::new(Query::default);

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct DnsResponse {
        message: Message,
        valid_until: Instant,
        name_server_group: Option<String>,
    }

    impl DnsResponse {
        pub fn new_with_max_ttl<R, I>(query: Query, records: R) -> Self
        where
            R: IntoIterator<Item = Record, IntoIter = I>,
            I: Iterator<Item = Record>,
        {
            let valid_until = Instant::now() + Duration::from_secs(u64::from(MAX_TTL));
            Self::new_with_deadline(query, records, valid_until)
        }

        pub fn new_with_deadline<R, I>(query: Query, records: R, valid_until: Instant) -> Self
        where
            R: IntoIterator<Item = Record, IntoIter = I>,
            I: Iterator<Item = Record>,
        {
            use op::message::{update_header_counts, HeaderCounts};
            let mut message = Message::new();
            message.add_query(query.clone());
            message.add_answers(records);

            let header = update_header_counts(
                message.header(),
                message.truncated(),
                HeaderCounts {
                    query_count: message.queries().len(),
                    answer_count: message.answers().len(),
                    nameserver_count: message.name_servers().len(),
                    additional_count: message.additionals().len(),
                },
            );

            message.set_header(header);

            Self {
                message,
                valid_until,
                name_server_group: None,
            }
        }

        pub fn empty() -> Self {
            Self {
                message: Default::default(),
                valid_until: Instant::now(),
                name_server_group: None,
            }
        }

        /// Return new instance with given rdata and the maximum TTL.
        pub fn from_rdata(query: Query, rdata: RData) -> Self {
            let record = Record::from_rdata(query.name().clone(), MAX_TTL, rdata);
            Self::new_with_max_ttl(query, vec![record])
        }

        pub fn query(&self) -> &Query {
            self.deref().query().unwrap_or(&DEFAULT_QUERY)
        }

        pub fn message(&self) -> &Message {
            &self.message
        }

        pub fn valid_until(&self) -> Instant {
            self.valid_until
        }

        pub fn with_valid_until(mut self, valid_until: Instant) -> Self {
            self.valid_until = valid_until;
            self
        }

        pub fn name_server_group(&self) -> Option<&str> {
            self.name_server_group.as_deref()
        }

        pub fn with_name_server_group(mut self, group_name: String) -> Self {
            self.name_server_group = Some(group_name);
            self
        }

        pub fn records(&self) -> &[Record] {
            self.answers()
        }

        pub fn record_iter(&self) -> std::slice::Iter<'_, Record> {
            self.answers().iter()
        }

        pub fn ip_addrs(&self) -> Vec<IpAddr> {
            self.ip_addrs_iter().collect()
        }

        pub fn ip_addrs_iter(&self) -> impl Iterator<Item = IpAddr> + '_ {
            self.message()
                .answers()
                .iter()
                .flat_map(|r| r.data().ip_addr())
        }

        pub fn set_valid_until_max(&mut self) {
            self.set_valid_until(MAX_TTL)
        }

        pub fn set_valid_until(&mut self, ttl: u32) {
            let valid_until = Instant::now() + Duration::from_secs(ttl as u64);
            self.valid_until = valid_until
        }

        pub fn into_message(self, header: Option<Header>) -> Message {
            let mut message = self.message;
            if let Some(header) = header {
                message.set_header(header);
            }
            message
        }
    }

    impl std::ops::Deref for DnsResponse {
        type Target = Message;

        fn deref(&self) -> &Self::Target {
            &self.message
        }
    }

    impl std::ops::DerefMut for DnsResponse {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.message
        }
    }

    impl From<Message> for DnsResponse {
        fn from(message: Message) -> Self {
            let valid_until = Instant::now()
                + Duration::from_secs(
                    message
                        .answers()
                        .iter()
                        .map(|r| r.ttl())
                        .min()
                        .unwrap_or(MAX_TTL) as u64,
                );
            Self {
                message,
                valid_until,
                name_server_group: None,
            }
        }
    }

    impl DnsResponse {
        pub fn max_ttl(&self) -> Option<u32> {
            self.answers().iter().map(|record| record.ttl()).max()
        }

        pub fn min_ttl(&self) -> Option<u32> {
            self.answers().iter().map(|record| record.ttl()).min()
        }

        pub fn set_new_ttl(&mut self, ttl: u32) {
            for record in self.answers_mut() {
                record.set_ttl(ttl);
            }
        }

        pub fn set_max_ttl(&mut self, ttl: u32) {
            for record in self.answers_mut() {
                record.set_max_ttl(ttl);
            }
        }

        pub fn set_min_ttl(&mut self, ttl: u32) {
            for record in self.answers_mut() {
                record.set_min_ttl(ttl);
            }
        }
    }
}

pub type DnsRequest = request::DnsRequest;
pub type DnsResponse = response::DnsResponse;
pub type DnsError = LookupError;
use ipnet::IpAdd;
pub use serial_message::SerialMessage;

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
