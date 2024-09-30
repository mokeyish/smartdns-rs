use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
};

use crate::{
    infra::{file_mode::FileMode, ipset::IpSet},
    libdns::proto::rr::{
        rdata::{HTTPS, SRV},
        Name, RecordType,
    },
    log::Level,
    proxy::ProxyConfig,
    third_ext::serde_str,
};

use byte_unit::Byte;
use ipnet::IpNet;
use serde::{self, Deserialize, Serialize};

mod audit;
mod cache;
mod domain;
mod domain_rule;
mod domain_set;
mod listener;
mod log;
mod nameserver;
pub mod parser;
mod response_mode;
mod server_opts;
mod speed_mode;

pub use audit::*;
pub use cache::*;
pub use domain::*;
pub use domain_rule::*;
pub use domain_set::*;
pub use listener::*;
pub use log::*;
pub use nameserver::*;
pub use response_mode::*;
pub use server_opts::*;
pub use speed_mode::*;

use self::parser::NomParser;

pub type DomainSets = HashMap<String, HashSet<WildcardName>>;
pub type ForwardRules = Vec<ForwardRule>;
pub type AddressRules = Vec<AddressRule>;
pub type DomainRules = Vec<ConfigForDomain<DomainRule>>;
pub type CNameRules = Vec<ConfigForDomain<CNameRule>>;
pub type SrvRecords = Vec<ConfigForDomain<SRV>>;
pub type HttpsRecords = Vec<ConfigForDomain<HttpsRecordRule>>;

#[derive(Default)]
pub struct Config {
    /// dns server name, default is host name
    ///
    /// ```
    /// server-name,
    ///
    /// example:
    ///   server-name smartdns
    /// ```
    pub server_name: Option<Name>,

    /// The number of worker threads
    pub num_workers: Option<usize>,

    pub mdns_lookup: Option<bool>,

    /// whether resolv local hostname to ip address
    pub resolv_hostname: Option<bool>,

    pub hosts_file: Option<glob::Pattern>,

    pub expand_ptr_from_address: Option<bool>,

    /// dns server run user
    ///
    /// ```
    /// user [username]
    ///
    /// exmaple:
    ///   user nobody
    /// ```
    pub user: Option<String>,

    /// Local domain suffix appended to DHCP names and hosts file entries.
    pub domain: Option<Name>,

    /// Include another configuration options
    ///
    /// conf-file [file]
    /// ```
    /// example:
    ///   conf-file blacklist-ip.conf
    /// ```
    pub conf_file: Option<PathBuf>,

    /// listeners
    pub listeners: Vec<ListenerConfig>,

    /// SSL Certificate file path
    pub bind_cert_file: Option<PathBuf>,
    /// SSL Certificate key file path
    pub bind_cert_key_file: Option<PathBuf>,
    /// SSL Certificate key file password
    pub bind_cert_key_pass: Option<String>,

    /// tcp connection idle timeout
    ///
    /// tcp-idle-time [second]
    pub tcp_idle_time: Option<u64>,

    pub cache: CacheConfig,

    /// List of hosts that supply bogus NX domain results
    pub bogus_nxdomain: IpSet,

    /// List of IPs that will be filtered when nameserver is configured -blacklist-ip parameter
    pub blacklist_ip: IpSet,

    /// List of IPs that will be accepted when nameserver is configured -whitelist-ip parameter
    pub whitelist_ip: IpSet,

    /// List of IPs that will be ignored
    pub ignore_ip: IpSet,

    /// speed check mode
    ///
    /// speed-check-mode [ping|tcp:port|http:port|https:port|none|,]
    /// ```ini
    /// example:
    ///   speed-check-mode ping,tcp:8080,http:80,https
    ///   speed-check-mode tcp:443,ping
    ///   speed-check-mode none
    /// ```
    pub speed_check_mode: Option<SpeedCheckModeList>,

    /// force AAAA query return SOA
    ///
    /// force-AAAA-SOA [yes|no]
    pub force_aaaa_soa: Option<bool>,

    /// force specific qtype return soa
    ///
    /// force-qtype-SOA [qtypeid |...]
    ///
    /// qtypeid: https://en.wikipedia.org/wiki/List_of_DNS_record_types
    /// ```ini
    /// example:
    ///   force-qtype-SOA 65 28
    /// ```
    pub force_qtype_soa: HashSet<RecordType>,

    /// Enable IPV4, IPV6 dual stack IP optimization selection strategy
    ///
    /// dualstack-ip-selection [yes|no]
    pub dualstack_ip_selection: Option<bool>,
    /// dualstack-ip-selection-threshold [num] (0~1000)
    pub dualstack_ip_selection_threshold: Option<u16>,
    /// dualstack-ip-allow-force-AAAA [yes|no]
    pub dualstack_ip_allow_force_aaaa: Option<bool>,

    /// edns client subnet
    ///
    /// ```
    /// example:
    ///   edns-client-subnet [ip/subnet]
    ///   edns-client-subnet 192.168.1.1/24
    ///   edns-client-subnet 8::8/56
    /// ```
    pub edns_client_subnet: Option<IpNet>,

    /// ttl for all resource record
    pub rr_ttl: Option<u64>,
    /// minimum ttl for resource record
    pub rr_ttl_min: Option<u64>,
    /// maximum ttl for resource record
    pub rr_ttl_max: Option<u64>,
    /// maximum reply ttl for resource record
    pub rr_ttl_reply_max: Option<u64>,

    /// ttl for local address and host (default: rr-ttl-min)
    pub local_ttl: Option<u64>,

    /// Maximum number of IPs returned to the client|8|number of IPs, 1~16
    pub max_reply_ip_num: Option<u8>,

    /// response mode
    ///
    /// response-mode [first-ping|fastest-ip|fastest-response]
    pub response_mode: Option<ResponseMode>,

    pub log: LogConfig,

    pub audit: AuditConfig,

    /// Support reading dnsmasq dhcp file to resolve local hostname
    pub dnsmasq_lease_file: Option<PathBuf>,

    /// certificate file
    pub ca_file: Option<PathBuf>,
    /// certificate path
    pub ca_path: Option<PathBuf>,

    /// remote dns server list
    pub nameservers: Vec<NameServerInfo>,

    /// specific nameserver to domain
    ///
    /// nameserver /domain/[group|-]
    ///
    /// ```
    /// example:
    ///   nameserver /www.example.com/office, Set the domain name to use the appropriate server group.
    ///   nameserver /www.example.com/-, ignore this domain
    /// ```
    pub forward_rules: Vec<ForwardRule>,

    /// specific address to domain
    ///
    /// address /domain/[ip|-|-4|-6|#|#4|#6]
    ///
    /// ```
    /// example:
    ///   address /www.example.com/1.2.3.4, return ip 1.2.3.4 to client
    ///   address /www.example.com/-, ignore address, query from upstream, suffix 4, for ipv4, 6 for ipv6, none for all
    ///   address /www.example.com/#, return SOA to client, suffix 4, for ipv4, 6 for ipv6, none for all
    /// ```
    pub address_rules: AddressRules,

    /// set domain rules
    pub domain_rules: DomainRules,

    pub cnames: CNameRules,

    pub srv_records: SrvRecords,

    pub https_records: HttpsRecords,

    /// The proxy server for upstream querying.
    pub proxy_servers: HashMap<String, ProxyConfig>,

    pub nftsets: Vec<ConfigForDomain<Vec<ConfigForIP<NFTsetConfig>>>>,

    pub resolv_file: Option<PathBuf>,
    pub domain_set_providers: HashMap<String, Vec<DomainSetProvider>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedProxyConfig {
    pub name: String,
    pub config: ProxyConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigForDomain<T: Sized + parser::NomParser> {
    pub domain: Domain,
    pub config: T,
}

impl<T: Sized + parser::NomParser> std::ops::Deref for ConfigForDomain<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConfigForIP<T: Sized + parser::NomParser> {
    V4(T),
    V6(T),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NFTsetConfig {
    pub family: &'static str,
    pub table: String,
    pub name: String,
}

pub type Options<'a> = Vec<(&'a str, Option<&'a str>)>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct SslConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_key: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_key_pass: Option<String>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum DomainAddress {
    SOA,
    SOAv4,
    SOAv6,
    IGN,
    IGNv4,
    IGNv6,
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
}

impl std::fmt::Display for DomainAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use DomainAddress::*;
        match self {
            SOA => write!(f, "#"),
            SOAv4 => write!(f, "#4"),
            SOAv6 => write!(f, "#6"),
            IGN => write!(f, "-"),
            IGNv4 => write!(f, "-4"),
            IGNv6 => write!(f, "-6"),
            IPv4(ip) => write!(f, "{ip}"),
            IPv6(ip) => write!(f, "{ip}"),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
#[allow(clippy::upper_case_acronyms)]
pub enum Ignorable<T> {
    #[default]
    IGN,
    Value(T),
}

pub type CNameRule = Ignorable<Name>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRule {
    #[serde(with = "serde_str")]
    pub domain: Domain,
    #[serde(with = "serde_str")]
    pub address: DomainAddress,
}

/// alias: nameserver rules
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRule {
    #[serde(with = "serde_str")]
    pub domain: Domain,
    pub nameserver: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum HttpsRecordRule {
    SOA,
    Ignore,
    Filter {
        no_ipv4_hint: bool,
        no_ipv6_hint: bool,
    },
    RecordData(HTTPS),
}

macro_rules! impl_from_str {
    ($($type:ty),*) => {
        $(
            impl FromStr for $type {
                type Err=nom::Err<nom::error::Error<String>>;

                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    match NomParser::parse(s) {
                        Ok((_, v)) => Ok(v),
                        Err(err) => Err(err.to_owned()),
                    }
                }
            }
        )*
    };
}

impl_from_str!(AddressRule, Domain, DomainAddress, ListenerAddress);
