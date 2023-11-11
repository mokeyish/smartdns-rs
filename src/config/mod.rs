use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use crate::{
    infra::file_mode::FileMode,
    libdns::proto::rr::{Name, RecordType},
};
use crate::{log::Level, proxy::ProxyConfig};

mod domain_rule;
mod domain_set_provider;
mod listener;
mod nameserver;
pub mod parser;
mod response_mode;
mod server_opts;
mod speed_mode;

use byte_unit::Byte;
pub use domain_rule::*;
pub use domain_set_provider::*;
use ipnet::IpNet;
pub use listener::*;
pub use nameserver::*;
pub use response_mode::*;
pub use server_opts::*;
pub use speed_mode::*;

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
pub enum Domain {
    Name(Name),
    Set(String),
}

impl From<Name> for Domain {
    #[inline]
    fn from(v: Name) -> Self {
        Self::Name(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConfigForIP<T: Sized + parser::NomParser> {
    V4(T),
    V6(T),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NftsetConfig {
    pub family: &'static str,
    pub table: String,
    pub name: String,
}

pub type Options<'a> = Vec<(&'a str, Option<&'a str>)>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SslConfig {
    pub server_name: Option<String>,
    pub certificate: Option<PathBuf>,
    pub certificate_key: Option<PathBuf>,
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

#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
#[allow(clippy::upper_case_acronyms)]
pub enum Ignorable<T> {
    #[default]
    IGN,
    Value(T),
}

pub type CName = Ignorable<Name>;

/// alias: nameserver rules
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRule {
    pub domain: Domain,
    pub nameserver: String,
}
