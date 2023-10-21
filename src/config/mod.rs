use crate::libdns::proto::rr::Name;

mod listener;
mod parser;

pub use listener::*;
pub use parser::NomParser;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigItem {
    NftSet(DomainConfigItem<Vec<IpConfig<NftsetConfig>>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainConfigItem<T: Sized + NomParser> {
    pub domain: Domain,
    pub config: T,
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
pub enum IpConfig<T: Sized + NomParser> {
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

use crate::dns_conf::{ServerOpts, SslConfig};
