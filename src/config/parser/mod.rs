use ipnet::Ipv6Net;
use nom::{
    IResult, Parser, branch::*, bytes::complete::*, character::complete::*, combinator::*,
    multi::*, sequence::*,
};

mod address_rule;
mod bind_addr;
mod bool;
mod bytes;
mod client_rule;
mod cname;
mod config_for_domain;
mod domain;
mod domain_rule;
mod domain_set;
mod file_mode;
mod forward_rule;
mod glob_pattern;
mod https_record;
mod ip_alias;
mod ip_net;
mod ip_set;
mod iporset;
mod log_level;
mod nameserver;
mod nftset;
mod nom_recipes;
mod options;
mod path;
mod proxy_config;
mod record_type;
mod response_mode;
mod speed_mode;
mod srv;
mod svcb;

use super::*;

pub(crate) trait NomParser: Sized {
    fn parse(input: &str) -> IResult<&str, Self>;

    // fn from_str(s: &str) -> Result<Self, nom::Err<nom::error::Error<&str>>> {
    //     match Self::parse(s) {
    //         Ok((_, v)) => Ok(v),
    //         Err(err) => Err(err),
    //     }
    // }
}

impl NomParser for usize {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        map(u64, |v| v as usize).parse(input)
    }
}

impl NomParser for u64 {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        u64(input)
    }
}

impl NomParser for u8 {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        u8(input)
    }
}

impl NomParser for String {
    fn parse(input: &str) -> IResult<&str, Self> {
        map(is_not(" \t\r\n"), ToString::to_string).parse(input)
    }
}

/// one line config.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::large_enum_variant)]
pub enum OneConfig {
    Address(AddressRule),
    AuditEnable(bool),
    AuditFile(PathBuf),
    AuditFileMode(FileMode),
    AuditNum(usize),
    AuditSize(Byte),
    BindCertFile(PathBuf),
    BindCertKeyFile(PathBuf),
    BindCertKeyPass(String),
    BlacklistIp(IpOrSet),
    BogusNxDomain(IpOrSet),
    CacheFile(PathBuf),
    CachePersist(bool),
    CacheSize(usize),
    CacheCheckpointTime(u64),
    CaFile(PathBuf),
    CaPath(PathBuf),
    ClientRule(ClientRule),
    CNAME(ConfigForDomain<CNameRule>),
    SrvRecord(ConfigForDomain<SRV>),
    GroupBegin(String),
    GroupEnd,
    HttpsRecord(ConfigForDomain<HttpsRecordRule>),
    ConfFile(PathBuf),
    DnsmasqLeaseFile(PathBuf),
    Dns64(Ipv6Net),
    Domain(Name),
    DomainRule(ConfigForDomain<DomainRule>),
    DomainSetProvider(DomainSetProvider),
    DualstackIpAllowForceAAAA(bool),
    DualstackIpSelection(bool),
    DualstackIpSelectionThreshold(u16),
    EdnsClientSubnet(IpNet),
    ExpandPtrFromAddress(bool),
    ForceAAAASOA(bool),
    ForceHTTPSSOA(bool),
    ForceQtypeSoa(RecordType),
    ForwardRule(ForwardRule),
    HostsFile(glob::Pattern),
    IgnoreIp(IpOrSet),
    Listener(BindAddrConfig),
    LocalTtl(u64),
    LogConsole(bool),
    LogNum(u64),
    LogSize(Byte),
    LogLevel(Level),
    LogFile(PathBuf),
    LogFileMode(FileMode),
    LogFilter(String),
    MaxReplyIpNum(u8),
    MdnsLookup(bool),
    NftSet(ConfigForDomain<Vec<ConfigForIP<NFTsetConfig>>>),
    NumWorkers(usize),
    PrefetchDomain(bool),
    ProxyConfig(NamedProxyConfig),
    ResolvHostname(bool),
    ResponseMode(ResponseMode),
    ServeExpired(bool),
    ServeExpiredTtl(u64),
    ServeExpiredReplyTtl(u64),
    Server(NameServerInfo),
    ServerName(Name),
    ResolvFile(PathBuf),
    RrTtl(u64),
    RrTtlMin(u64),
    RrTtlMax(u64),
    RrTtlReplyMax(u64),
    SpeedMode(Option<SpeedCheckModeList>),
    TcpIdleTime(u64),
    WhitelistIp(IpOrSet),
    User(String),
    IpSetProvider(IpSetProvider),
    IpAlias(IpAlias),
}

pub fn parse_config(input: &str) -> IResult<&str, OneConfig> {
    fn comment(input: &str) -> IResult<&str, Option<&str>> {
        opt(preceded(space1, preceded(char('#'), not_line_ending))).parse(input)
    }

    fn config_name<'a>(
        keyword: &'static str,
    ) -> impl Parser<&'a str, Output = &'a str, Error = nom::error::Error<&'a str>> {
        preceded(space0, tag_no_case(keyword))
    }

    fn config<'a, T: NomParser>(
        name: &'static str,
    ) -> impl Parser<&'a str, Output = T, Error = nom::error::Error<&'a str>> {
        preceded(config_name(name), preceded(space1, T::parse))
    }

    let group1 = alt((
        map(config("address"), OneConfig::Address),
        map(config("audit-enable"), OneConfig::AuditEnable),
        map(config("audit-file-mode"), OneConfig::AuditFileMode),
        map(config("audit-file"), OneConfig::AuditFile),
        map(config("audit-num"), OneConfig::AuditNum),
        map(config("audit-size"), OneConfig::AuditSize),
        map(config("bind-cert-file"), OneConfig::BindCertFile),
        map(config("bind-cert-key-file"), OneConfig::BindCertKeyFile),
        map(config("bind-cert-key-pass"), OneConfig::BindCertKeyPass),
        map(config("bogus-nxdomain"), OneConfig::BogusNxDomain),
        map(config("blacklist-ip"), OneConfig::BlacklistIp),
        map(config("cache-file"), OneConfig::CacheFile),
        map(config("cache-persist"), OneConfig::CachePersist),
        map(config("cache-size"), OneConfig::CacheSize),
        map(
            config("cache-checkpoint-time"),
            OneConfig::CacheCheckpointTime,
        ),
        map(config("ca-file"), OneConfig::CaFile),
        map(config("ca-path"), OneConfig::CaPath),
        map(config("client-rules"), OneConfig::ClientRule),
        map(config("client-rule"), OneConfig::ClientRule),
        map(config("conf-file"), OneConfig::ConfFile),
    ));

    let group2 = alt((
        map(config("domain-rules"), OneConfig::DomainRule),
        map(config("domain-rule"), OneConfig::DomainRule),
        map(config("domain-set"), OneConfig::DomainSetProvider),
        map(config("dnsmasq-lease-file"), OneConfig::DnsmasqLeaseFile),
        map(config("dns64"), OneConfig::Dns64),
        map(
            config("dualstack-ip-allow-force-AAAA"),
            OneConfig::DualstackIpAllowForceAAAA,
        ),
        map(
            config("dualstack-ip-selection"),
            OneConfig::DualstackIpSelection,
        ),
        map(config("edns-client-subnet"), OneConfig::EdnsClientSubnet),
        map(
            config("expand-ptr-from-address"),
            OneConfig::ExpandPtrFromAddress,
        ),
        map(config("force-AAAA-SOA"), OneConfig::ForceAAAASOA),
        map(config("force-HTTPS-SOA"), OneConfig::ForceHTTPSSOA),
        map(config("force-qtype-soa"), OneConfig::ForceQtypeSoa),
        map(config("response"), OneConfig::ResponseMode),
        map(config("group-begin"), OneConfig::GroupBegin),
        map(config_name("group-end"), |_| OneConfig::GroupEnd),
        map(config("prefetch-domain"), OneConfig::PrefetchDomain),
        map(config("cname"), OneConfig::CNAME),
        map(config("num-workers"), OneConfig::NumWorkers),
        map(config("domain"), OneConfig::Domain),
    ));

    let group3 = alt((
        map(config("hosts-file"), OneConfig::HostsFile),
        map(config("https-record"), OneConfig::HttpsRecord),
        map(config("ignore-ip"), OneConfig::IgnoreIp),
        map(config("local-ttl"), OneConfig::LocalTtl),
        map(config("log-console"), OneConfig::LogConsole),
        map(config("log-file-mode"), OneConfig::LogFileMode),
        map(config("log-file"), OneConfig::LogFile),
        map(config("log-filter"), OneConfig::LogFilter),
        map(config("log-level"), OneConfig::LogLevel),
        map(config("log-num"), OneConfig::LogNum),
        map(config("log-size"), OneConfig::LogSize),
        map(config("max-reply-ip-num"), OneConfig::MaxReplyIpNum),
        map(config("mdns-lookup"), OneConfig::MdnsLookup),
        map(config("nameserver"), OneConfig::ForwardRule),
        map(config("proxy-server"), OneConfig::ProxyConfig),
        map(config("rr-ttl-reply-max"), OneConfig::RrTtlReplyMax),
        map(config("rr-ttl-min"), OneConfig::RrTtlMin),
        map(config("rr-ttl-max"), OneConfig::RrTtlMax),
        map(config("rr-ttl"), OneConfig::RrTtl),
    ));

    let group4 = alt((
        map(config("resolv-file"), OneConfig::ResolvFile),
        map(config("resolv-hostanme"), OneConfig::ResolvHostname),
        map(config("response-mode"), OneConfig::ResponseMode),
        map(config("server-name"), OneConfig::ServerName),
        map(config("speed-check-mode"), OneConfig::SpeedMode),
        map(
            config("serve-expired-reply-ttl"),
            OneConfig::ServeExpiredReplyTtl,
        ),
        map(config("serve-expired-ttl"), OneConfig::ServeExpiredTtl),
        map(config("serve-expired"), OneConfig::ServeExpired),
        map(config("srv-record"), OneConfig::SrvRecord),
        map(config("resolv-hostname"), OneConfig::ResolvHostname),
        map(config("tcp-idle-time"), OneConfig::TcpIdleTime),
        map(config("nftset"), OneConfig::NftSet),
        map(config("user"), OneConfig::User),
    ));

    let group5 = alt((
        map(config("whitelist-ip"), OneConfig::WhitelistIp),
        map(config("ip-set"), OneConfig::IpSetProvider),
        map(config("ip-alias"), OneConfig::IpAlias),
        map(NomParser::parse, OneConfig::Listener),
        map(NomParser::parse, OneConfig::Server),
    ));

    let group = alt((group1, group2, group3, group4, group5));

    terminated(group, comment).parse(input)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn test_nftset() {
        assert_eq!(
            parse_config("nftset /www.example.com/#4:inet#tab#dns4").unwrap(),
            (
                "",
                OneConfig::NftSet(ConfigForDomain {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: vec![ConfigForIP::V4(NFTsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })]
                })
            )
        );

        assert_eq!(
            parse_config("nftset /www.example.com/#4:inet#tab#dns4 # comment 123").unwrap(),
            (
                "",
                OneConfig::NftSet(ConfigForDomain {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: vec![ConfigForIP::V4(NFTsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })]
                })
            )
        );
    }

    #[test]
    fn test_parse_blacklist_ip() {
        assert_eq!(
            parse_config("blacklist-ip  243.185.187.39").unwrap(),
            (
                "",
                OneConfig::BlacklistIp(IpOrSet::Net("243.185.187.39/32".parse().unwrap()))
            )
        );

        assert_eq!(
            parse_config("blacklist-ip ip-set:name").unwrap(),
            ("", OneConfig::BlacklistIp(IpOrSet::Set("name".to_string())))
        );
    }

    #[test]
    fn test_parse_whitelist_ip() {
        assert_eq!(
            parse_config("whitelist-ip  243.185.187.39").unwrap(),
            (
                "",
                OneConfig::WhitelistIp(IpOrSet::Net("243.185.187.39/32".parse().unwrap()))
            )
        );

        assert_eq!(
            parse_config("whitelist-ip ip-set:name").unwrap(),
            ("", OneConfig::WhitelistIp(IpOrSet::Set("name".to_string())))
        );
    }

    #[test]
    fn test_parse_log_size() {
        assert_eq!(
            parse_config("log-size 1M").unwrap(),
            ("", OneConfig::LogSize("1M".parse().unwrap()))
        );
    }

    #[test]
    fn test_parse_speed_check_mode() {
        assert_eq!(
            parse_config("speed-check-mode none").unwrap(),
            ("", OneConfig::SpeedMode(Default::default()))
        );
    }

    #[test]
    fn test_parse_response_mode() {
        assert_eq!(
            parse_config("response-mode fastest-response").unwrap(),
            ("", OneConfig::ResponseMode(ResponseMode::FastestResponse))
        );
    }

    #[test]
    fn test_parse_resolv_hostname() {
        assert_eq!(
            parse_config("resolv-hostname no").unwrap(),
            ("", OneConfig::ResolvHostname(false))
        );
    }

    #[test]
    fn test_parse_domain_set() {
        assert_eq!(
            parse_config("domain-set -name outbound -file /etc/smartdns/geoip.txt").unwrap(),
            (
                "",
                OneConfig::DomainSetProvider(DomainSetProvider::File(DomainSetFileProvider {
                    name: "outbound".to_string(),
                    file: Path::new("/etc/smartdns/geoip.txt").to_path_buf(),
                    content_type: Default::default(),
                }))
            )
        );

        assert_eq!(
            parse_config("domain-set -n proxy-server -f proxy-server-list.txt").unwrap(),
            (
                "",
                OneConfig::DomainSetProvider(DomainSetProvider::File(DomainSetFileProvider {
                    name: "proxy-server".to_string(),
                    file: Path::new("proxy-server-list.txt").to_path_buf(),
                    content_type: Default::default(),
                }))
            )
        );
    }

    #[test]
    fn test_parse_domain_rule() {
        assert_eq!(
            parse_config("domain-rules /domain-set:domain-block-list/ --address #").unwrap(),
            (
                "",
                OneConfig::DomainRule(ConfigForDomain {
                    domain: Domain::Set("domain-block-list".to_string()),
                    config: DomainRule {
                        address: Some(AddressRuleValue::SOA),
                        ..Default::default()
                    }
                })
            )
        );
    }

    #[test]
    fn test_parse_ip_set() {
        assert_eq!(
            parse_config("ip-set -name name -file /path/to/file.txt").unwrap(),
            (
                "",
                OneConfig::IpSetProvider(IpSetProvider {
                    name: "name".to_string(),
                    file: Path::new("/path/to/file.txt").to_path_buf(),
                })
            )
        );
    }
}
