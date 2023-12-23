use nom::{
    branch::*, bytes::complete::*, character::complete::*, combinator::*, multi::*, sequence::*,
    IResult,
};

mod address_rule;
mod bool;
mod bytes;
mod cname;
mod config_for_domain;
mod domain;
mod domain_policy;
mod domain_rule;
mod domain_set;
mod file_mode;
mod forward_rule;
mod ipnet;
mod listener;
mod log_level;
mod nameserver;
mod nftset;
mod options;
mod path;
mod proxy_config;
mod record_type;
mod response_mode;
mod speed_mode;

use super::*;

pub trait NomParser: Sized {
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
        map(u64, |v| v as usize)(input)
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
        map(is_not(" \t\r\n"), ToString::to_string)(input)
    }
}

/// one line config.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
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
    BlacklistIp(IpNet),
    BogusNxDomain(IpNet),
    CacheFile(PathBuf),
    CachePersist(bool),
    CacheSize(usize),
    CaFile(PathBuf),
    CaPath(PathBuf),
    CName(ConfigForDomain<CName>),
    ConfFile(PathBuf),
    DnsmasqLeaseFile(PathBuf),
    Domain(Name),
    DomainRule(ConfigForDomain<DomainRule>),
    DomainSetProvider(DomainSetProvider),
    DualstackIpAllowForceAAAA(bool),
    DualstackIpSelection(bool),
    DualstackIpSelectionThreshold(u16),
    EdnsClientSubnet(IpNet),
    ForceAAAASOA(bool),
    ForceQtypeSoa(RecordType),
    ForwardRule(ForwardRule),
    IgnoreIp(IpNet),
    Listener(ListenerConfig),
    LocalTtl(u64),
    LogNum(u64),
    LogSize(Byte),
    LogLevel(Level),
    LogFile(PathBuf),
    LogFileMode(FileMode),
    LogFilter(String),
    MaxReplyIpNum(u8),
    NftSet(ConfigForDomain<Vec<ConfigForIP<NftsetConfig>>>),
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
    SpeedMode(SpeedCheckModeList),
    TcpIdleTime(u64),
    WhitelistIp(IpNet),
    User(String),
}

pub fn parse_config(input: &str) -> IResult<&str, OneConfig> {
    let comment = opt(preceded(space1, preceded(char('#'), not_line_ending)));

    fn parse_item<'a, T: NomParser>(
        keyword: &'static str,
    ) -> impl FnMut(&'a str) -> IResult<&str, T> {
        preceded(tuple((space0, tag_no_case(keyword), space1)), T::parse)
    }

    let group1 = alt((
        map(parse_item("address"), OneConfig::Address),
        map(parse_item("audit-enable"), OneConfig::AuditEnable),
        map(parse_item("audit-file-mode"), OneConfig::AuditFileMode),
        map(parse_item("audit-file"), OneConfig::AuditFile),
        map(parse_item("audit-num"), OneConfig::AuditNum),
        map(parse_item("audit-size"), OneConfig::AuditSize),
        map(parse_item("bind-cert-file"), OneConfig::BindCertFile),
        map(parse_item("bind-cert-key-file"), OneConfig::BindCertKeyFile),
        map(parse_item("bind-cert-key-pass"), OneConfig::BindCertKeyPass),
        map(parse_item("blacklist-ip"), OneConfig::BlacklistIp),
        map(parse_item("cache-file"), OneConfig::CacheFile),
        map(parse_item("cache-persist"), OneConfig::CachePersist),
        map(parse_item("ca-file"), OneConfig::CaFile),
        map(parse_item("ca-path"), OneConfig::CaPath),
        map(parse_item("conf-file"), OneConfig::ConfFile),
        map(parse_item("cache-size"), OneConfig::CacheSize),
        map(parse_item("domain-rules"), OneConfig::DomainRule),
        map(parse_item("domain-rule"), OneConfig::DomainRule),
        map(parse_item("domain-set"), OneConfig::DomainSetProvider),
        map(
            parse_item("dnsmasq-lease-file"),
            OneConfig::DnsmasqLeaseFile,
        ),
        map(
            parse_item("dualstack-ip-allow-force-AAAA"),
            OneConfig::DualstackIpAllowForceAAAA,
        ),
    ));

    let group2 = alt((
        map(
            parse_item("dualstack-ip-selection"),
            OneConfig::DualstackIpSelection,
        ),
        map(
            parse_item("edns-client-subnet"),
            OneConfig::EdnsClientSubnet,
        ),
        map(parse_item("force-AAAA-SOA"), OneConfig::ForceAAAASOA),
        map(parse_item("force-qtype-soa"), OneConfig::ForceQtypeSoa),
        map(parse_item("response"), OneConfig::ResponseMode),
        map(parse_item("prefetch-domain"), OneConfig::PrefetchDomain),
        map(parse_item("cname"), OneConfig::CName),
        map(parse_item("num-workers"), OneConfig::NumWorkers),
        map(parse_item("domain"), OneConfig::Domain),
        map(parse_item("local-ttl"), OneConfig::LocalTtl),
        map(parse_item("log-file-mode"), OneConfig::LogFileMode),
        map(parse_item("log-file"), OneConfig::LogFile),
        map(parse_item("log-filter"), OneConfig::LogFilter),
        map(parse_item("log-level"), OneConfig::LogLevel),
        map(parse_item("log-num"), OneConfig::LogNum),
        map(parse_item("log-size"), OneConfig::LogSize),
        map(parse_item("max-reply-ip-num"), OneConfig::MaxReplyIpNum),
        map(parse_item("nameserver"), OneConfig::ForwardRule),
    ));

    let group3 = alt((
        map(parse_item("proxy-server"), OneConfig::ProxyConfig),
        map(parse_item("rr-ttl-reply-max"), OneConfig::RrTtlReplyMax),
        map(parse_item("rr-ttl-min"), OneConfig::RrTtlMin),
        map(parse_item("rr-ttl-max"), OneConfig::RrTtlMax),
        map(parse_item("rr-ttl"), OneConfig::RrTtl),
        map(parse_item("resolv-file"), OneConfig::ResolvFile),
        map(parse_item("response-mode"), OneConfig::ResponseMode),
        map(parse_item("server-name"), OneConfig::ServerName),
        map(parse_item("speed-check-mode"), OneConfig::SpeedMode),
        map(
            parse_item("serve-expired-reply-ttl"),
            OneConfig::ServeExpiredReplyTtl,
        ),
        map(parse_item("serve-expired-ttl"), OneConfig::ServeExpiredTtl),
        map(parse_item("serve-expired"), OneConfig::ServeExpired),
        map(parse_item("resolv-hostname"), OneConfig::ResolvHostname),
        map(parse_item("tcp-idle-time"), OneConfig::TcpIdleTime),
        map(parse_item("nftset"), OneConfig::NftSet),
        map(parse_item("user"), OneConfig::User),
        map(NomParser::parse, OneConfig::Listener),
        map(NomParser::parse, OneConfig::Server),
    ));
    terminated(alt((group1, group2, group3)), comment)(input)
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
                    config: vec![ConfigForIP::V4(NftsetConfig {
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
                    config: vec![ConfigForIP::V4(NftsetConfig {
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
                OneConfig::BlacklistIp("243.185.187.39/32".parse().unwrap())
            )
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
    }
}
