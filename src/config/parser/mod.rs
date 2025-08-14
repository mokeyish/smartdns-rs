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
// mod line;
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
pub enum ConfigItem {
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
    DualstackIpSelectionThreshold(u64),
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

impl std::fmt::Display for ConfigItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigItem::Address(rule) => {
                write!(f, "address {rule}")?;
            }
            ConfigItem::AuditEnable(_) => todo!(),
            ConfigItem::AuditFile(_) => todo!(),
            ConfigItem::AuditFileMode(_) => todo!(),
            ConfigItem::AuditNum(_) => todo!(),
            ConfigItem::AuditSize(_) => todo!(),
            ConfigItem::BindCertFile(_) => todo!(),
            ConfigItem::BindCertKeyFile(_) => todo!(),
            ConfigItem::BindCertKeyPass(_) => todo!(),
            ConfigItem::BlacklistIp(_) => todo!(),
            ConfigItem::BogusNxDomain(_) => todo!(),
            ConfigItem::CacheFile(_) => todo!(),
            ConfigItem::CachePersist(_) => todo!(),
            ConfigItem::CacheSize(_) => todo!(),
            ConfigItem::CacheCheckpointTime(_) => todo!(),
            ConfigItem::CaFile(_) => todo!(),
            ConfigItem::CaPath(_) => todo!(),
            ConfigItem::ClientRule(_) => todo!(),
            ConfigItem::CNAME(_) => todo!(),
            ConfigItem::SrvRecord(_) => todo!(),
            ConfigItem::GroupBegin(_) => todo!(),
            ConfigItem::GroupEnd => todo!(),
            ConfigItem::HttpsRecord(_) => todo!(),
            ConfigItem::ConfFile(_) => todo!(),
            ConfigItem::DnsmasqLeaseFile(_) => todo!(),
            ConfigItem::Domain(_) => todo!(),
            ConfigItem::DomainRule(_) => todo!(),
            ConfigItem::DomainSetProvider(_) => todo!(),
            ConfigItem::DualstackIpAllowForceAAAA(_) => todo!(),
            ConfigItem::DualstackIpSelection(_) => todo!(),
            ConfigItem::DualstackIpSelectionThreshold(_) => todo!(),
            ConfigItem::EdnsClientSubnet(_) => todo!(),
            ConfigItem::ExpandPtrFromAddress(_) => todo!(),
            ConfigItem::ForceAAAASOA(_) => todo!(),
            ConfigItem::ForceHTTPSSOA(_) => todo!(),
            ConfigItem::ForceQtypeSoa(_) => todo!(),
            ConfigItem::ForwardRule(rule) => {
                write!(f, "nameserver {rule}")?;
            }
            ConfigItem::HostsFile(_) => todo!(),
            ConfigItem::IgnoreIp(_) => todo!(),
            ConfigItem::Listener(_) => todo!(),
            ConfigItem::LocalTtl(_) => todo!(),
            ConfigItem::LogConsole(_) => todo!(),
            ConfigItem::LogNum(_) => todo!(),
            ConfigItem::LogSize(_) => todo!(),
            ConfigItem::LogLevel(_) => todo!(),
            ConfigItem::LogFile(_) => todo!(),
            ConfigItem::LogFileMode(_) => todo!(),
            ConfigItem::LogFilter(_) => todo!(),
            ConfigItem::MaxReplyIpNum(_) => todo!(),
            ConfigItem::MdnsLookup(_) => todo!(),
            ConfigItem::NftSet(_) => todo!(),
            ConfigItem::NumWorkers(_) => todo!(),
            ConfigItem::PrefetchDomain(_) => todo!(),
            ConfigItem::ProxyConfig(_) => todo!(),
            ConfigItem::ResolvHostname(_) => todo!(),
            ConfigItem::ResponseMode(_) => todo!(),
            ConfigItem::ServeExpired(_) => todo!(),
            ConfigItem::ServeExpiredTtl(_) => todo!(),
            ConfigItem::ServeExpiredReplyTtl(_) => todo!(),
            ConfigItem::Server(c) => {
                write!(f, "server {c}")?;
            }
            ConfigItem::ServerName(_) => todo!(),
            ConfigItem::ResolvFile(_) => todo!(),
            ConfigItem::RrTtl(_) => todo!(),
            ConfigItem::RrTtlMin(_) => todo!(),
            ConfigItem::RrTtlMax(_) => todo!(),
            ConfigItem::RrTtlReplyMax(_) => todo!(),
            ConfigItem::SpeedMode(_) => todo!(),
            ConfigItem::TcpIdleTime(_) => todo!(),
            ConfigItem::WhitelistIp(_) => todo!(),
            ConfigItem::User(_) => todo!(),
            ConfigItem::IpSetProvider(_) => todo!(),
            ConfigItem::IpAlias(_) => todo!(),
            ConfigItem::Dns64(_) => todo!(),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum ConfigLine<'a> {
    Config {
        config: ConfigItem,
        comment: Option<&'a str>,
    },
    Comment(&'a str),
    EmptyLine,
    Eof,
}

pub struct ConfigFile<'a>(Vec<ConfigLine<'a>>);

impl<'a> std::ops::Deref for ConfigFile<'a> {
    type Target = Vec<ConfigLine<'a>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> std::ops::DerefMut for ConfigFile<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> std::fmt::Display for ConfigFile<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for line in &self.0 {
            match line {
                ConfigLine::Config { config, comment } => {
                    writeln!(f, "{}{}", config, comment.unwrap_or_default())?
                }
                ConfigLine::Comment(comment) => writeln!(f, "{comment}")?,
                ConfigLine::EmptyLine => writeln!(f)?,
                ConfigLine::Eof => (),
            }
        }
        Ok(())
    }
}

impl ConfigFile<'_> {
    pub fn parse(input: &str) -> IResult<&str, ConfigFile<'_>> {
        map(separated_list0(line_ending, parse_line), ConfigFile).parse(input)
    }
}

fn parse_line<'a>(input: &'a str) -> IResult<&'a str, ConfigLine<'a>> {
    fn comment(input: &str) -> IResult<&str, &str> {
        map(recognize((char('#'), not_line_ending)), |comment: &str| {
            comment.trim_end()
        })
        .parse(input)
    }

    fn config_name<'a>(
        keyword: &'static str,
    ) -> impl Parser<&'a str, Output = &'a str, Error = nom::error::Error<&'a str>> {
        tag_no_case(keyword)
    }

    fn config<'a, T: NomParser>(
        name: &'static str,
    ) -> impl Parser<&'a str, Output = T, Error = nom::error::Error<&'a str>> {
        preceded(config_name(name), preceded(space1, T::parse))
    }

    let group1 = alt((
        map(config("address"), ConfigItem::Address),
        map(config("audit-enable"), ConfigItem::AuditEnable),
        map(config("audit-file-mode"), ConfigItem::AuditFileMode),
        map(config("audit-file"), ConfigItem::AuditFile),
        map(config("audit-num"), ConfigItem::AuditNum),
        map(config("audit-size"), ConfigItem::AuditSize),
        map(config("bind-cert-file"), ConfigItem::BindCertFile),
        map(config("bind-cert-key-file"), ConfigItem::BindCertKeyFile),
        map(config("bind-cert-key-pass"), ConfigItem::BindCertKeyPass),
        map(config("bogus-nxdomain"), ConfigItem::BogusNxDomain),
        map(config("blacklist-ip"), ConfigItem::BlacklistIp),
        map(config("cache-file"), ConfigItem::CacheFile),
        map(config("cache-persist"), ConfigItem::CachePersist),
        map(config("cache-size"), ConfigItem::CacheSize),
        map(
            config("cache-checkpoint-time"),
            ConfigItem::CacheCheckpointTime,
        ),
        map(config("ca-file"), ConfigItem::CaFile),
        map(config("ca-path"), ConfigItem::CaPath),
        map(config("client-rules"), ConfigItem::ClientRule),
        map(config("client-rule"), ConfigItem::ClientRule),
        map(config("conf-file"), ConfigItem::ConfFile),
    ));

    let group2 = alt((
        map(config("domain-rules"), ConfigItem::DomainRule),
        map(config("domain-rule"), ConfigItem::DomainRule),
        map(config("domain-set"), ConfigItem::DomainSetProvider),
        map(config("dnsmasq-lease-file"), ConfigItem::DnsmasqLeaseFile),
        map(config("dns64"), ConfigItem::Dns64),
        map(
            config("dualstack-ip-allow-force-AAAA"),
            ConfigItem::DualstackIpAllowForceAAAA,
        ),
        map(
            config("dualstack-ip-selection"),
            ConfigItem::DualstackIpSelection,
        ),
        map(
            config("dualstack-ip-selection-threshold"),
            ConfigItem::DualstackIpSelectionThreshold,
        ),
        map(config("edns-client-subnet"), ConfigItem::EdnsClientSubnet),
        map(
            config("expand-ptr-from-address"),
            ConfigItem::ExpandPtrFromAddress,
        ),
        map(config("force-AAAA-SOA"), ConfigItem::ForceAAAASOA),
        map(config("force-HTTPS-SOA"), ConfigItem::ForceHTTPSSOA),
        map(config("force-qtype-soa"), ConfigItem::ForceQtypeSoa),
        map(config("response"), ConfigItem::ResponseMode),
        map(config("group-begin"), ConfigItem::GroupBegin),
        map(config_name("group-end"), |_| ConfigItem::GroupEnd),
        map(config("prefetch-domain"), ConfigItem::PrefetchDomain),
        map(config("cname"), ConfigItem::CNAME),
        map(config("num-workers"), ConfigItem::NumWorkers),
        map(config("domain"), ConfigItem::Domain),
        map(config("hosts-file"), ConfigItem::HostsFile),
    ));

    let group3 = alt((
        map(config("https-record"), ConfigItem::HttpsRecord),
        map(config("ignore-ip"), ConfigItem::IgnoreIp),
        map(config("local-ttl"), ConfigItem::LocalTtl),
        map(config("log-console"), ConfigItem::LogConsole),
        map(config("log-file-mode"), ConfigItem::LogFileMode),
        map(config("log-file"), ConfigItem::LogFile),
        map(config("log-filter"), ConfigItem::LogFilter),
        map(config("log-level"), ConfigItem::LogLevel),
        map(config("log-num"), ConfigItem::LogNum),
        map(config("log-size"), ConfigItem::LogSize),
        map(config("max-reply-ip-num"), ConfigItem::MaxReplyIpNum),
        map(config("mdns-lookup"), ConfigItem::MdnsLookup),
        map(config("nameserver"), ConfigItem::ForwardRule),
        map(config("proxy-server"), ConfigItem::ProxyConfig),
        map(config("rr-ttl-reply-max"), ConfigItem::RrTtlReplyMax),
        map(config("rr-ttl-min"), ConfigItem::RrTtlMin),
        map(config("rr-ttl-max"), ConfigItem::RrTtlMax),
        map(config("rr-ttl"), ConfigItem::RrTtl),
        map(config("resolv-file"), ConfigItem::ResolvFile),
    ));

    let group4 = alt((
        map(config("resolv-hostanme"), ConfigItem::ResolvHostname),
        map(config("response-mode"), ConfigItem::ResponseMode),
        map(config("server-name"), ConfigItem::ServerName),
        map(config("speed-check-mode"), ConfigItem::SpeedMode),
        map(
            config("serve-expired-reply-ttl"),
            ConfigItem::ServeExpiredReplyTtl,
        ),
        map(config("serve-expired-ttl"), ConfigItem::ServeExpiredTtl),
        map(config("serve-expired"), ConfigItem::ServeExpired),
        map(config("srv-record"), ConfigItem::SrvRecord),
        map(config("resolv-hostname"), ConfigItem::ResolvHostname),
        map(config("tcp-idle-time"), ConfigItem::TcpIdleTime),
        map(config("nftset"), ConfigItem::NftSet),
        map(config("user"), ConfigItem::User),
    ));

    let group5 = alt((
        map(config("whitelist-ip"), ConfigItem::WhitelistIp),
        map(config("ip-set"), ConfigItem::IpSetProvider),
        map(config("ip-alias"), ConfigItem::IpAlias),
        map(NomParser::parse, ConfigItem::Listener),
        map(NomParser::parse, ConfigItem::Server),
    ));

    let group = alt((group1, group2, group3, group4, group5));

    alt((
        map(
            (
                preceded(space0, group),
                alt((
                    map(recognize((space1, comment)), Some),
                    map(space0, |_| None),
                )),
            ),
            |(config, comment)| ConfigLine::Config { config, comment },
        ),
        map(preceded(space0, comment), ConfigLine::Comment),
        map(eof, |_| ConfigLine::Eof),
        map(space0, |_| ConfigLine::EmptyLine),
    ))
    .parse(input)
}

pub fn parse_config(input: &str) -> IResult<&str, Option<ConfigItem>> {
    let (input, line) = parse_line(input)?;

    let item = match line {
        ConfigLine::Config { config, .. } => Some(config),
        _ => None,
    };

    Ok((input, item))
}

#[cfg(test)]
mod tests {
    use indoc::indoc;
    use std::path::Path;

    use super::*;

    #[test]
    fn test_nftset() {
        assert_eq!(
            parse_config("nftset /www.example.com/#4:inet#tab#dns4").unwrap(),
            (
                "",
                ConfigItem::NftSet(ConfigForDomain {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: vec![ConfigForIP::V4(NFTsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })]
                })
                .into()
            )
        );

        assert_eq!(
            parse_config("nftset /www.example.com/#4:inet#tab#dns4 # comment 123").unwrap(),
            (
                "",
                ConfigItem::NftSet(ConfigForDomain {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: vec![ConfigForIP::V4(NFTsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })]
                })
                .into()
            )
        );
    }

    #[test]
    fn test_parse_blacklist_ip() {
        assert_eq!(
            parse_config("blacklist-ip  243.185.187.39").unwrap(),
            (
                "",
                ConfigItem::BlacklistIp(IpOrSet::Net("243.185.187.39/32".parse().unwrap())).into()
            )
        );

        assert_eq!(
            parse_config("blacklist-ip ip-set:name").unwrap(),
            (
                "",
                ConfigItem::BlacklistIp(IpOrSet::Set("name".to_string())).into()
            )
        );
    }

    #[test]
    fn test_parse_whitelist_ip() {
        assert_eq!(
            parse_config("whitelist-ip  243.185.187.39").unwrap(),
            (
                "",
                ConfigItem::WhitelistIp(IpOrSet::Net("243.185.187.39/32".parse().unwrap())).into()
            )
        );

        assert_eq!(
            parse_config("whitelist-ip ip-set:name").unwrap(),
            (
                "",
                ConfigItem::WhitelistIp(IpOrSet::Set("name".to_string())).into()
            )
        );
    }

    #[test]
    fn test_parse_log_size() {
        assert_eq!(
            parse_config("log-size 1M").unwrap(),
            ("", ConfigItem::LogSize("1M".parse().unwrap()).into())
        );
    }

    #[test]
    fn test_parse_speed_check_mode() {
        assert_eq!(
            parse_config("speed-check-mode none").unwrap(),
            ("", ConfigItem::SpeedMode(Default::default()).into())
        );
    }

    #[test]
    fn test_parse_response_mode() {
        assert_eq!(
            parse_config("response-mode fastest-response").unwrap(),
            (
                "",
                ConfigItem::ResponseMode(ResponseMode::FastestResponse).into()
            )
        );
    }

    #[test]
    fn test_parse_resolv_hostname() {
        assert_eq!(
            parse_config("resolv-hostname no").unwrap(),
            ("", ConfigItem::ResolvHostname(false).into())
        );
    }

    #[test]
    fn test_parse_domain_set() {
        assert_eq!(
            parse_config("domain-set -name outbound -file /etc/smartdns/geoip.txt").unwrap(),
            (
                "",
                ConfigItem::DomainSetProvider(DomainSetProvider::File(DomainSetFileProvider {
                    name: "outbound".to_string(),
                    file: Path::new("/etc/smartdns/geoip.txt").to_path_buf(),
                    content_type: Default::default(),
                }))
                .into()
            )
        );

        assert_eq!(
            parse_config("domain-set -n proxy-server -f proxy-server-list.txt").unwrap(),
            (
                "",
                ConfigItem::DomainSetProvider(DomainSetProvider::File(DomainSetFileProvider {
                    name: "proxy-server".to_string(),
                    file: Path::new("proxy-server-list.txt").to_path_buf(),
                    content_type: Default::default(),
                }))
                .into()
            )
        );
    }

    #[test]
    fn test_parse_domain_rule() {
        assert_eq!(
            parse_config("domain-rules /domain-set:domain-block-list/ --address #").unwrap(),
            (
                "",
                ConfigItem::DomainRule(ConfigForDomain {
                    domain: Domain::Set("domain-block-list".to_string()),
                    config: DomainRule {
                        address: Some(AddressRuleValue::SOA),
                        ..Default::default()
                    }
                })
                .into()
            )
        );
    }

    #[test]
    fn test_parse_ip_set() {
        assert_eq!(
            parse_config("ip-set -name name -file /path/to/file.txt").unwrap(),
            (
                "",
                ConfigItem::IpSetProvider(IpSetProvider {
                    name: "name".to_string(),
                    file: Path::new("/path/to/file.txt").to_path_buf(),
                })
                .into()
            )
        );
    }

    #[test]
    fn test_parse_line() {
        assert_eq!(
            parse_line("address /example.com/1.2.3.5").unwrap().1,
            ConfigLine::Config {
                config: ConfigItem::Address(AddressRule {
                    domain: "example.com".parse().unwrap(),
                    address: "1.2.3.5".parse().unwrap()
                }),
                comment: None
            }
        );

        assert_eq!(
            parse_line("address /example.com/1.2.3.5  ").unwrap().1, // trailing spaces should be ignored
            ConfigLine::Config {
                config: ConfigItem::Address(AddressRule {
                    domain: "example.com".parse().unwrap(),
                    address: "1.2.3.5".parse().unwrap()
                }),
                comment: None
            }
        );

        assert_eq!(
            parse_line("address /example.com/1.2.3.5  # comment")
                .unwrap()
                .1, // trailing spaces should be ignored
            ConfigLine::Config {
                config: ConfigItem::Address(AddressRule {
                    domain: "example.com".parse().unwrap(),
                    address: "1.2.3.5".parse().unwrap()
                }),
                comment: Some("  # comment")
            }
        );

        assert_eq!(
            parse_line("# comment").unwrap().1,
            ConfigLine::Comment("# comment")
        );

        assert_eq!(
            parse_line("# comment  ").unwrap().1, // trailing spaces should be ignored
            ConfigLine::Comment("# comment")
        );

        assert_eq!(
            parse_line("  # comment").unwrap().1, // leading spaces should be ignored
            ConfigLine::Comment("# comment")
        );

        assert_eq!(parse_line("").unwrap().1, ConfigLine::Eof);

        assert_eq!(parse_line(" ").unwrap().1, ConfigLine::EmptyLine);
    }

    #[test]
    fn test_config_file_update() {
        let conf_in = indoc! {"
        # comments are preserved1
        address /example.com/1.2.3.4
        address /a.example.com/5.6.7.8 # comments are preserved2
        address /b.example.com/9.10.11.12 # comments are preserved3
          # comments are preserved4
        "};

        let conf_out = indoc! {"
        # comments are preserved1
        address /example.com/1.2.3.4
        address /a.example.com/#6 # comments are preserved2
        address /b.example.com/9.10.11.12 # comments are preserved3
        # comments are preserved4
        "};

        let (_, mut conf) = ConfigFile::parse(conf_in).unwrap();

        assert_eq!(conf.0.len(), 6);

        let mut rules = conf
            .0
            .iter()
            .enumerate()
            .flat_map(|(i, c)| match c {
                ConfigLine::Config {
                    config: ConfigItem::Address(rule),
                    ..
                } => Some((i, rule.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(rules.len(), 3);

        let (line, rule) = rules.get_mut(1).unwrap();
        rule.address = AddressRuleValue::SOAv6;
        if let Some(ConfigLine::Config { config, .. }) = conf.0.get_mut(*line) {
            *config = ConfigItem::Address(rule.clone());
        };

        assert_eq!(conf.to_string(), conf_out);
    }
}
