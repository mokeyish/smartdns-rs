use nom::{
    branch::*, bytes::complete::*, character::complete::*, combinator::*, multi::*, sequence::*,
    IResult,
};

mod bool;
mod bytes;
mod cname;
mod config_for_domain;
mod domain;
mod domain_policy;
mod domain_rule;
mod file_mode;
mod forward_rule;
mod ipnet;
mod listener;
mod log_level;
mod nameserver;
mod nftset;
mod options;
mod path;
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
        map(is_a(" \r\r\n"), Into::into)(input)
    }
}

impl NomParser for OneLineConfig {
    fn parse(input: &str) -> IResult<&str, Self> {
        let comment = opt(preceded(space1, preceded(char('#'), not_line_ending)));

        fn parse_item<'a, T: NomParser>(
            keyword: &'static str,
        ) -> impl FnMut(&'a str) -> IResult<&str, T> {
            preceded(tuple((space0, tag_no_case(keyword), space1)), T::parse)
        }

        let group1 = alt((
            map(parse_item("address"), OneLineConfig::Address),
            map(parse_item("audit-enable"), OneLineConfig::AuditEnable),
            map(parse_item("audit-file-mode"), OneLineConfig::AuditFileMode),
            map(parse_item("audit-file"), OneLineConfig::AuditFile),
            map(parse_item("audit-num"), OneLineConfig::AuditNum),
            map(parse_item("audit-size"), OneLineConfig::AuditSize),
            map(parse_item("bind-cert-file"), OneLineConfig::BindCertFile),
            map(
                parse_item("bind-cert-key-file"),
                OneLineConfig::BindCertKeyFile,
            ),
            map(
                parse_item("bind-cert-key-pass"),
                OneLineConfig::BindCertKeyPass,
            ),
            map(parse_item("cache-file"), OneLineConfig::CacheFile),
            map(parse_item("cache-persist"), OneLineConfig::CachePersist),
            map(parse_item("ca-file"), OneLineConfig::CaFile),
            map(parse_item("ca-path"), OneLineConfig::CaPath),
            map(parse_item("conf-file"), OneLineConfig::ConfFile),
            map(parse_item("cache-size"), OneLineConfig::CacheSize),
            map(parse_item("domain-rules"), OneLineConfig::DomainRule),
            map(parse_item("domain-rule"), OneLineConfig::DomainRule),
            map(
                parse_item("dnsmasq-lease-file"),
                OneLineConfig::DnsmasqLeaseFile,
            ),
            map(
                parse_item("dualstack-ip-allow-force-AAAA"),
                OneLineConfig::DualstackIpAllowForceAAAA,
            ),
            map(
                parse_item("dualstack-ip-selection"),
                OneLineConfig::DualstackIpSelection,
            ),
            map(
                parse_item("edns-client-subnet"),
                OneLineConfig::EdnsClientSubnet,
            ),
        ));

        let group2 = alt((
            map(parse_item("force-AAAA-SOA"), OneLineConfig::ForceAAAASOA),
            map(parse_item("force-qtype-soa"), OneLineConfig::ForceQtypeSoa),
            map(parse_item("response"), OneLineConfig::ResponseMode),
            map(parse_item("prefetch-domain"), OneLineConfig::PrefetchDomain),
            map(parse_item("cname"), OneLineConfig::CName),
            map(parse_item("num-workers"), OneLineConfig::NumWorkers),
            map(parse_item("domain"), OneLineConfig::Domain),
            map(parse_item("local-ttl"), OneLineConfig::LocalTtl),
            map(parse_item("log-file-mode"), OneLineConfig::LogFileMode),
            map(parse_item("log-file"), OneLineConfig::LogFile),
            map(parse_item("log-filter"), OneLineConfig::LogFilter),
            map(parse_item("log-level"), OneLineConfig::LogLevel),
            map(parse_item("log-num"), OneLineConfig::LogNum),
            map(parse_item("max-reply-ip-num"), OneLineConfig::MaxReplyIpNum),
        ));

        let group3 = alt((
            map(parse_item("rr-ttl-reply-max"), OneLineConfig::RrTtlReplyMax),
            map(parse_item("rr-ttl-min"), OneLineConfig::RrTtlMin),
            map(parse_item("rr-ttl-max"), OneLineConfig::RrTtlMax),
            map(parse_item("rr-ttl"), OneLineConfig::RrTtl),
            map(parse_item("resolv-file"), OneLineConfig::ResolvFile),
            map(parse_item("server-name"), OneLineConfig::ServerName),
            map(parse_item("speed-check-mode"), OneLineConfig::SpeedMode),
            map(
                parse_item("serve-expired-reply-ttl"),
                OneLineConfig::ServeExpiredReplyTtl,
            ),
            map(
                parse_item("serve-expired-ttl"),
                OneLineConfig::ServeExpiredTtl,
            ),
            map(parse_item("serve-expired"), OneLineConfig::ServeExpired),
            map(parse_item("tcp-idle-time"), OneLineConfig::TcpIdleTime),
            map(parse_item("nftset"), OneLineConfig::NftSet),
            map(parse_item("user"), OneLineConfig::User),
            map(NomParser::parse, OneLineConfig::Listener),
            map(NomParser::parse, OneLineConfig::Server),
        ));
        terminated(alt((group1, group2, group3)), comment)(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nftset() {
        assert_eq!(
            OneLineConfig::parse("nftset /www.example.com/#4:inet#tab#dns4").unwrap(),
            (
                "",
                OneLineConfig::NftSet(ConfigForDomain {
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
            OneLineConfig::parse("nftset /www.example.com/#4:inet#tab#dns4 # comment 123").unwrap(),
            (
                "",
                OneLineConfig::NftSet(ConfigForDomain {
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
}
