use super::*;
use crate::dns::Protocol;
use crate::log::warn;
use std::convert::{Into, TryInto};
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

impl NomParser for BindAddr {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        parse_bind_addr(input)
    }
}

fn parse_bind_addr(input: &str) -> IResult<&str, BindAddr> {
    let ip = alt((
        value(BindAddr::Localhost, tag_no_case("localhost")),
        map(nom_recipes::ipv4, BindAddr::V4),
        map(
            delimited(char('['), nom_recipes::ipv6, char(']')),
            BindAddr::V6,
        ),
    ));

    let any = value(BindAddr::All, char('*'));

    alt((ip, any)).parse(input)
}

impl NomParser for BindAddrConfig {
    fn parse(input: &str) -> IResult<&str, Self> {
        parse(input)
    }
}

impl NomParser for UdpBindAddrConfig {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into).parse(input)
    }
}

impl NomParser for TcpBindAddrConfig {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into).parse(input)
    }
}

impl NomParser for TlsBindAddrConfig {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into).parse(input)
    }
}

impl NomParser for QuicBindAddrConfig {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into).parse(input)
    }
}

impl NomParser for HttpsBindAddrConfig {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into).parse(input)
    }
}

impl NomParser for H3BindAddrConfig {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into).parse(input)
    }
}

/// dns server bind ip and port, default dns server port is 53, support binding multi ip and port
/// bind udp server
///   bind [IP]:[port] [-group [group]] [-no-rule-addr] [-no-rule-nameserver] [-no-rule-ipset] [-no-speed-check] [-no-cache] [-no-rule-soa] [-no-dualstack-selection]
/// bind tcp server
///   bind-tcp [IP]:[port] [-group [group]] [-no-rule-addr] [-no-rule-nameserver] [-no-rule-ipset] [-no-speed-check] [-no-cache] [-no-rule-soa] [-no-dualstack-selection]
/// option:
///   -group: set domain request to use the appropriate server group.
///   -no-rule-addr: skip address rule.
///   -no-rule-nameserver: skip nameserver rule.
///   -no-rule-ipset: skip ipset rule or nftset rule.
///   -no-speed-check: do not check speed.
///   -no-cache: skip cache.
///   -no-rule-soa: Skip address SOA(#) rules.
///   -no-dualstack-selection: Disable dualstack ip selection.
///   -force-aaaa-soa: force AAAA query return SOA.
/// example:
///  IPV4:
///    bind :53
///    bind :6053 -group office -no-speed-check
///  IPV6:
///    bind [::]:53
///    bind-tcp [::]:53
fn parse(input: &str) -> IResult<&str, BindAddrConfig> {
    let proto = alt((
        value(Protocol::Tcp, tag_no_case("bind-tcp")),
        value(Protocol::Tls, tag_no_case("bind-tls")),
        value(Protocol::Quic, tag_no_case("bind-quic")),
        value(Protocol::Https, tag_no_case("bind-https")),
        value(Protocol::H3, tag_no_case("bind-h3")),
        value(Protocol::Udp, tag_no_case("bind-udp")),
        value(Protocol::Udp, tag_no_case("bind")),
    ));

    let addr = map(opt(BindAddr::parse), |addr| {
        addr.unwrap_or(BindAddr::V4(Ipv4Addr::UNSPECIFIED))
    });

    let port = map_res(digit1, u16::from_str);

    let device = map(take_till(|c: char| c.is_whitespace()), |s: &str| {
        s.to_string()
    });

    let (input, (proto, addr, port, device)) = (
        preceded(space0, proto),
        preceded(space1, addr),
        preceded(char(':'), port),
        opt(preceded(char('@'), device)),
    )
        .parse(input)?;

    let (input, options) = opt(preceded(space1, options::parse)).parse(input)?;

    let (options, opts) = if let Some(options) = options {
        parse_server_opts(&options)
    } else {
        (Vec::with_capacity(0), Default::default())
    };

    let (options, ssl_config) =
        if !matches!(&proto, Protocol::Tcp | Protocol::Udp) && !options.is_empty() {
            parse_ssl_config(&options)
        } else {
            (Vec::with_capacity(0), Default::default())
        };

    if !options.is_empty() {
        warn!("unknown options {:?}", options);
    }

    let enabled = None;

    let listener = match proto {
        Protocol::Udp => UdpBindAddrConfig {
            addr,
            port,
            device,
            opts,
            enabled,
        }
        .into(),
        Protocol::Tcp => TcpBindAddrConfig {
            addr,
            port,
            device,
            opts,
            enabled,
        }
        .into(),
        Protocol::Tls => TlsBindAddrConfig {
            addr,
            port,
            device,
            opts,
            ssl_config,
            enabled,
        }
        .into(),
        Protocol::Https => HttpsBindAddrConfig {
            addr,
            port,
            device,
            opts,
            ssl_config,
            enabled,
        }
        .into(),
        Protocol::H3 => H3BindAddrConfig {
            addr,
            port,
            device,
            opts,
            ssl_config,
            enabled,
        }
        .into(),
        Protocol::Quic => QuicBindAddrConfig {
            addr,
            port,
            device,
            opts,
            ssl_config,
            enabled,
        }
        .into(),
        p => panic!("unexpected proto {}", p),
    };

    Ok((input, listener))
}

pub fn parse_server_opts<'b>(options: &Options<'b>) -> (Options<'b>, ServerOpts) {
    let mut opts = ServerOpts::default();

    let mut rest_options = vec![];

    for (k, v) in options {
        match k.to_lowercase().as_str() {
            "group" => opts.group = v.map(|s| s.to_string()),
            "no-rule-addr" => opts.no_rule_addr = Some(true),
            "no-rule-nameserver" => opts.no_rule_nameserver = Some(true),
            "no-rule-ipset" => opts.no_rule_ipset = Some(true),
            "no-speed-check" => opts.no_speed_check = Some(true),
            "no-cache" => opts.no_cache = Some(true),
            "no-rule-soa" => opts.no_rule_soa = Some(true),
            "no-serve-expired" => opts.no_serve_expired = Some(true),
            "no-dualstack-selection" => opts.no_dualstack_selection = Some(true),
            "force-aaaa-soa" => opts.force_aaaa_soa = Some(true),
            "force-https-soa" => opts.force_https_soa = Some(true),
            _ => rest_options.push((*k, *v)),
        }
    }
    (rest_options, opts)
}

fn parse_ssl_config<'b>(options: &Options<'b>) -> (Options<'b>, SslConfig) {
    let mut config = SslConfig::default();

    let mut rest_options = vec![];

    for (k, v) in options {
        match k.to_lowercase().as_str() {
            "server-name" => config.server_name = v.map(|s| s.to_string()),
            "ssl-certificate-key" => {
                config.certificate_key = v.map(Path::new).map(|p| p.to_path_buf())
            }
            "ssl-certificate" => config.certificate = v.map(Path::new).map(|p| p.to_path_buf()),
            _ => rest_options.push((*k, *v)),
        }
    }

    (rest_options, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bind_addr() {
        assert_eq!(parse_bind_addr("*").unwrap(), ("", BindAddr::All));

        assert_eq!(
            parse_bind_addr("0.0.0.0").unwrap(),
            ("", BindAddr::V4(Ipv4Addr::UNSPECIFIED))
        );

        assert_eq!(
            parse_bind_addr("[::]").unwrap(),
            ("", BindAddr::V6(Ipv6Addr::UNSPECIFIED))
        );
        assert_eq!(
            parse_bind_addr("localhost").unwrap(),
            ("", BindAddr::Localhost)
        );
    }

    #[test]
    fn test_parse_bind_udp() {
        assert_eq!(
            UdpBindAddrConfig::parse("bind 0.0.0.0:5353").unwrap(),
            (
                "",
                UdpBindAddrConfig {
                    addr: BindAddr::V4("0.0.0.0".parse().unwrap()),
                    port: 5353,
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            UdpBindAddrConfig::parse("bind [::1]:5353@eth0").unwrap(),
            (
                "",
                UdpBindAddrConfig {
                    addr: BindAddr::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: Default::default(),
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            UdpBindAddrConfig::parse("bind [::1]:5353@eth0 -no-cache").unwrap(),
            (
                "",
                UdpBindAddrConfig {
                    addr: BindAddr::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_cache: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            UdpBindAddrConfig::parse("bind [::1]:5353@eth0 --no-rule-addr").unwrap(),
            (
                "",
                UdpBindAddrConfig {
                    addr: BindAddr::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            UdpBindAddrConfig::parse("bind [::1]:5353@eth0 -qq --no-rule-addr -w123").unwrap(),
            (
                "",
                UdpBindAddrConfig {
                    addr: BindAddr::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            UdpBindAddrConfig::parse("bind :5353@eth0 -qq --no-rule-addr -w123").unwrap(),
            (
                "",
                UdpBindAddrConfig {
                    addr: BindAddr::V4(Ipv4Addr::UNSPECIFIED),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        );
    }

    #[test]
    fn test_parse_bind_tcp() {
        assert_eq!(
            TcpBindAddrConfig::parse("bind-tcp 0.0.0.0:5353").unwrap(),
            (
                "",
                TcpBindAddrConfig {
                    addr: BindAddr::V4("0.0.0.0".parse().unwrap()),
                    port: 5353,
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            TcpBindAddrConfig::parse("bind-tcp [::1]:5353@eth0").unwrap(),
            (
                "",
                TcpBindAddrConfig {
                    addr: BindAddr::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            TcpBindAddrConfig::parse("bind-tcp [::1]:5353@eth0 -no-cache").unwrap(),
            (
                "",
                TcpBindAddrConfig {
                    addr: BindAddr::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_cache: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            TcpBindAddrConfig::parse("bind-tcp [::1]:5353@eth0 --no-rule-addr").unwrap(),
            (
                "",
                TcpBindAddrConfig {
                    addr: BindAddr::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            TcpBindAddrConfig::parse("bind-tcp [::1]:5353@eth0 -qq --no-rule-addr -w123").unwrap(),
            (
                "",
                TcpBindAddrConfig {
                    addr: BindAddr::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            TcpBindAddrConfig::parse(
                "bind-tcp [::1]:5353@eth0 -qq --no-rule-addr -w123 -force-https-soa"
            )
            .unwrap(),
            (
                "",
                TcpBindAddrConfig {
                    addr: BindAddr::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        force_https_soa: Some(true),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        );
    }

    #[test]
    fn test_parse_bind_tls() {
        assert_eq!(
            TlsBindAddrConfig::parse("bind-tls 0.0.0.0:4453 -server-name dns.example.com -ssl-certificate /etc/nginx/dns.example.com.crt -ssl-certificate-key /etc/nginx/dns.example.com.key").unwrap(),
            (
                "", 
                TlsBindAddrConfig {
                    addr: BindAddr::V4("0.0.0.0".parse().unwrap()),
                    port: 4453,
                    ssl_config: SslConfig {
                        server_name: Some("dns.example.com".to_string()), 
                        certificate: Some(Path::new("/etc/nginx/dns.example.com.crt").to_path_buf()), 
                        certificate_key: Some(Path::new("/etc/nginx/dns.example.com.key").to_path_buf()),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
        );
    }

    #[test]
    fn test_parse_bind_h3() {
        assert_eq!(
            H3BindAddrConfig::parse("bind-h3 0.0.0.0:443").unwrap(),
            (
                "",
                H3BindAddrConfig {
                    addr: BindAddr::V4("0.0.0.0".parse().unwrap()),
                    port: 443,
                    ..Default::default()
                }
            )
        );

        assert_eq!(
            H3BindAddrConfig::parse("bind-h3 :443").unwrap(),
            (
                "",
                H3BindAddrConfig {
                    addr: BindAddr::V4(Ipv4Addr::UNSPECIFIED),
                    port: 443,
                    ..Default::default()
                }
            )
        );
    }
}
