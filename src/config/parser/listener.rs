use super::*;
use crate::dns::Protocol;
use crate::log::warn;
use std::convert::{Into, TryInto};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

impl NomParser for ListenerAddress {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        parse_listen_address(input)
    }
}

fn parse_listen_address(input: &str) -> IResult<&str, ListenerAddress> {
    let ip = alt((
        value(ListenerAddress::Localhost, tag_no_case("localhost")),
        map(
            map_res(
                take_while_m_n(4 + 3, 3 * 4 + 3, |c: char| c.is_ascii_digit() || c == '.'),
                Ipv4Addr::from_str,
            ),
            ListenerAddress::V4,
        ),
        map(
            map_res(
                delimited(
                    char('['),
                    take_while_m_n(2, 4 * 8 + 7, |c: char| c.is_ascii_hexdigit() || c == ':'),
                    char(']'),
                ),
                Ipv6Addr::from_str,
            ),
            ListenerAddress::V6,
        ),
    ));

    let any = value(ListenerAddress::All, char('*'));

    alt((ip, any))(input)
}

impl NomParser for Listener {
    fn parse(input: &str) -> IResult<&str, Self> {
        parse(input)
    }
}

impl NomParser for UdpListener {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into)(input)
    }
}

impl NomParser for TcpListener {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into)(input)
    }
}

impl NomParser for TlsListener {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into)(input)
    }
}

impl NomParser for QuicListener {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into)(input)
    }
}

impl NomParser for HttpsListener {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(parse, TryInto::try_into)(input)
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
fn parse(input: &str) -> IResult<&str, Listener> {
    let proto = alt((
        value(Protocol::Tcp, tag_no_case("bind-tcp")),
        value(Protocol::Tls, tag_no_case("bind-tls")),
        value(Protocol::Quic, tag_no_case("bind-quic")),
        value(Protocol::Https, tag_no_case("bind-https")),
        value(Protocol::Udp, tag_no_case("bind")),
    ));

    let listen = map(opt(ListenerAddress::parse), |addr| {
        addr.unwrap_or(ListenerAddress::V4(Ipv4Addr::UNSPECIFIED))
    });

    let port = map_res(digit1, u16::from_str);

    let device = map(take_till(|c: char| c.is_whitespace()), |s: &str| {
        s.to_string()
    });

    let (input, (proto, listen, port, device)) = tuple((
        preceded(space0, proto),
        preceded(space1, listen),
        preceded(char(':'), port),
        opt(preceded(char('@'), device)),
    ))(input)?;

    let (input, options) = opt(preceded(space1, options::parse))(input)?;

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

    let listener = match proto {
        Protocol::Udp => UdpListener {
            listen,
            port,
            device,
            opts,
        }
        .into(),
        Protocol::Tcp => TcpListener {
            listen,
            port,
            device,
            opts,
        }
        .into(),
        Protocol::Tls => TlsListener {
            listen,
            port,
            device,
            opts,
            ssl_config,
        }
        .into(),
        Protocol::Https => HttpsListener {
            listen,
            port,
            device,
            opts,
            ssl_config,
        }
        .into(),
        Protocol::Quic => QuicListener {
            listen,
            port,
            device,
            opts,
            ssl_config,
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
    fn test_parse_listen_address() {
        assert_eq!(
            parse_listen_address("*").unwrap(),
            ("", ListenerAddress::All)
        );

        assert_eq!(
            parse_listen_address("0.0.0.0").unwrap(),
            ("", ListenerAddress::V4(Ipv4Addr::UNSPECIFIED))
        );

        assert_eq!(
            parse_listen_address("[::]").unwrap(),
            ("", ListenerAddress::V6(Ipv6Addr::UNSPECIFIED))
        );
        assert_eq!(
            parse_listen_address("localhost").unwrap(),
            ("", ListenerAddress::Localhost)
        );
    }

    #[test]
    fn test_parse_udp_listener() {
        assert_eq!(
            UdpListener::parse("bind 0.0.0.0:5353").unwrap(),
            (
                "",
                UdpListener {
                    listen: ListenerAddress::V4("0.0.0.0".parse().unwrap()),
                    port: 5353,
                    device: None,
                    opts: Default::default()
                }
            )
        );

        assert_eq!(
            UdpListener::parse("bind [::1]:5353@eth0").unwrap(),
            (
                "",
                UdpListener {
                    listen: ListenerAddress::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: Default::default()
                }
            )
        );

        assert_eq!(
            UdpListener::parse("bind [::1]:5353@eth0 -no-cache").unwrap(),
            (
                "",
                UdpListener {
                    listen: ListenerAddress::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_cache: Some(true),
                        ..Default::default()
                    }
                }
            )
        );

        assert_eq!(
            UdpListener::parse("bind [::1]:5353@eth0 --no-rule-addr").unwrap(),
            (
                "",
                UdpListener {
                    listen: ListenerAddress::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    }
                }
            )
        );

        assert_eq!(
            UdpListener::parse("bind [::1]:5353@eth0 -qq --no-rule-addr -w123").unwrap(),
            (
                "",
                UdpListener {
                    listen: ListenerAddress::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    }
                }
            )
        );

        assert_eq!(
            UdpListener::parse("bind :5353@eth0 -qq --no-rule-addr -w123").unwrap(),
            (
                "",
                UdpListener {
                    listen: ListenerAddress::V4(Ipv4Addr::UNSPECIFIED),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    }
                }
            )
        );
    }

    #[test]
    fn test_parse_tcp_listener() {
        assert_eq!(
            TcpListener::parse("bind-tcp 0.0.0.0:5353").unwrap(),
            (
                "",
                TcpListener {
                    listen: ListenerAddress::V4("0.0.0.0".parse().unwrap()),
                    port: 5353,
                    device: None,
                    opts: Default::default()
                }
            )
        );

        assert_eq!(
            TcpListener::parse("bind-tcp [::1]:5353@eth0").unwrap(),
            (
                "",
                TcpListener {
                    listen: ListenerAddress::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: Default::default()
                }
            )
        );

        assert_eq!(
            TcpListener::parse("bind-tcp [::1]:5353@eth0 -no-cache").unwrap(),
            (
                "",
                TcpListener {
                    listen: ListenerAddress::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_cache: Some(true),
                        ..Default::default()
                    }
                }
            )
        );

        assert_eq!(
            TcpListener::parse("bind-tcp [::1]:5353@eth0 --no-rule-addr").unwrap(),
            (
                "",
                TcpListener {
                    listen: ListenerAddress::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    }
                }
            )
        );

        assert_eq!(
            TcpListener::parse("bind-tcp [::1]:5353@eth0 -qq --no-rule-addr -w123").unwrap(),
            (
                "",
                TcpListener {
                    listen: ListenerAddress::V6("::1".parse().unwrap()),
                    port: 5353,
                    device: Some("eth0".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    }
                }
            )
        );
    }

    #[test]
    fn test_parse_tls_listener() {
        assert_eq!(
            TlsListener::parse("bind-tls 0.0.0.0:4453 -server-name dns.example.com -ssl-certificate /etc/nginx/dns.example.com.crt -ssl-certificate-key /etc/nginx/dns.example.com.key").unwrap(),
            (
                "", 
                TlsListener {
                    listen: ListenerAddress::V4("0.0.0.0".parse().unwrap()),
                    port: 4453,
                    device: None,
                    opts: Default::default(),
                    ssl_config: SslConfig {
                        server_name: Some("dns.example.com".to_string()), 
                        certificate: Some(Path::new("/etc/nginx/dns.example.com.crt").to_path_buf()), 
                        certificate_key: Some(Path::new("/etc/nginx/dns.example.com.key").to_path_buf()),
                        ..Default::default()
                    }
                }
            )
        );
    }
}
