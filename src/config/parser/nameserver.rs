use std::str::FromStr;

use crate::dns_url::{DnsUrl, DnsUrlParamExt};
use crate::log;
use crate::third_ext::FromStrOrHex;

use super::*;

impl NomParser for NameServerInfo {
    fn parse(input: &str) -> IResult<&str, Self> {
        let dns_url = |default_proto| {
            let proto = map(
                opt(alt((
                    tag_no_case("udp://"),
                    tag_no_case("tcp://"),
                    #[cfg(feature = "dns-over-tls")]
                    tag_no_case("tls://"),
                    #[cfg(feature = "dns-over-https")]
                    tag_no_case("https://"),
                    #[cfg(feature = "dns-over-quic")]
                    tag_no_case("quic://"),
                    #[cfg(feature = "dns-over-h3")]
                    tag_no_case("h3://"),
                ))),
                move |p| p.unwrap_or(default_proto),
            );

            map_res(
                pair(proto, take_till1(|c: char| c.is_whitespace())),
                |(a, b)| {
                    let url: String = [a, b].concat();
                    match DnsUrl::from_str(&url) {
                        Ok(url) => Ok(url),
                        Err(err) => {
                            let url: String = [a, "[", b, "]"].concat();
                            match DnsUrl::from_str(&url) {
                                Ok(url) => Ok(url),
                                _ => Err(err),
                            }
                        }
                    }
                },
            )
        };

        let server_url = alt((
            value(
                NameServerUrl::System,
                pair(tag_no_case("system"), not(satisfy(|c| !c.is_whitespace()))),
            ),
            dns_url("udp://").map(|url| NameServerUrl::Url(url)),
        ));

        let (input, url) = alt((
            preceded(
                tag_no_case("server-udp"),
                preceded(space1, dns_url("udp://")),
            ),
            preceded(
                tag_no_case("server-tcp"),
                preceded(space1, dns_url("tcp://")),
            ),
            #[cfg(feature = "dns-over-tls")]
            preceded(
                tag_no_case("server-tls"),
                preceded(space1, dns_url("tls://")),
            ),
            #[cfg(feature = "dns-over-https")]
            preceded(
                tag_no_case("server-https"),
                preceded(space1, dns_url("https://")),
            ),
            #[cfg(feature = "dns-over-h3")]
            preceded(tag_no_case("server-h3"), preceded(space1, dns_url("h3://"))),
            #[cfg(feature = "dns-over-quic")]
            preceded(
                tag_no_case("server-quic"),
                preceded(space1, dns_url("quic://")),
            ),
        ))
        .map(NameServerUrl::Url)
        .or(preceded(
            tag_no_case("server"),
            preceded(space1, server_url),
        ))
        .parse(input)?;

        let (input, options) = opt(preceded(space1, options::parse)).parse(input)?;

        let mut nameserver: NameServerInfo = url.into();

        if let Some(options) = options {
            for (k, v) in options {
                match (k.to_lowercase().as_str(), &mut nameserver.server) {
                    ("e" | "exclude-default-group", _) => nameserver.exclude_default_group = true,
                    ("blacklist-ip", _) => nameserver.blacklist_ip = true,
                    ("whitelist-ip", _) => nameserver.whitelist_ip = true,
                    ("check-edns", _) => nameserver.check_edns = true,
                    ("b" | "bootstrap-dns", _) => nameserver.bootstrap_dns = true,
                    ("set-mark", _) => match v {
                        Some(m) => nameserver.so_mark = u32::from_str_or_hex(m).ok(),
                        None => {
                            log::warn!("expect mark")
                        }
                    },
                    ("g" | "group", _) => match v {
                        Some(g) => nameserver.group.push(g.to_string()),
                        None => {
                            log::warn!("expect group name")
                        }
                    },
                    ("p" | "proxy", _) => {
                        nameserver.proxy = v.map(|p| p.to_string());
                    }
                    ("interface", _) => {
                        nameserver.interface = v.map(|p| p.to_string());
                    }
                    ("subnet", _) => match v {
                        Some(s) => nameserver.subnet = IpNet::parse(s).ok().map(|s| s.1),
                        None => {
                            log::warn!("expect suedns client subnetbnet")
                        }
                    },
                    ("host-name", NameServerUrl::Url(server)) => match v {
                        Some(host_name) => {
                            if host_name == "-" {
                                server.set_sni_off(true);
                            } else {
                                server.set_host(host_name);
                            }
                        }
                        None => {
                            log::warn!("expect host-name")
                        }
                    },
                    ("k" | "no-check-certificate", NameServerUrl::Url(server)) => {
                        server.set_ssl_verify(false);
                    }
                    ("tls-host-verify", NameServerUrl::Url(server)) => match v {
                        Some(tls_host_verify) => match server.host() {
                            url::Host::Ipv4(ipv4_addr) => {
                                server.set_ip(IpAddr::V4(*ipv4_addr));
                                server.set_host(tls_host_verify);
                            }
                            url::Host::Ipv6(ipv6_addr) => {
                                server.set_ip(IpAddr::V6(*ipv6_addr));
                                server.set_host(tls_host_verify);
                            }
                            url::Host::Domain(_) => {
                                log::warn!("tls-host-verify expects an ip address host");
                            }
                        },
                        None => {
                            log::warn!("expect tls-host-verify")
                        }
                    },
                    _ => {
                        log::warn!("unknown server options: {}, {:?}", k, v);
                    }
                }
            }
        }

        Ok((input, nameserver))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_server_default() -> NameServerInfo {
        DnsUrl::from_str("udp://127.0.0.1:53").unwrap().into()
    }

    #[test]
    fn test_simple() {
        assert_eq!(
            NameServerInfo::parse("server 8.8.8.8:53 -interface Net"),
            Ok((
                "",
                NameServerInfo {
                    server: NameServerUrl::Url(DnsUrl::from_str("udp://8.8.8.8:53").unwrap()),
                    interface: Some("Net".to_string()),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server 8.8.8.8"),
            Ok((
                "",
                NameServerInfo {
                    server: NameServerUrl::Url(DnsUrl::from_str("udp://8.8.8.8").unwrap()),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server system"),
            Ok((
                "",
                NameServerInfo {
                    server: NameServerUrl::System,
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server system -exclude-default-group"),
            Ok((
                "",
                NameServerInfo {
                    server: NameServerUrl::System,
                    exclude_default_group: true,
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server 8.8.8.8 -subnet 192.168.1.1"),
            Ok((
                "",
                NameServerInfo {
                    server: NameServerUrl::Url(DnsUrl::from_str("udp://8.8.8.8").unwrap()),
                    subnet: Some("192.168.1.1/32".parse().unwrap()),
                    ..name_server_default()
                }
            ))
        );

        fn proto<'a>(input: &'a str, default_proto: &'static str) -> IResult<&'a str, &'a str> {
            map(
                opt(alt((
                    tag_no_case("tcp://"),
                    tag_no_case("tls://"),
                    tag_no_case("https://"),
                    tag_no_case("quic://"),
                    tag_no_case("h3://"),
                ))),
                move |p| p.unwrap_or(default_proto),
            )
            .parse(input)
        }

        assert_eq!(
            NameServerInfo::parse("server-tls 8.8.8.8:853"),
            Ok((
                "",
                NameServerInfo {
                    server: NameServerUrl::Url(DnsUrl::from_str("tls://8.8.8.8:853").unwrap()),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server-tls 8.8.8.8:853"),
            Ok((
                "",
                NameServerInfo {
                    server: NameServerUrl::Url(DnsUrl::from_str("tls://8.8.8.8:853").unwrap()),
                    ..name_server_default()
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server-tls 2606:4700:4700::1111"),
            Ok((
                "",
                NameServerInfo {
                    name: None,
                    server: NameServerUrl::Url(
                        DnsUrl::from_str("tls://[2606:4700:4700::1111]").unwrap()
                    ),
                    ..name_server_default()
                }
            ))
        );
    }

    #[test]
    fn test_server_https() {
        assert_eq!(
            NameServerInfo::parse(
                "server-https https://223.5.5.5/dns-query -g bootstrap -exclude-default-group"
            ),
            Ok((
                "",
                NameServerInfo {
                    server: NameServerUrl::Url(
                        DnsUrl::from_str("https://223.5.5.5/dns-query").unwrap()
                    ),
                    group: vec!["bootstrap".to_string()],
                    exclude_default_group: true,
                    ..name_server_default()
                }
            ))
        );
    }

    #[test]
    fn test_server_https_1() {
        assert_eq!(
            NameServerInfo::parse(
                "server https://dns.alidns.com/dns-query -group alidns -e # -proxy proxy"
            ),
            Ok((
                " # -proxy proxy",
                NameServerInfo {
                    server: NameServerUrl::Url(
                        DnsUrl::from_str("https://dns.alidns.com/dns-query").unwrap()
                    ),
                    group: vec!["alidns".to_string()],
                    exclude_default_group: true,
                    ..name_server_default()
                }
            ))
        );
    }
}
