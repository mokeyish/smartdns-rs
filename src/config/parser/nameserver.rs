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
                    tag_no_case("tls://"),
                    tag_no_case("https://"),
                    tag_no_case("quic://"),
                ))),
                move |p| p.unwrap_or(default_proto),
            );

            map_res(
                pair(proto, take_till1(|c: char| c.is_whitespace())),
                |(a, b)| {
                    let url: String = [a, b].concat();
                    DnsUrl::from_str(&url)
                },
            )
        };

        let (input, url) = alt((
            preceded(
                tag_no_case("server-udp"),
                preceded(space1, dns_url("udp://")),
            ),
            preceded(
                tag_no_case("server-tcp"),
                preceded(space1, dns_url("tcp://")),
            ),
            preceded(
                tag_no_case("server-tls"),
                preceded(space1, dns_url("tls://")),
            ),
            preceded(
                tag_no_case("server-https"),
                preceded(space1, dns_url("https://")),
            ),
            preceded(
                tag_no_case("server-quic"),
                preceded(space1, dns_url("quic://")),
            ),
            preceded(tag_no_case("server"), preceded(space1, dns_url("udp://"))),
        ))(input)?;

        let (input, options) = opt(preceded(space1, options::parse))(input)?;

        let mut nameserver = Self {
            url,
            group: Default::default(),
            blacklist_ip: Default::default(),
            whitelist_ip: Default::default(),
            check_edns: Default::default(),
            exclude_default_group: Default::default(),
            proxy: None,
            bootstrap_dns: Default::default(),
            resolve_group: None,
            edns_client_subnet: None,
            so_mark: None,
        };

        if let Some(options) = options {
            for (k, v) in options {
                match k.to_lowercase().as_str() {
                    "exclude-default-group" => nameserver.exclude_default_group = true,
                    "blacklist-ip" => nameserver.blacklist_ip = true,
                    "whitelist-ip" => nameserver.whitelist_ip = true,
                    "check-edns" => nameserver.check_edns = true,
                    "bootstrap-dns" => nameserver.bootstrap_dns = true,
                    "set-mark" => match v {
                        Some(m) => nameserver.so_mark = u32::from_str_or_hex(m).ok(),
                        None => {
                            log::warn!("expect mark")
                        }
                    },
                    "group" => match v {
                        Some(g) => nameserver.group.push(g.to_string()),
                        None => {
                            log::warn!("expect group name")
                        }
                    },
                    "proxy" => {
                        nameserver.proxy = v.map(|p| p.to_string());
                    }
                    "subnet" => match v {
                        Some(s) => nameserver.edns_client_subnet = s.parse().ok(),
                        None => {
                            log::warn!("expect suedns client subnetbnet")
                        }
                    },
                    "host-name" => match v {
                        Some(host_name) => {
                            if host_name == "-" {
                                nameserver.url.set_sni_off(true);
                            } else {
                                nameserver.url.set_host(host_name);
                            }
                        }
                        None => {
                            log::warn!("expect host-name")
                        }
                    },
                    "no-check-certificate" => {
                        nameserver.url.set_ssl_verify(false);
                    }
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

    #[test]
    fn test_simple() {
        assert_eq!(
            NameServerInfo::parse("server 8.8.8.8:53"),
            Ok((
                "",
                NameServerInfo {
                    url: DnsUrl::from_str("udp://8.8.8.8:53").unwrap(),
                    group: Default::default(),
                    blacklist_ip: Default::default(),
                    whitelist_ip: Default::default(),
                    check_edns: Default::default(),
                    exclude_default_group: Default::default(),
                    proxy: None,
                    bootstrap_dns: Default::default(),
                    resolve_group: None,
                    edns_client_subnet: None,
                    so_mark: None,
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server 8.8.8.8"),
            Ok((
                "",
                NameServerInfo {
                    url: DnsUrl::from_str("udp://8.8.8.8").unwrap(),
                    group: Default::default(),
                    blacklist_ip: Default::default(),
                    whitelist_ip: Default::default(),
                    check_edns: Default::default(),
                    exclude_default_group: Default::default(),
                    proxy: None,
                    bootstrap_dns: Default::default(),
                    resolve_group: None,
                    edns_client_subnet: None,
                    so_mark: None,
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
                ))),
                move |p| p.unwrap_or(default_proto),
            )(input)
        }

        assert_eq!(
            NameServerInfo::parse("server-tls 8.8.8.8:853"),
            Ok((
                "",
                NameServerInfo {
                    url: DnsUrl::from_str("tls://8.8.8.8:853").unwrap(),
                    group: Default::default(),
                    blacklist_ip: Default::default(),
                    whitelist_ip: Default::default(),
                    check_edns: Default::default(),
                    exclude_default_group: Default::default(),
                    proxy: None,
                    bootstrap_dns: Default::default(),
                    resolve_group: None,
                    edns_client_subnet: None,
                    so_mark: None,
                }
            ))
        );

        assert_eq!(
            NameServerInfo::parse("server-tls 8.8.8.8:853"),
            Ok((
                "",
                NameServerInfo {
                    url: DnsUrl::from_str("tls://8.8.8.8:853").unwrap(),
                    group: Default::default(),
                    blacklist_ip: Default::default(),
                    whitelist_ip: Default::default(),
                    check_edns: Default::default(),
                    exclude_default_group: Default::default(),
                    proxy: None,
                    bootstrap_dns: Default::default(),
                    resolve_group: None,
                    edns_client_subnet: None,
                    so_mark: None,
                }
            ))
        );
    }

    #[test]
    fn test_server_https() {
        assert_eq!(
            NameServerInfo::parse(
                "server-https https://223.5.5.5/dns-query -group bootstrap -exclude-default-group"
            ),
            Ok((
                "",
                NameServerInfo {
                    url: DnsUrl::from_str("https://223.5.5.5/dns-query").unwrap(),
                    group: vec!["bootstrap".to_string()],
                    blacklist_ip: Default::default(),
                    whitelist_ip: Default::default(),
                    check_edns: Default::default(),
                    exclude_default_group: true,
                    proxy: None,
                    bootstrap_dns: Default::default(),
                    resolve_group: None,
                    edns_client_subnet: None,
                    so_mark: None,
                }
            ))
        );
    }
}
