use super::*;
use crate::log;
use options::{self, parse_flag, parse_value, unkown_options};

impl NomParser for DomainRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut rule = DomainRule::default();

        let one = alt((
            map(
                parse_value(
                    alt((tag("speed-check-mode"), tag("c"))),
                    SpeedCheckModeList::parse,
                ),
                |v| {
                    rule.speed_check_mode
                        .get_or_insert_with(|| SpeedCheckModeList(vec![]))
                        .extend(v.0);
                },
            ),
            map(
                parse_value(alt((tag_no_case("address"), tag("a"))), NomParser::parse),
                |v| {
                    rule.address = Some(v);
                },
            ),
            map(
                parse_value(alt((tag_no_case("nameserver"), tag("n"))), alphanumeric1),
                |v| {
                    rule.nameserver = Some(v.to_string());
                },
            ),
            map(
                parse_flag(alt((tag_no_case("dualstack-ip-selection"), tag("d")))),
                |v| {
                    rule.dualstack_ip_selection = Some(v);
                },
            ),
            map(parse_value(tag_no_case("cname"), NomParser::parse), |v| {
                rule.cname = Some(v);
            }),
            map(parse_value(tag_no_case("subnet"), NomParser::parse), |v| {
                rule.subnet = Some(From::<IpNet>::from(v));
            }),
            map(parse_flag(tag_no_case("no-cache")), |v| {
                rule.no_cache = Some(v);
            }),
            map(parse_flag(tag_no_case("no-serve-expired")), |v| {
                rule.no_serve_expired = Some(v);
            }),
            map(
                parse_value(
                    alt((tag_no_case("response-mode"), tag("r"))),
                    NomParser::parse,
                ),
                |v| {
                    rule.response_mode = Some(v);
                },
            ),
            map(
                parse_value(tag_no_case("rr-ttl-min"), NomParser::parse),
                |v| {
                    rule.rr_ttl_min = Some(v);
                },
            ),
            map(
                parse_value(tag_no_case("rr-ttl-max"), NomParser::parse),
                |v| {
                    rule.rr_ttl_max = Some(v);
                },
            ),
            map(parse_value(tag_no_case("rr-ttl"), NomParser::parse), |v| {
                rule.rr_ttl = Some(v);
            }),
            map(unkown_options, |(n, v)| {
                log::warn!("domain rule: unkown options {}={:?}", n, v);
            }),
        ));

        let (input, _) = separated_list1(space1, one)(input)?;

        Ok((input, rule))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            DomainRule::parse("--speed-check-mode=ping -subnet 192.168.0.0/16"),
            Ok((
                "",
                DomainRule {
                    speed_check_mode: Some(vec![SpeedCheckMode::Ping].into()),
                    subnet: Some("192.168.0.0/16".parse().unwrap()),
                    ..Default::default()
                }
            ))
        );
        assert_eq!(
            DomainRule::parse("-c Ping,tcp:53"),
            Ok((
                "",
                DomainRule {
                    speed_check_mode: Some(
                        vec![SpeedCheckMode::Ping, SpeedCheckMode::Tcp(53)].into()
                    ),
                    ..Default::default()
                }
            ))
        );

        assert_eq!(
            DomainRule::parse("-c none"),
            Ok((
                "",
                DomainRule {
                    speed_check_mode: Some(vec![SpeedCheckMode::None].into()),
                    ..Default::default()
                }
            ))
        );

        assert_eq!(
            DomainRule::parse("-a -"),
            Ok((
                "",
                DomainRule {
                    address: Some(AddressRuleValue::IGN),
                    ..Default::default()
                }
            ))
        );

        assert_eq!(
            DomainRule::parse("-a=#6"),
            Ok((
                "",
                DomainRule {
                    address: Some(AddressRuleValue::SOAv6),
                    ..Default::default()
                }
            ))
        );

        assert_eq!(
            DomainRule::parse("--no-cache"),
            Ok((
                "",
                DomainRule {
                    no_cache: Some(true),
                    ..Default::default()
                }
            ))
        );
        assert_eq!(
            DomainRule::parse("--no-cache  -d"),
            Ok((
                "",
                DomainRule {
                    no_cache: Some(true),
                    dualstack_ip_selection: Some(true),
                    ..Default::default()
                }
            ))
        );
        assert_eq!(
            DomainRule::parse("-rr-ttl-min 60"),
            Ok((
                "",
                DomainRule {
                    rr_ttl_min: Some(60),
                    ..Default::default()
                }
            ))
        );

        assert_eq!(
            DomainRule::parse("-a 127.0.0.1"),
            Ok((
                "",
                DomainRule {
                    address: Some(AddressRuleValue::Addr {
                        v4: Some(["127.0.0.1".parse().unwrap()].into()),
                        v6: None
                    }),
                    ..Default::default()
                }
            ))
        );

        assert_eq!(
            DomainRule::parse("-a 127.0.0.1,::1"),
            Ok((
                "",
                DomainRule {
                    address: Some(AddressRuleValue::Addr {
                        v4: Some(["127.0.0.1".parse().unwrap()].into()),
                        v6: Some(["::1".parse().unwrap()].into())
                    }),
                    ..Default::default()
                }
            ))
        );
    }
}
