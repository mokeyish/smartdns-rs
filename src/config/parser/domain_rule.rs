use super::*;
use crate::log;

impl NomParser for DomainRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut rule = DomainRule::default();

        let one = alt((
            map(
                options::parse_value(
                    alt((tag("speed-check-mode"), tag("c"))),
                    SpeedCheckModeList::parse,
                ),
                |v| {
                    rule.speed_check_mode.extend(v.0);
                },
            ),
            map(
                options::parse_value(alt((tag("address"), tag("a"))), NomParser::parse),
                |v| {
                    rule.address = Some(v);
                },
            ),
            map(
                options::parse_value(alt((tag("nameserver"), tag("n"))), alphanumeric1),
                |v| {
                    rule.nameserver = Some(v.to_string());
                },
            ),
            map(
                options::parse_no_value(alt((tag("dualstack-ip-selection"), tag("d")))),
                |v| {
                    rule.dualstack_ip_selection = Some(v);
                },
            ),
            map(options::parse_value(tag("cname"), NomParser::parse), |v| {
                rule.cname = Some(v);
            }),
            map(options::parse_no_value(tag("no-cache")), |v| {
                rule.no_cache = Some(v);
            }),
            map(options::unknown_options, |(n, v)| {
                log::warn!("domain rule: unknown options {}={:?}", n, v)
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
            DomainRule::parse("--speed-check-mode=ping"),
            Ok((
                "",
                DomainRule {
                    speed_check_mode: vec![SpeedCheckMode::Ping].into(),
                    ..Default::default()
                }
            ))
        );
        assert_eq!(
            DomainRule::parse("-c Ping,tcp:53"),
            Ok((
                "",
                DomainRule {
                    speed_check_mode: vec![SpeedCheckMode::Ping, SpeedCheckMode::Tcp(53)].into(),
                    ..Default::default()
                }
            ))
        );

        assert_eq!(
            DomainRule::parse("-a -"),
            Ok((
                "",
                DomainRule {
                    address: Some(DomainAddress::IGN),
                    ..Default::default()
                }
            ))
        );

        assert_eq!(
            DomainRule::parse("-a=#6"),
            Ok((
                "",
                DomainRule {
                    address: Some(DomainAddress::SOAv6),
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
    }
}
