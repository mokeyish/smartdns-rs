use std::net::IpAddr;

use super::*;

impl NomParser for AddressRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        map(
            pair(
                delimited(char('/'), Domain::parse, char('/')),
                NomParser::parse,
            ),
            |(domain, address)| AddressRule { domain, address },
        )
        .parse(input)
    }
}

impl NomParser for AddressRuleValue {
    fn parse(input: &str) -> IResult<&str, Self> {
        use AddressRuleValue::*;

        let soa = value(SOA, char('#'));
        let soa_v4 = value(SOAv4, tag("#4"));
        let soa_v6 = value(SOAv6, tag("#6"));
        let ign = value(IGN, tag("-"));
        let ign_v4 = value(IGNv4, tag("-4"));
        let ign_v6 = value(IGNv6, tag("-6"));

        let ip_addrs = map(
            separated_list1((space0, char(','), space0), nom_recipes::ip),
            |ip_addrs| {
                let mut v4 = vec![];
                let mut v6 = vec![];
                for ip_addr in ip_addrs {
                    match ip_addr {
                        IpAddr::V4(ip) => v4.push(ip),
                        IpAddr::V6(ip) => v6.push(ip),
                    }
                }
                let v4 = if v4.is_empty() { None } else { Some(v4.into()) };
                let v6 = if v6.is_empty() { None } else { Some(v6.into()) };
                Addr { v4, v6 }
            },
        );

        alt((soa_v4, soa_v6, soa, ign_v4, ign_v6, ign, ip_addrs)).parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            AddressRule::parse("/example.com/#"),
            Ok((
                "",
                AddressRule {
                    domain: Domain::Name(WildcardName::Default("example.com".parse().unwrap())),
                    address: AddressRuleValue::SOA
                }
            ))
        );
    }

    #[test]
    fn test_parse_root() {
        assert_eq!(
            AddressRule::parse("/./#"),
            Ok((
                "",
                AddressRule {
                    domain: Domain::Name(WildcardName::Suffix(Name::root())),
                    address: AddressRuleValue::SOA
                }
            ))
        );
    }

    #[test]
    fn test_parse_full() {
        assert_eq!(
            AddressRule::parse("/-.example.com/#"),
            Ok((
                "",
                AddressRule {
                    domain: Domain::Name(WildcardName::Full("example.com".parse().unwrap())),
                    address: AddressRuleValue::SOA
                }
            ))
        );
    }

    #[test]
    fn test_parse_rule_value() {
        use AddressRuleValue::*;
        assert_eq!(AddressRuleValue::parse("#"), Ok(("", SOA)));
        assert_eq!(AddressRuleValue::parse("#4"), Ok(("", SOAv4)));
        assert_eq!(AddressRuleValue::parse("#6"), Ok(("", SOAv6)));
        assert_eq!(AddressRuleValue::parse("-"), Ok(("", IGN)));
        assert_eq!(AddressRuleValue::parse("-4"), Ok(("", IGNv4)));
        assert_eq!(AddressRuleValue::parse("-6"), Ok(("", IGNv6)));

        assert_eq!(
            AddressRuleValue::parse("127.0.0.1"),
            Ok((
                "",
                Addr {
                    v4: Some(["127.0.0.1".parse().unwrap()].into()),
                    v6: None
                }
            ))
        );
        assert_eq!(
            AddressRuleValue::parse("::1"),
            Ok((
                "",
                Addr {
                    v4: None,
                    v6: Some(["::1".parse().unwrap()].into())
                }
            ))
        );

        assert_eq!(
            AddressRuleValue::parse("::1, 127.0.0.1"),
            Ok((
                "",
                Addr {
                    v4: Some(["127.0.0.1".parse().unwrap()].into()),
                    v6: Some(["::1".parse().unwrap()].into())
                }
            ))
        );
    }
}
