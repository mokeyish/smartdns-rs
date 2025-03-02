use super::*;
use crate::libdns::proto::rr::rdata::svcb::{
    Alpn, EchConfigList, IpHint, SVCB, SvcParamKey, SvcParamValue,
};
use crate::libdns::proto::rr::rdata::{A, AAAA};

impl NomParser for SVCB {
    fn parse(input: &str) -> IResult<&str, Self> {
        let param_key = |name: &'static str| {
            terminated(tag_no_case(name), delimited(space0, char('='), space0))
        };

        let mut target_name = Name::root();
        let mut svc_priority = 0;

        let alpn = map(
            preceded(
                param_key("alpn"),
                delimited(
                    char('"'),
                    separated_list1(
                        char(','),
                        delimited(
                            space0,
                            take_while1(|c: char| c != ',' && c != '"' && !c.is_whitespace()),
                            space0,
                        ),
                    ),
                    char('"'),
                ),
            ),
            |alpn| {
                (
                    SvcParamKey::Alpn,
                    SvcParamValue::Alpn(Alpn(
                        alpn.into_iter().map(|s: &str| s.to_string()).collect(),
                    )),
                )
            },
        );

        let port = map(preceded(param_key("port"), u16), |port| {
            (SvcParamKey::Port, SvcParamValue::Port(port))
        });

        let ipv4hint = map(
            preceded(
                param_key("ipv4hint"),
                alt((
                    delimited(
                        char('"'),
                        separated_list1(
                            char(','),
                            delimited(space0, map(nom_recipes::ipv4, A::from), space0),
                        ),
                        char('"'),
                    ),
                    separated_list1(
                        char(','),
                        delimited(space0, map(nom_recipes::ipv4, A::from), space0),
                    ),
                )),
            ),
            |ip_addrs| {
                (
                    SvcParamKey::Ipv4Hint,
                    SvcParamValue::Ipv4Hint(IpHint(ip_addrs)),
                )
            },
        );
        let ipv6hint = map(
            preceded(
                param_key("ipv6hint"),
                alt((
                    delimited(
                        char('"'),
                        separated_list1(
                            char(','),
                            delimited(space0, map(nom_recipes::ipv6, AAAA::from), space0),
                        ),
                        char('"'),
                    ),
                    separated_list1(
                        char(','),
                        delimited(space0, map(nom_recipes::ipv6, AAAA::from), space0),
                    ),
                )),
            ),
            |ip_addrs| {
                (
                    SvcParamKey::Ipv6Hint,
                    SvcParamValue::Ipv6Hint(IpHint(ip_addrs)),
                )
            },
        );
        let ech = map(
            preceded(
                param_key("ech"),
                delimited(char('"'), is_not("\""), char('"')),
            ),
            |ech| {
                (
                    SvcParamKey::EchConfigList,
                    SvcParamValue::EchConfigList(EchConfigList(ech.as_bytes().to_vec())),
                )
            },
        );

        let mut svc_params = vec![];

        let (input, _) = separated_list0(
            char(','),
            delimited(
                space0,
                alt((
                    map(alt((alpn, port, ipv4hint, ipv6hint, ech)), |v| {
                        svc_params.push(v);
                    }),
                    map(preceded(param_key("target"), NomParser::parse), |v| {
                        target_name = v;
                    }),
                    map(preceded(param_key("priority"), u16), |v| {
                        svc_priority = v;
                    }),
                    map(space0, |_| {}),
                )),
                space0,
            ),
        )(input)?;

        Ok((input, SVCB::new(svc_priority, target_name, svc_params)))
    }
}

impl NomParser for HTTPS {
    fn parse(input: &str) -> IResult<&str, Self> {
        map(SVCB::parse, HTTPS)(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_svcb() {
        assert_eq!(
            SVCB::parse(r#"ech="aaa""#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![(
                        SvcParamKey::EchConfigList,
                        SvcParamValue::EchConfigList(EchConfigList(b"aaa".to_vec()))
                    ),]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"ipv4hint=127.0.0.1"#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![(
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec!["127.0.0.1".parse().unwrap()]))
                    ),]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"ipv4hint=127.0.0.1,192.168.1.1"#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![(
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![
                            "127.0.0.1".parse().unwrap(),
                            "192.168.1.1".parse().unwrap()
                        ]))
                    ),]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"ipv4hint=127.0.0.1, 192.168.1.1"#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![(
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![
                            "127.0.0.1".parse().unwrap(),
                            "192.168.1.1".parse().unwrap()
                        ]))
                    ),]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"ipv4hint=" 127.0.0.1, 192.168.1.1""#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![(
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![
                            "127.0.0.1".parse().unwrap(),
                            "192.168.1.1".parse().unwrap()
                        ]))
                    ),]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"ipv4hint=127.0.0.1,,ipv6hint=::1"#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![
                        (
                            SvcParamKey::Ipv4Hint,
                            SvcParamValue::Ipv4Hint(IpHint(vec!["127.0.0.1".parse().unwrap()]))
                        ),
                        (
                            SvcParamKey::Ipv6Hint,
                            SvcParamValue::Ipv6Hint(IpHint(vec!["::1".parse().unwrap()]))
                        )
                    ]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"ipv4hint=127.0.0.1, ,ipv6hint=::1"#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![
                        (
                            SvcParamKey::Ipv4Hint,
                            SvcParamValue::Ipv4Hint(IpHint(vec!["127.0.0.1".parse().unwrap()]))
                        ),
                        (
                            SvcParamKey::Ipv6Hint,
                            SvcParamValue::Ipv6Hint(IpHint(vec!["::1".parse().unwrap()]))
                        )
                    ]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"ipv4hint=127.0.0.1,ipv6hint="::1""#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![
                        (
                            SvcParamKey::Ipv4Hint,
                            SvcParamValue::Ipv4Hint(IpHint(vec!["127.0.0.1".parse().unwrap()]))
                        ),
                        (
                            SvcParamKey::Ipv6Hint,
                            SvcParamValue::Ipv6Hint(IpHint(vec!["::1".parse().unwrap()]))
                        )
                    ]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"ipv4hint=127.0.0.1,ipv6hint="::1, 2001:db8::1""#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![
                        (
                            SvcParamKey::Ipv4Hint,
                            SvcParamValue::Ipv4Hint(IpHint(vec!["127.0.0.1".parse().unwrap()]))
                        ),
                        (
                            SvcParamKey::Ipv6Hint,
                            SvcParamValue::Ipv6Hint(IpHint(vec![
                                "::1".parse().unwrap(),
                                "2001:db8::1".parse().unwrap()
                            ]))
                        )
                    ]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"alpn="h2,http/1.1""#),
            Ok((
                "",
                SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![(
                        SvcParamKey::Alpn,
                        SvcParamValue::Alpn(Alpn(vec!["h2".to_string(), "http/1.1".to_string()]))
                    ),]
                )
            ))
        );

        assert_eq!(
            SVCB::parse(r#"alpn="h2,http/1.1"  , priority=3"#),
            Ok((
                "",
                SVCB::new(
                    3,
                    ".".parse().unwrap(),
                    vec![(
                        SvcParamKey::Alpn,
                        SvcParamValue::Alpn(Alpn(vec!["h2".to_string(), "http/1.1".to_string()]))
                    ),]
                )
            ))
        );
    }
}
