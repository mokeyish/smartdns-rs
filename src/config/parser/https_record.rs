use super::*;

impl NomParser for HttpsRecordRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            map(char('#'), |_| Self::SOA),
            map(char('-'), |_| Self::Ignore),
            map(
                separated_list1(
                    char(','),
                    delimited(
                        space0,
                        alt((
                            value(4u8, tag_no_case("noipv4hint")),
                            value(6u8, tag_no_case("noipv6hint")),
                        )),
                        space0,
                    ),
                ),
                |no_hints| Self::Filter {
                    no_ipv4_hint: no_hints.contains(&4),
                    no_ipv6_hint: no_hints.contains(&6),
                },
            ),
            map(NomParser::parse, Self::RecordData),
        ))(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libdns::proto::rr::rdata::svcb::{Alpn, IpHint, SVCB, SvcParamKey, SvcParamValue};

    #[test]
    fn test_parse() {
        assert_eq!(HttpsRecordRule::parse("#"), Ok(("", HttpsRecordRule::SOA)));
        assert_eq!(
            HttpsRecordRule::parse("-"),
            Ok(("", HttpsRecordRule::Ignore))
        );
        assert_eq!(
            HttpsRecordRule::parse("noipv4hint"),
            Ok((
                "",
                HttpsRecordRule::Filter {
                    no_ipv4_hint: true,
                    no_ipv6_hint: false
                }
            ))
        );
        assert_eq!(
            HttpsRecordRule::parse("noipv6hint, noipv4hint"),
            Ok((
                "",
                HttpsRecordRule::Filter {
                    no_ipv4_hint: true,
                    no_ipv6_hint: true
                }
            ))
        );
        assert_eq!(
            HttpsRecordRule::parse(r#"alpn="h2,http/1.1""#),
            Ok((
                "",
                HttpsRecordRule::RecordData(HTTPS(SVCB::new(
                    0,
                    ".".parse().unwrap(),
                    vec![(
                        SvcParamKey::Alpn,
                        SvcParamValue::Alpn(Alpn(vec!["h2".to_string(), "http/1.1".to_string()]))
                    ),]
                )))
            ))
        );

        assert_eq!(
            HttpsRecordRule::parse(r#"ipv4hint=127.0.0.1,ipv6hint="::1, 2001:db8::1""#),
            Ok((
                "",
                HttpsRecordRule::RecordData(HTTPS(SVCB::new(
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
                )))
            ))
        );
    }
}
