use super::*;

impl NomParser for AddressRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        map(
            pair(
                delimited(char('/'), Domain::parse, char('/')),
                NomParser::parse,
            ),
            |(domain, address)| AddressRule { domain, address },
        )(input)
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
                    address: DomainAddress::SOA
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
                    address: DomainAddress::SOA
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
                    address: DomainAddress::SOA
                }
            ))
        );
    }
}
