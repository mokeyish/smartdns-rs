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
                    domain: Domain::Name("example.com".parse().unwrap()),
                    address: DomainAddress::SOA
                }
            ))
        );
    }
}
