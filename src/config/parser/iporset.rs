use super::*;

impl NomParser for IpOrSet {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            map(
                preceded(tag_no_case("ip-set:"), String::parse),
                IpOrSet::Set,
            ),
            map(NomParser::parse, IpOrSet::Net),
        ))(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            IpOrSet::parse("ip-set:name"),
            Ok(("", IpOrSet::Set("name".to_string())))
        );

        assert!(IpOrSet::parse("1234").is_err());

        assert_eq!(
            IpOrSet::parse("1.2.3.4/16"),
            Ok(("", IpOrSet::Net("1.2.3.4/16".parse().unwrap())))
        );

        assert_eq!(
            IpOrSet::parse("1.2.3.4"),
            Ok(("", IpOrSet::Net("1.2.3.4/32".parse().unwrap())))
        );
    }
}
