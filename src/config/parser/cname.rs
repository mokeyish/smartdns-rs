use super::*;

impl NomParser for CName {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            value(CName::IGN, char('-')),
            map(NomParser::parse, CName::Value),
        ))(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test() {
        assert_eq!(CName::parse("-"), Ok(("", CName::IGN)));
        assert_eq!(
            CName::parse("example.com"),
            Ok(("", CName::Value("example.com".parse().unwrap())))
        );
    }
}
