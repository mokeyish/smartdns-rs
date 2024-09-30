use super::*;

impl NomParser for CNameRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            value(CNameRule::IGN, char('-')),
            map(NomParser::parse, CNameRule::Value),
        ))(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test() {
        assert_eq!(CNameRule::parse("-"), Ok(("", CNameRule::IGN)));
        assert_eq!(
            CNameRule::parse("example.com"),
            Ok(("", CNameRule::Value("example.com".parse().unwrap())))
        );
    }
}
