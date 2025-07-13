use super::*;

impl NomParser for CNameRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            value(CNameRule::Ignore, char('-')),
            map(NomParser::parse, CNameRule::Value),
        ))
        .parse(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test() {
        assert_eq!(CNameRule::parse("-"), Ok(("", CNameRule::Ignore)));
        assert_eq!(
            CNameRule::parse("example.com"),
            Ok(("", CNameRule::Value("example.com".parse().unwrap())))
        );
    }
}
