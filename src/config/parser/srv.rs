use super::*;

impl NomParser for SRV {
    fn parse(input: &str) -> IResult<&str, Self> {
        map(
            (
                NomParser::parse,
                preceded(delimited(space0, char(','), space0), u16),
                preceded(delimited(space0, char(','), space0), u16),
                preceded(delimited(space0, char(','), space0), u16),
            ),
            |(target, port, priority, weight)| SRV::new(priority, weight, port, target),
        )
        .parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            SRV::parse("example.com,1688,1,2"),
            Ok(("", SRV::new(1, 2, 1688, "example.com".parse().unwrap())))
        );
        assert_eq!(
            SRV::parse("example.com,1688, 1 ,2"),
            Ok(("", SRV::new(1, 2, 1688, "example.com".parse().unwrap())))
        );
    }
}
