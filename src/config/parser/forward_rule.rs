use super::*;

impl NomParser for ForwardRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        map(
            pair(
                delimited(char('/'), Domain::parse, char('/')),
                map(is_not(" \t\r\n"), |s: &str| s.to_string()),
            ),
            |(domain, server)| ForwardRule {
                domain,
                nameserver: server,
            },
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
            ForwardRule::parse("/example.com/example-group"),
            Ok((
                "",
                ForwardRule {
                    domain: Domain::Name("example.com".parse().unwrap()),
                    nameserver: "example-group".to_string()
                }
            ))
        );
    }
}
