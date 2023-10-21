use super::*;

impl NomParser for bool {
    fn parse(input: &str) -> IResult<&str, Self> {
        parse(input)
    }
}

fn parse(input: &str) -> IResult<&str, bool> {
    alt((
        value(
            true,
            alt((
                tag_no_case("True"),
                tag_no_case("T"),
                tag_no_case("Yes"),
                tag_no_case("Y"),
                tag("1"),
            )),
        ),
        value(
            false,
            alt((
                tag_no_case("False"),
                tag_no_case("F"),
                tag_no_case("No"),
                tag_no_case("N"),
                tag("0"),
            )),
        ),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(parse("true"), Ok(("", true)));
        assert_eq!(parse("0"), Ok(("", false)));
        assert_eq!(parse("n"), Ok(("", false)));
    }
}
