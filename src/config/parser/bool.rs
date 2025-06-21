use super::*;

impl NomParser for bool {
    fn parse(input: &str) -> IResult<&str, Self> {
        let t = value(
            true,
            alt((
                tag_no_case("True"),
                tag_no_case("T"),
                tag_no_case("Yes"),
                tag_no_case("Y"),
                tag("1"),
            )),
        );

        let f = value(
            false,
            alt((
                tag_no_case("False"),
                tag_no_case("F"),
                tag_no_case("No"),
                tag_no_case("N"),
                tag("0"),
            )),
        );
        alt((t, f)).parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(bool::parse("true"), Ok(("", true)));
        assert_eq!(bool::parse("0"), Ok(("", false)));
        assert_eq!(bool::parse("n"), Ok(("", false)));
    }
}
