use super::*;

impl NomParser for Level {
    fn parse(input: &str) -> IResult<&str, Self> {
        let trace = value(Level::TRACE, tag_no_case("trace"));
        let debug = value(Level::DEBUG, tag_no_case("debug"));
        let info = value(
            Level::INFO,
            alt((tag_no_case("info"), tag_no_case("notice"))),
        );
        let warn = value(Level::WARN, tag_no_case("warn"));
        let error = value(
            Level::ERROR,
            alt((tag_no_case("error"), tag_no_case("fatal"))),
        );
        alt((trace, debug, info, warn, error))(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(Level::parse("trace"), Ok(("", Level::TRACE)));
        assert_eq!(Level::parse("Debug"), Ok(("", Level::DEBUG)));
        assert_eq!(Level::parse("info"), Ok(("", Level::INFO)));
        assert_eq!(Level::parse("notice"), Ok(("", Level::INFO)));
        assert_eq!(Level::parse("warn"), Ok(("", Level::WARN)));
        assert_eq!(Level::parse("error"), Ok(("", Level::ERROR)));
        assert_eq!(Level::parse("Fatal"), Ok(("", Level::ERROR)));
    }
}
