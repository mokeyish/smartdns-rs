use super::*;

impl NomParser for ResponseMode {
    fn parse(input: &str) -> IResult<&str, Self> {
        use ResponseMode::*;

        let first_ping = value(FirstPing, tag_no_case("first-ping"));
        let fatest_ip = value(FastestIp, tag_no_case("fastest-ip"));
        let fatest_response = value(FastestResponse, tag_no_case("fastest-response"));

        alt((first_ping, fatest_ip, fatest_response)).parse(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test() {
        use ResponseMode::*;
        assert_eq!(ResponseMode::parse("fiRst-ping"), Ok(("", FirstPing)));
        assert_eq!(ResponseMode::parse("fastest-ip"), Ok(("", FastestIp)));
        assert_eq!(
            ResponseMode::parse("fastest-response"),
            Ok(("", FastestResponse))
        );
    }
}
