use super::*;

impl NomParser for SpeedCheckModeList {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            value(Default::default(), tag_no_case("none")),
            map(
                separated_list1(delimited(space0, char(','), space0), NomParser::parse),
                SpeedCheckModeList,
            ),
        ))(input)
    }
}

impl NomParser for SpeedCheckMode {
    fn parse(input: &str) -> IResult<&str, Self> {
        use SpeedCheckMode::*;

        let ping = value(Ping, tag_no_case("ping"));
        let tcp = map(preceded(tag_no_case("tcp"), preceded(char(':'), u16)), Tcp);
        let http = map(
            preceded(
                tag_no_case("http"),
                map(opt(preceded(char(':'), u16)), |r| r.unwrap_or(80)),
            ),
            Http,
        );
        let https = map(
            preceded(
                tag_no_case("https"),
                map(opt(preceded(char(':'), u16)), |r| r.unwrap_or(443)),
            ),
            Https,
        );

        alt((ping, tcp, https, http))(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_speed_mode_parse() {
        use SpeedCheckMode::*;

        assert_eq!(SpeedCheckMode::parse("ping"), Ok(("", Ping)));
        assert_eq!(SpeedCheckMode::parse("Ping"), Ok(("", Ping)));
        assert_eq!(SpeedCheckMode::parse("tcp:96"), Ok(("", Tcp(96))));
        assert_eq!(SpeedCheckMode::parse("http"), Ok(("", Http(80))));
        assert_eq!(SpeedCheckMode::parse("http:82"), Ok(("", Http(82))));
        assert_eq!(SpeedCheckMode::parse("https"), Ok(("", Https(443))));
        assert_eq!(SpeedCheckMode::parse("https:8443"), Ok(("", Https(8443))));

        assert!(SpeedCheckMode::parse("tcp").is_err());
    }

    #[test]
    fn test_speed_mode_list_parse() {
        use SpeedCheckMode::*;
        assert_eq!(
            SpeedCheckModeList::parse("ping,tcp:96"),
            Ok(("", vec![Ping, Tcp(96)].into()))
        );
    }

    #[test]
    fn test_speed_mode_none() {
        assert_eq!(
            SpeedCheckModeList::parse("none"),
            Ok(("", Default::default()))
        );
    }
}
