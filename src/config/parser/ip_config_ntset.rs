use super::*;

impl NomParser for IpConfig<NftsetConfig> {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        parse(input)
    }
}

fn parse(input: &str) -> IResult<&str, IpConfig<NftsetConfig>> {
    let v4 = preceded(
        tag("#4:"),
        verify(NftsetConfig::parse, |x| {
            x.family == "inet" || x.family == "ip"
        }),
    );
    let v6 = preceded(
        tag("#6:"),
        verify(NftsetConfig::parse, |x| {
            x.family == "inet" || x.family == "ip6"
        }),
    );

    alt((
        map(char('-'), |_| IpConfig::None),
        map(v4, IpConfig::V4),
        map(v6, IpConfig::V6),
    ))(input)
}

impl NomParser for Vec<IpConfig<NftsetConfig>> {
    fn parse(input: &str) -> IResult<&str, Self> {
        separated_list1(
            tuple((space0, char(','), space0)),
            IpConfig::<NftsetConfig>::parse,
        )(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            parse("#4:inet#tab#dns4").unwrap(),
            (
                "",
                IpConfig::V4(NftsetConfig {
                    family: "inet",
                    table: "tab".to_string(),
                    name: "dns4".to_string(),
                })
            )
        );

        assert_eq!(
            parse("#6:ip6#tab#dns6").unwrap(),
            (
                "",
                IpConfig::V6(NftsetConfig {
                    family: "ip6",
                    table: "tab".to_string(),
                    name: "dns6".to_string(),
                })
            )
        );

        assert_eq!(parse("-").unwrap(), ("", IpConfig::None));
    }
}
