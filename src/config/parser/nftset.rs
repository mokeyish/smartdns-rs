use super::*;

use super::NftsetConfig;

impl NomParser for NftsetConfig {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        let family = alt((
            value("inet", tag("inet")),
            value("ip6", tag("ip6")),
            value("ip", tag("ip")),
        ));

        let table = preceded(char('#'), alphanumeric1);
        let name = preceded(char('#'), alphanumeric1);

        let (input, (family, table, name)) = tuple((family, table, name))(input)?;
        Ok((
            input,
            NftsetConfig {
                family,
                table: table.to_string(),
                name: name.to_string(),
            },
        ))
    }
}

impl NomParser for ConfigForIP<NftsetConfig> {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
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
            map(char('-'), |_| ConfigForIP::None),
            map(v4, ConfigForIP::V4),
            map(v6, ConfigForIP::V6),
        ))(input)
    }
}

impl NomParser for Vec<ConfigForIP<NftsetConfig>> {
    fn parse(input: &str) -> IResult<&str, Self> {
        separated_list1(
            tuple((space0, char(','), space0)),
            ConfigForIP::<NftsetConfig>::parse,
        )(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            NftsetConfig::parse("inet#tab1#dns4").unwrap(),
            (
                "",
                NftsetConfig {
                    family: "inet",
                    table: "tab1".to_string(),
                    name: "dns4".to_string()
                }
            )
        );

        assert_eq!(
            NftsetConfig::parse("inet#tab1#dns4").unwrap(),
            (
                "",
                NftsetConfig {
                    family: "inet",
                    table: "tab1".to_string(),
                    name: "dns4".to_string()
                }
            )
        );

        assert_eq!(
            NftsetConfig::parse("ip6#tab1#dns6").unwrap(),
            (
                "",
                NftsetConfig {
                    family: "ip6",
                    table: "tab1".to_string(),
                    name: "dns6".to_string()
                }
            )
        );
    }

    #[test]
    fn test_ip() {
        assert_eq!(
            ConfigForIP::<NftsetConfig>::parse("#4:inet#tab#dns4").unwrap(),
            (
                "",
                ConfigForIP::V4(NftsetConfig {
                    family: "inet",
                    table: "tab".to_string(),
                    name: "dns4".to_string(),
                })
            )
        );

        assert_eq!(
            ConfigForIP::<NftsetConfig>::parse("#6:ip6#tab#dns6").unwrap(),
            (
                "",
                ConfigForIP::V6(NftsetConfig {
                    family: "ip6",
                    table: "tab".to_string(),
                    name: "dns6".to_string(),
                })
            )
        );

        assert_eq!(
            ConfigForIP::<NftsetConfig>::parse("-").unwrap(),
            ("", ConfigForIP::None)
        );
    }
}
