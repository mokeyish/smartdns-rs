use super::*;

use super::NFTsetConfig;

impl NomParser for NFTsetConfig {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        let family = alt((
            value("inet", tag("inet")),
            value("ip6", tag("ip6")),
            value("ip", tag("ip")),
        ));

        let table = preceded(
            char('#'),
            take_while1(|c: char| c.is_ascii_alphanumeric() || c == '_'),
        );
        let name = preceded(
            char('#'),
            take_while1(|c: char| c.is_ascii_alphanumeric() || c == '_'),
        );

        let (input, (family, table, name)) = (family, table, name).parse(input)?;
        Ok((
            input,
            NFTsetConfig {
                family,
                table: table.to_string(),
                name: name.to_string(),
            },
        ))
    }
}

impl NomParser for ConfigForIP<NFTsetConfig> {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        let v4 = preceded(
            tag("#4:"),
            verify(NFTsetConfig::parse, |x| {
                x.family == "inet" || x.family == "ip"
            }),
        );
        let v6 = preceded(
            tag("#6:"),
            verify(NFTsetConfig::parse, |x| {
                x.family == "inet" || x.family == "ip6"
            }),
        );

        alt((
            map(char('-'), |_| ConfigForIP::None),
            map(v4, ConfigForIP::V4),
            map(v6, ConfigForIP::V6),
        ))
        .parse(input)
    }
}

impl NomParser for Vec<ConfigForIP<NFTsetConfig>> {
    fn parse(input: &str) -> IResult<&str, Self> {
        separated_list1(
            (space0, char(','), space0),
            ConfigForIP::<NFTsetConfig>::parse,
        )
        .parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            NFTsetConfig::parse("inet#tab1#dns_4").unwrap(),
            (
                "",
                NFTsetConfig {
                    family: "inet",
                    table: "tab1".to_string(),
                    name: "dns_4".to_string()
                }
            )
        );

        assert_eq!(
            NFTsetConfig::parse("inet#tab1#dns4").unwrap(),
            (
                "",
                NFTsetConfig {
                    family: "inet",
                    table: "tab1".to_string(),
                    name: "dns4".to_string()
                }
            )
        );

        assert_eq!(
            NFTsetConfig::parse("ip6#tab1#dns6").unwrap(),
            (
                "",
                NFTsetConfig {
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
            ConfigForIP::<NFTsetConfig>::parse("#4:inet#tab#dns4").unwrap(),
            (
                "",
                ConfigForIP::V4(NFTsetConfig {
                    family: "inet",
                    table: "tab".to_string(),
                    name: "dns4".to_string(),
                })
            )
        );

        assert_eq!(
            ConfigForIP::<NFTsetConfig>::parse("#6:ip6#tab#dns6").unwrap(),
            (
                "",
                ConfigForIP::V6(NFTsetConfig {
                    family: "ip6",
                    table: "tab".to_string(),
                    name: "dns6".to_string(),
                })
            )
        );

        assert_eq!(
            ConfigForIP::<NFTsetConfig>::parse("-").unwrap(),
            ("", ConfigForIP::None)
        );
    }
}
