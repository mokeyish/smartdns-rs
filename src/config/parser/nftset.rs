use super::*;

use super::NftsetConfig;

impl NomParser for NftsetConfig {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Self> {
        parse(input)
    }
}

fn parse(input: &str) -> IResult<&str, NftsetConfig> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            parse("inet#tab1#dns4").unwrap(),
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
            parse("inet#tab1#dns4").unwrap(),
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
            parse("ip6#tab1#dns6").unwrap(),
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
}
