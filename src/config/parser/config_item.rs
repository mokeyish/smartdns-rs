use super::*;

impl NomParser for ConfigItem {
    fn parse(input: &str) -> IResult<&str, Self> {
        parse(input)
    }
}

pub fn parse(input: &str) -> IResult<&str, ConfigItem> {
    let comment = opt(preceded(space1, preceded(char('#'), not_line_ending)));

    let item = |keyword, parser| {
        preceded(
            tuple((space0, keyword, space1)),
            terminated(parser, comment),
        )
    };

    alt((map(
        item(
            tag_no_case("nftset"),
            DomainConfigItem::<Vec<IpConfig<NftsetConfig>>>::parse,
        ),
        ConfigItem::NftSet,
    ),))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            parse("nftset /www.example.com/#4:inet#tab#dns4").unwrap(),
            (
                "",
                ConfigItem::NftSet(DomainConfigItem {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: vec![IpConfig::V4(NftsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })]
                })
            )
        );

        assert_eq!(
            parse("nftset /www.example.com/#4:inet#tab#dns4 # comment 123").unwrap(),
            (
                "",
                ConfigItem::NftSet(DomainConfigItem {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: vec![IpConfig::V4(NftsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })]
                })
            )
        );
    }
}
