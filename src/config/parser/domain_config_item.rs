use super::*;

impl<T: NomParser + Clone> NomParser for DomainConfigItem<T> {
    fn parse(input: &str) -> IResult<&str, Self> {
        parse(input)
    }
}

fn parse<T: NomParser + Clone>(input: &str) -> IResult<&str, DomainConfigItem<T>> {
    let domain = delimited(char('/'), Domain::parse, char('/'));
    let config = T::parse;
    map(pair(domain, config), |(domain, config)| DomainConfigItem {
        domain,
        config,
    })(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            parse("/www.example.com/#4:inet#tab#dns4").unwrap(),
            (
                "",
                DomainConfigItem {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: IpConfig::V4(NftsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })
                }
            )
        );

        assert_eq!(
            parse("/domain-set:abc/#6:inet#tab#dns4").unwrap(),
            (
                "",
                DomainConfigItem {
                    domain: Domain::Set("abc".to_string()),
                    config: IpConfig::V6(NftsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })
                }
            )
        );
    }
}
