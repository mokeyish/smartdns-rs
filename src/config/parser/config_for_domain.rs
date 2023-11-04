use super::*;

impl<T: NomParser + Clone> NomParser for ConfigForDomain<T> {
    fn parse(input: &str) -> IResult<&str, Self> {
        let domain = delimited(char('/'), Domain::parse, char('/'));
        let config = T::parse;
        map(
            pair(domain, preceded(space0, config)),
            |(domain, config)| ConfigForDomain { domain, config },
        )(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(
            ConfigForDomain::parse("/www.example.com/#4:inet#tab#dns4").unwrap(),
            (
                "",
                ConfigForDomain {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: ConfigForIP::V4(NftsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })
                }
            )
        );

        assert_eq!(
            ConfigForDomain::parse("/domain-set:abc/#6:inet#tab#dns4").unwrap(),
            (
                "",
                ConfigForDomain {
                    domain: Domain::Set("abc".to_string()),
                    config: ConfigForIP::V6(NftsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })
                }
            )
        );
    }
}
