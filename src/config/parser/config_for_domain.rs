use super::*;

impl<T: NomParser + Clone> NomParser for ConfigForDomain<T> {
    fn parse(input: &str) -> IResult<&str, Self> {
        let domain = map(opt(delimited(char('/'), Domain::parse, char('/'))), |n| {
            n.unwrap_or_else(|| Domain::Name(WildcardName::Default(Name::root())))
        });
        let config = T::parse;
        map(
            pair(domain, preceded(space0, config)),
            |(domain, config)| ConfigForDomain { domain, config },
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
            ConfigForDomain::parse("/www.example.com/#4:inet#tab#dns4").unwrap(),
            (
                "",
                ConfigForDomain {
                    domain: Domain::Name("www.example.com".parse().unwrap()),
                    config: ConfigForIP::V4(NFTsetConfig {
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
                    config: ConfigForIP::V6(NFTsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })
                }
            )
        );

        assert_eq!(
            ConfigForDomain::parse("#6:inet#tab#dns4").unwrap(),
            (
                "",
                ConfigForDomain {
                    domain: Domain::Name(WildcardName::Default(Name::root())),
                    config: ConfigForIP::V6(NFTsetConfig {
                        family: "inet",
                        table: "tab".to_string(),
                        name: "dns4".to_string()
                    })
                }
            )
        );
    }
}
