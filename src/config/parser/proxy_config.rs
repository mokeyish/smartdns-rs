use std::str::FromStr;

use super::*;

impl NomParser for NamedProxyConfig {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut name = None;
        let mut proxy = None;

        let one = alt((
            map(
                options::parse_value(
                    alt((tag_no_case("name"), tag_no_case("n"))),
                    NomParser::parse,
                ),
                |v| {
                    name = Some(v);
                },
            ),
            map(map_res(is_not(" \t\r\n"), ProxyConfig::from_str), |v| {
                proxy = Some(v)
            }),
        ));

        let (rest_input, _) = separated_list1(space1, one)(input)?;

        if let (Some(name), Some(config)) = (name, proxy) {
            return Ok((rest_input, NamedProxyConfig { name, config }));
        }

        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse_proxy_config() {
        assert_eq!(
            NamedProxyConfig::parse("socks5://user:pass@1.2.3.4:1080 -name proxy"),
            Ok((
                "",
                NamedProxyConfig {
                    name: "proxy".to_string(),
                    config: "socks5://user:pass@1.2.3.4:1080".parse().unwrap()
                }
            ))
        );
    }
}
