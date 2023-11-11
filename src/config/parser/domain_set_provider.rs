use url::Url;

use super::*;

///
/// domain-set -type list -file /path/to/list
/// domain-set -type http -url https://example.com/list
impl NomParser for DomainSetProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        use DomainSetProvider::*;
        alt((map(NomParser::parse, File), map(NomParser::parse, Http)))(input)
    }
}

/// domain-set -type list -file /path/to/list
/// domain-set -type list -f /path/to/list
impl NomParser for DomainSetFileProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut name = None;
        let mut file = None;
        let mut is_file_provider = false;

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
            map(
                options::parse_value(
                    alt((tag_no_case("file"), tag_no_case("f"))),
                    NomParser::parse,
                ),
                |v| {
                    file = Some(v);
                },
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("type"), tag_no_case("t"))),
                    tag_no_case("list"),
                ),
                |_| {
                    is_file_provider = true;
                },
            ),
        ));

        let (rest_input, _) = separated_list1(space1, one)(input)?;

        if is_file_provider {
            if let (Some(name), Some(file)) = (name, file) {
                return Ok((rest_input, DomainSetFileProvider { name, file }));
            }
        }

        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

/// domain-set -type http -url https://example.com/list
/// domain-set -type http -u https://example.com/list
impl NomParser for DomainSetHttpProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut name = None;
        let mut url = None;
        let mut interval = None;
        let mut is_url_provider = false;

        let one = alt((
            map(
                options::parse_value(alt((tag_no_case("name"), tag_no_case("n"))), String::parse),
                |v| {
                    name = Some(v);
                },
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("url"), tag_no_case("u"))),
                    map_res(is_not(" \t\r\n"), Url::parse),
                ),
                |v| {
                    url = Some(v);
                },
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("interval"), tag_no_case("i"))),
                    NomParser::parse,
                ),
                |v: usize| {
                    interval = Some(v);
                },
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("type"), tag_no_case("t"))),
                    tag_no_case("list"),
                ),
                |_| {
                    is_url_provider = true;
                },
            ),
        ));

        let (rest_input, _) = separated_list1(space1, one)(input)?;

        if is_url_provider && name.is_some() && url.is_some() {
            if let (Some(name), Some(url)) = (name, url) {
                return Ok((
                    rest_input,
                    DomainSetHttpProvider {
                        name,
                        url,
                        interval,
                    },
                ));
            }
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
    fn test_parse_file_provider() {
        assert_eq!(
            DomainSetProvider::parse("-type list -name set -file /path/to/list"),
            Ok((
                "",
                DomainSetProvider::File(DomainSetFileProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list")
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse("-type list -name set -f /path/to/list"),
            Ok((
                "",
                DomainSetProvider::File(DomainSetFileProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list")
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse("-t list -name set -f /path/to/list"),
            Ok((
                "",
                DomainSetProvider::File(DomainSetFileProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list")
                })
            ))
        );
    }

    #[test]
    fn test_parse_http_provider() {
        assert_eq!(
            DomainSetProvider::parse("-type list -name set -url https://example.com/ads.txt"),
            Ok((
                "",
                DomainSetProvider::Http(DomainSetHttpProvider {
                    name: "set".to_string(),
                    url: Url::parse("https://example.com/ads.txt").unwrap(),
                    interval: None
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse(
                "-type list -name set -url https://example.com/ads.txt -i 3600"
            ),
            Ok((
                "",
                DomainSetProvider::Http(DomainSetHttpProvider {
                    name: "set".to_string(),
                    url: Url::parse("https://example.com/ads.txt").unwrap(),
                    interval: Some(3600)
                })
            ))
        );

        assert_eq!(
            DomainSetProvider::parse(
                "-type list -name set -u https://example.com/ads.txt --interval 3600"
            ),
            Ok((
                "",
                DomainSetProvider::Http(DomainSetHttpProvider {
                    name: "set".to_string(),
                    url: Url::parse("https://example.com/ads.txt").unwrap(),
                    interval: Some(3600)
                })
            ))
        );
    }
}
