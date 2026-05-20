use super::*;

/// ip-set -type list -file /path/to/list
/// ip-set -type list -f /path/to/list
/// ip-set -type geoip -file /path/to/geoip.dat -match cn
impl NomParser for IpSetProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut name = None;
        let mut file = None;
        let mut content_type: IpSetContentType = Default::default();
        let mut match_tag = None;

        let one = alt((
            map(
                options::parse_value(alt((tag_no_case("name"), tag_no_case("n"))), String::parse),
                |v| name = Some(v),
            ),
            map(
                options::parse_value(alt((tag_no_case("file"), tag_no_case("f"))), PathBuf::parse),
                |v| file = Some(v),
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("type"), tag_no_case("t"))),
                    IpSetContentType::parse,
                ),
                |v| content_type = v,
            ),
            map(
                options::parse_value(
                    alt((tag_no_case("match"), tag_no_case("m"))),
                    String::parse,
                ),
                |v| match_tag = Some(v),
            ),
        ));

        let (rest_input, _) = separated_list1(space1, one).parse(input)?;

        if let (Some(name), Some(file)) = (name, file) {
            return Ok((
                rest_input,
                IpSetProvider {
                    name,
                    file,
                    content_type,
                    match_tag,
                },
            ));
        }

        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )))
    }
}

impl NomParser for IpSetContentType {
    fn parse(input: &str) -> IResult<&str, Self> {
        use IpSetContentType::*;
        alt((
            value(List, tag_no_case("list")),
            #[cfg(feature = "geodata")]
            value(GeoIp, tag_no_case("geoip")),
            #[cfg(feature = "geodata")]
            value(Mmdb, tag_no_case("mmdb")),
        ))
        .parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!(
            IpSetProvider::parse("-n name -f file.txt"),
            Ok((
                "",
                IpSetProvider {
                    name: "name".to_string(),
                    file: PathBuf::from("file.txt"),
                    content_type: Default::default(),
                    match_tag: None,
                }
            ))
        );

        assert_eq!(
            IpSetProvider::parse("-name set -file /path/to/list"),
            Ok((
                "",
                IpSetProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list"),
                    content_type: Default::default(),
                    match_tag: None,
                }
            ))
        );

        assert_eq!(
            IpSetProvider::parse("-type list -name set -file /path/to/list"),
            Ok((
                "",
                IpSetProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list"),
                    content_type: Default::default(),
                    match_tag: None,
                }
            ))
        );

        assert_eq!(
            IpSetProvider::parse("-type list -name set -f /path/to/list"),
            Ok((
                "",
                IpSetProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list"),
                    content_type: Default::default(),
                    match_tag: None,
                }
            ))
        );

        assert_eq!(
            IpSetProvider::parse("-t list -name set -f /path/to/list"),
            Ok((
                "",
                IpSetProvider {
                    name: "set".to_string(),
                    file: PathBuf::from("/path/to/list"),
                    content_type: Default::default(),
                    match_tag: None,
                }
            ))
        );
    }

    #[cfg(feature = "geodata")]
    #[test]
    fn parse_geoip() {
        assert_eq!(
            IpSetProvider::parse("-type geoip -name cn-ip -file /etc/smartdns/geoip.dat -match cn"),
            Ok((
                "",
                IpSetProvider {
                    name: "cn-ip".to_string(),
                    file: PathBuf::from("/etc/smartdns/geoip.dat"),
                    content_type: IpSetContentType::GeoIp,
                    match_tag: Some("cn".to_string()),
                }
            ))
        );

        assert_eq!(
            IpSetProvider::parse("-t geoip -n us-ip -f geoip.dat -m us"),
            Ok((
                "",
                IpSetProvider {
                    name: "us-ip".to_string(),
                    file: PathBuf::from("geoip.dat"),
                    content_type: IpSetContentType::GeoIp,
                    match_tag: Some("us".to_string()),
                }
            ))
        );
    }

    #[cfg(feature = "geodata")]
    #[test]
    fn parse_mmdb() {
        assert_eq!(
            IpSetProvider::parse(
                "-type mmdb -name cn-ip -file /etc/smartdns/country.mmdb -match CN"
            ),
            Ok((
                "",
                IpSetProvider {
                    name: "cn-ip".to_string(),
                    file: PathBuf::from("/etc/smartdns/country.mmdb"),
                    content_type: IpSetContentType::Mmdb,
                    match_tag: Some("CN".to_string()),
                }
            ))
        );
    }
}
