use super::*;

/// ip-set -type list -file /path/to/list
/// ip-set -type list -f /path/to/list
impl NomParser for IpSetProvider {
    fn parse(input: &str) -> IResult<&str, Self> {
        let mut name = None;
        let mut file = None;

        let one = alt((
            map(
                options::parse_value(alt((tag_no_case("name"), tag_no_case("n"))), String::parse),
                |v| name = Some(v),
            ),
            map(
                options::parse_value(alt((tag_no_case("file"), tag_no_case("f"))), PathBuf::parse),
                |v| file = Some(v),
            ),
            options::parse_value(
                alt((tag_no_case("type"), tag_no_case("t"))),
                value((), tag_no_case("list")),
            ),
        ));

        let (rest_input, _) = separated_list1(space1, one)(input)?;

        if let (Some(name), Some(file)) = (name, file) {
            return Ok((rest_input, IpSetProvider { name, file }));
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
    fn parse() {
        assert_eq!(
            IpSetProvider::parse("-n name -f file.txt"),
            Ok((
                "",
                IpSetProvider {
                    name: "name".to_string(),
                    file: PathBuf::from("file.txt"),
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
                }
            ))
        );
    }
}
