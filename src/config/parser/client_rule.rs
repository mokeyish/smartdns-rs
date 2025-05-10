use super::*;

impl NomParser for ClientRule {
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, client) = NomParser::parse(input)?;
        let mut group = None;

        let (input, _) = space1(input)?;

        let one = alt((map(
            options::parse_value(alt((tag_no_case("group"), tag("g"))), NomParser::parse),
            |v| {
                group = Some(v);
            },
        ),));

        let (rest_input, _) = separated_list1(space1, one).parse(input)?;

        let Some(group) = group else {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        };

        Ok((rest_input, ClientRule { group, client }))
    }
}

impl NomParser for Client {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            map(NomParser::parse, Client::IpAddr),
            map(nom_recipes::mac_addr, |mac| {
                Client::MacAddr(mac.to_string())
            }),
        ))
        .parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            ClientRule::parse("01:23:45:67:89:ab -group a"),
            Ok((
                "",
                ClientRule {
                    group: "a".to_string(),
                    client: Client::MacAddr("01:23:45:67:89:ab".to_string())
                }
            ))
        );

        assert_eq!(
            ClientRule::parse("192.168.0.0/16 --group a"),
            Ok((
                "",
                ClientRule {
                    group: "a".to_string(),
                    client: Client::IpAddr("192.168.0.0/16".parse().unwrap())
                }
            ))
        );
    }
}
