use super::*;

impl NomParser for IpAlias {
    fn parse(input: &str) -> IResult<&str, Self> {
        let ip_list = separated_list1(tuple((space0, char(','), space0)), nom_recipes::ip);
        map(
            separated_pair(IpOrSet::parse, space1, ip_list),
            |(ip, to)| IpAlias { ip, to: to.into() },
        )(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            IpAlias::parse("0.1.2.3 4.5.6.7,::89AB:CDEF"),
            Ok((
                "",
                IpAlias {
                    ip: IpOrSet::Net("0.1.2.3/32".parse().unwrap()),
                    to: ["4.5.6.7", "::89AB:CDEF"]
                        .map(|x| x.parse().unwrap())
                        .into(),
                }
            ))
        );

        assert_eq!(
            IpAlias::parse("ip-set:name  ::  ,  1.2.3.4"),
            Ok((
                "",
                IpAlias {
                    ip: IpOrSet::Set("name".to_string()),
                    to: ["::", "1.2.3.4"].map(|x| x.parse().unwrap()).into(),
                }
            ))
        );
    }
}
