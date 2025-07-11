use super::*;

impl NomParser for Name {
    fn parse(input: &str) -> IResult<&str, Self> {
        let name = is_not(" \n\t\\/|\"#',!+<>");
        map_res(name, |s: &str| s.parse()).parse(input)
    }
}

impl NomParser for WildcardName {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            map(
                (
                    map_res(
                        terminated(
                            verify(is_not("."), |w: &str| !w.is_empty() && w.contains('*')),
                            char('.'),
                        ),
                        Wildcard::from_str,
                    ),
                    NomParser::parse,
                ),
                |(w, n)| WildcardName::Sub(w, n),
            ),
            map(
                preceded((char('-'), char('.')), NomParser::parse),
                WildcardName::Full,
            ),
            map(
                preceded((opt(char('+')), char('.')), NomParser::parse),
                WildcardName::Suffix,
            ),
            map(NomParser::parse, |name: Name| {
                if name.is_wildcard() {
                    WildcardName::Sub(Default::default(), name.base_name())
                } else if name.is_root() {
                    WildcardName::Suffix(name)
                } else {
                    WildcardName::Default(name)
                }
            }),
            map(pair(char('+'), opt(char('.'))), |_| {
                WildcardName::Suffix(Name::root())
            }),
        ))
        .parse(input)
    }
}

impl std::str::FromStr for WildcardName {
    type Err = nom::Err<nom::error::Error<String>>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match NomParser::parse(s) {
            Ok((_, v)) => Ok(v),
            Err(e) => Err(e.to_owned()),
        }
    }
}

impl NomParser for Domain {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Domain> {
        let set_name = take_till1(|c| c == '/');

        alt((
            map(
                preceded(tag_no_case("domain-set:"), map(set_name, String::from)),
                Domain::Set,
            ),
            map(NomParser::parse, Domain::Name),
        ))
        .parse(input)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let (_, domain) = Domain::parse("domain-set:abc").unwrap();
        assert_eq!(domain, Domain::Set("abc".to_string()));

        let (_, domain) = Domain::parse("www.baidu.com").unwrap();
        assert_eq!(domain, Domain::Name("www.baidu.com".parse().unwrap()));

        let (_, domain) = Domain::parse("baidu.com").unwrap();
        assert_eq!(domain, Domain::Name("baidu.com".parse().unwrap()));

        let (_, domain) = Domain::parse("xxx.集团").unwrap();
        assert_eq!(domain, Domain::Name("xxx.集团".parse().unwrap()));

        let (_, domain) = Domain::parse("xxx.集团 w").unwrap();
        assert_eq!(domain, Domain::Name("xxx.集团".parse().unwrap()));
    }

    #[test]
    fn test2() {
        use std::str::FromStr;
        let n = Name::from_str(".").unwrap();
        assert_eq!(n, Name::root());

        let n = Name::from_str("*").unwrap();
        assert!(n.is_wildcard());
    }

    #[test]
    fn test3() {
        let (_, domain) = Domain::parse("domain-set:domain-block-list").unwrap();
        assert_eq!(domain, Domain::Set("domain-block-list".to_string()));
    }

    #[test]
    fn test4() {
        use std::str::FromStr;
        let n = WildcardName::from_str(".").unwrap();
        assert_eq!(n, WildcardName::Suffix(Name::root()));

        let n = WildcardName::from_str("*").unwrap();
        assert_eq!(n, WildcardName::Sub(Default::default(), Name::root()));
    }
}
