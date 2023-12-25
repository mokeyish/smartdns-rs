use super::*;

impl NomParser for Name {
    fn parse(input: &str) -> IResult<&str, Self> {
        let name = is_not(" \n\t\\/|\"#',!+<>");
        map_res(name, <Name as std::str::FromStr>::from_str)(input)
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
        ))(input)
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
}
