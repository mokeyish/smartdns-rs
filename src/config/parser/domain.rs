use std::str::FromStr;

use super::*;

impl NomParser for Domain {
    #[inline]
    fn parse(input: &str) -> IResult<&str, Domain> {
        parse(input)
    }
}

fn parse(input: &str) -> IResult<&str, Domain> {
    let set = alphanumeric0;

    let name = is_not(" \n\t\\/|\"#',!+*<>");

    alt((
        map(
            preceded(tag_no_case("domain-set:"), map(set, String::from)),
            Domain::Set,
        ),
        map(map_res(name, Name::from_str), Domain::Name),
    ))(input)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        let (_, domain) = parse("domain-set:abc").unwrap();
        assert_eq!(domain, Domain::Set("abc".to_string()));

        let (_, domain) = parse("www.baidu.com").unwrap();
        assert_eq!(
            domain,
            Domain::Name(Name::from_str("www.baidu.com").unwrap())
        );

        let (_, domain) = parse("baidu.com").unwrap();
        assert_eq!(domain, Domain::Name(Name::from_str("baidu.com").unwrap()));

        let (_, domain) = parse("xxx.集团").unwrap();
        assert_eq!(domain, Domain::Name(Name::from_str("xxx.集团").unwrap()));

        let (_, domain) = parse("xxx.集团 w").unwrap();
        assert_eq!(domain, Domain::Name(Name::from_str("xxx.集团").unwrap()));
    }
}
