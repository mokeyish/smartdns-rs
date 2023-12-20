use std::net::IpAddr;

use super::*;

impl NomParser for IpNet {
    fn parse(input: &str) -> IResult<&str, Self> {
        alt((
            map_res(is_a("0123456789abcdef:./"), IpNet::from_str),
            map(
                map_res(is_a("0123456789abcdef:./"), IpAddr::from_str),
                |ip| ip.into(),
            ),
        ))(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            IpNet::parse("1.2.3.4/16"),
            Ok(("", "1.2.3.4/16".parse().unwrap()))
        )
    }

    #[test]
    fn test_parse2() {
        assert_eq!(
            IpNet::parse("1.2.3.4"),
            Ok(("", "1.2.3.4/32".parse().unwrap()))
        )
    }
}
