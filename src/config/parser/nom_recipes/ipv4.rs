use std::net::Ipv4Addr;

use nom::{
    character::complete::{char, digit1},
    combinator::{map, map_res, recognize},
    error::context,
    multi::many_m_n,
    sequence::{preceded, tuple},
    IResult,
};

pub fn ipv4(input: &str) -> IResult<&str, Ipv4Addr> {
    fn octal(input: &str) -> IResult<&str, u8> {
        map_res(recognize(many_m_n(1, 3, digit1)), |s: &str| s.parse())(input)
    }

    context(
        "Ipv4Addr",
        map(
            tuple((
                octal,
                preceded(char('.'), octal),
                preceded(char('.'), octal),
                preceded(char('.'), octal),
            )),
            |(a, b, c, d)| Ipv4Addr::new(a, b, c, d),
        ),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4() {
        assert_eq!(ipv4("127.0.0.1"), Ok(("", Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(
            ipv4("255.255.255.255"),
            Ok(("", Ipv4Addr::new(255, 255, 255, 255)))
        );
        assert_eq!(ipv4("0.0.0.0"), Ok(("", Ipv4Addr::new(0, 0, 0, 0))));
        assert_eq!(ipv4("1.2.3.4"), Ok(("", Ipv4Addr::new(1, 2, 3, 4))));
        assert!(ipv4("256.0.0.0").is_err());
        assert!(ipv4("0.0 .0.256").is_err());
        assert!(ipv4("0.0.0").is_err());
    }
}
