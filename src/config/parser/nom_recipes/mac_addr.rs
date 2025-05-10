use nom::{
    AsChar, IResult, Parser,
    bytes::complete::take_while_m_n,
    character::complete::char,
    combinator::{recognize, verify},
    error::context,
    multi::separated_list1,
};

pub fn mac_addr(input: &str) -> IResult<&str, &str> {
    let hextal = take_while_m_n(2, 2, |c: char| c.is_hex_digit());
    let hextal = verify(hextal, |s: &str| s.len() == 2);

    let parts = separated_list1(char(':'), hextal);
    let parts = verify(parts, |s: &Vec<&str>| s.len() == 6);
    let parts = recognize(parts);
    context("MacAddr", parts).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_addr() {
        assert_eq!(mac_addr("01:23:45:67:89:ab"), Ok(("", "01:23:45:67:89:ab")));
        assert_eq!(
            mac_addr("01:23:45:67:89:ab "),
            Ok((" ", "01:23:45:67:89:ab"))
        );

        assert!(mac_addr("01:23:45:67:89").is_err());
        assert!(mac_addr("01-23-45-67-89-ab").is_err());
    }
}
