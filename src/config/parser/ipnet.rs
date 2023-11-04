use super::*;

impl NomParser for IpNet {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(
            is_a("0123456789abcdef:./"),
            <IpNet as std::str::FromStr>::from_str,
        )(input)
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
}
