use super::*;

impl NomParser for Byte {
    fn parse(input: &str) -> IResult<&str, Self> {
        let num = recognize(pair(digit1, opt(pair(char('.'), digit1))));
        let unit = alpha1;
        map_res(
            recognize(tuple((num, space0, unit))),
            <Byte as std::str::FromStr>::from_str,
        )(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use byte_unit::{n_gb_bytes, n_kb_bytes, n_mb_bytes};

    #[test]
    fn test_parse() {
        assert_eq!(Byte::parse("12kb"), Ok(("", n_kb_bytes(12).into())));
        assert_eq!(Byte::parse("123mb"), Ok(("", n_mb_bytes(123).into())));
        assert_eq!(Byte::parse("80mb"), Ok(("", n_mb_bytes(80).into())));
        assert_eq!(Byte::parse("30 gb"), Ok(("", n_gb_bytes(30).into())));
    }
}
