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

    #[test]
    fn test_parse() {
        use byte_unit::Unit;
        assert_eq!(
            Byte::parse("12kb"),
            Ok(("", Byte::from_i64_with_unit(12, Unit::Kbit).unwrap()))
        );
        assert_eq!(
            Byte::parse("123mb"),
            Ok(("", Byte::from_i64_with_unit(123, Unit::Mbit).unwrap()))
        );
        assert_eq!(
            Byte::parse("80mb"),
            Ok(("", Byte::from_i64_with_unit(80, Unit::Mbit).unwrap()))
        );
        assert_eq!(
            Byte::parse("30 gb"),
            Ok(("", Byte::from_i64_with_unit(30, Unit::Gbit).unwrap()))
        );
    }
}
