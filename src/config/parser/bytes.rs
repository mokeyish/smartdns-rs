use super::*;

impl NomParser for Byte {
    fn parse(input: &str) -> IResult<&str, Self> {
        let num = recognize(pair(digit1, opt(pair(char('.'), digit1))));
        let unit = alpha1;
        map_res(recognize(tuple((num, space0, unit))), |s| {
            Byte::parse_str(s, true)
        })(input)
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
            Ok(("", Byte::from_u64_with_unit(12, Unit::KB).unwrap()))
        );
        assert_eq!(
            Byte::parse("123mb"),
            Ok(("", Byte::from_u64_with_unit(123, Unit::MB).unwrap()))
        );
        assert_eq!(
            Byte::parse("123m"),
            Ok(("", Byte::from_u64_with_unit(123, Unit::MB).unwrap()))
        );
        assert_eq!(
            Byte::parse("80mb"),
            Ok(("", Byte::from_u64_with_unit(80, Unit::MB).unwrap()))
        );
        assert_eq!(
            Byte::parse("30 gb"),
            Ok(("", Byte::from_i64_with_unit(30, Unit::GB).unwrap()))
        );
        assert_eq!(
            Byte::parse("30GB"),
            Ok(("", Byte::from_i64_with_unit(30, Unit::GB).unwrap()))
        );
    }
}
