use super::*;

impl NomParser for FileMode {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(is_a("0o1234567"), <FileMode as std::str::FromStr>::from_str).parse(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_parse() {
        assert_eq!(FileMode::parse("644"), Ok(("", 0o644u32.into())));
        assert_eq!(FileMode::parse("0644"), Ok(("", 0o644u32.into())));
        assert_eq!(FileMode::parse("o644"), Ok(("", 0o644u32.into())));
        assert_eq!(FileMode::parse("0o755"), Ok(("", 0o755u32.into())));
    }
}
