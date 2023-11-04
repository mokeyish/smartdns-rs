use super::*;

impl NomParser for PathBuf {
    fn parse(input: &str) -> IResult<&str, Self> {
        let path = escaped(is_not("\n \t\\"), '\\', one_of(r" \"));
        map(path, Into::into)(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(PathBuf::parse("a/b/c"), Ok(("", "a/b/c".into())));
        assert_eq!(PathBuf::parse("a/ b/c"), Ok((" b/c", "a/".into())));
        assert_eq!(PathBuf::parse(r"a/\ b/c"), Ok(("", r"a/\ b/c".into())));
        assert_eq!(PathBuf::parse(r"a/\\b/c"), Ok(("", r"a/\\b/c".into())));
    }
}
