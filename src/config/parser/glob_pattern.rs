use glob::Pattern;

use super::*;

impl NomParser for Pattern {
    fn parse(input: &str) -> IResult<&str, Self> {
        let delimited_path = delimited(char('"'), is_not("\""), char('"'));
        let unix_path = recognize((
            opt(char('/')),
            separated_list1(char('/'), escaped(is_not("\n \t\\"), '\\', one_of(r#" \"#))),
            opt(char('/')),
        ));
        let windows_path = recognize((
            opt(pair(alpha1, tag(":\\"))),
            separated_list1(char('\\'), is_not("\\")),
            opt(char('\\')),
        ));
        map_res(
            alt((delimited_path, unix_path, windows_path)),
            FromStr::from_str,
        )
        .parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(Pattern::parse("a*"), Ok(("", "a*".parse().unwrap())));
        assert_eq!(Pattern::parse("/"), Ok(("", "/".parse().unwrap())));
        assert_eq!(
            Pattern::parse("a/b😁/c"),
            Ok(("", "a/b😁/c".parse().unwrap()))
        );
        assert_eq!(
            Pattern::parse("a/ b/c"),
            Ok((" b/c", "a/".parse().unwrap()))
        );
        assert_eq!(
            Pattern::parse("/a/b/c"),
            Ok(("", "/a/b/c".parse().unwrap()))
        );
        assert_eq!(
            Pattern::parse("/a/b/c/"),
            Ok(("", "/a/b/c/".parse().unwrap()))
        );
        assert_eq!(
            Pattern::parse("a/b/c*/"),
            Ok(("", "a/b/c*/".parse().unwrap()))
        );
        assert_eq!(
            Pattern::parse("**/*.rs"),
            Ok(("", "**/*.rs".parse().unwrap()))
        );
    }
}
