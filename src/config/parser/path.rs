use super::*;

impl NomParser for PathBuf {
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
        map(alt((delimited_path, unix_path, windows_path)), Into::into).parse(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(PathBuf::parse("a"), Ok(("", "a".into())));
        assert_eq!(PathBuf::parse("/"), Ok(("", "/".into())));
        assert_eq!(PathBuf::parse("a/b😁/c"), Ok(("", "a/b😁/c".into())));
        assert_eq!(PathBuf::parse("a/ b/c"), Ok((" b/c", "a/".into())));
        assert_eq!(PathBuf::parse("/a/b/c"), Ok(("", "/a/b/c".into())));
        assert_eq!(PathBuf::parse("/a/b/c/"), Ok(("", "/a/b/c/".into())));
        assert_eq!(PathBuf::parse("a/b/c/"), Ok(("", "a/b/c/".into())));
    }

    #[test]
    fn test_backslash_escaping_parse() {
        assert_eq!(PathBuf::parse(r#"a/\ b/c"#), Ok(("", r#"a/\ b/c"#.into())));
        assert_eq!(PathBuf::parse(r#"a/\\b/c"#), Ok(("", r#"a/\\b/c"#.into())));
    }

    #[test]
    fn test_delimited_path_parse() {
        assert_eq!(PathBuf::parse(r#""a/ b/c""#), Ok(("", "a/ b/c".into())));
    }

    #[test]
    fn test_windows_path_parse() {
        assert_eq!(
            PathBuf::parse(r#"C:\Users\Administrator\Desktop\smartdns\smartdns.log"#),
            Ok((
                "",
                r#"C:\Users\Administrator\Desktop\smartdns\smartdns.log"#.into()
            ))
        );
        assert_eq!(
            PathBuf::parse(r#"C:/Users/Administrator/Desktop/smartdns/smartdns.log"#),
            Ok((
                "",
                r#"C:/Users/Administrator/Desktop/smartdns/smartdns.log"#.into()
            ))
        );
        assert_eq!(
            PathBuf::parse(r#".\smartdns\smartdns.log"#),
            Ok(("", r#".\smartdns\smartdns.log"#.into()))
        );
        assert_eq!(
            PathBuf::parse(r#".\smartdns\"#),
            Ok(("", r#".\smartdns\"#.into()))
        );
    }
}
