use super::*;

pub fn parse(input: &str) -> IResult<&str, Options<'_>> {
    let key = preceded(
        take_while_m_n(1, 2, |c| c == '-'),
        recognize(pair(
            alpha1,
            take_while(|c: char| c == '-' || c.is_alphanumeric()),
        )),
    );
    let value = preceded(
        alt((tag("="), space1)),
        recognize(pair(
            is_not("-_ \t"),
            take_till(|c: char| c.is_whitespace()),
        )),
    );

    let key_value_pair = pair(key, opt(value));

    let (input, options) = separated_list0(space1, key_value_pair)(input)?;

    Ok((input, options))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_options() {
        assert_eq!(
            parse("-a a1 --b b0 -w").unwrap(),
            ("", vec![("a", Some("a1")), ("b", Some("b0")), ("w", None)])
        );

        assert_eq!(parse("---a").unwrap(), ("---a", vec![]));

        assert_eq!(parse("-w123").unwrap(), ("", vec![("w123", None)]));
    }
}
