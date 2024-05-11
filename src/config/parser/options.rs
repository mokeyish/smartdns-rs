use super::*;

fn name<'a, O, E: nom::error::ParseError<&'a str>, P: nom::Parser<&'a str, O, E>>(
    parser: P,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, E> {
    preceded(take_while_m_n(1, 2, |c| c == '-'), parser)
}

fn any_name(input: &str) -> IResult<&str, &str> {
    name(recognize(pair(
        alpha1,
        take_while(|c: char| c == '-' || c.is_alphanumeric()),
    )))(input)
}

pub fn parse_value<
    'a,
    ON,
    OV,
    E: nom::error::ParseError<&'a str>,
    N: nom::Parser<&'a str, ON, E>,
    V: nom::Parser<&'a str, OV, E>,
>(
    name: N,
    value: V,
) -> impl FnMut(&'a str) -> IResult<&'a str, OV, E> {
    preceded(
        tuple((
            take_while_m_n(1, 2, |c| c == '-'),
            name,
            alt((tag("="), recognize(pair(opt(char(':')), space1)))),
        )),
        value,
    )
}

pub fn parse_no_value<'a, O, E: nom::error::ParseError<&'a str>, N: nom::Parser<&'a str, O, E>>(
    name: N,
) -> impl FnMut(&'a str) -> IResult<&'a str, bool, E> {
    value(true, preceded(take_while_m_n(1, 2, |c| c == '-'), name))
}

pub fn unknown_value(input: &str) -> IResult<&str, &str> {
    preceded(
        alt((tag("="), recognize(pair(opt(char(':')), space1)))),
        recognize(pair(
            is_not("-_ \t#"),
            take_till(|c: char| c.is_whitespace()),
        )),
    )(input)
}

pub fn unknown_options(input: &str) -> IResult<&str, (&str, Option<&str>)> {
    let key = any_name;
    let value = unknown_value;
    pair(key, opt(value))(input)
}

pub fn parse(input: &str) -> IResult<&str, Options<'_>> {
    let (input, options) = separated_list0(space1, unknown_options)(input)?;

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

    #[test]
    fn test_parse_options1() {
        assert_eq!(
            parse("-group bootstrap -exclude-default-group").unwrap(),
            (
                "",
                vec![
                    ("group", Some("bootstrap")),
                    ("exclude-default-group", None)
                ]
            )
        );
    }

    #[test]
    fn test_parse_options2() {
        assert_eq!(
            parse("-group bootstrap # -exclude-default-group").unwrap(),
            (
                " # -exclude-default-group",
                vec![("group", Some("bootstrap"))]
            )
        );
    }
}
