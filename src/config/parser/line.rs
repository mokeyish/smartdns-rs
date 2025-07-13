use super::*;

#[derive(Debug, PartialEq)]
pub struct ConfigItem<'a> {
    name: &'a str,
    value: &'a str,
    options: Vec<(&'a str, Option<&'a str>)>,
}

impl std::fmt::Display for ConfigItem<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            name,
            value,
            options,
        } = self;

        write!(f, "{} {}", name, value)?;
        for (key, val) in options {
            if let Some(val) = val {
                write!(f, "  -{} {}", key, val)?;
            } else {
                write!(f, "  -{}", key)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum Line<'a, T = ConfigItem<'a>> {
    Config { config: T, comment: Option<&'a str> },
    Comment(&'a str),
    Empty,
    Eof,
}

impl Line<'_> {
    pub fn parse(input: &str) -> Result<Line<'_>, nom::Err<nom::error::Error<&str>>> {
        let (_, line) = parse(input)?;
        Ok(line)
    }
}

impl std::fmt::Display for Line<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Line::Config { config, comment } => {
                write!(f, "{}", config)?;

                if let Some(comment) = comment {
                    write!(f, "{}", comment)?;
                }
            }
            Line::Comment(comment) => {
                write!(f, "{}", comment)?;
            }
            Line::Empty => (),
            Line::Eof => (),
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Lines<'a, T = ConfigItem<'a>>(Vec<Line<'a, T>>);

impl Lines<'_> {
    pub fn parse(input: &str) -> Result<Lines<'_>, nom::Err<nom::error::Error<&str>>> {
        let (rest, lines) = separated_list0(line_ending, parse).parse(input)?;
        assert!(rest.is_empty(), "Expected to consume all input");
        Ok(Lines(lines))
    }
}

impl<'a> std::ops::Deref for Lines<'a> {
    type Target = Vec<Line<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> std::ops::DerefMut for Lines<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::fmt::Display for Lines<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for line in self.0.iter() {
            if matches!(line, Line::Eof) {
                continue;
            }
            writeln!(f, "{}", line)?;
        }
        Ok(())
    }
}

fn parse(input: &str) -> IResult<&str, Line<'_>> {
    fn comment<'a, N, NO, E>(peamble: N) -> impl Parser<&'a str, Output = &'a str, Error = E>
    where
        E: nom::error::ParseError<&'a str>,
        N: nom::Parser<&'a str, Output = NO, Error = E>,
    {
        return map(
            recognize((peamble, char('#'), not_line_ending)),
            |c: &str| c.trim_end(),
        );
    }

    fn option(input: &str) -> IResult<&str, (&str, Option<&str>)> {
        let name = preceded(take_while_m_n(1, 2, |c| c == '-'), is_not("=:"));
        let value = opt(preceded(alt((is_a("=:"), space1)), is_not(" \t")));
        (name, value).parse(input)
    }
    fn options(input: &str) -> IResult<&str, Vec<(&str, Option<&str>)>> {
        many0(option).parse(input)
    }

    fn config(input: &str) -> IResult<&str, (ConfigItem, Option<&str>)> {
        let name = preceded(space0, is_not(" \t\r\n#"));
        let value = preceded(space1, is_not(" \t\r\n"));
        let config = map((name, value, options), |(name, value, options)| {
            ConfigItem {
                name,
                value,
                options,
            }
        });
        let comment = alt((opt(comment(space1)), map(space0, |_| None)));
        (config, comment).parse(input)
    }

    alt((
        map(comment(space0), Line::Comment),
        map(config, |(config, comment)| Line::Config { config, comment }),
        map(eof, |_| Line::Eof),
        map(space0, |_| Line::Empty),
    ))
    .parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn test_parse_line() {
        assert_eq!(
            Line::parse("address /example.com/1.2.3.5").unwrap(),
            Line::Config {
                config: ConfigItem {
                    name: "address",
                    value: "/example.com/1.2.3.5",
                    options: vec![],
                },
                comment: None
            }
        );

        assert_eq!(
            Line::parse("address /example.com/1.2.3.5  ").unwrap(), // trailing spaces should be ignored
            Line::Config {
                config: ConfigItem {
                    name: "address",
                    value: "/example.com/1.2.3.5",
                    options: vec![]
                },
                comment: None
            }
        );

        assert_eq!(
            Line::parse("address /example.com/1.2.3.5  # comment").unwrap(), // trailing spaces should be ignored
            Line::Config {
                config: ConfigItem {
                    name: "address",
                    value: "/example.com/1.2.3.5",
                    options: vec![],
                },
                comment: Some("  # comment")
            }
        );

        assert_eq!(
            Line::parse("# comment").unwrap(),
            Line::Comment("# comment")
        );

        assert_eq!(
            Line::parse("# comment  ").unwrap(), // trailing spaces should be ignored
            Line::Comment("# comment")
        );

        assert_eq!(
            Line::parse("  # comment").unwrap(), // leading spaces should be preserved
            Line::Comment("  # comment")
        );

        assert_eq!(Line::parse("").unwrap(), Line::Eof);

        assert_eq!(Line::parse(" ").unwrap(), Line::Empty);
    }

    #[test]
    fn test_fmt() {
        let input = indoc! {r#"
        # comment 1

        # comment 2
        "#};

        let output = indoc! {r#"
        # comment 1

        # comment 2
        "#};

        let lines = Lines::parse(input).unwrap();

        assert_eq!(lines.to_string(), output);
    }
}
