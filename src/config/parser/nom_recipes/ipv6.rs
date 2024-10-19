use std::net::Ipv6Addr;

use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{char, hex_digit1},
    combinator::{map, map_res, opt, recognize, verify},
    error::context,
    multi::{many_m_n, separated_list0},
    sequence::{pair, preceded},
    IResult,
};

use super::ipv4;

pub fn ipv6(input: &str) -> IResult<&str, Ipv6Addr> {
    fn octal(input: &str) -> IResult<&str, u16> {
        map_res(recognize(many_m_n(1, 4, hex_digit1)), |s| {
            u16::from_str_radix(s, 16)
        })(input)
    }

    context(
        "Ipv6Addr",
        alt((
            map(preceded(tag("::ffff:"), ipv4), |ip| ip.to_ipv6_mapped()),
            map(
                verify(
                    pair(
                        separated_list0(char(':'), octal),
                        map(
                            opt(preceded(tag("::"), separated_list0(char(':'), octal))),
                            |v| v.unwrap_or_default(),
                        ),
                    ),
                    |(pre, post)| pre.len() == 8 || pre.len() + post.len() < 8,
                ),
                |(pre, post)| {
                    let mut octets = [0u16; 8];
                    for (i, octet) in pre.iter().enumerate() {
                        octets[i] = *octet;
                    }
                    if !post.is_empty() {
                        let n = 8 - post.len();
                        for (i, octet) in post.iter().enumerate() {
                            octets[i + n] = *octet;
                        }
                    }
                    Ipv6Addr::new(
                        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                        octets[6], octets[7],
                    )
                },
            ),
        )),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6() {
        assert_eq!(ipv6("::1"), Ok(("", Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
        assert_eq!(ipv6("::"), Ok(("", Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))));
        assert_eq!(
            ipv6("::ffff:0:0"),
            Ok(("", Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0)))
        );
        assert_eq!(
            ipv6("::ffff:1.2.3.4"),
            Ok(("", Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304)))
        );
        assert_eq!(
            ipv6("::ffff:192:0:2:128"),
            Ok(("", Ipv6Addr::new(0, 0, 0, 0xffff, 0x192, 0x0, 0x2, 0x128)))
        );
        assert_eq!(
            ipv6("2001:db8::1"),
            Ok(("", Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(
            ipv6("2001:db8:0:0:0:0:2:1"),
            Ok(("", Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0x2, 0x1)))
        );
        assert_eq!(
            ipv6("2001:db8:0:0:0:0:2:1"),
            Ok(("", Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0x2, 0x1)))
        );
    }
}
