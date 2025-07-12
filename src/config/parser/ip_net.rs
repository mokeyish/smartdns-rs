use std::net::IpAddr;

use super::*;

impl NomParser for IpNet {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(
            map(
                pair(
                    nom_recipes::ip,
                    opt(preceded(
                        char('/'),
                        map_res(digit1, |s: &str| s.parse::<u8>()),
                    )),
                ),
                |(ip, len)| {
                    (
                        ip,
                        len.unwrap_or(match ip {
                            IpAddr::V4(_) => 32,
                            IpAddr::V6(_) => 128,
                        }),
                    )
                },
            ),
            |(ip, len)| IpNet::new(ip, len),
        )
        .parse(input)
    }
}

impl NomParser for Ipv6Net {
    fn parse(input: &str) -> IResult<&str, Self> {
        map_res(
            (
                nom_recipes::ipv6,
                preceded(tag("/"), map_res(digit1, |s: &str| s.parse::<u8>())),
            ),
            |(ip, len)| Ipv6Net::new(ip, len),
        )
        .parse(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            IpNet::parse("1.2.3.4/16"),
            Ok(("", "1.2.3.4/16".parse().unwrap()))
        )
    }

    #[test]
    fn test_parse2() {
        assert_eq!(
            IpNet::parse("1.2.3.4"),
            Ok(("", "1.2.3.4/32".parse().unwrap()))
        )
    }
}
