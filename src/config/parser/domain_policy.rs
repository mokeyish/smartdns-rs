use super::*;
use std::str::FromStr;

impl NomParser for DomainAddress {
    fn parse(input: &str) -> IResult<&str, Self> {
        use DomainAddress::*;

        let soa = value(SOA, char('#'));
        let soa_v4 = value(SOAv4, tag("#4"));
        let soa_v6 = value(SOAv6, tag("#6"));
        let ign = value(IGN, tag("-"));
        let ign_v4 = value(IGNv4, tag("-4"));
        let ign_v6 = value(IGNv6, tag("-6"));
        let ipv4 = map(map_res(is_a("0123456789."), Ipv4Addr::from_str), IPv4);
        let ipv6 = map(map_res(is_a("0123456789abcdef:"), Ipv6Addr::from_str), IPv6);

        alt((soa_v4, soa_v6, soa, ign_v4, ign_v6, ign, ipv4, ipv6))(input)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test() {
        use DomainAddress::*;
        assert_eq!(DomainAddress::parse("#"), Ok(("", SOA)));
        assert_eq!(DomainAddress::parse("#4"), Ok(("", SOAv4)));
        assert_eq!(DomainAddress::parse("#6"), Ok(("", SOAv6)));
        assert_eq!(DomainAddress::parse("-"), Ok(("", IGN)));
        assert_eq!(DomainAddress::parse("-4"), Ok(("", IGNv4)));
        assert_eq!(DomainAddress::parse("-6"), Ok(("", IGNv6)));

        assert_eq!(
            DomainAddress::parse("127.0.0.1"),
            Ok(("", IPv4("127.0.0.1".parse().unwrap())))
        );
        assert_eq!(
            DomainAddress::parse("::1"),
            Ok(("", IPv6("::1".parse().unwrap())))
        );
    }
}
