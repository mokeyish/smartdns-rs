use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// https://en.wikipedia.org/wiki/.arpa
pub trait IpAddrToArpa {
    fn to_arpa(&self) -> String;
}

impl IpAddrToArpa for Ipv4Addr {
    fn to_arpa(&self) -> String {
        let [a, b, c, d] = self.octets();
        format!("{}.{}.{}.{}.in-addr.arpa", d, c, b, a)
    }
}

impl IpAddrToArpa for Ipv6Addr {
    fn to_arpa(&self) -> String {
        let mut arpa = self
            .octets()
            .into_iter()
            .map(|x| format!("{:02x}", x))
            .collect::<String>()
            .chars()
            .rev()
            .fold(String::new(), |mut v, i| {
                v.push(i);
                v.push('.');
                v
            });

        arpa.push_str("ip6.arpa");

        arpa
    }
}

impl IpAddrToArpa for IpAddr {
    fn to_arpa(&self) -> String {
        match self {
            IpAddr::V4(v) => v.to_arpa(),
            IpAddr::V6(v) => v.to_arpa(),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_to_arpa_ipv4() {
        assert_eq!(
            Ipv4Addr::from_str("127.0.0.1").unwrap().to_arpa(),
            "1.0.0.127.in-addr.arpa"
        );
    }

    #[test]
    fn test_to_arpa_ipv6() {
        assert_eq!(
            Ipv6Addr::from_str("ad67:f72c:be6f:eb85:a992:8fa1:0571:fbae")
                .unwrap()
                .to_arpa(),
            "e.a.b.f.1.7.5.0.1.a.f.8.2.9.9.a.5.8.b.e.f.6.e.b.c.2.7.f.7.6.d.a.ip6.arpa"
        );
    }

    #[test]
    fn test_to_arpa() {
        // https://www.whatsmydns.net/reverse-dns-generator
        assert_eq!(
            IpAddr::from_str("2002:7f00:1::").unwrap().to_arpa(),
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.f.7.2.0.0.2.ip6.arpa"
        );
        assert_eq!(
            IpAddr::from_str("192.168.1.2").unwrap().to_arpa(),
            "2.1.168.192.in-addr.arpa"
        );
    }
}
