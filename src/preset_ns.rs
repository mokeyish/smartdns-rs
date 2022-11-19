use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// IP addresses for Cloudflare's 1.1.1.1 DNS service
/// Please see: https://cloudflare-dns.com/
use trust_dns_resolver::config::CLOUDFLARE_IPS;
pub const CLOUDFLARE: &'static str = "cloudflare-dns.com";

/// IP addresses for Google Public DNS
/// Please see: https://dns.google/
use trust_dns_resolver::config::GOOGLE_IPS;
pub const GOOGLE: &'static str = "dns.google";

/// IP address for the Quad9 DNS service
/// Please see: https://www.quad9.net/
use trust_dns_resolver::config::QUAD9_IPS;
pub const QUAD9: &'static str = "dns.quad9.net";

/// IP address for the Ali DNS service
/// Please see: https://www.alidns.com/
const ALIDNS_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
    IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x0001)),
    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x0001)),
];
pub const ALIDNS: &'static str = "dns.alidns.com";

/// IP address for the DNSPod Public DNS service
/// Please see: https://www.dnspod.cn/Products/publicdns
const DNSPOD_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
    IpAddr::V6(Ipv6Addr::new(0x2402, 0x4e00, 0, 0, 0, 0, 0, 0)),
];

trait GetDnsHostName {
    fn get_host_name(self) -> Option<&'static str>;
}

impl GetDnsHostName for &[IpAddr] {
    fn get_host_name(self) -> Option<&'static str> {
        Some(match self {
            CLOUDFLARE_IPS => CLOUDFLARE,
            GOOGLE_IPS => GOOGLE,
            QUAD9_IPS => QUAD9,
            ALIDNS_IPS => ALIDNS,
            _ => return None,
        })
    }
}

pub fn find_dns_tls_name(ip: &IpAddr) -> Option<&'static str> {
    if CLOUDFLARE_IPS.contains(ip) {
        return CLOUDFLARE_IPS.get_host_name();
    }

    if GOOGLE_IPS.contains(ip) {
        return GOOGLE_IPS.get_host_name();
    }

    if QUAD9_IPS.contains(ip) {
        return QUAD9_IPS.get_host_name();
    }

    if ALIDNS_IPS.contains(ip) {
        return ALIDNS_IPS.get_host_name();
    }
    None
}

pub fn find_dns_ips(host: &str) -> Option<&'static [IpAddr]> {
    Some(match host {
        "cloudflare-dns.com" => CLOUDFLARE_IPS,
        "dns.google" => GOOGLE_IPS,
        "dns.quad9.net" => QUAD9_IPS,
        "dns.alidns.com" => ALIDNS_IPS,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_get_preset_dns_hostname() {
        assert_eq!(find_dns_ips("dns.google").unwrap(), GOOGLE_IPS);
    }
}
