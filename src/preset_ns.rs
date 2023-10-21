use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// IP addresses for Cloudflare's 1.1.1.1 DNS service
/// Please see: https://cloudflare-dns.com/
pub use crate::libdns::resolver::config::CLOUDFLARE_IPS;
pub const CLOUDFLARE: &str = "cloudflare-dns.com";

/// IP addresses for Google Public DNS
/// Please see: https://dns.google/
pub use crate::libdns::resolver::config::GOOGLE_IPS;
pub const GOOGLE: &str = "dns.google";

/// IP address for the Quad9 DNS service
/// Please see: https://www.quad9.net/
pub use crate::libdns::resolver::config::QUAD9_IPS;
pub const QUAD9: &str = "dns.quad9.net";

/// IP address for the Ali DNS service
/// Please see: https://www.alidns.com/
pub const ALIDNS_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
    IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x0001)),
    IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x0001)),
];
pub const ALIDNS: &str = "dns.alidns.com";

/// IP address for the DNSPod Public DNS service
/// Please see: https://www.dnspod.cn/Products/publicdns
pub const DNSPOD_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
    IpAddr::V6(Ipv6Addr::new(0x2402, 0x4e00, 0, 0, 0, 0, 0, 0)),
];
