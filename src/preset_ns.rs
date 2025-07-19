#![allow(unused_imports)]

use crate::libdns::resolver::config::ServerGroup;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// IP addresses for Cloudflare's 1.1.1.1 DNS service
/// Please see: https://cloudflare-dns.com/
pub use crate::libdns::resolver::config::CLOUDFLARE;

/// IP addresses for Google Public DNS
/// Please see: https://dns.google/
pub use crate::libdns::resolver::config::GOOGLE;

/// IP address for the Quad9 DNS service
/// Please see: https://www.quad9.net/
pub use crate::libdns::resolver::config::QUAD9;

/// IP address for the Ali DNS service
/// Please see: https://www.alidns.com/
pub const ALIDNS: ServerGroup<'static> = ServerGroup {
    ips: &[
        IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
        IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
        IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 0x0001)),
        IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 0x0001)),
    ],
    server_name: "dns.alidns.com",
    path: "/dns-query",
};

/// IP address for the DNSPod Public DNS service
/// Please see: https://www.dnspod.cn/Products/publicdns
pub const DNSPOD: ServerGroup<'static> = ServerGroup {
    ips: &[
        IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)),
        IpAddr::V6(Ipv6Addr::new(0x2402, 0x4e00, 0, 0, 0, 0, 0, 0)),
    ],
    server_name: "doh.pub",
    path: "/dns-query",
};
