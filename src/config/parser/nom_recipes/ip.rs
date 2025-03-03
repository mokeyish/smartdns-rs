use std::net::IpAddr;

use super::{ipv4, ipv6};
use nom::{IResult, Parser, branch::alt, combinator::map};

pub fn ip(input: &str) -> IResult<&str, IpAddr> {
    alt((map(ipv4, IpAddr::from), map(ipv6, IpAddr::from))).parse(input)
}
