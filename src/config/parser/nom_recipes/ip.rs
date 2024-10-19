use std::net::IpAddr;

use super::{ipv4, ipv6};
use nom::{branch::alt, combinator::map, IResult};

pub fn ip(input: &str) -> IResult<&str, IpAddr> {
    alt((map(ipv4, IpAddr::from), map(ipv6, IpAddr::from)))(input)
}
