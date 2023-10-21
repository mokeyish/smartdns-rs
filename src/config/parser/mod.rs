use nom::{
    branch::*, bytes::complete::*, character::complete::*, combinator::*, multi::*, sequence::*,
    IResult,
};

mod bool;
mod config_item;
mod domain;
mod domain_config_item;
mod ip_config_ntset;
mod listener;
mod nftset;
mod options;

use super::*;

pub trait NomParser: Sized {
    fn parse(input: &str) -> IResult<&str, Self>;

    fn from_str(s: &str) -> Result<Self, nom::Err<nom::error::Error<&str>>> {
        match Self::parse(s) {
            Ok((_, v)) => Ok(v),
            Err(err) => Err(err),
        }
    }
}
