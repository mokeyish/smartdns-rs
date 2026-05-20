use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Result, bail};
use ipnet::IpNet;
use prost::Message;

use super::WildcardName;

#[derive(Clone, PartialEq, Message)]
pub struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(message, repeated, tag = "3")]
    pub attribute: Vec<DomainAttribute>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DomainAttribute {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(bool, optional, tag = "2")]
    pub bool_value: Option<bool>,
    #[prost(int64, optional, tag = "3")]
    pub int_value: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    Plain = 0,
    Regex = 1,
    Domain = 2,
    Full = 3,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoSite>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoIp {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub reverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIp>,
}

pub fn load_geosite(path: &Path, tag: &str) -> Result<HashSet<WildcardName>> {
    let data = std::fs::read(path)?;
    let list = GeoSiteList::decode(data.as_slice())?;

    let site = list
        .entry
        .iter()
        .find(|e| e.country_code.eq_ignore_ascii_case(tag))
        .ok_or_else(|| anyhow::anyhow!("geosite tag '{}' not found in {:?}", tag, path))?;

    let mut set = HashSet::new();
    for d in &site.domain {
        let name_str = &d.value;
        if name_str.is_empty() {
            continue;
        }
        match DomainType::try_from(d.r#type) {
            Ok(DomainType::Domain) => {
                if let Ok(n) = name_str.parse() {
                    set.insert(WildcardName::Default(n));
                }
            }
            Ok(DomainType::Full) => {
                if let Ok(n) = name_str.parse() {
                    set.insert(WildcardName::Full(n));
                }
            }
            // Plain (keyword) and Regex are not supported by smartdns matching model
            _ => {}
        }
    }
    Ok(set)
}

pub fn load_geoip(path: &Path, tag: &str) -> Result<Vec<IpNet>> {
    let data = std::fs::read(path)?;
    let list = GeoIpList::decode(data.as_slice())?;

    let entry = list
        .entry
        .iter()
        .find(|e| e.country_code.eq_ignore_ascii_case(tag))
        .ok_or_else(|| anyhow::anyhow!("geoip tag '{}' not found in {:?}", tag, path))?;

    let mut nets = Vec::with_capacity(entry.cidr.len());
    for c in &entry.cidr {
        let addr = match c.ip.len() {
            4 => {
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&c.ip);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&c.ip);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => bail!("invalid IP length {} in geoip entry", c.ip.len()),
        };
        if let Ok(net) = IpNet::new(addr, c.prefix as u8) {
            nets.push(net);
        }
    }
    Ok(nets)
}

pub fn load_mmdb(path: &Path, tag: &str) -> Result<Vec<IpNet>> {
    let reader = maxminddb::Reader::open_readfile(path)?;
    let mut nets = Vec::new();

    let collect = |nets: &mut Vec<IpNet>, cidr: ipnetwork::IpNetwork| {
        let iter = reader
            .within::<maxminddb::geoip2::Country>(cidr)
            .into_iter()
            .flatten()
            .flatten();
        for item in iter {
            let matches = item
                .info
                .country
                .as_ref()
                .and_then(|c| c.iso_code)
                .is_some_and(|code| code.eq_ignore_ascii_case(tag));
            if matches && let Ok(net) = IpNet::new(item.ip_net.ip(), item.ip_net.prefix()) {
                nets.push(net);
            }
        }
    };

    if let Ok(v4) = "0.0.0.0/0".parse() {
        collect(&mut nets, v4);
    }
    if let Ok(v6) = "::/0".parse() {
        collect(&mut nets, v6);
    }

    if nets.is_empty() {
        bail!("mmdb country '{}' not found or empty in {:?}", tag, path);
    }
    Ok(nets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_data_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_data")
    }

    #[test]
    fn test_load_geosite_cn() {
        let path = test_data_dir().join("geosite.dat");
        if !path.exists() {
            return;
        }
        let set = load_geosite(&path, "cn").unwrap();
        assert!(!set.is_empty(), "cn geosite should not be empty");
        assert!(
            set.len() > 1000,
            "cn geosite should have many entries, got {}",
            set.len()
        );
    }

    #[test]
    fn test_load_geosite_not_found() {
        let path = test_data_dir().join("geosite.dat");
        if !path.exists() {
            return;
        }
        let result = load_geosite(&path, "nonexistent_tag_xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_geoip_cn() {
        let path = test_data_dir().join("geoip.dat");
        if !path.exists() {
            return;
        }
        let nets = load_geoip(&path, "cn").unwrap();
        assert!(!nets.is_empty(), "cn geoip should not be empty");
        assert!(
            nets.len() > 100,
            "cn geoip should have many entries, got {}",
            nets.len()
        );
    }

    #[test]
    fn test_load_geoip_not_found() {
        let path = test_data_dir().join("geoip.dat");
        if !path.exists() {
            return;
        }
        let result = load_geoip(&path, "nonexistent_tag_xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_mmdb_cn() {
        let path = test_data_dir().join("country.mmdb");
        if !path.exists() {
            return;
        }
        let nets = load_mmdb(&path, "CN").unwrap();
        assert!(!nets.is_empty(), "CN mmdb should not be empty");
        assert!(
            nets.len() > 100,
            "CN mmdb should have many entries, got {}",
            nets.len()
        );
    }

    #[test]
    fn test_load_mmdb_not_found() {
        let path = test_data_dir().join("country.mmdb");
        if !path.exists() {
            return;
        }
        let result = load_mmdb(&path, "ZZ");
        assert!(result.is_err());
    }
}
