use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use std::io::BufRead;

use crate::collections::DomainMap;
use crate::dns::{Name, RData};
use crate::libdns::proto::rr::RecordType;
use chrono::{DateTime, Local, NaiveDateTime};

pub struct LanClientStore {
    zone: Option<Name>,
    file: PathBuf,
}

impl LanClientStore {
    pub fn new<P: AsRef<Path>>(file: P, zone: Option<Name>) -> Self {
        Self {
            zone,
            file: file.as_ref().to_owned(),
        }
    }

    pub fn lookup(&self, name: &Name, record_type: RecordType) -> Option<RData> {
        match record_type {
            RecordType::A | RecordType::AAAA => {
                let store = match read_lease_file(self.file.as_path(), self.zone.as_ref()) {
                    Ok(v) => v,
                    Err(_) => return None,
                };

                let mut name = name.clone();

                if !name.is_fqdn() {
                    // try add zone
                    if let Some(zone) = self.zone.as_ref() {
                        if let Ok(n) = name.clone().append_name(zone) {
                            name = n;
                        }
                    }
                    name.set_fqdn(true);
                }

                if let Some(client_info) = store.find(&name).or_else(|| match self.zone.as_ref() {
                    Some(z) if !z.zone_of(&name) => {
                        if let Ok(n) = name.append_domain(z) {
                            name = n;
                            store.find(&name)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }) {
                    match client_info.ip {
                        IpAddr::V4(v) if record_type == RecordType::A => Some(RData::A(v.into())),
                        IpAddr::V6(v) if record_type == RecordType::AAAA => {
                            Some(RData::AAAA(v.into()))
                        }
                        _ => Default::default(),
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ClientInfo {
    id: String,
    ip: IpAddr,
    host: Name,
    mac: String,
    expires_at: NaiveDateTime,
}

impl ClientInfo {
    #[inline]
    fn is_expires(&self) -> bool {
        self.expires_at < Local::now().naive_local()
    }
}

impl FromStr for ClientInfo {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        // skip comments and empty line.
        if matches!(s.chars().next(), Some('#') | None) {
            return Err(());
        }

        let mut parts = s.split(' ').filter(|p| !p.is_empty());

        let timestamp = parts
            .next()
            .map(|timestamp| i64::from_str(timestamp).ok())
            .unwrap_or_default()
            .map(|timestamp| DateTime::from_timestamp(timestamp, 0).map(|s| s.naive_utc()))
            .unwrap_or_default()
            .unwrap_or_else(|| Local::now().naive_local());

        let mac = match parts.next() {
            Some(v) => v.to_string(),
            None => return Err(()),
        };

        let ip = match parts.next().map(IpAddr::from_str) {
            Some(Ok(v)) => v,
            _ => return Err(()),
        };
        let host = match parts.next().map(Name::from_str) {
            Some(Ok(v)) => v,
            _ => return Err(()),
        };
        let id = match parts.next() {
            Some(v) => v.to_string(),
            None => return Err(()),
        };

        Ok(Self {
            id,
            ip,
            host,
            mac,
            expires_at: timestamp,
        })
    }
}

fn read_lease_file<P: AsRef<Path>>(
    path: P,
    zone: Option<&Name>,
) -> std::io::Result<DomainMap<ClientInfo>> {
    let file = File::open(path.as_ref())?;

    let reader = BufReader::new(file);

    let mut map = HashMap::new();

    // let mut keys = vec![];
    // let mut values = vec![];

    for line in reader.lines() {
        let line = match line {
            Ok(v) => v,
            Err(_) => continue,
        };

        let line = line.trim_start();

        // skip comments and empty line.
        if matches!(line.chars().next(), Some('#') | None) {
            continue;
        }

        if let Ok(mut client_info) = ClientInfo::from_str(line) {
            if let Some(z) = zone {
                if let Ok(host) = client_info.host.clone().append_name(z) {
                    client_info.host = host;
                }
            }
            client_info.host.set_fqdn(true);
            map.insert(client_info.host.clone(), client_info);
        }
    }

    Ok(map.into())
}

#[cfg(test)]
mod tests {
    use crate::libdns::resolver::TryParseIp;

    use super::*;

    #[test]
    fn parse_client_info() {
        let client_info = ClientInfo::from_str(
            "1702763919 c5:65:92:0b:b5:72 192.168.100.16 Andy-PC 01:c5:65:92:0b:b5:72",
        )
        .unwrap();

        assert_eq!(client_info.expires_at.and_utc().timestamp(), 1702763919);
        assert_eq!(client_info.host, Name::from_str("andy-pc").unwrap());
        assert_eq!(client_info.ip, "192.168.100.16".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_read_dnsmasq_lease_file() {
        let host_ips = read_lease_file("tests/test_confs/dhcp.leases", None).unwrap();
        assert_eq!(
            host_ips
                .find(&Name::from_str("Andy-PC").unwrap())
                .map(|x| x.ip),
            Some("192.168.100.16".parse::<IpAddr>().unwrap())
        );

        assert_eq!(
            host_ips
                .find(&Name::from_str("andy-pc").unwrap())
                .map(|x| x.ip),
            Some("192.168.100.16".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            host_ips
                .find(&Name::from_str("iphone-abc").unwrap())
                .map(|x| x.ip),
            Some(
                "2402:4e00:1013:e500:0:9671:f018:4947"
                    .parse::<IpAddr>()
                    .unwrap()
            )
        );
    }

    #[test]
    fn test_lan_client_store_lookup() {
        let store = LanClientStore::new("tests/test_confs/dhcp.leases", Default::default());

        assert_eq!(
            store.lookup(&"iphone-abc".parse().unwrap(), RecordType::AAAA),
            "2402:4e00:1013:e500:0:9671:f018:4947".try_parse_ip()
        );

        assert_eq!(
            store.lookup(&"iphone-abc".parse().unwrap(), RecordType::A),
            None
        );
    }

    #[test]
    fn test_lan_client_store_lookup_fqdn() {
        let store = LanClientStore::new("tests/test_confs/dhcp.leases", Default::default());

        assert_eq!(
            store.lookup(&"iphone-abc.".parse().unwrap(), RecordType::AAAA),
            "2402:4e00:1013:e500:0:9671:f018:4947".try_parse_ip()
        );

        assert_eq!(
            store.lookup(&"iphone-abc.".parse().unwrap(), RecordType::A),
            None
        );
    }

    #[test]
    fn test_lan_client_store_lookup_zone() {
        let store = LanClientStore::new("tests/test_confs/dhcp.leases", Name::from_str("xyz").ok());

        assert_eq!(
            store.lookup(&"iphone-abc.xyz.".parse().unwrap(), RecordType::AAAA),
            "2402:4e00:1013:e500:0:9671:f018:4947".try_parse_ip()
        );

        assert_eq!(
            store.lookup(&"iphone-abc.xyz.".parse().unwrap(), RecordType::A),
            None
        );
    }
}
