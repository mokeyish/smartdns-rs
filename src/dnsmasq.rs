use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use std::io::BufRead;

use crate::collections::DomainMap;
use crate::libdns::proto::rr::{Name, RData};
use crate::libdns::proto::rr::{RecordType, rdata::PTR};
use chrono::{DateTime, Local, NaiveDateTime};

pub struct LanClientStore {
    zone: Option<Name>,
    file: PathBuf,
    cache: RwLock<Option<LeaseCache>>,
}

pub struct LeaseMappings {
    pub name_to_client: DomainMap<Arc<ClientInfo>>,
    pub ip_to_client: HashMap<IpAddr, Arc<ClientInfo>>,
}

impl LeaseMappings {
    pub fn find(&self, name: &Name) -> Option<&ClientInfo> {
        self.name_to_client.find(name).map(Arc::as_ref)
    }
}

struct LeaseCache {
    clients: Arc<DomainMap<Arc<ClientInfo>>>,
    ip_clients: Arc<HashMap<IpAddr, Arc<ClientInfo>>>,
    modified_at: Option<SystemTime>,
    checked_at: Instant,
}

const LEASE_FILE_STAT_INTERVAL: Duration = Duration::from_secs(2);

impl LanClientStore {
    pub fn new<P: AsRef<Path>>(file: P, zone: Option<Name>) -> Self {
        Self {
            zone,
            file: file.as_ref().to_owned(),
            cache: Default::default(),
        }
    }

    fn cached_clients(&self) -> Option<Arc<DomainMap<Arc<ClientInfo>>>> {
        let now = Instant::now();

        {
            let cache = self.cache.read().unwrap_or_else(|err| err.into_inner());
            if let Some(cache) = cache.as_ref()
                && now.duration_since(cache.checked_at) < LEASE_FILE_STAT_INTERVAL
            {
                return Some(cache.clients.clone());
            }
        }

        let modified_at = std::fs::metadata(self.file.as_path())
            .ok()
            .and_then(|meta| meta.modified().ok());

        {
            let mut cache = self.cache.write().unwrap_or_else(|err| err.into_inner());
            if let Some(cache) = cache.as_mut() {
                if now.duration_since(cache.checked_at) < LEASE_FILE_STAT_INTERVAL {
                    return Some(cache.clients.clone());
                }

                if cache.modified_at == modified_at {
                    cache.checked_at = now;
                    return Some(cache.clients.clone());
                }
            }
        }

        let refreshed = read_lease_file(self.file.as_path(), self.zone.as_ref()).ok();

        let mut cache = self.cache.write().unwrap_or_else(|err| err.into_inner());
        if let Some(lease_mappings) = refreshed {
            *cache = Some(LeaseCache {
                clients: Arc::new(lease_mappings.name_to_client),
                ip_clients: Arc::new(lease_mappings.ip_to_client),
                modified_at,
                checked_at: now,
            });
            Some(cache.as_ref().unwrap().clients.clone())
        } else if let Some(cache) = cache.as_mut() {
            // read failed, keep existing cache and avoid hot-loop retries.
            cache.checked_at = now;
            Some(cache.clients.clone())
        } else {
            None
        }
    }

    pub fn lookup(&self, name: &Name, record_type: RecordType) -> Option<RData> {
        match record_type {
            RecordType::A | RecordType::AAAA => {
                let store = self.cached_clients()?;

                let mut name = name.clone();

                if !name.is_fqdn() {
                    // try add zone
                    if let Some(zone) = self.zone.as_ref()
                        && let Ok(n) = name.clone().append_name(zone)
                    {
                        name = n;
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

    pub fn reverse_lookup(&self, ip: &IpAddr) -> Option<RData> {
        let cache = self.cache.read().unwrap_or_else(|err| err.into_inner());
        if let Some(lease_cache) = cache.as_ref()
            && let Some(client_info) = lease_cache.ip_clients.get(ip)
        {
            // Skip placeholder hostnames like "*"
            if client_info.host.to_string() != "*" {
                return Some(RData::PTR(PTR(client_info.host.clone())));
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
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

    /// Get the hostname
    #[inline]
    pub fn host(&self) -> &Name {
        &self.host
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
            Some(Ok(v)) => {
                // Validate hostname is not empty and is a valid FQDN
                let hostname_str = v.to_string();
                if hostname_str.is_empty() {
                    return Err(());
                }
                v
            }
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

fn read_lease_file<P: AsRef<Path>>(path: P, zone: Option<&Name>) -> std::io::Result<LeaseMappings> {
    let file = File::open(path.as_ref())?;

    let reader = BufReader::new(file);

    let mut name_map = HashMap::new();
    let mut ip_map = HashMap::new();

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
            if let Some(z) = zone
                && let Ok(host) = client_info.host.clone().append_name(z)
            {
                client_info.host = host;
            }
            client_info.host.set_fqdn(true);
            let client_info = Arc::new(client_info);
            name_map.insert(client_info.host.clone().into(), client_info.clone());
            ip_map.insert(client_info.ip, client_info);
        }
    }

    Ok(LeaseMappings {
        name_to_client: name_map.into(),
        ip_to_client: ip_map,
    })
}

/// Convert a PTR query name to an IP address.
/// PTR queries are in the format:
/// - IPv4: x.x.x.x.in-addr.arpa.
/// - IPv6: x.x.x.x...ip6.arpa. (reversed hex digits)
pub fn ptr_to_ip(name: &Name) -> Result<IpAddr, std::net::AddrParseError> {
    // Use hickory-proto's built-in parse_arpa_name()
    // Returns Result<ArpaNet, _> which has addr() method
    match name.parse_arpa_name() {
        Ok(arpa_net) => Ok(arpa_net.addr()),
        Err(_) => "invalid arpa name".parse(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libdns::resolver::IntoName;

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
        let host_ips = read_lease_file("tests/test_data/dhcp.leases", None).unwrap();
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
        let store = LanClientStore::new("tests/test_data/dhcp.leases", Default::default());

        assert_eq!(
            store.lookup(&"iphone-abc".parse().unwrap(), RecordType::AAAA),
            "2402:4e00:1013:e500:0:9671:f018:4947"
                .to_ip()
                .map(|s| s.into())
        );

        assert_eq!(
            store.lookup(&"iphone-abc".parse().unwrap(), RecordType::A),
            None
        );
    }

    #[test]
    fn test_lan_client_store_lookup_fqdn() {
        let store = LanClientStore::new("tests/test_data/dhcp.leases", Default::default());

        assert_eq!(
            store.lookup(&"iphone-abc.".parse().unwrap(), RecordType::AAAA),
            "2402:4e00:1013:e500:0:9671:f018:4947"
                .to_ip()
                .map(|s| s.into())
        );

        assert_eq!(
            store.lookup(&"iphone-abc.".parse().unwrap(), RecordType::A),
            None
        );
    }

    #[test]
    fn test_lan_client_store_lookup_zone() {
        let store = LanClientStore::new("tests/test_data/dhcp.leases", Name::from_str("xyz").ok());

        assert_eq!(
            store.lookup(&"iphone-abc.xyz.".parse().unwrap(), RecordType::AAAA),
            "2402:4e00:1013:e500:0:9671:f018:4947"
                .to_ip()
                .map(|s| s.into())
        );

        assert_eq!(
            store.lookup(&"iphone-abc.xyz.".parse().unwrap(), RecordType::A),
            None
        );
    }

    #[test]
    fn test_lan_client_store_reverse_lookup() {
        let store = LanClientStore::new("tests/test_data/dhcp.leases", Default::default());

        // First trigger cache initialization by doing a lookup
        let _ = store.lookup(&"Andy-PC".parse().unwrap(), RecordType::A);

        // Test IPv4 reverse lookup
        let ipv4 = "192.168.100.16".parse::<IpAddr>().unwrap();
        let rdata = store.reverse_lookup(&ipv4);
        assert!(rdata.is_some());

        // Test IPv6 reverse lookup
        let ipv6 = "2402:4e00:1013:e500:0:9671:f018:4947"
            .parse::<IpAddr>()
            .unwrap();
        let rdata = store.reverse_lookup(&ipv6);
        assert!(rdata.is_some());

        // Test IP not in lease file
        let ip_unknown = "10.0.0.1".parse::<IpAddr>().unwrap();
        let rdata = store.reverse_lookup(&ip_unknown);
        assert!(rdata.is_none());
    }

    #[test]
    fn test_ptr_to_ip_ipv4() {
        let name = Name::from_str("1.0.0.127.in-addr.arpa.").unwrap();
        let ip = ptr_to_ip(&name).unwrap();
        assert_eq!(ip, IpAddr::from_str("127.0.0.1").unwrap());

        let name = Name::from_str("16.100.168.192.in-addr.arpa.").unwrap();
        let ip = ptr_to_ip(&name).unwrap();
        assert_eq!(ip, IpAddr::from_str("192.168.100.16").unwrap());
    }

    #[test]
    fn test_ptr_to_ip_ipv6() {
        let name = Name::from_str(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        )
        .unwrap();
        let ip = ptr_to_ip(&name).unwrap();
        assert_eq!(ip, IpAddr::from_str("::1").unwrap());

        let name = Name::from_str(
            "7.4.9.4.8.1.0.f.1.7.6.9.0.0.0.0.0.0.5.e.3.1.0.1.0.0.e.4.2.0.4.2.ip6.arpa.",
        )
        .unwrap();
        let ip = ptr_to_ip(&name).unwrap();
        assert_eq!(
            ip,
            IpAddr::from_str("2402:4e00:1013:e500:0:9671:f018:4947").unwrap()
        );
    }

    #[test]
    fn test_ptr_to_ip_invalid() {
        let name = Name::from_str("invalid.name.test.").unwrap();
        let ip = ptr_to_ip(&name);
        assert!(ip.is_err());
    }

    #[test]
    fn test_client_info_hostname_validation() {
        // Test that ClientInfo validates hostname format
        let valid_line = "1702763919 c5:65:92:0b:b5:72 192.168.100.16 Andy-PC 01:c5:65:92:0b:b5:72";
        let result: Result<ClientInfo, ()> = valid_line.parse();
        assert!(result.is_ok(), "Valid line should parse successfully");
        let client_info = result.unwrap();
        assert!(!client_info.host().to_string().is_empty());
    }

    #[test]
    fn test_reverse_lookup_hostname_validation() {
        let store = LanClientStore::new("tests/test_data/dhcp.leases", Default::default());

        // Trigger cache initialization
        let _ = store.lookup(&"Andy-PC".parse().unwrap(), RecordType::A);

        // Test that valid hostname is returned correctly
        let ipv4 = "192.168.100.16".parse::<IpAddr>().unwrap();
        let rdata = store.reverse_lookup(&ipv4);
        assert!(rdata.is_some(), "Valid hostname should be returned");
        if let Some(RData::PTR(ptr)) = rdata {
            // Verify the hostname matches what's in the lease file
            assert_eq!(
                ptr.0.to_string(),
                "andy-pc.",
                "Hostname should match lease file (case-insensitive)"
            );
        }

        // Test IPv6 reverse lookup
        let ipv6 = "2402:4e00:1013:e500:0:9671:f018:4947"
            .parse::<IpAddr>()
            .unwrap();
        let rdata = store.reverse_lookup(&ipv6);
        assert!(rdata.is_some(), "IPv6 hostname should be returned");
        if let Some(RData::PTR(ptr)) = rdata {
            assert_eq!(
                ptr.0.to_string(),
                "iphone-abc.",
                "IPv6 hostname should match lease file"
            );
        }

        // Test that IP not in lease file returns None
        let ip_unknown = "10.0.0.1".parse::<IpAddr>().unwrap();
        let rdata = store.reverse_lookup(&ip_unknown);
        assert!(rdata.is_none(), "Unknown IP should return None");
    }
}
