use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use cfg_if::cfg_if;
use trust_dns_client::rr::{domain, LowerName};
use trust_dns_resolver::Name;

use crate::dns_url::DnsUrl;
use crate::log::{error, info, warn};

#[derive(Debug, Default, Clone)]
pub struct SmartDnsConfig {
    pub server_name: Name,
    pub user: Option<String>,
    pub audit_enable: bool,
    pub audit_file: Option<PathBuf>,
    pub log_level: Option<String>,
    pub binds: Vec<BindServer>,
    pub binds_tcp: Vec<BindServer>,
    pub servers: HashMap<String, Vec<DnsServer>>,
    pub forward_rules: Vec<ForwardRuleItem>,
    pub address_rules: Vec<AddressRuleItem>,
    pub conf_file: Option<PathBuf>,
    pub resolv_file: Option<String>,
    pub prefetch_domain: bool,
    pub cache_size: Option<usize>,
    pub serve_expired: bool,
    pub domain_sets: HashMap<String, HashSet<LowerName>>,
    pub dnsmasq_lease_file: Option<String>,
    pub rr_ttl: Option<u64>,
    pub rr_ttl_min: Option<u64>,
    pub rr_ttl_max: Option<u64>,
    pub speed_check_mode: Vec<SpeedCheckMode>,
}

impl SmartDnsConfig {
    pub fn new() -> Self {
        Self {
            server_name: "SmartDNS".parse().unwrap(),
            servers: HashMap::from([("default".to_string(), Default::default())]),
            ..Default::default()
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref();

        let mut cfg = Self::new();
        cfg.conf_file = Some(path.to_path_buf());
        cfg.load_file(path).expect("load conf file filed");

        if cfg.binds.is_empty() && cfg.binds_tcp.is_empty() {
            cfg.binds.push(BindServer {
                addr: ("0.0.0.0", 53)
                    .to_socket_addrs()
                    .unwrap()
                    .collect::<Vec<_>>(),
                ..Default::default()
            })
        }

        if let Some(ss) = cfg.servers.get("default") {
            for s in ss {
                info!("default server: {}", s.url.to_string());
            }
        }

        cfg
    }
}

/// dns server bind ip and port, default dns server port is 53, support binding multi ip and port
/// bind udp server
///   bind [IP]:[port] [-group [group]] [-no-rule-addr] [-no-rule-nameserver] [-no-rule-ipset] [-no-speed-check] [-no-cache] [-no-rule-soa] [-no-dualstack-selection]
/// bind tcp server
///   bind-tcp [IP]:[port] [-group [group]] [-no-rule-addr] [-no-rule-nameserver] [-no-rule-ipset] [-no-speed-check] [-no-cache] [-no-rule-soa] [-no-dualstack-selection]
/// option:
///   -group: set domain request to use the appropriate server group.
///   -no-rule-addr: skip address rule.
///   -no-rule-nameserver: skip nameserver rule.
///   -no-rule-ipset: skip ipset rule or nftset rule.
///   -no-speed-check: do not check speed.
///   -no-cache: skip cache.
///   -no-rule-soa: Skip address SOA(#) rules.
///   -no-dualstack-selection: Disable dualstack ip selection.
///   -force-aaaa-soa: force AAAA query return SOA.
/// example:
///  IPV4:
///    bind :53
///    bind :6053 -group office -no-speed-check
///  IPV6:
///    bind [::]:53
///    bind-tcp [::]:53
#[derive(Debug, Default, Clone)]
pub struct BindServer {
    /// bind adress
    pub addr: Vec<SocketAddr>,

    /// set domain request to use the appropriate server group.
    pub group: Option<String>,

    /// skip address rule.
    pub no_rule_addr: bool,

    /// skip nameserver rule.
    pub no_rule_nameserver: bool,

    /// skip ipset rule.
    pub no_rule_ipset: bool,

    /// do not check speed.
    pub no_speed_check: bool,

    /// skip cache.
    pub no_cache: bool,

    /// Skip address SOA(#) rules.
    pub no_rule_soa: bool,

    /// Disable dualstack ip selection.
    pub no_dualstack_selection: bool,

    /// force AAAA query return SOA.
    pub force_aaaa_soa: bool,
}

impl FromStr for BindServer {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = parse::split_options(s, ' ');

        let mut addr = None;
        let mut group = None;
        let mut no_rule_addr = false;
        let mut no_rule_nameserver = false;
        let mut no_rule_ipset = false;
        let mut no_speed_check = false;
        let mut no_cache = false;
        let mut no_rule_soa = false;
        let mut no_dualstack_selection = false;
        let mut force_aaaa_soa = false;

        while let Some(part) = parts.next() {
            if part.starts_with('-') {
                match part {
                    "-group" => group = parts.next().map(|p| p.to_string()),
                    "-no-rule-addr" => no_rule_addr = true,
                    "-no-rule-nameserver" => no_rule_nameserver = true,
                    "-no-rule-ipset" => no_rule_ipset = true,
                    "-no-speed-check" => no_speed_check = true,
                    "-no-cache" => no_cache = true,
                    "-no-rule-soa" => no_rule_soa = true,
                    "-no-dualstack-selection" => no_dualstack_selection = true,
                    "-force-aaaa-soa" => force_aaaa_soa = true,
                    opt => warn!("unknown option: {}", opt),
                }
            } else {
                if addr.is_none() {
                    addr = Some(part);
                } else {
                    error!("repeat addr ");
                }
            }
        }

        let sock_addrs = addr
            .map(|addr| parse::parse_sock_addrs(addr).ok())
            .unwrap_or_default()
            .expect(&[s, "addr expect [::]:53 or 0.0.0.0:53"].concat());

        Ok(Self {
            addr: sock_addrs,
            group,
            no_rule_addr,
            no_rule_nameserver,
            no_rule_ipset,
            no_speed_check,
            no_cache,
            no_rule_soa,
            no_dualstack_selection,
            force_aaaa_soa,
        })
    }
}

impl BindServer {
    pub fn has_extra_opts(&self) -> bool {
        self.group.is_some()
            || self.no_rule_addr
            || self.no_rule_nameserver
            || self.no_rule_ipset
            || self.no_speed_check
            || self.no_cache
            || self.no_rule_soa
            || self.no_dualstack_selection
            || self.force_aaaa_soa
    }
}

/// remote udp dns server list
/// server [IP]:[PORT] [-blacklist-ip] [-whitelist-ip] [-check-edns] [-group [group] ...] [-exclude-default-group]
/// default port is 53
///   -blacklist-ip: filter result with blacklist ip
///   -whitelist-ip: filter result whth whitelist ip,  result in whitelist-ip will be accepted.
///   -check-edns: result must exist edns RR, or discard result.
///   -group [group]: set server to group, use with nameserver /domain/group.
///   -exclude-default-group: exclude this server from default group.
/// server 8.8.8.8 -blacklist-ip -check-edns -group g1 -group g2
///
/// remote tcp dns server list
/// server-tcp [IP]:[PORT] [-blacklist-ip] [-whitelist-ip] [-group [group] ...] [-exclude-default-group]
/// default port is 53
/// server-tcp 8.8.8.8
///
/// remote tls dns server list
/// server-tls [IP]:[PORT] [-blacklist-ip] [-whitelist-ip] [-spki-pin [sha256-pin]] [-group [group] ...] [-exclude-default-group]
///   -spki-pin: TLS spki pin to verify.
///   -tls-host-verify: cert hostname to verify.
///   -host-name: TLS sni hostname.
///   -no-check-certificate: no check certificate.
/// Get SPKI with this command:
///    echo | openssl s_client -connect '[ip]:853' | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
/// default port is 853
/// server-tls 8.8.8.8
/// server-tls 1.0.0.1
///
/// remote https dns server list
/// server-https https://[host]:[port]/path [-blacklist-ip] [-whitelist-ip] [-spki-pin [sha256-pin]] [-group [group] ...] [-exclude-default-group]
///   -spki-pin: TLS spki pin to verify.
///   -tls-host-verify: cert hostname to verify.
///   -host-name: TLS sni hostname.
///   -http-host: http host.
///   -no-check-certificate: no check certificate.
/// default port is 443
/// server-https https://cloudflare-dns.com/dns-query
#[derive(Debug, Clone)]
pub struct DnsServer {
    pub url: DnsUrl,
    pub group: Option<String>,
    pub exclude_default_group: bool,
}

impl FromStr for DnsServer {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = parse::split_options(s, ' ');
        let mut server = None;
        let mut exclude_default_group = false;
        let mut group = None;

        while let Some(part) = parts.next() {
            if part.is_empty() {
                continue;
            }
            if part.starts_with('-') {
                if part == "-group" {
                    group = Some(parts.next().expect("group name").to_string());
                } else if part == "-exclude-default-group" {
                    exclude_default_group = true;
                } else {
                    warn!("unknown server options {}", part);
                }
            } else {
                server = Some(part);
            }
        }

        if let Some(url) = server.and_then(|s| DnsUrl::from_str(s).ok()) {
            Ok(Self {
                url,
                group,
                exclude_default_group,
            })
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone)]
pub struct DomainAddressRule {
    pub domain: LowerName,
    pub address: DomainAddress,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DomainAddress {
    SOA,
    SOAv4,
    SOAv6,
    IGN,
    IGNv4,
    IGNv6,
    IPv4(Ipv4Addr),
    IPv6(Ipv6Addr),
}

impl FromStr for DomainAddress {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "#" => Self::SOA,
            "#4" => Self::SOAv4,
            "#6" => Self::SOAv6,
            "-" => Self::IGN,
            "-4" => Self::IGNv4,
            "-6" => Self::IGNv6,
            ip => {
                let addr = IpAddr::from_str(ip);

                if let Ok(addr) = addr {
                    match addr {
                        IpAddr::V4(ipv4) => DomainAddress::IPv4(ipv4),
                        IpAddr::V6(ipv6) => DomainAddress::IPv6(ipv6),
                    }
                } else {
                    return Err(());
                }
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct AddressRuleItem {
    pub domain: DomainOrDomainSet,
    pub address: DomainAddress,
}

#[derive(Debug, Clone)]
pub struct ForwardRuleItem {
    pub domain: DomainOrDomainSet,
    pub server_group: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainOrDomainSet {
    Domain(LowerName),
    DomainSet(String),
}

impl FromStr for DomainOrDomainSet {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("domain-set:") {
            let idx = s.find(':').unwrap();
            let set_name = &s[(idx + 1)..];

            Ok(DomainOrDomainSet::DomainSet(set_name.to_string()))
        } else if let Ok(mut domain) = domain::Name::from_str(s) {
            domain.set_fqdn(true);
            Ok(DomainOrDomainSet::Domain(domain.into()))
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpeedCheckMode {
    Ping,
    Tcp(u16),
}

impl FromStr for SpeedCheckMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "ping" {
            Ok(SpeedCheckMode::Ping)
        } else if s.starts_with("tcp:") {
            u16::from_str(&s[4..])
                .map(|port| SpeedCheckMode::Tcp(port))
                .map_err(|_| ())
        } else {
            Err(())
        }
    }
}

mod parse {
    use super::*;
    use std::{collections::hash_map::Entry, ffi::OsStr, net::AddrParseError};

    use crate::log::{info, warn};

    impl SmartDnsConfig {
        pub fn load_file<P: AsRef<Path>>(
            &mut self,
            path: P,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let path = find_path(path, self.conf_file.as_ref());

            if path.exists() {
                let file = File::open(path)?;
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    self.config_item(line?.as_str());
                }
            }

            Ok(())
        }

        fn config_item(&mut self, conf_line: &str) {
            let mut conf_line = conf_line.trim_start();

            if let Some(line) = preline(conf_line) {
                conf_line = line;
            } else {
                return;
            }

            let sp_idx = conf_line.find(' ');
            match sp_idx {
                Some(sp_idx) if sp_idx > 0 => {
                    let conf_name = &conf_line[0..sp_idx];
                    let options = conf_line[sp_idx..].trim_start();

                    match conf_name {
                        "server" | "server-tcp" | "server-tls" | "server-https" => {
                            self.config_server(conf_name, options)
                        }
                        "user" => self.user = Some(options.to_string()),
                        "nameserver" => self.config_nameserver(options),
                        "address" => self.config_address(options),
                        "conf-file" => self.load_file(options).expect("load_file failed"),
                        "server-name" => {
                            self.server_name = options.parse().expect("unsupported server name.")
                        }
                        "resolv-file" => self.resolv_file = Some(options.to_string()),
                        "prefetch-domain" => self.prefetch_domain = parse_bool(options),
                        "cache-size" => self.cache_size = usize::from_str(options).ok(),
                        "audit-enable" => self.audit_enable = parse_bool(options),
                        "audit-file" => self.audit_file = Some(Path::new(options).to_owned()),
                        "log-level" => self.log_level = Some(options.to_string()),
                        "dnsmasq-lease-file" => self.dnsmasq_lease_file = Some(options.to_string()),
                        "bind" => self.config_bind(options, false),
                        "bind-tcp" => self.config_bind(options, true),
                        "serve-expired" => self.serve_expired = parse_bool(options),
                        "speed-check-mode" => self.config_speed_check_mode(options),
                        "rr-ttl" => self.rr_ttl = options.parse().ok(),
                        "rr-ttl-min" => self.rr_ttl_min = options.parse().ok(),
                        "rr-ttl-max" => self.rr_ttl_max = options.parse().ok(),
                        "domain-set" => self
                            .config_domain_set(options)
                            .expect("load domain-set failed"),
                        _ => warn!("unkonwn conf: {}", conf_name),
                    }
                }
                _ => (),
            }
        }

        fn config_bind(&mut self, options: &str, bind_tcp: bool) {
            if let Ok(bind) = BindServer::from_str(options) {
                if bind_tcp {
                    self.binds_tcp.push(bind);
                } else {
                    self.binds.push(bind);
                }
            }
        }

        #[inline]
        fn config_server(&mut self, _typ: &str, options: &str) {
            if let Ok(server) = DnsServer::from_str(options) {
                if !server.exclude_default_group {
                    self.servers
                        .get_mut("default")
                        .unwrap()
                        .push(server.clone());
                }

                if server.group.is_some() {
                    info!(
                        "append server {} to group {}",
                        server.url.to_string(),
                        server.group.as_ref().unwrap()
                    );
                }

                match self
                    .servers
                    .entry(server.group.clone().unwrap_or("default".to_string()))
                {
                    Entry::Occupied(g) => g.into_mut(),
                    Entry::Vacant(g) => g.insert(vec![]),
                }
                .push(server);
            }
        }

        #[inline]
        fn config_nameserver(&mut self, options: &str) {
            let parts = split_options(options, '/').collect::<Vec<&str>>();

            if parts.len() == 2 {
                let server_group = parts[1].to_string();
                let part0 = parts[0];

                let domain = DomainOrDomainSet::from_str(part0);

                if let Ok(domain) = domain {
                    self.forward_rules.push(ForwardRuleItem {
                        domain,
                        server_group,
                    })
                } else {
                    println!("parse err");
                }
            }
        }

        #[inline]
        fn config_address(&mut self, options: &str) {
            let parts = split_options(options, '/').collect::<Vec<&str>>();

            // skip if empty
            if parts.is_empty() {
                return;
            }

            if let Ok(domain) = DomainOrDomainSet::from_str(parts[0]) {
                let domain_address = parts.iter().nth(1).map(|p| *p).unwrap_or("#");

                if let Ok(addr) = DomainAddress::from_str(domain_address) {
                    self.address_rules.push(AddressRuleItem {
                        domain,
                        address: addr,
                    });
                }
            }
        }

        #[inline]
        fn config_domain_set(&mut self, options: &str) -> Result<(), Box<dyn std::error::Error>> {
            let mut parts = split_options(options, ' ');

            let mut set_name = None;
            let mut set_path = None;

            while let Some(p) = parts.next() {
                match p {
                    "-n" => set_name = parts.next(),
                    "-f" => set_path = parts.next(),
                    _ => (),
                }
            }

            if set_name.is_none() || set_path.is_none() {
                return Ok(());
            }

            let set_name = set_name.unwrap();
            let set_path = set_path.unwrap();

            let path = find_path(set_path, self.conf_file.as_ref());

            if path.exists() {
                let domain_set = {
                    if let Some(domain_set) = self.domain_sets.get_mut(set_name) {
                        domain_set
                    } else {
                        self.domain_sets
                            .insert(set_name.to_string(), Default::default());

                        self.domain_sets.get_mut(set_name).unwrap()
                    }
                };
                let file = File::open(path)?;
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    if let Some(line) = preline(line?.as_str()) {
                        if let Ok(mut d) = domain::Name::from_str(line) {
                            d.set_fqdn(true);
                            domain_set.insert(d.into());
                        }
                    }
                }
            }

            Ok(())
        }

        #[inline]
        fn config_speed_check_mode(&mut self, options: &str) {
            let mut parts = split_options(options, ',');

            while let Some(p) = parts.next() {
                if let Ok(m) = SpeedCheckMode::from_str(p) {
                    self.speed_check_mode.push(m)
                }
            }
        }
    }

    pub fn find_path<P: AsRef<Path>>(path: P, base_conf_file: Option<&PathBuf>) -> PathBuf {
        let mut path = path.as_ref().to_path_buf();
        if !path.exists() && !path.is_absolute() {
            if let Some(base_conf_file) = base_conf_file {
                if let Some(parent) = base_conf_file.parent() {
                    let new_path = parent.join(path.as_path());
                    if !new_path.exists()
                        && match base_conf_file.file_name() {
                            Some(file_name) if file_name == OsStr::new("smartdns.conf") => true,
                            _ => false,
                        }
                    {
                        // eg: /etc/smartdns.d/custom.conf
                        path = parent.join("smartdns.d").join(path);
                    } else {
                        path = new_path;
                    }
                }
            }
        }

        path
    }

    pub fn split_options<'a>(opt: &'a str, pat: char) -> impl Iterator<Item = &'a str> {
        opt.split(pat).filter(|p| !p.is_empty())
    }

    fn preline(line: &str) -> Option<&str> {
        let mut line = line.trim_start();

        // skip comments and empty line.
        if match line.chars().nth(0) {
            Some(t) if t == '#' => true,
            None => true,
            _ => false,
        } {
            return None;
        }

        // remove comments endding.
        match line.rfind('#') {
            Some(sharp_idx)
                if sharp_idx > 1
                    && match line.chars().nth(sharp_idx - 1) {
                        Some(c) if c.is_whitespace() => true,
                        _ => false,
                    } =>
            {
                line = &line[0..sharp_idx];
            }
            _ => (),
        };

        line = line.trim_end();

        if !line.is_empty() {
            Some(line)
        } else {
            None
        }
    }

    fn parse_bool(s: &str) -> bool {
        match s {
            "y" | "yes" | "t" | "true" | "1" => true,
            _ => false,
        }
    }

    pub fn parse_sock_addrs(addr: &str) -> Result<Vec<SocketAddr>, AddrParseError> {
        let addr = addr.trim();
        let mut sock_addrs = vec![];

        if addr.starts_with("*:") || addr.starts_with(":") {
            let port_str = addr.trim_start_matches("*:").trim_start_matches(':');
            let port = u16::from_str(port_str)
            .expect("The expected format for listening to both IPv4 and IPv6 addresses is :<port>,  *:<port>");

            cfg_if! {
                if #[cfg(target_os = "windows")] {
                    sock_addrs.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
                    sock_addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
                }else if #[cfg(target_os = "linux")]  {
                    // Linux cannot listen to ipv4 and ipv6 on the same port at the same time
                    sock_addrs.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
                } else {
                    // ipv4 default ?
                    sock_addrs.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
                }
            };
        } else {
            match SocketAddr::from_str(addr) {
                Ok(sock_addr) => sock_addrs.push(sock_addr),
                Err(err) => return Err(err),
            }
        }

        Ok(sock_addrs)
    }

    #[cfg(test)]
    mod tests {
        use trust_dns_resolver::config::Protocol;

        use super::*;

        #[test]
        fn test_config_server_0() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config_item(
                "server-https https://223.5.5.5/dns-query  -group bootstrap -exclude-default-group",
            );

            assert_eq!(cfg.servers.get("bootstrap").unwrap().len(), 1);

            let server = cfg.servers.get("bootstrap").unwrap().first().unwrap();

            assert_eq!(server.url.proto(), &Protocol::Https);
            assert_eq!(server.url.to_string(), "https://223.5.5.5/dns-query");

            assert_eq!(server.group, Some("bootstrap".to_string()));
            assert!(server.exclude_default_group);
        }

        #[test]
        fn test_config_server_1() {
            let mut cfg = SmartDnsConfig::new();
            assert_eq!(cfg.servers.values().map(|ss| ss.len()).sum::<usize>(), 0);

            cfg.config_item("server-https https://223.5.5.5/dns-query");

            assert_eq!(cfg.servers.len(), 1);

            let server = cfg.servers.get("default").unwrap().first().unwrap();

            assert_eq!(server.url.proto(), &Protocol::Https);
            assert_eq!(server.url.to_string(), "https://223.5.5.5/dns-query");
            assert!(server.group.is_none());
            assert!(!server.exclude_default_group);
        }

        #[test]
        fn test_config_address_soa() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config_item("address /test.example.com/#");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                DomainOrDomainSet::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::SOA);
        }

        #[test]
        fn test_config_address_soa_v4() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config_item("address /test.example.com/#4");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                DomainOrDomainSet::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::SOAv4);
        }

        #[test]
        fn test_config_address_soa_v6() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config_item("address /test.example.com/#6");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                DomainOrDomainSet::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::SOAv6);
        }

        #[test]
        fn test_config_address_ignore() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config_item("address /test.example.com/-");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                DomainOrDomainSet::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::IGN);
        }

        #[test]
        fn test_config_address_ignore_v4() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config_item("address /test.example.com/-4");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                DomainOrDomainSet::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::IGNv4);
        }

        #[test]
        fn test_config_address_ignore_v6() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config_item("address /test.example.com/-6");

            let domain_addr_rule = cfg.address_rules.first().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                DomainOrDomainSet::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::IGNv6);
        }

        #[test]
        fn test_config_nameserver() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config_item("nameserver /doh.pub/bootstrap");

            let nameserver_rule = cfg.forward_rules.first().unwrap();

            assert_eq!(
                nameserver_rule.domain,
                DomainOrDomainSet::from_str("doh.pub").unwrap().into()
            );

            assert_eq!(nameserver_rule.server_group, "bootstrap");
        }

        #[test]
        fn test_parse_config_speed_check_mode() {
            let mut cfg = SmartDnsConfig::new();
            cfg.config_item("speed-check-mode ping,tcp:123");

            assert_eq!(cfg.speed_check_mode.len(), 2);

            assert_eq!(cfg.speed_check_mode.get(0).unwrap(), &SpeedCheckMode::Ping);
            assert_eq!(
                cfg.speed_check_mode.get(1).unwrap(),
                &SpeedCheckMode::Tcp(123)
            );
        }

        #[test]
        fn test_parse_load_config_file_b() {
            let cfg = SmartDnsConfig::load_from_file("tests/test_confs/b_main.conf");

            assert_eq!(cfg.server_name, "SmartDNS123".parse().unwrap());
            assert_eq!(
                cfg.forward_rules.first().unwrap().domain,
                DomainOrDomainSet::from_str("doh.pub").unwrap().into()
            );
            assert_eq!(cfg.forward_rules.first().unwrap().server_group, "bootstrap");
        }

        #[test]
        #[cfg(failed_tests)]
        fn test_domain_set() {
            let cfg = SmartDnsConfig::load_from_file("tests/test_confs/b_main.conf");

            assert!(!cfg.domain_sets.is_empty());

            let domain_set = cfg.domain_sets.values().nth(0).unwrap();

            assert!(domain_set.len() > 0);

            assert!(domain_set.contains(&domain::Name::from_str("ads1.com").unwrap().into()));
            assert!(!domain_set.contains(&domain::Name::from_str("ads2c.cn").unwrap().into()));
            assert!(domain_set.is_match(&domain::Name::from_str("ads3.net").unwrap().into()));
            assert!(domain_set.is_match(&domain::Name::from_str("q.ads3.net").unwrap().into()));
        }

        #[test]
        fn test_addr_parse() {
            assert!(parse_sock_addrs("[::]:123").is_ok());
            assert!(parse_sock_addrs("0.0.0.0:123").is_ok());
            assert!(parse_sock_addrs(":123").is_ok());
            assert!(parse_sock_addrs("*:123").is_ok());
        }

        #[test]
        fn test_to_socket_addrs_1() {
            let sock_addrs = parse_sock_addrs("127.0.1.1:123").unwrap();
            assert_eq!(sock_addrs.len(), 1);
            let addr1 = sock_addrs[0];
            assert_eq!(addr1.ip().to_string(), "127.0.1.1");
            assert_eq!(addr1.port(), 123)
        }

        #[test]
        fn test_to_socket_addrs_2() {
            let sock_addrs = parse_sock_addrs("[::]:123").unwrap();
            let addr1 = sock_addrs[0];
            assert_eq!(addr1.ip().to_string(), "::");
            assert_eq!(addr1.port(), 123)
        }

        #[test]
        fn test_to_socket_addrs_3() {
            let sock_addrs = parse_sock_addrs(":123").unwrap();

            cfg_if! {
                if #[cfg(target_os = "windows")] {

                    assert_eq!(sock_addrs.len(), 2);

                    assert!(sock_addrs.get(0).unwrap().is_ipv6());
                    assert!(sock_addrs.get(1).unwrap().is_ipv4());

                    assert_eq!(sock_addrs.get(0).unwrap().ip().to_string(), "::");
                    assert_eq!(sock_addrs.get(1).unwrap().ip().to_string(), "0.0.0.0");

                    assert_eq!(sock_addrs.get(0).unwrap().port(), 123);
                    assert_eq!(sock_addrs.get(1).unwrap().port(), 123);

                }else if #[cfg(target_os = "linux")]  {
                    // Linux cannot listen to ipv4 and ipv6 on the same port at the same time

                    assert_eq!(sock_addrs.len(), 1);
                    assert!(sock_addrs.get(0).unwrap().is_ipv6());
                    assert_eq!(sock_addrs.get(0).unwrap().ip().to_string(), "::");
                    assert_eq!(sock_addrs.get(0).unwrap().port(), 123);


                } else {
                    // ipv4 default ?
                    assert_eq!(sock_addrs.len(), 1);
                    assert!(sock_addrs.get(0).unwrap().is_ipv4());
                    assert_eq!(sock_addrs.get(0).unwrap().ip().to_string(), "0.0.0.0");
                    assert_eq!(sock_addrs.get(0).unwrap().port(), 123);
                }
            };
        }
    }
}
