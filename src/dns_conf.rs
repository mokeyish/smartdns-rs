use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use cfg_if::cfg_if;
use ipnet::IpNet;
use trust_dns_proto::rr::Name;

use crate::dns::RecordType;
use crate::dns_rule::{CNameRule, DomainRule, DomainRuleMap, DomainRuleTreeNode, ResponseMode};
use crate::dns_url::{DnsUrl, DnsUrlParamExt};
use crate::infra::file_mode::FileMode;
use crate::infra::ipset::IpSet;
use crate::log::{debug, error, info, warn};
use crate::proxy::ProxyConfig;

#[derive(Default)]
pub struct SmartDnsConfig {
    /// dns server name, default is host name
    ///
    /// ```
    /// server-name,
    ///
    /// example:
    ///   server-name smartdns
    /// ```
    server_name: Option<Name>,

    /// The number of worker threads
    num_workers: Option<usize>,

    /// whether resolv local hostname to ip address
    resolv_hostname: Option<bool>,

    /// dns server run user
    ///
    /// ```
    /// user [username]
    ///
    /// exmaple:
    ///   user nobody
    /// ```
    user: Option<String>,

    /// Local domain suffix appended to DHCP names and hosts file entries.
    domain: Option<Name>,

    /// Include another configuration options
    ///
    /// conf-file [file]
    /// ```
    /// example:
    ///   conf-file blacklist-ip.conf
    /// ```
    conf_file: Option<PathBuf>,

    /// dns server bind ip and port, default dns server port is 53, support binding multi ip and port
    pub binds: Vec<BindServer>,
    /// bind tcp server
    pub binds_tcp: Vec<BindServer>,
    /// bind tls server
    pub binds_tls: Vec<BindServer>,
    /// bind https server
    pub binds_https: Vec<BindServer>,
    /// bind quic server
    pub binds_quic: Vec<BindServer>,

    /// SSL Certificate file path
    bind_cert_file: Option<PathBuf>,
    /// SSL Certificate key file path
    bind_cert_key_file: Option<PathBuf>,
    /// SSL Certificate key file password
    bind_cert_key_pass: Option<String>,

    /// tcp connection idle timeout
    ///
    /// tcp-idle-time [second]
    tcp_idle_time: Option<u64>,

    /// dns cache size
    ///
    /// ```
    /// cache-size [number]
    ///   0: for no cache
    /// ```
    cache_size: Option<usize>,
    /// enable persist cache when restart
    cache_persist: Option<bool>,
    /// cache persist file
    cache_file: Option<PathBuf>,

    /// prefetch domain
    ///
    /// ```
    /// prefetch-domain [yes|no]
    ///
    /// example:
    ///   prefetch-domain yes
    /// ```
    prefetch_domain: Option<bool>,

    /// cache serve expired
    ///
    /// serve-expired [yes|no]
    /// ```
    /// example:
    ///   serve-expired yes
    /// ```
    serve_expired: Option<bool>,
    /// cache serve expired TTL
    ///
    /// serve-expired-ttl [num]
    /// ```
    /// example:
    ///   serve-expired-ttl 0
    /// ```
    serve_expired_ttl: Option<u64>,
    /// reply TTL value to use when replying with expired data
    ///
    /// serve-expired-reply-ttl [num]
    /// ```
    /// example:
    ///   serve-expired-reply-ttl 30
    /// ```
    serve_expired_reply_ttl: Option<u64>,

    /// List of hosts that supply bogus NX domain results
    bogus_nxdomain: Arc<IpSet>,

    /// List of IPs that will be filtered when nameserver is configured -blacklist-ip parameter
    blacklist_ip: Arc<IpSet>,

    /// List of IPs that will be accepted when nameserver is configured -whitelist-ip parameter
    whitelist_ip: Arc<IpSet>,

    /// List of IPs that will be ignored
    ignore_ip: Arc<IpSet>,

    /// speed check mode
    ///
    /// speed-check-mode [ping|tcp:port|http:port|https:port|none|,]
    /// ```ini
    /// example:
    ///   speed-check-mode ping,tcp:8080,http:80,https
    ///   speed-check-mode tcp:443,ping
    ///   speed-check-mode none
    /// ```
    speed_check_mode: SpeedCheckModeList,

    /// force AAAA query return SOA
    ///
    /// force-AAAA-SOA [yes|no]
    force_aaaa_soa: Option<bool>,

    /// force specific qtype return soa
    ///
    /// force-qtype-SOA [qtypeid |...]
    ///
    /// qtypeid: https://en.wikipedia.org/wiki/List_of_DNS_record_types
    /// ```ini
    /// example:
    ///   force-qtype-SOA 65 28
    /// ```
    force_qtype_soa: HashSet<RecordType>,

    /// Enable IPV4, IPV6 dual stack IP optimization selection strategy
    ///
    /// dualstack-ip-selection [yes|no]
    dualstack_ip_selection: Option<bool>,
    /// dualstack-ip-selection-threshold [num] (0~1000)
    dualstack_ip_selection_threshold: Option<u16>,
    /// dualstack-ip-allow-force-AAAA [yes|no]
    dualstack_ip_allow_force_aaaa: Option<bool>,

    /// edns client subnet
    ///
    /// ```
    /// example:
    ///   edns-client-subnet [ip/subnet]
    ///   edns-client-subnet 192.168.1.1/24
    ///   edns-client-subnet 8::8/56
    /// ```
    edns_client_subnet: Option<IpNet>,

    /// ttl for all resource record
    rr_ttl: Option<u64>,
    /// minimum ttl for resource record
    rr_ttl_min: Option<u64>,
    /// maximum ttl for resource record
    rr_ttl_max: Option<u64>,
    /// maximum reply ttl for resource record
    rr_ttl_reply_max: Option<u64>,

    /// ttl for local address and host (default: rr-ttl-min)
    local_ttl: Option<u64>,

    /// Maximum number of IPs returned to the client|8|number of IPs, 1~16
    max_reply_ip_num: Option<u8>,

    /// response mode
    ///
    /// response-mode [first-ping|fastest-ip|fastest-response]
    response_mode: Option<ResponseMode>,

    /// set log level
    ///
    /// log-level [level], level=fatal, error, warn, notice, info, debug
    log_level: Option<String>,
    /// file path of log file.
    log_file: Option<PathBuf>,
    /// size of each log file, support k,m,g
    log_size: Option<u64>,
    /// number of logs, 0 means disable log
    log_num: Option<u64>,
    /// log file mode
    log_file_mode: Option<FileMode>,
    // log filter
    log_filter: Option<String>,

    /// dns audit
    ///
    /// enable or disable audit.
    audit_enable: Option<bool>,
    /// audit file
    ///
    /// ```
    /// example 1:
    ///   audit-file /var/log/smartdns-audit.log
    ///
    /// example 2:
    ///   audit-file /var/log/smartdns-audit.csv
    /// ```
    audit_file: Option<PathBuf>,
    /// audit-size size of each audit file, support k,m,g
    audit_size: Option<u64>,
    /// number of audit files.
    audit_num: Option<usize>,
    /// audit file mode
    audit_file_mode: Option<FileMode>,

    /// Support reading dnsmasq dhcp file to resolve local hostname
    dnsmasq_lease_file: Option<PathBuf>,

    /// certificate file
    ca_file: Option<PathBuf>,
    /// certificate path
    ca_path: Option<PathBuf>,

    /// remote dns server list
    servers: HashMap<String, Vec<NameServerInfo>>,

    /// specific nameserver to domain
    ///
    /// nameserver /domain/[group|-]
    ///
    /// ```
    /// example:
    ///   nameserver /www.example.com/office, Set the domain name to use the appropriate server group.
    ///   nameserver /www.example.com/-, ignore this domain
    /// ```
    forward_rules: Vec<ForwardRule>,

    /// specific address to domain
    ///
    /// address /domain/[ip|-|-4|-6|#|#4|#6]
    ///
    /// ```
    /// example:
    ///   address /www.example.com/1.2.3.4, return ip 1.2.3.4 to client
    ///   address /www.example.com/-, ignore address, query from upstream, suffix 4, for ipv4, 6 for ipv6, none for all
    ///   address /www.example.com/#, return SOA to client, suffix 4, for ipv4, 6 for ipv6, none for all
    /// ```
    address_rules: AddressRules,

    /// set domain rules
    domain_rules: DomainRules,

    cnames: CNameRules,

    /// The proxy server for upstream querying.
    proxy_servers: Arc<HashMap<String, ProxyConfig>>,

    resolv_file: Option<String>,
    domain_sets: HashMap<String, HashSet<Name>>,

    domain_rule_map: DomainRuleMap,
}

pub type DomainSets = HashMap<String, HashSet<Name>>;
pub type ForwardRules = Vec<ForwardRule>;
pub type AddressRules = Vec<ConfigItem<DomainId, DomainAddress>>;
pub type DomainRules = Vec<ConfigItem<DomainId, DomainRule>>;
pub type CNameRules = Vec<ConfigItem<DomainId, CNameRule>>;

impl SmartDnsConfig {
    pub fn new() -> Self {
        Self {
            servers: HashMap::from([("default".to_string(), Default::default())]),
            ..Default::default()
        }
    }

    pub fn load<P: AsRef<Path>>(path: Option<P>) -> Arc<Self> {
        if let Some(ref conf) = path {
            let path = conf.as_ref();

            SmartDnsConfig::load_from_file(path)
        } else {
            cfg_if! {
                if #[cfg(target_os = "android")] {
                    let candidate_path = [
                        "/data/data/com.termux/files/usr/etc/smartdns.conf",
                        "/data/data/com.termux/files/usr/etc/smartdns/smartdns.conf"
                    ];

                } else if #[cfg(target_os = "windows")] {
                    let candidate_path  = [crate::service::CONF_PATH];
                } else {
                    let candidate_path = [
                        crate::service::CONF_PATH,
                        "/etc/smartdns.conf",
                        "/etc/smartdns/smartdns.conf",
                        "/usr/local/etc/smartdns.conf",
                        "/usr/local/etc/smartdns/smartdns.conf"
                    ];
                }
            };

            candidate_path
                .iter()
                .map(Path::new)
                .filter(|p| p.exists())
                .map(SmartDnsConfig::load_from_file)
                .next()
                .expect("No configuation file found.")
        }
    }

    fn load_from_file<P: AsRef<Path>>(path: P) -> Arc<Self> {
        let path = path.as_ref();

        let mut cfg = Self::new();
        if !path.exists() {
            panic!("configuration file {:?} not exist.", path);
        }
        cfg.load_file(path).expect("load conf file filed");
        cfg.finalize()
    }
}

impl SmartDnsConfig {
    /// Print the config summary.
    pub fn summary(&self) {
        info!(r#"whoami 👉 {}"#, self.server_name());

        const DEFAULT_GROUP: &str = "default";
        for (group, servers) in self.servers.iter() {
            if group == DEFAULT_GROUP {
                continue;
            }
            for server in servers {
                let proxy = server
                    .proxy
                    .as_deref()
                    .map(|n| self.proxies().get(n))
                    .unwrap_or_default();

                info!(
                    "upstream server: {} [Group: {}] {}",
                    server.url.to_string(),
                    group,
                    match proxy {
                        Some(s) => format!("over {}", s),
                        None => "".to_string(),
                    }
                );
            }
        }

        if let Some(ss) = self.servers.get(DEFAULT_GROUP) {
            for s in ss {
                info!(
                    "upstream server: {} [Group: {}]",
                    s.url.to_string(),
                    DEFAULT_GROUP
                );
            }
        }
    }

    pub fn server_name(&self) -> Name {
        match self.server_name {
            Some(ref server_name) => Some(server_name.clone()),
            None => match hostname::get() {
                Ok(name) => match name.to_str() {
                    Some(s) => Name::from_str(s).ok(),
                    None => None,
                },
                Err(_) => None,
            },
        }
        .unwrap_or_else(|| Name::from_str(crate::NAME).unwrap())
    }

    /// The number of worker threads
    #[inline]
    pub fn num_workers(&self) -> Option<usize> {
        self.num_workers
    }

    /// SSL Certificate file path
    #[inline]
    pub fn bind_cert_file(&self) -> Option<&Path> {
        self.bind_cert_file.as_deref()
    }
    /// SSL Certificate key file path
    #[inline]
    pub fn bind_cert_key_file(&self) -> Option<&Path> {
        self.bind_cert_key_file.as_deref()
    }
    /// bind_cert_key_pass
    #[inline]
    pub fn bind_cert_key_pass(&self) -> Option<&str> {
        self.bind_cert_key_pass.as_deref()
    }

    /// whether resolv local hostname to ip address
    #[inline]
    pub fn resolv_hostanme(&self) -> bool {
        self.resolv_hostname.unwrap_or_default()
    }
    /// dns server run user
    #[inline]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    #[inline]
    pub fn domain(&self) -> Option<&Name> {
        self.domain.as_ref()
    }

    /// tcp connection idle timeout
    #[inline]
    pub fn tcp_idle_time(&self) -> u64 {
        self.tcp_idle_time.unwrap_or(120)
    }

    /// dns cache size
    #[inline]
    pub fn cache_size(&self) -> usize {
        self.cache_size.unwrap_or(512)
    }
    ///  enable persist cache when restart
    #[inline]
    pub fn cache_persist(&self) -> bool {
        self.cache_persist.unwrap_or(false)
    }

    /// cache persist file
    #[inline]
    pub fn cache_file(&self) -> PathBuf {
        self.cache_file
            .to_owned()
            .unwrap_or_else(|| std::env::temp_dir().join("smartdns.cache"))
    }

    /// prefetch domain
    #[inline]
    pub fn prefetch_domain(&self) -> bool {
        self.prefetch_domain.unwrap_or_default()
    }

    #[inline]
    pub fn dnsmasq_lease_file(&self) -> Option<&Path> {
        self.dnsmasq_lease_file.as_deref()
    }

    /// cache serve expired
    #[inline]
    pub fn serve_expired(&self) -> bool {
        self.serve_expired.unwrap_or(true)
    }

    /// cache serve expired TTL
    #[inline]
    pub fn serve_expired_ttl(&self) -> u64 {
        self.serve_expired_ttl.unwrap_or(0)
    }

    /// reply TTL value to use when replying with expired data
    #[inline]
    pub fn serve_expired_reply_ttl(&self) -> u64 {
        self.serve_expired_reply_ttl.unwrap_or(5)
    }

    /// List of hosts that supply bogus NX domain results
    #[inline]
    pub fn bogus_nxdomain(&self) -> &Arc<IpSet> {
        &self.bogus_nxdomain
    }
    /// List of IPs that will be filtered when nameserver is configured -blacklist-ip parameter
    #[inline]
    pub fn blacklist_ip(&self) -> &Arc<IpSet> {
        &self.blacklist_ip
    }
    /// List of IPs that will be accepted when nameserver is configured -whitelist-ip parameter
    #[inline]
    pub fn whitelist_ip(&self) -> &Arc<IpSet> {
        &self.whitelist_ip
    }
    /// List of IPs that will be ignored
    #[inline]
    pub fn ignore_ip(&self) -> &Arc<IpSet> {
        &self.ignore_ip
    }

    /// speed check mode
    #[inline]
    pub fn speed_check_mode(&self) -> &SpeedCheckModeList {
        &self.speed_check_mode
    }

    /// force AAAA query return SOA
    #[inline]
    pub fn force_aaaa_soa(&self) -> bool {
        self.force_aaaa_soa.unwrap_or_default()
    }

    /// force specific qtype return soa
    #[inline]
    pub fn force_qtype_soa(&self) -> &HashSet<RecordType> {
        &self.force_qtype_soa
    }

    /// Enable IPV4, IPV6 dual stack IP optimization selection strategy
    #[inline]
    pub fn dualstack_ip_selection(&self) -> bool {
        self.dualstack_ip_selection.unwrap_or(true)
    }
    /// dualstack-ip-selection-threshold [num] (0~1000)
    #[inline]
    pub fn dualstack_ip_selection_threshold(&self) -> u16 {
        self.dualstack_ip_selection_threshold.unwrap_or(10)
    }

    /// dualstack-ip-allow-force-AAAA
    #[inline]
    pub fn dualstack_ip_allow_force_aaaa(&self) -> bool {
        self.dualstack_ip_allow_force_aaaa.unwrap_or_default()
    }
    /// edns client subnet
    #[inline]
    pub fn edns_client_subnet(&self) -> Option<IpNet> {
        self.edns_client_subnet
    }

    /// ttl for all resource record
    #[inline]
    pub fn rr_ttl(&self) -> Option<u64> {
        self.rr_ttl
    }
    /// minimum ttl for resource record
    #[inline]
    pub fn rr_ttl_min(&self) -> Option<u64> {
        self.rr_ttl_min.or_else(|| self.rr_ttl())
    }
    /// maximum ttl for resource record
    #[inline]
    pub fn rr_ttl_max(&self) -> Option<u64> {
        self.rr_ttl_max.or_else(|| self.rr_ttl())
    }
    #[inline]
    pub fn rr_ttl_reply_max(&self) -> Option<u64> {
        self.rr_ttl_reply_max
    }

    #[inline]
    pub fn local_ttl(&self) -> u64 {
        self.local_ttl
            .unwrap_or_else(|| self.rr_ttl_min().unwrap_or_default())
    }

    /// Maximum number of IPs returned to the client|8|number of IPs, 1~16
    #[inline]
    pub fn max_reply_ip_num(&self) -> Option<u8> {
        self.max_reply_ip_num
    }

    /// response mode
    #[inline]
    pub fn response_mode(&self) -> ResponseMode {
        self.response_mode.unwrap_or(ResponseMode::FirstPing)
    }

    #[inline]
    pub fn log_enabled(&self) -> bool {
        self.log_num() > 0
    }
    pub fn log_level(&self) -> tracing::Level {
        use tracing::Level;
        match self.log_level.as_deref().unwrap_or("error") {
            "tarce" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" | "notice" => Level::INFO,
            "warn" => Level::WARN,
            "error" | "fatal" => Level::ERROR,
            _ => Level::ERROR,
        }
    }

    pub fn log_file(&self) -> PathBuf {
        match self.log_file.as_ref() {
            Some(e) => e.to_owned(),
            None => {
                cfg_if! {
                    if #[cfg(target_os="windows")] {
                        let mut path = std::env::temp_dir();
                        path.push("smartdns");
                        path.push("smartdns.log");
                        path
                    } else {
                        PathBuf::from(r"/var/log/smartdns/smartdns.log")
                    }

                }
            }
        }
    }

    #[inline]
    pub fn log_size(&self) -> u64 {
        use byte_unit::n_kb_bytes;
        self.audit_size.unwrap_or(n_kb_bytes(128) as u64)
    }
    #[inline]
    pub fn log_num(&self) -> u64 {
        self.log_num.unwrap_or(2)
    }

    #[inline]
    pub fn log_file_mode(&self) -> u32 {
        self.log_file_mode.map(|m| *m).unwrap_or(0o640)
    }

    #[inline]
    pub fn log_filter(&self) -> Option<&str> {
        self.log_filter.as_deref()
    }

    #[inline]
    pub fn audit_enable(&self) -> bool {
        self.audit_enable.unwrap_or_default()
    }

    #[inline]
    pub fn audit_file(&self) -> Option<&Path> {
        self.audit_file.as_deref()
    }

    #[inline]
    pub fn audit_num(&self) -> usize {
        self.audit_num.unwrap_or(2)
    }

    #[inline]
    pub fn audit_size(&self) -> u64 {
        use byte_unit::n_kb_bytes;
        self.audit_size.unwrap_or(n_kb_bytes(128) as u64)
    }

    #[inline]
    pub fn audit_file_mode(&self) -> u32 {
        self.audit_file_mode.map(|m| *m).unwrap_or(0o640)
    }
    /// certificate file
    #[inline]
    pub fn ca_file(&self) -> Option<&Path> {
        self.ca_file.as_deref()
    }

    /// certificate path
    #[inline]
    pub fn ca_path(&self) -> Option<&Path> {
        self.ca_path.as_deref()
    }

    /// remote dns server list
    #[inline]
    pub fn servers(&self) -> &HashMap<String, Vec<NameServerInfo>> {
        &self.servers
    }

    /// specific nameserver to domain
    #[inline]
    pub fn forward_rules(&self) -> &ForwardRules {
        &self.forward_rules
    }

    #[inline]
    pub fn address_rules(&self) -> &AddressRules {
        &self.address_rules
    }

    #[inline]
    pub fn domain_rules(&self) -> &DomainRules {
        &self.domain_rules
    }

    #[inline]
    pub fn proxies(&self) -> &Arc<HashMap<String, ProxyConfig>> {
        &self.proxy_servers
    }

    #[inline]
    pub fn resolv_file(&self) -> Option<&str> {
        self.resolv_file.as_deref()
    }

    #[inline]
    pub fn domain_sets(&self) -> &HashMap<String, HashSet<Name>> {
        &self.domain_sets
    }

    #[inline]
    pub fn cnames(&self) -> &CNameRules {
        &self.cnames
    }

    #[inline]
    pub fn find_domain_rule(&self, domain: &Name) -> Option<Arc<DomainRuleTreeNode>> {
        self.domain_rule_map.find(domain).cloned()
    }
}

#[derive(Clone)]
pub struct ConfigItem<N: Clone, V: Clone> {
    pub name: N,
    pub value: V,
}

impl<N: Clone, V: Clone> ConfigItem<N, V> {
    fn new(name: N, value: V) -> Self {
        Self { name, value }
    }
}

impl<N: Clone, V: Clone> Deref for ConfigItem<N, V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<N: Clone, V: Clone> DerefMut for ConfigItem<N, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
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
#[derive(Debug, Clone)]
pub struct BindServer {
    /// bind adress
    pub sock_addr: SocketAddr,

    /// bind network device.
    pub device: Option<String>,

    /// ssl config
    pub ssl_config: Option<SslConfig>,

    /// the options
    pub opts: ServerOpts,
}

impl BindServer {
    // bind network device.
    pub fn device(&self) -> Option<&str> {
        self.device.as_deref()
    }
}

impl FromStr for BindServer {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = parse::split_options(s, ' ');

        let mut addr = None;
        let mut device = None;
        let mut group = None;
        let mut no_rule_addr = None;
        let mut no_rule_nameserver = None;
        let mut no_rule_ipset = None;
        let mut no_speed_check = None;
        let mut no_cache = None;
        let mut no_rule_soa = None;
        let mut no_dualstack_selection = None;
        let mut force_aaaa_soa = None;
        let mut no_serve_expired = None;

        // ssl parameters
        let mut server_name = None;
        let mut ssl_certificate = None;
        let mut ssl_certificate_key = None;

        while let Some(part) = parts.next() {
            if part.starts_with('-') {
                match part {
                    "-group" => group = parts.next().map(|p| p.to_string()),
                    "-no-rule-addr" => no_rule_addr = Some(true),
                    "-no-rule-nameserver" => no_rule_nameserver = Some(true),
                    "-no-rule-ipset" => no_rule_ipset = Some(true),
                    "-no-speed-check" => no_speed_check = Some(true),
                    "-no-cache" => no_cache = Some(true),
                    "-no-rule-soa" => no_rule_soa = Some(true),
                    "-no-serve-expired" => no_serve_expired = Some(true),
                    "-no-dualstack-selection" => no_dualstack_selection = Some(true),
                    "-force-aaaa-soa" => force_aaaa_soa = Some(true),
                    "-server-name" => server_name = parts.next().map(|p| p.to_string()),
                    "-ssl-certificate" => {
                        ssl_certificate = parts.next().map(|p| Path::new(p).to_path_buf())
                    }
                    "-ssl-certificate-key" => {
                        ssl_certificate_key = parts.next().map(|p| Path::new(p).to_path_buf())
                    }
                    opt => warn!("unknown option: {}", opt),
                }
            } else if addr.is_none() {
                addr = Some(part);
            } else {
                error!("unexpected options: {}", part);
            }
        }

        if let Some(s) = addr {
            if let Some(at_idx) = s.find('@') {
                device = Some(s[at_idx + 1..].to_string());
                addr = Some(&s[0..at_idx])
            }
        }

        let sock_addrs = addr
            .map(|addr| parse::parse_sock_addrs(addr).ok())
            .unwrap_or_default()
            .unwrap_or_else(|| panic!("{} addr expect [::]:53 or 0.0.0.0:53", s));

        let ssl_config = Some(SslConfig {
            server_name,
            certificate: ssl_certificate,
            certificate_key: ssl_certificate_key,
        });

        Ok(Self {
            sock_addr: sock_addrs,
            device,
            ssl_config,
            opts: ServerOpts {
                group,
                no_rule_addr,
                no_rule_nameserver,
                no_rule_ipset,
                no_speed_check,
                no_cache,
                no_rule_soa,
                no_dualstack_selection,
                force_aaaa_soa,
                no_serve_expired,
            },
        })
    }
}

impl BindServer {
    pub fn is_default_opts(&self) -> bool {
        self.opts.is_default()
    }
}

#[derive(Debug, Clone)]
pub struct SslConfig {
    pub server_name: Option<String>,
    pub certificate: Option<PathBuf>,
    pub certificate_key: Option<PathBuf>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct ServerOpts {
    /// set domain request to use the appropriate server group.
    pub group: Option<String>,

    /// skip address rule.
    pub no_rule_addr: Option<bool>,

    /// skip nameserver rule.
    pub no_rule_nameserver: Option<bool>,

    /// skip ipset rule.
    pub no_rule_ipset: Option<bool>,

    /// do not check speed.
    pub no_speed_check: Option<bool>,

    /// skip cache.
    pub no_cache: Option<bool>,

    /// Skip address SOA(#) rules.
    pub no_rule_soa: Option<bool>,

    /// Disable dualstack ip selection.
    pub no_dualstack_selection: Option<bool>,

    /// force AAAA query return SOA.
    pub force_aaaa_soa: Option<bool>,

    /// do not serve expired
    pub no_serve_expired: Option<bool>,
}

impl ServerOpts {
    #[inline]
    pub fn is_default(&self) -> bool {
        self.eq(&Default::default())
    }

    /// set domain request to use the appropriate server group.
    #[inline]
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// skip address rule.
    #[inline]
    pub fn no_rule_addr(&self) -> bool {
        self.no_rule_addr.unwrap_or_default()
    }

    /// skip nameserver rule.
    #[inline]
    pub fn no_rule_nameserver(&self) -> bool {
        self.no_rule_nameserver.unwrap_or_default()
    }

    /// skip ipset rule.
    #[inline]
    pub fn no_rule_ipset(&self) -> bool {
        self.no_rule_ipset.unwrap_or_default()
    }

    ///  do not check speed.
    #[inline]
    pub fn no_speed_check(&self) -> bool {
        self.no_speed_check.unwrap_or_default()
    }

    /// skip cache.
    #[inline]
    pub fn no_cache(&self) -> bool {
        self.no_cache.unwrap_or_default()
    }

    /// Skip address SOA(#) rules.
    #[inline]
    pub fn no_rule_soa(&self) -> bool {
        self.no_rule_soa.unwrap_or_default()
    }

    /// Disable dualstack ip selection.
    #[inline]
    pub fn no_dualstack_selection(&self) -> bool {
        self.no_dualstack_selection.unwrap_or_default()
    }

    /// force AAAA query return SOA.
    #[inline]
    pub fn force_aaaa_soa(&self) -> bool {
        self.force_aaaa_soa.unwrap_or_default()
    }

    /// do not serve expired.
    #[inline]
    pub fn no_serve_expired(&self) -> bool {
        self.no_serve_expired.unwrap_or_default()
    }

    pub fn apply(&mut self, other: Self) {
        let Self {
            group,
            no_rule_addr,
            no_rule_nameserver,
            no_rule_ipset,
            no_speed_check,
            no_cache,
            no_rule_soa,
            no_dualstack_selection,
            force_aaaa_soa,
            no_serve_expired,
        } = other;

        if self.group.is_none() {
            self.group = group;
        }
        if self.no_rule_addr.is_none() {
            self.no_rule_addr = no_rule_addr;
        }
        if self.no_rule_nameserver.is_none() {
            self.no_rule_nameserver = no_rule_nameserver;
        }
        if self.no_rule_ipset.is_none() {
            self.no_rule_ipset = no_rule_ipset;
        }

        if self.no_speed_check.is_none() {
            self.no_speed_check = no_speed_check;
        }
        if self.no_cache.is_none() {
            self.no_cache = no_cache;
        }
        if self.no_rule_soa.is_none() {
            self.no_rule_soa = no_rule_soa;
        }

        if self.no_dualstack_selection.is_none() {
            self.no_dualstack_selection = no_dualstack_selection;
        }

        if self.force_aaaa_soa.is_none() {
            self.force_aaaa_soa = force_aaaa_soa;
        }

        if self.no_serve_expired.is_none() {
            self.no_serve_expired = no_serve_expired;
        }
    }
}

impl std::ops::AddAssign for ServerOpts {
    fn add_assign(&mut self, rhs: Self) {
        self.apply(rhs)
    }
}

/// remote udp dns server list
///
/// server [IP]:[PORT] [-blacklist-ip] [-whitelist-ip] [-check-edns] [-group [group] ...] [-exclude-default-group]
///
/// default port is 53
///   - -blacklist-ip: filter result with blacklist ip
///   - -whitelist-ip: filter result whth whitelist ip,  result in whitelist-ip will be accepted.
///   - -check-edns: result must exist edns RR, or discard result.
///   - -group [group]: set server to group, use with nameserver /domain/group.
///   - -exclude-default-group: exclude this server from default group.
/// ```ini, no-run
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
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NameServerInfo {
    /// the nameserver url.
    pub url: DnsUrl,

    /// set server to group, use with nameserver /domain/group.
    pub group: Option<String>,

    /// filter result with blacklist ip
    pub blacklist_ip: bool,

    /// filter result with whitelist ip,  result in whitelist-ip will be accepted.
    pub whitelist_ip: bool,

    /// result must exist edns RR, or discard result.
    pub check_edns: bool,

    /// exclude this server from default group.
    pub exclude_default_group: bool,

    /// use proxy to connect to server.
    pub proxy: Option<String>,

    /// set as bootstrap dns server
    pub bootstrap_dns: bool,

    /// nameserver group for resolving.
    pub resolve_group: Option<String>,
}

impl FromStr for NameServerInfo {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = parse::split_options(s, ' ');

        if let Some(Ok(mut url)) = parts.next().map(DnsUrl::from_str) {
            let mut exclude_default_group = false;
            let mut group = None;
            let mut blacklist_ip = false;
            let mut whitelist_ip = false;
            let mut check_edns = false;
            let mut proxy = None;
            let mut bootstrap_dns = false;

            while let Some(part) = parts.next() {
                if part.is_empty() {
                    continue;
                }
                if part.starts_with('-') {
                    match part {
                        "-exclude-default-group" => exclude_default_group = true,
                        "-blacklist-ip" => blacklist_ip = true,
                        "-whitelist-ip" => whitelist_ip = true,
                        "-check-edns" => check_edns = true,
                        "-bootstrap-dns" => bootstrap_dns = true,
                        "-group" => group = Some(parts.next().expect("group name").to_string()),
                        "-proxy" => proxy = Some(parts.next().expect("proxy name").to_string()),
                        "-host-name" | "-host-name:" => {
                            if let Some(host_name) =
                                Some(parts.next().expect("host name").to_string())
                            {
                                if host_name == "-" {
                                    url.set_sni_off(true);
                                } else {
                                    url.set_host_name(&host_name);
                                }
                            }
                        }
                        "-no-check-certificate" => {
                            url.set_ssl_verify(false);
                        }
                        _ => warn!("unknown server options {}", part),
                    }
                } else {
                    warn!("ignore: {}", part);
                }
            }
            Ok(Self {
                url,
                group,
                exclude_default_group,
                blacklist_ip,
                whitelist_ip,
                bootstrap_dns,
                check_edns,
                proxy,
                resolve_group: None,
            })
        } else {
            Err(())
        }
    }
}

impl From<DnsUrl> for NameServerInfo {
    fn from(url: DnsUrl) -> Self {
        Self {
            url,
            group: None,
            exclude_default_group: false,
            blacklist_ip: false,
            whitelist_ip: false,
            bootstrap_dns: false,
            check_edns: false,
            proxy: None,
            resolve_group: None,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
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

/// alias: nameserver rules
#[derive(Debug, Clone)]
pub struct ForwardRule {
    pub domain: DomainId,
    pub nameserver: String,
}

/// domain-rules /domain/ [-rules...]
impl FromStr for ConfigItem<DomainId, DomainRule> {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = parse::split_options(s, '/').collect::<Vec<&str>>();
        if parts.is_empty() {
            return Err(());
        }

        if let Ok(domain) = DomainId::from_str(parts[0]) {
            let mut speed_check_mode = vec![];
            let mut cname = None;
            let mut address = None;

            let mut nameserver = None;

            let mut dualstack_ip_selection = None;

            let mut parts = parse::split_options(parts[1], ' ').peekable();

            while let Some(part) = parts.next() {
                match part {
                    "-c" | "-speed-check-mode" => {
                        while let Some(s) = parts.peek() {
                            if s.starts_with('-') {
                                break;
                            }

                            if let Some(Ok(mode)) = parts.next().map(SpeedCheckMode::from_str) {
                                speed_check_mode.push(mode);
                            }
                        }
                    }
                    "-a" | "-address" => {
                        address = parts
                            .next()
                            .map(DomainAddress::from_str)
                            .map(|r| r.ok())
                            .unwrap_or_default()
                    }
                    "-n" | "-nameserver" => nameserver = parts.next().map(|s| s.to_string()),
                    "-d" | "-dualstack-ip-selection" => {
                        dualstack_ip_selection = parts.next().map(parse::parse_bool)
                    }
                    "-p" | "-ipset" => warn!("ignore ipset: {:?}", parts.next()),
                    "-t" | "-nftset" => warn!("ignore nftset: {:?}", parts.next()),
                    "-cname" => cname = parts.next().map(|s| s.parse().ok()).unwrap_or_default(),
                    opt => warn!("unknown option: {}", opt),
                }
            }

            Ok(Self {
                name: domain,
                value: DomainRule {
                    speed_check_mode: speed_check_mode.into(),
                    address,
                    cname,
                    response_mode: None,
                    nameserver,
                    dualstack_ip_selection,
                    no_cache: None,
                    no_serve_expired: None,
                    rr_ttl: None,
                    rr_ttl_min: None,
                    rr_ttl_max: None,
                },
            })
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DomainId {
    Domain(Name),
    DomainSet(String),
}

impl From<Name> for DomainId {
    #[inline]
    fn from(value: Name) -> Self {
        Self::Domain(value)
    }
}

impl FromStr for DomainId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("domain-set:") {
            let idx = s.find(':').unwrap();
            let set_name = &s[(idx + 1)..];

            Ok(DomainId::DomainSet(set_name.to_string()))
        } else if let Ok(mut domain) = Name::from_str(s) {
            domain.set_fqdn(true);
            Ok(DomainId::Domain(domain.to_lowercase()))
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct SpeedCheckModeList(Vec<SpeedCheckMode>);

impl SpeedCheckModeList {
    pub fn push(&mut self, mode: SpeedCheckMode) -> Option<SpeedCheckMode> {
        if self.0.iter().all(|m| m != &mode) {
            self.0.push(mode);
            None
        } else {
            Some(mode)
        }
    }
}

impl From<Vec<SpeedCheckMode>> for SpeedCheckModeList {
    fn from(value: Vec<SpeedCheckMode>) -> Self {
        let mut lst = Self(Vec::with_capacity(value.len()));
        for mode in value {
            lst.push(mode);
        }
        lst
    }
}

impl Deref for SpeedCheckModeList {
    type Target = Vec<SpeedCheckMode>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SpeedCheckModeList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        todo!()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SpeedCheckMode {
    None,
    Ping,
    Tcp(u16),
    Http(u16),
    Https(u16),
}

impl Default for SpeedCheckMode {
    #[inline]
    fn default() -> Self {
        Self::None
    }
}

impl FromStr for SpeedCheckMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ping" => Ok(SpeedCheckMode::Ping),
            "http" => Ok(SpeedCheckMode::Http(80)),
            "https" => Ok(SpeedCheckMode::Https(443)),
            _ => {
                if let Some(port) = s.strip_prefix("tcp:") {
                    u16::from_str(port).map(SpeedCheckMode::Tcp).map_err(|_| ())
                } else if let Some(port) = s.strip_prefix("http:") {
                    u16::from_str(port)
                        .map(SpeedCheckMode::Http)
                        .map_err(|_| ())
                } else if let Some(port) = s.strip_prefix("https:") {
                    u16::from_str(port)
                        .map(SpeedCheckMode::Https)
                        .map_err(|_| ())
                } else {
                    Err(())
                }
            }
        }
    }
}

impl FromStr for ResponseMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mode = match s.trim().to_lowercase().as_str() {
            "first-ping" => Self::FastestIp,
            "fastest-ip" => Self::FastestIp,
            "fastest-response" => Self::FastestResponse,
            _ => return Err(()),
        };

        Ok(mode)
    }
}

impl FromStr for CNameRule {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "-" {
            Ok(Self::Ignore)
        } else {
            Name::from_str(s).map_err(|_| ()).map(Self::Name)
        }
    }
}

mod parse {
    use byte_unit::Byte;

    use super::*;
    use std::{collections::hash_map::Entry, ffi::OsStr, net::AddrParseError};

    impl SmartDnsConfig {
        pub fn finalize(mut self) -> Arc<Self> {
            if self.binds.is_empty()
                && self.binds_tcp.is_empty()
                && self.binds_https.is_empty()
                && self.binds_tls.is_empty()
                && self.binds_quic.is_empty()
            {
                self.binds.push(BindServer {
                    sock_addr: ("0.0.0.0", 53).to_socket_addrs().unwrap().next().unwrap(),
                    device: None,
                    ssl_config: None,
                    opts: Default::default(),
                })
            }

            self.bogus_nxdomain = self.bogus_nxdomain.compact().into();
            self.blacklist_ip = self.blacklist_ip.compact().into();
            self.whitelist_ip = self.whitelist_ip.compact().into();
            self.ignore_ip = self.ignore_ip.compact().into();

            self.cnames.dedup_by(|a, b| a.name == b.name);

            let domain_rule_map = DomainRuleMap::create(
                self.domain_rules(),
                self.address_rules(),
                self.forward_rules(),
                self.domain_sets(),
                &self.cnames,
            );

            // set nameserver group for bootstraping
            for server in self.servers.values_mut().flatten() {
                if server.url.addrs().is_empty() {
                    let host = server.url.host().to_string();
                    if let Ok(Some(rule)) =
                        Name::from_str(host.as_str()).map(|domain| domain_rule_map.find(&domain))
                    {
                        server.resolve_group = rule.get(|r| r.nameserver.clone());
                    }
                }
            }

            // find device address
            {
                let f = |bind: &'_ &mut BindServer| bind.device.is_some();

                let binds = [
                    self.binds.iter_mut().filter(f),
                    self.binds_tcp.iter_mut().filter(f),
                    self.binds_https.iter_mut().filter(f),
                    self.binds_tls.iter_mut().filter(f),
                    self.binds_quic.iter_mut().filter(f),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();

                if !binds.is_empty() {
                    #[cfg(not(target_os = "android"))]
                    {
                        use local_ip_address::list_afinet_netifas;
                        match list_afinet_netifas() {
                            Ok(network_interfaces) => {
                                for bind in binds {
                                    let device = bind.device.as_deref().expect("bind device");

                                    let ips = network_interfaces
                                        .iter()
                                        .filter(|(dev, _ip)| dev == device)
                                        .map(|(_, ip)| *ip)
                                        .collect::<Vec<_>>();

                                    if ips.is_empty() {
                                        warn!("network device {} not found.", device);
                                    }

                                    let ip = ips.into_iter().find(|ip| {
                                        match bind.sock_addr {
                                            SocketAddr::V4(_) => ip.is_ipv4(),
                                            SocketAddr::V6(_) => ip.is_ipv6() && !matches!(ip, IpAddr::V6(ipv6) if (ipv6.segments()[0] & 0xffc0) == 0xfe80),
                                        }
                                    });

                                    match ip {
                                        Some(ip) => bind.sock_addr.set_ip(ip),
                                        None => {
                                            warn!("no ip address on device {}", device)
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                warn!("bind device failed, {}", err);
                            }
                        }
                    }

                    #[cfg(target_os = "android")]
                    warn!("currently, bind device {} not support for android.", device);
                }
            }

            self.domain_rule_map = domain_rule_map;

            // dedup bind address
            {
                // priority: QUIC => UDP
                let mut udp_addr = HashSet::new();
                // priority: Https => TLS => TCP
                let mut tcp_addr = HashSet::new();

                fn dedup(addr_set: &mut HashSet<SocketAddr>, binds: &[BindServer]) -> Vec<usize> {
                    let mut remove_idx = vec![];
                    for (idx, bind) in binds.iter().enumerate().rev() {
                        if !addr_set.insert(bind.sock_addr) {
                            remove_idx.push(idx);
                        }
                    }
                    remove_idx
                }

                // quic udp
                for idx in dedup(&mut udp_addr, &self.binds_quic) {
                    let bind = self.binds_quic.remove(idx);
                    warn!("remove duplicated bind-quic {:?}", bind.sock_addr);
                }

                // udp
                for idx in dedup(&mut udp_addr, &self.binds) {
                    let bind = self.binds.remove(idx);
                    warn!("remove duplicated bind-udp {:?}", bind.sock_addr);
                }

                // https tcp
                for idx in dedup(&mut tcp_addr, &self.binds_https) {
                    let bind = self.binds_https.remove(idx);
                    warn!("remove duplicated bind-https {:?}", bind.sock_addr);
                }
                // tls tcp
                for idx in dedup(&mut tcp_addr, &self.binds_tls) {
                    let bind = self.binds_tls.remove(idx);
                    warn!("remove duplicated bind-tls {:?}", bind.sock_addr);
                }

                // tcp
                for idx in dedup(&mut tcp_addr, &self.binds_tcp) {
                    let bind = self.binds_tcp.remove(idx);
                    warn!("remove duplicated bind-tcp {:?}", bind.sock_addr);
                }
            }

            self.into()
        }

        pub fn with(mut self, config: &str) -> Self {
            self.config(config);
            self
        }

        pub fn load_file<P: AsRef<Path>>(
            &mut self,
            path: P,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let path = find_path(path, self.conf_file.as_ref());

            if path.exists() {
                if self.conf_file.is_none() {
                    info!("loading configuration from: {:?}", path);
                    self.conf_file = Some(path.clone());
                } else {
                    debug!("loading extra configuration from {:?}", path);
                }
                let file = File::open(path)?;
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    self.config(line?.as_str());
                }
            } else {
                warn!("configuration file {:?} does not exist", path);
            }

            Ok(())
        }

        fn config(&mut self, conf_line: &str) {
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
                        "server-name" => self.server_name = options.parse().ok(),
                        "num-workers" => self.num_workers = options.parse().ok(),
                        "resolv-hostname" => self.resolv_hostname = Some(parse_bool(options)),
                        "user" => self.user = Some(options.to_string()),
                        "domain" => self.domain = options.parse().ok(),
                        "conf-file" => self.load_file(options).expect("load_file failed"),
                        "bind" => {
                            if let Ok(v) = options.parse() {
                                self.binds.push(v)
                            }
                        }
                        "bind-tcp" => {
                            if let Ok(v) = options.parse() {
                                self.binds_tcp.push(v)
                            }
                        }
                        "bind-tls" => {
                            if let Ok(v) = options.parse() {
                                self.binds_tls.push(v)
                            }
                        }
                        "bind-https" => {
                            if let Ok(v) = options.parse() {
                                self.binds_https.push(v)
                            }
                        }
                        "bind-quic" => {
                            if let Ok(v) = options.parse() {
                                self.binds_quic.push(v)
                            }
                        }
                        "bind-cert-file" => {
                            self.bind_cert_file = Some(Path::new(options).to_owned())
                        }
                        "bind-cert-key-file" => {
                            self.bind_cert_key_file = Some(Path::new(options).to_owned())
                        }
                        "bind-cert-key-pass" => self.bind_cert_key_pass = Some(options.to_string()),
                        "tcp-idle-time" => self.tcp_idle_time = options.parse().ok(),
                        "cache-size" => self.cache_size = options.parse().ok(),
                        "cache-persist" => self.cache_persist = Some(parse_bool(options)),
                        "cache-file" => self.cache_file = Some(Path::new(options).to_owned()),
                        "prefetch-domain" => self.prefetch_domain = Some(parse_bool(options)),
                        "serve-expired" => self.serve_expired = Some(parse_bool(options)),
                        "serve-expired-ttl" => self.serve_expired_ttl = options.parse().ok(),
                        "serve-expired-reply-ttl" => {
                            self.serve_expired_reply_ttl = options.parse().ok()
                        }
                        "bogus-nxdomain" => {
                            if let Ok(v) = options.parse::<IpNet>() {
                                self.bogus_nxdomain = (self.bogus_nxdomain.as_ref() + v).into()
                            }
                        }
                        "blacklist-ip" => {
                            if let Ok(v) = options.parse::<IpNet>() {
                                self.blacklist_ip = (self.blacklist_ip.as_ref() + v).into()
                            }
                        }
                        "whitelist-ip" => {
                            if let Ok(v) = options.parse::<IpNet>() {
                                self.whitelist_ip = (self.whitelist_ip.as_ref() + v).into()
                            }
                        }
                        "ignore-ip" => {
                            if let Ok(v) = options.parse::<IpNet>() {
                                self.ignore_ip = (self.ignore_ip.as_ref() + v).into()
                            }
                        }
                        "speed-check-mode" => self.config_speed_check_mode(options),
                        "force-AAAA-SOA" => self.force_aaaa_soa = Some(parse_bool(options)),
                        "force-qtype-SOA" => {
                            if let Ok(r) = u16::from_str(options).map(RecordType::from) {
                                self.force_qtype_soa.insert(r);
                            }
                        }
                        "dualstack-ip-selection-threshold" => {
                            self.dualstack_ip_selection_threshold = options.parse().ok()
                        }
                        "dualstack-ip-allow-force-AAAA" => {
                            self.dualstack_ip_allow_force_aaaa = Some(parse_bool(options))
                        }
                        "dualstack-ip-selection" => {
                            self.dualstack_ip_selection = Some(parse_bool(options))
                        }
                        "edns-client-subnet" => self.edns_client_subnet = options.parse().ok(),
                        "rr-ttl" => self.rr_ttl = options.parse().ok(),
                        "rr-ttl-min" => self.rr_ttl_min = options.parse().ok(),
                        "rr-ttl-max" => self.rr_ttl_max = options.parse().ok(),
                        "rr-ttl-reply-max" => self.rr_ttl_reply_max = options.parse().ok(),
                        "local-ttl" => self.local_ttl = options.parse().ok(),
                        "max-reply-ip-num" => self.max_reply_ip_num = options.parse().ok(),
                        "response-mode" => self.response_mode = options.parse().ok(),
                        "log-level" => self.log_level = Some(options.to_string()),
                        "log-file" => self.log_file = Some(Path::new(options).to_owned()),
                        "log-size" => {
                            self.log_size = Byte::from_str(options)
                                .map(|size| size.get_bytes() as u64)
                                .ok()
                        }
                        "log-num" => self.log_num = options.parse().ok(),
                        "log-file-mode" => self.log_file_mode = options.parse().ok(),
                        "log-filter" => self.log_filter = Some(options.to_string()),
                        "audit-enable" => self.audit_enable = Some(parse_bool(options)),
                        "audit-file" => self.audit_file = Some(Path::new(options).to_owned()),
                        "audit-size" => {
                            self.audit_size = Byte::from_str(options)
                                .map(|size| size.get_bytes() as u64)
                                .ok()
                        }
                        "audit-num" => self.audit_num = options.parse().ok(),
                        "audit-file-mode" => self.audit_file_mode = options.parse().ok(),
                        "dnsmasq-lease-file" => {
                            self.dnsmasq_lease_file = Some(Path::new(options).to_owned())
                        }
                        "ca-file" => self.ca_file = Some(Path::new(options).to_owned()),
                        "ca-path" => self.ca_path = Some(Path::new(options).to_owned()),
                        "server" | "server-tcp" | "server-tls" | "server-https" | "server-quic" => {
                            self.config_server(conf_name, options)
                        }
                        "nameserver" => self.config_nameserver(options),
                        "address" => self.config_address(options),
                        "domain-rules" => self.config_domain_rule(options),
                        "domain-rule" => self.config_domain_rule(options),
                        "proxy-server" => self.config_proxy_server(options),
                        "resolv-file" => self.resolv_file = Some(options.to_string()),
                        "cname" => self.config_cname(options),
                        "domain-set" => self
                            .config_domain_set(options)
                            .expect("load domain-set failed"),
                        _ => warn!("unkonwn conf: {}", conf_name),
                    }
                }
                _ => (),
            }
        }

        #[inline]
        fn config_server(&mut self, typ: &str, options: &str) {
            let options = options.trim_start();
            let server_options = match typ {
                "server-tcp" if !options.starts_with("tcp://") => {
                    Some(["tcp://", options].concat())
                }
                "server-tls" if !options.starts_with("tls://") => {
                    Some(["tls://", options.trim_start()].concat())
                }
                "server-https" if !options.starts_with("https://") => {
                    Some(["https://", options.trim_start()].concat())
                }
                "server-quic" if !options.starts_with("quic://") => {
                    Some(["quic://", options.trim_start()].concat())
                }
                _ => None,
            };

            let server_options = server_options.as_deref().unwrap_or(options);

            if let Ok(mut server) = NameServerInfo::from_str(server_options) {
                if !server.exclude_default_group {
                    self.servers
                        .get_mut("default")
                        .unwrap()
                        .push(server.clone());
                }

                if server.group.is_none() && server.bootstrap_dns {
                    server.group = Some("bootstrap-dns".to_string());
                }

                if server.group.is_some() {
                    debug!(
                        "append server {} to group {}",
                        server.url.to_string(),
                        server.group.as_ref().unwrap()
                    );
                }

                if let Some(group) = server.group.as_deref() {
                    match self.servers.entry(group.to_string()) {
                        Entry::Occupied(g) => g.into_mut(),
                        Entry::Vacant(g) => g.insert(vec![]),
                    }
                    .push(server);
                } else if server.exclude_default_group {
                    warn!("group name required when `-exclude_default_group` enabled");
                } else if server.bootstrap_dns {
                    warn!("upstream server {} not added!!!", server.url.to_string());
                }
            }
        }

        #[inline]
        fn config_nameserver(&mut self, options: &str) {
            let parts = split_options(options, '/').collect::<Vec<&str>>();

            if parts.len() == 2 {
                let server_group = parts[1].to_string();
                let part0 = parts[0];

                let domain = DomainId::from_str(part0);

                if let Ok(domain) = domain {
                    self.forward_rules.push(ForwardRule {
                        domain,
                        nameserver: server_group,
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

            if let Ok(domain) = DomainId::from_str(parts[0]) {
                let domain_address = parts.get(1).copied().unwrap_or("#");

                if let Ok(addr) = DomainAddress::from_str(domain_address) {
                    self.address_rules.push(ConfigItem {
                        name: domain,
                        value: addr,
                    });
                }
            }
        }

        fn config_cname(&mut self, options: &str) {
            let mut parts = split_options(options, '/');

            if let (Some(Ok(name)), Some(Ok(cname))) = (
                parts.next().map(DomainId::from_str),
                parts.next().map(CNameRule::from_str),
            ) {
                self.cnames.push(ConfigItem { name, value: cname })
            }
        }

        #[inline]
        fn config_proxy_server(&mut self, options: &str) {
            let mut parts = split_options(options, ' ');

            let mut name = None;
            let mut proxy = None;

            while let Some(part) = parts.next() {
                match part {
                    "-n" | "-name" => name = parts.next().map(|s| s.to_string()),
                    _ => proxy = ProxyConfig::from_str(part).ok(),
                }
            }

            match (name, proxy) {
                (Some(name), Some(proxy)) => {
                    let mut tmp = self.proxy_servers.as_ref().clone();
                    tmp.insert(name, proxy);
                    self.proxy_servers = tmp.into();
                }
                _ => warn!("the proxy url or name not specific"),
            }
        }

        #[inline]
        fn config_domain_rule(&mut self, options: &str) {
            if let Ok(rule) = options.parse() {
                self.domain_rules.push(rule)
            }
        }

        #[inline]
        fn config_domain_set(&mut self, options: &str) -> Result<(), Box<dyn std::error::Error>> {
            let mut parts = split_options(options, ' ');

            let mut set_name = None;
            let mut set_path = None;

            while let Some(p) = parts.next() {
                match p {
                    "-n" | "-name" => set_name = parts.next(),
                    "-f" | "-file" => set_path = parts.next(),
                    _ => warn!(">> domain-set: unexpected options {}.", p),
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
                        if let Ok(mut d) = Name::from_str(line) {
                            d.set_fqdn(true);
                            domain_set.insert(d);
                        }
                    }
                }
            } else {
                warn!(">> domain-set: file {:?} not exist.", path);
            }

            Ok(())
        }

        #[inline]
        fn config_speed_check_mode(&mut self, options: &str) {
            let parts = split_options(options, ',');
            for p in parts {
                if let Ok(m) = SpeedCheckMode::from_str(p) {
                    self.speed_check_mode.push(m);
                }
            }
        }
    }

    pub fn find_path<P: AsRef<Path>>(path: P, base_conf_file: Option<&PathBuf>) -> PathBuf {
        let mut path = path.as_ref().to_path_buf();
        if !path.exists() && !path.is_absolute() {
            if let Some(base_conf_file) = base_conf_file {
                if let Some(parent) = base_conf_file.parent() {
                    let mut new_path = parent.join(path.as_path());

                    if !new_path.exists()
                        && matches!(base_conf_file.file_name(), Some(file_name) if file_name == OsStr::new("smartdns.conf"))
                    {
                        // eg: /etc/smartdns.d/custom.conf
                        new_path = parent.join("smartdns.d").join(path.as_path());
                    }

                    if new_path.exists() {
                        path = new_path;
                    }
                }
            }
        }

        path
    }

    pub fn split_options(opt: &str, pat: char) -> impl Iterator<Item = &str> {
        opt.split(pat).filter(|p| !p.is_empty())
    }

    fn preline(line: &str) -> Option<&str> {
        let mut line = line.trim_start();

        // skip comments and empty line.
        if match line.chars().next() {
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
                    && matches!(line.chars().nth(sharp_idx - 1), Some(c) if c.is_whitespace()) =>
            {
                let preserve = line[0..sharp_idx].trim_end();
                if !preserve.ends_with("-a") && !preserve.ends_with("-address") {
                    line = preserve;
                }
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

    pub fn parse_bool(s: &str) -> bool {
        matches!(s, "y" | "yes" | "t" | "true" | "1")
    }

    pub fn parse_sock_addrs(addr: &str) -> Result<SocketAddr, AddrParseError> {
        let addr = addr.trim();
        if let Some(port) = addr.to_lowercase().strip_prefix("localhost:") {
            format!("127.0.0.1:{}", port).as_str().parse()
        } else if addr.starts_with(':') {
            format!("0.0.0.0{}", addr).as_str().parse()
        } else {
            addr.parse()
        }
    }

    #[cfg(test)]
    mod tests {
        use trust_dns_resolver::config::Protocol;

        use super::*;

        #[test]
        fn test_config_binds_dedup() {
            let cfg = SmartDnsConfig::new()
                .with("bind-tcp 0.0.0.0:4453@eth1")
                .with("bind-tls 0.0.0.0:4452@eth1")
                .with("bind-https 0.0.0.0:4453@eth1")
                .finalize();

            assert_eq!(cfg.binds_tcp.len(), 0);
            assert_eq!(cfg.binds_tls.len(), 1);
            assert_eq!(cfg.binds_https.len(), 1);
        }

        #[test]
        fn test_config_bind_with_device() {
            let cfg = SmartDnsConfig::new()
                .with("bind 0.0.0.0:4453@eth1")
                .with("bind 0.0.0.0:4453@eth1")
                .finalize();

            assert_eq!(cfg.binds.len(), 1);

            let bind = cfg.binds.get(0).unwrap();

            assert_eq!(bind.sock_addr, "0.0.0.0:4453".parse().unwrap());

            assert_eq!(bind.device, Some("eth1".to_string()));
        }

        #[test]
        fn test_config_bind_with_device_flags() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("bind-https 0.0.0.0:443@eth2 -no-rule-addr");

            let bind = cfg.binds_https.get(0).unwrap();

            assert_eq!(bind.sock_addr, "0.0.0.0:443".parse().unwrap());

            assert_eq!(bind.device, Some("eth2".to_string()));
            assert!(bind.opts.no_rule_addr());
        }

        #[test]
        fn test_config_bind_https() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config(
                "bind-https 0.0.0.0:4453 -server-name dns.example.com -ssl-certificate /etc/nginx/dns.example.com.crt -ssl-certificate-key /etc/nginx/dns.example.com.key",
            );

            assert!(!cfg.binds_https.is_empty());

            let bind = cfg.binds_https.iter().next().unwrap();
            let ssl_cfg = bind.ssl_config.as_ref().unwrap();

            assert_eq!(
                bind.sock_addr,
                "0.0.0.0:4453".parse::<SocketAddr>().unwrap()
            );

            assert_eq!(ssl_cfg.server_name, Some("dns.example.com".to_string()));
            assert_eq!(
                ssl_cfg.certificate,
                Some(Path::new("/etc/nginx/dns.example.com.crt").to_path_buf())
            );
            assert_eq!(
                ssl_cfg.certificate_key,
                Some(Path::new("/etc/nginx/dns.example.com.key").to_path_buf())
            );
        }

        #[test]
        fn test_config_server_0() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config(
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

            cfg.config("server-https https://223.5.5.5/dns-query");

            assert_eq!(cfg.servers.len(), 1);

            let server = cfg.servers.get("default").unwrap().first().unwrap();

            assert_eq!(server.url.proto(), &Protocol::Https);
            assert_eq!(server.url.to_string(), "https://223.5.5.5/dns-query");
            assert!(server.group.is_none());
            assert!(!server.exclude_default_group);
        }

        #[test]
        fn test_config_server_2() {
            let mut cfg = SmartDnsConfig::new();
            assert_eq!(cfg.servers.values().map(|ss| ss.len()).sum::<usize>(), 0);

            cfg.config(
                "server-https https://223.5.5.5/dns-query  -bootstrap-dns -exclude-default-group",
            );

            let servers = cfg.servers.get("bootstrap-dns").unwrap();

            assert_eq!(servers.len(), 1);

            let server = servers.first().unwrap();

            assert_eq!(server.url.proto(), &Protocol::Https);
            assert_eq!(server.url.to_string(), "https://223.5.5.5/dns-query");
            assert!(server.exclude_default_group);
            assert!(server.bootstrap_dns);
        }

        #[test]
        fn test_config_tls_server() {
            let mut cfg = SmartDnsConfig::new();
            assert_eq!(cfg.servers.values().map(|ss| ss.len()).sum::<usize>(), 0);

            cfg.config(
                "server-tls 45.90.28.0 -host-name: dns.nextdns.io -tls-host-verify: dns.nextdns.io",
            );

            let servers = cfg.servers.get("default").unwrap();

            assert_eq!(servers.len(), 1);

            let server = servers.first().unwrap();

            assert!(!server.exclude_default_group);
            assert_eq!(server.url.proto(), &Protocol::Tls);
            assert_eq!(server.url.to_string(), "tls://dns.nextdns.io");
            assert_eq!(server.url.addrs(), &["45.90.28.0:853".parse().unwrap()]);
            assert_eq!(server.url.domain(), Some("dns.nextdns.io"));
        }

        #[test]
        fn test_config_address_soa() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("address /test.example.com/#");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.name,
                DomainId::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.value, DomainAddress::SOA);
        }

        #[test]
        fn test_config_address_soa_v4() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("address /test.example.com/#4");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.name,
                DomainId::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.value, DomainAddress::SOAv4);
        }

        #[test]
        fn test_config_address_soa_v6() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("address /test.example.com/#6");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.name,
                DomainId::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.value, DomainAddress::SOAv6);
        }

        #[test]
        fn test_config_address_ignore() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("address /test.example.com/-");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.name,
                DomainId::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.value, DomainAddress::IGN);
        }

        #[test]
        fn test_config_address_ignore_v4() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("address /test.example.com/-4");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.name,
                DomainId::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.value, DomainAddress::IGNv4);
        }

        #[test]
        fn test_config_address_ignore_v6() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("address /test.example.com/-6");

            let domain_addr_rule = cfg.address_rules.first().unwrap();

            assert_eq!(
                domain_addr_rule.name,
                DomainId::from_str("test.example.com").unwrap()
            );

            assert_eq!(domain_addr_rule.value, DomainAddress::IGNv6);
        }

        #[test]
        fn test_config_nameserver() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("nameserver /doh.pub/bootstrap");

            let nameserver_rule = cfg.forward_rules.first().unwrap();

            assert_eq!(
                nameserver_rule.domain,
                DomainId::from_str("doh.pub").unwrap().into()
            );

            assert_eq!(nameserver_rule.nameserver, "bootstrap");
        }

        #[test]
        fn test_config_domain_rule() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("domain-rule /doh.pub/ -c ping -a 127.0.0.1 -n test -d yes");

            let domain_rule = cfg.domain_rules.first().unwrap();

            assert_eq!(
                domain_rule.name,
                DomainId::Domain(Name::from_str("doh.pub").unwrap().into())
            );
            assert_eq!(domain_rule.address, "127.0.0.1".parse().ok());
            assert_eq!(
                domain_rule.speed_check_mode,
                vec![SpeedCheckMode::Ping].into()
            );
            assert_eq!(domain_rule.nameserver, Some("test".to_string()));
            assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
        }

        #[test]
        fn test_config_domain_rule_2() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("domain-rules /doh.pub/ -c ping -a 127.0.0.1 -n test -d yes");

            let domain_rule = cfg.domain_rules.first().unwrap();

            assert_eq!(
                domain_rule.name,
                DomainId::Domain(Name::from_str("doh.pub").unwrap().into())
            );
            assert_eq!(domain_rule.address, "127.0.0.1".parse().ok());
            assert_eq!(
                domain_rule.speed_check_mode,
                vec![SpeedCheckMode::Ping].into()
            );
            assert_eq!(domain_rule.nameserver, Some("test".to_string()));
            assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
        }

        #[test]
        fn test_parse_config_log_file_mode() {
            let mut cfg = SmartDnsConfig::new();

            cfg.config("log-file-mode 644");
            assert_eq!(cfg.log_file_mode, Some(0o644u32.into()));
            cfg.config("log-file-mode 0o755");
            assert_eq!(cfg.log_file_mode, Some(0o755u32.into()));
        }

        #[test]
        fn test_parse_config_speed_check_mode() {
            let mut cfg = SmartDnsConfig::new();
            cfg.config("speed-check-mode ping,tcp:123");

            assert_eq!(cfg.speed_check_mode.len(), 2);

            assert_eq!(cfg.speed_check_mode.get(0).unwrap(), &SpeedCheckMode::Ping);
            assert_eq!(
                cfg.speed_check_mode.get(1).unwrap(),
                &SpeedCheckMode::Tcp(123)
            );
        }

        #[test]
        fn test_parse_config_speed_check_mode_https_omit_port() {
            let mut cfg = SmartDnsConfig::new();
            cfg.config("speed-check-mode http,https");

            assert_eq!(cfg.speed_check_mode.len(), 2);

            assert_eq!(
                cfg.speed_check_mode.get(0).unwrap(),
                &SpeedCheckMode::Http(80)
            );
            assert_eq!(
                cfg.speed_check_mode.get(1).unwrap(),
                &SpeedCheckMode::Https(443)
            );
        }

        #[test]
        fn test_parse_config_audit_size_1() {
            use byte_unit::n_mb_bytes;
            let mut cfg = SmartDnsConfig::new();
            cfg.config("audit-size 80mb");
            assert_eq!(cfg.audit_size, Some(n_mb_bytes(80) as u64));
        }

        #[test]
        fn test_parse_config_audit_size_2() {
            use byte_unit::n_gb_bytes;
            let mut cfg = SmartDnsConfig::new();
            cfg.config("audit-size 30 gb");
            assert_eq!(cfg.audit_size, Some(n_gb_bytes(30) as u64));
        }

        #[test]
        fn test_parse_load_config_file_b() {
            let cfg = SmartDnsConfig::load_from_file("tests/test_confs/b_main.conf");

            assert_eq!(cfg.server_name, "SmartDNS123".parse().ok());
            assert_eq!(
                cfg.forward_rules.first().unwrap().domain,
                DomainId::from_str("doh.pub").unwrap().into()
            );
            assert_eq!(cfg.forward_rules.first().unwrap().nameserver, "bootstrap");
        }

        #[test]
        fn test_parse_config_proxy_server() {
            let mut cfg = SmartDnsConfig::new();
            cfg.config("proxy-server socks5://127.0.0.1:1080 -n abc");

            assert_eq!(
                cfg.proxy_servers.get("abc").map(|s| s.to_string()),
                Some("socks5://127.0.0.1:1080".to_string())
            );
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
            assert_eq!(
                parse_sock_addrs("localhost:123"),
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 123))
            );
            assert_eq!(
                parse_sock_addrs("0.0.0.0:123"),
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 123))
            );
            assert_eq!(
                parse_sock_addrs(":123"),
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 123))
            );
            assert_eq!(
                parse_sock_addrs("[::1]:123"),
                "[::1]:123".parse::<SocketAddr>()
            );
            assert_eq!(
                parse_sock_addrs("[::]:123"),
                Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 123))
            );
        }
    }
}
