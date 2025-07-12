use cfg_if::cfg_if;
use ipnet::IpNet;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use crate::config::*;
use crate::dns::DomainRuleGetter;
use crate::infra::ipset::IpMap;
use crate::log;
use crate::{
    dns_rule::{DomainRuleMap, DomainRuleTreeNode},
    infra::ipset::IpSet,
    libdns::proto::rr::{Name, RecordType},
    log::{debug, info, warn},
    proxy::ProxyConfig,
};

const DEFAULT_GROUP: &str = "default";

#[cfg(target_os = "windows")]
pub const DEFAULT_CONF_DIR: &str = r"C:\ProgramData\smartdns";
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub const DEFAULT_CONF_DIR: &str = "/usr/local/etc/smartdns";
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const DEFAULT_CONF_DIR: &str = "/opt/homebrew/etc/smartdns";
#[cfg(target_os = "android")]
pub const DEFAULT_CONF_DIR: &str = "/data/data/com.termux/files/usr/etc/smartdns";
#[cfg(target_os = "linux")]
pub const DEFAULT_CONF_DIR: &str = "/etc/smartdns";

#[derive(Default)]
pub struct RuntimeConfig {
    conf_dir: PathBuf,
    conf_file: PathBuf,
    inner: Config,

    rule_groups: HashMap<String, RuleGroup>,

    domain_rule_group_map: HashMap<String, DomainRuleMap>,

    proxy_servers: Arc<HashMap<String, ProxyConfig>>,

    /// List of hosts that supply bogus NX domain results
    bogus_nxdomain: Arc<IpSet>,

    /// List of IPs that will be filtered when nameserver is configured -blacklist-ip parameter
    blacklist_ip: Arc<IpSet>,

    /// List of IPs that will be accepted when nameserver is configured -whitelist-ip parameter
    whitelist_ip: Arc<IpSet>,

    /// List of IPs that will be ignored
    ignore_ip: Arc<IpSet>,

    ip_alias: Arc<IpMap<Arc<[IpAddr]>>>,
}

impl RuntimeConfig {
    pub fn load<P: AsRef<Path>>(conf_dir: Option<PathBuf>, path: Option<P>) -> Arc<Self> {
        let mut builder = Self::builder();

        if let Some(conf_dir) = conf_dir {
            builder = builder.with_conf_dir(conf_dir);
        }

        if let Some(ref conf) = path {
            let mut path = Cow::Borrowed(conf.as_ref());
            if path.is_dir() {
                path = Cow::Owned(path.join(format!("{}.conf", crate::NAME.to_lowercase())));
            }
            builder.with_conf_file(path).build().into()
        } else {
            #[cfg(feature = "service")]
            let conf_path: &str = crate::service::CONF_PATH;
            #[cfg(not(feature = "service"))]
            let conf_path: &str = "./smartdns.conf";
            cfg_if! {
                if #[cfg(target_os = "android")] {
                    let candidate_path = [
                        conf_path,
                        "/data/data/com.termux/files/usr/etc/smartdns.conf",
                        "/data/data/com.termux/files/usr/etc/smartdns/smartdns.conf"
                    ];

                } else if #[cfg(target_os = "windows")] {
                    let candidate_path  = [conf_path];
                } else {
                    let candidate_path = [
                        conf_path,
                        "/etc/smartdns.conf",
                        "/etc/smartdns/smartdns.conf",
                        "/usr/local/etc/smartdns.conf",
                        "/usr/local/etc/smartdns/smartdns.conf"
                    ];
                }
            }

            let candidate_paths = candidate_path.iter().map(Path::new).filter(|p| p.exists());

            for p in candidate_paths {
                builder = builder.with_conf_file(p);
                match builder.load() {
                    Ok(_) => return builder.build().into(),
                    Err(_) => {
                        warn!("Failed to load configuration from {:?}", p);
                        continue;
                    }
                }
            }

            panic!("No configuation file found.")
        }
    }

    pub fn builder() -> RuntimeConfigBuilder {
        let conf_dir = PathBuf::from(DEFAULT_CONF_DIR);
        let conf_file = conf_dir.join("smartdns.conf");
        RuntimeConfigBuilder {
            conf_dir,
            conf_file,
            config: Default::default(),
            loaded_files: Default::default(),
            rule_groups: Default::default(),
            rule_group_stack: Default::default(),
            dirs: Default::default(),
        }
    }
}

impl RuntimeConfig {
    /// Print the config summary.
    pub fn summary(&self) {
        info!(r#"whoami 👉 {}"#, self.server_name());

        info!(r#"num workers: {}"#, self.num_workers());

        for server in self.nameservers.iter() {
            if !server.exclude_default_group && server.group.is_empty() {
                continue;
            }
            let proxy = server
                .proxy
                .as_deref()
                .map(|n| self.proxies().get(n))
                .unwrap_or_default();

            info!(
                "upstream server: {} [Group: {:?}] {}",
                server.server.to_string(),
                server.group,
                match proxy {
                    Some(s) => format!("over {s}"),
                    None => "".to_string(),
                }
            );
        }

        for server in self.nameservers.iter().filter(|s| !s.exclude_default_group) {
            info!(
                "upstream server: {} [Group: {}]",
                server.server.to_string(),
                DEFAULT_GROUP
            );
        }

        info!(
            "cache: {}",
            if self.cache_size() > 0 {
                format!("size({})", self.cache_size())
            } else {
                "OFF".to_string()
            }
        );

        if self.cache_size() > 0 {
            info!(
                "cache persist: {}",
                if self.cache_persist() { "YES" } else { "NO" }
            );

            info!(
                "domain prefetch: {}",
                if self.prefetch_domain() { "ON" } else { "OFF" }
            );
        }

        info!(
            "speed check mode: {}",
            match self.speed_check_mode() {
                Some(mode) => format!("{mode:?}"),
                None => "OFF".to_string(),
            }
        );
    }

    pub fn server_name(&self) -> Name {
        match self.server_name {
            Some(ref server_name) => Some(server_name.clone()),
            None => match hostname::get() {
                Ok(name) => match name.to_str() {
                    Some(s) => s.parse().ok(),
                    None => None,
                },
                Err(_) => None,
            },
        }
        .unwrap_or_else(|| crate::NAME.parse().unwrap())
    }

    /// The number of worker threads
    #[inline]
    pub fn num_workers(&self) -> usize {
        use std::num::NonZeroUsize;
        self.num_workers
            .unwrap_or(std::thread::available_parallelism().map_or(1, NonZeroUsize::get))
    }

    pub fn binds(&self) -> &[BindAddrConfig] {
        &self.binds
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
        self.resolv_hostname.unwrap_or(self.hosts_file.is_some())
    }

    /// hosts file path
    #[inline]
    pub fn hosts_file(&self) -> Option<&glob::Pattern> {
        self.hosts_file.as_ref()
    }

    /// Whether to expand the address record corresponding to PTR record
    #[inline]
    pub fn expand_ptr_from_address(&self) -> bool {
        self.expand_ptr_from_address.unwrap_or_default()
    }

    /// whether resolv mdns
    #[inline]
    pub fn mdns_lookup(&self) -> bool {
        self.mdns_lookup.unwrap_or_default()
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

    #[inline]
    pub fn cache_config(&self) -> &CacheConfig {
        &self.cache
    }

    /// dns cache size
    #[inline]
    pub fn cache_size(&self) -> usize {
        self.cache.size.unwrap_or(512)
    }

    /// enable persist cache when restart
    #[inline]
    pub fn cache_persist(&self) -> bool {
        self.cache.persist.unwrap_or(false)
    }

    /// cache save interval
    #[inline]
    pub fn cache_checkpoint_time(&self) -> u64 {
        self.cache.checkpoint_time.unwrap_or(24 * 60 * 60)
    }

    /// cache persist file
    #[inline]
    pub fn cache_file(&self) -> PathBuf {
        self.cache
            .file
            .to_owned()
            .unwrap_or_else(|| std::env::temp_dir().join("smartdns.cache"))
    }

    /// prefetch domain
    #[inline]
    pub fn prefetch_domain(&self) -> bool {
        self.cache.prefetch_domain.unwrap_or_default()
    }

    #[inline]
    pub fn dnsmasq_lease_file(&self) -> Option<&Path> {
        self.dnsmasq_lease_file.as_deref()
    }

    /// cache serve expired
    #[inline]
    pub fn serve_expired(&self) -> bool {
        self.cache.serve_expired.unwrap_or(true)
    }

    /// cache serve expired TTL
    #[inline]
    pub fn serve_expired_ttl(&self) -> u64 {
        self.cache.serve_expired_ttl.unwrap_or(0)
    }

    /// reply TTL value to use when replying with expired data
    #[inline]
    pub fn serve_expired_reply_ttl(&self) -> u64 {
        self.cache.serve_expired_reply_ttl.unwrap_or(5)
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

    pub fn ip_alias(&self) -> &Arc<IpMap<Arc<[IpAddr]>>> {
        &self.ip_alias
    }

    /// speed check mode
    #[inline]
    pub fn speed_check_mode(&self) -> Option<&SpeedCheckModeList> {
        self.speed_check_mode.as_ref()
    }

    /// force AAAA query return SOA
    #[inline]
    pub fn force_aaaa_soa(&self) -> bool {
        self.force_aaaa_soa.unwrap_or_default()
    }

    /// force HTTPS query return SOA
    #[inline]
    pub fn force_https_soa(&self) -> bool {
        self.force_https_soa.unwrap_or_default()
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
        self.local_ttl.or_else(|| self.rr_ttl_min()).unwrap_or(10)
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
    pub fn log_config(&self) -> &LogConfig {
        &self.log
    }

    #[inline]
    pub fn log_enabled(&self) -> bool {
        self.log_num() > 0
    }

    pub fn log_level(&self) -> Option<crate::log::Level> {
        self.log.level
    }

    pub fn log_file(&self) -> PathBuf {
        match self.log.file.as_ref() {
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
        use byte_unit::{Byte, Unit};
        self.log
            .size
            .unwrap_or_else(|| Byte::from_u64_with_unit(128, Unit::KB).unwrap())
            .as_u64()
    }
    #[inline]
    pub fn log_num(&self) -> u64 {
        self.log.num.unwrap_or(2)
    }

    #[inline]
    pub fn log_file_mode(&self) -> u32 {
        self.log.file_mode.map(|m| *m).unwrap_or(0o640)
    }

    #[inline]
    pub fn log_filter(&self) -> Option<&str> {
        self.log.filter.as_deref()
    }

    #[inline]
    pub fn audit_config(&self) -> &AuditConfig {
        &self.audit
    }

    #[inline]
    pub fn audit_enable(&self) -> bool {
        self.audit.enable.unwrap_or_default()
    }

    #[inline]
    pub fn audit_file(&self) -> Option<&Path> {
        self.audit.file.as_deref()
    }

    #[inline]
    pub fn audit_num(&self) -> usize {
        self.audit.num.unwrap_or(2)
    }

    #[inline]
    pub fn audit_size(&self) -> u64 {
        use byte_unit::{Byte, Unit};
        self.audit
            .size
            .unwrap_or_else(|| Byte::from_u64_with_unit(128, Unit::KB).unwrap())
            .as_u64()
    }

    #[inline]
    pub fn audit_file_mode(&self) -> u32 {
        self.audit.file_mode.map(|m| *m).unwrap_or(0o640)
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
    pub fn servers(&self) -> &[NameServerInfo] {
        &self.nameservers
    }

    #[inline]
    pub fn proxies(&self) -> &Arc<HashMap<String, ProxyConfig>> {
        &self.proxy_servers
    }

    #[inline]
    pub fn resolv_file(&self) -> Option<&Path> {
        self.resolv_file.as_deref()
    }

    pub fn valid_nftsets(&self) -> Vec<&ConfigForIP<NFTsetConfig>> {
        self.nftsets
            .iter()
            .flat_map(|x| &x.config)
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|x| !matches!(x, ConfigForIP::None))
            .collect()
    }

    pub fn rule_groups(&self) -> &HashMap<String, RuleGroup> {
        &self.rule_groups
    }

    pub fn rule_group(&self, name: &str) -> &RuleGroup {
        self.rule_groups.get(name).unwrap_or(RuleGroup::empty())
    }

    pub fn client_rules(&self) -> &[ClientRule] {
        &self.client_rules
    }

    #[inline]
    pub fn domain_rule_group(&self, name: &str) -> &DomainRuleMap {
        let name = if name.is_empty() { DEFAULT_GROUP } else { name };
        self.domain_rule_group_map
            .get(name)
            .unwrap_or(DomainRuleMap::empty())
    }

    #[inline]
    pub fn find_domain_rule(&self, domain: &Name, group: &str) -> Option<Arc<DomainRuleTreeNode>> {
        self.domain_rule_group(group)
            .find(domain)
            .or_else(|| self.domain_rule_group(DEFAULT_GROUP).find(domain))
            .cloned()
    }

    fn get_server_group(&self, group: &str) -> Vec<&NameServerInfo> {
        if group == DEFAULT_GROUP {
            self.servers()
                .iter()
                .filter(|s| s.group.iter().any(|g| g == DEFAULT_GROUP) || !s.exclude_default_group)
                .collect::<Vec<_>>()
        } else {
            self.servers()
                .iter()
                .filter(|s| s.group.iter().any(|g| g == group))
                .collect::<Vec<_>>()
        }
    }

    pub fn reload_new(&self) -> anyhow::Result<Arc<RuntimeConfig>> {
        let mut builder = RuntimeConfigBuilder {
            conf_dir: self.conf_dir.clone(),
            conf_file: self.conf_file.clone(),
            ..Self::builder()
        };

        builder.load()?;

        Ok(Arc::new(builder.build()))
    }
}

impl std::ops::Deref for RuntimeConfig {
    type Target = Config;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct RuntimeConfigBuilder {
    conf_dir: PathBuf,
    conf_file: PathBuf,
    config: Config,
    rule_groups: HashMap<String, RuleGroup>,
    rule_group_stack: Vec<(String, RuleGroup)>,
    loaded_files: HashSet<PathBuf>,
    dirs: HashSet<PathBuf>,
}

impl RuntimeConfigBuilder {
    pub fn build(mut self) -> RuntimeConfig {
        let loaded = self.loaded_files.contains(&self.conf_file);
        if !loaded {
            let _ = self.load();
        }

        let conf_file = self.conf_file;
        let conf_dir = self.conf_dir;
        let mut cfg = self.config;

        if !self.rule_group_stack.is_empty() {
            while let Some((name, group)) = self.rule_group_stack.pop() {
                self.rule_groups.entry(name).or_default().merge(group);
            }
        }

        if cfg.binds.is_empty() {
            cfg.binds.push(UdpBindAddrConfig::default().into())
        }

        fn get_ip_set<'a>(ip: &'a IpOrSet, cfg: &'a Config) -> &'a [IpNet] {
            match ip {
                IpOrSet::Net(net) => std::slice::from_ref(net),
                IpOrSet::Set(name) => match cfg.ip_sets.get(name) {
                    Some(net) => net,
                    None => {
                        warn!("unknown ip-set:{name}");
                        &[]
                    }
                },
            }
        }

        let make_ip_set = |set: &[IpOrSet]| {
            let iter = set.iter().flat_map(|ip| get_ip_set(ip, &cfg));
            Arc::new(IpSet::new(iter.copied()))
        };

        let bogus_nxdomain = make_ip_set(&cfg.bogus_nxdomain);
        let blacklist_ip = make_ip_set(&cfg.blacklist_ip);
        let whitelist_ip = make_ip_set(&cfg.whitelist_ip);
        let ignore_ip = make_ip_set(&cfg.ignore_ip);

        let ip_alias = cfg.ip_alias.iter().flat_map(|alias| {
            let to = std::iter::repeat(alias.to.clone());
            get_ip_set(&alias.ip, &cfg).iter().copied().zip(to)
        });
        let ip_alias = Arc::new(IpMap::from_iter(ip_alias));

        for (_, rule) in self.rule_groups.iter_mut() {
            if !rule.cnames.is_empty() {
                rule.cnames.dedup_by(|a, b| a.domain == b.domain);
            }
        }

        let mut domain_sets: HashMap<String, HashSet<WildcardName>> = HashMap::new();

        for (set_name, providers) in &cfg.domain_set_providers {
            let set = domain_sets.entry(set_name.to_string()).or_default();
            for p in providers.iter() {
                match p.get_domain_set() {
                    Ok(s) => {
                        log::info!("DoaminSet load {} records into {}", s.len(), p.name());
                        set.extend(s);
                    }
                    Err(err) => {
                        log::error!("DoaminSet load failed {} {}", p.name(), err);
                    }
                }
            }
        }

        let mut domain_rule_group_map = HashMap::new();

        let mut rule_map = Default::default();

        for (group_name, rule_group) in &self.rule_groups {
            let domain_rule_map = DomainRuleMap::create(
                &mut rule_map,
                &rule_group.domain_rules,
                &rule_group.address_rules,
                &rule_group.forward_rules,
                &domain_sets,
                &rule_group.cnames,
                &rule_group.srv_records,
                &rule_group.https_records,
                &cfg.nftsets,
            );
            domain_rule_group_map.insert(group_name.to_string(), domain_rule_map);
        }

        let domain_rule_map = domain_rule_group_map
            .get(DEFAULT_GROUP)
            .unwrap_or(DomainRuleMap::empty());

        // set nameserver group for bootstraping
        for server in cfg.nameservers.iter_mut() {
            if server.server.ip().is_none() {
                let host = server.server.host().to_string();
                if let Ok(Some(rule)) = host
                    .as_str()
                    .parse()
                    .map(|domain| domain_rule_map.find(&domain))
                {
                    server.resolve_group = rule.get(|r| r.nameserver.clone());
                }
            }
        }

        // find device address
        {
            if !cfg.binds.is_empty() {
                use local_ip_address::list_afinet_netifas;
                match list_afinet_netifas() {
                    Ok(network_interfaces) => {
                        for listener in &mut cfg.binds {
                            let device = match listener.device() {
                                Some(v) => v,
                                None => continue,
                            };

                            let ips = network_interfaces
                                .iter()
                                .filter(|(dev, _ip)| dev == device)
                                .map(|(_, ip)| *ip)
                                .collect::<Vec<_>>();

                            if ips.is_empty() {
                                warn!("network device {} not found.", device);
                            }

                            let ip = ips.into_iter().find(|ip| match listener.addr() {
                                BindAddr::Localhost => true,
                                BindAddr::All => true,
                                BindAddr::V4(_) => ip.is_ipv4(),
                                BindAddr::V6(_) => ip.is_ipv6() && !matches!(ip, IpAddr::V6(ipv6) if (ipv6.segments()[0] & 0xffc0) == 0xfe80),
                            });

                            match ip {
                                Some(ip) => *listener.mut_addr() = ip.into(),
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
        }

        // dedup bind address
        {
            let mut udp_addr = HashSet::new();
            let mut tcp_addr = HashSet::new();

            let mut remove_idx = vec![];
            for (idx, listener) in cfg.binds.iter().enumerate().rev() {
                let addr = listener.sock_addr();
                if matches!(
                    listener,
                    BindAddrConfig::Udp(_) | BindAddrConfig::Quic(_) | BindAddrConfig::H3(_)
                ) {
                    if !udp_addr.insert(addr) {
                        remove_idx.push(idx)
                    }
                } else if !tcp_addr.insert(addr) {
                    remove_idx.push(idx)
                }
            }

            for idx in remove_idx {
                let listener = cfg.binds.remove(idx);
                warn!("remove duplicated listener {:?}", listener);
            }
        }

        let mut proxy_servers = HashMap::with_capacity(0);

        std::mem::swap(&mut proxy_servers, &mut cfg.proxy_servers);

        RuntimeConfig {
            conf_dir,
            conf_file,
            inner: cfg,
            rule_groups: self.rule_groups,
            domain_rule_group_map,
            bogus_nxdomain,
            blacklist_ip,
            whitelist_ip,
            ignore_ip,
            ip_alias,
            proxy_servers: Arc::new(proxy_servers),
        }
    }
}

impl std::ops::Deref for RuntimeConfigBuilder {
    type Target = Config;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl std::ops::DerefMut for RuntimeConfigBuilder {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}

impl RuntimeConfigBuilder {
    pub fn with(mut self, config: &str) -> Self {
        self.config(config);
        self
    }

    pub fn with_conf_file<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.conf_file = path.as_ref().to_path_buf();
        self
    }

    pub fn with_conf_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.conf_dir = path.as_ref().to_path_buf();
        self
    }

    pub fn load(&mut self) -> anyhow::Result<()> {
        self.load_file(self.conf_file.clone())?;
        Ok(())
    }

    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        let path = self.resolve_filepath(path);

        if path.exists() {
            debug!("loading extra configuration from {:?}", path);
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                self.config(line.as_str());
            }
        } else {
            warn!("configuration file {:?} does not exist", path);
        }

        Ok(())
    }

    pub fn config(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return;
        }
        use crate::config::parser::OneConfig::*;
        let rule_group = match self.rule_group_stack.last_mut() {
            Some((_, rule_group)) => rule_group,
            None => {
                self.rule_group_stack
                    .push((DEFAULT_GROUP.to_string(), RuleGroup::default()));
                &mut self.rule_group_stack.last_mut().unwrap().1
            }
        };

        match parser::parse_config(line) {
            Ok((_, config_item)) => match config_item {
                AuditEnable(v) => self.audit.enable = Some(v),
                AuditFile(v) => self.audit.file = Some(v),
                AuditFileMode(v) => self.audit.file_mode = Some(v),
                AuditNum(v) => self.audit.num = Some(v),
                AuditSize(v) => self.audit.size = Some(v),
                BindCertFile(v) => self.bind_cert_file = Some(self.resolve_filepath(v)),
                BindCertKeyFile(v) => self.bind_cert_key_file = Some(self.resolve_filepath(v)),
                BindCertKeyPass(v) => self.bind_cert_key_pass = Some(v),
                CacheFile(v) => self.cache.file = Some(v),
                CachePersist(v) => self.cache.persist = Some(v),
                CacheCheckpointTime(v) => self.cache.checkpoint_time = Some(v),
                CNAME(v) => rule_group.cnames.push(v),
                Dns64(v) => self.dns64_prefix = Some(v),
                ExpandPtrFromAddress(v) => self.expand_ptr_from_address = Some(v),
                NftSet(v) => self.nftsets.push(v),
                HttpsRecord(v) => rule_group.https_records.push(v),
                Server(server) => self.nameservers.push(server),
                ResponseMode(mode) => self.response_mode = Some(mode),
                ResolvHostname(v) => self.resolv_hostname = Some(v),
                ServeExpired(v) => self.cache.serve_expired = Some(v),
                PrefetchDomain(v) => self.cache.prefetch_domain = Some(v),
                ForceAAAASOA(v) => self.force_aaaa_soa = Some(v),
                ForceHTTPSSOA(v) => self.force_https_soa = Some(v),
                DualstackIpAllowForceAAAA(v) => self.dualstack_ip_allow_force_aaaa = Some(v),
                DualstackIpSelection(v) => self.dualstack_ip_selection = Some(v),
                ServerName(v) => self.server_name = Some(v),
                NumWorkers(v) => self.num_workers = Some(v),
                Domain(v) => self.domain = Some(v),
                SpeedMode(v) => self.speed_check_mode = v,
                ServeExpiredTtl(v) => self.cache.serve_expired_ttl = Some(v),
                ServeExpiredReplyTtl(v) => self.cache.serve_expired_reply_ttl = Some(v),
                CacheSize(v) => self.cache.size = Some(v),
                ForceQtypeSoa(v) => {
                    self.force_qtype_soa.insert(v);
                }
                DualstackIpSelectionThreshold(v) => self.dualstack_ip_selection_threshold = Some(v),
                RrTtl(v) => self.rr_ttl = Some(v),
                RrTtlMin(v) => self.rr_ttl_min = Some(v),
                RrTtlMax(v) => self.rr_ttl_max = Some(v),
                RrTtlReplyMax(v) => self.rr_ttl_reply_max = Some(v),
                Listener(listener) => self.binds.push(listener),
                LocalTtl(v) => self.local_ttl = Some(v),
                LogConsole(v) => self.log.console = Some(v),
                LogNum(v) => self.log.num = Some(v),
                LogLevel(v) => self.log.level = Some(v),
                LogFile(v) => self.log.file = Some(v),
                LogFileMode(v) => self.log.file_mode = Some(v),
                LogFilter(v) => self.log.filter = Some(v),
                LogSize(v) => self.log.size = Some(v),
                MaxReplyIpNum(v) => self.max_reply_ip_num = Some(v),
                BlacklistIp(v) => self.blacklist_ip.push(v),
                BogusNxDomain(v) => self.bogus_nxdomain.push(v),
                WhitelistIp(v) => self.whitelist_ip.push(v),
                IgnoreIp(v) => self.ignore_ip.push(v),
                CaFile(v) => self.ca_file = Some(v),
                CaPath(v) => self.ca_path = Some(v),
                ConfFile(v) => {
                    if !self.loaded_files.contains(&v) {
                        self.load_file(v.clone()).expect("load_file failed");
                        if let Some(dir) = v.parent() {
                            self.dirs.insert(dir.to_path_buf());
                        }

                        self.loaded_files.insert(v);
                    }
                }
                DnsmasqLeaseFile(v) => self.dnsmasq_lease_file = Some(v),
                ResolvFile(v) => self.resolv_file = Some(v),
                SrvRecord(v) => rule_group.srv_records.push(v),
                DomainRule(v) => rule_group.domain_rules.push(v),
                ForwardRule(v) => rule_group.forward_rules.push(v),
                User(v) => self.user = Some(v),
                TcpIdleTime(v) => self.tcp_idle_time = Some(v),
                EdnsClientSubnet(v) => self.edns_client_subnet = Some(v),
                Address(v) => rule_group.address_rules.push(v),
                DomainSetProvider(mut v) => {
                    use crate::config::DomainSetProvider;
                    if let DomainSetProvider::File(provider) = &mut v {
                        provider.file = self.resolve_filepath(&provider.file);
                    }
                    self.domain_set_providers
                        .entry(v.name().to_string())
                        .or_default()
                        .push(v);
                }
                ProxyConfig(v) => {
                    self.proxy_servers.insert(v.name.clone(), v.config);
                }
                HostsFile(file) => self.hosts_file = Some(file),
                IpSetProvider(p) => {
                    let path = resolve_filepath(&p.file, Some(&self.conf_file));
                    match std::fs::read_to_string(path) {
                        Ok(text) => {
                            let net = self.ip_sets.entry(p.name.clone()).or_default();
                            let len = net.len();
                            net.extend(parse_ip_set_file(&text));
                            log::info!("IpSet load {} records into {}", net.len() - len, p.name);
                        }
                        Err(err) => {
                            log::error!("IpSet load failed {} {}", p.name, err);
                        }
                    }
                }
                MdnsLookup(enable) => self.mdns_lookup = Some(enable),
                IpAlias(alias) => self.ip_alias.push(alias),
                GroupBegin(v) => {
                    self.rule_group_stack
                        .push((v.clone(), RuleGroup::default()));
                }
                GroupEnd => {
                    if let Some((name, rule_group)) = self.rule_group_stack.pop() {
                        let group = self.rule_groups.entry(name).or_default();
                        group.merge(rule_group);
                    }
                }
                ClientRule(client_rule) => self.client_rules.push(client_rule),
            },
            Err(err) => {
                warn!("unknown conf: {}, {:?}", line, err);
            }
        }
    }

    #[inline]
    fn resolve_filepath<P: AsRef<Path>>(&self, filepath: P) -> PathBuf {
        let path = resolve_filepath(filepath, Some(&self.conf_file));

        if path.exists() {
            return path;
        }
        let Some(name) = path.file_name() else {
            return path;
        };

        for dir in self.dirs.iter() {
            let p = dir.join(name);
            if p.is_file() {
                return p;
            }
        }
        path
    }
}

fn resolve_filepath<P: AsRef<Path>>(filepath: P, base_file: Option<&PathBuf>) -> PathBuf {
    let filepath = filepath.as_ref();
    if filepath.is_file() {
        return filepath.to_path_buf();
    }

    if !filepath.is_absolute() {
        if let Some(base_conf_file) = base_file {
            if let Some(dir) = base_conf_file.parent() {
                let new_path = dir.join(filepath);

                if new_path.is_file() {
                    return new_path;
                }

                if matches!(base_conf_file.file_name(), Some(file_name) if file_name == OsStr::new("smartdns.conf"))
                {
                    // eg: /etc/smartdns.d/custom.conf
                    let new_path = dir.join("smartdns.d").join(filepath);

                    if new_path.is_file() {
                        return new_path;
                    }
                }

                if let Ok(new_path) = std::env::current_dir().map(|dir| dir.join(filepath)) {
                    if new_path.is_file() {
                        return new_path;
                    }
                }

                if let Some(new_path) = std::env::current_exe()
                    .ok()
                    .and_then(|exe| exe.parent().map(|dir| dir.join(filepath)))
                {
                    if new_path.is_file() {
                        return new_path;
                    }
                }
            }
        }
    }

    // try to resolve absolute path by extracting its file_name
    match filepath.file_name().map(Path::new) {
        Some(new_path) if new_path != filepath => {
            let new_path = resolve_filepath(new_path, base_file);
            if new_path.is_file() {
                log::warn!(
                    "File {} not found, but {} found",
                    filepath.display(),
                    new_path.display()
                );
                return new_path;
            }
        }
        _ => (),
    }

    filepath.to_path_buf()
}

#[cfg(test)]
mod tests {
    use crate::{dns::DomainRuleGetter, libdns::Protocol};
    use byte_unit::Byte;

    use crate::config::{BindAddr, HttpsBindAddrConfig, ServerOpts, SslConfig};

    use super::*;

    #[test]
    fn test_config_binds_dedup() {
        let cfg = RuntimeConfig::builder()
            .with("bind-tcp 0.0.0.0:4453@eth1")
            .with("bind-tls 0.0.0.0:4452@eth1")
            .with("bind-https 0.0.0.0:4453@eth1")
            .build();

        assert_eq!(
            cfg.binds()
                .iter()
                .filter(|x| matches!(x, BindAddrConfig::Tcp(_)))
                .count(),
            0
        );
        assert_eq!(
            cfg.binds()
                .iter()
                .filter(|x| matches!(x, BindAddrConfig::Tls(_)))
                .count(),
            1
        );
        assert_eq!(
            cfg.binds()
                .iter()
                .filter(|x| matches!(x, BindAddrConfig::Https(_)))
                .count(),
            1
        );
    }

    #[test]
    fn test_config_bind_with_device() {
        let cfg = RuntimeConfig::builder()
            .with("bind 0.0.0.0:4453@eth100")
            .with("bind 0.0.0.0:4453@eth100")
            .build();

        assert_eq!(cfg.binds().len(), 1);

        let bind = cfg.binds().first().unwrap();

        assert_eq!(bind.addr(), BindAddr::V4("0.0.0.0".parse().unwrap()));
        assert_eq!(bind.port(), 4453);

        assert_eq!(bind.device(), Some("eth100"));
    }

    #[test]
    fn test_config_bind_with_device_flags() {
        let cfg = RuntimeConfig::builder()
            .with("bind-https 0.0.0.0:443@eth2 -no-rule-addr")
            .build();

        let listener = cfg.binds().first().unwrap();

        assert_eq!(
            listener,
            &BindAddrConfig::Https(HttpsBindAddrConfig {
                addr: BindAddr::V4("0.0.0.0".parse().unwrap()),
                port: 443,
                device: Some("eth2".to_string()),
                opts: ServerOpts {
                    no_rule_addr: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            })
        );
    }

    #[test]
    fn test_config_bind_https() {
        let mut cfg = RuntimeConfig::builder();

        cfg.config(
                "bind-https 0.0.0.0:4453 -server-name dns.example.com -ssl-certificate /etc/nginx/dns.example.com.crt -ssl-certificate-key /etc/nginx/dns.example.com.key",
            );

        let cfg = cfg.build();

        assert!(!cfg.binds().is_empty());

        let listener = cfg.binds().first().unwrap();

        assert_eq!(
            listener,
            &BindAddrConfig::Https(HttpsBindAddrConfig {
                addr: BindAddr::V4("0.0.0.0".parse().unwrap()),
                port: 4453,
                ssl_config: SslConfig {
                    server_name: Some("dns.example.com".to_string()),
                    certificate: Some(Path::new("/etc/nginx/dns.example.com.crt").to_path_buf()),
                    certificate_key: Some(
                        Path::new("/etc/nginx/dns.example.com.key").to_path_buf()
                    ),
                    certificate_key_pass: None
                },
                ..Default::default()
            })
        );
    }

    #[test]
    fn test_config_server_0() {
        let cfg = RuntimeConfig::builder()
            .with(
                "server-https https://223.5.5.5/dns-query -group bootstrap -exclude-default-group",
            )
            .build();

        assert_eq!(cfg.get_server_group("bootstrap").len(), 1);

        let server_group = cfg.get_server_group("bootstrap");
        let server = server_group.first().cloned().unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");

        assert!(server.group.iter().any(|g| g == "bootstrap"));
        assert!(server.exclude_default_group);
    }

    #[test]
    fn test_config_server_1() {
        let cfg = RuntimeConfig::builder()
            .with("server-https https://223.5.5.5/dns-query")
            .build();

        assert_eq!(cfg.nameservers.len(), 1);

        let server_group = cfg.get_server_group(DEFAULT_GROUP);

        let server = server_group.first().cloned().unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert!(server.group.is_empty());
        assert!(!server.exclude_default_group);
    }

    #[test]
    fn test_config_server_2() {
        let cfg = RuntimeConfig::builder()
            .with("server-https https://223.5.5.5/dns-query  -bootstrap-dns -exclude-default-group")
            .build();

        let server = cfg.nameservers.iter().find(|s| s.bootstrap_dns).unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert!(server.exclude_default_group);
        assert!(server.bootstrap_dns);
    }

    #[test]
    fn test_config_server_with_client_subnet() {
        let cfg = RuntimeConfig::builder().with(
                "server-https https://223.5.5.5/dns-query  -bootstrap-dns -exclude-default-group -subnet 192.168.0.0/16",
            ).build();

        let server = cfg.nameservers.iter().find(|s| s.bootstrap_dns).unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert_eq!(server.subnet, Some("192.168.0.0/16".parse().unwrap()));
        assert!(server.exclude_default_group);
        assert!(server.bootstrap_dns);
    }

    #[test]
    fn test_config_server_with_mark_1() {
        let cfg = RuntimeConfig::builder()
            .with("server-https https://223.5.5.5/dns-query -set-mark 255")
            .build();
        let server = cfg.nameservers.first().unwrap();
        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert_eq!(server.so_mark, Some(255));
    }

    #[test]
    fn test_config_server_with_mark_2() {
        let cfg = RuntimeConfig::builder()
            .with("server-https https://223.5.5.5/dns-query -set-mark 0xff")
            .build();

        let server = cfg.nameservers.first().unwrap();

        assert_eq!(server.server.proto(), &Protocol::Https);
        assert_eq!(server.server.to_string(), "https://223.5.5.5/dns-query");
        assert_eq!(server.so_mark, Some(255));
    }

    #[test]
    fn test_config_tls_server() {
        let cfg = RuntimeConfig::builder()
            .with(
                "server-tls 45.90.28.0 -host-name: dns.nextdns.io -tls-host-verify: dns.nextdns.io",
            )
            .build();

        let server = cfg.nameservers.first().unwrap();

        assert!(!server.exclude_default_group);
        assert_eq!(server.server.proto(), &Protocol::Tls);
        assert_eq!(server.server.to_string(), "tls://dns.nextdns.io");
        assert_eq!(server.server.ip(), "45.90.28.0".parse::<IpAddr>().ok());
        assert_eq!(server.server.domain(), Some("dns.nextdns.io"));
    }

    #[test]
    fn test_config_address_soa() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/#");

        let cfg = builder.build();

        let domain_addr_rule = cfg
            .rule_groups
            .get(DEFAULT_GROUP)
            .unwrap()
            .address_rules
            .last()
            .unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::SOA);
    }

    #[test]
    fn test_config_domain_rules_without_args() {
        let mut builder = RuntimeConfig::builder();
        builder
            .config("domain-set -name domain-forwarding-list -file tests/test_data/block-list.txt");
        builder.config("domain-rules /domain-set:domain-forwarding-list/");
        let cfg = builder.build();
        assert!(
            cfg.rule_groups
                .get(DEFAULT_GROUP)
                .unwrap()
                .address_rules
                .last()
                .is_none()
        );
    }

    #[test]
    fn test_config_address_soa_v4() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/#4");

        let cfg = builder.build();

        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.last().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::SOAv4);
    }

    #[test]
    fn test_config_address_soa_v6() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/#6");

        let cfg = builder.build();

        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.last().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::SOAv6);
    }

    #[test]
    fn test_config_address_ignore() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/-");

        let cfg = builder.build();
        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.last().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::IGN);
    }

    #[test]
    fn test_config_address_ignore_v4() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/-4");

        let cfg = builder.build();
        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.last().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::IGNv4);
    }

    #[test]
    fn test_config_address_ignore_v6() {
        let mut builder = RuntimeConfig::builder();

        builder.config("address /test.example.com/-6");

        let cfg = builder.build();
        let domain_addr_rule = cfg.rule_group(DEFAULT_GROUP).address_rules.first().unwrap();

        assert_eq!(
            domain_addr_rule.domain,
            Domain::Name("test.example.com".parse().unwrap())
        );

        assert_eq!(domain_addr_rule.address, AddressRuleValue::IGNv6);
    }

    #[test]
    fn test_config_address_whitelist_mode() {
        let cfg = RuntimeConfig::builder()
            .with("address /google.com/-")
            .with("address /./#")
            .build();

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"cloudflare.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"google.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::IGN)
        );
    }

    #[test]
    fn test_config_address_wildcard_1() {
        let cfg = RuntimeConfig::builder()
            .with("address /-.example.com/#")
            .build();
        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"aa.example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            None
        );
    }

    #[test]
    fn test_config_address_wildcard_2() {
        let cfg = RuntimeConfig::builder().with("address /*/#").build();
        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"localhost".parse().unwrap())
                .cloned()
                .get_ref(|n| n.address.as_ref()),
            Some(&AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"aa.example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            None
        );
    }

    #[test]
    fn test_config_address_wildcard_3() {
        let cfg = RuntimeConfig::builder().with("address /+/#").build();
        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"localhost".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"aa.example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );
    }

    #[test]
    fn test_config_address_wildcard_4() {
        let cfg = RuntimeConfig::builder().with("address /./#").build();
        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"localhost".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );

        assert_eq!(
            cfg.domain_rule_group("default")
                .find(&"aa.example.com".parse().unwrap())
                .cloned()
                .get(|n| n.address.clone()),
            Some(AddressRuleValue::SOA)
        );
    }

    #[test]
    fn test_config_nameserver() {
        let mut builder = RuntimeConfig::builder();

        builder.config("nameserver /doh.pub/bootstrap");

        let cfg = builder.build();
        let nameserver_rule = cfg
            .rule_groups
            .get(DEFAULT_GROUP)
            .unwrap()
            .forward_rules
            .first()
            .unwrap();

        assert_eq!(
            nameserver_rule.domain,
            Domain::Name("doh.pub".parse().unwrap())
        );

        assert_eq!(nameserver_rule.nameserver, "bootstrap");
    }

    #[test]
    fn test_config_domain_rule() {
        let mut builder = RuntimeConfig::builder();

        builder.config("domain-rule /doh.pub/ -c ping -a 127.0.0.1 -n test -d yes");

        let cfg = builder.build();
        let domain_rule = cfg.rule_group(DEFAULT_GROUP).domain_rules.first().unwrap();

        assert_eq!(domain_rule.domain, Domain::Name("doh.pub".parse().unwrap()));
        assert_eq!(
            domain_rule.address,
            Some(AddressRuleValue::Addr {
                v4: Some(["127.0.0.1".parse().unwrap()].into()),
                v6: None
            })
        );
        assert_eq!(
            domain_rule.speed_check_mode,
            Some(vec![SpeedCheckMode::Ping].into())
        );
        assert_eq!(domain_rule.nameserver, Some("test".to_string()));
        assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
    }

    #[test]
    fn test_config_domain_rule_2() {
        let mut builder = RuntimeConfig::builder();

        builder.config("domain-rules /doh.pub/ -c ping -a 127.0.0.1 -n test -d yes");

        let cfg = builder.build();
        let domain_rule = cfg.rule_group(DEFAULT_GROUP).domain_rules.first().unwrap();

        assert_eq!(domain_rule.domain, Domain::Name("doh.pub".parse().unwrap()));
        assert_eq!(
            domain_rule.address,
            Some(AddressRuleValue::Addr {
                v4: Some(["127.0.0.1".parse().unwrap()].into()),
                v6: None
            })
        );
        assert_eq!(
            domain_rule.speed_check_mode,
            Some(vec![SpeedCheckMode::Ping].into())
        );
        assert_eq!(domain_rule.nameserver, Some("test".to_string()));
        assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
    }

    #[test]
    fn test_config_domain_rule_3() {
        let cfg = RuntimeConfig::builder()
            .with("domain-rules /doh.pub/ -c ping -a # -n test -d yes")
            .build();

        let domain_rule = cfg
            .domain_rule_group("default")
            .find(&"doh.pub".parse().unwrap())
            .cloned()
            .unwrap();

        assert_eq!(domain_rule.name(), &"doh.pub".parse().unwrap());
        assert_eq!(domain_rule.address, Some(AddressRuleValue::SOA));
        assert_eq!(
            domain_rule.speed_check_mode,
            Some(vec![SpeedCheckMode::Ping].into())
        );
        assert_eq!(domain_rule.nameserver, Some("test".to_string()));
        assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
    }

    #[test]
    fn test_parse_config_log_file_mode() {
        let mut cfg = RuntimeConfig::builder();

        cfg.config("log-file-mode 644");
        assert_eq!(cfg.log.file_mode, Some(0o644u32.into()));
        cfg.config("log-file-mode 0o755");
        assert_eq!(cfg.log.file_mode, Some(0o755u32.into()));
    }

    #[test]
    fn test_parse_config_speed_check_mode() {
        let mut cfg = RuntimeConfig::builder();
        cfg.config("speed-check-mode ping,tcp:123");

        assert_eq!(cfg.speed_check_mode.as_ref().unwrap().len(), 2);

        assert_eq!(
            cfg.speed_check_mode.as_ref().unwrap().first().unwrap(),
            &SpeedCheckMode::Ping
        );
        assert_eq!(
            cfg.speed_check_mode.as_ref().unwrap().get(1).unwrap(),
            &SpeedCheckMode::Tcp(123)
        );
    }

    #[test]
    fn test_parse_config_speed_check_mode_https_omit_port() {
        let mut cfg = RuntimeConfig::builder();
        cfg.config("speed-check-mode http,https");

        assert_eq!(cfg.speed_check_mode.as_ref().unwrap().len(), 2);

        assert_eq!(
            cfg.speed_check_mode.as_ref().unwrap().first().unwrap(),
            &SpeedCheckMode::Http(80)
        );
        assert_eq!(
            cfg.speed_check_mode.as_ref().unwrap().get(1).unwrap(),
            &SpeedCheckMode::Https(443)
        );
    }

    #[test]
    fn test_default_audit_size_1() {
        use byte_unit::Unit;
        let cfg = RuntimeConfig::builder().build();
        assert_eq!(
            cfg.audit_size(),
            Byte::from_i64_with_unit(128, Unit::KB).unwrap().as_u64()
        );
    }

    #[test]
    fn test_parse_config_audit_size_1() {
        use byte_unit::Unit;
        let mut cfg = RuntimeConfig::builder();
        cfg.config("audit-size 80mb");
        assert_eq!(cfg.audit.size, Byte::from_i64_with_unit(80, Unit::MB));
    }

    #[test]
    fn test_parse_config_audit_size_2() {
        use byte_unit::Unit;
        let mut cfg = RuntimeConfig::builder();
        cfg.config("audit-size 30 gb");
        assert_eq!(cfg.audit.size, Byte::from_i64_with_unit(30, Unit::GB));
    }

    #[test]
    fn test_parse_load_config_file_b() {
        let cfg = RuntimeConfig::builder()
            .with_conf_file("tests/test_data/b_main.conf")
            .build();

        assert_eq!(cfg.server_name, "SmartDNS123".parse().ok());
        assert_eq!(
            cfg.rule_group(DEFAULT_GROUP)
                .forward_rules
                .first()
                .unwrap()
                .domain,
            Domain::Name("doh.pub".parse().unwrap())
        );
        assert_eq!(
            cfg.rule_group(DEFAULT_GROUP)
                .forward_rules
                .first()
                .unwrap()
                .nameserver,
            "bootstrap"
        );
    }

    #[test]
    fn test_parse_config_proxy_server() {
        let mut cfg = RuntimeConfig::builder();
        cfg.config("proxy-server socks5://127.0.0.1:1080 -n abc");

        assert_eq!(
            cfg.proxy_servers.get("abc").map(|s| s.to_string()),
            Some("socks5://127.0.0.1:1080".to_string())
        );
    }

    #[test]
    fn test_domain_set() {
        use crate::collections::DomainSet;

        let cfg = RuntimeConfig::builder()
            .with_conf_file("tests/test_data/b_main.conf")
            .build();

        assert!(!cfg.domain_set_providers.is_empty());

        let domain_set_providers = cfg
            .domain_set_providers
            .get("block")
            .map(|s| s.as_slice())
            .unwrap_or_default();

        let domain_set = domain_set_providers
            .iter()
            .flat_map(|p| p.get_domain_set().unwrap_or_default())
            .collect::<DomainSet>();

        assert!(!domain_set.is_empty());

        assert!(domain_set.contains(&"ads1.com".parse().unwrap()));
        assert!(!domain_set.contains(&"ads2c.cn".parse().unwrap()));
        // assert!(domain_set.is_match(&Name::from_str("ads3.net").unwrap().into()));
        // assert!(domain_set.is_match(&Name::from_str("q.ads3.net").unwrap().into()));
    }

    #[test]
    fn test_parse_https_record() {
        let cfg = RuntimeConfig::builder().with("https-record #").build();
        assert_eq!(cfg.rule_group(DEFAULT_GROUP).https_records.len(), 1);
        assert_eq!(
            cfg.rule_group(DEFAULT_GROUP).https_records[0].config,
            HttpsRecordRule::SOA
        );
    }

    #[test]
    fn test_ip_set() {
        let cfg = RuntimeConfig::builder()
            .with_conf_file("tests/test_data/b_main.conf")
            .build();

        let v4: Vec<_> = include_str!("../tests/test_data/cf-ipv4.txt")
            .lines()
            .map(|line| line.parse().unwrap())
            .collect();
        let v6: Vec<_> = include_str!("../tests/test_data/cf-ipv6.txt")
            .lines()
            .map(|line| line.parse().unwrap())
            .collect();
        let all: [&[_]; 3] = [&["1.1.1.1/32".parse().unwrap()], &v4, &v6];
        let all = IpSet::new(all.into_iter().flatten().copied());

        assert_eq!(cfg.ip_sets["cf-ipv4"], v4);
        assert_eq!(cfg.ip_sets["cf-ipv6"], v6);
        assert_eq!(*cfg.whitelist_ip, all);
    }

    #[test]
    fn test_ip_alias() {
        let cfg = RuntimeConfig::builder()
            .with_conf_file("tests/test_data/b_main.conf")
            .build();
        let addr = |s: &str| s.parse::<IpAddr>().unwrap();
        let get_alias = |s: &str| &**cfg.ip_alias.get(&addr(s)).unwrap();

        assert_eq!(get_alias("104.16.0.0"), [addr("1.2.3.4"), addr("::5678")]);
        assert_eq!(get_alias("2400:cb00::"), [addr("::1234"), addr("5.6.7.8")]);
        assert_eq!(get_alias("172.64.0.0"), [addr("90AB::CDEF")]);
    }

    #[test]
    fn test_rule_group() {
        let cfg = RuntimeConfig::builder()
            .with("address /example.com/1.2.3.4")
            .with("group-begin a")
            .with("address /example.com/1.2.3.5")
            .with("group-end")
            .with("group-begin b")
            .with("address /example.com/1.2.3.6")
            .build();

        let g0 = cfg.rule_group("default");
        let g1 = cfg.rule_group("a");
        let g2 = cfg.rule_group("b");

        assert_eq!(
            g0.address_rules.first().unwrap().address,
            AddressRuleValue::Addr {
                v4: Some(vec!["1.2.3.4".parse().unwrap()].into()),
                v6: None
            }
        );
        assert_eq!(
            g1.address_rules.first().unwrap().address,
            AddressRuleValue::Addr {
                v4: Some(vec!["1.2.3.5".parse().unwrap()].into()),
                v6: None
            }
        );
        assert_eq!(
            g2.address_rules.first().unwrap().address,
            AddressRuleValue::Addr {
                v4: Some(vec!["1.2.3.6".parse().unwrap()].into()),
                v6: None
            }
        );
    }
}
