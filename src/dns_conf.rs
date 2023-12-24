use cfg_if::cfg_if;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use crate::config::*;
use crate::{
    dns_rule::{DomainRuleMap, DomainRuleTreeNode},
    infra::ipset::IpSet,
    libdns::proto::rr::{Name, RecordType},
    log::{debug, info, warn},
    proxy::ProxyConfig,
};

const DEFAULT_GROUP: &str = "default";

#[derive(Default)]
pub struct RuntimeConfig {
    inner: Config,

    domain_rule_map: DomainRuleMap,

    proxy_servers: Arc<HashMap<String, ProxyConfig>>,

    /// List of hosts that supply bogus NX domain results
    bogus_nxdomain: Arc<IpSet>,

    /// List of IPs that will be filtered when nameserver is configured -blacklist-ip parameter
    blacklist_ip: Arc<IpSet>,

    /// List of IPs that will be accepted when nameserver is configured -whitelist-ip parameter
    whitelist_ip: Arc<IpSet>,

    /// List of IPs that will be ignored
    ignore_ip: Arc<IpSet>,
}

impl RuntimeConfig {
    pub fn load<P: AsRef<Path>>(path: Option<P>) -> Arc<Self> {
        if let Some(ref conf) = path {
            let path = conf.as_ref();

            RuntimeConfig::load_from_file(path)
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

            candidate_path
                .iter()
                .map(Path::new)
                .filter(|p| p.exists())
                .map(RuntimeConfig::load_from_file)
                .next()
                .expect("No configuation file found.")
        }
    }

    fn load_from_file<P: AsRef<Path>>(path: P) -> Arc<Self> {
        let path = path.as_ref();

        let mut builder = Self::builder();
        if !path.exists() {
            panic!("configuration file {:?} not exist.", path);
        }
        builder.load_file(path).expect("load conf file filed");
        builder.build().into()
    }

    pub fn builder() -> RuntimeConfigBuilder {
        RuntimeConfigBuilder(Config {
            ..Default::default()
        })
    }
}

impl RuntimeConfig {
    /// Print the config summary.
    pub fn summary(&self) {
        info!(r#"whoami 👉 {}"#, self.server_name());

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
                    Some(s) => format!("over {}", s),
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
    pub fn num_workers(&self) -> Option<usize> {
        self.num_workers
    }

    pub fn listeners(&self) -> &[ListenerConfig] {
        &self.listeners
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

    #[inline]
    pub fn cache_config(&self) -> &CacheConfig {
        &self.cache
    }

    /// dns cache size
    #[inline]
    pub fn cache_size(&self) -> usize {
        self.cache.size.unwrap_or(512)
    }

    ///  enable persist cache when restart
    #[inline]
    pub fn cache_persist(&self) -> bool {
        self.cache.persist.unwrap_or(false)
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
    pub fn log_config(&self) -> &LogConfig {
        &self.log
    }

    #[inline]
    pub fn log_enabled(&self) -> bool {
        self.log_num() > 0
    }
    pub fn log_level(&self) -> crate::log::Level {
        self.log.level.unwrap_or(crate::log::Level::ERROR)
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
    pub fn resolv_file(&self) -> Option<&Path> {
        self.resolv_file.as_deref()
    }

    #[inline]
    pub fn cnames(&self) -> &CNameRules {
        &self.cnames
    }

    pub fn valid_nftsets(&self) -> Vec<&ConfigForIP<NftsetConfig>> {
        self.nftsets
            .iter()
            .flat_map(|x| &x.config)
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|x| !matches!(x, ConfigForIP::None))
            .collect()
    }

    #[inline]
    pub fn find_domain_rule(&self, domain: &Name) -> Option<Arc<DomainRuleTreeNode>> {
        self.domain_rule_map.find(domain).cloned()
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
}

impl std::ops::Deref for RuntimeConfig {
    type Target = Config;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct RuntimeConfigBuilder(Config);

impl RuntimeConfigBuilder {
    pub fn build(self) -> RuntimeConfig {
        let mut cfg = self.0;

        if cfg.listeners.is_empty() {
            cfg.listeners.push(UdpListenerConfig::default().into())
        }

        let bogus_nxdomain: Arc<IpSet> = cfg.bogus_nxdomain.compact().into();
        let blacklist_ip: Arc<IpSet> = cfg.blacklist_ip.compact().into();
        let whitelist_ip: Arc<IpSet> = cfg.whitelist_ip.compact().into();
        let ignore_ip: Arc<IpSet> = cfg.ignore_ip.compact().into();

        if !cfg.cnames.is_empty() {
            cfg.cnames.dedup_by(|a, b| a.domain == b.domain);
        }

        let mut domain_sets: HashMap<String, HashSet<Name>> = HashMap::new();

        for provider in cfg.domain_set_providers.values() {
            if let Ok(set) = provider.get_domain_set() {
                domain_sets
                    .entry(provider.name().to_string())
                    .or_default()
                    .extend(set);
            }
        }

        let domain_rule_map = DomainRuleMap::create(
            &cfg.domain_rules,
            &cfg.address_rules,
            &cfg.forward_rules,
            &domain_sets,
            &cfg.cnames,
            &cfg.nftsets,
        );

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
            if !cfg.listeners.is_empty() {
                use local_ip_address::list_afinet_netifas;
                match list_afinet_netifas() {
                    Ok(network_interfaces) => {
                        for listener in &mut cfg.listeners {
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

                            let ip = ips.into_iter().find(|ip| match listener.listen() {
                                ListenerAddress::Localhost => true,
                                ListenerAddress::All => true,
                                ListenerAddress::V4(_) => ip.is_ipv4(),
                                ListenerAddress::V6(_) => ip.is_ipv6() && !matches!(ip, IpAddr::V6(ipv6) if (ipv6.segments()[0] & 0xffc0) == 0xfe80),
                            });

                            match ip {
                                Some(ip) => *listener.mut_listen() = ip.into(),
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
            for (idx, listener) in cfg.listeners.iter().enumerate().rev() {
                let addr = listener.sock_addr();
                if matches!(listener, ListenerConfig::Udp(_) | ListenerConfig::Quic(_)) {
                    if !udp_addr.insert(addr) {
                        remove_idx.push(idx)
                    }
                } else if !tcp_addr.insert(addr) {
                    remove_idx.push(idx)
                }
            }

            for idx in remove_idx {
                let listener = cfg.listeners.remove(idx);
                warn!("remove duplicated listener {:?}", listener);
            }
        }

        let mut proxy_servers = HashMap::with_capacity(0);

        std::mem::swap(&mut proxy_servers, &mut cfg.proxy_servers);

        RuntimeConfig {
            inner: cfg,
            domain_rule_map,
            bogus_nxdomain,
            blacklist_ip,
            whitelist_ip,
            ignore_ip,
            proxy_servers: Arc::new(proxy_servers),
        }
    }
}

impl std::ops::Deref for RuntimeConfigBuilder {
    type Target = Config;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RuntimeConfigBuilder {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

mod parse {

    use super::*;
    use std::ffi::OsStr;

    impl RuntimeConfigBuilder {
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

        pub fn config(&mut self, conf_item: &str) {
            let mut conf_line = conf_item.trim_start();

            if let Some(line) = preline(conf_line) {
                conf_line = line;
            } else {
                return;
            }

            let sp_idx = conf_line.find(' ');
            match sp_idx {
                Some(sp_idx) if sp_idx > 0 => {
                    let conf_name = &conf_line[0..sp_idx];
                    use crate::config::parser::OneConfig::*;
                    match parser::parse_config(conf_line) {
                        Ok((_, config_item)) => match config_item {
                            AuditEnable(v) => self.audit.enable = Some(v),
                            AuditFile(v) => self.audit.file = Some(v),
                            AuditFileMode(v) => self.audit.file_mode = Some(v),
                            AuditNum(v) => self.audit.num = Some(v),
                            AuditSize(v) => self.audit.size = Some(v),
                            BindCertFile(v) => self.bind_cert_file = Some(v),
                            BindCertKeyFile(v) => self.bind_cert_key_file = Some(v),
                            BindCertKeyPass(v) => self.bind_cert_key_pass = Some(v),
                            CacheFile(v) => self.cache.file = Some(v),
                            CachePersist(v) => self.cache.persist = Some(v),
                            CName(v) => self.cnames.push(v),
                            NftSet(config) => self.nftsets.push(config),
                            Server(server) => self.nameservers.push(server),
                            ResponseMode(mode) => self.response_mode = Some(mode),
                            ResolvHostname(v) => self.resolv_hostname = Some(v),
                            ServeExpired(v) => self.cache.serve_expired = Some(v),
                            PrefetchDomain(v) => self.cache.prefetch_domain = Some(v),
                            ForceAAAASOA(v) => self.force_aaaa_soa = Some(v),
                            DualstackIpAllowForceAAAA(v) => {
                                self.dualstack_ip_allow_force_aaaa = Some(v)
                            }
                            DualstackIpSelection(v) => self.dualstack_ip_selection = Some(v),
                            ServerName(v) => self.server_name = Some(v),
                            NumWorkers(v) => self.num_workers = Some(v),
                            Domain(v) => self.domain = Some(v),
                            SpeedMode(v) => self.speed_check_mode.extend(v.0),
                            ServeExpiredTtl(v) => self.cache.serve_expired_ttl = Some(v),
                            ServeExpiredReplyTtl(v) => self.cache.serve_expired_reply_ttl = Some(v),
                            CacheSize(v) => self.cache.size = Some(v),
                            ForceQtypeSoa(v) => {
                                self.force_qtype_soa.insert(v);
                            }
                            DualstackIpSelectionThreshold(v) => {
                                self.dualstack_ip_selection_threshold = Some(v)
                            }
                            RrTtl(v) => self.rr_ttl = Some(v),
                            RrTtlMin(v) => self.rr_ttl_min = Some(v),
                            RrTtlMax(v) => self.rr_ttl_max = Some(v),
                            RrTtlReplyMax(v) => self.rr_ttl_reply_max = Some(v),
                            Listener(listener) => self.listeners.push(listener),
                            LocalTtl(v) => self.local_ttl = Some(v),
                            LogNum(v) => self.log.num = Some(v),
                            LogLevel(v) => self.log.level = Some(v),
                            LogFile(v) => self.log.file = Some(v),
                            LogFileMode(v) => self.log.file_mode = Some(v),
                            LogFilter(v) => self.log.filter = Some(v),
                            LogSize(v) => self.log.size = Some(v),
                            MaxReplyIpNum(v) => self.max_reply_ip_num = Some(v),
                            BlacklistIp(v) => self.blacklist_ip += v,
                            BogusNxDomain(v) => self.bogus_nxdomain += v,
                            WhitelistIp(v) => self.whitelist_ip += v,
                            IgnoreIp(v) => self.ignore_ip += v,
                            CaFile(v) => self.ca_file = Some(v),
                            CaPath(v) => self.ca_path = Some(v),
                            ConfFile(v) => self.load_file(v).expect("load_file failed"),
                            DnsmasqLeaseFile(v) => self.dnsmasq_lease_file = Some(v),
                            ResolvFile(v) => self.resolv_file = Some(v),
                            DomainRule(v) => self.domain_rules.push(v),
                            ForwardRule(v) => self.forward_rules.push(v),
                            User(v) => self.user = Some(v),
                            TcpIdleTime(v) => self.tcp_idle_time = Some(v),
                            EdnsClientSubnet(v) => self.edns_client_subnet = Some(v),
                            Address(v) => self.address_rules.push(v),
                            DomainSetProvider(v) => {
                                self.domain_set_providers.insert(v.name().to_string(), v);
                            }
                            ProxyConfig(v) => {
                                self.proxy_servers.insert(v.name.clone(), v.config);
                            }
                            // #[allow(unreachable_patterns)]
                            // c => log::warn!("unhandled config {:?}", c),
                        },
                        Err(err) => {
                            warn!("unknown conf: {}, {:?}", conf_name, err);
                        }
                    }
                }
                _ => (),
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
        if matches!(line.chars().next(), Some('#') | None) {
            return None;
        }

        // remove comments endding.
        match line.rfind('#') {
            Some(sharp_idx)
                if sharp_idx > 1
                    && matches!(line.chars().nth(sharp_idx - 1), Some(c) if c.is_whitespace()) =>
            {
                let preserve = line[0..sharp_idx].trim_end();
                if !preserve.ends_with("-a")
                    && !preserve.ends_with("-address")
                    && !preserve.ends_with("--address")
                {
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

    #[cfg(test)]
    mod tests {
        use crate::libdns::resolver::config::Protocol;
        use byte_unit::Byte;

        use crate::config::{HttpsListenerConfig, ListenerAddress, ServerOpts, SslConfig};

        use super::*;

        #[test]
        fn test_config_binds_dedup() {
            let cfg = RuntimeConfig::builder()
                .with("bind-tcp 0.0.0.0:4453@eth1")
                .with("bind-tls 0.0.0.0:4452@eth1")
                .with("bind-https 0.0.0.0:4453@eth1")
                .build();

            assert_eq!(
                cfg.listeners()
                    .iter()
                    .filter(|x| matches!(x, ListenerConfig::Tcp(_)))
                    .count(),
                0
            );
            assert_eq!(
                cfg.listeners()
                    .iter()
                    .filter(|x| matches!(x, ListenerConfig::Tls(_)))
                    .count(),
                1
            );
            assert_eq!(
                cfg.listeners()
                    .iter()
                    .filter(|x| matches!(x, ListenerConfig::Https(_)))
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

            assert_eq!(cfg.listeners().len(), 1);

            let bind = cfg.listeners().get(0).unwrap();

            assert_eq!(
                bind.listen(),
                ListenerAddress::V4("0.0.0.0".parse().unwrap())
            );
            assert_eq!(bind.port(), 4453);

            assert_eq!(bind.device(), Some("eth100"));
        }

        #[test]
        fn test_config_bind_with_device_flags() {
            let cfg = RuntimeConfig::builder()
                .with("bind-https 0.0.0.0:443@eth2 -no-rule-addr")
                .build();

            let listener = cfg.listeners().get(0).unwrap();

            assert_eq!(
                listener,
                &ListenerConfig::Https(HttpsListenerConfig {
                    listen: ListenerAddress::V4("0.0.0.0".parse().unwrap()),
                    port: 443,
                    device: Some("eth2".to_string()),
                    opts: ServerOpts {
                        no_rule_addr: Some(true),
                        ..Default::default()
                    },
                    ssl_config: Default::default()
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

            assert!(!cfg.listeners().is_empty());

            let listener = cfg.listeners().get(0).unwrap();

            assert_eq!(
                listener,
                &ListenerConfig::Https(HttpsListenerConfig {
                    listen: ListenerAddress::V4("0.0.0.0".parse().unwrap()),
                    port: 4453,
                    ssl_config: SslConfig {
                        server_name: Some("dns.example.com".to_string()),
                        certificate: Some(
                            Path::new("/etc/nginx/dns.example.com.crt").to_path_buf()
                        ),
                        certificate_key: Some(
                            Path::new("/etc/nginx/dns.example.com.key").to_path_buf()
                        ),
                        certificate_key_pass: None
                    },
                    device: None,
                    opts: Default::default()
                })
            );
        }

        #[test]
        fn test_config_server_0() {
            let cfg = RuntimeConfig::builder().with(
                "server-https https://223.5.5.5/dns-query -group bootstrap -exclude-default-group",
            ).build();

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
            let cfg = RuntimeConfig::builder().with(
                "server-https https://223.5.5.5/dns-query  -bootstrap-dns -exclude-default-group",
            ).build();

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
            assert_eq!(
                server.edns_client_subnet,
                Some("192.168.0.0/16".parse().unwrap())
            );
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
            let cfg = RuntimeConfig::builder().with("server-tls 45.90.28.0 -host-name: dns.nextdns.io -tls-host-verify: dns.nextdns.io").build();

            let server = cfg.nameservers.first().unwrap();

            assert!(!server.exclude_default_group);
            assert_eq!(server.server.proto(), &Protocol::Tls);
            assert_eq!(server.server.to_string(), "tls://dns.nextdns.io");
            assert_eq!(server.server.ip(), "45.90.28.0".parse::<IpAddr>().ok());
            assert_eq!(server.server.domain(), Some("dns.nextdns.io"));
        }

        #[test]
        fn test_config_address_soa() {
            let mut cfg = RuntimeConfig::builder();

            cfg.config("address /test.example.com/#");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                Domain::Name("test.example.com".parse().unwrap())
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::SOA);
        }

        #[test]
        fn test_config_domain_rules_without_args() {
            let mut cfg = RuntimeConfig::builder();
            cfg.config(
                "domain-set -name domain-forwarding-list -file tests/test_confs/block-list.txt",
            );
            cfg.config("domain-rules /domain-set:domain-forwarding-list/");
            assert!(cfg.address_rules.last().is_none());
        }

        #[test]
        fn test_config_address_soa_v4() {
            let mut cfg = RuntimeConfig::builder();

            cfg.config("address /test.example.com/#4");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                Domain::Name("test.example.com".parse().unwrap())
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::SOAv4);
        }

        #[test]
        fn test_config_address_soa_v6() {
            let mut cfg = RuntimeConfig::builder();

            cfg.config("address /test.example.com/#6");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                Domain::Name("test.example.com".parse().unwrap())
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::SOAv6);
        }

        #[test]
        fn test_config_address_ignore() {
            let mut cfg = RuntimeConfig::builder();

            cfg.config("address /test.example.com/-");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                Domain::Name("test.example.com".parse().unwrap())
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::IGN);
        }

        #[test]
        fn test_config_address_ignore_v4() {
            let mut cfg = RuntimeConfig::builder();

            cfg.config("address /test.example.com/-4");

            let domain_addr_rule = cfg.address_rules.last().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                Domain::Name("test.example.com".parse().unwrap())
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::IGNv4);
        }

        #[test]
        fn test_config_address_ignore_v6() {
            let mut cfg = RuntimeConfig::builder();

            cfg.config("address /test.example.com/-6");

            let domain_addr_rule = cfg.address_rules.first().unwrap();

            assert_eq!(
                domain_addr_rule.domain,
                Domain::Name("test.example.com".parse().unwrap())
            );

            assert_eq!(domain_addr_rule.address, DomainAddress::IGNv6);
        }

        #[test]
        fn test_config_address_whitelist_mode() {
            use std::str::FromStr;
            let cfg = RuntimeConfig::builder()
                .with("address /google.com/-")
                .with("address /*/#")
                .build();

            assert_eq!(
                cfg.find_domain_rule(&Name::from_str("cloudflare.com").unwrap())
                    .and_then(|r| r.get(|n| n.address)),
                Some(DomainAddress::SOA)
            );

            assert_eq!(
                cfg.find_domain_rule(&Name::from_str("google.com").unwrap())
                    .and_then(|r| r.get(|n| n.address)),
                Some(DomainAddress::IGN)
            );
        }

        #[test]
        fn test_config_nameserver() {
            let mut cfg = RuntimeConfig::builder();

            cfg.config("nameserver /doh.pub/bootstrap");

            let nameserver_rule = cfg.forward_rules.first().unwrap();

            assert_eq!(
                nameserver_rule.domain,
                Domain::Name("doh.pub".parse().unwrap())
            );

            assert_eq!(nameserver_rule.nameserver, "bootstrap");
        }

        #[test]
        fn test_config_domain_rule() {
            let mut cfg = RuntimeConfig::builder();

            cfg.config("domain-rule /doh.pub/ -c ping -a 127.0.0.1 -n test -d yes");

            let domain_rule = cfg.domain_rules.first().unwrap();

            assert_eq!(domain_rule.domain, Domain::Name("doh.pub".parse().unwrap()));
            assert_eq!(
                domain_rule.address,
                Some(DomainAddress::IPv4("127.0.0.1".parse().unwrap()))
            );
            assert_eq!(
                domain_rule.speed_check_mode,
                vec![SpeedCheckMode::Ping].into()
            );
            assert_eq!(domain_rule.nameserver, Some("test".to_string()));
            assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
        }

        #[test]
        fn test_config_domain_rule_2() {
            let mut cfg = RuntimeConfig::builder();

            cfg.config("domain-rules /doh.pub/ -c ping -a 127.0.0.1 -n test -d yes");

            let domain_rule = cfg.domain_rules.first().unwrap();

            assert_eq!(domain_rule.domain, Domain::Name("doh.pub".parse().unwrap()));
            assert_eq!(
                domain_rule.address,
                Some(DomainAddress::IPv4("127.0.0.1".parse().unwrap()))
            );
            assert_eq!(
                domain_rule.speed_check_mode,
                vec![SpeedCheckMode::Ping].into()
            );
            assert_eq!(domain_rule.nameserver, Some("test".to_string()));
            assert_eq!(domain_rule.dualstack_ip_selection, Some(true));
        }

        #[test]
        fn test_config_domain_rule_3() {
            let cfg = RuntimeConfig::builder()
                .with("domain-rules /doh.pub/ -c ping -a # -n test -d yes")
                .build();

            let domain_rule = cfg.find_domain_rule(&"doh.pub".parse().unwrap()).unwrap();

            assert_eq!(domain_rule.name(), &"doh.pub".parse().unwrap());
            assert_eq!(domain_rule.address, Some(DomainAddress::SOA));
            assert_eq!(
                domain_rule.speed_check_mode,
                vec![SpeedCheckMode::Ping].into()
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

            assert_eq!(cfg.speed_check_mode.len(), 2);

            assert_eq!(cfg.speed_check_mode.get(0).unwrap(), &SpeedCheckMode::Ping);
            assert_eq!(
                cfg.speed_check_mode.get(1).unwrap(),
                &SpeedCheckMode::Tcp(123)
            );
        }

        #[test]
        fn test_parse_config_speed_check_mode_https_omit_port() {
            let mut cfg = RuntimeConfig::builder();
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
            let cfg = RuntimeConfig::load_from_file("tests/test_confs/b_main.conf");

            assert_eq!(cfg.server_name, "SmartDNS123".parse().ok());
            assert_eq!(
                cfg.forward_rules.first().unwrap().domain,
                Domain::Name("doh.pub".parse().unwrap())
            );
            assert_eq!(cfg.forward_rules.first().unwrap().nameserver, "bootstrap");
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
        #[cfg(failed_tests)]
        fn test_domain_set() {
            let cfg = RuntimeConfig::load_from_file("tests/test_confs/b_main.conf");

            assert!(!cfg.domain_sets.is_empty());

            let domain_set = cfg.domain_sets.values().nth(0).unwrap();

            assert!(domain_set.len() > 0);

            assert!(domain_set.contains(&domain::Name::from_str("ads1.com").unwrap().into()));
            assert!(!domain_set.contains(&domain::Name::from_str("ads2c.cn").unwrap().into()));
            assert!(domain_set.is_match(&domain::Name::from_str("ads3.net").unwrap().into()));
            assert!(domain_set.is_match(&domain::Name::from_str("q.ads3.net").unwrap().into()));
        }
    }
}
