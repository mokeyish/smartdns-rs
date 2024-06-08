use crate::{
    dns_url::DnsUrl,
    third_ext::{serde_opt_str, serde_str},
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NameServerInfo {
    /// the nameserver url.
    #[serde(with = "serde_str")]
    pub server: DnsUrl,

    /// set server to group, use with nameserver /domain/group.
    /// ```
    /// example:
    ///   -g name
    ///   -group name
    /// ```
    pub group: Vec<String>,

    /// filter result with blacklist ip
    pub blacklist_ip: bool,

    /// filter result with whitelist ip,  result in whitelist-ip will be accepted.
    pub whitelist_ip: bool,

    /// result must exist edns RR, or discard result.
    pub check_edns: bool,

    /// exclude this server from default group.
    /// ```
    /// example:
    ///   -e
    ///   -exclude-default-group
    /// ```
    pub exclude_default_group: bool,

    /// use proxy to connect to server.
    /// ```
    /// example:
    ///   -p name
    ///   -proxy name
    /// ```
    pub proxy: Option<String>,

    /// set as bootstrap dns server
    /// ```
    /// example:
    ///   -b
    ///   -bootstrap-dns
    /// ```
    pub bootstrap_dns: bool,

    /// nameserver group for resolving.
    pub resolve_group: Option<String>,

    /// edns client subnet
    ///
    /// ```
    /// example:
    ///   -subnet [ip/subnet]
    ///   -subnet 192.168.1.1/24
    ///   -subnet 8::8/56
    /// ```
    #[serde(with = "serde_opt_str")]
    pub subnet: Option<IpNet>,

    /// The value for the SO_MARK option on socket.
    /// ```
    /// example:
    ///   -set-mark mark
    /// ```
    pub so_mark: Option<u32>,

    /// ```
    /// example:
    ///   -interface lo
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl From<DnsUrl> for NameServerInfo {
    fn from(url: DnsUrl) -> Self {
        Self {
            server: url,
            group: vec![],
            exclude_default_group: false,
            blacklist_ip: false,
            whitelist_ip: false,
            bootstrap_dns: false,
            check_edns: false,
            proxy: None,
            interface: None,
            so_mark: None,
            resolve_group: None,
            subnet: None,
        }
    }
}
