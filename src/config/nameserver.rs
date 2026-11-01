use crate::dns_url::DnsUrl;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// remote udp dns server list
///
/// server [IP]:[PORT] [-blacklist-ip] [-whitelist-ip] [-check-edns] [-group [group] ...] [-exclude-default-group] [-fallback]
///
/// default port is 53
///   - -blacklist-ip: filter result with blacklist ip
///   - -whitelist-ip: filter result whth whitelist ip,  result in whitelist-ip will be accepted.
///   - -check-edns: result must exist edns RR, or discard result.
///   - -group [group]: set server to group, use with nameserver /domain/group.
///   - -exclude-default-group: exclude this server from default group.
///   - -fallback: mark this server as a fallback DNS, it is only queried after
///     the primary servers of the group have failed (see [NameServerInfo::fallback]).
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
    /// the name of the nameserver
    pub name: Option<String>,

    /// the nameserver url.
    pub server: DnsUrl,

    /// set server to group, use with nameserver /domain/group.
    /// ```
    /// example:
    ///   -g name
    ///   -group name
    /// ```
    ///
    /// A group literally named `fallback` (e.g. `server 223.5.5.5 -e
    /// -group fallback`) is the well-known backup group: every other group's query
    /// is retried against it once when the primary group's answer fails (a
    /// transport error or a `ServFail` reply from a rate-limited public DNS).
    /// See `dns_client::FALLBACK_GROUP`.
    #[serde(default = "Default::default")]
    pub group: Vec<String>,

    /// filter result with blacklist ip
    #[serde(default = "Default::default")]
    pub blacklist_ip: bool,

    /// filter result with whitelist ip,  result in whitelist-ip will be accepted.
    #[serde(default = "Default::default")]
    pub whitelist_ip: bool,

    /// result must exist edns RR, or discard result.
    #[serde(default = "Default::default")]
    pub check_edns: bool,

    /// exclude this server from default group.
    /// ```
    /// example:
    ///   -e
    ///   -exclude-default-group
    /// ```
    #[serde(default = "Default::default")]
    pub exclude_default_group: bool,

    /// mark the server as a fallback DNS.
    ///
    /// Fallback servers are skipped on the first query and are only queried
    /// after the primary (non-fallback) servers of the *same group* have failed.
    /// This is useful for rate-limited public DNS servers, which should only be
    /// used as a backup to keep their traffic low. Matches the C version's
    /// `-fallback` server option.
    ///
    /// This is distinct from the group-level backup: a server in a group named
    /// `fallback` (`-group fallback`, see [`NameServerInfo::group`]) backs up
    /// *every other group* and is queried after the primary group fails.
    ///
    /// ```
    /// example:
    ///   -fallback
    /// ```
    #[serde(default = "Default::default")]
    pub fallback: bool,

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
    #[serde(default = "Default::default")]
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
    #[serde(default = "Default::default")]
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

    /// indicates whether the DNS server is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl NameServerInfo {
    pub fn enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

impl std::fmt::Display for NameServerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.server)?;
        for g in &self.group {
            write!(f, " -g {g}")?;
        }

        if self.exclude_default_group {
            write!(f, " -e")?;
        }

        if self.fallback {
            write!(f, " -fallback")?;
        }

        if let Some(proxy) = &self.proxy {
            write!(f, " -p {proxy}")?;
        }

        Ok(())
    }
}

impl From<DnsUrl> for NameServerInfo {
    fn from(url: DnsUrl) -> Self {
        Self {
            server: url,
            name: Default::default(),
            group: Default::default(),
            exclude_default_group: Default::default(),
            fallback: Default::default(),
            blacklist_ip: Default::default(),
            whitelist_ip: Default::default(),
            bootstrap_dns: Default::default(),
            check_edns: Default::default(),
            proxy: Default::default(),
            interface: Default::default(),
            so_mark: Default::default(),
            resolve_group: Default::default(),
            subnet: Default::default(),
            enabled: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;

    #[test]
    fn test_ipnet_json_serde() {
        #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
        struct Foo1 {
            subnet: IpNet,
        }

        let foo = Foo1 {
            subnet: "192.168.0.0/16".parse().unwrap(),
        };

        let json_str = serde_json::to_string(&foo).unwrap();

        assert_eq!(json_str, r#"{"subnet":"192.168.0.0/16"}"#);

        assert_eq!(foo, serde_json::from_str(&json_str).unwrap());

        #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
        struct Foo2 {
            subnet: Option<IpNet>,
        }

        let foo = Foo2 { subnet: None };

        let json_str = serde_json::to_string(&foo).unwrap();

        assert_eq!(json_str, r#"{"subnet":null}"#);

        assert_eq!(foo, serde_json::from_str(&json_str).unwrap());
    }

    #[test]
    fn test_json_deserialize_bind_addr_simple() {
        let json_str = r#"
        {
            "name": "AliDNS",
            "server": "https://dns.alidns.com/dns-query",
            "group": ["china"],
            "enabled": true
        }
        "#;

        let name_server: NameServerInfo = serde_json::from_str(json_str).unwrap();
        assert_eq!(name_server.name, Some("AliDNS".to_string()));
        assert_eq!(
            name_server.server,
            "https://dns.alidns.com/dns-query".parse().unwrap()
        );
        assert_eq!(name_server.group, vec!["china".to_string()]);
        assert_eq!(name_server.enabled, Some(true));
    }

    #[test]
    fn test_json_deserialize_fallback_default() {
        // Without the `fallback` key it defaults to `false`.
        let json_str = r#"{ "server": "223.5.5.5" }"#;
        let name_server: NameServerInfo = serde_json::from_str(json_str).unwrap();
        assert!(!name_server.fallback);

        // With `fallback: true` it is honored.
        let json_str = r#"{ "server": "223.5.5.5", "fallback": true }"#;
        let name_server: NameServerInfo = serde_json::from_str(json_str).unwrap();
        assert!(name_server.fallback);
    }

    #[test]
    fn test_display_fallback() {
        let mut info: NameServerInfo = DnsUrl::from_str("223.5.5.5").unwrap().into();
        // Without `-fallback` nothing extra is rendered.
        assert_eq!(info.to_string(), "udp://223.5.5.5");

        info.fallback = true;
        assert_eq!(info.to_string(), "udp://223.5.5.5 -fallback");
    }
}
