use std::net::Ipv4Addr;

use crate::dns_client::LookupOptions;
use crate::dns_url::{DnsUrl, ProtocolConfig};
use crate::libdns::{
    proto::rr::RecordType,
    resolver::config::{
        ConnectionConfig as LibdnsConnectionConfig, NameServerConfig as LibdnsNameServerConfig,
        ProtocolConfig as LibdnsProtocolConfig,
    },
};

impl From<&ProtocolConfig> for LibdnsProtocolConfig {
    fn from(value: &ProtocolConfig) -> Self {
        match value.clone() {
            ProtocolConfig::Udp => LibdnsProtocolConfig::Udp,
            ProtocolConfig::Tcp => LibdnsProtocolConfig::Tcp,
            #[cfg(feature = "dns-over-tls")]
            ProtocolConfig::Tls { server_name } => LibdnsProtocolConfig::Tls {
                server_name: server_name.unwrap_or_default(),
            },
            #[cfg(feature = "dns-over-quic")]
            ProtocolConfig::Quic { server_name } => LibdnsProtocolConfig::Quic {
                server_name: server_name.unwrap_or_default(),
            },
            #[cfg(feature = "dns-over-https")]
            ProtocolConfig::Https {
                server_name, path, ..
            } => LibdnsProtocolConfig::Https {
                server_name: server_name.unwrap_or_default(),
                path,
            },
            #[cfg(feature = "dns-over-h3")]
            ProtocolConfig::H3 {
                server_name,
                path,
                disable_grease,
            } => LibdnsProtocolConfig::H3 {
                server_name: server_name.unwrap_or_default(),
                path,
                disable_grease,
            },
            ProtocolConfig::System => LibdnsProtocolConfig::Udp,
            ProtocolConfig::Dhcp { .. } => LibdnsProtocolConfig::Udp,
        }
    }
}

impl From<&DnsUrl> for LibdnsConnectionConfig {
    fn from(url: &DnsUrl) -> Self {
        let mut conn = LibdnsConnectionConfig::new(url.proto().into());
        conn.port = url.port();
        conn
    }
}

impl From<&DnsUrl> for LibdnsNameServerConfig {
    fn from(url: &DnsUrl) -> Self {
        LibdnsNameServerConfig::new(
            url.ip().unwrap_or_else(|| Ipv4Addr::LOCALHOST.into()),
            true,
            vec![url.into()],
        )
    }
}

impl From<RecordType> for LookupOptions {
    fn from(record_type: RecordType) -> Self {
        Self {
            record_type,
            ..Default::default()
        }
    }
}
