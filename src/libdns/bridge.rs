use crate::dns_client::LookupOptions;
use crate::dns_url::{DnsUrl, ProtocolConfig};
use crate::libdns::{
    proto::rr::RecordType,
    resolver::config::{
        ConnectionConfig as LibdnsConnectionConfig, NameServerConfig as LibdnsNameServerConfig,
        ProtocolConfig as LibdnsProtocolConfig,
    },
};

impl From<&DnsUrl> for LibdnsConnectionConfig {
    fn from(url: &DnsUrl) -> Self {
        let server_name = url.name().clone();

        let proto = match url.proto().clone() {
            ProtocolConfig::Udp => LibdnsProtocolConfig::Udp,
            ProtocolConfig::Tcp => LibdnsProtocolConfig::Tcp,
            #[cfg(feature = "dns-over-tls")]
            ProtocolConfig::Tls => LibdnsProtocolConfig::Tls { server_name },
            #[cfg(feature = "dns-over-quic")]
            ProtocolConfig::Quic => LibdnsProtocolConfig::Quic { server_name },
            #[cfg(feature = "dns-over-https")]
            ProtocolConfig::Https { path, .. } => LibdnsProtocolConfig::Https { server_name, path },
            #[cfg(feature = "dns-over-h3")]
            ProtocolConfig::H3 {
                path,
                disable_grease,
            } => LibdnsProtocolConfig::H3 {
                server_name,
                path,
                disable_grease,
            },
            ProtocolConfig::System => LibdnsProtocolConfig::Udp,
            ProtocolConfig::Dhcp { .. } => LibdnsProtocolConfig::Udp,
        };

        let mut conn = LibdnsConnectionConfig::new(proto);
        conn.port = url.port();
        conn
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

impl From<&LibdnsNameServerConfig> for DnsUrl {
    fn from(config: &LibdnsNameServerConfig) -> Self {
        let mut url: Self = config.ip.into();
        if let Some(conn_config) = config.connections.first() {
            url.set_port(conn_config.port);

            match conn_config.protocol.clone() {
                LibdnsProtocolConfig::Udp => {
                    url.set_proto(ProtocolConfig::Udp);
                }
                LibdnsProtocolConfig::Tcp => {
                    url.set_proto(ProtocolConfig::Tcp);
                }
                LibdnsProtocolConfig::Tls { server_name } => {
                    url.set_name(server_name);
                    url.set_proto(ProtocolConfig::Tls);
                }
                LibdnsProtocolConfig::Https { server_name, path } => {
                    url.set_name(server_name);
                    url.set_proto(ProtocolConfig::Https {
                        path,
                        prefer: Default::default(),
                    });
                }
                LibdnsProtocolConfig::Quic { server_name } => {
                    url.set_name(server_name);
                    url.set_proto(ProtocolConfig::Quic);
                }
                LibdnsProtocolConfig::H3 {
                    server_name,
                    path,
                    disable_grease,
                } => {
                    url.set_name(server_name);
                    url.set_proto(ProtocolConfig::H3 {
                        path,
                        disable_grease,
                    });
                }
            };
        }

        url
    }
}
