use std::net::IpAddr;

use crate::dns::{DnsContext, DnsError, DnsRequest, DnsResponse, RData, Record};
use crate::infra::arp::lookup_client_mac_from_arp;
use crate::libdns::proto::op::Query;
use crate::libdns::proto::rr::rdata::TXT;
use crate::libdns::proto::rr::{DNSClass, Name, RecordType};

use crate::zone::ZoneProvider;

const UNKNOWN_CLIENT_MAC: &str = "N/A";

pub struct IdentityZoneProvider;

impl IdentityZoneProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ZoneProvider for IdentityZoneProvider {
    async fn lookup(
        &self,
        ctx: &DnsContext,
        req: &DnsRequest,
    ) -> Result<Option<DnsResponse>, DnsError> {
        let query = req.query().original().to_owned();

        if query.query_type() != RecordType::TXT {
            return Ok(None);
        }

        if !matches!(query.query_class(), DNSClass::CH | DNSClass::IN) {
            return Ok(None);
        }

        let query_name = normalize_query_name(query.name());
        let client_ip = normalize_client_ip(req.src().ip());
        let server_name = trim_fqdn_dot(ctx.cfg().server_name().to_string());
        let client_mac = || {
            lookup_client_mac_from_arp(client_ip).unwrap_or_else(|| UNKNOWN_CLIENT_MAC.to_string())
        };

        let res = match query_name.as_str() {
            // BIND compatibility
            "hostname.bind." | "id.server." => Some(txt_response(query, server_name.clone())),
            "version.bind." => Some(txt_response(query, crate::BUILD_VERSION.to_string())),
            "whoami.bind." | "client.ip.bind." | "clientip.bind." => {
                Some(txt_response(query, client_ip.to_string()))
            }
            "whoami.mac.bind." | "client.mac.bind." | "clientmac.bind." => {
                Some(txt_response(query, client_mac()))
            }
            "smartdns.info.bind." => Some(txt_response(
                query,
                build_info_kv_text(
                    &server_name,
                    crate::BUILD_VERSION,
                    &client_ip,
                    &client_mac(),
                ),
            )),
            "smartdns.info.json.bind." => Some(txt_response(
                query,
                build_info_json_text(
                    &server_name,
                    crate::BUILD_VERSION,
                    &client_ip,
                    &client_mac(),
                ),
            )),
            "smartdns.bind." => Some(txt_records_response(
                query,
                build_info_records_text(
                    &server_name,
                    crate::BUILD_VERSION,
                    &client_ip,
                    &client_mac(),
                ),
            )),

            // SmartDNS native names (without `.bind`)
            "hostname.smartdns." | "server-name.smartdns." | "server-name." => {
                Some(txt_response(query, server_name.clone()))
            }
            "version.smartdns." | "server-version.smartdns." | "version." => {
                Some(txt_response(query, crate::BUILD_VERSION.to_string()))
            }
            "client-ip.smartdns." | "clientip.smartdns." | "client-ip." => {
                Some(txt_response(query, client_ip.to_string()))
            }
            "whoami-mac.smartdns."
            | "client-mac.smartdns."
            | "clientmac.smartdns."
            | "client-mac." => Some(txt_response(query, client_mac())),
            "info.smartdns." => Some(txt_response(
                query,
                build_info_kv_text(
                    &server_name,
                    crate::BUILD_VERSION,
                    &client_ip,
                    &client_mac(),
                ),
            )),
            "json.smartdns." | "info.json.smartdns." => Some(txt_response(
                query,
                build_info_json_text(
                    &server_name,
                    crate::BUILD_VERSION,
                    &client_ip,
                    &client_mac(),
                ),
            )),
            "whoami.smartdns." | "whoami." | "smartdns." => Some(txt_records_response(
                query,
                build_info_records_text(
                    &server_name,
                    crate::BUILD_VERSION,
                    &client_ip,
                    &client_mac(),
                ),
            )),
            _ => None,
        };

        Ok(res)
    }
}

fn normalize_query_name(name: &Name) -> String {
    let mut normalized = name.clone();
    normalized.set_fqdn(true);
    normalized.to_string().to_ascii_lowercase()
}

fn trim_fqdn_dot(name: String) -> String {
    name.trim_end_matches('.').to_string()
}

fn normalize_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(addr) => addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4),
        IpAddr::V4(addr) => IpAddr::V4(addr),
    }
}

fn txt_response(query: Query, value: String) -> DnsResponse {
    let mut record = Record::from_rdata(
        query.name().to_owned(),
        crate::dns_client::MAX_TTL,
        RData::TXT(TXT::new(vec![value])),
    );
    record.set_dns_class(query.query_class());
    DnsResponse::new_with_max_ttl(query, vec![record])
}

fn txt_records_response(query: Query, values: Vec<String>) -> DnsResponse {
    let records = values
        .into_iter()
        .map(|value| {
            let mut record = Record::from_rdata(
                query.name().to_owned(),
                crate::dns_client::MAX_TTL,
                RData::TXT(TXT::new(vec![value])),
            );
            record.set_dns_class(query.query_class());
            record
        })
        .collect::<Vec<_>>();

    DnsResponse::new_with_max_ttl(query, records)
}

fn build_info_kv_text(
    server_name: &str,
    version: &str,
    client_ip: &IpAddr,
    client_mac: &str,
) -> String {
    format!(
        "server_name={server_name};server_version={version};client_ip={client_ip};client_mac={client_mac}",
    )
}

fn build_info_records_text(
    server_name: &str,
    version: &str,
    client_ip: &IpAddr,
    client_mac: &str,
) -> Vec<String> {
    vec![
        format!("server_name={server_name}"),
        format!("server_version={version}"),
        format!("client_ip={client_ip}"),
        format!("client_mac={client_mac}"),
    ]
}

fn build_info_json_text(
    server_name: &str,
    version: &str,
    client_ip: &IpAddr,
    client_mac: &str,
) -> String {
    let server_name = json_escape(server_name);
    let version = json_escape(version);
    let client_ip = json_escape(&client_ip.to_string());
    let client_mac = json_escape(client_mac);
    format!(
        r#"{{"server_name":"{server_name}","server_version":"{version}","client_ip":"{client_ip}","client_mac":"{client_mac}"}}"#
    )
}

fn json_escape(value: &str) -> String {
    value.chars().flat_map(|c| c.escape_default()).collect()
}
