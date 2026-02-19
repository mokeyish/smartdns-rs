use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use crate::libdns::proto::op::Query;
use crate::libdns::proto::rr::DNSClass;
use crate::libdns::proto::rr::rdata::{PTR, TXT};

use crate::config::HttpsRecordRule;
use crate::dns::*;
use crate::infra::ipset::IpSet;
use crate::middleware::*;

const UNKNOWN_CLIENT_MAC: &str = "N/A";

pub struct DnsZoneMiddleware {
    server_net: IpSet,
    server_names: BTreeSet<Name>,
}

impl DnsZoneMiddleware {
    pub fn new() -> Self {
        let server_net = {
            use local_ip_address::list_afinet_netifas;
            let ips = list_afinet_netifas().unwrap_or_default();
            IpSet::new(ips.into_iter().map(|(_, ip)| ip.into()))
        };

        let server_names = {
            let mut set = BTreeSet::new();
            set.insert(Name::from_str("smartdns.").unwrap());
            set.insert(Name::from_str("whoami.").unwrap());
            set
        };

        Self {
            server_net,
            server_names,
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsZoneMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query = req.query();
        let name = query.name();
        let query_type = query.query_type();

        if let Some(response) = self.handle_builtin_txt_query(ctx, req) {
            return Ok(response);
        }

        match query_type {
            RecordType::PTR => {
                let mut is_current_server = false;
                let name: &Name = name.borrow();

                if self.server_names.contains(name) {
                    is_current_server = true;
                } else if let Ok(net) = name.parse_arpa_name() {
                    is_current_server = self.server_net.overlap(&net);

                    if !is_current_server {
                        let is_private_ip = match net.addr() {
                            IpAddr::V4(ip) => ip.is_private(),
                            IpAddr::V6(ip) => {
                                const fn is_unique_local(ip: std::net::Ipv6Addr) -> bool {
                                    (ip.segments()[0] & 0xfe00) == 0xfc00
                                }
                                is_unique_local(ip)
                            }
                        };

                        if is_private_ip {
                            let mut res = DnsResponse::empty();
                            res.add_query(query.original().to_owned());
                            return Ok(res);
                        }
                    }
                }

                if is_current_server {
                    return Ok(DnsResponse::from_rdata(
                        req.query().original().to_owned(),
                        RData::PTR(PTR(ctx.cfg().server_name())),
                    ));
                }
            }
            RecordType::SRV => {
                if let Some(srv) = ctx.domain_rule.get_ref(|r| r.srv.as_ref()) {
                    return Ok(DnsResponse::from_rdata(
                        req.query().original().to_owned(),
                        RData::SRV(srv.clone()),
                    ));
                }
            }
            RecordType::HTTPS => {
                if let Some(https_rule) = ctx.domain_rule.get_ref(|r| r.https.as_ref()) {
                    match https_rule {
                        HttpsRecordRule::Ignore => (),
                        HttpsRecordRule::SOA => {
                            return Ok(DnsResponse::from_rdata(
                                req.query().original().to_owned(),
                                RData::default_soa(),
                            ));
                        }
                        HttpsRecordRule::Filter {
                            no_ipv4_hint,
                            no_ipv6_hint,
                        } => {
                            use crate::libdns::proto::rr::rdata::{SVCB, svcb::SvcParamKey};
                            let no_ipv4_hint = *no_ipv4_hint;
                            let no_ipv6_hint = *no_ipv6_hint;
                            return match next.run(ctx, req).await {
                                Ok(mut lookup) => {
                                    for record in lookup.answers_mut() {
                                        if let Some(https) = record.data_mut().as_https_mut() {
                                            let svc_params = https
                                                .svc_params()
                                                .iter()
                                                .filter(|(k, _)| match k {
                                                    SvcParamKey::Ipv4Hint => !no_ipv4_hint,
                                                    SvcParamKey::Ipv6Hint => !no_ipv6_hint,
                                                    _ => true,
                                                })
                                                .cloned()
                                                .collect();

                                            https.0 = SVCB::new(
                                                https.svc_priority(),
                                                https.target_name().clone(),
                                                svc_params,
                                            );
                                        }
                                    }
                                    Ok(lookup)
                                }
                                Err(err) => Err(err),
                            };
                        }
                        HttpsRecordRule::RecordData(https) => {
                            return Ok(DnsResponse::from_rdata(
                                req.query().original().to_owned(),
                                RData::HTTPS(https.clone()),
                            ));
                        }
                    }
                }
            }
            _ => (),
        }

        next.run(ctx, req).await
    }
}

impl DnsZoneMiddleware {
    fn handle_builtin_txt_query(&self, ctx: &DnsContext, req: &DnsRequest) -> Option<DnsResponse> {
        let query = req.query().original().to_owned();

        if query.query_type() != RecordType::TXT {
            return None;
        }

        if !matches!(query.query_class(), DNSClass::CH | DNSClass::IN) {
            return None;
        }

        let query_name = normalize_query_name(query.name());
        let client_ip = normalize_client_ip(req.src().ip());
        let server_name = trim_fqdn_dot(ctx.cfg().server_name().to_string());

        let value = match query_name.as_str() {
            "hostname.bind." | "id.server." => server_name.clone(),
            "version.bind." => crate::BUILD_VERSION.to_string(),
            "whoami.bind." | "client.ip.bind." | "clientip.bind." => client_ip.to_string(),
            "whoami.mac.bind." | "client.mac.bind." | "clientmac.bind." => {
                lookup_client_mac_from_arp(client_ip)
                    .unwrap_or_else(|| UNKNOWN_CLIENT_MAC.to_string())
            }
            "smartdns.info.bind." => {
                let client_mac = lookup_client_mac_from_arp(client_ip)
                    .unwrap_or_else(|| UNKNOWN_CLIENT_MAC.to_string());
                format!(
                    "server_name={server_name};server_version={};client_ip={client_ip};client_mac={client_mac}",
                    crate::BUILD_VERSION,
                )
            }
            _ => return None,
        };

        Some(txt_response(query, value))
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

fn parse_arp_table_mac(table: &str, target_ip: Ipv4Addr) -> Option<String> {
    let target_ip = target_ip.to_string();
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let ip = fields.next()?;
        let _hardware_type = fields.next()?;
        let _flags = fields.next()?;
        let mac = fields.next()?;

        if ip != target_ip {
            return None;
        }

        if mac == "00:00:00:00:00:00" {
            return None;
        }

        Some(mac.to_ascii_lowercase())
    })
}

fn normalize_mac_token(token: &str) -> Option<String> {
    let token = token.trim_matches(|c: char| matches!(c, '(' | ')' | '[' | ']' | ','));
    let normalized = token.replace('-', ":").to_ascii_lowercase();

    if normalized == "00:00:00:00:00:00" {
        return None;
    }

    let parts = normalized.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return None;
    }

    if !parts
        .iter()
        .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }

    Some(normalized)
}

fn parse_arp_command_output_mac(output: &str, target_ip: Ipv4Addr) -> Option<String> {
    let target_ip = target_ip.to_string();
    output.lines().find_map(|line| {
        if !line.contains(&target_ip) {
            return None;
        }
        line.split_whitespace().find_map(normalize_mac_token)
    })
}

#[cfg(not(target_os = "linux"))]
fn run_arp_command(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("arp").args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn lookup_client_mac_from_arp(client_ip: IpAddr) -> Option<String> {
    let client_ip = match client_ip {
        IpAddr::V4(ip) if !ip.is_loopback() => ip,
        _ => return None,
    };

    std::fs::read_to_string("/proc/net/arp")
        .ok()
        .and_then(|table| parse_arp_table_mac(&table, client_ip))
}

#[cfg(not(target_os = "linux"))]
fn lookup_client_mac_from_arp(client_ip: IpAddr) -> Option<String> {
    let client_ip = match client_ip {
        IpAddr::V4(ip) if !ip.is_loopback() => ip,
        _ => return None,
    };

    let ip = client_ip.to_string();

    #[cfg(target_os = "windows")]
    for args in [["-a", ip.as_str()]] {
        if let Some(output) = run_arp_command(&args)
            && let Some(mac) = parse_arp_command_output_mac(&output, client_ip)
        {
            return Some(mac);
        }
    }

    #[cfg(not(target_os = "windows"))]
    for args in [
        ["-n", ip.as_str()],
        ["-an", ip.as_str()],
        ["-a", ip.as_str()],
    ] {
        if let Some(output) = run_arp_command(&args)
            && let Some(mac) = parse_arp_command_output_mac(&output, client_ip)
        {
            return Some(mac);
        }
    }

    None
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::infra::ipset::IpSet;
    use crate::libdns::proto::rr::DNSClass;
    use crate::{dns_conf::RuntimeConfig, dns_mw::*};
    use std::net::SocketAddr;

    async fn search_with_query(
        mw: &DnsMiddlewareHandler,
        name: &str,
        query_type: RecordType,
        query_class: DNSClass,
        src: SocketAddr,
    ) -> DnsResponse {
        let mut query = Query::query(name.parse().unwrap(), query_type);
        query.set_query_class(query_class);
        let mut message = op::Message::query();
        message.add_query(query);
        let req = DnsRequest::new(message, src, Protocol::Udp);
        mw.search(&req, &Default::default()).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_srv_record() {
        let cfg = RuntimeConfig::builder()
            .with("srv-record /_vlmcs._tcp/example.com,1688,1,2")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let srv = mock
            .lookup_rdata("_vlmcs._tcp", RecordType::SRV)
            .await
            .unwrap()
            .pop()
            .unwrap()
            .into_srv()
            .unwrap();

        assert_eq!(srv.target(), &"example.com".parse().unwrap());
        assert_eq!(srv.port(), 1688);
        assert_eq!(srv.priority(), 1);
        assert_eq!(srv.weight(), 2);
    }

    #[test]
    fn test_arpa() {
        let local_net = IpSet::new(vec![
            "::1/128".parse().unwrap(),
            "192.168.1.1/32".parse().unwrap(),
        ]);

        let name1: Name =
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
                .parse()
                .unwrap();

        let net1 = name1.parse_arpa_name().unwrap();

        assert!(local_net.contains(&net1));

        let name2: Name = "1.168.192.in-addr.arpa.".parse().unwrap();
        let net2 = name2.parse_arpa_name().unwrap();

        assert!(local_net.overlap(&net2));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_server_hostname() {
        let cfg = RuntimeConfig::builder()
            .with("server-name smartdns-rs-test")
            .build()
            .unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);
        let response = search_with_query(
            &mock,
            "hostname.bind",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.8:5300".parse().unwrap(),
        )
        .await;
        let answer = response.answers().first().unwrap();
        assert_eq!(answer.record_type(), RecordType::TXT);
        assert_eq!(answer.dns_class(), DNSClass::CH);
        assert!(answer.data().to_string().contains("smartdns-rs-test"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_version_and_client_ip() {
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);

        let version_response = search_with_query(
            &mock,
            "version.bind",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.9:5300".parse().unwrap(),
        )
        .await;
        assert!(
            version_response.answers()[0]
                .data()
                .to_string()
                .contains(crate::BUILD_VERSION)
        );

        let ip_response = search_with_query(
            &mock,
            "whoami.bind",
            RecordType::TXT,
            DNSClass::CH,
            "192.168.1.9:5300".parse().unwrap(),
        )
        .await;
        assert!(
            ip_response.answers()[0]
                .data()
                .to_string()
                .contains("192.168.1.9")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_builtin_txt_client_mac_for_loopback() {
        let cfg = RuntimeConfig::builder().build().unwrap();
        let mock = DnsMockMiddleware::mock(DnsZoneMiddleware::new()).build(cfg);
        let response = search_with_query(
            &mock,
            "whoami.mac.bind",
            RecordType::TXT,
            DNSClass::CH,
            "127.0.0.1:5300".parse().unwrap(),
        )
        .await;
        assert!(
            response.answers()[0]
                .data()
                .to_string()
                .contains(UNKNOWN_CLIENT_MAC)
        );
    }

    #[test]
    fn test_parse_arp_table_mac() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     192.168.1.10     0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                     192.168.1.11     0x1         0x2         00:00:00:00:00:00     *        eth0";

        assert_eq!(
            parse_arp_table_mac(table, "192.168.1.10".parse().unwrap()),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            parse_arp_table_mac(table, "192.168.1.11".parse().unwrap()),
            None
        );
        assert_eq!(
            parse_arp_table_mac(table, "192.168.1.12".parse().unwrap()),
            None
        );
    }

    #[test]
    fn test_parse_arp_command_output_mac_unix() {
        let output = "? (192.168.1.10) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        assert_eq!(
            parse_arp_command_output_mac(output, "192.168.1.10".parse().unwrap()),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn test_parse_arp_command_output_mac_windows() {
        let output = "Interface: 192.168.1.1 --- 0x7\n\
                      Internet Address      Physical Address      Type\n\
                      192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic";
        assert_eq!(
            parse_arp_command_output_mac(output, "192.168.1.10".parse().unwrap()),
            Some("aa:bb:cc:dd:ee:ff".to_string())
        );
    }
}
