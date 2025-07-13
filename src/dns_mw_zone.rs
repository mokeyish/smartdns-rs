use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::libdns::proto::rr::rdata::PTR;

use crate::config::HttpsRecordRule;
use crate::dns::*;
use crate::infra::ipset::IpSet;
use crate::middleware::*;

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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::infra::ipset::IpSet;
    use crate::{dns_conf::RuntimeConfig, dns_mw::*};

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
}
