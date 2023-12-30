use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::libdns::proto::rr::rdata::PTR;
use ipnet::IpNet;

use crate::dns::*;
use crate::dns_conf::RuntimeConfig;
use crate::infra::ipset::IpSet;
use crate::middleware::*;

pub struct DnsZoneMiddleware {
    server_net: IpSet,
    server_names: BTreeSet<Name>,
}

impl DnsZoneMiddleware {
    pub fn new(_cfg: &RuntimeConfig) -> Self {
        let server_net = {
            use local_ip_address::list_afinet_netifas;
            let mut ips = Vec::<IpAddr>::new();

            if let Ok(network_interfaces) = list_afinet_netifas() {
                for (_, ip) in network_interfaces.iter() {
                    ips.push(*ip);
                }
            }

            IpSet::new(
                ips.into_iter()
                    .map(|ip| match ip {
                        IpAddr::V4(_) => IpNet::new(ip, 32).unwrap(),
                        IpAddr::V6(_) => IpNet::new(ip, 128).unwrap(),
                    })
                    .collect(),
            )
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
        let rtype = query.query_type();

        if rtype == RecordType::PTR {
            let mut is_current_server = false;
            let name: &Name = name.borrow();

            if self.server_names.contains(name) {
                is_current_server = true;
            } else if let Ok(net) = name.parse_arpa_name() {
                is_current_server = self.server_net.iter().any(|ip| net.contains(ip));
            }

            if is_current_server {
                return Ok(DnsResponse::from_rdata(
                    req.query().original().to_owned(),
                    RData::PTR(PTR(ctx.cfg().server_name())),
                ));
            }
        };

        next.run(ctx, req).await
    }
}

#[cfg(test)]
mod tests {

    use crate::infra::ipset::IpSet;

    use super::*;

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

        assert!(local_net.iter().any(|net| net2.contains(net)));
    }
}
