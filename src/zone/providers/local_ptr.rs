use std::borrow::Borrow;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::dns::{DnsContext, DnsError, DnsRequest, DnsResponse, Name, RData, RecordType};
use crate::infra::ipset::IpSet;
use crate::libdns::proto::rr::rdata::PTR;
use crate::zone::ZoneProvider;

pub struct LocalPtrZoneProvider {
    server_net: IpSet,
    server_names: BTreeSet<Name>,
}

impl LocalPtrZoneProvider {
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
impl ZoneProvider for LocalPtrZoneProvider {
    async fn lookup(
        &self,
        ctx: &DnsContext,
        req: &DnsRequest,
    ) -> Result<Option<DnsResponse>, DnsError> {
        if req.query().query_type() != RecordType::PTR {
            return Ok(None);
        }

        let query = req.query();
        let name: &Name = query.name().borrow();

        let mut is_current_server = false;
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
                    return Ok(Some(res));
                }
            }
        }

        if !is_current_server {
            return Ok(None);
        }

        Ok(Some(DnsResponse::from_rdata(
            query.original().to_owned(),
            RData::PTR(PTR(ctx.cfg().server_name())),
        )))
    }
}
