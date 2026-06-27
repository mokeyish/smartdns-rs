use crate::dns::*;
use crate::dnsmasq::LanClientStore;
use crate::libdns::proto::rr::RecordType;
use crate::middleware::*;
use std::borrow::Borrow;
use std::path::Path;
use std::time::{Duration, Instant};

pub struct DnsmasqMiddleware {
    client_store: LanClientStore,
}

impl DnsmasqMiddleware {
    pub fn new<P: AsRef<Path>>(lease_file: P, domain: Option<Name>) -> Self {
        Self {
            client_store: LanClientStore::new(lease_file, domain),
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsmasqMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        // If it's a PTR query, try to resolve it using reverse lookup.
        if req.query().query_type() == RecordType::PTR {
            // Extract the IP address from the PTR query name.
            // PTR queries are in the format: x.x.x.x.in-addr.arpa. for IPv4
            // or x.x.x.x...ip6.arpa. for IPv6.
            if let Ok(ip_addr) = crate::dnsmasq::ptr_to_ip(req.query().name())
                && let Some(rdata) = self.client_store.reverse_lookup(&ip_addr)
            {
                let local_ttl = ctx.cfg().local_ttl();
                let query = req.query().original().clone();
                let name = query.name().to_owned();
                let valid_until = Instant::now() + Duration::from_secs(local_ttl);

                let lookup = DnsResponse::new_with_deadline(
                    query,
                    vec![Record::from_rdata(name, local_ttl as u32, rdata)],
                    valid_until,
                );
                ctx.source = LookupFrom::Static;
                return Ok(lookup);
            }
            // If it's a PTR query but we couldn't resolve it from lease file, fall through.
        }

        // Existing lookup logic for A/AAAA, etc.
        if let Some(rdata) = self
            .client_store
            .lookup(req.query().name().borrow(), req.query().query_type())
        {
            let local_ttl = ctx.cfg().local_ttl();

            let query = req.query().original().clone();
            let name = query.name().to_owned();
            let valid_until = Instant::now() + Duration::from_secs(local_ttl);

            let lookup = DnsResponse::new_with_deadline(
                query,
                vec![Record::from_rdata(name, local_ttl as u32, rdata)],
                valid_until,
            );

            ctx.source = LookupFrom::Static;
            return Ok(lookup);
        }

        next.run(ctx, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_dnsmasq_middleware_reverse_lookup() {
        let mw = DnsmasqMiddleware::new("tests/test_data/dhcp.leases", None);

        // Trigger cache initialization first
        let _ = mw
            .client_store
            .lookup(&"Andy-PC".parse().unwrap(), RecordType::A);

        // Test IPv4 reverse lookup
        let name = Name::from_str("16.100.168.192.in-addr.arpa.").unwrap();
        let ip = crate::dnsmasq::ptr_to_ip(&name).unwrap();
        let rdata = mw.client_store.reverse_lookup(&ip);
        assert!(rdata.is_some());
        // Verify the returned PTR record contains the expected hostname
        if let Some(RData::PTR(ptr)) = rdata {
            assert_eq!(ptr.0.to_string(), "andy-pc.");
        }

        // Test IPv6 reverse lookup
        let name = Name::from_str(
            "7.4.9.4.8.1.0.f.1.7.6.9.0.0.0.0.0.0.5.e.3.1.0.1.0.0.e.4.2.0.4.2.ip6.arpa.",
        )
        .unwrap();
        let ip = crate::dnsmasq::ptr_to_ip(&name).unwrap();
        let rdata = mw.client_store.reverse_lookup(&ip);
        assert!(rdata.is_some());
        // Verify the returned PTR record contains the expected hostname
        if let Some(RData::PTR(ptr)) = rdata {
            assert_eq!(ptr.0.to_string(), "iphone-abc.");
        }

        // Test reverse lookup for IP not in lease file
        let ip = IpAddr::from_str("10.0.0.1").unwrap();
        let rdata = mw.client_store.reverse_lookup(&ip);
        assert!(rdata.is_none());
    }
}
