use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::libdns::proto::op::Query;
use tokio::sync::RwLock;

use crate::libdns::resolver::Hosts;
use crate::middleware::*;
use crate::{dns::*, log};

pub struct DnsHostsMiddleware(RwLock<Option<(Instant, Arc<Hosts>)>>);

impl DnsHostsMiddleware {
    pub fn new() -> Self {
        Self(Default::default())
    }
}

const EXPIRES: Duration = Duration::from_secs(5);

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsHostsMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let query = req.query().original();
        let is_ptr = query.query_type() == RecordType::PTR && ctx.cfg().expand_ptr_from_address();
        if query.query_type().is_ip_addr() || is_ptr {
            let hosts = self.0.read().await.as_ref().and_then(|(read_time, hosts)| {
                if Instant::now() - *read_time < EXPIRES {
                    Some(hosts.clone())
                } else {
                    None
                }
            });

            let hosts = match hosts {
                Some(v) => v,
                None => {
                    let hosts = match ctx.cfg().hosts_file() {
                        Some(pattern) => read_hosts(pattern.as_str()),
                        None => Hosts::default(), // read from system hosts file
                    };
                    let hosts = Arc::new(hosts);
                    *self.0.write().await = Some((Instant::now(), hosts.clone()));
                    hosts
                }
            };

            if let Some(lookup) = hosts.lookup_static_host(query).or_else(|| {
                let mut name = query.name().clone();
                name.set_fqdn(!name.is_fqdn());
                hosts.lookup_static_host(&Query::query(name, query.query_type()))
            }) {
                return Ok(DnsResponse::new_with_deadline(
                    query.clone(),
                    lookup.records().to_vec(),
                    lookup.valid_until(),
                ));
            }
        }

        next.run(ctx, req).await
    }
}

fn read_hosts(pattern: &str) -> Hosts {
    let mut hosts = Hosts::default();
    match glob::glob(pattern) {
        Ok(paths) => {
            for entry in paths {
                let path = match entry {
                    Ok(path) => {
                        if !path.is_file() {
                            continue;
                        }
                        path
                    }
                    Err(err) => {
                        log::error!("{}", err);
                        continue;
                    }
                };

                let file = match std::fs::OpenOptions::new().read(true).open(path) {
                    Ok(file) => file,
                    Err(err) => {
                        log::error!("{}", err);
                        continue;
                    }
                };

                if let Err(err) = hosts.read_hosts_conf(file) {
                    log::error!("{}", err);
                }
            }
        }
        Err(err) => {
            log::error!("{}", err);
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use crate::libdns::proto::rr::rdata::PTR;

    use super::*;

    use crate::{dns_conf::RuntimeConfig, dns_mw::*};

    #[tokio::test()]
    async fn test_query_ip() -> anyhow::Result<()> {
        let cfg = RuntimeConfig::builder()
            .with("hosts-file ./tests/test_data/hosts/a*.hosts")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(DnsHostsMiddleware::new()).build(cfg);

        let lookup = mock.lookup("hi.a1", RecordType::A).await?;
        let ip_addrs = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().ip_addr())
            .collect::<Vec<_>>();
        assert_eq!(ip_addrs, vec![IpAddr::from_str("1.1.1.1").unwrap()]);

        let lookup = mock.lookup("hi.a2", RecordType::A).await?;
        let ip_addrs = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().ip_addr())
            .collect::<Vec<_>>();
        assert_eq!(ip_addrs, vec![IpAddr::from_str("2.2.2.2").unwrap()]);

        Ok(())
    }

    #[tokio::test()]
    async fn test_query_ptr() -> anyhow::Result<()> {
        let cfg = RuntimeConfig::builder()
            .with("hosts-file ./tests/test_data/hosts/a*.hosts")
            .with("expand-ptr-from-address yes")
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(DnsHostsMiddleware::new()).build(cfg);

        let lookup = mock
            .lookup("1.1.1.1.in-addr.arpa.", RecordType::PTR)
            .await?;
        let hostnames = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().as_ptr())
            .collect::<Vec<_>>();
        assert_eq!(hostnames, vec![&PTR("hi.a1.".parse().unwrap())]);

        let lookup = mock
            .lookup("2.2.2.2.in-addr.arpa.", RecordType::PTR)
            .await?;
        let hostnames = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().as_ptr())
            .collect::<Vec<_>>();
        assert_eq!(hostnames, vec![&PTR("hi.a2.".parse().unwrap())]);

        Ok(())
    }
}
