use std::sync::Arc;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use crate::libdns::proto::op::Query;
use tokio::sync::RwLock;

use crate::libdns::resolver::Hosts;
use crate::middleware::*;
use crate::{dns::*, log};

pub struct DnsHostsMiddleware(RwLock<Option<HostsCache>>);

struct HostsCache {
    hosts: Arc<Hosts>,
    signature: HostsFileSignature,
    checked_at: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostsFileSignature {
    files: Vec<HostsFileMeta>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostsFileMeta {
    path: PathBuf,
    modified_at: Option<SystemTime>,
}

impl DnsHostsMiddleware {
    pub fn new() -> Self {
        Self(Default::default())
    }

    async fn cached_hosts(&self, hosts_file_pattern: Option<&glob::Pattern>) -> Arc<Hosts> {
        let now = Instant::now();

        {
            let cache = self.0.read().await;
            if let Some(cache) = cache.as_ref()
                && now.duration_since(cache.checked_at) < HOSTS_FILE_STAT_INTERVAL
            {
                return cache.hosts.clone();
            }
        }

        let signature = collect_hosts_signature(hosts_file_pattern);

        {
            let mut cache = self.0.write().await;
            if let Some(cache) = cache.as_mut() {
                if now.duration_since(cache.checked_at) < HOSTS_FILE_STAT_INTERVAL {
                    return cache.hosts.clone();
                }

                if cache.signature == signature {
                    cache.checked_at = now;
                    return cache.hosts.clone();
                }
            }
        }

        let refreshed_hosts = Arc::new(match hosts_file_pattern {
            Some(pattern) => read_hosts(pattern.as_str()),
            None => Hosts::default(),
        });

        let mut cache = self.0.write().await;
        *cache = Some(HostsCache {
            hosts: refreshed_hosts.clone(),
            signature,
            checked_at: now,
        });
        refreshed_hosts
    }
}

const HOSTS_FILE_STAT_INTERVAL: Duration = Duration::from_secs(2);

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
            let hosts = self.cached_hosts(ctx.cfg().hosts_file()).await;

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

fn collect_hosts_signature(hosts_file_pattern: Option<&glob::Pattern>) -> HostsFileSignature {
    let mut files = Vec::new();

    if let Some(pattern) = hosts_file_pattern {
        match glob::glob(pattern.as_str()) {
            Ok(paths) => {
                for entry in paths {
                    match entry {
                        Ok(path) => {
                            append_hosts_file_meta(path.as_path(), &mut files);
                        }
                        Err(err) => {
                            log::error!("{}", err);
                        }
                    }
                }
            }
            Err(err) => {
                log::error!("{}", err);
            }
        }
    }

    for path in system_hosts_paths() {
        append_hosts_file_meta(Path::new(path), &mut files);
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.dedup_by(|a, b| a.path == b.path);
    HostsFileSignature { files }
}

fn append_hosts_file_meta(path: &Path, files: &mut Vec<HostsFileMeta>) {
    if !path.is_file() {
        return;
    }

    let modified_at = std::fs::metadata(path)
        .ok()
        .and_then(|meta| meta.modified().ok());

    files.push(HostsFileMeta {
        path: path.to_path_buf(),
        modified_at,
    });
}

#[cfg(unix)]
fn system_hosts_paths() -> &'static [&'static str] {
    &["/etc/hosts"]
}

#[cfg(windows)]
fn system_hosts_paths() -> &'static [&'static str] {
    &["C:\\Windows\\System32\\drivers\\etc\\hosts"]
}

#[cfg(not(any(unix, windows)))]
fn system_hosts_paths() -> &'static [&'static str] {
    &[]
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
    use std::{net::IpAddr, str::FromStr, time::Duration};

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

    #[tokio::test()]
    async fn test_hosts_cache_refresh_on_file_change() -> anyhow::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let hosts_file = temp_dir.path().join("smartdns-hosts-refresh-test");
        std::fs::write(&hosts_file, "1.1.1.1 host-refresh\n")?;

        let cfg = RuntimeConfig::builder()
            .with(format!("hosts-file {}", hosts_file.display()))
            .build()
            .unwrap();

        let mock = DnsMockMiddleware::mock(DnsHostsMiddleware::new()).build(cfg);

        let lookup = mock.lookup("host-refresh", RecordType::A).await?;
        let ip_addrs = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().ip_addr())
            .collect::<Vec<_>>();
        assert_eq!(ip_addrs, vec![IpAddr::from_str("1.1.1.1").unwrap()]);

        tokio::time::sleep(HOSTS_FILE_STAT_INTERVAL + Duration::from_secs(1)).await;
        std::fs::write(&hosts_file, "2.2.2.2 host-refresh\n")?;
        tokio::time::sleep(HOSTS_FILE_STAT_INTERVAL + Duration::from_secs(1)).await;

        let lookup = mock.lookup("host-refresh", RecordType::A).await?;
        let ip_addrs = lookup
            .records()
            .iter()
            .flat_map(|r| r.data().ip_addr())
            .collect::<Vec<_>>();
        assert_eq!(ip_addrs, vec![IpAddr::from_str("2.2.2.2").unwrap()]);

        Ok(())
    }
}
