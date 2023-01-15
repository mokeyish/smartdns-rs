use std::time::Duration;

use crate::infra::ping::{ping, PingAddr};
use crate::log::warn;
use trust_dns_resolver::config::NameServerConfigGroup;

#[async_trait::async_trait]
pub trait NameServerConfigGroupExt: Send + Sync {
    async fn filter_available(&self) -> Self;
}

#[async_trait::async_trait]
impl NameServerConfigGroupExt for NameServerConfigGroup {
    async fn filter_available(&self) -> Self {
        let addrs = self
            .iter()
            .map(|item| {
                if item.protocol.is_datagram() {
                    PingAddr::Icmp(item.socket_addr.ip())
                } else {
                    PingAddr::Tcp(item.socket_addr)
                }
            })
            .collect::<Vec<_>>();

        let outputs = ping(&addrs, 3, Some(Duration::from_secs(3))).await;

        let mut group = Self::new();

        for (i, item) in self.iter().enumerate() {
            let out = &outputs[i];
            if out.has_err() {
                warn!(
                    "nameserver {} skipped. {:?}",
                    item.socket_addr,
                    out.duration().as_ref().unwrap_err()
                );
            } else {
                group.push(item.clone());
            }
        }
        group
    }
}
