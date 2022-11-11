use crate::{
    dns_client::{create_resolver, resolve},
    dns_conf::SmartDnsConfig,
    matcher::DomainNameServerMatcher,
};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use tokio::sync::Mutex;
use trust_dns_client::rr::LowerName;
use trust_dns_resolver::{
    config::{NameServerConfigGroup, ResolverOpts},
    TokioAsyncResolver,
};
use url::Host;

use crate::dns::*;
use crate::log::debug;
use crate::middleware::*;

#[derive(Debug)]
pub struct NameServerMiddleware {
    map: DomainNameServerMatcher,
    nameservers: Mutex<HashMap<String, NameServerConfigGroup>>,
    resolvers: Mutex<HashMap<String, Arc<TokioAsyncResolver>>>,
}

impl NameServerMiddleware {
    pub fn new(cfg: &SmartDnsConfig) -> Self {
        Self {
            map: DomainNameServerMatcher::create(cfg),
            nameservers: Default::default(),
            resolvers: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for NameServerMiddleware {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: crate::middleware::Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        let name = req.query().name();

        debug!("searching nameserver for: {}", name);

        let group_name = self.map.find(name).map(|s| s.as_str()).unwrap_or("default");

        if let Some(resolver) = self.get_resolver(&ctx.cfg, group_name).await {
            let rtype = req.query().query_type();
            debug!("forwarding lookup: {} {} @{}", name, rtype, group_name);
            let name: LowerName = name.clone();
            let resolve = resolver.lookup(name, rtype).await;

            return resolve;
        }

        next.run(ctx, req).await
    }
}

impl NameServerMiddleware {
    async fn get_resolver(
        &self,
        cfg: &SmartDnsConfig,
        group_name: &str,
    ) -> Option<Arc<TokioAsyncResolver>> {
        let resolver = async {
            let resolvers = self.resolvers.lock().await;
            resolvers.get(group_name).map(|r| Arc::clone(r))
        }
        .await;

        if resolver.is_some() {
            return resolver;
        }

        let group_name = if cfg.servers.contains_key(group_name) {
            group_name
        } else {
            "default"
        };

        let nameservers = self.get_nameservers(cfg, group_name).await;

        if let Some(Ok(resolver)) = nameservers.map(|ss| {
            create_resolver(
                ss,
                Some({
                    let mut opts = ResolverOpts::default();
                    opts.cache_size = 0;
                    opts
                }),
            )
        }) {
            let resolver = Arc::new(resolver);
            let mut resolvers = self.resolvers.lock().await;

            resolvers.insert(group_name.to_string(), Arc::clone(&resolver));

            Some(resolver)
        } else {
            None
        }
    }

    async fn get_nameservers(
        &self,
        cfg: &SmartDnsConfig,
        group_name: &str,
    ) -> Option<NameServerConfigGroup> {
        let config = async {
            let nameservers = self.nameservers.lock().await;
            nameservers.get(group_name).map(|n| n.clone())
        }
        .await;

        if config.is_some() {
            return config;
        }

        let mut name_server_cfg_group = NameServerConfigGroup::new();

        let ss = cfg
            .servers
            .get(group_name)
            .expect("default nameserver group not found!!!");

        for s in ss {
            if let Host::Domain(domain) = s.url.host() {
                if let Ok(Some(g_name)) = LowerName::from_str(domain).map(|n| self.map.find(&n)) {
                    use futures::future;

                    let config = cfg
                        .servers
                        .get(g_name)
                        .expect("default nameserver group not found!!!");

                    let tmp_config = future::join_all(
                        config
                            .iter()
                            .map(|c| c.url.to_nameserver_config_group(None)),
                    )
                    .await
                    .into_iter()
                    .flat_map(|x| x.into_iter())
                    .reduce(|mut p, c| {
                        p.merge(c);
                        p
                    });

                    if let Some(tmp_config) = tmp_config {
                        if let Ok(addrs) = resolve(domain, Some(tmp_config)).await {
                            if let Some(s) = s.url.to_nameserver_config_group(Some(addrs)).await {
                                if !s.is_empty() {
                                    name_server_cfg_group.merge(s);
                                    continue;
                                }
                            }
                        }
                    }
                    
                }
            }

            if let Some(s) = s.url.to_nameserver_config_group(None).await {
                if !s.is_empty() {
                    name_server_cfg_group.merge(s);
                }
            }

        }

        async {
            let mut nameservers = self.nameservers.lock().await;

            nameservers.insert(group_name.to_string(), name_server_cfg_group.clone());
        }
        .await;

        Some(name_server_cfg_group)
    }
}
