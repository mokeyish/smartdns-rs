pub mod proto {
    pub use trust_dns_proto::*;
}

pub mod resolver {
    use trust_dns_resolver::lookup::Lookup;
    pub use trust_dns_resolver::*;

    pub trait LookupTtl {
        fn max_ttl(&self) -> Option<u32>;
        fn min_ttl(&self) -> Option<u32>;

        fn with_new_ttl(&self, ttl: u32) -> Self
        where
            Self: Sized;

        fn with_max_ttl(&self, ttl: u32) -> Self
        where
            Self: Sized;

        fn with_min_ttl(&self, ttl: u32) -> Self
        where
            Self: Sized;
    }

    impl LookupTtl for Lookup {
        fn max_ttl(&self) -> Option<u32> {
            self.record_iter().map(|record| record.ttl()).max()
        }

        fn min_ttl(&self) -> Option<u32> {
            self.record_iter().map(|record| record.ttl()).min()
        }

        fn with_new_ttl(&self, ttl: u32) -> Self {
            let records = self
                .records()
                .iter()
                .map(|record| {
                    let mut record = record.clone();
                    record.set_ttl(ttl);
                    record
                })
                .collect::<Vec<_>>();

            Lookup::new_with_deadline(self.query().clone(), records.into(), self.valid_until())
        }

        fn with_max_ttl(&self, ttl: u32) -> Self {
            let records = self
                .records()
                .iter()
                .map(|record| {
                    let mut record = record.clone();
                    record.set_ttl(ttl.min(record.ttl()));
                    record
                })
                .collect::<Vec<_>>();

            Lookup::new_with_deadline(self.query().clone(), records.into(), self.valid_until())
        }

        fn with_min_ttl(&self, ttl: u32) -> Self {
            let records = self
                .records()
                .iter()
                .map(|record| {
                    let mut record = record.clone();
                    record.set_ttl(ttl.max(record.ttl()));
                    record
                })
                .collect::<Vec<_>>();

            Lookup::new_with_deadline(self.query().clone(), records.into(), self.valid_until())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt::Display, io, net::SocketAddr, sync::Arc};

    #[test]
    fn test_with_https_pure_ip_address() {
        use crate::trust_dns::resolver::config::ResolverOpts;
        use crate::trust_dns::resolver::config::{NameServerConfigGroup, ResolverConfig};
        use crate::trust_dns::resolver::name_server::TokioRuntimeProvider;
        use crate::trust_dns::resolver::AsyncResolver;
        use crate::trust_dns::resolver::TokioAsyncResolver;
        use trust_dns_proto::rr::IntoName;
        use trust_dns_proto::rr::TryParseIp;

        let resolver = Arc::new(
            TokioAsyncResolver::new(
                ResolverConfig::from_parts(
                    None,
                    vec![],
                    NameServerConfigGroup::from_ips_https(
                        &["223.5.5.5".parse().unwrap()],
                        443,
                        "223.5.5.5".to_string(),
                        true,
                    ),
                ),
                ResolverOpts::default(),
                TokioRuntimeProvider::new(),
            )
            .unwrap(),
        );

        use std::thread;

        // Let's resolve some names, we should be able to do it across threads
        let names = &["www.google.com", "www.reddit.com", "www.wikipedia.org"];

        async fn resolve<N: IntoName + Display + TryParseIp + 'static>(
            host: N,
            port: u16,
            resolver: Arc<AsyncResolver<TokioRuntimeProvider>>,
        ) -> io::Result<Vec<SocketAddr>> {
            // Now we use the global resolver to perform a lookup_ip.
            let name = host.to_string();
            let result = resolver.lookup_ip(host).await;
            // map the result into what we want...
            result
                .map_err(move |err| {
                    // we transform the error into a standard IO error for convenience
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        format!("dns resolution error for {name}: {err}"),
                    )
                })
                .map(move |lookup_ip| {
                    // we take all the IPs returned, and then send back the set of IPs
                    lookup_ip
                        .iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect::<Vec<_>>()
                })
        }

        // spawn all the threads to do the lookups
        let threads = names
            .iter()
            .map(|name| {
                let resolver = resolver.clone();
                let join = thread::spawn(move || {
                    let runtime = tokio::runtime::Runtime::new().expect("failed to launch Runtime");

                    runtime.block_on(async move { resolve(*name, 443, resolver).await })
                });

                (name, join)
            })
            .collect::<Vec<_>>();

        // print the resolved IPs
        for (name, join) in threads {
            let result = join
                .join()
                .expect("resolution thread failed")
                .expect("resolution failed");
            println!("{name} resolved to {result:?}");
        }
    }
}
