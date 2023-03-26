use std::{borrow::Borrow, sync::Arc};

use trust_dns_proto::{
    op::{Query, ResponseCode},
    rr::{rdata::SOA, IntoName, Record, RecordType},
};

use trust_dns_resolver::error::ResolveErrorKind;

use crate::{
    dns::{DefaultSOA, DnsContext, DnsError, DnsRequest, DnsResponse},
    dns_conf::{ServerOpts, SmartDnsConfig},
    middleware::{Middleware, MiddlewareBuilder, MiddlewareDefaultHandler, MiddlewareHost},
};

pub type DnsMiddlewareHost = MiddlewareHost<DnsContext, DnsRequest, DnsResponse, DnsError>;

pub struct DnsMiddlewareHandler {
    cfg: Arc<SmartDnsConfig>,
    host: DnsMiddlewareHost,
}

impl DnsMiddlewareHandler {
    pub async fn search(
        &self,
        req: &DnsRequest,
        server_opts: &ServerOpts,
    ) -> Result<DnsResponse, DnsError> {
        let cfg = self.cfg.clone();
        let mut ctx = DnsContext::new(req.query().name().borrow(), cfg, server_opts.clone());
        self.host.execute(&mut ctx, req).await
    }

    pub async fn lookup<N: IntoName>(
        &self,
        name: N,
        query_type: RecordType,
    ) -> Result<DnsResponse, DnsError> {
        let query = Query::query(name.into_name()?, query_type);
        self.search(&query.into(), &Default::default()).await
    }
}

pub struct DnsMiddlewareBuilder {
    builder: MiddlewareBuilder<DnsContext, DnsRequest, DnsResponse, DnsError>,
}

impl DnsMiddlewareBuilder {
    pub fn new() -> Self {
        Self {
            builder: MiddlewareBuilder::new(DnsDefaultHandler::default()),
        }
    }

    pub fn with<M: Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> + 'static>(
        mut self,
        middleware: M,
    ) -> Self {
        self.builder = self.builder.with(middleware);
        self
    }

    pub fn build(self, cfg: Arc<SmartDnsConfig>) -> DnsMiddlewareHandler {
        DnsMiddlewareHandler {
            host: self.builder.build(),
            cfg,
        }
    }
}

#[derive(Default)]
struct DnsDefaultHandler;

#[async_trait::async_trait]
impl MiddlewareDefaultHandler<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsDefaultHandler {
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
    ) -> Result<DnsResponse, DnsError> {
        let soa = Record::from_rdata(
            req.query().name().to_owned().into(),
            ctx.cfg().rr_ttl().unwrap_or_default() as u32,
            SOA::default_soa(),
        );
        Err(ResolveErrorKind::NoRecordsFound {
            query: req.query().original().to_owned().into(),
            soa: Some(Box::new(soa)),
            negative_ttl: None,
            response_code: ResponseCode::ServFail,
            trusted: true,
        }
        .into())
    }
}

#[cfg(test)]
pub use tests::*;

#[cfg(test)]
mod tests {

    use std::{
        collections::HashMap,
        net::{Ipv4Addr, Ipv6Addr},
    };
    use trust_dns_proto::rr::RData;
    use trust_dns_resolver::lookup::Lookup;

    use super::*;
    use crate::infra::middleware::*;

    pub struct DnsMockMiddleware {
        map: HashMap<Query, Result<DnsResponse, DnsError>>,
    }

    impl DnsMockMiddleware {
        #[inline]
        pub fn builder() -> DnsMockMiddlewareBuilder {
            DnsMockMiddlewareBuilder::new()
        }

        pub fn mock<M: Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> + 'static>(
            middleware: M,
        ) -> DnsMockMiddlewareBuilder {
            Self::builder().with_extra_middleware(middleware)
        }
    }

    #[async_trait::async_trait]
    impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsMockMiddleware {
        async fn handle(
            &self,
            ctx: &mut DnsContext,
            req: &DnsRequest,
            next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
        ) -> Result<DnsResponse, DnsError> {
            match self.map.get(req.query().original()) {
                Some(res) => res.clone(),
                None => next.run(ctx, req).await,
            }
        }
    }

    pub struct DnsMockMiddlewareBuilder {
        map: HashMap<Query, Result<DnsResponse, DnsError>>,
        builder: DnsMiddlewareBuilder,
    }

    impl DnsMockMiddlewareBuilder {
        fn new() -> Self {
            Self {
                map: Default::default(),
                builder: DnsMiddlewareBuilder::new(),
            }
        }

        pub fn with_extra_middleware<
            M: Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> + 'static,
        >(
            mut self,
            middleware: M,
        ) -> Self {
            self.builder = self.builder.with(middleware);
            self
        }

        pub fn build(self, cfg: Arc<SmartDnsConfig>) -> DnsMiddlewareHandler {
            let Self { map, builder } = self;

            builder.with(DnsMockMiddleware { map }).build(cfg)
        }

        pub fn with_a_record<N: IntoName>(self, name: N, ip: Ipv4Addr) -> Self {
            self.with_rdata(name, RData::A(ip.into()))
        }

        pub fn with_aaaa_record<N: IntoName>(self, name: N, ip: Ipv6Addr) -> Self {
            self.with_rdata(name, RData::AAAA(ip.into()))
        }

        pub fn with_rdata<N: IntoName>(mut self, name: N, rdata: RData) -> Self {
            let name = name.into_name().expect("");
            let query = Query::query(name, rdata.record_type());
            self.map
                .insert(query.clone(), Ok(Lookup::from_rdata(query, rdata)));
            self
        }
    }

    impl DnsMiddlewareHandler {
        pub async fn lookup_rdata<N: IntoName>(
            &self,
            name: N,
            query_type: RecordType,
        ) -> Result<Vec<RData>, DnsError> {
            self.lookup(name, query_type)
                .await
                .map(|lookup| lookup.into_iter().collect())
        }
    }

    #[test]
    fn test_mock_middleware_ip() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mw = DnsMockMiddleware::builder()
                    .with_a_record("qq.com", "1.5.6.7".parse().unwrap())
                    .build(Default::default());

                let res = mw.lookup_rdata("qq.com", RecordType::A).await.unwrap();

                assert_eq!(res, vec![RData::A("1.5.6.7".parse().unwrap())]);
            });
    }

    #[test]
    fn test_mock_middleware_soa() {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mw = DnsMockMiddleware::builder()
                    .with_a_record("qq.com", "1.5.6.7".parse().unwrap())
                    .build(Default::default());

                let res = mw.lookup_rdata("baidu.com", RecordType::A).await;

                assert!(res.is_err());

                let err = res.unwrap_err();

                assert!(err.is_soa());
            });
    }
}
