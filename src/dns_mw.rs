use std::{borrow::Borrow, sync::Arc};

use crate::libdns::proto::{
    error::ProtoErrorKind,
    op::{Query, ResponseCode},
    rr::{rdata::SOA, IntoName, Record, RecordType},
};

use crate::{
    config::ServerOpts,
    dns::{DefaultSOA, DnsContext, DnsError, DnsRequest, DnsResponse},
    dns_conf::RuntimeConfig,
    middleware::{Middleware, MiddlewareBuilder, MiddlewareDefaultHandler, MiddlewareHost},
};

pub type DnsMiddlewareHost = MiddlewareHost<DnsContext, DnsRequest, DnsResponse, DnsError>;

pub struct BackgroundQueryTask {
    pub ctx: DnsContext,
    pub req: DnsRequest,
    client: Arc<DnsMiddlewareHost>,
}

impl BackgroundQueryTask {
    pub fn new(ctx: &DnsContext, req: &DnsRequest, client: Arc<DnsMiddlewareHost>) -> Self {
        Self {
            ctx: ctx.clone(),
            req: req.clone(),
            client,
        }
    }

    pub fn from_query(
        query: Query,
        cfg: Arc<RuntimeConfig>,
        client: Arc<DnsMiddlewareHost>,
    ) -> Self {
        let ctx = DnsContext::new(query.name(), cfg, Default::default());
        let req = query.into();
        Self { ctx, req, client }
    }

    pub fn spawn(self) -> tokio::task::JoinHandle<(Self, Result<DnsResponse, DnsError>)> {
        tokio::spawn(async move {
            let Self {
                mut ctx,
                req,
                client,
            } = self;
            let res = client.execute(&mut ctx, &req).await;
            (Self { ctx, req, client }, res)
        })
    }
}

pub struct DnsMiddlewareHandler {
    cfg: Arc<RuntimeConfig>,
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
            builder: MiddlewareBuilder::new(DnsDefaultHandler),
        }
    }

    pub fn with<M: Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> + 'static>(
        mut self,
        middleware: M,
    ) -> Self {
        self.builder = self.builder.with(middleware);
        self
    }

    pub fn build(self, cfg: Arc<RuntimeConfig>) -> DnsMiddlewareHandler {
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
        Err(ProtoErrorKind::NoRecordsFound {
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

    use crate::libdns::proto::rr::RData;
    use std::{
        collections::HashMap,
        fmt::Debug,
        net::{Ipv4Addr, Ipv6Addr},
    };

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

        pub fn build<T: Into<Arc<RuntimeConfig>>>(self, cfg: T) -> DnsMiddlewareHandler {
            let Self { map, builder } = self;

            builder.with(DnsMockMiddleware { map }).build(cfg.into())
        }

        pub fn with_a_record<N: IntoName>(self, name: N, ip: Ipv4Addr) -> Self {
            self.with_rdata(name, RData::A(ip.into()), 10 * 60)
        }

        pub fn with_a_record_and_ttl<N: IntoName>(self, name: N, ip: Ipv4Addr, ttl: u32) -> Self {
            self.with_rdata(name, RData::A(ip.into()), ttl)
        }

        pub fn with_aaaa_record<N: IntoName>(self, name: N, ip: Ipv6Addr) -> Self {
            self.with_rdata(name, RData::AAAA(ip.into()), 10 * 60)
        }

        pub fn with_aaaa_record_and_ttl<N: IntoName>(
            self,
            name: N,
            ip: Ipv6Addr,
            ttl: u32,
        ) -> Self {
            self.with_rdata(name, RData::AAAA(ip.into()), ttl)
        }

        pub fn with_rdata<N: IntoName>(self, name: N, rdata: RData, ttl: u32) -> Self {
            let name = match name.into_name() {
                Ok(name) => name,
                Err(err) => panic!("invalid Name {}", err),
            };

            self.with_record(Record::from_rdata(name, ttl, rdata))
        }

        pub fn with_record(self, record: Record) -> Self {
            self.with_multi_records(record.name().clone(), record.record_type(), vec![record])
        }

        pub fn with_multi_records<Name: IntoName + Debug>(
            mut self,
            name: Name,
            record_type: RecordType,
            records: Vec<Record>,
        ) -> Self {
            let name = match name.into_name() {
                Ok(name) => name,
                Err(err) => panic!("invalid Name {}", err),
            };

            let query = Query::query(name, record_type);

            self.map.insert(
                query.clone(),
                Ok(DnsResponse::new_with_max_ttl(query, records)),
            );

            self
        }
    }

    impl DnsMiddlewareHandler {
        pub async fn lookup_rdata<N: IntoName>(
            &self,
            name: N,
            query_type: RecordType,
        ) -> Result<Vec<RData>, DnsError> {
            self.lookup(name, query_type).await.map(|lookup| {
                lookup
                    .record_iter()
                    .flat_map(|s| s.data())
                    .cloned()
                    .collect()
            })
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mock_middleware_ip() {
        let mw = DnsMockMiddleware::builder()
            .with_a_record("qq.com", "1.5.6.7".parse().unwrap())
            .build(RuntimeConfig::default());

        let res = mw.lookup_rdata("qq.com", RecordType::A).await.unwrap();

        assert_eq!(res, vec![RData::A("1.5.6.7".parse().unwrap())]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_mock_middleware_soa() {
        let mw = DnsMockMiddleware::builder()
            .with_a_record("qq.com", "1.5.6.7".parse().unwrap())
            .build(RuntimeConfig::default());

        let res = mw.lookup_rdata("baidu.com", RecordType::A).await;

        assert!(res.is_err());

        let err = res.unwrap_err();

        assert!(err.is_soa());
    }
}
