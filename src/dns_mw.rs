use std::{borrow::Borrow, sync::Arc};

use trust_dns_proto::{
    op::ResponseCode,
    rr::{RData, Record},
};

use trust_dns_resolver::error::ResolveErrorKind;

use crate::{
    dns::{DefaultSOA, DnsContext, DnsError, DnsRequest, DnsResponse},
    dns_client::DnsClient,
    dns_conf::{QueryOpts, SmartDnsConfig},
    matcher::DomainRuleMatcher,
    middleware::{Middleware, MiddlewareBuilder, MiddlewareDefaultHandler, MiddlewareHost},
};

pub struct DnsMiddlewareHandler {
    cfg: Arc<SmartDnsConfig>,
    client: Arc<DnsClient>,
    domain_rules: DomainRuleMatcher,
    host: MiddlewareHost<DnsContext, DnsRequest, DnsResponse, DnsError>,
}

impl DnsMiddlewareHandler {
    pub async fn search(
        &self,
        req: &DnsRequest,
        server_opts: &QueryOpts,
    ) -> Result<DnsResponse, DnsError> {
        let domain_rule = self
            .domain_rules
            .find(req.query().name().borrow())
            .map(|n| n.to_owned());

        let mut ctx = DnsContext {
            cfg: self.cfg.clone(),
            client: self.client.clone(),
            fastest_speed: Default::default(),
            lookup_source: Default::default(),
            no_cache: false,
            query_opts: server_opts.clone(),
            domain_rule,
        };
        self.host.execute(&mut ctx, req).await
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

    pub fn build(self, cfg: Arc<SmartDnsConfig>, client: Arc<DnsClient>) -> DnsMiddlewareHandler {
        let domain_rules = DomainRuleMatcher::create(&cfg);
        DnsMiddlewareHandler {
            host: self.builder.build(),
            cfg,
            domain_rules,
            client,
        }
    }
}

#[derive(Default)]
struct DnsDefaultHandler;

#[async_trait::async_trait]
impl<'a> MiddlewareDefaultHandler<DnsContext, DnsRequest, DnsResponse, DnsError>
    for DnsDefaultHandler
{
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
    ) -> Result<DnsResponse, DnsError> {
        let soa = Record::from_rdata(
            req.query().name().to_owned().into(),
            ctx.cfg.rr_ttl() as u32,
            RData::default_soa(),
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
