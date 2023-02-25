use std::{borrow::Borrow, sync::Arc};

use trust_dns_proto::{
    op::ResponseCode,
    rr::{RData, Record},
};

use trust_dns_resolver::error::ResolveErrorKind;

use crate::{
    dns::{DefaultSOA, DnsContext, DnsError, DnsRequest, DnsResponse},
    dns_conf::{ServerOpts, SmartDnsConfig},
    dns_rule::DomainRuleMap,
    middleware::{Middleware, MiddlewareBuilder, MiddlewareDefaultHandler, MiddlewareHost},
};

pub type DnsMiddlewareHost = MiddlewareHost<DnsContext, DnsRequest, DnsResponse, DnsError>;

pub struct DnsMiddlewareHandler {
    cfg: Arc<SmartDnsConfig>,
    domain_rule_map: DomainRuleMap,
    host: DnsMiddlewareHost,
}

impl DnsMiddlewareHandler {
    pub async fn search(
        &self,
        req: &DnsRequest,
        server_opts: &ServerOpts,
    ) -> Result<DnsResponse, DnsError> {
        let _cfg = self.cfg.as_ref();

        let domain_rule = self
            .domain_rule_map
            .find(req.query().name().borrow())
            .cloned();

        let mut ctx = DnsContext {
            cfg: self.cfg.clone(),
            fastest_speed: Default::default(),
            source: Default::default(),
            server_opts: server_opts.clone(),
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

    pub fn build(self, cfg: Arc<SmartDnsConfig>) -> DnsMiddlewareHandler {
        let domain_rule_map = DomainRuleMap::create(
            &cfg.domain_rules,
            &cfg.address_rules,
            &cfg.forward_rules,
            &cfg.domain_sets,
        );

        DnsMiddlewareHandler {
            host: self.builder.build(),
            cfg,
            domain_rule_map,
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
