

use std::sync::Arc;

use trust_dns_client::{rr::{Record, RData}, op::ResponseCode};
use trust_dns_resolver::error::ResolveErrorKind;

use crate::{
    dns_conf::SmartDnsConfig,
    middleware::{Middleware, MiddlewareBuilder, MiddlewareDefaultHandler, MiddlewareHost},
    dns::{
        DnsContext, DnsRequest, DnsResponse, DnsError, DefaultSOA
    }
};

pub struct DnsMiddlewareHandler {
    pub cfg: Arc<SmartDnsConfig>,
    host: MiddlewareHost<DnsContext, DnsRequest, DnsResponse, DnsError>
}

impl DnsMiddlewareHandler {
    
    pub async fn search(&self, req: & DnsRequest) -> Result<DnsResponse, DnsError> {
        let mut ctx = DnsContext{
            cfg: self.cfg.clone()
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

    pub fn with<M: Middleware<DnsContext, DnsRequest, DnsResponse, DnsError> + 'static>(mut self, middleware: M) -> Self {
        self.builder = self.builder.with(middleware);
        self
    }

    pub fn build(self, cfg: SmartDnsConfig) -> DnsMiddlewareHandler {
        DnsMiddlewareHandler {
            host: self.builder.build(),
            cfg: Arc::new(cfg)
        }
    }
}


#[derive(Default)]
struct DnsDefaultHandler;

#[async_trait::async_trait]
impl<'a> MiddlewareDefaultHandler<DnsContext, DnsRequest, DnsResponse, DnsError> for DnsDefaultHandler {
    async fn handle(&self, ctx: &mut DnsContext, req: &DnsRequest) -> Result<DnsResponse, DnsError> {
        let soa = Record::from_rdata(
            req.query().name().to_owned().into(), 
            ctx.cfg.rr_ttl() as u32, 
            RData::default_soa()
        );
        Err(ResolveErrorKind::NoRecordsFound { 
            query: req.query().original().to_owned().into(), 
            soa: Some(Box::new(soa)), 
            negative_ttl: None, 
            response_code: ResponseCode::ServFail, 
            trusted: true
        }.into())
    }
}

