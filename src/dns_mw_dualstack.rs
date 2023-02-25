use crate::dns::*;
use crate::middleware::*;

pub struct DnsDualStackIpSelectionMiddleware;

#[async_trait::async_trait]
impl Middleware<DnsContext, DnsRequest, DnsResponse, DnsError>
    for DnsDualStackIpSelectionMiddleware
{
    async fn handle(
        &self,
        ctx: &mut DnsContext,
        req: &DnsRequest,
        next: Next<'_, DnsContext, DnsRequest, DnsResponse, DnsError>,
    ) -> Result<DnsResponse, DnsError> {
        // use RecordType::{A, AAAA};

        // // highest priority
        // if ctx.server_opts.no_dualstack_selection() {
        //     return next.run(ctx, req).await;
        // }

        // let query_type = req.query().query_type();

        // // must be ip query.
        // if !matches!(query_type, A | AAAA) {
        //     return next.run(ctx, req).await;
        // }

        // // read config
        // let dualstack_ip_selection = ctx
        //     .domain_rule
        //     .as_ref()
        //     .map(|rule| rule.dualstack_ip_selection)
        //     .unwrap_or_default()
        //     .unwrap_or(ctx.cfg.dualstack_ip_selection());

        // if !dualstack_ip_selection {
        //     return next.run(ctx, req).await;
        // }

        // let (new_ctx, new_req, new_next) = {
        //     let mut new_req = req.clone();
        //     new_req.set_query_type(match query_type {
        //         A => AAAA,
        //         AAAA => A,
        //         typ @ _ => typ,
        //     });

        //     (ctx.clone(), new_req, next.clone())
        // };

        // let tasks = [
        //     next.run(ctx, req).boxed(),
        //     move || async { new_next.run(&mut new_ctx, &new_req).await }.boxed(),
        // ];

        // todo!()

        next.run(ctx, req).await
    }
}
