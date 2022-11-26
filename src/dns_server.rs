use cfg_if::cfg_if;
use futures::Future;

use std::io;

use crate::log::{debug, error, info, warn};
use trust_dns_client::op::{Edns, Header, MessageType, OpCode, ResponseCode};
use trust_dns_proto::rr::Record;
pub use trust_dns_server::server::Request;
pub use trust_dns_server::ServerFuture;
use trust_dns_server::{
    authority::{
        AuthLookup, EmptyLookup, LookupError, LookupObject, LookupOptions, MessageResponse,
        MessageResponseBuilder, ZoneType,
    },
    server::{RequestHandler, ResponseHandler, ResponseInfo},
    store::forwarder::ForwardLookup,
};

use crate::dns::DnsRequest;
use crate::dns_mw::DnsMiddlewareHandler;

pub struct MiddlewareBasedRequestHandler {
    handler: DnsMiddlewareHandler,
}

impl MiddlewareBasedRequestHandler {
    pub fn new(handler: DnsMiddlewareHandler) -> Self {
        Self { handler }
    }
}

#[async_trait::async_trait]
impl RequestHandler for MiddlewareBasedRequestHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let result = match request.message_type() {
            // TODO think about threading query lookups for multiple lookups, this could be a huge improvement
            //  especially for recursive lookups
            MessageType::Query => match request.op_code() {
                OpCode::Query => {
                    let response_edns: Option<Edns>;

                    // check if it's edns

                    if let Some(req_edns) = request.edns() {
                        let mut response = MessageResponseBuilder::from_message_request(request);

                        let mut response_header = Header::response_from_request(request.header());

                        let mut resp_edns: Edns = Edns::new();

                        // check our version against the request
                        // TODO: what version are we?
                        let our_version = 0;
                        resp_edns.set_dnssec_ok(true);
                        resp_edns.set_max_payload(req_edns.max_payload().max(512));
                        resp_edns.set_version(our_version);
                        if req_edns.version() > our_version {
                            warn!(
                                "request edns version greater than {}: {}",
                                our_version,
                                req_edns.version()
                            );
                            response_header.set_response_code(ResponseCode::BADVERS);
                            resp_edns.set_rcode_high(ResponseCode::BADVERS.high());
                            response.edns(resp_edns);

                            // TODO: should ResponseHandle consume self?
                            let result = response_handle
                                .send_response(response.build_no_records(response_header))
                                .await;

                            // couldn't handle the request
                            return match result {
                                Err(e) => {
                                    error!("request error: {}", e);
                                    ResponseInfo::serve_failed()
                                }
                                Ok(info) => info,
                            };
                        }

                        response_edns = Some(resp_edns);
                    } else {
                        response_edns = None;
                    }

                    debug!(
                        "query received: {} {} {}",
                        request.id(),
                        request.query(),
                        request.query().query_type()
                    );

                    let info = async {
                        let res = async {
                            // let query = request_info.query;

                            // let (response_header, sections) = self.build_response(
                            //     request_info,
                            //     request.id(),
                            //     request.header(),
                            //     query,
                            // )
                            // .await;

                            let request_id = request.id();

                            let request_header = request.header();

                            let (response_header, sections) = async {
                                let lookup_options = lookup_options_for_edns(request.edns());

                                // log algorithms being requested
                                if lookup_options.is_dnssec() {
                                    info!(
                                        "request: {} lookup_options: {:?}",
                                        request_id, lookup_options
                                    );
                                }

                                let mut response_header =
                                    Header::response_from_request(request_header);
                                response_header
                                    .set_authoritative(ZoneType::Forward.is_authoritative());

                                // debug!("performing {} on {}", query, authority.origin());

                                // let future = self.dns_server.search(request_info, lookup_options);

                                let future = async {
                                    let req: &DnsRequest = request;

                                    let lookup_result: Result<Box<dyn LookupObject>, LookupError> =
                                        match self.handler.search(req).await {
                                            Ok(lookup) => Ok(Box::new(ForwardLookup(lookup))),
                                            Err(err) => Err(LookupError::ResolveError(err)),
                                        };

                                    lookup_result
                                };

                                let sections = send_forwarded_response(
                                    future,
                                    request_header,
                                    &mut response_header,
                                )
                                .await;

                                (response_header, sections)
                            }
                            .await;

                            let response = MessageResponseBuilder::from_message_request(request)
                                .build(
                                    response_header,
                                    sections.answers.iter(),
                                    sections.ns.iter(),
                                    sections.soa.iter(),
                                    sections.additionals.iter(),
                                );

                            let result = send_response(
                                response_edns.clone(),
                                response,
                                response_handle.clone(),
                            )
                            .await;

                            match result {
                                Err(e) => {
                                    error!("error sending response: {}", e);
                                    ResponseInfo::serve_failed()
                                }
                                Ok(i) => i,
                            }
                        }
                        .await;

                        res
                    }
                    .await;

                    Ok(info)
                }
                OpCode::Update => {
                    debug!("update received: {}", request.id());
                    // self.update(request, response_edns, response_handle).await
                    todo!()
                }
                c => {
                    warn!("unimplemented op_code: {:?}", c);
                    let response = MessageResponseBuilder::from_message_request(request);

                    response_handle
                        .send_response(response.error_msg(request.header(), ResponseCode::NotImp))
                        .await
                }
            },
            MessageType::Response => {
                warn!("got a response as a request from id: {}", request.id());
                let response = MessageResponseBuilder::from_message_request(request);

                response_handle
                    .send_response(response.error_msg(request.header(), ResponseCode::FormErr))
                    .await
            }
        };

        match result {
            Err(e) => {
                error!("request failed: {}", e);
                ResponseInfo::serve_failed()
            }
            Ok(info) => info,
        }
    }
}

async fn send_forwarded_response(
    future: impl Future<Output = Result<Box<dyn LookupObject>, LookupError>>,
    request_header: &Header,
    response_header: &mut Header,
) -> LookupSections {
    response_header.set_recursion_available(true);
    response_header.set_authoritative(false);

    // Don't perform the recursive query if this is disabled...
    let answers = if !request_header.recursion_desired() {
        // cancel the future??
        // future.cancel();
        drop(future);

        info!(
            "request disabled recursion, returning no records: {}",
            request_header.id()
        );

        Box::new(EmptyLookup)
    } else {
        match future.await {
            Err(e) => {
                if e.is_nx_domain() {
                    response_header.set_response_code(ResponseCode::NXDomain);
                }
                debug!("error resolving: {}", e);
                Box::new(EmptyLookup)
            }
            Ok(rsp) => rsp,
        }
    };

    LookupSections {
        answers,
        ns: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
        soa: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
        additionals: Box::new(AuthLookup::default()) as Box<dyn LookupObject>,
    }
}

struct LookupSections {
    answers: Box<dyn LookupObject>,
    ns: Box<dyn LookupObject>,
    soa: Box<dyn LookupObject>,
    additionals: Box<dyn LookupObject>,
}

async fn send_response<'a, R: ResponseHandler>(
    _response_edns: Option<Edns>,
    response: MessageResponse<
        '_,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    >,
    mut response_handle: R,
) -> io::Result<ResponseInfo> {
    #[cfg(feature = "dnssec")]
    if let Some(mut resp_edns) = response_edns {
        // set edns DAU and DHU
        // send along the algorithms which are supported by this authority
        let mut algorithms = SupportedAlgorithms::default();
        algorithms.set(Algorithm::RSASHA256);
        algorithms.set(Algorithm::ECDSAP256SHA256);
        algorithms.set(Algorithm::ECDSAP384SHA384);
        algorithms.set(Algorithm::ED25519);

        let dau = EdnsOption::DAU(algorithms);
        let dhu = EdnsOption::DHU(algorithms);

        resp_edns.options_mut().insert(dau);
        resp_edns.options_mut().insert(dhu);

        response.set_edns(resp_edns);
    }

    response_handle.send_response(response).await
}

fn lookup_options_for_edns(edns: Option<&Edns>) -> LookupOptions {
    let _edns = match edns {
        Some(edns) => edns,
        None => return LookupOptions::default(),
    };

    cfg_if! {
        if #[cfg(feature = "dnssec")] {
            let supported_algorithms = if let Some(&EdnsOption::DAU(algs)) = edns.option(EdnsCode::DAU)
            {
               algs
            } else {
               debug!("no DAU in request, used default SupportAlgorithms");
               SupportedAlgorithms::default()
            };

            LookupOptions::for_dnssec(edns.dnssec_ok(), supported_algorithms)
        } else {
            LookupOptions::default()
        }
    }
}

trait ServeFaild {
    fn serve_failed() -> Self;
}

impl ServeFaild for ResponseInfo {
    fn serve_failed() -> Self {
        let mut header = Header::new();
        header.set_response_code(ResponseCode::ServFail);
        header.into()
    }
}
