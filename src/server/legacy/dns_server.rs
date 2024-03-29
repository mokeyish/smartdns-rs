use cfg_if::cfg_if;

use std::{io, sync::Arc};

use crate::{
    app::App,
    config::ServerOpts,
    dns::DnsResponse,
    log::{debug, error, info, warn},
};

use crate::libdns::{
    proto::{
        op::{Edns, Header, MessageType, OpCode, ResponseCode},
        rr::Record,
    },
    server::{
        authority::{LookupOptions, MessageResponse, MessageResponseBuilder, ZoneType},
        server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    },
};

use crate::dns::DnsRequest;

pub struct DnsServerHandler {
    app: Arc<App>,
    server_opts: ServerOpts,
}

impl DnsServerHandler {
    pub fn new(app: Arc<App>, server_opts: ServerOpts) -> Self {
        Self { app, server_opts }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsServerHandler {
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
                        "query received: {} {} {} client: {}",
                        request.id(),
                        request.query(),
                        request.query().query_type(),
                        request.src()
                    );

                    let info = async {
                        let request_id = request.id();

                        let request_header = request.header();

                        let (response_header, dns_response) = async {
                            let lookup_options = lookup_options_for_edns(request.edns());

                            // log algorithms being requested
                            if lookup_options.is_dnssec() {
                                info!(
                                    "request: {} lookup_options: {:?}",
                                    request_id, lookup_options
                                );
                            }

                            let mut response_header = Header::response_from_request(request_header);
                            response_header.set_authoritative(ZoneType::Forward.is_authoritative());

                            // debug!("performing {} on {}", query, authority.origin());

                            // let future = self.dns_server.search(request_info, lookup_options);

                            let future = async {
                                let req = &DnsRequest::from(request);

                                let handler = self.app.get_dns_handler().await;

                                handler.search(req, &self.server_opts).await
                            };

                            // send_forwarded_response
                            response_header.set_recursion_available(true);
                            response_header.set_authoritative(false);

                            let dns_response = if !request_header.recursion_desired() {
                                drop(future);
                                info!(
                                    "request disabled recursion, returning no records: {}",
                                    request_header.id()
                                );
                                DnsResponse::empty()
                            } else {
                                match future.await {
                                    Ok(rsp) => rsp,
                                    Err(e) => {
                                        if e.is_nx_domain() {
                                            response_header
                                                .set_response_code(ResponseCode::NXDomain);
                                        }

                                        match e.as_soa() {
                                            Some(soa) => soa,
                                            None => {
                                                debug!("error resolving: {}", e);
                                                DnsResponse::empty()
                                            }
                                        }
                                    }
                                }
                            };

                            (response_header, dns_response)
                        }
                        .await;

                        let response = MessageResponseBuilder::from_message_request(request).build(
                            response_header,
                            dns_response.answers(),
                            dns_response.name_servers(),
                            Box::new(None.into_iter()),
                            dns_response.additionals(),
                        );

                        let result =
                            send_response(response_edns.clone(), response, response_handle.clone())
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

async fn send_response<'a, R: ResponseHandler>(
    #[allow(unused_variables)] response_edns: Option<Edns>,
    #[allow(unused_mut)] mut response: MessageResponse<
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
        use crate::libdns::proto::rr::{
            dnssec::{Algorithm, SupportedAlgorithms},
            rdata::opt::EdnsOption,
        };
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
            use crate::libdns::proto::rr::{
                dnssec::SupportedAlgorithms,
                rdata::opt::{EdnsOption, EdnsCode}
            };
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

impl From<&Request> for crate::dns::DnsRequest {
    fn from(value: &Request) -> Self {
        use crate::libdns::proto::op::MessageParts;
        let message_parts = MessageParts {
            header: value.header().clone(),
            queries: vec![value.query().original().clone()],
            answers: value.answers().into_iter().cloned().collect(),
            name_servers: value.name_servers().into_iter().cloned().collect(),
            additionals: value.additionals().into_iter().cloned().collect(),
            sig0: value.sig0().into_iter().cloned().collect(),
            edns: value.edns().cloned(),
        };
        DnsRequest::new(message_parts.into(), value.src(), value.protocol())
    }
}
