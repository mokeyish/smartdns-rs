use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Query;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, FromRequest, Request, State},
};
use serde::{Deserialize, Serialize};

use super::openapi::{
    IntoParams, IntoRouter, ToSchema,
    http::{get, post},
    routes,
};
use super::{ServeState, StatefulRouter};
use crate::{dns::SerialMessage, libdns::Protocol, log};

pub fn routes() -> StatefulRouter {
    routes![serve_dns_get, serve_dns].into_router()
}

#[get("/dns-query", params(QueryParam), responses(
    (status = 200, description = "DNS response", body = DnsResponse)
))]
async fn serve_dns_get(
    State(state): State<Arc<ServeState>>,
    Query(parameters): Query<QueryParam>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
    match process(&state, req, addr, Some(parameters)).await {
        Ok((content_type, bytes)) => {
            let mut res = Body::from(bytes).into_response();
            res.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            res
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(r#"{{ "error": "{0}" }}"#, err),
        )
            .into_response(),
    }
}

#[post("/dns-query")]
async fn serve_dns(
    State(state): State<Arc<ServeState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    match process(&state, req, addr, None).await {
        Ok((content_type, bytes)) => {
            let mut res = Body::from(bytes).into_response();
            res.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            res
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(r#"{{ "error": "{0}" }}"#, err),
        )
            .into_response(),
    }
}

async fn process(
    state: &ServeState,
    req: Request,
    addr: SocketAddr,
    query_param: Option<QueryParam>,
) -> anyhow::Result<(&'static str, Bytes)> {
    const APPLICATION_DNS_MESSAGE: &str = "application/dns-message";
    const APPLICATION_JSON: &str = "application/json";

    let accept = match req.headers().get(header::ACCEPT).map(|s| s.to_str()) {
        Some(Ok(s)) => s,
        _ => "",
    };

    log::debug!(
        "DoH {} {} {}",
        req.method().as_str(),
        req.uri().to_string(),
        accept
    );

    let accept_dns_message = accept == APPLICATION_DNS_MESSAGE;

    let req_msg = match query_param {
        Some(query_param) if !accept_dns_message => {
            // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
            use crate::libdns::proto::{
                op::{Edns, Message, Query},
                rr::{Name, RecordType},
            };

            let name: Name = query_param.name.parse()?;
            let query_type: RecordType = query_param.query_type.parse().unwrap_or(RecordType::A);

            let dnssec = query_param.dnssec;
            let checking_disabled = query_param.checking_disabled;

            let mut message = Message::new();
            message.add_query(Query::query(name, query_type));
            message.set_checking_disabled(checking_disabled);
            if dnssec {
                let mut edns = Edns::new();
                edns.set_dnssec_ok(dnssec);
                message.set_edns(edns);
            }

            SerialMessage::raw(message, addr, Protocol::Https)
        }
        _ => {
            let bytes = Bytes::from_request(req, &state).await?;
            SerialMessage::binary(bytes.into(), addr, Protocol::Https)
        }
    };

    let res_msg = state.dns_handle.send(req_msg).await;

    let (content_type, bytes) = if accept_dns_message {
        (APPLICATION_DNS_MESSAGE, res_msg.try_into()?)
    } else {
        let message = match res_msg {
            SerialMessage::Raw(message, _, _) => message,
            SerialMessage::Bytes(_, _, _) => Err(anyhow::anyhow!("Invliad message type"))?,
        };
        (
            APPLICATION_JSON,
            serde_json::to_vec(&DnsResponse::from(message))?,
        )
    };

    Ok((content_type, bytes.into()))
}

#[derive(Deserialize, IntoParams)]
struct QueryParam {
    /// Query name
    name: String,

    /// Query type (either a numeric value or text ↗).
    #[serde(default = "QueryParam::default_query_type", rename = "type")]
    query_type: String,

    /// DO bit - whether the client wants DNSSEC data (either empty or one of 0, false, 1, or true).
    #[serde(default, rename = "do")]
    dnssec: bool,

    /// CD bit - disable validation (either empty or one of 0, false, 1, or true).
    #[serde(default, rename = "cd")]
    checking_disabled: bool,
}

impl QueryParam {
    fn default_query_type() -> String {
        "A".to_string()
    }
}

#[derive(Serialize, ToSchema)]
#[allow(non_snake_case)]
struct DnsResponse {
    /// The Response Code of the DNS Query
    status: u16,

    /// If true, it means the truncated bit was set.
    /// This happens when the DNS answer is larger
    /// than a single UDP or TCP packet. TC will
    /// almost always be false with Cloudflare
    /// DNS over HTTPS because Cloudflare supports
    /// the maximum response size.
    TC: bool,

    /// If true, it means the Recursive Desired
    /// bit was set. This is always set to true
    /// for Cloudflare DNS over HTTPS.
    RD: bool,

    /// If true, it means the Recursion Available
    /// bit was set. This is always set to true
    /// for Cloudflare DNS over HTTPS.
    RA: bool,

    /// If true, it means that every record
    /// in the answer was verified with DNSSEC.
    AD: bool,

    /// If true, the client asked to disable
    /// DNSSEC validation. In this case,
    /// Cloudflare will still fetch the DNSSEC-related records,
    /// but it will not attempt to validate the records.
    CD: bool,

    Question: Vec<Question>,
    Answer: Vec<Answer>,
}

#[derive(Serialize, ToSchema)]
struct Question {
    name: String,
    r#type: u16,
}

#[derive(Serialize, ToSchema)]
#[allow(non_snake_case)]
struct Answer {
    name: String,
    r#type: u16,
    TTL: u32,
    data: String,
}

impl From<crate::libdns::proto::op::Message> for DnsResponse {
    fn from(message: crate::libdns::proto::op::Message) -> Self {
        DnsResponse {
            status: message.response_code().into(),
            TC: message.truncated(),
            RD: message.recursion_desired(),
            RA: message.recursion_available(),
            AD: message.authoritative(),
            CD: true,
            Question: message
                .queries()
                .iter()
                .map(|q| Question {
                    name: q.name().to_string(),
                    r#type: q.query_type().into(),
                })
                .collect(),
            Answer: message
                .answers()
                .iter()
                .map(|r| Answer {
                    name: r.name().to_string(),
                    r#type: r.record_type().into(),
                    TTL: r.ttl(),
                    data: r.data().to_string(),
                })
                .collect(),
        }
    }
}
