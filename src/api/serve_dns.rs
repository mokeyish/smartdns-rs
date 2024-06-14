use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};

use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{
    body::Bytes,
    extract::{self, ConnectInfo, FromRequest, Request, State},
    routing::any,
    Router,
};
use serde::Serialize;

use super::{ServeState, StatefulRouter};
use crate::{dns::SerialMessage, libdns::Protocol, log};

pub fn routes() -> StatefulRouter {
    Router::new().route("/dns-query", any(serve_dns))
}

async fn serve_dns(
    State(state): State<Arc<ServeState>>,
    extract::Query(parameters): extract::Query<HashMap<String, String>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    match process(&state, req, addr, parameters).await {
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
    parameters: HashMap<String, String>,
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

    let req_msg = if !accept_dns_message && parameters.contains_key("name")
        || parameters.contains_key("query")
    {
        // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
        use crate::libdns::proto::{
            op::{Edns, Message, Query},
            rr::{Name, RecordType},
        };

        let name: Name = parameters
            .get("name")
            .or_else(|| parameters.get("query"))
            .ok_or_else(|| anyhow::anyhow!("Query name is required"))?
            .parse()?;

        let query_type = match parameters.get("type") {
            Some(s) => s.parse::<u16>().map(RecordType::from).or(s.parse())?,
            None => RecordType::A,
        };

        let dnssec = matches!(parameters.get("do"), Some(s) if s == "true" || s == "1");
        let checking_disabled = matches!(parameters.get("cd"), Some(s) if s == "true" || s == "1");

        let mut message = Message::new();
        message.add_query(Query::query(name, query_type));
        message.set_checking_disabled(checking_disabled);
        if dnssec {
            let mut edns = Edns::new();
            edns.set_dnssec_ok(dnssec);
            message.set_edns(edns);
        }

        SerialMessage::raw(message, addr, Protocol::Https)
    } else {
        let bytes = Bytes::from_request(req, &state).await?;
        SerialMessage::binary(bytes.into(), addr, Protocol::Https)
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
            serde_json::to_vec(&JsonMessage::from(message))?,
        )
    };

    Ok((content_type, bytes.into()))
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct JsonMessage {
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

#[derive(Serialize)]
struct Question {
    name: String,
    r#type: u16,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct Answer {
    name: String,
    r#type: u16,
    TTL: u32,
    data: String,
}

impl From<crate::libdns::proto::op::Message> for JsonMessage {
    fn from(message: crate::libdns::proto::op::Message) -> Self {
        JsonMessage {
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
