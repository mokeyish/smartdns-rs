use std::net::SocketAddr;
use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Bytes,
    extract::{self, ConnectInfo, FromRequest, Request, State},
    routing::any,
    Router,
};
use serde::Serialize;

use super::{ServeState, StatefulRouter};
use crate::{dns::SerialMessage, libdns::Protocol};

pub fn routes() -> StatefulRouter {
    Router::new().route("/dns-query", any(serve_dns))
}

async fn serve_dns(
    State(state): State<Arc<ServeState>>,
    extract::Query(query_parameters): extract::Query<HashMap<String, String>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Result<Bytes, super::ApiError> {
    if matches!(req.headers().get("accept").map(|s| s.to_str()), Some(Ok(t)) if t.contains("json"))
        || !query_parameters.is_empty()
    {
        // https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
        use crate::libdns::proto::{
            op::{Edns, Message, Query},
            rr::{Name, RecordType},
        };

        let name: Name = query_parameters
            .get("name")
            .ok_or_else(|| anyhow::anyhow!("Query name is required"))?
            .parse()?;
        let query_type: RecordType = query_parameters
            .get("type")
            .ok_or_else(|| anyhow::anyhow!("Query type is required"))?
            .parse()?;
        let dnssec = matches!(query_parameters.get("do"), Some(s) if s == "true" || s == "1");
        let checking_disabled =
            matches!(query_parameters.get("cd"), Some(s) if s == "true" || s == "1");

        let mut message = Message::new();
        message.add_query(Query::query(name, query_type));
        message.set_checking_disabled(checking_disabled);
        if dnssec {
            let mut edns = Edns::new();
            edns.set_dnssec_ok(dnssec);
            message.set_edns(edns);
        }

        let req_msg = SerialMessage::raw(message, addr, Protocol::Https);
        let res_msg = state.dns_handle.send(req_msg).await;
        let message = match res_msg {
            SerialMessage::Raw(message, _, _) => message,
            SerialMessage::Bytes(_, _, _) => Err(anyhow::anyhow!("Invliad message type"))?,
        };

        let res = ResponseMessage {
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
                    data: r.data().map(|r| r.to_string()).unwrap_or_default(),
                })
                .collect(),
        };

        Ok(serde_json::to_vec(&res)?.into())
    } else {
        Ok(if let Ok(bytes) = Bytes::from_request(req, &state).await {
            let req_msg = SerialMessage::binary(bytes.into(), addr, Protocol::Https);
            let res_msg = state.dns_handle.send(req_msg).await;
            res_msg.into()
        } else {
            Vec::default()
        }
        .into())
    }
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct ResponseMessage {
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
