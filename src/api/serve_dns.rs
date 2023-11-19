use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{FromRequest, Request, State},
    routing::any,
    Router,
};

use super::{ServeState, StatefulRouter};
use crate::libdns::{proto::xfer::SerialMessage, server::server::Protocol};

pub fn routes() -> StatefulRouter {
    Router::new().route("/dns-query", any(serve_dns))
}

async fn serve_dns(State(state): State<Arc<ServeState>>, req: Request) -> Bytes {
    let s = req
        .headers()
        .iter()
        .map(|(n, v)| format!("{}: {:?}", n, v))
        .collect::<Vec<_>>();

    println!("{}", s.join("\n"));

    if let Ok(bytes) = Bytes::from_request(req, &state).await {
        state
            .dns_handler
            .handle(
                SerialMessage::new(bytes.into(), "0.0.0.0:0".parse().unwrap()),
                Protocol::Https,
            )
            .await
            .into_parts()
            .0
    } else {
        Default::default()
    }
    .into()
}
