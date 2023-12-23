use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{FromRequest, Request, State},
    routing::any,
    Router,
};

use super::{ServeState, StatefulRouter};
use crate::{dns::SerialMessage, libdns::Protocol};

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
        let req_msg =
            SerialMessage::binary(bytes.into(), "0.0.0.0:0".parse().unwrap(), Protocol::Https);
        let res_msg = state.dns_handle.send(req_msg).await;
        res_msg.message
    } else {
        Default::default()
    }
    .into()
}
