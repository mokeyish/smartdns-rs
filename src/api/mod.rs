use std::{io, sync::Arc};

use axum::{
    body::Bytes,
    extract::{FromRequest, Request, State},
    routing::{any, get},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rustls::{Certificate, PrivateKey};
use tokio::net::TcpListener;

use crate::libdns::{proto::xfer::SerialMessage, server::server::Protocol};

use crate::{config::ServerOpts, dns_server::DnsServerHandler};

pub struct AppState {
    server_opts: ServerOpts,
    dns_handler: DnsServerHandler,
}

pub async fn register_https(
    tcp_listener: TcpListener,
    dns_handler: DnsServerHandler,
    server_opts: ServerOpts,
    certificate: Vec<Certificate>,
    certificate_key: PrivateKey,
    handle: axum_server::Handle,
) -> io::Result<()> {
    let state = Arc::new(AppState {
        server_opts,
        dns_handler,
    });

    let app = Router::new()
        .route("/dns-query", any(serve_dns))
        .nest("/api", Router::new().route("/version", get(version)))
        .with_state(state.clone());

    let certificate = certificate.into_iter().map(|c| c.0).collect::<Vec<_>>();
    let certificate_key = certificate_key.0;

    axum_server::from_tcp_rustls(
        tcp_listener.into_std()?,
        RustlsConfig::from_der(certificate, certificate_key).await?,
    )
    .handle(handle)
    .serve(app.into_make_service())
    .await?;

    Ok(())
}

async fn version() -> Json<&'static str> {
    Json(crate::version())
}

async fn serve_dns(State(state): State<Arc<AppState>>, req: Request) -> Bytes {
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
        println!("读取数据处理");
        Default::default()
    }
    .into()
}
