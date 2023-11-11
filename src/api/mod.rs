use std::{io, sync::Arc};

use axum::{routing::get, Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use rustls::{Certificate, PrivateKey};
use tokio::net::TcpListener;

mod cache;
mod serve_dns;

use crate::{app::App, dns_server::DnsServerHandler};

type StatefulRouter = Router<Arc<ServeState>>;

pub struct ServeState {
    app: Arc<App>,
    dns_handler: DnsServerHandler,
}

pub async fn register_https(
    app: Arc<App>,
    dns_handler: DnsServerHandler,
    tcp_listener: TcpListener,
    certificate: Vec<Certificate>,
    certificate_key: PrivateKey,
    handle: axum_server::Handle,
) -> io::Result<()> {
    let state = Arc::new(ServeState { app, dns_handler });

    let app = Router::new()
        .merge(serve_dns::routes())
        .nest("/api", api_routes())
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

fn api_routes() -> StatefulRouter {
    Router::new()
        .route("/version", get(version))
        .merge(cache::routes())
}

async fn version() -> Json<&'static str> {
    Json(crate::version())
}
