use std::{io, sync::Arc};

use axum::{routing::get, Json, Router};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

mod address;
mod audit;
mod cache;
mod forward;
mod listener;
mod log;
mod nameserver;
mod serve_dns;
mod settings;

use crate::{app::App, server::DnsHandle};

type StatefulRouter = Router<Arc<ServeState>>;

pub struct ServeState {
    app: Arc<App>,
    dns_handle: DnsHandle,
}

pub async fn serve(
    app: Arc<App>,
    dns_handle: DnsHandle,
    tcp_listener: TcpListener,
    certificate: Vec<Certificate>,
    certificate_key: PrivateKey,
) -> io::Result<CancellationToken> {
    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    let state = Arc::new(ServeState { app, dns_handle });

    let app = Router::new()
        .merge(serve_dns::routes())
        .nest("/api", api_routes())
        .with_state(state.clone());

    let certificate = certificate.into_iter().map(|c| c.0).collect::<Vec<_>>();
    let certificate_key = certificate_key.0;

    let tcp_listener = tcp_listener.into_std()?;
    let rustls_config = RustlsConfig::from_der(certificate, certificate_key).await?;

    tokio::spawn(async move {
        use crate::log;
        let shutdown_handle = Handle::new();

        tokio::select! {
            result = axum_server::from_tcp_rustls(
                tcp_listener,
                rustls_config,
            )
            .handle(shutdown_handle.clone())
            .serve(app.into_make_service()) => match result {
                Ok(()) => (),
                Err(e) => {
                    log::debug!("error receiving quic connection: {e}");
                }
            },
            _ = cancellation_token.cancelled() => {
                // A graceful shutdown was initiated. Break out of the loop.
                shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)))
            },
        };
    });

    Ok(token)
}

fn api_routes() -> StatefulRouter {
    Router::new()
        .route("/version", get(version))
        .merge(cache::routes())
        .merge(nameserver::routes())
        .merge(address::routes())
        .merge(forward::routes())
        .merge(settings::routes())
        .merge(audit::routes())
        .merge(listener::routes())
        .merge(log::routes())
}

async fn version() -> Json<&'static str> {
    Json(crate::version())
}

#[derive(Deserialize, Serialize)]
struct DataListPayload<T> {
    count: usize,
    data: Vec<T>,
}

impl<T> DataListPayload<T> {
    fn new(data: Vec<T>) -> Self {
        Self {
            count: data.len(),
            data,
        }
    }
}

trait IntoDataListPayload<T> {
    fn into_data_list_payload(self) -> DataListPayload<T>;
}

impl<T> IntoDataListPayload<T> for Vec<T> {
    #[inline]
    fn into_data_list_payload(self) -> DataListPayload<T> {
        DataListPayload::new(self)
    }
}
