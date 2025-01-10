use axum::extract::Request;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server,
};
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc};
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tower::{Service as _, ServiceExt};

use tokio_rustls::TlsAcceptor;

use super::{reap_tasks, sanitize_src_address, DnsHandle};

use crate::{
    api::ServeState,
    app::App,
    log,
    rustls::{tls_server_config, Certificate, PrivateKey},
};

pub fn serve(
    app: Arc<App>,
    listener: net::TcpListener,
    dns_handle: DnsHandle,
    certificate_and_key: (Vec<Certificate>, PrivateKey),
) -> io::Result<CancellationToken> {
    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    let tls_config = tls_server_config(b"h2", certificate_and_key.0, certificate_and_key.1)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("error creating TLS acceptor: {e}"),
            )
        })?;

    log::debug!("registered HTTPS: {:?}", listener);

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let state = Arc::new(ServeState { app, dns_handle });

    let make_service = crate::api::routes()
        .with_state(state.clone())
        .into_make_service_with_connect_info::<SocketAddr>();

    tokio::spawn(async move {
        let mut inner_join_set = JoinSet::new();
        loop {
            let (tcp_stream, src_addr) = tokio::select! {
                tcp_stream = listener.accept() => match tcp_stream {
                    Ok((t, s)) => (t, s),
                    Err(e) => {
                        log::debug!("error receiving TLS tcp_stream error: {}", e);
                        continue;
                    },
                },
                _ = cancellation_token.cancelled() => {
                    // A graceful shutdown was initiated. Break out of the loop.
                    break;
                },
            };

            // verify that the src address is safe for responses
            if let Err(e) = sanitize_src_address(src_addr) {
                log::warn!(
                    "address can not be responded to {src_addr}: {e}",
                    src_addr = src_addr,
                    e = e
                );
                continue;
            }

            let tls_acceptor = tls_acceptor.clone();

            // kick out to a different task immediately, let them do the TLS handshake
            let mut make_service = make_service.clone();
            inner_join_set.spawn(async move {
                log::debug!("starting HTTPS request from: {}", src_addr);

                // perform the TLS
                let tls_stream = tls_acceptor.accept(tcp_stream).await;

                let socket = match tls_stream {
                    Ok(tls_stream) => TokioIo::new(tls_stream),
                    Err(e) => {
                        log::debug!("https handshake src: {} error: {}", src_addr, e);
                        return;
                    }
                };

                log::debug!("accepted HTTPS request from: {}", src_addr);

                let tower_service = unwrap_infallible(make_service.call(src_addr).await);

                let hyper_service =
                    hyper::service::service_fn(move |request: Request<Incoming>| {
                        tower_service.clone().oneshot(request)
                    });

                if let Err(err) = server::conn::auto::Builder::new(TokioExecutor::new())
                    .http2()
                    .enable_connect_protocol()
                    .serve_connection_with_upgrades(socket, hyper_service)
                    .await
                {
                    eprintln!("failed to serve connection: {err:#}");
                }
            });

            reap_tasks(&mut inner_join_set);
        }
    });

    Ok(token)
}

fn unwrap_infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => match err {},
    }
}
