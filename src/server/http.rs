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

use super::{DnsHandle, reap_tasks, sanitize_src_address};

use crate::{api::ServeState, app::App, log};

pub fn serve(
    app: App,
    listener: net::TcpListener,
    dns_handle: DnsHandle,
) -> io::Result<CancellationToken> {
    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    log::debug!("registered HTTP: {:?}", listener);

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

            // kick out to a different task immediately, let them do the TLS handshake
            let mut make_service = make_service.clone();
            inner_join_set.spawn(async move {
                log::debug!("starting HTTP request from: {}", src_addr);

                let socket = tcp_stream;
                log::debug!("accepted HTTP request from: {}", src_addr);

                let tower_service = unwrap_infallible(make_service.call(src_addr).await);

                let hyper_service =
                    hyper::service::service_fn(move |request: Request<Incoming>| {
                        tower_service.clone().oneshot(request)
                    });

                let socket = TokioIo::new(socket);

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
