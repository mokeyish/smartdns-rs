use axum::{Extension, extract::ConnectInfo};
use axum_h3::H3Router;
use h3_util::quinn::H3QuinnAcceptor;

use quinn::{Endpoint, ServerConfig, TokioRuntime, crypto::rustls::QuicServerConfig};
use quinn::{TransportConfig, VarInt};
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::net;
use tokio_util::sync::CancellationToken;

use super::DnsHandle;

use crate::{
    api::ServeState,
    app::App,
    log,
    rustls::{ResolvesServerCert, tls_server_config},
};

pub fn serve(
    app: App,
    socket: net::UdpSocket,
    dns_handle: DnsHandle,
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
) -> io::Result<CancellationToken> {
    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    log::debug!("registered HTTP/3: {:?}", socket);

    let tls_config = tls_server_config(b"h3", server_cert_resolver)
        .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?;

    let server_config = {
        let mut server_config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config).unwrap()));

        server_config.transport_config(Arc::new(transport()));
        server_config
    };

    let config = Default::default();
    let endpoint = Endpoint::new(
        config,
        Some(server_config),
        socket.into_std()?,
        Arc::new(TokioRuntime),
    )?;

    let state = Arc::new(ServeState { app, dns_handle });

    let router = crate::api::routes().with_state(state.clone());
    let router = router.layer(Extension(ConnectInfo(SocketAddr::new(
        Ipv4Addr::UNSPECIFIED.into(),
        0,
    ))));
    let router = H3Router::new(router);

    let acceptor = H3QuinnAcceptor::new(endpoint);

    tokio::spawn(async move {
        if let Err(err) = router
            .serve_with_shutdown(acceptor, cancellation_token.cancelled())
            .await
        {
            eprintln!("failed to serve connection: {err:#}");
        }
    });

    Ok(token)
}

/// Returns a default endpoint configuration for DNS-over-H3
fn transport() -> TransportConfig {
    let mut transport_config = TransportConfig::default();

    transport_config.datagram_receive_buffer_size(None);
    transport_config.datagram_send_buffer_size(0);
    // clients never accept new bidirectional streams
    transport_config.max_concurrent_bidi_streams(VarInt::from_u32(3));
    // - SETTINGS
    // - QPACK encoder
    // - QPACK decoder
    // - RESERVED (GREASE)
    transport_config.max_concurrent_uni_streams(VarInt::from_u32(4));

    transport_config
}
