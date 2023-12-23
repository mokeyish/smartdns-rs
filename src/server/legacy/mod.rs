use std::{path::Path, sync::Arc, time::Duration};

mod dns_server;

use dns_server::DnsServerHandler;

use super::{
    net::{bind_to, tcp, udp},
    DnsHandle, ServerHandle,
};
use crate::{
    app::App,
    config::{IListenerConfig, ListenerConfig},
    libdns::server::ServerFuture,
    rustls::load_certificate_and_key,
};

pub async fn serve(
    app: &Arc<App>,
    listener_config: &ListenerConfig,
    handle: &DnsHandle,
    idle_time: u64,
    certificate_file: Option<&Path>,
    certificate_key_file: Option<&Path>,
) -> Result<ServerHandle, crate::Error> {
    let cfg = app.cfg().await;
    let handler = DnsServerHandler::new(app.clone(), listener_config.server_opts().clone());

    let server_handle = match listener_config {
        ListenerConfig::Udp(listener) => {
            let udp_socket = bind_to(udp, listener.sock_addr(), listener.device(), "UDP");
            let mut server = ServerFuture::new(handler);
            server.register_socket(udp_socket);
            server.into()
        }
        ListenerConfig::Tcp(listener) => {
            let tcp_listener = bind_to(tcp, listener.sock_addr(), listener.device(), "TCP");
            let mut server = ServerFuture::new(handler);
            server.register_listener(tcp_listener, Duration::from_secs(idle_time));

            server.into()
        }
        #[cfg(feature = "dns-over-tls")]
        ListenerConfig::Tls(listener) => {
            const LISTENER_TYPE: &str = "DNS over TLS";
            let ssl_config = &listener.ssl_config;

            let (certificate, certificate_key) = load_certificate_and_key(
                ssl_config,
                cfg.bind_cert_file(),
                cfg.bind_cert_key_file(),
                LISTENER_TYPE,
            )?;

            let tls_listener = bind_to(tcp, listener.sock_addr(), listener.device(), LISTENER_TYPE);

            let mut server = ServerFuture::new(handler);
            server
                .register_tls_listener(
                    tls_listener,
                    Duration::from_secs(idle_time),
                    (certificate.clone(), certificate_key.clone()),
                )
                .map_err(|err| {
                    crate::Error::RegisterListenerFailed(
                        LISTENER_TYPE,
                        listener.sock_addr(),
                        err.to_string(),
                    )
                })?;

            server.into()
        }
        #[cfg(feature = "dns-over-https")]
        ListenerConfig::Https(listener) => {
            const LISTENER_TYPE: &str = "DNS over HTTPS";
            let ssl_config = &listener.ssl_config;

            let (certificate, certificate_key) = load_certificate_and_key(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let https_listener =
                bind_to(tcp, listener.sock_addr(), listener.device(), LISTENER_TYPE);

            let dns_handle = handle.with_new_opt(listener_config.server_opts().clone());

            let app = app.clone();
            crate::api::serve(
                app,
                dns_handle,
                https_listener,
                certificate,
                certificate_key,
            )
            .await?
            .into()
        }
        #[cfg(feature = "dns-over-quic")]
        ListenerConfig::Quic(listener) => {
            const LISTENER_TYPE: &str = "DNS over QUIC";
            let ssl_config = &listener.ssl_config;

            let (certificate, certificate_key) = load_certificate_and_key(
                ssl_config,
                cfg.bind_cert_file(),
                cfg.bind_cert_key_file(),
                LISTENER_TYPE,
            )?;

            let quic_listener = bind_to(udp, listener.sock_addr(), listener.device(), "QUIC");

            let mut server = ServerFuture::new(handler);
            server
                .register_quic_listener(
                    quic_listener,
                    Duration::from_secs(idle_time),
                    (certificate.clone(), certificate_key.clone()),
                    ssl_config.server_name.clone(),
                )
                .map_err(|err| {
                    crate::Error::RegisterListenerFailed(
                        LISTENER_TYPE,
                        listener.sock_addr(),
                        err.to_string(),
                    )
                })?;

            server.into()
        }
        #[cfg(not(feature = "dns-over-tls"))]
        ListenerConfig::Tls(listener) => {
            warn!("Bind DoT not enabled")
        }
        #[cfg(not(feature = "dns-over-https"))]
        ListenerConfig::Https(listener) => {
            warn!("Bind DoH not enabled")
        }
        #[cfg(not(feature = "dns-over-quic"))]
        ListenerConfig::Quic(listener) => {
            warn!("Bind DoQ not enabled")
        }
    };

    Ok(server_handle)
}

impl From<ServerFuture<DnsServerHandler>> for ServerHandle {
    fn from(mut value: ServerFuture<DnsServerHandler>) -> Self {
        use tokio_util::sync::CancellationToken;
        let token = CancellationToken::new();
        let cancellation_token = token.clone();
        tokio::spawn(async move {
            cancellation_token.cancelled().await;
            let _ = value.shutdown_gracefully().await;
        });
        Self(token)
    }
}
