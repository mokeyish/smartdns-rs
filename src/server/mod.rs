#[cfg(feature = "dns-over-https")]
mod https;
mod net;
#[cfg(feature = "dns-over-quic")]
mod quic;
mod tcp;
#[cfg(feature = "dns-over-tls")]
mod tls;
mod udp;

use crate::libdns::proto::op::{Header, Message, ResponseCode};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
};
use tokio_util::sync::CancellationToken;

use futures_util::FutureExt;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

use crate::{
    app::App,
    config::{IListenerConfig as _, ListenerConfig, ServerOpts},
    dns::{DnsRequest, SerialMessage},
};

pub async fn serve(
    app: &Arc<App>,
    listener_config: &ListenerConfig,
    handle: &DnsHandle,
    idle_time: u64,
    certificate_file: Option<&Path>,
    certificate_key_file: Option<&Path>,
) -> Result<ServerHandle, crate::Error> {
    use crate::rustls::load_certificate_and_key;
    use net::{bind_to, setup_tcp_socket, setup_udp_socket};
    use std::time::Duration;

    let dns_handle = handle.with_new_opt(listener_config.server_opts().clone());

    let token = match listener_config {
        ListenerConfig::Udp(listener) => {
            let udp_socket = bind_to(
                setup_udp_socket,
                listener.sock_addr(),
                listener.device(),
                "UDP",
            );
            udp::serve(udp_socket, dns_handle)
        }
        ListenerConfig::Tcp(listener) => {
            let tcp_listener = bind_to(
                setup_tcp_socket,
                listener.sock_addr(),
                listener.device(),
                "TCP",
            );
            tcp::serve(tcp_listener, dns_handle, Duration::from_secs(idle_time))
        }
        #[cfg(feature = "dns-over-tls")]
        ListenerConfig::Tls(listener) => {
            const LISTENER_TYPE: &str = "DNS over TLS";
            let ssl_config = &listener.ssl_config;

            let (certificate, certificate_key) = load_certificate_and_key(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let tls_listener = bind_to(
                setup_tcp_socket,
                listener.sock_addr(),
                listener.device(),
                LISTENER_TYPE,
            );

            tls::serve(
                tls_listener,
                dns_handle,
                Duration::from_secs(idle_time),
                (certificate.clone(), certificate_key.clone_key()),
            )?
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

            let https_listener = bind_to(
                setup_tcp_socket,
                listener.sock_addr(),
                listener.device(),
                LISTENER_TYPE,
            );

            let app = app.clone();
            https::serve(
                app,
                dns_handle,
                https_listener,
                certificate,
                certificate_key,
            )
            .await?
        }
        #[cfg(feature = "dns-over-quic")]
        ListenerConfig::Quic(listener) => {
            const LISTENER_TYPE: &str = "DNS over QUIC";
            let ssl_config = &listener.ssl_config;

            let (certificate, certificate_key) = load_certificate_and_key(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let quic_listener = bind_to(
                setup_udp_socket,
                listener.sock_addr(),
                listener.device(),
                "QUIC",
            );

            quic::serve(
                quic_listener,
                dns_handle,
                Duration::from_secs(idle_time),
                (certificate, certificate_key),
                ssl_config.server_name.clone(),
            )?
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

    Ok(ServerHandle(token))
}

pub struct ServerHandle(CancellationToken);

impl ServerHandle {
    pub async fn shutdown(self) {
        self.0.cancel()
    }
}

impl From<CancellationToken> for ServerHandle {
    fn from(value: CancellationToken) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone)]
pub struct DnsHandle {
    sender: mpsc::Sender<IncomingDnsMessage>,
    opts: ServerOpts,
}

pub type IncomingDnsMessage = (SerialMessage, ServerOpts, oneshot::Sender<SerialMessage>);

pub type IncomingDnsRequest = mpsc::Receiver<IncomingDnsMessage>;

impl DnsHandle {
    pub fn new(buffer: Option<usize>) -> (IncomingDnsRequest, Self) {
        let (tx, rx) = mpsc::channel(buffer.unwrap_or(10));
        (
            rx,
            Self {
                sender: tx,
                opts: Default::default(),
            },
        )
    }

    pub async fn send(&self, message: SerialMessage) -> SerialMessage {
        let (tx, rx) = oneshot::channel();

        if let Err(err) = self.sender.send((message, self.opts.clone(), tx)).await {
            let message = err.0 .0;
            let addr = message.addr();
            let protocol = message.protocol();
            let request_header = DnsRequest::try_from(message)
                .map(|req| *req.header())
                .unwrap_or_default();
            let mut response_header = Header::response_from_request(&request_header);
            response_header.set_response_code(ResponseCode::Refused);
            let mut response_message = Message::new();
            response_message.set_header(response_header);
            return SerialMessage::raw(response_message, addr, protocol);
        }

        match rx.await {
            Ok(msg) => msg,
            Err(_) => {
                let mut response_header = Header::default();
                response_header.set_response_code(ResponseCode::Refused);
                let mut response_message = Message::new();
                response_message.set_header(response_header);
                response_message.into()
            }
        }
    }

    pub fn with_new_opt(&self, opts: ServerOpts) -> Self {
        Self {
            sender: self.sender.clone(),
            opts,
        }
    }
}

/// Reap finished tasks from a `JoinSet`, without awaiting or blocking.
pub fn reap_tasks(join_set: &mut JoinSet<()>) {
    while FutureExt::now_or_never(join_set.join_next())
        .flatten()
        .is_some()
    {}
}

/// Checks if the IP address is safe for returning messages
///
/// Examples of unsafe addresses are any with a port of `0`
///
/// # Returns
///
/// Error if the address should not be used for returned requests
fn sanitize_src_address(src: SocketAddr) -> Result<(), String> {
    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    if src.port() == 0 {
        return Err(format!("cannot respond to src on port 0: {src}"));
    }

    fn verify_v4(src: Ipv4Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v4 addr: {src}"));
        }

        if src.is_broadcast() {
            return Err(format!("cannot respond to broadcast v4 addr: {src}"));
        }

        // TODO: add check for is_reserved when that stabilizes

        Ok(())
    }

    fn verify_v6(src: Ipv6Addr) -> Result<(), String> {
        if src.is_unspecified() {
            return Err(format!("cannot respond to unspecified v6 addr: {src}"));
        }

        Ok(())
    }

    // currently checks that the src address aren't either the undefined IPv4 or IPv6 address, and not port 0.
    match src.ip() {
        IpAddr::V4(v4) => verify_v4(v4),
        IpAddr::V6(v6) => verify_v6(v6),
    }
}
