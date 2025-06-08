#[cfg(feature = "dns-over-h3")]
mod h3;
#[cfg(feature = "dns-over-https")]
mod https;
mod net;
#[cfg(feature = "dns-over-quic")]
mod quic;
mod tcp;
#[cfg(feature = "dns-over-tls")]
mod tls;
mod udp;

use crate::{
    config::SslConfig,
    dns_conf::RuntimeConfig,
    libdns::proto::op::{Header, Message, MessageType, ResponseCode},
};
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
    config::{BindAddrConfig, IBindConfig as _, ServerOpts},
    dns::{DnsRequest, SerialMessage},
};

pub fn serve(
    app: &App,
    cfg: &RuntimeConfig,
    bind_addr_config: &BindAddrConfig,
    handle: &DnsHandle,
    idle_time: u64,
    certificate_file: Option<&Path>,
    certificate_key_file: Option<&Path>,
) -> Result<ServerHandle, crate::Error> {
    use crate::rustls::TlsServerCertResolver;
    use net::{bind_to, setup_tcp_socket, setup_udp_socket};
    use std::time::Duration;

    let dns_handle = handle.with_new_opt(bind_addr_config.server_opts().clone());

    fn create_cert_resolver(
        ssl_config: &SslConfig,
        certificate_file: Option<&Path>,
        certificate_key_file: Option<&Path>,
        typ: &'static str,
    ) -> Result<Arc<TlsServerCertResolver>, crate::Error> {
        let certificate_file = ssl_config
            .certificate
            .as_deref()
            .or(certificate_file)
            .ok_or(crate::Error::CertificatePathNotDefined(typ))?;
        let certificate_key_file = ssl_config
            .certificate_key
            .as_deref()
            .or(certificate_key_file)
            .ok_or(crate::Error::CertificateKeyPathNotDefined(typ))?;
        let resolver = TlsServerCertResolver::new(certificate_file, certificate_key_file)?;
        Ok(Arc::new(resolver))
    }

    let token = match bind_addr_config {
        BindAddrConfig::Udp(bind_addr_config) => {
            let socket = bind_to(
                setup_udp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                "UDP",
            );
            udp::serve(socket, dns_handle)
        }
        BindAddrConfig::Tcp(bind_addr_config) => {
            let listener = bind_to(
                setup_tcp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                "TCP",
            );
            tcp::serve(listener, dns_handle, Duration::from_secs(idle_time))
        }
        #[cfg(feature = "dns-over-tls")]
        BindAddrConfig::Tls(bind_addr_config) => {
            const LISTENER_TYPE: &str = "DNS over TLS";
            let ssl_config = &bind_addr_config.ssl_config;

            let server_cert_resolver = create_cert_resolver(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let listener = bind_to(
                setup_tcp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                LISTENER_TYPE,
            );

            tls::serve(
                listener,
                dns_handle,
                Duration::from_secs(idle_time),
                server_cert_resolver,
            )?
        }
        #[cfg(feature = "dns-over-https")]
        BindAddrConfig::Https(bind_addr_config) => {
            const LISTENER_TYPE: &str = "DNS over HTTPS";
            let ssl_config = &bind_addr_config.ssl_config;

            let server_cert_resolver = create_cert_resolver(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let listener = bind_to(
                setup_tcp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                LISTENER_TYPE,
            );

            let app = app.clone();

            let h3_port = cfg
                .binds()
                .iter()
                .filter(|c| matches!(c, BindAddrConfig::H3(_)))
                .map(|c| c.port())
                .next();
            https::serve(app, listener, dns_handle, server_cert_resolver, h3_port)?
        }
        #[cfg(feature = "dns-over-h3")]
        BindAddrConfig::H3(bind_addr_config) => {
            const LISTENER_TYPE: &str = "DNS over H3";
            let ssl_config = &bind_addr_config.ssl_config;

            let server_cert_resolver = create_cert_resolver(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let listener = bind_to(
                setup_udp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                LISTENER_TYPE,
            );

            let app = app.clone();
            h3::serve(app, listener, dns_handle, server_cert_resolver)?
        }
        #[cfg(feature = "dns-over-quic")]
        BindAddrConfig::Quic(bind_addr_config) => {
            const LISTENER_TYPE: &str = "DNS over QUIC";
            let ssl_config = &bind_addr_config.ssl_config;

            let server_cert_resolver = create_cert_resolver(
                ssl_config,
                certificate_file,
                certificate_key_file,
                LISTENER_TYPE,
            )?;

            let listener = bind_to(
                setup_udp_socket,
                bind_addr_config.sock_addr(),
                bind_addr_config.device(),
                LISTENER_TYPE,
            );

            quic::serve(
                listener,
                dns_handle,
                Duration::from_secs(idle_time),
                server_cert_resolver,
                ssl_config.server_name.clone(),
            )?
        }
        #[cfg(not(feature = "dns-over-tls"))]
        BindAddrConfig::Tls(_) => {
            warn!("Bind DoT not enabled")
        }
        #[cfg(not(feature = "dns-over-https"))]
        BindAddrConfig::Https(_) => {
            warn!("Bind DoH not enabled")
        }
        #[cfg(not(feature = "dns-over-h3"))]
        BindAddrConfig::H3(_) => {
            warn!("Bind DoH3 not enabled")
        }
        #[cfg(not(feature = "dns-over-quic"))]
        BindAddrConfig::Quic(_) => {
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
    sender: mpsc::UnboundedSender<IncomingDnsMessage>,
    opts: ServerOpts,
}

pub type IncomingDnsMessage = (SerialMessage, ServerOpts, oneshot::Sender<SerialMessage>);

pub type IncomingDnsRequest = mpsc::UnboundedReceiver<IncomingDnsMessage>;

impl DnsHandle {
    pub fn new() -> (IncomingDnsRequest, Self) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            rx,
            Self {
                sender: tx,
                opts: Default::default(),
            },
        )
    }

    pub async fn send<T: Into<SerialMessage>>(&self, message: T) -> SerialMessage {
        let message = message.into();
        let (tx, rx) = oneshot::channel();

        if let Err(err) = self.sender.send((message, self.opts.clone(), tx)) {
            let message = err.0.0;
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
                response_header.set_message_type(MessageType::Response);
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
