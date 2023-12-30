use std::{io, time::Duration};

use rustls::{Certificate, PrivateKey};
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;

use super::{reap_tasks, sanitize_src_address, DnsHandle};

use crate::{dns::SerialMessage, libdns::Protocol, log};

pub fn serve(
    socket: net::UdpSocket,
    handler: DnsHandle,
    _timeout: Duration,
    certificate_and_key: (Vec<Certificate>, PrivateKey),
    _dns_hostname: Option<String>,
) -> io::Result<CancellationToken> {
    use crate::libdns::proto::quic::{DoqErrorCode, QuicServer};

    log::debug!("registered quic: {:?}", socket);

    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    let mut server = QuicServer::with_socket(socket, certificate_and_key.0, certificate_and_key.1)?;

    tokio::spawn(async move {
        let mut inner_join_set = JoinSet::new();
        loop {
            let (mut quic_streams, src_addr) = tokio::select! {
                result = server.next() => match result {
                    Ok(Some(c)) => c,
                    Ok(None) => continue,
                    Err(e) => {
                        log::debug!("error receiving quic connection: {e}");
                        continue;
                    }
                },
                _ = cancellation_token.cancelled() => {
                    // A graceful shutdown was initiated. Break out of the loop.
                    break;
                },
            };

            // verify that the src address is safe for responses
            // TODO: we're relying the quinn library to actually validate responses before we get here, but this check is still worth doing
            if let Err(e) = sanitize_src_address(src_addr) {
                log::warn!(
                    "address can not be responded to {src_addr}: {e}",
                    src_addr = src_addr,
                    e = e
                );
                continue;
            }

            let handler = handler.clone();
            let cancellation_token = cancellation_token.clone();

            inner_join_set.spawn(async move {
                log::debug!("starting quic stream request from: {src_addr}");

                let mut max_requests = 100u32;

                // Accept all inbound quic streams sent over the connection.
                loop {
                    let mut request_stream = tokio::select! {
                        result = quic_streams.next() => match result {
                            Some(Ok(next_request)) => next_request,
                            Some(Err(err)) => {
                                log::warn!("error accepting request {}: {}", src_addr, err);
                                break;
                            }
                            None => {
                                break;
                            }
                        },
                        _ = cancellation_token.cancelled() => {
                            // A graceful shutdown was initiated.
                            break;
                        },
                    };

                    let bytes = match request_stream.receive_bytes().await {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            log::warn!("error receiving bytes {}", err);
                            break;
                        }
                    };

                    log::debug!("Received bytes {} from {src_addr} {bytes:?}", bytes.len());

                    let req_message = SerialMessage::binary(bytes.into(), src_addr, Protocol::Quic);
                    let res_message = handler.send(req_message).await;

                    if let Err(err) = match res_message.try_into() {
                        Ok(buffer) => request_stream.send_bytes(buffer).await,
                        Err(err) => Err(err),
                    } {
                        log::warn!("quic stream processing failed from {src_addr}: {err}");
                    }

                    max_requests -= 1;

                    if max_requests == 0 {
                        log::warn!("exceeded request count, shutting down quic conn: {src_addr}");
                        // DOQ_NO_ERROR (0x0): No error. This is used when the connection or stream needs to be closed, but there is no error to signal.
                        let _ = request_stream.stop(DoqErrorCode::NoError);
                        break;
                    }

                    // we'll continue handling requests from here.
                }
            });

            reap_tasks(&mut inner_join_set);
        }
    });

    Ok(token)
}
