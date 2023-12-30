use std::time::Duration;

use futures_util::StreamExt;
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    dns::SerialMessage,
    libdns::{
        proto::{iocompat::AsyncIoTokioAsStd, tcp::TcpStream, xfer::DnsStreamHandle as _},
        Protocol,
    },
    log,
    third_ext::FutureTimeoutExt,
};

use super::{reap_tasks, sanitize_src_address, DnsHandle};

pub fn serve(
    listener: net::TcpListener,
    handler: DnsHandle,
    timeout: Duration,
) -> CancellationToken {
    log::debug!("register tcp: {:?}", listener);

    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    tokio::spawn(async move {
        let mut inner_join_set = JoinSet::new();
        loop {
            let (tcp_stream, src_addr) = tokio::select! {
                tcp_stream = listener.accept() => match tcp_stream {
                    Ok((t, s)) => (t, s),
                    Err(e) => {
                        log::debug!("error receiving TCP tcp_stream error: {}", e);
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

            let handler = handler.clone();

            // and spawn to the io_loop
            inner_join_set.spawn(async move {
                log::debug!("accepted request from: {}", src_addr);
                // take the created stream...
                let (mut buf_stream, mut stream_handle) =
                    TcpStream::from_stream(AsyncIoTokioAsStd(tcp_stream), src_addr);

                while let Ok(Some(message)) = buf_stream.next().timeout(timeout).await {
                    let message = match message {
                        Ok(message) => message,
                        Err(e) => {
                            log::debug!(
                                "error in TCP request_stream src: {} error: {}",
                                src_addr,
                                e
                            );
                            // we're going to bail on this connection...
                            return;
                        }
                    };

                    let (bytes, addr) = message.into_parts();
                    let req_message = SerialMessage::binary(bytes, addr, Protocol::Tcp);
                    let res_message = handler.send(req_message).await;
                    if let Err(err) = res_message
                        .try_into()
                        .map(|buffer| stream_handle.send(buffer))
                    {
                        log::error!("TCP stream processing failed from{:?}", err);
                    }
                }
            });

            reap_tasks(&mut inner_join_set);
        }
    });

    token
}
