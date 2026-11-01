use std::time::Duration;

use futures_util::StreamExt;
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;

use crate::{
    dns::SerialMessage,
    libdns::{
        Protocol,
        proto::runtime::iocompat::AsyncIoTokioAsStd,
        proto::{tcp::TcpStream, xfer::DnsStreamHandle as _},
    },
    log,
    third_ext::FutureTimeoutExt,
};

use super::{DnsHandle, reap_tasks, sanitize_src_address};

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
                let (mut buf_stream, stream_handle) =
                    TcpStream::from_stream(AsyncIoTokioAsStd(tcp_stream), src_addr);

                // Pipelined queries are handled concurrently and answered out of order
                // (RFC 7766 §6.2.1.1), so one slow upstream lookup doesn't stall the
                // whole connection.
                let mut request_set = JoinSet::new();

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
                    let handler = handler.clone();
                    let mut stream_handle = stream_handle.clone();
                    request_set.spawn(async move {
                        let res_message = handler.send(req_message).await;
                        if let Err(err) = res_message
                            .try_into()
                            .map(|buffer| stream_handle.send(buffer))
                        {
                            log::error!("TCP stream processing failed from{:?}", err);
                        }
                    });

                    reap_tasks(&mut request_set);
                }

                // the client stopped sending; finish in-flight queries, then poll the
                // stream once more so their queued answers are written out.
                while request_set.join_next().await.is_some() {}
                let _ = buf_stream.next().timeout(timeout).await;
            });

            reap_tasks(&mut inner_join_set);
        }
    });

    token
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Echo handler: the first byte of each request is how long (in 100ms) to wait
    /// before answering, the second byte identifies the request.
    fn spawn_echo_handler() -> DnsHandle {
        let (mut rx, handle) = DnsHandle::new();
        tokio::spawn(async move {
            while let Some((message, _, tx)) = rx.recv().await {
                tokio::spawn(async move {
                    let SerialMessage::Bytes(bytes, addr, protocol) = message else {
                        unreachable!("tcp server hands over raw bytes");
                    };
                    tokio::time::sleep(Duration::from_millis(100 * bytes[0] as u64)).await;
                    let _ = tx.send(SerialMessage::binary(bytes, addr, protocol));
                });
            }
        });
        handle
    }

    async fn read_frame(stream: &mut net::TcpStream) -> Vec<u8> {
        let len = stream.read_u16().await.unwrap();
        let mut buf = vec![0; len as usize];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    }

    async fn start_server() -> (net::TcpStream, CancellationToken) {
        let listener = net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = serve(listener, spawn_echo_handler(), Duration::from_secs(5));
        (net::TcpStream::connect(addr).await.unwrap(), token)
    }

    #[tokio::test]
    async fn test_pipelined_queries_answered_out_of_order() {
        let (mut stream, token) = start_server().await;

        // slow request (id 1) first, fast request (id 2) right behind it
        stream.write_all(&[0, 2, 5, 1, 0, 2, 0, 2]).await.unwrap();

        let first = read_frame(&mut stream).await;
        let second = read_frame(&mut stream).await;
        assert_eq!(first, vec![0, 2]);
        assert_eq!(second, vec![5, 1]);

        token.cancel();
    }

    #[tokio::test]
    async fn test_in_flight_answers_flushed_after_client_half_close() {
        let (mut stream, token) = start_server().await;

        stream.write_all(&[0, 2, 3, 1, 0, 2, 1, 2]).await.unwrap();
        stream.shutdown().await.unwrap();

        let first = read_frame(&mut stream).await;
        let second = read_frame(&mut stream).await;
        assert_eq!(first, vec![1, 2]);
        assert_eq!(second, vec![3, 1]);

        token.cancel();
    }
}
