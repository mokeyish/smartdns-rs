use super::{reap_tasks, sanitize_src_address, DnsHandle};
use crate::{
    dns::SerialMessage,
    libdns::{
        proto::{error::ProtoError, udp::UdpStream, xfer::DnsStreamHandle},
        Protocol,
    },
    log,
};
use futures_util::StreamExt as _;
use tokio::{net, task::JoinSet};
use tokio_util::sync::CancellationToken;

pub fn serve(socket: net::UdpSocket, handler: DnsHandle) -> CancellationToken {
    let token = CancellationToken::new();
    let cancellation_token = token.clone();

    tokio::spawn(async move {
        // create the new UdpStream, the IP address isn't relevant, and ideally goes essentially no where.
        //   the address used is acquired from the inbound queries
        let (mut stream, stream_handle) =
            UdpStream::with_bound(socket, ([127, 255, 255, 254], 0).into());

        let mut inner_join_set = JoinSet::new();
        loop {
            let message = tokio::select! {
                message = stream.next() => match message {
                    None => break,
                    Some(message) => message,
                },
                _ = cancellation_token.cancelled() => break,
            };

            let message = match message {
                Err(e) => {
                    log::warn!("error receiving message on udp_socket: {}", e);
                    continue;
                }
                Ok(message) => message,
            };

            let src_addr = message.addr();
            log::debug!("received udp request from: {}", src_addr);

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
            let mut stream_handle = stream_handle.with_remote_addr(src_addr);

            inner_join_set.spawn(async move {
                let (bytes, addr) = message.into_parts();
                let req_message = SerialMessage::binary(bytes, addr, Protocol::Udp);
                let res_message = handler.send(req_message).await;
                if let Err(err) = res_message
                    .try_into()
                    .map(|buffer| stream_handle.send(buffer))
                {
                    log::error!("UDP stream processing failed from{:?}", err);
                }
            });

            reap_tasks(&mut inner_join_set);
        }

        if cancellation_token.is_cancelled() {
            Ok(())
        } else {
            // TODO: let's consider capturing all the initial configuration details so that the socket could be recreated...
            Err(ProtoError::from("unexpected close of UDP socket"))
        }
    });
    token
}
