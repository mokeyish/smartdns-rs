use dhcproto::v4;
use dhcproto::v6;

use anyhow::{Result, anyhow};
use dhcproto::Decodable;
use dhcproto::Encodable;
use network_interface::MacAddr;
use network_interface::NetworkInterface;
use network_interface::NetworkInterfaceConfig;
use rand::RngCore;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub enum Message {
    V4(v4::Message),
    V6(v6::Message),
}

impl Message {
    fn set_xid(&mut self, xid: u32) {
        match self {
            Message::V4(message) => {
                message.set_xid(xid);
            }
            Message::V6(message) => {
                message.set_xid_num(xid);
            }
        }
    }
    #[allow(clippy::wrong_self_convention)]
    fn from_bytes(&self, bytes: &[u8]) -> Result<Self> {
        let msg = match self {
            Message::V4(_) => v4::Message::from_bytes(bytes)?.into(),
            Message::V6(_) => v6::Message::from_bytes(bytes)?.into(),
        };
        Ok(msg)
    }
}

impl From<v4::Message> for Message {
    fn from(value: v4::Message) -> Self {
        Self::V4(value)
    }
}

impl From<v6::Message> for Message {
    fn from(value: v6::Message) -> Self {
        Self::V6(value)
    }
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::V4(message) => write!(f, "{message}"),
            Message::V6(message) => write!(f, "{message}"),
        }
    }
}

impl Encodable for Message {
    fn encode(&self, e: &mut v6::Encoder<'_>) -> v6::EncodeResult<()> {
        match self {
            Message::V4(message) => message.encode(e),
            Message::V6(message) => message.encode(e),
        }
    }
}

async fn send_dhcp(bind_addr: Option<IpAddr>, mut message: Message) -> Result<Message> {
    let (mut bind_addr, server_addr) = match &message {
        Message::V4(_) => (
            SocketAddr::new(bind_addr.unwrap_or(Ipv4Addr::UNSPECIFIED.into()), 0),
            SocketAddr::new(Ipv4Addr::BROADCAST.into(), 6767),
        ),
        Message::V6(_) => (
            SocketAddr::new(bind_addr.unwrap_or(Ipv6Addr::UNSPECIFIED.into()), 546),
            SocketAddr::new(IpAddr::V6("FF02::1".parse().unwrap()), 547),
        ),
    };

    let xid: u32 = rand::rng().next_u32();

    message.set_xid(xid);

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(sock) => sock,
        Err(err) => {
            bind_addr.set_port(0);
            match UdpSocket::bind(bind_addr).await {
                Ok(sock) => sock,
                Err(_) => Err(err)?,
            }
        }
    };

    socket.set_broadcast(true)?;
    socket.send_to(&message.to_vec()?, server_addr).await?;
    let mut buf = vec![0; 1024];

    let (n, _) = socket.recv_from(&mut buf[..]).await?;

    let res = message.from_bytes(&buf[..n]).unwrap();

    Ok(res)
}

fn discover_v4_message(mac_addr: MacAddr) -> Result<Message> {
    use v4::{DhcpOption, Message, MessageType, OptionCode};
    let mut msg = Message::default();
    msg.set_chaddr(&mac_addr.octets());

    msg.set_opts(
        vec![
            DhcpOption::MessageType(MessageType::Discover),
            DhcpOption::ParameterRequestList(vec![
                OptionCode::SubnetMask,
                OptionCode::BroadcastAddr,
                OptionCode::TimeOffset,
                OptionCode::Router,
                OptionCode::DomainName,
                OptionCode::DomainNameServer,
                OptionCode::Hostname,
            ]),
            DhcpOption::End,
        ]
        .into_iter()
        .collect(),
    );

    Ok(msg.into())
}

fn discover_v6_message(_mac_addr: MacAddr) -> Result<Message> {
    use v6::{Message, MessageType};
    let mut msg = Message::default();
    msg.set_msg_type(MessageType::Solicit);
    Ok(msg.into())
}

fn find_default_interface() -> Result<NetworkInterface> {
    NetworkInterface::show()?
        .into_iter()
        .find(|i| !i.addr.iter().any(|ip| ip.ip().is_loopback()) && !i.addr.is_empty())
        .ok_or(anyhow!("No available network interface found"))
}

fn find_interface_by_name(name: &str) -> Result<NetworkInterface> {
    NetworkInterface::show()?
        .into_iter()
        .find(|iface| iface.name == name)
        .ok_or(anyhow!("Interface {} not found", name))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn test_dhcp_discover_v4() -> anyhow::Result<()> {
        let interface = find_default_interface()?;
        println!("Using network interface: {}", interface.name);

        let req = discover_v4_message(interface.mac_addr.unwrap())?;

        let bind_addr = interface
            .addr
            .iter()
            .filter(|addr| addr.ip().is_ipv4())
            .map(|addr| addr.ip())
            .next()
            .unwrap();
        println!("Binding to {bind_addr}");

        let res = timeout(Duration::from_secs(5), send_dhcp(Some(bind_addr), req)).await??;

        println!("{res}");

        Ok(())
    }
}
