use crate::log;
use anyhow::{Result, anyhow};
use cfg_if::cfg_if;
use dhcproto::{Decodable, Encodable, v4};
use netdev::{Interface as NetworkInterface, MacAddr};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

const TIMEOUT: Duration = Duration::from_secs(3);

pub fn find_interface_by_name(name: Option<&str>) -> Result<NetworkInterface> {
    match name {
        Some(name) => netdev::get_interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or(anyhow!("Interface {} not found", name)),
        None => netdev::get_default_interface().map_err(|err| anyhow::anyhow!(err)),
    }
}

async fn send_message<M: Decodable + Encodable>(
    mut bind_addr: SocketAddr,
    dst_addr: SocketAddr,
    message: M,
) -> Result<M> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;

    socket.set_nonblocking(true)?;

    socket.set_reuse_address(true)?;

    if socket.bind(&bind_addr.into()).is_err() {
        bind_addr.set_port(0);
        socket.bind(&bind_addr.into())?;
    }

    let udp_socket = std::net::UdpSocket::from(socket);

    let udp_socket = UdpSocket::from_std(udp_socket)?;

    if matches!(dst_addr.ip(), IpAddr::V4(ip) if ip.is_broadcast()) {
        udp_socket.set_broadcast(true)?;
    }

    udp_socket.send_to(&message.to_vec()?, dst_addr).await?;

    let mut buf = vec![0; 1024];

    let (n, _) = udp_socket.recv_from(&mut buf[..]).await?;

    let res = M::from_bytes(&buf[..n]).unwrap();

    Ok(res)
}

fn create_dhcp_v4_discover(mac_addr: MacAddr, broadcast: bool) -> Result<v4::Message> {
    use v4::{DhcpOption, Message, MessageType, OptionCode};
    let mut msg = Message::default();
    msg.set_chaddr(&mac_addr.octets());

    if broadcast {
        msg.set_flags(msg.flags().set_broadcast());
    }

    let mut opts = vec![DhcpOption::MessageType(MessageType::Discover)];

    if let Ok(Ok(host)) = hostname::get().map(|s| s.into_string()) {
        opts.push(DhcpOption::Hostname(host));
    }

    let mut client_identifier = vec![msg.htype().into()];

    client_identifier.extend(mac_addr.octets());

    opts.push(DhcpOption::ClientIdentifier(client_identifier));

    opts.push(DhcpOption::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::DomainName,
        OptionCode::PerformRouterDiscovery,
        OptionCode::StaticRoutingTable,
        OptionCode::NetBiosNameServers,
        OptionCode::NetBiosNodeType,
        OptionCode::NetBiosScope,
        OptionCode::DomainSearch,
        OptionCode::ClasslessStaticRoute,
        OptionCode::BroadcastAddr,
        OptionCode::TimeOffset,
        OptionCode::Hostname,
    ]));

    opts.push(DhcpOption::End);

    msg.set_opts(opts.into_iter().collect());

    Ok(msg)
}

pub async fn discover_v4(eth_name: Option<&str>) -> Result<v4::Message> {
    let interface = find_interface_by_name(eth_name)?;
    let mac_addr = interface
        .mac_addr
        .ok_or_else(|| anyhow!("No MAC address found for interface"))?;

    let gateway = interface
        .gateway
        .iter()
        .flat_map(|x| x.ipv4.iter())
        .next()
        .cloned()
        .unwrap_or(Ipv4Addr::BROADCAST);

    let mut retry_count = 3;
    while retry_count > 0 {
        match send_discover_v4(mac_addr, gateway).await {
            Ok(msg) => return Ok(msg),
            Err(e) => {
                log::error!("Failed to discover DHCPv4 server: {}", e);
                retry_count -= 1;
                if retry_count == 0 {
                    return Err(e);
                }
                sleep(Duration::from_secs(1)).await; // Wait for a second before retrying
            }
        }
    }
    Err(anyhow!("Failed to discover DHCPv4 server after retries"))
}

cfg_if! {
    if #[cfg(target_os = "macos")] {
        pub async fn send_discover_v4(mac_addr: MacAddr, dst: Ipv4Addr) -> Result<v4::Message> {
            let msg = create_dhcp_v4_discover(mac_addr, false).unwrap();
            let src = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 68);
            let dst = SocketAddr::new(dst.into(), 67);
            let res = timeout(
                TIMEOUT,
                send_message(src,dst,msg),
            )
            .await??;
            Ok(res)
        }
    } else {
        pub async fn send_discover_v4(mac_addr: MacAddr, dst: Ipv4Addr) -> Result<v4::Message> {
            let msg = create_dhcp_v4_discover(mac_addr, false).unwrap();
            let src = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 68);
            let dst = SocketAddr::new(dst.into(), 67);
            let res = timeout(
                TIMEOUT,
                send_message(src,dst,msg),
            )
            .await??;
            Ok(res)
        }
    }
}

pub trait DhcpMessageExt {
    fn nameservers(&self) -> Vec<IpAddr>;
}

impl DhcpMessageExt for v4::Message {
    fn nameservers(&self) -> Vec<IpAddr> {
        use v4::{DhcpOption, OptionCode};
        if let Some(DhcpOption::DomainNameServer(ns)) =
            self.opts().get(OptionCode::DomainNameServer)
        {
            return ns.iter().map(|&ip| ip.into()).collect();
        }
        if let Some(DhcpOption::NameServer(ns)) = self.opts().get(OptionCode::NameServer) {
            return ns.iter().map(|&ip| ip.into()).collect();
        }
        vec![]
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[tokio::test]
    async fn test_dhcp_get_dns() -> anyhow::Result<()> {
        let ci = std::env::var("GITHUB_ACTIONS").is_ok();
        if ci {
            #[cfg(not(windows))]
            {
                let msg = discover_v4(None).await?;
                assert!(!msg.nameservers().is_empty());
            }
        }
        Ok(())
    }
}
