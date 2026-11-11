use crate::log;
use anyhow::{Result, anyhow};
use dhcproto::v4::{CLIENT_PORT, MIN_PACKET_SIZE, SERVER_PORT};
use dhcproto::{Decodable, Encodable, v4};
use netdev::{Interface as NetworkInterface, MacAddr};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

/// How long to wait for a DHCPOFFER before retrying.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(3);
/// Number of DHCPDISCOVER attempts before giving up.
const DISCOVER_RETRIES: usize = 3;
/// Size of the fixed `chaddr` field in a BOOTP header.
const CHADDR_LEN: usize = 16;

pub fn find_interface_by_name(name: Option<&str>) -> Result<NetworkInterface> {
    match name {
        Some(name) => netdev::get_interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or(anyhow!("Interface {} not found", name)),
        None => netdev::get_default_interface().map_err(|err| anyhow::anyhow!(err)),
    }
}

/// Pad a DHCP message to the minimum BOOTP size.
///
/// RFC 1542 section 2.1 requires the UDP payload to hold at least the minimal
/// 300 octet BOOTP header, and receivers must silently discard shorter
/// messages. `dhcproto::MIN_PACKET_SIZE` exists but its encoder does not pad.
fn pad_packet(mut buf: Vec<u8>) -> Vec<u8> {
    if buf.len() < MIN_PACKET_SIZE {
        buf.resize(MIN_PACKET_SIZE, 0);
    }
    buf
}

/// Bind the socket to the interface the request must leave from.
///
/// Without this, a broadcast follows the main routing table. On a machine with
/// a VPN or a TUN-based proxy that default route points at the tunnel, so the
/// DHCPDISCOVER never reaches the physical link (and the reply never arrives).
fn bind_to_interface(socket: &Socket, if_index: Option<u32>) -> std::io::Result<()> {
    #[cfg(any(
        target_os = "android",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    {
        let Some(index) = if_index else {
            return Ok(());
        };
        let Some(index) = std::num::NonZeroU32::new(index) else {
            log::warn!("interface index is 0, skipping interface binding");
            return Ok(());
        };
        socket.bind_device_by_index_v4(Some(index))?;
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    )))]
    let _ = (socket, if_index);

    Ok(())
}

async fn send_message<M, F>(
    bind_addr: SocketAddr,
    dst_addr: SocketAddr,
    if_index: Option<u32>,
    message: M,
    is_expected: F,
) -> Result<M>
where
    M: Decodable + Encodable,
    F: Fn(&M) -> bool,
{
    let socket = Socket::new(
        Domain::for_address(bind_addr),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;

    socket.set_nonblocking(true)?;

    socket.set_reuse_address(true)?;

    // A missing binding is not fatal: the request can still leave through the
    // routing table if that table points at the right interface.
    if let Err(err) = bind_to_interface(&socket, if_index) {
        log::warn!(
            "could not bind socket to interface index {:?}: {}; continuing without interface binding",
            if_index,
            err
        );
    }

    if let Err(err) = socket.bind(&bind_addr.into()) {
        if bind_addr.port() == 0 {
            return Err(err.into());
        }
        // Falling back to an ephemeral port silently breaks DHCP: servers send
        // OFFER/ACK to port 68 (RFC 2131 section 4.1). Keep the fallback for
        // unprivileged users, but make the failure visible and actionable.
        let hint = match err.kind() {
            std::io::ErrorKind::PermissionDenied => "run as root or grant CAP_NET_BIND_SERVICE",
            std::io::ErrorKind::AddrInUse => "another DHCP client may already use this port",
            _ => "DHCP replies to this port may be lost",
        };
        log::warn!(
            "bind {} failed: {}; falling back to an ephemeral port ({})",
            bind_addr,
            err,
            hint
        );
        let mut fallback = bind_addr;
        fallback.set_port(0);
        socket.bind(&fallback.into())?;
    }

    if matches!(dst_addr.ip(), IpAddr::V4(ip) if ip.is_broadcast()) {
        socket.set_broadcast(true)?;
    }

    let udp_socket = UdpSocket::from_std(std::net::UdpSocket::from(socket))?;

    udp_socket
        .send_to(&pad_packet(message.to_vec()?), dst_addr)
        .await?;

    let mut buf = vec![0; 1500];

    loop {
        let (n, _) = udp_socket.recv_from(&mut buf[..]).await?;
        // Ignore malformed packets and replies that belong to another
        // transaction instead of panicking on them.
        if let Ok(reply) = M::from_bytes(&buf[..n])
            && is_expected(&reply)
        {
            return Ok(reply);
        }
    }
}

fn create_dhcp_v4_discover(mac_addr: MacAddr) -> Result<v4::Message> {
    use v4::{DhcpOption, Message, MessageType, OptionCode};
    let mut msg = Message::default();
    msg.set_chaddr(&mac_addr.octets());

    // RFC 2131 section 4.4.1: a client that cannot receive unicast before it is
    // configured SHOULD set the BROADCAST bit in any DHCPDISCOVER it sends.
    // Clearing it would let a server answer unicast to `yiaddr`, which a socket
    // bound to `0.0.0.0:68` cannot receive.
    msg.set_flags(msg.flags().set_broadcast());

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

    // No explicit `End`: dhcproto appends one, and its option set is a HashMap,
    // so an `End` pushed here would be encoded at an arbitrary position and
    // could terminate the option list before the client identifier gets out.
    msg.set_opts(opts.into_iter().collect());

    Ok(msg)
}

fn is_expected_reply(reply: &v4::Message, xid: u32, chaddr: &[u8]) -> bool {
    // hlen comes off the wire without validation and chaddr() slices
    // `chaddr[..hlen]`, so bound it by the fixed field size and by the address
    // that was sent before touching the address itself.
    let hlen = reply.hlen() as usize;
    reply.opcode() == v4::Opcode::BootReply
        && reply.xid() == xid
        && hlen == chaddr.len()
        && hlen <= CHADDR_LEN
        && reply.chaddr() == chaddr
        && matches!(reply.opts().msg_type(), Some(v4::MessageType::Offer))
}

pub async fn discover_v4(eth_name: Option<&str>) -> Result<v4::Message> {
    let interface = find_interface_by_name(eth_name)?;
    let mac_addr = interface
        .mac_addr
        .ok_or_else(|| anyhow!("No MAC address found for interface"))?;

    // RFC 2131 section 3.1: the client broadcasts DHCPDISCOVER on the local
    // physical subnet. Every attempt uses the limited broadcast address, so a
    // segment that discards client broadcast is not supported.
    let mut last_err = None;

    for attempt in 1..=DISCOVER_RETRIES {
        match send_discover_v4(mac_addr, Some(interface.index)).await {
            Ok(msg) => return Ok(msg),
            Err(err) => {
                log::warn!(
                    "DHCPDISCOVER attempt {}/{} on {} failed: {}",
                    attempt,
                    DISCOVER_RETRIES,
                    interface.name,
                    err
                );
                last_err = Some(err);
                if attempt < DISCOVER_RETRIES {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    let Some(err) = last_err else {
        return Err(anyhow!("no DHCPDISCOVER attempt was made"));
    };

    Err(err.context(format!("interface {}", interface.name)))
}

/// Send one DHCPDISCOVER to the limited broadcast address and wait for a reply.
pub async fn send_discover_v4(mac_addr: MacAddr, if_index: Option<u32>) -> Result<v4::Message> {
    let chaddr = mac_addr.octets();
    let msg = create_dhcp_v4_discover(mac_addr)?;
    let xid = msg.xid();
    let src = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), CLIENT_PORT);
    let dst = SocketAddr::new(Ipv4Addr::BROADCAST.into(), SERVER_PORT);

    let reply = timeout(
        DISCOVER_TIMEOUT,
        send_message(src, dst, if_index, msg, move |reply: &v4::Message| {
            is_expected_reply(reply, xid, &chaddr)
        }),
    )
    .await??;

    Ok(reply)
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
    use super::*;
    use dhcproto::v4::{DhcpOption, MessageType, Opcode, OptionCode};
    use std::str::FromStr;

    fn test_mac() -> MacAddr {
        MacAddr::from_str("00:11:22:33:44:55").unwrap()
    }

    fn offer_reply(mac: MacAddr, xid: u32) -> v4::Message {
        let mut reply = v4::Message::default();
        reply
            .set_opcode(Opcode::BootReply)
            .set_xid(xid)
            .set_chaddr(&mac.octets());
        reply.set_opts(
            vec![DhcpOption::MessageType(MessageType::Offer)]
                .into_iter()
                .collect(),
        );
        reply
    }

    #[test]
    fn test_discover_is_broadcast_and_well_formed() {
        let msg = create_dhcp_v4_discover(test_mac()).unwrap();
        assert_eq!(msg.hlen(), 6);
        assert!(msg.flags().broadcast());
        assert_eq!(msg.opts().msg_type(), Some(MessageType::Discover));
    }

    #[test]
    fn test_discover_options_survive_encoding() {
        let msg = create_dhcp_v4_discover(test_mac()).unwrap();
        let raw = msg.to_vec().unwrap();
        // The fixed header and the magic cookie precede the option list.
        let opts = v4::DhcpOptions::from_bytes(&raw[240..]).unwrap();

        assert_eq!(opts.msg_type(), Some(MessageType::Discover));
        assert!(opts.get(OptionCode::ClientIdentifier).is_some());
        assert!(opts.get(OptionCode::ParameterRequestList).is_some());
    }

    #[test]
    fn test_pad_packet_pads_to_minimum_without_truncating() {
        assert_eq!(pad_packet(vec![0u8; 10]).len(), MIN_PACKET_SIZE);

        let long = vec![0u8; 400];
        assert_eq!(pad_packet(long.clone()), long);
    }

    #[test]
    fn test_expected_reply_checks_xid_chaddr_and_type() {
        let mac = test_mac();
        let reply = offer_reply(mac, 42);

        assert!(is_expected_reply(&reply, 42, &mac.octets()));
        assert!(!is_expected_reply(&reply, 43, &mac.octets()));
    }

    #[test]
    fn test_expected_reply_rejects_wrong_message_type() {
        let mac = test_mac();
        let mut reply = offer_reply(mac, 42);
        reply.set_opts(
            vec![DhcpOption::MessageType(MessageType::Discover)]
                .into_iter()
                .collect(),
        );

        assert!(!is_expected_reply(&reply, 42, &mac.octets()));
    }

    #[test]
    fn test_expected_reply_rejects_non_bootreply() {
        let mac = test_mac();
        let mut reply = offer_reply(mac, 42);
        reply.set_opcode(Opcode::BootRequest);

        assert!(!is_expected_reply(&reply, 42, &mac.octets()));
    }

    #[test]
    fn test_expected_reply_rejects_out_of_range_hlen() {
        let mac = test_mac();
        let mut reply = offer_reply(mac, 42);
        // set_chaddr keeps hlen = 17 while chaddr holds 16 bytes; chaddr()
        // would panic, so the guard must reject the packet first.
        reply.set_chaddr(&[0u8; 17]);

        assert!(!is_expected_reply(&reply, 42, &mac.octets()));
    }

    #[test]
    fn test_expected_reply_rejects_hlen_beyond_chaddr_field() {
        let mut reply = offer_reply(test_mac(), 42);
        reply.set_chaddr(&[0u8; 17]);

        // hlen matches the supplied address length, so only the fixed-field
        // bound rejects it — and it must reject before chaddr() is called.
        assert!(!is_expected_reply(&reply, 42, &[0u8; 17]));
    }

    #[ignore]
    #[tokio::test]
    async fn test_dhcp_get_dns() -> anyhow::Result<()> {
        // Binding port 68 may require root. Set SMARTDNS_TEST_IFACE to pick
        // the interface explicitly (the default-route one may be a tunnel).
        let iface = std::env::var("SMARTDNS_TEST_IFACE").ok();
        let msg = discover_v4(iface.as_deref()).await?;
        assert!(!msg.nameservers().is_empty());
        Ok(())
    }
}
