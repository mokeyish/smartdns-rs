use crate::log;
use std::{
    io,
    net::{IpAddr, SocketAddr},
};
use tokio::net::{TcpListener, UdpSocket};

pub fn bind_to<T>(
    func: impl Fn(SocketAddr, Option<&str>, &str) -> io::Result<T>,
    sock_addr: SocketAddr,
    bind_device: Option<&str>,
    bind_type: &str,
) -> T {
    func(sock_addr, bind_device, bind_type).unwrap_or_else(|err| {
        panic!("cound not bind to {bind_type}: {sock_addr}, {err}");
    })
}

pub fn setup_tcp_socket(
    sock_addr: SocketAddr,
    bind_device: Option<&str>,
    bind_type: &str,
) -> io::Result<TcpListener> {
    let device_note = bind_device
        .map(|device| format!("@{device}"))
        .unwrap_or_default();

    log::debug!("binding {} to {:?}{}", bind_type, sock_addr, device_note);
    let tcp_listener = std::net::TcpListener::bind(sock_addr)?;

    setup_socket(&tcp_listener, bind_device, sock_addr.ip())?;

    let tcp_listener = TcpListener::from_std(tcp_listener)?;

    log::info!(
        "listening for {} on {:?}{}",
        bind_type,
        tcp_listener
            .local_addr()
            .expect("could not lookup local address"),
        device_note
    );

    Ok(tcp_listener)
}

pub fn setup_udp_socket(
    sock_addr: SocketAddr,
    bind_device: Option<&str>,
    bind_type: &str,
) -> io::Result<UdpSocket> {
    let device_note = bind_device
        .map(|device| format!("@{device}"))
        .unwrap_or_default();

    log::debug!("binding {} to {:?}{}", bind_type, sock_addr, device_note);
    let udp_socket = std::net::UdpSocket::bind(sock_addr)?;

    setup_socket(&udp_socket, bind_device, sock_addr.ip())?;

    // set UDP_CONNRESET off to ignore UdpSocket's WSAECONNRESET error
    #[cfg(all(target_os = "windows", target_env = "msvc"))]
    {
        // https://github.com/mokeyish/smartdns-rs/issues/391
        // https://github.com/shadowsocks/shadowsocks-rust/blob/3b47fa67fac6c2bded73616a284f26c6159cbe9a/src/relay/sys/windows/mod.rs#L17
        use std::ffi::c_void;
        use std::{mem, os::windows::io::AsRawSocket, ptr};
        use windows::Win32::Foundation::FALSE;
        use windows::Win32::Networking::WinSock::{
            SIO_UDP_CONNRESET, SOCKET, SOCKET_ERROR, WSAGetLastError, WSAIoctl,
        };

        let handle = SOCKET(udp_socket.as_raw_socket() as usize);
        let mut bytes_returned: u32 = 0;
        let enable = FALSE;
        unsafe {
            let ret = WSAIoctl(
                handle,
                SIO_UDP_CONNRESET,
                Some(&enable as *const _ as *const c_void),
                mem::size_of_val(&enable) as u32,
                Some(ptr::null_mut()),
                0,
                &mut bytes_returned,
                Some(ptr::null_mut()),
                None,
            );

            if ret == SOCKET_ERROR {
                // ignore the error here, just warn and continue
                let err_code = WSAGetLastError();
                log::warn!("WSAIoctl failed with error code {:?}", err_code);
                // return Err(td::io::Error::from_raw_os_error(err_code.0));
            }
        };
    }

    let udp_socket = UdpSocket::from_std(udp_socket)?;

    log::info!(
        "listening for {} on {:?}{}",
        bind_type,
        udp_socket
            .local_addr()
            .expect("could not lookup local address"),
        device_note
    );
    Ok(udp_socket)
}

#[allow(unused_variables)]
fn setup_socket<'a, T: Into<socket2::SockRef<'a>>>(
    socket: T,
    bind_device: Option<&str>,
    bind_addr: IpAddr,
) -> io::Result<()> {
    use socket2::Type;
    let sock_ref: socket2::SockRef<'a> = socket.into();
    sock_ref.set_nonblocking(true)?;
    let sock_typ = sock_ref.r#type()?;
    if bind_addr.is_ipv6()
        && (bind_addr.is_unspecified() || bind_addr.is_loopback())
        && sock_ref.only_v6()?
    {
        sock_ref.set_only_v6(false)?;
    }

    // https://github.com/pymumu/smartdns/blob/e26ecf6a52851f88e2937448019f74b753c0e6dc/src/dns_server/server_socket.c#L111
    if sock_typ == Type::STREAM {
        sock_ref.set_reuse_address(true)?;

        // enable TCP_FASTOPEN
        sock_ref.set_nodelay(true)?;
    }

    #[cfg(target_os = "macos")]
    sock_ref.set_reuse_port(true)?;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(device) = bind_device {
        sock_ref.bind_device(Some(device.as_bytes()))?;
    }

    Ok(())
}
