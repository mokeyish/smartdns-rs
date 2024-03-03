use async_socks5::SocksDatagram as Socks5Datagram;
use std::{
    fmt::{Display, Write},
    io,
    net::{AddrParseError, SocketAddr},
    ops::Deref,
    str::FromStr,
};
pub use tokio::net::TcpStream;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket as TokioUdpSocket;

use thiserror::Error;
use url::{ParseError, Url};

pub async fn connect_tcp(
    server_addr: SocketAddr,
    proxy: Option<&ProxyConfig>,
) -> io::Result<TcpStream> {
    let target_addr = server_addr.ip().to_string();
    let target_port = server_addr.port();

    match proxy {
        Some(proxy) => match proxy.proto {
            ProxyProtocol::Socks5 => {
                use async_socks5::Auth;
                let mut stream = TokioTcpStream::connect(proxy.server).await?;

                let auth = if proxy.username.is_some() {
                    let username = proxy.username.as_deref().unwrap_or_default();
                    let password = proxy.password.as_deref().unwrap_or_default();

                    Some(Auth {
                        username: username.to_string(),
                        password: password.to_string(),
                    })
                } else {
                    None
                };

                let _ = async_socks5::connect(&mut stream, server_addr, auth)
                    .await
                    .map_err(from_socks5_err)?;

                Ok(stream)
            }
            ProxyProtocol::Http => {
                use async_http_proxy::{http_connect_tokio, http_connect_tokio_with_basic_auth};

                let mut stream = TokioTcpStream::connect(proxy.server).await?;

                if let Some(user) = proxy.username.as_deref() {
                    http_connect_tokio_with_basic_auth(
                        &mut stream,
                        &target_addr,
                        target_port,
                        user,
                        proxy.password.as_deref().unwrap_or_default(),
                    )
                    .await
                } else {
                    http_connect_tokio(&mut stream, &target_addr, target_port).await
                }
                .map_err(from_http_err)?;

                Ok(stream)
            }
        },
        None => TokioTcpStream::connect(server_addr).await,
    }
}

pub async fn connect_udp(
    _server_addr: SocketAddr,
    local_addr: SocketAddr,
    proxy: Option<&ProxyConfig>,
) -> io::Result<UdpSocket> {
    match proxy {
        Some(proxy) => match proxy.proto {
            ProxyProtocol::Socks5 => {
                use async_socks5::{AddrKind, Auth};
                let stream = TokioTcpStream::connect(proxy.server).await?;

                let auth = if proxy.username.is_some() {
                    let username = proxy.username.as_deref().unwrap_or_default();
                    let password = proxy.password.as_deref().unwrap_or_default();

                    Some(Auth {
                        username: username.to_string(),
                        password: password.to_string(),
                    })
                } else {
                    None
                };

                let socket = TokioUdpSocket::bind(local_addr).await?;
                let socket = Socks5Datagram::associate(stream, socket, auth, None::<AddrKind>)
                    .await
                    .map_err(from_socks5_err)?;

                Ok(UdpSocket::Proxy(socket))
            }
            ProxyProtocol::Http => {
                unimplemented!()
            }
        },
        None => TokioUdpSocket::bind(local_addr).await.map(UdpSocket::Tokio),
    }
}

fn from_socks5_err(err: async_socks5::Error) -> io::Error {
    match err {
        async_socks5::Error::Io(io) => io,
        err => io::Error::new(io::ErrorKind::ConnectionRefused, err),
    }
}

fn from_http_err(err: async_http_proxy::HttpError) -> io::Error {
    match err {
        async_http_proxy::HttpError::IoError(io) => io,
        err => io::Error::new(io::ErrorKind::ConnectionRefused, err),
    }
}

pub enum UdpSocket {
    Tokio(TokioUdpSocket),
    Proxy(Socks5Datagram<TokioTcpStream>),
}

impl Deref for UdpSocket {
    type Target = TokioUdpSocket;

    fn deref(&self) -> &Self::Target {
        match self {
            UdpSocket::Tokio(s) => s,
            UdpSocket::Proxy(s) => s.get_ref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub proto: ProxyProtocol,
    pub server: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.proto {
            ProxyProtocol::Socks5 => "socks5://",
            ProxyProtocol::Http => "http://",
        })?;

        if let Some(user) = self.username.as_deref() {
            f.write_str(user)?;

            if let Some(pwd) = self.password.as_deref() {
                f.write_char(':')?;
                f.write_str(pwd)?;
            }
            f.write_char('@')?;
        }

        write!(f, "{}", self.server)?;

        Ok(())
    }
}

impl FromStr for ProxyConfig {
    type Err = ProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = Url::from_str(s)?;

        let proto = match url.scheme() {
            "socks5" => ProxyProtocol::Socks5,
            "http" => ProxyProtocol::Http,
            scheme => return Err(ProxyParseError::UnexpectedSchema(scheme.to_string())),
        };

        let server = match url
            .socket_addrs(|| match proto {
                ProxyProtocol::Socks5 => Some(1080),
                _ => None,
            })
            .into_iter()
            .flatten()
            .next()
        {
            Some(s) => s,
            None => return Err(ParseError::InvalidDomainCharacter.into()),
        };

        let mut username = Some(url.username());
        if matches!(username, Some("")) {
            username = None;
        }

        let password = url.password();

        Ok(Self {
            proto,
            server,
            username: username.map(|s| s.to_owned()),
            password: password.map(|s| s.to_owned()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Socks5,
    Http,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProxyParseError {
    #[error("UnexpectedSchema {0:?}")]
    UnexpectedSchema(String),
    #[error(" address parse error {0:?}")]
    Addr(#[from] AddrParseError),
    #[error("{0:?}")]
    Parse(#[from] ParseError),
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;

    #[test]
    fn test_parse_socks5() {
        assert_eq!(
            ProxyConfig::from_str("socks5://1.2.3.4:1080"),
            Ok(ProxyConfig {
                proto: ProxyProtocol::Socks5,
                server: "1.2.3.4:1080".parse().unwrap(),
                username: None,
                password: None
            })
        );
    }

    #[test]
    fn test_parse_socks5_with_user() {
        assert_eq!(
            ProxyConfig::from_str("socks5://user123@1.2.3.4:1080"),
            Ok(ProxyConfig {
                proto: ProxyProtocol::Socks5,
                server: "1.2.3.4:1080".parse().unwrap(),
                username: Some("user123".to_string()),
                password: None
            })
        );

        let url = Url::from_str("abc://user123@1.2.3.4:1080").unwrap();

        assert_eq!(url.username(), "user123");
        assert_eq!(url.password(), None);
    }

    #[test]
    fn test_parse_socks5_with_user_pass() {
        assert_eq!(
            ProxyConfig::from_str("socks5://user123:pass456@1.2.3.4:1080"),
            Ok(ProxyConfig {
                proto: ProxyProtocol::Socks5,
                server: "1.2.3.4:1080".parse().unwrap(),
                username: Some("user123".to_string()),
                password: Some("pass456".to_string())
            })
        );
    }

    #[test]
    fn test_parse_http() {
        assert_eq!(
            ProxyConfig::from_str("http://1.2.3.4:8080"),
            Ok(ProxyConfig {
                proto: ProxyProtocol::Http,
                server: "1.2.3.4:8080".parse().unwrap(),
                username: None,
                password: None
            })
        );
    }
}
