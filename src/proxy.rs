use std::{
    fmt::{Display, Write},
    net::{AddrParseError, SocketAddr},
    str::FromStr,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyConfig {
    Socks(SocksProxyConfig),
}

impl Display for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyConfig::Socks(s) => write!(f, "{}", s),
        }
    }
}

impl FromStr for ProxyConfig {
    type Err = ProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match SocksProxyConfig::from_str(s) {
            Ok(opt) => Ok(Self::Socks(opt)),
            Err(err) => Err(err),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksProxyConfig {
    pub server: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl FromStr for SocksProxyConfig {
    type Err = ProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // socks5://user:pass@1.2.3.4:1080

        match s.strip_prefix("socks5://") {
            Some(s) => {
                let mut username = None;
                let mut password = None;

                let server = match s.find('@') {
                    Some(at_idx) => {
                        let mut usr_pwd = s[0..at_idx].split(':');
                        username = usr_pwd.next().map(|s| s.to_string());
                        password = usr_pwd.next().map(|s| s.to_string());

                        SocketAddr::from_str(&s[at_idx + 1..])
                    }
                    None => SocketAddr::from_str(s),
                }?;

                Ok(Self {
                    server,
                    username,
                    password,
                })
            }
            None => Err(ProxyParseError::UnexpectedSchema),
        }
    }
}

impl Display for SocksProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("socks5://")?;

        if let Some(user) = self.username.as_deref() {
            f.write_str(user)?;

            if let Some(pwd) = self.password.as_deref() {
                f.write_char(':')?;
                f.write_str(pwd)?;
            }

            f.write_char('@')?;
        }

        write!(f, "{}", self.server)
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ProxyParseError {
    #[error("UnexpectedSchema")]
    UnexpectedSchema,
    #[error(" address parse error {0:?}")]
    Addr(#[from] AddrParseError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socks5() {
        assert_eq!(
            SocksProxyConfig::from_str("socks5://1.2.3.4:1080"),
            Ok(SocksProxyConfig {
                server: "1.2.3.4:1080".parse().unwrap(),
                username: None,
                password: None
            })
        );
    }

    #[test]
    fn test_parse_socks5_with_user() {
        assert_eq!(
            SocksProxyConfig::from_str("socks5://user123@1.2.3.4:1080"),
            Ok(SocksProxyConfig {
                server: "1.2.3.4:1080".parse().unwrap(),
                username: Some("user123".to_string()),
                password: None
            })
        );
    }

    #[test]
    fn test_parse_socks5_with_user_pass() {
        assert_eq!(
            SocksProxyConfig::from_str("socks5://user123:pass456@1.2.3.4:1080"),
            Ok(SocksProxyConfig {
                server: "1.2.3.4:1080".parse().unwrap(),
                username: Some("user123".to_string()),
                password: Some("pass456".to_string())
            })
        );
    }
}
