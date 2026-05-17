use std::{io, net::SocketAddr, path::PathBuf};

use hickory_net::NetError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("a certificate file must be specified for binding {0}")]
    CertificatePathNotDefined(&'static str),
    #[error("a certificate key file must be specified for binding {0}")]
    CertificateKeyPathNotDefined(&'static str),
    #[error("loading certificate {0} failed, due to: {1}")]
    LoadCertificateFailed(PathBuf, String),
    #[error("loading certificate key {0} failed, due to: {1}")]
    LoadCertificateKeyFailed(PathBuf, String),
    #[error("could not register {0} listener on addresss {1}, due to {2}")]
    RegisterListenerFailed(&'static str, SocketAddr, String),
    /// An error got returned by the hickory-net crate
    #[error("net error: {0}")]
    Net(#[from] NetError),
    /// An underlying IO error occurred
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}
