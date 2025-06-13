use std::{
    fs::{self, File},
    io::{self, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
pub type Certificate = CertificateDer<'static>;
pub type PrivateKey = PrivateKeyDer<'static>;

pub use rustls::server::ResolvesServerCert;
use rustls::{ClientConfig, ServerConfig, sign::CertifiedKey};

use crate::log::{info, warn};

#[derive(Clone)]
pub struct TlsClientConfigBundle {
    pub normal: Arc<ClientConfig>,
    pub sni_off: Arc<ClientConfig>,
    pub verify_off: Arc<ClientConfig>,
}

impl TlsClientConfigBundle {
    pub fn new(ca_path: Option<PathBuf>, ca_file: Option<PathBuf>) -> Self {
        let config = Self::create_tls_client_config(
            [ca_path, ca_file]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let sni_off = {
            let mut sni_off = config.clone();
            sni_off.enable_sni = false;
            sni_off
        };

        let verify_off = {
            let mut verify_off = config.clone();
            verify_off
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification));

            verify_off
        };

        Self {
            normal: Arc::new(config),
            sni_off: Arc::new(sni_off),
            verify_off: Arc::new(verify_off),
        }
    }

    fn create_tls_client_config(paths: &[PathBuf]) -> ClientConfig {
        use rustls::RootCertStore;

        let mut root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };

        let certs = {
            let certs1 = rustls_native_certs::load_native_certs().certs;

            let certs2 = paths
                .iter()
                .filter_map(|path| match load_certs_from_path(path.as_path()) {
                    Ok(certs) => Some(certs),
                    Err(err) => {
                        warn!("load certs from path failed.{}", err);
                        None
                    }
                })
                .flatten();

            certs1.into_iter().chain(certs2)
        };

        for cert in certs {
            root_store.add(cert).unwrap_or_else(|err| {
                warn!("load certs from path failed.{}", err);
            })
        }

        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    }
}

#[derive(Debug)]
pub(super) struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
            ED448,
        ]
    }
}

/// Load certificates from specific directory or file.
pub fn load_certs_from_path(path: &Path) -> Result<Vec<Certificate>, io::Error> {
    if path.is_dir() {
        let mut certs = vec![];
        for entry in path.read_dir()? {
            let path = entry?.path();
            if path.is_file() {
                certs.extend(load_pem_certs(path.as_path())?);
            }
        }
        Ok(certs)
    } else {
        load_pem_certs(path)
    }
}

fn load_pem_certs(path: &Path) -> Result<Vec<Certificate>, io::Error> {
    let mut file = BufReader::new(File::open(path)?);

    match rustls_pemfile::certs(&mut file).collect() {
        Ok(certs) => Ok(certs),
        Err(err) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Could not load PEM file {} {:?}", err, path),
        )),
    }
}

#[cfg(feature = "dns-over-tls")]
pub fn tls_server_config(
    protocol: &[u8],
    server_cert_resolver: Arc<dyn ResolvesServerCert>,
) -> Result<ServerConfig, io::Error> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| io::Error::other(format!("error creating TLS acceptor: {e}")))?
            .with_no_client_auth()
            .with_cert_resolver(server_cert_resolver);

    config.alpn_protocols = vec![protocol.to_vec()];
    Ok(config)
}

#[derive(Debug)]
pub struct TlsServerCertResolver {
    path: PathBuf,
    private_key: PathBuf,
    certified_key: RwLock<Arc<CertifiedKey>>,
}

impl TlsServerCertResolver {
    pub fn new(cert_path: &Path, key_path: &Path) -> Result<Self, crate::Error> {
        let certified_key = Self::load(cert_path, key_path)?;
        Ok(TlsServerCertResolver {
            path: cert_path.to_path_buf(),
            private_key: key_path.to_path_buf(),
            certified_key: RwLock::new(Arc::new(certified_key)),
        })
    }

    pub fn load(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey, crate::Error> {
        use crate::Error;
        use rustls::crypto::ring::default_provider;

        let cert_chain = CertificateDer::pem_file_iter(cert_path)
            .map_err(|e| {
                Error::LoadCertificateFailed(
                    cert_path.to_path_buf(),
                    format!(
                        "failed to read cert chain from {}: {e}",
                        cert_path.display()
                    ),
                )
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                Error::LoadCertificateFailed(
                    cert_path.to_path_buf(),
                    format!(
                        "failed to parse cert chain from {}: {e}",
                        cert_path.display()
                    ),
                )
            })?;

        let key_extension = key_path.extension();

        fn from_pem_file(key_path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
            let key_path = &key_path;
            info!("loading TLS PKCS8 key from PEM: {}", key_path.display());
            PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!("failed to read key from {}: {e}", key_path.display()),
                )
            })
        }

        fn try_from(key_path: &Path) -> Result<PrivateKeyDer<'static>, Error> {
            let key_path = &key_path;
            info!("loading TLS PKCS8 key from DER: {}", key_path.display());

            let buf = fs::read(key_path).map_err(|e| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!("error reading key from file: {e}"),
                )
            })?;

            PrivateKeyDer::try_from(buf).map_err(|e| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!("error parsing key DER: {e}"),
                )
            })
        }

        let key = if key_extension.is_some_and(|ext| ext == "pem") {
            from_pem_file(key_path)?
        } else if key_extension.is_some_and(|ext| ext == "der") {
            try_from(key_path)?
        } else {
            from_pem_file(key_path).or_else(|_| try_from(key_path)).map_err(|_| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!(
                        "unsupported private key file format (expected `.pem` or `.der` `.key` extension): {}",
                        key_path.display()
                    ),
                )
            })?
        };

        let certified_key =
            CertifiedKey::from_der(cert_chain, key, &default_provider()).map_err(|err| {
                Error::LoadCertificateKeyFailed(
                    key_path.to_path_buf(),
                    format!("failed to read certificate and keys: {err:?}"),
                )
            })?;

        Ok(certified_key)
    }
}

impl ResolvesServerCert for TlsServerCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.certified_key.read().ok().as_deref().cloned()
    }
}
