use std::{
    fs::File,
    io::{self, BufReader},
    path::{Path, PathBuf},
    sync::Arc,
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
pub type Certificate = CertificateDer<'static>;
pub type PrivateKey = PrivateKeyDer<'static>;

use rustls::ClientConfig;

use crate::{
    config::SslConfig,
    error::Error,
    log::{self, warn},
};

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
            let certs1 = rustls_native_certs::load_native_certs().unwrap_or_else(|err| {
                warn!("load native certs failed.{}", err);
                Default::default()
            });

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

pub fn load_certificate_and_key(
    ssl_config: &SslConfig,
    cert_file: Option<&Path>,
    key_file: Option<&Path>,
    typ: &'static str,
) -> Result<(Vec<Certificate>, PrivateKey), Error> {
    use crate::libdns::proto::rustls::tls_server::{read_cert, read_key};

    let certificate_path = ssl_config
        .certificate
        .as_deref()
        .or(cert_file)
        .ok_or_else(|| Error::CertificatePathNotDefined(typ))?;

    let certificate_key_path = ssl_config
        .certificate_key
        .as_deref()
        .or(key_file)
        .ok_or_else(|| Error::CertificateKeyPathNotDefined(typ))?;

    if let Some(server_name) = ssl_config.server_name.as_deref() {
        log::info!(
            "loading cert for DNS over Https named {} from {:?}",
            server_name,
            certificate_path
        );
    } else {
        log::info!(
            "loading cert for DNS over Https from {:?}",
            certificate_path
        );
    }

    let certificate = read_cert(certificate_path).map_err(|err| {
        Error::LoadCertificateFailed(certificate_path.to_path_buf(), err.to_string())
    })?;

    let certificate_key = read_key(certificate_key_path).map_err(|err| {
        Error::LoadCertificateKeyFailed(certificate_key_path.to_path_buf(), err.to_string())
    })?;

    Ok((certificate, certificate_key))
}
