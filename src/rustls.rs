use std::{
    fs::File,
    io::{self, BufReader},
    path::{Path, PathBuf},
    sync::Arc,
};

use rustls::ClientConfig;
use rustls_native_certs::Certificate;

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

            struct NoCertificateVerification;

            impl rustls::client::ServerCertVerifier for NoCertificateVerification {
                fn verify_server_cert(
                    &self,
                    _end_entity: &rustls::Certificate,
                    _intermediates: &[rustls::Certificate],
                    _server_name: &rustls::ServerName,
                    _scts: &mut dyn Iterator<Item = &[u8]>,
                    _ocsp: &[u8],
                    _now: std::time::SystemTime,
                ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
                    Ok(rustls::client::ServerCertVerified::assertion())
                }
            }

            verify_off
        };

        Self {
            normal: Arc::new(config),
            sni_off: Arc::new(sni_off),
            verify_off: Arc::new(verify_off),
        }
    }

    fn create_tls_client_config(paths: &[PathBuf]) -> ClientConfig {
        use rustls::{OwnedTrustAnchor, RootCertStore};

        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

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
            root_store
                .add(&rustls::Certificate(cert.0))
                .unwrap_or_else(|err| {
                    warn!("load certs from path failed.{}", err);
                })
        }

        ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth()
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
    let f = File::open(path)?;
    let mut f = BufReader::new(f);

    match rustls_pemfile::certs(&mut f) {
        Ok(contents) => Ok(contents.into_iter().map(Certificate).collect()),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Could not load PEM file {:?}", path),
        )),
    }
}

pub fn load_certificate_and_key(
    ssl_config: &SslConfig,
    cert_file: Option<&Path>,
    key_file: Option<&Path>,
    typ: &'static str,
) -> Result<(Vec<rustls::Certificate>, rustls::PrivateKey), Error> {
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
