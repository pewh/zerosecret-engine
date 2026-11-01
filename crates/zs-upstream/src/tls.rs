use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone)]
pub enum UpstreamTls {
    WhenOffered,
    Required(Vec<CertificateDer<'static>>),
    Pinned([u8; 32]),
}

#[derive(Clone, Debug)]
pub struct LoadedCa {
    pub roots: Vec<CertificateDer<'static>>,
    pub sha256: [u8; 32],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TlsConfigError {
    #[error("upstream_ca and upstream_cert_sha256 cannot both be set")]
    BothSet,
    #[error("upstream_ca {0} cannot be read")]
    Unreadable(String),
    #[error("upstream_ca {0} holds no usable PEM certificate")]
    NoCertificate(String),
    #[error("upstream_cert_sha256 must be 64 hex digits")]
    BadPin,
    #[error("the upstream TLS client configuration could not be built")]
    Config,
    #[error("the upstream host is not a valid TLS server name")]
    BadServerName,
}

impl UpstreamTls {
    pub fn from_config(ca: Option<&Path>, pin: Option<&str>) -> Result<Self, TlsConfigError> {
        match (ca, pin) {
            (Some(_), Some(_)) => Err(TlsConfigError::BothSet),
            (Some(path), None) => Self::from_loaded(Some(&load_ca(path)?), None),
            (None, pin) => Self::from_loaded(None, pin),
        }
    }

    pub fn from_loaded(ca: Option<&LoadedCa>, pin: Option<&str>) -> Result<Self, TlsConfigError> {
        match (ca, pin) {
            (Some(_), Some(_)) => Err(TlsConfigError::BothSet),
            (None, None) => Ok(Self::WhenOffered),
            (None, Some(pin)) => parse_pin(pin)
                .map(Self::Pinned)
                .ok_or(TlsConfigError::BadPin),
            (Some(ca), None) => Ok(Self::Required(ca.roots.clone())),
        }
    }

    pub fn required(&self) -> bool {
        !matches!(self, Self::WhenOffered)
    }

    pub fn pinned(&self) -> bool {
        matches!(self, Self::Pinned(_))
    }

    pub fn server_name(&self, host: &str) -> Result<ServerName<'static>, TlsConfigError> {
        let bare = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        ServerName::try_from(bare.to_string()).map_err(|_| TlsConfigError::BadServerName)
    }
}

fn parse_pin(pin: &str) -> Option<[u8; 32]> {
    if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(pin.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

pub fn load_ca(path: &Path) -> Result<LoadedCa, TlsConfigError> {
    let shown = path.display().to_string();
    let pem = std::fs::read(path).map_err(|_| TlsConfigError::Unreadable(shown.clone()))?;
    let certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<_, _>>()
        .map_err(|_| TlsConfigError::NoCertificate(shown.clone()))?;
    if certificates.is_empty() {
        return Err(TlsConfigError::NoCertificate(shown));
    }
    let mut store = RootCertStore::empty();
    for certificate in &certificates {
        store
            .add(certificate.clone())
            .map_err(|_| TlsConfigError::NoCertificate(shown.clone()))?;
    }
    let mut digest = Sha256::new();
    for certificate in &certificates {
        digest.update(certificate.as_ref());
    }
    Ok(LoadedCa {
        roots: certificates,
        sha256: digest.finalize().into(),
    })
}

pub fn client_config(tls: &UpstreamTls) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algorithms = provider.signature_verification_algorithms;
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TlsConfigError::Config)?;
    let config = match tls {
        UpstreamTls::Pinned(sha256) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedLeaf {
                sha256: *sha256,
                algorithms,
            }))
            .with_no_client_auth(),
        UpstreamTls::WhenOffered | UpstreamTls::Required(_) => {
            let mut roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            if let UpstreamTls::Required(extra) = tls {
                for certificate in extra {
                    roots
                        .add(certificate.clone())
                        .map_err(|_| TlsConfigError::Config)?;
                }
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct PinnedLeaf {
    sha256: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedLeaf {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest = Sha256::digest(end_entity.as_ref());
        let difference = digest
            .iter()
            .zip(self.sha256.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if difference == 0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn self_signed(name: &str) -> rcgen::CertifiedKey {
        rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap()
    }

    #[test]
    fn no_field_means_tls_when_offered() {
        let tls = UpstreamTls::from_config(None, None).unwrap();
        assert!(matches!(tls, UpstreamTls::WhenOffered));
        assert!(!tls.required() && !tls.pinned());
    }

    #[test]
    fn a_pin_is_64_hex_digits_in_any_case() {
        let pin = "AB".repeat(32);
        let tls = UpstreamTls::from_config(None, Some(&pin)).unwrap();
        assert!(matches!(tls, UpstreamTls::Pinned(bytes) if bytes == [0xab; 32]));
        assert!(tls.required() && tls.pinned());
        for bad in [
            "ab".repeat(31),
            "ab".repeat(33),
            format!("{}zz", "ab".repeat(31)),
            "+f".repeat(32),
            String::new(),
        ] {
            assert_eq!(
                UpstreamTls::from_config(None, Some(&bad)).err(),
                Some(TlsConfigError::BadPin),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_ca_file_must_hold_a_usable_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("ca.pem");
        std::fs::write(&good, self_signed("db.internal").cert.pem()).unwrap();
        let tls = UpstreamTls::from_config(Some(&good), None).unwrap();
        assert!(matches!(&tls, UpstreamTls::Required(roots) if roots.len() == 1));
        assert!(tls.required() && !tls.pinned());

        let missing = dir.path().join("missing.pem");
        assert!(matches!(
            UpstreamTls::from_config(Some(&missing), None),
            Err(TlsConfigError::Unreadable(_))
        ));
        let junk = dir.path().join("junk.pem");
        std::fs::write(&junk, "not a certificate").unwrap();
        assert!(matches!(
            UpstreamTls::from_config(Some(&junk), None),
            Err(TlsConfigError::NoCertificate(_))
        ));
        let key_only = dir.path().join("key.pem");
        std::fs::write(
            &key_only,
            self_signed("db.internal").key_pair.serialize_pem(),
        )
        .unwrap();
        assert!(matches!(
            UpstreamTls::from_config(Some(&key_only), None),
            Err(TlsConfigError::NoCertificate(_))
        ));
        assert_eq!(
            UpstreamTls::from_config(Some(&good), Some(&"ab".repeat(32))).err(),
            Some(TlsConfigError::BothSet)
        );
    }

    #[test]
    fn the_pin_accepts_exactly_its_leaf() {
        let leaf = self_signed("db.internal");
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&Sha256::digest(leaf.cert.der()));
        let verifier = PinnedLeaf {
            sha256,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        };
        let name = ServerName::try_from("any.name.invalid").unwrap();
        assert!(
            verifier
                .verify_server_cert(leaf.cert.der(), &[], &name, &[], UnixTime::now())
                .is_ok()
        );
        let other = self_signed("db.internal");
        assert!(
            verifier
                .verify_server_cert(other.cert.der(), &[], &name, &[], UnixTime::now())
                .is_err()
        );
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn every_variant_builds_a_client_config() {
        let ca = self_signed("db.internal").cert.der().clone();
        for tls in [
            UpstreamTls::WhenOffered,
            UpstreamTls::Required(vec![ca]),
            UpstreamTls::Pinned([7; 32]),
        ] {
            assert!(client_config(&tls).is_ok());
        }
    }

    #[test]
    fn server_name_is_a_dns_name_or_an_ip_address() {
        let tls = UpstreamTls::WhenOffered;
        assert!(matches!(
            tls.server_name("db.internal"),
            Ok(ServerName::DnsName(name)) if name.as_ref() == "db.internal"
        ));
        assert!(matches!(
            tls.server_name("10.0.0.5"),
            Ok(ServerName::IpAddress(rustls::pki_types::IpAddr::V4(_)))
        ));
        for v6 in ["::1", "[::1]", "fd00::5"] {
            assert!(
                matches!(
                    tls.server_name(v6),
                    Ok(ServerName::IpAddress(rustls::pki_types::IpAddr::V6(_)))
                ),
                "{v6}"
            );
        }
        for bad in ["", "bad name", "db..internal", "[::1", "[]"] {
            assert_eq!(
                tls.server_name(bad).err(),
                Some(TlsConfigError::BadServerName),
                "{bad:?}"
            );
        }
    }
}
