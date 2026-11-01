use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::sign::CertifiedKey;
use thiserror::Error;

pub(crate) mod platform;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("ca storage: {0}")]
    Storage(String),
    #[error("certificate operation: {0}")]
    Certificate(String),
}

const CA_CERT_FILE: &str = "ca.crt";
const CA_KEY_FILE: &str = "ca.key.pem";

pub struct LocalCa {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert_der: CertificateDer<'static>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

#[cfg(target_os = "macos")]
pub const DEFAULT_KEYCHAIN_LABEL: &str = "zerosecret-local-ca";

#[cfg(target_os = "macos")]
pub fn keychain_label_for(dir: impl AsRef<Path>) -> String {
    let canonical =
        std::fs::canonicalize(dir.as_ref()).unwrap_or_else(|_| dir.as_ref().to_path_buf());
    label_of(&canonical)
}

#[cfg(target_os = "macos")]
fn existing_keychain_label(dir: &Path) -> Option<String> {
    std::fs::canonicalize(dir)
        .ok()
        .map(|canonical| label_of(&canonical))
}

#[cfg(target_os = "macos")]
fn label_of(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{DEFAULT_KEYCHAIN_LABEL}-{hex}")
}

impl LocalCa {
    #[cfg(target_os = "macos")]
    pub fn load_or_create_in_keychain(dir: impl AsRef<Path>, label: &str) -> Result<Self, CaError> {
        platform::load_in_keychain(dir.as_ref(), label)
    }

    pub fn load_or_create_secure(dir: impl AsRef<Path>) -> Result<Self, CaError> {
        platform::load(dir.as_ref())
    }

    pub fn retire_secure(dir: impl AsRef<Path>) -> Result<(), CaError> {
        platform::retire(dir.as_ref())
    }

    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self, CaError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| CaError::Storage(e.to_string()))?;
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        let (ca_key, ca_cert) = if cert_path.exists() && key_path.exists() {
            let key_pem =
                std::fs::read_to_string(&key_path).map_err(|e| CaError::Storage(e.to_string()))?;
            let key =
                KeyPair::from_pem(&key_pem).map_err(|e| CaError::Certificate(e.to_string()))?;
            let params = CertificateParams::from_ca_cert_pem(
                &std::fs::read_to_string(&cert_path)
                    .map_err(|e| CaError::Storage(e.to_string()))?,
            )
            .map_err(|e| CaError::Certificate(e.to_string()))?;
            let cert = params
                .self_signed(&key)
                .map_err(|e| CaError::Certificate(e.to_string()))?;
            (key, cert)
        } else {
            let key = KeyPair::generate().map_err(|e| CaError::Certificate(e.to_string()))?;
            let mut params = CertificateParams::new(Vec::<String>::new())
                .map_err(|e| CaError::Certificate(e.to_string()))?;
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let cert = params
                .self_signed(&key)
                .map_err(|e| CaError::Certificate(e.to_string()))?;
            std::fs::write(&cert_path, cert.pem()).map_err(|e| CaError::Storage(e.to_string()))?;
            std::fs::write(&key_path, key.serialize_pem())
                .map_err(|e| CaError::Storage(e.to_string()))?;
            restrict(&key_path)?;
            restrict(&cert_path)?;
            (key, cert)
        };
        let ca_cert_der = ca_cert.der().clone();
        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_der,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        self.ca_key.public_key_der()
    }

    pub fn certificate_pem(&self) -> String {
        self.ca_cert.pem()
    }

    pub fn certified_key_for(&self, host: &str) -> Result<Arc<CertifiedKey>, CaError> {
        if let Ok(cache) = self.cache.lock()
            && let Some(key) = cache.get(host)
        {
            return Ok(key.clone());
        }
        let leaf_key = KeyPair::generate().map_err(|e| CaError::Certificate(e.to_string()))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|e| CaError::Certificate(e.to_string()))?;
        params.is_ca = IsCa::ExplicitNoCa;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host.to_string());
        let leaf = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|e| CaError::Certificate(e.to_string()))?;
        let leaf_der = leaf.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signer = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| CaError::Certificate(e.to_string()))?;
        let certified = Arc::new(CertifiedKey::new(
            vec![leaf_der, self.ca_cert_der.clone()],
            signer,
        ));
        let Ok(mut cache) = self.cache.lock() else {
            return Ok(certified);
        };
        cache.insert(host.to_string(), certified.clone());
        Ok(certified)
    }

    pub fn server_name_for(host: &str) -> Result<ServerName<'static>, CaError> {
        ServerName::try_from(host.to_string()).map_err(|e| CaError::Certificate(e.to_string()))
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), CaError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| CaError::Storage(e.to_string()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), CaError> {
    Ok(())
}

pub fn ca_dir_for(host: &str) -> PathBuf {
    Path::new(host).to_path_buf()
}
