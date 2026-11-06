use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair,
    KeyUsagePurpose,
};
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

const ROOT_NAME: &str = "ZeroSecret local CA";
const ROOT_LIFETIME: Duration = Duration::from_secs(3650 * 24 * 3600);
const LEAF_LIFETIME: Duration = Duration::from_secs(24 * 3600);
const LEAF_REUSE: Duration = Duration::from_secs(12 * 3600);
const CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

pub struct LocalCa {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert_der: CertificateDer<'static>,
    // A leaf is reused until its renewal time, half its lifetime.
    cache: Mutex<HashMap<String, (SystemTime, Arc<CertifiedKey>)>>,
}

// Only a new root gets these values; a stored root keeps its own.
pub(crate) fn root_params() -> Result<CertificateParams, rcgen::Error> {
    let now = SystemTime::now();
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ROOT_NAME);
    params.not_before = (now - CLOCK_SKEW).into();
    params.not_after = (now + ROOT_LIFETIME).into();
    Ok(params)
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
            let params = root_params().map_err(|e| CaError::Certificate(e.to_string()))?;
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
        let host = host.to_ascii_lowercase();
        let now = SystemTime::now();
        if let Ok(cache) = self.cache.lock()
            && let Some((renew_at, key)) = cache.get(&host)
            && now < *renew_at
        {
            return Ok(key.clone());
        }
        let leaf_key = KeyPair::generate().map_err(|e| CaError::Certificate(e.to_string()))?;
        let mut params = CertificateParams::new(vec![host.clone()])
            .map_err(|e| CaError::Certificate(e.to_string()))?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.not_before = (now - CLOCK_SKEW).into();
        params.not_after = (now + LEAF_LIFETIME).into();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host.clone());
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
        cache.insert(host, (now + LEAF_REUSE, certified.clone()));
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn case_variants_share_one_leaf() {
        let home = tempfile::tempdir().unwrap();
        let ca = LocalCa::load_or_create(home.path().join("ca")).unwrap();
        let lower = ca.certified_key_for("api.example.com").unwrap();
        for variant in ["API.EXAMPLE.COM", "Api.Example.Com", "api.example.com"] {
            assert!(
                Arc::ptr_eq(&lower, &ca.certified_key_for(variant).unwrap()),
                "{variant}"
            );
        }
        let other = ca.certified_key_for("other.example.com").unwrap();
        assert!(!Arc::ptr_eq(&lower, &other));
        assert_eq!(ca.cache.lock().unwrap().len(), 2);
    }

    fn validity(der: &CertificateDer<'_>) -> (SystemTime, SystemTime) {
        let params = CertificateParams::from_ca_cert_der(der).unwrap();
        (params.not_before.into(), params.not_after.into())
    }

    fn within(actual: SystemTime, expected: SystemTime, slack: Duration) -> bool {
        actual + slack >= expected && actual <= expected + slack
    }

    #[test]
    fn a_minted_leaf_expires_within_a_day() {
        let home = tempfile::tempdir().unwrap();
        let ca = LocalCa::load_or_create(home.path().join("ca")).unwrap();
        let now = SystemTime::now();
        let leaf = ca.certified_key_for("api.example.com").unwrap();
        let (not_before, not_after) = validity(&leaf.cert[0]);
        let slack = Duration::from_secs(60);
        assert!(within(not_before, now - Duration::from_secs(5 * 60), slack));
        assert!(within(
            not_after,
            now + Duration::from_secs(24 * 3600),
            slack
        ));
    }

    #[test]
    fn a_leaf_is_minted_again_before_it_expires() {
        let home = tempfile::tempdir().unwrap();
        let ca = LocalCa::load_or_create(home.path().join("ca")).unwrap();
        let first = ca.certified_key_for("api.example.com").unwrap();
        assert!(Arc::ptr_eq(
            &first,
            &ca.certified_key_for("api.example.com").unwrap()
        ));
        for (renew_at, _) in ca.cache.lock().unwrap().values_mut() {
            *renew_at = SystemTime::now() - Duration::from_secs(1);
        }
        assert!(!Arc::ptr_eq(
            &first,
            &ca.certified_key_for("api.example.com").unwrap()
        ));
    }

    #[test]
    fn a_new_root_is_named_and_lasts_ten_years() {
        let home = tempfile::tempdir().unwrap();
        let ca = LocalCa::load_or_create(home.path().join("ca")).unwrap();
        let now = SystemTime::now();
        let params = CertificateParams::from_ca_cert_der(&ca.ca_cert_der).unwrap();
        assert_eq!(
            params
                .distinguished_name
                .get(&rcgen::DnType::CommonName)
                .unwrap(),
            &rcgen::DnValue::Utf8String("ZeroSecret local CA".into())
        );
        assert_eq!(params.is_ca, IsCa::Ca(BasicConstraints::Constrained(0)));
        let (not_before, not_after) = validity(&ca.ca_cert_der);
        let slack = Duration::from_secs(3 * 24 * 3600);
        assert!(within(not_before, now, slack));
        assert!(within(
            not_after,
            now + Duration::from_secs(3650 * 24 * 3600),
            slack
        ));
    }

    #[test]
    fn an_existing_root_keeps_its_name_and_validity() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join("ca");
        std::fs::create_dir_all(&dir).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let old = params.self_signed(&key).unwrap();
        std::fs::write(dir.join(CA_CERT_FILE), old.pem()).unwrap();
        std::fs::write(dir.join(CA_KEY_FILE), key.serialize_pem()).unwrap();
        let ca = LocalCa::load_or_create(&dir).unwrap();
        assert_eq!(ca.public_key_der(), key.public_key_der());
        assert_eq!(validity(&ca.ca_cert_der), validity(old.der()));
        let leaf = ca.certified_key_for("api.example.com").unwrap();
        assert_eq!(leaf.cert[1], ca.ca_cert_der);
    }
}
