use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

pub fn wrong_ca() -> io::Result<PathBuf> {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    if let Some(path) = PATH.get() {
        return Ok(path.clone());
    }
    let path = generate()?;
    let _ = PATH.set(path.clone());
    Ok(path)
}

fn generate() -> io::Result<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance/wrong-ca");
    fs::create_dir_all(&root)?;
    let path = root.join("ca.pem");
    let mut params = CertificateParams::new(vec!["wrong-ca.conformance".to_string()])
        .map_err(|error| io::Error::other(error.to_string()))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().map_err(|error| io::Error::other(error.to_string()))?;
    let certificate = params
        .self_signed(&key)
        .map_err(|error| io::Error::other(error.to_string()))?;
    fs::write(&path, certificate.pem())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use sha2::{Digest, Sha256};

    fn digest(path: &Path) -> Vec<u8> {
        let bytes = fs::read(path).expect("read the certificate");
        Sha256::digest(&bytes).to_vec()
    }

    #[test]
    fn the_wrong_ca_is_a_valid_but_unrelated_ca() {
        let path = wrong_ca().expect("generate the wrong CA");
        let text = fs::read_to_string(&path).expect("read the PEM");
        assert!(text.contains("BEGIN CERTIFICATE"));
        let output = std::process::Command::new("openssl")
            .args(["x509", "-in", &path.to_string_lossy(), "-noout", "-text"])
            .output()
            .expect("openssl must be installed");
        assert!(output.status.success());
        let described = String::from_utf8_lossy(&output.stdout);
        assert!(described.contains("CA:TRUE"), "{described}");
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/db-test-certs/ca.pem");
        if !crate::test_fixtures::ready(&[], &[&fixture]) {
            return;
        }
        assert_ne!(digest(&path), digest(&fixture));
    }
}
