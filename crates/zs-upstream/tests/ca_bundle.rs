#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use rcgen::{CertifiedKey, generate_simple_self_signed};
use sha2::{Digest, Sha256};
use zs_upstream::{TlsConfigError, UpstreamTls, load_ca};

fn authority(name: &str) -> CertifiedKey {
    generate_simple_self_signed(vec![name.to_string()]).unwrap()
}

fn write(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

#[test]
fn the_hash_covers_certificates_not_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let first = authority("one.internal");
    let second = authority("two.internal");
    let plain = format!("{}{}", first.cert.pem(), second.cert.pem());
    let base = load_ca(&write(dir.path(), "plain.pem", &plain)).unwrap();
    assert_eq!(base.roots.len(), 2);

    let crlf = plain.replace('\n', "\r\n");
    let commented = format!(
        "# first authority\n{}\n# second authority\n{}",
        first.cert.pem(),
        second.cert.pem()
    );
    let with_key = format!("{plain}{}", second.key_pair.serialize_pem());
    for (name, text) in [
        ("crlf.pem", crlf),
        ("commented.pem", commented),
        ("with-key.pem", with_key),
    ] {
        let loaded = load_ca(&write(dir.path(), name, &text)).unwrap();
        assert_eq!(loaded.sha256, base.sha256, "{name}");
        assert_eq!(loaded.roots, base.roots, "{name}");
    }

    let shorter = load_ca(&write(dir.path(), "one.pem", &first.cert.pem())).unwrap();
    assert_ne!(shorter.sha256, base.sha256);

    let key_only = write(dir.path(), "key.pem", &first.key_pair.serialize_pem());
    assert!(matches!(
        load_ca(&key_only),
        Err(TlsConfigError::NoCertificate(_))
    ));
}

#[test]
fn the_hash_is_sha256_of_der_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let first = authority("one.internal");
    let second = authority("two.internal");
    let forward = load_ca(&write(
        dir.path(),
        "forward.pem",
        &format!("{}{}", first.cert.pem(), second.cert.pem()),
    ))
    .unwrap();
    let mut der = Sha256::new();
    der.update(first.cert.der());
    der.update(second.cert.der());
    let expected: [u8; 32] = der.finalize().into();
    assert_eq!(forward.sha256, expected);

    let reversed = load_ca(&write(
        dir.path(),
        "reversed.pem",
        &format!("{}{}", second.cert.pem(), first.cert.pem()),
    ))
    .unwrap();
    assert_ne!(reversed.sha256, forward.sha256);
}

#[test]
fn a_loaded_bundle_builds_the_trust_store_without_reading_the_file_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "ca.pem", &authority("one.internal").cert.pem());
    let loaded = load_ca(&path).unwrap();
    std::fs::write(&path, "garbage").unwrap();
    let tls = UpstreamTls::from_loaded(Some(&loaded), None).unwrap();
    assert!(matches!(&tls, UpstreamTls::Required(roots) if *roots == loaded.roots));
    assert_eq!(
        UpstreamTls::from_loaded(Some(&loaded), Some(&"ab".repeat(32))).err(),
        Some(TlsConfigError::BothSet)
    );
}
