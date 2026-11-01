#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::{Cell, RefCell};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConnection, Connection, ServerConnection};
use zeroize::Zeroizing;

use super::record::{
    CaRecord, MAX_RECORD_LEN, SecretBytes, ca_from_record, decode_record, encode_record, new_record,
};
use super::state::{
    NativeSnapshot, Step, load_locked, load_with, lock_directory, persist_account, retire_with,
    storage_account, transition,
};
use crate::ca::{CaError, LocalCa};

const HOST: &str = "storage.zerosecret.test";
const CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----\nQ0VSVA==\n-----END CERTIFICATE-----\n";
const KEY: &str = "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n";
pub(super) const MALFORMED: &str = "CA storage record malformed";
const INVALID: &str = "CA storage record invalid";

fn denial<T>(result: Result<T, CaError>) -> String {
    assert!(result.is_err());
    result
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default()
}

fn assert_denied<T>(result: Result<T, CaError>, message: &str) {
    assert_eq!(denial(result), format!("ca storage: {message}"));
}

fn record(certificate: &str, key: &str) -> CaRecord {
    CaRecord {
        certificate_pem: certificate.to_owned(),
        private_key_pem: Zeroizing::new(key.to_owned()),
    }
}

pub(super) fn generated() -> CaRecord {
    new_record().unwrap()
}

pub(super) fn encoded(record: &CaRecord) -> Vec<u8> {
    encode_record(record).unwrap().0.to_vec()
}

fn raw(magic: &[u8], version: u8, certificate_len: u32, key_len: u32, body: &[&[u8]]) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    bytes.push(version);
    bytes.extend_from_slice(&certificate_len.to_be_bytes());
    bytes.extend_from_slice(&key_len.to_be_bytes());
    for part in body {
        bytes.extend_from_slice(part);
    }
    bytes
}

fn framed(label: &str, len: usize) -> String {
    let begin = format!("-----BEGIN {label}-----\n");
    let end = format!("\n-----END {label}-----\n");
    let fill = len - begin.len() - end.len();
    format!("{begin}{}{end}", "A".repeat(fill))
}

fn same_record(left: &CaRecord, right: &CaRecord) -> bool {
    left.certificate_pem == right.certificate_pem
        && left.private_key_pem.as_str() == right.private_key_pem.as_str()
}

fn public_key(key_pem: &str) -> Vec<u8> {
    KeyPair::from_pem(key_pem).unwrap().public_key_der()
}

fn certificate_with(is_ca: IsCa, key: &KeyPair) -> String {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = is_ca;
    params.self_signed(key).unwrap().pem()
}

fn transfer(from: &mut Connection, to: &mut Connection) -> Result<(), rustls::Error> {
    let mut buffer = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut buffer).unwrap();
    }
    let mut pending = buffer.as_slice();
    while !pending.is_empty() {
        to.read_tls(&mut pending).unwrap();
        to.process_new_packets()?;
    }
    Ok(())
}

pub(super) fn handshake_succeeds(ca: &LocalCa, trusted_certificate_pem: &str) -> bool {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let resolver = rustls::sign::SingleCertAndKey::from(ca.certified_key_for(HOST).unwrap());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(trusted_certificate_pem.as_bytes()).unwrap())
        .unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(HOST).unwrap();
    let mut client = Connection::from(ClientConnection::new(Arc::new(client), name).unwrap());
    let mut server = Connection::from(ServerConnection::new(Arc::new(server)).unwrap());
    for _ in 0..16 {
        if !client.is_handshaking() && !server.is_handshaking() {
            return true;
        }
        if transfer(&mut client, &mut server).is_err()
            || transfer(&mut server, &mut client).is_err()
        {
            return false;
        }
    }
    false
}

#[test]
fn codec_round_trips_record() {
    let original = generated();
    let decoded = decode_record(&encoded(&original)).unwrap();
    assert!(same_record(&original, &decoded));
}

#[test]
fn codec_writes_exact_layout() {
    let bytes = encoded(&record(CERTIFICATE, KEY));
    let certificate_len = u32::try_from(CERTIFICATE.len()).unwrap();
    let key_len = u32::try_from(KEY.len()).unwrap();
    let expected = raw(
        b"ZSCA",
        1,
        certificate_len,
        key_len,
        &[CERTIFICATE.as_bytes(), KEY.as_bytes()],
    );
    assert!(bytes == expected);
    assert!(bytes.len() == 13 + CERTIFICATE.len() + KEY.len());
}

#[test]
fn codec_rejects_empty_input() {
    assert_denied(decode_record(&[]), MALFORMED);
}

#[test]
fn codec_rejects_wrong_magic_and_version() {
    let mut bytes = encoded(&record(CERTIFICATE, KEY));
    bytes[3] = b'X';
    assert_denied(decode_record(&bytes), MALFORMED);
    for version in [0u8, 2, 255] {
        let mut bytes = encoded(&record(CERTIFICATE, KEY));
        bytes[4] = version;
        assert_denied(decode_record(&bytes), MALFORMED);
    }
}

#[test]
fn codec_rejects_truncated_header() {
    let bytes = encoded(&record(CERTIFICATE, KEY));
    for len in 1..13 {
        assert_denied(decode_record(&bytes[..len]), MALFORMED);
    }
}

#[test]
fn codec_rejects_truncated_body() {
    let bytes = encoded(&record(CERTIFICATE, KEY));
    assert_denied(decode_record(&bytes[..bytes.len() - 1]), MALFORMED);
    assert_denied(decode_record(&bytes[..13 + CERTIFICATE.len()]), MALFORMED);
    assert_denied(decode_record(&bytes[..13]), MALFORMED);
}

#[test]
fn codec_rejects_overflowed_lengths() {
    let body: &[&[u8]] = &[CERTIFICATE.as_bytes(), KEY.as_bytes()];
    let key_len = u32::try_from(KEY.len()).unwrap();
    assert_denied(
        decode_record(&raw(b"ZSCA", 1, u32::MAX, u32::MAX, body)),
        MALFORMED,
    );
    assert_denied(
        decode_record(&raw(b"ZSCA", 1, u32::MAX, key_len, body)),
        MALFORMED,
    );
    assert_denied(
        decode_record(&raw(b"ZSCA", 1, 1, u32::MAX, body)),
        MALFORMED,
    );
}

#[test]
fn codec_rejects_trailing_data() {
    let mut bytes = encoded(&record(CERTIFICATE, KEY));
    bytes.push(b'\n');
    assert_denied(decode_record(&bytes), MALFORMED);
}

#[test]
fn codec_rejects_invalid_utf8() {
    let mut certificate = CERTIFICATE.as_bytes().to_vec();
    certificate[30] = 0xff;
    let mut key = KEY.as_bytes().to_vec();
    key[30] = 0xfe;
    let certificate_len = u32::try_from(certificate.len()).unwrap();
    let key_len = u32::try_from(key.len()).unwrap();
    let bad_certificate = raw(
        b"ZSCA",
        1,
        certificate_len,
        key_len,
        &[&certificate, KEY.as_bytes()],
    );
    assert_denied(decode_record(&bad_certificate), MALFORMED);
    let bad_key = raw(
        b"ZSCA",
        1,
        certificate_len,
        key_len,
        &[CERTIFICATE.as_bytes(), &key],
    );
    assert_denied(decode_record(&bad_key), MALFORMED);
}

#[test]
fn codec_rejects_invalid_pem() {
    let cases = [
        record("not pem", KEY),
        record(CERTIFICATE, "not pem"),
        record(KEY, KEY),
        record(CERTIFICATE, CERTIFICATE),
        record(&format!("{CERTIFICATE}{CERTIFICATE}"), KEY),
        record(CERTIFICATE, &format!("{KEY}{KEY}")),
        record(&format!("junk\n{CERTIFICATE}"), KEY),
    ];
    for case in &cases {
        assert_denied(encode_record(case), MALFORMED);
        let certificate = case.certificate_pem.as_bytes();
        let key = case.private_key_pem.as_bytes();
        let bytes = raw(
            b"ZSCA",
            1,
            u32::try_from(certificate.len()).unwrap(),
            u32::try_from(key.len()).unwrap(),
            &[certificate, key],
        );
        assert_denied(decode_record(&bytes), MALFORMED);
    }
}

#[test]
fn codec_rejects_empty_certificate_or_key() {
    assert_denied(encode_record(&record("", KEY)), MALFORMED);
    assert_denied(encode_record(&record(CERTIFICATE, "")), MALFORMED);
    let key_len = u32::try_from(KEY.len()).unwrap();
    let certificate_len = u32::try_from(CERTIFICATE.len()).unwrap();
    assert_denied(
        decode_record(&raw(b"ZSCA", 1, 0, key_len, &[KEY.as_bytes()])),
        MALFORMED,
    );
    assert_denied(
        decode_record(&raw(
            b"ZSCA",
            1,
            certificate_len,
            0,
            &[CERTIFICATE.as_bytes()],
        )),
        MALFORMED,
    );
}

#[test]
fn codec_bounds_record_length() {
    let largest = framed("CERTIFICATE", MAX_RECORD_LEN - 13 - KEY.len());
    let bytes = encoded(&record(&largest, KEY));
    assert!(bytes.len() == MAX_RECORD_LEN);
    assert!(same_record(
        &decode_record(&bytes).unwrap(),
        &record(&largest, KEY)
    ));

    let oversized = framed("CERTIFICATE", MAX_RECORD_LEN - 12 - KEY.len());
    assert_denied(encode_record(&record(&oversized, KEY)), MALFORMED);
    let bytes = raw(
        b"ZSCA",
        1,
        u32::try_from(oversized.len()).unwrap(),
        u32::try_from(KEY.len()).unwrap(),
        &[oversized.as_bytes(), KEY.as_bytes()],
    );
    assert!(bytes.len() == MAX_RECORD_LEN + 1);
    assert_denied(decode_record(&bytes), MALFORMED);
}

#[test]
fn new_record_is_a_self_signed_ca() {
    let record = generated();
    let params = CertificateParams::from_ca_cert_pem(&record.certificate_pem).unwrap();
    assert!(matches!(params.is_ca, IsCa::Ca(_)));
    assert!(encode_record(&record).is_ok());
    assert!(!same_record(&record, &generated()));
}

#[test]
fn ca_validation_loads_matching_pair() {
    let record = generated();
    let ca = ca_from_record(&record).unwrap();
    assert_eq!(ca.public_key_der(), public_key(&record.private_key_pem));
}

#[test]
fn ca_validation_denies_mismatched_pair() {
    let first = generated();
    let second = generated();
    let mixed = record(&first.certificate_pem, &second.private_key_pem);
    assert_denied(ca_from_record(&mixed), INVALID);
}

#[test]
fn ca_validation_denies_non_ca_certificate() {
    let key = KeyPair::generate().unwrap();
    let key_pem = key.serialize_pem();
    for is_ca in [IsCa::ExplicitNoCa, IsCa::NoCa] {
        let leaf = record(&certificate_with(is_ca, &key), &key_pem);
        assert_denied(ca_from_record(&leaf), INVALID);
    }
    let ca = record(
        &certificate_with(IsCa::Ca(BasicConstraints::Unconstrained), &key),
        &key_pem,
    );
    assert!(ca_from_record(&ca).is_ok());
}

#[test]
fn ca_validation_denies_corrupt_key() {
    let valid = generated();
    let corrupt = record(&valid.certificate_pem, KEY);
    assert_denied(ca_from_record(&corrupt), INVALID);
    let truncated = valid.private_key_pem[..valid.private_key_pem.len() / 2].to_owned();
    assert_denied(
        ca_from_record(&record(&valid.certificate_pem, &truncated)),
        INVALID,
    );
}

#[test]
fn ca_validation_denies_corrupt_certificate() {
    let valid = generated();
    assert_denied(
        ca_from_record(&record(CERTIFICATE, &valid.private_key_pem)),
        INVALID,
    );
}

#[test]
fn ca_validation_signs_leaf_trusted_by_stored_certificate() {
    let record = generated();
    let ca = ca_from_record(&record).unwrap();
    assert!(handshake_succeeds(&ca, &record.certificate_pem));
    assert!(!handshake_succeeds(&ca, &generated().certificate_pem));
}

const SENTINEL: &str = "native detail 7f3a";
pub(super) const UNAVAILABLE: &str = "secure CA storage unavailable";
pub(super) const BUSY: &str = "CA storage busy";
const PATH_INVALID: &str = "CA storage path invalid";
const IDENTITY_MISSING: &str = "CA storage identity missing";
const IDENTITY_MALFORMED: &str = "CA storage identity malformed";
const CERTIFICATE_INVALID: &str = "CA certificate invalid";
const CERTIFICATE_MISMATCH: &str = "CA certificate mismatch";
pub(super) const KEY_MISSING: &str = "CA private key missing";
pub(super) const INCOMPLETE: &str = "CA legacy identity incomplete";
const LEGACY_INVALID: &str = "CA legacy key invalid";
pub(super) const LEGACY_MISMATCH: &str = "CA legacy key mismatch";
const READBACK_MISMATCH: &str = "CA storage readback mismatch";
const PUBLICATION_FAILED: &str = "CA certificate publication failed";
pub(super) const REMOVAL_FAILED: &str = "CA legacy key removal failed";
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) const LOCKED: &str = "secure CA storage locked";
pub(super) const MIGRATION_INCOMPLETE: &str = "CA migration incomplete";
pub(super) const RECORD_REMOVAL_FAILED: &str = "CA record removal failed";
#[cfg(unix)]
const CLEANUP_FAILED: &str = "CA directory cleanup failed";
pub(super) const CERT_FILE: &str = "ca.crt";
pub(super) const KEY_FILE: &str = "ca.key.pem";
pub(super) const ID_FILE: &str = ".ca-storage-id";
const LOCK_FILE: &str = ".ca-storage.lock";
const ARTIFACTS: [&str; 5] = [
    "certificate",
    "file_key",
    "identity",
    "record",
    "native_legacy",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    Read,
    Readback,
    Write,
    WriteAltered,
    WriteDropped,
    Delete,
    DeleteIgnored,
    LegacyRead,
}

fn injected() -> CaError {
    CaError::Storage(SENTINEL.to_owned())
}

#[derive(Default)]
struct Native {
    record: RefCell<Option<Vec<u8>>>,
    legacy: RefCell<Option<String>>,
    fault: Cell<Option<Fault>>,
    reads: Cell<usize>,
    writes: Cell<usize>,
    deletes: Cell<usize>,
    accounts: RefCell<Vec<String>>,
    log: RefCell<Vec<&'static str>>,
}

impl Native {
    fn failing(&self, fault: Fault) -> bool {
        self.fault.get() == Some(fault)
    }

    fn next_read(&self) -> Result<(), CaError> {
        self.reads.set(self.reads.get() + 1);
        if self.failing(Fault::Read) || (self.failing(Fault::Readback) && self.reads.get() > 1) {
            return Err(injected());
        }
        Ok(())
    }

    fn record_bytes(&self) -> Option<SecretBytes> {
        self.record
            .borrow()
            .clone()
            .map(|bytes| SecretBytes(Zeroizing::new(bytes)))
    }

    fn legacy_key(&self) -> Result<Option<Zeroizing<String>>, CaError> {
        self.log.borrow_mut().push("legacy");
        if self.failing(Fault::LegacyRead) {
            return Err(injected());
        }
        Ok(self.legacy.borrow().clone().map(Zeroizing::new))
    }

    fn snapshot(&self) -> Result<NativeSnapshot, CaError> {
        self.next_read()?;
        Ok(NativeSnapshot {
            record: self.record_bytes(),
            legacy_key: self.legacy_key()?,
        })
    }

    fn read_record(&self, account: &str) -> Result<Option<SecretBytes>, CaError> {
        self.log.borrow_mut().push("record");
        self.accounts.borrow_mut().push(account.to_owned());
        self.next_read()?;
        Ok(self.record_bytes())
    }

    fn write(&self, bytes: &[u8]) -> Result<(), CaError> {
        self.writes.set(self.writes.get() + 1);
        let stored = match self.fault.get() {
            Some(Fault::Write) => return Err(injected()),
            Some(Fault::WriteDropped) => return Ok(()),
            Some(Fault::WriteAltered) => {
                let mut altered = bytes.to_vec();
                if let Some(last) = altered.last_mut() {
                    *last ^= 1;
                }
                altered
            }
            _ => bytes.to_vec(),
        };
        *self.record.borrow_mut() = Some(stored);
        Ok(())
    }

    fn write_record(&self, account: &str, bytes: &[u8]) -> Result<(), CaError> {
        self.accounts.borrow_mut().push(account.to_owned());
        self.write(bytes)
    }

    fn delete_record(&self, account: &str) -> Result<(), CaError> {
        self.log.borrow_mut().push("delete");
        self.accounts.borrow_mut().push(account.to_owned());
        self.deletes.set(self.deletes.get() + 1);
        match self.fault.get() {
            Some(Fault::Delete) => Err(injected()),
            Some(Fault::DeleteIgnored) => Ok(()),
            _ => {
                *self.record.borrow_mut() = None;
                Ok(())
            }
        }
    }

    fn delete(&self) -> Result<(), CaError> {
        self.deletes.set(self.deletes.get() + 1);
        if self.failing(Fault::Delete) {
            return Err(injected());
        }
        *self.legacy.borrow_mut() = None;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Artifacts {
    certificate: bool,
    file_key: bool,
    identity: bool,
    record: bool,
    native_legacy: bool,
}

fn present(items: &[&str]) -> Artifacts {
    assert!(items.iter().all(|item| ARTIFACTS.contains(item)));
    Artifacts {
        certificate: items.contains(&"certificate"),
        file_key: items.contains(&"file_key"),
        identity: items.contains(&"identity"),
        record: items.contains(&"record"),
        native_legacy: items.contains(&"native_legacy"),
    }
}

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub(super) dir: PathBuf,
    native: Native,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("ca");
        fs::create_dir(&dir).unwrap();
        Self {
            _root: root,
            dir,
            native: Native::default(),
        }
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub(super) fn put(&self, name: &str, contents: &[u8]) {
        fs::write(self.path(name), contents).unwrap();
    }

    fn read(&self, name: &str) -> Option<Vec<u8>> {
        fs::read(self.path(name)).ok()
    }

    pub(super) fn certificate(&self) -> Option<String> {
        fs::read_to_string(self.path(CERT_FILE)).ok()
    }

    pub(super) fn account(&self) -> Option<String> {
        fs::read_to_string(self.path(ID_FILE)).ok()
    }

    pub(super) fn file_key_is(&self, key: &str) -> bool {
        self.read(KEY_FILE).as_deref() == Some(key.as_bytes())
    }

    fn native_legacy_is(&self, key: &str) -> bool {
        self.native.legacy.borrow().as_deref() == Some(key)
    }

    fn stored_is(&self, bytes: &[u8]) -> bool {
        self.native.record.borrow().as_deref() == Some(bytes)
    }

    fn store(&self, record: &CaRecord) {
        *self.native.record.borrow_mut() = Some(encoded(record));
    }

    fn store_raw(&self, bytes: &[u8]) {
        *self.native.record.borrow_mut() = Some(bytes.to_vec());
    }

    fn native_legacy(&self, key: &str) {
        *self.native.legacy.borrow_mut() = Some(key.to_owned());
    }

    fn fault(&self, fault: Fault) {
        self.native.fault.set(Some(fault));
    }

    fn clear(&self) {
        self.native.fault.set(None);
    }

    fn counts(&self) -> (usize, usize, usize) {
        (
            self.native.reads.get(),
            self.native.writes.get(),
            self.native.deletes.get(),
        )
    }

    fn artifacts(&self) -> Artifacts {
        Artifacts {
            certificate: self.path(CERT_FILE).exists(),
            file_key: self.path(KEY_FILE).exists(),
            identity: self.path(ID_FILE).exists(),
            record: self.native.record.borrow().is_some(),
            native_legacy: self.native.legacy.borrow().is_some(),
        }
    }

    fn load(&self) -> Result<LocalCa, CaError> {
        let _lock = lock_directory(&self.dir)?;
        load_locked(
            &self.dir,
            || self.native.snapshot(),
            |bytes| self.native.write(bytes),
            || self.native.delete(),
        )
    }

    fn load_failing_at(&self, step: Step) -> Result<LocalCa, CaError> {
        let _lock = lock_directory(&self.dir)?;
        transition(
            &self.dir,
            || self.native.snapshot(),
            |bytes| self.native.write(bytes),
            || self.native.delete(),
            |current| {
                if current == step {
                    Err(io::Error::other(SENTINEL))
                } else {
                    Ok(())
                }
            },
        )
    }

    fn retire(&self) -> Result<(), CaError> {
        retire_with(
            &self.dir,
            || self.native.legacy_key(),
            |account| self.native.read_record(account),
            |account| self.native.delete_record(account),
        )
    }

    fn platform_load(&self) -> Result<LocalCa, CaError> {
        load_with(
            &self.dir,
            || self.native.legacy_key(),
            |account| self.native.read_record(account),
            |account, bytes| self.native.write_record(account, bytes),
            || self.native.delete(),
        )
    }
}

pub(super) fn assert_redacted<T>(result: Result<T, CaError>, message: &str) {
    let text = denial(result);
    assert!(!text.contains(SENTINEL));
    assert_eq!(text, format!("ca storage: {message}"));
}

pub(super) fn same_identity(ca: &LocalCa, record: &CaRecord) -> bool {
    ca.public_key_der() == public_key(&record.private_key_pem)
}

#[test]
fn state_valid_record_with_matching_certificate_loads() {
    let ca = generated();
    let f = Fixture::new();
    f.store(&ca);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(handshake_succeeds(&loaded, &ca.certificate_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn state_valid_record_restores_missing_certificate() {
    let ca = generated();
    let f = Fixture::new();
    f.store(&ca);
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert!(handshake_succeeds(&loaded, &f.certificate().unwrap()));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn state_valid_record_with_matching_file_legacy_deletes_it_last() {
    let ca = generated();
    let f = Fixture::new();
    f.store(&ca);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn state_valid_record_with_matching_native_legacy_restores_then_deletes() {
    let ca = generated();
    let f = Fixture::new();
    f.store(&ca);
    f.native_legacy(&ca.private_key_pem);
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(f.counts(), (1, 0, 1));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn state_valid_record_with_both_legacy_sources_deletes_both() {
    let ca = generated();
    let f = Fixture::new();
    f.store(&ca);
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    f.native_legacy(&ca.private_key_pem);
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(f.counts(), (1, 0, 1));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn state_absent_record_migrates_matching_file_legacy_pair() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(handshake_succeeds(&loaded, &ca.certificate_pem));
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (2, 1, 0));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));

    let reloaded = f.load().unwrap();
    assert!(same_identity(&reloaded, &ca));
    assert!(handshake_succeeds(&reloaded, &ca.certificate_pem));
    assert_eq!(f.counts(), (3, 1, 0));
}

#[test]
fn state_absent_record_migrates_matching_native_legacy_key() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.native_legacy(&ca.private_key_pem);
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (2, 1, 1));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn state_absent_record_migrates_both_matching_legacy_sources() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    f.native_legacy(&ca.private_key_pem);
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (2, 1, 1));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn state_all_absent_generates_stores_and_publishes() {
    let f = Fixture::new();
    let loaded = f.load().unwrap();
    let stored = decode_record(&f.native.record.borrow().clone().unwrap()).unwrap();
    assert!(same_identity(&loaded, &stored));
    assert_eq!(
        f.certificate().as_deref(),
        Some(stored.certificate_pem.as_str())
    );
    assert!(handshake_succeeds(&loaded, &f.certificate().unwrap()));
    assert_eq!(f.counts(), (2, 1, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn state_certificate_without_key_denies_without_replacing_identity() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    assert_redacted(f.load(), KEY_MISSING);
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(f.artifacts(), present(&["certificate"]));
}

#[test]
fn state_legacy_key_without_certificate_denies_incomplete_identity() {
    let ca = generated();
    let f = Fixture::new();
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    assert_redacted(f.load(), INCOMPLETE);
    assert!(f.file_key_is(&ca.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["file_key"]));

    let f = Fixture::new();
    f.native_legacy(&ca.private_key_pem);
    assert_redacted(f.load(), INCOMPLETE);
    assert!(f.native_legacy_is(&ca.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["native_legacy"]));
}

#[test]
fn state_unavailable_or_ambiguous_native_storage_denies_without_mutation() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    f.fault(Fault::Read);
    assert_redacted(f.load(), UNAVAILABLE);
    assert!(f.file_key_is(&ca.private_key_pem));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "file_key"]));

    let f = Fixture::new();
    f.fault(Fault::Read);
    assert_redacted(f.load(), UNAVAILABLE);
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&[]));
}

#[test]
fn state_corrupt_native_record_denies_without_mutation() {
    let ca = generated();
    let mut corrupt = encoded(&ca);
    corrupt.truncate(corrupt.len() - 1);
    let f = Fixture::new();
    f.store_raw(&corrupt);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    assert_redacted(f.load(), MALFORMED);
    assert!(f.stored_is(&corrupt));
    assert!(f.file_key_is(&ca.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "file_key", "record"])
    );
}

#[test]
fn state_invalid_native_record_denies_without_mutation() {
    let first = generated();
    let second = generated();
    let cases = [
        record(&first.certificate_pem, &second.private_key_pem),
        record(CERTIFICATE, &first.private_key_pem),
        record(&first.certificate_pem, KEY),
    ];
    for case in &cases {
        let f = Fixture::new();
        f.store(case);
        f.native_legacy(&first.private_key_pem);
        assert_redacted(f.load(), INVALID);
        assert!(f.stored_is(&encoded(case)));
        assert!(f.native_legacy_is(&first.private_key_pem));
        assert_eq!(f.counts(), (1, 0, 0));
        assert_eq!(f.artifacts(), present(&["record", "native_legacy"]));
    }
}

#[test]
fn state_native_record_mismatching_certificate_denies_without_mutation() {
    let ca = generated();
    let other = generated();
    let f = Fixture::new();
    f.store(&ca);
    f.put(CERT_FILE, other.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    assert_redacted(f.load(), CERTIFICATE_MISMATCH);
    assert_eq!(
        f.certificate().as_deref(),
        Some(other.certificate_pem.as_str())
    );
    assert!(f.file_key_is(&ca.private_key_pem));
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "file_key", "record"])
    );
}

#[test]
fn state_native_record_mismatching_legacy_key_denies_without_mutation() {
    let ca = generated();
    let other = generated();
    let f = Fixture::new();
    f.store(&ca);
    f.put(KEY_FILE, other.private_key_pem.as_bytes());
    assert_redacted(f.load(), LEGACY_MISMATCH);
    assert!(f.file_key_is(&other.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["file_key", "record"]));

    let f = Fixture::new();
    f.store(&ca);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.native_legacy(&other.private_key_pem);
    assert_redacted(f.load(), LEGACY_MISMATCH);
    assert!(f.native_legacy_is(&other.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "record", "native_legacy"])
    );
}

#[test]
fn state_legacy_key_mismatching_certificate_denies_without_mutation() {
    let ca = generated();
    let other = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, other.private_key_pem.as_bytes());
    assert_redacted(f.load(), LEGACY_MISMATCH);
    assert!(f.file_key_is(&other.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "file_key"]));
}

#[test]
fn state_disagreeing_legacy_sources_deny_without_mutation() {
    let ca = generated();
    let other = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    f.native_legacy(&other.private_key_pem);
    assert_redacted(f.load(), LEGACY_MISMATCH);
    assert!(f.file_key_is(&ca.private_key_pem));
    assert!(f.native_legacy_is(&other.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "file_key", "native_legacy"])
    );
}

#[test]
fn state_non_ca_legacy_pair_denies_without_mutation() {
    let key = KeyPair::generate().unwrap();
    let leaf = certificate_with(IsCa::ExplicitNoCa, &key);
    let f = Fixture::new();
    f.put(CERT_FILE, leaf.as_bytes());
    f.put(KEY_FILE, key.serialize_pem().as_bytes());
    assert_redacted(f.load(), INVALID);
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "file_key"]));
}

#[test]
fn fault_native_write_failure_keeps_legacy_for_retry() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    f.fault(Fault::Write);
    assert_redacted(f.load(), UNAVAILABLE);
    assert!(f.file_key_is(&ca.private_key_pem));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(f.counts(), (1, 1, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "file_key"]));

    f.clear();
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn fault_native_write_failure_on_fresh_state_publishes_nothing() {
    let f = Fixture::new();
    f.fault(Fault::Write);
    assert_redacted(f.load(), UNAVAILABLE);
    assert_eq!(f.counts(), (1, 1, 0));
    assert_eq!(f.artifacts(), present(&[]));

    f.clear();
    assert!(f.load().is_ok());
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn fault_native_readback_failure_keeps_legacy_for_retry() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    f.fault(Fault::Readback);
    assert_redacted(f.load(), UNAVAILABLE);
    assert!(f.file_key_is(&ca.private_key_pem));
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (2, 1, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "file_key", "record"])
    );

    f.clear();
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert_eq!(f.counts(), (3, 1, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn fault_native_readback_failure_on_fresh_state_withholds_certificate() {
    let f = Fixture::new();
    f.fault(Fault::Readback);
    assert_redacted(f.load(), UNAVAILABLE);
    assert_eq!(f.counts(), (2, 1, 0));
    assert_eq!(f.artifacts(), present(&["record"]));

    f.clear();
    let stored = decode_record(&f.native.record.borrow().clone().unwrap()).unwrap();
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &stored));
    assert_eq!(
        f.certificate().as_deref(),
        Some(stored.certificate_pem.as_str())
    );
    assert_eq!(f.counts(), (3, 1, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn fault_native_readback_mismatch_denies_and_keeps_legacy() {
    let ca = generated();
    for fault in [Fault::WriteAltered, Fault::WriteDropped] {
        let f = Fixture::new();
        f.put(CERT_FILE, ca.certificate_pem.as_bytes());
        f.put(KEY_FILE, ca.private_key_pem.as_bytes());
        f.fault(fault);
        assert_redacted(f.load(), READBACK_MISMATCH);
        assert!(f.file_key_is(&ca.private_key_pem));
        assert_eq!(
            f.certificate().as_deref(),
            Some(ca.certificate_pem.as_str())
        );
        assert_eq!(f.counts(), (2, 1, 0));
        let record = fault == Fault::WriteAltered;
        let expected = if record {
            present(&["certificate", "file_key", "record"])
        } else {
            present(&["certificate", "file_key"])
        };
        assert_eq!(f.artifacts(), expected);
    }

    let f = Fixture::new();
    f.fault(Fault::WriteAltered);
    assert_redacted(f.load(), READBACK_MISMATCH);
    assert_eq!(f.artifacts(), present(&["record"]));
}

#[test]
fn fault_public_create_failure_keeps_native_record_for_retry() {
    let f = Fixture::new();
    assert_redacted(
        f.load_failing_at(Step::CertificateCreate),
        PUBLICATION_FAILED,
    );
    assert_eq!(f.counts(), (2, 1, 0));
    assert_eq!(f.artifacts(), present(&["record"]));

    let stored = decode_record(&f.native.record.borrow().clone().unwrap()).unwrap();
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &stored));
    assert_eq!(
        f.certificate().as_deref(),
        Some(stored.certificate_pem.as_str())
    );
    assert_eq!(f.counts(), (3, 1, 0));
}

#[test]
fn fault_public_sync_failure_removes_partial_certificate() {
    let f = Fixture::new();
    assert_redacted(f.load_failing_at(Step::CertificateSync), PUBLICATION_FAILED);
    assert_eq!(f.counts(), (2, 1, 0));
    assert_eq!(f.artifacts(), present(&["record"]));

    let stored = decode_record(&f.native.record.borrow().clone().unwrap()).unwrap();
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &stored));
    assert_eq!(
        f.certificate().as_deref(),
        Some(stored.certificate_pem.as_str())
    );
}

#[test]
fn fault_public_restore_failure_retains_legacy_key() {
    let ca = generated();
    for step in [Step::CertificateCreate, Step::CertificateSync] {
        let f = Fixture::new();
        f.store(&ca);
        f.put(KEY_FILE, ca.private_key_pem.as_bytes());
        f.native_legacy(&ca.private_key_pem);
        assert_redacted(f.load_failing_at(step), PUBLICATION_FAILED);
        assert!(f.file_key_is(&ca.private_key_pem));
        assert!(f.native_legacy_is(&ca.private_key_pem));
        assert_eq!(f.counts(), (1, 0, 0));
        assert_eq!(
            f.artifacts(),
            present(&["file_key", "record", "native_legacy"])
        );

        let loaded = f.load().unwrap();
        assert!(same_identity(&loaded, &ca));
        assert_eq!(f.artifacts(), present(&["certificate", "record"]));
    }
}

#[test]
fn fault_file_legacy_read_failure_denies_without_mutation() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    assert_redacted(f.load_failing_at(Step::LegacyRead), UNAVAILABLE);
    assert!(f.file_key_is(&ca.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "file_key"]));
}

#[test]
fn fault_native_legacy_read_failure_denies_without_mutation() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.native_legacy(&ca.private_key_pem);
    f.fault(Fault::LegacyRead);
    assert_redacted(f.load(), UNAVAILABLE);
    assert!(f.native_legacy_is(&ca.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "native_legacy"]));
}

#[test]
fn fault_file_legacy_delete_failure_retains_record_and_key_for_retry() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    f.native_legacy(&ca.private_key_pem);
    assert_redacted(f.load_failing_at(Step::LegacyDelete), REMOVAL_FAILED);
    assert!(f.file_key_is(&ca.private_key_pem));
    assert!(f.native_legacy_is(&ca.private_key_pem));
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (2, 1, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "file_key", "record", "native_legacy"])
    );

    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert_eq!(f.counts(), (3, 1, 1));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn fault_native_legacy_delete_failure_retains_record_and_key_for_retry() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.native_legacy(&ca.private_key_pem);
    f.fault(Fault::Delete);
    assert_redacted(f.load(), REMOVAL_FAILED);
    assert!(f.native_legacy_is(&ca.private_key_pem));
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (2, 1, 1));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "record", "native_legacy"])
    );

    f.clear();
    let loaded = f.load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert_eq!(f.counts(), (3, 1, 2));
    assert_eq!(f.artifacts(), present(&["certificate", "record"]));
}

#[test]
fn fault_corrupt_legacy_key_pem_denies_without_mutation() {
    let ca = generated();
    let corrupt: [&[u8]; 3] = [KEY.as_bytes(), b"not pem", &[0xff, 0xfe, 0x00]];
    for bytes in corrupt {
        let f = Fixture::new();
        f.put(CERT_FILE, ca.certificate_pem.as_bytes());
        f.put(KEY_FILE, bytes);
        assert_redacted(f.load(), LEGACY_INVALID);
        assert!(f.read(KEY_FILE).as_deref() == Some(bytes));
        assert_eq!(f.counts(), (1, 0, 0));
        assert_eq!(f.artifacts(), present(&["certificate", "file_key"]));
    }

    let f = Fixture::new();
    f.store(&ca);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.native_legacy(KEY);
    assert_redacted(f.load(), LEGACY_INVALID);
    assert!(f.native_legacy_is(KEY));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "record", "native_legacy"])
    );
}

#[test]
fn fault_corrupt_certificate_pem_denies_without_mutation() {
    let ca = generated();
    let corrupt: [&[u8]; 3] = [CERTIFICATE.as_bytes(), b"not pem", &[0xff, 0xfe, 0x00]];
    for bytes in corrupt {
        let f = Fixture::new();
        f.store(&ca);
        f.put(CERT_FILE, bytes);
        assert_redacted(f.load(), CERTIFICATE_INVALID);
        assert!(f.read(CERT_FILE).as_deref() == Some(bytes));
        assert_eq!(f.counts(), (1, 0, 0));
        assert_eq!(f.artifacts(), present(&["certificate", "record"]));

        let f = Fixture::new();
        f.put(CERT_FILE, bytes);
        f.put(KEY_FILE, ca.private_key_pem.as_bytes());
        assert_redacted(f.load(), CERTIFICATE_INVALID);
        assert!(f.file_key_is(&ca.private_key_pem));
        assert_eq!(f.counts(), (1, 0, 0));
        assert_eq!(f.artifacts(), present(&["certificate", "file_key"]));
    }
}

#[test]
fn lock_contention_denies_second_lock() {
    let f = Fixture::new();
    let held = lock_directory(&f.dir).unwrap();
    assert_redacted(lock_directory(&f.dir), BUSY);
    assert_redacted(f.load(), BUSY);
    assert_redacted(f.platform_load(), BUSY);
    assert!(f.native.log.borrow().is_empty());
    assert_eq!(f.counts(), (0, 0, 0));
    assert_eq!(f.artifacts(), present(&[]));
    drop(held);
    assert!(lock_directory(&f.dir).is_ok());
}

#[test]
fn lock_creates_directory_and_keeps_lock_file() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("nested").join("ca");
    let held = lock_directory(&dir).unwrap();
    assert!(dir.join(LOCK_FILE).is_file());
    drop(held);
    assert!(dir.join(LOCK_FILE).is_file());
    assert!(lock_directory(&dir).is_ok());
    assert!(dir.join(LOCK_FILE).is_file());
}

#[test]
fn lock_does_not_truncate_existing_lock_file() {
    let f = Fixture::new();
    f.put(LOCK_FILE, b"held");
    let held = lock_directory(&f.dir).unwrap();
    assert_eq!(io::read_to_string(&held).unwrap(), "held");
    drop(held);
    assert_eq!(f.read(LOCK_FILE).as_deref(), Some(b"held".as_slice()));
}

#[test]
fn lock_rejects_non_regular_storage_paths() {
    for name in [LOCK_FILE, ID_FILE, KEY_FILE, CERT_FILE] {
        let f = Fixture::new();
        fs::create_dir(f.path(name)).unwrap();
        assert_redacted(lock_directory(&f.dir), PATH_INVALID);
        assert!(f.path(name).is_dir());
    }
}

#[cfg(unix)]
#[test]
fn lock_rejects_symlinked_storage_paths() {
    for name in [LOCK_FILE, ID_FILE, KEY_FILE, CERT_FILE] {
        let f = Fixture::new();
        let target = f._root.path().join("target");
        fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, f.path(name)).unwrap();
        assert_redacted(lock_directory(&f.dir), PATH_INVALID);
        assert_redacted(f.platform_load(), PATH_INVALID);
        assert_eq!(fs::read(&target).unwrap(), b"target");
        assert!(f.native.log.borrow().is_empty());
    }
}

pub(super) const ACCOUNT: &str = "0123456789abcdef0123456789abcdef";
const OTHER_ACCOUNT: &str = "fedcba9876543210fedcba9876543210";

fn failing_at(step: Step) -> impl FnMut(Step) -> io::Result<()> {
    move |current| {
        if current == step {
            Err(io::Error::other(SENTINEL))
        } else {
            Ok(())
        }
    }
}

#[test]
fn account_is_generated_in_memory_and_persisted_once() {
    let f = Fixture::new();
    let _lock = lock_directory(&f.dir).unwrap();
    let account = storage_account(&f.dir, true).unwrap();
    assert_eq!(account.len(), 32);
    assert!(
        account
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(f.artifacts(), present(&[]));
    assert_ne!(storage_account(&f.dir, true).unwrap(), account);

    persist_account(&f.dir, &account, &mut |_| Ok(())).unwrap();
    assert_eq!(f.account().as_deref(), Some(account.as_str()));
    assert_eq!(storage_account(&f.dir, false).unwrap(), account);
    assert_eq!(storage_account(&f.dir, true).unwrap(), account);
}

#[test]
fn account_persist_create_failure_leaves_no_identity() {
    let f = Fixture::new();
    let _lock = lock_directory(&f.dir).unwrap();
    let mut fault = failing_at(Step::IdentityCreate);
    assert_redacted(persist_account(&f.dir, ACCOUNT, &mut fault), UNAVAILABLE);
    assert_eq!(f.artifacts(), present(&[]));
}

#[test]
fn account_persist_refuses_existing_identity_file() {
    let f = Fixture::new();
    f.put(ID_FILE, OTHER_ACCOUNT.as_bytes());
    let _lock = lock_directory(&f.dir).unwrap();
    assert_redacted(
        persist_account(&f.dir, ACCOUNT, &mut |_| Ok(())),
        UNAVAILABLE,
    );
    assert_eq!(f.account().as_deref(), Some(OTHER_ACCOUNT));
    assert_eq!(f.artifacts(), present(&["identity"]));
}

#[test]
fn account_persist_sync_failure_removes_identity() {
    let f = Fixture::new();
    let _lock = lock_directory(&f.dir).unwrap();
    let mut fault = failing_at(Step::IdentitySync);
    assert_redacted(persist_account(&f.dir, ACCOUNT, &mut fault), UNAVAILABLE);
    assert_eq!(f.artifacts(), present(&[]));
}

#[test]
fn account_persist_verification_mismatch_removes_identity() {
    let f = Fixture::new();
    let _lock = lock_directory(&f.dir).unwrap();
    let path = f.path(ID_FILE);
    let mut tamper = |step: Step| -> io::Result<()> {
        if step == Step::IdentitySync {
            fs::write(&path, OTHER_ACCOUNT)?;
        }
        Ok(())
    };
    assert_redacted(persist_account(&f.dir, ACCOUNT, &mut tamper), UNAVAILABLE);
    assert_eq!(f.artifacts(), present(&[]));
}

#[test]
fn account_missing_without_recovery_source_denies() {
    let f = Fixture::new();
    let _lock = lock_directory(&f.dir).unwrap();
    assert_redacted(storage_account(&f.dir, false), IDENTITY_MISSING);
    assert_eq!(f.artifacts(), present(&[]));
}

#[test]
fn account_malformed_denies_without_replacement() {
    let upper = "A".repeat(32);
    let short = "a".repeat(31);
    let long = "a".repeat(33);
    let newline = format!("{}\n", "a".repeat(32));
    let non_hex = "g".repeat(32);
    let spaced = format!(" {}", "a".repeat(31));
    for contents in [
        "",
        upper.as_str(),
        short.as_str(),
        long.as_str(),
        newline.as_str(),
        non_hex.as_str(),
        spaced.as_str(),
    ] {
        for recovery in [false, true] {
            let f = Fixture::new();
            f.put(ID_FILE, contents.as_bytes());
            let _lock = lock_directory(&f.dir).unwrap();
            assert_redacted(storage_account(&f.dir, recovery), IDENTITY_MALFORMED);
            assert_eq!(f.account().as_deref(), Some(contents));
        }
    }
}

#[test]
fn load_certificate_without_identity_or_legacy_denies_before_account() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    assert_redacted(f.platform_load(), IDENTITY_MISSING);
    assert_eq!(*f.native.log.borrow(), vec!["legacy"]);
    assert_eq!(f.counts(), (0, 0, 0));
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(f.artifacts(), present(&["certificate"]));
}

#[test]
fn load_native_legacy_key_only_item_migrates() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.native_legacy(&ca.private_key_pem);
    let loaded = f.platform_load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(handshake_succeeds(&loaded, &ca.certificate_pem));
    let account = f.account().unwrap();
    assert!(
        f.native
            .accounts
            .borrow()
            .iter()
            .all(|seen| *seen == account)
    );
    assert_eq!(f.native.log.borrow()[..2], ["legacy", "record"]);
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (2, 1, 1));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record"])
    );
}

#[test]
fn load_file_legacy_key_migrates_with_new_identity() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    let loaded = f.platform_load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (2, 1, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record"])
    );

    let reloaded = f.platform_load().unwrap();
    assert!(same_identity(&reloaded, &ca));
    assert!(handshake_succeeds(&reloaded, &ca.certificate_pem));
    assert_eq!(f.counts(), (3, 1, 0));
}

#[test]
fn load_all_absent_generates_identity_record_and_certificate() {
    let f = Fixture::new();
    let loaded = f.platform_load().unwrap();
    let account = f.account().unwrap();
    assert!(
        f.native
            .accounts
            .borrow()
            .iter()
            .all(|seen| *seen == account)
    );
    let stored = decode_record(&f.native.record.borrow().clone().unwrap()).unwrap();
    assert!(same_identity(&loaded, &stored));
    assert_eq!(
        f.certificate().as_deref(),
        Some(stored.certificate_pem.as_str())
    );
    assert_eq!(f.counts(), (2, 1, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record"])
    );

    let reloaded = f.platform_load().unwrap();
    assert!(same_identity(&reloaded, &stored));
    assert_eq!(f.account(), Some(account));
    assert_eq!(f.counts(), (3, 1, 0));
}

#[test]
fn load_legacy_key_without_certificate_denies_before_account() {
    let ca = generated();
    let f = Fixture::new();
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    assert_redacted(f.platform_load(), INCOMPLETE);
    assert!(f.file_key_is(&ca.private_key_pem));
    assert_eq!(f.counts(), (0, 0, 0));
    assert_eq!(f.artifacts(), present(&["file_key"]));

    let f = Fixture::new();
    f.native_legacy(&ca.private_key_pem);
    assert_redacted(f.platform_load(), INCOMPLETE);
    assert!(f.native_legacy_is(&ca.private_key_pem));
    assert_eq!(f.counts(), (0, 0, 0));
    assert_eq!(f.artifacts(), present(&["native_legacy"]));
}

#[test]
fn load_existing_identity_with_certificate_only_denies() {
    let ca = generated();
    let f = Fixture::new();
    f.put(ID_FILE, "0123456789abcdef0123456789abcdef".as_bytes());
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    assert_redacted(f.platform_load(), KEY_MISSING);
    assert_eq!(
        *f.native.accounts.borrow(),
        vec!["0123456789abcdef0123456789abcdef".to_owned()]
    );
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "identity"]));
}

#[test]
fn load_malformed_identity_denies_before_native_read() {
    let ca = generated();
    let f = Fixture::new();
    f.put(ID_FILE, b"not-an-account");
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    assert_redacted(f.platform_load(), IDENTITY_MALFORMED);
    assert_eq!(f.counts(), (0, 0, 0));
    assert_eq!(f.account().as_deref(), Some("not-an-account"));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "file_key", "identity"])
    );
}

#[test]
fn load_native_legacy_read_failure_denies_before_account() {
    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.native_legacy(&ca.private_key_pem);
    f.fault(Fault::LegacyRead);
    assert_redacted(f.platform_load(), UNAVAILABLE);
    assert_eq!(*f.native.log.borrow(), vec!["legacy"]);
    assert_eq!(f.counts(), (0, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "native_legacy"]));
}

#[test]
fn load_unavailable_native_storage_leaves_no_identity() {
    let f = Fixture::new();
    f.fault(Fault::Read);
    assert_redacted(f.platform_load(), UNAVAILABLE);
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&[]));

    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    f.fault(Fault::Read);
    assert_redacted(f.platform_load(), UNAVAILABLE);
    assert!(f.file_key_is(&ca.private_key_pem));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "file_key"]));

    f.clear();
    let loaded = f.platform_load().unwrap();
    assert!(same_identity(&loaded, &ca));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record"])
    );
}

#[test]
fn load_new_identity_with_existing_native_record_denies_without_identity() {
    let ca = generated();
    let f = Fixture::new();
    f.store(&ca);
    assert_redacted(f.platform_load(), UNAVAILABLE);
    assert!(f.stored_is(&encoded(&ca)));
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["record"]));
}

#[test]
fn load_invalid_legacy_pair_without_identity_denies_before_identity() {
    let ca = generated();
    let other = generated();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = certificate_with(IsCa::ExplicitNoCa, &leaf_key);
    let leaf_key_pem = leaf_key.serialize_pem();
    let doubled = format!(
        "{}{}",
        ca.private_key_pem.as_str(),
        ca.private_key_pem.as_str()
    );
    let padded = format!("{}{}", ca.private_key_pem.as_str(), "\n".repeat(2000));
    let cases = [
        (
            ca.certificate_pem.as_str(),
            other.private_key_pem.as_str(),
            LEGACY_MISMATCH,
        ),
        (ca.certificate_pem.as_str(), KEY, LEGACY_INVALID),
        (leaf.as_str(), leaf_key_pem.as_str(), INVALID),
        (ca.certificate_pem.as_str(), doubled.as_str(), MALFORMED),
        (ca.certificate_pem.as_str(), padded.as_str(), MALFORMED),
    ];
    for (certificate, key, message) in cases {
        let f = Fixture::new();
        f.put(CERT_FILE, certificate.as_bytes());
        f.put(KEY_FILE, key.as_bytes());
        assert_redacted(f.platform_load(), message);
        assert!(f.file_key_is(key));
        assert_eq!(f.certificate().as_deref(), Some(certificate));
        assert_eq!(f.counts(), (0, 0, 0));
        assert_eq!(f.artifacts(), present(&["certificate", "file_key"]));

        let f = Fixture::new();
        f.put(CERT_FILE, certificate.as_bytes());
        f.native_legacy(key);
        assert_redacted(f.platform_load(), message);
        assert!(f.native_legacy_is(key));
        assert_eq!(f.counts(), (0, 0, 0));
        assert_eq!(f.artifacts(), present(&["certificate", "native_legacy"]));
    }
}

#[test]
fn load_persists_identity_only_after_native_absence_is_confirmed() {
    let f = Fixture::new();
    let seen = RefCell::new(Vec::new());
    let result = load_with(
        &f.dir,
        || Ok(None),
        |account| {
            seen.borrow_mut()
                .push(("read", f.account().as_deref() == Some(account)));
            f.native.read_record(account)
        },
        |account, bytes| {
            seen.borrow_mut()
                .push(("write", f.account().as_deref() == Some(account)));
            f.native.write_record(account, bytes)
        },
        || Ok(()),
    );
    assert!(result.is_ok());
    assert_eq!(
        *seen.borrow(),
        vec![("read", false), ("write", true), ("read", true)]
    );
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record"])
    );
}

#[test]
fn load_holds_lock_through_transition() {
    let f = Fixture::new();
    let contended = Cell::new(0);
    let result = load_with(
        &f.dir,
        || {
            if lock_directory(&f.dir).is_err() {
                contended.set(contended.get() + 1);
            }
            Ok(None)
        },
        |account| f.native.read_record(account),
        |account, bytes| {
            assert_redacted(lock_directory(&f.dir), BUSY);
            f.native.write_record(account, bytes)
        },
        || Ok(()),
    );
    assert!(result.is_ok());
    assert_eq!(contended.get(), 3);
    assert!(lock_directory(&f.dir).is_ok());
}

fn retirable(ca: &CaRecord) -> Fixture {
    let f = Fixture::new();
    f.store(ca);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(ID_FILE, ACCOUNT.as_bytes());
    f
}

#[test]
fn retire_deletes_the_validated_record_then_the_files() {
    let f = retirable(&generated());
    assert!(f.retire().is_ok());
    assert_eq!(f.artifacts(), present(&[]));
    assert_eq!(f.counts(), (2, 0, 1));
    assert_eq!(
        *f.native.log.borrow(),
        ["legacy", "record", "delete", "record"]
    );
    assert!(
        f.native
            .accounts
            .borrow()
            .iter()
            .all(|account| account == ACCOUNT)
    );
    assert!(f.path(LOCK_FILE).is_file());
    assert_redacted(f.retire(), IDENTITY_MISSING);
}

#[test]
fn retire_without_a_certificate_deletes_the_record_and_identity() {
    let ca = generated();
    let f = Fixture::new();
    f.store(&ca);
    f.put(ID_FILE, ACCOUNT.as_bytes());
    assert!(f.retire().is_ok());
    assert_eq!(f.artifacts(), present(&[]));
}

#[test]
fn retire_denies_a_mismatched_certificate_without_mutation() {
    let f = retirable(&generated());
    let other = generated();
    f.put(CERT_FILE, other.certificate_pem.as_bytes());
    assert_redacted(f.retire(), CERTIFICATE_MISMATCH);
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.certificate().as_deref(),
        Some(other.certificate_pem.as_str())
    );
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record"])
    );

    f.put(CERT_FILE, CERTIFICATE.as_bytes());
    assert_redacted(f.retire(), CERTIFICATE_INVALID);
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record"])
    );
}

#[test]
fn retire_denies_while_a_legacy_copy_exists() {
    let ca = generated();
    let f = retirable(&ca);
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    assert_redacted(f.retire(), MIGRATION_INCOMPLETE);
    assert_eq!(f.counts(), (0, 0, 0));
    assert!(f.file_key_is(&ca.private_key_pem));

    let f = retirable(&ca);
    f.native_legacy(&ca.private_key_pem);
    assert_redacted(f.retire(), MIGRATION_INCOMPLETE);
    assert_eq!(f.counts(), (0, 0, 0));
    assert!(f.native_legacy_is(&ca.private_key_pem));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record", "native_legacy"])
    );

    let f = retirable(&ca);
    f.fault(Fault::LegacyRead);
    assert_redacted(f.retire(), UNAVAILABLE);
    assert_eq!(f.counts(), (0, 0, 0));
}

#[test]
fn retire_denies_a_missing_directory_identity_or_record_without_mutation() {
    let root = tempfile::tempdir().unwrap();
    let absent = root.path().join("absent");
    assert_redacted(
        retire_with(
            &absent,
            || Ok(None),
            |_| panic!("read"),
            |_| panic!("delete"),
        ),
        IDENTITY_MISSING,
    );
    assert!(!absent.exists());

    let file = root.path().join("file");
    fs::write(&file, b"").unwrap();
    assert_redacted(
        retire_with(&file, || Ok(None), |_| panic!("read"), |_| panic!("delete")),
        PATH_INVALID,
    );

    let ca = generated();
    let f = Fixture::new();
    f.store(&ca);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    assert_redacted(f.retire(), IDENTITY_MISSING);
    assert_eq!(f.counts(), (0, 0, 0));

    f.put(ID_FILE, b"not-an-account");
    assert_redacted(f.retire(), IDENTITY_MALFORMED);
    assert_eq!(f.counts(), (0, 0, 0));

    let f = retirable(&ca);
    *f.native.record.borrow_mut() = None;
    assert_redacted(f.retire(), KEY_MISSING);
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(f.artifacts(), present(&["certificate", "identity"]));
}

#[test]
fn retire_never_deletes_a_record_it_cannot_validate() {
    let f = retirable(&generated());
    f.store_raw(b"ZSCA");
    assert_redacted(f.retire(), MALFORMED);
    assert_eq!(f.counts(), (1, 0, 0));
    assert!(f.stored_is(b"ZSCA"));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record"])
    );

    let f = retirable(&generated());
    f.fault(Fault::Read);
    assert_redacted(f.retire(), UNAVAILABLE);
    assert_eq!(f.counts(), (1, 0, 0));
    assert_eq!(
        f.artifacts(),
        present(&["certificate", "identity", "record"])
    );
}

#[test]
fn retire_keeps_the_files_until_the_record_reads_absent() {
    for fault in [Fault::Delete, Fault::DeleteIgnored] {
        let ca = generated();
        let f = retirable(&ca);
        f.fault(fault);
        assert_redacted(f.retire(), RECORD_REMOVAL_FAILED);
        assert!(f.stored_is(&encoded(&ca)));
        assert_eq!(
            f.artifacts(),
            present(&["certificate", "identity", "record"])
        );
        f.clear();
        assert!(f.retire().is_ok());
        assert_eq!(f.artifacts(), present(&[]));
    }

    let f = retirable(&generated());
    f.fault(Fault::Readback);
    assert_redacted(f.retire(), RECORD_REMOVAL_FAILED);
    assert_eq!(f.artifacts(), present(&["certificate", "identity"]));
    f.clear();
    assert_redacted(f.retire(), KEY_MISSING);
    assert_eq!(f.artifacts(), present(&["certificate", "identity"]));
}

#[cfg(unix)]
#[test]
fn retire_reports_a_failed_cleanup_after_the_record_is_gone() {
    use std::os::unix::fs::PermissionsExt;
    let f = retirable(&generated());
    drop(lock_directory(&f.dir).unwrap());
    fs::set_permissions(&f.dir, fs::Permissions::from_mode(0o555)).unwrap();
    let result = f.retire();
    fs::set_permissions(&f.dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert_redacted(result, CLEANUP_FAILED);
    assert_eq!(f.artifacts(), present(&["certificate", "identity"]));
    assert_eq!(f.counts(), (2, 0, 1));
}

#[test]
fn retire_holds_the_directory_lock() {
    let f = retirable(&generated());
    let held = lock_directory(&f.dir).unwrap();
    assert_redacted(f.retire(), BUSY);
    assert_eq!(f.counts(), (0, 0, 0));
    drop(held);

    let contended = Cell::new(0);
    let result = retire_with(
        &f.dir,
        || Ok(None),
        |account| {
            if lock_directory(&f.dir).is_err() {
                contended.set(contended.get() + 1);
            }
            f.native.read_record(account)
        },
        |account| {
            assert_redacted(lock_directory(&f.dir), BUSY);
            f.native.delete_record(account)
        },
    );
    assert!(result.is_ok());
    assert_eq!(contended.get(), 2);
    assert!(lock_directory(&f.dir).is_ok());
}
