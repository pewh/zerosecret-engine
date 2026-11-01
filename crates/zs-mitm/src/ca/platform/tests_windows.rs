#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rand::RngCore;
use rand::rngs::OsRng;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_FLAGS, ERROR_NO_SUCH_LOGON_SESSION, ERROR_NOT_FOUND,
    GetLastError,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_PERSIST, CRED_PERSIST_ENTERPRISE,
    CRED_PERSIST_LOCAL_MACHINE, CRED_PERSIST_NONE, CRED_PERSIST_SESSION, CRED_TYPE_DOMAIN_PASSWORD,
    CRED_TYPE_GENERIC, CRED_TYPE_GENERIC_CERTIFICATE, CREDENTIALW, CredDeleteW, CredWriteW,
};

use super::record::MAX_RECORD_LEN;
use super::state::lock_directory;
use super::tests::{
    ACCOUNT, BUSY, CERT_FILE, Fixture, ID_FILE, KEY_FILE, KEY_MISSING, MALFORMED, UNAVAILABLE,
    assert_redacted, encoded, generated, handshake_succeeds, same_identity,
};
use super::windows::{
    Credential, Metadata, absence, blob_len, delete_record, read_record, target, write_new,
};
use super::{load, retire};

const ROLE: &str = "ZS_NATIVE_CA_ROLE";
const CHILD_DIR: &str = "ZS_NATIVE_CA_DIR";
const LOCKED: &str = "locked";
const RELOAD: &str = "reload";

fn random_hex() -> String {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn blob_size(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).unwrap()
}

fn record_limit() -> u32 {
    u32::try_from(MAX_RECORD_LEN).unwrap()
}

fn seen(account: &str) -> Option<Metadata> {
    Credential::read(account)
        .unwrap()
        .map(|credential| credential.metadata(account))
}

fn assert_machine_local(stored: &Metadata, size: u32) {
    assert_eq!(
        (stored.kind, stored.persist, stored.size, stored.attributes),
        (CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE, size, 0)
    );
    assert!(stored.exact_target);
}

fn plant(account: &str, persist: CRED_PERSIST, bytes: &[u8]) -> bool {
    let mut target = target(account);
    let mut blob = bytes.to_vec();
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: blob_size(&blob),
        CredentialBlob: blob.as_mut_ptr(),
        Persist: persist,
        ..CREDENTIALW::default()
    };
    unsafe { CredWriteW(&credential, 0) != 0 }
}

fn delete_exact(account: &str) -> bool {
    let target = target(account);
    unsafe {
        CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) != 0 || GetLastError() == ERROR_NOT_FOUND
    }
}

fn files(f: &Fixture) -> Vec<&'static str> {
    [CERT_FILE, KEY_FILE, ID_FILE]
        .into_iter()
        .filter(|name| f.path(name).exists())
        .collect()
}

enum Owner {
    Account(String),
    Directory(PathBuf),
}

struct Cleanup(Owner);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let account = match &self.0 {
            Owner::Account(account) => Some(account.clone()),
            Owner::Directory(dir) => fs::read_to_string(dir.join(ID_FILE)).ok(),
        };
        let Some(account) = account else {
            return;
        };
        let clean = delete_exact(&account) && matches!(Credential::read(&account), Ok(None));
        if !clean && !std::thread::panicking() {
            panic!("native CA fixture cleanup failed");
        }
    }
}

fn test_path(function: &str) -> String {
    let module = module_path!();
    let module = module.split_once("::").map_or(module, |(_, rest)| rest);
    format!("{module}::{function}")
}

fn run_child(function: &str, role: &str, dir: &Path) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            test_path(function).as_str(),
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env(ROLE, role)
        .env(CHILD_DIR, dir)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{role} child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn with_children(function: &str, body: fn(&str)) {
    let Some(role) = std::env::var_os(ROLE) else {
        return body(function);
    };
    let dir = PathBuf::from(std::env::var_os(CHILD_DIR).unwrap());
    let account = fs::read_to_string(dir.join(ID_FILE)).unwrap();
    assert!(read_record(&account).unwrap().is_some());
    match role.to_str() {
        Some(LOCKED) => {
            assert_redacted(lock_directory(&dir), BUSY);
            assert_redacted(load(&dir), BUSY);
        }
        Some(RELOAD) => {
            let certificate = fs::read_to_string(dir.join(CERT_FILE)).unwrap();
            let loaded = load(&dir).unwrap();
            assert!(handshake_succeeds(&loaded, &certificate));
        }
        _ => panic!("unexpected native test role"),
    }
}

#[test]
fn windows_adapter_uses_exact_target() {
    let expected: Vec<u16> = "zerosecret.ca.v1/0123456789abcdef0123456789abcdef"
        .encode_utf16()
        .chain([0])
        .collect();
    let target = target(ACCOUNT);
    assert_eq!(target, expected);
    assert_eq!(target.iter().filter(|unit| **unit == 0).count(), 1);
    assert!(target.len() <= usize::try_from(CRED_MAX_GENERIC_TARGET_NAME_LENGTH).unwrap());
}

#[test]
fn windows_adapter_only_not_found_is_absence() {
    assert!(matches!(absence::<()>(ERROR_NOT_FOUND), Ok(None)));
    for error in [
        0,
        ERROR_ACCESS_DENIED,
        ERROR_INVALID_FLAGS,
        ERROR_NO_SUCH_LOGON_SESSION,
        ERROR_NOT_FOUND + 1,
        u32::MAX,
    ] {
        assert_redacted(absence::<()>(error), UNAVAILABLE);
    }
}

#[test]
fn windows_adapter_validates_credential_metadata() {
    let limit = record_limit();
    let valid = |size| blob_len(CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE, true, size);
    assert_eq!(valid(1).unwrap(), 1);
    assert_eq!(valid(limit).unwrap(), MAX_RECORD_LEN);
    for size in [0, limit + 1, u32::MAX] {
        assert_redacted(valid(size), UNAVAILABLE);
    }
    for kind in [
        0,
        CRED_TYPE_DOMAIN_PASSWORD,
        CRED_TYPE_GENERIC_CERTIFICATE,
        u32::MAX,
    ] {
        assert_redacted(
            blob_len(kind, CRED_PERSIST_LOCAL_MACHINE, true, 1),
            UNAVAILABLE,
        );
    }
    for persist in [
        CRED_PERSIST_NONE,
        CRED_PERSIST_SESSION,
        CRED_PERSIST_ENTERPRISE,
        u32::MAX,
    ] {
        assert_redacted(blob_len(CRED_TYPE_GENERIC, persist, true, 1), UNAVAILABLE);
    }
    for size in [1, limit] {
        assert_redacted(
            blob_len(CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE, false, size),
            UNAVAILABLE,
        );
    }
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_round_trip() {
    let account = random_hex();
    let _cleanup = Cleanup(Owner::Account(account.clone()));
    assert!(read_record(&account).unwrap().is_none());
    let bytes = encoded(&generated());
    write_new(&account, &bytes).unwrap();
    let stored = read_record(&account).unwrap().unwrap();
    assert!(stored.0.as_slice() == bytes.as_slice());
    let written = seen(&account).unwrap();
    assert_machine_local(&written, blob_size(&bytes));

    let mut other = bytes.clone();
    other[0] ^= 1;
    assert_redacted(write_new(&account, &bytes), UNAVAILABLE);
    assert_redacted(write_new(&account, &other), UNAVAILABLE);
    assert_eq!(seen(&account).as_ref(), Some(&written));
    let again = read_record(&account).unwrap().unwrap();
    assert!(again.0.as_slice() == bytes.as_slice());
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_missing() {
    let account = random_hex();
    let sibling = random_hex();
    let _cleanup = Cleanup(Owner::Account(sibling.clone()));
    write_new(&sibling, &encoded(&generated())).unwrap();
    assert!(read_record(&sibling).unwrap().is_some());
    assert!(read_record(&account).unwrap().is_none());
    assert!(seen(&account).is_none());
    assert!(seen(&sibling).is_some());
}

fn assert_boundary_absent(account: &str) {
    assert!(
        matches!(read_record(account), Ok(None)),
        "maximum-length target was not reported as absent"
    );
}

fn assert_read_failure(account: &str) {
    let result = read_record(account);
    assert!(
        !matches!(result, Ok(None)),
        "over-long target read was reported as absent"
    );
    assert!(
        !matches!(result, Ok(Some(_))),
        "over-long target read succeeded"
    );
    assert_redacted(result, UNAVAILABLE);
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_read_failure_is_not_absence() {
    // Real Windows counts the terminating NUL in this limit; Wine enforces neither boundary.
    let limit = usize::try_from(CRED_MAX_GENERIC_TARGET_NAME_LENGTH).unwrap();
    let mut boundary = random_hex();
    boundary.push_str(&"a".repeat(limit - target(&boundary).len()));
    let over = format!("{boundary}a");
    assert_eq!(target(&boundary).len(), limit);
    assert_eq!(target(&over).len(), limit + 1);
    let _cleanup = Cleanup(Owner::Account(boundary.clone()));
    assert_boundary_absent(&boundary);

    assert_read_failure(&over);
    assert_redacted(write_new(&over, &encoded(&generated())), UNAVAILABLE);
    assert_read_failure(&over);
    assert_boundary_absent(&boundary);
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_invalid_metadata_denies_without_mutation() {
    let ca = generated();
    let bytes = encoded(&ca);
    for persist in [CRED_PERSIST_SESSION, CRED_PERSIST_ENTERPRISE] {
        let account = random_hex();
        let _cleanup = Cleanup(Owner::Account(account.clone()));
        assert!(plant(&account, persist, &bytes));
        let planted = seen(&account).unwrap();
        assert_eq!(
            (planted.kind, planted.persist, planted.size),
            (CRED_TYPE_GENERIC, persist, blob_size(&bytes))
        );

        assert_redacted(read_record(&account), UNAVAILABLE);
        assert_redacted(write_new(&account, &bytes), UNAVAILABLE);
        let f = Fixture::new();
        f.put(ID_FILE, account.as_bytes());
        f.put(CERT_FILE, ca.certificate_pem.as_bytes());
        assert_redacted(load(&f.dir), UNAVAILABLE);
        assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
        assert_eq!(
            f.certificate().as_deref(),
            Some(ca.certificate_pem.as_str())
        );
        assert_eq!(seen(&account).as_ref(), Some(&planted));
    }
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_machine_local_persistence() {
    with_children(
        "native_ca_windows_machine_local_persistence",
        machine_local_persistence,
    );
}

fn machine_local_persistence(function: &str) {
    let f = Fixture::new();
    let _cleanup = Cleanup(Owner::Directory(f.dir.clone()));
    let created = load(&f.dir).unwrap();
    let account = f.account().unwrap();
    let stored = seen(&account).unwrap();
    let size = blob_size(&read_record(&account).unwrap().unwrap().0);
    assert_machine_local(&stored, size);

    run_child(function, RELOAD, &f.dir);
    assert_eq!(seen(&account).as_ref(), Some(&stored));
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    let reloaded = load(&f.dir).unwrap();
    assert!(reloaded.public_key_der() == created.public_key_der());
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_oversized_record() {
    let limit = random_hex();
    let oversized = random_hex();
    let empty = random_hex();
    let _cleanup =
        [&limit, &oversized, &empty].map(|account| Cleanup(Owner::Account(account.clone())));
    let too_long = [b'Z'; MAX_RECORD_LEN + 1];
    assert_redacted(write_new(&oversized, &too_long), UNAVAILABLE);
    assert_redacted(write_new(&empty, &[]), UNAVAILABLE);
    assert!(seen(&oversized).is_none());
    assert!(seen(&empty).is_none());
    assert!(!plant(&oversized, CRED_PERSIST_LOCAL_MACHINE, &too_long));
    assert!(seen(&oversized).is_none());

    write_new(&limit, &[b'Z'; MAX_RECORD_LEN]).unwrap();
    assert_eq!(
        read_record(&limit).unwrap().unwrap().0.len(),
        MAX_RECORD_LEN
    );
    assert_machine_local(&seen(&limit).unwrap(), record_limit());

    assert!(plant(&empty, CRED_PERSIST_LOCAL_MACHINE, &[]));
    let planted = seen(&empty).unwrap();
    assert_machine_local(&planted, 0);
    assert_redacted(read_record(&empty), UNAVAILABLE);
    assert_redacted(write_new(&empty, b"Z"), UNAVAILABLE);
    assert_eq!(seen(&empty).as_ref(), Some(&planted));
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_malformed_record_denies_without_mutation() {
    let account = random_hex();
    let _cleanup = Cleanup(Owner::Account(account.clone()));
    let ca = generated();
    let mut bytes = encoded(&ca);
    bytes[0] ^= 1;
    write_new(&account, &bytes).unwrap();
    let planted = seen(&account).unwrap();
    let f = Fixture::new();
    f.put(ID_FILE, account.as_bytes());
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    assert_redacted(load(&f.dir), MALFORMED);
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(seen(&account).as_ref(), Some(&planted));
    let stored = read_record(&account).unwrap().unwrap();
    assert!(stored.0.as_slice() == bytes.as_slice());
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_migration() {
    let ca = generated();
    let f = Fixture::new();
    let _cleanup = Cleanup(Owner::Directory(f.dir.clone()));
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    let migrated = load(&f.dir).unwrap();
    assert!(same_identity(&migrated, &ca));
    assert!(handshake_succeeds(&migrated, &ca.certificate_pem));
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    let account = f.account().unwrap();
    let bytes = encoded(&ca);
    let stored = read_record(&account).unwrap().unwrap();
    assert!(stored.0.as_slice() == bytes.as_slice());
    let written = seen(&account).unwrap();
    assert_machine_local(&written, blob_size(&bytes));

    let reloaded = load(&f.dir).unwrap();
    assert!(same_identity(&reloaded, &ca));
    assert!(handshake_succeeds(&reloaded, &ca.certificate_pem));
    assert_eq!(f.account(), Some(account.clone()));
    assert_eq!(seen(&account).as_ref(), Some(&written));
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_reload() {
    let f = Fixture::new();
    let _cleanup = Cleanup(Owner::Directory(f.dir.clone()));
    let created = load(&f.dir).unwrap();
    let account = f.account().unwrap();
    let certificate = f.certificate().unwrap();
    let written = seen(&account).unwrap();
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert!(handshake_succeeds(&created, &certificate));

    let reloaded = load(&f.dir).unwrap();
    assert!(reloaded.public_key_der() == created.public_key_der());
    assert!(handshake_succeeds(&reloaded, &certificate));
    assert_eq!(f.account(), Some(account.clone()));
    assert_eq!(seen(&account).as_ref(), Some(&written));

    fs::remove_file(f.path(CERT_FILE)).unwrap();
    let restored = load(&f.dir).unwrap();
    assert!(restored.public_key_der() == created.public_key_der());
    assert_eq!(f.certificate(), Some(certificate.clone()));
    assert_eq!(seen(&account).as_ref(), Some(&written));

    assert!(delete_exact(&account));
    assert_redacted(load(&f.dir), KEY_MISSING);
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(f.certificate(), Some(certificate));
    assert!(seen(&account).is_none());
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_concurrent_process_lock() {
    with_children(
        "native_ca_windows_concurrent_process_lock",
        concurrent_process_lock,
    );
}

fn concurrent_process_lock(function: &str) {
    let f = Fixture::new();
    let _cleanup = Cleanup(Owner::Directory(f.dir.clone()));
    let created = load(&f.dir).unwrap();
    let account = f.account().unwrap();
    let certificate = f.certificate().unwrap();
    let written = seen(&account).unwrap();

    let held = lock_directory(&f.dir).unwrap();
    run_child(function, LOCKED, &f.dir);
    assert_eq!(seen(&account).as_ref(), Some(&written));
    drop(held);
    run_child(function, RELOAD, &f.dir);

    assert_eq!(seen(&account).as_ref(), Some(&written));
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(f.certificate(), Some(certificate));
    assert_eq!(f.account(), Some(account));
    let reloaded = load(&f.dir).unwrap();
    assert!(reloaded.public_key_der() == created.public_key_der());
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_exact_cleanup() {
    let kept = random_hex();
    let removed = random_hex();
    let bytes = encoded(&generated());
    let keep = Cleanup(Owner::Account(kept.clone()));
    write_new(&kept, &bytes).unwrap();
    {
        let _cleanup = Cleanup(Owner::Account(removed.clone()));
        write_new(&removed, &bytes).unwrap();
        assert!(seen(&removed).is_some());
    }
    assert!(seen(&removed).is_none());
    assert!(seen(&kept).is_some());
    drop(keep);
    assert!(seen(&kept).is_none());
}

#[test]
#[ignore = "writes uniquely targeted Windows Credential Manager entries"]
fn native_ca_windows_retire() {
    let f = Fixture::new();
    let neighbour = Fixture::new();
    let _cleanup = Cleanup(Owner::Directory(f.dir.clone()));
    let _neighbour = Cleanup(Owner::Directory(neighbour.dir.clone()));
    load(&f.dir).unwrap();
    load(&neighbour.dir).unwrap();
    let account = f.account().unwrap();
    let kept = neighbour.account().unwrap();
    assert!(seen(&account).is_some());

    retire(&f.dir).unwrap();
    assert!(seen(&account).is_none());
    assert!(files(&f).is_empty());
    assert!(seen(&kept).is_some());
    assert_eq!(files(&neighbour), [CERT_FILE, ID_FILE]);
    assert!(delete_record(&account).is_ok());
    assert_redacted(retire(&f.dir), "CA storage identity missing");

    let foreign = random_hex();
    let _foreign = Cleanup(Owner::Account(foreign.clone()));
    let ca = generated();
    assert!(plant(&foreign, CRED_PERSIST_SESSION, &encoded(&ca)));
    let invalid = Fixture::new();
    invalid.put(ID_FILE, foreign.as_bytes());
    invalid.put(CERT_FILE, ca.certificate_pem.as_bytes());
    assert_redacted(retire(&invalid.dir), UNAVAILABLE);
    assert!(Credential::read(&foreign).unwrap().is_some());
    assert_eq!(files(&invalid), [CERT_FILE, ID_FILE]);

    load(&f.dir).unwrap();
    assert_ne!(f.account().unwrap(), account);
}
