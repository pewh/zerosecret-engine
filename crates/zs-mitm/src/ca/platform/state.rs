use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;

use rand::RngCore;
use rand::rngs::OsRng;
use rcgen::KeyPair;
use rustls::pki_types::CertificateDer;
use zeroize::Zeroizing;

use super::record::{
    CaRecord, MAX_RECORD_LEN, SecretBytes, ca_from_record, certificate_der, decode_record,
    encode_record, key_matches, new_record, secret_string,
};
use super::{denied, storage_error};
use crate::ca::{CA_CERT_FILE, CA_KEY_FILE, CaError, LocalCa};

const LOCK_FILE: &str = ".ca-storage.lock";
const ID_FILE: &str = ".ca-storage-id";
const ID_BYTES: usize = 16;
const ID_LEN: usize = 32;
const READ_LIMIT: usize = MAX_RECORD_LEN + 1;

pub(super) struct NativeSnapshot {
    pub(super) record: Option<SecretBytes>,
    pub(super) legacy_key: Option<Zeroizing<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    IdentityCreate,
    IdentitySync,
    LegacyRead,
    CertificateCreate,
    CertificateSync,
    LegacyDelete,
}

fn incomplete_legacy() -> CaError {
    denied("CA legacy identity incomplete")
}

fn readback_mismatch() -> CaError {
    denied("CA storage readback mismatch")
}

fn removal_failed() -> CaError {
    denied("CA legacy key removal failed")
}

fn inspect(path: &Path) -> Result<bool, CaError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(denied("CA storage path invalid")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(storage_error()),
    }
}

fn read_bounded(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, CaError> {
    if !inspect(path)? {
        return Ok(None);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(READ_LIMIT));
    File::open(path)
        .and_then(|file| file.take(READ_LIMIT as u64).read_to_end(&mut bytes))
        .map_err(|_| storage_error())?;
    Ok(Some(bytes))
}

fn bounded_text(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|_| bytes.len() <= MAX_RECORD_LEN)
}

fn read_certificate(path: &Path) -> Result<Option<(String, CertificateDer<'static>)>, CaError> {
    let invalid = || denied("CA certificate invalid");
    let Some(bytes) = read_bounded(path)? else {
        return Ok(None);
    };
    let text = bounded_text(&bytes).ok_or_else(invalid)?;
    let der = certificate_der(text).ok_or_else(invalid)?;
    Ok(Some((text.to_owned(), der)))
}

fn read_legacy_file(path: &Path) -> Result<Option<Zeroizing<String>>, CaError> {
    let Some(bytes) = read_bounded(path)? else {
        return Ok(None);
    };
    let text = bounded_text(&bytes).ok_or_else(|| denied("CA legacy key invalid"))?;
    Ok(Some(secret_string(text)))
}

fn create_file<S>(path: &Path, contents: &[u8], before_sync: S) -> io::Result<()>
where
    S: FnOnce() -> io::Result<()>,
{
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    let written = file
        .write_all(contents)
        .and_then(|()| before_sync())
        .and_then(|()| file.sync_all());
    if written.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    written
}

pub(super) fn lock_directory(dir: &Path) -> Result<File, CaError> {
    fs::create_dir_all(dir).map_err(|_| storage_error())?;
    for name in [LOCK_FILE, ID_FILE, CA_KEY_FILE, CA_CERT_FILE] {
        inspect(&dir.join(name))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(LOCK_FILE))
        .map_err(|_| storage_error())?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(denied("CA storage busy")),
        Err(TryLockError::Error(_)) => Err(storage_error()),
    }
}

fn parse_account(bytes: &[u8]) -> Result<String, CaError> {
    let malformed = || denied("CA storage identity malformed");
    if bytes.len() != ID_LEN
        || !bytes
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(malformed());
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| malformed())
}

pub(super) fn storage_account(
    dir: &Path,
    recovery_source_present: bool,
) -> Result<String, CaError> {
    let path = dir.join(ID_FILE);
    if let Some(bytes) = read_bounded(&path)? {
        return parse_account(&bytes);
    }
    if !recovery_source_present {
        return Err(denied("CA storage identity missing"));
    }
    let mut raw = [0u8; ID_BYTES];
    OsRng
        .try_fill_bytes(&mut raw)
        .map_err(|_| storage_error())?;
    Ok(raw.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(super) fn persist_account<F>(dir: &Path, account: &str, fault: &mut F) -> Result<(), CaError>
where
    F: FnMut(Step) -> io::Result<()>,
{
    let path = dir.join(ID_FILE);
    fault(Step::IdentityCreate)
        .and_then(|()| create_file(&path, account.as_bytes(), || fault(Step::IdentitySync)))
        .map_err(|_| storage_error())?;
    let verified =
        read_bounded(&path)?.is_some_and(|stored| stored.as_slice() == account.as_bytes());
    if !verified {
        let _ = fs::remove_file(&path);
        return Err(storage_error());
    }
    Ok(())
}

pub(super) fn load_with<L, R, W, D>(
    dir: &Path,
    mut read_legacy: L,
    mut read_record: R,
    mut write_record: W,
    delete_legacy: D,
) -> Result<LocalCa, CaError>
where
    L: FnMut() -> Result<Option<Zeroizing<String>>, CaError>,
    R: FnMut(&str) -> Result<Option<SecretBytes>, CaError>,
    W: FnMut(&str, &[u8]) -> Result<(), CaError>,
    D: FnMut() -> Result<(), CaError>,
{
    let _lock = lock_directory(dir)?;
    let certificate_path = dir.join(CA_CERT_FILE);
    let key_path = dir.join(CA_KEY_FILE);
    let certificate_present = inspect(&certificate_path)?;
    let file_legacy_present = inspect(&key_path)?;
    let native_legacy = read_legacy().map_err(|_| storage_error())?;
    let legacy_present = file_legacy_present || native_legacy.is_some();
    let identity_present = inspect(&dir.join(ID_FILE))?;
    if !identity_present && legacy_present {
        let public = read_certificate(&certificate_path)?.ok_or_else(incomplete_legacy)?;
        let file_legacy = read_legacy_file(&key_path)?;
        let legacy = legacy_keys(file_legacy.as_ref(), native_legacy.as_ref());
        validated(&legacy_record(public, &legacy)?)?;
    }
    let account = storage_account(dir, legacy_present || !certificate_present)?;
    let mut read_native = || -> Result<NativeSnapshot, CaError> {
        Ok(NativeSnapshot {
            record: read_record(&account)?,
            legacy_key: read_legacy()?,
        })
    };
    let mut pending = None;
    if !identity_present {
        let snapshot = read_native().map_err(|_| storage_error())?;
        if snapshot.record.is_some() {
            return Err(storage_error());
        }
        persist_account(dir, &account, &mut |_| Ok(()))?;
        pending = Some(snapshot);
    }
    load_locked(
        dir,
        || pending.take().map_or_else(&mut read_native, Ok),
        |bytes| write_record(&account, bytes),
        delete_legacy,
    )
}

pub(super) fn load_locked<R, W, D>(
    dir: &Path,
    read_native: R,
    write_native: W,
    delete_native_legacy: D,
) -> Result<LocalCa, CaError>
where
    R: FnMut() -> Result<NativeSnapshot, CaError>,
    W: FnMut(&[u8]) -> Result<(), CaError>,
    D: FnMut() -> Result<(), CaError>,
{
    transition(dir, read_native, write_native, delete_native_legacy, |_| {
        Ok(())
    })
}

fn require_legacy_match(identity: &CertificateDer<'_>, legacy: &[&str]) -> Result<(), CaError> {
    for key in legacy {
        let key = KeyPair::from_pem(key).map_err(|_| denied("CA legacy key invalid"))?;
        if !key_matches(identity, &key) {
            return Err(denied("CA legacy key mismatch"));
        }
    }
    Ok(())
}

fn legacy_keys<'a>(
    file: Option<&'a Zeroizing<String>>,
    native: Option<&'a Zeroizing<String>>,
) -> Vec<&'a str> {
    file.into_iter()
        .chain(native)
        .map(|key| key.as_str())
        .collect()
}

fn legacy_record(
    (certificate_pem, identity): (String, CertificateDer<'static>),
    legacy: &[&str],
) -> Result<CaRecord, CaError> {
    require_legacy_match(&identity, legacy)?;
    let key = legacy.first().ok_or_else(incomplete_legacy)?;
    Ok(CaRecord {
        certificate_pem,
        private_key_pem: secret_string(key),
    })
}

fn validated(record: &CaRecord) -> Result<SecretBytes, CaError> {
    let encoded = encode_record(record)?;
    ca_from_record(&decode_record(&encoded.0)?)?;
    Ok(encoded)
}

fn store<R, W>(
    record: &CaRecord,
    read_native: &mut R,
    write_native: &mut W,
) -> Result<LocalCa, CaError>
where
    R: FnMut() -> Result<NativeSnapshot, CaError>,
    W: FnMut(&[u8]) -> Result<(), CaError>,
{
    let encoded = validated(record)?;
    write_native(&encoded.0).map_err(|_| storage_error())?;
    let stored = read_native()
        .map_err(|_| storage_error())?
        .record
        .ok_or_else(readback_mismatch)?;
    if stored.0.as_slice() != encoded.0.as_slice() {
        return Err(readback_mismatch());
    }
    ca_from_record(&decode_record(&stored.0)?)
}

fn ensure_public<F>(
    path: &Path,
    certificate_pem: &str,
    identity: &CertificateDer<'_>,
    fault: &mut F,
) -> Result<(), CaError>
where
    F: FnMut(Step) -> io::Result<()>,
{
    match read_certificate(path)? {
        Some((_, published)) if published.as_ref() == identity.as_ref() => Ok(()),
        Some(_) => Err(denied("CA certificate mismatch")),
        None => fault(Step::CertificateCreate)
            .and_then(|()| {
                create_file(path, certificate_pem.as_bytes(), || {
                    fault(Step::CertificateSync)
                })
            })
            .map_err(|_| denied("CA certificate publication failed")),
    }
}

pub(super) fn transition<R, W, D, F>(
    dir: &Path,
    mut read_native: R,
    mut write_native: W,
    mut delete_native_legacy: D,
    mut fault: F,
) -> Result<LocalCa, CaError>
where
    R: FnMut() -> Result<NativeSnapshot, CaError>,
    W: FnMut(&[u8]) -> Result<(), CaError>,
    D: FnMut() -> Result<(), CaError>,
    F: FnMut(Step) -> io::Result<()>,
{
    let certificate_path = dir.join(CA_CERT_FILE);
    let key_path = dir.join(CA_KEY_FILE);
    let NativeSnapshot {
        record: stored,
        legacy_key: native_legacy,
    } = read_native().map_err(|_| storage_error())?;
    let public = read_certificate(&certificate_path)?;
    fault(Step::LegacyRead).map_err(|_| storage_error())?;
    let file_legacy = read_legacy_file(&key_path)?;
    let legacy = legacy_keys(file_legacy.as_ref(), native_legacy.as_ref());

    let (certificate_pem, ca) = match (stored, public, legacy.first()) {
        (Some(bytes), _, _) => {
            let record = decode_record(&bytes.0)?;
            let ca = ca_from_record(&record)?;
            require_legacy_match(&ca.ca_cert_der, &legacy)?;
            (record.certificate_pem, ca)
        }
        (None, None, None) => {
            let record = new_record()?;
            let ca = store(&record, &mut read_native, &mut write_native)?;
            (record.certificate_pem, ca)
        }
        (None, Some(_), None) => return Err(denied("CA private key missing")),
        (None, None, Some(_)) => return Err(incomplete_legacy()),
        (None, Some(public), Some(_)) => {
            let record = legacy_record(public, &legacy)?;
            let ca = store(&record, &mut read_native, &mut write_native)?;
            (record.certificate_pem, ca)
        }
    };

    ensure_public(
        &certificate_path,
        &certificate_pem,
        &ca.ca_cert_der,
        &mut fault,
    )?;
    if file_legacy.is_some() {
        fault(Step::LegacyDelete)
            .and_then(|()| fs::remove_file(&key_path))
            .map_err(|_| removal_failed())?;
    }
    if native_legacy.is_some() {
        delete_native_legacy().map_err(|_| removal_failed())?;
    }
    Ok(ca)
}

fn record_removal_failed() -> CaError {
    denied("CA record removal failed")
}

pub(super) fn retire_with<L, R, D>(
    dir: &Path,
    mut read_legacy: L,
    mut read_record: R,
    mut delete_record: D,
) -> Result<(), CaError>
where
    L: FnMut() -> Result<Option<Zeroizing<String>>, CaError>,
    R: FnMut(&str) -> Result<Option<SecretBytes>, CaError>,
    D: FnMut(&str) -> Result<(), CaError>,
{
    match fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(denied("CA storage path invalid")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(denied("CA storage identity missing"));
        }
        Err(_) => return Err(storage_error()),
    }
    let _lock = lock_directory(dir)?;
    let certificate_path = dir.join(CA_CERT_FILE);
    let id_path = dir.join(ID_FILE);
    if inspect(&dir.join(CA_KEY_FILE))? || read_legacy().map_err(|_| storage_error())?.is_some() {
        return Err(denied("CA migration incomplete"));
    }
    let account = parse_account(
        &read_bounded(&id_path)?.ok_or_else(|| denied("CA storage identity missing"))?,
    )?;
    let public = read_certificate(&certificate_path)?;
    let stored = read_record(&account)
        .map_err(|_| storage_error())?
        .ok_or_else(|| denied("CA private key missing"))?;
    let ca = ca_from_record(&decode_record(&stored.0)?)?;
    if public
        .as_ref()
        .is_some_and(|(_, published)| published.as_ref() != ca.ca_cert_der.as_ref())
    {
        return Err(denied("CA certificate mismatch"));
    }
    delete_record(&account).map_err(|_| record_removal_failed())?;
    if read_record(&account)
        .map_err(|_| record_removal_failed())?
        .is_some()
    {
        return Err(record_removal_failed());
    }
    let cleanup_failed = |_| denied("CA directory cleanup failed");
    if public.is_some() {
        fs::remove_file(&certificate_path).map_err(cleanup_failed)?;
    }
    fs::remove_file(&id_path).map_err(cleanup_failed)
}
