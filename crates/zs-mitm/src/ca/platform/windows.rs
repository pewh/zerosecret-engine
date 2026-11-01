use std::ptr::{self, NonNull};
use std::slice;

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError, WIN32_ERROR};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_PERSIST, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE,
    CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
};
use zeroize::{Zeroize, Zeroizing};

use super::record::{MAX_RECORD_LEN, SecretBytes};
use super::storage_error;
use crate::ca::CaError;

const SERVICE: &str = "zerosecret.ca.v1";

const _: () = assert!(MAX_RECORD_LEN == CRED_MAX_CREDENTIAL_BLOB_SIZE as usize);

#[cfg(test)]
pub(super) fn target(account: &str) -> Vec<u16> {
    target_in(SERVICE, account)
}

pub(super) fn target_in(service: &str, account: &str) -> Vec<u16> {
    format!("{service}/{account}")
        .encode_utf16()
        .chain([0])
        .collect()
}

pub(super) fn absence<T>(error: WIN32_ERROR) -> Result<Option<T>, CaError> {
    if error == ERROR_NOT_FOUND {
        Ok(None)
    } else {
        Err(storage_error())
    }
}

pub(super) fn blob_len(
    kind: CRED_TYPE,
    persist: CRED_PERSIST,
    blob_present: bool,
    size: u32,
) -> Result<usize, CaError> {
    let len = usize::try_from(size).map_err(|_| storage_error())?;
    if kind != CRED_TYPE_GENERIC
        || persist != CRED_PERSIST_LOCAL_MACHINE
        || !blob_present
        || !(1..=MAX_RECORD_LEN).contains(&len)
    {
        return Err(storage_error());
    }
    Ok(len)
}

pub(super) struct Credential(NonNull<CREDENTIALW>);

impl Credential {
    #[cfg(test)]
    pub(super) fn read(account: &str) -> Result<Option<Self>, CaError> {
        Self::read_in(SERVICE, account)
    }

    pub(super) fn read_in(service: &str, account: &str) -> Result<Option<Self>, CaError> {
        let target = target_in(service, account);
        let mut credential: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: `target` is a NUL-terminated UTF-16 buffer outliving the call; `credential` is a valid out-pointer freed on drop.
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
            // SAFETY: no precondition; reads this thread's last error from the failed call above.
            return absence(unsafe { GetLastError() });
        }
        NonNull::new(credential)
            .map(|credential| Some(Self(credential)))
            .ok_or_else(storage_error)
    }

    fn get(&self) -> &CREDENTIALW {
        // SAFETY: `self.0` is the non-null `CREDENTIALW` from `CredReadW`, valid until `drop`; the borrow is tied to `&self`.
        unsafe { self.0.as_ref() }
    }

    fn secret(&self) -> Result<SecretBytes, CaError> {
        let credential = self.get();
        let len = blob_len(
            credential.Type,
            credential.Persist,
            !credential.CredentialBlob.is_null(),
            credential.CredentialBlobSize,
        )?;
        // SAFETY: `blob_len` checked the pointer is non-null and `len` is `CredentialBlobSize` within the owned allocation.
        let blob = unsafe { slice::from_raw_parts(credential.CredentialBlob, len) };
        let mut secret = Zeroizing::new(Vec::with_capacity(len));
        secret.extend_from_slice(blob);
        Ok(SecretBytes(secret))
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Metadata {
    pub(super) kind: CRED_TYPE,
    pub(super) persist: CRED_PERSIST,
    pub(super) size: u32,
    pub(super) attributes: u32,
    pub(super) written: (u32, u32),
    pub(super) exact_target: bool,
}

#[cfg(test)]
impl Credential {
    pub(super) fn metadata(&self, account: &str) -> Metadata {
        let credential = self.get();
        let name = credential.TargetName.cast_const();
        let exact_target = !name.is_null()
            && target(account)
                .iter()
                .enumerate()
                // SAFETY: `TargetName` is NUL-terminated in the live allocation and `all` stops at the first differing unit.
                .all(|(index, unit)| unsafe { *name.add(index) } == *unit);
        Metadata {
            kind: credential.Type,
            persist: credential.Persist,
            size: credential.CredentialBlobSize,
            attributes: credential.AttributeCount,
            written: (
                credential.LastWritten.dwLowDateTime,
                credential.LastWritten.dwHighDateTime,
            ),
            exact_target,
        }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        let credential = self.get();
        let (blob, size) = (credential.CredentialBlob, credential.CredentialBlobSize);
        if let Some(len) = usize::try_from(size).ok().filter(|_| !blob.is_null()) {
            // SAFETY: `blob` is non-null with length `CredentialBlobSize` in the owned allocation, unborrowed during `drop`.
            unsafe { slice::from_raw_parts_mut(blob, len) }.zeroize();
        }
        // SAFETY: `self.0` came from `CredReadW` and is freed exactly once, here.
        unsafe { CredFree(self.0.as_ptr().cast_const().cast()) };
    }
}

pub(super) fn preflight() -> Result<(), CaError> {
    Ok(())
}

pub(super) fn read_record(account: &str) -> Result<Option<SecretBytes>, CaError> {
    read_record_in(SERVICE, account)
}

pub(super) fn read_record_in(service: &str, account: &str) -> Result<Option<SecretBytes>, CaError> {
    Credential::read_in(service, account)?
        .map(|credential| credential.secret())
        .transpose()
}

pub(super) fn write_new(account: &str, bytes: &[u8]) -> Result<(), CaError> {
    write_new_in(SERVICE, account, bytes)
}

pub(super) fn write_new_in(service: &str, account: &str, bytes: &[u8]) -> Result<(), CaError> {
    if !(1..=MAX_RECORD_LEN).contains(&bytes.len()) {
        return Err(storage_error());
    }
    let size = u32::try_from(bytes.len()).map_err(|_| storage_error())?;
    if Credential::read_in(service, account)?.is_some() {
        return Err(storage_error());
    }
    let mut target = target_in(service, account);
    let mut blob = Zeroizing::new(bytes.to_vec());
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: target.as_mut_ptr(),
        CredentialBlobSize: size,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..CREDENTIALW::default()
    };
    // SAFETY: `credential` points at `target` (NUL-terminated) and `blob` (length `size`); both outlive the call, which copies them.
    if unsafe { CredWriteW(&credential, 0) } == 0 {
        return Err(storage_error());
    }
    Ok(())
}

pub(super) fn delete_record(account: &str) -> Result<(), CaError> {
    delete_record_in(SERVICE, account)
}

pub(super) fn delete_record_in(service: &str, account: &str) -> Result<(), CaError> {
    let target = target_in(service, account);
    // SAFETY: `target` is a NUL-terminated UTF-16 buffer that outlives the call, which keeps no pointer to it.
    if unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
        return Ok(());
    }
    // SAFETY: no precondition; reads this thread's last error from the failed call above.
    absence::<()>(unsafe { GetLastError() }).map(|_| ())
}
