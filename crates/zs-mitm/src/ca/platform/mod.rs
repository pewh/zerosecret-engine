#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(test, target_os = "linux", target_os = "macos", target_os = "windows"))]
mod record;
#[cfg(any(test, target_os = "linux", target_os = "macos", target_os = "windows"))]
mod state;
#[cfg(test)]
mod tests;
#[cfg(all(test, target_os = "linux"))]
mod tests_linux;
#[cfg(all(test, target_os = "macos"))]
mod tests_macos;
#[cfg(all(test, target_os = "windows"))]
mod tests_windows;
#[cfg(target_os = "windows")]
mod windows;

use std::path::Path;

use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use self::linux as native;
#[cfg(target_os = "macos")]
use self::macos as native;
#[cfg(target_os = "windows")]
use self::windows as native;
use super::{CaError, LocalCa};

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) fn load(dir: &Path) -> Result<LocalCa, CaError> {
    native::preflight()?;
    state::load_with(
        dir,
        || Ok(None),
        native::read_record,
        native::write_new,
        || Err(storage_error()),
    )
}

// A new directory has no legacy source, so a shared raw-argument item is never read or deleted.
#[cfg(target_os = "macos")]
pub(super) fn load(dir: &Path) -> Result<LocalCa, CaError> {
    macos::preflight()?;
    match super::existing_keychain_label(dir) {
        Some(label) => load_checked(dir, &label),
        None => state::load_with(
            dir,
            || Ok(None),
            macos::read_record,
            |account, bytes| macos::write_new(account, dir, bytes),
            || Err(storage_error()),
        ),
    }
}

#[cfg(target_os = "macos")]
pub(super) fn load_in_keychain(dir: &Path, legacy_label: &str) -> Result<LocalCa, CaError> {
    macos::preflight()?;
    load_checked(dir, legacy_label)
}

#[cfg(target_os = "macos")]
fn load_checked(dir: &Path, legacy_label: &str) -> Result<LocalCa, CaError> {
    state::load_with(
        dir,
        || macos::read_legacy(legacy_label),
        macos::read_record,
        |account, bytes| macos::write_new(account, dir, bytes),
        || macos::delete_legacy(legacy_label),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn load(_dir: &Path) -> Result<LocalCa, CaError> {
    Err(denied("secure CA storage unsupported"))
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) fn retire(dir: &Path) -> Result<(), CaError> {
    native::preflight()?;
    state::retire_with(dir, || Ok(None), native::read_record, native::delete_record)
}

#[cfg(target_os = "macos")]
pub(super) fn retire(dir: &Path) -> Result<(), CaError> {
    macos::preflight()?;
    let label = super::existing_keychain_label(dir);
    state::retire_with(
        dir,
        || label.as_deref().map_or(Ok(None), macos::read_legacy),
        macos::read_record,
        macos::delete_record,
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn retire(_dir: &Path) -> Result<(), CaError> {
    Err(denied("secure CA storage unsupported"))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn device_preflight() -> Result<(), CaError> {
    native::preflight()
}

#[cfg(target_os = "macos")]
pub(crate) fn device_write_new(
    service: &str,
    _label: &str,
    account: &str,
    owner: &Path,
    bytes: &[u8],
) -> Result<(), CaError> {
    native::write_new_in(service, account, owner, bytes)
}

#[cfg(target_os = "linux")]
pub(crate) fn device_write_new(
    service: &str,
    label: &str,
    account: &str,
    _owner: &Path,
    bytes: &[u8],
) -> Result<(), CaError> {
    native::write_new_in(service, label, account, bytes)
}

#[cfg(target_os = "windows")]
pub(crate) fn device_write_new(
    service: &str,
    _label: &str,
    account: &str,
    _owner: &Path,
    bytes: &[u8],
) -> Result<(), CaError> {
    native::write_new_in(service, account, bytes)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn device_read(
    service: &str,
    account: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, CaError> {
    native::read_record_in(service, account).map(|found| found.map(|secret| secret.0))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn device_delete(service: &str, account: &str) -> Result<(), CaError> {
    native::delete_record_in(service, account)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn device_preflight() -> Result<(), CaError> {
    Err(denied("secure CA storage unsupported"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn device_write_new(
    _service: &str,
    _label: &str,
    _account: &str,
    _owner: &Path,
    _bytes: &[u8],
) -> Result<(), CaError> {
    Err(denied("secure CA storage unsupported"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn device_read(
    _service: &str,
    _account: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, CaError> {
    Err(denied("secure CA storage unsupported"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn device_delete(_service: &str, _account: &str) -> Result<(), CaError> {
    Err(denied("secure CA storage unsupported"))
}

#[cfg(any(test, target_os = "linux", target_os = "macos", target_os = "windows"))]
fn storage_error() -> CaError {
    denied("secure CA storage unavailable")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn locked_error() -> CaError {
    denied("secure CA storage locked")
}

fn denied(message: &'static str) -> CaError {
    CaError::Storage(message.to_owned())
}
