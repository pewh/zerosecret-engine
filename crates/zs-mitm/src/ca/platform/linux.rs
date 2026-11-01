use std::collections::HashMap;

use dbus_secret_service::{Collection, EncryptionType, SecretService};
use zeroize::Zeroizing;

use super::record::{MAX_RECORD_LEN, SecretBytes};
use super::{locked_error, storage_error};
use crate::ca::CaError;

pub(super) const SERVICE: &str = "zerosecret.ca.v1";
pub(super) const SCHEMA: &str = "1";
pub(super) const LABEL: &str = "ZeroSecret local CA";
pub(super) const CONTENT_TYPE: &str = "application/octet-stream";

#[cfg(test)]
pub(super) fn attributes(account: &str) -> HashMap<&str, &str> {
    attributes_in(SERVICE, account)
}

pub(super) fn attributes_in<'a>(service: &'a str, account: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([
        ("service", service),
        ("account", account),
        ("schema", SCHEMA),
    ])
}

pub(super) fn unique<T>(unlocked: Vec<T>, locked: &[T]) -> Result<Option<T>, CaError> {
    if !locked.is_empty() || unlocked.len() > 1 {
        return Err(storage_error());
    }
    Ok(unlocked.into_iter().next())
}

pub(super) fn bounded(secret: Vec<u8>) -> Result<SecretBytes, CaError> {
    let secret = Zeroizing::new(secret);
    if !(1..=MAX_RECORD_LEN).contains(&secret.len()) {
        return Err(storage_error());
    }
    Ok(SecretBytes(secret))
}

fn connect() -> Result<SecretService, CaError> {
    SecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, 0)
        .map_err(|_| storage_error())
}

fn unlocked_default(service: &SecretService) -> Result<Collection<'_>, CaError> {
    let collection = service
        .get_default_collection()
        .map_err(|_| storage_error())?;
    match collection.is_locked() {
        Ok(false) => Ok(collection),
        Ok(true) => Err(locked_error()),
        Err(_) => Err(storage_error()),
    }
}

// Must run before any CA directory is created or locked, so a refused start leaves nothing behind.
pub(super) fn preflight() -> Result<(), CaError> {
    let service = connect()?;
    unlocked_default(&service).map(|_| ())
}

pub(super) fn read_record(account: &str) -> Result<Option<SecretBytes>, CaError> {
    read_record_in(SERVICE, account)
}

pub(super) fn read_record_in(
    service_name: &str,
    account: &str,
) -> Result<Option<SecretBytes>, CaError> {
    let service = connect()?;
    unlocked_default(&service)?;
    let found = service
        .search_items(attributes_in(service_name, account))
        .map_err(|_| storage_error())?;
    let Some(item) = unique(found.unlocked, &found.locked)? else {
        return Ok(None);
    };
    if !matches!(item.is_locked(), Ok(false)) {
        return Err(storage_error());
    }
    let secret = item.get_secret().map_err(|_| storage_error())?;
    bounded(secret).map(Some)
}

pub(super) fn write_new(account: &str, bytes: &[u8]) -> Result<(), CaError> {
    write_new_in(SERVICE, LABEL, account, bytes)
}

pub(super) fn write_new_in(
    service_name: &str,
    label: &str,
    account: &str,
    bytes: &[u8],
) -> Result<(), CaError> {
    if !(1..=MAX_RECORD_LEN).contains(&bytes.len()) {
        return Err(storage_error());
    }
    let service = connect()?;
    let collection = unlocked_default(&service)?;
    let found = service
        .search_items(attributes_in(service_name, account))
        .map_err(|_| storage_error())?;
    if unique(found.unlocked, &found.locked)?.is_some() {
        return Err(storage_error());
    }
    collection
        .create_item(
            label,
            attributes_in(service_name, account),
            bytes,
            false,
            CONTENT_TYPE,
        )
        .map_err(|_| storage_error())?;
    Ok(())
}

pub(super) fn delete_record(account: &str) -> Result<(), CaError> {
    delete_record_in(SERVICE, account)
}

pub(super) fn delete_record_in(service_name: &str, account: &str) -> Result<(), CaError> {
    let service = connect()?;
    unlocked_default(&service)?;
    let found = service
        .search_items(attributes_in(service_name, account))
        .map_err(|_| storage_error())?;
    let Some(item) = unique(found.unlocked, &found.locked)? else {
        return Ok(());
    };
    item.delete().map_err(|_| storage_error())
}
