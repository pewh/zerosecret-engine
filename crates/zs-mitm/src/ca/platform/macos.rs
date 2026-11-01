// Classify `security` by exit status only (44 = absent); never read its locale-dependent stderr.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use zeroize::Zeroizing;

use super::record::{MAX_RECORD_LEN, SecretBytes, secret_string};
use super::{denied, locked_error, storage_error};
use crate::ca::CaError;

// Absolute path, so a `security` earlier on `PATH` can neither see the record nor forge an outcome.
pub(super) const SECURITY: &str = "/usr/bin/security";
pub(super) const SERVICE: &str = "zerosecret.ca.v1";
pub(super) const RECORD_PREFIX: &str = "zsca1:";
pub(super) const OWNER_PREFIX: &str = "zerosecret-ca-dir:";
pub(super) const ITEM_NOT_FOUND: i32 = 44;
#[cfg(not(test))]
pub(super) const SECURITY_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
pub(super) const SECURITY_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const TIMEOUT_ENV: &str = "ZS_KEYCHAIN_TIMEOUT_SECS";
pub(super) const MAX_TIMEOUT_SECS: u64 = 300;
pub(super) const LOCK_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const INTERACTION_NOT_ALLOWED: i32 = 36;
const POLL: Duration = Duration::from_millis(1);
const NAME_LIMIT: usize = 128;
const ENCODED_LIMIT: usize = (MAX_RECORD_LEN * 4).div_ceil(3);
const RECORD_OUTPUT_LIMIT: usize = RECORD_PREFIX.len() + ENCODED_LIMIT + 1;
const LEGACY_OUTPUT_LIMIT: usize = 2 * MAX_RECORD_LEN + 1;

pub(super) enum ItemStatus {
    Present,
    Missing,
}

pub(super) fn classify_find_status(status: ExitStatus) -> Result<ItemStatus, CaError> {
    if status.success() {
        return Ok(ItemStatus::Present);
    }
    match status.code() {
        Some(ITEM_NOT_FOUND) => Ok(ItemStatus::Missing),
        _ => Err(storage_error()),
    }
}

pub(super) fn classify_lock_status(status: Option<ExitStatus>) -> Result<(), CaError> {
    match status {
        Some(status) if status.success() => Ok(()),
        Some(status) if status.code() == Some(INTERACTION_NOT_ALLOWED) => Err(locked_error()),
        None => Err(locked_error()),
        Some(_) => Err(storage_error()),
    }
}

pub(super) fn parse_timeout(value: Option<&OsStr>) -> Result<Duration, CaError> {
    let Some(value) = value else {
        return Ok(SECURITY_TIMEOUT);
    };
    value
        .to_str()
        .filter(|digits| (1..=3).contains(&digits.len()))
        .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse::<u64>().ok())
        .filter(|seconds| (1..=MAX_TIMEOUT_SECS).contains(seconds))
        .map(Duration::from_secs)
        .ok_or_else(|| denied("CA storage timeout invalid"))
}

fn security_timeout() -> Result<Duration, CaError> {
    if cfg!(test) {
        Ok(SECURITY_TIMEOUT)
    } else {
        parse_timeout(std::env::var_os(TIMEOUT_ENV).as_deref())
    }
}

fn succeeded(status: ExitStatus) -> Result<(), CaError> {
    if status.success() {
        Ok(())
    } else {
        Err(storage_error())
    }
}

// An empty or option-like name could widen the match to someone else's item.
pub(super) fn checked_label(label: &str) -> Result<&str, CaError> {
    let exact = (1..=NAME_LIMIT).contains(&label.len())
        && label.starts_with(|c: char| c.is_ascii_alphanumeric())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if exact {
        Ok(label)
    } else {
        Err(storage_error())
    }
}

pub(super) fn find_args<'a>(account: &'a str, service: &'a str) -> [&'a str; 6] {
    ["find-generic-password", "-a", account, "-s", service, "-w"]
}

pub(super) fn delete_args(label: &str) -> [&str; 5] {
    ["delete-generic-password", "-a", label, "-s", label]
}

#[cfg(test)]
pub(super) fn delete_record_args(account: &str) -> [&str; 5] {
    delete_record_args_in(SERVICE, account)
}

pub(super) fn delete_record_args_in<'a>(service: &'a str, account: &'a str) -> [&'a str; 5] {
    ["delete-generic-password", "-a", account, "-s", service]
}

pub(super) const LOCK_CHECK_ARGS: [&str; 1] = ["show-keychain-info"];

// No `-U`: create-only, so an existing item fails instead of being overwritten.
#[cfg(test)]
pub(super) fn add_args<'a>(
    account: &'a str,
    comment: &'a OsStr,
    value: &'a OsStr,
) -> [&'a OsStr; 9] {
    add_args_in(SERVICE, account, comment, value)
}

pub(super) fn add_args_in<'a>(
    service: &'a str,
    account: &'a str,
    comment: &'a OsStr,
    value: &'a OsStr,
) -> [&'a OsStr; 9] {
    [
        OsStr::new("add-generic-password"),
        OsStr::new("-a"),
        OsStr::new(account),
        OsStr::new("-s"),
        OsStr::new(service),
        OsStr::new("-j"),
        comment,
        OsStr::new("-w"),
        value,
    ]
}

pub(super) fn owner_comment(owner: &Path) -> Result<OsString, CaError> {
    let canonical = fs::canonicalize(owner).map_err(|_| storage_error())?;
    let mut comment = OsString::from(OWNER_PREFIX);
    comment.push(canonical.as_os_str());
    Ok(comment)
}

pub(super) fn record_value(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, CaError> {
    if !(1..=MAX_RECORD_LEN).contains(&bytes.len()) {
        return Err(storage_error());
    }
    let encoded_len = (bytes.len() * 4).div_ceil(3);
    let mut value = Zeroizing::new(vec![0u8; RECORD_PREFIX.len() + encoded_len]);
    let (prefix, encoded) = value.split_at_mut(RECORD_PREFIX.len());
    prefix.copy_from_slice(RECORD_PREFIX.as_bytes());
    let written = STANDARD_NO_PAD
        .encode_slice(bytes, encoded)
        .map_err(|_| storage_error())?;
    if written != encoded_len {
        return Err(storage_error());
    }
    Ok(value)
}

pub(super) fn record_from_output(output: &[u8]) -> Result<SecretBytes, CaError> {
    let encoded = output
        .strip_suffix(b"\n")
        .and_then(|value| value.strip_prefix(RECORD_PREFIX.as_bytes()))
        .filter(|encoded| encoded.len() <= ENCODED_LIMIT)
        .ok_or_else(storage_error)?;
    let mut bytes = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(encoded.len())]);
    let len = STANDARD_NO_PAD
        .decode_slice(encoded, &mut bytes)
        .map_err(|_| storage_error())?;
    bytes.truncate(len);
    if !(1..=MAX_RECORD_LEN).contains(&bytes.len()) {
        return Err(storage_error());
    }
    Ok(SecretBytes(bytes))
}

fn nibble(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

pub(super) fn legacy_from_output(output: &[u8]) -> Result<Zeroizing<String>, CaError> {
    let (pairs, rest) = output
        .strip_suffix(b"\n")
        .filter(|hex| !hex.is_empty() && hex.len() <= 2 * MAX_RECORD_LEN)
        .ok_or_else(storage_error)?
        .as_chunks::<2>();
    if !rest.is_empty() {
        return Err(storage_error());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(pairs.len()));
    for &[high, low] in pairs {
        let byte = nibble(high)
            .zip(nibble(low))
            .map(|(high, low)| (high << 4) | low)
            .ok_or_else(storage_error)?;
        bytes.push(byte);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| storage_error())?;
    Ok(secret_string(text))
}

pub(super) fn command<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    #[cfg(test)]
    super::tests_macos::disposable::require_verified();
    let mut command = Command::new(SECURITY);
    command
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn drain(stdout: ChildStdout, capture: Option<usize>) -> io::Result<Zeroizing<Vec<u8>>> {
    let Some(limit) = capture else {
        let mut stdout = stdout;
        io::copy(&mut stdout, &mut io::sink())?;
        return Ok(Zeroizing::new(Vec::new()));
    };
    let bound = limit.saturating_add(1);
    let mut output = Zeroizing::new(Vec::with_capacity(bound));
    stdout
        .take(u64::try_from(bound).unwrap_or(u64::MAX))
        .read_to_end(&mut output)?;
    Ok(output)
}

fn wait_until(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL),
            _ => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

// A locked keychain's prompt holds stdout open, so the wait must never depend on reading it.
pub(super) fn run_bounded(
    mut command: Command,
    capture: Option<usize>,
    timeout: Duration,
) -> Result<(ExitStatus, Zeroizing<Vec<u8>>), CaError> {
    let deadline = Instant::now() + timeout;
    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| storage_error())?;
    let (sender, receiver) = mpsc::channel();
    let reading = child.stdout.take().map(|stdout| {
        thread::Builder::new().spawn(move || {
            let _ = sender.send(drain(stdout, capture));
        })
    });
    let read = match reading {
        Some(Ok(_)) => receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok(),
        _ => None,
    };
    let status = wait_until(
        &mut child,
        if read.is_some() {
            deadline
        } else {
            Instant::now()
        },
    );
    let (Some(Ok(output)), Some(status)) = (read, status) else {
        return Err(storage_error());
    };
    if capture.is_some_and(|limit| output.len() > limit) {
        return Err(storage_error());
    }
    Ok((status, output))
}

pub(super) fn run_status_bounded(
    mut command: Command,
    timeout: Duration,
) -> Result<Option<ExitStatus>, CaError> {
    let deadline = Instant::now() + timeout;
    let mut child = command
        .stdout(Stdio::null())
        .spawn()
        .map_err(|_| storage_error())?;
    Ok(wait_until(&mut child, deadline))
}

fn status<I, S>(args: I) -> Result<ExitStatus, CaError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_bounded(command(args), None, security_timeout()?).map(|(status, _)| status)
}

fn capture(args: [&str; 6], limit: usize) -> Result<(ExitStatus, Zeroizing<Vec<u8>>), CaError> {
    run_bounded(command(args), Some(limit), security_timeout()?)
}

// Run before touching any CA directory or Keychain item, so a locked keychain leaves nothing.
pub(super) fn preflight() -> Result<(), CaError> {
    let timeout = security_timeout()?;
    classify_lock_status(run_status_bounded(
        command(LOCK_CHECK_ARGS),
        timeout.min(LOCK_CHECK_TIMEOUT),
    )?)
}

pub(super) fn read_record(account: &str) -> Result<Option<SecretBytes>, CaError> {
    read_record_in(SERVICE, account)
}

pub(super) fn read_record_in(service: &str, account: &str) -> Result<Option<SecretBytes>, CaError> {
    let account = checked_label(account)?;
    let (status, output) = capture(find_args(account, service), RECORD_OUTPUT_LIMIT)?;
    match classify_find_status(status)? {
        ItemStatus::Missing => Ok(None),
        ItemStatus::Present => record_from_output(&output).map(Some),
    }
}

pub(super) fn read_legacy(legacy_label: &str) -> Result<Option<Zeroizing<String>>, CaError> {
    let label = checked_label(legacy_label)?;
    let (status, output) = capture(find_args(label, label), LEGACY_OUTPUT_LIMIT)?;
    match classify_find_status(status)? {
        ItemStatus::Missing => Ok(None),
        ItemStatus::Present => legacy_from_output(&output).map(Some),
    }
}

pub(super) fn write_new(account: &str, owner: &Path, bytes: &[u8]) -> Result<(), CaError> {
    write_new_in(SERVICE, account, owner, bytes)
}

pub(super) fn write_new_in(
    service: &str,
    account: &str,
    owner: &Path,
    bytes: &[u8],
) -> Result<(), CaError> {
    let account = checked_label(account)?;
    let value = record_value(bytes)?;
    let comment = owner_comment(owner)?;
    succeeded(status(add_args_in(
        service,
        account,
        &comment,
        OsStr::from_bytes(&value),
    ))?)
}

pub(super) fn delete_legacy(legacy_label: &str) -> Result<(), CaError> {
    let label = checked_label(legacy_label)?;
    succeeded(status(delete_args(label))?)
}

pub(super) fn delete_record(account: &str) -> Result<(), CaError> {
    delete_record_in(SERVICE, account)
}

pub(super) fn delete_record_in(service: &str, account: &str) -> Result<(), CaError> {
    let account = checked_label(account)?;
    let status = status(delete_record_args_in(service, account))?;
    if status.code() == Some(ITEM_NOT_FOUND) {
        return Ok(());
    }
    succeeded(status)
}
