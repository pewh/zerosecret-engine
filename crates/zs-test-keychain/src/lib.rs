#![cfg(target_os = "macos")]
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub const SECURITY: &str = "/usr/bin/security";
pub const KEYCHAIN_ENV: &str = "ZS_CI_KEYCHAIN";
pub const PASSWORD_FILE_ENV: &str = "ZS_CI_KEYCHAIN_PASSWORD_FILE";
pub const SERVICE: &str = "zerosecret.ca.v1";
pub const ID_FILE: &str = ".ca-storage-id";
pub const ITEM_NOT_FOUND: i32 = 44;
const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
const NAME_LIMIT: usize = 128;
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

static VERIFIED: AtomicBool = AtomicBool::new(false);

fn refuse(reason: &str) -> ! {
    panic!("refusing to touch a Keychain outside a disposable CI keychain: {reason}")
}

fn run(args: Vec<OsString>) -> Output {
    let mut child = Command::new(SECURITY)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + HELPER_TIMEOUT;
    let (sender, receiver) = mpsc::channel();
    if let Some(mut stdout) = child.stdout.take() {
        thread::spawn(move || {
            let mut output = Vec::new();
            let _ = stdout.read_to_end(&mut output);
            let _ = sender.send(output);
        });
    }
    let stdout = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_default();
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break status,
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            None => {
                let _ = child.kill();
                break child.wait().unwrap();
            }
        }
    };
    Output {
        status,
        stdout,
        stderr: Vec::new(),
    }
}

fn arguments<I, S>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect()
}

fn preference(args: [&str; 3]) -> Vec<PathBuf> {
    let output = run(arguments(args));
    if !output.status.success() {
        refuse("a Keychain preference query failed");
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim().trim_matches('"'))
        .filter(|line| !line.is_empty())
        .map(|line| fs::canonicalize(line).unwrap_or_else(|_| PathBuf::from(line)))
        .collect()
}

pub fn disposable_path<V>(var: V) -> Result<PathBuf, &'static str>
where
    V: Fn(&str) -> Option<OsString>,
{
    if var("GITHUB_ACTIONS").as_deref() != Some(OsStr::new("true")) {
        return Err("GITHUB_ACTIONS is not true");
    }
    let named = var(KEYCHAIN_ENV)
        .map(PathBuf::from)
        .ok_or("ZS_CI_KEYCHAIN is unset")?;
    let temp = var("RUNNER_TEMP")
        .map(PathBuf::from)
        .ok_or("RUNNER_TEMP is unset")?;
    let (Ok(path), Ok(temp)) = (fs::canonicalize(&named), fs::canonicalize(&temp)) else {
        return Err("the keychain or the runner temp directory does not exist");
    };
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
    let personal = var("HOME").is_some_and(|home| {
        let home = fs::canonicalize(&home).unwrap_or_else(|_| PathBuf::from(home));
        path.starts_with(home.join("Library").join("Keychains"))
    });
    if !named.is_absolute()
        || !path.is_file()
        || temp.parent().is_none()
        || !path.starts_with(&temp)
        || !name.ends_with(".keychain-db")
        || name.starts_with("login.")
        || personal
    {
        return Err("ZS_CI_KEYCHAIN is not a keychain file under RUNNER_TEMP");
    }
    Ok(path)
}

pub fn disposable_keychain() -> PathBuf {
    let path =
        disposable_path(|name| std::env::var_os(name)).unwrap_or_else(|reason| refuse(reason));
    // No `security` call may run before the environment checks above pass.
    if preference(["default-keychain", "-d", "user"]) != [path.clone()] {
        refuse("the user default keychain is not the disposable keychain");
    }
    let search = preference(["list-keychains", "-d", "user"]);
    if !search.contains(&path)
        || search
            .iter()
            .any(|entry| *entry != path && entry != Path::new(SYSTEM_KEYCHAIN))
    {
        refuse("the user keychain search list holds another keychain");
    }
    VERIFIED.store(true, Ordering::SeqCst);
    path
}

pub fn require_verified() {
    assert!(
        VERIFIED.load(Ordering::SeqCst),
        "the disposable keychain interlock has not run"
    );
}

pub fn security<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    require_verified();
    run(arguments(args))
}

pub fn is_exact(name: &str) -> bool {
    (1..=NAME_LIMIT).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn exact(name: &str) -> &str {
    assert!(is_exact(name), "fixture item name is not exact");
    name
}

fn lookup_status(status: ExitStatus) -> Option<bool> {
    if status.success() {
        Some(true)
    } else if status.code() == Some(ITEM_NOT_FOUND) {
        Some(false)
    } else {
        None
    }
}

fn lookup(account: &str, service: &str) -> Option<bool> {
    lookup_status(
        security([
            "find-generic-password",
            "-a",
            exact(account),
            "-s",
            exact(service),
        ])
        .status,
    )
}

pub fn exists(account: &str, service: &str) -> bool {
    lookup(account, service).expect("Keychain lookup failed")
}

pub fn delete_exact(account: &str, service: &str) -> bool {
    if !is_exact(account) || !is_exact(service) {
        return false;
    }
    for _ in 0..4 {
        match lookup(account, service) {
            Some(false) => return true,
            Some(true) => {
                let deleted = security(["delete-generic-password", "-a", account, "-s", service]);
                if !deleted.status.success() {
                    return false;
                }
            }
            None => return false,
        }
    }
    false
}

pub fn attributes(account: &str, service: &str) -> Vec<String> {
    let output = security([
        "find-generic-password",
        "-a",
        exact(account),
        "-s",
        exact(service),
    ]);
    assert!(output.status.success(), "Keychain item is missing");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| line.trim().to_owned())
        .collect()
}

pub fn keychain_of(attributes: &[String]) -> Option<PathBuf> {
    attributes.iter().find_map(|line| {
        let path = line.strip_prefix("keychain: \"")?.strip_suffix('"')?;
        Some(fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path)))
    })
}

pub fn has_attribute(attributes: &[String], name: &str, value: &OsStr) -> bool {
    let mut expected = format!("\"{name}\"<blob>=\"").into_bytes();
    expected.extend_from_slice(value.as_bytes());
    expected.push(b'"');
    attributes
        .iter()
        .any(|line| line.as_bytes() == expected.as_slice())
}

pub fn password_output(account: &str, service: &str) -> Option<Vec<u8>> {
    let output = security([
        "find-generic-password",
        "-a",
        exact(account),
        "-s",
        exact(service),
        "-w",
    ]);
    output.status.success().then_some(output.stdout)
}

pub fn plant(account: &str, service: &str, value: &[u8]) {
    let output = security([
        OsStr::new("add-generic-password"),
        OsStr::new("-a"),
        OsStr::new(exact(account)),
        OsStr::new("-s"),
        OsStr::new(exact(service)),
        OsStr::new("-w"),
        OsStr::from_bytes(value),
    ]);
    assert!(output.status.success(), "planting a Keychain item failed");
}

pub fn plant_legacy(label: &str, owner: &Path, key_pem: &str) {
    let mut comment = OsString::from("zerosecret-ca-dir:");
    comment.push(owner.as_os_str());
    let output = security([
        OsStr::new("add-generic-password"),
        OsStr::new("-a"),
        OsStr::new(exact(label)),
        OsStr::new("-s"),
        OsStr::new(label),
        OsStr::new("-w"),
        OsStr::new(key_pem),
        OsStr::new("-U"),
        OsStr::new("-j"),
        &comment,
    ]);
    assert!(output.status.success(), "planting a legacy item failed");
}

pub struct Locked {
    keychain: PathBuf,
    password: OsString,
}

fn password() -> OsString {
    let Some(path) = std::env::var_os(PASSWORD_FILE_ENV) else {
        refuse("ZS_CI_KEYCHAIN_PASSWORD_FILE is unset");
    };
    let private = fs::metadata(&path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o077 == 0);
    if !private {
        refuse("the keychain password file is missing or readable by others");
    }
    let mut bytes = fs::read(&path).unwrap_or_else(|_| refuse("the password file is unreadable"));
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() {
        refuse("the keychain password file is empty");
    }
    OsString::from_vec(bytes)
}

impl Locked {
    pub fn new(keychain: &Path) -> Self {
        let locked = Self {
            keychain: keychain.to_path_buf(),
            password: password(),
        };
        let output = security([OsStr::new("lock-keychain"), keychain.as_os_str()]);
        assert!(output.status.success(), "locking the keychain failed");
        locked
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        let unlocked = security([
            OsStr::new("unlock-keychain"),
            OsStr::new("-p"),
            &self.password,
            self.keychain.as_os_str(),
        ])
        .status
        .success();
        if !unlocked && !std::thread::panicking() {
            panic!("the disposable keychain did not unlock");
        }
    }
}

pub enum Item {
    Record(String),
    Legacy(String),
    Directory(PathBuf),
}

pub struct Cleanup(pub Vec<Item>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let mut clean = true;
        for item in &self.0 {
            let (account, service) = match item {
                Item::Record(account) => (Some(account.clone()), SERVICE.to_owned()),
                Item::Legacy(label) => (Some(label.clone()), label.clone()),
                Item::Directory(dir) => (
                    fs::read_to_string(dir.join(ID_FILE)).ok(),
                    SERVICE.to_owned(),
                ),
            };
            if let Some(account) = account {
                clean &= delete_exact(&account, &service);
            }
        }
        if !clean && !std::thread::panicking() {
            panic!("native CA fixture cleanup failed");
        }
    }
}
