#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use dbus_secret_service::{EncryptionType, Error, SecretService};
use rand::RngCore;
use rand::rngs::OsRng;

use super::linux::{
    CONTENT_TYPE, LABEL, attributes, bounded, delete_record, read_record, unique, write_new,
};
use super::record::MAX_RECORD_LEN;
use super::tests::{
    ACCOUNT, CERT_FILE, Fixture, ID_FILE, KEY_FILE, KEY_MISSING, LOCKED, MALFORMED, UNAVAILABLE,
    assert_redacted, encoded, generated, handshake_succeeds, same_identity,
};
use super::{load, retire};

const ROLE: &str = "ZS_NATIVE_CA_ROLE";
const PRIVATE_BUS: &str = "private-bus";
const MISSING_BUS: &str = "missing-bus";
const BUS_SOCKET: &str = "bus";

fn random_hex() -> String {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn connect() -> Result<SecretService, Error> {
    SecretService::connect_with_max_prompt_timeout(EncryptionType::Dh, 0)
}

fn count(account: &str) -> Result<(usize, usize), Error> {
    let service = connect()?;
    let found = service.search_items(attributes(account))?;
    Ok((found.unlocked.len(), found.locked.len()))
}

fn stored_items(account: &str) -> (usize, usize) {
    count(account).unwrap()
}

fn plant(account: &str, secret: &[u8]) {
    let service = connect().unwrap();
    let collection = service.get_default_collection().unwrap();
    collection
        .create_item(LABEL, attributes(account), secret, false, CONTENT_TYPE)
        .unwrap();
}

fn delete_exact(account: &str) -> Result<(), Error> {
    let service = connect()?;
    let found = service.search_items(attributes(account))?;
    for item in found.unlocked.iter().chain(&found.locked) {
        item.delete()?;
    }
    Ok(())
}

fn files(f: &Fixture) -> Vec<&'static str> {
    [CERT_FILE, KEY_FILE, ID_FILE]
        .into_iter()
        .filter(|name| f.path(name).exists())
        .collect()
}

fn wait_until<F: FnMut() -> bool>(mut ready: F) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "native fixture did not become ready"
        );
        sleep(Duration::from_millis(50));
    }
}

fn dbus_send(address: &str, args: &[&str]) -> String {
    Command::new("dbus-send")
        .arg(format!("--bus={address}"))
        .arg("--print-reply")
        .args(args)
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

fn has_owner(address: &str, name: &str) -> bool {
    dbus_send(
        address,
        &[
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            &format!("string:{name}"),
        ],
    )
    .contains("boolean true")
}

fn default_collection_unlocked(address: &str) -> bool {
    let alias = dbus_send(
        address,
        &[
            "--dest=org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service.ReadAlias",
            "string:default",
        ],
    );
    let Some(path) = alias.lines().find_map(|line| {
        line.trim()
            .strip_prefix("object path \"")?
            .strip_suffix('"')
            .filter(|path| *path != "/")
    }) else {
        return false;
    };
    dbus_send(
        address,
        &[
            "--dest=org.freedesktop.secrets",
            path,
            "org.freedesktop.DBus.Properties.Get",
            "string:org.freedesktop.Secret.Collection",
            "string:Locked",
        ],
    )
    .contains("boolean false")
}

fn isolate<'a>(command: &'a mut Command, root: &Path) -> &'a mut Command {
    let data = root.join("data");
    command
        .env("HOME", root)
        .env("XDG_RUNTIME_DIR", root)
        .env("XDG_DATA_HOME", &data)
        .env("XDG_CONFIG_HOME", &data)
        .env("XDG_CACHE_HOME", &data)
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("GNOME_KEYRING_CONTROL")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("data")).unwrap();
    root
}

struct PrivateBus {
    daemon: Child,
    keyring: Option<Child>,
    address: String,
    root: tempfile::TempDir,
}

impl PrivateBus {
    fn start() -> Self {
        let root = private_root();
        let socket = root.path().join(BUS_SOCKET);
        let mut daemon = isolate(&mut Command::new("dbus-daemon"), root.path())
            .args(["--session", "--nofork", "--print-address"])
            .arg(format!("--address=unix:path={}", socket.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut address = String::new();
        let printed = daemon
            .stdout
            .take()
            .map(|stdout| BufReader::new(stdout).read_line(&mut address));
        let mut bus = Self {
            daemon,
            keyring: None,
            address: address.trim().to_owned(),
            root,
        };
        assert!(matches!(printed, Some(Ok(len)) if len > 0));
        assert!(
            bus.address
                .starts_with(&format!("unix:path={},", socket.display()))
        );

        let mut keyring = isolate(&mut Command::new("gnome-keyring-daemon"), bus.root.path())
            .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
            .args(["--foreground", "--unlock", "--components=secrets"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let unlock = keyring
            .stdin
            .take()
            .map(|mut stdin| stdin.write_all(random_hex().as_bytes()));
        bus.keyring = Some(keyring);
        assert!(matches!(unlock, Some(Ok(()))));
        wait_until(|| {
            has_owner(&bus.address, "org.freedesktop.secrets")
                && default_collection_unlocked(&bus.address)
        });
        bus
    }

    fn run(&self, function: &str) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        isolate(&mut command, self.root.path()).env("DBUS_SESSION_BUS_ADDRESS", &self.address);
        run_child(command, PRIVATE_BUS, function);
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        for child in self.keyring.iter_mut().chain([&mut self.daemon]) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_missing_bus(function: &str) {
    let root = private_root();
    let address = format!("unix:path={}", root.path().join(MISSING_BUS).display());
    let mut command = Command::new(std::env::current_exe().unwrap());
    isolate(&mut command, root.path()).env("DBUS_SESSION_BUS_ADDRESS", address);
    run_child(command, MISSING_BUS, function);
}

fn test_path(function: &str) -> String {
    let module = module_path!();
    let module = module.split_once("::").map_or(module, |(_, rest)| rest);
    format!("{module}::{function}")
}

fn run_child(mut command: Command, role: &str, function: &str) {
    let output = command
        .args([
            test_path(function).as_str(),
            "--exact",
            "--ignored",
            "--test-threads=1",
        ])
        .env(ROLE, role)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{role} child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn role() -> Option<String> {
    std::env::var(ROLE).ok()
}

fn session_address() -> String {
    std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap()
}

fn assert_private_session(socket: &str) {
    let home = std::env::var("HOME").unwrap();
    let address = session_address();
    let expected = format!("unix:path={home}/{socket}");
    assert!(address == expected || address.starts_with(&format!("{expected},")));
}

fn native(function: &str, body: fn()) {
    match role().as_deref() {
        Some(PRIVATE_BUS) => {
            assert_private_session(BUS_SOCKET);
            body();
        }
        Some(_) => panic!("unexpected native test role"),
        None => PrivateBus::start().run(function),
    }
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
        let clean = delete_exact(&account).is_ok() && count(&account).is_ok_and(|n| n == (0, 0));
        if !clean && !std::thread::panicking() {
            panic!("native CA fixture cleanup failed");
        }
    }
}

struct Monitor {
    child: Child,
    address: String,
    log: PathBuf,
    _dir: tempfile::TempDir,
}

impl Monitor {
    fn start() -> Self {
        let address = session_address();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("monitor.log");
        let child = Command::new("dbus-monitor")
            .args(["--address", &address])
            .stdout(fs::File::create(&log).unwrap())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let monitor = Self {
            child,
            address,
            log,
            _dir: dir,
        };
        wait_until(|| monitor.traffic().contains("member=NameLost"));
        monitor
    }

    fn traffic(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn finish(self) -> String {
        let marker = random_hex();
        has_owner(&self.address, &marker);
        wait_until(|| self.traffic().contains(&marker));
        self.traffic()
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn byte_arrays(traffic: &str) -> Vec<Vec<u8>> {
    let mut arrays = Vec::new();
    let mut current: Option<Vec<u8>> = None;
    for line in traffic.lines() {
        let line = line.trim();
        if line.ends_with("array of bytes [") {
            current = Some(Vec::new());
        } else if let Some(bytes) = current.as_mut() {
            if line == "]" {
                arrays.extend(current.take());
            } else {
                bytes.extend(
                    line.split_whitespace()
                        .filter_map(|pair| u8::from_str_radix(pair, 16).ok()),
                );
            }
        }
    }
    arrays
}

fn message<'a>(traffic: &'a str, member: &str) -> Vec<&'a str> {
    let marker = format!("member={member}");
    traffic
        .lines()
        .skip_while(|line| !line.contains(&marker))
        .enumerate()
        .take_while(|(index, line)| {
            *index == 0
                || !["method ", "signal ", "error "]
                    .iter()
                    .any(|start| line.starts_with(start))
        })
        .map(|(_, line)| line.trim())
        .collect()
}

fn has_entry(lines: &[&str], key: &str, value: &str) -> bool {
    let key = format!("string \"{key}\"");
    let value = format!("string \"{value}\"");
    lines
        .windows(2)
        .any(|pair| pair[0] == key && pair[1].ends_with(&value))
}

#[test]
fn linux_adapter_uses_exact_attributes() {
    assert_eq!(
        attributes(ACCOUNT),
        HashMap::from([
            ("service", "zerosecret.ca.v1"),
            ("account", ACCOUNT),
            ("schema", "1"),
        ])
    );
    assert_eq!(LABEL, "ZeroSecret local CA");
    assert_eq!(CONTENT_TYPE, "application/octet-stream");
}

#[test]
fn linux_adapter_only_zero_matches_is_absence() {
    assert!(matches!(unique::<u8>(Vec::new(), &[]), Ok(None)));
    assert!(matches!(unique(vec![7u8], &[]), Ok(Some(7))));
    assert_redacted(unique(vec![7u8, 8], &[]), UNAVAILABLE);
    assert_redacted(unique::<u8>(Vec::new(), &[7]), UNAVAILABLE);
    assert_redacted(unique(vec![7u8], &[8]), UNAVAILABLE);
}

#[test]
fn linux_adapter_bounds_record_bytes() {
    assert_redacted(bounded(Vec::new()), UNAVAILABLE);
    assert_redacted(bounded(vec![7; MAX_RECORD_LEN + 1]), UNAVAILABLE);
    assert_eq!(bounded(vec![7]).unwrap().0.len(), 1);
    assert_eq!(
        bounded(vec![7; MAX_RECORD_LEN]).unwrap().0.len(),
        MAX_RECORD_LEN
    );
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_round_trip() {
    native("native_ca_linux_round_trip", round_trip);
}

fn round_trip() {
    let account = random_hex();
    let _cleanup = Cleanup(Owner::Account(account.clone()));
    let bytes = encoded(&generated());
    write_new(&account, &bytes).unwrap();
    let stored = read_record(&account).unwrap().unwrap();
    assert!(stored.0.as_slice() == bytes.as_slice());

    let service = connect().unwrap();
    let found = service.search_items(attributes(&account)).unwrap();
    assert_eq!((found.unlocked.len(), found.locked.len()), (1, 0));
    let item = &found.unlocked[0];
    let seen = item.get_attributes().unwrap();
    assert!(
        attributes(&account)
            .into_iter()
            .all(|(key, value)| seen.get(key).map(String::as_str) == Some(value))
    );
    assert_eq!(item.get_label().unwrap(), LABEL);

    assert_redacted(write_new(&account, &bytes), UNAVAILABLE);
    assert_eq!(stored_items(&account), (1, 0));
    let again = read_record(&account).unwrap().unwrap();
    assert!(again.0.as_slice() == bytes.as_slice());
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_encrypted_create_only_wire_contract() {
    native(
        "native_ca_linux_encrypted_create_only_wire_contract",
        encrypted_create_only_wire_contract,
    );
}

fn encrypted_create_only_wire_contract() {
    let account = random_hex();
    let _cleanup = Cleanup(Owner::Account(account.clone()));
    let bytes = encoded(&generated());
    let monitor = Monitor::start();
    assert!(monitor.address == session_address());
    write_new(&account, &bytes).unwrap();
    let stored = read_record(&account).unwrap().unwrap();
    assert!(stored.0.as_slice() == bytes.as_slice());
    let traffic = monitor.finish();

    let session = message(&traffic, "OpenSession");
    assert!(session.contains(&"string \"dh-ietf1024-sha256-aes128-cbc-pkcs7\""));
    assert!(!traffic.contains("string \"plain\""));
    let create = message(&traffic, "CreateItem");
    assert_eq!(
        create.iter().filter(|line| **line == "dict entry(").count(),
        5
    );
    assert!(has_entry(
        &create,
        "org.freedesktop.Secret.Item.Label",
        LABEL
    ));
    for (key, value) in attributes(&account) {
        assert!(has_entry(&create, key, value));
    }
    assert!(create.contains(&format!("string \"{CONTENT_TYPE}\"").as_str()));
    assert_eq!(create.last(), Some(&"boolean false"));
    assert!(!message(&traffic, "GetSecret").is_empty());
    let arrays = byte_arrays(&traffic);
    let sealed = (bytes.len() / 16 + 1) * 16;
    assert!(arrays.iter().filter(|array| array.len() == sealed).count() >= 2);
    assert!(!arrays.iter().any(|array| {
        array
            .windows(bytes.len())
            .any(|window| window == bytes.as_slice())
    }));
    assert!(!traffic.contains("BEGIN"));
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_missing() {
    native("native_ca_linux_missing", missing);
}

fn missing() {
    let account = random_hex();
    let sibling = random_hex();
    let _cleanup = Cleanup(Owner::Account(sibling.clone()));
    write_new(&sibling, &encoded(&generated())).unwrap();
    assert!(read_record(&sibling).unwrap().is_some());
    assert!(read_record(&account).unwrap().is_none());
    assert_eq!(stored_items(&account), (0, 0));
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_duplicate_ambiguity() {
    native("native_ca_linux_duplicate_ambiguity", duplicate_ambiguity);
}

fn duplicate_ambiguity() {
    let account = random_hex();
    let _cleanup = Cleanup(Owner::Account(account.clone()));
    let ca = generated();
    let bytes = encoded(&ca);
    plant(&account, &bytes);
    assert!(read_record(&account).unwrap().is_some());
    plant(&account, &bytes);
    assert_eq!(stored_items(&account), (2, 0));

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
    assert_eq!(stored_items(&account), (2, 0));
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_locked_default_collection_without_prompt() {
    native(
        "native_ca_linux_locked_default_collection_without_prompt",
        locked_default_collection_without_prompt,
    );
}

fn locked_default_collection_without_prompt() {
    let service = connect().unwrap();
    let collection = service.get_default_collection().unwrap();
    let account = random_hex();
    let other = random_hex();
    let bytes = encoded(&generated());
    write_new(&account, &bytes).unwrap();
    assert!(read_record(&account).unwrap().is_some());
    collection.lock().unwrap();
    assert!(collection.is_locked().unwrap());

    let f = Fixture::new();
    let started = Instant::now();
    assert_redacted(read_record(&account), LOCKED);
    assert_redacted(write_new(&other, &bytes), LOCKED);
    assert_redacted(delete_record(&account), LOCKED);
    assert_redacted(load(&f.dir), LOCKED);
    let stored = Fixture::new();
    stored.put(ID_FILE, account.as_bytes());
    assert_redacted(retire(&stored.dir), LOCKED);
    assert_eq!(files(&stored), [ID_FILE]);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(files(&f).is_empty());
    assert_eq!(stored_items(&account), (0, 1));
    assert_eq!(stored_items(&other), (0, 0));
    assert!(collection.is_locked().unwrap());
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_nonexistent_bus_unavailable() {
    let name = "native_ca_linux_nonexistent_bus_unavailable";
    match role().as_deref() {
        Some(MISSING_BUS) => missing_bus(),
        Some(_) => native(name, private_bus_absence),
        None => {
            native(name, private_bus_absence);
            run_missing_bus(name);
        }
    }
}

fn private_bus_absence() {
    assert!(read_record(&random_hex()).unwrap().is_none());
}

fn missing_bus() {
    assert_private_session(MISSING_BUS);
    let account = random_hex();
    assert_redacted(read_record(&account), UNAVAILABLE);
    assert_redacted(write_new(&account, &encoded(&generated())), UNAVAILABLE);

    let f = Fixture::new();
    assert_redacted(load(&f.dir), UNAVAILABLE);
    assert!(files(&f).is_empty());

    let ca = generated();
    let f = Fixture::new();
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    assert_redacted(load(&f.dir), UNAVAILABLE);
    assert_eq!(files(&f), [CERT_FILE, KEY_FILE]);
    assert!(f.file_key_is(&ca.private_key_pem));
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_oversized_record() {
    native("native_ca_linux_oversized_record", oversized_record);
}

fn oversized_record() {
    let limit = random_hex();
    let oversized = random_hex();
    let empty = random_hex();
    let _cleanup =
        [&limit, &oversized, &empty].map(|account| Cleanup(Owner::Account(account.clone())));
    let too_long = [b'Z'; MAX_RECORD_LEN + 1];
    assert_redacted(write_new(&oversized, &too_long), UNAVAILABLE);
    assert_redacted(write_new(&empty, &[]), UNAVAILABLE);
    assert_eq!(stored_items(&oversized), (0, 0));
    assert_eq!(stored_items(&empty), (0, 0));

    write_new(&limit, &[b'Z'; MAX_RECORD_LEN]).unwrap();
    assert_eq!(
        read_record(&limit).unwrap().unwrap().0.len(),
        MAX_RECORD_LEN
    );

    plant(&oversized, &too_long);
    plant(&empty, &[]);
    assert_redacted(read_record(&oversized), UNAVAILABLE);
    assert_redacted(read_record(&empty), UNAVAILABLE);
    assert_eq!(stored_items(&oversized), (1, 0));
    assert_eq!(stored_items(&empty), (1, 0));
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_malformed_record_denies_without_mutation() {
    native(
        "native_ca_linux_malformed_record_denies_without_mutation",
        malformed_record_denies_without_mutation,
    );
}

fn malformed_record_denies_without_mutation() {
    let account = random_hex();
    let _cleanup = Cleanup(Owner::Account(account.clone()));
    let ca = generated();
    let mut bytes = encoded(&ca);
    bytes[0] ^= 1;
    plant(&account, &bytes);
    let f = Fixture::new();
    f.put(ID_FILE, account.as_bytes());
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    assert_redacted(load(&f.dir), MALFORMED);
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert_eq!(stored_items(&account), (1, 0));
    let stored = read_record(&account).unwrap().unwrap();
    assert!(stored.0.as_slice() == bytes.as_slice());
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_migration() {
    native("native_ca_linux_migration", migration);
}

fn migration() {
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
    assert_eq!(stored_items(&account), (1, 0));
    let stored = read_record(&account).unwrap().unwrap();
    assert!(stored.0.as_slice() == encoded(&ca).as_slice());

    let reloaded = load(&f.dir).unwrap();
    assert!(same_identity(&reloaded, &ca));
    assert!(handshake_succeeds(&reloaded, &ca.certificate_pem));
    assert_eq!(f.account(), Some(account.clone()));
    assert_eq!(stored_items(&account), (1, 0));
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_reload() {
    native("native_ca_linux_reload", reload);
}

fn reload() {
    let f = Fixture::new();
    let _cleanup = Cleanup(Owner::Directory(f.dir.clone()));
    let created = load(&f.dir).unwrap();
    let account = f.account().unwrap();
    let certificate = f.certificate().unwrap();
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(stored_items(&account), (1, 0));
    assert!(handshake_succeeds(&created, &certificate));

    let reloaded = load(&f.dir).unwrap();
    assert!(reloaded.public_key_der() == created.public_key_der());
    assert!(handshake_succeeds(&reloaded, &certificate));
    assert_eq!(f.account(), Some(account.clone()));
    assert_eq!(stored_items(&account), (1, 0));

    fs::remove_file(f.path(CERT_FILE)).unwrap();
    let restored = load(&f.dir).unwrap();
    assert!(restored.public_key_der() == created.public_key_der());
    assert_eq!(f.certificate(), Some(certificate.clone()));
    assert_eq!(stored_items(&account), (1, 0));

    delete_exact(&account).unwrap();
    assert_redacted(load(&f.dir), KEY_MISSING);
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(f.certificate(), Some(certificate));
    assert_eq!(stored_items(&account), (0, 0));
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_exact_cleanup() {
    native("native_ca_linux_exact_cleanup", exact_cleanup);
}

fn exact_cleanup() {
    let kept = random_hex();
    let removed = random_hex();
    let bytes = encoded(&generated());
    let keep = Cleanup(Owner::Account(kept.clone()));
    write_new(&kept, &bytes).unwrap();
    {
        let _cleanup = Cleanup(Owner::Account(removed.clone()));
        write_new(&removed, &bytes).unwrap();
        assert_eq!(stored_items(&removed), (1, 0));
    }
    assert_eq!(stored_items(&removed), (0, 0));
    assert_eq!(stored_items(&kept), (1, 0));
    drop(keep);
    assert_eq!(stored_items(&kept), (0, 0));
}

#[test]
#[ignore = "spawns a private D-Bus session and gnome-keyring"]
fn native_ca_linux_retire() {
    native("native_ca_linux_retire", retire_exact);
}

fn retire_exact() {
    let f = Fixture::new();
    let neighbour = Fixture::new();
    let _cleanup = Cleanup(Owner::Directory(f.dir.clone()));
    let _neighbour = Cleanup(Owner::Directory(neighbour.dir.clone()));
    load(&f.dir).unwrap();
    load(&neighbour.dir).unwrap();
    let account = f.account().unwrap();
    let kept = neighbour.account().unwrap();
    assert_eq!(stored_items(&account), (1, 0));

    retire(&f.dir).unwrap();
    assert_eq!(stored_items(&account), (0, 0));
    assert!(files(&f).is_empty());
    assert_eq!(stored_items(&kept), (1, 0));
    assert_eq!(files(&neighbour), [CERT_FILE, ID_FILE]);
    assert!(delete_record(&account).is_ok());
    assert_redacted(retire(&f.dir), "CA storage identity missing");

    let ca = generated();
    let bytes = encoded(&ca);
    let duplicate = random_hex();
    let _duplicate = Cleanup(Owner::Account(duplicate.clone()));
    plant(&duplicate, &bytes);
    plant(&duplicate, &bytes);
    let ambiguous = Fixture::new();
    ambiguous.put(ID_FILE, duplicate.as_bytes());
    ambiguous.put(CERT_FILE, ca.certificate_pem.as_bytes());
    assert_redacted(retire(&ambiguous.dir), UNAVAILABLE);
    assert_redacted(delete_record(&duplicate), UNAVAILABLE);
    assert_eq!(stored_items(&duplicate), (2, 0));
    assert_eq!(files(&ambiguous), [CERT_FILE, ID_FILE]);

    load(&f.dir).unwrap();
    assert_ne!(f.account().unwrap(), account);
}
