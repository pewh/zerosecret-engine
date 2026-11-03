#![cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[cfg(target_os = "macos")]
use zs_test_keychain as disposable;

use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::atomic::Ordering;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

use common::clean_command;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use common::native_store::Store;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use common::random_hex;
use zs_mitm::LocalCa;

#[cfg(target_os = "macos")]
use macos::Store;

const MARKER: &str = "ZS_TEST_CHILD_MARKER";
const STARTED: &str = "started";
const CERT_FILE: &str = "ca.crt";
const KEY_FILE: &str = "ca.key.pem";
const ID_FILE: &str = ".ca-storage-id";
const LOCK_FILE: &str = ".ca-storage.lock";
const REFUSED: &str = "zs: local ca: ca storage: ";
const UNAVAILABLE: &str = "secure CA storage unavailable";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const LOCKED: &str = "secure CA storage locked";
const HOST: &str = "api.stripe.com";

#[test]
fn child_writes_marker() {
    let Some(path) = std::env::var_os(MARKER) else {
        return;
    };
    std::fs::write(path, STARTED).unwrap();
    let _ = std::io::stdin().read_to_end(&mut Vec::new());
}

fn legacy_ca(dir: &Path) -> Vec<u8> {
    LocalCa::load_or_create(dir).unwrap();
    std::fs::read(dir.join(CERT_FILE)).unwrap()
}

struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".zs-credentials")).unwrap();
        std::fs::write(
            dir.path().join("zs-policy.json"),
            r#"{"bindings":[],"signing_keys":[],"grants":[]}"#,
        )
        .unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn ca_dir(&self) -> PathBuf {
        self.path().join(".zs-ca")
    }

    fn ca(&self, name: &str) -> PathBuf {
        self.ca_dir().join(name)
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.ca(name)).unwrap()
    }

    fn account(&self) -> String {
        std::fs::read_to_string(self.ca(ID_FILE)).unwrap()
    }

    fn files(&self) -> Vec<&'static str> {
        [CERT_FILE, KEY_FILE, ID_FILE]
            .into_iter()
            .filter(|name| self.ca(name).exists())
            .collect()
    }

    fn snapshot(&self) -> Vec<Option<Vec<u8>>> {
        [CERT_FILE, KEY_FILE, ID_FILE]
            .into_iter()
            .map(|name| std::fs::read(self.ca(name)).ok())
            .collect()
    }

    fn changed(&self, before: &[Option<Vec<u8>>]) -> Vec<&'static str> {
        [CERT_FILE, KEY_FILE, ID_FILE]
            .into_iter()
            .zip(self.snapshot())
            .zip(before)
            .filter(|((_, now), then)| now != *then)
            .map(|((name, _), _)| name)
            .collect()
    }

    fn marker(&self, name: &str) -> PathBuf {
        let marker = self.path().join(name);
        let _ = std::fs::remove_file(&marker);
        marker
    }

    fn agent(&self, store: &Store, marker: &Path) -> Command {
        self.agent_with_ca_arg(store, marker, self.ca_dir().as_os_str())
    }

    fn agent_with_ca_arg(&self, store: &Store, marker: &Path, ca_arg: &OsStr) -> Command {
        let home = self.path();
        let mut command = clean_command(common::bin_path());
        command
            .arg("run")
            .arg("--policy")
            .arg(home.join("zs-policy.json"))
            .arg("--credentials-dir")
            .arg(home.join(".zs-credentials"))
            .arg("--audit")
            .arg(home.join("audit.jsonl"))
            .arg("--ca-dir")
            .arg(ca_arg)
            .arg("--")
            .arg(std::env::current_exe().unwrap())
            .args(["child_writes_marker", "--exact", "--test-threads=1"])
            .env("ZS_HOME", home)
            .env("USER", common::default_subject())
            .env(MARKER, marker)
            .current_dir(home)
            .stdin(Stdio::null());
        store.session(&mut command);
        command
    }

    fn run(&self, store: &Store) -> Outcome {
        let marker = self.marker("child-marker");
        Outcome::new(self.agent(store, &marker).output().unwrap(), &marker)
    }

    fn retire(&self, store: &Store, confirmed: bool) -> Output {
        let mut command = clean_command(common::bin_path());
        command
            .args(["ca", "retire", "--ca-dir"])
            .arg(self.ca_dir())
            .env("ZS_HOME", self.path())
            .current_dir(self.path())
            .stdin(Stdio::null());
        if confirmed {
            command.arg("--yes");
        }
        store.session(&mut command);
        command.output().unwrap()
    }
}

struct Outcome {
    code: Option<i32>,
    stderr: String,
    marker: Option<Vec<u8>>,
}

impl Outcome {
    fn new(output: Output, marker: &Path) -> Self {
        Self {
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            marker: std::fs::read(marker).ok(),
        }
    }
}

fn assert_started(outcome: &Outcome) {
    assert!(
        outcome.code == Some(0) && outcome.marker.as_deref() == Some(STARTED.as_bytes()),
        "the agent did not start the child:\n{}",
        outcome.stderr
    );
}

fn without_diag_log_line(stderr: &str) -> String {
    stderr
        .split_inclusive('\n')
        .filter(|line| !line.starts_with("zs: diagnostic log "))
        .collect()
}

fn assert_refused(outcome: &Outcome, reason: &str) {
    let line = format!("{REFUSED}{reason}\n");
    assert!(
        outcome.code == Some(1) && without_diag_log_line(&outcome.stderr) == line,
        "expected only {line:?}:\n{}",
        outcome.stderr
    );
    assert!(
        outcome.marker.is_none(),
        "the child started after a CA storage failure"
    );
}

fn refused_without_mutation(ws: &Workspace, store: &Store, reason: &str) {
    let before = ws.snapshot();
    assert_refused(&ws.run(store), reason);
    let changed = ws.changed(&before);
    assert!(
        changed.is_empty(),
        "a refused start changed the CA directory: {changed:?}"
    );
}

struct Cleanup<'a> {
    store: &'a Store,
    ws: &'a Workspace,
}

impl<'a> Cleanup<'a> {
    fn new(store: &'a Store, ws: &'a Workspace) -> Self {
        Self { store, ws }
    }
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        let Ok(account) = std::fs::read_to_string(self.ws.ca(ID_FILE)) else {
            return;
        };
        if !self.store.remove(&account) && !std::thread::panicking() {
            panic!("native CA fixture cleanup failed");
        }
    }
}

struct RunningAgent {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    marker: PathBuf,
    proxy: String,
}

impl RunningAgent {
    fn start(ws: &Workspace, store: &Store) -> Self {
        let marker = ws.marker("running-marker");
        let mut child = ws
            .agent(store, &marker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        let proxy = loop {
            line.clear();
            if stdout.read_line(&mut line).unwrap() == 0 {
                drop(stdin);
                let output = child.wait_with_output().unwrap();
                panic!(
                    "the agent exited before its proxy started:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if let Some((_, addr)) = line.trim().split_once("zs: proxy ") {
                break addr.to_owned();
            }
        };
        Self {
            child,
            stdin,
            stdout,
            marker,
            proxy,
        }
    }

    fn request(&self, runtime: &tokio::runtime::Runtime, trusted: &[u8]) -> Result<String, String> {
        let trusted = String::from_utf8(trusted.to_vec()).unwrap();
        runtime
            .block_on(common::proxied_request(
                &self.proxy,
                &trusted,
                HOST,
                443,
                "/v1/customers",
            ))
            .map(|(status, _)| status)
    }

    fn finish(mut self) -> Outcome {
        drop(self.stdin.take());
        let _ = self.stdout.read_to_end(&mut Vec::new());
        Outcome::new(self.child.wait_with_output().unwrap(), &self.marker)
    }
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn available_store_starts_the_child_without_a_key_file() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    assert_started(&ws.run(&store));
    assert_eq!(ws.files(), [CERT_FILE, ID_FILE]);
    assert_eq!(store.stored(&ws.account()), 1);
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn legacy_file_key_migrates_to_the_same_identity() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    let certificate = legacy_ca(&ws.ca_dir());
    assert_eq!(ws.files(), [CERT_FILE, KEY_FILE]);
    assert_started(&ws.run(&store));
    assert_eq!(ws.files(), [CERT_FILE, ID_FILE]);
    assert!(ws.read(CERT_FILE) == certificate);
    assert_eq!(store.stored(&ws.account()), 1);
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn reload_preserves_identity_and_restores_the_certificate() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    assert_started(&ws.run(&store));
    let certificate = ws.read(CERT_FILE);
    let account = ws.account();

    assert_started(&ws.run(&store));
    assert!(ws.read(CERT_FILE) == certificate);
    assert_eq!(ws.account(), account);
    assert_eq!(store.stored(&account), 1);

    std::fs::remove_file(ws.ca(CERT_FILE)).unwrap();
    assert_started(&ws.run(&store));
    assert!(ws.read(CERT_FILE) == certificate);
    assert_eq!(ws.files(), [CERT_FILE, ID_FILE]);
    assert_eq!(store.stored(&account), 1);
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn corrupt_state_never_starts_the_child() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    assert_started(&ws.run(&store));
    let account = ws.account();
    std::fs::write(ws.ca(CERT_FILE), b"corrupt certificate").unwrap();
    refused_without_mutation(&ws, &store, "CA certificate invalid");
    assert_eq!(store.stored(&account), 1);

    let malformed = Workspace::new();
    let junk = "0123456789ABCDEF0123456789ABCDEF";
    std::fs::create_dir_all(malformed.ca_dir()).unwrap();
    std::fs::write(malformed.ca(ID_FILE), junk).unwrap();
    refused_without_mutation(&malformed, &store, "CA storage identity malformed");
    assert_eq!(store.stored(junk), 0);
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn mismatched_state_never_starts_the_child() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    assert_started(&ws.run(&store));
    let account = ws.account();
    let other = tempfile::tempdir().unwrap();
    std::fs::write(ws.ca(CERT_FILE), legacy_ca(other.path())).unwrap();
    refused_without_mutation(&ws, &store, "CA certificate mismatch");
    assert_eq!(store.stored(&account), 1);

    let pair = Workspace::new();
    legacy_ca(&pair.ca_dir());
    std::fs::copy(other.path().join(KEY_FILE), pair.ca(KEY_FILE)).unwrap();
    refused_without_mutation(&pair, &store, "CA legacy key mismatch");
    assert_eq!(pair.files(), [CERT_FILE, KEY_FILE]);
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn partial_state_never_starts_the_child() {
    let store = Store::new();
    let certificate_only = Workspace::new();
    legacy_ca(&certificate_only.ca_dir());
    std::fs::remove_file(certificate_only.ca(KEY_FILE)).unwrap();
    refused_without_mutation(&certificate_only, &store, "CA storage identity missing");
    assert_eq!(certificate_only.files(), [CERT_FILE]);

    let key_only = Workspace::new();
    legacy_ca(&key_only.ca_dir());
    std::fs::remove_file(key_only.ca(CERT_FILE)).unwrap();
    refused_without_mutation(&key_only, &store, "CA legacy identity incomplete");
    assert_eq!(key_only.files(), [KEY_FILE]);

    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    assert_started(&ws.run(&store));
    let account = ws.account();
    assert!(store.remove(&account));
    refused_without_mutation(&ws, &store, "CA private key missing");
    assert_eq!(ws.files(), [CERT_FILE, ID_FILE]);
    assert_eq!(store.stored(&account), 0);
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn concurrent_agents_serialize_on_the_directory_lock_and_converge() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    std::fs::create_dir_all(ws.ca_dir()).unwrap();
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(ws.ca(LOCK_FILE))
        .unwrap();
    held.try_lock().unwrap();
    assert_refused(&ws.run(&store), "CA storage busy");
    assert!(ws.files().is_empty());
    drop(held);

    let markers = [ws.marker("first-marker"), ws.marker("second-marker")];
    let agents: Vec<Child> = markers
        .iter()
        .map(|marker| {
            ws.agent(&store, marker)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let outcomes: Vec<Outcome> = agents
        .into_iter()
        .zip(&markers)
        .map(|(agent, marker)| Outcome::new(agent.wait_with_output().unwrap(), marker))
        .collect();
    for outcome in &outcomes {
        if outcome.code == Some(0) {
            assert_started(outcome);
        } else {
            assert_refused(outcome, "CA storage busy");
        }
    }
    assert!(outcomes.iter().any(|outcome| outcome.code == Some(0)));
    assert_eq!(ws.files(), [CERT_FILE, ID_FILE]);
    let certificate = ws.read(CERT_FILE);
    let account = ws.account();
    assert_eq!(store.stored(&account), 1);

    assert_started(&ws.run(&store));
    assert!(ws.read(CERT_FILE) == certificate);
    assert_eq!(ws.account(), account);
    assert_eq!(store.stored(&account), 1);
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn tls_trust_in_the_legacy_certificate_survives_migration_and_reload() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    let upstream = common::spawn_fake_upstream();
    common::write_test_setup(ws.path(), upstream.addr.port(), true, true);
    let trusted = legacy_ca(&ws.ca_dir());
    let other = tempfile::tempdir().unwrap();
    let untrusted = legacy_ca(other.path());
    let runtime = tokio::runtime::Runtime::new().unwrap();

    for _ in 0..2 {
        let agent = RunningAgent::start(&ws, &store);
        assert!(agent.request(&runtime, &untrusted).is_err());
        let status = agent.request(&runtime, &trusted).unwrap();
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert_started(&agent.finish());
        assert_eq!(ws.files(), [CERT_FILE, ID_FILE]);
        assert!(ws.read(CERT_FILE) == trusted);
    }
    assert_eq!(upstream.requests.load(Ordering::SeqCst), 2);
    assert_eq!(store.stored(&ws.account()), 1);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "runs the agent against native CA storage"]
fn locked_collection_never_starts_the_child() {
    let store = Store::new();
    let ws = Workspace::new();
    assert_started(&ws.run(&store));
    let account = ws.account();
    let fresh = Workspace::new();
    store.lock();
    refused_without_mutation(&ws, &store, LOCKED);
    assert_eq!(store.count(&account), (0, 1));
    refused_without_mutation(&fresh, &store, LOCKED);
    assert!(fresh.files().is_empty());
    assert_eq!(store.locked(), Some(true));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "runs the agent against native CA storage"]
fn unavailable_bus_never_starts_the_child() {
    let unreachable = Store::unreachable();
    let fresh = Workspace::new();
    refused_without_mutation(&fresh, &unreachable, UNAVAILABLE);
    assert!(fresh.files().is_empty());
    let legacy = Workspace::new();
    let certificate = legacy_ca(&legacy.ca_dir());
    refused_without_mutation(&legacy, &unreachable, UNAVAILABLE);
    assert_eq!(legacy.files(), [CERT_FILE, KEY_FILE]);

    let store = Store::new();
    let _cleanup = Cleanup::new(&store, &legacy);
    assert_started(&legacy.run(&store));
    assert!(legacy.read(CERT_FILE) == certificate);
    assert_eq!(legacy.files(), [CERT_FILE, ID_FILE]);
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "runs the agent against native CA storage"]
fn invalid_native_record_never_starts_the_child() {
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_PERSIST_SESSION,
    };

    let store = Store::new();
    let other = tempfile::tempdir().unwrap();
    let certificate = legacy_ca(other.path());
    for (persist, bytes, reason) in [
        (CRED_PERSIST_SESSION, b"ZSCA".as_slice(), UNAVAILABLE),
        (
            CRED_PERSIST_LOCAL_MACHINE,
            b"corrupt".as_slice(),
            "CA storage record malformed",
        ),
    ] {
        let ws = Workspace::new();
        let account = random_hex();
        std::fs::create_dir_all(ws.ca_dir()).unwrap();
        std::fs::write(ws.ca(ID_FILE), &account).unwrap();
        std::fs::write(ws.ca(CERT_FILE), &certificate).unwrap();
        let _cleanup = Cleanup::new(&store, &ws);
        store.plant(&account, persist, bytes);
        refused_without_mutation(&ws, &store, reason);
        assert_eq!(store.stored(&account), 1);
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the agent against native CA storage"]
fn legacy_keychain_item_migrates_to_the_same_identity() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    let upstream = common::spawn_fake_upstream();
    common::write_test_setup(ws.path(), upstream.addr.port(), true, true);
    let trusted = legacy_ca(&ws.ca_dir());
    let key = std::fs::read_to_string(ws.ca(KEY_FILE)).unwrap();
    std::fs::remove_file(ws.ca(KEY_FILE)).unwrap();
    let label = zs_mitm::keychain_label_for(ws.ca_dir());
    let _legacy = store.plant_legacy(&label, &ws.ca_dir(), &key);
    assert!(store.legacy(&label));
    assert_eq!(ws.files(), [CERT_FILE]);
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let agent = RunningAgent::start(&ws, &store);
    let status = agent.request(&runtime, &trusted).unwrap();
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_started(&agent.finish());
    assert_eq!(ws.files(), [CERT_FILE, ID_FILE]);
    assert!(ws.read(CERT_FILE) == trusted);
    let account = ws.account();
    assert_eq!(store.stored(&account), 1);
    assert!(!store.legacy(&label));

    assert_started(&ws.run(&store));
    assert!(ws.read(CERT_FILE) == trusted);
    assert_eq!(ws.account(), account);
    assert_eq!(store.stored(&account), 1);
    assert_eq!(upstream.requests.load(Ordering::SeqCst), 1);
}

#[cfg(target_os = "macos")]
const SHARED_DEFAULT_LABEL: &str = "zerosecret-local-ca-db1f16dd93727acd";

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the agent against native CA storage"]
fn shared_default_label_item_never_blocks_a_fresh_directory() {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(b".zs-ca");
    let hex: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        format!("{}-{hex}", zs_mitm::DEFAULT_KEYCHAIN_LABEL),
        SHARED_DEFAULT_LABEL
    );
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    let other = tempfile::tempdir().unwrap();
    legacy_ca(other.path());
    let key = std::fs::read_to_string(other.path().join(KEY_FILE)).unwrap();
    let _orphan = store.plant_legacy(SHARED_DEFAULT_LABEL, Path::new(".zs-ca"), &key);
    let planted = store.legacy_value(SHARED_DEFAULT_LABEL);
    assert!(planted.is_some());
    assert!(!ws.ca_dir().exists());

    let marker = ws.marker("child-marker");
    let output = ws
        .agent_with_ca_arg(&store, &marker, OsStr::new(".zs-ca"))
        .output()
        .unwrap();
    assert_started(&Outcome::new(output, &marker));
    assert_eq!(ws.files(), [CERT_FILE, ID_FILE]);
    let account = ws.account();
    assert_eq!(store.stored(&account), 1);
    assert!(
        store.legacy_value(SHARED_DEFAULT_LABEL) == planted,
        "the agent changed the shared pre-record item"
    );

    let certificate = ws.read(CERT_FILE);
    assert_started(&ws.run(&store));
    assert!(ws.read(CERT_FILE) == certificate);
    assert_eq!(ws.account(), account);
    assert!(store.legacy_value(SHARED_DEFAULT_LABEL) == planted);
}

#[cfg(target_os = "macos")]
// Must match `LOCK_CHECK_TIMEOUT` in crates/zs-mitm/src/ca/platform/macos.rs.
const SHIPPED_LOCK_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(target_os = "macos")]
fn refused_while_locked(ws: &Workspace, store: &Store) {
    let before = ws.snapshot();
    let marker = ws.marker("child-marker");
    let started = Instant::now();
    let mut agent = ws
        .agent(store, &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = agent.stderr.take().unwrap();
    let reading = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    let status = loop {
        if let Some(status) = agent.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(30) {
            let _ = agent.kill();
            let _ = agent.wait();
            panic!("the agent waited on a locked keychain");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let elapsed = started.elapsed();
    let output = Output {
        status,
        stdout: Vec::new(),
        stderr: reading.join().unwrap(),
    };
    assert_refused(&Outcome::new(output, &marker), LOCKED);
    println!(
        "locked keychain: the agent refused in {} ms",
        elapsed.as_millis()
    );
    assert!(
        elapsed < 2 * SHIPPED_LOCK_CHECK_TIMEOUT,
        "the locked keychain refused only after {} ms",
        elapsed.as_millis()
    );
    let changed = ws.changed(&before);
    assert!(
        changed.is_empty(),
        "a refused start changed the CA directory: {changed:?}"
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the agent against native CA storage"]
fn locked_keychain_never_starts_the_child() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    assert_started(&ws.run(&store));
    let account = ws.account();
    let certificate = ws.read(CERT_FILE);
    let fresh = Workspace::new();
    let _fresh_cleanup = Cleanup::new(&store, &fresh);
    {
        let _locked = store.lock();
        refused_while_locked(&ws, &store);
        refused_while_locked(&fresh, &store);
        assert!(!fresh.ca_dir().exists());
    }
    assert_eq!(store.stored(&account), 1);

    assert_started(&ws.run(&store));
    assert!(ws.read(CERT_FILE) == certificate);
    assert_eq!(ws.account(), account);
    assert_eq!(store.stored(&account), 1);

    assert_started(&fresh.run(&store));
    assert_eq!(fresh.files(), [CERT_FILE, ID_FILE]);
    assert_eq!(store.stored(&fresh.account()), 1);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the agent against native CA storage"]
fn keychain_timeout_setting_is_checked_before_any_keychain_call() {
    let store = Store::new();
    let ws = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    for value in ["0", "301", "5s", "sk_live_must_not_echo"] {
        let marker = ws.marker("child-marker");
        let output = ws
            .agent(&store, &marker)
            .env("ZS_KEYCHAIN_TIMEOUT_SECS", value)
            .output()
            .unwrap();
        assert_refused(&Outcome::new(output, &marker), "CA storage timeout invalid");
        assert!(!ws.ca_dir().exists());
    }
    let marker = ws.marker("child-marker");
    let output = ws
        .agent(&store, &marker)
        .env("ZS_KEYCHAIN_TIMEOUT_SECS", "10")
        .output()
        .unwrap();
    assert_started(&Outcome::new(output, &marker));
    assert_eq!(store.stored(&ws.account()), 1);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "runs the agent against native CA storage"]
fn invalid_native_record_never_starts_the_child() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD_NO_PAD;

    let store = Store::new();
    let other = tempfile::tempdir().unwrap();
    let certificate = legacy_ca(other.path());
    let unprefixed = b"corrupt".to_vec();
    let undecodable = format!("zsca1:{}", STANDARD_NO_PAD.encode(b"corrupt")).into_bytes();
    for (value, reason) in [
        (unprefixed, UNAVAILABLE),
        (undecodable, "CA storage record malformed"),
    ] {
        let ws = Workspace::new();
        let account = random_hex();
        std::fs::create_dir_all(ws.ca_dir()).unwrap();
        std::fs::write(ws.ca(ID_FILE), &account).unwrap();
        std::fs::write(ws.ca(CERT_FILE), &certificate).unwrap();
        let _cleanup = Cleanup::new(&store, &ws);
        store.plant(&account, &value);
        let planted = store.value(&account);
        assert!(planted.is_some());
        refused_without_mutation(&ws, &store, reason);
        assert_eq!(store.stored(&account), 1);
        assert!(
            store.value(&account) == planted,
            "a refused start changed the native record"
        );
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
#[ignore = "runs the agent against native CA storage"]
fn test_home_cleanup_removes_exactly_its_own_record() {
    let store = Store::new();
    let kept = Workspace::new();
    let _cleanup = Cleanup::new(&store, &kept);
    assert_started(&kept.run(&store));
    let kept_account = kept.account();
    let exe = std::env::current_exe().unwrap();
    let child = [
        exe.to_str().unwrap(),
        "child_writes_marker",
        "--exact",
        "--test-threads=1",
    ];
    assert!(std::env::var_os(MARKER).is_none());
    let started = |home: &common::TestHome| {
        let (policy, creds, audit, ca_dir, _) =
            common::write_test_setup(home.path(), common::free_port(), true, true);
        common::spawn_agent_capturing(
            &common::bin_path(),
            &policy,
            &creds,
            &audit,
            &ca_dir,
            &child,
        )
        .unwrap();
        std::fs::read_to_string(ca_dir.join(ID_FILE)).unwrap()
    };

    let home = common::TestHome::new(".zs-ca");
    let account = started(&home);
    assert_eq!(store.stored(&account), 1);
    drop(home);
    assert_eq!(store.stored(&account), 0);

    let absent = common::TestHome::new(".zs-ca");
    let account = started(&absent);
    assert!(store.remove(&account));
    drop(absent);
    drop(common::TestHome::new(".zs-ca"));

    let inexact = common::TestHome::new(".zs-ca");
    let ca_dir = inexact.path().join(".zs-ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
    std::fs::write(ca_dir.join(ID_FILE), "0123456789ABCDEF0123456789ABCDEF").unwrap();
    assert!(std::panic::catch_unwind(move || drop(inexact)).is_err());
    assert_eq!(store.stored(&kept_account), 1);
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn retire_removes_exactly_the_directory_record() {
    let store = Store::new();
    let ws = Workspace::new();
    let other = Workspace::new();
    let _cleanup = Cleanup::new(&store, &ws);
    let _other = Cleanup::new(&store, &other);
    assert_started(&ws.run(&store));
    assert_started(&other.run(&store));
    let account = ws.account();
    let kept = other.account();

    let unconfirmed = ws.retire(&store, false);
    assert_eq!(unconfirmed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unconfirmed.stderr).contains("--yes"));
    assert_eq!(store.stored(&account), 1);
    assert_eq!(ws.files(), [CERT_FILE, ID_FILE]);

    let retired = ws.retire(&store, true);
    assert_eq!(
        String::from_utf8_lossy(&retired.stdout),
        format!(
            "zs: retired CA directory {}: native record, ca.crt and .ca-storage-id removed\n",
            ws.ca_dir().display()
        )
    );
    assert_eq!(retired.status.code(), Some(0));
    assert!(retired.stderr.is_empty());
    assert_eq!(store.stored(&account), 0);
    assert!(ws.files().is_empty());
    assert_eq!(store.stored(&kept), 1);
    assert_eq!(other.files(), [CERT_FILE, ID_FILE]);

    let again = ws.retire(&store, true);
    assert_eq!(again.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&again.stderr),
        format!("{REFUSED}CA storage identity missing\n")
    );

    assert_started(&ws.run(&store));
    assert_ne!(ws.account(), account);
    assert_eq!(store.stored(&ws.account()), 1);
}

#[cfg(target_os = "macos")]
mod macos {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::disposable::{self, Cleanup, Item, Locked, SERVICE};

    pub struct Store {
        keychain: PathBuf,
    }

    impl Store {
        pub fn new() -> Self {
            Self {
                keychain: disposable::disposable_keychain(),
            }
        }

        pub fn session<'a>(&self, command: &'a mut Command) -> &'a mut Command {
            if let Some(home) = std::env::var_os("HOME") {
                command.env("HOME", home);
            }
            command
        }

        pub fn stored(&self, account: &str) -> usize {
            if !disposable::exists(account, SERVICE) {
                return 0;
            }
            let found = disposable::keychain_of(&disposable::attributes(account, SERVICE));
            assert!(
                found.as_deref() == Some(self.keychain.as_path()),
                "the CA record is outside the disposable keychain"
            );
            1
        }

        pub fn remove(&self, account: &str) -> bool {
            disposable::delete_exact(account, SERVICE)
        }

        pub fn value(&self, account: &str) -> Option<Vec<u8>> {
            disposable::password_output(account, SERVICE)
        }

        pub fn plant(&self, account: &str, value: &[u8]) {
            disposable::plant(account, SERVICE, value);
        }

        pub fn legacy(&self, label: &str) -> bool {
            disposable::exists(label, label)
        }

        pub fn legacy_value(&self, label: &str) -> Option<Vec<u8>> {
            disposable::password_output(label, label)
        }

        pub fn plant_legacy(&self, label: &str, owner: &Path, key_pem: &str) -> Cleanup {
            let cleanup = Cleanup(vec![Item::Legacy(label.to_owned())]);
            disposable::plant_legacy(label, owner, key_pem);
            cleanup
        }

        pub fn lock(&self) -> Locked {
            Locked::new(&self.keychain)
        }
    }
}
