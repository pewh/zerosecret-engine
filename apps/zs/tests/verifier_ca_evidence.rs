#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
use zs_test_keychain as disposable;

use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rand::RngCore;
use rand::rngs::OsRng;
use serde_json::Value;

use disposable::{Cleanup, Item, SERVICE};

const REQUIRED_VECTORS: [&str; 4] = [
    "child_environment",
    "child_files",
    "agent_listener",
    "agent_output",
];
const CHILD_MEMORY: &str = "child_memory";
const MEMORY_INCOMPLETE: &str = "forced core dumps are unavailable on this platform in v0";
const CREDENTIAL_REF: &str = "stripe-prod";
const CA_CERT: &str = "ca.crt";
const CA_KEY: &str = "ca.key.pem";
const ID_FILE: &str = ".ca-storage-id";
const VERIFIER_TIMEOUT: Duration = Duration::from_secs(180);
// curl honours `-q` only as the first argument; it keeps a runner's `~/.curlrc` out.
const WORKLOAD: &str = r#"#!/bin/sh
env > "$ZS_VERIFY_ENV_REPORT" || exit 3
code=$(/usr/bin/curl -q -sS --max-time 30 -o /dev/null -w '%{http_code}' https://api.stripe.com/v1/customers)
rc=$?
printf '%s %s' "$code" "$rc" > "$1"
"#;

// Deliberately no `Debug`, `Display` or equality, so no assertion macro can print it.
struct Synthetic(String);

impl Synthetic {
    fn fresh() -> Self {
        let mut raw = [0u8; 16];
        OsRng.fill_bytes(&mut raw);
        let hex: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
        Self(format!("sk_test_zsv_k6b_{hex}"))
    }

    fn found_in(&self, haystack: &[u8]) -> bool {
        let needle = self.0.as_bytes();
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn write_private(&self, path: &Path) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(self.0.as_bytes()).unwrap();
        let mode = file.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the credential file must be private");
    }
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn template_safe(path: &Path) -> String {
    let text = path.to_str().expect("fixture paths are UTF-8").to_owned();
    assert!(
        !text.contains([' ', '\t', '\'', '"']),
        "a fixture path would be split by the verifier's tokenizer"
    );
    text
}

fn verifier_binary() -> PathBuf {
    let path = common::bin_path().with_file_name("zs-verify");
    assert!(
        path.is_file(),
        "zs-verify is not built next to zs; run `cargo build --locked -p zs-verify` first"
    );
    path
}

/// The grant is signed over the upstream it authorises, so the port has to be chosen before the
/// grant is minted and handed to the verifier. The verifier binds it with `--upstream-port`.
fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("a probe socket binds");
    probe
        .local_addr()
        .expect("the probe socket has an address")
        .port()
}

struct Fixture {
    root: PathBuf,
    policy: PathBuf,
    creds: PathBuf,
    audit: PathBuf,
    work: PathBuf,
    tmp: PathBuf,
    ca_dir: PathBuf,
    workload: PathBuf,
    upstream_port: u16,
}

impl Fixture {
    fn new(root: &Path) -> Self {
        let upstream_port = free_port();
        let (policy, creds, audit, _, _) =
            common::write_test_setup(root, upstream_port, true, false);
        private_dir(&creds);
        let work = root.join("work");
        let tmp = root.join("tmp");
        std::fs::create_dir(&work).unwrap();
        std::fs::create_dir(&tmp).unwrap();
        let workload = root.join("workload.sh");
        std::fs::write(&workload, WORKLOAD).unwrap();
        std::fs::set_permissions(&workload, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            root: root.to_path_buf(),
            policy,
            creds,
            audit,
            ca_dir: work.join(".zs-ca"),
            work,
            tmp,
            workload,
            upstream_port,
        }
    }

    fn verify(&self, credential_file: &Path, status_file: &Path) -> Run {
        let agent = format!(
            "--agent-cmd={} run --policy {{POLICY_FILE}} --credentials-dir {{CREDS_DIR}} \
             --audit {{AUDIT_FILE}} --ca-dir {} --as default -- {{CHILD}}",
            template_safe(&common::bin_path()),
            template_safe(&self.ca_dir),
        );
        let child = format!(
            "--child-cmd={} {}",
            template_safe(&self.workload),
            template_safe(status_file),
        );
        let mut command = Command::new(verifier_binary());
        command
            .arg(format!("--policy-file={}", self.policy.display()))
            .arg(format!("--credential-file={}", credential_file.display()))
            .arg(format!("--creds-dir={}", template_safe(&self.creds)))
            .arg(format!("--audit-file={}", template_safe(&self.audit)))
            .arg(format!("--upstream-port={}", self.upstream_port))
            .arg(agent)
            .arg(child)
            .env_clear()
            .env("TMPDIR", &self.tmp)
            .env("ZS_HOME", &self.root)
            .env("USER", common::default_subject())
            .current_dir(&self.work)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in ["PATH", "HOME"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        Run::bounded(command)
    }

    fn account(&self) -> String {
        let account = std::fs::read_to_string(self.ca_dir.join(ID_FILE)).unwrap();
        assert!(
            account.len() == 32
                && account
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
            "the CA storage account is not 32 lowercase hex digits"
        );
        account
    }

    fn assert_secure_ca(&self, keychain: &Path) -> (String, Vec<u8>) {
        assert!(
            !self.ca_dir.join(CA_KEY).exists(),
            "secure CA startup wrote a key file"
        );
        let certificate = std::fs::read(self.ca_dir.join(CA_CERT)).unwrap();
        let account = self.account();
        assert!(
            disposable::exists(&account, SERVICE),
            "the CA record is missing"
        );
        assert_eq!(
            disposable::keychain_of(&disposable::attributes(&account, SERVICE)).as_deref(),
            Some(keychain),
            "the CA record is outside the disposable keychain"
        );
        (account, certificate)
    }
}

struct Run {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Run {
    fn bounded(mut command: Command) -> Self {
        let mut child = command.spawn().unwrap();
        let drain = |mut pipe: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let _ = pipe.read_to_end(&mut bytes);
                bytes
            })
        };
        let stdout = drain(Box::new(child.stdout.take().unwrap()));
        let stderr = drain(Box::new(child.stderr.take().unwrap()));
        let deadline = Instant::now() + VERIFIER_TIMEOUT;
        let status = loop {
            match child.try_wait().unwrap() {
                Some(status) => break status,
                None if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the verifier did not finish within {VERIFIER_TIMEOUT:?}");
                }
            }
        };
        Self {
            code: status.code(),
            stdout: stdout.join().unwrap(),
            stderr: stderr.join().unwrap(),
        }
    }

    fn assert_silent(&self, credentials: &[&Synthetic]) {
        for credential in credentials {
            assert!(
                !credential.found_in(&self.stdout) && !credential.found_in(&self.stderr),
                "the verifier's output contains a synthetic credential"
            );
        }
    }

    fn report(&self) -> Value {
        match serde_json::from_slice(&self.stdout) {
            Ok(report) => report,
            // Shown only after `assert_silent`: the verifier's diagnostics are fixed text.
            Err(_) => panic!(
                "the verifier printed no JSON report (exit {:?}): {}",
                self.code,
                String::from_utf8_lossy(&self.stderr)
            ),
        }
    }
}

fn summary(label: &str, code: Option<i32>, report: &Value) -> String {
    let decisions = &report["decisions"];
    let files = &report["vectors"]["child_files"];
    let mut out = format!(
        "verifier evidence [{label}]: exit={code:?} leaked={} upstream_requests={} \
         upstream_auth_ok={} upstream_auth_mismatch={} negative_control_rejected={} \
         files_scanned={} files_skipped={}",
        report["leaked"],
        decisions["upstream_requests"],
        decisions["upstream_auth_ok"],
        decisions["upstream_auth_mismatch"],
        decisions["negative_control_rejected"],
        files["files_scanned"],
        files["files_skipped"],
    );
    for name in REQUIRED_VECTORS.iter().chain([&CHILD_MEMORY]) {
        let vector = &report["vectors"][name];
        out.push_str(&format!(
            "\n  {name}: status={} found={}",
            vector["status"], vector["found"]
        ));
        if let Some(reason) = vector["reason"].as_str() {
            out.push_str(&format!(" reason={reason:?}"));
        }
    }
    out
}

fn assert_complete_and_clean(report: &Value) {
    assert_eq!(report["leaked"], false);
    assert_eq!(report["decisions"]["upstream_requests"], 1);
    assert_eq!(report["decisions"]["negative_control_rejected"], true);
    for name in REQUIRED_VECTORS {
        let vector = &report["vectors"][name];
        assert_eq!(vector["status"], "complete", "{name} is incomplete");
        assert_eq!(vector["found"], false, "{name} did not report clean");
    }
    let scanned = report["vectors"]["child_files"]["files_scanned"].as_u64();
    assert!(
        scanned.is_some_and(|scanned| scanned > 0),
        "the file scan read no file"
    );
    let memory = &report["vectors"][CHILD_MEMORY];
    assert_eq!(memory["status"], "incomplete");
    assert!(memory["found"].is_null(), "child memory must make no claim");
    assert_eq!(memory["reason"], MEMORY_INCOMPLETE);
    assert_eq!(
        report["incomplete"],
        serde_json::json!([MEMORY_INCOMPLETE]),
        "child memory must be the only incomplete vector"
    );
}

fn assert_child_got_200(status_file: &Path) {
    assert_eq!(
        std::fs::read_to_string(status_file).unwrap(),
        "200 0",
        "the workload's HTTPS request through the agent did not get HTTP 200 (status, exit)"
    );
}

#[test]
#[ignore = "runs the agent against native CA storage"]
fn hardened_verifier_passes_on_secure_ca_startup_and_discriminates_the_credential() {
    let keychain = disposable::disposable_keychain();
    let root = tempfile::tempdir().unwrap();
    let fixture = Fixture::new(root.path());
    // Must drop before `root`, so the storage ID is still readable when the record is deleted.
    let record = Cleanup(vec![Item::Directory(fixture.ca_dir.clone())]);

    let injected = Synthetic::fresh();
    let injected_file = fixture.creds.join(CREDENTIAL_REF);
    injected.write_private(&injected_file);
    let other = Synthetic::fresh();
    assert!(
        injected.0 != other.0,
        "the two synthetic credentials must differ"
    );
    let other_dir = fixture.root.join("verifier-only");
    private_dir(&other_dir);
    let other_file = other_dir.join("credential");
    other.write_private(&other_file);

    let status = fixture.root.join("status-positive");
    let positive = fixture.verify(&injected_file, &status);
    positive.assert_silent(&[&injected, &other]);
    let report = positive.report();
    println!("{}", summary("positive", positive.code, &report));
    assert_eq!(positive.code, Some(0), "the verifier did not pass");
    assert_complete_and_clean(&report);
    assert_eq!(report["decisions"]["upstream_auth_ok"], 1);
    assert_eq!(report["decisions"]["upstream_auth_mismatch"], 0);
    assert_child_got_200(&status);
    let (account, certificate) = fixture.assert_secure_ca(&keychain);

    let status = fixture.root.join("status-discrimination");
    let discrimination = fixture.verify(&other_file, &status);
    discrimination.assert_silent(&[&injected, &other]);
    let report = discrimination.report();
    println!(
        "{}",
        summary("discrimination", discrimination.code, &report)
    );
    assert_eq!(
        discrimination.code,
        Some(1),
        "a credential mismatch must fail the verdict"
    );
    assert_complete_and_clean(&report);
    assert_eq!(report["decisions"]["upstream_auth_ok"], 0);
    assert_eq!(report["decisions"]["upstream_auth_mismatch"], 1);
    assert_child_got_200(&status);
    let (reloaded, reloaded_certificate) = fixture.assert_secure_ca(&keychain);
    assert!(
        reloaded == account && reloaded_certificate == certificate,
        "the second start did not reload the same CA identity"
    );

    let audit = std::fs::read(&fixture.audit).unwrap();
    assert!(
        !injected.found_in(&audit) && !other.found_in(&audit),
        "the audit journal contains a synthetic credential"
    );

    drop(record);
    assert!(
        !disposable::exists(&account, SERVICE),
        "the CA record survived cleanup"
    );
    let removed = root.path().to_path_buf();
    root.close().unwrap();
    assert!(!removed.exists(), "the fixture directory survived cleanup");
}
