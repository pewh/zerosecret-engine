#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const VALID_TOKEN: &str = "sk_test_zs_only_this_exact_value_is_accepted";

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("zs")
}

struct Validating {
    port: u16,
    accepted: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
}

fn spawn_validating_upstream() -> Validating {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let rejected = Arc::new(AtomicUsize::new(0));
    let acc = accepted.clone();
    let rej = rejected.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let acc = acc.clone();
            let rej = rej.clone();
            std::thread::spawn(move || {
                loop {
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    loop {
                        match stream.read(&mut byte) {
                            Ok(0) | Err(_) => return,
                            Ok(_) => {}
                        }
                        buf.push(byte[0]);
                        if buf.ends_with(b"\r\n\r\n") || buf.len() > 65536 {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let presented = head
                        .lines()
                        .skip(1)
                        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                        .and_then(|l| l.split_once(':'))
                        .map(|(_, v)| v.trim().to_string())
                        .unwrap_or_default();

                    let ok = presented == format!("Bearer {VALID_TOKEN}");
                    if ok {
                        acc.fetch_add(1, Ordering::SeqCst);
                        let body = br#"{"authenticated":true,"object":"list"}"#;
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n");
                        let _ = stream.write_all(
                            format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes(),
                        );
                        let _ = stream.write_all(body);
                    } else {
                        rej.fetch_add(1, Ordering::SeqCst);
                        let body = br#"{"error":"invalid_api_key"}"#;
                        let _ = stream.write_all(
                            b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n",
                        );
                        let _ = stream.write_all(
                            format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes(),
                        );
                        let _ = stream.write_all(body);
                    }
                    let _ = stream.flush();
                }
            });
        }
    });

    Validating {
        port,
        accepted,
        rejected,
    }
}

fn workspace(upstream_port: u16, credential: &str) -> common::TestHome {
    let dir = common::TestHome::new(".zs-ca");
    let creds = dir.path().join(".zs-credentials");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("stripe-prod"), credential).unwrap();

    let signing = zs_grant::ControlSigningKey::generate("test-k1");
    let verifying_hex: String = signing
        .verifying_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let connection = common::loopback_connection(upstream_port, true);
    let grant = serde_json::to_string(
        &signing
            .sign(zs_grant::Grant {
                subject: "alice".into(),
                workload: "default".into(),
                resource: "stripe-production".into(),
                host: "api.stripe.com".into(),
                protocol: "https".into(),
                source: zs_policy::CredentialSource::file("stripe-prod"),
                operations: vec!["GET".into()],
                environment: "development".into(),
                expires_at_ms: now_ms + 3_600_000,
                grant_id: "g-https-real".into(),
                materialization: zs_policy::Materialization::Retrieve,
                upstream_host: connection.upstream_host,
                upstream_port: connection.upstream_port,
                upstream_tls: connection.upstream_tls,
                local_endpoint: connection.local_endpoint,
            })
            .unwrap(),
    )
    .unwrap();

    let config = format!(
        r#"{{"bindings":[{{"resource":"stripe-production","host":"api.stripe.com","upstream_host":"127.0.0.1","upstream_port":{upstream_port},"upstream_plaintext":true,"auth":{{"scheme":"bearer"}}}}],"signing_keys":[{{"key_id":"test-k1","verifying_key_hex":"{verifying_hex}"}}],"grants":[{grant}]}}"#
    );
    std::fs::write(dir.path().join("zs-policy.json"), config).unwrap();
    dir
}

fn run_workload(home: &std::path::Path) -> String {
    let output = Command::new(binary())
        .args([
            "run",
            "--policy",
            &home.join("zs-policy.json").display().to_string(),
            "--credentials-dir",
            &home.join(".zs-credentials").display().to_string(),
            "--audit",
            &home.join("audit.jsonl").display().to_string(),
            "--ca-dir",
            &home.join(".zs-ca").display().to_string(),
            "--",
            "curl",
            "-s",
            "--max-time",
            "20",
            "-o",
            "-",
            "-w",
            "\nHTTP_STATUS:%{http_code}\n",
            "https://api.stripe.com/v1/customers",
        ])
        .env("ZS_HOME", home)
        .env("USER", "alice")
        .current_dir(home)
        .output()
        .expect("zs must run");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_workload_with_no_credential_makes_a_call_the_upstream_accepts() {
    let upstream = spawn_validating_upstream();
    let home = workspace(upstream.port, VALID_TOKEN);

    let out = run_workload(home.path());

    assert!(
        out.contains("HTTP_STATUS:200"),
        "the upstream refused the call, so the agent did not inject the right credential:\n{out}"
    );
    assert!(
        out.contains("\"authenticated\":true"),
        "the workload did not receive the authenticated response:\n{out}"
    );
    assert_eq!(
        upstream.accepted.load(Ordering::SeqCst),
        1,
        "exactly one request must have been accepted"
    );
    assert_eq!(
        upstream.rejected.load(Ordering::SeqCst),
        0,
        "no request should have been refused"
    );
}

#[test]
fn a_wrong_credential_is_refused_by_the_validating_upstream() {
    let upstream = spawn_validating_upstream();
    let home = workspace(upstream.port, "sk_test_this_is_not_the_right_value");

    let out = run_workload(home.path());

    assert!(
        out.contains("HTTP_STATUS:401"),
        "a wrong credential must be refused by the upstream:\n{out}"
    );
    assert_eq!(
        upstream.accepted.load(Ordering::SeqCst),
        0,
        "no request should have been accepted with a wrong credential"
    );
    assert!(
        upstream.rejected.load(Ordering::SeqCst) >= 1,
        "the upstream must have refused the call"
    );
}

#[test]
fn the_credential_never_reaches_the_workload() {
    let upstream = spawn_validating_upstream();
    let home = workspace(upstream.port, VALID_TOKEN);

    let output = Command::new(binary())
        .args([
            "run",
            "--policy",
            &home.path().join("zs-policy.json").display().to_string(),
            "--credentials-dir",
            &home.path().join(".zs-credentials").display().to_string(),
            "--audit",
            &home.path().join("audit.jsonl").display().to_string(),
            "--ca-dir",
            &home.path().join(".zs-ca").display().to_string(),
            "--",
            "/usr/bin/env",
        ])
        .env("ZS_HOME", home.path())
        .env("USER", "alice")
        .current_dir(home.path())
        .output()
        .expect("zs must run");
    let env_dump = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !env_dump.contains(VALID_TOKEN),
        "the credential reached the workload's environment:\n{env_dump}"
    );

    let call = run_workload(home.path());
    assert!(
        call.contains("HTTP_STATUS:200"),
        "the call must succeed for this assertion to mean anything:\n{call}"
    );
    assert!(
        !call.contains(VALID_TOKEN),
        "the credential appeared in what the workload could read:\n{call}"
    );
}

#[test]
fn the_strict_label_matches_what_the_child_actually_holds() {
    let upstream = spawn_validating_upstream();
    let home = workspace(upstream.port, VALID_TOKEN);

    let listing = Command::new(binary())
        .args([
            "resources",
            "--policy",
            &home.path().join("zs-policy.json").display().to_string(),
        ])
        .env("ZS_HOME", home.path())
        .env("USER", "alice")
        .current_dir(home.path())
        .output()
        .expect("zs must run");
    let listing = String::from_utf8_lossy(&listing.stdout).to_string();
    let verdict = listing
        .lines()
        .find(|l| l.starts_with("stripe-production\t"))
        .unwrap_or_else(|| panic!("no resource line in:\n{listing}"))
        .rsplit('\t')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();

    assert_eq!(
        verdict, "strict",
        "an intercepted resource with a grant is strict (ADR-0022):\n{listing}"
    );

    let output = Command::new(binary())
        .args([
            "run",
            "--policy",
            &home.path().join("zs-policy.json").display().to_string(),
            "--credentials-dir",
            &home.path().join(".zs-credentials").display().to_string(),
            "--audit",
            &home.path().join("audit.jsonl").display().to_string(),
            "--ca-dir",
            &home.path().join(".zs-ca").display().to_string(),
            "--",
            "/usr/bin/env",
        ])
        .env("ZS_HOME", home.path())
        .env("USER", "alice")
        .current_dir(home.path())
        .output()
        .expect("zs must run");
    let env_dump = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !env_dump.contains(VALID_TOKEN),
        "the resource claims strict while the credential is in the child's environment:\n{env_dump}"
    );

    let call = run_workload(home.path());
    assert!(
        call.contains("HTTP_STATUS:200"),
        "the strict claim needs a call that succeeded:\n{call}"
    );
    assert_eq!(
        upstream.accepted.load(Ordering::SeqCst),
        1,
        "the upstream must have accepted exactly one authenticated call"
    );
}

#[test]
fn the_call_is_audited_without_the_credential() {
    let upstream = spawn_validating_upstream();
    let home = workspace(upstream.port, VALID_TOKEN);

    let out = run_workload(home.path());
    assert!(out.contains("HTTP_STATUS:200"), "{out}");

    let mut journal = String::new();
    for _ in 0..40 {
        journal = std::fs::read_to_string(home.path().join("audit.jsonl")).unwrap_or_default();
        if journal.contains("\"decision\"") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    assert!(
        journal.contains("\"decision\""),
        "the call must be audited:\n{journal}"
    );
    assert!(
        journal.contains("allow"),
        "an accepted call must be recorded as allowed:\n{journal}"
    );
    assert!(
        !journal.contains(VALID_TOKEN),
        "the audit journal must never contain the credential:\n{journal}"
    );
}
