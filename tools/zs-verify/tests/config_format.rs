#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

const SYNTHETIC_CREDENTIAL: &str = "sk_test_zsv_localonly";

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("zs-verify")
}

fn credential_file(dir: &Path) -> PathBuf {
    let path = dir.join("credential.txt");
    std::fs::write(&path, SYNTHETIC_CREDENTIAL).unwrap();
    path
}

fn run_with_config(config: &str) -> (std::process::Output, PathBuf, Vec<u8>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = dir.path().join("zs-policy.json");
    std::fs::write(&policy, config).unwrap();
    let before = std::fs::read(&policy).unwrap();
    let credential = credential_file(dir.path());
    let output = Command::new(binary())
        .args([
            format!("--policy-file={}", policy.display()),
            "--agent-cmd=/usr/bin/true".to_string(),
            "--child-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", credential.display()),
            format!("--creds-dir={}", dir.path().display()),
            format!("--audit-file={}", dir.path().join("audit.jsonl").display()),
        ])
        .output()
        .expect("zs-verify must run");
    (output, policy, before, dir)
}

#[test]
fn a_bindings_config_source_file_is_left_byte_identical() {
    let (_output, policy, before, _dir) = run_with_config(
        r#"{"bindings":[{"resource":"r","host":"api.example.com","protocol":"https"}]}"#,
    );

    assert_eq!(
        before,
        std::fs::read(&policy).unwrap(),
        "zs-verify must redirect a copy, never the caller's file"
    );
}

#[test]
fn a_legacy_resources_config_source_file_is_left_byte_identical() {
    let (output, policy, before, _dir) = run_with_config(
        r#"{"resources":[{"name":"r","host":"api.example.com","protocol":"https"}]}"#,
    );

    assert_eq!(before, std::fs::read(&policy).unwrap());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("no `bindings` or `resources` array"),
        "a v0 config must still be recognised and redirected: {combined}"
    );
}

#[test]
fn a_config_with_no_redirectable_entries_is_refused() {
    let (output, policy, before, _dir) = run_with_config(r#"{"signing_keys":[],"grants":[]}"#);

    assert!(
        !output.status.success(),
        "a config zs-verify cannot redirect must not produce a report"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("never exercised") || stderr.contains("refusing"),
        "the refusal must say why: {stderr}"
    );
    assert_eq!(
        before,
        std::fs::read(&policy).unwrap(),
        "a refused run must leave the source policy byte-identical"
    );
}

#[test]
fn an_invalid_policy_is_refused_before_the_agent_starts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = dir.path().join("zs-policy.json");
    std::fs::write(&policy, "{ this is not json").unwrap();
    let before = std::fs::read(&policy).unwrap();
    let marker = dir.path().join("agent-started");
    let credential = credential_file(dir.path());

    let output = Command::new(binary())
        .args([
            format!("--policy-file={}", policy.display()),
            format!("--agent-cmd=/usr/bin/touch {}", marker.display()),
            "--child-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", credential.display()),
        ])
        .output()
        .expect("zs-verify must run");

    assert!(!output.status.success());
    assert!(
        !marker.exists(),
        "an invalid policy must fail before the agent is launched"
    );
    assert_eq!(before, std::fs::read(&policy).unwrap());
}

#[test]
fn the_removed_credential_value_flag_is_refused_without_echoing_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = dir.path().join("zs-policy.json");
    std::fs::write(
        &policy,
        r#"{"bindings":[{"resource":"r","host":"api.example.com","protocol":"https"}]}"#,
    )
    .unwrap();
    let credential = credential_file(dir.path());

    let output = Command::new(binary())
        .args([
            format!("--policy-file={}", policy.display()),
            "--agent-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", credential.display()),
            format!("--credential-value={SYNTHETIC_CREDENTIAL}"),
        ])
        .output()
        .expect("zs-verify must run");

    assert_eq!(output.status.code(), Some(2));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("--credential-value"));
    assert!(
        !combined.contains(SYNTHETIC_CREDENTIAL),
        "a rejection that echoes its argument echoes the secret that argument carried"
    );
}

#[test]
fn the_secret_placeholder_template_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = dir.path().join("zs-policy.json");
    std::fs::write(
        &policy,
        r#"{"bindings":[{"resource":"r","host":"api.example.com","protocol":"https"}]}"#,
    )
    .unwrap();
    let credential = credential_file(dir.path());

    let output = Command::new(binary())
        .args([
            format!("--policy-file={}", policy.display()),
            "--agent-cmd=/usr/bin/true {CREDENTIAL}".to_string(),
            format!("--credential-file={}", credential.display()),
        ])
        .output()
        .expect("zs-verify must run");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("{CREDENTIAL_FILE}"));
}

fn report_for(config: &str, agent_request: &str) -> serde_json::Value {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = dir.path().join("zs-policy.json");
    std::fs::write(&policy, config).unwrap();
    let credential = credential_file(dir.path());

    let script = dir.path().join("agent.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nprintf '{agent_request}' | nc 127.0.0.1 \"$ZS_VERIFY_PORT\" >/dev/null 2>&1 || true\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let output = Command::new(binary())
        .args([
            format!("--policy-file={}", policy.display()),
            format!(
                "--agent-cmd=env ZS_VERIFY_PORT={{UPSTREAM_PORT}} {}",
                script.display()
            ),
            "--child-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", credential.display()),
            format!("--creds-dir={}", dir.path().display()),
            format!("--audit-file={}", dir.path().join("audit.jsonl").display()),
        ])
        .output()
        .expect("zs-verify must run");
    serde_json::from_slice(&output.stdout).expect("a report must be printed")
}

#[test]
fn a_query_parameter_config_is_redirected_not_refused() {
    let config = r#"{"bindings":[{"resource":"r","host":"api.example.com","protocol":"https","auth":{"scheme":"query_param","param":"api_key"}}],"signing_keys":[],"grants":[]}"#;
    let report = report_for(
        config,
        &format!(
            "GET /v1/x?api_key={SYNTHETIC_CREDENTIAL} HTTP/1.1\\r\\nHost: api.example.com\\r\\n\\r\\n"
        ),
    );

    assert_eq!(report["decisions"]["upstream_requests"], 1);
    assert_eq!(report["decisions"]["upstream_auth_ok"], 1);
    assert_eq!(report["decisions"]["upstream_auth_mismatch"], 0);
}

#[test]
fn an_api_key_header_config_is_redirected_not_refused() {
    let config = r#"{"bindings":[{"resource":"r","host":"api.example.com","protocol":"https","auth":{"scheme":"api_key_header","header":"X-Api-Key"}}],"signing_keys":[],"grants":[]}"#;
    let report = report_for(
        config,
        &format!(
            "GET /v1/x HTTP/1.1\\r\\nHost: api.example.com\\r\\nX-Api-Key: {SYNTHETIC_CREDENTIAL}\\r\\n\\r\\n"
        ),
    );

    assert_eq!(report["decisions"]["upstream_requests"], 1);
    assert_eq!(report["decisions"]["upstream_auth_ok"], 1);
    assert_eq!(report["decisions"]["upstream_auth_mismatch"], 0);
}
