#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn zs(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zs"))
        .env("ZS_HOME", home)
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("failed to execute zs")
}

fn stdout_json(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8(output.stdout.clone()).expect("stdout not utf8");
    serde_json::from_str(&stdout).expect("stdout not valid JSON")
}

#[test]
fn test_zs_status_json_signed_out() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let output = zs(home.path(), work.path(), &["status", "--json"]);

    assert_eq!(output.status.code(), Some(1));
    let json = stdout_json(&output);
    assert_eq!(json["signed_in"], false);
    assert_eq!(json["subject"], serde_json::Value::Null);
    assert_eq!(json["enrolled"], false);
    assert_eq!(json["device_id"], serde_json::Value::Null);
}

#[test]
fn test_zs_status_json_signed_in() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    fs::write(home.path().join(".zs-session"), "dev-alice\n").unwrap();
    fs::write(
        work.path().join("zs-policy.json"),
        r#"{"bindings":[{"resource":"stripe","host":"api.stripe.com"}]}"#,
    )
    .unwrap();
    let output = zs(home.path(), work.path(), &["status", "--json"]);

    assert!(output.status.success(), "{output:?}");
    let json = stdout_json(&output);
    assert_eq!(json["signed_in"], true);
    assert_eq!(json["subject"], "dev-alice");
    assert_eq!(json["enrolled"], false);
    assert_eq!(json["control_url"], serde_json::Value::Null);
    assert_eq!(json["resources_count"], 1);
    assert_eq!(json["cached_grants_count"], 0);
}

#[test]
fn test_zs_doctor_json_valid_policy() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    fs::write(
        work.path().join("zs-policy.json"),
        r#"{"bindings":[{"resource":"stripe","host":"api.stripe.com"}]}"#,
    )
    .unwrap();
    let output = zs(home.path(), work.path(), &["doctor", "--json"]);

    assert!(output.status.success(), "{output:?}");
    let json = stdout_json(&output);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["policy_valid"], true);
    assert_eq!(json["bindings_count"], 1);
    assert_eq!(json["ca_certificate_present"], false);
    let diagnostics = json["diagnostics"].as_array().unwrap();
    assert!(diagnostics.iter().all(|d| d["level"] != "error"));
}

#[test]
fn test_zs_doctor_json_reports_the_policy_error() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    fs::write(
        work.path().join("zs-policy.json"),
        r#"{"bindings":[{"resource":"x","host":"h","auth_type":"bearer"}]}"#,
    )
    .unwrap();
    let output = zs(home.path(), work.path(), &["doctor", "--json"]);

    assert_eq!(output.status.code(), Some(1));
    let json = stdout_json(&output);
    assert_eq!(json["status"], "error");
    assert_eq!(json["policy_valid"], false);
    let errors: Vec<&serde_json::Value> = json["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|d| d["level"] == "error" && d["check"] == "policy")
        .collect();
    assert_eq!(errors.len(), 1);
    assert!(errors[0]["message"].as_str().unwrap().contains("auth_type"));
}

#[test]
fn test_json_flag_is_refused_where_it_does_nothing() {
    let home = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    for command in ["logout", "resources"] {
        let output = zs(home.path(), work.path(), &[command, "--json"]);
        assert_eq!(output.status.code(), Some(2), "{command}: {output:?}");
        assert!(output.stdout.is_empty(), "{command}");
    }
}
