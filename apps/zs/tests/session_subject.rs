#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("zs")
}

fn workspace() -> common::TestHome {
    let dir = common::TestHome::new(".zs-ca");
    let config = serde_json::json!({
        "bindings": [{
            "resource": "stripe-production",
            "host": "api.stripe.com",
            "protocol": "https",
            "auth": {"scheme": "bearer"}
        }],
        "signing_keys": [],
        "grants": []
    });
    std::fs::write(
        dir.path().join("zs-policy.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    dir
}

fn zs(home: &Path, user: &str, args: &[&str]) -> (i32, String) {
    let output = Command::new(binary())
        .args(args)
        .env("ZS_HOME", home)
        .env("USER", user)
        .current_dir(home)
        .output()
        .expect("zs must run");
    (
        output.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn sign_in_as(home: &Path, subject: &str) {
    std::fs::write(home.join(".zs-session"), subject).unwrap();
}

// Polled, not read once: the proxy's audit write races the child's exit.
fn audited_subjects(home: &Path, user: &str) -> String {
    let audit = home.join("audit.log");
    // Per-test CA dir: a shared one serializes on the CA lock and aborts with "CA storage busy".
    let ca_dir = home.join(".zs-ca");
    let (_code, _output) = zs(
        home,
        user,
        &[
            "run",
            "--audit",
            audit.to_str().unwrap(),
            "--ca-dir",
            ca_dir.to_str().unwrap(),
            "--",
            "curl",
            "-s",
            "-o",
            "/dev/null",
            // Generous on purpose: a tight deadline flakes under concurrent load.
            "--max-time",
            "30",
            "https://api.stripe.com/v1/charges",
        ],
    );
    for _ in 0..50 {
        let journal = std::fs::read_to_string(&audit).unwrap_or_default();
        if !journal.trim().is_empty() {
            return journal;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let journal = std::fs::read_to_string(&audit).unwrap_or_default();
    if journal.trim().is_empty() {
        panic!("no audit record was written. zs said:\n{_output}");
    }
    journal
}

#[test]
fn run_authorizes_as_the_session_subject_not_the_local_username() {
    let home = workspace();
    sign_in_as(home.path(), "alice@company.com");

    let journal = audited_subjects(home.path(), "localuser");

    assert_audited(&journal);
    assert!(
        journal.contains("alice@company.com"),
        "the decision must be recorded against the signed-in subject: {journal}"
    );
    assert!(
        !journal.contains("localuser"),
        "the local username must not authorize anything: {journal}"
    );
}

fn assert_audited(journal: &str) {
    assert!(
        journal.contains("\"decision\""),
        "no decision was audited at all, so this test can prove nothing: {journal}"
    );
}

#[test]
fn without_a_session_the_local_username_is_still_used() {
    let home = workspace();

    let journal = audited_subjects(home.path(), "localuser");

    assert_audited(&journal);
    assert!(
        journal.contains("localuser"),
        "with no session, $USER remains the subject: {journal}"
    );
}

#[test]
fn an_empty_session_file_falls_back_to_the_local_username() {
    let home = workspace();
    sign_in_as(home.path(), "   \n");

    let journal = audited_subjects(home.path(), "localuser");

    assert_audited(&journal);
    assert!(
        journal.contains("localuser"),
        "an empty session must fall back rather than authorize as nobody: {journal}"
    );
}

#[test]
fn logging_out_returns_run_to_the_local_username() {
    let home = workspace();
    sign_in_as(home.path(), "alice@company.com");
    assert_eq!(zs(home.path(), "localuser", &["logout"]).0, 0);

    let journal = audited_subjects(home.path(), "localuser");

    assert_audited(&journal);
    assert!(
        !journal.contains("alice@company.com"),
        "after logout the previous subject must not still authorize: {journal}"
    );
    assert!(
        journal.contains("localuser"),
        "after logout, $USER is the subject again: {journal}"
    );
}
