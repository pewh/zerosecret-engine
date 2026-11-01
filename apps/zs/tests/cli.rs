#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

const CREDENTIAL: &str = "sk_live_cli_must_not_print_this";

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("zs")
}

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Output {
    fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn zs(home: &Path, args: &[&str]) -> Output {
    let output = Command::new(binary())
        .args(args)
        .env("ZS_HOME", home)
        .env("USER", "alice")
        .current_dir(home)
        .output()
        .expect("zs must run");
    Output {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = serde_json::json!({
        "bindings": [
            {
                "resource": "stripe-production",
                "host": "api.stripe.com",
                "protocol": "https",
                "auth": {"scheme": "bearer"}
            },
            {
                "resource": "analytics-db",
                "host": "db.internal",
                "protocol": "postgres"
            }
        ],
        "signing_keys": [],
        "grants": []
    });
    std::fs::write(
        dir.path().join("zs-policy.json"),
        serde_json::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    let credentials = dir.path().join(".zs-credentials");
    std::fs::create_dir_all(&credentials).unwrap();
    std::fs::write(credentials.join("stripe-production"), CREDENTIAL).unwrap();
    dir
}

#[test]
fn status_without_a_session_exits_1() {
    let home = workspace();
    let out = zs(home.path(), &["status"]);

    assert_eq!(out.code, 1, "stdout={} stderr={}", out.stdout, out.stderr);
    assert!(
        out.combined().contains("not signed in"),
        "must say why: {}",
        out.combined()
    );
}

#[test]
fn status_after_login_reports_subject_and_grant_count() {
    let home = workspace();
    assert_eq!(zs(home.path(), &["login"]).code, 0);

    let out = zs(home.path(), &["status"]);

    assert_eq!(out.code, 0, "stderr={}", out.stderr);
    assert!(
        out.stdout.contains("alice"),
        "status must name the subject: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("grant"),
        "status must report the cached-grant count: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains("control"),
        "status must report control-plane reachability: {}",
        out.stdout
    );
}

#[test]
fn login_prints_signed_in_as_and_exits_0() {
    let home = workspace();

    let out = zs(home.path(), &["login"]);

    assert_eq!(out.code, 0, "stderr={}", out.stderr);
    assert!(
        out.stdout.contains("signed in as alice"),
        "got {}",
        out.stdout
    );
}

#[test]
fn logout_prints_signed_out_and_exits_0() {
    let home = workspace();
    zs(home.path(), &["login"]);

    let out = zs(home.path(), &["logout"]);

    assert_eq!(out.code, 0, "stderr={}", out.stderr);
    assert!(out.stdout.contains("signed out"), "got {}", out.stdout);
}

#[test]
fn logout_clears_the_session_so_status_fails_again() {
    let home = workspace();
    zs(home.path(), &["login"]);
    assert_eq!(zs(home.path(), &["status"]).code, 0, "signed in");

    zs(home.path(), &["logout"]);

    assert_eq!(
        zs(home.path(), &["status"]).code,
        1,
        "after logout, status must report not signed in"
    );
}

#[test]
fn logout_without_a_session_still_succeeds() {
    let home = workspace();

    let out = zs(home.path(), &["logout"]);

    assert_eq!(out.code, 0, "stderr={}", out.stderr);
}

#[test]
fn zs_login_refuses_plain_http_to_a_remote_host() {
    let home = workspace();

    let out = zs(
        home.path(),
        &["login", "--control", "http://example.invalid:8443"],
    );

    assert_eq!(out.code, 1, "{}", out.combined());
    assert!(
        out.combined()
            .contains("http is allowed only for a loopback control plane"),
        "got {}",
        out.combined()
    );
    assert!(!home.path().join(".zs-session").exists());
    assert!(!home.path().join(".zs-device.json").exists());
}

#[test]
fn zs_login_parses_the_host_instead_of_matching_a_loopback_prefix() {
    let home = workspace();

    for url in [
        "http://127.0.0.1.evil.com:8443",
        "http://localhost.evil.com",
        "http://127.0.0.1@evil.com",
    ] {
        let out = zs(home.path(), &["login", "--control", url]);
        assert_eq!(out.code, 1, "{url}: {}", out.combined());
        assert!(
            out.combined()
                .contains("http is allowed only for a loopback control plane"),
            "{url}: {}",
            out.combined()
        );
    }
    let out = zs(home.path(), &["login", "--control", "ftp://127.0.0.1"]);
    assert_eq!(out.code, 1, "{}", out.combined());
    assert!(out.combined().contains("https"), "{}", out.combined());
    assert!(!home.path().join(".zs-session").exists());
}

#[test]
fn zs_login_names_a_bad_device_name_before_any_request() {
    let home = workspace();

    let out = zs(
        home.path(),
        &[
            "login",
            "--control",
            "http://127.0.0.1:9",
            "--device-name",
            "bad/name",
        ],
    );

    assert_eq!(out.code, 1, "{}", out.combined());
    assert!(
        out.combined().contains("--device-name"),
        "got {}",
        out.combined()
    );
}

#[test]
fn status_reports_not_enrolled_for_an_unknown_control_url() {
    let home = workspace();
    zs(home.path(), &["login"]);

    let out = zs(home.path(), &["status", "--control", "http://127.0.0.1:9"]);

    assert_eq!(out.code, 0, "{}", out.combined());
    assert!(
        out.stdout.contains("device: not enrolled"),
        "got {}",
        out.stdout
    );
}

fn stored_enrolment(control: &str) -> zs::device::Enrolment {
    zs::device::Enrolment {
        control: control.into(),
        control_ca_sha256: "ab".repeat(32),
        subject: "alice@company.com".into(),
        device_id: "dev-cli-status".into(),
        organization: "default".into(),
        client_certificate: "CERT".into(),
        grant_verifying_key_hex: "cd".repeat(32),
        grant_verifying_key_id: "control-k1".into(),
        wire_url: "https://localhost:8444".into(),
    }
}

#[test]
fn status_names_the_enrolment_for_the_control_url() {
    let home = workspace();
    zs(home.path(), &["login"]);
    zs::device::save_file(
        home.path(),
        &zs::device::DeviceFile {
            enrolments: vec![stored_enrolment("http://127.0.0.1:9")],
        },
    )
    .unwrap();

    let out = zs(home.path(), &["status", "--control", "http://127.0.0.1:9/"]);

    assert_eq!(out.code, 0, "{}", out.combined());
    assert!(
        out.stdout.contains(
            "device: dev-cli-status (enrolled with http://127.0.0.1:9 as alice@company.com)"
        ),
        "got {}",
        out.stdout
    );

    let other = zs(home.path(), &["status", "--control", "http://127.0.0.1:10"]);
    assert!(
        other.stdout.contains("device: not enrolled"),
        "got {}",
        other.stdout
    );
}

#[test]
fn logout_with_an_empty_device_file_still_removes_the_session() {
    for content in ["", "{\"enrolments\": []}"] {
        let home = workspace();
        zs(home.path(), &["login"]);
        std::fs::write(home.path().join(".zs-device.json"), content).unwrap();

        let out = zs(home.path(), &["logout"]);

        assert_eq!(out.code, 0, "{content:?}: {}", out.combined());
        assert!(!home.path().join(".zs-session").exists(), "{content:?}");
        assert!(!home.path().join(".zs-device.json").exists(), "{content:?}");
    }
}

#[test]
fn resources_lists_name_host_protocol_and_materialization() {
    let home = workspace();

    let out = zs(home.path(), &["resources"]);

    assert_eq!(out.code, 0, "stderr={}", out.stderr);
    let lines: Vec<&str> = out
        .stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        lines,
        [
            lines[0],
            "  connection: from the policy file (local mode)",
            lines[2],
            "  connection: from the policy file (local mode)",
        ],
        "one resource line and one connection line per resource: {}",
        out.stdout
    );

    let stripe = lines[0];
    assert!(stripe.starts_with("stripe-production\t"), "name: {stripe}");
    assert!(stripe.contains("api.stripe.com"), "host: {stripe}");
    assert!(stripe.contains("https"), "protocol: {stripe}");

    let db = lines[2];
    assert!(db.starts_with("analytics-db\t"), "name: {db}");
    assert!(db.contains("db.internal"), "host: {db}");
    assert!(db.contains("postgres"), "protocol: {db}");
}

#[test]
fn resources_with_a_control_plane_it_cannot_reach_says_the_connection_is_signed_at_run_time() {
    let home = workspace();

    let local = zs(home.path(), &["resources"]);
    assert_eq!(local.code, 0, "stderr={}", local.stderr);
    assert!(
        local
            .stdout
            .contains("  connection: from the policy file (local mode)\n"),
        "{}",
        local.stdout
    );

    let out = zs(
        home.path(),
        &["resources", "--control", "http://127.0.0.1:10"],
    );

    assert_eq!(out.code, 0, "stderr={}", out.stderr);
    let connection: Vec<&str> = out
        .stdout
        .lines()
        .filter(|l| l.starts_with("  connection"))
        .collect();
    assert_eq!(
        connection,
        [
            "  connection: signed at run time",
            "  connection: signed at run time"
        ],
        "{}",
        out.stdout
    );
    assert!(!out.stdout.contains("local mode"), "{}", out.stdout);
}

#[test]
fn resources_without_a_config_exits_nonzero() {
    let home = tempfile::tempdir().unwrap();

    let out = zs(home.path(), &["resources"]);

    assert_ne!(
        out.code, 0,
        "a missing config must not look like an empty resource list"
    );
}

#[test]
fn doctor_still_reports_config_and_ca_state() {
    let home = workspace();

    let out = zs(home.path(), &["doctor"]);

    assert_eq!(out.code, 0, "stderr={}", out.stderr);
    assert!(out.stdout.contains("resource bindings"), "{}", out.stdout);
    assert!(
        out.stdout.contains("ca certificate present"),
        "{}",
        out.stdout
    );
}

#[test]
fn no_command_prints_a_credential() {
    let home = workspace();
    zs(home.path(), &["login"]);

    for args in [
        vec!["status"],
        vec!["resources"],
        vec!["doctor"],
        vec!["login"],
        vec!["logout"],
        vec!["status", "--nonsense"],
        vec!["resources", "--nonsense"],
        vec!["not-a-command"],
    ] {
        let out = zs(home.path(), &args);
        assert!(
            !out.combined().contains(CREDENTIAL),
            "`zs {}` printed a credential: {}",
            args.join(" "),
            out.combined()
        );
    }
}

#[test]
fn an_unknown_command_exits_2_and_lists_the_real_ones() {
    let home = workspace();

    let out = zs(home.path(), &["frobnicate"]);

    assert_eq!(out.code, 2, "{}", out.combined());
    let text = out.combined();
    for command in [
        "login",
        "logout",
        "status",
        "doctor",
        "run",
        "resources",
        "ca",
    ] {
        assert!(
            text.contains(command),
            "usage must list `{command}`: {text}"
        );
    }
}

fn ca_dir(home: &Path) -> PathBuf {
    let dir = home.join(".zs-ca");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ca.crt"), "certificate").unwrap();
    std::fs::write(
        dir.join(".ca-storage-id"),
        "0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    dir
}

fn ca_files_intact(dir: &Path) -> bool {
    std::fs::read(dir.join("ca.crt")).is_ok_and(|bytes| bytes == b"certificate")
        && std::fs::read(dir.join(".ca-storage-id"))
            .is_ok_and(|bytes| bytes == b"0123456789abcdef0123456789abcdef")
        && !dir.join(".ca-storage.lock").exists()
}

#[test]
fn ca_retire_refuses_without_an_explicit_directory_and_confirmation() {
    let home = workspace();
    let dir = ca_dir(home.path());

    let out = zs(home.path(), &["ca"]);
    assert_eq!(out.code, 2, "{}", out.combined());
    assert!(
        out.stderr
            .starts_with("zs: usage: zs ca retire --ca-dir <dir> --yes\n")
    );

    let out = zs(home.path(), &["ca", "list"]);
    assert_eq!(out.code, 2, "{}", out.combined());
    assert!(out.stderr.starts_with("zs: usage: zs ca retire"));

    let out = zs(home.path(), &["ca", "retire", "--yes"]);
    assert_eq!(out.code, 2, "{}", out.combined());
    assert!(out.stderr.starts_with("zs: ca retire needs --ca-dir\n"));

    let out = zs(home.path(), &["ca", "retire", "--ca-dir"]);
    assert_eq!(out.code, 2, "{}", out.combined());
    assert_eq!(out.stderr, "zs: --ca-dir needs a value\n");

    let out = zs(
        home.path(),
        &["ca", "retire", "--ca-dir", ".zs-ca", "--force"],
    );
    assert_eq!(out.code, 2, "{}", out.combined());
    assert!(
        out.stderr
            .starts_with("zs: unknown ca retire argument: --force\n")
    );

    let out = zs(home.path(), &["ca", "retire", "--ca-dir", ".zs-ca"]);
    assert_eq!(out.code, 2, "{}", out.combined());
    assert_eq!(
        out.stderr,
        "zs: ca retire deletes the CA private key of .zs-ca permanently, and every client \
         that trusts its ca.crt stops trusting the agent. Rerun with --yes to retire it\n"
    );
    assert!(out.stdout.is_empty());
    assert!(ca_files_intact(&dir));
}
