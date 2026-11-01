#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use zs::AgentFile;

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("zs")
}

#[test]
fn tilde_and_relative_paths_resolve_against_home_and_the_policy_directory() {
    let (dir, home) = (Path::new("/repo"), Path::new("/home/u"));
    assert_eq!(
        zs::resolve_setting_path(Path::new("~/.zs-credentials/acme"), dir, home),
        PathBuf::from("/home/u/.zs-credentials/acme")
    );
    assert_eq!(
        zs::resolve_setting_path(Path::new("zerosecret/control-ca.crt"), dir, home),
        PathBuf::from("/repo/zerosecret/control-ca.crt")
    );
    assert_eq!(
        zs::resolve_setting_path(Path::new("/abs/x"), dir, home),
        PathBuf::from("/abs/x")
    );
}

#[test]
fn a_file_credentials_dir_outside_zs_credentials_is_refused() {
    let (dir, home) = (Path::new("/repo"), Path::new("/home/u"));
    for bad in [
        "~/.ssh",
        "~/.zs-credentials/../.ssh",
        "/etc",
        "creds",
        "~/.zs-credentials",
        "~/.zs-credentials/acme/..",
        "~/.zs-credentials-other/acme",
    ] {
        assert!(
            zs::checked_credentials_dir(Path::new(bad), dir, home).is_err(),
            "{bad}"
        );
    }
    assert!(zs::checked_credentials_dir(Path::new("~/.zs-credentials/acme"), dir, home).is_ok());
    assert!(
        zs::checked_credentials_dir(Path::new("/home/u/.zs-credentials/acme"), dir, home).is_ok()
    );
    assert!(
        zs::checked_credentials_dir(Path::new("~/.zs-credentials/acme"), dir, Path::new(""))
            .is_err()
    );
}

#[test]
fn differing_control_cas_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
    let in_dir = ca_dir.join("control-ca.crt");
    let named = tmp.path().join("named.crt");
    std::fs::write(
        &in_dir,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
        &named,
        "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let error = zs::control_ca_pem(Some(&named), &ca_dir).unwrap_err();
    assert!(error.contains(&named.display().to_string()), "{error}");
    assert!(error.contains(&in_dir.display().to_string()), "{error}");

    let same = tmp.path().join("same.crt");
    std::fs::write(
        &same,
        "-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----\r\n",
    )
    .unwrap();
    assert!(zs::control_ca_pem(Some(&same), &ca_dir).is_ok());

    let alone = tmp.path().join("alone");
    std::fs::create_dir_all(&alone).unwrap();
    assert!(
        zs::control_ca_pem(Some(&named), &alone)
            .unwrap()
            .contains("BBBB")
    );
    assert!(zs::control_ca_pem(None, &ca_dir).unwrap().contains("AAAA"));

    let missing = tmp.path().join("missing.crt");
    let error = zs::control_ca_pem(Some(&missing), &ca_dir).unwrap_err();
    assert!(error.contains(&missing.display().to_string()), "{error}");

    let error = zs::control_ca_pem(None, &alone).unwrap_err();
    assert!(error.contains("run.control_ca"), "{error}");
}

#[test]
fn a_crlf_copy_of_the_control_ca_hashes_the_same() {
    let lf = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let crlf = "-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----\r\n";
    let hash = zs::control_ca_sha256(lf);
    assert_eq!(hash, zs::control_ca_sha256(crlf));
    assert_eq!(hash, zs::control_ca_sha256(&format!("\n  {lf}\n")));
    assert_eq!(hash.len(), 64);
    assert!(
        hash.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_ne!(hash, zs::control_ca_sha256("other"));
}

#[test]
fn an_unknown_run_key_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("zs-policy.json");
    std::fs::write(&path, r#"{"run":{"contol":"x"},"bindings":[]}"#).unwrap();
    let error = AgentFile::load(&path).unwrap_err().to_string();
    assert!(error.contains("unknown field"), "{error}");
}

struct Fixture {
    home: common::TestHome,
    other: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let home = common::TestHome::new(".zs-ca");
        std::fs::create_dir_all(home.path().join("repo")).unwrap();
        std::fs::write(
            home.path().join("repo/zs-policy.json"),
            r#"{"run":{"audit":"logs/a.jsonl"},"bindings":[]}"#,
        )
        .unwrap();
        Self {
            home,
            other: tempfile::tempdir().unwrap(),
        }
    }

    fn policy(&self) -> PathBuf {
        self.home.path().join("repo/zs-policy.json")
    }

    fn write_policy(&self, content: &str) {
        std::fs::write(self.policy(), content).unwrap();
    }

    fn run(&self, extra: &[String]) -> std::process::Output {
        let mut args: Vec<String> = vec![
            "run".into(),
            "--policy".into(),
            self.policy().display().to_string(),
            "--ca-dir".into(),
            self.home.path().join(".zs-ca").display().to_string(),
        ];
        args.extend(extra.iter().cloned());
        args.push("--".into());
        args.push("true".into());
        Command::new(binary())
            .args(&args)
            .env("ZS_HOME", self.home.path())
            .env("USER", "alice")
            .current_dir(self.other.path())
            .output()
            .expect("zs must run")
    }
}

#[test]
fn run_settings_fill_absent_flags() {
    let fixture = Fixture::new();
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.home.path().join("repo/logs/a.jsonl").exists());
    assert!(!fixture.other.path().join(".zs-audit").exists());
}

#[test]
fn a_flag_wins_over_the_file() {
    let fixture = Fixture::new();
    let flag = fixture.home.path().join("flag.jsonl");
    let output = fixture.run(&["--audit".into(), flag.display().to_string()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(flag.exists());
    assert!(!fixture.home.path().join("repo/logs/a.jsonl").exists());
}

#[test]
fn a_file_credentials_dir_outside_zs_credentials_stops_the_run() {
    let fixture = Fixture::new();
    fixture.write_policy(r#"{"run":{"credentials_dir":"/etc"},"bindings":[]}"#);
    let output = fixture.run(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr:\n{stderr}");
    assert!(stderr.contains("run.credentials_dir"), "{stderr}");
}

#[test]
fn a_credentials_dir_flag_may_name_any_directory() {
    let fixture = Fixture::new();
    fixture.write_policy(r#"{"run":{"credentials_dir":"/etc"},"bindings":[]}"#);
    let flag = fixture.home.path().join("x");
    let output = fixture.run(&["--credentials-dir".into(), flag.display().to_string()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_run_block_without_credentials_dir_keeps_local_grants() {
    let fixture = Fixture::new();
    let key = zs_grant::ControlSigningKey::generate("file-k1");
    let verifying_key_hex: String = key
        .verifying_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    fixture.write_policy(&format!(
        r#"{{"run":{{"audit":"logs/a.jsonl"}},"bindings":[],"signing_keys":[{{"key_id":"file-k1","verifying_key_hex":"{verifying_key_hex}"}}],"grants":[]}}"#
    ));
    let output = fixture.run(&[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.home.path().join("repo/logs/a.jsonl").exists());
}

#[test]
fn an_invalid_policy_names_its_path() {
    let fixture = Fixture::new();
    fixture.write_policy("not json");
    let output = fixture.run(&[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let prefix = format!("zs: policy: {}: ", fixture.policy().display());
    assert_eq!(output.status.code(), Some(1), "stderr:\n{stderr}");
    assert!(stderr.lines().any(|l| l.starts_with(&prefix)), "{stderr}");
}
