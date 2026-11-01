#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};
use zs::AgentFile;

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

fn zs(args: &[&Path]) -> Output {
    let output = Command::new(binary())
        .arg("ca-sha256")
        .args(args)
        .output()
        .expect("zs must run");
    Output {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

#[test]
fn zs_ca_sha256_prints_the_bundle_hash() {
    let dir = tempfile::tempdir().unwrap();
    let first = generate_simple_self_signed(vec!["one.internal".into()]).unwrap();
    let second = generate_simple_self_signed(vec!["two.internal".into()]).unwrap();
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(
        &bundle,
        format!("# bundle\r\n{}{}", first.cert.pem(), second.cert.pem()),
    )
    .unwrap();
    let mut der = Sha256::new();
    der.update(first.cert.der());
    der.update(second.cert.der());
    let expected: String = der
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let out = zs(&[&bundle]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout, format!("{expected}\n"));
    assert_eq!(out.stderr, "");
    assert_eq!(expected.len(), 64);
}

#[test]
fn zs_ca_sha256_refuses_a_non_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_simple_self_signed(vec!["one.internal".into()]).unwrap();
    let good = dir.path().join("good.pem");
    std::fs::write(&good, key.cert.pem()).unwrap();
    assert_eq!(zs(&[&good]).code, 0);

    let bad = dir.path().join("key.pem");
    let content = key.key_pair.serialize_pem();
    std::fs::write(&bad, &content).unwrap();
    let out = zs(&[&bad]);
    assert_eq!(out.code, 1);
    assert_eq!(
        out.stderr,
        format!("zs: {}: not a PEM certificate bundle\n", bad.display())
    );
    assert_eq!(out.stdout, "");
    let body = content.lines().nth(1).unwrap();
    assert!(!out.stdout.contains(body) && !out.stderr.contains(body));

    let missing = dir.path().join("missing.pem");
    let out = zs(&[&missing]);
    assert_eq!(out.code, 1);
    assert_eq!(
        out.stderr,
        format!("zs: {}: not a PEM certificate bundle\n", missing.display())
    );

    let usage = zs(&[]);
    assert_eq!(usage.code, 2);
    assert_eq!(usage.stdout, "");
}

#[test]
fn the_ca_file_is_read_once() {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(
        &ca,
        generate_simple_self_signed(vec!["db.internal".into()])
            .unwrap()
            .cert
            .pem(),
    )
    .unwrap();
    let policy = dir.path().join("zs-policy.json");
    std::fs::write(
        &policy,
        serde_json::json!({
            "bindings": [{
                "resource": "db",
                "host": "db.internal",
                "protocol": "postgres",
                "upstream_ca": ca,
            }],
            "signing_keys": [],
            "grants": [],
        })
        .to_string(),
    )
    .unwrap();

    let file = AgentFile::load(&policy).unwrap();
    let binding = &file.bindings[0];
    let loaded = binding.loaded_ca.as_ref().expect("the CA is loaded");
    assert_eq!(loaded.roots.len(), 1);
    assert!(binding.upstream_tls().unwrap().required());

    std::fs::write(&ca, "garbage").unwrap();
    let tls = binding.upstream_tls().unwrap();
    assert!(tls.required());
    assert!(matches!(&tls, zs_upstream::UpstreamTls::Required(roots) if *roots == loaded.roots));
}
