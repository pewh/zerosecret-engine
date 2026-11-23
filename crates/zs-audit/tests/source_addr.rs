#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zs_audit::{AuditError, AuditRequest, Decision, Journal, verify_chain};

const TODAY: &str = r#"{"seq":1,"subject":"alice@example.test","workload":"claude-code","resource":"db-main","protocol":"postgres","operation":"connect","decision":"deny","reason":"caller_refused","credential_ref":"ref-1","timestamp_ms":7000,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"ee30157379b9d7b95eb4f82c38d77527654e66b31f4addfc76038950c1f159a5"}"#;

fn request(source_addr: Option<&str>) -> AuditRequest {
    AuditRequest {
        subject: "alice@example.test".into(),
        workload: "claude-code".into(),
        resource: "db-main".into(),
        protocol: "postgres".into(),
        operation: "connect".into(),
        decision: Decision::Deny,
        reason: Some("caller_refused".into()),
        credential_ref: Some("ref-1".into()),
        source_addr: source_addr.map(str::to_string),
    }
}

fn written(source_addr: Option<&str>) -> (tempfile::TempDir, std::path::PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    Journal::open(&path)
        .unwrap()
        .append(&request(source_addr), 7000)
        .unwrap();
    let line = std::fs::read_to_string(&path).unwrap();
    (dir, path, line)
}

#[test]
fn a_journal_line_written_before_source_addr_still_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    std::fs::write(&path, format!("{TODAY}\n")).unwrap();
    assert_eq!(verify_chain(&path).unwrap(), 1);
    assert_eq!(Journal::open(&path).unwrap().last_seq().unwrap(), 1);
}

#[test]
fn a_record_without_source_addr_has_the_bytes_of_today() {
    let (_dir, _path, line) = written(None);
    assert_eq!(line, format!("{TODAY}\n"));
    assert!(!line.contains("source_addr"), "{line}");
}

#[test]
fn a_record_with_source_addr_verifies_and_carries_it() {
    let (_dir, path, line) = written(Some("172.17.0.2"));
    assert!(
        line.contains(
            "\"credential_ref\":\"ref-1\",\"source_addr\":\"172.17.0.2\",\"timestamp_ms\""
        ),
        "{line}"
    );
    assert_eq!(verify_chain(&path).unwrap(), 1);
    assert!(Journal::open(&path).is_ok());
}

#[test]
fn source_addr_changes_the_hash() {
    let (_a, _pa, with) = written(Some("172.17.0.2"));
    let (_b, _pb, without) = written(None);
    let (_c, _pc, other) = written(Some("172.17.0.3"));
    let hash = |line: &str| {
        serde_json::from_str::<zs_audit::AuditRecord>(line)
            .unwrap()
            .hash
    };
    assert_ne!(hash(&with), hash(&without));
    assert_ne!(hash(&with), hash(&other));
}

#[test]
fn changing_source_addr_after_the_write_breaks_the_chain() {
    let (_dir, path, line) = written(Some("172.17.0.2"));
    assert_eq!(verify_chain(&path).unwrap(), 1);
    std::fs::write(&path, line.replace("172.17.0.2", "172.17.0.9")).unwrap();
    assert!(matches!(
        verify_chain(&path),
        Err(AuditError::ChainBroken(1))
    ));
    assert!(Journal::open(&path).is_err());
}

#[test]
fn removing_source_addr_after_the_write_breaks_the_chain() {
    let (_dir, path, line) = written(Some("172.17.0.2"));
    std::fs::write(&path, line.replace(",\"source_addr\":\"172.17.0.2\"", "")).unwrap();
    assert!(matches!(
        verify_chain(&path),
        Err(AuditError::ChainBroken(1))
    ));
}

#[test]
fn adding_source_addr_to_an_old_line_breaks_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    std::fs::write(
        &path,
        TODAY.replace(
            "\"timestamp_ms\"",
            "\"source_addr\":\"10.0.0.1\",\"timestamp_ms\"",
        ),
    )
    .unwrap();
    assert!(matches!(
        verify_chain(&path),
        Err(AuditError::ChainBroken(1))
    ));
}
