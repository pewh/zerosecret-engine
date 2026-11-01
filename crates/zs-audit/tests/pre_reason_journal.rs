#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zs_audit::{AuditRequest, Decision, Journal, verify_chain};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/pre_reason.jsonl"
);

fn temp_copy() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    std::fs::copy(FIXTURE, &path).unwrap();
    (dir, path)
}

#[test]
fn a_journal_written_before_the_reason_field_still_verifies() {
    assert_eq!(verify_chain(FIXTURE).unwrap(), 4);
    let (_dir, path) = temp_copy();
    let journal = Journal::open(&path).unwrap();
    assert_eq!(journal.last_seq().unwrap(), 4);
}

#[test]
fn a_pre_reason_journal_accepts_records_with_a_reason() {
    let (_dir, path) = temp_copy();
    {
        let journal = Journal::open(&path).unwrap();
        journal
            .append(
                &AuditRequest {
                    subject: "alice@example.test".into(),
                    workload: "claude-code".into(),
                    resource: "api.example.test:443".into(),
                    protocol: "https".into(),
                    operation: "connect".into(),
                    decision: Decision::Deny,
                    reason: Some("grant g-1 is revoked".into()),
                    credential_ref: None,
                },
                5000,
            )
            .unwrap();
    }
    assert_eq!(verify_chain(&path).unwrap(), 5);
    assert!(Journal::open(&path).is_ok());
    let content = std::fs::read_to_string(&path).unwrap();
    let last = content.lines().last().unwrap();
    assert!(
        last.contains("\"decision\":\"deny\",\"reason\":\"grant g-1 is revoked\""),
        "{last}"
    );
}
