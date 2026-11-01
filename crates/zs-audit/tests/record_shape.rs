#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zs_audit::{AuditRecord, Decision};

fn record() -> AuditRecord {
    AuditRecord {
        seq: 1,
        subject: "alice@company.com".into(),
        workload: "claude-code".into(),
        resource: "example-api".into(),
        protocol: "https".into(),
        operation: "GET".into(),
        decision: Decision::Allow,
        reason: None,
        credential_ref: None,
        timestamp_ms: 1,
        prev_hash: String::new(),
        hash: String::new(),
    }
}

// Before adding a field, decide whether it can carry a credential (QueryParamHttp puts one in the URL).
#[test]
fn the_audit_record_field_set_is_pinned() {
    let serialized = serde_json::to_string(&record()).unwrap();
    let expected = [
        "seq",
        "subject",
        "workload",
        "resource",
        "protocol",
        "operation",
        "decision",
        "timestamp_ms",
        "prev_hash",
        "hash",
    ];
    for field in expected {
        assert!(
            serialized.contains(&format!("\"{field}\"")),
            "missing field {field}: {serialized}"
        );
    }
    let count = serialized.matches("\":").count();
    assert_eq!(
        count,
        expected.len(),
        "AuditRecord gained or lost a field. A path or URL here would record the \
         query-parameter auth scheme's credential on every request: {serialized}"
    );
}

#[test]
fn no_audit_field_can_hold_a_request_path() {
    let serialized = serde_json::to_string(&record()).unwrap();
    for forbidden in ["path", "url", "uri", "query", "request", "target", "body"] {
        assert!(
            !serialized.contains(&format!("\"{forbidden}\"")),
            "`{forbidden}` can carry a query-string credential into the audit trail: \
             {serialized}"
        );
    }
}

#[test]
fn a_deny_record_with_a_reason_has_exactly_one_more_field() {
    let mut denied = record();
    denied.decision = Decision::Deny;
    denied.reason = Some("grant g-1 is revoked".into());
    let serialized = serde_json::to_string(&denied).unwrap();
    assert!(serialized.contains("\"reason\""), "{serialized}");
    assert_eq!(serialized.matches("\":").count(), 11, "{serialized}");
}
