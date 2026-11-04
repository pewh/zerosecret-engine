use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit sink unavailable: {0}")]
    SinkUnavailable(String),
    #[error("audit chain broken at record {0}")]
    ChainBroken(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
    Passthrough,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub seq: u64,
    pub subject: String,
    pub workload: String,
    pub resource: String,
    pub protocol: String,
    pub operation: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    pub timestamp_ms: u64,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct AuditRequest {
    pub subject: String,
    pub workload: String,
    pub resource: String,
    pub protocol: String,
    pub operation: String,
    pub decision: Decision,
    pub reason: Option<String>,
    pub credential_ref: Option<String>,
}

struct ChainState {
    seq: u64,
    prev_hash: String,
}

pub struct Journal {
    path: PathBuf,
    file: Mutex<File>,
    state: Mutex<ChainState>,
}

fn hash_record(req: &AuditRequest, seq: u64, timestamp_ms: u64, prev_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seq.to_le_bytes());
    hasher.update(timestamp_ms.to_le_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(req.subject.as_bytes());
    hasher.update([0u8]);
    hasher.update(req.workload.as_bytes());
    hasher.update([0u8]);
    hasher.update(req.resource.as_bytes());
    hasher.update([0u8]);
    hasher.update(req.protocol.as_bytes());
    hasher.update([0u8]);
    hasher.update(req.operation.as_bytes());
    hasher.update([0u8]);
    hasher.update(match req.decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::Passthrough => "passthrough",
    });
    if let Some(reason) = &req.reason {
        hasher.update([0u8]);
        hasher.update(reason.as_bytes());
        hasher.update([0u8]);
    }
    if let Some(reference) = &req.credential_ref {
        hasher.update([1u8]);
        hasher.update(reference.as_bytes());
        hasher.update([0u8]);
    }
    format!("{:x}", hasher.finalize())
}

fn normalize_operation(value: &str) -> String {
    value.replace('\0', "\u{FFFD}")
}

fn normalize(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| value.replace('\0', "\u{FFFD}"))
}

fn framed(record: &AuditRecord) -> bool {
    [record.reason.as_deref(), record.credential_ref.as_deref()]
        .into_iter()
        .flatten()
        .all(|value| !value.contains('\0'))
}

impl Journal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref().to_path_buf();
        let mut seq = 0u64;
        let mut prev_hash = "0".repeat(64);
        if path.exists() {
            let file = File::open(&path)
                .map_err(|e| AuditError::SinkUnavailable(format!("{}: {e}", path.display())))?;
            for line in BufReader::new(file).lines() {
                let line = line.map_err(|e| AuditError::SinkUnavailable(e.to_string()))?;
                if line.trim().is_empty() {
                    continue;
                }
                let record: AuditRecord =
                    serde_json::from_str(&line).map_err(|_| AuditError::ChainBroken(seq + 1))?;
                if record.seq != seq + 1 || record.prev_hash != prev_hash || !framed(&record) {
                    return Err(AuditError::ChainBroken(seq + 1));
                }
                let request = AuditRequest {
                    subject: record.subject.clone(),
                    workload: record.workload.clone(),
                    resource: record.resource.clone(),
                    protocol: record.protocol.clone(),
                    operation: record.operation.clone(),
                    decision: record.decision,
                    reason: record.reason.clone(),
                    credential_ref: record.credential_ref.clone(),
                };
                let expected =
                    hash_record(&request, record.seq, record.timestamp_ms, &record.prev_hash);
                if expected != record.hash {
                    return Err(AuditError::ChainBroken(record.seq));
                }
                seq = record.seq;
                prev_hash = record.hash;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| AuditError::SinkUnavailable(format!("{}: {e}", path.display())))?;
        Ok(Self {
            path,
            file: Mutex::new(file),
            state: Mutex::new(ChainState { seq, prev_hash }),
        })
    }

    pub fn append_seq(&self, request: &AuditRequest, timestamp_ms: u64) -> Result<u64, AuditError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuditError::SinkUnavailable("audit state lock poisoned".into()))?;
        let seq = state.seq + 1;
        let request = AuditRequest {
            operation: normalize_operation(&request.operation),
            reason: normalize(request.reason.as_deref()),
            credential_ref: normalize(request.credential_ref.as_deref()),
            ..request.clone()
        };
        let hash = hash_record(&request, seq, timestamp_ms, &state.prev_hash);
        let record = AuditRecord {
            seq,
            subject: request.subject.clone(),
            workload: request.workload.clone(),
            resource: request.resource.clone(),
            protocol: request.protocol.clone(),
            operation: request.operation.clone(),
            decision: request.decision,
            reason: request.reason.clone(),
            credential_ref: request.credential_ref.clone(),
            timestamp_ms,
            prev_hash: state.prev_hash.clone(),
            hash: hash.clone(),
        };
        let line = serde_json::to_string(&record)
            .map_err(|e| AuditError::SinkUnavailable(e.to_string()))?;
        let mut file = self
            .file
            .lock()
            .map_err(|_| AuditError::SinkUnavailable("audit file lock poisoned".into()))?;
        writeln!(file, "{line}").map_err(|e| AuditError::SinkUnavailable(e.to_string()))?;
        file.sync_all()
            .map_err(|e| AuditError::SinkUnavailable(e.to_string()))?;
        state.seq = seq;
        state.prev_hash = hash;
        Ok(seq)
    }

    pub fn append(&self, request: &AuditRequest, timestamp_ms: u64) -> Result<(), AuditError> {
        self.append_seq(request, timestamp_ms).map(|_| ())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_seq(&self) -> Result<u64, AuditError> {
        self.state
            .lock()
            .map(|state| state.seq)
            .map_err(|_| AuditError::SinkUnavailable("audit state lock poisoned".into()))
    }
}

pub fn verify_chain(path: impl AsRef<Path>) -> Result<u64, AuditError> {
    let file = File::open(path.as_ref())
        .map_err(|e| AuditError::SinkUnavailable(format!("{}: {e}", path.as_ref().display())))?;
    let mut seq = 0u64;
    let mut prev_hash = "0".repeat(64);
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| AuditError::SinkUnavailable(e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecord =
            serde_json::from_str(&line).map_err(|_| AuditError::ChainBroken(seq + 1))?;
        if record.seq != seq + 1 || record.prev_hash != prev_hash || !framed(&record) {
            return Err(AuditError::ChainBroken(seq + 1));
        }
        let request = AuditRequest {
            subject: record.subject.clone(),
            workload: record.workload.clone(),
            resource: record.resource.clone(),
            protocol: record.protocol.clone(),
            operation: record.operation.clone(),
            decision: record.decision,
            reason: record.reason.clone(),
            credential_ref: record.credential_ref.clone(),
        };
        let expected = hash_record(&request, record.seq, record.timestamp_ms, &record.prev_hash);
        if expected != record.hash {
            return Err(AuditError::ChainBroken(record.seq));
        }
        seq = record.seq;
        prev_hash = record.hash;
    }
    Ok(seq)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn request(subject: &str, op: &str) -> AuditRequest {
        AuditRequest {
            subject: subject.into(),
            workload: "claude-code".into(),
            resource: "api.stripe.com".into(),
            protocol: "https".into(),
            operation: op.into(),
            decision: Decision::Allow,
            reason: None,
            credential_ref: None,
        }
    }

    fn denied(reason: &str) -> AuditRequest {
        AuditRequest {
            decision: Decision::Deny,
            reason: Some(reason.into()),
            ..request("alice", "connect")
        }
    }

    #[test]
    fn chain_survives_reload_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let journal = Journal::open(&path).unwrap();
            journal.append(&request("alice", "GET"), 1000).unwrap();
            journal.append(&request("bob", "POST"), 2000).unwrap();
        }
        assert_eq!(verify_chain(&path).unwrap(), 2);
        let journal = Journal::open(&path).unwrap();
        journal.append(&request("carol", "GET"), 3000).unwrap();
        assert_eq!(verify_chain(&path).unwrap(), 3);
    }

    #[test]
    fn tampering_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&path).unwrap();
        journal.append(&request("alice", "GET"), 1000).unwrap();
        journal.append(&request("alice", "POST"), 2000).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("POST", "DELETE");
        std::fs::write(&path, tampered).unwrap();
        assert!(verify_chain(&path).is_err());
        assert!(Journal::open(&path).is_err());
    }

    #[test]
    fn credentials_pushed_into_fields_stay_greppable_but_chain_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&path).unwrap();
        journal
            .append(&request("sk_test_this_field_is_an_identifier", "GET"), 1000)
            .unwrap();
        assert!(verify_chain(&path).is_ok());
    }

    #[test]
    fn append_seq_returns_the_sequence_number_it_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Journal::open(dir.path().join("audit.jsonl")).unwrap();
        let request = AuditRequest {
            subject: "alice".into(),
            workload: "w".into(),
            resource: "r:443".into(),
            protocol: "https".into(),
            operation: "GET".into(),
            decision: Decision::Allow,
            reason: None,
            credential_ref: None,
        };
        assert_eq!(journal.append_seq(&request, 1).unwrap(), 1);
        journal.append(&request, 2).unwrap();
        assert_eq!(journal.append_seq(&request, 3).unwrap(), 3);
        assert_eq!(journal.last_seq().unwrap(), 3);
    }

    #[test]
    fn a_record_without_a_reason_omits_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&path).unwrap();
        journal.append(&request("alice", "GET"), 1000).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("\"reason\""), "{content}");
    }

    #[test]
    fn tampering_with_a_reason_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&path).unwrap();
        journal
            .append(&denied("grant g-1 is revoked"), 1000)
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, content.replace("g-1", "g-2")).unwrap();
        assert!(matches!(
            Journal::open(&path),
            Err(AuditError::ChainBroken(1))
        ));
    }

    #[test]
    fn removing_a_reason_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&path).unwrap();
        journal
            .append(&denied("grant g-1 is revoked"), 1000)
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            content.replace(",\"reason\":\"grant g-1 is revoked\"", ""),
        )
        .unwrap();
        assert!(matches!(
            verify_chain(&path),
            Err(AuditError::ChainBroken(1))
        ));
    }

    #[test]
    fn a_reason_record_never_hashes_like_a_record_without_one() {
        let with_reason = AuditRequest {
            operation: "X".into(),
            decision: Decision::Deny,
            reason: Some("allow".into()),
            ..request("alice", "X")
        };
        let without_reason = AuditRequest {
            operation: "X\0deny".into(),
            decision: Decision::Allow,
            reason: None,
            ..request("alice", "X")
        };
        assert_ne!(
            hash_record(&with_reason, 1, 1000, "prev"),
            hash_record(&without_reason, 1, 1000, "prev")
        );
    }

    #[test]
    fn a_nul_in_an_operation_is_replaced_so_later_records_still_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&path).unwrap();
        journal.append(&request("alice", "X\0deny"), 1000).unwrap();
        journal.append(&request("alice", "GET"), 2000).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines = content.lines();
        let first: AuditRecord = serde_json::from_str(lines.next().unwrap()).unwrap();
        let second: AuditRecord = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(first.operation, "X\u{FFFD}deny");
        assert!(!content.contains('\0'));
        assert_eq!(second.seq, 2);
        assert!(verify_chain(&path).is_ok());
    }

    #[test]
    fn a_nul_in_a_reason_is_replaced_and_an_empty_reason_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&path).unwrap();
        journal.append(&denied("a\0b"), 1000).unwrap();
        journal.append(&denied(""), 2000).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines = content.lines();
        let first: AuditRecord = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(first.reason, Some("a\u{FFFD}b".to_string()));
        assert!(!lines.next().unwrap().contains("\"reason\""));
        assert_eq!(verify_chain(&path).unwrap(), 2);
    }

    #[test]
    fn a_record_without_credential_ref_hashes_as_before() {
        let request = request("alice", "GET");
        assert_eq!(
            hash_record(&request, 1, 5000, &"0".repeat(64)),
            "12453eb1261d88da0c413c8e33980347399d3585f7ed95d86f08ced9201a9f1f"
        );
    }

    #[test]
    fn credential_ref_changes_the_hash() {
        let mut request = request("alice", "GET");
        request.reason = Some("no grant".into());
        request.credential_ref = Some("file:vault:kv/stripe".into());
        assert_eq!(
            hash_record(&request, 1, 5000, &"0".repeat(64)),
            "2cba7316c520a9cc6871abd2c7e297fb239f1f4dcfc67efa35f3794431dea82b"
        );
        let mut without = request.clone();
        without.credential_ref = None;
        assert_ne!(
            hash_record(&request, 1, 5000, &"0".repeat(64)),
            hash_record(&without, 1, 5000, &"0".repeat(64))
        );
    }

    #[test]
    fn reason_and_credential_ref_cannot_be_swapped() {
        let mut as_reason = request("alice", "GET");
        as_reason.reason = Some("file:vault:kv/stripe".into());
        let mut as_reference = request("alice", "GET");
        as_reference.credential_ref = Some("file:vault:kv/stripe".into());
        assert_ne!(
            hash_record(&as_reason, 1, 5000, &"0".repeat(64)),
            hash_record(&as_reference, 1, 5000, &"0".repeat(64))
        );
    }

    #[test]
    fn a_reference_moved_into_the_reason_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&path).unwrap();
        let mut record = request("alice", "GET");
        record.reason = Some("no grant".into());
        record.credential_ref = Some("file:vault:kv/stripe".into());
        journal.append(&record, 5000).unwrap();
        drop(journal);
        assert_eq!(verify_chain(&path).unwrap(), 1);

        let line = std::fs::read_to_string(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("credential_ref");
        object.insert(
            "reason".into(),
            "no grant\u{0}\u{1}file:vault:kv/stripe".into(),
        );
        std::fs::write(&path, format!("{value}\n")).unwrap();

        assert!(matches!(
            verify_chain(&path),
            Err(AuditError::ChainBroken(1))
        ));
        assert!(matches!(
            Journal::open(&path),
            Err(AuditError::ChainBroken(1))
        ));
    }

    #[test]
    fn old_journal_still_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let line = concat!(
            r#"{"seq":1,"subject":"alice","workload":"claude-code","resource":"api.stripe.com:443","#,
            r#""protocol":"https","operation":"GET","decision":"allow","timestamp_ms":5000,"#,
            r#""prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","#,
            r#""hash":"7b0c8d702c8409b4bc25ecae7e72797ebbef164c7b98c9bfc17f42dc3bbd6ceb"}"#,
            "\n"
        );
        std::fs::write(&path, line).unwrap();
        assert_eq!(verify_chain(&path).unwrap(), 1);
        let journal = Journal::open(&path).unwrap();
        let record = AuditRequest {
            subject: "alice".into(),
            workload: "claude-code".into(),
            resource: "api.stripe.com:443".into(),
            protocol: "https".into(),
            operation: "GET".into(),
            decision: Decision::Allow,
            reason: None,
            credential_ref: Some("file:vault:kv/stripe".into()),
        };
        journal.append(&record, 6000).unwrap();
        assert_eq!(verify_chain(&path).unwrap(), 2);
    }
}
