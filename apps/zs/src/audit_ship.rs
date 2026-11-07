use std::io::Write;
use std::path::{Path, PathBuf};

use zs::wire_client::WireClient;
use zs_wire::AuditIngestRecord;

pub(crate) const MAX_BATCH_BYTES: usize = 1 << 20;

#[derive(Clone)]
pub(crate) struct ShipCursor {
    path: PathBuf,
}

impl ShipCursor {
    pub(crate) fn beside(journal: &Path) -> ShipCursor {
        let mut path = journal.as_os_str().to_os_string();
        path.push(".shipped");
        ShipCursor {
            path: PathBuf::from(path),
        }
    }

    pub(crate) fn load_or_init(&self, fallback: u64) -> std::io::Result<u64> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(text.trim().parse().unwrap_or_else(|_| {
                stderr_line!("zs: the audit ship cursor is unreadable; reshipping the journal");
                0
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.store(fallback)?;
                Ok(fallback)
            }
            Err(e) => Err(e),
        }
    }

    pub(crate) fn store(&self, seq: u64) -> std::io::Result<()> {
        let mut temp = self.path.as_os_str().to_os_string();
        temp.push(format!(".tmp{}", std::process::id()));
        let temp = PathBuf::from(temp);
        let _ = std::fs::remove_file(&temp);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let written = options
            .open(&temp)
            .and_then(|mut file| {
                writeln!(file, "{seq}")?;
                file.sync_all()
            })
            .and_then(|()| std::fs::rename(&temp, &self.path));
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        written
    }
}

pub(crate) fn batches(
    records: Vec<(u64, AuditIngestRecord)>,
    max_bytes: usize,
) -> Vec<Vec<(u64, AuditIngestRecord)>> {
    let mut out = Vec::new();
    let mut batch = Vec::new();
    let mut size = 2usize;
    for (seq, record) in records {
        let len = serde_json::to_vec(&record).map_or(max_bytes, |json| json.len());
        if !batch.is_empty() && size.saturating_add(len + 1) > max_bytes {
            out.push(std::mem::take(&mut batch));
            size = 2;
        }
        size = size.saturating_add(len + usize::from(!batch.is_empty()));
        batch.push((seq, record));
    }
    if !batch.is_empty() {
        out.push(batch);
    }
    out
}

pub(crate) async fn ship_audit(
    wire: &WireClient,
    journal: &Path,
    cursor: &ShipCursor,
    shipped: &mut u64,
) {
    let path = journal.to_path_buf();
    let device_id = wire.device_id().to_string();
    let after = *shipped;
    let records = match tokio::task::spawn_blocking(move || {
        unshipped_records(&path, after, &device_id)
    })
    .await
    {
        Ok(Ok(records)) => records,
        Ok(Err(e)) => {
            stderr_line!("zs: cannot read the audit journal to ship it: {e}");
            return;
        }
        Err(e) => {
            stderr_line!("zs: the audit journal read did not finish: {e}");
            return;
        }
    };
    for batch in batches(records, MAX_BATCH_BYTES) {
        let highest = batch.iter().map(|(seq, _)| *seq).fold(*shipped, u64::max);
        let records: Vec<AuditIngestRecord> = batch.into_iter().map(|(_, record)| record).collect();
        if let Err(e) = wire.submit_audit(&records).await {
            stderr_line!("zs: cannot ship {} audit record(s): {e}", records.len());
            return;
        }
        *shipped = highest;
        if let Err(e) = cursor.store(highest) {
            stderr_line!("zs: cannot record the audit ship cursor: {e}");
        }
    }
}

pub(crate) fn unshipped_records(
    journal: &Path,
    after_seq: u64,
    device_id: &str,
) -> std::io::Result<Vec<(u64, AuditIngestRecord)>> {
    let content = match std::fs::read_to_string(journal) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut records = Vec::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let Ok(record) = serde_json::from_str::<zs_audit::AuditRecord>(line) else {
            continue;
        };
        if record.seq <= after_seq {
            continue;
        }
        records.push((
            record.seq,
            AuditIngestRecord {
                subject: record.subject,
                workload: record.workload,
                resource: record.resource,
                protocol: record.protocol,
                operation: record.operation,
                decision: match record.decision {
                    zs_audit::Decision::Allow => "allow",
                    zs_audit::Decision::Deny => "deny",
                    zs_audit::Decision::Passthrough => "passthrough",
                }
                .to_string(),
                reason: record.reason,
                credential_ref: record.credential_ref,
                timestamp_ms: record.timestamp_ms,
                device_id: device_id.to_string(),
                seq: Some(record.seq),
                hash: Some(record.hash),
            },
        ));
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use zs_audit::{AuditRequest, Decision, Journal};

    fn request(reason: Option<String>) -> AuditRequest {
        AuditRequest {
            subject: "alice@example.test".into(),
            workload: "claude-code".into(),
            resource: "api.example.test:443".into(),
            protocol: "https".into(),
            operation: "connect".into(),
            decision: Decision::Deny,
            reason,
            credential_ref: None,
        }
    }

    fn record(reason_bytes: usize) -> AuditIngestRecord {
        AuditIngestRecord {
            subject: "alice@example.test".into(),
            workload: "claude-code".into(),
            resource: "api.example.test:443".into(),
            protocol: "https".into(),
            operation: "connect".into(),
            decision: "deny".into(),
            reason: Some("r".repeat(reason_bytes)),
            credential_ref: None,
            timestamp_ms: 5000,
            device_id: "dev-1".into(),
            seq: None,
            hash: None,
        }
    }

    fn records_totalling(bytes: usize) -> Vec<(u64, AuditIngestRecord)> {
        let each = 100_000;
        (1..=(bytes / each) as u64 + 1)
            .map(|seq| (seq, record(each)))
            .collect()
    }

    fn strip(batch: &[(u64, AuditIngestRecord)]) -> Vec<&AuditIngestRecord> {
        batch.iter().map(|(_, record)| record).collect()
    }

    fn flatten_seqs(batches: &[Vec<(u64, AuditIngestRecord)>]) -> Vec<u64> {
        batches.iter().flatten().map(|(seq, _)| *seq).collect()
    }

    #[test]
    fn missing_cursor_starts_at_the_fallback_and_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let c = ShipCursor::beside(&dir.join("audit.jsonl"));
        assert_eq!(c.load_or_init(41).unwrap(), 41);
        assert_eq!(
            std::fs::read_to_string(dir.join("audit.jsonl.shipped"))
                .unwrap()
                .trim(),
            "41"
        );
    }

    #[test]
    fn cursor_file_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("audit.jsonl");
        let c = ShipCursor::beside(&journal);
        assert_eq!(c.load_or_init(3).unwrap(), 3);
        c.store(97).unwrap();
        assert_eq!(ShipCursor::beside(&journal).load_or_init(0).unwrap(), 97);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            leftovers,
            vec![std::ffi::OsString::from("audit.jsonl.shipped")]
        );
    }

    #[test]
    fn a_corrupt_cursor_reships_the_whole_journal() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("audit.jsonl");
        std::fs::write(dir.path().join("audit.jsonl.shipped"), "not a seq\n").unwrap();
        assert_eq!(ShipCursor::beside(&journal).load_or_init(41).unwrap(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn the_cursor_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let c = ShipCursor::beside(&dir.path().join("audit.jsonl"));
        c.store(5).unwrap();
        let mode = std::fs::metadata(dir.path().join("audit.jsonl.shipped"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "mode {mode:o}");
    }

    #[test]
    fn batches_stay_under_the_byte_cap() {
        let records = records_totalling(3 << 20);
        let n = records.len() as u64;
        let out = batches(records, MAX_BATCH_BYTES);
        assert!(out.len() >= 3);
        assert!(
            out.iter()
                .all(|b| serde_json::to_vec(&strip(b)).unwrap().len() <= MAX_BATCH_BYTES)
        );
        assert_eq!(flatten_seqs(&out), (1..=n).collect::<Vec<_>>());
    }

    #[test]
    fn a_record_over_the_cap_ships_alone_and_is_not_dropped() {
        let records = vec![(1, record(10)), (2, record(2_000)), (3, record(10))];
        let out = batches(records, 1_000);
        assert_eq!(out.len(), 3);
        assert_eq!(flatten_seqs(&out), vec![1, 2, 3]);
    }

    #[test]
    fn unshipped_records_carry_the_reason_seq_and_chain_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&path).unwrap();
        journal.append(&request(None), 5000).unwrap();
        journal
            .append(&request(Some("grant g-1 is revoked".into())), 5000)
            .unwrap();
        let hashes: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<zs_audit::AuditRecord>(line)
                    .unwrap()
                    .hash
            })
            .collect();
        let records = unshipped_records(&path, 0, "dev-1").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].1.reason, None);
        assert_eq!(records[1].1.reason.as_deref(), Some("grant g-1 is revoked"));
        assert_eq!(records[1].1.seq, Some(2));
        assert_eq!(records[1].1.hash.as_deref(), Some(hashes[1].as_str()));
        assert_eq!(unshipped_records(&path, 1, "dev-1").unwrap().len(), 1);
    }

    fn client_for(wire_url: String) -> WireClient {
        let tls_key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&tls_key)
            .unwrap();
        let ca_pem = certificate.pem();
        let verifying = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let enrolment = zs::device::Enrolment {
            control: "http://c".into(),
            control_ca_sha256: zs::control_ca_sha256(&ca_pem),
            subject: "alice@example.test".into(),
            device_id: "dev-x".into(),
            organization: "default".into(),
            client_certificate: ca_pem.clone(),
            grant_verifying_key_hex: verifying
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
            grant_verifying_key_id: "control-k1".into(),
            wire_url,
            environment: None,
            control_ca_pems: Vec::new(),
        };
        let secrets = zs::device::DeviceSecrets::new(
            zs_mitm::Zeroizing::new(tls_key.serialize_pem()),
            zs_mitm::Zeroizing::new(vec![7u8; 32]),
        );
        WireClient::from_identity(&ca_pem, &enrolment, &secrets).unwrap()
    }

    async fn wire_accepting_first_batch_only(batches: Arc<AtomicUsize>) -> String {
        let app = axum::Router::new().route(
            "/wire/audit",
            axum::routing::post(move |_body: axum::body::Bytes| async move {
                if batches.fetch_add(1, Ordering::SeqCst) == 0 {
                    axum::http::StatusCode::OK
                } else {
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn a_failed_batch_leaves_the_cursor_at_the_last_success() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("audit.jsonl");
        let journal = Journal::open(&journal_path).unwrap();
        for _ in 0..4 {
            journal
                .append(&request(Some("r".repeat(400_000))), 5000)
                .unwrap();
        }
        let all = unshipped_records(&journal_path, 0, "dev-x").unwrap();
        let planned = batches(all, MAX_BATCH_BYTES);
        assert!(planned.len() >= 2, "the journal must need two batches");
        let last_seq_of_first_batch = planned[0].last().unwrap().0;

        let calls = Arc::new(AtomicUsize::new(0));
        let wire = client_for(wire_accepting_first_batch_only(calls.clone()).await);
        let cursor = ShipCursor::beside(&journal_path);
        let mut shipped = cursor.load_or_init(0).unwrap();
        ship_audit(&wire, &journal_path, &cursor, &mut shipped).await;

        assert_eq!(calls.load(Ordering::SeqCst), 2, "it stops at the refusal");
        assert_eq!(shipped, last_seq_of_first_batch);
        assert_eq!(cursor.load_or_init(0).unwrap(), last_seq_of_first_batch);
    }
}
