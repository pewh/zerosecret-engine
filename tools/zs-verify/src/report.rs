use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub(crate) const CHILD_ENVIRONMENT: &str = "child_environment";
pub(crate) const CHILD_FILES: &str = "child_files";
pub(crate) const CHILD_MEMORY: &str = "child_memory";
pub(crate) const AGENT_LISTENER: &str = "agent_listener";
pub(crate) const AGENT_OUTPUT: &str = "agent_output";

const REQUIRED_VECTORS: [&str; 4] = [CHILD_ENVIRONMENT, CHILD_FILES, AGENT_LISTENER, AGENT_OUTPUT];
const COMPLETE: &str = "complete";
const INCOMPLETE: &str = "incomplete";
const ENVIRONMENT_METHOD: &str = "child self-report (macOS cannot read foreign environ post-exec)";

pub(crate) struct DecisionEvidence {
    pub(crate) upstream_requests: usize,
    pub(crate) upstream_auth_ok: usize,
    pub(crate) upstream_auth_mismatch: usize,
    pub(crate) negative_control_rejected: bool,
}

pub(crate) struct VectorEvidence {
    pub(crate) status: &'static str,
    pub(crate) found: Option<bool>,
    pub(crate) files_scanned: Option<usize>,
    pub(crate) files_skipped: Option<usize>,
    pub(crate) reason: Option<&'static str>,
}

impl VectorEvidence {
    pub(crate) fn complete(found: bool) -> Self {
        Self {
            status: COMPLETE,
            found: Some(found),
            files_scanned: None,
            files_skipped: None,
            reason: None,
        }
    }

    pub(crate) fn incomplete(reason: &'static str) -> Self {
        Self {
            status: INCOMPLETE,
            found: None,
            files_scanned: None,
            files_skipped: None,
            reason: Some(reason),
        }
    }

    fn to_json(&self, name: &str) -> Value {
        let mut out = Map::new();
        out.insert("status".into(), json!(self.status));
        if name == CHILD_ENVIRONMENT && self.status == COMPLETE {
            out.insert("method".into(), json!(ENVIRONMENT_METHOD));
        }
        if let Some(found) = self.found {
            out.insert("found".into(), json!(found));
        }
        if let Some(files_scanned) = self.files_scanned {
            out.insert("files_scanned".into(), json!(files_scanned));
        }
        if let Some(files_skipped) = self.files_skipped {
            out.insert("files_skipped".into(), json!(files_skipped));
        }
        if let Some(reason) = self.reason {
            out.insert("reason".into(), json!(reason));
        }
        Value::Object(out)
    }
}

pub(crate) struct VerificationReport {
    pub(crate) leaked: bool,
    pub(crate) vectors: BTreeMap<&'static str, VectorEvidence>,
    pub(crate) decisions: DecisionEvidence,
    pub(crate) elapsed_ms: u64,
}

impl VerificationReport {
    pub(crate) fn succeeds(&self) -> bool {
        let decisions = &self.decisions;
        !self.leaked
            && decisions.upstream_requests > 0
            && decisions.upstream_auth_ok > 0
            && decisions.upstream_auth_mismatch == 0
            && decisions.negative_control_rejected
            && self.evidence_complete()
            && REQUIRED_VECTORS.iter().all(|name| {
                self.vectors
                    .get(name)
                    .is_some_and(|vector| vector.found == Some(false))
            })
    }

    fn evidence_complete(&self) -> bool {
        REQUIRED_VECTORS.iter().all(|name| {
            self.vectors
                .get(name)
                .is_some_and(|vector| vector.status == COMPLETE)
        }) && self
            .vectors
            .get(CHILD_FILES)
            .and_then(|vector| vector.files_scanned)
            .is_some_and(|scanned| scanned > 0)
    }

    pub(crate) fn exit_code(&self) -> i32 {
        if self.succeeds() {
            0
        } else if self.leaked || self.evidence_complete() {
            1
        } else {
            2
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        let vectors: Map<String, Value> = self
            .vectors
            .iter()
            .map(|(name, vector)| (name.to_string(), vector.to_json(name)))
            .collect();
        let incomplete: Vec<&str> = self
            .vectors
            .values()
            .filter(|vector| vector.status != COMPLETE)
            .filter_map(|vector| vector.reason)
            .collect();
        json!({
            "leaked": self.leaked,
            "incomplete": incomplete,
            "vectors": vectors,
            "decisions": {
                "upstream_requests": self.decisions.upstream_requests,
                "upstream_auth_ok": self.decisions.upstream_auth_ok,
                "upstream_auth_mismatch": self.decisions.upstream_auth_mismatch,
                "negative_control_rejected": self.decisions.negative_control_rejected,
            },
            "latency_p50_ms": null,
            "latency_p95_ms": null,
            "rss_bytes": null,
            "elapsed_ms": self.elapsed_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const REQUIRED: [&str; 4] = [
        "child_environment",
        "child_files",
        "agent_listener",
        "agent_output",
    ];
    const MEMORY_REASON: &str = "forced core dumps are unavailable on this platform in v0";

    fn complete(found: bool) -> VectorEvidence {
        VectorEvidence {
            status: "complete",
            found: Some(found),
            files_scanned: None,
            files_skipped: None,
            reason: None,
        }
    }

    fn passing() -> VerificationReport {
        let mut vectors = std::collections::BTreeMap::new();
        vectors.insert("child_environment", complete(false));
        vectors.insert(
            "child_files",
            VectorEvidence {
                files_scanned: Some(12),
                files_skipped: Some(3),
                ..complete(false)
            },
        );
        vectors.insert(
            "child_memory",
            VectorEvidence {
                status: "incomplete",
                found: None,
                files_scanned: None,
                files_skipped: None,
                reason: Some(MEMORY_REASON),
            },
        );
        vectors.insert("agent_listener", complete(false));
        vectors.insert("agent_output", complete(false));
        VerificationReport {
            leaked: false,
            vectors,
            decisions: DecisionEvidence {
                upstream_requests: 1,
                upstream_auth_ok: 1,
                upstream_auth_mismatch: 0,
                negative_control_rejected: true,
            },
            elapsed_ms: 7,
        }
    }

    fn vector<'a>(report: &'a mut VerificationReport, name: &str) -> &'a mut VectorEvidence {
        report
            .vectors
            .get_mut(name)
            .unwrap_or_else(|| panic!("the passing report carries {name}"))
    }

    fn assert_fails(report: &VerificationReport, condition: &str) {
        assert!(!report.succeeds(), "{condition} must fail the predicate");
        assert_ne!(report.exit_code(), 0, "{condition} must not exit 0");
    }

    #[test]
    fn a_report_with_every_predicate_holding_succeeds() {
        let report = passing();
        assert!(report.succeeds());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn a_leak_fails() {
        let mut report = passing();
        report.leaked = true;
        assert_fails(&report, "leaked");
    }

    #[test]
    fn zero_upstream_requests_fails() {
        let mut report = passing();
        report.decisions.upstream_requests = 0;
        assert_fails(&report, "zero upstream requests");
    }

    #[test]
    fn zero_upstream_auth_successes_fails() {
        let mut report = passing();
        report.decisions.upstream_auth_ok = 0;
        assert_fails(&report, "zero upstream auth successes");
    }

    #[test]
    fn an_upstream_auth_mismatch_fails() {
        let mut report = passing();
        report.decisions.upstream_auth_mismatch = 1;
        assert_fails(&report, "an upstream auth mismatch");
    }

    #[test]
    fn a_failed_negative_control_fails() {
        let mut report = passing();
        report.decisions.negative_control_rejected = false;
        assert_fails(&report, "a negative control that was not rejected");
    }

    #[test]
    fn each_incomplete_required_vector_fails() {
        for name in REQUIRED {
            let mut report = passing();
            vector(&mut report, name).status = "incomplete";
            assert_fails(&report, &format!("an incomplete {name}"));
        }
    }

    #[test]
    fn each_required_vector_found_true_fails() {
        for name in REQUIRED {
            let mut report = passing();
            vector(&mut report, name).found = Some(true);
            assert_fails(&report, &format!("{name} found the credential"));
        }
    }

    #[test]
    fn a_complete_required_vector_without_a_verdict_fails() {
        for name in REQUIRED {
            let mut report = passing();
            vector(&mut report, name).found = None;
            assert_fails(&report, &format!("{name} without a verdict"));
        }
    }

    #[test]
    fn a_missing_required_vector_fails() {
        for name in REQUIRED {
            let mut report = passing();
            report.vectors.remove(name);
            assert_fails(&report, &format!("a missing {name}"));
        }
    }

    #[test]
    fn a_file_scan_of_zero_files_fails() {
        let mut report = passing();
        vector(&mut report, "child_files").files_scanned = Some(0);
        assert_fails(&report, "a file scan of zero files");

        let mut report = passing();
        vector(&mut report, "child_files").files_scanned = None;
        assert_fails(&report, "a file scan without a count");
    }

    #[test]
    fn an_incomplete_child_memory_vector_does_not_decide_the_exit() {
        let report = passing();
        assert_eq!(report.vectors["child_memory"].status, "incomplete");
        assert!(report.succeeds());

        let mut report = passing();
        report.vectors.remove("child_memory");
        assert!(report.succeeds());
    }

    #[test]
    fn complete_evidence_of_a_leak_or_a_failed_control_exits_1() {
        let mut leak = passing();
        leak.leaked = true;
        let mut found = passing();
        vector(&mut found, "agent_output").found = Some(true);
        let mut vacuous = passing();
        vacuous.decisions.upstream_requests = 0;
        let mut unauthorized = passing();
        unauthorized.decisions.upstream_auth_ok = 0;
        let mut mismatch = passing();
        mismatch.decisions.upstream_auth_mismatch = 1;
        let mut control = passing();
        control.decisions.negative_control_rejected = false;
        for report in [leak, found, vacuous, unauthorized, mismatch, control] {
            assert_eq!(report.exit_code(), 1);
        }
    }

    #[test]
    fn incomplete_evidence_exits_2() {
        let mut incomplete = passing();
        vector(&mut incomplete, "child_environment").status = "incomplete";
        let mut missing = passing();
        missing.vectors.remove("agent_listener");
        let mut empty_scan = passing();
        vector(&mut empty_scan, "child_files").files_scanned = Some(0);
        for report in [incomplete, missing, empty_scan] {
            assert_eq!(report.exit_code(), 2);
        }
    }

    #[test]
    fn an_observed_leak_exits_1_even_when_other_evidence_is_incomplete() {
        let mut report = passing();
        vector(&mut report, "agent_listener").status = "incomplete";
        vector(&mut report, "child_environment").found = Some(true);
        report.leaked = true;
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn the_json_keeps_every_existing_field_and_adds_the_control() {
        let json = passing().to_json();
        assert_eq!(json["leaked"], false);
        assert_eq!(json["incomplete"], serde_json::json!([MEMORY_REASON]));
        assert_eq!(json["latency_p50_ms"], serde_json::Value::Null);
        assert_eq!(json["latency_p95_ms"], serde_json::Value::Null);
        assert_eq!(json["rss_bytes"], serde_json::Value::Null);
        assert_eq!(json["elapsed_ms"], 7);

        let decisions = &json["decisions"];
        assert_eq!(decisions["upstream_requests"], 1);
        assert_eq!(decisions["upstream_auth_ok"], 1);
        assert_eq!(decisions["upstream_auth_mismatch"], 0);
        assert_eq!(decisions["negative_control_rejected"], true);

        let vectors = &json["vectors"];
        for name in REQUIRED {
            assert_eq!(vectors[name]["status"], "complete", "{name}");
            assert_eq!(vectors[name]["found"], false, "{name}");
        }
        assert_eq!(vectors["child_files"]["files_scanned"], 12);
        assert_eq!(vectors["child_files"]["files_skipped"], 3);
        assert!(vectors["child_environment"]["method"].is_string());
        assert_eq!(vectors["child_memory"]["status"], "incomplete");
        assert_eq!(vectors["child_memory"]["reason"], MEMORY_REASON);
    }

    #[test]
    fn an_incomplete_vector_carries_no_verdict_in_the_json() {
        let json = passing().to_json();
        let memory = json["vectors"]["child_memory"]
            .as_object()
            .expect("child_memory is an object");
        assert!(!memory.contains_key("found"));
        assert!(!memory.contains_key("files_scanned"));
    }
}
