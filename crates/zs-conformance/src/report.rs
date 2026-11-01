use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Pass,
    Fail(String),
    Skipped(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseReport {
    pub id: String,
    pub outcome: Outcome,
    pub controls: Vec<(String, Outcome)>,
    pub evidence: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub cases: Vec<CaseReport>,
}

impl CaseReport {
    pub fn redact(&mut self, secrets: &[String]) {
        let mut value = match serde_json::to_value(&*self) {
            Ok(value) => value,
            Err(_) => return,
        };
        redact_value(&mut value, &longest_first(secrets));
        if let Ok(redacted) = serde_json::from_value(value) {
            *self = redacted;
        }
    }
}

impl Report {
    pub fn redact(&mut self, secrets: &[String]) {
        let mut value = match serde_json::to_value(&*self) {
            Ok(value) => value,
            Err(_) => return,
        };
        redact_value(&mut value, &longest_first(secrets));
        if let Ok(redacted) = serde_json::from_value(value) {
            *self = redacted;
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::from("| Case | Result | Controls | Evidence |\n|---|---|---|---|\n");
        for case in &self.cases {
            let controls = if case.controls.is_empty() {
                "n/a".to_string()
            } else {
                case.controls
                    .iter()
                    .map(|(name, outcome)| format!("{name} {}", control_label(outcome)))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                case.id,
                result_label(&case.outcome),
                controls,
                one_line(&case.evidence)
            ));
        }
        out.push('\n');
        out.push_str(&self.summary());
        out.push('\n');
        out
    }

    pub fn write_json(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        fs::write(path, json)
    }

    pub fn exit_code(&self, allow_skips: bool) -> i32 {
        let mut code = 0;
        for case in &self.cases {
            if outcome_fails(&case.outcome, allow_skips) {
                code = 1;
            }
            for (_, outcome) in &case.controls {
                if outcome_fails(outcome, allow_skips) {
                    code = 1;
                }
            }
        }
        code
    }

    fn summary(&self) -> String {
        let mut pass = 0;
        let mut fail = 0;
        let mut skipped = 0;
        let mut failed_ids = Vec::new();
        for case in &self.cases {
            match &case.outcome {
                Outcome::Pass => pass += 1,
                Outcome::Fail(_) => {
                    fail += 1;
                    failed_ids.push(case.id.as_str());
                }
                Outcome::Skipped(_) => skipped += 1,
            }
        }
        let mut summary = format!("PASS {pass} · FAIL {fail} · SKIPPED {skipped}");
        let controls: Vec<&Outcome> = self
            .cases
            .iter()
            .flat_map(|case| case.controls.iter().map(|(_, outcome)| outcome))
            .collect();
        let refused = controls
            .iter()
            .filter(|outcome| matches!(outcome, Outcome::Pass))
            .count();
        let not_refused = controls
            .iter()
            .filter(|outcome| matches!(outcome, Outcome::Fail(_)))
            .count();
        let not_run = controls.len() - refused - not_refused;
        summary.push_str(&format!(
            " · controls REFUSED {refused} · NOT REFUSED {not_refused} · SKIPPED {not_run}"
        ));
        if !failed_ids.is_empty() {
            summary.push_str(&format!(" · failing: {}", failed_ids.join(", ")));
        }
        summary
    }
}

fn outcome_fails(outcome: &Outcome, allow_skips: bool) -> bool {
    match outcome {
        Outcome::Pass => false,
        Outcome::Fail(_) => true,
        Outcome::Skipped(_) => !allow_skips,
    }
}

fn result_label(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "PASS",
        Outcome::Fail(_) => "FAIL",
        Outcome::Skipped(_) => "SKIPPED",
    }
}

fn control_label(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "REFUSED",
        Outcome::Fail(_) => "NOT REFUSED",
        Outcome::Skipped(_) => "SKIPPED",
    }
}

fn one_line(text: &str) -> String {
    text.replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn longest_first(secrets: &[String]) -> Vec<String> {
    let mut ordered = secrets.to_vec();
    ordered.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    ordered
}

fn redact_value(value: &mut serde_json::Value, secrets: &[String]) {
    match value {
        serde_json::Value::String(text) => {
            for secret in secrets {
                if !secret.is_empty() && text.contains(secret.as_str()) {
                    *text = text.replace(secret.as_str(), "[REDACTED]");
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_value(item, secrets);
            }
        }
        serde_json::Value::Object(fields) => {
            for (_, field) in fields.iter_mut() {
                redact_value(field, secrets);
            }
        }
        _ => {}
    }
}
