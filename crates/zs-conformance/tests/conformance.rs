#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use zs_conformance::report::{CaseReport, Outcome, Report};

const CRATE_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn crate_path(relative: &str) -> PathBuf {
    Path::new(CRATE_DIR).join(relative)
}

fn relative_path(path: &Path) -> String {
    path.strip_prefix(CRATE_DIR)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn walk(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, visit);
        } else if path.is_file() {
            visit(&path);
        }
    }
}

#[test]
fn the_manifest_names_no_zerosecret_crate() {
    let text = fs::read_to_string(crate_path("Cargo.toml")).expect("read the manifest");
    let manifest: toml::Value = toml::from_str(&text).expect("parse the manifest");
    for table in ["dependencies", "dev-dependencies"] {
        if let Some(toml::Value::Table(entries)) = manifest.get(table) {
            for key in entries.keys() {
                assert!(!key.starts_with("zs-"), "{table} names {key}");
                assert_ne!(key, "control", "{table} names control");
            }
        }
    }
}

#[test]
fn no_case_source_names_zerosecret() {
    let needles = ["zerosecret", "zs-policy", "zs "];
    walk(&crate_path("src"), &mut |path| {
        let text = fs::read_to_string(path).unwrap_or_default().to_lowercase();
        for needle in needles {
            assert!(
                !text.contains(needle),
                "{} names {needle}",
                relative_path(path)
            );
        }
    });
}

#[test]
fn the_registry_enumerates_without_a_config() {
    let dir = tempfile::tempdir().expect("temp dir");
    let previous = std::env::current_dir().expect("current dir");
    std::env::set_current_dir(dir.path()).expect("enter the temp dir");
    let cases = zs_conformance::registry();
    std::env::set_current_dir(&previous).expect("restore the current dir");
    assert!(!cases.is_empty());
}

#[test]
fn the_adapter_script_is_the_only_file_that_names_the_implementation() {
    let allowed = ["README.md", "adapters/zerosecret.sh", "conformance.toml"];
    let mut matches = Vec::new();
    walk(&crate_path(""), &mut |path| {
        let relative = relative_path(path);
        if relative.starts_with("tests/") || relative.starts_with("target/") {
            return;
        }
        let text = fs::read_to_string(path).unwrap_or_default().to_lowercase();
        if text.contains("zerosecret") {
            matches.push(relative);
        }
    });
    assert!(
        matches.iter().all(|path| allowed.contains(&path.as_str())),
        "unexpected paths name the implementation: {matches:?}"
    );
    assert!(
        matches.iter().any(|path| path == "conformance.toml"),
        "the config must name the implementation: {matches:?}"
    );
}

#[test]
fn a_report_redacts_every_occurrence_of_a_secret() {
    let mut report = Report {
        cases: vec![CaseReport {
            id: "X-01".to_string(),
            outcome: Outcome::Fail("the client rejected hunter2-fixture".to_string()),
            controls: vec![(
                "X-01-wrongpass".to_string(),
                Outcome::Fail("hunter2-fixture was accepted".to_string()),
            )],
            evidence: "output hunter2-fixture hunter2-fixture".to_string(),
        }],
    };
    report.redact(&["hunter2-fixture".to_string()]);
    let markdown = report.to_markdown();
    let json = serde_json::to_string(&report).expect("serialize the report");
    for text in [markdown.as_str(), json.as_str()] {
        assert!(!text.contains("hunter2-fixture"));
        assert!(text.contains("[REDACTED]"));
    }
}

#[test]
fn a_secret_that_contains_another_is_redacted_whole() {
    let mut report = Report {
        cases: vec![CaseReport {
            id: "X-01".to_string(),
            outcome: Outcome::Pass,
            controls: Vec::new(),
            evidence: "the client printed hunter2-fixture-long".to_string(),
        }],
    };
    report.redact(&["hunter2".to_string(), "hunter2-fixture-long".to_string()]);
    assert_eq!(report.cases[0].evidence, "the client printed [REDACTED]");
}

#[test]
fn the_exit_code_is_non_zero_when_a_case_skipped() {
    let report = Report {
        cases: vec![
            CaseReport {
                id: "X-01".to_string(),
                outcome: Outcome::Pass,
                controls: Vec::new(),
                evidence: String::new(),
            },
            CaseReport {
                id: "X-02".to_string(),
                outcome: Outcome::Skipped("no fixture".to_string()),
                controls: Vec::new(),
                evidence: String::new(),
            },
        ],
    };
    assert_eq!(report.exit_code(false), 1);
    assert_eq!(report.exit_code(true), 0);
}

#[test]
fn the_registry_has_a_unique_id_per_case() {
    let mut ids = std::collections::BTreeSet::new();
    for case in zs_conformance::registry() {
        assert!(ids.insert(case.id), "duplicate case id: {}", case.id);
    }
}
