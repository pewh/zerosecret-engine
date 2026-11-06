#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const BINDINGS: &str =
    r#"{"bindings":[{"resource":"r","host":"api.example.com","protocol":"https"}]}"#;
const REQUIRED_VECTORS: [&str; 4] = [
    "child_environment",
    "child_files",
    "agent_listener",
    "agent_output",
];
const NEGATIVE_CONTROL_VALUE: &str = "zs-verify-negative-control-wrong-credential";
const LEGACY_REPORT: &str = "/tmp/zs-child-env-report.txt";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_zs-verify"))
}

fn clean_stub() -> &'static str {
    env!("CARGO_BIN_EXE_zs-stub-clean")
}

fn leaky_stub() -> &'static str {
    env!("CARGO_BIN_EXE_zs-stub-leaky")
}

fn unique(label: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{label}_{}_{nanos}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)()
    }
}

fn executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

struct Fixture {
    dir: tempfile::TempDir,
    policy: PathBuf,
    credential_file: PathBuf,
    credential: String,
    tmp: PathBuf,
    work: PathBuf,
    source_bytes: Vec<u8>,
}

impl Fixture {
    fn new(config: &str) -> Self {
        Self::with_credential(config, &unique("sk_test_zsv_v3"))
    }

    fn with_credential(config: &str, credential: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = dir.path().join("zs-policy.json");
        std::fs::write(&policy, config).unwrap();
        let creds = dir.path().join("creds");
        std::fs::create_dir(&creds).unwrap();
        let credential_file = creds.join("credential.txt");
        std::fs::write(&credential_file, credential).unwrap();
        let tmp = dir.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        std::fs::write(work.join("readme.txt"), "a workspace file").unwrap();
        let source_bytes = std::fs::read(&policy).unwrap();
        Self {
            dir,
            policy,
            credential_file,
            credential: credential.to_string(),
            tmp,
            work,
            source_bytes,
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn assert_source_unchanged(&self, when: &str) {
        assert_eq!(
            self.source_bytes,
            std::fs::read(&self.policy).unwrap(),
            "the source policy must be byte-identical {when}"
        );
    }

    fn run_dirs(&self) -> usize {
        std::fs::read_dir(&self.tmp)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("zs-verify-")
            })
            .count()
    }

    fn child_script(&self, name: &str, body: &str) -> PathBuf {
        let path = self.path().join(name);
        executable(&path, &format!("{body}\nexec sleep 3\n"));
        path
    }

    fn run(&self, extra: &[String]) -> Output {
        let mut args = vec![
            format!("--policy-file={}", self.policy.display()),
            format!("--credential-file={}", self.credential_file.display()),
            format!("--creds-dir={}", self.path().join("creds").display()),
            format!("--audit-file={}", self.path().join("audit.jsonl").display()),
        ];
        args.extend(extra.iter().cloned());
        std::fs::write(self.path().join("audit.jsonl"), "").unwrap();
        Command::new(binary())
            .args(args)
            .env("TMPDIR", &self.tmp)
            .current_dir(&self.work)
            .output()
            .expect("zs-verify must run")
    }

    fn run_stub(&self, agent: &str, flags: &str, child: Option<&Path>) -> Output {
        self.run(&[
            format!(
                "--agent-cmd={agent} --creds-file {{CREDENTIAL_FILE}} {flags} --child-cmd {{CHILD}}"
            ),
            match child {
                Some(child) => format!("--child-cmd={}", child.display()),
                None => "--child-cmd=sleep 3".to_string(),
            },
        ])
    }

    fn assert_silent_about_the_credential(&self, output: &Output) {
        assert!(
            !combined(output).contains(&self.credential),
            "no report or diagnostic may contain the credential"
        );
    }
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("the verifier prints one JSON report")
}

fn vector<'a>(report: &'a Value, name: &str) -> &'a Value {
    &report["vectors"][name]
}

fn assert_positive_decisions(report: &Value) {
    let decisions = &report["decisions"];
    assert_eq!(decisions["upstream_requests"], 1);
    assert_eq!(decisions["upstream_auth_ok"], 1);
    assert_eq!(decisions["upstream_auth_mismatch"], 0);
    assert_eq!(decisions["negative_control_rejected"], true);
}

fn assert_clean_vectors(report: &Value, except: &[&str]) {
    for name in REQUIRED_VECTORS
        .iter()
        .filter(|name| !except.contains(name))
    {
        assert_eq!(vector(report, name)["status"], "complete", "{name}");
        assert_eq!(vector(report, name)["found"], false, "{name}");
    }
    if !except.contains(&"child_files") {
        assert!(
            vector(report, "child_files")["files_scanned"]
                .as_u64()
                .unwrap()
                > 0
        );
    }
    assert_eq!(vector(report, "child_memory")["status"], "incomplete");
}

#[test]
fn a_clean_authenticated_run_exits_zero_and_leaves_nothing_behind() {
    let fixture = Fixture::new(BINDINGS);
    let seen = fixture.path().join("seen.txt");
    let child = fixture.child_script(
        "child.sh",
        &format!(
            "printf '%s\\n' \"$ZS_VERIFY_ENV_REPORT\" > {}",
            seen.display()
        ),
    );
    assert_eq!(fixture.run_dirs(), 0);

    let output = fixture.run_stub(
        clean_stub(),
        "--upstream-port {UPSTREAM_PORT}",
        Some(&child),
    );

    assert_eq!(output.status.code(), Some(0));
    let report = report(&output);
    assert_eq!(report["leaked"], false);
    assert_positive_decisions(&report);
    assert_clean_vectors(&report, &[]);
    assert!(
        report["rss_bytes"].is_null(),
        "an unmeasured resident set must be null, never a fabricated number"
    );
    let seen = std::fs::read_to_string(&seen).unwrap();
    let run_report = Path::new(seen.trim());
    assert!(run_report.starts_with(&fixture.tmp));
    assert!(
        run_report
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name.to_string_lossy().starts_with("zs-verify-"))
    );
    assert!(!run_report.exists());
    assert_eq!(
        fixture.run_dirs(),
        0,
        "a successful run removes its directory"
    );
    fixture.assert_source_unchanged("after a successful run");
    fixture.assert_silent_about_the_credential(&output);
}

#[test]
fn the_clean_stub_without_an_upstream_request_exits_one() {
    let fixture = Fixture::new(BINDINGS);

    let output = fixture.run_stub(clean_stub(), "", None);

    assert_eq!(output.status.code(), Some(1));
    let report = report(&output);
    assert_eq!(report["leaked"], false);
    assert_eq!(report["decisions"]["upstream_requests"], 0);
    assert_eq!(report["decisions"]["upstream_auth_ok"], 0);
    assert_eq!(report["decisions"]["negative_control_rejected"], true);
    assert_clean_vectors(&report, &[]);
    fixture.assert_source_unchanged("after a zero-activity run");
    fixture.assert_silent_about_the_credential(&output);
}

#[test]
fn each_leak_vector_exits_one_and_names_only_that_vector() {
    for (mode, leaked_vector) in [
        ("environment", "child_environment"),
        ("file", "child_files"),
        ("listener", "agent_listener"),
        ("output", "agent_output"),
    ] {
        let fixture = Fixture::new(BINDINGS);

        let output = fixture.run_stub(
            leaky_stub(),
            &format!("--upstream-port {{UPSTREAM_PORT}} --leak {mode}"),
            None,
        );

        assert_eq!(output.status.code(), Some(1), "{mode}");
        let report = report(&output);
        assert_eq!(report["leaked"], true, "{mode}");
        assert_eq!(vector(&report, leaked_vector)["found"], true, "{mode}");
        assert_positive_decisions(&report);
        assert_clean_vectors(&report, &[leaked_vector]);
        fixture.assert_source_unchanged("after a leak");
        fixture.assert_silent_about_the_credential(&output);
    }
}

#[test]
fn a_listener_probed_without_the_run_token_is_incomplete() {
    let fixture = Fixture::new(BINDINGS);

    let output = fixture.run_stub(
        clean_stub(),
        "--upstream-port {UPSTREAM_PORT} --no-run-token",
        None,
    );

    assert_eq!(output.status.code(), Some(2));
    let report = report(&output);
    assert_positive_decisions(&report);
    assert_eq!(vector(&report, "agent_listener")["status"], "incomplete");
    assert_eq!(
        vector(&report, "agent_listener")["reason"],
        "the agent listener was probed only without the run token"
    );
    assert_clean_vectors(&report, &["agent_listener"]);
    fixture.assert_silent_about_the_credential(&output);
}

#[test]
fn a_missing_environment_report_exits_two() {
    let fixture = Fixture::new(BINDINGS);
    let child = fixture.child_script("child.sh", "rm -f \"$ZS_VERIFY_ENV_REPORT\"");

    let output = fixture.run_stub(
        clean_stub(),
        "--upstream-port {UPSTREAM_PORT}",
        Some(&child),
    );

    assert_eq!(output.status.code(), Some(2));
    let report = report(&output);
    assert_eq!(report["leaked"], false);
    let environment = vector(&report, "child_environment");
    assert_eq!(environment["status"], "incomplete");
    assert_eq!(
        environment["reason"],
        "child environment self-report missing"
    );
    assert!(environment.get("found").is_none());
    assert_positive_decisions(&report);
    assert_clean_vectors(&report, &["child_environment"]);
    fixture.assert_source_unchanged("after a missing report");
    fixture.assert_silent_about_the_credential(&output);
}

#[test]
fn a_stale_report_outside_the_run_directory_is_ignored() {
    let fixture = Fixture::new(BINDINGS);
    let sibling = fixture.tmp.join("zs-verify-stale");
    std::fs::create_dir(&sibling).unwrap();
    std::fs::write(
        sibling.join("child-environment.txt"),
        "PATH=/bin\nHOME=/home/dev\n",
    )
    .unwrap();
    let elsewhere = fixture.path().join("zs-verify-elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    let stale = format!("PATH=/bin\nZS_CREDENTIAL={}\n", fixture.credential);
    std::fs::write(elsewhere.join("child-environment.txt"), &stale).unwrap();
    let _legacy = OnDrop(|| {
        let _ = std::fs::remove_file(LEGACY_REPORT);
    });
    std::fs::write(LEGACY_REPORT, &stale).unwrap();
    let child = fixture.child_script("child.sh", "rm -f \"$ZS_VERIFY_ENV_REPORT\"");

    let output = fixture.run_stub(
        clean_stub(),
        "--upstream-port {UPSTREAM_PORT}",
        Some(&child),
    );

    assert_eq!(output.status.code(), Some(2));
    let report = report(&output);
    let environment = vector(&report, "child_environment");
    assert_eq!(environment["status"], "incomplete");
    assert_eq!(
        environment["reason"],
        "child environment self-report missing"
    );
    assert!(environment.get("found").is_none());
    assert_eq!(report["leaked"], false);
    assert_positive_decisions(&report);
    assert_clean_vectors(&report, &["child_environment"]);
    fixture.assert_source_unchanged("after a stale-report run");
    fixture.assert_silent_about_the_credential(&output);
}

#[test]
fn a_cleanup_failure_exits_two_after_an_otherwise_passing_report() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(BINDINGS);
    let child = fixture.child_script("child.sh", &format!("chmod 555 {}", fixture.tmp.display()));
    let tmp = fixture.tmp.clone();
    let _restore = OnDrop(move || {
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    });

    let output = fixture.run_stub(
        clean_stub(),
        "--upstream-port {UPSTREAM_PORT}",
        Some(&child),
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("cannot remove the temporary run directory; refusing to trust this run")
    );
    let report = report(&output);
    assert_eq!(report["leaked"], false);
    assert_positive_decisions(&report);
    assert_clean_vectors(&report, &[]);
    fixture.assert_source_unchanged("after a cleanup failure");
    fixture.assert_silent_about_the_credential(&output);
}

#[test]
fn a_negative_control_the_oracle_cannot_reject_exits_one() {
    let fixture = Fixture::with_credential(BINDINGS, NEGATIVE_CONTROL_VALUE);

    let output = fixture.run_stub(clean_stub(), "--upstream-port {UPSTREAM_PORT}", None);

    assert_eq!(output.status.code(), Some(1));
    let report = report(&output);
    assert_eq!(report["leaked"], false);
    assert_eq!(report["decisions"]["negative_control_rejected"], false);
    assert_eq!(report["decisions"]["upstream_requests"], 1);
    assert_eq!(report["decisions"]["upstream_auth_ok"], 1);
    assert_clean_vectors(&report, &[]);
    fixture.assert_source_unchanged("after a failed negative control");
}

#[test]
fn no_sentinel_or_credential_reaches_a_report_an_error_or_argv() {
    let policy_sentinel = unique("zsv_policy_sentinel");
    let path_sentinel = unique("zsv_path_sentinel");
    let stderr_sentinel = unique("zsv_stderr_sentinel");
    let fixture = Fixture::new(&format!(
        r#"{{"bindings":[{{"resource":"r","host":"api.example.com","protocol":"https","note":"{policy_sentinel}"}}]}}"#
    ));
    let agent_dir = fixture.path().join(&path_sentinel);
    std::fs::create_dir(&agent_dir).unwrap();
    let agent = agent_dir.join("agent");
    std::os::unix::fs::symlink(clean_stub(), &agent).unwrap();
    let argv = fixture.path().join("argv.txt");
    let child = fixture.child_script(
        "child.sh",
        &format!(
            "printf '%s\\n' {stderr_sentinel} >&2\nps -axww -o args= > {}",
            argv.display()
        ),
    );

    let output = fixture.run_stub(
        &agent.display().to_string(),
        "--upstream-port {UPSTREAM_PORT}",
        Some(&child),
    );

    assert_eq!(output.status.code(), Some(0));
    let processes = std::fs::read_to_string(&argv).unwrap();
    assert!(processes.contains(&format!(
        "--credential-file={}",
        fixture.credential_file.display()
    )));
    assert!(processes.contains(&format!("{path_sentinel}/agent --creds-file")));
    assert!(
        !processes.contains(&fixture.credential),
        "no process argument list may carry the credential"
    );

    let stderr_control = fixture.child_script(
        "stderr-control.sh",
        &format!(
            "printf '%s\\n' \"$(cat {})\" >&2",
            fixture.credential_file.display()
        ),
    );
    let control = fixture.run_stub(
        &agent.display().to_string(),
        "--upstream-port {UPSTREAM_PORT}",
        Some(&stderr_control),
    );
    assert_eq!(control.status.code(), Some(1));
    assert_eq!(vector(&report(&control), "agent_output")["found"], true);

    let spawn_failure = fixture.run(&[format!("--agent-cmd={}/absent", agent_dir.display())]);
    assert_eq!(spawn_failure.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&spawn_failure.stderr)
            .contains("cannot spawn the agent; refusing to report on a scan that never ran")
    );

    let broken = fixture.path().join("broken.json");
    std::fs::write(&broken, format!("{{\"bindings\": \"{policy_sentinel}")).unwrap();
    let parse_failure = Command::new(binary())
        .args([
            format!("--policy-file={}", broken.display()),
            format!("--credential-file={}", fixture.credential_file.display()),
            format!("--agent-cmd={}", agent.display()),
        ])
        .env("TMPDIR", &fixture.tmp)
        .current_dir(&fixture.work)
        .output()
        .unwrap();
    assert_eq!(parse_failure.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&parse_failure.stderr)
            .contains("the policy file cannot be read as JSON")
    );

    for run in [&output, &control, &spawn_failure, &parse_failure] {
        let text = combined(run);
        for sentinel in [
            &policy_sentinel,
            &path_sentinel,
            &stderr_sentinel,
            &fixture.credential,
        ] {
            assert!(
                !text.contains(sentinel.as_str()),
                "a report or error echoed a sentinel"
            );
        }
    }
    fixture.assert_source_unchanged("after the sentinel runs");
}

#[test]
fn every_injected_failure_leaves_the_source_policy_byte_identical() {
    let refused = |fixture: &Fixture, output: &Output, text: &str| {
        fixture.assert_silent_about_the_credential(output);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty(), "a refusal prints no report");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(text),
            "the refusal names its cause"
        );
    };

    let invalid = Fixture::new("{ this is not json");
    let output = invalid.run(&["--agent-cmd=/usr/bin/true".to_string()]);
    refused(&invalid, &output, "the policy file cannot be read as JSON");
    invalid.assert_source_unchanged("after an invalid-JSON failure");

    let empty = Fixture::new(r#"{"signing_keys":[],"grants":[]}"#);
    let output = empty.run(&["--agent-cmd=/usr/bin/true".to_string()]);
    refused(
        &empty,
        &output,
        "the policy has no `bindings` or `resources` array",
    );
    empty.assert_source_unchanged("after a no-entries failure");

    let unspawnable = Fixture::new(BINDINGS);
    let output = unspawnable.run(&["--agent-cmd=/nonexistent/zs-verify-probe".to_string()]);
    refused(&unspawnable, &output, "cannot spawn the agent");
    unspawnable.assert_source_unchanged("after a spawn failure");

    let rejected = Fixture::new(BINDINGS);
    let output = rejected.run(&["--agent-cmd=/usr/bin/true".to_string(), "bare".to_string()]);
    refused(&rejected, &output, "every argument must be --name=value");
    rejected.assert_source_unchanged("after an argument rejection");

    let vacuous = Fixture::new(BINDINGS);
    let output = vacuous.run(&[
        "--agent-cmd=/usr/bin/true".to_string(),
        "--child-cmd=/usr/bin/true".to_string(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    let report = report(&output);
    assert_eq!(report["decisions"]["upstream_requests"], 0);
    assert_eq!(
        vector(&report, "child_environment")["reason"],
        "child environment self-report missing"
    );
    assert_eq!(
        vector(&report, "agent_listener")["reason"],
        "agent did not report a proxy address"
    );
    vacuous.assert_source_unchanged("after an agent that never reached the upstream");
    vacuous.assert_silent_about_the_credential(&output);
}

#[test]
fn each_run_receives_a_distinct_environment_report_path() {
    let fixture = Fixture::new(BINDINGS);
    let record = fixture.path().join("seen-paths.txt");
    let agent = fixture.path().join("agent.sh");
    executable(
        &agent,
        &format!(
            "printf '%s\\n' \"$ZS_VERIFY_ENV_REPORT\" >> {}\n",
            record.display()
        ),
    );

    for _ in 0..2 {
        fixture.run(&[format!("--agent-cmd={}", agent.display())]);
    }

    let seen: Vec<String> = std::fs::read_to_string(&record)
        .unwrap()
        .lines()
        .map(str::to_string)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(seen.len(), 2, "both runs must report a path: {seen:?}");
    assert_ne!(
        seen[0], seen[1],
        "two runs must not share an environment-report path"
    );
    for path in &seen {
        assert!(
            path.ends_with("/child-environment.txt"),
            "the report keeps its documented name: {path}"
        );
        assert!(Path::new(path).starts_with(&fixture.tmp));
        assert!(
            !Path::new(path).exists(),
            "the run directory must not outlive the run: {path}"
        );
    }
    assert_eq!(fixture.run_dirs(), 0);
    fixture.assert_source_unchanged("after the per-run report checks");
}

#[test]
fn the_child_command_line_carries_a_path_not_a_credential() {
    let fixture = Fixture::new(BINDINGS);
    let record = fixture.path().join("argv.txt");
    let agent = fixture.path().join("agent.sh");
    executable(
        &agent,
        &format!("printf '%s\\n' \"$@\" > {}\n", record.display()),
    );

    fixture.run(&[format!(
        "--agent-cmd={} --creds-file {{CREDENTIAL_FILE}}",
        agent.display()
    )]);

    let argv = std::fs::read_to_string(&record).unwrap();
    assert!(
        argv.contains(&fixture.credential_file.display().to_string()),
        "the template must expand to the credential PATH"
    );
    assert!(
        !argv.contains(&fixture.credential),
        "no credential value may appear in the child argument list"
    );
    assert!(!argv.contains("{CREDENTIAL_FILE}"));
    fixture.assert_source_unchanged("after the child argv check");
}

#[test]
fn the_verifier_argument_list_contains_no_credential_value() {
    let fixture = Fixture::new(BINDINGS);
    let record = fixture.path().join("parent-argv.txt");
    let agent = fixture.path().join("agent.sh");
    executable(
        &agent,
        &format!(
            "ps -o args= -p \"$PPID\" > {} 2>/dev/null || true\n",
            record.display()
        ),
    );

    fixture.run(&[format!("--agent-cmd={}", agent.display())]);

    let parent_argv = std::fs::read_to_string(&record).unwrap_or_default();
    assert!(
        parent_argv.contains("--credential-file="),
        "the verifier is invoked with a credential PATH"
    );
    assert!(
        !parent_argv.contains(&fixture.credential),
        "the credential value must never appear in the verifier's argv"
    );
    fixture.assert_source_unchanged("after the verifier argv check");
}

#[test]
fn an_agent_that_floods_stderr_does_not_hang_the_verifier() {
    let fixture = Fixture::new(BINDINGS);
    let agent = fixture.path().join("noisy-agent.sh");
    executable(
        &agent,
        "head -c 200000 /dev/zero | tr '\\0' 'x' >&2\nsleep 1\n",
    );
    std::fs::write(fixture.path().join("audit.jsonl"), "").unwrap();
    let mut verifier = Command::new(binary())
        .args([
            format!("--policy-file={}", fixture.policy.display()),
            format!("--credential-file={}", fixture.credential_file.display()),
            format!("--creds-dir={}", fixture.path().join("creds").display()),
            format!(
                "--audit-file={}",
                fixture.path().join("audit.jsonl").display()
            ),
            format!("--agent-cmd={}", agent.display()),
            "--child-cmd=/usr/bin/true".to_string(),
        ])
        .env("TMPDIR", &fixture.tmp)
        .current_dir(&fixture.work)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("zs-verify must run");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        if let Some(status) = verifier.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = verifier.kill();
            let _ = verifier.wait();
            panic!("the verifier hung on an agent that filled its stderr pipe");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };

    assert_eq!(status.code(), Some(2));
    fixture.assert_source_unchanged("after a stderr flood");
}
