#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

fn wait_for_log_text(dir: &Path, needle: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let found = std::fs::read_dir(dir.join(".zs-log"))
            .into_iter()
            .flatten()
            .filter_map(|e| std::fs::read_to_string(e.ok()?.path()).ok())
            .any(|text| text.contains(needle));
        if found {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

#[cfg(unix)]
fn end_run(agent: &mut common::TempAgent) {
    wait_for_log_text(&agent.dir, "\"child_spawned\"");
    let logs = agent.dir.join(".zs-log");
    let file = std::fs::read_dir(&logs)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let text = std::fs::read_to_string(file).unwrap();
    let spawned = text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|e| e["event"] == "child_spawned")
        .unwrap();
    let pid = spawned["fields"]["pid"].as_u64().unwrap();
    let killed = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status()
        .unwrap();
    assert!(killed.success());
    let mut process = agent.agent.take().unwrap();
    process.child.wait().unwrap();
}

fn diag_events(dir: &Path) -> (String, Vec<serde_json::Value>) {
    let logs = dir.join(".zs-log");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let files: Vec<_> = std::fs::read_dir(&logs)
            .map(|entries| entries.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default();
        if let [file] = files.as_slice() {
            let text = std::fs::read_to_string(file).unwrap();
            if text.contains("\"child_exited\"") || std::time::Instant::now() >= deadline {
                let events = text
                    .lines()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                return (text, events);
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no single log file in {logs:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn a_refused_start_still_writes_its_log() {
    let home = tempfile::tempdir().unwrap();
    let policy = home.path().join("zs-policy.json");
    std::fs::write(
        &policy,
        r#"{"bindings":[{"resource":"r","host":"h","path":["/x"]}]}"#,
    )
    .unwrap();
    let audit = home.path().join(".zs-audit").join("audit.jsonl");
    let status = std::process::Command::new(common::bin_path())
        .args(["run", "--policy"])
        .arg(&policy)
        .arg("--audit")
        .arg(&audit)
        .arg("--ca-dir")
        .arg(home.path().join(".zs-ca"))
        .args(["--", "true"])
        .output()
        .unwrap();
    assert!(
        !status.status.success(),
        "positive control: the bad config is refused"
    );
    let logs: Vec<_> = std::fs::read_dir(home.path().join(".zs-log"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    assert_eq!(logs.len(), 1);
    let text = std::fs::read_to_string(&logs[0]).unwrap();
    assert!(
        text.contains("\"run_refused\"") && text.contains("\"stage\":\"config\""),
        "{text}"
    );
    assert!(text.contains("\"run_ended\""), "{text}");
    let stderr = String::from_utf8_lossy(&status.stderr);
    assert!(stderr.contains("zs: diagnostic log "), "{stderr}");
    assert!(
        !stderr.contains("zs: diagnostic log unavailable"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_run_logs_its_lifecycle_and_bindings() {
    let mut agent = common::setup_agent(true, true);
    let process = agent.agent.as_ref().unwrap();
    let (proxy, ca) = (
        process.proxy_addr.clone(),
        std::fs::read_to_string(&process.ca_path).unwrap(),
    );
    let (status, _) = common::proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    end_run(&mut agent);
    let (text, events) = diag_events(&agent.dir);
    let has = |name: &str| events.iter().any(|e| e["event"] == name);
    for name in [
        "run_started",
        "binding",
        "listener_bound",
        "child_spawned",
        "conn_accepted",
        "classified",
        "request_decided",
        "child_exited",
        "run_ended",
    ] {
        assert!(has(name), "missing {name}: {text}");
    }
    let started = events.iter().find(|e| e["event"] == "run_started").unwrap();
    assert!(started["fields"]["subject_source"].is_string());
    let binding = events.iter().find(|e| e["event"] == "binding").unwrap();
    assert_eq!(binding["resource"], "stripe-production");
    assert_eq!(binding["fields"]["host"], "api.stripe.com");
    assert!(!text.contains("sk_test_zsv_synthetic_value_9f27c4d1"));
}

#[cfg(unix)]
#[test]
fn a_signal_killed_child_logs_its_signal_not_a_code() {
    let temp = common::TestHome::new(".zs-ca");
    let dir = temp.path().to_path_buf();
    let upstream = common::spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) =
        common::write_test_setup(&dir, upstream.addr.port(), true, true);
    let mut agent = common::spawn_agent(
        common::bin_path().as_path(),
        policy.as_path(),
        creds.as_path(),
        audit.as_path(),
        ca_dir.as_path(),
        &["sh", "-c", "kill -9 $$"],
        true,
    )
    .expect("agent spawn");
    let status = agent.child.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(1),
        "the run keeps its exit code for a signalled child"
    );
    let (text, events) = diag_events(&dir);
    assert!(
        events.iter().any(|e| e["event"] == "child_spawned"),
        "positive control: the child was spawned: {text}"
    );
    let exited = events
        .iter()
        .find(|e| e["event"] == "child_exited")
        .unwrap_or_else(|| panic!("missing child_exited: {text}"));
    assert_eq!(exited["fields"]["signal"], 9, "{text}");
    assert!(exited["fields"].get("code").is_none(), "{text}");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_run_logs_decisions_without_credentials_or_request_data() {
    let mut agent = common::setup_agent_with(true, true, &["GET", "POST"], Some(&["/oauth/token"]));
    let process = agent.agent.as_ref().unwrap();
    let (proxy, ca) = (
        process.proxy_addr.clone(),
        std::fs::read_to_string(&process.ca_path).unwrap(),
    );
    let (status, _) = common::proxied_request(&proxy, &ca, "api.stripe.com", 443, "/oauth/token")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    let forwarded = common::tunneled_exchange(
        &proxy,
        &ca,
        "api.stripe.com",
        443,
        b"GET /zs-diag-secret-segment HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token-zsdiag\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(forwarded.starts_with("HTTP/1.1 200"), "{forwarded}");
    let queried = common::tunneled_exchange(
        &proxy,
        &ca,
        "api.stripe.com",
        443,
        b"GET /zs-diag-secret-segment?zs_diag_query=1 HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(queried.starts_with("HTTP/1.1 200"), "{queried}");
    let refused = common::tunneled_exchange(
        &proxy,
        &ca,
        "api.stripe.com",
        443,
        b"GET /oauth/../oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
    end_run(&mut agent);

    let (text, events) = diag_events(&agent.dir);
    let decided: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["event"] == "request_decided")
        .collect();
    assert!(
        decided.iter().any(|e| e["fields"]["decision"] == "allow"),
        "{text}"
    );
    assert!(
        decided
            .iter()
            .any(|e| e["fields"]["decision"] == "passthrough"),
        "{text}"
    );
    assert!(
        decided
            .iter()
            .any(|e| e["fields"]["scope"] == "refuse" && e["fields"]["rule"] == "dot_segment"),
        "{text}"
    );
    assert!(decided.iter().all(|e| e["audit_seq"].is_u64()), "{text}");
    assert!(
        decided.iter().all(|e| e["fields"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v != "invalid")),
        "{text}"
    );
    for name in ["child_exited", "run_ended"] {
        assert!(events.iter().any(|e| e["event"] == name), "{name}: {text}");
    }
    for forbidden in [
        "sk_test_zsv_synthetic_value_9f27c4d1",
        "zs-diag-secret-segment",
        "zs_diag_query",
        "caller-token-zsdiag",
        "oauth/token",
    ] {
        assert!(!text.contains(forbidden), "{forbidden} leaked into the log");
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_request_target_never_puts_userinfo_or_a_path_into_dest() {
    let mut agent = common::setup_agent(true, true);
    let process = agent.agent.as_ref().unwrap();
    let (proxy, ca) = (
        process.proxy_addr.clone(),
        std::fs::read_to_string(&process.ca_path).unwrap(),
    );
    let (status, _) = common::proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    for request in [
        &b"GET https://user:zsdiag-userinfo-secret@api.stripe.com:443/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n"[..],
        &b"GET https://zsdiag-userinfo-token:x@api.stripe.com/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n"[..],
        &b"CONNECT zsdiag-connect-token:x@api.stripe.com HTTP/1.1\r\nHost: api.stripe.com\r\n\r\n"[..],
        &b"CONNECT api.stripe.com/zsdiag-connect-path:443 HTTP/1.1\r\nHost: api.stripe.com\r\n\r\n"[..],
    ] {
        common::raw_exchange(&proxy, request).await;
    }
    end_run(&mut agent);

    let (text, events) = diag_events(&agent.dir);
    let accepted: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["event"] == "conn_accepted")
        .collect();
    assert!(
        accepted.iter().any(|e| e["dest"] == "api.stripe.com:443"),
        "positive control: a clean destination is logged: {text}"
    );
    assert!(
        accepted.iter().filter(|e| e["dest"] == "invalid").count() >= 4,
        "every request with userinfo or a path was seen: {text}"
    );
    for forbidden in [
        "zsdiag-userinfo-secret",
        "zsdiag-userinfo-token",
        "zsdiag-connect-token",
        "zsdiag-connect-path",
    ] {
        assert!(!text.contains(forbidden), "{forbidden} leaked into the log");
    }
}
