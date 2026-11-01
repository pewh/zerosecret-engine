#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{
    AgentProcess, FakeUpstream, TestHome, bin_path, spawn_agent, spawn_fake_upstream,
    write_test_setup_granting,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

const SECRET: &str = "sk_test_zsv_synthetic_value_9f27c4d1";

struct HttpAgent {
    agent: AgentProcess,
    upstream: FakeUpstream,
    audit: PathBuf,
    dir: PathBuf,
    _temp: TestHome,
}

impl Drop for HttpAgent {
    fn drop(&mut self) {
        let _ = self.agent.child.kill();
        let _ = self.agent.child.wait();
    }
}

fn setup(protocol: &str, operations: &[&str], child: &[&str]) -> HttpAgent {
    let temp = TestHome::new(".zs-ca");
    let dir = PathBuf::from(temp.path());
    let upstream = spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) = write_test_setup_granting(
        &dir,
        upstream.addr.port(),
        true,
        true,
        operations,
        protocol == "https",
        None,
        protocol,
    );
    let text = std::fs::read_to_string(&policy).unwrap();
    let text = text.replace(
        r#""resource": "stripe-production", "host""#,
        &format!(r#""resource": "stripe-production", "protocol": "{protocol}", "host""#),
    );
    std::fs::write(&policy, text).unwrap();
    let child: Vec<String> = child
        .iter()
        .map(|a| a.replace("{dir}", dir.to_str().unwrap()))
        .collect();
    let child: Vec<&str> = child.iter().map(String::as_str).collect();
    let agent = spawn_agent(
        bin_path().as_path(),
        policy.as_path(),
        creds.as_path(),
        audit.as_path(),
        ca_dir.as_path(),
        &child,
        true,
    )
    .expect("agent spawn");
    HttpAgent {
        agent,
        upstream,
        audit,
        dir,
        _temp: temp,
    }
}

fn request(proxy: &str, method: &str, target: &str, host: &str) -> String {
    let mut stream = std::net::TcpStream::connect(proxy).unwrap();
    stream
        .write_all(
            format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status).unwrap();
    let mut rest = String::new();
    let _ = reader.read_to_string(&mut rest);
    status
}

fn audit_records(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[test]
fn an_http_binding_injects_the_credential_into_a_cleartext_upstream() {
    let agent = setup("http", &["GET"], &["sleep", "20"]);
    let status = request(
        &agent.agent.proxy_addr,
        "GET",
        "http://api.stripe.com/v1/customers",
        "api.stripe.com",
    );
    assert!(status.starts_with("HTTP/1.1 200"), "got: {status}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 1);
    let auth = agent.upstream.last_auth.lock().unwrap().clone();
    assert!(auth.contains(SECRET), "credential not injected: {auth}");
    let head = agent.upstream.last_head.lock().unwrap().clone();
    assert!(
        head.lines().any(|l| l == "Host: api.stripe.com"),
        "port 80 is the default and is not named: {head}"
    );
    let records = audit_records(&agent.audit);
    assert!(
        records.iter().any(|r| r["protocol"] == "http"
            && r["operation"] == "GET"
            && r["decision"] == "allow"),
        "audit must record the cleartext request as http: {records:?}"
    );
}

#[test]
fn an_http_binding_still_enforces_its_methods() {
    let agent = setup("http", &["GET"], &["sleep", "20"]);
    let status = request(
        &agent.agent.proxy_addr,
        "POST",
        "http://api.stripe.com/v1/customers",
        "api.stripe.com",
    );
    assert!(status.contains("502"), "got: {status}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn connect_to_an_http_binding_is_denied() {
    let agent = setup("http", &["GET"], &["sleep", "20"]);
    let status = request(
        &agent.agent.proxy_addr,
        "CONNECT",
        "api.stripe.com:443",
        "api.stripe.com:443",
    );
    assert!(status.contains("502"), "got: {status}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn an_https_request_to_an_http_binding_is_denied() {
    let agent = setup("http", &["GET"], &["sleep", "20"]);
    let status = request(
        &agent.agent.proxy_addr,
        "GET",
        "https://api.stripe.com/v1/customers",
        "api.stripe.com",
    );
    assert!(status.contains("502"), "got: {status}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn the_child_gets_http_proxy_only_when_an_http_binding_exists() {
    let probe = [
        "sh",
        "-c",
        "printf %s \"${HTTP_PROXY:-unset}\" > {dir}/http_proxy; sleep 20",
    ];
    for (protocol, expect_set) in [("http", true), ("https", false)] {
        let agent = setup(protocol, &["GET"], &probe);
        let file = agent.dir.join("http_proxy");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !file.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let value = std::fs::read_to_string(&file).unwrap();
        if expect_set {
            assert_eq!(value, format!("http://{}", agent.agent.proxy_addr));
        } else {
            assert_eq!(value, "unset");
        }
    }
}

#[test]
fn an_any_method_binding_injects_every_method() {
    let agent = setup("http", &["*"], &["sleep", "20"]);
    for method in ["DELETE", "PATCH", "OPTIONS"] {
        let status = request(
            &agent.agent.proxy_addr,
            method,
            "http://api.stripe.com/v1/customers",
            "api.stripe.com",
        );
        assert!(status.starts_with("HTTP/1.1 200"), "{method}: {status}");
    }
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 3);
    assert!(agent.upstream.last_auth.lock().unwrap().contains(SECRET));
    let logs = agent.dir.join(".zs-log");
    let text: String = std::fs::read_dir(&logs)
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    let operations: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|e| e["event"] == "binding" || e["event"] == "grant_minted")
        .map(|e| e["fields"]["operations"].clone())
        .collect();
    assert!(!operations.is_empty(), "no binding event: {text}");
    for logged in operations {
        assert_eq!(logged, serde_json::json!(["*"]), "{text}");
    }
}
