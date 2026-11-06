#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{
    AgentProcess, EchoMode, FakeUpstream, TestHome, bin_path, spawn_agent, spawn_echo_upstream,
    write_test_setup_granting,
};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

const SECRET: &str = "sk_test_zsv_synthetic_value_9f27c4d1";

struct EchoAgent {
    agent: AgentProcess,
    upstream: FakeUpstream,
    audit: PathBuf,
    _temp: TestHome,
}

impl Drop for EchoAgent {
    fn drop(&mut self) {
        let _ = self.agent.child.kill();
        let _ = self.agent.child.wait();
    }
}

impl EchoAgent {
    // The whole reply the workload receives: status line, head and body.
    fn request(&self, method: &str, path: &str) -> String {
        let mut stream = std::net::TcpStream::connect(&self.agent.proxy_addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        stream
            .write_all(&common::authorized_for_proxy(
                &self.agent.proxy_addr,
                format!(
                    "{method} http://api.stripe.com{path} HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            ))
            .unwrap();
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply);
        String::from_utf8_lossy(&reply).into_owned()
    }

    fn get(&self, path: &str) -> String {
        self.request("GET", path)
    }
}

fn setup(mode: EchoMode, auth: Option<&str>) -> EchoAgent {
    let temp = TestHome::new(".zs-ca");
    let dir = PathBuf::from(temp.path());
    let upstream = spawn_echo_upstream(mode);
    let (policy, creds, audit, ca_dir, _) = write_test_setup_granting(
        &dir,
        upstream.addr.port(),
        true,
        true,
        &["*"],
        false,
        None,
        "http",
    );
    let text = std::fs::read_to_string(&policy).unwrap();
    let auth = auth
        .map(|a| format!(r#""auth": {a}, "#))
        .unwrap_or_default();
    let text = text.replace(
        r#""resource": "stripe-production", "host""#,
        &format!(r#""resource": "stripe-production", "protocol": "http", {auth}"host""#),
    );
    std::fs::write(&policy, text).unwrap();
    let agent = spawn_agent(
        bin_path().as_path(),
        policy.as_path(),
        creds.as_path(),
        audit.as_path(),
        ca_dir.as_path(),
        &["sleep", "30"],
        true,
    )
    .expect("agent spawn");
    EchoAgent {
        agent,
        upstream,
        audit,
        _temp: temp,
    }
}

fn setup_echo(mode: EchoMode) -> EchoAgent {
    setup(mode, None)
}

fn setup_echo_query(mode: EchoMode) -> EchoAgent {
    setup(
        mode,
        Some(r#"{"scheme": "query-param", "param": "api_key"}"#),
    )
}

fn audit_records(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn denied_because(agent: &EchoAgent, reason: &str) -> bool {
    audit_records(&agent.audit)
        .iter()
        .any(|r| r["decision"] == "deny" && r["reason"] == reason)
}

#[test]
fn an_upstream_that_echoes_the_credential_in_a_header_is_refused() {
    let quiet = setup_echo(EchoMode::Nothing);
    let reply = quiet.get("/v1/charges");
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(
        quiet.upstream.last_head.lock().unwrap().contains(SECRET),
        "the positive control must inject the credential"
    );
    assert!(!denied_because(&quiet, "response echo"));

    let agent = setup_echo(EchoMode::AuthorizationInHeader("x-debug-auth"));
    let reply = agent.get("/v1/charges");
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    assert!(!reply.contains(SECRET), "{reply}");
    assert!(
        !reply.to_ascii_lowercase().contains("x-debug-auth"),
        "{reply}"
    );
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 1);
    assert!(
        denied_because(&agent, "response echo"),
        "{:?}",
        audit_records(&agent.audit)
    );
}

#[test]
fn a_redirect_that_keeps_a_query_credential_is_refused() {
    let quiet = setup_echo_query(EchoMode::Nothing);
    let reply = quiet.get("/v1/charges");
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(
        quiet
            .upstream
            .last_head
            .lock()
            .unwrap()
            .contains(&format!("api_key={SECRET}")),
        "the positive control must inject the query credential"
    );

    let agent = setup_echo_query(EchoMode::QueryInLocation);
    let reply = agent.get("/v1/charges");
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    assert!(!reply.contains(SECRET), "{reply}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 1);
    assert!(denied_because(&agent, "response echo"));
}

#[test]
fn trace_on_an_injected_binding_is_refused_before_materialization() {
    let agent = setup_echo(EchoMode::Trace);
    let reply = agent.get("/v1/charges");
    assert!(!reply.contains(SECRET), "{reply}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 1);
    assert!(denied_because(&agent, "response echo"));

    let reply = agent.request("TRACE", "/v1/charges");
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    assert!(!reply.contains(SECRET), "{reply}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 1);
    assert!(
        denied_because(&agent, "trace refused"),
        "{:?}",
        audit_records(&agent.audit)
    );
}

#[test]
fn an_injected_request_asks_for_identity_encoding() {
    let agent = setup_echo(EchoMode::Nothing);
    let reply = agent.get("/v1/charges");
    assert!(
        reply.starts_with("HTTP/1.1 200"),
        "{reply} {:?}",
        audit_records(&agent.audit)
    );
    let head = agent
        .upstream
        .last_head
        .lock()
        .unwrap()
        .to_ascii_lowercase();
    assert!(head.contains("accept-encoding: identity"), "{head}");
}

const QUIET_BODY: &str = r#"{"object":"list","data":[]}"#;

#[test]
fn a_body_that_echoes_the_credential_is_cut_and_audited() {
    let quiet = setup_echo(EchoMode::Nothing);
    assert!(quiet.get("/v1/charges").ends_with(QUIET_BODY));
    assert!(!denied_because(&quiet, "response echo"));
    for chunked in [false, true] {
        let agent = setup_echo(EchoMode::AuthorizationInBody { chunked });
        let reply = agent.get("/v1/charges");
        assert_eq!(
            agent.upstream.requests.load(Ordering::SeqCst),
            1,
            "chunked={chunked}"
        );
        assert!(!reply.contains(SECRET), "chunked={chunked}");
        assert!(
            audit_records(&agent.audit)
                .iter()
                .any(|r| r["decision"] == "deny" && r["reason"] == "response echo"),
            "chunked={chunked}: {:?}",
            audit_records(&agent.audit)
        );
    }
}

#[test]
fn a_compressed_response_to_an_injected_request_is_denied() {
    let quiet = setup_echo(EchoMode::Nothing);
    assert!(quiet.get("/v1/charges").starts_with("HTTP/1.1 200"));
    let agent = setup_echo(EchoMode::GzipBody);
    let reply = agent.get("/v1/charges");
    assert!(reply.starts_with("HTTP/1.1 502"), "{reply}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 1);
    assert!(
        denied_because(&agent, "response encoded"),
        "{:?}",
        audit_records(&agent.audit)
    );
}
