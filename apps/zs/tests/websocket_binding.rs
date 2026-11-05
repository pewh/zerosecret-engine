#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod ws_fake;

use common::{AgentProcess, TestHome, bin_path, open_tunnel, spawn_agent, write_test_setup_with};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ws_fake::{Reply, Seen, frame, read_frame, read_head, spawn_ws_upstream};

const SECRET: &str = "sk_test_zsv_synthetic_value_9f27c4d1";
const AUTH: &str = r#"[{"taskType":"authentication","apiKey":"zs-brokered"}]"#;

struct WsAgent {
    agent: AgentProcess,
    seen: Arc<Mutex<Seen>>,
    audit: PathBuf,
    _temp: TestHome,
}

impl Drop for WsAgent {
    fn drop(&mut self) {
        let _ = self.agent.child.kill();
        let _ = self.agent.child.wait();
    }
}

async fn setup(reply: Reply) -> WsAgent {
    setup_scoped(reply, None).await
}

async fn setup_scoped(reply: Reply, paths: Option<&[&str]>) -> WsAgent {
    let temp = TestHome::new(".zs-ca");
    let dir = PathBuf::from(temp.path());
    let seen = Arc::new(Mutex::new(Seen::default()));
    let port = spawn_ws_upstream(reply, seen.clone()).await;
    let (policy, creds, audit, ca_dir, _) =
        write_test_setup_with(&dir, port, true, true, &["GET"], true, paths);
    let text = std::fs::read_to_string(&policy).unwrap().replace(
        r#""operations": "#,
        r#""auth": {"scheme": "websocket-json-field", "field": "apiKey"}, "operations": "#,
    );
    std::fs::write(&policy, text).unwrap();
    let agent = tokio::task::spawn_blocking(move || {
        spawn_agent(
            bin_path().as_path(),
            policy.as_path(),
            creds.as_path(),
            audit.as_path(),
            ca_dir.as_path(),
            &["sleep", "20"],
            true,
        )
    })
    .await
    .unwrap()
    .expect("agent spawn");
    WsAgent {
        audit: dir.join(".zs-audit").join("audit.jsonl"),
        agent,
        seen,
        _temp: temp,
    }
}

async fn upgrade(
    agent: &WsAgent,
) -> (
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    String,
) {
    upgrade_to(agent, "/v1").await
}

async fn upgrade_to(
    agent: &WsAgent,
    path: &str,
) -> (
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    String,
) {
    let ca = std::fs::read_to_string(&agent.agent.ca_path).unwrap();
    let mut tls = open_tunnel(&agent.agent.proxy_addr, &ca, "api.stripe.com", 443)
        .await
        .unwrap();
    tls.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: api.stripe.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let head = read_head(&mut tls).await;
    (tls, head)
}

fn audit_text(agent: &WsAgent) -> String {
    std::fs::read_to_string(&agent.audit).unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_credential_is_written_into_the_auth_message_and_never_returned() {
    let agent = setup(Reply::Ok).await;
    let (mut tls, head) = upgrade(&agent).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    tls.write_all(&frame(1, AUTH.as_bytes(), Some([7, 1, 9, 3])))
        .await
        .unwrap();
    let (opcode, reply) = read_frame(&mut tls).await.expect("a reply frame");
    assert_eq!(opcode, 1);
    assert!(!String::from_utf8_lossy(&reply).contains(SECRET));

    let seen = agent.seen.lock().unwrap();
    let message: serde_json::Value = serde_json::from_slice(&seen.message).unwrap();
    assert_eq!(message[0]["apiKey"], SECRET);
    assert_eq!(message[0]["taskType"], "authentication");
    assert!(seen.head.contains("Connection: Upgrade"), "{}", seen.head);
    assert!(
        !seen
            .head
            .to_ascii_lowercase()
            .contains("sec-websocket-extensions"),
        "compression must not be negotiated: {}",
        seen.head
    );
    drop(seen);
    assert!(audit_text(&agent).contains(r#""operation":"websocket message","decision":"allow""#));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_out_of_scope_upgrade_gets_no_credential() {
    let agent = setup_scoped(Reply::Ok, Some(&["/v1"])).await;
    let (mut tls, head) = upgrade_to(&agent, "/ws").await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    tls.write_all(&frame(1, AUTH.as_bytes(), Some([7, 1, 9, 3])))
        .await
        .unwrap();
    let _ = read_frame(&mut tls).await;
    let seen = agent.seen.lock().unwrap();
    assert!(
        !seen.head.to_ascii_lowercase().contains("authorization"),
        "{}",
        seen.head
    );
    let forwarded = String::from_utf8_lossy(&seen.message).into_owned();
    assert!(!forwarded.contains(SECRET), "{forwarded}");
    assert_eq!(forwarded, AUTH, "the client's message must pass unchanged");
    drop(seen);
    let audit = audit_text(&agent);
    assert!(audit.contains(r#""decision":"passthrough""#), "{audit}");
    assert!(
        !audit.contains(r#""operation":"GET","decision":"allow""#),
        "{audit}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_refuses_the_upgrade_reaches_the_client() {
    let agent = setup(Reply::Status).await;
    let (mut tls, head) = upgrade(&agent).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    let mut body = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut body)).await;
    assert!(
        String::from_utf8_lossy(&body).contains("denied"),
        "the upstream's body must reach the client: {:?}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_upgrade_whose_head_echoes_the_credential_is_withheld() {
    let quiet = setup(Reply::Status).await;
    let (_tls, head) = upgrade(&quiet).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");

    let agent = setup(Reply::StatusEcho).await;
    let (_tls, head) = upgrade(&agent).await;
    assert!(head.starts_with("HTTP/1.1 502 ZeroSecret denied"), "{head}");
    assert!(!head.contains(SECRET), "{head}");
    let audit = audit_text(&agent);
    let denied = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|record| record["decision"] == "deny" && record["reason"] == "response echo");
    assert!(denied, "{audit}");
}

fn denied_because(agent: &WsAgent, reason: &str) -> bool {
    audit_text(agent)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|record| record["decision"] == "deny" && record["reason"] == reason)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_upgrade_whose_body_echoes_the_credential_is_cut() {
    let quiet = setup(Reply::Status).await;
    let (mut tls, head) = upgrade(&quiet).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    let mut body = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut body)).await;
    assert!(String::from_utf8_lossy(&body).contains("denied"));
    assert!(!denied_because(&quiet, "response echo"));

    let agent = setup(Reply::StatusBodyEcho).await;
    let (mut tls, head) = upgrade(&agent).await;
    let mut body = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut body)).await;
    let reply = format!("{head}{}", String::from_utf8_lossy(&body));
    assert!(!reply.contains(SECRET), "{reply}");
    assert!(
        denied_because(&agent, "response echo"),
        "{}",
        audit_text(&agent)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_upgrade_with_a_coded_body_is_denied() {
    let quiet = setup(Reply::Status).await;
    let (_tls, head) = upgrade(&quiet).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert!(!denied_because(&quiet, "response encoded"));

    let agent = setup(Reply::StatusGzip).await;
    let (_tls, head) = upgrade(&agent).await;
    assert!(head.starts_with("HTTP/1.1 502 ZeroSecret denied"), "{head}");
    assert!(
        denied_because(&agent, "response encoded"),
        "{}",
        audit_text(&agent)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_extension_is_refused_and_audited() {
    let agent = setup(Reply::Extensions).await;
    let (_tls, head) = upgrade(&agent).await;
    assert!(head.starts_with("HTTP/1.1 502 ZeroSecret denied"), "{head}");
    let audit = audit_text(&agent);
    let denied = audit
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|record| record["decision"] == "deny" && record["reason"] == "websocket extension");
    assert!(denied, "one record must carry both fields: {audit}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_echoes_the_credential_ends_the_session() {
    let agent = setup(Reply::Echo).await;
    let (mut tls, head) = upgrade(&agent).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    tls.write_all(&frame(1, AUTH.as_bytes(), Some([5, 5, 5, 5])))
        .await
        .unwrap();
    assert!(
        read_frame(&mut tls).await.is_none(),
        "the echoed credential must not reach the workload"
    );
    assert!(
        agent
            .seen
            .lock()
            .unwrap()
            .message
            .windows(SECRET.len())
            .any(|w| w == SECRET.as_bytes())
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !audit_text(&agent).contains("websocket echo") && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(audit_text(&agent).contains(
        r#""operation":"websocket message","decision":"deny","reason":"websocket echo""#
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_request_to_a_websocket_binding_is_denied() {
    let agent = setup(Reply::Ok).await;
    let ca = std::fs::read_to_string(&agent.agent.ca_path).unwrap();
    let mut tls = open_tunnel(&agent.agent.proxy_addr, &ca, "api.stripe.com", 443)
        .await
        .unwrap();
    tls.write_all(b"GET /v1 HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let head = read_head(&mut tls).await;
    assert!(head.contains("502"), "{head}");
    assert!(agent.seen.lock().unwrap().head.is_empty());
}
