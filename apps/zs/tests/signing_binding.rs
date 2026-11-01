#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{
    AgentProcess, FakeUpstream, TestHome, bin_path, loopback_connection, spawn_agent,
    spawn_fake_upstream, write_test_setup_signing,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

const SECRET: &str = "sk_test_zsv_synthetic_value_9f27c4d1";
const SIGV4: &str = r#""auth": {"scheme": "aws-sigv4", "access_key_id": "AKIDTEST", "region": "eu-central-003", "service": "s3"}, "local_endpoint": true, "operations": "#;

struct Agent {
    agent: AgentProcess,
    upstream: FakeUpstream,
    dir: PathBuf,
    _temp: TestHome,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.agent.child.kill();
        let _ = self.agent.child.wait();
    }
}

fn setup(auth: &str, operations: &[&str]) -> Agent {
    let temp = TestHome::new(".zs-ca");
    let dir = PathBuf::from(temp.path());
    let upstream = spawn_fake_upstream();
    let mut connection = loopback_connection(upstream.addr.port(), true);
    connection.local_endpoint = auth.contains(r#""local_endpoint": true"#);
    let (policy, creds, audit, ca_dir, _) =
        write_test_setup_signing(&dir, upstream.addr.port(), operations, connection);
    let text = std::fs::read_to_string(&policy)
        .unwrap()
        .replace(r#""operations": "#, auth);
    std::fs::write(&policy, text).unwrap();
    let probe = format!(
        "printf %s \"${{ZS_STRIPE_PRODUCTION_URL:-unset}}\" > {}/endpoint; sleep 20",
        dir.display()
    );
    let agent = spawn_agent(
        bin_path().as_path(),
        policy.as_path(),
        creds.as_path(),
        audit.as_path(),
        ca_dir.as_path(),
        &["sh", "-c", &probe],
        true,
    )
    .expect("agent spawn");
    Agent {
        agent,
        upstream,
        dir,
        _temp: temp,
    }
}

fn endpoint(agent: &Agent) -> String {
    let file = agent.dir.join("endpoint");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !file.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let url = std::fs::read_to_string(file).unwrap();
    url.strip_prefix("http://")
        .expect("an http endpoint")
        .to_string()
}

fn send(addr: &str, raw: &str) -> (String, String) {
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status).unwrap();
    let mut rest = String::new();
    let _ = reader.read_to_string(&mut rest);
    (status, rest)
}

#[test]
fn the_endpoint_re_signs_sigv4_for_the_real_host_and_scope() {
    let agent = setup(SIGV4, &["GET", "PUT"]);
    let addr = endpoint(&agent);
    let (status, _) = send(
        &addr,
        &format!(
            "GET /bucket/dir/a%20b.txt?list-type=2 HTTP/1.1\r\nHost: {addr}\r\nx-amz-date: 20261016T120000Z\r\nx-amz-content-sha256: UNSIGNED-PAYLOAD\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKIDTEST/20261016/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=placeholder\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 1);
    let auth = agent.upstream.last_auth.lock().unwrap().clone();
    assert!(
        auth.contains("Credential=AKIDTEST/20261016/eu-central-003/s3/aws4_request"),
        "the binding's scope wins over the client's: {auth}"
    );
    assert!(
        !auth.contains("Signature=placeholder") && !auth.contains(SECRET),
        "{auth}"
    );
    let head = agent.upstream.last_head.lock().unwrap().clone();
    assert!(
        head.starts_with("GET /bucket/dir/a%20b.txt?list-type=2 HTTP/1.1"),
        "{head}"
    );
    assert!(head.lines().any(|l| l == "Host: api.stripe.com"), "{head}");
}

#[test]
fn a_signed_request_without_sigv4_headers_is_denied_and_not_forwarded() {
    let agent = setup(SIGV4, &["GET"]);
    let addr = endpoint(&agent);
    let (status, _) = send(
        &addr,
        &format!(
            "GET /bucket/k HTTP/1.1\r\nHost: {addr}\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKIDTEST/20261016/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=placeholder\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(status.contains("502"), "{status}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 0);
}

#[test]
fn an_anonymous_request_is_forwarded_without_a_credential() {
    let agent = setup(SIGV4, &["GET"]);
    let addr = endpoint(&agent);
    let (status, _) = send(
        &addr,
        &format!("GET /bucket/public.png HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_eq!(agent.upstream.requests.load(Ordering::SeqCst), 1);
    let head = agent.upstream.last_head.lock().unwrap().clone();
    assert!(
        head.starts_with("GET /bucket/public.png HTTP/1.1"),
        "{head}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("authorization:"),
        "{head}"
    );
    assert!(!head.contains(SECRET), "{head}");
}

fn presign(addr: &str, method: &str) -> (String, String) {
    let date = common::amz_now();
    let day = &date[..8];
    let body = format!(
        r#"{{"url":"http://{addr}/bucket/k.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDTEST%2F{day}%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date={date}&X-Amz-Expires=600&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3D%22k.txt%22&X-Amz-Signature=00","method":"{method}"}}"#
    );
    send(
        addr,
        &format!(
            "POST /.zs/presign HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

#[test]
fn a_presigned_url_is_re_signed_for_the_public_origin() {
    let agent = setup(SIGV4, &["GET", "PUT"]);
    let addr = endpoint(&agent);
    let (status, body) = presign(&addr, "GET");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let url = body.rsplit("\r\n\r\n").next().unwrap();
    assert!(
        url.starts_with("https://api.stripe.com/bucket/k.txt?"),
        "{url}"
    );
    let day = &common::amz_now()[..8];
    assert!(
        url.contains(&format!(
            "X-Amz-Credential=AKIDTEST%2F{day}%2Feu-central-003%2Fs3%2Faws4_request"
        )),
        "{url}"
    );
    assert!(
        url.contains("response-content-disposition=attachment%3B%20filename%3D%22k.txt%22"),
        "{url}"
    );
    let signature = url.rsplit("X-Amz-Signature=").next().unwrap();
    assert_eq!(signature.len(), 64, "{url}");
    assert!(!url.contains(SECRET));
    assert_eq!(
        agent.upstream.requests.load(Ordering::SeqCst),
        0,
        "presigning never calls upstream"
    );
}

#[test]
fn a_presign_for_an_ungranted_method_is_denied() {
    let agent = setup(SIGV4, &["GET"]);
    let addr = endpoint(&agent);
    let (status, _) = presign(&addr, "DELETE");
    assert!(status.contains("502"), "{status}");
}

#[test]
fn the_hmac_body_signature_is_computed_by_the_agent() {
    let agent = setup(
        r#""auth": {"scheme": "hmac-body-signature", "id_header": "va", "signature_header": "signature"}, "operations": "#,
        &["POST"],
    );
    let body = r#"{"account":"0000001234567890"}"#;
    let (status, _) = send(
        &agent.agent.proxy_addr,
        &format!(
            "POST https://api.stripe.com/api/v2/balance HTTP/1.1\r\nHost: api.stripe.com\r\nva: 0000001234567890\r\nsignature: placeholder\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let head = agent.upstream.last_head.lock().unwrap().clone();
    let signature = head
        .lines()
        .find_map(|l| l.strip_prefix("signature: "))
        .expect("a signature header");
    assert_eq!(signature.len(), 64, "{head}");
    assert_ne!(signature, "placeholder");
    assert!(!head.contains(SECRET));
    assert_eq!(&*agent.upstream.last_body.lock().unwrap(), body.as_bytes());
}
