#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::{kill_agent, proxied_request, raw_exchange, setup_agent, write_test_setup};

const HOST: &str = "api.stripe.com";

fn proxy_and_ca(agent: &common::TempAgent) -> (String, String) {
    let process = agent.agent.as_ref().unwrap();
    (
        process.proxy_addr.clone(),
        std::fs::read_to_string(&process.ca_path).unwrap(),
    )
}

fn journal_of(agent: &common::TempAgent) -> String {
    std::fs::read_to_string(agent.dir.join(".zs-audit").join("audit.jsonl")).unwrap()
}

fn records(journal: &str, decision: &str, operation: &str) -> usize {
    let decision = format!(r#""decision":"{decision}""#);
    let operation = format!(r#""operation":"{operation}""#);
    journal
        .lines()
        .filter(|l| l.contains(&decision) && l.contains(&operation))
        .count()
}

fn denies(journal: &str) -> Vec<serde_json::Value> {
    journal
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|r| r["decision"] == "deny")
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn known_resource_without_grant_denies() {
    let mut agent = setup_agent(false, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let ca = std::fs::read_to_string(agent.agent.as_ref().unwrap().ca_path.clone()).unwrap();
    let result = proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers").await;
    let (status, _) = result.unwrap();
    assert!(status.contains("502"), "expected denial, got: {status}");
    assert_eq!(
        agent
            .upstream
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    kill_agent(&mut agent);
    let denied = denies(&journal_of(&agent));
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["operation"], "connect");
    assert!(
        denied[0]["reason"]
            .as_str()
            .unwrap()
            .contains("denied for api.stripe.com"),
        "{denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_absolute_form_request_without_a_grant_records_its_method_and_reason() {
    let mut agent = setup_agent(false, true);
    let (proxy, _) = proxy_and_ca(&agent);
    let response = raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(!response.starts_with("HTTP/1.1 2"), "{response}");
    assert_eq!(
        agent
            .upstream
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let denied = denies(&journal_of(&agent));
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["operation"], "GET");
    assert!(
        denied[0]["reason"]
            .as_str()
            .unwrap()
            .contains("denied for api.stripe.com"),
        "{denied:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn materialization_failure_denies() {
    let mut agent = setup_agent(true, false);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let ca = std::fs::read_to_string(agent.agent.as_ref().unwrap().ca_path.clone()).unwrap();
    let (status, _) = proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers")
        .await
        .unwrap();
    assert!(status.contains("502"), "expected denial, got: {status}");
    assert_eq!(
        agent
            .upstream
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    kill_agent(&mut agent);
    let denied = denies(&journal_of(&agent));
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["operation"], "GET");
    assert_eq!(denied[0]["reason"], "materialize failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_protocol_no_layer_carries_is_denied_rather_than_proxied() {
    let temp = common::TestHome::new(".zs-ca");
    let dir = temp.path();
    let upstream = common::spawn_fake_upstream();
    let creds_dir = dir.join(".zs-credentials");
    std::fs::create_dir_all(&creds_dir).unwrap();
    std::fs::create_dir_all(dir.join(".zs-audit")).unwrap();
    std::fs::write(creds_dir.join("cache-cred"), "sk_test_zs_unintercepted\n").unwrap();
    let https_upstream = common::spawn_fake_upstream();
    std::fs::write(creds_dir.join("stripe-cred"), "sk_test_zs_intercepted\n").unwrap();

    let signing = zs_grant::ControlSigningKey::generate("test-k1");
    let verifying_hex: String = signing
        .verifying_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let connection = common::uninterceptable_connection("cache.internal");
    let signed = signing
        .sign(zs_grant::Grant {
            subject: common::default_subject(),
            workload: "default".into(),
            resource: "session-cache".into(),
            host: "cache.internal".into(),
            protocol: "redis".into(),
            source: zs_policy::CredentialSource::file("cache-cred"),
            operations: vec!["GET".into()],
            environment: "development".into(),
            expires_at_ms: now_ms + 3_600_000,
            grant_id: "g-redis".into(),
            materialization: zs_policy::Materialization::Retrieve,
            upstream_host: connection.upstream_host,
            upstream_port: connection.upstream_port,
            upstream_tls: connection.upstream_tls,
            local_endpoint: connection.local_endpoint,
        })
        .unwrap();
    let connection = common::loopback_connection(https_upstream.addr.port(), true);
    let https_signed = signing
        .sign(zs_grant::Grant {
            subject: common::default_subject(),
            workload: "default".into(),
            resource: "stripe-production".into(),
            host: "api.stripe.com".into(),
            protocol: "https".into(),
            source: zs_policy::CredentialSource::file("stripe-cred"),
            operations: vec!["GET".into()],
            environment: "development".into(),
            expires_at_ms: now_ms + 3_600_000,
            grant_id: "g-https".into(),
            materialization: zs_policy::Materialization::Retrieve,
            upstream_host: connection.upstream_host,
            upstream_port: connection.upstream_port,
            upstream_tls: connection.upstream_tls,
            local_endpoint: connection.local_endpoint,
        })
        .unwrap();
    let port = upstream.addr.port();
    let https_port = https_upstream.addr.port();
    let policy = format!(
        r#"{{"bindings": [{{"resource": "session-cache", "host": "cache.internal", "protocol": "redis", "upstream_host": "127.0.0.1", "upstream_port": {port}}}, {{"resource": "stripe-production", "host": "api.stripe.com", "protocol": "https", "upstream_host": "127.0.0.1", "upstream_port": {https_port}, "upstream_plaintext": true}}], "signing_keys": [{{"key_id": "test-k1", "verifying_key_hex": "{verifying_hex}"}}], "grants": [{}, {}]}}"#,
        serde_json::to_string(&signed).unwrap(),
        serde_json::to_string(&https_signed).unwrap()
    );
    let policy_path = dir.join("zs-policy.json");
    std::fs::write(&policy_path, policy).unwrap();

    let agent = common::spawn_agent(
        common::bin_path().as_path(),
        policy_path.as_path(),
        creds_dir.as_path(),
        dir.join(".zs-audit").join("audit.jsonl").as_path(),
        dir.join(".zs-ca").as_path(),
        &["sleep", "20"],
        true,
    )
    .expect("agent spawn");

    let ca = std::fs::read_to_string(&agent.ca_path).unwrap();
    let (control_status, _) = proxied_request(
        &agent.proxy_addr,
        &ca,
        "api.stripe.com",
        443,
        "/v1/customers",
    )
    .await
    .unwrap();
    assert!(
        control_status.starts_with("HTTP/1.1 200"),
        "the HTTPS positive control through the same agent must succeed: {control_status}"
    );
    assert!(
        https_upstream
            .saw_authorization
            .load(std::sync::atomic::Ordering::SeqCst),
        "the HTTPS positive control must reach its upstream authenticated"
    );

    let result = proxied_request(&agent.proxy_addr, &ca, "cache.internal", 443, "/").await;

    match &result {
        Err(_) => {}
        Ok((status, _)) => assert!(
            !status.contains(" 200"),
            "a protocol no layer carries must not be served, got: {status}"
        ),
    }

    assert_eq!(
        upstream.requests.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the request must not have reached upstream with a credential attached: {result:?}"
    );

    let mut agent = common::TempAgent {
        dir: PathBuf::from(dir),
        agent: Some(agent),
        upstream,
        _temp: temp,
    };
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_audit_sink_blocks_startup() {
    let dir = common::TestHome::new(".zs-ca");
    let upstream = common::spawn_fake_upstream();
    let (policy, creds, _audit, ca_dir, _) =
        write_test_setup(dir.path(), upstream.addr.port(), true, true);
    let mut cmd = std::process::Command::new(common::bin_path());
    cmd.args([
        "run",
        "--policy",
        policy.to_str().unwrap(),
        "--credentials-dir",
        creds.to_str().unwrap(),
        "--audit",
        "/nonexistent-zs-dir/audit.jsonl",
        "--ca-dir",
        ca_dir.to_str().unwrap(),
        "--as",
        "default",
        "--",
        "sleep",
        "1",
    ])
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    let output = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "agent must fail closed when the audit sink is unavailable"
    );
    assert!(
        stderr.contains("audit sink unavailable"),
        "stderr: {stderr}"
    );
    assert_eq!(
        upstream.requests.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_journal_records_decisions_but_never_the_credential() {
    let mut agent = setup_agent(true, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let ca = std::fs::read_to_string(agent.agent.as_ref().unwrap().ca_path.clone()).unwrap();
    let (status, _) = proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected success, got: {status}"
    );
    kill_agent(&mut agent);
    // Poll: kill_agent returns once signalled, and the last journal write can land after that.
    let audit_dir = agent.dir.join(".zs-audit");
    let journal_path = audit_dir.join("audit.jsonl");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let journal = loop {
        match std::fs::read_to_string(&journal_path) {
            Ok(contents) if contents.contains("api.stripe.com") => break contents,
            _ if std::time::Instant::now() >= deadline => {
                panic!(
                    "audit journal never recorded the request within 5 s: {}",
                    std::fs::read_to_string(&journal_path).unwrap_or_default()
                )
            }
            _ => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    };
    assert!(journal.contains("api.stripe.com"));
    assert!(journal.contains("allow"));
    assert!(
        !journal.contains("sk_test_zsv_synthetic_value_9f27c4d1"),
        "credential leaked into audit journal"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_request_reaches_upstream_with_injected_credential() {
    let mut agent = setup_agent(true, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let ca = std::fs::read_to_string(agent.agent.as_ref().unwrap().ca_path.clone()).unwrap();
    let (status, body) =
        proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers?limit=1")
            .await
            .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected success, got: {status}"
    );
    assert!(body.contains("cus_zs_probe_1"), "body: {body}");
    let upstream_requests = agent
        .upstream
        .requests
        .load(std::sync::atomic::Ordering::SeqCst);

    assert_eq!(upstream_requests, 1);
    assert!(
        agent
            .upstream
            .saw_authorization
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    let auth = agent.upstream.last_auth.lock().unwrap().clone();
    assert!(
        auth.contains("sk_test_zsv_synthetic_value_9f27c4d1"),
        "injected header wrong: {auth}"
    );
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_under_a_get_only_grant_is_not_forwarded() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = setup_agent(true, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let ca = std::fs::read_to_string(agent.agent.as_ref().unwrap().ca_path.clone()).unwrap();
    let (status, _) = proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    let before = agent.upstream.requests.load(SeqCst);
    let response = raw_exchange(
        &proxy,
        b"POST https://api.stripe.com/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(
        response.starts_with("HTTP/1.1 ") && !response.starts_with("HTTP/1.1 2"),
        "{response}"
    );
    assert_eq!(agent.upstream.requests.load(SeqCst), before);
    let journal = std::fs::read_to_string(agent.dir.join(".zs-audit").join("audit.jsonl")).unwrap();
    assert!(
        journal
            .lines()
            .any(|l| l.contains(r#""operation":"POST""#) && l.contains(r#""decision":"deny""#)),
        "{journal}"
    );
    let post_denies: Vec<_> = denies(&journal)
        .into_iter()
        .filter(|r| r["operation"] == "POST")
        .collect();
    assert!(!post_denies.is_empty(), "{journal}");
    for deny in post_denies {
        let reason = deny["reason"].as_str().unwrap();
        assert_eq!(
            reason, "grant does not permit the requested operation",
            "{deny}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_absolute_form_body_in_the_same_segment_is_forwarded() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = setup_agent(true, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let ca = std::fs::read_to_string(agent.agent.as_ref().unwrap().ca_path.clone()).unwrap();
    let (status, _) = proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    let before = agent.upstream.requests.load(SeqCst);
    let response = raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 29\r\nConnection: close\r\n\r\ngrant_type=client_credentials",
    )
    .await;
    kill_agent(&mut agent);
    assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
    assert_eq!(agent.upstream.requests.load(SeqCst), before + 1);
    assert_eq!(
        agent.upstream.last_body.lock().unwrap().as_slice(),
        b"grant_type=client_credentials"
    );
    let head = agent
        .upstream
        .last_head
        .lock()
        .unwrap()
        .to_ascii_lowercase();
    assert_eq!(head.matches("content-length:").count(), 1, "{head}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_absolute_form_keep_alive_connection_serves_a_second_request() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut agent = setup_agent(true, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let request = b"GET https://api.stripe.com/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: keep-alive\r\n\r\n";
    let mut stream = tokio::net::TcpStream::connect(&proxy).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut first = Vec::new();
    let mut byte = [0u8; 1];
    while !first.ends_with(b"\r\n\r\n") {
        assert_eq!(
            stream.read(&mut byte).await.unwrap(),
            1,
            "first response head"
        );
        first.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&first).to_ascii_lowercase();
    let length: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .map(|v| v.trim().parse().unwrap())
        .unwrap();
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    let announced_close = head.lines().any(|l| l.trim() == "connection: close");
    let _ = stream.write_all(request).await;
    let mut second = [0u8; 12];
    let served = matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut second)
        )
        .await,
        Ok(Ok(_))
    );
    kill_agent(&mut agent);
    assert!(head.starts_with("http/1.1 200"), "positive control: {head}");
    assert!(
        served || announced_close,
        "the proxy closed a kept-alive connection without announcing Connection: close"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_under_a_post_grant_is_forwarded() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = common::setup_agent_with(true, true, &["GET", "POST"], None);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let ca = std::fs::read_to_string(agent.agent.as_ref().unwrap().ca_path.clone()).unwrap();
    let (status, _) = proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    let before = agent.upstream.requests.load(SeqCst);
    let response = raw_exchange(
        &proxy,
        b"POST https://api.stripe.com/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await;
    kill_agent(&mut agent);
    assert!(response.starts_with("HTTP/1.1 200"), "{response:?}");
    assert_eq!(agent.upstream.requests.load(SeqCst), before + 1);
    assert_eq!(agent.upstream.last_body.lock().unwrap().as_slice(), b"{}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_443_upstream_is_reached_over_tls_without_an_opt_out() {
    use tokio::io::AsyncReadExt;
    let temp = common::TestHome::new(".zs-ca");
    let dir = PathBuf::from(temp.path());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let first_byte = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut byte = [0u8; 1];
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read_exact(&mut byte),
        )
        .await
        {
            Ok(Ok(_)) => Some(byte[0]),
            _ => None,
        }
    });
    let (policy, creds, audit, ca_dir, _) =
        common::write_test_setup_with(&dir, port, true, true, &["GET"], false, None);
    let mut agent = common::spawn_agent(
        common::bin_path().as_path(),
        policy.as_path(),
        creds.as_path(),
        audit.as_path(),
        ca_dir.as_path(),
        &["sleep", "20"],
        true,
    )
    .expect("agent spawn");
    let proxy = agent.proxy_addr.clone();
    let exchange = tokio::spawn(async move {
        raw_exchange(
            &proxy,
            b"GET https://api.stripe.com/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
        )
        .await
    });
    let byte = first_byte.await.unwrap();
    let _ = agent.child.kill();
    let _ = agent.child.wait();
    exchange.abort();
    assert_eq!(
        byte,
        Some(0x16),
        "the credential-bearing hop must open with a TLS ClientHello"
    );
}

fn node_with_env_proxy() -> Option<String> {
    let required = std::env::var("ZS_TEST_NODE").ok();
    let node = required.clone().unwrap_or_else(|| "node".into());
    let major = std::process::Command::new(&node)
        .args(["-p", "process.versions.node.split('.')[0]"])
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        });
    match major {
        Some(major) if major >= 24 => Some(node),
        _ if required.is_some() => panic!("ZS_TEST_NODE={node} is not Node 24 or later"),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_fetch_from_a_directory_without_undici_goes_through_the_agent() {
    let Some(node) = node_with_env_proxy() else {
        eprintln!("skipping: needs Node 24 or later (set ZS_TEST_NODE)");
        return;
    };
    let mut agent = setup_agent(true, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let ca_path = agent.agent.as_ref().unwrap().ca_path.clone();
    let (status, _) = proxied_request(
        &proxy,
        &std::fs::read_to_string(&ca_path).unwrap(),
        "api.stripe.com",
        443,
        "/v1/customers",
    )
    .await
    .unwrap();
    assert!(status.starts_with("HTTP/1.1 200"), "agent ready: {status}");
    let empty = tempfile::tempdir().unwrap();
    let out = tokio::process::Command::new(&node)
        .args([
            "-e",
            "fetch('https://api.stripe.com/v1/customers').then(r=>console.log(r.status),e=>console.log('ERR',(e.cause&&e.cause.code)||e.message))",
        ])
        .current_dir(empty.path())
        .env_remove("NODE_OPTIONS")
        .env_remove("https_proxy")
        .env("HTTPS_PROXY", format!("http://{proxy}"))
        .env("NODE_EXTRA_CA_CERTS", &ca_path)
        .env("NODE_USE_ENV_PROXY", "1")
        .output()
        .await
        .unwrap();
    kill_agent(&mut agent);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "200",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        agent
            .upstream
            .last_auth
            .lock()
            .unwrap()
            .contains("sk_test_zsv_synthetic_value_9f27c4d1")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn put_and_delete_are_forwarded_only_when_the_grant_names_them() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = common::setup_agent_with(true, true, &["GET", "PUT", "DELETE"], None);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let ca = std::fs::read_to_string(agent.agent.as_ref().unwrap().ca_path.clone()).unwrap();
    let (status, _) = proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    let before = agent.upstream.requests.load(SeqCst);
    let put = raw_exchange(
        &proxy,
        b"PUT https://api.stripe.com/v1/customers/c1 HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await;
    let delete = raw_exchange(
        &proxy,
        b"DELETE https://api.stripe.com/v1/customers/c1 HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let patch = raw_exchange(
        &proxy,
        b"PATCH https://api.stripe.com/v1/customers/c1 HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await;
    kill_agent(&mut agent);
    assert!(put.starts_with("HTTP/1.1 200"), "{put:?}");
    assert!(delete.starts_with("HTTP/1.1 200"), "{delete:?}");
    assert!(
        !patch.starts_with("HTTP/1.1 2"),
        "PATCH is not granted: {patch:?}"
    );
    assert_eq!(agent.upstream.requests.load(SeqCst), before + 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_request_for_another_host_is_refused_before_the_upstream() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = setup_agent(true, true);
    let (proxy, ca) = proxy_and_ca(&agent);
    let (status, _) = proxied_request(&proxy, &ca, HOST, 443, "/v1/customers")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    let before = agent.upstream.requests.load(SeqCst);
    let response = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /v1/customers HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert_eq!(agent.upstream.requests.load(SeqCst), before);
    assert_eq!(records(&journal_of(&agent), "deny", "GET"), 1);
    let denied = denies(&journal_of(&agent));
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(denied[0]["reason"], "host_mismatch");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_absolute_form_request_is_sent_with_the_uri_host() {
    let mut agent = setup_agent(true, true);
    let (proxy, _) = proxy_and_ca(&agent);
    let response = raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/v1/customers HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let head = agent.upstream.last_head.lock().unwrap().clone();
    assert_eq!(
        common::header_lines(&head, "Host"),
        vec!["Host: api.stripe.com"],
        "{head}"
    );
}

const SCOPE: &[&str] = &["/oauth/token"];
const CREDENTIAL: &str = "sk_test_zsv_synthetic_value_9f27c4d1";
const CALLER: &str = "Authorization: Bearer caller-token";

fn authorization_lines(head: &str) -> Vec<String> {
    head.lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .map(str::to_string)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_path_outside_the_scope_keeps_the_client_authorization_through_connect() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = common::setup_agent_with(true, true, &["GET", "POST"], Some(SCOPE));
    let (proxy, ca) = proxy_and_ca(&agent);
    let (status, _) = proxied_request(&proxy, &ca, HOST, 443, "/oauth/token")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    assert!(
        agent
            .upstream
            .last_auth
            .lock()
            .unwrap()
            .contains(CREDENTIAL)
    );
    let before = agent.upstream.requests.load(SeqCst);
    let response = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /oauth/authenticate HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(agent.upstream.requests.load(SeqCst), before + 1);
    let head = agent.upstream.last_head.lock().unwrap().clone();
    assert_eq!(
        authorization_lines(&head),
        vec![CALLER.to_string()],
        "{head}"
    );
    assert!(!head.contains(CREDENTIAL), "{head}");
    assert_eq!(records(&journal_of(&agent), "passthrough", "GET"), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_path_outside_the_scope_keeps_the_client_authorization_in_absolute_form() {
    let mut agent = common::setup_agent_with(true, true, &["GET", "POST"], Some(SCOPE));
    let (proxy, _) = proxy_and_ca(&agent);
    let injected = raw_exchange(
        &proxy,
        b"POST https://api.stripe.com/oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 29\r\nConnection: close\r\n\r\ngrant_type=client_credentials",
    )
    .await;
    assert!(
        injected.starts_with("HTTP/1.1 200"),
        "positive control: {injected}"
    );
    assert!(
        agent
            .upstream
            .last_auth
            .lock()
            .unwrap()
            .contains(CREDENTIAL)
    );
    let forwarded = raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/oauth/authenticate HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(forwarded.starts_with("HTTP/1.1 200"), "{forwarded}");
    let head = agent.upstream.last_head.lock().unwrap().clone();
    assert_eq!(
        authorization_lines(&head),
        vec![CALLER.to_string()],
        "{head}"
    );
    assert!(!head.contains(CREDENTIAL), "{head}");
    let journal = journal_of(&agent);
    assert_eq!(records(&journal, "allow", "POST"), 1, "{journal}");
    assert_eq!(records(&journal, "passthrough", "GET"), 1, "{journal}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_path_outside_the_scope_needs_no_grant() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = common::setup_agent_with(false, true, &["GET"], Some(SCOPE));
    let (proxy, ca) = proxy_and_ca(&agent);
    let forwarded = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /oauth/authenticate HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    let after_forward = agent.upstream.requests.load(SeqCst);
    let denied = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(forwarded.starts_with("HTTP/1.1 200"), "{forwarded}");
    assert_eq!(after_forward, 1);
    assert_eq!(
        authorization_lines(&agent.upstream.last_head.lock().unwrap()),
        vec![CALLER.to_string()]
    );
    assert!(
        denied.starts_with("HTTP/1.1 502"),
        "negative control: {denied}"
    );
    assert_eq!(agent.upstream.requests.load(SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_path_outside_the_scope_never_materializes_the_credential() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = common::setup_agent_with(true, false, &["GET"], Some(SCOPE));
    let (proxy, ca) = proxy_and_ca(&agent);
    let forwarded = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /oauth/authenticate HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    let denied = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(forwarded.starts_with("HTTP/1.1 200"), "{forwarded}");
    assert!(
        denied.starts_with("HTTP/1.1 502"),
        "negative control: {denied}"
    );
    assert_eq!(agent.upstream.requests.load(SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ambiguous_target_on_a_scoped_binding_is_refused_before_the_upstream() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = common::setup_agent_with(true, true, &["GET", "POST"], Some(SCOPE));
    let (proxy, ca) = proxy_and_ca(&agent);
    let (status, _) = proxied_request(&proxy, &ca, HOST, 443, "/oauth/token")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    let before = agent.upstream.requests.load(SeqCst);
    let tunnel_targets = [
        "/oauth/../oauth/token",
        "/oauth/./token",
        "/oauth/token/..",
        "//oauth/token",
        "/oauth//token",
        "/oauth%2Ftoken",
        "/oauth%2ftoken",
        "/oauth%5Ctoken",
        "/oauth/%2e%2e/oauth/token",
        "/oauth/%252e%252e/token",
        "/oauth/token;x=1",
        "/oauth/..;/token",
        "/oauth\\token",
        "/oauth/to%zzken",
        "/oauth/token%00",
        "/oauth/token#x",
    ];
    for target in tunnel_targets {
        let request = format!(
            "POST {target} HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let response = common::tunneled_exchange(&proxy, &ca, HOST, 443, request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{target}: {response}");
    }
    let absolute_targets = [
        "/oauth/../oauth/token",
        "//oauth/token",
        "/oauth%2Ftoken",
        "/oauth/token;x=1",
    ];
    for target in absolute_targets {
        let request = format!(
            "POST https://api.stripe.com{target} HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let response = raw_exchange(&proxy, request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{target}: {response}");
    }
    kill_agent(&mut agent);
    assert_eq!(agent.upstream.requests.load(SeqCst), before);
    assert_eq!(
        records(&journal_of(&agent), "deny", "POST"),
        tunnel_targets.len() + absolute_targets.len()
    );
    let allowed = [
        "not_origin_form",
        "fragment",
        "forbidden_byte",
        "bad_escape",
        "forbidden_escape",
        "dot_segment",
        "empty_segment",
    ];
    let post_denies: Vec<_> = denies(&journal_of(&agent))
        .into_iter()
        .filter(|r| r["operation"] == "POST")
        .collect();
    for deny in &post_denies {
        let reason = deny["reason"].as_str().unwrap();
        assert!(allowed.contains(&reason), "{deny}");
    }
    assert!(
        post_denies.iter().any(|r| r["reason"] == "dot_segment"),
        "{post_denies:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_closes_the_tunnel_before_a_pipelined_request() {
    use std::sync::atomic::Ordering::SeqCst;
    use tokio::io::AsyncReadExt;
    let mut agent = common::setup_agent_with(true, true, &["GET", "POST"], Some(SCOPE));
    let (proxy, ca) = proxy_and_ca(&agent);
    let (status, _) = proxied_request(&proxy, &ca, HOST, 443, "/oauth/token")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );
    let before = agent.upstream.requests.load(SeqCst);
    let mut tls = common::open_tunnel(&proxy, &ca, HOST, 443).await.unwrap();
    let response = common::exchange(
        &mut tls,
        b"GET /oauth/../oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\n\r\nGET /oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\n\r\n",
    )
    .await;
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tls.read_to_end(&mut rest),
    )
    .await;
    drop(tls);
    kill_agent(&mut agent);
    assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    assert!(!String::from_utf8_lossy(&rest).contains("HTTP/1.1 200"));
    assert_eq!(agent.upstream.requests.load(SeqCst), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_query_neither_widens_nor_narrows_the_scope() {
    let mut agent = common::setup_agent_with(true, true, &["GET"], Some(SCOPE));
    let (proxy, ca) = proxy_and_ca(&agent);
    let injected = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /oauth/token?grant_type=client_credentials HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(injected.starts_with("HTTP/1.1 200"), "{injected}");
    let injected_head = agent.upstream.last_head.lock().unwrap().clone();
    let forwarded = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /oauth/authenticate?next=/oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(forwarded.starts_with("HTTP/1.1 200"), "{forwarded}");
    assert!(
        injected_head.starts_with("GET /oauth/token?grant_type=client_credentials HTTP/1.1\r\n")
    );
    assert!(injected_head.contains(CREDENTIAL), "{injected_head}");
    let head = agent.upstream.last_head.lock().unwrap().clone();
    assert!(head.starts_with("GET /oauth/authenticate?next=/oauth/token HTTP/1.1\r\n"));
    assert_eq!(
        authorization_lines(&head),
        vec![CALLER.to_string()],
        "{head}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn methods_are_checked_only_inside_the_scope() {
    use std::sync::atomic::Ordering::SeqCst;
    let mut agent = common::setup_agent_with(true, true, &["POST"], Some(SCOPE));
    let (proxy, ca) = proxy_and_ca(&agent);
    let injected = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"POST /oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    )
    .await;
    assert!(
        injected.starts_with("HTTP/1.1 200"),
        "positive control: {injected}"
    );
    assert!(
        agent
            .upstream
            .last_auth
            .lock()
            .unwrap()
            .contains(CREDENTIAL)
    );
    let forwarded = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /oauth/authenticate HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(forwarded.starts_with("HTTP/1.1 200"), "{forwarded}");
    let before = agent.upstream.requests.load(SeqCst);
    let denied = common::tunneled_exchange(
        &proxy,
        &ca,
        HOST,
        443,
        b"GET /oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    kill_agent(&mut agent);
    assert!(
        denied.starts_with("HTTP/1.1 502"),
        "negative control: {denied}"
    );
    assert_eq!(agent.upstream.requests.load(SeqCst), before);
    let journal = journal_of(&agent);
    assert_eq!(records(&journal, "allow", "POST"), 1, "{journal}");
    assert_eq!(records(&journal, "passthrough", "GET"), 1, "{journal}");
    assert_eq!(records(&journal, "deny", "GET"), 1, "{journal}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kept_alive_tunnel_decides_each_request_by_its_own_path() {
    let mut agent = common::setup_agent_with(true, true, &["GET", "POST"], Some(SCOPE));
    let (proxy, ca) = proxy_and_ca(&agent);
    let mut tls = common::open_tunnel(&proxy, &ca, HOST, 443).await.unwrap();
    let first = common::exchange(
        &mut tls,
        b"POST /oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
    let first_head = agent.upstream.last_head.lock().unwrap().clone();
    let second = common::exchange(
        &mut tls,
        b"GET /oauth/authenticate HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\n\r\n",
    )
    .await;
    let second_head = agent.upstream.last_head.lock().unwrap().clone();
    let third = common::exchange(
        &mut tls,
        b"POST /oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\nContent-Length: 2\r\n\r\n{}",
    )
    .await;
    let third_head = agent.upstream.last_head.lock().unwrap().clone();
    drop(tls);
    kill_agent(&mut agent);
    for response in [&first, &second, &third] {
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }
    let injected = vec![format!("Authorization: Bearer {CREDENTIAL}")];
    assert_eq!(authorization_lines(&first_head), injected, "{first_head}");
    assert_eq!(
        authorization_lines(&second_head),
        vec![CALLER.to_string()],
        "{second_head}"
    );
    assert_eq!(authorization_lines(&third_head), injected, "{third_head}");
}
