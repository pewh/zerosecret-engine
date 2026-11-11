// Test code: `unwrap`/`expect` are assertions; a failed setup should abort the test loudly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use zs::{AgentHandler, GrantCache, ResourceBinding};
use zs_grant::{ControlSigningKey, Grant, SignedGrant};
use zs_mitm::{Flow, FlowHandler};
use zs_protocol::Destination;

mod common;
#[cfg(unix)]
mod matrix_support;
mod ws_fake;

const SUBJECT: &str = "alice@company.com";
const WORKLOAD: &str = "claude-code";
const RESOURCE: &str = "stripe-production";
const HOST: &str = "api.stripe.com";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn grant_with_id(grant_id: &str) -> Grant {
    let connection = common::default_connection(HOST, "https");
    Grant {
        subject: SUBJECT.into(),
        workload: WORKLOAD.into(),
        resource: RESOURCE.into(),
        host: HOST.to_string(),
        protocol: "https".into(),
        source: zs_policy::CredentialSource::file("stripe-prod"),
        operations: vec!["GET".into()],
        environment: "development".into(),
        expires_at_ms: now_ms() + 300_000,
        grant_id: grant_id.into(),
        materialization: zs_policy::Materialization::Retrieve,
        upstream_host: connection.upstream_host,
        upstream_port: connection.upstream_port,
        upstream_tls: connection.upstream_tls,
        local_endpoint: connection.local_endpoint,
        version: zs_grant::GRANT_VERSION,
    }
}

fn agent_with(signed: SignedGrant, verifier_key: &ControlSigningKey) -> AgentHandler {
    agent_in(
        bearer_binding(),
        signed,
        verifier_key,
        std::path::Path::new("/nonexistent"),
    )
}

fn bearer_binding() -> ResourceBinding {
    ResourceBinding {
        resource: RESOURCE.to_string(),
        host: HOST.to_string(),
        protocol: "https".to_string(),
        upstream_host: None,
        upstream_port: None,
        upstream_plaintext: false,
        upstream_auth_optional: false,
        listen_port: None,
        local_endpoint: false,
        operations: Vec::new(),
        paths: None,
        upstream_ca: None,
        upstream_cert_sha256: None,
        client_auth_plugin: None,
        user: None,
        auth_source: None,
        auth: zs::HttpAuth::Bearer,
        source: None,
        loaded_ca: None,
    }
}

fn agent_in(
    binding: ResourceBinding,
    signed: SignedGrant,
    verifier_key: &ControlSigningKey,
    store: &std::path::Path,
) -> AgentHandler {
    let verifier = zs_grant::AgentVerifier::new(vec![(
        verifier_key.key_id().to_string(),
        ed25519_dalek::VerifyingKey::from_bytes(&verifier_key.verifying_key_bytes()).unwrap(),
    )]);
    let cache = GrantCache::new();
    cache.insert(signed);
    AgentHandler::from_grants(
        zs_identity::Subject::new(SUBJECT).unwrap(),
        zs_identity::WorkloadLabel::new(WORKLOAD).unwrap(),
        vec![binding],
        cache,
        verifier,
        test_materializer(store),
    )
}

fn test_materializer(store: &std::path::Path) -> Arc<zs_materializer::Materializer> {
    struct NoExchange;
    #[async_trait::async_trait]
    impl zs_materializer::ExchangeProvider for NoExchange {
        async fn exchange(
            &self,
            _grant: &zs_grant::Grant,
        ) -> Result<zs_credential::Credential, zs_materializer::MaterializationError> {
            Err(zs_materializer::MaterializationError::Exchange(
                "not configured".into(),
            ))
        }
    }
    Arc::new(zs_materializer::Materializer::new(
        zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(store))),
        Arc::new(NoExchange),
    ))
}

fn classify(handler: &AgentHandler) -> Flow {
    handler.classify(&Destination::new(HOST.to_string(), 443))
}

fn deny_reason(flow: &Flow) -> String {
    match flow {
        Flow::Deny { reason } => reason.clone(),
        other => panic!("expected a denial, got {other:?}"),
    }
}

#[test]
fn a_revoked_grant_is_denied_before_it_expires() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-revoke-me")).unwrap(), &key);

    assert!(
        matches!(classify(&handler), Flow::Intercept { .. }),
        "the grant must be usable before it is revoked, or the test proves nothing"
    );

    handler.apply_revocations(&["g-revoke-me".to_string()]);

    let reason = deny_reason(&classify(&handler));
    assert!(
        reason.contains("revoked"),
        "the denial must say the grant was revoked, not that it expired: {reason}"
    );
}

#[test]
fn revoking_one_grant_leaves_others_working() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-keep-me")).unwrap(), &key);

    handler.apply_revocations(&["g-some-other-grant".to_string()]);

    assert!(
        matches!(classify(&handler), Flow::Intercept { .. }),
        "revoking an unrelated grant id must not deny this one"
    );
}

#[test]
fn revocations_accumulate_across_refreshes() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-first")).unwrap(), &key);

    handler.apply_revocations(&["g-first".to_string()]);
    handler.apply_revocations(&["g-second".to_string()]);

    let reason = deny_reason(&classify(&handler));
    assert!(
        reason.contains("revoked"),
        "a revocation must not be forgotten on the next refresh: {reason}"
    );
}

#[test]
fn an_empty_refresh_does_not_reinstate_a_revoked_grant() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-revoked")).unwrap(), &key);
    handler.apply_revocations(&["g-revoked".to_string()]);

    handler.apply_revocations(&[]);

    let reason = deny_reason(&classify(&handler));
    assert!(
        reason.contains("revoked"),
        "an empty refresh must not reinstate a revoked grant: {reason}"
    );
}

#[test]
fn a_revoked_grant_id_stays_revoked_even_if_reinserted() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-replayed")).unwrap(), &key);
    handler.apply_revocations(&["g-replayed".to_string()]);

    handler.cache_grant(key.sign(grant_with_id("g-replayed")).unwrap());
    let reason = deny_reason(&classify(&handler));
    assert!(
        reason.contains("revoked"),
        "re-caching a revoked grant must not restore it: {reason}"
    );

    handler.cache_grant(key.sign(grant_with_id("g-fresh")).unwrap());
    assert!(
        matches!(classify(&handler), Flow::Intercept { .. }),
        "a newly minted grant with an unrevoked id must be usable"
    );
}

#[test]
fn a_grant_near_expiry_needs_renewal_and_a_fresh_one_does_not() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-near")).unwrap(), &key);
    assert!(!handler.grant_needs_renewal(RESOURCE, 150_000));
    assert!(handler.grant_needs_renewal(RESOURCE, 300_000));
}

#[test]
fn a_revoked_grant_is_never_renewed() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-revoked")).unwrap(), &key);
    assert!(handler.grant_needs_renewal(RESOURCE, 300_000));
    handler.apply_revocations(&["g-revoked".to_string()]);
    assert!(
        !handler.grant_needs_renewal(RESOURCE, 300_000),
        "renewal would mint around the revocation"
    );
}

#[test]
fn a_post_is_denied_under_a_get_only_grant() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-get")).unwrap(), &key);
    let reason = handler
        .materialize(HOST, "POST")
        .err()
        .expect("POST must be denied")
        .reason;
    assert_eq!(reason, "grant does not permit the requested operation");
}

#[test]
fn revoking_a_grant_also_stops_the_grants_renewed_from_it() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-original")).unwrap(), &key);
    handler.renew_grant(key.sign(grant_with_id("g-renewed-1")).unwrap());
    handler.renew_grant(key.sign(grant_with_id("g-renewed-2")).unwrap());
    assert!(matches!(classify(&handler), Flow::Intercept { .. }));

    handler.apply_revocations(&["g-original".to_string()]);

    let reason = deny_reason(&classify(&handler));
    assert!(reason.contains("revoked"), "{reason}");
    assert!(!handler.grant_needs_renewal(RESOURCE, 300_000));
}

fn intercepted_resource(handler: &AgentHandler) -> String {
    match classify(handler) {
        Flow::Intercept { resource, .. } => resource,
        other => panic!("expected an intercept, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provider_failure_is_audited_as_fixed_text() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-provider")).unwrap(), &key);
    let resource = intercepted_resource(&handler);

    let denied = handler
        .materialize(&resource, "GET")
        .err()
        .expect("the provider failure must deny");

    assert_eq!(denied.audit_reason(), zs::MATERIALIZE_FAILED);
    assert_ne!(denied.reason, zs::MATERIALIZE_FAILED);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_grant_keeps_its_reason_through_materialize() {
    let key = ControlSigningKey::generate("control-k1");
    let handler = agent_with(key.sign(grant_with_id("g-revoke-me")).unwrap(), &key);
    let resource = intercepted_resource(&handler);

    handler.apply_revocations(&["g-revoke-me".to_string()]);

    let denied = handler
        .materialize(&resource, "GET")
        .err()
        .expect("a revoked grant must deny");
    assert!(denied.audit_reason().contains("revoked"), "{denied}");
}

struct Proxied {
    addr: std::net::SocketAddr,
    ca_pem: String,
    handler: Arc<AgentHandler>,
    journal: std::path::PathBuf,
    seen: Arc<std::sync::Mutex<ws_fake::Seen>>,
    _home: tempfile::TempDir,
}

async fn proxy_to_websocket_upstream(grant_id: &str) -> Proxied {
    let seen = Arc::new(std::sync::Mutex::new(ws_fake::Seen::default()));
    let port = ws_fake::spawn_ws_upstream(ws_fake::Reply::Ok, seen.clone()).await;
    let mut binding = bearer_binding();
    binding.upstream_host = Some("127.0.0.1".into());
    binding.upstream_port = Some(port);
    binding.upstream_plaintext = !binding.is_http();
    let connection = binding.connection().unwrap();
    let key = ControlSigningKey::generate("control-k1");
    let signed = key
        .sign(Grant {
            upstream_host: connection.upstream_host,
            upstream_port: connection.upstream_port,
            upstream_tls: connection.upstream_tls,
            local_endpoint: connection.local_endpoint,
            ..grant_with_id(grant_id)
        })
        .unwrap();
    let home = tempfile::tempdir().unwrap();
    let store = home.path().join("creds");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
        store.join("stripe-prod"),
        "sk_test_zsv_revocation_value_5d3a",
    )
    .unwrap();
    let handler = Arc::new(agent_in(binding, signed, &key, &store));
    let ca = Arc::new(zs_mitm::LocalCa::load_or_create(home.path().join(".zs-ca")).unwrap());
    let ca_pem = ca.certificate_pem();
    let journal = home.path().join("audit.jsonl");
    let token = Arc::new(zs_mitm::RunToken::generate());
    let proxy = zs_mitm::ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        ca,
        handler.clone(),
        Arc::new(zs_audit::Journal::open(&journal).unwrap()),
        token.clone(),
    )
    .await
    .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });
    common::register_proxy_authorization(&addr.to_string(), token.proxy_authorization().as_str());
    Proxied {
        addr,
        ca_pem,
        handler,
        journal,
        seen,
        _home: home,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn revocation_ends_an_open_header_scheme_websocket() {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    let proxied = proxy_to_websocket_upstream("g-websocket").await;
    let mut tls = common::open_tunnel(&proxied.addr.to_string(), &proxied.ca_pem, HOST, 443)
        .await
        .unwrap();
    tls.write_all(b"GET /v1 HTTP/1.1\r\nHost: api.stripe.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        .await
        .unwrap();
    let head = ws_fake::read_head(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let upgrade = proxied.seen.lock().unwrap().head.to_ascii_lowercase();
    assert!(
        upgrade.contains("authorization: bearer "),
        "positive control: the upgrade carries the injected header"
    );
    let ping = ws_fake::frame(1, br#"{"op":"ping"}"#, Some([7, 1, 9, 3]));
    for _ in 0..2 {
        tls.write_all(&ping).await.unwrap();
        assert_eq!(
            ws_fake::read_frame(&mut tls)
                .await
                .map(|(opcode, _)| opcode),
            Some(1),
            "positive control: a message is relayed before the revocation"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(proxied.seen.lock().unwrap().messages, 2);

    let revoked_at = std::time::Instant::now();
    proxied
        .handler
        .apply_revocations(&["g-websocket".to_string()]);
    let close = loop {
        assert!(
            revoked_at.elapsed() < Duration::from_secs(7),
            "the session stayed open 7 s after revocation"
        );
        let _ = tls.write_all(&ping).await;
        match ws_fake::read_frame(&mut tls).await {
            Some((8, payload)) => break payload,
            Some(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            None => panic!("the session ended without a Close frame"),
        }
    };
    assert_eq!(close, 1008u16.to_be_bytes(), "the Close code is 1008");
    let revoked = || {
        std::fs::read_to_string(&proxied.journal)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .any(|record| {
                record["operation"] == "websocket message"
                    && record["decision"] == "deny"
                    && record["reason"] == "websocket revoked"
            })
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !revoked() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        revoked(),
        "{}",
        std::fs::read_to_string(&proxied.journal).unwrap_or_default()
    );
}

#[cfg(unix)]
#[test]
fn slow_renewals_do_not_delay_revocation() {
    use std::io::BufRead;
    use std::time::{Duration, Instant};

    use matrix_support::{FakeControl, FakeGrant};

    let control = FakeControl::start();
    control.answer(FakeGrant::ShortThenHang);
    let home = control.token_home();
    let mut agent = home.spawn_child(&["sleep", "30"], &[("ZS_REFRESH_SECONDS", "1")]);
    let stdout = agent.stdout.take().unwrap();
    let (sender, lines) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            let _ = sender.send(line);
        }
    });
    let mut seen: Vec<String> = Vec::new();
    let wait = |lines: &std::sync::mpsc::Receiver<String>,
                seen: &mut Vec<String>,
                limit: Duration,
                until: &dyn Fn(&str) -> bool| {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if let Ok(line) = lines.recv_timeout(Duration::from_millis(100)) {
                seen.push(line.clone());
                if until(&line) {
                    return true;
                }
            }
        }
        false
    };

    assert!(
        wait(&lines, &mut seen, Duration::from_secs(15), &|line| {
            line.starts_with("zs: proxy ")
        }),
        "the agent did not start: {seen:?}"
    );
    let renewed = Instant::now() + Duration::from_secs(15);
    while control.grant_calls() < 2 && Instant::now() < renewed {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        control.grant_calls() >= 2,
        "positive control: the agent asked for a renewal, which the control plane hangs"
    );

    control.revoke("g-fake");
    let applied = wait(&lines, &mut seen, Duration::from_secs(5), &|line| {
        line.contains("revoked grant")
    });
    let _ = agent.kill();
    let _ = agent.wait();
    drop(reader);
    assert!(
        applied,
        "the revocation list did not arrive within 5 s while a renewal hung: {seen:?}"
    );
}
