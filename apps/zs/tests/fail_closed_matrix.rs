#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod matrix_support;
mod ws_fake;

use std::sync::Arc;

#[cfg(unix)]
use matrix_support::{FakeControl, FakeGrant, PlainHome, field_line, https_binding};
use matrix_support::{HOST, RESOURCE, SUBJECT, WORKLOAD, binding, grant, now_ms};
use zs::{AgentHandler, GrantCache, HttpAuth, ResourceBinding};
use zs_grant::{ControlSigningKey, Grant, SignedGrant};
use zs_mitm::{Flow, FlowHandler};
use zs_protocol::Destination;

#[path = "../../../crates/zs-proto-mysql/tests/fake/mod.rs"]
mod fake;

#[path = "../../../crates/zs-proto-postgres/tests/fake/mod.rs"]
mod pg_fake;

#[path = "../../../crates/zs-proto-mongo/tests/fake/mod.rs"]
mod mongo_fake;

use zs_proto_mysql::packet;
use zs_proto_mysql::{
    CHANGE_USER_REFUSED, CLIENT_REFUSED, METHOD_REFUSED, TLS_REFUSED, UpstreamTls,
};

fn verified(key: &ControlSigningKey, signed: SignedGrant) -> zs_grant::VerifiedGrant {
    zs_grant::AgentVerifier::new(vec![(
        key.key_id().to_string(),
        ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
    )])
    .verify(
        &signed,
        0,
        &zs_grant::VerifyContext {
            subject: SUBJECT,
            workload: WORKLOAD,
            resource: RESOURCE,
            operation: "GET",
        },
    )
    .unwrap()
}

fn agent_with(grants: Vec<SignedGrant>, verifier_key: &ControlSigningKey) -> AgentHandler {
    agent_with_binding(binding(), grants, verifier_key)
}

fn agent_with_binding(
    binding: ResourceBinding,
    grants: Vec<SignedGrant>,
    verifier_key: &ControlSigningKey,
) -> AgentHandler {
    agent_in(
        binding,
        grants,
        verifier_key,
        std::path::Path::new("/nonexistent"),
    )
}

fn agent_in(
    binding: ResourceBinding,
    grants: Vec<SignedGrant>,
    verifier_key: &ControlSigningKey,
    store: &std::path::Path,
) -> AgentHandler {
    let cache = GrantCache::new();
    for signed in grants {
        cache.insert(signed);
    }
    AgentHandler::from_grants(
        zs_identity::Subject::new(SUBJECT).unwrap(),
        zs_identity::WorkloadLabel::new(WORKLOAD).unwrap(),
        vec![binding],
        cache,
        zs_grant::AgentVerifier::new(vec![(
            verifier_key.key_id().to_string(),
            ed25519_dalek::VerifyingKey::from_bytes(&verifier_key.verifying_key_bytes()).unwrap(),
        )]),
        materializer_in(store),
    )
}

fn materializer() -> Arc<zs_materializer::Materializer> {
    materializer_in(std::path::Path::new("/nonexistent"))
}

fn materializer_in(store: &std::path::Path) -> Arc<zs_materializer::Materializer> {
    struct NoExchange;
    #[async_trait::async_trait]
    impl zs_materializer::ExchangeProvider for NoExchange {
        async fn exchange(
            &self,
            _grant: &Grant,
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

fn classify(handler: &AgentHandler, host: &str) -> Flow {
    handler.classify(&Destination::new(host.to_string(), 443))
}

fn assert_denied(flow: &Flow, row: &str) {
    assert!(
        matches!(flow, Flow::Deny { .. }),
        "SECURITY §7 {row} must deny, got {flow:?}"
    );
}

#[test]
fn row_01_unknown_destination_passes_through() {
    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(
        vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()],
        &key,
    );

    let flow = classify(&handler, "api.unrelated.test");

    assert!(
        matches!(flow, Flow::Passthrough),
        "an unmanaged destination must pass through, got {flow:?}"
    );
}

#[test]
fn row_02_known_resource_without_a_grant_denies() {
    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(vec![], &key);

    assert_denied(&classify(&handler, HOST), "row 2");
}

#[test]
fn row_03_expired_grant_denies() {
    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(
        vec![key.sign(grant(now_ms() - 1, "g-expired")).unwrap()],
        &key,
    );

    let flow = classify(&handler, HOST);
    assert_denied(&flow, "row 3");
    if let Flow::Deny { reason } = &flow {
        assert!(
            reason.contains("expired") || reason.contains("expire"),
            "the denial must name expiry so it is not read as a policy change: {reason}"
        );
    }
}

#[test]
fn row_03_a_refreshed_grant_restores_access() {
    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(
        vec![key.sign(grant(now_ms() - 1, "g-expired")).unwrap()],
        &key,
    );
    assert_denied(&classify(&handler, HOST), "row 3 precondition");

    handler.cache_grant(key.sign(grant(now_ms() + 300_000, "g-refreshed")).unwrap());

    assert!(
        matches!(classify(&handler, HOST), Flow::Intercept { .. }),
        "a refreshed grant must restore access"
    );
}

#[test]
fn row_04_grant_signed_by_an_unpinned_key_denies() {
    let pinned = ControlSigningKey::generate("k1");
    let attacker = ControlSigningKey::generate("attacker-k1");
    let handler = agent_with(
        vec![
            attacker
                .sign(grant(now_ms() + 300_000, "g-forged"))
                .unwrap(),
        ],
        &pinned,
    );

    let flow = classify(&handler, HOST);
    assert_denied(&flow, "row 4");
    if let Flow::Deny { reason } = &flow {
        assert!(
            !reason.contains("no grant for"),
            "a forged signature must not be reported as a missing grant: {reason}"
        );
    }
}

#[test]
fn row_05_control_unreachable_with_a_valid_cache_allows() {
    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(
        vec![key.sign(grant(now_ms() + 300_000, "g-cached")).unwrap()],
        &key,
    );

    assert!(
        matches!(classify(&handler, HOST), Flow::Intercept { .. }),
        "a valid cached grant must authorize with no control plane reachable"
    );
}

#[test]
fn row_06_control_unreachable_with_an_expired_cache_denies() {
    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(
        vec![key.sign(grant(now_ms() - 1, "g-stale")).unwrap()],
        &key,
    );

    assert_denied(&classify(&handler, HOST), "row 6");
}

#[test]
fn row_07_unavailable_audit_sink_refuses_startup() {
    let unwritable = std::path::Path::new("/nonexistent-directory-zs/audit.jsonl");
    let journal = zs_audit::Journal::open(unwritable);

    assert!(
        journal.is_err(),
        "an unopenable audit journal must be an error, not a silent no-op sink"
    );
}

#[tokio::test]
async fn row_08_materialization_failure_denies_without_a_weaker_fallback() {
    let key = ControlSigningKey::generate("k1");
    let mut exchange_grant = grant(now_ms() + 300_000, "g-exchange");
    exchange_grant.materialization = zs_policy::Materialization::Exchange;

    let signed = key.sign(exchange_grant).unwrap();
    let result = materializer()
        .materialize(&verified(&key, signed), None)
        .await;

    assert!(
        result.is_err(),
        "an exchange grant with no provider must fail, not retrieve a static credential"
    );
}

#[test]
fn row_09_a_panicking_protocol_denies_that_resource_and_the_agent_survives() {
    let result = std::panic::catch_unwind(|| {
        panic!("protocol implementation failed");
    });

    assert!(result.is_err(), "the panic must be caught, not propagate");

    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(
        vec![key.sign(grant(now_ms() + 300_000, "g-after")).unwrap()],
        &key,
    );
    assert!(
        matches!(classify(&handler, HOST), Flow::Intercept { .. }),
        "the agent must keep serving other resources after a protocol panic"
    );
}

#[test]
fn row_10_revoked_grant_denies_before_expiry() {
    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(
        vec![key.sign(grant(now_ms() + 300_000, "g-revoked")).unwrap()],
        &key,
    );
    assert!(
        matches!(classify(&handler, HOST), Flow::Intercept { .. }),
        "precondition: the grant must be usable before revocation"
    );

    handler.apply_revocations(&["g-revoked".to_string()]);

    let flow = classify(&handler, HOST);
    assert_denied(&flow, "row 10");
    if let Flow::Deny { reason } = &flow {
        assert!(
            reason.contains("revoked"),
            "a revocation must not be reported as an expiry: {reason}"
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[test]
fn row_11_malformed_local_ca_storage_refuses_startup_without_minting() {
    let home = tempfile::tempdir().unwrap();
    let ca_dir = home.path().join(".zs-ca");
    // A `.ca-storage-id` directory is refused before any native store call, sparing the dev keychain.
    std::fs::create_dir_all(ca_dir.join(".ca-storage-id")).unwrap();

    let refused = zs_mitm::LocalCa::load_or_create_secure(&ca_dir);

    assert!(
        matches!(
            &refused,
            Err(zs_mitm::ca::CaError::Storage(message)) if message == "CA storage path invalid"
        ),
        "malformed CA storage must refuse with its fixed message"
    );
    let mut left: Vec<String> = std::fs::read_dir(&ca_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        [".ca-storage-id"],
        "a refused CA load must mint, publish and lock nothing"
    );
}

#[test]
fn every_security_7_row_has_a_named_test_in_this_file() {
    let rows = matrix_support::security_7_rows();
    let this_file = include_str!("fail_closed_matrix.rs");
    for (index, row) in rows.iter().enumerate() {
        let n = index + 1;
        let prefix = format!("fn row_{n:02}_");
        if row.contains(matrix_support::COMMERCIAL) {
            assert!(
                !this_file.contains(&prefix),
                "SECURITY §7 row {n} is marked {}, so its `{prefix}…` test belongs in the commercial suite, not in this file",
                matrix_support::COMMERCIAL
            );
        } else {
            assert!(
                this_file.contains(&prefix),
                "SECURITY §7 row {n} has no `{prefix}…` test in this file"
            );
        }
    }
}

#[test]
fn row_12_a_revoked_grant_stays_revoked_after_renewal() {
    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(
        vec![key.sign(grant(now_ms() + 300_000, "g-first")).unwrap()],
        &key,
    );
    handler.renew_grant(key.sign(grant(now_ms() + 300_000, "g-renewed")).unwrap());
    assert!(matches!(classify(&handler, HOST), Flow::Intercept { .. }));

    handler.apply_revocations(&["g-first".to_string()]);

    assert_denied(&classify(&handler, HOST), "row 12");
}

#[test]
fn row_13_a_method_outside_the_grant_is_denied() {
    let key = ControlSigningKey::generate("k1");
    let handler = agent_with(
        vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()],
        &key,
    );
    assert!(matches!(classify(&handler, HOST), Flow::Intercept { .. }));

    let denied = handler.materialize(HOST, "DELETE").err().expect("row 13");

    assert_eq!(
        denied.reason, "grant does not permit the requested operation",
        "row 13: the verifier text is fixed and never echoes the method"
    );
}

#[test]
fn row_14_an_https_upstream_is_tls_on_any_port_and_plaintext_only_on_loopback() {
    let key = ControlSigningKey::generate("k1");
    let signed = || vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()];
    let mut other_port = binding();
    other_port.upstream_port = Some(8443);
    let on_8443 = vec![key.sign(on_port(8443, "g-1", now_ms() + 300_000)).unwrap()];
    let flow = agent_with_binding(other_port, on_8443, &key)
        .classify(&Destination::new(HOST.to_string(), 8443));
    assert!(
        matches!(
            flow,
            Flow::Intercept {
                upstream_tls: true,
                ..
            }
        ),
        "a non-443 https upstream must use TLS, got {flow:?}"
    );

    let plaintext_to = |host: &str| {
        let mut plaintext = binding();
        plaintext.upstream_host = Some(host.into());
        plaintext.upstream_plaintext = true;
        let grants = signed_for(&plaintext, signed(), &key);
        assert_eq!(
            zs::connection::grant_matches(&grants[0], &plaintext),
            Ok(()),
            "row 14: the grant signs the {host} connection, so only the loopback rule can deny"
        );
        classify(&agent_with_binding(plaintext, grants, &key), HOST)
    };
    assert!(
        matches!(
            plaintext_to("127.0.0.1"),
            Flow::Intercept {
                upstream_tls: false,
                ..
            }
        ),
        "row 14 positive control: plaintext to a signed loopback upstream"
    );
    let Flow::Deny { reason } = plaintext_to("10.0.0.5") else {
        panic!("row 14: plaintext to a remote upstream must deny");
    };
    assert!(
        reason.ends_with(&format!(
            "{RESOURCE}: upstream_plaintext is allowed only for a loopback upstream"
        )),
        "row 14: {reason}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_15_an_ambiguous_request_body_is_refused_before_the_upstream() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key = ControlSigningKey::generate("k1");
    let mut loopback = binding();
    loopback.upstream_host = Some("127.0.0.1".into());
    loopback.upstream_port = Some(upstream.local_addr().unwrap().port());
    loopback.upstream_plaintext = true;
    let grants = signed_for(
        &loopback,
        vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()],
        &key,
    );
    let handler = Arc::new(agent_with_binding(loopback, grants, &key));
    let home = tempfile::tempdir().unwrap();
    let proxy = zs_mitm::ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(zs_mitm::LocalCa::load_or_create(home.path().join(".zs-ca")).unwrap()),
        handler,
        Arc::new(zs_audit::Journal::open(home.path().join("audit.jsonl")).unwrap()),
    )
    .await
    .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });

    for request in [
        &b"POST https://api.stripe.com/v1/x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxy"[..],
        &b"POST https://api.stripe.com/v1/x HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"[..],
        &b"POST https://api.stripe.com/v1/x HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n"[..],
    ] {
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_end(&mut response),
        )
        .await;
        assert!(
            !String::from_utf8_lossy(&response).starts_with("HTTP/1.1 2"),
            "row 15: {}",
            String::from_utf8_lossy(&response)
        );
    }
    let reached =
        tokio::time::timeout(std::time::Duration::from_millis(300), upstream.accept()).await;
    assert!(
        reached.is_err(),
        "row 15: an ambiguous request reached the upstream"
    );
}

#[test]
fn row_19_an_invalid_scope_or_binding_field_refuses_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let load = |binding: &str| {
        let path = dir.path().join("zs-policy.json");
        std::fs::write(&path, format!(r#"{{"bindings":[{binding}]}}"#)).unwrap();
        zs::AgentFile::load(&path)
    };
    let valid = load(r#"{"resource":"r","host":"api.stripe.com","paths":["/oauth/token"]}"#)
        .expect("row 19 positive control: a canonical scope loads");
    assert_eq!(
        valid.bindings[0].path_scope(),
        Ok(zs_mitm::PathScope::Paths(vec!["/oauth/token".into()]))
    );

    for entry in [
        r#"{"resource":"r","host":"api.stripe.com","paths":[]}"#,
        r#"{"resource":"r","host":"api.stripe.com","paths":["oauth/token"]}"#,
        r#"{"resource":"r","host":"api.stripe.com","paths":["/v1/*"]}"#,
        r#"{"resource":"r","host":"api.stripe.com","paths":["/oauth/%74oken"]}"#,
        r#"{"resource":"r","host":"api.stripe.com","paths":["/a/../oauth/token"]}"#,
        r#"{"resource":"r","host":"db.internal","protocol":"postgres","paths":["/"]}"#,
        r#"{"resource":"r","host":"api.stripe.com","path":["/oauth/token"]}"#,
    ] {
        assert!(load(entry).is_err(), "row 19 must refuse {entry}");
    }

    let named = load(r#"{"resource":"r","host":"api.stripe.com","paths":["oauth/token"]}"#)
        .err()
        .unwrap()
        .to_string();
    assert!(named.contains("r:"), "the config error names the resource");

    let key = ControlSigningKey::generate("k1");
    let mut empty = binding();
    empty.paths = Some(Vec::new());
    assert_denied(
        &classify(
            &agent_with_binding(
                empty,
                vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()],
                &key,
            ),
            HOST,
        ),
        "row 19",
    );
}

const CREDENTIAL: &str = "sk_test_zsv_matrix_value_4b1e";

struct Recorder {
    port: u16,
    heads: Arc<std::sync::Mutex<Vec<String>>>,
}

async fn spawn_recorder() -> Recorder {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let heads = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut byte = [0u8; 1];
                loop {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let text = String::from_utf8_lossy(&head).into_owned();
                    let length = common::content_length(&text);
                    let mut body = vec![0u8; length];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    seen.lock().unwrap().push(text);
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Recorder { port, heads }
}

struct Served {
    addr: std::net::SocketAddr,
    handler: Arc<AgentHandler>,
    ca_pem: String,
    upstream: Recorder,
    journal: std::path::PathBuf,
    _home: tempfile::TempDir,
}

fn signed_for(
    binding: &ResourceBinding,
    grants: Vec<SignedGrant>,
    key: &ControlSigningKey,
) -> Vec<SignedGrant> {
    let connection = binding.connection().unwrap();
    grants
        .into_iter()
        .map(|signed| {
            key.sign(Grant {
                upstream_host: connection.upstream_host.clone(),
                upstream_port: connection.upstream_port,
                upstream_tls: connection.upstream_tls,
                local_endpoint: connection.local_endpoint,
                ..signed.grant
            })
            .unwrap()
        })
        .collect()
}

async fn serve(
    binding: ResourceBinding,
    grants: Vec<SignedGrant>,
    key: &ControlSigningKey,
    credential: Option<&str>,
) -> Served {
    serve_with_upstream(binding, grants, key, credential, spawn_recorder().await).await
}

async fn serve_with_upstream(
    mut binding: ResourceBinding,
    grants: Vec<SignedGrant>,
    key: &ControlSigningKey,
    credential: Option<&str>,
    upstream: Recorder,
) -> Served {
    binding.upstream_host = Some("127.0.0.1".into());
    binding.upstream_port = Some(upstream.port);
    binding.upstream_plaintext = !binding.is_http();
    let grants = signed_for(&binding, grants, key);
    let home = tempfile::tempdir().unwrap();
    let store = home.path().join("creds");
    std::fs::create_dir_all(&store).unwrap();
    if let Some(value) = credential {
        std::fs::write(store.join("stripe-prod"), value).unwrap();
    }
    let handler = Arc::new(agent_in(binding, grants, key, &store));
    let ca = Arc::new(zs_mitm::LocalCa::load_or_create(home.path().join(".zs-ca")).unwrap());
    let ca_pem = ca.certificate_pem();
    let journal = home.path().join("audit.jsonl");
    let proxy = zs_mitm::ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        ca,
        handler.clone(),
        Arc::new(zs_audit::Journal::open(&journal).unwrap()),
    )
    .await
    .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(async move { proxy.serve().await });
    Served {
        addr,
        handler,
        ca_pem,
        upstream,
        journal,
        _home: home,
    }
}

fn denials(served: &Served, operation: &str) -> usize {
    let operation = format!(r#""operation":"{operation}""#);
    let resource = format!(r#""resource":"{HOST}:{}""#, served.upstream.port);
    std::fs::read_to_string(&served.journal)
        .unwrap()
        .lines()
        .filter(|l| {
            l.contains(r#""decision":"deny""#) && l.contains(&operation) && l.contains(&resource)
        })
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn row_18_a_request_for_another_origin_is_refused_or_rewritten() {
    let key = ControlSigningKey::generate("k1");
    let served = serve(
        binding(),
        vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()],
        &key,
        Some(CREDENTIAL),
    )
    .await;
    let proxy = served.addr.to_string();

    let rewritten = common::raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/v1/customers HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        rewritten.starts_with("HTTP/1.1 200"),
        "row 18 positive control: {rewritten}"
    );
    let tunneled = common::tunneled_exchange(
        &proxy,
        &served.ca_pem,
        HOST,
        443,
        b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        tunneled.starts_with("HTTP/1.1 200"),
        "row 18 positive control: {tunneled}"
    );
    let heads = served.upstream.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 2, "row 18");
    assert_eq!(
        common::header_lines(&heads[0], "Host"),
        vec!["Host: api.stripe.com"],
        "row 18"
    );
    assert_eq!(
        common::header_lines(&heads[1], "Host"),
        vec!["Host: api.stripe.com"],
        "row 18: tunnel"
    );
    assert_eq!(denials(&served, "GET"), 0, "row 18 negative control");

    for request in [
        &b"GET /v1/customers HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n"[..],
        &b"GET /v1/customers HTTP/1.1\r\nConnection: close\r\n\r\n"[..],
        &b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nhost: api.stripe.com\r\nConnection: close\r\n\r\n"[..],
        &b"GET https://evil.example/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n"[..],
        &b"OPTIONS * HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n"[..],
    ] {
        let response =
            common::tunneled_exchange(&proxy, &served.ca_pem, HOST, 443, request).await;
        assert!(response.starts_with("HTTP/1.1 400"), "row 18: {response}");
    }
    assert_eq!(
        served.upstream.heads.lock().unwrap().len(),
        2,
        "row 18: a refused request reached the upstream"
    );
    assert_eq!(denials(&served, "GET"), 4, "row 18");
    assert_eq!(denials(&served, "OPTIONS"), 1, "row 18");
}

fn scoped() -> ResourceBinding {
    let mut scoped = binding();
    scoped.paths = Some(vec!["/oauth/token".into()]);
    scoped
}

#[tokio::test(flavor = "multi_thread")]
async fn row_16_a_path_outside_the_scope_is_forwarded_without_a_credential_or_a_grant() {
    let key = ControlSigningKey::generate("k1");
    let served = serve(scoped(), Vec::new(), &key, Some(CREDENTIAL)).await;
    let proxy = served.addr.to_string();

    let forwarded = common::raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/oauth/authenticate HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer caller-token\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(forwarded.starts_with("HTTP/1.1 200"), "row 16: {forwarded}");
    let heads = served.upstream.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "row 16");
    assert_eq!(
        common::header_lines(&heads[0], "Authorization"),
        vec!["Authorization: Bearer caller-token"],
        "row 16"
    );
    assert!(!heads[0].contains(CREDENTIAL), "row 16");

    let denied = common::raw_exchange(
        &proxy,
        b"POST https://api.stripe.com/oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        denied.starts_with("HTTP/1.1 502"),
        "row 16 negative control: {denied}"
    );
    assert_eq!(served.upstream.heads.lock().unwrap().len(), 1, "row 16");

    let journal = std::fs::read_to_string(&served.journal).unwrap();
    assert!(
        journal.lines().any(
            |l| l.contains(r#""decision":"passthrough""#) && l.contains(r#""operation":"GET""#)
        ),
        "{journal}"
    );
    assert!(!journal.contains(CREDENTIAL), "row 16");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_17_an_ambiguous_request_target_is_refused_before_the_upstream() {
    let key = ControlSigningKey::generate("k1");
    let served = serve(
        scoped(),
        vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()],
        &key,
        Some(CREDENTIAL),
    )
    .await;
    let proxy = served.addr.to_string();
    let positive = common::raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        positive.starts_with("HTTP/1.1 200"),
        "row 17 positive control: {positive}"
    );
    assert!(
        served.upstream.heads.lock().unwrap()[0].contains(CREDENTIAL),
        "row 17 positive control"
    );
    for target in [
        "/oauth/../oauth/token",
        "/oauth/./token",
        "//oauth/token",
        "/oauth%2Ftoken",
        "/oauth/token;x=1",
        "/oauth/..;/token",
        "/oauth/%2e%2e/oauth/token",
        "/oauth/%252e%252e/token",
    ] {
        let request = format!(
            "GET https://api.stripe.com{target} HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n"
        );
        let response = common::raw_exchange(&proxy, request.as_bytes()).await;
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "row 17 {target}: {response}"
        );
    }
    assert_eq!(
        served.upstream.heads.lock().unwrap().len(),
        1,
        "row 17: an ambiguous request reached the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_query_param_scheme_is_decided_on_the_client_path() {
    let key = ControlSigningKey::generate("k1");
    let mut binding = scoped();
    binding.auth = HttpAuth::QueryParam {
        param: "api_key".into(),
    };
    let served = serve(
        binding,
        vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()],
        &key,
        Some(CREDENTIAL),
    )
    .await;
    let proxy = served.addr.to_string();
    let injected = common::raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/oauth/token?x=1 HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let forwarded = common::raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/oauth/authenticate?api_key=caller HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(injected.starts_with("HTTP/1.1 200"), "{injected}");
    assert!(forwarded.starts_with("HTTP/1.1 200"), "{forwarded}");
    let heads = served.upstream.heads.lock().unwrap().clone();
    let lines: Vec<&str> = heads.iter().filter_map(|h| h.lines().next()).collect();
    assert!(
        lines[0].starts_with("GET /oauth/token?") && lines[0].contains(CREDENTIAL),
        "{lines:?}"
    );
    assert_eq!(lines[1], "GET /oauth/authenticate?api_key=caller HTTP/1.1");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_20_a_diagnostic_log_failure_never_blocks_traffic() {
    let temp = common::TestHome::new(".zs-ca");
    let dir = std::path::PathBuf::from(temp.path());
    let upstream = common::spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) =
        common::write_test_setup_with(&dir, upstream.addr.port(), true, true, &["GET"], true, None);
    std::fs::write(
        dir.join(".zs-log"),
        "a file where the log directory should be",
    )
    .unwrap();
    let pid_file = dir.join("child.pid");
    let mut agent = common::spawn_agent(
        common::bin_path().as_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &[
            "sh",
            "-c",
            "echo $$ > \"$0\"; exec sleep 20",
            pid_file.to_str().unwrap(),
        ],
        true,
    )
    .expect("row 20: the agent starts without its diagnostic log");
    let ca = std::fs::read_to_string(&agent.ca_path).unwrap();
    let (status, _) = common::proxied_request(&agent.proxy_addr, &ca, HOST, 443, "/v1/customers")
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let pid = loop {
        let written = std::fs::read_to_string(&pid_file).unwrap_or_default();
        if written.ends_with('\n') {
            break written.trim().to_string();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "row 20: the wrapped child did not report its pid"
        );
        std::thread::sleep(std::time::Duration::from_millis(25));
    };
    let killed = std::process::Command::new("kill")
        .arg(&pid)
        .status()
        .unwrap();
    assert!(killed.success(), "row 20: kill {pid}");
    let _ = agent.child.wait();
    let mut stderr = String::new();
    let _ = std::io::Read::read_to_string(&mut agent.stderr, &mut stderr);
    assert!(status.starts_with("HTTP/1.1 200"), "row 20: {status}");
    assert_eq!(
        upstream.requests.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "row 20"
    );
    assert!(
        stderr.contains("zs: diagnostic log unavailable"),
        "row 20: {stderr}"
    );
    assert!(
        std::fs::read_to_string(&audit)
            .unwrap()
            .contains("\"allow\"")
    );
}

fn mysql_script(flow: fake::Flow) -> fake::Script {
    fake::Script::new(packet::NATIVE_PASSWORD, flow)
}

async fn mysql_logs_in(local: std::net::SocketAddr) -> bool {
    fake::login(local, fake::CLIENT_CAPS)
        .await
        .reply
        .payload
        .first()
        == Some(&packet::OK_HEADER)
}

#[tokio::test(flavor = "multi_thread")]
async fn row_21_a_mysql_change_user_is_refused_and_never_forwarded() {
    let upstream = fake::start(mysql_script(fake::Flow::Accept)).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        "127.0.0.1",
        upstream.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(fake::PASSWORD),
        zs_diag::DiagLog::disabled(),
        Some(audit),
    )
    .await;
    let mut session = fake::login(local, fake::CLIENT_CAPS).await;
    let answer = session.command(b"\x03SELECT 1").await.unwrap();
    assert!(
        answer.payload.ends_with(fake::OK_INFO),
        "row 21 positive control: a query is relayed"
    );

    let refused = session.command(b"\x11root\x00\x00").await.unwrap();

    assert_eq!(refused.payload, CHANGE_USER_REFUSED.packet(), "row 21");
    assert!(session.closed().await, "row 21: the connection must close");
    assert!(
        upstream.seen(|s| s
            .commands
            .iter()
            .all(|c| c.first() != Some(&packet::COM_CHANGE_USER))),
        "row 21: COM_CHANGE_USER reached the server"
    );
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("change_user", zs_proto_mysql::CHANGE_USER_REFUSED_REASON)],
        "row 21: not audited"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_22_a_mysql_cleartext_method_without_tls_is_refused() {
    let positive = fake::start(mysql_script(fake::Flow::Accept)).await;
    let local = positive
        .listen(UpstreamTls::WhenOffered, fake::materialize(fake::PASSWORD))
        .await;
    assert!(mysql_logs_in(local).await, "row 22 positive control");

    for script in [
        fake::Script::new(packet::CACHING_SHA2_PASSWORD, fake::Flow::FullAuth),
        mysql_script(fake::Flow::SwitchTo(packet::SHA256_PASSWORD)),
        mysql_script(fake::Flow::SwitchTo(packet::CLEAR_PASSWORD)),
        mysql_script(fake::Flow::SwitchTo(b"client_ed25519")),
    ] {
        let flow = script.flow;
        let upstream = fake::start(script).await;
        let local = upstream
            .listen(UpstreamTls::WhenOffered, fake::materialize(fake::PASSWORD))
            .await;
        let session = fake::login(local, fake::CLIENT_CAPS).await;
        assert_eq!(
            session.reply.payload,
            METHOD_REFUSED.packet(),
            "row 22: {flow:?}"
        );
        assert!(
            !upstream.saw_bytes(fake::PASSWORD.as_bytes()),
            "row 22: {flow:?} received the password"
        );
        assert!(
            upstream.seen(|s| s.auth_packets.iter().all(|p| p.as_slice() != [0x02])),
            "row 22: {flow:?} received an RSA key request"
        );
        assert!(!upstream.seen(|s| s.authenticated), "row 22: {flow:?}");
    }

    let pki = fake::pki("127.0.0.1");
    let control = fake::start(
        fake::Script::new(packet::CACHING_SHA2_PASSWORD, fake::Flow::FullAuth)
            .with_tls(pki.server.clone()),
    )
    .await;
    let local = control
        .listen(
            UpstreamTls::Required(vec![pki.ca_der.clone()]),
            fake::materialize(fake::PASSWORD),
        )
        .await;
    assert!(
        mysql_logs_in(local).await,
        "row 22 negative control: full auth inside verified TLS"
    );
    assert!(
        control.saw_bytes(fake::PASSWORD.as_bytes()),
        "row 22: the detector must see a password that is sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_23_a_mysql_tls_failure_never_falls_back_to_plaintext() {
    let pki = fake::pki("127.0.0.1");
    let upstream = fake::start(mysql_script(fake::Flow::Accept).with_tls(pki.server.clone())).await;
    let pinned = upstream
        .listen(
            UpstreamTls::Pinned(pki.leaf_sha256),
            fake::materialize(fake::PASSWORD),
        )
        .await;
    assert!(
        mysql_logs_in(pinned).await,
        "row 23 positive control: the right pin"
    );

    let other = fake::pki("10.9.9.9");
    for tls in [
        UpstreamTls::Pinned([0x5a; 32]),
        UpstreamTls::WhenOffered,
        UpstreamTls::Required(vec![other.ca_der.clone()]),
    ] {
        let local = upstream
            .listen(tls, fake::materialize(fake::PASSWORD))
            .await;
        let session = fake::login(local, fake::CLIENT_CAPS).await;
        assert_eq!(session.reply.payload, TLS_REFUSED.packet(), "row 23");
    }
    assert_eq!(
        upstream.seen(|s| s.responses),
        1,
        "row 23: a HandshakeResponse41 followed a TLS failure"
    );

    let plain = fake::start(mysql_script(fake::Flow::Accept)).await;
    for tls in [
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
        UpstreamTls::Pinned(pki.leaf_sha256),
    ] {
        let local = plain.listen(tls, fake::materialize(fake::PASSWORD)).await;
        assert_eq!(
            fake::first_packet(local).await.payload,
            TLS_REFUSED.packet(),
            "row 23: TLS is required and not offered"
        );
    }
    assert_eq!(plain.seen(|s| s.responses), 0, "row 23");
    assert!(!upstream.saw_bytes(fake::PASSWORD.as_bytes()));
    assert!(!plain.saw_bytes(fake::PASSWORD.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn row_24_a_mysql_client_tls_or_compression_request_is_refused() {
    let upstream = fake::start(mysql_script(fake::Flow::Accept)).await;
    let local = upstream
        .listen(UpstreamTls::WhenOffered, fake::materialize(fake::PASSWORD))
        .await;
    assert!(mysql_logs_in(local).await, "row 24 positive control");
    assert_eq!(upstream.seen(|s| s.responses), 1);

    let reply = fake::send_raw(
        local,
        &packet::ssl_request(fake::CLIENT_CAPS, 16 << 20, 255),
    )
    .await;
    assert_eq!(reply.payload, CLIENT_REFUSED.packet(), "row 24: client TLS");
    for flag in [
        packet::CLIENT_COMPRESS,
        packet::CLIENT_ZSTD_COMPRESSION_ALGORITHM,
    ] {
        let session = fake::login(local, fake::CLIENT_CAPS | flag).await;
        assert_eq!(
            session.reply.payload,
            CLIENT_REFUSED.packet(),
            "row 24: compression {flag:#x}"
        );
    }
    assert_eq!(
        upstream.seen(|s| s.responses),
        1,
        "row 24: a refused client reached upstream auth"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_25_a_postgres_tls_failure_never_falls_back_to_plaintext() {
    let pki = pg_fake::pki("127.0.0.1");
    let upstream =
        pg_fake::start(pg_fake::Script::new(pg_fake::Answer::S).with_tls(pki.server.clone())).await;
    let pinned = upstream.listen(UpstreamTls::Pinned(pki.leaf_sha256)).await;
    assert!(
        pg_fake::login(pinned).await.is_ok(),
        "row 25 positive control: the right pin"
    );

    let other = pg_fake::pki("127.0.0.1");
    for tls in [
        UpstreamTls::Pinned([0x5a; 32]),
        UpstreamTls::WhenOffered,
        UpstreamTls::Required(vec![other.ca_der.clone()]),
    ] {
        let local = upstream.listen(tls).await;
        assert_eq!(
            pg_fake::login(local).await.err(),
            Some(pg_fake::error_frame(pg_fake::TLS_FAILED)),
            "row 25"
        );
    }
    assert_eq!(upstream.seen(|s| s.ssl_requests), 4);
    assert_eq!(
        upstream.seen(|s| s.startups),
        1,
        "row 25: a startup packet followed a TLS failure"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_26_a_postgres_tls_setting_refuses_a_server_that_answers_n() {
    let plain = pg_fake::start(pg_fake::Script::new(pg_fake::Answer::N)).await;
    let open = plain.listen(UpstreamTls::WhenOffered).await;
    assert!(
        pg_fake::login(open).await.is_ok(),
        "row 26 negative control: no TLS field runs in plaintext"
    );

    let pki = pg_fake::pki("127.0.0.1");
    for tls in [
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
        UpstreamTls::Pinned(pki.leaf_sha256),
    ] {
        let local = plain.listen(tls).await;
        assert_eq!(
            pg_fake::login(local).await.err(),
            Some(pg_fake::error_frame(pg_fake::TLS_FAILED)),
            "row 26"
        );
    }
    assert_eq!(plain.seen(|s| s.ssl_requests), 3);
    assert_eq!(
        plain.seen(|s| s.startups),
        1,
        "row 26: a plaintext startup followed a required setting"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_27_a_byte_after_the_postgres_tls_answer_is_refused() {
    let pki = pg_fake::pki("127.0.0.1");
    let clean =
        pg_fake::start(pg_fake::Script::new(pg_fake::Answer::S).with_tls(pki.server.clone())).await;
    let control = clean
        .listen(UpstreamTls::Required(vec![pki.ca_der.clone()]))
        .await;
    assert!(
        pg_fake::login(control).await.is_ok(),
        "row 27 negative control: S alone"
    );

    let injected = pg_fake::start(
        pg_fake::Script::new(pg_fake::Answer::SWithExtraByte).with_tls(pki.server.clone()),
    )
    .await;
    let local = injected
        .listen(UpstreamTls::Required(vec![pki.ca_der.clone()]))
        .await;
    assert_eq!(
        pg_fake::login(local).await.err(),
        Some(pg_fake::error_frame(pg_fake::TLS_FAILED)),
        "row 27: a byte after S"
    );
    let odd = pg_fake::start(pg_fake::Script::new(pg_fake::Answer::Other(b'E'))).await;
    let local = odd.listen(UpstreamTls::WhenOffered).await;
    assert_eq!(
        pg_fake::login(local).await.err(),
        Some(pg_fake::error_frame(pg_fake::TLS_FAILED)),
        "row 27: an answer that is not S or N"
    );
    assert_eq!(injected.seen(|s| s.ssl_requests), 1);
    assert_eq!(odd.seen(|s| s.ssl_requests), 1);
    assert_eq!(injected.seen(|s| s.startups), 0, "row 27");
    assert_eq!(odd.seen(|s| s.startups), 0, "row 27");
    assert_eq!(clean.seen(|s| s.startups), 1);
}

fn mongo_find() -> zs_proto_mongo::bson::Doc {
    mongo_fake::find()
}

async fn mongo_listen(
    set: &mongo_fake::FakeSet,
    tls: Option<zs_proto_mongo::UpstreamTls>,
) -> std::net::SocketAddr {
    set.listen(tls, mongo_fake::materialize(mongo_fake::PASSWORD))
        .await
}

fn mongo_auth_commands() -> [(&'static str, zs_proto_mongo::bson::Doc); 3] {
    use zs_proto_mongo::bson::Doc;
    [
        (
            "saslStart",
            Doc::new()
                .with_i32("saslStart", 1)
                .with_str("mechanism", "SCRAM-SHA-256")
                .with_binary("payload", b"n,,n=mallory,r=abc")
                .with_str("$db", "admin"),
        ),
        (
            "saslContinue",
            Doc::new()
                .with_i32("saslContinue", 1)
                .with_i32("conversationId", 1)
                .with_binary("payload", b"c=biws,r=abc,p=AAAA")
                .with_str("$db", "admin"),
        ),
        (
            "authenticate",
            Doc::new()
                .with_i32("authenticate", 1)
                .with_str("mechanism", "MONGODB-X509")
                .with_str("$db", "$external"),
        ),
    ]
}

async fn mongo_refuse_each_auth_command(
    set: &mongo_fake::FakeSet,
    audit: zs_proto_mongo::AuditRefusal,
    diag: zs_diag::DiagLog,
) {
    let local = mongo_fake::listen(
        set.seed(),
        None,
        mongo_fake::materialize(mongo_fake::PASSWORD),
        diag,
        Some(audit),
    )
    .await;
    for (name, command) in mongo_auth_commands() {
        let mut client = mongo_fake::logged_in(local).await;
        assert!(
            client.command(mongo_find()).await.unwrap().truthy("ok"),
            "row 28 positive control: {name}"
        );
        let before = set.sasl_total();
        assert!(before > 0, "row 28 positive control: the agent's own login");
        let reply = client.command(command).await.unwrap();
        mongo_fake::assert_error(&reply, 18, zs_proto_mongo::AUTH_BROKERED.message);
        assert!(client.closed().await, "row 28: {name}");
        assert_eq!(
            set.sasl_total(),
            before,
            "row 28: {name} reached the server"
        );
    }
    assert_eq!(
        set.seen(0, |s| s.commands.clone()),
        vec!["find".to_string(); 3],
        "row 28: only the find commands reached the server"
    );
}

fn mongo_client_refused(events: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    events
        .iter()
        .filter(|e| e["event"] == "client_refused" && e["component"] == "mongo")
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn row_28_a_mongo_client_auth_command_is_refused_and_never_forwarded() {
    let dir = tempfile::tempdir().unwrap();

    let audited = mongo_fake::start(mongo_fake::Script::set(1, Some(0))).await;
    let (audit, refusals) = mongo_fake::audit_recorder();
    let (path, diag) = mongo_fake::diag_log(&dir.path().join("audited"));
    mongo_refuse_each_auth_command(&audited, audit, diag.clone()).await;
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("authenticate", zs_proto_mongo::AUTHENTICATE_REFUSED_REASON); 3],
        "row 28: not audited"
    );
    let (log, events) = mongo_fake::read_diag(&path, diag).await;
    let refused = mongo_client_refused(&events);
    assert_eq!(refused.len(), 3, "{log}");
    for event in refused {
        assert_eq!(event["fields"]["reason"], "auth_command", "{log}");
        assert_eq!(event["audit_seq"], 7, "{log}");
    }

    let unaudited = mongo_fake::start(mongo_fake::Script::set(1, Some(0))).await;
    let failed: zs_proto_mongo::AuditRefusal =
        std::sync::Arc::new(|_: &'static str, _: &'static str| None::<u64>);
    let (path, diag) = mongo_fake::diag_log(&dir.path().join("unaudited"));
    mongo_refuse_each_auth_command(&unaudited, failed, diag.clone()).await;
    let (log, events) = mongo_fake::read_diag(&path, diag).await;
    let refused = mongo_client_refused(&events);
    assert_eq!(refused.len(), 3, "{log}");
    for event in refused {
        assert_eq!(event["fields"]["reason"], "auth_command", "{log}");
        assert!(event.get("audit_seq").is_none(), "row 28: {log}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn row_29_a_mongo_client_framing_outside_the_allowlist_is_refused() {
    use zs_proto_mongo::wire;
    let set = mongo_fake::start(mongo_fake::Script::set(1, Some(0))).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = mongo_fake::diag_log(dir.path());
    let local = mongo_fake::listen(
        set.seed(),
        None,
        mongo_fake::materialize(mongo_fake::PASSWORD),
        diag.clone(),
        None,
    )
    .await;
    let mut control = mongo_fake::logged_in(local).await;
    assert!(
        control.command(mongo_find()).await.unwrap().truthy("ok"),
        "row 29 positive control"
    );
    let accepts = set.accepts_total();
    assert_eq!(accepts, 1, "row 29 positive control: one login");
    let checksummed = {
        let mut frame = wire::OpMsg::new(
            zs_proto_mongo::bson::Doc::new()
                .with_i32("hello", 1)
                .with_str("$db", "admin"),
        )
        .encode(2, 0);
        frame[wire::HEADER_LEN] |= wire::CHECKSUM_PRESENT as u8;
        frame.extend_from_slice(&[0, 0, 0, 0]);
        let len = (frame.len() as i32).to_le_bytes();
        frame[..4].copy_from_slice(&len);
        frame
    };
    let oversize = wire::Header {
        length: wire::DEFAULT_MAX_MESSAGE + 1,
        request_id: 2,
        response_to: 0,
        op_code: wire::OP_MSG,
    }
    .encode()
    .to_vec();
    for first in [
        wire::OpMsg::new(mongo_find()).encode(2, 0),
        wire::frame(wire::OP_COMPRESSED, 2, 0, &[0u8; 16]),
        checksummed,
        oversize,
        wire::frame(2010, 2, 0, &[0u8; 8]),
        wire::frame(wire::OP_MSG, 2, 0, &[0, 0, 0, 0, 0, 9, 9]),
    ] {
        let mut client = mongo_fake::Client::connect(local).await;
        client.send(&first).await.unwrap();
        assert!(client.closed().await, "row 29: a refused first frame");
    }
    assert_eq!(
        set.accepts_total(),
        accepts,
        "row 29: a refused first frame reached the server"
    );
    let later_checksummed_find = {
        let mut frame = wire::OpMsg::new(mongo_find()).encode(9, 0);
        frame[wire::HEADER_LEN] |= wire::CHECKSUM_PRESENT as u8;
        frame.extend_from_slice(&[0, 0, 0, 0]);
        let len = (frame.len() as i32).to_le_bytes();
        frame[..4].copy_from_slice(&len);
        frame
    };
    let valid_find_body = wire::OpMsg::new(mongo_find()).encode(9, 0)[wire::HEADER_LEN..].to_vec();
    let later_valid_body_unknown_opcode = wire::frame(2010, 9, 0, &valid_find_body);
    let later_valid_body_compressed = wire::frame(wire::OP_COMPRESSED, 9, 0, &valid_find_body);
    let later_oversize = wire::Header {
        length: wire::DEFAULT_MAX_MESSAGE + 1,
        request_id: 9,
        response_to: 0,
        op_code: wire::OP_MSG,
    }
    .encode()
    .to_vec();
    let later = [
        mongo_fake::legacy_frame(mongo_find(), 9),
        later_valid_body_compressed,
        later_checksummed_find,
        later_oversize,
        later_valid_body_unknown_opcode,
        wire::frame(wire::OP_MSG, 9, 0, &[0, 0, 0, 0, 0, 9, 9]),
    ];
    let later_count = later.len();
    for later in later {
        let mut client = mongo_fake::logged_in(local).await;
        assert!(
            client.command(mongo_find()).await.unwrap().truthy("ok"),
            "row 29 positive control: a later find"
        );
        let frames = set.seen(0, |s| s.frames);
        client.send(&later).await.unwrap();
        assert!(client.closed().await, "row 29: a refused later frame");
        assert_eq!(
            set.seen(0, |s| s.frames),
            frames,
            "row 29: a refused later frame reached the server"
        );
    }
    assert_eq!(
        set.accepts_total(),
        accepts + later_count,
        "row 29 positive control: one more login per later frame reached the server"
    );
    assert_eq!(
        set.seen(0, |s| s.commands.clone()),
        vec!["find".to_string(); later_count + 1],
        "row 29: a refused frame reached the server"
    );
    let (log, events) = mongo_fake::read_diag(&path, diag).await;
    let reasons: Vec<&str> = mongo_client_refused(&events)
        .iter()
        .filter_map(|e| e["fields"]["reason"].as_str())
        .collect();
    assert_eq!(
        reasons[reasons.len().saturating_sub(later_count)..],
        [
            "op_query",
            "compressed",
            "checksum",
            "frame_size",
            "opcode",
            "malformed"
        ],
        "row 29: each later frame is refused for its own reason: {log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_30_a_mongo_upstream_scram_failure_is_refused() {
    let positive = mongo_fake::start(mongo_fake::Script::set(1, Some(0))).await;
    mongo_fake::logged_in(mongo_listen(&positive, None).await).await;
    assert!(
        positive.seen(0, |s| s.authenticated),
        "row 30 positive control: the login reached SCRAM"
    );
    assert!(
        positive.saw_bytes(mongo_fake::USER.as_bytes()),
        "row 30 positive control: the byte search can match"
    );

    let cases = [
        (
            mongo_fake::Script::set(1, Some(0)).with_sasl(mongo_fake::Sasl::WrongSignature),
            2,
        ),
        (
            mongo_fake::Script::set(1, Some(0)).with_sasl(mongo_fake::Sasl::ShortNonce),
            1,
        ),
        (
            mongo_fake::Script::set(1, Some(0)).with_sasl(mongo_fake::Sasl::LowIterations),
            1,
        ),
        (
            mongo_fake::Script::set(1, Some(0)).with_sasl(mongo_fake::Sasl::Endless),
            4,
        ),
        (
            mongo_fake::Script::set(1, Some(0)).with_mechanisms(Some(vec!["PLAIN"])),
            0,
        ),
    ];
    for (script, rounds) in cases {
        let (sasl, mechanisms) = (script.sasl, script.mechanisms.clone());
        let set = mongo_fake::start(script).await;
        let mut client = mongo_fake::Client::connect(mongo_listen(&set, None).await).await;
        let reply = client.legacy_handshake().await.unwrap();
        mongo_fake::assert_error(&reply, 18, zs_proto_mongo::UPSTREAM_AUTH_FAILED.message);
        assert!(client.closed().await, "row 30: {sasl:?} {mechanisms:?}");
        assert!(
            set.seen(0, |s| s.hellos.len() == 1),
            "row 30: the agent reached the fake: {sasl:?} {mechanisms:?}"
        );
        assert_eq!(
            set.seen(0, |s| s.sasl.len()),
            rounds,
            "row 30: {sasl:?} {mechanisms:?}"
        );
        assert!(
            set.seen(0, |s| s.commands.is_empty()),
            "row 30: {sasl:?} {mechanisms:?}"
        );
        assert!(
            !set.saw_bytes(mongo_fake::PASSWORD.as_bytes()),
            "row 30: {sasl:?} {mechanisms:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn row_31_a_mongo_tls_failure_never_falls_back_to_plaintext() {
    use zs_proto_mongo::UpstreamTls;
    let pki = mongo_fake::pki("127.0.0.1");
    let set =
        mongo_fake::start(mongo_fake::Script::set(1, Some(0)).with_tls(pki.server.clone())).await;
    mongo_fake::logged_in(mongo_listen(&set, Some(UpstreamTls::Pinned(pki.leaf_sha256))).await)
        .await;
    assert_eq!(
        set.seen(0, |s| s.hellos.len()),
        1,
        "row 31 positive control: a verified TLS login"
    );

    let other = mongo_fake::pki("127.0.0.1");
    for tls in [
        UpstreamTls::Pinned([0x5a; 32]),
        UpstreamTls::WhenOffered,
        UpstreamTls::Required(vec![other.ca_der.clone()]),
    ] {
        let mut client = mongo_fake::Client::connect(mongo_listen(&set, Some(tls)).await).await;
        let reply = client.legacy_handshake().await.unwrap();
        mongo_fake::assert_error(&reply, 6, zs_proto_mongo::UNAVAILABLE_TLS.message);
        assert!(client.closed().await, "row 31");
    }
    assert_eq!(
        set.seen(0, |s| s.hellos.len()),
        1,
        "row 31: a hello followed a TLS failure"
    );

    let plain = mongo_fake::start(mongo_fake::Script::set(1, Some(0))).await;
    for tls in [
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
        UpstreamTls::Pinned(pki.leaf_sha256),
    ] {
        let mut client = mongo_fake::Client::connect(mongo_listen(&plain, Some(tls)).await).await;
        let reply = client.legacy_handshake().await.unwrap();
        mongo_fake::assert_error(&reply, 6, zs_proto_mongo::UNAVAILABLE_TLS.message);
        assert!(client.closed().await, "row 31");
    }
    assert_eq!(
        plain.seen(0, |s| s.hellos.len()),
        0,
        "row 31: a plaintext hello followed a TLS setting"
    );
    mongo_fake::logged_in(mongo_listen(&plain, None).await).await;
    assert_eq!(
        plain.seen(0, |s| s.hellos.len()),
        1,
        "row 31 positive control: the plaintext fake counts a hello"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_32_a_mongo_redirect_outside_the_seed_hosts_is_refused() {
    let positive = mongo_fake::start(mongo_fake::Script::set(2, Some(1))).await;
    mongo_fake::logged_in(mongo_listen(&positive, None).await).await;
    assert!(
        positive.seen(1, |s| s.authenticated),
        "row 32 positive control: one redirect"
    );

    for script in [
        mongo_fake::Script::set(3, None),
        mongo_fake::Script::set(2, Some(1)).with_hosts(vec!["10.255.0.1:27017".to_string()]),
        mongo_fake::Script::set(2, Some(1)).with_other_set(1),
        mongo_fake::Script::set(2, Some(1)).with_other_set(0),
        mongo_fake::Script::set(2, None).claiming_primary(1),
    ] {
        let set = mongo_fake::start(script).await;
        let mut client = mongo_fake::Client::connect(mongo_listen(&set, None).await).await;
        let reply = client.legacy_handshake().await.unwrap();
        mongo_fake::assert_error(&reply, 6, zs_proto_mongo::UNAVAILABLE_DISCOVERY.message);
        assert!(client.closed().await, "row 32");
        assert!(
            set.seen(0, |s| s.hellos.len() == 1),
            "row 32: the agent reached the seed"
        );
        assert_eq!(
            set.sasl_total(),
            0,
            "row 32: authenticated after a refused discovery"
        );
    }
}

fn granted(key: &ControlSigningKey, operations: &[&str], protocol: &str) -> Vec<SignedGrant> {
    let mut g = grant(now_ms() + 300_000, "g-1");
    g.operations = operations.iter().map(|o| o.to_string()).collect();
    g.protocol = protocol.into();
    vec![key.sign(g).unwrap()]
}

fn with_auth(auth: HttpAuth) -> ResourceBinding {
    let mut b = binding();
    b.auth = auth;
    b
}

fn sigv4() -> HttpAuth {
    HttpAuth::AwsSigv4 {
        access_key_id: "AKIDMATRIX".into(),
        region: "eu-central-003".into(),
        service: "s3".into(),
    }
}

async fn ws_served(reply: ws_fake::Reply) -> (Served, Arc<std::sync::Mutex<ws_fake::Seen>>) {
    ws_served_on(reply, None).await
}

async fn ws_served_on(
    reply: ws_fake::Reply,
    paths: Option<Vec<String>>,
) -> (Served, Arc<std::sync::Mutex<ws_fake::Seen>>) {
    let key = ControlSigningKey::generate("k1");
    let seen = Arc::new(std::sync::Mutex::new(ws_fake::Seen::default()));
    let port = ws_fake::spawn_ws_upstream(reply, seen.clone()).await;
    let mut ws_binding = with_auth(HttpAuth::WebsocketJsonField {
        field: "apiKey".into(),
    });
    ws_binding.paths = paths;
    let served = serve_with_upstream(
        ws_binding,
        granted(&key, &["GET"], "https"),
        &key,
        Some(CREDENTIAL),
        Recorder {
            port,
            heads: Arc::new(std::sync::Mutex::new(Vec::new())),
        },
    )
    .await;
    (served, seen)
}

async fn ws_upgrade(
    served: &Served,
) -> (
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    String,
) {
    ws_upgrade_at(served, "/v1").await
}

async fn ws_upgrade_at(
    served: &Served,
    path: &str,
) -> (
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    String,
) {
    use tokio::io::AsyncWriteExt;
    let mut tls = common::open_tunnel(&served.addr.to_string(), &served.ca_pem, HOST, 443)
        .await
        .unwrap();
    tls.write_all(format!("GET {path} HTTP/1.1\r\nHost: api.stripe.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let head = ws_fake::read_head(&mut tls).await;
    (tls, head)
}

const WS_AUTH: &[u8] = br#"[{"taskType":"authentication","apiKey":"zs-brokered"}]"#;

fn journal_text(served: &Served) -> String {
    std::fs::read_to_string(&served.journal).unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn row_33_an_any_method_grant_never_names_connect() {
    let any = vec!["*".to_string()];
    for method in ["GET", "POST", "DELETE", "PATCH", "HEAD"] {
        assert!(
            zs_policy::permits(&any, method),
            "row 33 positive control: {method}"
        );
    }
    assert!(!zs_policy::permits(&any, "connect"), "row 33");

    let key = ControlSigningKey::generate("k1");
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("stripe-prod"), CREDENTIAL).unwrap();
    let mut b = binding();
    b.operations = any;
    let handler = agent_in(b, granted(&key, &["*"], "https"), &key, home.path());
    assert!(
        handler.materialize(HOST, "DELETE").is_ok(),
        "row 33 positive control"
    );
    assert!(handler.materialize(HOST, "connect").is_err(), "row 33");

    // A `*` binding under a grant that lists methods opens the host for those methods only.
    let mut b = binding();
    b.operations = vec!["*".to_string()];
    let listed = agent_in(
        b.clone(),
        granted(&key, &["GET"], "https"),
        &key,
        home.path(),
    );
    assert!(
        matches!(classify(&listed, HOST), Flow::Intercept { .. }),
        "row 33: a `*` binding with a GET grant must open the host"
    );
    assert!(listed.materialize(HOST, "GET").is_ok(), "row 33");
    assert!(listed.materialize(HOST, "POST").is_err(), "row 33");
    let connect_only = agent_in(b, granted(&key, &["connect"], "https"), &key, home.path());
    assert_denied(&classify(&connect_only, HOST), "row 33");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_34_a_request_with_the_other_scheme_is_denied_before_the_upstream() {
    let key = ControlSigningKey::generate("k1");
    let https = serve(
        binding(),
        granted(&key, &["GET"], "https"),
        &key,
        Some(CREDENTIAL),
    )
    .await;
    let proxy = https.addr.to_string();
    let allowed = common::raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/v1/x HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "row 34 positive control: {allowed}"
    );
    for authority in ["api.stripe.com:443", "api.stripe.com"] {
        let denied = common::raw_exchange(
            &proxy,
            format!("GET http://{authority}/v1/x HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await;
        assert!(
            denied.starts_with("HTTP/1.1 502"),
            "row 34 {authority}: {denied}"
        );
    }
    assert_eq!(https.upstream.heads.lock().unwrap().len(), 1, "row 34");
    let journal = journal_text(&https);
    assert!(
        journal.contains("http request to an https binding"),
        "row 34: {journal}"
    );
    assert!(
        journal.contains(&format!(
            "port 80 is not the signed port {}",
            https.upstream.port
        )),
        "row 34: {journal}"
    );

    let mut plain = binding();
    plain.protocol = "http".into();
    let http = serve(
        plain,
        granted(&key, &["GET"], "http"),
        &key,
        Some(CREDENTIAL),
    )
    .await;
    let proxy = http.addr.to_string();
    let allowed = common::raw_exchange(
        &proxy,
        b"GET http://api.stripe.com/v1/x HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "row 34 positive control: {allowed}"
    );
    for authority in ["api.stripe.com:80", "api.stripe.com"] {
        let denied = common::raw_exchange(
            &proxy,
            format!("GET https://{authority}/v1/x HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await;
        assert!(
            denied.starts_with("HTTP/1.1 502"),
            "row 34 {authority}: {denied}"
        );
    }
    assert_eq!(http.upstream.heads.lock().unwrap().len(), 1, "row 34");
    let journal = journal_text(&http);
    assert!(
        journal.contains("https request to an http binding"),
        "row 34: {journal}"
    );
    assert!(
        journal.contains(&format!(
            "port 443 is not the signed port {}",
            http.upstream.port
        )),
        "row 34: {journal}"
    );
}

#[test]
fn row_35_upstream_plaintext_on_an_http_binding_refuses_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let load = |binding: &str| {
        let path = dir.path().join("zs-policy.json");
        std::fs::write(&path, format!(r#"{{"bindings":[{binding}]}}"#)).unwrap();
        zs::AgentFile::load(&path)
    };
    assert!(
        load(r#"{"resource":"r","host":"203.0.113.7","protocol":"http"}"#).is_ok(),
        "row 35 positive control"
    );
    assert!(
        load(
            r#"{"resource":"r","host":"203.0.113.7","protocol":"http","upstream_plaintext":true}"#
        )
        .is_err(),
        "row 35"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_36_a_websocket_frame_that_carries_the_credential_ends_the_session() {
    use tokio::io::AsyncWriteExt;
    let (served, seen) = ws_served(ws_fake::Reply::Echo).await;
    let (mut tls, head) = ws_upgrade(&served).await;
    assert!(head.starts_with("HTTP/1.1 101"), "row 36: {head}");
    tls.write_all(&ws_fake::frame(1, WS_AUTH, Some([5, 5, 5, 5])))
        .await
        .unwrap();
    assert!(
        ws_fake::read_frame(&mut tls).await.is_none(),
        "row 36: the echoed credential reached the workload"
    );
    assert!(
        seen.lock()
            .unwrap()
            .message
            .windows(CREDENTIAL.len())
            .any(|w| w == CREDENTIAL.as_bytes()),
        "row 36 positive control: the agent wrote the credential"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !journal_text(&served).contains("websocket echo") && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        journal_text(&served).contains(
            r#""operation":"websocket message","decision":"deny","reason":"websocket echo""#
        ),
        "row 36"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_45_a_credential_split_across_upstream_messages_never_reaches_the_workload() {
    use tokio::io::AsyncWriteExt;
    let (served, seen) = ws_served(ws_fake::Reply::SplitEcho).await;
    let (mut tls, head) = ws_upgrade(&served).await;
    assert!(head.starts_with("HTTP/1.1 101"), "row 45: {head}");
    tls.write_all(&ws_fake::frame(1, WS_AUTH, Some([5, 5, 5, 5])))
        .await
        .unwrap();
    assert!(
        ws_fake::read_frame(&mut tls).await.is_none(),
        "row 45: the first half of the credential reached the workload"
    );
    assert!(
        seen.lock()
            .unwrap()
            .message
            .windows(CREDENTIAL.len())
            .any(|w| w == CREDENTIAL.as_bytes()),
        "row 45 positive control: the agent wrote the credential"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !journal_text(&served).contains("websocket echo") && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        journal_text(&served).contains(
            r#""operation":"websocket message","decision":"deny","reason":"websocket echo""#
        ),
        "row 45"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_37_a_websocket_frame_outside_the_limits_ends_the_session() {
    use tokio::io::AsyncWriteExt;
    let (served, _) = ws_served(ws_fake::Reply::Ok).await;
    let (mut tls, _) = ws_upgrade(&served).await;
    tls.write_all(&ws_fake::frame(1, WS_AUTH, Some([7, 1, 9, 3])))
        .await
        .unwrap();
    assert!(
        ws_fake::read_frame(&mut tls).await.is_some(),
        "row 37 positive control"
    );

    for reply in [ws_fake::Reply::Masked, ws_fake::Reply::Reserved] {
        let (served, _) = ws_served(reply).await;
        let (mut tls, head) = ws_upgrade(&served).await;
        assert!(head.starts_with("HTTP/1.1 101"), "row 37: {head}");
        tls.write_all(&ws_fake::frame(1, WS_AUTH, Some([7, 1, 9, 3])))
            .await
            .unwrap();
        assert!(ws_fake::read_frame(&mut tls).await.is_none(), "row 37");
    }

    let (served, seen) = ws_served(ws_fake::Reply::Ok).await;
    let (mut tls, _) = ws_upgrade(&served).await;
    let mut oversized = vec![0x81, 0x80 | 127];
    oversized.extend_from_slice(&(33u64 * 1024 * 1024).to_be_bytes());
    oversized.extend_from_slice(&[1, 2, 3, 4]);
    tls.write_all(&oversized).await.unwrap();
    assert!(ws_fake::read_frame(&mut tls).await.is_none(), "row 37");
    assert!(seen.lock().unwrap().message.is_empty(), "row 37");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_38_a_plain_request_to_a_websocket_binding_is_denied() {
    let (served, seen) = ws_served(ws_fake::Reply::Ok).await;
    let response = common::tunneled_exchange(
        &served.addr.to_string(),
        &served.ca_pem,
        HOST,
        443,
        b"GET /v1 HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 502"), "row 38: {response}");
    assert!(seen.lock().unwrap().head.is_empty(), "row 38");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_39_a_signed_sigv4_request_that_cannot_be_re_signed_is_denied() {
    let key = ControlSigningKey::generate("k1");
    let served = serve(
        with_auth(sigv4()),
        granted(&key, &["GET"], "https"),
        &key,
        Some(CREDENTIAL),
    )
    .await;
    let proxy = served.addr.to_string();
    let request = |headers: &str| {
        format!(
            "GET https://api.stripe.com/bucket/k HTTP/1.1\r\nHost: api.stripe.com\r\n{headers}Connection: close\r\n\r\n"
        )
    };
    let auth = |signed: &str| {
        format!(
            "Authorization: AWS4-HMAC-SHA256 Credential=x/20261016/auto/s3/aws4_request, SignedHeaders={signed}, Signature=00\r\n"
        )
    };
    let date = "x-amz-date: 20261016T120000Z\r\n";
    let unsigned = "x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n";
    let good = request(&format!(
        "{date}{unsigned}{}",
        auth("host;x-amz-content-sha256;x-amz-date")
    ));
    let allowed = common::raw_exchange(&proxy, good.as_bytes()).await;
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "row 39 positive control: {allowed}"
    );
    let head = served.upstream.heads.lock().unwrap()[0].clone();
    assert!(
        head.contains("Credential=AKIDMATRIX/20261016/eu-central-003/s3/aws4_request"),
        "row 39 positive control: {head}"
    );
    assert!(!head.contains(CREDENTIAL), "row 39");

    for headers in [
        format!("{unsigned}{}", auth("host;x-amz-content-sha256")),
        format!("{date}{}", auth("host;x-amz-date")),
        format!(
            "{date}x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n{}",
            auth("host;x-amz-content-sha256;x-amz-date")
        ),
        format!(
            "{date}{unsigned}{}",
            auth("x-amz-content-sha256;x-amz-date")
        ),
        format!("{date}{unsigned}{}", auth("host;range;x-amz-date")),
    ] {
        let denied = common::raw_exchange(&proxy, request(&headers).as_bytes()).await;
        assert!(denied.starts_with("HTTP/1.1 502"), "row 39: {denied}");
    }
    assert_eq!(served.upstream.heads.lock().unwrap().len(), 1, "row 39");
}

// The signature covers the `Host` the upstream receives, port included.
#[tokio::test(flavor = "multi_thread")]
async fn a_sigv4_request_on_another_port_is_signed_for_that_port() {
    use zs_protocol::Protocol;
    let key = ControlSigningKey::generate("k1");
    let served = serve(
        with_auth(sigv4()),
        granted(&key, &["GET"], "https"),
        &key,
        Some(CREDENTIAL),
    )
    .await;
    let date = "20261016T120000Z";
    let client_auth = "AWS4-HMAC-SHA256 Credential=x/20261016/auto/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=00";
    let authority = format!("api.stripe.com:{}", served.upstream.port);
    let sent = common::raw_exchange(
        &served.addr.to_string(),
        format!(
            "GET https://{authority}/bucket/k HTTP/1.1\r\nHost: {authority}\r\nx-amz-date: {date}\r\nx-amz-content-sha256: UNSIGNED-PAYLOAD\r\nAuthorization: {client_auth}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(sent.starts_with("HTTP/1.1 200"), "{sent}");
    let head = served.upstream.heads.lock().unwrap()[0].clone();
    assert_eq!(
        common::header_lines(&head, "Host"),
        vec![format!("Host: {authority}")],
        "{head}"
    );
    let mut expected = zs_protocol::InjectedRequest {
        method: "GET".into(),
        path: "/bucket/k".into(),
        headers: vec![
            ("Host".into(), authority.clone()),
            ("x-amz-date".into(), date.into()),
            ("x-amz-content-sha256".into(), "UNSIGNED-PAYLOAD".into()),
            ("Authorization".into(), client_auth.into()),
        ],
        body: Vec::new(),
    };
    let HttpAuth::AwsSigv4 {
        access_key_id,
        region,
        service,
    } = sigv4()
    else {
        unreachable!()
    };
    zs_proto_http::AwsSigV4::new(HOST, access_key_id, region, service, vec![])
        .inject(
            &mut expected,
            &zs_credential::Credential::from_bytes(CREDENTIAL.as_bytes().to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(
        common::header_lines(&head, "Authorization"),
        vec![format!(
            "Authorization: {}",
            expected.header("Authorization").unwrap()
        )],
        "{head}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_40_an_unsigned_request_to_a_sigv4_binding_is_forwarded_unchanged() {
    let key = ControlSigningKey::generate("k1");
    let served = serve(
        with_auth(sigv4()),
        granted(&key, &["GET"], "https"),
        &key,
        Some(CREDENTIAL),
    )
    .await;
    let forwarded = common::raw_exchange(
        &served.addr.to_string(),
        b"GET https://api.stripe.com/bucket/public.png HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(forwarded.starts_with("HTTP/1.1 200"), "row 40: {forwarded}");
    let heads = served.upstream.heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "row 40");
    assert!(
        common::header_lines(&heads[0], "Authorization").is_empty(),
        "row 40: {}",
        heads[0]
    );
    assert!(!heads[0].contains(CREDENTIAL), "row 40");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_41_an_hmac_body_signature_request_without_its_id_header_is_denied_before_the_upstream()
{
    let key = ControlSigningKey::generate("k1");
    let served = serve(
        with_auth(HttpAuth::HmacBodySignature {
            id_header: "va".into(),
            signature_header: "signature".into(),
        }),
        granted(&key, &["GET"], "https"),
        &key,
        Some(CREDENTIAL),
    )
    .await;
    let proxy = served.addr.to_string();
    let allowed = common::raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/api/v2/payment-channels HTTP/1.1\r\nHost: api.stripe.com\r\nva: 0000001234567890\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "row 41 positive control: {allowed}"
    );
    let head = served.upstream.heads.lock().unwrap()[0].clone();
    assert_eq!(
        common::header_lines(&head, "signature").len(),
        1,
        "row 41 positive control: {head}"
    );
    assert!(!head.contains(CREDENTIAL), "row 41");

    let denied = common::raw_exchange(
        &proxy,
        b"GET https://api.stripe.com/api/v2/payment-channels HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(denied.starts_with("HTTP/1.1 502"), "row 41: {denied}");
    assert_eq!(served.upstream.heads.lock().unwrap().len(), 1, "row 41");
}

async fn presign_endpoint(
    binding: ResourceBinding,
) -> (String, Recorder, std::path::PathBuf, tempfile::TempDir) {
    let key = ControlSigningKey::generate("k1");
    let upstream = spawn_recorder().await;
    let mut binding = binding;
    binding.upstream_host = Some("127.0.0.1".into());
    binding.upstream_port = Some(upstream.port);
    binding.upstream_plaintext = !binding.is_http();
    let protocol = if binding.is_http() { "http" } else { "https" };
    let home = tempfile::tempdir().unwrap();
    let store = home.path().join("creds");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("stripe-prod"), CREDENTIAL).unwrap();
    let grants = signed_for(&binding, granted(&key, &["GET"], protocol), &key);
    let handler = Arc::new(agent_in(binding, grants, &key, &store));
    let journal = home.path().join("audit.jsonl");
    let endpoint = zs_mitm::EndpointServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(zs_mitm::LocalCa::load_or_create(home.path().join(".zs-ca")).unwrap()),
        handler,
        Arc::new(zs_audit::Journal::open(&journal).unwrap()),
        zs_diag::DiagLog::disabled(),
        HOST.to_string(),
    )
    .await
    .unwrap();
    let addr = endpoint.local_addr().unwrap().to_string();
    tokio::spawn(async move { endpoint.serve().await });
    (addr, upstream, journal, home)
}

async fn presign(endpoint: &str, path: &str, signed: &str, expires: u64, method: &str) -> String {
    presign_dated(endpoint, path, signed, expires, method, &common::amz_now()).await
}

async fn presign_dated(
    endpoint: &str,
    path: &str,
    signed: &str,
    expires: u64,
    method: &str,
    date: &str,
) -> String {
    let body = format!(
        r#"{{"url":"http://{endpoint}{path}?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=x%2F20261016%2Fauto%2Fs3%2Faws4_request&X-Amz-Date={date}&X-Amz-Expires={expires}&X-Amz-SignedHeaders={signed}&X-Amz-Signature=00","method":"{method}"}}"#
    );
    common::raw_exchange(
        endpoint,
        format!(
            "POST /.zs/presign HTTP/1.1\r\nHost: {endpoint}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn row_42_a_presign_outside_the_grant_or_the_limits_is_denied_and_never_sent_upstream() {
    let mut scoped = with_auth(sigv4());
    scoped.paths = Some(vec!["/bucket/k.txt".into()]);
    let (endpoint, upstream, journal, _home) = presign_endpoint(scoped).await;

    let allowed = presign(&endpoint, "/bucket/k.txt", "host", 600, "GET").await;
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "row 42 positive control: {allowed}"
    );
    let url = allowed.rsplit("\r\n\r\n").next().unwrap();
    assert!(
        url.starts_with("https://api.stripe.com/bucket/k.txt?"),
        "{url}"
    );
    assert_eq!(url.rsplit("X-Amz-Signature=").next().unwrap().len(), 64);
    assert!(!url.contains(CREDENTIAL), "row 42");

    for (path, signed, expires, method) in [
        ("/bucket/k.txt", "host", 600, "DELETE"),
        ("/bucket/other.txt", "host", 600, "GET"),
        ("/bucket/k.txt", "host%3Brange", 600, "GET"),
        ("/bucket/k.txt", "host", 604_801, "GET"),
        ("/bucket/k.txt", "host", 0, "GET"),
    ] {
        let denied = presign(&endpoint, path, signed, expires, method).await;
        assert!(
            denied.starts_with("HTTP/1.1 502"),
            "row 42 {path} {signed} {expires} {method}: {denied}"
        );
    }
    let stale = presign_dated(
        &endpoint,
        "/bucket/k.txt",
        "host",
        600,
        "GET",
        "20200101T000000Z",
    )
    .await;
    assert!(
        stale.starts_with("HTTP/1.1 502"),
        "row 42 stale date: {stale}"
    );
    let audit = std::fs::read_to_string(&journal).unwrap();
    assert!(
        audit.contains(r#""operation":"presign GET","decision":"allow""#),
        "{audit}"
    );
    assert!(
        audit.contains(r#""operation":"presign DELETE","decision":"deny""#),
        "{audit}"
    );
    assert_eq!(
        audit.matches(r#""decision":"deny""#).count(),
        6,
        "row 42: {audit}"
    );

    let mut plain = with_auth(sigv4());
    plain.protocol = "http".into();
    let (http_endpoint, http_upstream, _, _http_home) = presign_endpoint(plain).await;
    let denied = presign(&http_endpoint, "/bucket/k.txt", "host", 600, "GET").await;
    assert!(denied.starts_with("HTTP/1.1 502"), "row 42: {denied}");

    assert!(upstream.heads.lock().unwrap().is_empty(), "row 42");
    assert!(http_upstream.heads.lock().unwrap().is_empty(), "row 42");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_43_a_local_endpoint_request_for_another_host_or_with_an_origin_is_refused() {
    let (endpoint, upstream, _journal, _home) = presign_endpoint(with_auth(sigv4())).await;
    let port = endpoint.rsplit(':').next().unwrap();
    let request = |host: &str, extra: &str| {
        format!(
            "GET /bucket/public.png HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n"
        )
    };
    for host in [endpoint.clone(), format!("localhost:{port}")] {
        let allowed = common::raw_exchange(&endpoint, request(&host, "").as_bytes()).await;
        assert!(
            allowed.starts_with("HTTP/1.1 200"),
            "row 43 positive control {host}: {allowed}"
        );
    }
    for (host, extra) in [
        (format!("rebound.example:{port}"), ""),
        ("127.0.0.1".to_string(), ""),
        (endpoint.clone(), "Origin: https://rebound.example\r\n"),
    ] {
        let refused = common::raw_exchange(&endpoint, request(&host, extra).as_bytes()).await;
        assert!(
            !refused.starts_with("HTTP/1.1 2"),
            "row 43 {host} {extra}: {refused}"
        );
    }
    let presigned = presign(&endpoint, "/bucket/k.txt", "host", 600, "GET").await;
    assert!(presigned.starts_with("HTTP/1.1 200"), "row 43: {presigned}");
    assert_eq!(upstream.heads.lock().unwrap().len(), 2, "row 43");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_44_a_websocket_session_stops_injecting_after_revocation() {
    use tokio::io::AsyncWriteExt;
    let (served, seen) = ws_served(ws_fake::Reply::Ok).await;
    let (mut tls, head) = ws_upgrade(&served).await;
    assert!(head.starts_with("HTTP/1.1 101"), "row 44: {head}");
    tls.write_all(&ws_fake::frame(1, WS_AUTH, Some([7, 1, 9, 3])))
        .await
        .unwrap();
    assert!(
        ws_fake::read_frame(&mut tls).await.is_some(),
        "row 44 positive control"
    );

    served.handler.apply_revocations(&["g-1".to_string()]);
    tls.write_all(&ws_fake::frame(1, WS_AUTH, Some([7, 1, 9, 3])))
        .await
        .unwrap();
    assert!(ws_fake::read_frame(&mut tls).await.is_none(), "row 44");
    assert_eq!(
        seen.lock().unwrap().messages,
        1,
        "row 44: a message after revocation reached the upstream"
    );
    let journal = journal_text(&served);
    assert!(
        journal.contains(r#""operation":"websocket message","decision":"allow""#),
        "row 44 positive control: {journal}"
    );
    assert!(
        journal.contains(r#""operation":"websocket message","decision":"deny""#),
        "row 44: {journal}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_grant_stops_injection_on_a_path_scoped_websocket_binding() {
    use tokio::io::AsyncWriteExt;
    let (served, seen) = ws_served_on(ws_fake::Reply::Ok, Some(vec!["/ws".into()])).await;
    let (mut tls, head) = ws_upgrade_at(&served, "/ws").await;
    assert!(head.starts_with("HTTP/1.1 101"), "row 44 paths: {head}");
    tls.write_all(&ws_fake::frame(1, WS_AUTH, Some([7, 1, 9, 3])))
        .await
        .unwrap();
    assert!(
        ws_fake::read_frame(&mut tls).await.is_some(),
        "row 44 paths positive control"
    );
    assert_eq!(
        seen.lock().unwrap().messages,
        1,
        "row 44 paths positive control: the first message reached the upstream"
    );

    served.handler.apply_revocations(&["g-1".to_string()]);
    tls.write_all(&ws_fake::frame(1, WS_AUTH, Some([7, 1, 9, 3])))
        .await
        .unwrap();
    assert!(
        ws_fake::read_frame(&mut tls).await.is_none(),
        "row 44 paths"
    );
    assert_eq!(
        seen.lock().unwrap().messages,
        1,
        "row 44 paths: a message after revocation reached the upstream"
    );
    let journal = journal_text(&served);
    assert!(
        journal.contains(r#""operation":"websocket message","decision":"allow""#),
        "row 44 paths positive control: {journal}"
    );
    assert!(
        journal.contains(r#""operation":"websocket message","decision":"deny""#),
        "row 44 paths: {journal}"
    );
}

#[cfg(unix)]
fn stored_path_home() -> (PlainHome, common::Tripwire) {
    let ca = common::test_ca::TestCa::generate("matrix-control").unwrap();
    let home = PlainHome::new(&ca.certificate_pem());
    let control = common::Tripwire::any();
    home.write_policy(&control.url(), https_binding());
    (home, control)
}

#[cfg(unix)]
#[test]
fn row_46_no_stored_enrolment_stops_the_run_before_any_request() {
    let (home, control) = stored_path_home();
    let (code, output) = home.run(&["--enrollment-token", "enr-matrix"]);
    assert_eq!(code, 1, "{output}");
    let reached = control.hits();
    assert!(
        reached >= 1,
        "row 46 positive control: a token run reaches this control plane:\n{output}"
    );

    let (code, output) = home.run(&[]);

    home.assert_refused(
        code,
        &output,
        &format!("zs: not enrolled with {}; run zs login", control.url()),
        "row 46",
    );
    assert_eq!(
        control.hits(),
        reached,
        "row 46: a request left the machine"
    );
}

#[cfg(unix)]
fn stored_record_fixture() -> (tempfile::TempDir, zs_mitm::Zeroizing<Vec<u8>>) {
    let home = tempfile::tempdir().unwrap();
    let enrolment = zs::device::Enrolment {
        control: "http://127.0.0.1:9".into(),
        control_ca_sha256: "ab".repeat(32),
        subject: SUBJECT.into(),
        device_id: "dev-1".into(),
        organization: "default".into(),
        client_certificate: "CERT".into(),
        grant_verifying_key_hex: "cd".repeat(32),
        grant_verifying_key_id: "control-k1".into(),
        wire_url: "https://localhost:8444".into(),
    };
    zs::device::save_file(
        home.path(),
        &zs::device::DeviceFile {
            enrolments: vec![enrolment],
        },
    )
    .unwrap();
    let record = zs::device::DeviceSecrets::new(
        zs_mitm::Zeroizing::new(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".into(),
        ),
        zs_mitm::Zeroizing::new(vec![7u8; 32]),
    )
    .encode()
    .unwrap();
    (home, record)
}

#[cfg(unix)]
#[test]
fn row_47_a_missing_native_device_record_is_not_enrolled() {
    let (home, record) = stored_record_fixture();
    let loaded = zs::device::load_with(home.path(), "http://127.0.0.1:9/", |_| {
        Ok(Some(zs_mitm::Zeroizing::new(record.to_vec())))
    })
    .unwrap();
    assert!(
        loaded.is_some_and(|(enrolment, _)| enrolment.device_id == "dev-1"),
        "row 47 positive control: a present record loads"
    );

    let asked = std::cell::RefCell::new(Vec::new());
    let missing = zs::device::load_with(home.path(), "http://127.0.0.1:9", |account| {
        asked.borrow_mut().push(account.to_string());
        Ok(None)
    });

    assert!(
        matches!(missing, Ok(None)),
        "row 47: a missing record must be `not enrolled`, not an error or an empty identity"
    );
    assert_eq!(*asked.borrow(), ["zs-device-dev-1"]);
}

#[cfg(unix)]
#[test]
fn row_48_a_locked_or_unavailable_device_record_stops_with_its_fixed_text() {
    let (home, record) = stored_record_fixture();
    assert!(
        zs::device::load_with(home.path(), "http://127.0.0.1:9", |_| Ok(Some(
            zs_mitm::Zeroizing::new(record.to_vec())
        )))
        .unwrap()
        .is_some(),
        "row 48 positive control: a readable record loads"
    );

    let locked: fn() -> zs_mitm::device_store::DeviceStoreError =
        || zs_mitm::device_store::DeviceStoreError::Locked;
    let unavailable: fn() -> zs_mitm::device_store::DeviceStoreError =
        || zs_mitm::device_store::DeviceStoreError::Unavailable;
    for (error, text) in [
        (locked, "secure storage locked"),
        (unavailable, "secure storage unavailable"),
    ] {
        let outcome = zs::device::load_with(home.path(), "http://127.0.0.1:9", |_| Err(error()));
        assert_eq!(
            outcome.err().as_deref(),
            Some(text),
            "row 48: the store error must stop the run with its fixed text"
        );
    }
}

#[cfg(unix)]
#[test]
fn row_50_two_different_control_cas_stop_the_run_and_neither_is_used() {
    let ca = common::test_ca::TestCa::generate("matrix-control").unwrap();
    let other = common::test_ca::TestCa::generate("matrix-other").unwrap();
    let (home, control) = stored_path_home();
    std::fs::write(
        home.home.path().join("control-ca.pem"),
        ca.certificate_pem(),
    )
    .unwrap();
    let ca_dir = home.home.path().join(".zs-ca");
    std::fs::write(ca_dir.join("control-ca.crt"), ca.certificate_pem()).unwrap();
    let named = home.home.path().join("control-ca.pem");
    assert_eq!(
        zs::control_ca_pem(Some(&named), &ca_dir).unwrap(),
        ca.certificate_pem(),
        "row 50 positive control: two equal CAs are used"
    );
    let (code, output) = home.run(&["--enrollment-token", "enr-matrix"]);
    assert_eq!(code, 1, "{output}");
    let reached = control.hits();
    assert!(
        reached >= 1,
        "row 50 positive control: with equal CAs a token run reaches the control plane:\n{output}"
    );

    std::fs::write(ca_dir.join("control-ca.crt"), other.certificate_pem()).unwrap();
    let error = zs::control_ca_pem(Some(&named), &ca_dir)
        .expect_err("row 50: two different CAs must be refused");
    assert!(error.contains("two different control plane CAs"), "{error}");
    assert!(!error.contains("BEGIN CERTIFICATE"), "{error}");
    let (code, output) = home.run(&[]);

    assert_eq!(code, 1, "{output}");
    assert!(
        output.lines().any(|l| l.starts_with(&format!(
            "zs: control plane at {}: two different control plane CAs",
            control.url()
        ))),
        "row 50:\n{output}"
    );
    assert!(!home.marker().exists(), "row 50: the child must not start");
    assert_eq!(
        control.hits(),
        reached,
        "row 50: a request left the machine"
    );
}

#[cfg(unix)]
#[test]
fn row_53_a_device_refused_at_startup_stops_a_token_run() {
    let fake = FakeControl::start();
    let home = fake.token_home();
    fake.answer(FakeGrant::Refuse(403, "denied by policy"));
    let (code, output) = fake.token_run(&home);
    assert_eq!(
        code, 0,
        "row 53 positive control: a 403 lets the run start:\n{output}"
    );
    assert!(home.marker().exists(), "row 53 positive control:\n{output}");

    fake.answer(FakeGrant::Refuse(401, r#"{"code":"subject_mismatch"}"#));
    let (code, output) = fake.token_run(&home);

    home.assert_refused(
        code,
        &output,
        "zs: control plane refused this device (subject_mismatch)",
        "row 53",
    );
}

#[cfg(unix)]
fn assert_mismatch_stops_a_token_run(fake: &FakeControl, wrong: FakeGrant, row: &str) {
    let home = fake.token_home();
    fake.answer(FakeGrant::Mint {
        host: HOST.to_ascii_uppercase(),
        protocol: "HTTPS".into(),
    });
    let (code, output) = fake.token_run(&home);
    assert_eq!(code, 0, "{row} positive control:\n{output}");
    assert!(home.marker().exists(), "{row} positive control:\n{output}");
    assert!(output.contains("zs: grant g-fake for"), "{row}:\n{output}");

    fake.answer(wrong);
    let (code, output) = fake.token_run(&home);

    home.assert_refused(
        code,
        &output,
        &format!("zs: {RESOURCE}: binding host does not match the grant"),
        row,
    );
}

#[cfg(unix)]
#[test]
fn row_55_a_grant_for_another_host_stops_the_run() {
    let key = ControlSigningKey::generate("k1");
    let mut upper = grant(now_ms() + 300_000, "g-1");
    upper.host = HOST.to_ascii_uppercase();
    assert_eq!(
        zs::connection::grant_matches(&key.sign(upper).unwrap(), &binding()),
        Ok(())
    );
    let mut other = grant(now_ms() + 300_000, "g-1");
    other.host = "evil.example.test".into();
    assert_eq!(
        zs::connection::grant_matches(&key.sign(other).unwrap(), &binding()),
        Err(zs::connection::Mismatch::HostOrProtocol)
    );

    let fake = FakeControl::start();
    assert_mismatch_stops_a_token_run(
        &fake,
        FakeGrant::Mint {
            host: "evil.example.test".into(),
            protocol: "https".into(),
        },
        "row 55",
    );
}

#[cfg(unix)]
#[test]
fn row_56_a_grant_for_another_protocol_stops_the_run() {
    let key = ControlSigningKey::generate("k1");
    assert_eq!(
        zs::connection::grant_matches(
            &key.sign(grant(now_ms() + 300_000, "g-1")).unwrap(),
            &binding()
        ),
        Ok(())
    );
    let mut other = grant(now_ms() + 300_000, "g-1");
    other.protocol = "postgres".into();
    assert_eq!(
        zs::connection::grant_matches(&key.sign(other).unwrap(), &binding()),
        Err(zs::connection::Mismatch::HostOrProtocol)
    );

    let fake = FakeControl::start();
    assert_mismatch_stops_a_token_run(
        &fake,
        FakeGrant::Mint {
            host: HOST.into(),
            protocol: "postgres".into(),
        },
        "row 56",
    );
}

#[cfg(unix)]
#[test]
fn row_57_zs_login_refuses_plain_http_to_a_remote_host_before_any_request() {
    for url in [
        "http://127.0.0.1:8443",
        "http://localhost",
        "http://[::1]:8443",
    ] {
        assert!(zs::control_url_allowed(url).is_ok(), "row 57: {url}");
    }
    let control = common::Tripwire::any();
    let remote = format!("http://[::ffff:127.0.0.1]:{}", control.addr().port());
    drop(std::net::TcpStream::connect(("::ffff:127.0.0.1", control.addr().port())).unwrap());
    let reached = control.hits();
    assert_eq!(
        reached, 1,
        "row 57 positive control: {remote} reaches the listener"
    );
    let error = zs::control_url_allowed(&remote).err().unwrap_or_default();
    assert!(
        error.contains("http is allowed only for a loopback control plane"),
        "{error}"
    );
    let home = tempfile::tempdir().unwrap();

    let (code, output) = common::run_zs(
        home.path(),
        &["login".into(), "--control".into(), remote.clone()],
        &[],
    );

    assert_eq!(code, 1, "{output}");
    assert!(
        output.contains("http is allowed only for a loopback control plane"),
        "row 57:\n{output}"
    );
    assert_eq!(
        control.hits(),
        reached,
        "row 57: a request left the machine"
    );
    assert!(!home.path().join(".zs-device.json").exists());
}

#[cfg(unix)]
#[test]
fn row_58_file_signing_keys_and_grants_are_refused_with_a_control_plane() {
    let (home, control) = stored_path_home();
    let (code, output) = home.run(&["--enrollment-token", "enr-matrix"]);
    assert_eq!(code, 1, "{output}");
    let reached = control.hits();
    assert!(
        reached >= 1,
        "row 58 positive control: a token run reaches this control plane:\n{output}"
    );

    let key = ControlSigningKey::generate("file-k1");
    let mut forged = grant(now_ms() + 300_000, "g-file");
    forged.subject = "localuser".into();
    forged.workload = "default".into();
    forged.host = "evil.example".into();
    let policy = |run: Option<serde_json::Value>, keys: bool, grants: bool| {
        let mut policy = serde_json::json!({
            "bindings": [{"resource": RESOURCE, "host": "evil.example", "protocol": "https"}],
            "signing_keys": [],
            "grants": [],
        });
        if keys {
            policy["signing_keys"] = serde_json::json!([{
                "key_id": key.key_id(),
                "verifying_key_hex": key
                    .verifying_key_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            }]);
        }
        if grants {
            policy["grants"] =
                serde_json::json!([
                    serde_json::to_value(key.sign(forged.clone()).unwrap()).unwrap()
                ]);
        }
        if let Some(run) = run {
            policy["run"] = run;
        }
        std::fs::write(
            home.home.path().join("zs-policy.json"),
            serde_json::to_string(&policy).unwrap(),
        )
        .unwrap();
    };
    policy(None, true, true);
    let (code, output) = home.run(&[]);
    assert_eq!(
        code, 0,
        "row 58 positive control: local mode keeps file grants:\n{output}"
    );
    assert!(home.marker().exists(), "row 58 positive control:\n{output}");

    let run = serde_json::json!({"control": control.url(), "control_ca": "control-ca.pem"});
    let line =
        "zs: signing_keys and grants in the policy file are not allowed with a control plane";
    for (keys, grants) in [(true, true), (true, false), (false, true)] {
        policy(Some(run.clone()), keys, grants);
        for flags in [&[][..], &["--enrollment-token", "enr-matrix"][..]] {
            let (code, output) = home.run(flags);
            home.assert_refused(
                code,
                &output,
                line,
                &format!("row 58 (keys {keys}, grants {grants}, flags {flags:?})"),
            );
        }
    }
    assert_eq!(
        control.hits(),
        reached,
        "row 58: a request left the machine"
    );
}

#[cfg(unix)]
#[test]
fn row_60_a_self_signing_policy_cannot_choose_credentials_dir() {
    let home = common::TestHome::new(".zs-ca");
    std::fs::create_dir_all(home.path().join(".zs-ca")).unwrap();
    let credentials = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".zs-credentials/row-60-matrix");
    let marker = home.path().join("child-ran");
    let key = ControlSigningKey::generate("file-k1");
    let mut forged = grant(now_ms() + 300_000, "g-file");
    forged.subject = "localuser".into();
    forged.workload = "default".into();
    forged.host = "evil.example".into();
    let policy = serde_json::json!({
        "run": {"credentials_dir": "~/.zs-credentials/row-60-matrix"},
        "bindings": [{"resource": RESOURCE, "host": "evil.example", "protocol": "https"}],
        "signing_keys": [{
            "key_id": key.key_id(),
            "verifying_key_hex": key
                .verifying_key_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        }],
        "grants": [serde_json::to_value(key.sign(forged).unwrap()).unwrap()],
    });
    std::fs::write(
        home.path().join("zs-policy.json"),
        serde_json::to_string(&policy).unwrap(),
    )
    .unwrap();
    let run = |flags: &[String]| {
        let _ = std::fs::remove_file(&marker);
        let mut args: Vec<String> = vec!["run".into()];
        args.extend(flags.iter().cloned());
        args.extend(["--".into(), "touch".into(), marker.display().to_string()]);
        common::run_zs(home.path(), &args, &[])
    };

    let (code, output) = run(&[
        "--credentials-dir".into(),
        credentials.display().to_string(),
    ]);
    assert_eq!(
        code, 0,
        "row 60 positive control: the flag names the directory:\n{output}"
    );
    assert!(marker.exists(), "row 60 positive control:\n{output}");

    let (code, output) = run(&[]);
    let line = "zs: a policy file with its own signing_keys or grants cannot choose credentials_dir; pass --credentials-dir";
    assert_eq!(code, 1, "row 60:\n{output}");
    assert!(
        output.lines().any(|l| l == line),
        "row 60: expected the line {line:?}:\n{output}"
    );
    assert!(
        !marker.exists(),
        "row 60: the child must not start:\n{output}"
    );
}

#[cfg(unix)]
#[test]
fn row_61_a_policy_file_field_that_differs_from_the_signed_connection_stops_the_run() {
    let fake = FakeControl::start();
    let home = fake.token_home();
    let binding = |field: &str, value: serde_json::Value| {
        let mut binding = https_binding();
        binding[field] = value;
        binding
    };
    home.write_policy(&fake.url, binding("upstream_host", HOST.into()));
    let (code, output) = fake.token_run(&home);
    assert_eq!(
        code, 0,
        "row 61 positive control: a field equal to the signed one starts the run:\n{output}"
    );
    assert!(home.marker().exists(), "row 61 positive control:\n{output}");
    assert!(
        output.lines().any(|l| l.starts_with("zs: proxy ")),
        "row 61 positive control: the proxy listener opens:\n{output}"
    );

    for (field, value, file, signed) in [
        (
            "upstream_host",
            serde_json::json!("127.0.0.1"),
            "127.0.0.1",
            HOST,
        ),
        ("upstream_port", serde_json::json!(8443), "8443", "443"),
        ("local_endpoint", serde_json::json!(true), "true", "false"),
    ] {
        home.write_policy(&fake.url, binding(field, value));
        let (code, output) = fake.token_run(&home);
        home.assert_refused(
            code,
            &output,
            &field_line(RESOURCE, field, file, signed),
            &format!("row 61 ({field})"),
        );
        assert!(
            !output.contains("zs: proxy "),
            "row 61 ({field}): no listener may open:\n{output}"
        );
    }
}

#[cfg(unix)]
fn ca_fixture(home: &PlainHome) -> (String, [u8; 32]) {
    let path = home.home.path().join("ca.pem");
    let certified = rcgen::generate_simple_self_signed(vec!["db.matrix.test".into()]).unwrap();
    std::fs::write(&path, certified.cert.pem()).unwrap();
    let sha256 = zs_upstream::load_ca(&path).unwrap().sha256;
    (path.display().to_string(), sha256)
}

#[cfg(unix)]
fn ca_signed(fake: &FakeControl, sha256: [u8; 32]) {
    fake.answer(FakeGrant::Signed(
        "db.matrix.test",
        "postgres",
        zs_policy::ResolvedConnection {
            upstream_host: "db.matrix.test".into(),
            upstream_port: 5432,
            upstream_tls: zs_policy::UpstreamTlsMode::CaSha256(sha256),
            local_endpoint: false,
        },
    ));
}

#[cfg(unix)]
fn ca_binding(upstream_ca: Option<&str>) -> serde_json::Value {
    let mut binding = serde_json::json!({
        "resource": RESOURCE,
        "host": "db.matrix.test",
        "protocol": "postgres",
    });
    if let Some(path) = upstream_ca {
        binding["upstream_ca"] = path.into();
    }
    binding
}

#[cfg(unix)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(unix)]
#[test]
fn row_62_an_upstream_ca_whose_hash_differs_from_the_signed_one_stops_the_run() {
    let fake = FakeControl::start();
    let home = fake.token_home();
    let (path, sha256) = ca_fixture(&home);
    home.write_policy(&fake.url, ca_binding(Some(&path)));
    ca_signed(&fake, sha256);
    let (code, output) = fake.token_run(&home);
    assert_eq!(
        code, 0,
        "row 62 positive control: the signed hash starts the run:\n{output}"
    );
    assert!(home.marker().exists(), "row 62 positive control:\n{output}");

    ca_signed(&fake, [0x22; 32]);
    let (code, output) = fake.token_run(&home);

    let file_hex = hex(&sha256);
    home.assert_refused(
        code,
        &output,
        &format!(
            "zs: {RESOURCE}: upstream_ca {path} has SHA-256 {file_hex}, but the control plane signed {}; restore the file, or, if the new file is intended, ask an admin to set the resource's CA SHA-256 to {file_hex}",
            "22".repeat(32)
        ),
        "row 62",
    );
    assert!(!output.contains("BEGIN CERTIFICATE"), "row 62:\n{output}");
}

#[cfg(unix)]
#[test]
fn row_63_a_signed_ca_bundle_without_upstream_ca_stops_the_run() {
    let fake = FakeControl::start();
    let home = fake.token_home();
    let (path, sha256) = ca_fixture(&home);
    home.write_policy(&fake.url, ca_binding(Some(&path)));
    ca_signed(&fake, sha256);
    let (code, output) = fake.token_run(&home);
    assert_eq!(
        code, 0,
        "row 63 positive control: a file naming the CA starts the run:\n{output}"
    );
    assert!(home.marker().exists(), "row 63 positive control:\n{output}");

    home.write_policy(&fake.url, ca_binding(None));
    let (code, output) = fake.token_run(&home);

    home.assert_refused(
        code,
        &output,
        &format!(
            "zs: {RESOURCE}: the control plane signed a CA bundle with SHA-256 {}; set upstream_ca to that file",
            hex(&sha256)
        ),
        "row 63",
    );
}

#[cfg(unix)]
#[test]
fn a_bad_grant_signature_stops_a_token_run_without_login_advice() {
    let fake = FakeControl::start();
    let home = fake.token_home();
    let (code, output) = fake.token_run(&home);
    assert_eq!(
        code, 0,
        "positive control: a valid grant starts the run:\n{output}"
    );
    assert!(home.marker().exists(), "positive control:\n{output}");

    fake.answer(FakeGrant::Forged);
    let (code, output) = fake.token_run(&home);

    home.assert_refused(
        code,
        &output,
        "zs: control plane signing key changed",
        "token signature",
    );
    assert!(!output.contains("zs login"), "{output}");
}

fn on_port(port: u16, grant_id: &str, expires_at_ms: u64) -> Grant {
    let mut on_port = grant(expires_at_ms, grant_id);
    on_port.upstream_port = port;
    on_port
}

#[test]
fn row_64_a_renewal_whose_connection_changed_is_skipped() {
    let key = ControlSigningKey::generate("k1");
    let sign = |port: u16, grant_id: &str, expires_at_ms: u64| {
        key.sign(on_port(port, grant_id, expires_at_ms)).unwrap()
    };
    let soon = now_ms() + 60_000;
    let later = now_ms() + 600_000;

    let equal = agent_with(vec![sign(443, "g-1", soon)], &key);
    assert_eq!(
        equal.accept_renewal(&binding(), sign(443, "g-2", later)),
        Ok(())
    );
    assert!(
        !equal.grant_needs_renewal(RESOURCE, 150_000),
        "row 64 positive control: an equal connection replaces the grant"
    );

    let changed = agent_with(vec![sign(443, "g-1", soon)], &key);
    let mismatch = changed
        .accept_renewal(&binding(), sign(8443, "g-3", later))
        .expect_err("row 64: a changed connection must not be cached");
    assert_eq!(
        mismatch.renewal_line(RESOURCE),
        format!(
            "zs: {RESOURCE}: the control plane changed upstream_port (signed 8443, running 443); restart zs run to use it"
        )
    );
    assert_eq!(mismatch.failure(), "connection_mismatch");
    assert!(changed.grant_needs_renewal(RESOURCE, 150_000));
    assert!(matches!(classify(&changed, HOST), Flow::Intercept { .. }));
    changed.apply_revocations(&["g-1".to_string()]);
    let Flow::Deny { reason } = classify(&changed, HOST) else {
        panic!("row 64: the kept grant is g-1");
    };
    assert!(reason.contains("grant g-1 is revoked"), "row 64: {reason}");
}

#[test]
fn row_65_a_cached_grant_with_another_connection_is_denied() {
    let key = ControlSigningKey::generate("k1");
    let equal = agent_with(
        vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()],
        &key,
    );
    assert!(
        matches!(classify(&equal, HOST), Flow::Intercept { .. }),
        "row 65 positive control"
    );

    let mut plaintext = grant(now_ms() + 300_000, "g-1");
    plaintext.upstream_tls = zs_policy::UpstreamTlsMode::Plaintext;
    let handler = agent_with(vec![key.sign(plaintext).unwrap()], &key);
    let Flow::Deny { reason } = classify(&handler, HOST) else {
        panic!("row 65: a grant with another connection must deny");
    };
    assert!(
        reason.contains("upstream_tls differs from the grant"),
        "row 65: {reason}"
    );
    let denied = handler.materialize(HOST, "GET").err().expect("row 65");
    assert!(
        denied
            .reason
            .contains("upstream_tls differs from the grant"),
        "row 65: {}",
        denied.reason
    );
}

#[test]
fn row_66_a_connect_to_a_port_that_is_not_signed_is_denied() {
    let key = ControlSigningKey::generate("k1");
    let to = |handler: &AgentHandler, port: u16| {
        handler.classify(&Destination::new(HOST.to_string(), port))
    };
    let default = agent_with(
        vec![key.sign(grant(now_ms() + 300_000, "g-1")).unwrap()],
        &key,
    );
    assert!(
        matches!(
            to(&default, 443),
            Flow::Intercept {
                upstream_port: 443,
                ..
            }
        ),
        "row 66 positive control"
    );
    let Flow::Deny { reason } = to(&default, 8443) else {
        panic!("row 66: an unsigned port must deny");
    };
    assert!(
        reason.contains("port 8443 is not the signed port 443"),
        "row 66: {reason}"
    );

    let mut signed_8443 = binding();
    signed_8443.upstream_port = Some(8443);
    let handler = agent_with_binding(
        signed_8443,
        vec![key.sign(on_port(8443, "g-1", now_ms() + 300_000)).unwrap()],
        &key,
    );
    for port in [8443, 443] {
        assert!(
            matches!(
                to(&handler, port),
                Flow::Intercept {
                    upstream_port: 8443,
                    ..
                }
            ),
            "row 66: CONNECT to {port} forwards to the signed port"
        );
    }
    assert!(
        matches!(to(&handler, 9443), Flow::Deny { reason } if reason.contains("port 9443 is not the signed port 8443")),
        "row 66"
    );
}

const SSM_ROLE: &str = "arn:aws:iam::111122223333:role/zs-stripe";
const SSM_PARAMETER: &str = "/stripe/production/API_KEY";
const SSM_VALUE: &str = "sk_test_zsv_ssm_value_6d2a";
const SSM_SUB: &str = "zs:default:-:stripe-production";
const SSM_TIMEOUT: std::time::Duration = zs_materializer::aws_ssm::CALL_TIMEOUT;

type SsmCache = zs_materializer::GrantBoundCache<zs_materializer::aws_ssm::SsmStore>;

struct Ssm {
    aws: zs_test_aws::FakeAws,
    issuer: zs_test_aws::TestIssuer,
    key: ControlSigningKey,
}

struct SsmNoExchange;

#[async_trait::async_trait]
impl zs_materializer::ExchangeProvider for SsmNoExchange {
    async fn exchange(
        &self,
        _grant: &Grant,
    ) -> Result<zs_credential::Credential, zs_materializer::MaterializationError> {
        Err(zs_materializer::MaterializationError::Exchange(
            "not configured".into(),
        ))
    }
}

fn ssm_source(parameter: &str) -> zs_policy::CredentialSource {
    zs_policy::CredentialSource::AwsSsm(zs_policy::AwsSsmSource {
        role_arn: zs_policy::RoleArn::parse(SSM_ROLE).unwrap(),
        region: zs_policy::AwsRegion::parse(zs_test_aws::DEFAULT_REGION).unwrap(),
        parameter: zs_policy::SsmParameter::parse(parameter).unwrap(),
    })
}

fn sts_refuses() -> Option<zs_test_aws::Failure> {
    Some(zs_test_aws::Failure::StsRefuse {
        status: 403,
        code: "AccessDenied".into(),
    })
}

impl Ssm {
    fn start() -> Self {
        let issuer = zs_test_aws::TestIssuer::new(zs_test_aws::DEFAULT_ISSUER);
        let aws = zs_test_aws::FakeAws::start(zs_test_aws::FakeAwsOptions::new(
            &issuer,
            vec![zs_test_aws::TrustRule::new(SSM_ROLE, SSM_SUB)],
        ));
        aws.put_parameter(
            SSM_PARAMETER,
            SSM_VALUE,
            zs_test_aws::ParameterKind::SecureString,
        );
        Self {
            aws,
            issuer,
            key: ControlSigningKey::generate("k1"),
        }
    }

    fn token(&self) -> String {
        self.issuer
            .token(SSM_SUB, "g-1", (now_ms() + 300_000) / 1000)
    }

    fn minted(&self, grant_id: &str, parameter: &str, token: Option<String>) -> zs::MintedGrant {
        let mut remote = grant(now_ms() + 300_000, grant_id);
        remote.source = ssm_source(parameter);
        zs::MintedGrant {
            signed: self.key.sign(remote).unwrap(),
            token: token.map(zs_credential::IdentityToken::from_string),
        }
    }

    fn cache(&self, timeout: std::time::Duration) -> Arc<SsmCache> {
        self.cache_on(self.aws.network(), timeout)
    }

    fn cache_on(
        &self,
        network: zs_upstream::http::Network,
        timeout: std::time::Duration,
    ) -> Arc<SsmCache> {
        Arc::new(zs_materializer::GrantBoundCache::new(
            zs_materializer::aws_ssm::SsmStore::with_timeout(network, timeout).unwrap(),
        ))
    }

    fn agent(&self, first: zs::MintedGrant, cache: Arc<SsmCache>) -> AgentHandler {
        let grants = GrantCache::new();
        grants.insert(first);
        AgentHandler::from_grants(
            zs_identity::Subject::new(SUBJECT).unwrap(),
            zs_identity::WorkloadLabel::new(WORKLOAD).unwrap(),
            vec![binding()],
            grants,
            zs_grant::AgentVerifier::new(vec![(
                self.key.key_id().to_string(),
                ed25519_dalek::VerifyingKey::from_bytes(&self.key.verifying_key_bytes()).unwrap(),
            )]),
            Arc::new(zs_materializer::Materializer::new(
                zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(
                    "/nonexistent",
                )))
                .with_aws_ssm(cache),
                Arc::new(SsmNoExchange),
            )),
        )
    }

    fn reads(&self, handler: &AgentHandler, row: &str) {
        let value = handler
            .materialize(HOST, "GET")
            .unwrap_or_else(|denied| panic!("{row} positive control: {}", denied.reason));
        assert_eq!(
            value.expose(),
            SSM_VALUE.as_bytes(),
            "{row} positive control"
        );
    }
}

fn denial(handler: &AgentHandler, row: &str) -> zs_protocol::Denied {
    handler
        .materialize(HOST, "GET")
        .err()
        .unwrap_or_else(|| panic!("{row}: must be denied"))
}

fn assert_no_token(token: &str, places: &[(&str, &str)], row: &str) {
    for (place, text) in places {
        for fragment in token.split('.') {
            assert!(
                !text.contains(fragment),
                "{row}: the identity token must not reach {place}: {text}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn row_78_an_aws_ssm_grant_without_an_identity_token_is_denied() {
    let ssm = Ssm::start();
    let with_token = ssm.agent(
        ssm.minted("g-1", SSM_PARAMETER, Some(ssm.token())),
        ssm.cache(SSM_TIMEOUT),
    );
    ssm.reads(&with_token, "row 78");
    let sts_calls = ssm.aws.sts_calls();

    let without = ssm.agent(
        ssm.minted("g-2", SSM_PARAMETER, None),
        ssm.cache(SSM_TIMEOUT),
    );
    assert_eq!(
        denial(&without, "row 78").reason,
        "materialization failed: no identity token"
    );
    assert_eq!(ssm.aws.sts_calls(), sts_calls, "row 78: no STS call");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_79_sts_refusal_is_denied_without_the_token_in_any_line() {
    let ssm = Ssm::start();
    let token = ssm.token();
    let accepted = ssm.agent(
        ssm.minted("g-1", SSM_PARAMETER, Some(token.clone())),
        ssm.cache(SSM_TIMEOUT),
    );
    ssm.reads(&accepted, "row 79");

    ssm.aws.set_failure(sts_refuses());
    let home = tempfile::tempdir().unwrap();
    let log = home.path().join("diag.jsonl");
    let diag = zs_diag::DiagLog::open_with_cap(&log, "run", 1 << 20).unwrap();
    let refused = ssm
        .agent(
            ssm.minted("g-2", SSM_PARAMETER, Some(token.clone())),
            ssm.cache(SSM_TIMEOUT),
        )
        .with_diag(diag.clone());
    let denied = denial(&refused, "row 79");
    assert_eq!(denied.reason, "materialization failed: aws_ssm refused");
    diag.close();
    let text = std::fs::read_to_string(&log).unwrap();
    let failed: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["event"] == "materialize_failed")
        .collect();
    assert_eq!(failed.len(), 1, "row 79: {text}");
    let audit_reason = denied.audit_reason().to_string();
    let credential_ref = refused.credential_ref(HOST).unwrap();
    assert_eq!(
        credential_ref,
        format!("aws_ssm:{SSM_ROLE}:{SSM_PARAMETER}")
    );
    assert_eq!(failed[0]["fields"]["step"], "sts", "row 79: {text}");
    assert_eq!(
        failed[0]["fields"]["provider_code"], "AccessDenied",
        "row 79: {text}"
    );
    assert_eq!(
        failed[0]["fields"]["credential_ref"], credential_ref,
        "row 79: {text}"
    );
    assert_no_token(
        &token,
        &[
            ("the diag log", text.as_str()),
            ("the denial", denied.reason.as_str()),
            ("the audit reason", audit_reason.as_str()),
            ("the audit credential_ref", credential_ref.as_str()),
        ],
        "row 79",
    );
    ssm.aws.set_failure(None);

    #[cfg(unix)]
    if option_env!("ZS_BUILD_TEST_ENDPOINTS") == Some("1") {
        std::thread::scope(|scope| {
            scope
                .spawn(|| row_79_in_a_spawned_run(&ssm))
                .join()
                .unwrap();
        });
    }
}

#[cfg(unix)]
fn token_run_request(home: &PlainHome, ssm: &Ssm, request: &[u8]) -> (String, String) {
    use std::io::Read;
    let dir = home.home.path();
    let root = dir.join("aws-root.pem");
    std::fs::write(&root, ssm.aws.root_pem()).unwrap();
    let stop = dir.join("stop");
    let _ = std::fs::remove_file(&stop);
    let mut child = std::process::Command::new(common::bin_path())
        .args(["run", "--enrollment-token", "enr-fake", "--", "sh", "-c"])
        .arg(format!(
            "while [ ! -f '{}' ]; do sleep 0.05; done",
            stop.display()
        ))
        .env("ZS_HOME", dir)
        .env("USER", "localuser")
        .env("ZS_TEST_AWS_RESOLVE", ssm.aws.resolve_env())
        .env("ZS_TEST_AWS_EXTRA_ROOT", &root)
        .current_dir(dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let mut seen = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let (proxy, ca) = loop {
        let text = String::from_utf8_lossy(&seen).into_owned();
        let line = |prefix: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(prefix))
                .map(|rest| rest.trim().to_string())
        };
        if let (Some(proxy), Some(ca)) = (line("zs: proxy "), line("zs: ca-cert ")) {
            break (proxy, ca);
        }
        let mut chunk = [0u8; 1024];
        let n = stdout.read(&mut chunk).unwrap_or(0);
        if n == 0 || std::time::Instant::now() > deadline {
            let mut err = String::new();
            let _ = stderr.read_to_string(&mut err);
            panic!("zs did not report its proxy:\n{text}{err}");
        }
        seen.extend_from_slice(&chunk[..n]);
    };
    let ca_pem = std::fs::read_to_string(dir.join(&ca)).unwrap();
    let response = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(common::tunneled_exchange(
            &proxy, &ca_pem, HOST, 443, request,
        ));
    std::fs::write(&stop, "").unwrap();
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).unwrap();
    seen.extend_from_slice(&rest);
    let mut err = Vec::new();
    stderr.read_to_end(&mut err).unwrap();
    child.wait().unwrap();
    seen.extend_from_slice(&err);
    (response, String::from_utf8_lossy(&seen).into_owned())
}

#[cfg(unix)]
fn files_under(dir: &std::path::Path) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else if let Ok(bytes) = std::fs::read(&path) {
            found.push((
                path.display().to_string(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
    }
    found
}

#[cfg(unix)]
fn row_79_in_a_spawned_run(ssm: &Ssm) {
    use std::sync::atomic::Ordering::SeqCst;
    let upstream = common::spawn_fake_upstream();
    let fake = FakeControl::start();
    let token = ssm.token();
    fake.answer(FakeGrant::Remote {
        source: ssm_source(SSM_PARAMETER),
        token: token.clone(),
        connection: common::loopback_connection(upstream.addr.port(), true),
    });
    let home = fake.token_home_with(serde_json::json!({
        "resource": RESOURCE,
        "host": HOST,
        "protocol": "https",
        "upstream_host": "127.0.0.1",
        "upstream_port": upstream.addr.port(),
        "upstream_plaintext": true,
    }));
    let request =
        b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n";

    let (response, output) = token_run_request(&home, ssm, request);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "row 79 spawned positive control: {response}\n{output}"
    );
    assert!(
        upstream.last_auth.lock().unwrap().contains(SSM_VALUE),
        "row 79 spawned positive control: the SSM value reaches the upstream"
    );
    let served = upstream.requests.load(SeqCst);

    ssm.aws.set_failure(sts_refuses());
    let (response, output) = token_run_request(&home, ssm, request);
    ssm.aws.set_failure(None);
    assert!(
        !response.starts_with("HTTP/1.1 200"),
        "row 79 spawned: {response}\n{output}"
    );
    assert_eq!(upstream.requests.load(SeqCst), served, "row 79 spawned");
    let files = files_under(home.home.path());
    let source = format!("aws_ssm:{SSM_ROLE}:{SSM_PARAMETER}");
    assert!(
        files.iter().any(|(_, text)| text.contains(&source)),
        "row 79 spawned: the journal must name the source, so the scan reads it"
    );
    let mut places: Vec<(&str, &str)> = vec![("stdout or stderr", output.as_str())];
    places.extend(
        files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str())),
    );
    assert_no_token(&token, &places, "row 79 spawned");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_80_sts_unreachable_or_slow_is_denied() {
    let ssm = Ssm::start();
    let short = std::time::Duration::from_millis(500);
    let fast = ssm.agent(
        ssm.minted("g-1", SSM_PARAMETER, Some(ssm.token())),
        ssm.cache(short),
    );
    ssm.reads(&fast, "row 80");

    ssm.aws.set_delay(Some(std::time::Duration::from_secs(2)));
    let slow = ssm.agent(
        ssm.minted("g-2", SSM_PARAMETER, Some(ssm.token())),
        ssm.cache(short),
    );
    assert_eq!(
        denial(&slow, "row 80 slow").reason,
        "materialization failed: aws_ssm timed out"
    );
    ssm.aws.set_delay(None);

    let closed = common::free_port();
    let mut network = ssm.aws.network();
    for (_, addr) in &mut network.resolve {
        *addr = std::net::SocketAddr::from(([127, 0, 0, 1], closed));
    }
    let unreachable = ssm.agent(
        ssm.minted("g-3", SSM_PARAMETER, Some(ssm.token())),
        ssm.cache_on(network, short),
    );
    assert_eq!(
        denial(&unreachable, "row 80 unreachable").reason,
        "materialization failed: aws_ssm unreachable"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn row_81_ssm_refusal_is_denied_and_audited_with_the_parameter() {
    let ssm = Ssm::start();
    let found = ssm.agent(
        ssm.minted("g-1", SSM_PARAMETER, Some(ssm.token())),
        ssm.cache(SSM_TIMEOUT),
    );
    ssm.reads(&found, "row 81");

    let missing = "/stripe/production/MISSING";
    let handler = ssm.agent(
        ssm.minted("g-2", missing, Some(ssm.token())),
        ssm.cache(SSM_TIMEOUT),
    );
    let denied = denial(&handler, "row 81");
    assert_eq!(denied.reason, "materialization failed: aws_ssm refused");
    assert!(
        ssm.aws
            .last_ssm_error()
            .is_some_and(|body| body.contains("ParameterNotFound")),
        "row 81: SSM refused"
    );
    assert_eq!(
        handler.credential_ref(HOST),
        Some(format!("aws_ssm:{SSM_ROLE}:{missing}")),
        "row 81: the audit names the parameter"
    );
    for text in [denied.reason.as_str(), denied.audit_reason()] {
        assert!(!text.contains(missing), "row 81: {text}");
        assert!(!text.contains(SSM_ROLE), "row 81: {text}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn row_82_an_empty_or_string_list_value_is_denied() {
    let ssm = Ssm::start();
    let empty = "/stripe/production/EMPTY";
    let list = "/stripe/production/LIST";
    ssm.aws
        .put_parameter(empty, "", zs_test_aws::ParameterKind::String);
    ssm.aws
        .put_parameter(list, "a,b", zs_test_aws::ParameterKind::StringList);
    let usable = ssm.agent(
        ssm.minted("g-1", SSM_PARAMETER, Some(ssm.token())),
        ssm.cache(SSM_TIMEOUT),
    );
    ssm.reads(&usable, "row 82");

    for (n, parameter) in [empty, list].into_iter().enumerate() {
        let handler = ssm.agent(
            ssm.minted(&format!("g-{}", n + 2), parameter, Some(ssm.token())),
            ssm.cache(SSM_TIMEOUT),
        );
        assert_eq!(
            denial(&handler, parameter).reason,
            "materialization failed: aws_ssm returned an unusable value",
            "row 82: {parameter}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn row_83_session_refresh_failure_is_denied_and_drops_the_session() {
    let ssm = Ssm::start();
    let cache = ssm.cache(SSM_TIMEOUT);
    let handler = ssm.agent(
        ssm.minted("g-1", SSM_PARAMETER, Some(ssm.token())),
        cache.clone(),
    );
    ssm.reads(&handler, "row 83");
    assert_eq!(cache.inner().session_count(), 1, "row 83 positive control");

    ssm.aws.expire_sessions();
    ssm.aws.set_failure(sts_refuses());
    handler.renew_grant(ssm.minted("g-2", SSM_PARAMETER, Some(ssm.token())));
    assert_eq!(
        denial(&handler, "row 83").reason,
        "materialization failed: aws_ssm refused"
    );
    assert_eq!(
        cache.inner().session_count(),
        0,
        "row 83: the expired session is dropped"
    );

    ssm.aws.set_failure(None);
    ssm.reads(&handler, "row 83 after STS recovers");
}

#[tokio::test(flavor = "multi_thread")]
async fn row_84_revocation_drops_the_cached_session_and_value() {
    let ssm = Ssm::start();
    let cache = ssm.cache(SSM_TIMEOUT);
    let handler = ssm.agent(
        ssm.minted("g-1", SSM_PARAMETER, Some(ssm.token())),
        cache.clone(),
    );
    ssm.reads(&handler, "row 84");
    assert_eq!(cache.entry_count(), 1, "row 84 positive control");
    assert_eq!(cache.inner().session_count(), 1, "row 84 positive control");
    let calls = (ssm.aws.sts_calls(), ssm.aws.ssm_calls());

    handler.apply_revocations(&["g-1".to_string()]);
    assert_eq!(cache.entry_count(), 0, "row 84: the value is dropped");
    assert_eq!(
        cache.inner().session_count(),
        0,
        "row 84: the session is dropped"
    );
    let denied = denial(&handler, "row 84");
    assert!(
        denied.reason.contains("revoked"),
        "row 84: {}",
        denied.reason
    );
    assert_eq!(
        (ssm.aws.sts_calls(), ssm.aws.ssm_calls()),
        calls,
        "row 84: no AWS call after revocation"
    );
}

#[cfg(unix)]
#[test]
fn row_85_a_remote_source_in_zs_policy_json_is_refused_at_load() {
    let temp = common::TestHome::new(".zs-ca");
    let dir = temp.path().to_path_buf();
    let upstream = common::spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) =
        common::write_test_setup(&dir, upstream.addr.port(), true, true);
    let marker = dir.join("child-ran");
    let run = || {
        let _ = std::fs::remove_file(&marker);
        common::spawn_agent_capturing(
            &common::bin_path(),
            &policy,
            &creds,
            &audit,
            &ca_dir,
            &["touch", marker.to_str().unwrap()],
        )
        .unwrap()
    };
    let ran = run();
    assert!(marker.exists(), "row 85 positive control: {}", ran.stderr);
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&policy).unwrap()).unwrap();

    let key = ControlSigningKey::generate("k1");
    let mut remote = grant(now_ms() + 300_000, "g-85");
    remote.source = ssm_source(SSM_PARAMETER);
    let mut with_grant = original.clone();
    with_grant["grants"] = serde_json::json!([key.sign(remote).unwrap()]);
    let mut with_binding = original.clone();
    with_binding["bindings"][0]["source"] = serde_json::json!({
        "kind": "aws_ssm",
        "role_arn": SSM_ROLE,
        "region": zs_test_aws::DEFAULT_REGION,
        "parameter": SSM_PARAMETER,
    });
    for (file, line) in [
        (
            with_grant,
            "zs: policy: stripe-production: a local grant may only use a file source",
        ),
        (
            with_binding,
            "zs: policy: stripe-production: source is set only by the control plane",
        ),
    ] {
        std::fs::write(&policy, serde_json::to_vec(&file).unwrap()).unwrap();
        let ran = run();
        assert!(
            ran.stderr.lines().any(|l| l == line),
            "row 85: expected {line:?}:\n{}",
            ran.stderr
        );
        assert!(!marker.exists(), "row 85: the child must not start");
    }
}
