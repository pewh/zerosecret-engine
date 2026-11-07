#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use zs::connection::{Mismatch, grant_matches};
use zs::{AgentHandler, GrantCache, ResourceBinding};
use zs_grant::{ControlSigningKey, Grant, SignedGrant};
use zs_mitm::{Flow, FlowHandler};
use zs_protocol::Destination;

mod common;

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

fn grant(expires_at_ms: u64) -> Grant {
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
        expires_at_ms,
        grant_id: "g-test".into(),
        materialization: zs_policy::Materialization::Retrieve,
        upstream_host: connection.upstream_host,
        upstream_port: connection.upstream_port,
        upstream_tls: connection.upstream_tls,
        local_endpoint: connection.local_endpoint,
        version: zs_grant::GRANT_VERSION,
    }
}

fn agent_with(signed: SignedGrant, verifier_key: &ControlSigningKey) -> AgentHandler {
    let bindings = vec![ResourceBinding {
        resource: RESOURCE.to_string(),
        host: HOST.to_string(),
        protocol: "https".to_string(),
        upstream_host: None,
        upstream_port: None,
        upstream_plaintext: false,
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
    }];
    let verifier = zs_grant::AgentVerifier::new(vec![(
        verifier_key.key_id().to_string(),
        ed25519_dalek::VerifyingKey::from_bytes(&verifier_key.verifying_key_bytes()).unwrap(),
    )]);
    let cache = GrantCache::new();
    cache.insert(signed);
    AgentHandler::from_grants(
        zs_identity::Subject::new(SUBJECT).unwrap(),
        zs_identity::WorkloadLabel::new(WORKLOAD).unwrap(),
        bindings,
        cache,
        verifier,
        test_materializer(),
    )
}

fn test_materializer() -> Arc<zs_materializer::Materializer> {
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
        zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(
            "/nonexistent",
        ))),
        Arc::new(NoExchange),
    ))
}

fn denied(flow: &Flow) -> bool {
    matches!(flow, Flow::Deny { .. })
}

#[test]
fn valid_cached_grant_is_intercepted() {
    let key = ControlSigningKey::generate("control-k1");
    let signed = key.sign(grant(now_ms() + 300_000)).unwrap();
    let handler = agent_with(signed, &key);

    let flow = handler.classify(&Destination::new(HOST.to_string(), 443));
    assert!(
        matches!(flow, Flow::Intercept { .. }),
        "a valid cached grant must authorize interception, got {flow:?}"
    );
}

#[test]
fn expired_grant_denies() {
    let key = ControlSigningKey::generate("control-k1");
    let signed = key.sign(grant(now_ms().saturating_sub(1))).unwrap();
    let handler = agent_with(signed, &key);

    let flow = handler.classify(&Destination::new(HOST.to_string(), 443));
    assert!(
        denied(&flow),
        "an expired grant must deny, not fall back to anything, got {flow:?}"
    );
}

#[test]
fn grant_signed_by_an_unpinned_key_denies() {
    let attacker = ControlSigningKey::generate("attacker-k1");
    let real = ControlSigningKey::generate("control-k1");
    let signed = attacker.sign(grant(now_ms() + 300_000)).unwrap();
    let handler = agent_with(signed, &real);

    let flow = handler.classify(&Destination::new(HOST.to_string(), 443));
    assert!(
        denied(&flow),
        "a grant signed by an unpinned key must deny, got {flow:?}"
    );
}

#[test]
fn empty_cache_denies_rather_than_falling_back() {
    let key = ControlSigningKey::generate("control-k1");
    let bindings = vec![ResourceBinding {
        resource: RESOURCE.to_string(),
        host: HOST.to_string(),
        protocol: "https".to_string(),
        upstream_host: None,
        upstream_port: None,
        upstream_plaintext: false,
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
    }];
    let verifier = zs_grant::AgentVerifier::new(vec![(
        key.key_id().to_string(),
        ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
    )]);
    let handler = AgentHandler::from_grants(
        zs_identity::Subject::new(SUBJECT).unwrap(),
        zs_identity::WorkloadLabel::new(WORKLOAD).unwrap(),
        bindings,
        GrantCache::new(),
        verifier,
        test_materializer(),
    );

    let flow = handler.classify(&Destination::new(HOST.to_string(), 443));
    assert!(
        denied(&flow),
        "no grant must deny; there is no local-policy fallback, got {flow:?}"
    );
}

#[test]
fn grant_for_one_resource_does_not_authorize_another() {
    let key = ControlSigningKey::generate("control-k1");
    let signed = key.sign(grant(now_ms() + 300_000)).unwrap();
    let handler = agent_with(signed, &key);

    let flow = handler.classify(&Destination::new("api.github.com".to_string(), 443));
    assert!(
        matches!(flow, Flow::Passthrough),
        "an unknown host is passthrough, not intercept, got {flow:?}"
    );
}

#[test]
fn grant_for_another_subject_denies() {
    let key = ControlSigningKey::generate("control-k1");
    let mut other = grant(now_ms() + 300_000);
    other.subject = "mallory@elsewhere.com".into();
    let handler = agent_with(key.sign(other).unwrap(), &key);

    let flow = handler.classify(&Destination::new(HOST.to_string(), 443));
    assert!(
        denied(&flow),
        "a grant naming a different subject must deny, got {flow:?}"
    );
}

#[test]
fn a_grant_for_another_host_is_refused() {
    let key = ControlSigningKey::generate("control-k1");
    let mut other = grant(now_ms() + 300_000);
    other.host = "evil.example".into();
    let handler = agent_with(key.sign(other).unwrap(), &key);

    let flow = handler.classify(&Destination::new(HOST.to_string(), 443));
    let Flow::Deny { reason } = flow else {
        panic!("a grant naming another host must deny, got {flow:?}");
    };
    assert!(
        reason.contains("binding host does not match the grant"),
        "unexpected reason: {reason}"
    );
    assert!(handler.materialize(HOST, "GET").is_err());
}

#[test]
fn grant_matches_compares_host_and_protocol_ignoring_ascii_case() {
    let key = ControlSigningKey::generate("control-k1");
    let handler_binding = |host: &str, protocol: &str| ResourceBinding {
        resource: RESOURCE.to_string(),
        host: host.to_string(),
        protocol: protocol.to_string(),
        upstream_host: None,
        upstream_port: None,
        upstream_plaintext: false,
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
    };
    let signed = key.sign(grant(now_ms() + 300_000)).unwrap();
    assert_eq!(
        grant_matches(&signed, &handler_binding("API.Stripe.COM", "HTTPS")),
        Ok(())
    );
    for (host, protocol) in [("api.stripe.com", "postgres"), ("evil.example", "https")] {
        assert_eq!(
            grant_matches(&signed, &handler_binding(host, protocol)),
            Err(Mismatch::HostOrProtocol),
            "{host} {protocol}"
        );
    }
}
