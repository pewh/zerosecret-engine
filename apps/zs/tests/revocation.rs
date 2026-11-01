// Test code: `unwrap`/`expect` are assertions; a failed setup should abort the test loudly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

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
