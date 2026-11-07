#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use zs::{AgentFile, AgentHandler, GrantCache, HttpAuth, ResourceBinding};
use zs_grant::{ControlSigningKey, Grant, SignedGrant};
use zs_policy::{AwsRegion, AwsSsmSource, CredentialSource, RoleArn, SsmParameter};

const SUBJECT: &str = "alice@company.com";
const WORKLOAD: &str = "claude-code";
const RESOURCE: &str = "acme-db";
const HOST: &str = "db.acme.internal";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

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

fn agent(old: SignedGrant, key: &ControlSigningKey) -> AgentHandler {
    let cache = GrantCache::new();
    cache.insert(old);
    AgentHandler::from_grants(
        zs_identity::Subject::new(SUBJECT).unwrap(),
        zs_identity::WorkloadLabel::new(WORKLOAD).unwrap(),
        vec![binding()],
        cache,
        zs_grant::AgentVerifier::new(vec![(
            key.key_id().to_string(),
            ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
        )]),
        Arc::new(zs_materializer::Materializer::new(
            zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(
                "/nonexistent",
            ))),
            Arc::new(NoExchange),
        )),
    )
}

fn binding() -> ResourceBinding {
    ResourceBinding {
        resource: RESOURCE.into(),
        host: HOST.into(),
        protocol: "postgres".into(),
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
        auth: HttpAuth::Bearer,
        source: None,
        loaded_ca: None,
    }
}

fn aws_ssm_source() -> CredentialSource {
    CredentialSource::AwsSsm(AwsSsmSource {
        role_arn: RoleArn::parse("arn:aws:iam::123456789012:role/zs-acme-db").unwrap(),
        region: AwsRegion::parse("ap-southeast-1").unwrap(),
        parameter: SsmParameter::parse("/acme/prod/DB_PASSWORD").unwrap(),
    })
}

fn grant(source: CredentialSource, expires_at_ms: u64) -> Grant {
    Grant {
        subject: SUBJECT.into(),
        workload: WORKLOAD.into(),
        resource: RESOURCE.into(),
        host: HOST.into(),
        protocol: "postgres".into(),
        source,
        operations: vec!["connect".into()],
        environment: "development".into(),
        expires_at_ms,
        grant_id: "g-1".into(),
        materialization: zs_policy::Materialization::Retrieve,
        upstream_host: HOST.into(),
        upstream_port: 5432,
        upstream_tls: zs_policy::UpstreamTlsMode::Default,
        local_endpoint: false,
        version: zs_grant::GRANT_VERSION,
    }
}

fn write_policy(value: serde_json::Value) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    file
}

#[test]
fn a_local_grant_with_a_remote_source_is_refused_at_load() {
    let key = ControlSigningKey::generate("k1");
    let signed = key.sign(grant(aws_ssm_source(), u64::MAX)).unwrap();
    let file = write_policy(serde_json::json!({
        "bindings": [],
        "grants": [signed],
        "signing_keys": [],
    }));
    let error = AgentFile::load(file.path())
        .expect_err("a local grant with an aws_ssm source must be refused")
        .to_string();
    assert_eq!(
        error,
        "policy: acme-db: a local grant may only use a file source"
    );
}

#[test]
fn a_binding_with_a_source_key_is_refused_at_load() {
    let file = write_policy(serde_json::json!({
        "bindings": [{
            "resource": RESOURCE,
            "host": HOST,
            "protocol": "postgres",
            "source": {"kind": "aws_ssm", "role_arn": "arn:aws:iam::123456789012:role/zs-acme-db", "region": "ap-southeast-1", "parameter": "/acme/prod/DB_PASSWORD"},
        }],
        "grants": [],
        "signing_keys": [],
    }));
    let error = AgentFile::load(file.path())
        .expect_err("a binding must not set a source")
        .to_string();
    assert_eq!(
        error,
        "policy: acme-db: source is set only by the control plane"
    );
}

#[test]
fn a_renewal_with_a_changed_source_is_skipped() {
    let key = ControlSigningKey::generate("k1");
    let old = key
        .sign(grant(
            CredentialSource::file("/tmp/old"),
            now_ms().saturating_add(1_000),
        ))
        .unwrap();
    let handler = agent(old, &key);
    let renewed = key
        .sign(grant(aws_ssm_source(), now_ms().saturating_add(300_000)))
        .unwrap();
    assert_eq!(
        handler.accept_renewal(&binding(), renewed),
        Err(zs::connection::Mismatch::Source)
    );
    assert!(
        handler.grant_needs_renewal(RESOURCE, 60_000),
        "the old grant must still be cached after a refused renewal"
    );
}
