#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use zs::{AgentHandler, GrantCache, HttpAuth, MintedGrant, ResourceBinding};
use zs_credential::{Credential, IdentityToken};
use zs_grant::{ControlSigningKey, Grant, SignedGrant};
use zs_materializer::{CredentialStore, MaterializationError, RetrieveContext};
use zs_mitm::FlowHandler;
use zs_policy::{AwsRegion, AwsSsmSource, CredentialSource, RoleArn, SourceKind, SsmParameter};

const SUBJECT: &str = "alice@company.com";
const WORKLOAD: &str = "claude-code";
const RESOURCE: &str = "acme-db";
const HOST: &str = "db.acme.internal";
const TOKEN_A: &str = "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJnLTEifQ.c2lnbmF0dXJlLWE";
const TOKEN_B: &str = "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJnLTIifQ.c2lnbmF0dXJlLWI";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

struct RecordingStore {
    seen: Mutex<Vec<Option<String>>>,
    refuse: bool,
}

impl RecordingStore {
    fn new(refuse: bool) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            refuse,
        })
    }

    fn seen(&self) -> Vec<Option<String>> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl CredentialStore for RecordingStore {
    fn kind(&self) -> SourceKind {
        SourceKind::AwsSsm
    }

    async fn retrieve(&self, cx: &RetrieveContext<'_>) -> Result<Credential, MaterializationError> {
        self.seen
            .lock()
            .unwrap()
            .push(cx.identity_token.map(|token| token.expose().to_string()));
        if self.refuse {
            return Err(MaterializationError::Refused {
                kind: SourceKind::AwsSsm,
                step: "sts",
                code: "AccessDenied".to_string(),
            });
        }
        Ok(Credential::from_bytes(b"synthetic-ssm-value".to_vec()).unwrap())
    }
}

struct NoExchange;

#[async_trait::async_trait]
impl zs_materializer::ExchangeProvider for NoExchange {
    async fn exchange(&self, _grant: &Grant) -> Result<Credential, MaterializationError> {
        Err(MaterializationError::Exchange("not configured".into()))
    }
}

fn aws_ssm_source() -> CredentialSource {
    CredentialSource::AwsSsm(AwsSsmSource {
        role_arn: RoleArn::parse("arn:aws:iam::123456789012:role/zs-acme-db").unwrap(),
        region: AwsRegion::parse("ap-southeast-1").unwrap(),
        parameter: SsmParameter::parse("/acme/prod/DB_PASSWORD").unwrap(),
    })
}

fn signed(key: &ControlSigningKey, grant_id: &str) -> SignedGrant {
    key.sign(Grant {
        subject: SUBJECT.into(),
        workload: WORKLOAD.into(),
        resource: RESOURCE.into(),
        host: HOST.into(),
        protocol: "postgres".into(),
        source: aws_ssm_source(),
        operations: vec!["connect".into()],
        environment: "development".into(),
        expires_at_ms: now_ms().saturating_add(300_000),
        grant_id: grant_id.into(),
        materialization: zs_policy::Materialization::Retrieve,
        upstream_host: HOST.into(),
        upstream_port: 5432,
        upstream_tls: zs_policy::UpstreamTlsMode::Default,
        local_endpoint: false,
    })
    .unwrap()
}

fn minted(key: &ControlSigningKey, grant_id: &str, token: &str) -> MintedGrant {
    MintedGrant {
        signed: signed(key, grant_id),
        token: Some(IdentityToken::from_string(token.to_string())),
    }
}

fn binding(key: &ControlSigningKey) -> ResourceBinding {
    let mut binding = ResourceBinding {
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
    };
    zs::connection::reconcile(&mut binding, &signed(key, "g-0")).unwrap();
    binding
}

fn agent(key: &ControlSigningKey, first: MintedGrant, store: Arc<RecordingStore>) -> AgentHandler {
    let cache = GrantCache::new();
    cache.insert(first);
    AgentHandler::from_grants(
        zs_identity::Subject::new(SUBJECT).unwrap(),
        zs_identity::WorkloadLabel::new(WORKLOAD).unwrap(),
        vec![binding(key)],
        cache,
        zs_grant::AgentVerifier::new(vec![(
            key.key_id().to_string(),
            ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
        )]),
        Arc::new(zs_materializer::Materializer::new(
            zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(
                "/nonexistent",
            )))
            .with_aws_ssm(store),
            Arc::new(NoExchange),
        )),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn the_identity_token_reaches_the_store_context() {
    let key = ControlSigningKey::generate("k1");
    let store = RecordingStore::new(false);
    let handler = agent(&key, minted(&key, "g-1", TOKEN_A), store.clone());

    let credential = handler
        .materialize(RESOURCE, "connect")
        .unwrap_or_else(|denied| panic!("an aws_ssm grant must materialize: {}", denied.reason));
    assert_eq!(credential.expose(), b"synthetic-ssm-value");
    assert_eq!(store.seen(), vec![Some(TOKEN_A.to_string())]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_without_a_token_reaches_the_store_with_none() {
    let key = ControlSigningKey::generate("k1");
    let store = RecordingStore::new(false);
    let handler = agent(&key, signed(&key, "g-1").into(), store.clone());

    handler
        .materialize(RESOURCE, "connect")
        .unwrap_or_else(|denied| panic!("the recording store must be reached: {}", denied.reason));
    assert_eq!(store.seen(), vec![None]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_renewed_grant_replaces_its_token() {
    let key = ControlSigningKey::generate("k1");
    let store = RecordingStore::new(false);
    let handler = agent(&key, minted(&key, "g-1", TOKEN_A), store.clone());
    handler
        .materialize(RESOURCE, "connect")
        .unwrap_or_else(|denied| panic!("positive control: {}", denied.reason));

    handler
        .accept_renewal(&binding(&key), minted(&key, "g-2", TOKEN_B))
        .unwrap();
    handler
        .materialize(RESOURCE, "connect")
        .unwrap_or_else(|denied| panic!("the renewed grant must materialize: {}", denied.reason));

    assert_eq!(
        store.seen(),
        vec![Some(TOKEN_A.to_string()), Some(TOKEN_B.to_string())]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_token_is_not_in_any_diag_or_audit_line() {
    let key = ControlSigningKey::generate("k1");
    let home = tempfile::tempdir().unwrap();
    let log = home.path().join("diag.jsonl");
    let diag = zs_diag::DiagLog::open_with_cap(&log, "run", 1 << 20).unwrap();
    let store = RecordingStore::new(true);
    let handler = agent(&key, minted(&key, "g-1", TOKEN_A), store.clone()).with_diag(diag.clone());

    let Err(denied) = handler.materialize(RESOURCE, "connect") else {
        panic!("a refusing store must deny");
    };
    assert_eq!(
        store.seen(),
        vec![Some(TOKEN_A.to_string())],
        "positive control: the run must reach the recording store with the token"
    );
    assert_eq!(denied.reason, "materialization failed: aws_ssm refused");

    diag.close();
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(text.contains("materialize_failed"), "{text}");
    let audit_ref = handler.credential_ref(RESOURCE).unwrap();
    assert_eq!(
        audit_ref,
        "aws_ssm:arn:aws:iam::123456789012:role/zs-acme-db:/acme/prod/DB_PASSWORD"
    );
    let audit_reason = denied.audit_reason().to_string();
    let debug = format!("{:?}", minted(&key, "g-1", TOKEN_A));
    for (place, line) in [
        ("diag", text.as_str()),
        ("denial", denied.reason.as_str()),
        ("audit reason", audit_reason.as_str()),
        ("audit credential_ref", audit_ref.as_str()),
        ("debug", debug.as_str()),
    ] {
        for fragment in TOKEN_A.split('.') {
            assert!(
                !line.contains(fragment),
                "the token must not reach the {place}: {line}"
            );
        }
    }
}
