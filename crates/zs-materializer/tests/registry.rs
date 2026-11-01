#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use zs_credential::{Credential, IdentityToken};
use zs_grant::{ControlSigningKey, Grant, SignedGrant, VerifiedGrant};
use zs_materializer::{
    CredentialStore, ExchangeProvider, MaterializationError, Materializer, RetrieveContext,
    StoreRegistry,
};
use zs_policy::{
    AwsRegion, AwsSsmSource, CredentialSource, Materialization, RoleArn, SourceKind, SsmParameter,
};

fn aws_ssm_source() -> CredentialSource {
    CredentialSource::AwsSsm(AwsSsmSource {
        role_arn: RoleArn::parse("arn:aws:iam::123456789012:role/zs-acme-db").unwrap(),
        region: AwsRegion::parse("ap-southeast-1").unwrap(),
        parameter: SsmParameter::parse("/acme/prod/DB_PASSWORD").unwrap(),
    })
}

fn grant(source: CredentialSource, mode: Materialization) -> Grant {
    let connection = zs_policy::Connection::default()
        .resolve("db.acme.internal", "postgres")
        .unwrap();
    Grant {
        subject: "alice@company.com".into(),
        workload: "claude-code".into(),
        resource: "acme-db".into(),
        host: "db.acme.internal".into(),
        protocol: "postgres".into(),
        source,
        operations: vec!["connect".into()],
        environment: "development".into(),
        expires_at_ms: u64::MAX,
        grant_id: "g-1".into(),
        materialization: mode,
        upstream_host: connection.upstream_host,
        upstream_port: connection.upstream_port,
        upstream_tls: connection.upstream_tls,
        local_endpoint: connection.local_endpoint,
    }
}

fn verified(source: CredentialSource, mode: Materialization) -> VerifiedGrant {
    let key = ControlSigningKey::from_bytes("k", &[7; 32]);
    let signed: SignedGrant = key.sign(grant(source, mode)).unwrap();
    zs_grant::AgentVerifier::new(vec![(
        key.key_id().to_string(),
        ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
    )])
    .verify(
        &signed,
        0,
        &zs_grant::VerifyContext {
            subject: "alice@company.com",
            workload: "claude-code",
            resource: "acme-db",
            operation: "connect",
        },
    )
    .unwrap()
}

struct RecordingStore {
    kind: SourceKind,
    retrieved: std::sync::Mutex<Vec<String>>,
    forgotten: std::sync::Mutex<Vec<String>>,
}

impl RecordingStore {
    fn new(kind: SourceKind) -> Arc<Self> {
        Arc::new(Self {
            kind,
            retrieved: std::sync::Mutex::new(Vec::new()),
            forgotten: std::sync::Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl CredentialStore for RecordingStore {
    fn kind(&self) -> SourceKind {
        self.kind
    }

    async fn retrieve(&self, cx: &RetrieveContext<'_>) -> Result<Credential, MaterializationError> {
        self.retrieved
            .lock()
            .unwrap()
            .push(cx.grant.grant().source.display_ref());
        Credential::from_bytes(b"value".to_vec())
            .map_err(|e| MaterializationError::File(e.reason().to_string()))
    }

    fn forget(&self, resource: &str) {
        self.forgotten.lock().unwrap().push(resource.to_string());
    }
}

struct RecordingExchange {
    calls: std::sync::Mutex<usize>,
}

impl RecordingExchange {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: std::sync::Mutex::new(0),
        })
    }
}

#[async_trait::async_trait]
impl ExchangeProvider for RecordingExchange {
    async fn exchange(&self, _grant: &Grant) -> Result<Credential, MaterializationError> {
        *self.calls.lock().unwrap() += 1;
        Credential::from_bytes(b"exchanged".to_vec())
            .map_err(|e| MaterializationError::File(e.reason().to_string()))
    }
}

fn file_only(store: Arc<RecordingStore>) -> (Materializer, Arc<RecordingExchange>) {
    let exchange = RecordingExchange::new();
    (
        Materializer::new(StoreRegistry::new(store), exchange.clone()),
        exchange,
    )
}

#[tokio::test]
async fn an_aws_ssm_grant_with_no_store_is_denied_no_store() {
    let file = RecordingStore::new(SourceKind::File);
    let (materializer, _) = file_only(file.clone());
    let error = match materializer
        .materialize(&verified(aws_ssm_source(), Materialization::Retrieve), None)
        .await
    {
        Ok(_) => panic!("a registry without an aws_ssm store must deny"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "materialization failed: no store for aws_ssm"
    );
    assert_eq!(error.diag_code(), "no_store");
}

#[tokio::test]
async fn an_aws_ssm_grant_never_reaches_the_file_store() {
    let file = RecordingStore::new(SourceKind::File);
    let (materializer, _) = file_only(file.clone());
    let _ = materializer
        .materialize(&verified(aws_ssm_source(), Materialization::Retrieve), None)
        .await;
    assert!(
        file.retrieved.lock().unwrap().is_empty(),
        "an aws_ssm grant must never fall back to the file store"
    );
}

#[tokio::test]
async fn a_file_grant_reaches_the_file_store_with_its_reference() {
    let file = RecordingStore::new(SourceKind::File);
    let (materializer, _) = file_only(file.clone());
    let credential = materializer
        .materialize(
            &verified(
                CredentialSource::file("vault:kv/stripe"),
                Materialization::Retrieve,
            ),
            None,
        )
        .await
        .expect("a file grant must materialize");
    assert_eq!(credential.expose(), b"value");
    assert_eq!(
        file.retrieved.lock().unwrap().as_slice(),
        ["file:vault:kv/stripe"]
    );
}

#[tokio::test]
async fn file_errors_keep_their_text() {
    let dir = tempfile::tempdir().unwrap();
    let materializer = Materializer::new(
        StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(dir.path()))),
        RecordingExchange::new(),
    );
    let error = match materializer
        .materialize(
            &verified(CredentialSource::file("missing"), Materialization::Retrieve),
            None,
        )
        .await
    {
        Ok(_) => panic!("a missing file must deny"),
        Err(error) => error,
    };
    assert!(
        error.to_string().starts_with("materialization denied: "),
        "{error}"
    );
}

#[tokio::test]
async fn forget_reaches_every_store() {
    let file = RecordingStore::new(SourceKind::File);
    let aws = RecordingStore::new(SourceKind::AwsSsm);
    let materializer = Materializer::new(
        StoreRegistry::new(file.clone()).with_aws_ssm(aws.clone()),
        RecordingExchange::new(),
    );
    materializer.forget("acme-db");
    assert_eq!(file.forgotten.lock().unwrap().as_slice(), ["acme-db"]);
    assert_eq!(aws.forgotten.lock().unwrap().as_slice(), ["acme-db"]);
}

#[tokio::test]
async fn source_mode_mismatch_is_denied() {
    let file = RecordingStore::new(SourceKind::File);
    let aws = RecordingStore::new(SourceKind::AwsSsm);
    let exchange = RecordingExchange::new();
    let materializer = Materializer::new(
        StoreRegistry::new(file.clone()).with_aws_ssm(aws.clone()),
        exchange.clone(),
    );
    let error = match materializer
        .materialize(&verified(aws_ssm_source(), Materialization::Exchange), None)
        .await
    {
        Ok(_) => panic!("an aws_ssm source labelled exchange must deny"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "materialization failed: source does not match materialization"
    );
    assert_eq!(error.diag_code(), "source_mismatch");
    assert!(aws.retrieved.lock().unwrap().is_empty());
    assert_eq!(*exchange.calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn identity_token_debug_is_redacted() {
    let token = IdentityToken::from_string("header.payload.signature".into());
    assert!(!format!("{token:?}").contains("payload"));
}
