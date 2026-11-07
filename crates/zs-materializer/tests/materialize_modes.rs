#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zs_grant::{ControlSigningKey, Grant, SignedGrant, VerifiedGrant};
use zs_materializer::{
    CredentialStore, ExchangeProvider, MaterializationError, Materializer, RetrieveContext,
    StoreRegistry,
};
use zs_policy::{CredentialSource, Materialization, SourceKind};

fn signed(mode: Materialization, credential_ref: &str) -> SignedGrant {
    let connection = zs_policy::Connection::default()
        .resolve("api.stripe.com", "https")
        .unwrap();
    ControlSigningKey::from_bytes("k", &[7; 32])
        .sign(Grant {
            subject: "alice@company.com".into(),
            workload: "claude-code".into(),
            resource: "stripe-production".into(),
            host: "api.stripe.com".into(),
            protocol: "https".into(),
            source: CredentialSource::file(credential_ref),
            operations: vec!["GET".into()],
            environment: "development".into(),
            expires_at_ms: u64::MAX,
            grant_id: "g-1".into(),
            materialization: mode,
            upstream_host: connection.upstream_host,
            upstream_port: connection.upstream_port,
            upstream_tls: connection.upstream_tls,
            local_endpoint: connection.local_endpoint,
            version: zs_grant::GRANT_VERSION,
        })
        .unwrap()
}

fn verified(signed: &SignedGrant) -> VerifiedGrant {
    let key = ControlSigningKey::from_bytes("k", &[7; 32]);
    zs_grant::AgentVerifier::new(vec![(
        key.key_id().to_string(),
        ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
    )])
    .verify(
        signed,
        0,
        &zs_grant::VerifyContext {
            subject: "alice@company.com",
            workload: "claude-code",
            resource: "stripe-production",
            operation: "GET",
            environment: None,
        },
    )
    .unwrap()
}

struct RecordingStore {
    calls: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl CredentialStore for RecordingStore {
    fn kind(&self) -> SourceKind {
        SourceKind::File
    }

    async fn retrieve(
        &self,
        cx: &RetrieveContext<'_>,
    ) -> Result<zs_credential::Credential, MaterializationError> {
        self.calls
            .lock()
            .unwrap()
            .push(cx.grant.grant().source.display_ref());
        zs_credential::Credential::from_bytes(b"retrieved-value".to_vec())
            .map_err(|e| MaterializationError::File(e.reason().to_string()))
    }
}

struct RecordingExchange {
    calls: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ExchangeProvider for RecordingExchange {
    async fn exchange(
        &self,
        grant: &Grant,
    ) -> Result<zs_credential::Credential, MaterializationError> {
        self.calls.lock().unwrap().push(grant.grant_id.clone());
        zs_credential::Credential::from_bytes(b"exchanged-value".to_vec())
            .map_err(|e| MaterializationError::File(e.reason().to_string()))
    }
}

fn materializer() -> (
    Materializer,
    std::sync::Arc<RecordingStore>,
    std::sync::Arc<RecordingExchange>,
) {
    let store = std::sync::Arc::new(RecordingStore {
        calls: std::sync::Mutex::new(Vec::new()),
    });
    let exchange = std::sync::Arc::new(RecordingExchange {
        calls: std::sync::Mutex::new(Vec::new()),
    });
    (
        Materializer::new(StoreRegistry::new(store.clone()), exchange.clone()),
        store,
        exchange,
    )
}

#[tokio::test]
async fn retrieve_grant_uses_the_store() {
    let (materializer, store, exchange) = materializer();
    let signed = signed(Materialization::Retrieve, "vault:kv/stripe");
    let credential = materializer
        .materialize(&verified(&signed), None)
        .await
        .expect("a retrieve grant must materialize from the store");

    assert_eq!(credential.expose(), b"retrieved-value");
    assert_eq!(store.calls.lock().unwrap().len(), 1);
    assert_eq!(
        store.calls.lock().unwrap().as_slice(),
        ["file:vault:kv/stripe"]
    );
    assert!(
        exchange.calls.lock().unwrap().is_empty(),
        "a retrieve grant must not reach the exchange provider"
    );
}

#[tokio::test]
async fn exchange_grant_uses_the_exchange_provider() {
    let (materializer, store, exchange) = materializer();
    let signed = signed(Materialization::Exchange, "aws:role/deploy");
    let credential = materializer
        .materialize(&verified(&signed), None)
        .await
        .expect("an exchange grant must materialize by exchange");

    assert_eq!(credential.expose(), b"exchanged-value");
    assert_eq!(exchange.calls.lock().unwrap().len(), 1);
    assert!(
        store.calls.lock().unwrap().is_empty(),
        "an exchange grant must not fall back to retrieving a stored credential"
    );
}
