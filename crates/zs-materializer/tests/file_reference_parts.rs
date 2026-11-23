#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::Arc;

use zs_credential::Credential;
use zs_grant::{ControlSigningKey, Grant, VerifiedGrant};
use zs_materializer::{
    ExchangeProvider, FileStore, MaterializationError, Materializer, StoreRegistry,
};
use zs_policy::{CredentialSource, Materialization};

struct NoExchange;

#[async_trait::async_trait]
impl ExchangeProvider for NoExchange {
    async fn exchange(&self, _grant: &Grant) -> Result<Credential, MaterializationError> {
        Err(MaterializationError::Exchange("unused".into()))
    }
}

fn verified(reference: &str) -> VerifiedGrant {
    let connection = zs_policy::Connection::default()
        .resolve("api.example.test", "https")
        .unwrap();
    let key = ControlSigningKey::from_bytes("k", &[7; 32]);
    let signed = key
        .sign(Grant {
            subject: "alice@company.com".into(),
            workload: "claude-code".into(),
            resource: "api".into(),
            host: "api.example.test".into(),
            protocol: "https".into(),
            source: CredentialSource::file(reference),
            operations: vec!["GET".into()],
            environment: "development".into(),
            expires_at_ms: u64::MAX,
            grant_id: "g-1".into(),
            materialization: Materialization::Retrieve,
            upstream_host: connection.upstream_host,
            upstream_port: connection.upstream_port,
            upstream_tls: connection.upstream_tls,
            local_endpoint: connection.local_endpoint,
            listen_addr: connection.listen_addr.clone(),
            listen_allow: connection.listen_allow.clone(),
            access: zs_policy::Access::ReadWrite,
            version: zs_grant::GRANT_VERSION,
        })
        .unwrap();
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
            resource: "api",
            operation: "GET",
            environment: None,
        },
    )
    .unwrap()
}

async fn read(root: &Path, reference: &str) -> Result<Vec<u8>, String> {
    let materializer = Materializer::new(
        StoreRegistry::new(Arc::new(FileStore::new(root))),
        Arc::new(NoExchange),
    );
    materializer
        .materialize(&verified(reference), None)
        .await
        .map(|credential| credential.expose().to_vec())
        .map_err(|error| error.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reference_with_a_part_that_is_not_a_plain_name_is_not_resolvable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("a")).unwrap();
    std::fs::write(dir.path().join("a").join("b"), "nested-value").unwrap();
    std::fs::write(dir.path().join("x"), "plain-value").unwrap();

    assert_eq!(
        read(dir.path(), "a/b").await.as_deref(),
        Ok(b"nested-value".as_slice()),
        "positive control: a reference of plain names resolves"
    );
    assert_eq!(
        read(dir.path(), "./x").await,
        Err("materialization denied: credential reference ./x not resolvable".to_string()),
        "negative control: a leading `.` part is refused (SECURITY.md §4 rule 10)"
    );

    let mut resolved = Vec::new();
    for reference in ["a/./b", "a//b", "a/b/", "a/b/."] {
        if read(dir.path(), reference).await.is_ok() {
            resolved.push(reference);
        }
    }
    assert!(
        resolved.is_empty(),
        "SECURITY.md §4 rule 10: a `file` reference resolves only when every part of its path \
         is a plain name, and a `.` part is refused. These references resolved: {resolved:?}"
    );
}
