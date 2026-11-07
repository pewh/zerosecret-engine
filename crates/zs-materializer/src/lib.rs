pub mod aws_ssm;
mod cache;

use std::sync::Arc;

pub use cache::GrantBoundCache;
use thiserror::Error;
use zs_credential::{Credential, CredentialRef, IdentityToken};
use zs_grant::{Grant, VerifiedGrant};
use zs_policy::{Materialization, SourceKind};
use zs_upstream::TransportKind;

#[derive(Debug, Error)]
pub enum MaterializationError {
    #[error("materialization denied: {0}")]
    File(String),
    #[error("materialization failed: no store for {}", .0.as_str())]
    NoStore(SourceKind),
    #[error("materialization failed: no identity token")]
    NoIdentityToken,
    #[error("materialization failed: {} refused", .kind.as_str())]
    Refused {
        kind: SourceKind,
        step: &'static str,
        code: String,
    },
    #[error("materialization failed: {} {}", .kind.as_str(), transport_phrase(*.transport))]
    Transport {
        kind: SourceKind,
        step: &'static str,
        transport: TransportKind,
    },
    #[error("materialization failed: session expired")]
    SessionExpired,
    #[error("materialization failed: {} returned an unusable value", .0.as_str())]
    InvalidValue(SourceKind),
    #[error("materialization failed: source does not match materialization")]
    SourceMismatch,
    #[error("exchange failed: {0}")]
    Exchange(String),
}

fn transport_phrase(transport: TransportKind) -> &'static str {
    match transport {
        TransportKind::TimedOut => "timed out",
        TransportKind::Tls => "tls refused",
        TransportKind::Unreachable | TransportKind::Other => "unreachable",
    }
}

impl MaterializationError {
    pub fn diag_code(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::NoStore(_) => "no_store",
            Self::NoIdentityToken => "no_identity_token",
            Self::Refused { .. } => "refused",
            Self::Transport { .. } => "transport",
            Self::SessionExpired => "session_expired",
            Self::InvalidValue(_) => "invalid_value",
            Self::SourceMismatch => "source_mismatch",
            Self::Exchange(_) => "exchange",
        }
    }
}

pub struct RetrieveContext<'a> {
    pub grant: &'a VerifiedGrant,
    pub identity_token: Option<&'a IdentityToken>,
    pub now_ms: u64,
}

#[async_trait::async_trait]
pub trait CredentialStore: Send + Sync {
    fn kind(&self) -> SourceKind;

    async fn retrieve(&self, cx: &RetrieveContext<'_>) -> Result<Credential, MaterializationError>;

    fn forget(&self, _resource: &str) {}
}

#[async_trait::async_trait]
pub trait ExchangeProvider: Send + Sync {
    async fn exchange(&self, grant: &Grant) -> Result<Credential, MaterializationError>;
}

pub struct StoreRegistry {
    file: Arc<dyn CredentialStore>,
    aws_ssm: Option<Arc<dyn CredentialStore>>,
}

impl StoreRegistry {
    pub fn new(file: Arc<dyn CredentialStore>) -> Self {
        Self {
            file,
            aws_ssm: None,
        }
    }

    pub fn with_aws_ssm(mut self, store: Arc<dyn CredentialStore>) -> Self {
        self.aws_ssm = Some(store);
        self
    }

    fn route(&self, kind: SourceKind) -> Result<&Arc<dyn CredentialStore>, MaterializationError> {
        match kind {
            SourceKind::File => Ok(&self.file),
            SourceKind::AwsSsm => self
                .aws_ssm
                .as_ref()
                .ok_or(MaterializationError::NoStore(SourceKind::AwsSsm)),
        }
    }

    fn forget(&self, resource: &str) {
        self.file.forget(resource);
        if let Some(store) = &self.aws_ssm {
            store.forget(resource);
        }
    }
}

pub struct FileStore {
    root: std::path::PathBuf,
}

impl FileStore {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn read(&self, reference: &str) -> Result<Credential, MaterializationError> {
        let reference = CredentialRef::new(reference)
            .map_err(|e| MaterializationError::File(e.reason().to_string()))?;
        let relative = reference
            .as_str()
            .trim_start_matches('/')
            .replace("..", "__");
        let unresolvable = || {
            MaterializationError::File(format!("credential reference {reference} not resolvable"))
        };
        if !std::path::Path::new(&relative)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
        {
            return Err(unresolvable());
        }
        let path = self.root.join(relative);
        let value = std::fs::read(&path).map_err(|_| unresolvable())?;
        let trimmed: Vec<u8> = value
            .into_iter()
            .take_while(|b| *b != b'\n' && *b != b'\r')
            .collect();
        Credential::from_bytes(trimmed)
            .map_err(|e| MaterializationError::File(e.reason().to_string()))
    }
}

#[async_trait::async_trait]
impl CredentialStore for FileStore {
    fn kind(&self) -> SourceKind {
        SourceKind::File
    }

    async fn retrieve(&self, cx: &RetrieveContext<'_>) -> Result<Credential, MaterializationError> {
        match &cx.grant.grant().source {
            zs_policy::CredentialSource::File { reference } => self.read(reference),
            zs_policy::CredentialSource::AwsSsm(_) => Err(MaterializationError::SourceMismatch),
        }
    }
}

pub struct Materializer {
    stores: StoreRegistry,
    exchange: Arc<dyn ExchangeProvider>,
}

impl Materializer {
    pub fn new(stores: StoreRegistry, exchange: Arc<dyn ExchangeProvider>) -> Self {
        Self { stores, exchange }
    }

    pub async fn materialize(
        &self,
        grant: &VerifiedGrant,
        token: Option<&IdentityToken>,
    ) -> Result<Credential, MaterializationError> {
        let signed = grant.grant();
        let source = &signed.source;
        if source
            .mode()
            .is_some_and(|mode| mode != signed.materialization)
        {
            return Err(MaterializationError::SourceMismatch);
        }
        match signed.materialization {
            Materialization::Retrieve => {
                let store = self.stores.route(source.kind())?;
                let cx = RetrieveContext {
                    grant,
                    identity_token: token,
                    now_ms: now_ms(),
                };
                store.retrieve(&cx).await
            }
            Materialization::Exchange => self.exchange.exchange(signed).await,
        }
    }

    pub fn forget(&self, resource: &str) {
        self.stores.forget(resource);
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn signed(reference: &str) -> zs_grant::SignedGrant {
        let control = zs_grant::ControlSigningKey::from_bytes("k", &[7; 32]);
        let connection = zs_policy::Connection::default()
            .resolve("api.stripe.com", "https")
            .unwrap();
        control
            .sign(Grant {
                subject: "a".into(),
                workload: "w".into(),
                resource: "stripe".into(),
                host: "api.stripe.com".into(),
                protocol: "https".into(),
                source: zs_policy::CredentialSource::file(reference),
                operations: vec!["GET".into()],
                environment: "dev".into(),
                expires_at_ms: u64::MAX,
                grant_id: "g".into(),
                materialization: Materialization::Retrieve,
                upstream_host: connection.upstream_host,
                upstream_port: connection.upstream_port,
                upstream_tls: connection.upstream_tls,
                local_endpoint: connection.local_endpoint,
                version: zs_grant::GRANT_VERSION,
            })
            .unwrap()
    }

    fn verify(signed: &zs_grant::SignedGrant) -> VerifiedGrant {
        let key = zs_grant::ControlSigningKey::from_bytes("k", &[7; 32]);
        let verifier = zs_grant::AgentVerifier::new(vec![(
            key.key_id().to_string(),
            ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
        )]);
        verifier
            .verify(
                signed,
                0,
                &zs_grant::VerifyContext {
                    subject: "a",
                    workload: "w",
                    resource: "stripe",
                    operation: "GET",
                    environment: None,
                },
            )
            .unwrap()
    }

    #[test]
    fn retrieve_via_file_store() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stripe"), "sk_test_value").unwrap();
        let store = FileStore::new(dir.path());
        let credential = store.read("stripe").unwrap();
        assert_eq!(credential.expose(), b"sk_test_value");
    }

    #[test]
    fn a_trailing_newline_is_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stripe-prod"), "sk_test_abc123\n").unwrap();
        let store = FileStore::new(dir.path());
        let credential = store.read("stripe-prod").unwrap();
        assert_eq!(credential.expose(), b"sk_test_abc123");
    }

    #[test]
    fn missing_reference_denied() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(dir.path());
        let error = match store.read("nope") {
            Ok(_) => panic!("expected a denial"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "materialization denied: credential reference nope not resolvable"
        );
    }

    #[test]
    fn a_reference_outside_the_reference_alphabet_is_denied_before_the_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a b"), "spaced").unwrap();
        let store = FileStore::new(dir.path());
        for reference in ["", "a b", "..\\secret", "C:\\secret"] {
            let error = match store.read(reference) {
                Ok(_) => panic!("{reference:?} must be denied"),
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                "materialization denied: invalid credential reference",
                "{reference:?}"
            );
        }
    }

    #[test]
    fn a_reference_with_a_prefix_or_root_component_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        std::fs::write(dir.path().join("a").join("b"), "nested").unwrap();
        std::fs::write(dir.path().join("x"), "plain").unwrap();
        let store = FileStore::new(dir.path());
        assert_eq!(store.read("a/b").unwrap().expose(), b"nested");

        let mut refused = vec!["./x", "."];
        if cfg!(windows) {
            refused.extend(["C:/x", "C:x"]);
        }
        for reference in refused {
            let error = match store.read(reference) {
                Ok(_) => panic!("{reference:?} must be refused"),
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                format!("materialization denied: credential reference {reference} not resolvable"),
                "{reference:?}"
            );
        }
    }

    #[test]
    fn a_leading_slash_and_parent_segments_follow_the_file_rules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("__")).unwrap();
        std::fs::write(dir.path().join("__").join("secret"), "flattened").unwrap();
        let store = FileStore::new(dir.path());
        for reference in ["/../secret", "../secret"] {
            let credential = store.read(reference).unwrap();
            assert_eq!(credential.expose(), b"flattened", "{reference}");
        }
    }

    #[tokio::test]
    async fn the_materializer_reads_a_retrieve_grant_from_the_file_store() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stripe"), "sk_test_value").unwrap();
        let materializer = Materializer::new(
            StoreRegistry::new(Arc::new(FileStore::new(dir.path()))),
            Arc::new(UnusedExchange),
        );
        let signed = signed("stripe");
        let verified = verify(&signed);
        let credential = materializer.materialize(&verified, None).await.unwrap();
        assert_eq!(credential.expose(), b"sk_test_value");
    }

    struct UnusedExchange;

    #[async_trait::async_trait]
    impl ExchangeProvider for UnusedExchange {
        async fn exchange(&self, _grant: &Grant) -> Result<Credential, MaterializationError> {
            Err(MaterializationError::Exchange("unused".into()))
        }
    }
}
