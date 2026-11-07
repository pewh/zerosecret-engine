use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zs_policy::CredentialSource;

pub const GRANT_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum GrantError {
    #[error("grant signature invalid")]
    SignatureInvalid,
    #[error("grant expired")]
    Expired,
    #[error("grant malformed: {0}")]
    Malformed(String),
    #[error("grant is for subject {expected}, presented for {actual}")]
    SubjectMismatch { expected: String, actual: String },
    #[error("grant is for workload {expected}, presented for {actual}")]
    WorkloadMismatch { expected: String, actual: String },
    #[error("grant is for resource {expected}, presented for {actual}")]
    ResourceMismatch { expected: String, actual: String },
    #[error("grant does not permit the requested operation")]
    OperationNotGranted { operation: String },
    #[error("grant field {field} has a reserved separator")]
    Unsignable { field: &'static str },
    #[error("grant version not supported by this zs; upgrade zs")]
    UnsupportedVersion,
    #[error("grant is for another environment")]
    EnvironmentMismatch,
}

#[derive(Debug, Clone)]
pub struct VerifyContext<'a> {
    pub subject: &'a str,
    pub workload: &'a str,
    pub resource: &'a str,
    pub operation: &'a str,
    pub environment: Option<&'a str>,
}

pub fn canonical_payload(grant: &Grant) -> Vec<u8> {
    let mut out = String::new();
    let mut field = |key: &str, value: &str| {
        out.push_str(key);
        out.push('\u{1f}');
        out.push_str(value);
        out.push('\u{1e}');
    };
    if let CredentialSource::File { reference } = &grant.source {
        field("credential_ref", reference);
    }
    field("environment", &grant.environment);
    field("expires_at_ms", &grant.expires_at_ms.to_string());
    field("grant_id", &grant.grant_id);
    field("host", &grant.host);
    field(
        "local_endpoint",
        if grant.local_endpoint {
            "true"
        } else {
            "false"
        },
    );
    field(
        "materialization",
        match grant.materialization {
            zs_policy::Materialization::Retrieve => "retrieve",
            zs_policy::Materialization::Exchange => "exchange",
        },
    );
    let mut operations = grant.operations.clone();
    operations.sort();
    field("operations", &operations.join("\u{1d}"));
    field("protocol", &grant.protocol);
    field("resource", &grant.resource);
    if let CredentialSource::AwsSsm(source) = &grant.source {
        field("source.kind", zs_policy::SourceKind::AwsSsm.as_str());
        field("source.parameter", source.parameter.as_str());
        field("source.region", source.region.as_str());
        field("source.role_arn", source.role_arn.as_str());
    }
    field("subject", &grant.subject);
    field("upstream_host", &grant.upstream_host);
    field("upstream_port", &grant.upstream_port.to_string());
    field("upstream_tls", &grant.upstream_tls.to_string());
    if grant.version > GRANT_VERSION {
        field("version", &grant.version.to_string());
    }
    field("workload", &grant.workload);
    out.into_bytes()
}

const FORBIDDEN_ANYWHERE: [char; 2] = ['\u{1e}', '\u{1f}'];
const FORBIDDEN_IN_OPERATIONS: [char; 3] = ['\u{1d}', '\u{1e}', '\u{1f}'];

fn reject_separators(grant: &Grant) -> Result<(), GrantError> {
    let mut strings: Vec<(&'static str, &str)> = vec![
        ("environment", &grant.environment),
        ("grant_id", &grant.grant_id),
        ("host", &grant.host),
        ("protocol", &grant.protocol),
        ("resource", &grant.resource),
        ("subject", &grant.subject),
        ("upstream_host", &grant.upstream_host),
        ("workload", &grant.workload),
    ];
    if let CredentialSource::File { reference } = &grant.source {
        strings.push(("credential_ref", reference));
    }
    for (field, value) in strings {
        if value.contains(FORBIDDEN_ANYWHERE) {
            return Err(GrantError::Unsignable { field });
        }
    }
    if grant
        .operations
        .iter()
        .any(|operation| operation.contains(FORBIDDEN_IN_OPERATIONS))
    {
        return Err(GrantError::Unsignable {
            field: "operations",
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "GrantWire", into = "GrantWire")]
pub struct Grant {
    pub subject: String,
    pub workload: String,
    pub resource: String,
    pub host: String,
    pub protocol: String,
    pub source: CredentialSource,
    pub operations: Vec<String>,
    pub environment: String,
    pub expires_at_ms: u64,
    pub grant_id: String,
    // Signed, never chosen locally: agent config must not turn an exchange into a retrieve.
    #[serde(default)]
    pub materialization: zs_policy::Materialization,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub upstream_tls: zs_policy::UpstreamTlsMode,
    pub local_endpoint: bool,
    pub version: u32,
}

#[derive(Serialize, Deserialize)]
struct GrantWire {
    subject: String,
    workload: String,
    resource: String,
    host: String,
    protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<CredentialSource>,
    operations: Vec<String>,
    environment: String,
    expires_at_ms: u64,
    grant_id: String,
    #[serde(default)]
    materialization: zs_policy::Materialization,
    upstream_host: String,
    upstream_port: u16,
    upstream_tls: zs_policy::UpstreamTlsMode,
    #[serde(
        default = "default_grant_version",
        skip_serializing_if = "version_is_one"
    )]
    version: u32,
    local_endpoint: bool,
}

fn default_grant_version() -> u32 {
    GRANT_VERSION
}

fn version_is_one(version: &u32) -> bool {
    *version == GRANT_VERSION
}

impl From<Grant> for GrantWire {
    fn from(grant: Grant) -> Self {
        let (credential_ref, source) = match grant.source {
            CredentialSource::File { reference } => (Some(reference), None),
            other => (None, Some(other)),
        };
        Self {
            subject: grant.subject,
            workload: grant.workload,
            resource: grant.resource,
            host: grant.host,
            protocol: grant.protocol,
            credential_ref,
            source,
            operations: grant.operations,
            environment: grant.environment,
            expires_at_ms: grant.expires_at_ms,
            grant_id: grant.grant_id,
            materialization: grant.materialization,
            upstream_host: grant.upstream_host,
            upstream_port: grant.upstream_port,
            upstream_tls: grant.upstream_tls,
            version: grant.version,
            local_endpoint: grant.local_endpoint,
        }
    }
}

impl TryFrom<GrantWire> for Grant {
    type Error = GrantError;

    fn try_from(wire: GrantWire) -> Result<Self, GrantError> {
        let source = match (wire.credential_ref, wire.source) {
            (Some(reference), None) => CredentialSource::File { reference },
            (None, Some(source)) => source,
            _ => {
                return Err(GrantError::Malformed(
                    "grant must name exactly one credential source".into(),
                ));
            }
        };
        Ok(Self {
            subject: wire.subject,
            workload: wire.workload,
            resource: wire.resource,
            host: wire.host,
            protocol: wire.protocol,
            source,
            operations: wire.operations,
            environment: wire.environment,
            expires_at_ms: wire.expires_at_ms,
            grant_id: wire.grant_id,
            materialization: wire.materialization,
            upstream_host: wire.upstream_host,
            upstream_port: wire.upstream_port,
            upstream_tls: wire.upstream_tls,
            version: if wire.version == 0 {
                GRANT_VERSION
            } else {
                wire.version
            },
            local_endpoint: wire.local_endpoint,
        })
    }
}

impl Grant {
    pub fn connection(&self) -> zs_policy::ResolvedConnection {
        zs_policy::ResolvedConnection {
            upstream_host: self.upstream_host.clone(),
            upstream_port: self.upstream_port,
            upstream_tls: self.upstream_tls,
            local_endpoint: self.local_endpoint,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedGrant {
    pub grant: Grant,
    pub signature: String,
    pub signing_key_id: String,
}

pub struct ControlSigningKey {
    key: SigningKey,
    key_id: String,
}

impl ControlSigningKey {
    pub fn generate(key_id: impl Into<String>) -> Self {
        let mut secret = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut secret);
        Self {
            key: SigningKey::from_bytes(&secret),
            key_id: key_id.into(),
        }
    }

    pub fn from_bytes(key_id: impl Into<String>, bytes: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(bytes),
            key_id: key_id.into(),
        }
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn sign(&self, grant: Grant) -> Result<SignedGrant, GrantError> {
        reject_separators(&grant)?;
        let payload = canonical_payload(&grant);
        let signature = self.key.sign(&payload);
        Ok(SignedGrant {
            grant,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            signing_key_id: self.key_id.clone(),
        })
    }
}

#[derive(Clone)]
pub struct AgentVerifier {
    keys: std::sync::Arc<std::sync::RwLock<Vec<(String, VerifyingKey)>>>,
}

impl AgentVerifier {
    pub fn keys(&self) -> Vec<(String, VerifyingKey)> {
        self.keys
            .read()
            .map(|keys| keys.clone())
            .unwrap_or_default()
    }

    pub fn new(keys: Vec<(String, VerifyingKey)>) -> Self {
        Self {
            keys: std::sync::Arc::new(std::sync::RwLock::new(keys)),
        }
    }

    // An empty set is ignored so an old control plane never empties the ring.
    pub fn replace(&self, keys: Vec<(String, VerifyingKey)>) {
        if keys.is_empty() {
            return;
        }
        if let Ok(mut current) = self.keys.write() {
            *current = keys;
        }
    }

    pub fn verify(
        &self,
        signed: &SignedGrant,
        now_ms: u64,
        context: &VerifyContext<'_>,
    ) -> Result<VerifiedGrant, GrantError> {
        let key = self
            .keys()
            .into_iter()
            .find(|(id, _)| *id == signed.signing_key_id)
            .map(|(_, k)| k)
            .ok_or(GrantError::SignatureInvalid)?;
        let payload = canonical_payload(&signed.grant);
        let bytes: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(&signed.signature)
            .map_err(|_| GrantError::SignatureInvalid)?
            .try_into()
            .map_err(|_| GrantError::SignatureInvalid)?;
        let signature = Signature::from_bytes(&bytes);
        key.verify(&payload, &signature)
            .map_err(|_| GrantError::SignatureInvalid)?;
        if signed.grant.version != GRANT_VERSION {
            return Err(GrantError::UnsupportedVersion);
        }
        if let Some(environment) = context.environment
            && signed.grant.environment != environment
        {
            return Err(GrantError::EnvironmentMismatch);
        }
        if signed.grant.expires_at_ms <= now_ms {
            return Err(GrantError::Expired);
        }
        if signed.grant.subject != context.subject {
            return Err(GrantError::SubjectMismatch {
                expected: signed.grant.subject.clone(),
                actual: context.subject.to_string(),
            });
        }
        if signed.grant.workload != context.workload {
            return Err(GrantError::WorkloadMismatch {
                expected: signed.grant.workload.clone(),
                actual: context.workload.to_string(),
            });
        }
        if signed.grant.resource != context.resource {
            return Err(GrantError::ResourceMismatch {
                expected: signed.grant.resource.clone(),
                actual: context.resource.to_string(),
            });
        }
        if !zs_policy::permits(&signed.grant.operations, context.operation) {
            return Err(GrantError::OperationNotGranted {
                operation: context.operation.to_string(),
            });
        }
        Ok(VerifiedGrant {
            signed: signed.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedGrant {
    signed: SignedGrant,
}

impl VerifiedGrant {
    pub fn grant(&self) -> &Grant {
        &self.signed.grant
    }

    pub fn signed(&self) -> &SignedGrant {
        &self.signed
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    type FieldSetter = fn(&mut Grant) -> &mut String;

    fn file_source(reference: &str) -> CredentialSource {
        CredentialSource::file(reference)
    }

    fn grant(expires_in_ms: i64) -> Grant {
        Grant {
            subject: "alice@company.com".into(),
            workload: "claude-code".into(),
            resource: "stripe-production".into(),
            host: "api.stripe.com".into(),
            protocol: "https".into(),
            source: CredentialSource::file("vault:kv/stripe"),
            operations: vec!["GET".into()],
            environment: "development".into(),
            expires_at_ms: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
                + expires_in_ms) as u64,
            grant_id: "g-1".into(),
            materialization: zs_policy::Materialization::Retrieve,
            upstream_host: "api.stripe.com".into(),
            upstream_port: 443,
            upstream_tls: zs_policy::UpstreamTlsMode::Default,
            local_endpoint: false,
            version: GRANT_VERSION,
        }
    }

    fn ctx<'a>(resource: &'a str, operation: &'a str) -> VerifyContext<'a> {
        VerifyContext {
            subject: "alice@company.com",
            workload: "claude-code",
            resource,
            operation,
            environment: None,
        }
    }

    fn verifier_for(control: &ControlSigningKey) -> AgentVerifier {
        AgentVerifier::new(vec![(
            "k1".into(),
            VerifyingKey::from_bytes(&control.verifying_key_bytes()).unwrap(),
        )])
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn tampering_with_host_invalidates_the_signature() {
        let control = ControlSigningKey::generate("k1");
        let mut signed = control.sign(grant(60_000)).unwrap();
        signed.grant.host = "evil.example".into();
        assert!(matches!(
            verifier_for(&control).verify(&signed, now_ms(), &ctx("stripe-production", "GET")),
            Err(GrantError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_grant_without_host_does_not_parse() {
        let mut value = serde_json::to_value(grant(60_000)).unwrap();
        value.as_object_mut().unwrap().remove("host");
        assert!(serde_json::from_value::<Grant>(value).is_err());
    }

    #[test]
    fn each_connection_field_is_signed() {
        let control = ControlSigningKey::generate("k1");
        let signed = control.sign(grant(60_000)).unwrap();
        let verifier = verifier_for(&control);
        let context = ctx("stripe-production", "GET");
        assert!(verifier.verify(&signed, now_ms(), &context).is_ok());

        let mut host = signed.clone();
        host.grant.upstream_host = "evil.example".into();
        let mut port = signed.clone();
        port.grant.upstream_port = 8443;
        let mut tls = signed.clone();
        tls.grant.upstream_tls = zs_policy::UpstreamTlsMode::Plaintext;
        let mut pinned = signed.clone();
        pinned.grant.upstream_tls = zs_policy::UpstreamTlsMode::PinSha256([7u8; 32]);
        let mut local = signed.clone();
        local.grant.local_endpoint = true;
        for changed in [host, port, tls, pinned, local] {
            assert!(matches!(
                verifier.verify(&changed, now_ms(), &context),
                Err(GrantError::SignatureInvalid)
            ));
        }
    }

    #[test]
    fn a_grant_without_connection_fields_does_not_parse() {
        let adr_0037_only = r#"{"subject":"alice@company.com","workload":"claude-code","resource":"stripe-production","host":"api.stripe.com","protocol":"https","credential_ref":"vault:kv/stripe","operations":["GET"],"environment":"development","expires_at_ms":1,"grant_id":"g-1","materialization":"retrieve"}"#;
        assert!(serde_json::from_str::<Grant>(adr_0037_only).is_err());
        let mut full = serde_json::from_str::<serde_json::Value>(adr_0037_only).unwrap();
        let object = full.as_object_mut().unwrap();
        object.insert("upstream_host".into(), "api.stripe.com".into());
        object.insert("upstream_port".into(), 443.into());
        object.insert("upstream_tls".into(), "default".into());
        object.insert("local_endpoint".into(), false.into());
        assert!(serde_json::from_value::<Grant>(full.clone()).is_ok());
        for key in [
            "upstream_host",
            "upstream_port",
            "upstream_tls",
            "local_endpoint",
        ] {
            let mut missing = full.clone();
            missing.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<Grant>(missing).is_err(), "{key}");
        }
    }

    #[test]
    fn canonical_keys_are_alphabetical() {
        let payload = String::from_utf8(canonical_payload(&grant(60_000))).unwrap();
        let keys: Vec<&str> = payload
            .split('\u{1e}')
            .filter(|record| !record.is_empty())
            .map(|record| record.split('\u{1f}').next().unwrap())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
        for key in [
            "local_endpoint",
            "upstream_host",
            "upstream_port",
            "upstream_tls",
        ] {
            assert!(keys.contains(&key), "{key}");
        }
    }

    #[test]
    fn the_connection_is_the_resolved_grant_fields() {
        let mut g = grant(60_000);
        g.upstream_port = 3307;
        g.local_endpoint = true;
        let resolved = g.connection();
        assert_eq!(resolved.upstream_host, "api.stripe.com");
        assert_eq!(resolved.upstream_port, 3307);
        assert_eq!(resolved.upstream_tls, zs_policy::UpstreamTlsMode::Default);
        assert!(resolved.local_endpoint);
    }

    #[test]
    fn a_grant_for_one_resource_is_rejected_for_another() {
        let control = ControlSigningKey::generate("k1");
        let signed = control.sign(grant(60_000)).unwrap();
        let err = verifier_for(&control)
            .verify(&signed, now_ms(), &ctx("github", "GET"))
            .unwrap_err();
        assert!(
            matches!(err, GrantError::ResourceMismatch { .. }),
            "expected ResourceMismatch, got {err:?}"
        );
    }

    #[test]
    fn an_operation_outside_the_grant_is_rejected() {
        let control = ControlSigningKey::generate("k1");
        let signed = control.sign(grant(60_000)).unwrap();
        let err = verifier_for(&control)
            .verify(&signed, now_ms(), &ctx("stripe-production", "DELETE"))
            .unwrap_err();
        assert!(
            matches!(err, GrantError::OperationNotGranted { .. }),
            "expected OperationNotGranted, got {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "grant does not permit the requested operation"
        );
    }

    #[test]
    fn an_any_method_grant_permits_every_method_but_connect() {
        let control = ControlSigningKey::generate("k1");
        let mut any = grant(60_000);
        any.operations = vec!["*".into()];
        let signed = control.sign(any).unwrap();
        let verifier = verifier_for(&control);
        for method in ["GET", "POST", "DELETE", "PATCH"] {
            assert!(
                verifier
                    .verify(&signed, now_ms(), &ctx("stripe-production", method))
                    .is_ok()
            );
        }
        assert!(matches!(
            verifier.verify(&signed, now_ms(), &ctx("stripe-production", "connect")),
            Err(GrantError::OperationNotGranted { .. })
        ));
    }

    #[test]
    fn mismatches_are_distinguishable_from_a_bad_signature() {
        let control = ControlSigningKey::generate("k1");
        let signed = control.sign(grant(60_000)).unwrap();
        let verifier = verifier_for(&control);
        let wrong_subject = VerifyContext {
            subject: "bob@company.com",
            workload: "claude-code",
            resource: "stripe-production",
            operation: "GET",
            environment: None,
        };
        assert!(matches!(
            verifier.verify(&signed, now_ms(), &wrong_subject),
            Err(GrantError::SubjectMismatch { .. })
        ));
        let wrong_workload = VerifyContext {
            subject: "alice@company.com",
            workload: "other-agent",
            resource: "stripe-production",
            operation: "GET",
            environment: None,
        };
        assert!(matches!(
            verifier.verify(&signed, now_ms(), &wrong_workload),
            Err(GrantError::WorkloadMismatch { .. })
        ));
    }

    #[test]
    fn signing_payload_is_canonical_across_operation_order() {
        let control = ControlSigningKey::generate("k1");
        let mut a = grant(60_000);
        a.operations = vec!["GET".into(), "POST".into()];
        let mut b = a.clone();
        b.operations = vec!["POST".into(), "GET".into()];
        assert_eq!(
            control.sign(a).unwrap().signature,
            control.sign(b).unwrap().signature,
            "two semantically identical grants must produce the same signature"
        );
    }

    #[test]
    fn signing_payload_distinguishes_field_boundaries() {
        let control = ControlSigningKey::generate("k1");
        let mut a = grant(60_000);
        a.subject = "alice".into();
        a.workload = "bob".into();
        let mut b = grant(60_000);
        b.subject = "alicebob".into();
        b.workload = String::new();
        assert_ne!(
            control.sign(a).unwrap().signature,
            control.sign(b).unwrap().signature,
            "field concatenation must not be ambiguous across boundaries"
        );
    }

    #[test]
    fn round_trip_sign_and_verify() {
        let control = ControlSigningKey::generate("k1");
        let signed = control.sign(grant(60_000)).unwrap();
        let verifier = AgentVerifier::new(vec![(
            "k1".into(),
            VerifyingKey::from_bytes(&control.verifying_key_bytes()).unwrap(),
        )]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(
            verifier
                .verify(&signed, now, &ctx("stripe-production", "GET"))
                .is_ok()
        );
    }

    #[test]
    fn tampered_grant_fails_signature() {
        let control = ControlSigningKey::generate("k1");
        let mut signed = control.sign(grant(60_000)).unwrap();
        signed.grant.operations = vec!["DELETE".into()];
        let verifier = AgentVerifier::new(vec![(
            "k1".into(),
            VerifyingKey::from_bytes(&control.verifying_key_bytes()).unwrap(),
        )]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(matches!(
            verifier.verify(&signed, now, &ctx("stripe-production", "GET")),
            Err(GrantError::SignatureInvalid)
        ));
    }

    #[test]
    fn expired_grant_denied() {
        let control = ControlSigningKey::generate("k1");
        let signed = control.sign(grant(-1_000)).unwrap();
        let verifier = AgentVerifier::new(vec![(
            "k1".into(),
            VerifyingKey::from_bytes(&control.verifying_key_bytes()).unwrap(),
        )]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        assert!(matches!(
            verifier.verify(&signed, now, &ctx("stripe-production", "GET")),
            Err(GrantError::Expired)
        ));
    }

    #[test]
    fn tampering_with_materialization_invalidates_the_signature() {
        let key = ControlSigningKey::generate("k1");
        let mut signed = key.sign(grant(60_000)).unwrap();
        assert_eq!(
            signed.grant.materialization,
            zs_policy::Materialization::Retrieve
        );

        let verifier = AgentVerifier::new(vec![(
            key.key_id().to_string(),
            VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
        )]);
        let context = VerifyContext {
            subject: "alice@company.com",
            workload: "claude-code",
            resource: "stripe-production",
            operation: "GET",
            environment: None,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        verifier
            .verify(&signed, now, &context)
            .expect("the unmodified grant must verify");

        signed.grant.materialization = zs_policy::Materialization::Exchange;
        assert!(
            verifier.verify(&signed, now, &context).is_err(),
            "flipping the materialization mode must invalidate the signature"
        );
    }

    fn golden_grant() -> Grant {
        Grant {
            subject: "alice@company.com".into(),
            workload: "claude-code".into(),
            resource: "stripe-production".into(),
            host: "api.stripe.com".into(),
            protocol: "https".into(),
            source: CredentialSource::file("vault:kv/stripe"),
            operations: vec!["POST".into(), "GET".into()],
            environment: "development".into(),
            expires_at_ms: 1_700_000_000_000,
            grant_id: "g-1".into(),
            materialization: zs_policy::Materialization::Retrieve,
            upstream_host: "api.stripe.com".into(),
            upstream_port: 443,
            upstream_tls: zs_policy::UpstreamTlsMode::Default,
            local_endpoint: false,
            version: GRANT_VERSION,
        }
    }

    #[test]
    fn file_grant_canonical_bytes_are_frozen() {
        let grant = golden_grant();
        let expected = concat!(
            "credential_ref\u{1f}vault:kv/stripe\u{1e}",
            "environment\u{1f}development\u{1e}",
            "expires_at_ms\u{1f}1700000000000\u{1e}",
            "grant_id\u{1f}g-1\u{1e}",
            "host\u{1f}api.stripe.com\u{1e}",
            "local_endpoint\u{1f}false\u{1e}",
            "materialization\u{1f}retrieve\u{1e}",
            "operations\u{1f}GET\u{1d}POST\u{1e}",
            "protocol\u{1f}https\u{1e}",
            "resource\u{1f}stripe-production\u{1e}",
            "subject\u{1f}alice@company.com\u{1e}",
            "upstream_host\u{1f}api.stripe.com\u{1e}",
            "upstream_port\u{1f}443\u{1e}",
            "upstream_tls\u{1f}default\u{1e}",
            "workload\u{1f}claude-code\u{1e}",
        );
        assert_eq!(canonical_payload(&grant), expected.as_bytes());

        let signed = ControlSigningKey::from_bytes("k1", &[7; 32])
            .sign(grant)
            .unwrap();
        assert_eq!(
            signed.signature,
            "en6VlGR4Uwr0S5O2RtqEMImkapf4Wj+4Jze39lwTXEf7KKs/rA1fKq2iNJXoadEZdp3Blf7wbdPAbhZIHE5WAw=="
        );

        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/grant-file.json")).unwrap();
        let case = &vector["cases"][0];
        assert_eq!(
            case["expect"]["payload_hex"].as_str().unwrap(),
            hex_lower(expected.as_bytes())
        );
        assert_eq!(
            case["expect"]["signature_b64"].as_str().unwrap(),
            signed.signature
        );
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn a_separator_in_any_signed_value_is_refused() {
        let key = ControlSigningKey::from_bytes("k1", &[7; 32]);
        let fields: [(&'static str, FieldSetter); 8] = [
            ("subject", |g| &mut g.subject),
            ("workload", |g| &mut g.workload),
            ("resource", |g| &mut g.resource),
            ("host", |g| &mut g.host),
            ("protocol", |g| &mut g.protocol),
            ("environment", |g| &mut g.environment),
            ("grant_id", |g| &mut g.grant_id),
            ("upstream_host", |g| &mut g.upstream_host),
        ];
        for (field, setter) in fields {
            for separator in ['\u{1e}', '\u{1f}'] {
                let mut grant = golden_grant();
                *setter(&mut grant) = format!("a{separator}b");
                assert!(
                    matches!(
                        key.sign(grant),
                        Err(GrantError::Unsignable { field: reported }) if reported == field
                    ),
                    "{field} with {separator:?}"
                );
            }
        }
        for separator in ['\u{1e}', '\u{1f}'] {
            let mut grant = golden_grant();
            grant.source = file_source(&format!("a{separator}b"));
            assert!(
                matches!(
                    key.sign(grant),
                    Err(GrantError::Unsignable {
                        field: "credential_ref"
                    })
                ),
                "credential_ref with {separator:?}"
            );
        }
        for separator in ['\u{1d}', '\u{1e}', '\u{1f}'] {
            let mut grant = golden_grant();
            grant.operations = vec![format!("a{separator}b")];
            assert!(
                matches!(
                    key.sign(grant),
                    Err(GrantError::Unsignable {
                        field: "operations"
                    })
                ),
                "operations with {separator:?}"
            );
        }
    }

    fn aws_ssm_grant() -> Grant {
        let mut grant = golden_grant();
        grant.resource = "acme-db".into();
        grant.host = "db.acme.internal".into();
        grant.protocol = "postgres".into();
        grant.source = CredentialSource::AwsSsm(zs_policy::AwsSsmSource {
            role_arn: zs_policy::RoleArn::parse("arn:aws:iam::123456789012:role/zs-acme-db")
                .unwrap(),
            region: zs_policy::AwsRegion::parse("ap-southeast-1").unwrap(),
            parameter: zs_policy::SsmParameter::parse("/acme/prod/DB_PASSWORD").unwrap(),
        });
        grant
    }

    #[test]
    fn file_grant_json_uses_credential_ref() {
        let value = serde_json::to_value(golden_grant()).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(
            object.get("credential_ref"),
            Some(&"vault:kv/stripe".into())
        );
        assert!(!object.contains_key("source"));
    }

    #[test]
    fn aws_ssm_grant_json_uses_source() {
        let value = serde_json::to_value(aws_ssm_grant()).unwrap();
        let object = value.as_object().unwrap();
        assert!(!object.contains_key("credential_ref"));
        let source = object.get("source").unwrap().as_object().unwrap();
        assert_eq!(source.get("kind"), Some(&"aws_ssm".into()));
        assert_eq!(source.get("region"), Some(&"ap-southeast-1".into()));
        assert_eq!(
            source.get("parameter"),
            Some(&"/acme/prod/DB_PASSWORD".into())
        );
        assert_eq!(
            source.get("role_arn"),
            Some(&"arn:aws:iam::123456789012:role/zs-acme-db".into())
        );
        assert_eq!(
            serde_json::from_value::<Grant>(value).unwrap().source,
            aws_ssm_grant().source
        );
    }

    #[test]
    fn grant_json_with_both_keys_is_refused() {
        let mut value = serde_json::to_value(aws_ssm_grant()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("credential_ref".into(), "vault:kv/stripe".into());
        assert!(serde_json::from_value::<Grant>(value).is_err());
    }

    #[test]
    fn grant_json_with_neither_key_is_refused() {
        let mut value = serde_json::to_value(golden_grant()).unwrap();
        value.as_object_mut().unwrap().remove("credential_ref");
        assert!(serde_json::from_value::<Grant>(value).is_err());
    }

    #[test]
    fn aws_ssm_canonical_records_sit_between_resource_and_subject() {
        let payload = String::from_utf8(canonical_payload(&aws_ssm_grant())).unwrap();
        assert!(payload.contains(concat!(
            "resource\u{1f}acme-db\u{1e}",
            "source.kind\u{1f}aws_ssm\u{1e}",
            "source.parameter\u{1f}/acme/prod/DB_PASSWORD\u{1e}",
            "source.region\u{1f}ap-southeast-1\u{1e}",
            "source.role_arn\u{1f}arn:aws:iam::123456789012:role/zs-acme-db\u{1e}",
            "subject\u{1f}alice@company.com\u{1e}",
        )));
        assert!(!payload.contains("credential_ref"));
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct PreSourceGrant {
        subject: String,
        workload: String,
        resource: String,
        host: String,
        protocol: String,
        credential_ref: String,
        operations: Vec<String>,
        environment: String,
        expires_at_ms: u64,
        grant_id: String,
        materialization: zs_policy::Materialization,
        upstream_host: String,
        upstream_port: u16,
        upstream_tls: zs_policy::UpstreamTlsMode,
        local_endpoint: bool,
    }

    #[test]
    fn pre_source_agent_json_refuses_an_aws_ssm_grant() {
        let value = serde_json::to_value(aws_ssm_grant()).unwrap();
        assert!(serde_json::from_value::<PreSourceGrant>(value).is_err());
        let value = serde_json::to_value(golden_grant()).unwrap();
        assert!(serde_json::from_value::<PreSourceGrant>(value).is_ok());
    }

    #[test]
    fn a_cloned_verifier_shares_the_replaced_key_set() {
        let first = ControlSigningKey::generate("control-k1");
        let second = ControlSigningKey::generate("control-k2");
        let verifier = verifier_for(&first);
        let clone = verifier.clone();
        let signed = second.sign(grant(60_000)).unwrap();
        let context = ctx("stripe-production", "GET");

        assert!(matches!(
            clone.verify(&signed, now_ms(), &context),
            Err(GrantError::SignatureInvalid)
        ));
        let second_key = VerifyingKey::from_bytes(&second.verifying_key_bytes()).unwrap();
        clone.replace(vec![("control-k2".to_string(), second_key)]);
        assert!(verifier.verify(&signed, now_ms(), &context).is_ok());

        verifier.replace(Vec::new());
        assert!(
            verifier.verify(&signed, now_ms(), &context).is_ok(),
            "an empty set must not clear the ring"
        );
        assert_eq!(verifier.keys().len(), 1);
    }

    #[test]
    fn an_unknown_grant_version_is_refused_by_name() {
        let control = ControlSigningKey::generate("k1");
        let verifier = verifier_for(&control);
        let context = ctx("stripe-production", "GET");

        let signed = control.sign(grant(60_000)).unwrap();
        assert!(verifier.verify(&signed, now_ms(), &context).is_ok());

        let mut next = grant(60_000);
        next.version = 2;
        let signed = control.sign(next).unwrap();
        let err = verifier.verify(&signed, now_ms(), &context).unwrap_err();
        assert!(
            matches!(&err, GrantError::UnsupportedVersion),
            "expected UnsupportedVersion, got {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "grant version not supported by this zs; upgrade zs"
        );

        let mut document = serde_json::to_value(&signed).unwrap();
        document["grant"].as_object_mut().unwrap().remove("version");
        let stripped: SignedGrant = serde_json::from_value(document).unwrap();
        assert!(matches!(
            verifier.verify(&stripped, now_ms(), &context),
            Err(GrantError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_grant_for_another_environment_is_refused() {
        let control = ControlSigningKey::generate("k1");
        let verifier = verifier_for(&control);
        let mut production_grant = grant(60_000);
        production_grant.environment = "production".into();
        let production = control.sign(production_grant).unwrap();
        let development = control.sign(grant(60_000)).unwrap();

        let in_production = VerifyContext {
            environment: Some("production"),
            ..ctx("stripe-production", "GET")
        };
        assert!(
            verifier
                .verify(&production, now_ms(), &in_production)
                .is_ok()
        );
        let err = verifier
            .verify(&development, now_ms(), &in_production)
            .unwrap_err();
        assert!(
            matches!(err, GrantError::EnvironmentMismatch),
            "expected EnvironmentMismatch, got {err:?}"
        );
        assert_eq!(err.to_string(), "grant is for another environment");

        let no_environment = ctx("stripe-production", "GET");
        assert!(
            verifier
                .verify(&production, now_ms(), &no_environment)
                .is_ok()
        );
        assert!(
            verifier
                .verify(&development, now_ms(), &no_environment)
                .is_ok()
        );
    }

    #[test]
    fn verify_returns_a_verified_grant_for_the_same_signed_grant() {
        let control = ControlSigningKey::generate("k1");
        let signed = control.sign(golden_grant()).unwrap();
        let verified = verifier_for(&control)
            .verify(&signed, 0, &ctx("stripe-production", "GET"))
            .unwrap();
        assert_eq!(verified.signed().signature, signed.signature);
        assert_eq!(verified.grant().source, signed.grant.source);
        assert_eq!(verified.grant().grant_id, "g-1");
    }
}
