// The grant-verifying key is pinned at enrolment and never refetched per request (ADR-0016).

use std::time::{Duration, SystemTime};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use thiserror::Error;
use zs_grant::{AgentVerifier, GrantError, SignedGrant, VerifyContext};
use zs_mitm::Zeroizing;
use zs_upstream::http::{self, Network, ProxyPolicy, Roots, transport_kind};
use zs_wire::{
    AuditIngestRecord, EnrollmentRequest, EnrollmentResponse, GrantMintRequest, GrantMintResponse,
    PolicyResponse, WireRefusal, device_signature_message,
};

use crate::device::{DeviceSecrets, Enrolment};

const WIRE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum WireError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("control plane refused: {status}")]
    Refused { status: u16 },
    #[error("malformed response: {0}")]
    Malformed(String),
    #[error("grant rejected: {0}")]
    Grant(#[from] GrantError),
    #[error("device identity: {0}")]
    Identity(String),
    #[error("device refused: {code}")]
    DeviceRefused { code: String },
}

// The HTTP client and the CA set its roots were built from, so an unchanged set is not rebuilt.
struct WireHttp {
    roots: Vec<String>,
    client: reqwest::Client,
}

pub struct WireClient {
    wire_url: String,
    http: std::sync::Mutex<WireHttp>,
    identity: Option<reqwest::Identity>,
    device_id: String,
    device_key: SigningKey,
    verifier: AgentVerifier,
    environment: Option<String>,
}

impl WireClient {
    pub async fn enroll(
        enroll_url: &str,
        ca_pem: &str,
        enrollment_token: &str,
        device_name: &str,
    ) -> Result<Self, WireError> {
        let (enrollment, secrets) =
            Self::enroll_identity(enroll_url, ca_pem, enrollment_token, device_name).await?;
        let enrolment = Enrolment {
            control: enroll_url.to_string(),
            control_ca_sha256: crate::control_ca_sha256(ca_pem),
            subject: String::new(),
            device_id: enrollment.device_id,
            organization: enrollment.organization,
            client_certificate: enrollment.client_certificate,
            grant_verifying_key_hex: hex(&enrollment.grant_verifying_key),
            grant_verifying_key_id: enrollment.grant_verifying_key_id,
            wire_url: enrollment.wire_url,
            environment: enrollment.environment,
            control_ca_pems: enrollment.control_ca_pems,
        };
        Self::from_identity(ca_pem, &enrolment, &secrets)
    }

    pub async fn enroll_identity(
        enroll_url: &str,
        ca_pem: &str,
        enrollment_token: &str,
        device_name: &str,
    ) -> Result<(EnrollmentResponse, DeviceSecrets), WireError> {
        let tls_key =
            rcgen::KeyPair::generate().map_err(|e| WireError::Identity(format!("keypair: {e}")))?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|e| WireError::Identity(format!("csr params: {e}")))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, device_name.to_string());
        let csr = params
            .serialize_request(&tls_key)
            .map_err(|e| WireError::Identity(format!("csr: {e}")))?
            .pem()
            .map_err(|e| WireError::Identity(format!("csr pem: {e}")))?;

        let seed = random_seed();
        let device_public_key = SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec();

        let enroll_http = wire_client(&[ca_pem], None)?;
        let response = enroll_http
            .post(format!("{enroll_url}/wire/enroll"))
            .json(&EnrollmentRequest {
                device_public_key,
                device_name: device_name.to_string(),
                enrollment_token: enrollment_token.to_string(),
                csr,
            })
            .header(reqwest::header::USER_AGENT, crate::WIRE_USER_AGENT)
            .send()
            .await
            .map_err(|e| WireError::Transport(transport_kind(&e).to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(WireError::Refused {
                status: status.as_u16(),
            });
        }
        let enrollment: EnrollmentResponse = response
            .json()
            .await
            .map_err(|e| WireError::Malformed(e.to_string()))?;

        let secrets = DeviceSecrets::new(
            Zeroizing::new(tls_key.serialize_pem()),
            Zeroizing::new(seed.to_vec()),
        );
        Ok((enrollment, secrets))
    }

    pub fn from_identity(
        ca_pem: &str,
        enrolment: &Enrolment,
        secrets: &DeviceSecrets,
    ) -> Result<Self, WireError> {
        if enrolment.wire_url.is_empty() {
            return Err(WireError::Malformed(
                "enrolment returned no wire URL; the control plane has no wire listener".into(),
            ));
        }
        crate::wire_url_allowed(&enrolment.wire_url).map_err(WireError::Malformed)?;
        let key_bytes = unhex(&enrolment.grant_verifying_key_hex)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| WireError::Malformed("verifying key is not 32 bytes".into()))?;
        let verifying = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| WireError::Malformed("verifying key is not a valid Ed25519 key".into()))?;

        let seed = Zeroizing::new(
            <[u8; 32]>::try_from(secrets.device_seed())
                .map_err(|_| WireError::Identity("device seed is not 32 bytes".into()))?,
        );
        let device_key = SigningKey::from_bytes(&seed);

        let identity_pem = Zeroizing::new(format!(
            "{}\n{}",
            enrolment.client_certificate,
            secrets.tls_key_pem()
        ));
        let identity = reqwest::Identity::from_pem(identity_pem.as_bytes())
            .map_err(|e| WireError::Identity(e.to_string()))?;
        let client = wire_client(
            &trust_set(ca_pem, &enrolment.control_ca_pems),
            Some(identity.clone()),
        )?;
        let http = std::sync::Mutex::new(WireHttp {
            roots: enrolment.control_ca_pems.clone(),
            client,
        });

        Ok(Self {
            wire_url: enrolment.wire_url.trim_end_matches('/').to_string(),
            http,
            identity: Some(identity),
            device_id: enrolment.device_id.clone(),
            device_key,
            verifier: AgentVerifier::new(vec![(
                enrolment.grant_verifying_key_id.clone(),
                verifying,
            )]),
            environment: enrolment.environment.clone(),
        })
    }

    fn http(&self) -> reqwest::Client {
        match self.http.lock() {
            Ok(current) => current.client.clone(),
            Err(poisoned) => poisoned.into_inner().client.clone(),
        }
    }

    fn roots(&self) -> Vec<String> {
        match self.http.lock() {
            Ok(current) => current.roots.clone(),
            Err(poisoned) => poisoned.into_inner().roots.clone(),
        }
    }

    // A non-empty set of PEM certificates replaces the trusted roots: it becomes the whole trust,
    // so a CA the control plane no longer publishes is dropped, even the one pinned at enrolment.
    // Any invalid PEM rejects the whole update and keeps the current client. An unchanged set
    // keeps the current client and its connections. Returns whether the roots changed.
    pub fn set_roots(&self, pems: &[String]) -> Result<bool, WireError> {
        if pems.is_empty() || self.roots() == pems {
            return Ok(false);
        }
        let client = wire_client(&trust_set("", pems), self.identity.clone())?;
        match self.http.lock() {
            Ok(mut current) => {
                *current = WireHttp {
                    roots: pems.to_vec(),
                    client,
                }
            }
            Err(poisoned) => {
                *poisoned.into_inner() = WireHttp {
                    roots: pems.to_vec(),
                    client,
                }
            }
        }
        Ok(true)
    }

    pub fn verifier(&self) -> &AgentVerifier {
        &self.verifier
    }

    pub fn install_key_set(
        &self,
        keys: &[zs_wire::VerifyingKeyEntry],
        diag: &zs_diag::DiagLog,
    ) -> bool {
        apply_key_set(&self.verifier, keys, diag)
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn wire_url(&self) -> &str {
        &self.wire_url
    }

    pub async fn fetch_policy(&self) -> Result<PolicyResponse, WireError> {
        let response = self
            .http()
            .get(format!("{}/wire/policy", self.wire_url))
            .header(reqwest::header::USER_AGENT, crate::WIRE_USER_AGENT)
            .send()
            .await
            .map_err(|e| WireError::Transport(transport_kind(&e).to_string()))?;
        Self::json(response).await
    }

    pub async fn revoke_grant(
        &self,
        grant_id: &str,
        reason: Option<&str>,
    ) -> Result<(), WireError> {
        let response = self
            .http()
            .post(format!("{}/wire/revoke", self.wire_url))
            .json(&zs_wire::RevokeRequest {
                grant_id: grant_id.to_string(),
                reason: reason.map(String::from),
            })
            .header(reqwest::header::USER_AGENT, crate::WIRE_USER_AGENT)
            .send()
            .await
            .map_err(|e| WireError::Transport(transport_kind(&e).to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(WireError::Transport(format!(
                "revoke refused: {}",
                response.status()
            )))
        }
    }

    pub async fn fetch_revocations(&self) -> Result<zs_wire::RevocationsResponse, WireError> {
        let response = self
            .http()
            .get(format!("{}/wire/revocations", self.wire_url))
            .header(reqwest::header::USER_AGENT, crate::WIRE_USER_AGENT)
            .send()
            .await
            .map_err(|e| WireError::Transport(transport_kind(&e).to_string()))?;
        Self::json(response).await
    }

    // Verify here so no caller can obtain an unverified grant.
    pub async fn request_grant(
        &self,
        request: &GrantMintRequest,
    ) -> Result<crate::MintedGrant, WireError> {
        let body = serde_json::json!({
            "device_id": request.device_id,
            "subject": request.subject,
            "workload": request.workload,
            "resource": request.resource,
            "operations": request.operations,
        });
        let signature = base64::engine::general_purpose::STANDARD.encode(
            self.device_key
                .sign(device_signature_message(request).as_bytes())
                .to_bytes(),
        );

        let response = self
            .http()
            .post(format!("{}/wire/grant", self.wire_url))
            .header("x-device-signature", signature)
            .json(&body)
            .header(reqwest::header::USER_AGENT, crate::WIRE_USER_AGENT)
            .send()
            .await
            .map_err(|e| WireError::Transport(transport_kind(&e).to_string()))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let code = response
                .json::<WireRefusal>()
                .await
                .map(|refusal| refusal.code)
                .unwrap_or_else(|_| "device_unknown".to_string());
            return Err(WireError::DeviceRefused { code });
        }
        let minted: GrantMintResponse = Self::json(response).await?;
        let signed: SignedGrant = serde_json::from_str(&minted.signed_grant_json)
            .map_err(|e| WireError::Malformed(e.to_string()))?;

        for operation in &request.operations {
            self.verify_grant(
                &signed,
                &VerifyContext {
                    subject: &request.subject,
                    workload: &request.workload,
                    resource: &request.resource,
                    operation,
                    environment: self.environment.as_deref(),
                },
            )?;
        }
        Ok(crate::MintedGrant {
            signed,
            token: minted
                .identity_token
                .map(zs_credential::IdentityToken::from_string),
        })
    }

    pub fn verify_grant(
        &self,
        signed: &SignedGrant,
        context: &VerifyContext<'_>,
    ) -> Result<(), WireError> {
        self.verifier.verify(signed, now_ms(), context)?;
        Ok(())
    }

    pub async fn submit_audit(&self, records: &[AuditIngestRecord]) -> Result<(), WireError> {
        let response = self
            .http()
            .post(format!("{}/wire/audit", self.wire_url))
            .json(records)
            .header(reqwest::header::USER_AGENT, crate::WIRE_USER_AGENT)
            .send()
            .await
            .map_err(|e| WireError::Transport(transport_kind(&e).to_string()))?;
        if !response.status().is_success() {
            return Err(WireError::Refused {
                status: response.status().as_u16(),
            });
        }
        Ok(())
    }

    async fn json<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, WireError> {
        let status = response.status();
        if !status.is_success() {
            return Err(WireError::Refused {
                status: status.as_u16(),
            });
        }
        response
            .json()
            .await
            .map_err(|e| WireError::Malformed(e.to_string()))
    }
}

// The trusted CAs are the published set when there is one; without a set (a `v0.3.0` record or
// control plane) the pinned CA is the set of one. The pinned CA is not added to a published set:
// once the control plane stops publishing it (retired), it no longer authenticates the wire.
fn trust_set<'a>(pinned: &'a str, published: &'a [String]) -> Vec<&'a str> {
    if published.is_empty() {
        vec![pinned]
    } else {
        published.iter().map(String::as_str).collect()
    }
}

fn wire_client(
    trust: &[&str],
    identity: Option<reqwest::Identity>,
) -> Result<reqwest::Client, WireError> {
    let mut roots: Vec<CertificateDer<'static>> = Vec::with_capacity(trust.len());
    for pem_text in trust {
        let der = root_certificate(pem_text)?;
        if !roots
            .iter()
            .any(|existing| existing.as_ref() == der.as_ref())
        {
            roots.push(der);
        }
    }
    http::client(
        Roots::Only(roots),
        WIRE_REQUEST_TIMEOUT,
        identity,
        false,
        ProxyPolicy::System,
        &Network::default(),
    )
    .map_err(|e| WireError::Transport(e.to_string()))
}

// The local CA is trusted when it is the one the record enrolled with, or any CA the control
// plane has published to this device since.
pub fn pin_accepts(ca_pem: &str, enrolment: &crate::device::Enrolment) -> bool {
    let hash = crate::control_ca_sha256(ca_pem);
    hash == enrolment.control_ca_sha256
        || enrolment
            .control_ca_pems
            .iter()
            .any(|pem| crate::control_ca_sha256(pem) == hash)
}

// An absent or empty set keeps the current keys; an invalid entry rejects the whole set.
pub fn apply_key_set(
    verifier: &AgentVerifier,
    keys: &[zs_wire::VerifyingKeyEntry],
    diag: &zs_diag::DiagLog,
) -> bool {
    if keys.is_empty() {
        return false;
    }
    let mut parsed = Vec::with_capacity(keys.len());
    for entry in keys {
        match <[u8; 32]>::try_from(entry.key.as_slice())
            .ok()
            .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        {
            Some(key) => parsed.push((entry.kid.clone(), key)),
            None => {
                diag.emit(zs_diag::Event::new(zs_diag::Component::Grant, "key_set_invalid").warn());
                return false;
            }
        }
    }
    verifier.replace(parsed);
    true
}

fn root_certificate(ca_pem: &str) -> Result<CertificateDer<'static>, WireError> {
    CertificateDer::from_pem_slice(ca_pem.as_bytes())
        .map_err(|e| WireError::Identity(format!("control CA: {e}")))
}

fn random_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed.as_mut());
    seed
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn now_ms() -> u64 {
    crate::clock_ms(SystemTime::now())
}
