#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;

pub const CLIENT_ID: &str = "zerosecret-control";
pub const ISSUER: &str = "https://idp.test";
pub const ACCESS_TOKEN: &str = "access-token-must-not-leak";
pub const AUTHORIZE_PATH_PREFIX: &str = "http://127.0.0.1";
pub const SIGNING_KID: &str = "idp-key-1";

#[derive(Default)]
struct Behaviour {
    id_token: Option<String>,
    raw_response: Option<String>,
    last_form: Option<std::collections::HashMap<String, String>>,
    hold: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}

pub struct FakeIdp {
    address: std::net::SocketAddr,
    signing: ring::signature::RsaKeyPair,
    impostor: ring::signature::RsaKeyPair,
    behaviour: Arc<tokio::sync::Mutex<Behaviour>>,
    token_requests: Arc<std::sync::atomic::AtomicUsize>,
    jwks_requests: Arc<std::sync::atomic::AtomicUsize>,
}

const SIGNING_KEY_DER: &[u8] = include_bytes!("idp_signing_key.pk8");
const IMPOSTOR_KEY_DER: &[u8] = include_bytes!("impostor_key.pk8");

fn key_pair(der: &[u8]) -> ring::signature::RsaKeyPair {
    ring::signature::RsaKeyPair::from_pkcs8(der).expect("fixed test key must parse")
}

impl FakeIdp {
    pub fn keys_only() -> Self {
        Self {
            address: "127.0.0.1:1".parse().unwrap(),
            signing: key_pair(SIGNING_KEY_DER),
            impostor: key_pair(IMPOSTOR_KEY_DER),
            behaviour: Arc::new(tokio::sync::Mutex::new(Behaviour::default())),
            token_requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            jwks_requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    pub async fn start() -> Self {
        let idp = Self::keys_only();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let shared = Arc::new(ServerState {
            jwks: jwks_document(&idp.signing),
            behaviour: idp.behaviour.clone(),
            token_requests: idp.token_requests.clone(),
            jwks_requests: idp.jwks_requests.clone(),
        });
        let app = Router::new()
            .route("/token", post(token_endpoint))
            .route("/jwks", get(jwks_endpoint))
            .with_state(shared);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self { address, ..idp }
    }

    pub fn authorize_url(&self) -> String {
        format!(
            "http://{}/authorize?response_type=code&client_id={CLIENT_ID}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A8443%2Flogin%2Fcallback&scope=openid+email",
            self.address
        )
    }

    pub fn token_url(&self) -> String {
        format!("http://{}/token", self.address)
    }

    pub fn jwks_url(&self) -> String {
        format!("http://{}/jwks", self.address)
    }

    pub async fn set_id_token(&self, token: String) {
        let mut behaviour = self.behaviour.lock().await;
        behaviour.id_token = Some(token);
        behaviour.raw_response = None;
    }

    pub async fn last_token_request_field(&self, name: &str) -> Option<String> {
        let behaviour = self.behaviour.lock().await;
        behaviour
            .last_form
            .as_ref()
            .and_then(|form| form.get(name).cloned())
    }

    pub async fn last_token_request_was_form_encoded(&self) -> bool {
        self.behaviour.lock().await.last_form.is_some()
    }

    pub async fn hold_next_token_request(
        &self,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let received = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        self.behaviour.lock().await.hold = Some((received.clone(), release.clone()));
        (received, release)
    }

    pub fn token_requests(&self) -> usize {
        self.token_requests
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn jwks_requests(&self) -> usize {
        self.jwks_requests.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn id_token_for(&self, subject: &str, issuer: &str, audience: &str) -> String {
        let mut claims = claims(subject, audience, 3600);
        claims["iss"] = serde_json::Value::String(issuer.to_string());
        self.sign(&self.signing, "RS256", &claims)
    }

    pub async fn set_raw_token_response(&self, body: &str) {
        let mut behaviour = self.behaviour.lock().await;
        behaviour.raw_response = Some(body.to_string());
        behaviour.id_token = None;
    }

    pub fn signed_id_token(&self, subject: &str) -> String {
        self.sign(&self.signing, "RS256", &claims(subject, CLIENT_ID, 3600))
    }

    pub fn id_token_for_audience(&self, subject: &str, audience: &str) -> String {
        self.sign(&self.signing, "RS256", &claims(subject, audience, 3600))
    }

    pub fn expired_id_token(&self, subject: &str) -> String {
        self.sign(&self.signing, "RS256", &claims(subject, CLIENT_ID, -3600))
    }

    pub fn id_token_signed_by_an_impostor(&self, subject: &str) -> String {
        self.sign(&self.impostor, "RS256", &claims(subject, CLIENT_ID, 3600))
    }

    pub fn unsigned_id_token(&self, subject: &str) -> String {
        let header = b64(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = b64(claims(subject, CLIENT_ID, 3600).to_string().as_bytes());
        format!("{header}.{payload}.")
    }

    pub fn unsigned_id_token_with_a_valid_signature(&self, subject: &str) -> String {
        self.sign(&self.signing, "none", &claims(subject, CLIENT_ID, 3600))
    }

    fn sign(
        &self,
        key: &ring::signature::RsaKeyPair,
        algorithm: &str,
        claims: &serde_json::Value,
    ) -> String {
        let header = b64(
            serde_json::json!({ "alg": algorithm, "typ": "JWT", "kid": SIGNING_KID })
                .to_string()
                .as_bytes(),
        );
        let payload = b64(claims.to_string().as_bytes());
        let message = format!("{header}.{payload}");
        let mut signature = vec![0u8; key.public().modulus_len()];
        key.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            message.as_bytes(),
            &mut signature,
        )
        .expect("test signing must succeed");
        format!("{message}.{}", b64(&signature))
    }
}

fn claims(subject: &str, audience: &str, expires_in: i64) -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    serde_json::json!({
        "iss": ISSUER,
        "sub": subject,
        "email": subject,
        "aud": audience,
        "iat": now - 10,
        "exp": now + expires_in,
    })
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn jwks_document(key: &ring::signature::RsaKeyPair) -> serde_json::Value {
    let components: ring::signature::RsaPublicKeyComponents<Vec<u8>> = key.public().into();
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": SIGNING_KID,
            "n": b64(&components.n),
            "e": b64(&components.e),
        }]
    })
}

struct ServerState {
    jwks: serde_json::Value,
    behaviour: Arc<tokio::sync::Mutex<Behaviour>>,
    token_requests: Arc<std::sync::atomic::AtomicUsize>,
    jwks_requests: Arc<std::sync::atomic::AtomicUsize>,
}

async fn jwks_endpoint(State(state): State<Arc<ServerState>>) -> Json<serde_json::Value> {
    state
        .jwks_requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Json(state.jwks.clone())
}

async fn token_endpoint(
    State(state): State<Arc<ServerState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    state
        .token_requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.starts_with("application/x-www-form-urlencoded") {
        return (
            StatusCode::BAD_REQUEST,
            [("content-type", "application/json")],
            r#"{"errorCode":"E0000021","errorSummary":"Bad request. Accept and/or Content-Type headers likely do not match supported values."}"#,
        )
            .into_response();
    }
    let form: std::collections::HashMap<String, String> =
        serde_urlencoded::from_str(&body).unwrap_or_default();

    let mut behaviour = state.behaviour.lock().await;
    behaviour.last_form = Some(form.clone());

    for required in ["grant_type", "code", "client_id", "redirect_uri"] {
        if form
            .get(required)
            .map(String::as_str)
            .unwrap_or_default()
            .is_empty()
        {
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                format!(
                    r#"{{"error":"invalid_request","error_description":"missing {required}"}}"#
                ),
            )
                .into_response();
        }
    }

    let hold = behaviour.hold.take();
    let raw_response = behaviour.raw_response.clone();
    let id_token = behaviour.id_token.clone().unwrap_or_default();
    drop(behaviour);
    if let Some((received, release)) = hold {
        received.notify_one();
        release.notified().await;
    }
    if let Some(raw) = raw_response {
        return ([("content-type", "application/json")], raw).into_response();
    }
    Json(serde_json::json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
    }))
    .into_response()
}
