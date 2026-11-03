#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::response::IntoResponse;
use zs::wire_client::{WireClient, WireError};

async fn refusing_wire(body: &'static str) -> String {
    let app = axum::Router::new().route(
        "/wire/grant",
        axum::routing::post(move || async move {
            (axum::http::StatusCode::UNAUTHORIZED, body).into_response()
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://127.0.0.1:{port}")
}

fn client_for_wire_url(wire_url: String) -> Result<WireClient, WireError> {
    let tls_key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&tls_key)
        .unwrap();
    let ca_pem = certificate.pem();
    let verifying = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    let enrolment = zs::device::Enrolment {
        control: "http://c".into(),
        control_ca_sha256: zs::control_ca_sha256(&ca_pem),
        subject: "alice@company.com".into(),
        device_id: "dev-x".into(),
        organization: "default".into(),
        client_certificate: ca_pem.clone(),
        grant_verifying_key_hex: verifying
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        grant_verifying_key_id: "control-k1".into(),
        wire_url,
    };
    let secrets = zs::device::DeviceSecrets::new(
        zs_mitm::Zeroizing::new(tls_key.serialize_pem()),
        zs_mitm::Zeroizing::new(vec![7u8; 32]),
    );
    WireClient::from_identity(&ca_pem, &enrolment, &secrets)
}

#[test]
fn a_plain_http_wire_url_to_a_remote_host_is_refused() {
    let error = client_for_wire_url("http://wire.example.test:8444".into())
        .err()
        .expect("a plain-http wire URL to a remote host must be refused");
    assert!(
        matches!(&error, WireError::Malformed(text) if text.contains("use https")),
        "got {error:?}"
    );
    assert!(client_for_wire_url("https://wire.example.test:8444".into()).is_ok());
    assert!(client_for_wire_url("http://127.0.0.1:8444".into()).is_ok());
}

async fn refusal_for(body: &'static str) -> WireError {
    let client = client_for_wire_url(refusing_wire(body).await).unwrap();
    client
        .request_grant(&zs_wire::GrantMintRequest {
            device_id: "dev-x".into(),
            subject: "alice@company.com".into(),
            workload: "claude-code".into(),
            resource: "stripe-production".into(),
            operations: vec!["GET".into()],
        })
        .await
        .expect_err("a 401 must be refused")
}

#[tokio::test]
async fn a_401_with_a_code_keeps_the_code() {
    let error = refusal_for(r#"{"code":"not_a_member"}"#).await;
    assert!(
        matches!(&error, WireError::DeviceRefused { code } if code == "not_a_member"),
        "got {error:?}"
    );
}

#[tokio::test]
async fn a_401_without_a_body_is_device_unknown() {
    let error = refusal_for("").await;
    assert!(
        matches!(&error, WireError::DeviceRefused { code } if code == "device_unknown"),
        "got {error:?}"
    );
    let error = refusal_for("not json").await;
    assert!(
        matches!(&error, WireError::DeviceRefused { code } if code == "device_unknown"),
        "got {error:?}"
    );
}
