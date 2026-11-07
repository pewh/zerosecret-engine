#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use zs::device::{DeviceSecrets, Enrolment};
use zs::wire_client::{WireClient, WireError};
use zs_mitm::Zeroizing;

#[tokio::test]
async fn wire_client_times_out_a_silent_control_plane() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            held.push(stream);
        }
    });

    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let pem = certificate.pem();
    let enrolment = Enrolment {
        control: format!("https://localhost:{port}"),
        control_ca_sha256: String::new(),
        subject: "alice@company.com".into(),
        device_id: "dev-test".into(),
        organization: "default".into(),
        client_certificate: pem.clone(),
        grant_verifying_key_hex: ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        grant_verifying_key_id: "control-k1".into(),
        wire_url: format!("https://localhost:{port}"),
        environment: None,
        control_ca_pems: Vec::new(),
    };
    let secrets = DeviceSecrets::new(
        Zeroizing::new(key.serialize_pem()),
        Zeroizing::new(vec![7u8; 32]),
    );
    let client = WireClient::from_identity(&pem, &enrolment, &secrets).unwrap();

    let start = Instant::now();
    let error = client.fetch_revocations().await.unwrap_err();
    assert!(start.elapsed() < Duration::from_secs(35));
    assert!(
        matches!(&error, WireError::Transport(text) if text == "timed out"),
        "{error:?}"
    );
}
