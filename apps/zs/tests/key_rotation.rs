#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod matrix_support;

use matrix_support::{FakeControl, RESOURCE, SUBJECT, TlsWire, WORKLOAD, grant, now_ms};
use zs::wire_client::apply_key_set;
use zs_grant::{AgentVerifier, ControlSigningKey, GrantError, SignedGrant, VerifyContext};

fn verifier(keys: &[&ControlSigningKey]) -> AgentVerifier {
    AgentVerifier::new(
        keys.iter()
            .map(|key| {
                (
                    key.key_id().to_string(),
                    ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
                )
            })
            .collect(),
    )
}

fn entries(keys: &[&ControlSigningKey]) -> Vec<zs_wire::VerifyingKeyEntry> {
    keys.iter()
        .map(|key| zs_wire::VerifyingKeyEntry {
            kid: key.key_id().to_string(),
            key: key.verifying_key_bytes().to_vec(),
        })
        .collect()
}

fn context() -> VerifyContext<'static> {
    VerifyContext {
        subject: SUBJECT,
        workload: WORKLOAD,
        resource: RESOURCE,
        operation: "GET",
        environment: None,
    }
}

fn signed_by(key: &ControlSigningKey) -> SignedGrant {
    key.sign(grant(now_ms() + 60_000, "g-rotation")).unwrap()
}

#[test]
fn an_agent_verifies_a_grant_signed_by_a_key_learned_on_refresh() {
    let first = ControlSigningKey::generate("control-k1");
    let second = ControlSigningKey::generate("control-k2");
    let verifier = verifier(&[&first]);
    let diag = zs_diag::DiagLog::disabled();

    let renewed = signed_by(&second);
    assert!(
        matches!(
            verifier.verify(&renewed, now_ms(), &context()),
            Err(GrantError::SignatureInvalid)
        ),
        "control: a grant of the unknown key must not verify"
    );
    assert!(
        verifier
            .verify(&signed_by(&first), now_ms(), &context())
            .is_ok()
    );

    assert!(apply_key_set(
        &verifier,
        &entries(&[&first, &second]),
        &diag
    ));
    assert!(
        verifier.verify(&renewed, now_ms(), &context()).is_ok(),
        "the grant of the learned key does not verify"
    );
}

#[test]
fn a_retired_key_no_longer_verifies() {
    let first = ControlSigningKey::generate("control-k1");
    let second = ControlSigningKey::generate("control-k2");
    let verifier = verifier(&[&first, &second]);
    let diag = zs_diag::DiagLog::disabled();

    let old = signed_by(&first);
    assert!(verifier.verify(&old, now_ms(), &context()).is_ok());

    assert!(apply_key_set(&verifier, &entries(&[&second]), &diag));
    assert!(
        matches!(
            verifier.verify(&old, now_ms(), &context()),
            Err(GrantError::SignatureInvalid)
        ),
        "a grant of the retired key still verifies"
    );
    assert!(
        verifier
            .verify(&signed_by(&second), now_ms(), &context())
            .is_ok()
    );
}

#[test]
fn an_absent_or_empty_key_set_keeps_the_current_keys() {
    let first = ControlSigningKey::generate("control-k1");
    let verifier = verifier(&[&first]);
    let diag = zs_diag::DiagLog::disabled();
    let current = signed_by(&first);

    assert!(!apply_key_set(&verifier, &[], &diag));
    assert!(verifier.verify(&current, now_ms(), &context()).is_ok());
    assert_eq!(verifier.keys().len(), 1);

    let mut invalid = entries(&[&ControlSigningKey::generate("control-k2")]);
    invalid[0].key.truncate(31);
    assert!(!apply_key_set(&verifier, &invalid, &diag));
    assert_eq!(verifier.keys().len(), 1, "an invalid entry changed the set");
    assert!(verifier.verify(&current, now_ms(), &context()).is_ok());
}

#[test]
fn wire_requests_carry_the_agent_version() {
    let control = FakeControl::start();
    let ca_pem = control.ca_pem().to_string();
    let token = format!("enr-{}", "a1".repeat(32));
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime
        .block_on(zs::wire_client::WireClient::enroll_identity(
            &control.url,
            &ca_pem,
            &token,
            "laptop",
        ))
        .expect("enrolment against the fake control");

    let recorded = control.user_agents();
    assert!(!recorded.is_empty(), "the fake control received no request");
    assert!(
        recorded.iter().all(|agent| agent == zs::WIRE_USER_AGENT),
        "user agents = {recorded:?}, want {}",
        zs::WIRE_USER_AGENT
    );
    assert!(
        zs::WIRE_USER_AGENT.starts_with("zs/"),
        "the user agent is {}",
        zs::WIRE_USER_AGENT
    );
}

fn client_for(control: &FakeControl, environment: Option<&str>) -> zs::wire_client::WireClient {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let ca_pem = control.ca_pem().to_string();
    let token = format!("enr-{}", "a1".repeat(32));
    let (response, secrets) = runtime
        .block_on(zs::wire_client::WireClient::enroll_identity(
            &control.url,
            &ca_pem,
            &token,
            "laptop",
        ))
        .expect("enrolment");
    let enrolment = zs::device::Enrolment {
        control: control.url.clone(),
        control_ca_sha256: zs::control_ca_sha256(&ca_pem),
        subject: SUBJECT.into(),
        device_id: response.device_id,
        organization: response.organization,
        client_certificate: response.client_certificate,
        grant_verifying_key_hex: response
            .grant_verifying_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        grant_verifying_key_id: response.grant_verifying_key_id,
        wire_url: response.wire_url,
        environment: environment.map(str::to_string),
        control_ca_pems: Vec::new(),
    };
    zs::wire_client::WireClient::from_identity(&ca_pem, &enrolment, &secrets)
        .expect("a wire client")
}

#[test]
fn a_v0_3_device_record_loads_as_a_set_of_one() {
    let original = zs::device::Enrolment {
        control: "https://control.example.test".into(),
        control_ca_sha256: zs::control_ca_sha256(
            "-----BEGIN CERTIFICATE-----\nONE\n-----END CERTIFICATE-----\n",
        ),
        subject: SUBJECT.into(),
        device_id: "dev-v03".into(),
        organization: "default".into(),
        client_certificate: "CERT".into(),
        grant_verifying_key_hex: "cd".repeat(32),
        grant_verifying_key_id: "control-k1".into(),
        wire_url: "https://control.example.test:8444".into(),
        environment: None,
        control_ca_pems: Vec::new(),
    };
    let mut text = serde_json::to_value(&original).unwrap();
    let object = text.as_object_mut().unwrap();
    object.remove("environment");
    object.remove("control_ca_pems");
    let loaded: zs::device::Enrolment = serde_json::from_value(text).unwrap();
    assert!(loaded.environment.is_none());
    assert!(loaded.control_ca_pems.is_empty());
    assert_eq!(loaded.control_ca_sha256, original.control_ca_sha256);

    let first = rcgen::CertificateParams::new(vec!["control.example.test".to_string()])
        .unwrap()
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap()
        .pem();
    let second = rcgen::CertificateParams::new(vec!["control.example.test".to_string()])
        .unwrap()
        .self_signed(&rcgen::KeyPair::generate().unwrap())
        .unwrap()
        .pem();
    let mut enrolled = original.clone();
    enrolled.control_ca_sha256 = zs::control_ca_sha256(&first);
    assert!(zs::wire_client::pin_accepts(&first, &enrolled));
    assert!(!zs::wire_client::pin_accepts(&second, &enrolled));
    enrolled.control_ca_pems = vec![second.clone()];
    assert!(zs::wire_client::pin_accepts(&second, &enrolled));
}

#[test]
fn a_refused_ca_set_keeps_the_working_client() {
    let control = FakeControl::start();
    let client = client_for(&control, None);
    let ca = |name: &str| {
        rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem()
    };
    let first = ca("control.example.test");
    let second = ca("control.example.test");

    assert!(client.set_roots(std::slice::from_ref(&first)).is_ok());
    assert!(client.set_roots(&[first.clone(), second.clone()]).is_ok());
    assert!(
        client
            .set_roots(&["not a certificate".to_string()])
            .is_err(),
        "an invalid PEM must be refused"
    );

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime
        .block_on(client.fetch_revocations())
        .expect("the client still reaches the control plane after a refused set");
}

fn tls_client(url: &str, pin: &str, environment: Option<&str>) -> zs::wire_client::WireClient {
    let tls_key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&tls_key)
        .unwrap();
    let client_pem = certificate.pem();
    let verifying = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    let enrolment = zs::device::Enrolment {
        control: url.to_string(),
        control_ca_sha256: zs::control_ca_sha256(pin),
        subject: SUBJECT.into(),
        device_id: "dev-tls".into(),
        organization: "default".into(),
        client_certificate: client_pem.clone(),
        grant_verifying_key_hex: verifying
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        grant_verifying_key_id: "control-k1".into(),
        wire_url: url.to_string(),
        environment: environment.map(str::to_string),
        control_ca_pems: Vec::new(),
    };
    let secrets = zs::device::DeviceSecrets::new(
        zs_mitm::Zeroizing::new(tls_key.serialize_pem()),
        zs_mitm::Zeroizing::new(vec![7u8; 32]),
    );
    zs::wire_client::WireClient::from_identity(pin, &enrolment, &secrets).expect("a wire client")
}

#[test]
fn a_new_device_ca_is_trusted_before_it_signs() {
    let first = common::test_ca::TestCa::generate("control-1").unwrap();
    let second = common::test_ca::TestCa::generate("control-2").unwrap();
    let wire = TlsWire::start(&first);
    let published = vec![first.certificate_pem(), second.certificate_pem()];
    wire.set_ca_pems(published.clone());

    let client = tls_client(&wire.url, &first.certificate_pem(), None);
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let response = runtime
        .block_on(client.fetch_revocations())
        .expect("positive control: the pinned CA is trusted");
    assert_eq!(response.control_ca_pems.len(), 2);
    client
        .set_roots(&response.control_ca_pems)
        .expect("the published set parses");

    wire.set_leaf(&second);
    runtime
        .block_on(client.fetch_revocations())
        .expect("a published CA is trusted before it signs");
}

fn mint_request() -> zs_wire::GrantMintRequest {
    zs_wire::GrantMintRequest {
        device_id: "dev-fake".into(),
        subject: SUBJECT.into(),
        workload: WORKLOAD.into(),
        resource: RESOURCE.into(),
        operations: vec!["GET".into()],
    }
}

#[test]
fn an_agent_that_missed_the_publish_window_recovers_at_the_next_refresh() {
    let control = FakeControl::start();
    let client = client_for(&control, None);
    let diag = zs_diag::DiagLog::disabled();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");

    runtime
        .block_on(client.request_grant(&mint_request()))
        .expect("positive control: a grant signed by control-k1");

    // The control promoted a key the agent never saw; one renewal is refused.
    let seed = [9u8; 32];
    let promoted = zs_grant::ControlSigningKey::from_bytes("control-k2", &seed);
    control.set_signing_key("control-k2", seed);
    let refused = runtime
        .block_on(client.request_grant(&mint_request()))
        .expect_err("a renewal signed by the unseen key must be refused");
    assert!(
        refused.to_string().contains("grant signature invalid"),
        "the refusal is {refused}"
    );
    assert!(
        client.verifier().keys().len() == 1,
        "the refused renewal changed the key set"
    );

    // The next refresh carries the published set and the following renewal succeeds.
    let mut published: Vec<zs_wire::VerifyingKeyEntry> = client
        .verifier()
        .keys()
        .into_iter()
        .map(|(kid, key)| zs_wire::VerifyingKeyEntry {
            kid,
            key: key.to_bytes().to_vec(),
        })
        .collect();
    published.push(zs_wire::VerifyingKeyEntry {
        kid: "control-k2".into(),
        key: promoted.verifying_key_bytes().to_vec(),
    });
    control.set_key_set(published);
    assert!(apply_key_set(client.verifier(), &control.key_set(), &diag));
    runtime
        .block_on(client.request_grant(&mint_request()))
        .expect("the renewal after the refresh");
}
