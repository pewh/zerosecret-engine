#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};
use zs_grant::{ControlSigningKey, Grant, GrantError, canonical_payload};
use zs_policy::CredentialSource;
use zs_vectors::{Runner, check};

fn hex_decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn signing_key(context: &Value) -> ControlSigningKey {
    let seed = hex_decode(context["key_seed_hex"].as_str().unwrap());
    let key_id = context["key_id"].as_str().unwrap();
    ControlSigningKey::from_bytes(key_id, &seed.try_into().unwrap())
}

fn signed_grant(context: &Value, input: &Value) -> Value {
    let key = signing_key(context);
    let grant: Grant = serde_json::from_value(input.clone()).unwrap();
    let signed = key.sign(grant).unwrap();
    json!({
        "payload_hex": hex_encode(&canonical_payload(&signed.grant)),
        "signature_b64": signed.signature,
    })
}

fn grant_refusal(context: &Value, input: &Value) -> Value {
    let key = signing_key(context);
    let mut object = input.as_object().unwrap().clone();
    let field = object
        .remove("field")
        .map(|value| value.as_str().unwrap().to_string());
    let value = object.remove("value");
    let mut grant: Grant = serde_json::from_value(Value::Object(object)).unwrap();
    if let (Some(field), Some(value)) = (field, value) {
        overwrite(&mut grant, &field, value);
    }
    match key.sign(grant) {
        Ok(signed) => json!({"payload_hex": hex_encode(&canonical_payload(&signed.grant))}),
        Err(GrantError::Unsignable { field }) => json!({"refused_field": field}),
        Err(error) => panic!("unexpected sign error: {error}"),
    }
}

fn overwrite(grant: &mut Grant, field: &str, value: Value) {
    let text = value.as_str().unwrap_or_default().to_string();
    match field {
        "subject" => grant.subject = text,
        "workload" => grant.workload = text,
        "resource" => grant.resource = text,
        "host" => grant.host = text,
        "protocol" => grant.protocol = text,
        "environment" => grant.environment = text,
        "grant_id" => grant.grant_id = text,
        "upstream_host" => grant.upstream_host = text,
        "credential_ref" => grant.source = CredentialSource::file(text),
        "operations" => {
            grant.operations = value
                .as_array()
                .unwrap()
                .iter()
                .map(|operation| operation.as_str().unwrap().to_string())
                .collect()
        }
        other => panic!("unknown field {other}"),
    }
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

fn grant_json(_context: &Value, input: &Value) -> Value {
    let parser = input["parser"].as_str().unwrap();
    let text = input["text"].as_str().unwrap();
    let value: Value = serde_json::from_str(text).unwrap();
    match parser {
        "grant" => match serde_json::from_value::<Grant>(value) {
            Ok(grant) => json!({"accepted": true, "grant_id": grant.grant_id}),
            Err(_) => json!({"accepted": false}),
        },
        "pre_source" => match serde_json::from_value::<PreSourceGrant>(value) {
            Ok(grant) => json!({"accepted": true, "grant_id": grant.grant_id}),
            Err(_) => json!({"accepted": false}),
        },
        other => panic!("unknown parser {other}"),
    }
}

#[test]
fn every_zs_grant_vector_matches() {
    check(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors"),
        &[
            Runner {
                file: "grant-file.json",
                case: signed_grant,
            },
            Runner {
                file: "grant-aws-ssm.json",
                case: signed_grant,
            },
            Runner {
                file: "grant-refusals.json",
                case: grant_refusal,
            },
            Runner {
                file: "grant-json.json",
                case: grant_json,
            },
        ],
    );
}
