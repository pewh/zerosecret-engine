#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use zs_vectors::{Runner, check};

fn device_signature(_context: &Value, input: &Value) -> Value {
    let request: zs_wire::GrantMintRequest = serde_json::from_value(input.clone())
        .unwrap_or_else(|error| panic!("device-signature: {error}"));
    json!({"message": zs_wire::device_signature_message(&request)})
}

fn login_code(_context: &Value, input: &Value) -> Value {
    let challenge = input
        .as_str()
        .unwrap_or_else(|| panic!("login-code: the input is not a string"));
    json!({"code": zs_wire::login_code(challenge)})
}

fn dto<T: DeserializeOwned + Serialize>(_context: &Value, input: &Value) -> Value {
    let text = input
        .as_str()
        .unwrap_or_else(|| panic!("a dto: the input is not a JSON text"));
    match serde_json::from_str::<T>(text) {
        Ok(value) => json!({
            "accepted": true,
            "reserialized": serde_json::to_string(&value).unwrap(),
        }),
        Err(_) => json!({"accepted": false}),
    }
}

const RUNNERS: &[Runner] = &[
    Runner {
        file: "device-signature.json",
        case: device_signature,
    },
    Runner {
        file: "login-code.json",
        case: login_code,
    },
    Runner {
        file: "dto-login-claim.json",
        case: dto::<zs_wire::LoginClaim>,
    },
    Runner {
        file: "dto-wire-refusal.json",
        case: dto::<zs_wire::WireRefusal>,
    },
    Runner {
        file: "dto-enrollment-token-response.json",
        case: dto::<zs_wire::EnrollmentTokenResponse>,
    },
    Runner {
        file: "dto-enrollment-request.json",
        case: dto::<zs_wire::EnrollmentRequest>,
    },
    Runner {
        file: "dto-enrollment-response.json",
        case: dto::<zs_wire::EnrollmentResponse>,
    },
    Runner {
        file: "dto-grant-mint-request.json",
        case: dto::<zs_wire::GrantMintRequest>,
    },
    Runner {
        file: "dto-grant-mint-response.json",
        case: dto::<zs_wire::GrantMintResponse>,
    },
    Runner {
        file: "dto-audit-ingest-record.json",
        case: dto::<zs_wire::AuditIngestRecord>,
    },
    Runner {
        file: "dto-policy-response.json",
        case: dto::<zs_wire::PolicyResponse>,
    },
    Runner {
        file: "dto-revoke-request.json",
        case: dto::<zs_wire::RevokeRequest>,
    },
    Runner {
        file: "dto-revocations-response.json",
        case: dto::<zs_wire::RevocationsResponse>,
    },
];

#[test]
fn every_zs_wire_vector_matches() {
    check(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors"),
        RUNNERS,
    );
}
