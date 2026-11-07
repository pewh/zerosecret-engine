use serde::{Deserialize, Serialize};

pub fn login_code(challenge: &str) -> String {
    challenge
        .chars()
        .take(6)
        .collect::<String>()
        .to_ascii_uppercase()
}

pub fn device_signature_message(request: &GrantMintRequest) -> String {
    let mut message = String::from("{\"device_id\":");
    push_json_string(&mut message, &request.device_id);
    message.push_str(",\"subject\":");
    push_json_string(&mut message, &request.subject);
    message.push_str(",\"workload\":");
    push_json_string(&mut message, &request.workload);
    message.push_str(",\"resource\":");
    push_json_string(&mut message, &request.resource);
    message.push_str(",\"operations\":[");
    for (index, operation) in request.operations.iter().enumerate() {
        if index > 0 {
            message.push(',');
        }
        push_json_string(&mut message, operation);
    }
    message.push_str("]}");
    message
}

fn push_json_string(out: &mut String, value: &str) {
    out.push_str(&serde_json::Value::String(value.to_owned()).to_string());
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginClaim {
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
}

impl std::fmt::Debug for LoginClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginClaim")
            .field("subject", &self.subject)
            .field(
                "enrollment_token",
                &self.enrollment_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRefusal {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentTokenResponse {
    pub token: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub device_public_key: Vec<u8>,
    pub device_name: String,
    pub enrollment_token: String,
    pub csr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyingKeyEntry {
    pub kid: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub device_id: String,
    pub organization: String,
    pub client_certificate: String,
    pub grant_verifying_key: Vec<u8>,
    pub grant_verifying_key_id: String,
    pub wire_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_verifying_keys: Vec<VerifyingKeyEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub control_ca_pems: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantMintRequest {
    pub device_id: String,
    pub subject: String,
    pub workload: String,
    pub resource: String,
    pub operations: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GrantMintResponse {
    pub signed_grant_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_token: Option<String>,
}

impl std::fmt::Debug for GrantMintResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantMintResponse")
            .field("signed_grant_json", &self.signed_grant_json)
            .field(
                "identity_token",
                &self.identity_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditIngestRecord {
    pub subject: String,
    pub workload: String,
    pub resource: String,
    pub protocol: String,
    pub operation: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    pub timestamp_ms: u64,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub version: u64,
    pub policy_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub grant_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationsResponse {
    pub revoked_grant_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grant_verifying_keys: Vec<VerifyingKeyEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub control_ca_pems: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{GrantMintRequest, device_signature_message, login_code};
    use serde_json::json;

    const DEVICE_ID: &str = "dev-0123456789abcdef0123456789abcdef";

    fn request(text: &str, operations: &[&str]) -> GrantMintRequest {
        GrantMintRequest {
            device_id: DEVICE_ID.to_string(),
            subject: text.to_string(),
            workload: text.to_string(),
            resource: text.to_string(),
            operations: operations.iter().map(|one| one.to_string()).collect(),
        }
    }

    fn value_form(request: &GrantMintRequest) -> String {
        json!({
            "device_id": &request.device_id,
            "subject": &request.subject,
            "workload": &request.workload,
            "resource": &request.resource,
            "operations": &request.operations,
        })
        .to_string()
    }

    #[test]
    fn login_code_is_the_first_six_challenge_characters_in_upper_case() {
        assert_eq!(login_code("ab12cd34ef56"), "AB12CD");
    }

    #[test]
    fn device_signature_message_matches_the_serde_json_value_form() {
        let texts = [
            "<", ">", "&", "\u{2028}", "\u{2029}", "\u{7}", "a\nb", "é", "🔐",
        ];
        for text in texts {
            let request = request(text, &[text]);
            assert_eq!(
                device_signature_message(&request),
                value_form(&request),
                "text {text:?}"
            );
        }
        let empty = request("acme-db", &[]);
        assert_eq!(device_signature_message(&empty), value_form(&empty));
    }
}
