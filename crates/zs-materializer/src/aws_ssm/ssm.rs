use zeroize::Zeroizing;
use zs_credential::Credential;
use zs_policy::{AwsSsmSource, SourceKind};
use zs_proto_http::sigv4;

use super::safe_code;
use super::sts::SessionCredentials;
use crate::MaterializationError;

pub(crate) const TARGET: &str = "AmazonSSM.GetParameter";
pub(crate) const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

pub(crate) fn endpoint_host(region: &str) -> String {
    format!("ssm.{region}.amazonaws.com")
}

pub(crate) struct SignedRequest {
    pub headers: Vec<(&'static str, Zeroizing<String>)>,
    pub body: Vec<u8>,
}

pub(crate) fn signed_request(
    source: &AwsSsmSource,
    session: &SessionCredentials,
    amz_date: &str,
) -> Result<SignedRequest, MaterializationError> {
    let host = endpoint_host(source.region.as_str());
    let body = serde_json::json!({
        "Name": source.parameter.as_str(),
        "WithDecryption": true,
    })
    .to_string()
    .into_bytes();
    let headers = [
        ("content-type", CONTENT_TYPE),
        ("host", host.as_str()),
        ("x-amz-date", amz_date),
        ("x-amz-security-token", session.session_token.as_str()),
        ("x-amz-target", TARGET),
    ];
    let signature = sigv4::sign(
        session.secret_access_key.as_bytes(),
        amz_date,
        &sigv4::Scope {
            access_key_id: &session.access_key_id,
            region: source.region.as_str(),
            service: "ssm",
        },
        &sigv4::Request {
            method: "POST",
            path: "/",
            query: sigv4::Query::Raw(""),
            headers: &headers,
            payload_sha256: &sigv4::payload_sha256(&body),
        },
    )
    .map_err(|_| MaterializationError::Refused {
        kind: SourceKind::AwsSsm,
        step: "sign",
        code: "SigningFailed".to_string(),
    })?;
    Ok(SignedRequest {
        headers: vec![
            ("content-type", Zeroizing::new(CONTENT_TYPE.to_string())),
            ("x-amz-date", Zeroizing::new(amz_date.to_string())),
            (
                "x-amz-security-token",
                Zeroizing::new(session.session_token.to_string()),
            ),
            ("x-amz-target", Zeroizing::new(TARGET.to_string())),
            ("authorization", Zeroizing::new(signature.authorization())),
        ],
        body,
    })
}

#[derive(serde::Deserialize)]
struct Output {
    #[serde(rename = "Parameter")]
    parameter: Param,
}

#[derive(serde::Deserialize)]
struct Param {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Value")]
    value: Zeroizing<String>,
}

pub(crate) fn error_code(error_type_header: Option<&str>, body: &[u8]) -> String {
    let from_body = || {
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("__type")
                    .or_else(|| v.get("code"))
                    .and_then(|t| t.as_str())
                    .map(str::to_string)
            })
    };
    let raw = error_type_header
        .map(str::to_string)
        .or_else(from_body)
        .unwrap_or_default();
    let raw = raw.rsplit_once('#').map_or(raw.as_str(), |(_, r)| r);
    let raw = raw.split_once(':').map_or(raw, |(l, _)| l);
    safe_code(raw)
}

pub(crate) fn parse_response(
    status: u16,
    error_type_header: Option<&str>,
    body: &[u8],
) -> Result<Credential, MaterializationError> {
    if !(200..300).contains(&status) {
        let code = error_code(error_type_header, body);
        if code == "ExpiredTokenException" || code == "UnrecognizedClientException" {
            return Err(MaterializationError::SessionExpired);
        }
        return Err(MaterializationError::Refused {
            kind: SourceKind::AwsSsm,
            step: "ssm",
            code,
        });
    }
    let invalid = || MaterializationError::InvalidValue(SourceKind::AwsSsm);
    let out: Output = serde_json::from_slice(body).map_err(|_| invalid())?;
    if !matches!(out.parameter.kind.as_str(), "String" | "SecureString") {
        return Err(invalid());
    }
    if out.parameter.value.is_empty() {
        return Err(invalid());
    }
    Credential::from_bytes(out.parameter.value.as_bytes().to_vec()).map_err(|_| invalid())
}
