use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use crate::net::{Handler, Req, Resp};
use crate::{Counters, Failure, ParameterKind, State, now};

pub(crate) fn handler(state: Arc<Mutex<State>>, counters: Arc<Counters>) -> Handler {
    Arc::new(move |req: Req| {
        let state = state.clone();
        let counters = counters.clone();
        Box::pin(async move {
            counters.ssm.fetch_add(1, Ordering::SeqCst);
            let resp = answer(&state, req);
            if resp.status == 200 {
                counters.ssm_ok.fetch_add(1, Ordering::SeqCst);
            } else {
                state.lock().unwrap().last_ssm_error =
                    Some(String::from_utf8_lossy(&resp.body).to_string());
            }
            resp
        })
    })
}

fn ssm_error(code: &str, message: Option<&str>) -> Resp {
    let body = match message {
        Some(m) => serde_json::json!({ "__type": code, "message": m }),
        None => serde_json::json!({ "__type": code }),
    };
    Resp::new(400, "application/x-amz-json-1.1", body.to_string())
}

pub fn glob(pattern: &str, value: &str) -> bool {
    fn go(p: &[u8], v: &[u8]) -> bool {
        match (p.first(), v.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], v) || (!v.is_empty() && go(p, &v[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &v[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &v[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), value.as_bytes())
}

fn as_list(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => vec![],
    }
}

fn session_allows(policy: &serde_json::Value, action: &str, resource: &str, via: &str) -> bool {
    if policy.is_null() {
        return true;
    }
    let statements = match &policy["Statement"] {
        serde_json::Value::Array(a) => a.clone(),
        s @ serde_json::Value::Object(_) => vec![s.clone()],
        _ => vec![],
    };
    let matches = |s: &serde_json::Value| {
        as_list(&s["Action"])
            .iter()
            .any(|a| glob(&a.to_ascii_lowercase(), &action.to_ascii_lowercase()))
            && as_list(&s["Resource"]).iter().any(|r| glob(r, resource))
    };
    let allowed = statements.iter().any(|s| {
        s["Effect"] == "Allow"
            && matches(s)
            && match s.get("Condition") {
                None => true,
                Some(c) => c["StringEquals"].as_object().is_some_and(|m| {
                    m.iter()
                        .all(|(k, v)| k == "kms:ViaService" && v.as_str() == Some(via))
                }),
            }
    });
    let denied = statements
        .iter()
        .any(|s| s["Effect"] == "Deny" && matches(s));
    allowed && !denied
}

fn amz_date_epoch(v: &str) -> Option<u64> {
    if v.len() != 16 {
        return None;
    }
    let n = |a: usize, b: usize| v.get(a..b)?.parse::<i64>().ok();
    let (y, m, d, h, mi, s) = (
        n(0, 4)?,
        n(4, 6)?,
        n(6, 8)?,
        n(9, 11)?,
        n(11, 13)?,
        n(13, 15)?,
    );
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + s).ok()
}

pub fn verify_sigv4(
    req: &Req,
    host: &str,
    region: &str,
    akid: &str,
    secret: &str,
    token: &str,
) -> Result<(), String> {
    use aws_sigv4::http_request::{
        PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign,
    };
    let auth = req.header("authorization").ok_or("no Authorization")?;
    let rest = auth
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or("not AWS4-HMAC-SHA256")?;
    let field = |name: &str| {
        rest.split(',')
            .map(str::trim)
            .find_map(|p| p.strip_prefix(name))
            .map(str::to_string)
    };
    let credential = field("Credential=").ok_or("no Credential")?;
    let signed = field("SignedHeaders=").ok_or("no SignedHeaders")?;
    let signature = field("Signature=").ok_or("no Signature")?;
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5
        || parts[0] != akid
        || parts[2] != region
        || parts[3] != "ssm"
        || parts[4] != "aws4_request"
    {
        return Err("credential scope".into());
    }
    let amz = req.header("x-amz-date").ok_or("no x-amz-date")?;
    if amz.get(..8) != Some(parts[1]) {
        return Err("scope date".into());
    }
    let when = UNIX_EPOCH + Duration::from_secs(amz_date_epoch(amz).ok_or("bad x-amz-date")?);
    let signed_list: Vec<&str> = signed.split(';').collect();
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = if signed_list.contains(&"x-amz-content-sha256") {
        PayloadChecksumKind::XAmzSha256
    } else {
        PayloadChecksumKind::NoHeader
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    for name in &signed_list {
        if matches!(
            *name,
            "x-amz-date" | "x-amz-security-token" | "x-amz-content-sha256"
        ) {
            continue;
        }
        let value = if *name == "host" {
            host.to_string()
        } else {
            req.header(name).ok_or("signed header missing")?.to_string()
        };
        headers.push((name.to_string(), value));
    }
    let identity: aws_smithy_runtime_api::client::identity::Identity =
        aws_credential_types::Credentials::new(akid, secret, Some(token.to_string()), None, "fake")
            .into();
    let params = aws_sigv4::sign::v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("ssm")
        .time(when)
        .settings(settings)
        .build()
        .map_err(|e| e.to_string())?
        .into();
    let uri = format!("https://{host}{}", req.path);
    let signable = SignableRequest::new(
        &req.method,
        uri,
        headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        SignableBody::Bytes(&req.body),
    )
    .map_err(|e| e.to_string())?;
    let (instructions, expected) = sign(signable, &params)
        .map_err(|e| e.to_string())?
        .into_parts();
    let expected_auth = instructions
        .headers()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    let expected_signed = expected_auth
        .split(',')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("SignedHeaders="))
        .unwrap_or_default()
        .to_string();
    if expected_signed != signed {
        return Err(format!(
            "signed header set differs: verifier={expected_signed}"
        ));
    }
    if expected != signature {
        return Err("signature mismatch".into());
    }
    Ok(())
}

const INVALID_TOKEN: &str = "The security token included in the request is invalid.";

fn answer(state: &Arc<Mutex<State>>, req: Req) -> Resp {
    let s = state.lock().unwrap();
    let region = s.region.clone();
    let host = format!("ssm.{region}.amazonaws.com");
    if req.header("host") != Some(host.as_str()) {
        return ssm_error("InvalidSignatureException", Some("host"));
    }
    let Some(auth) = req.header("authorization") else {
        return ssm_error(
            "MissingAuthenticationTokenException",
            Some("Missing Authentication Token"),
        );
    };
    let akid = auth
        .split("Credential=")
        .nth(1)
        .and_then(|c| c.split('/').next())
        .unwrap_or_default()
        .to_string();
    let Some(session) = s.sessions.get(&akid) else {
        return ssm_error("UnrecognizedClientException", Some(INVALID_TOKEN));
    };
    if req.header("x-amz-security-token") != Some(session.token.as_str()) {
        return ssm_error("UnrecognizedClientException", Some(INVALID_TOKEN));
    }
    if now() >= session.expires_at {
        return ssm_error(
            "ExpiredTokenException",
            Some("The security token included in the request is expired"),
        );
    }
    let Some(dated) = req.header("x-amz-date").and_then(amz_date_epoch) else {
        return ssm_error("IncompleteSignatureException", None);
    };
    if dated.abs_diff(now()) > s.max_skew_s {
        return ssm_error("InvalidSignatureException", Some("Signature expired"));
    }
    if let Err(e) = verify_sigv4(&req, &host, &region, &akid, &session.secret, &session.token) {
        return ssm_error(
            "InvalidSignatureException",
            Some(&format!(
                "The request signature we calculated does not match the signature you provided. ({e})"
            )),
        );
    }
    if req.method != "POST" || req.header("x-amz-target") != Some("AmazonSSM.GetParameter") {
        return ssm_error("UnknownOperationException", None);
    }
    if req.header("content-type") != Some("application/x-amz-json-1.1") {
        return ssm_error("SerializationException", None);
    }
    if let Some(Failure::SsmRefuse { code }) = &s.fail {
        return ssm_error(code, Some("refused by the fake"));
    }
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&req.body) else {
        return ssm_error("SerializationException", None);
    };
    let Some(name) = body["Name"].as_str() else {
        return ssm_error("ValidationException", None);
    };
    let decrypt = body["WithDecryption"].as_bool().unwrap_or(false);
    let account = session.role_arn.split(':').nth(4).unwrap_or_default();
    let arn = format!(
        "arn:aws:ssm:{region}:{account}:parameter/{}",
        name.trim_start_matches('/')
    );
    let rule = s.trust.iter().find(|r| r.role_arn == session.role_arn);
    let principal = format!(
        "arn:aws:sts::{account}:assumed-role/{}/{}",
        session.role_arn.rsplit('/').next().unwrap_or_default(),
        session.session_name
    );
    let role_allows = rule.is_some_and(|r| glob(&r.parameter_glob, &arn));
    let via = format!("ssm.{region}.amazonaws.com");
    if !role_allows || !session_allows(&session.policy, "ssm:GetParameter", &arn, &via) {
        let why = if role_allows {
            "because no session policy allows the ssm:GetParameter action"
        } else {
            "because no identity-based policy allows the ssm:GetParameter action"
        };
        return ssm_error(
            "AccessDeniedException",
            Some(&format!(
                "User: {principal} is not authorized to perform: ssm:GetParameter on resource: {arn} {why}"
            )),
        );
    }
    let Some(param) = s.params.get(name) else {
        return ssm_error("ParameterNotFound", None);
    };
    if param.kind == ParameterKind::SecureString && decrypt {
        let key = format!("arn:aws:kms:{region}:{account}:key/fake");
        let kms_role =
            rule.is_some_and(|r| r.kms_decrypt) && !matches!(s.fail, Some(Failure::KmsDenied));
        if !kms_role || !session_allows(&session.policy, "kms:Decrypt", &key, &via) {
            return ssm_error(
                "AccessDeniedException",
                Some(&format!(
                    "User: {principal} is not authorized to perform: kms:Decrypt on resource: {key} (Service: AWSKMS; Status Code: 400; Error Code: AccessDeniedException)"
                )),
            );
        }
    }
    let out = serde_json::json!({
        "Parameter": {
            "ARN": arn,
            "DataType": "text",
            "LastModifiedDate": 1_582_657_288.8,
            "Name": name,
            "Type": param.kind.as_str(),
            "Value": param.value,
            "Version": 3,
        }
    });
    Resp::new(200, "application/x-amz-json-1.1", out.to_string())
}
