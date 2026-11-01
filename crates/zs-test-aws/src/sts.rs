use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::net::{Handler, Req, Resp};
use crate::{Counters, Failure, Session, State, now, random_string};

struct Es256Verifier(p256::ecdsa::VerifyingKey);

impl signature::Verifier<Vec<u8>> for Es256Verifier {
    fn verify(&self, msg: &[u8], sig: &Vec<u8>) -> Result<(), signature::Error> {
        let sig = p256::ecdsa::Signature::from_slice(sig).map_err(|_| signature::Error::new())?;
        p256::ecdsa::signature::Verifier::verify(&self.0, msg, &sig)
            .map_err(|_| signature::Error::new())
    }
}

impl jsonwebtoken::crypto::JwtVerifier for Es256Verifier {
    fn algorithm(&self) -> jsonwebtoken::Algorithm {
        jsonwebtoken::Algorithm::ES256
    }
}

fn es256_verifier(
    alg: &jsonwebtoken::Algorithm,
    key: &jsonwebtoken::DecodingKey,
) -> jsonwebtoken::errors::Result<Box<dyn jsonwebtoken::crypto::JwtVerifier>> {
    use jsonwebtoken::errors::ErrorKind;
    if *alg != jsonwebtoken::Algorithm::ES256 || key.family() != jsonwebtoken::AlgorithmFamily::Ec {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key.as_bytes())
        .map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    Ok(Box::new(Es256Verifier(vk)))
}

static ES256_ONLY: jsonwebtoken::crypto::CryptoProvider = jsonwebtoken::crypto::CryptoProvider {
    signer_factory: |_, _| Err(jsonwebtoken::errors::ErrorKind::InvalidAlgorithm.into()),
    verifier_factory: es256_verifier,
    jwk_utils: jsonwebtoken::crypto::JwkUtils::new_unimplemented(),
};

pub(crate) fn handler(state: Arc<Mutex<State>>, counters: Arc<Counters>) -> Handler {
    let _ = ES256_ONLY.install_default();
    Arc::new(move |req: Req| {
        let state = state.clone();
        let counters = counters.clone();
        Box::pin(async move {
            counters.sts.fetch_add(1, Ordering::SeqCst);
            let delay = state.lock().unwrap().delay;
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            let resp = answer(&state, req);
            if resp.status == 200 {
                counters.sts_ok.fetch_add(1, Ordering::SeqCst);
            } else {
                state.lock().unwrap().last_sts_error =
                    Some(String::from_utf8_lossy(&resp.body).to_string());
            }
            resp
        })
    })
}

fn sts_error(status: u16, code: &str, message: &str) -> Resp {
    Resp::new(
        status,
        "text/xml",
        format!(
            "<ErrorResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\n  <Error>\n    <Type>Sender</Type>\n    <Code>{code}</Code>\n    <Message>{message}</Message>\n  </Error>\n  <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>\n</ErrorResponse>\n"
        ),
    )
}

pub(crate) fn iso(epoch: u64) -> String {
    let days = (epoch / 86_400) as i64;
    let rem = epoch % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
}

fn valid_session_name(s: &str) -> bool {
    (2..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+=,.@-".contains(&b))
}

const INVALID: &str = "The web identity token provided could not be validated.";
const NO_KEY: &str = "Couldn't retrieve verification key from your identity provider";

fn answer(state: &Arc<Mutex<State>>, req: Req) -> Resp {
    if req.method != "POST" || req.path != "/" {
        return sts_error(400, "InvalidAction", "Could not find operation");
    }
    if !req
        .header("content-type")
        .is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"))
    {
        return sts_error(400, "InvalidParameterValue", "form body expected");
    }
    let form: Vec<(String, String)> = form_urlencoded::parse(&req.body).into_owned().collect();
    let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let (issuer, jwks_json) = {
        let mut s = state.lock().unwrap();
        s.last_sts_form = form.clone();
        match s.fail.clone() {
            Some(Failure::StsGarbage(body)) => return Resp::new(200, "text/xml", body),
            Some(Failure::StsRefuse { status, code }) => {
                return sts_error(status, &code, "refused by the fake");
            }
            _ => {}
        }
        (s.issuer.clone(), s.jwks_json.clone())
    };
    if get("Action").as_deref() != Some("AssumeRoleWithWebIdentity")
        || get("Version").as_deref() != Some("2011-06-15")
    {
        return sts_error(400, "InvalidAction", "Could not find operation");
    }
    let (Some(role_arn), Some(session_name), Some(token)) = (
        get("RoleArn"),
        get("RoleSessionName"),
        get("WebIdentityToken"),
    ) else {
        return sts_error(400, "MissingParameter", "A required parameter is missing");
    };
    if !valid_session_name(&session_name) {
        return sts_error(
            400,
            "ValidationError",
            "1 validation error detected: Value at 'roleSessionName' failed to satisfy constraint",
        );
    }
    let duration: u64 = get("DurationSeconds")
        .and_then(|d| d.parse().ok())
        .unwrap_or(3600);
    let policy = match get("Policy") {
        Some(p) if p.chars().count() > 2048 => {
            return sts_error(
                400,
                "ValidationError",
                "1 validation error detected: Value at 'policy' failed to satisfy constraint: Member must have length less than or equal to 2048",
            );
        }
        Some(p) => match serde_json::from_str::<serde_json::Value>(&p) {
            Ok(v) => v,
            Err(_) => return sts_error(400, "MalformedPolicyDocument", "Syntax errors in policy."),
        },
        None => serde_json::Value::Null,
    };

    let Ok(unverified) = jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(&token)
    else {
        return sts_error(400, "InvalidIdentityToken", INVALID);
    };
    if unverified.claims["iss"].as_str() != Some(issuer.as_str()) {
        return sts_error(
            400,
            "InvalidIdentityToken",
            "No OpenIDConnect provider found in your account for the issuer",
        );
    }
    let Ok(jwks) = serde_json::from_str::<serde_json::Value>(&jwks_json) else {
        return sts_error(400, "InvalidIdentityToken", NO_KEY);
    };
    if jwks["keys"]
        .as_array()
        .is_some_and(|keys| keys.iter().any(|k| k.get("d").is_some()))
    {
        return sts_error(400, "InvalidIdentityToken", "JWKS contains a private key");
    }
    let Ok(set) = serde_json::from_value::<jsonwebtoken::jwk::JwkSet>(jwks) else {
        return sts_error(400, "InvalidIdentityToken", NO_KEY);
    };
    let Ok(header) = jsonwebtoken::decode_header(&token) else {
        return sts_error(400, "InvalidIdentityToken", INVALID);
    };
    if header.alg != jsonwebtoken::Algorithm::ES256 {
        return sts_error(400, "InvalidIdentityToken", "Unsupported algorithm");
    }
    let Some(jwk) = header.kid.as_deref().and_then(|kid| set.find(kid)) else {
        return sts_error(400, "InvalidIdentityToken", NO_KEY);
    };
    let Ok(key) = jsonwebtoken::DecodingKey::from_jwk(jwk) else {
        return sts_error(400, "InvalidIdentityToken", "Unusable verification key");
    };
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_audience(&[crate::AUDIENCE]);
    validation.set_issuer(&[issuer.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = 0;
    let claims = match jsonwebtoken::decode::<Claims>(&token, &key, &validation) {
        Ok(d) => d.claims,
        Err(e) => {
            use jsonwebtoken::errors::ErrorKind;
            return match e.kind() {
                ErrorKind::ExpiredSignature => {
                    sts_error(400, "ExpiredTokenException", "Token expired")
                }
                ErrorKind::InvalidAudience => {
                    sts_error(400, "InvalidIdentityToken", "Incorrect token audience")
                }
                _ => sts_error(400, "InvalidIdentityToken", INVALID),
            };
        }
    };
    if !(6..=255).contains(&claims.sub.len()) {
        return sts_error(400, "InvalidIdentityToken", "Invalid sub length");
    }

    let mut s = state.lock().unwrap();
    let denied = "Not authorized to perform sts:AssumeRoleWithWebIdentity";
    let Some(rule) = s.trust.iter().find(|r| r.role_arn == role_arn) else {
        return sts_error(403, "AccessDenied", denied);
    };
    if claims.sub != rule.sub {
        return sts_error(403, "AccessDenied", denied);
    }
    if !(900..=rule.max_session_s).contains(&duration) {
        return sts_error(
            400,
            "ValidationError",
            "The requested DurationSeconds exceeds the MaxSessionDuration set for this role.",
        );
    }
    let akid = format!(
        "ASIA{}",
        random_string(16, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    );
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let secret = random_string(40, alphabet);
    let token_value = format!("IQoJb3JpZ2luX2Vj{}==", random_string(600, alphabet));
    let expires_at = now() + duration;
    let role_name = role_arn.rsplit('/').next().unwrap_or_default().to_string();
    let account = role_arn.split(':').nth(4).unwrap_or_default().to_string();
    s.sessions.insert(
        akid.clone(),
        Session {
            secret: secret.clone(),
            token: token_value.clone(),
            expires_at,
            role_arn: role_arn.clone(),
            session_name: session_name.clone(),
            policy,
        },
    );
    Resp::new(
        200,
        "text/xml",
        format!(
            r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>{sub}</SubjectFromWebIdentityToken>
    <Audience>sts.amazonaws.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}</Arn>
      <AssumedRoleId>AROAFAKEFAKEFAKEFAKE:{session_name}</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <SessionToken>{token_value}</SessionToken>
      <SecretAccessKey>{secret}</SecretAccessKey>
      <Expiration>{exp}</Expiration>
      <AccessKeyId>{akid}</AccessKeyId>
    </Credentials>
    <SourceIdentity></SourceIdentity>
    <Provider>{issuer}</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>
"#,
            sub = claims.sub,
            exp = iso(expires_at),
        ),
    )
}
