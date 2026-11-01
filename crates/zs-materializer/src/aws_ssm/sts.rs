use zeroize::Zeroizing;
use zs_policy::{AwsSsmSource, SourceKind};

use super::{iso8601_epoch, safe_code, xml};
use crate::MaterializationError;

pub(crate) const DURATION_SECONDS: u32 = 900;
pub(crate) const MAX_POLICY_CHARS: usize = 2048;

pub(crate) struct SessionCredentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Zeroizing<String>,
    pub expires_at: u64,
}

impl Clone for SessionCredentials {
    fn clone(&self) -> Self {
        Self {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
            expires_at: self.expires_at,
        }
    }
}

pub(crate) fn endpoint_host(region: &str) -> String {
    format!("sts.{region}.amazonaws.com")
}

pub fn role_session_name(subject: &str) -> String {
    let mut name: String = subject
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "+=,.@-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    name.truncate(64);
    if name.len() < 2 {
        name.push_str(&"zs"[..2 - name.len()]);
    }
    name
}

pub(crate) fn session_policy(source: &AwsSsmSource) -> Result<String, MaterializationError> {
    let policy = zs_policy::aws_ssm_session_policy(source);
    if policy.chars().count() > MAX_POLICY_CHARS {
        return Err(MaterializationError::Refused {
            kind: SourceKind::AwsSsm,
            step: "policy",
            code: "PolicyTooLong".to_string(),
        });
    }
    Ok(policy)
}

pub(crate) fn form_fields(
    source: &AwsSsmSource,
    session_name: &str,
    policy: &str,
    token: &str,
) -> Vec<(&'static str, Zeroizing<String>)> {
    vec![
        ("Action", Zeroizing::new("AssumeRoleWithWebIdentity".into())),
        ("Version", Zeroizing::new("2011-06-15".into())),
        ("RoleArn", Zeroizing::new(source.role_arn.as_str().into())),
        ("RoleSessionName", Zeroizing::new(session_name.into())),
        ("WebIdentityToken", Zeroizing::new(token.into())),
        (
            "DurationSeconds",
            Zeroizing::new(DURATION_SECONDS.to_string()),
        ),
        ("Policy", Zeroizing::new(policy.into())),
    ]
}

pub(crate) fn form_body(fields: &[(&'static str, Zeroizing<String>)]) -> Zeroizing<String> {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        serializer.append_pair(name, value);
    }
    Zeroizing::new(serializer.finish())
}

const R: &str = "AssumeRoleWithWebIdentityResponse/AssumeRoleWithWebIdentityResult/Credentials/";

fn refused(code: impl Into<String>) -> MaterializationError {
    MaterializationError::Refused {
        kind: SourceKind::AwsSsm,
        step: "sts",
        code: code.into(),
    }
}

pub(crate) fn parse_response(
    status: u16,
    body: &str,
) -> Result<SessionCredentials, MaterializationError> {
    if !(200..300).contains(&status) {
        let code = xml::extract(body, &["ErrorResponse/Error/Code"])
            .ok()
            .and_then(|mut f| f.remove(0))
            .map(|c| safe_code(c.trim()))
            .unwrap_or_else(|| "unparsed".to_string());
        return Err(refused(code));
    }
    let wanted = [
        &format!("{R}AccessKeyId")[..],
        &format!("{R}SecretAccessKey")[..],
        &format!("{R}SessionToken")[..],
        &format!("{R}Expiration")[..],
    ];
    let mut f = xml::extract(body, &wanted).map_err(|_| refused("MalformedResponse"))?;
    let mut take = |i: usize| {
        f[i].take()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| refused("IncompleteResponse"))
    };
    let akid = take(0)?;
    let secret = take(1)?;
    let token = take(2)?;
    let expiration = take(3)?;
    let akid = akid.trim().to_string();
    if !(16..=128).contains(&akid.len()) || !akid.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(refused("MalformedResponse"));
    }
    let expires_at =
        iso8601_epoch(expiration.trim()).ok_or_else(|| refused("MalformedResponse"))?;
    Ok(SessionCredentials {
        access_key_id: akid,
        secret_access_key: Zeroizing::new(secret.trim().to_string()),
        session_token: Zeroizing::new(token.trim().to_string()),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn role_session_name_follows_d6() {
        assert_eq!(role_session_name("alice@company.com"), "alice@company.com");
        assert_eq!(role_session_name("a b/c_d"), "a-b-c-d");
        assert_eq!(role_session_name("a"), "az");
        assert_eq!(role_session_name(""), "zs");
        assert_eq!(role_session_name(&"x".repeat(80)).len(), 64);
    }

    #[test]
    fn the_aws_reference_answers_parse() {
        let ok = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <SessionToken>AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp+IEXAMPLE</SessionToken>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <Expiration>2014-10-24T23:00:23Z</Expiration>
      <AccessKeyId>ASgeIAIOSFODNN7EXAMPLE</AccessKeyId>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#;
        let session = parse_response(200, ok).unwrap();
        assert_eq!(session.access_key_id, "ASgeIAIOSFODNN7EXAMPLE");
        assert_eq!(session.expires_at, 1_414_191_623);
        let err = r#"<ErrorResponse><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>m</Message></Error></ErrorResponse>"#;
        match parse_response(400, err) {
            Err(MaterializationError::Refused { step, code, .. }) => {
                assert_eq!(step, "sts");
                assert_eq!(code, "InvalidIdentityToken");
            }
            _ => panic!("a 400 must be a refusal"),
        }
    }
}
