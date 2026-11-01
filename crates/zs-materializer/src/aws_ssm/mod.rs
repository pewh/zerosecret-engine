mod ssm;
mod sts;
mod xml;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use zeroize::Zeroizing;
use zs_credential::{Credential, IdentityToken};
use zs_policy::{AwsSsmSource, CredentialSource, SourceKind};
use zs_upstream::http::{self, Network, ProxyPolicy, Roots, transport_kind};

use sts::SessionCredentials;
pub use sts::role_session_name;

use crate::{CredentialStore, MaterializationError, RetrieveContext};

pub const SESSION_MARGIN_S: u64 = 60;
pub const CALL_TIMEOUT: Duration = Duration::from_secs(5);

struct CachedSession {
    source: AwsSsmSource,
    grant_expires_at_ms: u64,
    creds: SessionCredentials,
}

pub struct SsmStore {
    http: reqwest::Client,
    sessions: Mutex<HashMap<(String, String), CachedSession>>,
}

fn transport(step: &'static str, error: &reqwest::Error) -> MaterializationError {
    MaterializationError::Transport {
        kind: SourceKind::AwsSsm,
        step,
        transport: transport_kind(error),
    }
}

impl SsmStore {
    pub fn new(network: Network) -> Result<Self, MaterializationError> {
        Self::with_timeout(network, CALL_TIMEOUT)
    }

    pub fn with_timeout(network: Network, timeout: Duration) -> Result<Self, MaterializationError> {
        let http = http::client(
            Roots::WebPki,
            timeout,
            None,
            true,
            ProxyPolicy::None,
            &network,
        )
        .map_err(|_| MaterializationError::NoStore(SourceKind::AwsSsm))?;
        Ok(Self {
            http,
            sessions: Mutex::default(),
        })
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().map_or(0, |s| s.len())
    }

    fn sweep(&self, now_ms: u64) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, s| now_ms < s.grant_expires_at_ms);
        }
    }

    fn cached_session(
        &self,
        key: &(String, String),
        source: &AwsSsmSource,
        now_ms: u64,
    ) -> Option<SessionCredentials> {
        let mut sessions = self.sessions.lock().ok()?;
        match sessions.get(key) {
            Some(s)
                if s.source == *source
                    && (now_ms / 1000).saturating_add(SESSION_MARGIN_S) < s.creds.expires_at =>
            {
                Some(s.creds.clone())
            }
            Some(_) => {
                sessions.remove(key);
                None
            }
            None => None,
        }
    }

    fn drop_session(&self, key: &(String, String)) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(key);
        }
    }

    async fn assume_role(
        &self,
        source: &AwsSsmSource,
        subject: &str,
        token: &IdentityToken,
    ) -> Result<SessionCredentials, MaterializationError> {
        let policy = sts::session_policy(source)?;
        let session_name = sts::role_session_name(subject);
        let fields = sts::form_fields(source, &session_name, &policy, token.expose());
        let body = sts::form_body(&fields);
        drop(fields);
        let url = format!("https://{}/", sts::endpoint_host(source.region.as_str()));
        let response = self
            .http
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body.as_bytes().to_vec())
            .send()
            .await
            .map_err(|e| transport("sts", &e))?;
        let status = response.status().as_u16();
        let body = Zeroizing::new(
            response
                .bytes()
                .await
                .map_err(|e| transport("sts", &e))?
                .to_vec(),
        );
        let text = std::str::from_utf8(&body).map_err(|_| MaterializationError::Refused {
            kind: SourceKind::AwsSsm,
            step: "sts",
            code: "MalformedResponse".to_string(),
        })?;
        sts::parse_response(status, text)
    }

    async fn get_parameter(
        &self,
        source: &AwsSsmSource,
        session: &SessionCredentials,
        now_ms: u64,
    ) -> Result<Credential, MaterializationError> {
        let date = zs_proto_http::sigv4::amz_date(UNIX_EPOCH + Duration::from_millis(now_ms));
        let signed = ssm::signed_request(source, session, &date)?;
        let url = format!("https://{}/", ssm::endpoint_host(source.region.as_str()));
        let mut request = self.http.post(url);
        for (name, value) in &signed.headers {
            request = request.header(*name, value.as_str());
        }
        let response = request
            .body(signed.body)
            .send()
            .await
            .map_err(|e| transport("ssm", &e))?;
        let status = response.status().as_u16();
        let error_type = response
            .headers()
            .get("x-amzn-ErrorType")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = Zeroizing::new(
            response
                .bytes()
                .await
                .map_err(|e| transport("ssm", &e))?
                .to_vec(),
        );
        ssm::parse_response(status, error_type.as_deref(), &body)
    }
}

#[async_trait::async_trait]
impl CredentialStore for SsmStore {
    fn kind(&self) -> SourceKind {
        SourceKind::AwsSsm
    }

    async fn retrieve(&self, cx: &RetrieveContext<'_>) -> Result<Credential, MaterializationError> {
        let grant = cx.grant.grant();
        let CredentialSource::AwsSsm(source) = &grant.source else {
            return Err(MaterializationError::SourceMismatch);
        };
        self.sweep(cx.now_ms);
        let token = cx
            .identity_token
            .ok_or(MaterializationError::NoIdentityToken)?;
        let key = (grant.resource.clone(), source.role_arn.as_str().to_string());
        let mut refreshed = false;
        loop {
            let session = match self.cached_session(&key, source, cx.now_ms) {
                Some(session) => session,
                None => {
                    refreshed = true;
                    let session = self.assume_role(source, &grant.subject, token).await?;
                    if let Ok(mut sessions) = self.sessions.lock() {
                        sessions.insert(
                            key.clone(),
                            CachedSession {
                                source: source.clone(),
                                grant_expires_at_ms: grant.expires_at_ms,
                                creds: session.clone(),
                            },
                        );
                    }
                    session
                }
            };
            if let Ok(mut sessions) = self.sessions.lock()
                && let Some(cached) = sessions.get_mut(&key)
            {
                cached.grant_expires_at_ms = grant.expires_at_ms;
            }
            match self.get_parameter(source, &session, cx.now_ms).await {
                Ok(value) => return Ok(value),
                Err(MaterializationError::SessionExpired) => {
                    self.drop_session(&key);
                    if refreshed {
                        return Err(MaterializationError::SessionExpired);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn forget(&self, resource: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|(r, _), _| r != resource);
        }
    }
}

pub(crate) fn safe_code(code: &str) -> String {
    let code: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
        .take(64)
        .collect();
    if code.is_empty() {
        "unknown".into()
    } else {
        code
    }
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub(crate) fn iso8601_epoch(value: &str) -> Option<u64> {
    let b = value.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> {
        let s = value.get(from..to)?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, s) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let tail = &value[19..];
    let tail = match tail.strip_prefix('.') {
        Some(frac) => {
            let digits = frac.trim_end_matches('Z');
            if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            &frac[digits.len()..]
        }
        None => tail,
    };
    if tail != "Z"
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || s > 60
    {
        return None;
    }
    u64::try_from(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn iso8601_parses_sts_expirations() {
        assert_eq!(iso8601_epoch("2014-10-24T23:00:23Z"), Some(1_414_191_623));
        assert_eq!(
            iso8601_epoch("2014-10-24T23:00:23.123Z"),
            Some(1_414_191_623)
        );
        assert_eq!(iso8601_epoch("2014-10-24 23:00:23Z"), None);
        assert_eq!(iso8601_epoch("2014-10-24T23:00:23+01:00"), None);
    }
}
