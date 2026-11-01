use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;
use zs_protocol::Denied;

pub(crate) const ALGORITHM: &str = "AWS4-HMAC-SHA256";

pub struct Scope<'a> {
    pub access_key_id: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

pub enum Query<'a> {
    Raw(&'a str),
    Pairs(Vec<(String, String)>),
}

pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Query<'a>,
    pub headers: &'a [(&'a str, &'a str)],
    pub payload_sha256: &'a str,
}

pub struct Signature {
    pub signed_headers: String,
    pub signature: String,
    pub credential: String,
}

impl Signature {
    pub fn authorization(&self) -> String {
        format!(
            "{ALGORITHM} Credential={}, SignedHeaders={}, Signature={}",
            self.credential, self.signed_headers, self.signature
        )
    }
}

pub fn payload_sha256(body: &[u8]) -> String {
    sha256_hex(body)
}

pub fn amz_date(now: SystemTime) -> String {
    let seconds = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3_600,
        (rest / 60) % 60,
        rest % 60
    )
}

pub fn sign(
    secret: &[u8],
    amz_date: &str,
    scope: &Scope<'_>,
    req: &Request<'_>,
) -> Result<Signature, Denied> {
    if !valid_amz_date(amz_date) {
        return Err(Denied::new("aws-sigv4 needs a valid x-amz-date"));
    }
    let date = &amz_date[..8];
    let (canonical_headers, signed_headers, names) = canonical_headers(req.headers)?;
    if !names.iter().any(|name| name == "host") {
        return Err(Denied::new("aws-sigv4 must sign the host header"));
    }
    let query = match &req.query {
        Query::Raw(raw) => canonical_query(query_pairs(raw)),
        Query::Pairs(pairs) => canonical_query(pairs.clone()),
    };
    let canonical_request = format!(
        "{}\n{}\n{query}\n{canonical_headers}\n{signed_headers}\n{}",
        req.method,
        canonical_path(req.path),
        req.payload_sha256
    );
    let credential = credential_scope(scope, date);
    let scope_string = format!("{date}/{}/{}/aws4_request", scope.region, scope.service);
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope_string}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let initial = {
        let mut key = Vec::with_capacity(4 + secret.len());
        key.extend_from_slice(b"AWS4");
        key.extend_from_slice(secret);
        Zeroizing::new(key)
    };
    let k_date = Zeroizing::new(hmac_sha256(&initial, date.as_bytes()));
    let k_region = Zeroizing::new(hmac_sha256(&k_date, scope.region.as_bytes()));
    let k_service = Zeroizing::new(hmac_sha256(&k_region, scope.service.as_bytes()));
    let k_signing = Zeroizing::new(hmac_sha256(&k_service, b"aws4_request"));
    Ok(Signature {
        signed_headers,
        signature: hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes())),
        credential,
    })
}

fn canonical_headers(headers: &[(&str, &str)]) -> Result<(String, String, Vec<String>), Denied> {
    let mut pairs: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), collapse(value)))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut canonical = String::new();
    let mut names: Vec<String> = Vec::new();
    let mut index = 0;
    while index < pairs.len() {
        let name = &pairs[index].0;
        let mut values = vec![pairs[index].1.clone()];
        let mut next = index + 1;
        while next < pairs.len() && pairs[next].0 == *name {
            values.push(pairs[next].1.clone());
            next += 1;
        }
        canonical.push_str(&format!("{name}:{}\n", values.join(",")));
        names.push(name.clone());
        index = next;
    }
    if names.is_empty() {
        return Err(Denied::new("aws-sigv4 needs at least one signed header"));
    }
    Ok((canonical, names.join(";"), names))
}

fn valid_amz_date(value: &str) -> bool {
    value.len() == 16
        && value.as_bytes()[8] == b'T'
        && value.ends_with('Z')
        && value[..8].bytes().all(|b| b.is_ascii_digit())
        && value[9..15].bytes().all(|b| b.is_ascii_digit())
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

pub(crate) fn credential_scope(scope: &Scope<'_>, date: &str) -> String {
    format!(
        "{}/{date}/{}/{}/aws4_request",
        scope.access_key_id, scope.region, scope.service
    )
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return Vec::new();
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub(crate) fn percent_decode(value: &str) -> Vec<u8> {
    let hex_digit = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).copied().and_then(hex_digit),
                bytes.get(i + 2).copied().and_then(hex_digit),
            )
        {
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

pub(crate) fn aws_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(crate) fn canonical_path(path: &str) -> String {
    path.split('/')
        .map(|segment| aws_encode(&percent_decode(segment)))
        .collect::<Vec<_>>()
        .join("/")
}

pub(crate) fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (
                aws_encode(&percent_decode(k)),
                aws_encode(&percent_decode(v)),
            )
        })
        .collect()
}

pub(crate) fn canonical_query(mut pairs: Vec<(String, String)>) -> String {
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub(crate) fn collapse(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::time::Duration;

    #[test]
    fn amz_date_formats_epoch_zero() {
        assert_eq!(amz_date(UNIX_EPOCH), "19700101T000000Z");
        assert_eq!(
            amz_date(UNIX_EPOCH + Duration::from_secs(1_369_353_600)),
            "20130524T000000Z"
        );
        assert_eq!(
            amz_date(UNIX_EPOCH + Duration::from_secs(1_709_251_199)),
            "20240229T235959Z"
        );
    }

    #[test]
    fn sign_refuses_headers_without_host() {
        let scope = Scope {
            access_key_id: "AKID",
            region: "ap-southeast-1",
            service: "ssm",
        };
        let headers = [("x-amz-date", "20130524T000000Z")];
        let request = Request {
            method: "POST",
            path: "/",
            query: Query::Raw(""),
            headers: &headers,
            payload_sha256: "UNSIGNED-PAYLOAD",
        };
        assert!(sign(b"secret", "20130524T000000Z", &scope, &request).is_err());
    }

    #[test]
    fn sign_matches_aws_sigv4_crate_for_an_ssm_post() {
        use aws_credential_types::Credentials;
        use aws_sigv4::http_request::{
            PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings, sign as aws_sign,
        };
        use aws_smithy_runtime_api::client::identity::Identity;

        let body = br#"{"Name":"/acme/prod/DB_PASSWORD","WithDecryption":true}"#;
        let amz = "20261027T031500Z";
        let token = "session-token";
        let host = "ssm.ap-southeast-1.amazonaws.com";
        let digest = payload_sha256(body);

        let scope = Scope {
            access_key_id: "AKIDEXAMPLE",
            region: "ap-southeast-1",
            service: "ssm",
        };
        let headers = [
            ("host", host),
            ("x-amz-content-sha256", digest.as_str()),
            ("x-amz-date", amz),
            ("x-amz-security-token", token),
            ("x-amz-target", "AmazonSSM.GetParameter"),
        ];
        let request = Request {
            method: "POST",
            path: "/",
            query: Query::Raw(""),
            headers: &headers,
            payload_sha256: &digest,
        };
        let ours = sign(
            b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            amz,
            &scope,
            &request,
        )
        .unwrap();

        let identity: Identity = Credentials::new(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            Some(token.to_string()),
            None,
            "test",
        )
        .into();
        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let params = aws_sigv4::sign::v4::SigningParams::builder()
            .identity(&identity)
            .region("ap-southeast-1")
            .name("ssm")
            .time(UNIX_EPOCH + Duration::from_secs(1_793_070_900))
            .settings(settings)
            .build()
            .unwrap()
            .into();
        let uri = format!("https://{host}/");
        let signable = SignableRequest::new(
            "POST",
            uri,
            [("host", host), ("x-amz-target", "AmazonSSM.GetParameter")].into_iter(),
            SignableBody::Bytes(body),
        )
        .unwrap();
        let (instructions, _) = aws_sign(signable, &params).unwrap().into_parts();
        let expected = instructions
            .headers()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.to_string())
            .unwrap();
        assert_eq!(ours.authorization(), expected);
    }
}
