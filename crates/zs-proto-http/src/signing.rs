use crate::sigv4::{
    ALGORITHM, Query, Request, Scope, aws_encode, canonical_query, collapse, credential_scope, hex,
    hmac_sha256, percent_decode, query_pairs, sha256_hex, sign,
};
use zs_credential::Credential;
use zs_identity::WorkloadLabel;
use zs_protocol::{Context, Denied, Destination, InjectedRequest, Protocol};

const MAX_PRESIGN_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_PRESIGN_ENDPOINT_SECONDS: u64 = 15 * 60;
const MAX_PRESIGN_SKEW_SECONDS: u64 = 15 * 60;

fn secret_of(credential: &Credential) -> Result<&str, Denied> {
    std::str::from_utf8(credential.expose())
        .map_err(|_| Denied::new("credential is not valid utf-8 for signing"))
}

fn allowed(workloads: &[WorkloadLabel], context: &Context) -> Result<(), Denied> {
    if workloads
        .iter()
        .any(|w| w.as_str() == context.workload.as_str())
    {
        Ok(())
    } else {
        Err(Denied::new("workload has no grant"))
    }
}

fn presign_expiry(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn valid_amz_date(value: &str) -> bool {
    value.len() == 16
        && value.as_bytes()[8] == b'T'
        && value.ends_with('Z')
        && value[..8].bytes().all(|b| b.is_ascii_digit())
        && value[9..15].bytes().all(|b| b.is_ascii_digit())
}

fn amz_epoch(value: &str) -> Option<u64> {
    if !valid_amz_date(value) {
        return None;
    }
    let field = |from: usize, to: usize| value[from..to].parse::<i64>().ok();
    let (year, month, day) = (field(0, 4)?, field(4, 6)?, field(6, 8)?);
    let (hour, minute, second) = (field(9, 11)?, field(11, 13)?, field(13, 15)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).ok()
}

// Re-signs AWS Signature Version 4 requests. The client signs with a placeholder secret; the
// agent recomputes the signature with the real secret, for the real host, under the access key,
// region and service the binding names, so the client cannot pick another scope.
pub struct AwsSigV4 {
    host: String,
    access_key_id: String,
    region: String,
    service: String,
    allowed_workloads: Vec<WorkloadLabel>,
}

impl AwsSigV4 {
    pub fn new(
        host: impl Into<String>,
        access_key_id: impl Into<String>,
        region: impl Into<String>,
        service: impl Into<String>,
        allowed_workloads: Vec<WorkloadLabel>,
    ) -> Self {
        Self {
            host: host.into(),
            access_key_id: access_key_id.into(),
            region: region.into(),
            service: service.into(),
            allowed_workloads,
        }
    }

    fn scope(&self) -> Scope<'_> {
        Scope {
            access_key_id: &self.access_key_id,
            region: &self.region,
            service: &self.service,
        }
    }

    // The proxy pins `Host` to the authority it forwards: the host, and the port when it is not
    // the scheme's default. Only the binding's host may be signed.
    fn signed_authority<'a>(&self, authority: &'a str) -> Result<&'a str, Denied> {
        let host = match authority.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                host
            }
            Some(_) => return Err(Denied::new("aws-sigv4 needs a host and port it can sign")),
            None => authority,
        };
        if host.eq_ignore_ascii_case(&self.host) {
            Ok(authority)
        } else {
            Err(Denied::new("aws-sigv4 signs only the binding's host"))
        }
    }

    pub(crate) fn resign_url_at(
        &self,
        authority: &str,
        path_and_query: &str,
        method: &str,
        credential: &Credential,
        now: std::time::SystemTime,
    ) -> Result<String, Denied> {
        let secret = secret_of(credential)?;
        let authority = self.signed_authority(authority)?;
        let (path, query) = path_and_query
            .split_once('?')
            .ok_or_else(|| Denied::new("a presigned URL has a query"))?;
        let pairs = query_pairs(query);
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| String::from_utf8_lossy(&percent_decode(v)).into_owned())
        };
        if get("X-Amz-Algorithm").as_deref() != Some(ALGORITHM) {
            return Err(Denied::new("a presigned URL names AWS4-HMAC-SHA256"));
        }
        if get("X-Amz-SignedHeaders").as_deref() != Some("host") {
            return Err(Denied::new("a presigned URL may sign only the host header"));
        }
        let amz_date = get("X-Amz-Date")
            .filter(|d| valid_amz_date(d))
            .ok_or_else(|| Denied::new("a presigned URL needs X-Amz-Date"))?;
        let now_seconds = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if !amz_epoch(&amz_date)
            .is_some_and(|dated| dated.abs_diff(now_seconds) <= MAX_PRESIGN_SKEW_SECONDS)
        {
            return Err(Denied::new(
                "a presigned URL must be dated within 15 minutes of now",
            ));
        }
        let expires: u64 = get("X-Amz-Expires")
            .and_then(|e| presign_expiry(&e))
            .filter(|e| (1..=MAX_PRESIGN_SECONDS).contains(e))
            .ok_or_else(|| Denied::new("a presigned URL needs X-Amz-Expires up to seven days"))?;
        let mut kept: Vec<(String, String)> = pairs
            .into_iter()
            .filter(|(k, _)| {
                !k.eq_ignore_ascii_case("X-Amz-Signature")
                    && !k.eq_ignore_ascii_case("X-Amz-Credential")
                    && !k.eq_ignore_ascii_case("X-Amz-Expires")
            })
            .collect();
        kept.push((
            "X-Amz-Credential".into(),
            aws_encode(credential_scope(&self.scope(), &amz_date[..8]).as_bytes()),
        ));
        kept.push(("X-Amz-Expires".into(), expires.to_string()));
        let query = canonical_query(kept.clone());
        let method = method.to_ascii_uppercase();
        let signature = sign(
            secret.as_bytes(),
            &amz_date,
            &self.scope(),
            &Request {
                method: &method,
                path,
                query: Query::Pairs(kept),
                headers: &[("host", authority)],
                payload_sha256: "UNSIGNED-PAYLOAD",
            },
        )?;
        Ok(format!(
            "{path}?{query}&X-Amz-Signature={}",
            signature.signature
        ))
    }
}

fn crlf_at(bytes: &[u8], at: usize) -> Option<usize> {
    bytes
        .get(at..)?
        .windows(2)
        .position(|pair| pair == b"\r\n")
        .map(|index| at + index)
}

type StreamedBody = (Vec<u8>, Vec<(String, String)>);

fn decode_streamed_body(body: &[u8]) -> Result<StreamedBody, Denied> {
    let mut decoded = Vec::new();
    let mut at = 0;
    loop {
        let line_end =
            crlf_at(body, at).ok_or_else(|| Denied::new("a streamed body has no chunk line"))?;
        let line = &body[at..line_end];
        at = line_end + 2;
        let size_text = line.split(|byte| *byte == b';').next().unwrap_or(line);
        if size_text.is_empty() || !size_text.iter().all(u8::is_ascii_hexdigit) {
            return Err(Denied::new("a streamed chunk size is not hexadecimal"));
        }
        let size_text = std::str::from_utf8(size_text)
            .map_err(|_| Denied::new("a streamed chunk size is not text"))?;
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| Denied::new("a streamed chunk size is not hexadecimal"))?;
        if size == 0 {
            break;
        }
        let end = at
            .checked_add(size)
            .ok_or_else(|| Denied::new("a streamed chunk overflows"))?;
        let chunk = body
            .get(at..end)
            .ok_or_else(|| Denied::new("a streamed chunk runs past the body"))?;
        decoded.extend_from_slice(chunk);
        at = end;
        if body.get(at..at + 2) != Some(b"\r\n") {
            return Err(Denied::new("a streamed chunk has no terminator"));
        }
        at += 2;
    }
    let mut trailers = Vec::new();
    loop {
        let line_end = crlf_at(body, at)
            .ok_or_else(|| Denied::new("a streamed body has no trailer terminator"))?;
        let line = &body[at..line_end];
        at = line_end + 2;
        if line.is_empty() {
            break;
        }
        let text =
            std::str::from_utf8(line).map_err(|_| Denied::new("a streamed trailer is not text"))?;
        let (name, value) = text
            .split_once(':')
            .ok_or_else(|| Denied::new("a streamed trailer has no colon"))?;
        let name = name.trim().to_ascii_lowercase();
        if name == "x-amz-trailer-signature" {
            continue;
        }
        if !name.starts_with("x-amz-checksum-") {
            return Err(Denied::new(
                "a streamed body carries an unexpected trailer header",
            ));
        }
        trailers.push((name, value.trim().to_string()));
    }
    if at != body.len() {
        return Err(Denied::new("a streamed body has data after its trailer"));
    }
    Ok((decoded, trailers))
}

fn signed_headers_of(authorization: Option<&str>) -> Vec<String> {
    let listed = authorization.and_then(|a| {
        a.split([',', ' '])
            .find_map(|part| part.trim().strip_prefix("SignedHeaders="))
    });
    let mut names: Vec<String> = listed
        .unwrap_or("host;x-amz-content-sha256;x-amz-date")
        .split(';')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    names.sort();
    names.dedup();
    names
}

impl Protocol for AwsSigV4 {
    fn matches(&self, destination: &Destination) -> bool {
        destination.host.eq_ignore_ascii_case(&self.host)
    }

    fn authorize(&self, context: &Context) -> Result<(), Denied> {
        allowed(&self.allowed_workloads, context)
    }

    fn inject(&self, request: &mut InjectedRequest, credential: &Credential) -> Result<(), Denied> {
        if request.header("Authorization").is_none() {
            return Ok(());
        }
        let secret = secret_of(credential)?;
        let amz_date = request
            .header("x-amz-date")
            .filter(|d| valid_amz_date(d))
            .ok_or_else(|| Denied::new("aws-sigv4 needs an x-amz-date header"))?
            .to_string();
        let mut payload = request
            .header("x-amz-content-sha256")
            .ok_or_else(|| Denied::new("aws-sigv4 needs an x-amz-content-sha256 header"))?
            .to_string();
        let mut signed = signed_headers_of(request.header("Authorization"));
        if payload.starts_with("STREAMING-") {
            if request
                .header_values("content-encoding")
                .iter()
                .flat_map(|value| value.split(','))
                .any(|encoding| !encoding.trim().eq_ignore_ascii_case("aws-chunked"))
            {
                return Err(Denied::new(
                    "a streamed body has an unexpected content-encoding",
                ));
            }
            let (decoded, trailers) = decode_streamed_body(&request.body)?;
            if let Some(expected) = request.header("x-amz-decoded-content-length") {
                let expected = expected.trim();
                let expected = (!expected.is_empty()
                    && expected.bytes().all(|b| b.is_ascii_digit()))
                .then(|| expected.parse::<usize>().ok())
                .flatten();
                if expected != Some(decoded.len()) {
                    return Err(Denied::new(
                        "a streamed body's decoded length does not match",
                    ));
                }
            }
            payload = sha256_hex(&decoded);
            request.body = decoded;
            request.set_header("x-amz-content-sha256", payload.clone());
            for (name, value) in trailers {
                request.set_header(name.clone(), value);
                signed.push(name);
            }
            request.remove_header("content-encoding");
            request.remove_header("content-length");
            request.remove_header("x-amz-trailer");
            signed.retain(|name| {
                name != "content-encoding" && name != "content-length" && name != "x-amz-trailer"
            });
            signed.sort();
            signed.dedup();
        }
        let authority = self
            .signed_authority(
                request
                    .header("Host")
                    .ok_or_else(|| Denied::new("aws-sigv4 needs a Host header"))?,
            )?
            .to_string();
        if !signed.iter().any(|h| h == "host") {
            return Err(Denied::new("aws-sigv4 must sign the host header"));
        }
        let mut headers: Vec<(String, String)> = Vec::with_capacity(signed.len());
        for name in &signed {
            if name == "host" {
                headers.push((name.clone(), authority.clone()));
                continue;
            }
            let values = request.header_values(name);
            if values.is_empty() {
                return Err(Denied::new("a signed header is missing"));
            }
            headers.push((
                name.clone(),
                values
                    .iter()
                    .map(|value| collapse(value))
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        let headers: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let (path, query) = request.path.split_once('?').unwrap_or((&request.path, ""));
        let signature = sign(
            secret.as_bytes(),
            &amz_date,
            &self.scope(),
            &Request {
                method: &request.method,
                path,
                query: Query::Raw(query),
                headers: &headers,
                payload_sha256: &payload,
            },
        )?;
        request.set_header("Authorization", signature.authorization());
        Ok(())
    }

    fn resign_url(
        &self,
        authority: &str,
        path_and_query: &str,
        method: &str,
        credential: &Credential,
    ) -> Result<String, Denied> {
        let query = path_and_query
            .split_once('?')
            .map(|(_, query)| query)
            .unwrap_or("");
        let pairs = query_pairs(query);
        let get = |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| String::from_utf8_lossy(&percent_decode(value)).into_owned())
        };
        let expires = get("X-Amz-Expires").and_then(|value| presign_expiry(&value));
        let Some(expires) = expires.filter(|expires| *expires <= MAX_PRESIGN_ENDPOINT_SECONDS)
        else {
            return Err(Denied::new("a presigned URL is capped at fifteen minutes"));
        };
        let now = std::time::SystemTime::now();
        let now_seconds = now
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if let Some(dated) = get("X-Amz-Date").and_then(|date| amz_epoch(&date))
            && dated.saturating_add(expires)
                > now_seconds.saturating_add(MAX_PRESIGN_ENDPOINT_SECONDS)
        {
            return Err(Denied::new("a presigned URL is capped at fifteen minutes"));
        }
        self.resign_url_at(authority, path_and_query, method, credential, now)
    }
}

// signature = HMAC-SHA256(key, "METHOD:<id header value>:sha256hex(body):key"), written to the
// signature header. A request without a body is signed over "{}".
pub struct HmacBodySignature {
    host: String,
    id_header: String,
    signature_header: String,
    allowed_workloads: Vec<WorkloadLabel>,
}

impl HmacBodySignature {
    pub fn new(
        host: impl Into<String>,
        id_header: impl Into<String>,
        signature_header: impl Into<String>,
        allowed_workloads: Vec<WorkloadLabel>,
    ) -> Self {
        Self {
            host: host.into(),
            id_header: id_header.into(),
            signature_header: signature_header.into(),
            allowed_workloads,
        }
    }
}

impl Protocol for HmacBodySignature {
    fn matches(&self, destination: &Destination) -> bool {
        destination.host.eq_ignore_ascii_case(&self.host)
    }

    fn authorize(&self, context: &Context) -> Result<(), Denied> {
        allowed(&self.allowed_workloads, context)
    }

    fn inject(&self, request: &mut InjectedRequest, credential: &Credential) -> Result<(), Denied> {
        let secret = secret_of(credential)?;
        let id = request
            .header(&self.id_header)
            .ok_or_else(|| Denied::new("hmac-body-signature needs its id header"))?
            .to_string();
        let signed_body: &[u8] = if request.body.is_empty() {
            b"{}"
        } else {
            &request.body
        };
        let string_to_sign = format!(
            "{}:{id}:{}:{secret}",
            request.method.to_ascii_uppercase(),
            sha256_hex(signed_body)
        );
        let signature = hex(&hmac_sha256(secret.as_bytes(), string_to_sign.as_bytes()));
        request.set_header(&self.signature_header, signature);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::sigv4::canonical_path;

    fn credential(value: &str) -> Credential {
        Credential::from_bytes(value.as_bytes().to_vec()).unwrap()
    }

    // AWS's published example: GET /test.txt with a Range header, secret
    // wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY, us-east-1, 20130524T000000Z.
    #[test]
    fn a_request_signature_matches_the_aws_reference_vector() {
        let signer = AwsSigV4::new(
            "examplebucket.s3.amazonaws.com",
            "AKIAIOSFODNN7EXAMPLE",
            "us-east-1",
            "s3",
            vec![],
        );
        let mut request = InjectedRequest {
            method: "GET".into(),
            path: "/test.txt".into(),
            headers: vec![
                ("Host".into(), "examplebucket.s3.amazonaws.com".into()),
                ("Range".into(), "bytes=0-9".into()),
                (
                    "x-amz-content-sha256".into(),
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                ),
                ("x-amz-date".into(), "20130524T000000Z".into()),
                (
                    "Authorization".into(),
                    "AWS4-HMAC-SHA256 Credential=placeholder/20130524/auto/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=00".into(),
                ),
            ],
            body: Vec::new(),
        };
        signer
            .inject(
                &mut request,
                &credential("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            )
            .unwrap();
        assert_eq!(
            request.header("Authorization"),
            Some(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            )
        );
    }

    // AWS's published presigned-URL example: GET /test.txt, 86400 s, 20130524T000000Z.
    #[test]
    fn a_presigned_url_matches_the_aws_reference_vector() {
        let signer = AwsSigV4::new(
            "examplebucket.s3.amazonaws.com",
            "AKIAIOSFODNN7EXAMPLE",
            "us-east-1",
            "s3",
            vec![],
        );
        let url = signer
            .resign_url_at(
                "examplebucket.s3.amazonaws.com",
                "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=placeholder%2F20130524%2Fauto%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=00",
                "GET",
                &credential("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
                at("20130524T000000Z"),
            )
            .unwrap();
        assert!(
            url.contains(
                "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
            ),
            "{url}"
        );
        assert!(
            url.ends_with(
                "X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "{url}"
        );
    }

    // Reference signatures from @smithy/signature-v4 (uriEscapePath: false) over the encoded
    // path /b/a%281%29%21%20x.txt; the presign one over UNSIGNED-PAYLOAD. B2 re-encodes `(`,
    // `)` and `!` before it checks.
    #[test]
    fn a_path_is_signed_in_its_aws_encoded_form() {
        let signer = AwsSigV4::new(
            "s3.example.com",
            "AKIDMATRIX",
            "eu-central-003",
            "s3",
            vec![],
        );
        for path in ["/b/a(1)!%20x.txt", "/b/a%281%29%21%20x.txt"] {
            let mut request = InjectedRequest {
                method: "GET".into(),
                path: path.into(),
                headers: vec![
                    ("Host".into(), "s3.example.com".into()),
                    ("x-amz-content-sha256".into(), "UNSIGNED-PAYLOAD".into()),
                    ("x-amz-date".into(), "20261016T120000Z".into()),
                    (
                        "Authorization".into(),
                        "AWS4-HMAC-SHA256 Credential=placeholder/20261016/auto/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=00".into(),
                    ),
                ],
                body: Vec::new(),
            };
            signer
                .inject(&mut request, &credential("matrix-secret"))
                .unwrap();
            assert!(
                request.header("Authorization").unwrap().ends_with(
                    "Signature=e0e46f4c14aabbe6bb6c066f48167edb88b09afdc2be7a192bd54fc20f9f2997"
                ),
                "{path}"
            );
            assert_eq!(request.path, path, "the forwarded path is unchanged");
        }
        let url = signer
            .resign_url_at(
                "s3.example.com",
                "/b/a(1)!%20x.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=placeholder%2F20261016%2Fauto%2Fs3%2Faws4_request&X-Amz-Date=20261016T120000Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=00",
                "GET",
                &credential("matrix-secret"),
                at("20261016T120000Z"),
            )
            .unwrap();
        assert!(
            url.ends_with(
                "X-Amz-Signature=3b88d9bdc385564e8bad7596a80df48ff977d4ee7e3c64f43b0644dd1b16a720"
            ),
            "{url}"
        );
    }

    // Reference signatures from @smithy/signature-v4 for host s3.example.com, port 8443. The
    // proxy pins `Host` to the authority it forwards, so a non-443 port is signed with it.
    #[test]
    fn a_non_default_port_is_signed_with_the_host() {
        let signer = AwsSigV4::new(
            "s3.example.com",
            "AKIDMATRIX",
            "eu-central-003",
            "s3",
            vec![],
        );
        let request = |host: Option<&str>| {
            InjectedRequest {
            method: "GET".into(),
            path: "/b/k.txt".into(),
            headers: host
                .map(|h| ("Host".to_string(), h.to_string()))
                .into_iter()
                .chain([
                    ("x-amz-content-sha256".into(), "UNSIGNED-PAYLOAD".into()),
                    ("x-amz-date".into(), "20261016T120000Z".into()),
                    (
                        "Authorization".into(),
                        "AWS4-HMAC-SHA256 Credential=placeholder/20261016/auto/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=00".into(),
                    ),
                ])
                .collect(),
            body: Vec::new(),
        }
        };
        let cred = credential("matrix-secret");
        let mut ported = request(Some("s3.example.com:8443"));
        signer.inject(&mut ported, &cred).unwrap();
        assert!(
            ported.header("Authorization").unwrap().ends_with(
                "Signature=4144a42854abce324f6eb8f6fab699aab232062bebe46c471e086223281de568"
            ),
            "{:?}",
            ported.header("Authorization")
        );
        for host in [
            Some("evil.example"),
            Some("evil.example:8443"),
            Some("s3.example.com.evil:8443"),
            Some("s3.example.com:x"),
            None,
        ] {
            assert!(
                signer.inject(&mut request(host), &cred).is_err(),
                "{host:?}"
            );
        }
        let url = signer
            .resign_url_at(
                "s3.example.com:8443",
                "/b/k.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=placeholder%2F20261016%2Fauto%2Fs3%2Faws4_request&X-Amz-Date=20261016T120000Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=00",
                "GET",
                &cred,
                at("20261016T120000Z"),
            )
            .unwrap();
        assert!(
            url.ends_with(
                "X-Amz-Signature=7b1bffcc2cae3bc429c188f3e957097aa21237276e46e3f6c71b72eee418610b"
            ),
            "{url}"
        );
        assert!(
            signer
                .resign_url_at(
                    "evil.example",
                    "/b/k.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20261016T120000Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=00",
                    "GET",
                    &cred,
                    at("20261016T120000Z"),
                )
                .is_err()
        );
    }

    #[test]
    fn a_path_segment_is_decoded_then_aws_encoded() {
        assert_eq!(canonical_path("/b/a(1)!*'.txt"), "/b/a%281%29%21%2A%27.txt");
        assert_eq!(canonical_path("/b/a%2Fb/c~d"), "/b/a%2Fb/c~d");
        assert_eq!(canonical_path("/b/caf%c3%a9"), "/b/caf%C3%A9");
        assert_eq!(canonical_path("/"), "/");
        assert_eq!(canonical_path("/b//k/"), "/b//k/");
    }

    #[test]
    fn streaming_payloads_and_unsigned_hosts_are_refused() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let base = |payload: &str, signed: &str| InjectedRequest {
            method: "PUT".into(),
            path: "/b/k".into(),
            headers: vec![
                ("Host".into(), "s3.example.com".into()),
                ("x-amz-content-sha256".into(), payload.into()),
                ("x-amz-date".into(), "20261016T000000Z".into()),
                (
                    "Authorization".into(),
                    format!("AWS4-HMAC-SHA256 Credential=x, SignedHeaders={signed}, Signature=0"),
                ),
            ],
            body: Vec::new(),
        };
        let cred = credential("s");
        assert!(
            signer
                .inject(
                    &mut base("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "host;x-amz-date"),
                    &cred
                )
                .is_err()
        );
        assert!(
            signer
                .inject(&mut base("UNSIGNED-PAYLOAD", "x-amz-date"), &cred)
                .is_err()
        );
        assert!(
            signer
                .inject(&mut base("UNSIGNED-PAYLOAD", "host;x-amz-date"), &cred)
                .is_ok()
        );
    }

    #[test]
    fn a_streamed_body_is_decoded_and_re_signed() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let mut request = InjectedRequest {
            method: "PUT".into(),
            path: "/b/k".into(),
            headers: vec![
                ("Host".into(), "s3.example.com".into()),
                (
                    "x-amz-content-sha256".into(),
                    "STREAMING-UNSIGNED-PAYLOAD-TRAILER".into(),
                ),
                ("x-amz-date".into(), "20261016T000000Z".into()),
                ("content-encoding".into(), "aws-chunked".into()),
                ("x-amz-decoded-content-length".into(), "5".into()),
                (
                    "Authorization".into(),
                    "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length, Signature=0".into(),
                ),
            ],
            body: b"5\r\nhello\r\n0\r\n\r\n".to_vec(),
        };
        signer
            .inject(&mut request, &credential("streamed-secret"))
            .unwrap();
        assert_eq!(request.body, b"hello");
        assert_eq!(
            request.header("x-amz-content-sha256"),
            Some(sha256_hex(b"hello").as_str())
        );
        assert!(request.header("content-encoding").is_none());
        let authorization = request.header("Authorization").unwrap();
        assert!(
            !authorization.contains("content-encoding"),
            "{authorization}"
        );
        assert!(
            authorization.contains(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length"
            ),
            "{authorization}"
        );
    }

    #[test]
    fn a_streamed_checksum_trailer_is_lifted_into_a_header() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let mut request = InjectedRequest {
            method: "PUT".into(),
            path: "/b/k".into(),
            headers: vec![
                ("Host".into(), "s3.example.com".into()),
                (
                    "x-amz-content-sha256".into(),
                    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".into(),
                ),
                ("x-amz-date".into(), "20261016T000000Z".into()),
                ("content-encoding".into(), "aws-chunked".into()),
                ("x-amz-trailer".into(), "x-amz-checksum-crc32".into()),
                (
                    "Authorization".into(),
                    "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-date;x-amz-trailer, Signature=0"
                        .into(),
                ),
            ],
            body: b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\nx-amz-trailer-signature:0000\r\n\r\n".to_vec(),
        };
        signer
            .inject(&mut request, &credential("streamed-secret"))
            .unwrap();
        assert_eq!(request.header("x-amz-checksum-crc32"), Some("AAAAAA=="));
        assert!(request.header("x-amz-trailer").is_none());
        assert!(request.header("x-amz-trailer-signature").is_none());
        assert!(request.header("content-encoding").is_none());
        let authorization = request.header("Authorization").unwrap();
        assert!(!authorization.contains("x-amz-trailer"), "{authorization}");
        assert!(
            authorization.contains("SignedHeaders=host;x-amz-checksum-crc32;x-amz-date,"),
            "{authorization}"
        );
    }

    #[test]
    fn a_streamed_body_with_a_second_content_encoding_header_is_refused() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let mut request = InjectedRequest {
            method: "PUT".into(),
            path: "/b/k".into(),
            headers: vec![
                ("Host".into(), "s3.example.com".into()),
                (
                    "x-amz-content-sha256".into(),
                    "STREAMING-UNSIGNED-PAYLOAD-TRAILER".into(),
                ),
                ("x-amz-date".into(), "20261016T000000Z".into()),
                ("content-encoding".into(), "aws-chunked".into()),
                ("content-encoding".into(), "gzip".into()),
                (
                    "Authorization".into(),
                    "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-date, Signature=0"
                        .into(),
                ),
            ],
            body: b"5\r\nhello\r\n0\r\n\r\n".to_vec(),
        };
        assert!(
            signer
                .inject(&mut request, &credential("streamed-secret"))
                .is_err()
        );
    }

    #[test]
    fn a_streamed_body_with_the_wrong_decoded_length_is_refused() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let mut request = InjectedRequest {
            method: "PUT".into(),
            path: "/b/k".into(),
            headers: vec![
                ("Host".into(), "s3.example.com".into()),
                (
                    "x-amz-content-sha256".into(),
                    "STREAMING-UNSIGNED-PAYLOAD-TRAILER".into(),
                ),
                ("x-amz-date".into(), "20261016T000000Z".into()),
                ("x-amz-decoded-content-length".into(), "6".into()),
                (
                    "Authorization".into(),
                    "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-date, Signature=0"
                        .into(),
                ),
            ],
            body: b"5\r\nhello\r\n0\r\n\r\n".to_vec(),
        };
        assert!(
            signer
                .inject(&mut request, &credential("streamed-secret"))
                .is_err()
        );
    }

    #[test]
    fn an_unexpected_trailer_header_is_refused() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let mut request = InjectedRequest {
            method: "PUT".into(),
            path: "/b/k".into(),
            headers: vec![
                ("Host".into(), "s3.example.com".into()),
                (
                    "x-amz-content-sha256".into(),
                    "STREAMING-UNSIGNED-PAYLOAD-TRAILER".into(),
                ),
                ("x-amz-date".into(), "20261016T000000Z".into()),
                (
                    "Authorization".into(),
                    "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-date, Signature=0"
                        .into(),
                ),
            ],
            body: b"5\r\nhello\r\n0\r\nx-amz-meta-other:value\r\n\r\n".to_vec(),
        };
        assert!(
            signer
                .inject(&mut request, &credential("streamed-secret"))
                .is_err()
        );
    }

    #[test]
    fn a_streamed_body_with_another_content_encoding_is_refused() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let mut request = InjectedRequest {
            method: "PUT".into(),
            path: "/b/k".into(),
            headers: vec![
                ("Host".into(), "s3.example.com".into()),
                (
                    "x-amz-content-sha256".into(),
                    "STREAMING-UNSIGNED-PAYLOAD-TRAILER".into(),
                ),
                ("x-amz-date".into(), "20261016T000000Z".into()),
                ("content-encoding".into(), "aws-chunked,gzip".into()),
                (
                    "Authorization".into(),
                    "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-date, Signature=0"
                        .into(),
                ),
            ],
            body: b"5\r\nhello\r\n0\r\n\r\n".to_vec(),
        };
        assert!(
            signer
                .inject(&mut request, &credential("streamed-secret"))
                .is_err()
        );
    }

    #[test]
    fn a_streamed_chunk_past_the_body_is_refused() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let mut headers = vec![
            ("Host".to_string(), "s3.example.com".to_string()),
            (
                "x-amz-content-sha256".to_string(),
                "STREAMING-UNSIGNED-PAYLOAD-TRAILER".to_string(),
            ),
            ("x-amz-date".to_string(), "20261016T000000Z".to_string()),
            (
                "Authorization".to_string(),
                "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-date, Signature=0"
                    .to_string(),
            ),
        ];
        for body in [
            b"5\r\nhel".to_vec(),
            b"zz\r\nhello\r\n0\r\n\r\n".to_vec(),
            b"5\r\nhello\r\n".to_vec(),
            b"+5\r\nhello\r\n0\r\n\r\n".to_vec(),
            b"5\r\nhello\r\n0\r\n\r\nEXTRA-DATA".to_vec(),
        ] {
            let mut request = InjectedRequest {
                method: "PUT".into(),
                path: "/b/k".into(),
                headers: headers.clone(),
                body,
            };
            assert!(
                signer
                    .inject(&mut request, &credential("streamed-secret"))
                    .is_err()
            );
            headers = request.headers;
        }
    }

    #[test]
    fn the_presign_endpoint_caps_its_expiry() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let cred = credential("presign-secret");
        let long = "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=placeholder%2F20261016%2Fauto%2Fs3%2Faws4_request&X-Amz-Date=20261016T120000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=0";
        let error = signer
            .resign_url("s3.example.com", long, "GET", &cred)
            .unwrap_err();
        assert!(error.reason.contains("fifteen minutes"), "{}", error.reason);
        for expires in ["+86400", "%2B86400", "901", "", "abc"] {
            let url = long.replace("X-Amz-Expires=86400", &format!("X-Amz-Expires={expires}"));
            let error = signer
                .resign_url("s3.example.com", &url, "GET", &cred)
                .unwrap_err();
            assert!(
                error.reason.contains("fifteen minutes"),
                "{expires}: {}",
                error.reason
            );
        }
        let missing = long.replace("&X-Amz-Expires=86400", "");
        let error = signer
            .resign_url("s3.example.com", &missing, "GET", &cred)
            .unwrap_err();
        assert!(error.reason.contains("fifteen minutes"), "{}", error.reason);
        let within = long.replace("X-Amz-Expires=86400", "X-Amz-Expires=900");
        let error = signer
            .resign_url("s3.example.com", &within, "GET", &cred)
            .unwrap_err();
        assert!(
            !error.reason.contains("fifteen minutes"),
            "{}",
            error.reason
        );
    }

    fn amz_date_of(epoch: u64) -> String {
        let days = i64::try_from(epoch / 86_400).unwrap();
        let rest = epoch % 86_400;
        let shifted = days + 719_468;
        let era = shifted.div_euclid(146_097);
        let day_of_era = shifted - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_index = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_index + 2) / 5 + 1;
        let month = if month_index < 10 {
            month_index + 3
        } else {
            month_index - 9
        };
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        format!(
            "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
            rest / 3_600,
            rest % 3_600 / 60,
            rest % 60
        )
    }

    #[test]
    fn an_endpoint_presign_dated_ahead_cannot_outlive_fifteen_minutes() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let cred = credential("presign-secret");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(amz_epoch(&amz_date_of(now)), Some(now));
        let url = |dated: u64| {
            format!(
                "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date={}&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=0",
                amz_date_of(dated)
            )
        };
        let error = signer
            .resign_url("s3.example.com", &url(now + 600), "GET", &cred)
            .unwrap_err();
        assert_eq!(error.reason, "a presigned URL is capped at fifteen minutes");
        assert!(
            signer
                .resign_url("s3.example.com", &url(now), "GET", &cred)
                .is_ok()
        );
    }

    #[test]
    fn a_presigned_url_needs_a_valid_amz_date() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let cred = credential("presign-secret");
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let url = |date: &str| {
            format!(
                "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256{date}&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=0"
            )
        };
        let signed = signer
            .resign_url_at(
                "s3.example.com",
                &url("&X-Amz-Date=20231114T221320Z"),
                "GET",
                &cred,
                now,
            )
            .unwrap();
        assert!(signed.contains("X-Amz-Date=20231114T221320Z"), "{signed}");
        for date in [
            "",
            "&X-Amz-Date=",
            "&X-Amz-Date=2023-11-14T22:13:20Z",
            "&X-Amz-Date=20231114T221320",
            "&X-Amz-Date=20231114T22132oZ",
        ] {
            let error = signer
                .resign_url_at("s3.example.com", &url(date), "GET", &cred, now)
                .unwrap_err();
            assert_eq!(error.reason, "a presigned URL needs X-Amz-Date", "{date}");
        }
    }

    #[test]
    fn repeated_signed_header_values_are_joined_with_commas() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let request = |values: Vec<(&str, &str)>| {
            let mut headers = vec![
                ("Host".to_string(), "s3.example.com".to_string()),
                ("x-amz-content-sha256".to_string(), "UNSIGNED-PAYLOAD".to_string()),
                ("x-amz-date".to_string(), "20261016T000000Z".to_string()),
                (
                    "Authorization".to_string(),
                    "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;my-header1;x-amz-date, Signature=0".to_string(),
                ),
            ];
            for (name, value) in values {
                headers.push((name.to_string(), value.to_string()));
            }
            InjectedRequest {
                method: "GET".into(),
                path: "/".into(),
                headers,
                body: Vec::new(),
            }
        };
        let cred = credential("duplicate-header-secret");
        let mut repeated = request(vec![
            ("My-Header1", "value2"),
            ("My-Header1", "value2"),
            ("My-Header1", "value1"),
        ]);
        let mut joined = request(vec![("My-Header1", "value2,value2,value1")]);
        signer.inject(&mut repeated, &cred).unwrap();
        signer.inject(&mut joined, &cred).unwrap();
        assert_eq!(
            repeated.header("Authorization"),
            joined.header("Authorization")
        );
        assert!(
            !repeated
                .header("Authorization")
                .unwrap()
                .ends_with("Signature=0")
        );
    }

    #[test]
    fn a_query_signed_request_is_forwarded_unchanged() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let mut request = InjectedRequest {
            method: "GET".into(),
            path: "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc".into(),
            headers: vec![],
            body: Vec::new(),
        };
        signer.inject(&mut request, &credential("s")).unwrap();
        assert!(request.header("Authorization").is_none());
        assert_eq!(
            request.path,
            "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc"
        );
    }

    #[test]
    fn an_anonymous_request_is_forwarded_unchanged() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let mut request = InjectedRequest {
            method: "GET".into(),
            path: "/b/public.png".into(),
            headers: vec![("Host".into(), "s3.example.com".into())],
            body: Vec::new(),
        };
        signer.inject(&mut request, &credential("s")).unwrap();
        assert!(request.header("Authorization").is_none());
        assert_eq!(request.path, "/b/public.png");
    }

    #[test]
    fn a_presigned_url_that_signs_more_than_host_or_lasts_too_long_is_refused() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let cred = credential("s");
        let url = |signed: &str, expires: u64| {
            format!(
                "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20261016T000000Z&X-Amz-Expires={expires}&X-Amz-SignedHeaders={signed}&X-Amz-Signature=0"
            )
        };
        let now = at("20261016T000000Z");
        assert!(
            signer
                .resign_url_at("s3.example.com", &url("host", 600), "GET", &cred, now)
                .is_ok()
        );
        assert!(
            signer
                .resign_url_at(
                    "s3.example.com",
                    &url("host%3Bcontent-type", 600),
                    "PUT",
                    &cred,
                    now
                )
                .is_err()
        );
        assert!(
            signer
                .resign_url_at(
                    "s3.example.com",
                    &url("host", MAX_PRESIGN_SECONDS + 1),
                    "GET",
                    &cred,
                    now
                )
                .is_err()
        );
    }

    fn at(amz_date: &str) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(amz_epoch(amz_date).unwrap())
    }

    #[test]
    fn an_amz_date_converts_to_unix_seconds() {
        assert_eq!(amz_epoch("19700101T000000Z"), Some(0));
        assert_eq!(amz_epoch("20130524T000000Z"), Some(1_369_353_600));
        assert_eq!(amz_epoch("20240229T235959Z"), Some(1_709_251_199));
        assert_eq!(amz_epoch("20261332T000000Z"), None);
    }

    // The seven-day cap counts from X-Amz-Date, so a far-dated URL would outlive it.
    #[test]
    fn a_presigned_url_dated_more_than_fifteen_minutes_from_now_is_refused() {
        let signer = AwsSigV4::new("s3.example.com", "AKID", "r", "s3", vec![]);
        let cred = credential("s");
        let url = "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20261016T120000Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=0";
        for (now, ok) in [
            ("20261016T120000Z", true),
            ("20261016T121500Z", true),
            ("20261016T114500Z", true),
            ("20261016T121501Z", false),
            ("20261016T114459Z", false),
            ("20261015T120000Z", false),
        ] {
            assert_eq!(
                signer
                    .resign_url_at("s3.example.com", url, "GET", &cred, at(now))
                    .is_ok(),
                ok,
                "now {now}"
            );
        }
    }

    fn hmac_signer() -> HmacBodySignature {
        HmacBodySignature::new("pay.example.com", "va", "signature", vec![])
    }

    #[test]
    fn the_hmac_body_signature_covers_method_id_and_body() {
        let signer = hmac_signer();
        let body = br#"{"account":"0000001234567890"}"#.to_vec();
        let mut request = InjectedRequest {
            method: "POST".into(),
            path: "/api/v2/balance".into(),
            headers: vec![
                ("va".into(), "0000001234567890".into()),
                ("signature".into(), "placeholder".into()),
            ],
            body: body.clone(),
        };
        signer
            .inject(&mut request, &credential("SANDBOX-KEY"))
            .unwrap();
        let expected = hex(&hmac_sha256(
            b"SANDBOX-KEY",
            format!("POST:0000001234567890:{}:SANDBOX-KEY", sha256_hex(&body)).as_bytes(),
        ));
        assert_eq!(request.header("signature"), Some(expected.as_str()));
        assert_eq!(
            request
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("signature"))
                .count(),
            1
        );
        request.remove_header("va");
        assert!(
            signer
                .inject(&mut request, &credential("SANDBOX-KEY"))
                .is_err()
        );
    }

    #[test]
    fn a_request_without_a_body_is_signed_over_an_empty_object() {
        let signer = hmac_signer();
        let mut request = InjectedRequest {
            method: "GET".into(),
            path: "/api/v2/payment-channels".into(),
            headers: vec![("va".into(), "0000001234567890".into())],
            body: Vec::new(),
        };
        signer
            .inject(&mut request, &credential("SANDBOX-KEY"))
            .unwrap();
        let expected = hex(&hmac_sha256(
            b"SANDBOX-KEY",
            format!("GET:0000001234567890:{}:SANDBOX-KEY", sha256_hex(b"{}")).as_bytes(),
        ));
        assert_eq!(request.header("signature"), Some(expected.as_str()));
        assert!(request.body.is_empty());
    }

    #[test]
    fn the_header_names_come_from_the_binding() {
        let signer = HmacBodySignature::new("pay.example.com", "X-Merchant", "X-Sig", vec![]);
        let mut request = InjectedRequest {
            method: "get".into(),
            path: "/v1/channels".into(),
            headers: vec![
                ("x-merchant".into(), "m-42".into()),
                ("va".into(), "ignored".into()),
                ("x-sig".into(), "placeholder".into()),
            ],
            body: Vec::new(),
        };
        signer
            .inject(&mut request, &credential("SANDBOX-KEY"))
            .unwrap();
        let expected = hex(&hmac_sha256(
            b"SANDBOX-KEY",
            format!("GET:m-42:{}:SANDBOX-KEY", sha256_hex(b"{}")).as_bytes(),
        ));
        assert_eq!(request.header("X-Sig"), Some(expected.as_str()));
        assert_eq!(
            request
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("x-sig"))
                .count(),
            1
        );
        assert!(request.header("signature").is_none());

        request.remove_header("x-merchant");
        assert!(
            signer
                .inject(&mut request, &credential("SANDBOX-KEY"))
                .is_err_and(|denied| denied.reason == "hmac-body-signature needs its id header")
        );
    }
}
