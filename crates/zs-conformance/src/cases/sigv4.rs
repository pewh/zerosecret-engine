use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::Protocol;
use crate::runner::{Case, Context, SIGV4_ACCESS_KEY_ID, Upstream};

const VECTORS: &str = "vectors/aws-sig-v4-test-suite/v4";
const HOST: &str = "example.amazonaws.com";
const DATE: &str = "20150830T123600Z";
const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const REGION: &str = "us-east-1";
const SERVICE: &str = "service";
const ZERO_SIGNATURE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "SV-01",
            protocol: Protocol::Http,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: every_vector,
        },
        Case {
            id: "SV-02",
            protocol: Protocol::Http,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: path_encoding,
        },
        Case {
            id: "SV-03",
            protocol: Protocol::Http,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: signed_port,
        },
        Case {
            id: "SV-04",
            protocol: Protocol::Http,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: resigning,
        },
        Case {
            id: "SV-05",
            protocol: Protocol::Http,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: streaming_body,
        },
        Case {
            id: "SV-06",
            protocol: Protocol::Http,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: presigned_url_cap,
        },
    ]
}

pub struct Vector {
    pub name: String,
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub canonical_request: String,
    pub string_to_sign: String,
    pub signature: String,
    pub token: Option<String>,
}

pub fn vectors() -> Vec<Vector> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    let Ok(entries) = fs::read_dir(&directory) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    paths.sort();
    paths
        .iter()
        .filter_map(|path| read_vector(path).ok())
        .collect()
}

fn read_vector(directory: &Path) -> Result<Vector, String> {
    let name = directory
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| "a vector directory has no name".to_string())?;
    let request = read(directory, "request.txt")?;
    let (head, body) = match request.split_once("\n\n") {
        Some((head, body)) => (head, body.as_bytes().to_vec()),
        None => (request.as_str(), Vec::new()),
    };
    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| format!("{name} has an empty request file"))?;
    let (method, rest) = request_line
        .split_once(' ')
        .ok_or_else(|| format!("{name} has no method"))?;
    let target = rest
        .strip_suffix(" HTTP/1.1")
        .unwrap_or(rest)
        .replace(' ', "%20");
    let method = method.to_string();
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    let canonical_request = read(directory, "header-canonical-request.txt")?;
    let string_to_sign = read(directory, "header-string-to-sign.txt")?;
    let signature = read(directory, "header-signature.txt")?;
    let context: serde_json::Value =
        serde_json::from_str(&read(directory, "context.json")?).unwrap_or_default();
    let token = match context
        .get("credentials")
        .and_then(|credentials| credentials.get("token"))
        .and_then(|token| token.as_str())
    {
        Some(token)
            if !context
                .get("omit_session_token")
                .and_then(|omit| omit.as_bool())
                .unwrap_or(false) =>
        {
            Some(token.to_string())
        }
        _ => None,
    };
    Ok(Vector {
        name,
        method,
        target,
        headers,
        body,
        canonical_request,
        string_to_sign,
        signature,
        token,
    })
}

fn read(directory: &Path, name: &str) -> Result<String, String> {
    fs::read_to_string(directory.join(name))
        .map(|text| text.trim_end_matches('\n').to_string())
        .map_err(|error| format!("cannot read {}/{name}: {error}", directory.display()))
}

struct Request<'a> {
    method: &'a str,
    url: &'a str,
    date: &'a str,
    hash: &'a str,
    authorization: Option<String>,
    headers: &'a [(String, String)],
    body: &'a [u8],
    insecure: bool,
}

fn fake_authorization(date: &str, signed: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={SIGV4_ACCESS_KEY_ID}/{}/{REGION}/{SERVICE}/aws4_request, SignedHeaders={signed}, Signature={ZERO_SIGNATURE}",
        date.get(..8).unwrap_or(date)
    )
}

fn new_vector(ctx: &Context, vector: &Vector) -> Result<String, String> {
    let date = vector
        .string_to_sign
        .lines()
        .nth(1)
        .ok_or_else(|| format!("{} has no date in its string to sign", vector.name))?;
    let signed = vector
        .canonical_request
        .lines()
        .rev()
        .nth(1)
        .ok_or_else(|| format!("{} has no signed headers", vector.name))?;
    let hash = vector
        .canonical_request
        .lines()
        .last()
        .ok_or_else(|| format!("{} has no payload hash", vector.name))?;
    let url = format!("http://{HOST}{}", vector.target);
    let mut headers = vector.headers.clone();
    if let Some(token) = &vector.token {
        headers.push(("x-amz-security-token".to_string(), token.clone()));
    }
    send(
        ctx,
        &Request {
            method: &vector.method,
            url: &url,
            date,
            hash,
            authorization: Some(fake_authorization(date, signed)),
            headers: &headers,
            body: &vector.body,
            insecure: false,
        },
    )
}

fn every_vector(ctx: &Context) -> Result<String, String> {
    let vectors = vectors();
    if vectors.is_empty() {
        return Err(format!("no vectors found under {VECTORS}"));
    }
    let mut covered: Vec<&str> = Vec::new();
    let mut requests = 0;
    let mut literal_rule = 0;
    let mut normalizing_rule = 0;
    let mut identical_rule = 0;
    for vector in &vectors {
        if covered.contains(&vector.name.as_str()) {
            continue;
        }
        let partner = rule_partner(&vectors, vector);
        if let Some(partner) = partner {
            covered.push(partner.name.as_str());
        }
        let status = new_vector(ctx, vector)?;
        let probe = ctx
            .http
            .as_ref()
            .ok_or_else(|| "the fake upstream is missing".to_string())?;
        if let Err(reason) = status_ok(&status, Some(probe)) {
            return Err(format!("{}: {reason}", vector.name));
        }
        let canonical = probe
            .last_canonical_request()
            .ok_or_else(|| format!("{}: the upstream saw no signed request", vector.name))?;
        let string_to_sign = probe
            .last_string_to_sign()
            .ok_or_else(|| format!("{}: the upstream built no string to sign", vector.name))?;
        let signature = probe
            .last_expected_signature()
            .ok_or_else(|| format!("{}: the upstream computed no signature", vector.name))?;
        if !probe.signature_verified() {
            return Err(format!(
                "{}: the upstream did not verify the forwarded signature",
                vector.name
            ));
        }
        let mut candidates = vec![vector];
        if let Some(partner) = partner {
            candidates.push(partner);
        }
        let Some(matched) = candidates.iter().find(|candidate| {
            candidate.canonical_request == canonical
                && candidate.string_to_sign == string_to_sign
                && candidate.signature == signature
        }) else {
            return Err(format!(
                "{}: the canonical request differs: upstream {:?}, expected {:?}",
                vector.name,
                one_line(&canonical),
                candidates
                    .iter()
                    .map(|candidate| one_line(&candidate.canonical_request))
                    .collect::<Vec<_>>()
                    .join(" or ")
            ));
        };
        if let Some(partner) = partner {
            if vector.canonical_request == partner.canonical_request {
                identical_rule += 1;
            } else if matched.name.ends_with("-unnormalized") {
                literal_rule += 1;
            } else {
                normalizing_rule += 1;
            }
        }
        requests += 1;
    }
    Ok(format!(
        "{requests} requests replayed from {} vendored variants; {literal_rule} path-rule pairs matched the literal S3 rule, {normalizing_rule} matched the normalizing rule and {identical_rule} expect the same canonical request under both rules",
        vectors.len()
    ))
}

fn rule_partner<'a>(vectors: &'a [Vector], vector: &Vector) -> Option<&'a Vector> {
    let partner = if let Some(stem) = vector.name.strip_suffix("-unnormalized") {
        format!("{stem}-normalized")
    } else {
        let stem = vector.name.strip_suffix("-normalized")?;
        format!("{stem}-unnormalized")
    };
    vectors.iter().find(|candidate| candidate.name == partner)
}

fn path_encoding(ctx: &Context) -> Result<String, String> {
    let target = "/a%28b%29!/c//d?list-type=2";
    let status = send(
        ctx,
        &Request {
            method: "GET",
            url: &format!("http://{HOST}{target}"),
            date: DATE,
            hash: EMPTY_HASH,
            authorization: Some(fake_authorization(DATE, "host;x-amz-date")),
            headers: &[],
            body: &[],
            insecure: false,
        },
    )?;
    status_ok(&status, ctx.http.as_ref())?;
    let canonical = ctx
        .http
        .as_ref()
        .and_then(|probe| probe.last_canonical_request())
        .ok_or_else(|| "the upstream saw no signed request".to_string())?;
    let path = canonical
        .lines()
        .nth(1)
        .ok_or_else(|| "the canonical request has no path line".to_string())?;
    if path != "/a%28b%29%21/c//d" {
        return Err(format!(
            "the signed path is {path:?}, AWS encodes that key as \"/a%28b%29%21/c//d\""
        ));
    }
    Ok(format!(
        "the signed path is {path}; the parentheses and the exclamation mark are percent-encoded and the double slash is preserved"
    ))
}

fn signed_port(ctx: &Context) -> Result<String, String> {
    let upstream = ctx
        .http
        .as_ref()
        .map(|probe| probe.addr())
        .ok_or_else(|| "the fake upstream is missing".to_string())?;
    let host = format!("example.amazonaws.com:{}", upstream.port());
    let status = send(
        ctx,
        &Request {
            method: "GET",
            url: &format!("https://{host}/bucket/key"),
            date: DATE,
            hash: EMPTY_HASH,
            authorization: Some(fake_authorization(DATE, "host;x-amz-date")),
            headers: &[],
            body: &[],
            insecure: true,
        },
    )?;
    status_ok(&status, ctx.http.as_ref())?;
    let signed = ctx
        .http
        .as_ref()
        .and_then(|probe| probe.last_signed_host())
        .ok_or_else(|| "the upstream saw no signed host".to_string())?;
    if signed != host {
        return Err(format!(
            "the signed host is {signed:?}, the forwarded authority is {host:?}"
        ));
    }
    if !ctx
        .http
        .as_ref()
        .is_some_and(|probe| probe.signature_verified())
    {
        return Err(
            "the upstream did not verify the request re-signed for that authority".to_string(),
        );
    }
    Ok(format!(
        "the signed host is {signed}, so the non-default port reached the canonical request"
    ))
}

fn resigning(ctx: &Context) -> Result<String, String> {
    let fake = format!(
        "AWS4-HMAC-SHA256 Credential=FAKEKEYINSANDBOX/20261027/eu-west-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature={ZERO_SIGNATURE}"
    );
    let signed = send_with_authorization(
        ctx,
        "GET",
        &format!("http://{HOST}/bucket/key"),
        Some(&fake),
    )?;
    status_ok(&signed, ctx.http.as_ref())?;
    let probe = ctx
        .http
        .as_ref()
        .ok_or_else(|| "the fake upstream is missing".to_string())?;
    let authorization = probe
        .last_authorization()
        .ok_or_else(|| "the upstream saw no Authorization header".to_string())?;
    if !authorization.contains(&format!("Credential={SIGV4_ACCESS_KEY_ID}/")) {
        return Err(format!(
            "the upstream saw {authorization:?}, not the binding's access key"
        ));
    }
    if authorization.contains("FAKEKEYINSANDBOX") {
        return Err("the client's access key reached the upstream".to_string());
    }
    if !probe.signature_verified() {
        return Err("the upstream did not verify the re-signed request".to_string());
    }
    let unsigned =
        send_with_authorization(ctx, "GET", &format!("http://{HOST}/bucket/public"), None)?;
    status_ok(&unsigned, ctx.http.as_ref())?;
    if !probe.reached() {
        return Err("the unsigned request never reached the upstream".to_string());
    }
    if probe.last_authorization().is_some() {
        return Err("the unsigned request reached the upstream signed".to_string());
    }
    Ok(format!(
        "the forged credential was replaced by {SIGV4_ACCESS_KEY_ID} and verified, and the unsigned request was relayed without an Authorization header"
    ))
}

fn streaming_body(ctx: &Context) -> Result<String, String> {
    let chunked = b"5\r\nhello\r\n0\r\n\r\n".to_vec();
    let headers = vec![
        (
            "x-amz-content-sha256".to_string(),
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER".to_string(),
        ),
        ("content-encoding".to_string(), "aws-chunked".to_string()),
        ("x-amz-decoded-content-length".to_string(), "5".to_string()),
    ];
    let signed =
        "content-encoding;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length";
    let status = send(
        ctx,
        &Request {
            method: "PUT",
            url: &format!("http://{HOST}/bucket/key"),
            date: DATE,
            hash: "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            authorization: Some(fake_authorization(DATE, signed)),
            headers: &headers,
            body: &chunked,
            insecure: false,
        },
    )?;
    status_ok(&status, ctx.http.as_ref())?;
    let probe = ctx
        .http
        .as_ref()
        .ok_or_else(|| "the fake upstream is missing".to_string())?;
    if !probe.signature_verified() {
        return Err("the upstream did not verify the streamed body's signature".to_string());
    }
    let body = probe.last_body();
    if body != b"hello" {
        return Err(format!(
            "the upstream received {:?} instead of the decoded payload",
            one_line(&String::from_utf8_lossy(&body))
        ));
    }
    if probe
        .last_header("content-encoding")
        .is_some_and(|encoding| encoding.to_ascii_lowercase().contains("aws-chunked"))
    {
        return Err("the upstream still saw content-encoding: aws-chunked".to_string());
    }
    let trailer = b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32:NhCmhg==\r\n\r\n".to_vec();
    let trailer_headers = vec![(
        "x-amz-trailer".to_string(),
        "x-amz-checksum-crc32".to_string(),
    )];
    let trailer_signed = "host;x-amz-content-sha256;x-amz-date;x-amz-trailer";
    let status = send(
        ctx,
        &Request {
            method: "PUT",
            url: &format!("http://{HOST}/bucket/key"),
            date: DATE,
            hash: "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            authorization: Some(fake_authorization(DATE, trailer_signed)),
            headers: &trailer_headers,
            body: &trailer,
            insecure: false,
        },
    )?;
    status_ok(&status, ctx.http.as_ref())?;
    if !probe.signature_verified() {
        return Err("the upstream did not verify the trailer request's signature".to_string());
    }
    if probe.last_body() != b"hello" {
        return Err(
            "the upstream did not receive the trailer request's decoded payload".to_string(),
        );
    }
    if probe.last_header("x-amz-checksum-crc32").as_deref() != Some("NhCmhg==") {
        return Err(format!(
            "the upstream saw the checksum as {:?}",
            probe.last_header("x-amz-checksum-crc32")
        ));
    }
    if probe.last_header("x-amz-trailer").is_some() {
        return Err("the upstream still saw an x-amz-trailer header".to_string());
    }
    Ok("the aws-chunked body was decoded to \"hello\", re-signed as a plain payload and the upstream verified it; a checksum trailer became an x-amz-checksum-crc32 request header".to_string())
}

fn presigned_url_cap(ctx: &Context) -> Result<String, String> {
    let url = format!("https://{HOST}/bucket/key");
    if crate::adapter::presign(&ctx.adapter, &ctx.handle, &url, "GET", 86_400).is_ok() {
        return Err("the endpoint issued a presigned URL for 86400 seconds".to_string());
    }
    let issued = crate::adapter::presign(&ctx.adapter, &ctx.handle, &url, "GET", 600)
        .map_err(|error| format!("presign failed for 600 seconds: {error}"))?;
    let (path, query) = split_url(&issued)?;
    let parameter = |name: &str| {
        query
            .split('&')
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
            .map(str::to_string)
    };
    if parameter("X-Amz-Expires").as_deref() != Some("600") {
        return Err(format!(
            "the issued URL carries X-Amz-Expires {:?}, not 600",
            parameter("X-Amz-Expires")
        ));
    }
    let credential_prefix = format!("{SIGV4_ACCESS_KEY_ID}%2F");
    if !parameter("X-Amz-Credential").is_some_and(|value| value.starts_with(&credential_prefix)) {
        return Err(format!(
            "the issued URL does not carry the {SIGV4_ACCESS_KEY_ID} credential: {:?}",
            parameter("X-Amz-Credential")
        ));
    }
    let status = replay_presigned(ctx, &path, &query)?;
    status_ok(&status, ctx.http.as_ref())?;
    if !ctx
        .http
        .as_ref()
        .is_some_and(|probe| probe.query_signature_verified())
    {
        return Err(format!(
            "the fake upstream did not verify the issued URL over TLS: {status}"
        ));
    }
    Ok("the endpoint refused a presigned URL for 86400 seconds and issued one for 600 seconds that the upstream verified over TLS".to_string())
}

fn split_url(url: &str) -> Result<(String, String), String> {
    let rest = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or_else(|| "the presigned URL has no scheme".to_string())?;
    let at = rest
        .find('/')
        .ok_or_else(|| "the presigned URL has no path".to_string())?;
    let (path, query) = rest[at..]
        .split_once('?')
        .ok_or_else(|| "the presigned URL has no query".to_string())?;
    Ok((path.to_string(), query.to_string()))
}

fn replay_presigned(ctx: &Context, path: &str, query: &str) -> Result<String, String> {
    let (tls_addr, ca_pem) = match ctx.http.as_ref() {
        Some(probe) if probe.tls_addr().port() != 0 && !probe.ca_pem().is_empty() => {
            (probe.tls_addr(), probe.ca_pem().to_string())
        }
        _ => return Err("the fake upstream has no TLS listener".to_string()),
    };
    let directory = scratch();
    let ca_file = directory.join("ca.pem");
    let header_file = directory.join("headers");
    if let Err(error) = fs::write(&ca_file, ca_pem) {
        let _ = fs::remove_dir_all(&directory);
        return Err(format!("cannot write the fake CA: {error}"));
    }
    let url = format!("https://{HOST}{path}?{query}");
    let connect_to = format!("{HOST}:443:127.0.0.1:{}", tls_addr.port());
    if let Some(probe) = ctx.http.as_ref() {
        probe.begin();
    }
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--http1.1",
            "--max-time",
            "20",
            "--output",
            "/dev/null",
        ])
        .arg("--cacert")
        .arg(&ca_file)
        .arg("--connect-to")
        .arg(connect_to)
        .arg("--dump-header")
        .arg(&header_file)
        .arg(&url)
        .output();
    let response = fs::read_to_string(&header_file).unwrap_or_default();
    let _ = fs::remove_dir_all(&directory);
    let output = output.map_err(|error| format!("cannot run curl: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "the TLS replay failed: {}",
            one_line(&String::from_utf8_lossy(&output.stderr))
        ));
    }
    response
        .lines()
        .rfind(|line| line.starts_with("HTTP/"))
        .map(|line| line.trim().to_string())
        .ok_or_else(|| "the fake upstream sent no status line".to_string())
}

fn send_with_authorization(
    ctx: &Context,
    method: &str,
    url: &str,
    authorization: Option<&str>,
) -> Result<String, String> {
    send(
        ctx,
        &Request {
            method,
            url,
            date: DATE,
            hash: EMPTY_HASH,
            authorization: authorization.map(str::to_string),
            headers: &[],
            body: &[],
            insecure: false,
        },
    )
}

fn send(ctx: &Context, request: &Request<'_>) -> Result<String, String> {
    let directory = scratch();
    let header_file = directory.join("headers");
    let body_file = directory.join("body");
    if let Err(error) = fs::write(&body_file, request.body) {
        let _ = fs::remove_dir_all(&directory);
        return Err(format!("cannot write the body: {error}"));
    }
    let mut command = Command::new("curl");
    command
        .args(["--silent", "--show-error", "--path-as-is", "--http1.1"])
        .args(["--max-time", "20", "--output", "/dev/null"])
        .arg("--dump-header")
        .arg(&header_file)
        .arg("--proxy")
        .arg(match ctx.env.get("CONFORMANCE_PROXY_USERINFO") {
            Some(userinfo) => format!("http://{userinfo}@{}", ctx.endpoint),
            None => format!("http://{}", ctx.endpoint),
        });
    if request.insecure {
        command.arg("--insecure");
    }
    command.arg("--request").arg(request.method);
    for (name, value) in request.headers {
        command.arg("--header").arg(format!("{name}: {value}"));
    }
    command
        .arg("--header")
        .arg(format!("x-amz-date: {}", request.date))
        .arg("--header")
        .arg(format!("x-amz-content-sha256: {}", request.hash));
    if let Some(authorization) = &request.authorization {
        command
            .arg("--header")
            .arg(format!("Authorization: {authorization}"));
    }
    if !request.body.is_empty() {
        command
            .arg("--data-binary")
            .arg(format!("@{}", body_file.display()));
    }
    command.arg(request.url);
    if let Some(probe) = ctx.http.as_ref() {
        probe.begin();
    }
    let output = command.output();
    let response = fs::read_to_string(&header_file).unwrap_or_default();
    let _ = fs::remove_dir_all(&directory);
    let output = output.map_err(|error| format!("cannot run curl: {error}"))?;
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr);
        return Err(format!("curl failed: {}", one_line(&reason)));
    }
    response
        .lines()
        .rfind(|line| line.starts_with("HTTP/"))
        .map(|line| line.trim().to_string())
        .ok_or_else(|| "the proxy sent no status line".to_string())
}

fn status_ok(status: &str, probe: Option<&crate::fake_upstream::FakeProbe>) -> Result<(), String> {
    if status.contains(" 200") {
        return Ok(());
    }
    let checked = probe.filter(|probe| {
        probe.reached() && !probe.signature_verified() && !probe.query_signature_verified()
    });
    Err(
        match checked.and_then(|probe| probe.last_expected_signature()) {
            Some(expected) => format!(
                "the upstream refused the request with {status}: authentication failed, its signature check expected {expected}"
            ),
            None => format!(
                "the request ended with {status} without the upstream's signature check rejecting it"
            ),
        },
    )
}

fn scratch() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "zs-conformance-curl-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = fs::create_dir_all(&directory);
    directory
}

fn one_line(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > 320 {
        line.chars().take(320).collect::<String>() + "..."
    } else {
        line
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn the_vendored_suite_holds_its_cases() {
        let vectors = vectors();
        assert_eq!(vectors.len(), 38);
        let vanilla = vectors
            .iter()
            .find(|vector| vector.name == "get-vanilla")
            .expect("get-vanilla");
        assert_eq!(vanilla.method, "GET");
        assert_eq!(vanilla.target, "/");
        assert_eq!(
            vanilla.signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert!(vanilla.canonical_request.ends_with(
            "host;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
    }

    #[test]
    fn folded_continuation_lines_become_one_header_value() {
        let vectors = vectors();
        let multiline = vectors
            .iter()
            .find(|vector| vector.name == "get-header-value-multiline")
            .expect("get-header-value-multiline");
        assert_eq!(
            multiline
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("my-header1"))
                .map(|(_, value)| value.as_str()),
            Some("value1 value2 value3")
        );
    }

    #[test]
    fn a_normalization_pair_holds_both_aws_rules() {
        let vectors = vectors();
        let literal = vectors
            .iter()
            .find(|vector| vector.name == "get-relative-unnormalized")
            .expect("get-relative-unnormalized");
        let normalizing = rule_partner(&vectors, literal).expect("its partner");
        assert_eq!(normalizing.name, "get-relative-normalized");
        assert_eq!(
            normalizing.canonical_request.lines().nth(1),
            Some("/"),
            "the normalizing rule resolves the dot segments"
        );
        assert_eq!(
            literal.canonical_request.lines().nth(1),
            Some("/example/.."),
            "the literal rule keeps them"
        );
    }

    #[test]
    fn a_session_token_comes_from_the_context_file() {
        let vectors = vectors();
        let token = vectors
            .iter()
            .find(|vector| vector.name == "get-vanilla-with-session-token")
            .and_then(|vector| vector.token.as_deref());
        assert_eq!(
            token,
            Some("6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267")
        );
        let omitted = vectors
            .iter()
            .find(|vector| vector.name == "post-sts-header-after")
            .expect("post-sts-header-after");
        assert!(omitted.token.is_none(), "the case omits the token");
    }
}
