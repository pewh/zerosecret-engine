use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const TERMINATOR: &str = "aws4_request";

struct State {
    secret_access_key: String,
    last_authorization: Mutex<Option<String>>,
    signature_verified: AtomicBool,
    last_signed_host: Mutex<Option<String>>,
    last_canonical_request: Mutex<Option<String>>,
    last_string_to_sign: Mutex<Option<String>>,
    last_expected_signature: Mutex<Option<String>>,
    last_body: Mutex<Vec<u8>>,
    last_headers: Mutex<Vec<(String, String)>>,
    query_signature_verified: AtomicBool,
    requests: AtomicU64,
    baseline: AtomicU64,
}

#[derive(Clone)]
pub struct FakeProbe {
    state: Arc<State>,
    addr: SocketAddr,
    tls_addr: SocketAddr,
    ca_pem: String,
}

impl FakeProbe {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn tls_addr(&self) -> SocketAddr {
        self.tls_addr
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn last_authorization(&self) -> Option<String> {
        state_value(&self.state.last_authorization)
    }

    pub fn signature_verified(&self) -> bool {
        self.state.signature_verified.load(Ordering::SeqCst)
    }

    pub fn last_signed_host(&self) -> Option<String> {
        state_value(&self.state.last_signed_host)
    }

    pub fn last_canonical_request(&self) -> Option<String> {
        state_value(&self.state.last_canonical_request)
    }

    pub fn last_string_to_sign(&self) -> Option<String> {
        state_value(&self.state.last_string_to_sign)
    }

    pub fn last_expected_signature(&self) -> Option<String> {
        state_value(&self.state.last_expected_signature)
    }

    pub fn query_signature_verified(&self) -> bool {
        self.state.query_signature_verified.load(Ordering::SeqCst)
    }

    pub fn begin(&self) {
        self.state
            .baseline
            .store(self.state.requests.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    pub fn reached(&self) -> bool {
        self.state.requests.load(Ordering::SeqCst) > self.state.baseline.load(Ordering::SeqCst)
    }

    pub fn last_body(&self) -> Vec<u8> {
        self.state
            .last_body
            .lock()
            .map(|body| body.clone())
            .unwrap_or_default()
    }

    pub fn last_header(&self, name: &str) -> Option<String> {
        self.state.last_headers.lock().ok().and_then(|headers| {
            headers
                .iter()
                .find(|(header, _)| header.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        })
    }
}

fn state_value(slot: &Mutex<Option<String>>) -> Option<String> {
    match slot.lock() {
        Ok(slot) => slot.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

pub struct FakeUpstream {
    pub addr: SocketAddr,
    pub tls_addr: SocketAddr,
    pub ca_pem: String,
    state: Arc<State>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl FakeUpstream {
    pub fn spawn(secret_access_key: String) -> FakeUpstream {
        let state = Arc::new(State {
            secret_access_key,
            last_authorization: Mutex::new(None),
            signature_verified: AtomicBool::new(false),
            last_signed_host: Mutex::new(None),
            last_canonical_request: Mutex::new(None),
            last_string_to_sign: Mutex::new(None),
            last_expected_signature: Mutex::new(None),
            last_body: Mutex::new(Vec::new()),
            last_headers: Mutex::new(Vec::new()),
            query_signature_verified: AtomicBool::new(false),
            requests: AtomicU64::new(0),
            baseline: AtomicU64::new(0),
        });
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let unbound = || FakeUpstream {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            tls_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            ca_pem: String::new(),
            state: Arc::clone(&state),
            shutdown: None,
            thread: None,
        };
        let Some((listener, addr)) = bind() else {
            return unbound();
        };
        let tls = tls_material().and_then(|(ca_pem, certificate, key)| {
            let acceptor = tls_acceptor(certificate, key)?;
            let (tls_listener, tls_addr) = bind()?;
            Some((tls_listener, tls_addr, ca_pem, acceptor))
        });
        let (tls_addr, ca_pem) = match &tls {
            Some((_, addr, pem, _)) => (*addr, pem.clone()),
            None => (SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), String::new()),
        };
        let serve_tls = tls.map(|(listener, _, _, acceptor)| (listener, acceptor));
        let server_state = Arc::clone(&state);
        let thread = thread::Builder::new()
            .name("fake-upstream".into())
            .spawn(move || serve(listener, serve_tls, server_state, shutdown_rx))
            .ok();
        FakeUpstream {
            addr,
            tls_addr,
            ca_pem,
            state,
            shutdown: Some(shutdown_tx),
            thread,
        }
    }

    pub fn last_authorization(&self) -> Option<String> {
        state_value(&self.state.last_authorization)
    }

    pub fn signature_verified(&self) -> bool {
        self.state.signature_verified.load(Ordering::SeqCst)
    }

    pub fn last_signed_host(&self) -> Option<String> {
        state_value(&self.state.last_signed_host)
    }

    pub fn query_signature_verified(&self) -> bool {
        self.state.query_signature_verified.load(Ordering::SeqCst)
    }

    pub fn last_body(&self) -> Vec<u8> {
        self.state
            .last_body
            .lock()
            .map(|body| body.clone())
            .unwrap_or_default()
    }

    pub fn probe(&self) -> FakeProbe {
        FakeProbe {
            state: Arc::clone(&self.state),
            addr: self.addr,
            tls_addr: self.tls_addr,
            ca_pem: self.ca_pem.clone(),
        }
    }

    pub fn shutdown(mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn bind() -> Option<(std::net::TcpListener, SocketAddr)> {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
    listener.set_nonblocking(true).ok()?;
    let addr = listener.local_addr().ok()?;
    Some((listener, addr))
}

fn serve(
    listener: std::net::TcpListener,
    tls: Option<(std::net::TcpListener, std::sync::Arc<ServerConfig>)>,
    state: Arc<State>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    runtime.block_on(async move {
        let Ok(listener) = TcpListener::from_std(listener) else {
            return;
        };
        let tls = match tls {
            Some((tls_listener, config)) => match TcpListener::from_std(tls_listener) {
                Ok(tls_listener) => Some((tls_listener, TlsAcceptor::from(config))),
                Err(_) => None,
            },
            None => None,
        };
        loop {
            let tls_accepted = async {
                match &tls {
                    Some((tls_listener, _)) => tls_listener.accept().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let connection_state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let service = service_fn(move |request| {
                            let state = Arc::clone(&connection_state);
                            async move { respond(request, state).await }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
                accepted = tls_accepted => {
                    let Ok((stream, _)) = accepted else { continue };
                    let Some((_, acceptor)) = &tls else { continue };
                    let acceptor = acceptor.clone();
                    let connection_state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        let service = service_fn(move |request| {
                            let state = Arc::clone(&connection_state);
                            async move { respond(request, state).await }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
    });
}

fn tls_material() -> Option<(String, Vec<u8>, Vec<u8>)> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    let mut authority = CertificateParams::new(Vec::new()).ok()?;
    let mut authority_name = DistinguishedName::new();
    authority_name.push(DnType::CommonName, "conformance fake ca");
    authority.distinguished_name = authority_name;
    authority.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let authority_key = KeyPair::generate().ok()?;
    let authority_certificate = authority.self_signed(&authority_key).ok()?;
    let mut leaf = CertificateParams::new(vec!["example.amazonaws.com".to_string()]).ok()?;
    let mut leaf_name = DistinguishedName::new();
    leaf_name.push(DnType::CommonName, "example.amazonaws.com");
    leaf.distinguished_name = leaf_name;
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().ok()?;
    let leaf_certificate = leaf
        .signed_by(&leaf_key, &authority_certificate, &authority_key)
        .ok()?;
    Some((
        authority_certificate.pem(),
        leaf_certificate.der().to_vec(),
        leaf_key.serialize_der(),
    ))
}

fn tls_acceptor(certificate: Vec<u8>, key: Vec<u8>) -> Option<std::sync::Arc<ServerConfig>> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
        )
        .ok()?;
    Some(std::sync::Arc::new(config))
}

async fn respond(
    request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or_default().to_string();
    let headers = request.headers().clone();
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let body = request
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();
    state.requests.fetch_add(1, Ordering::SeqCst);
    for slot in [
        &state.last_signed_host,
        &state.last_canonical_request,
        &state.last_string_to_sign,
        &state.last_expected_signature,
    ] {
        set_last(slot, None);
    }
    let body_hash = sha256_hex(&body);
    let declared_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let payload_matches = match declared_hash.as_deref() {
        None | Some("UNSIGNED-PAYLOAD") => true,
        Some(declared) => declared.eq_ignore_ascii_case(&body_hash),
    };
    let payload_hash = declared_hash.unwrap_or(body_hash);
    if let Ok(mut last) = state.last_body.lock() {
        *last = body.to_vec();
    }
    if let Ok(mut last) = state.last_headers.lock() {
        *last = headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_ascii_lowercase(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
    }
    let presigned =
        verify_query_signature(&method, &path, &query, &headers, &state.secret_access_key);
    state.query_signature_verified.store(
        presigned.as_ref().is_some_and(|(verified, _, _)| *verified),
        Ordering::SeqCst,
    );
    if let Some((_, host, computed)) = &presigned {
        if let Some(computed) = computed {
            set_last(
                &state.last_canonical_request,
                Some(computed.canonical_request.clone()),
            );
            set_last(
                &state.last_string_to_sign,
                Some(computed.string_to_sign.clone()),
            );
            set_last(
                &state.last_expected_signature,
                Some(computed.expected_signature.clone()),
            );
        }
        set_last(&state.last_signed_host, host.clone());
    }
    let parsed = authorization.as_deref().and_then(parse_authorization);
    let (verified, signed_host, computed) = match parsed.as_ref() {
        Some(parsed) => verify(
            parsed,
            &method,
            &path,
            &query,
            &headers,
            &payload_hash,
            &state.secret_access_key,
        ),
        None => (false, None, None),
    };
    let verified = verified && payload_matches;
    if let Some(computed) = &computed {
        set_last(
            &state.last_canonical_request,
            Some(computed.canonical_request.clone()),
        );
        set_last(
            &state.last_string_to_sign,
            Some(computed.string_to_sign.clone()),
        );
        set_last(
            &state.last_expected_signature,
            Some(computed.expected_signature.clone()),
        );
    }
    set_last(&state.last_authorization, authorization.clone());
    if presigned.is_none() {
        set_last(&state.last_signed_host, signed_host.clone());
    }
    state.signature_verified.store(verified, Ordering::SeqCst);
    let refused = (authorization.is_some() && !verified)
        || presigned
            .as_ref()
            .is_some_and(|(query_verified, _, _)| !query_verified);
    let payload = serde_json::json!({
        "method": method.as_str(),
        "path": path,
        "signature_verified": verified,
        "query_signature_verified": state.query_signature_verified.load(Ordering::SeqCst),
        "signed_host": signed_host,
        "error": if refused { Some("SignatureDoesNotMatch") } else { None },
    })
    .to_string();
    let mut response = Response::new(Full::new(Bytes::from(payload)));
    *response.status_mut() = if refused {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::OK
    };
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(response)
}

fn set_last(slot: &Mutex<Option<String>>, value: Option<String>) {
    match slot.lock() {
        Ok(mut slot) => *slot = value,
        Err(poisoned) => *poisoned.into_inner() = value,
    }
}

struct Authorization {
    date: String,
    region: String,
    service: String,
    signed_headers: Vec<String>,
    signature: String,
}

fn parse_authorization(value: &str) -> Option<Authorization> {
    let rest = value.strip_prefix(ALGORITHM)?;
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(found) = part.strip_prefix("Credential=") {
            credential = Some(found);
        } else if let Some(found) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(found);
        } else if let Some(found) = part.strip_prefix("Signature=") {
            signature = Some(found);
        }
    }
    let mut scope = credential?.split('/');
    let _access_key = scope.next()?;
    let date = scope.next()?.to_string();
    let region = scope.next()?.to_string();
    let service = scope.next()?.to_string();
    if scope.next()? != TERMINATOR || scope.next().is_some() || date.len() != 8 {
        return None;
    }
    let signed_headers: Vec<String> = signed_headers?
        .split(';')
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect();
    if signed_headers.is_empty() {
        return None;
    }
    Some(Authorization {
        date,
        region,
        service,
        signed_headers,
        signature: signature?.to_string(),
    })
}

struct Computed {
    canonical_request: String,
    string_to_sign: String,
    expected_signature: String,
}

fn verify(
    authorization: &Authorization,
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    payload_hash: &str,
    secret: &str,
) -> (bool, Option<String>, Option<Computed>) {
    let Some(amz_date) = headers
        .get("x-amz-date")
        .and_then(|value| value.to_str().ok())
    else {
        return (false, None, None);
    };
    if !authorization
        .signed_headers
        .iter()
        .any(|name| name == "host")
    {
        return (false, None, None);
    }
    let Some((canonical_headers, signed_host)) =
        canonical_headers(headers, &authorization.signed_headers)
    else {
        return (false, None, None);
    };
    let signed_list = authorization.signed_headers.join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_path(path),
        canonical_query(query_pairs(query)),
        canonical_headers,
        signed_list,
        payload_hash
    );
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{}/{}/{}/{TERMINATOR}\n{}",
        authorization.date,
        authorization.region,
        authorization.service,
        sha256_hex(canonical_request.as_bytes())
    );
    let Some(expected) = signature_hex(
        secret,
        &authorization.date,
        &authorization.region,
        &authorization.service,
        &string_to_sign,
    ) else {
        return (false, signed_host, None);
    };
    let verified = expected.eq_ignore_ascii_case(&authorization.signature)
        && amz_date.get(..8) == Some(authorization.date.as_str());
    (
        verified,
        signed_host,
        Some(Computed {
            canonical_request,
            string_to_sign,
            expected_signature: expected,
        }),
    )
}

fn verify_query_signature(
    method: &Method,
    path: &str,
    query: &str,
    headers: &HeaderMap,
    secret: &str,
) -> Option<(bool, Option<String>, Option<Computed>)> {
    let pairs = query_pairs(query);
    let get = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    if get("X-Amz-Algorithm").as_deref() != Some(ALGORITHM) {
        return None;
    }
    let credential = get("X-Amz-Credential")?;
    let credential = String::from_utf8_lossy(&percent_decode(&credential)).into_owned();
    let mut scope = credential.split('/');
    let _access_key = scope.next()?;
    let date = scope.next()?.to_string();
    let region = scope.next()?.to_string();
    let service = scope.next()?.to_string();
    if scope.next()? != TERMINATOR || scope.next().is_some() {
        return None;
    }
    let amz_date = get("X-Amz-Date")?;
    let signature = get("X-Amz-Signature")?;
    let signed_headers = get("X-Amz-SignedHeaders")?;
    if !signed_headers
        .split(';')
        .any(|name| name.eq_ignore_ascii_case("host"))
    {
        return None;
    }
    let host = headers
        .get("host")
        .and_then(|value| value.to_str().ok())?
        .to_string();
    let kept: Vec<(String, String)> = pairs
        .into_iter()
        .filter(|(key, _)| !key.eq_ignore_ascii_case("X-Amz-Signature"))
        .collect();
    let canonical_request = format!(
        "{}\n{}\n{}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
        method.as_str(),
        canonical_path(path),
        canonical_query(kept)
    );
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{date}/{region}/{service}/{TERMINATOR}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let expected = signature_hex(secret, &date, &region, &service, &string_to_sign)?;
    Some((
        expected.eq_ignore_ascii_case(&signature) && amz_date.get(..8) == Some(date.as_str()),
        Some(host),
        Some(Computed {
            canonical_request,
            string_to_sign,
            expected_signature: expected,
        }),
    ))
}

fn canonical_headers(headers: &HeaderMap, signed: &[String]) -> Option<(String, Option<String>)> {
    let mut names = signed.to_vec();
    names.sort();
    names.dedup();
    let mut canonical = String::new();
    let mut host = None;
    for name in &names {
        let mut values = Vec::new();
        for value in headers.get_all(name.as_str()).iter() {
            values.push(collapse(value.to_str().ok()?));
        }
        if values.is_empty() {
            return None;
        }
        let value = values.join(",");
        if name == "host" {
            host = Some(value.clone());
        }
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(&value);
        canonical.push('\n');
    }
    Some((canonical, host))
}

fn signature_hex(
    secret: &str,
    date: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> Option<String> {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes())?;
    let region_key = hmac_sha256(&date_key, region.as_bytes())?;
    let service_key = hmac_sha256(&region_key, service.as_bytes())?;
    let signing_key = hmac_sha256(&service_key, TERMINATOR.as_bytes())?;
    let signature = hmac_sha256(&signing_key, string_to_sign.as_bytes())?;
    Some(hex(&signature))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(data);
    Some(mac.finalize().into_bytes().to_vec())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hex_digit(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}

fn percent_decode(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && let (Some(high), Some(low)) = (
                bytes.get(index + 1).copied().and_then(hex_digit),
                bytes.get(index + 2).copied().and_then(hex_digit),
            )
        {
            out.push(high << 4 | low);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    out
}

fn aws_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn canonical_path(path: &str) -> String {
    path.split('/')
        .map(|segment| aws_encode(&percent_decode(segment)))
        .collect::<Vec<_>>()
        .join("/")
}

fn query_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                aws_encode(&percent_decode(key)),
                aws_encode(&percent_decode(value)),
            )
        })
        .collect()
}

fn canonical_query(mut pairs: Vec<(String, String)>) -> String {
    pairs.sort();
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn collapse(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::process::Command;
    use std::time::Duration;

    use super::*;

    const ACCESS_KEY: &str = "AKIDCONFORMANCE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const AMZ_DATE: &str = "20260101T000000Z";
    const DATE: &str = "20260101";
    const REGION: &str = "us-east-1";
    const SERVICE: &str = "s3";
    const PAYLOAD_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn authorization(addr: SocketAddr, secret: &str, target: &str) -> String {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let signed = "host;x-amz-content-sha256;x-amz-date";
        let canonical_headers =
            format!("host:{addr}\nx-amz-content-sha256:{PAYLOAD_HASH}\nx-amz-date:{AMZ_DATE}\n");
        let canonical_request = format!(
            "GET\n{}\n{}\n{canonical_headers}\n{signed}\n{PAYLOAD_HASH}",
            canonical_path(path),
            canonical_query(query_pairs(query)),
        );
        let string_to_sign = format!(
            "{ALGORITHM}\n{AMZ_DATE}\n{DATE}/{REGION}/{SERVICE}/{TERMINATOR}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = signature_hex(secret, DATE, REGION, SERVICE, &string_to_sign).unwrap();
        format!(
            "{ALGORITHM} Credential={ACCESS_KEY}/{DATE}/{REGION}/{SERVICE}/{TERMINATOR}, SignedHeaders={signed}, Signature={signature}"
        )
    }

    fn request(addr: SocketAddr, secret: &str) -> String {
        let target = "/probe?b=2&a=1";
        let authorization = authorization(addr, secret, target);
        format!(
            "GET {target} HTTP/1.1\r\nHost: {addr}\r\nx-amz-date: {AMZ_DATE}\r\nx-amz-content-sha256: {PAYLOAD_HASH}\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n"
        )
    }

    fn exchange(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    fn presigned_target(host: &str, secret: &str) -> String {
        let path = "/bucket/key";
        let credential =
            aws_encode(format!("{ACCESS_KEY}/{DATE}/{REGION}/{SERVICE}/{TERMINATOR}").as_bytes());
        let query = format!(
            "X-Amz-Algorithm={ALGORITHM}&X-Amz-Credential={credential}&X-Amz-Date={AMZ_DATE}&X-Amz-Expires=600&X-Amz-SignedHeaders=host"
        );
        let canonical_request = format!(
            "GET\n{}\n{}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
            canonical_path(path),
            canonical_query(query_pairs(&query)),
        );
        let string_to_sign = format!(
            "{ALGORITHM}\n{AMZ_DATE}\n{DATE}/{REGION}/{SERVICE}/{TERMINATOR}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = signature_hex(secret, DATE, REGION, SERVICE, &string_to_sign).unwrap();
        format!("{path}?{query}&X-Amz-Signature={signature}")
    }

    fn presigned_request(host: &str, target: &str) -> String {
        format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
    }

    #[test]
    fn a_presigned_query_verifies() {
        let upstream = FakeUpstream::spawn(SECRET.to_string());
        let host = "example.amazonaws.com";
        let response = exchange(
            upstream.addr,
            &presigned_request(host, &presigned_target(host, SECRET)),
        );
        assert!(
            response.contains("\"query_signature_verified\":true"),
            "{response}"
        );
        assert!(upstream.query_signature_verified());
        assert_eq!(upstream.last_signed_host().as_deref(), Some(host));
        upstream.shutdown();
    }

    #[test]
    fn a_presigned_query_with_another_key_does_not_verify() {
        let upstream = FakeUpstream::spawn(SECRET.to_string());
        let host = "example.amazonaws.com";
        let response = exchange(
            upstream.addr,
            &presigned_request(
                host,
                &presigned_target(host, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYWRONGSECRET"),
            ),
        );
        assert!(
            response.contains("\"query_signature_verified\":false"),
            "{response}"
        );
        assert!(!upstream.query_signature_verified());
        upstream.shutdown();
    }

    #[test]
    fn the_tls_material_chains_to_its_authority() {
        let (ca_pem, certificate, _key) = tls_material().expect("tls material");
        let directory = tempfile::tempdir().expect("temp dir");
        let ca = directory.path().join("ca.pem");
        let der = directory.path().join("leaf.der");
        let pem = directory.path().join("leaf.pem");
        std::fs::write(&ca, ca_pem).expect("write the ca");
        std::fs::write(&der, certificate).expect("write the leaf");
        let converted = Command::new("openssl")
            .args(["x509", "-inform", "DER", "-in"])
            .arg(&der)
            .arg("-out")
            .arg(&pem)
            .status()
            .expect("openssl must be installed");
        assert!(converted.success());
        let verified = Command::new("openssl")
            .args(["verify", "-CAfile"])
            .arg(&ca)
            .arg(&pem)
            .output()
            .expect("openssl must be installed");
        assert!(
            verified.status.success(),
            "{}",
            String::from_utf8_lossy(&verified.stderr)
        );
    }

    #[test]
    fn the_tls_listener_serves_a_trusted_certificate() {
        let upstream = FakeUpstream::spawn(SECRET.to_string());
        assert_ne!(upstream.tls_addr.port(), 0, "a tls listener");
        let directory = tempfile::tempdir().expect("temp dir");
        let ca = directory.path().join("ca.pem");
        std::fs::write(&ca, &upstream.ca_pem).expect("write the ca");
        let output = Command::new("curl")
            .args(["--silent", "--show-error", "--max-time", "10"])
            .args(["--output", "/dev/null", "--write-out", "%{http_code}"])
            .arg("--cacert")
            .arg(&ca)
            .arg("--connect-to")
            .arg(format!(
                "example.amazonaws.com:443:127.0.0.1:{}",
                upstream.tls_addr.port()
            ))
            .arg("https://example.amazonaws.com/")
            .output()
            .expect("curl must be installed");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout), "200");
        upstream.shutdown();
    }

    #[test]
    fn a_correctly_signed_request_verifies() {
        let upstream = FakeUpstream::spawn(SECRET.to_string());
        let response = exchange(upstream.addr, &request(upstream.addr, SECRET));
        assert!(
            response.contains("\"signature_verified\":true"),
            "{response}"
        );
        assert!(response.contains("\"method\":\"GET\""), "{response}");
        assert!(response.contains("\"path\":\"/probe\""), "{response}");
        assert!(!response.contains(SECRET), "{response}");
        assert!(upstream.signature_verified());
        let host = upstream.last_signed_host().unwrap();
        assert!(host.contains(&upstream.addr.port().to_string()), "{host}");
        assert_eq!(host, upstream.addr.to_string());
        assert!(
            upstream
                .last_authorization()
                .unwrap()
                .starts_with(ALGORITHM)
        );
        upstream.shutdown();
    }

    #[test]
    fn a_request_signed_with_another_key_does_not_verify() {
        let upstream = FakeUpstream::spawn(SECRET.to_string());
        let response = exchange(
            upstream.addr,
            &request(upstream.addr, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYWRONGSECRET"),
        );
        assert!(
            response.contains("\"signature_verified\":false"),
            "{response}"
        );
        assert!(!upstream.signature_verified());
        assert!(upstream.last_authorization().is_some());
        assert!(upstream.last_signed_host().is_some());
        upstream.shutdown();
    }
}
