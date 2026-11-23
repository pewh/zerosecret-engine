#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zs::{AgentHandler, GrantCache};
use zs_grant::{ControlSigningKey, Grant};

const SUBJECT: &str = "alice@company.com";
const WORKLOAD: &str = "claude-code";

const LOOPBACK: &str = "localhost";
const API: &str = "echo-api";
const API_REF: &str = "echo-api-token";
const TOKEN: &str = "zs-review-range-token-0123456789";
const ECHO_PATH: &str = "/debug/headers";

// The fake upstream answers every request with this JSON and the request's `Authorization` value.
const BODY_START: &str = "{\"authorization\":\"";
const SCHEME: &str = "Bearer ";
const BODY_END: &str = "\"}";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn materializer(credentials: &Path) -> Arc<zs_materializer::Materializer> {
    struct NoExchange;
    #[async_trait::async_trait]
    impl zs_materializer::ExchangeProvider for NoExchange {
        async fn exchange(
            &self,
            _grant: &zs_grant::Grant,
        ) -> Result<zs_credential::Credential, zs_materializer::MaterializationError> {
            Err(zs_materializer::MaterializationError::Exchange(
                "not configured".into(),
            ))
        }
    }
    Arc::new(zs_materializer::Materializer::new(
        zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(credentials))),
        Arc::new(NoExchange),
    ))
}

type Seen = Arc<Mutex<Vec<String>>>;

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then_some(value.trim())
    })
}

// `bytes=a-b` or `bytes=a-` on a body of `len` bytes, as an inclusive range.
fn byte_range(value: &str, len: usize) -> Option<(usize, usize)> {
    let (first, last) = value.strip_prefix("bytes=")?.split_once('-')?;
    let first: usize = first.parse().ok()?;
    let last = match last {
        "" => len.checked_sub(1)?,
        last => last.parse::<usize>().ok()?.min(len.checked_sub(1)?),
    };
    (first <= last).then_some((first, last))
}

// An upstream that returns the `Authorization` header it received and honours `Range`.
async fn echoing_upstream() -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let record = record.clone();
            tokio::spawn(async move {
                let head = String::from_utf8_lossy(&read_head(&mut stream).await).into_owned();
                let body = format!(
                    "{BODY_START}{}{BODY_END}",
                    header(&head, "authorization").unwrap_or("")
                );
                let range = header(&head, "range").and_then(|r| byte_range(r, body.len()));
                record.lock().unwrap().push(head);
                let answer = match range {
                    Some((first, last)) => format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Type: application/json\r\n\
                         Content-Range: bytes {first}-{last}/{}\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{}",
                        body.len(),
                        last - first + 1,
                        &body[first..=last]
                    ),
                    None => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Accept-Ranges: bytes\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                };
                let _ = stream.write_all(answer.as_bytes()).await;
            });
        }
    });
    (port, seen)
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    let read = async {
        while stream.read(&mut byte).await.unwrap_or(0) == 1 {
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), read).await;
    head
}

struct Answer {
    head: String,
    body: Vec<u8>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// The body bytes the workload received; a chunked body is decoded, a cut body is kept as far as it came.
fn split_answer(raw: &[u8]) -> Answer {
    let end = find(raw, b"\r\n\r\n").map_or(raw.len(), |at| at + 4);
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut rest = &raw[end..];
    let chunked = header(&head, "transfer-encoding").is_some_and(|v| v.contains("chunked"));
    if !chunked {
        return Answer {
            head,
            body: rest.to_vec(),
        };
    }
    let mut body = Vec::new();
    while let Some(line_end) = find(rest, b"\r\n") {
        let size = std::str::from_utf8(&rest[..line_end])
            .ok()
            .and_then(|line| usize::from_str_radix(line.trim(), 16).ok());
        let Some(size) = size.filter(|size| *size > 0) else {
            break;
        };
        let start = line_end + 2;
        let Some(chunk) = rest.get(start..start + size) else {
            body.extend_from_slice(&rest[start.min(rest.len())..]);
            break;
        };
        body.extend_from_slice(chunk);
        rest = rest.get(start + size + 2..).unwrap_or(&[]);
    }
    Answer { head, body }
}

struct Workload {
    proxy: std::net::SocketAddr,
    ca: Arc<zs_mitm::LocalCa>,
    token: Arc<zs_mitm::RunToken>,
    port: u16,
}

impl Workload {
    // One request through the proxy, as the workload sends it: CONNECT, TLS, then GET.
    async fn get(&self, range: Option<&str>) -> Answer {
        use rustls::pki_types::pem::PemObject;
        let port = self.port;
        let mut tcp = TcpStream::connect(self.proxy).await.unwrap();
        let connect = format!(
            "CONNECT {LOOPBACK}:{port} HTTP/1.1\r\nHost: {LOOPBACK}:{port}\r\n\
             Proxy-Authorization: {}\r\n\r\n",
            self.token.proxy_authorization().as_str()
        );
        tcp.write_all(connect.as_bytes()).await.unwrap();
        let established = String::from_utf8_lossy(&read_head(&mut tcp).await).into_owned();
        assert!(established.starts_with("HTTP/1.1 200"), "{established}");
        let der =
            rustls::pki_types::CertificateDer::from_pem_slice(self.ca.certificate_pem().as_bytes())
                .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from(LOOPBACK.to_string()).unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();

        let range = range.map_or(String::new(), |range| format!("Range: {range}\r\n"));
        let request = format!(
            "GET {ECHO_PATH} HTTP/1.1\r\nHost: {LOOPBACK}:{port}\r\n{range}Connection: close\r\n\r\n"
        );
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        let mut buffer = [0u8; 4096];
        let read = async {
            while let Ok(n) = tls.read(&mut buffer).await {
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..n]);
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(5), read).await;
        split_answer(&raw)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn range_requests_do_not_return_an_echoed_credential_in_parts() {
    let (port, seen) = echoing_upstream().await;

    let file: zs::AgentFile = serde_json::from_value(serde_json::json!({
        "bindings": [{
            "resource": API,
            "host": LOOPBACK,
            "protocol": "https",
            "upstream_port": port,
            "upstream_plaintext": true
        }]
    }))
    .unwrap();
    file.validate()
        .expect("the agent accepts this policy file at load");

    let home = tempfile::tempdir().unwrap();
    let credentials = home.path().join("credentials");
    std::fs::create_dir_all(&credentials).unwrap();
    std::fs::write(credentials.join(API_REF), TOKEN).unwrap();

    let key = ControlSigningKey::generate("control-k1");
    let verifier = zs_grant::AgentVerifier::new(vec![(
        key.key_id().to_string(),
        ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
    )]);
    let cache = GrantCache::new();
    cache.insert(
        key.sign(Grant {
            subject: SUBJECT.into(),
            workload: WORKLOAD.into(),
            resource: API.into(),
            host: LOOPBACK.into(),
            protocol: "https".into(),
            source: zs_policy::CredentialSource::file(API_REF),
            operations: vec!["GET".into()],
            environment: "development".into(),
            expires_at_ms: now_ms() + 300_000,
            grant_id: "g-echo-api".into(),
            materialization: zs_policy::Materialization::Retrieve,
            upstream_host: LOOPBACK.into(),
            upstream_port: port,
            upstream_tls: zs_policy::UpstreamTlsMode::Plaintext,
            local_endpoint: false,
            listen_addr: None,
            listen_allow: Vec::new(),
            access: zs_policy::Access::ReadWrite,
            version: zs_grant::GRANT_VERSION,
        })
        .unwrap(),
    );
    let handler = AgentHandler::from_grants(
        zs_identity::Subject::new(SUBJECT).unwrap(),
        zs_identity::WorkloadLabel::new(WORKLOAD).unwrap(),
        file.bindings.clone(),
        cache,
        verifier,
        materializer(&credentials),
    );

    let ca = Arc::new(zs_mitm::LocalCa::load_or_create(home.path().join("ca")).unwrap());
    let token = Arc::new(zs_mitm::RunToken::generate());
    let server = zs_mitm::ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        ca.clone(),
        Arc::new(handler),
        Arc::new(zs_audit::Journal::open(home.path().join("audit.jsonl")).unwrap()),
        token.clone(),
    )
    .await
    .unwrap();
    let proxy = server.local_addr().unwrap();
    tokio::spawn(async move { server.serve().await });
    let workload = Workload {
        proxy,
        ca,
        token,
        port,
    };

    // Controls: the agent injects the credential, and the echo guard cuts the whole echo.
    let whole = workload.get(None).await;
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .any(|head| head.contains(&format!("{SCHEME}{TOKEN}"))),
        "positive control: the upstream gets the injected credential"
    );
    assert!(
        find(&whole.body, TOKEN.as_bytes()).is_none() && !whole.head.contains(TOKEN),
        "negative control: a response that echoes the whole credential does not reach the \
         workload (SECURITY.md §4 rule 9)"
    );

    // The workload knows the layout of the echo, so it knows where the credential starts.
    let start = BODY_START.len() + SCHEME.len();
    let first = workload
        .get(Some(&format!("bytes={start}-{}", start + 6)))
        .await;
    let second = workload.get(Some(&format!("bytes={}-", start + 7))).await;

    let mut joined = first.body.clone();
    joined.extend_from_slice(&second.body);
    assert!(
        find(&joined, TOKEN.as_bytes()).is_none(),
        "two `Range` requests returned the injected credential to the workload in two parts \
         ({} bytes, then {} bytes); each response passed the echo guard.\nfirst head: {}\nsecond head: {}",
        first.body.len(),
        second.body.len(),
        first.head.lines().next().unwrap_or(""),
        second.head.lines().next().unwrap_or(""),
    );
}
