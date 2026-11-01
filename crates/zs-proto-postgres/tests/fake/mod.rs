#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zs_credential::Credential;
use zs_diag::DiagLog;
use zs_proto_postgres::{Materialize, PostgresListener, SslPolicy, UpstreamEndpoint, UpstreamTls};

pub const PASSWORD: &str = "zs-pg-test-password";
pub const WRONG: &str = "zs-pg-test-wrong-password";
pub const RESOURCE: &str = "orders-pg";
pub const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
pub const CANCEL_CODE: u32 = 80_877_102;
pub const TLS_FAILED: (&str, &str) = ("08006", "upstream TLS failed");
pub const UNAVAILABLE: (&str, &str) = ("08006", "upstream unavailable");
pub const AUTH_FAILED: (&str, &str) = ("28000", "upstream authentication failed");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    N,
    S,
    SWithExtraByte,
    Other(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auth {
    Scram,
    Method(u32),
}

#[derive(Clone)]
pub struct Script {
    pub answer: Answer,
    pub auth: Auth,
    pub tls: Option<Arc<rustls::ServerConfig>>,
}

impl Script {
    pub fn new(answer: Answer) -> Self {
        Self {
            answer,
            auth: Auth::Scram,
            tls: None,
        }
    }

    pub fn with_tls(mut self, server: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(server);
        self
    }

    pub fn with_auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }
}

#[derive(Default)]
pub struct Seen {
    pub ssl_requests: usize,
    pub tls: bool,
    pub startups: usize,
    pub authenticated: bool,
    pub after_method: Option<u8>,
    pub method_settled: bool,
    pub queries: Vec<String>,
    pub cancels: Vec<Vec<u8>>,
}

pub struct Fake {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Seen>>,
}

impl Fake {
    pub fn seen<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.seen.lock().unwrap())
    }

    pub async fn listen(&self, tls: UpstreamTls) -> SocketAddr {
        listen(
            "127.0.0.1",
            self.addr.port(),
            tls,
            materialize(PASSWORD),
            DiagLog::disabled(),
        )
        .await
    }
}

pub async fn start(script: Script) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (script, record) = (script.clone(), record.clone());
            tokio::spawn(async move {
                let _ = serve(tcp, script, record).await;
            });
        }
    });
    Fake { addr, seen }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let total = (u32::from_be_bytes(len) as usize).clamp(4, 1 << 20);
    let mut packet = len.to_vec();
    packet.resize(total, 0);
    stream.read_exact(&mut packet[4..]).await?;
    Ok(packet)
}

async fn serve(mut tcp: TcpStream, script: Script, seen: Arc<Mutex<Seen>>) -> std::io::Result<()> {
    let first = read_packet(&mut tcp).await?;
    let (mut stream, packet): (Box<dyn Io>, Vec<u8>) = if first == SSL_REQUEST {
        seen.lock().unwrap().ssl_requests += 1;
        match script.answer {
            Answer::N | Answer::Other(_) => {
                let reply = match script.answer {
                    Answer::Other(byte) => byte,
                    _ => b'N',
                };
                tcp.write_all(&[reply]).await?;
                let next = read_packet(&mut tcp).await?;
                (Box::new(tcp), next)
            }
            Answer::S | Answer::SWithExtraByte => {
                let reply: &[u8] = if script.answer == Answer::S {
                    b"S"
                } else {
                    b"S\0"
                };
                tcp.write_all(reply).await?;
                let Some(server) = script.tls.clone() else {
                    return Ok(());
                };
                let mut tls = tokio_rustls::TlsAcceptor::from(server).accept(tcp).await?;
                seen.lock().unwrap().tls = true;
                let next = read_packet(&mut tls).await?;
                (Box::new(tls), next)
            }
        }
    } else {
        (Box::new(tcp), first)
    };
    if packet.len() == 16 && packet[4..8] == CANCEL_CODE.to_be_bytes() {
        seen.lock().unwrap().cancels.push(packet);
        return Ok(());
    }
    seen.lock().unwrap().startups += 1;
    if let Auth::Method(code) = script.auth {
        let mut body = code.to_be_bytes().to_vec();
        if code == 5 {
            body.extend_from_slice(b"salt");
        }
        write_tagged(&mut stream, b'R', &body).await?;
        let after = read_tagged(&mut stream).await;
        let mut seen = seen.lock().unwrap();
        seen.after_method = after.ok().map(|(tag, _)| tag);
        seen.method_settled = true;
        return Ok(());
    }
    if !scram(&mut stream).await? {
        return write_tagged(
            &mut stream,
            b'E',
            b"SFATAL\0C28P01\0Mpassword authentication failed\0\0",
        )
        .await;
    }
    seen.lock().unwrap().authenticated = true;
    write_tagged(&mut stream, b'R', &0u32.to_be_bytes()).await?;
    write_tagged(&mut stream, b'S', b"server_version\x0016.4\0").await?;
    write_tagged(&mut stream, b'K', &[0, 0, 0, 7, 0, 0, 0, 9]).await?;
    write_tagged(&mut stream, b'Z', b"I").await?;
    while let Ok((tag, body)) = read_tagged(&mut stream).await {
        if tag != b'Q' {
            break;
        }
        let sql = String::from_utf8_lossy(&body)
            .trim_end_matches('\0')
            .to_string();
        seen.lock().unwrap().queries.push(sql);
        write_tagged(&mut stream, b'C', b"SELECT 1\0").await?;
        write_tagged(&mut stream, b'Z', b"I").await?;
    }
    let _ = stream.shutdown().await;
    Ok(())
}

async fn scram<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> std::io::Result<bool> {
    let mut offer = 10u32.to_be_bytes().to_vec();
    offer.extend_from_slice(b"SCRAM-SHA-256\0\0");
    write_tagged(stream, b'R', &offer).await?;
    let (_, initial) = read_tagged(stream).await?;
    let initial = String::from_utf8_lossy(&initial).into_owned();
    let client_first_bare = initial
        .split_once("n,,")
        .map(|(_, bare)| bare.to_string())
        .ok_or_else(|| std::io::Error::other("no client-first-bare"))?;
    let client_nonce = client_first_bare
        .split(',')
        .find_map(|part| part.strip_prefix("r="))
        .ok_or_else(|| std::io::Error::other("no client nonce"))?
        .to_string();
    let server_first = format!(
        "r={client_nonce}fakeServerNonce,s={},i=4096",
        base64::engine::general_purpose::STANDARD.encode(b"zs-pg-fake-salt")
    );
    let mut challenge = 11u32.to_be_bytes().to_vec();
    challenge.extend_from_slice(server_first.as_bytes());
    write_tagged(stream, b'R', &challenge).await?;
    let (_, final_body) = read_tagged(stream).await?;
    let client_final = String::from_utf8_lossy(&final_body).into_owned();
    let expected =
        zs_proto_postgres::client_final_message(PASSWORD, &server_first, &client_first_bare)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    if client_final
        != format!(
            "{},p={}",
            expected.client_final_without_proof, expected.proof
        )
    {
        return Ok(false);
    }
    let verifier = format!(
        "v={}",
        base64::engine::general_purpose::STANDARD.encode(&expected.expected_server_signature)
    );
    let mut sasl_final = 12u32.to_be_bytes().to_vec();
    sasl_final.extend_from_slice(verifier.as_bytes());
    write_tagged(stream, b'R', &sasl_final).await?;
    Ok(true)
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = vec![tag];
    msg.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(body);
    msg
}

pub async fn write_tagged<S: AsyncWrite + Unpin>(
    stream: &mut S,
    tag: u8,
    body: &[u8],
) -> std::io::Result<()> {
    stream.write_all(&frame(tag, body)).await?;
    stream.flush().await
}

pub async fn read_tagged<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<(u8, Vec<u8>)> {
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).await?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await?;
    let mut body = vec![0u8; (u32::from_be_bytes(len) as usize).clamp(4, 1 << 20) - 4];
    stream.read_exact(&mut body).await?;
    Ok((tag[0], body))
}

pub fn error_frame((code, reason): (&str, &str)) -> Vec<u8> {
    let mut body = b"SFATAL\0C".to_vec();
    body.extend_from_slice(code.as_bytes());
    body.extend_from_slice(b"\0M");
    body.extend_from_slice(reason.as_bytes());
    body.extend_from_slice(b"\0\0");
    frame(b'E', &body)
}

pub struct Pki {
    pub ca_der: CertificateDer<'static>,
    pub ca_pem: String,
    pub leaf_sha256: [u8; 32],
    pub server: Arc<rustls::ServerConfig>,
}

pub fn pki(san: &str) -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "zs-pg-test-ca");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let mut leaf_params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let mut leaf_sha256 = [0u8; 32];
    leaf_sha256.copy_from_slice(&Sha256::digest(leaf.der()));
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )
    .unwrap();
    Pki {
        ca_der: ca.der().clone(),
        ca_pem: ca.pem(),
        leaf_sha256,
        server: Arc::new(server),
    }
}

pub async fn listen(
    host: &str,
    port: u16,
    tls: UpstreamTls,
    materialize: Materialize,
    diag: DiagLog,
) -> SocketAddr {
    let endpoint = UpstreamEndpoint::new(host, port).unwrap();
    let listener = PostgresListener::bind_endpoint(
        "127.0.0.1:0",
        endpoint,
        SslPolicy::RefuseOnLoopback,
        tls,
        materialize,
    )
    .await
    .unwrap()
    .with_diag(diag, RESOURCE);
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    local
}

pub fn materialize(password: &'static str) -> Materialize {
    Arc::new(move || Ok(Credential::from_bytes(password.as_bytes().to_vec()).unwrap()))
}

pub fn counted(password: &'static str) -> (Materialize, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let materialize: Materialize = Arc::new(move || {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(Credential::from_bytes(password.as_bytes().to_vec()).unwrap())
    });
    (materialize, calls)
}

pub async fn login(local: SocketAddr) -> Result<TcpStream, Vec<u8>> {
    let mut client = TcpStream::connect(local).await.unwrap();
    client
        .write_all(&zs_proto_postgres::startup_packet("alice", "appdb"))
        .await
        .unwrap();
    loop {
        let (tag, body) = tokio::time::timeout(Duration::from_secs(10), read_tagged(&mut client))
            .await
            .expect("the listener must answer within 10 s")
            .expect("the listener closed without an answer");
        match tag {
            b'Z' => return Ok(client),
            b'E' => return Err(frame(tag, &body)),
            _ => {}
        }
    }
}

pub async fn query(client: &mut TcpStream, sql: &str) -> String {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    write_tagged(client, b'Q', &body).await.unwrap();
    let mut complete = String::new();
    loop {
        let (tag, body) = tokio::time::timeout(Duration::from_secs(10), read_tagged(client))
            .await
            .unwrap()
            .unwrap();
        match tag {
            b'C' => {
                complete = String::from_utf8_lossy(&body)
                    .trim_end_matches('\0')
                    .to_string()
            }
            b'Z' => return complete,
            _ => {}
        }
    }
}

pub fn cancel_packet() -> Vec<u8> {
    let mut packet = 16u32.to_be_bytes().to_vec();
    packet.extend_from_slice(&CANCEL_CODE.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 9]);
    packet
}

pub async fn send_cancel(local: SocketAddr) {
    let mut client = TcpStream::connect(local).await.unwrap();
    client.write_all(&cancel_packet()).await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest)).await;
}

pub fn open_diag(dir: &Path) -> (DiagLog, PathBuf) {
    let path = dir.join("diag.jsonl");
    (DiagLog::open_with_cap(&path, "t-1", 1 << 20).unwrap(), path)
}

pub async fn events(diag: &DiagLog, path: &Path) -> Vec<serde_json::Value> {
    tokio::time::sleep(Duration::from_millis(200)).await;
    diag.close();
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

pub fn named<'a>(events: &'a [serde_json::Value], name: &str) -> Vec<&'a serde_json::Value> {
    events.iter().filter(|e| e["event"] == name).collect()
}

pub async fn eventually(check: impl Fn() -> bool) -> bool {
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    check()
}
