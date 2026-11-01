#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use zs_diag::DiagLog;
use zs_proto_mysql::packet::{self, AuthSwitch, Greeting, HandshakeResponse, Packet};
use zs_proto_mysql::{
    AuditRefusal, Materialize, MysqlListener, UpstreamEndpoint, UpstreamTls, scramble,
};

pub const PASSWORD: &str = "zs-test-password";
pub const WRONG: &str = "zs-test-wrong-password";
pub const RESOURCE: &str = "orders-mysql";
pub const OK_INFO: &[u8] = b"zs-fake-ok";
pub const SERVER_VERSION: &[u8] = b"8.4.2-zs-fake";
pub const CONNECTION_ID: u32 = 4242;
pub const DENY_TEXT: &str = "Access denied for user 'alice'@'localhost' (using password: YES)";

pub const SERVER_CAPS: u32 = packet::CLIENT_LONG_PASSWORD
    | packet::CLIENT_FOUND_ROWS
    | packet::CLIENT_LONG_FLAG
    | packet::CLIENT_CONNECT_WITH_DB
    | packet::CLIENT_COMPRESS
    | packet::CLIENT_LOCAL_FILES
    | packet::CLIENT_PROTOCOL_41
    | packet::CLIENT_TRANSACTIONS
    | packet::CLIENT_SECURE_CONNECTION
    | packet::CLIENT_MULTI_STATEMENTS
    | packet::CLIENT_MULTI_RESULTS
    | packet::CLIENT_PLUGIN_AUTH
    | packet::CLIENT_CONNECT_ATTRS
    | packet::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | packet::CLIENT_SESSION_TRACK
    | packet::CLIENT_DEPRECATE_EOF
    | packet::CLIENT_ZSTD_COMPRESSION_ALGORITHM
    | packet::CLIENT_MULTI_FACTOR_AUTHENTICATION;

pub const CLIENT_CAPS: u32 = packet::CLIENT_LONG_PASSWORD
    | packet::CLIENT_FOUND_ROWS
    | packet::CLIENT_LONG_FLAG
    | packet::CLIENT_CONNECT_WITH_DB
    | packet::CLIENT_PROTOCOL_41
    | packet::CLIENT_TRANSACTIONS
    | packet::CLIENT_SECURE_CONNECTION
    | packet::CLIENT_MULTI_RESULTS
    | packet::CLIENT_PLUGIN_AUTH
    | packet::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | packet::CLIENT_CONNECT_ATTRS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Accept,
    ResetAfterCommand,
    FullAuth,
    SwitchTo(&'static [u8]),
    EndlessSwitch,
    ErrBeforeGreeting,
}

#[derive(Clone)]
pub struct Script {
    pub plugin: &'static [u8],
    pub flow: Flow,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub deny_text: &'static str,
}

impl Script {
    pub fn new(plugin: &'static [u8], flow: Flow) -> Self {
        Self {
            plugin,
            flow,
            tls: None,
            deny_text: DENY_TEXT,
        }
    }

    pub fn with_deny_text(mut self, text: &'static str) -> Self {
        self.deny_text = text;
        self
    }

    pub fn with_tls(mut self, server: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(server);
        self
    }
}

#[derive(Default)]
pub struct Seen {
    pub accepts: usize,
    pub ssl_requests: usize,
    pub tls: bool,
    pub responses: usize,
    pub auth_packets: Vec<Vec<u8>>,
    pub authenticated: bool,
    pub commands: Vec<Vec<u8>>,
    pub user: Vec<u8>,
    pub database: Option<Vec<u8>>,
    pub attributes: Option<Vec<u8>>,
    pub capabilities: u32,
}

pub struct Fake {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Seen>>,
}

impl Fake {
    pub fn seen<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.seen.lock().unwrap())
    }

    pub fn saw_bytes(&self, needle: &[u8]) -> bool {
        self.seen(|s| {
            s.auth_packets
                .iter()
                .chain(s.commands.iter())
                .any(|p| p.windows(needle.len()).any(|w| w == needle))
        })
    }

    pub async fn listen(&self, tls: UpstreamTls, materialize: Materialize) -> SocketAddr {
        listen(
            "127.0.0.1",
            self.addr.port(),
            tls,
            materialize,
            DiagLog::disabled(),
            None,
        )
        .await
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub fn salt(tag: u8) -> Vec<u8> {
    (0..20u8)
        .map(|i| 0x21 + (i.wrapping_add(tag) % 90))
        .collect()
}

pub async fn start(script: Script) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            record.lock().unwrap().accepts += 1;
            let (script, record) = (script.clone(), record.clone());
            tokio::spawn(async move {
                let _ = serve(stream, script, record).await;
            });
        }
    });
    Fake { addr, seen }
}

fn token_matches(plugin: &[u8], challenge: &[u8], data: &[u8]) -> bool {
    let expected = if plugin == packet::CACHING_SHA2_PASSWORD {
        scramble::caching_sha2(PASSWORD.as_bytes(), challenge)
    } else {
        scramble::native(PASSWORD.as_bytes(), challenge)
    };
    expected == data
}

fn cleartext() -> Vec<u8> {
    let mut out = PASSWORD.as_bytes().to_vec();
    out.push(0);
    out
}

async fn exchange(
    stream: &mut Box<dyn Io>,
    seq: &mut u8,
    payload: &[u8],
    seen: &Arc<Mutex<Seen>>,
) -> std::io::Result<Vec<u8>> {
    packet::write_packet(stream, *seq, payload).await?;
    let answer = packet::read_packet(stream, packet::HANDSHAKE_LIMIT).await?;
    *seq = answer.seq.wrapping_add(1);
    seen.lock()
        .unwrap()
        .auth_packets
        .push(answer.payload.clone());
    Ok(answer.payload)
}

async fn authenticate(
    stream: &mut Box<dyn Io>,
    script: &Script,
    first: &[u8],
    seq: &mut u8,
    seen: &Arc<Mutex<Seen>>,
) -> std::io::Result<bool> {
    match script.flow {
        Flow::Accept | Flow::ResetAfterCommand => {
            if !token_matches(script.plugin, &salt(1), first) {
                return Ok(false);
            }
            if script.plugin == packet::CACHING_SHA2_PASSWORD {
                packet::write_packet(stream, *seq, &[packet::MORE_DATA_HEADER, 0x03]).await?;
                *seq = seq.wrapping_add(1);
            }
            Ok(true)
        }
        Flow::FullAuth => {
            if !token_matches(packet::CACHING_SHA2_PASSWORD, &salt(1), first) {
                return Ok(false);
            }
            let answer = exchange(stream, seq, &[packet::MORE_DATA_HEADER, 0x04], seen).await?;
            Ok(answer == cleartext())
        }
        Flow::SwitchTo(plugin) => {
            let request = AuthSwitch {
                plugin: plugin.to_vec(),
                data: salt(7),
            };
            let answer = exchange(stream, seq, &request.encode(), seen).await?;
            if plugin == packet::SHA256_PASSWORD || plugin == packet::CLEAR_PASSWORD {
                Ok(answer == cleartext())
            } else {
                Ok(token_matches(plugin, &salt(7), &answer))
            }
        }
        Flow::EndlessSwitch => loop {
            let request = AuthSwitch {
                plugin: packet::NATIVE_PASSWORD.to_vec(),
                data: salt(3),
            };
            let answer = exchange(stream, seq, &request.encode(), seen).await?;
            if !token_matches(packet::NATIVE_PASSWORD, &salt(3), &answer) {
                return Ok(false);
            }
        },
        Flow::ErrBeforeGreeting => Ok(false),
    }
}

async fn serve(mut tcp: TcpStream, script: Script, seen: Arc<Mutex<Seen>>) -> std::io::Result<()> {
    if script.flow == Flow::ErrBeforeGreeting {
        let refusal = packet::err_packet(1040, "08004", "Too many connections");
        return packet::write_packet(&mut tcp, 0, &refusal).await;
    }
    let mut capabilities = SERVER_CAPS;
    if script.tls.is_some() {
        capabilities |= packet::CLIENT_SSL;
    }
    let greeting = Greeting {
        server_version: SERVER_VERSION.to_vec(),
        connection_id: CONNECTION_ID,
        scramble: salt(1),
        capabilities,
        charset: 255,
        status: 2,
        plugin: script.plugin.to_vec(),
    };
    packet::write_packet(&mut tcp, 0, &greeting.encode()).await?;
    let first = packet::read_packet(&mut tcp, packet::HANDSHAKE_LIMIT).await?;
    let (mut stream, response): (Box<dyn Io>, Packet) = if packet::is_ssl_request(&first.payload) {
        seen.lock().unwrap().ssl_requests += 1;
        let Some(server) = script.tls.clone() else {
            return Ok(());
        };
        let mut tls = tokio_rustls::TlsAcceptor::from(server).accept(tcp).await?;
        seen.lock().unwrap().tls = true;
        let response = packet::read_packet(&mut tls, packet::HANDSHAKE_LIMIT).await?;
        (Box::new(tls), response)
    } else {
        if script.flow == Flow::ResetAfterCommand {
            tcp.set_zero_linger()?;
        }
        (Box::new(tcp), first)
    };
    let parsed = HandshakeResponse::parse(&response.payload)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    {
        let mut record = seen.lock().unwrap();
        record.responses += 1;
        record.auth_packets.push(parsed.auth_data.clone());
        record.user = parsed.user.clone();
        record.database = parsed.database.clone();
        record.attributes = parsed.attributes.clone();
        record.capabilities = parsed.capabilities;
    }
    let mut seq = response.seq.wrapping_add(1);
    if !authenticate(&mut stream, &script, &parsed.auth_data, &mut seq, &seen).await? {
        let denied = packet::err_packet(1045, "28000", script.deny_text);
        return packet::write_packet(&mut stream, seq, &denied).await;
    }
    seen.lock().unwrap().authenticated = true;
    packet::write_packet(&mut stream, seq, &packet::ok_packet(OK_INFO)).await?;
    loop {
        let Ok(command) = packet::read_packet(&mut stream, 1 << 24).await else {
            return Ok(());
        };
        if command.payload.first() == Some(&packet::COM_QUIT) {
            return Ok(());
        }
        seen.lock().unwrap().commands.push(command.payload.clone());
        if script.flow == Flow::ResetAfterCommand {
            return Ok(());
        }
        packet::write_packet(
            &mut stream,
            command.seq.wrapping_add(1),
            &packet::ok_packet(OK_INFO),
        )
        .await?;
    }
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
        .push(rcgen::DnType::CommonName, "zs-mysql-test-ca");
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
    audit: Option<AuditRefusal>,
) -> SocketAddr {
    let endpoint = UpstreamEndpoint::new(host, port).unwrap();
    let mut listener = MysqlListener::bind_endpoint("127.0.0.1:0", endpoint, tls, materialize)
        .await
        .unwrap()
        .with_diag(diag, RESOURCE);
    if let Some(audit) = audit {
        listener = listener.with_refusal_audit(audit);
    }
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    local
}

pub fn materialize(password: &'static str) -> Materialize {
    Arc::new(move || {
        Ok(zs_credential::Credential::from_bytes(password.as_bytes().to_vec()).unwrap())
    })
}

pub fn counted(password: &'static str) -> (Materialize, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let materialize: Materialize = Arc::new(move || {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(zs_credential::Credential::from_bytes(password.as_bytes().to_vec()).unwrap())
    });
    (materialize, calls)
}

pub type Refusals = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

pub fn audit_recorder() -> (AuditRefusal, Refusals) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let audit: AuditRefusal = Arc::new(move |operation: &'static str, reason: &'static str| {
        record.lock().unwrap().push((operation, reason));
        Some(7)
    });
    (audit, seen)
}

fn client_response(capabilities: u32, user: &[u8], database: Option<&[u8]>) -> HandshakeResponse {
    let mut attributes = Vec::new();
    packet::put_lenenc_bytes(&mut attributes, b"_client_name");
    packet::put_lenenc_bytes(&mut attributes, b"zs-fake-client");
    HandshakeResponse {
        capabilities,
        max_packet: 16 << 20,
        charset: 255,
        user: user.to_vec(),
        auth_data: b"client-auth-data-ignored".to_vec(),
        database: database.map(<[u8]>::to_vec),
        plugin: Some(packet::NATIVE_PASSWORD.to_vec()),
        attributes: Some(attributes),
    }
}

pub struct Session {
    pub stream: TcpStream,
    pub greeting: Greeting,
    pub reply: Packet,
}

impl Session {
    pub async fn command(&mut self, payload: &[u8]) -> std::io::Result<Packet> {
        packet::write_packet(&mut self.stream, 0, payload).await?;
        packet::read_packet(&mut self.stream, 1 << 24).await
    }

    pub async fn query(&mut self, sql: &str) -> std::io::Result<Vec<u8>> {
        let mut command = vec![packet::COM_QUERY];
        command.extend_from_slice(sql.as_bytes());
        packet::write_packet(&mut self.stream, 0, &command).await?;
        let mut all = Vec::new();
        let mut eofs = 0;
        loop {
            let next = packet::read_packet(&mut self.stream, 1 << 24).await?;
            let first = next.payload.first().copied();
            let opening = all.is_empty();
            all.extend_from_slice(&next.payload);
            if first == Some(packet::ERR_HEADER) || (opening && first == Some(packet::OK_HEADER)) {
                return Ok(all);
            }
            if first == Some(packet::SWITCH_HEADER) && next.payload.len() < 9 {
                eofs += 1;
                if eofs == 2 {
                    return Ok(all);
                }
            }
        }
    }

    pub async fn closed(&mut self) -> bool {
        let mut rest = Vec::new();
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.stream.read_to_end(&mut rest)).await,
            Ok(Ok(_)) | Ok(Err(_))
        )
    }
}

pub async fn login(addr: SocketAddr, capabilities: u32) -> Session {
    login_as(addr, capabilities, b"alice", Some(b"appdb")).await
}

pub async fn login_as(
    addr: SocketAddr,
    capabilities: u32,
    user: &[u8],
    database: Option<&[u8]>,
) -> Session {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let hello = packet::read_packet(&mut stream, packet::HANDSHAKE_LIMIT)
        .await
        .unwrap();
    let greeting = Greeting::parse(&hello.payload).unwrap();
    let response = client_response(capabilities, user, database);
    packet::write_packet(&mut stream, 1, &response.encode())
        .await
        .unwrap();
    let reply = packet::read_packet(&mut stream, packet::HANDSHAKE_LIMIT)
        .await
        .unwrap();
    Session {
        stream,
        greeting,
        reply,
    }
}

pub async fn send_raw(addr: SocketAddr, payload: &[u8]) -> Packet {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    packet::read_packet(&mut stream, packet::HANDSHAKE_LIMIT)
        .await
        .unwrap();
    packet::write_packet(&mut stream, 1, payload).await.unwrap();
    packet::read_packet(&mut stream, packet::HANDSHAKE_LIMIT)
        .await
        .unwrap()
}

pub async fn first_packet(addr: SocketAddr) -> Packet {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    packet::read_packet(&mut stream, packet::HANDSHAKE_LIMIT)
        .await
        .unwrap()
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
