#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zs_diag::DiagLog;
use zs_proto_redis::reply::Framer;
use zs_proto_redis::resp::{self, Command};
use zs_proto_redis::{
    AuditRefusal, Auth, Materialize, RedisListener, UpstreamEndpoint, UpstreamTls,
};

pub const USER: &str = "zs-app";
pub const PASSWORD: &str = "zs-test-redis-password";
pub const SHORT_PASSWORD: &str = "s3";
pub const WRONG: &str = "zs-test-wrong-password";
pub const CLIENT_PASSWORD: &str = "client-supplied-secret";
pub const RESOURCE: &str = "orders-redis";
pub const MOVED_TARGET: &str = "10.255.0.7:6379";
pub const OK: &[u8] = b"+OK\r\n";
pub const WRONG_PASS: &[u8] = b"-WRONGPASS invalid username-password pair\r\n";
pub const HELLO_REPLY: &[u8] = b"%3\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n7.2.0\r\n$5\r\nproto\r\n$1\r\n3\r\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMode {
    Accept,
    Refuse,
    Open,
}

pub const OPEN_REPLY: &[u8] = b"-ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?\r\n";

#[derive(Clone)]
struct Echo {
    reply: Vec<u8>,
    split: Option<usize>,
    delay: Duration,
}

#[derive(Clone)]
pub struct Script {
    auth: AuthMode,
    user: &'static str,
    password: &'static str,
    tls: Option<Arc<rustls::ServerConfig>>,
    replies: Arc<Mutex<VecDeque<Vec<u8>>>>,
    echo: Option<Echo>,
    default_reply: Vec<u8>,
    silent: bool,
    reply_delay: Duration,
}

impl Script {
    pub fn new() -> Self {
        Self {
            auth: AuthMode::Accept,
            user: USER,
            password: PASSWORD,
            tls: None,
            replies: Arc::new(Mutex::new(VecDeque::new())),
            echo: None,
            default_reply: OK.to_vec(),
            silent: false,
            reply_delay: Duration::ZERO,
        }
    }

    pub fn accepting(user: &'static str, password: &'static str) -> Self {
        Self {
            user,
            password,
            ..Self::new()
        }
    }

    pub fn refusing_auth() -> Self {
        Self {
            auth: AuthMode::Refuse,
            ..Self::new()
        }
    }

    pub fn open() -> Self {
        Self {
            auth: AuthMode::Open,
            ..Self::new()
        }
    }

    pub fn echoing(credential: &'static str) -> Self {
        Self {
            password: credential,
            echo: Some(Echo {
                reply: echo_reply(credential.as_bytes()),
                split: None,
                delay: Duration::ZERO,
            }),
            ..Self::new()
        }
    }

    pub fn echoing_split(credential: &'static str, credential_bytes_first: usize) -> Self {
        let reply = echo_reply(credential.as_bytes());
        let cut = reply.len() - credential.len() - 2 + credential_bytes_first.min(credential.len());
        Self {
            password: credential,
            echo: Some(Echo {
                reply,
                split: Some(cut),
                delay: Duration::from_millis(100),
            }),
            ..Self::new()
        }
    }

    pub fn with_reply_delay(mut self, delay: Duration) -> Self {
        self.reply_delay = delay;
        self
    }

    pub fn silent(mut self) -> Self {
        self.silent = true;
        self
    }

    pub fn top_level_moved(target: &str) -> Self {
        Self::new().with_reply(format!("-MOVED {target}\r\n").into_bytes())
    }

    pub fn nested_moved(target: &str) -> Self {
        Self::new().with_reply(format!("*1\r\n-MOVED {target}\r\n").into_bytes())
    }

    pub fn with_reply(self, reply: Vec<u8>) -> Self {
        self.replies.lock().unwrap().push_back(reply);
        self
    }

    pub fn with_tls(mut self, server: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(server);
        self
    }

    pub fn with_default_reply(mut self, reply: Vec<u8>) -> Self {
        self.default_reply = reply;
        self
    }
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

pub fn echo_reply(credential: &[u8]) -> Vec<u8> {
    let mut reply = Vec::new();
    reply.extend_from_slice(format!("${}\r\n", credential.len() + 5).as_bytes());
    reply.extend_from_slice(b"echo:");
    reply.extend_from_slice(credential);
    reply.extend_from_slice(b"\r\n");
    reply
}

#[derive(Default)]
pub struct Seen {
    pub accepts: usize,
    pub tls: bool,
    pub frames: Vec<Vec<Vec<u8>>>,
    pub names: Vec<String>,
    pub auth_ok: bool,
}

pub struct Fake {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Seen>>,
}

impl Fake {
    pub fn seen<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.seen.lock().unwrap())
    }

    pub fn frames(&self) -> Vec<Vec<Vec<u8>>> {
        self.seen(|seen| seen.frames.clone())
    }

    pub fn names(&self) -> Vec<String> {
        self.seen(|seen| seen.names.clone())
    }

    pub fn commands(&self) -> Vec<Vec<Vec<u8>>> {
        self.frames()
            .into_iter()
            .filter(|args| !named(args, "AUTH"))
            .collect()
    }

    pub fn auths(&self) -> Vec<Vec<Vec<u8>>> {
        self.frames()
            .into_iter()
            .filter(|args| named(args, "AUTH"))
            .collect()
    }

    pub fn authenticated(&self) -> bool {
        self.seen(|seen| seen.auth_ok)
    }

    pub fn saw_bytes(&self, needle: &[u8]) -> bool {
        !needle.is_empty()
            && self.frames().iter().any(|args| {
                args.iter()
                    .any(|arg| arg.windows(needle.len()).any(|window| window == needle))
            })
    }

    pub async fn listen(&self, tls: Option<UpstreamTls>, materialize: Materialize) -> SocketAddr {
        listen(
            self.addr,
            tls,
            auth(),
            materialize,
            DiagLog::disabled(),
            None,
        )
        .await
    }
}

fn named(args: &[Vec<u8>], name: &str) -> bool {
    args.first()
        .is_some_and(|arg| arg.eq_ignore_ascii_case(name.as_bytes()))
}

pub async fn start(script: Script) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(script);
    let seen = Arc::new(Mutex::new(Seen::default()));
    let task_seen = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            task_seen.lock().unwrap().accepts += 1;
            let (script, seen) = (state.clone(), task_seen.clone());
            tokio::spawn(async move {
                let config = script.tls.clone();
                match config {
                    Some(config) => {
                        let acceptor = tokio_rustls::TlsAcceptor::from(config);
                        if let Ok(stream) = acceptor.accept(stream).await {
                            seen.lock().unwrap().tls = true;
                            let _ = serve(stream, script, seen).await;
                        }
                    }
                    None => {
                        let _ = serve(stream, script, seen).await;
                    }
                }
            });
        }
    });
    Fake { addr, seen }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    script: Arc<Script>,
    seen: Arc<Mutex<Seen>>,
) -> std::io::Result<()> {
    loop {
        let Some(command) = resp::read_command(&mut stream).await.ok().flatten() else {
            return Ok(());
        };
        let args: Vec<Vec<u8>> = command.args().iter().map(|arg| arg.to_vec()).collect();
        let name = String::from_utf8_lossy(&args[0]).to_ascii_uppercase();
        {
            let mut seen = seen.lock().unwrap();
            seen.frames.push(args.clone());
            seen.names.push(name.clone());
        }
        if script.silent {
            tokio::time::sleep(Duration::from_secs(60)).await;
            return Ok(());
        }
        if name == "AUTH" {
            stream.write_all(&auth_reply(&script, &args, &seen)).await?;
            stream.flush().await?;
            continue;
        }
        if name == "HELLO" {
            stream
                .write_all(&hello_reply(&script, &args, &seen))
                .await?;
            stream.flush().await?;
            continue;
        }
        tokio::time::sleep(script.reply_delay).await;
        if let Some(echo) = &script.echo {
            write_echo(&mut stream, echo).await?;
            continue;
        }
        let reply = script
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| script.default_reply.clone());
        stream.write_all(&reply).await?;
        stream.flush().await?;
    }
}

async fn write_echo<S: AsyncWrite + Unpin>(stream: &mut S, echo: &Echo) -> std::io::Result<()> {
    if let Some(cut) = echo.split {
        stream.write_all(&echo.reply[..cut]).await?;
        stream.flush().await?;
        tokio::time::sleep(echo.delay).await;
        stream.write_all(&echo.reply[cut..]).await?;
    } else {
        stream.write_all(&echo.reply).await?;
    }
    stream.flush().await
}

fn auth_reply(script: &Script, args: &[Vec<u8>], seen: &Mutex<Seen>) -> Vec<u8> {
    if script.auth == AuthMode::Refuse {
        return WRONG_PASS.to_vec();
    }
    if script.auth == AuthMode::Open {
        return match args {
            [_, _] => OPEN_REPLY.to_vec(),
            [_, user, _] if user.as_slice() == b"default" => OK.to_vec(),
            _ => WRONG_PASS.to_vec(),
        };
    }
    let (user, credential) = match args {
        [_, credential] => (None, credential),
        [_, user, credential, ..] => (Some(user), credential),
        _ => return WRONG_PASS.to_vec(),
    };
    let user_ok = user.is_none_or(|user| user.as_slice() == script.user.as_bytes());
    let credential_ok = credential.as_slice() == script.password.as_bytes();
    if user_ok && credential_ok {
        seen.lock().unwrap().auth_ok = true;
        OK.to_vec()
    } else {
        WRONG_PASS.to_vec()
    }
}

fn hello_reply(script: &Script, args: &[Vec<u8>], seen: &Mutex<Seen>) -> Vec<u8> {
    let mut index = 1;
    if args
        .get(1)
        .is_some_and(|arg| !arg.is_empty() && arg.iter().all(|byte| byte.is_ascii_digit()))
    {
        index = 2;
    }
    while index < args.len() {
        if args[index].eq_ignore_ascii_case(b"AUTH") {
            if index + 2 >= args.len() {
                return WRONG_PASS.to_vec();
            }
            let user_ok = args[index + 1].as_slice() == script.user.as_bytes();
            let credential_ok = args[index + 2].as_slice() == script.password.as_bytes();
            if script.auth == AuthMode::Accept && user_ok && credential_ok {
                seen.lock().unwrap().auth_ok = true;
                return HELLO_REPLY.to_vec();
            }
            return WRONG_PASS.to_vec();
        }
        if args[index].eq_ignore_ascii_case(b"SETNAME") {
            index += 2;
            continue;
        }
        break;
    }
    HELLO_REPLY.to_vec()
}

pub fn auth() -> Auth {
    Auth::new(Some(USER.to_string()))
}

pub fn auth_default() -> Auth {
    Auth::new(None)
}

pub fn admit_all() -> zs_protocol::CallerCheck {
    Arc::new(|_, _| true)
}

pub async fn listen(
    upstream: SocketAddr,
    tls: Option<UpstreamTls>,
    auth: Auth,
    materialize: Materialize,
    diag: DiagLog,
    audit: Option<AuditRefusal>,
) -> SocketAddr {
    listen_with(
        upstream,
        tls,
        auth,
        materialize,
        diag,
        audit,
        None,
        Some(admit_all()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn listen_with(
    upstream: SocketAddr,
    tls: Option<UpstreamTls>,
    auth: Auth,
    materialize: Materialize,
    diag: DiagLog,
    audit: Option<AuditRefusal>,
    budget: Option<Duration>,
    caller_check: Option<zs_protocol::CallerCheck>,
) -> SocketAddr {
    let endpoint = UpstreamEndpoint::new(upstream.ip().to_string(), upstream.port()).unwrap();
    let mut listener =
        RedisListener::bind_endpoint("127.0.0.1:0", endpoint, tls, auth, materialize)
            .await
            .unwrap()
            .with_diag(diag, RESOURCE);
    if let Some(audit) = audit {
        listener = listener.with_refusal_audit(audit);
    }
    if let Some(budget) = budget {
        listener = listener.with_handshake_budget(budget);
    }
    if let Some(check) = caller_check {
        listener = listener.with_caller_check(check);
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

pub fn denied() -> Materialize {
    Arc::new(|| Err(zs_protocol::Denied::new("no grant for orders-redis")))
}

pub fn counter() -> (Materialize, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let materialize: Materialize = Arc::new(move || {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(zs_credential::Credential::from_bytes(PASSWORD.as_bytes().to_vec()).unwrap())
    });
    (materialize, calls)
}

pub type Refusals = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

pub fn audit_recorder() -> (AuditRefusal, Refusals) {
    let seen: Refusals = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let audit: AuditRefusal = Arc::new(move |operation: &'static str, reason: &'static str| {
        record.lock().unwrap().push((operation, reason));
        Some(7)
    });
    (audit, seen)
}

pub fn unaudited() -> AuditRefusal {
    Arc::new(|_: &'static str, _: &'static str| None::<u64>)
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
        .push(rcgen::DnType::CommonName, "zs-redis-test-ca");
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

pub struct Client {
    pub stream: TcpStream,
    buffered: Vec<u8>,
}

impl Client {
    pub async fn connect(addr: SocketAddr) -> Self {
        Self {
            stream: TcpStream::connect(addr).await.unwrap(),
            buffered: Vec::new(),
        }
    }

    pub async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.stream.flush().await
    }

    pub async fn send_command(&mut self, args: &[&[u8]]) -> std::io::Result<()> {
        let command = Command::new(args.iter().map(|arg| arg.to_vec()).collect());
        self.send(&command.encode()).await
    }

    pub async fn read_reply(&mut self) -> Vec<u8> {
        let mut framer = Framer::new();
        let mut frame = Vec::new();
        let mut reader = vec![0u8; 64 * 1024];
        loop {
            if !self.buffered.is_empty() {
                let buffered = std::mem::take(&mut self.buffered);
                let mut out = Vec::new();
                let (consumed, _) = framer.push(&buffered, &mut out).unwrap();
                frame.extend_from_slice(&buffered[..consumed]);
                if framer.at_boundary() {
                    self.buffered = buffered[consumed..].to_vec();
                    return frame;
                }
            }
            let read = self.stream.read(&mut reader).await.unwrap();
            if read == 0 {
                panic!("the fake client reached EOF before a reply");
            }
            self.buffered.extend_from_slice(&reader[..read]);
        }
    }

    pub async fn close_write(&mut self) {
        let _ = self.stream.shutdown().await;
    }

    pub async fn command(&mut self, args: &[&[u8]]) -> Vec<u8> {
        self.send_command(args).await.unwrap();
        self.read_reply().await
    }

    pub async fn read_to_end(&mut self) -> Vec<u8> {
        let mut rest = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), self.stream.read_to_end(&mut rest)).await;
        rest
    }

    pub async fn closed(&mut self) -> bool {
        let mut rest = Vec::new();
        matches!(
            tokio::time::timeout(Duration::from_secs(5), self.stream.read_to_end(&mut rest)).await,
            Ok(Ok(_)) | Ok(Err(_))
        )
    }
}

pub async fn logged_in(addr: SocketAddr) -> Client {
    let mut client = Client::connect(addr).await;
    let reply = client.command(&[b"PING"]).await;
    assert_eq!(
        reply, OK,
        "positive control: the upstream accepts the login"
    );
    client
}

pub fn error_text(frame: &[u8]) -> String {
    let text = std::str::from_utf8(frame).unwrap_or_default();
    text.trim_start_matches('-').trim_end().to_string()
}

pub fn diag_log(dir: &Path) -> (PathBuf, DiagLog) {
    let path = dir.join("diag.jsonl");
    let diag = DiagLog::open_with_cap(&path, "t-1", 1 << 20).unwrap();
    (path, diag)
}

pub async fn read_diag(path: &Path, diag: DiagLog) -> (String, Vec<serde_json::Value>) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    diag.close();
    let text = std::fs::read_to_string(path).unwrap();
    let events = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (text, events)
}

pub fn in_conn<'a>(
    events: &'a [serde_json::Value],
    name: &str,
    conn: u64,
) -> Vec<&'a serde_json::Value> {
    events
        .iter()
        .filter(|event| {
            event["event"] == name && event["conn"] == conn && event["component"] == "redis"
        })
        .collect()
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
