#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use md5::Md5;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zs_diag::DiagLog;
use zs_proto_mongo::bson::Doc;
use zs_proto_mongo::topology::is_hello;
use zs_proto_mongo::wire::{self, Header, OpMsg, OpQuery};
use zs_proto_mongo::{
    AuditRefusal, Auth, Materialize, MongoListener, UpstreamEndpoint, UpstreamTls,
};

pub const USER: &str = "alice";
pub const SOURCE: &str = "appdb";
pub const PASSWORD: &str = "zs-test-password";
pub const WRONG: &str = "zs-test-wrong-password";
pub const RESOURCE: &str = "orders-mongo";
pub const SET: &str = "rs0";
pub const SALT: &[u8] = b"zs-fake-mongo-salt";
pub const ITERATIONS: u32 = 4096;
pub const HIGH_ITERATIONS: u32 = 100_000;
pub const AUTH_FAILED_TEXT: &str = "Authentication failed.";
pub const BIG_LEN: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Set,
    Standalone,
    Mongos,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sasl {
    Accept,
    WrongSignature,
    ShortNonce,
    LowIterations,
    HighIterations,
    NoSkip,
    Endless,
}

#[derive(Clone)]
pub struct Script {
    pub mode: Mode,
    pub members: usize,
    pub primary: Option<usize>,
    pub mechanisms: Option<Vec<&'static str>>,
    pub sasl: Sasl,
    pub max_wire: i32,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub member_tls: Option<(usize, Arc<rustls::ServerConfig>)>,
    pub hosts: Option<Vec<String>>,
    pub claimed_primary: Option<usize>,
    pub other_set: Option<usize>,
    pub hello_ok: bool,
    pub silent: bool,
    pub streamed: usize,
    pub compressed_replies: bool,
}

impl Script {
    pub fn set(members: usize, primary: Option<usize>) -> Self {
        Self {
            mode: Mode::Set,
            members,
            primary,
            mechanisms: Some(vec!["SCRAM-SHA-1", "SCRAM-SHA-256"]),
            sasl: Sasl::Accept,
            max_wire: 21,
            tls: None,
            member_tls: None,
            hosts: None,
            claimed_primary: None,
            other_set: None,
            hello_ok: true,
            silent: false,
            streamed: 0,
            compressed_replies: false,
        }
    }

    pub fn standalone() -> Self {
        Self {
            mode: Mode::Standalone,
            ..Self::set(1, Some(0))
        }
    }

    pub fn mongos() -> Self {
        Self {
            mode: Mode::Mongos,
            ..Self::set(1, Some(0))
        }
    }

    pub fn with_mechanisms(mut self, mechanisms: Option<Vec<&'static str>>) -> Self {
        self.mechanisms = mechanisms;
        self
    }

    pub fn with_sasl(mut self, sasl: Sasl) -> Self {
        self.sasl = sasl;
        self
    }

    pub fn with_max_wire(mut self, version: i32) -> Self {
        self.max_wire = version;
        self
    }

    pub fn with_tls(mut self, server: Arc<rustls::ServerConfig>) -> Self {
        self.tls = Some(server);
        self
    }

    pub fn with_member_tls(mut self, member: usize, server: Arc<rustls::ServerConfig>) -> Self {
        self.member_tls = Some((member, server));
        self
    }

    pub fn with_hosts(mut self, hosts: Vec<String>) -> Self {
        self.hosts = Some(hosts);
        self
    }

    pub fn claiming_primary(mut self, member: usize) -> Self {
        self.claimed_primary = Some(member);
        self
    }

    pub fn with_other_set(mut self, member: usize) -> Self {
        self.other_set = Some(member);
        self
    }

    pub fn with_hello_error(mut self) -> Self {
        self.hello_ok = false;
        self
    }

    pub fn silent(mut self) -> Self {
        self.silent = true;
        self
    }

    pub fn streamed(mut self, replies: usize) -> Self {
        self.streamed = replies;
        self
    }

    pub fn with_compressed_replies(mut self) -> Self {
        self.compressed_replies = true;
        self
    }
}

#[derive(Default)]
pub struct Seen {
    pub accepts: usize,
    pub frames: usize,
    pub hellos: Vec<Doc>,
    pub hello_ops: Vec<i32>,
    pub sasl: Vec<String>,
    pub sasl_dbs: Vec<String>,
    pub authenticated: bool,
    pub commands: Vec<String>,
    pub raw: Vec<Vec<u8>>,
    pub tls: bool,
}

pub struct Member {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Seen>>,
}

struct SetState {
    script: Script,
    addrs: Vec<String>,
    primary: Mutex<Option<usize>>,
    silent_member: Mutex<Option<usize>>,
}

pub struct FakeSet {
    pub members: Vec<Member>,
    state: Arc<SetState>,
}

impl FakeSet {
    pub fn seed(&self) -> SocketAddr {
        self.members[0].addr
    }

    pub fn addr(&self, member: usize) -> String {
        self.state.addrs[member].clone()
    }

    pub fn set_primary(&self, primary: Option<usize>) {
        *self.state.primary.lock().unwrap() = primary;
    }

    pub fn silence(&self, member: Option<usize>) {
        *self.state.silent_member.lock().unwrap() = member;
    }

    pub fn seen<T>(&self, member: usize, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.members[member].seen.lock().unwrap())
    }

    pub fn saw_bytes(&self, needle: &[u8]) -> bool {
        self.members.iter().any(|m| {
            m.seen
                .lock()
                .unwrap()
                .raw
                .iter()
                .any(|frame| frame.windows(needle.len()).any(|w| w == needle))
        })
    }

    pub fn sasl_total(&self) -> usize {
        self.members
            .iter()
            .map(|m| m.seen.lock().unwrap().sasl.len())
            .sum()
    }

    pub fn accepts_total(&self) -> usize {
        self.members
            .iter()
            .map(|m| m.seen.lock().unwrap().accepts)
            .sum()
    }

    pub async fn listen(&self, tls: Option<UpstreamTls>, materialize: Materialize) -> SocketAddr {
        listen(self.seed(), tls, materialize, DiagLog::disabled(), None).await
    }
}

pub async fn start(script: Script) -> FakeSet {
    let mut listeners = Vec::new();
    for _ in 0..script.members {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let addrs: Vec<String> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().to_string())
        .collect();
    let state = Arc::new(SetState {
        primary: Mutex::new(script.primary),
        silent_member: Mutex::new(None),
        script,
        addrs,
    });
    let mut members = Vec::new();
    for (index, listener) in listeners.into_iter().enumerate() {
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (task_state, task_seen) = (state.clone(), seen.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                task_seen.lock().unwrap().accepts += 1;
                let (state, seen) = (task_state.clone(), task_seen.clone());
                tokio::spawn(async move {
                    let config = match &state.script.member_tls {
                        Some((member, server)) if *member == index => Some(server.clone()),
                        _ => state.script.tls.clone(),
                    };
                    match config {
                        Some(config) => {
                            let acceptor = tokio_rustls::TlsAcceptor::from(config);
                            if let Ok(stream) = acceptor.accept(stream).await {
                                seen.lock().unwrap().tls = true;
                                let _ = serve(stream, index, state, seen).await;
                            }
                        }
                        None => {
                            let _ = serve(stream, index, state, seen).await;
                        }
                    }
                });
            }
        });
        members.push(Member { addr, seen });
    }
    FakeSet { members, state }
}

struct ServerScram {
    mechanism: &'static str,
    first_bare: String,
    server_first: String,
    nonce: String,
    salted: Vec<u8>,
    user_ok: bool,
    skip_empty: bool,
    finished: bool,
}

fn hmac(mechanism: &str, key: &[u8], data: &[u8]) -> Vec<u8> {
    if mechanism == "SCRAM-SHA-1" {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    } else {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

fn hash(mechanism: &str, data: &[u8]) -> Vec<u8> {
    if mechanism == "SCRAM-SHA-1" {
        Sha1::digest(data).to_vec()
    } else {
        Sha256::digest(data).to_vec()
    }
}

fn salted_password(mechanism: &str, iterations: u32) -> Vec<u8> {
    let password: Vec<u8> = if mechanism == "SCRAM-SHA-1" {
        let digest = Md5::digest(format!("{USER}:mongo:{PASSWORD}").as_bytes());
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            .into_bytes()
    } else {
        PASSWORD.as_bytes().to_vec()
    };
    let mut first = SALT.to_vec();
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut block = hmac(mechanism, &password, &first);
    let mut result = block.clone();
    for _ in 1..iterations {
        block = hmac(mechanism, &password, &block);
        for (a, b) in result.iter_mut().zip(&block) {
            *a ^= *b;
        }
    }
    result
}

fn failed(code: i32, name: &str, text: &str) -> Doc {
    Doc::new()
        .with_f64("ok", 0.0)
        .with_str("errmsg", text)
        .with_i32("code", code)
        .with_str("codeName", name)
}

fn hello_reply(state: &SetState, index: usize, request: &Doc) -> Doc {
    let script = &state.script;
    if !script.hello_ok {
        return failed(91, "ShutdownInProgress", "fake hello error");
    }
    let primary = *state.primary.lock().unwrap();
    let writable = match script.mode {
        Mode::Set => primary == Some(index),
        Mode::Standalone | Mode::Mongos => true,
    };
    let mut doc = Doc::new()
        .with_bool("helloOk", true)
        .with_bool("isWritablePrimary", writable)
        .with_bool("ismaster", writable);
    match script.mode {
        Mode::Mongos => doc = doc.with_str("msg", "isdbgrid"),
        Mode::Standalone => {}
        Mode::Set => {
            let set_name = if script.other_set == Some(index) {
                "other"
            } else {
                SET
            };
            let hosts: Vec<&str> = match &script.hosts {
                Some(hosts) => hosts.iter().map(String::as_str).collect(),
                None => state.addrs.iter().map(String::as_str).collect(),
            };
            doc = doc
                .with_str("setName", set_name)
                .with_strings("hosts", &hosts)
                .with_str("me", &state.addrs[index])
                .with_bool("secondary", !writable)
                .with_strings("passives", &["10.255.0.9:27017"])
                .with_strings("arbiters", &["10.255.0.8:27017"]);
            if let Some(claimed) = script.claimed_primary.or(primary) {
                doc = doc.with_str("primary", &state.addrs[claimed]);
            }
        }
    }
    doc = doc
        .with_doc("topologyVersion", &Doc::new().with_i64("counter", 0))
        .with_i32("maxWireVersion", script.max_wire)
        .with_i32("minWireVersion", 0)
        .with_i32("maxBsonObjectSize", 16 * 1024 * 1024)
        .with_i32("maxMessageSizeBytes", 48_000_000)
        .with_i32("logicalSessionTimeoutMinutes", 30)
        .with_strings("compression", &["zlib"]);
    if request.contains("saslSupportedMechs")
        && let Some(mechanisms) = &script.mechanisms
    {
        doc = doc.with_strings("saslSupportedMechs", mechanisms);
    }
    if request.contains("speculativeAuthenticate") {
        doc = doc.with_doc(
            "speculativeAuthenticate",
            &Doc::new().with_i32("conversationId", 9),
        );
    }
    doc.with_f64("ok", 1.0)
}

fn sasl_reply(
    script: &Script,
    seen: &Mutex<Seen>,
    request: &Doc,
    scram: &mut Option<ServerScram>,
) -> Doc {
    let database = request.str("$db").unwrap_or_default().to_string();
    if request.first_key() == Some("saslStart") {
        let mechanism = if request.str("mechanism") == Some("SCRAM-SHA-1") {
            "SCRAM-SHA-1"
        } else {
            "SCRAM-SHA-256"
        };
        {
            let mut seen = seen.lock().unwrap();
            seen.sasl.push(format!("saslStart:{mechanism}"));
            seen.sasl_dbs.push(database);
        }
        let payload = String::from_utf8(request.binary("payload").unwrap().to_vec()).unwrap();
        let bare = payload.strip_prefix("n,,").unwrap().to_string();
        let client_nonce = bare
            .split(',')
            .find_map(|p| p.strip_prefix("r="))
            .unwrap()
            .to_string();
        let nonce = if script.sasl == Sasl::ShortNonce {
            "forged-nonce".to_string()
        } else {
            format!("{client_nonce}fake-server-nonce")
        };
        let iterations = match script.sasl {
            Sasl::LowIterations => 1024,
            Sasl::HighIterations => HIGH_ITERATIONS,
            _ => ITERATIONS,
        };
        let server_first = format!("r={nonce},s={},i={iterations}", STANDARD.encode(SALT));
        *scram = Some(ServerScram {
            mechanism,
            user_ok: bare.starts_with(&format!("n={USER},")),
            first_bare: bare,
            server_first: server_first.clone(),
            nonce,
            salted: salted_password(mechanism, iterations),
            skip_empty: request
                .doc("options")
                .and_then(|o| o.bool("skipEmptyExchange"))
                .unwrap_or(false),
            finished: false,
        });
        return Doc::new()
            .with_i32("conversationId", 1)
            .with_bool("done", false)
            .with_binary("payload", server_first.as_bytes())
            .with_f64("ok", 1.0);
    }
    seen.lock().unwrap().sasl.push("saslContinue".to_string());
    let Some(state) = scram.as_mut() else {
        return failed(17, "ProtocolError", "no conversation");
    };
    if state.finished {
        let done = script.sasl != Sasl::Endless;
        return Doc::new()
            .with_i32("conversationId", 1)
            .with_bool("done", done)
            .with_binary("payload", b"")
            .with_f64("ok", 1.0);
    }
    let text = String::from_utf8(request.binary("payload").unwrap_or_default().to_vec()).unwrap();
    let Some((without_proof, proof)) = text.rsplit_once(",p=") else {
        return failed(17, "ProtocolError", "no proof");
    };
    let auth_message = format!(
        "{},{},{without_proof}",
        state.first_bare, state.server_first
    );
    let client_key = hmac(state.mechanism, &state.salted, b"Client Key");
    let stored_key = hash(state.mechanism, &client_key);
    let signature = hmac(state.mechanism, &stored_key, auth_message.as_bytes());
    let expected: Vec<u8> = client_key
        .iter()
        .zip(&signature)
        .map(|(a, b)| a ^ b)
        .collect();
    let nonce_ok = without_proof == format!("c=biws,r={}", state.nonce);
    if !state.user_ok || !nonce_ok || STANDARD.decode(proof).ok() != Some(expected) {
        return failed(18, "AuthenticationFailed", AUTH_FAILED_TEXT);
    }
    let server_key = hmac(state.mechanism, &state.salted, b"Server Key");
    let mut server_signature = hmac(state.mechanism, &server_key, auth_message.as_bytes());
    if script.sasl == Sasl::WrongSignature {
        server_signature[0] ^= 0xff;
    }
    seen.lock().unwrap().authenticated = true;
    state.finished = true;
    let done = state.skip_empty && !matches!(script.sasl, Sasl::NoSkip | Sasl::Endless);
    Doc::new()
        .with_i32("conversationId", 1)
        .with_bool("done", done)
        .with_binary(
            "payload",
            format!("v={}", STANDARD.encode(&server_signature)).as_bytes(),
        )
        .with_f64("ok", 1.0)
}

fn command_reply(name: &str, request: &Doc) -> Doc {
    match name {
        "find" => {
            let big = request
                .doc("filter")
                .and_then(|f| f.bool("big"))
                .unwrap_or(false);
            let item = if big {
                Doc::new().with_str("blob", &"z".repeat(BIG_LEN))
            } else {
                Doc::new().with_i32("n", 1)
            };
            let cursor = Doc::new()
                .with_array("firstBatch", &Doc::new().with_doc("0", &item))
                .with_i64("id", 0)
                .with_str("ns", "appdb.orders");
            Doc::new().with_doc("cursor", &cursor).with_f64("ok", 1.0)
        }
        "insert" => Doc::new().with_i32("n", 1).with_f64("ok", 1.0),
        _ => Doc::new().with_f64("ok", 1.0),
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    index: usize,
    state: Arc<SetState>,
    seen: Arc<Mutex<Seen>>,
) -> std::io::Result<()> {
    let mut hellos_here = 0usize;
    let mut scram = None;
    let mut next_id = 1000;
    loop {
        let header = wire::read_header(&mut stream).await?;
        seen.lock().unwrap().frames += 1;
        if !header.length_ok(wire::DEFAULT_MAX_MESSAGE)
            || ![wire::OP_MSG, wire::OP_QUERY].contains(&header.op_code)
        {
            return Ok(());
        }
        let payload = wire::read_payload(&mut stream, &header).await?;
        {
            let mut frame = header.encode().to_vec();
            frame.extend_from_slice(&payload);
            seen.lock().unwrap().raw.push(frame);
        }
        let (request, legacy, flags) = match header.op_code {
            wire::OP_MSG => {
                let msg = OpMsg::parse(&payload).unwrap();
                (msg.body().unwrap().clone(), false, msg.flags)
            }
            wire::OP_QUERY => (OpQuery::parse(&payload).unwrap().query, true, 0),
            _ => return Ok(()),
        };
        let name = request.first_key().unwrap_or_default().to_string();
        let script = &state.script;
        let reply = if is_hello(&name) {
            hellos_here += 1;
            {
                let mut seen = seen.lock().unwrap();
                seen.hellos.push(request.clone());
                seen.hello_ops.push(header.op_code);
            }
            let silenced = *state.silent_member.lock().unwrap() == Some(index);
            if script.silent || silenced {
                continue;
            }
            if hellos_here > 1 && request.contains("client") {
                failed(
                    186,
                    "ClientMetadataCannotBeMutated",
                    "The client metadata document may only be sent in the first hello",
                )
            } else if flags & wire::EXHAUST_ALLOWED != 0 && script.streamed > 0 {
                let mut response_to = header.request_id;
                for i in 0..script.streamed {
                    let mut msg = OpMsg::new(hello_reply(&state, index, &request));
                    if i + 1 < script.streamed {
                        msg.flags = wire::MORE_TO_COME;
                    }
                    next_id += 1;
                    stream.write_all(&msg.encode(next_id, response_to)).await?;
                    stream.flush().await?;
                    response_to = next_id;
                }
                continue;
            } else {
                hello_reply(&state, index, &request)
            }
        } else if name == "saslStart" || name == "saslContinue" {
            sasl_reply(script, &seen, &request, &mut scram)
        } else {
            seen.lock().unwrap().commands.push(name.clone());
            command_reply(&name, &request)
        };
        next_id += 1;
        let mut bytes = if legacy {
            wire::op_reply(&reply, next_id, header.request_id)
        } else {
            OpMsg::new(reply).encode(next_id, header.request_id)
        };
        if script.compressed_replies && !is_hello(&name) && !name.starts_with("sasl") {
            bytes[12..16].copy_from_slice(&wire::OP_COMPRESSED.to_le_bytes());
        }
        stream.write_all(&bytes).await?;
        stream.flush().await?;
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
        .push(rcgen::DnType::CommonName, "zs-mongo-test-ca");
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

pub fn auth() -> Auth {
    Auth::new(USER, SOURCE)
}

pub fn admit_all() -> zs_protocol::CallerCheck {
    Arc::new(|_, _| true)
}

pub async fn listen(
    seed: SocketAddr,
    tls: Option<UpstreamTls>,
    materialize: Materialize,
    diag: DiagLog,
    audit: Option<AuditRefusal>,
) -> SocketAddr {
    listen_with(seed, tls, materialize, diag, audit, None).await
}

pub async fn listen_with(
    seed: SocketAddr,
    tls: Option<UpstreamTls>,
    materialize: Materialize,
    diag: DiagLog,
    audit: Option<AuditRefusal>,
    budget: Option<Duration>,
) -> SocketAddr {
    listen_gated(
        seed,
        tls,
        materialize,
        diag,
        audit,
        budget,
        Some(admit_all()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn listen_gated(
    seed: SocketAddr,
    tls: Option<UpstreamTls>,
    materialize: Materialize,
    diag: DiagLog,
    audit: Option<AuditRefusal>,
    budget: Option<Duration>,
    caller_check: Option<zs_protocol::CallerCheck>,
) -> SocketAddr {
    let endpoint = UpstreamEndpoint::new(seed.ip().to_string(), seed.port()).unwrap();
    let mut listener =
        MongoListener::bind_endpoint("127.0.0.1:0", endpoint, tls, auth(), materialize)
            .await
            .unwrap()
            .with_diag(diag, RESOURCE);
    if let Some(audit) = audit {
        listener = listener.with_refusal_audit(audit);
    }
    if let Some(budget) = budget {
        listener = listener.with_handshake_budget(budget);
    }
    let listener = match caller_check {
        Some(check) => listener.with_caller_check(check),
        None => listener,
    };
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
    Arc::new(|| Err(zs_protocol::Denied::new("no grant for orders-mongo")))
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

pub fn legacy_hello() -> Doc {
    Doc::new()
        .with_i32("isMaster", 1)
        .with_bool("helloOk", true)
        .with_doc(
            "client",
            &Doc::new()
                .with_doc(
                    "driver",
                    &Doc::new()
                        .with_str("name", "zs-fake-client")
                        .with_str("version", "1"),
                )
                // A real mongod rejects client metadata without `os.type`
                // (ClientMetadataMissingField, code 183), and the listener
                // forwards the first hello upstream unchanged.
                .with_doc(
                    "os",
                    &Doc::new()
                        .with_str("type", "Linux")
                        .with_str("name", "zs-fake-os")
                        .with_str("architecture", "x86_64"),
                ),
        )
        .with_strings("compression", &["zlib"])
        .with_str("saslSupportedMechs", "admin.mallory")
        .with_doc(
            "speculativeAuthenticate",
            &Doc::new().with_i32("saslStart", 1),
        )
}

pub fn find() -> Doc {
    Doc::new()
        .with_str("find", "orders")
        .with_doc("filter", &Doc::new())
        .with_str("$db", "appdb")
}

pub fn big_find() -> Doc {
    Doc::new()
        .with_str("find", "orders")
        .with_doc("filter", &Doc::new().with_bool("big", true))
        .with_str("$db", "appdb")
}

pub fn legacy_frame(query: Doc, request_id: i32) -> Vec<u8> {
    OpQuery {
        flags: 0,
        collection: "admin.$cmd".to_string(),
        skip: 0,
        limit: -1,
        query,
    }
    .encode(request_id)
}

pub struct Client {
    pub stream: TcpStream,
    next: i32,
}

impl Client {
    pub async fn connect(addr: SocketAddr) -> Self {
        Self {
            stream: TcpStream::connect(addr).await.unwrap(),
            next: 1,
        }
    }

    pub fn next_id(&mut self) -> i32 {
        self.next += 1;
        self.next
    }

    pub async fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(bytes).await
    }

    pub async fn read_frame(&mut self) -> std::io::Result<(Header, Vec<u8>)> {
        let header = wire::read_header(&mut self.stream).await?;
        let payload = wire::read_payload(&mut self.stream, &header).await?;
        Ok((header, payload))
    }

    pub async fn read_doc(&mut self) -> std::io::Result<(Header, Doc)> {
        let (header, payload) = self.read_frame().await?;
        let doc = if header.op_code == wire::OP_REPLY {
            wire::parse_op_reply(&payload).unwrap()
        } else {
            OpMsg::parse(&payload).unwrap().body().unwrap().clone()
        };
        Ok((header, doc))
    }

    pub async fn legacy_handshake(&mut self) -> std::io::Result<Doc> {
        let id = self.next_id();
        self.send(&legacy_frame(legacy_hello(), id)).await?;
        let (header, doc) = self.read_doc().await?;
        assert_eq!(header.op_code, wire::OP_REPLY);
        assert_eq!(header.response_to, id);
        Ok(doc)
    }

    pub async fn msg_handshake(&mut self) -> std::io::Result<Doc> {
        let client = legacy_hello().doc("client").unwrap();
        let hello = Doc::new()
            .with_i32("hello", 1)
            .with_doc("client", &client)
            .with_strings("compression", &["zlib"])
            .with_str("$db", "admin");
        let id = self.next_id();
        self.send(&OpMsg::new(hello).encode(id, 0)).await?;
        let (header, doc) = self.read_doc().await?;
        assert_eq!(header.op_code, wire::OP_MSG);
        assert_eq!(header.response_to, id);
        Ok(doc)
    }

    pub async fn command(&mut self, doc: Doc) -> std::io::Result<Doc> {
        let id = self.next_id();
        self.send(&OpMsg::new(doc).encode(id, 0)).await?;
        Ok(self.read_doc().await?.1)
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
    let reply = client.legacy_handshake().await.unwrap();
    assert!(reply.truthy("ok"), "positive control: the login works");
    client
}

pub fn assert_error(doc: &Doc, code: i64, text: &str) {
    assert!(!doc.truthy("ok"), "an error reply: {:?}", doc.str("errmsg"));
    assert_eq!(doc.int("code"), Some(code), "{:?}", doc.str("errmsg"));
    assert_eq!(doc.str("errmsg"), Some(text));
}

pub fn diag_log(dir: &Path) -> (std::path::PathBuf, DiagLog) {
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
        .map(|l| serde_json::from_str(l).unwrap())
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
        .filter(|e| e["event"] == name && e["conn"] == conn && e["component"] == "mongo")
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

pub fn counter() -> (Materialize, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let materialize: Materialize = Arc::new(move || {
        count.fetch_add(1, Ordering::SeqCst);
        Ok(zs_credential::Credential::from_bytes(PASSWORD.as_bytes().to_vec()).unwrap())
    });
    (materialize, calls)
}
