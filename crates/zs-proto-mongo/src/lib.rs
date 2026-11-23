pub mod bson;
pub mod primary;
mod read_only;
pub mod scram;
pub mod topology;
pub mod wire;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;
use zs_diag::{Component, DiagLog, Event, ServerText};

use bson::Doc;
use primary::{PrimaryState, must_close};
pub use read_only::{READ_ONLY_REASON, READ_ONLY_REFUSED, check};
use scram::Mechanism;
use topology::{Discovery, Hello, Role};
use wire::{OpMsg, OpQuery};
pub use zs_upstream::{TlsConfigError, UpstreamEndpoint, UpstreamTls};

pub use zs_protocol::{AuditRefusal, Materialize};
use zs_protocol::{
    Caller, ClientStream, ClientWriteHalf, FrontListener, ListenSpec, SessionAccess,
};

pub const AUTHENTICATE_REFUSED_REASON: &str = "client authentication commands are refused";

const HANDSHAKE_BUDGET: Duration = Duration::from_secs(15);
const MAX_SASL_CONTINUES: usize = 3;
const AUTH_COMMANDS: [&str; 3] = ["saslStart", "saslContinue", "authenticate"];

pub struct Reply {
    pub code: i32,
    pub code_name: &'static str,
    pub message: &'static str,
}

impl Reply {
    pub fn doc(&self) -> Doc {
        Doc::new()
            .with_f64("ok", 0.0)
            .with_str("errmsg", self.message)
            .with_i32("code", self.code)
            .with_str("codeName", self.code_name)
    }
}

pub const DENIED: Reply = Reply {
    code: 13,
    code_name: "Unauthorized",
    message: "zs: connect denied",
};
pub const UPSTREAM_AUTH_FAILED: Reply = Reply {
    code: 18,
    code_name: "AuthenticationFailed",
    message: "zs: upstream authentication failed",
};
pub const AUTH_BROKERED: Reply = Reply {
    code: 18,
    code_name: "AuthenticationFailed",
    message: "zs: authentication is brokered",
};
pub const UNAVAILABLE_CONNECT: Reply = Reply {
    code: 6,
    code_name: "HostUnreachable",
    message: "zs: upstream unavailable (connect)",
};
pub const UNAVAILABLE_TLS: Reply = Reply {
    code: 6,
    code_name: "HostUnreachable",
    message: "zs: upstream unavailable (tls)",
};
pub const UNAVAILABLE_DISCOVERY: Reply = Reply {
    code: 6,
    code_name: "HostUnreachable",
    message: "zs: upstream unavailable (discovery)",
};
pub const UNAVAILABLE_HANDSHAKE: Reply = Reply {
    code: 6,
    code_name: "HostUnreachable",
    message: "zs: upstream unavailable (handshake)",
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    user: String,
    source: String,
}

impl Auth {
    pub fn new(user: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            source: source.into(),
        }
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone)]
struct Tls {
    config: Arc<rustls::ClientConfig>,
    setting: UpstreamTls,
}

pub struct MongoListener {
    listener: FrontListener,
    shared: Shared,
    caller_check: Option<zs_protocol::CallerCheck>,
}

#[derive(Clone)]
struct Shared {
    seed: UpstreamEndpoint,
    tls: Option<Tls>,
    auth: Auth,
    materialize: Materialize,
    audit_refusal: AuditRefusal,
    diag: DiagLog,
    resource: String,
    listener_addr: String,
    primary: PrimaryState,
    budget: Duration,
    cursors: Arc<read_only::Cursors>,
}

impl MongoListener {
    pub async fn bind_endpoint(
        local: &ListenSpec,
        seed: UpstreamEndpoint,
        tls: Option<UpstreamTls>,
        auth: Auth,
        materialize: Materialize,
    ) -> std::io::Result<Self> {
        let tls = match tls {
            Some(setting) => Some(Tls {
                config: zs_upstream::client_config(&setting).map_err(std::io::Error::other)?,
                setting,
            }),
            None => None,
        };
        let listener = FrontListener::bind(local).await?;
        // The address a replica-set reply advertises as the only host: `host:port` for TCP, the
        // socket path for a Unix socket (drivers read a host ending in `.sock` as a socket path).
        let listener_addr = match listener.local() {
            ListenSpec::Tcp(addr) => addr.to_string(),
            ListenSpec::Unix(path) => path.display().to_string(),
        };
        Ok(Self {
            listener,
            caller_check: None,
            shared: Shared {
                seed,
                tls,
                auth,
                materialize,
                audit_refusal: Arc::new(|_: &'static str, _: &'static str| None::<u64>),
                diag: DiagLog::disabled(),
                resource: String::new(),
                listener_addr,
                primary: PrimaryState::new(),
                budget: HANDSHAKE_BUDGET,
                cursors: Arc::default(),
            },
        })
    }

    pub fn with_diag(mut self, diag: DiagLog, resource: &str) -> Self {
        self.shared.diag = diag;
        self.shared.resource = resource.to_string();
        self
    }

    pub fn with_refusal_audit(mut self, audit: AuditRefusal) -> Self {
        self.shared.audit_refusal = audit;
        self
    }

    pub fn with_handshake_budget(mut self, budget: Duration) -> Self {
        self.shared.budget = budget;
        self
    }

    pub fn local(&self) -> &ListenSpec {
        self.listener.local()
    }

    pub fn with_caller_check(mut self, check: zs_protocol::CallerCheck) -> Self {
        self.caller_check = Some(check);
        self
    }

    pub async fn serve(self) -> std::io::Result<()> {
        loop {
            let (client, caller) = self.listener.accept().await?;
            if !zs_protocol::admitted(self.caller_check.as_ref(), &caller).await {
                self.shared.diag.emit(
                    Event::new(Component::Mongo, "caller_refused")
                        .conn(self.shared.diag.next_conn())
                        .token("listener", "mongo"),
                );
                drop(client);
                continue;
            }
            let shared = self.shared.clone();
            tokio::spawn(async move { handle_connection(client, shared, caller).await });
        }
    }
}

struct Conn {
    shared: Shared,
    id: u64,
    started: Instant,
    first: OnceLock<(i32, bool)>,
    next_id: AtomicI32,
}

struct Stopped(&'static str);

impl Conn {
    fn event(&self, name: &'static str) -> Event {
        Event::new(Component::Mongo, name)
            .conn(self.id)
            .resource(&self.shared.resource)
            .dest_withheld()
    }

    fn emit(&self, event: Event) {
        self.shared.diag.emit(event);
    }

    fn request_id(&self) -> i32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn upstream_failed(&self, stage: &'static str, kind: &'static str) {
        self.emit(
            self.event("upstream_failed")
                .warn()
                .code("stage", stage)
                .failure(kind),
        );
    }

    fn refused(&self, reason: &'static str, audit_seq: Option<u64>) {
        let mut event = self.event("client_refused").warn().code("reason", reason);
        if let Some(seq) = audit_seq {
            event = event.audit_seq(seq);
        }
        self.emit(event);
    }

    fn command_refused(&self, refusal: &read_only::Refusal) {
        let mut event = self
            .event("command_refused")
            .warn()
            .code("reason", refusal.reason);
        if let Some(command) = refusal.command {
            event = event.code("command", command);
        }
        if let Some(seq) = (self.shared.audit_refusal)("query", READ_ONLY_REASON) {
            event = event.audit_seq(seq);
        }
        self.emit(event);
    }

    fn closed(&self, up: u64, down: u64, by: &'static str) {
        self.emit(
            self.event("conn_closed")
                .num("bytes_up", up)
                .num("bytes_down", down)
                .num("ms", self.started.elapsed().as_millis() as u64)
                .code("closed_by", by),
        );
    }

    async fn answer<W: AsyncWrite + Unpin>(&self, client: &mut W, reply: &Reply) {
        let Some((request_id, legacy)) = self.first.get().copied() else {
            return;
        };
        let doc = reply.doc();
        let frame = if legacy {
            wire::op_reply(&doc, self.request_id(), request_id)
        } else {
            OpMsg::new(doc).encode(self.request_id(), request_id)
        };
        let _ = client.write_all(&frame).await;
        let _ = client.flush().await;
    }

    async fn fail(
        &self,
        client: &mut ClientStream,
        stage: &'static str,
        kind: &'static str,
        reply: &Reply,
    ) -> Stopped {
        self.upstream_failed(stage, kind);
        self.answer(client, reply).await;
        Stopped("refused")
    }
}

async fn handle_connection(mut client: ClientStream, shared: Shared, caller: Caller) {
    let budget = shared.budget;
    let conn = Conn {
        id: shared.diag.next_conn(),
        shared,
        started: Instant::now(),
        first: OnceLock::new(),
        next_id: AtomicI32::new(1),
    };
    conn.emit(conn.event("conn_accepted"));
    match tokio::time::timeout(budget, handshake(&mut client, &conn, caller)).await {
        Ok(Ok(session)) => relay(client, session, &conn).await,
        Ok(Err(Stopped(by))) => conn.closed(0, 0, by),
        Err(_) => {
            conn.upstream_failed("handshake", "timed_out");
            conn.answer(&mut client, &UNAVAILABLE_HANDSHAKE).await;
            conn.closed(0, 0, "timeout");
        }
    }
}

struct First {
    request_id: i32,
    legacy: bool,
    database: String,
    hello: Doc,
}

fn refuse(conn: &Conn, reason: &'static str) -> Stopped {
    conn.refused(reason, None);
    Stopped("refused")
}

async fn read_first(client: &mut ClientStream, conn: &Conn) -> Result<First, Stopped> {
    let Ok(header) = wire::read_header(client).await else {
        return Err(Stopped("client"));
    };
    if !header.length_ok(wire::DEFAULT_MAX_MESSAGE) {
        return Err(refuse(conn, "frame_size"));
    }
    match header.op_code {
        wire::OP_MSG | wire::OP_QUERY => {}
        wire::OP_COMPRESSED => return Err(refuse(conn, "compressed")),
        _ => return Err(refuse(conn, "opcode")),
    }
    let Ok(payload) = wire::read_payload(client, &header).await else {
        return Err(Stopped("client"));
    };
    let legacy = header.op_code == wire::OP_QUERY;
    let parsed = if legacy {
        OpQuery::parse(&payload).ok().and_then(|query| {
            let database = query.database()?.to_string();
            Some((database, query.query))
        })
    } else {
        if wire::msg_flags(&payload).is_some_and(|f| f & wire::CHECKSUM_PRESENT != 0) {
            return Err(refuse(conn, "checksum"));
        }
        OpMsg::parse(&payload)
            .ok()
            .and_then(|msg| msg.body().cloned())
            .map(|doc| (doc.str("$db").unwrap_or("admin").to_string(), doc))
    };
    let Some((database, hello)) = parsed else {
        return Err(refuse(conn, if legacy { "op_query" } else { "malformed" }));
    };
    match bson::exceeds_depth(&hello.encode(), 0, bson::MAX_DOCUMENT_DEPTH) {
        Ok(false) => {}
        Ok(true) => return Err(refuse(conn, "document_depth")),
        Err(_) => return Err(refuse(conn, "malformed")),
    }
    if !hello.first_key().is_some_and(topology::is_hello) {
        return Err(refuse(
            conn,
            if legacy { "op_query" } else { "first_message" },
        ));
    }
    let _ = conn.first.set((header.request_id, legacy));
    let op = if legacy { "op_query" } else { "op_msg" };
    conn.emit(conn.event("client_hello").code("op", op));
    Ok(First {
        request_id: header.request_id,
        legacy,
        database,
        hello,
    })
}

struct Session {
    upstream: Box<dyn Io>,
    max_message: usize,
    pinned: Option<String>,
    watch: zs_protocol::SessionWatch,
    read_only: bool,
}

struct Found {
    upstream: Box<dyn Io>,
    reply: Doc,
    hello: Hello,
    pinned: Option<String>,
}

async fn handshake(
    client: &mut ClientStream,
    conn: &Conn,
    caller: Caller,
) -> Result<Session, Stopped> {
    let first = read_first(client, conn).await?;
    let (password, watch, read_only) = match (conn.shared.materialize)(&caller) {
        Ok(materialized) => {
            conn.emit(conn.event("materialized").code("decision", "allow"));
            let read_only = materialized.access() == SessionAccess::ReadOnly;
            let (credential, watch) = materialized.into_parts();
            (
                Zeroizing::new(credential.expose().to_vec()),
                watch,
                read_only,
            )
        }
        Err(denied) => {
            conn.emit(
                conn.event("materialized")
                    .warn()
                    .code("decision", "deny")
                    .code("deny_kind", denied.kind().as_str()),
            );
            conn.answer(client, &DENIED).await;
            return Err(Stopped("refused"));
        }
    };
    let hello = topology::handshake_hello(
        &first.hello,
        &first.database,
        conn.shared.auth.user(),
        conn.shared.auth.source(),
    );
    let mut found = discover(client, conn, &hello).await?;
    authenticate(client, conn, &mut found.upstream, &found.hello, &password).await?;
    let mut reply = found.reply;
    topology::rewrite_reply(&mut reply, &conn.shared.listener_addr);
    let frame = if first.legacy {
        wire::op_reply(&reply, conn.request_id(), first.request_id)
    } else {
        OpMsg::new(reply).encode(conn.request_id(), first.request_id)
    };
    if client.write_all(&frame).await.is_err() {
        return Err(Stopped("client"));
    }
    Ok(Session {
        upstream: found.upstream,
        max_message: found.hello.max_message,
        pinned: found.pinned,
        watch,
        read_only,
    })
}

fn discovered(conn: &Conn, role: &'static str, hello: &Hello) -> Event {
    conn.event("discovery").code("role", role).num(
        "max_wire_version",
        u64::try_from(hello.max_wire_version).unwrap_or(0),
    )
}

fn dialed_address(endpoint: &UpstreamEndpoint) -> String {
    if endpoint.host().contains(':') {
        format!("[{}]:{}", endpoint.host(), endpoint.port())
    } else {
        format!("{}:{}", endpoint.host(), endpoint.port())
    }
}

async fn try_cached(conn: &Conn, hello: &Doc) -> Option<Found> {
    let cached = conn.shared.primary.known()?;
    let (host, port) = topology::split_host_port(&cached)?;
    let endpoint = UpstreamEndpoint::new(host, port).ok()?;
    let attempt = async {
        let mut upstream = open(conn, &endpoint).await.ok()?;
        let reply = command(conn, &mut upstream, hello.clone()).await.ok()?;
        Some((upstream, reply))
    };
    let (upstream, reply) = tokio::time::timeout(conn.shared.budget / 3, attempt)
        .await
        .ok()??;
    let parsed = Hello::read(&reply);
    if !topology::confirm_cached(&parsed) {
        if parsed.ok {
            conn.shared.primary.stepped_down(&cached);
        }
        return None;
    }
    conn.emit(discovered(conn, "cached", &parsed));
    Some(Found {
        upstream,
        reply,
        hello: parsed,
        pinned: Some(cached),
    })
}

async fn discover(client: &mut ClientStream, conn: &Conn, hello: &Doc) -> Result<Found, Stopped> {
    if let Some(found) = try_cached(conn, hello).await {
        return Ok(found);
    }
    let seed = conn.shared.seed.clone();
    let (upstream, reply) = connect_and_hello(client, conn, &seed, hello).await?;
    let parsed = Hello::read(&reply);
    match topology::classify(&parsed) {
        Discovery::Use(role) => {
            conn.emit(discovered(conn, role.code(), &parsed));
            let pinned = (role == Role::Primary).then(|| dialed_address(&seed));
            if let Some(address) = &pinned {
                conn.shared.primary.found(address);
            }
            Ok(Found {
                upstream,
                reply,
                hello: parsed,
                pinned,
            })
        }
        Discovery::Redirect(target) => {
            drop(upstream);
            redirect(client, conn, hello, &parsed, target).await
        }
        Discovery::Refuse(kind) => Err(conn
            .fail(client, "discovery", kind, &UNAVAILABLE_DISCOVERY)
            .await),
    }
}

async fn redirect(
    client: &mut ClientStream,
    conn: &Conn,
    hello: &Doc,
    seed: &Hello,
    target: String,
) -> Result<Found, Stopped> {
    let endpoint = topology::split_host_port(&target)
        .and_then(|(host, port)| UpstreamEndpoint::new(host, port).ok());
    let Some(endpoint) = endpoint else {
        return Err(conn
            .fail(client, "discovery", "not_in_hosts", &UNAVAILABLE_DISCOVERY)
            .await);
    };
    let (upstream, reply) = connect_and_hello(client, conn, &endpoint, hello).await?;
    let confirmed = Hello::read(&reply);
    if let Err(kind) = topology::confirm_redirect(seed, &confirmed) {
        return Err(conn
            .fail(client, "discovery", kind, &UNAVAILABLE_DISCOVERY)
            .await);
    }
    conn.emit(discovered(conn, "redirect", &confirmed));
    let address = dialed_address(&endpoint);
    conn.shared.primary.found(&address);
    Ok(Found {
        upstream,
        reply,
        hello: confirmed,
        pinned: Some(address),
    })
}

async fn open(
    conn: &Conn,
    endpoint: &UpstreamEndpoint,
) -> Result<Box<dyn Io>, (&'static str, &'static str)> {
    let tcp = endpoint
        .connect()
        .await
        .map_err(|e| ("connect", zs_diag::io_kind(&e)))?;
    conn.emit(conn.event("upstream_connected"));
    let Some(tls) = &conn.shared.tls else {
        conn.emit(conn.event("tls").code("result", "plaintext"));
        return Ok(Box::new(tcp));
    };
    let name = tls
        .setting
        .server_name(endpoint.host())
        .map_err(|_| ("tls", "bad_server_name"))?;
    let connector = tokio_rustls::TlsConnector::from(tls.config.clone());
    let stream = connector
        .connect(name, tcp)
        .await
        .map_err(|e| ("tls", zs_diag::io_kind(&e)))?;
    let result = if tls.setting.pinned() {
        "pinned"
    } else {
        "verified"
    };
    conn.emit(conn.event("tls").code("result", result));
    Ok(Box::new(stream))
}

async fn connect_and_hello(
    client: &mut ClientStream,
    conn: &Conn,
    endpoint: &UpstreamEndpoint,
    hello: &Doc,
) -> Result<(Box<dyn Io>, Doc), Stopped> {
    let mut upstream = match open(conn, endpoint).await {
        Ok(upstream) => upstream,
        Err(("tls", kind)) => {
            conn.emit(
                conn.event("tls")
                    .warn()
                    .code("result", "failed")
                    .failure(kind),
            );
            return Err(conn.fail(client, "tls", kind, &UNAVAILABLE_TLS).await);
        }
        Err((_, kind)) => {
            return Err(conn
                .fail(client, "connect", kind, &UNAVAILABLE_CONNECT)
                .await);
        }
    };
    match command(conn, &mut upstream, hello.clone()).await {
        Ok(reply) => Ok((upstream, reply)),
        Err(kind) => Err(conn
            .fail(client, "discovery", kind, &UNAVAILABLE_DISCOVERY)
            .await),
    }
}

async fn command(conn: &Conn, upstream: &mut Box<dyn Io>, doc: Doc) -> Result<Doc, &'static str> {
    let io = |e: std::io::Error| zs_diag::io_kind(&e);
    let request_id = conn.request_id();
    upstream
        .write_all(&OpMsg::new(doc).encode(request_id, 0))
        .await
        .map_err(io)?;
    upstream.flush().await.map_err(io)?;
    let header = wire::read_header(upstream).await.map_err(io)?;
    if header.op_code != wire::OP_MSG
        || header.response_to != request_id
        || !header.length_ok(wire::DEFAULT_MAX_MESSAGE)
    {
        return Err("malformed");
    }
    let payload = wire::read_payload(upstream, &header).await.map_err(io)?;
    OpMsg::parse(&payload)
        .ok()
        .and_then(|msg| msg.body().cloned())
        .ok_or("malformed")
}

enum AuthStop {
    Rejected(Mechanism, Doc),
    Failed(&'static str),
}

async fn authenticate(
    client: &mut ClientStream,
    conn: &Conn,
    upstream: &mut Box<dyn Io>,
    hello: &Hello,
    password: &[u8],
) -> Result<(), Stopped> {
    match run_scram(conn, upstream, hello, password).await {
        Ok(mechanism) => {
            conn.emit(
                conn.event("upstream_auth_ok")
                    .code("mechanism", mechanism.name()),
            );
            Ok(())
        }
        Err(AuthStop::Rejected(mechanism, reply)) => {
            report_rejection(conn, mechanism, &reply, password);
            conn.upstream_failed("auth", "refused");
            conn.answer(client, &UPSTREAM_AUTH_FAILED).await;
            Err(Stopped("refused"))
        }
        Err(AuthStop::Failed(kind)) => {
            Err(conn.fail(client, "auth", kind, &UPSTREAM_AUTH_FAILED).await)
        }
    }
}

async fn step(
    conn: &Conn,
    upstream: &mut Box<dyn Io>,
    doc: Doc,
    mechanism: Mechanism,
) -> Result<Doc, AuthStop> {
    match command(conn, upstream, doc).await {
        Ok(reply) if reply.truthy("ok") => Ok(reply),
        Ok(reply) => Err(AuthStop::Rejected(mechanism, reply)),
        Err(kind) => Err(AuthStop::Failed(kind)),
    }
}

fn payload_text(reply: &Doc) -> Result<&str, AuthStop> {
    reply
        .binary("payload")
        .and_then(|p| std::str::from_utf8(p).ok())
        .ok_or(AuthStop::Failed("malformed"))
}

fn continue_doc(conversation: i32, payload: &[u8], source: &str) -> Doc {
    Doc::new()
        .with_i32("saslContinue", 1)
        .with_i32("conversationId", conversation)
        .with_binary("payload", payload)
        .with_str("$db", source)
}

async fn run_scram(
    conn: &Conn,
    upstream: &mut Box<dyn Io>,
    hello: &Hello,
    password: &[u8],
) -> Result<Mechanism, AuthStop> {
    let mechanism =
        Mechanism::choose(hello.mechanisms.as_deref()).ok_or(AuthStop::Failed("mechanism"))?;
    let auth = &conn.shared.auth;
    let mut client = scram::Client::new(mechanism, auth.user(), password, &scram::fresh_nonce())
        .map_err(|e| AuthStop::Failed(e.kind()))?;
    let start = Doc::new()
        .with_i32("saslStart", 1)
        .with_str("mechanism", mechanism.name())
        .with_binary("payload", client.client_first().as_bytes())
        .with_i32("autoAuthorize", 1)
        .with_doc("options", &Doc::new().with_bool("skipEmptyExchange", true))
        .with_str("$db", auth.source());
    let reply = step(conn, upstream, start, mechanism).await?;
    let conversation = reply
        .int("conversationId")
        .and_then(|id| i32::try_from(id).ok())
        .ok_or(AuthStop::Failed("malformed"))?;
    let server_first = payload_text(&reply)?.to_string();
    let (client, client_final) = tokio::task::spawn_blocking(move || {
        let client_final = client.client_final(&server_first);
        (client, client_final)
    })
    .await
    .map_err(|_| AuthStop::Failed("derivation"))?;
    let client_final = client_final.map_err(|e| AuthStop::Failed(e.kind()))?;
    let mut reply = step(
        conn,
        upstream,
        continue_doc(conversation, client_final.as_bytes(), auth.source()),
        mechanism,
    )
    .await?;
    client
        .verify(payload_text(&reply)?)
        .map_err(|e| AuthStop::Failed(e.kind()))?;
    let mut continues = 1;
    while !reply.bool("done").unwrap_or(false) {
        if continues >= MAX_SASL_CONTINUES {
            return Err(AuthStop::Failed("too_many_rounds"));
        }
        continues += 1;
        reply = step(
            conn,
            upstream,
            continue_doc(conversation, b"", auth.source()),
            mechanism,
        )
        .await?;
    }
    Ok(mechanism)
}

fn report_rejection(conn: &Conn, mechanism: Mechanism, reply: &Doc, password: &[u8]) {
    let mut event = conn
        .event("upstream_auth_failed")
        .warn()
        .code("mechanism", mechanism.name())
        .failure("refused");
    if let Some(code) = reply.int("code").and_then(|c| u64::try_from(c).ok()) {
        event = event.num("code", code);
    }
    if let Some(name) = reply.str("codeName") {
        event = event.token("code_name", name);
    }
    if let Some(text) = reply.str("errmsg") {
        event = event.server_text(ServerText::new(text, password));
    }
    conn.emit(event);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    Client,
    Server,
    Refused(&'static str),
    ReadOnly,
    AuthCommand(i32),
    StepDown(&'static str),
    Broken(&'static str),
    Revoked(&'static str),
}

impl Ending {
    fn code(self) -> &'static str {
        match self {
            Ending::Client => "client",
            Ending::Server | Ending::Broken(_) => "upstream",
            Ending::Refused(_) | Ending::ReadOnly | Ending::AuthCommand(_) => "refused",
            Ending::StepDown(_) => "stepdown",
            Ending::Revoked(_) => "revoked",
        }
    }
}

struct Relay {
    tracked: Mutex<HashSet<i32>>,
    expected: Mutex<HashMap<i32, read_only::Expect>>,
    up: AtomicU64,
    down: AtomicU64,
    limit: usize,
    pinned: Option<String>,
    read_only: bool,
    client: tokio::sync::Mutex<ClientWriteHalf>,
}

impl Relay {
    fn track(&self, request_id: i32) {
        if let Ok(mut set) = self.tracked.lock() {
            set.insert(request_id);
        }
    }

    fn expect(&self, request_id: i32, expect: read_only::Expect) {
        if let Ok(mut map) = self.expected.lock() {
            map.insert(request_id, expect);
        }
    }

    fn expected(&self, response_to: i32) -> Option<read_only::Expect> {
        self.expected
            .lock()
            .ok()
            .and_then(|mut map| map.remove(&response_to))
    }

    /// Whether a reply to `request_id` is still awaited. A client that reuses such an id would
    /// let one reply be read as the other (a cursor reply as a `hello`, or the reverse).
    fn pending(&self, request_id: i32) -> bool {
        self.tracked
            .lock()
            .map(|set| set.contains(&request_id))
            .unwrap_or(true)
            || self
                .expected
                .lock()
                .map(|map| map.contains_key(&request_id))
                .unwrap_or(true)
    }

    fn take(&self, response_to: i32) -> bool {
        self.tracked
            .lock()
            .map(|mut set| set.remove(&response_to))
            .unwrap_or(false)
    }

    async fn reply(&self, frame: &[u8]) -> Result<(), Ending> {
        let mut client = self.client.lock().await;
        let sent = async {
            client.write_all(frame).await?;
            client.flush().await
        }
        .await;
        if sent.is_err() {
            return Err(Ending::Client);
        }
        self.down.fetch_add(frame.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

async fn client_to_upstream<R, W>(
    client: &mut R,
    upstream: &mut W,
    conn: &Conn,
    relay: &Relay,
) -> Ending
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let Ok(header) = wire::read_header(client).await else {
            return Ending::Client;
        };
        if !header.length_ok(relay.limit) {
            return Ending::Refused("frame_size");
        }
        match header.op_code {
            wire::OP_MSG => {}
            wire::OP_QUERY => return Ending::Refused("op_query"),
            wire::OP_COMPRESSED => return Ending::Refused("compressed"),
            _ => return Ending::Refused("opcode"),
        }
        let Ok(payload) = wire::read_payload(client, &header).await else {
            return Ending::Client;
        };
        if relay.pending(header.request_id) {
            return Ending::Refused("request_id");
        }
        if wire::msg_flags(&payload).is_some_and(|f| f & wire::CHECKSUM_PRESENT != 0) {
            return Ending::Refused("checksum");
        }
        let Some(command) = wire::command_name(&payload) else {
            return Ending::Refused("malformed");
        };
        if AUTH_COMMANDS.contains(&command) {
            return Ending::AuthCommand(header.request_id);
        }
        match wire::exceeds_depth(&payload, crate::bson::MAX_DOCUMENT_DEPTH) {
            Ok(false) => {}
            Ok(true) => return Ending::Refused("document_depth"),
            Err(_) => return Ending::Refused("malformed"),
        }
        if wire::body_sections(&payload) != Ok(1) {
            return Ending::Refused("malformed");
        }
        let unanswered = wire::msg_flags(&payload).is_none_or(|f| f & wire::MORE_TO_COME != 0);
        if relay.read_only {
            match read_only::screen(&payload, &conn.shared.cursors, Instant::now()) {
                Ok(Some(expect)) if !unanswered => relay.expect(header.request_id, expect),
                Ok(_) => {}
                Err(refusal) => {
                    conn.command_refused(&refusal);
                    if refusal.reason == read_only::MALFORMED || unanswered {
                        return Ending::ReadOnly;
                    }
                    let refused = OpMsg::new(READ_ONLY_REFUSED.doc())
                        .encode(conn.request_id(), header.request_id);
                    if let Err(ending) = relay.reply(&refused).await {
                        return ending;
                    }
                    continue;
                }
            }
        }
        let frame = if topology::is_hello(command) {
            let Ok(mut msg) = OpMsg::parse(&payload) else {
                return Ending::Refused("malformed");
            };
            if let Some(body) = msg.body_mut() {
                topology::strip_client_hello(body);
            }
            relay.track(header.request_id);
            msg.encode(header.request_id, header.response_to)
        } else {
            let mut frame = header.encode().to_vec();
            frame.extend_from_slice(&payload);
            frame
        };
        let sent = async {
            upstream.write_all(&frame).await?;
            upstream.flush().await
        }
        .await;
        if let Err(error) = sent {
            return Ending::Broken(zs_diag::io_kind(&error));
        }
        relay.up.fetch_add(frame.len() as u64, Ordering::Relaxed);
    }
}

async fn copy_exact<R, W>(reader: &mut R, writer: &mut W, mut left: usize) -> Result<(), Ending>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
    while left > 0 {
        let want = left.min(buffer.len());
        let n = match reader.read(&mut buffer[..want]).await {
            Ok(0) => return Err(Ending::Broken("unexpected_eof")),
            Ok(n) => n,
            Err(error) => return Err(Ending::Broken(zs_diag::io_kind(&error))),
        };
        if writer.write_all(&buffer[..n]).await.is_err() {
            return Err(Ending::Client);
        }
        left -= n;
    }
    Ok(())
}

async fn upstream_to_client<R>(upstream: &mut R, conn: &Conn, relay: &Relay) -> Ending
where
    R: AsyncRead + Unpin,
{
    loop {
        let header = match wire::read_header(upstream).await {
            Ok(header) => header,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ending::Server;
            }
            Err(error) => return Ending::Broken(zs_diag::io_kind(&error)),
        };
        if header.op_code != wire::OP_MSG {
            return Ending::Broken("opcode");
        }
        if !header.length_ok(relay.limit) {
            return Ending::Broken("frame_size");
        }
        let hello = relay.take(header.response_to);
        if hello {
            relay.expected(header.response_to);
        }
        if !hello
            && relay.read_only
            && let Some(expect) = relay.expected(header.response_to)
        {
            let payload = match wire::read_payload(upstream, &header).await {
                Ok(payload) => payload,
                Err(error) => return Ending::Broken(zs_diag::io_kind(&error)),
            };
            if wire::msg_flags(&payload).is_some_and(|f| f & wire::MORE_TO_COME != 0) {
                relay.expect(header.request_id, expect);
            }
            conn.shared
                .cursors
                .replied(&expect, &payload, Instant::now());
            let mut client = relay.client.lock().await;
            if client.write_all(&header.encode()).await.is_err()
                || client.write_all(&payload).await.is_err()
            {
                return Ending::Client;
            }
            drop(client);
            relay
                .down
                .fetch_add(header.length as u64, Ordering::Relaxed);
            continue;
        }
        if !hello {
            let mut client = relay.client.lock().await;
            if client.write_all(&header.encode()).await.is_err() {
                return Ending::Client;
            }
            if let Err(ending) = copy_exact(upstream, &mut *client, header.body_len()).await {
                return ending;
            }
            drop(client);
            relay
                .down
                .fetch_add(header.length as u64, Ordering::Relaxed);
            continue;
        }
        let payload = match wire::read_payload(upstream, &header).await {
            Ok(payload) => payload,
            Err(error) => return Ending::Broken(zs_diag::io_kind(&error)),
        };
        let Ok(mut msg) = OpMsg::parse(&payload) else {
            return Ending::Broken("malformed");
        };
        if msg.flags & wire::MORE_TO_COME != 0 {
            relay.track(header.request_id);
        }
        let mut stepped_down = false;
        if let Some(body) = msg.body_mut() {
            stepped_down =
                relay.pinned.is_some() && body.truthy("ok") && !Hello::read(body).writable;
            topology::rewrite_reply(body, &conn.shared.listener_addr);
        }
        let frame = msg.encode(header.request_id, header.response_to);
        if relay.client.lock().await.write_all(&frame).await.is_err() {
            return Ending::Client;
        }
        relay.down.fetch_add(frame.len() as u64, Ordering::Relaxed);
        if stepped_down {
            if let Some(pinned) = &relay.pinned {
                conn.shared.primary.stepped_down(pinned);
            }
            return Ending::StepDown("hello");
        }
    }
}

async fn watch_primary(conn: &Conn, pinned: Option<String>) -> &'static str {
    let Some(pinned) = pinned else {
        return std::future::pending().await;
    };
    let mut changes = conn.shared.primary.subscribe();
    loop {
        if let Some(trigger) = must_close(&pinned, &changes.borrow_and_update()) {
            return trigger;
        }
        if changes.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

async fn relay(client: ClientStream, session: Session, conn: &Conn) {
    let (mut client_read, client_write) = client.into_split();
    let state = Relay {
        tracked: Mutex::new(HashSet::new()),
        expected: Mutex::new(HashMap::new()),
        up: AtomicU64::new(0),
        down: AtomicU64::new(0),
        limit: session.max_message,
        pinned: session.pinned,
        read_only: session.read_only,
        client: tokio::sync::Mutex::new(client_write),
    };
    let (mut upstream_read, mut upstream_write) = tokio::io::split(session.upstream);
    let ending = {
        let forward = async {
            let ending =
                client_to_upstream(&mut client_read, &mut upstream_write, conn, &state).await;
            if ending == Ending::Client {
                let _ = upstream_write.shutdown().await;
            }
            ending
        };
        let backward = upstream_to_client(&mut upstream_read, conn, &state);
        let watch = watch_primary(conn, state.pinned.clone());
        tokio::pin!(forward);
        tokio::pin!(backward);
        tokio::pin!(watch);
        let relayed = async {
            tokio::select! {
                ending = &mut forward => match ending {
                    Ending::Client => match backward.as_mut().await {
                        broken @ Ending::Broken(_) => broken,
                        _ => Ending::Client,
                    },
                    other => other,
                },
                ending = &mut backward => ending,
                trigger = &mut watch => Ending::StepDown(trigger),
            }
        };
        tokio::select! {
            ending = relayed => ending,
            reason = session.watch.ended() => Ending::Revoked(reason),
        }
    };
    match ending {
        Ending::Broken(kind) => conn.upstream_failed("relay", kind),
        Ending::Refused(reason) => conn.refused(reason, None),
        Ending::AuthCommand(request_id) => {
            let seq = (conn.shared.audit_refusal)("authenticate", AUTHENTICATE_REFUSED_REASON);
            conn.refused("auth_command", seq);
            let refusal = OpMsg::new(AUTH_BROKERED.doc()).encode(conn.request_id(), request_id);
            let _ = state.client.lock().await.write_all(&refusal).await;
        }
        Ending::StepDown(trigger) => conn.emit(conn.event("stepdown").code("trigger", trigger)),
        Ending::Revoked(reason) => {
            conn.refused(
                zs_protocol::session_end_code(reason),
                (conn.shared.audit_refusal)("connect", reason),
            );
        }
        Ending::Client | Ending::Server | Ending::ReadOnly => {}
    }
    conn.closed(
        state.up.load(Ordering::Relaxed),
        state.down.load(Ordering::Relaxed),
        ending.code(),
    );
}
