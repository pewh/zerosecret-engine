pub mod guard;
mod read_only;
mod read_only_commands;
pub mod reply;
pub mod resp;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use zeroize::Zeroizing;
use zs_diag::{Component, DiagLog, Event};
use zs_protocol::SessionAccess;

use guard::EchoGuard;
use resp::{Command, Refusal};

pub use read_only::{
    EXEC_ABORTED, MultiState, READ_ONLY_REASON, READ_ONLY_REFUSED, Verdict, admit,
};
pub use zs_protocol::{AuditRefusal, Materialize};
pub use zs_upstream::{TlsConfigError, UpstreamEndpoint, UpstreamTls};

pub const CLIENT_TLS_REFUSED_REASON: &str = "client tls";
pub const UPSTREAM_AUTH_REFUSED_REASON: &str = "upstream authentication failed";
pub const UPSTREAM_UNAVAILABLE_REASON: &str = "upstream unavailable";
pub const HANDSHAKE_TIMEOUT_REASON: &str = "handshake timed out";
pub const MATERIALIZE_FAILED_REASON: &str = "materialize failed";
pub const CREDENTIAL_ECHO_REASON: &str = "credential echo";
pub const USER_MISMATCH_REASON: &str = "auth user mismatch";
pub const NON_RESP_REFUSED_REASON: &str = "non-resp command";
pub const CLUSTER_REDIRECT_REASON: &str = "cluster redirect";
pub const REFUSAL_BACKLOG_REASON: &str = "read-only refusal backlog";
pub const REFUSAL_BACKLOG: usize = 16_384;

const HANDSHAKE_BUDGET: Duration = Duration::from_secs(15);
const READ_BUFFER: usize = 16 * 1024;
const AUTH_REPLY_LIMIT: usize = 4096;
const REFUSAL_DRAIN: Duration = Duration::from_secs(2);
const LINGER: Duration = Duration::from_secs(2);
const LINGER_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct Reply {
    pub message: &'static str,
}

impl Reply {
    pub fn frame(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(self.message.len() + 3);
        frame.push(b'-');
        frame.extend_from_slice(self.message.as_bytes());
        frame.extend_from_slice(b"\r\n");
        frame
    }
}

pub const DENIED: Reply = Reply {
    message: "ERR ZeroSecret denied the connection",
};
pub const UPSTREAM_UNAVAILABLE: Reply = Reply {
    message: "ERR ZeroSecret upstream unavailable",
};
pub const UPSTREAM_AUTH_FAILED: Reply = Reply {
    message: "ERR ZeroSecret upstream authentication failed",
};
pub const USER_MISMATCH: Reply = Reply {
    message: "ERR ZeroSecret refused AUTH for another user",
};
pub const NON_RESP: Reply = Reply {
    message: "ERR ZeroSecret refused a non-RESP command",
};
pub const CLUSTER_REDIRECT: Reply = Reply {
    message: "ERR ZeroSecret refused a cluster redirect",
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Auth {
    user: Option<String>,
    upstream_optional: bool,
}

impl Auth {
    pub fn new(user: Option<String>) -> Self {
        Self {
            user,
            upstream_optional: false,
        }
    }

    pub fn with_upstream_optional(mut self, optional: bool) -> Self {
        self.upstream_optional = optional;
        self
    }

    pub fn upstream_optional(&self) -> bool {
        self.upstream_optional
    }

    pub fn user(&self) -> &str {
        self.user.as_deref().unwrap_or("default")
    }

    pub fn names_user(&self) -> bool {
        self.user.is_some()
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone)]
struct Tls {
    config: Arc<rustls::ClientConfig>,
    setting: UpstreamTls,
}

pub struct RedisListener {
    listener: TcpListener,
    shared: Shared,
    caller_check: Option<zs_protocol::CallerCheck>,
}

#[derive(Clone)]
struct Shared {
    upstream: UpstreamEndpoint,
    tls: Option<Tls>,
    auth: Auth,
    materialize: Materialize,
    audit_refusal: AuditRefusal,
    diag: DiagLog,
    resource: String,
    budget: Duration,
}

impl RedisListener {
    pub async fn bind_endpoint(
        local: &str,
        upstream: UpstreamEndpoint,
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
        Ok(Self {
            listener: TcpListener::bind(local).await?,
            caller_check: None,
            shared: Shared {
                upstream,
                tls,
                auth,
                materialize,
                audit_refusal: Arc::new(|_: &'static str, _: &'static str| None::<u64>),
                diag: DiagLog::disabled(),
                resource: String::new(),
                budget: HANDSHAKE_BUDGET,
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

    pub fn with_caller_check(mut self, check: zs_protocol::CallerCheck) -> Self {
        self.caller_check = Some(check);
        self
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    pub async fn serve(self) -> std::io::Result<()> {
        loop {
            let (client, peer) = self.listener.accept().await?;
            if !zs_protocol::admitted(self.caller_check.as_ref(), &client, peer).await {
                self.shared.diag.emit(
                    Event::new(Component::Redis, "caller_refused")
                        .conn(self.shared.diag.next_conn())
                        .token("listener", "redis"),
                );
                drop(client);
                continue;
            }
            let shared = self.shared.clone();
            tokio::spawn(async move { handle_connection(client, shared).await });
        }
    }
}

struct Conn {
    shared: Shared,
    id: u64,
    started: Instant,
}

impl Conn {
    fn event(&self, name: &'static str) -> Event {
        Event::new(Component::Redis, name)
            .conn(self.id)
            .resource(&self.shared.resource)
            .dest_withheld()
    }

    fn emit(&self, event: Event) {
        self.shared.diag.emit(event);
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

    fn command_refused(&self, refused: &read_only::Refused, reason: &'static str) {
        let mut event = self.event("command_refused").warn().code("reason", reason);
        if let Some(command) = refused.command {
            event = event.token("command", command);
        }
        if let Some(subcommand) = refused.subcommand {
            event = event.token("subcommand", subcommand);
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

    fn audit(&self, reason: &'static str) -> Option<u64> {
        (self.shared.audit_refusal)("connect", reason)
    }
}

struct Stopped(&'static str);

async fn handle_connection(mut client: TcpStream, shared: Shared) {
    let conn = Conn {
        id: shared.diag.next_conn(),
        shared,
        started: Instant::now(),
    };
    conn.emit(conn.event("conn_accepted"));
    match tokio::time::timeout(conn.shared.budget, handshake(&mut client, &conn)).await {
        Ok(Ok(session)) => relay(client, session, &conn).await,
        Ok(Err(Stopped(by))) => conn.closed(0, 0, by),
        Err(_) => {
            conn.upstream_failed("handshake", "timed_out");
            conn.refused("handshake_timeout", conn.audit(HANDSHAKE_TIMEOUT_REASON));
            answer_and_linger(&mut client, Some(UPSTREAM_UNAVAILABLE)).await;
            conn.closed(0, 0, "timeout");
        }
    }
}

async fn refuse(
    client: &mut TcpStream,
    conn: &Conn,
    reply: &Reply,
    code: &'static str,
    reason: &'static str,
) -> Stopped {
    conn.refused(code, conn.audit(reason));
    answer_and_linger(client, Some(*reply)).await;
    Stopped("refused")
}

async fn answer_and_linger(client: &mut TcpStream, reply: Option<Reply>) {
    let (mut read, mut write) = client.split();
    answer_then_drain(&mut read, &mut write, reply).await;
}

async fn answer_then_drain<R, W>(read: &mut R, write: &mut W, reply: Option<Reply>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if let Some(reply) = reply {
        let _ = write.write_all(&reply.frame()).await;
    }
    let _ = write.flush().await;
    let _ = write.shutdown().await;
    let drain = async {
        let mut sink = vec![0u8; READ_BUFFER];
        let mut total = 0usize;
        while total < LINGER_LIMIT {
            match read.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(read) => total += read,
            }
        }
    };
    let _ = tokio::time::timeout(LINGER, drain).await;
}

struct Session {
    upstream: Box<dyn Io>,
    credential: Zeroizing<Vec<u8>>,
    guard: EchoGuard,
    watch: zs_protocol::SessionWatch,
    read_only: bool,
}

async fn handshake(client: &mut TcpStream, conn: &Conn) -> Result<Session, Stopped> {
    let materialize = conn.shared.materialize.clone();
    let materialized = tokio::task::spawn_blocking(move || materialize()).await;
    let (credential, watch, read_only) = match materialized {
        Ok(Ok(materialized)) => {
            conn.emit(conn.event("materialized").code("decision", "allow"));
            let read_only = materialized.access() == SessionAccess::ReadOnly;
            let (credential, watch) = materialized.into_parts();
            (
                Zeroizing::new(credential.expose().to_vec()),
                watch,
                read_only,
            )
        }
        Ok(Err(denied)) => {
            conn.emit(
                conn.event("materialized")
                    .warn()
                    .code("decision", "deny")
                    .code("deny_kind", denied.kind().as_str()),
            );
            conn.refused("denied", None);
            answer_and_linger(client, Some(DENIED)).await;
            return Err(Stopped("refused"));
        }
        Err(_) => {
            conn.emit(
                conn.event("materialized")
                    .warn()
                    .code("decision", "deny")
                    .code("deny_kind", "materialize_failed"),
            );
            return Err(refuse(
                client,
                conn,
                &DENIED,
                "materialize_failed",
                MATERIALIZE_FAILED_REASON,
            )
            .await);
        }
    };
    let mut upstream = open(client, conn).await?;
    let request = auth_frame(&conn.shared.auth, &credential);
    let sent = async {
        upstream.write_all(&request).await?;
        upstream.flush().await
    }
    .await;
    if let Err(error) = sent {
        conn.upstream_failed("auth", zs_diag::io_kind(&error));
        return Err(refuse(
            client,
            conn,
            &UPSTREAM_UNAVAILABLE,
            "upstream_unavailable",
            UPSTREAM_UNAVAILABLE_REASON,
        )
        .await);
    }
    match read_auth_reply(&mut upstream).await {
        Ok(AuthReply::Ok) => conn.emit(conn.event("upstream_auth_ok")),
        Ok(AuthReply::Open) if conn.shared.auth.upstream_optional() => {
            conn.emit(conn.event("upstream_auth_not_required").warn());
        }
        Ok(AuthReply::Refused | AuthReply::Open) => {
            conn.upstream_failed("auth", "refused");
            return Err(refuse(
                client,
                conn,
                &UPSTREAM_AUTH_FAILED,
                "upstream_auth",
                UPSTREAM_AUTH_REFUSED_REASON,
            )
            .await);
        }
        Ok(AuthReply::Other(kind)) | Err(kind) => {
            conn.upstream_failed("auth", kind);
            return Err(refuse(
                client,
                conn,
                &UPSTREAM_UNAVAILABLE,
                "upstream_unavailable",
                UPSTREAM_UNAVAILABLE_REASON,
            )
            .await);
        }
    }
    let guard = EchoGuard::new(&credential);
    Ok(Session {
        upstream,
        credential,
        guard,
        watch,
        read_only,
    })
}

fn auth_frame(auth: &Auth, credential: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut args = vec![Zeroizing::new(b"AUTH".to_vec())];
    if auth.user() != "default" {
        args.push(Zeroizing::new(auth.user().as_bytes().to_vec()));
    }
    args.push(Zeroizing::new(credential.to_vec()));
    Command::from_zeroized(args).encode()
}

async fn open(client: &mut TcpStream, conn: &Conn) -> Result<Box<dyn Io>, Stopped> {
    let tcp = match conn.shared.upstream.connect().await {
        Ok(tcp) => tcp,
        Err(error) => {
            conn.upstream_failed("connect", zs_diag::io_kind(&error));
            return Err(refuse(
                client,
                conn,
                &UPSTREAM_UNAVAILABLE,
                "upstream_unavailable",
                UPSTREAM_UNAVAILABLE_REASON,
            )
            .await);
        }
    };
    conn.emit(conn.event("upstream_connected"));
    let Some(tls) = &conn.shared.tls else {
        conn.emit(conn.event("tls").code("result", "plaintext"));
        return Ok(Box::new(tcp));
    };
    let Ok(name) = tls.setting.server_name(conn.shared.upstream.host()) else {
        conn.emit(
            conn.event("tls")
                .warn()
                .code("result", "failed")
                .failure("bad_server_name"),
        );
        conn.upstream_failed("tls", "bad_server_name");
        return Err(refuse(
            client,
            conn,
            &UPSTREAM_UNAVAILABLE,
            "upstream_unavailable",
            UPSTREAM_UNAVAILABLE_REASON,
        )
        .await);
    };
    let connector = tokio_rustls::TlsConnector::from(tls.config.clone());
    match connector.connect(name, tcp).await {
        Ok(stream) => {
            let result = if tls.setting.pinned() {
                "pinned"
            } else {
                "verified"
            };
            conn.emit(conn.event("tls").code("result", result));
            Ok(Box::new(stream))
        }
        Err(error) => {
            let kind = zs_diag::io_kind(&error);
            conn.emit(
                conn.event("tls")
                    .warn()
                    .code("result", "failed")
                    .failure(kind),
            );
            conn.upstream_failed("tls", kind);
            Err(refuse(
                client,
                conn,
                &UPSTREAM_UNAVAILABLE,
                "upstream_unavailable",
                UPSTREAM_UNAVAILABLE_REASON,
            )
            .await)
        }
    }
}

enum AuthReply {
    Ok,
    Open,
    Refused,
    Other(&'static str),
}

const OPEN_UPSTREAM_REPLIES: [&[u8]; 2] = [
    b"ERR AUTH <password> called without any password configured for the default user.",
    b"ERR Client sent AUTH, but no password is set",
];

async fn read_auth_reply<R: AsyncRead + Unpin>(reader: &mut R) -> Result<AuthReply, &'static str> {
    let mut first = [0u8; 1];
    reader
        .read_exact(&mut first)
        .await
        .map_err(|error| zs_diag::io_kind(&error))?;
    let refused = first[0] == b'-';
    if !refused && first[0] != b'+' {
        return Ok(AuthReply::Other("malformed"));
    }
    let line = read_auth_line(reader).await?;
    if refused {
        if OPEN_UPSTREAM_REPLIES
            .iter()
            .any(|text| line.starts_with(text))
        {
            return Ok(AuthReply::Open);
        }
        Ok(AuthReply::Refused)
    } else if line.as_slice() == b"OK" {
        Ok(AuthReply::Ok)
    } else {
        Ok(AuthReply::Other("unexpected_reply"))
    }
}

async fn read_auth_line<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut line = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        if line.len() >= AUTH_REPLY_LIMIT {
            return Err("oversized_reply");
        }
        reader
            .read_exact(&mut byte)
            .await
            .map_err(|error| zs_diag::io_kind(&error))?;
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
                return Ok(line);
            }
            return Err("malformed");
        }
        line.push(byte[0]);
    }
}

enum Ending {
    Client,
    Server,
    Refused {
        reply: Option<Reply>,
        code: &'static str,
        reason: &'static str,
    },
    ReadOnly,
    Echo,
    Redirect,
    Broken(&'static str),
    Revoked(&'static str),
}

impl Ending {
    fn code(&self) -> &'static str {
        match self {
            Ending::Client => "client",
            Ending::Server | Ending::Broken(_) => "upstream",
            Ending::Refused { .. } | Ending::ReadOnly => "refused",
            Ending::Echo => "echo",
            Ending::Redirect => "redirect",
            Ending::Revoked(_) => "revoked",
        }
    }
}

fn refused(reply: Option<Reply>, code: &'static str, reason: &'static str) -> Ending {
    Ending::Refused {
        reply,
        code,
        reason,
    }
}

fn backlog() -> Ending {
    refused(None, "refusal_backlog", REFUSAL_BACKLOG_REASON)
}

#[derive(Clone, Copy)]
enum Slot {
    Pass,
    Agent(Reply),
    Replace(Reply),
}

#[derive(Default)]
struct Runs {
    runs: VecDeque<(Slot, u64)>,
    held: usize,
}

struct Slots {
    queue: Mutex<Runs>,
    open: AtomicU64,
    ready: Notify,
}

impl Slots {
    fn new() -> Self {
        Self {
            queue: Mutex::new(Runs::default()),
            open: AtomicU64::new(0),
            ready: Notify::new(),
        }
    }

    fn queue(&self) -> MutexGuard<'_, Runs> {
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn push(&self, slot: Slot) -> bool {
        {
            let mut guard = self.queue();
            let queue = &mut *guard;
            match (slot, queue.runs.back_mut()) {
                (Slot::Pass, Some((Slot::Pass, run))) => *run += 1,
                (Slot::Pass, _) => queue.runs.push_back((slot, 1)),
                _ if queue.held >= REFUSAL_BACKLOG => return false,
                _ => {
                    queue.held += 1;
                    queue.runs.push_back((slot, 1));
                }
            }
            self.open.fetch_add(1, Ordering::AcqRel);
        }
        self.ready.notify_one();
        true
    }

    fn agents(&self, out: &mut Vec<u8>) -> u64 {
        let mut queue = self.queue();
        let mut taken = 0;
        while let Some((Slot::Agent(reply), _)) = queue.runs.front().copied() {
            queue.runs.pop_front();
            queue.held -= 1;
            out.extend_from_slice(&reply.frame());
            taken += 1;
        }
        taken
    }

    fn reply(&self) -> Option<Slot> {
        self.queue()
            .runs
            .front()
            .map(|(slot, _)| *slot)
            .filter(|slot| !matches!(slot, Slot::Agent(_)))
    }

    fn answered(&self) {
        let mut queue = self.queue();
        let Some((slot, run)) = queue.runs.front_mut() else {
            return;
        };
        if matches!(slot, Slot::Pass) && *run > 1 {
            *run -= 1;
            return;
        }
        let held = !matches!(slot, Slot::Pass);
        queue.runs.pop_front();
        if held {
            queue.held -= 1;
        }
    }

    fn settle(&self, written: u64) {
        self.open.fetch_sub(written, Ordering::AcqRel);
    }

    fn settled(&self) -> bool {
        self.open.load(Ordering::Acquire) == 0
    }
}

async fn client_to_upstream<R, W>(
    reader: &mut R,
    writer: &mut W,
    conn: &Conn,
    credential: &[u8],
    up: &AtomicU64,
    forwarded: &AtomicU64,
    slots: Option<&Slots>,
) -> Ending
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let auth = &conn.shared.auth;
    let mut multi = MultiState::new();
    loop {
        let mut command = match resp::read_command(reader).await {
            Ok(Some(command)) => command,
            Ok(None) => return Ending::Client,
            Err(Refusal::ClientTls) => {
                return refused(None, "client_tls", CLIENT_TLS_REFUSED_REASON);
            }
            Err(Refusal::NonResp) => {
                return refused(Some(NON_RESP), "non_resp", NON_RESP_REFUSED_REASON);
            }
        };
        let mut slot = Slot::Pass;
        if let Some(slots) = slots {
            let args: Vec<&[u8]> = command.args().iter().map(|arg| arg.as_slice()).collect();
            match multi.check(&args) {
                Verdict::Forward => {}
                Verdict::Abort => slot = Slot::Replace(EXEC_ABORTED),
                Verdict::Refuse => {
                    if !slots.push(Slot::Agent(READ_ONLY_REFUSED)) {
                        return backlog();
                    }
                    conn.command_refused(&read_only::refused(&args), read_only::NOT_ALLOWED);
                    continue;
                }
                Verdict::Close => {
                    conn.command_refused(&read_only::refused(&args), read_only::MALFORMED);
                    return Ending::ReadOnly;
                }
            }
            if matches!(slot, Slot::Replace(_)) {
                command = Command::new(vec![b"DISCARD".to_vec()]);
            }
        }
        if matches!(
            command.rewrite_auth(auth.user(), auth.names_user(), credential),
            resp::Rewrite::UserMismatch
        ) {
            return refused(Some(USER_MISMATCH), "user_mismatch", USER_MISMATCH_REASON);
        }
        if let Some(slots) = slots
            && !slots.push(slot)
        {
            return backlog();
        }
        let frame = command.encode();
        let sent = async {
            writer.write_all(&frame).await?;
            writer.flush().await
        }
        .await;
        if let Err(error) = sent {
            return Ending::Broken(zs_diag::io_kind(&error));
        }
        up.fetch_add(frame.len() as u64, Ordering::Relaxed);
        forwarded.fetch_add(1, Ordering::Release);
    }
}

async fn write_out<W>(writer: &mut W, out: &[u8], down: &AtomicU64) -> Result<(), Ending>
where
    W: AsyncWrite + Unpin,
{
    if out.is_empty() {
        return Ok(());
    }
    if writer.write_all(out).await.is_err() {
        return Err(Ending::Client);
    }
    down.fetch_add(out.len() as u64, Ordering::Relaxed);
    Ok(())
}

async fn upstream_to_client<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut guard: EchoGuard,
    down: &AtomicU64,
    answered: &AtomicU64,
    progress: &Notify,
    slots: Option<&Slots>,
) -> Ending
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut framer = reply::Framer::new();
    let mut buffer = vec![0u8; READ_BUFFER];
    let mut current = None;
    loop {
        let read = match slots {
            None => reader.read(&mut buffer).await,
            Some(slots) => {
                if framer.at_boundary() {
                    let mut out = Vec::new();
                    let written = slots.agents(&mut out);
                    if written > 0 {
                        let Some(released) = guard.push(&out) else {
                            return Ending::Echo;
                        };
                        if let Err(ending) = write_out(writer, &released, down).await {
                            return ending;
                        }
                        slots.settle(written);
                        progress.notify_one();
                    }
                }
                tokio::select! {
                    biased;
                    read = reader.read(&mut buffer) => read,
                    _ = slots.ready.notified() => continue,
                }
            }
        };
        let read = match read {
            Ok(0) => break,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Ending::Broken(zs_diag::io_kind(&error)),
            Ok(read) => read,
        };
        let mut out = Vec::new();
        let mut offset = 0;
        let mut redirected = false;
        let mut complete = 0u64;
        let mut written = 0u64;
        while offset < read {
            if let Some(slots) = slots
                && framer.at_boundary()
            {
                written += slots.agents(&mut out);
                current = None;
                if !matches!(buffer[offset], b'>' | b'|') {
                    let Some(slot) = slots.reply() else {
                        return Ending::Broken("unsolicited_reply");
                    };
                    current = Some(slot);
                }
            }
            let mark = out.len();
            match framer.push(&buffer[offset..read], &mut out) {
                Ok((consumed, step)) => {
                    offset += consumed;
                    if step == reply::Outcome::Redirect {
                        redirected = true;
                        break;
                    }
                    if let Some(Slot::Replace(reply)) = current {
                        out.truncate(mark);
                        if framer.at_boundary() {
                            out.extend_from_slice(&reply.frame());
                        }
                    }
                    if framer.at_boundary() {
                        complete += 1;
                        if let Some(slots) = slots
                            && current.take().is_some()
                        {
                            slots.answered();
                            written += 1 + slots.agents(&mut out);
                        }
                    }
                }
                Err(_) => return Ending::Broken("malformed"),
            }
        }
        let Some(released) = guard.push(&out) else {
            return Ending::Echo;
        };
        if let Err(ending) = write_out(writer, &released, down).await {
            return ending;
        }
        if let Some(slots) = slots {
            slots.settle(written);
        }
        if complete > 0 || written > 0 {
            answered.fetch_add(complete, Ordering::Release);
            progress.notify_one();
        }
        if redirected {
            return Ending::Redirect;
        }
    }
    let whole = framer.at_boundary();
    let mut out = Vec::new();
    let outcome = framer.finish(&mut out);
    if matches!(current, Some(Slot::Replace(_))) {
        out.clear();
    }
    if let Some(slots) = slots
        && whole
    {
        slots.agents(&mut out);
    }
    let Some(released) = guard.push(&out) else {
        return Ending::Echo;
    };
    if let Err(ending) = write_out(writer, &released, down).await {
        return ending;
    }
    let tail = guard.flush();
    if let Err(ending) = write_out(writer, &tail, down).await {
        return ending;
    }
    if outcome == reply::Outcome::Redirect {
        return Ending::Redirect;
    }
    Ending::Server
}

async fn relay(client: TcpStream, session: Session, conn: &Conn) {
    let up = AtomicU64::new(0);
    let down = AtomicU64::new(0);
    let forwarded = AtomicU64::new(0);
    let answered = AtomicU64::new(0);
    let progress = Notify::new();
    let slots = session.read_only.then(Slots::new);
    let settled = || match &slots {
        Some(slots) => slots.settled(),
        None => answered.load(Ordering::Acquire) >= forwarded.load(Ordering::Acquire),
    };
    let (client_read, mut client_write) = client.into_split();
    let mut client_read = tokio::io::BufReader::with_capacity(READ_BUFFER, client_read);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(session.upstream);
    let ending = {
        let forward = async {
            let ending = client_to_upstream(
                &mut client_read,
                &mut upstream_write,
                conn,
                &session.credential,
                &up,
                &forwarded,
                slots.as_ref(),
            )
            .await;
            if matches!(ending, Ending::Client) {
                let _ = upstream_write.shutdown().await;
            }
            ending
        };
        let backward = upstream_to_client(
            &mut upstream_read,
            &mut client_write,
            session.guard,
            &down,
            &answered,
            &progress,
            slots.as_ref(),
        );
        tokio::pin!(forward);
        tokio::pin!(backward);
        let relayed = async {
            tokio::select! {
            ending = &mut forward => match ending {
                Ending::Client => match backward.as_mut().await {
                    broken @ Ending::Broken(_) => broken,
                    _ => Ending::Client,
                },
                refusal @ (Ending::Refused { .. } | Ending::ReadOnly) => {
                    let deadline = tokio::time::sleep(REFUSAL_DRAIN);
                    tokio::pin!(deadline);
                    loop {
                        if settled() {
                            break refusal;
                        }
                        tokio::select! {
                            ending = &mut backward => match ending {
                                stop @ (Ending::Echo | Ending::Redirect) => break stop,
                                _ => break refusal,
                            },
                            _ = progress.notified() => {}
                            _ = &mut deadline => break refusal,
                        }
                    }
                }
                other => other,
            },
            ending = &mut backward => ending,
            }
        };
        tokio::select! {
            ending = relayed => ending,
            reason = session.watch.ended() => Ending::Revoked(reason),
        }
    };
    match ending {
        Ending::Refused {
            reply,
            code,
            reason,
        } => {
            conn.refused(code, conn.audit(reason));
            answer_then_drain(&mut client_read, &mut client_write, reply).await;
        }
        Ending::ReadOnly => answer_then_drain(&mut client_read, &mut client_write, None).await,
        Ending::Echo => conn.refused("credential_echo", conn.audit(CREDENTIAL_ECHO_REASON)),
        Ending::Redirect => {
            conn.refused("cluster_redirect", conn.audit(CLUSTER_REDIRECT_REASON));
            answer_then_drain(&mut client_read, &mut client_write, Some(CLUSTER_REDIRECT)).await;
        }
        Ending::Broken(kind) => conn.upstream_failed("relay", kind),
        Ending::Revoked(reason) => conn.refused("revoked", conn.audit(reason)),
        Ending::Client | Ending::Server => {}
    }
    conn.closed(
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed),
        ending.code(),
    );
}
