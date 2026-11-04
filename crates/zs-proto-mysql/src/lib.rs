pub mod packet;
pub mod scramble;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;
use zs_diag::{Component, DiagLog, Event, ServerText};

use packet::{
    AuthSwitch, CACHING_SHA2_PASSWORD, CLEAR_PASSWORD, CLIENT_COMPRESS, CLIENT_SSL,
    CLIENT_ZSTD_COMPRESSION_ALGORITHM, COM_CHANGE_USER, COM_QUIT, ERR_HEADER, Greeting,
    HANDSHAKE_LIMIT, HandshakeResponse, MORE_DATA_HEADER, NATIVE_PASSWORD, OK_HEADER,
    REQUIRED_SERVER_CAPABILITIES, SCRAMBLE_LEN, SHA256_PASSWORD, STRIPPED_CAPABILITIES,
    SWITCH_HEADER, ServerError, client_capabilities, err_packet, read_packet, ssl_request,
    write_packet,
};
pub use zs_upstream::{TlsConfigError, UpstreamEndpoint, UpstreamTls};

pub use zs_protocol::Materialize;
pub type AuditRefusal = Arc<dyn Fn(&'static str, &'static str) -> Option<u64> + Send + Sync>;

pub const CHANGE_USER_REFUSED_REASON: &str = "client COM_CHANGE_USER is refused";

const HANDSHAKE_BUDGET: Duration = Duration::from_secs(15);
const MAX_AUTH_ROUNDS: usize = 3;

pub struct Reply {
    pub code: u16,
    pub sqlstate: &'static str,
    pub message: &'static str,
}

impl Reply {
    pub fn packet(&self) -> Vec<u8> {
        err_packet(self.code, self.sqlstate, self.message)
    }
}

pub const DENIED: Reply = Reply {
    code: 1045,
    sqlstate: "28000",
    message: "ZeroSecret denied the connection",
};
pub const UPSTREAM_UNAVAILABLE: Reply = Reply {
    code: 2003,
    sqlstate: "HY000",
    message: "ZeroSecret upstream unavailable",
};
pub const UPSTREAM_AUTH_FAILED: Reply = Reply {
    code: 1045,
    sqlstate: "28000",
    message: "ZeroSecret upstream authentication failed",
};
pub const METHOD_REFUSED: Reply = Reply {
    code: 1251,
    sqlstate: "08004",
    message: "ZeroSecret refused the upstream authentication method",
};
pub const TLS_REFUSED: Reply = Reply {
    code: 2026,
    sqlstate: "HY000",
    message: "ZeroSecret upstream TLS failed",
};
pub const CLIENT_REFUSED: Reply = Reply {
    code: 1043,
    sqlstate: "08S01",
    message: "ZeroSecret refused client TLS or compression",
};
pub const BAD_HANDSHAKE: Reply = Reply {
    code: 1043,
    sqlstate: "08S01",
    message: "ZeroSecret refused a malformed handshake",
};
pub const CHANGE_USER_REFUSED: Reply = Reply {
    code: 1227,
    sqlstate: "42000",
    message: "ZeroSecret refused COM_CHANGE_USER",
};
pub const UPSTREAM_REFUSED: &str = "ZeroSecret upstream refused the connection";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientAuth {
    #[default]
    CachingSha2,
    Native,
}

impl ClientAuth {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "caching_sha2_password" => Some(Self::CachingSha2),
            "mysql_native_password" => Some(Self::Native),
            _ => None,
        }
    }

    pub fn plugin(self) -> &'static [u8] {
        match self {
            Self::CachingSha2 => CACHING_SHA2_PASSWORD,
            Self::Native => NATIVE_PASSWORD,
        }
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub struct MysqlListener {
    listener: TcpListener,
    shared: Shared,
}

#[derive(Clone)]
struct Shared {
    upstream: UpstreamEndpoint,
    tls: Arc<rustls::ClientConfig>,
    tls_required: bool,
    tls_pinned: bool,
    materialize: Materialize,
    audit_refusal: AuditRefusal,
    diag: DiagLog,
    resource: String,
    client_auth: ClientAuth,
    upstream_tls: UpstreamTls,
}

impl MysqlListener {
    pub async fn bind_endpoint(
        local: &str,
        upstream: UpstreamEndpoint,
        tls: UpstreamTls,
        materialize: Materialize,
    ) -> std::io::Result<Self> {
        let config = zs_upstream::client_config(&tls).map_err(std::io::Error::other)?;
        Ok(Self {
            listener: TcpListener::bind(local).await?,
            shared: Shared {
                upstream,
                tls: config,
                tls_required: tls.required(),
                tls_pinned: tls.pinned(),
                materialize,
                audit_refusal: Arc::new(|_: &'static str, _: &'static str| None::<u64>),
                diag: DiagLog::disabled(),
                resource: String::new(),
                client_auth: ClientAuth::default(),
                upstream_tls: tls,
            },
        })
    }

    pub fn with_client_auth(mut self, auth: ClientAuth) -> Self {
        self.shared.client_auth = auth;
        self
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

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    pub async fn serve(self) -> std::io::Result<()> {
        loop {
            let (client, _peer) = self.listener.accept().await?;
            let shared = self.shared.clone();
            tokio::spawn(async move { handle_connection(client, shared).await });
        }
    }
}

struct Conn {
    shared: Shared,
    id: u64,
    started: Instant,
    client_seq: AtomicU8,
}

struct Stopped(&'static str);

impl Conn {
    fn event(&self, name: &'static str) -> Event {
        Event::new(Component::Mysql, name)
            .conn(self.id)
            .resource(&self.shared.resource)
            .dest(self.shared.upstream.host(), self.shared.upstream.port())
    }

    fn emit(&self, event: Event) {
        self.shared.diag.emit(event);
    }

    async fn refuse(&self, client: &mut TcpStream, reply: &Reply) {
        let seq = self.client_seq.load(Ordering::SeqCst);
        let _ = write_packet(client, seq, &reply.packet()).await;
    }

    async fn fail(
        &self,
        client: &mut TcpStream,
        stage: &'static str,
        kind: &'static str,
        reply: &Reply,
    ) -> Stopped {
        self.upstream_failed(stage, kind);
        self.refuse(client, reply).await;
        Stopped("refused")
    }

    fn upstream_failed(&self, stage: &'static str, kind: &'static str) {
        self.emit(
            self.event("upstream_failed")
                .warn()
                .code("stage", stage)
                .failure(kind),
        );
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
}

async fn handle_connection(mut client: TcpStream, shared: Shared) {
    let conn = Conn {
        id: shared.diag.next_conn(),
        shared,
        started: Instant::now(),
        client_seq: AtomicU8::new(0),
    };
    conn.emit(conn.event("conn_accepted"));
    let outcome = tokio::time::timeout(HANDSHAKE_BUDGET, handshake(&mut client, &conn)).await;
    match outcome {
        Ok(Ok(upstream)) => relay(client, upstream, &conn).await,
        Ok(Err(Stopped(by))) => conn.closed(0, 0, by),
        Err(_) => {
            conn.upstream_failed("handshake", "timed_out");
            conn.refuse(&mut client, &UPSTREAM_UNAVAILABLE).await;
            conn.closed(0, 0, "timeout");
        }
    }
}

async fn handshake(client: &mut TcpStream, conn: &Conn) -> Result<Box<dyn Io>, Stopped> {
    let password = materialize(client, conn).await?;
    let (tcp, greeting) = open_upstream(client, conn).await?;
    let Some((plugin, auth_data)) = first_answer(&greeting, &password) else {
        return Err(conn
            .fail(
                client,
                "greeting",
                "malformed_scramble",
                &UPSTREAM_UNAVAILABLE,
            )
            .await);
    };
    let offered = greeting.capabilities & !STRIPPED_CAPABILITIES;
    let response = greet_client(client, conn, &greeting, offered).await?;
    let tls = greeting.capabilities & CLIENT_SSL != 0;
    let mut flags = (response.capabilities & offered) | REQUIRED_SERVER_CAPABILITIES;
    if tls {
        flags |= CLIENT_SSL;
    }
    let request = ssl_request(flags, response.max_packet, response.charset);
    let (mut upstream, seq) = secure_upstream(client, conn, tcp, tls, &request).await?;
    let outgoing = HandshakeResponse {
        capabilities: flags,
        max_packet: response.max_packet,
        charset: response.charset,
        user: response.user,
        auth_data: auth_data.to_vec(),
        database: response.database,
        plugin: Some(plugin.to_vec()),
        attributes: response.attributes,
    };
    if let Err(error) = write_packet(&mut upstream, seq, &outgoing.encode()).await {
        return Err(conn
            .fail(
                client,
                "auth",
                zs_diag::io_kind(&error),
                &UPSTREAM_UNAVAILABLE,
            )
            .await);
    }
    let state = AuthState { plugin, rounds: 0 };
    let reply = match authenticate(&mut upstream, conn, &password, tls, state).await {
        Ok(ok) => {
            let seq = conn.client_seq.load(Ordering::SeqCst);
            return match write_packet(client, seq, &ok).await {
                Ok(()) => Ok(upstream),
                Err(_) => Err(Stopped("client")),
            };
        }
        Err(AuthStop::Rejected) => &UPSTREAM_AUTH_FAILED,
        Err(AuthStop::Refused) => &METHOD_REFUSED,
        Err(AuthStop::Broken) => &UPSTREAM_UNAVAILABLE,
    };
    conn.refuse(client, reply).await;
    Err(Stopped("refused"))
}

async fn materialize(client: &mut TcpStream, conn: &Conn) -> Result<Zeroizing<Vec<u8>>, Stopped> {
    match (conn.shared.materialize)() {
        Ok(credential) => {
            conn.emit(conn.event("materialized").code("decision", "allow"));
            Ok(Zeroizing::new(credential.expose().to_vec()))
        }
        Err(denied) => {
            conn.emit(
                conn.event("materialized")
                    .warn()
                    .code("decision", "deny")
                    .code("deny_kind", denied.kind().as_str()),
            );
            conn.refuse(client, &DENIED).await;
            Err(Stopped("refused"))
        }
    }
}

async fn open_upstream(
    client: &mut TcpStream,
    conn: &Conn,
) -> Result<(TcpStream, Greeting), Stopped> {
    let mut tcp = match conn.shared.upstream.connect().await {
        Ok(tcp) => tcp,
        Err(error) => {
            let kind = zs_diag::io_kind(&error);
            return Err(conn
                .fail(client, "connect", kind, &UPSTREAM_UNAVAILABLE)
                .await);
        }
    };
    conn.emit(conn.event("upstream_connected"));
    let hello = match read_packet(&mut tcp, HANDSHAKE_LIMIT).await {
        Ok(hello) => hello,
        Err(error) => {
            let kind = zs_diag::io_kind(&error);
            return Err(conn
                .fail(client, "greeting", kind, &UPSTREAM_UNAVAILABLE)
                .await);
        }
    };
    if hello.payload.first() == Some(&ERR_HEADER) {
        let (code, sqlstate) = ServerError::parse(&hello.payload)
            .map(|e| (e.code, e.sqlstate))
            .unwrap_or((UPSTREAM_UNAVAILABLE.code, None));
        conn.emit(
            conn.event("upstream_failed")
                .warn()
                .code("stage", "greeting")
                .failure("server_error")
                .num("errno", u64::from(code)),
        );
        let sqlstate = sqlstate.unwrap_or_else(|| "HY000".to_string());
        let _ = write_packet(client, 0, &err_packet(code, &sqlstate, UPSTREAM_REFUSED)).await;
        return Err(Stopped("refused"));
    }
    let Ok(greeting) = Greeting::parse(&hello.payload) else {
        return Err(conn
            .fail(client, "greeting", "malformed", &UPSTREAM_UNAVAILABLE)
            .await);
    };
    let ssl_offered = greeting.capabilities & CLIENT_SSL != 0;
    conn.emit(
        conn.event("greeting")
            .token(
                "server_version",
                &String::from_utf8_lossy(&greeting.server_version),
            )
            .flag("ssl_offered", ssl_offered)
            .token("plugin", &String::from_utf8_lossy(&greeting.plugin)),
    );
    if greeting.capabilities & REQUIRED_SERVER_CAPABILITIES != REQUIRED_SERVER_CAPABILITIES {
        return Err(conn
            .fail(client, "greeting", "unsupported_server", &METHOD_REFUSED)
            .await);
    }
    if !ssl_offered && conn.shared.tls_required {
        conn.emit(conn.event("tls").warn().code("result", "not_offered"));
        conn.upstream_failed("tls", "not_offered");
        conn.refuse(client, &TLS_REFUSED).await;
        return Err(Stopped("refused"));
    }
    Ok((tcp, greeting))
}

fn first_answer(
    greeting: &Greeting,
    password: &[u8],
) -> Option<(&'static [u8], Zeroizing<Vec<u8>>)> {
    if greeting.scramble.len() != SCRAMBLE_LEN {
        return None;
    }
    if greeting.plugin == CACHING_SHA2_PASSWORD {
        Some((
            CACHING_SHA2_PASSWORD,
            Zeroizing::new(scramble::caching_sha2(password, &greeting.scramble)),
        ))
    } else {
        Some((
            NATIVE_PASSWORD,
            Zeroizing::new(scramble::native(password, &greeting.scramble)),
        ))
    }
}

fn fresh_scramble() -> Vec<u8> {
    let mut bytes = [0u8; SCRAMBLE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| b % 127 + 1).collect()
}

async fn greet_client(
    client: &mut TcpStream,
    conn: &Conn,
    greeting: &Greeting,
    offered: u32,
) -> Result<HandshakeResponse, Stopped> {
    let to_client = Greeting {
        server_version: greeting.server_version.clone(),
        connection_id: greeting.connection_id,
        scramble: fresh_scramble(),
        capabilities: offered,
        charset: greeting.charset,
        status: greeting.status,
        plugin: conn.shared.client_auth.plugin().to_vec(),
    };
    if write_packet(client, 0, &to_client.encode()).await.is_err() {
        return Err(Stopped("client"));
    }
    let Ok(answer) = read_packet(client, HANDSHAKE_LIMIT).await else {
        return Err(Stopped("client"));
    };
    conn.client_seq
        .store(answer.seq.wrapping_add(1), Ordering::SeqCst);
    let capabilities = client_capabilities(&answer.payload).unwrap_or(0);
    let reason = if capabilities & CLIENT_SSL != 0 {
        Some("client_ssl")
    } else if capabilities & (CLIENT_COMPRESS | CLIENT_ZSTD_COMPRESSION_ALGORITHM) != 0 {
        Some("client_compress")
    } else {
        None
    };
    if let Some(reason) = reason {
        conn.emit(conn.event("client_refused").warn().code("reason", reason));
        conn.refuse(client, &CLIENT_REFUSED).await;
        return Err(Stopped("refused"));
    }
    match HandshakeResponse::parse(&answer.payload) {
        Ok(response) => Ok(response),
        Err(_) => {
            conn.emit(
                conn.event("client_refused")
                    .warn()
                    .code("reason", "bad_response"),
            );
            conn.refuse(client, &BAD_HANDSHAKE).await;
            Err(Stopped("refused"))
        }
    }
}

async fn secure_upstream(
    client: &mut TcpStream,
    conn: &Conn,
    mut tcp: TcpStream,
    tls: bool,
    request: &[u8],
) -> Result<(Box<dyn Io>, u8), Stopped> {
    if !tls {
        conn.emit(conn.event("tls").code("result", "not_offered"));
        return Ok((Box::new(tcp), 1));
    }
    if let Err(error) = write_packet(&mut tcp, 1, request).await {
        let kind = zs_diag::io_kind(&error);
        return Err(conn.fail(client, "tls", kind, &TLS_REFUSED).await);
    }
    let failed = |kind: &'static str| {
        conn.event("tls")
            .warn()
            .code("result", "failed")
            .failure(kind)
    };
    let Ok(name) = conn
        .shared
        .upstream_tls
        .server_name(conn.shared.upstream.host())
    else {
        conn.emit(failed("bad_server_name"));
        conn.upstream_failed("tls", "bad_server_name");
        conn.refuse(client, &TLS_REFUSED).await;
        return Err(Stopped("refused"));
    };
    let connector = tokio_rustls::TlsConnector::from(conn.shared.tls.clone());
    match connector.connect(name, tcp).await {
        Ok(stream) => {
            let result = if conn.shared.tls_pinned {
                "pinned"
            } else {
                "verified"
            };
            conn.emit(conn.event("tls").code("result", result));
            Ok((Box::new(stream), 2))
        }
        Err(error) => {
            let kind = zs_diag::io_kind(&error);
            conn.emit(failed(kind));
            conn.upstream_failed("tls", kind);
            conn.refuse(client, &TLS_REFUSED).await;
            Err(Stopped("refused"))
        }
    }
}

enum AuthStop {
    Rejected,
    Refused,
    Broken,
}

struct AuthState {
    plugin: &'static [u8],
    rounds: usize,
}

fn plugin_name(plugin: &[u8]) -> String {
    String::from_utf8_lossy(plugin).into_owned()
}

fn auth_stop(conn: &Conn, kind: &'static str, stop: AuthStop) -> AuthStop {
    conn.upstream_failed("auth", kind);
    stop
}

fn cleartext(password: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    out.extend_from_slice(password);
    out.push(0);
    out
}

fn report_rejection(conn: &Conn, payload: &[u8], password: &[u8]) {
    let mut event = conn.event("upstream_auth_failed").warn().failure("refused");
    if let Ok(error) = ServerError::parse(payload) {
        event = event
            .num("errno", u64::from(error.code))
            .server_text(ServerText::new(&error.message, password));
        if let Some(sqlstate) = &error.sqlstate {
            event = event.token("sqlstate", sqlstate);
        }
    }
    conn.emit(event);
}

async fn authenticate(
    upstream: &mut Box<dyn Io>,
    conn: &Conn,
    password: &[u8],
    tls: bool,
    mut state: AuthState,
) -> Result<Vec<u8>, AuthStop> {
    loop {
        let next = match read_packet(upstream, HANDSHAKE_LIMIT).await {
            Ok(next) => next,
            Err(error) => return Err(auth_stop(conn, zs_diag::io_kind(&error), AuthStop::Broken)),
        };
        let seq = next.seq.wrapping_add(1);
        let header = next.payload.first().copied();
        if matches!(header, Some(SWITCH_HEADER | MORE_DATA_HEADER)) {
            if state.rounds >= MAX_AUTH_ROUNDS {
                return Err(auth_stop(conn, "too_many_rounds", AuthStop::Refused));
            }
            state.rounds += 1;
        }
        let answer = match header {
            Some(OK_HEADER) => {
                conn.emit(
                    conn.event("upstream_auth_ok")
                        .token("plugin", &plugin_name(state.plugin)),
                );
                return Ok(next.payload);
            }
            Some(ERR_HEADER) => {
                report_rejection(conn, &next.payload, password);
                return Err(AuthStop::Rejected);
            }
            Some(SWITCH_HEADER) => Some(switch_answer(
                conn,
                &next.payload,
                password,
                tls,
                &mut state,
            )?),
            Some(MORE_DATA_HEADER) => more_data_answer(conn, &next.payload, password, tls, &state)?,
            _ => return Err(auth_stop(conn, "malformed", AuthStop::Broken)),
        };
        if let Some(answer) = answer
            && let Err(error) = write_packet(upstream, seq, &answer).await
        {
            return Err(auth_stop(conn, zs_diag::io_kind(&error), AuthStop::Broken));
        }
    }
}

fn switch_answer(
    conn: &Conn,
    payload: &[u8],
    password: &[u8],
    tls: bool,
    state: &mut AuthState,
) -> Result<Zeroizing<Vec<u8>>, AuthStop> {
    let Ok(switch) = AuthSwitch::parse(payload) else {
        return Err(auth_stop(conn, "malformed", AuthStop::Broken));
    };
    conn.emit(
        conn.event("auth_step")
            .token("plugin", &plugin_name(&switch.plugin))
            .code("step", "switch"),
    );
    let scramble_ok = switch.data.len() == SCRAMBLE_LEN;
    let (plugin, answer): (&'static [u8], Zeroizing<Vec<u8>>) = match switch.plugin.as_slice() {
        NATIVE_PASSWORD if scramble_ok => (
            NATIVE_PASSWORD,
            Zeroizing::new(scramble::native(password, &switch.data)),
        ),
        CACHING_SHA2_PASSWORD if scramble_ok => (
            CACHING_SHA2_PASSWORD,
            Zeroizing::new(scramble::caching_sha2(password, &switch.data)),
        ),
        NATIVE_PASSWORD | CACHING_SHA2_PASSWORD => {
            return Err(auth_stop(conn, "malformed_scramble", AuthStop::Broken));
        }
        SHA256_PASSWORD if tls => (SHA256_PASSWORD, cleartext(password)),
        CLEAR_PASSWORD if tls => (CLEAR_PASSWORD, cleartext(password)),
        SHA256_PASSWORD | CLEAR_PASSWORD => {
            return Err(auth_stop(conn, "cleartext_without_tls", AuthStop::Refused));
        }
        _ => return Err(auth_stop(conn, "unknown_plugin", AuthStop::Refused)),
    };
    state.plugin = plugin;
    Ok(answer)
}

fn more_data_answer(
    conn: &Conn,
    payload: &[u8],
    password: &[u8],
    tls: bool,
    state: &AuthState,
) -> Result<Option<Zeroizing<Vec<u8>>>, AuthStop> {
    if state.plugin != CACHING_SHA2_PASSWORD || payload.len() != 2 {
        return Err(auth_stop(conn, "unexpected_more_data", AuthStop::Broken));
    }
    let step = |name: &'static str| {
        conn.event("auth_step")
            .token("plugin", "caching_sha2_password")
            .code("step", name)
    };
    match payload.get(1).copied() {
        Some(0x03) => {
            conn.emit(step("fast_ok"));
            Ok(None)
        }
        Some(0x04) if tls => {
            conn.emit(step("full_auth"));
            Ok(Some(cleartext(password)))
        }
        Some(0x04) => Err(auth_stop(conn, "cleartext_without_tls", AuthStop::Refused)),
        _ => Err(auth_stop(conn, "unexpected_more_data", AuthStop::Broken)),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    Client,
    Server,
    ChangeUser,
    Broken(&'static str),
}

impl Ending {
    fn code(self) -> &'static str {
        match self {
            Ending::Client => "client",
            Ending::Server | Ending::Broken(_) => "upstream",
            Ending::ChangeUser => "change_user",
        }
    }
}

async fn forward_commands<R, W>(
    client: &mut R,
    upstream: &mut W,
    bytes: &AtomicU64,
    quit: &AtomicBool,
) -> Ending
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let mut header = [0u8; 4];
        if client.read_exact(&mut header).await.is_err() {
            return Ending::Client;
        }
        let len =
            usize::from(header[0]) | usize::from(header[1]) << 8 | usize::from(header[2]) << 16;
        let mut payload = vec![0u8; len];
        if client.read_exact(&mut payload).await.is_err() {
            return Ending::Client;
        }
        if header[3] == 0 && payload.first() == Some(&COM_CHANGE_USER) {
            return Ending::ChangeUser;
        }
        let quitting = header[3] == 0 && payload.first() == Some(&COM_QUIT);
        if quitting {
            quit.store(true, Ordering::SeqCst);
        }
        let sent = async {
            upstream.write_all(&header).await?;
            upstream.write_all(&payload).await?;
            upstream.flush().await
        }
        .await;
        if let Err(error) = sent {
            return Ending::Broken(zs_diag::io_kind(&error));
        }
        bytes.fetch_add((len + 4) as u64, Ordering::Relaxed);
        if quitting {
            return Ending::Client;
        }
    }
}

async fn copy_counted<R, W>(reader: &mut R, writer: &mut W, bytes: &AtomicU64) -> Ending
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let n = match reader.read(&mut buffer).await {
            Ok(0) => return Ending::Server,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ending::Server;
            }
            Err(error) => return Ending::Broken(zs_diag::io_kind(&error)),
            Ok(n) => n,
        };
        if writer.write_all(&buffer[..n]).await.is_err() || writer.flush().await.is_err() {
            return Ending::Client;
        }
        bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
}

async fn relay(client: TcpStream, upstream: Box<dyn Io>, conn: &Conn) {
    let up = AtomicU64::new(0);
    let down = AtomicU64::new(0);
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let ending = {
        // A server closes in answer to COM_QUIT, so the backward half can report EOF before the
        // forward half returns. The flag records the client's intent before the write, which keeps
        // the attribution to the client whatever order the halves finish in.
        let quit = AtomicBool::new(false);
        let forward = async {
            let ending = forward_commands(&mut client_read, &mut upstream_write, &up, &quit).await;
            let _ = upstream_write.shutdown().await;
            ending
        };
        let backward = copy_counted(&mut upstream_read, &mut client_write, &down);
        tokio::pin!(forward);
        tokio::pin!(backward);
        tokio::select! {
            ending = &mut forward => match ending {
                Ending::ChangeUser | Ending::Broken(_) => ending,
                other => match backward.as_mut().await {
                    broken @ Ending::Broken(_) => broken,
                    _ => other,
                },
            },
            ending = &mut backward => {
                if quit.load(Ordering::SeqCst) {
                    Ending::Client
                } else {
                    ending
                }
            }
        }
    };
    if let Ending::Broken(kind) = ending {
        conn.upstream_failed("relay", kind);
    }
    if ending == Ending::ChangeUser {
        let mut event = conn.event("change_user_refused").warn();
        if let Some(seq) = (conn.shared.audit_refusal)("change_user", CHANGE_USER_REFUSED_REASON) {
            event = event.audit_seq(seq);
        }
        conn.emit(event);
        let _ = write_packet(&mut client_write, 1, &CHANGE_USER_REFUSED.packet()).await;
    }
    conn.closed(
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed),
        ending.code(),
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use zs_protocol::{Denied, DenyKind};

    #[test]
    fn deny_kind_is_read_from_the_denied_kind_not_its_text() {
        assert_eq!(
            Denied::new("x")
                .with_kind(DenyKind::AuditUnavailable)
                .kind()
                .as_str(),
            "audit_unavailable"
        );
        assert_eq!(
            Denied::new("audit sink unavailable: x").kind().as_str(),
            "policy"
        );
        assert_eq!(
            Denied::new("x")
                .with_kind(DenyKind::Materialize)
                .kind()
                .as_str(),
            "materialize"
        );
    }
}
