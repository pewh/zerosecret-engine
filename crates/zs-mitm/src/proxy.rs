use std::convert::Infallible;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::sign::CertifiedKey;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use zs_audit::{AuditError, AuditRequest, Decision, Journal};
use zs_diag::{Component, DiagLog, Event};
use zs_protocol::{Context, Destination, InjectedRequest, Protocol};

use crate::ca::LocalCa;
use crate::echo::{self, EchoNeedles, RequestSnapshot};
use crate::http1::{self, Guarded, TargetGuard};
use crate::pipeline;
use crate::scope::{PathScope, Refusal, ScopeDecision};
use crate::websocket;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ca: {0}")]
    Ca(#[from] crate::ca::CaError),
    #[error("audit: {0}")]
    Audit(#[from] AuditError),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("framing: {0}")]
    Framing(&'static str),
    #[error("http: {0}")]
    Http(#[from] hyper::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }

    fn protocol(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

// No variant may ever carry a credential: Debug output reaches logs and panics.
#[derive(Debug)]
pub enum Flow {
    Intercept {
        resource: String,
        upstream_host: String,
        upstream_port: u16,
        upstream_tls: bool,
        scheme: Scheme,
        scope: PathScope,
    },
    Passthrough,
    Deny {
        reason: String,
    },
}

pub trait FlowHandler: Send + Sync {
    fn classify(&self, destination: &Destination) -> Flow;
    fn subject(&self) -> String;
    fn workload(&self) -> String;
    fn protocol_for(&self, resource: &str) -> Option<Arc<dyn Protocol>>;
    fn materialize(
        &self,
        resource: &str,
        operation: &str,
    ) -> Result<zs_credential::Credential, zs_protocol::Denied>;
    fn authorize_message(&self, resource: &str, operation: &str)
    -> Result<(), zs_protocol::Denied>;

    fn credential_ref(&self, _resource: &str) -> Option<String> {
        None
    }
}

pub struct ProxyServer {
    listener: TcpListener,
    ca: Arc<LocalCa>,
    handler: Arc<dyn FlowHandler>,
    journal: Arc<Journal>,
    diag: DiagLog,
}

#[derive(Debug, PartialEq, Eq)]
enum ProxyTarget {
    Tunnel {
        host: String,
        port: u16,
    },
    Absolute {
        scheme: Scheme,
        host: String,
        port: u16,
        path: String,
    },
}

// An http:// target is served only for an http binding or a passthrough host: a credential
// crosses the network in cleartext only where the binding says so (ADR-0033).
fn parse_proxy_target(method: &str, target: &str) -> Option<ProxyTarget> {
    if method == "CONNECT" {
        let (host, port) = split_authority(strip_userinfo(target), 443);
        if host.is_empty() {
            return None;
        }
        return Some(ProxyTarget::Tunnel { host, port });
    }
    let (scheme, rest) = match target.strip_prefix("https://") {
        Some(rest) => (Scheme::Https, rest),
        None => (Scheme::Http, target.strip_prefix("http://")?),
    };
    let (authority, path) = match rest.find('/') {
        Some(at) => (rest.get(..at)?, rest.get(at..)?),
        None => (rest, "/"),
    };
    let authority = strip_userinfo(authority);
    if authority.is_empty() {
        return None;
    }
    let (host, port) = split_authority(authority, scheme.default_port());
    Some(ProxyTarget::Absolute {
        scheme,
        host,
        port,
        path: path.to_string(),
    })
}

fn strip_userinfo(authority: &str) -> &str {
    authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
}

fn split_authority(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    }
}

const UNSUPPORTED_FORM: &str = "only CONNECT and absolute-URI http or https requests are supported";

fn bad_request(reason: &str) -> ProxyError {
    ProxyError::BadRequest(reason.into())
}

impl ProxyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            ProxyError::Io(e) => zs_diag::io_kind(e),
            ProxyError::Ca(_) => "ca",
            ProxyError::Audit(_) => "audit_unavailable",
            ProxyError::BadRequest(reason) => bad_request_code(reason),
            ProxyError::Framing(code) => code,
            ProxyError::Http(error) if error.is_parse_too_large() => "invalid_data",
            ProxyError::Http(error) if error.is_parse() => "unparseable",
            ProxyError::Http(_) => "io",
        }
    }
}

fn bad_request_code(reason: &str) -> &'static str {
    match reason {
        "unparseable request" | "unparseable inner request" => "unparseable",
        UNSUPPORTED_FORM => "unsupported_form",
        "unsupported transfer-encoding" => "unsupported_coding",
        "conflicting content-length" => "conflicting_length",
        "unparseable content-length" => "unparseable_length",
        "body too large" => "body_too_large",
        "truncated chunked body" => "truncated_chunked",
        "unparseable chunk size" => "unparseable_chunk",
        "malformed chunk" => "malformed_chunk",
        "chunk line too large" => "line_too_large",
        "unparseable upstream response" => "bad_upstream_response",
        _ => "bad_request",
    }
}

#[derive(Clone, Copy)]
struct Trace {
    conn: u64,
    req: u64,
    withheld: bool,
}

fn holds_userinfo(method: &str, target: &str) -> bool {
    let authority = if method == "CONNECT" {
        target
    } else {
        let rest = target.strip_prefix("https://").unwrap_or(target);
        rest.split('/').next().unwrap_or(rest)
    };
    authority.contains('@')
}

fn at_dest(event: Event, trace: Trace, host: &str, port: u16) -> Event {
    if trace.withheld {
        event.dest_withheld()
    } else {
        event.dest(host, port)
    }
}

fn proxy_event(conn: u64, name: &'static str) -> Event {
    Event::new(Component::Proxy, name).conn(conn)
}

fn with_seq(event: Event, seq: Option<u64>) -> Event {
    match seq {
        Some(seq) => event.audit_seq(seq),
        None => event,
    }
}

fn classified(trace: Trace, destination: &Destination, flow: &'static str) -> Event {
    at_dest(
        proxy_event(trace.conn, "classified"),
        trace,
        &destination.host,
        destination.port,
    )
    .code("flow", flow)
}

fn method_event(event: Event, method: &str) -> Event {
    let standard = (1..=16).contains(&method.len())
        && method
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
    if standard {
        event.token("method", method)
    } else {
        event.code("method", "nonstandard")
    }
}

fn elapsed_ms(started: std::time::Instant) -> u64 {
    started.elapsed().as_millis() as u64
}

impl ProxyServer {
    pub async fn bind(
        addr: SocketAddr,
        ca: Arc<LocalCa>,
        handler: Arc<dyn FlowHandler>,
        journal: Arc<Journal>,
    ) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            ca,
            handler,
            journal,
            diag: DiagLog::disabled(),
        })
    }

    pub fn with_diag(mut self, diag: DiagLog) -> Self {
        self.diag = diag;
        self
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(&self) -> std::io::Result<()> {
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let conn = self.diag.next_conn();
            let diag = self.diag.clone();
            let this = ProxyShared {
                ca: self.ca.clone(),
                handler: self.handler.clone(),
                journal: self.journal.clone(),
                diag: self.diag.clone(),
            };
            let state = ConnectionState::default();
            tokio::spawn(async move {
                let started = std::time::Instant::now();
                let result = handle_connection(stream, this, conn, state.clone()).await;
                if state.upgraded() {
                    return;
                }
                let closed = proxy_event(conn, "conn_closed").num("ms", elapsed_ms(started));
                match result {
                    Ok(()) => diag.emit(closed.code("result", "ok")),
                    Err(e) => {
                        tracing_or_stderr(&format!("connection ended: {e}"));
                        diag.emit(closed.warn().code("result", "error").failure(e.code()));
                    }
                }
            });
        }
    }
}

// A loopback HTTP listener for one https binding, for clients that ignore proxy variables
// (Bun's S3 client). Each request is served as an absolute-URI request to the binding's origin.
pub struct EndpointServer {
    listener: TcpListener,
    shared: ProxyShared,
    origin_host: String,
    origin_port: u16,
}

const PRESIGN_PATH: &str = "/.zs/presign";

impl EndpointServer {
    pub async fn bind(
        addr: SocketAddr,
        ca: Arc<LocalCa>,
        handler: Arc<dyn FlowHandler>,
        journal: Arc<Journal>,
        diag: DiagLog,
        origin_host: String,
    ) -> Result<Self, ProxyError> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self {
            listener,
            shared: ProxyShared {
                ca,
                handler,
                journal,
                diag,
            },
            origin_host,
            origin_port: 443,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve(&self) -> std::io::Result<()> {
        loop {
            let (stream, _peer) = self.listener.accept().await?;
            let conn = self.shared.diag.next_conn();
            let shared = ProxyShared {
                ca: self.shared.ca.clone(),
                handler: self.shared.handler.clone(),
                journal: self.shared.journal.clone(),
                diag: self.shared.diag.clone(),
            };
            let host = self.origin_host.clone();
            let port = self.origin_port;
            tokio::spawn(async move {
                if let Err(e) = serve_endpoint_connection(stream, shared, host, port, conn).await {
                    tracing_or_stderr(&format!("endpoint connection ended: {e}"));
                }
            });
        }
    }
}

async fn serve_endpoint_connection(
    stream: TcpStream,
    shared: ProxyShared,
    host: String,
    port: u16,
    conn: u64,
) -> Result<(), ProxyError> {
    let local_port = stream.local_addr()?.port();
    let loopback_hosts = [
        format!("127.0.0.1:{local_port}"),
        format!("localhost:{local_port}"),
    ];
    let state = ConnectionState::default();
    let guard = TargetGuard::default();
    let req = Arc::new(AtomicU64::new(0));
    let service = {
        let shared = shared.clone();
        let state = state.clone();
        let guard = guard.clone();
        let req = req.clone();
        let host = host.clone();
        let loopback_hosts = loopback_hosts.clone();
        hyper::service::service_fn(move |request: Request<Incoming>| {
            let shared = shared.clone();
            let state = state.clone();
            let guard = guard.clone();
            let req = req.clone();
            let host = host.clone();
            let loopback_hosts = loopback_hosts.clone();
            async move {
                let response = endpoint_request(
                    request,
                    shared,
                    &state,
                    &guard,
                    &req,
                    &host,
                    port,
                    conn,
                    &loopback_hosts,
                )
                .await;
                Ok::<_, Infallible>(response)
            }
        })
    };
    let served = http1::server()
        .serve_connection(TokioIo::new(Guarded::new(stream, guard)), service)
        .await;
    finish_connection(served, state)
}

#[allow(clippy::too_many_arguments)]
async fn endpoint_request(
    request: Request<Incoming>,
    shared: ProxyShared,
    state: &ConnectionState,
    guard: &TargetGuard,
    req: &AtomicU64,
    host: &str,
    port: u16,
    conn: u64,
    loopback_hosts: &[String; 2],
) -> Response<http1::Body> {
    let origin_form = request.uri().scheme().is_none()
        && request.uri().authority().is_none()
        && request.uri().path().starts_with('/');
    let mut named = request.headers().get_all(hyper::header::HOST).iter();
    let loopback = match (named.next(), named.next()) {
        (Some(value), None) => loopback_hosts
            .iter()
            .any(|known| value.as_bytes().eq_ignore_ascii_case(known.as_bytes())),
        _ => false,
    };
    let has_origin = request.headers().contains_key("origin");
    if !origin_form || !loopback || has_origin {
        return http1::reply(http1::Reply::Refused);
    }
    let number = req.fetch_add(1, Ordering::SeqCst) + 1;
    if guard.bad_at(number - 1) {
        state.fail(ProxyError::Framing("fragment"));
        return http1::reply(http1::Reply::Refused);
    }
    let trace = Trace {
        conn,
        req: number,
        withheld: false,
    };
    let (injected, extensions) = match http1::into_injected(request).await {
        Ok(pair) => pair,
        Err(framing) => {
            state.fail(ProxyError::Framing(framing.code()));
            return http1::reply(http1::Reply::Refused);
        }
    };
    if injected.method == "POST" && injected.path == PRESIGN_PATH {
        return match handle_presign(&shared, host, port, &injected.body).await {
            Ok(response) => response,
            Err(error) => failure(state, error),
        };
    }
    handle_absolute(
        &shared,
        AbsoluteRequest {
            scheme: Scheme::Https,
            host: host.to_string(),
            port,
            request: injected,
            extensions,
        },
        trace,
        state,
    )
    .await
}

async fn handle_presign(
    shared: &ProxyShared,
    host: &str,
    port: u16,
    body: &[u8],
) -> Result<Response<http1::Body>, ProxyError> {
    let destination = Destination::new(host.to_string(), port);
    let parsed: Option<(String, String)> = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            Some((
                v.get("url")?.as_str()?.to_string(),
                v.get("method")?.as_str()?.to_ascii_uppercase(),
            ))
        });
    let Some((url, method)) = parsed else {
        return Ok(http1::reply(http1::Reply::Refused));
    };
    let operation = format!("presign {method}");
    let path_and_query = url
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| rest[at..].to_string()));
    let signed = (|| {
        let path_and_query = path_and_query.ok_or_else(|| zs_protocol::Denied::new("no path"))?;
        let Flow::Intercept {
            resource,
            scheme: Scheme::Https,
            scope,
            ..
        } = shared.handler.classify(&destination)
        else {
            return Err(zs_protocol::Denied::new("not an https binding"));
        };
        let path = path_and_query.split('?').next().unwrap_or("");
        if scope.decide(path) != ScopeDecision::Inject {
            return Err(zs_protocol::Denied::new(
                "path is outside the binding's scope",
            ));
        }
        let protocol = shared
            .handler
            .protocol_for(&resource)
            .ok_or_else(|| zs_protocol::Denied::new("no protocol"))?;
        let credential = shared.handler.materialize(&resource, &method)?;
        protocol.resign_url(
            &authority(host, port),
            &path_and_query,
            &method,
            &credential,
        )
    })();
    match signed {
        Ok(signed) => {
            audit(shared, &destination, Decision::Allow, &operation, None)?;
            Ok(http1::text_response(format!(
                "https://{}{signed}",
                authority(host, port)
            )))
        }
        Err(denied) => {
            audit(
                shared,
                &destination,
                Decision::Deny,
                &operation,
                Some(denied.audit_reason()),
            )?;
            Ok(http1::reply(http1::Reply::Denied))
        }
    }
}

#[derive(Clone, Default)]
struct ConnectionState {
    failure: Arc<std::sync::Mutex<Option<ProxyError>>>,
    upgraded: Arc<std::sync::atomic::AtomicBool>,
}

impl ConnectionState {
    fn fail(&self, error: ProxyError) {
        let mut slot = match self.failure.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    fn upgrade(&self) {
        self.upgraded.store(true, Ordering::SeqCst);
    }

    fn upgraded(&self) -> bool {
        self.upgraded.load(Ordering::SeqCst)
    }

    fn take(&self) -> Option<ProxyError> {
        match self.failure.lock() {
            Ok(mut slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        }
    }
}

fn failure(state: &ConnectionState, error: ProxyError) -> Response<http1::Body> {
    let reply = match &error {
        ProxyError::Audit(_) => http1::Reply::AuditUnavailable,
        _ => http1::Reply::Denied,
    };
    state.fail(error);
    http1::reply(reply)
}

fn finish_connection(
    served: Result<(), hyper::Error>,
    state: ConnectionState,
) -> Result<(), ProxyError> {
    if let Some(error) = state.take() {
        return Err(error);
    }
    match served {
        Ok(()) => Ok(()),
        Err(error) => transport_error(error),
    }
}

fn transport_error(error: hyper::Error) -> Result<(), ProxyError> {
    if error.is_incomplete_message() || error.is_closed() || error.is_canceled() {
        return Ok(());
    }
    Err(ProxyError::Http(error))
}

async fn passthrough_upstream(host: &str, port: u16) -> Option<TcpStream> {
    let addr = tokio::net::lookup_host((host, port)).await.ok()?.next()?;
    TcpStream::connect(addr).await.ok()
}

#[derive(Clone)]
struct ProxyShared {
    ca: Arc<LocalCa>,
    handler: Arc<dyn FlowHandler>,
    journal: Arc<Journal>,
    diag: DiagLog,
}

fn tracing_or_stderr(msg: &str) {
    let _ = writeln!(std::io::stderr(), "zs-mitm: {msg}");
}

fn audit_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn handle_connection(
    stream: TcpStream,
    shared: ProxyShared,
    conn: u64,
    state: ConnectionState,
) -> Result<(), ProxyError> {
    let guard = TargetGuard::default();
    let req = Arc::new(AtomicU64::new(0));
    let service = {
        let shared = shared.clone();
        let state = state.clone();
        let guard = guard.clone();
        hyper::service::service_fn(move |request: Request<Incoming>| {
            let shared = shared.clone();
            let state = state.clone();
            let guard = guard.clone();
            let req = req.clone();
            async move {
                Ok::<_, Infallible>(front_door(request, shared, conn, &req, &state, &guard).await)
            }
        })
    };
    let diag = shared.diag.clone();
    let served = http1::server()
        .serve_connection(TokioIo::new(Guarded::new(stream, guard)), service)
        .with_upgrades()
        .await;
    if served.as_ref().is_err_and(hyper::Error::is_parse) {
        diag.emit(
            proxy_event(conn, "conn_accepted")
                .dest_withheld()
                .code("form", "unparseable"),
        );
    }
    finish_connection(served, state)
}

async fn front_door(
    request: Request<Incoming>,
    shared: ProxyShared,
    conn: u64,
    req: &AtomicU64,
    state: &ConnectionState,
    guard: &TargetGuard,
) -> Response<http1::Body> {
    let method = request.method().as_str().to_string();
    let target = request.uri().to_string();
    let withheld = holds_userinfo(&method, &target);
    let number = req.fetch_add(1, Ordering::SeqCst) + 1;
    let parsed = parse_proxy_target(&method, &target);
    if guard.bad_at(number - 1) {
        if let Some(ProxyTarget::Absolute {
            scheme, host, port, ..
        }) = &parsed
        {
            let destination = Destination::new(host.clone(), *port);
            audit_as(
                &shared,
                &destination,
                Decision::Deny,
                &method,
                Some("fragment"),
                *scheme,
            )
            .ok();
        }
        state.fail(ProxyError::Framing("fragment"));
        return http1::reply(http1::Reply::Refused);
    }
    match parsed {
        Some(ProxyTarget::Tunnel { host, port }) => {
            tunnel(request, shared, conn, state.clone(), host, port, withheld).await
        }
        Some(ProxyTarget::Absolute {
            scheme,
            host,
            port,
            path,
        }) => {
            let trace = Trace {
                conn,
                req: number,
                withheld,
            };
            if number == 1 {
                shared.diag.emit(at_dest(
                    proxy_event(conn, "conn_accepted").code("form", "absolute"),
                    trace,
                    &host,
                    port,
                ));
            }
            let (mut injected, extensions) = match http1::into_injected(request).await {
                Ok(pair) => pair,
                Err(framing) => {
                    state.fail(ProxyError::Framing(framing.code()));
                    return http1::reply(http1::Reply::Refused);
                }
            };
            injected.path = path;
            handle_absolute(
                &shared,
                AbsoluteRequest {
                    scheme,
                    host,
                    port,
                    request: injected,
                    extensions,
                },
                trace,
                state,
            )
            .await
        }
        None => {
            state.fail(bad_request(UNSUPPORTED_FORM));
            http1::reply(http1::Reply::Refused)
        }
    }
}

async fn tunnel(
    mut request: Request<Incoming>,
    shared: ProxyShared,
    conn: u64,
    state: ConnectionState,
    host: String,
    port: u16,
    withheld: bool,
) -> Response<http1::Body> {
    let trace = Trace {
        conn,
        req: 0,
        withheld,
    };
    let destination = Destination::new(host.clone(), port);
    shared.diag.emit(at_dest(
        proxy_event(conn, "conn_accepted").code("form", "connect"),
        trace,
        &host,
        port,
    ));
    match shared.handler.classify(&destination) {
        Flow::Deny { reason } => {
            let seq = audit(
                &shared,
                &destination,
                Decision::Deny,
                "connect",
                Some(&reason),
            )
            .ok();
            shared.diag.emit(with_seq(
                classified(trace, &destination, "deny").warn(),
                seq,
            ));
            http1::reply(http1::Reply::Denied)
        }
        Flow::Passthrough => {
            let recorded = audit(
                &shared,
                &destination,
                Decision::Passthrough,
                "connect",
                None,
            );
            shared.diag.emit(with_seq(
                classified(trace, &destination, "passthrough"),
                recorded.as_ref().ok().copied(),
            ));
            if recorded.is_err() {
                return http1::reply(http1::Reply::AuditUnavailable);
            }
            let Some(upstream) = passthrough_upstream(&host, port).await else {
                return http1::reply(http1::Reply::UpstreamUnreachable);
            };
            let upgrade = hyper::upgrade::on(&mut request);
            state.upgrade();
            let diag = shared.diag.clone();
            tokio::spawn(async move {
                let started = std::time::Instant::now();
                let mut client = match upgrade.await {
                    Ok(upgraded) => TokioIo::new(upgraded),
                    Err(_) => return,
                };
                let mut upstream = upstream;
                let result = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                let closed = proxy_event(conn, "conn_closed").num("ms", elapsed_ms(started));
                match result {
                    Ok(_) => diag.emit(closed.code("result", "ok")),
                    Err(error) => {
                        tracing_or_stderr(&format!("passthrough ended: {error}"));
                        diag.emit(
                            closed
                                .warn()
                                .code("result", "error")
                                .failure(zs_diag::io_kind(&error)),
                        );
                    }
                }
            });
            http1::reply(http1::Reply::Established)
        }
        Flow::Intercept {
            scheme: Scheme::Http,
            ..
        } => {
            let seq = audit(
                &shared,
                &destination,
                Decision::Deny,
                "connect",
                Some("CONNECT to an http binding"),
            )
            .ok();
            shared.diag.emit(with_seq(
                classified(trace, &destination, "deny").warn(),
                seq,
            ));
            http1::reply(http1::Reply::Denied)
        }
        Flow::Intercept {
            resource,
            upstream_host,
            upstream_port,
            upstream_tls,
            scheme: Scheme::Https,
            scope,
        } => {
            let recorded = audit(&shared, &destination, Decision::Allow, "connect", None);
            shared.diag.emit(with_seq(
                classified(trace, &destination, "intercept").resource(&resource),
                recorded.as_ref().ok().copied(),
            ));
            if recorded.is_err() {
                return http1::reply(http1::Reply::AuditUnavailable);
            }
            if let Err((kind, reason)) = authorize_request(&shared, &resource) {
                let seq = audit(
                    &shared,
                    &destination,
                    Decision::Deny,
                    "connect",
                    Some(&reason),
                )
                .ok();
                shared.diag.emit(with_seq(
                    proxy_event(trace.conn, "request_decided")
                        .warn()
                        .resource(&resource)
                        .code("decision", "deny")
                        .code("deny_kind", kind),
                    seq,
                ));
                return http1::reply(http1::Reply::DeniedBecause(reason));
            }
            let upgrade = hyper::upgrade::on(&mut request);
            state.upgrade();
            let diag = shared.diag.clone();
            tokio::spawn(async move {
                let started = std::time::Instant::now();
                let upgraded = match upgrade.await {
                    Ok(upgraded) => upgraded,
                    Err(_) => return,
                };
                let result = serve_intercepted(
                    TokioIo::new(upgraded),
                    shared,
                    resource,
                    Upstream {
                        host: upstream_host,
                        port: upstream_port,
                        tls: upstream_tls,
                    },
                    destination,
                    scope,
                    conn,
                )
                .await;
                let closed = proxy_event(conn, "conn_closed").num("ms", elapsed_ms(started));
                match result {
                    Ok(()) => diag.emit(closed.code("result", "ok")),
                    Err(error) => {
                        tracing_or_stderr(&format!("connection ended: {error}"));
                        diag.emit(closed.warn().code("result", "error").failure(error.code()));
                    }
                }
            });
            http1::reply(http1::Reply::Established)
        }
    }
}

struct AbsoluteRequest {
    scheme: Scheme,
    host: String,
    port: u16,
    request: InjectedRequest,
    extensions: hyper::http::Extensions,
}

#[derive(Clone)]
pub(crate) struct Upstream {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

// The `Host` sent upstream. It is also written into the request before `inject`, so a scheme
// that signs `Host` signs what the upstream receives.
fn authority(host: &str, port: u16) -> String {
    authority_for(Scheme::Https, host, port)
}

fn authority_for(scheme: Scheme, host: &str, port: u16) -> String {
    if port == scheme.default_port() {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

fn origin_refusal(
    target: &str,
    headers: &[(String, String)],
    host: &str,
    port: u16,
) -> Option<Refusal> {
    if !target.starts_with('/') {
        return Some(Refusal::NotOriginForm);
    }
    let mut named = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Host"))
        .map(|(_, v)| v.trim());
    let value = match (named.next(), named.next()) {
        (None, _) => return Some(Refusal::HostMissing),
        (Some(_), Some(_)) => return Some(Refusal::HostRepeated),
        (Some(value), None) => value,
    };
    let (name, named_port) = match value.rsplit_once(':') {
        Some((name, digits)) if !name.contains(':') || name.ends_with(']') => {
            match digits.parse::<u16>() {
                Ok(p) => (name, p),
                Err(_) => return Some(Refusal::HostMismatch),
            }
        }
        _ => (value, 443),
    };
    if !name.is_empty() && name.eq_ignore_ascii_case(host) && named_port == port {
        None
    } else {
        Some(Refusal::HostMismatch)
    }
}

#[cfg(test)]
fn tunnel_request_names_origin(
    target: &str,
    headers: &[(String, String)],
    host: &str,
    port: u16,
) -> bool {
    origin_refusal(target, headers, host, port).is_none()
}

struct SiteReport {
    shared: ProxyShared,
    state: ConnectionState,
    trace: Trace,
    record: Destination,
    scheme: Scheme,
    resource: String,
    dest: Option<(String, u16)>,
    started: std::time::Instant,
}

impl SiteReport {
    fn decided(&self, facts: &pipeline::RequestFacts, scope: &'static str) -> Event {
        method_event(
            proxy_event(self.trace.conn, "request_decided")
                .req(self.trace.req)
                .resource(&self.resource),
            &facts.method,
        )
        .code("scope", scope)
    }

    fn located(&self, name: &'static str) -> Event {
        let event = proxy_event(self.trace.conn, name).req(self.trace.req);
        match &self.dest {
            Some((host, port)) => at_dest(event, self.trace, host.as_str(), *port),
            None => event.resource(&self.resource),
        }
    }
}

impl pipeline::Report for SiteReport {
    fn audit(
        &self,
        facts: &pipeline::RequestFacts,
        decision: Decision,
        reason: Option<&str>,
    ) -> Result<u64, AuditError> {
        audit_as(
            &self.shared,
            &self.record,
            decision,
            &facts.operation,
            reason,
            self.scheme,
        )
    }

    fn audit_failed(&self, error: AuditError) {
        self.state.fail(ProxyError::Audit(error));
    }

    fn refused(&self, facts: &pipeline::RequestFacts, rule: &'static str, seq: Option<u64>) {
        let mut event = self
            .decided(facts, "refuse")
            .warn()
            .code("rule", rule)
            .code("decision", "deny");
        if let Some(seq) = seq {
            event = event.audit_seq(seq);
        }
        self.shared.diag.emit(event);
    }

    fn forwarded(&self, facts: &pipeline::RequestFacts, seq: u64) {
        self.shared.diag.emit(
            self.decided(facts, "forward")
                .code("decision", "passthrough")
                .audit_seq(seq),
        );
    }

    fn authorized(&self, facts: &pipeline::RequestFacts, seq: u64) {
        self.shared.diag.emit(
            self.decided(facts, "inject")
                .code("decision", "allow")
                .audit_seq(seq),
        );
    }

    fn denied(&self, facts: &pipeline::RequestFacts, stage: &'static str, seq: u64) {
        self.shared.diag.emit(
            self.decided(facts, "inject")
                .warn()
                .code("decision", "deny")
                .code("deny_kind", stage)
                .audit_seq(seq),
        );
    }

    fn relayed(&self, _facts: &pipeline::RequestFacts, status: u16, bytes: u64) {
        self.shared.diag.emit(
            self.located("response_relayed")
                .num("status", u64::from(status))
                .num("bytes", bytes)
                .num("ms", elapsed_ms(self.started)),
        );
    }

    fn failed(&self, _facts: &pipeline::RequestFacts, stage: &'static str, kind: &'static str) {
        self.shared.diag.emit(
            self.located("upstream_failed")
                .warn()
                .code("stage", stage)
                .failure(kind),
        );
    }
}

async fn handle_absolute(
    shared: &ProxyShared,
    absolute: AbsoluteRequest,
    trace: Trace,
    state: &ConnectionState,
) -> Response<http1::Body> {
    let AbsoluteRequest {
        scheme,
        host,
        port,
        mut request,
        extensions,
    } = absolute;
    let method = request.method.clone();
    let destination = Destination::new(host.clone(), port);
    let (resource, upstream, scope) = match shared.handler.classify(&destination) {
        Flow::Intercept { scheme: bound, .. } if bound != scheme => {
            let seq = audit_as(
                shared,
                &destination,
                Decision::Deny,
                &method,
                Some(match bound {
                    Scheme::Http => "https request to an http binding",
                    Scheme::Https => "http request to an https binding",
                }),
                scheme,
            )
            .ok();
            shared.diag.emit(with_seq(
                classified(trace, &destination, "deny")
                    .req(trace.req)
                    .warn(),
                seq,
            ));
            return http1::reply(http1::Reply::Denied);
        }
        Flow::Deny { reason } => {
            let seq = audit_as(
                shared,
                &destination,
                Decision::Deny,
                &method,
                Some(&reason),
                scheme,
            )
            .ok();
            shared.diag.emit(with_seq(
                classified(trace, &destination, "deny")
                    .req(trace.req)
                    .warn(),
                seq,
            ));
            return http1::reply(http1::Reply::Denied);
        }
        Flow::Passthrough => {
            let recorded = audit_as(
                shared,
                &destination,
                Decision::Passthrough,
                "connect",
                None,
                scheme,
            );
            shared.diag.emit(with_seq(
                classified(trace, &destination, "passthrough").req(trace.req),
                recorded.as_ref().ok().copied(),
            ));
            if let Err(error) = recorded {
                return failure(state, ProxyError::Audit(error));
            }
            (
                String::new(),
                Upstream {
                    host: host.clone(),
                    port,
                    tls: scheme == Scheme::Https,
                },
                PathScope::Host,
            )
        }
        Flow::Intercept {
            resource,
            upstream_host,
            upstream_port,
            upstream_tls,
            scheme: _,
            scope,
        } => {
            let recorded = audit_as(
                shared,
                &destination,
                Decision::Allow,
                "connect",
                None,
                scheme,
            );
            shared.diag.emit(with_seq(
                classified(trace, &destination, "intercept")
                    .req(trace.req)
                    .resource(&resource),
                recorded.as_ref().ok().copied(),
            ));
            if let Err(error) = recorded {
                return failure(state, ProxyError::Audit(error));
            }
            (
                resource,
                Upstream {
                    host: upstream_host,
                    port: upstream_port,
                    tls: upstream_tls,
                },
                scope,
            )
        }
    };

    request.remove_header("Proxy-Connection");
    let facts = pipeline::RequestFacts {
        resource: resource.clone(),
        operation: method.clone(),
        method,
        path: request.path.clone(),
        destination: destination.clone(),
        subject: shared.handler.subject(),
        workload: shared.handler.workload(),
    };
    let report: Arc<dyn pipeline::Report> = Arc::new(SiteReport {
        shared: shared.clone(),
        state: state.clone(),
        trace,
        record: destination,
        scheme,
        resource,
        dest: Some((host.clone(), port)),
        started: std::time::Instant::now(),
    });
    let pending = pipeline::Pending {
        facts,
        request,
        extensions,
        authority: authority_for(scheme, &host, port),
        route: pipeline::Route::Fresh { upstream },
        report: report.clone(),
        skip_inject: false,
        echo: None,
    };
    pipeline::run(shared.handler.clone(), scope, report, pending).await
}

fn authorize_request(shared: &ProxyShared, resource: &str) -> Result<(), (&'static str, String)> {
    let subject = shared.handler.subject();
    let workload = shared.handler.workload();
    let protocol = shared
        .handler
        .protocol_for(resource)
        .ok_or_else(|| ("identity", format!("no protocol for {resource}")))?;
    let subject = zs_identity::Subject::new(subject).map_err(|e| ("identity", e.to_string()))?;
    let workload =
        zs_identity::WorkloadLabel::new(workload).map_err(|e| ("identity", e.to_string()))?;
    let ctx = Context {
        subject: &subject,
        workload: &workload,
    };
    protocol
        .authorize(&ctx)
        .map_err(|e| ("authorize", e.reason.clone()))
}

fn audit(
    shared: &ProxyShared,
    destination: &Destination,
    decision: Decision,
    operation: &str,
    reason: Option<&str>,
) -> Result<u64, AuditError> {
    audit_as(
        shared,
        destination,
        decision,
        operation,
        reason,
        Scheme::Https,
    )
}

fn audit_as(
    shared: &ProxyShared,
    destination: &Destination,
    decision: Decision,
    operation: &str,
    reason: Option<&str>,
    scheme: Scheme,
) -> Result<u64, AuditError> {
    let resource = format!("{}:{}", destination.host, destination.port);
    let request = AuditRequest {
        subject: shared.handler.subject(),
        workload: shared.handler.workload(),
        resource: resource.clone(),
        protocol: scheme.protocol().into(),
        operation: operation.to_string(),
        decision,
        reason: reason.map(str::to_string),
        credential_ref: shared.handler.credential_ref(&resource),
    };
    shared.journal.append_seq(&request, audit_now())
}

#[derive(Clone)]
struct TunnelShared {
    shared: ProxyShared,
    resource: String,
    upstream: Upstream,
    origin: Destination,
    scope: PathScope,
    conn: u64,
}

async fn serve_intercepted<S>(
    client: S,
    shared: ProxyShared,
    resource: String,
    upstream: Upstream,
    origin: Destination,
    scope: PathScope,
    conn: u64,
) -> Result<(), ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let certified = shared.ca.certified_key_for(&origin.host)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| ProxyError::Ca(crate::ca::CaError::Certificate(e.to_string())))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(StaticResolver(certified)));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tls_client = match acceptor.accept(client).await {
        Ok(tls) => tls,
        Err(e) => {
            shared.diag.emit(
                proxy_event(conn, "client_tls_failed")
                    .warn()
                    .resource(&resource)
                    .failure(zs_diag::io_kind(&e)),
            );
            return Err(e.into());
        }
    };
    let inner = TunnelShared {
        shared,
        resource,
        upstream,
        origin,
        scope,
        conn,
    };
    let state = ConnectionState::default();
    let guard = TargetGuard::default();
    let req = Arc::new(AtomicU64::new(0));
    let senders: Arc<tokio::sync::Mutex<Option<http1::Sender>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let service = {
        let inner = inner.clone();
        let state = state.clone();
        let guard = guard.clone();
        let req = req.clone();
        let senders = senders.clone();
        hyper::service::service_fn(move |request: Request<Incoming>| {
            let inner = inner.clone();
            let state = state.clone();
            let guard = guard.clone();
            let req = req.clone();
            let senders = senders.clone();
            async move {
                let response =
                    tunneled_request(request, inner, &state, &guard, &req, senders.clone()).await;
                Ok::<_, Infallible>(response)
            }
        })
    };
    let served = http1::server()
        .serve_connection(TokioIo::new(Guarded::new(tls_client, guard)), service)
        .with_upgrades()
        .await;
    finish_connection(served, state)
}

async fn tunneled_request(
    mut request: Request<Incoming>,
    inner: TunnelShared,
    state: &ConnectionState,
    guard: &TargetGuard,
    req: &AtomicU64,
    senders: Arc<tokio::sync::Mutex<Option<http1::Sender>>>,
) -> Response<http1::Body> {
    let TunnelShared {
        shared,
        resource,
        upstream,
        origin,
        scope,
        conn,
    } = inner;
    let number = req.fetch_add(1, Ordering::SeqCst) + 1;
    let fragment = guard.bad_at(number - 1);
    let upgrade = if request.headers().contains_key(hyper::header::UPGRADE) {
        Some(hyper::upgrade::on(&mut request))
    } else {
        None
    };
    let (mut injected, extensions) = match http1::into_injected(request).await {
        Ok(pair) => pair,
        Err(framing) => {
            state.fail(ProxyError::Framing(framing.code()));
            return http1::reply(http1::Reply::Refused);
        }
    };
    let record = Destination::new(origin.host.clone(), upstream.port);
    let facts = pipeline::RequestFacts {
        resource: resource.clone(),
        operation: injected.method.clone(),
        method: injected.method.clone(),
        path: injected.path.clone(),
        destination: record.clone(),
        subject: shared.handler.subject(),
        workload: shared.handler.workload(),
    };
    let report: Arc<dyn pipeline::Report> = Arc::new(SiteReport {
        shared: shared.clone(),
        state: state.clone(),
        trace: Trace {
            conn,
            req: number,
            withheld: false,
        },
        record,
        scheme: Scheme::Https,
        resource: resource.clone(),
        dest: None,
        started: std::time::Instant::now(),
    });
    if fragment {
        let seq = report.audit(&facts, Decision::Deny, Some("fragment")).ok();
        report.refused(&facts, "fragment", seq);
        state.fail(ProxyError::Framing("fragment"));
        return http1::reply(http1::Reply::Refused);
    }
    if let Some(refusal) =
        origin_refusal(&injected.path, &injected.headers, &origin.host, origin.port)
    {
        let seq = report
            .audit(&facts, Decision::Deny, Some(refusal.code()))
            .ok();
        report.refused(&facts, refusal.code(), seq);
        return http1::reply(http1::Reply::Refused);
    }
    injected.remove_header("Proxy-Connection");
    let authority = authority(&origin.host, origin.port);

    if upgrade.is_some() && websocket::is_upgrade(&injected) {
        let skip_inject = match pipeline::authorize_only(&shared.handler, &*report, &scope, &facts)
        {
            Ok(skip) => skip,
            Err(reply) => return *reply,
        };
        let (injection, echo) = if skip_inject {
            (None, None)
        } else {
            let before = RequestSnapshot::of(&injected);
            match pipeline::inject_only(
                &shared.handler,
                &*report,
                &facts,
                &mut injected,
                &authority,
            ) {
                Ok(pair) => {
                    let echo = pair.as_ref().map(|(_, credential)| {
                        EchoNeedles::from_injection(&before, &injected, credential.expose())
                    });
                    (pair, echo)
                }
                Err(reply) => return *reply,
            }
        };
        let Some(upgrade) = upgrade else {
            return http1::reply(http1::Reply::Refused);
        };
        return serve_websocket(
            upgrade,
            &shared,
            &facts.destination,
            &mut injected,
            &extensions,
            &upstream,
            &origin,
            (injection, echo),
            (conn, number, &resource),
        )
        .await;
    }

    let pending = pipeline::Pending {
        facts,
        request: injected,
        extensions,
        authority,
        route: pipeline::Route::Tunnel { senders, upstream },
        report: report.clone(),
        skip_inject: false,
        echo: None,
    };
    pipeline::run(shared.handler.clone(), scope, report, pending).await
}

#[allow(clippy::too_many_arguments)]
async fn serve_websocket(
    upgrade: hyper::upgrade::OnUpgrade,
    shared: &ProxyShared,
    record: &Destination,
    request: &mut InjectedRequest,
    extensions: &hyper::http::Extensions,
    upstream: &Upstream,
    origin: &Destination,
    (injection, echo): (pipeline::Injected, Option<EchoNeedles>),
    (conn, req, resource): (u64, u64, &str),
) -> Response<http1::Body> {
    let event = |name: &'static str| proxy_event(conn, name).req(req).resource(resource);
    request.remove_header("Sec-WebSocket-Extensions");
    let mut sender = match connect_upstream(&upstream.host, upstream.port, upstream.tls, true).await
    {
        Ok(sender) => sender,
        Err(error) => {
            shared.diag.emit(
                event("upstream_failed")
                    .warn()
                    .code("stage", "connect")
                    .failure(error.code()),
            );
            return http1::reply(http1::Reply::UpstreamUnreachable);
        }
    };
    let mut outbound = match outbound(request, &authority(&origin.host, origin.port), extensions) {
        Ok(outbound) => outbound,
        Err(error) => {
            shared.diag.emit(
                event("upstream_failed")
                    .warn()
                    .code("stage", "connect")
                    .failure(error.code()),
            );
            return http1::reply(http1::Reply::Refused);
        }
    };
    outbound.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("Upgrade"),
    );
    let mut response = match sender.send_request(outbound).await {
        Ok(response) => response,
        Err(error) => {
            shared.diag.emit(
                event("upstream_failed")
                    .warn()
                    .code("stage", "relay")
                    .failure(ProxyError::Http(error).code()),
            );
            return http1::reply(http1::Reply::UpstreamUnreachable);
        }
    };
    let switching = response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS;
    let refusal = echo.as_ref().and_then(|needles| {
        if needles.found_in_response_head(&response) {
            Some("response echo")
        } else if !switching && echo::encoded(response.headers()) {
            Some("response encoded")
        } else {
            None
        }
    });
    if let Some(reason) = refusal {
        drop(response);
        drop(sender);
        let seq = audit(
            shared,
            record,
            Decision::Deny,
            &request.method,
            Some(reason),
        )
        .ok();
        shared
            .diag
            .emit(with_seq(event("websocket_refused").warn(), seq));
        return http1::reply(http1::Reply::Denied);
    }
    let upstream_upgrade = hyper::upgrade::on(&mut response);
    if !switching {
        let mut response = response.map(http1::boxed);
        if let Some(needles) = echo {
            let shared = shared.clone();
            let record = record.clone();
            let method = request.method.clone();
            let resource = resource.to_string();
            response = response.map(|body| {
                echo::guarded(body, Arc::new(needles), move || {
                    let seq = audit(
                        &shared,
                        &record,
                        Decision::Deny,
                        &method,
                        Some("response echo"),
                    )
                    .ok();
                    shared.diag.emit(with_seq(
                        proxy_event(conn, "websocket_refused")
                            .req(req)
                            .resource(&resource)
                            .warn(),
                        seq,
                    ));
                })
            });
        }
        let mut response = http1::counted(response, |_| {});
        response.headers_mut().insert(
            hyper::header::CONNECTION,
            hyper::header::HeaderValue::from_static("close"),
        );
        return response;
    }
    drop(echo);
    if response.headers().contains_key("sec-websocket-extensions") {
        let seq = audit(
            shared,
            record,
            Decision::Deny,
            &request.method,
            Some("websocket extension"),
        )
        .ok();
        shared
            .diag
            .emit(with_seq(event("websocket_refused").warn(), seq));
        return http1::reply(http1::Reply::Denied);
    }
    let mut switching = Response::new(http1::empty_body());
    *switching.status_mut() = hyper::StatusCode::SWITCHING_PROTOCOLS;
    *switching.headers_mut() = response.headers().clone();
    *switching.extensions_mut() = std::mem::take(response.extensions_mut());
    shared.diag.emit(event("websocket_opened"));
    let shared = shared.clone();
    let record = record.clone();
    let resource = resource.to_string();
    let method = request.method.clone();
    tokio::spawn(async move {
        let (Ok(client_io), Ok(upstream_io)) = (upgrade.await, upstream_upgrade.await) else {
            return;
        };
        let event = |name: &'static str| proxy_event(conn, name).req(req).resource(&resource);
        let on_inject = || {
            let verdict = match shared.handler.classify(&record) {
                Flow::Intercept { .. } => shared
                    .handler
                    .authorize_message(&resource, &method)
                    .map_err(|denied| denied.reason),
                Flow::Deny { reason } => Err(reason),
                Flow::Passthrough => Err("no binding".to_string()),
            };
            let (decision, reason) = match verdict {
                Ok(()) => (Decision::Allow, None),
                Err(reason) => (Decision::Deny, Some(reason)),
            };
            audit(
                &shared,
                &record,
                decision,
                "websocket message",
                reason.as_deref(),
            )
            .is_ok()
                && decision == Decision::Allow
        };
        let ended = websocket::relay(
            TokioIo::new(client_io),
            TokioIo::new(upstream_io),
            injection,
            &on_inject,
        )
        .await;
        match ended {
            websocket::Ended::Closed => shared.diag.emit(event("websocket_closed")),
            websocket::Ended::Echoed | websocket::Ended::Withheld => {
                let (reason, result) = if ended == websocket::Ended::Echoed {
                    ("websocket echo", "echo")
                } else {
                    ("websocket withheld", "withheld")
                };
                let seq = audit(
                    &shared,
                    &record,
                    Decision::Deny,
                    "websocket message",
                    Some(reason),
                )
                .ok();
                shared.diag.emit(with_seq(
                    event("websocket_closed").warn().code("result", result),
                    seq,
                ));
            }
            websocket::Ended::Refused => shared
                .diag
                .emit(event("websocket_closed").warn().code("result", "refused")),
            websocket::Ended::Violation(_) => shared
                .diag
                .emit(event("websocket_closed").warn().code("result", "violation")),
        }
    });
    switching
}

pub(crate) fn outbound(
    request: &InjectedRequest,
    authority: &str,
    extensions: &hyper::http::Extensions,
) -> Result<Request<http_body_util::Full<bytes::Bytes>>, ProxyError> {
    http1::from_injected(
        InjectedRequest {
            method: request.method.clone(),
            path: request.path.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
        },
        authority,
        extensions.clone(),
    )
}

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl AsyncStream for TcpStream {}
impl AsyncStream for tokio_rustls::client::TlsStream<tokio::net::TcpStream> {}

pub(crate) async fn connect_upstream(
    host: &str,
    port: u16,
    tls: bool,
    upgrades: bool,
) -> Result<http1::Sender, ProxyError> {
    http1::client(upstream_io(host, port, tls).await?, upgrades).await
}

async fn upstream_io(host: &str, port: u16, tls: bool) -> Result<Box<dyn AsyncStream>, ProxyError> {
    let addr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or_else(|| {
            ProxyError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no address",
            ))
        })?;
    let tcp = TcpStream::connect(addr).await?;
    if tls {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ProxyError::Ca(crate::ca::CaError::Certificate(e.to_string())))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let server_name = LocalCa::server_name_for(host)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tls = connector.connect(server_name, tcp).await?;
        Ok(Box::new(tls) as Box<dyn AsyncStream>)
    } else {
        Ok(Box::new(tcp) as Box<dyn AsyncStream>)
    }
}

struct StaticResolver(Arc<CertifiedKey>);

impl std::fmt::Debug for StaticResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StaticResolver")
    }
}

impl rustls::server::ResolvesServerCert for StaticResolver {
    fn resolve(&self, _hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn server_config_negotiates_h2_client_down_to_http11() {
        let dir = tempfile::tempdir().unwrap();
        let ca = crate::ca::LocalCa::load_or_create(dir.path()).unwrap();
        let certified = ca.certified_key_for("api.stripe.com").unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(StaticResolver(certified)));
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        use rustls::pki_types::pem::PemObject;
        let der =
            rustls::pki_types::CertificateDer::from_pem_slice(ca.certificate_pem().as_bytes())
                .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(stream).await.unwrap();
            tls.get_ref().1.alpn_protocol().map(|p| p.to_vec())
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let name = crate::ca::LocalCa::server_name_for("api.stripe.com").unwrap();
        let tls = connector.connect(name, tcp).await.unwrap();
        let client_alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        let server_alpn = server.await.unwrap();

        assert_eq!(
            client_alpn.as_deref(),
            Some(&b"http/1.1"[..]),
            "an h2-offering client must be negotiated down to http/1.1"
        );
        assert_eq!(server_alpn.as_deref(), Some(&b"http/1.1"[..]));
    }

    #[test]
    fn connect_is_still_a_tunnel() {
        let target = parse_proxy_target("CONNECT", "api.sendgrid.com:443")
            .expect("CONNECT must remain supported");
        assert_eq!(
            target,
            ProxyTarget::Tunnel {
                host: "api.sendgrid.com".into(),
                port: 443
            }
        );
    }

    #[test]
    fn an_absolute_uri_request_names_its_origin() {
        let target = parse_proxy_target("GET", "https://api.sendgrid.com/v3/scopes")
            .expect("an absolute-URI request must be understood, not rejected");
        assert_eq!(
            target,
            ProxyTarget::Absolute {
                scheme: Scheme::Https,
                host: "api.sendgrid.com".into(),
                port: 443,
                path: "/v3/scopes".into(),
            }
        );
    }

    #[test]
    fn an_absolute_uri_carries_its_explicit_port_and_empty_path() {
        let target = parse_proxy_target("POST", "https://api.sendgrid.com:8443")
            .expect("an explicit port must be honoured");
        assert_eq!(
            target,
            ProxyTarget::Absolute {
                scheme: Scheme::Https,
                host: "api.sendgrid.com".into(),
                port: 8443,
                path: "/".into(),
            }
        );
    }

    #[test]
    fn a_cleartext_absolute_uri_defaults_to_port_80() {
        assert_eq!(
            parse_proxy_target("GET", "http://95.31.0.68/api/v1/download/x/1"),
            Some(ProxyTarget::Absolute {
                scheme: Scheme::Http,
                host: "95.31.0.68".into(),
                port: 80,
                path: "/api/v1/download/x/1".into(),
            })
        );
        assert_eq!(authority_for(Scheme::Http, "95.31.0.68", 80), "95.31.0.68");
        assert_eq!(
            authority_for(Scheme::Http, "95.31.0.68", 8080),
            "95.31.0.68:8080"
        );
    }

    #[test]
    fn an_origin_form_request_is_not_proxy_traffic() {
        assert!(
            parse_proxy_target("GET", "/v3/scopes").is_none(),
            "origin-form has no host, so the proxy cannot route it"
        );
    }

    #[test]
    fn userinfo_is_stripped_before_the_target_is_parsed() {
        match parse_proxy_target("GET", "https://user:pw@api.stripe.com:8443/v1/customers") {
            Some(ProxyTarget::Absolute {
                host, port, path, ..
            }) => {
                assert_eq!(host, "api.stripe.com");
                assert_eq!(port, 8443);
                assert_eq!(path, "/v1/customers");
            }
            other => panic!("{other:?}"),
        }
        match parse_proxy_target("CONNECT", "user:pw@api.stripe.com:443") {
            Some(ProxyTarget::Tunnel { host, port }) => {
                assert_eq!(host, "api.stripe.com");
                assert_eq!(port, 443);
            }
            other => panic!("{other:?}"),
        }
        assert!(parse_proxy_target("GET", "https://user:pw@/x").is_none());
        assert!(parse_proxy_target("CONNECT", "user:pw@").is_none());
    }

    #[test]
    fn only_http_and_https_absolute_uris_are_proxy_traffic() {
        for target in [
            "ftp://api.sendgrid.com/x",
            "ws://api.sendgrid.com/x",
            "HTTP://api.sendgrid.com/x",
            "//api.sendgrid.com/x",
        ] {
            assert!(parse_proxy_target("GET", target).is_none(), "{target}");
        }
    }

    #[test]
    fn userinfo_in_the_authority_withholds_the_destination_from_the_log() {
        for (method, target) in [
            ("GET", "https://user:pw@api.stripe.com:443/x"),
            ("GET", "https://token:x@api.stripe.com/x"),
            ("GET", "https://token@api.stripe.com"),
            ("CONNECT", "token:x@api.stripe.com"),
            ("CONNECT", "user:pw@api.stripe.com:443"),
        ] {
            assert!(holds_userinfo(method, target), "{method} {target}");
        }
        for (method, target) in [
            ("GET", "https://api.stripe.com/users/@me"),
            ("GET", "https://api.stripe.com:443/x?mail=a@b"),
            ("CONNECT", "api.stripe.com:443"),
        ] {
            assert!(!holds_userinfo(method, target), "{method} {target}");
        }
        let trace = Trace {
            conn: 1,
            req: 1,
            withheld: true,
        };
        let line = at_dest(proxy_event(1, "conn_accepted"), trace, "token", 443);
        let open = at_dest(
            proxy_event(1, "conn_accepted"),
            Trace {
                withheld: false,
                ..trace
            },
            "token",
            443,
        );
        assert_ne!(format!("{line:?}"), format!("{open:?}"));
        assert!(!format!("{line:?}").contains("token"));
    }

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_tunnel_request_must_name_the_connect_origin() {
        let names = |target: &str, values: &[(&str, &str)], host: &str, port: u16| {
            tunnel_request_names_origin(target, &headers(values), host, port)
        };
        assert!(names(
            "/x",
            &[("Host", "api.stripe.com")],
            "api.stripe.com",
            443
        ));
        assert!(names(
            "/x",
            &[("host", "API.Stripe.com:443")],
            "api.stripe.com",
            443
        ));
        assert!(names(
            "/x",
            &[("Host", "localhost:8443")],
            "localhost",
            8443
        ));
        assert!(names("/x", &[("Host", "[::1]:8443")], "[::1]", 8443));
        assert!(names("/x", &[("Host", "[::1]")], "[::1]", 443));
        assert!(!names("/x", &[], "api.stripe.com", 443));
        assert!(!names("/x", &[("Host", "")], "api.stripe.com", 443));
        assert!(!names(
            "/x",
            &[("Host", "api.stripe.com"), ("HOST", "api.stripe.com")],
            "api.stripe.com",
            443
        ));
        assert!(!names(
            "/x",
            &[("Host", "evil.example")],
            "api.stripe.com",
            443
        ));
        assert!(!names(
            "/x",
            &[("Host", "api.stripe.com.")],
            "api.stripe.com",
            443
        ));
        assert!(!names("/x", &[("Host", "localhost")], "localhost", 8443));
        assert!(!names(
            "/x",
            &[("Host", "api.stripe.com:")],
            "api.stripe.com",
            443
        ));
        assert!(!names(
            "/x",
            &[("Host", "api.stripe.com:8443")],
            "api.stripe.com",
            443
        ));
        assert!(!names(
            "*",
            &[("Host", "api.stripe.com")],
            "api.stripe.com",
            443
        ));
        assert!(!names(
            "https://evil.example/x",
            &[("Host", "api.stripe.com")],
            "api.stripe.com",
            443
        ));
    }

    #[test]
    fn an_origin_refusal_names_the_rule_that_fired() {
        let named = |target: &str, values: &[(&str, &str)]| {
            origin_refusal(target, &headers(values), "api.stripe.com", 443)
        };
        assert_eq!(named("/x", &[("Host", "api.stripe.com")]), None);
        assert_eq!(named("/x", &[]), Some(Refusal::HostMissing));
        assert_eq!(
            named(
                "/x",
                &[("Host", "api.stripe.com"), ("host", "api.stripe.com")]
            ),
            Some(Refusal::HostRepeated)
        );
        assert_eq!(
            named("/x", &[("Host", "evil.example")]),
            Some(Refusal::HostMismatch)
        );
        assert_eq!(
            named("*", &[("Host", "api.stripe.com")]),
            Some(Refusal::NotOriginForm)
        );
    }

    #[test]
    fn a_proxy_error_maps_to_a_fixed_code() {
        assert_eq!(
            bad_request("conflicting content-length").code(),
            "conflicting_length"
        );
        assert_eq!(
            bad_request("unparseable inner request").code(),
            "unparseable"
        );
        assert_eq!(bad_request("some other text").code(), "bad_request");
        assert_eq!(bad_request(UNSUPPORTED_FORM).code(), "unsupported_form");
        assert_eq!(
            ProxyError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut)).code(),
            "timed_out"
        );
    }

    #[tokio::test]
    async fn the_proxy_logs_each_request_decision_with_its_audit_record() {
        struct Scoped;
        impl FlowHandler for Scoped {
            fn classify(&self, _destination: &Destination) -> Flow {
                Flow::Intercept {
                    resource: "api.stripe.com".into(),
                    upstream_host: "127.0.0.1".into(),
                    upstream_port: 9,
                    upstream_tls: false,
                    scheme: Scheme::Https,
                    scope: PathScope::from_entries(Some(&["/oauth/token".to_string()][..]))
                        .unwrap(),
                }
            }
            fn subject(&self) -> String {
                "alice".into()
            }
            fn workload(&self) -> String {
                "w".into()
            }
            fn protocol_for(&self, _resource: &str) -> Option<Arc<dyn Protocol>> {
                None
            }
            fn materialize(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<zs_credential::Credential, zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
            fn authorize_message(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<(), zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
        }
        let home = tempfile::tempdir().unwrap();
        let log_path = home.path().join("diag.jsonl");
        let diag = zs_diag::DiagLog::open_with_cap(&log_path, "t-1", 1 << 20).unwrap();
        let server = ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(crate::ca::LocalCa::load_or_create(home.path().join("ca")).unwrap()),
            Arc::new(Scoped),
            Arc::new(Journal::open(home.path().join("audit.jsonl")).unwrap()),
        )
        .await
        .unwrap()
        .with_diag(diag.clone());
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move { server.serve().await });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET https://api.stripe.com/a/../oauth/token HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response)).await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 400"));
        tokio::time::sleep(Duration::from_millis(200)).await;
        diag.close();
        let log = std::fs::read_to_string(&log_path).unwrap();
        let events: Vec<serde_json::Value> = log
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let decided = events
            .iter()
            .find(|e| e["event"] == "request_decided")
            .expect("a request_decided event");
        assert_eq!(decided["fields"]["scope"], "refuse");
        assert_eq!(decided["fields"]["rule"], "dot_segment");
        assert_eq!(decided["fields"]["decision"], "deny");
        assert_eq!(decided["audit_seq"], 2);
        assert!(
            events
                .iter()
                .any(|e| e["event"] == "conn_accepted" && e["fields"]["form"] == "absolute")
        );
        assert!(
            events
                .iter()
                .any(|e| e["event"] == "classified" && e["audit_seq"] == 1)
        );
        assert!(!log.contains("/a/../oauth/token") && !log.contains("oauth/token"));
        let journal: Vec<serde_json::Value> =
            std::fs::read_to_string(home.path().join("audit.jsonl"))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
        assert_eq!(journal.len(), 2);
        assert!(journal[0].get("reason").is_none());
        assert_eq!(journal[1]["operation"], "GET");
        assert_eq!(journal[1]["decision"], "deny");
        assert_eq!(journal[1]["reason"], "dot_segment");
    }

    #[tokio::test]
    async fn a_connect_time_authorize_deny_records_connect_and_its_reason() {
        struct Refusing;
        impl Protocol for Refusing {
            fn matches(&self, _destination: &Destination) -> bool {
                true
            }
            fn authorize(&self, _context: &Context) -> Result<(), zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("workload has no grant"))
            }
            fn inject(
                &self,
                _request: &mut InjectedRequest,
                _credential: &zs_credential::Credential,
            ) -> Result<(), zs_protocol::Denied> {
                Ok(())
            }
        }
        struct Scoped;
        impl FlowHandler for Scoped {
            fn classify(&self, _destination: &Destination) -> Flow {
                Flow::Intercept {
                    resource: "api.stripe.com".into(),
                    upstream_host: "127.0.0.1".into(),
                    upstream_port: 9,
                    upstream_tls: false,
                    scheme: Scheme::Https,
                    scope: PathScope::Host,
                }
            }
            fn subject(&self) -> String {
                "alice".into()
            }
            fn workload(&self) -> String {
                "w".into()
            }
            fn protocol_for(&self, _resource: &str) -> Option<Arc<dyn Protocol>> {
                Some(Arc::new(Refusing))
            }
            fn materialize(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<zs_credential::Credential, zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
            fn authorize_message(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<(), zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
        }
        let home = tempfile::tempdir().unwrap();
        let server = ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(crate::ca::LocalCa::load_or_create(home.path().join("ca")).unwrap()),
            Arc::new(Scoped),
            Arc::new(Journal::open(home.path().join("audit.jsonl")).unwrap()),
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move { server.serve().await });
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response)).await;
        assert!(!response.starts_with(b"HTTP/1.1 200"));
        let journal: Vec<serde_json::Value> =
            std::fs::read_to_string(home.path().join("audit.jsonl"))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
        assert_eq!(journal.len(), 2);
        assert_eq!(journal[0]["decision"], "allow");
        assert_eq!(journal[0]["operation"], "connect");
        assert!(journal[0].get("reason").is_none());
        assert_eq!(journal[1]["decision"], "deny");
        assert_eq!(journal[1]["operation"], "connect");
        assert_eq!(journal[1]["reason"], "workload has no grant");
    }

    #[tokio::test]
    async fn a_tunneled_request_line_never_puts_its_path_in_the_log() {
        struct Allow;
        impl Protocol for Allow {
            fn matches(&self, _destination: &Destination) -> bool {
                true
            }
            fn authorize(&self, _context: &Context) -> Result<(), zs_protocol::Denied> {
                Ok(())
            }
            fn inject(
                &self,
                _request: &mut InjectedRequest,
                _credential: &zs_credential::Credential,
            ) -> Result<(), zs_protocol::Denied> {
                Ok(())
            }
        }
        struct Scoped;
        impl FlowHandler for Scoped {
            fn classify(&self, _destination: &Destination) -> Flow {
                Flow::Intercept {
                    resource: "api.stripe.com".into(),
                    upstream_host: "127.0.0.1".into(),
                    upstream_port: 9,
                    upstream_tls: false,
                    scheme: Scheme::Https,
                    scope: PathScope::from_entries(Some(&["/oauth/token".to_string()][..]))
                        .unwrap(),
                }
            }
            fn subject(&self) -> String {
                "alice".into()
            }
            fn workload(&self) -> String {
                "w".into()
            }
            fn protocol_for(&self, _resource: &str) -> Option<Arc<dyn Protocol>> {
                Some(Arc::new(Allow))
            }
            fn materialize(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<zs_credential::Credential, zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
            fn authorize_message(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<(), zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
        }
        let home = tempfile::tempdir().unwrap();
        let log_path = home.path().join("diag.jsonl");
        let diag = zs_diag::DiagLog::open_with_cap(&log_path, "t-2", 1 << 20).unwrap();
        let ca = Arc::new(crate::ca::LocalCa::load_or_create(home.path().join("ca")).unwrap());
        let server = ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            ca.clone(),
            Arc::new(Scoped),
            Arc::new(Journal::open(home.path().join("audit.jsonl")).unwrap()),
        )
        .await
        .unwrap()
        .with_diag(diag.clone());
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move { server.serve().await });

        use rustls::pki_types::pem::PemObject;
        let der =
            rustls::pki_types::CertificateDer::from_pem_slice(ca.certificate_pem().as_bytes())
                .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        for line in [
            "foo /v1/../oauth/cus_distinct777 HTTP/1.1",
            "GET /oauth/authenticate HTTP/1.1",
        ] {
            let mut tcp = TcpStream::connect(addr).await.unwrap();
            tcp.write_all(
                b"CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n",
            )
            .await
            .unwrap();
            let mut established = [0u8; 39];
            tcp.read_exact(&mut established).await.unwrap();
            assert!(established.starts_with(b"HTTP/1.1 200"));
            let name = crate::ca::LocalCa::server_name_for("api.stripe.com").unwrap();
            let mut tls = connector.connect(name, tcp).await.unwrap();
            tls.write_all(
                format!("{line}\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
            let mut response = Vec::new();
            let _ =
                tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut response)).await;
            assert!(!response.is_empty());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        diag.close();
        let log = std::fs::read_to_string(&log_path).unwrap();
        let events: Vec<serde_json::Value> = log
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert!(events.iter().any(|e| e["event"] == "request_decided"
            && e["fields"]["method"] == "nonstandard"
            && e["fields"]["scope"] == "refuse"));
        assert!(events.iter().any(|e| e["event"] == "request_decided"
            && e["fields"]["method"] == "GET"
            && e["fields"]["scope"] == "forward"));
        assert!(!log.contains("cus_distinct777") && !log.contains("/v1/"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_tunnel_framing_refusal_reaches_conn_closed() {
        struct Scoped;
        impl FlowHandler for Scoped {
            fn classify(&self, _destination: &Destination) -> Flow {
                Flow::Intercept {
                    resource: "scoped.test".into(),
                    upstream_host: "127.0.0.1".into(),
                    upstream_port: 9,
                    upstream_tls: false,
                    scheme: Scheme::Https,
                    scope: PathScope::from_entries(Some(&["/v1/customers".to_string()][..]))
                        .unwrap(),
                }
            }
            fn subject(&self) -> String {
                "alice".into()
            }
            fn workload(&self) -> String {
                "w".into()
            }
            fn protocol_for(&self, _resource: &str) -> Option<Arc<dyn Protocol>> {
                Some(Arc::new(Allow))
            }
            fn materialize(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<zs_credential::Credential, zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
            fn authorize_message(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<(), zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
        }
        let home = tempfile::tempdir().unwrap();
        let log_path = home.path().join("diag.jsonl");
        let diag = zs_diag::DiagLog::open_with_cap(&log_path, "t-conn", 1 << 20).unwrap();
        let ca = Arc::new(crate::ca::LocalCa::load_or_create(home.path().join("ca")).unwrap());
        let server = ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            ca.clone(),
            Arc::new(Scoped),
            Arc::new(Journal::open(home.path().join("audit.jsonl")).unwrap()),
        )
        .await
        .unwrap()
        .with_diag(diag.clone());
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move { server.serve().await });

        use rustls::pki_types::pem::PemObject;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"CONNECT scoped.test:443 HTTP/1.1\r\nHost: scoped.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut established = vec![0u8; 39];
        tcp.read_exact(&mut established).await.unwrap();
        assert!(established.starts_with(b"HTTP/1.1 200"));
        let der =
            rustls::pki_types::CertificateDer::from_pem_slice(ca.certificate_pem().as_bytes())
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
        let name = crate::ca::LocalCa::server_name_for("scoped.test").unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();
        tls.write_all(b"POST /v1/customers HTTP/1.1\r\nHost: scoped.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut response)).await;
        let text = String::from_utf8_lossy(&response).into_owned();
        assert!(text.starts_with("HTTP/1.1 400"), "{text}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        diag.close();
        let log = std::fs::read_to_string(&log_path).unwrap();
        let events: Vec<serde_json::Value> = log
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let closed = events
            .iter()
            .find(|event| event["event"] == "conn_closed")
            .expect("a conn_closed event");
        assert_eq!(closed["fields"]["result"], "error", "{log}");
        assert_eq!(
            closed["error"]["kind"], "unsupported_coding",
            "the tunnel's framing code must reach conn_closed: {log}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_hello_pipelined_behind_connect_completes_the_handshake() {
        struct Allow;
        impl Protocol for Allow {
            fn matches(&self, _destination: &Destination) -> bool {
                true
            }
            fn authorize(&self, _context: &Context) -> Result<(), zs_protocol::Denied> {
                Ok(())
            }
            fn inject(
                &self,
                _request: &mut InjectedRequest,
                _credential: &zs_credential::Credential,
            ) -> Result<(), zs_protocol::Denied> {
                Ok(())
            }
        }
        struct Pipelined;
        impl FlowHandler for Pipelined {
            fn classify(&self, _destination: &Destination) -> Flow {
                Flow::Intercept {
                    resource: "pipelined.test".into(),
                    upstream_host: "127.0.0.1".into(),
                    upstream_port: 9,
                    upstream_tls: false,
                    scheme: Scheme::Https,
                    scope: PathScope::Host,
                }
            }
            fn subject(&self) -> String {
                "alice".into()
            }
            fn workload(&self) -> String {
                "w".into()
            }
            fn protocol_for(&self, _resource: &str) -> Option<Arc<dyn Protocol>> {
                Some(Arc::new(Allow))
            }
            fn materialize(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<zs_credential::Credential, zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
            fn authorize_message(
                &self,
                _resource: &str,
                _operation: &str,
            ) -> Result<(), zs_protocol::Denied> {
                Err(zs_protocol::Denied::new("not in this test"))
            }
        }
        let home = tempfile::tempdir().unwrap();
        let ca = Arc::new(crate::ca::LocalCa::load_or_create(home.path().join("ca")).unwrap());
        let server = ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            ca.clone(),
            Arc::new(Pipelined),
            Arc::new(Journal::open(home.path().join("audit.jsonl")).unwrap()),
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move { server.serve().await });

        use rustls::pki_types::pem::PemObject;
        let der =
            rustls::pki_types::CertificateDer::from_pem_slice(ca.certificate_pem().as_bytes())
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
        let name = crate::ca::LocalCa::server_name_for("pipelined.test").unwrap();
        let mut connection = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut hello = Vec::new();
        connection.write_tls(&mut hello).unwrap();
        assert!(!hello.is_empty());

        let response = tokio::task::spawn_blocking(move || {
            use std::io::Read as _;
            let mut tcp = std::net::TcpStream::connect(addr).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut request =
                b"CONNECT pipelined.test:443 HTTP/1.1\r\nHost: pipelined.test:443\r\n\r\n".to_vec();
            request.extend_from_slice(&hello);
            tcp.write_all(&request).unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                tcp.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
            }
            assert!(head.starts_with(b"HTTP/1.1 200"), "{:?}", head);
            let mut stream = rustls::Stream::new(&mut connection, &mut tcp);
            stream
                .write_all(b"GET /v1/customers HTTP/1.1\r\nHost: pipelined.test\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut response = Vec::new();
            let _ = stream.read_to_end(&mut response);
            response
        })
        .await
        .unwrap();
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 "),
            "{response:?}"
        );
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum UpstreamMode {
        KeepAliveThenClose,
        HeadThenClose,
        DropSecondOnFirst,
    }

    struct ScriptedUpstream {
        port: u16,
        requests: Arc<std::sync::atomic::AtomicUsize>,
        connections: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn scripted_upstream(mode: UpstreamMode) -> ScriptedUpstream {
        use std::sync::atomic::AtomicUsize;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let requests_t = requests.clone();
        let connections_t = connections.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let index = connections_t.fetch_add(1, Ordering::SeqCst);
                let requests = requests_t.clone();
                tokio::spawn(async move {
                    let mut served = 0;
                    loop {
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        loop {
                            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                                return;
                            }
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") {
                                break;
                            }
                        }
                        let number = requests.fetch_add(1, Ordering::SeqCst) + 1;
                        served += 1;
                        match mode {
                            UpstreamMode::DropSecondOnFirst => {
                                if index == 0 && served == 2 {
                                    return;
                                }
                                let _ = stream
                                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                                    .await;
                            }
                            UpstreamMode::KeepAliveThenClose => {
                                let _ = stream
                                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                                    .await;
                                if number == 1 {
                                    return;
                                }
                            }
                            UpstreamMode::HeadThenClose => {
                                let _ = stream
                                    .write_all(
                                        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhalf!",
                                    )
                                    .await;
                                return;
                            }
                        }
                    }
                });
            }
        });
        ScriptedUpstream {
            port,
            requests,
            connections,
        }
    }

    struct Allow;

    impl Protocol for Allow {
        fn matches(&self, _destination: &Destination) -> bool {
            true
        }
        fn authorize(&self, _context: &Context) -> Result<(), zs_protocol::Denied> {
            Ok(())
        }
        fn inject(
            &self,
            _request: &mut InjectedRequest,
            _credential: &zs_credential::Credential,
        ) -> Result<(), zs_protocol::Denied> {
            Ok(())
        }
    }

    struct Forwarding(u16);

    impl FlowHandler for Forwarding {
        fn classify(&self, _destination: &Destination) -> Flow {
            Flow::Intercept {
                resource: "upstream.test".into(),
                upstream_host: "127.0.0.1".into(),
                upstream_port: self.0,
                upstream_tls: false,
                scheme: Scheme::Https,
                scope: PathScope::from_entries(Some(&["/other".to_string()][..])).unwrap(),
            }
        }
        fn subject(&self) -> String {
            "alice".into()
        }
        fn workload(&self) -> String {
            "w".into()
        }
        fn protocol_for(&self, _resource: &str) -> Option<Arc<dyn Protocol>> {
            Some(Arc::new(Allow))
        }
        fn materialize(
            &self,
            _resource: &str,
            _operation: &str,
        ) -> Result<zs_credential::Credential, zs_protocol::Denied> {
            Err(zs_protocol::Denied::new("not in this test"))
        }
        fn authorize_message(
            &self,
            _resource: &str,
            _operation: &str,
        ) -> Result<(), zs_protocol::Denied> {
            Err(zs_protocol::Denied::new("not in this test"))
        }
    }

    async fn forwarding_proxy(
        upstream_port: u16,
    ) -> (std::net::SocketAddr, Arc<crate::ca::LocalCa>) {
        let home = tempfile::tempdir().unwrap();
        let ca = Arc::new(crate::ca::LocalCa::load_or_create(home.path().join("ca")).unwrap());
        let server = ProxyServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            ca.clone(),
            Arc::new(Forwarding(upstream_port)),
            Arc::new(Journal::open(home.path().join("audit.jsonl")).unwrap()),
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move { server.serve().await });
        (addr, ca)
    }

    async fn tunnel_client(
        addr: std::net::SocketAddr,
        ca: &crate::ca::LocalCa,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        use rustls::pki_types::pem::PemObject;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"CONNECT upstream.test:443 HTTP/1.1\r\nHost: upstream.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut established = vec![0u8; 39];
        tcp.read_exact(&mut established).await.unwrap();
        assert!(established.starts_with(b"HTTP/1.1 200"), "{established:?}");
        let der =
            rustls::pki_types::CertificateDer::from_pem_slice(ca.certificate_pem().as_bytes())
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
        let name = crate::ca::LocalCa::server_name_for("upstream.test").unwrap();
        connector.connect(name, tcp).await.unwrap()
    }

    async fn exchange_tunnel(
        client: &mut tokio_rustls::client::TlsStream<TcpStream>,
        request: &[u8],
    ) -> String {
        client.write_all(request).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while client.read(&mut byte).await.unwrap_or(0) == 1 {
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        let length = head
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        let _ = client.read_exact(&mut body).await;
        format!("{head}{}", String::from_utf8_lossy(&body))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reused_upstream_that_closed_is_retried_once() {
        let upstream = scripted_upstream(UpstreamMode::KeepAliveThenClose).await;
        let (addr, ca) = forwarding_proxy(upstream.port).await;
        let mut client = tunnel_client(addr, &ca).await;
        let request = b"GET /v1/customers HTTP/1.1\r\nHost: upstream.test\r\n\r\n";
        let first = exchange_tunnel(&mut client, request).await;
        assert!(first.starts_with("HTTP/1.1 200"), "{first}");
        let second = exchange_tunnel(&mut client, request).await;
        assert!(second.starts_with("HTTP/1.1 200"), "{second}");
        assert!(
            second.ends_with("ok"),
            "the retried request must reach the upstream: {second}"
        );
        assert_eq!(upstream.requests.load(Ordering::SeqCst), 2);
        assert_eq!(upstream.connections.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_idempotent_request_lost_on_a_reused_upstream_is_retried_once() {
        let upstream = scripted_upstream(UpstreamMode::DropSecondOnFirst).await;
        let (addr, ca) = forwarding_proxy(upstream.port).await;
        let mut client = tunnel_client(addr, &ca).await;
        let request = b"GET /v1/customers HTTP/1.1\r\nHost: upstream.test\r\n\r\n";
        let first = exchange_tunnel(&mut client, request).await;
        assert!(first.starts_with("HTTP/1.1 200"), "{first}");
        let second = exchange_tunnel(&mut client, request).await;
        assert!(second.starts_with("HTTP/1.1 200"), "{second}");
        assert!(second.ends_with("ok"), "{second}");
        assert_eq!(upstream.requests.load(Ordering::SeqCst), 3);
        assert_eq!(upstream.connections.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_written_post_lost_on_a_reused_upstream_is_not_sent_again() {
        let upstream = scripted_upstream(UpstreamMode::DropSecondOnFirst).await;
        let (addr, ca) = forwarding_proxy(upstream.port).await;
        let mut client = tunnel_client(addr, &ca).await;
        let request =
            b"POST /v1/customers HTTP/1.1\r\nHost: upstream.test\r\nContent-Length: 0\r\n\r\n";
        let first = exchange_tunnel(&mut client, request).await;
        assert!(first.starts_with("HTTP/1.1 200"), "{first}");
        let second = exchange_tunnel(&mut client, request).await;
        assert_eq!(
            second.lines().next().unwrap_or(""),
            "HTTP/1.1 502 upstream unreachable",
            "{second}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(upstream.requests.load(Ordering::SeqCst), 2);
        assert_eq!(upstream.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_that_got_a_response_head_is_never_sent_twice() {
        let upstream = scripted_upstream(UpstreamMode::HeadThenClose).await;
        let (addr, ca) = forwarding_proxy(upstream.port).await;
        let mut client = tunnel_client(addr, &ca).await;
        let response = exchange_tunnel(
            &mut client,
            b"POST /v1/customers HTTP/1.1\r\nHost: upstream.test\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(upstream.requests.load(Ordering::SeqCst), 1);
        assert_eq!(upstream.connections.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_fresh_upstream_failure_answers_upstream_unreachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (addr, ca) = forwarding_proxy(port).await;
        let mut client = tunnel_client(addr, &ca).await;
        let response = exchange_tunnel(
            &mut client,
            b"GET /v1/customers HTTP/1.1\r\nHost: upstream.test\r\n\r\n",
        )
        .await;
        assert_eq!(
            response.lines().next().unwrap_or(""),
            "HTTP/1.1 502 upstream unreachable",
            "{response}"
        );
    }

    #[test]
    fn authority_omits_only_the_default_port() {
        let ProxyTarget::Absolute { host, port, .. } =
            parse_proxy_target("GET", "https://api.stripe.com:443/x").unwrap()
        else {
            panic!("absolute-form expected");
        };
        assert_eq!(authority(&host, port), "api.stripe.com");
        let ProxyTarget::Absolute { host, port, .. } =
            parse_proxy_target("GET", "https://api.stripe.com:8443/x").unwrap()
        else {
            panic!("absolute-form expected");
        };
        assert_eq!(authority(&host, port), "api.stripe.com:8443");
    }
}
