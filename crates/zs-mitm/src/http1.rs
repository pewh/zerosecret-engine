use std::error::Error as StdError;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Body as _, Frame, Incoming, SizeHint};
use hyper::ext::ReasonPhrase;
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderName, HeaderValue, TRANSFER_ENCODING,
};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use zs_protocol::InjectedRequest;

use crate::proxy::ProxyError;

pub(crate) const MAX_HEAD: usize = 64 * 1024;
pub(crate) const MAX_BODY: usize = 32 * 1024 * 1024;
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) const HOP_BY_HOP: &[&str] = &[
    "Connection",
    "Proxy-Connection",
    "Keep-Alive",
    "Content-Length",
    "Transfer-Encoding",
];

pub(crate) type BodyError = Box<dyn StdError + Send + Sync>;
pub(crate) type Body = BoxBody<Bytes, BodyError>;

#[derive(Clone, Default)]
pub(crate) struct TargetGuard {
    seen: std::sync::Arc<std::sync::Mutex<Seen>>,
}

#[derive(Default)]
struct Seen {
    bad: Vec<u64>,
    poison: Option<u64>,
}

impl TargetGuard {
    pub(crate) fn bad_at(&self, index: u64) -> bool {
        let seen = match self.seen.lock() {
            Ok(seen) => seen,
            Err(poisoned) => poisoned.into_inner(),
        };
        seen.bad.contains(&index) || seen.poison.is_some_and(|poison| index >= poison)
    }

    fn record(&self, index: u64) {
        let mut seen = match self.seen.lock() {
            Ok(seen) => seen,
            Err(poisoned) => poisoned.into_inner(),
        };
        seen.bad.push(index);
    }

    fn poison(&self, index: u64) {
        let mut seen = match self.seen.lock() {
            Ok(seen) => seen,
            Err(poisoned) => poisoned.into_inner(),
        };
        seen.poison = Some(seen.poison.map_or(index, |poison| poison.min(index)));
    }
}

fn content_length(value: &[u8]) -> Option<u64> {
    let mut length = None;
    for part in value.split(|byte| *byte == b',') {
        let part = trim(part);
        let parsed: u64 = std::str::from_utf8(part).ok()?.parse().ok()?;
        match length {
            Some(previous) if previous != parsed => return None,
            Some(_) => {}
            None => length = Some(parsed),
        }
    }
    length
}

#[derive(Clone, Copy)]
enum Phase {
    RequestLine,
    Headers,
    Body(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkEnd(u8),
    Trailers,
}

pub(crate) struct Guarded<S> {
    inner: S,
    guard: TargetGuard,
    phase: Phase,
    line: Vec<u8>,
    length: u64,
    chunked: bool,
    seen: u64,
    disabled: bool,
}

impl<S> Guarded<S> {
    pub(crate) fn new(inner: S, guard: TargetGuard) -> Self {
        Self {
            inner,
            guard,
            phase: Phase::RequestLine,
            line: Vec::new(),
            length: 0,
            chunked: false,
            seen: 0,
            disabled: false,
        }
    }

    fn poison(&mut self) {
        self.guard.poison(self.seen);
        self.disabled = true;
    }

    fn scan(&mut self, bytes: &[u8]) {
        if self.disabled {
            return;
        }
        for &byte in bytes {
            if self.disabled {
                return;
            }
            match self.phase {
                Phase::Body(remaining) => {
                    self.phase = if remaining <= 1 {
                        Phase::RequestLine
                    } else {
                        Phase::Body(remaining - 1)
                    };
                }
                Phase::ChunkData(remaining) => {
                    self.phase = if remaining <= 1 {
                        Phase::ChunkEnd(2)
                    } else {
                        Phase::ChunkData(remaining - 1)
                    };
                }
                Phase::ChunkEnd(expected) => {
                    if !matches!((expected, byte), (2, b'\r') | (1, b'\n')) {
                        self.poison();
                        return;
                    }
                    self.phase = if expected == 1 {
                        Phase::ChunkSize
                    } else {
                        Phase::ChunkEnd(1)
                    };
                }
                Phase::RequestLine | Phase::Headers | Phase::ChunkSize | Phase::Trailers => {
                    if byte == b'\n' {
                        let line = std::mem::take(&mut self.line);
                        self.line_done(&line);
                    } else if self.line.len() < MAX_HEAD {
                        self.line.push(byte);
                    } else {
                        self.line.clear();
                    }
                }
            }
        }
    }

    fn line_done(&mut self, raw: &[u8]) {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        match self.phase {
            Phase::RequestLine => {
                if line.is_empty() {
                    return;
                }
                let index = self.seen;
                self.seen += 1;
                let mut parts = line.split(|byte| *byte == b' ');
                let method = parts.next().unwrap_or_default();
                let target = parts.next().unwrap_or_default();
                if target.contains(&b'#') {
                    self.guard.record(index);
                }
                if method.eq_ignore_ascii_case(b"CONNECT") {
                    self.disabled = true;
                }
                self.length = 0;
                self.chunked = false;
                self.phase = Phase::Headers;
            }
            Phase::Headers => {
                if line.is_empty() {
                    self.phase = if self.chunked {
                        Phase::ChunkSize
                    } else if self.length > 0 {
                        Phase::Body(self.length)
                    } else {
                        Phase::RequestLine
                    };
                    return;
                }
                let Some(at) = line.iter().position(|byte| *byte == b':') else {
                    return;
                };
                let (name, value) = (&line[..at], &line[at + 1..]);
                let value = trim(value);
                if name.eq_ignore_ascii_case(b"content-length") {
                    match content_length(value) {
                        Some(length) => self.length = length,
                        None => {
                            self.poison();
                            return;
                        }
                    }
                }
                if name.eq_ignore_ascii_case(b"transfer-encoding")
                    && value.to_ascii_lowercase().ends_with(b"chunked")
                {
                    self.chunked = true;
                }
            }
            Phase::ChunkSize => {
                let size = line.split(|byte| *byte == b';').next().unwrap_or_default();
                let size = trim(size);
                let Some(size) = std::str::from_utf8(size)
                    .ok()
                    .and_then(|text| u64::from_str_radix(text, 16).ok())
                else {
                    self.poison();
                    return;
                };
                self.phase = if size == 0 {
                    Phase::Trailers
                } else {
                    Phase::ChunkData(size)
                };
            }
            Phase::Trailers => {
                if line.is_empty() {
                    self.phase = Phase::RequestLine;
                }
            }
            Phase::Body(_) | Phase::ChunkData(_) | Phase::ChunkEnd(_) => {}
        }
    }
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |at| at + 1);
    &bytes[start..end]
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &polled {
            this.scan(&buf.filled()[before..]);
        }
        polled
    }
}

pub(crate) type Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

pub(crate) fn server() -> hyper::server::conn::http1::Builder {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_HEAD)
        .auto_date_header(false)
        .preserve_header_case(true)
        .title_case_headers(true);
    builder
}

pub(crate) async fn client<S>(io: S, upgrades: bool) -> Result<Sender, ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = hyper::client::conn::http1::Builder::new();
    builder
        .max_buf_size(MAX_HEAD)
        .preserve_header_case(true)
        .title_case_headers(true);
    let (sender, connection) = builder.handshake(TokioIo::new(io)).await?;
    if upgrades {
        tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
    } else {
        tokio::spawn(async move {
            let _ = connection.await;
        });
    }
    Ok(sender)
}

pub(crate) enum Reply {
    Denied,
    AuditUnavailable,
    UpstreamUnreachable,
    Refused,
    Established,
    DeniedBecause(String),
}

pub(crate) fn reply(kind: Reply) -> Response<Body> {
    let (status, phrase, closes) = match kind {
        Reply::Denied => (
            StatusCode::BAD_GATEWAY,
            ReasonPhrase::from_static(b"ZeroSecret denied"),
            true,
        ),
        Reply::AuditUnavailable => (
            StatusCode::BAD_GATEWAY,
            ReasonPhrase::from_static(b"audit unavailable"),
            true,
        ),
        Reply::UpstreamUnreachable => (
            StatusCode::BAD_GATEWAY,
            ReasonPhrase::from_static(b"upstream unreachable"),
            true,
        ),
        Reply::Refused => (
            StatusCode::BAD_REQUEST,
            ReasonPhrase::from_static(b"ZeroSecret refused an ambiguous request"),
            true,
        ),
        Reply::Established => (
            StatusCode::OK,
            ReasonPhrase::from_static(b"Connection established"),
            false,
        ),
        Reply::DeniedBecause(reason) => match ReasonPhrase::try_from(reason) {
            Ok(phrase) if !phrase.as_bytes().is_empty() => (StatusCode::BAD_GATEWAY, phrase, true),
            _ => (
                StatusCode::BAD_GATEWAY,
                ReasonPhrase::from_static(b"ZeroSecret denied"),
                true,
            ),
        },
    };
    let mut response = Response::new(fixed_body(Bytes::new()));
    *response.status_mut() = status;
    response.extensions_mut().insert(phrase);
    if closes {
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

pub(crate) fn empty_body() -> Body {
    fixed_body(Bytes::new())
}

pub(crate) fn boxed(body: Incoming) -> Body {
    body.map_err(BodyError::from).boxed()
}

pub(crate) fn counted(
    response: Response<Body>,
    finish: impl FnOnce(u64) + Send + Sync + 'static,
) -> Response<Body> {
    response.map(|body| Relayed::new(body, finish).boxed())
}

pub(crate) fn text_response(body: String) -> Response<Body> {
    let mut response = Response::new(fixed_body(Bytes::from(body)));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

fn fixed_body(bytes: Bytes) -> Body {
    Full::new(bytes)
        .map_err(|never: std::convert::Infallible| -> BodyError { match never {} })
        .boxed()
}

pub(crate) enum Framing {
    UnsupportedCoding,
    BodyTooLarge,
    Read(Box<dyn StdError + Send + Sync>),
}

impl Framing {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Framing::UnsupportedCoding => "unsupported_coding",
            Framing::BodyTooLarge => "body_too_large",
            Framing::Read(error) => match error.downcast_ref::<hyper::Error>() {
                Some(error) if error.is_parse_too_large() => "invalid_data",
                _ => "unparseable",
            },
        }
    }
}

pub(crate) async fn into_injected(
    request: Request<Incoming>,
) -> Result<(InjectedRequest, hyper::http::Extensions), Framing> {
    let (parts, body) = request.into_parts();
    let mut codings = parts.headers.get_all(TRANSFER_ENCODING).iter();
    if let Some(coding) = codings.next()
        && (codings.next().is_some() || !coding.as_bytes().eq_ignore_ascii_case(b"chunked"))
    {
        return Err(Framing::UnsupportedCoding);
    }
    if body
        .size_hint()
        .exact()
        .is_some_and(|exact| exact > MAX_BODY as u64)
    {
        return Err(Framing::BodyTooLarge);
    }
    let collected = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|error| match error.downcast::<hyper::Error>() {
            Ok(error) => Framing::Read(Box::new(*error)),
            Err(error) => {
                if error.is::<LengthLimitError>() {
                    Framing::BodyTooLarge
                } else {
                    Framing::Read(error)
                }
            }
        })?;
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    let path = if parts.uri.scheme().is_some() || parts.uri.authority().is_some() {
        parts.uri.to_string()
    } else {
        parts
            .uri
            .path_and_query()
            .map(|target| target.as_str().to_string())
            .unwrap_or_else(|| "/".to_string())
    };
    let injected = InjectedRequest {
        method: parts.method.as_str().to_string(),
        path,
        headers,
        body: collected.to_bytes().to_vec(),
    };
    Ok((injected, parts.extensions))
}

pub(crate) fn from_injected(
    request: InjectedRequest,
    authority: &str,
    extensions: hyper::http::Extensions,
) -> Result<Request<Full<Bytes>>, ProxyError> {
    let mut out = Request::new(Full::new(Bytes::from(request.body)));
    *out.method_mut() = Method::from_bytes(request.method.as_bytes())
        .map_err(|_| ProxyError::BadRequest("unparseable request".into()))?;
    *out.uri_mut() = request
        .path
        .parse()
        .map_err(|_| ProxyError::BadRequest("unparseable request".into()))?;
    out.headers_mut().insert(
        HOST,
        HeaderValue::from_str(authority)
            .map_err(|_| ProxyError::BadRequest("unparseable request".into()))?,
    );
    for (name, value) in request.headers {
        if name.eq_ignore_ascii_case("host")
            || HOP_BY_HOP.iter().any(|hop| name.eq_ignore_ascii_case(hop))
        {
            continue;
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ProxyError::BadRequest("unparseable request".into()))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|_| ProxyError::BadRequest("unparseable request".into()))?;
        out.headers_mut().append(name, value);
    }
    *out.extensions_mut() = extensions;
    Ok(out)
}

pub(crate) struct Relayed<B> {
    inner: B,
    bytes: u64,
    finish: Option<Box<dyn FnOnce(u64) + Send + Sync>>,
}

impl<B> Relayed<B> {
    pub(crate) fn new(inner: B, finish: impl FnOnce(u64) + Send + Sync + 'static) -> Self {
        Self {
            inner,
            bytes: 0,
            finish: Some(Box::new(finish)),
        }
    }
}

impl<B> Drop for Relayed<B> {
    fn drop(&mut self) {
        if let Some(finish) = self.finish.take() {
            finish(self.bytes);
        }
    }
}

impl<B> hyper::body::Body for Relayed<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(None) => {
                if let Some(finish) = this.finish.take() {
                    finish(this.bytes);
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.len() as u64;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    #[tokio::test(start_paused = true)]
    async fn a_stalled_request_head_is_closed() {
        let (io, mut client) = tokio::io::duplex(1 << 16);
        let served = tokio::spawn(server().serve_connection(
            TokioIo::new(io),
            hyper::service::service_fn(|_request: Request<Incoming>| async {
                Ok::<_, Infallible>(Response::new(empty_body()))
            }),
        ));
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
            .await
            .unwrap();
        assert!(read_head(&mut client).await.starts_with("HTTP/1.1 200"));
        client.write_all(b"GET / HTTP/1.1\r\nHo").await.unwrap();
        let started = tokio::time::Instant::now();
        let closed = tokio::time::timeout(HEADER_READ_TIMEOUT * 2, served)
            .await
            .expect("a stalled head must close the connection");
        assert!(closed.unwrap().is_err());
        assert!(started.elapsed() >= HEADER_READ_TIMEOUT);
    }

    async fn read_head(stream: &mut DuplexStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                break;
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    async fn read_reply(stream: &mut DuplexStream) -> String {
        let mut out = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buffer)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    out.extend_from_slice(&buffer[..n]);
                    if out.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                _ => break,
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    type Captured =
        Arc<Mutex<Option<Result<(InjectedRequest, hyper::http::Extensions), &'static str>>>>;

    async fn injected_from(request_bytes: &[u8]) -> (Captured, String) {
        let (mut peer, io) = tokio::io::duplex(64 * 1024);
        let captured: Captured = Arc::new(Mutex::new(None));
        let slot = captured.clone();
        let service = hyper::service::service_fn(move |request: Request<Incoming>| {
            let slot = slot.clone();
            async move {
                let outcome = into_injected(request).await;
                *slot.lock().unwrap() = Some(match outcome {
                    Ok(pair) => Ok(pair),
                    Err(framing) => Err(framing.code()),
                });
                Ok::<_, Infallible>(reply(Reply::Refused))
            }
        });
        tokio::spawn(server().serve_connection(TokioIo::new(io), service));
        peer.write_all(request_bytes).await.unwrap();
        let reply_head = read_reply(&mut peer).await;
        (captured, reply_head)
    }

    #[tokio::test]
    async fn a_request_becomes_injected_with_its_body_and_header_case() {
        let (captured, _) = injected_from(
            b"POST /p?q=1 HTTP/1.1\r\nHost: h\r\nX-MiXeD: 1\r\nContent-Length: 2\r\n\r\nab",
        )
        .await;
        let (injected, extensions) = captured
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .expect("an injected request");
        assert_eq!(injected.method, "POST");
        assert_eq!(injected.path, "/p?q=1");
        assert_eq!(injected.body, b"ab");
        assert!(
            injected
                .headers
                .iter()
                .any(|(name, value)| name.eq_ignore_ascii_case("x-mixed") && value == "1")
        );

        let outbound = from_injected(injected, "h", extensions).unwrap();
        let (mut peer, io) = tokio::io::duplex(64 * 1024);
        let reader = tokio::spawn(async move {
            let head = read_head(&mut peer).await;
            peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            head
        });
        let mut sender = client(io, false).await.unwrap();
        sender.send_request(outbound).await.unwrap();
        let head = reader.await.unwrap();
        assert!(head.starts_with("POST /p?q=1 HTTP/1.1\r\n"), "{head}");
        assert_eq!(
            head.lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("host:"))
                .collect::<Vec<_>>(),
            vec!["Host: h"],
            "{head}"
        );
        assert!(head.contains("\r\nX-MiXeD: 1\r\n"), "{head}");
        assert!(
            head.contains("\r\ncontent-length: 2\r\n")
                || head.contains("\r\nContent-Length: 2\r\n"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn a_coding_other_than_chunked_is_refused() {
        let (captured, head) = injected_from(
            b"POST /p HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        )
        .await;
        assert_eq!(
            captured.lock().unwrap().take().unwrap().err(),
            Some("unsupported_coding")
        );
        assert!(!head.starts_with("HTTP/1.1 2"), "{head}");
    }

    #[tokio::test]
    async fn a_body_over_the_cap_is_refused() {
        let (captured, _) =
            injected_from(b"POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 33554433\r\n\r\n").await;
        assert_eq!(
            captured.lock().unwrap().take().unwrap().err(),
            Some("body_too_large")
        );
    }

    async fn reply_head(
        request: &'static [u8],
        make: impl Fn() -> Reply + Send + Sync + 'static,
    ) -> String {
        let (mut peer, io) = tokio::io::duplex(8192);
        let service = hyper::service::service_fn(move |_request: Request<Incoming>| {
            let response = reply(make());
            async move { Ok::<_, Infallible>(response) }
        });
        tokio::spawn(server().serve_connection(TokioIo::new(io), service));
        peer.write_all(request).await.unwrap();
        read_reply(&mut peer).await
    }

    const GET: &[u8] = b"GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n";
    const CONNECT: &[u8] = b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n";

    fn guard_of(script: &[u8]) -> TargetGuard {
        let guard = TargetGuard::default();
        let mut guarded = Guarded::new((), guard.clone());
        guarded.scan(script);
        guard
    }

    #[test]
    fn a_fragment_in_a_request_line_is_recorded() {
        let guard = guard_of(b"GET /oauth/token#x HTTP/1.1\r\nHost: h\r\n\r\n");
        assert!(guard.bad_at(0));
        assert!(!guard.bad_at(1));
    }

    #[test]
    fn a_fragment_in_a_second_request_is_recorded_at_its_own_index() {
        let script = concat!(
            "GET /a HTTP/1.1\r\nHost: h\r\n\r\n",
            "GET /b#x HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        let guard = guard_of(script.as_bytes());
        assert!(!guard.bad_at(0));
        assert!(guard.bad_at(1));
    }

    #[test]
    fn a_body_that_looks_like_a_request_line_is_not_a_target() {
        let script = concat!(
            "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 32\r\n\r\n",
            "GET /b#x HTTP/1.1\r\nHost: h\r\n\r\n",
            "xx",
        );
        let guard = guard_of(script.as_bytes());
        assert!(!guard.bad_at(0));
        assert!(!guard.bad_at(1), "the body must be skipped by its length");
        let after = guard_of(
            concat!(
                "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 32\r\n\r\n",
                "GET /b#x HTTP/1.1\r\nHost: h\r\n\r\n",
                "xx",
                "GET /c#y HTTP/1.1\r\nHost: h\r\n\r\n",
            )
            .as_bytes(),
        );
        assert!(
            after.bad_at(1),
            "the request after the body keeps its index"
        );
    }

    #[test]
    fn a_chunked_body_is_skipped() {
        let script = concat!(
            "POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            "5\r\nGET /\r\n",
            "0\r\n\r\n",
            "GET /c#y HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        let guard = guard_of(script.as_bytes());
        assert!(!guard.bad_at(0));
        assert!(guard.bad_at(1), "a fragment after a chunked body is seen");
    }

    #[test]
    fn a_multi_chunk_body_keeps_the_index_in_step() {
        let script = concat!(
            "POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
            "1\r\nx\r\n",
            "5\r\n\r\nX\r\n\r\n",
            "0\r\n\r\n",
            "GET /b#z HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        let guard = guard_of(script.as_bytes());
        assert!(!guard.bad_at(0), "the body is not a request");
        assert!(
            guard.bad_at(1),
            "the request after two chunks must keep its own index"
        );
    }

    #[test]
    fn a_content_length_list_is_accepted_when_every_value_agrees() {
        let script = concat!(
            "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 2, 2\r\n\r\n",
            "x\n",
            "GET /b#z HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        let guard = guard_of(script.as_bytes());
        assert!(!guard.bad_at(0));
        assert!(guard.bad_at(1));
    }

    #[test]
    fn an_unparseable_framing_poisons_every_later_request() {
        let script = concat!(
            "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: two\r\n\r\n",
            "GET /b HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        let guard = guard_of(script.as_bytes());
        assert!(
            guard.bad_at(1),
            "after a lost parse every later request is refused"
        );
    }

    #[test]
    fn an_upgrade_header_does_not_stop_the_scan() {
        let script = concat!(
            "GET /a HTTP/1.1\r\nHost: h\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
            "GET /b#z HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        let guard = guard_of(script.as_bytes());
        assert!(!guard.bad_at(0));
        assert!(
            guard.bad_at(1),
            "a connection that stays HTTP/1 must keep the guard"
        );
    }

    #[test]
    fn a_connect_request_stops_the_scan() {
        let script = concat!(
            "CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n",
            "\x16\x03\x01#\x00\x00#",
            "GET /c#y HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        let guard = guard_of(script.as_bytes());
        assert!(!guard.bad_at(0));
        assert!(!guard.bad_at(1));
    }

    #[tokio::test]
    async fn each_reply_writes_its_exact_status_line() {
        let cases: Vec<(&'static str, String)> = vec![
            (
                "HTTP/1.1 502 ZeroSecret denied",
                reply_head(GET, || Reply::Denied).await,
            ),
            (
                "HTTP/1.1 502 audit unavailable",
                reply_head(GET, || Reply::AuditUnavailable).await,
            ),
            (
                "HTTP/1.1 502 upstream unreachable",
                reply_head(GET, || Reply::UpstreamUnreachable).await,
            ),
            (
                "HTTP/1.1 400 ZeroSecret refused an ambiguous request",
                reply_head(GET, || Reply::Refused).await,
            ),
            (
                "HTTP/1.1 200 Connection established",
                reply_head(CONNECT, || Reply::Established).await,
            ),
            (
                "HTTP/1.1 502 workload has no grant",
                reply_head(GET, || Reply::DeniedBecause("workload has no grant".into())).await,
            ),
            (
                "HTTP/1.1 502 ZeroSecret denied",
                reply_head(GET, || Reply::DeniedBecause("bad\nreason".into())).await,
            ),
        ];
        for (expected, head) in cases {
            assert_eq!(head.lines().next().unwrap_or(""), expected, "{head}");
            if !expected.starts_with("HTTP/1.1 2") {
                assert!(head.contains("Content-Length: 0\r\n"), "{head}");
                assert!(head.contains("Connection: close\r\n"), "{head}");
            }
        }
    }
}
