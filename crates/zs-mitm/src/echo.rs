// What an injected request's response must never carry back to the workload: the credential,
// raw and percent-encoded, and every header or query value that `inject` added or changed.
// Needle bytes are zeroized on drop, and the type has no `Debug`.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Frame, SizeHint};
use zeroize::{Zeroize, Zeroizing};
use zs_protocol::InjectedRequest;

use crate::http1::{Body, BodyError};

// Upstream messages that end with this many bytes of the credential's start are held.
pub(crate) const HOLD_PREFIX: usize = 8;

// An injected header or query value shorter than this is too common to refuse on.
const SHORTEST_INJECTED: usize = 8;

// Headers the agent sets on every injected request whose values carry no credential.
const NOT_NEEDLES: [&str; 2] = ["host", "accept-encoding"];

// `x-amz-*` values are dates, body hashes and checksums that the upstream may legitimately
// return, except the session token, which is a credential.
fn is_needle_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if NOT_NEEDLES.contains(&lower.as_str()) {
        return false;
    }
    !lower.starts_with("x-amz-") || lower == "x-amz-security-token"
}

// The parts of a request `inject` may change, taken before it runs.
pub(crate) struct RequestSnapshot {
    headers: Vec<(String, String)>,
    path: String,
}

impl RequestSnapshot {
    pub(crate) fn of(request: &InjectedRequest) -> Self {
        Self {
            headers: request.headers.clone(),
            path: request.path.clone(),
        }
    }
}

pub(crate) struct EchoNeedles {
    needles: Vec<Zeroizing<Vec<u8>>>,
}

impl EchoNeedles {
    pub(crate) fn from_injection(
        before: &RequestSnapshot,
        after: &InjectedRequest,
        secret: &[u8],
    ) -> Self {
        let mut echo = Self {
            needles: Vec::new(),
        };
        echo.push(Zeroizing::new(secret.to_vec()));
        echo.push(percent_encoded(secret, b"0123456789ABCDEF"));
        echo.push(percent_encoded(secret, b"0123456789abcdef"));
        for (name, value) in &after.headers {
            if !is_needle_header(name) || value.len() < SHORTEST_INJECTED {
                continue;
            }
            let unchanged = before
                .headers
                .iter()
                .any(|(was, prior)| was.eq_ignore_ascii_case(name) && prior == value);
            if !unchanged {
                echo.push(Zeroizing::new(value.as_bytes().to_vec()));
                if let Some(token) = scheme_token(value) {
                    echo.push(Zeroizing::new(token.as_bytes().to_vec()));
                }
            }
        }
        let prior = query_pairs(&before.path);
        for pair in query_pairs(&after.path) {
            if pair.1.len() >= SHORTEST_INJECTED && !prior.contains(&pair) {
                echo.push(Zeroizing::new(pair.1.as_bytes().to_vec()));
            }
        }
        echo
    }

    fn push(&mut self, needle: Zeroizing<Vec<u8>>) {
        if !needle.is_empty() && !self.needles.iter().any(|n| **n == *needle) {
            self.needles.push(needle);
        }
    }

    pub(crate) fn found_in(&self, bytes: &[u8]) -> bool {
        self.needles
            .iter()
            .any(|needle| contains(bytes, needle, |a, b| a == b))
    }

    // Header names arrive lowercased, so a name is matched without regard to ASCII case.
    pub(crate) fn found_in_head(&self, headers: &hyper::HeaderMap) -> bool {
        headers.iter().any(|(name, value)| {
            self.found_in(value.as_bytes())
                || self.needles.iter().any(|needle| {
                    contains(name.as_str().as_bytes(), needle, |a, b| {
                        a.eq_ignore_ascii_case(b)
                    })
                })
        })
    }

    // The headers and a non-standard reason phrase, which the relay would otherwise pass on.
    pub(crate) fn found_in_response_head<B>(&self, response: &hyper::Response<B>) -> bool {
        self.found_in_head(response.headers())
            || response
                .extensions()
                .get::<hyper::ext::ReasonPhrase>()
                .is_some_and(|phrase| self.found_in(phrase.as_bytes()))
    }

    // The longest end of `window` that is a start of some needle.
    fn started(&self, window: &[u8]) -> usize {
        self.needles
            .iter()
            .map(|needle| started_prefix(window, needle))
            .max()
            .unwrap_or(0)
    }
}

// `Basic …`, `Bearer …`: the token alone can come back without its scheme.
fn scheme_token(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (!scheme.is_empty()
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && token.len() >= SHORTEST_INJECTED)
        .then_some(token)
}

// A coded body cannot be scanned, so only an absent or `identity` coding is relayed.
pub(crate) fn encoded(headers: &hyper::HeaderMap) -> bool {
    headers
        .get_all(hyper::header::CONTENT_ENCODING)
        .iter()
        .any(|value| match value.to_str() {
            Ok(codings) => codings
                .split(',')
                .map(str::trim)
                .any(|coding| !coding.is_empty() && !coding.eq_ignore_ascii_case("identity")),
            Err(_) => true,
        })
}

#[derive(Debug)]
struct Echoed;

impl std::fmt::Display for Echoed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("response echo")
    }
}

impl std::error::Error for Echoed {}

type Polled = Poll<Option<Result<Frame<Bytes>, BodyError>>>;

// Holds back only an end that starts a needle, so a needle split across chunks is seen whole.
struct Guarded {
    inner: Body,
    needles: Arc<EchoNeedles>,
    held: Zeroizing<Vec<u8>>,
    trailers: Option<hyper::HeaderMap>,
    on_echo: Option<Box<dyn FnOnce() + Send + Sync>>,
    done: bool,
}

pub(crate) fn guarded(
    body: Body,
    needles: Arc<EchoNeedles>,
    on_echo: impl FnOnce() + Send + Sync + 'static,
) -> Body {
    Guarded {
        inner: body,
        needles,
        held: Zeroizing::new(Vec::new()),
        trailers: None,
        on_echo: Some(Box::new(on_echo)),
        done: false,
    }
    .boxed()
}

impl Guarded {
    fn echo(&mut self) -> Polled {
        self.done = true;
        self.held.zeroize();
        self.trailers = None;
        if let Some(on_echo) = self.on_echo.take() {
            on_echo();
        }
        Poll::Ready(Some(Err(Box::new(Echoed))))
    }

    fn release_tail(&mut self) -> Polled {
        self.done = true;
        if self.needles.started(&self.held) >= HOLD_PREFIX {
            return self.echo();
        }
        if self.held.is_empty() {
            return Poll::Ready(self.trailers.take().map(|t| Ok(Frame::trailers(t))));
        }
        let tail = Bytes::copy_from_slice(&self.held);
        self.held.zeroize();
        Poll::Ready(Some(Ok(Frame::data(tail))))
    }
}

impl hyper::body::Body for Guarded {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Polled {
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
            }
            let frame = match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                None => return this.release_tail(),
                Some(Err(error)) => {
                    this.done = true;
                    this.held.zeroize();
                    return Poll::Ready(Some(Err(error)));
                }
                Some(Ok(frame)) => frame,
            };
            match frame.into_data() {
                Ok(data) => {
                    this.held.extend_from_slice(&data);
                    if this.needles.found_in(&this.held) {
                        return this.echo();
                    }
                    let cut = this.held.len() - this.needles.started(&this.held);
                    if cut > 0 {
                        let released = Bytes::copy_from_slice(&this.held[..cut]);
                        this.held.drain(..cut);
                        return Poll::Ready(Some(Ok(Frame::data(released))));
                    }
                }
                Err(frame) => {
                    let Ok(trailers) = frame.into_trailers() else {
                        continue;
                    };
                    if this.needles.found_in_head(&trailers) {
                        return this.echo();
                    }
                    this.trailers = Some(trailers);
                    return this.release_tail();
                }
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn contains(haystack: &[u8], needle: &[u8], same: impl Fn(&[u8], &[u8]) -> bool) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| same(window, needle))
}

// RFC 3986 percent-encoding: unreserved characters are kept, every other byte is `%XX`.
fn percent_encoded(bytes: &[u8], digits: &[u8; 16]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() * 3));
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(&[
                b'%',
                digits[usize::from(b >> 4)],
                digits[usize::from(b & 0x0f)],
            ]);
        }
    }
    out
}

fn query_pairs(path: &str) -> Vec<(&str, &str)> {
    path.split_once('?')
        .map_or("", |(_, query)| query)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .collect()
}

// The length of the longest end of `window` that is a start of `needle`, shorter than `needle`.
pub(crate) fn started_prefix(window: &[u8], needle: &[u8]) -> usize {
    (1..needle.len().min(window.len() + 1))
        .rev()
        .find(|&n| window.ends_with(&needle[..n]))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn request(path: &str) -> InjectedRequest {
        InjectedRequest {
            method: "GET".into(),
            path: path.into(),
            headers: vec![("Accept".into(), "application/json".into())],
            body: Vec::new(),
        }
    }

    #[test]
    fn needles_cover_raw_percent_encoded_and_injected_values() {
        let before = request("/v1/customers?limit=10");
        let mut after = request("/v1/customers?limit=10&api_key=s3cret+value!");
        after.set_header("Authorization", "Basic dXNlcjpzM2NyZXQrdmFsdWUh");
        let needles =
            EchoNeedles::from_injection(&RequestSnapshot::of(&before), &after, b"s3cret+value!");
        assert!(needles.found_in(b"..s3cret+value!.."));
        assert!(needles.found_in(b"Location: /x?api_key=s3cret%2Bvalue%21"));
        assert!(needles.found_in(b"location: /x?api_key=s3cret%2bvalue%21"));
        assert!(needles.found_in(b"seen Basic dXNlcjpzM2NyZXQrdmFsdWUh"));
        assert!(!needles.found_in(b"an ordinary body"));
        assert!(!needles.found_in(b"application/json limit=10"));
    }

    #[test]
    fn an_injected_query_value_is_a_needle() {
        let before = request("/v1/customers");
        let after = request("/v1/customers?X-Amz-Signature=0123456789abcdef");
        let needles =
            EchoNeedles::from_injection(&RequestSnapshot::of(&before), &after, b"unrelated-secret");
        assert!(needles.found_in(b"/next?sig=0123456789abcdef"));
    }

    #[test]
    fn host_amz_date_and_short_values_are_not_needles() {
        let before = request("/v1/customers");
        let mut after = request("/v1/customers");
        let after_host = "api.stripe.example.com";
        after.set_header("Host", after_host);
        after.set_header("x-amz-date", "20261105T000000Z");
        after.set_header(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        after.set_header("Accept-Encoding", "identity");
        after.set_header("x-amz-checksum-crc32", "AAAAAA==");
        after.set_header("x-amz-security-token", "FwoGZXIvYXdzEJr-session-token");
        after.set_header("X-Short", "1234567");
        let needles = EchoNeedles::from_injection(
            &RequestSnapshot::of(&before),
            &after,
            b"long-enough-secret",
        );
        assert!(needles.found_in(b"long-enough-secret"));
        assert!(!needles.found_in(b"20261105T000000Z"));
        assert!(!needles.found_in(after_host.as_bytes()));
        assert!(
            !needles.found_in(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert!(!needles.found_in(b"identity"));
        assert!(!needles.found_in(b"AAAAAA=="));
        assert!(needles.found_in(b"FwoGZXIvYXdzEJr-session-token"));
        assert!(!needles.found_in(b"1234567"));
    }

    #[test]
    fn the_head_check_covers_names_and_values() {
        let before = request("/v1");
        let after = request("/v1");
        let needles =
            EchoNeedles::from_injection(&RequestSnapshot::of(&before), &after, b"sk_live_head_42");
        let mut quiet = hyper::HeaderMap::new();
        quiet.insert("content-type", "application/json".parse().unwrap());
        assert!(!needles.found_in_head(&quiet));
        let mut in_value = quiet.clone();
        in_value.insert("x-debug", "got sk_live_head_42".parse().unwrap());
        assert!(needles.found_in_head(&in_value));
        let mut in_name = quiet.clone();
        in_name.insert(
            hyper::header::HeaderName::from_bytes(b"x-sk_live_head_42").unwrap(),
            "1".parse().unwrap(),
        );
        assert!(needles.found_in_head(&in_name));
        assert_eq!(needles.started(b"xx sk_live_he"), "sk_live_he".len());
        assert_eq!(needles.started(b"xx sk_live_head_42 "), 0);
    }

    #[test]
    fn the_token_after_an_injected_scheme_is_a_needle() {
        let before = request("/v1");
        let mut after = request("/v1");
        after.set_header("Authorization", "Basic dXNlcjpzM2NyZXQrdmFsdWUh");
        after.set_header("X-Api-Auth", "Token short");
        let needles =
            EchoNeedles::from_injection(&RequestSnapshot::of(&before), &after, b"s3cret+value!");
        assert!(needles.found_in(b"{\"seen\":\"dXNlcjpzM2NyZXQrdmFsdWUh\"}"));
        assert!(needles.found_in(b"Token short"));
        assert!(!needles.found_in(b"short"));
        assert!(!needles.found_in(b"Basic"));
    }

    struct Chunks(std::collections::VecDeque<Frame<Bytes>>);

    impl hyper::body::Body for Chunks {
        type Data = Bytes;
        type Error = BodyError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
            Poll::Ready(self.get_mut().0.pop_front().map(Ok))
        }
    }

    fn frames(frames: Vec<Frame<Bytes>>) -> Body {
        Chunks(frames.into()).boxed()
    }

    fn chunks(parts: &[&[u8]]) -> Body {
        frames(
            parts
                .iter()
                .map(|part| Frame::data(Bytes::copy_from_slice(part)))
                .collect(),
        )
    }

    fn needles() -> Arc<EchoNeedles> {
        let before = request("/v1");
        Arc::new(EchoNeedles::from_injection(
            &RequestSnapshot::of(&before),
            &before,
            b"sk_test_ws_guard_value_7c2d",
        ))
    }

    async fn collect(body: Body) -> Result<Vec<u8>, BodyError> {
        body.collect().await.map(|c| c.to_bytes().to_vec())
    }

    #[tokio::test]
    async fn a_body_without_the_credential_passes_unchanged() {
        let out = collect(guarded(chunks(&[b"hello ", b"world"]), needles(), || {})).await;
        assert_eq!(out.unwrap(), b"hello world");
    }

    #[tokio::test]
    async fn a_credential_split_across_chunks_is_caught() {
        let fired = Arc::new(AtomicBool::new(false));
        let f = fired.clone();
        let out = collect(guarded(
            chunks(&[b"x sk_test_ws_gu", b"ard_value_7c2d y"]),
            needles(),
            move || f.store(true, Ordering::SeqCst),
        ))
        .await;
        assert!(out.is_err());
        assert!(fired.load(Ordering::SeqCst));
    }

    struct Fed(tokio::sync::mpsc::UnboundedReceiver<&'static [u8]>);

    impl hyper::body::Body for Fed {
        type Data = Bytes;
        type Error = BodyError;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
            self.get_mut()
                .0
                .poll_recv(cx)
                .map(|part| part.map(|p| Ok(Frame::data(Bytes::from_static(p)))))
        }
    }

    async fn next_data(body: &mut Body) -> Vec<u8> {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
            .await
            .expect("a frame must come out without waiting for the next chunk");
        frame.unwrap().unwrap().into_data().unwrap().to_vec()
    }

    #[tokio::test]
    async fn a_chunk_that_ends_in_no_needle_start_is_released_at_once() {
        let (feed, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut body = guarded(Fed(rx).boxed(), needles(), || {});
        feed.send(b"data: {\"token\":\"hi\"}\n\n").unwrap();
        assert_eq!(next_data(&mut body).await, b"data: {\"token\":\"hi\"}\n\n");
        feed.send(b"data: next\n\n").unwrap();
        assert_eq!(next_data(&mut body).await, b"data: next\n\n");
    }

    #[tokio::test]
    async fn only_a_needle_start_at_the_end_of_a_chunk_is_held() {
        let (feed, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut body = guarded(Fed(rx).boxed(), needles(), || {});
        feed.send(b"abc sk_test").unwrap();
        assert_eq!(next_data(&mut body).await, b"abc ");
        feed.send(b"!more").unwrap();
        assert_eq!(next_data(&mut body).await, b"sk_test!more");
        drop(feed);
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn a_held_prefix_at_end_of_stream_is_withheld() {
        let out = collect(guarded(chunks(&[b"tail sk_test_ws"]), needles(), || {})).await;
        assert!(out.is_err());
    }

    #[tokio::test]
    async fn a_short_prefix_at_end_of_stream_is_released() {
        let out = collect(guarded(chunks(&[b"tail ", b"sk_test"]), needles(), || {})).await;
        assert_eq!(out.unwrap(), b"tail sk_test");
    }

    #[tokio::test]
    async fn an_echo_fires_once_and_ends_the_data() {
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        let mut body = guarded(
            chunks(&[
                b"0123456789012345678901234567890123456789 ",
                b"sk_test_ws_guard_value_7c2d",
                b" after",
            ]),
            needles(),
            move || {
                f.fetch_add(1, Ordering::SeqCst);
            },
        );
        let mut released = Vec::new();
        let mut errors = 0;
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => released.extend_from_slice(frame.data_ref().unwrap()),
                Err(error) => {
                    assert_eq!(fired.load(Ordering::SeqCst), 1);
                    assert_eq!(error.to_string(), "response echo");
                    errors += 1;
                }
            }
        }
        assert_eq!(errors, 1);
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert!(!contains(&released, b"sk_test", |a, b| a == b));
        assert!(!contains(&released, b"after", |a, b| a == b));
    }

    #[tokio::test]
    async fn trailers_are_checked_and_follow_the_released_tail() {
        let mut quiet = hyper::HeaderMap::new();
        quiet.insert("x-checksum", "abc".parse().unwrap());
        let mut body = guarded(
            frames(vec![
                Frame::data(Bytes::from_static(b"payload")),
                Frame::trailers(quiet),
            ]),
            needles(),
            || {},
        );
        let first = body.frame().await.unwrap().unwrap();
        assert_eq!(first.data_ref().unwrap().as_ref(), b"payload");
        assert!(body.frame().await.unwrap().unwrap().is_trailers());
        assert!(body.frame().await.is_none());

        let fired = Arc::new(AtomicBool::new(false));
        let f = fired.clone();
        let mut loud = hyper::HeaderMap::new();
        loud.insert("x-debug", "sk_test_ws_guard_value_7c2d".parse().unwrap());
        let out = collect(guarded(
            frames(vec![
                Frame::data(Bytes::from_static(b"payload")),
                Frame::trailers(loud),
            ]),
            needles(),
            move || f.store(true, Ordering::SeqCst),
        ))
        .await;
        assert!(out.is_err());
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn only_an_identity_content_encoding_is_scannable() {
        let mut headers = hyper::HeaderMap::new();
        assert!(!encoded(&headers));
        headers.insert("content-encoding", "identity".parse().unwrap());
        assert!(!encoded(&headers));
        headers.insert("content-encoding", "gzip".parse().unwrap());
        assert!(encoded(&headers));
        headers.insert("content-encoding", "identity, br".parse().unwrap());
        assert!(encoded(&headers));
    }

    #[test]
    fn a_window_ending_in_a_needle_start_reports_its_length() {
        assert_eq!(started_prefix(b"xxsk_li", b"sk_live"), 5);
        assert_eq!(started_prefix(b"xxsk_live", b"sk_live"), 0);
        assert_eq!(started_prefix(b"abc", b"sk_live"), 0);
        assert_eq!(started_prefix(b"", b"sk_live"), 0);
    }
}
