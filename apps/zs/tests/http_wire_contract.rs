#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{
    TempAgent, exchange, header_lines, kill_agent, open_tunnel, setup_agent, setup_agent_with,
};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const HOST: &str = "api.stripe.com";
const SECRET: &str = "sk_test_zsv_synthetic_value_9f27c4d1";

fn proxy_of(agent: &TempAgent) -> String {
    agent.agent.as_ref().unwrap().proxy_addr.clone()
}

fn ca_of(agent: &TempAgent) -> String {
    std::fs::read_to_string(&agent.agent.as_ref().unwrap().ca_path).unwrap()
}

async fn tunnel(agent: &TempAgent) -> tokio_rustls::client::TlsStream<TcpStream> {
    open_tunnel(&proxy_of(agent), &ca_of(agent), HOST, 443)
        .await
        .unwrap()
}

fn requests(agent: &TempAgent) -> usize {
    agent.upstream.requests.load(Ordering::SeqCst)
}

fn last_head(agent: &TempAgent) -> String {
    agent.upstream.last_head.lock().unwrap().clone()
}

async fn connect_line(agent: &TempAgent) -> (TcpStream, String) {
    let mut tcp = TcpStream::connect(proxy_of(agent)).await.unwrap();
    tcp.write_all(&common::authorized_for_proxy(
        &proxy_of(agent),
        format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes(),
    ))
    .await
    .unwrap();
    let head = read_head(&mut tcp).await;
    (tcp, head)
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while let Ok(Ok(1)) = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte)).await
    {
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&head).into_owned()
}

async fn read_line<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.ok()?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Some(line);
        }
    }
}

async fn read_chunked<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(line) = read_line(stream).await {
        let text = String::from_utf8_lossy(&line).into_owned();
        let size = usize::from_str_radix(text.trim().split(';').next().unwrap_or(""), 16).unwrap();
        if size == 0 {
            while let Some(trailer) = read_line(stream).await {
                if trailer == b"\r\n" {
                    break;
                }
            }
            break;
        }
        let start = body.len();
        body.resize(start + size, 0);
        stream.read_exact(&mut body[start..]).await.unwrap();
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await.unwrap();
        assert_eq!(&crlf, b"\r\n");
    }
    body
}

fn first_line(response: &str) -> &str {
    response.lines().next().unwrap_or("")
}

#[tokio::test(flavor = "multi_thread")]
async fn request_header_names_reach_the_upstream_in_their_case() {
    let mut agent = setup_agent(true, true);
    let mut tls = tunnel(&agent).await;
    let response = exchange(
        &mut tls,
        b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nX-Custom-B: 1\r\nx-custom-a: 2\r\nX-MiXeD-Case: 3\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "positive control: {response}"
    );
    let head = last_head(&agent);
    assert!(head.contains("\r\nX-Custom-B: 1\r\n"), "head: {head}");
    assert!(head.contains("\r\nx-custom-a: 2\r\n"), "head: {head}");
    assert!(head.contains("\r\nX-MiXeD-Case: 3\r\n"), "head: {head}");
    assert_eq!(
        header_lines(&head, "host"),
        vec![format!("Host: {HOST}")],
        "head: {head}"
    );
    let authorization = header_lines(&head, "authorization");
    assert_eq!(authorization.len(), 1, "head: {head}");
    assert!(
        authorization[0].contains(SECRET),
        "the credential must reach the upstream, got: {authorization:?}"
    );
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chunked_request_reaches_the_upstream_with_one_content_length() {
    let mut agent = setup_agent_with(true, true, &["POST"], None);
    let mut tls = tunnel(&agent).await;
    let response = exchange(
        &mut tls,
        b"POST /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "positive control: {response}"
    );
    assert_eq!(
        agent.upstream.last_body.lock().unwrap().clone(),
        b"hello".to_vec()
    );
    let head = last_head(&agent);
    let lengths = header_lines(&head, "content-length");
    assert_eq!(lengths.len(), 1, "head: {head}");
    assert_eq!(
        lengths[0].split_once(':').unwrap().1.trim(),
        "5",
        "head: {head}"
    );
    assert!(
        header_lines(&head, "transfer-encoding").is_empty(),
        "head: {head}"
    );
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn response_status_line_and_header_case_reach_the_client() {
    let mut agent = setup_agent(true, true);
    let mut tls = tunnel(&agent).await;
    let response = exchange(
        &mut tls,
        b"GET /zs-contract/case HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "response: {response}"
    );
    assert!(
        response.contains("\r\nX-Upstream-MiXeD: 1\r\n"),
        "response: {response}"
    );
    assert!(response.ends_with("ok"), "response: {response}");
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_64_mib_chunked_response_reaches_the_client_whole() {
    let mut agent = setup_agent(true, true);
    let mut tls = tunnel(&agent).await;
    tls.write_all(
        b"GET /zs-contract/big HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let started = Instant::now();
    let read = tokio::time::timeout(Duration::from_secs(30), async {
        let head = read_head(&mut tls).await;
        let body = read_chunked(&mut tls).await;
        (head, body)
    })
    .await
    .expect("the 64 MiB response did not arrive within 30 s");
    let (head, body) = read;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    assert_eq!(body.len(), 64 * 1024 * 1024);
    assert!(body.iter().all(|b| *b == b'z'));
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "took {:?}",
        started.elapsed()
    );
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn two_requests_in_one_tunnel_use_one_upstream_connection() {
    let mut agent = setup_agent(true, true);
    let mut tls = tunnel(&agent).await;
    let request = b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\n\r\n";
    let first = exchange(&mut tls, request).await;
    assert!(first.starts_with("HTTP/1.1 200"), "first: {first}");
    let second = exchange(&mut tls, request).await;
    assert!(second.starts_with("HTTP/1.1 200"), "second: {second}");
    assert_eq!(requests(&agent), 2);
    assert_eq!(agent.upstream.connections.load(Ordering::SeqCst), 1);
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_replies_keep_their_status_lines() {
    let mut denied = setup_agent(false, true);
    let response = common::raw_exchange(
        &proxy_of(&denied),
        format!(
            "GET https://{HOST}/v1/customers HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(first_line(&response), "HTTP/1.1 502 ZeroSecret denied");
    kill_agent(&mut denied);

    let mut scoped = setup_agent_with(true, true, &["GET"], Some(&["/v1/customers"]));
    let mut tls = tunnel(&scoped).await;
    let ambiguous = exchange(
        &mut tls,
        b"GET /v1/../v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        first_line(&ambiguous),
        "HTTP/1.1 400 ZeroSecret refused an ambiguous request"
    );
    let (_tcp, head) = connect_line(&scoped).await;
    assert_eq!(first_line(&head), "HTTP/1.1 200 Connection established");
    kill_agent(&mut scoped);
}

fn assert_refused_or_clean(label: &str, response: &str, agent: &TempAgent, before: usize) {
    let after = requests(agent);
    if response.starts_with("HTTP/1.1 2") {
        assert_eq!(after, before + 1, "{label}: {response}");
        let head = last_head(agent);
        for line in head.split_inclusive("\r\n").filter(|l| !l.is_empty()) {
            assert!(
                line.ends_with("\r\n"),
                "{label}: line without CRLF: {line:?}"
            );
        }
        assert!(
            header_lines(&head, "content-length").len() <= 1,
            "{label}: {head}"
        );
        assert!(
            header_lines(&head, "transfer-encoding").is_empty(),
            "{label}: {head}"
        );
    } else {
        assert_eq!(after, before, "{label}: reached the upstream: {response}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn framing_probes_never_reach_the_upstream_malformed() {
    let mut agent = setup_agent_with(true, true, &["GET", "POST"], None);
    let mut tls = tunnel(&agent).await;
    let control = exchange(
        &mut tls,
        b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        control.starts_with("HTTP/1.1 200"),
        "positive control: {control}"
    );
    assert_eq!(requests(&agent), 1);
    assert!(
        agent.upstream.saw_authorization.load(Ordering::SeqCst),
        "positive control must carry the credential"
    );
    drop(tls);

    let pad = "X-Pad: zzzzzzzzzzzzzzzzzzzzzzzzzzzz\r\n".repeat(2560);
    let probes: Vec<(&str, Vec<u8>, bool)> = vec![
        (
            "content-length with chunked",
            b"POST /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(),
            false,
        ),
        (
            "chunked with identity",
            b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n".to_vec(),
            false,
        ),
        (
            "gzip with chunked",
            b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n".to_vec(),
            true,
        ),
        (
            "obs-fold",
            b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nX-A: 1\r\n 2\r\n\r\n".to_vec(),
            false,
        ),
        (
            "space before the colon",
            b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n".to_vec(),
            false,
        ),
        (
            "head over the cap",
            format!("GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nX-A: 1\r\n{pad}").into_bytes(),
            false,
        ),
        (
            "raw space in the target",
            b"GET /a b HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n".to_vec(),
            false,
        ),
        (
            "raw fragment in the target",
            b"GET /v1/customers#x HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n".to_vec(),
            true,
        ),
    ];
    for (label, request, must_refuse) in probes {
        let mut tls = tunnel(&agent).await;
        let before = requests(&agent);
        let started = Instant::now();
        let response = exchange(&mut tls, &request).await;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{label}: the connection hung instead of answering"
        );
        if must_refuse {
            assert!(
                !response.starts_with("HTTP/1.1 2"),
                "{label}: forwarded: {response}"
            );
            assert_eq!(requests(&agent), before, "{label}: reached the upstream");
        } else {
            assert_refused_or_clean(label, &response, &agent, before);
        }
    }

    for (label, request) in [
        (
            "plaintext instead of a ClientHello",
            "GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\n\r\n",
        ),
        (
            "plaintext POST",
            "POST /admin HTTP/1.1\r\nHost: api.stripe.com\r\n\r\n",
        ),
    ] {
        let before = requests(&agent);
        let (mut tcp, head) = connect_line(&agent).await;
        assert_eq!(first_line(&head), "HTTP/1.1 200 Connection established");
        let _ = tcp.write_all(request.as_bytes()).await;
        let mut response = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut response)).await;
        assert!(
            !String::from_utf8_lossy(&response).starts_with("HTTP/1.1 2"),
            "{label}: {response:?}"
        );
        assert_eq!(requests(&agent), before, "{label} reached the upstream");
    }
    kill_agent(&mut agent);
}
