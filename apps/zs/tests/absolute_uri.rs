#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{kill_agent, setup_agent};
use std::io::{BufRead, BufReader, Read, Write};

fn absolute_uri_request(proxy: &str, url: &str, host: &str) -> (String, String) {
    let mut stream = std::net::TcpStream::connect(proxy).unwrap();
    stream
        .write_all(&common::authorized_for_proxy(
            proxy,
            format!(
                "GET {url} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        ))
        .unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);
    let mut status = String::new();
    reader.read_line(&mut status).unwrap();
    let mut rest = String::new();
    reader.read_to_string(&mut rest).unwrap();
    (status, rest)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_absolute_uri_request_is_intercepted_and_gets_the_credential() {
    let mut agent = setup_agent(true, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let (status, body) = absolute_uri_request(
        &proxy,
        "https://api.stripe.com/v1/customers?limit=1",
        "api.stripe.com",
    );
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected success, got: {status}"
    );
    assert!(body.contains("cus_zs_probe_1"), "body: {body}");
    assert_eq!(
        agent
            .upstream
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let auth = agent.upstream.last_auth.lock().unwrap().clone();
    assert!(
        auth.contains("sk_test_zsv_synthetic_value_9f27c4d1"),
        "the credential must be injected on the absolute-URI path too, got: {auth}"
    );
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_absolute_uri_request_without_a_grant_is_denied() {
    let mut agent = setup_agent(false, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let (status, _) = absolute_uri_request(
        &proxy,
        "https://api.stripe.com/v1/customers",
        "api.stripe.com",
    );
    assert!(status.contains("502"), "expected denial, got: {status}");
    assert_eq!(
        agent
            .upstream
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a denied absolute-URI request must not reach upstream"
    );
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_intercepted_absolute_uri_that_cannot_be_injected_is_not_forwarded() {
    let mut agent = setup_agent(true, false);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let (status, _) = absolute_uri_request(
        &proxy,
        "https://api.stripe.com/v1/customers",
        "api.stripe.com",
    );
    assert!(status.contains("502"), "expected denial, got: {status}");
    assert_eq!(
        agent
            .upstream
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a request that could not be injected must never reach upstream"
    );
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_test_child_reports_the_run_token() {
    let mut agent = setup_agent(true, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let token = agent.agent.as_ref().unwrap().proxy_authorization.clone();
    assert!(
        !token.is_empty(),
        "the test child must report the run token through the env file"
    );
    let ca = std::fs::read_to_string(&agent.agent.as_ref().unwrap().ca_path).unwrap();

    let mut tls = common::open_tunnel_with(&proxy, &token, &ca, "api.stripe.com", 443)
        .await
        .expect("the captured token must open a tunnel");
    let response = common::exchange(
        &mut tls,
        b"GET /v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let seen = agent
        .upstream
        .requests
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(seen, 1, "the tunnel must reach the fake upstream");

    let Err(refused) = common::open_tunnel_with(&proxy, "", &ca, "api.stripe.com", 443).await
    else {
        panic!("a CONNECT without the token must be refused");
    };
    assert!(
        refused.starts_with("HTTP/1.1 407"),
        "expected 407 without the token, got: {refused}"
    );
    assert_eq!(
        agent
            .upstream
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        seen,
        "a CONNECT without the token must not reach upstream"
    );
    kill_agent(&mut agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cleartext_absolute_uri_is_refused_and_never_reaches_upstream() {
    let mut agent = setup_agent(true, true);
    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let (status, _) = absolute_uri_request(
        &proxy,
        "http://api.stripe.com/v1/customers",
        "api.stripe.com",
    );
    assert!(
        !status.starts_with("HTTP/1.1 200"),
        "cleartext must not be served, got: {status}"
    );
    assert_eq!(
        agent
            .upstream
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a cleartext request must never reach upstream"
    );
    kill_agent(&mut agent);
}
