#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zs_credential::Credential;
use zs_proto_postgres::{PostgresListener, SslPolicy, UpstreamEndpoint, UpstreamTls};

mod fake;

use fake::{Answer, Auth, Script};

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hi(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(password).unwrap();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut ui = mac.finalize().into_bytes().to_vec();
    let mut result = ui.clone();
    for _ in 1..iterations {
        mac = Hmac::<Sha256>::new_from_slice(password).unwrap();
        mac.update(&ui);
        ui = mac.finalize().into_bytes().to_vec();
        for (a, b) in result.iter_mut().zip(ui.iter()) {
            *a ^= *b;
        }
    }
    result
}

const PASSWORD: &str = "upstream_secret_pencil";
const USER: &str = "alice";

struct MockUpstream {
    addr: std::net::SocketAddr,
    authenticated: Arc<std::sync::atomic::AtomicBool>,
    accepts: Arc<std::sync::atomic::AtomicUsize>,
}

async fn mock_upstream() -> MockUpstream {
    serve_mock(TcpListener::bind("127.0.0.1:0").await.unwrap())
}

fn serve_mock(listener: TcpListener) -> MockUpstream {
    let addr = listener.local_addr().unwrap();
    let authenticated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let flag = authenticated.clone();
    let count = accepts.clone();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let flag = flag.clone();
            tokio::spawn(async move {
                if serve_scram(&mut stream).await.is_ok() {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            });
        }
    });

    MockUpstream {
        addr,
        authenticated,
        accepts,
    }
}

async fn serve_scram(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut rest = vec![0u8; len.saturating_sub(4)];
    stream.read_exact(&mut rest).await?;
    if rest == [0x04, 0xd2, 0x16, 0x2f] {
        stream.write_all(b"N").await?;
        stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let mut startup = vec![0u8; len.saturating_sub(4)];
        stream.read_exact(&mut startup).await?;
    }

    let mechanism = b"SCRAM-SHA-256\0\0";
    let mut msg = b"R".to_vec();
    msg.extend_from_slice(&((4 + 4 + mechanism.len()) as u32).to_be_bytes());
    msg.extend_from_slice(&10u32.to_be_bytes());
    msg.extend_from_slice(mechanism);
    stream.write_all(&msg).await?;

    let client_first = read_message(stream).await?;
    let client_first_bare = extract_client_first_bare(&client_first.1)
        .ok_or_else(|| std::io::Error::other("no client-first-bare"))?;

    let salt = b"W22ZaJ0SNY7soEsUEjb6gQ==";
    let server_nonce = "serverNonceForTest123";
    let server_first = format!(
        "r={},s={},i=4096",
        client_nonce(&client_first_bare)
            .unwrap_or_default()
            .to_owned()
            + server_nonce,
        String::from_utf8_lossy(salt)
    );
    let mut msg = b"R".to_vec();
    msg.extend_from_slice(&((4 + 4 + server_first.len()) as u32).to_be_bytes());
    msg.extend_from_slice(&11u32.to_be_bytes());
    msg.extend_from_slice(server_first.as_bytes());
    stream.write_all(&msg).await?;

    let (_, final_body) = read_message(stream).await?;
    if !final_body.contains("p=") {
        return Err(std::io::Error::other("no client proof"));
    }

    let without_proof = final_body
        .rsplit_once(",p=")
        .map(|(prefix, _)| prefix.to_string())
        .unwrap_or_default();

    let salt_decoded = base64::engine::general_purpose::STANDARD
        .decode(salt)
        .unwrap();
    let salted_password = hi(PASSWORD.as_bytes(), &salt_decoded, 4096);
    let server_key = hmac_sha256(&salted_password, b"Server Key");
    let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
    let server_sig = hmac_sha256(&server_key, auth_message.as_bytes());
    let verifier = format!(
        "v={}",
        base64::engine::general_purpose::STANDARD.encode(&server_sig)
    );
    let mut sasl_final = b"R".to_vec();
    sasl_final.extend_from_slice(&((4 + 4 + verifier.len()) as u32).to_be_bytes());
    sasl_final.extend_from_slice(&12u32.to_be_bytes());
    sasl_final.extend_from_slice(verifier.as_bytes());
    stream.write_all(&sasl_final).await?;

    let mut ok = b"R".to_vec();
    ok.extend_from_slice(&8u32.to_be_bytes());
    ok.extend_from_slice(&0u32.to_be_bytes());
    stream.write_all(&ok).await?;
    let mut ready = b"Z".to_vec();
    ready.extend_from_slice(&5u32.to_be_bytes());
    ready.push(b'I');
    stream.write_all(&ready).await?;
    Ok(())
}

async fn read_message(stream: &mut TcpStream) -> std::io::Result<(u8, String)> {
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag).await?;
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut body = vec![0u8; len.saturating_sub(4)];
    stream.read_exact(&mut body).await?;
    Ok((tag[0], String::from_utf8_lossy(&body).into_owned()))
}

fn extract_client_first_bare(body: &str) -> Option<String> {
    let idx = body.find("n,,")?;
    Some(body[idx + 3..].to_string())
}

fn client_nonce(bare: &str) -> Option<&str> {
    bare.split(',').find_map(|p| p.strip_prefix("r="))
}

fn credential() -> Credential {
    Credential::from_bytes(PASSWORD.as_bytes().to_vec()).unwrap()
}

#[tokio::test]
async fn client_authenticates_through_the_listener_without_a_password() {
    let upstream = mock_upstream().await;
    let listener = PostgresListener::bind(
        "127.0.0.1:0",
        upstream.addr,
        SslPolicy::RefuseOnLoopback,
        Arc::new(|| Ok(credential())),
    )
    .await
    .expect("listener must bind")
    .with_caller_check(fake::admit_all());
    let local = listener.local_addr();
    tokio::spawn(async move { listener.serve().await });

    let mut client = TcpStream::connect(local).await.unwrap();
    client
        .write_all(&startup_packet(USER, "appdb"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("listener must respond")
        .unwrap();
    assert!(n > 0, "listener closed without responding");
    assert!(
        buf[..n].starts_with(&zs_proto_postgres::authentication_ok()),
        "the listener must answer AuthenticationOk, not a refusal"
    );

    assert!(
        upstream
            .authenticated
            .load(std::sync::atomic::Ordering::SeqCst),
        "the listener must have completed SCRAM upstream on the client's behalf"
    );

    let seen = String::from_utf8_lossy(&buf[..n]);
    assert!(
        !seen.contains(PASSWORD),
        "the upstream password must never reach the client side"
    );
}

#[tokio::test]
async fn sslrequest_is_explicitly_refused_on_loopback() {
    let upstream = mock_upstream().await;
    let listener = PostgresListener::bind(
        "127.0.0.1:0",
        upstream.addr,
        SslPolicy::RefuseOnLoopback,
        Arc::new(|| Ok(credential())),
    )
    .await
    .unwrap()
    .with_caller_check(fake::admit_all());
    let local = listener.local_addr();
    tokio::spawn(async move { listener.serve().await });

    let mut client = TcpStream::connect(local).await.unwrap();
    let mut ssl_request = 8u32.to_be_bytes().to_vec();
    ssl_request.extend_from_slice(&80_877_103u32.to_be_bytes());
    client.write_all(&ssl_request).await.unwrap();

    let mut reply = [0u8; 1];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_exact(&mut reply),
    )
    .await
    .expect("listener must answer SSLRequest rather than ignore it")
    .unwrap();
    assert_eq!(
        reply[0], b'N',
        "the listener must refuse TLS explicitly with 'N', never silently ignore the request"
    );
}

#[tokio::test]
async fn materialization_failure_denies_the_connection() {
    let upstream = mock_upstream().await;
    let listener = PostgresListener::bind(
        "127.0.0.1:0",
        upstream.addr,
        SslPolicy::RefuseOnLoopback,
        Arc::new(|| Err(zs_protocol::Denied::new("vault unavailable"))),
    )
    .await
    .unwrap()
    .with_caller_check(fake::admit_all());
    let local = listener.local_addr();
    tokio::spawn(async move { listener.serve().await });

    let mut client = TcpStream::connect(local).await.unwrap();
    client
        .write_all(&startup_packet(USER, "appdb"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await.unwrap();
    let seen = String::from_utf8_lossy(&buf[..n]);
    assert!(
        n == 0 || seen.starts_with('E'),
        "materialization failure must deny with an ErrorResponse or close, got {n} bytes: {seen:?}"
    );
    assert!(
        !upstream
            .authenticated
            .load(std::sync::atomic::Ordering::SeqCst),
        "no upstream session may be established when materialization failed"
    );
}

#[tokio::test]
async fn binding_does_not_probe_upstream() {
    let raw = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = UpstreamEndpoint::new("127.0.0.1", raw.local_addr().unwrap().port()).unwrap();
    let listener = PostgresListener::bind_endpoint(
        "127.0.0.1:0",
        endpoint,
        SslPolicy::RefuseOnLoopback,
        UpstreamTls::WhenOffered,
        Arc::new(|| Ok(credential())),
    )
    .await
    .unwrap()
    .with_caller_check(fake::admit_all());
    let local = listener.local_addr();
    tokio::spawn(async move { listener.serve().await });

    let early = tokio::time::timeout(std::time::Duration::from_millis(100), raw.accept()).await;
    assert!(
        early.is_err(),
        "binding and serving must not contact the upstream before a client arrives"
    );

    let upstream = serve_mock(raw);
    let mut client = TcpStream::connect(local).await.unwrap();
    client
        .write_all(&startup_packet(USER, "appdb"))
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("listener must respond")
        .unwrap();
    assert!(n > 0, "listener closed without responding");
    assert!(
        buf[..n].starts_with(&zs_proto_postgres::authentication_ok()),
        "the listener must answer AuthenticationOk, not a refusal"
    );
    assert!(
        upstream
            .authenticated
            .load(std::sync::atomic::Ordering::SeqCst)
    );
    assert_eq!(
        upstream.accepts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one client must cause exactly one upstream connection"
    );
}

fn startup_packet(user: &str, database: &str) -> Vec<u8> {
    let mut body = 196_608u32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(database.as_bytes());
    body.push(0);
    body.push(0);
    let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    packet
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_tls_carries_scram_and_a_relayed_query() {
    let pki = fake::pki("127.0.0.1");
    let upstream = fake::start(Script::new(Answer::S).with_tls(pki.server.clone())).await;
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let local = fake::listen(
        "127.0.0.1",
        upstream.addr.port(),
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
        fake::materialize(fake::PASSWORD),
        diag.clone(),
    )
    .await;

    let mut client = fake::login(local)
        .await
        .expect("a login inside verified TLS");
    assert_eq!(fake::query(&mut client, "SELECT 1").await, "SELECT 1");

    assert!(
        upstream.seen(|s| s.tls && s.authenticated),
        "the login ran inside TLS"
    );
    assert_eq!(upstream.seen(|s| s.startups), 1);
    assert_eq!(
        upstream.seen(|s| s.queries.clone()),
        vec!["SELECT 1".to_string()]
    );
    drop(client);
    let events = fake::events(&diag, &log).await;
    let tls = fake::named(&events, "tls");
    assert_eq!(tls.len(), 1, "{events:?}");
    assert_eq!(tls[0]["fields"]["result"], "verified");
    assert_eq!(tls[0]["level"], "info");
    assert!(
        fake::named(&events, "upstream_failed").is_empty(),
        "{events:?}"
    );
    assert!(
        !std::fs::read_to_string(&log)
            .unwrap()
            .contains(fake::PASSWORD)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_leaf_logs_in_and_a_wrong_pin_is_refused_before_the_startup() {
    let pki = fake::pki("db.zs-test.invalid");
    let upstream = fake::start(Script::new(Answer::S).with_tls(pki.server.clone())).await;
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let pinned = fake::listen(
        "127.0.0.1",
        upstream.addr.port(),
        UpstreamTls::Pinned(pki.leaf_sha256),
        fake::materialize(fake::PASSWORD),
        diag.clone(),
    )
    .await;
    let mut client = fake::login(pinned)
        .await
        .expect("positive control: the right pin, any name");
    assert_eq!(fake::query(&mut client, "SELECT 1").await, "SELECT 1");
    assert_eq!(upstream.seen(|s| s.startups), 1);

    let wrong = upstream.listen(UpstreamTls::Pinned([0x5a; 32])).await;
    assert_eq!(
        fake::login(wrong).await.err(),
        Some(fake::error_frame(fake::TLS_FAILED))
    );
    assert_eq!(upstream.seen(|s| s.ssl_requests), 2);
    assert_eq!(
        upstream.seen(|s| s.startups),
        1,
        "a wrong pin let the startup packet through"
    );
    drop(client);
    let events = fake::events(&diag, &log).await;
    assert_eq!(fake::named(&events, "tls")[0]["fields"]["result"], "pinned");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_ca_or_a_wrong_name_is_refused_before_the_startup() {
    let pki = fake::pki("127.0.0.1");
    let upstream = fake::start(Script::new(Answer::S).with_tls(pki.server.clone())).await;
    let control = upstream
        .listen(UpstreamTls::Required(vec![pki.ca_der.clone()]))
        .await;
    assert!(
        fake::login(control).await.is_ok(),
        "positive control: the right CA and name"
    );

    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let unknown = fake::listen(
        "127.0.0.1",
        upstream.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(fake::PASSWORD),
        diag.clone(),
    )
    .await;
    assert_eq!(
        fake::login(unknown).await.err(),
        Some(fake::error_frame(fake::TLS_FAILED))
    );
    let other = fake::pki("127.0.0.1");
    let untrusted = upstream
        .listen(UpstreamTls::Required(vec![other.ca_der.clone()]))
        .await;
    assert_eq!(
        fake::login(untrusted).await.err(),
        Some(fake::error_frame(fake::TLS_FAILED))
    );
    let misnamed_pki = fake::pki("db.zs-test.invalid");
    let misnamed = fake::start(Script::new(Answer::S).with_tls(misnamed_pki.server.clone())).await;
    let wrong_name = misnamed
        .listen(UpstreamTls::Required(vec![misnamed_pki.ca_der.clone()]))
        .await;
    assert_eq!(
        fake::login(wrong_name).await.err(),
        Some(fake::error_frame(fake::TLS_FAILED))
    );

    assert_eq!(upstream.seen(|s| s.ssl_requests), 3);
    assert_eq!(
        upstream.seen(|s| s.startups),
        1,
        "a failed verification let the startup packet through"
    );
    assert_eq!(misnamed.seen(|s| s.ssl_requests), 1);
    assert_eq!(misnamed.seen(|s| s.startups), 0);

    let events = fake::events(&diag, &log).await;
    let tls = fake::named(&events, "tls");
    assert_eq!(tls[0]["fields"]["result"], "failed", "{events:?}");
    assert_eq!(tls[0]["level"], "warn");
    assert!(tls[0]["error"].get("text").is_none(), "{events:?}");
    let failed = fake::named(&events, "upstream_failed");
    assert_eq!(failed[0]["fields"]["stage"], "tls");
    assert_eq!(failed[0]["error"]["kind"], tls[0]["error"]["kind"]);
    assert_eq!(
        fake::named(&events, "conn_failed")[0]["fields"]["stage"],
        "tls"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_tls_field_and_an_n_answer_runs_in_plaintext() {
    let plain = fake::start(Script::new(Answer::N)).await;
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let local = fake::listen(
        "127.0.0.1",
        plain.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(fake::PASSWORD),
        diag.clone(),
    )
    .await;
    let mut client = fake::login(local)
        .await
        .expect("a plaintext login when the server answers N");
    assert_eq!(fake::query(&mut client, "SELECT 1").await, "SELECT 1");
    assert_eq!(
        plain.seen(|s| s.ssl_requests),
        1,
        "the listener must ask for TLS first"
    );
    assert!(plain.seen(|s| !s.tls && s.authenticated));
    drop(client);
    let events = fake::events(&diag, &log).await;
    let tls = fake::named(&events, "tls");
    assert_eq!(tls[0]["fields"]["result"], "not_offered");
    assert_eq!(tls[0]["level"], "info");
    assert!(fake::named(&events, "upstream_failed").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_required_setting_refuses_a_server_that_answers_n() {
    let plain = fake::start(Script::new(Answer::N)).await;
    let open = plain.listen(UpstreamTls::WhenOffered).await;
    assert!(
        fake::login(open).await.is_ok(),
        "negative control: no TLS field runs in plaintext"
    );
    let pki = fake::pki("127.0.0.1");
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let required = fake::listen(
        "127.0.0.1",
        plain.addr.port(),
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
        fake::materialize(fake::PASSWORD),
        diag.clone(),
    )
    .await;
    assert_eq!(
        fake::login(required).await.err(),
        Some(fake::error_frame(fake::TLS_FAILED))
    );
    let pinned = plain.listen(UpstreamTls::Pinned(pki.leaf_sha256)).await;
    assert_eq!(
        fake::login(pinned).await.err(),
        Some(fake::error_frame(fake::TLS_FAILED))
    );
    assert_eq!(plain.seen(|s| s.ssl_requests), 3);
    assert_eq!(
        plain.seen(|s| s.startups),
        1,
        "a required setting let a plaintext startup through"
    );
    let events = fake::events(&diag, &log).await;
    let tls = fake::named(&events, "tls");
    assert_eq!(tls[0]["fields"]["result"], "not_offered");
    assert_eq!(tls[0]["level"], "warn");
    let failed = fake::named(&events, "upstream_failed");
    assert_eq!(failed[0]["fields"]["stage"], "tls");
    assert_eq!(failed[0]["error"]["kind"], "not_offered");
}

#[tokio::test(flavor = "multi_thread")]
async fn s_followed_by_an_extra_byte_is_refused_before_the_handshake() {
    let pki = fake::pki("127.0.0.1");
    let clean = fake::start(Script::new(Answer::S).with_tls(pki.server.clone())).await;
    let control = clean
        .listen(UpstreamTls::Required(vec![pki.ca_der.clone()]))
        .await;
    assert!(
        fake::login(control).await.is_ok(),
        "negative control: S alone"
    );

    let injected =
        fake::start(Script::new(Answer::SWithExtraByte).with_tls(pki.server.clone())).await;
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let local = fake::listen(
        "127.0.0.1",
        injected.addr.port(),
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
        fake::materialize(fake::PASSWORD),
        diag.clone(),
    )
    .await;
    assert_eq!(
        fake::login(local).await.err(),
        Some(fake::error_frame(fake::TLS_FAILED))
    );
    assert_eq!(injected.seen(|s| s.ssl_requests), 1);
    assert_eq!(
        injected.seen(|s| s.startups),
        0,
        "a byte after S let the startup packet through"
    );
    assert_eq!(clean.seen(|s| s.startups), 1);
    let events = fake::events(&diag, &log).await;
    let failed = fake::named(&events, "upstream_failed");
    assert_eq!(failed[0]["fields"]["stage"], "tls");
    assert_eq!(failed[0]["error"]["kind"], "extra_bytes", "{events:?}");
    let tls = fake::named(&events, "tls");
    assert_eq!(tls[0]["fields"]["result"], "failed", "{events:?}");
    assert_eq!(tls[0]["error"]["kind"], "extra_bytes", "{events:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_other_than_s_or_n_is_refused() {
    let plain = fake::start(Script::new(Answer::N)).await;
    let open = plain.listen(UpstreamTls::WhenOffered).await;
    assert!(fake::login(open).await.is_ok(), "negative control: N");
    for byte in [b'E', b'G', 0] {
        let odd = fake::start(Script::new(Answer::Other(byte))).await;
        let local = odd.listen(UpstreamTls::WhenOffered).await;
        assert_eq!(
            fake::login(local).await.err(),
            Some(fake::error_frame(fake::TLS_FAILED)),
            "answer {byte:#04x}"
        );
        assert_eq!(odd.seen(|s| s.ssl_requests), 1);
        assert_eq!(
            odd.seen(|s| s.startups),
            0,
            "answer {byte:#04x} let the startup packet through"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_request_negotiates_tls_and_reaches_the_server() {
    let pki = fake::pki("127.0.0.1");
    let upstream = fake::start(Script::new(Answer::S).with_tls(pki.server.clone())).await;
    let (materialize, calls) = fake::counted(fake::PASSWORD);
    let local = fake::listen(
        "127.0.0.1",
        upstream.addr.port(),
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
        materialize,
        zs_diag::DiagLog::disabled(),
    )
    .await;

    let session = fake::login(local)
        .await
        .expect("positive control: a login inside TLS");
    drop(session);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(upstream.seen(|s| s.startups), 1);
    assert!(upstream.seen(|s| s.cancels.is_empty()));

    fake::send_cancel(local).await;

    assert!(
        fake::eventually(|| upstream.seen(|s| s.cancels.len()) == 1).await,
        "the cancel never reached the server"
    );
    assert_eq!(
        upstream.seen(|s| s.cancels.clone()),
        vec![fake::cancel_packet()]
    );
    assert!(
        upstream.seen(|s| s.tls),
        "the cancel must travel inside TLS"
    );
    assert_eq!(upstream.seen(|s| s.ssl_requests), 2);
    assert_eq!(upstream.seen(|s| s.startups), 1);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a cancel must not materialize a credential"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_with_a_required_setting_is_never_sent_in_plaintext() {
    let plain = fake::start(Script::new(Answer::N)).await;
    let open = plain.listen(UpstreamTls::WhenOffered).await;
    fake::send_cancel(open).await;
    assert!(
        fake::eventually(|| plain.seen(|s| s.cancels.len()) == 1).await,
        "negative control: no TLS field sends the cancel in plaintext"
    );

    let pki = fake::pki("127.0.0.1");
    let required = plain
        .listen(UpstreamTls::Required(vec![pki.ca_der.clone()]))
        .await;
    fake::send_cancel(required).await;
    assert!(fake::eventually(|| plain.seen(|s| s.ssl_requests) == 2).await);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        plain.seen(|s| s.cancels.len()),
        1,
        "a required setting sent the cancel in plaintext"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_scram_method_is_refused_and_logged_with_its_method() {
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let scram = fake::start(Script::new(Answer::N)).await;
    let control = fake::listen(
        "127.0.0.1",
        scram.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(fake::PASSWORD),
        diag.clone(),
    )
    .await;
    assert!(
        fake::login(control).await.is_ok(),
        "negative control: SCRAM-SHA-256 logs in"
    );
    let mut others = Vec::new();
    for code in [5u32, 3, 7, 0] {
        let other = fake::start(Script::new(Answer::N).with_auth(Auth::Method(code))).await;
        let local = fake::listen(
            "127.0.0.1",
            other.addr.port(),
            UpstreamTls::WhenOffered,
            fake::materialize(fake::PASSWORD),
            diag.clone(),
        )
        .await;
        assert_eq!(
            fake::login(local).await.err(),
            Some(fake::error_frame(fake::AUTH_FAILED)),
            "method {code}"
        );
        assert_eq!(other.seen(|s| s.startups), 1);
        assert!(!other.seen(|s| s.authenticated));
        others.push((code, other));
    }
    let events = fake::events(&diag, &log).await;
    for (code, other) in &others {
        assert!(
            other.seen(|s| s.method_settled),
            "method {code}: the upstream saw the connection end"
        );
        assert_eq!(
            other.seen(|s| s.after_method),
            None,
            "method {code}: nothing follows the method request"
        );
    }
    assert_eq!(
        fake::named(&events, "upstream_auth_ok").len(),
        1,
        "{events:?}"
    );
    let failed = fake::named(&events, "upstream_auth_failed");
    let mut methods: Vec<String> = failed
        .iter()
        .map(|e| {
            e["fields"]["method"]
                .as_str()
                .unwrap_or("absent")
                .to_string()
        })
        .collect();
    methods.sort();
    assert_eq!(methods, ["cleartext", "md5", "other", "other"]);
    assert!(
        failed.iter().all(|e| e["error"]["kind"] == "scram"),
        "{events:?}"
    );
    assert!(
        !std::fs::read_to_string(&log)
            .unwrap()
            .contains(fake::PASSWORD)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_the_check_admits_is_relayed() {
    let plain = fake::start(Script::new(Answer::N)).await;
    let home = tempfile::tempdir().unwrap();
    let (diag, _log) = fake::open_diag(home.path());
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();
    let check: zs_protocol::CallerCheck = Arc::new(move |peer, local| {
        record.lock().unwrap().push((peer, local));
        true
    });
    let local = fake::listen_gated(
        "127.0.0.1",
        plain.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(fake::PASSWORD),
        diag,
        Some(check),
    )
    .await;

    let mut client = fake::login(local)
        .await
        .expect("the admitted caller is relayed");
    assert_eq!(fake::query(&mut client, "SELECT 1").await, "SELECT 1");

    let calls = seen.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0.ip(), local.ip());
    assert_eq!(calls[0].1, local, "the local address is the listener's");
    drop(calls);
    assert_eq!(plain.seen(|s| s.accepts), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_peer_lookup_denies() {
    let plain = fake::start(Script::new(Answer::N)).await;
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let local = fake::listen_gated(
        "127.0.0.1",
        plain.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(fake::PASSWORD),
        diag.clone(),
        Some(Arc::new(|_, _| false)),
    )
    .await;

    let mut client = TcpStream::connect(local).await.unwrap();
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buffer))
        .await
        .expect("the refusal is prompt")
        .expect("the refusal is readable");
    assert_eq!(read, 0, "the client sees EOF with zero bytes");

    let events = fake::events(&diag, &log).await;
    assert_eq!(plain.seen(|s| s.accepts), 0);
    assert!(fake::named(&events, "materialized").is_empty());
    let refused = fake::named(&events, "caller_refused");
    assert_eq!(refused.len(), 1, "{events:?}");
    assert_eq!(refused[0]["fields"]["listener"], "postgres");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_listener_without_a_caller_check_refuses() {
    let plain = fake::start(Script::new(Answer::N)).await;
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let local = fake::listen_gated(
        "127.0.0.1",
        plain.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(fake::PASSWORD),
        diag.clone(),
        None,
    )
    .await;

    let mut client = TcpStream::connect(local).await.unwrap();
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buffer))
        .await
        .expect("the refusal is prompt")
        .expect("the refusal is readable");
    assert_eq!(read, 0, "the client sees EOF with zero bytes");
    let events = fake::events(&diag, &log).await;
    assert_eq!(plain.seen(|s| s.accepts), 0);
    assert_eq!(
        fake::named(&events, "caller_refused").len(),
        1,
        "{events:?}"
    );
}
