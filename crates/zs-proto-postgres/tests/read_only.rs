#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fake::{Answer, Script};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zs_diag::DiagLog;
use zs_proto_postgres::{
    AuditRefusal, Materialize, PARSE_REFUSAL, PostgresListener, QUERY_REFUSAL, SslPolicy,
    UpstreamEndpoint, UpstreamTls,
};
use zs_protocol::SessionAccess;

type Refusals = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

const ESCAPE: &str = "SET default_transaction_read_only = off";
const READ_ONLY_REFUSED: (&str, &str) = (
    "28000",
    "connection options not accepted on a read-only resource",
);

struct Session {
    local: SocketAddr,
    refusals: Refusals,
    diag: DiagLog,
    log: PathBuf,
    _home: tempfile::TempDir,
}

impl Session {
    async fn events(&self) -> Vec<serde_json::Value> {
        fake::events(&self.diag, &self.log).await
    }

    fn refusals(&self) -> Vec<(&'static str, &'static str)> {
        self.refusals.lock().unwrap().clone()
    }
}

async fn listen_as(port: u16, access: SessionAccess) -> Session {
    let refusals: Refusals = Arc::new(Mutex::new(Vec::new()));
    let record = refusals.clone();
    let audit: AuditRefusal = Arc::new(move |operation: &'static str, reason: &'static str| {
        record.lock().unwrap().push((operation, reason));
        Some(7)
    });
    let materialize: Materialize =
        Arc::new(move || Ok(fake::granted_as(fake::PASSWORD.as_bytes(), access)));
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let listener = PostgresListener::bind_endpoint(
        "127.0.0.1:0",
        UpstreamEndpoint::new("127.0.0.1", port).unwrap(),
        SslPolicy::RefuseOnLoopback,
        UpstreamTls::WhenOffered,
        materialize,
    )
    .await
    .unwrap()
    .with_diag(diag.clone(), fake::RESOURCE)
    .with_refusal_audit(audit)
    .with_caller_check(fake::admit_all());
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    Session {
        local,
        refusals,
        diag,
        log,
        _home: home,
    }
}

fn query(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    fake::frame(b'Q', &body)
}

fn parse(name: &str, sql: &str, types: &[u32]) -> Vec<u8> {
    let mut body = name.as_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(sql.as_bytes());
    body.push(0);
    body.extend_from_slice(&(types.len() as u16).to_be_bytes());
    for oid in types {
        body.extend_from_slice(&oid.to_be_bytes());
    }
    fake::frame(b'P', &body)
}

fn bind(statement: &str) -> Vec<u8> {
    let mut body = vec![0];
    body.extend_from_slice(statement.as_bytes());
    body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
    fake::frame(b'B', &body)
}

fn execute() -> Vec<u8> {
    fake::frame(b'E', &[0, 0, 0, 0, 0])
}

fn sync() -> Vec<u8> {
    fake::frame(b'S', &[])
}

fn function_call() -> Vec<u8> {
    let mut body = 2078u32.to_be_bytes().to_vec();
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&3u16.to_be_bytes());
    for argument in [&b"default_transaction_read_only"[..], b"off", b"f"] {
        body.extend_from_slice(&(argument.len() as u32).to_be_bytes());
        body.extend_from_slice(argument);
    }
    body.extend_from_slice(&0u16.to_be_bytes());
    fake::frame(b'F', &body)
}

fn batch() -> Vec<Vec<u8>> {
    vec![
        parse("s1", "SELECT 1", &[]),
        parse("s2", "BEGIN READ WRITE", &[23]),
        bind("s1"),
        execute(),
        parse("s3", "SELECT 2", &[]),
        sync(),
    ]
}

fn client_startup() -> Vec<u8> {
    fake::startup(&[
        ("user", "alice"),
        ("default_transaction_read_only", "off"),
        ("database", "appdb"),
        (
            "options",
            "-c application_name=orders -c default_transaction_read_only=off",
        ),
    ])
}

async fn until_ready(client: &mut TcpStream) {
    loop {
        let (tag, _) = tokio::time::timeout(Duration::from_secs(10), fake::read_tagged(client))
            .await
            .unwrap()
            .unwrap();
        if tag == b'Z' {
            return;
        }
    }
}

async fn send_all(client: &mut TcpStream, messages: &[Vec<u8>]) {
    client.write_all(&messages.concat()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_startup_reaches_the_upstream_rewritten() {
    let upstream = fake::start(Script::new(Answer::N)).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;

    let mut client = fake::login_with(session.local, &client_startup())
        .await
        .expect("a read-only login works");
    assert_eq!(fake::query(&mut client, "SELECT 1").await, "SELECT 1");

    assert_eq!(
        upstream.seen(|s| s.startup.clone()),
        fake::startup(&[
            ("user", "alice"),
            ("database", "appdb"),
            (
                "options",
                "-capplication_name=orders -c default_transaction_read_only=on",
            ),
        ])
    );
    assert!(session.refusals().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_query_reaches_the_upstream_as_the_refusal_statement() {
    let upstream = fake::start(Script::new(Answer::N)).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();

    fake::query(&mut client, "SELECT 'before'").await;
    fake::query(&mut client, ESCAPE).await;
    fake::query(&mut client, "SELECT 'after'").await;

    assert_eq!(
        upstream.seen(|s| s.messages.clone()),
        vec![
            query("SELECT 'before'"),
            query(QUERY_REFUSAL),
            query("SELECT 'after'")
        ]
    );
    assert_eq!(session.refusals(), vec![("query", "read-only")]);
    let events = session.events().await;
    let refused = fake::named(&events, "statement_refused");
    assert_eq!(refused.len(), 1, "{events:?}");
    assert_eq!(
        refused[0]["fields"]["word"],
        "default_transaction_read_only"
    );
    assert_eq!(refused[0]["audit_seq"], 7);
    let log = std::fs::read_to_string(&session.log).unwrap_or_default();
    assert!(!log.contains("= off"), "the statement text reached the log");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_parse_mid_batch_is_replaced_and_its_neighbours_are_untouched() {
    let upstream = fake::start(Script::new(Answer::N)).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();

    send_all(&mut client, &batch()).await;
    until_ready(&mut client).await;

    let mut expected = batch();
    expected[1] = parse("s2", PARSE_REFUSAL, &[]);
    assert_eq!(upstream.seen(|s| s.messages.clone()), expected);
    assert_eq!(session.refusals(), vec![("query", "read-only")]);
    let events = session.events().await;
    assert_eq!(
        fake::named(&events, "statement_refused")[0]["fields"]["word"],
        "read write"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_function_call_is_replaced_by_the_query_refusal() {
    let upstream = fake::start(Script::new(Answer::N)).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();

    send_all(&mut client, &[function_call()]).await;
    until_ready(&mut client).await;
    fake::query(&mut client, "SELECT 'after'").await;

    assert_eq!(
        upstream.seen(|s| s.messages.clone()),
        vec![query(QUERY_REFUSAL), query("SELECT 'after'")]
    );
    assert_eq!(session.refusals(), vec![("query", "read-only")]);
    let events = session.events().await;
    assert_eq!(
        fake::named(&events, "statement_refused")[0]["fields"]["word"],
        "function_call"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_write_session_forwards_every_byte_unchanged() {
    let upstream = fake::start(Script::new(Answer::N)).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadWrite).await;
    let mut client = fake::login_with(session.local, &client_startup())
        .await
        .unwrap();

    fake::query(&mut client, ESCAPE).await;
    send_all(&mut client, &batch()).await;
    until_ready(&mut client).await;
    let unknown = fake::frame(b'z', b"zs");
    send_all(&mut client, &[function_call(), unknown.clone()]).await;
    fake::query(&mut client, "SELECT 'after'").await;

    assert_eq!(upstream.seen(|s| s.startup.clone()), client_startup());
    let mut expected = vec![query(ESCAPE)];
    expected.extend(batch());
    expected.extend([function_call(), unknown, query("SELECT 'after'")]);
    assert_eq!(upstream.seen(|s| s.messages.clone()), expected);
    assert!(session.refusals().is_empty());
    let events = session.events().await;
    assert!(fake::named(&events, "statement_refused").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_message_ends_a_read_only_session() {
    let upstream = fake::start(Script::new(Answer::N)).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();

    fake::query(&mut client, "SELECT 'before'").await;
    send_all(
        &mut client,
        &[fake::frame(b'z', b"zs"), query("SELECT 'after'")],
    )
    .await;
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
        .await
        .expect("the session must close")
        .ok();

    assert!(rest.is_empty());
    assert_eq!(
        upstream.seen(|s| s.messages.clone()),
        vec![query("SELECT 'before'")]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_options_string_that_cannot_be_parsed_denies_a_read_only_connection() {
    let upstream = fake::start(Script::new(Answer::N)).await;
    let refused = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let unknown = fake::startup(&[("user", "alice"), ("options", "-q -c x.y=1")]);

    assert_eq!(
        fake::login_with(refused.local, &unknown).await.err(),
        Some(fake::error_frame(READ_ONLY_REFUSED))
    );
    assert_eq!(upstream.seen(|s| s.accepts), 0);
    assert_eq!(refused.refusals(), vec![("connect", "read-only")]);

    let allowed = listen_as(upstream.addr.port(), SessionAccess::ReadWrite).await;
    assert!(
        fake::login_with(allowed.local, &unknown).await.is_ok(),
        "negative control: a read-write session forwards the options unchanged"
    );
    assert_eq!(upstream.seen(|s| s.startup.clone()), unknown);
}
