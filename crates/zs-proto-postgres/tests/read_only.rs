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
const CANNOT_OPEN_READ_ONLY: (&str, &str) =
    ("08004", "zs: the server cannot open a read-only session");

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
        Arc::new(move |_| Ok(fake::granted_as(fake::PASSWORD.as_bytes(), access)));
    let home = tempfile::tempdir().unwrap();
    let (diag, log) = fake::open_diag(home.path());
    let listener = PostgresListener::bind_endpoint(
        &fake::loopback(),
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
    let local = fake::tcp_addr(listener.local());
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

type Frames = Arc<Mutex<Vec<Vec<u8>>>>;
type Status = &'static [(&'static str, &'static str)];

const SUPERUSER_LOGIN: [(&str, &str); 3] = [
    ("server_encoding", "UTF8"),
    ("default_transaction_read_only", "on"),
    ("is_superuser", "on"),
];
const HIDDEN: &str = "SELECT zs_hidden()";
const INSERT: &str = "INSERT INTO t VALUES (2)";

fn complete(tag: &str) -> Vec<u8> {
    let mut body = tag.as_bytes().to_vec();
    body.push(0);
    fake::frame(b'C', &body)
}

fn ready() -> Vec<u8> {
    fake::frame(b'Z', b"I")
}

fn copy_in() -> Vec<u8> {
    fake::frame(b'G', &[0, 0, 1, 0, 0])
}

fn copy_out() -> Vec<u8> {
    [
        fake::frame(b'H', &[0, 0, 1, 0, 0]),
        fake::frame(b'd', b"1\n"),
        fake::frame(b'd', b"2\n"),
        fake::frame(b'c', &[]),
        complete("COPY 2"),
    ]
    .concat()
}

fn wide() -> Vec<u8> {
    let mut row = 1u16.to_be_bytes().to_vec();
    row.extend_from_slice(&3000u32.to_be_bytes());
    row.extend((0..3000).map(|at| b'a' + (at % 26) as u8));
    [
        fake::frame(
            b'T',
            b"\0\x01wide\0\0\0\0\0\0\0\0\0\0\x19\xff\xff\xff\xff\xff\xff\0\0",
        ),
        fake::frame(b'D', &row),
        fake::frame(b'N', b"SNOTICE\0C00000\0Mzs notice\0\0"),
        fake::parameter_status("application_name", "orders"),
        complete("SELECT 1"),
    ]
    .concat()
}

fn results(text: &str) -> Vec<u8> {
    if text.contains("zs_hidden") {
        [
            complete("SELECT 1"),
            fake::parameter_status("default_transaction_read_only", "off"),
        ]
        .concat()
    } else if text.contains("RESET ROLE") {
        [
            complete("RESET"),
            fake::parameter_status("is_superuser", "off"),
        ]
        .concat()
    } else if text.contains("SET ROLE admin") {
        [
            complete("SET"),
            fake::parameter_status("is_superuser", "on"),
        ]
        .concat()
    } else if text.contains("wide") {
        wide()
    } else {
        complete("SELECT 1")
    }
}

#[derive(Default)]
struct Emulator {
    statement: String,
    copy: Option<bool>,
    show: Option<&'static str>,
}

const CONFIRM: &str = "SHOW default_transaction_read_only";

fn shown(value: Option<&str>) -> Vec<u8> {
    let Some(value) = value else {
        return [fake::error_frame(("42501", "permission denied")), ready()].concat();
    };
    let mut description = 1u16.to_be_bytes().to_vec();
    description.extend_from_slice(b"default_transaction_read_only\0");
    description.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 255, 255, 255, 255, 255, 255]);
    description.extend_from_slice(&[0, 0]);
    let mut row = 1u16.to_be_bytes().to_vec();
    row.extend_from_slice(&(value.len() as u32).to_be_bytes());
    row.extend_from_slice(value.as_bytes());
    [
        fake::frame(b'T', &description),
        fake::frame(b'D', &row),
        complete("SHOW"),
        ready(),
    ]
    .concat()
}

impl Emulator {
    fn answer(&mut self, tag: u8, body: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(body).into_owned();
        match tag {
            b'Q' if text.contains(CONFIRM) => shown(self.show),
            b'Q' if text.contains("STDIN") => {
                self.copy = Some(false);
                copy_in()
            }
            b'Q' if text.contains("STDOUT") => [copy_out(), ready()].concat(),
            b'Q' if text.contains("BOTH") => fake::frame(b'W', &[0, 0, 0]),
            b'Q' => [results(&text), ready()].concat(),
            b'P' => {
                self.statement = text;
                fake::frame(b'1', &[])
            }
            b'B' => fake::frame(b'2', &[]),
            b'E' if self.statement.contains("STDIN") => {
                self.copy = Some(true);
                copy_in()
            }
            b'E' => results(&self.statement),
            b'S' if self.copy.is_some() => Vec::new(),
            b'S' => ready(),
            b'c' => match self.copy.take() {
                Some(false) => [complete("COPY 2"), ready()].concat(),
                Some(true) => complete("COPY 2"),
                None => Vec::new(),
            },
            _ => Vec::new(),
        }
    }
}

struct Emulated {
    addr: SocketAddr,
    frames: Frames,
}

impl Emulated {
    fn frames(&self) -> Vec<Vec<u8>> {
        self.frames.lock().unwrap().clone()
    }
}

async fn write_bytewise(tcp: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    for byte in bytes {
        tcp.write_all(&[*byte]).await?;
        tcp.flush().await?;
    }
    Ok(())
}

async fn emulated(status: Status, bytewise: bool) -> Emulated {
    emulated_showing(status, bytewise, None).await
}

async fn emulated_showing(status: Status, bytewise: bool, show: Option<&'static str>) -> Emulated {
    let frames: Frames = Arc::new(Mutex::new(Vec::new()));
    let record = frames.clone();
    let addr = fake::start_with(move |mut tcp| {
        let record = record.clone();
        async move {
            tcp.set_nodelay(true)?;
            fake::accept_login(&mut tcp, status).await?;
            let mut emulator = Emulator {
                show,
                ..Emulator::default()
            };
            loop {
                let (tag, body) = fake::read_tagged(&mut tcp).await?;
                record.lock().unwrap().push(fake::frame(tag, &body));
                let reply = emulator.answer(tag, &body);
                if bytewise {
                    write_bytewise(&mut tcp, &reply).await?;
                } else {
                    tcp.write_all(&reply).await?;
                }
                if tag == b'X' {
                    return Ok(());
                }
            }
        }
    })
    .await;
    Emulated { addr, frames }
}

async fn reply(client: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let (tag, body) = tokio::time::timeout(Duration::from_secs(10), fake::read_tagged(client))
            .await
            .expect("the reply must arrive within 10 s")
            .unwrap();
        bytes.extend_from_slice(&fake::frame(tag, &body));
        if tag == b'Z' {
            return bytes;
        }
    }
}

async fn until_tag(client: &mut TcpStream, wanted: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let (tag, body) = tokio::time::timeout(Duration::from_secs(10), fake::read_tagged(client))
            .await
            .expect("the message must arrive within 10 s")
            .unwrap();
        bytes.extend_from_slice(&fake::frame(tag, &body));
        if tag == wanted {
            return bytes;
        }
    }
}

async fn closed(client: &mut TcpStream) -> Vec<u8> {
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
        .await
        .expect("the session must close within 5 s")
        .ok();
    rest
}

fn extended(sql: &str) -> Vec<Vec<u8>> {
    vec![parse("", sql, &[]), bind(""), execute(), sync()]
}

type Arrivals = Arc<Mutex<Vec<(Vec<u8>, bool)>>>;

async fn timing_upstream() -> (SocketAddr, Arrivals) {
    let arrivals: Arrivals = Arc::new(Mutex::new(Vec::new()));
    let record = arrivals.clone();
    let addr = fake::start_with(move |mut tcp| {
        let record = record.clone();
        async move {
            fake::accept_login(&mut tcp, &fake::READ_ONLY_LOGIN).await?;
            loop {
                let (tag, body) = fake::read_tagged(&mut tcp).await?;
                let mut next = [0u8; 1];
                let early = matches!(
                    tokio::time::timeout(Duration::from_millis(300), tcp.peek(&mut next)).await,
                    Ok(Ok(read)) if read > 0
                );
                record
                    .lock()
                    .unwrap()
                    .push((fake::frame(tag, &body), early));
                match tag {
                    b'Q' => {
                        tcp.write_all(&[complete("SELECT 1"), ready()].concat())
                            .await?
                    }
                    b'S' => tcp.write_all(&ready()).await?,
                    _ => {}
                }
            }
        }
    })
    .await;
    (addr, arrivals)
}

#[tokio::test(flavor = "multi_thread")]
async fn units_are_forwarded_one_at_a_time() {
    let (upstream, arrivals) = timing_upstream().await;
    let session = listen_as(upstream.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();

    send_all(&mut client, &[query("SELECT 1"), query("SELECT 2")]).await;
    reply(&mut client).await;
    reply(&mut client).await;
    let mut batch = extended("SELECT 3");
    batch.push(query("SELECT 4"));
    send_all(&mut client, &batch).await;
    reply(&mut client).await;
    reply(&mut client).await;

    let early: Vec<(Vec<u8>, bool)> = vec![
        (query("SELECT 1"), false),
        (query("SELECT 2"), false),
        (parse("", "SELECT 3", &[]), true),
        (bind(""), true),
        (execute(), true),
        (sync(), false),
        (query("SELECT 4"), false),
    ];
    assert_eq!(
        *arrivals.lock().unwrap(),
        early,
        "the messages of one unit arrive together, the next unit only after ReadyForQuery"
    );
    assert!(session.refusals().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_write_session_does_not_hold_pipelined_units() {
    let (upstream, arrivals) = timing_upstream().await;
    let session = listen_as(upstream.port(), SessionAccess::ReadWrite).await;
    let mut client = fake::login(session.local).await.unwrap();

    send_all(&mut client, &[query("SELECT 1"), query("SELECT 2")]).await;
    let first = reply(&mut client).await;
    let second = reply(&mut client).await;

    assert_eq!(first, [complete("SELECT 1"), ready()].concat());
    assert_eq!(second, first);
    assert_eq!(
        *arrivals.lock().unwrap(),
        vec![(query("SELECT 1"), true), (query("SELECT 2"), false)],
        "a read-write session forwards the pipelined Query without waiting"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn split_server_messages_are_framed_correctly() {
    let upstream = emulated(&fake::READ_ONLY_LOGIN, true).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();

    send_all(&mut client, &[query("SELECT wide")]).await;
    let expected = [wide(), ready()].concat();
    let mut received = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(20), client.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        received, expected,
        "every byte reaches the client unchanged"
    );

    send_all(&mut client, &[query(HIDDEN), query(INSERT)]).await;
    let rest = closed(&mut client).await;
    assert!(
        complete("SELECT 1").starts_with(&rest),
        "at most what came before the ParameterStatus reaches the client: {rest:?}"
    );
    assert!(
        fake::eventually(|| upstream.frames().len() == 2).await,
        "{:?}",
        upstream.frames()
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        upstream.frames(),
        vec![query("SELECT wide"), query(HIDDEN)],
        "the pipelined INSERT never reached the upstream"
    );
    assert_eq!(session.refusals(), vec![("connect", "read-only escaped")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_parameter_status_off_closes_the_session_before_the_next_unit() {
    let upstream = emulated(&fake::READ_ONLY_LOGIN, false).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadWrite).await;
    let mut control = fake::login(session.local).await.unwrap();
    let mut pipelined = vec![query(HIDDEN)];
    pipelined.extend(extended(INSERT));
    pipelined.push(query(INSERT));
    send_all(&mut control, &pipelined).await;
    for _ in 0..3 {
        reply(&mut control).await;
    }
    assert_eq!(
        upstream.frames(),
        pipelined,
        "negative control: a read-write session forwards every unit"
    );
    assert!(session.refusals().is_empty());

    let upstream = emulated(&fake::READ_ONLY_LOGIN, false).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();
    assert_eq!(
        fake::query(&mut client, "SELECT 'before'").await,
        "SELECT 1"
    );
    send_all(&mut client, &pipelined).await;

    let rest = closed(&mut client).await;
    assert!(
        complete("SELECT 1").starts_with(&rest),
        "at most what came before the ParameterStatus reaches the client: {rest:?}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        upstream.frames(),
        vec![query("SELECT 'before'"), query(HIDDEN)],
        "no message of the next unit reached the upstream"
    );
    assert_eq!(session.refusals(), vec![("connect", "read-only escaped")]);
    let events = session.events().await;
    let escaped = fake::named(&events, "client_refused");
    assert_eq!(escaped.len(), 1, "{events:?}");
    assert_eq!(escaped[0]["fields"]["reason"], "read_only_escaped");
    assert_eq!(escaped[0]["audit_seq"], 7);
    assert_eq!(
        fake::named(&events, "conn_closed")[0]["fields"]["closed_by"],
        "escaped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_superuser_login_scans_with_the_superuser_words() {
    let statements = [
        "SELECT pg_reload_conf()",
        "ALTER SYSTEM SET work_mem = '64MB'",
        "SELECT pg_terminate_backend(7)",
        "SET ROLE other",
        "SET SESSION AUTHORIZATION other",
    ];
    let upstream = emulated(&fake::READ_ONLY_LOGIN, false).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut control = fake::login(session.local).await.unwrap();
    for statement in statements {
        fake::query(&mut control, statement).await;
    }
    assert_eq!(
        upstream.frames(),
        statements.map(query).to_vec(),
        "negative control: a non-superuser read-only session forwards them"
    );
    assert!(session.refusals().is_empty());
    assert!(fake::named(&session.events().await, "superuser_session").is_empty());

    let upstream = emulated(&SUPERUSER_LOGIN, false).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();
    assert_eq!(
        fake::query(&mut client, "SELECT program_id FROM t").await,
        "SELECT 1"
    );
    for statement in statements {
        fake::query(&mut client, statement).await;
    }

    let mut expected = vec![query("SELECT program_id FROM t")];
    expected.extend(statements.map(|_| query(QUERY_REFUSAL)));
    assert_eq!(upstream.frames(), expected);
    assert_eq!(session.refusals(), vec![("query", "read-only"); 5]);
    let events = session.events().await;
    assert_eq!(
        fake::named(&events, "superuser_session").len(),
        1,
        "{events:?}"
    );
    let words: Vec<String> = fake::named(&events, "statement_refused")
        .iter()
        .map(|event| event["fields"]["word"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        words,
        [
            "pg_reload_conf",
            "alter system",
            "pg_terminate_backend",
            "set role",
            "session authorization"
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_that_becomes_superuser_scans_with_the_superuser_words_from_then_on() {
    let upstream = emulated(&fake::READ_ONLY_LOGIN, false).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();
    let alter = "ALTER SYSTEM SET work_mem = '64MB'";

    fake::query(&mut client, alter).await;
    fake::query(&mut client, "SET ROLE admin").await;
    fake::query(&mut client, alter).await;
    fake::query(&mut client, "RESET ROLE").await;
    fake::query(&mut client, alter).await;

    assert_eq!(
        upstream.frames(),
        vec![
            query(alter),
            query("SET ROLE admin"),
            query(QUERY_REFUSAL),
            query("RESET ROLE"),
            query(QUERY_REFUSAL),
        ],
        "forwarded before the server reports is_superuser on, refused after, and still after off"
    );
    assert_eq!(session.refusals(), vec![("query", "read-only"); 2]);
    let events = session.events().await;
    assert_eq!(
        fake::named(&events, "superuser_session").len(),
        1,
        "{events:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_reports_read_write_at_login_fails_closed() {
    const READ_WRITE_LOGIN: [(&str, &str); 3] = [
        ("server_encoding", "UTF8"),
        ("default_transaction_read_only", "off"),
        ("is_superuser", "off"),
    ];
    let upstream = emulated(&READ_WRITE_LOGIN, false).await;
    let control = listen_as(upstream.addr.port(), SessionAccess::ReadWrite).await;
    let mut allowed = fake::login(control.local)
        .await
        .expect("negative control: a read-write login works");
    assert_eq!(fake::query(&mut allowed, "SELECT 1").await, "SELECT 1");

    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    assert_eq!(
        pipelined_login(session.local).await,
        fake::error_frame(CANNOT_OPEN_READ_ONLY),
        "the session closes with the fixed error and nothing else"
    );
    assert_eq!(session.refusals(), vec![("connect", "read-only escaped")]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(upstream.frames(), vec![query("SELECT 1")]);
}

async fn pipelined_login(local: SocketAddr) -> Vec<u8> {
    let mut client = TcpStream::connect(local).await.unwrap();
    let mut first = zs_proto_postgres::startup_packet("alice", "appdb");
    first.extend_from_slice(&query("SELECT 'first'"));
    client.write_all(&first).await.unwrap();
    closed(&mut client).await
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_never_reports_the_mode_fails_closed() {
    const UNREPORTED_LOGIN: [(&str, &str); 2] =
        [("server_encoding", "UTF8"), ("is_superuser", "off")];
    let reported = emulated(&fake::READ_ONLY_LOGIN, false).await;
    let control = listen_as(reported.addr.port(), SessionAccess::ReadOnly).await;
    let mut allowed = fake::login(control.local)
        .await
        .expect("control: a login that reports the mode on works");
    assert_eq!(
        fake::query(&mut allowed, "SELECT 'first'").await,
        "SELECT 1"
    );
    assert_eq!(reported.frames(), vec![query("SELECT 'first'")]);
    assert!(control.refusals().is_empty());

    let unreported = emulated(&UNREPORTED_LOGIN, false).await;
    let read_write = listen_as(unreported.addr.port(), SessionAccess::ReadWrite).await;
    let mut unaffected = fake::login(read_write.local)
        .await
        .expect("a read-write session does not need the report");
    assert_eq!(
        fake::query(&mut unaffected, "SELECT 'rw'").await,
        "SELECT 1"
    );
    assert!(read_write.refusals().is_empty());

    let session = listen_as(unreported.addr.port(), SessionAccess::ReadOnly).await;
    assert_eq!(
        pipelined_login(session.local).await,
        fake::error_frame(CANNOT_OPEN_READ_ONLY),
        "the session closes with the fixed error and no server startup message"
    );
    assert_eq!(session.refusals(), vec![("connect", "read-only escaped")]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        unreported.frames(),
        vec![query("SELECT 'rw'")],
        "the pipelined first Query never reached the upstream"
    );
    let events = session.events().await;
    assert_eq!(
        fake::named(&events, "client_refused")[0]["fields"]["reason"],
        "read_only_escaped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_older_than_14_is_asked_for_the_mode_before_the_client_is_ready() {
    const OLD_LOGIN: [(&str, &str); 3] = [
        ("server_version", "13.16"),
        ("server_encoding", "UTF8"),
        ("is_superuser", "off"),
    ];
    let upstream = emulated_showing(&OLD_LOGIN, false, Some("on")).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local)
        .await
        .expect("a 13.x server that answers on opens a read-only session");
    assert_eq!(fake::query(&mut client, "SELECT 'first'").await, "SELECT 1");
    assert_eq!(
        upstream.frames(),
        vec![query(CONFIRM), query("SELECT 'first'")],
        "the agent asks once, before the client's first query"
    );
    assert!(session.refusals().is_empty());
    for statement in [
        ESCAPE,
        "COPY t TO PROGRAM 'true'",
        "COPY t TO '/tmp/zs-out'",
    ] {
        fake::query(&mut client, statement).await;
    }
    assert_eq!(
        upstream.frames()[2..],
        [
            query(QUERY_REFUSAL),
            query(QUERY_REFUSAL),
            query(QUERY_REFUSAL)
        ],
        "the scan still refuses on a 13.x server, in a non-superuser session"
    );
    assert_eq!(session.refusals(), vec![("query", "read-only"); 3]);

    let read_write_upstream = emulated_showing(&OLD_LOGIN, false, Some("off")).await;
    let read_write = listen_as(read_write_upstream.addr.port(), SessionAccess::ReadWrite).await;
    let mut unaffected = fake::login(read_write.local)
        .await
        .expect("negative control: a read-write session does not ask");
    assert_eq!(
        fake::query(&mut unaffected, "SELECT 'rw'").await,
        "SELECT 1"
    );
    assert_eq!(read_write_upstream.frames(), vec![query("SELECT 'rw'")]);

    for show in [Some("off"), Some("On"), None] {
        let upstream = emulated_showing(&OLD_LOGIN, false, show).await;
        let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
        assert_eq!(
            pipelined_login(session.local).await,
            fake::error_frame(CANNOT_OPEN_READ_ONLY),
            "{show:?}: the session closes with the fixed error and nothing else"
        );
        assert_eq!(
            session.refusals(),
            vec![("connect", "read-only escaped")],
            "{show:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            upstream.frames(),
            vec![query(CONFIRM)],
            "{show:?}: the pipelined first Query never reached the upstream"
        );
    }

    const NEW_UNREPORTED: [(&str, &str); 3] = [
        ("server_version", "14.13"),
        ("server_encoding", "UTF8"),
        ("is_superuser", "off"),
    ];
    let upstream = emulated_showing(&NEW_UNREPORTED, false, Some("on")).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    assert_eq!(
        pipelined_login(session.local).await,
        fake::error_frame(CANNOT_OPEN_READ_ONLY),
        "a 14+ server that does not report the mode fails closed"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        upstream.frames().is_empty(),
        "no query is sent to a 14+ server"
    );
}

fn encoded_login(encoding: Option<&'static str>) -> Status {
    let mut status: Vec<(&'static str, &'static str)> = encoding
        .map(|encoding| ("server_encoding", encoding))
        .into_iter()
        .collect();
    status.extend([
        ("default_transaction_read_only", "on"),
        ("is_superuser", "off"),
    ]);
    Box::leak(status.into_boxed_slice())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_session_opens_only_on_a_multi_byte_server_encoding() {
    for encoding in ["UTF8", "EUC_JP"] {
        let upstream = emulated(encoded_login(Some(encoding)), false).await;
        let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
        let mut client = fake::login(session.local)
            .await
            .unwrap_or_else(|_| panic!("a {encoding} server opens a read-only session"));
        assert_eq!(fake::query(&mut client, "SELECT 'first'").await, "SELECT 1");
        assert_eq!(upstream.frames(), vec![query("SELECT 'first'")]);
        assert!(session.refusals().is_empty(), "{encoding}");
    }

    let latin5 = emulated(encoded_login(Some("LATIN5")), false).await;
    let read_write = listen_as(latin5.addr.port(), SessionAccess::ReadWrite).await;
    let mut unaffected = fake::login(read_write.local)
        .await
        .expect("negative control: a read-write session on LATIN5 opens");
    assert_eq!(
        fake::query(&mut unaffected, "SELECT 'rw'").await,
        "SELECT 1"
    );
    assert!(read_write.refusals().is_empty());

    for encoding in [Some("LATIN5"), Some("SQL_ASCII"), Some("WIN1254"), None] {
        let upstream = emulated(encoded_login(encoding), false).await;
        let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
        assert_eq!(
            pipelined_login(session.local).await,
            fake::error_frame(CANNOT_OPEN_READ_ONLY),
            "{encoding:?}: the session closes with the fixed error and nothing else"
        );
        assert_eq!(
            session.refusals(),
            vec![("connect", "read-only escaped")],
            "{encoding:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            upstream.frames().is_empty(),
            "{encoding:?}: the pipelined first Query never reached the upstream"
        );
        let events = session.events().await;
        assert_eq!(
            fake::named(&events, "client_refused")[0]["fields"]["reason"],
            "read_only_escaped",
            "{encoding:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pgbouncer_upstream_fails_closed() {
    let startups: Frames = Arc::new(Mutex::new(Vec::new()));
    let record = startups.clone();
    let upstream = fake::start_with(move |mut tcp| {
        let record = record.clone();
        async move {
            let startup = fake::read_startup(&mut tcp).await?;
            record.lock().unwrap().push(startup.clone());
            if startup.windows(8).any(|window| window == b"options\0") {
                tcp.write_all(&fake::frame(
                    b'E',
                    b"SERROR\0C08P01\0Munsupported startup parameter: options\0\0",
                ))
                .await?;
                return Ok(());
            }
            fake::complete_login(&mut tcp, &[]).await?;
            loop {
                let (tag, _) = fake::read_tagged(&mut tcp).await?;
                if tag == b'Q' {
                    tcp.write_all(&[complete("SELECT 1"), ready()].concat())
                        .await?;
                }
            }
        }
    })
    .await;

    let control = listen_as(upstream.port(), SessionAccess::ReadWrite).await;
    let mut allowed = fake::login(control.local)
        .await
        .expect("negative control: a login without options works");
    assert_eq!(fake::query(&mut allowed, "SELECT 1").await, "SELECT 1");

    let session = listen_as(upstream.port(), SessionAccess::ReadOnly).await;
    let mut client = TcpStream::connect(session.local).await.unwrap();
    client
        .write_all(&zs_proto_postgres::startup_packet("alice", "appdb"))
        .await
        .unwrap();
    assert_eq!(
        closed(&mut client).await,
        fake::error_frame(fake::UNAVAILABLE),
        "the client gets a connection error and nothing else"
    );
    let startups = startups.lock().unwrap().clone();
    assert_eq!(startups.len(), 2);
    assert!(
        startups[1]
            .windows(35)
            .any(|window| window == b"-c default_transaction_read_only=on")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn copy_to_stdout_flows_in_a_read_only_session() {
    let upstream = emulated(&fake::READ_ONLY_LOGIN, false).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();

    send_all(
        &mut client,
        &[query("COPY t TO STDOUT"), query("SELECT 'after'")],
    )
    .await;
    assert_eq!(reply(&mut client).await, [copy_out(), ready()].concat());
    assert_eq!(
        reply(&mut client).await,
        [complete("SELECT 1"), ready()].concat()
    );
    assert_eq!(
        upstream.frames(),
        vec![query("COPY t TO STDOUT"), query("SELECT 'after'")]
    );
    assert!(session.refusals().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn copy_in_and_copy_both_close_a_read_only_session() {
    for statement in ["COPY t FROM STDIN", "START_REPLICATION BOTH"] {
        let upstream = emulated(&fake::READ_ONLY_LOGIN, false).await;
        let control = listen_as(upstream.addr.port(), SessionAccess::ReadWrite).await;
        let mut allowed = fake::login(control.local).await.unwrap();
        send_all(&mut allowed, &[query(statement)]).await;
        let (tag, _) =
            tokio::time::timeout(Duration::from_secs(10), fake::read_tagged(&mut allowed))
                .await
                .unwrap()
                .unwrap();
        assert!(
            matches!(tag, b'G' | b'W'),
            "negative control: a read-write session forwards the copy response"
        );
        assert!(control.refusals().is_empty());

        let upstream = emulated(&fake::READ_ONLY_LOGIN, false).await;
        let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
        let mut client = fake::login(session.local).await.unwrap();
        assert_eq!(
            fake::query(&mut client, "SELECT 'before'").await,
            "SELECT 1"
        );
        send_all(&mut client, &[query(statement), query("SELECT 'next'")]).await;

        assert_eq!(
            closed(&mut client).await,
            Vec::<u8>::new(),
            "{statement}: the copy response is not forwarded"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            upstream.frames(),
            vec![query("SELECT 'before'"), query(statement)],
            "{statement}: the next unit never reached the upstream"
        );
        assert_eq!(
            session.refusals(),
            vec![("connect", "read-only escaped")],
            "{statement}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_closes_after_the_switching_unit_is_still_audited() {
    for drop_socket in [false, true] {
        let upstream = fake::start_with(|mut tcp| async move {
            fake::accept_login(&mut tcp, &fake::READ_ONLY_LOGIN).await?;
            let (tag, _) = fake::read_tagged(&mut tcp).await?;
            assert_eq!(tag, b'Q');
            tokio::time::sleep(Duration::from_millis(200)).await;
            tcp.write_all(
                &[
                    complete("SELECT 1"),
                    fake::parameter_status("default_transaction_read_only", "off"),
                    ready(),
                ]
                .concat(),
            )
            .await?;
            while fake::read_tagged(&mut tcp).await.is_ok() {}
            Ok(())
        })
        .await;
        let session = listen_as(upstream.port(), SessionAccess::ReadOnly).await;
        let mut client = fake::login(session.local).await.unwrap();

        send_all(
            &mut client,
            &[
                query("SELECT zs_hidden(); COMMIT; INSERT INTO t VALUES (2)"),
                fake::frame(b'X', &[]),
            ],
        )
        .await;
        if drop_socket {
            drop(client);
        } else {
            client.shutdown().await.unwrap();
            closed(&mut client).await;
        }

        assert!(
            fake::eventually(|| !session.refusals().is_empty()).await,
            "drop_socket={drop_socket}: no audit"
        );
        assert_eq!(
            session.refusals(),
            vec![("connect", "read-only escaped")],
            "drop_socket={drop_socket}"
        );
    }
}

async fn framing_upstream(bad: Vec<u8>) -> Emulated {
    let frames: Frames = Arc::new(Mutex::new(Vec::new()));
    let record = frames.clone();
    let bad = Arc::new(bad);
    let addr = fake::start_with(move |mut tcp| {
        let (record, bad) = (record.clone(), bad.clone());
        async move {
            fake::accept_login(&mut tcp, &fake::READ_ONLY_LOGIN).await?;
            loop {
                let (tag, body) = fake::read_tagged(&mut tcp).await?;
                record.lock().unwrap().push(fake::frame(tag, &body));
                if body.starts_with(b"SELECT 'bad'") {
                    let _ = tcp
                        .write_all(&[complete("SELECT 1"), bad.to_vec()].concat())
                        .await;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let _ = tcp.write_all(&[complete("AFTER"), ready()].concat()).await;
                } else {
                    tcp.write_all(&[complete("SELECT 1"), ready()].concat())
                        .await?;
                }
            }
        }
    })
    .await;
    Emulated { addr, frames }
}

fn oversized_status() -> Vec<u8> {
    let mut body = b"x\0".to_vec();
    body.extend(std::iter::repeat_n(b'v', 16 * 1024 + 1 - 4 - 3));
    body.push(0);
    let message = fake::frame(b'S', &body);
    assert_eq!(message.len() - 1, 16 * 1024 + 1);
    message
}

#[tokio::test(flavor = "multi_thread")]
async fn every_bad_backend_frame_closes_a_read_only_session() {
    let cases: [(&str, Vec<u8>, Vec<u8>); 6] = [
        ("length 3", vec![b'C', 0, 0, 0, 3], complete("SELECT 1")),
        (
            "length 0x8000_0000",
            vec![b'D', 0x80, 0, 0, 0],
            complete("SELECT 1"),
        ),
        (
            "status of 16 KiB + 1",
            oversized_status(),
            complete("SELECT 1"),
        ),
        (
            "ReadyForQuery of length 6",
            vec![b'Z', 0, 0, 0, 6, b'I', b'I'],
            complete("SELECT 1"),
        ),
        (
            "status without its second NUL",
            fake::frame(b'S', b"x\0y"),
            complete("SELECT 1"),
        ),
        (
            "ReadyForQuery with no unit outstanding",
            [ready(), ready()].concat(),
            [complete("SELECT 1"), ready()].concat(),
        ),
    ];
    for (name, bad, allowed) in cases {
        let upstream = framing_upstream(bad).await;
        let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
        let mut client = fake::login(session.local).await.unwrap();
        assert_eq!(fake::query(&mut client, "SELECT 'good'").await, "SELECT 1");

        send_all(&mut client, &[query("SELECT 'bad'")]).await;
        let rest = closed(&mut client).await;
        assert!(
            allowed.starts_with(&rest),
            "{name}: nothing from the bad message on reached the client: {rest:?}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            upstream.frames(),
            vec![query("SELECT 'good'"), query("SELECT 'bad'")],
            "{name}"
        );
        let events = session.events().await;
        let failed = fake::named(&events, "conn_failed");
        assert_eq!(failed.len(), 1, "{name}: {events:?}");
        assert_eq!(failed[0]["fields"]["stage"], "relay", "{name}");
        assert_eq!(
            failed[0]["error"]["kind"], "invalid_data",
            "{name}: closed by the framing check: {failed:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_backend_message_larger_than_the_buffer_reaches_the_client_intact() {
    let mut row = 1u16.to_be_bytes().to_vec();
    row.extend_from_slice(&(100 * 1024u32).to_be_bytes());
    row.extend((0..100 * 1024).map(|at| (at % 251) as u8));
    let reply = [fake::frame(b'D', &row), complete("SELECT 1"), ready()].concat();
    let sent = reply.clone();
    let upstream = fake::start_with(move |mut tcp| {
        let sent = sent.clone();
        async move {
            fake::accept_login(&mut tcp, &fake::READ_ONLY_LOGIN).await?;
            loop {
                fake::read_tagged(&mut tcp).await?;
                for chunk in sent.chunks(7 * 1024 + 3) {
                    tcp.write_all(chunk).await?;
                    tcp.flush().await?;
                }
            }
        }
    })
    .await;
    let session = listen_as(upstream.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();

    send_all(&mut client, &[query("SELECT big")]).await;
    let mut received = vec![0u8; reply.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, reply);
    assert_eq!(fake::query(&mut client, "SELECT big").await, "SELECT 1");
}

const SCREEN_CAP: usize = 64 << 20;

async fn whole_frames_upstream() -> Emulated {
    let frames: Frames = Arc::new(Mutex::new(Vec::new()));
    let record = frames.clone();
    let addr = fake::start_with(move |mut tcp| {
        let record = record.clone();
        async move {
            fake::accept_login(&mut tcp, &fake::READ_ONLY_LOGIN).await?;
            loop {
                let mut header = [0u8; 5];
                tcp.read_exact(&mut header).await?;
                let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
                let mut message = header.to_vec();
                message.resize(1 + length, 0);
                tcp.read_exact(&mut message[5..]).await?;
                record.lock().unwrap().push(message);
                if header[0] == b'Q' {
                    tcp.write_all(&[complete("SELECT 1"), ready()].concat())
                        .await?;
                }
            }
        }
    })
    .await;
    Emulated { addr, frames }
}

fn oversized_header() -> Vec<u8> {
    let mut header = vec![b'Q'];
    header.extend_from_slice(&((SCREEN_CAP + 5) as u32).to_be_bytes());
    header
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_text_is_screened_and_one_above_64_mib_closes_a_read_only_session() {
    let padding = "a".repeat(2 << 20);
    let long = format!("SELECT '{padding}'");
    let long_escape = format!("SELECT '{padding}'; {ESCAPE}");

    let control = whole_frames_upstream().await;
    let read_write = listen_as(control.addr.port(), SessionAccess::ReadWrite).await;
    let mut unaffected = fake::login(read_write.local).await.unwrap();
    let mut over = oversized_header();
    over.extend(std::iter::repeat_n(b' ', SCREEN_CAP));
    over.push(0);
    send_all(&mut unaffected, &[over.clone()]).await;
    assert_eq!(
        reply(&mut unaffected).await,
        [complete("SELECT 1"), ready()].concat()
    );
    assert!(
        fake::eventually(|| control.frames() == vec![over.clone()]).await,
        "negative control: a read-write session forwards a Query above 64 MiB"
    );
    assert!(read_write.refusals().is_empty());

    let upstream = whole_frames_upstream().await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();
    assert_eq!(fake::query(&mut client, &long).await, "SELECT 1");
    fake::query(&mut client, &long_escape).await;
    assert_eq!(
        upstream.frames(),
        vec![query(&long), query(QUERY_REFUSAL)],
        "a text above 1 MiB is forwarded whole, or replaced when it holds a listed word"
    );
    assert_eq!(session.refusals(), vec![("query", "read-only")]);

    let mut oversized = oversized_header();
    oversized.extend_from_slice(b"SELECT 1");
    send_all(&mut client, &[oversized]).await;
    assert_eq!(closed(&mut client).await, Vec::<u8>::new());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        upstream.frames().len(),
        2,
        "no byte of the oversized Query was forwarded"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flush_without_sync_lets_the_unit_continue() {
    let upstream = emulated(&fake::READ_ONLY_LOGIN, false).await;
    let session = listen_as(upstream.addr.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();
    let flush = fake::frame(b'H', &[]);

    send_all(
        &mut client,
        &[
            parse("", "SELECT 1", &[]),
            bind(""),
            execute(),
            flush.clone(),
        ],
    )
    .await;
    assert_eq!(
        until_tag(&mut client, b'C').await,
        [
            fake::frame(b'1', &[]),
            fake::frame(b'2', &[]),
            complete("SELECT 1")
        ]
        .concat(),
        "the results of a flushed unit arrive before its Sync"
    );
    send_all(&mut client, &[bind(""), execute(), sync()]).await;
    assert_eq!(
        reply(&mut client).await,
        [fake::frame(b'2', &[]), complete("SELECT 1"), ready()].concat()
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fake::query(&mut client, "SELECT 'after'").await, "SELECT 1");
    assert_eq!(upstream.frames().len(), 8);
}

#[tokio::test(flavor = "multi_thread")]
async fn terminate_flows_while_a_unit_runs() {
    let terminated = Arc::new(Mutex::new(false));
    let record = terminated.clone();
    let upstream = fake::start_with(move |mut tcp| {
        let record = record.clone();
        async move {
            fake::accept_login(&mut tcp, &fake::READ_ONLY_LOGIN).await?;
            let (tag, _) = fake::read_tagged(&mut tcp).await?;
            assert_eq!(tag, b'Q');
            let (tag, _) = fake::read_tagged(&mut tcp).await?;
            *record.lock().unwrap() = tag == b'X';
            Ok(())
        }
    })
    .await;
    let session = listen_as(upstream.port(), SessionAccess::ReadOnly).await;
    let mut client = fake::login(session.local).await.unwrap();

    send_all(
        &mut client,
        &[query("SELECT pg_sleep(60)"), fake::frame(b'X', &[])],
    )
    .await;
    assert!(fake::eventually(|| *terminated.lock().unwrap()).await);
    closed(&mut client).await;
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
