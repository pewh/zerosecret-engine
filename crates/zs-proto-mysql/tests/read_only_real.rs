#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;

use fake::CLIENT_CAPS;
use zs_diag::DiagLog;
use zs_proto_mysql::UpstreamTls;
use zs_proto_mysql::packet::{self, CLIENT_QUERY_ATTRIBUTES, COM_QUERY, COM_STMT_PREPARE};
use zs_protocol::SessionAccess;

const ROOT_PASSWORD: &str = "zs-test-root";
const CAPS: u32 = CLIENT_CAPS & !packet::CLIENT_CONNECT_WITH_DB;
const REFUSED_TEXT: &str = "zs: refused, read-only resource";
const SERVER_STATUS_IN_TRANS: u8 = 0x01;

type Server = (String, u16);

fn address(var: &str) -> Option<Server> {
    let value = std::env::var(var).ok().filter(|v| !v.is_empty())?;
    let (host, port) = value.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

fn plain() -> Option<Server> {
    let found = address("ZS_TEST_MYSQL")
        .and(
            std::env::var("ZS_TEST_MYSQL_CERTS")
                .ok()
                .filter(|v| !v.is_empty()),
        )
        .and_then(|_| address("ZS_TEST_MYSQL_PLAIN"));
    assert!(
        found.is_some() || std::env::var("ZS_REQUIRE_MYSQL").is_err(),
        "ZS_REQUIRE_MYSQL is set: ZS_TEST_MYSQL, ZS_TEST_MYSQL_PLAIN and ZS_TEST_MYSQL_CERTS must be set"
    );
    found
}

async fn listen(server: &Server, access: SessionAccess) -> SocketAddr {
    fake::listen(
        &server.0,
        server.1,
        UpstreamTls::WhenOffered,
        fake::materialize_with(ROOT_PASSWORD, access),
        DiagLog::disabled(),
        None,
    )
    .await
}

async fn open(server: &Server, access: SessionAccess, capabilities: u32) -> fake::Session {
    let local = listen(server, access).await;
    let session = fake::login_as(local, capabilities, b"root", None).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control: the login works"
    );
    session
}

async fn read_only(server: &Server) -> fake::Session {
    open(server, SessionAccess::ReadOnly, CAPS).await
}

async fn read_write(server: &Server) -> fake::Session {
    open(server, SessionAccess::ReadWrite, CAPS).await
}

fn error(answer: &[u8]) -> Option<(u16, String)> {
    packet::ServerError::parse(answer)
        .ok()
        .map(|e| (e.code, e.message))
}

fn is_refusal(answer: &[u8]) -> bool {
    error(answer) == Some((1792, REFUSED_TEXT.to_string()))
}

fn is_read_only_error(answer: &[u8]) -> bool {
    error(answer).is_some_and(|(code, message)| code == 1792 && message.contains("READ ONLY"))
}

async fn bytes(session: &mut fake::Session, text: &[u8]) -> Vec<u8> {
    let mut command = vec![COM_QUERY];
    command.extend_from_slice(text);
    session.run(&command).await.unwrap()
}

async fn works(session: &mut fake::Session, sql: &str) -> Vec<u8> {
    let answer = session.query(sql).await.unwrap();
    assert!(error(&answer).is_none(), "{sql}: {:?}", error(&answer));
    answer
}

async fn insert_is_read_only(session: &mut fake::Session, db: &str, after: &str) {
    let answer = session
        .query(&format!("INSERT INTO {db}.t VALUES (1)"))
        .await
        .unwrap();
    assert!(
        is_read_only_error(&answer),
        "after {after}: {:?}",
        error(&answer)
    );
}

async fn fresh_database(server: &Server, db: &str) -> fake::Session {
    let mut admin = read_write(server).await;
    works(&mut admin, &format!("DROP DATABASE IF EXISTS {db}")).await;
    works(&mut admin, &format!("CREATE DATABASE {db}")).await;
    works(&mut admin, &format!("CREATE TABLE {db}.t (id INT)")).await;
    admin
}

async fn drop_database(admin: &mut fake::Session, db: &str) {
    works(admin, &format!("DROP DATABASE {db}")).await;
}

async fn rows(admin: &mut fake::Session, db: &str) -> Vec<u8> {
    works(admin, &format!("SELECT COUNT(*) FROM {db}.t")).await
}

fn status(ok: &[u8]) -> u8 {
    assert_eq!(ok.first(), Some(&packet::OK_HEADER), "an OK packet");
    ok[3]
}

#[tokio::test(flavor = "multi_thread")]
async fn session_starts_read_only_and_insert_gets_1792() {
    let Some(server) = plain() else { return };
    let db = "zs_ro_start";
    let mut admin = fresh_database(&server, db).await;
    let empty = rows(&mut admin, db).await;

    let mut session = read_only(&server).await;
    works(&mut session, "SELECT 1").await;
    insert_is_read_only(&mut session, db, "login").await;
    assert_eq!(rows(&mut admin, db).await, empty);

    let mut writer = read_write(&server).await;
    works(&mut writer, &format!("INSERT INTO {db}.t VALUES (1)")).await;
    assert_ne!(
        rows(&mut admin, db).await,
        empty,
        "negative control: the same INSERT succeeds read-write"
    );
    drop_database(&mut admin, db).await;
}

const ESCAPES: [&str; 15] = [
    "SET SESSION TRANSACTION READ WRITE",
    "SET @@session.transaction_read_only = 0",
    "/*!80000 set transaction_read_only = 0 */",
    "START TRANSACTION READ WRITE",
    "SET TRANSACTION READ WRITE",
    "PREPARE s FROM @q",
    "EXECUTE s",
    "CALL sys.execute_prepared_stmt(CONCAT('SET SESSION transaction', '_read_only = 0'))",
    "SELECT 1 INTO OUTFILE '/var/lib/mysql-files/zs-ro-probe.txt'",
    "SELECT 1 INTO DUMPFILE '/var/lib/mysql-files/zs-ro-probe.bin'",
    "SET GLOBAL net_retry_count = 11",
    "SET PERSIST_ONLY net_retry_count = 11",
    "SET PERSIST net_retry_count = 11",
    "SELECT LOAD_FILE('/etc/hostname')",
    "KILL 4242424",
];

#[tokio::test(flavor = "multi_thread")]
async fn every_spike_escape_is_refused() {
    let Some(server) = plain() else { return };
    let db = "zs_ro_escape";
    let mut admin = fresh_database(&server, db).await;
    let empty = rows(&mut admin, db).await;
    let global = works(&mut admin, "SELECT @@global.net_retry_count").await;

    for escape in [
        "SET SESSION TRANSACTION READ WRITE",
        "SET @@session.transaction_read_only = 0",
        "/*!80000 set transaction_read_only = 0 */",
        "SET TRANSACTION READ WRITE",
        "CALL sys.execute_prepared_stmt(CONCAT('SET SESSION transaction', '_read_only = 0'))",
    ] {
        let mut control = read_write(&server).await;
        works(&mut control, "SET SESSION transaction_read_only = ON").await;
        insert_is_read_only(&mut control, db, "control setup").await;
        works(&mut control, escape).await;
        works(&mut control, &format!("INSERT INTO {db}.t VALUES (1)")).await;
        works(&mut admin, &format!("DELETE FROM {db}.t")).await;
    }
    let mut control = read_write(&server).await;
    works(&mut control, "SET SESSION transaction_read_only = ON").await;
    works(
        &mut control,
        "SET @q = CONCAT('SET SESSION transaction', '_read_only = 0')",
    )
    .await;
    works(&mut control, "PREPARE s FROM @q").await;
    works(&mut control, "EXECUTE s").await;
    works(&mut control, &format!("INSERT INTO {db}.t VALUES (1)")).await;
    works(&mut admin, &format!("DELETE FROM {db}.t")).await;
    works(&mut control, "SET GLOBAL net_retry_count = 11").await;
    works(
        &mut control,
        &format!("SET GLOBAL net_retry_count = {}", count(&global)),
    )
    .await;
    works(&mut control, "SET PERSIST_ONLY net_retry_count = 11").await;
    works(&mut control, "RESET PERSIST net_retry_count").await;

    let mut session = read_only(&server).await;
    works(
        &mut session,
        "SET @q = CONCAT('SET SESSION transaction', '_read_only = 0')",
    )
    .await;
    for escape in ESCAPES {
        let answer = session.query(escape).await.unwrap();
        assert!(is_refusal(&answer), "{escape}: {:?}", error(&answer));
        insert_is_read_only(&mut session, db, escape).await;
    }
    let answer = session.run(&[packet::COM_RESET_CONNECTION]).await.unwrap();
    assert!(
        is_refusal(&answer),
        "COM_RESET_CONNECTION: {:?}",
        error(&answer)
    );
    insert_is_read_only(&mut session, db, "COM_RESET_CONNECTION").await;
    works(&mut session, "SELECT 1").await;

    assert_eq!(rows(&mut admin, db).await, empty);
    assert_eq!(
        works(&mut admin, "SELECT @@global.net_retry_count").await,
        global
    );
    let persisted = works(
        &mut admin,
        "SELECT COUNT(*) FROM performance_schema.persisted_variables WHERE VARIABLE_NAME = 'net_retry_count'",
    )
    .await;
    assert!(
        persisted.windows(2).any(|w| w == [1, b'0']),
        "nothing was persisted"
    );
    drop_database(&mut admin, db).await;
}

fn count(answer: &[u8]) -> String {
    let digits: Vec<u8> = answer
        .iter()
        .rev()
        .skip(5)
        .take_while(|b| b.is_ascii_digit())
        .copied()
        .collect();
    digits.iter().rev().map(|b| char::from(*b)).collect()
}

const GBK_ESCAPES: [&[u8]; 3] = [
    b"SET @x = '\x81\x5c', @@session.transaction_read_only = 0",
    b"SET @x = '\x81A', @@session.transaction_read_only = 0",
    b"PREPARE s FROM '\x81\x5cSELECT 1'",
];

#[tokio::test(flavor = "multi_thread")]
async fn escapes_in_gbk_client_charset_are_refused() {
    let Some(server) = plain() else { return };
    let db = "zs_ro_gbk";
    let mut admin = fresh_database(&server, db).await;
    let empty = rows(&mut admin, db).await;

    for escape in &GBK_ESCAPES[..2] {
        let mut control = read_write(&server).await;
        works(&mut control, "SET NAMES gbk").await;
        works(&mut control, "SET SESSION transaction_read_only = ON").await;
        insert_is_read_only(&mut control, db, "control setup").await;
        let answer = bytes(&mut control, escape).await;
        assert!(error(&answer).is_none(), "{escape:?}: {:?}", error(&answer));
        works(&mut control, &format!("INSERT INTO {db}.t VALUES (1)")).await;
        works(&mut admin, &format!("DELETE FROM {db}.t")).await;
    }

    let mut session = read_only(&server).await;
    works(&mut session, "SET NAMES gbk").await;
    for escape in GBK_ESCAPES {
        let answer = bytes(&mut session, escape).await;
        assert!(is_refusal(&answer), "{escape:?}: {:?}", error(&answer));
        insert_is_read_only(&mut session, db, "a GBK escape").await;
    }
    assert_eq!(rows(&mut admin, db).await, empty);
    drop_database(&mut admin, db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn escapes_with_a_no_break_space_of_a_single_byte_charset_are_refused() {
    let Some(server) = plain() else { return };
    let db = "zs_ro_nbsp";
    let mut admin = fresh_database(&server, db).await;
    let empty = rows(&mut admin, db).await;
    let cases: [(&str, &[u8]); 3] = [
        ("latin1", b"SET SESSION TRANSACTION READ\xa0WRITE"),
        ("latin1", b"SET\xa0SESSION\xa0TRANSACTION\xa0READ\xa0WRITE"),
        ("cp852", b"SET SESSION TRANSACTION READ\xffWRITE"),
    ];

    for (charset, escape) in cases {
        let mut control = read_write(&server).await;
        works(&mut control, &format!("SET NAMES {charset}")).await;
        works(&mut control, "SET SESSION transaction_read_only = ON").await;
        insert_is_read_only(&mut control, db, "control setup").await;
        let answer = bytes(&mut control, escape).await;
        assert!(error(&answer).is_none(), "{escape:?}: {:?}", error(&answer));
        works(&mut control, &format!("INSERT INTO {db}.t VALUES (1)")).await;
        works(&mut admin, &format!("DELETE FROM {db}.t")).await;

        let mut session = read_only(&server).await;
        works(&mut session, &format!("SET NAMES {charset}")).await;
        let answer = bytes(&mut session, escape).await;
        assert!(is_refusal(&answer), "{escape:?}: {:?}", error(&answer));
        insert_is_read_only(&mut session, db, charset).await;
    }
    let mut session = read_only(&server).await;
    works(&mut session, "SET NAMES latin1").await;
    let answer = bytes(&mut session, b"PREPARE\xa0s FROM 'SELECT 1'").await;
    assert!(is_refusal(&answer), "{:?}", error(&answer));
    assert_eq!(rows(&mut admin, db).await, empty);
    drop_database(&mut admin, db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_script_gets_read_only_error() {
    let Some(server) = plain() else { return };
    let db = "zs_ro_migration";
    let mut admin = fresh_database(&server, db).await;
    let migration = [
        format!("CREATE TABLE {db}.users (id BIGINT PRIMARY KEY, email VARCHAR(255))"),
        format!("ALTER TABLE {db}.t ADD COLUMN created_at DATETIME"),
        format!("CREATE INDEX t_id ON {db}.t (id)"),
        format!("INSERT INTO {db}.t (id) VALUES (1)"),
        format!("UPDATE {db}.t SET id = 2"),
        format!("DELETE FROM {db}.t"),
        format!("DROP TABLE {db}.t"),
    ];

    let mut session = read_only(&server).await;
    for statement in &migration {
        let answer = session.query(statement).await.unwrap();
        let (code, message) = error(&answer).unwrap_or_default();
        assert_eq!(code, 1792, "{statement}: {message}");
        assert!(message.contains("READ ONLY"), "{statement}: {message}");
    }
    works(&mut session, &format!("SELECT * FROM {db}.t")).await;

    let mut writer = read_write(&server).await;
    for statement in &migration {
        works(&mut writer, statement).await;
    }
    drop_database(&mut admin, db).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn call_of_customer_procedure_that_unsets_is_the_documented_limit() {
    let Some(server) = plain() else { return };
    let db = "zs_ro_limit";
    let mut admin = fresh_database(&server, db).await;
    let empty = rows(&mut admin, db).await;
    works(
        &mut admin,
        &format!("CREATE PROCEDURE {db}.p_unset() SET SESSION transaction_read_only = 0"),
    )
    .await;

    let mut session = read_only(&server).await;
    insert_is_read_only(&mut session, db, "login").await;
    works(&mut session, &format!("CALL {db}.p_unset()")).await;
    works(&mut session, &format!("INSERT INTO {db}.t VALUES (1)")).await;
    assert_ne!(
        rows(&mut admin, db).await,
        empty,
        "the documented limit: a procedure that switches the mode off escapes"
    );
    drop_database(&mut admin, db).await;
}

async fn prepare(session: &mut fake::Session, sql: &str) -> Vec<u8> {
    let mut command = vec![COM_STMT_PREPARE];
    command.extend_from_slice(sql.as_bytes());
    session.command(&command).await.unwrap().payload
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_statement_inside_a_transaction_keeps_the_session_usable() {
    let Some(server) = plain() else { return };
    let db = "zs_ro_txn";
    let mut admin = fresh_database(&server, db).await;

    let mut session = read_only(&server).await;
    let answer = prepare(&mut session, "SET GLOBAL net_retry_count = 11").await;
    assert_eq!(
        error(&answer).map(|e| e.0),
        Some(1295),
        "a refused COM_STMT_PREPARE gets one ERR from the server"
    );
    works(&mut session, "SELECT 1").await;

    let begun = works(&mut session, "START TRANSACTION").await;
    assert_ne!(status(&begun) & SERVER_STATUS_IN_TRANS, 0);
    works(&mut session, &format!("SELECT * FROM {db}.t")).await;
    let answer = session
        .query("SET GLOBAL net_retry_count = 11")
        .await
        .unwrap();
    assert!(is_refusal(&answer), "{:?}", error(&answer));
    let answer = prepare(&mut session, "PREPARE s FROM @q").await;
    assert_eq!(error(&answer).map(|e| e.0), Some(1295));
    let answer = session.query("SET TRANSACTION READ WRITE").await.unwrap();
    assert!(is_refusal(&answer), "{:?}", error(&answer));
    works(&mut session, &format!("SELECT * FROM {db}.t")).await;
    let still = works(&mut session, "DO 1").await;
    assert_ne!(
        status(&still) & SERVER_STATUS_IN_TRANS,
        0,
        "the transaction is still open after the refusals"
    );
    insert_is_read_only(&mut session, db, "a refusal in a transaction").await;
    let committed = works(&mut session, "COMMIT").await;
    assert_eq!(status(&committed) & SERVER_STATUS_IN_TRANS, 0);
    works(&mut session, "SELECT 1").await;
    drop_database(&mut admin, db).await;
}

fn with_header(text: &str) -> Vec<u8> {
    let mut out = vec![COM_QUERY, 0x00, 0x01];
    out.extend_from_slice(text.as_bytes());
    out
}

fn one_attribute(text: &str) -> Vec<u8> {
    let mut out = vec![COM_QUERY, 0x01, 0x01, 0x00, 0x01, 0xfe, 0x00];
    packet::put_lenenc_bytes(&mut out, b"zs_attr");
    packet::put_lenenc_bytes(&mut out, b"value");
    out.extend_from_slice(text.as_bytes());
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn query_attributes_are_refused_unless_empty_on_a_real_server() {
    let Some(server) = plain() else { return };
    let db = "zs_ro_attr";
    let mut admin = fresh_database(&server, db).await;
    let caps = CAPS | CLIENT_QUERY_ATTRIBUTES;

    let mut writer = open(&server, SessionAccess::ReadWrite, caps).await;
    assert_ne!(writer.greeting.capabilities & CLIENT_QUERY_ATTRIBUTES, 0);
    let answer = writer.run(&one_attribute("SELECT 1")).await.unwrap();
    assert!(
        error(&answer).is_none(),
        "negative control: the server reads the attribute block: {:?}",
        error(&answer)
    );

    let mut session = open(&server, SessionAccess::ReadOnly, caps).await;
    let answer = session.run(&with_header("SELECT 1")).await.unwrap();
    assert!(error(&answer).is_none(), "{:?}", error(&answer));
    for refused in [
        with_header("SET SESSION TRANSACTION READ WRITE"),
        one_attribute("SET SESSION TRANSACTION READ WRITE"),
        one_attribute("SELECT 1"),
    ] {
        let answer = session.run(&refused).await.unwrap();
        assert!(is_refusal(&answer), "{:?}", error(&answer));
    }
    let answer = session
        .run(&with_header(&format!("INSERT INTO {db}.t VALUES (1)")))
        .await
        .unwrap();
    assert!(is_read_only_error(&answer), "{:?}", error(&answer));
    let answer = session.run(&with_header("SELECT 2")).await.unwrap();
    assert!(error(&answer).is_none(), "{:?}", error(&answer));
    drop_database(&mut admin, db).await;
}
