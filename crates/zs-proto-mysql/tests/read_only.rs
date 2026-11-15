#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fake::{CLIENT_CAPS, Flow, Script};
use zs_diag::DiagLog;
use zs_proto_mysql::packet::{self, CLIENT_QUERY_ATTRIBUTES, COM_QUERY, COM_STMT_PREPARE};
use zs_proto_mysql::{
    MAX_SCREENED_COMMAND, READ_ONLY_REFUSED, REFUSAL, SESSION_START, UpstreamTls,
};
use zs_protocol::SessionAccess;

const MARKER: &str = "zs-statement-marker";
const ALLOWED: [u8; 13] = [
    0x01, 0x02, 0x03, 0x04, 0x09, 0x0e, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
];

struct Rig {
    fake: fake::Fake,
    local: SocketAddr,
    diag: DiagLog,
    path: PathBuf,
    refusals: fake::Refusals,
    _home: tempfile::TempDir,
}

impl Rig {
    async fn start(script: Script, access: SessionAccess) -> Self {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("diag.jsonl");
        let diag = DiagLog::open_with_cap(&path, "t-1", 1 << 20).unwrap();
        let fake = fake::start(script).await;
        let (audit, refusals) = fake::audit_recorder();
        let local = fake::listen(
            "127.0.0.1",
            fake.addr.port(),
            UpstreamTls::WhenOffered,
            fake::materialize_with(fake::PASSWORD, access),
            diag.clone(),
            Some(audit),
        )
        .await;
        Self {
            fake,
            local,
            diag,
            path,
            refusals,
            _home: home,
        }
    }

    async fn login(&self, capabilities: u32) -> fake::Session {
        let session = fake::login(self.local, capabilities).await;
        assert_eq!(
            session.reply.payload.first(),
            Some(&packet::OK_HEADER),
            "positive control: the login works"
        );
        session
    }

    fn commands(&self) -> Vec<Vec<u8>> {
        self.fake.seen(|s| s.commands.clone())
    }

    fn refusals(&self) -> Vec<(&'static str, &'static str)> {
        self.refusals.lock().unwrap().clone()
    }

    async fn log(&self) -> (String, Vec<serde_json::Value>) {
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.diag.close();
        let text = std::fs::read_to_string(&self.path).unwrap();
        let events = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        (text, events)
    }
}

fn named(events: &[serde_json::Value], name: &str, field: &str) -> Vec<String> {
    events
        .iter()
        .filter(|e| e["event"] == name && e["component"] == "mysql")
        .map(|e| e["fields"][field].as_str().unwrap_or_default().to_string())
        .collect()
}

fn native() -> Script {
    Script::new(packet::NATIVE_PASSWORD, Flow::Accept)
}

fn with_header(command: u8, attributes: bool, text: &[u8]) -> Vec<u8> {
    let mut out = vec![command];
    if attributes {
        out.extend_from_slice(&[0x00, 0x01]);
    }
    out.extend_from_slice(text);
    out
}

fn com_query(text: &str) -> Vec<u8> {
    with_header(COM_QUERY, false, text.as_bytes())
}

fn refusal(attributes: bool) -> Vec<u8> {
    with_header(COM_QUERY, attributes, REFUSAL.as_bytes())
}

fn session_start(attributes: bool) -> Vec<u8> {
    with_header(COM_QUERY, attributes, SESSION_START.as_bytes())
}

fn one_attribute(text: &str) -> Vec<u8> {
    let mut out = vec![COM_QUERY, 0x01, 0x01, 0x00, 0x01, 0xfe, 0x00];
    packet::put_lenenc_bytes(&mut out, b"zs_attr");
    packet::put_lenenc_bytes(&mut out, b"value");
    out.extend_from_slice(text.as_bytes());
    out
}

async fn answered(session: &mut fake::Session, command: &[u8]) -> u8 {
    let reply = session.command(command).await.unwrap();
    assert!(
        reply.payload.ends_with(fake::OK_INFO),
        "the upstream answered the command"
    );
    reply.seq
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_only_session_sets_the_mode_before_the_first_client_command() {
    let rig = Rig::start(native(), SessionAccess::ReadOnly).await;
    let mut session = rig.login(CLIENT_CAPS).await;
    assert_eq!(
        session.reply.seq, 2,
        "the client's sequence ids are not disturbed"
    );
    assert_eq!(session.reply.payload, packet::ok_packet(fake::OK_INFO));

    let reply = session.command(&com_query("SELECT 1")).await.unwrap();
    assert_eq!(reply.seq, 1);
    assert!(reply.payload.ends_with(fake::OK_INFO));
    assert_eq!(
        rig.commands(),
        vec![session_start(false), com_query("SELECT 1")]
    );
    assert!(rig.refusals().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_start_that_is_not_ok_denies_the_connection() {
    let positive = Rig::start(native(), SessionAccess::ReadOnly).await;
    positive.login(CLIENT_CAPS).await;

    let refused = packet::err_packet(1227, "42000", "Access denied; you need the privilege");
    for reply in [refused, vec![0x01], vec![0xfe, 0, 0, 2, 0]] {
        let rig = Rig::start(native().with_first_reply(reply), SessionAccess::ReadOnly).await;
        let mut session = fake::login(rig.local, CLIENT_CAPS).await;
        assert_eq!(session.reply.payload, READ_ONLY_REFUSED.packet());
        assert_eq!(session.reply.seq, 2);
        assert!(session.closed().await);
        assert_eq!(rig.commands(), vec![session_start(false)]);
        assert_eq!(rig.refusals(), vec![("connect", "read-only")]);
        let (_, events) = rig.log().await;
        assert_eq!(named(&events, "client_refused", "reason"), ["read_only"]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mariadb_greeting_fails_closed() {
    let mariadb = || native().with_server_version(b"5.5.5-10.11.6-MariaDB-log");
    let rig = Rig::start(mariadb(), SessionAccess::ReadWrite).await;
    let mut session = rig.login(CLIENT_CAPS).await;
    answered(&mut session, &com_query("SELECT 1")).await;
    assert_eq!(
        rig.commands(),
        vec![com_query("SELECT 1")],
        "negative control: a read-write session to MariaDB is unchanged"
    );

    let rig = Rig::start(mariadb(), SessionAccess::ReadOnly).await;
    let mut session = fake::login(rig.local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload, READ_ONLY_REFUSED.packet());
    assert!(session.closed().await);
    assert_eq!(
        rig.fake.seen(|s| s.responses),
        0,
        "no login was sent upstream"
    );
    assert!(rig.commands().is_empty());
    assert_eq!(rig.refusals(), vec![("connect", "read-only")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn query_attributes_are_refused_unless_empty() {
    let script = || native().with_capabilities(CLIENT_QUERY_ATTRIBUTES);
    let rig = Rig::start(script(), SessionAccess::ReadOnly).await;
    let mut session = rig.login(CLIENT_CAPS | CLIENT_QUERY_ATTRIBUTES).await;
    assert_ne!(
        rig.fake.seen(|s| s.capabilities) & CLIENT_QUERY_ATTRIBUTES,
        0,
        "the flag was agreed upstream"
    );

    let innocent = with_header(COM_QUERY, true, b"SELECT 1");
    answered(&mut session, &innocent).await;
    answered(
        &mut session,
        &with_header(COM_QUERY, true, b"PREPARE s FROM @q"),
    )
    .await;
    answered(&mut session, &one_attribute("SELECT 1")).await;
    answered(&mut session, &[COM_QUERY]).await;
    answered(&mut session, &[COM_QUERY, 0x00]).await;
    answered(&mut session, &[COM_QUERY, 0x01, 0x01]).await;
    let after = with_header(COM_QUERY, true, b"SELECT 2");
    answered(&mut session, &after).await;
    assert_eq!(
        rig.commands(),
        vec![
            session_start(true),
            innocent,
            refusal(true),
            refusal(true),
            refusal(true),
            refusal(true),
            refusal(true),
            after,
        ]
    );
    let (_, events) = rig.log().await;
    assert_eq!(
        named(&events, "statement_refused", "word"),
        [
            "prepare",
            "query_attributes",
            "query_attributes",
            "query_attributes",
            "query_attributes"
        ]
    );

    let rig = Rig::start(script(), SessionAccess::ReadWrite).await;
    let mut session = rig.login(CLIENT_CAPS | CLIENT_QUERY_ATTRIBUTES).await;
    let attributed = one_attribute("SET SESSION TRANSACTION READ WRITE");
    answered(&mut session, &attributed).await;
    assert_eq!(
        rig.commands(),
        vec![attributed],
        "negative control: a read-write session forwards attributes unchanged"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_attribute_layout_follows_the_flag_both_legs_agreed() {
    let rig = Rig::start(native(), SessionAccess::ReadOnly).await;
    let mut session = rig.login(CLIENT_CAPS | CLIENT_QUERY_ATTRIBUTES).await;
    assert_eq!(
        rig.fake.seen(|s| s.capabilities) & CLIENT_QUERY_ATTRIBUTES,
        0,
        "the server did not offer the flag"
    );
    answered(&mut session, &com_query("SELECT 1")).await;
    answered(&mut session, &com_query("KILL 1")).await;

    let offered = Rig::start(
        native().with_capabilities(CLIENT_QUERY_ATTRIBUTES),
        SessionAccess::ReadOnly,
    )
    .await;
    let mut other = offered.login(CLIENT_CAPS).await;
    answered(&mut other, &com_query("SELECT 1")).await;

    assert_eq!(
        rig.commands(),
        vec![session_start(false), com_query("SELECT 1"), refusal(false)]
    );
    assert_eq!(
        offered.commands(),
        vec![session_start(false), com_query("SELECT 1")]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_connection_is_refused() {
    let rig = Rig::start(native(), SessionAccess::ReadOnly).await;
    let mut session = rig.login(CLIENT_CAPS).await;
    answered(&mut session, &com_query("SELECT 1")).await;
    answered(&mut session, &[packet::COM_RESET_CONNECTION]).await;
    answered(&mut session, &com_query("SELECT 2")).await;
    assert_eq!(
        rig.commands(),
        vec![
            session_start(false),
            com_query("SELECT 1"),
            refusal(false),
            com_query("SELECT 2"),
        ]
    );
    assert_eq!(rig.refusals(), vec![("query", "read-only")]);
    let (_, events) = rig.log().await;
    assert_eq!(
        named(&events, "command_refused", "command"),
        ["com_reset_connection"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_command_outside_the_allowlist_is_replaced() {
    let rig = Rig::start(native(), SessionAccess::ReadOnly).await;
    let mut session = rig.login(CLIENT_CAPS).await;
    let mut expected = vec![session_start(false)];
    let mut refused = 0;
    for byte in 0..=u8::MAX {
        if byte == packet::COM_QUIT || byte == packet::COM_CHANGE_USER {
            continue;
        }
        let command = [byte, b'z', b's'];
        answered(&mut session, &command).await;
        if ALLOWED.contains(&byte) {
            expected.push(command.to_vec());
        } else {
            expected.push(refusal(false));
            refused += 1;
        }
    }
    answered(&mut session, &[]).await;
    expected.push(refusal(false));
    assert_eq!(rig.commands(), expected);
    assert_eq!(refused, 256 - 13 - 1);
    assert_eq!(rig.refusals().len(), refused + 1);
    let (log, events) = rig.log().await;
    let commands = named(&events, "command_refused", "command");
    assert_eq!(commands.len(), refused + 1, "{log}");
    assert!(commands.contains(&"com_binlog_dump".to_string()));
    assert!(commands.contains(&"unknown".to_string()));
    assert_eq!(commands.last().map(String::as_str), Some("empty"));
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_statements_are_replaced_audited_and_their_text_is_never_logged() {
    let rig = Rig::start(native(), SessionAccess::ReadOnly).await;
    let mut session = rig.login(CLIENT_CAPS).await;
    let global = format!("SET GLOBAL max_connections = 1 -- {MARKER}");
    answered(&mut session, &com_query(&global)).await;
    let prepare = with_header(
        COM_STMT_PREPARE,
        false,
        format!("SET TRANSACTION READ WRITE /* {MARKER} */").as_bytes(),
    );
    answered(&mut session, &prepare).await;
    let innocent = with_header(COM_STMT_PREPARE, false, b"SELECT ? FROM dual");
    answered(&mut session, &innocent).await;
    assert_eq!(
        rig.commands(),
        vec![
            session_start(false),
            refusal(false),
            with_header(COM_STMT_PREPARE, false, REFUSAL.as_bytes()),
            innocent,
        ]
    );
    assert_eq!(
        rig.refusals(),
        vec![("query", "read-only"), ("query", "read-only")]
    );
    let (log, events) = rig.log().await;
    assert_eq!(
        named(&events, "statement_refused", "word"),
        ["global", "read write"]
    );
    assert!(!log.contains(MARKER), "{log}");
    assert!(!log.contains("max_connections"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_write_session_forwards_every_byte_unchanged() {
    let rig = Rig::start(native(), SessionAccess::ReadWrite).await;
    let mut session = rig.login(CLIENT_CAPS).await;
    let mut long = com_query("SELECT 1 ");
    long.resize(packet::MAX_PAYLOAD + 5, b' ');
    long.extend_from_slice(b"; SET GLOBAL x = 1");
    let sent = vec![
        com_query("SET SESSION TRANSACTION READ WRITE"),
        with_header(COM_STMT_PREPARE, false, b"PREPARE s FROM @q"),
        vec![packet::COM_RESET_CONNECTION],
        vec![0x30, 0x31],
        long,
    ];
    for command in &sent {
        answered(&mut session, command).await;
    }
    assert_eq!(rig.commands(), sent, "no SET injected, nothing replaced");
    assert!(rig.refusals().is_empty());
    let (_, events) = rig.log().await;
    assert!(named(&events, "statement_refused", "word").is_empty());
    assert!(named(&events, "command_refused", "command").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn command_over_16mb_is_reassembled_then_scanned() {
    let rig = Rig::start(native(), SessionAccess::ReadOnly).await;
    let mut session = rig.login(CLIENT_CAPS).await;

    let mut innocent = com_query("SELECT '");
    innocent.resize(packet::MAX_PAYLOAD + 10, b'a');
    innocent.push(b'\'');
    assert_eq!(answered(&mut session, &innocent).await, 2);

    let mut escape = com_query("SELECT 1 ");
    escape.resize(packet::MAX_PAYLOAD + 5, b' ');
    escape.extend_from_slice(b"; SET GLOBAL max_connections = 1");
    assert_eq!(
        answered(&mut session, &escape).await,
        2,
        "the replacement keeps the packet count, so the reply has the sequence id the client expects"
    );

    let mut exact = com_query("SELECT '");
    exact.resize(packet::MAX_PAYLOAD - 1, b'b');
    exact.push(b'\'');
    assert_eq!(answered(&mut session, &exact).await, 2);

    let mut data = vec![0x18, 1, 0, 0, 0, 0, 0];
    data.resize(packet::MAX_PAYLOAD, b'x');
    data.push(packet::COM_RESET_CONNECTION);
    data.extend_from_slice(b"SET GLOBAL max_connections = 1");
    answered(&mut session, &data).await;

    answered(&mut session, &com_query("SELECT 2")).await;
    let commands = rig.commands();
    assert_eq!(commands.len(), 6);
    assert_eq!(commands[0], session_start(false));
    assert!(
        commands[1] == innocent,
        "an innocent 16 MB+ query passes byte for byte"
    );
    let mut padded = refusal(false);
    padded.resize(escape.len(), b' ');
    assert!(
        commands[2] == padded,
        "an escape after the first 16 MB is refused"
    );
    assert!(
        commands[3] == exact,
        "a query of exactly 0xffffff bytes passes"
    );
    assert!(
        commands[4] == data,
        "continuation packets of an allowed command are data"
    );
    assert_eq!(commands[5], com_query("SELECT 2"));

    let mut huge = com_query("SELECT '");
    huge.resize(MAX_SCREENED_COMMAND + 1, b'c');
    let _ = packet::write_packet(&mut session.stream, 0, &huge).await;
    assert!(
        session.closed().await,
        "a command over the cap closes the session"
    );
    assert_eq!(
        rig.commands().len(),
        6,
        "nothing of it reached the upstream"
    );

    let mut session = rig.login(CLIENT_CAPS).await;
    let mut split = vec![packet::COM_RESET_CONNECTION];
    split.resize(packet::MAX_PAYLOAD + 1, 0);
    let _ = packet::write_packet(&mut session.stream, 0, &split).await;
    assert!(
        session.closed().await,
        "a refused command split over packets closes the session"
    );
    assert_eq!(rig.commands().len(), 7);
    assert_eq!(rig.commands()[6], session_start(false));
    let (_, events) = rig.log().await;
    assert_eq!(
        named(&events, "command_refused", "reason"),
        ["too_large", "split"]
    );
}
