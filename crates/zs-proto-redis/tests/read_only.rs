#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fake::{Client, PASSWORD, Script};
use zs_diag::DiagLog;
use zs_proto_redis::resp::Command;
use zs_proto_redis::{
    CREDENTIAL_ECHO_REASON, EXEC_ABORTED, NON_RESP, NON_RESP_REFUSED_REASON, READ_ONLY_REASON,
    READ_ONLY_REFUSED,
};
use zs_protocol::SessionAccess;

const MARKER: &[u8] = b"zs-ro-argument-marker";
const PUSH: &[u8] = b">3\r\n$7\r\nmessage\r\n$2\r\nch\r\n$1\r\nx\r\n";
const ECHOED: &str = "-NOPERM read-only";

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
        Self::with_password(script, access, PASSWORD).await
    }

    async fn with_password(script: Script, access: SessionAccess, password: &'static str) -> Self {
        let fake = fake::start(script).await;
        let home = tempfile::tempdir().unwrap();
        let (path, diag) = fake::diag_log(home.path());
        let (audit, refusals) = fake::audit_recorder();
        let local = fake::listen(
            fake.addr,
            None,
            fake::auth(),
            fake::materialize_with(password, access),
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

    async fn client(&self) -> Client {
        Client::connect(self.local).await
    }

    fn refusals(&self) -> Vec<(&'static str, &'static str)> {
        self.refusals.lock().unwrap().clone()
    }

    async fn log(&self) -> (String, Vec<serde_json::Value>) {
        fake::read_diag(&self.path, self.diag.clone()).await
    }
}

fn frame(parts: &[&[u8]]) -> Vec<u8> {
    Command::new(parts.iter().map(|part| part.to_vec()).collect())
        .encode()
        .to_vec()
}

fn pipeline(commands: &[&[&[u8]]]) -> Vec<u8> {
    commands.iter().flat_map(|command| frame(command)).collect()
}

fn args(parts: &[&[u8]]) -> Vec<Vec<u8>> {
    parts.iter().map(|part| part.to_vec()).collect()
}

fn bulk(value: &str) -> Vec<u8> {
    format!("${}\r\n{value}\r\n", value.len()).into_bytes()
}

fn noperm() -> Vec<u8> {
    READ_ONLY_REFUSED.frame()
}

fn read_only_refusals(count: usize) -> Vec<(&'static str, &'static str)> {
    vec![("query", READ_ONLY_REASON); count]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_takes_the_reply_position_of_the_refused_command() {
    let script = Script::new()
        .with_reply_delay(Duration::from_millis(200))
        .with_reply(bulk("a"))
        .with_reply(bulk("c"));
    let rig = Rig::start(script, SessionAccess::ReadOnly).await;
    let mut client = rig.client().await;

    client
        .send(&pipeline(&[
            &[b"GET", b"a"],
            &[b"SET", b"b", MARKER],
            &[b"GET", b"c"],
        ]))
        .await
        .unwrap();

    assert_eq!(client.read_reply().await, bulk("a"), "the reply to GET a");
    assert_eq!(client.read_reply().await, noperm(), "the refusal of SET");
    assert_eq!(client.read_reply().await, bulk("c"), "the reply to GET c");
    assert_eq!(
        rig.fake.commands(),
        vec![args(&[b"GET", b"a"]), args(&[b"GET", b"c"])]
    );
    assert!(
        !rig.fake.saw_bytes(MARKER),
        "SET never reached the upstream"
    );
    assert_eq!(rig.refusals(), read_only_refusals(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn refusals_before_after_and_between_replies_keep_their_positions() {
    let script = Script::new()
        .with_reply_delay(Duration::from_millis(50))
        .with_reply(bulk("a"))
        .with_reply(bulk("c"));
    let rig = Rig::start(script, SessionAccess::ReadOnly).await;
    let mut client = rig.client().await;

    client
        .send(&pipeline(&[
            &[b"DEL", b"x"],
            &[b"GET", b"a"],
            &[b"FLUSHALL"],
            &[b"CONFIG", b"SET", b"x", b"y"],
            &[b"GET", b"c"],
            &[b"SET", b"y", b"z"],
        ]))
        .await
        .unwrap();

    for expected in [noperm(), bulk("a"), noperm(), noperm(), bulk("c"), noperm()] {
        assert_eq!(client.read_reply().await, expected);
    }
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);
    assert_eq!(rig.fake.names(), vec!["AUTH", "GET", "GET", "PING"]);
    assert_eq!(rig.refusals(), read_only_refusals(4));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_long_mixed_pipeline_keeps_every_reply_in_order() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rig = Rig::start(Script::new(), SessionAccess::ReadOnly).await;
    let total = 10_000;
    let refused = |n: usize| n % 3 == 1;
    let refusals = (0..total).filter(|n| refused(*n)).count();
    let mut write = Vec::new();
    let mut expected = Vec::new();
    for n in 0..total {
        let key = format!("k{n}");
        if refused(n) {
            write.extend_from_slice(&frame(&[b"SET", key.as_bytes(), b"v"]));
            expected.extend_from_slice(&noperm());
        } else {
            write.extend_from_slice(&frame(&[b"GET", key.as_bytes()]));
            expected.extend_from_slice(fake::OK);
        }
    }
    let (mut read, mut send) = rig.client().await.stream.into_split();
    let writer = tokio::spawn(async move { send.write_all(&write).await });
    let mut received = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    while received.len() < expected.len() {
        let read = tokio::time::timeout(Duration::from_secs(20), read.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(read > 0, "the agent closed the session");
        received.extend_from_slice(&buffer[..read]);
    }
    assert!(received == expected, "a reply left its position");
    writer.await.unwrap().unwrap();
    let names = rig.fake.names();
    assert_eq!(names.len(), 1 + total - refusals);
    assert!(names[1..].iter().all(|name| name == "GET"));
    assert_eq!(rig.refusals().len(), refusals);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_command_split_across_segments_is_checked_whole() {
    let rig = Rig::start(Script::new(), SessionAccess::ReadOnly).await;
    let mut client = rig.client().await;
    let bytes = pipeline(&[&[b"SET", b"k", MARKER], &[b"GET", b"k"]]);
    for chunk in bytes.chunks(3) {
        client.send(chunk).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(client.read_reply().await, noperm());
    assert_eq!(client.read_reply().await, fake::OK);
    assert_eq!(rig.fake.commands(), vec![args(&[b"GET", b"k"])]);
    assert!(!rig.fake.saw_bytes(MARKER));
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_command_in_multi_aborts_exec() {
    let script = Script::new()
        .with_reply(fake::OK.to_vec())
        .with_reply(b"+QUEUED\r\n".to_vec())
        .with_reply(fake::OK.to_vec());
    let rig = Rig::start(script, SessionAccess::ReadOnly).await;
    let mut client = rig.client().await;

    client
        .send(&pipeline(&[
            &[b"MULTI"],
            &[b"GET", b"k"],
            &[b"SET", b"k", MARKER],
            &[b"EXEC"],
        ]))
        .await
        .unwrap();

    assert_eq!(client.read_reply().await, fake::OK);
    assert_eq!(client.read_reply().await, b"+QUEUED\r\n".to_vec());
    assert_eq!(client.read_reply().await, noperm());
    assert_eq!(client.read_reply().await, EXEC_ABORTED.frame());
    assert_eq!(
        client.command(&[b"GET", b"k"]).await,
        fake::OK,
        "the session stays usable"
    );
    assert_eq!(
        rig.fake.commands(),
        vec![
            args(&[b"MULTI"]),
            args(&[b"GET", b"k"]),
            args(&[b"DISCARD"]),
            args(&[b"GET", b"k"]),
        ],
        "the upstream never received SET or EXEC"
    );
    assert!(!rig.fake.saw_bytes(MARKER));
    assert_eq!(rig.refusals(), read_only_refusals(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_clean_multi_is_forwarded_unchanged() {
    let exec = b"*2\r\n$1\r\na\r\n$1\r\nb\r\n".to_vec();
    let script = Script::new()
        .with_reply(fake::OK.to_vec())
        .with_reply(b"+QUEUED\r\n".to_vec())
        .with_reply(b"+QUEUED\r\n".to_vec())
        .with_reply(exec.clone());
    let rig = Rig::start(script, SessionAccess::ReadOnly).await;
    let mut client = rig.client().await;

    client
        .send(&pipeline(&[
            &[b"MULTI"],
            &[b"GET", b"a"],
            &[b"GET", b"b"],
            &[b"EXEC"],
        ]))
        .await
        .unwrap();

    for expected in [
        fake::OK.to_vec(),
        b"+QUEUED\r\n".to_vec(),
        b"+QUEUED\r\n".to_vec(),
        exec,
    ] {
        assert_eq!(client.read_reply().await, expected);
    }
    assert_eq!(
        rig.fake.commands(),
        vec![
            args(&[b"MULTI"]),
            args(&[b"GET", b"a"]),
            args(&[b"GET", b"b"]),
            args(&[b"EXEC"]),
        ]
    );
    assert!(rig.refusals().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn resp3_push_frames_do_not_take_a_reply_position() {
    let mut first = PUSH.to_vec();
    first.extend_from_slice(&bulk("a"));
    let mut last = bulk("c");
    last.extend_from_slice(PUSH);
    let script = Script::new()
        .with_reply_delay(Duration::from_millis(50))
        .with_reply(first)
        .with_reply(last);
    let rig = Rig::start(script, SessionAccess::ReadOnly).await;
    let mut client = rig.client().await;
    assert_eq!(
        client.command(&[b"HELLO", b"3"]).await,
        fake::HELLO_REPLY.to_vec()
    );

    client
        .send(&pipeline(&[
            &[b"GET", b"a"],
            &[b"SET", b"b", MARKER],
            &[b"GET", b"c"],
        ]))
        .await
        .unwrap();

    for expected in [PUSH.to_vec(), bulk("a"), noperm(), bulk("c"), PUSH.to_vec()] {
        assert_eq!(client.read_reply().await, expected);
    }
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);
    assert_eq!(
        rig.fake.names(),
        vec!["AUTH", "HELLO", "GET", "GET", "PING"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_written_bytes_pass_the_echo_guard() {
    let control = Rig::with_password(
        Script::accepting(fake::USER, ECHOED),
        SessionAccess::ReadWrite,
        ECHOED,
    )
    .await;
    let mut client = fake::logged_in(control.local).await;
    assert_eq!(
        client.command(&[b"SET", b"k", b"v"]).await,
        fake::OK,
        "negative control: a read-write session gets the upstream reply"
    );

    let rig = Rig::with_password(
        Script::accepting(fake::USER, ECHOED),
        SessionAccess::ReadOnly,
        ECHOED,
    )
    .await;
    let mut client = fake::logged_in(rig.local).await;
    client.send_command(&[b"SET", b"k", b"v"]).await.unwrap();
    let received = client.read_to_end().await;
    assert!(
        !received
            .windows(8)
            .any(|window| ECHOED.as_bytes().windows(8).any(|needle| needle == window)),
        "a credential window reached the client: {}",
        String::from_utf8_lossy(&received)
    );
    assert!(client.closed().await);
    assert_eq!(
        rig.refusals(),
        vec![
            ("query", READ_ONLY_REASON),
            ("connect", CREDENTIAL_ECHO_REASON)
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_command_closes_after_the_earlier_replies() {
    let script = Script::new()
        .with_reply_delay(Duration::from_millis(100))
        .with_reply(bulk("a"));
    let rig = Rig::start(script, SessionAccess::ReadOnly).await;
    let mut client = rig.client().await;
    let mut write = pipeline(&[&[b"GET", b"a"], &[b"SET", b"b", MARKER]]);
    write.extend_from_slice(b"*0\r\n");
    write.extend_from_slice(&frame(&[b"GET", b"c"]));
    client.send(&write).await.unwrap();

    assert_eq!(client.read_reply().await, bulk("a"));
    assert_eq!(client.read_reply().await, noperm());
    assert_eq!(client.read_to_end().await, Vec::<u8>::new());
    assert!(client.closed().await);
    assert_eq!(rig.fake.commands(), vec![args(&[b"GET", b"a"])]);
    assert_eq!(rig.refusals(), read_only_refusals(2));
    let (text, events) = rig.log().await;
    let reasons: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["event"] == "command_refused")
        .map(|event| &event["fields"]["reason"])
        .collect();
    assert_eq!(reasons, ["command", "malformed"], "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_frame_the_parser_rejects_is_refused_after_the_pending_replies() {
    let script = Script::new()
        .with_reply_delay(Duration::from_millis(100))
        .with_reply(bulk("a"));
    let rig = Rig::start(script, SessionAccess::ReadOnly).await;

    for (bad, reply) in [
        (&b"PING\r\n"[..], bulk("a")),
        (&b"*1\r\n:1\r\n"[..], fake::OK.to_vec()),
    ] {
        let mut client = rig.client().await;
        let mut write = pipeline(&[&[b"GET", b"a"], &[b"SET", b"b", MARKER]]);
        write.extend_from_slice(bad);
        client.send(&write).await.unwrap();
        assert_eq!(client.read_reply().await, reply);
        assert_eq!(client.read_reply().await, noperm());
        assert_eq!(client.read_reply().await, NON_RESP.frame());
        assert!(client.closed().await);
    }
    assert_eq!(rig.fake.names(), vec!["AUTH", "GET", "AUTH", "GET"]);
    assert!(!rig.fake.saw_bytes(MARKER));
    assert_eq!(
        rig.refusals(),
        vec![
            ("query", READ_ONLY_REASON),
            ("connect", NON_RESP_REFUSED_REASON),
            ("query", READ_ONLY_REASON),
            ("connect", NON_RESP_REFUSED_REASON),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_is_audited_and_logged_with_the_command_name_only() {
    let rig = Rig::start(Script::new(), SessionAccess::ReadOnly).await;
    let mut client = fake::logged_in(rig.local).await;

    for command in [
        &[&b"SET"[..], MARKER, MARKER][..],
        &[&b"CLIENT"[..], b"Kill", b"ID", MARKER][..],
        &[&b"JSON.SET"[..], MARKER, b"$", MARKER][..],
    ] {
        assert_eq!(client.command(command).await, noperm());
    }
    assert_eq!(client.command(&[b"GET", b"k"]).await, fake::OK);
    assert!(!rig.fake.saw_bytes(MARKER));
    assert_eq!(rig.refusals(), read_only_refusals(3));

    let (text, events) = rig.log().await;
    let refused: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["event"] == "command_refused")
        .collect();
    assert_eq!(refused.len(), 3, "{text}");
    let commands: Vec<&serde_json::Value> = refused
        .iter()
        .map(|event| &event["fields"]["command"])
        .collect();
    assert_eq!(commands, ["set", "client", "json.set"], "{text}");
    assert_eq!(refused[1]["fields"]["subcommand"], "kill", "{text}");
    assert!(refused[0]["fields"].get("subcommand").is_none(), "{text}");
    assert!(
        refused.iter().all(|event| event["audit_seq"] == 7),
        "{text}"
    );
    assert!(
        refused
            .iter()
            .all(|event| event["fields"]["reason"] == "command"),
        "{text}"
    );
    assert!(
        !text.contains(std::str::from_utf8(MARKER).unwrap()),
        "an argument reached the diag log"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_write_session_forwards_writes_unchanged() {
    let rig = Rig::start(Script::new(), SessionAccess::ReadWrite).await;
    let mut client = rig.client().await;
    let commands: &[&[&[u8]]] = &[
        &[b"SET", b"k", b"v"],
        &[b"MULTI"],
        &[b"SET", b"k", b"w"],
        &[b"EXEC"],
        &[b"JSON.SET", b"k", b"$", b"{}"],
        &[b"FLUSHALL"],
    ];
    client.send(&pipeline(commands)).await.unwrap();
    for _ in commands {
        assert_eq!(client.read_reply().await, fake::OK);
    }
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);
    let mut expected: Vec<Vec<Vec<u8>>> = commands.iter().map(|command| args(command)).collect();
    expected.push(args(&[b"PING"]));
    assert_eq!(rig.fake.commands(), expected);
    assert!(rig.refusals().is_empty());
}
