#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fake::{Client, Script, assert_error};
use tokio::io::AsyncReadExt;
use zs_diag::DiagLog;
use zs_proto_mongo::bson::Doc;
use zs_proto_mongo::wire::{self, OpMsg, Section};
use zs_proto_mongo::{AUTH_BROKERED, READ_ONLY_REASON, READ_ONLY_REFUSED};
use zs_protocol::SessionAccess;

const MARKER: &str = "zs-ro-argument-marker";
const TARGET: &str = "zs-ro-target-marker";

struct Rig {
    set: fake::FakeSet,
    local: SocketAddr,
    diag: DiagLog,
    path: PathBuf,
    refusals: fake::Refusals,
    _home: tempfile::TempDir,
}

impl Rig {
    async fn start(access: SessionAccess) -> Self {
        let set = fake::start(Script::set(1, Some(0))).await;
        let home = tempfile::tempdir().unwrap();
        let (path, diag) = fake::diag_log(home.path());
        let (audit, refusals) = fake::audit_recorder();
        let local = fake::listen(
            set.seed(),
            None,
            fake::materialize_with(fake::PASSWORD, access),
            diag.clone(),
            Some(audit),
        )
        .await;
        Self {
            set,
            local,
            diag,
            path,
            refusals,
            _home: home,
        }
    }

    async fn login(&self) -> Client {
        fake::logged_in(self.local).await
    }

    fn raw(&self) -> Vec<Vec<u8>> {
        self.set.seen(0, |s| s.raw.clone())
    }

    fn frames(&self) -> usize {
        self.set.seen(0, |s| s.frames)
    }

    fn commands(&self) -> Vec<String> {
        self.set.seen(0, |s| s.commands.clone())
    }

    fn refusals(&self) -> Vec<(&'static str, &'static str)> {
        self.refusals.lock().unwrap().clone()
    }

    async fn log(&self) -> (String, Vec<serde_json::Value>) {
        fake::read_diag(&self.path, self.diag.clone()).await
    }
}

fn command(name: &str) -> Doc {
    Doc::new().with_str(name, "orders").with_str("$db", "appdb")
}

fn array_of(documents: &[Doc]) -> Doc {
    documents
        .iter()
        .enumerate()
        .fold(Doc::new(), |array, (at, document)| {
            array.with_doc(&at.to_string(), document)
        })
}

fn aggregate(stages: &[Doc]) -> Doc {
    Doc::new()
        .with_str("aggregate", "orders")
        .with_array("pipeline", &array_of(stages))
        .with_doc("cursor", &Doc::new())
        .with_str("$db", "appdb")
}

fn write_stage(name: &str) -> Doc {
    Doc::new().with_str(name, TARGET)
}

fn insert_with_marker() -> Doc {
    Doc::new()
        .with_str("insert", "orders")
        .with_array(
            "documents",
            &array_of(&[Doc::new().with_str("probe", MARKER)]),
        )
        .with_str("$db", "appdb")
}

fn sequence(identifier: &str, documents: &[Doc]) -> Section {
    let mut raw = Vec::new();
    raw.extend_from_slice(identifier.as_bytes());
    raw.push(0);
    for document in documents {
        raw.extend_from_slice(&document.encode());
    }
    let mut section = ((raw.len() + 4) as i32).to_le_bytes().to_vec();
    section.extend_from_slice(&raw);
    Section::Sequence(section)
}

async fn send(client: &mut Client, message: OpMsg) -> (i32, Vec<u8>) {
    let id = client.next_id();
    let frame = message.encode(id, 0);
    client.send(&frame).await.unwrap();
    (id, frame)
}

async fn answered(client: &mut Client, message: OpMsg) -> (Vec<u8>, Doc) {
    let (id, frame) = send(client, message).await;
    let (header, reply) = client.read_doc().await.unwrap();
    assert_eq!(header.response_to, id, "the reply answers the request");
    (frame, reply)
}

async fn refused(client: &mut Client, message: OpMsg) {
    let (id, _) = send(client, message).await;
    let (header, reply) = client.read_doc().await.unwrap();
    assert_eq!(header.response_to, id, "the refusal answers the request");
    assert_eq!(header.op_code, wire::OP_MSG);
    assert_error(&reply, 13, READ_ONLY_REFUSED.message);
    assert_eq!(reply.str("codeName"), Some("Unauthorized"));
}

async fn usable(client: &mut Client) {
    let reply = client.command(fake::find()).await.unwrap();
    assert!(reply.truthy("ok"), "the session answers the next command");
}

async fn silent_close(client: &mut Client) {
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.stream.read_to_end(&mut rest))
        .await
        .expect("the session closed")
        .ok();
    assert_eq!(
        rest,
        Vec::<u8>::new(),
        "the agent wrote a reply on a session that it closed"
    );
}

fn allowed_commands() -> Vec<Doc> {
    vec![
        fake::find(),
        command("getMore").with_i64("getMore", 7),
        Doc::new()
            .with_str("killCursors", "orders")
            .with_array("cursors", &Doc::new().with_i64("0", 7))
            .with_str("$db", "appdb"),
        command("count"),
        command("distinct").with_str("key", "n"),
        aggregate(&[Doc::new().with_doc("$match", &Doc::new())]),
        command("listCollections"),
        command("listIndexes"),
        command("listDatabases"),
        command("dbStats"),
        command("collStats"),
        Doc::new()
            .with_doc("explain", &fake::find())
            .with_str("verbosity", "queryPlanner")
            .with_str("$db", "appdb"),
        Doc::new().with_i32("hello", 1).with_str("$db", "admin"),
        Doc::new().with_i32("isMaster", 1).with_str("$db", "admin"),
        Doc::new().with_i32("ping", 1).with_str("$db", "admin"),
        Doc::new().with_i32("buildInfo", 1).with_str("$db", "admin"),
        Doc::new()
            .with_str("endSessions", "x")
            .with_str("$db", "admin"),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn allowlisted_commands_are_forwarded_byte_for_byte_and_answered() {
    let rig = Rig::start(SessionAccess::ReadOnly).await;
    let mut client = rig.login().await;
    for body in allowed_commands() {
        let name = body.first_key().unwrap().to_string();
        let (frame, reply) = answered(&mut client, OpMsg::new(body)).await;
        assert!(reply.truthy("ok"), "{name}");
        assert_eq!(
            rig.raw().last(),
            Some(&frame),
            "{name}: the upstream received the client's bytes"
        );
    }
    assert!(rig.refusals().is_empty());
    let (log, events) = rig.log().await;
    assert!(
        fake::in_conn(&events, "command_refused", 1).is_empty(),
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_commands_never_reach_the_upstream_and_the_session_stays_usable() {
    let rig = Rig::start(SessionAccess::ReadOnly).await;
    let mut client = rig.login().await;
    usable(&mut client).await;
    assert_eq!(
        rig.commands(),
        vec!["find".to_string()],
        "positive control: the session relays an allowed command"
    );

    let names = [
        "insert",
        "update",
        "delete",
        "findAndModify",
        "bulkWrite",
        "create",
        "drop",
        "createIndexes",
        "dropIndexes",
        "renameCollection",
        "mapReduce",
        "eval",
        "setParameter",
        "shutdown",
        "fsync",
        "createUser",
        "applyOps",
        "commitTransaction",
        "abortTransaction",
        "ismaster",
        "buildinfo",
        "zsMadeUpCommand",
    ];
    for name in names {
        let body = command(name).with_str("marker", MARKER);
        refused(&mut client, OpMsg::new(body)).await;
        usable(&mut client).await;
    }
    refused(&mut client, OpMsg::new(insert_with_marker())).await;
    usable(&mut client).await;

    assert_eq!(
        rig.commands(),
        vec!["find".to_string(); names.len() + 2],
        "only the allowed commands reached the upstream"
    );
    assert!(
        !rig.set.saw_bytes(MARKER.as_bytes()),
        "a refused command reached the upstream"
    );
    assert_eq!(
        rig.refusals(),
        vec![("query", READ_ONLY_REASON); names.len() + 1]
    );

    let (log, events) = rig.log().await;
    let refusals = fake::in_conn(&events, "command_refused", 1);
    assert_eq!(refusals.len(), names.len() + 1, "{log}");
    for (event, name) in refusals.iter().zip(names.iter().chain(["insert"].iter())) {
        assert_eq!(event["fields"]["command"], *name, "{log}");
        assert_eq!(event["fields"]["reason"], "command", "{log}");
        assert_eq!(event["audit_seq"], 7, "{log}");
        assert_eq!(event["level"], "warn", "{log}");
    }
    assert!(!log.contains(MARKER), "a command argument reached the log");
    assert!(!log.contains(fake::PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_write_session_forwards_insert_unchanged() {
    let rig = Rig::start(SessionAccess::ReadWrite).await;
    let mut client = rig.login().await;
    for body in [
        insert_with_marker(),
        command("update"),
        command("zsMadeUpCommand"),
    ] {
        let name = body.first_key().unwrap().to_string();
        let (frame, reply) = answered(&mut client, OpMsg::new(body)).await;
        assert!(reply.truthy("ok"), "{name}");
        assert_eq!(rig.raw().last(), Some(&frame), "{name}");
    }
    assert_eq!(
        rig.commands(),
        ["insert", "update", "zsMadeUpCommand"].map(String::from)
    );
    assert!(rig.set.saw_bytes(MARKER.as_bytes()));
    assert!(rig.refusals().is_empty());
    let (log, events) = rig.log().await;
    assert!(
        fake::in_conn(&events, "command_refused", 1).is_empty(),
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn out_and_merge_are_refused_even_nested_and_never_forwarded() {
    let rig = Rig::start(SessionAccess::ReadOnly).await;
    let mut client = rig.login().await;
    let plain = aggregate(&[Doc::new().with_doc("$match", &Doc::new())]);
    let (_, reply) = answered(&mut client, OpMsg::new(plain)).await;
    assert!(
        reply.truthy("ok"),
        "positive control: an aggregate without a write stage"
    );

    let mut bodies = Vec::new();
    for write in ["$out", "$merge"] {
        bodies.push(aggregate(&[write_stage(write)]));
        bodies.push(aggregate(&[Doc::new().with_doc(
            "$facet",
            &Doc::new().with_array("a", &array_of(&[write_stage(write)])),
        )]));
        bodies.push(aggregate(&[Doc::new().with_doc(
            "$lookup",
            &Doc::new()
                .with_str("from", "other")
                .with_array("pipeline", &array_of(&[write_stage(write)])),
        )]));
        bodies.push(aggregate(&[Doc::new().with_doc(
            "$unionWith",
            &Doc::new()
                .with_str("coll", "other")
                .with_array("pipeline", &array_of(&[write_stage(write)])),
        )]));
        bodies.push(
            Doc::new()
                .with_doc("explain", &aggregate(&[write_stage(write)]))
                .with_str("$db", "appdb"),
        );
    }
    let refused_count = bodies.len();
    for body in bodies {
        refused(&mut client, OpMsg::new(body)).await;
    }
    usable(&mut client).await;
    assert!(
        !rig.set.saw_bytes(TARGET.as_bytes()),
        "a command with a write stage reached the upstream"
    );
    assert_eq!(rig.refusals().len(), refused_count);

    let writer = Rig::start(SessionAccess::ReadWrite).await;
    let mut client = writer.login().await;
    let (_, reply) = answered(&mut client, OpMsg::new(aggregate(&[write_stage("$out")]))).await;
    assert!(reply.truthy("ok"));
    assert!(
        writer.set.saw_bytes(TARGET.as_bytes()),
        "negative control: a read-write session forwards the same aggregate"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_sequence_is_refused_whatever_the_command() {
    let rig = Rig::start(SessionAccess::ReadOnly).await;
    let mut client = rig.login().await;
    usable(&mut client).await;
    for body in [
        command("insert"),
        command("find"),
        command("aggregate"),
        command("update"),
    ] {
        let message = OpMsg {
            flags: 0,
            sections: vec![
                Section::Body(body),
                sequence("documents", &[Doc::new().with_str("probe", MARKER)]),
            ],
        };
        refused(&mut client, message).await;
        usable(&mut client).await;
    }
    let first = OpMsg {
        flags: 0,
        sections: vec![
            sequence("pipeline", &[write_stage("$out")]),
            Section::Body(aggregate(&[])),
        ],
    };
    refused(&mut client, first).await;
    usable(&mut client).await;
    assert!(!rig.set.saw_bytes(MARKER.as_bytes()));
    assert!(!rig.set.saw_bytes(TARGET.as_bytes()));
    assert_eq!(rig.commands(), vec!["find".to_string(); 6]);
    assert_eq!(rig.refusals().len(), 5);

    let writer = Rig::start(SessionAccess::ReadWrite).await;
    let mut client = writer.login().await;
    let message = OpMsg {
        flags: 0,
        sections: vec![
            Section::Body(command("insert")),
            sequence("documents", &[Doc::new().with_str("probe", MARKER)]),
        ],
    };
    let (frame, reply) = answered(&mut client, message).await;
    assert!(reply.truthy("ok"));
    assert_eq!(
        writer.raw().last(),
        Some(&frame),
        "negative control: a read-write session forwards the sequence"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn more_to_come_write_closes_the_session_without_reply() {
    let rig = Rig::start(SessionAccess::ReadOnly).await;
    let mut positive = rig.login().await;
    let (_, frame) = send(
        &mut positive,
        OpMsg {
            flags: wire::MORE_TO_COME,
            sections: vec![Section::Body(fake::find())],
        },
    )
    .await;
    assert!(
        fake::eventually(|| rig.raw().last() == Some(&frame)).await,
        "positive control: an allowed command with moreToCome is forwarded as before"
    );
    assert!(rig.refusals().is_empty());

    let mut client = rig.login().await;
    usable(&mut client).await;
    send(
        &mut client,
        OpMsg {
            flags: wire::MORE_TO_COME,
            sections: vec![Section::Body(insert_with_marker())],
        },
    )
    .await;
    silent_close(&mut client).await;
    assert!(!rig.set.saw_bytes(MARKER.as_bytes()));
    assert_eq!(rig.refusals(), vec![("query", READ_ONLY_REASON)]);
    let (log, events) = rig.log().await;
    let refusals = fake::in_conn(&events, "command_refused", 2);
    assert_eq!(refusals.len(), 1, "{log}");
    assert_eq!(refusals[0]["fields"]["command"], "insert", "{log}");
    assert_eq!(refusals[0]["fields"]["reason"], "command", "{log}");
    assert!(!log.contains(MARKER));

    let writer = Rig::start(SessionAccess::ReadWrite).await;
    let mut client = writer.login().await;
    let (_, frame) = send(
        &mut client,
        OpMsg {
            flags: wire::MORE_TO_COME,
            sections: vec![Section::Body(insert_with_marker())],
        },
    )
    .await;
    assert!(fake::eventually(|| writer.raw().last() == Some(&frame)).await);
    assert!(
        writer.set.saw_bytes(MARKER.as_bytes()),
        "negative control: a read-write session forwards the moreToCome insert"
    );
}

fn compressed(inner: &OpMsg) -> Vec<u8> {
    let frame = inner.encode(9, 0);
    let content = &frame[wire::HEADER_LEN..];
    let mut payload = wire::OP_MSG.to_le_bytes().to_vec();
    payload.extend_from_slice(&(content.len() as i32).to_le_bytes());
    payload.push(0);
    payload.extend_from_slice(content);
    wire::frame(wire::OP_COMPRESSED, 9, 0, &payload)
}

fn legacy_write(op_code: i32) -> Vec<u8> {
    let mut payload = 0i32.to_le_bytes().to_vec();
    payload.extend_from_slice(b"appdb.orders\0");
    payload.extend_from_slice(&0i32.to_le_bytes());
    payload.extend_from_slice(&Doc::new().with_str("probe", MARKER).encode());
    wire::frame(op_code, 9, 0, &payload)
}

#[tokio::test(flavor = "multi_thread")]
async fn only_op_msg_passes_in_a_read_only_session() {
    let rig = Rig::start(SessionAccess::ReadOnly).await;
    let mut positive = rig.login().await;
    usable(&mut positive).await;

    let cases: [(&str, Vec<u8>); 7] = [
        (
            "OP_QUERY insert",
            fake::legacy_frame(insert_with_marker(), 9),
        ),
        ("OP_QUERY find", fake::legacy_frame(fake::find(), 9)),
        (
            "OP_COMPRESSED insert",
            compressed(&OpMsg::new(insert_with_marker())),
        ),
        ("OP_COMPRESSED find", compressed(&OpMsg::new(fake::find()))),
        ("OP_UPDATE", legacy_write(2001)),
        ("OP_INSERT", legacy_write(2002)),
        ("OP_DELETE", legacy_write(2006)),
    ];
    for (name, bytes) in &cases {
        let mut client = rig.login().await;
        let before = rig.frames();
        client.send(bytes).await.unwrap();
        silent_close(&mut client).await;
        assert_eq!(rig.frames(), before, "{name} reached the upstream");
    }
    assert!(!rig.set.saw_bytes(MARKER.as_bytes()));
    assert_eq!(
        rig.commands(),
        vec!["find".to_string()],
        "only the positive control reached the upstream"
    );

    let writer = Rig::start(SessionAccess::ReadWrite).await;
    for (name, bytes) in &cases {
        let mut client = writer.login().await;
        let before = writer.frames();
        client.send(bytes).await.unwrap();
        silent_close(&mut client).await;
        assert_eq!(
            writer.frames(),
            before,
            "negative control: {name} is closed for a read-write session too"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unparseable_message_closes_the_session_and_is_never_forwarded() {
    let rig = Rig::start(SessionAccess::ReadOnly).await;
    let mut positive = rig.login().await;
    usable(&mut positive).await;

    let framed = |sections: &[u8]| {
        let mut payload = 0u32.to_le_bytes().to_vec();
        payload.extend_from_slice(sections);
        wire::frame(wire::OP_MSG, 9, 0, &payload)
    };
    let body = |doc: &[u8]| {
        let mut section = vec![0u8];
        section.extend_from_slice(doc);
        section
    };
    let with_bad_element = |mut doc: Vec<u8>| {
        let at = doc.len() - 1;
        doc.splice(at..at, [0x99, b'x', 0]);
        let total = (doc.len() as i32).to_le_bytes();
        doc[..4].copy_from_slice(&total);
        doc
    };
    let mut truncated = body(&command("find").encode());
    truncated.extend_from_slice(&[1, 200, 0, 0, 0, b'd', 0]);

    let cases = [
        (
            "bad element",
            framed(&body(&with_bad_element(command("find").encode()))),
        ),
        (
            "bad element in a write",
            framed(&body(&with_bad_element(
                Doc::new().with_str("insert", MARKER).encode(),
            ))),
        ),
        ("no first key", framed(&body(&Doc::new().encode()))),
        ("truncated sequence", framed(&truncated)),
    ];
    for (name, bytes) in &cases {
        let mut client = rig.login().await;
        let before = rig.frames();
        client.send(bytes).await.unwrap();
        silent_close(&mut client).await;
        assert_eq!(rig.frames(), before, "{name} reached the upstream");
    }
    assert!(!rig.set.saw_bytes(MARKER.as_bytes()));
    let (log, events) = rig.log().await;
    for conn in 2..=5 {
        let closed = fake::in_conn(&events, "client_refused", conn);
        assert_eq!(closed.len(), 1, "{log}");
        assert_eq!(closed[0]["fields"]["reason"], "malformed", "{log}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_auth_command_still_ends_a_read_only_session_as_an_auth_refusal() {
    let rig = Rig::start(SessionAccess::ReadOnly).await;
    let mut client = rig.login().await;
    usable(&mut client).await;
    let reply = client
        .command(
            Doc::new()
                .with_i32("saslStart", 1)
                .with_str("mechanism", MARKER)
                .with_str("$db", "admin"),
        )
        .await
        .unwrap();
    assert_error(&reply, 18, AUTH_BROKERED.message);
    assert!(client.closed().await);
    assert!(!rig.set.saw_bytes(MARKER.as_bytes()));
    assert_eq!(
        rig.refusals(),
        vec![("authenticate", zs_proto_mongo::AUTHENTICATE_REFUSED_REASON)]
    );
}
