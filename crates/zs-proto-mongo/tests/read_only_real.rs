#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fake::{Client, assert_error};
use tokio::io::AsyncReadExt;
use zs_diag::DiagLog;
use zs_proto_mongo::bson::Doc;
use zs_proto_mongo::wire::{self, OpMsg, Section};
use zs_proto_mongo::{Auth, MongoListener, READ_ONLY_REFUSED, UpstreamEndpoint, UpstreamTls};
use zs_protocol::SessionAccess;

const USER: &str = "zs_sha256";
const SOURCE: &str = "zsdb";
const PASSWORD: &str = "zs-test-sha256-password";
const DATABASE: &str = "zsdb";
const COLLECTION_COUNT: i64 = 5;

struct Real {
    server: (String, u16),
    certs: PathBuf,
}

fn configured() -> Option<Real> {
    let value = std::env::var("ZS_TEST_MONGO")
        .ok()
        .filter(|v| !v.is_empty())?;
    let (host, port) = value.rsplit_once(':')?;
    Some(Real {
        server: (host.to_string(), port.parse().ok()?),
        certs: PathBuf::from(
            std::env::var("ZS_TEST_MONGO_CERTS")
                .ok()
                .filter(|v| !v.is_empty())?,
        ),
    })
}

fn real() -> Option<Real> {
    let found = configured();
    assert!(
        found.is_some() || std::env::var("ZS_REQUIRE_MONGO").is_err(),
        "ZS_REQUIRE_MONGO is set: ZS_TEST_MONGO and ZS_TEST_MONGO_CERTS must be set"
    );
    found
}

impl Real {
    async fn listen(&self, access: SessionAccess) -> SocketAddr {
        let endpoint = UpstreamEndpoint::new(self.server.0.clone(), self.server.1).unwrap();
        let tls = UpstreamTls::from_config(Some(&self.certs.join("ca.pem")), None).unwrap();
        let listener = MongoListener::bind_endpoint(
            &fake::loopback(),
            endpoint,
            Some(tls),
            Auth::new(USER, SOURCE),
            fake::materialize_with(PASSWORD, access),
        )
        .await
        .unwrap()
        .with_caller_check(fake::admit_all())
        .with_diag(DiagLog::disabled(), "real-mongo-read-only");
        let local = fake::tcp_addr(listener.local());
        tokio::spawn(listener.serve());
        local
    }

    async fn open(&self, access: SessionAccess) -> Client {
        let local = self.listen(access).await;
        let mut client = Client::connect(local).await;
        let hello = client.legacy_handshake().await.unwrap();
        assert!(
            hello.truthy("ok"),
            "positive control: the login works: {:?}",
            hello.str("errmsg")
        );
        client
    }

    async fn setup(&self) -> Setup {
        Setup {
            client: self.open(SessionAccess::ReadWrite).await,
            created: Vec::new(),
        }
    }
}

fn array_of(documents: &[Doc]) -> Doc {
    documents
        .iter()
        .enumerate()
        .fold(Doc::new(), |array, (at, document)| {
            array.with_doc(&at.to_string(), document)
        })
}

fn command(name: &str, collection: &str) -> Doc {
    Doc::new()
        .with_str(name, collection)
        .with_str("$db", DATABASE)
}

fn admin(name: &str, value: i32) -> Doc {
    Doc::new().with_i32(name, value).with_str("$db", "admin")
}

fn list_collections() -> Doc {
    Doc::new()
        .with_i32("listCollections", 1)
        .with_str("$db", DATABASE)
}

fn insert(collection: &str, documents: &[Doc]) -> Doc {
    command("insert", collection).with_array("documents", &array_of(documents))
}

fn find(collection: &str, filter: &Doc) -> Doc {
    command("find", collection).with_doc("filter", filter)
}

fn aggregate(collection: &str, stages: &[Doc]) -> Doc {
    command("aggregate", collection)
        .with_array("pipeline", &array_of(stages))
        .with_doc("cursor", &Doc::new())
}

fn explaining(mut inner: Doc) -> Doc {
    inner.remove("$db");
    Doc::new()
        .with_doc("explain", &inner)
        .with_str("verbosity", "queryPlanner")
        .with_str("$db", DATABASE)
}

fn stage(name: &str, value: &Doc) -> Doc {
    Doc::new().with_doc(name, value)
}

fn batch(reply: &Doc, which: &str) -> Vec<Doc> {
    reply
        .doc("cursor")
        .and_then(|cursor| cursor.doc(which))
        .map(|batch| {
            batch
                .elements()
                .iter()
                .map(|e| Doc::parse(&e.value).unwrap())
                .collect()
        })
        .unwrap_or_default()
}

fn ok(reply: &Doc) {
    assert!(
        reply.truthy("ok"),
        "{:?} (code {:?})",
        reply.str("errmsg"),
        reply.int("code")
    );
}

fn refused(reply: &Doc) {
    assert_error(reply, 13, READ_ONLY_REFUSED.message);
    assert_eq!(reply.str("codeName"), Some("Unauthorized"));
}

struct Setup {
    client: Client,
    created: Vec<String>,
}

impl Setup {
    async fn run(&mut self, body: Doc) -> Doc {
        self.client.command(body).await.unwrap()
    }

    async fn reset(&mut self, collection: &str, documents: &[Doc]) {
        let _ = self.run(command("drop", collection)).await;
        if !documents.is_empty() {
            ok(&self.run(insert(collection, documents)).await);
        }
        self.created.push(collection.to_string());
    }

    async fn names(&mut self) -> Vec<String> {
        let reply = self.run(list_collections()).await;
        ok(&reply);
        batch(&reply, "firstBatch")
            .iter()
            .filter_map(|c| c.str("name").map(str::to_string))
            .collect()
    }

    async fn count(&mut self, collection: &str, filter: &Doc) -> i64 {
        let reply = self
            .run(command("count", collection).with_doc("query", filter))
            .await;
        ok(&reply);
        reply.int("n").unwrap()
    }

    async fn index_names(&mut self, collection: &str) -> Vec<String> {
        let reply = self.run(command("listIndexes", collection)).await;
        ok(&reply);
        batch(&reply, "firstBatch")
            .iter()
            .filter_map(|c| c.str("name").map(str::to_string))
            .collect()
    }

    async fn finish(mut self, extra: &[&str]) {
        let mut all = self.created.clone();
        all.extend(extra.iter().map(|name| name.to_string()));
        for collection in all {
            let _ = self.run(command("drop", &collection)).await;
        }
        let names = self.names().await;
        for gone in self
            .created
            .iter()
            .map(String::as_str)
            .chain(extra.iter().copied())
        {
            assert!(!names.iter().any(|n| n == gone), "{gone} was left behind");
        }
    }
}

fn numbered() -> Vec<Doc> {
    (1..=COLLECTION_COUNT as i32)
        .map(|n| Doc::new().with_i32("n", n))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn find_and_cursor_work() {
    let Some(real) = real() else { return };
    let collection = "zs_ro_cursor";
    let mut setup = real.setup().await;
    setup.reset(collection, &numbered()).await;
    let mut client = real.open(SessionAccess::ReadOnly).await;

    let build = client.command(admin("buildInfo", 1)).await.unwrap();
    ok(&build);
    eprintln!("mongo server version: {:?}", build.str("version"));
    for body in [admin("hello", 1), admin("isMaster", 1), admin("ping", 1)] {
        ok(&client.command(body).await.unwrap());
    }

    let first = client
        .command(
            find(collection, &Doc::new())
                .with_doc("sort", &Doc::new().with_i32("n", 1))
                .with_i32("batchSize", 2),
        )
        .await
        .unwrap();
    ok(&first);
    let opened = batch(&first, "firstBatch");
    assert_eq!(opened.len(), 2);
    assert_eq!(opened[0].int("n"), Some(1));
    let cursor = first.doc("cursor").unwrap().int("id").unwrap();
    assert_ne!(cursor, 0, "the server kept a cursor open");

    let more = client
        .command(
            command("getMore", collection)
                .with_i64("getMore", cursor)
                .with_str("collection", collection)
                .with_i32("batchSize", 10),
        )
        .await
        .unwrap();
    ok(&more);
    let rest = batch(&more, "nextBatch");
    assert_eq!(rest.len(), 3, "getMore returns the remaining documents");
    assert_eq!(rest[2].int("n"), Some(5));
    assert_eq!(more.doc("cursor").unwrap().int("id"), Some(0));

    let again = client
        .command(find(collection, &Doc::new()).with_i32("batchSize", 1))
        .await
        .unwrap();
    ok(&again);
    let abandoned = again.doc("cursor").unwrap().int("id").unwrap();
    let killed = client
        .command(
            command("killCursors", collection)
                .with_array("cursors", &Doc::new().with_i64("0", abandoned)),
        )
        .await
        .unwrap();
    ok(&killed);
    assert_eq!(
        killed.doc("cursorsKilled").unwrap().int("0"),
        Some(abandoned)
    );

    let counted = client.command(command("count", collection)).await.unwrap();
    ok(&counted);
    assert_eq!(counted.int("n"), Some(COLLECTION_COUNT));

    let distinct = client
        .command(command("distinct", collection).with_str("key", "n"))
        .await
        .unwrap();
    ok(&distinct);
    assert_eq!(distinct.doc("values").unwrap().elements().len(), 5);

    let grouped = client
        .command(aggregate(
            collection,
            &[
                stage(
                    "$match",
                    &Doc::new().with_doc("n", &Doc::new().with_i32("$gte", 2)),
                ),
                stage(
                    "$group",
                    &Doc::new()
                        .with_i32("_id", 1)
                        .with_doc("total", &Doc::new().with_str("$sum", "$n")),
                ),
            ],
        ))
        .await
        .unwrap();
    ok(&grouped);
    assert_eq!(batch(&grouped, "firstBatch")[0].int("total"), Some(14));

    let listed = client.command(list_collections()).await.unwrap();
    ok(&listed);
    assert!(
        batch(&listed, "firstBatch")
            .iter()
            .any(|c| c.str("name") == Some(collection))
    );

    let indexes = client
        .command(command("listIndexes", collection))
        .await
        .unwrap();
    ok(&indexes);
    assert_eq!(batch(&indexes, "firstBatch")[0].str("name"), Some("_id_"));

    let explained = client
        .command(explaining(find(collection, &Doc::new())))
        .await
        .unwrap();
    ok(&explained);
    assert!(explained.doc("queryPlanner").is_some());

    for body in [
        Doc::new()
            .with_i32("listDatabases", 1)
            .with_bool("nameOnly", true)
            .with_str("$db", "admin"),
        Doc::new().with_i32("dbStats", 1).with_str("$db", DATABASE),
        command("collStats", collection),
    ] {
        ok(&client.command(body).await.unwrap());
    }

    let ended = client
        .command(
            Doc::new()
                .with_str("endSessions", "x")
                .with_str("$db", "admin"),
        )
        .await;
    assert!(ended.is_ok());

    setup.finish(&[]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn insert_update_delete_find_and_modify_bulk_write_are_refused_with_code_13() {
    let Some(real) = real() else { return };
    let collection = "zs_ro_writes";
    let mut setup = real.setup().await;
    setup.reset(collection, &numbered()).await;
    let mut client = real.open(SessionAccess::ReadOnly).await;
    let positive = client.command(command("count", collection)).await.unwrap();
    ok(&positive);
    assert_eq!(positive.int("n"), Some(COLLECTION_COUNT));

    let probe = Doc::new().with_str("probe", "zs-ro-refused");
    let first = Doc::new().with_i32("n", 1);
    let touch = Doc::new().with_doc("$set", &Doc::new().with_bool("touched", true));
    let writes = [
        ("insert", insert(collection, std::slice::from_ref(&probe))),
        (
            "update",
            command("update", collection).with_array(
                "updates",
                &array_of(&[Doc::new()
                    .with_doc("q", &first)
                    .with_doc("u", &touch)
                    .with_bool("multi", true)]),
            ),
        ),
        (
            "delete",
            command("delete", collection).with_array(
                "deletes",
                &array_of(&[Doc::new().with_doc("q", &Doc::new()).with_i32("limit", 0)]),
            ),
        ),
        (
            "findAndModify",
            command("findAndModify", collection)
                .with_doc("query", &first)
                .with_doc("update", &touch),
        ),
        (
            "bulkWrite",
            Doc::new()
                .with_i32("bulkWrite", 1)
                .with_array(
                    "ops",
                    &array_of(&[Doc::new()
                        .with_i32("insert", 0)
                        .with_doc("document", &probe)]),
                )
                .with_array(
                    "nsInfo",
                    &array_of(&[Doc::new().with_str("ns", &format!("{DATABASE}.{collection}"))]),
                )
                .with_str("$db", "admin"),
        ),
        ("create", command("create", "zs_ro_created")),
        ("drop", command("drop", collection)),
        (
            "createIndexes",
            command("createIndexes", collection).with_array(
                "indexes",
                &array_of(&[Doc::new()
                    .with_doc("key", &Doc::new().with_i32("n", 1))
                    .with_str("name", "zs_ro_index")]),
            ),
        ),
    ];
    for (name, body) in writes {
        let reply = client.command(body).await.unwrap();
        assert!(!reply.truthy("ok"), "{name} was not refused");
        refused(&reply);
    }
    let still = client.command(command("count", collection)).await.unwrap();
    ok(&still);
    assert_eq!(
        still.int("n"),
        Some(COLLECTION_COUNT),
        "the session is usable"
    );

    assert_eq!(setup.count(collection, &Doc::new()).await, COLLECTION_COUNT);
    assert_eq!(
        setup
            .count(collection, &Doc::new().with_str("probe", "zs-ro-refused"))
            .await,
        0,
        "no document was inserted"
    );
    assert_eq!(
        setup
            .count(collection, &Doc::new().with_bool("touched", true))
            .await,
        0,
        "no document was updated"
    );
    assert_eq!(setup.index_names(collection).await, ["_id_"]);
    assert!(
        !setup.names().await.iter().any(|n| n == "zs_ro_created"),
        "create was refused"
    );

    let mut writer = real.open(SessionAccess::ReadWrite).await;
    let inserted = writer
        .command(insert(collection, std::slice::from_ref(&probe)))
        .await
        .unwrap();
    ok(&inserted);
    assert_eq!(
        inserted.int("n"),
        Some(1),
        "negative control: the same insert works read-write"
    );
    assert_eq!(
        setup
            .count(collection, &Doc::new().with_str("probe", "zs-ro-refused"))
            .await,
        1
    );
    setup.finish(&["zs_ro_created"]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn out_and_merge_are_refused_even_nested() {
    let Some(real) = real() else { return };
    let collection = "zs_ro_pipeline";
    let (out_target, merge_target) = ("zs_ro_out_target", "zs_ro_merge_target");
    let mut setup = real.setup().await;
    setup.reset(collection, &numbered()).await;
    let _ = setup.run(command("drop", out_target)).await;
    let _ = setup.run(command("drop", merge_target)).await;
    let mut client = real.open(SessionAccess::ReadOnly).await;
    let positive = client
        .command(aggregate(
            collection,
            &[stage("$match", &Doc::new().with_i32("n", 1))],
        ))
        .await
        .unwrap();
    ok(&positive);
    assert_eq!(batch(&positive, "firstBatch").len(), 1);

    let out = |target: &str| Doc::new().with_str("$out", target);
    let merge = |target: &str| Doc::new().with_doc("$merge", &Doc::new().with_str("into", target));
    let mut attempts = Vec::new();
    for (write, target) in [(out as fn(&str) -> Doc, out_target), (merge, merge_target)] {
        attempts.push(aggregate(collection, &[write(target)]));
        attempts.push(aggregate(
            collection,
            &[stage(
                "$facet",
                &Doc::new().with_array("branch", &array_of(&[write(target)])),
            )],
        ));
        attempts.push(aggregate(
            collection,
            &[stage(
                "$lookup",
                &Doc::new()
                    .with_str("from", collection)
                    .with_str("as", "joined")
                    .with_array("pipeline", &array_of(&[write(target)])),
            )],
        ));
        attempts.push(aggregate(
            collection,
            &[stage(
                "$unionWith",
                &Doc::new()
                    .with_str("coll", collection)
                    .with_array("pipeline", &array_of(&[write(target)])),
            )],
        ));
        attempts.push(explaining(aggregate(collection, &[write(target)])));
    }
    for body in attempts {
        refused(&client.command(body).await.unwrap());
    }
    let names = setup.names().await;
    assert!(!names.iter().any(|n| n == out_target), "$out wrote");
    assert!(!names.iter().any(|n| n == merge_target), "$merge wrote");
    ok(&client.command(command("count", collection)).await.unwrap());

    let mut writer = real.open(SessionAccess::ReadWrite).await;
    ok(&writer
        .command(aggregate(collection, &[out(out_target)]))
        .await
        .unwrap());
    ok(&writer
        .command(aggregate(collection, &[merge(merge_target)]))
        .await
        .unwrap());
    let names = setup.names().await;
    assert!(
        names.iter().any(|n| n == out_target),
        "negative control: $out works read-write"
    );
    assert!(
        names.iter().any(|n| n == merge_target),
        "negative control: $merge works read-write"
    );
    setup.finish(&[out_target, merge_target]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_command_is_refused() {
    let Some(real) = real() else { return };
    let mut client = real.open(SessionAccess::ReadOnly).await;
    ok(&client.command(admin("ping", 1)).await.unwrap());

    for body in [
        admin("zsNoSuchCommand", 1),
        admin("Ping", 1),
        admin("ismaster", 1),
        admin("serverStatus", 1),
    ] {
        refused(&client.command(body).await.unwrap());
    }
    ok(&client.command(admin("ping", 1)).await.unwrap());

    let mut writer = real.open(SessionAccess::ReadWrite).await;
    let reply = writer.command(admin("zsNoSuchCommand", 1)).await.unwrap();
    assert!(!reply.truthy("ok"));
    assert_eq!(
        reply.int("code"),
        Some(59),
        "negative control: a read-write session reaches the server, which answers CommandNotFound"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_document_sequence_insert_is_refused() {
    let Some(real) = real() else { return };
    let collection = "zs_ro_sequence";
    let mut setup = real.setup().await;
    setup.reset(collection, &numbered()).await;
    let sequence = |document: &Doc| {
        let mut raw = b"documents\0".to_vec();
        raw.extend_from_slice(&document.encode());
        let mut section = ((raw.len() + 4) as i32).to_le_bytes().to_vec();
        section.extend_from_slice(&raw);
        Section::Sequence(section)
    };
    let message = || OpMsg {
        flags: 0,
        sections: vec![
            Section::Body(command("insert", collection)),
            sequence(&Doc::new().with_str("probe", "zs-ro-sequence")),
        ],
    };
    let mut client = real.open(SessionAccess::ReadOnly).await;
    ok(&client.command(command("count", collection)).await.unwrap());
    let id = client.next_id();
    client.send(&message().encode(id, 0)).await.unwrap();
    let (header, reply) = client.read_doc().await.unwrap();
    assert_eq!(header.response_to, id);
    refused(&reply);
    assert_eq!(
        setup
            .count(collection, &Doc::new().with_str("probe", "zs-ro-sequence"))
            .await,
        0
    );

    let mut writer = real.open(SessionAccess::ReadWrite).await;
    let id = writer.next_id();
    writer.send(&message().encode(id, 0)).await.unwrap();
    let (_, reply) = writer.read_doc().await.unwrap();
    ok(&reply);
    assert_eq!(
        setup
            .count(collection, &Doc::new().with_str("probe", "zs-ro-sequence"))
            .await,
        1,
        "negative control: the same message writes read-write"
    );
    setup.finish(&[]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn more_to_come_write_closes_the_session_without_reply() {
    let Some(real) = real() else { return };
    let collection = "zs_ro_more_to_come";
    let mut setup = real.setup().await;
    setup.reset(collection, &numbered()).await;
    let probe = || {
        insert(
            collection,
            &[Doc::new().with_str("probe", "zs-ro-more-to-come")],
        )
        .with_doc("writeConcern", &Doc::new().with_i32("w", 0))
    };
    let unacknowledged = |client: &mut Client| {
        let id = client.next_id();
        OpMsg {
            flags: wire::MORE_TO_COME,
            sections: vec![Section::Body(probe())],
        }
        .encode(id, 0)
    };

    let mut client = real.open(SessionAccess::ReadOnly).await;
    ok(&client.command(command("count", collection)).await.unwrap());
    let frame = unacknowledged(&mut client);
    client.send(&frame).await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.stream.read_to_end(&mut rest))
        .await
        .expect("the session closed")
        .ok();
    assert!(rest.is_empty(), "the agent answered a moreToCome write");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        setup
            .count(
                collection,
                &Doc::new().with_str("probe", "zs-ro-more-to-come")
            )
            .await,
        0,
        "the document was not written"
    );

    let mut writer = real.open(SessionAccess::ReadWrite).await;
    let frame = unacknowledged(&mut writer);
    writer.send(&frame).await.unwrap();
    let mut written = 0;
    for _ in 0..50 {
        written = setup
            .count(
                collection,
                &Doc::new().with_str("probe", "zs-ro-more-to-come"),
            )
            .await;
        if written == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        written, 1,
        "negative control: the same unacknowledged write lands read-write"
    );
    setup.finish(&[]).await;
}

async fn connected(local: SocketAddr) -> Client {
    let mut client = Client::connect(local).await;
    let hello = client.legacy_handshake().await.unwrap();
    assert!(hello.truthy("ok"), "positive control: the login works");
    client
}

fn get_more(collection: &str, cursor: i64) -> Doc {
    command("getMore", collection)
        .with_i64("getMore", cursor)
        .with_str("collection", collection)
        .with_i32("batchSize", 10)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cursor_opened_read_write_cannot_finish_in_a_read_only_session() {
    let Some(real) = real() else { return };
    let (source, target) = ("zs_ro_cursor_merge_source", "zs_ro_cursor_merge_target");
    let mut setup = real.setup().await;
    setup.reset(source, &numbered()).await;
    setup.reset(target, &[]).await;
    let merge = command("aggregate", source)
        .with_array(
            "pipeline",
            &array_of(&[stage("$merge", &Doc::new().with_str("into", target))]),
        )
        .with_doc("cursor", &Doc::new().with_i32("batchSize", 0));
    let prepared = setup.run(merge).await;
    ok(&prepared);
    let cursor = prepared.doc("cursor").unwrap().int("id").unwrap();
    assert_ne!(cursor, 0, "the server kept the $merge cursor open");
    assert_eq!(
        setup.count(target, &Doc::new()).await,
        0,
        "batchSize 0 wrote nothing yet"
    );

    let local = real.listen(SessionAccess::ReadOnly).await;
    let mut session = connected(local).await;
    refused(&session.command(get_more(source, cursor)).await.unwrap());
    let kill =
        command("killCursors", source).with_array("cursors", &Doc::new().with_i64("0", cursor));
    refused(&session.command(kill).await.unwrap());
    assert_eq!(
        setup.count(target, &Doc::new()).await,
        0,
        "nothing merged through the read-only session"
    );

    let finished = setup.run(get_more(source, cursor)).await;
    ok(&finished);
    assert_eq!(
        setup.count(target, &Doc::new()).await,
        COLLECTION_COUNT,
        "negative control: the cursor was live and a read-write getMore runs the write"
    );

    let opened = session
        .command(find(source, &Doc::new()).with_i32("batchSize", 2))
        .await
        .unwrap();
    ok(&opened);
    let read_cursor = opened.doc("cursor").unwrap().int("id").unwrap();
    assert_ne!(read_cursor, 0);
    let mut pooled = connected(local).await;
    let more = pooled.command(get_more(source, read_cursor)).await.unwrap();
    ok(&more);
    assert_eq!(
        batch(&more, "nextBatch").len(),
        3,
        "positive control: another connection of the pool continues a read cursor"
    );
    assert_eq!(more.doc("cursor").unwrap().int("id"), Some(0));
    refused(&pooled.command(get_more(source, read_cursor)).await.unwrap());
    setup.finish(&[]).await;
}
