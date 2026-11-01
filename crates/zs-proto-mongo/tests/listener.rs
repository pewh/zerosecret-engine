#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::time::Duration;

use fake::{Client, PASSWORD, Sasl, Script, WRONG, assert_error};
use zs_diag::DiagLog;
use zs_proto_mongo::bson::Doc;
use zs_proto_mongo::wire::{self, Header, OpMsg, OpQuery};
use zs_proto_mongo::{
    AUTH_BROKERED, AUTHENTICATE_REFUSED_REASON, DENIED, UNAVAILABLE_DISCOVERY,
    UNAVAILABLE_HANDSHAKE, UNAVAILABLE_TLS, UPSTREAM_AUTH_FAILED, UpstreamTls,
};

#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_handshake_logs_in_rewrites_the_reply_and_relays_a_command() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let local = set.listen(None, fake::materialize(PASSWORD)).await;
    let listener = local.to_string();
    let mut client = Client::connect(local).await;
    let reply = client.legacy_handshake().await.unwrap();

    assert!(reply.truthy("ok"));
    assert_eq!(reply.str("setName"), Some(fake::SET));
    assert_eq!(reply.strings("hosts"), Some(vec![listener.clone()]));
    assert_eq!(reply.str("me"), Some(listener.as_str()));
    assert_eq!(reply.str("primary"), Some(listener.as_str()));
    for gone in [
        "passives",
        "arbiters",
        "saslSupportedMechs",
        "speculativeAuthenticate",
        "compression",
    ] {
        assert!(!reply.contains(gone), "{gone} reached the client");
    }
    let found = client.command(fake::find()).await.unwrap();
    assert!(found.truthy("ok"));
    assert_eq!(
        set.seen(0, |s| s.commands.clone()),
        vec!["find".to_string()]
    );

    let hello = set.seen(0, |s| s.hellos[0].clone());
    assert_eq!(set.seen(0, |s| s.hello_ops.clone()), vec![wire::OP_MSG]);
    assert_eq!(hello.first_key(), Some("isMaster"));
    assert_eq!(hello.str("saslSupportedMechs"), Some("appdb.alice"));
    assert_eq!(hello.str("$db"), Some("admin"));
    assert!(hello.contains("client"));
    assert!(!hello.contains("speculativeAuthenticate") && !hello.contains("compression"));
    assert_eq!(
        set.seen(0, |s| s.sasl.clone()),
        vec![
            "saslStart:SCRAM-SHA-256".to_string(),
            "saslContinue".to_string()
        ]
    );
    assert_eq!(
        set.seen(0, |s| s.sasl_dbs.clone()),
        vec![fake::SOURCE.to_string()]
    );
    assert!(set.seen(0, |s| s.authenticated));
    assert!(
        set.saw_bytes(b"appdb.alice"),
        "positive: the detector reads upstream frames"
    );
    assert!(!set.saw_bytes(PASSWORD.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_op_msg_handshake_gets_an_op_msg_reply_and_later_hellos_are_stripped() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let local = set.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = Client::connect(local).await;
    let reply = client.msg_handshake().await.unwrap();
    assert!(reply.truthy("ok"));
    assert_eq!(reply.strings("hosts"), Some(vec![local.to_string()]));

    let later = client
        .command(
            Doc::new()
                .with_i32("hello", 1)
                .with_strings("compression", &["zlib"])
                .with_str("saslSupportedMechs", "admin.mallory")
                .with_str("$db", "admin"),
        )
        .await
        .unwrap();
    assert_eq!(later.strings("hosts"), Some(vec![local.to_string()]));
    assert!(!later.contains("compression"));
    let hellos = set.seen(0, |s| s.hellos.clone());
    assert_eq!(hellos.len(), 2);
    assert!(!hellos[1].contains("compression") && !hellos[1].contains("saslSupportedMechs"));
    assert_eq!(hellos.iter().filter(|h| h.contains("client")).count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn scram_sha1_is_used_when_listed_alone_and_when_no_list_is_sent() {
    for (mechanisms, expected) in [
        (Some(vec!["SCRAM-SHA-1"]), "saslStart:SCRAM-SHA-1"),
        (None, "saslStart:SCRAM-SHA-1"),
        (Some(vec!["SCRAM-SHA-256"]), "saslStart:SCRAM-SHA-256"),
    ] {
        let set = fake::start(Script::set(1, Some(0)).with_mechanisms(mechanisms.clone())).await;
        let local = set.listen(None, fake::materialize(PASSWORD)).await;
        let mut client = fake::logged_in(local).await;
        assert!(client.command(fake::find()).await.unwrap().truthy("ok"));
        assert_eq!(
            set.seen(0, |s| s.sasl[0].clone()),
            expected,
            "{mechanisms:?}"
        );
        assert!(set.seen(0, |s| s.authenticated));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_secondary_seed_redirects_once_to_the_primary_in_hosts() {
    let set = fake::start(Script::set(3, Some(1))).await;
    let local = set.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::logged_in(local).await;
    assert!(client.command(fake::find()).await.unwrap().truthy("ok"));
    assert_eq!(set.seen(0, |s| (s.hellos.len(), s.sasl.len())), (1, 0));
    assert_eq!(set.seen(1, |s| s.sasl.len()), 2);
    assert!(set.seen(1, |s| s.authenticated));
    assert_eq!(
        set.seen(1, |s| s.commands.clone()),
        vec!["find".to_string()]
    );
    assert_eq!(
        set.seen(1, |s| s.hellos[0]
            .str("saslSupportedMechs")
            .map(str::to_string)),
        Some("appdb.alice".to_string())
    );
    assert_eq!(set.seen(2, |s| s.accepts), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn discovery_refuses_each_unsafe_answer_and_never_authenticates() {
    let positive = fake::start(Script::set(2, Some(1))).await;
    fake::logged_in(positive.listen(None, fake::materialize(PASSWORD)).await).await;

    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let cases = [
        (Script::set(3, None), "no_primary"),
        (
            Script::set(2, Some(1)).with_hosts(vec!["10.255.0.1:27017".to_string()]),
            "not_in_hosts",
        ),
        (Script::set(2, Some(1)).with_other_set(1), "set_mismatch"),
        (Script::set(2, None).claiming_primary(1), "second_redirect"),
        (Script::set(1, Some(0)).with_max_wire(5), "old_server"),
        (Script::set(1, Some(0)).with_hello_error(), "hello_error"),
    ];
    let mut sets = Vec::new();
    for (script, kind) in &cases {
        let set = fake::start(script.clone()).await;
        let local = fake::listen(
            set.seed(),
            None,
            fake::materialize(PASSWORD),
            diag.clone(),
            None,
        )
        .await;
        let mut client = Client::connect(local).await;
        let reply = client.legacy_handshake().await.unwrap();
        assert_error(&reply, 6, UNAVAILABLE_DISCOVERY.message);
        assert!(client.closed().await, "{kind}");
        assert_eq!(
            set.sasl_total(),
            0,
            "{kind}: authenticated after a refused discovery"
        );
        sets.push(set);
    }
    let (log, events) = fake::read_diag(&path, diag).await;
    for (conn, (_, kind)) in cases.iter().enumerate() {
        let failed = fake::in_conn(&events, "upstream_failed", conn as u64 + 1);
        assert_eq!(failed.len(), 1, "{log}");
        assert_eq!(failed[0]["fields"]["stage"], "discovery", "{log}");
        assert_eq!(failed[0]["error"]["kind"], *kind, "{log}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn standalone_and_mongos_replies_keep_their_shape() {
    for script in [Script::standalone(), Script::mongos()] {
        let mode = script.mode;
        let set = fake::start(script).await;
        let local = set.listen(None, fake::materialize(PASSWORD)).await;
        let mut client = Client::connect(local).await;
        let reply = client.legacy_handshake().await.unwrap();
        assert!(reply.truthy("ok"), "{mode:?}");
        assert!(
            !reply.contains("hosts") && !reply.contains("me") && !reply.contains("setName"),
            "{mode:?}"
        );
        assert!(
            !reply.contains("compression") && !reply.contains("saslSupportedMechs"),
            "{mode:?}"
        );
        assert_eq!(
            reply.str("msg"),
            (mode == fake::Mode::Mongos).then_some("isdbgrid")
        );
        assert!(client.command(fake::find()).await.unwrap().truthy("ok"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_password_gets_code_18_relays_nothing_and_the_diag_never_holds_it() {
    let control = fake::start(Script::set(1, Some(0))).await;
    fake::logged_in(control.listen(None, fake::materialize(PASSWORD)).await).await;

    let set = fake::start(Script::set(1, Some(0))).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        set.seed(),
        None,
        fake::materialize(WRONG),
        diag.clone(),
        None,
    )
    .await;
    let mut client = Client::connect(local).await;
    let reply = client.legacy_handshake().await.unwrap();
    assert_error(&reply, 18, UPSTREAM_AUTH_FAILED.message);
    assert!(client.closed().await);
    assert_eq!(
        set.seen(0, |s| s.sasl.len()),
        2,
        "positive: the agent answered the server"
    );
    assert!(!set.seen(0, |s| s.authenticated));
    assert!(set.seen(0, |s| s.commands.is_empty()));

    let (log, events) = fake::read_diag(&path, diag).await;
    let failed = fake::in_conn(&events, "upstream_auth_failed", 1);
    assert_eq!(failed.len(), 1, "{log}");
    assert_eq!(failed[0]["fields"]["code"], 18, "{log}");
    assert_eq!(
        failed[0]["fields"]["code_name"], "AuthenticationFailed",
        "{log}"
    );
    assert_eq!(failed[0]["fields"]["mechanism"], "SCRAM-SHA-256", "{log}");
    assert_eq!(failed[0]["error"]["text"], fake::AUTH_FAILED_TEXT, "{log}");
    let stage = fake::in_conn(&events, "upstream_failed", 1);
    assert_eq!(stage.len(), 1, "{log}");
    assert_eq!(stage[0]["fields"]["stage"], "auth", "{log}");
    assert_eq!(stage[0]["error"]["kind"], "refused", "{log}");
    assert!(!log.contains(WRONG));
}

#[tokio::test(flavor = "multi_thread")]
async fn scram_failures_are_refused_before_any_command() {
    let no_skip = fake::start(Script::set(1, Some(0)).with_sasl(Sasl::NoSkip)).await;
    let mut client = fake::logged_in(no_skip.listen(None, fake::materialize(PASSWORD)).await).await;
    assert!(
        client.command(fake::find()).await.unwrap().truthy("ok"),
        "negative control: one extra empty round"
    );
    assert_eq!(no_skip.seen(0, |s| s.sasl.len()), 3);

    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let cases = [
        (
            Script::set(1, Some(0)).with_sasl(Sasl::WrongSignature),
            "signature",
            2,
        ),
        (
            Script::set(1, Some(0)).with_sasl(Sasl::ShortNonce),
            "nonce",
            1,
        ),
        (
            Script::set(1, Some(0)).with_sasl(Sasl::LowIterations),
            "iterations",
            1,
        ),
        (
            Script::set(1, Some(0)).with_sasl(Sasl::Endless),
            "too_many_rounds",
            4,
        ),
        (
            Script::set(1, Some(0)).with_mechanisms(Some(vec!["PLAIN"])),
            "mechanism",
            0,
        ),
    ];
    let mut sets = Vec::new();
    for (script, kind, rounds) in &cases {
        let set = fake::start(script.clone()).await;
        let local = fake::listen(
            set.seed(),
            None,
            fake::materialize(PASSWORD),
            diag.clone(),
            None,
        )
        .await;
        let mut client = Client::connect(local).await;
        let reply = client.legacy_handshake().await.unwrap();
        assert_error(&reply, 18, UPSTREAM_AUTH_FAILED.message);
        assert!(client.closed().await, "{kind}");
        assert_eq!(set.seen(0, |s| s.sasl.len()), *rounds, "{kind}");
        assert!(set.seen(0, |s| s.commands.is_empty()), "{kind}");
        assert!(!set.saw_bytes(PASSWORD.as_bytes()), "{kind}");
        sets.push(set);
    }
    let (log, events) = fake::read_diag(&path, diag).await;
    for (conn, (_, kind, _)) in cases.iter().enumerate() {
        let failed = fake::in_conn(&events, "upstream_failed", conn as u64 + 1);
        assert_eq!(failed[0]["fields"]["stage"], "auth", "{log}");
        assert_eq!(failed[0]["error"]["kind"], *kind, "{log}");
    }
}

#[test]
fn the_scram_derivation_does_not_stall_the_runtime_worker() {
    let upstream_runtime = tokio::runtime::Runtime::new().unwrap();
    let set = upstream_runtime.block_on(fake::start(
        Script::set(1, Some(0)).with_sasl(Sasl::HighIterations),
    ));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (stall, login) = runtime.block_on(async {
        let local = set.listen(None, fake::materialize(PASSWORD)).await;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ticker_stop = stop.clone();
        let ticker = tokio::spawn(async move {
            let mut last = std::time::Instant::now();
            let mut stall = Duration::ZERO;
            while !ticker_stop.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(5)).await;
                stall = stall.max(last.elapsed());
                last = std::time::Instant::now();
            }
            stall
        });
        let started = std::time::Instant::now();
        let mut client = fake::logged_in(local).await;
        let login = started.elapsed();
        assert!(client.command(fake::find()).await.unwrap().truthy("ok"));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        (ticker.await.unwrap(), login)
    });
    assert!(
        login > Duration::from_millis(250),
        "negative control: {} rounds must take longer than the stall budget, took {login:?}",
        fake::HIGH_ITERATIONS
    );
    assert!(
        stall < Duration::from_millis(150),
        "the worker stalled {stall:?} during a {login:?} login"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_auth_commands_are_refused_audited_and_never_forwarded() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        set.seed(),
        None,
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;
    for command in ["saslStart", "saslContinue", "authenticate"] {
        let mut client = fake::logged_in(local).await;
        let reply = client
            .command(
                Doc::new()
                    .with_i32(command, 1)
                    .with_str("mechanism", "SCRAM-SHA-256")
                    .with_str("$db", "admin"),
            )
            .await
            .unwrap();
        assert_error(&reply, 18, AUTH_BROKERED.message);
        assert!(client.closed().await, "{command}");
    }
    assert_eq!(
        set.seen(0, |s| s.sasl.len()),
        6,
        "only the agent's own SCRAM rounds reached the server"
    );
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("authenticate", AUTHENTICATE_REFUSED_REASON); 3]
    );

    let mut client = fake::logged_in(local).await;
    let mut both = OpMsg::new(fake::find()).encode(client.next_id(), 0);
    both.extend_from_slice(
        &OpMsg::new(Doc::new().with_i32("saslStart", 1).with_str("$db", "admin"))
            .encode(client.next_id(), 0),
    );
    client.send(&both).await.unwrap();
    assert!(client.closed().await);
    assert!(fake::eventually(|| set.seen(0, |s| s.commands.len()) == 1).await);
    assert_eq!(
        set.seen(0, |s| s.commands.clone()),
        vec!["find".to_string()]
    );
    assert_eq!(set.seen(0, |s| s.sasl.len()), 8);
    assert_eq!(refusals.lock().unwrap().len(), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn framing_outside_the_allowlist_is_refused_and_never_forwarded() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        set.seed(),
        None,
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
    )
    .await;
    let checksummed = {
        let mut frame =
            OpMsg::new(Doc::new().with_i32("hello", 1).with_str("$db", "admin")).encode(2, 0);
        frame[wire::HEADER_LEN] |= wire::CHECKSUM_PRESENT as u8;
        frame.extend_from_slice(&[0, 0, 0, 0]);
        let len = (frame.len() as i32).to_le_bytes();
        frame[..4].copy_from_slice(&len);
        frame
    };
    let oversize = Header {
        length: wire::DEFAULT_MAX_MESSAGE + 1,
        request_id: 2,
        response_to: 0,
        op_code: wire::OP_MSG,
    }
    .encode()
    .to_vec();
    let client_hello = vec![
        0x16, 0x03, 0x01, 0x06, 0x1b, 0x01, 0x00, 0x06, 0x17, 0x03, 0x03, 0x7b, 0x3f, 0x0f, 0x85,
        0x85, 0x00, 0x01,
    ];
    let legacy_hello_elsewhere = OpQuery {
        flags: 0,
        collection: "admin.other".to_string(),
        skip: 0,
        limit: -1,
        query: fake::legacy_hello(),
    }
    .encode(2);
    let in_range_non_mongo = Header {
        length: 16_843_030,
        request_id: 2,
        response_to: 0,
        op_code: 0x0100_0301,
    }
    .encode()
    .to_vec();
    let first_cases: [(&str, Vec<u8>); 8] = [
        ("first_message", OpMsg::new(fake::find()).encode(2, 0)),
        ("op_query", fake::legacy_frame(fake::find(), 2)),
        ("op_query", legacy_hello_elsewhere),
        (
            "compressed",
            wire::frame(wire::OP_COMPRESSED, 2, 0, &[0u8; 16]),
        ),
        ("checksum", checksummed),
        ("frame_size", oversize),
        ("frame_size", client_hello),
        ("opcode", in_range_non_mongo),
    ];
    for (reason, bytes) in &first_cases {
        let mut client = Client::connect(local).await;
        client.send(bytes).await.unwrap();
        assert!(client.closed().await, "{reason}");
    }
    assert_eq!(
        set.accepts_total(),
        0,
        "a refused first message reached the server"
    );

    let later_cases: [(&str, Vec<u8>); 3] = [
        ("op_query", fake::legacy_frame(fake::find(), 9)),
        ("opcode", wire::frame(2010, 9, 0, &[0u8; 8])),
        (
            "malformed",
            wire::frame(wire::OP_MSG, 9, 0, &[0, 0, 0, 0, 0, 9, 9]),
        ),
    ];
    for (reason, bytes) in &later_cases {
        let mut client = fake::logged_in(local).await;
        client.send(bytes).await.unwrap();
        assert!(client.closed().await, "{reason}");
    }
    assert_eq!(
        set.seen(0, |s| s.accepts),
        3,
        "positive: three logins reached the server"
    );
    assert!(
        set.seen(0, |s| s.commands.is_empty()),
        "a refused frame reached the server"
    );

    let (log, events) = fake::read_diag(&path, diag).await;
    let reasons: Vec<&str> = first_cases
        .iter()
        .chain(later_cases.iter())
        .map(|(reason, _)| *reason)
        .collect();
    for (conn, reason) in reasons.iter().enumerate() {
        let refused = fake::in_conn(&events, "client_refused", conn as u64 + 1);
        assert_eq!(refused.len(), 1, "{log}");
        assert_eq!(refused[0]["fields"]["reason"], *reason, "{log}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_deny_answers_the_first_message_with_code_13_and_never_connects() {
    let set = fake::start(Script::set(1, Some(0))).await;
    fake::logged_in(set.listen(None, fake::materialize(PASSWORD)).await).await;
    assert_eq!(set.accepts_total(), 1, "positive control");

    let local = set.listen(None, fake::denied()).await;
    let mut client = Client::connect(local).await;
    let reply = client.legacy_handshake().await.unwrap();
    assert_error(&reply, 13, DENIED.message);
    assert!(client.closed().await);
    assert_eq!(
        set.accepts_total(),
        1,
        "a denied connection reached the server"
    );

    let mut msg_client = Client::connect(local).await;
    let reply = msg_client.msg_handshake().await.unwrap();
    assert_error(&reply, 13, DENIED.message);
    assert!(msg_client.closed().await);
    assert_eq!(
        set.accepts_total(),
        1,
        "a denied OP_MSG connection reached the server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_hello_nested_past_the_depth_limit_is_refused_before_any_upstream() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let local = set.listen(None, fake::materialize(PASSWORD)).await;
    fake::logged_in(local).await;
    let accepted = set.accepts_total();

    let mut nested = Doc::new().with_i32("probe", 1);
    for _ in 0..zs_proto_mongo::bson::MAX_DOCUMENT_DEPTH {
        nested = Doc::new().with_doc("n", &nested);
    }
    let hello = Doc::new()
        .with_i32("hello", 1)
        .with_doc("client", &nested)
        .with_str("$db", "admin");
    let mut client = Client::connect(local).await;
    client.send(&OpMsg::new(hello).encode(7, 0)).await.unwrap();
    assert!(client.closed().await);
    assert_eq!(
        set.accepts_total(),
        accepted,
        "a nested first hello reached the server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_handshake_budget_answers_the_first_message_with_unavailable_handshake() {
    let set = fake::start(Script::set(1, Some(0)).silent()).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen_with(
        set.seed(),
        None,
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
        Some(Duration::from_millis(500)),
    )
    .await;
    let mut client = Client::connect(local).await;
    let reply = client.legacy_handshake().await.unwrap();
    assert_error(&reply, 6, UNAVAILABLE_HANDSHAKE.message);
    assert!(client.closed().await);
    assert_eq!(
        set.seen(0, |s| s.hellos.len()),
        1,
        "positive: the hello reached the server"
    );

    let (log, events) = fake::read_diag(&path, diag).await;
    let failed = fake::in_conn(&events, "upstream_failed", 1);
    assert_eq!(failed[0]["fields"]["stage"], "handshake", "{log}");
    assert_eq!(failed[0]["error"]["kind"], "timed_out", "{log}");
    assert_eq!(
        fake::in_conn(&events, "conn_closed", 1)[0]["fields"]["closed_by"],
        "timeout",
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_tls_is_verified_or_pinned_and_never_falls_back() {
    let pki = fake::pki("127.0.0.1");
    let other = fake::pki("127.0.0.1");
    let tls_set = fake::start(Script::set(1, Some(0)).with_tls(pki.server.clone())).await;
    let plain_set = fake::start(Script::set(1, Some(0))).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let cases: [(Option<UpstreamTls>, bool, Option<&str>); 7] = [
        (
            Some(UpstreamTls::Required(vec![pki.ca_der.clone()])),
            true,
            Some("verified"),
        ),
        (
            Some(UpstreamTls::Pinned(pki.leaf_sha256)),
            true,
            Some("pinned"),
        ),
        (Some(UpstreamTls::Pinned([0x5a; 32])), true, None),
        (
            Some(UpstreamTls::Required(vec![other.ca_der.clone()])),
            true,
            None,
        ),
        (Some(UpstreamTls::WhenOffered), true, None),
        (
            Some(UpstreamTls::Required(vec![pki.ca_der.clone()])),
            false,
            None,
        ),
        (None, false, Some("plaintext")),
    ];
    for (tls, to_tls_set, result) in cases.iter().cloned() {
        let seed = if to_tls_set {
            tls_set.seed()
        } else {
            plain_set.seed()
        };
        let local = fake::listen(seed, tls, fake::materialize(PASSWORD), diag.clone(), None).await;
        let mut client = Client::connect(local).await;
        let reply = client.legacy_handshake().await.unwrap();
        match result {
            Some(_) => assert!(reply.truthy("ok"), "{result:?}"),
            None => assert_error(&reply, 6, UNAVAILABLE_TLS.message),
        }
    }
    assert_eq!(
        tls_set.seen(0, |s| s.hellos.len()),
        2,
        "a hello followed a TLS failure on the TLS server"
    );
    assert_eq!(
        plain_set.seen(0, |s| s.hellos.len()),
        1,
        "only the plaintext binding sent a hello to the plaintext server"
    );
    assert!(!tls_set.saw_bytes(PASSWORD.as_bytes()) && !plain_set.saw_bytes(PASSWORD.as_bytes()));

    let (log, events) = fake::read_diag(&path, diag).await;
    for (conn, (_, _, result)) in cases.iter().enumerate() {
        let conn = conn as u64 + 1;
        let tls = fake::in_conn(&events, "tls", conn);
        match result {
            Some(expected) => assert_eq!(tls[0]["fields"]["result"], *expected, "{log}"),
            None => {
                assert_eq!(tls[0]["fields"]["result"], "failed", "{log}");
                let failed = fake::in_conn(&events, "upstream_failed", conn);
                assert_eq!(failed[0]["fields"]["stage"], "tls", "{log}");
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_pin_also_checks_the_redirect_target() {
    let pki = fake::pki("127.0.0.1");
    let other = fake::pki("127.0.0.1");
    let pin = || Some(UpstreamTls::Pinned(pki.leaf_sha256));

    let same = fake::start(Script::set(2, Some(1)).with_tls(pki.server.clone())).await;
    let local = same.listen(pin(), fake::materialize(PASSWORD)).await;
    let mut client = Client::connect(local).await;
    assert!(client.legacy_handshake().await.unwrap().truthy("ok"));
    assert!(
        same.seen(1, |s| s.authenticated),
        "positive control: one leaf on both members"
    );

    let split = fake::start(
        Script::set(2, Some(1))
            .with_tls(pki.server.clone())
            .with_member_tls(1, other.server.clone()),
    )
    .await;
    let local = split.listen(pin(), fake::materialize(PASSWORD)).await;
    let mut client = Client::connect(local).await;
    let reply = client.legacy_handshake().await.unwrap();
    assert_error(&reply, 6, UNAVAILABLE_TLS.message);
    assert_eq!(
        split.seen(0, |s| s.hellos.len()),
        1,
        "the seed answered the hello"
    );
    assert_eq!(
        split.seen(1, |s| s.hellos.len()),
        0,
        "no hello reached the other leaf"
    );
    assert_eq!(split.sasl_total(), 0, "no SCRAM ran on either member");
}

#[tokio::test(flavor = "multi_thread")]
async fn streamed_hello_replies_are_each_rewritten() {
    let set = fake::start(Script::set(1, Some(0)).streamed(3)).await;
    let local = set.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::logged_in(local).await;
    let mut msg = OpMsg::new(
        Doc::new()
            .with_i32("hello", 1)
            .with_doc("topologyVersion", &Doc::new().with_i64("counter", 0))
            .with_i64("maxAwaitTimeMS", 100)
            .with_str("$db", "admin"),
    );
    msg.flags = wire::EXHAUST_ALLOWED;
    let id = client.next_id();
    client.send(&msg.encode(id, 0)).await.unwrap();
    let mut response_to = id;
    for i in 0..3 {
        let (header, payload) = client.read_frame().await.unwrap();
        let reply = OpMsg::parse(&payload).unwrap();
        assert_eq!(header.response_to, response_to, "reply {i}");
        assert_eq!(reply.flags & wire::MORE_TO_COME != 0, i < 2, "reply {i}");
        let body = reply.body().unwrap();
        assert_eq!(
            body.strings("hosts"),
            Some(vec![local.to_string()]),
            "reply {i}"
        );
        assert!(!body.contains("compression"), "reply {i}");
        response_to = header.request_id;
    }
    assert!(
        client.command(fake::find()).await.unwrap().truthy("ok"),
        "the relay continues after the chain"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_command_pipelined_after_the_first_hello_is_answered_in_order() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let local = set.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = Client::connect(local).await;
    let mut both = fake::legacy_frame(fake::legacy_hello(), 2);
    both.extend_from_slice(&OpMsg::new(fake::find()).encode(3, 0));
    client.send(&both).await.unwrap();
    let (first, hello) = client.read_doc().await.unwrap();
    assert_eq!((first.op_code, first.response_to), (wire::OP_REPLY, 2));
    assert!(hello.truthy("ok"));
    let (second, found) = client.read_doc().await.unwrap();
    assert_eq!((second.op_code, second.response_to), (wire::OP_MSG, 3));
    assert!(found.truthy("ok"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_reply_streams_through_intact() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let local = set.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::logged_in(local).await;
    let reply = client.command(fake::big_find()).await.unwrap();
    let batch = reply.doc("cursor").unwrap().doc("firstBatch").unwrap();
    let item = batch.doc("0").unwrap();
    let blob = item.str("blob").unwrap();
    assert_eq!(blob.len(), fake::BIG_LEN);
    assert!(blob.bytes().all(|b| b == b'z'));
    assert!(
        client.command(fake::find()).await.unwrap().truthy("ok"),
        "the framing holds after the large reply"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn diag_records_each_step_and_never_the_password_user_or_host() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        set.seed(),
        None,
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
    )
    .await;
    let mut client = fake::logged_in(local).await;
    assert!(client.command(fake::find()).await.unwrap().truthy("ok"));
    drop(client);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (log, events) = fake::read_diag(&path, diag).await;
    let names: Vec<&str> = events
        .iter()
        .filter(|e| e["conn"] == 1)
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "conn_accepted",
            "materialized",
            "client_hello",
            "upstream_connected",
            "tls",
            "discovery",
            "upstream_auth_ok",
            "conn_closed"
        ],
        "{log}"
    );
    let field = |name: &str, key: &str| fake::in_conn(&events, name, 1)[0]["fields"][key].clone();
    assert_eq!(field("materialized", "decision"), "allow");
    assert_eq!(field("client_hello", "op"), "op_query");
    assert_eq!(field("tls", "result"), "plaintext");
    assert_eq!(field("discovery", "role"), "primary");
    assert_eq!(field("discovery", "max_wire_version"), 21);
    assert_eq!(field("upstream_auth_ok", "mechanism"), "SCRAM-SHA-256");
    assert_eq!(field("conn_closed", "closed_by"), "client");
    assert!(field("conn_closed", "bytes_up").as_u64().unwrap() > 0);
    assert!(field("conn_closed", "bytes_down").as_u64().unwrap() > 0);
    for event in events.iter().filter(|e| e["component"] == "mongo") {
        assert_eq!(event["dest"], "invalid", "{event}");
        assert_eq!(event["resource"], fake::RESOURCE, "{event}");
    }
    let leaks = |text: &str| -> Vec<String> {
        [PASSWORD, fake::USER, fake::SOURCE, &set.seed().to_string()]
            .into_iter()
            .filter(|secret| text.contains(*secret))
            .map(str::to_string)
            .collect()
    };
    let planted = format!("{log}{{\"planted\":\"{}\"}}", fake::USER);
    assert_eq!(
        leaks(&planted),
        vec![fake::USER.to_string()],
        "negative control: the scan finds a planted user"
    );
    assert_eq!(leaks(&log), Vec::<String>::new(), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_frame_that_is_not_op_msg_closes_the_relay() {
    let set = fake::start(Script::set(1, Some(0)).with_compressed_replies()).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        set.seed(),
        None,
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
    )
    .await;
    let mut client = fake::logged_in(local).await;
    let id = client.next_id();
    client
        .send(&OpMsg::new(fake::find()).encode(id, 0))
        .await
        .unwrap();
    assert!(client.closed().await);
    assert_eq!(
        set.seen(0, |s| s.commands.clone()),
        vec!["find".to_string()]
    );

    let (log, events) = fake::read_diag(&path, diag).await;
    let failed = fake::in_conn(&events, "upstream_failed", 1);
    assert_eq!(failed[0]["fields"]["stage"], "relay", "{log}");
    assert_eq!(failed[0]["error"]["kind"], "opcode", "{log}");
    assert_eq!(
        fake::in_conn(&events, "conn_closed", 1)[0]["fields"]["closed_by"],
        "upstream",
        "{log}"
    );
}
