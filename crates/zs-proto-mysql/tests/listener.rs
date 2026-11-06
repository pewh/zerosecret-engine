#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::sync::Arc;
use std::sync::atomic::Ordering;

use fake::{CLIENT_CAPS, Flow, PASSWORD, Script, WRONG};
use zs_diag::DiagLog;
use zs_proto_mysql::packet::{self, ServerError};
use zs_proto_mysql::{
    BAD_HANDSHAKE, CHANGE_USER_REFUSED, CHANGE_USER_REFUSED_REASON, CLIENT_REFUSED, ClientAuth,
    DENIED, METHOD_REFUSED, MysqlListener, TLS_REFUSED, UPSTREAM_AUTH_FAILED, UPSTREAM_REFUSED,
    UpstreamEndpoint, UpstreamTls, scramble,
};

fn native() -> Script {
    Script::new(packet::NATIVE_PASSWORD, Flow::Accept)
}

fn sha2(flow: Flow) -> Script {
    Script::new(packet::CACHING_SHA2_PASSWORD, flow)
}

#[tokio::test(flavor = "multi_thread")]
async fn native_login_relays_a_query_with_a_rewritten_greeting() {
    let fake = fake::start(native()).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let mut session = fake::login(local, CLIENT_CAPS).await;

    assert_eq!(session.reply.payload.first(), Some(&packet::OK_HEADER));
    assert_eq!(session.reply.seq, 2);
    let answer = session.command(b"\x03SELECT 1").await.unwrap();
    assert!(answer.payload.ends_with(fake::OK_INFO));
    assert_eq!(answer.seq, 1);
    assert_eq!(
        fake.seen(|s| s.commands.clone()),
        vec![b"\x03SELECT 1".to_vec()]
    );

    let greeting = &session.greeting;
    assert_eq!(greeting.server_version, fake::SERVER_VERSION);
    assert_eq!(greeting.connection_id, fake::CONNECTION_ID);
    assert_eq!(greeting.plugin, packet::CACHING_SHA2_PASSWORD);
    assert_eq!(greeting.capabilities & packet::STRIPPED_CAPABILITIES, 0);
    assert_eq!(
        greeting.capabilities,
        fake::SERVER_CAPS & !packet::STRIPPED_CAPABILITIES
    );
    assert_eq!(greeting.scramble.len(), 20);
    assert_ne!(greeting.scramble, fake::salt(1));
    assert!(!greeting.scramble.contains(&0));

    assert_eq!(
        fake.seen(|s| s.auth_packets[0].clone()),
        scramble::native(PASSWORD.as_bytes(), &fake::salt(1))
    );
    assert_eq!(fake.seen(|s| s.user.clone()), b"alice");
    assert_eq!(fake.seen(|s| s.database.clone()), Some(b"appdb".to_vec()));
    assert!(fake.seen(|s| s.attributes.clone()).is_some());
    assert_eq!(fake.seen(|s| s.capabilities & packet::CLIENT_SSL), 0);
    assert!(!fake.saw_bytes(PASSWORD.as_bytes()));
    assert!(!fake.saw_bytes(b"client-auth-data-ignored"));
}

#[tokio::test(flavor = "multi_thread")]
async fn caching_sha2_fast_path_logs_in() {
    let fake = fake::start(sha2(Flow::Accept)).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload.first(), Some(&packet::OK_HEADER));
    assert_eq!(session.reply.seq, 2);
    assert_eq!(
        fake.seen(|s| s.auth_packets[0].clone()),
        scramble::caching_sha2(PASSWORD.as_bytes(), &fake::salt(1))
    );
    assert!(!fake.saw_bytes(PASSWORD.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_auth_switch_to_native_is_followed() {
    let fake = fake::start(sha2(Flow::SwitchTo(packet::NATIVE_PASSWORD))).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload.first(), Some(&packet::OK_HEADER));
    assert_eq!(fake.seen(|s| s.auth_packets.len()), 2);
    assert!(fake.seen(|s| s.authenticated));
}

#[tokio::test(flavor = "multi_thread")]
async fn full_auth_on_plaintext_is_refused_and_the_password_is_never_sent() {
    let fake = fake::start(sha2(Flow::FullAuth)).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let mut session = fake::login(local, CLIENT_CAPS).await;

    assert_eq!(session.reply.payload, METHOD_REFUSED.packet());
    assert_eq!(session.reply.seq, 2);
    assert!(session.closed().await);
    assert_eq!(
        fake.seen(|s| s.auth_packets.len()),
        1,
        "positive: the scramble answer reached the server"
    );
    assert!(!fake.saw_bytes(PASSWORD.as_bytes()));
    assert!(fake.seen(|s| s.auth_packets.iter().all(|p| p.as_slice() != [0x02])));
    assert!(!fake.seen(|s| s.authenticated));

    let pki = fake::pki("127.0.0.1");
    let tls_fake = fake::start(sha2(Flow::FullAuth).with_tls(pki.server.clone())).await;
    let local = tls_fake
        .listen(
            UpstreamTls::Required(vec![pki.ca_der.clone()]),
            fake::materialize(PASSWORD),
        )
        .await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "negative control: full auth inside TLS"
    );
    assert!(tls_fake.seen(|s| s.tls && s.authenticated));
    assert!(
        tls_fake.saw_bytes(PASSWORD.as_bytes()),
        "the detector sees the password when it is sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn cleartext_switches_on_plaintext_are_refused_and_work_inside_tls() {
    for plugin in [packet::SHA256_PASSWORD, packet::CLEAR_PASSWORD] {
        let fake = fake::start(Script::new(packet::NATIVE_PASSWORD, Flow::SwitchTo(plugin))).await;
        let local = fake
            .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
            .await;
        let session = fake::login(local, CLIENT_CAPS).await;
        assert_eq!(session.reply.payload, METHOD_REFUSED.packet());
        assert!(fake::eventually(|| fake.seen(|s| s.responses == 1)).await);
        assert!(!fake.saw_bytes(PASSWORD.as_bytes()));

        let pki = fake::pki("127.0.0.1");
        let tls_fake = fake::start(
            Script::new(packet::NATIVE_PASSWORD, Flow::SwitchTo(plugin))
                .with_tls(pki.server.clone()),
        )
        .await;
        let local = tls_fake
            .listen(
                UpstreamTls::Required(vec![pki.ca_der.clone()]),
                fake::materialize(PASSWORD),
            )
            .await;
        let session = fake::login(local, CLIENT_CAPS).await;
        assert_eq!(session.reply.payload.first(), Some(&packet::OK_HEADER));
        assert!(tls_fake.saw_bytes(PASSWORD.as_bytes()));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_plugin_is_refused_even_inside_tls() {
    let pki = fake::pki("127.0.0.1");
    let fake = fake::start(
        Script::new(packet::NATIVE_PASSWORD, Flow::SwitchTo(b"client_ed25519"))
            .with_tls(pki.server.clone()),
    )
    .await;
    let local = fake
        .listen(
            UpstreamTls::Required(vec![pki.ca_der.clone()]),
            fake::materialize(PASSWORD),
        )
        .await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload, METHOD_REFUSED.packet());
    assert!(fake.seen(|s| s.tls));
    assert_eq!(fake.seen(|s| s.auth_packets.len()), 1);
    assert!(!fake.saw_bytes(PASSWORD.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn more_than_three_auth_rounds_are_refused() {
    let fake = fake::start(Script::new(packet::NATIVE_PASSWORD, Flow::EndlessSwitch)).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload, METHOD_REFUSED.packet());
    assert_eq!(fake.seen(|s| s.auth_packets.len()), 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn client_tls_and_compression_requests_are_refused_before_upstream_auth() {
    let fake = fake::start(native()).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control"
    );
    assert_eq!(fake.seen(|s| s.responses), 1);

    let reply = fake::send_raw(local, &packet::ssl_request(CLIENT_CAPS, 16 << 20, 255)).await;
    assert_eq!((reply.seq, reply.payload), (2, CLIENT_REFUSED.packet()));
    for extra in [
        packet::CLIENT_COMPRESS,
        packet::CLIENT_ZSTD_COMPRESSION_ALGORITHM,
    ] {
        let session = fake::login(local, CLIENT_CAPS | extra).await;
        assert_eq!(session.reply.payload, CLIENT_REFUSED.packet());
    }
    let reply = fake::send_raw(local, b"\x00\x02").await;
    assert_eq!(reply.payload, BAD_HANDSHAKE.packet());
    assert_eq!(
        fake.seen(|s| s.responses),
        1,
        "no refused client reached upstream auth"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn change_user_is_refused_audited_and_never_forwarded() {
    let fake = fake::start(native()).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        "127.0.0.1",
        fake.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;
    let mut session = fake::login(local, CLIENT_CAPS).await;
    let answer = session.command(b"\x03SELECT 1").await.unwrap();
    assert!(answer.payload.ends_with(fake::OK_INFO), "positive control");

    let refused = session.command(b"\x11root\x00\x00").await.unwrap();
    assert_eq!(
        (refused.seq, refused.payload),
        (1, CHANGE_USER_REFUSED.packet())
    );
    assert!(session.closed().await);
    assert_eq!(
        fake.seen(|s| s.commands.clone()),
        vec![b"\x03SELECT 1".to_vec()]
    );
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("change_user", CHANGE_USER_REFUSED_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn change_user_pipelined_after_a_query_is_never_forwarded() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fake = fake::start(native()).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let mut session = fake::login(local, CLIENT_CAPS).await;
    let mut both = packet::frame(0, b"\x03SELECT 2");
    both.extend_from_slice(&packet::frame(0, b"\x11root\x00\x00"));
    session.stream.write_all(&both).await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        session.stream.read_to_end(&mut rest),
    )
    .await;

    assert!(
        fake::eventually(|| fake.seen(|s| s.commands.len() == 1)).await,
        "positive: the query was forwarded"
    );
    let refusal = packet::frame(1, &CHANGE_USER_REFUSED.packet());
    assert!(rest.windows(refusal.len()).any(|w| w == refusal.as_slice()));
    assert!(fake.seen(|s| {
        s.commands
            .iter()
            .all(|c| c.first() != Some(&packet::COM_CHANGE_USER))
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_err_before_the_greeting_is_relayed_as_a_refusal() {
    let fake = fake::start(Script::new(
        packet::NATIVE_PASSWORD,
        Flow::ErrBeforeGreeting,
    ))
    .await;
    let (materialize, calls) = fake::counted(PASSWORD);
    let local = fake.listen(UpstreamTls::WhenOffered, materialize).await;
    let reply = fake::first_packet(local).await;
    assert_eq!(reply.seq, 0);
    let error = ServerError::parse(&reply.payload).unwrap();
    assert_eq!(error.code, 1040);
    assert_eq!(error.sqlstate.as_deref(), Some("08004"));
    assert_eq!(error.message, UPSTREAM_REFUSED);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the client never sent a handshake response, so no credential is materialized"
    );
    assert_eq!(fake.seen(|s| s.accepts), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_materialize_denial_answers_after_the_client_handshake() {
    let fake = fake::start(native()).await;
    let allowed = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let session = fake::login(allowed, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control"
    );
    assert_eq!(fake.seen(|s| s.accepts), 1);

    let denied: zs_proto_mysql::Materialize =
        Arc::new(|| Err(zs_protocol::Denied::new("no grant for orders-mysql")));
    let local = fake.listen(UpstreamTls::WhenOffered, denied).await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(
        (session.reply.seq, session.reply.payload.clone()),
        (2, DENIED.packet())
    );
    let error = ServerError::parse(&session.reply.payload).unwrap();
    assert_eq!(
        (
            error.code,
            error.sqlstate.as_deref(),
            error.message.as_str()
        ),
        (1045, Some("28000"), "ZeroSecret denied the connection")
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(fake.seen(|s| s.accepts), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_tls_with_a_private_ca_logs_in_and_checks_the_name() {
    let pki = fake::pki("127.0.0.1");
    let fake = fake::start(native().with_tls(pki.server.clone())).await;
    let local = fake
        .listen(
            UpstreamTls::Required(vec![pki.ca_der.clone()]),
            fake::materialize(PASSWORD),
        )
        .await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload.first(), Some(&packet::OK_HEADER));
    assert!(fake.seen(|s| s.tls && s.ssl_requests == 1));
    assert_eq!(
        fake.seen(|s| s.capabilities & packet::CLIENT_SSL),
        packet::CLIENT_SSL
    );

    let other_name = fake::pki("10.9.9.9");
    let mismatched = fake::start(native().with_tls(other_name.server.clone())).await;
    let local = mismatched
        .listen(
            UpstreamTls::Required(vec![other_name.ca_der.clone()]),
            fake::materialize(PASSWORD),
        )
        .await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload, TLS_REFUSED.packet());
    assert_eq!(mismatched.seen(|s| s.responses), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_pin_or_an_untrusted_certificate_never_falls_back_to_plaintext() {
    let pki = fake::pki("127.0.0.1");
    let fake = fake::start(native().with_tls(pki.server.clone())).await;
    let pinned = fake
        .listen(
            UpstreamTls::Pinned(pki.leaf_sha256),
            fake::materialize(PASSWORD),
        )
        .await;
    let session = fake::login(pinned, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control: the right pin"
    );
    assert_eq!(fake.seen(|s| s.responses), 1);

    for tls in [UpstreamTls::Pinned([0x5a; 32]), UpstreamTls::WhenOffered] {
        let local = fake.listen(tls, fake::materialize(PASSWORD)).await;
        let mut session = fake::login(local, CLIENT_CAPS).await;
        assert_eq!(
            (session.reply.seq, session.reply.payload.clone()),
            (2, TLS_REFUSED.packet())
        );
        assert!(session.closed().await);
    }
    assert!(fake::eventually(|| fake.seen(|s| s.ssl_requests == 3)).await);
    assert_eq!(
        fake.seen(|s| s.responses),
        1,
        "no HandshakeResponse41 after a TLS failure"
    );
    assert!(!fake.saw_bytes(PASSWORD.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn required_tls_that_is_not_offered_is_refused() {
    let fake = fake::start(native()).await;
    let plain = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let session = fake::login(plain, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control"
    );

    let pki = fake::pki("127.0.0.1");
    for tls in [
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
        UpstreamTls::Pinned(pki.leaf_sha256),
    ] {
        let local = fake.listen(tls, fake::materialize(PASSWORD)).await;
        let reply = fake::first_packet(local).await;
        assert_eq!((reply.seq, reply.payload), (0, TLS_REFUSED.packet()));
    }
    assert_eq!(fake.seen(|s| s.responses), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn diag_records_upstream_auth_failed_and_never_the_password() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("diag.jsonl");
    let diag = DiagLog::open_with_cap(&path, "t-1", 1 << 20).unwrap();
    let fake = fake::start(native()).await;
    let listen = |password: &'static str| {
        fake::listen(
            "127.0.0.1",
            fake.addr.port(),
            UpstreamTls::WhenOffered,
            fake::materialize(password),
            diag.clone(),
            None,
        )
    };
    let good = listen(PASSWORD).await;
    let session = fake::login(good, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control"
    );
    let bad = listen(WRONG).await;
    let session = fake::login(bad, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload, UPSTREAM_AUTH_FAILED.packet());
    let echoing = fake::start(
        native().with_deny_text("Access denied, rejected secret zs-test-wrong-password"),
    )
    .await;
    let local = fake::listen(
        "127.0.0.1",
        echoing.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(WRONG),
        diag.clone(),
        None,
    )
    .await;
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload, UPSTREAM_AUTH_FAILED.packet());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    diag.close();

    let log = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let find = |name: &str| {
        events
            .iter()
            .find(|e| e["event"] == name && e["component"] == "mysql")
            .cloned()
    };
    for name in [
        "conn_accepted",
        "materialized",
        "upstream_connected",
        "greeting",
        "tls",
        "upstream_auth_ok",
        "conn_closed",
    ] {
        assert!(find(name).is_some(), "missing {name}: {log}");
    }
    let greeting = find("greeting").unwrap();
    assert_eq!(greeting["fields"]["server_version"], "8.4.2-zs-fake");
    assert_eq!(greeting["fields"]["ssl_offered"], false);
    assert_eq!(find("tls").unwrap()["fields"]["result"], "not_offered");
    let failed = find("upstream_auth_failed").expect("an auth failure event");
    assert_eq!(failed["fields"]["errno"], 1045);
    assert_eq!(failed["fields"]["sqlstate"], "28000");
    assert_eq!(failed["error"]["kind"], "refused");
    assert_eq!(failed["resource"], fake::RESOURCE);
    assert!(
        failed["error"]["text"]
            .as_str()
            .unwrap()
            .starts_with("Access denied")
    );
    assert!(!log.contains(PASSWORD));
    assert!(!log.contains(WRONG));

    let failures: Vec<_> = events
        .iter()
        .filter(|e| e["event"] == "upstream_auth_failed")
        .collect();
    assert_eq!(failures.len(), 2, "{log}");
    assert!(
        failures[0]["error"]["text"].is_string(),
        "the normal text is kept: {log}"
    );
    assert!(
        failures[1]["error"].get("text").is_none(),
        "a server text that holds the password is dropped: {log}"
    );
    assert_eq!(failures[1]["error"]["kind"], "refused");
    assert!(!log.contains(WRONG));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_greeting_names_the_configured_client_plugin_and_both_log_in() {
    assert_eq!(ClientAuth::default(), ClientAuth::CachingSha2);
    assert_eq!(
        ClientAuth::parse("mysql_native_password"),
        Some(ClientAuth::Native)
    );
    assert_eq!(
        ClientAuth::parse("caching_sha2_password"),
        Some(ClientAuth::CachingSha2)
    );
    assert_eq!(ClientAuth::parse("sha256_password"), None);
    let fake = fake::start(native()).await;
    for (auth, plugin) in [
        (ClientAuth::CachingSha2, packet::CACHING_SHA2_PASSWORD),
        (ClientAuth::Native, packet::NATIVE_PASSWORD),
    ] {
        let endpoint = UpstreamEndpoint::new("127.0.0.1", fake.addr.port()).unwrap();
        let listener = MysqlListener::bind_endpoint(
            "127.0.0.1:0",
            endpoint,
            UpstreamTls::WhenOffered,
            fake::materialize(PASSWORD),
        )
        .await
        .unwrap()
        .with_client_auth(auth);
        let local = listener.local_addr();
        tokio::spawn(listener.serve());
        let session = fake::login(local, CLIENT_CAPS).await;
        assert_eq!(session.greeting.plugin, plugin, "{auth:?}");
        assert_eq!(
            session.reply.payload.first(),
            Some(&packet::OK_HEADER),
            "{auth:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_reset_after_login_is_logged_as_a_relay_failure() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("diag.jsonl");
    let diag = DiagLog::open_with_cap(&path, "t-1", 1 << 20).unwrap();
    let clean = fake::start(native()).await;
    let reset = fake::start(Script::new(
        packet::NATIVE_PASSWORD,
        Flow::ResetAfterCommand,
    ))
    .await;
    for upstream in [&clean, &reset] {
        let local = fake::listen(
            "127.0.0.1",
            upstream.addr.port(),
            UpstreamTls::WhenOffered,
            fake::materialize(PASSWORD),
            diag.clone(),
            None,
        )
        .await;
        let mut session = fake::login(local, CLIENT_CAPS).await;
        assert_eq!(
            session.reply.payload.first(),
            Some(&packet::OK_HEADER),
            "positive control"
        );
        let _ = session.command(b"\x03SELECT 1").await;
        assert!(fake::eventually(|| upstream.seen(|s| s.commands.len() == 1)).await);
        drop(session);
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    diag.close();

    let log = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let relay: Vec<_> = events
        .iter()
        .filter(|e| e["event"] == "upstream_failed" && e["fields"]["stage"] == "relay")
        .collect();
    assert_eq!(
        relay.len(),
        1,
        "only the reset connection is a relay failure: {log}"
    );
    assert_eq!(relay[0]["error"]["kind"], "connection_reset", "{log}");
    assert_eq!(relay[0]["conn"], 2, "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_normal_end_of_a_verified_tls_session_is_not_a_relay_failure() {
    use tokio::io::AsyncWriteExt;
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("diag.jsonl");
    let diag = DiagLog::open_with_cap(&path, "t-1", 1 << 20).unwrap();
    let pki = fake::pki("127.0.0.1");
    let fake = fake::start(native().with_tls(pki.server.clone())).await;
    let local = fake::listen(
        "127.0.0.1",
        fake.addr.port(),
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
    )
    .await;
    let mut session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control"
    );
    let answer = session.command(b"\x03SELECT 1").await.unwrap();
    assert!(answer.payload.ends_with(fake::OK_INFO));
    assert!(fake.seen(|s| s.tls));
    packet::write_packet(&mut session.stream, 0, &[packet::COM_QUIT])
        .await
        .unwrap();
    session.stream.shutdown().await.unwrap();
    drop(session);

    let closed = |log: &str| {
        log.lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .any(|e| e["event"] == "conn_closed")
    };
    for _ in 0..100 {
        if closed(&std::fs::read_to_string(&path).unwrap_or_default()) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    diag.close();
    let log = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let ended = events
        .iter()
        .find(|e| e["event"] == "conn_closed")
        .expect("a conn_closed event");
    assert_eq!(ended["fields"]["closed_by"], "client", "{log}");
    assert!(
        events
            .iter()
            .all(|e| !(e["event"] == "upstream_failed" && e["fields"]["stage"] == "relay")),
        "a clean TLS close is not a relay failure: {log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn com_quit_is_the_clients_close_even_when_the_server_closes_first() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("diag.jsonl");
    let diag = DiagLog::open_with_cap(&path, "t-1", 1 << 20).unwrap();
    let fake = fake::start(native()).await;
    let local = fake::listen(
        "127.0.0.1",
        fake.addr.port(),
        UpstreamTls::WhenOffered,
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
    )
    .await;
    let mut session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control"
    );
    packet::write_packet(&mut session.stream, 0, &[packet::COM_QUIT])
        .await
        .unwrap();

    let ended = |log: &str| {
        log.lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .find(|e| e["event"] == "conn_closed")
    };
    let mut closed = None;
    for _ in 0..100 {
        closed = ended(&std::fs::read_to_string(&path).unwrap_or_default());
        if closed.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    drop(session);
    diag.close();
    let log = std::fs::read_to_string(&path).unwrap();
    let closed = closed.expect("a conn_closed event while the client still holds its socket");
    assert_eq!(closed["fields"]["closed_by"], "client", "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_refusals_are_logged_as_upstream_failed_at_stage_tls() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("diag.jsonl");
    let diag = DiagLog::open_with_cap(&path, "t-1", 1 << 20).unwrap();
    let pki = fake::pki("127.0.0.1");
    let tls_fake = fake::start(native().with_tls(pki.server.clone())).await;
    let plain_fake = fake::start(native()).await;
    let listen = |port: u16, tls: UpstreamTls| {
        fake::listen(
            "127.0.0.1",
            port,
            tls,
            fake::materialize(PASSWORD),
            diag.clone(),
            None,
        )
    };

    let good = listen(tls_fake.addr.port(), UpstreamTls::Pinned(pki.leaf_sha256)).await;
    let session = fake::login(good, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control: the right pin"
    );
    let wrong_pin = listen(tls_fake.addr.port(), UpstreamTls::Pinned([0x5a; 32])).await;
    let session = fake::login(wrong_pin, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload, TLS_REFUSED.packet());
    let not_offered = listen(
        plain_fake.addr.port(),
        UpstreamTls::Required(vec![pki.ca_der.clone()]),
    )
    .await;
    let reply = fake::first_packet(not_offered).await;
    assert_eq!(reply.payload, TLS_REFUSED.packet());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    diag.close();

    let log = std::fs::read_to_string(&path).unwrap();
    let events: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let in_conn = |name: &str, conn: u64| {
        events
            .iter()
            .filter(|e| e["event"] == name && e["conn"] == conn && e["component"] == "mysql")
            .cloned()
            .collect::<Vec<_>>()
    };
    let tls_failures = |conn: u64| {
        in_conn("upstream_failed", conn)
            .into_iter()
            .filter(|e| e["fields"]["stage"] == "tls")
            .collect::<Vec<_>>()
    };
    assert_eq!(in_conn("tls", 1)[0]["fields"]["result"], "pinned", "{log}");
    assert!(tls_failures(1).is_empty(), "{log}");

    let pin_tls = in_conn("tls", 2);
    assert_eq!(pin_tls[0]["fields"]["result"], "failed", "{log}");
    let pin_failed = tls_failures(2);
    assert_eq!(pin_failed.len(), 1, "{log}");
    assert_eq!(pin_failed[0]["level"], "warn", "{log}");
    assert_eq!(
        pin_failed[0]["error"]["kind"], pin_tls[0]["error"]["kind"],
        "{log}"
    );

    assert_eq!(
        in_conn("tls", 3)[0]["fields"]["result"],
        "not_offered",
        "{log}"
    );
    let absent = tls_failures(3);
    assert_eq!(absent.len(), 1, "{log}");
    assert_eq!(absent[0]["error"]["kind"], "not_offered", "{log}");
    assert!(!log.contains(PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cleartext_plugin_in_the_greeting_gets_a_native_scramble_on_plaintext() {
    for greeting_plugin in [packet::CLEAR_PASSWORD, packet::SHA256_PASSWORD] {
        let pki = fake::pki("127.0.0.1");
        let tls_fake = fake::start(
            Script::new(greeting_plugin, Flow::SwitchTo(packet::CLEAR_PASSWORD))
                .with_tls(pki.server.clone()),
        )
        .await;
        let local = tls_fake
            .listen(
                UpstreamTls::Required(vec![pki.ca_der.clone()]),
                fake::materialize(PASSWORD),
            )
            .await;
        let session = fake::login(local, CLIENT_CAPS).await;
        assert_eq!(
            session.reply.payload.first(),
            Some(&packet::OK_HEADER),
            "negative control: a cleartext switch inside verified TLS"
        );
        assert!(tls_fake.seen(|s| s.tls && s.authenticated));
        assert!(
            tls_fake.saw_bytes(PASSWORD.as_bytes()),
            "the detector sees the password when it is sent"
        );

        let fake = fake::start(Script::new(
            greeting_plugin,
            Flow::SwitchTo(b"client_ed25519"),
        ))
        .await;
        let local = fake
            .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
            .await;
        let mut session = fake::login(local, CLIENT_CAPS).await;
        assert_eq!(session.reply.payload, METHOD_REFUSED.packet());
        assert!(session.closed().await);
        assert!(fake::eventually(|| fake.seen(|s| s.responses == 1)).await);
        assert!(!fake.seen(|s| s.tls));
        let first = fake.seen(|s| s.auth_packets[0].clone());
        assert_eq!(first.len(), 20);
        assert_eq!(
            first,
            scramble::native(PASSWORD.as_bytes(), &fake::salt(1)),
            "the first answer is a native scramble"
        );
        assert_eq!(fake.seen(|s| s.auth_packets.len()), 1);
        assert!(!fake.saw_bytes(PASSWORD.as_bytes()));
        assert!(!fake.seen(|s| s.authenticated));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn local_infile_is_never_offered_upstream() {
    let fake = fake::start(native()).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(PASSWORD))
        .await;
    let session = fake::login(local, CLIENT_CAPS | packet::CLIENT_LOCAL_FILES).await;

    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive: the login reached the server"
    );
    assert!(fake.seen(|s| s.authenticated));
    assert_eq!(
        fake.seen(|s| s.capabilities & packet::CLIENT_LOCAL_FILES),
        0,
        "the forwarded response must not carry CLIENT_LOCAL_FILES"
    );
    assert_eq!(
        session.greeting.capabilities & packet::CLIENT_LOCAL_FILES,
        0
    );
    assert_ne!(
        fake.seen(|s| s.capabilities & packet::CLIENT_CONNECT_ATTRS),
        0,
        "negative control: a capability the client set and the server offered survives"
    );
}
