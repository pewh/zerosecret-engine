#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::sync::atomic::Ordering;
use std::time::Duration;

use fake::{CLIENT_PASSWORD, MOVED_TARGET, PASSWORD, SHORT_PASSWORD, USER, WRONG};
use zs_diag::DiagLog;
use zs_proto_redis::{
    CLIENT_TLS_REFUSED_REASON, CLUSTER_REDIRECT, CLUSTER_REDIRECT_REASON, CREDENTIAL_ECHO_REASON,
    DENIED, HANDSHAKE_TIMEOUT_REASON, MATERIALIZE_FAILED_REASON, NON_RESP, NON_RESP_REFUSED_REASON,
    UPSTREAM_AUTH_FAILED, UPSTREAM_AUTH_REFUSED_REASON, UPSTREAM_UNAVAILABLE,
    UPSTREAM_UNAVAILABLE_REASON, USER_MISMATCH, USER_MISMATCH_REASON, UpstreamTls,
};

fn leaks(bytes: &[u8], secret: &[u8]) -> bool {
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && needle.len() <= haystack.len()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }
    if secret.len() < 8 {
        return contains(bytes, secret);
    }
    (0..=secret.len() - 8).any(|start| contains(bytes, &secret[start..start + 8]))
}

fn args(parts: &[&[u8]]) -> Vec<Vec<u8>> {
    parts.iter().map(|part| part.to_vec()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_normal_connection_authenticates_upstream_and_relays_a_command() {
    let fake = fake::start(fake::Script::new()).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::logged_in(local).await;

    assert_eq!(client.command(&[b"GET", b"k"]).await, fake::OK);
    assert_eq!(
        fake.names(),
        vec!["AUTH".to_string(), "PING".to_string(), "GET".to_string()]
    );
    assert_eq!(
        fake.auths(),
        vec![args(&[b"AUTH", USER.as_bytes(), PASSWORD.as_bytes()])]
    );
    assert!(fake.authenticated());
    assert!(!fake.saw_bytes(CLIENT_PASSWORD.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_authenticates_before_it_reads_a_client_byte() {
    let fake = fake::start(fake::Script::new()).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::Client::connect(local).await;

    assert!(
        fake::eventually(|| fake.seen(|seen| seen.names.len() == 1)).await,
        "the agent authenticates without a client byte"
    );
    assert_eq!(fake.names(), vec!["AUTH".to_string()]);
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_credential_is_refused_with_the_fixed_error() {
    let fake = fake::start(fake::Script::new()).await;
    let (audit, refusals) = fake::audit_recorder();
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(WRONG),
        diag.clone(),
        Some(audit),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    assert_eq!(client.read_reply().await, UPSTREAM_AUTH_FAILED.frame());
    assert!(client.closed().await);
    assert_eq!(
        fake.auths(),
        vec![args(&[b"AUTH", USER.as_bytes(), WRONG.as_bytes()])],
        "positive: the agent sent its AUTH before it read the client"
    );
    assert!(!fake.authenticated());
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", UPSTREAM_AUTH_REFUSED_REASON)]
    );

    let (_text, events) = fake::read_diag(&path, diag).await;
    assert!(fake::in_conn(&events, "upstream_auth_ok", 1).is_empty());
    let refused = fake::in_conn(&events, "client_refused", 1);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["fields"]["reason"], "upstream_auth");
    assert_eq!(refused[0]["audit_seq"], 7);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_auth_forms_are_rewritten_and_the_client_password_never_reaches_upstream() {
    let fake = fake::start(fake::Script::accepting("default", PASSWORD)).await;
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth_default(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        None,
    )
    .await;
    let mut client = fake::Client::connect(local).await;

    assert_eq!(
        client.command(&[b"AUTH", CLIENT_PASSWORD.as_bytes()]).await,
        fake::OK
    );
    assert_eq!(
        client
            .command(&[b"AUTH", b"default", CLIENT_PASSWORD.as_bytes()])
            .await,
        fake::OK
    );
    assert_eq!(
        client
            .command(&[
                b"HELLO",
                b"3",
                b"AUTH",
                b"default",
                CLIENT_PASSWORD.as_bytes(),
            ])
            .await,
        fake::HELLO_REPLY
    );
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);

    let frames = fake.frames();
    assert_eq!(
        frames[1],
        args(&[b"AUTH", PASSWORD.as_bytes()]),
        "AUTH <pass> is rewritten to the credential"
    );
    assert_eq!(
        frames[2],
        args(&[b"AUTH", b"default", PASSWORD.as_bytes()]),
        "AUTH <user> <pass> is rewritten in place"
    );
    assert_eq!(
        frames[3],
        args(&[b"HELLO", b"3", b"AUTH", b"default", PASSWORD.as_bytes()]),
        "the AUTH clause of HELLO is rewritten in place"
    );
    assert!(
        !fake.saw_bytes(CLIENT_PASSWORD.as_bytes()),
        "the client password never reaches the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_binding_user_is_used_for_every_auth_form() {
    let fake = fake::start(fake::Script::new()).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::Client::connect(local).await;

    assert_eq!(
        client
            .command(&[b"AUTH", USER.as_bytes(), CLIENT_PASSWORD.as_bytes()])
            .await,
        fake::OK
    );
    assert_eq!(
        client
            .command(&[
                b"HELLO",
                b"3",
                b"SETNAME",
                b"client",
                b"AUTH",
                USER.as_bytes(),
                CLIENT_PASSWORD.as_bytes(),
            ])
            .await,
        fake::HELLO_REPLY
    );
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);

    let frames = fake.frames();
    assert_eq!(
        frames[1],
        args(&[b"AUTH", USER.as_bytes(), PASSWORD.as_bytes()])
    );
    assert_eq!(
        frames[2],
        args(&[
            b"HELLO",
            b"3",
            b"SETNAME",
            b"client",
            b"AUTH",
            USER.as_bytes(),
            PASSWORD.as_bytes(),
        ])
    );
    assert!(!fake.saw_bytes(CLIENT_PASSWORD.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn another_user_is_refused_audited_and_never_forwarded() {
    let fake = fake::start(fake::Script::new()).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut client = fake::logged_in(local).await;
    assert_eq!(
        client
            .command(&[b"AUTH", b"mallory", CLIENT_PASSWORD.as_bytes()])
            .await,
        USER_MISMATCH.frame()
    );
    assert!(client.closed().await);
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", USER_MISMATCH_REASON)]
    );
    assert_eq!(
        fake.commands(),
        vec![args(&[b"PING"])],
        "the refused AUTH is not forwarded"
    );
    assert!(!fake.saw_bytes(b"mallory"));

    let mut client = fake::Client::connect(local).await;
    assert_eq!(
        client
            .command(&[
                b"HELLO",
                b"3",
                b"AUTH",
                b"mallory",
                CLIENT_PASSWORD.as_bytes(),
            ])
            .await,
        USER_MISMATCH.frame()
    );
    assert!(client.closed().await);
    assert!(!fake.saw_bytes(b"mallory"));

    let mut client = fake::Client::connect(local).await;
    assert_eq!(
        client
            .command(&[
                b"HELLO",
                b"3",
                b"AUTH",
                USER.as_bytes(),
                PASSWORD.as_bytes(),
                b"AUTH",
                b"mallory",
                CLIENT_PASSWORD.as_bytes(),
            ])
            .await,
        USER_MISMATCH.frame(),
        "a second AUTH clause reaches the server after the checked one"
    );
    assert!(client.closed().await);
    assert!(!fake.saw_bytes(b"mallory"));
    assert!(!fake.saw_bytes(CLIENT_PASSWORD.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_resp_frame_is_refused_audited_and_never_forwarded() {
    let fake = fake::start(fake::Script::new()).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut positive = fake::logged_in(local).await;
    assert_eq!(positive.command(&[b"GET", b"k"]).await, fake::OK);

    let oversized = format!("*{}\r\n", 1_048_577).into_bytes();
    let huge_element = format!("*1\r\n${}\r\n", 32 * 1024 * 1024 + 1).into_bytes();
    let oversized_header = {
        let mut frame = b"*".to_vec();
        frame.extend_from_slice(&[b'1'; 100]);
        frame
    };
    let inline = b"PING\r\n".to_vec();
    let attribute = b"|1\r\n$1\r\na\r\n$1\r\nb\r\n".to_vec();
    let non_bulk = b"*1\r\n+PING\r\n".to_vec();
    let negative = b"*-1\r\n".to_vec();
    let non_numeric = b"*x\r\n".to_vec();
    let truncated = b"*2\r\n$4\r\nAUTH\r\n".to_vec();

    for frame in [
        inline,
        attribute,
        non_bulk,
        negative,
        non_numeric,
        oversized,
        huge_element,
        oversized_header,
        truncated.clone(),
    ] {
        let mut client = fake::Client::connect(local).await;
        client.send(&frame).await.unwrap();
        if frame == truncated {
            client.close_write().await;
        }
        assert_eq!(
            client.read_reply().await,
            NON_RESP.frame(),
            "{frame:?} is refused"
        );
        assert!(client.closed().await);
    }

    let refusals = refusals.lock().unwrap();
    assert_eq!(refusals.len(), 9);
    assert!(
        refusals.iter().all(
            |(operation, reason)| *operation == "connect" && *reason == NON_RESP_REFUSED_REASON
        )
    );
    assert_eq!(
        fake.commands(),
        vec![args(&[b"PING"]), args(&[b"GET", b"k"])],
        "no refused frame reached upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_reply_carrying_the_credential_closes_before_a_window_reaches_the_client() {
    let fake = fake::start(fake::Script::echoing(PASSWORD)).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    client.send_command(&[b"GET", b"secret"]).await.unwrap();
    assert!(
        fake::eventually(|| fake.seen(|seen| seen.names.len() == 2)).await,
        "positive: the command reached upstream"
    );
    let received = client.read_to_end().await;
    assert!(
        !leaks(&received, PASSWORD.as_bytes()),
        "the reply carried a credential window; {} bytes received",
        received.len()
    );
    assert!(client.closed().await);
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", CREDENTIAL_ECHO_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_split_across_reads_is_caught() {
    let fake = fake::start(fake::Script::echoing_split(PASSWORD, 3)).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    client.send_command(&[b"GET", b"secret"]).await.unwrap();
    assert!(fake::eventually(|| fake.seen(|seen| seen.names.len() == 2)).await);
    let received = client.read_to_end().await;
    assert!(
        !leaks(&received, PASSWORD.as_bytes()),
        "the reply carried a credential window; {} bytes received",
        received.len()
    );
    assert!(
        !received.is_empty(),
        "positive: the reply was partly relayed before the window completed"
    );
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", CREDENTIAL_ECHO_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_short_credential_echo_is_caught() {
    let fake = fake::start(fake::Script::echoing(SHORT_PASSWORD)).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(SHORT_PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    client.send_command(&[b"GET", b"secret"]).await.unwrap();
    assert!(fake::eventually(|| fake.seen(|seen| seen.names.len() == 2)).await);
    let received = client.read_to_end().await;
    assert!(
        !leaks(&received, SHORT_PASSWORD.as_bytes()),
        "the reply carried the credential; {} bytes received",
        received.len()
    );
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", CREDENTIAL_ECHO_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_top_level_cluster_redirect_is_refused_and_a_nested_one_is_relayed() {
    let fake = fake::start(fake::Script::top_level_moved(MOVED_TARGET)).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    assert_eq!(
        client.command(&[b"GET", b"k"]).await,
        CLUSTER_REDIRECT.frame()
    );
    assert!(client.closed().await);
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", CLUSTER_REDIRECT_REASON)]
    );

    let ask = format!("-ASK {MOVED_TARGET}\r\n").into_bytes();
    let fake = fake::start(fake::Script::new().with_reply(ask)).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::Client::connect(local).await;
    assert_eq!(
        client.command(&[b"GET", b"k"]).await,
        CLUSTER_REDIRECT.frame()
    );

    let nested = format!("*1\r\n-MOVED {MOVED_TARGET}\r\n");
    let fake = fake::start(fake::Script::nested_moved(MOVED_TARGET)).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::Client::connect(local).await;
    assert_eq!(client.command(&[b"GET", b"k"]).await, nested.as_bytes());
    assert_eq!(
        client.command(&[b"PING"]).await,
        fake::OK,
        "a nested redirect leaves the connection open"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_tls_hello_is_refused_without_a_write() {
    let fake = fake::start(fake::Script::new()).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut positive = fake::logged_in(local).await;
    assert_eq!(positive.command(&[b"PING"]).await, fake::OK);

    let mut client = fake::Client::connect(local).await;
    client.send(b"\x16\x03\x01\x00\xff").await.unwrap();
    let received = client.read_to_end().await;
    assert!(received.is_empty(), "{received:?}");
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", CLIENT_TLS_REFUSED_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_tls_is_verified_and_pinned() {
    let pki = fake::pki("127.0.0.1");

    let verified = fake::start(fake::Script::new().with_tls(pki.server.clone())).await;
    let local = fake::listen(
        verified.addr,
        Some(UpstreamTls::Required(vec![pki.ca_der.clone()])),
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        None,
    )
    .await;
    let mut client = fake::Client::connect(local).await;
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);
    assert!(verified.seen(|seen| seen.tls));
    assert!(verified.authenticated());

    let pinned = fake::start(fake::Script::new().with_tls(pki.server.clone())).await;
    let local = fake::listen(
        pinned.addr,
        Some(UpstreamTls::Pinned(pki.leaf_sha256)),
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        None,
    )
    .await;
    let mut client = fake::Client::connect(local).await;
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);
    assert!(pinned.authenticated());

    let untrusted = fake::start(fake::Script::new().with_tls(pki.server)).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        untrusted.addr,
        Some(UpstreamTls::Required(Vec::new())),
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;
    let mut client = fake::Client::connect(local).await;
    assert_eq!(client.read_reply().await, UPSTREAM_UNAVAILABLE.frame());
    assert!(
        untrusted.names().is_empty(),
        "no application byte reached an untrusted upstream"
    );
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", UPSTREAM_UNAVAILABLE_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_other_command_is_relayed_in_pipeline_order() {
    let fake = fake::start(fake::Script::new()).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::Client::connect(local).await;

    let commands: Vec<Vec<&[u8]>> = vec![
        vec![b"SELECT", b"1"],
        vec![b"CLIENT", b"SETINFO", b"LIB-NAME", b"go-redis"],
        vec![b"MULTI"],
        vec![b"EVAL", b"return 1", b"0"],
        vec![b"SUBSCRIBE", b"orders"],
        vec![b"CLIENT", b"SETINFO", b"LIB-VER", b"9.5.1"],
    ];
    for command in &commands {
        client.send_command(command).await.unwrap();
    }
    for _ in 0..commands.len() {
        assert_eq!(client.read_reply().await, fake::OK);
    }

    let expected: Vec<Vec<Vec<u8>>> = commands
        .iter()
        .map(|command| command.iter().map(|part| part.to_vec()).collect())
        .collect();
    assert_eq!(fake.commands(), expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn one_materialize_runs_per_connection_and_a_clean_connection_audits_no_refusal() {
    let fake = fake::start(fake::Script::new()).await;
    let (materialize, calls) = fake::counter();
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        materialize,
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    for _ in 0..2 {
        let mut client = fake::Client::connect(local).await;
        assert_eq!(client.command(&[b"PING"]).await, fake::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(refusals.lock().unwrap().is_empty());
    assert_eq!(fake.auths().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_that_cannot_be_audited_still_closes() {
    let fake = fake::start(fake::Script::new()).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(PASSWORD),
        diag.clone(),
        Some(fake::unaudited()),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    client.send(b"PING\r\n").await.unwrap();
    assert_eq!(client.read_reply().await, NON_RESP.frame());
    assert!(client.closed().await);

    let (_text, events) = fake::read_diag(&path, diag).await;
    let refused = fake::in_conn(&events, "client_refused", 1);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["fields"]["reason"], "non_resp");
    assert!(refused[0].get("audit_seq").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_materializer_sends_the_denied_error_and_audits_nothing_extra() {
    let fake = fake::start(fake::Script::new()).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        fake::denied(),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    assert_eq!(client.read_reply().await, DENIED.frame());
    assert!(client.closed().await);
    assert!(refusals.lock().unwrap().is_empty());
    assert!(
        fake.names().is_empty(),
        "no upstream connection is made after a denial"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_handshake_budget_bounds_a_silent_upstream() {
    let fake = fake::start(fake::Script::new().silent()).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen_with(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        Some(audit),
        Some(Duration::from_millis(100)),
        Some(fake::admit_all()),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    assert_eq!(client.read_reply().await, UPSTREAM_UNAVAILABLE.frame());
    assert!(client.closed().await);
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", HANDSHAKE_TIMEOUT_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_materializer_is_bounded_by_the_handshake_budget() {
    let fake = fake::start(fake::Script::new()).await;
    let (audit, refusals) = fake::audit_recorder();
    let slow: zs_protocol::Materialize = std::sync::Arc::new(|| {
        std::thread::sleep(Duration::from_secs(2));
        Ok(zs_credential::Credential::from_bytes(PASSWORD.as_bytes().to_vec()).unwrap())
    });
    let local = fake::listen_with(
        fake.addr,
        None,
        fake::auth(),
        slow,
        DiagLog::disabled(),
        Some(audit),
        Some(Duration::from_millis(100)),
        Some(fake::admit_all()),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    let started = std::time::Instant::now();
    assert_eq!(client.read_reply().await, UPSTREAM_UNAVAILABLE.frame());
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the timeout did not preempt the materializer"
    );
    assert!(client.closed().await);
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", HANDSHAKE_TIMEOUT_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_panicking_materializer_denies_with_the_fixed_text() {
    let fake = fake::start(fake::Script::new()).await;
    let (audit, refusals) = fake::audit_recorder();
    let panicking: zs_protocol::Materialize =
        std::sync::Arc::new(|| panic!("the materializer panicked"));
    let local = fake::listen_with(
        fake.addr,
        None,
        fake::auth(),
        panicking,
        DiagLog::disabled(),
        Some(audit),
        None,
        Some(fake::admit_all()),
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    assert_eq!(client.read_reply().await, DENIED.frame());
    assert!(client.closed().await);
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", MATERIALIZE_FAILED_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_listener_without_a_caller_check_refuses_every_connection() {
    let fake = fake::start(fake::Script::new()).await;
    let local = fake::listen_with(
        fake.addr,
        None,
        fake::auth(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        None,
        None,
        None,
    )
    .await;

    let mut client = fake::Client::connect(local).await;
    let received = client.read_to_end().await;
    assert!(received.is_empty(), "{received:?}");
    assert!(client.closed().await);
    assert!(fake.names().is_empty());
    assert_eq!(fake.seen(|seen| seen.accepts), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_without_a_protover_rewrites_its_auth_clause() {
    let fake = fake::start(fake::Script::accepting("default", PASSWORD)).await;
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth_default(),
        fake::materialize(PASSWORD),
        DiagLog::disabled(),
        None,
    )
    .await;
    let mut client = fake::Client::connect(local).await;

    assert_eq!(
        client
            .command(&[b"HELLO", b"AUTH", b"default", CLIENT_PASSWORD.as_bytes()])
            .await,
        fake::HELLO_REPLY
    );
    assert_eq!(
        fake.frames()[1],
        args(&[b"HELLO", b"AUTH", b"default", PASSWORD.as_bytes()])
    );
    assert!(!fake.saw_bytes(CLIENT_PASSWORD.as_bytes()));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_reply_larger_than_the_frame_limit_is_relayed_intact() {
    let size = 33 * 1024 * 1024;
    let header = format!("${size}\r\n").into_bytes();
    let mut value = header.clone();
    value.resize(header.len() + size, b'z');
    value.extend_from_slice(b"\r\n");

    let fake = fake::start(fake::Script::new().with_reply(value)).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::Client::connect(local).await;

    client.send_command(&[b"GET", b"big"]).await.unwrap();
    let received = client.read_reply().await;
    assert_eq!(received.len(), header.len() + size + 2);
    assert_eq!(&received[..header.len()], header.as_slice());
    assert_eq!(received.iter().filter(|byte| **byte == b'z').count(), size);
    assert!(received.ends_with(b"\r\n"));
    assert_eq!(
        client.command(&[b"PING"]).await,
        fake::OK,
        "the connection continues after the large reply"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_upstream_is_refused_without_the_opt_in_even_for_a_named_default_user() {
    for auth in [
        zs_proto_redis::Auth::new(None),
        zs_proto_redis::Auth::new(Some("default".to_string())),
    ] {
        let fake = fake::start(fake::Script::open()).await;
        let (audit, refusals) = fake::audit_recorder();
        let local = fake::listen(
            fake.addr,
            None,
            auth.clone(),
            fake::materialize(PASSWORD),
            DiagLog::disabled(),
            Some(audit),
        )
        .await;
        let mut client = fake::Client::connect(local).await;
        assert_eq!(
            client.read_reply().await,
            UPSTREAM_AUTH_FAILED.frame(),
            "{auth:?}"
        );
        assert!(client.closed().await);
        assert_eq!(
            fake.auths(),
            vec![args(&[b"AUTH", PASSWORD.as_bytes()])],
            "O1: the default user is sent the one-argument AUTH, which an open server refuses: {auth:?}"
        );
        assert_eq!(
            *refusals.lock().unwrap(),
            vec![("connect", UPSTREAM_AUTH_REFUSED_REASON)]
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_upstream_is_served_with_the_opt_in() {
    let fake = fake::start(fake::Script::open()).await;
    let (audit, refusals) = fake::audit_recorder();
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        fake.addr,
        None,
        zs_proto_redis::Auth::new(None).with_upstream_optional(true),
        fake::materialize(PASSWORD),
        diag.clone(),
        Some(audit),
    )
    .await;
    let mut client = fake::Client::connect(local).await;
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);
    assert_eq!(
        client.command(&[b"SET", b"k", b"v"]).await,
        fake::OK,
        "the open upstream serves the session"
    );
    assert_eq!(fake.names(), vec!["AUTH", "PING", "SET"]);
    assert!(refusals.lock().unwrap().is_empty());

    let (_text, events) = fake::read_diag(&path, diag).await;
    assert_eq!(
        fake::in_conn(&events, "upstream_auth_not_required", 1).len(),
        1
    );
    assert!(fake::in_conn(&events, "upstream_auth_ok", 1).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_opt_in_never_serves_a_refused_credential_or_an_unknown_user() {
    let cases = [
        (
            fake::start(fake::Script::new()).await,
            zs_proto_redis::Auth::new(Some(USER.to_string())),
            WRONG,
        ),
        (
            fake::start(fake::Script::open()).await,
            zs_proto_redis::Auth::new(Some(USER.to_string())),
            PASSWORD,
        ),
    ];
    for (fake, auth, password) in cases {
        let (audit, refusals) = fake::audit_recorder();
        let local = fake::listen(
            fake.addr,
            None,
            auth.with_upstream_optional(true),
            fake::materialize(password),
            DiagLog::disabled(),
            Some(audit),
        )
        .await;
        let mut client = fake::Client::connect(local).await;
        assert_eq!(client.read_reply().await, UPSTREAM_AUTH_FAILED.frame());
        assert!(client.closed().await);
        assert_eq!(
            fake.names(),
            vec!["AUTH"],
            "positive: the agent's AUTH reached the upstream, nothing after it"
        );
        assert_eq!(
            *refusals.lock().unwrap(),
            vec![("connect", UPSTREAM_AUTH_REFUSED_REASON)]
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_line_between_frames_is_ignored_like_redis_does() {
    let fake = fake::start(fake::Script::new()).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::Client::connect(local).await;
    client
        .send(b"*1\r\n$4\r\nPING\r\n\r\n*1\r\n$4\r\nPING\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(client.read_reply().await, fake::OK);
    assert_eq!(client.read_reply().await, fake::OK);
    assert_eq!(fake.names(), vec!["AUTH", "PING", "PING"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn replies_to_earlier_frames_arrive_before_a_refusal() {
    let fake = fake::start(fake::Script::new().with_reply_delay(Duration::from_millis(300))).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut client = fake::Client::connect(local).await;
    client
        .send(b"*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$1\r\nk\r\nAUTH x\r\n")
        .await
        .unwrap();
    assert_eq!(client.read_reply().await, fake::OK, "the PING reply");
    assert_eq!(client.read_reply().await, fake::OK, "the GET reply");
    assert_eq!(client.read_reply().await, NON_RESP.frame());
    assert!(client.closed().await);
    assert_eq!(fake.names(), vec!["AUTH", "PING", "GET"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_reaches_a_client_that_is_still_sending_a_large_frame() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fake = fake::start(fake::Script::refusing_auth()).await;
    let local = fake.listen(None, fake::materialize(PASSWORD)).await;
    let mut frame = format!("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n${}\r\n", 8 << 20).into_bytes();
    frame.extend(std::iter::repeat_n(b'z', 8 << 20));
    frame.extend_from_slice(b"\r\n");
    let stream = tokio::net::TcpStream::connect(local).await.unwrap();
    let (mut read, mut write) = stream.into_split();
    let writer = tokio::spawn(async move { write.write_all(&frame).await });
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), read.read_to_end(&mut received))
        .await
        .expect("the agent closes after the refusal")
        .expect("the client reads the refusal, not a reset");
    assert_eq!(received, UPSTREAM_AUTH_FAILED.frame());
    assert!(
        writer.await.unwrap().is_ok(),
        "the agent drained the frame instead of resetting the connection"
    );
}
