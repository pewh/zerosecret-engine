#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use zs_diag::DiagLog;
use zs_proto_redis::{
    Auth, CREDENTIAL_ECHO_REASON, RedisListener, UPSTREAM_AUTH_FAILED,
    UPSTREAM_AUTH_REFUSED_REASON, UPSTREAM_UNAVAILABLE, UPSTREAM_UNAVAILABLE_REASON, USER_MISMATCH,
    USER_MISMATCH_REASON, UpstreamEndpoint, UpstreamTls,
};

// These tests reach a real server, so they are ignored by default. The address never carries a
// port default: a test host is chosen by the operator, not by this repository.
//
// ZS_TEST_REDIS_ADDR, ZS_TEST_REDIS_PASSWORD: a Redis whose default user has that password.
// ZS_TEST_REDIS_ACL_USER, ZS_TEST_REDIS_ACL_PASSWORD: an ACL user on the same server.
// ZS_TEST_REDIS_NOAUTH_ADDR: a Redis with no password.
// ZS_TEST_REDIS_TLS_ADDR, ZS_TEST_REDIS_CERTS: a TLS-only Redis with the same users, and the
// directory of `tools/db-test-certs.sh` (`ca.pem`, `server.pem` for 127.0.0.1).
fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

fn materialize(password: String) -> zs_protocol::Materialize {
    Arc::new(move || {
        Ok(zs_credential::Credential::from_bytes(password.clone().into_bytes()).unwrap())
    })
}

fn endpoint(addr: &str) -> UpstreamEndpoint {
    let (host, port) = addr.rsplit_once(':').expect("address must be host:port");
    UpstreamEndpoint::new(host.to_string(), port.parse().unwrap()).unwrap()
}

async fn front(
    addr: &str,
    auth: Auth,
    password: String,
    audit: Option<zs_proto_redis::AuditRefusal>,
) -> SocketAddr {
    front_tls(addr, None, auth, password, audit).await
}

async fn front_tls(
    addr: &str,
    tls: Option<UpstreamTls>,
    auth: Auth,
    password: String,
    audit: Option<zs_proto_redis::AuditRefusal>,
) -> SocketAddr {
    front_logged(addr, tls, auth, password, audit, DiagLog::disabled()).await
}

async fn front_logged(
    addr: &str,
    tls: Option<UpstreamTls>,
    auth: Auth,
    password: String,
    audit: Option<zs_proto_redis::AuditRefusal>,
    diag: DiagLog,
) -> SocketAddr {
    let mut listener = RedisListener::bind_endpoint(
        "127.0.0.1:0",
        endpoint(addr),
        tls,
        auth,
        materialize(password),
    )
    .await
    .unwrap()
    .with_diag(diag, "redis-real")
    .with_caller_check(fake::admit_all());
    if let Some(audit) = audit {
        listener = listener.with_refusal_audit(audit);
    }
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    local
}

fn key(name: &str) -> String {
    format!(
        "zs-broker-test-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

fn leaks(bytes: &[u8], secret: &[u8]) -> bool {
    let window = secret.len().min(8);
    secret
        .windows(window)
        .any(|needle| bytes.windows(window).any(|part| part == needle))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn a_real_redis_is_brokered_end_to_end() {
    let addr = required("ZS_TEST_REDIS_ADDR");
    let password = required("ZS_TEST_REDIS_PASSWORD");
    let local = front(&addr, Auth::new(None), password, None).await;
    let mut client = fake::Client::connect(local).await;

    assert_eq!(client.command(&[b"PING"]).await, b"+PONG\r\n".to_vec());
    let key = key("e2e");
    assert_eq!(
        client.command(&[b"SET", key.as_bytes(), b"value"]).await,
        fake::OK
    );
    assert_eq!(
        client.command(&[b"GET", key.as_bytes()]).await,
        b"$5\r\nvalue\r\n".to_vec()
    );
    assert_eq!(
        client.command(&[b"DEL", key.as_bytes()]).await,
        b":1\r\n".to_vec(),
        "the fixture key is removed"
    );

    // The client's own password would fail the server. A +OK is the rewrite proof.
    for auth in [
        &[&b"AUTH"[..], b"client-supplied-password"][..],
        &[&b"AUTH"[..], b"default", b"client-supplied-password"][..],
    ] {
        assert_eq!(client.command(auth).await, fake::OK, "{auth:?}");
    }
    assert_eq!(
        client.command(&[b"ACL", b"WHOAMI"]).await,
        b"$7\r\ndefault\r\n"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn a_go_redis_handshake_pipelined_in_one_write_keeps_reply_order() {
    let addr = required("ZS_TEST_REDIS_ADDR");
    let password = required("ZS_TEST_REDIS_PASSWORD");
    let local = front(&addr, Auth::new(None), password, None).await;
    let mut client = fake::Client::connect(local).await;

    let mut write = Vec::new();
    for command in [
        &[&b"HELLO"[..], b"3", b"AUTH", b"default", b"zs-brokered"][..],
        &[&b"CLIENT"[..], b"SETINFO", b"LIB-NAME", b"go-redis"][..],
        &[&b"CLIENT"[..], b"SETINFO", b"LIB-VER", b"9.14.0"][..],
        &[&b"SELECT"[..], b"1"][..],
        &[&b"PING"[..]][..],
    ] {
        write.extend_from_slice(
            &zs_proto_redis::resp::Command::new(command.iter().map(|arg| arg.to_vec()).collect())
                .encode(),
        );
    }
    client.send(&write).await.unwrap();

    let hello = client.read_reply().await;
    assert_eq!(hello.first(), Some(&b'%'), "HELLO 3 answers a RESP3 map");
    assert!(
        hello.windows(7).any(|part| part == b"\r\nproto"),
        "{}",
        String::from_utf8_lossy(&hello)
    );
    for expected in [fake::OK, fake::OK, fake::OK, b"+PONG\r\n"] {
        assert_eq!(client.read_reply().await, expected.to_vec());
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Redis ACL user: set ZS_TEST_REDIS_ADDR, ZS_TEST_REDIS_ACL_USER and ZS_TEST_REDIS_ACL_PASSWORD"]
async fn an_acl_user_is_brokered_and_another_user_is_refused() {
    let addr = required("ZS_TEST_REDIS_ADDR");
    let user = required("ZS_TEST_REDIS_ACL_USER");
    let password = required("ZS_TEST_REDIS_ACL_PASSWORD");
    let (audit, refusals) = fake::audit_recorder();
    let local = front(&addr, Auth::new(Some(user.clone())), password, Some(audit)).await;

    let mut client = fake::Client::connect(local).await;
    let whoami = client.command(&[b"ACL", b"WHOAMI"]).await;
    assert_eq!(
        whoami,
        format!("${}\r\n{user}\r\n", user.len()).into_bytes(),
        "positive control: R1 logged in as the binding user"
    );
    assert_eq!(
        client
            .command(&[b"AUTH", user.as_bytes(), b"client-supplied-password"])
            .await,
        fake::OK,
        "the client's AUTH for the binding user is rewritten"
    );

    let mut other = fake::Client::connect(local).await;
    assert_eq!(
        other
            .command(&[b"AUTH", b"default", b"client-supplied-password"])
            .await,
        USER_MISMATCH.frame()
    );
    assert!(other.closed().await);
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", USER_MISMATCH_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn a_wrong_credential_is_refused_by_the_real_server() {
    let addr = required("ZS_TEST_REDIS_ADDR");
    let password = required("ZS_TEST_REDIS_PASSWORD");
    let right = front(&addr, Auth::new(None), password, None).await;
    let mut client = fake::Client::connect(right).await;
    assert_eq!(
        client.command(&[b"PING"]).await,
        b"+PONG\r\n".to_vec(),
        "positive control: the right credential logs in"
    );

    let (audit, refusals) = fake::audit_recorder();
    let wrong = front(
        &addr,
        Auth::new(None),
        "zs-wrong-password".into(),
        Some(audit),
    )
    .await;
    let mut client = fake::Client::connect(wrong).await;
    assert_eq!(client.read_reply().await, UPSTREAM_AUTH_FAILED.frame());
    assert!(client.closed().await);
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", UPSTREAM_AUTH_REFUSED_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn config_get_requirepass_closes_before_the_credential_reaches_the_client() {
    let addr = required("ZS_TEST_REDIS_ADDR");
    let password = required("ZS_TEST_REDIS_PASSWORD");
    let (audit, refusals) = fake::audit_recorder();
    let local = front(&addr, Auth::new(None), password.clone(), Some(audit)).await;
    let mut client = fake::Client::connect(local).await;
    assert_eq!(
        client
            .command(&[b"CONFIG", b"GET", b"maxmemory"])
            .await
            .first(),
        Some(&b'*'),
        "positive control: the default user may run CONFIG GET"
    );

    client
        .send_command(&[b"CONFIG", b"GET", b"requirepass"])
        .await
        .unwrap();
    let received = client.read_to_end().await;
    assert!(
        !leaks(&received, password.as_bytes()),
        "a credential window reached the client; {} bytes received",
        received.len()
    );
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", CREDENTIAL_ECHO_REASON)]
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Redis with no password: set ZS_TEST_REDIS_NOAUTH_ADDR"]
async fn a_real_redis_without_a_password_refuses_the_brokers_auth() {
    let addr = required("ZS_TEST_REDIS_NOAUTH_ADDR");
    let mut direct = fake::Client::connect(addr.parse().unwrap()).await;
    assert_eq!(
        direct.command(&[b"PING"]).await,
        b"+PONG\r\n".to_vec(),
        "positive control: the server needs no password"
    );

    let (audit, refusals) = fake::audit_recorder();
    let local = front(
        &addr,
        Auth::new(None),
        "unused-password".into(),
        Some(audit),
    )
    .await;
    let mut client = fake::Client::connect(local).await;

    assert_eq!(client.read_reply().await, UPSTREAM_AUTH_FAILED.frame());
    assert!(client.closed().await);
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", UPSTREAM_AUTH_REFUSED_REASON)]
    );
}

fn certs() -> PathBuf {
    PathBuf::from(required("ZS_TEST_REDIS_CERTS"))
}

fn leaf_sha256() -> [u8; 32] {
    let pem = std::fs::read(certs().join("server.pem")).unwrap();
    let der = CertificateDer::from_pem_slice(&pem).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(der.as_ref()));
    out
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a TLS Redis: set ZS_TEST_REDIS_TLS_ADDR, ZS_TEST_REDIS_CERTS, ZS_TEST_REDIS_ACL_USER and ZS_TEST_REDIS_ACL_PASSWORD"]
async fn an_acl_user_logs_in_over_verified_and_pinned_tls() {
    let addr = required("ZS_TEST_REDIS_TLS_ADDR");
    let user = required("ZS_TEST_REDIS_ACL_USER");
    let password = required("ZS_TEST_REDIS_ACL_PASSWORD");
    let ca = UpstreamTls::from_config(Some(&certs().join("ca.pem")), None).unwrap();
    for tls in [ca, UpstreamTls::Pinned(leaf_sha256())] {
        let local = front_tls(
            &addr,
            Some(tls),
            Auth::new(Some(user.clone())),
            password.clone(),
            None,
        )
        .await;
        let mut client = fake::Client::connect(local).await;
        assert_eq!(
            client.command(&[b"ACL", b"WHOAMI"]).await,
            format!("${}\r\n{user}\r\n", user.len()).into_bytes()
        );
        let key = key("tls");
        assert_eq!(
            client.command(&[b"SET", key.as_bytes(), b"over-tls"]).await,
            fake::OK
        );
        assert_eq!(
            client.command(&[b"GET", key.as_bytes()]).await,
            b"$8\r\nover-tls\r\n".to_vec()
        );
        assert_eq!(
            client.command(&[b"DEL", key.as_bytes()]).await,
            b":1\r\n".to_vec()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a TLS Redis: set ZS_TEST_REDIS_TLS_ADDR, ZS_TEST_REDIS_CERTS and ZS_TEST_REDIS_PASSWORD"]
async fn an_untrusted_or_misnamed_tls_upstream_is_refused_at_the_tls_step() {
    let addr = required("ZS_TEST_REDIS_TLS_ADDR");
    let password = required("ZS_TEST_REDIS_PASSWORD");
    let ca = UpstreamTls::from_config(Some(&certs().join("ca.pem")), None).unwrap();
    let positive = front_tls(
        &addr,
        Some(ca.clone()),
        Auth::new(None),
        password.clone(),
        None,
    )
    .await;
    let mut client = fake::Client::connect(positive).await;
    assert_eq!(
        client.command(&[b"PING"]).await,
        b"+PONG\r\n".to_vec(),
        "positive control: the test CA verifies 127.0.0.1"
    );

    let port = addr.rsplit_once(':').unwrap().1;
    for (upstream, tls) in [
        (addr.clone(), UpstreamTls::WhenOffered),
        (addr.clone(), UpstreamTls::Pinned([0x5a; 32])),
        (format!("localhost:{port}"), ca),
    ] {
        let (audit, refusals) = fake::audit_recorder();
        let dir = tempfile::tempdir().unwrap();
        let (path, diag) = fake::diag_log(dir.path());
        let local = front_logged(
            &upstream,
            Some(tls),
            Auth::new(None),
            password.clone(),
            Some(audit),
            diag.clone(),
        )
        .await;
        let mut client = fake::Client::connect(local).await;
        assert_eq!(
            client.read_reply().await,
            UPSTREAM_UNAVAILABLE.frame(),
            "{upstream}"
        );
        assert!(client.closed().await);
        assert_eq!(
            *refusals.lock().unwrap(),
            vec![("connect", UPSTREAM_UNAVAILABLE_REASON)],
            "{upstream}"
        );
        let (text, events) = fake::read_diag(&path, diag).await;
        assert!(
            events
                .iter()
                .any(|event| event["event"] == "tls" && event["fields"]["result"] == "failed"),
            "{upstream}: the refusal must come from the TLS step, not the TCP connect:\n{text}"
        );
        assert!(
            !events
                .iter()
                .any(|event| event["event"] == "upstream_auth_ok"),
            "{upstream}: {text}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Redis with no password: set ZS_TEST_REDIS_NOAUTH_ADDR"]
async fn a_real_open_redis_is_served_only_with_the_opt_in() {
    let addr = required("ZS_TEST_REDIS_NOAUTH_ADDR");
    let (audit, refusals) = fake::audit_recorder();
    let named_default = front(
        &addr,
        Auth::new(Some("default".into())),
        "unused-password".into(),
        Some(audit),
    )
    .await;
    let mut client = fake::Client::connect(named_default).await;
    assert_eq!(
        client.read_reply().await,
        UPSTREAM_AUTH_FAILED.frame(),
        "a binding that names `default` is refused like one without `user`"
    );
    assert_eq!(
        *refusals.lock().unwrap(),
        vec![("connect", UPSTREAM_AUTH_REFUSED_REASON)]
    );

    let (audit, refusals) = fake::audit_recorder();
    let opted_in = front(
        &addr,
        Auth::new(None).with_upstream_optional(true),
        "unused-password".into(),
        Some(audit),
    )
    .await;
    let mut client = fake::Client::connect(opted_in).await;
    let key = key("open");
    assert_eq!(
        client.command(&[b"SET", key.as_bytes(), b"open"]).await,
        fake::OK
    );
    assert_eq!(
        client.command(&[b"GET", key.as_bytes()]).await,
        b"$4\r\nopen\r\n".to_vec()
    );
    assert_eq!(
        client.command(&[b"ACL", b"WHOAMI"]).await,
        b"$7\r\ndefault\r\n".to_vec()
    );
    assert_eq!(
        client.command(&[b"DEL", key.as_bytes()]).await,
        b":1\r\n".to_vec()
    );
    assert!(refusals.lock().unwrap().is_empty());
}
