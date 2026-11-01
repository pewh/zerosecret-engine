#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fake::CLIENT_CAPS;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use zs_diag::DiagLog;
use zs_proto_mysql::packet;
use zs_proto_mysql::{
    CHANGE_USER_REFUSED, ClientAuth, METHOD_REFUSED, MysqlListener, TLS_REFUSED,
    UPSTREAM_AUTH_FAILED, UpstreamEndpoint, UpstreamTls,
};

const ROOT_PASSWORD: &str = "zs-test-root";
const SHA2_PASSWORD: &str = "zs-test-sha2-password";
const NATIVE_PASSWORD: &str = "zs-test-native-password";
const CAPS: u32 = CLIENT_CAPS & !packet::CLIENT_CONNECT_WITH_DB;

type Server = (String, u16);

struct Real {
    tls: Server,
    plain: Server,
    certs: PathBuf,
}

fn address(var: &str) -> Option<Server> {
    let value = std::env::var(var).ok().filter(|v| !v.is_empty())?;
    let (host, port) = value.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

fn configured() -> Option<Real> {
    Some(Real {
        tls: address("ZS_TEST_MYSQL")?,
        plain: address("ZS_TEST_MYSQL_PLAIN")?,
        certs: PathBuf::from(
            std::env::var("ZS_TEST_MYSQL_CERTS")
                .ok()
                .filter(|v| !v.is_empty())?,
        ),
    })
}

fn real() -> Option<Real> {
    let found = configured();
    assert!(
        found.is_some() || std::env::var("ZS_REQUIRE_MYSQL").is_err(),
        "ZS_REQUIRE_MYSQL is set: ZS_TEST_MYSQL, ZS_TEST_MYSQL_PLAIN and ZS_TEST_MYSQL_CERTS must be set"
    );
    found
}

impl Real {
    fn ca(&self) -> UpstreamTls {
        UpstreamTls::from_config(Some(&self.certs.join("ca.pem")), None).unwrap()
    }

    fn leaf_sha256(&self) -> [u8; 32] {
        let pem = std::fs::read(self.certs.join("server.pem")).unwrap();
        let der = CertificateDer::from_pem_slice(&pem).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(der.as_ref()));
        out
    }
}

async fn listen(
    server: &Server,
    tls: UpstreamTls,
    password: &'static str,
    diag: DiagLog,
) -> SocketAddr {
    fake::listen(
        &server.0,
        server.1,
        tls,
        fake::materialize(password),
        diag,
        None,
    )
    .await
}

async fn login(local: SocketAddr, user: &[u8]) -> fake::Session {
    fake::login_as(local, CAPS, user, None).await
}

async fn flush_privileges(server: &Server, tls: UpstreamTls) {
    let local = listen(server, tls, ROOT_PASSWORD, DiagLog::disabled()).await;
    let mut session = login(local, b"root").await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "root login"
    );
    let answer = session.query("FLUSH PRIVILEGES").await.unwrap();
    assert_eq!(answer.first(), Some(&packet::OK_HEADER), "FLUSH PRIVILEGES");
}

fn diag_log(dir: &Path) -> (PathBuf, DiagLog) {
    let path = dir.join("diag.jsonl");
    let diag = DiagLog::open_with_cap(&path, "t-1", 1 << 20).unwrap();
    (path, diag)
}

async fn close_and_read(path: &Path, diag: DiagLog) -> (String, Vec<serde_json::Value>) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    diag.close();
    let text = std::fs::read_to_string(path).unwrap();
    let events = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (text, events)
}

fn count(events: &[serde_json::Value], event: &str, field: &str, value: &str) -> usize {
    events
        .iter()
        .filter(|e| {
            e["event"] == event && (e["fields"][field] == value || e["error"][field] == value)
        })
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn caching_sha2_logs_in_over_verified_tls_by_full_auth_then_by_the_fast_path() {
    let Some(real) = real() else { return };
    flush_privileges(&real.tls, real.ca()).await;
    let home = tempfile::tempdir().unwrap();
    let (path, diag) = diag_log(home.path());
    let local = listen(&real.tls, real.ca(), SHA2_PASSWORD, diag.clone()).await;

    let mut first = login(local, b"zs_sha2").await;
    assert_eq!(
        first.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "full auth inside TLS"
    );
    let rows = first.query("SELECT 1").await.unwrap();
    assert_ne!(rows.first(), Some(&packet::ERR_HEADER));
    let second = login(local, b"zs_sha2").await;
    assert_eq!(
        second.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "fast path"
    );
    drop((first, second));

    let (text, events) = close_and_read(&path, diag).await;
    assert_eq!(
        count(&events, "auth_step", "step", "full_auth"),
        1,
        "{text}"
    );
    assert_eq!(count(&events, "auth_step", "step", "fast_ok"), 1, "{text}");
    assert_eq!(count(&events, "tls", "result", "verified"), 2, "{text}");
    assert!(!text.contains(SHA2_PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn native_logs_in_over_plaintext_and_caching_sha2_full_auth_is_refused() {
    let Some(real) = real() else { return };
    let home = tempfile::tempdir().unwrap();
    let (path, diag) = diag_log(home.path());
    let native = listen(
        &real.plain,
        UpstreamTls::WhenOffered,
        NATIVE_PASSWORD,
        diag.clone(),
    )
    .await;
    let mut session = login(native, b"zs_native").await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control: native over plaintext"
    );
    assert_ne!(
        session.query("SELECT 1").await.unwrap().first(),
        Some(&packet::ERR_HEADER)
    );

    flush_privileges(&real.plain, UpstreamTls::WhenOffered).await;
    let sha2 = listen(
        &real.plain,
        UpstreamTls::WhenOffered,
        SHA2_PASSWORD,
        diag.clone(),
    )
    .await;
    let refused = login(sha2, b"zs_sha2").await;
    assert_eq!(refused.reply.payload, METHOD_REFUSED.packet());

    let (text, events) = close_and_read(&path, diag).await;
    assert!(
        count(&events, "tls", "result", "not_offered") >= 2,
        "the plain server offered TLS: {text}"
    );
    assert_eq!(
        count(&events, "upstream_failed", "kind", "cleartext_without_tls"),
        1,
        "{text}"
    );
    assert!(!text.contains(SHA2_PASSWORD) && !text.contains(NATIVE_PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_password_gets_the_fixed_refusal_and_the_log_keeps_errno_1045() {
    let Some(real) = real() else { return };
    let right = listen(&real.tls, real.ca(), NATIVE_PASSWORD, DiagLog::disabled()).await;
    assert_eq!(
        login(right, b"zs_native").await.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control"
    );
    let home = tempfile::tempdir().unwrap();
    let (path, diag) = diag_log(home.path());
    let wrong = listen(&real.tls, real.ca(), fake::WRONG, diag.clone()).await;

    let session = login(wrong, b"zs_native").await;

    assert_eq!(session.reply.payload, UPSTREAM_AUTH_FAILED.packet());
    let (text, events) = close_and_read(&path, diag).await;
    let failed = events
        .iter()
        .find(|e| e["event"] == "upstream_auth_failed")
        .unwrap_or_else(|| panic!("no upstream_auth_failed: {text}"));
    assert_eq!(failed["fields"]["errno"], 1045);
    assert!(
        failed["error"]["text"]
            .as_str()
            .unwrap()
            .starts_with("Access denied")
    );
    assert!(!text.contains(fake::WRONG) && !text.contains(NATIVE_PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_pin_accepts_the_server_leaf_and_anything_else_refuses() {
    let Some(real) = real() else { return };
    let pinned = listen(
        &real.tls,
        UpstreamTls::Pinned(real.leaf_sha256()),
        NATIVE_PASSWORD,
        DiagLog::disabled(),
    )
    .await;
    assert_eq!(
        login(pinned, b"zs_native").await.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control: the right pin"
    );
    for tls in [UpstreamTls::Pinned([0x5a; 32]), UpstreamTls::WhenOffered] {
        let local = listen(&real.tls, tls, NATIVE_PASSWORD, DiagLog::disabled()).await;
        assert_eq!(
            login(local, b"zs_native").await.reply.payload,
            TLS_REFUSED.packet()
        );
    }
    let required = listen(&real.plain, real.ca(), NATIVE_PASSWORD, DiagLog::disabled()).await;
    assert_eq!(
        fake::first_packet(required).await.payload,
        TLS_REFUSED.packet(),
        "TLS is required and the plain server does not offer it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn change_user_is_refused_against_a_real_server() {
    let Some(real) = real() else { return };
    let local = listen(&real.tls, real.ca(), NATIVE_PASSWORD, DiagLog::disabled()).await;
    let mut session = login(local, b"zs_native").await;
    assert_ne!(
        session.query("SELECT 1").await.unwrap().first(),
        Some(&packet::ERR_HEADER),
        "positive control"
    );

    let refused = session.command(b"\x11root\x00\x00").await.unwrap();

    assert_eq!(refused.payload, CHANGE_USER_REFUSED.packet());
    assert!(session.closed().await);
}

const CLIENT_IMAGES: [&str; 4] = ["mysql:5.7", "mysql:8.0", "mysql:8.4", "mysql:9"];

async fn listen_with(server: &Server, auth: ClientAuth, tls: UpstreamTls) -> SocketAddr {
    let endpoint = UpstreamEndpoint::new(server.0.as_str(), server.1).unwrap();
    let listener = MysqlListener::bind_endpoint(
        "127.0.0.1:0",
        endpoint,
        tls,
        fake::materialize(NATIVE_PASSWORD),
    )
    .await
    .unwrap()
    .with_client_auth(auth);
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    local
}

fn client_logs_in(image: &str, port: u16) -> bool {
    let output = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "host",
            image,
            "mysql",
            "-h127.0.0.1",
        ])
        .arg(format!("-P{port}"))
        .args(["-uzs_native", "--ssl-mode=DISABLED", "-N", "-e", "SELECT 1"])
        .output();
    match output {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            let stderr = &o.stderr[..o.stderr.len().min(2000)];
            eprintln!(
                "{image} client failed ({}): {}",
                o.status,
                String::from_utf8_lossy(stderr)
            );
            false
        }
        Err(error) => {
            eprintln!("{image} client did not start: {error}");
            false
        }
    }
}

#[ignore = "needs Linux docker --network host; CI db-real runs it"]
#[tokio::test(flavor = "multi_thread")]
async fn real_mysql_clients_log_in_through_the_listener() {
    let Some(real) = real() else { return };
    if std::env::var("ZS_TEST_MYSQL_CLIENTS").is_err() {
        return;
    }
    let mut matrix = Vec::new();
    for auth in [ClientAuth::CachingSha2, ClientAuth::Native] {
        let local = listen_with(&real.tls, auth, real.ca()).await;
        for image in CLIENT_IMAGES {
            let ok = tokio::task::spawn_blocking(move || client_logs_in(image, local.port()))
                .await
                .unwrap();
            matrix.push((image, auth, ok));
        }
    }
    eprintln!("zs-mysql-client-matrix {matrix:?}");
    let works = |image: &str, auth: ClientAuth| {
        matrix
            .iter()
            .any(|(i, a, ok)| *i == image && *a == auth && *ok)
    };
    for image in CLIENT_IMAGES {
        assert!(
            works(image, ClientAuth::CachingSha2) || works(image, ClientAuth::Native),
            "{image} logs in with neither greeting: {matrix:?}"
        );
    }
    for image in ["mysql:8.0", "mysql:8.4", "mysql:9"] {
        assert!(
            works(image, ClientAuth::CachingSha2),
            "{image} fails with the default greeting: {matrix:?}"
        );
    }
}
