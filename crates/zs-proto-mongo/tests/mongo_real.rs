#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::PathBuf;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use zs_diag::DiagLog;
use zs_proto_mongo::bson::Doc;
use zs_proto_mongo::{Auth, MongoListener, UPSTREAM_AUTH_FAILED, UpstreamEndpoint, UpstreamTls};

const SHA256_USER: &str = "zs_sha256";
const SHA256_SOURCE: &str = "zsdb";
const SHA256_PASSWORD: &str = "zs-test-sha256-password";
const SHA1_USER: &str = "zs_sha1";
const SHA1_SOURCE: &str = "admin";
const SHA1_PASSWORD: &str = "zs-test-sha1-password";

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

    async fn listen(
        &self,
        tls: Option<UpstreamTls>,
        user: &str,
        source: &str,
        password: &'static str,
        diag: DiagLog,
    ) -> SocketAddr {
        let endpoint = UpstreamEndpoint::new(self.server.0.clone(), self.server.1).unwrap();
        let listener = MongoListener::bind_endpoint(
            "127.0.0.1:0",
            endpoint,
            tls,
            Auth::new(user, source),
            fake::materialize(password),
        )
        .await
        .unwrap()
        .with_caller_check(fake::admit_all())
        .with_diag(diag, "real-mongo");
        let local = listener.local_addr();
        tokio::spawn(listener.serve());
        local
    }
}

fn insert(probe: &str) -> Doc {
    Doc::new()
        .with_str("insert", "zs_real")
        .with_array(
            "documents",
            &Doc::new().with_doc("0", &Doc::new().with_str("probe", probe)),
        )
        .with_str("$db", "zsdb")
}

fn find(probe: &str) -> Doc {
    Doc::new()
        .with_str("find", "zs_real")
        .with_doc("filter", &Doc::new().with_str("probe", probe))
        .with_str("$db", "zsdb")
}

async fn read_and_write(local: SocketAddr, probe: &str) {
    let mut client = fake::Client::connect(local).await;
    let hello = client.legacy_handshake().await.unwrap();
    assert!(hello.truthy("ok"), "{:?}", hello.str("errmsg"));
    assert_eq!(hello.str("setName"), Some("rs0"));
    assert_eq!(hello.strings("hosts"), Some(vec![local.to_string()]));
    assert_eq!(hello.str("primary"), Some(local.to_string().as_str()));
    let inserted = client.command(insert(probe)).await.unwrap();
    assert!(inserted.truthy("ok"), "{:?}", inserted.str("errmsg"));
    assert_eq!(inserted.int("n"), Some(1));
    let found = client.command(find(probe)).await.unwrap();
    assert!(found.truthy("ok"), "{:?}", found.str("errmsg"));
    let first = found
        .doc("cursor")
        .and_then(|cursor| cursor.doc("firstBatch"))
        .and_then(|batch| batch.doc("0"))
        .expect("the find reply carries cursor.firstBatch[0]");
    assert_eq!(first.str("probe"), Some(probe));
}

struct Login {
    user: &'static str,
    source: &'static str,
    password: &'static str,
    mechanism: &'static str,
    probe: &'static str,
}

const SHA256: Login = Login {
    user: SHA256_USER,
    source: SHA256_SOURCE,
    password: SHA256_PASSWORD,
    mechanism: "SCRAM-SHA-256",
    probe: "sha256",
};

const SHA1: Login = Login {
    user: SHA1_USER,
    source: SHA1_SOURCE,
    password: SHA1_PASSWORD,
    mechanism: "SCRAM-SHA-1",
    probe: "sha1",
};

async fn logs_in_and_works(login: Login, over_tls: bool) {
    let Some(real) = real() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let tls = over_tls.then(|| real.ca());
    let local = real
        .listen(tls, login.user, login.source, login.password, diag.clone())
        .await;
    read_and_write(local, login.probe).await;
    let (log, events) = fake::read_diag(&path, diag).await;
    let expected = if over_tls { "verified" } else { "plaintext" };
    assert_eq!(
        fake::in_conn(&events, "tls", 1)[0]["fields"]["result"],
        expected,
        "{log}"
    );
    assert_eq!(
        fake::in_conn(&events, "upstream_auth_ok", 1)[0]["fields"]["mechanism"],
        login.mechanism,
        "{log}"
    );
    assert!(!log.contains(login.password));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sha256_user_logs_in_over_verified_tls_and_reads_and_writes() {
    logs_in_and_works(SHA256, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sha256_user_logs_in_over_plaintext_and_reads_and_writes() {
    logs_in_and_works(SHA256, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sha1_user_logs_in_over_verified_tls_and_reads_and_writes() {
    logs_in_and_works(SHA1, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sha1_user_logs_in_over_plaintext_and_reads_and_writes() {
    logs_in_and_works(SHA1, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_leaf_logs_in() {
    let Some(real) = real() else { return };
    let local = real
        .listen(
            Some(UpstreamTls::Pinned(real.leaf_sha256())),
            SHA256_USER,
            SHA256_SOURCE,
            SHA256_PASSWORD,
            DiagLog::disabled(),
        )
        .await;
    read_and_write(local, "pinned").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_password_is_refused_with_code_18() {
    let Some(real) = real() else { return };
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = real
        .listen(
            Some(real.ca()),
            SHA256_USER,
            SHA256_SOURCE,
            "zs-test-wrong",
            diag.clone(),
        )
        .await;
    let mut client = fake::Client::connect(local).await;
    let reply = client.legacy_handshake().await.unwrap();
    fake::assert_error(&reply, 18, UPSTREAM_AUTH_FAILED.message);
    let (log, events) = fake::read_diag(&path, diag).await;
    let failed = fake::in_conn(&events, "upstream_auth_failed", 1);
    assert_eq!(failed[0]["fields"]["code"], 18, "{log}");
    assert!(!log.contains("zs-test-wrong"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Linux host networking and the mongo:8.0 image; CI runs it"]
async fn a_real_driver_runs_insert_find_and_a_transaction_through_the_agent() {
    let Some(real) = real() else { return };
    let local = real
        .listen(
            Some(real.ca()),
            SHA256_USER,
            SHA256_SOURCE,
            SHA256_PASSWORD,
            DiagLog::disabled(),
        )
        .await;
    let script = r#"
const c = db.getSiblingDB("zsdb").zs_driver;
c.insertOne({ probe: "driver" });
const s = db.getMongo().startSession();
s.withTransaction(() => { s.getDatabase("zsdb").zs_driver.insertOne({ probe: "txn" }); });
s.endSession();
const one = c.findOne({ probe: "driver" });
if (!one) throw new Error("no find result");
print(c.countDocuments({ probe: { $in: ["driver", "txn"] } }) >= 2 ? "zs-driver-ok" : "zs-driver-bad");
"#;
    let uri = format!("mongodb://{local}/zsdb");
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("docker")
            .args([
                "run",
                "--rm",
                "--network",
                "host",
                "mongo:8.0",
                "mongosh",
                "--quiet",
                &uri,
                "--eval",
                script,
            ])
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("zs-driver-ok"),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
