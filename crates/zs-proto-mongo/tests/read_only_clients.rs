#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;
#[path = "../../zs-conformance/tests/clients/matrix.rs"]
mod matrix;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use zs_diag::DiagLog;
use zs_proto_mongo::{Auth, MongoListener, UpstreamEndpoint, UpstreamTls};
use zs_protocol::SessionAccess;

const USER: &str = "zs_sha256";
const PASSWORD: &str = "zs-test-sha256-password";
const DATABASE: &str = "zsdb";
const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

struct Real {
    server: SocketAddr,
    certs: PathBuf,
}

fn required() -> bool {
    std::env::var_os("ZS_REQUIRE_MONGO").is_some()
}

fn real() -> Option<Real> {
    let found = std::env::var("ZS_TEST_MONGO")
        .ok()
        .filter(|v| !v.is_empty())
        .and_then(|value| value.parse().ok())
        .zip(
            std::env::var("ZS_TEST_MONGO_CERTS")
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        )
        .map(|(server, certs)| Real { server, certs });
    assert!(
        found.is_some() || !required(),
        "ZS_REQUIRE_MONGO is set: ZS_TEST_MONGO (ip:port) and ZS_TEST_MONGO_CERTS must be set"
    );
    found
}

async fn admin(real: &Real, dir: Option<&Path>, collection: &str, operation: &str) -> String {
    let mut command = matrix::node_command(dir, "mongodb", MANIFEST, "admin.js")
        .expect("the driver is needed for the fixture");
    let output = command
        .env("ZS_ADMIN_HOST", real.server.ip().to_string())
        .env("ZS_ADMIN_PORT", real.server.port().to_string())
        .env("ZS_ADMIN_USER", USER)
        .env("ZS_ADMIN_PASSWORD", PASSWORD)
        .env("ZS_ADMIN_DB", DATABASE)
        .env("ZS_ADMIN_COLLECTION", collection)
        .env("ZS_ADMIN_OP", operation)
        .output()
        .await
        .expect("node is needed to prepare the fixture");
    assert!(
        output.status.success(),
        "fixture operation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

async fn session(
    real: &Real,
    name: &str,
    dir: Option<&Path>,
    access: SessionAccess,
) -> Result<(), String> {
    let (expected_rows, expected_touched) = match access {
        SessionAccess::ReadOnly => ("1", "0"),
        SessionAccess::ReadWrite => ("2", "1"),
    };
    let label = matrix::label(access);
    let collection = format!("zs_ro_cl_{name}_{label}_{}", std::process::id());
    admin(real, dir, &collection, "seed").await;
    let (audit, refusals) = fake::audit_recorder();
    let tls = UpstreamTls::from_config(Some(&real.certs.join("ca.pem")), None).unwrap();
    let endpoint = UpstreamEndpoint::new(real.server.ip().to_string(), real.server.port()).unwrap();
    let listener = MongoListener::bind_endpoint(
        &fake::loopback(),
        endpoint,
        Some(tls),
        Auth::new(USER, DATABASE),
        fake::materialize_with(PASSWORD, access),
    )
    .await
    .unwrap()
    .with_refusal_audit(audit)
    .with_caller_check(fake::admit_all())
    .with_diag(DiagLog::disabled(), "real-mongo-read-only-clients");
    let local = fake::tcp_addr(listener.local());
    tokio::spawn(listener.serve());
    let mut command = matrix::node_command(dir, "mongodb", MANIFEST, "mongodb.js").unwrap();
    command
        .env("ZS_CLIENT_HOST", local.ip().to_string())
        .env("ZS_CLIENT_PORT", local.port().to_string())
        .env("ZS_CLIENT_DB", DATABASE)
        .env("ZS_CLIENT_TABLE", &collection)
        .env("ZS_CLIENT_ACCESS", label);
    let success = matrix::run(name, access, command).await;
    let rows = admin(real, dir, &collection, "count").await;
    let touched = admin(real, dir, &collection, "touched").await;
    admin(real, dir, &collection, "drop").await;
    let refused = refusals.lock().unwrap().len();
    matrix::judge(
        access,
        success,
        refused,
        &[
            ("documents in the collection", rows, expected_rows),
            ("documents updated", touched, expected_touched),
        ],
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a real MongoDB, node and the mongodb driver in tests/clients"]
async fn real_clients_read_through_a_read_only_session_and_are_refused_a_write() {
    let Some(real) = real() else { return };
    let dir = matrix::clients_dir();
    let dir = dir.as_deref();
    matrix::matrix(
        required(),
        &["mongodb"],
        |_| async move { matrix::node_version(dir, "mongodb").await },
        |name, access| {
            let real = &real;
            async move { session(real, &name, dir, access).await }
        },
    )
    .await;
}
