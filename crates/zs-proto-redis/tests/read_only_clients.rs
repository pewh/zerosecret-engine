#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;
#[path = "../../zs-conformance/tests/clients/matrix.rs"]
mod matrix;

use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;

use tokio::process::Command;
use zs_diag::DiagLog;
use zs_proto_redis::{Auth, RedisListener, UpstreamEndpoint};
use zs_protocol::SessionAccess;

const KEYS: [&str; 6] = ["k", "new", "ctr", "list", "pipe", "multi"];
const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

struct Real {
    address: SocketAddr,
    password: String,
}

fn required() -> bool {
    std::env::var_os("ZS_REQUIRE_REDIS").is_some()
}

fn real() -> Option<Real> {
    let found = std::env::var("ZS_TEST_REDIS_ADDR")
        .ok()
        .and_then(|value| value.parse().ok())
        .zip(std::env::var("ZS_TEST_REDIS_PASSWORD").ok())
        .map(|(address, password)| Real { address, password });
    assert!(
        found.is_some() || !required(),
        "ZS_REQUIRE_REDIS is set: ZS_TEST_REDIS_ADDR (ip:port) and ZS_TEST_REDIS_PASSWORD must be set"
    );
    found
}

async fn admin(real: &Real, arguments: &[&str]) -> String {
    let output = Command::new("sh")
        .arg(matrix::script(MANIFEST, "admin.sh"))
        .args(arguments)
        .env("ZS_ADMIN_HOST", real.address.ip().to_string())
        .env("ZS_ADMIN_PORT", real.address.port().to_string())
        .env("ZS_ADMIN_PASSWORD", &real.password)
        .stdin(Stdio::null())
        .output()
        .await
        .expect("redis-cli is needed to prepare the fixture");
    assert!(
        output.status.success(),
        "fixture command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn names(prefix: &str) -> Vec<String> {
    KEYS.iter().map(|key| format!("{prefix}:{key}")).collect()
}

async fn front(real: &Real, access: SessionAccess) -> (SocketAddr, fake::Refusals) {
    let password = real.password.clone();
    let (audit, refusals) = fake::audit_recorder();
    let materialize: zs_protocol::Materialize =
        Arc::new(move |_| Ok(fake::granted_with(password.as_bytes(), access)));
    let endpoint =
        UpstreamEndpoint::new(real.address.ip().to_string(), real.address.port()).unwrap();
    let listener = RedisListener::bind_endpoint(
        &fake::loopback(),
        endpoint,
        None,
        Auth::new(None),
        materialize,
    )
    .await
    .unwrap()
    .with_diag(DiagLog::disabled(), "redis-real-read-only-clients")
    .with_caller_check(fake::admit_all())
    .with_refusal_audit(audit);
    let local = fake::tcp_addr(listener.local());
    tokio::spawn(listener.serve());
    (local, refusals)
}

async fn session(
    real: &Real,
    name: &str,
    dir: Option<&Path>,
    access: SessionAccess,
) -> Result<(), String> {
    let (expected_present, expected_value) = match access {
        SessionAccess::ReadOnly => ("1", "v1"),
        SessionAccess::ReadWrite => ("5", ""),
    };
    let label = matrix::label(access);
    let prefix = format!("zs-ro-cl-{name}-{label}-{}", std::process::id());
    let keys = names(&prefix);
    let all: Vec<&str> = keys.iter().map(String::as_str).collect();
    let mut cleanup = vec!["DEL"];
    cleanup.extend(&all);
    admin(real, &cleanup).await;
    admin(real, &["SET", &keys[0], "v1", "EX", "300"]).await;
    let (local, refusals) = front(real, access).await;
    let mut command = matrix::node_command(dir, "ioredis", MANIFEST, "ioredis.js").unwrap();
    command
        .env("ZS_CLIENT_HOST", local.ip().to_string())
        .env("ZS_CLIENT_PORT", local.port().to_string())
        .env("ZS_CLIENT_TABLE", &prefix)
        .env("ZS_CLIENT_ACCESS", label);
    let success = matrix::run(name, access, command).await;
    let mut exists = vec!["EXISTS"];
    exists.extend(&all);
    let present = admin(real, &exists).await;
    let value = admin(real, &["GET", &keys[0]]).await;
    admin(real, &cleanup).await;
    let refused = refusals.lock().unwrap().len();
    matrix::judge(
        access,
        success,
        refused,
        &[
            ("keys that exist", present, expected_present),
            ("value of the seeded key", value, expected_value),
        ],
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a real Redis, redis-cli, node and the ioredis driver in tests/clients"]
async fn real_clients_read_through_a_read_only_session_and_are_refused_a_write() {
    let Some(real) = real() else { return };
    let dir = matrix::clients_dir();
    let dir = dir.as_deref();
    matrix::matrix(
        required(),
        &["ioredis"],
        |_| async move { matrix::node_version(dir, "ioredis").await },
        |name, access| {
            let real = &real;
            async move { session(real, &name, dir, access).await }
        },
    )
    .await;
}
