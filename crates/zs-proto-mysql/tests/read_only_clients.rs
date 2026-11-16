#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;
#[path = "../../zs-conformance/tests/clients/matrix.rs"]
mod matrix;

use std::path::Path;

use zs_diag::DiagLog;
use zs_proto_mysql::UpstreamTls;
use zs_protocol::SessionAccess;

const ROOT_PASSWORD: &str = "zs-test-root";
const USER: &str = "zs_ro_clients";
const USER_PASSWORD: &str = "zs-ro-clients-pw";
const DATABASE: &str = "zs_ro_clients";
const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

type Server = (String, u16);

fn required() -> bool {
    std::env::var_os("ZS_REQUIRE_MYSQL").is_some()
}

fn server() -> Option<Server> {
    let found = std::env::var("ZS_TEST_MYSQL_PLAIN")
        .ok()
        .filter(|v| !v.is_empty())
        .and_then(|value| {
            let (host, port) = value.rsplit_once(':')?;
            Some((host.to_string(), port.parse().ok()?))
        });
    assert!(
        found.is_some() || !required(),
        "ZS_REQUIRE_MYSQL is set and ZS_TEST_MYSQL_PLAIN is not host:port"
    );
    found
}

async fn admin(server: &Server, dir: Option<&Path>, sql: &str) -> String {
    let mut command = matrix::node_command(dir, "mysql2", MANIFEST, "admin.js")
        .expect("the driver is needed for the fixture");
    let output = command
        .env("ZS_ADMIN_HOST", &server.0)
        .env("ZS_ADMIN_PORT", server.1.to_string())
        .env("ZS_ADMIN_PASSWORD", ROOT_PASSWORD)
        .env("ZS_ADMIN_SQL", sql)
        .output()
        .await
        .expect("node is needed to prepare the fixture");
    assert!(
        output.status.success(),
        "fixture statement failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

async fn prepare(server: &Server, dir: Option<&Path>, table: &str) {
    for sql in [
        format!("CREATE DATABASE IF NOT EXISTS {DATABASE}"),
        format!(
            "CREATE USER IF NOT EXISTS '{USER}'@'%' IDENTIFIED WITH mysql_native_password BY '{USER_PASSWORD}'"
        ),
        format!(
            "ALTER USER '{USER}'@'%' IDENTIFIED WITH mysql_native_password BY '{USER_PASSWORD}'"
        ),
        format!("GRANT SELECT, INSERT ON {DATABASE}.* TO '{USER}'@'%'"),
        format!("DROP TABLE IF EXISTS {DATABASE}.{table}"),
        format!("CREATE TABLE {DATABASE}.{table} (id INT)"),
        format!("INSERT INTO {DATABASE}.{table} VALUES (1)"),
    ] {
        admin(server, dir, &sql).await;
    }
}

async fn session(
    server: &Server,
    name: &str,
    dir: Option<&Path>,
    access: SessionAccess,
) -> Result<(), String> {
    let expected_rows = match access {
        SessionAccess::ReadOnly => "1",
        SessionAccess::ReadWrite => "4",
    };
    let label = matrix::label(access);
    let table = format!("t_{name}_{label}_{}", std::process::id());
    prepare(server, dir, &table).await;
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        &server.0,
        server.1,
        UpstreamTls::WhenOffered,
        fake::materialize_with(USER_PASSWORD, access),
        DiagLog::disabled(),
        Some(audit),
    )
    .await;
    let mut command = matrix::node_command(dir, "mysql2", MANIFEST, "mysql2.js").unwrap();
    command
        .env("ZS_CLIENT_HOST", local.ip().to_string())
        .env("ZS_CLIENT_PORT", local.port().to_string())
        .env("ZS_CLIENT_USER", USER)
        .env("ZS_CLIENT_DB", DATABASE)
        .env("ZS_CLIENT_TABLE", &table)
        .env("ZS_CLIENT_ACCESS", label);
    let success = matrix::run(name, access, command).await;
    let rows = admin(
        server,
        dir,
        &format!("SELECT count(*) FROM {DATABASE}.{table}"),
    )
    .await;
    admin(
        server,
        dir,
        &format!("DROP TABLE IF EXISTS {DATABASE}.{table}"),
    )
    .await;
    let refused = refusals.lock().unwrap().len();
    matrix::judge(
        access,
        success,
        refused,
        &[("rows in the table", rows, expected_rows)],
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a real MySQL, node and the mysql2 driver in tests/clients"]
async fn real_clients_read_through_a_read_only_session_and_are_refused_a_write() {
    let Some(server) = server() else { return };
    let dir = matrix::clients_dir();
    let dir = dir.as_deref();
    matrix::matrix(
        required(),
        &["mysql2"],
        |_| async move { matrix::node_version(dir, "mysql2").await },
        |name, access| {
            let server = &server;
            async move { session(server, &name, dir, access).await }
        },
    )
    .await;
}
