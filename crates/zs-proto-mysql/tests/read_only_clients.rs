#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use zs_diag::DiagLog;
use zs_proto_mysql::UpstreamTls;
use zs_protocol::SessionAccess;

const ROOT_PASSWORD: &str = "zs-test-root";
const USER: &str = "zs_ro_clients";
const USER_PASSWORD: &str = "zs-ro-clients-pw";
const DATABASE: &str = "zs_ro_clients";
const CLIENTS: [&str; 1] = ["mysql2"];
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

type Server = (String, u16);

fn server() -> Option<Server> {
    let required = std::env::var_os("ZS_REQUIRE_MYSQL").is_some();
    let found = std::env::var("ZS_TEST_MYSQL_PLAIN")
        .ok()
        .filter(|v| !v.is_empty())
        .and_then(|value| {
            let (host, port) = value.rsplit_once(':')?;
            Some((host.to_string(), port.parse().ok()?))
        });
    assert!(
        found.is_some() || !required,
        "ZS_REQUIRE_MYSQL is set and ZS_TEST_MYSQL_PLAIN is not host:port"
    );
    found
}

fn clients_dir() -> Option<PathBuf> {
    std::env::var_os("ZS_CLIENTS_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn script(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/clients")
        .join(file)
}

fn node(dir: Option<&Path>, script_file: &str, tail: &[&str]) -> Result<Command, String> {
    let dir = dir.ok_or("ZS_CLIENTS_DIR is not set")?;
    let modules = dir.join("node/node_modules");
    if !modules.join("mysql2").exists() {
        return Err(format!(
            "{} is not installed",
            modules.join("mysql2").display()
        ));
    }
    let mut command = Command::new("node");
    command
        .arg(script(script_file))
        .args(tail)
        .env("NODE_PATH", modules)
        .kill_on_drop(true)
        .stdin(Stdio::null());
    Ok(command)
}

async fn version(name: &str, dir: Option<&Path>) -> Result<String, String> {
    if name != "mysql2" {
        return Err(format!("unknown client {name}"));
    }
    let modules = dir
        .ok_or("ZS_CLIENTS_DIR is not set")?
        .join("node/node_modules");
    if !modules.join("mysql2").exists() {
        return Err(format!(
            "{} is not installed",
            modules.join("mysql2").display()
        ));
    }
    let output = Command::new("node")
        .args(["-p", "require('mysql2/package.json').version"])
        .env("NODE_PATH", modules)
        .output()
        .await
        .map_err(|e| format!("cannot start the client runtime: {e}"))?;
    if !output.status.success() {
        return Err("the client runtime or driver does not start".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn admin(server: &Server, dir: Option<&Path>, sql: &str) -> String {
    let mut command = node(dir, "admin.js", &[]).expect("the driver is needed for the fixture");
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

async fn run(
    name: &str,
    dir: Option<&Path>,
    local: SocketAddr,
    table: &str,
    access: &str,
) -> (bool, Vec<String>) {
    assert_eq!(name, "mysql2");
    let mut command = node(dir, "mysql2.js", &[]).unwrap();
    command
        .env("ZS_CLIENT_HOST", local.ip().to_string())
        .env("ZS_CLIENT_PORT", local.port().to_string())
        .env("ZS_CLIENT_USER", USER)
        .env("ZS_CLIENT_DB", DATABASE)
        .env("ZS_CLIENT_TABLE", table)
        .env("ZS_CLIENT_ACCESS", access);
    match tokio::time::timeout(CLIENT_TIMEOUT, command.output()).await {
        Ok(Ok(output)) => {
            let mut lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::to_string)
                .collect();
            lines.extend(
                String::from_utf8_lossy(&output.stderr)
                    .lines()
                    .map(|l| format!("stderr: {l}")),
            );
            (output.status.success(), lines)
        }
        Ok(Err(e)) => (false, vec![format!("could not start: {e}")]),
        Err(_) => (false, vec![format!("timed out after {CLIENT_TIMEOUT:?}")]),
    }
}

async fn session(
    server: &Server,
    name: &str,
    dir: Option<&Path>,
    access: SessionAccess,
) -> Result<(), String> {
    let (label, expected_rows) = match access {
        SessionAccess::ReadOnly => ("read_only", "1"),
        SessionAccess::ReadWrite => ("read_write", "4"),
    };
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
    let (success, lines) = run(name, dir, local, &table, label).await;
    for line in &lines {
        println!("  {name} {label}: {line}");
    }
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
    let mut problems = Vec::new();
    if !success {
        problems.push("the client reported a failure".to_string());
    }
    if rows != expected_rows {
        problems.push(format!(
            "the table holds {rows} rows, expected {expected_rows}"
        ));
    }
    match access {
        SessionAccess::ReadOnly if refused == 0 => {
            problems.push("the agent audited no refusal of the switch-off attempt".to_string());
        }
        SessionAccess::ReadWrite if refused != 0 => {
            problems.push(format!("a read-write session was refused {refused} times"));
        }
        _ => {}
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a real MySQL, node and the mysql2 driver in tests/clients"]
async fn real_clients_read_through_a_read_only_session_and_are_refused_a_write() {
    let Some(server) = server() else { return };
    let dir = clients_dir();
    let require = std::env::var_os("ZS_REQUIRE_CLIENTS").is_some();
    let mut failures = Vec::new();
    for name in CLIENTS {
        let found = match version(name, dir.as_deref()).await {
            Ok(found) => found,
            Err(reason) => {
                println!("client {name}: not run: {reason}");
                if require {
                    failures.push(format!("{name}: not run: {reason}"));
                }
                continue;
            }
        };
        let read_only = session(&server, name, dir.as_deref(), SessionAccess::ReadOnly).await;
        let control = session(&server, name, dir.as_deref(), SessionAccess::ReadWrite).await;
        let verdict = |outcome: &Result<(), String>| match outcome {
            Ok(()) => "PASS".to_string(),
            Err(why) => format!("FAIL ({why})"),
        };
        println!(
            "client {name} ({found}): read-only session {}; read-write control {}",
            verdict(&read_only),
            verdict(&control)
        );
        if let Err(why) = read_only {
            failures.push(format!("{name} read-only: {why}"));
        }
        if let Err(why) = control {
            failures.push(format!("{name} read-write control: {why}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
