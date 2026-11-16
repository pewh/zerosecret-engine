#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use zs_diag::DiagLog;
use zs_proto_mongo::{Auth, MongoListener, UpstreamEndpoint, UpstreamTls};
use zs_protocol::SessionAccess;

const USER: &str = "zs_sha256";
const PASSWORD: &str = "zs-test-sha256-password";
const DATABASE: &str = "zsdb";
const CLIENTS: [&str; 1] = ["mongodb"];
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

struct Real {
    server: SocketAddr,
    certs: PathBuf,
}

fn real() -> Option<Real> {
    let required = std::env::var_os("ZS_REQUIRE_MONGO").is_some();
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
        found.is_some() || !required,
        "ZS_REQUIRE_MONGO is set: ZS_TEST_MONGO (ip:port) and ZS_TEST_MONGO_CERTS must be set"
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

fn modules(dir: Option<&Path>) -> Result<PathBuf, String> {
    let modules = dir
        .ok_or("ZS_CLIENTS_DIR is not set")?
        .join("node/node_modules");
    if modules.join("mongodb").exists() {
        Ok(modules)
    } else {
        Err(format!(
            "{} is not installed",
            modules.join("mongodb").display()
        ))
    }
}

fn node(dir: Option<&Path>, script_file: &str) -> Result<Command, String> {
    let mut command = Command::new("node");
    command
        .arg(script(script_file))
        .env("NODE_PATH", modules(dir)?)
        .kill_on_drop(true)
        .stdin(Stdio::null());
    Ok(command)
}

async fn version(dir: Option<&Path>) -> Result<String, String> {
    let output = Command::new("node")
        .args(["-p", "require('mongodb/package.json').version"])
        .env("NODE_PATH", modules(dir)?)
        .output()
        .await
        .map_err(|e| format!("cannot start the client runtime: {e}"))?;
    if !output.status.success() {
        return Err("the client runtime or driver does not start".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn admin(real: &Real, dir: Option<&Path>, collection: &str, operation: &str) -> String {
    let mut command = node(dir, "admin.js").expect("the driver is needed for the fixture");
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

async fn run(
    dir: Option<&Path>,
    local: SocketAddr,
    collection: &str,
    access: &str,
) -> (bool, Vec<String>) {
    let mut command = node(dir, "mongodb.js").unwrap();
    command
        .env("ZS_CLIENT_HOST", local.ip().to_string())
        .env("ZS_CLIENT_PORT", local.port().to_string())
        .env("ZS_CLIENT_DB", DATABASE)
        .env("ZS_CLIENT_TABLE", collection)
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
    real: &Real,
    name: &str,
    dir: Option<&Path>,
    access: SessionAccess,
) -> Result<(), String> {
    let (label, expected_rows, expected_touched) = match access {
        SessionAccess::ReadOnly => ("read_only", "1", "0"),
        SessionAccess::ReadWrite => ("read_write", "2", "1"),
    };
    let collection = format!("zs_ro_cl_{name}_{label}_{}", std::process::id());
    admin(real, dir, &collection, "seed").await;
    let (audit, refusals) = fake::audit_recorder();
    let tls = UpstreamTls::from_config(Some(&real.certs.join("ca.pem")), None).unwrap();
    let endpoint = UpstreamEndpoint::new(real.server.ip().to_string(), real.server.port()).unwrap();
    let listener = MongoListener::bind_endpoint(
        "127.0.0.1:0",
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
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    let (success, lines) = run(dir, local, &collection, label).await;
    for line in &lines {
        println!("  {name} {label}: {line}");
    }
    let rows = admin(real, dir, &collection, "count").await;
    let touched = admin(real, dir, &collection, "touched").await;
    admin(real, dir, &collection, "drop").await;
    let refused = refusals.lock().unwrap().len();
    let mut problems = Vec::new();
    if !success {
        problems.push("the client reported a failure".to_string());
    }
    if rows != expected_rows {
        problems.push(format!(
            "the collection holds {rows} documents, expected {expected_rows}"
        ));
    }
    if touched != expected_touched {
        problems.push(format!(
            "{touched} documents were updated, expected {expected_touched}"
        ));
    }
    match access {
        SessionAccess::ReadOnly if refused == 0 => {
            problems.push("the agent audited no refusal".to_string());
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
#[ignore = "needs a real MongoDB, node and the mongodb driver in tests/clients"]
async fn real_clients_read_through_a_read_only_session_and_are_refused_a_write() {
    let Some(real) = real() else { return };
    let dir = clients_dir();
    let require = std::env::var_os("ZS_REQUIRE_CLIENTS").is_some();
    let mut failures = Vec::new();
    for name in CLIENTS {
        let found = match version(dir.as_deref()).await {
            Ok(found) => found,
            Err(reason) => {
                println!("client {name}: not run: {reason}");
                if require {
                    failures.push(format!("{name}: not run: {reason}"));
                }
                continue;
            }
        };
        let read_only = session(&real, name, dir.as_deref(), SessionAccess::ReadOnly).await;
        let control = session(&real, name, dir.as_deref(), SessionAccess::ReadWrite).await;
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
