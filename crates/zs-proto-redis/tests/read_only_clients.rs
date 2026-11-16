#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::process::Command;
use zs_diag::DiagLog;
use zs_proto_redis::{Auth, RedisListener, UpstreamEndpoint};
use zs_protocol::SessionAccess;

const CLIENTS: [&str; 1] = ["ioredis"];
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);
const KEYS: [&str; 6] = ["k", "new", "ctr", "list", "pipe", "multi"];

struct Real {
    address: SocketAddr,
    password: String,
}

fn real() -> Option<Real> {
    let required = std::env::var_os("ZS_REQUIRE_REDIS").is_some();
    let found = std::env::var("ZS_TEST_REDIS_ADDR")
        .ok()
        .and_then(|value| value.parse().ok())
        .zip(std::env::var("ZS_TEST_REDIS_PASSWORD").ok())
        .map(|(address, password)| Real { address, password });
    assert!(
        found.is_some() || !required,
        "ZS_REQUIRE_REDIS is set: ZS_TEST_REDIS_ADDR (ip:port) and ZS_TEST_REDIS_PASSWORD must be set"
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
    if modules.join("ioredis").exists() {
        Ok(modules)
    } else {
        Err(format!(
            "{} is not installed",
            modules.join("ioredis").display()
        ))
    }
}

async fn version(dir: Option<&Path>) -> Result<String, String> {
    let output = Command::new("node")
        .args(["-p", "require('ioredis/package.json').version"])
        .env("NODE_PATH", modules(dir)?)
        .output()
        .await
        .map_err(|e| format!("cannot start the client runtime: {e}"))?;
    if !output.status.success() {
        return Err("the client runtime or driver does not start".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn admin(real: &Real, arguments: &[&str]) -> String {
    let output = Command::new("sh")
        .arg(script("admin.sh"))
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
        Arc::new(move || Ok(fake::granted_with(password.as_bytes(), access)));
    let endpoint =
        UpstreamEndpoint::new(real.address.ip().to_string(), real.address.port()).unwrap();
    let listener =
        RedisListener::bind_endpoint("127.0.0.1:0", endpoint, None, Auth::new(None), materialize)
            .await
            .unwrap()
            .with_diag(DiagLog::disabled(), "redis-real-read-only-clients")
            .with_caller_check(fake::admit_all())
            .with_refusal_audit(audit);
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    (local, refusals)
}

async fn run(
    dir: Option<&Path>,
    local: SocketAddr,
    prefix: &str,
    access: &str,
) -> (bool, Vec<String>) {
    let mut command = Command::new("node");
    command
        .arg(script("ioredis.js"))
        .env("NODE_PATH", modules(dir).unwrap())
        .env("ZS_CLIENT_HOST", local.ip().to_string())
        .env("ZS_CLIENT_PORT", local.port().to_string())
        .env("ZS_CLIENT_TABLE", prefix)
        .env("ZS_CLIENT_ACCESS", access)
        .kill_on_drop(true)
        .stdin(Stdio::null());
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
    let (label, expected_present, expected_value) = match access {
        SessionAccess::ReadOnly => ("read_only", "1", "v1"),
        SessionAccess::ReadWrite => ("read_write", "5", ""),
    };
    let prefix = format!("zs-ro-cl-{name}-{label}-{}", std::process::id());
    let keys = names(&prefix);
    let all: Vec<&str> = keys.iter().map(String::as_str).collect();
    let mut cleanup = vec!["DEL"];
    cleanup.extend(&all);
    admin(real, &cleanup).await;
    admin(real, &["SET", &keys[0], "v1", "EX", "300"]).await;
    let (local, refusals) = front(real, access).await;
    let (success, lines) = run(dir, local, &prefix, label).await;
    for line in &lines {
        println!("  {name} {label}: {line}");
    }
    let mut exists = vec!["EXISTS"];
    exists.extend(&all);
    let present = admin(real, &exists).await;
    let value = admin(real, &["GET", &keys[0]]).await;
    admin(real, &cleanup).await;
    let refused = refusals.lock().unwrap().len();
    let mut problems = Vec::new();
    if !success {
        problems.push("the client reported a failure".to_string());
    }
    if present != expected_present {
        problems.push(format!("{present} keys exist, expected {expected_present}"));
    }
    if value != expected_value {
        problems.push("the seeded key does not hold the expected value".to_string());
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
#[ignore = "needs a real Redis, redis-cli, node and the ioredis driver in tests/clients"]
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
