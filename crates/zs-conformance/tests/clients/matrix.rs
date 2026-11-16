#![allow(dead_code)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use zs_protocol::SessionAccess;

const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

pub fn clients_dir() -> Option<PathBuf> {
    std::env::var_os("ZS_CLIENTS_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub fn script(manifest_dir: &str, file: &str) -> PathBuf {
    Path::new(manifest_dir).join("tests/clients").join(file)
}

pub fn installed(dir: Option<&Path>, relative: &str) -> Result<PathBuf, String> {
    let dir = dir.ok_or("ZS_CLIENTS_DIR is not set")?;
    let path = dir.join(relative);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!("{} is not installed", path.display()))
    }
}

pub fn node_modules(dir: Option<&Path>, package: &str) -> Result<PathBuf, String> {
    installed(dir, &format!("node/node_modules/{package}"))
        .map(|found| found.parent().unwrap().to_path_buf())
}

pub fn node_command(
    dir: Option<&Path>,
    package: &str,
    manifest_dir: &str,
    file: &str,
) -> Result<Command, String> {
    let mut command = Command::new("node");
    command
        .arg(script(manifest_dir, file))
        .env("NODE_PATH", node_modules(dir, package)?);
    Ok(command)
}

pub async fn node_version(dir: Option<&Path>, package: &str) -> Result<String, String> {
    let output = Command::new("node")
        .args(["-p", &format!("require('{package}/package.json').version")])
        .env("NODE_PATH", node_modules(dir, package)?)
        .output()
        .await
        .map_err(|e| format!("cannot start the client runtime: {e}"))?;
    if !output.status.success() {
        return Err("the client runtime or driver does not start".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn label(access: SessionAccess) -> &'static str {
    match access {
        SessionAccess::ReadOnly => "read_only",
        SessionAccess::ReadWrite => "read_write",
    }
}

pub async fn run(name: &str, access: SessionAccess, mut command: Command) -> bool {
    command.kill_on_drop(true).stdin(Stdio::null());
    let (success, lines) = match tokio::time::timeout(CLIENT_TIMEOUT, command.output()).await {
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
    };
    for line in &lines {
        println!("  {name} {}: {line}", label(access));
    }
    success
}

pub fn judge(
    access: SessionAccess,
    success: bool,
    refused: usize,
    found: &[(&str, String, &str)],
) -> Result<(), String> {
    let mut problems = Vec::new();
    if !success {
        problems.push("the client reported a failure".to_string());
    }
    for (what, got, expected) in found {
        if got != expected {
            problems.push(format!("{what}: found {got}, expected {expected}"));
        }
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

pub async fn matrix<V, VF, S, SF>(required: bool, names: &[&str], version: V, session: S)
where
    V: Fn(String) -> VF,
    VF: Future<Output = Result<String, String>>,
    S: Fn(String, SessionAccess) -> SF,
    SF: Future<Output = Result<(), String>>,
{
    let verdict = |outcome: &Result<(), String>| match outcome {
        Ok(()) => "PASS".to_string(),
        Err(why) => format!("FAIL ({why})"),
    };
    let mut failures = Vec::new();
    for name in names {
        let found = match version(name.to_string()).await {
            Ok(found) => found,
            Err(reason) => {
                println!("client {name}: not run: {reason}");
                if required {
                    failures.push(format!("{name}: not run: {reason}"));
                }
                continue;
            }
        };
        let read_only = session(name.to_string(), SessionAccess::ReadOnly).await;
        let control = session(name.to_string(), SessionAccess::ReadWrite).await;
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
