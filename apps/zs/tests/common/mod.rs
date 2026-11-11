#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

use std::io::{Read, Write};

use base64::Engine as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "api.stripe.com";

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod native_store;

pub mod test_ca;

#[cfg(not(target_os = "windows"))]
const OS_VARIABLES: &[&str] = &["PATH"];
#[cfg(target_os = "windows")]
const OS_VARIABLES: &[&str] = &["PATH", "SystemRoot", "SystemDrive", "windir", "TEMP", "TMP"];

pub fn clean_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in OS_VARIABLES {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

static PROXY_AUTHORIZATIONS: std::sync::Mutex<Vec<(String, String)>> =
    std::sync::Mutex::new(Vec::new());

pub fn register_proxy_authorization(proxy: &str, authorization: &str) {
    let mut all = PROXY_AUTHORIZATIONS.lock().unwrap();
    all.push((proxy.to_string(), authorization.to_string()));
}

static ENDPOINT_PREFIXES: std::sync::Mutex<Vec<(String, String)>> =
    std::sync::Mutex::new(Vec::new());

pub fn register_endpoint_prefix(addr: &str, prefix: &str) {
    let mut all = ENDPOINT_PREFIXES.lock().unwrap();
    all.push((addr.to_string(), prefix.to_string()));
}

pub fn endpoint_prefix(addr: &str) -> String {
    let all = ENDPOINT_PREFIXES.lock().unwrap();
    all.iter()
        .rev()
        .find(|(known, _)| known == addr)
        .map(|(_, prefix)| prefix.clone())
        .unwrap_or_default()
}

pub fn authorized_for_proxy(proxy: &str, request: &[u8]) -> Vec<u8> {
    let authorization = registered_proxy_authorization(proxy);
    with_proxy_authorization(request, &authorization)
}

fn registered_proxy_authorization(proxy: &str) -> String {
    let all = PROXY_AUTHORIZATIONS.lock().unwrap();
    all.iter()
        .rev()
        .find(|(addr, _)| addr == proxy)
        .map(|(_, authorization)| authorization.clone())
        .unwrap_or_default()
}

fn with_proxy_authorization(request: &[u8], authorization: &str) -> Vec<u8> {
    let Some(line_end) = request.windows(2).position(|pair| pair == b"\r\n") else {
        return request.to_vec();
    };
    if authorization.is_empty() {
        return request.to_vec();
    }
    let mut out = Vec::with_capacity(request.len() + authorization.len() + 32);
    out.extend_from_slice(&request[..line_end + 2]);
    out.extend_from_slice(format!("Proxy-Authorization: {authorization}\r\n").as_bytes());
    out.extend_from_slice(&request[line_end + 2..]);
    out
}

pub fn random_hex() -> String {
    use rand::RngCore;
    use rand::rngs::OsRng;

    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub struct TestHome {
    ca_dir: PathBuf,
    dir: tempfile::TempDir,
}

impl TestHome {
    pub fn new(ca_dir: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        Self {
            ca_dir: dir.path().join(ca_dir),
            dir,
        }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl Drop for TestHome {
    fn drop(&mut self) {
        let removed = match storage_account(&self.ca_dir) {
            Ok(Some(account)) => remove_record(&account),
            Ok(None) => true,
            Err(()) => false,
        };
        if !removed && !std::thread::panicking() {
            panic!("native CA record cleanup failed");
        }
    }
}

#[cfg(target_os = "macos")]
fn remove_record(account: &str) -> bool {
    native_ca::remove_record(account)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn remove_record(account: &str) -> bool {
    native_store::Store::inherited().remove(account)
}

fn storage_account(ca_dir: &Path) -> Result<Option<String>, ()> {
    const ID_FILE: &str = ".ca-storage-id";
    const ACCOUNT_LEN: usize = 32;
    match std::fs::read(ca_dir.join(ID_FILE)) {
        Ok(bytes)
            if bytes.len() == ACCOUNT_LEN
                && bytes
                    .iter()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) =>
        {
            String::from_utf8(bytes).map(Some).map_err(|_| ())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        _ => Err(()),
    }
}

// Delete only the exact service/account item; never enumerate or prefix-match the user's keychain.
#[cfg(target_os = "macos")]
mod native_ca {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const SECURITY: &str = "/usr/bin/security";
    const SERVICE: &str = "zerosecret.ca.v1";
    const ITEM_NOT_FOUND: i32 = 44;
    const TIMEOUT: Duration = Duration::from_secs(10);
    const ATTEMPTS: usize = 4;

    fn delete(account: &str) -> Option<i32> {
        let mut child = Command::new(SECURITY)
            .args(["delete-generic-password", "-a", account, "-s", SERVICE])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let deadline = Instant::now() + TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return status.code(),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
    }

    pub fn remove_record(account: &str) -> bool {
        for _ in 0..ATTEMPTS {
            match delete(account) {
                Some(0) => {}
                Some(ITEM_NOT_FOUND) => return true,
                _ => return false,
            }
        }
        false
    }
}

pub fn default_connection(host: &str, protocol: &str) -> zs_policy::ResolvedConnection {
    zs_policy::Connection::default()
        .resolve(host, protocol)
        .expect("default_connection needs a protocol the agent intercepts")
}

pub fn uninterceptable_connection(host: &str) -> zs_policy::ResolvedConnection {
    zs_policy::ResolvedConnection {
        upstream_host: host.to_string(),
        upstream_port: 0,
        upstream_tls: zs_policy::UpstreamTlsMode::Default,
        local_endpoint: false,
    }
}

pub fn default_subject() -> String {
    std::env::var("USER").unwrap_or_else(|_| "local".into())
}

#[allow(dead_code)]
pub struct FakeUpstream {
    pub addr: std::net::SocketAddr,
    pub requests: Arc<AtomicUsize>,
    pub connections: Arc<AtomicUsize>,
    pub saw_authorization: Arc<AtomicBool>,
    pub last_auth: Arc<std::sync::Mutex<String>>,
    pub last_head: Arc<std::sync::Mutex<String>>,
    pub last_body: Arc<std::sync::Mutex<Vec<u8>>>,
}

pub fn spawn_fake_upstream() -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(AtomicUsize::new(0));
    let saw_authorization = Arc::new(AtomicBool::new(false));
    let last_auth = Arc::new(std::sync::Mutex::new(String::new()));
    let last_head = Arc::new(std::sync::Mutex::new(String::new()));
    let last_body = Arc::new(std::sync::Mutex::new(Vec::new()));
    let requests_t = requests.clone();
    let connections_t = connections.clone();
    let saw_t = saw_authorization.clone();
    let auth_t = last_auth.clone();
    let head_t = last_head.clone();
    let body_t = last_body.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            connections_t.fetch_add(1, Ordering::SeqCst);
            let requests_t = requests_t.clone();
            let saw_t = saw_t.clone();
            let auth_t = auth_t.clone();
            let head_t = head_t.clone();
            let body_t = body_t.clone();
            std::thread::spawn(move || {
                loop {
                    let mut buf = Vec::new();
                    let mut byte = [0u8; 1];
                    loop {
                        if stream.read(&mut byte).unwrap_or(0) == 0 {
                            return;
                        }
                        buf.push(byte[0]);
                        if buf.ends_with(b"\r\n\r\n") || buf.len() > 65536 {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let path = head
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("")
                        .to_string();
                    let length: usize = head
                        .lines()
                        .find_map(|l| {
                            l.split_once(':')
                                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                                .map(|(_, v)| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    let mut body = vec![0u8; length];
                    if stream.read_exact(&mut body).is_err() {
                        return;
                    }
                    *head_t.lock().unwrap() = head.clone();
                    *body_t.lock().unwrap() = body;
                    requests_t.fetch_add(1, Ordering::SeqCst);
                    if let Some(auth) = head
                        .lines()
                        .skip(1)
                        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    {
                        saw_t.store(true, Ordering::SeqCst);
                        *auth_t.lock().unwrap() = auth.to_string();
                    }
                    let body = br#"{"object":"list","data":[{"id":"cus_zs_probe_1","object":"customer"}],"has_more":false}"#;
                    if path == "/zs-contract/case" {
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nX-Upstream-MiXeD: 1\r\nContent-Length: 2\r\n\r\nok",
                        );
                    } else if path == "/zs-contract/big" {
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
                        );
                        let chunk = vec![b'z'; 64 * 1024];
                        for _ in 0..1024 {
                            if stream
                                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                                .is_err()
                            {
                                return;
                            }
                            if stream.write_all(&chunk).is_err() {
                                return;
                            }
                            if stream.write_all(b"\r\n").is_err() {
                                return;
                            }
                        }
                        let _ = stream.write_all(b"0\r\n\r\n");
                    } else {
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n");
                        let _ = stream.write_all(
                            format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes(),
                        );
                        let _ = stream.write_all(body);
                    }
                    let _ = stream.flush();
                }
            });
        }
    });
    FakeUpstream {
        addr,
        requests,
        connections,
        saw_authorization,
        last_auth,
        last_head,
        last_body,
    }
}

// How a fake upstream answers an injected request, for the response echo guard.
#[derive(Clone, Copy)]
pub enum EchoMode {
    // 200 with a body that names nothing from the request.
    Nothing,
    // 200 that copies the request's Authorization value into the named response header.
    AuthorizationInHeader(&'static str),
    // 302 whose Location keeps the request's query string.
    QueryInLocation,
    // 200 `message/http` whose body is the request head, as a TRACE server answers.
    Trace,
    // 200 whose body names the request's Authorization value; chunked splits it across chunks.
    AuthorizationInBody { chunked: bool },
    // 200 with `Content-Encoding: gzip`.
    GzipBody,
}

pub fn spawn_echo_upstream(mode: EchoMode) -> FakeUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = FakeUpstream {
        addr: listener.local_addr().unwrap(),
        requests: Arc::new(AtomicUsize::new(0)),
        connections: Arc::new(AtomicUsize::new(0)),
        saw_authorization: Arc::new(AtomicBool::new(false)),
        last_auth: Arc::new(std::sync::Mutex::new(String::new())),
        last_head: Arc::new(std::sync::Mutex::new(String::new())),
        last_body: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let requests = upstream.requests.clone();
    let connections = upstream.connections.clone();
    let last_head = upstream.last_head.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            connections.fetch_add(1, Ordering::SeqCst);
            let requests = requests.clone();
            let last_head = last_head.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                while !buf.ends_with(b"\r\n\r\n") && buf.len() <= 65536 {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    buf.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                *last_head.lock().unwrap() = head.clone();
                requests.fetch_add(1, Ordering::SeqCst);
                let target = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("");
                let authorization = head
                    .lines()
                    .skip(1)
                    .find_map(|l| {
                        l.split_once(':')
                            .filter(|(k, _)| k.trim().eq_ignore_ascii_case("authorization"))
                            .map(|(_, v)| v.trim().to_string())
                    })
                    .unwrap_or_default();
                let (status, extra, content_type, body) = match mode {
                    EchoMode::Nothing => (
                        "200 OK",
                        String::new(),
                        "application/json",
                        br#"{"object":"list","data":[]}"#.to_vec(),
                    ),
                    EchoMode::AuthorizationInHeader(name) => (
                        "200 OK",
                        format!("{name}: {authorization}\r\n"),
                        "application/json",
                        br#"{"object":"list","data":[]}"#.to_vec(),
                    ),
                    EchoMode::QueryInLocation => {
                        let query = target.split_once('?').map_or("", |(_, q)| q);
                        (
                            "302 Found",
                            format!("Location: /next?{query}\r\n"),
                            "text/plain",
                            b"moved".to_vec(),
                        )
                    }
                    EchoMode::Trace => ("200 OK", String::new(), "message/http", buf.clone()),
                    EchoMode::AuthorizationInBody { chunked: false } => (
                        "200 OK",
                        String::new(),
                        "application/json",
                        format!(r#"{{"seen":"{authorization}"}}"#).into_bytes(),
                    ),
                    EchoMode::AuthorizationInBody { chunked: true } => {
                        let body = format!(r#"{{"seen":"{authorization}"}}"#).into_bytes();
                        let at = body.len() / 2;
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                        );
                        for part in [&body[..at], &body[at..]] {
                            let _ = stream.write_all(format!("{:x}\r\n", part.len()).as_bytes());
                            let _ = stream.write_all(part);
                            let _ = stream.write_all(b"\r\n");
                            let _ = stream.flush();
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                        let _ = stream.write_all(b"0\r\n\r\n");
                        let _ = stream.flush();
                        return;
                    }
                    EchoMode::GzipBody => (
                        "200 OK",
                        "Content-Encoding: gzip\r\n".to_string(),
                        "application/json",
                        b"\x1f\x8b\x08\x00\x00\x00\x00\x00".to_vec(),
                    ),
                };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status}\r\n{extra}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            });
        }
    });
    upstream
}

pub fn write_test_setup(
    dir: &std::path::Path,
    upstream_port: u16,
    include_grant: bool,
    include_credential: bool,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    write_test_setup_with(
        dir,
        upstream_port,
        include_grant,
        include_credential,
        &["GET"],
        true,
        None,
    )
}

pub fn write_test_setup_with(
    dir: &std::path::Path,
    upstream_port: u16,
    include_grant: bool,
    include_credential: bool,
    operations: &[&str],
    upstream_plaintext: bool,
    paths: Option<&[&str]>,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    write_test_setup_granting(
        dir,
        upstream_port,
        include_grant,
        include_credential,
        operations,
        upstream_plaintext,
        paths,
        "https",
    )
}

pub fn loopback_connection(port: u16, plaintext: bool) -> zs_policy::ResolvedConnection {
    zs_policy::ResolvedConnection {
        upstream_host: "127.0.0.1".into(),
        upstream_port: port,
        upstream_tls: if plaintext {
            zs_policy::UpstreamTlsMode::Plaintext
        } else {
            zs_policy::UpstreamTlsMode::Default
        },
        local_endpoint: false,
    }
}

pub fn write_test_setup_signing(
    dir: &std::path::Path,
    upstream_port: u16,
    operations: &[&str],
    connection: zs_policy::ResolvedConnection,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    write_local_setup(
        dir,
        upstream_port,
        true,
        true,
        operations,
        true,
        None,
        "https",
        connection,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_test_setup_granting(
    dir: &std::path::Path,
    upstream_port: u16,
    include_grant: bool,
    include_credential: bool,
    operations: &[&str],
    upstream_plaintext: bool,
    paths: Option<&[&str]>,
    grant_protocol: &str,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    write_local_setup(
        dir,
        upstream_port,
        include_grant,
        include_credential,
        operations,
        upstream_plaintext,
        paths,
        grant_protocol,
        loopback_connection(upstream_port, upstream_plaintext),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_local_setup(
    dir: &std::path::Path,
    upstream_port: u16,
    include_grant: bool,
    include_credential: bool,
    operations: &[&str],
    upstream_plaintext: bool,
    paths: Option<&[&str]>,
    grant_protocol: &str,
    connection: zs_policy::ResolvedConnection,
) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let policy_path = dir.join("zs-policy.json");
    let creds_dir = dir.join(".zs-credentials");
    let audit_path = dir.join(".zs-audit").join("audit.jsonl");
    let ca_dir = dir.join(".zs-ca");
    std::fs::create_dir_all(&creds_dir).unwrap();
    std::fs::create_dir_all(dir.join(".zs-audit")).unwrap();
    let signing = zs_grant::ControlSigningKey::generate("test-k1");
    let verifying_hex: String = signing
        .verifying_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let grants = if include_grant {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let signed = signing
            .sign(zs_grant::Grant {
                subject: default_subject(),
                workload: "default".into(),
                resource: "stripe-production".into(),
                host: HOST.to_string(),
                protocol: grant_protocol.into(),
                source: zs_policy::CredentialSource::file("stripe-prod"),
                operations: operations.iter().map(|o| o.to_string()).collect(),
                environment: "development".into(),
                expires_at_ms: now_ms + 3_600_000,
                grant_id: "g-test".into(),
                materialization: zs_policy::Materialization::Retrieve,
                upstream_host: connection.upstream_host,
                upstream_port: connection.upstream_port,
                upstream_tls: connection.upstream_tls,
                local_endpoint: connection.local_endpoint,
                version: zs_grant::GRANT_VERSION,
            })
            .unwrap();
        serde_json::to_string(&signed).unwrap()
    } else {
        String::new()
    };
    let grants_json = if grants.is_empty() {
        String::new()
    } else {
        grants
    };
    let operations_json = serde_json::to_string(operations).unwrap();
    let paths_json = paths
        .map(|p| format!(r#", "paths": {}"#, serde_json::to_string(p).unwrap()))
        .unwrap_or_default();
    let policy = format!(
        r#"{{"bindings": [{{"resource": "stripe-production", "host": "{HOST}", "upstream_host": "127.0.0.1", "upstream_port": {upstream_port}, "upstream_plaintext": {upstream_plaintext}, "operations": {operations_json}{paths_json}}}], "signing_keys": [{{"key_id": "test-k1", "verifying_key_hex": "{verifying_hex}"}}], "grants": [{grants_json}]}}"#
    );
    std::fs::write(&policy_path, policy).unwrap();
    if include_credential {
        std::fs::write(
            creds_dir.join("stripe-prod"),
            "sk_test_zsv_synthetic_value_9f27c4d1\n",
        )
        .unwrap();
    }
    (
        policy_path,
        creds_dir,
        audit_path,
        ca_dir,
        dir.join(".zs-ca"),
    )
}

#[allow(dead_code)]
pub struct AgentProcess {
    pub child: std::process::Child,
    pub stdout: std::process::ChildStdout,
    pub proxy_addr: String,
    pub startup_stdout: String,
    pub proxy_authorization: String,
    pub endpoint_urls: Vec<(String, String)>,
    pub ca_path: PathBuf,
    pub stderr: std::process::ChildStderr,
    pub postgres_port: Option<u16>,
    pub mysql_port: Option<u16>,
    pub mongo_port: Option<u16>,
    pub redis_port: Option<u16>,
}

#[cfg(unix)]
const CHILD_ENV_SCRIPT: &str =
    r#"env | grep -E "^(HTTPS_PROXY|ZS_[A-Z0-9_]+_URL)=" > "$ZS_TEST_ENV_FILE"; exec "$@""#;

#[derive(Clone, Copy)]
pub enum ChildAction {
    Sleep(u64),
    PrintEnv,
}

impl ChildAction {
    fn encoded(self) -> String {
        match self {
            ChildAction::Sleep(seconds) => format!("sleep:{seconds}"),
            ChildAction::PrintEnv => "env".to_string(),
        }
    }
}

/// The child that `zs run` starts in place of `sleep`, `/usr/bin/env` or `sh -c`, so the same
/// test runs on Windows: this test executable filtered to `zs_test_child`, with the action in
/// `ZS_TEST_CHILD_ACTION`. The action reaches the child only through the agent's environment,
/// so a spawn helper takes both `args` and `env()`.
pub struct TestChild {
    pub args: Vec<String>,
    action: String,
}

impl TestChild {
    pub fn env(&self) -> [(&str, &str); 1] {
        [("ZS_TEST_CHILD_ACTION", self.action.as_str())]
    }
}

pub fn child(action: ChildAction) -> TestChild {
    let exe = std::env::current_exe().expect("the test executable has a path");
    let exe = exe.to_str().expect("the test executable path is UTF-8");
    TestChild {
        args: vec![
            exe.to_string(),
            "--exact".to_string(),
            "common::zs_test_child".to_string(),
            "--ignored".to_string(),
            "--nocapture".to_string(),
        ],
        action: action.encoded(),
    }
}

/// The test child's entry point. Every binary that includes `common` lists it as an ignored
/// test, so a CI step that runs `-- --ignored` against a pinned count passes
/// `--skip common::zs_test_child`. Without `ZS_TEST_CHILD_ACTION` it returns at once.
#[test]
#[ignore]
fn zs_test_child() {
    let Ok(action) = std::env::var("ZS_TEST_CHILD_ACTION") else {
        return;
    };
    #[cfg(windows)]
    write_child_env_file();
    if action == "env" {
        for (name, value) in std::env::vars_os() {
            println!("{}={}", name.to_string_lossy(), value.to_string_lossy());
        }
        return;
    }
    let seconds: u64 = action
        .strip_prefix("sleep:")
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or_else(|| panic!("unknown ZS_TEST_CHILD_ACTION: {action}"));
    std::thread::sleep(Duration::from_secs(seconds));
}

#[cfg(windows)]
fn write_child_env_file() {
    let Some(path) = std::env::var_os("ZS_TEST_ENV_FILE") else {
        return;
    };
    let mut text = String::new();
    if let Some(value) = std::env::var_os("HTTPS_PROXY") {
        text.push_str(&format!("HTTPS_PROXY={}\n", value.to_string_lossy()));
    }
    let mut endpoints: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            (name.starts_with("ZS_") && name.ends_with("_URL"))
                .then(|| (name, value.to_string_lossy().into_owned()))
        })
        .collect();
    endpoints.sort();
    for (name, value) in endpoints {
        text.push_str(&format!("{name}={value}\n"));
    }
    let mut pending = PathBuf::from(&path);
    pending.as_mut_os_string().push(".pending");
    if std::fs::write(&pending, text).is_ok() {
        let _ = std::fs::rename(&pending, &path);
    }
}

pub fn parse_child_env(text: &str) -> (String, Vec<(String, String)>) {
    let mut authorization = String::new();
    let mut endpoints = Vec::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("HTTPS_PROXY=") {
            if let Some((userinfo, _)) = value
                .strip_prefix("http://")
                .and_then(|rest| rest.split_once('@'))
            {
                authorization = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(userinfo)
                );
            }
        } else if let Some((name, url)) = line
            .strip_prefix("ZS_")
            .and_then(|rest| rest.split_once('='))
            && name.ends_with("_URL")
        {
            endpoints.push((format!("ZS_{name}"), url.to_string()));
        }
    }
    (authorization, endpoints)
}

pub fn spawn_agent<C: AsRef<std::ffi::OsStr>>(
    bin: &std::path::Path,
    policy: &std::path::Path,
    creds: &std::path::Path,
    audit: &std::path::Path,
    ca_dir: &std::path::Path,
    child: &[C],
    audit_dir_exists: bool,
) -> Result<AgentProcess, String> {
    spawn_agent_with_env(
        bin,
        policy,
        creds,
        audit,
        ca_dir,
        child,
        audit_dir_exists,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_agent_with_env<C: AsRef<std::ffi::OsStr>>(
    bin: &std::path::Path,
    policy: &std::path::Path,
    creds: &std::path::Path,
    audit: &std::path::Path,
    ca_dir: &std::path::Path,
    child: &[C],
    audit_dir_exists: bool,
    env: &[(&str, &str)],
) -> Result<AgentProcess, String> {
    if !audit_dir_exists {
        std::fs::remove_dir_all(audit.parent().unwrap()).ok();
    }
    let mut arguments: Vec<std::ffi::OsString> = vec![
        "run".into(),
        "--policy".into(),
        policy.as_os_str().to_owned(),
        "--credentials-dir".into(),
        creds.as_os_str().to_owned(),
        "--audit".into(),
        audit.as_os_str().to_owned(),
        "--ca-dir".into(),
        ca_dir.as_os_str().to_owned(),
        "--as".into(),
        "default".into(),
        "--".into(),
    ];
    let env_file = std::env::temp_dir().join(format!("zs-child-env-{}.env", random_hex()));
    #[cfg(unix)]
    {
        arguments.push("/bin/sh".into());
        arguments.push("-c".into());
        arguments.push(CHILD_ENV_SCRIPT.into());
        arguments.push("sh".into());
    }
    arguments.extend(child.iter().map(|arg| arg.as_ref().to_owned()));
    let mut cmd = Command::new(bin);
    cmd.args(&arguments)
        .env("ZS_HOME", policy.parent().unwrap())
        .envs(env.iter().copied())
        .env("ZS_TEST_ENV_FILE", &env_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let mut buf = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() > deadline {
            return Err("agent did not report proxy address in time".into());
        }
        let mut out = [0u8; 1024];
        let n = std::io::Read::read(&mut stdout, &mut out).unwrap_or(0);
        if n == 0 {
            let mut err = Vec::new();
            std::io::Read::read_to_end(&mut stderr, &mut err).map_err(|e| e.to_string())?;
            let status = child.wait().map_err(|e| e.to_string())?;
            return Err(format!(
                "agent exited early ({status}): {}",
                String::from_utf8_lossy(&err)
            ));
        }
        buf.extend_from_slice(&out[..n]);
        let text = String::from_utf8_lossy(&buf).into_owned();
        let addr = text.lines().find_map(|l| l.strip_prefix("zs: proxy "));
        let ca = text.lines().find_map(|l| l.strip_prefix("zs: ca-cert "));
        if let (Some(addr), Some(ca)) = (addr, ca) {
            let port_of = |kind: &str| {
                text.lines()
                    .filter(|l| l.starts_with(kind))
                    .find_map(|l| l.rsplit_once("-> 127.0.0.1:"))
                    .and_then(|(_, port)| port.trim().parse().ok())
            };
            let (proxy_authorization, endpoint_urls) = {
                let path = &env_file;
                let deadline = Instant::now() + Duration::from_secs(10);
                let text = loop {
                    match std::fs::read_to_string(path) {
                        Ok(text) if text.contains("HTTPS_PROXY=") && text.ends_with('\n') => {
                            break Some(text);
                        }
                        _ if Instant::now() >= deadline => break None,
                        _ => std::thread::sleep(Duration::from_millis(20)),
                    }
                };
                std::fs::remove_file(path).ok();
                let parsed = text.as_deref().map(parse_child_env);
                match parsed {
                    Some((authorization, endpoints)) if !authorization.is_empty() => {
                        (authorization, endpoints)
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(
                            "the child never reported an HTTPS_PROXY with the run token".into()
                        );
                    }
                }
            };
            register_proxy_authorization(addr.trim(), &proxy_authorization);
            return Ok(AgentProcess {
                child,
                stdout,
                proxy_addr: addr.trim().to_string(),
                startup_stdout: text.clone(),
                proxy_authorization,
                endpoint_urls,
                ca_path: PathBuf::from(ca.trim()),
                stderr,
                postgres_port: port_of("zs: postgres "),
                mysql_port: port_of("zs: mysql "),
                mongo_port: port_of("zs: mongo "),
                redis_port: port_of("zs: redis "),
            });
        }
    }
}

pub async fn open_tunnel(
    proxy: &str,
    ca_pem: &str,
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    let authorization = registered_proxy_authorization(proxy);
    open_tunnel_with(proxy, &authorization, ca_pem, host, port).await
}

pub async fn open_tunnel_with(
    proxy: &str,
    proxy_authorization: &str,
    ca_pem: &str,
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let (tcp, status) = loop {
        let attempt = async {
            let mut tcp = tokio::net::TcpStream::connect(proxy)
                .await
                .map_err(|e| e.to_string())?;
            tcp.write_all(
                format!(
                    "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: {proxy_authorization}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .map_err(|e| e.to_string())?;
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                tcp.read_exact(&mut byte).await.map_err(|e| e.to_string())?;
                head.push(byte[0]);
                if head.len() > 8192 {
                    return Err("proxy head too large".to_string());
                }
            }
            Ok::<_, String>((tcp, String::from_utf8_lossy(&head).into_owned()))
        };
        match attempt.await {
            Ok(pair) => break pair,
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    };
    if !status.starts_with("HTTP/1.1 200") {
        return Err(status);
    }
    let der = rustls::pki_types::CertificateDer::from(pem_to_der(ca_pem).ok_or("bad ca pem")?);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).map_err(|e| e.to_string())?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())
}

pub fn header_lines(head: &str, name: &str) -> Vec<String> {
    let prefix = format!("{}:", name.to_ascii_lowercase());
    head.lines()
        .filter(|l| l.to_ascii_lowercase().starts_with(&prefix))
        .map(str::to_string)
        .collect()
}

pub fn content_length(head: &str) -> usize {
    header_lines(head, "content-length")
        .first()
        .and_then(|l| l.split_once(':'))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0)
}

pub async fn exchange<S>(stream: &mut S, request: &[u8]) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if stream.write_all(request).await.is_err() {
        return String::new();
    }
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte)).await {
            Ok(Ok(1)) => head.push(byte[0]),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let length = content_length(&text);
    let mut body = vec![0u8; length];
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut body)).await;
    format!("{text}{}", String::from_utf8_lossy(&body))
}

pub async fn tunneled_exchange(
    proxy: &str,
    ca_pem: &str,
    host: &str,
    port: u16,
    request: &[u8],
) -> String {
    match open_tunnel(proxy, ca_pem, host, port).await {
        Ok(mut tls) => exchange(&mut tls, request).await,
        Err(status) => status,
    }
}

pub async fn raw_exchange(proxy: &str, request: &[u8]) -> String {
    let authorization = registered_proxy_authorization(proxy);
    raw_exchange_with(proxy, &with_proxy_authorization(request, &authorization)).await
}

pub async fn raw_exchange_without_token(proxy: &str, request: &[u8]) -> String {
    raw_exchange_with(proxy, request).await
}

async fn raw_exchange_with(proxy: &str, request: &[u8]) -> String {
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).into_owned()
}

pub async fn proxied_request(
    proxy: &str,
    ca_pem: &str,
    host: &str,
    port: u16,
    path: &str,
) -> Result<(String, String), String> {
    let mut tls = match open_tunnel(proxy, ca_pem, host, port).await {
        Ok(tls) => tls,
        Err(refusal) if refusal.starts_with("HTTP/") => {
            let status = refusal.lines().next().unwrap_or("").to_string();
            return Ok((status, String::new()));
        }
        Err(e) => return Err(e),
    };
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let response = exchange(&mut tls, request.as_bytes()).await;
    let status = response.lines().next().unwrap_or("").to_string();
    if status.is_empty() {
        return Err("no response".into());
    }
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

#[allow(dead_code)]
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64_decode(&body)
}

#[allow(dead_code)]
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = alphabet.iter().position(|a| *a == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

const FIRST_TEST_PORT: u16 = 20_000;
const TEST_PORT_SPAN: usize = 12_000;

#[allow(dead_code)]
pub fn free_port() -> u16 {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let base = std::process::id() as usize * 389;
    for _ in 0..TEST_PORT_SPAN {
        let offset = (base + NEXT.fetch_add(1, Ordering::Relaxed)) % TEST_PORT_SPAN;
        let port = FIRST_TEST_PORT + offset as u16;
        // Binding is the portable test of "free": it also refuses a port the operating system
        // has reserved. `connect_timeout` does not — it waits the full timeout wherever the
        // platform reports a dropped connection rather than a refusal, which Windows does, so
        // the scan cost 200 ms per candidate and the Windows job timed out before it found one.
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free loopback port below the ephemeral range");
}

#[allow(dead_code)]
pub struct TempAgent {
    pub dir: PathBuf,
    pub agent: Option<AgentProcess>,
    pub upstream: FakeUpstream,
    pub _temp: TestHome,
}

pub fn setup_agent(include_grant: bool, include_credential: bool) -> TempAgent {
    setup_agent_with(include_grant, include_credential, &["GET"], None)
}

#[allow(dead_code)]
pub fn setup_agent_with(
    include_grant: bool,
    include_credential: bool,
    operations: &[&str],
    paths: Option<&[&str]>,
) -> TempAgent {
    let temp = TestHome::new(".zs-ca");
    let dir = PathBuf::from(temp.path());
    let upstream = spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) = write_test_setup_with(
        &dir,
        upstream.addr.port(),
        include_grant,
        include_credential,
        operations,
        true,
        paths,
    );
    let child = child(ChildAction::Sleep(120));
    let agent = spawn_agent_with_env(
        bin_path().as_path(),
        policy.as_path(),
        creds.as_path(),
        audit.as_path(),
        ca_dir.as_path(),
        &child.args,
        true,
        &child.env(),
    );
    TempAgent {
        dir,
        agent: Some(agent.expect("agent spawn")),
        upstream,
        _temp: temp,
    }
}

/// The `zs` binary. Inside the `zs` package cargo names it; a test crate in another package
/// (which includes this module by `#[path]`) finds it next to its own `deps/` directory, so
/// the binary must be built first (`cargo build -p zs`; a workspace run builds it).
pub fn bin_path() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_zs") {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().expect("the test executable has a path");
    let path = exe
        .parent()
        .and_then(Path::parent)
        .expect("the test executable lives in <target>/<profile>/deps")
        .join(format!("zs{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.is_file(),
        "{} does not exist; build the agent first: cargo build -p zs",
        path.display()
    );
    path
}

/// Runs `zs <args>` in `home` (also its `ZS_HOME`) as user `localuser`, and returns the exit
/// code with stdout and stderr joined.
pub fn run_zs(home: &Path, args: &[String], env: &[(&str, &str)]) -> (i32, String) {
    let mut command = Command::new(bin_path());
    command
        .args(args)
        .env("ZS_HOME", home)
        .env("USER", "localuser")
        .current_dir(home);
    for (k, v) in env {
        command.env(k, v);
    }
    let out = command.output().expect("zs must run");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[allow(dead_code)]
pub async fn direct_rtt_baseline(addr: std::net::SocketAddr, requests: usize) -> Vec<Duration> {
    let mut samples = Vec::new();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = b"GET /v1/customers HTTP/1.1\r\nHost: baseline\r\n\r\n";
    for _ in 0..requests {
        let start = Instant::now();
        stream.write_all(request).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let length: usize = String::from_utf8_lossy(&head)
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse().ok())
            })
            .flatten()
            .unwrap_or(0);
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await.unwrap();
        samples.push(start.elapsed());
    }
    samples
}

pub fn kill_agent(agent: &mut TempAgent) {
    if let Some(mut a) = agent.agent.take() {
        let _ = a.child.kill();
        let _ = a.child.wait();
    }
}

pub fn write_postgres_setup(
    dir: &std::path::Path,
    upstream_port: u16,
    include_grant: bool,
) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    write_postgres_setup_signing(
        dir,
        upstream_port,
        include_grant,
        loopback_connection(upstream_port, false),
    )
}

pub fn write_postgres_setup_signing(
    dir: &std::path::Path,
    upstream_port: u16,
    include_grant: bool,
    connection: zs_policy::ResolvedConnection,
) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let policy_path = dir.join("zs-policy.json");
    let creds_dir = dir.join(".zs-credentials");
    let audit_path = dir.join(".zs-audit").join("audit.jsonl");
    let ca_dir = dir.join(".zs-ca");
    std::fs::create_dir_all(&creds_dir).unwrap();
    std::fs::create_dir_all(dir.join(".zs-audit")).unwrap();
    std::fs::write(creds_dir.join("pg-prod"), "upstream_secret_pencil\n").unwrap();

    let signing = zs_grant::ControlSigningKey::generate("test-k1");
    let verifying_hex: String = signing
        .verifying_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let grants = if include_grant {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        serde_json::to_string(
            &signing
                .sign(zs_grant::Grant {
                    subject: default_subject(),
                    workload: "default".into(),
                    resource: "appdb".into(),
                    host: "db.internal".into(),
                    protocol: "postgres".into(),
                    source: zs_policy::CredentialSource::file("pg-prod"),
                    operations: vec!["connect".into()],
                    environment: "development".into(),
                    expires_at_ms: now_ms + 3_600_000,
                    grant_id: "g-pg".into(),
                    materialization: zs_policy::Materialization::Retrieve,
                    upstream_host: connection.upstream_host,
                    upstream_port: connection.upstream_port,
                    upstream_tls: connection.upstream_tls,
                    local_endpoint: connection.local_endpoint,
                    version: zs_grant::GRANT_VERSION,
                })
                .unwrap(),
        )
        .unwrap()
    } else {
        String::new()
    };
    let policy = format!(
        r#"{{"bindings": [{{"resource": "appdb", "host": "db.internal", "protocol": "postgres", "upstream_host": "127.0.0.1", "upstream_port": {upstream_port}}}], "signing_keys": [{{"key_id": "test-k1", "verifying_key_hex": "{verifying_hex}"}}], "grants": [{grants}]}}"#
    );
    std::fs::write(&policy_path, policy).unwrap();
    (policy_path, creds_dir, audit_path, ca_dir)
}

pub struct CapturedAgent {
    pub child_output: String,
    pub stderr: String,
}

pub fn spawn_agent_capturing<C: AsRef<std::ffi::OsStr>>(
    bin: &std::path::Path,
    policy: &std::path::Path,
    creds: &std::path::Path,
    audit: &std::path::Path,
    ca_dir: &std::path::Path,
    child: &[C],
) -> Result<CapturedAgent, String> {
    spawn_agent_capturing_with_env(bin, policy, creds, audit, ca_dir, child, &[])
}

pub fn spawn_agent_capturing_with_env<C: AsRef<std::ffi::OsStr>>(
    bin: &std::path::Path,
    policy: &std::path::Path,
    creds: &std::path::Path,
    audit: &std::path::Path,
    ca_dir: &std::path::Path,
    child: &[C],
    env: &[(&str, &str)],
) -> Result<CapturedAgent, String> {
    let mut command = Command::new(bin);
    command
        .args([
            "run",
            "--policy",
            policy.to_str().unwrap(),
            "--credentials-dir",
            creds.to_str().unwrap(),
            "--audit",
            audit.to_str().unwrap(),
            "--ca-dir",
            ca_dir.to_str().unwrap(),
            "--as",
            "default",
            "--",
        ])
        .args(child.iter().map(|arg| arg.as_ref()))
        .env("ZS_HOME", policy.parent().unwrap())
        .envs(env.iter().copied())
        // The Windows runner image exports PGPASSWORD; these tests prove that `zs run` does
        // not add it, not that the host has none.
        .env_remove("PGPASSWORD")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // `.output()` waits forever. A workload or an agent that never exits took the whole
    // Windows job to its 15-minute limit once, which reports nothing about which one hung.
    // Bound it, and name the process that did not exit.
    let (code, stdout, stderr) = run_bounded(command, AGENT_TIMEOUT)?;
    if code.is_none() {
        return Err(format!(
            "the agent did not exit within {AGENT_TIMEOUT:?}; stdout={stdout:?} stderr={stderr:?}"
        ));
    }
    Ok(CapturedAgent {
        child_output: stdout,
        stderr,
    })
}

const AGENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

fn run_bounded(
    mut command: Command,
    timeout: std::time::Duration,
) -> Result<(Option<i32>, String, String), String> {
    use std::io::Read;
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    // The drains report over a channel. Joining the threads would block on a pipe that a
    // grandchild still holds, which is the same hang the deadline exists to escape.
    let (tx, rx) = std::sync::mpsc::channel::<(usize, Vec<u8>)>();
    for (index, pipe) in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .enumerate()
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            let _ = tx.send((index, bytes));
        });
    }
    drop(tx);
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => break Some(status),
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    };
    let mut out = [String::new(), String::new()];
    let mut received = 0;
    let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while received < 2 {
        let remaining = drain_deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok((index, bytes)) => {
                out[index] = String::from_utf8_lossy(&bytes).into_owned();
                received += 1;
            }
            Err(_) => break,
        }
    }
    Ok((
        status.and_then(|s| s.code()),
        out[0].clone(),
        out[1].clone(),
    ))
}

pub struct Tripwire {
    addr: std::net::SocketAddr,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Tripwire {
    pub fn bind(addr: std::net::SocketAddr) -> Self {
        let listener = (0..250)
            .find_map(|_| {
                std::net::TcpListener::bind(addr).ok().or_else(|| {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    None
                })
            })
            .unwrap_or_else(|| panic!("{addr} stayed bound after the control plane stopped"));
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::spawn({
            let hits = hits.clone();
            let stop = stop.clone();
            move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            hits.fetch_add(1, Ordering::SeqCst);
                            drop(stream);
                        }
                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                    }
                }
            }
        });
        Self {
            addr,
            hits,
            stop,
            thread: Some(thread),
        }
    }

    pub fn any() -> Self {
        Self::bind(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    pub fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn hits(&self) -> usize {
        std::thread::sleep(std::time::Duration::from_millis(200));
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for Tripwire {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// The current UTC time as an AWS `X-Amz-Date` (YYYYMMDDTHHMMSSZ).
pub fn amz_now() -> String {
    amz_after(0)
}

// The UTC time `offset_secs` from now as an AWS `X-Amz-Date`.
pub fn amz_after(offset_secs: i64) -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + offset_secs;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}
