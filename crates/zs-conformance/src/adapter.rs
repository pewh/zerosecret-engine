use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::config::Protocol;

pub const SETUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct SetupRequest {
    pub protocol: Protocol,
    pub case: String,
    pub upstream: SocketAddr,
    pub credential_file: PathBuf,
    pub upstream_ca: Option<PathBuf>,
    pub upstream_tls: Option<String>,
    pub operations: Vec<String>,
    pub auth_scheme: Option<String>,
    pub access_key_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Handle {
    pub handle: String,
    pub endpoint: SocketAddr,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum AdapterError {
    Timeout,
    NonZeroExit { code: Option<i32>, stderr: String },
    Leaked,
    BadJson(String),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterError::Timeout => formatter.write_str("adapter setup timed out"),
            AdapterError::NonZeroExit { code, stderr } => match code {
                Some(code) => write!(formatter, "adapter exited {code}: {stderr}"),
                None => write!(formatter, "adapter failed: {stderr}"),
            },
            AdapterError::Leaked => formatter.write_str("adapter printed the credential"),
            AdapterError::BadJson(reason) => {
                write!(formatter, "adapter printed no handle: {reason}")
            }
        }
    }
}

struct Output {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

pub fn setup(
    adapter: &Path,
    request: &SetupRequest,
    secrets: &[String],
    timeout: Duration,
) -> Result<Handle, AdapterError> {
    let mut command = Command::new(adapter);
    command.args(["setup", "--protocol", request.protocol.as_str()]);
    command.args(["--case", request.case.as_str()]);
    command.args([
        "--upstream-host",
        request.upstream.ip().to_string().as_str(),
    ]);
    command.args([
        "--upstream-port",
        request.upstream.port().to_string().as_str(),
    ]);
    command.args(["--credential-file", path_text(&request.credential_file)]);
    if let Some(path) = &request.upstream_ca {
        command.args(["--upstream-ca", path_text(path)]);
    }
    if let Some(value) = &request.upstream_tls {
        command.args(["--upstream-tls", value]);
    }
    if !request.operations.is_empty() {
        command.args(["--operations", request.operations.join(",").as_str()]);
    }
    if let Some(value) = &request.auth_scheme {
        command.args(["--auth-scheme", value]);
    }
    if let Some(value) = &request.access_key_id {
        command.args(["--access-key-id", value]);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = run(command, timeout)?;
    scan(&output.stdout, &output.stderr, secrets)?;
    if !output.status.success() {
        return Err(AdapterError::NonZeroExit {
            code: output.status.code(),
            stderr: output.stderr,
        });
    }
    let line = match output
        .stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
    {
        Some(line) => line.trim(),
        None => return Err(AdapterError::BadJson("stdout was empty".to_string())),
    };
    serde_json::from_str::<Handle>(line).map_err(|error| AdapterError::BadJson(error.to_string()))
}

pub fn teardown(adapter: &Path, handle: &Handle) -> Result<(), AdapterError> {
    let mut command = Command::new(adapter);
    command.args(["teardown", "--handle", &handle.handle]);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = run(command, SETUP_TIMEOUT)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(AdapterError::NonZeroExit {
            code: output.status.code(),
            stderr: output.stderr,
        })
    }
}

pub fn presign(
    adapter: &Path,
    handle: &Handle,
    url: &str,
    method: &str,
    expires: u64,
) -> Result<String, AdapterError> {
    let mut command = Command::new(adapter);
    command.args([
        "presign",
        "--handle",
        &handle.handle,
        "--url",
        url,
        "--method",
        method,
        "--expires",
        &expires.to_string(),
    ]);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = run(command, SETUP_TIMEOUT)?;
    if !output.status.success() {
        return Err(AdapterError::NonZeroExit {
            code: output.status.code(),
            stderr: output.stderr,
        });
    }
    let line = match output
        .stdout
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
    {
        Some(line) => line.trim(),
        None => return Err(AdapterError::BadJson("presign printed nothing".to_string())),
    };
    #[derive(Deserialize)]
    struct Presigned {
        url: String,
    }
    serde_json::from_str::<Presigned>(line)
        .map(|presigned| presigned.url)
        .map_err(|error| AdapterError::BadJson(error.to_string()))
}

fn path_text(path: &Path) -> &str {
    path.to_str().unwrap_or_default()
}

fn scan(stdout: &str, stderr: &str, secrets: &[String]) -> Result<(), AdapterError> {
    for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
        if stdout.contains(secret.as_str()) || stderr.contains(secret.as_str()) {
            return Err(AdapterError::Leaked);
        }
    }
    Ok(())
}

fn kill_tree(child: &mut std::process::Child) {
    kill_descendants(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

fn kill_descendants(pid: u32) {
    let Ok(output) = Command::new("pgrep")
        .args(["-P", &pid.to_string()])
        .stderr(Stdio::null())
        .output()
    else {
        return;
    };
    for descendant in String::from_utf8_lossy(&output.stdout).split_whitespace() {
        let Ok(descendant) = descendant.parse::<u32>() else {
            continue;
        };
        kill_descendants(descendant);
        let _ = Command::new("kill")
            .args(["-KILL", &descendant.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn run(mut command: Command, timeout: Duration) -> Result<Output, AdapterError> {
    let mut child = command.spawn().map_err(|error| AdapterError::NonZeroExit {
        code: None,
        stderr: format!("cannot run the adapter: {error}"),
    })?;
    let stdout = child.stdout.take().map(read_stream);
    let stderr = child.stderr.take().map(read_stream);
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_tree(&mut child);
                    return Err(AdapterError::Timeout);
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                kill_tree(&mut child);
                return Err(AdapterError::NonZeroExit {
                    code: None,
                    stderr: format!("cannot wait for the adapter: {error}"),
                });
            }
        }
    };
    Ok(Output {
        status,
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

fn read_stream(mut stream: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stream.read_to_end(&mut buffer);
        let _ = sender.send(buffer);
    });
    receiver
}

fn collect(stream: Option<mpsc::Receiver<Vec<u8>>>) -> String {
    match stream {
        Some(receiver) => match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => String::new(),
        },
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        crate::test_lock::lock()
    }

    fn fixture(name: &str) -> PathBuf {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
        }
        path
    }

    fn request(case: &str) -> SetupRequest {
        SetupRequest {
            protocol: Protocol::Postgres,
            case: case.to_string(),
            upstream: "127.0.0.1:5434".parse().expect("upstream"),
            credential_file: PathBuf::from("/tmp/conformance-credential"),
            upstream_ca: Some(PathBuf::from("/tmp/ca.pem")),
            upstream_tls: Some("ca-sha256:00".to_string()),
            operations: vec!["connect".to_string()],
            auth_scheme: None,
            access_key_id: None,
        }
    }

    #[test]
    fn a_well_formed_adapter_returns_its_endpoint() {
        let _lock = lock_env();
        let handle = setup(
            &fixture("stub-adapter.sh"),
            &request("X-01"),
            &[],
            Duration::from_secs(5),
        )
        .expect("a stub handle");
        assert_eq!(handle.handle, "stub-1");
        assert_eq!(handle.endpoint, "127.0.0.1:45999".parse().expect("addr"));
        assert_eq!(
            handle.env.get("PGHOST").map(String::as_str),
            Some("127.0.0.1")
        );
    }

    #[test]
    fn an_adapter_that_never_returns_fails_the_case() {
        let _lock = lock_env();
        let dir = tempfile::tempdir().expect("temp dir");
        let pid_file = dir.path().join("adapter.pid");
        let started = Instant::now();
        let result = {
            let _guard = EnvGuard::set("STUB_PID_FILE", pid_file.to_str().expect("path"));
            setup(
                &fixture("hanging-adapter.sh"),
                &request("X-02"),
                &[],
                Duration::from_secs(2),
            )
        };
        assert!(matches!(result, Err(AdapterError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid = std::fs::read_to_string(&pid_file).expect("pid file");
        let alive = || {
            Command::new("kill")
                .args(["-0", pid.trim()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("kill probe")
                .success()
        };
        let probed = Instant::now();
        while alive() && probed.elapsed() < Duration::from_secs(3) {
            thread::sleep(Duration::from_millis(50));
        }
        assert!(!alive(), "the adapter's child process is still running");
    }

    #[test]
    fn a_credential_on_stdout_is_a_leak() {
        let _lock = lock_env();
        let _guard = EnvGuard::set("LEAK_STREAM", "stdout");
        let _secret = EnvGuard::set("LEAK_SECRET", "hunter2-fixture");
        let result = setup(
            &fixture("leaky-adapter.sh"),
            &request("X-03"),
            &["hunter2-fixture".to_string()],
            Duration::from_secs(5),
        );
        assert!(matches!(result, Err(AdapterError::Leaked)));
    }

    #[test]
    fn a_credential_on_stderr_is_a_leak() {
        let _lock = lock_env();
        let _stream = EnvGuard::set("LEAK_STREAM", "stderr");
        let _secret = EnvGuard::set("LEAK_SECRET", "hunter2-fixture");
        let result = setup(
            &fixture("leaky-adapter.sh"),
            &request("X-04"),
            &["hunter2-fixture".to_string()],
            Duration::from_secs(5),
        );
        assert!(matches!(result, Err(AdapterError::Leaked)));
    }

    #[test]
    fn a_non_zero_setup_is_a_failure_not_a_skip() {
        let _lock = lock_env();
        let _code = EnvGuard::set("STUB_EXIT", "3");
        let _stderr = EnvGuard::set("STUB_STDERR", "the fixture refused");
        let result = setup(
            &fixture("stub-adapter.sh"),
            &request("X-05"),
            &[],
            Duration::from_secs(5),
        );
        match result {
            Err(AdapterError::NonZeroExit { code, stderr }) => {
                assert_eq!(code, Some(3));
                assert!(stderr.contains("the fixture refused"));
            }
            other => panic!("expected a non-zero exit, got {other:?}"),
        }
    }

    #[test]
    fn the_request_is_passed_as_the_documented_flags() {
        let _lock = lock_env();
        let dir = tempfile::tempdir().expect("temp dir");
        let args_file = dir.path().join("args.txt");
        let parsed = {
            let _guard = EnvGuard::set("STUB_ARGS_FILE", args_file.to_str().expect("path"));
            let mut full = request("X-06");
            full.auth_scheme = Some("aws-sigv4".to_string());
            full.access_key_id = Some("AKIDCONFORMANCE".to_string());
            setup(
                &fixture("stub-adapter.sh"),
                &full,
                &[],
                Duration::from_secs(5),
            )
            .expect("stub handle")
        };
        assert_eq!(parsed.endpoint, "127.0.0.1:45999".parse().expect("addr"));
        let args = std::fs::read_to_string(&args_file).expect("args file");
        let args: Vec<&str> = args.lines().collect();
        for flag in [
            "--protocol",
            "--case",
            "--upstream-host",
            "--upstream-port",
            "--credential-file",
            "--upstream-ca",
            "--upstream-tls",
            "--operations",
            "--auth-scheme",
            "--access-key-id",
        ] {
            assert_eq!(args.iter().filter(|arg| **arg == flag).count(), 1, "{flag}");
        }
        assert!(args.contains(&"aws-sigv4"));
        assert!(args.contains(&"127.0.0.1"));
        assert!(args.contains(&"5434"));
    }

    #[test]
    fn an_absent_upstream_ca_omits_the_flag() {
        let _lock = lock_env();
        let dir = tempfile::tempdir().expect("temp dir");
        let args_file = dir.path().join("args.txt");
        {
            let _guard = EnvGuard::set("STUB_ARGS_FILE", args_file.to_str().expect("path"));
            let mut bare = request("X-07");
            bare.upstream_ca = None;
            setup(
                &fixture("stub-adapter.sh"),
                &bare,
                &[],
                Duration::from_secs(5),
            )
            .expect("stub handle");
        }
        let args = std::fs::read_to_string(&args_file).expect("args file");
        assert!(!args.lines().any(|line| line == "--upstream-ca"));
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }
}
