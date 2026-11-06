#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

struct Workspace {
    dir: common::TestHome,
}

impl Workspace {
    fn new() -> Self {
        let dir = common::TestHome::new(".zs-ca");
        std::fs::create_dir_all(dir.path().join(".zs-credentials")).unwrap();
        std::fs::write(
            dir.path().join("zs-policy.json"),
            r#"{"bindings":[],"signing_keys":[],"grants":[]}"#,
        )
        .unwrap();
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn marker(&self) -> PathBuf {
        self.path().join("child-ran")
    }

    fn marker_child(&self) -> Vec<String> {
        vec![
            "/usr/bin/touch".to_string(),
            self.marker().display().to_string(),
        ]
    }
}

struct Outcome {
    code: i32,
    stderr: String,
}

fn zs_run(ws: &Workspace, options: &[&str], child: &[String]) -> Outcome {
    let home = ws.path();
    let mut args: Vec<String> = vec![
        "run".into(),
        "--policy".into(),
        home.join("zs-policy.json").display().to_string(),
        "--credentials-dir".into(),
        home.join(".zs-credentials").display().to_string(),
        "--audit".into(),
        home.join("audit.jsonl").display().to_string(),
        "--ca-dir".into(),
        home.join(".zs-ca").display().to_string(),
    ];
    args.extend(options.iter().map(|o| o.to_string()));
    args.push("--".into());
    args.extend(child.iter().cloned());
    let output = Command::new(common::bin_path())
        .args(&args)
        .env("ZS_HOME", home)
        .env("USER", "alice")
        .current_dir(home)
        .output()
        .expect("zs must run");
    Outcome {
        code: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn assert_refused(ws: &Workspace, outcome: &Outcome, code: i32, prefix: &str) {
    assert_eq!(outcome.code, code, "stderr:\n{}", outcome.stderr);
    assert!(
        outcome.stderr.lines().any(|line| line.starts_with(prefix)),
        "expected a line starting with {prefix:?}:\n{}",
        outcome.stderr
    );
    assert!(
        !ws.marker().exists(),
        "the child must not launch after a startup failure"
    );
}

#[test]
fn a_marker_child_runs_when_startup_succeeds() {
    let ws = Workspace::new();
    let outcome = zs_run(&ws, &[], &ws.marker_child());
    assert_eq!(outcome.code, 0, "stderr:\n{}", outcome.stderr);
    assert!(ws.marker().exists());
}

#[test]
fn no_command_after_the_separator_exits_2() {
    let ws = Workspace::new();
    let outcome = zs_run(&ws, &[], &[]);
    assert_refused(&ws, &outcome, 2, "zs: no command supplied after --");
}

#[test]
fn an_invalid_policy_exits_1() {
    let ws = Workspace::new();
    std::fs::write(ws.path().join("zs-policy.json"), "not json").unwrap();
    let outcome = zs_run(&ws, &[], &ws.marker_child());
    assert_refused(&ws, &outcome, 1, "zs: policy: ");
}

#[test]
fn an_invalid_workload_exits_1() {
    let ws = Workspace::new();
    let outcome = zs_run(&ws, &["--as", ""], &ws.marker_child());
    assert_refused(&ws, &outcome, 1, "zs: identity value must be non-empty");
}

#[test]
fn an_unavailable_audit_sink_exits_1() {
    let ws = Workspace::new();
    let blocker = ws.path().join("not-a-directory");
    std::fs::write(&blocker, b"").unwrap();
    let audit = blocker.join("audit.jsonl").display().to_string();
    let outcome = zs_run(&ws, &["--audit", &audit], &ws.marker_child());
    assert_refused(&ws, &outcome, 1, "zs: audit sink unavailable: ");
}

#[test]
fn an_absent_audit_directory_is_created_private() {
    let ws = Workspace::new();
    let dir = ws.path().join("fresh").join(".zs-audit");
    let audit = dir.join("audit.jsonl").display().to_string();
    let outcome = zs_run(&ws, &["--audit", &audit], &ws.marker_child());
    assert_eq!(outcome.code, 0, "stderr:\n{}", outcome.stderr);
    assert!(ws.marker().exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}

#[test]
fn a_bad_listen_address_exits_2() {
    let ws = Workspace::new();
    let outcome = zs_run(&ws, &["--listen", "not-an-address"], &ws.marker_child());
    assert_refused(&ws, &outcome, 2, "zs: bad --listen: ");
}

#[test]
fn a_nonexistent_child_exits_1() {
    let ws = Workspace::new();
    let missing = ws.path().join("no-such-program").display().to_string();
    let outcome = zs_run(&ws, &[], &[missing]);
    assert_refused(&ws, &outcome, 1, "zs: failed to launch child: ");
}

fn free_loopback_port() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], common::free_port()))
}

fn rebinds_within(addr: std::net::SocketAddr, limit: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < limit {
        if std::net::TcpListener::bind(addr).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

fn write_postgres_policy(ws: &Workspace, upstream_port: u16) {
    std::fs::write(
        ws.path().join("zs-policy.json"),
        format!(
            r#"{{"bindings":[{{"resource":"appdb","host":"db.internal","protocol":"postgres","upstream_host":"127.0.0.1","upstream_port":{upstream_port}}}],"signing_keys":[],"grants":[]}}"#
        ),
    )
    .unwrap();
}

#[test]
fn an_unusable_ca_directory_exits_1() {
    let ws = Workspace::new();
    let not_a_dir = ws.path().join("ca-is-a-file");
    std::fs::write(&not_a_dir, b"").unwrap();
    let ca_dir = not_a_dir.display().to_string();
    let outcome = zs_run(&ws, &["--ca-dir", &ca_dir], &ws.marker_child());
    assert_refused(&ws, &outcome, 1, "zs: local ca: ");
}

#[test]
fn an_unreachable_control_plane_exits_1() {
    let ws = Workspace::new();
    let ca_dir = ws.path().join(".zs-ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
    let ca = common::test_ca::TestCa::generate("startup-lifecycle")
        .unwrap()
        .certificate_pem();
    std::fs::write(ca_dir.join("control-ca.crt"), ca).unwrap();
    let closed = free_loopback_port();
    let control_url = format!("http://{closed}");
    let outcome = zs_run(
        &ws,
        &[
            "--control",
            &control_url,
            "--enrollment-token",
            "enr-synthetic-lifecycle",
        ],
        &ws.marker_child(),
    );
    assert_refused(
        &ws,
        &outcome,
        1,
        &format!("zs: control plane at {control_url}: enrolment failed: "),
    );
    assert!(!outcome.stderr.contains("enr-synthetic-lifecycle"));
}

#[test]
fn a_missing_enrollment_token_exits_1() {
    let ws = Workspace::new();
    let outcome = zs_run(
        &ws,
        &["--control", "http://127.0.0.1:1"],
        &ws.marker_child(),
    );
    assert_refused(
        &ws,
        &outcome,
        1,
        "zs: control plane at http://127.0.0.1:1: ",
    );
}

#[test]
fn a_proxy_bind_failure_exits_1() {
    let ws = Workspace::new();
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let listen = held.local_addr().unwrap().to_string();
    let outcome = zs_run(&ws, &["--listen", &listen], &ws.marker_child());
    assert_refused(&ws, &outcome, 1, "zs: proxy bind: ");
}

#[test]
fn an_invalid_postgres_endpoint_after_the_proxy_starts_exits_1_and_releases_the_proxy() {
    let ws = Workspace::new();
    write_postgres_policy(&ws, 0);
    let proxy = free_loopback_port();
    let listen = proxy.to_string();
    let outcome = zs_run(&ws, &["--listen", &listen], &ws.marker_child());
    assert_refused(
        &ws,
        &outcome,
        1,
        "zs: invalid postgres upstream for appdb: ",
    );
    assert!(rebinds_within(proxy, std::time::Duration::from_secs(3)));
}

#[test]
fn child_spawn_failure_releases_started_services() {
    let ws = Workspace::new();
    let proxy = free_loopback_port();
    let listen = proxy.to_string();
    let missing = ws.path().join("no-such-program").display().to_string();
    let outcome = zs_run(&ws, &["--listen", &listen], &[missing]);
    assert_refused(&ws, &outcome, 1, "zs: failed to launch child: ");
    assert!(rebinds_within(proxy, std::time::Duration::from_secs(3)));
}

#[test]
fn child_exit_releases_all_services() {
    let ws = Workspace::new();
    write_postgres_policy(&ws, 1);
    let home = ws.path();
    let output = Command::new(common::bin_path())
        .args([
            "run",
            "--policy",
            &home.join("zs-policy.json").display().to_string(),
            "--credentials-dir",
            &home.join(".zs-credentials").display().to_string(),
            "--audit",
            &home.join("audit.jsonl").display().to_string(),
            "--ca-dir",
            &home.join(".zs-ca").display().to_string(),
            "--",
        ])
        .args(ws.marker_child())
        .env("ZS_HOME", home)
        .env("USER", "alice")
        .current_dir(home)
        .output()
        .expect("zs must run");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(ws.marker().exists());

    let proxy: std::net::SocketAddr = stdout
        .lines()
        .find_map(|line| line.strip_prefix("zs: proxy "))
        .and_then(|addr| addr.trim().parse().ok())
        .unwrap_or_else(|| panic!("no proxy address in:\n{stdout}"));
    let postgres: std::net::SocketAddr = stdout
        .lines()
        .find_map(|line| line.strip_prefix("zs: postgres appdb -> "))
        .and_then(|addr| addr.trim().parse().ok())
        .unwrap_or_else(|| panic!("no postgres address in:\n{stdout}"));
    for addr in [proxy, postgres] {
        assert!(
            rebinds_within(addr, std::time::Duration::from_secs(3)),
            "{addr} was not released"
        );
    }
}

#[test]
fn the_child_receives_every_proxy_ca_and_postgres_variable() {
    let ws = Workspace::new();
    write_postgres_policy(&ws, 1);
    let home = ws.path();
    let ca_dir = home.join(".zs-ca");
    let system_roots = home.join("system-roots.pem");
    std::fs::write(&system_roots, "SYSTEM ROOTS FIXTURE\n").unwrap();
    let output = Command::new(common::bin_path())
        .args([
            "run",
            "--policy",
            &home.join("zs-policy.json").display().to_string(),
            "--credentials-dir",
            &home.join(".zs-credentials").display().to_string(),
            "--audit",
            &home.join("audit.jsonl").display().to_string(),
            "--ca-dir",
            &ca_dir.display().to_string(),
            "--",
            "/usr/bin/env",
        ])
        .env("ZS_HOME", home)
        .env("USER", "alice")
        .env("SSL_CERT_FILE", &system_roots)
        .env("NO_PROXY", "internal.example")
        .env_remove("no_proxy")
        .current_dir(home)
        .output()
        .expect("zs must run");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(output.status.code(), Some(0), "{stdout}");

    let value = |prefix: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .map(str::trim)
            .unwrap_or_else(|| panic!("no {prefix:?} in:\n{stdout}"))
            .to_string()
    };
    let proxy = value("zs: proxy ");
    let postgres: std::net::SocketAddr = value("zs: postgres appdb -> ").parse().unwrap();
    let ca = ca_dir.join("ca.crt").display().to_string();
    let bundle = ca_dir.join("ca-bundle.crt");

    let proxy_url = value("HTTPS_PROXY=");
    let userinfo = proxy_url
        .strip_prefix("http://zs:")
        .and_then(|rest| rest.split_once('@'))
        .expect("the proxy URL carries the run token");
    assert_eq!(userinfo.1, proxy);
    assert_eq!(userinfo.0.len(), 64, "{proxy_url}");
    assert_eq!(value("https_proxy="), proxy_url);
    assert_eq!(value("NODE_EXTRA_CA_CERTS="), ca);
    for name in ["SSL_CERT_FILE=", "REQUESTS_CA_BUNDLE=", "CURL_CA_BUNDLE="] {
        assert_eq!(value(name), bundle.display().to_string(), "{name}");
    }
    let ca_pem = std::fs::read_to_string(&ca).unwrap();
    let bundle_pem = std::fs::read_to_string(&bundle).unwrap();
    assert!(
        bundle_pem.starts_with(&ca_pem),
        "the bundle starts with the agent CA"
    );
    assert!(
        bundle_pem.ends_with("SYSTEM ROOTS FIXTURE\n"),
        "the bundle keeps the roots SSL_CERT_FILE named"
    );
    for name in ["NO_PROXY=", "no_proxy="] {
        assert_eq!(
            value(name),
            "internal.example,127.0.0.1,localhost,::1",
            "{name}"
        );
    }
    assert!(value("NODE_OPTIONS=").contains("node-preload.cjs"));
    assert_eq!(value("NODE_USE_ENV_PROXY="), "1");
    assert_eq!(value("PGHOST="), postgres.ip().to_string());
    assert_eq!(value("PGPORT="), postgres.port().to_string());
    assert!(!stdout.contains("PGPASSWORD="));
}

#[cfg(unix)]
struct LiveAgent {
    child: std::process::Child,
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
}

#[cfg(unix)]
impl LiveAgent {
    fn new(ws: &Workspace, child: &[String]) -> Self {
        let home = ws.path();
        let mut command = Command::new(common::bin_path());
        command
            .args([
                "run",
                "--policy",
                &home.join("zs-policy.json").display().to_string(),
                "--credentials-dir",
                &home.join(".zs-credentials").display().to_string(),
                "--audit",
                &home.join("audit.jsonl").display().to_string(),
                "--ca-dir",
                &home.join(".zs-ca").display().to_string(),
                "--",
            ])
            .args(child)
            .env("ZS_HOME", home)
            .env("USER", "alice")
            .current_dir(home)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().expect("zs must run");
        let stdout = child.stdout.take().expect("zs stdout is piped");
        let stderr = child.stderr.take().expect("zs stderr is piped");
        Self {
            child,
            stdout,
            stderr,
        }
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.child.id()).expect("the child pid fits in i32")
    }

    fn signal(&self, signal: i32) {
        // SAFETY: `pid` is the live child this process spawned and has not reaped.
        let pid = self.pid();
        unsafe { libc::kill(pid, signal) };
    }

    fn wait_ready(&mut self, path: &Path) {
        for _ in 0..300 {
            if path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("the child never reached {}", path.display());
    }

    fn wait_code(&mut self) -> Option<i32> {
        self.child.wait().expect("zs must exit").code()
    }

    fn output_text(&mut self) -> String {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut self.stdout, &mut text).expect("zs stdout must read");
        std::io::Read::read_to_string(&mut self.stderr, &mut text).expect("zs stderr must read");
        text
    }
}

#[cfg(unix)]
#[test]
fn sigterm_to_zs_reaches_the_child_and_zs_exits_with_its_code() {
    let ws = Workspace::new();
    let ready = ws.path().join("child-ready");
    let marker = ws.path().join("child-term");
    let script = format!(
        "trap 'echo got-term > \"{}\"; exit 7' TERM; touch \"{}\"; i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done",
        marker.display(),
        ready.display()
    );
    let mut agent = LiveAgent::new(&ws, &["/bin/sh".to_string(), "-c".to_string(), script]);
    agent.wait_ready(&ready);
    agent.signal(libc::SIGTERM);

    let code = agent.wait_code();
    let output = agent.output_text();
    assert_eq!(code, Some(7), "output:\n{output}");
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().trim(),
        "got-term",
        "output:\n{output}"
    );
}

#[cfg(unix)]
#[test]
fn sighup_to_zs_reaches_the_child_and_zs_exits_with_its_code() {
    let ws = Workspace::new();
    let ready = ws.path().join("child-ready");
    let marker = ws.path().join("child-hup");
    let script = format!(
        "trap 'echo got-hup > \"{}\"; exit 9' HUP; touch \"{}\"; i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done",
        marker.display(),
        ready.display()
    );
    let mut agent = LiveAgent::new(&ws, &["/bin/sh".to_string(), "-c".to_string(), script]);
    agent.wait_ready(&ready);
    agent.signal(libc::SIGHUP);

    let code = agent.wait_code();
    let output = agent.output_text();
    assert_eq!(code, Some(9), "output:\n{output}");
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().trim(),
        "got-hup",
        "output:\n{output}"
    );
}

#[cfg(unix)]
#[test]
fn sigint_does_not_kill_zs_before_the_child_exits() {
    let ws = Workspace::new();
    let ready = ws.path().join("child-ready");
    let script = format!(
        "trap '' INT; touch \"{}\"; sleep 0.5; exit 3",
        ready.display()
    );
    let mut agent = LiveAgent::new(&ws, &["/bin/sh".to_string(), "-c".to_string(), script]);
    agent.wait_ready(&ready);
    agent.signal(libc::SIGINT);

    let code = agent.wait_code();
    let output = agent.output_text();
    assert_eq!(code, Some(3), "output:\n{output}");
    assert!(output.contains("zs: child-pid"), "output:\n{output}");
}

#[test]
fn a_closed_stdout_does_not_stop_the_agent() {
    let ws = Workspace::new();
    let home = ws.path();
    let script = format!("sleep 1; touch '{}'", ws.marker().display());
    let mut agent = Command::new(common::bin_path())
        .args([
            "run",
            "--policy",
            &home.join("zs-policy.json").display().to_string(),
            "--credentials-dir",
            &home.join(".zs-credentials").display().to_string(),
            "--audit",
            &home.join("audit.jsonl").display().to_string(),
            "--ca-dir",
            &home.join(".zs-ca").display().to_string(),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .env("ZS_HOME", home)
        .env("USER", "alice")
        .current_dir(home)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("zs must run");
    drop(agent.stdout.take());
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut agent.stderr.take().unwrap(), &mut stderr).unwrap();
    let status = agent.wait().unwrap();

    assert_eq!(status.code(), Some(0), "stderr:\n{stderr}");
    assert!(ws.marker().exists());
    assert!(!stderr.contains("panicked"), "stderr:\n{stderr}");
}
