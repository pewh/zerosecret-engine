#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::process::Command;

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Output {
    fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

fn zs(home: &Path, args: &[String]) -> Output {
    let output = Command::new(common::bin_path())
        .args(args)
        .env("ZS_HOME", home)
        .env("USER", "alice")
        .current_dir(home)
        .output()
        .expect("zs must run");
    Output {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn workspace() -> common::TestHome {
    let dir = common::TestHome::new(".");
    std::fs::write(
        dir.path().join("zs-policy.json"),
        r#"{"bindings":[{"resource":"stripe-production","host":"api.stripe.com","protocol":"https"}],"signing_keys":[],"grants":[]}"#,
    )
    .unwrap();
    dir
}

#[test]
fn login_against_a_configured_control_plane_actually_contacts_it() {
    let home = workspace();
    let unreachable = "http://127.0.0.1:1".to_string();
    let control_ca = home.path().join("control-ca.pem");
    std::fs::write(
        &control_ca,
        common::test_ca::TestCa::generate("zerosecret-control")
            .unwrap()
            .certificate_pem(),
    )
    .unwrap();

    let out = zs(
        home.path(),
        &[
            "login".into(),
            "--control".into(),
            unreachable,
            "--control-ca".into(),
            control_ca.display().to_string(),
        ],
    );

    assert_ne!(
        out.code,
        0,
        "login against an unreachable control plane must fail, not fall back to a local \
         session: {}",
        out.combined()
    );
    assert!(
        !home.path().join(".zs-session").exists(),
        "a failed login must not leave a session behind"
    );
    let text = out.combined().to_lowercase();
    assert!(
        !text.contains("unknown"),
        "`--control` must be a recognised flag, not an unknown argument: {}",
        out.combined()
    );
    assert!(
        out.stdout.contains("zs: signing in to http://127.0.0.1:1"),
        "login must name the control plane it chose: {}",
        out.combined()
    );
    assert!(
        out.stderr
            .contains("zs: cannot reach the control plane at http://127.0.0.1:1"),
        "the error must come from the connect attempt to the control plane: {}",
        out.combined()
    );
}

#[test]
fn login_without_a_control_plane_says_it_is_local() {
    let home = workspace();

    let out = zs(home.path(), &["login".into()]);

    assert_eq!(out.code, 0, "{}", out.combined());
    let text = out.combined().to_lowercase();
    assert!(
        text.contains("local"),
        "a local session must say so, or it reads as SSO: {}",
        out.combined()
    );
}

#[test]
fn run_with_a_control_plane_enrols_before_serving() {
    let home = workspace();

    let out = zs(
        home.path(),
        &[
            "run".into(),
            "--control".into(),
            "http://127.0.0.1:1".into(),
            "--enrollment-token".into(),
            "enr-does-not-matter".into(),
            "--audit".into(),
            home.path().join("audit.jsonl").display().to_string(),
            "--ca-dir".into(),
            home.path().display().to_string(),
            "--".into(),
            "echo".into(),
            "hi".into(),
        ],
    );

    assert_ne!(
        out.code,
        0,
        "an agent that cannot reach its control plane must not serve: {}",
        out.combined()
    );
    assert!(
        !out.stdout.contains("hi"),
        "the child must not run when enrolment failed: {}",
        out.stdout
    );
    assert!(
        !out.combined().to_lowercase().contains("unknown"),
        "`--control` and `--enrollment-token` must be recognised flags: {}",
        out.combined()
    );
}

#[test]
fn run_without_a_control_plane_still_uses_local_config() {
    let home = workspace();

    let out = zs(
        home.path(),
        &[
            "run".into(),
            "--audit".into(),
            home.path().join("audit.jsonl").display().to_string(),
            "--ca-dir".into(),
            home.path().display().to_string(),
            "--".into(),
            "echo".into(),
            "local-ok".into(),
        ],
    );

    assert_eq!(out.code, 0, "{}", out.combined());
    assert!(
        out.stdout.contains("local-ok"),
        "the offline path must keep working: {}",
        out.combined()
    );
}

fn run_listening(home: &Path, listen: &str) -> Output {
    zs(
        home,
        &[
            "run".into(),
            "--listen".into(),
            listen.into(),
            "--audit".into(),
            home.join("audit.jsonl").display().to_string(),
            "--ca-dir".into(),
            home.display().to_string(),
            "--".into(),
            "echo".into(),
            "listen-ok".into(),
        ],
    )
}

#[test]
fn a_non_loopback_listen_address_is_refused() {
    let home = workspace();

    for loopback in ["127.0.0.1:0", "[::1]:0"] {
        let ok = run_listening(home.path(), loopback);
        assert_eq!(ok.code, 0, "{loopback}: {}", ok.combined());
        assert!(
            ok.stdout.contains("listen-ok"),
            "{loopback} must start and run the child: {}",
            ok.combined()
        );
    }

    for open in ["0.0.0.0:0", "192.168.1.10:0", "[::]:0"] {
        let out = run_listening(home.path(), open);
        assert_eq!(out.code, 2, "{open}: {}", out.combined());
        assert!(
            out.stderr
                .contains("zs: --listen must be a loopback address"),
            "{open}: {}",
            out.combined()
        );
        assert!(
            !out.stdout.contains("listen-ok"),
            "the child must not run behind a non-loopback listener: {}",
            out.combined()
        );
    }
}

struct CountingListener {
    port: u16,
    accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CountingListener {
    fn start() -> Self {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(AtomicUsize::new(0));
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let (count, halt) = (accepted.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok(_) => {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                }
            }
        });
        Self {
            port,
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for CountingListener {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run_enrolling(home: &Path, control: &str, enroll_url: Option<&str>) -> Output {
    let control_ca = home.join("control-ca.pem");
    std::fs::write(
        &control_ca,
        common::test_ca::TestCa::generate("zerosecret-control")
            .unwrap()
            .certificate_pem(),
    )
    .unwrap();
    let mut args: Vec<String> = vec![
        "run".into(),
        "--control".into(),
        control.into(),
        "--control-ca".into(),
        control_ca.display().to_string(),
        "--enrollment-token".into(),
        "t".into(),
    ];
    if let Some(url) = enroll_url {
        args.push("--enroll-url".into());
        args.push(url.into());
    }
    args.extend([
        "--audit".into(),
        home.join("audit.jsonl").display().to_string(),
        "--ca-dir".into(),
        home.display().to_string(),
        "--".into(),
        "echo".into(),
        "enrolled-ok".into(),
    ]);
    zs(home, &args)
}

#[test]
fn an_http_enrolment_url_is_refused_unless_loopback() {
    let home = workspace();
    let listener = CountingListener::start();
    let loopback = format!("http://127.0.0.1:{}", listener.port);

    let proceeds = run_enrolling(home.path(), &loopback, None);
    assert!(
        !proceeds
            .stderr
            .contains("http is allowed only for a loopback control plane"),
        "a loopback http control plane must pass the URL check: {}",
        proceeds.combined()
    );
    assert!(
        listener.accepted() >= 1,
        "a loopback control plane must be contacted: {}",
        proceeds.combined()
    );

    let before = listener.accepted();
    let remote = run_enrolling(home.path(), "http://control.example.com", None);
    assert_eq!(remote.code, 1, "{}", remote.combined());
    assert!(
        remote
            .stderr
            .contains("http is allowed only for a loopback control plane"),
        "{}",
        remote.combined()
    );
    assert!(!remote.stdout.contains("enrolled-ok"));

    let remote_enrol = run_enrolling(home.path(), &loopback, Some("http://control.example.com"));
    assert_eq!(remote_enrol.code, 1, "{}", remote_enrol.combined());
    assert!(
        remote_enrol
            .stderr
            .contains("http is allowed only for a loopback control plane"),
        "{}",
        remote_enrol.combined()
    );
    assert_eq!(
        listener.accepted(),
        before,
        "a refused enrolment URL must not open any connection"
    );
}

#[test]
fn usage_names_the_control_plane_flags() {
    let home = workspace();

    let out = zs(home.path(), &["frobnicate".into()]);

    let text = out.combined();
    assert!(
        text.contains("--control"),
        "usage must name --control: {text}"
    );
}

#[test]
fn control_without_a_value_is_a_usage_error() {
    let home = workspace();

    let out = zs(home.path(), &["login".into(), "--control".into()]);

    assert_eq!(out.code, 2, "{}", out.combined());
    assert!(
        out.combined().contains("needs a value"),
        "a flag with no value must say so, not report it as unknown: {}",
        out.combined()
    );
}

#[test]
fn status_reports_the_configured_control_plane() {
    let home = workspace();
    zs(home.path(), &["login".into()]);

    let out = zs(
        home.path(),
        &[
            "status".into(),
            "--control".into(),
            "https://control.example.test".into(),
        ],
    );

    assert_eq!(out.code, 0, "{}", out.combined());
    assert!(
        out.stdout.contains("control.example.test"),
        "status must name the control plane it is configured against: {}",
        out.stdout
    );
}
