#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::BufRead;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const COLD_START_BUDGET: Duration = Duration::from_millis(400);

fn measure_cold_start(dir: &std::path::Path, port: u16) -> (Duration, Child) {
    let (policy, creds, audit, ca_dir, _) = common::write_test_setup(dir, port, true, true);
    let started = Instant::now();
    let mut child = Command::new(common::bin_path())
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
            "sleep",
            "5",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let stdout = child.stdout.take().unwrap();
    let reader = std::io::BufReader::new(stdout);
    let mut elapsed = None;
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.contains("zs: proxy ") {
            elapsed = Some(started.elapsed());
            break;
        }
        if started.elapsed() > Duration::from_secs(10) {
            break;
        }
    }
    (
        elapsed.expect("agent must report the proxy ready within 10 s"),
        child,
    )
}

#[test]
fn cold_start_and_rss_within_budget() {
    let dir = common::TestHome::new(".zs-ca");
    let upstream = common::spawn_fake_upstream();

    // Warm-up absorbs macOS first-exec code signing and exits before any agent work.
    let _ = Command::new(common::bin_path())
        .arg("--warm-binary-not-a-command")
        .output();

    let (cold_start, child) = measure_cold_start(dir.path(), upstream.addr.port());
    println!("cold start to proxy ready: {cold_start:?}");

    if cfg!(debug_assertions) {
        println!("debug build: cold-start budget (400 ms) is enforced on release builds in CI");
    } else {
        assert!(
            cold_start <= COLD_START_BUDGET,
            "cold start {cold_start:?} exceeds {COLD_START_BUDGET:?}"
        );
    }

    let mut child = child;
    let pid = child.id();
    let mut rss_kb = 0;
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(100));
        rss_kb = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
            .unwrap_or(0);
        if rss_kb > 0 {
            break;
        }
    }
    println!("agent rss: {rss_kb} KiB");
    assert!(
        rss_kb > 0,
        "the agent was not running when its RSS was read, so nothing was measured — this \
         is a fixture failure, not a footprint regression"
    );
    assert!(
        rss_kb * 1024 <= 60 * 1024 * 1024,
        "agent RSS {rss_kb} KiB exceeds 60 MB"
    );
    let _ = child.kill();
    let _ = child.wait();
}
