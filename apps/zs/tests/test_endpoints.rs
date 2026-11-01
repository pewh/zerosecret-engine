#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

fn run_started(dir: &Path) -> serde_json::Value {
    let logs = dir.join(".zs-log");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let files: Vec<_> = std::fs::read_dir(&logs)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok().map(|e| e.path()))
                    .collect()
            })
            .unwrap_or_default();
        if let [file] = files.as_slice()
            && let Ok(text) = std::fs::read_to_string(file)
            && let Some(event) = text
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .find(|event| event["event"] == "run_started")
        {
            return event;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no run_started event in {}",
            logs.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[cfg(unix)]
#[test]
fn release_binary_ignores_test_endpoint_variables() {
    let temp = common::TestHome::new(".zs-ca");
    let dir = temp.path().to_path_buf();
    let upstream = common::spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) =
        common::write_test_setup(&dir, upstream.addr.port(), true, true);
    let mut agent = common::spawn_agent_with_env(
        common::bin_path().as_path(),
        policy.as_path(),
        creds.as_path(),
        audit.as_path(),
        ca_dir.as_path(),
        &["sleep", "20"],
        true,
        &[
            (
                "ZS_TEST_AWS_RESOLVE",
                "ssm.ap-southeast-1.amazonaws.com=127.0.0.1:9",
            ),
            ("ZS_TEST_AWS_EXTRA_ROOT", "/nonexistent-test-root.pem"),
        ],
    )
    .expect("agent spawn");

    let event = run_started(&dir);
    let built_with_test_endpoints = option_env!("ZS_BUILD_TEST_ENDPOINTS") == Some("1");
    assert_eq!(
        event["fields"]["test_endpoints"].as_bool(),
        Some(built_with_test_endpoints),
        "run_started must report the build, not the environment: {event}"
    );
    assert_eq!(
        event["fields"]["test_resolve"].as_u64(),
        Some(u64::from(built_with_test_endpoints)),
        "only a test-endpoint build may read ZS_TEST_AWS_RESOLVE: {event}"
    );

    let _ = agent.child.kill();
    let _ = agent.child.wait();
}
