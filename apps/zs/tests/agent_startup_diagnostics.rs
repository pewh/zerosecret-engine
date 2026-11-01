#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

#[test]
fn early_exit_preserves_stderr_and_status() {
    let dir = common::TestHome::new(".");
    let missing = dir.path().join("missing-policy.json");
    let result = common::spawn_agent(
        &common::bin_path(),
        &missing,
        dir.path(),
        &dir.path().join("audit.jsonl"),
        dir.path(),
        &["true"],
        true,
    );
    let error = match result {
        Err(error) => error,
        Ok(mut agent) => {
            let _ = agent.child.kill();
            let _ = agent.child.wait();
            panic!("missing policy must prevent startup");
        }
    };
    assert!(
        error.contains("policy"),
        "startup diagnostic missing: {error}"
    );
    assert!(
        error.contains("exit status:"),
        "exit status missing: {error}"
    );
}
