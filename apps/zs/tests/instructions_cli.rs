#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

#[test]
fn test_zs_agent_instructions_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .arg("agent-instructions")
        .output()
        .expect("failed to execute zs agent-instructions");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout not utf8");
    let header = format!(
        "# ZeroSecret Integration Protocol (zs {})",
        env!("CARGO_PKG_VERSION")
    );
    assert!(stdout.starts_with(&header), "header missing: {stdout}");
    assert!(stdout.contains("zs schema"));
    assert!(stdout.contains("zs init --dry-run"));
    assert!(stdout.contains("not brokered"));
    assert!(stdout.contains("back up `.env` to `~/.zs-backups/<project>/` with 0600 permissions"));
    assert!(stdout.contains("zs run -- <command>"));
    assert!(stdout.contains("zs doctor --json"));
}

#[test]
fn test_zs_agent_instructions_rejects_extra_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .args(["agent-instructions", "--markdown"])
        .output()
        .expect("failed to execute zs agent-instructions");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
