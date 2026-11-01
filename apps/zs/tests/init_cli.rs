#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::process::Command;

#[test]
fn test_zs_init_end_to_end() {
    let temp_dir = tempfile::tempdir().unwrap();
    let env_path = temp_dir.path().join(".env");
    let gitignore_path = temp_dir.path().join(".gitignore");

    fs::write(&env_path, "STRIPE_SECRET_KEY=sk_live_12345\n").unwrap();
    fs::write(&gitignore_path, "node_modules/\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .current_dir(temp_dir.path())
        .arg("init")
        .output()
        .expect("failed to execute zs init");

    assert!(output.status.success(), "zs init failed: {:?}", output);
    assert!(temp_dir.path().join("zs-policy.json").exists());

    let updated_env = fs::read_to_string(&env_path).unwrap();
    assert!(!updated_env.contains("sk_live_12345"));
    assert!(updated_env.contains("placeholder_managed_by_zerosecret"));

    let backups: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".env.zerosecret_backup_")
        })
        .collect();
    assert_eq!(backups.len(), 1);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(backups[0].path()).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    let gitignore = fs::read_to_string(&gitignore_path).unwrap();
    assert!(gitignore.contains("*.zerosecret_backup_*"));
}

#[test]
fn test_zs_init_dry_run_leaves_env_intact() {
    let temp_dir = tempfile::tempdir().unwrap();
    let env_path = temp_dir.path().join(".env");

    fs::write(&env_path, "STRIPE_SECRET_KEY=sk_live_12345\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .current_dir(temp_dir.path())
        .args(["init", "--dry-run"])
        .output()
        .expect("failed to execute zs init --dry-run");

    assert!(
        output.status.success(),
        "zs init --dry-run failed: {:?}",
        output
    );
    assert!(!temp_dir.path().join("zs-policy.json").exists());

    let updated_env = fs::read_to_string(&env_path).unwrap();
    assert!(updated_env.contains("sk_live_12345"));
    assert!(!updated_env.contains("placeholder_managed_by_zerosecret"));

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("placeholder_managed_by_zerosecret"));
    assert!(stdout.contains("dry-run"));

    let backups: Vec<_> = fs::read_dir(temp_dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".env.zerosecret_backup_")
        })
        .collect();
    assert!(backups.is_empty());
}

#[test]
fn test_zs_init_existing_policy_without_force_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let env_path = temp_dir.path().join(".env");
    let policy_path = temp_dir.path().join("zs-policy.json");

    fs::write(&env_path, "STRIPE_SECRET_KEY=sk_live_12345\n").unwrap();
    fs::write(&policy_path, "{}\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .current_dir(temp_dir.path())
        .arg("init")
        .output()
        .expect("failed to execute zs init");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("zs-policy.json already exists; pass --force to overwrite"));

    let force_output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .current_dir(temp_dir.path())
        .args(["init", "--force"])
        .output()
        .expect("failed to execute zs init --force");

    assert!(force_output.status.success());
    let policy_content = fs::read_to_string(&policy_path).unwrap();
    assert!(policy_content.contains("api.stripe.com"));
}

#[test]
fn test_zs_init_policy_validates_with_doctor() {
    let temp_dir = tempfile::tempdir().unwrap();
    let env_path = temp_dir.path().join(".env");

    let env_content = "STRIPE_SECRET_KEY=sk_live_12345\n\
OPENAI_API_KEY=sk-proj-67890\n\
GITHUB_TOKEN=ghp_abcdef\n\
DATABASE_URL=postgres://u:p@db.internal:5432/myapp\n";
    fs::write(&env_path, env_content).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .current_dir(temp_dir.path())
        .arg("init")
        .output()
        .expect("failed to execute zs init");

    assert!(output.status.success());

    let doctor_output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .current_dir(temp_dir.path())
        .args(["doctor", "--json"])
        .output()
        .expect("failed to execute zs doctor --json");

    assert!(doctor_output.status.success());
    let stdout = String::from_utf8(doctor_output.stdout).unwrap();
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["policy_valid"], true);
    assert_eq!(json["bindings_count"], 4);
}

fn init(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_zs"))
        .current_dir(dir)
        .arg("init")
        .args(args)
        .output()
        .expect("failed to execute zs init")
}

fn backups(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".env.zerosecret_backup_")
        })
        .collect()
}

#[test]
fn test_zs_init_rerun_is_refused_and_keeps_the_original_backup() {
    let temp_dir = tempfile::tempdir().unwrap();
    let env_path = temp_dir.path().join(".env");
    fs::write(
        &env_path,
        "DATABASE_URL=postgres://app:secret@db.prod.example:5432/main\n",
    )
    .unwrap();

    assert!(init(temp_dir.path(), &[]).status.success());
    let policy_before = fs::read_to_string(temp_dir.path().join("zs-policy.json")).unwrap();
    let env_before = fs::read_to_string(&env_path).unwrap();

    let rerun = init(temp_dir.path(), &["--force"]);
    assert_eq!(rerun.status.code(), Some(1));
    let stderr = String::from_utf8(rerun.stderr).unwrap();
    assert!(stderr.contains("already sanitized"), "{stderr}");

    assert_eq!(
        fs::read_to_string(temp_dir.path().join("zs-policy.json")).unwrap(),
        policy_before
    );
    assert_eq!(fs::read_to_string(&env_path).unwrap(), env_before);
    let found = backups(temp_dir.path());
    assert_eq!(found.len(), 1);
    assert!(
        fs::read_to_string(&found[0])
            .unwrap()
            .contains("secret@db.prod.example")
    );
}

#[test]
fn test_zs_init_reports_unbrokered_keys_by_name_only() {
    let temp_dir = tempfile::tempdir().unwrap();
    let env_path = temp_dir.path().join(".env");
    fs::write(
        &env_path,
        "STRIPE_SECRET_KEY=sk_live_brokered1\n\
JWT_SECRET=jwt-signing-value-1\n\
STRIPE_PUBLISHABLE_KEY=pk_live_public1\n\
REDIS_URL=redis://:redispass1@cache.example:6379/0\n",
    )
    .unwrap();

    let output = init(temp_dir.path(), &[]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let all = format!("{stdout}{stderr}");

    assert!(all.contains("replaced in .env: STRIPE_SECRET_KEY"), "{all}");
    assert!(
        all.contains("not brokered, left in .env: JWT_SECRET"),
        "{all}"
    );
    assert!(
        all.contains("not brokered, left in .env: REDIS_URL"),
        "{all}"
    );
    assert!(!all.contains("STRIPE_PUBLISHABLE_KEY"), "{all}");
    for value in ["sk_live_brokered1", "jwt-signing-value-1", "redispass1"] {
        assert!(!all.contains(value), "{value} leaked: {all}");
    }

    let env = fs::read_to_string(&env_path).unwrap();
    assert!(!env.contains("sk_live_brokered1"));
    assert!(env.contains("JWT_SECRET=jwt-signing-value-1"));
    assert!(env.contains("STRIPE_PUBLISHABLE_KEY=pk_live_public1"));
}

#[test]
fn test_zs_init_malformed_env_stops_without_writing() {
    let temp_dir = tempfile::tempdir().unwrap();
    let env_path = temp_dir.path().join(".env");
    let original = "STRIPE_SECRET_KEY=sk_live_12345\nthis line has no separator\n";
    fs::write(&env_path, original).unwrap();

    let output = init(temp_dir.path(), &[]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("line 2"), "{stderr}");
    assert!(!stderr.contains("separator"), "{stderr}");
    assert!(!temp_dir.path().join("zs-policy.json").exists());
    assert_eq!(fs::read_to_string(&env_path).unwrap(), original);
    assert!(backups(temp_dir.path()).is_empty());
}

#[test]
fn test_zs_init_dry_run_ignores_an_existing_policy() {
    let temp_dir = tempfile::tempdir().unwrap();
    fs::write(temp_dir.path().join(".env"), "GITHUB_TOKEN=ghp_abc\n").unwrap();
    fs::write(temp_dir.path().join("zs-policy.json"), "{}\n").unwrap();

    let output = init(temp_dir.path(), &["--dry-run"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(temp_dir.path().join("zs-policy.json")).unwrap(),
        "{}\n"
    );
}

#[test]
fn test_zs_init_rejects_listen_port_zero() {
    let temp_dir = tempfile::tempdir().unwrap();
    fs::write(
        temp_dir.path().join(".env"),
        "DATABASE_URL=postgres://app:pw@db.example:5432/main\n",
    )
    .unwrap();
    let output = init(temp_dir.path(), &["--listen-port-start", "0"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!temp_dir.path().join("zs-policy.json").exists());
}
