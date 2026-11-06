#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sandbox {
    _root: tempfile::TempDir,
    ws: PathBuf,
    home: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let ws = root.path().join("proj");
        let home = root.path().join("home");
        fs::create_dir(&ws).unwrap();
        fs::create_dir(&home).unwrap();
        Self {
            _root: root,
            ws,
            home,
        }
    }

    fn with_env(content: &str) -> Self {
        let sandbox = Self::new();
        fs::write(sandbox.ws.join(".env"), content).unwrap();
        sandbox
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zs"));
        command
            .current_dir(&self.ws)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home);
        command
    }

    fn init(&self, args: &[&str]) -> Output {
        self.command()
            .arg("init")
            .args(args)
            .output()
            .expect("failed to execute zs init")
    }

    fn backup_dir(&self) -> PathBuf {
        self.home.join(".zs-backups/proj")
    }

    fn backups(&self) -> Vec<PathBuf> {
        match fs::read_dir(self.backup_dir()) {
            Ok(entries) => entries.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn env_path(&self) -> PathBuf {
        self.ws.join(".env")
    }
}

fn workspace_names(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn test_zs_init_end_to_end() {
    let sandbox = Sandbox::with_env("STRIPE_SECRET_KEY=sk_live_12345\n");
    let gitignore_path = sandbox.ws.join(".gitignore");
    fs::write(&gitignore_path, "node_modules/\n").unwrap();

    let output = sandbox.init(&[]);

    assert!(output.status.success(), "zs init failed: {:?}", output);
    assert!(sandbox.ws.join("zs-policy.json").exists());

    let updated_env = fs::read_to_string(sandbox.env_path()).unwrap();
    assert!(!updated_env.contains("sk_live_12345"));
    assert!(updated_env.contains("placeholder_managed_by_zerosecret"));

    let backups = sandbox.backups();
    assert_eq!(backups.len(), 1);
    assert!(
        fs::read_to_string(&backups[0])
            .unwrap()
            .contains("sk_live_12345")
    );

    let gitignore = fs::read_to_string(&gitignore_path).unwrap();
    assert!(gitignore.contains("*.zerosecret_backup_*"));
}

#[test]
fn the_backup_is_written_outside_the_workspace() {
    let sandbox = Sandbox::with_env("STRIPE_SECRET_KEY=sk_live_12345\n");

    let output = sandbox.init(&[]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let backups = sandbox.backups();
    assert_eq!(backups.len(), 1);
    assert!(
        fs::read_to_string(&backups[0])
            .unwrap()
            .contains("sk_live_12345")
    );
    assert!(
        !workspace_names(&sandbox.ws)
            .iter()
            .any(|n| n.contains("zerosecret_backup")),
        "a backup file is in the workspace"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains(&format!("backup saved to {}", backups[0].display())),
        "{stdout}"
    );
    let env = fs::read_to_string(sandbox.env_path()).unwrap();
    assert!(
        env.lines()
            .next()
            .unwrap()
            .ends_with(&format!("the original is at {}", backups[0].display())),
        "{env}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = fs::metadata(&backups[0]).unwrap().permissions().mode();
        assert_eq!(file_mode & 0o777, 0o600);
        let dir_mode = fs::metadata(sandbox.backup_dir())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o077, 0);
    }
}

#[test]
fn dry_run_never_prints_an_unbrokered_value() {
    let sandbox = Sandbox::with_env(
        "STRIPE_SECRET_KEY=sk_live_12345\nAPP_NAME=unbrokered_value_7f3a\nexport JWT_SECRET=\"jwt-signing-value-1\"\n# a comment\n",
    );

    let output = sandbox.init(&["--dry-run"]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("STRIPE_SECRET_KEY=placeholder_managed_by_zerosecret"));
    assert!(stdout.contains("APP_NAME=<withheld>"), "{stdout}");
    assert!(stdout.contains("export JWT_SECRET=<withheld>"), "{stdout}");
    assert!(!stdout.contains("# a comment"));
    assert!(stdout.contains("# <withheld>"));
    for value in [
        "unbrokered_value_7f3a",
        "jwt-signing-value-1",
        "sk_live_12345",
    ] {
        assert!(!stdout.contains(value), "{value} leaked: {stdout}");
    }
    assert!(sandbox.backups().is_empty());
    assert!(!sandbox.home.join(".zs-backups").exists());
}

#[test]
fn dry_run_withholds_comment_lines() {
    let sandbox = Sandbox::with_env(
        "STRIPE_SECRET_KEY=sk_live_12345\n# OLD_KEY=commented_secret_9d1e\n\n# note: token comment_secret_44ab\nAPP_NAME=plain\n",
    );

    let output = sandbox.init(&["--dry-run"]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("# <withheld>"), "{stdout}");
    assert!(stdout.contains("APP_NAME=<withheld>"), "{stdout}");
    for value in ["commented_secret_9d1e", "comment_secret_44ab", "OLD_KEY"] {
        assert!(!stdout.contains(value), "{value} leaked: {stdout}");
    }
    assert_eq!(
        fs::read_to_string(sandbox.env_path()).unwrap(),
        "STRIPE_SECRET_KEY=sk_live_12345\n# OLD_KEY=commented_secret_9d1e\n\n# note: token comment_secret_44ab\nAPP_NAME=plain\n"
    );
}

#[test]
fn a_real_run_keeps_comment_lines_in_the_env_file() {
    let sandbox = Sandbox::with_env("STRIPE_SECRET_KEY=sk_live_12345\n# keep this note\n");

    assert!(sandbox.init(&[]).status.success());

    let env = fs::read_to_string(sandbox.env_path()).unwrap();
    assert!(env.contains("# keep this note"), "{env}");
}

#[test]
fn init_refuses_without_a_home_directory() {
    let sandbox = Sandbox::with_env("STRIPE_SECRET_KEY=sk_live_12345\n");

    let output = sandbox
        .command()
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .arg("init")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("zs: cannot find the home directory for the .env backup"),
        "{stderr}"
    );
    assert_eq!(
        fs::read_to_string(sandbox.env_path()).unwrap(),
        "STRIPE_SECRET_KEY=sk_live_12345\n"
    );
    assert!(!sandbox.ws.join("zs-policy.json").exists());
}

#[cfg(unix)]
#[test]
fn init_refuses_a_backup_directory_that_others_can_read() {
    use std::os::unix::fs::PermissionsExt;
    let sandbox = Sandbox::with_env("STRIPE_SECRET_KEY=sk_live_12345\n");
    fs::create_dir_all(sandbox.backup_dir()).unwrap();
    fs::set_permissions(sandbox.backup_dir(), fs::Permissions::from_mode(0o755)).unwrap();

    let output = sandbox.init(&[]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("zs: the .env backup directory is not private"),
        "{stderr}"
    );
    assert!(!stderr.contains("sk_live_12345"));
    assert_eq!(
        fs::read_to_string(sandbox.env_path()).unwrap(),
        "STRIPE_SECRET_KEY=sk_live_12345\n"
    );
    assert!(sandbox.backups().is_empty());
}

#[cfg(unix)]
#[test]
fn init_refuses_a_symlinked_backup_directory() {
    let sandbox = Sandbox::with_env("STRIPE_SECRET_KEY=sk_live_12345\n");
    let elsewhere = sandbox.home.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::create_dir(sandbox.home.join(".zs-backups")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, sandbox.backup_dir()).unwrap();

    let output = sandbox.init(&[]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
    assert_eq!(
        fs::read_to_string(sandbox.env_path()).unwrap(),
        "STRIPE_SECRET_KEY=sk_live_12345\n"
    );
}

#[test]
fn test_zs_init_dry_run_leaves_env_intact() {
    let sandbox = Sandbox::with_env("STRIPE_SECRET_KEY=sk_live_12345\n");

    let output = sandbox.init(&["--dry-run"]);

    assert!(
        output.status.success(),
        "zs init --dry-run failed: {:?}",
        output
    );
    assert!(!sandbox.ws.join("zs-policy.json").exists());

    let updated_env = fs::read_to_string(sandbox.env_path()).unwrap();
    assert!(updated_env.contains("sk_live_12345"));
    assert!(!updated_env.contains("placeholder_managed_by_zerosecret"));

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("placeholder_managed_by_zerosecret"));
    assert!(stdout.contains("dry-run"));
    assert!(!stdout.contains("sk_live_12345"));

    assert!(sandbox.backups().is_empty());
}

#[test]
fn test_zs_init_existing_policy_without_force_fails() {
    let sandbox = Sandbox::with_env("STRIPE_SECRET_KEY=sk_live_12345\n");
    let policy_path = sandbox.ws.join("zs-policy.json");
    fs::write(&policy_path, "{}\n").unwrap();

    let output = sandbox.init(&[]);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("zs-policy.json already exists; pass --force to overwrite"));

    let force_output = sandbox.init(&["--force"]);

    assert!(force_output.status.success());
    let policy_content = fs::read_to_string(&policy_path).unwrap();
    assert!(policy_content.contains("api.stripe.com"));
}

#[test]
fn test_zs_init_policy_validates_with_doctor() {
    let env_content = "STRIPE_SECRET_KEY=sk_live_12345\n\
OPENAI_API_KEY=sk-proj-67890\n\
GITHUB_TOKEN=ghp_abcdef\n\
DATABASE_URL=postgres://u:p@db.internal:5432/myapp\n";
    let sandbox = Sandbox::with_env(env_content);

    let output = sandbox.init(&[]);

    assert!(output.status.success());

    let doctor_output = sandbox
        .command()
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

#[test]
fn test_zs_init_rerun_is_refused_and_keeps_the_original_backup() {
    let sandbox =
        Sandbox::with_env("DATABASE_URL=postgres://app:secret@db.prod.example:5432/main\n");

    assert!(sandbox.init(&[]).status.success());
    let policy_before = fs::read_to_string(sandbox.ws.join("zs-policy.json")).unwrap();
    let env_before = fs::read_to_string(sandbox.env_path()).unwrap();

    let rerun = sandbox.init(&["--force"]);
    assert_eq!(rerun.status.code(), Some(1));
    let stderr = String::from_utf8(rerun.stderr).unwrap();
    assert!(stderr.contains("already sanitized"), "{stderr}");

    assert_eq!(
        fs::read_to_string(sandbox.ws.join("zs-policy.json")).unwrap(),
        policy_before
    );
    assert_eq!(fs::read_to_string(sandbox.env_path()).unwrap(), env_before);
    let found = sandbox.backups();
    assert_eq!(found.len(), 1);
    assert!(
        fs::read_to_string(&found[0])
            .unwrap()
            .contains("secret@db.prod.example")
    );
}

#[test]
fn test_zs_init_reports_unbrokered_keys_by_name_only() {
    let sandbox = Sandbox::with_env(
        "STRIPE_SECRET_KEY=sk_live_brokered1\n\
JWT_SECRET=jwt-signing-value-1\n\
STRIPE_PUBLISHABLE_KEY=pk_live_public1\n\
REDIS_URL=redis://:redispass1@cache.example:6379/0\n",
    );

    let output = sandbox.init(&[]);
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

    let env = fs::read_to_string(sandbox.env_path()).unwrap();
    assert!(!env.contains("sk_live_brokered1"));
    assert!(env.contains("JWT_SECRET=jwt-signing-value-1"));
    assert!(env.contains("STRIPE_PUBLISHABLE_KEY=pk_live_public1"));
}

#[test]
fn test_zs_init_malformed_env_stops_without_writing() {
    let original = "STRIPE_SECRET_KEY=sk_live_12345\nthis line has no separator\n";
    let sandbox = Sandbox::with_env(original);

    let output = sandbox.init(&[]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("line 2"), "{stderr}");
    assert!(!stderr.contains("separator"), "{stderr}");
    assert!(!sandbox.ws.join("zs-policy.json").exists());
    assert_eq!(fs::read_to_string(sandbox.env_path()).unwrap(), original);
    assert!(sandbox.backups().is_empty());
}

#[test]
fn test_zs_init_dry_run_ignores_an_existing_policy() {
    let sandbox = Sandbox::with_env("GITHUB_TOKEN=ghp_abc\n");
    fs::write(sandbox.ws.join("zs-policy.json"), "{}\n").unwrap();

    let output = sandbox.init(&["--dry-run"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(sandbox.ws.join("zs-policy.json")).unwrap(),
        "{}\n"
    );
}

#[test]
fn test_zs_init_rejects_listen_port_zero() {
    let sandbox = Sandbox::with_env("DATABASE_URL=postgres://app:pw@db.example:5432/main\n");
    let output = sandbox.init(&["--listen-port-start", "0"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!sandbox.ws.join("zs-policy.json").exists());
}
