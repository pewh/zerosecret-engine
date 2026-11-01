use crate::cli::VerifyArgs;
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) const ERR_POLICY_REQUIRED: &str = "--policy-file= is required to redirect the agent";
pub(crate) const ERR_POLICY_UNREADABLE: &str = "the policy file cannot be read as JSON; refusing to report on a path that was never \
     exercised";
pub(crate) const ERR_POLICY_NO_ENTRIES: &str = "the policy has no `bindings` or `resources` array to redirect; refusing to report on a \
     path that was never exercised";
pub(crate) const ERR_WORKSPACE_CREATE: &str = "cannot create the temporary run directory";
pub(crate) const ERR_WORKSPACE_WRITE: &str =
    "cannot write the redirected policy into the temporary run directory";
pub(crate) const ERR_WORKSPACE_CLEANUP: &str =
    "cannot remove the temporary run directory; refusing to trust this run";

const ENV_REPORT_NAME: &str = "child-environment.txt";

pub(crate) struct PreparedWorkspace {
    dir: tempfile::TempDir,
    policy_path: PathBuf,
    env_report_path: PathBuf,
}

impl PreparedWorkspace {
    pub(crate) fn prepare(args: &VerifyArgs, upstream_port: u16) -> Result<Self, &'static str> {
        Self::prepare_in(args, upstream_port, &std::env::temp_dir())
    }

    pub(crate) fn prepare_in(
        args: &VerifyArgs,
        upstream_port: u16,
        root: &Path,
    ) -> Result<Self, &'static str> {
        if args.policy_file.as_os_str().is_empty() {
            return Err(ERR_POLICY_REQUIRED);
        }
        // Validate before creating anything, so an invalid policy leaves no directory behind.
        let source =
            std::fs::read_to_string(&args.policy_file).map_err(|_| ERR_POLICY_UNREADABLE)?;
        let mut policy: serde_json::Value =
            serde_json::from_str(&source).map_err(|_| ERR_POLICY_UNREADABLE)?;

        let mut rewritten = 0usize;
        for key in ["bindings", "resources"] {
            if let Some(entries) = policy.get_mut(key).and_then(|r| r.as_array_mut()) {
                for entry in entries {
                    if let Some(entry) = entry.as_object_mut() {
                        entry.insert("upstream_port".into(), json!(upstream_port));
                        entry.insert("upstream_host".into(), json!("127.0.0.1"));
                        rewritten += 1;
                    }
                }
            }
        }
        if rewritten == 0 {
            return Err(ERR_POLICY_NO_ENTRIES);
        }
        let redirected = serde_json::to_string_pretty(&policy).map_err(|_| ERR_WORKSPACE_WRITE)?;

        let dir = tempfile::Builder::new()
            .prefix("zs-verify-")
            .tempdir_in(root)
            .map_err(|_| ERR_WORKSPACE_CREATE)?;
        let policy_path = dir.path().join("zs-policy.json");
        std::fs::write(&policy_path, redirected).map_err(|_| ERR_WORKSPACE_WRITE)?;
        let env_report_path = dir.path().join(ENV_REPORT_NAME);

        Ok(Self {
            dir,
            policy_path,
            env_report_path,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn root(&self) -> &Path {
        self.dir.path()
    }

    pub(crate) fn policy_path(&self) -> &Path {
        &self.policy_path
    }

    pub(crate) fn env_report_path(&self) -> &Path {
        &self.env_report_path
    }

    pub(crate) fn close(self) -> Result<(), &'static str> {
        self.dir.close().map_err(|_| ERR_WORKSPACE_CLEANUP)
    }

    // Substitutes the credential PATH only, never its value, so no secret reaches argv.
    pub(crate) fn expand(&self, template: &str, args: &VerifyArgs, upstream_port: u16) -> String {
        template
            .replace(
                "{CREDENTIAL_FILE}",
                &args.credential_file.display().to_string(),
            )
            .replace("{UPSTREAM_PORT}", &upstream_port.to_string())
            .replace("{CREDS_DIR}", &args.creds_dir.display().to_string())
            .replace("{POLICY_FILE}", &self.policy_path.display().to_string())
            .replace("{AUDIT_FILE}", &args.audit_file.display().to_string())
            .replace("{CHILD}", &args.child_cmd)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::cli;

    const SYNTHETIC: &str = "sk_test_zsv_localonly";
    const PORT: u16 = 45671;

    fn bytes_of(path: &std::path::Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    fn args_for(dir: &std::path::Path, policy: &str) -> cli::VerifyArgs {
        let cred = dir.join("cred.txt");
        std::fs::write(&cred, SYNTHETIC).unwrap();
        let policy_path = dir.join("zs-policy.json");
        std::fs::write(&policy_path, policy).unwrap();
        match cli::parse(vec![
            "--agent-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", cred.display()),
            format!("--policy-file={}", policy_path.display()),
        ]) {
            Ok(args) => args,
            Err(message) => panic!("fixture arguments must parse: {message}"),
        }
    }

    const BINDINGS: &str =
        r#"{"bindings":[{"resource":"r","host":"api.example.com","protocol":"https"}]}"#;

    #[test]
    fn prepare_rewrites_only_a_temporary_policy() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(dir.path(), BINDINGS);
        let before = bytes_of(&args.policy_file);

        let prepared = PreparedWorkspace::prepare(&args, PORT).expect("a bindings policy prepares");

        let after = bytes_of(&args.policy_file);
        assert_eq!(
            before, after,
            "the source policy must be byte-identical after preparation"
        );
        assert_ne!(
            prepared.policy_path(),
            args.policy_file,
            "the prepared policy must be a separate file"
        );

        let rewritten: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(prepared.policy_path()).unwrap())
                .unwrap();
        let binding = &rewritten["bindings"][0];
        assert_eq!(binding["upstream_port"], PORT);
        assert_eq!(binding["upstream_host"], "127.0.0.1");
    }

    #[test]
    fn a_legacy_resources_policy_is_redirected_in_the_copy() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(
            dir.path(),
            r#"{"resources":[{"name":"r","host":"api.example.com","protocol":"https"}]}"#,
        );
        let before = bytes_of(&args.policy_file);

        let prepared = PreparedWorkspace::prepare(&args, PORT).expect("a v0 policy prepares");

        assert_eq!(before, bytes_of(&args.policy_file));
        let rewritten: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(prepared.policy_path()).unwrap())
                .unwrap();
        assert_eq!(rewritten["resources"][0]["upstream_port"], PORT);
        assert_eq!(rewritten["resources"][0]["upstream_host"], "127.0.0.1");
    }

    #[test]
    fn invalid_json_fails_without_agent_start() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(dir.path(), "{ this is not json");
        let before = bytes_of(&args.policy_file);

        let err = match PreparedWorkspace::prepare(&args, PORT) {
            Ok(_) => panic!("invalid JSON must be refused"),
            Err(message) => message,
        };

        assert_eq!(err, ERR_POLICY_UNREADABLE);
        assert_eq!(
            before,
            bytes_of(&args.policy_file),
            "a failed preparation must leave the source policy byte-identical"
        );
    }

    #[test]
    fn missing_bindings_fails() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(dir.path(), r#"{"signing_keys":[],"grants":[]}"#);
        let before = bytes_of(&args.policy_file);

        let err = match PreparedWorkspace::prepare(&args, PORT) {
            Ok(_) => panic!("a policy with no redirectable entry must be refused"),
            Err(message) => message,
        };

        assert_eq!(err, ERR_POLICY_NO_ENTRIES);
        assert_eq!(before, bytes_of(&args.policy_file));
    }

    #[test]
    fn a_missing_policy_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_for(dir.path(), BINDINGS);
        args.policy_file = dir.path().join("absent.json");
        let err = match PreparedWorkspace::prepare(&args, PORT) {
            Ok(_) => panic!("a missing policy must be refused"),
            Err(message) => message,
        };
        assert_eq!(err, ERR_POLICY_UNREADABLE);
    }

    #[test]
    fn an_absent_policy_argument_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_for(dir.path(), BINDINGS);
        args.policy_file = std::path::PathBuf::new();
        let err = match PreparedWorkspace::prepare(&args, PORT) {
            Ok(_) => panic!("preparation without a policy must be refused"),
            Err(message) => message,
        };
        assert_eq!(err, ERR_POLICY_REQUIRED);
    }

    #[test]
    fn write_failure_fails() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(dir.path(), BINDINGS);
        let before = bytes_of(&args.policy_file);

        let err = match PreparedWorkspace::prepare_in(&args, PORT, std::path::Path::new("/")) {
            Ok(_) => panic!("an unwritable workspace root must be refused"),
            Err(message) => message,
        };

        assert_eq!(err, ERR_WORKSPACE_CREATE);
        assert_eq!(
            before,
            bytes_of(&args.policy_file),
            "a write failure must leave the source policy byte-identical"
        );
    }

    #[test]
    fn each_workspace_has_a_unique_environment_report() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(dir.path(), BINDINGS);

        let first = PreparedWorkspace::prepare(&args, PORT).unwrap();
        let second = PreparedWorkspace::prepare(&args, PORT).unwrap();

        assert_ne!(
            first.env_report_path(),
            second.env_report_path(),
            "two runs must not share an environment-report path"
        );
        assert_ne!(first.policy_path(), second.policy_path());
        for prepared in [&first, &second] {
            assert!(
                prepared
                    .env_report_path()
                    .file_name()
                    .is_some_and(|n| n == "child-environment.txt"),
                "the report keeps its documented name inside the run directory"
            );
            assert!(
                !prepared.env_report_path().exists(),
                "the report must be absent before the child runs"
            );
            assert!(
                prepared.env_report_path().starts_with(prepared.root()),
                "the report must live inside the run directory"
            );
        }
    }

    #[test]
    fn the_workspace_is_removed_when_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(dir.path(), BINDINGS);
        let root = {
            let prepared = PreparedWorkspace::prepare(&args, PORT).unwrap();
            assert!(prepared.policy_path().starts_with(prepared.root()));
            assert!(
                prepared
                    .root()
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("zs-verify-"))
            );
            prepared.root().to_path_buf()
        };
        assert!(!root.exists(), "the run directory must not outlive the run");
    }

    #[test]
    fn closing_the_workspace_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(dir.path(), BINDINGS);
        let prepared = PreparedWorkspace::prepare(&args, PORT).unwrap();
        let root = prepared.root().to_path_buf();
        std::fs::write(prepared.env_report_path(), "PATH=/bin\n").unwrap();

        assert!(prepared.close().is_ok());
        assert!(!root.exists(), "a closed run directory must be gone");
    }

    #[cfg(unix)]
    #[test]
    fn a_workspace_that_cannot_be_removed_fails_to_close() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let args = args_for(dir.path(), BINDINGS);
        let parent = dir.path().join("locked");
        std::fs::create_dir(&parent).unwrap();
        let prepared = PreparedWorkspace::prepare_in(&args, PORT, &parent).unwrap();
        let root = prepared.root().to_path_buf();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();

        let closed = prepared.close();

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(closed.err(), Some(ERR_WORKSPACE_CLEANUP));
        assert!(root.exists(), "the failure is real: the directory survived");
    }

    #[test]
    fn the_credential_file_placeholder_expands_to_a_path_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut args = args_for(dir.path(), BINDINGS);
        args.agent_cmd = "agent --creds-file {CREDENTIAL_FILE} --policy {POLICY_FILE}".to_string();
        let prepared = PreparedWorkspace::prepare(&args, PORT).unwrap();

        let expanded = prepared.expand(&args.agent_cmd, &args, PORT);

        assert!(expanded.contains(&args.credential_file.display().to_string()));
        assert!(expanded.contains(&prepared.policy_path().display().to_string()));
        assert!(
            !expanded.contains(SYNTHETIC),
            "the expanded command must never contain the credential value"
        );
        assert!(!expanded.contains("{CREDENTIAL_FILE}"));
        assert!(!expanded.contains("{POLICY_FILE}"));
    }
}
