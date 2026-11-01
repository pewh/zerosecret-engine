// Error messages are fixed strings: never echo the input, which may carry the secret.
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub(crate) const ERR_AGENT_CMD: &str = "--agent-cmd= is required and must name a program";
pub(crate) const ERR_CREDENTIAL_FILE: &str =
    "--credential-file= is required and must name a readable file";
pub(crate) const ERR_CREDENTIAL_UNREADABLE: &str =
    "the credential file cannot be read as UTF-8 text";
pub(crate) const ERR_CREDENTIAL_EMPTY: &str =
    "the credential file is empty; an absence claim about an empty credential is vacuous";
pub(crate) const ERR_CREDENTIAL_VALUE_REMOVED: &str = "--credential-value= is removed because it places a credential in argv; use \
     --credential-file=<path>";
pub(crate) const ERR_SECRET_PLACEHOLDER: &str = "the {CREDENTIAL} template is removed because it expands a secret into argv; use \
     {CREDENTIAL_FILE}, which expands to a path";
pub(crate) const ERR_UNKNOWN_ARGUMENT: &str = "unknown argument";
pub(crate) const ERR_MALFORMED_ARGUMENT: &str = "every argument must be --name=value";
pub(crate) const ERR_REPEATED_ARGUMENT: &str = "an argument is repeated";

pub(crate) struct VerifyArgs {
    pub(crate) agent_cmd: String,
    pub(crate) child_cmd: String,
    pub(crate) credential_file: PathBuf,
    pub(crate) creds_dir: PathBuf,
    pub(crate) policy_file: PathBuf,
    pub(crate) audit_file: PathBuf,
    pub(crate) exclude: String,
    pub(crate) proxy_addr: Option<String>,
}

fn uses_secret_placeholder(template: &str) -> bool {
    template.contains("{CREDENTIAL}")
}

fn set_once(slot: &mut Option<String>, value: &str) -> Result<(), &'static str> {
    if slot.is_some() {
        return Err(ERR_REPEATED_ARGUMENT);
    }
    *slot = Some(value.to_string());
    Ok(())
}

pub(crate) fn parse<I, S>(args: I) -> Result<VerifyArgs, &'static str>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut agent_cmd = None;
    let mut child_cmd = None;
    let mut credential_file = None;
    let mut creds_dir = None;
    let mut policy_file = None;
    let mut audit_file = None;
    let mut exclude = None;
    let mut proxy_addr = None;

    for arg in args {
        let arg: String = arg.into();
        let Some((key, value)) = arg.split_once('=') else {
            return Err(ERR_MALFORMED_ARGUMENT);
        };
        match key {
            "--agent-cmd" => set_once(&mut agent_cmd, value)?,
            "--child-cmd" => set_once(&mut child_cmd, value)?,
            "--credential-file" => set_once(&mut credential_file, value)?,
            "--creds-dir" => set_once(&mut creds_dir, value)?,
            "--policy-file" => set_once(&mut policy_file, value)?,
            "--audit-file" => set_once(&mut audit_file, value)?,
            "--exclude" => set_once(&mut exclude, value)?,
            "--proxy-addr" => set_once(&mut proxy_addr, value)?,
            "--credential-value" => return Err(ERR_CREDENTIAL_VALUE_REMOVED),
            _ => return Err(ERR_UNKNOWN_ARGUMENT),
        }
    }

    let agent_cmd = agent_cmd
        .filter(|c| !c.trim().is_empty())
        .ok_or(ERR_AGENT_CMD)?;
    let child_cmd = child_cmd.unwrap_or_else(|| "sleep 2".to_string());
    if uses_secret_placeholder(&agent_cmd) || uses_secret_placeholder(&child_cmd) {
        return Err(ERR_SECRET_PLACEHOLDER);
    }

    let credential_file = credential_file
        .filter(|c| !c.is_empty())
        .ok_or(ERR_CREDENTIAL_FILE)?;
    let credential_file = PathBuf::from(credential_file);
    drop(read_credential(&credential_file)?);

    Ok(VerifyArgs {
        agent_cmd,
        child_cmd,
        credential_file,
        creds_dir: PathBuf::from(creds_dir.unwrap_or_default()),
        policy_file: PathBuf::from(policy_file.unwrap_or_default()),
        audit_file: PathBuf::from(audit_file.unwrap_or_default()),
        exclude: exclude.unwrap_or_default(),
        proxy_addr,
    })
}

// Separate from `parse` on purpose: the credential value must never enter `VerifyArgs`.
pub(crate) fn read_credential(path: &Path) -> Result<Zeroizing<String>, &'static str> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| ERR_CREDENTIAL_UNREADABLE)?);
    let text = std::str::from_utf8(&bytes).map_err(|_| ERR_CREDENTIAL_UNREADABLE)?;
    let trimmed = Zeroizing::new(text.trim().to_string());
    if trimmed.is_empty() {
        return Err(ERR_CREDENTIAL_EMPTY);
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const SYNTHETIC: &str = "sk_test_zsv_localonly";

    trait ResultExt {
        fn err_of(self) -> &'static str;
        fn ok_of(self) -> VerifyArgs;
    }

    impl ResultExt for Result<VerifyArgs, &'static str> {
        fn err_of(self) -> &'static str {
            match self {
                Ok(_) => panic!("this argument shape must be rejected"),
                Err(message) => message,
            }
        }

        fn ok_of(self) -> VerifyArgs {
            match self {
                Ok(args) => args,
                Err(message) => panic!("this argument shape must parse: {message}"),
            }
        }
    }

    fn credential_file(dir: &std::path::Path, contents: &str) -> std::path::PathBuf {
        let path = dir.join("cred.txt");
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn minimal(cred: &std::path::Path) -> Vec<String> {
        vec![
            "--agent-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", cred.display()),
        ]
    }

    #[test]
    fn every_accepted_option_is_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let args = vec![
            "--agent-cmd=agent {CREDENTIAL_FILE}".to_string(),
            "--child-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", cred.display()),
            format!("--creds-dir={}", dir.path().display()),
            format!("--policy-file={}", dir.path().join("p.json").display()),
            format!("--audit-file={}", dir.path().join("a.jsonl").display()),
            "--exclude=creds".to_string(),
            "--proxy-addr=127.0.0.1:9999".to_string(),
        ];
        let parsed = parse(args).ok_of();
        assert_eq!(parsed.agent_cmd, "agent {CREDENTIAL_FILE}");
        assert_eq!(parsed.child_cmd, "/usr/bin/true");
        assert_eq!(parsed.credential_file, cred);
        assert_eq!(parsed.creds_dir, dir.path());
        assert_eq!(parsed.policy_file, dir.path().join("p.json"));
        assert_eq!(parsed.audit_file, dir.path().join("a.jsonl"));
        assert_eq!(parsed.exclude, "creds");
        assert_eq!(parsed.proxy_addr.as_deref(), Some("127.0.0.1:9999"));
    }

    #[test]
    fn child_cmd_defaults_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let parsed = parse(minimal(&cred)).ok_of();
        assert_eq!(parsed.child_cmd, "sleep 2");
        assert!(parsed.proxy_addr.is_none());
    }

    #[test]
    fn a_missing_agent_cmd_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let err = parse(vec![format!("--credential-file={}", cred.display())]).err_of();
        assert_eq!(err, ERR_AGENT_CMD);
    }

    #[test]
    fn an_empty_agent_cmd_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let err = parse(vec![
            "--agent-cmd=".to_string(),
            format!("--credential-file={}", cred.display()),
        ])
        .err_of();
        assert_eq!(err, ERR_AGENT_CMD);
    }

    #[test]
    fn a_missing_credential_file_flag_is_rejected() {
        let err = parse(vec!["--agent-cmd=/usr/bin/true".to_string()]).err_of();
        assert_eq!(err, ERR_CREDENTIAL_FILE);
    }

    #[test]
    fn an_empty_credential_file_value_is_rejected() {
        let err = parse(vec![
            "--agent-cmd=/usr/bin/true".to_string(),
            "--credential-file=".to_string(),
        ])
        .err_of();
        assert_eq!(err, ERR_CREDENTIAL_FILE);
    }

    #[test]
    fn an_unreadable_credential_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.txt");
        let err = parse(vec![
            "--agent-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", missing.display()),
        ])
        .err_of();
        assert_eq!(err, ERR_CREDENTIAL_UNREADABLE);
    }

    #[test]
    fn an_empty_credential_file_content_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), "   \n\t ");
        let err = parse(vec![
            "--agent-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", cred.display()),
        ])
        .err_of();
        assert_eq!(err, ERR_CREDENTIAL_EMPTY);
    }

    #[test]
    fn a_non_utf8_credential_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred.bin");
        std::fs::write(&path, [0x66u8, 0xff, 0xfe, 0x00]).unwrap();
        let err = parse(vec![
            "--agent-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", path.display()),
        ])
        .err_of();
        assert_eq!(err, ERR_CREDENTIAL_UNREADABLE);
    }

    #[test]
    fn the_removed_credential_value_flag_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let err = parse(vec![
            "--agent-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", cred.display()),
            format!("--credential-value={SYNTHETIC}"),
        ])
        .err_of();
        assert_eq!(err, ERR_CREDENTIAL_VALUE_REMOVED);
    }

    #[test]
    fn no_rejection_text_echoes_the_supplied_value() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let shapes: Vec<Vec<String>> = vec![
            vec![format!("--credential-value={SYNTHETIC}")],
            vec![format!("--unknown-flag={SYNTHETIC}")],
            vec![format!("--agent-cmd=x {{CREDENTIAL}} {SYNTHETIC}")],
            vec![SYNTHETIC.to_string()],
            vec![
                "--agent-cmd=/usr/bin/true".to_string(),
                format!("--credential-file={}", cred.display()),
                format!("--exclude={SYNTHETIC}"),
                format!("--exclude={SYNTHETIC}"),
            ],
        ];
        for shape in shapes {
            let err = parse(shape.clone()).err_of();
            assert!(
                !err.contains(SYNTHETIC),
                "the rejection text must not echo the input"
            );
        }
    }

    #[test]
    fn an_unknown_flag_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let mut args = minimal(&cred);
        args.push("--not-a-flag=1".to_string());
        assert_eq!(parse(args).err_of(), ERR_UNKNOWN_ARGUMENT);
    }

    #[test]
    fn a_malformed_argument_without_equals_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let mut args = minimal(&cred);
        args.push("--policy-file".to_string());
        assert_eq!(parse(args).err_of(), ERR_MALFORMED_ARGUMENT);
    }

    #[test]
    fn a_bare_positional_argument_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let mut args = minimal(&cred);
        args.push("positional".to_string());
        assert_eq!(parse(args).err_of(), ERR_MALFORMED_ARGUMENT);
    }

    #[test]
    fn a_repeated_flag_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let mut args = minimal(&cred);
        args.push("--child-cmd=/usr/bin/true".to_string());
        args.push("--child-cmd=/usr/bin/false".to_string());
        assert_eq!(parse(args).err_of(), ERR_REPEATED_ARGUMENT);
    }

    #[test]
    fn a_repeated_credential_file_flag_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let mut args = minimal(&cred);
        args.push(format!("--credential-file={}", cred.display()));
        assert_eq!(parse(args).err_of(), ERR_REPEATED_ARGUMENT);
    }

    #[test]
    fn an_agent_template_may_reference_the_credential_file() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let parsed = parse(vec![
            "--agent-cmd=agent --creds-file {CREDENTIAL_FILE}".to_string(),
            format!("--credential-file={}", cred.display()),
        ])
        .ok_of();
        assert!(parsed.agent_cmd.contains("{CREDENTIAL_FILE}"));
    }

    #[test]
    fn an_agent_template_referencing_the_secret_placeholder_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let err = parse(vec![
            "--agent-cmd=agent --credential {CREDENTIAL}".to_string(),
            format!("--credential-file={}", cred.display()),
        ])
        .err_of();
        assert_eq!(err, ERR_SECRET_PLACEHOLDER);
    }

    #[test]
    fn the_file_placeholder_is_not_mistaken_for_the_secret_placeholder() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        assert!(
            parse(vec![
                "--agent-cmd=a {CREDENTIAL_FILE} {CREDENTIAL_FILE}".to_string(),
                format!("--credential-file={}", cred.display()),
            ])
            .is_ok()
        );
    }

    #[test]
    fn a_child_template_referencing_the_secret_placeholder_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let err = parse(vec![
            "--agent-cmd=/usr/bin/true".to_string(),
            "--child-cmd=sh -c 'echo {CREDENTIAL}'".to_string(),
            format!("--credential-file={}", cred.display()),
        ])
        .err_of();
        assert_eq!(err, ERR_SECRET_PLACEHOLDER);
    }

    #[test]
    fn the_parsed_arguments_never_contain_the_credential_value() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let parsed = parse(vec![
            "--agent-cmd=agent {CREDENTIAL_FILE}".to_string(),
            "--child-cmd=/usr/bin/true".to_string(),
            format!("--credential-file={}", cred.display()),
        ])
        .ok_of();
        let rendered = format!(
            "{}{}{}{}{}{}{}{:?}",
            parsed.agent_cmd,
            parsed.child_cmd,
            parsed.credential_file.display(),
            parsed.creds_dir.display(),
            parsed.policy_file.display(),
            parsed.audit_file.display(),
            parsed.exclude,
            parsed.proxy_addr
        );
        assert!(
            !rendered.contains(SYNTHETIC),
            "VerifyArgs holds a path, never the secret"
        );
    }

    #[test]
    fn the_credential_is_read_separately_into_a_zeroizing_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), SYNTHETIC);
        let parsed = parse(minimal(&cred)).ok_of();
        let secret = read_credential(&parsed.credential_file).unwrap();
        assert_eq!(secret.as_str(), SYNTHETIC);
    }

    #[test]
    fn a_trailing_newline_is_not_part_of_the_credential() {
        let dir = tempfile::tempdir().unwrap();
        let cred = credential_file(dir.path(), &format!("{SYNTHETIC}\n"));
        let secret = read_credential(&cred).unwrap();
        assert_eq!(secret.as_str(), SYNTHETIC);
    }
}
