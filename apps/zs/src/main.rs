macro_rules! stdout_line {
    ($($arg:tt)*) => {{
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

macro_rules! stderr_line {
    ($($arg:tt)*) => {{
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

mod init;
mod instructions;
mod login;
mod run;
mod schema;

use std::io::Write;
use std::path::PathBuf;

use zs::AgentFile;
use zs_identity::Subject;

fn default_subject() -> Result<Subject, String> {
    let user = std::env::var("USER").unwrap_or_else(|_| "local".into());
    if let Ok(subject) = Subject::new(user) {
        return Ok(subject);
    }
    Subject::new("local").map_err(|e| format!("cannot construct a default subject: {e}"))
}

#[derive(Default)]
struct Explicit {
    credentials_dir: bool,
    ca_dir: bool,
    audit: bool,
}

struct Args {
    command: String,
    policy: PathBuf,
    credentials_dir: PathBuf,
    audit: PathBuf,
    ca_dir: PathBuf,
    listen: String,
    workload: String,
    rest: Vec<String>,
    oidc_authorize: Option<String>,
    oidc_token: Option<String>,
    control: Option<String>,
    control_ca: Option<PathBuf>,
    explicit: Explicit,
    credentials_dir_from_policy: bool,
    enrollment_token: Option<String>,
    enroll_url: Option<String>,
    device_name: String,
    confirmed: bool,
    log: Option<PathBuf>,
    json: bool,
    init_opts: init::InitOptions,
}

const USAGE: &str = "usage: zs <login|logout|status|doctor|run|resources|ca|ca-sha256|schema|agent-instructions|init|version> [options]\n\
    \n\
    Control plane (omit for offline development against local config):\n\
    \x20 --control <url>             base URL of the control plane\n\
    \x20 --control-ca <path>         PEM file with the control plane's CA (default: <ca-dir>/control-ca.crt)\n\
    \x20 --enrollment-token <token>  one-time token from an operator, for `run`\n\
    \x20 --enroll-url <url>          where /wire/enroll is served (default: --control)\n\
    \x20 --device-name <name>        name recorded at enrolment (default: workstation)\n\
    \n\
    Diagnostics (for `run`):\n\
    \x20 --log <path>                write the diagnostic log here (default: .zs-log beside the audit directory)";

const CA_USAGE: &str = "usage: zs ca retire --ca-dir <dir> --yes\n\
    \n\
    Deletes the CA private key of <dir> from native secure storage, then its ca.crt and\n\
    .ca-storage-id. Every client that trusts that ca.crt stops trusting the agent.";

const CA_SHA256_USAGE: &str = "usage: zs ca-sha256 <file>\n\
    \n\
    Prints the SHA-256 of the certificates in a PEM CA bundle, the value an admin signs as\n\
    ca-sha256:<hex>. Comments, line endings and keys in the file do not change it.";

const SIMPLE_COMMANDS: &[&str] = &["login", "logout", "status", "resources"];

const NO_ARGUMENT_COMMANDS: &[&str] = &["schema", "agent-instructions", "version"];

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let command = match it.next().ok_or(USAGE)?.as_str() {
        "--version" | "-V" => "version".to_string(),
        name => name.to_string(),
    };
    let mut args = Args {
        command,
        policy: PathBuf::from("zs-policy.json"),
        credentials_dir: PathBuf::from(".zs-credentials"),
        audit: PathBuf::from(".zs-audit/audit.jsonl"),
        ca_dir: PathBuf::from(".zs-ca"),
        listen: "127.0.0.1:0".into(),
        workload: "default".into(),
        rest: Vec::new(),
        oidc_authorize: None,
        oidc_token: None,
        control: None,
        control_ca: None,
        explicit: Explicit::default(),
        credentials_dir_from_policy: false,
        enrollment_token: None,
        enroll_url: None,
        device_name: "workstation".into(),
        confirmed: false,
        log: None,
        json: false,
        init_opts: init::InitOptions::default(),
    };
    if args.command == "init" {
        while let Some(a) = it.next() {
            match a.as_str() {
                "--dry-run" => args.init_opts.dry_run = true,
                "--force" => args.init_opts.force = true,
                "--from-env" => {
                    args.init_opts.from_env =
                        Some(PathBuf::from(it.next().ok_or("--from-env needs a value")?));
                }
                "--control" => {
                    args.init_opts.control = Some(it.next().ok_or("--control needs a value")?);
                }
                "--listen-port-start" => {
                    let val = it.next().ok_or("--listen-port-start needs a value")?;
                    args.init_opts.listen_port_start = val
                        .parse::<u16>()
                        .ok()
                        .filter(|port| *port != 0)
                        .ok_or("--listen-port-start must be 1 to 65535")?;
                }
                other => return Err(format!("unknown init argument: {other}")),
            }
        }
        return Ok(args);
    }
    if NO_ARGUMENT_COMMANDS.contains(&args.command.as_str()) {
        if let Some(other) = it.next() {
            return Err(format!("unknown {} argument: {other}", args.command));
        }
        return Ok(args);
    }
    if args.command == "ca" {
        if it.next().as_deref() != Some("retire") {
            return Err(CA_USAGE.into());
        }
        let mut ca_dir = None;
        while let Some(a) = it.next() {
            match a.as_str() {
                "--ca-dir" => {
                    ca_dir = Some(PathBuf::from(it.next().ok_or("--ca-dir needs a value")?))
                }
                "--yes" => args.confirmed = true,
                other => return Err(format!("unknown ca retire argument: {other}\n{CA_USAGE}")),
            }
        }
        // No default: retiring the wrong directory destroys a CA that clients trust.
        args.ca_dir = ca_dir.ok_or_else(|| format!("ca retire needs --ca-dir\n{CA_USAGE}"))?;
        return Ok(args);
    }
    if args.command == "ca-sha256" {
        let (Some(file), None) = (it.next(), it.next()) else {
            return Err(CA_SHA256_USAGE.into());
        };
        args.rest = vec![file];
        return Ok(args);
    }
    if args.command == "doctor" {
        while let Some(a) = it.next() {
            match a.as_str() {
                "--policy" => {
                    args.policy = PathBuf::from(it.next().ok_or("--policy needs a value")?)
                }
                "--audit" => args.audit = PathBuf::from(it.next().ok_or("--audit needs a value")?),
                "--ca-dir" => {
                    args.ca_dir = PathBuf::from(it.next().ok_or("--ca-dir needs a value")?)
                }
                "--json" => args.json = true,
                other => return Err(format!("unknown doctor argument: {other}")),
            }
        }
        return Ok(args);
    }
    if SIMPLE_COMMANDS.contains(&args.command.as_str()) {
        while let Some(a) = it.next() {
            match a.as_str() {
                "--policy" => {
                    args.policy = PathBuf::from(it.next().ok_or("--policy needs a value")?)
                }
                "--credentials-dir" => {
                    args.credentials_dir =
                        PathBuf::from(it.next().ok_or("--credentials-dir needs a value")?);
                    args.explicit.credentials_dir = true;
                }
                "--control" => args.control = Some(it.next().ok_or("--control needs a value")?),
                "--control-ca" => {
                    args.control_ca = Some(PathBuf::from(
                        it.next().ok_or("--control-ca needs a value")?,
                    ))
                }
                "--ca-dir" => {
                    args.ca_dir = PathBuf::from(it.next().ok_or("--ca-dir needs a value")?);
                    args.explicit.ca_dir = true;
                }
                "--enrollment-token" => {
                    args.enrollment_token =
                        Some(it.next().ok_or("--enrollment-token needs a value")?)
                }
                "--enroll-url" => {
                    args.enroll_url = Some(it.next().ok_or("--enroll-url needs a value")?)
                }
                "--device-name" => {
                    args.device_name = it.next().ok_or("--device-name needs a value")?
                }
                "--json" if args.command == "status" => args.json = true,
                other => return Err(format!("unknown {} argument: {other}", args.command)),
            }
        }
        return Ok(args);
    }
    if args.command != "run" {
        return Err(format!("unknown command: {}\n{USAGE}", args.command));
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "--as" => args.workload = it.next().ok_or("--as needs a value")?,
            "--policy" => args.policy = PathBuf::from(it.next().ok_or("--policy needs a value")?),
            "--credentials-dir" => {
                args.credentials_dir =
                    PathBuf::from(it.next().ok_or("--credentials-dir needs a value")?);
                args.explicit.credentials_dir = true;
            }
            "--audit" => {
                args.audit = PathBuf::from(it.next().ok_or("--audit needs a value")?);
                args.explicit.audit = true;
            }
            "--ca-dir" => {
                args.ca_dir = PathBuf::from(it.next().ok_or("--ca-dir needs a value")?);
                args.explicit.ca_dir = true;
            }
            "--control-ca" => {
                args.control_ca = Some(PathBuf::from(
                    it.next().ok_or("--control-ca needs a value")?,
                ))
            }
            "--listen" => args.listen = it.next().ok_or("--listen needs a value")?,
            "--log" => args.log = Some(PathBuf::from(it.next().ok_or("--log needs a value")?)),
            "--oidc-authorize" => {
                args.oidc_authorize = Some(it.next().ok_or("--oidc-authorize needs a value")?)
            }
            "--oidc-token" => {
                args.oidc_token = Some(it.next().ok_or("--oidc-token needs a value")?)
            }
            "--control" => args.control = Some(it.next().ok_or("--control needs a value")?),
            "--enrollment-token" => {
                args.enrollment_token = Some(it.next().ok_or("--enrollment-token needs a value")?)
            }
            "--enroll-url" => {
                args.enroll_url = Some(it.next().ok_or("--enroll-url needs a value")?)
            }
            "--device-name" => args.device_name = it.next().ok_or("--device-name needs a value")?,
            "--" => {
                args.rest = it.collect();
                break;
            }
            other => {
                args.rest.push(other.to_string());
                args.rest.extend(it);
                break;
            }
        }
    }
    Ok(args)
}

fn main() {
    std::process::exit(real_main());
}

fn apply_run_settings(args: &mut Args) -> Result<(), String> {
    let Some(settings) = zs::load_run_settings(&args.policy).map_err(|e| e.to_string())? else {
        return Ok(());
    };
    let policy_dir = match args.policy.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from);
    let resolve = |value: &std::path::Path| -> Result<PathBuf, String> {
        match &home {
            Some(home) => Ok(zs::resolve_setting_path(value, &policy_dir, home)),
            None if value.starts_with("~") => Err(format!(
                "run setting {}: HOME is not set, so ~ cannot expand",
                value.display()
            )),
            None => Ok(zs::resolve_setting_path(
                value,
                &policy_dir,
                std::path::Path::new(""),
            )),
        }
    };
    if args.control.is_none() {
        args.control = settings.control;
    }
    if args.control_ca.is_none()
        && let Some(path) = settings.control_ca.as_deref()
    {
        args.control_ca = Some(resolve(path)?);
    }
    if !args.explicit.credentials_dir
        && let Some(path) = settings.credentials_dir.as_deref()
    {
        let home = home.as_deref().unwrap_or(std::path::Path::new(""));
        args.credentials_dir =
            zs::checked_credentials_dir(path, &policy_dir, home).map_err(|e| e.to_string())?;
        args.credentials_dir_from_policy = true;
    }
    if !args.explicit.ca_dir
        && let Some(path) = settings.ca_dir.as_deref()
    {
        args.ca_dir = resolve(path)?;
    }
    if !args.explicit.audit
        && let Some(path) = settings.audit.as_deref()
    {
        args.audit = resolve(path)?;
    }
    Ok(())
}

fn real_main() -> i32 {
    let mut args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            stderr_line!("zs: {e}");
            return 2;
        }
    };
    if matches!(
        args.command.as_str(),
        "run" | "login" | "status" | "resources"
    ) && let Err(e) = apply_run_settings(&mut args)
    {
        stderr_line!("zs: {e}");
        return 1;
    }
    match args.command.as_str() {
        "doctor" => doctor(&args),
        "run" => run::run(&args),
        "login" => login(&args),
        "logout" => login::logout(),
        "status" => status(&args),
        "resources" => resources(&args),
        "ca" => ca_retire(&args),
        "ca-sha256" => ca_sha256(&args),
        "schema" => schema::print_schema(),
        "agent-instructions" => instructions::print_instructions(),
        "version" => version(),
        "init" => init::run_init(&args.init_opts),
        _ => {
            stderr_line!("zs: unknown command: {}\n{USAGE}", args.command);
            2
        }
    }
}

fn version() -> i32 {
    stdout_line!("{}", version_line());
    0
}

fn version_line() -> String {
    format!(
        "zs {} ({}, built {}, {})",
        env!("ZS_BUILD_VERSION"),
        env!("ZS_BUILD_COMMIT"),
        env!("ZS_BUILD_TIME"),
        env!("ZS_BUILD_TARGET")
    )
}

fn zs_home() -> PathBuf {
    std::env::var("ZS_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
        })
}

fn session_path() -> PathBuf {
    zs_home().join(".zs-session")
}

fn current_session() -> Option<String> {
    std::fs::read_to_string(session_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn login(args: &Args) -> i32 {
    match args.control.as_deref() {
        Some(control) => login::login_via_control_plane(args, control),
        None => login_locally(),
    }
}

fn store_session(subject: &str) -> Result<(), String> {
    let path = session_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, subject).map_err(|e| format!("cannot write session: {e}"))
}

fn login_locally() -> i32 {
    let subject = match default_subject() {
        Ok(subject) => subject,
        Err(e) => {
            eprintln!("zs: {e}");
            return 1;
        }
    };
    if let Err(e) = store_session(subject.as_str()) {
        eprintln!("zs: {e}");
        return 1;
    }
    println!(
        "signed in as {} (local session, no identity provider — pass --control <url> for SSO)",
        subject.as_str()
    );
    0
}

fn status(args: &Args) -> i32 {
    let session = current_session();
    let (bindings, grants) = match AgentFile::load(&args.policy) {
        Ok(file) => (file.bindings.len(), file.grants.len()),
        Err(_) => (0, 0),
    };
    if args.json {
        return status_json(args, session, bindings, grants);
    }
    let Some(subject) = session else {
        stdout_line!("not signed in");
        return 1;
    };
    stdout_line!("subject: {subject}");
    stdout_line!("workload: {}", args.workload);
    match args.control.as_deref() {
        Some(control) => stdout_line!("control plane: {control} (configured, not probed)"),
        None => stdout_line!("control plane: none configured (offline, local config only)"),
    }
    match login::device_line(args.control.as_deref()) {
        Ok(line) => stdout_line!("{line}"),
        Err(line) => {
            stderr_line!("{line}");
            return 1;
        }
    }
    stdout_line!("resources: {bindings}");
    stdout_line!("cached grants: {grants}");
    0
}

fn status_json(args: &Args, session: Option<String>, bindings: usize, grants: usize) -> i32 {
    let device = login::device_enrolment(args.control.as_deref());
    let enrolment = device.as_ref().ok().and_then(Option::as_ref);
    let val = serde_json::json!({
        "signed_in": session.is_some(),
        "subject": session,
        "enrolled": enrolment.is_some(),
        "device_id": enrolment.map(|e| e.device_id.as_str()),
        "control_url": args.control.as_deref().map(zs::device::normalise),
        "resources_count": bindings,
        "cached_grants_count": grants,
        "error": device.as_ref().err(),
    });
    stdout_line!("{val}");
    if session.is_some() && device.is_ok() {
        0
    } else {
        1
    }
}

fn ca_sha256(args: &Args) -> i32 {
    let Some(file) = args.rest.first() else {
        return 2;
    };
    match zs_upstream::load_ca(std::path::Path::new(file)) {
        Ok(loaded) => {
            let hex: String = loaded.sha256.iter().map(|b| format!("{b:02x}")).collect();
            stdout_line!("{hex}");
            0
        }
        Err(_) => {
            stderr_line!("zs: {file}: not a PEM certificate bundle");
            1
        }
    }
}

fn resources(args: &Args) -> i32 {
    let file = match AgentFile::load(&args.policy) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("zs: cannot read {}: {e}", args.policy.display());
            return 1;
        }
    };
    let control_policy = run::control_policy(args);
    for binding in &file.bindings {
        let mode = file
            .grants
            .iter()
            .find(|g| g.grant.resource == binding.resource)
            .map(|g| g.grant.materialization.clone());
        let materialization = match &mode {
            Some(zs_policy::Materialization::Retrieve) => "retrieve",
            Some(zs_policy::Materialization::Exchange) => "exchange",
            None => "unknown (no cached grant)",
        };
        stdout_line!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            binding.resource,
            binding.host,
            binding.protocol,
            interception_layer(binding),
            materialization,
            strict_label(binding, mode.is_some()),
        );
        stdout_line!(
            "{}",
            connection_line(
                args.control.is_some(),
                control_policy.as_ref(),
                &binding.resource
            )
        );
    }
    0
}

fn connection_line(controlled: bool, policy: Option<&zs_policy::Policy>, resource: &str) -> String {
    if !controlled {
        return "  connection: from the policy file (local mode)".to_string();
    }
    let Some(found) = policy.and_then(|p| p.resources.iter().find(|r| r.name == resource)) else {
        return "  connection: signed at run time".to_string();
    };
    let summary: String = found
        .connection
        .summary()
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let shown = if summary.is_empty() {
        "default"
    } else {
        summary.as_str()
    };
    format!("  connection (control plane, display only): {shown}")
}

// Enumerated, not negated: `protocol` is free-form, so an `else` would mislabel typos.
fn interception_layer(binding: &zs::ResourceBinding) -> &'static str {
    match zs_protocol::InterceptedProtocol::parse(&binding.protocol) {
        Some(protocol) if protocol.layer() == zs_protocol::Layer::L7 => "L1",
        Some(_) => "L3",
        None => "-",
    }
}

// No grant means `unknown`, never `strict`.
fn strict_label(binding: &zs::ResourceBinding, granted: bool) -> &'static str {
    match (interception_layer(binding), granted) {
        ("-", _) => "not-strict",
        (_, true) => "strict",
        (_, false) => "strict-unknown",
    }
}

fn ca_retire(args: &Args) -> i32 {
    let dir = args.ca_dir.display();
    if !args.confirmed {
        let _ = writeln!(
            std::io::stderr(),
            "zs: ca retire deletes the CA private key of {dir} permanently, and every client \
             that trusts its ca.crt stops trusting the agent. Rerun with --yes to retire it"
        );
        return 2;
    }
    match zs_mitm::LocalCa::retire_secure(&args.ca_dir) {
        Ok(()) => {
            let _ = std::fs::remove_file(args.ca_dir.join("ca-bundle.crt"));
            let _ = writeln!(
                std::io::stdout(),
                "zs: retired CA directory {dir}: native record, ca.crt and .ca-storage-id removed"
            );
            0
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "zs: local ca: {error}");
            1
        }
    }
}

fn doctor(args: &Args) -> i32 {
    let policy_res = AgentFile::load(&args.policy);
    if args.json {
        return doctor_json(args, &policy_res);
    }
    match policy_res {
        Ok(file) => {
            stdout_line!(
                "zs: config {} with {} resource bindings",
                args.policy.display(),
                file.bindings.len()
            );
            for b in &file.bindings {
                stdout_line!("zs: resource {} -> host {}", b.resource, b.host);
            }
            stdout_line!(
                "zs: {} pinned signing key(s), {} cached grant(s)",
                file.signing_keys.len(),
                file.grants.len()
            );
        }
        Err(e) => stdout_line!("zs: config unavailable: {e}"),
    }
    stdout_line!("zs: audit path {}", args.audit.display());
    stdout_line!("zs: ca dir {}", args.ca_dir.display());
    stdout_line!(
        "zs: ca certificate present: {}",
        args.ca_dir.join("ca.crt").exists()
    );
    0
}

fn doctor_json(args: &Args, policy_res: &Result<AgentFile, zs::ConfigError>) -> i32 {
    let ca_present = args.ca_dir.join("ca.crt").exists();
    let mut diagnostics = Vec::new();
    if let Err(e) = policy_res {
        diagnostics.push(serde_json::json!({
            "level": "error",
            "check": "policy",
            "message": e.to_string(),
        }));
    }
    if !ca_present {
        diagnostics.push(serde_json::json!({
            "level": "info",
            "check": "ca",
            "message": format!("no ca.crt in {}", args.ca_dir.display()),
        }));
    }
    let file = policy_res.as_ref().ok();
    let val = serde_json::json!({
        "status": if file.is_some() { "ok" } else { "error" },
        "policy_file": args.policy.to_string_lossy(),
        "policy_valid": file.is_some(),
        "bindings_count": file.map_or(0, |f| f.bindings.len()),
        "signing_keys_count": file.map_or(0, |f| f.signing_keys.len()),
        "cached_grants_count": file.map_or(0, |f| f.grants.len()),
        "ca_dir": args.ca_dir.to_string_lossy(),
        "ca_certificate_present": ca_present,
        "audit_path": args.audit.to_string_lossy(),
        "diagnostics": diagnostics,
    });
    stdout_line!("{val}");
    if file.is_some() { 0 } else { 1 }
}

#[cfg(test)]
mod version_tests {
    #[test]
    fn the_version_line_names_the_build() {
        let line = super::version_line();
        assert!(line.starts_with("zs "), "{line}");
        assert!(line.contains(", built "), "{line}");
        assert!(line.ends_with(')'), "{line}");
    }
}
