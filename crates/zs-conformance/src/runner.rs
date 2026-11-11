use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::adapter::{self, AdapterError, Handle, SetupRequest};
use crate::config::{Config, Fixtures, Protocol};
use crate::fake_upstream::{FakeProbe, FakeUpstream};
use crate::provision::{self, ProvisionError, Roles};
use crate::report::{CaseReport, Outcome, Report};
use crate::wrongca;

pub const SIGV4_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
pub const SIGV4_ACCESS_KEY_ID: &str = "AKIDCONFORMANCE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    Positive,
    WrongPassword,
    WrongCa,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Upstream {
    Primary,
    Tls,
}

#[derive(Clone, Copy)]
pub struct Case {
    pub id: &'static str,
    pub protocol: Protocol,
    pub upstream: Upstream,
    pub serial_group: Option<&'static str>,
    pub credential: Option<&'static str>,
    pub run: fn(&Context) -> Result<String, String>,
}

pub struct Context {
    pub endpoint: SocketAddr,
    pub env: BTreeMap<String, String>,
    pub roles: Roles,
    pub variant: Variant,
    pub fixtures: Fixtures,
    pub http: Option<FakeProbe>,
    pub adapter: PathBuf,
    pub handle: Handle,
}

pub fn run_case(case: &Case, config: &Config) -> CaseReport {
    if !config.implementation.capabilities.contains(&case.protocol) {
        return skipped(
            case,
            format!(
                "the implementation does not declare the {} capability",
                case.protocol
            ),
        );
    }
    if case.protocol == Protocol::Http {
        return execute_http(case, config);
    }
    let Some(fixture) = fixture_for(case, config) else {
        return skipped(case, missing_fixture(case));
    };
    match provision::provision(case.protocol, fixture) {
        Ok(roles) => execute(case, config, &roles, fixture),
        Err(ProvisionError::FixtureUnreachable { fixture, .. }) => {
            skipped(case, unreachable_fixture(case, fixture))
        }
        Err(error) => {
            let reason = format!("provisioning failed: {error}");
            CaseReport {
                id: case.id.to_string(),
                outcome: Outcome::Fail(reason.clone()),
                controls: Vec::new(),
                evidence: reason,
            }
        }
    }
}

pub fn run_cases(cases: &[Case], config: &Config) -> Report {
    let mut report = Report::default();
    for case in cases {
        report.cases.push(run_case(case, config));
    }
    report
}

pub fn run_all(config: &Config, _allow_skips: bool) -> Report {
    run_cases(&crate::registry(), config)
}

pub fn report_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/conformance/report.json")
}

fn execute(case: &Case, config: &Config, roles: &Roles, fixture: SocketAddr) -> CaseReport {
    let positive = run_variant(case, config, roles, fixture, Variant::Positive, None);
    let wrong_password = run_variant(case, config, roles, fixture, Variant::WrongPassword, None);
    let mut controls = vec![("wrongpass", wrong_password)];
    if has_tls_identity(case) {
        let wrong_ca = match wrong_ca_fixture(case, config, fixture) {
            Ok(target) => run_variant(case, config, roles, target, Variant::WrongCa, None),
            Err(outcome) => outcome,
        };
        controls.push(("wrongca", wrong_ca));
    }
    let mut secrets = vec![roles.password.clone()];
    if let Some(credential) = case.credential {
        secrets.push(credential.to_string());
    }
    assemble(case, positive, controls, &secrets)
}

fn has_tls_identity(case: &Case) -> bool {
    case.protocol != Protocol::Redis || case.upstream == Upstream::Tls
}

fn execute_http(case: &Case, config: &Config) -> CaseReport {
    let roles = Roles {
        user: "conformance".to_string(),
        password: SIGV4_SECRET.to_string(),
        database: String::new(),
    };
    let positive = run_http_variant(case, config, &roles, Variant::Positive);
    let wrong_password = run_http_variant(case, config, &roles, Variant::WrongPassword);
    assemble(
        case,
        positive,
        vec![("wrongpass", wrong_password)],
        &[SIGV4_SECRET.to_string()],
    )
}

fn assemble(
    case: &Case,
    positive: (Outcome, String),
    controls: Vec<(&str, (Outcome, String))>,
    secrets: &[String],
) -> CaseReport {
    let mut report = CaseReport {
        id: case.id.to_string(),
        outcome: positive.0,
        controls: Vec::new(),
        evidence: positive.1,
    };
    for (suffix, (outcome, evidence)) in controls {
        let name = format!("{}-{suffix}", case.id);
        match &outcome {
            Outcome::Pass => {
                report
                    .evidence
                    .push_str(&format!("; {name} refused: {}", brief(&evidence)));
            }
            Outcome::Fail(reason) => {
                if report.outcome == Outcome::Pass {
                    report.outcome = Outcome::Fail(format!("{name} failed: {reason}"));
                }
                report.evidence.push_str(&format!("; {name}: {reason}"));
            }
            Outcome::Skipped(reason) => {
                report
                    .evidence
                    .push_str(&format!("; {name} skipped: {reason}"));
            }
        }
        report.controls.push((name, outcome));
    }
    report.redact(secrets);
    report
}

fn brief(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > 240 {
        line.chars().take(240).collect::<String>() + "..."
    } else {
        line
    }
}

fn wrong_ca_fixture(
    case: &Case,
    config: &Config,
    fixture: SocketAddr,
) -> Result<SocketAddr, (Outcome, String)> {
    if case.protocol != Protocol::Postgres || case.upstream == Upstream::Tls {
        return Ok(fixture);
    }
    let tls_case = Case {
        upstream: Upstream::Tls,
        ..*case
    };
    let Some(target) = config.fixtures.postgres_tls else {
        let reason = format!(
            "the wrong-CA control needs a TLS-serving upstream: {}",
            missing_fixture(&tls_case)
        );
        return Err((Outcome::Skipped(reason.clone()), reason));
    };
    match provision::provision(Protocol::Postgres, target) {
        Ok(_) => Ok(target),
        Err(ProvisionError::FixtureUnreachable { fixture, .. }) => {
            let reason = format!(
                "the wrong-CA control needs a TLS-serving upstream: {}",
                unreachable_fixture(&tls_case, fixture)
            );
            Err((Outcome::Skipped(reason.clone()), reason))
        }
        Err(error) => {
            let reason = format!("provisioning failed: {error}");
            Err((Outcome::Fail(reason.clone()), reason))
        }
    }
}

fn run_http_variant(
    case: &Case,
    config: &Config,
    roles: &Roles,
    variant: Variant,
) -> (Outcome, String) {
    let fake = FakeUpstream::spawn(roles.password.clone());
    let outcome = run_variant(case, config, roles, fake.addr, variant, Some(&fake));
    fake.shutdown();
    outcome
}

fn run_variant(
    case: &Case,
    config: &Config,
    roles: &Roles,
    fixture: SocketAddr,
    variant: Variant,
    fake: Option<&FakeUpstream>,
) -> (Outcome, String) {
    let credential = match variant {
        Variant::WrongPassword => "conformance-wrong-password".to_string(),
        _ => case.credential.unwrap_or(&roles.password).to_string(),
    };
    let credentials = match CredentialFile::write(&credential) {
        Ok(credentials) => credentials,
        Err(reason) => return (Outcome::Fail(reason.clone()), reason),
    };
    let tls = match tls_setup(case, variant) {
        Ok(tls) => tls,
        Err(reason) => return (Outcome::Fail(reason.clone()), reason),
    };
    let (upstream_ca, upstream_tls) = match tls {
        Some(tls) => (tls.ca, Some(tls.mode)),
        None => (None, None),
    };
    let auth = match case.protocol {
        Protocol::Http => (
            Some("aws-sigv4".to_string()),
            Some(SIGV4_ACCESS_KEY_ID.to_string()),
        ),
        _ => (None, None),
    };
    let request = SetupRequest {
        protocol: case.protocol,
        case: case.id.to_string(),
        upstream: fixture,
        credential_file: credentials.path().to_path_buf(),
        upstream_ca,
        upstream_tls,
        operations: operations_for(case.protocol),
        auth_scheme: auth.0,
        access_key_id: auth.1,
    };
    let secrets = [roles.password.clone(), credential.clone()];
    let handle = match adapter::setup(
        &config.implementation.adapter,
        &request,
        &secrets,
        adapter::SETUP_TIMEOUT,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            let reason = setup_failure(&error);
            return match variant {
                Variant::Positive => (Outcome::Fail(reason.clone()), reason),
                _ => (
                    Outcome::Fail(format!(
                        "the control failed at adapter setup, before a client connected: {reason}"
                    )),
                    reason,
                ),
            };
        }
    };
    let context = Context {
        endpoint: handle.endpoint,
        env: handle.env.clone(),
        roles: roles.clone(),
        variant,
        fixtures: config.fixtures.clone(),
        http: fake.map(FakeUpstream::probe),
        adapter: config.implementation.adapter.clone(),
        handle: handle.clone(),
    };
    let outcome = (case.run)(&context);
    let teardown = adapter::teardown(&config.implementation.adapter, &handle);
    let (status, mut evidence) = match (variant, outcome) {
        (Variant::Positive, Ok(evidence)) => (Outcome::Pass, evidence),
        (Variant::Positive, Err(reason)) => (Outcome::Fail(reason.clone()), reason),
        (_, Ok(evidence)) => (
            Outcome::Fail("the control succeeded where it had to be refused".to_string()),
            evidence,
        ),
        (variant, Err(reason)) => {
            let status = classify(variant, reason.clone());
            (status.0, reason)
        }
    };
    if let Err(error) = teardown {
        evidence.push_str(&format!("; teardown: {error}"));
        if matches!(status, Outcome::Pass) {
            return (Outcome::Fail(format!("teardown failed: {error}")), evidence);
        }
    }
    (status, evidence)
}

fn classify(variant: Variant, reason: String) -> (Outcome, String) {
    match variant {
        Variant::Positive => (Outcome::Fail(reason.clone()), reason),
        Variant::WrongPassword => {
            if names_authentication(&reason) {
                (Outcome::Pass, reason)
            } else {
                (
                    Outcome::Fail(format!(
                        "the wrong-password control failed for another reason: {reason}"
                    )),
                    reason,
                )
            }
        }
        Variant::WrongCa => {
            if names_tls(&reason) {
                (Outcome::Pass, reason)
            } else {
                (
                    Outcome::Fail(format!(
                        "the wrong-CA control failed for another reason: {reason}"
                    )),
                    reason,
                )
            }
        }
    }
}

fn setup_failure(error: &AdapterError) -> String {
    format!("adapter setup failed: {error}")
}

fn names_authentication(reason: &str) -> bool {
    let reason = reason.to_lowercase();
    [
        "password",
        "authentication",
        "auth failed",
        "access denied",
        "28p01",
        "1045",
        "scram",
        "no pg_hba",
    ]
    .iter()
    .any(|marker| reason.contains(marker))
}

fn names_tls(reason: &str) -> bool {
    let reason = reason.to_lowercase();
    [
        "certificate",
        "tls",
        "ssl",
        "unknown ca",
        "self-signed",
        "verify",
        "ca-sha256",
    ]
    .iter()
    .any(|marker| reason.contains(marker))
}

fn operations_for(protocol: Protocol) -> Vec<String> {
    match protocol {
        Protocol::Http => vec!["GET".to_string(), "POST".to_string(), "PUT".to_string()],
        _ => vec!["connect".to_string()],
    }
}

fn fixture_for(case: &Case, config: &Config) -> Option<SocketAddr> {
    match (case.protocol, case.upstream) {
        (Protocol::Postgres, Upstream::Tls) => config.fixtures.postgres_tls,
        (Protocol::Postgres, Upstream::Primary) => config.fixtures.postgres,
        (Protocol::Mysql, _) => config.fixtures.mysql,
        (Protocol::Mongodb, _) => config.fixtures.mongodb,
        (Protocol::Http, _) => None,
        (Protocol::Redis, Upstream::Tls) => config.fixtures.redis_tls,
        (Protocol::Redis, Upstream::Primary) => config.fixtures.redis,
    }
}

fn missing_fixture(case: &Case) -> String {
    format!(
        "the {} fixture is not configured; start it with `{}`",
        case.protocol,
        compose_command(case)
    )
}

fn unreachable_fixture(case: &Case, fixture: SocketAddr) -> String {
    format!(
        "the {} fixture is not listening on {fixture}; start it with `{}`",
        case.protocol,
        compose_command(case)
    )
}

fn compose_command(case: &Case) -> &'static str {
    match (case.protocol, case.upstream) {
        (Protocol::Postgres, Upstream::Tls) => "docker compose --profile pgtls up -d postgres-tls",
        (Protocol::Redis, Upstream::Tls) => "docker compose --profile redis up -d redis-tls",
        (protocol, _) => provision::compose_command(protocol),
    }
}

fn skipped(case: &Case, reason: String) -> CaseReport {
    CaseReport {
        id: case.id.to_string(),
        outcome: Outcome::Skipped(reason.clone()),
        controls: Vec::new(),
        evidence: reason,
    }
}

struct TlsSetup {
    ca: Option<PathBuf>,
    mode: String,
}

fn tls_setup(case: &Case, variant: Variant) -> Result<Option<TlsSetup>, String> {
    let path = if !has_tls_identity(case) {
        return Ok(Some(TlsSetup {
            ca: None,
            mode: "plaintext".to_string(),
        }));
    } else if variant == Variant::WrongCa {
        wrongca::wrong_ca().map_err(|error| format!("cannot write the wrong CA: {error}"))?
    } else if case.upstream == Upstream::Tls
        || matches!(case.protocol, Protocol::Mysql | Protocol::Mongodb)
    {
        fixture_ca()
    } else {
        return Ok(None);
    };
    let pin = ca_pin(&path)?;
    Ok(Some(TlsSetup {
        ca: Some(path),
        mode: format!("ca-sha256:{pin}"),
    }))
}

pub(crate) fn fixture_ca() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/db-test-certs/ca.pem")
}

fn ca_pin(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut blocks = 0;
    let mut current = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            inside = true;
            current.clear();
        } else if line.contains("END CERTIFICATE") {
            if inside {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(current.replace(char::is_whitespace, ""))
                    .map_err(|error| format!("cannot decode {}: {error}", path.display()))?;
                digest.update(&der);
                blocks += 1;
            }
            inside = false;
        } else if inside {
            current.push_str(line);
        }
    }
    if blocks == 0 {
        return Err(format!("{} holds no certificate", path.display()));
    }
    let digest = digest.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

struct CredentialFile {
    dir: PathBuf,
}

impl CredentialFile {
    fn write(credential: &str) -> Result<Self, String> {
        use std::io::Write;
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos())
            .unwrap_or_default();
        let dir = std::env::temp_dir().join(format!(
            "zs-conformance-credential-{}-{}-{nanos:08x}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
            builder.mode(0o700);
            options.mode(0o600);
        }
        builder
            .create(&dir)
            .map_err(|error| format!("cannot create the credential directory: {error}"))?;
        let file = Self { dir };
        options
            .open(file.path())
            .and_then(|mut handle| handle.write_all(credential.as_bytes()))
            .map_err(|error| format!("cannot write the credential file: {error}"))?;
        Ok(file)
    }

    fn path(&self) -> PathBuf {
        self.dir.join("credential")
    }
}

impl Drop for CredentialFile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;

    fn fixture(name: &str) -> PathBuf {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o755));
        }
        path
    }

    fn config() -> Config {
        Config {
            implementation: crate::Implementation {
                name: "stub".to_string(),
                adapter: fixture("stub-adapter.sh"),
                capabilities: vec![
                    Protocol::Postgres,
                    Protocol::Mysql,
                    Protocol::Mongodb,
                    Protocol::Redis,
                ],
            },
            fixtures: Fixtures {
                postgres: Some("127.0.0.1:5434".parse().expect("postgres")),
                postgres_tls: Some("127.0.0.1:5435".parse().expect("postgres tls")),
                mysql: Some("127.0.0.1:3307".parse().expect("mysql")),
                mongodb: Some("127.0.0.1:27018".parse().expect("mongodb")),
                redis: Some("127.0.0.1:6380".parse().expect("redis")),
                redis_tls: Some("127.0.0.1:6382".parse().expect("redis tls")),
            },
        }
    }

    fn case(id: &'static str, run: fn(&Context) -> Result<String, String>) -> Case {
        Case {
            id,
            protocol: Protocol::Postgres,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run,
        }
    }

    fn accepts(ctx: &Context) -> Result<String, String> {
        match ctx.variant {
            Variant::Positive => Ok("the query returned a row".to_string()),
            Variant::WrongPassword => Err("password authentication failed for user".to_string()),
            Variant::WrongCa => Err("certificate verify failed".to_string()),
        }
    }

    fn postgres_up() -> bool {
        crate::test_fixtures::ready(&["127.0.0.1:5434", "127.0.0.1:5435"], &[])
    }

    #[test]
    fn every_positive_yields_two_controls() {
        let _lock = crate::test_lock::lock();
        if !postgres_up() {
            return;
        }
        let report = run_case(&case("X-01", accepts), &config());
        assert_eq!(report.controls.len(), 2);
        assert_eq!(report.controls[0].0, "X-01-wrongpass");
        assert_eq!(report.controls[1].0, "X-01-wrongca");
        assert!(matches!(report.outcome, Outcome::Pass));
    }

    #[test]
    fn a_control_that_succeeds_is_a_failure() {
        let _lock = crate::test_lock::lock();
        if !postgres_up() {
            return;
        }
        fn always_ok(_: &Context) -> Result<String, String> {
            Ok("accepted".to_string())
        }
        let report = run_case(&case("X-02", always_ok), &config());
        assert!(matches!(report.controls[0].1, Outcome::Fail(_)));
        assert!(matches!(report.controls[1].1, Outcome::Fail(_)));
    }

    #[test]
    fn a_wrongca_control_must_fail_on_tls_not_on_setup() {
        let _lock = crate::test_lock::lock();
        if !postgres_up() {
            return;
        }
        fn setup_failure(_: &Context) -> Result<String, String> {
            Err("adapter setup failed".to_string())
        }
        fn tls_failure(ctx: &Context) -> Result<String, String> {
            match ctx.variant {
                Variant::Positive => Ok("ok".to_string()),
                Variant::WrongPassword => Err("password authentication failed".to_string()),
                Variant::WrongCa => Err("certificate verify failed".to_string()),
            }
        }
        let other = run_case(&case("X-03", setup_failure), &config());
        assert!(matches!(other.controls[1].1, Outcome::Fail(_)));
        let expected = run_case(&case("X-04", tls_failure), &config());
        assert!(matches!(expected.controls[1].1, Outcome::Pass));
    }

    #[test]
    fn cases_in_a_serial_group_never_interleave() {
        let _lock = crate::test_lock::lock();
        if !postgres_up() {
            return;
        }
        static SPANS: Mutex<Vec<(String, Instant, Instant)>> = Mutex::new(Vec::new());
        fn recording(ctx: &Context) -> Result<String, String> {
            let start = Instant::now();
            std::thread::sleep(std::time::Duration::from_millis(20));
            SPANS
                .lock()
                .expect("spans")
                .push((ctx.roles.user.clone(), start, Instant::now()));
            Ok("ok".to_string())
        }
        let mut first = case("X-05", recording);
        first.serial_group = Some("shared");
        let mut second = case("X-06", recording);
        second.serial_group = Some("shared");
        run_case(&first, &config());
        run_case(&second, &config());
        let mut spans = SPANS.lock().expect("spans");
        assert_eq!(spans.len(), 6);
        spans.sort_by_key(|span| span.1);
        for pair in spans.windows(2) {
            assert!(pair[0].2 <= pair[1].1, "two cases in one group interleaved");
        }
    }

    #[test]
    fn a_missing_fixture_skips_and_names_the_compose_command() {
        let _lock = crate::test_lock::lock();
        let mut config = config();
        config.fixtures.mysql = None;
        let mut mysql = case("X-07", accepts);
        mysql.protocol = Protocol::Mysql;
        let report = run_case(&mysql, &config);
        match report.outcome {
            Outcome::Skipped(reason) => {
                assert!(
                    reason.contains("docker compose --profile mysql up -d mysql"),
                    "{reason}"
                );
            }
            other => panic!("expected a skip, got {other:?}"),
        }
    }

    #[test]
    fn a_control_that_fails_at_adapter_setup_is_not_a_refusal() {
        let _lock = crate::test_lock::lock();
        if !postgres_up() {
            return;
        }
        unsafe {
            std::env::set_var("STUB_EXIT", "3");
            std::env::set_var("STUB_STDERR", "certificate verify failed: password");
        }
        let report = run_case(&case("X-09", accepts), &config());
        unsafe {
            std::env::remove_var("STUB_EXIT");
            std::env::remove_var("STUB_STDERR");
        }
        assert_eq!(report.controls.len(), 2);
        for (name, outcome) in &report.controls {
            assert!(matches!(outcome, Outcome::Fail(_)), "{name}: {outcome:?}");
        }
    }

    #[test]
    fn an_undeclared_capability_is_skipped_not_passed() {
        let _lock = crate::test_lock::lock();
        let mut mongodb = case("X-10", accepts);
        mongodb.protocol = Protocol::Mongodb;
        let mut config = config();
        config.implementation.capabilities = vec![Protocol::Postgres];
        match run_case(&mongodb, &config).outcome {
            Outcome::Skipped(reason) => assert!(reason.contains("mongodb capability"), "{reason}"),
            other => panic!("expected a skip, got {other:?}"),
        }
    }

    #[test]
    fn a_plaintext_postgres_case_takes_its_wrongca_control_to_the_tls_fixture() {
        let _lock = crate::test_lock::lock();
        if !postgres_up() {
            return;
        }
        let config = config();
        let primary = config.fixtures.postgres.expect("postgres");
        let target = wrong_ca_fixture(&case("X-11", accepts), &config, primary)
            .unwrap_or_else(|(outcome, _)| panic!("{outcome:?}"));
        assert_eq!(Some(target), config.fixtures.postgres_tls);
        let mut mysql = case("X-12", accepts);
        mysql.protocol = Protocol::Mysql;
        let mysql_fixture = config.fixtures.mysql.expect("mysql");
        assert_eq!(
            wrong_ca_fixture(&mysql, &config, mysql_fixture).ok(),
            Some(mysql_fixture)
        );
        let mut without_tls = config.clone();
        without_tls.fixtures.postgres_tls = None;
        match wrong_ca_fixture(&case("X-13", accepts), &without_tls, primary) {
            Err((Outcome::Skipped(reason), _)) => {
                assert!(reason.contains("--profile pgtls"), "{reason}")
            }
            other => panic!("expected a skipped control, got {other:?}"),
        }
    }

    #[test]
    fn captured_client_output_is_redacted_in_the_report() {
        let _lock = crate::test_lock::lock();
        if !postgres_up() {
            return;
        }
        static SEEN: Mutex<Option<String>> = Mutex::new(None);
        fn echo(ctx: &Context) -> Result<String, String> {
            *SEEN.lock().expect("seen") = Some(ctx.roles.password.clone());
            Ok(format!("the client printed {}", ctx.roles.password))
        }
        let report = run_case(&case("X-08", echo), &config());
        let secret = SEEN.lock().expect("seen").clone().expect("secret");
        assert!(!report.evidence.contains(&secret));
        assert!(report.evidence.contains("[REDACTED]"));
    }

    #[test]
    fn a_plaintext_redis_binding_has_no_ca_and_a_tls_one_is_pinned() {
        let mut plaintext = case("X-14", accepts);
        plaintext.protocol = Protocol::Redis;
        let setup = tls_setup(&plaintext, Variant::Positive)
            .expect("tls setup")
            .expect("a plaintext mode");
        assert_eq!(setup.mode, "plaintext");
        assert!(setup.ca.is_none());
        let mut tls = plaintext;
        tls.upstream = Upstream::Tls;
        if !fixture_ca().exists() {
            return;
        }
        let setup = tls_setup(&tls, Variant::Positive)
            .expect("tls setup")
            .expect("a pinned mode");
        assert!(setup.mode.starts_with("ca-sha256:"), "{}", setup.mode);
        assert_eq!(setup.ca, Some(fixture_ca()));
    }

    #[test]
    fn a_plaintext_redis_case_carries_only_the_wrongpass_control() {
        let _lock = crate::test_lock::lock();
        if !crate::test_fixtures::ready(&["127.0.0.1:6380", "127.0.0.1:6382"], &[&fixture_ca()]) {
            return;
        }
        let mut plaintext = case("X-15", accepts);
        plaintext.protocol = Protocol::Redis;
        let report = run_case(&plaintext, &config());
        let names: Vec<&str> = report
            .controls
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(names, ["X-15-wrongpass"]);
        let mut tls = case("X-16", accepts);
        tls.protocol = Protocol::Redis;
        tls.upstream = Upstream::Tls;
        let report = run_case(&tls, &config());
        let names: Vec<&str> = report
            .controls
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(names, ["X-16-wrongpass", "X-16-wrongca"]);
        assert!(
            matches!(report.outcome, Outcome::Pass),
            "{:?}",
            report.outcome
        );
    }
}
