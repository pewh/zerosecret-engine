use std::io::Write;
use std::process::Command;

use super::audit_ship::{ShipCursor, ship_audit};
use super::{current_session, default_subject};
use zs::wire_client::WireError;
use zs::{AgentFile, AgentHandler, GrantCache};
use zs_audit::Journal;
use zs_diag::{Component, DiagLog, Event};
use zs_identity::{Subject, WorkloadLabel};
use zs_mitm::{LocalCa, ProxyServer, RunToken};

struct UnconfiguredExchange;

#[async_trait::async_trait]
impl zs_materializer::ExchangeProvider for UnconfiguredExchange {
    async fn exchange(
        &self,
        _grant: &zs_grant::Grant,
    ) -> Result<zs_credential::Credential, zs_materializer::MaterializationError> {
        Err(zs_materializer::MaterializationError::Exchange(
            "no exchange provider configured".into(),
        ))
    }
}

fn authorizing_subject() -> Result<(Subject, &'static str), String> {
    match current_session() {
        Some(session) => Subject::new(session.clone())
            .map(|subject| (subject, "session"))
            .map_err(|e| format!("the session names an unusable subject ({session}): {e}")),
        None => default_subject().map(|subject| (subject, "env")),
    }
}

fn enrolment_subject(identity: &StoredIdentity) -> Result<(Subject, &'static str), String> {
    let subject = &identity.enrolment.subject;
    Subject::new(subject.clone())
        .map(|subject| (subject, "enrolment"))
        .map_err(|e| format!("the stored enrolment names an unusable subject ({subject}): {e}"))
}

const NO_LONGER_ENROLLED: &str = "zs: this device is no longer enrolled; run zs login";
const SIGNING_KEY_CHANGED: &str = "zs: control plane signing key changed; run zs login";
const TOKEN_SIGNING_KEY_CHANGED: &str = "zs: control plane signing key changed";
const CA_CHANGED: &str = "zs: control plane CA changed; run zs login";
const FILE_GRANTS_WITH_CONTROL: &str =
    "zs: signing_keys and grants in the policy file are not allowed with a control plane";
const FILE_GRANTS_WITH_POLICY_CREDENTIALS: &str = "zs: a policy file with its own signing_keys or grants cannot choose credentials_dir; pass --credentials-dir";

fn device_refusal_line(error: &WireError, stored: bool) -> Option<String> {
    match error {
        WireError::DeviceRefused { .. } if stored => Some(NO_LONGER_ENROLLED.to_string()),
        WireError::DeviceRefused { code } => {
            let code: String = code.chars().filter(|c| !c.is_control()).collect();
            Some(format!("zs: control plane refused this device ({code})"))
        }
        WireError::Grant(zs_grant::GrantError::SignatureInvalid) if stored => {
            Some(SIGNING_KEY_CHANGED.to_string())
        }
        WireError::Grant(zs_grant::GrantError::SignatureInvalid) => {
            Some(TOKEN_SIGNING_KEY_CHANGED.to_string())
        }
        _ => None,
    }
}

fn startup_refusal_line(error: &WireError, stored: bool, wire_url: &str) -> Option<String> {
    match error {
        WireError::Transport(_) => Some(unavailable_line(wire_url)),
        WireError::Refused { status } if *status >= 500 => Some(unavailable_line(wire_url)),
        _ => device_refusal_line(error, stored),
    }
}

fn unavailable_line(wire_url: &str) -> String {
    let wire_url: String = wire_url.chars().filter(|c| !c.is_control()).collect();
    format!("zs: control plane unavailable at {wire_url}; check the connection and retry")
}

fn device_record_line(text: &str) -> String {
    format!(
        "zs: device record: {}",
        text.strip_prefix("device record: ").unwrap_or(text)
    )
}

struct StoredIdentity {
    ca_pem: String,
    enrolment: zs::device::Enrolment,
    secrets: zs::device::DeviceSecrets,
}

// A non-empty CA set that parses replaces the trusted roots and is saved to the device record.
// The set is the whole wire trust: a CA the control plane stopped publishing is dropped.
fn install_ca_set(
    wire: &zs::wire_client::WireClient,
    control: &str,
    pems: &[String],
    diag: &DiagLog,
) {
    match wire.set_roots(pems) {
        // An empty or unchanged set: the record already holds it, so the file is not reread.
        Ok(false) => return,
        Ok(true) => {}
        Err(_) => {
            diag.emit(Event::new(Component::Grant, "ca_set_invalid").warn());
            return;
        }
    }
    let home = super::zs_home();
    let mut file = match zs::device::load_file(&home) {
        Ok(file) => file,
        Err(_) => return,
    };
    let mut changed = false;
    for slot in file.enrolments.iter_mut() {
        if zs::device::normalise(&slot.control) == zs::device::normalise(control)
            && slot.control_ca_pems != pems
        {
            slot.control_ca_pems = pems.to_vec();
            changed = true;
        }
    }
    if changed {
        let _ = zs::device::save_file(&home, &file);
    }
}

fn stored_identity(control: &str, args: &super::Args) -> Result<StoredIdentity, RunRefusal> {
    let ca_pem = zs::control_ca_pem(args.control_ca.as_deref(), &args.ca_dir)
        .map_err(RunRefusal::Control)?;
    let (enrolment, secrets) =
        match zs::device::load_with(&super::zs_home(), control, zs_mitm::device_store::read) {
            Ok(Some(found)) => found,
            Ok(None) => {
                return Err(RunRefusal::Line(format!(
                    "zs: not enrolled with {}; run zs login",
                    zs::device::normalise(control)
                )));
            }
            Err(text) => return Err(RunRefusal::Line(device_record_line(&text))),
        };
    if !zs::wire_client::pin_accepts(&ca_pem, &enrolment) {
        return Err(RunRefusal::Line(CA_CHANGED.to_string()));
    }
    Ok(StoredIdentity {
        ca_pem,
        enrolment,
        secrets,
    })
}

const POLICY_FETCH_SECONDS: u64 = 10;

pub(crate) fn control_policy(args: &super::Args) -> Option<zs_policy::Policy> {
    let control = args.control.as_deref()?;
    let identity = stored_identity(control, args).ok()?;
    let client = zs::wire_client::WireClient::from_identity(
        &identity.ca_pem,
        &identity.enrolment,
        &identity.secrets,
    )
    .ok()?;
    let runtime = tokio::runtime::Runtime::new().ok()?;
    let fetched = runtime
        .block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(POLICY_FETCH_SECONDS),
                client.fetch_policy(),
            )
            .await
        })
        .ok()?
        .ok()?;
    serde_json::from_str(&fetched.policy_json).ok()
}

const REFRESH_SECONDS: u64 = 60;
const RENEW_WITHIN_MS: u64 = 150_000;

// A shorter interval is for tests and for an operator who wants a tighter revocation bound;
// it can never be longer than the bound the agent claims.
fn refresh_interval() -> std::time::Duration {
    let seconds = std::env::var("ZS_REFRESH_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(REFRESH_SECONDS)
        .clamp(1, REFRESH_SECONDS);
    std::time::Duration::from_secs(seconds)
}

#[derive(Clone)]
struct L3Audit {
    journal: std::sync::Arc<Journal>,
    subject: String,
    workload: String,
    resource: String,
    protocol: &'static str,
    handler: std::sync::Arc<dyn zs_mitm::FlowHandler>,
}

impl L3Audit {
    fn new(
        prepared: &PreparedRun,
        resource: &str,
        protocol: &'static str,
        handler: std::sync::Arc<dyn zs_mitm::FlowHandler>,
    ) -> Self {
        Self {
            journal: prepared.journal.clone(),
            subject: prepared.audit_subject.clone(),
            workload: prepared.audit_workload.clone(),
            resource: resource.to_string(),
            protocol,
            handler,
        }
    }

    fn record(
        &self,
        operation: &str,
        reason: Option<&str>,
        decision: zs_audit::Decision,
    ) -> Result<u64, zs_audit::AuditError> {
        let request = zs_audit::AuditRequest {
            subject: self.subject.clone(),
            workload: self.workload.clone(),
            resource: self.resource.clone(),
            protocol: self.protocol.to_string(),
            operation: operation.to_string(),
            decision,
            reason: reason.map(str::to_string),
            credential_ref: self.handler.credential_ref(&self.resource),
        };
        let at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.journal.append_seq(&request, at_ms)
    }
}

type L3Materialize = zs_protocol::Materialize;

fn l3_materialize(audit: L3Audit) -> L3Materialize {
    std::sync::Arc::new(move || {
        let outcome = audit
            .handler
            .materialize(&audit.resource, "connect")
            .map_err(|denied| denied.with_kind(zs_protocol::DenyKind::Materialize));
        let decision = match &outcome {
            Ok(_) => zs_audit::Decision::Allow,
            Err(_) => zs_audit::Decision::Deny,
        };
        if let Err(e) = audit.record(
            "connect",
            outcome
                .as_ref()
                .err()
                .map(zs_protocol::Denied::audit_reason),
            decision,
        ) {
            return Err(
                zs_protocol::Denied::new(format!("audit sink unavailable: {e}"))
                    .with_kind(zs_protocol::DenyKind::AuditUnavailable),
            );
        }
        outcome
    })
}

fn l3_cancel_authorize(audit: L3Audit) -> zs_proto_postgres::CancelAuthorize {
    std::sync::Arc::new(move || audit.handler.authorize_message(&audit.resource, "connect"))
}

fn l3_refusal_audit(audit: L3Audit) -> zs_proto_postgres::AuditRefusal {
    std::sync::Arc::new(move |operation: &'static str, reason: &'static str| {
        match audit.record(operation, Some(reason), zs_audit::Decision::Deny) {
            Ok(seq) => Some(seq),
            Err(e) => {
                stderr_line!(
                    "zs: {} {operation} on {} was refused but not recorded: {e}",
                    audit.protocol,
                    audit.resource
                );
                None
            }
        }
    })
}

fn mongo_refusal_audit<E: std::fmt::Display>(
    resource: String,
    record: impl Fn(&'static str, &'static str) -> Result<u64, E> + Send + Sync + 'static,
    report: impl Fn(&str) + Send + Sync + 'static,
) -> zs_proto_mongo::AuditRefusal {
    std::sync::Arc::new(move |operation: &'static str, reason: &'static str| {
        match record(operation, reason) {
            Ok(seq) => Some(seq),
            Err(e) => {
                report(&format!(
                    "zs: mongo {operation} on {resource} was refused but not recorded: {e}"
                ));
                None
            }
        }
    })
}

fn announce_l3(
    prepared: &PreparedRun,
    kind: &'static str,
    resource: &str,
    local: std::net::SocketAddr,
) {
    stdout_line!("zs: {kind} {resource} -> 127.0.0.1:{}", local.port());
    prepared.diag.emit(
        Event::new(Component::Agent, "listener_bound")
            .code("kind", kind)
            .resource(resource)
            .token("addr", &local.to_string()),
    );
}

async fn mint_grant(
    client: &zs::wire_client::WireClient,
    binding: &zs::ResourceBinding,
    subject: &str,
    workload: &str,
) -> Result<zs::MintedGrant, WireError> {
    let request = zs_wire::GrantMintRequest {
        device_id: client.device_id().to_string(),
        subject: subject.to_string(),
        workload: workload.to_string(),
        resource: binding.resource.clone(),
        operations: binding.operations(),
    };
    client.request_grant(&request).await
}

async fn renew_grants(
    client: &zs::wire_client::WireClient,
    agent: &AgentHandler,
    bindings: &[zs::ResourceBinding],
    stored: bool,
    diag: &DiagLog,
) {
    let subject = zs_mitm::FlowHandler::subject(agent);
    let workload = zs_mitm::FlowHandler::workload(agent);
    for binding in bindings {
        if !agent.grant_needs_renewal(&binding.resource, RENEW_WITHIN_MS) {
            continue;
        }
        let minted = mint_grant(client, binding, &subject, &workload).await;
        match renewal(agent, binding, minted, stored, diag) {
            Ok(line) => stdout_line!("{line}"),
            Err(line) => stderr_line!("{line}"),
        }
    }
}

fn renewal(
    agent: &AgentHandler,
    binding: &zs::ResourceBinding,
    minted: Result<zs::MintedGrant, WireError>,
    stored: bool,
    diag: &DiagLog,
) -> Result<String, String> {
    let failed = |failure: &'static str| {
        Event::new(Component::Grant, "renewal_failed")
            .warn()
            .resource(&binding.resource)
            .failure(failure)
    };
    let minted = match minted {
        Ok(minted) => minted,
        Err(e) => {
            diag.emit(failed("wire"));
            return Err(device_refusal_line(&e, stored).unwrap_or_else(|| {
                format!("zs: cannot renew the grant for {}: {e}", binding.resource)
            }));
        }
    };
    let renewed = format!(
        "zs: renewed grant {} for {}",
        minted.signed.grant.grant_id, binding.resource
    );
    let event = grant_event("grant_renewed", &minted.signed, binding);
    match agent.accept_renewal(binding, minted) {
        Ok(()) => {
            diag.emit(event);
            Ok(renewed)
        }
        Err(mismatch) => {
            diag.emit(failed(mismatch.failure()));
            Err(mismatch.renewal_line(&binding.resource))
        }
    }
}

fn grant_event(
    name: &'static str,
    signed: &zs_grant::SignedGrant,
    binding: &zs::ResourceBinding,
) -> Event {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    Event::new(Component::Grant, name)
        .resource(&binding.resource)
        .token("grant_id", &signed.grant.grant_id)
        .tokens("operations", &signed.grant.operations)
        .num(
            "expires_in_s",
            signed.grant.expires_at_ms.saturating_sub(now) / 1000,
        )
}

fn emit_run_start(
    diag: &DiagLog,
    args: &super::Args,
    file: &AgentFile,
    subject_source: &'static str,
) {
    diag.emit(
        Event::new(Component::Agent, "run_started")
            .token("version", env!("CARGO_PKG_VERSION"))
            .code("os", std::env::consts::OS)
            .token("listen", &args.listen)
            .num("bindings", file.bindings.len() as u64)
            .code("subject_source", subject_source)
            .flag("test_endpoints", cfg!(zs_test_endpoints))
            .num(
                "test_resolve",
                zs::network_for_stores().resolve.len() as u64,
            ),
    );
}

fn emit_bindings(diag: &DiagLog, file: &AgentFile) {
    for binding in &file.bindings {
        diag.emit(
            Event::new(Component::Agent, "binding")
                .resource(&binding.resource)
                .token("host", &binding.host)
                .token("protocol", &binding.protocol)
                .code("scheme", scheme_code(&binding.auth))
                .tokens("operations", &binding.operations())
                .num(
                    "scope_entries",
                    binding.paths.as_ref().map_or(0, |p| p.len() as u64),
                )
                .flag("scoped", binding.paths.is_some())
                .flag(
                    "upstream_override",
                    binding.upstream_host.is_some() || binding.upstream_port.is_some(),
                )
                .flag("upstream_plaintext", binding.upstream_plaintext),
        );
    }
}

fn scheme_code(auth: &zs::HttpAuth) -> &'static str {
    match auth {
        zs::HttpAuth::Bearer => "bearer",
        zs::HttpAuth::Basic => "basic",
        zs::HttpAuth::ApiKeyHeader { .. } => "api_key_header",
        zs::HttpAuth::QueryParam { .. } => "query_param",
        zs::HttpAuth::WebsocketJsonField { .. } => "websocket_json_field",
        zs::HttpAuth::AwsSigv4 { .. } => "aws_sigv4",
        zs::HttpAuth::HmacBodySignature { .. } => "hmac_body_signature",
    }
}

enum RunRefusal {
    Line(String),
    Control(String),
}

struct Connection<'a> {
    control: &'a str,
    stored: Option<StoredIdentity>,
}

async fn connect(
    connection: Connection<'_>,
    args: &super::Args,
) -> Result<zs::wire_client::WireClient, RunRefusal> {
    let control = connection.control.trim_end_matches('/');
    if let Some(identity) = connection.stored {
        return zs::wire_client::WireClient::from_identity(
            &identity.ca_pem,
            &identity.enrolment,
            &identity.secrets,
        )
        .map_err(|e| {
            RunRefusal::Line(format!(
                "zs: the stored enrolment for {control} is unusable ({e}); run zs login"
            ))
        });
    }
    let token = args.enrollment_token.as_deref().ok_or_else(|| {
        RunRefusal::Control(
            "--enrollment-token is required with --control (ask an operator for one)".to_string(),
        )
    })?;
    let enroll_url = args
        .enroll_url
        .as_deref()
        .map(|u| u.trim_end_matches('/'))
        .unwrap_or(control);
    zs::control_url_allowed(control).map_err(RunRefusal::Control)?;
    zs::control_url_allowed(enroll_url).map_err(RunRefusal::Control)?;
    let ca_pem = zs::control_ca_pem(args.control_ca.as_deref(), &args.ca_dir)
        .map_err(RunRefusal::Control)?;

    zs::wire_client::WireClient::enroll(enroll_url, &ca_pem, token, &args.device_name)
        .await
        .map_err(|e| RunRefusal::Control(format!("enrolment failed: {e}")))
}

async fn enrol_and_fetch(
    connection: Connection<'_>,
    args: &super::Args,
    file: &mut AgentFile,
    grants: &GrantCache,
    subject: &zs_identity::Subject,
    workload: &zs_identity::WorkloadLabel,
    diag: &DiagLog,
) -> Result<zs::wire_client::WireClient, RunRefusal> {
    let stored = connection.stored.is_some();
    let client = connect(connection, args).await?;

    let mut granted = 0usize;
    for binding in &mut file.bindings {
        match mint_grant(&client, binding, subject.as_str(), workload.as_str()).await {
            Ok(minted) => {
                if let Err(mismatch) = zs::connection::reconcile(binding, &minted.signed) {
                    return Err(RunRefusal::Line(mismatch.startup_line(&binding.resource)));
                }
                stdout_line!(
                    "zs: grant {} for {}",
                    minted.signed.grant.grant_id,
                    binding.resource
                );
                diag.emit(grant_event("grant_minted", &minted.signed, binding));
                grants.insert(minted);
                granted += 1;
            }
            Err(e) => {
                if let Some(line) = startup_refusal_line(&e, stored, client.wire_url()) {
                    return Err(RunRefusal::Line(line));
                }
                stderr_line!("zs: no grant for {}: {e}", binding.resource);
                diag.emit(
                    Event::new(Component::Grant, "grant_failed")
                        .warn()
                        .resource(&binding.resource)
                        .failure("wire"),
                );
            }
        }
    }
    file.validate().map_err(|e| {
        RunRefusal::Line(format!(
            "zs: {e} (after applying the control plane's signed connection)"
        ))
    })?;
    stdout_line!(
        "zs: enrolled as {} with {granted} of {} resources granted",
        client.device_id(),
        file.bindings.len()
    );

    Ok(client)
}

struct BackgroundTasks(Vec<tokio::task::JoinHandle<()>>);

impl BackgroundTasks {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, task: tokio::task::JoinHandle<()>) {
        self.0.push(task);
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        for task in self.0.drain(..) {
            task.abort();
        }
    }
}

struct RunningServices {
    proxy_addr: std::net::SocketAddr,
    token: std::sync::Arc<RunToken>,
    http_proxy: bool,
    postgres_addr: Option<std::net::SocketAddr>,
    mysql_addr: Option<std::net::SocketAddr>,
    l3: Vec<(String, std::net::SocketAddr)>,
    endpoints: Vec<(String, std::net::SocketAddr)>,
    _tasks: BackgroundTasks,
}

struct PreparedRun {
    file: AgentFile,
    journal: std::sync::Arc<Journal>,
    shipped: std::sync::Arc<tokio::sync::Mutex<u64>>,
    ca: std::sync::Arc<LocalCa>,
    wire: Option<std::sync::Arc<zs::wire_client::WireClient>>,
    stored: bool,
    agent: std::sync::Arc<AgentHandler>,
    audit_subject: String,
    audit_workload: String,
    runtime: tokio::runtime::Runtime,
    diag: DiagLog,
}

pub(super) fn run(args: &super::Args) -> i32 {
    let diag = open_diag(args);
    let code = run_with(args, &diag);
    diag.close();
    code
}

fn open_diag(args: &super::Args) -> DiagLog {
    match DiagLog::open_run(&args.audit, args.log.as_deref()) {
        Ok(diag) => {
            if let Some(path) = diag.path() {
                stderr_line!("zs: diagnostic log {}", path.display());
            }
            diag
        }
        Err(e) => {
            stderr_line!("zs: diagnostic log unavailable: {}", zs_diag::io_kind(&e));
            DiagLog::disabled()
        }
    }
}

fn refuse_control(diag: &DiagLog, control: &str, refusal: RunRefusal) -> i32 {
    match refusal {
        RunRefusal::Line(line) => stderr_line!("{line}"),
        RunRefusal::Control(e) => stderr_line!("zs: control plane at {control}: {e}"),
    }
    refuse_run(diag, "control", 1)
}

fn refuse_run(diag: &DiagLog, stage: &'static str, code: i32) -> i32 {
    diag.emit(
        Event::new(Component::Agent, "run_refused")
            .error()
            .code("stage", stage),
    );
    code
}

fn run_with(args: &super::Args, diag: &DiagLog) -> i32 {
    let prepared = match prepare(args, diag) {
        Ok(prepared) => prepared,
        Err(code) => return code,
    };
    let ca_path = absolute_path(&args.ca_dir.join("ca.crt"));
    prepared.runtime.block_on(async {
        let services = match start_services(&prepared, args).await {
            Ok(services) => services,
            Err(code) => return code,
        };
        let child = build_child(args, &services, &ca_path);
        let code = match wait_for_child(child, &services, &ca_path, diag, &args.rest[0]).await {
            Ok(code) => code,
            Err(code) => return code,
        };
        if let Some(wire) = prepared.wire.as_deref() {
            ship_audit(
                wire,
                &args.audit,
                &ShipCursor::beside(&args.audit),
                &mut *prepared.shipped.lock().await,
            )
            .await;
        }
        drop(services);
        code
    })
}

fn create_audit_dir(audit: &std::path::Path) -> std::io::Result<()> {
    let Some(dir) = audit.parent().filter(|d| !d.as_os_str().is_empty()) else {
        return Ok(());
    };
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

fn prepare(args: &super::Args, diag: &DiagLog) -> Result<PreparedRun, i32> {
    if args.rest.is_empty() {
        stderr_line!("zs: no command supplied after --");
        return Err(refuse_run(diag, "args", 2));
    }
    let mut file = match AgentFile::load(&args.policy) {
        Ok(p) => p,
        Err(e) => {
            stderr_line!("zs: {e}");
            return Err(refuse_run(diag, "config", 1));
        }
    };
    if let Some(control) = args.control.as_deref()
        && (!file.signing_keys.is_empty() || !file.grants.is_empty())
    {
        return Err(refuse_control(
            diag,
            control,
            RunRefusal::Line(FILE_GRANTS_WITH_CONTROL.to_string()),
        ));
    }
    if args.control.is_none()
        && args.credentials_dir_from_policy
        && (!file.signing_keys.is_empty() || !file.grants.is_empty())
    {
        stderr_line!("{FILE_GRANTS_WITH_POLICY_CREDENTIALS}");
        return Err(refuse_run(diag, "signing_keys", 1));
    }
    let verifier = match file.verifier() {
        Ok(v) => v,
        Err(e) => {
            stderr_line!("zs: {e}");
            return Err(refuse_run(diag, "signing_keys", 1));
        }
    };
    let stored = match (args.control.as_deref(), args.enrollment_token.is_some()) {
        (Some(control), false) => match stored_identity(control, args) {
            Ok(identity) => Some(identity),
            Err(refusal) => return Err(refuse_control(diag, control, refusal)),
        },
        _ => None,
    };
    let subject = match stored.as_ref() {
        Some(identity) => enrolment_subject(identity),
        None => authorizing_subject(),
    };
    let (subject, subject_source) = match subject {
        Ok(subject) => subject,
        Err(e) => {
            stderr_line!("zs: {e}");
            return Err(refuse_run(diag, "subject", 1));
        }
    };
    let workload = match WorkloadLabel::new(args.workload.clone()) {
        Ok(w) => w,
        Err(e) => {
            stderr_line!("zs: {e}");
            return Err(refuse_run(diag, "workload", 1));
        }
    };
    emit_run_start(diag, args, &file, subject_source);
    // One shared journal: a second `Journal::open` on the path would interleave hash chains.
    if let Err(e) = create_audit_dir(&args.audit) {
        stderr_line!("zs: audit sink unavailable: {e}");
        return Err(refuse_run(diag, "audit", 1));
    }
    let journal = match Journal::open(&args.audit) {
        Ok(j) => std::sync::Arc::new(j),
        Err(e) => {
            stderr_line!("zs: audit sink unavailable: {e}");
            return Err(refuse_run(diag, "audit", 1));
        }
    };
    let last_seq = match journal.last_seq() {
        Ok(seq) => seq,
        Err(e) => {
            stderr_line!("zs: audit sink unavailable: {e}");
            return Err(refuse_run(diag, "audit", 1));
        }
    };
    let ca = match LocalCa::load_or_create_secure(&args.ca_dir) {
        Ok(ca) => ca,
        Err(error) => {
            stderr_line!("zs: local ca: {error}");
            return Err(refuse_run(diag, "ca", 1));
        }
    };
    let ssm = match zs_materializer::aws_ssm::SsmStore::new(zs::network_for_stores()) {
        Ok(store) => zs_materializer::GrantBoundCache::new(store),
        Err(e) => {
            stderr_line!("zs: aws_ssm store: {e}");
            return Err(refuse_run(diag, "store", 1));
        }
    };
    let materializer = std::sync::Arc::new(zs_materializer::Materializer::new(
        zs_materializer::StoreRegistry::new(std::sync::Arc::new(zs_materializer::FileStore::new(
            args.credentials_dir.clone(),
        )))
        .with_aws_ssm(std::sync::Arc::new(ssm)),
        std::sync::Arc::new(UnconfiguredExchange),
    ));

    let grants = GrantCache::new();
    for signed in file.grants.clone() {
        grants.insert(signed);
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            stderr_line!("zs: {e}");
            return Err(refuse_run(diag, "runtime", 1));
        }
    };

    let uses_stored = stored.is_some();
    let wire = match args.control.as_deref() {
        None => None,
        Some(control) => {
            let connection = Connection { control, stored };
            match runtime.block_on(enrol_and_fetch(
                connection, args, &mut file, &grants, &subject, &workload, diag,
            )) {
                Ok(client) => Some(std::sync::Arc::new(client)),
                Err(refusal) => return Err(refuse_control(diag, control, refusal)),
            }
        }
    };
    emit_bindings(diag, &file);

    let verifier = match wire.as_ref() {
        None => verifier,
        Some(client) => client.verifier().clone(),
    };

    let audit_subject = subject.as_str().to_string();
    let audit_workload = workload.as_str().to_string();

    let agent = std::sync::Arc::new(
        AgentHandler::from_grants(
            subject,
            workload,
            file.bindings.clone(),
            grants,
            verifier,
            materializer,
        )
        .with_diag(diag.clone()),
    );
    let control = args.control.clone().unwrap_or_default();
    if let Some(client) = wire.as_ref() {
        match runtime.block_on(client.fetch_revocations()) {
            Ok(response) => {
                client.install_key_set(&response.grant_verifying_keys, diag);
                install_ca_set(client, &control, &response.control_ca_pems, diag);
                if !response.revoked_grant_ids.is_empty() {
                    agent.apply_revocations(&response.revoked_grant_ids);
                    stdout_line!(
                        "zs: applied {} revoked grant(s) known at startup",
                        response.revoked_grant_ids.len()
                    );
                }
            }
            Err(e) => {
                stderr_line!("zs: cannot read revocations at startup: {e}");
                return Err(refuse_run(diag, "revocations", 1));
            }
        }
    }
    let shipped = match wire.as_ref() {
        None => last_seq,
        Some(_) => match ShipCursor::beside(&args.audit).load_or_init(last_seq) {
            Ok(seq) if seq > last_seq => 0,
            Ok(seq) => seq,
            Err(e) => {
                stderr_line!("zs: audit ship cursor unavailable: {e}");
                return Err(refuse_run(diag, "audit", 1));
            }
        },
    };

    Ok(PreparedRun {
        file,
        journal,
        shipped: std::sync::Arc::new(tokio::sync::Mutex::new(shipped)),
        ca: std::sync::Arc::new(ca),
        wire,
        stored: uses_stored,
        agent,
        audit_subject,
        audit_workload,
        runtime,
        diag: diag.clone(),
    })
}

async fn start_services(
    prepared: &PreparedRun,
    args: &super::Args,
) -> Result<RunningServices, i32> {
    let listen: std::net::SocketAddr = match args.listen.parse() {
        Ok(a) => a,
        Err(e) => {
            stderr_line!("zs: bad --listen: {e}");
            return Err(refuse_run(&prepared.diag, "listen", 2));
        }
    };
    if !listen.ip().is_loopback() {
        stderr_line!("zs: --listen must be a loopback address");
        return Err(refuse_run(&prepared.diag, "listen", 2));
    }
    let mut tasks = BackgroundTasks::new();
    let token = std::sync::Arc::new(RunToken::generate());
    let handler: std::sync::Arc<dyn zs_mitm::FlowHandler> = prepared.agent.clone();
    let l3_handler = handler.clone();
    let server = match ProxyServer::bind(
        listen,
        prepared.ca.clone(),
        handler,
        prepared.journal.clone(),
        token.clone(),
    )
    .await
    {
        Ok(s) => s.with_diag(prepared.diag.clone()),
        Err(e) => {
            stderr_line!("zs: proxy bind: {e}");
            return Err(refuse_run(&prepared.diag, "proxy_bind", 1));
        }
    };
    let addr = match server.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            stderr_line!("zs: proxy local addr: {e}");
            return Err(refuse_run(&prepared.diag, "proxy_bind", 1));
        }
    };
    prepared.diag.emit(
        Event::new(Component::Agent, "listener_bound")
            .code("kind", "proxy")
            .token("addr", &addr.to_string()),
    );
    tasks.push(tokio::spawn(async move {
        let _ = server.serve().await;
    }));

    let mut pg_endpoint = None;
    let mut mysql_endpoint = None;
    let mut l3 = Vec::new();
    for binding in prepared.file.bindings.iter().filter(|b| b.is_postgres()) {
        let (upstream_host, upstream_port) = binding.upstream();
        let endpoint = match zs_proto_postgres::UpstreamEndpoint::new(upstream_host, upstream_port)
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                stderr_line!(
                    "zs: invalid postgres upstream for {}: {error}",
                    binding.resource
                );
                return Err(refuse_run(&prepared.diag, "postgres_upstream", 1));
            }
        };
        let tls = match binding.upstream_tls() {
            Ok(tls) => tls,
            Err(error) => {
                stderr_line!("zs: {error}");
                return Err(refuse_run(&prepared.diag, "postgres_tls", 1));
            }
        };
        let audit = L3Audit::new(prepared, &binding.resource, "postgres", l3_handler.clone());
        let refusal_audit = l3_refusal_audit(audit.clone());
        let cancel_authorize = l3_cancel_authorize(audit.clone());
        let pg = match zs_proto_postgres::PostgresListener::bind_endpoint(
            &binding.listen_addr(),
            endpoint,
            zs_proto_postgres::SslPolicy::RefuseOnLoopback,
            tls,
            l3_materialize(audit),
        )
        .await
        {
            Ok(listener) => listener
                .with_diag(prepared.diag.clone(), &binding.resource)
                .with_refusal_audit(refusal_audit)
                .with_cancel_authorize(cancel_authorize)
                .with_expected_user(binding.user.clone())
                .with_caller_check(crate::peer::caller_check()),
            Err(e) => {
                stderr_line!("zs: postgres listener for {}: {e}", binding.resource);
                return Err(refuse_run(&prepared.diag, "postgres_bind", 1));
            }
        };
        let local = pg.local_addr();
        announce_l3(prepared, "postgres", &binding.resource, local);
        tasks.push(tokio::spawn(async move {
            let _ = pg.serve().await;
        }));
        if pg_endpoint.is_none() {
            pg_endpoint = Some(local);
        }
        l3.push((binding.env_prefix(), local));
    }

    for binding in prepared.file.bindings.iter().filter(|b| b.is_mysql()) {
        let (upstream_host, upstream_port) = binding.upstream();
        let endpoint = match zs_proto_mysql::UpstreamEndpoint::new(upstream_host, upstream_port) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                stderr_line!(
                    "zs: invalid mysql upstream for {}: {error}",
                    binding.resource
                );
                return Err(refuse_run(&prepared.diag, "mysql_upstream", 1));
            }
        };
        let tls = match binding.upstream_tls() {
            Ok(tls) => tls,
            Err(error) => {
                stderr_line!("zs: {error}");
                return Err(refuse_run(&prepared.diag, "mysql_tls", 1));
            }
        };
        let client_auth = match binding.mysql_client_auth() {
            Ok(auth) => auth,
            Err(error) => {
                stderr_line!("zs: {error}");
                return Err(refuse_run(&prepared.diag, "mysql_client_auth", 1));
            }
        };
        let audit = L3Audit::new(prepared, &binding.resource, "mysql", l3_handler.clone());
        let refusal_audit = l3_refusal_audit(audit.clone());
        let mysql = match zs_proto_mysql::MysqlListener::bind_endpoint(
            &binding.listen_addr(),
            endpoint,
            tls,
            l3_materialize(audit),
        )
        .await
        {
            Ok(listener) => listener
                .with_diag(prepared.diag.clone(), &binding.resource)
                .with_refusal_audit(refusal_audit)
                .with_expected_user(binding.user.clone())
                .with_client_auth(client_auth)
                .with_caller_check(crate::peer::caller_check()),
            Err(e) => {
                stderr_line!("zs: mysql listener for {}: {e}", binding.resource);
                return Err(refuse_run(&prepared.diag, "mysql_bind", 1));
            }
        };
        let local = mysql.local_addr();
        announce_l3(prepared, "mysql", &binding.resource, local);
        tasks.push(tokio::spawn(async move {
            let _ = mysql.serve().await;
        }));
        if mysql_endpoint.is_none() {
            mysql_endpoint = Some(local);
        }
        l3.push((binding.env_prefix(), local));
    }

    for binding in prepared.file.bindings.iter().filter(|b| b.is_mongo()) {
        let (upstream_host, upstream_port) = binding.upstream();
        let endpoint = match zs_proto_mongo::UpstreamEndpoint::new(upstream_host, upstream_port) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                stderr_line!(
                    "zs: invalid mongo upstream for {}: {error}",
                    binding.resource
                );
                return Err(refuse_run(&prepared.diag, "mongo_upstream", 1));
            }
        };
        let tls = match binding.mongo_tls() {
            Ok(tls) => tls,
            Err(error) => {
                stderr_line!("zs: {error}");
                return Err(refuse_run(&prepared.diag, "mongo_tls", 1));
            }
        };
        let auth = match binding.mongo_auth() {
            Ok(auth) => auth,
            Err(error) => {
                stderr_line!("zs: {error}");
                return Err(refuse_run(&prepared.diag, "mongo_auth", 1));
            }
        };
        let audit = L3Audit::new(prepared, &binding.resource, "mongo", l3_handler.clone());
        let refusals = audit.clone();
        let refusal_audit = mongo_refusal_audit(
            binding.resource.clone(),
            move |operation, reason| {
                refusals.record(operation, Some(reason), zs_audit::Decision::Deny)
            },
            |line| stderr_line!("{line}"),
        );
        let mongo = match zs_proto_mongo::MongoListener::bind_endpoint(
            &binding.listen_addr(),
            endpoint,
            tls,
            auth,
            l3_materialize(audit),
        )
        .await
        {
            Ok(listener) => listener
                .with_diag(prepared.diag.clone(), &binding.resource)
                .with_refusal_audit(refusal_audit)
                .with_caller_check(crate::peer::caller_check()),
            Err(e) => {
                stderr_line!("zs: mongo listener for {}: {e}", binding.resource);
                return Err(refuse_run(&prepared.diag, "mongo_bind", 1));
            }
        };
        let local = mongo.local_addr();
        announce_l3(prepared, "mongo", &binding.resource, local);
        tasks.push(tokio::spawn(async move {
            let _ = mongo.serve().await;
        }));
        l3.push((binding.env_prefix(), local));
    }

    let mut endpoints = Vec::new();
    for binding in prepared.file.bindings.iter().filter(|b| b.local_endpoint) {
        let endpoint = match zs_mitm::EndpointServer::bind(
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            prepared.ca.clone(),
            l3_handler.clone(),
            prepared.journal.clone(),
            prepared.diag.clone(),
            binding.host.clone(),
            token.clone(),
        )
        .await
        {
            Ok(endpoint) => endpoint,
            Err(e) => {
                stderr_line!("zs: endpoint listener for {}: {e}", binding.resource);
                return Err(refuse_run(&prepared.diag, "endpoint_bind", 1));
            }
        };
        let local = match endpoint.local_addr() {
            Ok(local) => local,
            Err(e) => {
                stderr_line!("zs: endpoint local addr for {}: {e}", binding.resource);
                return Err(refuse_run(&prepared.diag, "endpoint_bind", 1));
            }
        };
        announce_l3(prepared, "endpoint", &binding.resource, local);
        tasks.push(tokio::spawn(async move {
            let _ = endpoint.serve().await;
        }));
        endpoints.push((binding.env_prefix(), local));
    }

    if let Some(wire) = prepared.wire.clone() {
        let agent = prepared.agent.clone();
        let audit_path = args.audit.clone();
        let cursor = ShipCursor::beside(&audit_path);
        let shipped = prepared.shipped.clone();
        let bindings = prepared.file.bindings.clone();
        let stored = prepared.stored;
        let diag = prepared.diag.clone();
        let every = refresh_interval();

        let control = args.control.clone().unwrap_or_default();
        let (revocation_wire, revocation_agent, revocation_diag) =
            (wire.clone(), agent.clone(), diag.clone());
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                match revocation_wire.fetch_revocations().await {
                    Ok(response) => {
                        revocation_wire
                            .install_key_set(&response.grant_verifying_keys, &revocation_diag);
                        install_ca_set(
                            &revocation_wire,
                            &control,
                            &response.control_ca_pems,
                            &revocation_diag,
                        );
                        let learned = response.revoked_grant_ids.len();
                        revocation_agent.apply_revocations(&response.revoked_grant_ids);
                        if learned > 0 {
                            stdout_line!("zs: applied {learned} revoked grant(s)");
                            revocation_diag.emit(
                                Event::new(Component::Grant, "revocations_applied")
                                    .num("count", learned as u64),
                            );
                        }
                    }
                    Err(e) => {
                        stderr_line!("zs: revocation refresh failed: {e}");
                        revocation_diag.emit(
                            Event::new(Component::Grant, "refresh_failed")
                                .warn()
                                .failure("wire"),
                        );
                    }
                }
            }
        }));

        let (renewal_wire, renewal_agent, renewal_diag) = (wire.clone(), agent.clone(), diag);
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                renew_grants(
                    &renewal_wire,
                    &renewal_agent,
                    &bindings,
                    stored,
                    &renewal_diag,
                )
                .await;
            }
        }));

        tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                ship_audit(&wire, &audit_path, &cursor, &mut *shipped.lock().await).await;
            }
        }));
    }

    Ok(RunningServices {
        proxy_addr: addr,
        token,
        http_proxy: prepared.file.bindings.iter().any(|b| b.is_http()),
        postgres_addr: pg_endpoint,
        mysql_addr: mysql_endpoint,
        l3,
        endpoints,
        _tasks: tasks,
    })
}

const SYSTEM_ROOTS: [&str; 3] = [
    "/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
];
const LOOPBACK_NO_PROXY: &str = "127.0.0.1,localhost,::1";

// SSL_CERT_FILE, REQUESTS_CA_BUNDLE and CURL_CA_BUNDLE replace the trust store, and a
// passthrough host presents its real certificate, so those variables name the agent CA
// followed by the roots the parent trusted.
fn write_ca_bundle(ca_path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut bundle = std::fs::read(ca_path).ok()?;
    let roots = std::env::var_os("SSL_CERT_FILE")
        .map(std::path::PathBuf::from)
        .into_iter()
        .chain(SYSTEM_ROOTS.iter().map(std::path::PathBuf::from))
        .find_map(|path| std::fs::read(path).ok())?;
    if !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend(roots);
    let path = ca_path.with_file_name("ca-bundle.crt");
    std::fs::write(&path, bundle).ok()?;
    Some(path)
}

fn absolute_path(path: &std::path::Path) -> std::path::PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

// Bun splits BUN_OPTIONS on whitespace and keeps any quote as part of the name, so a
// preload under a directory with a space cannot be named there. The file is a constant, so
// it is written to a space-free directory keyed by that directory instead.
enum BunPreloadDir {
    CaDir(std::path::PathBuf),
    PerUserTemp(std::path::PathBuf),
}

impl BunPreloadDir {
    fn path(&self) -> &std::path::Path {
        match self {
            Self::CaDir(path) | Self::PerUserTemp(path) => path,
        }
    }
}

const BUN_PRELOAD_REFUSED: &str =
    "zs: the bun preload could not be installed privately; Bun's WebSocket will not be intercepted";

fn bun_preload_dir(ca_dir: &std::path::Path) -> Option<BunPreloadDir> {
    if !ca_dir.to_string_lossy().chars().any(char::is_whitespace) {
        return Some(BunPreloadDir::CaDir(ca_dir.to_path_buf()));
    }
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    ca_dir.hash(&mut hasher);
    let dir = std::env::temp_dir().join(preload_dir_name(hasher.finish()));
    (!dir.to_string_lossy().chars().any(char::is_whitespace))
        .then_some(BunPreloadDir::PerUserTemp(dir))
}

#[cfg(unix)]
fn preload_dir_name(hash: u64) -> String {
    format!("zs-preload-{}-{hash:016x}", effective_uid())
}

#[cfg(not(unix))]
fn preload_dir_name(hash: u64) -> String {
    format!("zs-preload-{hash:016x}")
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(dir)?;
            let private = meta.is_dir()
                && meta.uid() == effective_uid()
                && meta.permissions().mode() & 0o777 == 0o700;
            if private {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "the preload directory is not private to this user",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::symlink_metadata(dir)?.is_dir() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "the preload path is not a directory",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn owned_by_effective_user(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.uid() == effective_uid()
}

#[cfg(not(unix))]
fn owned_by_effective_user(_meta: &std::fs::Metadata) -> bool {
    true
}

fn install_bun_preload(dir: &BunPreloadDir) -> std::io::Result<std::path::PathBuf> {
    match dir {
        BunPreloadDir::CaDir(path) => std::fs::create_dir_all(path)?,
        BunPreloadDir::PerUserTemp(path) => create_private_dir(path)?,
    }
    let preload = dir.path().join("bun-preload.js");
    match std::fs::symlink_metadata(&preload) {
        Ok(meta) => {
            if !meta.is_file() || !owned_by_effective_user(&meta) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "the bun preload is not a regular file owned by this user",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    static STAGED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let staged = dir.path().join(format!(
        ".bun-preload-{}-{}.tmp",
        std::process::id(),
        STAGED.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let installed = write_private_file(&staged, zs::BUN_PRELOAD_SOURCE.as_bytes())
        .and_then(|()| std::fs::rename(&staged, &preload));
    if let Err(error) = installed {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    Ok(preload)
}

fn write_private_file(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(content)
}

fn no_proxy() -> String {
    match std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        Some(existing) => format!("{existing},{LOOPBACK_NO_PROXY}"),
        None => LOOPBACK_NO_PROXY.to_string(),
    }
}

fn build_child(
    args: &super::Args,
    services: &RunningServices,
    ca_path: &std::path::Path,
) -> Command {
    let addr = services.proxy_addr;
    let bundle = write_ca_bundle(ca_path).unwrap_or_else(|| {
        stderr_line!(
            "zs: no system root bundle found; SSL_CERT_FILE trusts only the agent CA, so passthrough hosts fail TLS"
        );
        ca_path.to_path_buf()
    });
    let no_proxy = no_proxy();
    let proxy_url = services.token.proxy_url(addr);
    let mut cmd = Command::new(&args.rest[0]);
    cmd.args(&args.rest[1..])
        .env("HTTPS_PROXY", proxy_url.as_str())
        .env("https_proxy", proxy_url.as_str())
        .env("NO_PROXY", &no_proxy)
        .env("no_proxy", &no_proxy)
        .env("NODE_EXTRA_CA_CERTS", ca_path)
        .env("SSL_CERT_FILE", &bundle)
        .env("REQUESTS_CA_BUNDLE", &bundle)
        .env("CURL_CA_BUNDLE", &bundle)
        .env("NODE_USE_ENV_PROXY", "1");
    if services.http_proxy {
        cmd.env("HTTP_PROXY", proxy_url.as_str())
            .env("http_proxy", proxy_url.as_str());
    }
    let ca_dir = std::fs::canonicalize(&args.ca_dir).unwrap_or_else(|_| args.ca_dir.clone());
    match bun_preload_dir(&ca_dir) {
        None => stderr_line!(
            "zs: no directory without a space for the bun preload; Bun's WebSocket will not be intercepted"
        ),
        Some(dir) => match install_bun_preload(&dir) {
            Ok(bun_preload) => {
                cmd.env(
                    "BUN_OPTIONS",
                    zs::bun_options_with_preload(
                        std::env::var("BUN_OPTIONS").ok().as_deref(),
                        &bun_preload,
                    ),
                );
            }
            Err(_) => stderr_line!("{}", BUN_PRELOAD_REFUSED),
        },
    }
    let preload_path = ca_dir.join("node-preload.cjs");
    match std::fs::write(&preload_path, zs::NODE_PRELOAD_SOURCE) {
        Ok(()) => {
            cmd.env(
                "NODE_OPTIONS",
                zs::node_options_with_preload(
                    std::env::var("NODE_OPTIONS").ok().as_deref(),
                    &preload_path,
                ),
            );
        }
        Err(e) => {
            stderr_line!(
                "zs: could not write the node preload ({e}); Node's global fetch will not be intercepted"
            );
        }
    }
    if let Some(pg) = services.postgres_addr {
        cmd.env("PGHOST", pg.ip().to_string())
            .env("PGPORT", pg.port().to_string());
    }
    if let Some(mysql) = services.mysql_addr {
        cmd.env("MYSQL_HOST", mysql.ip().to_string())
            .env("MYSQL_TCP_PORT", mysql.port().to_string());
    }
    for (prefix, addr) in &services.l3 {
        cmd.env(format!("{prefix}_HOST"), addr.ip().to_string())
            .env(format!("{prefix}_PORT"), addr.port().to_string());
    }
    for (prefix, addr) in &services.endpoints {
        cmd.env(
            format!("{prefix}_URL"),
            services.token.endpoint_url(*addr).as_str(),
        );
    }
    cmd
}

async fn wait_for_child(
    cmd: Command,
    services: &RunningServices,
    ca_path: &std::path::Path,
    diag: &DiagLog,
    program: &str,
) -> Result<i32, i32> {
    let mut cmd = tokio::process::Command::from(cmd);
    let mut signals = match ChildSignals::install() {
        Ok(signals) => Some(signals),
        Err(e) => {
            stderr_line!(
                "zs: cannot install the child signal handlers; a signal may skip the final audit ship: {e}"
            );
            None
        }
    };
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            stderr_line!("zs: failed to launch child: {e}");
            return Err(refuse_run(diag, "child_spawn", 1));
        }
    };
    let pid = child.id().unwrap_or_default();
    stdout_line!("zs: proxy {}", services.proxy_addr);
    stdout_line!("zs: ca-cert {}", ca_path.display());
    stdout_line!("zs: child-pid {pid}");
    let _ = std::io::stdout().flush();
    let name = std::path::Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("invalid");
    diag.emit(
        Event::new(Component::Agent, "child_spawned")
            .token("program", name)
            .num("pid", u64::from(pid)),
    );
    let status = match signals.as_mut() {
        Some(signals) => signals.wait_for(&mut child).await,
        None => child.wait().await,
    };
    let (code, exit_event) = match status {
        Ok(status) => {
            let code = status.code().unwrap_or(1);
            (code, exit_event(&status, code))
        }
        Err(e) => {
            stderr_line!("zs: child wait: {e}");
            (
                1,
                Event::new(Component::Agent, "child_exited").num("code", 1),
            )
        }
    };
    diag.emit(exit_event);
    Ok(code)
}

#[cfg(unix)]
struct ChildSignals {
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ChildSignals {
    fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }

    async fn wait_for(
        &mut self,
        child: &mut tokio::process::Child,
    ) -> std::io::Result<std::process::ExitStatus> {
        loop {
            tokio::select! {
                status = child.wait() => return status,
                _ = self.terminate.recv() => forward_signal(child.id(), libc::SIGTERM),
                _ = self.hangup.recv() => forward_signal(child.id(), libc::SIGHUP),
                _ = self.interrupt.recv() => {}
            }
        }
    }
}

#[cfg(unix)]
fn forward_signal(pid: Option<u32>, signal: i32) {
    // SAFETY: `pid` comes from `tokio::process::Child::id` for a child this process spawned
    // and has not reaped, so the kernel still reserves the identifier.
    let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) else {
        return;
    };
    unsafe {
        libc::kill(pid, signal);
    }
}

#[cfg(not(unix))]
struct ChildSignals;

#[cfg(not(unix))]
impl ChildSignals {
    fn install() -> std::io::Result<Self> {
        Ok(Self)
    }

    async fn wait_for(
        &mut self,
        child: &mut tokio::process::Child,
    ) -> std::io::Result<std::process::ExitStatus> {
        loop {
            tokio::select! {
                status = child.wait() => return status,
                _ = tokio::signal::ctrl_c() => {}
            }
        }
    }
}

#[cfg(unix)]
fn exit_event(status: &std::process::ExitStatus, code: i32) -> Event {
    use std::os::unix::process::ExitStatusExt;
    let event = Event::new(Component::Agent, "child_exited");
    match (status.code(), status.signal()) {
        (None, Some(signal)) => event.num("signal", u64::from(signal.unsigned_abs())),
        _ => event.num("code", u64::from(code.unsigned_abs())),
    }
}

#[cfg(not(unix))]
fn exit_event(_status: &std::process::ExitStatus, code: i32) -> Event {
    Event::new(Component::Agent, "child_exited").num("code", u64::from(code.unsigned_abs()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn rebinds_within(addr: std::net::SocketAddr, limit: std::time::Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < limit {
            if std::net::TcpListener::bind(addr).is_ok() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn a_mongo_refusal_is_recorded_as_a_deny_and_a_failed_write_reports_one_line() {
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let fail = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let audit = mongo_refusal_audit(
            "orders-mongo".to_string(),
            {
                let recorded = recorded.clone();
                let fail = fail.clone();
                move |operation, reason| {
                    if fail.load(std::sync::atomic::Ordering::SeqCst) {
                        return Err("disk full");
                    }
                    let mut recorded = recorded.lock().unwrap();
                    recorded.push((operation, reason));
                    Ok(recorded.len() as u64)
                }
            },
            {
                let lines = lines.clone();
                move |line| lines.lock().unwrap().push(line.to_string())
            },
        );
        assert_eq!(
            audit("authenticate", zs_proto_mongo::AUTHENTICATE_REFUSED_REASON),
            Some(1)
        );
        assert_eq!(
            *recorded.lock().unwrap(),
            vec![("authenticate", zs_proto_mongo::AUTHENTICATE_REFUSED_REASON)]
        );
        assert!(lines.lock().unwrap().is_empty());
        fail.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            audit("authenticate", zs_proto_mongo::AUTHENTICATE_REFUSED_REASON),
            None
        );
        assert_eq!(
            *lines.lock().unwrap(),
            vec![
                "zs: mongo authenticate on orders-mongo was refused but not recorded: disk full"
                    .to_string()
            ]
        );
        assert_eq!(recorded.lock().unwrap().len(), 1);
    }

    struct DenyingHandler;

    impl zs_mitm::FlowHandler for DenyingHandler {
        fn classify(&self, _destination: &zs_protocol::Destination) -> zs_mitm::Flow {
            zs_mitm::Flow::Deny {
                reason: "not in this test".into(),
            }
        }
        fn subject(&self) -> String {
            "alice".into()
        }
        fn workload(&self) -> String {
            "default".into()
        }
        fn protocol_for(
            &self,
            _resource: &str,
        ) -> Option<std::sync::Arc<dyn zs_protocol::Protocol>> {
            None
        }
        fn materialize(
            &self,
            _resource: &str,
            _operation: &str,
        ) -> Result<zs_credential::Credential, zs_protocol::Denied> {
            Err(
                zs_protocol::Denied::new("credential reference x not resolvable")
                    .with_audit_reason(zs::MATERIALIZE_FAILED),
            )
        }
        fn authorize_message(
            &self,
            _resource: &str,
            _operation: &str,
        ) -> Result<(), zs_protocol::Denied> {
            Err(zs_protocol::Denied::new("not in this test"))
        }
    }

    #[test]
    fn an_l3_connect_deny_records_the_audit_reason() {
        let home = tempfile::tempdir().unwrap();
        let prepared = prepared_with_postgres_ports(home.path(), &[]);
        let materialize = l3_materialize(L3Audit::new(
            &prepared,
            "orders-db",
            "postgres",
            std::sync::Arc::new(DenyingHandler),
        ));
        let Err(denied) = materialize() else {
            panic!("materialize must be denied");
        };
        assert_eq!(denied.reason, "credential reference x not resolvable");
        let journal = std::fs::read_to_string(home.path().join("audit.jsonl")).unwrap();
        let last = journal.lines().last().unwrap();
        let record: serde_json::Value = serde_json::from_str(last).unwrap();
        assert_eq!(record["operation"], "connect");
        assert_eq!(record["decision"], "deny");
        assert_eq!(record["reason"], "materialize failed");
        assert!(!last.contains("not resolvable"), "{last}");
    }

    #[tokio::test]
    async fn dropping_background_tasks_cancels_a_pending_task() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let mut tasks = BackgroundTasks::new();
        tasks.push(tokio::spawn(async move {
            let _tx = tx;
            std::future::pending::<()>().await;
        }));
        drop(tasks);
        let closed = tokio::time::timeout(std::time::Duration::from_secs(3), rx).await;
        assert!(matches!(closed, Ok(Err(_))), "the task was not cancelled");
    }

    #[test]
    fn device_record_errors_print_one_prefix() {
        assert_eq!(
            device_record_line("secure storage locked"),
            "zs: device record: secure storage locked"
        );
        assert_eq!(
            device_record_line("device record: wrong length"),
            "zs: device record: wrong length"
        );
    }

    #[test]
    fn device_refusals_and_a_bad_signature_stop_both_paths() {
        let refused = WireError::DeviceRefused {
            code: "subject_mismatch".into(),
        };
        assert_eq!(
            device_refusal_line(&refused, true).as_deref(),
            Some(NO_LONGER_ENROLLED)
        );
        assert_eq!(
            device_refusal_line(&refused, false).as_deref(),
            Some("zs: control plane refused this device (subject_mismatch)")
        );
        let hostile = WireError::DeviceRefused {
            code: "x\u{1b}[2Jy\n".into(),
        };
        assert_eq!(
            device_refusal_line(&hostile, false).as_deref(),
            Some("zs: control plane refused this device (x[2Jy)")
        );
        let forged = WireError::Grant(zs_grant::GrantError::SignatureInvalid);
        assert_eq!(
            device_refusal_line(&forged, true).as_deref(),
            Some(SIGNING_KEY_CHANGED)
        );
        assert_eq!(
            device_refusal_line(&forged, false).as_deref(),
            Some("zs: control plane signing key changed")
        );
        for stored in [true, false] {
            for policy in [403, 404] {
                assert_eq!(
                    device_refusal_line(&WireError::Refused { status: policy }, stored),
                    None
                );
                assert_eq!(
                    startup_refusal_line(
                        &WireError::Refused { status: policy },
                        stored,
                        "https://w"
                    ),
                    None
                );
            }
            assert_eq!(
                device_refusal_line(&WireError::Transport("reset".into()), stored),
                None,
                "a renewal keeps its cached grants"
            );
            assert_eq!(
                device_refusal_line(&WireError::Refused { status: 503 }, stored),
                None,
                "a renewal keeps its cached grants"
            );
            assert_eq!(
                startup_refusal_line(&refused, stored, "https://w"),
                device_refusal_line(&refused, stored)
            );
            assert_eq!(
                startup_refusal_line(&forged, stored, "https://w"),
                device_refusal_line(&forged, stored)
            );
        }
    }

    #[test]
    fn an_unavailable_control_plane_stops_a_startup_with_a_fixed_line() {
        let line = "zs: control plane unavailable at https://localhost:8444; check the connection and retry";
        for stored in [true, false] {
            for error in [
                WireError::Transport("tcp connect error: secret-detail".into()),
                WireError::Refused { status: 500 },
                WireError::Refused { status: 503 },
            ] {
                assert_eq!(
                    startup_refusal_line(&error, stored, "https://localhost:8444").as_deref(),
                    Some(line)
                );
            }
            assert_eq!(
                startup_refusal_line(&WireError::Refused { status: 499 }, stored, "https://w"),
                None
            );
        }
        assert_eq!(
            unavailable_line("https://w\u{1b}[2J\n"),
            "zs: control plane unavailable at https://w[2J; check the connection and retry"
        );
    }

    fn mysql_grant(
        key: &zs_grant::ControlSigningKey,
        port: u16,
        grant_id: &str,
        expires_in_ms: u64,
    ) -> zs_grant::SignedGrant {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        key.sign(zs_grant::Grant {
            subject: "alice".into(),
            workload: "default".into(),
            resource: "orders-mysql".into(),
            host: "mysql.orders.test".into(),
            protocol: "mysql".into(),
            source: zs_policy::CredentialSource::file("orders-mysql"),
            operations: vec!["connect".into()],
            environment: "development".into(),
            expires_at_ms: now + expires_in_ms,
            grant_id: grant_id.into(),
            materialization: zs_policy::Materialization::Retrieve,
            upstream_host: "mysql.orders.test".into(),
            upstream_port: port,
            upstream_tls: zs_policy::UpstreamTlsMode::Default,
            local_endpoint: false,
            version: zs_grant::GRANT_VERSION,
        })
        .unwrap()
    }

    fn renewal_agent(
        key: &zs_grant::ControlSigningKey,
        binding: &zs::ResourceBinding,
    ) -> AgentHandler {
        let grants = GrantCache::new();
        grants.insert(mysql_grant(key, 3306, "g-1", 60_000));
        AgentHandler::from_grants(
            Subject::new("alice").unwrap(),
            WorkloadLabel::new("default").unwrap(),
            vec![binding.clone()],
            grants,
            zs_grant::AgentVerifier::new(vec![(
                key.key_id().to_string(),
                ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
            )]),
            std::sync::Arc::new(zs_materializer::Materializer::new(
                zs_materializer::StoreRegistry::new(std::sync::Arc::new(
                    zs_materializer::FileStore::new("/nonexistent"),
                )),
                std::sync::Arc::new(UnconfiguredExchange),
            )),
        )
    }

    #[test]
    fn a_renewed_grant_with_a_changed_connection_is_skipped() {
        let home = tempfile::tempdir().unwrap();
        let key = zs_grant::ControlSigningKey::generate("k1");
        let mut binding: zs::ResourceBinding = serde_json::from_value(serde_json::json!({
            "resource": "orders-mysql",
            "host": "mysql.orders.test",
            "protocol": "mysql",
        }))
        .unwrap();
        zs::connection::reconcile(&mut binding, &mysql_grant(&key, 3306, "g-1", 60_000)).unwrap();
        let log = home.path().join("diag.jsonl");
        let diag = DiagLog::open_with_cap(&log, "run", 1 << 20).unwrap();

        let equal = renewal_agent(&key, &binding);
        assert_eq!(
            renewal(
                &equal,
                &binding,
                Ok(mysql_grant(&key, 3306, "g-2", 600_000).into()),
                true,
                &diag
            ),
            Ok("zs: renewed grant g-2 for orders-mysql".to_string())
        );
        assert!(!equal.grant_needs_renewal("orders-mysql", RENEW_WITHIN_MS));

        let changed = renewal_agent(&key, &binding);
        assert_eq!(
            renewal(
                &changed,
                &binding,
                Ok(mysql_grant(&key, 3307, "g-3", 600_000).into()),
                true,
                &diag
            ),
            Err("zs: orders-mysql: the control plane changed upstream_port (signed 3307, running 3306); restart zs run to use it".to_string())
        );
        assert!(changed.grant_needs_renewal("orders-mysql", RENEW_WITHIN_MS));
        changed.apply_revocations(&["g-1".into()]);
        let reason = zs_mitm::FlowHandler::authorize_message(&changed, "orders-mysql", "connect")
            .unwrap_err()
            .reason;
        assert!(reason.contains("grant g-1 is revoked"), "{reason}");

        diag.close();
        let events: Vec<serde_json::Value> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let named = |name: &str| {
            events
                .iter()
                .filter(|e| e["event"] == name)
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(named("grant_renewed").len(), 1, "{events:?}");
        let failed = named("renewal_failed");
        assert_eq!(failed.len(), 1, "{events:?}");
        assert_eq!(failed[0]["error"]["kind"], "connection_mismatch");
        assert_eq!(failed[0]["resource"], "orders-mysql");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_materialization_failure_emits_its_diag_code() {
        let home = tempfile::tempdir().unwrap();
        let key = zs_grant::ControlSigningKey::generate("k1");
        let mut binding: zs::ResourceBinding = serde_json::from_value(serde_json::json!({
            "resource": "orders-mysql",
            "host": "mysql.orders.test",
            "protocol": "mysql",
        }))
        .unwrap();
        zs::connection::reconcile(&mut binding, &mysql_grant(&key, 3306, "g-1", 60_000)).unwrap();
        let log = home.path().join("diag.jsonl");
        let diag = DiagLog::open_with_cap(&log, "run", 1 << 20).unwrap();
        let agent = renewal_agent(&key, &binding).with_diag(diag.clone());

        let Err(denied) = zs_mitm::FlowHandler::materialize(&agent, "orders-mysql", "connect")
        else {
            panic!("a missing credential file must deny");
        };
        assert!(
            denied.reason.starts_with("materialization denied: "),
            "{}",
            denied.reason
        );

        diag.close();
        let text = std::fs::read_to_string(&log).unwrap();
        let failed: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| event["event"] == "materialize_failed")
            .collect();
        assert_eq!(failed.len(), 1, "{text}");
        assert_eq!(failed[0]["error"]["kind"], "file");
        assert_eq!(failed[0]["resource"], "orders-mysql");
        assert!(!text.contains("not resolvable"), "{text}");
    }

    #[test]
    fn dropping_an_empty_owner_is_safe() {
        drop(BackgroundTasks::new());
    }

    fn args_listening(home: &std::path::Path, listen: &str) -> crate::Args {
        crate::Args {
            command: "run".into(),
            policy: home.join("zs-policy.json"),
            credentials_dir: home.join(".zs-credentials"),
            audit: home.join("audit.jsonl"),
            ca_dir: home.join(".zs-ca"),
            listen: listen.into(),
            workload: "default".into(),
            rest: vec!["/usr/bin/true".into()],
            oidc_authorize: None,
            oidc_token: None,
            control: None,
            control_ca: None,
            explicit: Default::default(),
            credentials_dir_from_policy: false,
            enrollment_token: None,
            enroll_url: None,
            device_name: "workstation".into(),
            confirmed: false,
            log: None,
            json: false,
            init_opts: Default::default(),
        }
    }

    fn prepared_with_postgres_ports(home: &std::path::Path, ports: &[u16]) -> PreparedRun {
        let bindings: Vec<String> = ports
            .iter()
            .enumerate()
            .map(|(i, port)| {
                format!(
                    r#"{{"resource":"db{i}","host":"db{i}.internal","protocol":"postgres","upstream_host":"127.0.0.1","upstream_port":{port}}}"#
                )
            })
            .collect();
        std::fs::write(
            home.join("zs-policy.json"),
            format!(
                r#"{{"bindings":[{}],"signing_keys":[],"grants":[]}}"#,
                bindings.join(",")
            ),
        )
        .unwrap();
        let file = AgentFile::load(&home.join("zs-policy.json")).unwrap();
        let materializer = std::sync::Arc::new(zs_materializer::Materializer::new(
            zs_materializer::StoreRegistry::new(std::sync::Arc::new(
                zs_materializer::FileStore::new(home.join(".zs-credentials")),
            )),
            std::sync::Arc::new(UnconfiguredExchange),
        ));
        let agent = std::sync::Arc::new(AgentHandler::from_grants(
            Subject::new("alice").unwrap(),
            WorkloadLabel::new("default").unwrap(),
            file.bindings.clone(),
            GrantCache::new(),
            zs_grant::AgentVerifier::new(Vec::new()),
            materializer,
        ));
        PreparedRun {
            file,
            journal: std::sync::Arc::new(Journal::open(home.join("audit.jsonl")).unwrap()),
            shipped: std::sync::Arc::new(tokio::sync::Mutex::new(0)),
            ca: std::sync::Arc::new(LocalCa::load_or_create(home.join(".zs-ca")).unwrap()),
            wire: None,
            stored: false,
            agent,
            audit_subject: "alice".into(),
            audit_workload: "default".into(),
            runtime: tokio::runtime::Runtime::new().unwrap(),
            diag: DiagLog::disabled(),
        }
    }

    #[test]
    fn dropping_started_services_releases_every_listener_while_the_runtime_lives() {
        let home = tempfile::tempdir().unwrap();
        let prepared = prepared_with_postgres_ports(home.path(), &[1]);
        let args = args_listening(home.path(), "127.0.0.1:0");

        let services = prepared
            .runtime
            .block_on(start_services(&prepared, &args))
            .unwrap_or_else(|code| panic!("start_services failed with {code}"));
        let proxy = services.proxy_addr;
        let postgres = services.postgres_addr.expect("a postgres listener");
        assert!(std::net::TcpListener::bind(proxy).is_err());
        assert!(std::net::TcpListener::bind(postgres).is_err());

        drop(services);

        for addr in [proxy, postgres] {
            assert!(
                rebinds_within(addr, std::time::Duration::from_secs(3)),
                "{addr} stayed bound after its owner dropped"
            );
        }
        drop(prepared);
    }

    #[test]
    fn a_failure_after_the_proxy_binds_releases_it_while_the_runtime_lives() {
        let home = tempfile::tempdir().unwrap();
        let prepared = prepared_with_postgres_ports(home.path(), &[1, 0]);
        let proxy = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let args = args_listening(home.path(), &proxy.to_string());

        let outcome = prepared.runtime.block_on(start_services(&prepared, &args));

        assert!(matches!(outcome, Err(1)));
        assert!(
            rebinds_within(proxy, std::time::Duration::from_secs(3)),
            "the proxy stayed bound after a later startup failure"
        );
        drop(prepared);
    }

    #[test]
    fn dropping_running_services_releases_a_bound_listener() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let mut tasks = BackgroundTasks::new();
        tasks.push(runtime.spawn(async move { while listener.accept().await.is_ok() {} }));
        let services = RunningServices {
            proxy_addr: addr,
            token: std::sync::Arc::new(RunToken::generate()),
            http_proxy: false,
            postgres_addr: None,
            mysql_addr: None,
            l3: Vec::new(),
            endpoints: Vec::new(),
            _tasks: tasks,
        };
        assert!(std::net::TcpListener::bind(addr).is_err());
        drop(services);
        assert!(rebinds_within(addr, std::time::Duration::from_secs(3)));
    }

    #[test]
    fn the_ca_path_given_to_the_child_is_absolute() {
        let path = absolute_path(std::path::Path::new(".zs-ca/ca.crt"));
        assert!(
            path.is_absolute(),
            "the child would resolve a relative CA path against its own cwd: {}",
            path.display()
        );
        assert!(path.ends_with(".zs-ca/ca.crt"), "{}", path.display());
    }

    #[test]
    fn a_bun_preload_path_never_contains_a_space() {
        let plain = std::path::Path::new("/tmp/zs-ca");
        match bun_preload_dir(plain) {
            Some(BunPreloadDir::CaDir(dir)) => assert_eq!(dir.as_path(), plain),
            _ => panic!("a CA directory without a space must be used in place"),
        }
        let spaced = std::path::Path::new("/tmp/my project/.zs-ca");
        let Some(BunPreloadDir::PerUserTemp(dir)) = bun_preload_dir(spaced) else {
            panic!("a CA directory with a space must use the fallback");
        };
        assert!(
            !dir.to_string_lossy().chars().any(char::is_whitespace),
            "Bun cannot name a preload under a path with a space: {}",
            dir.display()
        );
        #[cfg(unix)]
        assert!(
            dir.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format!("zs-preload-{}-", effective_uid()))),
            "the fallback must be keyed per user: {}",
            dir.display()
        );
        match bun_preload_dir(spaced) {
            Some(BunPreloadDir::PerUserTemp(again)) => {
                assert_eq!(dir, again, "the fallback must be stable")
            }
            _ => panic!("the fallback must be stable"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_shared_bun_preload_directory_is_refused_and_nothing_is_written() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        for mode in [0o777, 0o755, 0o750] {
            let dir = root
                .path()
                .join(format!("zs-preload-{}-{mode:o}", effective_uid()));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let error = install_bun_preload(&BunPreloadDir::PerUserTemp(dir.clone())).unwrap_err();
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{mode:o}"
            );
            assert!(!dir.join("bun-preload.js").exists(), "{mode:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_bun_preload_directory_is_private_and_the_file_is_too() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("zs-preload-501-abc");
        let preload = install_bun_preload(&BunPreloadDir::PerUserTemp(dir.clone())).unwrap();
        assert_eq!(preload, dir.join("bun-preload.js"));
        let dir_mode = std::fs::symlink_metadata(&dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "{dir_mode:o}");
        let file_mode = std::fs::symlink_metadata(&preload)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "{file_mode:o}");
        assert_eq!(
            std::fs::read_to_string(&preload).unwrap(),
            zs::BUN_PRELOAD_SOURCE
        );
        let again = install_bun_preload(&BunPreloadDir::PerUserTemp(dir)).unwrap();
        assert_eq!(
            again, preload,
            "a stale preload owned by this user is replaced"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_bun_preload_symlink_is_refused_without_touching_its_target() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("zs-preload-501-abc");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("bun-preload.js")).unwrap();

        let error = install_bun_preload(&BunPreloadDir::PerUserTemp(dir)).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }

    #[test]
    fn concurrent_runs_sharing_a_ca_dir_all_install_the_bun_preload() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("ca");
        let installs: Vec<_> = (0..4)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    (0..200)
                        .map(|_| install_bun_preload(&BunPreloadDir::CaDir(dir.clone())))
                        .filter(Result::is_err)
                        .count()
                })
            })
            .collect();
        let failed: usize = installs.into_iter().map(|t| t.join().unwrap()).sum();

        assert_eq!(failed, 0, "every concurrent install must succeed");
        assert_eq!(
            std::fs::read_to_string(dir.join("bun-preload.js")).unwrap(),
            zs::BUN_PRELOAD_SOURCE
        );
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["bun-preload.js"], "no staging file is left behind");
    }
}
