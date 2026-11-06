//! Fixtures shared by every file that tests a SECURITY §7 row. A file that includes this
//! module also declares `mod common;` (`apps/zs/tests/common`), which these fixtures use.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(dead_code)]

#[cfg(unix)]
use std::sync::Arc;

use zs::{HttpAuth, ResourceBinding};
#[cfg(unix)]
use zs_grant::ControlSigningKey;
use zs_grant::Grant;

pub const SUBJECT: &str = "alice@company.com";
pub const WORKLOAD: &str = "claude-code";
pub const RESOURCE: &str = "stripe-production";
pub const HOST: &str = "api.stripe.com";

/// The text that ends the Result cell of a SECURITY §7 row whose test needs the control
/// plane. Such a row is tested in the commercial suite, not in `fail_closed_matrix.rs`.
pub const COMMERCIAL: &str = "(commercial suite)";

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn grant(expires_at_ms: u64, grant_id: &str) -> Grant {
    let connection = crate::common::default_connection(HOST, "https");
    Grant {
        subject: SUBJECT.into(),
        workload: WORKLOAD.into(),
        resource: RESOURCE.into(),
        host: HOST.to_string(),
        protocol: "https".into(),
        source: zs_policy::CredentialSource::file("stripe-prod"),
        operations: vec!["GET".into()],
        environment: "development".into(),
        expires_at_ms,
        grant_id: grant_id.into(),
        materialization: zs_policy::Materialization::Retrieve,
        upstream_host: connection.upstream_host,
        upstream_port: connection.upstream_port,
        upstream_tls: connection.upstream_tls,
        local_endpoint: connection.local_endpoint,
    }
}

pub fn binding() -> ResourceBinding {
    ResourceBinding {
        resource: RESOURCE.to_string(),
        host: HOST.to_string(),
        protocol: "https".to_string(),
        upstream_host: None,
        upstream_port: None,
        upstream_plaintext: false,
        listen_port: None,
        local_endpoint: false,
        operations: Vec::new(),
        paths: None,
        upstream_ca: None,
        upstream_cert_sha256: None,
        client_auth_plugin: None,
        user: None,
        auth_source: None,
        auth: HttpAuth::Bearer,
        source: None,
        loaded_ca: None,
    }
}

/// A `ZS_HOME` whose policy file names a control plane and its CA (`control-ca.pem`).
#[cfg(unix)]
pub struct PlainHome {
    pub home: crate::common::TestHome,
}

#[cfg(unix)]
impl PlainHome {
    pub fn new(control_ca_pem: &str) -> Self {
        let home = crate::common::TestHome::new(".zs-ca");
        std::fs::create_dir_all(home.path().join(".zs-ca")).unwrap();
        std::fs::write(home.path().join("control-ca.pem"), control_ca_pem).unwrap();
        Self { home }
    }

    pub fn write_policy(&self, control: &str, binding: serde_json::Value) {
        let policy = serde_json::json!({
            "run": {"control": control, "control_ca": "control-ca.pem"},
            "bindings": [binding],
            "signing_keys": [],
            "grants": [],
        });
        std::fs::write(
            self.home.path().join("zs-policy.json"),
            serde_json::to_string(&policy).unwrap(),
        )
        .unwrap();
    }

    pub fn marker(&self) -> std::path::PathBuf {
        self.home.path().join("child-ran")
    }

    pub fn run(&self, flags: &[&str]) -> (i32, String) {
        let _ = std::fs::remove_file(self.marker());
        let mut args: Vec<String> = vec!["run".into()];
        args.extend(flags.iter().map(|flag| flag.to_string()));
        args.extend([
            "--".into(),
            "touch".into(),
            self.marker().display().to_string(),
        ]);
        crate::common::run_zs(self.home.path(), &args, &[])
    }

    /// Starts `zs run` against this home and leaves it running.
    pub fn spawn_child(&self, child: &[&str], env: &[(&str, &str)]) -> std::process::Child {
        let mut command = std::process::Command::new(crate::common::bin_path());
        command
            .args(["run", "--enrollment-token", "enr-fake", "--"])
            .args(child)
            .env("ZS_HOME", self.home.path())
            .env("USER", "localuser")
            .envs(env.iter().copied())
            .current_dir(self.home.path())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command.spawn().expect("the agent must start")
    }

    pub fn assert_refused(&self, code: i32, output: &str, line: &str, row: &str) {
        assert_eq!(code, 1, "{row}:\n{output}");
        assert!(
            output.lines().any(|l| l == line),
            "{row}: expected the line {line:?}:\n{output}"
        );
        assert!(
            !self.marker().exists(),
            "{row}: the child must not start:\n{output}"
        );
    }
}

#[cfg(unix)]
pub fn https_binding() -> serde_json::Value {
    serde_json::json!({"resource": RESOURCE, "host": HOST, "protocol": "https"})
}

#[cfg(unix)]
pub fn field_line(resource: &str, field: &str, file: &str, signed: &str) -> String {
    format!(
        "zs: {resource}: {field} is {file} in the policy file, but the control plane signed {signed}; remove {field} from the policy file, or ask an admin to change resource {resource}"
    )
}

/// What the fake control plane's `/wire/grant` answers.
#[cfg(unix)]
pub enum FakeGrant {
    Refuse(u16, &'static str),
    Mint {
        host: String,
        protocol: String,
    },
    Signed(&'static str, &'static str, zs_policy::ResolvedConnection),
    Forged,
    /// Answers the first request with a grant that needs renewal at once, then never answers.
    ShortThenHang,
    Remote {
        source: zs_policy::CredentialSource,
        token: String,
        connection: zs_policy::ResolvedConnection,
    },
}

/// A control plane wire API stand-in (plain HTTP): it enrols any device with the test CA and
/// answers `/wire/grant` as told by `answer`.
#[cfg(unix)]
pub struct FakeControl {
    pub url: String,
    ca_pem: String,
    grant: Arc<std::sync::Mutex<FakeGrant>>,
    revoked: Arc<std::sync::Mutex<Vec<String>>>,
    grant_calls: Arc<std::sync::atomic::AtomicUsize>,
    _runtime: tokio::runtime::Runtime,
}

#[cfg(unix)]
impl FakeControl {
    pub fn start() -> Self {
        use axum::response::IntoResponse;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let ca = Arc::new(crate::common::test_ca::TestCa::generate("fake-control").unwrap());
        let key = Arc::new(ControlSigningKey::generate("control-k1"));
        let grant = Arc::new(std::sync::Mutex::new(FakeGrant::Mint {
            host: HOST.into(),
            protocol: "https".into(),
        }));
        let revoked: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let grant_calls: Arc<std::sync::atomic::AtomicUsize> = Arc::default();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let enrol = {
            let (ca, key, url) = (ca.clone(), key.clone(), url.clone());
            move |axum::Json(request): axum::Json<zs_wire::EnrollmentRequest>| async move {
                axum::Json(zs_wire::EnrollmentResponse {
                    device_id: "dev-fake".into(),
                    organization: "default".into(),
                    client_certificate: ca
                        .issue_client_certificate(&request.csr, "dev-fake", "default")
                        .unwrap(),
                    grant_verifying_key: key.verifying_key_bytes().to_vec(),
                    grant_verifying_key_id: key.key_id().to_string(),
                    wire_url: url,
                })
            }
        };
        let mint = {
            let (key, grant, grant_calls) = (key.clone(), grant.clone(), grant_calls.clone());
            move |axum::Json(request): axum::Json<serde_json::Value>| async move {
                use std::sync::atomic::Ordering;
                let text = |field: &str| request[field].as_str().unwrap_or_default().to_string();
                let mut source = zs_policy::CredentialSource::file("fake");
                let mut identity_token = None;
                let mut expires_in_ms = 300_000;
                let answered = grant_calls.fetch_add(1, Ordering::SeqCst) + 1;
                if answered > 1 && matches!(&*grant.lock().unwrap(), FakeGrant::ShortThenHang) {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "slow renewal")
                        .into_response();
                }
                let (host, protocol, forged, connection) = match &*grant.lock().unwrap() {
                    FakeGrant::Refuse(status, body) => {
                        return (axum::http::StatusCode::from_u16(*status).unwrap(), *body)
                            .into_response();
                    }
                    FakeGrant::Mint { host, protocol } => (
                        host.clone(),
                        protocol.clone(),
                        false,
                        crate::common::default_connection(host, protocol),
                    ),
                    FakeGrant::ShortThenHang => {
                        expires_in_ms = 60_000;
                        (
                            HOST.into(),
                            "https".into(),
                            false,
                            crate::common::default_connection(HOST, "https"),
                        )
                    }
                    FakeGrant::Signed(host, protocol, connection) => (
                        host.to_string(),
                        protocol.to_string(),
                        false,
                        connection.clone(),
                    ),
                    FakeGrant::Forged => (
                        HOST.into(),
                        "https".into(),
                        true,
                        crate::common::default_connection(HOST, "https"),
                    ),
                    FakeGrant::Remote {
                        source: remote,
                        token,
                        connection,
                    } => {
                        source = remote.clone();
                        identity_token = Some(token.clone());
                        (HOST.into(), "https".into(), false, connection.clone())
                    }
                };
                let other = ControlSigningKey::generate("control-k1");
                let signer = if forged { &other } else { &*key };
                let signed = signer
                    .sign(Grant {
                        subject: text("subject"),
                        workload: text("workload"),
                        resource: text("resource"),
                        host,
                        protocol,
                        source,
                        operations: serde_json::from_value(request["operations"].clone())
                            .unwrap_or_default(),
                        environment: "development".into(),
                        expires_at_ms: now_ms() + expires_in_ms,
                        grant_id: "g-fake".into(),
                        materialization: zs_policy::Materialization::Retrieve,
                        upstream_host: connection.upstream_host,
                        upstream_port: connection.upstream_port,
                        upstream_tls: connection.upstream_tls,
                        local_endpoint: connection.local_endpoint,
                    })
                    .unwrap();
                axum::Json(zs_wire::GrantMintResponse {
                    signed_grant_json: serde_json::to_string(&signed).unwrap(),
                    identity_token,
                })
                .into_response()
            }
        };
        let app = axum::Router::new()
            .route("/wire/enroll", axum::routing::post(enrol))
            .route("/wire/grant", axum::routing::post(mint))
            .route(
                "/wire/revocations",
                axum::routing::get({
                    let revoked = revoked.clone();
                    move || {
                        let revoked = revoked.lock().unwrap().clone();
                        async move {
                            axum::Json(zs_wire::RevocationsResponse {
                                revoked_grant_ids: revoked,
                            })
                        }
                    }
                }),
            )
            .route("/wire/audit", axum::routing::post(|| async { "" }));
        runtime.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url,
            ca_pem: ca.certificate_pem(),
            grant,
            revoked,
            grant_calls,
            _runtime: runtime,
        }
    }

    pub fn answer(&self, grant: FakeGrant) {
        *self.grant.lock().unwrap() = grant;
    }

    pub fn revoke(&self, grant_id: &str) {
        self.revoked.lock().unwrap().push(grant_id.to_string());
    }

    pub fn grant_calls(&self) -> usize {
        self.grant_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn token_home(&self) -> PlainHome {
        self.token_home_with(https_binding())
    }

    pub fn token_home_with(&self, binding: serde_json::Value) -> PlainHome {
        let home = PlainHome::new(&self.ca_pem);
        home.write_policy(&self.url, binding);
        home
    }

    pub fn token_run(&self, home: &PlainHome) -> (i32, String) {
        home.run(&["--enrollment-token", "enr-fake"])
    }
}

/// The data rows of the SECURITY §7 table, in order (row 1 first). Panics unless there are
/// exactly ninety-seven.
pub fn security_7_rows() -> Vec<String> {
    let security = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/SECURITY.md"),
    )
    .expect("SECURITY.md must be readable");

    let matrix = security
        .split("## 7. Fail-closed matrix")
        .nth(1)
        .expect("SECURITY §7 must exist")
        .split("## 8.")
        .next()
        .expect("§7 must be followed by §8");

    let rows: Vec<String> = matrix
        .lines()
        .filter(|l| l.trim_start().starts_with('|'))
        .filter(|l| !l.contains("---") && !l.contains("Condition"))
        .map(str::to_string)
        .collect();

    assert_eq!(
        rows.len(),
        97,
        "SECURITY §7 must have ninety-seven rows; found {}:\n{}",
        rows.len(),
        rows.join("\n")
    );
    rows
}
