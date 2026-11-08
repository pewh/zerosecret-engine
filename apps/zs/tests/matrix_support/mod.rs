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
        version: zs_grant::GRANT_VERSION,
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
    user_agents: Arc<std::sync::Mutex<Vec<String>>>,
    signing_key: Arc<std::sync::Mutex<ControlSigningKey>>,
    key_set: Arc<std::sync::Mutex<Vec<zs_wire::VerifyingKeyEntry>>>,
    mint_version: Arc<std::sync::atomic::AtomicU32>,
    mint_environment: Arc<std::sync::Mutex<String>>,
    _runtime: tokio::runtime::Runtime,
}

#[cfg(unix)]
impl FakeControl {
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn set_signing_key(&self, key_id: &str, seed: [u8; 32]) {
        *self.signing_key.lock().unwrap() = ControlSigningKey::from_bytes(key_id, &seed);
    }

    pub fn set_key_set(&self, entries: Vec<zs_wire::VerifyingKeyEntry>) {
        *self.key_set.lock().unwrap() = entries;
    }

    pub fn key_set(&self) -> Vec<zs_wire::VerifyingKeyEntry> {
        self.key_set.lock().unwrap().clone()
    }

    pub fn set_minted_version(&self, version: u32) {
        self.mint_version
            .store(version, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set_minted_environment(&self, environment: &str) {
        *self.mint_environment.lock().unwrap() = environment.to_string();
    }

    pub fn user_agents(&self) -> Vec<String> {
        self.user_agents.lock().unwrap().clone()
    }

    pub fn start() -> Self {
        use axum::response::IntoResponse;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let ca = Arc::new(crate::common::test_ca::TestCa::generate("fake-control").unwrap());
        let key = Arc::new(std::sync::Mutex::new(ControlSigningKey::generate(
            "control-k1",
        )));
        let key_set: Arc<std::sync::Mutex<Vec<zs_wire::VerifyingKeyEntry>>> = Arc::default();
        let grant = Arc::new(std::sync::Mutex::new(FakeGrant::Mint {
            host: HOST.into(),
            protocol: "https".into(),
        }));
        let revoked: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let grant_calls: Arc<std::sync::atomic::AtomicUsize> = Arc::default();
        let user_agents: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let mint_version = Arc::new(std::sync::atomic::AtomicU32::new(zs_grant::GRANT_VERSION));
        let mint_environment: Arc<std::sync::Mutex<String>> =
            Arc::new(std::sync::Mutex::new("development".to_string()));
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let enrol = {
            let (ca, key, url) = (ca.clone(), key.clone(), url.clone());
            let agents = user_agents.clone();
            move |headers: axum::http::HeaderMap,
                  axum::Json(request): axum::Json<zs_wire::EnrollmentRequest>| async move {
                if let Some(value) = headers.get(axum::http::header::USER_AGENT) {
                    agents
                        .lock()
                        .unwrap()
                        .push(value.to_str().unwrap_or_default().to_string());
                }
                let (verifying_key, key_id) = {
                    let current = key.lock().unwrap();
                    (
                        current.verifying_key_bytes().to_vec(),
                        current.key_id().to_string(),
                    )
                };
                axum::Json(zs_wire::EnrollmentResponse {
                    device_id: "dev-fake".into(),
                    organization: "default".into(),
                    client_certificate: ca
                        .issue_client_certificate(&request.csr, "dev-fake", "default")
                        .unwrap(),
                    grant_verifying_key: verifying_key,
                    grant_verifying_key_id: key_id,
                    wire_url: url,
                    grant_verifying_keys: Vec::new(),
                    control_ca_pems: Vec::new(),
                    environment: None,
                })
            }
        };
        let mint = {
            let (key, grant, grant_calls) = (key.clone(), grant.clone(), grant_calls.clone());
            let agents = user_agents.clone();
            let version = mint_version.clone();
            let environment = mint_environment.clone();
            move |headers: axum::http::HeaderMap,
                  axum::Json(request): axum::Json<serde_json::Value>| async move {
                use std::sync::atomic::Ordering;
                if let Some(value) = headers.get(axum::http::header::USER_AGENT) {
                    agents
                        .lock()
                        .unwrap()
                        .push(value.to_str().unwrap_or_default().to_string());
                }
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
                let signed = if forged {
                    ControlSigningKey::generate("control-k1")
                        .sign(Grant {
                            subject: text("subject"),
                            workload: text("workload"),
                            resource: text("resource"),
                            host,
                            protocol,
                            source,
                            operations: serde_json::from_value(request["operations"].clone())
                                .unwrap_or_default(),
                            environment: environment.lock().unwrap().clone(),
                            expires_at_ms: now_ms() + expires_in_ms,
                            grant_id: "g-fake".into(),
                            materialization: zs_policy::Materialization::Retrieve,
                            upstream_host: connection.upstream_host,
                            upstream_port: connection.upstream_port,
                            upstream_tls: connection.upstream_tls,
                            local_endpoint: connection.local_endpoint,
                            version: version.load(std::sync::atomic::Ordering::SeqCst),
                        })
                        .unwrap()
                } else {
                    let signer = key.lock().unwrap();
                    signer
                        .sign(Grant {
                            subject: text("subject"),
                            workload: text("workload"),
                            resource: text("resource"),
                            host,
                            protocol,
                            source,
                            operations: serde_json::from_value(request["operations"].clone())
                                .unwrap_or_default(),
                            environment: environment.lock().unwrap().clone(),
                            expires_at_ms: now_ms() + expires_in_ms,
                            grant_id: "g-fake".into(),
                            materialization: zs_policy::Materialization::Retrieve,
                            upstream_host: connection.upstream_host,
                            upstream_port: connection.upstream_port,
                            upstream_tls: connection.upstream_tls,
                            local_endpoint: connection.local_endpoint,
                            version: version.load(std::sync::atomic::Ordering::SeqCst),
                        })
                        .unwrap()
                };
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
                    let agents = user_agents.clone();
                    let keys = key_set.clone();
                    move |headers: axum::http::HeaderMap| {
                        let revoked = revoked.lock().unwrap().clone();
                        if let Some(value) = headers.get(axum::http::header::USER_AGENT) {
                            agents
                                .lock()
                                .unwrap()
                                .push(value.to_str().unwrap_or_default().to_string());
                        }
                        async move {
                            axum::Json(zs_wire::RevocationsResponse {
                                revoked_grant_ids: revoked,
                                grant_verifying_keys: keys.lock().unwrap().clone(),
                                control_ca_pems: Vec::new(),
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
            user_agents,
            signing_key: key,
            key_set,
            mint_version,
            mint_environment,
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
/// exactly one hundred and fifteen.
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
        116,
        "SECURITY §7 must have one hundred and sixteen rows; found {}:\n{}",
        rows.len(),
        rows.join("\n")
    );
    rows
}

/// A TLS wire endpoint whose leaf certificate can be swapped, for the CA-trust rows.
#[cfg(unix)]
pub struct TlsWire {
    pub url: String,
    server: Arc<std::sync::Mutex<Arc<rustls::ServerConfig>>>,
    keys: Arc<std::sync::Mutex<Vec<zs_wire::VerifyingKeyEntry>>>,
    ca_pems: Arc<std::sync::Mutex<Vec<String>>>,
    requests: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(unix)]
impl TlsWire {
    pub fn start(ca: &crate::common::test_ca::TestCa) -> Self {
        let (chain, key) = ca.issue_server_certificate("127.0.0.1").unwrap();
        let server = Arc::new(std::sync::Mutex::new(Arc::new(server_config(&chain, &key))));
        let keys: Arc<std::sync::Mutex<Vec<zs_wire::VerifyingKeyEntry>>> = Arc::default();
        let ca_pems: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let requests: Arc<std::sync::atomic::AtomicUsize> = Arc::default();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());

        let accepting = server.clone();
        let served_keys = keys.clone();
        let served_pems = ca_pems.clone();
        let counted = requests.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let config = accepting.lock().unwrap().clone();
                    let keys = served_keys.clone();
                    let pems = served_pems.clone();
                    let counted = counted.clone();
                    tokio::spawn(async move {
                        let acceptor = tokio_rustls::TlsAcceptor::from(config);
                        let Ok(mut tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut request = Vec::new();
                        let mut buffer = [0u8; 1024];
                        loop {
                            match tokio::io::AsyncReadExt::read(&mut tls, &mut buffer).await {
                                Ok(0) | Err(_) => return,
                                Ok(read) => {
                                    request.extend_from_slice(&buffer[..read]);
                                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                        break;
                                    }
                                    if request.len() > 16 * 1024 {
                                        return;
                                    }
                                }
                            }
                        }
                        let head = String::from_utf8_lossy(&request);
                        let path = head
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or_default()
                            .to_string();
                        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let body = match path.as_str() {
                            "/wire/revocations" => serde_json::json!({
                                "revoked_grant_ids": [],
                                "grant_verifying_keys": *keys.lock().unwrap(),
                                "control_ca_pems": *pems.lock().unwrap(),
                            })
                            .to_string(),
                            "/wire/audit" => String::new(),
                            _ => String::new(),
                        };
                        let status = if path == "/wire/revocations" || path == "/wire/audit" {
                            "200 OK"
                        } else {
                            "404 Not Found"
                        };
                        let response = format!(
                            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = tokio::io::AsyncWriteExt::write_all(&mut tls, response.as_bytes()).await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut tls).await;
                    });
                }
            });
        });

        Self {
            url,
            server,
            keys,
            ca_pems,
            requests,
        }
    }

    pub fn set_leaf(&self, ca: &crate::common::test_ca::TestCa) {
        let (chain, key) = ca.issue_server_certificate("127.0.0.1").unwrap();
        *self.server.lock().unwrap() = Arc::new(server_config(&chain, &key));
    }

    pub fn set_ca_pems(&self, pems: Vec<String>) {
        *self.ca_pems.lock().unwrap() = pems;
    }

    pub fn set_keys(&self, keys: Vec<zs_wire::VerifyingKeyEntry>) {
        *self.keys.lock().unwrap() = keys;
    }

    pub fn requests(&self) -> usize {
        self.requests.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(unix)]
fn server_config(chain: &str, key: &str) -> rustls::ServerConfig {
    use rustls::pki_types::pem::PemObject;
    let certificates: Vec<rustls::pki_types::CertificateDer<'static>> = chain
        .split_inclusive("-----END CERTIFICATE-----\n")
        .filter(|block| block.contains("BEGIN CERTIFICATE"))
        .map(|block| rustls::pki_types::CertificateDer::from_pem_slice(block.as_bytes()).unwrap())
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap()
}
