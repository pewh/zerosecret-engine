#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod issuer;
pub mod net;
mod ssm;
mod sts;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use issuer::TestIssuer;
pub use net::TestCa;
use zs_upstream::http::Network;

pub const DEFAULT_REGION: &str = "ap-southeast-1";
pub const DEFAULT_ISSUER: &str = "https://issuer.zs.test";
pub const AUDIENCE: &str = "sts.amazonaws.com";

#[derive(Clone)]
pub struct TrustRule {
    pub role_arn: String,
    pub sub: String,
    pub parameter_glob: String,
    pub max_session_s: u64,
    pub kms_decrypt: bool,
}

impl TrustRule {
    pub fn new(role_arn: &str, sub: &str) -> Self {
        Self {
            role_arn: role_arn.to_string(),
            sub: sub.to_string(),
            parameter_glob: "arn:aws:ssm:*:*:parameter/*".to_string(),
            max_session_s: 3600,
            kms_decrypt: true,
        }
    }
}

#[derive(Clone)]
pub enum Failure {
    StsRefuse { status: u16, code: String },
    StsGarbage(String),
    SsmRefuse { code: String },
    KmsDenied,
}

pub struct FakeAwsOptions {
    pub region: String,
    pub issuer: String,
    pub jwks_json: String,
    pub trust: Vec<TrustRule>,
    pub delay: Option<Duration>,
    pub fail: Option<Failure>,
}

impl FakeAwsOptions {
    pub fn new(issuer: &TestIssuer, trust: Vec<TrustRule>) -> Self {
        Self {
            region: DEFAULT_REGION.to_string(),
            issuer: issuer.issuer().to_string(),
            jwks_json: issuer.jwks_json(),
            trust,
            delay: None,
            fail: None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ParameterKind {
    String,
    StringList,
    SecureString,
}

impl ParameterKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::String => "String",
            Self::StringList => "StringList",
            Self::SecureString => "SecureString",
        }
    }
}

pub(crate) struct Session {
    pub secret: String,
    pub token: String,
    pub expires_at: u64,
    pub role_arn: String,
    pub session_name: String,
    pub policy: serde_json::Value,
}

pub(crate) struct Param {
    pub kind: ParameterKind,
    pub value: String,
}

pub(crate) struct State {
    pub region: String,
    pub issuer: String,
    pub jwks_json: String,
    pub trust: Vec<TrustRule>,
    pub sessions: HashMap<String, Session>,
    pub params: HashMap<String, Param>,
    pub delay: Option<Duration>,
    pub fail: Option<Failure>,
    pub max_skew_s: u64,
    pub last_sts_form: Vec<(String, String)>,
    pub last_sts_error: Option<String>,
    pub last_ssm_error: Option<String>,
}

#[derive(Default)]
pub(crate) struct Counters {
    pub sts: AtomicUsize,
    pub sts_ok: AtomicUsize,
    pub ssm: AtomicUsize,
    pub ssm_ok: AtomicUsize,
}

pub struct FakeAws {
    state: Arc<Mutex<State>>,
    counters: Arc<Counters>,
    ca: TestCa,
    region: String,
    sts_addr: SocketAddr,
    ssm_addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeAws {
    pub fn start(opts: FakeAwsOptions) -> Self {
        let ca = TestCa::new();
        let region = opts.region.clone();
        let sts_host = format!("sts.{region}.amazonaws.com");
        let ssm_host = format!("ssm.{region}.amazonaws.com");
        let acceptor = ca.acceptor(&[sts_host.as_str(), ssm_host.as_str()]);
        let state = Arc::new(Mutex::new(State {
            region: opts.region,
            issuer: opts.issuer,
            jwks_json: opts.jwks_json,
            trust: opts.trust,
            sessions: HashMap::new(),
            params: HashMap::new(),
            delay: opts.delay,
            fail: opts.fail,
            max_skew_s: 300,
            last_sts_form: Vec::new(),
            last_sts_error: None,
            last_ssm_error: None,
        }));
        let counters = Arc::new(Counters::default());
        let sts_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind sts");
        let ssm_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ssm");
        let sts_addr = sts_listener.local_addr().expect("sts addr");
        let ssm_addr = ssm_listener.local_addr().expect("ssm addr");
        sts_listener.set_nonblocking(true).expect("sts nonblocking");
        ssm_listener.set_nonblocking(true).expect("ssm nonblocking");
        let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
        let sts_handler = sts::handler(state.clone(), counters.clone());
        let ssm_handler = ssm::handler(state.clone(), counters.clone());
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("fake aws runtime");
            runtime.block_on(async move {
                let sts_listener =
                    tokio::net::TcpListener::from_std(sts_listener).expect("sts listener");
                let ssm_listener =
                    tokio::net::TcpListener::from_std(ssm_listener).expect("ssm listener");
                tokio::spawn(net::serve(sts_listener, acceptor.clone(), sts_handler));
                tokio::spawn(net::serve(ssm_listener, acceptor, ssm_handler));
                let _ = stopped.await;
            });
        });
        Self {
            state,
            counters,
            ca,
            region,
            sts_addr,
            ssm_addr,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn sts_host(&self) -> String {
        format!("sts.{}.amazonaws.com", self.region)
    }

    pub fn ssm_host(&self) -> String {
        format!("ssm.{}.amazonaws.com", self.region)
    }

    pub fn sts_addr(&self) -> SocketAddr {
        self.sts_addr
    }

    pub fn ssm_addr(&self) -> SocketAddr {
        self.ssm_addr
    }

    pub fn network(&self) -> Network {
        Network {
            resolve: vec![
                (self.sts_host(), self.sts_addr),
                (self.ssm_host(), self.ssm_addr),
            ],
            extra_roots: vec![self.ca.root_der()],
        }
    }

    pub fn resolve_env(&self) -> String {
        format!(
            "{}={},{}={}",
            self.sts_host(),
            self.sts_addr,
            self.ssm_host(),
            self.ssm_addr
        )
    }

    pub fn root_pem(&self) -> String {
        self.ca.root_pem()
    }

    pub fn sts_calls(&self) -> usize {
        self.counters.sts.load(Ordering::SeqCst)
    }

    pub fn sts_ok(&self) -> usize {
        self.counters.sts_ok.load(Ordering::SeqCst)
    }

    pub fn ssm_calls(&self) -> usize {
        self.counters.ssm.load(Ordering::SeqCst)
    }

    pub fn ssm_ok(&self) -> usize {
        self.counters.ssm_ok.load(Ordering::SeqCst)
    }

    pub fn put_parameter(&self, name: &str, value: &str, kind: ParameterKind) {
        self.state.lock().unwrap().params.insert(
            name.to_string(),
            Param {
                kind,
                value: value.to_string(),
            },
        );
    }

    pub fn set_failure(&self, fail: Option<Failure>) {
        self.state.lock().unwrap().fail = fail;
    }

    pub fn set_delay(&self, delay: Option<Duration>) {
        self.state.lock().unwrap().delay = delay;
    }

    pub fn set_max_skew(&self, seconds: u64) {
        self.state.lock().unwrap().max_skew_s = seconds;
    }

    pub fn set_jwks(&self, jwks_json: &str) {
        self.state.lock().unwrap().jwks_json = jwks_json.to_string();
    }

    pub fn expire_sessions(&self) {
        for session in self.state.lock().unwrap().sessions.values_mut() {
            session.expires_at = 0;
        }
    }

    pub fn session_count(&self) -> usize {
        self.state.lock().unwrap().sessions.len()
    }

    pub fn secrets(&self) -> Vec<String> {
        let state = self.state.lock().unwrap();
        let mut out: Vec<String> = state
            .sessions
            .iter()
            .flat_map(|(akid, s)| [akid.clone(), s.secret.clone(), s.token.clone()])
            .collect();
        out.extend(
            state
                .params
                .values()
                .filter(|p| !p.value.is_empty())
                .map(|p| p.value.clone()),
        );
        out
    }

    pub fn last_sts_form(&self) -> Vec<(String, String)> {
        self.state.lock().unwrap().last_sts_form.clone()
    }

    pub fn last_sts_error(&self) -> Option<String> {
        self.state.lock().unwrap().last_sts_error.clone()
    }

    pub fn last_ssm_error(&self) -> Option<String> {
        self.state.lock().unwrap().last_ssm_error.clone()
    }
}

impl Drop for FakeAws {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn random_string(len: usize, alphabet: &[u8]) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| alphabet[*b as usize % alphabet.len()] as char)
        .collect()
}
