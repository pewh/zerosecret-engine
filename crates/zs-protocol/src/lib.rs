use zs_credential::Credential;
use zs_identity::{Subject, WorkloadLabel};

#[cfg(feature = "session")]
mod front;

#[cfg(feature = "session")]
pub use front::{ClientReadHalf, ClientStream, ClientWriteHalf, FrontListener};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller {
    Tcp {
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
    },
    Unix {
        uid: Option<u32>,
    },
}

const UNKNOWN_LOCAL: std::net::SocketAddr = std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::UNSPECIFIED,
    0,
));

impl Caller {
    pub fn tcp(peer: std::net::SocketAddr, local: std::io::Result<std::net::SocketAddr>) -> Self {
        Self::Tcp {
            peer,
            local: local.unwrap_or(UNKNOWN_LOCAL),
        }
    }
}

pub type CallerCheck = std::sync::Arc<dyn Fn(&Caller) -> bool + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenSpec {
    Tcp(std::net::SocketAddr),
    Unix(std::path::PathBuf),
}

impl ListenSpec {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Tcp(addr) if addr.ip().to_canonical().is_loopback() => "loopback",
            Self::Tcp(_) => "network",
            Self::Unix(_) => "unix",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

impl Destination {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

pub struct Context<'a> {
    pub subject: &'a Subject,
    pub workload: &'a WorkloadLabel,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DenyKind {
    Materialize,
    AuditUnavailable,
    #[default]
    Policy,
}

impl DenyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Materialize => "materialize",
            Self::AuditUnavailable => "audit_unavailable",
            Self::Policy => "policy",
        }
    }
}

pub const REVALIDATE_EVERY: std::time::Duration = std::time::Duration::from_secs(5);
pub const GRANT_REVOKED_REASON: &str = "grant revoked";
pub const ACCESS_CHANGED_REASON: &str = "access changed";

pub fn session_end_code(reason: &str) -> &'static str {
    if reason == ACCESS_CHANGED_REASON {
        "access_changed"
    } else {
        "revoked"
    }
}

pub type SessionCheck = std::sync::Arc<dyn Fn() -> Result<(), &'static str> + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionAccess {
    ReadWrite,
    ReadOnly,
}

pub struct Materialized {
    credential: Credential,
    access: SessionAccess,
    check: SessionCheck,
    #[cfg(feature = "session")]
    wake: Option<tokio::sync::watch::Receiver<u64>>,
}

impl Materialized {
    pub fn new(credential: Credential, access: SessionAccess, check: SessionCheck) -> Self {
        Self {
            credential,
            access,
            check,
            #[cfg(feature = "session")]
            wake: None,
        }
    }

    #[cfg(feature = "session")]
    #[must_use]
    pub fn with_wake(mut self, wake: tokio::sync::watch::Receiver<u64>) -> Self {
        self.wake = Some(wake);
        self
    }

    pub fn access(&self) -> SessionAccess {
        self.access
    }

    pub fn into_parts(self) -> (Credential, SessionWatch) {
        (
            self.credential,
            SessionWatch {
                check: self.check,
                #[cfg(feature = "session")]
                wake: self.wake,
            },
        )
    }
}

#[must_use]
pub struct SessionWatch {
    #[cfg_attr(not(feature = "session"), allow(dead_code))]
    check: SessionCheck,
    #[cfg(feature = "session")]
    wake: Option<tokio::sync::watch::Receiver<u64>>,
}

#[cfg(feature = "session")]
impl SessionWatch {
    pub async fn ended(self) -> &'static str {
        let mut wake = self.wake;
        let mut ticks = tokio::time::interval_at(
            tokio::time::Instant::now() + REVALIDATE_EVERY,
            REVALIDATE_EVERY,
        );
        loop {
            tokio::select! {
                _ = ticks.tick() => {}
                changed = async {
                    match wake.as_mut() {
                        Some(wake) => wake.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if changed.is_err() {
                        wake = None;
                        continue;
                    }
                }
            }
            if let Err(reason) = (self.check)() {
                return reason;
            }
        }
    }
}

pub type Materialize =
    std::sync::Arc<dyn Fn(&Caller) -> Result<Materialized, Denied> + Send + Sync>;

pub type AuditRefusal =
    std::sync::Arc<dyn Fn(&'static str, &'static str) -> Option<u64> + Send + Sync>;

#[cfg(feature = "session")]
pub async fn admitted(check: Option<&CallerCheck>, caller: &Caller) -> bool {
    let unknown = matches!(caller, Caller::Tcp { local, .. } if *local == UNKNOWN_LOCAL);
    let (Some(check), false) = (check, unknown) else {
        return false;
    };
    let (check, caller) = (check.clone(), *caller);
    tokio::task::spawn_blocking(move || check(&caller))
        .await
        .unwrap_or(false)
}

#[derive(Debug, thiserror::Error)]
#[error("denied: {reason}")]
pub struct Denied {
    pub reason: String,
    audit_reason: Option<&'static str>,
    kind: DenyKind,
}

impl Denied {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            audit_reason: None,
            kind: DenyKind::Policy,
        }
    }

    #[must_use]
    pub fn with_kind(mut self, kind: DenyKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn kind(&self) -> DenyKind {
        self.kind
    }

    #[must_use]
    pub fn with_audit_reason(mut self, reason: &'static str) -> Self {
        self.audit_reason = Some(reason);
        self
    }

    pub fn audit_reason(&self) -> &str {
        self.audit_reason.unwrap_or(&self.reason)
    }
}

impl From<String> for Denied {
    fn from(reason: String) -> Self {
        Self::new(reason)
    }
}

impl From<zs_credential::Denied> for Denied {
    fn from(e: zs_credential::Denied) -> Self {
        Self::new(e.reason().to_string())
    }
}

#[derive(Debug, Default)]
pub struct InjectedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl InjectedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    pub fn header_values(&self, name: &str) -> Vec<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|(key, _)| key.to_ascii_lowercase() == lower)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    pub fn remove_header(&mut self, name: &str) {
        let lower = name.to_ascii_lowercase();
        self.headers
            .retain(|(k, _)| k.to_ascii_lowercase() != lower);
    }

    pub fn set_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        self.remove_header(&name);
        self.headers.push((name, value.into()));
    }
}

pub trait Protocol: Send + Sync {
    fn matches(&self, destination: &Destination) -> bool;
    fn authorize(&self, context: &Context) -> Result<(), Denied>;
    fn inject(&self, request: &mut InjectedRequest, credential: &Credential) -> Result<(), Denied>;

    fn inject_message(
        &self,
        _message: &mut Vec<u8>,
        _credential: &Credential,
    ) -> Result<bool, Denied> {
        Ok(false)
    }

    // `authority` is the host the answer URL names, with a port when it is not the default.
    fn resign_url(
        &self,
        _authority: &str,
        _path_and_query: &str,
        _method: &str,
        _credential: &Credential,
    ) -> Result<String, Denied> {
        Err(Denied::new("this auth scheme cannot sign a URL"))
    }

    fn keeps_range(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterceptedProtocol {
    Https,
    Http,
    Postgres,
    Mysql,
    Mongo,
    Redis,
}

impl InterceptedProtocol {
    pub const ALL: [Self; 6] = [
        Self::Https,
        Self::Http,
        Self::Postgres,
        Self::Mysql,
        Self::Mongo,
        Self::Redis,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
            Self::Mongo => "mongo",
            Self::Redis => "redis",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
            Self::Postgres => 5432,
            Self::Mysql => 3306,
            Self::Mongo => 27017,
            Self::Redis => 6379,
        }
    }

    pub fn layer(self) -> Layer {
        match self {
            Self::Https | Self::Http => Layer::L7,
            Self::Postgres | Self::Mysql | Self::Mongo | Self::Redis => Layer::L3,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|protocol| value.eq_ignore_ascii_case(protocol.name()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layer {
    L7,
    L3,
}

pub fn classify_intercepted_protocol(value: &str) -> Option<InterceptedProtocol> {
    InterceptedProtocol::parse(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_audit_reason_defaults_to_the_reason() {
        assert_eq!(
            Denied::new("workload has no grant").audit_reason(),
            "workload has no grant"
        );
        assert_eq!(
            Denied::from("workload has no grant".to_string()).audit_reason(),
            "workload has no grant"
        );
    }

    #[test]
    fn an_audit_reason_changes_only_the_audit_text() {
        let denied = Denied::new("credential reference x not resolvable")
            .with_audit_reason("materialize failed");
        assert_eq!(denied.reason, "credential reference x not resolvable");
        assert_eq!(denied.audit_reason(), "materialize failed");
        assert_eq!(
            denied.to_string(),
            "denied: credential reference x not resolvable"
        );
    }

    #[test]
    fn protocol_classification_is_an_explicit_allowlist() {
        for (values, expected) in [
            (["https", "HTTPS", "hTtPs"], InterceptedProtocol::Https),
            (["http", "HTTP", "hTtP"], InterceptedProtocol::Http),
            (
                ["postgres", "POSTGRES", "pOsTgReS"],
                InterceptedProtocol::Postgres,
            ),
            (["mysql", "MYSQL", "mYsQl"], InterceptedProtocol::Mysql),
            (["mongo", "MONGO", "mOnGo"], InterceptedProtocol::Mongo),
            (["redis", "REDIS", "rEdIs"], InterceptedProtocol::Redis),
        ] {
            for value in values {
                assert_eq!(classify_intercepted_protocol(value), Some(expected));
            }
        }
        for value in [
            "",
            " http",
            "http ",
            "postgresql",
            "mariadb",
            "mysqlx",
            " https",
            "https ",
            "https\n",
            "mysql ",
            "mongodb",
            "mongo ",
        ] {
            assert_eq!(classify_intercepted_protocol(value), None);
        }
    }

    #[test]
    fn every_protocol_round_trips_its_name() {
        for protocol in InterceptedProtocol::ALL {
            assert_eq!(InterceptedProtocol::parse(protocol.name()), Some(protocol));
            assert_eq!(
                InterceptedProtocol::parse(&protocol.name().to_ascii_uppercase()),
                Some(protocol)
            );
        }
        assert_eq!(InterceptedProtocol::ALL.len(), 6);
    }

    #[test]
    fn default_ports() {
        assert_eq!(InterceptedProtocol::Https.default_port(), 443);
        assert_eq!(InterceptedProtocol::Http.default_port(), 80);
        assert_eq!(InterceptedProtocol::Postgres.default_port(), 5432);
        assert_eq!(InterceptedProtocol::Mysql.default_port(), 3306);
        assert_eq!(InterceptedProtocol::Mongo.default_port(), 27017);
        assert_eq!(InterceptedProtocol::Redis.default_port(), 6379);
    }

    #[test]
    fn a_listen_spec_names_its_listener_kind() {
        let tcp = |text: &str| ListenSpec::Tcp(text.parse().unwrap());
        for loopback in [
            "127.0.0.1:5432",
            "127.0.0.2:5432",
            "[::1]:5432",
            "[::ffff:127.0.0.1]:5432",
        ] {
            assert_eq!(tcp(loopback).kind(), "loopback", "{loopback}");
        }
        for network in [
            "172.17.0.1:5433",
            "[fd00::1]:5433",
            "[::ffff:172.17.0.1]:5433",
        ] {
            assert_eq!(tcp(network).kind(), "network", "{network}");
        }
        assert_eq!(
            ListenSpec::Unix("/run/zs/.s.PGSQL.5432".into()).kind(),
            "unix"
        );
    }

    #[test]
    fn layers_split_l7_from_l3() {
        assert_eq!(InterceptedProtocol::Https.layer(), Layer::L7);
        assert_eq!(InterceptedProtocol::Http.layer(), Layer::L7);
        assert_eq!(InterceptedProtocol::Postgres.layer(), Layer::L3);
        assert_eq!(InterceptedProtocol::Mysql.layer(), Layer::L3);
        assert_eq!(InterceptedProtocol::Mongo.layer(), Layer::L3);
        assert_eq!(InterceptedProtocol::Redis.layer(), Layer::L3);
    }

    #[test]
    fn the_diag_code_of_a_session_end_tells_an_access_change_from_a_grant_end() {
        assert_eq!(session_end_code(ACCESS_CHANGED_REASON), "access_changed");
        assert_eq!(session_end_code(GRANT_REVOKED_REASON), "revoked");
        assert_eq!(session_end_code("access unknown"), "revoked");
    }

    #[cfg(feature = "session")]
    mod session {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        use super::super::*;

        const REVOKED: &str = "grant revoked";

        fn checker(fails_from: usize) -> (SessionCheck, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let check: SessionCheck = Arc::new(move || {
                if count.fetch_add(1, Ordering::SeqCst) + 1 >= fails_from {
                    Err(REVOKED)
                } else {
                    Ok(())
                }
            });
            (check, calls)
        }

        fn materialized(check: SessionCheck) -> Materialized {
            let credential = Credential::from_bytes(b"secret".to_vec()).unwrap();
            Materialized::new(credential, SessionAccess::ReadWrite, check)
        }

        fn watch(fails_from: usize) -> (SessionWatch, Arc<AtomicUsize>) {
            let (check, calls) = checker(fails_from);
            let (_, watch) = materialized(check).into_parts();
            (watch, calls)
        }

        fn watch_with(
            fails_from: usize,
            wake: tokio::sync::watch::Receiver<u64>,
        ) -> (SessionWatch, Arc<AtomicUsize>) {
            let (check, calls) = checker(fails_from);
            let (_, watch) = materialized(check).with_wake(wake).into_parts();
            (watch, calls)
        }

        #[tokio::test(start_paused = true)]
        async fn ended_returns_the_first_reason() {
            let (watch, calls) = watch(3);
            let started = tokio::time::Instant::now();
            assert_eq!(watch.ended().await, REVOKED);
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            assert_eq!(started.elapsed(), REVALIDATE_EVERY * 3);
        }

        #[tokio::test(start_paused = true)]
        async fn ended_waits_one_interval_before_the_first_check() {
            let (watch, calls) = watch(1);
            let ended = watch.ended();
            tokio::pin!(ended);
            let early = REVALIDATE_EVERY - Duration::from_millis(1);
            assert!(tokio::time::timeout(early, &mut ended).await.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                tokio::time::timeout(Duration::from_millis(2), &mut ended).await,
                Ok(REVOKED)
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn ended_does_not_return_while_the_check_passes() {
            let (watch, calls) = watch(usize::MAX);
            let waited = REVALIDATE_EVERY * 12 + Duration::from_secs(2);
            assert!(tokio::time::timeout(waited, watch.ended()).await.is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 12);
        }

        #[tokio::test(start_paused = true)]
        async fn ended_checks_at_once_on_a_wake() {
            let (tx, rx) = tokio::sync::watch::channel(0u64);
            let (watch, calls) = watch_with(1, rx);
            let started = tokio::time::Instant::now();
            let ended = watch.ended();
            tokio::pin!(ended);
            tokio::select! {
                _ = tokio::time::sleep(REVALIDATE_EVERY / 5) => {}
                reason = &mut ended => panic!("ended before the wake: {reason}"),
            }
            tx.send(1).unwrap();
            assert_eq!((&mut ended).await, REVOKED);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(
                started.elapsed() < REVALIDATE_EVERY,
                "{:?}",
                started.elapsed()
            );
        }

        #[tokio::test(start_paused = true)]
        async fn a_wake_with_a_passing_check_keeps_the_session() {
            let (tx, rx) = tokio::sync::watch::channel(0u64);
            let (watch, calls) = watch_with(usize::MAX, rx);
            let ended = watch.ended();
            tokio::pin!(ended);
            for value in 1..=3 {
                tx.send(value).unwrap();
                tokio::select! {
                    reason = &mut ended => panic!("ended on a passing check: {reason}"),
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            assert!(
                tokio::time::timeout(REVALIDATE_EVERY * 2, &mut ended)
                    .await
                    .is_err()
            );
        }

        #[tokio::test(start_paused = true)]
        async fn a_dropped_wake_sender_keeps_the_tick() {
            let (tx, rx) = tokio::sync::watch::channel(0u64);
            let (watch, calls) = watch_with(3, rx);
            drop(tx);
            let started = tokio::time::Instant::now();
            assert_eq!(watch.ended().await, REVOKED);
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            assert_eq!(started.elapsed(), REVALIDATE_EVERY * 3);
        }

        #[tokio::test]
        async fn admitted_is_false_without_a_check() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (accepted, peer) = listener.accept().await.unwrap();
            let caller = Caller::tcp(peer, accepted.local_addr());
            let allow: CallerCheck = Arc::new(|_| true);
            let refuse: CallerCheck = Arc::new(|_| false);
            let panics: CallerCheck = Arc::new(|_| panic!("the caller check panicked"));
            assert!(admitted(Some(&allow), &caller).await);
            assert!(!admitted(None, &caller).await);
            assert!(!admitted(Some(&refuse), &caller).await);
            assert!(!admitted(Some(&panics), &caller).await);
        }

        #[tokio::test]
        async fn the_check_gets_the_caller() {
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let record = seen.clone();
            let check: CallerCheck = Arc::new(move |caller| {
                record.lock().unwrap().push(*caller);
                true
            });
            let tcp = Caller::Tcp {
                peer: "127.0.0.1:40001".parse().unwrap(),
                local: "127.0.0.1:5432".parse().unwrap(),
            };
            let unix = Caller::Unix { uid: Some(501) };
            assert!(admitted(Some(&check), &tcp).await);
            assert!(admitted(Some(&check), &unix).await);
            assert_eq!(*seen.lock().unwrap(), vec![tcp, unix]);
        }

        #[tokio::test]
        async fn a_tcp_caller_without_a_local_address_is_refused_before_the_check() {
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let allow: CallerCheck = Arc::new(move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                true
            });
            let peer: std::net::SocketAddr = "127.0.0.1:40001".parse().unwrap();
            let known = Caller::tcp(peer, Ok("127.0.0.1:5432".parse().unwrap()));
            assert!(admitted(Some(&allow), &known).await);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let unknown = Caller::tcp(
                peer,
                Err(std::io::Error::from(std::io::ErrorKind::NotConnected)),
            );
            assert!(!admitted(Some(&allow), &unknown).await);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
}
