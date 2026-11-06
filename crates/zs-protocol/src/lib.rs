use zs_credential::Credential;
use zs_identity::{Subject, WorkloadLabel};

pub type CallerCheck =
    std::sync::Arc<dyn Fn(std::net::SocketAddr, std::net::SocketAddr) -> bool + Send + Sync>;

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

pub type Materialize = std::sync::Arc<dyn Fn() -> Result<Credential, Denied> + Send + Sync>;

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterceptedProtocol {
    Https,
    Http,
    Postgres,
    Mysql,
    Mongo,
}

impl InterceptedProtocol {
    pub const ALL: [Self; 5] = [
        Self::Https,
        Self::Http,
        Self::Postgres,
        Self::Mysql,
        Self::Mongo,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
            Self::Mongo => "mongo",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
            Self::Postgres => 5432,
            Self::Mysql => 3306,
            Self::Mongo => 27017,
        }
    }

    pub fn layer(self) -> Layer {
        match self {
            Self::Https | Self::Http => Layer::L7,
            Self::Postgres | Self::Mysql | Self::Mongo => Layer::L3,
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
        ] {
            for value in values {
                assert_eq!(classify_intercepted_protocol(value), Some(expected));
            }
        }
        for value in [
            "",
            "redis",
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
        assert_eq!(InterceptedProtocol::ALL.len(), 5);
    }

    #[test]
    fn default_ports() {
        assert_eq!(InterceptedProtocol::Https.default_port(), 443);
        assert_eq!(InterceptedProtocol::Http.default_port(), 80);
        assert_eq!(InterceptedProtocol::Postgres.default_port(), 5432);
        assert_eq!(InterceptedProtocol::Mysql.default_port(), 3306);
        assert_eq!(InterceptedProtocol::Mongo.default_port(), 27017);
    }

    #[test]
    fn layers_split_l7_from_l3() {
        assert_eq!(InterceptedProtocol::Https.layer(), Layer::L7);
        assert_eq!(InterceptedProtocol::Http.layer(), Layer::L7);
        assert_eq!(InterceptedProtocol::Postgres.layer(), Layer::L3);
        assert_eq!(InterceptedProtocol::Mysql.layer(), Layer::L3);
        assert_eq!(InterceptedProtocol::Mongo.layer(), Layer::L3);
    }
}
