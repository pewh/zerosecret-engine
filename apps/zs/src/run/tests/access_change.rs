use std::cell::Cell;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;

use super::*;

mod mongo;
mod mysql;
mod postgres;
mod redis;

const ACCESS_CHANGED: &str = "access changed";
const POOL: usize = 4;
const CLOSE_BOUND: Duration = zs_protocol::REVALIDATE_EVERY.saturating_add(Duration::from_secs(2));
const ONE_TICK: Duration = zs_protocol::REVALIDATE_EVERY.saturating_add(Duration::from_secs(1));

struct Spec {
    resource: &'static str,
    protocol: &'static str,
    extra: String,
    plaintext: bool,
    password: &'static str,
}

fn grant(
    key: &zs_grant::ControlSigningKey,
    spec: &Spec,
    port: u16,
    grant_id: &str,
    access: zs_policy::Access,
) -> zs_grant::SignedGrant {
    let version = match access {
        zs_policy::Access::ReadWrite => zs_grant::GRANT_VERSION,
        zs_policy::Access::ReadOnly => zs_grant::GRANT_VERSION_ACCESS,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    key.sign(zs_grant::Grant {
        subject: "alice".into(),
        workload: "default".into(),
        resource: spec.resource.into(),
        host: format!("{}.internal", spec.resource),
        protocol: spec.protocol.into(),
        source: zs_policy::CredentialSource::file(spec.resource),
        operations: vec!["connect".into()],
        environment: "development".into(),
        expires_at_ms: now + 600_000,
        grant_id: grant_id.into(),
        materialization: zs_policy::Materialization::Retrieve,
        upstream_host: "127.0.0.1".into(),
        upstream_port: port,
        upstream_tls: if spec.plaintext {
            zs_policy::UpstreamTlsMode::Plaintext
        } else {
            zs_policy::UpstreamTlsMode::Default
        },
        local_endpoint: false,
        listen_addr: None,
        listen_allow: Vec::new(),
        access,
        version,
    })
    .unwrap()
}

struct Rig {
    services: RunningServices,
    prepared: PreparedRun,
    key: zs_grant::ControlSigningKey,
    spec: Spec,
    port: u16,
    next_grant: Cell<u32>,
    home: tempfile::TempDir,
}

impl Rig {
    fn start(
        runtime: tokio::runtime::Runtime,
        spec: Spec,
        port: u16,
        access: zs_policy::Access,
    ) -> Self {
        let home = tempfile::tempdir().unwrap();
        let credentials = home.path().join(".zs-credentials");
        std::fs::create_dir_all(&credentials).unwrap();
        std::fs::write(
            credentials.join(spec.resource),
            format!("{}\n", spec.password),
        )
        .unwrap();
        let policy = home.path().join("zs-policy.json");
        std::fs::write(
            &policy,
            format!(
                r#"{{"bindings":[{{"resource":"{resource}","host":"{resource}.internal","protocol":"{protocol}","upstream_host":"127.0.0.1","upstream_port":{port}{extra}}}],"signing_keys":[],"grants":[]}}"#,
                resource = spec.resource,
                protocol = spec.protocol,
                extra = spec.extra,
            ),
        )
        .unwrap();
        let file = AgentFile::load(&policy).unwrap();
        let key = zs_grant::ControlSigningKey::generate("k1");
        let grants = GrantCache::new();
        grants.insert(grant(&key, &spec, port, "g-1", access));
        let agent = std::sync::Arc::new(AgentHandler::from_grants(
            Subject::new("alice").unwrap(),
            WorkloadLabel::new("default").unwrap(),
            file.bindings.clone(),
            grants,
            zs_grant::AgentVerifier::new(vec![(
                key.key_id().to_string(),
                ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
            )]),
            std::sync::Arc::new(zs_materializer::Materializer::new(
                zs_materializer::StoreRegistry::new(std::sync::Arc::new(
                    zs_materializer::FileStore::new(&credentials),
                )),
                std::sync::Arc::new(UnconfiguredExchange),
            )),
        ));
        let prepared = PreparedRun {
            file,
            journal: std::sync::Arc::new(Journal::open(home.path().join("audit.jsonl")).unwrap()),
            shipped: std::sync::Arc::new(tokio::sync::Mutex::new(0)),
            ca: std::sync::Arc::new(LocalCa::load_or_create(home.path().join(".zs-ca")).unwrap()),
            wire: None,
            revocation_cursor: None,
            revocation_hold: false,
            revocation_started: std::time::Instant::now(),
            stored: false,
            agent,
            audit_subject: "alice".into(),
            audit_workload: "default".into(),
            runtime,
            diag: DiagLog::open_with_cap(&home.path().join("diag.jsonl"), "t-1", 1 << 20).unwrap(),
        };
        let services = prepared
            .runtime
            .block_on(start_services(
                &prepared,
                &args_listening(home.path(), "127.0.0.1:0"),
            ))
            .unwrap_or_else(|code| panic!("start_services failed with {code}"));
        assert_eq!(services.l3.len(), 1);
        Self {
            services,
            prepared,
            key,
            spec,
            port,
            next_grant: Cell::new(2),
            home,
        }
    }

    fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.prepared.runtime
    }

    fn listener(&self) -> std::net::SocketAddr {
        self.services.l3[0].1
    }

    fn renew(&self, access: zs_policy::Access) -> Instant {
        let id = format!("g-{}", self.next_grant.replace(self.next_grant.get() + 1));
        assert_eq!(
            renewal(
                &self.prepared.agent,
                &self.prepared.file.bindings[0],
                Ok(grant(&self.key, &self.spec, self.port, &id, access).into()),
                None,
                true,
                &DiagLog::disabled()
            ),
            Ok(format!("zs: renewed grant {id} for {}", self.spec.resource))
        );
        Instant::now()
    }

    fn records(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.home.path().join("audit.jsonl"))
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .filter(|record: &serde_json::Value| {
                record["resource"] == self.spec.resource && record["operation"] == "connect"
            })
            .collect()
    }

    fn allowed(&self) -> usize {
        self.records()
            .iter()
            .filter(|record| record["decision"] == "allow")
            .count()
    }

    fn denied(&self, reason: Option<&str>) -> usize {
        self.records()
            .iter()
            .filter(|record| {
                record["decision"] == "deny"
                    && reason.is_none_or(|reason| record["reason"] == reason)
            })
            .count()
    }

    async fn denials_reach(&self, reason: &str, wanted: usize) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while self.denied(Some(reason)) < wanted && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn assert_connects(&self, allowed: usize, access_changed: usize) {
        let records = format!("{:?}", self.records());
        assert_eq!(self.allowed(), allowed, "{records}");
        assert_eq!(
            self.denied(Some(ACCESS_CHANGED)),
            access_changed,
            "{records}"
        );
        assert_eq!(self.denied(None), access_changed, "{records}");
        std::thread::sleep(Duration::from_millis(300));
        self.prepared.diag.close();
        let log = std::fs::read_to_string(self.home.path().join("diag.jsonl")).unwrap();
        let reasons: Vec<String> = log
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["event"] == "client_refused")
            .map(|event| {
                event["fields"]["reason"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        assert_eq!(
            reasons,
            vec!["access_changed".to_string(); access_changed],
            "the diag log names an access change, not a revocation: {log}"
        );
    }
}

async fn closes_within_bound(stream: &mut tokio::net::TcpStream, held: Instant) {
    let mut rest = Vec::new();
    let read = tokio::time::timeout_at(
        tokio::time::Instant::from_std(held + CLOSE_BOUND),
        stream.read_to_end(&mut rest),
    )
    .await;
    assert!(
        read.is_ok(),
        "the session was still open {CLOSE_BOUND:?} after the agent held the new access level"
    );
    assert!(
        rest.is_empty(),
        "the agent wrote on the session that it ended"
    );
}
