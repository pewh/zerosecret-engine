#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "../../../crates/zs-proto-mongo/tests/fake/mod.rs"]
mod fake;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zs_proto_mongo::bson::Doc;
use zs_proto_mongo::{AUTH_BROKERED, UPSTREAM_AUTH_FAILED};

const RESOURCE: &str = "orders-mongo";

struct Setup {
    policy: PathBuf,
    creds: PathBuf,
    audit: PathBuf,
    ca_dir: PathBuf,
}

fn write_setup(dir: &Path, port: u16, password: &str) -> Setup {
    let creds = dir.join(".zs-credentials");
    let audit = dir.join(".zs-audit").join("audit.jsonl");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::create_dir_all(dir.join(".zs-audit")).unwrap();
    std::fs::write(creds.join(RESOURCE), format!("{password}\n")).unwrap();
    let signing = zs_grant::ControlSigningKey::generate("test-k1");
    let verifying_hex: String = signing
        .verifying_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let binding = format!(
        r#"{{"resource":"{RESOURCE}","host":"{RESOURCE}.internal","protocol":"mongo","upstream_host":"127.0.0.1","upstream_port":{port},"user":"{}","auth_source":"{}","upstream_plaintext":true}}"#,
        fake::USER,
        fake::SOURCE
    );
    let connection = common::loopback_connection(port, true);
    let grant = serde_json::to_string(
        &signing
            .sign(zs_grant::Grant {
                subject: common::default_subject(),
                workload: "default".into(),
                resource: RESOURCE.into(),
                host: format!("{RESOURCE}.internal"),
                protocol: "mongo".into(),
                source: zs_policy::CredentialSource::file(RESOURCE),
                operations: vec!["connect".into()],
                environment: "development".into(),
                expires_at_ms: now_ms + 3_600_000,
                grant_id: format!("g-{RESOURCE}"),
                materialization: zs_policy::Materialization::Retrieve,
                upstream_host: connection.upstream_host,
                upstream_port: connection.upstream_port,
                upstream_tls: connection.upstream_tls,
                local_endpoint: connection.local_endpoint,
            })
            .unwrap(),
    )
    .unwrap();
    let policy = dir.join("zs-policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"bindings":[{binding}],"signing_keys":[{{"key_id":"test-k1","verifying_key_hex":"{verifying_hex}"}}],"grants":[{grant}]}}"#
        ),
    )
    .unwrap();
    Setup {
        policy,
        creds,
        audit,
        ca_dir: dir.join(".zs-ca"),
    }
}

fn spawn(setup: &Setup) -> common::AgentProcess {
    tokio::task::block_in_place(|| {
        common::spawn_agent(
            &common::bin_path(),
            &setup.policy,
            &setup.creds,
            &setup.audit,
            &setup.ca_dir,
            &["sleep", "30"],
            true,
        )
        .expect("agent must start")
    })
}

fn listener(agent: &common::AgentProcess) -> SocketAddr {
    SocketAddr::from((
        [127, 0, 0, 1],
        agent.mongo_port.expect("a `zs: mongo` line"),
    ))
}

fn diag_text(dir: &Path) -> String {
    std::fs::read_dir(dir.join(".zs-log"))
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
                .collect()
        })
        .unwrap_or_default()
}

async fn diag_with(dir: &Path, needle: &str) -> String {
    for _ in 0..100 {
        let text = diag_text(dir);
        if text.contains(needle) {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no {needle} in the diagnostic log: {}", diag_text(dir));
}

fn stop(mut agent: common::AgentProcess) {
    let _ = agent.child.kill();
    let _ = agent.child.wait();
}

#[test]
fn zs_run_points_the_child_at_the_mongo_listener_without_a_credential() {
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), 27017, fake::PASSWORD);
    let agent = common::spawn_agent_capturing(
        &common::bin_path(),
        &setup.policy,
        &setup.creds,
        &setup.audit,
        &setup.ca_dir,
        &["/usr/bin/env"],
    )
    .expect("agent must start");
    let out = &agent.child_output;
    let env = |key: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(format!("{key}=").as_str()))
            .map(str::to_string)
    };
    assert_eq!(
        env("ZS_ORDERS_MONGO_HOST").as_deref(),
        Some("127.0.0.1"),
        "{out}"
    );
    let port = env("ZS_ORDERS_MONGO_PORT").expect("ZS_ORDERS_MONGO_PORT");
    assert_ne!(
        port, "27017",
        "the port must be the listener, not the server"
    );
    let stored = std::fs::read_to_string(setup.creds.join(RESOURCE)).unwrap();
    assert!(
        stored.contains(fake::PASSWORD),
        "positive control: the credential exists"
    );
    assert!(
        !out.contains(fake::PASSWORD),
        "the password reached the child"
    );
    assert!(!out.lines().any(|l| l.starts_with("MONGO_")), "{out}");
}

#[test]
fn mongo_binding_fields_are_checked_at_config_load() {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    let certified = rcgen::generate_simple_self_signed(vec!["db.internal".to_string()]).unwrap();
    std::fs::write(&ca, certified.cert.pem()).unwrap();
    let ca = serde_json::to_string(&ca).unwrap();
    let pin = "ab".repeat(32);
    let load = |bindings: &str| {
        let path = dir.path().join("zs-policy.json");
        std::fs::write(&path, format!(r#"{{"bindings":[{bindings}]}}"#)).unwrap();
        zs::AgentFile::load(&path)
    };

    let valid = load(&format!(
        r#"{{"resource":"a","host":"db","protocol":"mongo","user":"u"}},{{"resource":"b","host":"db.remote","protocol":"mongo","user":"u","auth_source":"appdb","upstream_plaintext":true}},{{"resource":"c","host":"db","protocol":"mongo","user":"u","upstream_ca":{ca}}},{{"resource":"d","host":"db","protocol":"mongo","user":"u","upstream_cert_sha256":"{pin}"}}"#
    ))
    .expect("positive control: valid mongo bindings load");
    let a = &valid.bindings[0];
    assert_eq!(a.upstream(), ("db".to_string(), 27017));
    assert_eq!(a.operations(), vec!["connect".to_string()]);
    assert_eq!(a.env_prefix(), "ZS_A");
    assert_eq!(a.mongo_auth(), Ok(zs_proto_mongo::Auth::new("u", "admin")));
    assert!(matches!(
        a.mongo_tls(),
        Ok(Some(zs_proto_mongo::UpstreamTls::WhenOffered))
    ));
    let b = &valid.bindings[1];
    assert_eq!(b.mongo_auth(), Ok(zs_proto_mongo::Auth::new("u", "appdb")));
    assert!(matches!(b.mongo_tls(), Ok(None)));
    assert!(matches!(
        valid.bindings[2].mongo_tls(),
        Ok(Some(zs_proto_mongo::UpstreamTls::Required(_)))
    ));
    assert!(matches!(
        valid.bindings[3].mongo_tls(),
        Ok(Some(zs_proto_mongo::UpstreamTls::Pinned(_)))
    ));

    for bad in [
        r#"{"resource":"a","host":"db","protocol":"mongo"}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"mongo","user":""}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"mongo","user":"u","auth_source":""}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"postgres","user":"u"}"#.to_string(),
        r#"{"resource":"a","host":"api.stripe.com","auth_source":"x"}"#.to_string(),
        format!(r#"{{"resource":"a","host":"db","protocol":"mongo","user":"u","upstream_plaintext":true,"upstream_ca":{ca}}}"#),
        format!(r#"{{"resource":"a","host":"db","protocol":"mongo","user":"u","upstream_plaintext":true,"upstream_cert_sha256":"{pin}"}}"#),
        format!(r#"{{"resource":"a","host":"db","protocol":"mongo","user":"u","upstream_ca":{ca},"upstream_cert_sha256":"{pin}"}}"#),
        r#"{"resource":"a","host":"db","protocol":"mongo","user":"u","auth":{"scheme":"basic"}}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"mongo","user":"u","paths":["/x"]}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"mongo","user":"u","client_auth_plugin":"mysql_native_password"}"#.to_string(),
        r#"{"resource":"a","host":"db.remote","protocol":"mysql","upstream_plaintext":true}"#.to_string(),
        r#"{"resource":"orders-db","host":"db","protocol":"mongo","user":"u"},{"resource":"orders.db","host":"db","protocol":"postgres"}"#.to_string(),
    ] {
        assert!(load(&bad).is_err(), "must refuse {bad}");
    }
}

#[test]
fn zs_resources_reports_a_mongo_binding_as_l3() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("zs-policy.json"),
        r#"{"bindings":[{"resource":"orders-mongo","host":"db.internal","protocol":"mongo","user":"u"}],"signing_keys":[],"grants":[]}"#,
    )
    .unwrap();
    let output = std::process::Command::new(common::bin_path())
        .arg("resources")
        .env("ZS_HOME", dir.path())
        .env("USER", "alice")
        .current_dir(dir.path())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text
        .lines()
        .find(|l| l.starts_with("orders-mongo\t"))
        .unwrap_or_else(|| panic!("no orders-mongo line: {text}"));
    assert_eq!(line.split('\t').nth(3), Some("L3"), "{line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mongo_client_reaches_the_server_through_zs_run_and_each_step_is_recorded() {
    let upstream = fake::start(fake::Script::set(1, Some(0))).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), upstream.seed().port(), fake::PASSWORD);
    let agent = spawn(&setup);

    let mut client = fake::logged_in(listener(&agent)).await;
    assert!(client.command(fake::find()).await.unwrap().truthy("ok"));
    let refused = client
        .command(Doc::new().with_i32("saslStart", 1).with_str("$db", "admin"))
        .await
        .unwrap();
    fake::assert_error(&refused, 18, AUTH_BROKERED.message);
    assert_eq!(
        upstream.seen(0, |s| s.commands.clone()),
        vec!["find".to_string()]
    );

    let diag = diag_with(dir.path(), "\"client_refused\"").await;
    stop(agent);
    let audit = std::fs::read_to_string(&setup.audit).unwrap();
    let records: Vec<serde_json::Value> = audit
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let count = |decision: &str, operation: &str| {
        records
            .iter()
            .filter(|r| {
                r["resource"] == RESOURCE
                    && r["protocol"] == "mongo"
                    && r["decision"] == decision
                    && r["operation"] == operation
            })
            .count()
    };
    assert_eq!(count("allow", "connect"), 1, "{audit}");
    let find = |decision: &str, operation: &str| {
        records
            .iter()
            .find(|r| {
                r["resource"] == RESOURCE
                    && r["protocol"] == "mongo"
                    && r["decision"] == decision
                    && r["operation"] == operation
            })
            .unwrap()
    };
    assert!(find("allow", "connect").get("reason").is_none(), "{audit}");
    assert_eq!(
        find("deny", "authenticate")["reason"],
        zs_proto_mongo::AUTHENTICATE_REFUSED_REASON,
        "{audit}"
    );
    assert_eq!(count("deny", "authenticate"), 1, "{audit}");
    for needle in [
        "\"component\":\"mongo\"",
        "\"upstream_auth_ok\"",
        "\"client_refused\"",
        "\"audit_seq\"",
        "\"listener_bound\"",
    ] {
        assert!(diag.contains(needle), "missing {needle}: {diag}");
    }
    let stored = std::fs::read_to_string(setup.creds.join(RESOURCE)).unwrap();
    assert!(
        stored.contains(fake::PASSWORD),
        "positive control: the credential exists"
    );
    assert!(!audit.contains(fake::PASSWORD));
    assert!(!diag.contains(fake::PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_brokered_password_fails_upstream_auth_and_relays_nothing() {
    let upstream = fake::start(fake::Script::set(1, Some(0))).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), upstream.seed().port(), fake::WRONG);
    let agent = spawn(&setup);

    let mut client = fake::Client::connect(listener(&agent)).await;
    let reply = client.legacy_handshake().await.unwrap();
    fake::assert_error(&reply, 18, UPSTREAM_AUTH_FAILED.message);
    assert_eq!(
        upstream.seen(0, |s| s.sasl.len()),
        2,
        "positive: the agent answered the server"
    );
    assert!(!upstream.seen(0, |s| s.authenticated));
    assert!(upstream.seen(0, |s| s.commands.is_empty()));
    let diag = diag_with(dir.path(), "\"upstream_auth_failed\"").await;
    stop(agent);
    let stored = std::fs::read_to_string(setup.creds.join(RESOURCE)).unwrap();
    assert!(
        stored.contains(fake::WRONG),
        "positive control: the credential exists"
    );
    assert!(!diag.contains(fake::WRONG));
}
