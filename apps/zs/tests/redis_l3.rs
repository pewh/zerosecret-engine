#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "../../../crates/zs-proto-redis/tests/fake/mod.rs"]
mod fake;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct Setup {
    policy: PathBuf,
    creds: PathBuf,
    audit: PathBuf,
    ca_dir: PathBuf,
}

fn write_setup(dir: &Path, port: u16) -> Setup {
    write_setup_for(dir, port, Some(fake::USER), fake::PASSWORD)
}

fn write_setup_for(dir: &Path, port: u16, user: Option<&str>, password: &str) -> Setup {
    write_setup_with(dir, port, user, password, "")
}

fn write_setup_with(
    dir: &Path,
    port: u16,
    user: Option<&str>,
    password: &str,
    extra: &str,
) -> Setup {
    let creds = dir.join(".zs-credentials");
    let audit = dir.join(".zs-audit").join("audit.jsonl");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::create_dir_all(dir.join(".zs-audit")).unwrap();
    std::fs::write(creds.join(fake::RESOURCE), format!("{password}\n")).unwrap();
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
    let user = user
        .map(|user| format!(r#","user":"{user}""#))
        .unwrap_or_default();
    let binding = format!(
        r#"{{"resource":"{}","host":"{}.internal","protocol":"redis","upstream_host":"127.0.0.1","upstream_port":{port}{user},"upstream_plaintext":true{extra}}}"#,
        fake::RESOURCE,
        fake::RESOURCE,
    );
    let connection = common::loopback_connection(port, true);
    let grant = serde_json::to_string(
        &signing
            .sign(zs_grant::Grant {
                subject: common::default_subject(),
                workload: "default".into(),
                resource: fake::RESOURCE.into(),
                host: format!("{}.internal", fake::RESOURCE),
                protocol: "redis".into(),
                source: zs_policy::CredentialSource::file(fake::RESOURCE),
                operations: vec!["connect".into()],
                environment: "development".into(),
                expires_at_ms: now_ms + 3_600_000,
                grant_id: format!("g-{}", fake::RESOURCE),
                materialization: zs_policy::Materialization::Retrieve,
                upstream_host: connection.upstream_host,
                upstream_port: connection.upstream_port,
                upstream_tls: connection.upstream_tls,
                local_endpoint: connection.local_endpoint,
                version: zs_grant::GRANT_VERSION,
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
        agent.redis_port.expect("a `zs: redis` line"),
    ))
}

fn stop(mut agent: common::AgentProcess) {
    let _ = agent.child.kill();
    let _ = agent.child.wait();
}

fn args(parts: &[&[u8]]) -> Vec<Vec<u8>> {
    parts.iter().map(|part| part.to_vec()).collect()
}

async fn wait_for_connect_allows(path: &Path, wanted: usize) {
    for _ in 0..100 {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let count = text
            .lines()
            .filter(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .is_some_and(|record| {
                        record["resource"] == fake::RESOURCE
                            && record["protocol"] == "redis"
                            && record["operation"] == "connect"
                            && record["decision"] == "allow"
                    })
            })
            .count();
        if count >= wanted {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn zs_run_points_the_child_at_the_redis_listener_without_a_credential() {
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), 6379);
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
        env("ZS_ORDERS_REDIS_HOST").as_deref(),
        Some("127.0.0.1"),
        "{out}"
    );
    let port = env("ZS_ORDERS_REDIS_PORT").expect("ZS_ORDERS_REDIS_PORT");
    assert_ne!(
        port, "6379",
        "the port must be the listener, not the upstream server"
    );
    let stored = std::fs::read_to_string(setup.creds.join(fake::RESOURCE)).unwrap();
    assert!(
        stored.contains(fake::PASSWORD),
        "positive control: the credential exists"
    );
    assert!(
        !out.contains(fake::PASSWORD),
        "the password reached the child"
    );
    assert!(!out.lines().any(|l| l.starts_with("REDIS_")), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redis_client_reaches_the_upstream_through_the_broker() {
    let upstream = fake::start(fake::Script::accepting(fake::USER, fake::PASSWORD)).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), upstream.addr.port());
    let agent = spawn(&setup);

    let mut client = fake::logged_in(listener(&agent)).await;
    assert_eq!(client.command(&[b"SET", b"k", b"v"]).await, fake::OK);
    assert_eq!(client.command(&[b"PING"]).await, fake::OK);

    assert!(
        upstream.authenticated(),
        "positive control: the upstream accepted the brokered login"
    );
    assert_eq!(
        upstream.names(),
        vec![
            "AUTH".to_string(),
            "PING".to_string(),
            "SET".to_string(),
            "PING".to_string()
        ]
    );
    assert!(
        upstream.commands().contains(&args(&[b"SET", b"k", b"v"])),
        "{:?}",
        upstream.commands()
    );
    assert!(
        upstream.commands().contains(&args(&[b"PING"])),
        "{:?}",
        upstream.commands()
    );
    assert_eq!(
        upstream.auths(),
        vec![args(&[
            &b"AUTH"[..],
            fake::USER.as_bytes(),
            fake::PASSWORD.as_bytes()
        ])],
        "the only upstream AUTH is the agent's own"
    );
    stop(agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_auth_is_rewritten_and_its_password_never_reaches_upstream() {
    let upstream = fake::start(fake::Script::accepting(fake::USER, fake::PASSWORD)).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), upstream.addr.port());
    let agent = spawn(&setup);

    let mut client = fake::Client::connect(listener(&agent)).await;
    client
        .send_command(&[
            b"AUTH",
            fake::USER.as_bytes(),
            fake::CLIENT_PASSWORD.as_bytes(),
        ])
        .await
        .unwrap();
    assert_eq!(
        client.read_reply().await,
        fake::OK,
        "the rewritten AUTH is accepted upstream"
    );

    let agent_auth = args(&[
        &b"AUTH"[..],
        fake::USER.as_bytes(),
        fake::PASSWORD.as_bytes(),
    ]);
    let auths = upstream.auths();
    assert_eq!(
        auths.len(),
        2,
        "one handshake AUTH (R1) and one rewritten client AUTH (R2): {auths:?}"
    );
    assert!(
        auths.iter().all(|frame| *frame == agent_auth),
        "every upstream AUTH carries the agent's user and credential, never the client's: {auths:?}"
    );
    assert!(
        !upstream.saw_bytes(fake::CLIENT_PASSWORD.as_bytes()),
        "the client password never reaches the upstream: {:?}",
        upstream.frames()
    );
    stop(agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_auth_for_another_user_is_refused() {
    let upstream = fake::start(fake::Script::accepting(fake::USER, fake::PASSWORD)).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), upstream.addr.port());
    let agent = spawn(&setup);

    let mut client = fake::logged_in(listener(&agent)).await;
    let before = upstream.auths();
    assert_eq!(before.len(), 1, "positive control: the brokered login ran");

    client
        .send_command(&[b"AUTH", b"mallory", fake::CLIENT_PASSWORD.as_bytes()])
        .await
        .unwrap();
    let reply = client.read_reply().await;
    assert_eq!(
        fake::error_text(&reply),
        zs_proto_redis::USER_MISMATCH.message,
        "{reply:?}"
    );
    assert_eq!(reply, zs_proto_redis::USER_MISMATCH.frame());
    assert!(client.closed().await, "the refused connection must close");
    assert_eq!(
        upstream.auths(),
        before,
        "the refused AUTH is never forwarded upstream"
    );
    stop(agent);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_audit_journal_records_one_connect_allow_per_connection() {
    let upstream = fake::start(fake::Script::accepting(fake::USER, fake::PASSWORD)).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), upstream.addr.port());
    let agent = spawn(&setup);

    for _ in 0..2 {
        let mut client = fake::logged_in(listener(&agent)).await;
        assert_eq!(client.command(&[b"PING"]).await, fake::OK);
    }
    wait_for_connect_allows(&setup.audit, 2).await;
    stop(agent);

    let audit = std::fs::read_to_string(&setup.audit).unwrap();
    assert!(
        !audit.is_empty(),
        "positive control: the journal has records"
    );
    let records: Vec<serde_json::Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        records.len() >= 2,
        "positive control: at least the two new records exist:\n{audit}"
    );
    let allows = records
        .iter()
        .filter(|record| {
            record["resource"] == fake::RESOURCE
                && record["protocol"] == "redis"
                && record["operation"] == "connect"
                && record["decision"] == "allow"
        })
        .count();
    assert_eq!(
        allows, 2,
        "exactly one connect allow per admitted connection:\n{audit}"
    );
    assert!(
        !audit.contains(fake::PASSWORD),
        "the credential must never reach the journal"
    );
}

#[test]
fn redis_binding_fields_are_checked_at_config_load() {
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
        r#"{{"resource":"a","host":"db","protocol":"redis"}},{{"resource":"b","host":"db","protocol":"redis","user":"u"}},{{"resource":"c","host":"db","protocol":"redis","upstream_plaintext":true}},{{"resource":"d","host":"db","protocol":"redis","user":"u","upstream_ca":{ca}}},{{"resource":"e","host":"db","protocol":"redis","user":"u","upstream_cert_sha256":"{pin}"}},{{"resource":"f","host":"db","protocol":"redis","upstream_auth_optional":true}}"#
    ))
    .expect("positive control: valid redis bindings load");
    let a = &valid.bindings[0];
    assert_eq!(a.upstream(), ("db".to_string(), 6379));
    assert_eq!(a.operations(), vec!["connect".to_string()]);
    assert_eq!(a.env_prefix(), "ZS_A");
    assert_eq!(a.redis_auth(), zs_proto_redis::Auth::new(None));
    assert_eq!(
        valid.bindings[1].redis_auth(),
        zs_proto_redis::Auth::new(Some("u".to_string()))
    );
    assert!(matches!(
        a.redis_tls(),
        Ok(Some(zs_proto_redis::UpstreamTls::WhenOffered))
    ));
    assert!(matches!(valid.bindings[2].redis_tls(), Ok(None)));
    assert_eq!(
        valid.bindings[5].redis_auth(),
        zs_proto_redis::Auth::new(None).with_upstream_optional(true)
    );
    assert!(!a.redis_auth().upstream_optional());
    assert!(matches!(
        valid.bindings[3].redis_tls(),
        Ok(Some(zs_proto_redis::UpstreamTls::Required(_)))
    ));
    assert!(matches!(
        valid.bindings[4].redis_tls(),
        Ok(Some(zs_proto_redis::UpstreamTls::Pinned(_)))
    ));

    for bad in [
        r#"{"resource":"a","host":"db","protocol":"redis","user":""}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"redis","auth_source":"x"}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"redis","auth":{"scheme":"basic"}}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"redis","paths":["/x"]}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"redis","client_auth_plugin":"mysql_native_password"}"#.to_string(),
        format!(r#"{{"resource":"a","host":"db","protocol":"redis","upstream_plaintext":true,"upstream_ca":{ca}}}"#),
        format!(r#"{{"resource":"a","host":"db","protocol":"redis","upstream_plaintext":true,"upstream_cert_sha256":"{pin}"}}"#),
        format!(r#"{{"resource":"a","host":"db","protocol":"redis","upstream_ca":{ca},"upstream_cert_sha256":"{pin}"}}"#),
        r#"{"resource":"a","host":"db","protocol":"redis","listen_port":0}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"mysql","upstream_auth_optional":true}"#.to_string(),
        r#"{"resource":"a","host":"api.stripe.com","upstream_auth_optional":true}"#.to_string(),
        r#"{"resource":"a","host":"api.stripe.com","user":"u"}"#.to_string(),
    ] {
        assert!(load(&bad).is_err(), "must refuse {bad}");
    }
}

#[test]
fn zs_resources_reports_a_redis_binding_as_l3() {
    let dir = tempfile::tempdir().unwrap();
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
    let connection = common::default_connection("orders-redis.internal", "redis");
    let grant = serde_json::to_string(
        &signing
            .sign(zs_grant::Grant {
                subject: "alice".into(),
                workload: "default".into(),
                resource: "orders-redis".into(),
                host: "orders-redis.internal".into(),
                protocol: "redis".into(),
                source: zs_policy::CredentialSource::file("orders-redis"),
                operations: vec!["connect".into()],
                environment: "development".into(),
                expires_at_ms: now_ms + 3_600_000,
                grant_id: "g-orders-redis".into(),
                materialization: zs_policy::Materialization::Retrieve,
                upstream_host: connection.upstream_host,
                upstream_port: connection.upstream_port,
                upstream_tls: connection.upstream_tls,
                local_endpoint: connection.local_endpoint,
                version: zs_grant::GRANT_VERSION,
            })
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("zs-policy.json"),
        format!(
            r#"{{"bindings":[{{"resource":"orders-redis","host":"orders-redis.internal","protocol":"redis","user":"u"}}],"signing_keys":[{{"key_id":"test-k1","verifying_key_hex":"{verifying_hex}"}}],"grants":[{grant}]}}"#
        ),
    )
    .unwrap();
    let output = std::process::Command::new(common::bin_path())
        .arg("resources")
        .env("ZS_HOME", dir.path())
        .env("USER", "alice")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text
        .lines()
        .find(|l| l.starts_with("orders-redis\t"))
        .unwrap_or_else(|| panic!("no orders-redis line: {text}"));
    assert_eq!(line.split('\t').nth(3), Some("L3"), "{line}");
    assert_eq!(
        line.rsplit('\t').next(),
        Some("strict"),
        "a granted redis binding is intercepted; materialization does not decide the label: {line}"
    );
}

const CLIENT_DONE: &str = "zs-redis-client-done";

// A real client against a real Redis through the `zs` binary. The client is an operator's
// command (for example a Node or Go program) that reads `ZS_ORDERS_REDIS_HOST` and
// `ZS_ORDERS_REDIS_PORT` and exits non-zero on any failure.
#[test]
#[ignore = "needs a password-protected Redis on 127.0.0.1 and a client: set ZS_TEST_REDIS_ADDR, ZS_TEST_REDIS_PASSWORD and ZS_TEST_REDIS_CLIENT"]
fn a_real_client_reaches_a_real_redis_through_zs_run() {
    let addr = std::env::var("ZS_TEST_REDIS_ADDR").expect("set ZS_TEST_REDIS_ADDR");
    let password = std::env::var("ZS_TEST_REDIS_PASSWORD").expect("set ZS_TEST_REDIS_PASSWORD");
    let client = std::env::var("ZS_TEST_REDIS_CLIENT").expect("set ZS_TEST_REDIS_CLIENT");
    let user = std::env::var("ZS_TEST_REDIS_USER").ok();
    let (host, port) = addr
        .rsplit_once(':')
        .expect("ZS_TEST_REDIS_ADDR is host:port");
    assert_eq!(host, "127.0.0.1", "the setup signs a loopback upstream");
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup_for(
        dir.path(),
        port.parse().unwrap(),
        user.as_deref(),
        &password,
    );

    let child_env = dir.path().join("child.env");
    let script = format!(
        "/usr/bin/env > '{}' && {client} && echo {CLIENT_DONE}",
        child_env.display()
    );
    let agent = common::spawn_agent_capturing_with_env(
        &common::bin_path(),
        &setup.policy,
        &setup.creds,
        &setup.audit,
        &setup.ca_dir,
        &["/bin/sh", "-c", &script],
        &[("ZS_TEST_REDIS_PASSWORD", ""), ("ZS_TEST_REDIS_CLIENT", "")],
    )
    .expect("agent must run");
    let out = &agent.child_output;
    assert!(
        out.lines().any(|line| line == CLIENT_DONE),
        "the client failed\nstdout:\n{out}\nstderr:\n{}",
        agent.stderr
    );
    let env = std::fs::read_to_string(&child_env).unwrap();
    assert!(
        env.lines()
            .any(|line| line.starts_with("ZS_ORDERS_REDIS_PORT=")),
        "positive control: the child env was written"
    );
    assert!(
        !env.contains(&password) && !out.contains(&password) && !agent.stderr.contains(&password),
        "the credential reached the child or its output"
    );

    let audit = std::fs::read_to_string(&setup.audit).unwrap();
    let records: Vec<serde_json::Value> = audit
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let connect = |decision: &str| {
        records
            .iter()
            .filter(|record| {
                record["resource"] == fake::RESOURCE
                    && record["protocol"] == "redis"
                    && record["operation"] == "connect"
                    && record["decision"] == decision
            })
            .count()
    };
    assert!(connect("allow") >= 1, "no connect allow:\n{audit}");
    assert_eq!(connect("deny"), 0, "a connection was refused:\n{audit}");
    assert!(
        !audit.contains(&password),
        "the credential reached the audit"
    );
    eprintln!("{} connect allow records\n{out}", connect("allow"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_redis_is_served_through_zs_run_only_with_upstream_auth_optional() {
    let open = fake::start(fake::Script::open()).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup_with(
        dir.path(),
        open.addr.port(),
        None,
        fake::PASSWORD,
        r#","upstream_auth_optional":true"#,
    );
    let agent = spawn(&setup);
    let mut client = fake::Client::connect(listener(&agent)).await;
    assert_eq!(
        client.command(&[b"SET", b"k", b"v"]).await,
        fake::OK,
        "the opted-in binding serves the open upstream"
    );
    stop(agent);

    let closed = fake::start(fake::Script::open()).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup_for(dir.path(), closed.addr.port(), None, fake::PASSWORD);
    let agent = spawn(&setup);
    let mut client = fake::Client::connect(listener(&agent)).await;
    assert_eq!(
        client.read_reply().await,
        zs_proto_redis::UPSTREAM_AUTH_FAILED.frame(),
        "without the field the open upstream is refused"
    );
    assert_eq!(closed.names(), vec!["AUTH"]);
    stop(agent);
}
