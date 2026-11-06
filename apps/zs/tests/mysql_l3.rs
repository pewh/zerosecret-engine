#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "../../../crates/zs-proto-mysql/tests/fake/mod.rs"]
mod fake;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fake::{CLIENT_CAPS, Flow, PASSWORD, Script, WRONG};
use zs_proto_mysql::packet;
use zs_proto_mysql::{CHANGE_USER_REFUSED, UPSTREAM_AUTH_FAILED, USER_REFUSED};

const RESOURCE: &str = "orders-mysql";

struct Setup {
    policy: PathBuf,
    creds: PathBuf,
    audit: PathBuf,
    ca_dir: PathBuf,
}

fn write_setup(dir: &Path, bindings: &[(&str, &str, u16)], password: &str) -> Setup {
    let creds = dir.join(".zs-credentials");
    let audit = dir.join(".zs-audit").join("audit.jsonl");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::create_dir_all(dir.join(".zs-audit")).unwrap();
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
    let mut entries = Vec::new();
    let mut grants = Vec::new();
    for (resource, protocol, port) in bindings {
        std::fs::write(creds.join(resource), format!("{password}\n")).unwrap();
        entries.push(format!(
            r#"{{"resource":"{resource}","host":"{resource}.internal","protocol":"{protocol}","upstream_host":"127.0.0.1","upstream_port":{port}}}"#
        ));
        let connection = common::loopback_connection(*port, false);
        grants.push(
            serde_json::to_string(
                &signing
                    .sign(zs_grant::Grant {
                        subject: common::default_subject(),
                        workload: "default".into(),
                        resource: (*resource).into(),
                        host: format!("{resource}.internal"),
                        protocol: (*protocol).into(),
                        source: zs_policy::CredentialSource::file(*resource),
                        operations: vec!["connect".into()],
                        environment: "development".into(),
                        expires_at_ms: now_ms + 3_600_000,
                        grant_id: format!("g-{resource}"),
                        materialization: zs_policy::Materialization::Retrieve,
                        upstream_host: connection.upstream_host,
                        upstream_port: connection.upstream_port,
                        upstream_tls: connection.upstream_tls,
                        local_endpoint: connection.local_endpoint,
                    })
                    .unwrap(),
            )
            .unwrap(),
        );
    }
    let policy = dir.join("zs-policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"bindings":[{}],"signing_keys":[{{"key_id":"test-k1","verifying_key_hex":"{verifying_hex}"}}],"grants":[{}]}}"#,
            entries.join(","),
            grants.join(",")
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
        agent.mysql_port.expect("a `zs: mysql` line"),
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
fn zs_run_points_the_child_at_each_l3_listener_without_a_password() {
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(
        dir.path(),
        &[(RESOURCE, "mysql", 3306), ("orders-pg", "postgres", 5432)],
        PASSWORD,
    );
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

    assert_eq!(env("MYSQL_HOST").as_deref(), Some("127.0.0.1"), "{out}");
    let port = env("MYSQL_TCP_PORT").expect("MYSQL_TCP_PORT");
    assert_ne!(
        port, "3306",
        "MYSQL_TCP_PORT must be the listener, not the server"
    );
    assert_eq!(env("ZS_ORDERS_MYSQL_HOST").as_deref(), Some("127.0.0.1"));
    assert_eq!(env("ZS_ORDERS_MYSQL_PORT"), Some(port));
    assert_eq!(env("ZS_ORDERS_PG_HOST").as_deref(), Some("127.0.0.1"));
    assert_eq!(env("ZS_ORDERS_PG_PORT"), env("PGPORT"));
    let stored = std::fs::read_to_string(setup.creds.join(RESOURCE)).unwrap();
    assert!(
        stored.contains(PASSWORD),
        "positive control: the credential exists"
    );
    assert!(!out.contains(PASSWORD), "the password reached the child");
    assert!(!out.contains("MYSQL_PWD"));
}

#[test]
fn mysql_binding_fields_are_checked_at_config_load() {
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
        r#"{{"resource":"a","host":"db","protocol":"mysql","upstream_ca":{ca}}},{{"resource":"b","host":"db","protocol":"mysql","upstream_cert_sha256":"{pin}"}},{{"resource":"c","host":"db","protocol":"mysql"}},{{"resource":"d","host":"db","protocol":"mysql","client_auth_plugin":"mysql_native_password"}},{{"resource":"e","host":"db","protocol":"mysql","user":"app"}},{{"resource":"f","host":"db","protocol":"postgres","user":"app"}}"#
    ))
    .expect("positive control: valid mysql bindings load");
    assert_eq!(valid.bindings[4].user.as_deref(), Some("app"));
    assert_eq!(valid.bindings[5].user.as_deref(), Some("app"));
    assert_eq!(valid.bindings[2].upstream(), ("db".to_string(), 3306));
    assert_eq!(valid.bindings[2].operations(), vec!["connect".to_string()]);
    assert_eq!(valid.bindings[2].env_prefix(), "ZS_C");
    assert_eq!(
        valid.bindings[2].mysql_client_auth(),
        Ok(zs_proto_mysql::ClientAuth::CachingSha2)
    );
    assert_eq!(
        valid.bindings[3].mysql_client_auth(),
        Ok(zs_proto_mysql::ClientAuth::Native)
    );

    for bad in [
        format!(
            r#"{{"resource":"a","host":"db","protocol":"mysql","upstream_ca":{ca},"upstream_cert_sha256":"{pin}"}}"#
        ),
        r#"{"resource":"a","host":"db","protocol":"mysql","upstream_ca":"/nonexistent/zs-ca.pem"}"#
            .to_string(),
        r#"{"resource":"a","host":"db","protocol":"mysql","upstream_cert_sha256":"abc"}"#.to_string(),
        format!(r#"{{"resource":"a","host":"api.stripe.com","upstream_ca":{ca}}}"#),
        r#"{"resource":"a","host":"db","protocol":"mysql","auth":{"scheme":"basic"}}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"mysql","paths":["/x"]}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"mysql","client_auth_plugin":"sha256_password"}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"mysql","user":""}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"postgres","user":""}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"mysql","user":"app","auth_source":"admin"}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"postgres","auth_source":"admin"}"#.to_string(),
        r#"{"resource":"a","host":"api.stripe.com","user":"app"}"#.to_string(),
        r#"{"resource":"a","host":"db","protocol":"postgres","client_auth_plugin":"mysql_native_password"}"#.to_string(),
        r#"{"resource":"orders-db","host":"db","protocol":"mysql"},{"resource":"orders.db","host":"db","protocol":"postgres"}"#
            .to_string(),
    ] {
        assert!(load(&bad).is_err(), "must refuse {bad}");
    }
}

#[test]
fn listen_port_is_checked_at_config_load() {
    let dir = tempfile::tempdir().unwrap();
    let load = |bindings: &str| {
        let path = dir.path().join("zs-policy.json");
        std::fs::write(&path, format!(r#"{{"bindings":[{bindings}]}}"#)).unwrap();
        zs::AgentFile::load(&path)
    };

    let valid = load(
        r#"{"resource":"a","host":"db","protocol":"mysql","listen_port":13306},{"resource":"b","host":"db","protocol":"postgres","listen_port":15432},{"resource":"c","host":"db","protocol":"mongo","user":"app","listen_port":27117},{"resource":"d","host":"db","protocol":"mysql"}"#,
    )
    .expect("positive control: listen_port on each L3 protocol loads");
    assert_eq!(valid.bindings[0].listen_addr(), "127.0.0.1:13306");
    assert_eq!(valid.bindings[3].listen_addr(), "127.0.0.1:0");

    for bad in [
        r#"{"resource":"a","host":"api.stripe.com","listen_port":13306}"#,
        r#"{"resource":"a","host":"db","protocol":"mysql","listen_port":0}"#,
        r#"{"resource":"a","host":"db","protocol":"mysql","listen_port":13306},{"resource":"b","host":"db","protocol":"postgres","listen_port":13306}"#,
    ] {
        assert!(load(bad).is_err(), "must refuse {bad}");
    }
}

fn with_listen_port(setup: &Setup, upstream_port: u16, listen_port: u16) {
    let policy = std::fs::read_to_string(&setup.policy).unwrap();
    let from = format!(r#""upstream_port":{upstream_port}}}"#);
    assert!(policy.contains(&from), "{policy}");
    std::fs::write(
        &setup.policy,
        policy.replacen(
            &from,
            &format!(r#""upstream_port":{upstream_port},"listen_port":{listen_port}}}"#),
            1,
        ),
    )
    .unwrap();
}

#[test]
fn zs_run_binds_the_mysql_listener_on_its_listen_port() {
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), &[(RESOURCE, "mysql", 3306)], PASSWORD);
    let port = common::free_port();
    with_listen_port(&setup, 3306, port);
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

    let stderr = &agent.stderr;
    assert_eq!(
        env("ZS_ORDERS_MYSQL_PORT"),
        Some(port.to_string()),
        "{out}{stderr}"
    );
    assert_eq!(env("MYSQL_TCP_PORT"), Some(port.to_string()), "{stderr}");
}

#[test]
fn zs_run_refuses_to_start_when_the_listen_port_is_taken() {
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), &[(RESOURCE, "mysql", 3306)], PASSWORD);
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    with_listen_port(&setup, 3306, taken.local_addr().unwrap().port());
    let marker = dir.path().join("child-ran");
    let output = std::process::Command::new(common::bin_path())
        .args(["run", "--policy"])
        .arg(&setup.policy)
        .arg("--credentials-dir")
        .arg(&setup.creds)
        .arg("--audit")
        .arg(&setup.audit)
        .arg("--ca-dir")
        .arg(&setup.ca_dir)
        .args(["--", "/usr/bin/touch"])
        .arg(&marker)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "zs run must refuse a taken listen_port"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("mysql listener for orders-mysql"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "the child must not start");
}

#[test]
fn zs_resources_reports_a_mysql_binding_as_l3() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("zs-policy.json"),
        r#"{"bindings":[{"resource":"orders-mysql","host":"db.internal","protocol":"mysql"}],"signing_keys":[],"grants":[]}"#,
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
        .find(|l| l.starts_with("orders-mysql\t"))
        .unwrap_or_else(|| panic!("no orders-mysql line: {text}"));
    assert_eq!(line.split('\t').nth(3), Some("L3"), "{line}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mysql_client_reaches_the_server_through_zs_run_and_each_step_is_recorded() {
    let upstream = fake::start(Script::new(packet::NATIVE_PASSWORD, Flow::Accept)).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(
        dir.path(),
        &[(RESOURCE, "mysql", upstream.addr.port())],
        PASSWORD,
    );
    let agent = spawn(&setup);

    let mut session = fake::login(listener(&agent), CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control"
    );
    assert_eq!(
        session.greeting.plugin,
        packet::CACHING_SHA2_PASSWORD,
        "default greeting"
    );
    let answer = session.command(b"\x03SELECT 1").await.unwrap();
    assert!(answer.payload.ends_with(fake::OK_INFO));
    let refused = session.command(b"\x11root\x00\x00").await.unwrap();
    assert_eq!(refused.payload, CHANGE_USER_REFUSED.packet());
    assert_eq!(
        upstream.seen(|s| s.commands.clone()),
        vec![b"\x03SELECT 1".to_vec()]
    );

    let diag = diag_with(dir.path(), "\"change_user_refused\"").await;
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
                    && r["protocol"] == "mysql"
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
                    && r["protocol"] == "mysql"
                    && r["decision"] == decision
                    && r["operation"] == operation
            })
            .unwrap()
    };
    assert!(find("allow", "connect").get("reason").is_none(), "{audit}");
    assert_eq!(
        find("deny", "change_user")["reason"],
        zs_proto_mysql::CHANGE_USER_REFUSED_REASON,
        "{audit}"
    );
    assert_eq!(count("deny", "change_user"), 1, "{audit}");
    for needle in [
        "\"component\":\"mysql\"",
        "\"upstream_auth_ok\"",
        "\"change_user_refused\"",
        "\"audit_seq\"",
    ] {
        assert!(diag.contains(needle), "missing {needle}: {diag}");
    }
    let stored = std::fs::read_to_string(setup.creds.join(RESOURCE)).unwrap();
    assert!(
        stored.contains(PASSWORD),
        "positive control: the credential exists"
    );
    assert!(!audit.contains(PASSWORD));
    assert!(!diag.contains(PASSWORD));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_port_scan_writes_no_allow() {
    let upstream = fake::start(Script::new(packet::NATIVE_PASSWORD, Flow::Accept)).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(
        dir.path(),
        &[(RESOURCE, "mysql", upstream.addr.port())],
        PASSWORD,
    );
    let agent = spawn(&setup);

    for _ in 0..3 {
        drop(
            tokio::net::TcpStream::connect(listener(&agent))
                .await
                .unwrap(),
        );
    }
    let session = fake::login(listener(&agent), CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control"
    );
    drop(session);
    for _ in 0..100 {
        if diag_text(dir.path()).matches("\"conn_closed\"").count() >= 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let diag = diag_text(dir.path());
    let accounted =
        diag.matches("\"conn_closed\"").count() + diag.matches("\"caller_refused\"").count();
    assert_eq!(accounted, 4, "{diag}");
    stop(agent);

    let audit = std::fs::read_to_string(&setup.audit).unwrap();
    let allowed = audit
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|r| {
            r["resource"] == RESOURCE && r["operation"] == "connect" && r["decision"] == "allow"
        })
        .count();
    assert_eq!(allowed, 1, "{audit}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_brokered_password_fails_upstream_auth_and_relays_nothing() {
    let upstream = fake::start(Script::new(packet::NATIVE_PASSWORD, Flow::Accept)).await;
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(
        dir.path(),
        &[(RESOURCE, "mysql", upstream.addr.port())],
        WRONG,
    );
    let agent = spawn(&setup);

    let session = fake::login(listener(&agent), CLIENT_CAPS).await;

    assert_eq!(session.reply.payload, UPSTREAM_AUTH_FAILED.packet());
    assert_eq!(
        upstream.seen(|s| s.responses),
        1,
        "positive: the agent answered the server"
    );
    assert!(!upstream.seen(|s| s.authenticated));
    assert!(upstream.seen(|s| s.commands.is_empty()));
    let diag = diag_with(dir.path(), "\"upstream_auth_failed\"").await;
    stop(agent);
    let stored = std::fs::read_to_string(setup.creds.join(RESOURCE)).unwrap();
    assert!(
        stored.contains(WRONG),
        "positive control: the credential exists"
    );
    assert!(!diag.contains(WRONG));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handshake_user_other_than_the_bound_user_is_refused() {
    const INTRUDER: &[u8] = b"zs_intruder_role";
    let upstream = fake::start(Script::new(packet::NATIVE_PASSWORD, Flow::Accept)).await;
    let port = upstream.addr.port();
    let dir = common::TestHome::new(".zs-ca");
    let setup = write_setup(dir.path(), &[(RESOURCE, "mysql", port)], PASSWORD);
    let policy = std::fs::read_to_string(&setup.policy).unwrap();
    let from = format!(r#""upstream_port":{port}}}"#);
    assert!(policy.contains(&from), "{policy}");
    std::fs::write(
        &setup.policy,
        policy.replacen(
            &from,
            &format!(r#""upstream_port":{port},"user":"app"}}"#),
            1,
        ),
    )
    .unwrap();
    let agent = spawn(&setup);

    let refused = fake::login_as(listener(&agent), CLIENT_CAPS, INTRUDER, Some(b"appdb")).await;
    assert_eq!(refused.reply.payload, USER_REFUSED.packet());
    let error = packet::ServerError::parse(&refused.reply.payload).unwrap();
    assert_eq!(
        (error.code, error.sqlstate.as_deref()),
        (1045, Some("28000"))
    );
    assert!(
        !refused
            .reply
            .payload
            .windows(INTRUDER.len())
            .any(|w| w == INTRUDER)
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        upstream.seen(|s| s.responses),
        0,
        "the handshake response reached the server"
    );

    let session = fake::login_as(listener(&agent), CLIENT_CAPS, b"app", Some(b"appdb")).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control: the bound user logs in"
    );
    assert_eq!(upstream.seen(|s| s.responses), 1);
    assert_eq!(upstream.seen(|s| s.user.clone()), b"app".to_vec());
    assert!(upstream.seen(|s| s.authenticated));
    drop(session);

    stop(agent);
    let audit = std::fs::read_to_string(&setup.audit).unwrap();
    let count = |decision: &str, reason: Option<&str>| {
        audit
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|r| {
                r["resource"] == RESOURCE
                    && r["protocol"] == "mysql"
                    && r["operation"] == "connect"
                    && r["decision"] == decision
                    && r.get("reason").and_then(|v| v.as_str()) == reason
            })
            .count()
    };
    assert_eq!(count("deny", Some("user mismatch")), 1, "{audit}");
    assert_eq!(count("allow", None), 1, "{audit}");
    let intruder = String::from_utf8_lossy(INTRUDER);
    assert!(!audit.contains(intruder.as_ref()), "{audit}");
    assert!(!diag_text(dir.path()).contains(intruder.as_ref()));
}
