#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

#[path = "../../../crates/zs-proto-postgres/tests/fake/mod.rs"]
mod pg_fake;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

struct MockPostgres {
    port: u16,
    saw_scram: Arc<AtomicBool>,
}

fn mock_postgres() -> MockPostgres {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let saw_scram = Arc::new(AtomicBool::new(false));
    let flag = saw_scram.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let flag = flag.clone();
            std::thread::spawn(move || {
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    return;
                }
                let mut rest = vec![0u8; (u32::from_be_bytes(len) as usize).saturating_sub(4)];
                if stream.read_exact(&mut rest).is_err() {
                    return;
                }
                if rest == [0x04, 0xd2, 0x16, 0x2f] {
                    if stream.write_all(b"N").is_err() || stream.read_exact(&mut len).is_err() {
                        return;
                    }
                    rest = vec![0u8; (u32::from_be_bytes(len) as usize).saturating_sub(4)];
                    if stream.read_exact(&mut rest).is_err() {
                        return;
                    }
                }
                let mechanism = b"SCRAM-SHA-256\0\0";
                let mut msg = b"R".to_vec();
                msg.extend_from_slice(&((4 + 4 + mechanism.len()) as u32).to_be_bytes());
                msg.extend_from_slice(&10u32.to_be_bytes());
                msg.extend_from_slice(mechanism);
                let _ = stream.write_all(&msg);
                let _ = stream.flush();

                let mut tag = [0u8; 1];
                if stream.read_exact(&mut tag).is_ok() && tag[0] == b'p' {
                    flag.store(true, Ordering::SeqCst);
                }
            });
        }
    });

    MockPostgres { port, saw_scram }
}

#[test]
fn zs_run_exposes_postgres_through_l3_without_a_password() {
    let dir = common::TestHome::new(".zs-ca");
    let upstream = mock_postgres();
    let (policy, creds, audit, ca_dir) =
        common::write_postgres_setup(dir.path(), upstream.port, true);

    let agent = common::spawn_agent_capturing(
        &common::bin_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &["/usr/bin/env"],
    )
    .expect("agent must start and run the child");

    assert!(
        !agent.child_output.contains("PGPASSWORD"),
        "PGPASSWORD must never be set in the child environment — that is the PRODUCT §4 \
         claim for the psql line. Child env was:\n{}",
        agent.child_output
    );
    assert!(
        agent.child_output.contains("PGHOST=127.0.0.1"),
        "the child must be pointed at the local L3 listener via PGHOST. Child env was:\n{}",
        agent.child_output
    );
    assert!(
        agent.child_output.contains("PGPORT="),
        "the child must be pointed at the listener's port via PGPORT. Child env was:\n{}",
        agent.child_output
    );

    let pgport: u16 = agent
        .child_output
        .lines()
        .find_map(|l| l.strip_prefix("PGPORT="))
        .and_then(|v| v.trim().parse().ok())
        .expect("PGPORT must parse");
    assert_ne!(
        pgport, upstream.port,
        "PGPORT must be the L3 listener, not the upstream database"
    );
}

#[test]
fn no_postgres_resource_means_no_pg_environment() {
    let dir = common::TestHome::new(".zs-ca");
    let fake = common::spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) =
        common::write_test_setup(dir.path(), fake.addr.port(), true, true);

    let agent = common::spawn_agent_capturing(
        &common::bin_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &["/usr/bin/env"],
    )
    .expect("agent must start");

    assert!(
        !agent.child_output.contains("PGHOST="),
        "an HTTPS-only policy must not set PGHOST. Child env was:\n{}",
        agent.child_output
    );
}

#[test]
fn a_client_connecting_to_pghost_reaches_the_database_through_the_listener() {
    let dir = common::TestHome::new(".zs-ca");
    let upstream = mock_postgres();
    let (policy, creds, audit, ca_dir) =
        common::write_postgres_setup(dir.path(), upstream.port, true);

    let mut agent = common::spawn_agent(
        &common::bin_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &["sleep", "10"],
        true,
    )
    .expect("agent must start");

    let pg_port = agent
        .postgres_port
        .expect("agent must report its postgres listener port");

    let mut client =
        std::net::TcpStream::connect(("127.0.0.1", pg_port)).expect("connect to L3 listener");
    client
        .write_all(&startup_packet("alice", "appdb"))
        .expect("send startup");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !upstream.saw_scram.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    assert!(
        upstream.saw_scram.load(Ordering::SeqCst),
        "the listener must have opened a SCRAM exchange with the upstream database"
    );

    let _ = agent.child.kill();
    let _ = agent.child.wait();
}

fn startup_packet(user: &str, database: &str) -> Vec<u8> {
    let mut body = 196_608u32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(database.as_bytes());
    body.push(0);
    body.push(0);
    let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    packet
}

#[test]
fn no_postgres_credential_reaches_the_child_or_the_agent_output() {
    const SECRET: &str = "upstream_secret_pencil";
    let dir = common::TestHome::new(".zs-ca");
    let upstream = mock_postgres();
    let (policy, creds, audit, ca_dir) =
        common::write_postgres_setup(dir.path(), upstream.port, true);

    let agent = common::spawn_agent_capturing(
        &common::bin_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &["/usr/bin/env"],
    )
    .expect("agent must start");

    assert!(
        !agent.child_output.contains(SECRET),
        "the upstream password must not appear in the child's environment:\n{}",
        agent.child_output
    );
    assert!(
        !agent.child_output.contains("PGPASSWORD"),
        "PGPASSWORD must not be set at all, even empty"
    );

    let journal = std::fs::read_to_string(&audit).unwrap_or_default();
    assert!(
        !journal.contains(SECRET),
        "the upstream password must not reach the audit journal"
    );
}

#[test]
fn postgres_binding_tls_fields_are_checked_at_config_load() {
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
        r#"{{"resource":"a","host":"db","protocol":"postgres","upstream_ca":{ca}}},{{"resource":"b","host":"db","protocol":"postgres","upstream_cert_sha256":"{pin}"}},{{"resource":"c","host":"db","protocol":"postgres"}}"#
    ))
    .expect("positive control: TLS fields load on postgres bindings");
    assert!(matches!(
        valid.bindings[0].upstream_tls(),
        Ok(zs_upstream::UpstreamTls::Required(roots)) if roots.len() == 1
    ));
    assert!(matches!(
        valid.bindings[1].upstream_tls(),
        Ok(zs_upstream::UpstreamTls::Pinned(bytes)) if bytes == [0xab; 32]
    ));
    assert!(matches!(
        valid.bindings[2].upstream_tls(),
        Ok(zs_upstream::UpstreamTls::WhenOffered)
    ));
    let https = load(
        r#"{"resource":"h","host":"api.example.com","upstream_host":"127.0.0.1","upstream_port":8080,"upstream_plaintext":true}"#,
    )
    .expect("negative control: an https binding may still set upstream_plaintext on loopback");
    assert_eq!(https.bindings[0].https_upstream_tls(), Ok(false));

    let plaintext = "a: upstream_plaintext is allowed only on an https binding";
    for (bad, message) in [
        (
            r#"{"resource":"a","host":"db","protocol":"postgres","upstream_host":"127.0.0.1","upstream_plaintext":true}"#.to_string(),
            plaintext,
        ),
        (
            r#"{"resource":"a","host":"db","protocol":"postgres","upstream_plaintext":true}"#.to_string(),
            plaintext,
        ),
        (
            r#"{"resource":"a","host":"db","protocol":"mysql","upstream_host":"127.0.0.1","upstream_plaintext":true}"#.to_string(),
            plaintext,
        ),
        (
            r#"{"resource":"a","host":"db","protocol":"postgres","client_auth_plugin":"mysql_native_password"}"#.to_string(),
            "a: client_auth_plugin is allowed only on a mysql binding",
        ),
        (
            r#"{"resource":"a","host":"db","protocol":"postgres","upstream_ca":"/nonexistent/zs-ca.pem"}"#.to_string(),
            "a: upstream_ca /nonexistent/zs-ca.pem cannot be read",
        ),
        (
            format!(r#"{{"resource":"a","host":"db","protocol":"postgres","upstream_ca":{ca},"upstream_cert_sha256":"{pin}"}}"#),
            "a: upstream_ca and upstream_cert_sha256 cannot both be set",
        ),
        (
            r#"{"resource":"a","host":"db","protocol":"postgres","upstream_cert_sha256":"abc"}"#.to_string(),
            "a: upstream_cert_sha256 must be 64 hex digits",
        ),
    ] {
        let error = load(&bad)
            .err()
            .unwrap_or_else(|| panic!("must refuse {bad}"));
        assert_eq!(error.to_string(), format!("policy: {message}"), "{bad}");
    }
}

fn with_upstream_ca(policy: &std::path::Path, port: u16, ca: &str) -> String {
    let text = std::fs::read_to_string(policy).unwrap();
    let field = format!("\"upstream_port\": {port}");
    assert!(text.contains(&field), "{text}");
    std::fs::write(
        policy,
        text.replace(&field, &format!("{field}, \"upstream_ca\": {ca}")),
    )
    .unwrap();
    text
}

#[tokio::test(flavor = "multi_thread")]
async fn zs_run_verifies_a_postgres_upstream_with_its_upstream_ca() {
    let pki = pg_fake::pki("127.0.0.1");
    let upstream =
        pg_fake::start(pg_fake::Script::new(pg_fake::Answer::S).with_tls(pki.server.clone())).await;
    let port = upstream.addr.port();
    let dir = common::TestHome::new(".zs-ca");
    let ca = dir.path().join("upstream-ca.pem");
    std::fs::write(&ca, &pki.ca_pem).unwrap();
    let mut signed_ca = common::loopback_connection(port, false);
    signed_ca.upstream_tls =
        zs_policy::UpstreamTlsMode::CaSha256(zs_upstream::load_ca(&ca).unwrap().sha256);
    let (policy, creds, audit, ca_dir) =
        common::write_postgres_setup_signing(dir.path(), port, true, signed_ca);
    std::fs::write(creds.join("pg-prod"), format!("{}\n", pg_fake::PASSWORD)).unwrap();
    with_upstream_ca(&policy, port, &serde_json::to_string(&ca).unwrap());
    let first = dir.path().join("started-first");
    let second = dir.path().join("started-second");
    let third = dir.path().join("started-third");
    let spawn = |marker: &std::path::Path| {
        let child = format!("touch {}; sleep 30", marker.display());
        tokio::task::block_in_place(|| {
            common::spawn_agent(
                &common::bin_path(),
                &policy,
                &creds,
                &audit,
                &ca_dir,
                &["sh", "-c", child.as_str()],
                true,
            )
        })
    };
    let listener = |agent: &common::AgentProcess| {
        std::net::SocketAddr::from((
            [127, 0, 0, 1],
            agent.postgres_port.expect("a `zs: postgres` line"),
        ))
    };

    let mut agent = spawn(&first).expect("the agent must start with a valid upstream_ca");
    let mut client = pg_fake::login(listener(&agent))
        .await
        .expect("a verified TLS login through zs run");
    assert_eq!(pg_fake::query(&mut client, "SELECT 1").await, "SELECT 1");
    assert!(upstream.seen(|s| s.tls && s.authenticated));
    assert!(
        pg_fake::eventually(|| first.exists()).await,
        "positive control: the child ran"
    );
    drop(client);
    let _ = agent.child.kill();
    let _ = agent.child.wait();

    common::write_postgres_setup(dir.path(), port, true);
    std::fs::write(creds.join("pg-prod"), format!("{}\n", pg_fake::PASSWORD)).unwrap();
    let mut agent = spawn(&second).expect("the agent must start with no TLS field");
    assert_eq!(
        pg_fake::login(listener(&agent)).await.err(),
        Some(pg_fake::error_frame(pg_fake::TLS_FAILED)),
        "no TLS field must refuse a private CA"
    );
    assert_eq!(upstream.seen(|s| s.startups), 1);
    assert!(
        pg_fake::eventually(|| second.exists()).await,
        "positive control: the child ran without a TLS field"
    );
    let _ = agent.child.kill();
    let _ = agent.child.wait();

    with_upstream_ca(&policy, port, "\"/nonexistent/zs-ca.pem\"");
    assert!(
        spawn(&third).is_err(),
        "a missing upstream_ca must stop zs run"
    );
    assert!(!third.exists(), "the child ran with a missing upstream_ca");
}

const INTRUDER: &str = "zs_intruder_role";

fn bind_user(policy: &std::path::Path, port: u16, user: &str) {
    let text = std::fs::read_to_string(policy).unwrap();
    let field = format!("\"upstream_port\": {port}");
    assert!(text.contains(&field), "{text}");
    std::fs::write(
        policy,
        text.replace(&field, &format!("{field}, \"user\": \"{user}\"")),
    )
    .unwrap();
}

struct PgRun {
    agent: common::AgentProcess,
    upstream: pg_fake::Fake,
    audit: std::path::PathBuf,
    dir: common::TestHome,
}

impl PgRun {
    async fn start(user: Option<&str>) -> Self {
        Self::start_with(user, pg_fake::Script::new(pg_fake::Answer::N), true).await
    }

    async fn start_with(user: Option<&str>, script: pg_fake::Script, grant: bool) -> Self {
        let upstream = pg_fake::start(script).await;
        let port = upstream.addr.port();
        let dir = common::TestHome::new(".zs-ca");
        let (policy, creds, audit, ca_dir) = common::write_postgres_setup(dir.path(), port, grant);
        std::fs::write(creds.join("pg-prod"), format!("{}\n", pg_fake::PASSWORD)).unwrap();
        if let Some(user) = user {
            bind_user(&policy, port, user);
        }
        let agent = tokio::task::block_in_place(|| {
            common::spawn_agent(
                &common::bin_path(),
                &policy,
                &creds,
                &audit,
                &ca_dir,
                &["sleep", "30"],
                true,
            )
        })
        .expect("the agent must start");
        Self {
            agent,
            upstream,
            audit,
            dir,
        }
    }

    fn listener(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::from((
            [127, 0, 0, 1],
            self.agent.postgres_port.expect("a `zs: postgres` line"),
        ))
    }

    fn diag(&self) -> String {
        std::fs::read_dir(self.dir.path().join(".zs-log"))
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn stop(mut self) -> (Vec<serde_json::Value>, String, String) {
        let _ = self.agent.child.kill();
        let _ = self.agent.child.wait();
        let text = std::fs::read_to_string(&self.audit).unwrap();
        let records = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let diag = self.diag();
        (records, text, diag)
    }
}

fn audited(records: &[serde_json::Value], decision: &str, reason: Option<&str>) -> usize {
    records
        .iter()
        .filter(|r| {
            r["resource"] == "appdb"
                && r["protocol"] == "postgres"
                && r["operation"] == "connect"
                && r["decision"] == decision
                && r.get("reason").and_then(|v| v.as_str()) == reason
        })
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_startup_user_other_than_the_bound_user_is_refused() {
    let run = PgRun::start(Some("app")).await;

    let refused = pg_fake::login_with(
        run.listener(),
        &pg_fake::startup(&[("user", INTRUDER), ("database", "appdb")]),
    )
    .await
    .expect_err("a startup user other than the bound user must be refused");
    assert_eq!(
        refused,
        pg_fake::error_frame(("28000", "database user not allowed by the binding"))
    );
    assert!(!String::from_utf8_lossy(&refused).contains(INTRUDER));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        run.upstream.seen(|s| s.accepts),
        0,
        "upstream was contacted"
    );

    let mut client = pg_fake::login_with(
        run.listener(),
        &pg_fake::startup(&[("user", "app"), ("database", "appdb")]),
    )
    .await
    .expect("positive control: the bound user logs in");
    assert_eq!(pg_fake::query(&mut client, "SELECT 1").await, "SELECT 1");
    assert_eq!(run.upstream.seen(|s| s.accepts), 1);
    assert!(run.upstream.seen(|s| s.authenticated));
    drop(client);

    let (records, text, diag) = run.stop();
    assert_eq!(
        audited(&records, "deny", Some("user mismatch")),
        1,
        "{text}"
    );
    assert_eq!(audited(&records, "allow", None), 1, "{text}");
    assert!(!text.contains(INTRUDER), "{text}");
    assert!(!diag.contains(INTRUDER), "{diag}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replication_startup_is_refused() {
    let run = PgRun::start(None).await;

    for value in ["database", "true", "false", "0"] {
        let refused = pg_fake::login_with(
            run.listener(),
            &pg_fake::startup(&[
                ("user", "alice"),
                ("database", "appdb"),
                ("replication", value),
            ]),
        )
        .await
        .err()
        .unwrap_or_else(|| panic!("replication={value} must be refused"));
        assert_eq!(
            refused,
            pg_fake::error_frame(("28000", "replication connections are refused")),
            "replication={value}"
        );
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        run.upstream.seen(|s| s.accepts),
        0,
        "upstream was contacted"
    );

    let client = pg_fake::login(run.listener())
        .await
        .expect("positive control: a startup without replication logs in");
    assert_eq!(run.upstream.seen(|s| s.accepts), 1);
    drop(client);

    let (records, text, _) = run.stop();
    assert_eq!(
        audited(&records, "deny", Some("replication refused")),
        4,
        "{text}"
    );
    assert_eq!(audited(&records, "allow", None), 1, "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_close_ends_the_relay() {
    let run = PgRun::start_with(
        None,
        pg_fake::Script::new(pg_fake::Answer::N).with_close_after_auth(),
        true,
    )
    .await;
    let client = pg_fake::login(run.listener())
        .await
        .expect("positive control: the login completes before the upstream closes");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut diag = run.diag();
    while !diag.contains("\"conn_closed\"") && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        diag = run.diag();
    }
    assert!(
        diag.contains("\"conn_closed\""),
        "an upstream close must end the relay while the client is idle: {diag}"
    );
    assert!(
        diag.contains("\"closed_by\":\"upstream\""),
        "the upstream closed first: {diag}"
    );
    drop(client);

    let (records, text, _) = run.stop();
    assert_eq!(audited(&records, "allow", None), 1, "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_terminate_is_recorded_before_the_relay_ends() {
    let run = PgRun::start(None).await;
    let mut client = pg_fake::login(run.listener())
        .await
        .expect("positive control: the login works");
    pg_fake::write_tagged(&mut client, b'X', b"").await.unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut diag = run.diag();
    while !diag.contains("\"conn_closed\"") && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        diag = run.diag();
    }
    let terminate = diag.find("\"client_terminate\"").unwrap_or_else(|| {
        panic!("the relay must record a Terminate before the upstream sees it: {diag}")
    });
    let closed = diag
        .find("\"conn_closed\"")
        .unwrap_or_else(|| panic!("a Terminate must end the relay: {diag}"));
    assert!(terminate < closed, "{diag}");
    assert!(diag.contains("\"closed_by\":\"client\""), "{diag}");
    assert!(
        pg_fake::eventually(|| run.upstream.seen(|s| s.terminated)).await,
        "the relay must forward the Terminate after recording it"
    );
    drop(client);

    let (records, text, _) = run.stop();
    assert_eq!(audited(&records, "allow", None), 1, "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_without_a_grant_is_refused() {
    let run = PgRun::start_with(None, pg_fake::Script::new(pg_fake::Answer::N), false).await;
    pg_fake::send_cancel(run.listener()).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        run.upstream.seen(|s| s.accepts),
        0,
        "a cancel without a grant must not reach the upstream"
    );

    let (records, text, diag) = run.stop();
    let refused: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| {
            r["resource"] == "appdb"
                && r["protocol"] == "postgres"
                && r["operation"] == "cancel"
                && r["decision"] == "deny"
        })
        .collect();
    assert_eq!(refused.len(), 1, "{text}");
    assert_eq!(refused[0]["reason"], "cancel without a grant", "{text}");
    assert!(diag.contains("\"reason\":\"cancel\""), "{diag}");

    let authorized = PgRun::start(None).await;
    pg_fake::send_cancel(authorized.listener()).await;
    assert!(
        pg_fake::eventually(|| authorized.upstream.seen(|s| s.cancels.len()) == 1).await,
        "positive control: a cancel covered by the grant reaches the upstream"
    );
    let (records, text, _) = authorized.stop();
    assert_eq!(
        audited(&records, "allow", None),
        0,
        "a cancel must not materialize a credential: {text}"
    );
}
