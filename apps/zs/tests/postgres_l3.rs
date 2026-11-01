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
