#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use base64::Engine as _;
use common::{
    TestHome, bin_path, loopback_connection, spawn_agent, spawn_agent_capturing,
    spawn_fake_upstream, write_test_setup, write_test_setup_signing,
};

const SIGV4: &str = r#""auth": {"scheme": "aws-sigv4", "access_key_id": "AKIDTEST", "region": "eu-central-003", "service": "s3"}, "local_endpoint": true, "operations": "#;

fn hex_of(authorization: &str) -> String {
    let encoded = authorization
        .strip_prefix("Basic ")
        .expect("a Basic authorization");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("valid base64");
    let decoded = String::from_utf8(decoded).expect("utf-8 credentials");
    decoded
        .strip_prefix("zs:")
        .expect("the zs user")
        .to_string()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

fn diag_text(home: &Path) -> String {
    let log = home.join(".zs-log");
    files(&log)
        .iter()
        .map(|path| read(path))
        .collect::<Vec<_>>()
        .join("\n")
}

fn kill(mut child: std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
#[test]
fn the_child_gets_the_token_in_https_proxy_and_stdout_never_shows_it() {
    let dir = TestHome::new(".zs-ca");
    let upstream = spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) =
        write_test_setup(dir.path(), upstream.addr.port(), true, true);
    let captured = spawn_agent_capturing(
        bin_path().as_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &["sh", "-c", "printf %s \"$HTTPS_PROXY\""],
    )
    .expect("agent spawn");

    let output = captured.child_output;
    let start = output
        .find("http://zs:")
        .unwrap_or_else(|| panic!("the child must print its proxy url: {output}"));
    let rest = &output[start + "http://zs:".len()..];
    let (hex, after) = rest.split_once('@').expect("the userinfo terminator");
    let addr = after.lines().next().unwrap_or("").trim();

    assert_eq!(hex.len(), 64, "{hex}");
    assert!(
        hex.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "not lowercase hex: {hex}"
    );
    assert!(addr.starts_with("127.0.0.1:"), "{addr}");
    assert!(output.contains("zs: proxy 127.0.0.1:"), "{output}");

    let control = format!("http://zs:{hex}@");
    for line in output.lines().filter(|line| !line.contains(&control)) {
        assert!(!line.contains(hex), "the agent printed the token: {line}");
    }
    assert!(
        !captured.stderr.contains(hex),
        "stderr carries the token: {}",
        captured.stderr
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_run_token_never_reaches_the_journal_or_diag() {
    let dir = TestHome::new(".zs-ca");
    let upstream = spawn_fake_upstream();
    let (policy, creds, audit, ca_dir, _) =
        write_test_setup(dir.path(), upstream.addr.port(), true, true);
    let agent = spawn_agent(
        bin_path().as_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &["sleep", "20"],
        true,
    )
    .expect("agent spawn");
    let hex = hex_of(&agent.proxy_authorization);
    assert_eq!(hex.len(), 64, "control: the child env carried the token");
    let ca = read(&agent.ca_path);

    let (status, _) = common::proxied_request(
        &agent.proxy_addr,
        &ca,
        "api.stripe.com",
        443,
        "/v1/customers",
    )
    .await
    .unwrap();
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_eq!(upstream.requests.load(Ordering::SeqCst), 1);
    let refused = common::raw_exchange_without_token(
        &agent.proxy_addr,
        b"CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n",
    )
    .await;
    assert!(
        refused.starts_with("HTTP/1.1 407 ZeroSecret needs the run token"),
        "{refused}"
    );
    let denied = common::raw_exchange(
        &agent.proxy_addr,
        b"GET http://api.stripe.com/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(!denied.starts_with("HTTP/1.1 407"), "{denied}");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let encoded = agent
        .proxy_authorization
        .strip_prefix("Basic ")
        .expect("a Basic authorization")
        .to_string();
    let needles = [hex.clone(), encoded];
    let journal = read(&audit);
    assert!(journal.contains(r#""decision":"allow""#), "{journal}");
    assert!(journal.contains(r#""decision":"deny""#), "{journal}");
    let diag = diag_text(dir.path());
    assert!(diag.contains("caller_refused"), "{diag}");
    for needle in &needles {
        assert!(
            !journal.contains(needle),
            "the audit journal carries the token"
        );
        assert!(!diag.contains(needle), "the diag log carries the token");
        for path in files(dir.path()) {
            assert!(
                !read(&path).contains(needle),
                "{} carries the token",
                path.display()
            );
        }
    }
    kill(agent.child);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_endpoint_token_never_reaches_stdout_journal_or_diag() {
    let dir = TestHome::new(".zs-ca");
    let upstream = spawn_fake_upstream();
    let mut connection = loopback_connection(upstream.addr.port(), true);
    connection.local_endpoint = true;
    let (policy, creds, audit, ca_dir, _) = write_test_setup_signing(
        dir.path(),
        upstream.addr.port(),
        &["GET", "PUT"],
        connection,
    );
    let text = read(&policy).replace(r#""operations": "#, SIGV4);
    std::fs::write(&policy, text).unwrap();
    let probe = format!(
        "printf %s \"${{ZS_STRIPE_PRODUCTION_URL:-unset}}\" > {}/endpoint; sleep 20",
        dir.path().display()
    );
    let agent = spawn_agent(
        bin_path().as_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &["sh", "-c", &probe],
        true,
    )
    .expect("agent spawn");
    let file = dir.path().join("endpoint");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !file.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let url = read(&file);
    let rest = url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("an http endpoint: {url}"));
    let (host, hex) = rest.split_once('/').expect("the path token");
    assert_eq!(hex.len(), 64, "control: the child url carries the token");

    let allowed = common::raw_exchange(
        host,
        format!(
            "GET /{hex}/bucket/public.png HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await;
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    let presigned = common::raw_exchange(
        host,
        format!(
            "POST /{hex}/.zs/presign HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            presign_body(host).len(),
            presign_body(host)
        )
        .as_bytes(),
    )
    .await;
    assert!(presigned.starts_with("HTTP/1.1 200"), "{presigned}");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let journal = read(&audit);
    assert!(journal.contains(r#""decision":"allow""#), "{journal}");
    assert!(
        !journal.contains(hex),
        "the audit journal carries the token"
    );
    let diag = diag_text(dir.path());
    assert!(diag.contains("listener_bound"), "{diag}");
    assert!(!diag.contains(hex), "the diag log carries the token");
    assert!(
        agent.startup_stdout.contains("zs: endpoint"),
        "{}",
        agent.startup_stdout
    );
    assert!(
        !agent.startup_stdout.contains(hex),
        "stdout carries the token: {}",
        agent.startup_stdout
    );
    kill(agent.child);
}

fn presign_body(host: &str) -> String {
    let date = common::amz_now();
    let day = &date[..8];
    format!(
        r#"{{"url":"http://{host}/bucket/k.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDTEST%2F{day}%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date={date}&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=00","method":"GET"}}"#
    )
}

#[path = "../../../crates/zs-proto-mongo/tests/fake/mod.rs"]
mod mongo_fake;
#[path = "../../../crates/zs-proto-mysql/tests/fake/mod.rs"]
mod mysql_fake;
#[path = "../../../crates/zs-proto-postgres/tests/fake/mod.rs"]
mod pg_fake;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn three_protocol_setup(
    home: &std::path::Path,
    ports: &[(&str, &str, u16)],
) -> (PathBuf, PathBuf, PathBuf) {
    let policy_path = home.join("zs-policy.json");
    let creds_dir = home.join(".zs-credentials");
    let audit = home.join(".zs-audit").join("audit.jsonl");
    std::fs::create_dir_all(&creds_dir).unwrap();
    std::fs::create_dir_all(home.join(".zs-audit")).unwrap();
    for (name, value) in [
        ("pg-cred", pg_fake::PASSWORD),
        ("my-cred", mysql_fake::PASSWORD),
        ("mo-cred", mongo_fake::PASSWORD),
    ] {
        std::fs::write(creds_dir.join(name), value).unwrap();
    }
    let signing = zs_grant::ControlSigningKey::generate("test-k1");
    let verifying: String = signing
        .verifying_key_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut bindings = Vec::new();
    let mut grants = Vec::new();
    let credentials = ["pg-cred", "my-cred", "mo-cred"];
    for (index, (resource, host, port)) in ports.iter().enumerate() {
        let protocol = match *resource {
            "pg-db" => "postgres",
            "my-db" => "mysql",
            _ => "mongo",
        };
        let mut connection = loopback_connection(*port, false);
        let plaintext = if protocol == "mongo" {
            connection.upstream_tls = zs_policy::UpstreamTlsMode::Plaintext;
            r#","upstream_plaintext":true,"user":"alice","auth_source":"admin""#
        } else {
            ""
        };
        bindings.push(format!(
            r#"{{"resource":"{resource}","host":"{host}","protocol":"{protocol}","upstream_host":"127.0.0.1","upstream_port":{port}{plaintext}}}"#
        ));
        let grant = signing
            .sign(zs_grant::Grant {
                subject: common::default_subject(),
                workload: "default".into(),
                resource: (*resource).into(),
                host: (*host).into(),
                protocol: protocol.into(),
                source: zs_policy::CredentialSource::file(credentials[index]),
                operations: vec!["connect".into()],
                environment: "development".into(),
                expires_at_ms: now_ms() + 3_600_000,
                grant_id: format!("g-{index}"),
                materialization: zs_policy::Materialization::Retrieve,
                upstream_host: connection.upstream_host,
                upstream_port: connection.upstream_port,
                upstream_tls: connection.upstream_tls,
                local_endpoint: connection.local_endpoint,
                version: zs_grant::GRANT_VERSION,
            })
            .unwrap();
        grants.push(serde_json::to_string(&grant).unwrap());
    }
    let policy = format!(
        r#"{{"bindings":[{}],"signing_keys":[{{"key_id":"test-k1","verifying_key_hex":"{verifying}"}}],"grants":[{}]}}"#,
        bindings.join(","),
        grants.join(",")
    );
    std::fs::write(&policy_path, policy).unwrap();
    (policy_path, creds_dir, audit)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_same_user_database_client_is_relayed() {
    let home = TestHome::new(".zs-ca");
    let pg = pg_fake::start(pg_fake::Script::new(pg_fake::Answer::N)).await;
    let mysql = mysql_fake::start(mysql_fake::Script::new(
        zs_proto_mysql::packet::NATIVE_PASSWORD,
        mysql_fake::Flow::Accept,
    ))
    .await;
    let mongo = mongo_fake::start(mongo_fake::Script::set(1, Some(0))).await;
    let ca_dir = home.path().join(".zs-ca");
    let (policy, creds, audit) = three_protocol_setup(
        home.path(),
        &[
            ("pg-db", "pg.internal", pg.addr.port()),
            ("my-db", "my.internal", mysql.addr.port()),
            ("mo-db", "mo.internal", mongo.seed().port()),
        ],
    );
    let agent = spawn_agent(
        bin_path().as_path(),
        &policy,
        &creds,
        &audit,
        &ca_dir,
        &["sleep", "20"],
        true,
    )
    .expect("agent spawn");

    let pg_port = agent.postgres_port.expect("a postgres listener");
    let mysql_port = agent.mysql_port.expect("a mysql listener");
    let mongo_port = agent.mongo_port.expect("a mongo listener");
    let address = |port: u16| std::net::SocketAddr::from(([127, 0, 0, 1], port));

    pg_fake::login(address(pg_port))
        .await
        .expect("a same-user postgres client is relayed");
    mysql_fake::login(address(mysql_port), mysql_fake::CLIENT_CAPS).await;
    let mut client = mongo_fake::Client::connect(address(mongo_port)).await;
    client
        .legacy_handshake()
        .await
        .expect("a same-user mongo client is relayed");

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(pg.seen(|s| s.accepts), 1, "postgres upstream");
    assert_eq!(mysql.seen(|s| s.accepts), 1, "mysql upstream");
    assert_eq!(mongo.seen(0, |s| s.accepts), 1, "mongo upstream");
    kill(agent.child);
}
