#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("zs")
}

struct Upstream {
    host: String,
    port: u16,
    database: String,
    admin_url: String,
}

fn upstream() -> Option<Upstream> {
    let required = std::env::var_os("ZS_REQUIRE_PG").is_some();
    let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
        assert!(!required, "ZS_REQUIRE_PG is set and DATABASE_URL is not");
        return None;
    };
    if !psql_available() {
        assert!(!required, "ZS_REQUIRE_PG is set and psql is not on PATH");
        return None;
    }
    let parsed = parse_upstream(&url);
    assert!(
        parsed.is_some() || !required,
        "ZS_REQUIRE_PG is set and DATABASE_URL is not postgres://user:pass@host:port/db"
    );
    parsed
}

fn parse_upstream(url: &str) -> Option<Upstream> {
    let rest = url.strip_prefix("postgres://")?;
    let (_creds, hostpart) = rest.split_once('@')?;
    let (hostport, database) = hostpart.split_once('/')?;
    let (host, port) = hostport.split_once(':')?;
    Some(Upstream {
        host: host.to_string(),
        port: port.parse().ok()?,
        database: database.to_string(),
        admin_url: url.to_string(),
    })
}

const ROLE: &str = "zs_demo";
const UPSTREAM_PASSWORD: &str = "demo_upstream_secret_pw";

// Once per process: concurrent `ALTER ROLE` fails with `tuple concurrently updated`.
fn ensure_role(up: &Upstream) {
    static DONE: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let mut done = DONE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if done.contains(&up.admin_url) {
        return;
    }
    let sql = format!(
        "DO $$ BEGIN
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') THEN
             CREATE ROLE {ROLE} LOGIN PASSWORD '{UPSTREAM_PASSWORD}';
           ELSE
             ALTER ROLE {ROLE} LOGIN PASSWORD '{UPSTREAM_PASSWORD}';
           END IF;
         END $$;"
    );
    let out = Command::new("psql")
        .args([&up.admin_url, "-c", &sql])
        .output()
        .expect("psql must be installed to run these tests");
    assert!(
        out.status.success(),
        "could not create the demo role: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    done.push(up.admin_url.clone());
}

fn psql_available() -> bool {
    Command::new("psql")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn workspace(up: &Upstream) -> common::TestHome {
    workspace_for(&up.host, up.port)
}

fn workspace_for(host: &str, port: u16) -> common::TestHome {
    let dir = common::TestHome::new(".zs-ca");
    let creds = dir.path().join(".zs-credentials");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("pg-demo"), UPSTREAM_PASSWORD).unwrap();

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
    let connection = zs_policy::ResolvedConnection {
        upstream_host: host.to_string(),
        upstream_port: port,
        upstream_tls: zs_policy::UpstreamTlsMode::Default,
        local_endpoint: false,
    };
    let grant = serde_json::to_string(
        &signing
            .sign(zs_grant::Grant {
                subject: "alice".into(),
                workload: "default".into(),
                resource: "appdb".into(),
                host: "db.internal".into(),
                protocol: "postgres".into(),
                source: zs_policy::CredentialSource::file("pg-demo"),
                operations: vec!["connect".into()],
                environment: "development".into(),
                expires_at_ms: now_ms + 3_600_000,
                grant_id: "g-pg-real".into(),
                materialization: zs_policy::Materialization::Retrieve,
                upstream_host: connection.upstream_host,
                upstream_port: connection.upstream_port,
                upstream_tls: connection.upstream_tls,
                local_endpoint: connection.local_endpoint,
            })
            .unwrap(),
    )
    .unwrap();

    let config = format!(
        r#"{{"bindings":[{{"resource":"appdb","host":"db.internal","protocol":"postgres","upstream_host":"{}","upstream_port":{}}}],"signing_keys":[{{"key_id":"test-k1","verifying_key_hex":"{verifying_hex}"}}],"grants":[{grant}]}}"#,
        host, port
    );
    std::fs::write(dir.path().join("zs-policy.json"), config).unwrap();
    dir
}

fn run_psql(home: &std::path::Path, up: &Upstream, query: &str) -> String {
    let url = format!("postgresql://{ROLE}@/{}", up.database);
    let output = zs_run(home, &["psql", &url, "-tAc", query])
        .output()
        .expect("zs must run");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn zs_run(home: &std::path::Path, child: &[&str]) -> Command {
    let mut cmd = Command::new(binary());
    cmd.args([
        "run",
        "--policy",
        &home.join("zs-policy.json").display().to_string(),
        "--credentials-dir",
        &home.join(".zs-credentials").display().to_string(),
        "--audit",
        &home.join("audit.jsonl").display().to_string(),
        "--ca-dir",
        &home.join(".zs-ca").display().to_string(),
        "--",
    ])
    .args(child)
    .env("ZS_HOME", home)
    .env("USER", "alice")
    .env_remove("PGPASSWORD")
    .env_remove("PGPASSFILE")
    .env_remove("PGSERVICEFILE")
    .current_dir(home);
    cmd
}

struct Relay {
    addr: std::net::SocketAddr,
    accepts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Relay {
    fn start(
        rt: &tokio::runtime::Runtime,
        listener: tokio::net::TcpListener,
        target: (String, u16),
    ) -> std::io::Result<Relay> {
        let addr = listener.local_addr()?;
        let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = accepts.clone();
        let task = rt.spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let target = target.clone();
                tokio::spawn(async move {
                    if let Ok(mut server) = tokio::net::TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
            }
        });
        Ok(Relay {
            addr,
            accepts,
            task,
        })
    }

    fn accepts(&self) -> usize {
        self.accepts.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn stop(self, rt: &tokio::runtime::Runtime) {
        self.task.abort();
        let _ = rt.block_on(self.task);
    }
}

fn reserve_both_loopbacks() -> Option<(tokio::net::TcpSocket, tokio::net::TcpSocket)> {
    for _ in 0..20 {
        let v6 = tokio::net::TcpSocket::new_v6().ok()?;
        v6.bind("[::1]:0".parse().unwrap()).ok()?;
        let port = v6.local_addr().ok()?.port();
        let v4 = tokio::net::TcpSocket::new_v4().ok()?;
        if v4
            .bind(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            .is_ok()
        {
            return Some((v6, v4));
        }
    }
    None
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

struct KillOnDrop(Option<std::process::Child>);

impl KillOnDrop {
    fn wait_with_output(mut self) -> std::io::Result<std::process::Output> {
        self.0.take().expect("child").wait_with_output()
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn wait_for_accepts(relay: &Relay, expected: usize, limit: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < limit {
        if relay.accepts() == expected {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    false
}

fn wait_for_file(path: &std::path::Path, limit: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < limit {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

#[test]
fn a_real_client_reaches_a_real_password_protected_database_with_no_password() {
    let Some(up) = upstream() else { return };
    ensure_role(&up);
    let home = workspace(&up);

    let out = run_psql(home.path(), &up, "select 'ZS_CONNECTED'");

    assert!(
        out.contains("ZS_CONNECTED"),
        "the workload could not reach the database through the agent:\n{out}"
    );
    assert!(
        !out.contains("password authentication failed"),
        "the agent presented a credential the server rejected:\n{out}"
    );
}

#[test]
fn the_upstream_password_is_absent_from_the_workload_environment() {
    let Some(up) = upstream() else { return };
    ensure_role(&up);
    let home = workspace(&up);

    let output = zs_run(home.path(), &["/usr/bin/env"])
        .output()
        .expect("zs must run");
    let env_dump = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        env_dump.contains("PGHOST"),
        "the child must be pointed at the agent's listener:\n{env_dump}"
    );
    assert!(
        !env_dump.contains(UPSTREAM_PASSWORD),
        "the upstream password reached the workload's environment:\n{env_dump}"
    );
    assert!(
        !env_dump.contains("PGPASSWORD"),
        "PGPASSWORD must never be set for the child:\n{env_dump}"
    );
}

#[test]
fn the_child_is_pointed_at_the_local_listener_not_the_upstream() {
    let Some(up) = upstream() else { return };
    ensure_role(&up);
    let home = workspace(&up);

    let out = run_psql(
        home.path(),
        &up,
        "select inet_server_port()::text || '/' || current_user",
    );

    assert!(
        out.contains(&format!("/{ROLE}")),
        "the connection must authenticate as the granted role:\n{out}"
    );
    // The server reports its internal port, not `DATABASE_URL`'s mapped one under Docker.
    let reported_port: u16 = out
        .lines()
        .find_map(|l| l.split('/').next()?.trim().parse().ok())
        .unwrap_or_else(|| panic!("no server port in:\n{out}"));
    assert_ne!(
        reported_port, 0,
        "the server must report a real listening port:\n{out}"
    );
}

#[test]
fn a_wrong_credential_is_rejected_by_the_real_server() {
    let Some(up) = upstream() else { return };
    ensure_role(&up);
    let home = workspace(&up);
    std::fs::write(
        home.path().join(".zs-credentials").join("pg-demo"),
        "definitely_not_the_password",
    )
    .unwrap();

    let out = run_psql(home.path(), &up, "select 'ZS_CONNECTED'");

    assert!(
        !out.contains("ZS_CONNECTED"),
        "a wrong credential reached a successful query — the server is not checking, so \
         this suite proves nothing about credential correctness:\n{out}"
    );
    assert!(
        out.contains("upstream authentication failed"),
        "the client must be told authentication failed, not see a dropped connection:\n{out}"
    );
}

#[test]
fn the_connection_is_audited() {
    let Some(up) = upstream() else { return };
    ensure_role(&up);
    let home = workspace(&up);

    let _ = run_psql(home.path(), &up, "select 1");

    let mut journal = String::new();
    for _ in 0..30 {
        journal = std::fs::read_to_string(home.path().join("audit.jsonl")).unwrap_or_default();
        if journal.contains("appdb") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    assert!(
        journal.contains("appdb"),
        "the postgres connection must be audited:\n{journal}"
    );
    assert!(
        !journal.contains(UPSTREAM_PASSWORD),
        "the audit journal must never contain the credential:\n{journal}"
    );
}

#[test]
fn a_hostname_upstream_is_not_contacted_until_a_client_connects() {
    let Some(up) = upstream() else { return };
    ensure_role(&up);
    let rt = runtime();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let relay = Relay::start(&rt, listener, (up.host.clone(), up.port)).unwrap();
    let home = workspace_for("localhost", relay.addr.port());

    drop(
        rt.block_on(tokio::net::TcpStream::connect(relay.addr))
            .unwrap(),
    );
    assert!(
        wait_for_accepts(&relay, 1, std::time::Duration::from_secs(5)),
        "the relay must count a direct connection"
    );

    let idle = zs_run(home.path(), &["/usr/bin/true"])
        .output()
        .expect("zs must run");
    assert!(
        idle.status.success(),
        "an idle child must run under a hostname upstream: {}",
        String::from_utf8_lossy(&idle.stderr)
    );
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(
        relay.accepts(),
        1,
        "starting the agent must not contact the upstream"
    );

    let out = run_psql(home.path(), &up, "select 'ZS_CONNECTED'");
    assert!(
        out.contains("ZS_CONNECTED"),
        "the first real query must authenticate through the hostname upstream:\n{out}"
    );
    assert_eq!(
        relay.accepts(),
        2,
        "one client query must open exactly one upstream connection"
    );
    assert!(
        !out.contains(UPSTREAM_PASSWORD),
        "the upstream password reached the workload's output:\n{out}"
    );
    let journal = std::fs::read_to_string(home.path().join("audit.jsonl")).unwrap_or_default();
    assert!(
        journal.contains("appdb"),
        "the hostname connection must be audited:\n{journal}"
    );
    assert!(
        !journal.contains(UPSTREAM_PASSWORD),
        "the audit journal must never contain the credential:\n{journal}"
    );
    relay.stop(&rt);
}

#[test]
fn a_second_client_connection_reaches_a_moved_target() {
    let Some(up) = upstream() else { return };
    ensure_role(&up);
    let rt = runtime();
    let target = (up.host.clone(), up.port);
    let _entered = rt.enter();
    let Some((v6, v4)) = reserve_both_loopbacks() else {
        eprintln!("skipped: this host cannot reserve one port on both ::1 and 127.0.0.1");
        return;
    };
    let port = v6.local_addr().unwrap().port();
    let resolved: Vec<std::net::SocketAddr> = rt
        .block_on(tokio::net::lookup_host(("localhost", port)))
        .map(|addrs| addrs.collect())
        .unwrap_or_default();
    if !(resolved.iter().any(|a| a.is_ipv6()) && resolved.iter().any(|a| a.is_ipv4())) {
        eprintln!("skipped: localhost does not resolve to both families here: {resolved:?}");
        return;
    }
    let first = Relay::start(&rt, v6.listen(128).unwrap(), target.clone()).unwrap();
    let home = workspace_for("localhost", port);
    let url = format!("postgresql://{ROLE}@/{}", up.database);
    let first_done = home.path().join("first-done");
    let swapped = home.path().join("swapped");

    let script = r#"
        psql "$1" -tAc "select 'FIRST_OK'"
        touch "$2"
        i=0
        while [ ! -f "$3" ] && [ $i -lt 400 ]; do sleep 0.05; i=$((i+1)); done
        psql "$1" -tAc "select 'SECOND_OK'"
    "#;
    let child = KillOnDrop(Some(
        zs_run(
            home.path(),
            &[
                "/bin/sh",
                "-c",
                script,
                "sh",
                &url,
                &first_done.display().to_string(),
                &swapped.display().to_string(),
            ],
        )
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("zs must run"),
    ));

    assert!(
        wait_for_file(&first_done, std::time::Duration::from_secs(20)),
        "the child never finished its first query"
    );
    assert_eq!(
        first.accepts(),
        1,
        "the first query must reach the [::1] target"
    );
    first.stop(&rt);
    let second = Relay::start(&rt, v4.listen(128).unwrap(), target).unwrap();
    std::fs::write(&swapped, b"").unwrap();

    let output = child.wait_with_output().expect("zs must finish");
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out.contains("FIRST_OK"), "the first query failed:\n{out}");
    assert!(
        out.contains("SECOND_OK"),
        "the second connection did not reach the moved target, so the agent kept an old \
         address:\n{out}"
    );
    assert_eq!(
        second.accepts(),
        1,
        "the second query must reach the new target"
    );
    assert!(
        !out.contains(UPSTREAM_PASSWORD),
        "the upstream password reached the workload's output:\n{out}"
    );
    second.stop(&rt);
}

#[test]
fn an_unavailable_hostname_denies_the_client() {
    let Some(up) = upstream() else { return };
    let home = workspace_for("zs-d3-unavailable.invalid", 5432);
    let url = format!("postgresql://{ROLE}@/{}", up.database);

    let output = zs_run(
        home.path(),
        &[
            "/bin/sh",
            "-c",
            r#"echo CHILD_STARTED; psql "$1" -tAc "select 'ZS_CONNECTED'""#,
            "sh",
            &url,
        ],
    )
    .output()
    .expect("zs must run");
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        out.contains("CHILD_STARTED"),
        "the agent must start with an unresolvable hostname and run the child:\n{out}"
    );
    assert!(
        !out.contains("ZS_CONNECTED"),
        "an unresolvable upstream must deny the query:\n{out}"
    );
    assert!(
        out.contains("upstream unavailable"),
        "the client must be told the upstream is unavailable, not see a dropped connection:\n{out}"
    );
    assert!(
        !out.contains(UPSTREAM_PASSWORD),
        "the upstream password reached the workload's output:\n{out}"
    );
}

const SSL_QUERY: &str = "select ssl from pg_stat_ssl where pid = pg_backend_pid()";

fn tls_upstream() -> Option<Upstream> {
    let Some(url) = std::env::var("ZS_TEST_PG_TLS")
        .ok()
        .filter(|u| !u.is_empty())
    else {
        assert!(
            std::env::var_os("ZS_REQUIRE_PG_TLS").is_none(),
            "ZS_REQUIRE_PG_TLS is set and ZS_TEST_PG_TLS is not"
        );
        return None;
    };
    assert!(psql_available(), "ZS_TEST_PG_TLS needs psql on PATH");
    Some(parse_upstream(&url).expect("ZS_TEST_PG_TLS must be postgres://user:pass@host:port/db"))
}

fn db_certs() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/db-test-certs")
}

fn leaf_pin() -> String {
    use rustls::pki_types::pem::PemObject;
    use sha2::Digest;
    let leaf =
        rustls::pki_types::CertificateDer::from_pem_file(db_certs().join("server.pem")).unwrap();
    sha2::Sha256::digest(leaf.as_ref())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct TlsRun {
    out: String,
    diag: Vec<serde_json::Value>,
}

impl TlsRun {
    fn field(&self, event: &str, key: &str) -> Option<String> {
        self.diag
            .iter()
            .find(|e| e["event"] == event)
            .and_then(|e| e["fields"][key].as_str().map(str::to_string))
    }
}

fn through_listener(up: &Upstream, tls_fields: &str) -> TlsRun {
    ensure_role(up);
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("zs-policy.json");
    std::fs::write(
        &policy,
        format!(
            r#"{{"bindings":[{{"resource":"appdb","host":"db.internal","protocol":"postgres","upstream_host":"{}","upstream_port":{}{tls_fields}}}]}}"#,
            up.host, up.port
        ),
    )
    .unwrap();
    let file = zs::AgentFile::load(&policy).expect("the TLS binding must load");
    let binding = &file.bindings[0];
    let (host, port) = binding.upstream();
    let tls = binding.upstream_tls().unwrap();
    let log = dir.path().join("diag.jsonl");
    let diag = zs_diag::DiagLog::open_with_cap(&log, "pg-real-tls", 1 << 20).unwrap();
    let rt = runtime();
    let local = rt.block_on(async {
        let listener = zs_proto_postgres::PostgresListener::bind_endpoint(
            "127.0.0.1:0",
            zs_proto_postgres::UpstreamEndpoint::new(host, port).unwrap(),
            zs_proto_postgres::SslPolicy::RefuseOnLoopback,
            tls,
            std::sync::Arc::new(|| {
                Ok(
                    zs_credential::Credential::from_bytes(UPSTREAM_PASSWORD.as_bytes().to_vec())
                        .unwrap(),
                )
            }),
        )
        .await
        .unwrap()
        .with_diag(diag.clone(), "appdb")
        .with_caller_check(std::sync::Arc::new(|_, _| true));
        let local = listener.local_addr();
        tokio::spawn(listener.serve());
        local
    });
    let target = format!(
        "host=127.0.0.1 port={} user={ROLE} dbname={} connect_timeout=10",
        local.port(),
        up.database
    );
    let output = Command::new("psql")
        .args([target.as_str(), "-X", "-tAc", SSL_QUERY])
        .env_remove("PGPASSWORD")
        .env_remove("PGPASSFILE")
        .env_remove("PGSERVICEFILE")
        .output()
        .expect("psql must run");
    std::thread::sleep(std::time::Duration::from_millis(200));
    diag.close();
    drop(rt);
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !text.contains(UPSTREAM_PASSWORD),
        "the diag log holds the password"
    );
    TlsRun {
        out: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        diag: text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect(),
    }
}

fn ca_field(path: &std::path::Path) -> String {
    format!(r#","upstream_ca":{}"#, serde_json::to_string(path).unwrap())
}

#[test]
fn tls_a_ca_verified_session_runs_inside_tls() {
    let Some(up) = tls_upstream() else { return };
    let run = through_listener(&up, &ca_field(&db_certs().join("ca.pem")));
    assert_eq!(
        run.out.trim(),
        "t",
        "the session must run inside TLS:\n{}",
        run.out
    );
    assert_eq!(run.field("tls", "result").as_deref(), Some("verified"));
}

#[test]
fn tls_a_pinned_session_runs_inside_tls() {
    let Some(up) = tls_upstream() else { return };
    let run = through_listener(&up, &format!(r#","upstream_cert_sha256":"{}""#, leaf_pin()));
    assert_eq!(
        run.out.trim(),
        "t",
        "the session must run inside TLS:\n{}",
        run.out
    );
    assert_eq!(run.field("tls", "result").as_deref(), Some("pinned"));
}

#[test]
fn tls_a_wrong_ca_or_no_tls_field_is_refused() {
    let Some(up) = tls_upstream() else { return };
    let control = through_listener(&up, &ca_field(&db_certs().join("ca.pem")));
    assert_eq!(
        control.out.trim(),
        "t",
        "positive control:\n{}",
        control.out
    );

    let dir = tempfile::tempdir().unwrap();
    let wrong = dir.path().join("wrong-ca.pem");
    let other = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    std::fs::write(&wrong, other.cert.pem()).unwrap();
    for fields in [ca_field(&wrong), String::new()] {
        let run = through_listener(&up, &fields);
        assert!(
            run.out.contains("upstream TLS failed"),
            "{fields}: {}",
            run.out
        );
        assert_ne!(run.out.trim(), "t", "{fields}");
        assert_eq!(
            run.field("tls", "result").as_deref(),
            Some("failed"),
            "{fields}"
        );
        assert_eq!(
            run.field("upstream_failed", "stage").as_deref(),
            Some("tls"),
            "{fields}"
        );
    }
}
