#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;
#[path = "../../zs-conformance/tests/clients/matrix.rs"]
mod matrix;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use tokio::process::Command;
use zs_credential::Credential;
use zs_proto_postgres::{
    AuditRefusal, Materialize, PostgresListener, SslPolicy, UpstreamEndpoint, UpstreamTls,
};
use zs_protocol::{Materialized, SessionAccess};

const ROLE: &str = "zs_read_only_probe";
const ROLE_PASSWORD: &str = "zs-read-only-probe-pw";
const CLIENTS: [&str; 4] = ["libpq", "node-postgres", "pgx", "psycopg"];
const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

struct Database {
    host: String,
    port: u16,
    name: String,
    user: String,
    password: String,
}

fn required() -> bool {
    std::env::var_os("ZS_REQUIRE_PG").is_some()
}

fn database() -> Option<Database> {
    let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
        assert!(!required(), "ZS_REQUIRE_PG is set and DATABASE_URL is not");
        return None;
    };
    let parsed = parse_url(&url);
    assert!(
        parsed.is_some() || !required(),
        "ZS_REQUIRE_PG is set and DATABASE_URL is not postgres://user:pass@host:port/db"
    );
    parsed
}

fn parse_url(url: &str) -> Option<Database> {
    let rest = url.strip_prefix("postgres://")?;
    let (credentials, location) = rest.split_once('@')?;
    let (user, password) = credentials.split_once(':')?;
    let (address, name) = location.split_once('/')?;
    let (host, port) = address.split_once(':')?;
    Some(Database {
        host: host.to_string(),
        port: port.parse().ok()?,
        name: name.to_string(),
        user: user.to_string(),
        password: password.to_string(),
    })
}

type Refusals = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

async fn listen(db: &Database, access: SessionAccess) -> (SocketAddr, Refusals) {
    let materialize: Materialize = Arc::new(move || {
        Ok(Materialized::new(
            Credential::from_bytes(ROLE_PASSWORD.as_bytes().to_vec()).unwrap(),
            access,
            Arc::new(|| Ok(())),
        ))
    });
    let refusals: Refusals = Arc::new(Mutex::new(Vec::new()));
    let record = refusals.clone();
    let audit: AuditRefusal = Arc::new(move |operation: &'static str, reason: &'static str| {
        record.lock().unwrap().push((operation, reason));
        Some(1)
    });
    let listener = PostgresListener::bind_endpoint(
        "127.0.0.1:0",
        UpstreamEndpoint::new(db.host.clone(), db.port).unwrap(),
        SslPolicy::RefuseOnLoopback,
        UpstreamTls::WhenOffered,
        materialize,
    )
    .await
    .unwrap()
    .with_refusal_audit(audit)
    .with_caller_check(fake::admit_all());
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    (local, refusals)
}

async fn admin(db: &Database, sql: &str) -> String {
    let output = Command::new("psql")
        .args(["-X", "-A", "-t", "-v", "ON_ERROR_STOP=1"])
        .args(["-h", &db.host, "-p", &db.port.to_string()])
        .args(["-U", &db.user, "-d", &db.name, "-c", sql])
        .env("PGPASSWORD", &db.password)
        .output()
        .await
        .expect("psql is needed to prepare the fixture");
    assert!(
        output.status.success(),
        "fixture statement failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

async fn prepare(db: &Database, table: &str) {
    admin(
        db,
        &format!(
            "DO $$ BEGIN
               IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') THEN
                 CREATE ROLE {ROLE} LOGIN NOSUPERUSER PASSWORD '{ROLE_PASSWORD}';
               ELSE
                 ALTER ROLE {ROLE} LOGIN NOSUPERUSER PASSWORD '{ROLE_PASSWORD}';
               END IF;
             END $$;
             DROP TABLE IF EXISTS {table}; CREATE TABLE {table} (id int);
             INSERT INTO {table} VALUES (1); GRANT SELECT, INSERT ON {table} TO {ROLE}"
        ),
    )
    .await;
}

type Spec = (
    &'static str,
    Vec<String>,
    Option<PathBuf>,
    Vec<(&'static str, PathBuf)>,
);

fn build(name: &str, dir: Option<&Path>, run: bool) -> Result<Command, String> {
    let script = |file: &str| matrix::script(MANIFEST, file).display().to_string();
    let (program, args, cwd, env): Spec = match name {
        "libpq" => (
            if run { "sh" } else { "psql" },
            if run {
                vec![script("psql.sh")]
            } else {
                vec!["--version".into()]
            },
            None,
            vec![],
        ),
        "node-postgres" => (
            "node",
            if run {
                vec![script("node-postgres.js")]
            } else {
                vec!["-p".into(), "require('pg/package.json').version".into()]
            },
            None,
            vec![("NODE_PATH", matrix::node_modules(dir, "pg")?)],
        ),
        "pgx" => {
            let module = matrix::installed(dir, "go/go.mod")?
                .parent()
                .unwrap()
                .to_path_buf();
            (
                "go",
                if run {
                    vec!["run".into(), script("pgx.go")]
                } else {
                    vec![
                        "list".into(),
                        "-m".into(),
                        "-f".into(),
                        "{{.Version}}".into(),
                        "github.com/jackc/pgx/v5".into(),
                    ]
                },
                Some(module),
                vec![],
            )
        }
        "psycopg" => (
            "python3",
            if run {
                vec![script("psycopg_client.py")]
            } else {
                vec![
                    "-c".into(),
                    "import psycopg; print(psycopg.__version__)".into(),
                ]
            },
            None,
            vec![(
                "PYTHONPATH",
                matrix::installed(dir, "python/psycopg")?
                    .parent()
                    .unwrap()
                    .to_path_buf(),
            )],
        ),
        other => return Err(format!("unknown client {other}")),
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .envs(env)
        .env_remove("DATABASE_URL")
        .stdin(Stdio::null());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    Ok(command)
}

async fn version(name: &str, dir: Option<&Path>) -> Result<String, String> {
    let mut command = build(name, dir, false)?;
    let output = command
        .output()
        .await
        .map_err(|e| format!("cannot start the client runtime: {e}"))?;
    if !output.status.success() {
        return Err("the client runtime or driver does not start".to_string());
    }
    let text = if output.stdout.iter().any(|b| !b.is_ascii_whitespace()) {
        output.stdout
    } else {
        output.stderr
    };
    Ok(String::from_utf8_lossy(&text)
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .trim()
        .to_string())
}

async fn session(
    db: &Database,
    name: &str,
    dir: Option<&Path>,
    access: SessionAccess,
) -> Result<(), String> {
    let expected_rows = match access {
        SessionAccess::ReadOnly => "1",
        SessionAccess::ReadWrite => "3",
    };
    let label = matrix::label(access);
    let table = format!(
        "zs_ro_cl_{}_{label}_{}",
        name.replace('-', "_"),
        std::process::id()
    );
    prepare(db, &table).await;
    let (local, refusals) = listen(db, access).await;
    let mut command = build(name, dir, true).unwrap();
    command
        .env("ZS_CLIENT_HOST", local.ip().to_string())
        .env("ZS_CLIENT_PORT", local.port().to_string())
        .env("ZS_CLIENT_USER", ROLE)
        .env("ZS_CLIENT_DB", &db.name)
        .env("ZS_CLIENT_TABLE", &table)
        .env("ZS_CLIENT_ACCESS", label);
    let success = matrix::run(name, access, command).await;
    let rows = admin(db, &format!("SELECT count(*) FROM {table}")).await;
    admin(db, &format!("DROP TABLE IF EXISTS {table}")).await;
    let refused = refusals.lock().unwrap().len();
    matrix::judge(
        access,
        success,
        refused,
        &[("rows in the table", rows, expected_rows)],
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a real PostgreSQL, psql and the client programs in tests/clients"]
async fn real_clients_read_through_a_read_only_session_and_are_refused_a_write() {
    let Some(db) = database() else { return };
    let dir = matrix::clients_dir();
    let dir = dir.as_deref();
    matrix::matrix(
        required(),
        &CLIENTS,
        |name| async move { version(&name, dir).await },
        |name, access| {
            let db = &db;
            async move { session(db, &name, dir, access).await }
        },
    )
    .await;
}
