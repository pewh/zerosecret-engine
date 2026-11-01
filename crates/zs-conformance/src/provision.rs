use std::error::Error;
use std::fmt;
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cases::{CLIENT_TIMEOUT, output_within};
use crate::config::Protocol;

const MONGODB_ROLES: [(&str, &str, &str); 2] = [
    ("zs_sha256", "zs-test-sha256-password", "zsdb"),
    ("zs_sha1", "zs-test-sha1-password", "admin"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roles {
    pub user: String,
    pub password: String,
    pub database: String,
}

#[derive(Debug)]
pub enum ProvisionError {
    FixtureUnreachable {
        protocol: Protocol,
        fixture: SocketAddr,
    },
    AdminCredentialMissing {
        protocol: Protocol,
        variable: &'static str,
    },
    Failed(String),
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProvisionError::FixtureUnreachable { protocol, fixture } => write!(
                formatter,
                "the {protocol} fixture is not listening on {fixture}; start it with `{}`",
                compose_command(*protocol)
            ),
            ProvisionError::AdminCredentialMissing { protocol, variable } => write!(
                formatter,
                "no {protocol} administrator credential; set {variable}"
            ),
            ProvisionError::Failed(reason) => formatter.write_str(reason),
        }
    }
}

impl Error for ProvisionError {}

type ProvisionCache = Mutex<Vec<((Protocol, SocketAddr), Roles)>>;

pub fn provision(protocol: Protocol, fixture: SocketAddr) -> Result<Roles, ProvisionError> {
    static CACHE: OnceLock<ProvisionCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_, roles)) = cache.iter().find(|((cached_protocol, cached_fixture), _)| {
        *cached_protocol == protocol && *cached_fixture == fixture
    }) {
        return Ok(roles.clone());
    }
    let roles = provision_uncached(protocol, fixture)?;
    cache.push(((protocol, fixture), roles.clone()));
    Ok(roles)
}

fn provision_uncached(protocol: Protocol, fixture: SocketAddr) -> Result<Roles, ProvisionError> {
    if !listening(fixture) {
        return Err(ProvisionError::FixtureUnreachable { protocol, fixture });
    }
    match protocol {
        Protocol::Postgres => provision_postgres(fixture),
        Protocol::Mysql => provision_mysql(fixture),
        Protocol::Mongodb => {
            verify_mongodb(fixture)?;
            let (user, password, database) = MONGODB_ROLES[0];
            Ok(Roles {
                user: user.to_string(),
                password: password.to_string(),
                database: database.to_string(),
            })
        }
        Protocol::Http => Err(ProvisionError::Failed(
            "the http protocol has no fixture roles".to_string(),
        )),
    }
}

pub fn flush_privileges(fixture: SocketAddr) -> Result<(), ProvisionError> {
    if !listening(fixture) {
        return Err(ProvisionError::FixtureUnreachable {
            protocol: Protocol::Mysql,
            fixture,
        });
    }
    let (admin, password) = administrator(Protocol::Mysql)?;
    let output = run(
        mysql_admin(fixture, &admin, &password).args(["--execute", "FLUSH PRIVILEGES"]),
        None,
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err(ProvisionError::Failed(redact(
            &String::from_utf8_lossy(&output.stderr),
            &[&password],
        )))
    }
}

fn provision_postgres(fixture: SocketAddr) -> Result<Roles, ProvisionError> {
    let (admin, admin_password) = administrator(Protocol::Postgres)?;
    let password = fixture_password().to_string();
    let sql = postgres_sql(&password);
    let output = run(
        postgres_command(fixture, &admin).env("PGPASSWORD", &admin_password),
        Some(sql.as_bytes()),
    )
    .map_err(|error| ProvisionError::Failed(redact(&error.to_string(), &[&password])))?;
    if !output.status.success() {
        return Err(ProvisionError::Failed(redact(
            &String::from_utf8_lossy(&output.stderr),
            &[&password, &admin_password],
        )));
    }
    Ok(Roles {
        user: "zs_conformance".to_string(),
        password,
        database: "conformance".to_string(),
    })
}

fn postgres_command(fixture: SocketAddr, admin: &str) -> Command {
    let mut command = Command::new("psql");
    command
        .args([
            "-h",
            &fixture.ip().to_string(),
            "-p",
            &fixture.port().to_string(),
            "-U",
            admin,
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-q",
            "-f",
            "-",
        ])
        .env_remove("PGPASSFILE")
        .env_remove("PGSERVICEFILE")
        .env_remove("PGSERVICE");
    command
}

fn postgres_sql(password: &str) -> String {
    format!(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zs_conformance') \
         THEN CREATE ROLE zs_conformance LOGIN PASSWORD '{password}'; \
         ELSE ALTER ROLE zs_conformance LOGIN PASSWORD '{password}'; END IF; END $$;\n\
         SELECT 'CREATE DATABASE conformance' \
         WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'conformance')\n\
         \\gexec\n\
         \\c conformance\n\
         GRANT ALL ON SCHEMA public TO zs_conformance;\n"
    )
}

fn provision_mysql(fixture: SocketAddr) -> Result<Roles, ProvisionError> {
    let (admin, password) = administrator(Protocol::Mysql)?;
    let sql = "CREATE DATABASE IF NOT EXISTS conformance; \
               GRANT ALL PRIVILEGES ON conformance.* TO 'zs_sha2'@'%'; \
               GRANT ALL PRIVILEGES ON conformance.* TO 'zs_native'@'%';";
    let output = run(
        mysql_admin(fixture, &admin, &password).args(["--execute", sql]),
        None,
    )?;
    if !output.status.success() {
        return Err(ProvisionError::Failed(redact(
            &String::from_utf8_lossy(&output.stderr),
            &[&password],
        )));
    }
    Ok(Roles {
        user: "zs_sha2".to_string(),
        password: "zs-test-sha2-password".to_string(),
        database: "conformance".to_string(),
    })
}

fn mysql_admin(fixture: SocketAddr, admin: &str, password: &str) -> Command {
    let mut command = Command::new("mysql");
    command
        .args([
            "--no-defaults",
            "--connect-timeout=10",
            "--host",
            &fixture.ip().to_string(),
            "--port",
            &fixture.port().to_string(),
            "--user",
            admin,
            "--protocol=TCP",
        ])
        .env("MYSQL_PWD", password);
    command
}

fn run(command: &mut Command, input: Option<&[u8]>) -> Result<Output, ProvisionError> {
    output_within(command, input, CLIENT_TIMEOUT).map_err(ProvisionError::Failed)
}

fn verify_mongodb(fixture: SocketAddr) -> Result<(), ProvisionError> {
    for role in MONGODB_ROLES {
        verify_mongodb_role(fixture, role)?;
    }
    Ok(())
}

fn verify_mongodb_role(
    fixture: SocketAddr,
    (user, password, source): (&str, &str, &str),
) -> Result<(), ProvisionError> {
    let script = format!(
        "const e = encodeURIComponent; print(connect(`mongodb://${{e(process.env.CONFORMANCE_MONGO_USER)}}:${{e(process.env.CONFORMANCE_MONGO_PASSWORD)}}@{fixture}/{source}?authSource={source}&directConnection=true&serverSelectionTimeoutMS=5000`).runCommand({{ ping: 1 }}).ok)"
    );
    let output = run(
        Command::new("mongosh")
            .args(["--nodb", "--quiet", "--norc", "--eval", &script])
            .env("CONFORMANCE_MONGO_USER", user)
            .env("CONFORMANCE_MONGO_PASSWORD", password)
            .env("MONGOSH_DISABLE_TELEMETRY", "1"),
        None,
    )?;
    if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "1" {
        return Ok(());
    }
    let error = redact(&String::from_utf8_lossy(&output.stderr), &[password]);
    Err(ProvisionError::Failed(format!(
        "the mongodb fixture has no {user} role in {source} that accepts the fixture password; run tools/mongo-test-setup.sh: {}",
        error.split_whitespace().collect::<Vec<_>>().join(" ")
    )))
}

fn administrator(protocol: Protocol) -> Result<(String, String), ProvisionError> {
    let (variable, user, password) = match protocol {
        Protocol::Postgres => ("ZS_CONFORMANCE_PG_ADMIN", "postgres", "postgres"),
        Protocol::Mysql => ("ZS_CONFORMANCE_MYSQL_ADMIN", "root", "zs-test-root"),
        Protocol::Mongodb => ("ZS_CONFORMANCE_MONGO_ADMIN", "root", "zs-test-root"),
        Protocol::Http => ("ZS_CONFORMANCE_HTTP_ADMIN", "none", "none"),
    };
    match std::env::var(variable) {
        Ok(value) => match value.split_once(':') {
            Some((user, password)) => Ok((user.to_string(), password.to_string())),
            None => Ok((value, password.to_string())),
        },
        Err(_) if protocol == Protocol::Http => {
            Err(ProvisionError::AdminCredentialMissing { protocol, variable })
        }
        Err(_) => Ok((user.to_string(), password.to_string())),
    }
}

pub(crate) fn compose_command(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "docker compose up -d postgres",
        Protocol::Mysql => "docker compose --profile mysql up -d mysql",
        Protocol::Mongodb => "docker compose --profile mongo up -d mongo",
        Protocol::Http => "no fixture: the suite serves its own http upstream",
    }
}

fn listening(fixture: SocketAddr) -> bool {
    TcpStream::connect_timeout(&fixture, Duration::from_millis(750)).is_ok()
}

fn fixture_password() -> &'static str {
    static PASSWORD: OnceLock<String> = OnceLock::new();
    PASSWORD.get_or_init(|| {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.subsec_nanos())
            .unwrap_or_default();
        format!("zs-conf-{nanos:08x}{:04x}", std::process::id() & 0xffff)
    })
}

fn redact(text: &str, secrets: &[&str]) -> String {
    let mut redacted = text.to_string();
    for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
        redacted = redacted.replace(secret, "[REDACTED]");
    }
    redacted
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const POSTGRES: &str = "127.0.0.1:5434";
    const MYSQL: &str = "127.0.0.1:3307";

    #[test]
    fn an_unreachable_fixture_is_distinguishable_from_a_wrong_answer() {
        let fixture: SocketAddr = "127.0.0.1:1".parse().expect("address");
        let error = provision(Protocol::Mysql, fixture).expect_err("the fixture is closed");
        assert!(matches!(error, ProvisionError::FixtureUnreachable { .. }));
        let text = error.to_string();
        assert!(text.contains("not listening"), "{text}");
        assert!(
            text.contains("docker compose --profile mysql up -d mysql"),
            "{text}"
        );
    }

    #[test]
    fn provisioning_never_puts_the_password_in_argv() {
        let fixture: SocketAddr = POSTGRES.parse().expect("address");
        let password = fixture_password();
        let sql = postgres_sql(password);
        assert!(sql.contains(password));
        let command = postgres_command(fixture, "postgres");
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|arg| arg == "-f"));
        assert!(args.iter().any(|arg| arg == "-"));
        assert!(
            !args.iter().any(|arg| arg.contains(password)),
            "the password is in argv: {args:?}"
        );
    }

    #[test]
    fn provisioning_is_idempotent() {
        if !crate::test_fixtures::ready(&[POSTGRES], &[]) {
            return;
        }
        let fixture: SocketAddr = POSTGRES.parse().expect("address");
        let first = provision(Protocol::Postgres, fixture).expect("first provision");
        let second = provision(Protocol::Postgres, fixture).expect("second provision");
        assert_eq!(first.user, second.user);
        assert_eq!(first.password, second.password);
        assert_ne!(first.password, "postgres");
    }

    #[test]
    fn the_mongodb_roles_are_verified_against_the_fixture() {
        let fixture: SocketAddr = "127.0.0.1:27018".parse().expect("address");
        if !listening(fixture) {
            return;
        }
        let roles = provision(Protocol::Mongodb, fixture).expect("provision mongodb");
        assert_eq!(roles.user, "zs_sha256");
        assert!(verify_mongodb_role(fixture, ("zs_sha256", "not-the-password", "zsdb")).is_err());
    }

    #[test]
    fn the_mysql_fixture_password_is_not_the_admin_password() {
        let fixture: SocketAddr = MYSQL.parse().expect("address");
        if !listening(fixture) {
            return;
        }
        match provision(Protocol::Mysql, fixture) {
            Ok(roles) => assert_ne!(roles.password, "zs-test-root"),
            Err(ProvisionError::Failed(reason)) if reason.contains("mysql_native_password") => {
                eprintln!(
                    "the local mysql client cannot load the fixture's auth plugin; CI's 8.0 client can"
                );
            }
            Err(error) => panic!("provision mysql: {error}"),
        }
    }
}
