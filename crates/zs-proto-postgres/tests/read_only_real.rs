#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use zs_credential::Credential;
use zs_proto_postgres::{
    AuditRefusal, Materialize, PostgresListener, SslPolicy, UpstreamEndpoint, UpstreamTls,
};
use zs_protocol::{Materialized, SessionAccess};

const ROLE: &str = "zs_read_only_probe";
const ROLE_PASSWORD: &str = "zs-read-only-probe-pw";
const REFUSED: &str = "zs: refused, read-only resource";
const READ_ONLY: &str = "25006";

struct Database {
    host: String,
    port: u16,
    name: String,
    user: String,
    password: String,
}

fn database() -> Option<Database> {
    let required = std::env::var_os("ZS_REQUIRE_PG").is_some();
    let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
        assert!(!required, "ZS_REQUIRE_PG is set and DATABASE_URL is not");
        return None;
    };
    let parsed = parse_url(&url);
    assert!(
        parsed.is_some() || !required,
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

async fn listen(db: &Database, password: &str, access: SessionAccess) -> (SocketAddr, Refusals) {
    let password = password.as_bytes().to_vec();
    let materialize: Materialize = Arc::new(move || {
        Ok(Materialized::new(
            Credential::from_bytes(password.clone()).unwrap(),
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

#[derive(Debug, Default)]
struct Reply {
    tags: Vec<u8>,
    errors: Vec<(String, String)>,
    rows: Vec<Vec<Option<String>>>,
    status: u8,
}

impl Reply {
    fn ok(&self) -> bool {
        self.errors.is_empty()
    }

    fn refused_with(&self, sqlstate: &str) -> bool {
        self.errors.len() == 1 && self.errors[0].0 == sqlstate
    }

    fn message(&self) -> &str {
        self.errors
            .first()
            .map_or("", |(_, message)| message.as_str())
    }

    fn value(&self) -> Option<&str> {
        self.rows.first()?.first()?.as_deref()
    }
}

fn error_fields(body: &[u8]) -> (String, String) {
    let field = |code: u8| {
        body.split(|b| *b == 0)
            .find_map(|field| field.strip_prefix(&[code]))
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .unwrap_or_default()
    };
    (field(b'C'), field(b'M'))
}

fn data_row(body: &[u8]) -> Vec<Option<String>> {
    let count = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut at = 2;
    let mut row = Vec::new();
    for _ in 0..count {
        let length = i32::from_be_bytes(body[at..at + 4].try_into().unwrap());
        at += 4;
        if length < 0 {
            row.push(None);
            continue;
        }
        let end = at + length as usize;
        row.push(Some(String::from_utf8_lossy(&body[at..end]).into_owned()));
        at = end;
    }
    row
}

struct Client {
    stream: TcpStream,
}

impl Client {
    async fn open(local: SocketAddr, user: &str, db: &Database, extra: &[(&str, &str)]) -> Self {
        Self::try_open(local, user, db, extra)
            .await
            .unwrap_or_else(|(code, message)| panic!("login refused: {code} {message}"))
    }

    async fn try_open(
        local: SocketAddr,
        user: &str,
        db: &Database,
        extra: &[(&str, &str)],
    ) -> Result<Self, (String, String)> {
        let mut parameters = vec![("user", user), ("database", db.name.as_str())];
        parameters.extend_from_slice(extra);
        match fake::login_with(local, &fake::startup(&parameters)).await {
            Ok(stream) => Ok(Self { stream }),
            Err(frame) => Err(error_fields(&frame[5..])),
        }
    }

    async fn send(&mut self, messages: &[Vec<u8>]) {
        self.stream.write_all(&messages.concat()).await.unwrap();
    }

    async fn reply(&mut self) -> Reply {
        let mut reply = Reply::default();
        loop {
            let (tag, body) =
                tokio::time::timeout(Duration::from_secs(10), fake::read_tagged(&mut self.stream))
                    .await
                    .expect("the server must answer within 10 s")
                    .expect("the session closed");
            reply.tags.push(tag);
            match tag {
                b'E' => reply.errors.push(error_fields(&body)),
                b'D' => reply.rows.push(data_row(&body)),
                b'Z' => {
                    reply.status = body[0];
                    return reply;
                }
                _ => {}
            }
        }
    }

    async fn simple(&mut self, sql: &str) -> Reply {
        self.send(&[query(sql)]).await;
        self.reply().await
    }

    async fn close(mut self) {
        let _ = self.stream.write_all(&fake::frame(b'X', &[])).await;
    }
}

fn query(sql: &str) -> Vec<u8> {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    fake::frame(b'Q', &body)
}

fn parse(name: &str, sql: &str) -> Vec<u8> {
    let mut body = name.as_bytes().to_vec();
    body.push(0);
    body.extend_from_slice(sql.as_bytes());
    body.extend_from_slice(&[0, 0, 0]);
    fake::frame(b'P', &body)
}

fn bind(statement: &str) -> Vec<u8> {
    let mut body = vec![0];
    body.extend_from_slice(statement.as_bytes());
    body.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
    fake::frame(b'B', &body)
}

fn execute() -> Vec<u8> {
    fake::frame(b'E', &[0, 0, 0, 0, 0])
}

fn sync() -> Vec<u8> {
    fake::frame(b'S', &[])
}

fn function_call(arguments: [&str; 3]) -> Vec<u8> {
    let mut body = 2078u32.to_be_bytes().to_vec();
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&3u16.to_be_bytes());
    for argument in arguments {
        body.extend_from_slice(&(argument.len() as u32).to_be_bytes());
        body.extend_from_slice(argument.as_bytes());
    }
    body.extend_from_slice(&0u16.to_be_bytes());
    fake::frame(b'F', &body)
}

static ROLE_READY: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

struct Fixture {
    db: Database,
    table: &'static str,
}

impl Fixture {
    async fn new(table: &'static str) -> Option<Self> {
        let db = database()?;
        ROLE_READY
            .get_or_init(|| async {
                let mut admin = admin(&db).await;
                let created = admin
                    .simple(&format!(
                        "DO $$ BEGIN
                           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') THEN
                             CREATE ROLE {ROLE} LOGIN NOSUPERUSER PASSWORD '{ROLE_PASSWORD}';
                           ELSE
                             ALTER ROLE {ROLE} LOGIN NOSUPERUSER PASSWORD '{ROLE_PASSWORD}';
                           END IF;
                         END $$"
                    ))
                    .await;
                assert!(
                    created.ok(),
                    "could not prepare the probe role: {created:?}"
                );
                admin.close().await;
            })
            .await;
        let mut admin = admin(&db).await;
        let prepared = admin
            .simple(&format!(
                "DROP TABLE IF EXISTS {table}; CREATE TABLE {table} (id int); \
                 INSERT INTO {table} VALUES (1); GRANT SELECT, INSERT ON {table} TO {ROLE}"
            ))
            .await;
        assert!(prepared.ok(), "could not prepare {table}: {prepared:?}");
        admin.close().await;
        Some(Self { db, table })
    }

    async fn session(&self, access: SessionAccess) -> Client {
        self.session_with(access, &[]).await
    }

    async fn session_with(&self, access: SessionAccess, extra: &[(&str, &str)]) -> Client {
        let (local, _) = listen(&self.db, ROLE_PASSWORD, access).await;
        Client::open(local, ROLE, &self.db, extra).await
    }

    async fn rows(&self) -> String {
        let mut admin = admin(&self.db).await;
        let count = admin
            .simple(&format!("SELECT count(*) FROM {}", self.table))
            .await;
        admin.close().await;
        count.value().unwrap().to_string()
    }

    fn insert(&self) -> String {
        format!("INSERT INTO {} VALUES (2)", self.table)
    }

    async fn remove(self) {
        let mut admin = admin(&self.db).await;
        admin
            .simple(&format!("DROP TABLE IF EXISTS {}", self.table))
            .await;
        admin.close().await;
    }
}

async fn admin(db: &Database) -> Client {
    let (local, _) = listen(db, &db.password, SessionAccess::ReadWrite).await;
    Client::open(local, &db.user, db, &[]).await
}

const MODE: &str = "SELECT setting FROM pg_settings WHERE name LIKE 'default_transaction_read%'";

async fn assert_still_read_only(session: &mut Client, fixture: &Fixture, after: &str) {
    let mode = session.simple(MODE).await;
    assert_eq!(mode.value(), Some("on"), "after {after:?}");
    let insert = session.simple(&fixture.insert()).await;
    assert!(
        insert.refused_with(READ_ONLY),
        "after {after:?}: {insert:?}"
    );
    assert!(
        insert.message().contains("read-only transaction"),
        "after {after:?}: the database, not the agent, refuses the INSERT: {insert:?}"
    );
    assert_eq!(insert.status, b'I', "after {after:?}");
}

const ESCAPES: [&str; 14] = [
    "SET default_transaction_read_only = off",
    "SELECT set_config('default_transaction_read_only','off',false)",
    "SELECT set_config(name,'off',false) FROM pg_settings WHERE name LIKE 'default_transaction_read%'",
    "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
    "BEGIN READ WRITE",
    "BEGIN; SET TRANSACTION READ WRITE",
    "BEGIN; SET LOCAL transaction_read_only = off",
    "DO $$ BEGIN PERFORM set_config('default_transaction_read_only', 'off', false); END $$",
    "SELECT query_to_xml(concat('select set_', 'config(''default_transaction_read_only'',''off'',false)'), false, false, '')",
    "SELECT query_to_xmlschema('select 1', false, false, '')",
    "SELECT * FROM ts_stat('select to_tsvector(''x'')')",
    "SELECT ts_rewrite('a'::tsquery, 'select ''a''::tsquery, ''b''::tsquery')",
    "SELECT U&\"\\0073et_config\"('default_transaction_read_only', 'off', false)",
    "SET/**/default_transaction_read_only = off",
];

#[tokio::test(flavor = "multi_thread")]
async fn refused_query_returns_25006_and_session_stays_usable() {
    let Some(fixture) = Fixture::new("zs_ro_query").await else {
        return;
    };
    let mut session = fixture.session(SessionAccess::ReadOnly).await;

    let read = session
        .simple(&format!("SELECT count(*) FROM {}", fixture.table))
        .await;
    assert_eq!(read.value(), Some("1"), "positive control: a read works");
    assert_still_read_only(&mut session, &fixture, "login").await;

    for escape in ESCAPES {
        let refused = session.simple(escape).await;
        assert!(refused.refused_with(READ_ONLY), "{escape}: {refused:?}");
        assert_eq!(refused.message(), REFUSED, "{escape}");
        assert_eq!(refused.status, b'I', "{escape}");
        assert_still_read_only(&mut session, &fixture, escape).await;
    }

    let read = session
        .simple(&format!("SELECT count(*) FROM {}", fixture.table))
        .await;
    assert_eq!(read.value(), Some("1"));
    session.close().await;
    assert_eq!(fixture.rows().await, "1");
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refused_parse_mid_batch_keeps_order() {
    let Some(fixture) = Fixture::new("zs_ro_parse").await else {
        return;
    };
    let mut session = fixture.session(SessionAccess::ReadOnly).await;
    let count = format!("SELECT count(*) FROM {}", fixture.table);

    session
        .send(&[
            parse("s1", &count),
            parse("s2", "BEGIN READ WRITE"),
            parse("s3", "SELECT 2"),
            sync(),
        ])
        .await;
    let batch = session.reply().await;
    assert_eq!(batch.tags, b"1EZ", "{batch:?}");
    assert!(batch.refused_with("42883"), "{batch:?}");
    assert!(batch.message().contains("zs_refused_read_only_resource"));
    assert_eq!(batch.status, b'I');

    session
        .send(&[
            parse("", "SELECT 'first'"),
            sync(),
            parse("", "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE"),
            bind(""),
            execute(),
            sync(),
            bind("s1"),
            execute(),
            sync(),
        ])
        .await;
    let first = session.reply().await;
    let refused = session.reply().await;
    let last = session.reply().await;
    assert_eq!(first.tags, b"1Z", "{first:?}");
    assert_eq!(refused.tags, b"EZ", "{refused:?}");
    assert!(refused.refused_with("42883"), "{refused:?}");
    assert_eq!(last.tags, b"2DCZ", "{last:?}");
    assert_eq!(last.value(), Some("1"));

    assert_eq!(session.simple("BEGIN").await.status, b'T');
    let read = session.simple(&count).await;
    assert_eq!(read.value(), Some("1"));
    let refused = session.simple("SET TRANSACTION READ WRITE").await;
    assert!(refused.refused_with(READ_ONLY), "{refused:?}");
    assert_eq!(refused.message(), REFUSED);
    assert_eq!(
        refused.status, b'E',
        "the transaction is failed, as for any error"
    );
    let aborted = session.simple("SELECT 1").await;
    assert!(aborted.refused_with("25P02"), "{aborted:?}");
    assert_eq!(session.simple("ROLLBACK").await.status, b'I');

    assert_eq!(session.simple("BEGIN").await.status, b'T');
    session
        .send(&[
            parse("", "BEGIN READ WRITE"),
            sync(),
            parse("", "SELECT 3"),
            sync(),
        ])
        .await;
    let refused = session.reply().await;
    let after = session.reply().await;
    assert_eq!(refused.tags, b"EZ", "{refused:?}");
    assert_eq!(refused.status, b'E');
    assert_eq!(after.tags, b"EZ", "{after:?}");
    assert!(after.refused_with("25P02"), "{after:?}");
    assert_eq!(session.simple("ROLLBACK").await.status, b'I');

    assert_still_read_only(&mut session, &fixture, "the batches").await;
    session.close().await;
    assert_eq!(fixture.rows().await, "1");
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn function_call_message_is_refused() {
    let Some(fixture) = Fixture::new("zs_ro_function").await else {
        return;
    };
    let mut control = fixture.session(SessionAccess::ReadWrite).await;
    control
        .send(&[function_call(["application_name", "zs-probe", "f"])])
        .await;
    let called = control.reply().await;
    assert!(
        called.ok() && called.tags.contains(&b'V'),
        "negative control: a read-write session calls the function: {called:?}"
    );
    let name = control.simple("SHOW application_name").await;
    assert_eq!(name.value(), Some("zs-probe"));
    control.close().await;

    let mut session = fixture.session(SessionAccess::ReadOnly).await;
    session
        .send(&[function_call(["default_transaction_read_only", "off", "f"])])
        .await;
    let refused = session.reply().await;
    assert_eq!(refused.tags, b"EZ", "{refused:?}");
    assert!(refused.refused_with(READ_ONLY), "{refused:?}");
    assert_eq!(refused.message(), REFUSED);
    assert_still_read_only(&mut session, &fixture, "a function call").await;
    session.close().await;
    assert_eq!(fixture.rows().await, "1");
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn migration_script_gets_read_only_error() {
    let Some(fixture) = Fixture::new("zs_ro_migration").await else {
        return;
    };
    let mut session = fixture.session(SessionAccess::ReadOnly).await;

    let script = session
        .simple(&format!(
            "CREATE TABLE zs_ro_migration_new (id int); ALTER TABLE {} ADD COLUMN note text; {};",
            fixture.table,
            fixture.insert()
        ))
        .await;
    assert!(script.refused_with(READ_ONLY), "{script:?}");
    assert!(script.message().contains("read-only"), "{script:?}");

    let guarded = session
        .simple(&format!(
            "SET statement_timeout = 0; SET default_transaction_read_only = off; {};",
            fixture.insert()
        ))
        .await;
    assert!(guarded.refused_with(READ_ONLY), "{guarded:?}");
    assert!(guarded.message().contains("read-only"), "{guarded:?}");

    session
        .send(&[
            parse("", &format!("INSERT INTO {} VALUES (3)", fixture.table)),
            bind(""),
            execute(),
            sync(),
        ])
        .await;
    let prepared = session.reply().await;
    assert!(prepared.refused_with(READ_ONLY), "{prepared:?}");
    assert!(prepared.message().contains("read-only"), "{prepared:?}");
    session.close().await;

    let mut admin = admin(&fixture.db).await;
    let created = admin
        .simple("SELECT to_regclass('zs_ro_migration_new') IS NULL")
        .await;
    assert_eq!(created.value(), Some("t"));
    admin.close().await;
    assert_eq!(fixture.rows().await, "1");
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn read_write_grant_changes_nothing() {
    let Some(fixture) = Fixture::new("zs_ro_write").await else {
        return;
    };
    let mut session = fixture.session(SessionAccess::ReadWrite).await;

    let mode = session.simple("SHOW default_transaction_read_only").await;
    assert_eq!(mode.value(), Some("off"));
    let insert = session.simple(&fixture.insert()).await;
    assert!(insert.ok(), "{insert:?}");
    for statement in [
        "SET default_transaction_read_only = off",
        "BEGIN READ WRITE",
        "COMMIT",
    ] {
        let reply = session.simple(statement).await;
        assert!(reply.ok(), "{statement}: {reply:?}");
    }
    session.close().await;
    assert_eq!(fixture.rows().await, "2");
    fixture.remove().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn client_startup_cannot_switch_the_mode_off() {
    let Some(fixture) = Fixture::new("zs_ro_startup").await else {
        return;
    };
    let switch_off: [&[(&str, &str)]; 8] = [
        &[("default_transaction_read_only", "off")],
        &[("DEFAULT_TRANSACTION_READ_ONLY", "off")],
        &[("transaction_read_only", "off")],
        &[("options", "-c default_transaction_read_only=off")],
        &[("options", "-cdefault_transaction_read_only=off")],
        &[("options", "--default-transaction-read-only=off")],
        &[("options", "-c x.y=1\\")],
        &[
            ("options", "-c x.y=1 -c default_transaction_read_only=off"),
            ("default_transaction_read_only", "off"),
        ],
    ];

    let controls: [(&[(&str, &str)], &str); 3] = [
        (&[("options", "--default-transaction-read-only=on")], "on"),
        (
            &[
                ("options", "-c default_transaction_read_only=on"),
                ("default_transaction_read_only", "off"),
            ],
            "off",
        ),
        (
            &[(
                "options",
                "-c default_transaction_read_only=on -c Default-Transaction-Read-Only=off",
            )],
            "off",
        ),
    ];
    for (extra, expected) in controls {
        let mut control = fixture.session_with(SessionAccess::ReadWrite, extra).await;
        let mode = control.simple("SHOW default_transaction_read_only").await;
        control.close().await;
        assert_eq!(
            mode.value(),
            Some(expected),
            "negative control: the server applies {extra:?} unchanged in a read-write session"
        );
    }

    for extra in switch_off {
        let mut session = fixture.session_with(SessionAccess::ReadOnly, extra).await;
        assert_still_read_only(&mut session, &fixture, &format!("{extra:?}")).await;
        session.close().await;
    }

    let (local, refusals) = listen(&fixture.db, ROLE_PASSWORD, SessionAccess::ReadOnly).await;
    let trailing = Client::try_open(local, ROLE, &fixture.db, &[("options", "-c x.y=1 \\")]).await;
    assert_eq!(
        trailing.err().map(|(code, _)| code),
        Some("28000".to_string())
    );
    assert_eq!(*refusals.lock().unwrap(), vec![("connect", "read-only")]);

    assert_eq!(fixture.rows().await, "1");
    fixture.remove().await;
}
