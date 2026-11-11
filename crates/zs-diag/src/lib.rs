use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

const QUEUE: usize = 4096;
const CAP: u64 = 50 * 1024 * 1024;
const KEEP: usize = 10;
const TEXT_LIMIT: usize = 200;
const TOKEN_LIMIT: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Component {
    Agent,
    Grant,
    Proxy,
    Postgres,
    Mysql,
    Mongo,
    Redis,
}

impl Component {
    fn as_str(self) -> &'static str {
        match self {
            Component::Agent => "agent",
            Component::Grant => "grant",
            Component::Proxy => "proxy",
            Component::Postgres => "postgres",
            Component::Mysql => "mysql",
            Component::Mongo => "mongo",
            Component::Redis => "redis",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn new(value: &str) -> Option<Self> {
        let permitted = |b: u8| b.is_ascii_alphanumeric() || b"._-:@[]/".contains(&b);
        // A lone `*` is the any-method operation (ADR-0033); it holds no request data.
        (value == "*"
            || (!value.is_empty() && value.len() <= TOKEN_LIMIT && value.bytes().all(permitted)))
        .then(|| Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerText(String);

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

impl ServerText {
    pub fn new(text: &str, secret: &[u8]) -> Option<Self> {
        if holds(text.as_bytes(), secret) {
            return None;
        }
        let cleaned: String = text.chars().filter(|c| !c.is_control()).collect();
        if holds(cleaned.as_bytes(), secret) {
            return None;
        }
        Some(Self(cleaned.chars().take(TEXT_LIMIT).collect()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Code(&'static str),
    Num(u64),
    Flag(bool),
    Token(Token),
    Tokens(Vec<Token>),
    Invalid,
}

impl Value {
    fn of(text: &str) -> Self {
        Token::new(text).map_or(Value::Invalid, Value::Token)
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            Value::Code(code) => (*code).into(),
            Value::Num(n) => (*n).into(),
            Value::Flag(b) => (*b).into(),
            Value::Token(t) => t.as_str().into(),
            Value::Tokens(ts) => ts
                .iter()
                .map(|t| serde_json::Value::from(t.as_str()))
                .collect::<Vec<_>>()
                .into(),
            Value::Invalid => "invalid".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    component: Component,
    name: &'static str,
    level: Level,
    ts_ms: u64,
    conn: Option<u64>,
    req: Option<u64>,
    resource: Option<Value>,
    dest: Option<Value>,
    audit_seq: Option<u64>,
    fields: Vec<(&'static str, Value)>,
    failure: Option<&'static str>,
    text: Option<ServerText>,
}

impl Event {
    pub fn new(component: Component, name: &'static str) -> Self {
        Self {
            component,
            name,
            level: Level::Info,
            ts_ms: 0,
            conn: None,
            req: None,
            resource: None,
            dest: None,
            audit_seq: None,
            fields: Vec::new(),
            failure: None,
            text: None,
        }
    }

    pub fn warn(mut self) -> Self {
        self.level = Level::Warn;
        self
    }

    pub fn error(mut self) -> Self {
        self.level = Level::Error;
        self
    }

    pub fn conn(mut self, id: u64) -> Self {
        self.conn = Some(id);
        self
    }

    pub fn req(mut self, n: u64) -> Self {
        self.req = Some(n);
        self
    }

    pub fn resource(mut self, name: &str) -> Self {
        self.resource = Some(Value::of(name));
        self
    }

    pub fn dest(mut self, host: &str, port: u16) -> Self {
        let permitted = |b: u8| b.is_ascii_alphanumeric() || b".-:[]".contains(&b);
        let valid = !host.is_empty() && host.bytes().all(permitted);
        self.dest = Some(if valid {
            Value::of(&format!("{host}:{port}"))
        } else {
            Value::Invalid
        });
        self
    }

    pub fn dest_withheld(mut self) -> Self {
        self.dest = Some(Value::Invalid);
        self
    }

    pub fn audit_seq(mut self, seq: u64) -> Self {
        self.audit_seq = Some(seq);
        self
    }

    pub fn code(mut self, key: &'static str, value: &'static str) -> Self {
        self.fields.push((key, Value::Code(value)));
        self
    }

    pub fn num(mut self, key: &'static str, value: u64) -> Self {
        self.fields.push((key, Value::Num(value)));
        self
    }

    pub fn flag(mut self, key: &'static str, value: bool) -> Self {
        self.fields.push((key, Value::Flag(value)));
        self
    }

    pub fn token(mut self, key: &'static str, value: &str) -> Self {
        self.fields.push((key, Value::of(value)));
        self
    }

    pub fn tokens(mut self, key: &'static str, values: &[String]) -> Self {
        let tokens: Option<Vec<Token>> = values.iter().map(|v| Token::new(v)).collect();
        self.fields
            .push((key, tokens.map_or(Value::Invalid, Value::Tokens)));
        self
    }

    pub fn failure(mut self, kind: &'static str) -> Self {
        self.failure = Some(kind);
        self
    }

    pub fn server_text(mut self, text: Option<ServerText>) -> Self {
        self.text = text;
        self
    }

    fn at(mut self, ts_ms: u64) -> Self {
        self.ts_ms = ts_ms;
        self
    }

    fn to_line(&self, run: &str, seq: u64) -> String {
        let mut line = serde_json::Map::new();
        line.insert("ts_ms".into(), self.ts_ms.into());
        line.insert("run".into(), run.into());
        line.insert("seq".into(), seq.into());
        line.insert("level".into(), self.level.as_str().into());
        line.insert("component".into(), self.component.as_str().into());
        line.insert("event".into(), self.name.into());
        if let Some(conn) = self.conn {
            line.insert("conn".into(), conn.into());
        }
        if let Some(req) = self.req {
            line.insert("req".into(), req.into());
        }
        if let Some(resource) = &self.resource {
            line.insert("resource".into(), resource.to_json());
        }
        if let Some(dest) = &self.dest {
            line.insert("dest".into(), dest.to_json());
        }
        if let Some(seq) = self.audit_seq {
            line.insert("audit_seq".into(), seq.into());
        }
        if !self.fields.is_empty() {
            let mut fields = serde_json::Map::new();
            for (key, value) in &self.fields {
                fields.insert((*key).into(), value.to_json());
            }
            line.insert("fields".into(), fields.into());
        }
        if self.failure.is_some() || self.text.is_some() {
            let mut error = serde_json::Map::new();
            if let Some(kind) = self.failure {
                error.insert("kind".into(), kind.into());
            }
            if let Some(text) = &self.text {
                error.insert("text".into(), text.as_str().into());
            }
            line.insert("error".into(), error.into());
        }
        serde_json::Value::Object(line).to_string()
    }
}

enum Message {
    Event(Box<Event>),
    Stop,
}

struct Inner {
    path: PathBuf,
    conn: AtomicU64,
    dropped: Arc<AtomicU64>,
    sender: SyncSender<Message>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone, Default)]
pub struct DiagLog {
    inner: Option<Arc<Inner>>,
}

impl DiagLog {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn open_run(audit_path: &Path, explicit: Option<&Path>) -> std::io::Result<Self> {
        let run = format!("{}-{}", now_ms(), std::process::id());
        if let Some(path) = explicit {
            return Self::open_with_cap(path, &run, CAP);
        }
        let dir = log_dir(audit_path);
        create_private_dir(&dir)?;
        let current = dir.join(format!("run-{run}.jsonl"));
        let log = Self::open_with_cap(&current, &run, CAP)?;
        prune(&dir, &current, KEEP);
        Ok(log)
    }

    pub fn open_with_cap(path: &Path, run: &str, cap: u64) -> std::io::Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_private_dir(parent)?;
        }
        let file = open_private_file(path)?;
        let (sender, receiver) = sync_channel(QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let writer = Writer::new(
            Box::new(BufWriter::new(file)),
            Box::new(std::io::stderr()),
            run,
            cap,
        );
        let counted = dropped.clone();
        let handle = std::thread::Builder::new()
            .name("zs-diag".into())
            .spawn(move || drain(writer, receiver, counted))?;
        Ok(Self {
            inner: Some(Arc::new(Inner {
                path: path.to_path_buf(),
                conn: AtomicU64::new(0),
                dropped,
                sender,
                writer: Mutex::new(Some(handle)),
            })),
        })
    }

    pub fn path(&self) -> Option<PathBuf> {
        self.inner.as_ref().map(|inner| inner.path.clone())
    }

    pub fn next_conn(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |inner| inner.conn.fetch_add(1, Ordering::Relaxed) + 1)
    }

    pub fn emit(&self, event: Event) {
        let Some(inner) = &self.inner else {
            return;
        };
        let stamped = Box::new(event.at(now_ms()));
        if inner.sender.try_send(Message::Event(stamped)).is_err() {
            inner.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn close(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let handle = inner.writer.lock().ok().and_then(|mut slot| slot.take());
        if let Some(handle) = handle {
            let _ = inner.sender.send(Message::Stop);
            let _ = handle.join();
        }
    }
}

struct Writer {
    out: Box<dyn Write + Send>,
    warn: Box<dyn Write + Send>,
    run: String,
    seq: u64,
    written: u64,
    cap: u64,
    capped: bool,
    failed: bool,
}

impl Writer {
    fn new(out: Box<dyn Write + Send>, warn: Box<dyn Write + Send>, run: &str, cap: u64) -> Self {
        Self {
            out,
            warn,
            run: run.to_string(),
            seq: 0,
            written: 0,
            cap,
            capped: false,
            failed: false,
        }
    }

    fn write_line(&mut self, line: &str) -> bool {
        if self.failed {
            return false;
        }
        let written = writeln!(self.out, "{line}").and_then(|()| self.out.flush());
        match written {
            Ok(()) => true,
            Err(error) => {
                self.failed = true;
                let _ = writeln!(
                    self.warn,
                    "zs: diagnostic log unavailable: {}",
                    io_kind(&error)
                );
                let _ = self.warn.flush();
                false
            }
        }
    }

    fn put(&mut self, event: &Event) {
        if self.capped || self.failed {
            return;
        }
        let line = event.to_line(&self.run, self.seq + 1);
        if self.written + line.len() as u64 + 1 > self.cap {
            self.capped = true;
            let notice = Event::new(Component::Agent, "log_capped")
                .warn()
                .at(now_ms())
                .to_line(&self.run, self.seq + 1);
            self.write_line(&notice);
            return;
        }
        self.seq += 1;
        if self.write_line(&line) {
            self.written += line.len() as u64 + 1;
        }
    }
}

fn drain(mut writer: Writer, receiver: Receiver<Message>, dropped: Arc<AtomicU64>) {
    for message in receiver {
        match message {
            Message::Event(event) => writer.put(&event),
            Message::Stop => break,
        }
    }
    let end = Event::new(Component::Agent, "run_ended")
        .num("dropped", dropped.load(Ordering::Relaxed))
        .at(now_ms());
    writer.put(&end);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn log_dir(audit_path: &Path) -> PathBuf {
    let audit_dir = audit_path.parent().unwrap_or_else(|| Path::new(""));
    audit_dir
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(".zs-log")
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

fn open_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn prune(dir: &Path, current: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut runs: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("run-") && n.ends_with(".jsonl"))
        })
        .filter(|path| path.file_name() != current.file_name())
        .collect();
    runs.sort();
    let excess = runs.len().saturating_sub(keep.saturating_sub(1));
    for old in runs.into_iter().take(excess) {
        let _ = std::fs::remove_file(old);
    }
}

pub fn io_kind(error: &std::io::Error) -> &'static str {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::NotFound => "not_found",
        ErrorKind::PermissionDenied => "permission_denied",
        ErrorKind::ConnectionRefused => "connection_refused",
        ErrorKind::ConnectionReset => "connection_reset",
        ErrorKind::ConnectionAborted => "connection_aborted",
        ErrorKind::NotConnected => "not_connected",
        ErrorKind::AddrInUse => "addr_in_use",
        ErrorKind::AddrNotAvailable => "addr_not_available",
        ErrorKind::BrokenPipe => "broken_pipe",
        ErrorKind::AlreadyExists => "already_exists",
        ErrorKind::WouldBlock => "would_block",
        ErrorKind::InvalidInput => "invalid_input",
        ErrorKind::InvalidData => "invalid_data",
        ErrorKind::TimedOut => "timed_out",
        ErrorKind::WriteZero => "write_zero",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::UnexpectedEof => "unexpected_eof",
        ErrorKind::OutOfMemory => "out_of_memory",
        ErrorKind::StorageFull => "storage_full",
        ErrorKind::ReadOnlyFilesystem => "read_only_filesystem",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn a_token_refuses_text_that_can_hold_request_data() {
        for good in [
            "api.stripe.com:443",
            "g-4477452a",
            "caching_sha2_password",
            "[::1]:5432",
            "/oauth/token",
            "GET",
            "8.0.36-0ubuntu0.22.04.1",
            "*",
        ] {
            assert!(Token::new(good).is_some(), "{good}");
        }
        let long = "a".repeat(129);
        for bad in [
            "",
            "a b",
            "/x?y=1",
            "%2F",
            "a=b",
            "a&b",
            "a#b",
            "a;b",
            "a\\b",
            "\"x\"",
            "a\tb",
            &long,
            "a*",
            "**",
            "*.example.com",
        ] {
            assert!(Token::new(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn server_text_is_cut_cleaned_and_dropped_when_it_holds_the_secret() {
        let secret = b"pencil-42";
        assert_eq!(
            ServerText::new("password authentication failed\nfor user \"app\"", secret)
                .unwrap()
                .as_str(),
            "password authentication failedfor user \"app\""
        );
        assert!(ServerText::new("bad password pencil-42 given", secret).is_none());
        assert!(ServerText::new("bad pencil-\u{0}42", secret).is_none());
        assert_eq!(
            ServerText::new(&"x".repeat(500), secret)
                .unwrap()
                .as_str()
                .len(),
            200
        );
        assert!(ServerText::new("anything", b"").is_some());
    }

    #[test]
    fn server_text_is_checked_for_the_secret_before_it_is_cut() {
        let secret = b"pencil-42";
        assert!(ServerText::new(&"x".repeat(195), secret).is_some());
        let split = format!("{}pencil-\u{1}42", "x".repeat(195));
        assert!(ServerText::new(&split, secret).is_none());
    }

    #[test]
    fn a_destination_with_userinfo_or_a_path_is_recorded_as_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        let log = DiagLog::open_with_cap(&path, "1-1", 1 << 20).unwrap();
        for host in [
            "api.stripe.com",
            "user:zsdiag-dest-secret@api.stripe.com",
            "zsdiag-dest-token@api.stripe.com",
            "api.stripe.com/zsdiag-dest-path",
            "api.stripe.com?zsdiag=1",
            "[::1]",
            "",
        ] {
            log.emit(Event::new(Component::Proxy, "conn_accepted").dest(host, 443));
        }
        log.close();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("zsdiag"), "{text}");
        let lines = lines(&path);
        let dests: Vec<&str> = lines
            .iter()
            .take(7)
            .map(|l| l["dest"].as_str().unwrap())
            .collect();
        assert_eq!(
            dests,
            [
                "api.stripe.com:443",
                "invalid",
                "invalid",
                "invalid",
                "invalid",
                "[::1]:443",
                "invalid"
            ]
        );
    }

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Broken {
        attempts: Arc<AtomicU64>,
        on_flush: bool,
    }

    impl Write for Broken {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            if self.on_flush {
                Ok(buf.len())
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.on_flush {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn a_write_failure_warns_once_and_stops_writing() {
        let healthy = Shared::default();
        let quiet = Shared::default();
        let mut writer = Writer::new(
            Box::new(healthy.clone()),
            Box::new(quiet.clone()),
            "1-1",
            1 << 20,
        );
        for n in 0..3 {
            writer.put(&Event::new(Component::Proxy, "conn_accepted").conn(n));
        }
        assert_eq!(healthy.text().lines().count(), 3);
        assert_eq!(quiet.text(), "");

        for (on_flush, kind) in [(false, "storage_full"), (true, "permission_denied")] {
            let attempts = Arc::new(AtomicU64::new(0));
            let warned = Shared::default();
            let sink = Broken {
                attempts: attempts.clone(),
                on_flush,
            };
            let mut writer = Writer::new(Box::new(sink), Box::new(warned.clone()), "1-1", 1 << 20);
            writer.put(&Event::new(Component::Proxy, "conn_accepted").conn(0));
            let first = attempts.load(Ordering::Relaxed);
            assert!(first >= 1, "{kind}");
            for n in 1..5 {
                writer.put(&Event::new(Component::Proxy, "conn_accepted").conn(n));
            }
            assert_eq!(
                warned.text(),
                format!("zs: diagnostic log unavailable: {kind}\n")
            );
            assert_eq!(attempts.load(Ordering::Relaxed), first, "{kind}");
        }
    }

    #[test]
    fn events_are_one_json_object_per_line_with_the_documented_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        let log = DiagLog::open_with_cap(&path, "100-7", 1 << 20).unwrap();
        let conn = log.next_conn();
        log.emit(
            Event::new(Component::Proxy, "request_decided")
                .conn(conn)
                .req(2)
                .resource("stripe-production")
                .dest("api.stripe.com", 443)
                .audit_seq(9)
                .token("method", "POST")
                .code("decision", "allow")
                .num("status", 200)
                .flag("scoped", true)
                .tokens("operations", &["GET".to_string(), "POST".to_string()]),
        );
        log.emit(
            Event::new(Component::Postgres, "upstream_auth_failed")
                .warn()
                .failure("refused")
                .server_text(ServerText::new("bad proof", b"pw")),
        );
        log.close();
        let lines = lines(&path);
        assert_eq!(lines.len(), 3);
        let first = &lines[0];
        assert_eq!(first["run"], "100-7");
        assert_eq!(first["seq"], 1);
        assert_eq!(first["level"], "info");
        assert_eq!(first["component"], "proxy");
        assert_eq!(first["event"], "request_decided");
        assert_eq!(first["conn"], 1);
        assert_eq!(first["req"], 2);
        assert_eq!(first["resource"], "stripe-production");
        assert_eq!(first["dest"], "api.stripe.com:443");
        assert_eq!(first["audit_seq"], 9);
        assert_eq!(first["fields"]["method"], "POST");
        assert_eq!(first["fields"]["decision"], "allow");
        assert_eq!(first["fields"]["status"], 200);
        assert_eq!(first["fields"]["scoped"], true);
        assert_eq!(first["fields"]["operations"][1], "POST");
        assert!(first["ts_ms"].as_u64().unwrap() > 0);
        assert_eq!(lines[1]["level"], "warn");
        assert_eq!(lines[1]["error"]["kind"], "refused");
        assert_eq!(lines[1]["error"]["text"], "bad proof");
        assert_eq!(lines[2]["event"], "run_ended");
        assert_eq!(lines[2]["fields"]["dropped"], 0);
        assert_eq!(lines[2]["seq"], 3);
    }

    #[test]
    fn an_invalid_token_is_recorded_as_invalid_not_as_its_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        let log = DiagLog::open_with_cap(&path, "1-1", 1 << 20).unwrap();
        log.emit(
            Event::new(Component::Agent, "binding")
                .resource("a b")
                .token("host", "x?leak=1")
                .tokens("scope", &["/ok".to_string(), "/bad?q".to_string()]),
        );
        log.close();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("leak") && !text.contains("bad?q") && !text.contains("a b"));
        let first = &lines(&path)[0];
        assert_eq!(first["resource"], "invalid");
        assert_eq!(first["fields"]["host"], "invalid");
        assert_eq!(first["fields"]["scope"], "invalid");
    }

    #[test]
    fn a_capped_log_stops_after_one_notice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        let log = DiagLog::open_with_cap(&path, "1-1", 600).unwrap();
        for n in 0..50 {
            log.emit(Event::new(Component::Proxy, "conn_accepted").conn(n));
        }
        log.close();
        let lines = lines(&path);
        assert!(
            lines.len() > 1,
            "positive control: some events were written"
        );
        assert_eq!(lines.last().unwrap()["event"], "log_capped");
        assert_eq!(
            lines.iter().filter(|l| l["event"] == "log_capped").count(),
            1
        );
        assert!(lines.iter().all(|l| l["event"] != "run_ended"));
    }

    #[test]
    fn a_disabled_log_does_nothing() {
        let log = DiagLog::disabled();
        log.emit(Event::new(Component::Agent, "run_started"));
        assert_eq!(log.next_conn(), 0);
        assert!(log.path().is_none());
        log.close();
    }

    #[test]
    fn connection_ids_are_unique_across_clones() {
        let dir = tempfile::tempdir().unwrap();
        let log = DiagLog::open_with_cap(&dir.path().join("run.jsonl"), "1-1", 1 << 20).unwrap();
        let other = log.clone();
        assert_eq!(log.next_conn(), 1);
        assert_eq!(other.next_conn(), 2);
        assert_eq!(log.next_conn(), 3);
        log.close();
    }

    #[test]
    fn open_run_puts_the_log_next_to_the_audit_directory_and_keeps_ten_runs() {
        let home = tempfile::tempdir().unwrap();
        let logs = home.path().join(".zs-log");
        std::fs::create_dir_all(&logs).unwrap();
        for n in 0..12 {
            std::fs::write(logs.join(format!("run-000000000000{n:01}-1.jsonl")), "").unwrap();
        }
        std::fs::write(logs.join("notes.txt"), "keep").unwrap();
        let audit = home.path().join(".zs-audit").join("audit.jsonl");
        let log = DiagLog::open_run(&audit, None).unwrap();
        let path = log.path().unwrap();
        log.close();
        assert_eq!(path.parent().unwrap(), logs.as_path());
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        assert!(
            name.starts_with("run-") && name.ends_with(".jsonl"),
            "{name}"
        );
        let runs: Vec<String> = std::fs::read_dir(&logs)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("run-") && n.ends_with(".jsonl"))
            .collect();
        assert_eq!(runs.len(), 10, "{runs:?}");
        assert!(runs.contains(&name));
        assert!(logs.join("notes.txt").exists());
        let mut planted: Vec<String> = (0..12)
            .map(|n| format!("run-000000000000{n:01}-1.jsonl"))
            .collect();
        planted.sort();
        for gone in &planted[..3] {
            assert!(!logs.join(gone).exists(), "{gone}");
        }
        for kept in &planted[3..] {
            assert!(logs.join(kept).exists(), "{kept}");
        }
    }

    #[test]
    fn retention_keeps_the_current_run_when_older_names_sort_after_it() {
        let home = tempfile::tempdir().unwrap();
        let logs = home.path().join(".zs-log");
        std::fs::create_dir_all(&logs).unwrap();
        let mut planted: Vec<String> = (0..12)
            .map(|n| format!("run-9999999999999-{n}.jsonl"))
            .collect();
        for name in &planted {
            std::fs::write(logs.join(name), "").unwrap();
        }
        planted.sort();
        let audit = home.path().join(".zs-audit").join("audit.jsonl");
        let log = DiagLog::open_run(&audit, None).unwrap();
        let path = log.path().unwrap();
        log.emit(Event::new(Component::Agent, "run_started"));
        log.close();
        assert!(path.exists(), "the current run was pruned");
        assert!(!lines(&path).is_empty());
        let mut runs: Vec<String> = std::fs::read_dir(&logs)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("run-") && n.ends_with(".jsonl"))
            .collect();
        runs.sort();
        assert_eq!(runs.len(), 10, "{runs:?}");
        let mut expected: Vec<String> = planted[3..].to_vec();
        expected.push(path.file_name().unwrap().to_str().unwrap().to_string());
        expected.sort();
        assert_eq!(runs, expected);
    }

    #[test]
    fn an_explicit_path_is_used_as_is_and_nothing_is_pruned() {
        let home = tempfile::tempdir().unwrap();
        let logs = home.path().join(".zs-log");
        std::fs::create_dir_all(&logs).unwrap();
        for n in 0..12 {
            std::fs::write(logs.join(format!("run-000000000000{n:01}-1.jsonl")), "").unwrap();
        }
        let explicit = home.path().join("deep").join("mine.jsonl");
        let audit = home.path().join(".zs-audit").join("audit.jsonl");
        let log = DiagLog::open_run(&audit, Some(&explicit)).unwrap();
        log.close();
        assert_eq!(log.path().unwrap(), explicit);
        assert!(explicit.exists());
        assert_eq!(std::fs::read_dir(&logs).unwrap().count(), 12);
    }

    #[test]
    fn the_default_directory_for_a_relative_audit_path_is_dot_zs_log() {
        assert_eq!(
            log_dir(Path::new(".zs-audit/audit.jsonl")),
            PathBuf::from(".zs-log")
        );
        assert_eq!(log_dir(Path::new("audit.jsonl")), PathBuf::from(".zs-log"));
        assert_eq!(
            log_dir(Path::new("/tmp/x/.zs-audit/audit.jsonl")),
            PathBuf::from("/tmp/x/.zs-log")
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_private_to_the_user() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let audit = home.path().join(".zs-audit").join("audit.jsonl");
        let log = DiagLog::open_run(&audit, None).unwrap();
        let path = log.path().unwrap();
        log.close();
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn io_kinds_are_fixed_codes() {
        let kind = |k| io_kind(&std::io::Error::from(k));
        assert_eq!(kind(std::io::ErrorKind::TimedOut), "timed_out");
        assert_eq!(
            kind(std::io::ErrorKind::ConnectionRefused),
            "connection_refused"
        );
        assert_eq!(kind(std::io::ErrorKind::UnexpectedEof), "unexpected_eof");
        assert_eq!(io_kind(&std::io::Error::other("free text")), "other");
    }
}
