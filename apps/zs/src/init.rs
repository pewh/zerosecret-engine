use std::fs;
use std::io::{ErrorKind, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PLACEHOLDER: &str = "placeholder_managed_by_zerosecret";
pub const SANITIZED_MARKER: &str = "# zs init: brokered secrets in this file were replaced; the original is in a .zerosecret_backup_* file";

const SECRET_QUERY_WORDS: &[&str] = &["password", "passwd", "pwd", "secret", "token"];
const SECRET_KEY_WORDS: &[&str] = &[
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "API_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
];
const PUBLIC_KEY_WORDS: &[&str] = &["PUBLIC", "PUBLISHABLE"];
const PUBLIC_VALUE_PREFIXES: &[&str] = &["pk_live_", "pk_test_"];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScannedBinding {
    pub resource: String,
    pub host: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<ScannedAuth>,
}

fn default_protocol() -> String {
    "https".into()
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "scheme", rename_all = "kebab-case")]
pub enum ScannedAuth {
    Bearer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unbrokered {
    pub key: String,
    pub reason: &'static str,
}

#[derive(Debug, Default)]
pub struct ScanReport {
    pub bindings: Vec<ScannedBinding>,
    pub sanitized: String,
    pub replaced: Vec<String>,
    pub unbrokered: Vec<Unbrokered>,
}

pub struct InitOptions {
    pub dry_run: bool,
    pub force: bool,
    pub from_env: Option<PathBuf>,
    pub control: Option<String>,
    pub listen_port_start: u16,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            force: false,
            from_env: None,
            control: None,
            listen_port_start: 54320,
        }
    }
}

struct HttpService {
    resource: &'static str,
    host: &'static str,
    key_word: &'static str,
    value_prefixes: &'static [&'static str],
}

const HTTP_SERVICES: &[HttpService] = &[
    HttpService {
        resource: "stripe",
        host: "api.stripe.com",
        key_word: "STRIPE",
        value_prefixes: &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
    },
    HttpService {
        resource: "openai",
        host: "api.openai.com",
        key_word: "OPENAI",
        value_prefixes: &["sk-proj-"],
    },
    HttpService {
        resource: "github",
        host: "api.github.com",
        key_word: "GITHUB",
        value_prefixes: &["ghp_", "github_pat_"],
    },
];

impl HttpService {
    fn matches(&self, upper_key: &str, value: &str) -> bool {
        if value.starts_with("whsec_") {
            return false;
        }
        (upper_key.contains(self.key_word)
            && (upper_key.contains("KEY") || upper_key.contains("TOKEN")))
            || self.value_prefixes.iter().any(|p| value.starts_with(p))
    }
}

struct DbScheme {
    prefix: &'static str,
    protocol: &'static str,
    resource: &'static str,
}

const DB_SCHEMES: &[DbScheme] = &[
    DbScheme {
        prefix: "postgres://",
        protocol: "postgres",
        resource: "postgres-db",
    },
    DbScheme {
        prefix: "postgresql://",
        protocol: "postgres",
        resource: "postgres-db",
    },
    DbScheme {
        prefix: "mysql://",
        protocol: "mysql",
        resource: "mysql-db",
    },
    DbScheme {
        prefix: "mongodb://",
        protocol: "mongo",
        resource: "mongo-db",
    },
];

struct DbUrl<'a> {
    user: Option<&'a str>,
    has_password: bool,
    host: &'a str,
    port: Option<u16>,
    path: &'a str,
    query: Option<&'a str>,
}

impl DbUrl<'_> {
    fn is_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }

    fn query_param(&self, name: &str) -> Option<&str> {
        self.query?
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    fn safe_query(&self) -> String {
        let kept: Vec<&str> = self
            .query
            .unwrap_or("")
            .split('&')
            .filter(|pair| !pair.is_empty())
            .filter(|pair| {
                let name = pair.split_once('=').map_or(*pair, |(k, _)| k);
                let lower = name.to_ascii_lowercase();
                !SECRET_QUERY_WORDS.iter().any(|w| lower.contains(w))
            })
            .collect();
        if kept.is_empty() {
            String::new()
        } else {
            format!("?{}", kept.join("&"))
        }
    }
}

fn parse_db_url(rest: &str) -> Option<DbUrl<'_>> {
    let (before_query, query) = match rest.split_once('?') {
        Some((before, query)) => (before, Some(query)),
        None => (rest, None),
    };
    let (userinfo, location) = match before_query.rsplit_once('@') {
        Some((userinfo, location)) => (Some(userinfo), location),
        None => (None, before_query),
    };
    let (host_port, path) = location.split_once('/').unwrap_or((location, ""));
    let (host, port) = split_host_port(host_port)?;
    let (user, password) = match userinfo {
        Some(info) => info.split_once(':').unwrap_or((info, "")),
        None => ("", ""),
    };
    Some(DbUrl {
        user: Some(user).filter(|u| !u.is_empty()),
        has_password: !password.is_empty(),
        host,
        port,
        path,
        query,
    })
}

fn split_host_port(host_port: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = match host_port.strip_prefix('[') {
        Some(bracketed) => {
            let (host, after) = bracketed.split_once(']')?;
            if after.is_empty() {
                (host, None)
            } else {
                (host, Some(after.strip_prefix(':')?))
            }
        }
        None => match host_port.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        },
    };
    if host.is_empty() || host.contains([',', ' ', '@']) {
        return None;
    }
    let port = match port {
        Some(port) => Some(port.parse::<u16>().ok().filter(|p| *p != 0)?),
        None => None,
    };
    Some((host, port))
}

fn url_has_password(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let before_query = rest.split_once('?').map_or(rest, |(b, _)| b);
    before_query
        .rsplit_once('@')
        .and_then(|(info, _)| info.split_once(':'))
        .is_some_and(|(_, password)| !password.is_empty())
}

fn env_value(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = raw.strip_prefix(quote) {
            return inner.find(quote).map(|end| &inner[..end]);
        }
    }
    Some(raw.split(" #").next().unwrap_or(raw).trim())
}

fn unique_resource(bindings: &[ScannedBinding], base: &str) -> String {
    let taken = |name: &str| bindings.iter().any(|b| b.resource == name);
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|idx| format!("{base}-{idx}"))
        .find(|name| !taken(name))
        .unwrap_or_else(|| base.to_string())
}

fn take_port(next: &mut Option<u16>) -> Result<u16, String> {
    let port = next.ok_or("listen ports run past 65535; pass a lower --listen-port-start")?;
    *next = port.checked_add(1);
    Ok(port)
}

pub fn already_sanitized(content: &str) -> bool {
    content.contains(PLACEHOLDER) || content.lines().any(|l| l.trim() == SANITIZED_MARKER)
}

fn classify(
    name: &str,
    value: &str,
    report: &mut ScanReport,
    next_port: &mut Option<u16>,
) -> Result<Option<String>, String> {
    if value.starts_with("mongodb+srv://") {
        report.unbrokered.push(Unbrokered {
            key: name.to_string(),
            reason: "mongodb+srv needs a DNS SRV lookup that the mongo broker does not do; use a mongodb:// URL",
        });
        return Ok(None);
    }
    if let Some((scheme, rest)) = DB_SCHEMES
        .iter()
        .find_map(|s| value.strip_prefix(s.prefix).map(|rest| (s, rest)))
    {
        let Some(url) = parse_db_url(rest) else {
            report.unbrokered.push(Unbrokered {
                key: name.to_string(),
                reason: "database URL with several hosts or an unreadable host or port",
            });
            return Ok(None);
        };
        if url.is_loopback() && !url.has_password {
            return Ok(None);
        }
        let port = take_port(next_port)?;
        let is_mongo = scheme.protocol == "mongo";
        report.bindings.push(ScannedBinding {
            resource: unique_resource(&report.bindings, scheme.resource),
            host: url.host.to_string(),
            protocol: scheme.protocol.into(),
            listen_port: Some(port),
            upstream_port: url.port,
            user: is_mongo.then(|| url.user.unwrap_or("app").to_string()),
            auth_source: url
                .query_param("authSource")
                .filter(|_| is_mongo)
                .map(str::to_string),
            auth: None,
        });
        let user_prefix = match url.user {
            Some(user) if !is_mongo => format!("{user}@"),
            _ => String::new(),
        };
        return Ok(Some(format!(
            "{}{user_prefix}127.0.0.1:{port}/{}{}",
            scheme.prefix,
            url.path,
            url.safe_query()
        )));
    }
    let upper = name.to_ascii_uppercase();
    if PUBLIC_KEY_WORDS.iter().any(|w| upper.contains(w))
        || PUBLIC_VALUE_PREFIXES.iter().any(|p| value.starts_with(p))
    {
        return Ok(None);
    }
    if let Some(service) = HTTP_SERVICES.iter().find(|s| s.matches(&upper, value)) {
        if !report
            .bindings
            .iter()
            .any(|b| b.resource == service.resource)
        {
            report.bindings.push(ScannedBinding {
                resource: service.resource.into(),
                host: service.host.into(),
                protocol: "https".into(),
                listen_port: None,
                upstream_port: None,
                user: None,
                auth_source: None,
                auth: Some(ScannedAuth::Bearer),
            });
        }
        return Ok(Some(PLACEHOLDER.into()));
    }
    if url_has_password(value) {
        report.unbrokered.push(Unbrokered {
            key: name.to_string(),
            reason: "URL with an embedded password for a protocol zs init does not broker",
        });
    } else if SECRET_KEY_WORDS.iter().any(|w| upper.contains(w)) || upper.ends_with("_KEY") {
        report.unbrokered.push(Unbrokered {
            key: name.to_string(),
            reason: "zs init cannot broker this value; move it out of the file by hand",
        });
    }
    Ok(None)
}

pub fn scan_and_sanitize(content: &str, listen_port_start: u16) -> Result<ScanReport, String> {
    let mut report = ScanReport::default();
    let mut next_port = Some(listen_port_start);
    let mut lines = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            lines.push(line.to_string());
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            return Err(format!("line {number}: expected KEY=VALUE"));
        };
        let key = raw_key.trim();
        let name = key.strip_prefix("export ").unwrap_or(key).trim();
        if name.is_empty() {
            return Err(format!("line {number}: expected KEY=VALUE"));
        }
        let value = env_value(raw_value).ok_or_else(|| {
            format!("line {number}: multi-line or unterminated quoted values are not supported")
        })?;
        match classify(name, value, &mut report, &mut next_port)? {
            Some(new_value) => {
                lines.push(format!("{key}={new_value}"));
                report.replaced.push(name.to_string());
            }
            None => lines.push(line.to_string()),
        }
    }
    if !report.replaced.is_empty() {
        lines.insert(0, SANITIZED_MARKER.to_string());
    }
    report.sanitized = lines.join("\n");
    if content.ends_with('\n') {
        report.sanitized.push('\n');
    }
    Ok(report)
}

fn format_backup_timestamp(secs: u64) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_month = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m_month <= 2 { y + 1 } else { y };

    format!("{y:04}{m_month:02}{d:02}_{h:02}{m:02}{s:02}")
}

fn open_new_private(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn create_backup(env_path: &Path, content: &str, timestamp: &str) -> Result<PathBuf, String> {
    let mut base = env_path.as_os_str().to_owned();
    base.push(format!(".zerosecret_backup_{timestamp}"));
    for attempt in 0..100u32 {
        let mut name = base.clone();
        if attempt > 0 {
            name.push(format!("_{attempt}"));
        }
        let path = PathBuf::from(name);
        match open_new_private(&path) {
            Ok(mut file) => {
                return file
                    .write_all(content.as_bytes())
                    .and_then(|()| file.sync_all())
                    .map(|()| path.clone())
                    .map_err(|e| format!("cannot write backup {}: {e}", path.display()));
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot create backup {}: {e}", path.display())),
        }
    }
    Err(format!(
        "cannot create backup: {} and 99 numbered variants already exist",
        PathBuf::from(base).display()
    ))
}

fn ensure_gitignore() -> Result<(), String> {
    let path = Path::new(".gitignore");
    let mut content = fs::read_to_string(path).unwrap_or_default();
    if content.contains("*.zerosecret_backup_*") {
        return Ok(());
    }
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str("# ZeroSecret pre-init credential backups\n*.zerosecret_backup_*\n");
    fs::write(path, content).map_err(|e| format!("cannot update .gitignore: {e}"))
}

fn find_env_file(opts: &InitOptions) -> Option<PathBuf> {
    if let Some(path) = &opts.from_env {
        return Some(path.clone());
    }
    [".env", ".env.local", ".env.development"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

fn print_report(report: &ScanReport, env_path: &Path) {
    for binding in &report.bindings {
        stdout_line!("zs: binding {} -> {}", binding.resource, binding.host);
    }
    if !report.replaced.is_empty() {
        stdout_line!(
            "zs: replaced in {}: {}",
            env_path.display(),
            report.replaced.join(", ")
        );
    }
    for item in &report.unbrokered {
        stdout_line!(
            "zs: not brokered, left in {}: {} ({})",
            env_path.display(),
            item.key,
            item.reason
        );
    }
}

pub fn run_init(opts: &InitOptions) -> i32 {
    let policy_path = Path::new("zs-policy.json");
    if !opts.dry_run && policy_path.exists() && !opts.force {
        stderr_line!("zs: zs-policy.json already exists; pass --force to overwrite");
        return 1;
    }

    let Some(env_path) = find_env_file(opts) else {
        stderr_line!("zs: no .env, .env.local or .env.development found; pass --from-env <path>");
        return 2;
    };

    let env_content = match fs::read_to_string(&env_path) {
        Ok(c) => c,
        Err(e) => {
            stderr_line!("zs: cannot read {}: {e}", env_path.display());
            return 2;
        }
    };

    if already_sanitized(&env_content) {
        stderr_line!(
            "zs: {} was already sanitized by zs init; restore it from its .zerosecret_backup_* file before running zs init again",
            env_path.display()
        );
        return 1;
    }

    let report = match scan_and_sanitize(&env_content, opts.listen_port_start) {
        Ok(report) => report,
        Err(e) => {
            stderr_line!("zs: {}: {e}", env_path.display());
            return 2;
        }
    };

    let policy_val = serde_json::json!({
        "run": {
            "control": opts.control.as_deref().unwrap_or("http://127.0.0.1:8443"),
            "control_ca": "zerosecret/control-ca.crt"
        },
        "bindings": report.bindings
    });
    let policy_str = match serde_json::to_string_pretty(&policy_val) {
        Ok(s) => s,
        Err(e) => {
            stderr_line!("zs: cannot format policy: {e}");
            return 2;
        }
    };

    if opts.dry_run {
        stdout_line!("--- zs-policy.json (dry-run) ---");
        stdout_line!("{policy_str}");
        stdout_line!("--- {} (dry-run) ---", env_path.display());
        stdout_line!("{}", report.sanitized);
        print_report(&report, &env_path);
        return 0;
    }

    let backup_path = if report.replaced.is_empty() {
        None
    } else {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = match create_backup(&env_path, &env_content, &format_backup_timestamp(secs)) {
            Ok(path) => path,
            Err(e) => {
                stderr_line!("zs: {e}");
                return 2;
            }
        };
        if let Err(e) = ensure_gitignore() {
            stderr_line!("zs: {e}");
            return 2;
        }
        Some(backup)
    };

    if let Err(e) = fs::write(policy_path, format!("{policy_str}\n")) {
        stderr_line!("zs: cannot write zs-policy.json: {e}");
        return 2;
    }

    if backup_path.is_some()
        && let Err(e) = fs::write(&env_path, &report.sanitized)
    {
        stderr_line!("zs: cannot rewrite {}: {e}", env_path.display());
        return 2;
    }

    stdout_line!(
        "zs: generated zs-policy.json with {} binding(s)",
        report.bindings.len()
    );
    print_report(&report, &env_path);
    match backup_path {
        Some(path) => stdout_line!("zs: backup saved to {}", path.display()),
        None => stdout_line!(
            "zs: no secret replaced; {} left unchanged",
            env_path.display()
        ),
    }
    0
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn scan(content: &str) -> ScanReport {
        scan_and_sanitize(content, 54320).unwrap()
    }

    #[test]
    fn test_classify_env_lines_detects_services_and_scrubs_secrets() {
        let report = scan(
            r#"
# Comments should be ignored
STRIPE_SECRET_KEY=sk_live_supersecret12345
OPENAI_API_KEY=sk-proj-abcde987654321
DATABASE_URL=postgres://myuser:mypassword@db.internal.example:5432/production
PORT=8080
"#,
        );
        let bindings = &report.bindings;
        let sanitized_env = &report.sanitized;

        assert_eq!(bindings.len(), 3);
        assert_eq!(bindings[0].resource, "stripe");
        assert_eq!(bindings[0].host, "api.stripe.com");

        assert_eq!(bindings[1].resource, "openai");
        assert_eq!(bindings[1].host, "api.openai.com");

        assert_eq!(bindings[2].resource, "postgres-db");
        assert_eq!(bindings[2].host, "db.internal.example");
        assert_eq!(bindings[2].protocol, "postgres");
        assert_eq!(bindings[2].listen_port, Some(54320));

        assert!(!sanitized_env.contains("sk_live_supersecret12345"));
        assert!(!sanitized_env.contains("sk-proj-abcde987654321"));
        assert!(!sanitized_env.contains("mypassword"));

        assert!(sanitized_env.starts_with(SANITIZED_MARKER));
        assert!(sanitized_env.contains("STRIPE_SECRET_KEY=placeholder_managed_by_zerosecret"));
        assert!(sanitized_env.contains("OPENAI_API_KEY=placeholder_managed_by_zerosecret"));
        assert!(
            sanitized_env.contains("DATABASE_URL=postgres://myuser@127.0.0.1:54320/production")
        );
        assert!(sanitized_env.contains("PORT=8080"));
        assert_eq!(
            report.replaced,
            ["STRIPE_SECRET_KEY", "OPENAI_API_KEY", "DATABASE_URL"]
        );
        assert!(report.unbrokered.is_empty());
    }

    #[test]
    fn test_detects_all_protocols_and_ports_and_strips_quotes() {
        let report = scan(
            r#"
# Header comment
DATABASE_URL=postgres://pguser:pgpass@pg.example.com:5432/primary_db
SECONDARY_PG=postgresql://pguser:pgpass@pg2.example.com:5433/secondary_db
MYSQL_URL=mysql://myuser:mypass@mysql.example.com:3306/users_db
MONGO_URI=mongodb://mongouser:mongopass@mongo.example.com:27017/records_db?authSource=records
STRIPE_API_KEY="sk_test_stripesecret999"
OPENAI_KEY='sk-proj-opensecret888'
export GITHUB_TOKEN="ghp_githubsecret777" # inline comment
CACHE_HOST=redis.local:6379
"#,
        );
        let bindings = &report.bindings;
        let sanitized_env = &report.sanitized;

        assert_eq!(bindings.len(), 7);
        assert_eq!(bindings[0].resource, "postgres-db");
        assert_eq!(bindings[0].host, "pg.example.com");
        assert_eq!(bindings[0].protocol, "postgres");
        assert_eq!(bindings[0].listen_port, Some(54320));
        assert_eq!(bindings[0].upstream_port, Some(5432));

        assert_eq!(bindings[1].resource, "postgres-db-2");
        assert_eq!(bindings[1].host, "pg2.example.com");
        assert_eq!(bindings[1].listen_port, Some(54321));
        assert_eq!(bindings[1].upstream_port, Some(5433));

        assert_eq!(bindings[2].resource, "mysql-db");
        assert_eq!(bindings[2].protocol, "mysql");
        assert_eq!(bindings[2].listen_port, Some(54322));
        assert_eq!(bindings[2].upstream_port, Some(3306));
        assert_eq!(bindings[2].user, None);

        assert_eq!(bindings[3].resource, "mongo-db");
        assert_eq!(bindings[3].protocol, "mongo");
        assert_eq!(bindings[3].listen_port, Some(54323));
        assert_eq!(bindings[3].upstream_port, Some(27017));
        assert_eq!(bindings[3].user.as_deref(), Some("mongouser"));
        assert_eq!(bindings[3].auth_source.as_deref(), Some("records"));

        assert_eq!(bindings[4].resource, "stripe");
        assert_eq!(bindings[5].resource, "openai");
        assert_eq!(bindings[6].resource, "github");

        for secret in [
            "sk_test_stripesecret999",
            "sk-proj-opensecret888",
            "ghp_githubsecret777",
            "pgpass",
            "mypass",
            "mongopass",
        ] {
            assert!(!sanitized_env.contains(secret), "{secret} survived");
        }
        assert!(
            sanitized_env.contains("SECONDARY_PG=postgresql://pguser@127.0.0.1:54321/secondary_db")
        );
        assert!(sanitized_env.contains("MYSQL_URL=mysql://myuser@127.0.0.1:54322/users_db"));
        assert!(
            sanitized_env
                .contains("MONGO_URI=mongodb://127.0.0.1:54323/records_db?authSource=records")
        );
        assert!(sanitized_env.contains("export GITHUB_TOKEN=placeholder_managed_by_zerosecret"));
        assert!(sanitized_env.contains("CACHE_HOST=redis.local:6379"));
    }

    #[test]
    fn test_password_with_at_sign_never_reaches_the_policy() {
        let report = scan("DATABASE_URL=postgres://app:p@ss/w0rd@db.prod.example:5432/main\n");
        assert_eq!(report.bindings.len(), 1);
        assert_eq!(report.bindings[0].host, "db.prod.example");
        assert_eq!(report.bindings[0].upstream_port, Some(5432));
        let policy = serde_json::to_string(&report.bindings).unwrap();
        assert!(!policy.contains("ss/w0rd"));
        assert!(!report.sanitized.contains("ss/w0rd"));
        assert!(
            report
                .sanitized
                .contains("DATABASE_URL=postgres://app@127.0.0.1:54320/main\n")
        );
    }

    #[test]
    fn test_secret_query_parameters_are_dropped() {
        let report = scan(
            "DATABASE_URL=postgres://app@db.prod.example:5432/main?sslmode=require&password=hunter2&sslpassword=x2&application_name=web\n",
        );
        assert!(!report.sanitized.contains("hunter2"));
        assert!(!report.sanitized.contains("x2"));
        assert!(report.sanitized.contains(
            "DATABASE_URL=postgres://app@127.0.0.1:54320/main?sslmode=require&application_name=web\n"
        ));
    }

    #[test]
    fn test_loopback_url_without_password_is_left_alone() {
        let content =
            "DATABASE_URL=postgres://app@127.0.0.1:54320/main\nLOCAL=mysql://root@localhost/dev\n";
        let report = scan(content);
        assert!(report.bindings.is_empty());
        assert!(report.replaced.is_empty());
        assert_eq!(report.sanitized, content);
    }

    #[test]
    fn test_loopback_url_with_password_is_brokered() {
        let report = scan("DATABASE_URL=postgres://app:pw@localhost:5432/dev\n");
        assert_eq!(report.bindings.len(), 1);
        assert_eq!(report.bindings[0].host, "localhost");
        assert!(!report.sanitized.contains(":pw@"));
    }

    #[test]
    fn test_unbrokered_secrets_stay_and_are_reported() {
        let content = "JWT_SECRET=signing-value\n\
STRIPE_PUBLISHABLE_KEY=pk_live_abc\n\
NEXT_PUBLIC_MAP_KEY=public-map\n\
STRIPE_WEBHOOK_SECRET=whsec_abc\n\
AWS_SECRET_ACCESS_KEY=aws-secret\n\
REDIS_URL=redis://:redispass@cache.example:6379/0\n\
MONGO_URI=mongodb+srv://u:pw@cluster0.example.net/app\n\
PG_FARM=postgres://u:pw@h1:5432,h2:5432/app\n";
        let report = scan(content);
        assert!(report.bindings.is_empty());
        assert!(report.replaced.is_empty());
        assert_eq!(report.sanitized, content);
        let keys: Vec<&str> = report.unbrokered.iter().map(|u| u.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "JWT_SECRET",
                "STRIPE_WEBHOOK_SECRET",
                "AWS_SECRET_ACCESS_KEY",
                "REDIS_URL",
                "MONGO_URI",
                "PG_FARM"
            ]
        );
        for item in &report.unbrokered {
            for value in [
                "signing-value",
                "whsec_abc",
                "aws-secret",
                "redispass",
                "pw@",
            ] {
                assert!(!item.reason.contains(value));
            }
        }
    }

    #[test]
    fn test_malformed_lines_stop_the_scan_without_echoing_content() {
        let err = scan_and_sanitize("A=1\nnot a pair\n", 54320).unwrap_err();
        assert_eq!(err, "line 2: expected KEY=VALUE");
        let err = scan_and_sanitize("=value\n", 54320).unwrap_err();
        assert_eq!(err, "line 1: expected KEY=VALUE");
        let err = scan_and_sanitize("KEY=\"-----BEGIN KEY-----\nabc==\n-----END-----\"\n", 54320)
            .unwrap_err();
        assert!(err.starts_with("line 1: multi-line"), "{err}");
        assert!(!err.contains("BEGIN"));
    }

    #[test]
    fn test_listen_port_overflow_is_an_error() {
        let content = "A=postgres://u:p@h1:5432/a\nB=postgres://u:p@h2:5432/b\n";
        let report = scan_and_sanitize(content, 65534).unwrap();
        assert_eq!(report.bindings[1].listen_port, Some(65535));
        let err = scan_and_sanitize(
            "A=postgres://u:p@h1/a\nB=postgres://u:p@h2/b\nC=postgres://u:p@h3/c\n",
            65534,
        )
        .unwrap_err();
        assert!(err.contains("65535"), "{err}");
    }

    #[test]
    fn test_already_sanitized_detection() {
        assert!(already_sanitized(&format!("{SANITIZED_MARKER}\nA=1\n")));
        assert!(already_sanitized(
            "STRIPE_KEY=placeholder_managed_by_zerosecret\n"
        ));
        assert!(!already_sanitized("STRIPE_KEY=sk_live_x\n"));
    }

    #[test]
    fn test_backup_never_overwrites_an_existing_backup() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let first = create_backup(&env_path, "ORIGINAL=1\n", "20261023_000000").unwrap();
        let second = create_backup(&env_path, "SANITIZED=1\n", "20261023_000000").unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read_to_string(&first).unwrap(), "ORIGINAL=1\n");
        assert_eq!(fs::read_to_string(&second).unwrap(), "SANITIZED=1\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&first, &second] {
                let mode = fs::metadata(path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
        }
    }
}
