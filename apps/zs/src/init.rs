use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{ErrorKind, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use zeroize::Zeroizing;

pub const PLACEHOLDER: &str = "placeholder_managed_by_zerosecret";
const PLACEHOLDER_VALUES: &[&str] = &[PLACEHOLDER, "zs-brokered"];
const CREDENTIALS_DIR_NOT_PRIVATE: &str = "the credential directory is not private";
const HOST_SUFFIXES: &[&str] = &["_HOST", "_HOSTNAME"];
const PASSWORD_SUFFIXES: &[&str] = &["_PASSWORD", "_PASS", "_PASSWD", "_PWD"];
const DB_USER_SUFFIXES: &[&str] = &["_USER", "_USERNAME"];
const DIALECT_SUFFIXES: &[&str] = &["_DIALECT", "_DRIVER", "_CONNECTION", "_ENGINE", "_TYPE"];
const URL_SUFFIXES: &[&str] = &["_URL", "_BASE_URL", "_API_URL"];
const BASIC_PAIRS: &[(&str, &str)] = &[
    ("_CLIENT_ID", "_CLIENT_SECRET"),
    ("_USERNAME", "_PASSWORD"),
    ("_USER", "_PASSWORD"),
    ("_AUTH_USER", "_AUTH_PASSWORD"),
    ("_AUTH_USERNAME", "_AUTH_PASSWORD"),
    ("_ID", "_SECRET"),
];
const TOKEN_SUFFIXES: &[&str] = &[
    "_AUTH_TOKEN",
    "_ACCESS_TOKEN",
    "_API_KEY",
    "_TOKEN",
    "_KEY",
    "_SECRET",
    "_PASSWORD",
];
const HTTP_OPERATIONS: &[&str] = &["GET", "POST"];
const REDIS_REASON: &str = "zs does not broker Redis yet";
const ONE_PER_HOST_REASON: &str = "several credentials in this file target the same host; zs injects one credential per host, so none of them is brokered";
pub const SANITIZED_MARKER: &str =
    "# zs init: brokered secrets in this file were replaced; the original is at";
const BACKUP_PATH_PENDING: &str = "<backup path>";
const WITHHELD: &str = "<withheld>";
const BACKUP_DIR_NOT_PRIVATE: &str = "the .env backup directory is not private";
const NO_HOME: &str = "cannot find the home directory for the .env backup";

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<String>,
}

fn default_protocol() -> String {
    "https".into()
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "scheme", rename_all = "kebab-case")]
pub enum ScannedAuth {
    Bearer,
    Basic,
    ApiKeyHeader { header: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unbrokered {
    pub key: String,
    pub reason: Cow<'static, str>,
}

pub struct ScannedCredential {
    pub resource: String,
    value: Zeroizing<String>,
}

impl ScannedCredential {
    fn new(resource: &str, value: &str) -> Self {
        Self {
            resource: resource.to_string(),
            value: Zeroizing::new(value.to_string()),
        }
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Default)]
pub struct ScanReport {
    pub bindings: Vec<ScannedBinding>,
    pub credentials: Vec<ScannedCredential>,
    pub sanitized: String,
    pub masked: String,
    pub replaced: Vec<String>,
    pub unbrokered: Vec<Unbrokered>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOverride {
    Bearer,
    Header(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanOverrides {
    pub db: Vec<(String, String)>,
    pub auth: Vec<(String, AuthOverride)>,
}

pub fn parse_db_override(raw: &str) -> Result<(String, String), String> {
    let (prefix, protocol) = raw
        .split_once('=')
        .ok_or("--db needs PREFIX=mysql, postgres or mongo")?;
    let protocol = protocol.to_ascii_lowercase();
    if prefix.is_empty() || !["mysql", "postgres", "mongo"].contains(&protocol.as_str()) {
        return Err("--db needs PREFIX=mysql, postgres or mongo".into());
    }
    Ok((prefix.to_ascii_uppercase(), protocol))
}

pub fn parse_auth_override(raw: &str) -> Result<(String, AuthOverride), String> {
    const USAGE: &str = "--auth needs KEY=bearer or KEY=header:<Name>";
    let (key, scheme) = raw.split_once('=').ok_or(USAGE)?;
    let auth = match scheme.split_once(':') {
        None if scheme.eq_ignore_ascii_case("bearer") => AuthOverride::Bearer,
        Some((kind, header))
            if kind.eq_ignore_ascii_case("header")
                && !header.is_empty()
                && header
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-') =>
        {
            AuthOverride::Header(header.to_string())
        }
        _ => return Err(USAGE.into()),
    };
    if key.is_empty() {
        return Err(USAGE.into());
    }
    Ok((key.to_string(), auth))
}

pub struct InitOptions {
    pub dry_run: bool,
    pub force: bool,
    pub from_env: Option<PathBuf>,
    pub control: Option<String>,
    pub listen_port_start: u16,
    pub overrides: ScanOverrides,
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            force: false,
            from_env: None,
            control: None,
            listen_port_start: 54320,
            overrides: ScanOverrides::default(),
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
    password: &'a str,
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
        password,
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
    content.contains(PLACEHOLDER)
        || content
            .lines()
            .any(|l| l.trim().starts_with(SANITIZED_MARKER))
}

fn classify(
    name: &str,
    value: &str,
    report: &mut ScanReport,
    next_port: &mut Option<u16>,
) -> Result<Option<String>, String> {
    if value.starts_with("mongodb+srv://") {
        report.skip(
            name,
            "mongodb+srv needs a DNS SRV lookup that the mongo broker does not do; use a mongodb:// URL",
        );
        return Ok(None);
    }
    if let Some((scheme, rest)) = DB_SCHEMES
        .iter()
        .find_map(|s| value.strip_prefix(s.prefix).map(|rest| (s, rest)))
    {
        let Some(url) = parse_db_url(rest) else {
            report.skip(
                name,
                "database URL with several hosts or an unreadable host or port",
            );
            return Ok(None);
        };
        if url.is_loopback() && !url.has_password {
            return Ok(None);
        }
        let port = take_port(next_port)?;
        let is_mongo = scheme.protocol == "mongo";
        let resource = unique_resource(&report.bindings, scheme.resource);
        if url.has_password && !is_placeholder(url.password) {
            report
                .credentials
                .push(ScannedCredential::new(&resource, url.password));
        }
        report.bindings.push(ScannedBinding {
            resource,
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
            operations: Vec::new(),
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
    let names_a_secret = ["PASSWORD", "PASSWD", "SECRET", "PRIVATE"]
        .iter()
        .any(|w| upper.contains(w));
    if (PUBLIC_KEY_WORDS.iter().any(|w| upper.contains(w)) && !names_a_secret)
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
                operations: Vec::new(),
            });
            if !is_placeholder(value) {
                report
                    .credentials
                    .push(ScannedCredential::new(service.resource, value));
            }
        }
        return Ok(Some(PLACEHOLDER.into()));
    }
    if url_has_password(value) {
        report.skip(
            name,
            "URL with an embedded password for a protocol zs init does not broker",
        );
    } else if SECRET_KEY_WORDS.iter().any(|w| upper.contains(w)) || upper.ends_with("_KEY") {
        report.skip(
            name,
            "zs init cannot broker this value; move it out of the file by hand, or pass --auth KEY=bearer or KEY=header:<Name> when a matching _URL key names its host",
        );
    }
    Ok(None)
}

impl ScanReport {
    fn skip(&mut self, key: &str, reason: impl Into<Cow<'static, str>>) {
        self.unbrokered.push(Unbrokered {
            key: key.to_string(),
            reason: reason.into(),
        });
    }

    fn host_taken(&self, host: &str) -> bool {
        self.bindings
            .iter()
            .any(|b| b.listen_port.is_none() && b.host.eq_ignore_ascii_case(host))
    }

    fn port_taken(&self, port: u16) -> bool {
        self.bindings.iter().any(|b| b.listen_port == Some(port))
    }
}

fn is_placeholder(value: &str) -> bool {
    PLACEHOLDER_VALUES.contains(&value)
}

struct Entry {
    name: String,
    value: String,
}

fn entries(content: &str) -> Vec<Entry> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let (raw_key, raw_value) = line.split_once('=')?;
            let key = raw_key.trim();
            let name = key.strip_prefix("export ").unwrap_or(key).trim();
            let value = env_value(raw_value)?;
            (!name.is_empty()).then(|| Entry {
                name: name.to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

#[derive(Default)]
struct Plan {
    rewrites: HashMap<String, String>,
    claimed: HashSet<String>,
}

impl Plan {
    fn handled(&self, name: &str) -> bool {
        self.rewrites.contains_key(name) || self.claimed.contains(name)
    }
}

fn lookup<'a>(entries: &'a [Entry], name: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|e| e.name == name)
        .map(|e| e.value.as_str())
        .filter(|v| !v.is_empty())
}

fn first_key(entries: &[Entry], prefix: &str, suffixes: &[&str]) -> Option<(String, String)> {
    suffixes.iter().find_map(|suffix| {
        let name = format!("{prefix}{suffix}");
        lookup(entries, &name).map(|value| (name, value.to_string()))
    })
}

fn resource_name(bindings: &[ScannedBinding], prefix: &str, protocol: &str) -> String {
    let base = prefix.to_ascii_lowercase().replace('_', "-");
    let base = if ["db", "database", "data"].contains(&base.as_str()) || base.is_empty() {
        format!("{protocol}-db")
    } else {
        base
    };
    unique_resource(bindings, &base)
}

fn default_port(protocol: &str) -> u16 {
    match protocol {
        "mysql" => 3306,
        "postgres" => 5432,
        _ => 27017,
    }
}

fn protocol_named_in(text: &str) -> Option<&'static str> {
    let upper = text.to_ascii_uppercase();
    if upper.contains("MYSQL") || upper.contains("MARIADB") {
        Some("mysql")
    } else if upper.contains("POSTGRE")
        || upper.contains("PSQL")
        || upper.split(['_', '-']).any(|segment| segment == "PG")
    {
        Some("postgres")
    } else if upper.contains("MONGO") {
        Some("mongo")
    } else {
        None
    }
}

fn db_protocol(
    entries: &[Entry],
    prefix: &str,
    overrides: &ScanOverrides,
) -> Result<&'static str, Cow<'static, str>> {
    if let Some((_, protocol)) = overrides
        .db
        .iter()
        .find(|(p, _)| p.eq_ignore_ascii_case(prefix))
    {
        return Ok(match protocol.as_str() {
            "mysql" => "mysql",
            "postgres" => "postgres",
            _ => "mongo",
        });
    }
    if prefix.to_ascii_uppercase().contains("REDIS") {
        return Err(REDIS_REASON.into());
    }
    if let Some(protocol) = protocol_named_in(prefix) {
        return Ok(protocol);
    }
    match lookup(entries, &format!("{prefix}_PORT")) {
        Some("3306") => return Ok("mysql"),
        Some("5432") => return Ok("postgres"),
        Some("27017") => return Ok("mongo"),
        _ => {}
    }
    if let Some(protocol) =
        first_key(entries, prefix, DIALECT_SUFFIXES).and_then(|(_, v)| protocol_named_in(&v))
    {
        return Ok(protocol);
    }
    Err(format!(
        "cannot tell the protocol of {prefix}_HOST; if it is a database, rerun with --db {prefix}=mysql, postgres or mongo"
    )
    .into())
}

fn plan_databases(
    entries: &[Entry],
    overrides: &ScanOverrides,
    report: &mut ScanReport,
    plan: &mut Plan,
    next_port: &mut Option<u16>,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for entry in entries {
        let Some(prefix) = HOST_SUFFIXES
            .iter()
            .find_map(|suffix| entry.name.strip_suffix(suffix))
        else {
            continue;
        };
        if prefix.is_empty() || !seen.insert(prefix.to_string()) {
            continue;
        }
        let Some((password_key, password)) = first_key(entries, prefix, PASSWORD_SUFFIXES) else {
            continue;
        };
        if plan.handled(&password_key) {
            continue;
        }
        plan.claimed.insert(password_key.clone());
        if is_placeholder(&password) {
            continue;
        }
        let protocol = match db_protocol(entries, prefix, overrides) {
            Ok(protocol) => protocol,
            Err(reason) => {
                report.skip(&password_key, reason);
                continue;
            }
        };
        let Some((host, host_port)) = split_host_port(&entry.value) else {
            report.skip(&password_key, format!("{} is not a host name", entry.name));
            continue;
        };
        let port_key = format!("{prefix}_PORT");
        let upstream_port = match (lookup(entries, &port_key), host_port) {
            (Some(raw), _) => match raw.parse::<u16>().ok().filter(|p| *p != 0) {
                Some(port) => port,
                None => {
                    report.skip(&password_key, format!("{port_key} is not a port"));
                    continue;
                }
            },
            (None, Some(port)) => port,
            (None, None) => default_port(protocol),
        };
        let user = first_key(entries, prefix, DB_USER_SUFFIXES).map(|(_, v)| v);
        if protocol == "mongo" && user.is_none() {
            report.skip(
                &password_key,
                format!("a MongoDB binding needs {prefix}_USER or {prefix}_USERNAME"),
            );
            continue;
        }
        let mut listen_port = upstream_port;
        if report.port_taken(listen_port) {
            if lookup(entries, &port_key).is_none() {
                report.skip(
                    &password_key,
                    format!("port {listen_port} is taken by another binding; set {port_key}"),
                );
                continue;
            }
            listen_port = take_port(next_port)?;
            plan.rewrites.insert(port_key, listen_port.to_string());
        }
        let resource = resource_name(&report.bindings, prefix, protocol);
        let host_prefix = format!("{prefix}_");
        for other in entries {
            let same_group = other.name == entry.name
                || (other.name.starts_with(&host_prefix)
                    && HOST_SUFFIXES.iter().any(|s| other.name.ends_with(s))
                    && other.value == entry.value);
            if same_group {
                plan.rewrites
                    .insert(other.name.clone(), "127.0.0.1".to_string());
            }
        }
        plan.rewrites.insert(password_key, PLACEHOLDER.to_string());
        report
            .credentials
            .push(ScannedCredential::new(&resource, &password));
        report.bindings.push(ScannedBinding {
            resource,
            host: host.to_string(),
            protocol: protocol.into(),
            listen_port: Some(listen_port),
            upstream_port: Some(upstream_port),
            user: (protocol == "mongo").then(|| user.unwrap_or_default()),
            auth_source: (protocol == "mongo")
                .then(|| lookup(entries, &format!("{prefix}_AUTH_SOURCE")).map(str::to_string))
                .flatten(),
            auth: None,
            operations: Vec::new(),
        });
    }
    Ok(())
}

fn http_host(value: &str) -> Option<(&'static str, String)> {
    let lower = value.to_ascii_lowercase();
    let (protocol, rest) = if lower.starts_with("https://") {
        ("https", &value[8..])
    } else if lower.starts_with("http://") {
        ("http", &value[7..])
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, _) = split_host_port(host_port)?;
    Some((protocol, host.to_ascii_lowercase()))
}

fn url_prefixes(name: &str) -> Vec<String> {
    let Some(base) = URL_SUFFIXES
        .iter()
        .rev()
        .find_map(|suffix| name.strip_suffix(suffix))
    else {
        return Vec::new();
    };
    let mut prefixes = vec![base.to_string()];
    if let Some(full) = name.strip_suffix("_URL")
        && full != base
    {
        prefixes.push(full.to_string());
    }
    prefixes.retain(|p| !p.is_empty());
    prefixes
}

fn http_binding(
    report: &mut ScanReport,
    resource_prefix: &str,
    protocol: &str,
    host: String,
    auth: ScannedAuth,
    credential: &str,
) {
    let resource = resource_name(&report.bindings, resource_prefix, protocol);
    report
        .credentials
        .push(ScannedCredential::new(&resource, credential));
    report.bindings.push(ScannedBinding {
        resource,
        host,
        protocol: protocol.into(),
        listen_port: None,
        upstream_port: None,
        user: None,
        auth_source: None,
        auth: Some(auth),
        operations: HTTP_OPERATIONS.iter().map(|op| op.to_string()).collect(),
    });
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

struct HttpCandidate {
    prefix: String,
    protocol: &'static str,
    host: String,
    key: String,
    auth: ScannedAuth,
    credential: Zeroizing<String>,
}

fn plan_http(candidates: Vec<HttpCandidate>, report: &mut ScanReport, plan: &mut Plan) {
    let shared: HashSet<String> = candidates
        .iter()
        .filter(|c| {
            report.host_taken(&c.host)
                || candidates
                    .iter()
                    .filter(|o| o.host.eq_ignore_ascii_case(&c.host))
                    .count()
                    > 1
        })
        .map(|c| c.host.to_ascii_lowercase())
        .collect();
    for candidate in candidates {
        if shared.contains(&candidate.host.to_ascii_lowercase()) {
            report.skip(&candidate.key, ONE_PER_HOST_REASON);
            continue;
        }
        http_binding(
            report,
            &candidate.prefix,
            candidate.protocol,
            candidate.host,
            candidate.auth,
            &candidate.credential,
        );
        plan.rewrites.insert(candidate.key, PLACEHOLDER.to_string());
    }
}

fn basic_candidates(entries: &[Entry], plan: &mut Plan) -> Vec<HttpCandidate> {
    let mut candidates = Vec::new();
    for entry in entries {
        let Some((protocol, host)) = http_host(&entry.value) else {
            continue;
        };
        if is_loopback_host(&host) {
            continue;
        }
        let pair = url_prefixes(&entry.name).into_iter().find_map(|prefix| {
            BASIC_PAIRS.iter().find_map(|(user_suffix, secret_suffix)| {
                let user = lookup(entries, &format!("{prefix}{user_suffix}"))?;
                let secret_key = format!("{prefix}{secret_suffix}");
                let secret = lookup(entries, &secret_key)?;
                Some((
                    prefix.clone(),
                    user.to_string(),
                    secret_key,
                    secret.to_string(),
                ))
            })
        });
        let Some((prefix, user, secret_key, secret)) = pair else {
            continue;
        };
        if plan.handled(&secret_key) {
            continue;
        }
        plan.claimed.insert(secret_key.clone());
        if is_placeholder(&secret) {
            continue;
        }
        candidates.push(HttpCandidate {
            prefix,
            protocol,
            host,
            key: secret_key,
            auth: ScannedAuth::Basic,
            credential: Zeroizing::new(
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}")),
            ),
        });
    }
    candidates
}

fn override_candidates(
    entries: &[Entry],
    overrides: &ScanOverrides,
    plan: &mut Plan,
) -> Result<Vec<HttpCandidate>, String> {
    let mut candidates = Vec::new();
    for (key, auth) in &overrides.auth {
        let Some(value) = lookup(entries, key) else {
            return Err(format!("--auth {key}: the file has no value for {key}"));
        };
        if plan.handled(key) {
            continue;
        }
        plan.claimed.insert(key.clone());
        if is_placeholder(value) {
            continue;
        }
        let prefix = TOKEN_SUFFIXES
            .iter()
            .find_map(|suffix| key.strip_suffix(suffix))
            .unwrap_or(key);
        let Some((protocol, host)) = URL_SUFFIXES
            .iter()
            .find_map(|suffix| lookup(entries, &format!("{prefix}{suffix}")))
            .and_then(http_host)
        else {
            return Err(format!(
                "--auth {key}: no {prefix}_URL, {prefix}_BASE_URL or {prefix}_API_URL names its host"
            ));
        };
        if is_loopback_host(&host) {
            return Err(format!(
                "--auth {key}: its URL is a loopback address, which zs does not broker"
            ));
        }
        candidates.push(HttpCandidate {
            prefix: prefix.to_string(),
            protocol,
            host,
            key: key.clone(),
            auth: match auth {
                AuthOverride::Bearer => ScannedAuth::Bearer,
                AuthOverride::Header(header) => ScannedAuth::ApiKeyHeader {
                    header: header.clone(),
                },
            },
            credential: Zeroizing::new(value.to_string()),
        });
    }
    Ok(candidates)
}

#[cfg(test)]
fn scan_and_sanitize(content: &str, listen_port_start: u16) -> Result<ScanReport, String> {
    scan_with(content, listen_port_start, &ScanOverrides::default())
}

pub fn scan_with(
    content: &str,
    listen_port_start: u16,
    overrides: &ScanOverrides,
) -> Result<ScanReport, String> {
    let mut report = ScanReport::default();
    let mut next_port = Some(listen_port_start);
    let parsed = entries(content);
    let mut plan = Plan::default();
    plan_databases(&parsed, overrides, &mut report, &mut plan, &mut next_port)?;
    let mut candidates = basic_candidates(&parsed, &mut plan);
    candidates.extend(override_candidates(&parsed, overrides, &mut plan)?);
    plan_http(candidates, &mut report, &mut plan);
    let mut lines = Vec::new();
    let mut masked = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            lines.push(line.to_string());
            masked.push(if trimmed.is_empty() {
                line.to_string()
            } else {
                format!("# {WITHHELD}")
            });
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
        let outcome = if let Some(new_value) = plan.rewrites.get(name) {
            Some(new_value.clone())
        } else if plan.claimed.contains(name) {
            None
        } else {
            classify(name, value, &mut report, &mut next_port)?
        };
        match outcome {
            Some(new_value) => {
                let rewritten = format!("{key}={new_value}");
                masked.push(rewritten.clone());
                lines.push(rewritten);
                report.replaced.push(name.to_string());
            }
            None => {
                lines.push(line.to_string());
                masked.push(format!("{key}={WITHHELD}"));
            }
        }
    }
    if !report.replaced.is_empty() {
        let marker = format!("{SANITIZED_MARKER} {BACKUP_PATH_PENDING}");
        lines.insert(0, marker.clone());
        masked.insert(0, marker);
    }
    report.sanitized = lines.join("\n");
    report.masked = masked.join("\n");
    if content.ends_with('\n') {
        report.sanitized.push('\n');
        report.masked.push('\n');
    }
    Ok(report)
}

fn with_backup_path(sanitized: &str, backup: &Path) -> String {
    match sanitized.split_once('\n') {
        Some((first, rest)) if first.ends_with(BACKUP_PATH_PENDING) => {
            format!("{SANITIZED_MARKER} {}\n{rest}", backup.display())
        }
        _ => sanitized.to_string(),
    }
}

fn backup_dir(home: &Path, workspace: &Path) -> PathBuf {
    let project = workspace
        .file_name()
        .map_or_else(|| "workspace".into(), |name| name.to_os_string());
    home.join(".zs-backups").join(project)
}

fn home_dir() -> Option<PathBuf> {
    let name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
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

fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    ensure_private(dir, "backup directory", BACKUP_DIR_NOT_PRIVATE)
}

fn ensure_private(dir: &Path, label: &str, not_private: &str) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| format!("cannot create {label} {}: {e}", dir.display()))?;
    let meta = fs::symlink_metadata(dir)
        .map_err(|e| format!("cannot inspect {label} {}: {e}", dir.display()))?;
    let private = meta.is_dir() && !meta.file_type().is_symlink();
    #[cfg(unix)]
    let private = {
        use std::os::unix::fs::PermissionsExt;
        private && meta.permissions().mode() & 0o077 == 0
    };
    if private {
        Ok(())
    } else {
        Err(not_private.to_string())
    }
}

fn credentials_dir(home: &Path, workspace: &Path) -> PathBuf {
    let project = workspace
        .file_name()
        .map_or_else(|| "workspace".into(), |name| name.to_os_string());
    home.join(".zs-credentials").join(project)
}

fn write_credentials(dir: &Path, credentials: &[ScannedCredential]) -> Result<(), String> {
    ensure_private(dir, "credential directory", CREDENTIALS_DIR_NOT_PRIVATE)?;
    let mut pending = Vec::new();
    for credential in credentials {
        let path = dir.join(&credential.resource);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                return Err(format!(
                    "credential path {} is not a regular file",
                    path.display()
                ));
            }
            Ok(_) => {
                let existing = Zeroizing::new(
                    fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?,
                );
                if existing.as_slice() != credential.value().as_bytes() {
                    return Err(format!(
                        "credential file {} already holds another value; move it away first",
                        path.display()
                    ));
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => pending.push((path, credential)),
            Err(e) => return Err(format!("cannot inspect {}: {e}", path.display())),
        }
    }
    for (path, credential) in pending {
        let mut file = open_new_private(&path)
            .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        file.write_all(credential.value().as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(())
}

fn tilde_path(home: &Path, path: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) => {
            let parts: Vec<String> = rest
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            format!("~/{}", parts.join("/"))
        }
        Err(_) => path.display().to_string(),
    }
}

fn create_backup(
    env_path: &Path,
    content: &str,
    timestamp: &str,
    dir: &Path,
) -> Result<PathBuf, String> {
    ensure_private_dir(dir)?;
    let file_name = env_path.file_name().ok_or("cannot name the backup file")?;
    let mut base = file_name.to_owned();
    base.push(format!(".{timestamp}"));
    for attempt in 0..100u32 {
        let mut name = base.clone();
        if attempt > 0 {
            name.push(format!("_{attempt}"));
        }
        let path = dir.join(name);
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
        dir.join(base).display()
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

fn binding_operations(binding: &ScannedBinding) -> String {
    if binding.listen_port.is_some() {
        "connect".into()
    } else if binding.operations.is_empty() {
        "GET".into()
    } else {
        binding.operations.join(",")
    }
}

fn print_report(report: &ScanReport, env_path: &Path) {
    for binding in &report.bindings {
        match binding.listen_port {
            Some(port) => stdout_line!(
                "zs: binding {} -> {} (listener 127.0.0.1:{port})",
                binding.resource,
                binding.host
            ),
            None => stdout_line!("zs: binding {} -> {}", binding.resource, binding.host),
        }
    }
    for binding in &report.bindings {
        stdout_line!(
            "zs: control plane resource: name={} host={} protocol={} operations={} credential_ref={}",
            binding.resource,
            binding.host,
            binding.protocol,
            binding_operations(binding),
            binding.resource
        );
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
            "zs: {} was already sanitized by zs init; restore it from its backup under ~/.zs-backups/ before running zs init again",
            env_path.display()
        );
        return 1;
    }

    let report = match scan_with(&env_content, opts.listen_port_start, &opts.overrides) {
        Ok(report) => report,
        Err(e) => {
            stderr_line!("zs: {}: {e}", env_path.display());
            return 2;
        }
    };

    let needs_home = !report.replaced.is_empty() || !report.credentials.is_empty();
    let (home, workspace) = if needs_home {
        let Some(home) = home_dir() else {
            stderr_line!("zs: {NO_HOME}");
            return 2;
        };
        match std::env::current_dir() {
            Ok(dir) => (home, dir),
            Err(e) => {
                stderr_line!("zs: cannot read the working directory: {e}");
                return 2;
            }
        }
    } else {
        (PathBuf::new(), PathBuf::new())
    };
    let creds_dir = credentials_dir(&home, &workspace);

    let mut run = serde_json::json!({
        "control": opts.control.as_deref().unwrap_or("http://127.0.0.1:8443"),
        "control_ca": "zerosecret/control-ca.crt"
    });
    if !report.credentials.is_empty() {
        run["credentials_dir"] = serde_json::Value::String(tilde_path(&home, &creds_dir));
    }
    let policy_val = serde_json::json!({
        "run": run,
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
        stdout_line!("{}", report.masked);
        print_report(&report, &env_path);
        for credential in &report.credentials {
            stdout_line!(
                "zs: would write credential {} (0600)",
                tilde_path(&home, &creds_dir.join(&credential.resource))
            );
        }
        return 0;
    }

    let backup_path = if report.replaced.is_empty() {
        None
    } else {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = match create_backup(
            &env_path,
            &env_content,
            &format_backup_timestamp(secs),
            &backup_dir(&home, &workspace),
        ) {
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

    if !report.credentials.is_empty() {
        if let Err(e) = write_credentials(&creds_dir, &report.credentials) {
            stderr_line!("zs: {e}");
            return 2;
        }
        for credential in &report.credentials {
            stdout_line!(
                "zs: credential {} written (0600)",
                tilde_path(&home, &creds_dir.join(&credential.resource))
            );
        }
    }

    if let Err(e) = fs::write(policy_path, format!("{policy_str}\n")) {
        stderr_line!("zs: cannot write zs-policy.json: {e}");
        return 2;
    }

    if let Some(backup) = &backup_path
        && let Err(e) = fs::write(&env_path, with_backup_path(&report.sanitized, backup))
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

    fn scan_err(content: &str, port: u16) -> String {
        scan_and_sanitize(content, port)
            .err()
            .expect("the scan must fail")
    }

    fn scan_overridden(content: &str, overrides: &ScanOverrides) -> ScanReport {
        scan_with(content, 54320, overrides).unwrap()
    }

    fn credential<'a>(report: &'a ScanReport, resource: &str) -> &'a str {
        report
            .credentials
            .iter()
            .find(|c| c.resource == resource)
            .expect("credential")
            .value()
    }

    fn reason<'a>(report: &'a ScanReport, key: &str) -> &'a str {
        &report
            .unbrokered
            .iter()
            .find(|u| u.key == key)
            .expect("unbrokered key")
            .reason
    }

    #[test]
    fn split_postgres_keys_become_one_binding_on_the_app_port() {
        let report = scan(
            "STORAGE_POSTGRE_HOST=db.example.internal\nSTORAGE_POSTGRE_PORT=5432\nSTORAGE_POSTGRE_USER=svc\nSTORAGE_POSTGRE_PASSWORD=pg-secret-1\nSTORAGE_POSTGRE_DATABASE=app\n",
        );
        assert_eq!(report.bindings.len(), 1);
        let b = &report.bindings[0];
        assert_eq!(b.resource, "storage-postgre");
        assert_eq!(b.protocol, "postgres");
        assert_eq!(b.host, "db.example.internal");
        assert_eq!(b.listen_port, Some(5432));
        assert_eq!(b.upstream_port, Some(5432));
        assert_eq!(credential(&report, "storage-postgre"), "pg-secret-1");
        assert!(
            report
                .sanitized
                .contains("STORAGE_POSTGRE_HOST=127.0.0.1\n")
        );
        assert!(report.sanitized.contains("STORAGE_POSTGRE_PORT=5432\n"));
        assert!(
            report
                .sanitized
                .contains("STORAGE_POSTGRE_PASSWORD=placeholder_managed_by_zerosecret\n")
        );
        assert!(!report.sanitized.contains("pg-secret-1"));
        assert!(!report.masked.contains("pg-secret-1"));
        assert!(report.unbrokered.is_empty());
    }

    #[test]
    fn unnamed_db_keys_need_db_and_then_share_one_listener_with_the_replica() {
        let content = "DB_DATABASE=app\nDB_USER=svc\nDB_PASSWORD=my-secret-1\nDB_HOST=cluster.example.internal\nDB_REPLICA_HOST=cluster.example.internal\n";
        let report = scan(content);
        assert!(report.bindings.is_empty());
        assert_eq!(report.sanitized, content);
        assert!(reason(&report, "DB_PASSWORD").contains("--db DB=mysql"));

        let overrides = ScanOverrides {
            db: vec![("DB".into(), "mysql".into())],
            ..ScanOverrides::default()
        };
        let report = scan_overridden(content, &overrides);
        assert_eq!(report.bindings.len(), 1);
        let b = &report.bindings[0];
        assert_eq!(
            (b.resource.as_str(), b.protocol.as_str()),
            ("mysql-db", "mysql")
        );
        assert_eq!(b.listen_port, Some(3306));
        assert_eq!(b.upstream_port, Some(3306));
        assert!(report.sanitized.contains("DB_HOST=127.0.0.1\n"));
        assert!(report.sanitized.contains("DB_REPLICA_HOST=127.0.0.1\n"));
        assert_eq!(credential(&report, "mysql-db"), "my-secret-1");
        assert!(report.unbrokered.is_empty());
    }

    #[test]
    fn a_db_port_names_the_protocol_and_a_taken_port_moves() {
        let report = scan(
            "A_HOST=a.example\nA_PORT=5432\nA_PASSWORD=pa\nB_HOST=b.example\nB_PORT=5432\nB_PASSWORD=pb\n",
        );
        assert_eq!(report.bindings.len(), 2);
        assert_eq!(report.bindings[0].listen_port, Some(5432));
        assert_eq!(report.bindings[1].listen_port, Some(54320));
        assert_eq!(report.bindings[1].upstream_port, Some(5432));
        assert!(report.sanitized.contains("B_PORT=54320\n"));
    }

    #[test]
    fn redis_and_userless_mongo_groups_are_reported() {
        let report = scan(
            "STORAGE_REDIS_HOST=cache.example\nSTORAGE_REDIS_PASSWORD=rs\nMONGO_HOST=m.example\nMONGO_PASSWORD=ms\n",
        );
        assert!(report.bindings.is_empty());
        assert_eq!(reason(&report, "STORAGE_REDIS_PASSWORD"), REDIS_REASON);
        assert!(reason(&report, "MONGO_PASSWORD").contains("MONGO_USER"));
        assert_eq!(report.unbrokered.len(), 2);
    }

    #[test]
    fn basic_pairs_become_basic_bindings_and_keep_the_user() {
        let report = scan(
            "TOOL_OAUTH_URL=https://auth.example/oauth\nTOOL_OAUTH_CLIENT_ID=tool\nTOOL_OAUTH_CLIENT_SECRET=s1\nPARTNER_API_URL=https://partner.example\nPARTNER_API_USERNAME=client\nPARTNER_API_PASSWORD=s2\nPIGEON_BASE_URL=https://pigeon.example/\nPIGEON_AUTH_USER=pu\nPIGEON_AUTH_PASSWORD=s3\n",
        );
        let names: Vec<&str> = report
            .bindings
            .iter()
            .map(|b| b.resource.as_str())
            .collect();
        assert_eq!(names, ["tool-oauth", "partner-api", "pigeon"]);
        for b in &report.bindings {
            assert_eq!(b.auth, Some(ScannedAuth::Basic));
            assert_eq!(b.operations, ["GET", "POST"]);
        }
        assert_eq!(report.bindings[0].host, "auth.example");
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        assert_eq!(credential(&report, "tool-oauth"), b64("tool:s1"));
        assert_eq!(credential(&report, "partner-api"), b64("client:s2"));
        assert_eq!(credential(&report, "pigeon"), b64("pu:s3"));
        assert!(report.sanitized.contains("TOOL_OAUTH_CLIENT_ID=tool\n"));
        assert!(
            report
                .sanitized
                .contains("TOOL_OAUTH_CLIENT_SECRET=placeholder_managed_by_zerosecret\n")
        );
        let policy = serde_json::to_string(&report.bindings).unwrap();
        assert!(policy.contains(r#""auth":{"scheme":"basic"}"#), "{policy}");
        for secret in ["s1", "s2", "s3"] {
            assert!(!report.sanitized.contains(&format!("={secret}\n")));
        }
    }

    #[test]
    fn a_loopback_url_is_the_app_itself_and_is_never_brokered() {
        let report = scan(
            "PUBLIC_URL=http://localhost:8000\nPUBLIC_USERNAME=u\nPUBLIC_PASSWORD=inbound-check\nIP_URL=http://127.0.0.1:9/x\nIP_ID=a\nIP_SECRET=s\n",
        );
        assert!(report.bindings.is_empty());
        assert!(report.sanitized.contains("PUBLIC_PASSWORD=inbound-check\n"));
        assert!(reason(&report, "PUBLIC_PASSWORD").contains("cannot broker"));
        let overrides = ScanOverrides {
            auth: vec![("PUBLIC_PASSWORD".into(), AuthOverride::Bearer)],
            ..ScanOverrides::default()
        };
        let err = scan_with(
            "PUBLIC_URL=http://localhost:8000\nPUBLIC_PASSWORD=inbound-check\n",
            54320,
            &overrides,
        )
        .err()
        .unwrap();
        assert!(
            err.contains("loopback") && !err.contains("inbound-check"),
            "{err}"
        );
    }

    #[test]
    fn a_second_credential_for_one_host_is_reported() {
        let report = scan(
            "OAUTH_URL=https://auth.example\nOAUTH_CLIENT_ID=a\nOAUTH_CLIENT_SECRET=s1\nOTHER_OAUTH_URL=https://auth.example/x\nOTHER_OAUTH_CLIENT_ID=b\nOTHER_OAUTH_CLIENT_SECRET=s2\n",
        );
        assert!(report.bindings.is_empty());
        assert!(report.credentials.is_empty());
        for key in ["OAUTH_CLIENT_SECRET", "OTHER_OAUTH_CLIENT_SECRET"] {
            assert_eq!(reason(&report, key), ONE_PER_HOST_REASON);
        }
        assert!(report.sanitized.contains("OAUTH_CLIENT_SECRET=s1\n"));
        assert!(report.sanitized.contains("OTHER_OAUTH_CLIENT_SECRET=s2\n"));
    }

    #[test]
    fn auth_overrides_broker_a_named_header_or_a_bearer() {
        let content = "SQUID_URL=https://squid.example\nSQUID_KEY=k1\nB2B_NOTIF_BASE_URL=https://notif.example\nB2B_NOTIF_AUTH_TOKEN=t1\n";
        let report = scan(content);
        assert!(report.bindings.is_empty());
        assert!(reason(&report, "SQUID_KEY").contains("--auth"));

        let overrides = ScanOverrides {
            auth: vec![
                ("SQUID_KEY".into(), AuthOverride::Header("app-key".into())),
                ("B2B_NOTIF_AUTH_TOKEN".into(), AuthOverride::Bearer),
            ],
            ..ScanOverrides::default()
        };
        let report = scan_overridden(content, &overrides);
        assert_eq!(report.bindings.len(), 2);
        assert_eq!(
            report.bindings[0].auth,
            Some(ScannedAuth::ApiKeyHeader {
                header: "app-key".into()
            })
        );
        assert_eq!(report.bindings[0].host, "squid.example");
        assert_eq!(report.bindings[1].resource, "b2b-notif");
        assert_eq!(report.bindings[1].auth, Some(ScannedAuth::Bearer));
        assert_eq!(credential(&report, "squid"), "k1");
        assert!(report.unbrokered.is_empty());
        assert!(!report.sanitized.contains("=k1\n") && !report.sanitized.contains("=t1\n"));
    }

    #[test]
    fn a_bad_auth_override_stops_without_naming_a_value() {
        let missing = ScanOverrides {
            auth: vec![("NOPE_KEY".into(), AuthOverride::Bearer)],
            ..ScanOverrides::default()
        };
        let err = scan_with("A=secret-a\n", 54320, &missing).err().unwrap();
        assert!(
            err.contains("NOPE_KEY") && !err.contains("secret-a"),
            "{err}"
        );
        let no_url = ScanOverrides {
            auth: vec![("LONE_TOKEN".into(), AuthOverride::Bearer)],
            ..ScanOverrides::default()
        };
        let err = scan_with("LONE_TOKEN=secret-b\n", 54320, &no_url)
            .err()
            .unwrap();
        assert!(
            err.contains("LONE_URL") && !err.contains("secret-b"),
            "{err}"
        );
    }

    #[test]
    fn placeholder_values_are_skipped_silently() {
        let report = scan(
            "DB_HOST=db.example\nDB_PORT=3306\nDB_PASSWORD=zs-brokered\nX_URL=https://x.example\nX_USER=u\nX_PASSWORD=zs-brokered\n",
        );
        assert!(report.bindings.is_empty());
        assert!(report.credentials.is_empty());
        assert!(report.unbrokered.is_empty());
    }

    #[test]
    fn overrides_parse_and_refuse_bad_input() {
        assert_eq!(
            parse_db_override("db=MySQL").unwrap(),
            ("DB".to_string(), "mysql".to_string())
        );
        assert!(parse_db_override("DB=oracle").is_err());
        assert!(parse_db_override("=mysql").is_err());
        assert_eq!(
            parse_auth_override("SQUID_KEY=header:app-key").unwrap(),
            (
                "SQUID_KEY".to_string(),
                AuthOverride::Header("app-key".into())
            )
        );
        assert_eq!(
            parse_auth_override("T=bearer").unwrap().1,
            AuthOverride::Bearer
        );
        assert!(parse_auth_override("T=header:").is_err());
        assert!(parse_auth_override("T=header:bad name").is_err());
        assert!(parse_auth_override("T=basic").is_err());
    }

    #[test]
    fn credentials_are_written_private_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("home/.zs-credentials/proj");
        let first = [ScannedCredential::new("db", "v1")];
        write_credentials(&creds, &first).unwrap();
        assert_eq!(fs::read_to_string(creds.join("db")).unwrap(), "v1");
        write_credentials(&creds, &first).unwrap();
        let other = [ScannedCredential::new("db", "v2")];
        let err = write_credentials(&creds, &other).unwrap_err();
        assert!(err.contains("another value") && !err.contains("v1") && !err.contains("v2"));
        assert_eq!(fs::read_to_string(creds.join("db")).unwrap(), "v1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file = fs::metadata(creds.join("db")).unwrap().permissions().mode();
            let directory = fs::metadata(&creds).unwrap().permissions().mode();
            assert_eq!((file & 0o777, directory & 0o777), (0o600, 0o700));
            let target = dir.path().join("victim");
            fs::write(&target, "KEEP").unwrap();
            std::os::unix::fs::symlink(&target, creds.join("link")).unwrap();
            let linked = [ScannedCredential::new("link", "v3")];
            assert!(write_credentials(&creds, &linked).is_err());
            assert_eq!(fs::read_to_string(&target).unwrap(), "KEEP");
        }
    }

    #[test]
    fn tilde_path_names_the_home_relative_directory() {
        assert_eq!(
            tilde_path(Path::new("/h"), Path::new("/h/.zs-credentials/p")),
            "~/.zs-credentials/p"
        );
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
        let err = scan_err("A=1\nnot a pair\n", 54320);
        assert_eq!(err, "line 2: expected KEY=VALUE");
        let err = scan_err("=value\n", 54320);
        assert_eq!(err, "line 1: expected KEY=VALUE");
        let err = scan_err("KEY=\"-----BEGIN KEY-----\nabc==\n-----END-----\"\n", 54320);
        assert!(err.starts_with("line 1: multi-line"), "{err}");
        assert!(!err.contains("BEGIN"));
    }

    #[test]
    fn test_listen_port_overflow_is_an_error() {
        let content = "A=postgres://u:p@h1:5432/a\nB=postgres://u:p@h2:5432/b\n";
        let report = scan_and_sanitize(content, 65534).unwrap();
        assert_eq!(report.bindings[1].listen_port, Some(65535));
        let err = scan_err(
            "A=postgres://u:p@h1/a\nB=postgres://u:p@h2/b\nC=postgres://u:p@h3/c\n",
            65534,
        );
        assert!(err.contains("65535"), "{err}");
    }

    #[test]
    fn test_already_sanitized_detection() {
        assert!(already_sanitized(&format!(
            "{SANITIZED_MARKER} /h/.zs-backups/p/.env.1\nA=1\n"
        )));
        assert!(already_sanitized(
            "STRIPE_KEY=placeholder_managed_by_zerosecret\n"
        ));
        assert!(!already_sanitized("STRIPE_KEY=sk_live_x\n"));
    }

    #[test]
    fn test_backup_never_overwrites_an_existing_backup() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let backups = dir.path().join("backups/proj");
        let first = create_backup(&env_path, "ORIGINAL=1\n", "20261023_000000", &backups).unwrap();
        let second =
            create_backup(&env_path, "SANITIZED=1\n", "20261023_000000", &backups).unwrap();
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

    #[test]
    fn test_backup_dir_is_home_zs_backups_project() {
        assert_eq!(
            backup_dir(Path::new("/home/u"), Path::new("/work/project")),
            Path::new("/home/u/.zs-backups/project")
        );
    }

    #[test]
    fn test_masked_withholds_every_unbrokered_value() {
        let report = scan(
            "STRIPE_SECRET_KEY=sk_live_x\nAPP_NAME=plain_value\n# note\nexport JWT_SECRET='abc'\n",
        );
        assert!(report.masked.contains("APP_NAME=<withheld>"));
        assert!(report.masked.contains("export JWT_SECRET=<withheld>"));
        assert!(report.masked.contains("# <withheld>"));
        assert!(!report.masked.contains("# note"));
        assert!(report.sanitized.contains("# note"));
        assert!(
            report
                .masked
                .contains("STRIPE_SECRET_KEY=placeholder_managed_by_zerosecret")
        );
        for value in ["plain_value", "abc", "sk_live_x"] {
            assert!(!report.masked.contains(value), "{value} leaked");
        }
        assert!(report.sanitized.contains("APP_NAME=plain_value"));
    }

    #[test]
    fn test_marker_names_the_backup_path() {
        let report = scan("STRIPE_SECRET_KEY=sk_live_x\n");
        let written = with_backup_path(&report.sanitized, Path::new("/h/.zs-backups/p/.env.1"));
        assert!(
            written.starts_with(&format!("{SANITIZED_MARKER} /h/.zs-backups/p/.env.1\n")),
            "{written}"
        );
        assert!(already_sanitized(&written));
    }

    #[cfg(unix)]
    #[test]
    fn test_backup_refuses_a_symlink_at_the_backup_name() {
        let dir = tempfile::tempdir().unwrap();
        let env_path = dir.path().join(".env");
        let backups = dir.path().join("backups");
        let target = dir.path().join("victim");
        fs::write(&target, "KEEP\n").unwrap();
        ensure_private_dir(&backups).unwrap();
        std::os::unix::fs::symlink(&target, backups.join(".env.20261023_000000")).unwrap();
        let written = create_backup(&env_path, "SECRET=1\n", "20261023_000000", &backups).unwrap();
        assert_ne!(written, backups.join(".env.20261023_000000"));
        assert_eq!(fs::read_to_string(&target).unwrap(), "KEEP\n");
    }
}
