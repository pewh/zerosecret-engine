pub mod connection;
pub mod device;
#[cfg(zs_test_endpoints)]
mod test_network;
pub mod wire_client;

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use zs_credential::{Credential, IdentityToken};
use zs_grant::{AgentVerifier, SignedGrant, VerifyContext};
use zs_identity::{Subject, WorkloadLabel};
use zs_mitm::{Flow, FlowHandler, PathScope, Scheme};
use zs_proto_http::{
    ApiKeyHeaderHttp, AwsSigV4, BasicAuthHttp, BearerHttp, HmacBodySignature, QueryParamHttp,
    WebSocketJsonField,
};
use zs_protocol::{Denied, Destination, Protocol};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("policy: {0}")]
    Policy(String),
    #[error("identity: {0}")]
    Identity(String),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ResourceBinding {
    pub resource: String,
    pub host: String,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub upstream_host: Option<String>,
    #[serde(default)]
    pub upstream_port: Option<u16>,
    #[serde(default)]
    pub upstream_plaintext: bool,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub local_endpoint: bool,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub upstream_ca: Option<PathBuf>,
    #[serde(default)]
    pub upstream_cert_sha256: Option<String>,
    #[serde(default)]
    pub client_auth_plugin: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub auth_source: Option<String>,
    #[serde(default)]
    pub auth: HttpAuth,
    #[serde(default)]
    pub source: Option<serde_json::Value>,
    #[serde(skip)]
    pub loaded_ca: Option<Arc<zs_upstream::LoadedCa>>,
}

#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(tag = "scheme", rename_all = "kebab-case")]
pub enum HttpAuth {
    #[default]
    Bearer,
    Basic,
    ApiKeyHeader {
        header: String,
    },
    QueryParam {
        param: String,
    },
    WebsocketJsonField {
        field: String,
    },
    AwsSigv4 {
        access_key_id: String,
        region: String,
        service: String,
    },
    HmacBodySignature {
        id_header: String,
        signature_header: String,
    },
}

impl HttpAuth {
    fn validate(&self) -> Result<(), String> {
        let HttpAuth::HmacBodySignature {
            id_header,
            signature_header,
        } = self
        else {
            return Ok(());
        };
        if !is_header_token(id_header) || !is_header_token(signature_header) {
            return Err("hmac-body-signature header names must be HTTP tokens".into());
        }
        if id_header.eq_ignore_ascii_case(signature_header) {
            return Err("hmac-body-signature id_header and signature_header must differ".into());
        }
        if [
            "host",
            "authorization",
            "content-length",
            "transfer-encoding",
        ]
        .iter()
        .any(|reserved| signature_header.eq_ignore_ascii_case(reserved))
        {
            return Err(format!(
                "hmac-body-signature may not write the {signature_header} header"
            ));
        }
        Ok(())
    }
}

fn is_header_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn default_protocol() -> String {
    "https".to_string()
}

impl ResourceBinding {
    pub fn operations(&self) -> Vec<String> {
        if self.is_l3() {
            vec!["connect".to_string()]
        } else if self.operations.is_empty() {
            vec!["GET".to_string()]
        } else {
            self.operations.clone()
        }
    }

    pub fn is_http(&self) -> bool {
        zs_protocol::classify_intercepted_protocol(&self.protocol)
            == Some(zs_protocol::InterceptedProtocol::Http)
    }

    pub fn scheme(&self) -> Scheme {
        if self.is_http() {
            Scheme::Http
        } else {
            Scheme::Https
        }
    }

    pub fn https_upstream_tls(&self) -> Result<bool, String> {
        if self.is_http() {
            return if self.upstream_plaintext {
                Err(format!(
                    "{}: upstream_plaintext is for https bindings; an http binding is always plaintext",
                    self.resource
                ))
            } else {
                Ok(false)
            };
        }
        if !self.upstream_plaintext {
            return Ok(true);
        }
        let host = self.upstream_host.as_deref().unwrap_or(&self.host);
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback());
        if loopback {
            Ok(false)
        } else {
            Err(format!(
                "{}: upstream_plaintext is allowed only for a loopback upstream",
                self.resource
            ))
        }
    }

    pub fn path_scope(&self) -> Result<PathScope, String> {
        let https = matches!(
            zs_protocol::classify_intercepted_protocol(&self.protocol),
            Some(zs_protocol::InterceptedProtocol::Https | zs_protocol::InterceptedProtocol::Http)
        );
        if self.paths.is_some() && !https {
            return Err(format!(
                "{}: paths is allowed only on an http or https binding",
                self.resource
            ));
        }
        PathScope::from_entries(self.paths.as_deref())
            .map_err(|e| format!("{}: {e}", self.resource))
    }

    pub fn is_postgres(&self) -> bool {
        zs_protocol::classify_intercepted_protocol(&self.protocol)
            == Some(zs_protocol::InterceptedProtocol::Postgres)
    }

    pub fn upstream(&self) -> (String, u16) {
        let default_port = zs_protocol::InterceptedProtocol::parse(&self.protocol)
            .map(zs_protocol::InterceptedProtocol::default_port)
            .unwrap_or(0);
        (
            self.upstream_host
                .clone()
                .unwrap_or_else(|| self.host.clone()),
            self.upstream_port.unwrap_or(default_port),
        )
    }

    pub fn is_mysql(&self) -> bool {
        zs_protocol::classify_intercepted_protocol(&self.protocol)
            == Some(zs_protocol::InterceptedProtocol::Mysql)
    }

    pub fn is_mongo(&self) -> bool {
        zs_protocol::classify_intercepted_protocol(&self.protocol)
            == Some(zs_protocol::InterceptedProtocol::Mongo)
    }

    pub fn is_l3(&self) -> bool {
        matches!(
            zs_protocol::classify_intercepted_protocol(&self.protocol),
            Some(
                zs_protocol::InterceptedProtocol::Postgres
                    | zs_protocol::InterceptedProtocol::Mysql
                    | zs_protocol::InterceptedProtocol::Mongo
            )
        )
    }

    pub fn env_prefix(&self) -> String {
        let name: String = self
            .resource
            .bytes()
            .map(|b| {
                let upper = b.to_ascii_uppercase();
                if upper.is_ascii_uppercase() || upper.is_ascii_digit() {
                    char::from(upper)
                } else {
                    '_'
                }
            })
            .collect();
        format!("ZS_{name}")
    }

    pub fn upstream_tls(&self) -> Result<zs_upstream::UpstreamTls, String> {
        let unloaded = self
            .upstream_ca
            .as_deref()
            .filter(|_| self.loaded_ca.is_none());
        if let Some(path) = unloaded {
            return Err(format!(
                "{}: {}",
                self.resource,
                zs_upstream::TlsConfigError::Unreadable(path.display().to_string())
            ));
        }
        zs_upstream::UpstreamTls::from_loaded(
            self.loaded_ca.as_deref(),
            self.upstream_cert_sha256.as_deref(),
        )
        .map_err(|e| format!("{}: {e}", self.resource))
    }

    pub fn mysql_client_auth(&self) -> Result<zs_proto_mysql::ClientAuth, String> {
        match self.client_auth_plugin.as_deref() {
            None => Ok(zs_proto_mysql::ClientAuth::default()),
            Some(name) => zs_proto_mysql::ClientAuth::parse(name).ok_or_else(|| {
                format!(
                    "{}: client_auth_plugin must be caching_sha2_password or mysql_native_password",
                    self.resource
                )
            }),
        }
    }

    pub fn mongo_auth(&self) -> Result<zs_proto_mongo::Auth, String> {
        let user = self
            .user
            .as_deref()
            .filter(|u| !u.is_empty())
            .ok_or_else(|| format!("{}: a mongo binding needs a non-empty user", self.resource))?;
        let source = self.auth_source.as_deref().unwrap_or("admin");
        if source.is_empty() {
            return Err(format!("{}: auth_source must not be empty", self.resource));
        }
        Ok(zs_proto_mongo::Auth::new(user, source))
    }

    pub fn mongo_tls(&self) -> Result<Option<zs_upstream::UpstreamTls>, String> {
        if !self.upstream_plaintext {
            return self.upstream_tls().map(Some);
        }
        if self.upstream_ca.is_some() || self.upstream_cert_sha256.is_some() {
            return Err(format!(
                "{}: upstream_plaintext cannot be set with upstream_ca or upstream_cert_sha256",
                self.resource
            ));
        }
        Ok(None)
    }

    pub fn listen_addr(&self) -> String {
        format!("127.0.0.1:{}", self.listen_port.unwrap_or(0))
    }

    pub fn l3_fields(&self) -> Result<(), String> {
        if self.listen_port == Some(0) {
            return Err(format!("{}: listen_port must be 1 to 65535", self.resource));
        }
        if !self.is_l3() && self.listen_port.is_some() {
            return Err(format!(
                "{}: listen_port is allowed only on a mysql, postgres or mongo binding",
                self.resource
            ));
        }
        if !self.is_l3() && self.user.is_some() {
            return Err(format!(
                "{}: user is allowed only on a mysql, postgres or mongo binding",
                self.resource
            ));
        }
        if !self.is_mongo() && self.auth_source.is_some() {
            return Err(format!(
                "{}: auth_source is allowed only on a mongo binding",
                self.resource
            ));
        }
        if self.user.as_deref() == Some("") {
            return Err(format!("{}: user must not be empty", self.resource));
        }
        if !self.is_l3() {
            if self.upstream_ca.is_some()
                || self.upstream_cert_sha256.is_some()
                || self.client_auth_plugin.is_some()
            {
                return Err(format!(
                    "{}: upstream_ca and upstream_cert_sha256 are allowed only on a mysql, postgres or mongo binding, and client_auth_plugin only on a mysql binding",
                    self.resource
                ));
            }
            return Ok(());
        }
        if self.is_mongo() {
            if self.auth != HttpAuth::default() {
                return Err(format!(
                    "{}: auth is not allowed on a mongo binding",
                    self.resource
                ));
            }
            if self.client_auth_plugin.is_some() {
                return Err(format!(
                    "{}: client_auth_plugin is allowed only on a mysql binding",
                    self.resource
                ));
            }
            self.mongo_auth()?;
            return self.mongo_tls().map(|_| ());
        }
        if self.upstream_plaintext {
            return Err(format!(
                "{}: upstream_plaintext is allowed only on an https binding",
                self.resource
            ));
        }
        if self.is_mysql() {
            if self.auth != HttpAuth::default() {
                return Err(format!(
                    "{}: auth is not allowed on a mysql binding",
                    self.resource
                ));
            }
            self.mysql_client_auth()?;
        } else if self.client_auth_plugin.is_some() {
            return Err(format!(
                "{}: client_auth_plugin is allowed only on a mysql binding",
                self.resource
            ));
        }
        self.upstream_tls().map(|_| ())
    }
}

pub struct MintedGrant {
    pub signed: SignedGrant,
    pub token: Option<IdentityToken>,
}

impl std::fmt::Debug for MintedGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedGrant")
            .field("grant_id", &self.signed.grant.grant_id)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl From<SignedGrant> for MintedGrant {
    fn from(signed: SignedGrant) -> Self {
        Self {
            signed,
            token: None,
        }
    }
}

// In-memory only: a persisted cache extends revocation lag past the TTL (ADR-0017).
#[derive(Default)]
pub struct GrantCache {
    grants: std::sync::Mutex<HashMap<String, Arc<MintedGrant>>>,
}

impl GrantCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(subject: &str, workload: &str, resource: &str) -> String {
        format!("{subject}\u{1f}{workload}\u{1f}{resource}")
    }

    pub fn insert(&self, minted: impl Into<MintedGrant>) {
        let minted = minted.into();
        let key = Self::key(
            &minted.signed.grant.subject,
            &minted.signed.grant.workload,
            &minted.signed.grant.resource,
        );
        if let Ok(mut grants) = self.grants.lock() {
            grants.insert(key, Arc::new(minted));
        }
    }

    pub fn get(&self, subject: &str, workload: &str, resource: &str) -> Option<Arc<MintedGrant>> {
        self.grants
            .lock()
            .ok()?
            .get(&Self::key(subject, workload, resource))
            .cloned()
    }

    pub fn all(&self) -> Vec<Arc<MintedGrant>> {
        self.grants
            .lock()
            .map(|grants| grants.values().cloned().collect())
            .unwrap_or_default()
    }
}

#[derive(Default)]
pub struct RevocationSet {
    revoked: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl RevocationSet {
    pub fn new() -> Self {
        Self::default()
    }

    // Additive only: replacing the set would resurrect revoked grants (ADR-0018).
    pub fn extend(&self, grant_ids: &[String]) {
        if let Ok(mut revoked) = self.revoked.lock() {
            revoked.extend(grant_ids.iter().cloned());
        }
    }

    // A poisoned lock denies: the set may be incomplete, so fail closed.
    pub fn contains(&self, grant_id: &str) -> bool {
        match self.revoked.lock() {
            Ok(revoked) => revoked.contains(grant_id),
            Err(_) => true,
        }
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RunSettings {
    #[serde(default)]
    pub control: Option<String>,
    #[serde(default)]
    pub control_ca: Option<PathBuf>,
    #[serde(default)]
    pub credentials_dir: Option<PathBuf>,
    #[serde(default)]
    pub ca_dir: Option<PathBuf>,
    #[serde(default)]
    pub audit: Option<PathBuf>,
}

#[derive(Deserialize)]
struct RunSettingsOnly {
    #[serde(default)]
    run: Option<RunSettings>,
}

pub fn load_run_settings(path: &Path) -> Result<Option<RunSettings>, ConfigError> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ConfigError::Policy(format!("{}: {e}", path.display()))),
    };
    let parsed: RunSettingsOnly = serde_json::from_str(&content)
        .map_err(|e| ConfigError::Policy(format!("{}: {e}", path.display())))?;
    Ok(parsed.run)
}

pub fn resolve_setting_path(value: &Path, policy_dir: &Path, home: &Path) -> PathBuf {
    if let Ok(rest) = value.strip_prefix("~") {
        if rest.as_os_str().is_empty() {
            return home.to_path_buf();
        }
        return home.join(rest);
    }
    if value.is_absolute() || value.has_root() {
        return value.to_path_buf();
    }
    policy_dir.join(value)
}

fn has_parent_component(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
}

pub fn checked_credentials_dir(
    value: &Path,
    policy_dir: &Path,
    home: &Path,
) -> Result<PathBuf, ConfigError> {
    let refuse =
        |why: &str| ConfigError::Policy(format!("run.credentials_dir {}: {why}", value.display()));
    if home.as_os_str().is_empty() {
        return Err(refuse(
            "HOME is not set, so the directory cannot be checked",
        ));
    }
    if has_parent_component(value) {
        return Err(refuse("a `..` component is not allowed"));
    }
    let resolved = resolve_setting_path(value, policy_dir, home);
    if has_parent_component(&resolved) {
        return Err(refuse("a `..` component is not allowed"));
    }
    let base = home.join(".zs-credentials");
    if !resolved.starts_with(&base) || resolved.components().count() <= base.components().count() {
        return Err(refuse("it must be a directory below ~/.zs-credentials/"));
    }
    Ok(resolved)
}

pub fn control_url_allowed(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| format!("control plane URL {url} is not a valid URL"))?;
    match parsed.scheme() {
        "https" if parsed.host_str().is_some_and(|host| !host.is_empty()) => Ok(()),
        "http" if is_loopback_host(parsed.host_str()) => Ok(()),
        "http" => Err(format!(
            "control plane URL {url}: http is allowed only for a loopback control plane \
             (localhost, 127.0.0.0/8 or ::1); use https"
        )),
        _ => Err(format!(
            "control plane URL {url}: use https (or http for a loopback control plane)"
        )),
    }
}

pub fn wire_url_allowed(url: &str) -> Result<(), String> {
    let parsed =
        reqwest::Url::parse(url).map_err(|_| format!("wire URL {url} is not a valid URL"))?;
    match parsed.scheme() {
        "https" if parsed.host_str().is_some_and(|host| !host.is_empty()) => Ok(()),
        "http" if is_loopback_host(parsed.host_str()) => Ok(()),
        _ => Err(format!(
            "wire URL {url}: use https (or http for a loopback wire listener)"
        )),
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|address| address == std::net::Ipv6Addr::LOCALHOST);
    }
    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|address| address.is_loopback())
}

pub fn control_ca_sha256(pem: &str) -> String {
    use sha2::{Digest, Sha256};
    let normalised: String = pem.chars().filter(|c| *c != '\r').collect();
    Sha256::digest(normalised.trim().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn control_ca_pem(control_ca: Option<&Path>, ca_dir: &Path) -> Result<String, String> {
    let named = match control_ca {
        Some(path) => Some((
            path.to_path_buf(),
            std::fs::read_to_string(path).map_err(|e| {
                format!(
                    "cannot read the control plane CA at {}: {e}",
                    path.display()
                )
            })?,
        )),
        None => None,
    };
    let in_dir_path = ca_dir.join("control-ca.crt");
    let in_dir = match std::fs::read_to_string(&in_dir_path) {
        Ok(pem) => Some(pem),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(format!(
                "cannot read the control plane CA at {}: {e}",
                in_dir_path.display()
            ));
        }
    };
    match (named, in_dir) {
        (Some((path, named)), Some(in_dir)) => {
            if control_ca_sha256(&named) == control_ca_sha256(&in_dir) {
                Ok(named)
            } else {
                Err(format!(
                    "two different control plane CAs: {} and {} differ; remove one",
                    path.display(),
                    in_dir_path.display()
                ))
            }
        }
        (Some((_, pem)), None) | (None, Some(pem)) => Ok(pem),
        (None, None) => Err(format!(
            "no control plane CA: set run.control_ca in zs-policy.json, pass --control-ca, or place control-ca.crt in {}",
            ca_dir.display()
        )),
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentFile {
    #[serde(default)]
    pub run: Option<RunSettings>,
    pub bindings: Vec<ResourceBinding>,
    #[serde(default)]
    pub signing_keys: Vec<SigningKeyEntry>,
    #[serde(default)]
    pub grants: Vec<SignedGrant>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SigningKeyEntry {
    pub key_id: String,
    pub verifying_key_hex: String,
}

impl AgentFile {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Policy(format!("{}: {e}", path.display())))?;
        let mut file: Self =
            serde_json::from_str(&content).map_err(|e| ConfigError::Policy(e.to_string()))?;
        for binding in &mut file.bindings {
            if let Some(path) = binding.upstream_ca.as_deref()
                && binding.is_l3()
            {
                let loaded = zs_upstream::load_ca(path)
                    .map_err(|e| ConfigError::Policy(format!("{}: {e}", binding.resource)))?;
                binding.loaded_ca = Some(Arc::new(loaded));
            }
        }
        file.validate()?;
        Ok(file)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut prefixes = std::collections::HashSet::new();
        let mut listen_ports = std::collections::HashSet::new();
        for signed in &self.grants {
            if !matches!(
                signed.grant.source,
                zs_policy::CredentialSource::File { .. }
            ) {
                return Err(ConfigError::Policy(format!(
                    "{}: a local grant may only use a file source",
                    signed.grant.resource
                )));
            }
        }
        for binding in &self.bindings {
            if binding.source.is_some() {
                return Err(ConfigError::Policy(format!(
                    "{}: source is set only by the control plane",
                    binding.resource
                )));
            }
            binding.l3_fields().map_err(ConfigError::Policy)?;
            if !binding.is_l3() {
                binding.https_upstream_tls().map_err(ConfigError::Policy)?;
            }
            binding.path_scope().map_err(ConfigError::Policy)?;
            binding
                .auth
                .validate()
                .map_err(|e| ConfigError::Policy(format!("{}: {e}", binding.resource)))?;
            if let Some(port) = binding.listen_port
                && !listen_ports.insert(port)
            {
                return Err(ConfigError::Policy(format!(
                    "{}: listen_port {port} is already used by another binding",
                    binding.resource
                )));
            }
            if binding.local_endpoint
                && zs_protocol::classify_intercepted_protocol(&binding.protocol)
                    != Some(zs_protocol::InterceptedProtocol::Https)
            {
                return Err(ConfigError::Policy(format!(
                    "{}: local_endpoint is allowed only on an https binding",
                    binding.resource
                )));
            }
            if (binding.is_l3() || binding.local_endpoint) && !prefixes.insert(binding.env_prefix())
            {
                return Err(ConfigError::Policy(format!(
                    "{}: {}_HOST is already set by another binding",
                    binding.resource,
                    binding.env_prefix()
                )));
            }
        }
        Ok(())
    }

    // An invalid key is an error, not a skip, so a typo is not a silent policy denial.
    pub fn verifier(&self) -> Result<AgentVerifier, ConfigError> {
        let mut keys = Vec::new();
        for entry in &self.signing_keys {
            let bytes = decode_hex32(&entry.verifying_key_hex).ok_or_else(|| {
                ConfigError::Policy(format!("signing key {} is not 32 hex bytes", entry.key_id))
            })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
                ConfigError::Policy(format!("signing key {} is not a valid key", entry.key_id))
            })?;
            keys.push((entry.key_id.clone(), key));
        }
        Ok(AgentVerifier::new(keys))
    }
}

fn decode_hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

pub const MATERIALIZE_FAILED: &str = "materialize failed";

pub const WIRE_USER_AGENT: &str = concat!("zs/", env!("ZS_BUILD_VERSION"));

pub const NODE_PRELOAD_SOURCE: &str = r#"'use strict';
// Installed by `zs run`. Routes Node's global fetch (undici) through the ZeroSecret proxy,
// which undici does not do from HTTPS_PROXY alone.
try {
  const { createRequire } = require('module');
  const path = require('path');
  const fs = require('fs');
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  if (proxy) {
    const anchors = [];
    if (process.argv[1]) {
      try {
        anchors.push(path.dirname(fs.realpathSync(process.argv[1])));
      } catch (e) {}
    }
    anchors.push(process.cwd());
    for (const dir of anchors) {
      try {
        const req = createRequire(path.join(dir, 'zs-preload-anchor.js'));
        const { ProxyAgent, setGlobalDispatcher } = req('undici');
        setGlobalDispatcher(new ProxyAgent(proxy));
        break;
      } catch (e) {}
    }
  }
} catch (e) {
  // A workload without undici cannot be helped, but must not be broken.
}
"#;

pub const BUN_PRELOAD_SOURCE: &str = r#"// Installed by `zs run`. Bun's WebSocket ignores HTTPS_PROXY; route it through the
// ZeroSecret proxy. fetch already honours the variable.
const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
const Native = globalThis.WebSocket;
if (proxy && typeof Native === 'function' && !Native.__zsProxied) {
  const loopback = /^wss?:\/\/(localhost|127\.[0-9.]+|\[::1\])(:|\/|$)/i;
  class ZsWebSocket extends Native {
    constructor(url, options) {
      const target = String(url);
      if (!/^wss?:/i.test(target) || loopback.test(target)) {
        super(url, options);
      } else if (options == null) {
        super(url, { proxy });
      } else if (typeof options === 'string' || Array.isArray(options)) {
        super(url, { protocols: options, proxy });
      } else {
        super(url, { proxy, ...options });
      }
    }
  }
  Object.defineProperty(ZsWebSocket, '__zsProxied', { value: true });
  globalThis.WebSocket = ZsWebSocket;
}
"#;

pub fn bun_options_with_preload(existing: Option<&str>, preload: &std::path::Path) -> String {
    let ours = format!("--preload={}", preload.display());
    match existing.map(str::trim).filter(|e| !e.is_empty()) {
        Some(existing) => format!("{existing} {ours}"),
        None => ours,
    }
}

// NODE_OPTIONS is split on whitespace and honours double quotes; Bun splits on whitespace
// and keeps any quote as part of the name, so a Bun preload path must contain none.
fn quoted_option(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    if !text
        .chars()
        .any(|c| c.is_whitespace() || c == '"' || c == '\\')
    {
        return text;
    }
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn node_options_with_preload(existing: Option<&str>, preload: &std::path::Path) -> String {
    let ours = format!("--require={}", quoted_option(preload));
    match existing.map(str::trim).filter(|e| !e.is_empty()) {
        Some(existing) => format!("{existing} {ours}"),
        None => ours,
    }
}

pub struct AgentConfig {
    pub bindings: Vec<ResourceBinding>,
    pub credentials_dir: PathBuf,
    pub subject: Subject,
    pub workload: WorkloadLabel,
}

pub struct AgentHandler {
    subject: Subject,
    workload: WorkloadLabel,
    bindings: HashMap<String, ResourceBinding>,
    protocols: HashMap<String, Arc<dyn Protocol>>,
    materializer: Arc<zs_materializer::Materializer>,
    grants: GrantCache,
    verifier: AgentVerifier,
    revoked: RevocationSet,
    lineage: std::sync::Mutex<HashMap<String, Vec<String>>>,
    diag: Option<zs_diag::DiagLog>,
}

// A grant lives minutes; 32 renewals back is hours of history, and no revoked grant of that
// age can still be valid. The chain therefore stays bounded without losing a live ancestor.
const MAX_LINEAGE: usize = 32;

fn resource_key(host: &str) -> String {
    host.to_ascii_lowercase()
}

fn protocol_for_auth(
    auth: &HttpAuth,
    host: &str,
    allowed: Vec<WorkloadLabel>,
) -> Arc<dyn Protocol> {
    match auth {
        HttpAuth::Bearer => Arc::new(BearerHttp::new(host.to_string(), allowed)),
        HttpAuth::Basic => Arc::new(BasicAuthHttp::new(host.to_string(), allowed)),
        HttpAuth::ApiKeyHeader { header } => Arc::new(ApiKeyHeaderHttp::new(
            host.to_string(),
            header.clone(),
            allowed,
        )),
        HttpAuth::QueryParam { param } => Arc::new(QueryParamHttp::new(
            host.to_string(),
            param.clone(),
            allowed,
        )),
        HttpAuth::WebsocketJsonField { field } => Arc::new(WebSocketJsonField::new(
            host.to_string(),
            field.clone(),
            allowed,
        )),
        HttpAuth::AwsSigv4 {
            access_key_id,
            region,
            service,
        } => Arc::new(AwsSigV4::new(
            host.to_string(),
            access_key_id.clone(),
            region.clone(),
            service.clone(),
            allowed,
        )),
        HttpAuth::HmacBodySignature {
            id_header,
            signature_header,
        } => Arc::new(HmacBodySignature::new(
            host.to_string(),
            id_header.clone(),
            signature_header.clone(),
            allowed,
        )),
    }
}

pub fn network_for_stores() -> zs_upstream::http::Network {
    #[cfg(zs_test_endpoints)]
    {
        test_network::network_from_env()
    }
    #[cfg(not(zs_test_endpoints))]
    {
        zs_upstream::http::Network::default()
    }
}

pub(crate) fn clock_ms(now: std::time::SystemTime) -> u64 {
    now.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(u64::MAX)
}

fn now_ms() -> u64 {
    clock_ms(std::time::SystemTime::now())
}

impl AgentHandler {
    pub fn from_grants(
        subject: Subject,
        workload: WorkloadLabel,
        bindings: Vec<ResourceBinding>,
        grants: GrantCache,
        verifier: AgentVerifier,
        materializer: Arc<zs_materializer::Materializer>,
    ) -> Self {
        let mut by_host = HashMap::new();
        let mut protocols: HashMap<String, Arc<dyn Protocol>> = HashMap::new();
        for binding in bindings {
            // Enumerate, never negate (ADR-0022): an unknown protocol gets no handler and denies.
            match zs_protocol::classify_intercepted_protocol(&binding.protocol) {
                Some(
                    zs_protocol::InterceptedProtocol::Postgres
                    | zs_protocol::InterceptedProtocol::Mysql
                    | zs_protocol::InterceptedProtocol::Mongo,
                ) => {
                    by_host.insert(binding.resource.clone(), binding);
                }
                Some(
                    zs_protocol::InterceptedProtocol::Https
                    | zs_protocol::InterceptedProtocol::Http,
                ) => {
                    let key = resource_key(&binding.host);
                    protocols.insert(
                        key.clone(),
                        protocol_for_auth(&binding.auth, &binding.host, vec![workload.clone()]),
                    );
                    by_host.insert(key, binding);
                }
                None => {}
            }
        }
        Self {
            subject,
            workload,
            bindings: by_host,
            protocols,
            materializer,
            grants,
            verifier,
            revoked: RevocationSet::new(),
            lineage: std::sync::Mutex::new(HashMap::new()),
            diag: None,
        }
    }

    pub fn with_diag(mut self, diag: zs_diag::DiagLog) -> Self {
        self.diag = Some(diag);
        self
    }

    fn binding_for(&self, host: &str) -> Option<&ResourceBinding> {
        self.bindings.get(&resource_key(host))
    }

    pub fn apply_revocations(&self, grant_ids: &[String]) {
        self.revoked.extend(grant_ids);
        for minted in self.grants.all() {
            if self.is_revoked(&minted.signed.grant.grant_id) {
                self.materializer.forget(&minted.signed.grant.resource);
            }
        }
    }

    pub fn cache_grant(&self, minted: impl Into<MintedGrant>) {
        self.grants.insert(minted);
    }

    pub fn renew_grant(&self, minted: impl Into<MintedGrant>) {
        let minted = minted.into();
        let previous = self.grants.get(
            self.subject.as_str(),
            self.workload.as_str(),
            &minted.signed.grant.resource,
        );
        if let (Some(previous), Ok(mut lineage)) = (previous, self.lineage.lock()) {
            let mut chain = lineage
                .remove(&previous.signed.grant.grant_id)
                .unwrap_or_default();
            chain.push(previous.signed.grant.grant_id.clone());
            if chain.len() > MAX_LINEAGE {
                let excess = chain.len() - MAX_LINEAGE;
                chain.drain(..excess);
            }
            lineage.insert(minted.signed.grant.grant_id.clone(), chain);
        }
        self.grants.insert(minted);
    }

    pub fn accept_renewal(
        &self,
        binding: &ResourceBinding,
        minted: impl Into<MintedGrant>,
    ) -> Result<(), connection::Mismatch> {
        let minted = minted.into();
        if let Some(previous) = self.grants.get(
            self.subject.as_str(),
            self.workload.as_str(),
            &minted.signed.grant.resource,
        ) && previous.signed.grant.source != minted.signed.grant.source
        {
            self.materializer.forget(&minted.signed.grant.resource);
            return Err(connection::Mismatch::Source);
        }
        connection::grant_matches(&minted.signed, binding)?;
        self.renew_grant(minted);
        Ok(())
    }

    fn is_revoked(&self, grant_id: &str) -> bool {
        if self.revoked.contains(grant_id) {
            return true;
        }
        match self.lineage.lock() {
            Ok(lineage) => lineage
                .get(grant_id)
                .is_some_and(|chain| chain.iter().any(|id| self.revoked.contains(id))),
            Err(_) => true,
        }
    }

    pub fn grant_needs_renewal(&self, resource: &str, within_ms: u64) -> bool {
        match self
            .grants
            .get(self.subject.as_str(), self.workload.as_str(), resource)
        {
            Some(minted) => {
                !self.is_revoked(&minted.signed.grant.grant_id)
                    && minted.signed.grant.expires_at_ms <= now_ms().saturating_add(within_ms)
            }
            None => false,
        }
    }

    fn authorized(
        &self,
        binding: &ResourceBinding,
        operation: &str,
    ) -> Result<(zs_grant::VerifiedGrant, Arc<MintedGrant>), String> {
        let resource = binding.resource.as_str();
        let minted = self
            .grants
            .get(self.subject.as_str(), self.workload.as_str(), resource)
            .ok_or_else(|| format!("no grant for {resource}"))?;
        let signed = &minted.signed;
        if self.is_revoked(&signed.grant.grant_id) {
            return Err(format!("grant {} is revoked", signed.grant.grant_id));
        }
        let verified = self
            .verifier
            .verify(
                signed,
                now_ms(),
                &VerifyContext {
                    subject: self.subject.as_str(),
                    workload: self.workload.as_str(),
                    resource,
                    operation,
                    environment: None,
                },
            )
            .map_err(|e| e.to_string())?;
        connection::grant_matches(signed, binding)
            .map_err(|mismatch| format!("{resource}: {}", mismatch.deny_reason()))?;
        Ok((verified, minted))
    }

    // A `*` binding also opens the host for a grant that lists methods; each request is then
    // checked against its own method in `materialize`.
    fn authorized_for_any(&self, binding: &ResourceBinding) -> Result<(), String> {
        let mut operations = binding.operations();
        if operations.iter().any(|o| o == zs_policy::ANY_METHOD)
            && let Some(minted) = self.grants.get(
                self.subject.as_str(),
                self.workload.as_str(),
                &binding.resource,
            )
        {
            operations.extend(
                minted
                    .signed
                    .grant
                    .operations
                    .iter()
                    .filter(|o| *o != zs_policy::CONNECT)
                    .cloned(),
            );
        }
        let mut last = String::new();
        for operation in operations {
            match self.authorized(binding, &operation) {
                Ok(_) => return Ok(()),
                Err(reason) => last = reason,
            }
        }
        Err(last)
    }
}

impl FlowHandler for AgentHandler {
    fn classify(&self, destination: &Destination) -> Flow {
        let Some(binding) = self.binding_for(&destination.host) else {
            return Flow::Passthrough;
        };
        let denied = |reason: String| Flow::Deny {
            reason: format!(
                "{} denied for {}: {reason}",
                self.subject.as_str(),
                binding.host
            ),
        };
        let protocol_port = zs_policy::default_port(&binding.protocol);
        let Some(upstream_port) = binding.upstream_port.or(protocol_port) else {
            return denied(format!("protocol {} has no default port", binding.protocol));
        };
        if destination.port != upstream_port && Some(destination.port) != protocol_port {
            return denied(format!(
                "port {} is not the signed port {upstream_port}",
                destination.port
            ));
        }
        let upstream_tls = match binding.https_upstream_tls() {
            Ok(tls) => tls,
            Err(reason) => return denied(reason),
        };
        let scope = match binding.path_scope() {
            Ok(scope) => scope,
            Err(reason) => return denied(reason),
        };
        let authorized = match scope {
            PathScope::Host => self.authorized_for_any(binding),
            PathScope::Paths(_) => Ok(()),
        };
        if let Err(reason) = authorized {
            return denied(reason);
        }
        Flow::Intercept {
            resource: resource_key(&binding.host),
            upstream_host: binding
                .upstream_host
                .clone()
                .unwrap_or_else(|| destination.host.clone()),
            upstream_port,
            upstream_tls,
            scheme: binding.scheme(),
            scope,
        }
    }

    fn subject(&self) -> String {
        self.subject.as_str().to_string()
    }

    fn workload(&self) -> String {
        self.workload.as_str().to_string()
    }

    fn protocol_for(&self, resource: &str) -> Option<Arc<dyn Protocol>> {
        self.protocols.get(resource).cloned()
    }

    fn materialize(&self, resource: &str, operation: &str) -> Result<Credential, Denied> {
        let binding = self
            .bindings
            .get(resource)
            .ok_or_else(|| Denied::new("unknown resource"))?;
        let (verified, minted) = self.authorized(binding, operation).map_err(Denied::new)?;
        let materializer = self.materializer.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(materializer.materialize(&verified, minted.token.as_ref()))
        })
        .map_err(|e| {
            if let Some(diag) = &self.diag {
                let mut event =
                    zs_diag::Event::new(zs_diag::Component::Agent, "materialize_failed")
                        .warn()
                        .resource(&binding.resource)
                        .failure(e.diag_code())
                        .token("credential_ref", &verified.grant().source.display_ref());
                match &e {
                    zs_materializer::MaterializationError::Refused { step, code, .. } => {
                        event = event.code("step", step).token("provider_code", code);
                    }
                    zs_materializer::MaterializationError::Transport { step, .. } => {
                        event = event.code("step", step);
                    }
                    _ => {}
                }
                diag.emit(event);
            }
            Denied::new(e.to_string()).with_audit_reason(MATERIALIZE_FAILED)
        })
    }

    fn authorize_message(&self, resource: &str, operation: &str) -> Result<(), Denied> {
        let binding = self
            .bindings
            .get(resource)
            .ok_or_else(|| Denied::new("unknown resource"))?;
        self.authorized(binding, operation)
            .map(|_| ())
            .map_err(|reason| {
                Denied::new(format!(
                    "{} denied for {}: {reason}",
                    self.subject.as_str(),
                    binding.host
                ))
            })
    }

    fn credential_ref(&self, resource: &str) -> Option<String> {
        let binding = match self.bindings.get(resource) {
            Some(binding) => binding,
            None => {
                let (host, port) = resource.rsplit_once(':')?;
                port.parse::<u16>().ok()?;
                self.binding_for(host)?
            }
        };
        self.grants
            .get(
                self.subject.as_str(),
                self.workload.as_str(),
                &binding.resource,
            )
            .map(|minted| minted.signed.grant.source.display_ref())
    }
}

#[cfg(test)]
mod control_url_tests {
    use super::{control_url_allowed, wire_url_allowed};

    #[test]
    fn a_wire_url_must_be_https_unless_it_is_loopback() {
        for url in [
            "https://localhost:8444",
            "https://wire.example.com/",
            "http://127.0.0.1:9",
            "http://localhost:8444",
            "http://[::1]:8444",
        ] {
            assert!(wire_url_allowed(url).is_ok(), "{url}");
        }
        for url in [
            "http://wire.example.com:8444",
            "http://10.0.0.1",
            "http://127.0.0.1.evil.com",
            "ftp://127.0.0.1",
            "wire.example.com:8444",
            "https://",
        ] {
            assert!(wire_url_allowed(url).is_err(), "{url}");
        }
    }

    #[test]
    fn https_is_allowed_for_any_host() {
        assert!(control_url_allowed("https://control.example.com").is_ok());
        assert!(control_url_allowed("https://10.0.0.5:8443/").is_ok());
    }

    #[test]
    fn plain_http_is_allowed_for_loopback_hosts() {
        for url in [
            "http://localhost:8443",
            "http://LOCALHOST",
            "http://127.0.0.1:9",
            "http://127.1.2.3",
            "http://[::1]:8443/",
        ] {
            assert!(control_url_allowed(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn plain_http_to_any_other_host_is_refused() {
        for url in [
            "http://example.invalid:8443",
            "http://127.0.0.1.evil.com",
            "http://localhost.evil.com",
            "http://127.0.0.1@evil.com",
            "http://10.0.0.1",
            "http://0.0.0.0",
            "http://[::ffff:127.0.0.1]",
            "http://[::2]",
        ] {
            let error = control_url_allowed(url).err().unwrap_or_default();
            assert!(
                error.contains("http is allowed only for a loopback control plane"),
                "{url}: {error}"
            );
        }
    }

    #[test]
    fn other_schemes_and_garbage_are_refused() {
        for url in ["ftp://127.0.0.1", "127.0.0.1:8443", "", "https://"] {
            assert!(control_url_allowed(url).is_err(), "{url}");
        }
    }
}

#[cfg(test)]
mod clock_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::clock_ms;

    fn grant(key: &zs_grant::ControlSigningKey, expires_at_ms: u64) -> zs_grant::SignedGrant {
        let connection = zs_policy::Connection::default()
            .resolve("api.stripe.com", "https")
            .unwrap();
        key.sign(zs_grant::Grant {
            subject: "alice@company.com".into(),
            workload: "claude-code".into(),
            resource: "stripe-production".into(),
            host: "api.stripe.com".into(),
            protocol: "https".into(),
            source: zs_policy::CredentialSource::file("stripe-prod"),
            operations: vec!["GET".into()],
            environment: "development".into(),
            expires_at_ms,
            grant_id: "g-clock".into(),
            materialization: zs_policy::Materialization::Retrieve,
            upstream_host: connection.upstream_host,
            upstream_port: connection.upstream_port,
            upstream_tls: connection.upstream_tls,
            local_endpoint: connection.local_endpoint,
            version: zs_grant::GRANT_VERSION,
        })
        .unwrap()
    }

    fn verifier(key: &zs_grant::ControlSigningKey) -> zs_grant::AgentVerifier {
        zs_grant::AgentVerifier::new(vec![(
            key.key_id().to_string(),
            ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
        )])
    }

    #[test]
    fn a_pre_epoch_clock_denies() {
        let before_epoch = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        let pre_epoch = clock_ms(before_epoch);
        assert_eq!(
            pre_epoch,
            u64::MAX,
            "a clock before 1970 must read as the latest possible time, so every grant has expired"
        );

        let key = zs_grant::ControlSigningKey::generate("control-k1");
        let context = zs_grant::VerifyContext {
            subject: "alice@company.com",
            workload: "claude-code",
            resource: "stripe-production",
            operation: "GET",
            environment: None,
        };
        let signed = grant(&key, clock_ms(std::time::SystemTime::now()) + 300_000);
        assert!(
            verifier(&key).verify(&signed, pre_epoch, &context).is_err(),
            "a grant must not verify under a pre-epoch clock"
        );
        assert!(
            verifier(&key)
                .verify(&signed, clock_ms(std::time::SystemTime::now()), &context)
                .is_ok(),
            "positive control: the same grant verifies under the real clock"
        );
    }
}

#[cfg(test)]
mod renewal_lineage_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::sync::Arc;

    use super::{AgentHandler, Destination, Flow, GrantCache, MAX_LINEAGE, ResourceBinding};
    use zs_grant::{ControlSigningKey, Grant, SignedGrant};
    use zs_mitm::FlowHandler;

    struct NoExchange;

    #[async_trait::async_trait]
    impl zs_materializer::ExchangeProvider for NoExchange {
        async fn exchange(
            &self,
            _grant: &Grant,
        ) -> Result<zs_credential::Credential, zs_materializer::MaterializationError> {
            Err(zs_materializer::MaterializationError::Exchange(
                "not configured".into(),
            ))
        }
    }

    fn binding() -> ResourceBinding {
        serde_json::from_value(serde_json::json!({
            "resource": "stripe-production",
            "host": "api.stripe.com",
            "protocol": "https",
            "auth": {"scheme": "bearer"}
        }))
        .unwrap()
    }

    fn grant(key: &ControlSigningKey, grant_id: &str) -> SignedGrant {
        let connection = zs_policy::Connection::default()
            .resolve("api.stripe.com", "https")
            .unwrap();
        key.sign(Grant {
            subject: "alice@company.com".into(),
            workload: "claude-code".into(),
            resource: "stripe-production".into(),
            host: "api.stripe.com".into(),
            protocol: "https".into(),
            source: zs_policy::CredentialSource::file("stripe-prod"),
            operations: vec!["GET".into()],
            environment: "development".into(),
            expires_at_ms: super::clock_ms(std::time::SystemTime::now()) + 300_000,
            grant_id: grant_id.into(),
            materialization: zs_policy::Materialization::Retrieve,
            upstream_host: connection.upstream_host,
            upstream_port: connection.upstream_port,
            upstream_tls: connection.upstream_tls,
            local_endpoint: connection.local_endpoint,
            version: zs_grant::GRANT_VERSION,
        })
        .unwrap()
    }

    fn handler(key: &ControlSigningKey) -> AgentHandler {
        let cache = GrantCache::new();
        cache.insert(grant(key, "g-0"));
        let verifier = zs_grant::AgentVerifier::new(vec![(
            key.key_id().to_string(),
            ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
        )]);
        let materializer = Arc::new(zs_materializer::Materializer::new(
            zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(
                "/nonexistent",
            ))),
            Arc::new(NoExchange),
        ));
        AgentHandler::from_grants(
            zs_identity::Subject::new("alice@company.com").unwrap(),
            zs_identity::WorkloadLabel::new("claude-code").unwrap(),
            vec![binding()],
            cache,
            verifier,
            materializer,
        )
    }

    fn denial(handler: &AgentHandler) -> String {
        match handler.classify(&Destination::new("api.stripe.com".to_string(), 443)) {
            Flow::Deny { reason } => reason,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn the_renewal_lineage_is_bounded() {
        let key = ControlSigningKey::generate("control-k1");
        let handler = handler(&key);
        assert!(
            matches!(
                handler.classify(&Destination::new("api.stripe.com".to_string(), 443)),
                Flow::Intercept { .. }
            ),
            "positive control: the first grant is usable"
        );

        let renewals = MAX_LINEAGE * 3;
        for i in 1..=renewals {
            handler.renew_grant(grant(&key, &format!("g-{i}")));
        }

        let chain = {
            let lineage = handler.lineage.lock().unwrap();
            assert_eq!(lineage.len(), 1, "one chain per resource");
            lineage.values().next().unwrap().clone()
        };
        assert_eq!(
            chain.len(),
            MAX_LINEAGE,
            "the chain must not grow with every renewal"
        );
        assert_eq!(chain.last().unwrap(), &format!("g-{}", renewals - 1));
        assert!(
            !chain.contains(&"g-0".to_string()),
            "the oldest ancestor falls out of the bounded window"
        );

        handler.apply_revocations(&[chain.last().unwrap().clone()]);
        assert!(
            denial(&handler).contains("revoked"),
            "positive control: a revoked ancestor inside the window still denies"
        );
    }
}
