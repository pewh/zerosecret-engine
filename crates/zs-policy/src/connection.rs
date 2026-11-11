use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const CA_PREFIX: &str = "ca-sha256:";
const PIN_PREFIX: &str = "pin-sha256:";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UpstreamTlsMode {
    #[default]
    Default,
    Plaintext,
    CaSha256([u8; 32]),
    PinSha256([u8; 32]),
}

impl fmt::Display for UpstreamTlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("default"),
            Self::Plaintext => f.write_str("plaintext"),
            Self::CaSha256(digest) => write!(f, "{CA_PREFIX}{}", hex_lower(digest)),
            Self::PinSha256(digest) => write!(f, "{PIN_PREFIX}{}", hex_lower(digest)),
        }
    }
}

impl FromStr for UpstreamTlsMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "default" {
            return Ok(Self::Default);
        }
        if value == "plaintext" {
            return Ok(Self::Plaintext);
        }
        if let Some(digits) = value.strip_prefix(CA_PREFIX) {
            return parse_digest(digits, CA_PREFIX).map(Self::CaSha256);
        }
        if let Some(digits) = value.strip_prefix(PIN_PREFIX) {
            return parse_digest(digits, PIN_PREFIX).map(Self::PinSha256);
        }
        Err(format!(
            "upstream_tls must be default, plaintext, {CA_PREFIX}<64 hex> or {PIN_PREFIX}<64 hex>"
        ))
    }
}

impl Serialize for UpstreamTlsMode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for UpstreamTlsMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

fn hex_lower(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn short_hex(bytes: &[u8; 32]) -> String {
    let head: String = hex_lower(bytes).chars().take(8).collect();
    format!("{head}…")
}

fn parse_digest(digits: &str, prefix: &str) -> Result<[u8; 32], String> {
    let raw = digits.as_bytes();
    if raw.len() != 64 || !raw.iter().all(u8::is_ascii_hexdigit) {
        return Err(format!(
            "upstream_tls {prefix} must be followed by 64 hex digits"
        ));
    }
    let mut out = [0u8; 32];
    let (pairs, _) = raw.as_chunks::<2>();
    for (slot, [high, low]) in out.iter_mut().zip(pairs) {
        *slot = (nibble(*high) << 4) | nibble(*low);
    }
    Ok(out)
}

fn nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => digit - b'A' + 10,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    #[serde(default)]
    pub upstream_host: Option<String>,
    #[serde(default)]
    pub upstream_port: Option<u16>,
    #[serde(default)]
    pub upstream_tls: UpstreamTlsMode,
    #[serde(default)]
    pub local_endpoint: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedConnection {
    pub upstream_host: String,
    pub upstream_port: u16,
    pub upstream_tls: UpstreamTlsMode,
    pub local_endpoint: bool,
}

pub fn default_port(protocol: &str) -> Option<u16> {
    zs_protocol::InterceptedProtocol::parse(protocol)
        .map(zs_protocol::InterceptedProtocol::default_port)
}

pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn is_host_name_or_ip(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

impl Connection {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        match (&self.upstream_host, self.upstream_port) {
            (Some(host), Some(port)) => parts.push(format!("{host}:{port}")),
            (Some(host), None) => parts.push(host.clone()),
            (None, Some(port)) => parts.push(format!(":{port}")),
            (None, None) => {}
        }
        match &self.upstream_tls {
            UpstreamTlsMode::Default => {}
            UpstreamTlsMode::Plaintext => parts.push("plaintext".to_string()),
            UpstreamTlsMode::CaSha256(digest) => parts.push(format!("ca {}", short_hex(digest))),
            UpstreamTlsMode::PinSha256(digest) => {
                parts.push(format!("pin {}", short_hex(digest)));
            }
        }
        if self.local_endpoint {
            parts.push("local endpoint".to_string());
        }
        parts.join(" ")
    }

    pub fn validate(&self, host: &str, protocol: &str) -> Result<(), String> {
        let Some(_) = default_port(protocol) else {
            return if self.is_default() {
                Ok(())
            } else {
                Err(format!(
                    "connection fields are not allowed on a {protocol} resource"
                ))
            };
        };
        if self.upstream_port == Some(0) {
            return Err("upstream_port must be 1 to 65535".to_string());
        }
        if let Some(upstream) = self.upstream_host.as_deref()
            && !is_host_name_or_ip(upstream)
        {
            return Err(
                "upstream_host must be a host name or an IP literal, with no port".to_string(),
            );
        }
        let https = protocol.eq_ignore_ascii_case("https");
        if self.local_endpoint && !https {
            return Err("local_endpoint is allowed only on an https resource".to_string());
        }
        let l3 = ["postgres", "mysql", "mongo", "redis"]
            .iter()
            .any(|name| protocol.eq_ignore_ascii_case(name));
        match self.upstream_tls {
            UpstreamTlsMode::Default => Ok(()),
            UpstreamTlsMode::CaSha256(_) | UpstreamTlsMode::PinSha256(_) if l3 => Ok(()),
            UpstreamTlsMode::CaSha256(_) | UpstreamTlsMode::PinSha256(_) => Err(
                "upstream_tls ca-sha256 and pin-sha256 are allowed only on postgres, mysql, mongo and redis"
                    .to_string(),
            ),
            UpstreamTlsMode::Plaintext => {
                let upstream = self.upstream_host.as_deref().unwrap_or(host);
                if protocol.eq_ignore_ascii_case("mongo")
                    || protocol.eq_ignore_ascii_case("redis")
                    || (https && is_loopback_host(upstream))
                {
                    Ok(())
                } else {
                    Err("upstream_tls plaintext is allowed only on mongo and redis, or on https with a loopback upstream_host".to_string())
                }
            }
        }
    }

    pub fn resolve(&self, host: &str, protocol: &str) -> Result<ResolvedConnection, String> {
        self.validate(host, protocol)?;
        let Some(port) = default_port(protocol) else {
            return Err(format!("{protocol} is not a protocol the agent intercepts"));
        };
        Ok(ResolvedConnection {
            upstream_host: self
                .upstream_host
                .clone()
                .unwrap_or_else(|| host.to_string()),
            upstream_port: self.upstream_port.unwrap_or(port),
            upstream_tls: self.upstream_tls,
            local_endpoint: self.local_endpoint,
        })
    }
}
