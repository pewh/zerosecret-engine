use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Postgres,
    Mysql,
    Mongodb,
    Http,
    Redis,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Postgres => "postgres",
            Protocol::Mysql => "mysql",
            Protocol::Mongodb => "mongodb",
            Protocol::Http => "http",
            Protocol::Redis => "redis",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub implementation: Implementation,
    pub fixtures: Fixtures,
}

#[derive(Clone, Debug)]
pub struct Implementation {
    pub name: String,
    pub adapter: PathBuf,
    pub capabilities: Vec<Protocol>,
}

#[derive(Clone, Debug, Default)]
pub struct Fixtures {
    pub postgres: Option<SocketAddr>,
    pub postgres_tls: Option<SocketAddr>,
    pub mysql: Option<SocketAddr>,
    pub mongodb: Option<SocketAddr>,
    pub redis: Option<SocketAddr>,
    pub redis_tls: Option<SocketAddr>,
}

#[derive(Debug)]
pub enum ConfigError {
    Read(io::Error),
    Parse(toml::de::Error),
    Address { field: &'static str, value: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read(error) => write!(formatter, "cannot read the config: {error}"),
            ConfigError::Parse(error) => write!(formatter, "cannot parse the config: {error}"),
            ConfigError::Address { field, value } => {
                write!(
                    formatter,
                    "fixture {field} is not a socket address: {value}"
                )
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConfigError::Read(error) => Some(error),
            ConfigError::Parse(error) => Some(error),
            ConfigError::Address { .. } => None,
        }
    }
}

#[derive(Deserialize)]
struct RawConfig {
    implementation: RawImplementation,
    #[serde(default)]
    fixtures: RawFixtures,
}

#[derive(Deserialize)]
struct RawImplementation {
    name: String,
    adapter: PathBuf,
    #[serde(default)]
    capabilities: Vec<Protocol>,
}

#[derive(Default, Deserialize)]
struct RawFixtures {
    postgres: Option<String>,
    postgres_tls: Option<String>,
    mysql: Option<String>,
    mongodb: Option<String>,
    redis: Option<String>,
    redis_tls: Option<String>,
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = fs::read_to_string(path).map_err(ConfigError::Read)?;
    let raw: RawConfig = toml::from_str(&text).map_err(ConfigError::Parse)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let adapter = if raw.implementation.adapter.is_absolute() {
        raw.implementation.adapter
    } else {
        base.join(raw.implementation.adapter)
    };
    Ok(Config {
        implementation: Implementation {
            name: raw.implementation.name,
            adapter,
            capabilities: raw.implementation.capabilities,
        },
        fixtures: Fixtures {
            postgres: address("postgres", &raw.fixtures.postgres)?,
            postgres_tls: address("postgres_tls", &raw.fixtures.postgres_tls)?,
            mysql: address("mysql", &raw.fixtures.mysql)?,
            mongodb: address("mongodb", &raw.fixtures.mongodb)?,
            redis: address("redis", &raw.fixtures.redis)?,
            redis_tls: address("redis_tls", &raw.fixtures.redis_tls)?,
        },
    })
}

fn address(field: &'static str, value: &Option<String>) -> Result<Option<SocketAddr>, ConfigError> {
    match value {
        None => Ok(None),
        Some(text) => text
            .parse::<SocketAddr>()
            .map(Some)
            .map_err(|_| ConfigError::Address {
                field,
                value: text.clone(),
            }),
    }
}
