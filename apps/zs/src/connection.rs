use std::net::SocketAddr;

use zs_grant::SignedGrant;
use zs_policy::{ResolvedConnection, UpstreamTlsMode, default_port};

use crate::ResourceBinding;
use crate::cidr::Cidr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    HostOrProtocol,
    Field {
        field: &'static str,
        file: String,
        signed: String,
    },
    Tls {
        field: &'static str,
        file: String,
        signed: UpstreamTlsMode,
        running: Option<UpstreamTlsMode>,
    },
    CaHash {
        path: String,
        file_hex: String,
        signed_hex: String,
    },
    CaMissing {
        signed_hex: String,
    },
    Source,
    Listen(String),
}

const HOST_MISMATCH: &str = "binding host does not match the grant";

impl Mismatch {
    pub fn startup_line(&self, resource: &str) -> String {
        match self {
            Self::HostOrProtocol => format!("zs: {resource}: {HOST_MISMATCH}"),
            Self::Field {
                field,
                file,
                signed,
            } => field_line(resource, field, file, signed),
            Self::Tls {
                field,
                file,
                signed,
                ..
            } => field_line(resource, field, file, &format!("upstream_tls {signed}")),
            Self::CaHash {
                path,
                file_hex,
                signed_hex,
            } => format!(
                "zs: {resource}: upstream_ca {path} has SHA-256 {file_hex}, but the control plane signed {signed_hex}; restore the file, or, if the new file is intended, ask an admin to set the resource's CA SHA-256 to {file_hex}"
            ),
            Self::CaMissing { signed_hex } => format!(
                "zs: {resource}: the control plane signed a CA bundle with SHA-256 {signed_hex}; set upstream_ca to that file"
            ),
            Self::Source => format!("zs: {resource}: source changed"),
            Self::Listen(message) => format!("zs: {message}"),
        }
    }

    pub fn renewal_line(&self, resource: &str) -> String {
        let (field, signed, running) = match self {
            Self::HostOrProtocol => return format!("zs: {resource}: {HOST_MISMATCH}"),
            Self::Field {
                field,
                file,
                signed,
            } => (*field, signed.clone(), file.clone()),
            Self::Tls {
                file,
                signed,
                running,
                ..
            } => (
                TLS,
                signed.to_string(),
                running.map_or_else(|| file.clone(), |mode| mode.to_string()),
            ),
            Self::CaHash {
                file_hex,
                signed_hex,
                ..
            } => (
                TLS,
                format!("ca-sha256:{signed_hex}"),
                format!("ca-sha256:{file_hex}"),
            ),
            Self::CaMissing { signed_hex } => (
                TLS,
                format!("ca-sha256:{signed_hex}"),
                UpstreamTlsMode::Default.to_string(),
            ),
            Self::Source => return format!("zs: {resource}: source changed"),
            Self::Listen(message) => return format!("zs: {message}"),
        };
        format!(
            "zs: {resource}: the control plane changed {field} (signed {signed}, running {running}); restart zs run to use it"
        )
    }

    pub fn deny_reason(&self) -> String {
        let field = match self {
            Self::HostOrProtocol => return HOST_MISMATCH.to_string(),
            Self::Field { field, .. } => field,
            Self::Tls { .. } | Self::CaHash { .. } | Self::CaMissing { .. } => TLS,
            Self::Source => return "source changed".to_string(),
            Self::Listen(message) => return message.clone(),
        };
        format!("{field} differs from the grant")
    }

    pub fn failure(&self) -> &'static str {
        match self {
            Self::HostOrProtocol => "host_mismatch",
            Self::Field { .. }
            | Self::Tls { .. }
            | Self::CaHash { .. }
            | Self::CaMissing { .. }
            | Self::Listen(_) => "connection_mismatch",
            Self::Source => "source_mismatch",
        }
    }
}

const TLS: &str = "upstream_tls";

fn field_line(resource: &str, field: &str, file: &str, signed: &str) -> String {
    format!(
        "zs: {resource}: {field} is {file} in the policy file, but the control plane signed {signed}; remove {field} from the policy file, or ask an admin to change resource {resource}"
    )
}

impl ResourceBinding {
    pub fn connection(&self) -> Result<ResolvedConnection, String> {
        let upstream_port = match self.upstream_port {
            Some(port) => port,
            None => default_port(&self.protocol).ok_or_else(|| {
                format!(
                    "{}: protocol {} has no default port",
                    self.resource, self.protocol
                )
            })?,
        };
        Ok(ResolvedConnection {
            upstream_host: self
                .upstream_host
                .clone()
                .unwrap_or_else(|| self.host.clone()),
            upstream_port,
            upstream_tls: self.tls_mode()?,
            local_endpoint: self.local_endpoint,
            listen_addr: self.listen_addr.clone(),
            listen_allow: self.listen_allow.clone(),
        })
    }

    fn tls_mode(&self) -> Result<UpstreamTlsMode, String> {
        if self.upstream_plaintext {
            return Ok(UpstreamTlsMode::Plaintext);
        }
        if let Some(pin) = self.upstream_cert_sha256.as_deref() {
            return match format!("pin-sha256:{pin}").parse() {
                Ok(UpstreamTlsMode::PinSha256(digest)) => Ok(UpstreamTlsMode::PinSha256(digest)),
                _ => Err(format!(
                    "{}: upstream_cert_sha256 must be 64 hex digits",
                    self.resource
                )),
            };
        }
        match (&self.loaded_ca, &self.upstream_ca) {
            (Some(loaded), _) => Ok(UpstreamTlsMode::CaSha256(loaded.sha256)),
            (None, Some(path)) => Err(format!(
                "{}: cannot read upstream_ca {}",
                self.resource,
                shown(&path.display().to_string())
            )),
            (None, None) => Ok(UpstreamTlsMode::Default),
        }
    }

    fn tls_set(&self) -> bool {
        self.upstream_plaintext || self.upstream_ca.is_some() || self.upstream_cert_sha256.is_some()
    }
}

fn same_host_and_protocol(signed: &SignedGrant, binding: &ResourceBinding) -> bool {
    signed.grant.host.eq_ignore_ascii_case(&binding.host)
        && signed
            .grant
            .protocol
            .eq_ignore_ascii_case(&binding.protocol)
}

pub fn reconcile(binding: &mut ResourceBinding, signed: &SignedGrant) -> Result<(), Mismatch> {
    if !same_host_and_protocol(signed, binding) {
        return Err(Mismatch::HostOrProtocol);
    }
    let wanted = signed.grant.connection();
    if let Some(host) = binding.upstream_host.as_deref()
        && !host.eq_ignore_ascii_case(&wanted.upstream_host)
    {
        return Err(field("upstream_host", host, &wanted.upstream_host));
    }
    if let Some(port) = binding.upstream_port
        && port != wanted.upstream_port
    {
        return Err(field(
            "upstream_port",
            &port.to_string(),
            &wanted.upstream_port.to_string(),
        ));
    }
    if binding.tls_set() {
        let running = binding.tls_mode().ok();
        if running != Some(wanted.upstream_tls) {
            return Err(tls_mismatch(binding, running, wanted.upstream_tls));
        }
    } else if let UpstreamTlsMode::CaSha256(digest) = wanted.upstream_tls {
        return Err(Mismatch::CaMissing {
            signed_hex: hex(&digest),
        });
    }
    if binding.local_endpoint && !wanted.local_endpoint {
        return Err(field("local_endpoint", "true", "false"));
    }
    if let Some(mismatch) = listen_mismatch(
        binding.listen_addr.as_deref(),
        &binding.listen_allow,
        &wanted,
        false,
    ) {
        return Err(mismatch);
    }

    if binding.upstream_host.is_none() && !wanted.upstream_host.eq_ignore_ascii_case(&binding.host)
    {
        binding.upstream_host = Some(wanted.upstream_host.clone());
    }
    if binding.upstream_port.is_none()
        && default_port(&binding.protocol) != Some(wanted.upstream_port)
    {
        binding.upstream_port = Some(wanted.upstream_port);
    }
    match wanted.upstream_tls {
        UpstreamTlsMode::Plaintext => binding.upstream_plaintext = true,
        UpstreamTlsMode::PinSha256(digest) if binding.upstream_cert_sha256.is_none() => {
            binding.upstream_cert_sha256 = Some(hex(&digest));
        }
        _ => {}
    }
    binding.local_endpoint = wanted.local_endpoint;
    if binding.listen_addr.is_none() && wanted.listen_addr.is_some() {
        binding.listen_addr = wanted.listen_addr.clone();
    }
    if binding.listen_allow.is_empty() && !wanted.listen_allow.is_empty() {
        binding.listen_allow = wanted.listen_allow.clone();
    }
    if wanted.listen_addr.is_some() {
        binding.listen().map_err(Mismatch::Listen)?;
    }
    grant_matches(signed, binding)
}

fn listen_mismatch(
    file_addr: Option<&str>,
    file_allow: &[String],
    wanted: &ResolvedConnection,
    unset_differs: bool,
) -> Option<Mismatch> {
    let signed_addr = wanted.listen_addr.as_deref();
    match (file_addr, signed_addr) {
        (Some(file), Some(signed)) if canonical_addr(file) != canonical_addr(signed) => {
            return Some(field(
                "listen_addr",
                &canonical_addr(file),
                &canonical_addr(signed),
            ));
        }
        (Some(file), None) if !is_loopback_addr(file) => {
            return Some(field("listen_addr", &canonical_addr(file), "none"));
        }
        (None, Some(signed)) if unset_differs => {
            return Some(field("listen_addr", "none", &canonical_addr(signed)));
        }
        _ => {}
    }
    if file_allow.is_empty() {
        if unset_differs && !wanted.listen_allow.is_empty() {
            return Some(field(
                "listen_allow",
                "none",
                &wanted.listen_allow.join(","),
            ));
        }
    } else if !same_cidrs(file_allow, &wanted.listen_allow) {
        return Some(field(
            "listen_allow",
            &file_allow.join(","),
            &if wanted.listen_allow.is_empty() {
                "none".to_string()
            } else {
                wanted.listen_allow.join(",")
            },
        ));
    }
    None
}

fn parse_addr(text: &str) -> Option<SocketAddr> {
    text.parse::<SocketAddr>()
        .ok()
        .map(|addr| SocketAddr::new(addr.ip().to_canonical(), addr.port()))
}

fn canonical_addr(text: &str) -> String {
    parse_addr(text).map_or_else(|| text.to_string(), |addr| addr.to_string())
}

fn is_loopback_addr(text: &str) -> bool {
    parse_addr(text).is_some_and(|addr| addr.ip().is_loopback())
}

fn same_cidrs(left: &[String], right: &[String]) -> bool {
    let parse = |list: &[String]| {
        list.iter()
            .map(|entry| entry.parse::<Cidr>())
            .collect::<Result<Vec<_>, _>>()
    };
    match (parse(left), parse(right)) {
        (Ok(left), Ok(right)) => {
            left.iter().all(|cidr| right.contains(cidr))
                && right.iter().all(|cidr| left.contains(cidr))
        }
        _ => false,
    }
}

pub fn grant_matches(signed: &SignedGrant, binding: &ResourceBinding) -> Result<(), Mismatch> {
    if !same_host_and_protocol(signed, binding) {
        return Err(Mismatch::HostOrProtocol);
    }
    let wanted = signed.grant.connection();
    let running = match binding.connection() {
        Ok(running) => running,
        Err(_) if binding.tls_mode().is_err() => {
            return Err(tls_mismatch(binding, None, wanted.upstream_tls));
        }
        Err(_) => return Err(Mismatch::HostOrProtocol),
    };
    if !running
        .upstream_host
        .eq_ignore_ascii_case(&wanted.upstream_host)
    {
        return Err(field(
            "upstream_host",
            &running.upstream_host,
            &wanted.upstream_host,
        ));
    }
    if running.upstream_port != wanted.upstream_port {
        return Err(field(
            "upstream_port",
            &running.upstream_port.to_string(),
            &wanted.upstream_port.to_string(),
        ));
    }
    if running.upstream_tls != wanted.upstream_tls {
        return Err(tls_mismatch(
            binding,
            Some(running.upstream_tls),
            wanted.upstream_tls,
        ));
    }
    if running.local_endpoint != wanted.local_endpoint {
        return Err(field(
            "local_endpoint",
            &running.local_endpoint.to_string(),
            &wanted.local_endpoint.to_string(),
        ));
    }
    if let Some(mismatch) = listen_mismatch(
        running.listen_addr.as_deref(),
        &running.listen_allow,
        &wanted,
        true,
    ) {
        return Err(mismatch);
    }
    Ok(())
}

fn tls_mismatch(
    binding: &ResourceBinding,
    running: Option<UpstreamTlsMode>,
    wanted: UpstreamTlsMode,
) -> Mismatch {
    if let (Some(UpstreamTlsMode::CaSha256(file)), UpstreamTlsMode::CaSha256(signed)) =
        (running, wanted)
    {
        return Mismatch::CaHash {
            path: ca_path(binding),
            file_hex: hex(&file),
            signed_hex: hex(&signed),
        };
    }
    let (name, value) = if binding.upstream_plaintext {
        ("upstream_plaintext", "true".to_string())
    } else if let Some(pin) = binding.upstream_cert_sha256.as_deref() {
        ("upstream_cert_sha256", shown(&pin.to_ascii_lowercase()))
    } else if binding.upstream_ca.is_some() {
        ("upstream_ca", ca_path(binding))
    } else {
        (TLS, UpstreamTlsMode::Default.to_string())
    };
    Mismatch::Tls {
        field: name,
        file: value,
        signed: wanted,
        running,
    }
}

fn field(name: &'static str, file: &str, signed: &str) -> Mismatch {
    Mismatch::Field {
        field: name,
        file: shown(file),
        signed: shown(signed),
    }
}

fn ca_path(binding: &ResourceBinding) -> String {
    binding
        .upstream_ca
        .as_deref()
        .map(|path| shown(&path.display().to_string()))
        .unwrap_or_default()
}

fn shown(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
