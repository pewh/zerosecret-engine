use std::net::SocketAddr;
use std::time::Duration;

use rustls_pki_types::CertificateDer;
use thiserror::Error;

use crate::TransportKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyPolicy {
    None,
    System,
}

#[derive(Clone)]
pub enum Roots {
    WebPki,
    Only(Vec<CertificateDer<'static>>),
}

#[derive(Default, Clone)]
pub struct Network {
    pub resolve: Vec<(String, SocketAddr)>,
    pub extra_roots: Vec<CertificateDer<'static>>,
}

#[derive(Debug, Error)]
#[error("outbound client configuration failed")]
pub struct ClientError;

pub fn client(
    roots: Roots,
    timeout: Duration,
    identity: Option<reqwest::Identity>,
    https_only: bool,
    proxy: ProxyPolicy,
    network: &Network,
) -> Result<reqwest::Client, ClientError> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .https_only(https_only);
    if proxy == ProxyPolicy::None {
        builder = builder.no_proxy();
    }
    if let Roots::Only(certificates) = roots {
        builder = builder.tls_built_in_root_certs(false);
        builder = with_roots(builder, certificates)?;
    }
    builder = with_roots(builder, network.extra_roots.clone())?;
    for (host, address) in &network.resolve {
        builder = builder.resolve(host, *address);
    }
    if let Some(identity) = identity {
        builder = builder.identity(identity);
    }
    builder.build().map_err(|_| ClientError)
}

fn with_roots(
    mut builder: reqwest::ClientBuilder,
    certificates: Vec<CertificateDer<'static>>,
) -> Result<reqwest::ClientBuilder, ClientError> {
    for certificate in certificates {
        let certificate =
            reqwest::Certificate::from_der(certificate.as_ref()).map_err(|_| ClientError)?;
        builder = builder.add_root_certificate(certificate);
    }
    Ok(builder)
}

pub fn transport_kind(error: &reqwest::Error) -> TransportKind {
    if source_is_rustls(error) {
        return TransportKind::Tls;
    }
    if error.is_timeout() {
        return TransportKind::TimedOut;
    }
    if error.is_connect() {
        return TransportKind::Unreachable;
    }
    TransportKind::Other
}

fn source_is_rustls(error: &(dyn std::error::Error + 'static)) -> bool {
    if error.downcast_ref::<rustls::Error>().is_some() {
        return true;
    }
    if let Some(io) = error.downcast_ref::<std::io::Error>()
        && let Some(inner) = io.get_ref()
        && source_is_rustls(inner as &(dyn std::error::Error + 'static))
    {
        return true;
    }
    error.source().is_some_and(source_is_rustls)
}
