use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

#[derive(Clone)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Resp {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn new(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
        }
    }
}

pub type Handler = Arc<dyn Fn(Req) -> Pin<Box<dyn Future<Output = Resp> + Send>> + Send + Sync>;

pub struct TestCa {
    key: KeyPair,
    cert: rcgen::Certificate,
}

impl Default for TestCa {
    fn default() -> Self {
        Self::new()
    }
}

impl TestCa {
    pub fn new() -> Self {
        let mut params =
            CertificateParams::new(Vec::<String>::new()).unwrap_or_else(|e| panic!("ca: {e}"));
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "zs-test-aws root");
        let key = KeyPair::generate().unwrap_or_else(|e| panic!("ca key: {e}"));
        let cert = params
            .self_signed(&key)
            .unwrap_or_else(|e| panic!("ca cert: {e}"));
        Self { key, cert }
    }

    pub fn issue(&self, host: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        self.issue_many(&[host])
    }

    pub fn issue_many(&self, hosts: &[&str]) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let names: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();
        let leaf_key = KeyPair::generate().unwrap_or_else(|e| panic!("leaf key: {e}"));
        let leaf = CertificateParams::new(names)
            .unwrap_or_else(|e| panic!("leaf: {e}"))
            .signed_by(&leaf_key, &self.cert, &self.key)
            .unwrap_or_else(|e| panic!("leaf cert: {e}"));
        (
            leaf.der().clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
    }

    pub fn root_pem(&self) -> String {
        self.cert.pem()
    }

    pub fn root_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    pub fn acceptor(&self, hosts: &[&str]) -> TlsAcceptor {
        let (cert, key) = self.issue_many(hosts);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|e| panic!("tls versions: {e}"))
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap_or_else(|e| panic!("tls cert: {e}"));
        TlsAcceptor::from(Arc::new(config))
    }
}

async fn read_request<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> Option<Req> {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8(buf[..end].to_vec()).ok()?;
            let mut lines = head.split("\r\n");
            let mut start = lines.next()?.split(' ');
            let method = start.next()?.to_string();
            let path = start.next()?.to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect();
            let len: usize = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let total = end + 4 + len;
            while buf.len() < total {
                let mut chunk = [0u8; 8192];
                let n = stream.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let body = buf[end + 4..total].to_vec();
            buf.drain(..total);
            return Some(Req {
                method,
                path,
                headers,
                body,
            });
        }
        let mut chunk = [0u8; 8192];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

pub(crate) async fn serve(
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
    handler: Handler,
) {
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = acceptor.accept(tcp).await else {
                return;
            };
            let mut buf = Vec::new();
            while let Some(req) = read_request(&mut tls, &mut buf).await {
                let resp = handler(req).await;
                let head = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nContent-Type: {}\r\nx-amzn-RequestId: 4d1a6f8e-0000-4000-8000-000000000000\r\n\r\n",
                    resp.status,
                    resp.body.len(),
                    resp.content_type
                );
                let mut bytes = head.into_bytes();
                bytes.extend_from_slice(&resp.body);
                if tls.write_all(&bytes).await.is_err() {
                    return;
                }
            }
        });
    }
}
