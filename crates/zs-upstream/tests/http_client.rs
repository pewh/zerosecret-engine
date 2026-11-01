#![cfg(feature = "reqwest")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zs_upstream::TransportKind;
use zs_upstream::http::{self, ClientError, Network, ProxyPolicy, Roots};

fn self_signed(host: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let certified = generate_simple_self_signed(vec![host.to_string()]).unwrap();
    (
        certified.cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der())),
    )
}

#[derive(Clone, Default)]
struct Seen {
    connections: Arc<AtomicUsize>,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
}

async fn start_tls_server(
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap(),
    );
    let seen = Seen::default();
    let task = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            task.connections.fetch_add(1, Ordering::SeqCst);
            let config = config.clone();
            let task = task.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(config).accept(stream).await
                else {
                    return;
                };
                let mut buffer = vec![0u8; 8192];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                task.requests
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buffer[..read]).to_string());
                let response =
                    b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
                let _ = stream.write_all(response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, seen)
}

async fn start_plain_server(response: Option<String>, hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            hits.fetch_add(1, Ordering::SeqCst);
            let response = response.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer).await;
                match response {
                    Some(response) => {
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    }
                    None => tokio::time::sleep(Duration::from_secs(60)).await,
                }
            });
        }
    });
    address
}

fn client(roots: Roots, timeout: Duration, network: &Network) -> reqwest::Client {
    http::client(roots, timeout, None, false, ProxyPolicy::None, network).unwrap()
}

#[tokio::test]
async fn does_not_follow_a_redirect() {
    let second_hits = Arc::new(AtomicUsize::new(0));
    let second = start_plain_server(
        Some("HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".into()),
        second_hits.clone(),
    )
    .await;
    let first = start_plain_server(
        Some(format!(
            "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:{second}/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        )),
        Arc::new(AtomicUsize::new(0)),
    )
    .await;

    let response = client(Roots::WebPki, Duration::from_secs(5), &Network::default())
        .get(format!("http://{first}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 302);
    assert_eq!(second_hits.load(Ordering::SeqCst), 0);
}

const PROXY_CHILD: &str = "ZS_HTTP_CLIENT_PROXY_CHILD";

async fn run_proxy_child(policy: &str) -> usize {
    let proxy_hits = Arc::new(AtomicUsize::new(0));
    let proxy = start_plain_server(None, proxy_hits.clone()).await;
    let exe = std::env::current_exe().unwrap();
    let policy = policy.to_string();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(exe)
            .args(["proxy_child", "--exact", "--test-threads=1", "--nocapture"])
            .env(PROXY_CHILD, policy)
            .env("HTTPS_PROXY", format!("http://{proxy}"))
            .env("https_proxy", format!("http://{proxy}"))
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    proxy_hits.load(Ordering::SeqCst)
}

#[tokio::test]
async fn proxy_child() {
    let Ok(policy) = std::env::var(PROXY_CHILD) else {
        return;
    };
    let (certificate, key) = self_signed("target.test");
    let (address, seen) = start_tls_server(certificate.clone(), key).await;
    let network = Network {
        resolve: vec![("target.test".into(), address)],
        ..Network::default()
    };
    let (proxy, timeout) = match policy.as_str() {
        "none" => (ProxyPolicy::None, Duration::from_secs(5)),
        _ => (ProxyPolicy::System, Duration::from_millis(500)),
    };
    let result = http::client(
        Roots::Only(vec![certificate]),
        timeout,
        None,
        false,
        proxy,
        &network,
    )
    .unwrap()
    .get("https://target.test/")
    .send()
    .await;
    if proxy == ProxyPolicy::None {
        assert_eq!(result.unwrap().status().as_u16(), 200);
        assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
    } else {
        assert!(result.is_err());
        assert_eq!(seen.connections.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_none_ignores_https_proxy_env() {
    assert!(
        run_proxy_child("system").await > 0,
        "the child must see HTTPS_PROXY, or this test proves nothing"
    );
    assert_eq!(run_proxy_child("none").await, 0);
}

#[tokio::test]
async fn times_out_a_silent_server() {
    let address = start_plain_server(None, Arc::new(AtomicUsize::new(0))).await;
    let start = Instant::now();
    let error = client(
        Roots::WebPki,
        Duration::from_millis(300),
        &Network::default(),
    )
    .get(format!("http://{address}/"))
    .send()
    .await
    .unwrap_err();
    assert_eq!(http::transport_kind(&error), TransportKind::TimedOut);
    assert!(start.elapsed() < Duration::from_millis(1300));
}

#[tokio::test]
async fn tls_failure_is_not_unreachable() {
    let (trusted, _) = self_signed("other.test");
    let (certificate, key) = self_signed("tls.test");
    let (address, _) = start_tls_server(certificate, key).await;
    let network = Network {
        resolve: vec![("tls.test".into(), address)],
        ..Network::default()
    };

    let error = client(Roots::Only(vec![trusted]), Duration::from_secs(5), &network)
        .get("https://tls.test/")
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        http::transport_kind(&error),
        TransportKind::Tls,
        "{error:?}"
    );
}

#[tokio::test]
async fn closed_port_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let error = client(Roots::WebPki, Duration::from_secs(5), &Network::default())
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(http::transport_kind(&error), TransportKind::Unreachable);
}

#[tokio::test]
async fn error_display_has_no_url() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);

    let error = client(Roots::WebPki, Duration::from_secs(5), &Network::default())
        .get(format!("http://{address}/secret-path"))
        .send()
        .await
        .unwrap_err();
    let text = http::transport_kind(&error).to_string();
    assert!(!text.contains("127.0.0.1"), "{text}");
    assert!(!text.contains("secret-path"), "{text}");
    assert!(!ClientError.to_string().contains("127.0.0.1"));
}

#[tokio::test]
async fn resolve_override_keeps_the_hostname() {
    let (certificate, key) = self_signed("ssm.ap-southeast-1.amazonaws.com");
    let (address, seen) = start_tls_server(certificate.clone(), key).await;
    let network = Network {
        resolve: vec![("ssm.ap-southeast-1.amazonaws.com".into(), address)],
        ..Network::default()
    };

    let response = client(
        Roots::Only(vec![certificate]),
        Duration::from_secs(5),
        &network,
    )
    .get("https://ssm.ap-southeast-1.amazonaws.com/")
    .send()
    .await
    .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let requests = seen.requests.lock().unwrap();
    let request = requests.first().expect("the server must see the request");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("host: ssm.ap-southeast-1.amazonaws.com"),
        "{request}"
    );
}
