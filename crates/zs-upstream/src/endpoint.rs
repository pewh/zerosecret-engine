use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

const TOTAL_CONNECT_BUDGET: Duration = Duration::from_secs(5);
const CANDIDATE_CONNECT_BUDGET: Duration = Duration::from_secs(2);

#[derive(Clone, Eq, PartialEq)]
pub struct UpstreamEndpoint {
    host: String,
    port: u16,
}

impl UpstreamEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> io::Result<Self> {
        let host = host.into();
        if host.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upstream host must not be empty",
            ));
        }
        if port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upstream port must not be zero",
            ));
        }
        Ok(Self { host, port })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn connect(&self) -> io::Result<TcpStream> {
        connect_with(self, |host, port| async move {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|addrs| addrs.collect())
        })
        .await
    }
}

pub async fn connect_with<R, F>(endpoint: &UpstreamEndpoint, resolve: R) -> io::Result<TcpStream>
where
    R: FnOnce(String, u16) -> F,
    F: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    connect_via(endpoint, resolve, TcpStream::connect).await
}

/// `connect_with` with the TCP connect passed in, so tests can hold a connect open without
/// relying on how the host treats a full listen backlog.
async fn connect_via<R, F, C, G>(
    endpoint: &UpstreamEndpoint,
    resolve: R,
    mut connect: C,
) -> io::Result<TcpStream>
where
    R: FnOnce(String, u16) -> F,
    F: Future<Output = io::Result<Vec<SocketAddr>>>,
    C: FnMut(SocketAddr) -> G,
    G: Future<Output = io::Result<TcpStream>>,
{
    let attempt = async {
        let candidates = resolve(endpoint.host.clone(), endpoint.port)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "upstream host could not be resolved",
                )
            })?;
        let mut seen = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if seen.contains(&candidate) {
                continue;
            }
            seen.push(candidate);
        }
        if seen.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "no upstream candidates were resolved",
            ));
        }

        let mut last_error = io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "all upstream candidates failed",
        );
        for candidate in seen {
            match tokio::time::timeout(CANDIDATE_CONNECT_BUDGET, connect(candidate)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(_)) => {
                    last_error = io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "upstream candidate refused the connection",
                    );
                }
                Err(_) => {
                    last_error = io::Error::new(
                        io::ErrorKind::TimedOut,
                        "upstream candidate connect timed out",
                    );
                }
            }
        }

        Err(last_error)
    };

    match tokio::time::timeout(TOTAL_CONNECT_BUDGET, attempt).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "upstream connect exceeded the total connect budget",
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::io::ErrorKind;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    const SENTINEL_HOST: &str = "s3cr3t-host-should-not-leak.invalid";

    #[test]
    fn endpoint_rejects_empty_host() {
        let error = match UpstreamEndpoint::new("", 5432) {
            Ok(_) => panic!("expected empty host to be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(!error.to_string().contains(SENTINEL_HOST));
    }

    #[test]
    fn endpoint_rejects_zero_port() {
        let error = match UpstreamEndpoint::new(SENTINEL_HOST, 0) {
            Ok(_) => panic!("expected zero port to be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(!error.to_string().contains(SENTINEL_HOST));
    }

    #[tokio::test]
    async fn no_candidates_denies() {
        let endpoint = UpstreamEndpoint::new(SENTINEL_HOST, 5432).unwrap();
        let result = connect_with(&endpoint, |_host, _port| async { Ok(Vec::new()) }).await;
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
        assert!(!error.to_string().contains(SENTINEL_HOST));
    }

    #[tokio::test]
    async fn resolver_error_is_redacted() {
        let endpoint = UpstreamEndpoint::new(SENTINEL_HOST, 5432).unwrap();
        let result = connect_with(&endpoint, |_host, _port| async {
            Err(io::Error::other(SENTINEL_HOST))
        })
        .await;
        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
        assert!(!error.to_string().contains(SENTINEL_HOST));
    }

    #[tokio::test]
    async fn first_candidate_failure_uses_second() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = live.accept().await;
        });

        let endpoint = UpstreamEndpoint::new(SENTINEL_HOST, 5432).unwrap();
        let candidates: Vec<SocketAddr> = vec![dead_addr, live_addr];
        let stream = connect_with(&endpoint, move |_host, _port| {
            let candidates = candidates.clone();
            async move { Ok(candidates) }
        })
        .await
        .unwrap();

        assert_eq!(stream.peer_addr().unwrap(), live_addr);
    }

    #[tokio::test]
    async fn all_candidates_fail() {
        let dead_one = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr_one = dead_one.local_addr().unwrap();
        drop(dead_one);

        let dead_two = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr_two = dead_two.local_addr().unwrap();
        drop(dead_two);

        let endpoint = UpstreamEndpoint::new(SENTINEL_HOST, 5432).unwrap();
        let candidates = vec![dead_addr_one, dead_addr_two];
        let result = connect_with(&endpoint, move |_host, _port| {
            let candidates = candidates.clone();
            async move { Ok(candidates) }
        })
        .await;

        let error = result.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
        assert!(!error.to_string().contains(SENTINEL_HOST));
    }

    /// A TCP connect that never finishes, as to a host that drops the SYN. It records each
    /// address it was asked for. A real socket cannot do this portably: Linux drops a SYN to
    /// a full listen backlog, macOS may answer it with a reset.
    fn hanging_connect(
        attempts: std::sync::Arc<std::sync::Mutex<Vec<SocketAddr>>>,
    ) -> impl FnMut(SocketAddr) -> std::future::Pending<io::Result<TcpStream>> {
        move |addr| {
            attempts.lock().unwrap().push(addr);
            std::future::pending()
        }
    }

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    #[tokio::test(start_paused = true)]
    async fn total_budget_is_bounded() {
        let candidates = vec![test_addr(1), test_addr(2), test_addr(3)];
        let attempts = std::sync::Arc::default();

        let endpoint = UpstreamEndpoint::new(SENTINEL_HOST, 5432).unwrap();
        let t0 = tokio::time::Instant::now();
        let error = connect_via(
            &endpoint,
            move |_host, _port| async move { Ok(candidates) },
            hanging_connect(std::sync::Arc::clone(&attempts)),
        )
        .await
        .unwrap_err();
        let elapsed = t0.elapsed();

        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(!error.to_string().contains(SENTINEL_HOST));
        assert_eq!(elapsed, TOTAL_CONNECT_BUDGET);
        // 2 s + 2 s spent on the first two; the total budget cuts the third short.
        assert_eq!(
            *attempts.lock().unwrap(),
            vec![test_addr(1), test_addr(2), test_addr(3)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_candidates_are_not_retried() {
        let addr = test_addr(1);
        let attempts = std::sync::Arc::default();

        let endpoint = UpstreamEndpoint::new(SENTINEL_HOST, 5432).unwrap();
        let t0 = tokio::time::Instant::now();
        let error = connect_via(
            &endpoint,
            move |_host, _port| async move { Ok(vec![addr, addr]) },
            hanging_connect(std::sync::Arc::clone(&attempts)),
        )
        .await
        .unwrap_err();
        let elapsed = t0.elapsed();

        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert_eq!(elapsed, CANDIDATE_CONNECT_BUDGET);
        assert_eq!(*attempts.lock().unwrap(), vec![addr]);
    }

    #[tokio::test]
    async fn connect_resolves_and_connects_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let endpoint = UpstreamEndpoint::new("127.0.0.1", addr.port()).unwrap();
        let stream = endpoint.connect().await.unwrap();

        assert_eq!(stream.peer_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn localhost_reaches_an_ipv4_only_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let endpoint = UpstreamEndpoint::new("localhost", addr.port()).unwrap();
        let stream = endpoint.connect().await.unwrap();

        assert_eq!(stream.peer_addr().unwrap(), addr);
    }
}
