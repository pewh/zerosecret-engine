use std::net::SocketAddr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

pub(crate) fn caller_check() -> zs_protocol::CallerCheck {
    std::sync::Arc::new(admits)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn same_user(peer: SocketAddr, local: SocketAddr) -> std::io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        linux::same_user(peer, local)
    }
    #[cfg(target_os = "macos")]
    {
        macos::same_user(peer, local)
    }
}

fn admits(peer: SocketAddr, local: SocketAddr) -> bool {
    #[cfg(zs_test_endpoints)]
    if std::env::var_os("ZS_TEST_PEER_LOOKUP").is_some_and(|value| value == "fail") {
        return false;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        same_user(peer, local).unwrap_or(false)
    }
    #[cfg(windows)]
    {
        let _ = (peer, local);
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (peer, local);
        false
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn connected(local: &str) -> (TcpListener, TcpStream, TcpStream, SocketAddr) {
        let listener = TcpListener::bind(local).expect("a loopback listener");
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).expect("a loopback client");
        let (peer, _) = listener.accept().expect("an accepted connection");
        (listener, client, peer, addr)
    }

    #[test]
    fn a_socket_of_this_process_is_found() {
        let (_listener, client, peer, addr) = connected("127.0.0.1:0");
        assert!(
            same_user(client.local_addr().unwrap(), addr).expect("a lookup"),
            "the client {} to {} must be this process",
            client.local_addr().unwrap(),
            peer.local_addr().unwrap()
        );
    }

    #[test]
    fn a_closed_socket_is_not_admitted() {
        let (listener, client, _peer, addr) = connected("127.0.0.1:0");
        let client_addr = client.local_addr().unwrap();
        drop(client);
        drop(_peer);
        drop(listener);
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !admits(client_addr, addr),
            "a closed socket must not be admitted"
        );
    }

    #[test]
    fn a_same_user_client_is_found_over_ipv6_loopback() {
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            eprintln!("skipped: [::1] cannot be bound on this host");
            return;
        };
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).expect("an ipv6 loopback client");
        let (peer, _) = listener.accept().expect("an accepted connection");
        assert!(
            same_user(client.local_addr().unwrap(), addr).expect("a lookup"),
            "the client must be found over ::1 ({} -> {})",
            client.local_addr().unwrap(),
            peer.local_addr().unwrap()
        );
    }
}
