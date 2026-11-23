use std::net::SocketAddr;

use zs::cidr::Cidr;
use zs_protocol::Caller;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

pub(crate) fn caller_check() -> zs_protocol::CallerCheck {
    std::sync::Arc::new(admits)
}

#[allow(dead_code)]
pub(crate) fn allow_list_check(
    allow: Vec<Cidr>,
    refused: impl Fn(SocketAddr) + Send + Sync + 'static,
) -> zs_protocol::CallerCheck {
    std::sync::Arc::new(move |caller: &Caller| match *caller {
        Caller::Tcp { peer, local } => {
            let admitted =
                !local.ip().is_unspecified() && allow.iter().any(|entry| entry.contains(peer.ip()));
            if !admitted {
                refused(peer);
            }
            admitted
        }
        Caller::Unix { .. } => false,
    })
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

fn admits(caller: &Caller) -> bool {
    admits_with(caller, lookup_fails())
}

#[cfg(zs_test_endpoints)]
fn lookup_fails() -> bool {
    std::env::var_os("ZS_TEST_PEER_LOOKUP").is_some_and(|value| value == "fail")
}

#[cfg(not(zs_test_endpoints))]
fn lookup_fails() -> bool {
    false
}

fn admits_with(caller: &Caller, lookup_fails: bool) -> bool {
    if lookup_fails {
        return false;
    }
    match *caller {
        Caller::Tcp { peer, local } => tcp_admits(peer, local),
        Caller::Unix { uid } => unix_admits(uid),
    }
}

fn unix_admits(uid: Option<u32>) -> bool {
    #[cfg(unix)]
    {
        uid == Some(unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        let _ = uid;
        false
    }
}

fn tcp_admits(peer: SocketAddr, local: SocketAddr) -> bool {
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
            !admits(&Caller::Tcp {
                peer: client_addr,
                local: addr
            }),
            "a closed socket must not be admitted"
        );
    }

    fn agent_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    #[test]
    fn a_unix_caller_of_the_agent_user_is_admitted() {
        assert!(admits_with(
            &Caller::Unix {
                uid: Some(agent_uid())
            },
            false
        ));
    }

    #[test]
    fn a_unix_caller_of_another_user_is_refused() {
        assert!(admits_with(
            &Caller::Unix {
                uid: Some(agent_uid())
            },
            false
        ));
        for other in [agent_uid().wrapping_add(1), agent_uid().wrapping_sub(1)] {
            assert!(
                !admits_with(&Caller::Unix { uid: Some(other) }, false),
                "uid {other} must be refused"
            );
        }
    }

    #[test]
    fn a_unix_caller_without_a_user_id_is_refused() {
        assert!(!admits_with(&Caller::Unix { uid: None }, false));
    }

    #[test]
    fn a_failed_lookup_refuses_unix_and_tcp_callers() {
        let (_listener, client, _peer, addr) = connected("127.0.0.1:0");
        let tcp = Caller::Tcp {
            peer: client.local_addr().unwrap(),
            local: addr,
        };
        let unix = Caller::Unix {
            uid: Some(agent_uid()),
        };
        assert!(admits_with(&tcp, false));
        assert!(admits_with(&unix, false));
        assert!(!admits_with(&tcp, true));
        assert!(!admits_with(&unix, true));
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

#[cfg(test)]
mod allow_list_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::sync::{Arc, Mutex};

    fn cidrs(entries: &[&str]) -> Vec<Cidr> {
        entries.iter().map(|entry| entry.parse().unwrap()).collect()
    }

    fn tcp(peer: &str, local: &str) -> Caller {
        Caller::Tcp {
            peer: peer.parse().unwrap(),
            local: local.parse().unwrap(),
        }
    }

    fn check(entries: &[&str]) -> (zs_protocol::CallerCheck, Arc<Mutex<Vec<SocketAddr>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let check = allow_list_check(cidrs(entries), move |peer| sink.lock().unwrap().push(peer));
        (check, seen)
    }

    #[test]
    fn a_peer_inside_the_list_is_admitted_and_one_outside_is_refused() {
        let (check, seen) = check(&["172.17.0.0/16", "10.1.2.3/32"]);
        assert!(check(&tcp("172.17.0.2:40000", "172.17.0.1:5432")));
        assert!(check(&tcp("10.1.2.3:41000", "172.17.0.1:5432")));
        assert!(seen.lock().unwrap().is_empty());
        assert!(!check(&tcp("172.18.0.2:40000", "172.17.0.1:5432")));
        assert!(!check(&tcp("10.1.2.4:40000", "172.17.0.1:5432")));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                "172.18.0.2:40000".parse::<SocketAddr>().unwrap(),
                "10.1.2.4:40000".parse::<SocketAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn an_ipv4_mapped_peer_is_compared_as_ipv4() {
        let (check, seen) = check(&["172.17.0.0/16"]);
        assert!(check(&tcp("[::ffff:172.17.0.2]:40000", "172.17.0.1:5432")));
        assert!(seen.lock().unwrap().is_empty());
        assert!(!check(&tcp("[::ffff:172.18.0.2]:40000", "172.17.0.1:5432")));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn an_empty_list_admits_nothing() {
        let (check, seen) = check(&[]);
        assert!(!check(&tcp("127.0.0.1:40000", "127.0.0.1:5432")));
        assert!(!check(&tcp("172.17.0.2:40000", "172.17.0.1:5432")));
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_caller_with_an_unknown_local_address_is_refused_even_inside_the_list() {
        let (check, seen) = check(&["172.17.0.0/16"]);
        assert!(check(&tcp("172.17.0.2:40000", "172.17.0.1:5432")));
        assert!(!check(&tcp("172.17.0.2:40000", "0.0.0.0:0")));
        assert_eq!(
            *seen.lock().unwrap(),
            vec!["172.17.0.2:40000".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn a_unix_caller_is_refused_and_reported_to_nobody() {
        let (check, seen) = check(&["0.0.0.0/0"]);
        assert!(check(&tcp("172.17.0.2:40000", "172.17.0.1:5432")));
        assert!(!check(&Caller::Unix { uid: Some(0) }));
        assert!(!check(&Caller::Unix { uid: None }));
        assert!(seen.lock().unwrap().is_empty());
    }
}
