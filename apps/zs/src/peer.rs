use std::net::{IpAddr, SocketAddr};

use zs::cidr::Cidr;
use zs_protocol::Caller;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

pub(crate) fn caller_check() -> zs_protocol::CallerCheck {
    std::sync::Arc::new(admits)
}

pub(crate) fn allow_list_check(
    allow: Vec<Cidr>,
    refused: impl Fn(SocketAddr) + Send + Sync + 'static,
) -> zs_protocol::CallerCheck {
    std::sync::Arc::new(move |caller: &Caller| match *caller {
        Caller::Tcp { peer, local } => {
            let admitted = allow_list_admits(&allow, peer, local, lookup_fails());
            if !admitted {
                refused(peer);
            }
            admitted
        }
        Caller::Unix { .. } => false,
    })
}

fn allow_list_admits(
    allow: &[Cidr],
    peer: SocketAddr,
    local: SocketAddr,
    lookup_fails: bool,
) -> bool {
    if local.ip().is_unspecified() || !allow.iter().any(|entry| entry.contains(peer.ip())) {
        return false;
    }
    match host_address(peer.ip(), local.ip()) {
        Ok(false) => true,
        Ok(true) => admits_with(&Caller::Tcp { peer, local }, lookup_fails),
        Err(_) => false,
    }
}

fn host_address(ip: IpAddr, local: IpAddr) -> std::io::Result<bool> {
    let ip = ip.to_canonical();
    if ip.is_loopback() || ip == local.to_canonical() {
        return Ok(true);
    }
    Ok(interface_addresses()?.contains(&ip))
}

#[cfg(unix)]
fn interface_addresses() -> std::io::Result<Vec<IpAddr>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut addresses = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        let item = unsafe { &*entry };
        if !item.ifa_addr.is_null() {
            match i32::from(unsafe { (*item.ifa_addr).sa_family }) {
                libc::AF_INET => {
                    let v4 = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in>() };
                    addresses.push(IpAddr::from(v4.sin_addr.s_addr.to_ne_bytes()));
                }
                libc::AF_INET6 => {
                    let v6 = unsafe { &*item.ifa_addr.cast::<libc::sockaddr_in6>() };
                    addresses.push(IpAddr::from(v6.sin6_addr.s6_addr));
                }
                _ => {}
            }
        }
        entry = item.ifa_next;
    }
    unsafe { libc::freeifaddrs(list) };
    Ok(addresses)
}

#[cfg(not(unix))]
fn interface_addresses() -> std::io::Result<Vec<IpAddr>> {
    Err(std::io::ErrorKind::Unsupported.into())
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

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn connected_on(
        ip: std::net::IpAddr,
    ) -> Option<(
        std::net::TcpListener,
        std::net::TcpStream,
        SocketAddr,
        SocketAddr,
    )> {
        let listener = std::net::TcpListener::bind((ip, 0)).ok()?;
        let addr = listener.local_addr().ok()?;
        let client =
            std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)).ok()?;
        let peer = client.local_addr().ok()?;
        Some((listener, client, peer, addr))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn routed_ip() -> Option<std::net::IpAddr> {
        let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        probe.connect("192.0.2.1:9").ok()?;
        let ip = probe.local_addr().ok()?.ip();
        (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_host_local_peer_inside_the_list_is_admitted_only_when_the_agent_user_holds_its_socket() {
        let (check, seen) = check(&["127.0.0.0/8"]);
        let (_listener, _client, peer, addr) =
            connected_on([127, 0, 0, 1].into()).expect("a loopback connection");
        assert!(check(&Caller::Tcp { peer, local: addr }));
        assert!(seen.lock().unwrap().is_empty());
        let unheld: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(!check(&Caller::Tcp {
            peer: unheld,
            local: addr
        }));
        assert_eq!(*seen.lock().unwrap(), vec![unheld]);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_host_local_peer_inside_the_list_is_refused_when_the_lookup_fails() {
        let allow = cidrs(&["127.0.0.0/8"]);
        let (_listener, _client, peer, addr) =
            connected_on([127, 0, 0, 1].into()).expect("a loopback connection");
        assert!(allow_list_admits(&allow, peer, addr, false));
        assert!(!allow_list_admits(&allow, peer, addr, true));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_peer_with_the_listener_address_is_a_host_peer() {
        let allow = cidrs(&["192.0.2.0/24"]);
        let listener: SocketAddr = "192.0.2.1:5432".parse().unwrap();
        assert!(allow_list_admits(
            &allow,
            "192.0.2.10:40000".parse().unwrap(),
            listener,
            false
        ));
        assert!(!allow_list_admits(
            &allow,
            "192.0.2.1:40000".parse().unwrap(),
            listener,
            false
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_peer_that_is_not_an_address_of_this_host_is_admitted_by_the_list_alone() {
        let allow = cidrs(&["192.0.2.0/24"]);
        let peer: SocketAddr = "192.0.2.10:40000".parse().unwrap();
        let listener: SocketAddr = "192.0.2.1:5432".parse().unwrap();
        assert!(allow_list_admits(&allow, peer, listener, false));
        assert!(allow_list_admits(&allow, peer, listener, true));
        assert!(!allow_list_admits(
            &allow,
            "198.51.100.10:40000".parse().unwrap(),
            listener,
            true
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_interface_addresses_hold_loopback_and_the_routed_address() {
        let addresses = interface_addresses().expect("the interface addresses");
        assert!(addresses.contains(&[127, 0, 0, 1].into()), "{addresses:?}");
        assert!(
            !addresses.contains(&[192, 0, 2, 10].into()),
            "{addresses:?}"
        );
        if let Some(ip) = routed_ip() {
            assert!(addresses.contains(&ip), "{ip} in {addresses:?}");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_peer_on_an_interface_address_of_this_host_is_looked_up() {
        let Some(ip) = routed_ip() else {
            eprintln!("skipped: this host has no routed non-loopback address");
            return;
        };
        let allow = cidrs(&[&format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })]);
        let Some((_listener, _client, peer, addr)) = connected_on(ip) else {
            eprintln!("skipped: no connection to {ip} on this host");
            return;
        };
        assert!(allow_list_admits(&allow, peer, addr, false));
        assert!(!allow_list_admits(&allow, peer, addr, true));
        let elsewhere: SocketAddr = "192.0.2.1:5432".parse().unwrap();
        assert!(!allow_list_admits(
            &allow,
            SocketAddr::new(ip, 1),
            elsewhere,
            false
        ));
        assert!(!allow_list_admits(
            &allow,
            SocketAddr::new(ip, 1),
            elsewhere,
            true
        ));
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
