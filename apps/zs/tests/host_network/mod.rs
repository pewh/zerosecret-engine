#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::time::Duration;

pub const OTHER_NETWORK: &str = "192.0.2.0/24";

pub fn host_ip() -> Option<IpAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect("192.0.2.1:9").ok()?;
    let ip = probe.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

pub fn delivers_inbound(ip: IpAddr) -> bool {
    use std::io::{Read, Write};

    let Ok(listener) = std::net::TcpListener::bind((ip, 0)) else {
        return false;
    };
    let (Ok(addr), Ok(())) = (listener.local_addr(), listener.set_nonblocking(true)) else {
        return false;
    };
    let Ok(mut client) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    if client.write_all(b"z").is_err() {
        return false;
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if let Ok((mut server, _)) = listener.accept() {
            let _ = server.set_nonblocking(false);
            let _ = server.set_read_timeout(Some(Duration::from_secs(2)));
            let mut byte = [0u8; 1];
            return matches!(server.read(&mut byte), Ok(1));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

pub fn cannot_run_here(reason: &str) {
    assert!(
        std::env::var_os("ZS_REQUIRE_NETWORK").is_none_or(|value| value != "1"),
        "ZS_REQUIRE_NETWORK=1, but {reason}"
    );
    eprintln!("skipped: {reason}");
}

pub fn routed_ip() -> Option<IpAddr> {
    let Some(ip) = host_ip() else {
        cannot_run_here("this host has no non-loopback IPv4 address with a route");
        return None;
    };
    if OTHER_NETWORK
        .parse::<zs::cidr::Cidr>()
        .unwrap()
        .contains(ip)
    {
        cannot_run_here(&format!("the host address {ip} is inside {OTHER_NETWORK}"));
        return None;
    }
    Some(ip)
}

pub fn route_b_host() -> Option<IpAddr> {
    let ip = routed_ip()?;
    if !delivers_inbound(ip) {
        cannot_run_here(&format!(
            "a plain listener of this test binary on {ip} gets no byte from a client of the same process (a host firewall holds inbound data)"
        ));
        return None;
    }
    Some(ip)
}
