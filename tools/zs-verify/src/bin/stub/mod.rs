use std::io::{Read, Write};
use std::net::TcpStream;

use base64::Engine as _;

pub fn run_token() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    format!("{:032x}{:032x}", nanos, u128::from(std::process::id()))
}

pub fn proxy_url(token: &str, addr: std::net::SocketAddr) -> String {
    format!("http://zs:{token}@{addr}")
}

pub fn carries_token(request: &[u8], token: &str) -> bool {
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("zs:{token}"))
    );
    String::from_utf8_lossy(request).lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("proxy-authorization") && value.trim() == expected
        })
    })
}

pub fn refuse(mut stream: TcpStream, token: Option<&str>) {
    let mut request = [0u8; 4096];
    let read = stream.read(&mut request).unwrap_or(0);
    let answer: &[u8] = match token {
        Some(token) if !carries_token(&request[..read], token) => {
            b"HTTP/1.1 407 ZeroSecret needs the run token\r\nContent-Length: 0\r\n\r\n"
        }
        _ => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
    };
    let _ = stream.write_all(answer);
}

pub fn call_upstream(port: &str, credential: &str) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect upstream");
    stream
        .write_all(
            format!(
                "GET /v1/probe HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {credential}\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("send upstream request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
}
