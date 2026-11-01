use std::io::{Read, Write};
use std::net::TcpStream;

pub fn refuse(mut stream: TcpStream) {
    let mut request = [0u8; 4096];
    let _ = stream.read(&mut request);
    let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
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
