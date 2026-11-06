#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;

use common::{kill_agent, setup_agent};

#[tokio::test(flavor = "multi_thread")]
async fn unknown_destination_passes_through_without_credential() {
    let mut agent = setup_agent(true, true);
    let plain = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let plain_port = plain.local_addr().unwrap().port();
    let seen = std::thread::spawn(move || {
        let (mut stream, _) = plain.accept().unwrap();
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if std::io::Read::read(&mut stream, &mut byte).unwrap_or(0) == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&buf).into_owned();
        let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
        request
    });

    let proxy = agent.agent.as_ref().unwrap().proxy_addr.clone();
    let mut stream = TcpStream::connect(&proxy).unwrap();
    stream
        .write_all(&common::authorized_for_proxy(
            &proxy,
            format!(
                "CONNECT 127.0.0.1:{plain_port} HTTP/1.1\r\nHost: 127.0.0.1:{plain_port}\r\n\r\n"
            )
            .as_bytes(),
        ))
        .unwrap();
    let mut connect_response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).unwrap();
        connect_response.push(byte[0]);
        if connect_response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let status_line = String::from_utf8_lossy(&connect_response)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(
        status_line.contains(" 200 "),
        "CONNECT failed: {status_line}"
    );

    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .unwrap();
    let request = seen.join().unwrap();
    assert!(
        !request.to_ascii_lowercase().contains("authorization:"),
        "credential leaked on passthrough: {request}"
    );
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let response_text = String::from_utf8_lossy(&response).into_owned();
    assert!(
        response_text.starts_with("HTTP/1.0 200"),
        "passthrough response: {response_text}"
    );
    kill_agent(&mut agent);
}
