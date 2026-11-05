#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy, PartialEq)]
pub enum Reply {
    Ok,
    Echo,
    // Echoes the message as two messages, split ten bytes into the `apiKey` value.
    SplitEcho,
    Masked,
    Reserved,
    Status,
    // A 403 whose head names the credential the agent injects.
    StatusEcho,
    Extensions,
}

#[derive(Default)]
pub struct Seen {
    pub head: String,
    pub message: Vec<u8>,
    pub messages: usize,
}

pub fn frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    let bit = if mask.is_some() { 0x80 } else { 0 };
    if payload.len() < 126 {
        out.push(bit | payload.len() as u8);
    } else {
        out.push(bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    match mask {
        Some(m) => {
            out.extend_from_slice(&m);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), r.read_exact(&mut head))
        .await
        .ok()?
        .ok()?;
    let mut len = u64::from(head[1] & 0x7f);
    if len == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b).await.ok()?;
        len = u64::from(u16::from_be_bytes(b));
    }
    let mask = if head[1] & 0x80 != 0 {
        let mut m = [0u8; 4];
        r.read_exact(&mut m).await.ok()?;
        Some(m)
    } else {
        None
    };
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await.ok()?;
    if let Some(m) = mask {
        payload
            .iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b ^= m[i % 4]);
    }
    Some((head[0] & 0x0f, payload))
}

pub async fn read_head<R: AsyncRead + Unpin>(r: &mut R) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if r.read_exact(&mut byte).await.is_err() {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

pub async fn spawn_ws_upstream(reply: Reply, seen: Arc<Mutex<Seen>>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let head = read_head(&mut stream).await;
                seen.lock().unwrap().head = head;
                if matches!(reply, Reply::Status) {
                    let _ = stream
                        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\ndenied")
                        .await;
                    return;
                }
                if matches!(reply, Reply::StatusEcho) {
                    let _ = stream
                        .write_all(b"HTTP/1.1 403 Forbidden\r\nX-Debug-Key: sk_test_zsv_synthetic_value_9f27c4d1\r\nContent-Length: 6\r\n\r\ndenied")
                        .await;
                    return;
                }
                if matches!(reply, Reply::Extensions) {
                    let _ = stream
                        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
                        .await;
                    return;
                }
                stream
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n")
                    .await
                    .unwrap();
                while let Some((_, message)) = read_frame(&mut stream).await {
                    {
                        let mut seen = seen.lock().unwrap();
                        if seen.messages == 0 {
                            seen.message = message.clone();
                        }
                        seen.messages += 1;
                    }
                    let ok = br#"{"data":[{"taskType":"authentication"}]}"#.to_vec();
                    let answer = match reply {
                        Reply::Ok => frame(1, &ok, None),
                        Reply::Echo => frame(1, &message, None),
                        Reply::SplitEcho => {
                            let marker = br#""apiKey":""#;
                            let at = message
                                .windows(marker.len())
                                .position(|w| w == marker)
                                .map_or(message.len() / 2, |i| i + marker.len() + 10);
                            [
                                frame(1, &message[..at], None),
                                frame(1, &message[at..], None),
                            ]
                            .concat()
                        }
                        Reply::Masked => frame(1, &ok, Some([1, 2, 3, 4])),
                        Reply::Reserved => {
                            let mut f = frame(1, &ok, None);
                            f[0] |= 0x40;
                            f
                        }
                        Reply::Status | Reply::StatusEcho | Reply::Extensions => {
                            frame(1, &ok, None)
                        }
                    };
                    if stream.write_all(&answer).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}
