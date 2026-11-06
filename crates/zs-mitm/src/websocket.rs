use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;
use zs_credential::Credential;
use zs_protocol::{InjectedRequest, Protocol};

use crate::echo::{HOLD_PREFIX, started_prefix};

const MAX_MESSAGE: usize = 32 * 1024 * 1024;
// A frame's buffer grows as its bytes arrive; the header's length is not reserved up front.
const INITIAL_RESERVE: u64 = 16 * 1024;
const HOLD_FOR: std::time::Duration = std::time::Duration::from_secs(5);
pub(crate) const REVALIDATE_EVERY: std::time::Duration = std::time::Duration::from_secs(5);
const POLICY_VIOLATION: u16 = 1008;

const CONTINUATION: u8 = 0x0;
const TEXT: u8 = 0x1;
const BINARY: u8 = 0x2;
const CLOSE: u8 = 0x8;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Ended {
    Closed,
    Echoed,
    Withheld,
    Refused,
    Revoked,
    Violation(&'static str),
}

#[derive(Debug, PartialEq, Eq)]
struct Frame {
    fin: bool,
    rsv: u8,
    opcode: u8,
    mask: Option<[u8; 4]>,
    payload: Vec<u8>,
}

pub(crate) fn is_upgrade(request: &InjectedRequest) -> bool {
    request.method.eq_ignore_ascii_case("GET")
        && request
            .header("Upgrade")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket"))
        && request.header("Connection").is_some_and(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Frame>, Ended> {
    let mut head = [0u8; 2];
    match reader.read_exact(&mut head[..1]).await {
        Ok(_) => {}
        Err(_) => return Ok(None),
    }
    reader
        .read_exact(&mut head[1..])
        .await
        .map_err(|_| Ended::Violation("truncated frame"))?;
    let fin = head[0] & 0x80 != 0;
    let rsv = head[0] & 0x70;
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let length = match head[1] & 0x7f {
        126 => {
            let mut b = [0u8; 2];
            reader
                .read_exact(&mut b)
                .await
                .map_err(|_| Ended::Violation("truncated frame"))?;
            u64::from(u16::from_be_bytes(b))
        }
        127 => {
            let mut b = [0u8; 8];
            reader
                .read_exact(&mut b)
                .await
                .map_err(|_| Ended::Violation("truncated frame"))?;
            u64::from_be_bytes(b)
        }
        n => u64::from(n),
    };
    if length > MAX_MESSAGE as u64 {
        return Err(Ended::Violation("frame too large"));
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        reader
            .read_exact(&mut m)
            .await
            .map_err(|_| Ended::Violation("truncated frame"))?;
        Some(m)
    } else {
        None
    };
    let mut payload = Vec::new();
    read_payload(reader, length, &mut payload)
        .await
        .map_err(|_| Ended::Violation("truncated frame"))?;
    if let Some(m) = mask {
        apply_mask(&mut payload, m);
    }
    Ok(Some(Frame {
        fin,
        rsv,
        opcode,
        mask,
        payload,
    }))
}

async fn read_payload<R: AsyncRead + Unpin>(
    reader: &mut R,
    length: u64,
    payload: &mut Vec<u8>,
) -> std::io::Result<()> {
    payload.reserve(length.min(INITIAL_RESERVE) as usize);
    let read = reader.take(length).read_to_end(payload).await?;
    if read as u64 != length {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

fn apply_mask(payload: &mut [u8], mask: [u8; 4]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
}

fn encode_frame(fin: bool, opcode: u8, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(if fin { 0x80 } else { 0 } | opcode);
    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => out.push(mask_bit | n as u8),
        n if n <= usize::from(u16::MAX) => {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(m) => {
            out.extend_from_slice(&m);
            let start = out.len();
            out.extend_from_slice(payload);
            apply_mask(&mut out[start..], m);
        }
        None => out.extend_from_slice(payload),
    }
    out
}

fn is_control(opcode: u8) -> bool {
    opcode & 0x08 != 0
}

// Client to upstream. Text messages are reassembled so the protocol can write the credential
// into them; everything else is forwarded frame by frame.
async fn client_to_upstream<R, W>(
    mut client: R,
    mut upstream: W,
    injection: Option<(Arc<dyn Protocol>, Arc<Credential>)>,
    on_inject: &(dyn Fn() -> bool + Send + Sync),
) -> Ended
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut text: Option<([u8; 4], Vec<u8>)> = None;
    let mut in_binary = false;
    loop {
        let frame = match read_frame(&mut client).await {
            Ok(Some(f)) => f,
            Ok(None) => {
                let _ = upstream.shutdown().await;
                return Ended::Closed;
            }
            Err(e) => return e,
        };
        if frame.rsv != 0 {
            return Ended::Violation("reserved bits set");
        }
        let Some(mask) = frame.mask else {
            return Ended::Violation("unmasked client frame");
        };
        let out = if is_control(frame.opcode) {
            Some(encode_frame(
                frame.fin,
                frame.opcode,
                Some(mask),
                &frame.payload,
            ))
        } else {
            match (frame.opcode, text.as_mut(), in_binary) {
                (TEXT, None, false) => {
                    text = Some((mask, frame.payload));
                    None
                }
                (CONTINUATION, Some((_, buffer)), _) => {
                    if buffer.len() + frame.payload.len() > MAX_MESSAGE {
                        return Ended::Violation("message too large");
                    }
                    buffer.extend_from_slice(&frame.payload);
                    None
                }
                (BINARY, None, false) | (CONTINUATION, None, true) => {
                    in_binary = !frame.fin;
                    Some(encode_frame(
                        frame.fin,
                        frame.opcode,
                        Some(mask),
                        &frame.payload,
                    ))
                }
                _ => return Ended::Violation("unexpected opcode"),
            }
        };
        if !is_control(frame.opcode)
            && frame.fin
            && let Some((mask, mut message)) = text.take()
        {
            if let Some((protocol, credential)) = &injection {
                match protocol.inject_message(&mut message, credential) {
                    Ok(true) if !on_inject() => {
                        message.zeroize();
                        return Ended::Refused;
                    }
                    Ok(_) => {}
                    Err(_) => return Ended::Violation("message injection failed"),
                }
            }
            let mut encoded = encode_frame(true, TEXT, Some(mask), &message);
            message.zeroize();
            let written = upstream.write_all(&encoded).await;
            encoded.zeroize();
            if written.is_err() {
                return Ended::Closed;
            }
            continue;
        }
        if let Some(bytes) = out
            && upstream.write_all(&bytes).await.is_err()
        {
            return Ended::Closed;
        }
    }
}

// The client-visible stream must never contain an 8-byte window of the credential, or the whole
// credential when it is shorter. `visible` is the tail of what has been written, so a window
// that crosses the boundary is checked with the bytes about to be written.
fn exposes(visible: &[u8], bytes: &[u8], secret: &[u8]) -> bool {
    let width = secret.len().min(HOLD_PREFIX);
    if width == 0 {
        return false;
    }
    let is_part = |window: &[u8]| secret.windows(width).any(|part| part == window);
    if bytes.windows(width).any(&is_part) {
        return true;
    }
    for taken in 1..width.min(visible.len() + 1) {
        let end = width - taken;
        if end > bytes.len() {
            continue;
        }
        let mut window = Vec::with_capacity(width);
        window.extend_from_slice(&visible[visible.len() - taken..]);
        window.extend_from_slice(&bytes[..end]);
        if is_part(&window) {
            return true;
        }
    }
    false
}

fn remember(visible: &mut Vec<u8>, bytes: &[u8]) {
    let keep = HOLD_PREFIX - 1;
    let from_bytes = bytes.len().min(keep);
    let from_visible = keep - from_bytes;
    let start = visible.len().saturating_sub(from_visible);
    let mut next = Vec::with_capacity(keep);
    next.extend_from_slice(&visible[start..]);
    next.extend_from_slice(&bytes[bytes.len() - from_bytes..]);
    *visible = next;
}

// Upstream to client. A data message is assembled until its last fragment and checked before
// it is written; so is every control frame. Before every write, the bytes about to go out are
// checked together with the last 7 bytes already written: an 8-byte window of the credential
// (the whole credential when it is shorter) ends the session with nothing written. The data tail
// holds the trailing bytes of the data messages in order and a control payload never enters it,
// so a control frame cannot release a held message. While the tail ends with at least `hold_at`
// bytes of the credential's start, whole data messages are held: a later data message either
// completes the credential (the session ends, nothing held is written) or breaks the match, and
// a held message is written only if it exposes no 8-byte window. A held message is never written
// if the upstream ends or is quiet for `hold_for`. An upstream Close ends the session after it is
// written: no later frame is read, held messages are dropped and the session reports `Withheld`.
// `mid_frame` is set while a frame is partly written.
async fn upstream_to_client<R, W>(
    mut upstream: R,
    mut client: W,
    credential: Option<Arc<Credential>>,
    hold_for: std::time::Duration,
    mid_frame: &AtomicBool,
) -> Ended
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let secret: &[u8] = credential.as_deref().map_or(&[], Credential::expose);
    let carries =
        |bytes: &[u8]| !secret.is_empty() && bytes.windows(secret.len()).any(|w| w == secret);
    let keep = secret.len().saturating_sub(1);
    let hold_at = HOLD_PREFIX.min(secret.len().div_ceil(2)).max(1);
    let mut tail: Vec<u8> = Vec::new();
    let mut visible: Vec<u8> = Vec::new();
    let mut message: Option<(u8, Vec<u8>)> = None;
    let mut streamed: u64 = 0;
    let mut held: std::collections::VecDeque<(u64, u8, Vec<u8>)> =
        std::collections::VecDeque::new();
    loop {
        let read = if held.is_empty() {
            read_frame(&mut upstream).await
        } else {
            match tokio::time::timeout(hold_for, read_frame(&mut upstream)).await {
                Ok(read) => read,
                Err(_) => return Ended::Withheld,
            }
        };
        let frame = match read {
            Ok(Some(f)) => f,
            Ok(None) if !held.is_empty() => return Ended::Withheld,
            Ok(None) => {
                let _ = client.shutdown().await;
                return Ended::Closed;
            }
            Err(e) => return e,
        };
        if frame.mask.is_some() {
            return Ended::Violation("masked server frame");
        }
        if frame.rsv != 0 {
            return Ended::Violation("reserved bits set");
        }
        let (control, opcode, payload) = if is_control(frame.opcode) {
            (Some(frame.fin), frame.opcode, frame.payload)
        } else {
            match (frame.opcode, message.as_mut()) {
                (TEXT | BINARY, None) => message = Some((frame.opcode, frame.payload)),
                (CONTINUATION, Some((_, buffer))) => {
                    if buffer.len() + frame.payload.len() > MAX_MESSAGE {
                        return Ended::Violation("message too large");
                    }
                    buffer.extend_from_slice(&frame.payload);
                }
                _ => return Ended::Violation("unexpected opcode"),
            }
            if !frame.fin {
                continue;
            }
            let Some((opcode, payload)) = message.take() else {
                return Ended::Violation("unexpected opcode");
            };
            (None, opcode, payload)
        };
        if let Some(fin) = control {
            if exposes(&visible, &payload, secret) {
                return Ended::Echoed;
            }
            let encoded = encode_frame(fin, opcode, None, &payload);
            mid_frame.store(true, Ordering::SeqCst);
            if client.write_all(&encoded).await.is_err() {
                return Ended::Closed;
            }
            mid_frame.store(false, Ordering::SeqCst);
            remember(&mut visible, &payload);
            if opcode == CLOSE {
                return if held.is_empty() {
                    Ended::Closed
                } else {
                    Ended::Withheld
                };
            }
            continue;
        }
        let mut window = std::mem::take(&mut tail);
        window.extend_from_slice(&payload);
        if carries(&window) {
            return Ended::Echoed;
        }
        let started = started_prefix(&window, secret);
        streamed += payload.len() as u64;
        let release_to = if started >= hold_at {
            streamed - started as u64
        } else {
            streamed
        };
        tail = window[window.len().saturating_sub(keep)..].to_vec();
        held.push_back((streamed, opcode, payload));
        while held.front().is_some_and(|(end, _, _)| *end <= release_to) {
            let Some((_, opcode, payload)) = held.pop_front() else {
                break;
            };
            if exposes(&visible, &payload, secret) {
                return Ended::Echoed;
            }
            let encoded = encode_frame(true, opcode, None, &payload);
            mid_frame.store(true, Ordering::SeqCst);
            if client.write_all(&encoded).await.is_err() {
                return Ended::Closed;
            }
            mid_frame.store(false, Ordering::SeqCst);
            remember(&mut visible, &payload);
        }
    }
}

pub(crate) async fn relay<C, U>(
    client: C,
    upstream: U,
    injection: Option<(Arc<dyn Protocol>, Credential)>,
    on_inject: &(dyn Fn() -> bool + Send + Sync),
    revalidate: &(dyn Fn() -> bool + Send + Sync),
) -> Ended
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let injection = injection.map(|(p, c)| (p, Arc::new(c)));
    let guard = injection.as_ref().map(|(_, c)| c.clone());
    let injecting = injection.is_some();
    let (client_r, mut client_w) = tokio::io::split(client);
    let (upstream_r, upstream_w) = tokio::io::split(upstream);
    let mid_frame = AtomicBool::new(false);
    let refused = async {
        if !injecting {
            return std::future::pending().await;
        }
        let mut every = tokio::time::interval(REVALIDATE_EVERY);
        loop {
            every.tick().await;
            if !revalidate() {
                return;
            }
        }
    };
    let ended = tokio::select! {
        ended = client_to_upstream(client_r, upstream_w, injection, on_inject) => ended,
        ended = upstream_to_client(upstream_r, &mut client_w, guard, HOLD_FOR, &mid_frame) => ended,
        () = refused => Ended::Revoked,
    };
    if ended == Ended::Revoked && !mid_frame.load(Ordering::SeqCst) {
        let close = encode_frame(true, CLOSE, None, &POLICY_VIOLATION.to_be_bytes());
        let _ = tokio::time::timeout(HOLD_FOR, async {
            let _ = client_w.write_all(&close).await;
            let _ = client_w.shutdown().await;
        })
        .await;
    }
    ended
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[tokio::test]
    async fn a_frame_round_trips_for_every_length_class() {
        for len in [0usize, 125, 126, 65535, 65536] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            for mask in [None, Some([1, 2, 3, 4])] {
                let bytes = encode_frame(true, BINARY, mask, &payload);
                let frame = read_frame(&mut bytes.as_slice()).await.unwrap().unwrap();
                assert_eq!(frame.payload, payload, "len {len}");
                assert_eq!(frame.mask, mask);
                assert!(frame.fin);
            }
        }
    }

    #[tokio::test]
    async fn an_oversized_length_is_refused_before_allocation() {
        let mut bytes = vec![0x82, 127];
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(
            read_frame(&mut bytes.as_slice()).await,
            Err(Ended::Violation("frame too large"))
        );
    }

    #[tokio::test]
    async fn a_large_declared_length_is_not_reserved_before_its_bytes_arrive() {
        let mut payload = Vec::new();
        let sent = [b'a'; 10];
        let read = read_payload(&mut sent.as_slice(), MAX_MESSAGE as u64, &mut payload).await;
        assert!(read.is_err(), "ten bytes cannot fill the declared length");
        assert!(
            payload.capacity() <= 64 * 1024,
            "reserved {} bytes for 10 received",
            payload.capacity()
        );

        let mut whole = Vec::new();
        let body: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        read_payload(&mut body.as_slice(), body.len() as u64, &mut whole)
            .await
            .unwrap();
        assert_eq!(whole, body);
    }

    const SECRET: &[u8] = b"sk_test_ws_guard_value_7c2d";

    fn secret() -> Arc<Credential> {
        Arc::new(Credential::from_bytes(SECRET.to_vec()).unwrap())
    }

    async fn from_upstream(frames: &[Vec<u8>]) -> (Ended, Vec<u8>) {
        from_upstream_with(secret(), frames).await
    }

    async fn from_upstream_with(
        credential: Arc<Credential>,
        frames: &[Vec<u8>],
    ) -> (Ended, Vec<u8>) {
        let input = frames.concat();
        let (client, mut seen) = tokio::io::duplex(1 << 20);
        let ended = upstream_to_client(
            input.as_slice(),
            client,
            Some(credential),
            HOLD_FOR,
            &AtomicBool::new(false),
        )
        .await;
        let mut out = Vec::new();
        seen.read_to_end(&mut out).await.unwrap();
        (ended, out)
    }

    #[tokio::test]
    async fn a_control_frame_that_carries_the_credential_never_reaches_the_client() {
        let mut reason = b"\x03\xe8invalid apiKey ".to_vec();
        reason.extend_from_slice(SECRET);
        let (ended, out) = from_upstream(&[encode_frame(true, 0x8, None, &reason)]).await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out.is_empty(), "unexpected client output");
    }

    #[tokio::test]
    async fn a_credential_split_between_a_ping_and_a_message_is_caught() {
        let (head, rest) = SECRET.split_at(HOLD_PREFIX + 2);
        let (ended, out) = from_upstream(&[
            text(&[b"{\"apiKey\":\"", head]),
            encode_frame(true, 0x9, None, rest),
        ])
        .await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out.is_empty(), "unexpected client output");

        let (ended, out) = from_upstream(&[
            encode_frame(true, 0x9, None, &[b"k=", head].concat()),
            text(&[rest, b"\"}"]),
        ])
        .await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out.is_empty(), "unexpected client output");
    }

    #[tokio::test]
    async fn a_close_reason_that_ends_in_a_credential_prefix_never_reaches_the_client() {
        let mut reason = b"\x03\xe8invalid apiKey ".to_vec();
        reason.extend_from_slice(&SECRET[..SECRET.len() - 3]);
        let (ended, out) = from_upstream(&[encode_frame(true, CLOSE, None, &reason)]).await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out.is_empty(), "unexpected client output");

        let mut short = b"\x03\xe8bye ".to_vec();
        short.extend_from_slice(&SECRET[..HOLD_PREFIX - 1]);
        let close = encode_frame(true, CLOSE, None, &short);
        let (ended, out) = from_upstream(std::slice::from_ref(&close)).await;
        assert_eq!(ended, Ended::Closed);
        assert!(out == close, "the under-prefix close is relayed");
    }

    #[tokio::test]
    async fn a_ping_between_two_halves_of_the_credential_is_caught() {
        let (head, rest) = SECRET.split_at(HOLD_PREFIX);
        let ping = encode_frame(true, 0x9, None, b"p");
        let (ended, out) = from_upstream(&[
            text(&[b"{\"apiKey\":\"", head]),
            ping.clone(),
            text(&[rest, b"\"}"]),
        ])
        .await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out == ping, "only the harmless ping goes out");
    }

    #[tokio::test]
    async fn a_breaking_close_does_not_release_a_held_prefix() {
        let mut prefix = b"{\"apiKey\":\"".to_vec();
        prefix.extend_from_slice(&SECRET[..SECRET.len() - 2]);
        let close = encode_frame(true, CLOSE, None, &1000u16.to_be_bytes());
        let (ended, out) = from_upstream(&[text(&[&prefix]), close.clone()]).await;
        assert_eq!(ended, Ended::Withheld);
        assert!(out == close, "the held text must stay held");
    }

    #[tokio::test]
    async fn a_close_reason_carrying_a_middle_fragment_is_caught() {
        let mut reason = 1000u16.to_be_bytes().to_vec();
        reason.extend_from_slice(&SECRET[8..20]);
        let (ended, out) = from_upstream(&[
            text(&[&SECRET[..8]]),
            encode_frame(true, CLOSE, None, &reason),
        ])
        .await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out.is_empty(), "unexpected client output");
    }

    #[tokio::test]
    async fn no_data_frame_follows_an_upstream_close() {
        let close = encode_frame(true, CLOSE, None, &1000u16.to_be_bytes());
        let (ended, out) =
            from_upstream(&[text(&[&SECRET[..8]]), close.clone(), text(&[&SECRET[8..]])]).await;
        assert_eq!(ended, Ended::Withheld);
        assert!(out == close, "held and post-Close data are dropped");
    }

    #[tokio::test]
    async fn a_close_reason_that_carries_the_rest_of_a_held_start_ends_the_session() {
        let (head, rest) = SECRET.split_at(HOLD_PREFIX);
        let mut reason = 1000u16.to_be_bytes().to_vec();
        reason.extend_from_slice(rest);
        let (ended, out) = from_upstream(&[
            text(&[b"{\"apiKey\":\"", head]),
            encode_frame(true, CLOSE, None, &reason),
        ])
        .await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out.is_empty(), "unexpected client output");
    }

    #[tokio::test]
    async fn a_ping_between_two_harmless_messages_is_relayed() {
        let first = text(&[b"hello"]);
        let ping = encode_frame(true, 0x9, None, b"p");
        let second = text(&[b"world"]);
        let (ended, out) = from_upstream(&[first.clone(), ping.clone(), second.clone()]).await;
        assert_eq!(ended, Ended::Closed);
        assert!(
            out == [first, ping, second].concat(),
            "the ping is relayed in order"
        );
    }

    #[tokio::test]
    async fn a_credential_split_between_a_control_payload_and_a_message_is_caught() {
        let (head, rest) = SECRET.split_at(4);
        let ping = encode_frame(true, 0x9, None, &[b"k=", head].concat());
        let (ended, out) = from_upstream(&[ping.clone(), text(&[rest, b"\"}"])]).await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out == ping, "only the under-prefix ping goes out");
    }

    #[tokio::test]
    async fn a_chain_of_short_control_payloads_is_caught_at_the_second() {
        let first = encode_frame(true, 0x9, None, &SECRET[..7]);
        let second = encode_frame(true, 0x9, None, &SECRET[7..14]);
        let (ended, out) = from_upstream(&[first.clone(), second]).await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out == first, "only seven bytes of the start go out");
    }

    #[tokio::test]
    async fn a_credential_split_across_fragments_never_reaches_the_client() {
        let (head, last) = SECRET.split_at(SECRET.len() - 1);
        let mut first = b"{\"apiKey\":\"".to_vec();
        first.extend_from_slice(head);
        let mut second = last.to_vec();
        second.extend_from_slice(b"\"}");
        let (ended, out) = from_upstream(&[
            encode_frame(false, TEXT, None, &first),
            encode_frame(true, CONTINUATION, None, &second),
        ])
        .await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out.is_empty(), "no fragment may go out before the check");
    }

    fn text(parts: &[&[u8]]) -> Vec<u8> {
        encode_frame(true, TEXT, None, &parts.concat())
    }

    #[tokio::test]
    async fn a_credential_split_across_messages_never_reaches_the_client() {
        let (head, rest) = SECRET.split_at(HOLD_PREFIX);
        let (ended, out) =
            from_upstream(&[text(&[b"{\"apiKey\":\"", head]), text(&[rest, b"\"}"])]).await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out.is_empty(), "the first half went out");
    }

    #[tokio::test]
    async fn a_credential_split_over_many_messages_leaks_less_than_the_hold_prefix() {
        let short = HOLD_PREFIX - 1;
        let pieces: Vec<Vec<u8>> = std::iter::once(text(&[b"k=", &SECRET[..short]]))
            .chain(
                SECRET[short..]
                    .chunks(3)
                    .map(|chunk| encode_frame(true, TEXT, None, chunk)),
            )
            .collect();
        let (ended, out) = from_upstream(&pieces).await;
        assert_eq!(ended, Ended::Echoed);
        assert!(
            out == pieces[0],
            "only the first message, under the prefix, goes out"
        );
    }

    #[tokio::test]
    async fn a_held_prefix_is_never_released_when_it_would_expose_the_credential() {
        let held = text(&[b"x", &SECRET[..HOLD_PREFIX + 2]]);
        let breaking = text(&[b"not the rest"]);
        let (ended, out) = from_upstream(&[held, breaking]).await;
        assert_eq!(ended, Ended::Echoed);
        assert!(out.is_empty(), "a held prefix must never be released");
    }

    #[tokio::test]
    async fn a_held_message_that_exposes_no_8_byte_window_is_released() {
        let short = b"abcd-efghi";
        let credential = Arc::new(Credential::from_bytes(short.to_vec()).unwrap());
        let held = text(&[b"x", &short[..6]]);
        let breaking = text(&[b"not the rest"]);
        let (ended, out) = from_upstream_with(credential, &[held.clone(), breaking.clone()]).await;
        assert_eq!(ended, Ended::Closed);
        assert!(
            out == [held, breaking].concat(),
            "the benign release writes"
        );
    }

    #[tokio::test]
    async fn a_held_message_is_withheld_when_the_upstream_ends_or_goes_quiet() {
        let held = text(&[b"x", &SECRET[..HOLD_PREFIX]]);
        let (ended, out) = from_upstream(std::slice::from_ref(&held)).await;
        assert_eq!(ended, Ended::Withheld);
        assert!(out.is_empty(), "unexpected client output");

        let (mut upstream, upstream_r) = tokio::io::duplex(1 << 16);
        upstream.write_all(&held).await.unwrap();
        let (client, mut seen) = tokio::io::duplex(1 << 16);
        let ended = upstream_to_client(
            upstream_r,
            client,
            Some(secret()),
            std::time::Duration::from_millis(50),
            &AtomicBool::new(false),
        )
        .await;
        assert_eq!(ended, Ended::Withheld);
        let mut out = Vec::new();
        seen.read_to_end(&mut out).await.unwrap();
        assert!(out.is_empty(), "unexpected client output");
        drop(upstream);
    }

    #[tokio::test]
    async fn a_fragmented_message_is_delivered_whole_and_a_ping_goes_first() {
        let (ended, out) = from_upstream(&[
            encode_frame(false, TEXT, None, b"hel"),
            encode_frame(true, 0x9, None, b"p"),
            encode_frame(true, CONTINUATION, None, b"lo"),
        ])
        .await;
        assert_eq!(ended, Ended::Closed);
        let mut out = out.as_slice();
        let ping = read_frame(&mut out).await.unwrap().unwrap();
        assert_eq!((ping.opcode, ping.payload.as_slice()), (0x9, &b"p"[..]));
        let text = read_frame(&mut out).await.unwrap().unwrap();
        assert!(text.fin);
        assert_eq!(
            (text.opcode, text.payload.as_slice()),
            (TEXT, &b"hello"[..])
        );
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn an_upstream_message_out_of_order_or_over_the_limit_ends_the_session() {
        let (ended, _) = from_upstream(&[encode_frame(true, CONTINUATION, None, b"x")]).await;
        assert_eq!(ended, Ended::Violation("unexpected opcode"));
        let (ended, _) = from_upstream(&[
            encode_frame(false, TEXT, None, b"a"),
            encode_frame(true, BINARY, None, b"b"),
        ])
        .await;
        assert_eq!(ended, Ended::Violation("unexpected opcode"));
        let half = vec![b'a'; MAX_MESSAGE / 2 + 1];
        let (ended, out) = from_upstream(&[
            encode_frame(false, BINARY, None, &half),
            encode_frame(true, CONTINUATION, None, &half),
        ])
        .await;
        assert_eq!(ended, Ended::Violation("message too large"));
        assert!(out.is_empty());
    }

    struct AppendCredential;

    impl Protocol for AppendCredential {
        fn matches(&self, _: &zs_protocol::Destination) -> bool {
            true
        }
        fn authorize(&self, _: &zs_protocol::Context) -> Result<(), zs_protocol::Denied> {
            Ok(())
        }
        fn inject(
            &self,
            _: &mut InjectedRequest,
            _: &Credential,
        ) -> Result<(), zs_protocol::Denied> {
            Ok(())
        }
        fn inject_message(
            &self,
            message: &mut Vec<u8>,
            credential: &Credential,
        ) -> Result<bool, zs_protocol::Denied> {
            message.extend_from_slice(credential.expose());
            Ok(true)
        }
    }

    #[tokio::test]
    async fn a_refused_injection_ends_the_session_before_the_message_is_written() {
        let input = encode_frame(true, TEXT, Some([1, 2, 3, 4]), b"{}");
        let (upstream, mut seen) = tokio::io::duplex(1 << 16);
        let injection: Option<(Arc<dyn Protocol>, Arc<Credential>)> =
            Some((Arc::new(AppendCredential), secret()));
        let ended = client_to_upstream(input.as_slice(), upstream, injection, &|| false).await;
        assert_eq!(ended, Ended::Refused);
        let mut out = Vec::new();
        seen.read_to_end(&mut out).await.unwrap();
        assert!(out.is_empty(), "unexpected client output");
    }

    fn injection() -> Option<(Arc<dyn Protocol>, Credential)> {
        Some((
            Arc::new(AppendCredential),
            Credential::from_bytes(SECRET.to_vec()).unwrap(),
        ))
    }

    fn allows_once() -> impl Fn() -> bool + Send + Sync {
        let checks = std::sync::atomic::AtomicUsize::new(0);
        move || checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
    }

    #[tokio::test]
    async fn a_session_ends_when_revalidation_refuses() {
        tokio::time::pause();
        let (client, mut workload) = tokio::io::duplex(1 << 16);
        let (upstream, _server) = tokio::io::duplex(1 << 16);
        let started = tokio::time::Instant::now();
        let ended = relay(client, upstream, injection(), &|| true, &allows_once()).await;
        assert_eq!(ended, Ended::Revoked);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= REVALIDATE_EVERY && elapsed < REVALIDATE_EVERY * 2,
            "{elapsed:?}"
        );
        let close = read_frame(&mut workload).await.unwrap().unwrap();
        assert_eq!(
            (close.opcode, close.payload.as_slice()),
            (0x8, &1008u16.to_be_bytes()[..])
        );
        assert!(read_frame(&mut workload).await.unwrap().is_none());

        let (client, _workload) = tokio::io::duplex(1 << 16);
        let (upstream, _server) = tokio::io::duplex(1 << 16);
        let uninjected = tokio::time::timeout(
            REVALIDATE_EVERY * 3,
            relay(client, upstream, None, &|| true, &|| false),
        )
        .await;
        assert!(
            uninjected.is_err(),
            "a session without a credential is not revalidated"
        );
    }

    #[tokio::test]
    async fn a_refusal_during_a_half_written_frame_adds_no_close_frame() {
        tokio::time::pause();
        let (client, mut workload) = tokio::io::duplex(64);
        let (upstream, mut server) = tokio::io::duplex(1 << 16);
        let message = encode_frame(true, BINARY, None, &[b'm'; 1000]);
        server.write_all(&message).await.unwrap();
        let relayed = tokio::spawn(async move {
            let revalidate = allows_once();
            relay(client, upstream, injection(), &|| true, &revalidate).await
        });
        tokio::time::sleep(REVALIDATE_EVERY + std::time::Duration::from_millis(1)).await;
        let mut out = Vec::new();
        workload.read_to_end(&mut out).await.unwrap();
        assert_eq!(relayed.await.unwrap(), Ended::Revoked);
        assert!(
            !out.is_empty() && out.len() < message.len(),
            "{}",
            out.len()
        );
        assert_eq!(out, message[..out.len()]);
    }

    #[test]
    fn an_upgrade_needs_get_upgrade_and_connection() {
        let mut request = InjectedRequest {
            method: "GET".into(),
            path: "/v1".into(),
            headers: vec![
                ("Upgrade".into(), "websocket".into()),
                ("Connection".into(), "keep-alive, Upgrade".into()),
            ],
            body: Vec::new(),
        };
        assert!(is_upgrade(&request));
        request.method = "POST".into();
        assert!(!is_upgrade(&request));
        request.method = "GET".into();
        request.remove_header("Connection");
        assert!(!is_upgrade(&request));
    }
}
