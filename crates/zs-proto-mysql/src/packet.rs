use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
pub const CLIENT_FOUND_ROWS: u32 = 0x0000_0002;
pub const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
pub const CLIENT_COMPRESS: u32 = 0x0000_0020;
pub const CLIENT_LOCAL_FILES: u32 = 0x0000_0080;
pub const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
pub const CLIENT_SSL: u32 = 0x0000_0800;
pub const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
pub const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
pub const CLIENT_MULTI_STATEMENTS: u32 = 0x0001_0000;
pub const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
pub const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
pub const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
pub const CLIENT_SESSION_TRACK: u32 = 0x0080_0000;
pub const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;
pub const CLIENT_ZSTD_COMPRESSION_ALGORITHM: u32 = 0x0400_0000;
pub const CLIENT_MULTI_FACTOR_AUTHENTICATION: u32 = 0x1000_0000;

pub const REQUIRED_SERVER_CAPABILITIES: u32 =
    CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
pub const STRIPPED_CAPABILITIES: u32 = CLIENT_SSL
    | CLIENT_COMPRESS
    | CLIENT_LOCAL_FILES
    | CLIENT_ZSTD_COMPRESSION_ALGORITHM
    | CLIENT_MULTI_FACTOR_AUTHENTICATION;

pub const NATIVE_PASSWORD: &[u8] = b"mysql_native_password";
pub const CACHING_SHA2_PASSWORD: &[u8] = b"caching_sha2_password";
pub const SHA256_PASSWORD: &[u8] = b"sha256_password";
pub const CLEAR_PASSWORD: &[u8] = b"mysql_clear_password";

pub const COM_QUIT: u8 = 0x01;
pub const COM_QUERY: u8 = 0x03;
pub const COM_CHANGE_USER: u8 = 0x11;

pub const OK_HEADER: u8 = 0x00;
pub const MORE_DATA_HEADER: u8 = 0x01;
pub const SWITCH_HEADER: u8 = 0xfe;
pub const ERR_HEADER: u8 = 0xff;

pub const MAX_PAYLOAD: usize = 0x00ff_ffff;
pub const HANDSHAKE_LIMIT: usize = 1 << 20;
pub const SCRAMBLE_LEN: usize = 20;
const SSL_REQUEST_LEN: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("mysql packet is truncated")]
    Truncated,
    #[error("mysql packet is malformed: {0}")]
    Malformed(&'static str),
    #[error("mysql protocol version {0} is not supported")]
    UnsupportedVersion(u8),
}

pub struct Packet {
    pub seq: u8,
    pub payload: Vec<u8>,
}

pub fn frame(seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 8);
    let mut seq = seq;
    let mut rest = payload;
    loop {
        let len = rest.len().min(MAX_PAYLOAD);
        out.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
        out.push(seq);
        out.extend_from_slice(&rest[..len]);
        rest = &rest[len..];
        seq = seq.wrapping_add(1);
        if len < MAX_PAYLOAD {
            return out;
        }
    }
}

pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> std::io::Result<Packet> {
    let mut payload = Vec::new();
    loop {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header).await?;
        let len =
            usize::from(header[0]) | usize::from(header[1]) << 8 | usize::from(header[2]) << 16;
        if payload.len() + len > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mysql packet exceeds the limit",
            ));
        }
        let start = payload.len();
        payload.resize(start + len, 0);
        reader.read_exact(&mut payload[start..]).await?;
        if len < MAX_PAYLOAD {
            return Ok(Packet {
                seq: header[3],
                payload,
            });
        }
    }
}

pub async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    seq: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let wire = zeroize::Zeroizing::new(frame(seq, payload));
    writer.write_all(&wire).await?;
    writer.flush().await
}

pub fn put_lenenc_int(out: &mut Vec<u8>, value: u64) {
    if value < 0xfb {
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(0xfc);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0x00ff_ffff {
        out.push(0xfd);
        out.extend_from_slice(&(value as u32).to_le_bytes()[..3]);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

pub fn put_lenenc_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_lenenc_int(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.at
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.at).copied()
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], PacketError> {
        let end = self.at.checked_add(n).ok_or(PacketError::Truncated)?;
        let slice = self.input.get(self.at..end).ok_or(PacketError::Truncated)?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, PacketError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PacketError> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, PacketError> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn nul_terminated(&mut self) -> Result<&'a [u8], PacketError> {
        let rest = &self.input[self.at..];
        let end = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or(PacketError::Malformed("missing NUL terminator"))?;
        self.at += end + 1;
        Ok(&rest[..end])
    }

    fn nul_terminated_or_rest(&mut self) -> &'a [u8] {
        let rest = &self.input[self.at..];
        match rest.iter().position(|b| *b == 0) {
            Some(end) => {
                self.at += end + 1;
                &rest[..end]
            }
            None => {
                self.at = self.input.len();
                rest
            }
        }
    }

    fn rest(&mut self) -> &'a [u8] {
        let rest = &self.input[self.at..];
        self.at = self.input.len();
        rest
    }

    fn lenenc_int(&mut self) -> Result<u64, PacketError> {
        match self.u8()? {
            first @ 0..=0xfa => Ok(u64::from(first)),
            0xfc => Ok(u64::from(self.u16()?)),
            0xfd => {
                let b = self.bytes(3)?;
                Ok(u64::from(u32::from_le_bytes([b[0], b[1], b[2], 0])))
            }
            0xfe => {
                let b = self.bytes(8)?;
                Ok(u64::from_le_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]))
            }
            _ => Err(PacketError::Malformed("invalid length-encoded integer")),
        }
    }

    fn lenenc_bytes(&mut self) -> Result<&'a [u8], PacketError> {
        let len = usize::try_from(self.lenenc_int()?)
            .map_err(|_| PacketError::Malformed("length does not fit"))?;
        self.bytes(len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Greeting {
    pub server_version: Vec<u8>,
    pub connection_id: u32,
    pub scramble: Vec<u8>,
    pub capabilities: u32,
    pub charset: u8,
    pub status: u16,
    pub plugin: Vec<u8>,
}

impl Greeting {
    pub fn parse(payload: &[u8]) -> Result<Self, PacketError> {
        let mut r = Reader::new(payload);
        let version = r.u8()?;
        if version != 10 {
            return Err(PacketError::UnsupportedVersion(version));
        }
        let server_version = r.nul_terminated()?.to_vec();
        let connection_id = r.u32()?;
        let mut scramble = r.bytes(8)?.to_vec();
        r.u8()?;
        let low = u32::from(r.u16()?);
        if r.remaining() == 0 {
            return Ok(Self {
                server_version,
                connection_id,
                scramble,
                capabilities: low,
                charset: 0,
                status: 0,
                plugin: Vec::new(),
            });
        }
        let charset = r.u8()?;
        let status = r.u16()?;
        let capabilities = low | u32::from(r.u16()?) << 16;
        let data_len = usize::from(r.u8()?);
        r.bytes(10)?;
        if capabilities & CLIENT_SECURE_CONNECTION != 0 {
            let part2 = r.bytes(data_len.saturating_sub(8).max(13))?;
            scramble.extend_from_slice(part2.strip_suffix(&[0u8]).unwrap_or(part2));
        }
        let plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
            r.nul_terminated_or_rest().to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            server_version,
            connection_id,
            scramble,
            capabilities,
            charset,
            status,
            plugin,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![10];
        out.extend_from_slice(&self.server_version);
        out.push(0);
        out.extend_from_slice(&self.connection_id.to_le_bytes());
        let (part1, part2) = self.scramble.split_at(self.scramble.len().min(8));
        out.extend_from_slice(part1);
        out.extend(std::iter::repeat_n(0u8, 8 - part1.len()));
        out.push(0);
        out.extend_from_slice(&(self.capabilities as u16).to_le_bytes());
        out.push(self.charset);
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&((self.capabilities >> 16) as u16).to_le_bytes());
        if self.capabilities & CLIENT_PLUGIN_AUTH != 0 {
            out.push((self.scramble.len() + 1) as u8);
        } else {
            out.push(0);
        }
        out.extend_from_slice(&[0u8; 10]);
        if self.capabilities & CLIENT_SECURE_CONNECTION != 0 {
            out.extend_from_slice(part2);
            out.extend(std::iter::repeat_n(
                0u8,
                13usize.saturating_sub(part2.len()),
            ));
        }
        if self.capabilities & CLIENT_PLUGIN_AUTH != 0 {
            out.extend_from_slice(&self.plugin);
            out.push(0);
        }
        out
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub capabilities: u32,
    pub max_packet: u32,
    pub charset: u8,
    pub user: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub database: Option<Vec<u8>>,
    pub plugin: Option<Vec<u8>>,
    pub attributes: Option<Vec<u8>>,
}

impl HandshakeResponse {
    pub fn parse(payload: &[u8]) -> Result<Self, PacketError> {
        let mut r = Reader::new(payload);
        let capabilities = r.u32()?;
        if capabilities & CLIENT_PROTOCOL_41 == 0 {
            return Err(PacketError::Malformed("client is not protocol 4.1"));
        }
        let max_packet = r.u32()?;
        let charset = r.u8()?;
        r.bytes(23)?;
        let user = r.nul_terminated()?.to_vec();
        let auth_data = if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            r.lenenc_bytes()?
        } else if capabilities & CLIENT_SECURE_CONNECTION != 0 {
            let len = usize::from(r.u8()?);
            r.bytes(len)?
        } else {
            r.nul_terminated()?
        }
        .to_vec();
        let database = (capabilities & CLIENT_CONNECT_WITH_DB != 0 && r.remaining() > 0)
            .then(|| r.nul_terminated_or_rest().to_vec());
        let plugin = (capabilities & CLIENT_PLUGIN_AUTH != 0 && r.remaining() > 0)
            .then(|| r.nul_terminated_or_rest().to_vec());
        let attributes = if capabilities & CLIENT_CONNECT_ATTRS != 0 && r.remaining() > 0 {
            Some(r.lenenc_bytes()?.to_vec())
        } else {
            None
        };
        Ok(Self {
            capabilities,
            max_packet,
            charset,
            user,
            auth_data,
            database,
            plugin,
            attributes,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.capabilities.to_le_bytes());
        out.extend_from_slice(&self.max_packet.to_le_bytes());
        out.push(self.charset);
        out.extend_from_slice(&[0u8; 23]);
        out.extend_from_slice(&self.user);
        out.push(0);
        if self.capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            put_lenenc_bytes(&mut out, &self.auth_data);
        } else if self.capabilities & CLIENT_SECURE_CONNECTION != 0 {
            out.push(self.auth_data.len() as u8);
            out.extend_from_slice(&self.auth_data);
        } else {
            out.extend_from_slice(&self.auth_data);
            out.push(0);
        }
        if self.capabilities & CLIENT_CONNECT_WITH_DB != 0 {
            out.extend_from_slice(self.database.as_deref().unwrap_or_default());
            out.push(0);
        }
        if self.capabilities & CLIENT_PLUGIN_AUTH != 0 {
            out.extend_from_slice(self.plugin.as_deref().unwrap_or_default());
            out.push(0);
        }
        if self.capabilities & CLIENT_CONNECT_ATTRS != 0 {
            put_lenenc_bytes(&mut out, self.attributes.as_deref().unwrap_or_default());
        }
        out
    }
}

pub fn ssl_request(capabilities: u32, max_packet: u32, charset: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(SSL_REQUEST_LEN);
    out.extend_from_slice(&(capabilities | CLIENT_SSL).to_le_bytes());
    out.extend_from_slice(&max_packet.to_le_bytes());
    out.push(charset);
    out.extend_from_slice(&[0u8; 23]);
    out
}

pub fn client_capabilities(payload: &[u8]) -> Option<u32> {
    payload.first_chunk::<4>().map(|b| u32::from_le_bytes(*b))
}

pub fn is_ssl_request(payload: &[u8]) -> bool {
    payload.len() == SSL_REQUEST_LEN
        && client_capabilities(payload).is_some_and(|c| c & CLIENT_SSL != 0)
}

pub fn err_packet(code: u16, sqlstate: &str, message: &str) -> Vec<u8> {
    let mut out = vec![ERR_HEADER];
    out.extend_from_slice(&code.to_le_bytes());
    out.push(b'#');
    out.extend_from_slice(sqlstate.as_bytes());
    out.extend_from_slice(message.as_bytes());
    out
}

pub fn ok_packet(info: &[u8]) -> Vec<u8> {
    let mut out = vec![OK_HEADER, 0, 0, 0x02, 0x00, 0, 0];
    out.extend_from_slice(info);
    out
}

pub struct ServerError {
    pub code: u16,
    pub sqlstate: Option<String>,
    pub message: String,
}

impl ServerError {
    pub fn parse(payload: &[u8]) -> Result<Self, PacketError> {
        let mut r = Reader::new(payload);
        if r.u8()? != ERR_HEADER {
            return Err(PacketError::Malformed("not an ERR packet"));
        }
        let code = r.u16()?;
        let sqlstate = if r.peek() == Some(b'#') {
            r.u8()?;
            Some(String::from_utf8_lossy(r.bytes(5)?).into_owned())
        } else {
            None
        };
        let message = String::from_utf8_lossy(r.rest()).into_owned();
        Ok(Self {
            code,
            sqlstate,
            message,
        })
    }
}

pub struct AuthSwitch {
    pub plugin: Vec<u8>,
    pub data: Vec<u8>,
}

impl AuthSwitch {
    pub fn parse(payload: &[u8]) -> Result<Self, PacketError> {
        let mut r = Reader::new(payload);
        if r.u8()? != SWITCH_HEADER {
            return Err(PacketError::Malformed("not an auth switch request"));
        }
        let plugin = r.nul_terminated_or_rest().to_vec();
        let data = r.rest();
        Ok(Self {
            plugin,
            data: data.strip_suffix(&[0u8]).unwrap_or(data).to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![SWITCH_HEADER];
        out.extend_from_slice(&self.plugin);
        out.push(0);
        out.extend_from_slice(&self.data);
        out.push(0);
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn mysql8_greeting() -> Vec<u8> {
        let mut p = vec![10];
        p.extend_from_slice(b"8.0.36\0");
        p.extend_from_slice(&13u32.to_le_bytes());
        p.extend_from_slice(b"abcdefgh");
        p.push(0);
        p.extend_from_slice(&[0xff, 0xff]);
        p.push(0xff);
        p.extend_from_slice(&[0x02, 0x00]);
        p.extend_from_slice(&[0xff, 0xdf]);
        p.push(21);
        p.extend_from_slice(&[0u8; 10]);
        p.extend_from_slice(b"ijklmnopqrst\0");
        p.extend_from_slice(b"caching_sha2_password\0");
        p
    }

    #[test]
    fn frame_splits_at_the_payload_limit_and_ends_with_an_empty_packet() {
        let payload = vec![7u8; MAX_PAYLOAD];
        let wire = frame(3, &payload);
        assert_eq!(wire.len(), 4 + MAX_PAYLOAD + 4);
        assert_eq!(&wire[..4], &[0xff, 0xff, 0xff, 3]);
        assert_eq!(&wire[4 + MAX_PAYLOAD..], &[0, 0, 0, 4]);
        assert_eq!(
            frame(0, b"\x03SELECT 1"),
            b"\x09\x00\x00\x00\x03SELECT 1".to_vec()
        );
    }

    #[tokio::test]
    async fn read_packet_joins_continuation_packets_and_returns_the_last_seq() {
        let payload: Vec<u8> = (0..MAX_PAYLOAD + 5).map(|i| (i % 251) as u8).collect();
        let wire = frame(7, &payload);
        let mut input: &[u8] = &wire;
        let packet = read_packet(&mut input, MAX_PAYLOAD * 2).await.unwrap();
        assert_eq!(packet.seq, 8);
        assert_eq!(packet.payload, payload);
        assert!(input.is_empty());
    }

    #[tokio::test]
    async fn read_packet_refuses_a_payload_over_the_limit() {
        let wire = frame(0, &[1u8; 100]);
        let mut input: &[u8] = &wire;
        let error = read_packet(&mut input, 99).await.err().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let mut input: &[u8] = &wire;
        assert_eq!(
            read_packet(&mut input, 100).await.unwrap().payload.len(),
            100
        );
    }

    #[test]
    fn lenenc_integers_round_trip_and_refuse_null_and_err_markers() {
        for value in [
            0u64,
            250,
            251,
            0xffff,
            0x1_0000,
            0xff_ffff,
            0x100_0000,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            put_lenenc_int(&mut out, value);
            let mut reader = Reader::new(&out);
            assert_eq!(reader.lenenc_int().unwrap(), value, "{value}");
            assert_eq!(reader.remaining(), 0);
        }
        for marker in [0xfbu8, 0xff] {
            assert!(Reader::new(&[marker]).lenenc_int().is_err());
        }
        assert_eq!(
            Reader::new(&[0xfc, 0x01]).lenenc_int(),
            Err(PacketError::Truncated)
        );
        let mut out = Vec::new();
        put_lenenc_bytes(&mut out, b"abc");
        assert_eq!(Reader::new(&out).lenenc_bytes().unwrap(), b"abc");
    }

    #[test]
    fn a_mysql8_greeting_parses() {
        let greeting = Greeting::parse(&mysql8_greeting()).unwrap();
        assert_eq!(greeting.server_version, b"8.0.36");
        assert_eq!(greeting.connection_id, 13);
        assert_eq!(greeting.scramble, b"abcdefghijklmnopqrst");
        assert_eq!(greeting.capabilities, 0xdfff_ffff);
        assert_eq!(greeting.charset, 0xff);
        assert_eq!(greeting.status, 2);
        assert_eq!(greeting.plugin, CACHING_SHA2_PASSWORD);
    }

    #[test]
    fn a_greeting_round_trips_through_encode() {
        let greeting = Greeting::parse(&mysql8_greeting()).unwrap();
        assert_eq!(Greeting::parse(&greeting.encode()).unwrap(), greeting);
        let rewritten = Greeting {
            capabilities: greeting.capabilities & !STRIPPED_CAPABILITIES,
            scramble: (1u8..=20).collect(),
            plugin: NATIVE_PASSWORD.to_vec(),
            ..greeting
        };
        assert_eq!(Greeting::parse(&rewritten.encode()).unwrap(), rewritten);
    }

    #[test]
    fn a_greeting_plugin_without_a_terminator_is_read_to_the_end() {
        let mut bytes = mysql8_greeting();
        bytes.pop();
        assert_eq!(
            Greeting::parse(&bytes).unwrap().plugin,
            CACHING_SHA2_PASSWORD
        );
    }

    #[test]
    fn a_protocol_9_or_truncated_greeting_is_refused() {
        let mut bytes = mysql8_greeting();
        bytes[0] = 9;
        assert_eq!(
            Greeting::parse(&bytes),
            Err(PacketError::UnsupportedVersion(9))
        );
        assert_eq!(
            Greeting::parse(&mysql8_greeting()[..12]),
            Err(PacketError::Truncated)
        );
    }

    fn response(capabilities: u32) -> HandshakeResponse {
        let mut attributes = Vec::new();
        put_lenenc_bytes(&mut attributes, b"_client_name");
        put_lenenc_bytes(&mut attributes, b"zs-test");
        HandshakeResponse {
            capabilities,
            max_packet: 16 << 20,
            charset: 45,
            user: b"alice".to_vec(),
            auth_data: (1u8..=20).collect(),
            database: Some(b"appdb".to_vec()),
            plugin: Some(NATIVE_PASSWORD.to_vec()),
            attributes: Some(attributes),
        }
    }

    #[test]
    fn handshake_response_round_trips_for_each_auth_data_encoding() {
        let all =
            CLIENT_PROTOCOL_41 | CLIENT_CONNECT_WITH_DB | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS;
        for capabilities in [
            all | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
            all | CLIENT_SECURE_CONNECTION,
            all,
        ] {
            let sent = response(capabilities);
            let parsed = HandshakeResponse::parse(&sent.encode()).unwrap();
            assert!(parsed == sent, "{capabilities:#x}");
        }
        let bare = response(CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION);
        let parsed = HandshakeResponse::parse(&bare.encode()).unwrap();
        assert_eq!(parsed.user, b"alice");
        assert_eq!(parsed.auth_data, bare.auth_data);
        assert!(
            parsed.database.is_none() && parsed.plugin.is_none() && parsed.attributes.is_none()
        );
    }

    #[test]
    fn a_pre_41_response_is_refused() {
        let old = response(CLIENT_SECURE_CONNECTION).encode();
        assert!(matches!(
            HandshakeResponse::parse(&old),
            Err(PacketError::Malformed(_))
        ));
    }

    #[test]
    fn the_ssl_request_is_32_bytes_and_detected() {
        let request = ssl_request(CLIENT_PROTOCOL_41, 16 << 20, 255);
        assert_eq!(request.len(), 32);
        assert!(is_ssl_request(&request));
        assert_eq!(
            client_capabilities(&request),
            Some(CLIENT_PROTOCOL_41 | CLIENT_SSL)
        );
        assert!(!is_ssl_request(
            &response(CLIENT_PROTOCOL_41 | CLIENT_SSL).encode()
        ));
        assert_eq!(client_capabilities(&[1, 2]), None);
    }

    #[test]
    fn err_packets_round_trip_with_and_without_sqlstate() {
        let error = ServerError::parse(&err_packet(1045, "28000", "denied")).unwrap();
        assert_eq!(
            (
                error.code,
                error.sqlstate.as_deref(),
                error.message.as_str()
            ),
            (1045, Some("28000"), "denied")
        );
        let old = [ERR_HEADER, 0x10, 0x04, b'T', b'o', b'o'];
        let error = ServerError::parse(&old).unwrap();
        assert_eq!(
            (error.code, error.sqlstate, error.message.as_str()),
            (1040, None, "Too")
        );
        assert!(ServerError::parse(&[OK_HEADER, 0, 0]).is_err());
    }

    #[test]
    fn an_auth_switch_drops_the_trailing_nul_and_an_old_switch_has_no_plugin() {
        let sent = AuthSwitch {
            plugin: NATIVE_PASSWORD.to_vec(),
            data: (1u8..=20).collect(),
        };
        let parsed = AuthSwitch::parse(&sent.encode()).unwrap();
        assert_eq!((parsed.plugin, parsed.data), (sent.plugin, sent.data));
        let old = AuthSwitch::parse(&[SWITCH_HEADER]).unwrap();
        assert!(old.plugin.is_empty() && old.data.is_empty());
        assert_eq!(ok_packet(b"x")[0], OK_HEADER);
    }
}
