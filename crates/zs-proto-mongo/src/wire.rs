use tokio::io::{AsyncRead, AsyncReadExt};

use crate::bson::{self, Doc, Malformed, cstring_end, int32_at};

pub const HEADER_LEN: usize = 16;
pub const OP_REPLY: i32 = 1;
pub const OP_QUERY: i32 = 2004;
pub const OP_COMPRESSED: i32 = 2012;
pub const OP_MSG: i32 = 2013;
pub const CHECKSUM_PRESENT: u32 = 1;
pub const MORE_TO_COME: u32 = 1 << 1;
pub const EXHAUST_ALLOWED: u32 = 1 << 16;
pub const DEFAULT_MAX_MESSAGE: usize = 48_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub length: usize,
    pub request_id: i32,
    pub response_to: i32,
    pub op_code: i32,
}

impl Header {
    pub fn parse(raw: &[u8; HEADER_LEN]) -> Self {
        let word = |i: usize| i32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
        Self {
            length: usize::try_from(word(0)).unwrap_or(0),
            request_id: word(4),
            response_to: word(8),
            op_code: word(12),
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut raw = [0u8; HEADER_LEN];
        raw[..4].copy_from_slice(&(self.length as i32).to_le_bytes());
        raw[4..8].copy_from_slice(&self.request_id.to_le_bytes());
        raw[8..12].copy_from_slice(&self.response_to.to_le_bytes());
        raw[12..].copy_from_slice(&self.op_code.to_le_bytes());
        raw
    }

    pub fn body_len(&self) -> usize {
        self.length.saturating_sub(HEADER_LEN)
    }

    pub fn length_ok(&self, limit: usize) -> bool {
        self.length >= HEADER_LEN && self.length <= limit
    }
}

pub fn frame(op_code: i32, request_id: i32, response_to: i32, payload: &[u8]) -> Vec<u8> {
    let header = Header {
        length: HEADER_LEN + payload.len(),
        request_id,
        response_to,
        op_code,
    };
    let mut out = header.encode().to_vec();
    out.extend_from_slice(payload);
    out
}

fn i32_at(bytes: &[u8], at: usize) -> Result<i32, Malformed> {
    let raw: [u8; 4] = bytes
        .get(at..at + 4)
        .ok_or(Malformed)?
        .try_into()
        .map_err(|_| Malformed)?;
    Ok(i32::from_le_bytes(raw))
}

pub fn msg_flags(payload: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(payload.get(..4)?.try_into().ok()?))
}

fn sections_end(payload: &[u8], flags: u32) -> Option<usize> {
    let end = if flags & CHECKSUM_PRESENT != 0 {
        payload.len().checked_sub(4)?
    } else {
        payload.len()
    };
    (end >= 4).then_some(end)
}

pub enum Section {
    Body(Doc),
    Sequence(Vec<u8>),
}

pub struct OpMsg {
    pub flags: u32,
    pub sections: Vec<Section>,
}

impl OpMsg {
    pub fn new(body: Doc) -> Self {
        Self {
            flags: 0,
            sections: vec![Section::Body(body)],
        }
    }

    pub fn parse(payload: &[u8]) -> Result<Self, Malformed> {
        let flags = msg_flags(payload).ok_or(Malformed)?;
        let end = sections_end(payload, flags).ok_or(Malformed)?;
        let mut at = 4;
        let mut sections = Vec::new();
        let mut bodies = 0;
        while at < end {
            let kind = payload[at];
            let rest = payload.get(at + 1..end).ok_or(Malformed)?;
            let used = match kind {
                0 => {
                    let (doc, used) = Doc::read(rest)?;
                    sections.push(Section::Body(doc));
                    bodies += 1;
                    used
                }
                1 => {
                    let size = int32_at(rest, 0)?;
                    if size < 5 || size > rest.len() {
                        return Err(Malformed);
                    }
                    sections.push(Section::Sequence(rest[..size].to_vec()));
                    size
                }
                _ => return Err(Malformed),
            };
            at += 1 + used;
        }
        if bodies != 1 {
            return Err(Malformed);
        }
        Ok(Self {
            flags: flags & !CHECKSUM_PRESENT,
            sections,
        })
    }

    pub fn body(&self) -> Option<&Doc> {
        self.sections.iter().find_map(|section| match section {
            Section::Body(doc) => Some(doc),
            Section::Sequence(_) => None,
        })
    }

    pub fn body_mut(&mut self) -> Option<&mut Doc> {
        self.sections.iter_mut().find_map(|section| match section {
            Section::Body(doc) => Some(doc),
            Section::Sequence(_) => None,
        })
    }

    pub fn encode(&self, request_id: i32, response_to: i32) -> Vec<u8> {
        let mut payload = (self.flags & !CHECKSUM_PRESENT).to_le_bytes().to_vec();
        for section in &self.sections {
            match section {
                Section::Body(doc) => {
                    payload.push(0);
                    payload.extend_from_slice(&doc.encode());
                }
                Section::Sequence(raw) => {
                    payload.push(1);
                    payload.extend_from_slice(raw);
                }
            }
        }
        frame(OP_MSG, request_id, response_to, &payload)
    }
}

pub fn command_name(payload: &[u8]) -> Option<&str> {
    let flags = msg_flags(payload)?;
    let end = sections_end(payload, flags)?;
    let mut at = 4;
    while at < end {
        match payload[at] {
            0 => return bson::first_key(payload.get(at + 1..end)?),
            1 => {
                let size = int32_at(payload, at + 1).ok().filter(|s| *s >= 5)?;
                at += 1 + size;
            }
            _ => return None,
        }
    }
    None
}

pub fn exceeds_depth(payload: &[u8], limit: usize) -> Result<bool, Malformed> {
    let flags = msg_flags(payload).ok_or(Malformed)?;
    let end = sections_end(payload, flags).ok_or(Malformed)?;
    let mut at = 4;
    while at < end {
        let kind = *payload.get(at).ok_or(Malformed)?;
        at += 1;
        match kind {
            0 => {
                let total = int32_at(payload, at)?;
                let section = payload.get(..end).ok_or(Malformed)?;
                if bson::exceeds_depth(section, at, limit)? {
                    return Ok(true);
                }
                at = at.checked_add(total).ok_or(Malformed)?;
            }
            1 => {
                let size = int32_at(payload, at)?;
                if size < 5 {
                    return Err(Malformed);
                }
                let section_end = at.checked_add(size).ok_or(Malformed)?;
                if section_end > end {
                    return Err(Malformed);
                }
                let identifier_end = cstring_end(payload, at + 4)?;
                at = identifier_end + 1;
                if at > section_end {
                    return Err(Malformed);
                }
                while at < section_end {
                    let total = int32_at(payload, at)?;
                    let section = payload.get(..section_end).ok_or(Malformed)?;
                    if bson::exceeds_depth(section, at, limit)? {
                        return Ok(true);
                    }
                    at = at.checked_add(total).ok_or(Malformed)?;
                }
            }
            _ => return Err(Malformed),
        }
    }
    Ok(false)
}

pub struct OpQuery {
    pub flags: i32,
    pub collection: String,
    pub skip: i32,
    pub limit: i32,
    pub query: Doc,
}

impl OpQuery {
    pub fn parse(payload: &[u8]) -> Result<Self, Malformed> {
        let flags = i32_at(payload, 0)?;
        let end = cstring_end(payload, 4)?;
        let collection = std::str::from_utf8(&payload[4..end])
            .map_err(|_| Malformed)?
            .to_string();
        let skip = i32_at(payload, end + 1)?;
        let limit = i32_at(payload, end + 5)?;
        let (query, _) = Doc::read(payload.get(end + 9..).ok_or(Malformed)?)?;
        Ok(Self {
            flags,
            collection,
            skip,
            limit,
            query,
        })
    }

    pub fn database(&self) -> Option<&str> {
        self.collection
            .strip_suffix(".$cmd")
            .filter(|database| !database.is_empty())
    }

    pub fn encode(&self, request_id: i32) -> Vec<u8> {
        let mut payload = self.flags.to_le_bytes().to_vec();
        payload.extend_from_slice(self.collection.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&self.skip.to_le_bytes());
        payload.extend_from_slice(&self.limit.to_le_bytes());
        payload.extend_from_slice(&self.query.encode());
        frame(OP_QUERY, request_id, 0, &payload)
    }
}

pub fn op_reply(doc: &Doc, request_id: i32, response_to: i32) -> Vec<u8> {
    let mut payload = 0i32.to_le_bytes().to_vec();
    payload.extend_from_slice(&0i64.to_le_bytes());
    payload.extend_from_slice(&0i32.to_le_bytes());
    payload.extend_from_slice(&1i32.to_le_bytes());
    payload.extend_from_slice(&doc.encode());
    frame(OP_REPLY, request_id, response_to, &payload)
}

pub fn parse_op_reply(payload: &[u8]) -> Result<Doc, Malformed> {
    if i32_at(payload, 16)? != 1 {
        return Err(Malformed);
    }
    Ok(Doc::read(payload.get(20..).ok_or(Malformed)?)?.0)
}

pub async fn read_header<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> std::io::Result<Header> {
    let mut raw = [0u8; HEADER_LEN];
    reader.read_exact(&mut raw).await?;
    Ok(Header::parse(&raw))
}

pub async fn read_payload<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    header: &Header,
) -> std::io::Result<Vec<u8>> {
    if !header.length_ok(DEFAULT_MAX_MESSAGE) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "wire frame length out of range",
        ));
    }
    let mut payload = vec![0u8; header.body_len()];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn payload(frame: &[u8]) -> &[u8] {
        &frame[HEADER_LEN..]
    }

    fn nested(depth: usize) -> Doc {
        let mut document = Doc::new().with_i32("probe", 1);
        for _ in 1..depth {
            document = Doc::new().with_doc("n", &document);
        }
        document
    }

    fn sequence(document: &Doc) -> Vec<u8> {
        let identifier = b"documents\0";
        let encoded = document.encode();
        let size = 4 + identifier.len() + encoded.len();
        let mut raw = Vec::new();
        raw.extend_from_slice(&(size as i32).to_le_bytes());
        raw.extend_from_slice(identifier);
        raw.extend_from_slice(&encoded);
        raw
    }

    #[test]
    fn a_shallow_command_is_within_the_depth_limit() {
        let message =
            OpMsg::new(Doc::new().with_i32("ping", 1).with_str("$db", "zsdb")).encode(1, 0);
        assert!(!exceeds_depth(payload(&message), bson::MAX_DOCUMENT_DEPTH).unwrap());
    }

    #[test]
    fn the_depth_walk_is_cheap_on_a_large_document() {
        let mut document = Doc::new();
        for index in 0..20_000 {
            document = document.with_str(&format!("k{index}"), "value");
        }
        let message = OpMsg::new(document).encode(1, 0);
        let payload = payload(&message);
        let started = std::time::Instant::now();
        for _ in 0..10 {
            assert!(!exceeds_depth(payload, bson::MAX_DOCUMENT_DEPTH).unwrap());
        }
        let elapsed = started.elapsed();
        eprintln!(
            "depth walk: {elapsed:?} for ten passes over {} bytes",
            payload.len()
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "ten passes took {elapsed:?}"
        );
    }

    #[test]
    fn a_deep_body_is_refused() {
        let message = OpMsg::new(nested(bson::MAX_DOCUMENT_DEPTH + 1)).encode(1, 0);
        assert!(exceeds_depth(payload(&message), bson::MAX_DOCUMENT_DEPTH).unwrap());
    }

    #[test]
    fn a_deep_document_sequence_is_refused() {
        let mut message = OpMsg::new(Doc::new().with_str("insert", "conformance"));
        message.sections.push(Section::Sequence(sequence(&nested(
            bson::MAX_DOCUMENT_DEPTH + 1,
        ))));
        let frame = message.encode(1, 0);
        assert!(exceeds_depth(payload(&frame), bson::MAX_DOCUMENT_DEPTH).unwrap());
    }

    #[test]
    fn a_sequence_that_overruns_the_payload_is_malformed() {
        let mut message = OpMsg::new(Doc::new().with_str("insert", "conformance"));
        message
            .sections
            .push(Section::Sequence(vec![200, 0, 0, 0, b'd', 0]));
        let frame = message.encode(1, 0);
        assert_eq!(
            exceeds_depth(payload(&frame), bson::MAX_DOCUMENT_DEPTH),
            Err(Malformed)
        );
    }

    #[test]
    fn a_header_round_trips_and_checks_its_length() {
        let header = Header {
            length: 42,
            request_id: 7,
            response_to: -3,
            op_code: OP_MSG,
        };
        assert_eq!(Header::parse(&header.encode()), header);
        assert!(
            !Header {
                length: 15,
                ..header
            }
            .length_ok(100)
        );
        assert!(
            Header {
                length: 16,
                ..header
            }
            .length_ok(100)
        );
        assert!(
            Header {
                length: 100,
                ..header
            }
            .length_ok(100)
        );
        assert!(
            !Header {
                length: 101,
                ..header
            }
            .length_ok(100)
        );
        let mut negative = header.encode();
        negative[..4].copy_from_slice(&(-5i32).to_le_bytes());
        assert_eq!(Header::parse(&negative).length, 0);
    }

    #[test]
    fn a_tls_client_hello_fails_the_frame_check() {
        let hello: [u8; HEADER_LEN] = [
            0x16, 0x03, 0x01, 0x06, 0x1b, 0x01, 0x00, 0x06, 0x17, 0x03, 0x03, 0x7b, 0x3f, 0x0f,
            0x85, 0x85,
        ];
        let header = Header::parse(&hello);
        assert_eq!(header.length, 100_729_622);
        assert!(!header.length_ok(DEFAULT_MAX_MESSAGE));
        assert!(![OP_MSG, OP_QUERY].contains(&header.op_code));
    }

    #[test]
    fn op_msg_finds_its_body_after_a_document_sequence() {
        let mut sequence = Vec::new();
        let item = Doc::new().with_i32("x", 1).encode();
        sequence.extend_from_slice(&((4 + 10 + item.len()) as i32).to_le_bytes());
        sequence.extend_from_slice(b"documents\0");
        sequence.extend_from_slice(&item);
        let msg = OpMsg {
            flags: 0,
            sections: vec![
                Section::Sequence(sequence.clone()),
                Section::Body(
                    Doc::new()
                        .with_str("insert", "orders")
                        .with_str("$db", "appdb"),
                ),
            ],
        };
        let frame = msg.encode(5, 0);
        let header = Header::parse(frame[..HEADER_LEN].try_into().unwrap());
        assert_eq!(
            (header.length, header.request_id, header.op_code),
            (frame.len(), 5, OP_MSG)
        );
        assert_eq!(command_name(payload(&frame)), Some("insert"));
        let parsed = OpMsg::parse(payload(&frame)).unwrap();
        assert_eq!(parsed.body().unwrap().str("$db"), Some("appdb"));
        assert_eq!(parsed.encode(5, 0), frame);
    }

    #[test]
    fn a_checksum_is_dropped_and_never_written() {
        let mut frame = OpMsg::new(Doc::new().with_i32("ping", 1)).encode(1, 0);
        frame[HEADER_LEN] |= CHECKSUM_PRESENT as u8;
        frame.extend_from_slice(&[1, 2, 3, 4]);
        let len = (frame.len() as i32).to_le_bytes();
        frame[..4].copy_from_slice(&len);
        assert_eq!(msg_flags(payload(&frame)), Some(CHECKSUM_PRESENT));
        assert_eq!(command_name(payload(&frame)), Some("ping"));
        let parsed = OpMsg::parse(payload(&frame)).unwrap();
        assert_eq!(parsed.flags & CHECKSUM_PRESENT, 0);
        let again = parsed.encode(1, 0);
        assert_eq!(msg_flags(payload(&again)), Some(0));
        assert_eq!(again.len(), frame.len() - 4);
    }

    #[test]
    fn malformed_op_msg_payloads_are_refused() {
        let body = Doc::new().with_i32("ping", 1).encode();
        let with = |sections: &[(u8, &[u8])]| {
            let mut out = 0u32.to_le_bytes().to_vec();
            for (kind, bytes) in sections {
                out.push(*kind);
                out.extend_from_slice(bytes);
            }
            out
        };
        for (case, bytes) in [
            ("two bodies", with(&[(0, &body), (0, &body)])),
            ("no body", 0u32.to_le_bytes().to_vec()),
            ("unknown section kind", with(&[(2, &body)])),
            (
                "sequence past the end",
                with(&[(1, &[50, 0, 0, 0, b'd', 0]), (0, &body)]),
            ),
            ("truncated flags", vec![0, 0]),
        ] {
            assert!(OpMsg::parse(&bytes).is_err(), "{case}");
        }
        assert_eq!(command_name(&with(&[(2, &body)])), None);
    }

    #[test]
    fn op_query_reads_its_database() {
        for (collection, database) in [
            ("admin.$cmd", Some("admin")),
            ("test.$cmd", Some("test")),
            ("admin.users", None),
            (".$cmd", None),
        ] {
            let query = OpQuery {
                flags: 0,
                collection: collection.to_string(),
                skip: 0,
                limit: -1,
                query: Doc::new().with_i32("isMaster", 1),
            };
            let frame = query.encode(9);
            assert_eq!(
                Header::parse(frame[..HEADER_LEN].try_into().unwrap()).op_code,
                OP_QUERY
            );
            let parsed = OpQuery::parse(payload(&frame)).unwrap();
            assert_eq!(parsed.database(), database, "{collection}");
            assert_eq!(parsed.query.first_key(), Some("isMaster"));
            assert_eq!(parsed.limit, -1);
        }
        assert!(OpQuery::parse(&[0, 0, 0, 0, b'a']).is_err());
    }

    #[test]
    fn op_reply_round_trips() {
        let frame = op_reply(&Doc::new().with_f64("ok", 1.0), 11, 9);
        let header = Header::parse(frame[..HEADER_LEN].try_into().unwrap());
        assert_eq!(
            (header.op_code, header.request_id, header.response_to),
            (OP_REPLY, 11, 9)
        );
        assert!(parse_op_reply(payload(&frame)).unwrap().truthy("ok"));
    }

    #[tokio::test]
    async fn frames_are_read_from_a_stream() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let frame = OpMsg::new(Doc::new().with_i32("hello", 1)).encode(3, 0);
        a.write_all(&frame).await.unwrap();
        let header = read_header(&mut b).await.unwrap();
        let body = read_payload(&mut b, &header).await.unwrap();
        assert_eq!(header.length, frame.len());
        assert_eq!(command_name(&body), Some("hello"));
    }

    #[tokio::test]
    async fn read_payload_refuses_an_out_of_range_length() {
        let (_a, mut b) = tokio::io::duplex(16);
        for length in [0, HEADER_LEN - 1, DEFAULT_MAX_MESSAGE + 1] {
            let header = Header {
                length,
                request_id: 1,
                response_to: 0,
                op_code: OP_MSG,
            };
            let err = read_payload(&mut b, &header).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{length}");
        }
        let empty = Header {
            length: HEADER_LEN,
            request_id: 1,
            response_to: 0,
            op_code: OP_MSG,
        };
        assert!(read_payload(&mut b, &empty).await.unwrap().is_empty());
    }
}
