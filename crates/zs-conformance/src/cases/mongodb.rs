use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Output};
use std::time::Duration;

use super::{CLIENT_TIMEOUT, output_within};
use crate::config::Protocol;
use crate::runner::{Case, Context, Upstream};

const SHA1_USER: &str = "zs_sha1";
const SHA1_PASSWORD: &str = "zs-test-sha1-password";
const PING: &str = "db.runCommand({ping:1}).ok";
const AUTHENTICATED_USERS: &str = "print(db.runCommand({connectionStatus:1}).authInfo.authenticatedUsers.map(u => u.user + '@' + u.db).join(','))";
const OP_REPLY: i32 = 1;
const OP_QUERY: i32 = 2004;
const OP_MSG: i32 = 2013;
const CHECKSUM_PRESENT: u32 = 1;
const MAX_FRAME: i32 = 48_000_000;
const NESTING_DEPTH: usize = 150;
const OP_MSG_COLLECTION: &str = "conformance_op_msg";
const NESTED_COLLECTION: &str = "conformance_nested";
const PROBE: &str = "ZS_CONFORMANCE_MG03";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(15);

pub fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "MG-01",
            protocol: Protocol::Mongodb,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: scram_sha256,
        },
        Case {
            id: "MG-02",
            protocol: Protocol::Mongodb,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: Some(SHA1_PASSWORD),
            run: scram_sha1,
        },
        Case {
            id: "MG-03",
            protocol: Protocol::Mongodb,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: op_msg_round_trip,
        },
        Case {
            id: "MG-04",
            protocol: Protocol::Mongodb,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: op_query_hello,
        },
        Case {
            id: "MG-05",
            protocol: Protocol::Mongodb,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: speculative_hello,
        },
        Case {
            id: "MG-06",
            protocol: Protocol::Mongodb,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: nesting_depth,
        },
        Case {
            id: "MG-07",
            protocol: Protocol::Mongodb,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: direct_connection,
        },
    ]
}

fn scram_sha256(ctx: &Context) -> Result<String, String> {
    let uri = format!(
        "mongodb://{}/{}?authSource={}",
        ctx.endpoint, ctx.roles.database, ctx.roles.database
    );
    let value = mongosh_ping(&uri)?;
    expect_one(&value, "the SCRAM-SHA-256 connection")?;
    let expected = format!("{}@{}", ctx.roles.user, ctx.roles.database);
    let users = authenticated_users(&uri)?;
    if users != expected {
        return Err(format!(
            "the upstream session authenticated as {users:?}, not {expected}"
        ));
    }
    Ok(format!(
        "the credential-free mongosh ping returned 1 and connectionStatus reported the upstream session authenticated as {expected}"
    ))
}

fn authenticated_users(uri: &str) -> Result<String, String> {
    let mut command = mongosh_command(uri, AUTHENTICATED_USERS);
    let output = output_within(&mut command, None, CLIENT_TIMEOUT)?;
    ensure_success(&output, "the connectionStatus query failed")?;
    Ok(stdout_text(&output).trim().to_string())
}

fn scram_sha1(ctx: &Context) -> Result<String, String> {
    let uri = format!(
        "mongodb://{}/{}?authSource=admin",
        ctx.endpoint, ctx.roles.database
    );
    let value = mongosh_ping(&uri)?;
    expect_one(&value, "the SCRAM-SHA-1 connection")?;
    let expected = format!("{SHA1_USER}@admin");
    let users = authenticated_users(&uri)?;
    if users != expected {
        return Err(format!(
            "the upstream session authenticated as {users:?}, not {expected}"
        ));
    }
    Ok(format!(
        "mongosh printed 1 with authSource=admin and connectionStatus reported the upstream session authenticated as {expected}"
    ))
}

fn speculative_hello(ctx: &Context) -> Result<String, String> {
    let uri = format!(
        "mongodb://{}/{}?authSource={}",
        ctx.endpoint, ctx.roles.database, ctx.roles.database
    );
    let value = mongosh_ping(&uri)?;
    expect_one(&value, "the speculative handshake")?;
    Ok("mongosh sends speculativeAuthenticate in its first hello when the connection carries credentials, which is the observable this case relies on; this credential-free invocation cannot carry one, so the observed completion is the ping only".to_string())
}

fn direct_connection(ctx: &Context) -> Result<String, String> {
    let uri = format!("mongodb://{}/?directConnection=true", ctx.endpoint);
    let value = mongosh_ping(&uri)?;
    expect_one(&value, "the direct connection")?;
    Ok("the ping succeeded with directConnection=true, so the client reached the single node without topology discovery".to_string())
}

fn op_msg_round_trip(ctx: &Context) -> Result<String, String> {
    let database = &ctx.roles.database;
    let mut raw = Raw::connect(ctx.endpoint)?;
    raw.handshake(database)?;
    let insert = Document::new()
        .with_str("insert", OP_MSG_COLLECTION)
        .with_bool("ordered", true)
        .with_str("$db", database);
    let inserted = raw.sequence_command(
        &insert,
        "documents",
        &[Document::new().with_str("probe", PROBE)],
    )?;
    let acknowledged = inserted.get("n").and_then(Value::as_i64).unwrap_or(0);
    if acknowledged < 1 {
        return Err(format!(
            "the insert acknowledged {acknowledged} document(s)"
        ));
    }
    let find = Document::new()
        .with_str("find", OP_MSG_COLLECTION)
        .with_doc("filter", &Document::new().with_str("probe", PROBE))
        .with_str("$db", database);
    let found = raw.command(&find)?;
    match cursor_probe(&found) {
        Some(probe) if probe == PROBE => Ok(format!(
            "an OP_MSG insert with a payload type 1 documents section was acknowledged with n = {acknowledged} and the following find returned {probe}"
        )),
        Some(other) => Err(format!(
            "the find returned probe {:?} instead of {PROBE:?}",
            one_line(other)
        )),
        None => Err("the find returned no document in cursor.firstBatch".to_string()),
    }
}

fn op_query_hello(ctx: &Context) -> Result<String, String> {
    let mut raw = Raw::connect(ctx.endpoint)?;
    let request_id = raw.next_id();
    raw.send(&op_query(&hello(None), request_id))?;
    let (opcode, reply) = raw.receive().map_err(|error| error.to_string())?;
    if opcode != OP_REPLY {
        return Err(format!(
            "the proxy answered the legacy hello with opcode {opcode}"
        ));
    }
    if !reply_ok(&reply) {
        return Err(error_text(&reply));
    }
    Ok("the legacy OP_QUERY hello without a $db field was answered with ok: 1".to_string())
}

fn nesting_depth(ctx: &Context) -> Result<String, String> {
    let database = &ctx.roles.database;
    let mut raw = Raw::connect(ctx.endpoint)?;
    raw.handshake(database)?;
    let insert = Document::new()
        .with_str("insert", NESTED_COLLECTION)
        .with_bool("ordered", true)
        .with_str("$db", database);
    let document = nested(NESTING_DEPTH);
    let request_id = raw.next_id();
    let mut accepted = false;
    let refusal = match raw.send(&op_msg(
        &insert,
        request_id,
        Some(("documents", &[document])),
    )) {
        Err(reason) => format!("the write was refused: {reason}"),
        Ok(()) => match raw.receive() {
            Ok((_, reply)) => {
                if reply_ok(&reply) {
                    accepted = true;
                    format!(
                        "the proxy relayed a document nested {NESTING_DEPTH} levels deep and the upstream answered ok: 1"
                    )
                } else {
                    error_text(&reply)
                }
            }
            Err(ReceiveError::Malformed(reason)) => {
                return Err(format!(
                    "the proxy answered the nested write with a malformed reply: {reason}"
                ));
            }
            Err(ReceiveError::TimedOut) => {
                return Err(format!(
                    "the proxy neither answered nor refused a document nested {NESTING_DEPTH} levels deep within {} s",
                    READ_TIMEOUT.as_secs()
                ));
            }
            Err(error) => format!("the connection was refused: {error}"),
        },
    };
    let mut follow = Raw::connect(ctx.endpoint)?;
    follow.handshake(database)?;
    follow.command(&ping_command(database))?;
    if accepted {
        return Err(format!(
            "{refusal}; the proxy stayed up and a following ping returned ok: 1"
        ));
    }
    Ok(format!(
        "the nested document was not accepted ({refusal}); the proxy stayed up and a following ping returned ok: 1"
    ))
}

fn mongosh_ping(uri: &str) -> Result<String, String> {
    let output = output_within(&mut mongosh_command(uri, PING), None, CLIENT_TIMEOUT)?;
    ensure_success(&output, "the mongosh ping failed")?;
    Ok(stdout_text(&output))
}

fn mongosh_command(uri: &str, script: &str) -> Command {
    let mut command = Command::new("mongosh");
    command
        .arg(uri)
        .args(["--quiet", "--norc", "--eval", script])
        .env("MONGOSH_DISABLE_TELEMETRY", "1");
    command
}

fn expect_one(value: &str, action: &str) -> Result<(), String> {
    if value.trim() == "1" {
        Ok(())
    } else {
        Err(format!("{action} printed {:?}", one_line(value)))
    }
}

fn ensure_success(output: &Output, action: &str) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }
    let error = stderr_text(output);
    if error.trim().is_empty() {
        Err(format!("{action} with status {}", output.status))
    } else {
        Err(format!("{action}: {}", one_line(&error)))
    }
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn one_line(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > 320 {
        line.chars().take(320).collect::<String>() + "..."
    } else {
        line
    }
}

struct Raw {
    stream: TcpStream,
    request_id: i32,
}

impl Raw {
    fn connect(endpoint: SocketAddr) -> Result<Self, String> {
        let stream = TcpStream::connect_timeout(&endpoint, CONNECT_TIMEOUT)
            .map_err(|error| format!("cannot connect to {endpoint}: {error}"))?;
        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(|error| format!("cannot set the read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(READ_TIMEOUT))
            .map_err(|error| format!("cannot set the write timeout: {error}"))?;
        Ok(Self {
            stream,
            request_id: 1,
        })
    }

    fn next_id(&mut self) -> i32 {
        self.request_id += 1;
        self.request_id
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), String> {
        self.stream
            .write_all(frame)
            .map_err(|error| format!("cannot write to the proxy: {error}"))?;
        self.stream
            .flush()
            .map_err(|error| format!("cannot flush the proxy connection: {error}"))
    }

    fn receive(&mut self) -> Result<(i32, Document), ReceiveError> {
        let mut header = [0u8; 16];
        read_exact(&mut self.stream, &mut header)?;
        let length = i32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        if !(16..=MAX_FRAME).contains(&length) {
            return Err(ReceiveError::Malformed(format!(
                "the proxy sent a {length}-byte frame"
            )));
        }
        let opcode = i32::from_le_bytes([header[12], header[13], header[14], header[15]]);
        let mut payload = vec![0u8; length as usize - 16];
        read_exact(&mut self.stream, &mut payload)?;
        let document = match opcode {
            OP_MSG => parse_op_msg(&payload).map_err(ReceiveError::Malformed)?,
            OP_REPLY => parse_op_reply(&payload).map_err(ReceiveError::Malformed)?,
            other => {
                return Err(ReceiveError::Malformed(format!(
                    "the proxy replied with opcode {other}"
                )));
            }
        };
        Ok((opcode, document))
    }

    fn handshake(&mut self, database: &str) -> Result<Document, String> {
        self.command(&hello(Some(database)))
    }

    fn command(&mut self, body: &Document) -> Result<Document, String> {
        let request_id = self.next_id();
        self.send(&op_msg(body, request_id, None))?;
        let (opcode, reply) = self.receive().map_err(|error| error.to_string())?;
        if opcode != OP_MSG {
            return Err(format!("the proxy answered a command with opcode {opcode}"));
        }
        if !reply_ok(&reply) {
            return Err(error_text(&reply));
        }
        Ok(reply)
    }

    fn sequence_command(
        &mut self,
        body: &Document,
        identifier: &str,
        documents: &[Document],
    ) -> Result<Document, String> {
        let request_id = self.next_id();
        self.send(&op_msg(body, request_id, Some((identifier, documents))))?;
        let (opcode, reply) = self.receive().map_err(|error| error.to_string())?;
        if opcode != OP_MSG {
            return Err(format!("the proxy answered a command with opcode {opcode}"));
        }
        if !reply_ok(&reply) {
            return Err(error_text(&reply));
        }
        Ok(reply)
    }
}

enum ReceiveError {
    Closed(String),
    TimedOut,
    Malformed(String),
}

impl std::fmt::Display for ReceiveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiveError::Closed(reason) => formatter.write_str(reason),
            ReceiveError::TimedOut => formatter.write_str("the proxy did not answer in time"),
            ReceiveError::Malformed(reason) => formatter.write_str(reason),
        }
    }
}

fn read_exact(stream: &mut TcpStream, buffer: &mut [u8]) -> Result<(), ReceiveError> {
    match stream.read_exact(buffer) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            Err(ReceiveError::TimedOut)
        }
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Err(
            ReceiveError::Closed("the proxy closed the connection".to_string()),
        ),
        Err(error) => Err(ReceiveError::Closed(format!(
            "the proxy connection failed: {error}"
        ))),
    }
}

fn hello(database: Option<&str>) -> Document {
    let mut document = Document::new()
        .with_i32("hello", 1)
        .with_bool("helloOk", true)
        .with_doc("client", &client_metadata());
    if let Some(database) = database {
        document = document.with_str("$db", database);
    }
    document
}

fn client_metadata() -> Document {
    Document::new()
        .with_doc(
            "driver",
            &Document::new()
                .with_str("name", "conformance")
                .with_str("version", "1"),
        )
        .with_doc(
            "os",
            &Document::new()
                .with_str("type", "Linux")
                .with_str("name", "conformance")
                .with_str("architecture", "x86_64"),
        )
}

fn ping_command(database: &str) -> Document {
    Document::new()
        .with_i32("ping", 1)
        .with_str("$db", database)
}

fn nested(depth: usize) -> Document {
    let mut document = Document::new().with_str("probe", PROBE);
    for _ in 0..depth {
        document = Document::new().with_doc("n", &document);
    }
    document
}

fn frame(opcode: i32, request_id: i32, payload: &[u8]) -> Vec<u8> {
    let length = 16 + payload.len();
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&(length as i32).to_le_bytes());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(&0i32.to_le_bytes());
    frame.extend_from_slice(&opcode.to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn op_query(query: &Document, request_id: i32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0i32.to_le_bytes());
    payload.extend_from_slice(b"admin.$cmd\0");
    payload.extend_from_slice(&0i32.to_le_bytes());
    payload.extend_from_slice(&(-1i32).to_le_bytes());
    query.encode_into(&mut payload);
    frame(OP_QUERY, request_id, &payload)
}

fn op_msg(body: &Document, request_id: i32, sequence: Option<(&str, &[Document])>) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.push(0);
    body.encode_into(&mut payload);
    if let Some((identifier, documents)) = sequence {
        let mut encoded = Vec::new();
        for document in documents {
            document.encode_into(&mut encoded);
        }
        payload.push(1);
        let size = 4 + identifier.len() + 1 + encoded.len();
        payload.extend_from_slice(&(size as i32).to_le_bytes());
        payload.extend_from_slice(identifier.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&encoded);
    }
    frame(OP_MSG, request_id, &payload)
}

fn parse_op_msg(payload: &[u8]) -> Result<Document, String> {
    let mut offset = 0;
    let flags = u32::from_le_bytes(read_array::<4>(payload, &mut offset)?);
    let end = if flags & CHECKSUM_PRESENT != 0 {
        payload
            .len()
            .checked_sub(4)
            .ok_or_else(|| "the reply carries no checksum".to_string())?
    } else {
        payload.len()
    };
    let section = &payload[..end];
    let mut body = None;
    while offset < end {
        let kind = read_byte(section, &mut offset)?;
        match kind {
            0 => body = Some(parse_document(section, &mut offset)?),
            1 => {
                let size = usize::try_from(read_i32(section, &mut offset)?)
                    .map_err(|_| "the sequence section is negative".to_string())?;
                if size < 5 {
                    return Err(format!("the sequence section is {size} bytes"));
                }
                let section_end = offset
                    .checked_sub(4)
                    .and_then(|start| start.checked_add(size))
                    .ok_or_else(|| "the sequence section overflows".to_string())?;
                if section_end > end {
                    return Err("the sequence section overruns the reply".to_string());
                }
                let _identifier = read_cstring(section, &mut offset)?;
                while offset < section_end {
                    let _document = parse_document(section, &mut offset)?;
                }
                if offset != section_end {
                    return Err("the sequence section has a length mismatch".to_string());
                }
            }
            other => return Err(format!("the reply has section kind {other}")),
        }
    }
    body.ok_or_else(|| "the reply carried no body section".to_string())
}

fn parse_op_reply(payload: &[u8]) -> Result<Document, String> {
    let mut offset = 0;
    let _flags = read_i32(payload, &mut offset)?;
    let _cursor = read_i64(payload, &mut offset)?;
    let _starting_from = read_i32(payload, &mut offset)?;
    let returned = read_i32(payload, &mut offset)?;
    if returned < 1 {
        return Err("the legacy reply carried no document".to_string());
    }
    parse_document(payload, &mut offset)
}

fn reply_ok(reply: &Document) -> bool {
    reply
        .get("ok")
        .and_then(Value::as_f64)
        .is_some_and(|ok| ok == 1.0)
}

fn error_text(reply: &Document) -> String {
    let code = reply.get("code").and_then(Value::as_i64);
    let message = reply
        .get("errmsg")
        .and_then(Value::as_str)
        .unwrap_or("no error message");
    match code {
        Some(code) => format!(
            "the command was refused with code {code}: {}",
            one_line(message)
        ),
        None => format!("the command was refused: {}", one_line(message)),
    }
}

fn cursor_probe(reply: &Document) -> Option<&str> {
    reply
        .get("cursor")
        .and_then(Value::as_document)
        .and_then(|cursor| cursor.get("firstBatch"))
        .and_then(Value::as_array)
        .and_then(|batch| batch.first())
        .and_then(Value::as_document)
        .and_then(|document| document.get("probe"))
        .and_then(Value::as_str)
}

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Double(f64),
    String(String),
    Document(Document),
    Array(Vec<Value>),
    Boolean(bool),
    Int32(i32),
    Int64(i64),
    Other,
}

impl Value {
    fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(value) => Some(value),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Double(value) => Some(*value),
            Value::Int32(value) => Some(f64::from(*value)),
            Value::Int64(value) => Some(*value as f64),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Double(value) => Some(*value as i64),
            Value::Int32(value) => Some(i64::from(*value)),
            Value::Int64(value) => Some(*value),
            _ => None,
        }
    }

    fn as_document(&self) -> Option<&Document> {
        match self {
            Value::Document(document) => Some(document),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(values) => Some(values),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Document {
    elements: Vec<(String, Value)>,
}

impl Document {
    fn new() -> Self {
        Self::default()
    }

    fn with_str(mut self, name: &str, value: &str) -> Self {
        self.elements
            .push((name.to_string(), Value::String(value.to_string())));
        self
    }

    fn with_i32(mut self, name: &str, value: i32) -> Self {
        self.elements.push((name.to_string(), Value::Int32(value)));
        self
    }

    fn with_bool(mut self, name: &str, value: bool) -> Self {
        self.elements
            .push((name.to_string(), Value::Boolean(value)));
        self
    }

    fn with_doc(mut self, name: &str, value: &Document) -> Self {
        self.elements
            .push((name.to_string(), Value::Document(value.clone())));
        self
    }

    fn get(&self, name: &str) -> Option<&Value> {
        self.elements
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(&[0u8; 4]);
        for (name, value) in &self.elements {
            out.push(type_byte(value));
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            encode_value(out, value);
        }
        out.push(0);
        let length = i32::try_from(out.len().saturating_sub(start)).unwrap_or(i32::MAX);
        if let Some(slot) = out.get_mut(start..start + 4) {
            slot.copy_from_slice(&length.to_le_bytes());
        }
    }
}

fn type_byte(value: &Value) -> u8 {
    match value {
        Value::Double(_) => 0x01,
        Value::String(_) => 0x02,
        Value::Document(_) => 0x03,
        Value::Array(_) => 0x04,
        Value::Boolean(_) => 0x08,
        Value::Int32(_) => 0x10,
        Value::Int64(_) => 0x12,
        Value::Other => 0x0A,
    }
}

fn encode_value(out: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Double(value) => out.extend_from_slice(&value.to_le_bytes()),
        Value::String(value) => encode_string(out, value),
        Value::Document(document) => document.encode_into(out),
        Value::Array(values) => {
            let document = Document {
                elements: values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| (index.to_string(), value.clone()))
                    .collect(),
            };
            document.encode_into(out);
        }
        Value::Boolean(value) => out.push(u8::from(*value)),
        Value::Int32(value) => out.extend_from_slice(&value.to_le_bytes()),
        Value::Int64(value) => out.extend_from_slice(&value.to_le_bytes()),
        Value::Other => {}
    }
}

fn encode_string(out: &mut Vec<u8>, value: &str) {
    let length = i32::try_from(value.len() + 1).unwrap_or(i32::MAX);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    out.push(0);
}

fn parse_document(bytes: &[u8], offset: &mut usize) -> Result<Document, String> {
    let start = *offset;
    let length = read_i32(bytes, offset)?;
    if length < 5 {
        return Err(format!("the document at {start} is {length} bytes"));
    }
    let end = start
        .checked_add(length as usize)
        .ok_or_else(|| format!("the document at {start} overflows"))?;
    if end > bytes.len() {
        return Err(format!(
            "the document at {start} ends after the {} available bytes",
            bytes.len()
        ));
    }
    let mut elements = Vec::new();
    loop {
        let kind = read_byte(bytes, offset)?;
        if kind == 0 {
            break;
        }
        let name = read_cstring(bytes, offset)?;
        let value = parse_value(kind, bytes, offset)?;
        elements.push((name, value));
    }
    if *offset != end {
        return Err(format!(
            "the document at {start} declares {length} bytes but ends at {}",
            *offset - start
        ));
    }
    Ok(Document { elements })
}

fn parse_value(kind: u8, bytes: &[u8], offset: &mut usize) -> Result<Value, String> {
    match kind {
        0x01 => Ok(Value::Double(f64::from_le_bytes(read_array::<8>(
            bytes, offset,
        )?))),
        0x02 => Ok(Value::String(read_string(bytes, offset)?)),
        0x03 => Ok(Value::Document(parse_document(bytes, offset)?)),
        0x04 => {
            let document = parse_document(bytes, offset)?;
            Ok(Value::Array(
                document
                    .elements
                    .into_iter()
                    .map(|(_, value)| value)
                    .collect(),
            ))
        }
        0x08 => Ok(Value::Boolean(read_byte(bytes, offset)? != 0)),
        0x10 => Ok(Value::Int32(read_i32(bytes, offset)?)),
        0x12 => Ok(Value::Int64(read_i64(bytes, offset)?)),
        _ => {
            skip_value(kind, bytes, offset)?;
            Ok(Value::Other)
        }
    }
}

fn skip_value(kind: u8, bytes: &[u8], offset: &mut usize) -> Result<(), String> {
    match kind {
        0x05 => {
            let length = read_i32(bytes, offset)?;
            if length < 0 {
                return Err(format!("a binary value is {length} bytes"));
            }
            let _subtype = read_byte(bytes, offset)?;
            skip(bytes, offset, length as usize)
        }
        0x06 | 0x0A | 0x7F | 0xFF => Ok(()),
        0x07 => skip(bytes, offset, 12),
        0x09 | 0x11 => skip(bytes, offset, 8),
        0x0B => {
            let _pattern = read_cstring(bytes, offset)?;
            let _options = read_cstring(bytes, offset)?;
            Ok(())
        }
        0x0C => {
            let _namespace = read_string(bytes, offset)?;
            skip(bytes, offset, 12)
        }
        0x0D | 0x0E => {
            let _code = read_string(bytes, offset)?;
            Ok(())
        }
        0x0F => {
            let total = read_i32(bytes, offset)?;
            if total < 4 {
                return Err(format!("a code-with-scope value is {total} bytes"));
            }
            skip(bytes, offset, total as usize - 4)
        }
        0x13 => skip(bytes, offset, 16),
        other => Err(format!(
            "the reply carries unsupported BSON type 0x{other:02x}"
        )),
    }
}

fn skip(bytes: &[u8], offset: &mut usize, count: usize) -> Result<(), String> {
    let _skipped = read_bytes(bytes, offset, count)?;
    Ok(())
}

fn read_bytes<'a>(bytes: &'a [u8], offset: &mut usize, count: usize) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(count)
        .ok_or_else(|| "the reply offset overflows".to_string())?;
    let slice = bytes
        .get(*offset..end)
        .ok_or_else(|| format!("the reply ended after {} bytes", bytes.len()))?;
    *offset = end;
    Ok(slice)
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], String> {
    let slice = read_bytes(bytes, offset, N)?;
    let mut array = [0u8; N];
    array.copy_from_slice(slice);
    Ok(array)
}

fn read_byte(bytes: &[u8], offset: &mut usize) -> Result<u8, String> {
    let slice = read_bytes(bytes, offset, 1)?;
    match slice.first() {
        Some(byte) => Ok(*byte),
        None => Err("the reply ended before a type byte".to_string()),
    }
}

fn read_i32(bytes: &[u8], offset: &mut usize) -> Result<i32, String> {
    Ok(i32::from_le_bytes(read_array::<4>(bytes, offset)?))
}

fn read_i64(bytes: &[u8], offset: &mut usize) -> Result<i64, String> {
    Ok(i64::from_le_bytes(read_array::<8>(bytes, offset)?))
}

fn read_string(bytes: &[u8], offset: &mut usize) -> Result<String, String> {
    let length = read_i32(bytes, offset)?;
    if length < 1 {
        return Err(format!("a string value is {length} bytes"));
    }
    let slice = read_bytes(bytes, offset, length as usize)?;
    match slice.last() {
        Some(0) => String::from_utf8(slice[..slice.len() - 1].to_vec())
            .map_err(|error| format!("a string value is not UTF-8: {error}")),
        _ => Err("a string value has no terminator".to_string()),
    }
}

fn read_cstring(bytes: &[u8], offset: &mut usize) -> Result<String, String> {
    let start = *offset;
    let end = bytes
        .iter()
        .enumerate()
        .skip(start)
        .find(|(_, byte)| **byte == 0)
        .map(|(index, _)| index)
        .ok_or_else(|| "a BSON name has no terminator".to_string())?;
    *offset = end + 1;
    String::from_utf8(bytes[start..end].to_vec())
        .map_err(|error| format!("a BSON name is not UTF-8: {error}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::Fixtures;
    use crate::provision::Roles;
    use crate::runner::Variant;

    fn encoded(document: &Document) -> Vec<u8> {
        let mut out = Vec::new();
        document.encode_into(&mut out);
        out
    }

    fn context() -> Context {
        Context {
            endpoint: "127.0.0.1:27018".parse().expect("address"),
            env: BTreeMap::new(),
            roles: Roles {
                user: "zs_sha256".to_string(),
                password: "zs-test-sha256-password".to_string(),
                database: "zsdb".to_string(),
            },
            variant: Variant::Positive,
            fixtures: Fixtures::default(),
            http: None,
            adapter: std::path::PathBuf::new(),
            handle: crate::adapter::Handle {
                handle: String::new(),
                endpoint: "127.0.0.1:27018".parse().expect("address"),
                env: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn the_registry_lists_mg_01_to_mg_07() {
        let cases = cases();
        let ids: Vec<&str> = cases.iter().map(|case| case.id).collect();
        assert_eq!(
            ids,
            [
                "MG-01", "MG-02", "MG-03", "MG-04", "MG-05", "MG-06", "MG-07"
            ]
        );
        assert!(cases.iter().all(|case| case.protocol == Protocol::Mongodb));
        assert!(cases.iter().all(|case| case.serial_group.is_none()));
        assert_eq!(cases[1].credential, Some(SHA1_PASSWORD));
        assert!(
            cases
                .iter()
                .enumerate()
                .all(|(index, case)| index == 1 || case.credential.is_none())
        );
    }

    #[test]
    fn a_document_round_trips_through_the_decoder() {
        let document = Document::new()
            .with_str("name", "probe")
            .with_i32("count", 3)
            .with_bool("ok", true)
            .with_doc(
                "cursor",
                &Document::new()
                    .with_str("collection", "conformance_op_msg")
                    .with_doc("firstBatch", &Document::new().with_str("probe", PROBE)),
            );
        let encoded = encoded(&document);
        let mut offset = 0;
        let parsed = parse_document(&encoded, &mut offset).expect("document");
        assert_eq!(parsed, document);
        assert_eq!(offset, encoded.len());
        assert_eq!(
            parsed.get("cursor").and_then(Value::as_document),
            Some(
                &Document::new()
                    .with_str("collection", "conformance_op_msg")
                    .with_doc("firstBatch", &Document::new().with_str("probe", PROBE))
            )
        );
        assert_eq!(parsed.get("count").and_then(Value::as_i64), Some(3));
        assert_eq!(parsed.get("ok"), Some(&Value::Boolean(true)));
    }

    #[test]
    fn unsupported_bson_types_are_skipped() {
        let mut bytes = vec![0u8; 4];
        bytes.extend_from_slice(&[0x11]);
        bytes.extend_from_slice(b"time\0");
        bytes.extend_from_slice(&[0u8; 8]);
        bytes.extend_from_slice(&[0x12]);
        bytes.extend_from_slice(b"count\0");
        bytes.extend_from_slice(&1i64.to_le_bytes());
        bytes.push(0);
        let length = i32::try_from(bytes.len()).expect("length");
        bytes[..4].copy_from_slice(&length.to_le_bytes());
        let mut offset = 0;
        let parsed = parse_document(&bytes, &mut offset).expect("document");
        assert_eq!(parsed.get("count").and_then(Value::as_i64), Some(1));
        assert_eq!(parsed.get("time"), Some(&Value::Other));
    }

    #[test]
    fn a_binary_value_skips_its_subtype_and_payload() {
        let mut bytes = vec![0u8; 4];
        bytes.extend_from_slice(&[0x05]);
        bytes.extend_from_slice(b"hash\0");
        bytes.extend_from_slice(&20i32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&[0xab; 20]);
        bytes.extend_from_slice(&[0x12]);
        bytes.extend_from_slice(b"keyId\0");
        bytes.extend_from_slice(&7i64.to_le_bytes());
        bytes.push(0);
        let length = i32::try_from(bytes.len()).expect("length");
        bytes[..4].copy_from_slice(&length.to_le_bytes());
        let mut offset = 0;
        let parsed = parse_document(&bytes, &mut offset).expect("document");
        assert_eq!(parsed.get("hash"), Some(&Value::Other));
        assert_eq!(parsed.get("keyId").and_then(Value::as_i64), Some(7));
        assert_eq!(offset, bytes.len());
    }

    #[test]
    fn the_legacy_hello_query_has_no_database_field() {
        let document = hello(None);
        assert!(document.get("$db").is_none());
        let frame = op_query(&document, 4);
        assert_eq!(
            i32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]),
            OP_QUERY
        );
        let mut offset = 16 + 4 + "admin.$cmd".len() + 1 + 4 + 4;
        let parsed = parse_document(&frame, &mut offset).expect("query");
        assert!(parsed.get("$db").is_none());
        assert_eq!(parsed.get("hello").and_then(Value::as_i64), Some(1));
    }

    #[test]
    fn an_op_msg_sequence_section_carries_the_identifier() {
        let body = Document::new()
            .with_str("insert", OP_MSG_COLLECTION)
            .with_str("$db", "zsdb");
        let document = Document::new().with_str("probe", PROBE);
        let frame = op_msg(
            &body,
            9,
            Some(("documents", std::slice::from_ref(&document))),
        );
        assert_eq!(
            i32::from_le_bytes([frame[12], frame[13], frame[14], frame[15]]),
            OP_MSG
        );
        assert_eq!(
            u32::from_le_bytes([frame[16], frame[17], frame[18], frame[19]]),
            0
        );
        let payload = &frame[16..];
        let parsed = parse_op_msg(payload).expect("body");
        assert_eq!(parsed, body);
        let identifier = payload
            .windows(b"documents\0".len())
            .position(|window| window == b"documents\0")
            .expect("identifier");
        let mut offset = identifier + b"documents\0".len();
        let sequence = parse_document(payload, &mut offset).expect("sequence document");
        assert_eq!(sequence, document);
    }

    #[test]
    fn a_cursor_reply_yields_the_probe() {
        let reply = Document::new()
            .with_doc(
                "cursor",
                &Document {
                    elements: vec![(
                        "firstBatch".to_string(),
                        Value::Array(vec![Value::Document(
                            Document::new().with_str("probe", PROBE),
                        )]),
                    )],
                },
            )
            .with_i32("ok", 1);
        assert!(reply_ok(&reply));
        assert_eq!(cursor_probe(&reply), Some(PROBE));
    }

    #[test]
    fn an_error_reply_names_its_code_and_message() {
        let reply = Document::new()
            .with_i32("ok", 0)
            .with_i32("code", 18)
            .with_str("errmsg", "Authentication failed.");
        assert!(!reply_ok(&reply));
        let text = error_text(&reply);
        assert!(text.contains("18"));
        assert!(text.contains("Authentication failed."));
    }

    #[test]
    fn a_document_nested_past_the_server_limit_is_built() {
        let document = nested(NESTING_DEPTH);
        let mut bytes = encoded(&document);
        let mut depth = 0;
        let mut offset = 0;
        while let Ok(parsed) = parse_document(&bytes, &mut offset) {
            depth += 1;
            let Some(next) = parsed.get("n").and_then(Value::as_document) else {
                break;
            };
            bytes = encoded(next);
            offset = 0;
        }
        assert_eq!(depth, NESTING_DEPTH + 1);
    }

    #[test]
    fn mongosh_arguments_name_the_local_endpoint_and_no_password() {
        let ctx = context();
        let uri = format!(
            "mongodb://{}/{}?authSource={}",
            ctx.endpoint, ctx.roles.database, ctx.roles.database
        );
        let command = mongosh_command(&uri, PING);
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|arg| arg == &uri));
        assert!(args.iter().any(|arg| arg == "--norc"));
        assert!(args.iter().any(|arg| arg == PING));
        assert!(!args.iter().any(|arg| arg.contains(&ctx.roles.password)));
        assert!(uri.contains(&ctx.roles.database));
        assert!(!uri.contains('@'));
    }

    #[test]
    fn a_ping_output_other_than_one_is_refused() {
        assert!(expect_one("1\n", "the ping").is_ok());
        let error = expect_one("0\n", "the ping").expect_err("zero");
        assert!(error.contains("the ping printed"));
    }

    #[test]
    fn evidence_and_errors_stay_on_one_line() {
        assert_eq!(one_line("first\nsecond\tthird"), "first second third");
        assert_eq!(one_line(&"a".repeat(400)).len(), 323);
    }
}
