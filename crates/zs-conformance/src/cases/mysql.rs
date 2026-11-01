use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Output};
use std::time::Duration;

use super::{CLIENT_TIMEOUT, output_within};
use crate::config::Protocol;
use crate::provision::{self, ProvisionError};
use crate::runner::{Case, Context, Upstream};

const ROW: &str = "ZS_CONFORMANCE_OK";
const QUERY: &str = "select 'ZS_CONFORMANCE_OK'";
const NATIVE_USER: &str = "zs_native";
const NATIVE_PASSWORD: &str = "zs-test-native-password";
const AUTH_CACHE_GROUP: &str = "mysql-authcache";
const METADATA_QUERY: &str = "select 'a' as v, 1 as i, cast('{}' as json) as j";
const WARNING_QUERY: &str = "set session sql_mode=''; \
                             create temporary table conformance_warn (v varchar(3)); \
                             insert into conformance_warn values ('abcdef'); \
                             show warnings";
const COLUMN_NAMES: [&str; 3] = ["v", "i", "j"];
const METADATA: [(&str, &str, &str); 3] = [
    ("VAR_STRING", "utf8mb4_0900_ai_ci (255)", "NOT_NULL"),
    ("LONGLONG", "binary (63)", "NOT_NULL BINARY NUM"),
    ("JSON", "utf8mb4_0900_ai_ci (255)", "BINARY"),
];

pub fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "MY-01",
            protocol: Protocol::Mysql,
            upstream: Upstream::Primary,
            serial_group: Some(AUTH_CACHE_GROUP),
            credential: None,
            run: cached_authentication,
        },
        Case {
            id: "MY-02",
            protocol: Protocol::Mysql,
            upstream: Upstream::Primary,
            serial_group: Some(AUTH_CACHE_GROUP),
            credential: None,
            run: flushed_authentication,
        },
        Case {
            id: "MY-03",
            protocol: Protocol::Mysql,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: Some(NATIVE_PASSWORD),
            run: native_authentication,
        },
        Case {
            id: "MY-04",
            protocol: Protocol::Mysql,
            upstream: Upstream::Tls,
            serial_group: None,
            credential: None,
            run: upstream_tls,
        },
        Case {
            id: "MY-05",
            protocol: Protocol::Mysql,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: result_metadata,
        },
        Case {
            id: "MY-06",
            protocol: Protocol::Mysql,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: truncation_warnings,
        },
        Case {
            id: "MY-07",
            protocol: Protocol::Mysql,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: session_reset,
        },
        Case {
            id: "MY-08",
            protocol: Protocol::Mysql,
            upstream: Upstream::Primary,
            serial_group: None,
            credential: None,
            run: json_error,
        },
    ]
}

fn cached_authentication(ctx: &Context) -> Result<String, String> {
    let first = connection_id(ctx)?;
    let second = connection_id(ctx)?;
    if first == second {
        return Err(format!(
            "both connections reported server connection id {first}, so the second did not authenticate a new upstream session"
        ));
    }
    Ok(format!(
        "two consecutive connections as {} authenticated two upstream sessions ({first}, {second}); the caching_sha2_password fast path cannot be proven with this client, so the case proves only that a second authentication after a successful one succeeds",
        ctx.roles.user
    ))
}

fn connection_id(ctx: &Context) -> Result<String, String> {
    let output = run_query(ctx, &ctx.roles.user, "select connection_id()")?;
    ensure_success(&output, "the connection query failed")?;
    let value = stdout_text(&output).trim().to_string();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!(
            "the connection query returned {:?}",
            one_line(&value)
        ));
    }
    Ok(value)
}

fn flushed_authentication(ctx: &Context) -> Result<String, String> {
    let fixture = ctx
        .fixtures
        .mysql
        .ok_or_else(|| "the mysql fixture is not configured".to_string())?;
    provision::flush_privileges(fixture).map_err(|error| flush_error(&error))?;
    let row = run_row(ctx, &ctx.roles.user)?;
    Ok(format!(
        "FLUSH PRIVILEGES succeeded and the next connection returned {row}; the client cannot observe which caching_sha2_password exchange the proxy used"
    ))
}

fn flush_error(error: &ProvisionError) -> String {
    let reason = error.to_string();
    let lower = reason.to_lowercase();
    if lower.contains("mysql_native_password") && lower.contains("cannot be loaded") {
        format!(
            "the environment cannot run this case: FLUSH PRIVILEGES needs the fixture administrator, which uses mysql_native_password, and the installed mysql client cannot load that plugin: {reason}"
        )
    } else {
        format!("the privilege flush failed: {reason}")
    }
}

fn native_authentication(ctx: &Context) -> Result<String, String> {
    run_row(ctx, NATIVE_USER)?;
    Ok(format!(
        "the row came back as {NATIVE_USER} with the fixture mysql_native_password credential"
    ))
}

fn upstream_tls(ctx: &Context) -> Result<String, String> {
    let output = run_query(
        ctx,
        &ctx.roles.user,
        "show session status like 'Ssl_version'",
    )?;
    ensure_success(&output, "the TLS status query failed")?;
    let text = stdout_text(&output);
    let version = text
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    if !version.starts_with("TLS") {
        return Err(format!(
            "the upstream session reported no TLS version: {:?}",
            one_line(&text)
        ));
    }
    Ok(format!(
        "the upstream session reported Ssl_version {version} with the adapter pinned to the TLS fixture CA by ca-sha256"
    ))
}

fn result_metadata(ctx: &Context) -> Result<String, String> {
    let mut command = mysql_command(ctx, &ctx.roles.user);
    command.args(["--table", "--column-type-info", "--execute", METADATA_QUERY]);
    let output = output_within(&mut command, None, CLIENT_TIMEOUT)?;
    ensure_success(&output, "the metadata query failed")?;
    let names = column_names(&stdout_text(&output));
    if names != COLUMN_NAMES {
        return Err(format!(
            "the client reported columns {names:?}, expected {COLUMN_NAMES:?}"
        ));
    }
    let fields = metadata_fields(&stdout_text(&output))?;
    if fields.len() != METADATA.len() {
        return Err(format!(
            "the client reported {} Field blocks, not {}",
            fields.len(),
            METADATA.len()
        ));
    }
    for (index, (field, expected)) in fields.iter().zip(METADATA.iter()).enumerate() {
        if field.0.as_str() != expected.0
            || field.1.as_str() != expected.1
            || field.2.as_str() != expected.2
        {
            return Err(format!(
                "field {} reported {} / {} / {}, expected {} / {} / {}",
                index + 1,
                field.0,
                field.1,
                field.2,
                expected.0,
                expected.1,
                expected.2
            ));
        }
    }
    Ok(format!(
        "three Field blocks reported {} / {} / {} with their charsets and flags, frozen from a local direct connection",
        METADATA[0].0, METADATA[1].0, METADATA[2].0
    ))
}

fn column_names(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| line.trim_start().starts_with("Field "))
        .filter_map(|line| line.split('`').nth(1).map(str::to_string))
        .collect()
}

fn metadata_fields(text: &str) -> Result<Vec<(String, String, String)>, String> {
    let mut fields: Vec<(String, String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("Field ") {
            fields.push((String::new(), String::new(), String::new()));
        } else if let Some(value) = line.strip_prefix("Type:") {
            let field = fields
                .last_mut()
                .ok_or_else(|| "a type line came before any Field block".to_string())?;
            field.0 = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("Collation:") {
            let field = fields
                .last_mut()
                .ok_or_else(|| "a collation line came before any Field block".to_string())?;
            field.1 = value.trim().to_string();
        } else if let Some(value) = line.strip_prefix("Flags:") {
            let field = fields
                .last_mut()
                .ok_or_else(|| "a flags line came before any Field block".to_string())?;
            field.2 = value.trim().to_string();
        }
    }
    Ok(fields)
}

fn truncation_warnings(ctx: &Context) -> Result<String, String> {
    let mut command = mysql_command(ctx, &ctx.roles.user);
    command.args(["-vvv", "--execute", WARNING_QUERY]);
    let output = output_within(&mut command, None, CLIENT_TIMEOUT)?;
    ensure_success(&output, "the truncating insert failed")?;
    let text = stdout_text(&output);
    let count = insert_warning_count(&text).ok_or_else(|| {
        format!(
            "the insert's OK packet reported no warning count: {}",
            one_line(&text)
        )
    })?;
    if count == 0 {
        return Err("the insert's OK packet reported 0 warnings".to_string());
    }
    if !contains_token(&text, "1265") {
        return Err(format!(
            "SHOW WARNINGS did not return warning 1265: {}",
            one_line(&text)
        ));
    }
    Ok(format!(
        "the truncating insert's OK packet reported {count} warning(s) and SHOW WARNINGS returned 1265 (Data truncated)"
    ))
}

fn insert_warning_count(text: &str) -> Option<u64> {
    text.lines()
        .find(|line| line.contains("1 row affected"))
        .and_then(|line| {
            line.split(',')
                .find(|part| part.contains("warning"))
                .and_then(|part| part.split_whitespace().next())
                .and_then(|count| count.parse().ok())
        })
}

fn session_reset(ctx: &Context) -> Result<String, String> {
    let mut raw = Raw::connect(ctx.endpoint)?;
    raw.handshake(&ctx.roles.user, &ctx.roles.database)?;
    raw.command("set @v=1")?;
    match raw.query("select @v")? {
        Reply::Rows { rows } if rows.len() == 1 && rows[0] == [Some(b"1".to_vec())] => {}
        Reply::Rows { rows } => {
            return Err(format!(
                "the user variable did not hold before the reset: {}",
                one_line(&row_text(&rows))
            ));
        }
        Reply::Error(reason) => return Err(format!("the first read was refused: {reason}")),
        Reply::Ok => return Err("the first read returned no row set".to_string()),
    }
    raw.reset()?;
    match raw.query("select @v")? {
        Reply::Rows { rows }
            if rows.len() == 1 && rows[0].len() == 1 && rows[0][0].is_none() =>
        {
            Ok("the raw-socket client sent COM_RESET_CONNECTION (0x1f); the following select on the same connection answered NULL".to_string())
        }
        Reply::Rows { rows } => Err(format!(
            "the session reset left @v as {}",
            one_line(&row_text(&rows))
        )),
        Reply::Error(reason) => Err(format!("the read-back was refused: {reason}")),
        Reply::Ok => Err("the read-back returned no row set".to_string()),
    }
}

const COM_QUERY: u8 = 0x03;
const COM_RESET_CONNECTION: u8 = 0x1f;
const CLIENT_CAPABILITIES: u32 = 0x0008_A20D;
const MAX_PACKET: u32 = 16_777_216;
const CHARSET: u8 = 45;
const CLIENT_PLUGIN: &str = "caching_sha2_password";
const SOCKET_TIMEOUT: Duration = Duration::from_secs(15);

struct Raw {
    stream: TcpStream,
}

enum Reply {
    Ok,
    Error(String),
    Rows { rows: Vec<Vec<Option<Vec<u8>>>> },
}

impl Raw {
    fn connect(endpoint: SocketAddr) -> Result<Self, String> {
        let stream = TcpStream::connect_timeout(&endpoint, SOCKET_TIMEOUT)
            .map_err(|error| format!("cannot connect to {endpoint}: {error}"))?;
        stream
            .set_read_timeout(Some(SOCKET_TIMEOUT))
            .map_err(|error| format!("cannot set the read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(SOCKET_TIMEOUT))
            .map_err(|error| format!("cannot set the write timeout: {error}"))?;
        Ok(Self { stream })
    }

    fn handshake(&mut self, user: &str, database: &str) -> Result<(), String> {
        let (_seq, greeting) = self.read_packet()?;
        match greeting.first() {
            Some(0x0a) => {}
            Some(0xff) => return Err(server_error(&greeting)),
            _ => return Err("the proxy sent no protocol 10 greeting".to_string()),
        }
        let mut response = Vec::new();
        response.extend_from_slice(&CLIENT_CAPABILITIES.to_le_bytes());
        response.extend_from_slice(&MAX_PACKET.to_le_bytes());
        response.push(CHARSET);
        response.extend_from_slice(&[0u8; 23]);
        response.extend_from_slice(user.as_bytes());
        response.push(0);
        response.push(20);
        response.extend_from_slice(&[0u8; 20]);
        response.extend_from_slice(database.as_bytes());
        response.push(0);
        response.extend_from_slice(CLIENT_PLUGIN.as_bytes());
        response.push(0);
        self.write_packet(1, &response)?;
        let (seq, mut answer) = self.read_packet()?;
        if answer.first() == Some(&0xfe) {
            self.write_packet(seq.wrapping_add(1), &[])?;
            (_, answer) = self.read_packet()?;
        }
        if answer.as_slice() == [0x01, 0x03] {
            (_, answer) = self.read_packet()?;
        }
        match answer.first() {
            Some(0x00) => Ok(()),
            Some(0xff) => Err(server_error(&answer)),
            Some(0x01) => Err(
                "the proxy asked for full caching_sha2_password authentication from a credential-free client"
                    .to_string(),
            ),
            _ => Err("the proxy did not answer the handshake with OK".to_string()),
        }
    }

    fn command(&mut self, sql: &str) -> Result<(), String> {
        let mut payload = Vec::with_capacity(sql.len() + 1);
        payload.push(COM_QUERY);
        payload.extend_from_slice(sql.as_bytes());
        self.write_packet(0, &payload)?;
        match self.read_reply()? {
            Reply::Ok => Ok(()),
            Reply::Error(reason) => Err(format!("the command was refused: {reason}")),
            Reply::Rows { .. } => Err("the command returned a row set".to_string()),
        }
    }

    fn query(&mut self, sql: &str) -> Result<Reply, String> {
        let mut payload = Vec::with_capacity(sql.len() + 1);
        payload.push(COM_QUERY);
        payload.extend_from_slice(sql.as_bytes());
        self.write_packet(0, &payload)?;
        self.read_reply()
    }

    fn reset(&mut self) -> Result<(), String> {
        self.write_packet(0, &[COM_RESET_CONNECTION])?;
        match self.read_reply()? {
            Reply::Ok => Ok(()),
            Reply::Error(reason) => Err(format!("COM_RESET_CONNECTION was refused: {reason}")),
            Reply::Rows { .. } => Err("COM_RESET_CONNECTION returned a row set".to_string()),
        }
    }

    fn write_packet(&mut self, seq: u8, payload: &[u8]) -> Result<(), String> {
        let length =
            u32::try_from(payload.len()).map_err(|_| "the packet is too large".to_string())?;
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&length.to_le_bytes()[..3]);
        frame.push(seq);
        frame.extend_from_slice(payload);
        self.stream
            .write_all(&frame)
            .and_then(|()| self.stream.flush())
            .map_err(|error| format!("cannot write to the proxy: {error}"))
    }

    fn read_packet(&mut self) -> Result<(u8, Vec<u8>), String> {
        let mut header = [0u8; 4];
        self.stream
            .read_exact(&mut header)
            .map_err(|error| format!("cannot read a packet header: {error}"))?;
        let length =
            usize::from(header[0]) | usize::from(header[1]) << 8 | usize::from(header[2]) << 16;
        let mut payload = vec![0u8; length];
        self.stream
            .read_exact(&mut payload)
            .map_err(|error| format!("cannot read a packet body: {error}"))?;
        Ok((header[3], payload))
    }

    fn read_reply(&mut self) -> Result<Reply, String> {
        let (_seq, first) = self.read_packet()?;
        match first.first().copied() {
            Some(0x00) => return Ok(Reply::Ok),
            Some(0xff) => return Ok(Reply::Error(server_error(&first))),
            Some(_) => {}
            None => return Err("the proxy sent an empty packet".to_string()),
        }
        let mut offset = 0;
        let columns = usize::try_from(read_lenenc(&first, &mut offset)?)
            .map_err(|_| "the column count is too large".to_string())?;
        for _ in 0..columns {
            let (_seq, _definition) = self.read_packet()?;
        }
        let (_seq, end_of_columns) = self.read_packet()?;
        if !is_eof(&end_of_columns) {
            return Err("the proxy sent no end-of-columns packet".to_string());
        }
        let mut rows = Vec::new();
        loop {
            let (_seq, packet) = self.read_packet()?;
            if is_eof(&packet) {
                break;
            }
            if packet.first() == Some(&0xff) {
                return Ok(Reply::Error(server_error(&packet)));
            }
            rows.push(read_row(&packet)?);
        }
        Ok(Reply::Rows { rows })
    }
}

fn is_eof(packet: &[u8]) -> bool {
    packet.first() == Some(&0xfe) && packet.len() < 9
}

fn read_row(packet: &[u8]) -> Result<Vec<Option<Vec<u8>>>, String> {
    let mut offset = 0;
    let mut values = Vec::new();
    while offset < packet.len() {
        if packet[offset] == 0xfb {
            offset += 1;
            values.push(None);
            continue;
        }
        let length = usize::try_from(read_lenenc(packet, &mut offset)?)
            .map_err(|_| "a row value is too large".to_string())?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| "a row value overflows".to_string())?;
        let value = packet
            .get(offset..end)
            .ok_or_else(|| "a row value overruns the packet".to_string())?;
        values.push(Some(value.to_vec()));
        offset = end;
    }
    Ok(values)
}

fn read_lenenc(bytes: &[u8], offset: &mut usize) -> Result<u64, String> {
    let first = *bytes
        .get(*offset)
        .ok_or_else(|| "the packet ended before a length".to_string())?;
    *offset += 1;
    let mut read = |count: usize| -> Result<u64, String> {
        let end = offset
            .checked_add(count)
            .ok_or_else(|| "a length overflows".to_string())?;
        let slice = bytes
            .get(*offset..end)
            .ok_or_else(|| "a length overruns the packet".to_string())?;
        *offset = end;
        Ok(slice
            .iter()
            .rev()
            .fold(0u64, |value, byte| value << 8 | u64::from(*byte)))
    };
    match first {
        0xfc => read(2),
        0xfd => read(3),
        0xfe => read(8),
        other => Ok(u64::from(other)),
    }
}

fn server_error(packet: &[u8]) -> String {
    if packet.len() < 3 {
        return "the proxy sent a short error packet".to_string();
    }
    let code = u16::from_le_bytes([packet[1], packet[2]]);
    let mut message_start = 3;
    let mut sqlstate = String::new();
    if packet.get(3) == Some(&b'#')
        && let Some(state) = packet.get(4..9)
    {
        sqlstate = String::from_utf8_lossy(state).into_owned();
        message_start = 9;
    }
    let message = String::from_utf8_lossy(packet.get(message_start..).unwrap_or_default());
    if sqlstate.is_empty() {
        format!("error {code}: {}", one_line(&message))
    } else {
        format!("error {code} (SQLSTATE {sqlstate}): {}", one_line(&message))
    }
}

fn row_text(rows: &[Vec<Option<Vec<u8>>>]) -> String {
    rows.iter()
        .map(|row| {
            row.iter()
                .map(|value| match value {
                    Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                    None => "NULL".to_string(),
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn json_error(ctx: &Context) -> Result<String, String> {
    let output = run_query(ctx, &ctx.roles.user, "select cast('{bad' as json)")?;
    if output.status.success() {
        return Err("the invalid JSON cast succeeded".to_string());
    }
    let error = stderr_text(&output);
    if !contains_token(&error, "3141") {
        return Err(format!(
            "the invalid JSON cast did not report error 3141: {}",
            one_line(&error)
        ));
    }
    if !contains_token(&error, "22032") {
        return Err(format!(
            "the invalid JSON cast did not report SQLSTATE 22032: {}",
            one_line(&error)
        ));
    }
    Ok("error 3141 with SQLSTATE 22032 reached the client".to_string())
}

fn mysql_command(ctx: &Context, user: &str) -> Command {
    let mut command = Command::new("mysql");
    command
        .arg("--no-defaults")
        .arg("--connect-timeout=10")
        .arg("--protocol=TCP")
        .arg("--host")
        .arg(ctx.endpoint.ip().to_string())
        .arg("--port")
        .arg(ctx.endpoint.port().to_string())
        .arg("--user")
        .arg(user)
        .arg("--database")
        .arg(&ctx.roles.database)
        .env_remove("MYSQL_PWD");
    command
}

fn run_query(ctx: &Context, user: &str, sql: &str) -> Result<Output, String> {
    let mut command = mysql_command(ctx, user);
    command.args(["--batch", "--skip-column-names", "--execute", sql]);
    output_within(&mut command, None, CLIENT_TIMEOUT)
}

fn run_row(ctx: &Context, user: &str) -> Result<String, String> {
    let output = run_query(ctx, user, QUERY)?;
    ensure_success(&output, "the connection query failed")?;
    let value = stdout_text(&output);
    if value.trim() != ROW {
        return Err(format!(
            "the connection query returned {:?}",
            one_line(&value)
        ));
    }
    Ok(ROW.to_string())
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

fn contains_token(text: &str, token: &str) -> bool {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .any(|part| part == token)
}

fn one_line(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > 320 {
        line.chars().take(320).collect::<String>() + "..."
    } else {
        line
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::Fixtures;
    use crate::provision::Roles;
    use crate::runner::Variant;

    fn context() -> Context {
        Context {
            endpoint: "127.0.0.1:3307".parse().expect("address"),
            env: BTreeMap::new(),
            roles: Roles {
                user: "zs_sha2".to_string(),
                password: "hunter2-conformance".to_string(),
                database: "conformance".to_string(),
            },
            variant: Variant::Positive,
            fixtures: Fixtures::default(),
            http: None,
            adapter: std::path::PathBuf::new(),
            handle: crate::adapter::Handle {
                handle: String::new(),
                endpoint: "127.0.0.1:3307".parse().expect("address"),
                env: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn the_registry_lists_my_01_to_my_08() {
        let cases = cases();
        let ids: Vec<&str> = cases.iter().map(|case| case.id).collect();
        assert_eq!(
            ids,
            [
                "MY-01", "MY-02", "MY-03", "MY-04", "MY-05", "MY-06", "MY-07", "MY-08"
            ]
        );
        assert!(cases.iter().all(|case| case.protocol == Protocol::Mysql));
        assert_eq!(cases[0].serial_group, Some(AUTH_CACHE_GROUP));
        assert_eq!(cases[1].serial_group, Some(AUTH_CACHE_GROUP));
        assert!(cases[2..].iter().all(|case| case.serial_group.is_none()));
        assert_eq!(cases[2].credential, Some(NATIVE_PASSWORD));
        assert!(
            cases
                .iter()
                .enumerate()
                .all(|(index, case)| index == 2 || case.credential.is_none())
        );
        assert_eq!(cases[3].upstream, Upstream::Tls);
    }

    #[test]
    fn mysql_pwd_is_removed_and_no_password_reaches_the_arguments() {
        let ctx = context();
        let command = mysql_command(&ctx, &ctx.roles.user);
        let removed: Vec<String> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        assert!(removed.iter().any(|key| key == "MYSQL_PWD"));
        let args: Vec<String> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(!args.iter().any(|arg| arg.contains(&ctx.roles.password)));
        assert!(args.iter().any(|arg| arg == "127.0.0.1"));
        assert!(args.iter().any(|arg| arg == "3307"));
        assert!(args.iter().any(|arg| arg == &ctx.roles.user));
        assert!(args.iter().any(|arg| arg == &ctx.roles.database));
    }

    #[test]
    fn the_frozen_metadata_block_is_parsed() {
        let block = "Field   1:  `v`\n\
                     Catalog:    `def`\n\
                     Type:       VAR_STRING\n\
                     Collation:  utf8mb4_0900_ai_ci (255)\n\
                     Length:     4\n\
                     Flags:      NOT_NULL \n\
                     \n\
                     Field   2:  `i`\n\
                     Type:       LONGLONG\n\
                     Collation:  binary (63)\n\
                     Flags:      NOT_NULL BINARY NUM \n\
                     \n\
                     Field   3:  `j`\n\
                     Type:       JSON\n\
                     Collation:  utf8mb4_0900_ai_ci (255)\n\
                     Flags:      BINARY \n";
        assert_eq!(column_names(block), COLUMN_NAMES);
        let fields = metadata_fields(block).expect("fields");
        assert_eq!(fields.len(), 3);
        for (field, expected) in fields.iter().zip(METADATA.iter()) {
            assert_eq!(field.0, expected.0);
            assert_eq!(field.1, expected.1);
            assert_eq!(field.2, expected.2);
        }
    }

    #[test]
    fn the_ok_packet_warning_count_is_read_from_verbose_output() {
        let text = "insert into conformance_warn values ('abcdef')\n\
                    --------------\n\
                    \n\
                    Query OK, 1 row affected, 1 warning (0.001 sec)\n";
        assert_eq!(insert_warning_count(text), Some(1));
        assert_eq!(
            insert_warning_count("Query OK, 1 row affected (0.001 sec)\n"),
            None
        );
    }

    #[test]
    fn a_missing_field_block_is_empty_not_an_error() {
        assert!(metadata_fields("a\t1\t{}\n").expect("fields").is_empty());
    }

    #[test]
    fn the_missing_plugin_error_names_the_environment_limit() {
        let error = ProvisionError::Failed(
            "Authentication plugin 'mysql_native_password' cannot be loaded: dlopen failed"
                .to_string(),
        );
        let reason = flush_error(&error);
        assert!(reason.contains("the environment cannot run this case"));
        assert!(reason.contains("mysql_native_password"));
        let other = flush_error(&ProvisionError::Failed("server went away".to_string()));
        assert!(other.contains("the privilege flush failed"));
    }

    #[test]
    fn evidence_and_errors_stay_on_one_line() {
        assert_eq!(one_line("first\nsecond\tthird"), "first second third");
        assert_eq!(one_line(&"a".repeat(400)).len(), 323);
    }
}
