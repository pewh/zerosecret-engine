use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use crate::{PostgresError, Result};

pub const QUERY_REFUSAL: &str = "DO $$ BEGIN RAISE EXCEPTION USING ERRCODE = '25006', MESSAGE = 'zs: refused, read-only resource'; END $$";
pub const PARSE_REFUSAL: &str = "SELECT zs_refused_read_only_resource()";
pub const READ_ONLY_REASON: &str = "read-only";
pub const READ_ONLY_ESCAPED_REASON: &str = "read-only escaped";

pub(crate) const SCREENED: &[u8] = b"QPF";
pub(crate) const STREAMED: &[u8] = b"BCcdDEfHpSX";
pub(crate) const MAX_SCREENED_MESSAGE: u32 = 64 << 20;
pub(crate) const INLINE_SCAN_LIMIT: usize = 1 << 20;
pub(crate) const MAX_PARAMETER_STATUS: u32 = 16 * 1024;

const MODE_SETTING: &[u8] = b"default_transaction_read_only";
const SUPERUSER_SETTING: &[u8] = b"is_superuser";
const ENCODING_SETTING: &[u8] = b"server_encoding";
const VERSION_SETTING: &[u8] = b"server_version";
/// CockroachDB reports this; it speaks the protocol but is not PostgreSQL.
const FOREIGN_SETTING: &[u8] = b"crdb_version";
const MULTI_BYTE_ENCODINGS: [&[u8]; 7] = [
    b"UTF8",
    b"EUC_JP",
    b"EUC_CN",
    b"EUC_KR",
    b"EUC_TW",
    b"EUC_JIS_2004",
    b"MULE_INTERNAL",
];
const SUPERUSER_WORDS: [&str; 9] = [
    "program",
    "pg_reload_conf",
    "pg_terminate_backend",
    "pg_cancel_backend",
    "lo_import",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "session_authorization",
];
const QUOTED_ROLE: &str = "\"role\"";
const SUPERUSER_PHRASES: [(&[&str], &str); 8] = [
    (&["alter", "system"], "alter system"),
    (&["session", "authorization"], "session authorization"),
    (&["set", "role"], "set role"),
    (&["set", QUOTED_ROLE], "set role"),
    (&["set", "session", "role"], "set session role"),
    (&["set", "session", QUOTED_ROLE], "set session role"),
    (&["set", "local", "role"], "set local role"),
    (&["set", "local", QUOTED_ROLE], "set local role"),
];

const FUNCTION_CALL: &str = "function_call";
const AGENT_OPTION: &[u8] = b"-c default_transaction_read_only=on";
const SETTINGS: [&[u8]; 2] = [b"default_transaction_read_only", b"transaction_read_only"];
const ARGUMENT_OPTIONS: &[u8] = b"BCcDdfhkNprStvW-";
const FLAG_OPTIONS: &[u8] = b"bEeFijlnOPsT";
/// Refused in every read-only session: the mode switches, functions that run SQL text
/// (`query_to_xml*`, `ts_*`, `crosstab`, `connectby`, `xpath_table`), and functions that write
/// server files and can be granted to a login that is not a superuser.
const WORDS: [&str; 14] = [
    "set_config",
    "default_transaction_read_only",
    "transaction_read_only",
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "ts_stat",
    "ts_rewrite",
    "connectby",
    "xpath_table",
    "lo_export",
    "pg_file_write",
    "pg_file_rename",
    "pg_file_unlink",
];
const COPY: &str = "copy";
const PROGRAM: &str = "program";
const COPY_PROGRAM: &str = "copy program";
const COPY_TO_FILE: &str = "copy to file";
const DBLINK: &str = "dblink";
/// A prefix, like `dblink`: tablefunc installs `crosstab2`, `crosstab3` and `crosstab4` too.
const CROSSTAB: &str = "crosstab";
const READ_WRITE: &str = "read write";
const DO: &str = "do";
const UNICODE_ESCAPE: &str = "u&";

fn names_a_setting(name: &[u8]) -> bool {
    let name: Vec<u8> = name
        .iter()
        .map(|byte| match byte {
            b'-' => b'_',
            _ => byte.to_ascii_lowercase(),
        })
        .collect();
    SETTINGS.contains(&name.as_slice())
}

fn until_nul(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(PostgresError::BadStartup)?;
    Ok((&bytes[..end], &bytes[end + 1..]))
}

fn parameters(payload: &[u8]) -> Result<Vec<(&[u8], &[u8])>> {
    let declared = payload
        .first_chunk::<4>()
        .map(|length| u32::from_be_bytes(*length) as usize);
    if declared != Some(payload.len()) || payload.len() < 9 {
        return Err(PostgresError::BadStartup);
    }
    let mut rest = &payload[8..];
    let mut parameters = Vec::new();
    while rest != [0] {
        let (key, after) = until_nul(rest)?;
        let (value, after) = until_nul(after)?;
        if key.is_empty() {
            return Err(PostgresError::BadStartup);
        }
        parameters.push((key, value));
        rest = after;
    }
    Ok(parameters)
}

fn space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn split_options(options: &[u8]) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    let mut at = 0;
    while at < options.len() {
        if space(options[at]) {
            at += 1;
            continue;
        }
        let mut item = Vec::new();
        let mut escaped = false;
        while at < options.len() && (escaped || !space(options[at])) {
            if !escaped && options[at] == b'\\' {
                escaped = true;
            } else {
                escaped = false;
                item.push(options[at]);
            }
            at += 1;
        }
        items.push(item);
    }
    items
}

fn parse_options(items: Vec<Vec<u8>>) -> Result<Vec<(u8, Option<Vec<u8>>)>> {
    let mut parsed = Vec::new();
    let mut items = items.into_iter();
    while let Some(item) = items.next() {
        let letters = match item.as_slice() {
            [b'-', letters @ ..] if !letters.is_empty() && letters != b"-" => letters,
            _ => return Err(PostgresError::BadStartup),
        };
        for (at, letter) in letters.iter().enumerate() {
            if FLAG_OPTIONS.contains(letter) {
                parsed.push((*letter, None));
                continue;
            }
            if !ARGUMENT_OPTIONS.contains(letter) {
                return Err(PostgresError::BadStartup);
            }
            let argument = match &letters[at + 1..] {
                [] => items.next().ok_or(PostgresError::BadStartup)?,
                inline => inline.to_vec(),
            };
            if argument.is_empty() {
                return Err(PostgresError::BadStartup);
            }
            parsed.push((*letter, Some(argument)));
            break;
        }
    }
    Ok(parsed)
}

fn sets_a_setting(letter: u8, argument: &[u8]) -> bool {
    let name = argument
        .split(|byte| *byte == b'=')
        .next()
        .unwrap_or_default();
    matches!(letter, b'c' | b'-') && names_a_setting(name)
}

fn rebuild_options(client: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut rebuilt = Vec::new();
    for (letter, argument) in parse_options(split_options(client.unwrap_or_default()))? {
        if argument
            .as_deref()
            .is_some_and(|argument| sets_a_setting(letter, argument))
        {
            continue;
        }
        rebuilt.extend_from_slice(&[b'-', letter]);
        for byte in argument.unwrap_or_default() {
            if byte == b'\\' || space(byte) || byte >= 0x80 {
                rebuilt.push(b'\\');
            }
            rebuilt.push(byte);
        }
        rebuilt.push(b' ');
    }
    rebuilt.extend_from_slice(AGENT_OPTION);
    Ok(rebuilt)
}

pub fn read_only_startup(payload: &[u8]) -> Result<Vec<u8>> {
    let parameters = parameters(payload)?;
    let mut options = parameters.iter().filter(|(key, _)| *key == b"options");
    let client = options.next().map(|(_, value)| *value);
    if options.next().is_some() {
        return Err(PostgresError::BadStartup);
    }
    let rebuilt = rebuild_options(client)?;
    let mut kept: Vec<(&[u8], &[u8])> = parameters
        .into_iter()
        .filter(|(key, _)| *key != b"options" && !names_a_setting(key))
        .collect();
    kept.push((b"options", &rebuilt));
    let mut body = payload[4..8].to_vec();
    for (key, value) in kept {
        body.extend_from_slice(key);
        body.push(0);
        body.extend_from_slice(value);
        body.push(0);
    }
    body.push(0);
    let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    Ok(packet)
}

fn identifier(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$' || byte >= 0x80
}

fn prefix_at(text: &[u8], at: usize, word: &str) -> bool {
    text.get(at..at + word.len())
        .is_some_and(|found| found.eq_ignore_ascii_case(word.as_bytes()))
        && (at == 0 || !identifier(text[at - 1]))
}

fn word_at(text: &[u8], at: usize, word: &str) -> bool {
    prefix_at(text, at, word)
        && text
            .get(at + word.len())
            .is_none_or(|next| !identifier(*next))
}

fn quoted_at(text: &[u8], at: usize) -> bool {
    text.get(at..at + QUOTED_ROLE.len())
        .is_some_and(|found| found.eq_ignore_ascii_case(QUOTED_ROLE.as_bytes()))
}

fn comment_end(text: &[u8], mut at: usize) -> usize {
    let mut depth = 0usize;
    while at < text.len() {
        if text[at..].starts_with(b"/*") {
            depth += 1;
            at += 2;
        } else if text[at..].starts_with(b"*/") {
            depth -= 1;
            at += 2;
            if depth == 0 {
                return at;
            }
        } else {
            at += 1;
        }
    }
    text.len()
}

fn skip_blank(text: &[u8], mut at: usize, budget: &mut usize) -> Option<usize> {
    loop {
        let from = at;
        let rest = &text[at..];
        if rest.first().is_some_and(|byte| space(*byte)) {
            at += 1;
        } else if rest.starts_with(b"--") {
            at = rest
                .iter()
                .position(|byte| matches!(byte, b'\n' | b'\r'))
                .map_or(text.len(), |end| at + end + 1);
        } else if rest.starts_with(b"/*") {
            at = comment_end(text, at);
        } else {
            return Some(at);
        }
        *budget = budget.checked_sub(at - from)?;
    }
}

fn followed_by(text: &[u8], at: usize, word: &str, budget: &mut usize) -> bool {
    skip_blank(text, at, budget).is_none_or(|next| word_at(text, next, word))
}

fn superuser_match(text: &[u8], at: usize, budget: &mut usize) -> Option<&'static str> {
    if let Some(word) = SUPERUSER_WORDS.iter().find(|word| word_at(text, at, word)) {
        return Some(word);
    }
    SUPERUSER_PHRASES
        .iter()
        .find(|(words, _)| phrase_at(text, at, words, budget))
        .map(|(_, phrase)| *phrase)
}

fn phrase_at(text: &[u8], at: usize, words: &[&str], budget: &mut usize) -> bool {
    let Some((first, rest)) = words.split_first() else {
        return false;
    };
    if !word_at(text, at, first) {
        return false;
    }
    let mut end = at + first.len();
    for word in rest {
        match skip_blank(text, end, budget) {
            None => return true,
            Some(next) if *word == QUOTED_ROLE && quoted_at(text, next) => end = next + word.len(),
            Some(next) if word_at(text, next, word) => end = next + word.len(),
            Some(_) => return false,
        }
    }
    true
}

fn string_start(text: &[u8], at: usize) -> bool {
    match text.get(at) {
        Some(b'\'' | b'$') => true,
        Some(b'e' | b'E') => text.get(at + 1) == Some(&b'\''),
        _ => false,
    }
}

/// Whether a string literal follows `end`, after blanks and comments (fails closed when the
/// scan budget runs out). `COPY` takes a file name or a command only as a string literal.
fn literal_follows(text: &[u8], end: usize, budget: &mut usize) -> bool {
    skip_blank(text, end, budget).is_none_or(|next| string_start(text, next))
}

pub fn scan(text: &[u8], superuser: bool) -> Option<&'static str> {
    let mut budget = 4 * text.len() + 1024;
    let mut copy = false;
    for at in 0..text.len() {
        if superuser && let Some(found) = superuser_match(text, at, &mut budget) {
            return Some(found);
        }
        if let Some(word) = WORDS.iter().find(|word| word_at(text, at, word)) {
            return Some(word);
        }
        copy |= word_at(text, at, COPY);
        if copy && word_at(text, at, PROGRAM) && literal_follows(text, at + 7, &mut budget) {
            return Some(COPY_PROGRAM);
        }
        if copy && word_at(text, at, "to") && literal_follows(text, at + 2, &mut budget) {
            return Some(COPY_TO_FILE);
        }
        if let Some(prefix) = [DBLINK, CROSSTAB]
            .into_iter()
            .find(|prefix| prefix_at(text, at, prefix))
        {
            return Some(prefix);
        }
        if text[at].eq_ignore_ascii_case(&b'u') && text.get(at + 1) == Some(&b'&') {
            return Some(UNICODE_ESCAPE);
        }
        if word_at(text, at, "read") && followed_by(text, at + 4, "write", &mut budget) {
            return Some(READ_WRITE);
        }
        if (at == 0 || text[at - 1] == b';') && followed_by(text, at, DO, &mut budget) {
            return Some(DO);
        }
    }
    None
}

pub(crate) fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![tag];
    message.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(body);
    message
}

fn query_refusal() -> Vec<u8> {
    let mut body = QUERY_REFUSAL.as_bytes().to_vec();
    body.push(0);
    frame(b'Q', &body)
}

pub(crate) fn refusal(
    tag: u8,
    body: &[u8],
    superuser: bool,
) -> Result<Option<(&'static str, Vec<u8>)>> {
    match tag {
        b'Q' => Ok(scan(body, superuser).map(|word| (word, query_refusal()))),
        b'P' => {
            let (name, rest) = until_nul(body).map_err(|_| PostgresError::BadFraming)?;
            let (text, _) = until_nul(rest).map_err(|_| PostgresError::BadFraming)?;
            Ok(scan(text, superuser).map(|word| {
                let mut replaced = name.to_vec();
                replaced.push(0);
                replaced.extend_from_slice(PARSE_REFUSAL.as_bytes());
                replaced.extend_from_slice(&[0, 0, 0]);
                (word, frame(b'P', &replaced))
            }))
        }
        b'F' => Ok(Some((FUNCTION_CALL, query_refusal()))),
        _ => Ok(None),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Escaped,
    ReadOnly,
    Superuser,
    Other,
}

fn setting(body: &[u8]) -> Option<(&[u8], &[u8])> {
    let (name, rest) = until_nul(body).ok()?;
    let (value, rest) = until_nul(rest).ok()?;
    rest.is_empty().then_some((name, value))
}

pub(crate) fn parameter_status(body: &[u8]) -> Option<Status> {
    let (name, value) = setting(body)?;
    Some(match name {
        MODE_SETTING if value == b"on" => Status::ReadOnly,
        MODE_SETTING => Status::Escaped,
        SUPERUSER_SETTING if value == b"on" => Status::Superuser,
        _ => Status::Other,
    })
}

/// How a read-only session may start, read from the server's startup reports.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Start {
    /// The server reported `default_transaction_read_only = on`.
    Confirmed {
        superuser: bool,
    },
    /// A server older than 14 does not report the mode; the agent asks with
    /// [`CONFIRM_QUERY`] before the client gets `ReadyForQuery`.
    Unreported {
        superuser: bool,
    },
    Refused,
}

/// The first major version that reports `default_transaction_read_only`.
const REPORTING_VERSION: u32 = 14;

/// The major version of a plain PostgreSQL `server_version`: `13.16`, `9.6.24`, `13beta1`,
/// `12.20 (Debian ...)`. Anything else (`13.0.0` of CockroachDB, `11.2-YB-...` of YugabyteDB)
/// is not PostgreSQL, and the agent does not open a read-only session to it.
fn major_version(value: &[u8]) -> Option<u32> {
    let value = value.split(|byte| *byte == b' ').next()?;
    let digits = value
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let major: u32 = std::str::from_utf8(value.get(..digits)?)
        .ok()?
        .parse()
        .ok()?;
    if digits > 3 {
        return None;
    }
    let mut rest = &value[digits..];
    let mut components = 1;
    while let [b'.', after @ ..] = rest {
        let count = after
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if count == 0 {
            return None;
        }
        components += 1;
        rest = &after[count..];
    }
    if components > if major < 10 { 3 } else { 2 } {
        return None;
    }
    let pre_release = |tag: &[u8]| {
        rest.strip_prefix(tag)
            .is_some_and(|number| number.iter().all(u8::is_ascii_digit))
    };
    (rest.is_empty() || [&b"beta"[..], b"rc", b"devel"].into_iter().any(pre_release))
        .then_some(major)
}

fn read_startup(tail: &[u8]) -> Option<(bool, Option<bool>, bool, Option<u32>)> {
    let (mut superuser, mut mode, mut multi_byte, mut version) = (false, None, false, None);
    let mut rest = tail;
    while let [tag, a, b, c, d, after @ ..] = rest {
        let size = (u32::from_be_bytes([*a, *b, *c, *d]) as usize).checked_sub(4)?;
        let body = after.get(..size)?;
        if *tag == b'S' {
            match setting(body)? {
                (ENCODING_SETTING, value) => multi_byte = MULTI_BYTE_ENCODINGS.contains(&value),
                (VERSION_SETTING, value) => version = major_version(value),
                (FOREIGN_SETTING, _) => return None,
                _ => {}
            }
            match parameter_status(body)? {
                Status::Escaped => mode = Some(false),
                Status::ReadOnly => mode = mode.or(Some(true)),
                Status::Superuser => superuser = true,
                Status::Other => {}
            }
        }
        rest = &after[size..];
    }
    rest.is_empty()
        .then_some((superuser, mode, multi_byte, version))
}

pub(crate) fn startup_check(tail: &[u8]) -> Start {
    match read_startup(tail) {
        Some((superuser, Some(true), true, _)) => Start::Confirmed { superuser },
        Some((superuser, None, true, Some(version))) if version < REPORTING_VERSION => {
            Start::Unreported { superuser }
        }
        _ => Start::Refused,
    }
}

/// The query that confirms the mode on a server older than 14.
pub(crate) const CONFIRM_QUERY: &str = "SHOW default_transaction_read_only";

/// Reads the server's answer to [`CONFIRM_QUERY`]. `None`: refuse the session;
/// `Some(0)`: more bytes are needed; `Some(n)`: the answer is the first `n` bytes and
/// confirms the mode. Exactly one row with the value `on`, then an idle `ReadyForQuery`.
pub(crate) fn confirmation(answer: &[u8]) -> Option<usize> {
    let (mut rows, mut confirmed) = (0, false);
    let mut at = 0;
    loop {
        let Some(header) = answer.get(at..at + 5) else {
            return Some(0);
        };
        let size = (u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize)
            .checked_sub(4)?;
        let Some(body) = answer.get(at + 5..at + 5 + size) else {
            return Some(0);
        };
        at += 5 + size;
        match header[0] {
            b'T' | b'C' | b'N' => {}
            b'D' => {
                rows += 1;
                confirmed = body == [&1u16.to_be_bytes()[..], &2u32.to_be_bytes(), b"on"].concat();
            }
            b'Z' if body == b"I" && rows == 1 && confirmed => return Some(at),
            _ => return None,
        }
    }
}

#[derive(Default)]
struct GateState {
    units: u64,
    ready: u64,
    superuser: bool,
    escaped: bool,
}

impl GateState {
    fn idle(&self) -> bool {
        self.ready == self.units
    }
}

pub(crate) struct Gate {
    state: Mutex<GateState>,
    changed: Notify,
}

impl Gate {
    pub(crate) fn new(superuser: bool) -> Self {
        Self {
            state: Mutex::new(GateState {
                superuser,
                ..GateState::default()
            }),
            changed: Notify::new(),
        }
    }

    fn state(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn superuser(&self) -> bool {
        self.state().superuser
    }

    pub(crate) fn become_superuser(&self) -> bool {
        !std::mem::replace(&mut self.state().superuser, true)
    }

    pub(crate) fn escape(&self) {
        self.state().escaped = true;
    }

    pub(crate) fn escaped(&self) -> bool {
        self.state().escaped
    }

    pub(crate) fn ready(&self) -> bool {
        let expected = {
            let mut state = self.state();
            state.ready += 1;
            state.ready <= state.units
        };
        self.changed.notify_one();
        expected
    }

    fn unit(&self) {
        self.state().units += 1;
    }

    async fn idle(&self) {
        loop {
            let notified = self.changed.notified();
            let idle = self.state().idle();
            if idle {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Default)]
pub(crate) struct Units {
    open: bool,
}

impl Units {
    pub(crate) async fn admit(&mut self, gate: &Gate, tag: u8) -> Result<()> {
        match tag {
            b'c' | b'd' | b'f' | b'H' | b'X' => {}
            b'Q' | b'F' if self.open => return Err(PostgresError::BadFraming),
            b'Q' | b'F' => {
                gate.idle().await;
                gate.unit();
            }
            b'S' if self.open => {
                gate.unit();
                self.open = false;
            }
            b'S' => {
                gate.idle().await;
                gate.unit();
            }
            _ => {
                if !self.open {
                    gate.idle().await;
                    self.open = true;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screening_holds_at_most_64_mib_and_scans_inline_up_to_1_mib() {
        assert_eq!(MAX_SCREENED_MESSAGE, 64 * 1024 * 1024);
        assert_eq!(INLINE_SCAN_LIMIT, 1024 * 1024);
    }

    fn startup(parameters: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = 196_608u32.to_be_bytes().to_vec();
        for (key, value) in parameters {
            body.extend_from_slice(key.as_bytes());
            body.push(0);
            body.extend_from_slice(value);
            body.push(0);
        }
        body.push(0);
        let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
        packet.extend_from_slice(&body);
        packet
    }

    fn rewritten_options(options: &[u8]) -> Vec<u8> {
        let rewritten = read_only_startup(&startup(&[("user", b"app"), ("options", options)]))
            .unwrap_or_else(|_| {
                panic!(
                    "options {:?} were refused",
                    String::from_utf8_lossy(options)
                )
            });
        let (_, value) = crate::startup_parameters(&rewritten)
            .unwrap()
            .into_iter()
            .find(|(key, _)| *key == b"options")
            .unwrap();
        value.to_vec()
    }

    const AGENT: &str = "-c default_transaction_read_only=on";

    #[test]
    fn every_spike_escape_is_matched() {
        let escapes: [(&str, &str); 11] = [
            (
                "SET default_transaction_read_only = off",
                "default_transaction_read_only",
            ),
            (
                "SELECT set_config('default_transaction_read_only','off',false)",
                "set_config",
            ),
            (
                "SELECT set_config(name,'off',false) FROM pg_settings WHERE name LIKE '%read_only'",
                "set_config",
            ),
            (
                "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE",
                "read write",
            ),
            ("BEGIN READ WRITE", "read write"),
            ("BEGIN; SET TRANSACTION READ WRITE", "read write"),
            (
                "BEGIN; SET LOCAL transaction_read_only = off",
                "transaction_read_only",
            ),
            (
                "DO $$ BEGIN PERFORM set_config('default_transaction_read_only','off',false); END $$",
                "do",
            ),
            (
                "SELECT query_to_xml(concat('select set_', 'config(''default_transaction_read_only'',''off'',false)'), false, false, '')",
                "query_to_xml",
            ),
            ("SELECT U&\"\\0073et_config\"('x','y',false)", "u&"),
            (
                "SET/**/default_transaction_read_only = off",
                "default_transaction_read_only",
            ),
        ];
        for (text, word) in escapes {
            assert_eq!(scan(text.as_bytes(), false), Some(word), "{text}");
        }
    }

    #[test]
    fn ordinary_reads_with_near_miss_names_pass() {
        for text in [
            "select executed_at, program_id from global_settings",
            "select read_write_ratio from t",
            "select * from orders where note = 'do it'",
            "select readwrite, read_only, writer from t",
            "select \"read\", write from t",
            "select done, undo, todo from t; select doer from t",
            "select * from my_dblinks join ts_statistics using (id)",
            "select query_to_xml_x, my_set_config, set_configs from t",
            "select u & 1, menu.id from menu",
            "SELECT \"t\".\"id\", \"t\".\"name\" FROM \"public\".\"users\" AS \"t\" WHERE \"t\".\"id\" = $1 LIMIT $2 OFFSET $3",
            "SELECT users.id AS users_id FROM users WHERE users.email = %(email_1)s",
            "SELECT \"users\".* FROM \"users\" WHERE \"users\".\"id\" = $1 LIMIT $2",
            "SELECT * FROM \"users\" WHERE \"users\".\"deleted_at\" IS NULL ORDER BY \"users\".\"id\" LIMIT 1",
        ] {
            assert_eq!(scan(text.as_bytes(), false), None, "{text}");
        }
    }

    #[test]
    fn every_word_matches_alone_and_not_inside_a_longer_name() {
        let words = [
            "set_config",
            "default_transaction_read_only",
            "transaction_read_only",
            "query_to_xml",
            "query_to_xmlschema",
            "query_to_xml_and_xmlschema",
            "ts_stat",
            "ts_rewrite",
            "connectby",
            "xpath_table",
            "lo_export",
            "pg_file_write",
            "pg_file_rename",
            "pg_file_unlink",
        ];
        assert_eq!(
            super::WORDS,
            words,
            "the production words are the listed words"
        );
        for word in words {
            let upper = word.to_ascii_uppercase();
            for text in [
                word.to_string(),
                format!("select {word}(1)"),
                format!("select pg_catalog.{word}(1)"),
                format!("select \"{upper}\"(1)"),
                format!("select '{word}'"),
                format!("select 1 /* {word} */"),
                format!("select 1;{upper}"),
            ] {
                assert_eq!(scan(text.as_bytes(), false), Some(word), "{text}");
            }
            for text in [
                format!("select x{word}(1)"),
                format!("select {word}x(1)"),
                format!("select _{word}"),
                format!("select {word}_"),
                format!("select ${word}"),
                format!("select {word}$1"),
                format!("select 0{word}"),
                format!("select {word}9"),
            ] {
                assert_eq!(scan(text.as_bytes(), false), None, "{text}");
            }
        }
    }

    #[test]
    fn crosstab_matches_as_a_prefix_of_every_crosstab_function() {
        for text in [
            "select * from crosstab('select 1') as t(a int)",
            "SELECT * FROM crosstab2('select set' || '_config(''x'', ''off'', false), ''a''::text, ''b''::text')",
            "select * from crosstab3('q')",
            "select * from CROSSTAB4('q')",
            "select * from public.crosstab_hash('q', 'r')",
            "select \"crosstab2\"('q')",
        ] {
            for superuser in [false, true] {
                assert_eq!(scan(text.as_bytes(), superuser), Some(CROSSTAB), "{text}");
            }
        }
        for text in ["select my_crosstab from t", "select xcrosstab2 from t"] {
            assert_eq!(scan(text.as_bytes(), false), None, "{text}");
        }
    }

    #[test]
    fn dblink_matches_as_a_prefix_of_every_dblink_function() {
        for text in [
            "dblink",
            "select * from dblink('dbname=x', 'select 1') as t(a int)",
            "select dblink_exec('dbname=x', 'insert into t values (1)')",
            "select dblink_connect('c', 'dbname=x')",
            "select dblink_connect_u('c', 'dbname=x')",
            "select dblink_send_query('c', 'select 1')",
            "select dblink_open('c', 'cur', 'select 1')",
            "select pg_catalog.DBLINK_EXEC('x', 'y')",
            "select \"dblink_exec\"('x', 'y')",
            "select 1;DBLinkX",
            "select dblinks from t",
        ] {
            assert_eq!(scan(text.as_bytes(), false), Some("dblink"), "{text}");
        }
        for text in [
            "select xdblink('x')",
            "select my_dblink from t",
            "select $dblink_exec",
            "select 0dblink",
            "select \u{e9}dblink_exec('x', 'y')",
        ] {
            assert_eq!(scan(text.as_bytes(), false), None, "{text}");
        }
    }

    const SUPERUSER_WORDS: [&str; 9] = [
        "program",
        "pg_reload_conf",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "lo_import",
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "session_authorization",
    ];

    #[test]
    fn the_production_superuser_words_are_the_listed_words() {
        assert_eq!(super::SUPERUSER_WORDS, SUPERUSER_WORDS);
    }

    #[test]
    fn the_parameter_spellings_of_set_role_and_session_authorization_match() {
        for (text, word) in [
            (
                "SET session_authorization = 'other'",
                "session_authorization",
            ),
            (
                "set SESSION_AUTHORIZATION to other",
                "session_authorization",
            ),
            (
                "SET \"session_authorization\" = 'other'",
                "session_authorization",
            ),
            ("SHOW session_authorization", "session_authorization"),
            ("SET \"role\" = 'other'", "set role"),
            ("set \"ROLE\" to other", "set role"),
            ("SET \"Role\" = other", "set role"),
            ("SET\"role\" = other", "set role"),
            ("set/**/\"role\" = other", "set role"),
            ("set -- c\n\"role\" = other", "set role"),
            ("select 1; SET \"rOlE\" = other", "set role"),
            ("SET SESSION \"role\" = other", "set session role"),
            ("set session/* x */\"ROLE\" to other", "set session role"),
            ("SET LOCAL \"role\" = other", "set local role"),
            ("set\tlocal\n\"Role\" to other", "set local role"),
        ] {
            assert_eq!(scan(text.as_bytes(), true), Some(word), "{text:?}");
            assert_eq!(scan(text.as_bytes(), false), None, "{text:?}");
        }
        for text in [
            "select role from t",
            "SET \"roles\" = x",
            "SET \"my_role\" = x",
            "SET \"role_x\" = x",
            "SET x\"role\" = y",
            "RESET \"role\"",
            "SET SESSION x \"role\" = y",
            "set\"rol\" = x",
            "select session_authorizations",
            "select x_session_authorization",
        ] {
            assert_eq!(scan(text.as_bytes(), true), None, "{text:?}");
        }
    }

    #[test]
    fn every_superuser_word_matches_only_in_a_superuser_session() {
        for word in SUPERUSER_WORDS {
            let upper = word.to_ascii_uppercase();
            for text in [
                word.to_string(),
                format!("select {word}(1)"),
                format!("select pg_catalog.{word}(1)"),
                format!("select \"{upper}\"(1)"),
                format!("select '{word}'"),
                format!("select 1 /* {word} */"),
                format!("select 1;{upper}"),
            ] {
                assert_eq!(scan(text.as_bytes(), true), Some(word), "{text}");
                assert_eq!(scan(text.as_bytes(), false), None, "{text}");
            }
            for text in [
                format!("select x{word}(1)"),
                format!("select {word}x(1)"),
                format!("select _{word}"),
                format!("select {word}_"),
                format!("select ${word}"),
                format!("select {word}$1"),
                format!("select 0{word}"),
                format!("select {word}9"),
                format!("select \u{e9}{word}"),
            ] {
                assert_eq!(scan(text.as_bytes(), true), None, "{text}");
            }
        }
    }

    #[test]
    fn copy_with_a_program_is_matched_in_every_session() {
        for text in [
            "COPY t TO PROGRAM 'true'",
            "copy (select 1) to program 'true'",
            "COPY t FROM PROGRAM 'cat /etc/hostname'",
            "copy t to\tprogram\n'true'",
            "copy t to/**/program 'true'",
            "copy t to -- c\nprogram 'true'",
            "COPY t TO PROGRAM E'true'",
            "COPY t TO PROGRAM $$true$$",
            "SET ROLE admin; COPY t TO PROGRAM 'true'",
            "COPY t FROM PROGRAM /* c */ 'true'",
        ] {
            assert_eq!(scan(text.as_bytes(), false), Some("copy program"), "{text}");
            assert!(scan(text.as_bytes(), true).is_some(), "{text}");
        }
        for text in [
            "select program_id from t",
            "select programs from t",
            "select my_program from t",
            "select to_program from t",
            "select a from t where b similar to 'x%'",
            "SELECT * FROM program WHERE id = 1",
            "SELECT * FROM program.courses",
            "SET search_path TO program",
            "select 'moved to program X'",
            "COPY (SELECT * FROM program WHERE id = 1) TO STDOUT",
            "copy program to stdout",
        ] {
            assert_eq!(scan(text.as_bytes(), false), None, "{text}");
        }
    }

    #[test]
    fn copy_to_a_server_file_is_matched_in_every_session() {
        for text in [
            "COPY t TO '/tmp/out.csv'",
            "copy (select 1) to '/tmp/out'",
            "COPY t TO E'/tmp/out'",
            "copy t to e'/tmp/out'",
            "COPY t TO $$/tmp/out$$",
            "COPY t TO $f$/tmp/out$f$",
            "copy t to/**/'/tmp/out'",
            "copy t to -- c\n'/tmp/out'",
            "COPY BINARY t TO '/tmp/out'",
            "select 1; COPY t TO '/tmp/out'",
            "COPY (SELECT ';') TO '/tmp/out'",
        ] {
            for superuser in [false, true] {
                assert_eq!(
                    scan(text.as_bytes(), superuser),
                    Some("copy to file"),
                    "{text}"
                );
            }
        }
        for text in [
            "COPY t TO STDOUT",
            "copy (select 1) to stdout with (format csv)",
            "COPY t TO STDOUT; select 'x'",
            "select a from t where b similar to 'x%'",
            "select 'copy' from t",
            "select copy_count from t where x similar to 'y'",
            "select a from t where a::text similar to 'y'",
        ] {
            assert_eq!(scan(text.as_bytes(), false), None, "{text}");
        }
    }

    #[test]
    fn every_superuser_phrase_matches_with_blanks_and_comments_between() {
        for (first, second) in [
            ("alter", "system"),
            ("session", "authorization"),
            ("set", "role"),
        ] {
            let phrase = format!("{first} {second}");
            let upper = phrase.to_ascii_uppercase();
            for text in [
                phrase.clone(),
                format!("{first}  {second} x"),
                format!("{first}\n\t{second}"),
                format!("{first}/**/{second}"),
                format!("{first} /* a /* nested */ b */ {second}"),
                format!("{first} -- c\n{second}"),
                format!("select 1; {upper}"),
                format!("select '{phrase}'"),
                format!("{first}\x0b\x0c{second}"),
            ] {
                assert_eq!(
                    scan(text.as_bytes(), true),
                    Some(phrase.as_str()),
                    "{text:?}"
                );
                assert_eq!(scan(text.as_bytes(), false), None, "{text:?}");
            }
            let joined = format!("{first}_{second}");
            let parameter = (joined == "session_authorization").then_some(joined.as_str());
            assert_eq!(scan(joined.as_bytes(), true), parameter, "{joined:?}");
            for text in [
                format!("{first}{second}"),
                format!("{first}, {second}"),
                format!("x{first} {second}"),
                format!("{first} {second}x"),
                format!("{first} /* unterminated {second}"),
                format!("{first} -- {second}"),
                format!("{first}\u{a0}{second}"),
            ] {
                assert_eq!(scan(text.as_bytes(), true), None, "{text:?}");
            }
        }
        for text in [
            "ALTER SYSTEM SET work_mem = '64MB'",
            "SET SESSION AUTHORIZATION other",
            "set session authorization default",
            "SET ROLE other",
        ] {
            assert!(scan(text.as_bytes(), true).is_some(), "{text}");
            assert_eq!(scan(text.as_bytes(), false), None, "{text}");
        }
        for text in [
            "reset role",
            "select role from t where system = 1",
            "alter table t set (fillfactor = 70)",
        ] {
            assert_eq!(scan(text.as_bytes(), true), None, "{text}");
        }
    }

    #[test]
    fn set_session_role_and_set_local_role_match_with_blanks_and_comments_between() {
        for (middle, phrase) in [("session", "set session role"), ("local", "set local role")] {
            let upper = phrase.to_ascii_uppercase();
            for text in [
                format!("set {middle} role other"),
                format!("SET {} ROLE other", middle.to_ascii_uppercase()),
                format!("set\t{middle}\n role"),
                format!("set/**/{middle}/**/role"),
                format!("set /* a /* nested */ b */ {middle} -- c\nrole"),
                format!("set {middle}\x0b\x0crole"),
                format!("begin; {upper} other"),
                format!("select '{phrase}'"),
            ] {
                assert_eq!(scan(text.as_bytes(), true), Some(phrase), "{text:?}");
                assert_eq!(scan(text.as_bytes(), false), None, "{text:?}");
            }
            for text in [
                format!("set {middle}role"),
                format!("set{middle} role"),
                format!("set {middle}_role"),
                format!("set {middle}, role"),
                format!("set {middle} roles"),
                format!("reset {middle} role"),
                format!("set {middle} /* unterminated role"),
                format!("set {middle} -- role"),
                format!("set {middle}\u{a0}role"),
                format!("set {middle} x role"),
            ] {
                assert_eq!(scan(text.as_bytes(), true), None, "{text:?}");
            }
        }
        assert_eq!(
            scan(b"SET SESSION AUTHORIZATION other", true),
            Some("session authorization")
        );
        assert_eq!(scan(b"SET ROLE other", true), Some("set role"));
    }

    #[test]
    fn a_superuser_session_still_matches_every_ordinary_word() {
        assert_eq!(
            scan(b"SET default_transaction_read_only = off", true),
            Some("default_transaction_read_only")
        );
        assert_eq!(scan(b"select dblink_exec('x', 'y')", true), Some("dblink"));
        assert_eq!(scan(b"begin read write", true), Some("read write"));
        assert_eq!(scan(b"select 1; do $$ $$", true), Some("do"));
        assert_eq!(scan(b"select u&'x'", true), Some("u&"));
    }

    fn status(name: &str, value: &str) -> Vec<u8> {
        let mut body = name.as_bytes().to_vec();
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
        body
    }

    #[test]
    fn parameter_status_reads_the_mode_and_the_superuser_flag() {
        let read_only = "default_transaction_read_only";
        assert_eq!(
            parameter_status(&status(read_only, "on")),
            Some(Status::ReadOnly)
        );
        for value in ["off", "On", "ON", "", "true", "on "] {
            assert_eq!(
                parameter_status(&status(read_only, value)),
                Some(Status::Escaped),
                "{value:?}"
            );
        }
        assert_eq!(
            parameter_status(&status("is_superuser", "on")),
            Some(Status::Superuser)
        );
        assert_eq!(
            parameter_status(&status("is_superuser", "off")),
            Some(Status::Other)
        );
        assert_eq!(
            parameter_status(&status("Default_Transaction_Read_Only", "off")),
            Some(Status::Other)
        );
        for bad in [&b""[..], b"x", b"x\0", b"x\0y", b"x\0y\0z", b"x\0y\0\0"] {
            assert_eq!(parameter_status(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn startup_tail_fails_closed_on_a_mode_other_than_on() {
        let frame_status = |name, value| frame(b'S', &status(name, value));
        let key = frame(b'K', &[0, 0, 0, 7, 0, 0, 0, 9]);
        let tail = [
            frame_status("server_version", "16.4"),
            frame_status("server_encoding", "UTF8"),
            frame_status("default_transaction_read_only", "on"),
            frame_status("is_superuser", "off"),
            key.clone(),
        ]
        .concat();
        assert_eq!(startup_check(&tail), Start::Confirmed { superuser: false });
        let superuser = [tail.clone(), frame_status("is_superuser", "on")].concat();
        assert_eq!(
            startup_check(&superuser),
            Start::Confirmed { superuser: true }
        );
        assert_eq!(startup_check(&[]), Start::Refused, "no report of the mode");
        let unreported = [
            frame_status("server_version", "16.4"),
            frame_status("is_superuser", "on"),
            key.clone(),
        ]
        .concat();
        assert_eq!(
            startup_check(&unreported),
            Start::Refused,
            "no report of the mode"
        );
        let escaped = [
            frame_status("default_transaction_read_only", "off"),
            key.clone(),
        ]
        .concat();
        assert_eq!(startup_check(&escaped), Start::Refused);
        let mut truncated = tail.clone();
        truncated.pop();
        assert_eq!(startup_check(&truncated), Start::Refused);
        assert_eq!(startup_check(&[b'S', 0, 0, 0, 3]), Start::Refused);
    }

    #[test]
    fn startup_tail_fails_closed_on_a_single_byte_server_encoding() {
        let frame_status = |name: &str, value: &str| frame(b'S', &status(name, value));
        let tail = |encoding: Option<&str>| {
            [
                encoding
                    .map(|encoding| frame_status("server_encoding", encoding))
                    .unwrap_or_default(),
                frame_status("default_transaction_read_only", "on"),
                frame(b'K', &[0, 0, 0, 7, 0, 0, 0, 9]),
            ]
            .concat()
        };
        for encoding in [
            "UTF8",
            "EUC_JP",
            "EUC_CN",
            "EUC_KR",
            "EUC_TW",
            "EUC_JIS_2004",
            "MULE_INTERNAL",
        ] {
            assert_eq!(
                startup_check(&tail(Some(encoding))),
                Start::Confirmed { superuser: false },
                "{encoding}"
            );
        }
        for encoding in [
            "LATIN1",
            "LATIN5",
            "SQL_ASCII",
            "WIN1254",
            "utf8",
            "UTF-8",
            "",
            "SJIS",
            "GB18030",
        ] {
            assert_eq!(
                startup_check(&tail(Some(encoding))),
                Start::Refused,
                "{encoding}"
            );
        }
        assert_eq!(
            startup_check(&tail(None)),
            Start::Refused,
            "no encoding reported"
        );
        let replaced = [
            frame_status("server_encoding", "UTF8"),
            tail(Some("LATIN5")),
        ]
        .concat();
        assert_eq!(
            startup_check(&replaced),
            Start::Refused,
            "the last report counts"
        );
    }

    #[test]
    fn a_server_older_than_14_is_confirmed_by_a_query() {
        let frame_status = |name: &str, value: &str| frame(b'S', &status(name, value));
        let key = frame(b'K', &[0, 0, 0, 7, 0, 0, 0, 9]);
        let tail = |version: &str, encoding: &str, superuser: &str| {
            [
                frame_status("server_version", version),
                frame_status("server_encoding", encoding),
                frame_status("is_superuser", superuser),
                key.clone(),
            ]
            .concat()
        };
        for version in [
            "13.16",
            "13beta1",
            "12.20 (Debian 12.20-1)",
            "9.6.24",
            "10.23",
        ] {
            assert_eq!(
                startup_check(&tail(version, "UTF8", "off")),
                Start::Unreported { superuser: false },
                "{version}"
            );
        }
        assert_eq!(
            startup_check(&tail("13.16", "UTF8", "on")),
            Start::Unreported { superuser: true }
        );
        for version in [
            "14.0",
            "16.4",
            "17beta2",
            "",
            "x13",
            "13x",
            " 13.1",
            "13.0.0",
            "11.2-YB-2.18.0.0-b0",
            "12.1.2.3",
            "13.4-custom",
        ] {
            assert_eq!(
                startup_check(&tail(version, "UTF8", "off")),
                Start::Refused,
                "{version:?}"
            );
        }
        assert_eq!(
            startup_check(&tail("13.16", "LATIN5", "off")),
            Start::Refused,
            "a single-byte encoding fails closed on every version"
        );
        let off = [
            tail("13.16", "UTF8", "off"),
            frame_status("default_transaction_read_only", "off"),
        ]
        .concat();
        assert_eq!(startup_check(&off), Start::Refused, "a reported off wins");
        let on = [
            tail("13.16", "UTF8", "off"),
            frame_status("default_transaction_read_only", "on"),
        ]
        .concat();
        assert_eq!(startup_check(&on), Start::Confirmed { superuser: false });
        let cockroach = [
            tail("13.16", "UTF8", "off"),
            frame_status("crdb_version", "CockroachDB CCL v23.1.0"),
        ]
        .concat();
        assert_eq!(startup_check(&cockroach), Start::Refused, "not PostgreSQL");
        let no_version = [frame_status("server_encoding", "UTF8"), key.clone()].concat();
        assert_eq!(startup_check(&no_version), Start::Refused);
    }

    #[test]
    fn the_confirmation_answer_must_be_exactly_on() {
        let row = |value: &[u8]| {
            let mut body = 1u16.to_be_bytes().to_vec();
            body.extend_from_slice(&(value.len() as u32).to_be_bytes());
            body.extend_from_slice(value);
            frame(b'D', &body)
        };
        let description = frame(b'T', b"\0\x01default_transaction_read_only\0rest");
        let complete = frame(b'C', b"SHOW\0");
        let ready = frame(b'Z', b"I");
        let notice = frame(b'N', b"SNOTICE\0Mx\0\0");
        let answer = |parts: &[&[u8]]| parts.concat();
        let good = answer(&[&description, &row(b"on"), &complete, &ready]);
        assert_eq!(confirmation(&good), Some(good.len()));
        let noticed = answer(&[&notice, &description, &row(b"on"), &complete, &ready]);
        assert_eq!(confirmation(&noticed), Some(noticed.len()));
        for bad in [
            answer(&[&description, &row(b"off"), &complete, &ready]),
            answer(&[&description, &row(b"On"), &complete, &ready]),
            answer(&[&description, &complete, &ready]),
            answer(&[&description, &row(b"on"), &row(b"on"), &complete, &ready]),
            answer(&[&frame(b'E', b"SERROR\0C42501\0Mx\0\0"), &ready]),
            answer(&[&description, &row(b"on"), &complete, &frame(b'Z', b"T")]),
            answer(&[
                &description,
                &row(b"on"),
                &frame(b'S', b"a\0b\0"),
                &complete,
                &ready,
            ]),
        ] {
            assert_eq!(confirmation(&bad), None, "{bad:?}");
        }
        let unfinished = answer(&[&description, &row(b"on"), &complete]);
        assert_eq!(confirmation(&unfinished), Some(0), "needs more bytes");
        let mut truncated = good.clone();
        truncated.pop();
        assert_eq!(confirmation(&truncated), Some(0), "needs more bytes");
        let mut null = 1u16.to_be_bytes().to_vec();
        null.extend_from_slice(&(-1i32).to_be_bytes());
        let null_row = frame(b'D', &null);
        assert_eq!(
            confirmation(&answer(&[&description, &null_row, &complete, &ready])),
            None
        );
    }

    const HELD: std::time::Duration = std::time::Duration::from_millis(200);
    const PROMPT: std::time::Duration = std::time::Duration::from_secs(2);

    async fn admitted(units: &mut Units, gate: &Gate, tag: u8) -> bool {
        tokio::time::timeout(HELD, units.admit(gate, tag))
            .await
            .is_ok_and(|admitted| admitted.is_ok())
    }

    #[tokio::test]
    async fn a_ready_signal_that_arrives_before_the_wait_is_not_lost() {
        let gate = Gate::new(false);
        let mut units = Units::default();
        assert!(admitted(&mut units, &gate, b'Q').await);
        assert!(
            !admitted(&mut units, &gate, b'Q').await,
            "held before ReadyForQuery"
        );
        assert!(gate.ready());
        assert!(admitted(&mut units, &gate, b'Q').await);
        assert!(
            !admitted(&mut units, &gate, b'Q').await,
            "the permit stored by the earlier signal does not release the next unit"
        );

        assert!(gate.ready());
        assert!(
            tokio::time::timeout(PROMPT, units.admit(&gate, b'Q'))
                .await
                .is_ok(),
            "a ready signal sent before the wait releases it"
        );

        let (admitted, signalled) = tokio::join!(
            tokio::time::timeout(PROMPT, units.admit(&gate, b'Q')),
            async {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                gate.ready()
            }
        );
        assert!(
            admitted.is_ok() && signalled,
            "a signal during the wait releases it"
        );
        assert!(gate.ready());
        assert!(!gate.ready(), "a ReadyForQuery with no unit is a violation");
    }

    #[tokio::test]
    async fn copy_data_terminate_and_flush_are_never_held() {
        let gate = Gate::new(false);
        let mut units = Units::default();
        assert!(admitted(&mut units, &gate, b'Q').await);
        for tag in *b"dcfHX" {
            assert!(admitted(&mut units, &gate, tag).await, "{}", tag as char);
        }
        assert!(!admitted(&mut units, &gate, b'P').await);
    }

    #[tokio::test]
    async fn a_unit_ends_at_its_sync_and_a_query_inside_it_is_refused() {
        let gate = Gate::new(false);
        let mut units = Units::default();
        for tag in *b"PBDEHBECS" {
            assert!(admitted(&mut units, &gate, tag).await, "{}", tag as char);
        }
        for tag in *b"PSQF" {
            assert!(!admitted(&mut units, &gate, tag).await, "{}", tag as char);
        }
        assert!(gate.ready());
        assert!(admitted(&mut units, &gate, b'P').await);
        assert!(matches!(
            units.admit(&gate, b'Q').await,
            Err(PostgresError::BadFraming)
        ));
        assert!(matches!(
            units.admit(&gate, b'F').await,
            Err(PostgresError::BadFraming)
        ));
    }

    #[tokio::test]
    async fn a_sync_after_copy_messages_counts_and_waits_like_any_unit() {
        let gate = Gate::new(false);
        let mut units = Units::default();
        for tag in *b"PBEcS" {
            assert!(admitted(&mut units, &gate, tag).await, "{}", tag as char);
        }
        assert!(
            !admitted(&mut units, &gate, b'S').await,
            "a second Sync is a new unit"
        );
        assert!(gate.ready());
        assert!(admitted(&mut units, &gate, b'S').await);
        assert!(!admitted(&mut units, &gate, b'Q').await);
        assert!(gate.ready());
        assert!(admitted(&mut units, &gate, b'Q').await);
        assert!(
            !admitted(&mut units, &gate, b'Q').await,
            "each unit waits for its own ReadyForQuery"
        );
        assert!(gate.ready());
        assert!(gate.state().idle());
        assert!(!gate.ready(), "no ReadyForQuery is banked");
    }

    #[test]
    fn non_ascii_neighbours_are_identifier_bytes() {
        for text in [
            &b"select \xc3\xa9set_config(1)"[..],
            b"select set_config\xc3\xa9(1)",
            b"select \xe3\x80\x80set_config(1)",
            b"select set_config\xe3\x80\x80(1)",
            b"begin read\xc2\xa0write",
            b"begin \x83read write\x83",
        ] {
            assert_eq!(scan(text, false), None, "{}", String::from_utf8_lossy(text));
        }
        assert_eq!(
            scan(b"select \xc3\xa9 set_config(1)", false),
            Some("set_config")
        );
    }

    #[test]
    fn u_ampersand_matches_anywhere_in_any_case() {
        for text in [
            "select U&\"\\0064\"",
            "select u&'\\0064'",
            "select xu&y",
            "select 1 -- u&",
        ] {
            assert_eq!(scan(text.as_bytes(), false), Some("u&"), "{text}");
        }
        assert_eq!(scan(b"select u &1, u.id", false), None);
    }

    #[test]
    fn do_is_matched_only_as_the_first_word_of_a_statement() {
        for text in [
            "do $$ begin null; end $$",
            "DO 'begin null; end'",
            "  \t\n do $$ $$",
            "/* c */ DO $$ $$",
            "/* a /* nested */ b */ do $$ $$",
            "-- line\nDO $$ $$",
            "select 1; do $$ $$",
            "select 1;do $$ $$",
            "select 1;/*x*/\r\n--y\rDo $$ $$",
            ";do",
            "select ';'; do $$ $$",
            "select ';/*'; do $$ $$; select '*/'",
        ] {
            assert_eq!(scan(text.as_bytes(), false), Some("do"), "{text:?}");
        }
        for text in [
            "select 'do'",
            "select x from t where note = 'do it'",
            "select 1; select do_it()",
            ";done",
            "do$$ $$",
            "select 1 do",
            "select 1; /* do */ select 2",
            "select 1; -- do\nselect 2",
            "select 1; /* unterminated do",
        ] {
            assert_eq!(scan(text.as_bytes(), false), None, "{text:?}");
        }
    }

    #[test]
    fn read_write_matches_with_blanks_and_comments_between() {
        for text in [
            "begin read write",
            "BEGIN READ\n\t  WRITE",
            "begin read/**/write",
            "begin READ /* a /* nested */ b */ WRITE",
            "begin read -- c\nwrite",
            "begin read\x0b\x0cwrite",
            "set transaction isolation level read committed read write",
        ] {
            assert_eq!(scan(text.as_bytes(), false), Some("read write"), "{text:?}");
        }
        for text in [
            "begin read, write",
            "begin read write_x",
            "begin read only",
            "begin read /* unterminated write",
            "begin read -- write",
            "select read_write",
        ] {
            assert_eq!(scan(text.as_bytes(), false), None, "{text:?}");
        }
    }

    #[test]
    fn overlapping_comments_after_semicolons_finish_in_linear_time() {
        let mut text = b";/*".repeat(200_000);
        text.extend_from_slice(&b"*/".repeat(200_000));
        let started = std::time::Instant::now();
        let _ = scan(&text, false);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let mut text = b"read /*".repeat(200_000);
        text.extend_from_slice(&b"*/".repeat(200_000));
        let started = std::time::Instant::now();
        let _ = scan(&text, false);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn startup_drops_client_overrides_and_puts_agent_option_last() {
        let client = startup(&[
            ("user", b"app"),
            ("default_transaction_read_only", b"off"),
            ("database", b"appdb"),
            ("DEFAULT_TRANSACTION_READ_ONLY", b"off"),
            ("Transaction_Read_Only", b"off"),
            ("default-transaction-read-only", b"off"),
            ("application_name", b"orders"),
            ("_pq_.extension", b"1"),
            ("options", b"-c x.y=1\\"),
        ]);
        let expected = startup(&[
            ("user", b"app"),
            ("database", b"appdb"),
            ("application_name", b"orders"),
            ("_pq_.extension", b"1"),
            ("options", b"-cx.y=1 -c default_transaction_read_only=on"),
        ]);
        assert_eq!(read_only_startup(&client).unwrap(), expected);
        let plain = startup(&[("user", b"app"), ("database", b"appdb")]);
        let expected = startup(&[
            ("user", b"app"),
            ("database", b"appdb"),
            ("options", AGENT.as_bytes()),
        ]);
        assert_eq!(read_only_startup(&plain).unwrap(), expected);
    }

    #[test]
    fn every_option_form_that_names_a_setting_is_removed() {
        for options in [
            &b"-c default_transaction_read_only=off"[..],
            b"-cdefault_transaction_read_only=off",
            b"--default-transaction-read-only=off",
            b"--default_transaction_read_only=off",
            b"-c Default-Transaction_READ_ONLY=off",
            b"-c transaction_read_only=off",
            b"-ec default_transaction_read_only=off",
            b"-secdefault_transaction_read_only=off",
            b"\t -c\tdefault_transaction_read_only=off  ",
            b"-c default_transaction_read_only",
            b"-c default_transaction_read_only=on -c default_transaction_read_only=off",
        ] {
            let rewritten = rewritten_options(options);
            let text = String::from_utf8_lossy(&rewritten).into_owned();
            assert!(text.ends_with(AGENT), "{text}");
            assert!(
                !text.trim_end_matches(AGENT).contains("read"),
                "{text} from {:?}",
                String::from_utf8_lossy(options)
            );
        }
        assert_eq!(
            rewritten_options(b"-ec x.y=1"),
            b"-e -cx.y=1 -c default_transaction_read_only=on"
        );
    }

    #[test]
    fn kept_options_are_escaped_so_the_server_reads_the_same_items() {
        assert_eq!(
            rewritten_options(b"-c application_name=a\\ b -c search_path=x\\\\y --work-mem=4MB"),
            b"-capplication_name=a\\ b -csearch_path=x\\\\y --work-mem=4MB -c default_transaction_read_only=on"
        );
        assert_eq!(
            rewritten_options(b"-c application_name=caf\xc3\xa9\\\tx"),
            b"-capplication_name=caf\\\xc3\\\xa9\\\tx -c default_transaction_read_only=on"
        );
        assert_eq!(
            rewritten_options(b"-c x.y=-c\\ default_transaction_read_only=off"),
            b"-cx.y=-c\\ default_transaction_read_only=off -c default_transaction_read_only=on"
        );
    }

    #[test]
    fn an_options_string_that_cannot_be_parsed_with_certainty_is_refused() {
        for options in [
            &b"-q"[..],
            b"-c x.y=1 \\",
            b"-c",
            b"-c x.y=1 extra",
            b"extra",
            b"-",
            b"--",
            b"-- -c x.y=1",
            b"-e7",
        ] {
            assert!(
                read_only_startup(&startup(&[("user", b"app"), ("options", options)])).is_err(),
                "{:?}",
                String::from_utf8_lossy(options)
            );
        }
        let twice = startup(&[
            ("user", b"app"),
            ("options", b"-c x.y=1"),
            ("options", b"-c x.y=2"),
        ]);
        assert!(read_only_startup(&twice).is_err());
        let mut unterminated = startup(&[("user", b"app")]);
        unterminated.pop();
        let length = unterminated.len() as u32;
        unterminated[..4].copy_from_slice(&length.to_be_bytes());
        assert!(read_only_startup(&unterminated).is_err());
        let mut trailing = startup(&[("user", b"app")]);
        trailing.extend_from_slice(b"x\0");
        let length = trailing.len() as u32;
        trailing[..4].copy_from_slice(&length.to_be_bytes());
        assert!(read_only_startup(&trailing).is_err());
    }
}
