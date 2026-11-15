use crate::{PostgresError, Result};

pub const QUERY_REFUSAL: &str = "DO $$ BEGIN RAISE EXCEPTION USING ERRCODE = '25006', MESSAGE = 'zs: refused, read-only resource'; END $$";
pub const PARSE_REFUSAL: &str = "SELECT zs_refused_read_only_resource()";
pub const READ_ONLY_REASON: &str = "read-only";

pub(crate) const SCREENED: &[u8] = b"QPF";
pub(crate) const STREAMED: &[u8] = b"BCcdDEfHpSX";
pub(crate) const MAX_SCREENED_MESSAGE: u32 = 0x3fff_ffff;

const FUNCTION_CALL: &str = "function_call";
const AGENT_OPTION: &[u8] = b"-c default_transaction_read_only=on";
const SETTINGS: [&[u8]; 2] = [b"default_transaction_read_only", b"transaction_read_only"];
const ARGUMENT_OPTIONS: &[u8] = b"BCcDdfhkNprStvW-";
const FLAG_OPTIONS: &[u8] = b"bEeFijlnOPsT";
const WORDS: [&str; 8] = [
    "set_config",
    "default_transaction_read_only",
    "transaction_read_only",
    "query_to_xml",
    "query_to_xmlschema",
    "query_to_xml_and_xmlschema",
    "ts_stat",
    "ts_rewrite",
];
const DBLINK: &str = "dblink";
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

pub fn scan(text: &[u8], _superuser: bool) -> Option<&'static str> {
    let mut budget = 4 * text.len() + 1024;
    for at in 0..text.len() {
        if let Some(word) = WORDS.iter().find(|word| word_at(text, at, word)) {
            return Some(word);
        }
        if prefix_at(text, at, DBLINK) {
            return Some(DBLINK);
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

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        ];
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
