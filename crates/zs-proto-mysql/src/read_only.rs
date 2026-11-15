pub const REFUSAL: &str = "SIGNAL SQLSTATE '25006' SET MESSAGE_TEXT = 'zs: refused, read-only resource', MYSQL_ERRNO = 1792";
pub const READ_ONLY_REASON: &str = "read-only";
pub const SESSION_START: &str = "SET SESSION transaction_read_only = ON";
pub const MAX_SCREENED_COMMAND: usize = 64 << 20;

const WORDS: [&str; 11] = [
    "transaction_read_only",
    "tx_read_only",
    "prepare",
    "execute",
    "execute_prepared_stmt",
    "outfile",
    "dumpfile",
    "global",
    "kill",
    "shutdown",
    "load_file",
];
const PERSIST: &str = "persist";
const TOKENS: [&str; 2] = ["/*!", "/*m!"];
const READ_WRITE: &str = "read write";
const QUERY_ATTRIBUTES: &str = "query_attributes";
const EMPTY_ATTRIBUTES: [u8; 2] = [0x00, 0x01];

const COM_QUIT: u8 = 0x01;
const COM_INIT_DB: u8 = 0x02;
const COM_QUERY: u8 = 0x03;
const COM_FIELD_LIST: u8 = 0x04;
const COM_STATISTICS: u8 = 0x09;
const COM_PING: u8 = 0x0e;
const COM_STMT_PREPARE: u8 = 0x16;
const COM_STMT_EXECUTE: u8 = 0x17;
const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
const COM_STMT_CLOSE: u8 = 0x19;
const COM_STMT_RESET: u8 = 0x1a;
const COM_SET_OPTION: u8 = 0x1b;
const COM_STMT_FETCH: u8 = 0x1c;
const STREAMED: [u8; 11] = [
    COM_QUIT,
    COM_INIT_DB,
    COM_FIELD_LIST,
    COM_STATISTICS,
    COM_PING,
    COM_STMT_EXECUTE,
    COM_STMT_SEND_LONG_DATA,
    COM_STMT_CLOSE,
    COM_STMT_RESET,
    COM_SET_OPTION,
    COM_STMT_FETCH,
];

pub(crate) enum Kind {
    Screened,
    Streamed,
    Refused,
}

pub(crate) enum Refused {
    Word(&'static str),
    Command(&'static str, &'static str),
}

pub(crate) fn names_mariadb(server_version: &[u8]) -> bool {
    server_version
        .windows(7)
        .any(|found| found.eq_ignore_ascii_case(b"mariadb"))
}

pub(crate) fn kind(command: Option<u8>) -> Kind {
    match command {
        Some(COM_QUERY | COM_STMT_PREPARE) => Kind::Screened,
        Some(byte) if STREAMED.contains(&byte) => Kind::Streamed,
        _ => Kind::Refused,
    }
}

pub(crate) fn command_name(command: Option<u8>) -> &'static str {
    match command {
        None => "empty",
        Some(0x00) => "com_sleep",
        Some(COM_QUERY) => "com_query",
        Some(0x05) => "com_create_db",
        Some(0x06) => "com_drop_db",
        Some(0x07) => "com_refresh",
        Some(0x08) => "com_shutdown",
        Some(0x0a) => "com_process_info",
        Some(0x0b) => "com_connect",
        Some(0x0c) => "com_process_kill",
        Some(0x0d) => "com_debug",
        Some(0x0f) => "com_time",
        Some(0x10) => "com_delayed_insert",
        Some(0x12) => "com_binlog_dump",
        Some(0x13) => "com_table_dump",
        Some(0x14) => "com_connect_out",
        Some(0x15) => "com_register_slave",
        Some(COM_STMT_PREPARE) => "com_stmt_prepare",
        Some(0x1d) => "com_daemon",
        Some(0x1e) => "com_binlog_dump_gtid",
        Some(0x1f) => "com_reset_connection",
        Some(0x20) => "com_clone",
        Some(0x21) => "com_subscribe_group_replication_stream",
        Some(_) => "unknown",
    }
}

fn identifier(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

fn blank(byte: u8) -> bool {
    byte <= b' ' || byte >= 0x80
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

fn line_end(text: &[u8], at: usize) -> usize {
    text[at..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(text.len(), |end| at + end + 1)
}

fn comment_end(text: &[u8], at: usize) -> usize {
    text[at + 2..]
        .windows(2)
        .position(|pair| pair == b"*/")
        .map_or(text.len(), |end| at + 2 + end + 2)
}

fn skip_blank(text: &[u8], mut at: usize, budget: &mut usize) -> Option<usize> {
    loop {
        let from = at;
        let rest = &text[at..];
        if rest.first().is_some_and(|byte| blank(*byte)) {
            at += 1;
        } else if rest.starts_with(b"#") || rest.starts_with(b"--") {
            at = line_end(text, at);
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

pub fn scan(text: &[u8]) -> Option<&'static str> {
    let mut budget = 4 * text.len() + 1024;
    for at in 0..text.len() {
        if let Some(token) = TOKENS.iter().find(|token| {
            text.get(at..at + token.len())
                .is_some_and(|found| found.eq_ignore_ascii_case(token.as_bytes()))
        }) {
            return Some(token);
        }
        if !text[at].is_ascii_alphabetic() || (at > 0 && identifier(text[at - 1])) {
            continue;
        }
        if let Some(word) = WORDS.iter().find(|word| word_at(text, at, word)) {
            return Some(word);
        }
        if prefix_at(text, at, PERSIST) {
            return Some(PERSIST);
        }
        if word_at(text, at, "read") && followed_by(text, at + 4, "write", &mut budget) {
            return Some(READ_WRITE);
        }
    }
    None
}

fn with_header(command: u8, attributes: bool, text: &str) -> Vec<u8> {
    let mut out = vec![command];
    if attributes {
        out.extend_from_slice(&EMPTY_ATTRIBUTES);
    }
    out.extend_from_slice(text.as_bytes());
    out
}

pub(crate) fn session_start(attributes: bool) -> Vec<u8> {
    with_header(COM_QUERY, attributes, SESSION_START)
}

fn query_refusal(attributes: bool) -> Vec<u8> {
    with_header(COM_QUERY, attributes, REFUSAL)
}

pub(crate) fn refusal(payload: &[u8], attributes: bool) -> Option<(Refused, Vec<u8>)> {
    match payload.first().copied() {
        Some(COM_QUERY) => {
            let text = if attributes {
                match payload.get(1..3) {
                    Some(header) if header == EMPTY_ATTRIBUTES => &payload[3..],
                    _ => {
                        return Some((Refused::Word(QUERY_ATTRIBUTES), query_refusal(attributes)));
                    }
                }
            } else {
                &payload[1..]
            };
            scan(text).map(|word| (Refused::Word(word), query_refusal(attributes)))
        }
        Some(COM_STMT_PREPARE) => scan(&payload[1..]).map(|word| {
            (
                Refused::Word(word),
                with_header(COM_STMT_PREPARE, false, REFUSAL),
            )
        }),
        command => Some((
            Refused::Command(command_name(command), "not_allowed"),
            query_refusal(attributes),
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const WORDS: [&str; 11] = [
        "transaction_read_only",
        "tx_read_only",
        "prepare",
        "execute",
        "execute_prepared_stmt",
        "outfile",
        "dumpfile",
        "global",
        "kill",
        "shutdown",
        "load_file",
    ];

    fn found(text: &str) -> Option<&'static str> {
        scan(text.as_bytes())
    }

    #[test]
    fn every_spike_escape_is_matched() {
        let escapes = [
            ("SET SESSION TRANSACTION READ WRITE", "read write"),
            (
                "SET @@session.transaction_read_only = 0",
                "transaction_read_only",
            ),
            ("/*!80000 set transaction_read_only = 0 */", "/*!"),
            ("START TRANSACTION READ WRITE", "read write"),
            ("SET TRANSACTION READ WRITE", "read write"),
            ("PREPARE s FROM @q", "prepare"),
            ("EXECUTE s", "execute"),
            (
                "CALL sys.execute_prepared_stmt(CONCAT('SET transaction', '_read_only = 0'))",
                "execute_prepared_stmt",
            ),
            ("SELECT * FROM t INTO OUTFILE '/tmp/zs-out.txt'", "outfile"),
            (
                "SELECT * FROM t INTO DUMPFILE '/tmp/zs-out.bin'",
                "dumpfile",
            ),
            ("SET GLOBAL max_connections = 200", "global"),
            ("SET @@GLOBAL.read_only = 0", "global"),
            ("SET PERSIST max_connections = 200", "persist"),
            ("SET PERSIST_ONLY max_connections = 200", "persist"),
            ("SET @@persist_only.max_connections = 200", "persist"),
            ("KILL 42", "kill"),
            ("SHUTDOWN", "shutdown"),
            ("SELECT LOAD_FILE('/etc/hostname')", "load_file"),
            ("SET SESSION tx_read_only = 0", "tx_read_only"),
        ];
        for (text, word) in escapes {
            assert_eq!(found(text), Some(word), "{text}");
        }
    }

    #[test]
    fn every_word_matches_alone_and_not_inside_a_longer_name() {
        for word in WORDS {
            assert_eq!(found(word), Some(word), "{word}");
            assert_eq!(found(&word.to_uppercase()), Some(word), "{word}");
            assert_eq!(found(&format!("SELECT `{word}`")), Some(word), "{word}");
            assert_eq!(found(&format!("SELECT '{word}'")), Some(word), "{word}");
            assert_eq!(found(&format!("SELECT 1 -- {word}")), Some(word), "{word}");
            assert_eq!(
                found(&format!("SELECT 1 /* {word} */")),
                Some(word),
                "{word}"
            );
            assert_eq!(found(&format!("SELECT a.{word}(1)")), Some(word), "{word}");
            assert_eq!(found(&format!("SELECT @@{word}")), Some(word), "{word}");
            for near in [
                format!("SELECT my_{word}"),
                format!("SELECT {word}s"),
                format!("SELECT {word}2"),
                format!("SELECT x{word}"),
                format!("SELECT ${word}"),
                format!("SELECT {word}$"),
            ] {
                assert_eq!(found(&near), None, "{near}");
            }
        }
    }

    #[test]
    fn persist_matches_as_a_prefix_and_never_after_an_identifier_byte() {
        for text in [
            "SET PERSIST x = 1",
            "SET PERSIST_ONLY x = 1",
            "set persist_only x = 1",
            "SET @@persist.x = 1",
            "SELECT persists",
            "RESET PERSIST x",
        ] {
            assert_eq!(found(text), Some("persist"), "{text}");
        }
        for text in ["SELECT is_persisted", "SELECT xpersist", "SELECT $persist"] {
            assert_eq!(found(text), None, "{text}");
        }
    }

    #[test]
    fn versioned_comment_tokens_match_without_a_word_rule() {
        for (text, token) in [
            ("/*!80000 SELECT 1 */", "/*!"),
            ("SELECT x/*!1*/", "/*!"),
            ("SELECT 1/*!*/", "/*!"),
            ("/*m!100000 SELECT 1 */", "/*m!"),
            ("SELECT a/*M!100000 1 */", "/*m!"),
        ] {
            assert_eq!(found(text), Some(token), "{text}");
        }
        for text in [
            "/* ! */ SELECT 1",
            "/*+ BKA(t) */ SELECT 1",
            "SELECT '/*' , '!'",
        ] {
            assert_eq!(found(text), None, "{text}");
        }
    }

    #[test]
    fn read_write_matches_with_blanks_and_every_comment_style_between() {
        for text in [
            "READ WRITE",
            "read\twrite",
            "read\n\r\x0b\x0cwrite",
            "READ/* c */WRITE",
            "READ /* c /* d */ WRITE",
            "READ /**/ /* x */WRITE",
            "READ -- c\nWRITE",
            "READ --\tc\nWRITE",
            "READ --\nWRITE",
            "READ --x\nWRITE",
            "READ #c\nWRITE",
            "READ#\nWRITE",
            "READ /* a */ -- b\n # c\n /* d */ WRITE",
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ  WRITE",
        ] {
            assert_eq!(found(text), Some("read write"), "{text:?}");
        }
        for text in [
            "READ ONLY",
            "read_write",
            "READ, WRITE",
            "READ -- c WRITE",
            "READ # c WRITE",
            "READ -- c\rWRITE",
            "READ /* c WRITE",
            "SELECT 1; READ",
            "READ x WRITE",
            "READWRITE",
            "READ WRITES",
            "SELECT 1 FROM unread WRITE",
        ] {
            assert_eq!(found(text), None, "{text:?}");
        }
    }

    #[test]
    fn ordinary_reads_with_near_miss_names_pass() {
        for text in [
            "SELECT * FROM global_settings WHERE id = 1",
            "SELECT executed_at FROM jobs ORDER BY executed_at DESC LIMIT 10",
            "SELECT program_id FROM enrolments",
            "SELECT read_write_ratio FROM stats",
            "SELECT `main`.`User`.`id`, `main`.`User`.`email` FROM `main`.`User` WHERE `main`.`User`.`id` = ? LIMIT ? OFFSET ?",
            "SELECT users.id AS users_id, users.name AS users_name FROM users WHERE users.id = %s",
            "SELECT `orders`.* FROM `orders` WHERE `orders`.`customer_id` = 1 ORDER BY `orders`.`id` DESC LIMIT 1",
            "SELECT * FROM `products` WHERE code = 'D42' AND `products`.`deleted_at` IS NULL ORDER BY `products`.`id` LIMIT 1",
            "select u1_0.id,u1_0.name from users u1_0 where u1_0.id=?",
            "SELECT COUNT(*) FROM `information_schema`.`tables` WHERE `table_schema` = DATABASE()",
            "SELECT @@session.transaction_isolation, @@version_comment",
            "SHOW FULL TABLES FROM `app` LIKE 'schema_migrations'",
            "SELECT 1 /* app:orders,controller:index */",
            "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
            "SET SESSION TRANSACTION READ ONLY",
            "START TRANSACTION READ ONLY",
            "SELECT * FROM t FOR SHARE",
            "SELECT readers, writers FROM locks",
        ] {
            assert_eq!(found(text), None, "{text}");
        }
    }

    #[test]
    fn every_high_byte_is_a_boundary_and_a_blank() {
        for high in [0x80u8, 0x9a, 0xa0, 0xca, 0xff] {
            for word in WORDS {
                for text in [
                    [&[high][..], word.as_bytes()].concat(),
                    [word.as_bytes(), &[high]].concat(),
                    [b"SELECT x", &[high][..], word.as_bytes(), &[high], b"y"].concat(),
                ] {
                    assert_eq!(scan(&text), Some(word), "{text:?}");
                }
            }
            for text in [
                [b"SET TRANSACTION READ", &[high][..], b"WRITE"].concat(),
                [b"READ", &[high, high][..], b"/* c */", &[high], b"WRITE"].concat(),
                [b"x", &[high][..], b"READ", &[high], b"WRITE", &[high]].concat(),
            ] {
                assert_eq!(scan(&text), Some("read write"), "{text:?}");
            }
            let persist = [b"SET", &[high][..], b"PERSIST_ONLY x = 1"].concat();
            assert_eq!(scan(&persist), Some("persist"));
        }
        assert_eq!(scan(b"SELECT \xc3\xa9execute"), Some("execute"));
        assert_eq!(scan("SELECT caf\u{e9}_prepare".as_bytes()), None);
    }

    #[test]
    fn a_word_directly_after_a_gbk_letter_trail_byte_is_part_of_an_identifier() {
        assert_eq!(scan(b"SELECT \x81APREPARE"), None);
        assert_eq!(scan(b"SELECT \x81zexecute_prepared_stmt"), None);
        assert_eq!(scan(b"SELECT \x81\x5cPREPARE"), Some("prepare"));
    }

    #[test]
    fn escapes_after_a_gbk_character_with_an_ascii_trail_byte_still_match() {
        for (text, word) in [
            (&b"SELECT '\x81\x5c'; PREPARE s FROM @q"[..], "prepare"),
            (
                b"SET @x = '\x81\x5c', @@session.transaction_read_only = 0",
                "transaction_read_only",
            ),
            (
                b"SET @x = '\x81A', @@session.transaction_read_only = 0",
                "transaction_read_only",
            ),
            (b"SELECT '\x81\x5c' -- \nREAD WRITE", "read write"),
        ] {
            assert_eq!(scan(text), Some(word), "{text:?}");
        }
    }

    #[test]
    fn a_scan_that_runs_out_of_budget_refuses() {
        let mut text = "read -- ".repeat(2000);
        text.push_str("\nSELECT 1");
        assert_eq!(found(&text), Some("read write"));
        assert_eq!(found(&"read -- ".repeat(5)), None);
    }

    #[test]
    fn the_refusal_is_the_pinned_statement() {
        assert_eq!(
            REFUSAL,
            "SIGNAL SQLSTATE '25006' SET MESSAGE_TEXT = 'zs: refused, read-only resource', MYSQL_ERRNO = 1792"
        );
        assert_eq!(found(REFUSAL), None);
        assert_eq!(found(SESSION_START), Some("transaction_read_only"));
    }
}
