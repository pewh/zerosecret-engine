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
const FOLDED: [&str; 3] = [
    "transaction_read_only",
    "tx_read_only",
    "execute_prepared_stmt",
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

fn high_run(text: &[u8], at: usize) -> usize {
    text.get(at..).map_or(0, |rest| {
        rest.iter()
            .take(4)
            .take_while(|byte| **byte >= 0x80)
            .count()
    })
}

fn folded_ends(text: &[u8], at: usize, word: &str, budget: &mut usize) -> Option<u128> {
    let mut ends: u128 = 1;
    for expected in word.bytes() {
        let mut next: u128 = 0;
        let mut rest = ends;
        while rest != 0 {
            let offset = rest.trailing_zeros() as usize;
            rest &= rest - 1;
            *budget = budget.checked_sub(1)?;
            let position = at + offset;
            if text
                .get(position)
                .is_some_and(|byte| byte.eq_ignore_ascii_case(&expected))
            {
                next |= 1 << (offset + 1);
            }
            if expected.is_ascii_alphabetic() {
                for run in 1..=high_run(text, position) {
                    next |= 1 << (offset + run);
                }
            }
        }
        if next == 0 {
            return Some(0);
        }
        ends = next;
    }
    Some(ends)
}

fn folded_at(text: &[u8], at: usize, word: &str, budget: &mut usize) -> bool {
    let first = text[at];
    if !(first.eq_ignore_ascii_case(&word.as_bytes()[0]) || first >= 0x80) {
        return false;
    }
    let letters = word.bytes().take_while(|byte| *byte != b'_').count();
    let window = text
        .get(at + letters..)
        .map_or(&[][..], |rest| &rest[..rest.len().min(3 * letters + 1)]);
    if !window.contains(&b'_') {
        return false;
    }
    let Some(mut ends) = folded_ends(text, at, word, budget) else {
        return true;
    };
    while ends != 0 {
        let offset = ends.trailing_zeros() as usize;
        ends &= ends - 1;
        if text.get(at + offset).is_none_or(|next| !identifier(*next)) {
            return true;
        }
    }
    false
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
    let mut fold_budget = 64 * text.len() + 4096;
    for at in 0..text.len() {
        if let Some(token) = TOKENS.iter().find(|token| {
            text.get(at..at + token.len())
                .is_some_and(|found| found.eq_ignore_ascii_case(token.as_bytes()))
        }) {
            return Some(token);
        }
        if !(text[at].is_ascii_alphabetic() || text[at] >= 0x80)
            || (at > 0 && identifier(text[at - 1]))
        {
            continue;
        }
        if let Some(word) = WORDS.iter().find(|word| {
            if FOLDED.contains(word) {
                folded_at(text, at, word, &mut fold_budget)
            } else {
                word_at(text, at, word)
            }
        }) {
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

    fn spelled(word: &str, at: usize, character: &[u8]) -> Vec<u8> {
        let mut out = word.as_bytes().to_vec();
        out.splice(at..=at, character.iter().copied());
        out
    }

    #[test]
    fn a_word_with_a_non_ascii_letter_in_place_of_an_ascii_letter_matches() {
        for (text, word) in [
            (
                &b"SET SESSION trans\xc3\xa1ction_read_only = OFF"[..],
                "transaction_read_only",
            ),
            (
                b"SET SESSION transact\xc4\xb0on_read_only = OFF",
                "transaction_read_only",
            ),
            (
                b"SET SESSION trans\xe1ction_read_only = OFF",
                "transaction_read_only",
            ),
            (
                b"CALL sys.ex\xc3\xa9cute_prepared_stmt(CONCAT('SET SESSION transaction', '_read_only = 0'))",
                "execute_prepared_stmt",
            ),
            (b"SET SESSION tx_r\xc3\xa9ad_only = OFF", "tx_read_only"),
            (
                b"SET SESSION \xef\xbd\x94ransaction_read_only = OFF",
                "transaction_read_only",
            ),
        ] {
            assert_eq!(scan(text), Some(word), "{text:?}");
        }
        let characters: [&[u8]; 4] = [b"\xe9", b"\xc3\xa9", b"\xe3\x80\x81", b"\xf0\x9f\x98\x80"];
        for word in FOLDED {
            let letters: Vec<usize> = (0..word.len())
                .filter(|at| word.as_bytes()[*at].is_ascii_alphabetic())
                .collect();
            for &at in &letters {
                for character in characters {
                    let text = [b"SELECT ", &spelled(word, at, character)[..], b" FROM t"].concat();
                    assert_eq!(scan(&text), Some(word), "{text:?}");
                }
                if letters.contains(&(at + 1)) {
                    let twice = spelled(word, at, b"\xc3\xa9");
                    let twice = [&twice[..at + 2], b"\xe9", &twice[at + 3..]].concat();
                    assert_eq!(scan(&twice), Some(word), "{twice:?}");
                }
            }
        }
    }

    fn every_letter_two_bytes(word: &str) -> Vec<u8> {
        word.bytes()
            .flat_map(|byte| {
                if byte == b'_' {
                    vec![b'_']
                } else {
                    vec![0xc3, 0x80 + byte % 0x20]
                }
            })
            .collect()
    }

    #[test]
    fn only_letters_fold_and_an_underscore_stays_literal() {
        let all = every_letter_two_bytes("transaction_read_only");
        let text = [b"SET SESSION ", &all[..], b" = OFF"].concat();
        assert_eq!(scan(&text), Some("transaction_read_only"), "{text:?}");

        let first = all.iter().position(|byte| *byte == b'_').unwrap();
        let mut replaced = all.clone();
        replaced.splice(first..=first, b"\xc3\xa9".iter().copied());
        let text = [b"SET SESSION ", &replaced[..], b" = OFF"].concat();
        assert_eq!(scan(&text), None, "{text:?}");
        let both = all
            .iter()
            .flat_map(|byte| {
                if *byte == b'_' {
                    b"\xc3\xa9".to_vec()
                } else {
                    vec![*byte]
                }
            })
            .collect::<Vec<u8>>();
        let text = [b"SET SESSION ", &both[..], b" = OFF"].concat();
        assert_eq!(scan(&text), None, "{text:?}");
        for text in [
            "SELECT '\u{438}\u{43c}\u{44f}_\u{43f}\u{43e}\u{43b}\u{44c}\u{437}\u{43e}\u{432}\u{430}\u{442}\u{435}\u{43b}\u{44f}'",
            "SELECT '\u{6771}\u{4eac}_\u{5927}\u{962a}'",
        ] {
            assert_eq!(found(text), None, "{text}");
        }
        assert_eq!(
            found(
                "SELECT '\u{438}\u{432}_\u{43c}\u{438}\u{440}\u{430}_\u{43c}\u{438}\u{440}\u{430}'"
            ),
            Some("tx_read_only"),
            "documented limit: three non-Latin segments with the shape of tx_read_only"
        );

        for candidate in [
            &b"\xef\xbc\xbf"[..],
            b"\xef\xb9\x8f",
            b"\xcb\x8d",
            b"\xe2\x80\x97",
            b"\xcc\xb2",
            b"\xaf",
        ] {
            let text = [b"SET SESSION transaction", candidate, b"read_only = OFF"].concat();
            assert_eq!(scan(&text), None, "{text:?}");
        }
    }

    #[test]
    fn keywords_match_ascii_only_as_the_server_parses_them() {
        for text in [
            &b"SELECT LOAD_F\xc3\x8dLE('/etc/hostname')"[..],
            b"SET @@gl\xc3\xb6bal.net_retry_count = 11",
            b"SET GL\xc3\x96BAL net_retry_count = 11",
            b"SET @@p\xc3\xa9rsist.net_retry_count = 11",
            b"SET P\xc3\x89RSIST_ONLY x = 1",
            b"PR\xc3\x89PARE s FROM 'SELECT 1'",
            b"EX\xc3\x89CUTE s",
            b"K\xc3\x8dLL 999999",
            b"SH\xc3\x9aTDOWN",
            b"SELECT 1 INTO \xc3\x93UTFILE '/tmp/x'",
        ] {
            assert_eq!(scan(text), None, "{text:?}");
        }
    }

    #[test]
    fn non_latin_reads_pass() {
        for text in [
            "SELECT '\u{6771}\u{4eac}'",
            "SELECT 'ok \u{1f44d}'",
            "SELECT '\u{418}\u{432}\u{430}\u{43d}'",
            "SELECT 'Jos\u{e9} M\u{fc}ller'",
            "SELECT * FROM shops WHERE city = '\u{6771}\u{4eac}\u{90fd}\u{6e0b}\u{8c37}\u{533a}\u{795e}\u{5357}\u{4e00}\u{4e01}\u{76ee}'",
            "SELECT '\u{6771}_\u{4eac}_\u{90fd}'",
            "SELECT '\u{44f}_\u{442}\u{44b}'",
        ] {
            assert_eq!(found(text), None, "{text}");
        }
        let long = format!(
            "SELECT '{}', '{}'",
            "\u{6771}\u{4eac}\u{1f44d}".repeat(20_000),
            "\u{418}\u{432}\u{430}\u{43d} ".repeat(20_000)
        );
        assert_eq!(found(&long), None);
    }

    #[test]
    fn folded_near_misses_and_ascii_keywords_do_not_match() {
        for word in WORDS {
            let mut shorter = word.as_bytes().to_vec();
            shorter.remove(1);
            let last = shorter.len() - 1;
            shorter.splice(last.., b"\xc3\xa9".iter().copied());
            let text = [b"SELECT ", &shorter[..], b" FROM t"].concat();
            assert_eq!(scan(&text), None, "{text:?}");

            let dotted: Vec<String> = word.chars().map(String::from).collect();
            let text = format!("SELECT '{} \u{fc}'", dotted.join("."));
            assert_eq!(found(&text), None, "{text}");
        }
        for text in [
            &b"SET TRANSACTION R\xc3\x89AD WRITE"[..],
            b"START TRANSACTION READ WR\xc3\x8dTE",
            b"SELECT * FROM users WHERE name = 'Jos\xc3\xa9 M\xc3\xbcller'",
            b"SELECT 'caf\xc3\xa9', 'na\xc3\xafve'",
        ] {
            assert_eq!(scan(text), None, "{text:?}");
        }
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
