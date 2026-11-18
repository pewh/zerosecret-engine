pub const REFUSAL: &str = "SIGNAL SQLSTATE '25006' SET MESSAGE_TEXT = 'zs: refused, read-only resource', MYSQL_ERRNO = 1792";
pub const READ_ONLY_REASON: &str = "read-only";
pub const SESSION_START: &str = "SET SESSION transaction_read_only = ON";
pub const MAX_SCREENED_COMMAND: usize = 64 << 20;
pub(crate) const INLINE_SCAN_LIMIT: usize = 1 << 20;

const WORDS: [&str; 20] = [
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
    "restart",
    "purge",
    "flush",
    "reset",
    "replica",
    "replication",
    "group_replication",
    "slave",
    "clone",
];
const FOLDED: [&str; 3] = [
    "transaction_read_only",
    "tx_read_only",
    "execute_prepared_stmt",
];
const PERSIST: &str = "persist";
const TOKENS: [&str; 2] = ["/*!", "/*m!"];
const READ_WRITE: &str = "read write";
const CHANGE_MASTER: &str = "change master";
const ALTER_INSTANCE: &str = "alter instance";
/// Two-word phrases, each with its own state: a word of one phrase in the gap of another must
/// not reset it (`READ /*change*/ WRITE`).
const PHRASES: [(&str, &str, &str); 3] = [
    ("read", "write", READ_WRITE),
    ("change", "master", CHANGE_MASTER),
    ("alter", "instance", ALTER_INSTANCE),
];
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

struct Fold {
    word: &'static str,
    done: u32,
    letters: u32,
    literal: [u32; 256],
}

impl Fold {
    fn new(word: &'static str) -> Self {
        let mut literal = [0u32; 256];
        let mut letters = 0u32;
        for (at, expected) in word.bytes().enumerate() {
            if expected.is_ascii_alphabetic() {
                letters |= 1 << at;
            }
            for byte in 0..=u8::MAX {
                if byte.eq_ignore_ascii_case(&expected) {
                    literal[usize::from(byte)] |= 1 << at;
                }
            }
        }
        Self {
            word,
            done: 1 << word.len(),
            letters,
            literal,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Live {
    fresh: u32,
    high: [u32; 3],
    gb: [u32; 3],
}

impl Live {
    fn step(&mut self, fold: &Fold, byte: u8) -> bool {
        let high = byte >= 0x80;
        let lead = (0x81..=0xfe).contains(&byte);
        let digit = byte.is_ascii_digit();
        let open = self.fresh & fold.letters;
        let mut fresh = (self.fresh & fold.literal[usize::from(byte)]) << 1;
        if high {
            fresh |= (open | self.high[0] | self.high[1] | self.high[2]) << 1;
        }
        if digit {
            fresh |= self.gb[2] << 1;
        }
        let keep = |on: bool, mask: u32| if on { mask } else { 0 };
        *self = Live {
            fresh,
            high: [
                keep(high, open),
                keep(high, self.high[0]),
                keep(high, self.high[1]),
            ],
            gb: [
                keep(lead, open),
                keep(digit, self.gb[0]),
                keep(lead, self.gb[1]),
            ],
        };
        fresh & fold.done != 0
    }
}

fn folds() -> &'static [Fold; 3] {
    static FOLDS: std::sync::OnceLock<[Fold; 3]> = std::sync::OnceLock::new();
    FOLDS.get_or_init(|| FOLDED.map(Fold::new))
}

fn folded_match(text: &[u8], folds: &[Fold]) -> Option<&'static str> {
    let mut live = vec![Live::default(); folds.len()];
    for (at, &byte) in text.iter().enumerate() {
        let start = at == 0 || !identifier(text[at - 1]);
        let ends = text.get(at + 1).is_none_or(|next| !identifier(*next));
        for (fold, state) in folds.iter().zip(live.iter_mut()) {
            if start {
                state.fresh |= 1;
            }
            if state.step(fold, byte) && ends {
                return Some(fold.word);
            }
        }
    }
    None
}

const BETWEEN: u8 = 1;
const SLASH: u8 = 2;
const DASH: u8 = 4;
const LINE: u8 = 8;
const BLOCK: u8 = 16;
const STAR: u8 = 32;

fn between_step(states: u8, byte: u8) -> u8 {
    let mut next = 0;
    if states & BETWEEN != 0 {
        next |= match byte {
            b'#' => LINE,
            b'/' => SLASH,
            b'-' => DASH,
            _ if blank(byte) => BETWEEN,
            _ => 0,
        };
    }
    if states & SLASH != 0 && byte == b'*' {
        next |= BLOCK;
    }
    if states & DASH != 0 && byte == b'-' {
        next |= LINE;
    }
    if states & LINE != 0 {
        next |= if byte == b'\n' { BETWEEN } else { LINE };
    }
    if states & BLOCK != 0 {
        next |= if byte == b'*' { STAR } else { BLOCK };
    }
    if states & STAR != 0 {
        next |= match byte {
            b'/' => BETWEEN,
            b'*' => STAR,
            _ => BLOCK,
        };
    }
    next
}

fn ascii_match(text: &[u8]) -> Option<&'static str> {
    let mut between = [0u8; PHRASES.len()];
    let mut starts: [Option<usize>; PHRASES.len()] = [None; PHRASES.len()];
    for (at, &byte) in text.iter().enumerate() {
        if let Some(token) = TOKENS.iter().find(|token| {
            text.get(at..at + token.len())
                .is_some_and(|found| found.eq_ignore_ascii_case(token.as_bytes()))
        }) {
            return Some(token);
        }
        for (phrase, (_, second, name)) in PHRASES.iter().enumerate() {
            if starts[phrase] == Some(at) {
                between[phrase] |= BETWEEN;
            }
            if between[phrase] & BETWEEN != 0 && word_at(text, at, second) {
                return Some(name);
            }
        }
        if byte.is_ascii_alphabetic() && (at == 0 || !identifier(text[at - 1])) {
            if let Some(word) = WORDS.iter().find(|word| word_at(text, at, word)) {
                return Some(word);
            }
            if prefix_at(text, at, PERSIST) {
                return Some(PERSIST);
            }
            for (phrase, (first, _, _)) in PHRASES.iter().enumerate() {
                if word_at(text, at, first) {
                    starts[phrase] = Some(at + first.len());
                }
            }
        }
        for state in &mut between {
            *state = between_step(*state, byte);
        }
    }
    None
}

pub fn scan(text: &[u8]) -> Option<&'static str> {
    ascii_match(text).or_else(|| folded_match(text, folds()))
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

    const WORDS: [&str; 20] = [
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
        "restart",
        "purge",
        "flush",
        "reset",
        "replica",
        "replication",
        "group_replication",
        "slave",
        "clone",
    ];

    #[test]
    fn the_production_words_are_the_listed_words() {
        assert_eq!(super::WORDS, WORDS);
    }

    #[test]
    fn every_replication_log_flush_and_restart_statement_is_matched() {
        for (text, word) in [
            ("RESET BINARY LOGS AND GTIDS", "reset"),
            ("RESET MASTER", "reset"),
            ("RESET REPLICA ALL", "reset"),
            ("PURGE BINARY LOGS TO 'binlog.000002'", "purge"),
            ("FLUSH TABLES WITH READ LOCK", "flush"),
            ("FLUSH LOGS", "flush"),
            ("RESTART", "restart"),
            (
                "CHANGE REPLICATION SOURCE TO SOURCE_HOST = 'x'",
                "replication",
            ),
            (
                "CHANGE REPLICATION FILTER REPLICATE_DO_DB = (d)",
                "replication",
            ),
            ("STOP REPLICA", "replica"),
            ("START REPLICA IO_THREAD", "replica"),
            ("STOP SLAVE", "slave"),
            ("START GROUP_REPLICATION", "group_replication"),
            ("CHANGE MASTER TO MASTER_HOST = 'x'", "change master"),
            ("change/**/master to master_host = 'x'", "change master"),
            ("CHANGE -- c\nMASTER TO MASTER_HOST = 'x'", "change master"),
            ("CHANGE #c\n MASTER TO MASTER_HOST = 'x'", "change master"),
            ("START TRANSACTION READ /*change*/ WRITE", "read write"),
            ("SET TRANSACTION READ#change\nWRITE", "read write"),
            ("START TRANSACTION READ -- change\nWRITE", "read write"),
            ("START TRANSACTION READ /*alter*/ WRITE", "read write"),
            (
                "CHANGE /*read*/ MASTER TO MASTER_HOST = 'x'",
                "change master",
            ),
            (
                "CHANGE #alter\n MASTER TO MASTER_HOST = 'x'",
                "change master",
            ),
            ("ALTER INSTANCE ROTATE INNODB MASTER KEY", "alter instance"),
            ("alter /*read*/ instance reload tls", "alter instance"),
            ("CLONE LOCAL DATA DIRECTORY = '/tmp/zs'", "clone"),
        ] {
            assert_eq!(found(text), Some(word), "{text:?}");
        }
        for text in [
            "SELECT master FROM branches",
            "SELECT * FROM refs WHERE name = 'master'",
            "SELECT change_count, master_id FROM t",
            "SELECT reset_at, flushed, purged_at, replicas FROM t",
            "SELECT changed FROM t WHERE x = 'master'",
            "SELECT 'change' AS c, 'x master' AS m",
            "CHANGE x MASTER",
            "SELECT instance, altered FROM t",
            "ALTER TABLE t ADD COLUMN instance INT",
            "SELECT clones FROM t",
        ] {
            assert_eq!(found(text), None, "{text:?}");
        }
    }

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
    fn a_word_after_a_numeric_literal_is_not_matched_because_the_grammar_has_no_listed_word_there()
    {
        for text in [
            "SELECT 1.5PREPARE",
            "SELECT 1e1KILL",
            "SELECT 1.5EXECUTE",
            "SELECT 2E3SHUTDOWN",
        ] {
            assert_eq!(found(text), None, "{text}");
        }
        assert_eq!(found("SELECT 1.5 PREPARE"), Some("prepare"));
        assert_eq!(found("SELECT 1e1 KILL"), Some("kill"));
    }

    #[test]
    fn persist_matches_as_a_prefix_and_never_after_an_identifier_byte() {
        for text in [
            "SET PERSIST x = 1",
            "SET PERSIST_ONLY x = 1",
            "set persist_only x = 1",
            "SET @@persist.x = 1",
            "SELECT persists",
            "SET SESSION x = 1, PERSIST y = 2",
        ] {
            assert_eq!(found(text), Some("persist"), "{text}");
        }
        assert_eq!(found("RESET PERSIST x"), Some("reset"), "reset comes first");
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
    fn a_gb18030_four_byte_letter_folds() {
        for (text, word) in [
            (
                &b"SET SESSION trans\x81\x30\x89\x39ction_read_only = OFF"[..],
                "transaction_read_only",
            ),
            (
                b"CALL sys.ex\x81\x30\x8a\x35cute_prepared_stmt(CONCAT('SET SESSION transaction', '_read_only = 0'))",
                "execute_prepared_stmt",
            ),
            (b"SET SESSION \x81\x30\x89\x39x_read_only = OFF", "tx_read_only"),
            (
                b"SET SESSION transaction_read_onl\x81\x30\x89\x39",
                "transaction_read_only",
            ),
        ] {
            assert_eq!(scan(text), Some(word), "{text:?}");
        }
        for text in [
            &b"SET SESSION trans\x81\x30\x89ction_read_only = OFF"[..],
            b"SET SESSION trans\x81\x30\x89\x39\x30ction_read_only = OFF",
            b"SET SESSION trans\x30\x81\x30\x89\x39ction_read_only = OFF",
        ] {
            assert_eq!(scan(text), None, "{text:?}");
        }
    }

    #[test]
    fn ordinary_non_latin_snake_case_reads_pass() {
        let many = format!(
            "SELECT {}",
            [
                "'\u{43f}\u{43e}\u{43b}\u{44c}\u{437}\u{43e}\u{432}\u{430}\u{442}\u{435}\u{43b}\u{44c}_\u{441}\u{438}\u{441}\u{442}\u{435}\u{43c}\u{44b}'",
                "'\u{30e6}\u{30fc}\u{30b6}\u{30fc}\u{540d}_\u{30c7}\u{30fc}\u{30bf}\u{30d9}\u{30fc}\u{30b9}'",
                "'\u{438}\u{43c}\u{44f}_\u{43f}\u{43e}\u{43b}\u{44c}\u{437}\u{43e}\u{432}\u{430}\u{442}\u{435}\u{43b}\u{44f}'",
                "'\u{6771}\u{4eac}\u{90fd}\u{6e0b}\u{8c37}\u{533a}_\u{795e}\u{5357}'",
            ]
            .repeat(40)
            .join(", ")
        );
        for text in [
            "SELECT * FROM t WHERE note = '\u{6771}\u{4eac}\u{90fd}\u{6e0b}\u{8c37}\u{533a}\u{795e}\u{5357}\u{4e00}\u{4e01}\u{76ee}_\u{6771}\u{4eac}\u{90fd}\u{6e0b}\u{8c37}\u{533a}\u{795e}\u{5357}\u{4e00}\u{4e01}\u{76ee}_'".to_string(),
            format!("SELECT {}", ["'\u{43f}\u{43e}\u{43b}\u{44c}\u{437}\u{43e}\u{432}\u{430}\u{442}\u{435}\u{43b}\u{44c}_\u{441}\u{438}\u{441}\u{442}\u{435}\u{43c}\u{44b}'"; 3].join(", ")),
            "'\u{438}\u{43c}\u{44f}_\u{43f}\u{43e}\u{43b}\u{44c}\u{437}\u{43e}\u{432}\u{430}\u{442}\u{435}\u{43b}\u{44f} '".repeat(13),
            "'\u{30e6}\u{30fc}\u{30b6}\u{30fc}\u{540d}_\u{30c7}\u{30fc}\u{30bf}\u{30d9}\u{30fc}\u{30b9} '".repeat(8),
            many,
        ] {
            assert_eq!(found(&text), None, "{text}");
        }
    }

    fn reference_ends(text: &[u8], at: usize, word: &[u8]) -> Vec<usize> {
        let Some((&expected, rest)) = word.split_first() else {
            return vec![at];
        };
        let mut ends = Vec::new();
        if text
            .get(at)
            .is_some_and(|byte| byte.eq_ignore_ascii_case(&expected))
        {
            ends.extend(reference_ends(text, at + 1, rest));
        }
        if expected.is_ascii_alphabetic() {
            for run in 1..=4 {
                if text
                    .get(at..at + run)
                    .is_some_and(|bytes| bytes.iter().all(|byte| *byte >= 0x80))
                {
                    ends.extend(reference_ends(text, at + run, rest));
                }
            }
            let lead = |byte: u8| (0x81..=0xfe).contains(&byte);
            if let Some(&[a, b, c, d]) = text.get(at..at + 4)
                && lead(a)
                && b.is_ascii_digit()
                && lead(c)
                && d.is_ascii_digit()
            {
                ends.extend(reference_ends(text, at + 4, rest));
            }
        }
        ends
    }

    fn reference(text: &[u8], word: &str) -> bool {
        (0..=text.len()).any(|at| {
            (at == 0 || !identifier(text[at - 1]))
                && reference_ends(text, at, word.as_bytes())
                    .into_iter()
                    .any(|end| text.get(end).is_none_or(|next| !identifier(*next)))
        })
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn pick<T: Copy>(&mut self, items: &[T]) -> T {
            items[(self.next() % items.len() as u64) as usize]
        }
    }

    const ALPHABET: &[u8] = b"transctiodlyexupmTRANSCTIODLYEXUPM_0123456789 \x81\x89\xc3\xa1\xfe";
    const HIGH: [u8; 5] = [0x81, 0x89, 0xc3, 0xa1, 0xfe];

    fn mutated(rng: &mut Rng, word: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..rng.next() % 3 {
            out.push(rng.pick(ALPHABET));
        }
        for byte in word.bytes() {
            match rng.next() % 24 {
                0..=4 if byte.is_ascii_alphabetic() => {
                    for _ in 0..=rng.next() % 4 {
                        out.push(rng.pick(&HIGH));
                    }
                }
                5..=7 if byte.is_ascii_alphabetic() => {
                    out.push(rng.pick(&HIGH));
                    out.push(b'0' + (rng.next() % 10) as u8);
                    out.push(rng.pick(&HIGH));
                    out.push(b'0' + (rng.next() % 10) as u8);
                }
                8 => out.push(rng.pick(ALPHABET)),
                9 => {}
                10 => {
                    out.push(byte.to_ascii_uppercase());
                    out.push(rng.pick(ALPHABET));
                }
                11..=13 => out.push(byte.to_ascii_uppercase()),
                _ => out.push(byte),
            }
        }
        for _ in 0..rng.next() % 3 {
            out.push(rng.pick(ALPHABET));
        }
        out
    }

    #[test]
    fn the_fold_match_agrees_with_a_slow_reference_matcher() {
        let mut rng = Rng(0x5eed_2026_1116_0006);
        let mut matched = 0;
        for round in 0..6000 {
            let word = rng.pick(&FOLDED);
            let text: Vec<u8> = if round % 3 == 0 {
                (0..rng.next() % 40).map(|_| rng.pick(ALPHABET)).collect()
            } else {
                mutated(&mut rng, word)
            };
            for name in FOLDED {
                let expected = reference(&text, name);
                matched += usize::from(expected);
                assert_eq!(
                    folded_match(&text, &[Fold::new(name)]).is_some(),
                    expected,
                    "{name} in {text:?}"
                );
            }
        }
        assert!(
            matched > 200,
            "the generator reached real matches: {matched}"
        );
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
    fn many_reads_inside_one_comment_are_scanned_exactly() {
        let mut text = "read -- ".repeat(20_000);
        text.push_str("\nSELECT 1");
        assert_eq!(found(&text), None);
        text.push_str(" read /* read -- x */ -- y\n write");
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
