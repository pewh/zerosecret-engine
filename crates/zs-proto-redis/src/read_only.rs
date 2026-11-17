use std::cmp::Ordering;

use crate::Reply;
use crate::read_only_commands::{COMMANDS, CONTAINERS, NAMES, SUBCOMMAND_NAMES, SUBCOMMANDS};

pub const READ_ONLY_REASON: &str = "read-only";

pub const READ_ONLY_REFUSED: Reply = Reply {
    message: "NOPERM read-only resource",
};

pub const EXEC_ABORTED: Reply = Reply {
    message: "EXECABORT Transaction discarded because of previous errors.",
};

pub(crate) const MALFORMED: &str = "malformed";
pub(crate) const NOT_ALLOWED: &str = "command";

const BY_RULE: [&str; 9] = [
    "auth", "discard", "exec", "hello", "multi", "ping", "quit", "reset", "select",
];
const REFUSED_WHOLE: [&str; 11] = [
    "acl",
    "config",
    "debug",
    "eval",
    "eval_ro",
    "evalsha",
    "evalsha_ro",
    "fcall",
    "fcall_ro",
    "module",
    "script",
];
const OTHER: &str = "other";
const CLIENT_SUBCOMMANDS: [&str; 4] = ["getname", "id", "info", "setname"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Forward,
    Refuse,
    Abort,
    Close,
}

#[derive(Default)]
pub struct MultiState {
    active: bool,
    dirty: bool,
}

impl MultiState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&mut self, args: &[&[u8]]) -> Verdict {
        let Some(name) = args.first() else {
            return Verdict::Close;
        };
        if !admit(args) {
            self.dirty |= self.active;
            return Verdict::Refuse;
        }
        if is(name, "multi") {
            self.active = true;
        } else if is(name, "exec") {
            let aborted = self.dirty;
            *self = Self::default();
            if aborted {
                return Verdict::Abort;
            }
        } else if is(name, "discard") || is(name, "reset") {
            *self = Self::default();
        }
        Verdict::Forward
    }
}

pub(crate) struct Refused {
    pub(crate) command: Option<&'static str>,
    pub(crate) subcommand: Option<&'static str>,
}

pub fn admit(args: &[&[u8]]) -> bool {
    let Some((name, rest)) = args.split_first() else {
        return false;
    };
    let sub = rest.first();
    if REFUSED_WHOLE.iter().any(|whole| is(name, whole)) {
        return false;
    }
    if is(name, "client") {
        return sub.is_some_and(|sub| CLIENT_SUBCOMMANDS.iter().any(|known| is(sub, known)));
    }
    if BY_RULE.iter().any(|rule| is(name, rule)) {
        return true;
    }
    if is_container(name) {
        return sub.is_some_and(|sub| {
            SUBCOMMANDS
                .binary_search_by(|(container, known)| {
                    order(container, name).then_with(|| order(known, sub))
                })
                .is_ok()
        });
    }
    COMMANDS
        .binary_search_by(|known| order(known, name))
        .is_ok()
}

pub(crate) fn refused(args: &[&[u8]]) -> Refused {
    let Some((name, rest)) = args.split_first() else {
        return Refused {
            command: None,
            subcommand: None,
        };
    };
    let subcommand = rest.first().filter(|_| is_container(name)).map(|sub| {
        SUBCOMMAND_NAMES
            .binary_search_by(|(container, known)| {
                order(container, name).then_with(|| order(known, sub))
            })
            .map_or(OTHER, |at| SUBCOMMAND_NAMES[at].1)
    });
    Refused {
        command: Some(
            NAMES
                .binary_search_by(|known| order(known, name))
                .map_or(OTHER, |at| NAMES[at]),
        ),
        subcommand,
    }
}

fn is(arg: &[u8], name: &str) -> bool {
    arg.eq_ignore_ascii_case(name.as_bytes())
}

fn is_container(name: &[u8]) -> bool {
    CONTAINERS
        .binary_search_by(|container| order(container, name))
        .is_ok()
}

fn order(entry: &str, arg: &[u8]) -> Ordering {
    entry.bytes().cmp(arg.iter().map(u8::to_ascii_lowercase))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use sha2::{Digest, Sha256};

    use super::*;

    fn words(command: &str) -> Vec<&[u8]> {
        command.split(' ').map(str::as_bytes).collect()
    }

    fn admits(command: &str) -> bool {
        admit(&words(command))
    }

    fn assert_admitted(commands: &[&str]) {
        for command in commands {
            assert!(admits(command), "{command} must pass");
        }
    }

    fn assert_refused(commands: &[&str]) {
        for command in commands {
            assert!(!admits(command), "{command} must be refused");
        }
    }

    #[test]
    fn read_commands_pass_in_any_case() {
        assert_admitted(&[
            "GET k",
            "get k",
            "Get k",
            "gEt k",
            "MGET a b",
            "zRangeByScore z 0 1",
            "HGETALL h",
            "scan 0",
            "XREAD COUNT 1 STREAMS s 0",
            "XRANGE s - +",
            "DBSIZE",
            "TTL k",
            "TYPE k",
            "EXISTS k",
            "STRLEN k",
            "GEORADIUS_RO g 0 0 1 km",
            "BITFIELD_RO b GET u8 0",
        ]);
    }

    #[test]
    fn connection_and_transaction_commands_pass_by_rule() {
        assert_admitted(&[
            "PING",
            "ping",
            "HELLO 3",
            "hello 3 AUTH u p",
            "AUTH p",
            "Auth u p",
            "SELECT 1",
            "QUIT",
            "RESET",
            "MULTI",
            "multi",
            "EXEC",
            "Exec",
            "DISCARD",
            "discard",
        ]);
    }

    #[test]
    fn of_client_only_four_subcommands_pass() {
        assert_admitted(&[
            "CLIENT SETNAME app",
            "client getname",
            "Client Id",
            "CLIENT info",
            "cLiEnT sEtNaMe x",
        ]);
        assert_refused(&[
            "CLIENT",
            "CLIENT KILL ID 1",
            "client kill",
            "CLIENT LIST",
            "CLIENT SETINFO LIB-NAME x",
            "CLIENT REPLY OFF",
            "CLIENT TRACKING ON",
            "CLIENT PAUSE 10",
            "CLIENT UNPAUSE",
            "CLIENT NO-EVICT on",
            "CLIENT NO-TOUCH on",
            "CLIENT UNBLOCK 1",
            "CLIENT CACHING yes",
            "CLIENT HELP",
            "CLIENT SETNAMEX app",
        ]);
    }

    #[test]
    fn some_commands_are_refused_with_every_subcommand() {
        assert_refused(&[
            "EVAL_RO return 0",
            "eval_ro return 0",
            "EVALSHA_RO abc 0",
            "evalsha_ro abc 0",
            "FCALL_RO f 0",
            "Fcall_Ro f 0",
            "CONFIG GET maxmemory",
            "config set x y",
            "CONFIG",
            "ACL WHOAMI",
            "acl cat",
            "DEBUG SLEEP 0",
            "MODULE LIST",
            "SCRIPT EXISTS a",
            "SCRIPT LOAD x",
            "EVAL return 0",
            "eval x 0",
            "EVALSHA abc 0",
            "FCALL f 0",
        ]);
    }

    #[test]
    fn a_container_command_needs_a_read_subcommand() {
        assert_admitted(&[
            "OBJECT ENCODING k",
            "object freq k",
            "OBJECT IdleTime k",
            "OBJECT REFCOUNT k",
            "XINFO STREAM s",
            "xinfo groups s",
            "XINFO CONSUMERS s g",
            "MEMORY USAGE k",
        ]);
        assert_refused(&[
            "OBJECT",
            "XINFO",
            "MEMORY",
            "OBJECT HELP",
            "OBJECT GET",
            "MEMORY STATS",
            "MEMORY DOCTOR",
            "MEMORY PURGE",
            "XINFO HELP",
            "XGROUP CREATE s g $",
            "XGROUP",
            "FUNCTION LIST",
            "FUNCTION LOAD x",
            "PUBSUB CHANNELS",
            "COMMAND",
            "COMMAND COUNT",
            "COMMAND INFO get",
            "CLUSTER INFO",
            "LATENCY LATEST",
            "SLOWLOG GET",
        ]);
    }

    #[test]
    fn writes_and_server_commands_are_refused() {
        assert_refused(&[
            "SORT k STORE d",
            "SORT k",
            "SORT_RO k",
            "GEORADIUS g 0 0 1 km STORE d",
            "GEORADIUSBYMEMBER g m 1 km STORE d",
            "GEOSEARCHSTORE d s FROMLONLAT 0 0 BYRADIUS 1 km",
            "GETDEL k",
            "GETEX k EX 1",
            "SET k v",
            "set k v",
            "DEL k",
            "UNLINK k",
            "COPY a b",
            "RENAME a b",
            "EXPIRE k 1",
            "PERSIST k",
            "ZRANGESTORE d s 0 1",
            "BLPOP k 0",
            "XREADGROUP GROUP g c STREAMS s >",
            "FLUSHALL",
            "FLUSHDB",
            "KEYS *",
            "INFO",
            "SUBSCRIBE c",
            "SSUBSCRIBE c",
            "PSUBSCRIBE c",
            "PUBLISH c m",
            "WATCH k",
            "UNWATCH",
            "MONITOR",
            "REPLICAOF NO ONE",
            "SLAVEOF NO ONE",
            "SHUTDOWN",
            "SAVE",
            "BGSAVE",
            "SWAPDB 0 1",
            "MOVE k 1",
            "RESTORE k 0 x",
            "WAIT 0 0",
        ]);
    }

    #[test]
    fn module_and_unknown_commands_are_refused() {
        assert_refused(&[
            "JSON.SET k $ {}",
            "JSON.GET k",
            "FT.SEARCH i *",
            "BF.EXISTS b x",
            "zsMadeUpCommand",
            "GETX k",
            "GE k",
            "client|id",
            "object|encoding k",
            "",
        ]);
        assert!(!admit(&[b"GET\0".as_slice(), b"k"]));
        assert!(!admit(&[]));
    }

    #[test]
    fn the_tables_are_sorted_lowercase_and_unique() {
        assert!(COMMANDS.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(SUBCOMMANDS.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(CONTAINERS.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(NAMES.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(SUBCOMMAND_NAMES.windows(2).all(|pair| pair[0] < pair[1]));
        let names = COMMANDS
            .iter()
            .chain(CONTAINERS.iter())
            .chain(NAMES.iter())
            .chain(SUBCOMMANDS.iter().flat_map(|(command, sub)| [command, sub]))
            .chain(
                SUBCOMMAND_NAMES
                    .iter()
                    .flat_map(|(command, sub)| [command, sub]),
            );
        for name in names {
            assert_eq!(*name, name.to_ascii_lowercase());
            assert!(!name.contains('|'));
        }
        for (container, _) in SUBCOMMANDS {
            assert!(CONTAINERS.contains(&container));
        }
        assert!(!COMMANDS.iter().any(|name| CONTAINERS.contains(name)));
        for name in COMMANDS.iter().chain(CONTAINERS.iter()) {
            assert!(NAMES.binary_search(name).is_ok(), "{name}");
        }
        for pair in SUBCOMMANDS {
            assert!(SUBCOMMAND_NAMES.binary_search(&pair).is_ok(), "{pair:?}");
        }
        for (container, _) in SUBCOMMAND_NAMES {
            assert!(CONTAINERS.contains(&container), "{container}");
        }
    }

    #[test]
    fn the_production_table_is_pinned() {
        assert_eq!(
            (
                COMMANDS.len(),
                SUBCOMMANDS.len(),
                CONTAINERS.len(),
                NAMES.len(),
                SUBCOMMAND_NAMES.len()
            ),
            (81, 8, 15, 250, 129)
        );
        let mut hash = Sha256::new();
        for name in COMMANDS {
            hash.update(name);
            hash.update(b"\n");
        }
        for (container, sub) in SUBCOMMANDS {
            hash.update(container);
            hash.update(b"|");
            hash.update(sub);
            hash.update(b"\n");
        }
        for name in CONTAINERS.iter().chain(NAMES.iter()) {
            hash.update(name);
            hash.update(b"\n");
        }
        for (container, sub) in SUBCOMMAND_NAMES {
            hash.update(container);
            hash.update(b"|");
            hash.update(sub);
            hash.update(b"\n");
        }
        let digest: String = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest,
            "9f63b6078f43f2d84de7260d1b62d29895b237d1715a46058bd835bbc17604d6"
        );
    }

    #[test]
    fn script_commands_are_not_in_the_table() {
        for name in [
            "eval",
            "eval_ro",
            "evalsha",
            "evalsha_ro",
            "fcall",
            "fcall_ro",
        ] {
            assert!(COMMANDS.binary_search(&name).is_err(), "{name}");
            assert!(NAMES.binary_search(&name).is_ok(), "{name}");
        }
    }

    #[test]
    fn no_known_write_command_is_in_the_table() {
        for name in [
            "set",
            "setex",
            "setnx",
            "psetex",
            "mset",
            "msetnx",
            "append",
            "setrange",
            "incr",
            "incrby",
            "incrbyfloat",
            "decr",
            "decrby",
            "getset",
            "getdel",
            "getex",
            "del",
            "unlink",
            "copy",
            "rename",
            "renamenx",
            "move",
            "expire",
            "pexpire",
            "expireat",
            "pexpireat",
            "persist",
            "restore",
            "migrate",
            "sort",
            "sort_ro",
            "keys",
            "hset",
            "hsetnx",
            "hmset",
            "hdel",
            "hincrby",
            "hincrbyfloat",
            "hexpire",
            "hpersist",
            "lpush",
            "rpush",
            "lpushx",
            "rpushx",
            "lpop",
            "rpop",
            "linsert",
            "lset",
            "lrem",
            "ltrim",
            "lmove",
            "blmove",
            "rpoplpush",
            "brpoplpush",
            "blpop",
            "brpop",
            "lmpop",
            "blmpop",
            "sadd",
            "srem",
            "spop",
            "smove",
            "sinterstore",
            "sunionstore",
            "sdiffstore",
            "zadd",
            "zrem",
            "zincrby",
            "zpopmin",
            "zpopmax",
            "bzpopmin",
            "bzpopmax",
            "zmpop",
            "bzmpop",
            "zremrangebyrank",
            "zremrangebyscore",
            "zremrangebylex",
            "zrangestore",
            "zunionstore",
            "zinterstore",
            "zdiffstore",
            "xadd",
            "xdel",
            "xtrim",
            "xack",
            "xclaim",
            "xautoclaim",
            "xreadgroup",
            "xsetid",
            "pfadd",
            "pfmerge",
            "pfdebug",
            "setbit",
            "bitfield",
            "bitop",
            "geoadd",
            "georadius",
            "georadiusbymember",
            "geosearchstore",
            "eval",
            "evalsha",
            "fcall",
            "publish",
            "spublish",
            "subscribe",
            "flushall",
            "flushdb",
            "swapdb",
            "save",
            "bgsave",
            "bgrewriteaof",
            "shutdown",
            "replicaof",
            "slaveof",
            "monitor",
            "debug",
            "info",
            "watch",
            "unwatch",
            "wait",
        ] {
            assert!(COMMANDS.binary_search(&name).is_err(), "{name}");
            assert!(!admit(&[name.as_bytes()]), "{name}");
            assert!(!admit(&[name.as_bytes(), b"k", b"v"]), "{name}");
        }
        for (container, sub) in [
            ("config", "set"),
            ("config", "get"),
            ("config", "rewrite"),
            ("config", "resetstat"),
            ("acl", "setuser"),
            ("acl", "deluser"),
            ("acl", "load"),
            ("acl", "save"),
            ("client", "kill"),
            ("client", "pause"),
            ("client", "reply"),
            ("client", "tracking"),
            ("client", "no-evict"),
            ("script", "load"),
            ("script", "flush"),
            ("script", "kill"),
            ("function", "load"),
            ("function", "delete"),
            ("function", "flush"),
            ("function", "restore"),
            ("function", "kill"),
            ("xgroup", "create"),
            ("xgroup", "destroy"),
            ("xgroup", "setid"),
            ("xgroup", "createconsumer"),
            ("xgroup", "delconsumer"),
            ("memory", "purge"),
            ("module", "load"),
            ("module", "unload"),
            ("cluster", "reset"),
            ("cluster", "failover"),
            ("latency", "reset"),
            ("slowlog", "reset"),
        ] {
            assert!(
                SUBCOMMANDS.binary_search(&(container, sub)).is_err(),
                "{container} {sub}"
            );
            assert!(
                !admit(&[container.as_bytes(), sub.as_bytes()]),
                "{container} {sub}"
            );
        }
    }

    #[test]
    fn the_rule_lists_are_pinned() {
        assert_eq!(
            BY_RULE,
            [
                "auth", "discard", "exec", "hello", "multi", "ping", "quit", "reset", "select"
            ]
        );
        assert_eq!(
            REFUSED_WHOLE,
            [
                "acl",
                "config",
                "debug",
                "eval",
                "eval_ro",
                "evalsha",
                "evalsha_ro",
                "fcall",
                "fcall_ro",
                "module",
                "script",
            ]
        );
        assert_eq!(CLIENT_SUBCOMMANDS, ["getname", "id", "info", "setname"]);
    }

    fn run(state: &mut MultiState, commands: &[&str]) -> Vec<Verdict> {
        commands
            .iter()
            .map(|command| state.check(&words(command)))
            .collect()
    }

    #[test]
    fn a_refused_command_in_multi_aborts_exec() {
        let mut state = MultiState::new();
        assert_eq!(
            run(&mut state, &["MULTI", "GET k", "SET k v", "GET j", "EXEC"]),
            [
                Verdict::Forward,
                Verdict::Forward,
                Verdict::Refuse,
                Verdict::Forward,
                Verdict::Abort
            ]
        );
        assert_eq!(
            run(&mut state, &["MULTI", "GET k", "EXEC"]),
            [Verdict::Forward; 3],
            "the abort ended the transaction; the next one is clean"
        );
    }

    #[test]
    fn a_clean_transaction_is_forwarded() {
        let mut state = MultiState::new();
        assert_eq!(
            run(&mut state, &["multi", "GET a", "MGET a b", "exec"]),
            [Verdict::Forward; 4]
        );
    }

    #[test]
    fn discard_clears_a_dirty_transaction() {
        let mut state = MultiState::new();
        assert_eq!(
            run(
                &mut state,
                &["MULTI", "DEL k", "DISCARD", "MULTI", "GET k", "EXEC"]
            ),
            [
                Verdict::Forward,
                Verdict::Refuse,
                Verdict::Forward,
                Verdict::Forward,
                Verdict::Forward,
                Verdict::Forward
            ]
        );
    }

    #[test]
    fn reset_ends_a_dirty_transaction() {
        let mut state = MultiState::new();
        assert_eq!(
            run(&mut state, &["MULTI", "SET k v", "RESET", "EXEC"]),
            [
                Verdict::Forward,
                Verdict::Refuse,
                Verdict::Forward,
                Verdict::Forward
            ]
        );
    }

    #[test]
    fn a_refusal_outside_multi_does_not_mark_a_later_transaction() {
        let mut state = MultiState::new();
        assert_eq!(
            run(&mut state, &["SET k v", "MULTI", "GET k", "EXEC"]),
            [
                Verdict::Refuse,
                Verdict::Forward,
                Verdict::Forward,
                Verdict::Forward
            ]
        );
    }

    #[test]
    fn nested_multi_keeps_the_transaction_and_its_mark() {
        let mut state = MultiState::new();
        assert_eq!(
            run(&mut state, &["MULTI", "SET k v", "MULTI", "GET k", "EXEC"]),
            [
                Verdict::Forward,
                Verdict::Refuse,
                Verdict::Forward,
                Verdict::Forward,
                Verdict::Abort
            ]
        );
        assert_eq!(
            run(&mut state, &["MULTI", "MULTI", "GET k", "EXEC"]),
            [Verdict::Forward; 4]
        );
    }

    #[test]
    fn exec_and_discard_without_multi_are_forwarded() {
        let mut state = MultiState::new();
        assert_eq!(
            run(&mut state, &["EXEC", "DISCARD", "SET k v", "EXEC"]),
            [
                Verdict::Forward,
                Verdict::Forward,
                Verdict::Refuse,
                Verdict::Forward
            ]
        );
    }

    #[test]
    fn an_empty_command_closes() {
        let mut state = MultiState::new();
        assert_eq!(state.check(&[]), Verdict::Close);
        assert_eq!(run(&mut state, &["MULTI"]), [Verdict::Forward]);
        assert_eq!(state.check(&[]), Verdict::Close);
    }

    #[test]
    fn a_refusal_names_the_command_and_a_container_subcommand_only() {
        let named = |args: &[&[u8]]| {
            let refused = refused(args);
            [refused.command, refused.subcommand]
                .into_iter()
                .flatten()
                .map(|name| name.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        };
        for (command, expected) in [
            ("SET zs-key-marker zs-value-marker", "set"),
            ("CLIENT Kill ID 7", "client kill"),
            ("config SET maxmemory 1", "config set"),
            ("EVAL_RO return 0", "eval_ro"),
            ("OBJECT", "object"),
            ("JSON.SET zs-key-marker $ {}", "other"),
            ("zs-ro-command-marker x", "other"),
            ("XINFO zs-ro-argument-marker", "xinfo other"),
            ("OBJECT user:1234", "object other"),
            ("CLIENT a/b", "client other"),
            ("CONFIG k-1 x", "config other"),
            ("XINFO stream|x", "xinfo other"),
            ("XINFO consumers", "xinfo consumers"),
            ("SET kill", "set"),
        ] {
            assert_eq!(named(&words(command)), expected, "{command}");
        }
        assert_eq!(named(&[]), "");
        assert!(READ_ONLY_REFUSED.frame() == b"-NOPERM read-only resource\r\n");
        assert!(
            EXEC_ABORTED.frame()
                == b"-EXECABORT Transaction discarded because of previous errors.\r\n"
        );
    }
}
