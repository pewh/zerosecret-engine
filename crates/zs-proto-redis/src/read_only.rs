use std::cmp::Ordering;

use crate::Reply;
use crate::read_only_commands::{COMMANDS, CONTAINERS, SUBCOMMANDS};

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
const REFUSED_WHOLE: [&str; 8] = [
    "acl", "config", "debug", "eval", "evalsha", "fcall", "module", "script",
];
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
    pub(crate) command: Option<String>,
    pub(crate) subcommand: Option<String>,
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
    Refused {
        command: Some(lowercase(name)),
        subcommand: rest
            .first()
            .filter(|_| is_container(name))
            .map(|sub| lowercase(sub)),
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

fn lowercase(arg: &[u8]) -> String {
    String::from_utf8_lossy(arg).to_ascii_lowercase()
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
            "EVAL_RO return 0",
            "evalsha_ro abc 0",
            "Fcall_Ro f 0",
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
        let names = COMMANDS
            .iter()
            .chain(CONTAINERS.iter())
            .chain(SUBCOMMANDS.iter().flat_map(|(command, sub)| [command, sub]));
        for name in names {
            assert_eq!(*name, name.to_ascii_lowercase());
            assert!(!name.contains('|'));
        }
        for (container, _) in SUBCOMMANDS {
            assert!(CONTAINERS.contains(&container));
        }
        assert!(!COMMANDS.iter().any(|name| CONTAINERS.contains(name)));
    }

    #[test]
    fn the_production_table_is_pinned() {
        assert_eq!(
            (COMMANDS.len(), SUBCOMMANDS.len(), CONTAINERS.len()),
            (84, 8, 15)
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
        for name in CONTAINERS {
            hash.update(name);
            hash.update(b"\n");
        }
        let digest: String = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest,
            "693d513097f5c8e335e2c1726ede9971faa107143e4206b6914d8630fed51948"
        );
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
        }
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
        let set = refused(&words("SET zs-key-marker zs-value-marker"));
        assert_eq!(set.command.as_deref(), Some("set"));
        assert_eq!(set.subcommand, None);
        let kill = refused(&words("CLIENT Kill ID 7"));
        assert_eq!(kill.command.as_deref(), Some("client"));
        assert_eq!(kill.subcommand.as_deref(), Some("kill"));
        let config = refused(&words("config SET maxmemory 1"));
        assert_eq!(config.command.as_deref(), Some("config"));
        assert_eq!(config.subcommand.as_deref(), Some("set"));
        let module = refused(&words("JSON.SET zs-key-marker $ {}"));
        assert_eq!(module.command.as_deref(), Some("json.set"));
        assert_eq!(module.subcommand, None);
        let bare = refused(&words("OBJECT"));
        assert_eq!(bare.command.as_deref(), Some("object"));
        assert_eq!(bare.subcommand, None);
        let empty = refused(&[]);
        assert_eq!(empty.command, None);
        assert_eq!(empty.subcommand, None);
        assert!(READ_ONLY_REFUSED.frame() == b"-NOPERM read-only resource\r\n");
        assert!(
            EXEC_ABORTED.frame()
                == b"-EXECABORT Transaction discarded because of previous errors.\r\n"
        );
    }
}
