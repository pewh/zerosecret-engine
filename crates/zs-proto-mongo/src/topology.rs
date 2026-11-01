use crate::bson::{ARRAY, Doc, STRING, str_value};
use crate::wire::{DEFAULT_MAX_MESSAGE, HEADER_LEN};

pub const DEFAULT_PORT: u16 = 27017;
pub const MIN_WIRE_VERSION: i64 = 6;
const STRIPPED_FROM_CLIENT: [&str; 3] = [
    "speculativeAuthenticate",
    "saslSupportedMechs",
    "compression",
];
const REMOVED_FROM_REPLY: [&str; 3] = [
    "saslSupportedMechs",
    "speculativeAuthenticate",
    "compression",
];
const SET_ONLY: [&str; 2] = ["passives", "arbiters"];

pub fn is_hello(command: &str) -> bool {
    matches!(command, "hello" | "isMaster" | "ismaster")
}

pub fn strip_client_hello(doc: &mut Doc) {
    for field in STRIPPED_FROM_CLIENT {
        doc.remove(field);
    }
}

pub fn handshake_hello(client: &Doc, database: &str, user: &str, auth_source: &str) -> Doc {
    let mut doc = client.clone();
    strip_client_hello(&mut doc);
    if !doc.contains("$db") {
        doc = doc.with_str("$db", database);
    }
    doc.with_str("saslSupportedMechs", &format!("{auth_source}.{user}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub ok: bool,
    pub set_name: Option<String>,
    pub writable: bool,
    pub mongos: bool,
    pub primary: Option<String>,
    pub hosts: Vec<String>,
    pub max_wire_version: i64,
    pub max_message: usize,
    pub mechanisms: Option<Vec<String>>,
}

impl Hello {
    pub fn read(doc: &Doc) -> Self {
        Self {
            ok: doc.truthy("ok"),
            set_name: doc.str("setName").map(str::to_string),
            writable: doc
                .bool("isWritablePrimary")
                .or_else(|| doc.bool("ismaster"))
                .unwrap_or(false),
            mongos: doc.str("msg") == Some("isdbgrid"),
            primary: doc.str("primary").map(str::to_string),
            hosts: doc.strings("hosts").unwrap_or_default(),
            max_wire_version: doc.int("maxWireVersion").unwrap_or(0),
            max_message: doc
                .int("maxMessageSizeBytes")
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| *n >= HEADER_LEN)
                .map_or(DEFAULT_MAX_MESSAGE, |n| n.min(DEFAULT_MAX_MESSAGE)),
            mechanisms: doc.strings("saslSupportedMechs"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Primary,
    Standalone,
    Mongos,
}

impl Role {
    pub fn code(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Standalone => "standalone",
            Self::Mongos => "mongos",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Discovery {
    Use(Role),
    Redirect(String),
    Refuse(&'static str),
}

pub fn same_host(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

pub fn classify(hello: &Hello) -> Discovery {
    if !hello.ok {
        return Discovery::Refuse("hello_error");
    }
    if hello.max_wire_version < MIN_WIRE_VERSION {
        return Discovery::Refuse("old_server");
    }
    if hello.mongos {
        return Discovery::Use(Role::Mongos);
    }
    if hello.set_name.is_none() {
        return Discovery::Use(Role::Standalone);
    }
    if hello.writable {
        return Discovery::Use(Role::Primary);
    }
    match &hello.primary {
        None => Discovery::Refuse("no_primary"),
        Some(primary) if hello.hosts.iter().any(|h| same_host(h, primary)) => {
            Discovery::Redirect(primary.clone())
        }
        Some(_) => Discovery::Refuse("not_in_hosts"),
    }
}

pub fn confirm_redirect(seed: &Hello, target: &Hello) -> Result<(), &'static str> {
    if !target.ok {
        return Err("hello_error");
    }
    if target.max_wire_version < MIN_WIRE_VERSION {
        return Err("old_server");
    }
    if target.set_name != seed.set_name {
        return Err("set_mismatch");
    }
    if !target.writable {
        return Err("second_redirect");
    }
    Ok(())
}

pub fn confirm_cached(target: &Hello) -> bool {
    target.ok
        && target.max_wire_version >= MIN_WIRE_VERSION
        && target.set_name.is_some()
        && target.writable
}

pub fn rewrite_reply(doc: &mut Doc, listener: &str) {
    for field in REMOVED_FROM_REPLY {
        doc.remove(field);
    }
    if doc.str("setName").is_none() {
        return;
    }
    for field in SET_ONLY {
        doc.remove(field);
    }
    let writable = Hello::read(doc).writable;
    doc.set("hosts", ARRAY, Doc::new().with_str("0", listener).encode());
    doc.set("me", STRING, str_value(listener));
    if writable {
        doc.set("primary", STRING, str_value(listener));
    } else {
        doc.remove("primary");
    }
}

pub fn split_host_port(address: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = address.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if tail.is_empty() => DEFAULT_PORT,
            None => return None,
        };
        (host, port)
    } else {
        match address.rsplit_once(':') {
            Some((host, _)) if host.contains(':') => return None,
            Some((host, port)) => (host, port.parse().ok()?),
            None => (address, DEFAULT_PORT),
        }
    };
    (!host.is_empty()).then(|| (host.to_string(), port))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const LISTENER: &str = "127.0.0.1:41000";

    fn set_reply(writable: bool) -> Doc {
        let mut doc = Doc::new()
            .with_bool("isWritablePrimary", writable)
            .with_str("setName", "rs0")
            .with_strings("hosts", &["a:27017", "b:27017", "c:27017"])
            .with_str("me", "b:27017")
            .with_strings("passives", &["p:27017"])
            .with_strings("arbiters", &["q:27017"])
            .with_strings("saslSupportedMechs", &["SCRAM-SHA-256"])
            .with_doc(
                "speculativeAuthenticate",
                &Doc::new().with_i32("conversationId", 1),
            )
            .with_strings("compression", &["zlib"])
            .with_doc("topologyVersion", &Doc::new().with_i64("counter", 4))
            .with_i32("maxWireVersion", 21)
            .with_f64("ok", 1.0);
        if writable {
            doc = doc.with_str("primary", "b:27017");
        } else {
            doc = doc.with_str("primary", "a:27017");
        }
        doc
    }

    fn hello(set: bool, writable: bool, primary: Option<&str>, hosts: &[&str]) -> Hello {
        Hello {
            ok: true,
            set_name: set.then(|| "rs0".to_string()),
            writable,
            mongos: false,
            primary: primary.map(str::to_string),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            max_wire_version: 21,
            max_message: DEFAULT_MAX_MESSAGE,
            mechanisms: None,
        }
    }

    #[test]
    fn hello_commands_are_named_three_ways() {
        for name in ["hello", "isMaster", "ismaster"] {
            assert!(is_hello(name), "{name}");
        }
        for name in ["HELLO", "find", "saslStart", ""] {
            assert!(!is_hello(name), "{name}");
        }
    }

    #[test]
    fn the_handshake_hello_strips_auth_and_compression_and_names_the_binding_user() {
        let client = Doc::new()
            .with_i32("isMaster", 1)
            .with_bool("helloOk", true)
            .with_doc("client", &Doc::new().with_str("application", "app"))
            .with_strings("compression", &["zlib"])
            .with_str("saslSupportedMechs", "admin.mallory")
            .with_doc(
                "speculativeAuthenticate",
                &Doc::new().with_i32("saslStart", 1),
            );
        let upstream = handshake_hello(&client, "admin", "alice", "appdb");
        assert_eq!(upstream.first_key(), Some("isMaster"));
        assert!(upstream.contains("client"));
        assert!(!upstream.contains("compression"));
        assert!(!upstream.contains("speculativeAuthenticate"));
        assert_eq!(upstream.str("saslSupportedMechs"), Some("appdb.alice"));
        assert_eq!(upstream.str("$db"), Some("admin"));
        assert!(
            client.contains("compression"),
            "the client document is not changed"
        );
    }

    #[test]
    fn the_handshake_hello_keeps_the_client_database() {
        let legacy = handshake_hello(&Doc::new().with_i32("isMaster", 1), "test", "u", "s");
        assert_eq!(legacy.str("$db"), Some("test"));
        let msg = handshake_hello(
            &Doc::new().with_i32("hello", 1).with_str("$db", "test"),
            "admin",
            "u",
            "s",
        );
        assert_eq!(msg.str("$db"), Some("test"));
    }

    #[test]
    fn hello_reads_doubles_and_legacy_names() {
        let doc = Doc::new()
            .with_bool("ismaster", true)
            .with_str("setName", "rs0")
            .with_strings("hosts", &["a:1"])
            .with_i32("maxWireVersion", 17)
            .with_i32("maxMessageSizeBytes", 1000)
            .with_strings("saslSupportedMechs", &["SCRAM-SHA-1"])
            .with_f64("ok", 1.0);
        let read = Hello::read(&doc);
        assert!(read.ok && read.writable);
        assert_eq!(read.max_wire_version, 17);
        assert_eq!(read.max_message, 1000);
        assert_eq!(read.mechanisms, Some(vec!["SCRAM-SHA-1".to_string()]));
        let newer = doc.clone().with_bool("isWritablePrimary", false);
        assert!(
            !Hello::read(&newer).writable,
            "isWritablePrimary wins over ismaster"
        );
        for (size, expected) in [
            (Some(60_000_000), DEFAULT_MAX_MESSAGE),
            (Some(10), DEFAULT_MAX_MESSAGE),
            (None, DEFAULT_MAX_MESSAGE),
        ] {
            let mut sized = doc.clone();
            sized.remove("maxMessageSizeBytes");
            if let Some(size) = size {
                sized = sized.with_i32("maxMessageSizeBytes", size);
            }
            assert_eq!(Hello::read(&sized).max_message, expected, "{size:?}");
        }
        assert!(!Hello::read(&Doc::new().with_i32("ok", 0)).ok);
        assert!(Hello::read(&Doc::new().with_str("msg", "isdbgrid").with_i32("ok", 1)).mongos);
    }

    #[test]
    fn classify_follows_the_spec_table() {
        let primary = hello(true, false, Some("a:1"), &["a:1", "b:1"]);
        let cases = [
            (
                Hello {
                    ok: false,
                    ..hello(true, true, None, &[])
                },
                Discovery::Refuse("hello_error"),
            ),
            (
                Hello {
                    max_wire_version: 5,
                    ..hello(true, true, None, &[])
                },
                Discovery::Refuse("old_server"),
            ),
            (
                Hello {
                    mongos: true,
                    ..hello(false, true, None, &[])
                },
                Discovery::Use(Role::Mongos),
            ),
            (
                hello(false, true, None, &[]),
                Discovery::Use(Role::Standalone),
            ),
            (
                hello(true, true, None, &["a:1"]),
                Discovery::Use(Role::Primary),
            ),
            (primary, Discovery::Redirect("a:1".to_string())),
            (
                hello(true, false, None, &["a:1"]),
                Discovery::Refuse("no_primary"),
            ),
            (
                hello(true, false, Some("z:1"), &["a:1"]),
                Discovery::Refuse("not_in_hosts"),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(classify(&input), expected);
        }
    }

    #[test]
    fn host_names_match_without_case_and_ipv6_splits() {
        assert!(same_host("DB1:27017", "db1:27017"));
        assert!(!same_host("db1:27017", "db2:27017"));
        assert_eq!(
            classify(&hello(true, false, Some("DB1:27017"), &["db1:27017"])),
            Discovery::Redirect("DB1:27017".to_string())
        );
        for (input, expected) in [
            ("[::1]:27018", Some(("::1", 27018))),
            ("[::1]", Some(("::1", DEFAULT_PORT))),
            ("db:1234", Some(("db", 1234))),
            ("db", Some(("db", DEFAULT_PORT))),
            ("::1", None),
            ("", None),
            ("db:x", None),
            ("[::1]x", None),
            (":27017", None),
        ] {
            assert_eq!(
                split_host_port(input),
                expected.map(|(h, p)| (h.to_string(), p)),
                "{input}"
            );
        }
    }

    #[test]
    fn redirect_and_cache_confirmation_checks_the_target() {
        let seed = hello(true, false, Some("a:1"), &["a:1"]);
        assert_eq!(
            confirm_redirect(&seed, &hello(true, true, None, &["a:1"])),
            Ok(())
        );
        let cases = [
            (
                Hello {
                    ok: false,
                    ..hello(true, true, None, &[])
                },
                "hello_error",
            ),
            (
                Hello {
                    max_wire_version: 4,
                    ..hello(true, true, None, &[])
                },
                "old_server",
            ),
            (
                Hello {
                    set_name: Some("other".into()),
                    ..hello(true, true, None, &[])
                },
                "set_mismatch",
            ),
            (hello(true, false, None, &[]), "second_redirect"),
        ];
        for (target, kind) in cases {
            assert_eq!(confirm_redirect(&seed, &target), Err(kind));
        }
        assert!(confirm_cached(&hello(true, true, None, &[])));
        assert!(!confirm_cached(&hello(false, true, None, &[])));
        assert!(!confirm_cached(&hello(true, false, None, &[])));
    }

    #[test]
    fn a_set_reply_is_rewritten_to_one_member() {
        let mut writable = set_reply(true);
        rewrite_reply(&mut writable, LISTENER);
        assert_eq!(writable.strings("hosts"), Some(vec![LISTENER.to_string()]));
        assert_eq!(writable.str("me"), Some(LISTENER));
        assert_eq!(writable.str("primary"), Some(LISTENER));
        for gone in [
            "passives",
            "arbiters",
            "saslSupportedMechs",
            "speculativeAuthenticate",
            "compression",
        ] {
            assert!(!writable.contains(gone), "{gone}");
        }
        assert_eq!(writable.str("setName"), Some("rs0"));
        assert_eq!(
            writable.doc("topologyVersion").unwrap().int("counter"),
            Some(4)
        );
        let names: Vec<&str> = writable
            .elements()
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(names[..4], ["isWritablePrimary", "setName", "hosts", "me"]);

        let mut secondary = set_reply(false);
        rewrite_reply(&mut secondary, LISTENER);
        assert!(!secondary.contains("primary"));
        assert_eq!(secondary.strings("hosts"), Some(vec![LISTENER.to_string()]));
        assert_eq!(secondary.str("me"), Some(LISTENER));
    }

    #[test]
    fn duplicate_keys_from_the_server_do_not_survive_the_rewrite() {
        let mut doc = set_reply(true);
        doc = doc.with_strings("hosts", &["a:27017"]).with_f64("ok", 1.0);
        let mut bytes = doc.encode();
        let extra = Doc::new()
            .with_str("me", "evil:1")
            .with_str("primary", "evil:2")
            .with_strings("hosts", &["evil:3"])
            .with_strings("passives", &["evil:4"])
            .encode();
        bytes.pop();
        bytes.extend_from_slice(&extra[4..]);
        let total = (bytes.len() as i32).to_le_bytes();
        bytes[..4].copy_from_slice(&total);
        let mut doc = Doc::parse(&bytes).unwrap();
        assert_eq!(doc.elements().iter().filter(|e| e.name == "me").count(), 2);
        rewrite_reply(&mut doc, LISTENER);
        for name in ["me", "primary", "hosts"] {
            assert_eq!(
                doc.elements().iter().filter(|e| e.name == name).count(),
                1,
                "{name}"
            );
        }
        assert!(!doc.contains("passives"));
        assert_eq!(doc.str("me"), Some(LISTENER));
        assert_eq!(doc.str("primary"), Some(LISTENER));
        assert_eq!(doc.strings("hosts"), Some(vec![LISTENER.to_string()]));
    }

    #[test]
    fn standalone_and_mongos_replies_keep_their_shape() {
        for extra in [None, Some("isdbgrid")] {
            let mut doc = Doc::new()
                .with_bool("isWritablePrimary", true)
                .with_strings("compression", &["zlib"])
                .with_strings("saslSupportedMechs", &["SCRAM-SHA-256"])
                .with_f64("ok", 1.0);
            if let Some(msg) = extra {
                doc = doc.with_str("msg", msg);
            }
            rewrite_reply(&mut doc, LISTENER);
            assert!(!doc.contains("compression") && !doc.contains("saslSupportedMechs"));
            assert!(!doc.contains("hosts") && !doc.contains("me") && !doc.contains("primary"));
            assert!(doc.truthy("ok"));
        }
    }
}
