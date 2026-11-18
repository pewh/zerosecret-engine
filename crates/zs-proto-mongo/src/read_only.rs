use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::Reply;
use crate::bson::{self, DOCUMENT, Doc, INT64};
use crate::wire::{OpMsg, Section};

pub const READ_ONLY_REASON: &str = "read-only";

pub const READ_ONLY_REFUSED: Reply = Reply {
    code: 13,
    code_name: "Unauthorized",
    message: "zs: refused, read-only resource",
};

pub(crate) const MALFORMED: &str = "malformed";

const EXPLAIN: &str = "explain";
const WRITE_STAGES: [&str; 2] = ["$out", "$merge"];
const ALLOWED: [&str; 17] = [
    "find",
    "getMore",
    "killCursors",
    "count",
    "distinct",
    "aggregate",
    "listCollections",
    "listIndexes",
    "listDatabases",
    "dbStats",
    "collStats",
    EXPLAIN,
    "hello",
    "isMaster",
    "ping",
    "buildInfo",
    "endSessions",
];

pub(crate) struct Refusal {
    pub(crate) command: Option<&'static str>,
    pub(crate) reason: &'static str,
}

const CURSOR: &str = "cursor";
const GET_MORE: &str = "getMore";
const KILL_CURSORS: &str = "killCursors";
const CURSOR_COMMANDS: [&str; 4] = ["find", "aggregate", "listCollections", "listIndexes"];
/// Longer than the server's default cursor timeout (10 min); a `getMore` renews it.
pub(crate) const CURSOR_IDLE: Duration = Duration::from_secs(30 * 60);
pub(crate) const MAX_CURSORS: usize = 65_536;

/// The reply that a forwarded command in a read-only session waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Expect {
    /// A reply that may open a cursor (`find`, `aggregate`, `listCollections`, `listIndexes`).
    Cursor,
    /// The reply to a `getMore` of this cursor.
    More(i64),
}

/// Cursors opened by read-only sessions of one resource. A read-only session admits `getMore`
/// and `killCursors` only for these ids, so a cursor opened in a read-write session (a `$merge`
/// prepared with `batchSize: 0`) cannot finish in a read-only one. Shared by every session of
/// the listener, because a driver pool sends `getMore` on any of its connections.
#[derive(Default)]
pub(crate) struct Cursors {
    open: Mutex<HashMap<i64, Instant>>,
}

impl Cursors {
    fn lock(&self) -> MutexGuard<'_, HashMap<i64, Instant>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn opened(&self, id: i64, now: Instant) {
        if id == 0 {
            return;
        }
        let mut open = self.lock();
        if open.len() >= MAX_CURSORS && !open.contains_key(&id) {
            open.retain(|_, used| now.saturating_duration_since(*used) < CURSOR_IDLE);
            if open.len() >= MAX_CURSORS
                && let Some(oldest) = open
                    .iter()
                    .min_by_key(|(_, used)| **used)
                    .map(|(id, _)| *id)
            {
                open.remove(&oldest);
            }
        }
        open.insert(id, now);
    }

    /// Whether every id is open and was used within [`CURSOR_IDLE`]; marks them used.
    pub(crate) fn known(&self, ids: &[i64], now: Instant) -> bool {
        let mut open = self.lock();
        let live = |used: Option<&Instant>| {
            used.is_some_and(|used| now.saturating_duration_since(*used) < CURSOR_IDLE)
        };
        if ids.is_empty() || !ids.iter().all(|id| live(open.get(id))) {
            return false;
        }
        for id in ids {
            open.insert(*id, now);
        }
        true
    }

    pub(crate) fn closed(&self, ids: &[i64]) {
        let mut open = self.lock();
        for id in ids {
            open.remove(id);
        }
    }

    pub(crate) fn replied(&self, expect: &Expect, payload: &[u8], now: Instant) {
        match (expect, reply_cursor(payload)) {
            (Expect::Cursor, Some(id)) => self.opened(id, now),
            (Expect::More(id), Some(0)) => self.closed(&[*id]),
            _ => {}
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }
}

/// The `cursor.id` of an `OP_MSG` reply payload, read without copying the batch.
pub(crate) fn reply_cursor(payload: &[u8]) -> Option<i64> {
    let body = match payload.get(4..)? {
        [0, body @ ..] => body,
        _ => return None,
    };
    let (kind, cursor) = bson::top_level(body, CURSOR).ok()??;
    if kind != DOCUMENT {
        return None;
    }
    match bson::top_level(cursor, "id").ok()?? {
        (INT64, id) => Some(i64::from_le_bytes(id.try_into().ok()?)),
        _ => None,
    }
}

fn cursor_ids(body: &Doc) -> Option<Vec<i64>> {
    let int64 = |element: &bson::Element| {
        (element.kind == INT64)
            .then(|| {
                element
                    .value
                    .as_slice()
                    .try_into()
                    .ok()
                    .map(i64::from_le_bytes)
            })
            .flatten()
    };
    match body.first_key()? {
        GET_MORE => Some(vec![int64(body.get(GET_MORE)?)?]),
        KILL_CURSORS => {
            let array = body.get("cursors").filter(|e| e.kind == bson::ARRAY)?;
            Doc::parse(&array.value)
                .ok()?
                .elements()
                .iter()
                .map(int64)
                .collect()
        }
        _ => None,
    }
}

fn logged_name(name: &str) -> &'static str {
    ALLOWED
        .iter()
        .find(|allowed| **allowed == name)
        .copied()
        .unwrap_or("other")
}

pub fn check(body: &Doc) -> Result<(), &'static str> {
    admit(body, true)
}

fn admit(body: &Doc, explain_allowed: bool) -> Result<(), &'static str> {
    let name = body.first_key().ok_or(MALFORMED)?;
    let explained = !explain_allowed && [EXPLAIN, GET_MORE, KILL_CURSORS].contains(&name);
    if !ALLOWED.contains(&name) || explained {
        return Err("command");
    }
    let mut seen = HashSet::new();
    if !body.elements().iter().all(|e| seen.insert(e.name.as_str())) {
        return Err("duplicate_key");
    }
    match bson::contains_key(&body.encode(), &WRITE_STAGES) {
        Ok(false) => {}
        Ok(true) => return Err("write_stage"),
        Err(_) => return Err(MALFORMED),
    }
    if name == EXPLAIN {
        let inner = body
            .get(EXPLAIN)
            .filter(|e| e.kind == DOCUMENT)
            .and_then(|e| Doc::parse(&e.value).ok())
            .ok_or(MALFORMED)?;
        return admit(&inner, false);
    }
    Ok(())
}

/// Screens one client message of a read-only session. `Ok(Some(expect))`: forward it and
/// read its reply with [`Cursors::replied`].
pub(crate) fn screen(
    payload: &[u8],
    cursors: &Cursors,
    now: Instant,
) -> Result<Option<Expect>, Refusal> {
    let unparsed = || Refusal {
        command: None,
        reason: MALFORMED,
    };
    let message = OpMsg::parse(payload).map_err(|_| unparsed())?;
    let body = message.body().ok_or_else(unparsed)?;
    let refuse = |reason| Refusal {
        command: body.first_key().map(logged_name),
        reason,
    };
    if message
        .sections
        .iter()
        .any(|section| matches!(section, Section::Sequence(_)))
    {
        return Err(refuse("document_sequence"));
    }
    check(body).map_err(refuse)?;
    let name = body.first_key().unwrap_or_default();
    if CURSOR_COMMANDS.contains(&name) {
        return Ok(Some(Expect::Cursor));
    }
    if ![GET_MORE, KILL_CURSORS].contains(&name) {
        return Ok(None);
    }
    let ids = cursor_ids(body).ok_or_else(|| refuse(CURSOR))?;
    if !cursors.known(&ids, now) {
        return Err(refuse(CURSOR));
    }
    if name == KILL_CURSORS {
        cursors.closed(&ids);
        return Ok(None);
    }
    Ok(Some(Expect::More(ids[0])))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::wire::{self, Section};

    const PINNED: [&str; 17] = [
        "find",
        "getMore",
        "killCursors",
        "count",
        "distinct",
        "aggregate",
        "listCollections",
        "listIndexes",
        "listDatabases",
        "dbStats",
        "collStats",
        "explain",
        "hello",
        "isMaster",
        "ping",
        "buildInfo",
        "endSessions",
    ];

    const REFUSED: [&str; 31] = [
        "insert",
        "update",
        "delete",
        "findAndModify",
        "findandmodify",
        "bulkWrite",
        "create",
        "drop",
        "dropDatabase",
        "createIndexes",
        "dropIndexes",
        "renameCollection",
        "mapReduce",
        "eval",
        "copydb",
        "setParameter",
        "shutdown",
        "fsync",
        "compact",
        "createUser",
        "grantRolesToUser",
        "applyOps",
        "commitTransaction",
        "abortTransaction",
        "collMod",
        "currentOp",
        "killOp",
        "saslStart",
        "authenticate",
        "logout",
        "zsMadeUpCommand",
    ];

    fn command(name: &str) -> Doc {
        Doc::new().with_str(name, "orders").with_str("$db", "appdb")
    }

    fn pipeline(stages: &[Doc]) -> Doc {
        let array = stages
            .iter()
            .enumerate()
            .fold(Doc::new(), |array, (at, stage)| {
                array.with_doc(&at.to_string(), stage)
            });
        Doc::new()
            .with_str("aggregate", "orders")
            .with_array("pipeline", &array)
            .with_doc("cursor", &Doc::new())
            .with_str("$db", "appdb")
    }

    fn stage(name: &str) -> Doc {
        Doc::new().with_str(name, "elsewhere")
    }

    fn array_of(documents: &[Doc]) -> Doc {
        documents
            .iter()
            .enumerate()
            .fold(Doc::new(), |array, (at, document)| {
                array.with_doc(&at.to_string(), document)
            })
    }

    fn explain(inner: &Doc) -> Doc {
        Doc::new()
            .with_doc("explain", inner)
            .with_str("verbosity", "queryPlanner")
            .with_str("$db", "appdb")
    }

    #[test]
    fn the_production_allowlist_is_exactly_seventeen_names() {
        let mut production = super::ALLOWED.to_vec();
        production.sort_unstable();
        let mut pinned = PINNED.to_vec();
        pinned.sort_unstable();
        assert_eq!(production, pinned);
    }

    #[test]
    fn every_allowlisted_name_passes() {
        for name in super::ALLOWED {
            let body = match name {
                "explain" => explain(&command("find")),
                other => command(other),
            };
            assert_eq!(check(&body), Ok(()), "{name}");
        }
    }

    #[test]
    fn the_allowlist_has_no_other_name() {
        for name in REFUSED {
            assert_eq!(check(&command(name)), Err("command"), "{name}");
        }
    }

    #[test]
    fn a_name_that_differs_only_in_case_is_refused() {
        for name in [
            "Find",
            "FIND",
            "getmore",
            "GetMore",
            "killcursors",
            "listcollections",
            "listcollection",
            "ismaster",
            "ISMASTER",
            "buildinfo",
            "Hello",
            "PING",
            "endsessions",
            "Explain",
            "dbstats",
            "collstats",
        ] {
            assert_eq!(check(&command(name)), Err("command"), "{name}");
        }
    }

    #[test]
    fn a_body_with_no_first_key_is_malformed() {
        assert_eq!(check(&Doc::new()), Err("malformed"));
    }

    #[test]
    fn an_aggregate_without_a_write_stage_passes() {
        let body = pipeline(&[
            Doc::new().with_doc("$match", &Doc::new().with_i32("n", 1)),
            stage("$project"),
            stage("$outcome"),
            stage("$mergeObjects"),
        ]);
        assert_eq!(check(&body), Ok(()));
    }

    #[test]
    fn out_and_merge_are_refused_at_every_depth() {
        for write in ["$out", "$merge"] {
            let inside = |wrapper: Doc| pipeline(&[wrapper]);
            let facet = inside(Doc::new().with_doc(
                "$facet",
                &Doc::new().with_array("branch", &array_of(&[stage(write)])),
            ));
            let lookup = inside(
                Doc::new().with_doc(
                    "$lookup",
                    &Doc::new()
                        .with_str("from", "other")
                        .with_str("as", "joined")
                        .with_array("pipeline", &array_of(&[stage(write)])),
                ),
            );
            let union = inside(
                Doc::new().with_doc(
                    "$unionWith",
                    &Doc::new()
                        .with_str("coll", "other")
                        .with_array("pipeline", &array_of(&[stage(write)])),
                ),
            );
            let deep_facet = inside(Doc::new().with_doc(
                "$facet",
                &Doc::new().with_array(
                    "branch",
                    &array_of(&[Doc::new().with_doc(
                        "$unionWith",
                        &Doc::new().with_str("coll", "other").with_array(
                            "pipeline",
                            &array_of(&[Doc::new().with_doc(
                                "$lookup",
                                &Doc::new().with_array("pipeline", &array_of(&[stage(write)])),
                            )]),
                        ),
                    )]),
                ),
            ));
            let filter = Doc::new()
                .with_str("find", "orders")
                .with_doc(
                    "filter",
                    &Doc::new().with_doc(
                        "a",
                        &Doc::new().with_array(
                            "$or",
                            &array_of(&[Doc::new().with_doc("b", &stage(write))]),
                        ),
                    ),
                )
                .with_str("$db", "appdb");
            let top_level = pipeline(&[]).with_str(write, "elsewhere");
            let last_stage = pipeline(&[stage("$match"), stage("$project"), stage(write)]);
            for (place, body) in [
                ("depth one", last_stage),
                ("top level", top_level),
                ("facet", facet),
                ("lookup", lookup),
                ("unionWith", union),
                ("nested three levels", deep_facet),
                ("find filter", filter),
            ] {
                assert_eq!(check(&body), Err("write_stage"), "{write} in {place}");
            }
        }
    }

    #[test]
    fn a_write_stage_key_inside_scoped_code_is_refused() {
        let mut body = command("find");
        let scope = Doc::new().with_i32("$out", 1).encode();
        let source = crate::bson::str_value("function() { return true }");
        let mut value = ((4 + source.len() + scope.len()) as i32)
            .to_le_bytes()
            .to_vec();
        value.extend_from_slice(&source);
        value.extend_from_slice(&scope);
        body.set("filter", 0x0F, value);
        assert_eq!(check(&body), Err("write_stage"));
    }

    #[test]
    fn a_write_stage_name_as_a_value_is_not_a_key() {
        let value_only = Doc::new()
            .with_str("find", "orders")
            .with_doc("filter", &Doc::new().with_str("note", "$out"))
            .with_str("$db", "appdb");
        assert_eq!(check(&value_only), Ok(()));
    }

    #[test]
    fn a_duplicate_top_level_key_is_refused() {
        let mut doubled = command("find").with_doc("filter", &Doc::new());
        let mut elements = doubled.encode();
        let again = Doc::new().with_doc("filter", &Doc::new().with_i32("n", 1));
        let extra = &again.encode()[4..again.encode().len() - 1];
        let last = elements.len() - 1;
        elements.splice(last..last, extra.iter().copied());
        let total = (elements.len() as i32).to_le_bytes();
        elements[..4].copy_from_slice(&total);
        doubled = Doc::read(&elements).unwrap().0;
        assert_eq!(
            doubled
                .elements()
                .iter()
                .filter(|e| e.name == "filter")
                .count(),
            2,
            "control: the document has two filter keys"
        );
        assert_eq!(check(&doubled), Err("duplicate_key"));
        assert_eq!(
            check(&command("find").with_doc("filter", &Doc::new())),
            Ok(()),
            "negative control: one filter key passes"
        );
    }

    #[test]
    fn explain_of_an_allowed_command_passes() {
        for inner in [
            command("find"),
            command("count"),
            command("distinct"),
            pipeline(&[stage("$match"), stage("$project")]),
        ] {
            assert_eq!(check(&explain(&inner)), Ok(()), "{:?}", inner.first_key());
        }
    }

    #[test]
    fn explain_of_a_write_command_is_refused() {
        for name in ["insert", "update", "delete", "findAndModify", "mapReduce"] {
            assert_eq!(
                check(&explain(&command(name))),
                Err("command"),
                "explain {name}"
            );
        }
    }

    #[test]
    fn explain_of_explain_is_refused() {
        let twice = explain(&explain(&command("find")));
        assert_eq!(check(&twice), Err("command"));
    }

    #[test]
    fn explain_of_a_write_stage_is_refused() {
        for write in ["$out", "$merge"] {
            let inner = pipeline(&[stage("$match"), stage(write)]);
            assert_eq!(check(&explain(&inner)), Err("write_stage"), "{write}");
        }
    }

    #[test]
    fn explain_with_a_duplicate_key_in_the_inner_command_is_refused() {
        let inner = command("aggregate").with_array("pipeline", &Doc::new());
        let mut bytes = inner.encode();
        let again = Doc::new().with_array("pipeline", &array_of(&[stage("$match")]));
        let extra = again.encode()[4..again.encode().len() - 1].to_vec();
        let last = bytes.len() - 1;
        bytes.splice(last..last, extra);
        let total = (bytes.len() as i32).to_le_bytes();
        bytes[..4].copy_from_slice(&total);
        let doubled = Doc::read(&bytes).unwrap().0;
        assert_eq!(check(&explain(&doubled)), Err("duplicate_key"));
    }

    #[test]
    fn explain_without_a_command_document_is_refused() {
        let text = Doc::new()
            .with_str("explain", "find")
            .with_str("$db", "appdb");
        assert_eq!(check(&text), Err("malformed"));
        let empty = Doc::new()
            .with_doc("explain", &Doc::new())
            .with_str("$db", "appdb");
        assert_eq!(check(&empty), Err("malformed"));
        let array = Doc::new()
            .with_array("explain", &array_of(&[command("find")]))
            .with_str("$db", "appdb");
        assert_eq!(check(&array), Err("malformed"));
    }

    fn payload(sections: Vec<Section>) -> Vec<u8> {
        let frame = OpMsg { flags: 0, sections }.encode(1, 0);
        frame[wire::HEADER_LEN..].to_vec()
    }

    fn sequence(identifier: &str, documents: &[Doc]) -> Section {
        let mut raw = Vec::new();
        raw.extend_from_slice(identifier.as_bytes());
        raw.push(0);
        for document in documents {
            raw.extend_from_slice(&document.encode());
        }
        let mut section = ((raw.len() + 4) as i32).to_le_bytes().to_vec();
        section.extend_from_slice(&raw);
        Section::Sequence(section)
    }

    #[test]
    fn a_message_with_a_document_sequence_is_refused_with_its_command_name() {
        let plain = payload(vec![Section::Body(command("find"))]);
        assert!(screened(&plain).is_ok(), "positive control");
        for (body, logged) in [
            (command("find"), "find"),
            (command("insert"), "other"),
            (command("aggregate"), "aggregate"),
        ] {
            let with_sequence = payload(vec![
                Section::Body(body),
                sequence("documents", &[Doc::new().with_i32("n", 1)]),
            ]);
            let refusal = screened(&with_sequence).err().unwrap();
            assert_eq!(refusal.reason, "document_sequence", "{logged}");
            assert_eq!(refusal.command, Some(logged));
        }
    }

    #[test]
    fn a_message_that_does_not_parse_is_unparsed() {
        let mut bad = payload(vec![Section::Body(command("find"))]);
        bad.push(0x07);
        let refusal = screened(&bad).err().unwrap();
        assert_eq!(refusal.reason, MALFORMED);
        assert_eq!(refusal.command, None);

        let empty = payload(vec![Section::Body(Doc::new())]);
        let refusal = screened(&empty).err().unwrap();
        assert_eq!(refusal.reason, MALFORMED);

        let no_body = payload(vec![sequence("documents", &[])]);
        assert_eq!(screened(&no_body).err().unwrap().reason, MALFORMED);
    }

    #[test]
    fn a_refusal_names_the_command_and_not_its_arguments() {
        let body = command("insert").with_str("marker", "zs-argument-marker");
        let refusal = screened(&payload(vec![Section::Body(body)])).err().unwrap();
        assert_eq!(refusal.command, Some("other"));
        assert_eq!(refusal.reason, "command");
        let explained = Doc::new()
            .with_doc("explain", &command("insert"))
            .with_str("$db", "appdb");
        let refusal = screened(&payload(vec![Section::Body(explained)]))
            .err()
            .unwrap();
        assert_eq!(refusal.command, Some("explain"));
        assert!(!READ_ONLY_REFUSED.message.contains("insert"));
        let reply = READ_ONLY_REFUSED.doc();
        assert_eq!(reply.int("code"), Some(13));
        assert_eq!(reply.str("codeName"), Some("Unauthorized"));
        assert!(READ_ONLY_REFUSED.message.contains("read-only"));
    }

    fn screened(payload: &[u8]) -> Result<Option<Expect>, Refusal> {
        screen(payload, &Cursors::default(), Instant::now())
    }

    fn get_more(id: i64) -> Vec<u8> {
        payload(vec![Section::Body(
            command("getMore")
                .with_i64("getMore", id)
                .with_str("collection", "orders"),
        )])
    }

    fn kill_cursors(ids: &[i64]) -> Vec<u8> {
        let array = ids.iter().enumerate().fold(Doc::new(), |array, (at, id)| {
            array.with_i64(&at.to_string(), *id)
        });
        payload(vec![Section::Body(
            command("killCursors").with_array("cursors", &array),
        )])
    }

    #[test]
    fn a_cursor_command_expects_a_cursor_reply() {
        for name in ["find", "aggregate", "listCollections", "listIndexes"] {
            let message = payload(vec![Section::Body(command(name))]);
            assert!(
                matches!(screened(&message), Ok(Some(Expect::Cursor))),
                "{name}"
            );
        }
        for name in ["count", "distinct", "ping", "hello", "endSessions"] {
            let message = payload(vec![Section::Body(command(name))]);
            assert!(matches!(screened(&message), Ok(None)), "{name}");
        }
    }

    #[test]
    fn get_more_and_kill_cursors_need_a_cursor_that_a_read_only_session_opened() {
        let cursors = Cursors::default();
        let now = Instant::now();
        for message in [get_more(42), kill_cursors(&[42])] {
            let refusal = screen(&message, &cursors, now).err().unwrap();
            assert_eq!(refusal.reason, "cursor");
        }
        cursors.opened(42, now);
        assert!(matches!(
            screen(&get_more(42), &cursors, now),
            Ok(Some(Expect::More(42)))
        ));
        assert_eq!(
            screen(&kill_cursors(&[42, 7]), &cursors, now)
                .err()
                .unwrap()
                .reason,
            "cursor",
            "every id must be known"
        );
        assert!(matches!(
            screen(&kill_cursors(&[42]), &cursors, now),
            Ok(None)
        ));
        assert_eq!(
            screen(&get_more(42), &cursors, now).err().unwrap().reason,
            "cursor",
            "a killed cursor is forgotten"
        );
        cursors.opened(0, now);
        assert_eq!(
            screen(&get_more(0), &cursors, now).err().unwrap().reason,
            "cursor"
        );
    }

    #[test]
    fn a_cursor_id_that_is_not_an_int64_is_refused() {
        let cursors = Cursors::default();
        cursors.opened(42, Instant::now());
        for body in [
            command("getMore").with_i32("getMore", 42),
            command("getMore").with_str("getMore", "42"),
            command("killCursors").with_array("cursors", &Doc::new().with_i32("0", 42)),
            command("killCursors").with_array("cursors", &Doc::new()),
            command("killCursors"),
        ] {
            let message = payload(vec![Section::Body(body)]);
            assert_eq!(
                screen(&message, &cursors, Instant::now())
                    .err()
                    .unwrap()
                    .reason,
                "cursor"
            );
        }
    }

    #[test]
    fn explain_of_get_more_or_kill_cursors_is_refused() {
        for name in ["getMore", "killCursors"] {
            assert_eq!(check(&explain(&command(name))), Err("command"), "{name}");
        }
    }

    #[test]
    fn an_idle_cursor_is_forgotten_after_thirty_minutes() {
        let cursors = Cursors::default();
        let start = Instant::now();
        cursors.opened(42, start);
        let later = start + CURSOR_IDLE - std::time::Duration::from_secs(1);
        assert!(cursors.known(&[42], later), "use keeps it alive");
        assert!(cursors.known(
            &[42],
            later + CURSOR_IDLE - std::time::Duration::from_secs(1)
        ));
        assert!(!cursors.known(&[42], later + 2 * CURSOR_IDLE));
    }

    #[test]
    fn the_cursor_set_is_bounded_and_drops_the_oldest() {
        let cursors = Cursors::default();
        let start = Instant::now();
        for id in 1..=MAX_CURSORS as i64 {
            cursors.opened(id, start + std::time::Duration::from_millis(id as u64));
        }
        let later = start + std::time::Duration::from_secs(60);
        cursors.opened(-1, later);
        assert!(!cursors.known(&[1], later), "the oldest was dropped");
        assert!(cursors.known(&[2], later));
        assert!(cursors.known(&[-1], later));
        assert_eq!(cursors.len(), MAX_CURSORS);
    }

    fn reply(body: Doc, flags: u32) -> Vec<u8> {
        let frame = OpMsg {
            flags,
            sections: vec![Section::Body(body)],
        }
        .encode(9, 1);
        frame[wire::HEADER_LEN..].to_vec()
    }

    #[test]
    fn a_reply_names_its_cursor_id() {
        let cursor = |id: i64| {
            Doc::new()
                .with_doc(
                    "cursor",
                    &Doc::new()
                        .with_array("firstBatch", &Doc::new())
                        .with_i64("id", id)
                        .with_str("ns", "appdb.orders"),
                )
                .with_f64("ok", 1.0)
        };
        assert_eq!(reply_cursor(&reply(cursor(42), 0)), Some(42));
        assert_eq!(reply_cursor(&reply(cursor(0), 0)), Some(0));
        let error = Doc::new().with_f64("ok", 0.0).with_i32("code", 43);
        assert_eq!(reply_cursor(&reply(error, 0)), None);
        let int32 = Doc::new().with_doc("cursor", &Doc::new().with_i32("id", 42));
        assert_eq!(reply_cursor(&reply(int32, 0)), None);
        assert_eq!(reply_cursor(&[0, 0]), None);
    }

    #[test]
    fn replies_record_and_forget_cursors() {
        let cursors = Cursors::default();
        let now = Instant::now();
        let opened = |id| {
            reply(
                Doc::new().with_doc("cursor", &Doc::new().with_i64("id", id)),
                0,
            )
        };
        cursors.replied(&Expect::Cursor, &opened(42), now);
        assert!(cursors.known(&[42], now));
        cursors.replied(&Expect::Cursor, &opened(0), now);
        assert!(!cursors.known(&[0], now));
        cursors.replied(&Expect::More(42), &opened(42), now);
        assert!(
            cursors.known(&[42], now),
            "a getMore that keeps the cursor open"
        );
        cursors.replied(&Expect::More(42), &opened(0), now);
        assert!(
            !cursors.known(&[42], now),
            "an exhausted cursor is forgotten"
        );
    }
}
