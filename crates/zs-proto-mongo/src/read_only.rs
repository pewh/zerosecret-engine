use std::collections::HashSet;

use crate::Reply;
use crate::bson::{self, DOCUMENT, Doc};
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
    pub(crate) command: Option<String>,
    pub(crate) reason: &'static str,
}

pub fn check(body: &Doc) -> Result<(), &'static str> {
    admit(body, true)
}

fn admit(body: &Doc, explain_allowed: bool) -> Result<(), &'static str> {
    let name = body.first_key().ok_or(MALFORMED)?;
    if !ALLOWED.contains(&name) || (name == EXPLAIN && !explain_allowed) {
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

pub(crate) fn screen(payload: &[u8]) -> Result<(), Refusal> {
    let unparsed = || Refusal {
        command: None,
        reason: MALFORMED,
    };
    let message = OpMsg::parse(payload).map_err(|_| unparsed())?;
    let body = message.body().ok_or_else(unparsed)?;
    let refuse = |reason| Refusal {
        command: body.first_key().map(str::to_string),
        reason,
    };
    if message
        .sections
        .iter()
        .any(|section| matches!(section, Section::Sequence(_)))
    {
        return Err(refuse("document_sequence"));
    }
    check(body).map_err(refuse)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::wire::{self, Section};

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
    fn every_allowlisted_name_passes() {
        for name in ALLOWED {
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
        assert!(screen(&plain).is_ok(), "positive control");
        for body in [command("find"), command("insert"), command("aggregate")] {
            let name = body.first_key().unwrap().to_string();
            let with_sequence = payload(vec![
                Section::Body(body),
                sequence("documents", &[Doc::new().with_i32("n", 1)]),
            ]);
            let refusal = screen(&with_sequence).err().unwrap();
            assert_eq!(refusal.reason, "document_sequence", "{name}");
            assert_eq!(refusal.command.as_deref(), Some(name.as_str()));
        }
    }

    #[test]
    fn a_message_that_does_not_parse_is_unparsed() {
        let mut bad = payload(vec![Section::Body(command("find"))]);
        bad.push(0x07);
        let refusal = screen(&bad).err().unwrap();
        assert_eq!(refusal.reason, MALFORMED);
        assert_eq!(refusal.command, None);

        let empty = payload(vec![Section::Body(Doc::new())]);
        let refusal = screen(&empty).err().unwrap();
        assert_eq!(refusal.reason, MALFORMED);

        let no_body = payload(vec![sequence("documents", &[])]);
        assert_eq!(screen(&no_body).err().unwrap().reason, MALFORMED);
    }

    #[test]
    fn a_refusal_names_the_command_and_not_its_arguments() {
        let body = command("insert").with_str("marker", "zs-argument-marker");
        let refusal = screen(&payload(vec![Section::Body(body)])).err().unwrap();
        assert_eq!(refusal.command.as_deref(), Some("insert"));
        assert_eq!(refusal.reason, "command");
        assert!(!READ_ONLY_REFUSED.message.contains("insert"));
        let reply = READ_ONLY_REFUSED.doc();
        assert_eq!(reply.int("code"), Some(13));
        assert_eq!(reply.str("codeName"), Some("Unauthorized"));
        assert!(READ_ONLY_REFUSED.message.contains("read-only"));
    }
}
