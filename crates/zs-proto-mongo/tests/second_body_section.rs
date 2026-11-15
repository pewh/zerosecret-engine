#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use fake::{Script, assert_error};
use zs_proto_mongo::AUTH_BROKERED;
use zs_proto_mongo::bson::Doc;
use zs_proto_mongo::wire::{self, OpMsg, Section};

const MARKER: &str = "zs-review-second-body";

fn sasl_start() -> Doc {
    Doc::new()
        .with_i32("saslStart", 1)
        .with_str("mechanism", MARKER)
        .with_str("$db", "admin")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_auth_command_in_a_second_body_section_is_never_forwarded() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let local = set.listen(None, fake::materialize(fake::PASSWORD)).await;

    let mut session = fake::logged_in(local).await;
    let reply = session.command(fake::find()).await.unwrap();
    assert!(reply.truthy("ok"));
    assert_eq!(
        set.seen(0, |s| s.commands.clone()),
        vec!["find".to_string()],
        "positive control: the session relays a command"
    );

    let reply = session.command(sasl_start()).await.unwrap();
    assert_error(&reply, 18, AUTH_BROKERED.message);
    assert!(session.closed().await);
    assert!(
        !set.saw_bytes(MARKER.as_bytes()),
        "negative control: saslStart as the only body section is refused and not forwarded"
    );

    let mut session = fake::logged_in(local).await;
    let id = session.next_id();
    let frame = OpMsg {
        flags: 0,
        sections: vec![Section::Body(fake::find()), Section::Body(sasl_start())],
    }
    .encode(id, 0);
    assert!(
        OpMsg::parse(&frame[wire::HEADER_LEN..]).is_err(),
        "control: the agent's own OP_MSG parser calls a frame with two body sections malformed"
    );
    session.send(&frame).await.unwrap();
    let relayed = fake::eventually(|| set.saw_bytes(MARKER.as_bytes())).await;
    assert!(
        !relayed,
        "the upstream received a frame whose second body section is saslStart"
    );
}
