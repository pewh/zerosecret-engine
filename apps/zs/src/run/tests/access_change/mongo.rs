#[path = "../../../../../../crates/zs-proto-mongo/tests/fake/mod.rs"]
mod fake;

use zs_policy::Access;
use zs_proto_mongo::bson::Doc;

use super::{ACCESS_CHANGED, ONE_TICK, POOL, Rig, Spec, closes_within_bound};

const BEFORE: &str = "before-change";
const STILL_GRANTED: &str = "still-granted";
const REPLACEMENT: &str = "on-a-new-session";
const REPLACEMENT_AFTER_A_TICK: &str = "new-session-after-a-tick";

fn start(access: Access) -> (fake::FakeSet, Rig) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let upstream = runtime.block_on(fake::start(fake::Script::set(1, Some(0))));
    let spec = Spec {
        resource: fake::RESOURCE,
        protocol: "mongo",
        extra: format!(
            r#","user":"{}","auth_source":"{}","upstream_plaintext":true"#,
            fake::USER,
            fake::SOURCE
        ),
        plaintext: true,
        password: fake::PASSWORD,
    };
    let rig = Rig::start(runtime, spec, upstream.seed().port(), access);
    (upstream, rig)
}

fn marked_find(marker: &str) -> Doc {
    Doc::new()
        .with_str("find", marker)
        .with_doc("filter", &Doc::new())
        .with_str("$db", "appdb")
}

async fn answers(client: &mut fake::Client, marker: &str) {
    let reply = client.command(marked_find(marker)).await.unwrap();
    assert!(reply.truthy("ok"));
}

#[test]
fn open_session_closes_within_5s_of_an_access_change_and_is_audited() {
    let (upstream, rig) = start(Access::ReadWrite);
    let local = rig.listener();
    rig.runtime().block_on(async {
        let mut session = fake::logged_in(local).await;
        answers(&mut session, BEFORE).await;
        assert!(
            upstream.saw_bytes(BEFORE.as_bytes()),
            "positive control: the session relays a command"
        );

        rig.renew(Access::ReadWrite);
        tokio::time::sleep(ONE_TICK).await;
        answers(&mut session, STILL_GRANTED).await;
        assert!(
            upstream.saw_bytes(STILL_GRANTED.as_bytes()),
            "a renewal with the same access level closed the session"
        );
        assert_eq!(rig.denied(None), 0);

        let held = rig.renew(Access::ReadOnly);
        closes_within_bound(&mut session.stream, held).await;
        rig.denials_reach(ACCESS_CHANGED, 1).await;
    });
    rig.assert_connects(1, 1);
}

#[test]
fn pool_reconnects_after_access_change() {
    let (upstream, rig) = start(Access::ReadWrite);
    let local = rig.listener();
    rig.runtime().block_on(async {
        let mut pool = Vec::new();
        for n in 0..POOL {
            let mut session = fake::logged_in(local).await;
            let marker = format!("pool-{n}");
            answers(&mut session, &marker).await;
            assert!(
                upstream.saw_bytes(marker.as_bytes()),
                "positive control: the connection relays a command"
            );
            pool.push(session);
        }

        let held = rig.renew(Access::ReadOnly);
        for session in &mut pool {
            closes_within_bound(&mut session.stream, held).await;
        }
        rig.denials_reach(ACCESS_CHANGED, POOL).await;

        let mut replacement = fake::logged_in(local).await;
        answers(&mut replacement, REPLACEMENT).await;
        assert!(upstream.saw_bytes(REPLACEMENT.as_bytes()));

        tokio::time::sleep(ONE_TICK).await;
        answers(&mut replacement, REPLACEMENT_AFTER_A_TICK).await;
        assert!(
            upstream.saw_bytes(REPLACEMENT_AFTER_A_TICK.as_bytes()),
            "the check closed a session that opened after the change"
        );
    });
    rig.assert_connects(POOL + 1, POOL);
}
