#[path = "../../../../../../crates/zs-proto-mysql/tests/fake/mod.rs"]
mod fake;

use fake::{CLIENT_CAPS, Flow, Script};
use zs_policy::Access;
use zs_proto_mysql::packet;

use super::{ACCESS_CHANGED, ONE_TICK, POOL, Rig, Spec, closes_within_bound};

const BEFORE: &[u8] = b"SELECT 'before-change'";
const STILL_GRANTED: &[u8] = b"SELECT 'still-granted'";
const REPLACEMENT: &[u8] = b"SELECT 'on-a-new-session'";
const REPLACEMENT_AFTER_A_TICK: &[u8] = b"SELECT 'new-session-after-a-tick'";

fn start(access: Access) -> (fake::Fake, Rig) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let upstream = runtime.block_on(fake::start(Script::new(
        packet::NATIVE_PASSWORD,
        Flow::Accept,
    )));
    let spec = Spec {
        resource: fake::RESOURCE,
        protocol: "mysql",
        extra: String::new(),
        plaintext: false,
        password: fake::PASSWORD,
    };
    let rig = Rig::start(runtime, spec, upstream.addr.port(), access);
    (upstream, rig)
}

fn com_query(sql: &[u8]) -> Vec<u8> {
    let mut command = vec![packet::COM_QUERY];
    command.extend_from_slice(sql);
    command
}

async fn answers(session: &mut fake::Session, sql: &[u8]) {
    let reply = session.command(&com_query(sql)).await.unwrap();
    assert_eq!(reply.payload.first(), Some(&packet::OK_HEADER));
}

fn relayed(upstream: &fake::Fake, sql: &[u8]) -> bool {
    let command = com_query(sql);
    upstream.seen(|s| s.commands.iter().any(|seen| seen == &command))
}

async fn login(local: std::net::SocketAddr) -> fake::Session {
    let session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control: the login works"
    );
    session
}

#[test]
fn open_session_closes_within_5s_of_an_access_change_and_is_audited() {
    let (upstream, rig) = start(Access::ReadWrite);
    let local = rig.listener();
    rig.runtime().block_on(async {
        let mut session = login(local).await;
        answers(&mut session, BEFORE).await;
        assert!(
            relayed(&upstream, BEFORE),
            "positive control: the session relays a command"
        );

        rig.renew(Access::ReadWrite);
        tokio::time::sleep(ONE_TICK).await;
        answers(&mut session, STILL_GRANTED).await;
        assert!(
            relayed(&upstream, STILL_GRANTED),
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
    let (upstream, rig) = start(Access::ReadOnly);
    let local = rig.listener();
    rig.runtime().block_on(async {
        let mut pool = Vec::new();
        for n in 0..POOL {
            let mut session = login(local).await;
            let sql = format!("SELECT 'pool-{n}'");
            answers(&mut session, sql.as_bytes()).await;
            assert!(
                relayed(&upstream, sql.as_bytes()),
                "positive control: the connection relays a command"
            );
            pool.push(session);
        }

        let held = rig.renew(Access::ReadWrite);
        for session in &mut pool {
            closes_within_bound(&mut session.stream, held).await;
        }
        rig.denials_reach(ACCESS_CHANGED, POOL).await;

        let mut replacement = login(local).await;
        answers(&mut replacement, REPLACEMENT).await;
        assert!(relayed(&upstream, REPLACEMENT));

        tokio::time::sleep(ONE_TICK).await;
        answers(&mut replacement, REPLACEMENT_AFTER_A_TICK).await;
        assert!(
            relayed(&upstream, REPLACEMENT_AFTER_A_TICK),
            "the check closed a session that opened after the change"
        );
    });
    rig.assert_connects(POOL + 1, POOL);
}
