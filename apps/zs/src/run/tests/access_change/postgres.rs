#[path = "../../../../../../crates/zs-proto-postgres/tests/fake/mod.rs"]
mod fake;

use fake::{Answer, Script};
use zs_policy::Access;

use super::{ACCESS_CHANGED, ONE_TICK, POOL, Rig, Spec, closes_within_bound};

const BEFORE: &str = "SELECT 'before-change'";
const STILL_GRANTED: &str = "SELECT 'still-granted'";
const REPLACEMENT: &str = "SELECT 'on-a-new-session'";
const REPLACEMENT_AFTER_A_TICK: &str = "SELECT 'new-session-after-a-tick'";

fn start(access: Access) -> (fake::Fake, Rig) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let upstream = runtime.block_on(fake::start(Script::new(Answer::N)));
    let spec = Spec {
        resource: fake::RESOURCE,
        protocol: "postgres",
        extra: String::new(),
        plaintext: false,
        password: fake::PASSWORD,
    };
    let rig = Rig::start(runtime, spec, upstream.addr.port(), access);
    (upstream, rig)
}

fn relayed(upstream: &fake::Fake, sql: &str) -> bool {
    upstream.seen(|s| s.queries.iter().any(|seen| seen == sql))
}

#[test]
fn open_session_closes_within_5s_of_an_access_change_and_is_audited() {
    let (upstream, rig) = start(Access::ReadWrite);
    let local = rig.listener();
    rig.runtime().block_on(async {
        let mut session = fake::login(local)
            .await
            .expect("positive control: the login works");
        fake::query(&mut session, BEFORE).await;
        assert!(
            relayed(&upstream, BEFORE),
            "positive control: the session relays a query"
        );

        rig.renew(Access::ReadWrite);
        tokio::time::sleep(ONE_TICK).await;
        fake::query(&mut session, STILL_GRANTED).await;
        assert!(
            relayed(&upstream, STILL_GRANTED),
            "a renewal with the same access level closed the session"
        );
        assert_eq!(rig.denied(None), 0);

        let held = rig.renew(Access::ReadOnly);
        closes_within_bound(&mut session, held).await;
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
            let mut session = fake::login(local)
                .await
                .expect("positive control: the login works");
            let sql = format!("SELECT 'pool-{n}'");
            fake::query(&mut session, &sql).await;
            assert!(
                relayed(&upstream, &sql),
                "positive control: the connection relays a query"
            );
            pool.push(session);
        }

        let held = rig.renew(Access::ReadWrite);
        for session in &mut pool {
            closes_within_bound(session, held).await;
        }
        rig.denials_reach(ACCESS_CHANGED, POOL).await;

        let mut replacement = fake::login(local)
            .await
            .expect("the next connection must open a new session");
        fake::query(&mut replacement, REPLACEMENT).await;
        assert!(relayed(&upstream, REPLACEMENT));

        tokio::time::sleep(ONE_TICK).await;
        fake::query(&mut replacement, REPLACEMENT_AFTER_A_TICK).await;
        assert!(
            relayed(&upstream, REPLACEMENT_AFTER_A_TICK),
            "the check closed a session that opened after the change"
        );
    });
    rig.assert_connects(POOL + 1, POOL);
}
