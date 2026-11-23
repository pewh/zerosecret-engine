#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fake::{Client, Script, assert_error};
use tokio::io::AsyncReadExt;
use zs_diag::DiagLog;
use zs_proto_mongo::bson::Doc;
use zs_proto_mongo::wire::OpMsg;
use zs_proto_mongo::{DENIED, Materialize};
use zs_protocol::{Materialized, SessionCheck};

const REVOKED: &str = "grant revoked";
const STILL_GRANTED: &str = "still-granted";
const MARKER: &str = "zs-review-after-revocation";

fn grant_state() -> (Materialize, Arc<AtomicBool>) {
    let granted = Arc::new(AtomicBool::new(true));
    let state = granted.clone();
    let materialize: Materialize = Arc::new(move |_| {
        if !state.load(Ordering::SeqCst) {
            return Err(zs_protocol::Denied::new(REVOKED));
        }
        let state = state.clone();
        let check: SessionCheck = Arc::new(move || {
            if state.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(REVOKED)
            }
        });
        Ok(Materialized::new(
            zs_credential::Credential::from_bytes(fake::PASSWORD.as_bytes().to_vec()).unwrap(),
            zs_protocol::SessionAccess::ReadWrite,
            check,
        ))
    });
    (materialize, granted)
}

fn marked_find(marker: &str) -> Doc {
    Doc::new()
        .with_str("find", marker)
        .with_doc("filter", &Doc::new())
        .with_str("$db", "appdb")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_session_stops_after_the_grant_is_revoked() {
    let set = fake::start(Script::set(1, Some(0))).await;
    let (materialize, granted) = grant_state();
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        set.seed(),
        None,
        materialize,
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut session = fake::logged_in(local).await;
    let reply = session.command(fake::find()).await.unwrap();
    assert!(reply.truthy("ok"));
    assert_eq!(
        set.seen(0, |s| s.commands.clone()),
        vec!["find".to_string()],
        "positive control: the session relays a command while the grant is valid"
    );
    assert!(!set.saw_bytes(MARKER.as_bytes()));

    tokio::time::sleep(Duration::from_secs(6)).await;

    let reply = session
        .command(marked_find(STILL_GRANTED))
        .await
        .expect("a session with a valid grant was closed by the re-check");
    assert!(reply.truthy("ok"));
    assert!(set.saw_bytes(STILL_GRANTED.as_bytes()));
    assert!(refusals.lock().unwrap().is_empty());

    granted.store(false, Ordering::SeqCst);

    let mut second = Client::connect(local).await;
    let reply = second.legacy_handshake().await.unwrap();
    assert_error(&reply, 13, DENIED.message);
    assert!(
        second.closed().await,
        "negative control: a new connection is denied after the revocation"
    );

    tokio::time::sleep(Duration::from_secs(6)).await;

    let mut rest = Vec::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        session.stream.read_to_end(&mut rest),
    )
    .await;
    assert_eq!(
        rest,
        Vec::<u8>::new(),
        "the agent wrote a reply on the session that it ended"
    );
    let id = session.next_id();
    let _ = session
        .send(&OpMsg::new(marked_find(MARKER)).encode(id, 0))
        .await;
    let relayed = fake::eventually(|| set.saw_bytes(MARKER.as_bytes())).await;
    assert!(
        !relayed,
        "the upstream received a command on a session whose grant was revoked 6 s before"
    );
    assert_eq!(*refusals.lock().unwrap(), vec![("connect", REVOKED)]);
}
