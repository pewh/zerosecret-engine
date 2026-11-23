#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use zs_diag::DiagLog;
use zs_proto_redis::DENIED;
use zs_protocol::{Materialize, Materialized, SessionCheck};

const REVOKED: &str = "grant revoked";
const STILL_GRANTED: &[u8] = b"still-granted";
const MARKER: &[u8] = b"zs-review-after-revocation";

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

#[tokio::test(flavor = "multi_thread")]
async fn an_open_session_stops_after_the_grant_is_revoked() {
    let fake = fake::start(fake::Script::new()).await;
    let (materialize, granted) = grant_state();
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        fake.addr,
        None,
        fake::auth(),
        materialize,
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut session = fake::logged_in(local).await;
    assert_eq!(
        session.command(&[b"GET", b"before-revocation"]).await,
        fake::OK,
        "positive control: the session relays a command while the grant is valid"
    );
    assert!(fake.saw_bytes(b"before-revocation"));

    tokio::time::sleep(Duration::from_secs(6)).await;

    assert_eq!(
        session.command(&[b"GET", STILL_GRANTED]).await,
        fake::OK,
        "a session with a valid grant was closed by the re-check"
    );
    assert!(fake.saw_bytes(STILL_GRANTED));
    assert!(refusals.lock().unwrap().is_empty());

    granted.store(false, Ordering::SeqCst);

    let mut second = fake::Client::connect(local).await;
    assert_eq!(
        second.read_reply().await,
        DENIED.frame(),
        "negative control: a new connection is denied after the revocation"
    );
    assert!(second.closed().await);

    tokio::time::sleep(Duration::from_secs(6)).await;

    assert_eq!(
        session.read_to_end().await,
        Vec::<u8>::new(),
        "the agent wrote a reply on the session that it ended"
    );
    let _ = session.send_command(&[b"GET", MARKER]).await;
    let relayed = fake::eventually(|| fake.saw_bytes(MARKER)).await;
    assert!(
        !relayed,
        "the upstream received a command on a session whose grant was revoked 6 s before"
    );
    assert_eq!(*refusals.lock().unwrap(), vec![("connect", REVOKED)]);
}
