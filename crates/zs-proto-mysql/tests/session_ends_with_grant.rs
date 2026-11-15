#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use fake::{CLIENT_CAPS, Flow, Script};
use tokio::io::AsyncReadExt;
use zs_diag::DiagLog;
use zs_proto_mysql::packet;
use zs_proto_mysql::{DENIED, Materialize, UpstreamTls};
use zs_protocol::{Materialized, SessionCheck};

const REVOKED: &str = "grant revoked";
const BEFORE: &[u8] = b"SELECT 'before-revocation'";
const STILL_GRANTED: &[u8] = b"SELECT 'still-granted'";
const MARKER: &[u8] = b"SELECT 'zs-review-after-revocation'";

fn grant_state() -> (Materialize, Arc<AtomicBool>) {
    let granted = Arc::new(AtomicBool::new(true));
    let state = granted.clone();
    let materialize: Materialize = Arc::new(move || {
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

fn com_query(sql: &[u8]) -> Vec<u8> {
    let mut command = vec![packet::COM_QUERY];
    command.extend_from_slice(sql);
    command
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_session_stops_after_the_grant_is_revoked() {
    let fake = fake::start(Script::new(packet::NATIVE_PASSWORD, Flow::Accept)).await;
    let (materialize, granted) = grant_state();
    let (audit, refusals) = fake::audit_recorder();
    let local = fake::listen(
        "127.0.0.1",
        fake.addr.port(),
        UpstreamTls::WhenOffered,
        materialize,
        DiagLog::disabled(),
        Some(audit),
    )
    .await;

    let mut session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control: the login works while the grant is valid"
    );
    let reply = session.command(&com_query(BEFORE)).await.unwrap();
    assert_eq!(reply.payload.first(), Some(&packet::OK_HEADER));
    assert_eq!(
        fake.seen(|s| s.commands.clone()),
        vec![com_query(BEFORE)],
        "positive control: the session relays a command while the grant is valid"
    );

    tokio::time::sleep(Duration::from_secs(6)).await;

    let reply = session
        .command(&com_query(STILL_GRANTED))
        .await
        .expect("a session with a valid grant was closed by the re-check");
    assert_eq!(reply.payload.first(), Some(&packet::OK_HEADER));
    assert_eq!(
        fake.seen(|s| s.commands.clone()),
        vec![com_query(BEFORE), com_query(STILL_GRANTED)]
    );
    assert!(refusals.lock().unwrap().is_empty());

    granted.store(false, Ordering::SeqCst);

    let second = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(
        second.reply.payload,
        DENIED.packet(),
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
    let marker = com_query(MARKER);
    let _ = packet::write_packet(&mut session.stream, 0, &marker).await;
    let relayed = fake::eventually(|| fake.seen(|s| s.commands.iter().any(|c| c == &marker))).await;
    assert!(
        !relayed,
        "the upstream received a command on a session whose grant was revoked 6 s before"
    );
    assert_eq!(*refusals.lock().unwrap(), vec![("connect", REVOKED)]);
}
