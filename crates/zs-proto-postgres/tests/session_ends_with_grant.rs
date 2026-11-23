#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fake::{Answer, Script};
use tokio::io::AsyncReadExt;
use zs_credential::Credential;
use zs_proto_postgres::{
    AuditRefusal, Materialize, PostgresListener, SslPolicy, UpstreamEndpoint, UpstreamTls,
    error_response,
};
use zs_protocol::{Materialized, SessionCheck};

const REVOKED: &str = "grant revoked";
const STILL_GRANTED: &str = "SELECT 'still-granted'";
const MARKER: &str = "SELECT 'zs-review-after-revocation'";

type Refusals = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

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
            Credential::from_bytes(fake::PASSWORD.as_bytes().to_vec()).unwrap(),
            zs_protocol::SessionAccess::ReadWrite,
            check,
        ))
    });
    (materialize, granted)
}

async fn listen_audited(port: u16, materialize: Materialize) -> (SocketAddr, Refusals) {
    let seen: Refusals = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    let audit: AuditRefusal = Arc::new(move |operation: &'static str, reason: &'static str| {
        record.lock().unwrap().push((operation, reason));
        Some(7)
    });
    let listener = PostgresListener::bind_endpoint(
        "127.0.0.1:0",
        UpstreamEndpoint::new("127.0.0.1", port).unwrap(),
        SslPolicy::RefuseOnLoopback,
        UpstreamTls::WhenOffered,
        materialize,
    )
    .await
    .unwrap()
    .with_refusal_audit(audit)
    .with_caller_check(fake::admit_all());
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    (local, seen)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_session_stops_after_the_grant_is_revoked() {
    let upstream = fake::start(Script::new(Answer::N)).await;
    let (materialize, granted) = grant_state();
    let (local, refusals) = listen_audited(upstream.addr.port(), materialize).await;

    let mut session = fake::login(local)
        .await
        .expect("positive control: the login works while the grant is valid");
    fake::query(&mut session, "SELECT 'before-revocation'").await;
    assert_eq!(
        upstream.seen(|s| s.queries.clone()),
        vec!["SELECT 'before-revocation'".to_string()],
        "positive control: the session relays a query while the grant is valid"
    );

    tokio::time::sleep(Duration::from_secs(6)).await;

    fake::query(&mut session, STILL_GRANTED).await;
    assert!(
        upstream.seen(|s| s.queries.iter().any(|sql| sql == STILL_GRANTED)),
        "a session with a valid grant was closed by the re-check"
    );
    assert!(refusals.lock().unwrap().is_empty());

    granted.store(false, Ordering::SeqCst);

    assert_eq!(
        fake::login(local).await.err(),
        Some(error_response(REVOKED)),
        "negative control: a new connection is denied after the revocation"
    );

    tokio::time::sleep(Duration::from_secs(6)).await;

    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), session.read_to_end(&mut rest)).await;
    assert_eq!(
        rest,
        Vec::<u8>::new(),
        "the agent wrote a reply on the session that it ended"
    );
    let mut body = MARKER.as_bytes().to_vec();
    body.push(0);
    let _ = fake::write_tagged(&mut session, b'Q', &body).await;
    let relayed =
        fake::eventually(|| upstream.seen(|s| s.queries.iter().any(|sql| sql == MARKER))).await;
    assert!(
        !relayed,
        "the upstream received a query on a session whose grant was revoked 6 s before"
    );
    assert_eq!(*refusals.lock().unwrap(), vec![("connect", REVOKED)]);
}
