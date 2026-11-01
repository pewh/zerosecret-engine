#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::time::{Duration, Instant};

use fake::{PASSWORD, Script};
use zs_proto_mongo::bson::Doc;

fn hello() -> Doc {
    Doc::new().with_i32("hello", 1).with_str("$db", "admin")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_step_down_closes_every_pinned_connection_and_the_next_one_finds_the_new_primary() {
    let set = fake::start(Script::set(3, Some(0))).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        set.seed(),
        None,
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
    )
    .await;
    let mut a = fake::logged_in(local).await;
    let mut b = fake::logged_in(local).await;
    assert!(
        b.command(fake::find()).await.unwrap().truthy("ok"),
        "positive control"
    );

    set.set_primary(Some(2));
    let reply = a.command(hello()).await.unwrap();
    assert_eq!(reply.bool("isWritablePrimary"), Some(false));
    assert!(
        !reply.contains("primary"),
        "a stale member is never shown as primary"
    );
    assert_eq!(reply.strings("hosts"), Some(vec![local.to_string()]));
    assert!(
        a.closed().await,
        "the stepped-down connection closes after the reply"
    );
    assert!(
        b.closed().await,
        "the other connection pinned to the old primary closes"
    );

    let mut c = fake::logged_in(local).await;
    assert!(c.command(fake::find()).await.unwrap().truthy("ok"));
    assert!(set.seen(2, |s| s.authenticated));
    assert_eq!(
        set.seen(2, |s| s.commands.clone()),
        vec!["find".to_string()]
    );

    let (log, events) = fake::read_diag(&path, diag).await;
    for conn in [1, 2] {
        assert_eq!(
            fake::in_conn(&events, "stepdown", conn)[0]["fields"]["trigger"],
            "hello",
            "{log}"
        );
        assert_eq!(
            fake::in_conn(&events, "conn_closed", conn)[0]["fields"]["closed_by"],
            "stepdown",
            "{log}"
        );
    }
    assert_eq!(
        fake::in_conn(&events, "discovery", 3)[0]["fields"]["role"],
        "redirect",
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_connection_dials_the_cached_primary_first() {
    let set = fake::start(Script::set(3, Some(1))).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        set.seed(),
        None,
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
    )
    .await;
    let mut first = fake::logged_in(local).await;
    assert!(first.command(fake::find()).await.unwrap().truthy("ok"));
    let seed_accepts = set.seen(0, |s| s.accepts);

    let mut second = fake::logged_in(local).await;
    assert!(second.command(fake::find()).await.unwrap().truthy("ok"));
    assert_eq!(
        set.seen(0, |s| s.accepts),
        seed_accepts,
        "the cached primary skipped the seed"
    );
    assert_eq!(set.seen(1, |s| s.accepts), 2);
    assert!(
        first.command(fake::find()).await.unwrap().truthy("ok"),
        "the same primary keeps the first connection open"
    );

    let (log, events) = fake::read_diag(&path, diag).await;
    assert_eq!(
        fake::in_conn(&events, "discovery", 1)[0]["fields"]["role"],
        "redirect",
        "{log}"
    );
    assert_eq!(
        fake::in_conn(&events, "discovery", 2)[0]["fields"]["role"],
        "cached",
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cached_primary_that_stepped_down_is_marked_stale_and_closes_its_connections() {
    let set = fake::start(Script::set(2, Some(0))).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen(
        set.seed(),
        None,
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
    )
    .await;
    let mut old = fake::logged_in(local).await;
    assert!(
        old.command(fake::find()).await.unwrap().truthy("ok"),
        "positive control"
    );

    set.set_primary(Some(1));
    let mut new = fake::logged_in(local).await;
    assert!(new.command(fake::find()).await.unwrap().truthy("ok"));
    assert!(set.seen(1, |s| s.authenticated));
    assert!(
        old.closed().await,
        "the connection pinned to the old primary closes"
    );
    assert_eq!(
        set.seen(0, |s| s.accepts),
        3,
        "old login, the cached attempt and the seed discovery"
    );

    let (log, events) = fake::read_diag(&path, diag).await;
    let trigger = &fake::in_conn(&events, "stepdown", 1)[0]["fields"]["trigger"];
    assert!(
        trigger == "hello" || trigger == "newer_primary",
        "{trigger} {log}"
    );
    assert_eq!(
        fake::in_conn(&events, "discovery", 2)[0]["fields"]["role"],
        "redirect",
        "{log}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn standalone_connections_are_never_pinned() {
    let set = fake::start(Script::standalone()).await;
    let local = set.listen(None, fake::materialize(PASSWORD)).await;
    let mut a = fake::logged_in(local).await;
    let mut b = fake::logged_in(local).await;
    for client in [&mut a, &mut b] {
        assert!(client.command(fake::find()).await.unwrap().truthy("ok"));
        assert!(client.command(hello()).await.unwrap().truthy("ok"));
    }
    assert!(
        a.command(fake::find()).await.unwrap().truthy("ok"),
        "a stays open"
    );
    assert_eq!(set.seen(0, |s| s.accepts), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cached_primary_that_stalls_falls_back_to_the_seed_within_the_budget() {
    let set = fake::start(Script::set(2, Some(1))).await;
    let dir = tempfile::tempdir().unwrap();
    let (path, diag) = fake::diag_log(dir.path());
    let local = fake::listen_with(
        set.seed(),
        None,
        fake::materialize(PASSWORD),
        diag.clone(),
        None,
        Some(Duration::from_secs(3)),
    )
    .await;
    let mut first = fake::logged_in(local).await;
    assert!(first.command(fake::find()).await.unwrap().truthy("ok"));
    let mut cached = fake::logged_in(local).await;
    assert!(cached.command(fake::find()).await.unwrap().truthy("ok"));
    assert_eq!(
        set.seen(1, |s| s.accepts),
        2,
        "positive control: the cached path is used"
    );

    set.set_primary(Some(0));
    set.silence(Some(1));
    let started = Instant::now();
    let mut fallback = fake::logged_in(local).await;
    assert!(fallback.command(fake::find()).await.unwrap().truthy("ok"));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the cached attempt has its own limit"
    );
    assert_eq!(
        set.seen(1, |s| s.accepts),
        3,
        "the stalled cached member was tried"
    );
    assert!(set.seen(0, |s| s.authenticated));

    let (log, events) = fake::read_diag(&path, diag).await;
    assert_eq!(
        fake::in_conn(&events, "discovery", 2)[0]["fields"]["role"],
        "cached",
        "{log}"
    );
    assert_eq!(
        fake::in_conn(&events, "discovery", 3)[0]["fields"]["role"],
        "primary",
        "{log}"
    );
}
