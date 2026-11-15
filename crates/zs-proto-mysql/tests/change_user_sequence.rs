#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use fake::{CLIENT_CAPS, Flow, Script};
use zs_proto_mysql::packet;
use zs_proto_mysql::{CHANGE_USER_REFUSED, UpstreamTls};

const MARKER: &[u8] = b"zs-review-change-user";
const CONTINUATION_MARKER: &[u8] = b"zs-review-continuation";

fn change_user() -> Vec<u8> {
    let mut command = vec![packet::COM_CHANGE_USER];
    command.extend_from_slice(MARKER);
    command.extend_from_slice(&[0, 0]);
    command
}

#[tokio::test(flavor = "multi_thread")]
async fn change_user_with_a_nonzero_sequence_id_is_never_forwarded() {
    let fake = fake::start(Script::new(packet::NATIVE_PASSWORD, Flow::Accept)).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(fake::PASSWORD))
        .await;

    let mut session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(
        session.reply.payload.first(),
        Some(&packet::OK_HEADER),
        "positive control: the login works"
    );
    let answer = session.command(b"\x03SELECT 1").await.unwrap();
    assert!(
        answer.payload.ends_with(fake::OK_INFO),
        "positive control: the session relays a command"
    );

    let refused = session.command(&change_user()).await.unwrap();
    assert_eq!(refused.payload, CHANGE_USER_REFUSED.packet());
    assert!(session.closed().await);
    assert!(
        !fake.saw_bytes(MARKER),
        "negative control: COM_CHANGE_USER with sequence id 0 is refused and not forwarded"
    );

    let mut session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload.first(), Some(&packet::OK_HEADER));
    let _ = packet::write_packet(&mut session.stream, 1, &change_user()).await;
    let relayed = fake::eventually(|| fake.saw_bytes(MARKER)).await;
    assert!(
        !relayed,
        "the upstream received COM_CHANGE_USER in a packet with sequence id 1"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_continuation_packet_that_starts_with_0x11_is_forwarded() {
    let fake = fake::start(Script::new(packet::NATIVE_PASSWORD, Flow::Accept)).await;
    let local = fake
        .listen(UpstreamTls::WhenOffered, fake::materialize(fake::PASSWORD))
        .await;

    let mut session = fake::login(local, CLIENT_CAPS).await;
    assert_eq!(session.reply.payload.first(), Some(&packet::OK_HEADER));

    let mut command = vec![b' '; packet::MAX_PAYLOAD];
    command[0] = packet::COM_QUERY;
    command.push(packet::COM_CHANGE_USER);
    command.extend_from_slice(CONTINUATION_MARKER);
    let wire = packet::frame(0, &command);
    assert_eq!(
        wire[..5],
        [0xff, 0xff, 0xff, 0, packet::COM_QUERY],
        "control: the first packet has sequence id 0 and exactly 0xff_ffff payload bytes"
    );
    assert_eq!(
        wire[4 + packet::MAX_PAYLOAD..][3..5],
        [1, packet::COM_CHANGE_USER],
        "control: the continuation packet has sequence id 1 and starts with 0x11"
    );

    let answer = session.command(&command).await.unwrap();
    assert!(
        answer.payload.ends_with(fake::OK_INFO),
        "the upstream answered the command of two packets"
    );
    assert!(
        fake.seen(|s| s.commands.last().is_some_and(|seen| {
            seen.len() == command.len()
                && seen[packet::MAX_PAYLOAD] == packet::COM_CHANGE_USER
                && seen.ends_with(CONTINUATION_MARKER)
        })),
        "the upstream received the continuation packet and its marker"
    );

    let answer = session.command(b"\x03SELECT 1").await.unwrap();
    assert!(
        answer.payload.ends_with(fake::OK_INFO),
        "the session is still open"
    );
}
