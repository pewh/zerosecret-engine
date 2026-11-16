#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod fake;

use std::net::SocketAddr;
use std::sync::Arc;

use fake::Client;
use zs_diag::DiagLog;
use zs_proto_redis::resp::Command;
use zs_proto_redis::{
    Auth, EXEC_ABORTED, READ_ONLY_REASON, READ_ONLY_REFUSED, RedisListener, UpstreamEndpoint,
};
use zs_protocol::SessionAccess;

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name}"))
}

fn endpoint(addr: &str) -> UpstreamEndpoint {
    let (host, port) = addr.rsplit_once(':').expect("address must be host:port");
    UpstreamEndpoint::new(host.to_string(), port.parse().unwrap()).unwrap()
}

async fn front(access: SessionAccess) -> (SocketAddr, fake::Refusals) {
    let password = required("ZS_TEST_REDIS_PASSWORD");
    let (audit, refusals) = fake::audit_recorder();
    let materialize: zs_protocol::Materialize =
        Arc::new(move || Ok(fake::granted_with(password.as_bytes(), access)));
    let listener = RedisListener::bind_endpoint(
        "127.0.0.1:0",
        endpoint(&required("ZS_TEST_REDIS_ADDR")),
        None,
        Auth::new(None),
        materialize,
    )
    .await
    .unwrap()
    .with_diag(DiagLog::disabled(), "redis-real-read-only")
    .with_caller_check(fake::admit_all())
    .with_refusal_audit(audit);
    let local = listener.local_addr();
    tokio::spawn(listener.serve());
    (local, refusals)
}

async fn session(access: SessionAccess) -> (Client, fake::Refusals) {
    let (local, refusals) = front(access).await;
    (Client::connect(local).await, refusals)
}

async fn setup() -> Client {
    let addr = required("ZS_TEST_REDIS_ADDR");
    let password = required("ZS_TEST_REDIS_PASSWORD");
    let mut client = Client::connect(addr.parse().expect("ZS_TEST_REDIS_ADDR is ip:port")).await;
    assert_eq!(
        client.command(&[b"AUTH", password.as_bytes()]).await,
        fake::OK
    );
    client
}

fn key(name: &str) -> String {
    format!(
        "zs-ro-test-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

async fn put(setup: &mut Client, key: &str, value: &str) {
    assert_eq!(
        setup
            .command(&[b"SET", key.as_bytes(), value.as_bytes(), b"EX", b"300"])
            .await,
        fake::OK
    );
}

async fn remove(setup: &mut Client, keys: &[&str]) {
    let mut command: Vec<&[u8]> = vec![b"DEL"];
    command.extend(keys.iter().map(|key| key.as_bytes()));
    assert_eq!(
        setup.command(&command).await,
        format!(":{}\r\n", keys.len()).into_bytes()
    );
}

fn bulk(value: &str) -> Vec<u8> {
    format!("${}\r\n{value}\r\n", value.len()).into_bytes()
}

fn noperm() -> Vec<u8> {
    READ_ONLY_REFUSED.frame()
}

fn words(command: &str) -> Vec<&[u8]> {
    command.split(' ').map(str::as_bytes).collect()
}

fn text(reply: &[u8]) -> String {
    String::from_utf8_lossy(reply).into_owned()
}

fn refusals(recorded: &fake::Refusals) -> Vec<(&'static str, &'static str)> {
    recorded.lock().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn get_works_and_set_gets_noperm() {
    let mut setup = setup().await;
    let key = key("set");
    put(&mut setup, &key, "before").await;

    let (mut client, recorded) = session(SessionAccess::ReadOnly).await;
    assert_eq!(
        client.command(&[b"GET", key.as_bytes()]).await,
        bulk("before"),
        "positive control: a read works"
    );
    assert_eq!(
        client
            .command(&[b"SET", key.as_bytes(), b"after", b"EX", b"300"])
            .await,
        noperm()
    );
    assert_eq!(
        client.command(&[b"GET", key.as_bytes()]).await,
        bulk("before"),
        "the session stays usable"
    );
    assert_eq!(
        setup.command(&[b"GET", key.as_bytes()]).await,
        bulk("before"),
        "the key keeps its old value"
    );
    assert_eq!(refusals(&recorded), vec![("query", READ_ONLY_REASON)]);

    let (mut writer, recorded) = session(SessionAccess::ReadWrite).await;
    assert_eq!(
        writer
            .command(&[b"SET", key.as_bytes(), b"after", b"EX", b"300"])
            .await,
        fake::OK,
        "negative control: the same SET succeeds read-write"
    );
    assert_eq!(
        setup.command(&[b"GET", key.as_bytes()]).await,
        bulk("after")
    );
    assert!(refusals(&recorded).is_empty());
    remove(&mut setup, &[&key]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn eval_and_eval_ro_are_refused() {
    let mut setup = setup().await;
    let key = key("eval");
    put(&mut setup, &key, "before").await;
    let read = b"return redis.call('GET', KEYS[1])";
    let write = b"return redis.call('SET', KEYS[1], 'after', 'EX', 300)";
    let slowlog = b"return redis.call('SLOWLOG', 'LEN')";
    let sha = b"e0e1f9fabfc9d4800c877a703b823ac0578ff8db";

    let (mut client, recorded) = session(SessionAccess::ReadOnly).await;
    assert_eq!(
        client.command(&[b"GET", key.as_bytes()]).await,
        bulk("before"),
        "positive control: a read works"
    );
    for refused in [
        &[&b"EVAL"[..], b"return 1", b"0"][..],
        &[&b"EVAL"[..], write, b"1", key.as_bytes()][..],
        &[&b"EVALSHA"[..], sha, b"0"][..],
        &[&b"FCALL"[..], b"zs_ro_none", b"0"][..],
        &[&b"EVAL_RO"[..], read, b"1", key.as_bytes()][..],
        &[&b"EVAL_RO"[..], slowlog, b"0"][..],
        &[&b"eval_ro"[..], write, b"1", key.as_bytes()][..],
        &[&b"EVALSHA_RO"[..], sha, b"0"][..],
        &[&b"FCALL_RO"[..], b"zs_ro_none", b"0"][..],
    ] {
        assert_eq!(
            client.command(refused).await,
            noperm(),
            "{}",
            text(refused[0])
        );
    }
    assert_eq!(
        setup.command(&[b"GET", key.as_bytes()]).await,
        bulk("before"),
        "the key keeps its old value"
    );
    assert_eq!(refusals(&recorded), vec![("query", READ_ONLY_REASON); 9]);

    let (mut writer, recorded) = session(SessionAccess::ReadWrite).await;
    assert_eq!(
        writer.command(&[b"EVAL_RO", slowlog, b"0"]).await.first(),
        Some(&b':'),
        "negative control: EVAL_RO reaches the server read-write"
    );
    assert_eq!(
        writer
            .command(&[b"EVAL", write, b"1", key.as_bytes()])
            .await,
        fake::OK,
        "negative control: EVAL writes read-write"
    );
    assert_eq!(
        setup.command(&[b"GET", key.as_bytes()]).await,
        bulk("after")
    );
    assert!(refusals(&recorded).is_empty());
    remove(&mut setup, &[&key]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn write_forms_of_admitted_reads_are_refused_by_the_server() {
    let mut setup = setup().await;
    let key = key("forms");
    let geo = key.replace("forms", "forms-geo");
    let stored = key.replace("forms", "forms-stored");
    put(&mut setup, &key, "before").await;
    assert_eq!(
        setup
            .command(&words(&format!("GEOADD {geo} 13.36 38.11 p")))
            .await,
        b":1\r\n".to_vec()
    );
    assert_eq!(
        setup.command(&words(&format!("EXPIRE {geo} 300"))).await,
        b":1\r\n".to_vec()
    );

    let (mut client, recorded) = session(SessionAccess::ReadOnly).await;
    assert_eq!(
        client
            .command(&words(&format!("GEORADIUS_RO {geo} 13.36 38.11 10 km")))
            .await,
        b"*1\r\n$1\r\np\r\n".to_vec(),
        "positive control: the read form works"
    );
    assert_eq!(
        client
            .command(&words(&format!("BITFIELD_RO {key} GET u8 0")))
            .await
            .first(),
        Some(&b'*'),
        "positive control: BITFIELD_RO GET works"
    );
    for (form, error) in [
        (
            format!("GEORADIUS_RO {geo} 13.36 38.11 10 km STORE {stored}"),
            "-ERR syntax error",
        ),
        (
            format!("GEORADIUS_RO {geo} 13.36 38.11 10 km STOREDIST {stored}"),
            "-ERR syntax error",
        ),
        (
            format!("GEORADIUSBYMEMBER_RO {geo} p 10 km STORE {stored}"),
            "-ERR syntax error",
        ),
        (
            format!("GEOSEARCH {geo} FROMMEMBER p BYRADIUS 10 km STORE {stored}"),
            "-ERR syntax error",
        ),
        (
            format!("BITFIELD_RO {key} SET u8 0 1"),
            "-ERR BITFIELD_RO only supports the GET subcommand",
        ),
    ] {
        let reply = client.command(&words(&form)).await;
        assert!(
            reply.starts_with(error.as_bytes()),
            "{form}: {}",
            text(&reply)
        );
    }
    assert!(
        refusals(&recorded).is_empty(),
        "the server, not the agent, refused"
    );
    assert_eq!(
        setup.command(&words(&format!("EXISTS {stored}"))).await,
        b":0\r\n".to_vec()
    );
    assert_eq!(
        setup.command(&[b"GET", key.as_bytes()]).await,
        bulk("before")
    );
    remove(&mut setup, &[&key, &geo]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn container_commands_check_the_subcommand() {
    let mut setup = setup().await;
    let key = key("container");
    put(&mut setup, &key, "before").await;

    let (mut client, recorded) = session(SessionAccess::ReadOnly).await;
    assert_eq!(
        client
            .command(&[b"CLIENT", b"SETNAME", b"zs-ro-test"])
            .await,
        fake::OK
    );
    assert_eq!(
        client.command(&[b"client", b"GetName"]).await,
        bulk("zs-ro-test")
    );
    assert_eq!(
        client.command(&[b"CLIENT", b"ID"]).await.first(),
        Some(&b':')
    );
    assert!(
        text(&client.command(&[b"CLIENT", b"INFO"]).await).contains("name=zs-ro-test"),
        "CLIENT INFO passes"
    );
    assert_eq!(
        client
            .command(&[b"OBJECT", b"ENCODING", key.as_bytes()])
            .await,
        bulk("embstr")
    );
    assert_eq!(
        client
            .command(&[b"MEMORY", b"USAGE", key.as_bytes()])
            .await
            .first(),
        Some(&b':')
    );
    for refused in [
        "CLIENT KILL ID 999999999".to_string(),
        "client kill ID 999999999".to_string(),
        "CLIENT LIST".to_string(),
        "CLIENT SETINFO LIB-NAME zs".to_string(),
        "CLIENT".to_string(),
        "CONFIG GET maxmemory".to_string(),
        "OBJECT HELP".to_string(),
        "OBJECT".to_string(),
        "MEMORY STATS".to_string(),
        format!("XGROUP CREATE {key} g $ MKSTREAM"),
    ] {
        assert_eq!(
            client.command(&words(&refused)).await,
            noperm(),
            "{refused}"
        );
    }
    assert_eq!(refusals(&recorded), vec![("query", READ_ONLY_REASON); 10]);

    let (mut writer, recorded) = session(SessionAccess::ReadWrite).await;
    assert_eq!(
        writer
            .command(&[b"CONFIG", b"GET", b"maxmemory"])
            .await
            .first(),
        Some(&b'*'),
        "negative control: CONFIG GET reaches the server read-write"
    );
    assert_eq!(
        writer
            .command(&[b"CLIENT", b"KILL", b"ID", b"999999999"])
            .await,
        b":0\r\n".to_vec(),
        "negative control: CLIENT KILL reaches the server read-write"
    );
    assert!(refusals(&recorded).is_empty());
    remove(&mut setup, &[&key]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn refused_command_in_multi_aborts_exec() {
    let mut setup = setup().await;
    let key = key("multi");
    let other = key.replace("multi", "multi-other");
    put(&mut setup, &key, "before").await;
    put(&mut setup, &other, "other").await;

    let (mut client, recorded) = session(SessionAccess::ReadOnly).await;
    let pipeline: Vec<u8> = [
        "MULTI".to_string(),
        format!("GET {key}"),
        format!("SET {key} after"),
        "EXEC".to_string(),
    ]
    .iter()
    .flat_map(|command| {
        Command::new(words(command).iter().map(|part| part.to_vec()).collect())
            .encode()
            .to_vec()
    })
    .collect();
    client.send(&pipeline).await.unwrap();
    assert_eq!(client.read_reply().await, fake::OK);
    assert_eq!(client.read_reply().await, b"+QUEUED\r\n".to_vec());
    assert_eq!(client.read_reply().await, noperm());
    assert_eq!(client.read_reply().await, EXEC_ABORTED.frame());
    assert_eq!(
        setup.command(&[b"GET", key.as_bytes()]).await,
        bulk("before"),
        "nothing in the transaction ran"
    );
    assert_eq!(
        client.command(&[b"EXEC"]).await,
        b"-ERR EXEC without MULTI\r\n".to_vec(),
        "the server's transaction ended with the abort"
    );

    assert_eq!(client.command(&[b"MULTI"]).await, fake::OK);
    assert_eq!(
        client.command(&[b"GET", key.as_bytes()]).await,
        b"+QUEUED\r\n".to_vec()
    );
    assert_eq!(
        client.command(&[b"GET", other.as_bytes()]).await,
        b"+QUEUED\r\n".to_vec()
    );
    let mut both = b"*2\r\n".to_vec();
    both.extend_from_slice(&bulk("before"));
    both.extend_from_slice(&bulk("other"));
    assert_eq!(
        client.command(&[b"EXEC"]).await,
        both,
        "a clean transaction runs"
    );
    assert_eq!(refusals(&recorded), vec![("query", READ_ONLY_REASON)]);
    remove(&mut setup, &[&key, &other]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a password-protected Redis: set ZS_TEST_REDIS_ADDR and ZS_TEST_REDIS_PASSWORD"]
async fn module_and_unknown_commands_are_refused() {
    let mut setup = setup().await;
    let key = key("module");
    put(&mut setup, &key, "before").await;

    let (mut client, recorded) = session(SessionAccess::ReadOnly).await;
    for refused in [
        format!("JSON.SET {key} $ {{}}"),
        format!("JSON.GET {key}"),
        "FT.SEARCH zs-ro-index *".to_string(),
        format!("BF.ADD {key} x"),
        format!("ZSMADEUPCOMMAND {key}"),
    ] {
        assert_eq!(
            client.command(&words(&refused)).await,
            noperm(),
            "{refused}"
        );
    }
    assert_eq!(
        client.command(&[b"GET", key.as_bytes()]).await,
        bulk("before"),
        "the session stays usable"
    );
    assert_eq!(refusals(&recorded), vec![("query", READ_ONLY_REASON); 5]);

    let (mut writer, _) = session(SessionAccess::ReadWrite).await;
    let unknown = writer.command(&[b"ZSMADEUPCOMMAND", key.as_bytes()]).await;
    assert!(
        unknown.starts_with(b"-ERR unknown command"),
        "negative control: the server, not the agent, answers read-write: {}",
        text(&unknown)
    );
    assert_eq!(
        setup.command(&[b"GET", key.as_bytes()]).await,
        bulk("before")
    );
    remove(&mut setup, &[&key]).await;
}
