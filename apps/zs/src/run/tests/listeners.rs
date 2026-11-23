use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zs_protocol::ListenSpec;

use super::access_change::redis::fake;
use super::*;

#[cfg(unix)]
#[path = "../../../tests/host_network/mod.rs"]
mod host_network;

const PING: &[u8] = b"*1\r\n$4\r\nPING\r\n";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn grant(
    key: &zs_grant::ControlSigningKey,
    upstream_port: u16,
    listen: Option<(&str, &[&str])>,
) -> zs_grant::SignedGrant {
    grant_until(key, upstream_port, listen, now_ms() + 600_000)
}

fn grant_until(
    key: &zs_grant::ControlSigningKey,
    upstream_port: u16,
    listen: Option<(&str, &[&str])>,
    expires_at_ms: u64,
) -> zs_grant::SignedGrant {
    key.sign(zs_grant::Grant {
        subject: "alice".into(),
        workload: "default".into(),
        resource: fake::RESOURCE.into(),
        host: format!("{}.internal", fake::RESOURCE),
        protocol: "redis".into(),
        source: zs_policy::CredentialSource::file(fake::RESOURCE),
        operations: vec!["connect".into()],
        environment: "development".into(),
        expires_at_ms,
        grant_id: "g-1".into(),
        materialization: zs_policy::Materialization::Retrieve,
        upstream_host: "127.0.0.1".into(),
        upstream_port,
        upstream_tls: zs_policy::UpstreamTlsMode::Plaintext,
        local_endpoint: false,
        listen_addr: listen.map(|(addr, _)| addr.to_string()),
        listen_allow: listen.map_or_else(Vec::new, |(_, allow)| {
            allow.iter().map(|entry| entry.to_string()).collect()
        }),
        access: zs_policy::Access::ReadWrite,
        version: if listen.is_some() {
            zs_grant::GRANT_VERSION_LISTEN
        } else {
            zs_grant::GRANT_VERSION
        },
    })
    .unwrap()
}

fn upstream() -> (tokio::runtime::Runtime, fake::Fake) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let upstream = runtime.block_on(fake::start(fake::Script::accepting(
        fake::USER,
        fake::PASSWORD,
    )));
    (runtime, upstream)
}

struct Run {
    home: tempfile::TempDir,
    prepared: PreparedRun,
}

impl Run {
    fn new(
        runtime: tokio::runtime::Runtime,
        upstream_port: u16,
        fields: serde_json::Value,
        grants: Vec<zs_grant::SignedGrant>,
        trusted: &zs_grant::ControlSigningKey,
    ) -> Self {
        let home = tempfile::tempdir().unwrap();
        let credentials = home.path().join(".zs-credentials");
        std::fs::create_dir_all(&credentials).unwrap();
        std::fs::write(
            credentials.join(fake::RESOURCE),
            format!("{}\n", fake::PASSWORD),
        )
        .unwrap();
        let mut binding = json!({
            "resource": fake::RESOURCE,
            "host": format!("{}.internal", fake::RESOURCE),
            "protocol": "redis",
            "upstream_host": "127.0.0.1",
            "upstream_port": upstream_port,
            "user": fake::USER,
            "upstream_plaintext": true,
        });
        for (name, value) in fields.as_object().unwrap() {
            binding[name] = value.clone();
        }
        let policy = home.path().join("zs-policy.json");
        std::fs::write(
            &policy,
            json!({"bindings": [binding], "signing_keys": [], "grants": []}).to_string(),
        )
        .unwrap();
        let file = AgentFile::load(&policy).unwrap();
        let cache = GrantCache::new();
        for signed in grants {
            cache.insert(signed);
        }
        let agent = std::sync::Arc::new(AgentHandler::from_grants(
            Subject::new("alice").unwrap(),
            WorkloadLabel::new("default").unwrap(),
            file.bindings.clone(),
            cache,
            zs_grant::AgentVerifier::new(vec![(
                trusted.key_id().to_string(),
                ed25519_dalek::VerifyingKey::from_bytes(&trusted.verifying_key_bytes()).unwrap(),
            )]),
            std::sync::Arc::new(zs_materializer::Materializer::new(
                zs_materializer::StoreRegistry::new(std::sync::Arc::new(
                    zs_materializer::FileStore::new(&credentials),
                )),
                std::sync::Arc::new(UnconfiguredExchange),
            )),
        ));
        let prepared = PreparedRun {
            file,
            journal: std::sync::Arc::new(Journal::open(home.path().join("audit.jsonl")).unwrap()),
            shipped: std::sync::Arc::new(tokio::sync::Mutex::new(0)),
            ca: std::sync::Arc::new(LocalCa::load_or_create(home.path().join(".zs-ca")).unwrap()),
            wire: None,
            revocation_cursor: None,
            revocation_hold: false,
            revocation_started: std::time::Instant::now(),
            stored: false,
            agent,
            audit_subject: "alice".into(),
            audit_workload: "default".into(),
            runtime,
            diag: DiagLog::open_with_cap(&home.path().join("diag.jsonl"), "t-1", 1 << 20).unwrap(),
        };
        Self { home, prepared }
    }

    fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        self.prepared.runtime.block_on(future)
    }

    fn start(&self) -> Result<RunningServices, i32> {
        self.block_on(start_services(
            &self.prepared,
            &args_listening(self.home.path(), "127.0.0.1:0"),
        ))
    }

    fn started(&self) -> RunningServices {
        self.start()
            .unwrap_or_else(|code| panic!("start_services failed with {code}"))
    }

    #[cfg(unix)]
    fn front_line(&self) -> Option<String> {
        let audit = L3Audit::new(
            &self.prepared,
            fake::RESOURCE,
            "redis",
            self.prepared.agent.clone(),
        );
        listener_front(&self.prepared, &self.prepared.file.bindings[0], audit).err()
    }

    #[cfg(unix)]
    fn prefix(&self) -> String {
        self.prepared.file.bindings[0].env_prefix()
    }

    fn records(&self) -> Vec<serde_json::Value> {
        journal_records(self.home.path())
    }

    fn events(&self, name: &str) -> Vec<serde_json::Value> {
        self.prepared.diag.close();
        std::fs::read_to_string(self.home.path().join("diag.jsonl"))
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["event"] == name)
            .collect()
    }

    fn bound(&self) -> serde_json::Value {
        let bound: Vec<_> = self
            .events("listener_bound")
            .into_iter()
            .filter(|event| event["fields"]["kind"] == "redis")
            .collect();
        assert_eq!(bound.len(), 1, "{bound:?}");
        bound[0].clone()
    }
}

async fn ping<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> Vec<u8> {
    let _ = stream.write_all(PING).await;
    let mut reply = Vec::new();
    let mut buffer = [0u8; 64];
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while !reply.ends_with(b"\r\n") {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => reply.extend_from_slice(&buffer[..read]),
            }
        }
    })
    .await;
    reply
}

#[cfg(unix)]
fn free_port(ip: IpAddr) -> u16 {
    std::net::TcpListener::bind((ip, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn env_of(services: &RunningServices) -> Vec<(String, String)> {
    l3_env(services)
        .into_iter()
        .map(|(name, value)| (name, value.into_string().unwrap()))
        .collect()
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[test]
fn a_loopback_binding_listens_announces_and_sets_its_variables_as_before() {
    let (runtime, upstream) = upstream();
    let key = zs_grant::ControlSigningKey::generate("k1");
    let port = upstream.addr.port();
    let run = Run::new(
        runtime,
        port,
        json!({}),
        vec![grant(&key, port, None)],
        &key,
    );
    let services = run.started();
    let [(prefix, ListenSpec::Tcp(addr))] = services.l3.as_slice() else {
        panic!("one TCP listener: {:?}", services.l3);
    };
    assert_eq!(addr.ip(), IpAddr::from([127, 0, 0, 1]));

    let stream = run.block_on(tokio::net::TcpStream::connect(addr)).unwrap();
    assert_eq!(run.block_on(ping(stream)), fake::OK);
    assert!(
        upstream.authenticated(),
        "the upstream saw the brokered credential"
    );
    let records = run.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["decision"], "allow");
    assert!(records[0].get("source_addr").is_none(), "{records:?}");
    let (host, port) = (format!("{prefix}_HOST"), format!("{prefix}_PORT"));
    assert_eq!(
        env_of(&services),
        pairs(&[
            (host.as_str(), "127.0.0.1"),
            (port.as_str(), addr.port().to_string().as_str()),
        ])
    );
    let bound = run.bound();
    assert_eq!(bound["fields"]["listen"], "loopback", "{bound}");
    assert_eq!(bound["fields"]["addr"], addr.to_string(), "{bound}");
    let proxy: Vec<_> = run
        .events("listener_bound")
        .into_iter()
        .filter(|event| event["fields"]["kind"] == "proxy")
        .collect();
    assert_eq!(proxy.len(), 1, "{proxy:?}");
    assert_eq!(proxy[0]["fields"]["listen"], "loopback", "{proxy:?}");
}

#[cfg(unix)]
#[test]
fn a_unix_binding_serves_a_private_socket_and_removes_it_when_the_services_drop() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    let (runtime, upstream) = upstream();
    let key = zs_grant::ControlSigningKey::generate("k1");
    let port = upstream.addr.port();
    let sockets = tempfile::tempdir().unwrap();
    let dir = sockets.path().join("run");
    let run = Run::new(
        runtime,
        port,
        json!({ "listen_socket_dir": dir }),
        vec![grant(&key, port, None)],
        &key,
    );
    let services = run.started();
    let path = dir.join(format!("{}.sock", fake::RESOURCE));
    assert_eq!(
        services.l3,
        vec![(run.prefix(), ListenSpec::Unix(path.clone()))]
    );
    let socket = std::fs::symlink_metadata(&path).unwrap();
    assert!(socket.file_type().is_socket());
    assert_eq!(socket.permissions().mode() & 0o777, 0o600);
    let parent = std::fs::symlink_metadata(&dir).unwrap();
    assert_eq!(parent.permissions().mode() & 0o777, 0o700);

    let stream = run
        .block_on(tokio::net::UnixStream::connect(&path))
        .unwrap();
    assert_eq!(
        run.block_on(ping(stream)),
        fake::OK,
        "positive control: the client is served over the socket"
    );
    assert!(
        upstream.authenticated(),
        "the upstream saw the brokered credential"
    );
    let records = run.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["operation"], "connect");
    assert_eq!(records[0]["decision"], "allow");
    assert!(records[0].get("source_addr").is_none(), "{records:?}");
    let socket_name = format!("{}_SOCKET", run.prefix());
    assert_eq!(
        env_of(&services),
        pairs(&[(socket_name.as_str(), path.to_str().unwrap())])
    );
    let bound = run.bound();
    assert_eq!(bound["fields"]["listen"], "unix", "{bound}");
    assert_eq!(bound["fields"]["addr"], path.to_str().unwrap(), "{bound}");

    drop(services);
    assert!(
        std::fs::symlink_metadata(&path).is_err(),
        "the socket outlived the services"
    );
    assert!(dir.is_dir(), "the socket directory is kept");
}

#[cfg(unix)]
#[test]
fn a_group_writable_socket_directory_refuses_the_run() {
    use std::os::unix::fs::PermissionsExt;

    let (runtime, upstream) = upstream();
    let key = zs_grant::ControlSigningKey::generate("k1");
    let port = upstream.addr.port();
    let shared = tempfile::tempdir().unwrap();
    std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
    let run = Run::new(
        runtime,
        port,
        json!({ "listen_socket_dir": shared.path() }),
        vec![grant(&key, port, None)],
        &key,
    );
    let line = run
        .front_line()
        .expect("a group-writable directory is refused");
    assert_eq!(
        line,
        format!(
            "zs: {}: {}: socket directory is group- or world-writable",
            fake::RESOURCE,
            shared.path().display()
        )
    );
    assert!(!line.contains('\n'));
    assert!(matches!(run.start(), Err(1)));
    let stages = run.events("run_refused");
    assert_eq!(stages.len(), 1, "{stages:?}");
    assert_eq!(stages[0]["fields"]["stage"], "listen");
    let path = shared.path().join(format!("{}.sock", fake::RESOURCE));
    assert!(std::fs::symlink_metadata(&path).is_err());

    std::fs::set_permissions(shared.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let services = run.start().unwrap_or_else(|code| {
        panic!("negative control: a private directory must serve, got {code}")
    });
    assert!(std::fs::symlink_metadata(&path).is_ok());
    drop(services);
}

#[cfg(unix)]
fn network_run(ip: IpAddr, allow: &str) -> (fake::Fake, Run, SocketAddr) {
    let (runtime, upstream) = upstream();
    let key = zs_grant::ControlSigningKey::generate("k1");
    let port = upstream.addr.port();
    let addr = SocketAddr::new(ip, free_port(ip));
    let listen = addr.to_string();
    let run = Run::new(
        runtime,
        port,
        json!({ "listen_addr": listen, "listen_allow": [allow] }),
        vec![grant(
            &key,
            port,
            Some((listen.as_str(), std::slice::from_ref(&allow))),
        )],
        &key,
    );
    (upstream, run, addr)
}

#[cfg(unix)]
#[test]
fn a_network_listener_admits_only_a_source_in_its_signed_allow_list() {
    let Some(ip) = host_network::route_b_host() else {
        return;
    };

    let (upstream, run, addr) = network_run(ip, &format!("{ip}/32"));
    let services = run.started();
    assert_eq!(services.l3, vec![(run.prefix(), ListenSpec::Tcp(addr))]);
    let stream = run.block_on(tokio::net::TcpStream::connect(addr)).unwrap();
    assert_eq!(stream.local_addr().unwrap().ip(), ip);
    assert_eq!(
        run.block_on(ping(stream)),
        fake::OK,
        "positive control: a source inside the list is served"
    );
    assert!(
        upstream.authenticated(),
        "the upstream saw the brokered credential"
    );
    let records = run.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["operation"], "connect");
    assert_eq!(records[0]["decision"], "allow");
    assert_eq!(records[0]["source_addr"], ip.to_string());
    let (host, port) = (
        format!("{}_HOST", run.prefix()),
        format!("{}_PORT", run.prefix()),
    );
    assert_eq!(
        env_of(&services),
        pairs(&[
            (host.as_str(), ip.to_string().as_str()),
            (port.as_str(), addr.port().to_string().as_str()),
        ])
    );
    let bound = run.bound();
    assert_eq!(bound["fields"]["listen"], "network", "{bound}");
    assert_eq!(bound["fields"]["addr"], addr.to_string(), "{bound}");
    drop(services);

    let (upstream, run, addr) = network_run(ip, host_network::OTHER_NETWORK);
    let services = run.started();
    let stream = run.block_on(tokio::net::TcpStream::connect(addr)).unwrap();
    assert_eq!(stream.local_addr().unwrap().ip(), ip);
    assert!(
        run.block_on(ping(stream)).is_empty(),
        "a source outside the list gets no byte"
    );
    let records = run.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["operation"], "connect");
    assert_eq!(records[0]["decision"], "deny");
    assert_eq!(records[0]["reason"], "caller_refused");
    assert_eq!(records[0]["protocol"], "redis");
    assert_eq!(records[0]["source_addr"], ip.to_string());
    assert!(zs_audit::verify_chain(run.home.path().join("audit.jsonl")).is_ok());
    assert_eq!(upstream.seen(|seen| seen.accepts), 0);
    assert!(!upstream.authenticated());
    let refused = run.events("caller_refused");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0]["fields"]["listen"], "network");
    assert_eq!(refused[0]["fields"]["listener"], "redis");
    drop(services);
}

#[cfg(unix)]
#[test]
fn a_non_loopback_listen_addr_without_a_signed_grant_that_carries_it_refuses_the_run() {
    let addr = SocketAddr::from(([192, 0, 2, 10], 16_379));
    let listen = addr.to_string();
    let allow: &[&str] = &["10.0.0.0/8"];
    let fields = json!({ "listen_addr": listen, "listen_allow": allow });
    let key = zs_grant::ControlSigningKey::generate("k1");
    let stranger = zs_grant::ControlSigningKey::generate("k1");
    let refused = |reason: &str| {
        format!(
            "zs: {}: listen_addr {addr} needs a valid signed grant with the same listen_addr and listen_allow ({reason})",
            fake::RESOURCE
        )
    };

    let (runtime, upstream) = upstream();
    let port = upstream.addr.port();
    let signed = Run::new(
        runtime,
        port,
        fields.clone(),
        vec![grant(&key, port, Some((listen.as_str(), allow)))],
        &key,
    );
    assert_eq!(
        signed.front_line(),
        None,
        "positive control: the signed grant carries the listener"
    );

    let other_allow: &[&str] = &["10.1.0.0/16"];
    let no_grant = format!("no grant for {}", fake::RESOURCE);
    let other_addr = format!("{}: listen_addr differs from the grant", fake::RESOURCE);
    let other_list = format!("{}: listen_allow differs from the grant", fake::RESOURCE);
    for (case, grants, revoked, reason) in [
        ("no grant", Vec::new(), false, no_grant.as_str()),
        (
            "a grant without listener fields",
            vec![grant(&key, port, None)],
            false,
            other_addr.as_str(),
        ),
        (
            "a grant with another allow-list",
            vec![grant(&key, port, Some((listen.as_str(), other_allow)))],
            false,
            other_list.as_str(),
        ),
        (
            "a grant signed by a key this run does not trust",
            vec![grant(&stranger, port, Some((listen.as_str(), allow)))],
            false,
            "grant signature invalid",
        ),
        (
            "an expired grant",
            vec![grant_until(
                &key,
                port,
                Some((listen.as_str(), allow)),
                now_ms() - 1_000,
            )],
            false,
            "grant expired",
        ),
        (
            "a revoked grant",
            vec![grant(&key, port, Some((listen.as_str(), allow)))],
            true,
            "grant g-1 is revoked",
        ),
    ] {
        let run = Run::new(
            tokio::runtime::Runtime::new().unwrap(),
            port,
            fields.clone(),
            grants,
            &key,
        );
        if revoked {
            run.prepared.agent.apply_revocations(&["g-1".to_string()]);
        }
        let line = run.front_line();
        assert_eq!(line.as_deref(), Some(refused(reason).as_str()), "{case}");
        let line = line.unwrap();
        assert!(!line.contains('\n'), "{case}");
        assert!(!line.contains(fake::PASSWORD), "{case}");
        assert!(matches!(run.start(), Err(1)), "{case}");
        let stages = run.events("run_refused");
        assert_eq!(stages.len(), 1, "{case}: {stages:?}");
        assert_eq!(stages[0]["fields"]["stage"], "listen", "{case}");
    }
}

fn services_with(
    postgres: Option<ListenSpec>,
    mysql: Option<ListenSpec>,
    l3: &[(&str, ListenSpec)],
) -> RunningServices {
    RunningServices {
        proxy_addr: SocketAddr::from(([127, 0, 0, 1], 1)),
        token: std::sync::Arc::new(RunToken::generate()),
        http_proxy: false,
        postgres,
        mysql,
        l3: l3
            .iter()
            .map(|(prefix, local)| (prefix.to_string(), local.clone()))
            .collect(),
        endpoints: Vec::new(),
        _tasks: BackgroundTasks::new(),
        _sockets: Vec::new(),
    }
}

#[test]
fn a_unix_binding_gives_the_child_its_socket_and_no_host_or_port() {
    let pg = ListenSpec::Unix("/run/zs/pg/.s.PGSQL.5432".into());
    let mysql = ListenSpec::Unix("/run/zs/db/orders-mysql.sock".into());
    let redis = ListenSpec::Unix("/run/zs/db/orders-redis.sock".into());
    let services = services_with(
        Some(pg.clone()),
        Some(mysql.clone()),
        &[
            ("ZS_ORDERS_DB", pg),
            ("ZS_ORDERS_MYSQL", mysql),
            ("ZS_ORDERS_REDIS", redis),
        ],
    );
    assert_eq!(
        env_of(&services),
        pairs(&[
            ("PGHOST", "/run/zs/pg"),
            ("PGPORT", "5432"),
            ("MYSQL_UNIX_PORT", "/run/zs/db/orders-mysql.sock"),
            ("ZS_ORDERS_DB_SOCKET", "/run/zs/pg/.s.PGSQL.5432"),
            ("ZS_ORDERS_MYSQL_SOCKET", "/run/zs/db/orders-mysql.sock"),
            ("ZS_ORDERS_REDIS_SOCKET", "/run/zs/db/orders-redis.sock"),
        ])
    );
}

fn child_env(services: &RunningServices) -> std::collections::BTreeMap<String, Option<String>> {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".zs-ca")).unwrap();
    let command = build_child(
        &args_listening(home.path(), "127.0.0.1:0"),
        services,
        &home.path().join(".zs-ca").join("ca.crt"),
    );
    command
        .get_envs()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.map(|value| value.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

#[test]
fn a_unix_binding_removes_an_inherited_host_and_port_from_the_child() {
    let pg = ListenSpec::Unix("/run/zs/pg/.s.PGSQL.5432".into());
    let mysql = ListenSpec::Unix("/run/zs/db/orders-mysql.sock".into());
    let redis = ListenSpec::Unix("/run/zs/db/orders-redis.sock".into());
    let unix = child_env(&services_with(
        Some(pg.clone()),
        Some(mysql.clone()),
        &[
            ("ZS_ORDERS_DB", pg),
            ("ZS_ORDERS_MYSQL", mysql),
            ("ZS_ORDERS_REDIS", redis),
        ],
    ));
    for name in [
        "MYSQL_HOST",
        "MYSQL_TCP_PORT",
        "ZS_ORDERS_DB_HOST",
        "ZS_ORDERS_DB_PORT",
        "ZS_ORDERS_MYSQL_HOST",
        "ZS_ORDERS_MYSQL_PORT",
        "ZS_ORDERS_REDIS_HOST",
        "ZS_ORDERS_REDIS_PORT",
    ] {
        assert_eq!(unix.get(name), Some(&None), "{name} is not removed");
    }
    for (name, value) in [
        ("PGHOST", "/run/zs/pg"),
        ("PGPORT", "5432"),
        ("MYSQL_UNIX_PORT", "/run/zs/db/orders-mysql.sock"),
        ("ZS_ORDERS_REDIS_SOCKET", "/run/zs/db/orders-redis.sock"),
    ] {
        assert_eq!(unix.get(name), Some(&Some(value.to_string())), "{name}");
    }

    let mysql = ListenSpec::Tcp(SocketAddr::from(([127, 0, 0, 1], 33_060)));
    let redis = ListenSpec::Tcp(SocketAddr::from(([127, 0, 0, 1], 6_380)));
    let tcp = child_env(&services_with(
        None,
        Some(mysql.clone()),
        &[("ZS_ORDERS_MYSQL", mysql), ("ZS_ORDERS_REDIS", redis)],
    ));
    assert_eq!(
        tcp.get("ZS_ORDERS_REDIS_HOST"),
        Some(&Some("127.0.0.1".to_string()))
    );
    assert_eq!(tcp.get("MYSQL_TCP_PORT"), Some(&Some("33060".to_string())));
    let removed: Vec<_> = tcp.iter().filter(|(_, value)| value.is_none()).collect();
    assert!(
        removed.is_empty(),
        "a TCP binding removes no variable: {removed:?}"
    );
}

#[test]
fn a_tcp_binding_gives_the_child_its_host_and_port_as_before() {
    let pg = ListenSpec::Tcp(SocketAddr::from(([127, 0, 0, 1], 54_320)));
    let mysql = ListenSpec::Tcp(SocketAddr::from(([127, 0, 0, 1], 33_060)));
    let redis = ListenSpec::Tcp(SocketAddr::from(([172, 17, 0, 1], 6_380)));
    let services = services_with(
        Some(pg.clone()),
        Some(mysql.clone()),
        &[
            ("ZS_ORDERS_DB", pg),
            ("ZS_ORDERS_MYSQL", mysql),
            ("ZS_ORDERS_REDIS", redis),
        ],
    );
    assert_eq!(
        env_of(&services),
        pairs(&[
            ("PGHOST", "127.0.0.1"),
            ("PGPORT", "54320"),
            ("MYSQL_HOST", "127.0.0.1"),
            ("MYSQL_TCP_PORT", "33060"),
            ("ZS_ORDERS_DB_HOST", "127.0.0.1"),
            ("ZS_ORDERS_DB_PORT", "54320"),
            ("ZS_ORDERS_MYSQL_HOST", "127.0.0.1"),
            ("ZS_ORDERS_MYSQL_PORT", "33060"),
            ("ZS_ORDERS_REDIS_HOST", "172.17.0.1"),
            ("ZS_ORDERS_REDIS_PORT", "6380"),
        ])
    );
}
