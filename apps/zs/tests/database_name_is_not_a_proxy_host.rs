#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use zs::{AgentHandler, GrantCache, HttpAuth, ResourceBinding};
use zs_grant::{ControlSigningKey, Grant};
use zs_mitm::{Flow, FlowHandler, PathScope};
use zs_protocol::Destination;

const SUBJECT: &str = "alice@company.com";
const WORKLOAD: &str = "claude-code";

const HOST: &str = "data.example.test";
const API: &str = "data-api";
const API_PATH: &str = "/v2/pipeline";
const API_REF: &str = "data-api-token";
const TOKEN: &[u8] = b"zs-review-rest-token-0123456789";

const CACHE: &str = "cache";
const REDIS_PORT: u16 = 6379;

const PG: &str = "orders-pg";
const PG_HOST: &str = "pg.orders.test";
const PG_PORT: u16 = 5432;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn binding(resource: &str, host: &str, protocol: &str, paths: Option<&[&str]>) -> ResourceBinding {
    ResourceBinding {
        resource: resource.to_string(),
        host: host.to_string(),
        protocol: protocol.to_string(),
        upstream_host: None,
        upstream_port: None,
        upstream_plaintext: false,
        upstream_auth_optional: false,
        listen_port: None,
        local_endpoint: false,
        operations: Vec::new(),
        paths: paths.map(|paths| paths.iter().map(|path| path.to_string()).collect()),
        upstream_ca: None,
        upstream_cert_sha256: None,
        client_auth_plugin: None,
        user: None,
        auth_source: None,
        auth: HttpAuth::Bearer,
        source: None,
        loaded_ca: None,
    }
}

fn grant(resource: &str, host: &str, protocol: &str, operation: &str, reference: &str) -> Grant {
    let connection = zs_policy::Connection::default()
        .resolve(host, protocol)
        .unwrap();
    grant_with(resource, host, protocol, operation, reference, connection)
}

fn grant_with(
    resource: &str,
    host: &str,
    protocol: &str,
    operation: &str,
    reference: &str,
    connection: zs_policy::ResolvedConnection,
) -> Grant {
    Grant {
        subject: SUBJECT.into(),
        workload: WORKLOAD.into(),
        resource: resource.into(),
        host: host.into(),
        protocol: protocol.into(),
        source: zs_policy::CredentialSource::file(reference),
        operations: vec![operation.into()],
        environment: "development".into(),
        expires_at_ms: now_ms() + 300_000,
        grant_id: format!("g-{resource}"),
        materialization: zs_policy::Materialization::Retrieve,
        upstream_host: connection.upstream_host,
        upstream_port: connection.upstream_port,
        upstream_tls: connection.upstream_tls,
        local_endpoint: connection.local_endpoint,
        access: zs_policy::Access::ReadWrite,
        version: zs_grant::GRANT_VERSION,
    }
}

fn materializer(credentials: &Path) -> Arc<zs_materializer::Materializer> {
    struct NoExchange;
    #[async_trait::async_trait]
    impl zs_materializer::ExchangeProvider for NoExchange {
        async fn exchange(
            &self,
            _grant: &zs_grant::Grant,
        ) -> Result<zs_credential::Credential, zs_materializer::MaterializationError> {
            Err(zs_materializer::MaterializationError::Exchange(
                "not configured".into(),
            ))
        }
    }
    Arc::new(zs_materializer::Materializer::new(
        zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(credentials))),
        Arc::new(NoExchange),
    ))
}

fn agent(bindings: Vec<ResourceBinding>, grants: Vec<Grant>, credentials: &Path) -> AgentHandler {
    let key = ControlSigningKey::generate("control-k1");
    let verifier = zs_grant::AgentVerifier::new(vec![(
        key.key_id().to_string(),
        ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
    )]);
    let cache = GrantCache::new();
    for grant in grants {
        cache.insert(key.sign(grant).unwrap());
    }
    AgentHandler::from_grants(
        zs_identity::Subject::new(SUBJECT).unwrap(),
        zs_identity::WorkloadLabel::new(WORKLOAD).unwrap(),
        bindings,
        cache,
        verifier,
        materializer(credentials),
    )
}

fn at(host: &str, port: u16) -> Destination {
    Destination::new(host.to_string(), port)
}

#[test]
fn a_database_resource_name_is_not_a_proxy_host() {
    let credentials = tempfile::tempdir().unwrap();
    let handler = agent(
        vec![
            binding(API, HOST, "https", None),
            binding(PG, PG_HOST, "postgres", None),
        ],
        vec![
            grant(API, HOST, "https", "GET", API_REF),
            grant(PG, PG_HOST, "postgres", "connect", "orders-pg-password"),
        ],
        credentials.path(),
    );

    let bound = handler.classify(&at(HOST, 443));
    assert!(
        matches!(bound, Flow::Intercept { .. }),
        "positive control: the https binding's host is intercepted, got {bound:?}"
    );
    let unbound = handler.classify(&at("unbound.example.test", PG_PORT));
    assert!(
        matches!(unbound, Flow::Passthrough),
        "negative control: a host with no binding is passthrough, got {unbound:?}"
    );

    let flow = handler.classify(&at(PG, PG_PORT));
    assert!(
        matches!(flow, Flow::Passthrough),
        "`CONNECT {PG}:{PG_PORT}` names no http or https binding, so it is an unknown \
         destination (SECURITY.md §7 row 916); the proxy got {flow:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_https_credential_is_not_released_for_a_database_port() {
    let credentials = tempfile::tempdir().unwrap();
    std::fs::write(credentials.path().join(API_REF), TOKEN).unwrap();
    let handler = agent(
        vec![
            binding(API, HOST, "https", Some(&[API_PATH])),
            binding(CACHE, HOST, "redis", None),
        ],
        vec![
            grant(API, HOST, "https", "GET", API_REF),
            grant(CACHE, HOST, "redis", "connect", "cache-password"),
        ],
        credentials.path(),
    );

    let Flow::Intercept {
        resource,
        upstream_port,
        scope,
        ..
    } = handler.classify(&at(HOST, 443))
    else {
        panic!("positive control: the https binding's host is intercepted");
    };
    assert_eq!(upstream_port, 443);
    assert_eq!(scope, PathScope::Paths(vec![API_PATH.to_string()]));
    let credential = handler
        .materialize(&resource, "GET")
        .unwrap_or_else(|denied| panic!("positive control: {}", denied.reason));
    assert_eq!(
        credential.expose(),
        TOKEN,
        "positive control: the https binding releases its credential for its own port"
    );
    drop(credential);

    let wrong_port = handler.classify(&at(HOST, REDIS_PORT));
    assert!(
        matches!(wrong_port, Flow::Deny { .. }),
        "negative control: the https host on the Redis port is denied (SECURITY.md §7 row \
         981), got {wrong_port:?}"
    );

    let flow = handler.classify(&at(CACHE, REDIS_PORT));
    let shown = format!("{flow:?}");
    let released = match flow {
        Flow::Intercept { resource, .. } => {
            handler.protocol_for(&resource).is_some()
                && handler
                    .materialize(&resource, "GET")
                    .is_ok_and(|credential| credential.expose() == TOKEN)
        }
        Flow::Passthrough | Flow::Deny { .. } => false,
    };
    assert!(
        !released,
        "`CONNECT {CACHE}:{REDIS_PORT}` made the proxy release the https binding's credential \
         for a flow that is not the https binding's port and path scope: {shown}"
    );
}

const OUTSIDE: &str = "/outside/the/path/scope";

type Seen = Arc<Mutex<Vec<String>>>;

async fn recording_listener() -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let record = record.clone();
            tokio::spawn(async move {
                let head = read_head(&mut stream).await;
                record.lock().unwrap().push(head);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (port, seen)
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    let read = async {
        while stream.read(&mut byte).await.unwrap_or(0) == 1 {
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), read).await;
    String::from_utf8_lossy(&head).into_owned()
}

fn saw_token(seen: &Seen) -> bool {
    let token = String::from_utf8_lossy(TOKEN).into_owned();
    seen.lock()
        .unwrap()
        .iter()
        .any(|head| head.contains(&token))
}

async fn tunnel(
    proxy: std::net::SocketAddr,
    ca: &zs_mitm::LocalCa,
    token: &zs_mitm::RunToken,
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    use rustls::pki_types::pem::PemObject;
    let mut tcp = TcpStream::connect(proxy).await.unwrap();
    let connect = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: {}\r\n\r\n",
        token.proxy_authorization().as_str()
    );
    tcp.write_all(connect.as_bytes()).await.unwrap();
    let established = read_head(&mut tcp).await;
    if !established.starts_with("HTTP/1.1 200") {
        return Err(established);
    }
    let der =
        rustls::pki_types::CertificateDer::from_pem_slice(ca.certificate_pem().as_bytes()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    connector
        .connect(name, tcp)
        .await
        .map_err(|error| error.to_string())
}

async fn get(
    client: &mut tokio_rustls::client::TlsStream<TcpStream>,
    host: &str,
    port: u16,
    path: &str,
) -> String {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    client.write_all(request.as_bytes()).await.unwrap();
    read_head(client).await
}

#[tokio::test(flavor = "multi_thread")]
async fn the_proxy_does_not_send_an_https_credential_to_a_database_port() {
    const LOOPBACK: &str = "localhost";
    let (api_port, api_seen) = recording_listener().await;
    let (redis_port, redis_seen) = recording_listener().await;

    let file: zs::AgentFile = serde_json::from_value(serde_json::json!({
        "bindings": [
            {
                "resource": API,
                "host": LOOPBACK,
                "protocol": "https",
                "upstream_port": api_port,
                "upstream_plaintext": true,
                "paths": [API_PATH]
            },
            {
                "resource": CACHE,
                "host": LOOPBACK,
                "protocol": "redis",
                "upstream_host": "127.0.0.1",
                "upstream_port": redis_port,
                "upstream_plaintext": true
            }
        ]
    }))
    .unwrap();
    file.validate()
        .expect("the agent accepts this policy file at load");

    let plaintext = |host: &str, port: u16| zs_policy::ResolvedConnection {
        upstream_host: host.to_string(),
        upstream_port: port,
        upstream_tls: zs_policy::UpstreamTlsMode::Plaintext,
        local_endpoint: false,
    };
    let home = tempfile::tempdir().unwrap();
    let credentials = home.path().join("credentials");
    std::fs::create_dir_all(&credentials).unwrap();
    std::fs::write(credentials.join(API_REF), TOKEN).unwrap();
    let handler = agent(
        file.bindings.clone(),
        vec![
            grant_with(
                API,
                LOOPBACK,
                "https",
                "GET",
                API_REF,
                plaintext(LOOPBACK, api_port),
            ),
            grant_with(
                CACHE,
                LOOPBACK,
                "redis",
                "connect",
                "cache-password",
                plaintext("127.0.0.1", redis_port),
            ),
        ],
        &credentials,
    );

    let ca = Arc::new(zs_mitm::LocalCa::load_or_create(home.path().join("ca")).unwrap());
    let token = Arc::new(zs_mitm::RunToken::generate());
    let server = zs_mitm::ProxyServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        ca.clone(),
        Arc::new(handler),
        Arc::new(zs_audit::Journal::open(home.path().join("audit.jsonl")).unwrap()),
        token.clone(),
    )
    .await
    .unwrap();
    let proxy = server.local_addr().unwrap();
    tokio::spawn(async move { server.serve().await });

    let mut api = tunnel(proxy, &ca, &token, LOOPBACK, api_port)
        .await
        .expect("positive control: the https binding's host and port open a tunnel");
    let reply = get(&mut api, LOOPBACK, api_port, API_PATH).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(
        saw_token(&api_seen),
        "positive control: the https upstream gets the credential on the scoped path"
    );
    drop(api);

    api_seen.lock().unwrap().clear();
    let mut api = tunnel(proxy, &ca, &token, LOOPBACK, api_port)
        .await
        .unwrap();
    let reply = get(&mut api, LOOPBACK, api_port, OUTSIDE).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert_eq!(api_seen.lock().unwrap().len(), 1);
    assert!(
        !saw_token(&api_seen),
        "negative control: a path outside `paths` is forwarded without the credential"
    );
    drop(api);

    if let Ok(mut cache) = tunnel(proxy, &ca, &token, CACHE, redis_port).await {
        let _ = get(&mut cache, CACHE, redis_port, OUTSIDE).await;
    }
    assert!(
        !saw_token(&redis_seen),
        "`CONNECT {CACHE}:{redis_port}` then `GET {OUTSIDE}`: the listener on the Redis binding's \
         port received the https binding's credential, on a path outside `paths`"
    );
}

#[test]
fn a_binding_key_used_twice_is_refused_at_load() {
    let https = serde_json::json!({ "resource": API, "host": HOST, "protocol": "https" });
    let postgres = |resource: &str| {
        serde_json::json!({
            "resource": resource,
            "host": PG_HOST,
            "protocol": "postgres",
            "upstream_port": PG_PORT
        })
    };
    let validate = |bindings: serde_json::Value| {
        serde_json::from_value::<zs::AgentFile>(serde_json::json!({ "bindings": bindings }))
            .unwrap()
            .validate()
    };

    validate(serde_json::json!([https.clone(), postgres(PG)]))
        .expect("positive control: distinct keys load");

    for (case, bindings) in [
        (
            "database resource named as the https host",
            serde_json::json!([https.clone(), postgres(HOST)]),
        ),
        (
            "https host named as the database resource, other case",
            serde_json::json!([postgres(&HOST.to_ascii_uppercase()), https.clone()]),
        ),
        (
            "two https bindings on one host",
            serde_json::json!([
                https.clone(),
                { "resource": "second-api", "host": HOST.to_ascii_uppercase(), "protocol": "https" }
            ]),
        ),
    ] {
        let Err(error) = validate(bindings) else {
            panic!("{case}: a binding silently replaces another, so the load must refuse it");
        };
        assert!(
            error
                .to_string()
                .contains("is already used by another binding"),
            "{case}: {error}"
        );
    }
}
