use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;
use zs_diag::{Component, DiagLog, Event, ServerText};

#[derive(Debug, Error)]
pub enum PostgresError {
    #[error("bad startup message")]
    BadStartup,
    #[error("bad postgres message framing")]
    BadFraming,
    #[error("scram error: {0}")]
    Scram(String),
    #[error("upstream unavailable: {0}")]
    Unavailable(String),
    #[error("{detail}")]
    Refused {
        sqlstate: String,
        detail: String,
        message: String,
    },
    #[error("upstream refused authentication: {sqlstate} {message}")]
    AuthRefused { sqlstate: String, message: String },
    #[error("upstream asked for authentication type {0}; only SCRAM-SHA-256 is supported")]
    UnsupportedMethod(u32),
}

pub type Result<T> = std::result::Result<T, PostgresError>;

fn startup_parameters(payload: &[u8]) -> Result<Vec<(&[u8], &[u8])>> {
    let len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    if len < 8 || len > payload.len() {
        return Err(PostgresError::BadStartup);
    }
    let parts: Vec<&[u8]> = payload[8..len].split(|b| *b == 0).collect();
    Ok(parts
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[key, value]| (*key, *value))
        .collect())
}

pub fn parse_startup(payload: &[u8]) -> Result<(String, String)> {
    let mut user = String::new();
    let mut database = String::new();
    for (key, value) in startup_parameters(payload)? {
        let value = String::from_utf8_lossy(value).into_owned();
        match key {
            b"user" => user = value,
            b"database" => database = value,
            _ => {}
        }
    }
    Ok((user, database))
}

pub const USER_MISMATCH_REASON: &str = "user mismatch";
pub const REPLICATION_REFUSED_REASON: &str = "replication refused";

fn startup_refusal(payload: &[u8], expected_user: Option<&str>) -> Result<Option<&'static str>> {
    let parameters = startup_parameters(payload)?;
    if parameters
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case(b"replication"))
    {
        return Ok(Some(REPLICATION_REFUSED_REASON));
    }
    let Some(expected) = expected_user else {
        return Ok(None);
    };
    let mut users = parameters
        .iter()
        .filter(|(key, _)| *key == b"user")
        .peekable();
    let matches = users.peek().is_some() && users.all(|(_, user)| *user == expected.as_bytes());
    Ok((!matches).then_some(USER_MISMATCH_REASON))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return Vec::new();
    };
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hi(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(password) else {
        return Vec::new();
    };
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut ui = mac.finalize().into_bytes().to_vec();
    let mut result = ui.clone();
    for _ in 1..iterations {
        let Ok(next) = Hmac::<Sha256>::new_from_slice(password) else {
            return Vec::new();
        };
        mac = next;
        mac.update(&ui);
        ui = mac.finalize().into_bytes().to_vec();
        for (a, b) in result.iter_mut().zip(ui.iter()) {
            *a ^= *b;
        }
    }
    result
}

const MIN_SCRAM_ITERATIONS: u32 = 4096;
const MAX_SCRAM_ITERATIONS: u32 = 1_000_000;

pub struct ScramExchange {
    pub client_first_bare: String,
    pub client_final_without_proof: String,
    pub proof: String,
    pub expected_server_signature: Vec<u8>,
}

pub fn client_first_message(nonce: &mut [u8; 18]) -> (String, String) {
    RngCore::fill_bytes(&mut rand::rngs::OsRng, nonce);
    let nonce = base64::engine::general_purpose::STANDARD.encode(nonce);
    let client_first_bare = format!("n=,r={nonce}");
    let client_first = format!("n,,{client_first_bare}");
    (client_first, client_first_bare)
}

pub fn client_final_message(
    password: &str,
    server_first: &str,
    client_first_bare: &str,
) -> Result<ScramExchange> {
    let mut salt = None;
    let mut iterations = None;
    let mut server_nonce = None;
    for part in server_first.split(',') {
        if let Some(v) = part.strip_prefix("s=") {
            salt = base64::engine::general_purpose::STANDARD.decode(v).ok()
        } else if let Some(v) = part.strip_prefix("i=") {
            iterations = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("r=") {
            server_nonce = Some(v.to_string());
        }
    }
    let salt = salt.ok_or_else(|| PostgresError::Scram("no salt".into()))?;
    let iterations: u32 = iterations.ok_or_else(|| PostgresError::Scram("no iterations".into()))?;
    if !(MIN_SCRAM_ITERATIONS..=MAX_SCRAM_ITERATIONS).contains(&iterations) {
        return Err(PostgresError::Scram("iteration count out of range".into()));
    }
    let server_nonce = server_nonce.ok_or_else(|| PostgresError::Scram("no nonce".into()))?;
    let client_nonce = client_first_bare
        .split(',')
        .find_map(|part| part.strip_prefix("r="))
        .ok_or_else(|| PostgresError::Scram("no client nonce".into()))?;
    if !server_nonce.starts_with(client_nonce) || server_nonce.len() == client_nonce.len() {
        return Err(PostgresError::Scram(
            "server nonce does not extend the client nonce".into(),
        ));
    }
    let mut salted_password = hi(password.as_bytes(), &salt, iterations);
    let mut client_key = hmac_sha256(&salted_password, b"Client Key");
    let mut stored_key = Sha256::digest(&client_key).to_vec();
    let client_final_without_proof = format!("c=biws,r={server_nonce}");
    let auth_message = format!("{client_first_bare},{server_first},{client_final_without_proof}");
    let mut client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
    let mut proof = client_key.clone();
    for (a, b) in proof.iter_mut().zip(client_signature.iter()) {
        *a ^= *b;
    }
    let mut server_key = hmac_sha256(&salted_password, b"Server Key");
    let server_signature = hmac_sha256(&server_key, auth_message.as_bytes());
    let proof_text = base64::engine::general_purpose::STANDARD.encode(&proof);
    for secret in [
        &mut salted_password,
        &mut client_key,
        &mut stored_key,
        &mut client_signature,
        &mut server_key,
        &mut proof,
    ] {
        secret.zeroize();
    }
    Ok(ScramExchange {
        client_first_bare: client_first_bare.to_string(),
        client_final_without_proof,
        proof: proof_text,
        expected_server_signature: server_signature,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    fn admit_all() -> zs_protocol::CallerCheck {
        Arc::new(|_, _| true)
    }

    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use zs_upstream::connect_with;

    const PASSWORD: &str = "unit-test-upstream-pencil";
    const SALT: &[u8] = b"zs-unit-test-salt";
    const ITERATIONS: u32 = 4096;
    const UNRESOLVABLE_HOST: &str = "db.zs-unit-test.invalid";

    type Connecting = Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send>>;
    type Asked = Arc<Mutex<Vec<(String, u16)>>>;

    struct FakePostgres {
        addr: SocketAddr,
        accepts: Arc<AtomicUsize>,
        queries: Arc<Mutex<Vec<String>>>,
    }

    async fn fake_postgres(
        signature_override: Option<[u8; 32]>,
        parameter_padding: usize,
    ) -> FakePostgres {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let queries = Arc::new(Mutex::new(Vec::new()));
        let (count, seen) = (accepts.clone(), queries.clone());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                let seen = seen.clone();
                tokio::spawn(async move {
                    let _ =
                        serve_verified_query(stream, seen, signature_override, parameter_padding)
                            .await;
                });
            }
        });
        FakePostgres {
            addr,
            accepts,
            queries,
        }
    }

    async fn write_tagged(stream: &mut TcpStream, tag: u8, body: &[u8]) -> std::io::Result<()> {
        let mut msg = vec![tag];
        msg.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        msg.extend_from_slice(body);
        stream.write_all(&msg).await
    }

    async fn serve_verified_query(
        mut stream: TcpStream,
        seen: Arc<Mutex<Vec<String>>>,
        signature_override: Option<[u8; 32]>,
        parameter_padding: usize,
    ) -> std::io::Result<()> {
        read_startup_answering_n(&mut stream).await?;

        let mut offer = 10u32.to_be_bytes().to_vec();
        offer.extend_from_slice(b"SCRAM-SHA-256\0\0");
        write_tagged(&mut stream, b'R', &offer).await?;

        let (_, initial) = read_tagged(&mut stream)
            .await
            .map_err(std::io::Error::other)?;
        let initial = String::from_utf8_lossy(&initial).into_owned();
        let client_first_bare = initial
            .split_once("n,,")
            .map(|(_, bare)| bare.to_string())
            .ok_or_else(|| std::io::Error::other("no client-first-bare"))?;
        let client_nonce = client_first_bare
            .split(',')
            .find_map(|part| part.strip_prefix("r="))
            .ok_or_else(|| std::io::Error::other("no client nonce"))?;
        let server_first = format!(
            "r={client_nonce}fakeServerNonce,s={},i={ITERATIONS}",
            base64::engine::general_purpose::STANDARD.encode(SALT)
        );
        let mut challenge = 11u32.to_be_bytes().to_vec();
        challenge.extend_from_slice(server_first.as_bytes());
        write_tagged(&mut stream, b'R', &challenge).await?;

        let (_, final_body) = read_tagged(&mut stream)
            .await
            .map_err(std::io::Error::other)?;
        let client_final = String::from_utf8_lossy(&final_body).into_owned();
        let (without_proof, proof) = client_final
            .rsplit_once(",p=")
            .ok_or_else(|| std::io::Error::other("no client proof"))?;
        let proof = base64::engine::general_purpose::STANDARD
            .decode(proof)
            .map_err(std::io::Error::other)?;
        let salted = hi(PASSWORD.as_bytes(), SALT, ITERATIONS);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = Sha256::digest(&client_key).to_vec();
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
        let signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let recovered: Vec<u8> = proof
            .iter()
            .zip(signature.iter())
            .map(|(p, s)| p ^ s)
            .collect();
        if proof.len() != signature.len() || Sha256::digest(&recovered).to_vec() != stored_key {
            write_tagged(&mut stream, b'E', b"SFATAL\0C28P01\0Mbad proof\0\0").await?;
            return Err(std::io::Error::other("bad proof"));
        }

        let server_key = hmac_sha256(&salted, b"Server Key");
        let signature = signature_override
            .map(|forged| forged.to_vec())
            .unwrap_or_else(|| hmac_sha256(&server_key, auth_message.as_bytes()));
        let verifier = format!(
            "v={}",
            base64::engine::general_purpose::STANDARD.encode(signature)
        );
        let mut sasl_final = 12u32.to_be_bytes().to_vec();
        sasl_final.extend_from_slice(verifier.as_bytes());
        write_tagged(&mut stream, b'R', &sasl_final).await?;
        write_tagged(&mut stream, b'R', &0u32.to_be_bytes()).await?;
        write_tagged(&mut stream, b'S', b"client_encoding\0UTF8\0").await?;
        let mut remaining = parameter_padding;
        while remaining > 0 {
            let chunk = remaining.min(600_000);
            let mut parameter = b"zs_padding\0".to_vec();
            parameter.extend(std::iter::repeat_n(b'x', chunk));
            parameter.push(0);
            write_tagged(&mut stream, b'S', &parameter).await?;
            remaining -= chunk;
        }
        write_tagged(&mut stream, b'K', &[0, 0, 0, 7, 0, 0, 0, 9]).await?;
        write_tagged(&mut stream, b'Z', b"I").await?;

        let (tag, body) = read_tagged(&mut stream)
            .await
            .map_err(std::io::Error::other)?;
        if tag != b'Q' {
            return Err(std::io::Error::other("expected a simple query"));
        }
        let sql = String::from_utf8_lossy(&body)
            .trim_end_matches('\0')
            .to_string();
        seen.lock().unwrap().push(sql.clone());
        let mut complete = sql.into_bytes();
        complete.push(0);
        write_tagged(&mut stream, b'C', &complete).await?;
        write_tagged(&mut stream, b'Z', b"I").await
    }

    async fn query_through(local: SocketAddr) -> Result<String> {
        let io = |e: std::io::Error| PostgresError::Scram(e.to_string());
        let mut client = TcpStream::connect(local).await.map_err(io)?;
        client
            .write_all(&startup_packet("alice", "appdb"))
            .await
            .map_err(io)?;
        while read_tagged(&mut client).await?.0 != b'Z' {}
        let mut query = b"Q".to_vec();
        query.extend_from_slice(&(4 + 9u32).to_be_bytes());
        query.extend_from_slice(b"SELECT 1\0");
        client.write_all(&query).await.map_err(io)?;
        let mut complete = String::new();
        loop {
            let (tag, body) = read_tagged(&mut client).await?;
            match tag {
                b'C' => {
                    complete = String::from_utf8_lossy(&body)
                        .trim_end_matches('\0')
                        .to_string()
                }
                b'Z' => return Ok(complete),
                _ => {}
            }
        }
    }

    async fn startup_reply(local: SocketAddr) -> Vec<u8> {
        let mut client = TcpStream::connect(local).await.unwrap();
        client
            .write_all(&startup_packet("alice", "appdb"))
            .await
            .unwrap();
        let mut written = Vec::new();
        client.read_to_end(&mut written).await.unwrap();
        written
    }

    fn scripted(
        answers: Vec<Vec<SocketAddr>>,
    ) -> (
        impl Fn(UpstreamEndpoint) -> Connecting + Clone + Send + 'static,
        Asked,
    ) {
        let answers = Arc::new(Mutex::new(VecDeque::from(answers)));
        let asked: Asked = Arc::new(Mutex::new(Vec::new()));
        let record = asked.clone();
        let connect = move |endpoint: UpstreamEndpoint| -> Connecting {
            let (answers, record) = (answers.clone(), record.clone());
            Box::pin(async move {
                connect_with(&endpoint, move |host, port| async move {
                    record.lock().unwrap().push((host, port));
                    Ok(answers.lock().unwrap().pop_front().unwrap_or_default())
                })
                .await
            })
        };
        (connect, asked)
    }

    async fn scripted_upstream<F, Fut>(script: F) -> SocketAddr
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                script(stream).await;
            }
        });
        addr
    }

    async fn read_startup_answering_n(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        loop {
            let mut len = [0u8; 4];
            stream.read_exact(&mut len).await?;
            let mut packet = len.to_vec();
            packet.resize((u32::from_be_bytes(len) as usize).max(4), 0);
            stream.read_exact(&mut packet[4..]).await?;
            if packet != SSL_REQUEST_PACKET {
                return Ok(packet);
            }
            stream.write_all(b"N").await?;
        }
    }

    async fn read_client_startup(stream: &mut TcpStream) {
        read_startup_answering_n(stream).await.unwrap();
    }

    fn negotiation_request(code: u32) -> Vec<u8> {
        let mut packet = 8u32.to_be_bytes().to_vec();
        packet.extend_from_slice(&code.to_be_bytes());
        packet
    }

    async fn closed_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    fn materialize_password(password: &'static str) -> Materialize {
        Arc::new(move || Ok(Credential::from_bytes(password.as_bytes().to_vec()).unwrap()))
    }

    async fn serve_scripted<C, F>(connect: C, materialize: Materialize) -> SocketAddr
    where
        C: Fn(UpstreamEndpoint) -> F + Clone + Send + 'static,
        F: Future<Output = std::io::Result<TcpStream>> + Send + 'static,
    {
        let endpoint = UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap();
        let listener = PostgresListener::bind_endpoint(
            "127.0.0.1:0",
            endpoint,
            SslPolicy::RefuseOnLoopback,
            UpstreamTls::WhenOffered,
            materialize,
        )
        .await
        .unwrap()
        .with_caller_check(admit_all());
        let local = listener.local_addr();
        tokio::spawn(
            listener
                .with_cancel_authorize(Arc::new(|| Ok(())))
                .serve_with(connect),
        );
        local
    }

    #[tokio::test]
    async fn same_listener_resolves_for_each_client() {
        let first = fake_postgres(None, 0).await;
        let second = fake_postgres(None, 0).await;
        let (connect, asked) = scripted(vec![vec![first.addr], vec![second.addr]]);
        let local = serve_scripted(connect, materialize_password(PASSWORD)).await;

        let reply = tokio::time::timeout(Duration::from_secs(5), query_through(local))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, "SELECT 1");
        assert_eq!(first.accepts.load(Ordering::SeqCst), 1);
        assert_eq!(second.accepts.load(Ordering::SeqCst), 0);

        let reply = tokio::time::timeout(Duration::from_secs(5), query_through(local))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, "SELECT 1");
        assert_eq!(first.accepts.load(Ordering::SeqCst), 1);
        assert_eq!(second.accepts.load(Ordering::SeqCst), 1);
        assert_eq!(first.queries.lock().unwrap().as_slice(), ["SELECT 1"]);
        assert_eq!(second.queries.lock().unwrap().as_slice(), ["SELECT 1"]);

        let expected = (UNRESOLVABLE_HOST.to_string(), 5432);
        assert_eq!(
            asked.lock().unwrap().as_slice(),
            [expected.clone(), expected]
        );
    }

    #[tokio::test]
    async fn listener_falls_back_from_a_closed_candidate_and_authenticates() {
        let closed = closed_addr().await;
        let live = fake_postgres(None, 0).await;
        let (connect, asked) = scripted(vec![vec![closed, live.addr]]);
        let local = serve_scripted(connect, materialize_password(PASSWORD)).await;

        let reply = tokio::time::timeout(Duration::from_secs(5), query_through(local))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(reply, "SELECT 1");
        assert_eq!(live.accepts.load(Ordering::SeqCst), 1);
        assert_eq!(live.queries.lock().unwrap().as_slice(), ["SELECT 1"]);
        assert_eq!(asked.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fake_upstream_rejects_a_proof_from_the_wrong_password() {
        let live = fake_postgres(None, 0).await;
        let (connect, asked) = scripted(vec![vec![live.addr]]);
        let local = serve_scripted(connect, materialize_password("not-the-password")).await;

        let reply = tokio::time::timeout(Duration::from_secs(5), startup_reply(local))
            .await
            .unwrap();

        assert_eq!(reply, error_response("upstream authentication failed"));
        assert_eq!(asked.lock().unwrap().len(), 1);
        assert_eq!(live.accepts.load(Ordering::SeqCst), 1);
        assert!(live.queries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn materialization_denial_never_resolves_upstream() {
        let live = fake_postgres(None, 0).await;
        let (connect, asked) = scripted(vec![vec![live.addr]]);
        let materialize: Materialize =
            Arc::new(|| Err(zs_protocol::Denied::new("audit sink unavailable")));
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = front.local_addr().unwrap();
        let endpoint = UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap();
        let handled = tokio::spawn(async move {
            let (client, _) = front.accept().await.unwrap();
            handle_connection(
                client,
                Upstream::new(endpoint, UpstreamTls::WhenOffered).unwrap(),
                SslPolicy::RefuseOnLoopback,
                materialize,
                connect,
                HANDSHAKE_BUDGET,
                &Trace::disabled(),
            )
            .await
        });

        let mut client = TcpStream::connect(local).await.unwrap();
        client
            .write_all(&startup_packet("alice", "appdb"))
            .await
            .unwrap();
        let mut written = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut written))
            .await
            .unwrap()
            .unwrap();
        handled.await.unwrap().unwrap();

        assert_eq!(written.first(), Some(&b'E'));
        assert!(asked.lock().unwrap().is_empty());
        assert_eq!(live.accepts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_connect_never_echoes_the_materialized_credential() {
        const SENTINEL: &str = "zs-sentinel-credential-5b1e9d";
        let leaks = |text: &str| text.contains(SENTINEL);
        assert!(leaks(&format!("{:?}", std::io::Error::other(SENTINEL))));

        let closed = closed_addr().await;
        let (connect, asked) = scripted(vec![vec![closed]]);
        let materialized = Arc::new(AtomicUsize::new(0));
        let count = materialized.clone();
        let materialize: Materialize = Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(Credential::from_bytes(SENTINEL.as_bytes().to_vec()).unwrap())
        });
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = front.local_addr().unwrap();
        let endpoint = UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap();
        let handled = tokio::spawn(async move {
            let (client, _) = front.accept().await.unwrap();
            handle_connection(
                client,
                Upstream::new(endpoint, UpstreamTls::WhenOffered).unwrap(),
                SslPolicy::RefuseOnLoopback,
                materialize,
                connect,
                HANDSHAKE_BUDGET,
                &Trace::disabled(),
            )
            .await
        });

        let mut client = TcpStream::connect(local).await.unwrap();
        client
            .write_all(&startup_packet("alice", "appdb"))
            .await
            .unwrap();
        let mut written = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut written))
            .await
            .unwrap()
            .unwrap();
        let (stage, error) = handled.await.unwrap().unwrap_err();

        assert_eq!(stage, "connect");
        assert_eq!(materialized.load(Ordering::SeqCst), 1);
        assert_eq!(asked.lock().unwrap().len(), 1);
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        assert!(!leaks(&error.to_string()));
        assert!(!leaks(&format!("{error:?}")));
        assert_eq!(written, error_frame("08006", "upstream unavailable"));
        assert!(!leaks(&String::from_utf8_lossy(&written)));
    }

    #[test]
    fn startup_message_round_trip() {
        let mut payload = vec![0, 0, 0, 0];
        payload.extend_from_slice(&196608u32.to_be_bytes());
        payload.extend_from_slice(b"user\0alice\0database\0appdb\0\0");
        let len = payload.len() as u32;
        payload[0..4].copy_from_slice(&len.to_be_bytes());
        let (user, database) = parse_startup(&payload).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(database, "appdb");
    }

    #[test]
    fn scram_rfc7677_self_check() {
        let password = "pencil";
        let client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let exchange = client_final_message(password, server_first, client_first_bare).unwrap();
        assert_eq!(
            exchange.proof,
            "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
    }

    #[tokio::test]
    async fn wrong_server_signature_is_rejected() {
        let forged = fake_postgres(Some([0xFF; 32]), 0).await;
        let (connect, _asked) = scripted(vec![vec![forged.addr]]);
        let local = serve_scripted(connect, materialize_password(PASSWORD)).await;

        let reply = tokio::time::timeout(Duration::from_secs(5), startup_reply(local))
            .await
            .unwrap();

        assert_eq!(reply, error_response("upstream authentication failed"));
        assert_eq!(forged.accepts.load(Ordering::SeqCst), 1);
        assert!(
            forged.queries.lock().unwrap().is_empty(),
            "no query must reach the upstream after a signature mismatch"
        );
    }

    #[test]
    fn server_nonce_that_does_not_extend_the_client_nonce_is_rejected() {
        let client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        let server_first =
            "r=someoneElsesNonce%hvYDpWUa2RaTCAfuxFIlj,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        assert!(client_final_message("pencil", server_first, client_first_bare).is_err());
    }

    #[test]
    fn server_nonce_equal_to_the_client_nonce_is_rejected() {
        let client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        let server_first = "r=rOprNGfwEbeRWgbNEkqO,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        assert!(client_final_message("pencil", server_first, client_first_bare).is_err());
    }

    #[tokio::test]
    async fn an_upstream_that_is_starting_up_is_reported_unavailable() {
        let upstream = scripted_upstream(|mut stream| async move {
            read_client_startup(&mut stream).await;
            let _ = write_tagged(
                &mut stream,
                b'E',
                b"SFATAL\0C57P03\0Mthe database system is starting up\0\0",
            )
            .await;
        })
        .await;
        let (connect, _asked) = scripted(vec![vec![upstream]]);
        let local = serve_scripted(connect, materialize_password(PASSWORD)).await;

        let reply = tokio::time::timeout(Duration::from_secs(5), startup_reply(local))
            .await
            .unwrap();

        assert_eq!(reply, error_frame("08006", "upstream unavailable"));
    }

    #[tokio::test]
    async fn a_silent_upstream_is_reported_unavailable_within_the_budget() {
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
        let upstream = scripted_upstream(|mut stream| async move {
            read_client_startup(&mut stream).await;
            let _ = hold_rx.await;
        })
        .await;
        let (connect, _asked) = scripted(vec![vec![upstream]]);
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = front.local_addr().unwrap();
        let endpoint = UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap();
        let handled = tokio::spawn(async move {
            let (client, _) = front.accept().await.unwrap();
            handle_connection(
                client,
                Upstream::new(endpoint, UpstreamTls::WhenOffered).unwrap(),
                SslPolicy::RefuseOnLoopback,
                materialize_password(PASSWORD),
                connect,
                Duration::from_millis(200),
                &Trace::disabled(),
            )
            .await
        });

        let reply = tokio::time::timeout(Duration::from_secs(3), startup_reply(local))
            .await
            .expect("a silent upstream must not hold the client past the budget");
        let (stage, error) = handled.await.unwrap().unwrap_err();
        drop(hold_tx);

        assert_eq!(reply, error_frame("08006", "upstream unavailable"));
        assert_eq!(stage, "auth");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_silent_tls_answer_is_refused_within_the_budget() {
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
        let upstream = scripted_upstream(|mut stream| async move {
            let mut request = [0u8; 8];
            let _ = stream.read_exact(&mut request).await;
            let _ = seen_tx.send(request.to_vec());
            let _ = hold_rx.await;
        })
        .await;
        let (connect, _asked) = scripted(vec![vec![upstream]]);
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = front.local_addr().unwrap();
        let target = Upstream::new(
            UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap(),
            UpstreamTls::WhenOffered,
        )
        .unwrap();
        let handled = tokio::spawn(async move {
            let (client, _) = front.accept().await.unwrap();
            handle_connection(
                client,
                target,
                SslPolicy::RefuseOnLoopback,
                materialize_password(PASSWORD),
                connect,
                Duration::from_millis(200),
                &Trace::disabled(),
            )
            .await
        });

        let reply = tokio::time::timeout(Duration::from_secs(3), startup_reply(local))
            .await
            .expect("a silent TLS answer must not hold the client past the budget");
        let (stage, error) = handled.await.unwrap().unwrap_err();
        let request = seen_rx.await.unwrap();
        drop(hold_tx);

        assert_eq!(request, SSL_REQUEST_PACKET);
        assert_eq!(reply, error_frame("08006", "upstream unavailable"));
        assert_eq!(stage, "tls");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_reset_during_the_handshake_is_reported_unavailable() {
        let upstream = scripted_upstream(|mut stream| async move {
            read_client_startup(&mut stream).await;
            drop(stream);
        })
        .await;
        let (connect, _asked) = scripted(vec![vec![upstream]]);
        let local = serve_scripted(connect, materialize_password(PASSWORD)).await;

        let reply = tokio::time::timeout(Duration::from_secs(5), startup_reply(local))
            .await
            .unwrap();

        assert_eq!(reply, error_frame("08006", "upstream unavailable"));
    }

    fn startup_with(parameters: &[(&str, &str)]) -> Vec<u8> {
        let mut body = 196_608u32.to_be_bytes().to_vec();
        for (key, value) in parameters {
            body.extend_from_slice(key.as_bytes());
            body.push(0);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
        body.push(0);
        let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn startup_refusal_pins_the_parameter_edge_cases() {
        let mismatched = |parameters: &[(&str, &str)]| {
            startup_refusal(&startup_with(parameters), Some("app")).unwrap()
        };
        assert_eq!(
            mismatched(&[("user", "app"), ("user", "postgres")]),
            Some(USER_MISMATCH_REASON)
        );
        assert_eq!(
            mismatched(&[("database", "appdb")]),
            Some(USER_MISMATCH_REASON)
        );
        assert_eq!(mismatched(&[("USER", "app")]), Some(USER_MISMATCH_REASON));
        assert_eq!(
            startup_refusal(&startup_with(&[("REPLICATION", "database")]), None).unwrap(),
            Some(REPLICATION_REFUSED_REASON)
        );
        assert_eq!(
            startup_refusal(&startup_with(&[("Replication", "false")]), Some("app")).unwrap(),
            Some(REPLICATION_REFUSED_REASON)
        );
        assert_eq!(
            mismatched(&[("user", "app")]),
            None,
            "positive control: the bound user is accepted"
        );
        assert_eq!(
            mismatched(&[("user", "app"), ("user", "app")]),
            None,
            "a repeated user with the same value is accepted"
        );
    }

    #[tokio::test]
    async fn oversized_startup_parameters_are_refused() {
        let live = fake_postgres(None, 1_200_000).await;
        let (connect, _asked) = scripted(vec![vec![live.addr]]);
        let local = serve_scripted(connect, materialize_password(PASSWORD)).await;

        let reply = tokio::time::timeout(Duration::from_secs(5), startup_reply(local))
            .await
            .unwrap();

        assert_eq!(reply, error_frame("08006", "upstream unavailable"));
        assert!(live.queries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_gssenc_request_is_refused_and_the_startup_that_follows_is_served() {
        let live = fake_postgres(None, 0).await;
        let (connect, _asked) = scripted(vec![vec![live.addr]]);
        let local = serve_scripted(connect, materialize_password(PASSWORD)).await;

        let mut client = TcpStream::connect(local).await.unwrap();
        client
            .write_all(&negotiation_request(80_877_104))
            .await
            .unwrap();
        let mut answer = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut answer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&answer, b"N");
        client
            .write_all(&startup_packet("alice", "appdb"))
            .await
            .unwrap();
        let (tag, _) = tokio::time::timeout(Duration::from_secs(5), read_tagged(&mut client))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(tag, b'R');
        assert_eq!(live.accepts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_cancel_request_is_relayed_to_upstream_without_materializing() {
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let upstream = scripted_upstream(|mut stream| async move {
            let mut request = [0u8; 8];
            let _ = stream.read_exact(&mut request).await;
            let _ = stream.write_all(b"N").await;
            let mut received = request.to_vec();
            let _ = stream.read_to_end(&mut received).await;
            let _ = seen_tx.send(received);
        })
        .await;
        let (connect, asked) = scripted(vec![vec![upstream]]);
        let materialized = Arc::new(AtomicUsize::new(0));
        let count = materialized.clone();
        let materialize: Materialize = Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(Credential::from_bytes(PASSWORD.as_bytes().to_vec()).unwrap())
        });
        let local = serve_scripted(connect, materialize).await;

        let mut client = TcpStream::connect(local).await.unwrap();
        let mut cancel = 16u32.to_be_bytes().to_vec();
        cancel.extend_from_slice(&80_877_102u32.to_be_bytes());
        cancel.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 9]);
        client.write_all(&cancel).await.unwrap();
        let mut written = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut written))
            .await
            .unwrap()
            .unwrap();
        let relayed = tokio::time::timeout(Duration::from_secs(5), seen_rx)
            .await
            .unwrap()
            .unwrap();

        let mut expected = SSL_REQUEST_PACKET.to_vec();
        expected.extend_from_slice(&cancel);
        assert_eq!(relayed, expected);
        assert!(written.is_empty());
        assert_eq!(materialized.load(Ordering::SeqCst), 0);
        assert_eq!(asked.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_cancel_without_an_authorizer_is_refused() {
        let (connect, asked) = scripted(vec![vec![]]);
        let endpoint = UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap();
        let listener = PostgresListener::bind_endpoint(
            "127.0.0.1:0",
            endpoint,
            SslPolicy::RefuseOnLoopback,
            UpstreamTls::WhenOffered,
            materialize_password(PASSWORD),
        )
        .await
        .unwrap()
        .with_caller_check(admit_all());
        let local = listener.local_addr();
        tokio::spawn(listener.serve_with(connect));

        let mut client = TcpStream::connect(local).await.unwrap();
        client
            .write_all(&negotiation_request(CANCEL_REQUEST))
            .await
            .unwrap();
        let mut written = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut written))
            .await
            .expect("a refused cancel must close the connection")
            .unwrap();

        assert!(written.is_empty());
        assert_eq!(asked.lock().unwrap().len(), 0, "the upstream was contacted");
    }

    #[tokio::test]
    async fn a_silent_tls_answer_to_a_cancel_ends_within_the_budget() {
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();
        let upstream = scripted_upstream(|mut stream| async move {
            let mut request = [0u8; 8];
            let _ = stream.read_exact(&mut request).await;
            let _ = hold_rx.await;
        })
        .await;
        let (connect, _asked) = scripted(vec![vec![upstream]]);
        let home = tempfile::tempdir().unwrap();
        let log_path = home.path().join("diag.jsonl");
        let diag = zs_diag::DiagLog::open_with_cap(&log_path, "t-1", 1 << 20).unwrap();
        let trace = Trace {
            diag: diag.clone(),
            conn: 1,
            resource: "orders-db".to_string(),
            host: UNRESOLVABLE_HOST.to_string(),
            port: 5432,
            cancel_authorize: Some(Arc::new(|| Ok(()))),
            ..Trace::disabled()
        };
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = front.local_addr().unwrap();
        let target = Upstream::new(
            UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap(),
            UpstreamTls::WhenOffered,
        )
        .unwrap();
        let handled = tokio::spawn(async move {
            let (client, _) = front.accept().await.unwrap();
            handle_connection(
                client,
                target,
                SslPolicy::RefuseOnLoopback,
                materialize_password(PASSWORD),
                connect,
                Duration::from_millis(200),
                &trace,
            )
            .await
        });

        let mut client = TcpStream::connect(local).await.unwrap();
        let mut cancel = 16u32.to_be_bytes().to_vec();
        cancel.extend_from_slice(&CANCEL_REQUEST.to_be_bytes());
        cancel.extend_from_slice(&[0, 0, 0, 7, 0, 0, 0, 9]);
        client.write_all(&cancel).await.unwrap();
        let (stage, error) = tokio::time::timeout(Duration::from_secs(3), handled)
            .await
            .expect("a silent server must not hold a cancel past the budget")
            .unwrap()
            .unwrap_err();
        drop(hold_tx);
        tokio::time::sleep(Duration::from_millis(200)).await;
        diag.close();

        assert_eq!(stage, "cancel");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        let log = std::fs::read_to_string(&log_path).unwrap();
        let events: Vec<serde_json::Value> = log
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let tls = events.iter().find(|e| e["event"] == "tls").expect(&log);
        assert_eq!(tls["fields"]["result"], "failed", "{log}");
        assert_eq!(tls["error"]["kind"], "timed_out", "{log}");
        let failed = events
            .iter()
            .find(|e| e["event"] == "upstream_failed")
            .expect(&log);
        assert_eq!(failed["fields"]["stage"], "tls", "{log}");
        assert_eq!(failed["error"]["kind"], "timed_out", "{log}");
    }

    async fn refusal_for(sqlstate: &str) -> Vec<u8> {
        let mut body = b"SFATAL\0C".to_vec();
        body.extend_from_slice(sqlstate.as_bytes());
        body.extend_from_slice(b"\0Mrefused\0\0");
        let upstream = scripted_upstream(|mut stream| async move {
            read_client_startup(&mut stream).await;
            let _ = write_tagged(&mut stream, b'E', &body).await;
        })
        .await;
        let (connect, _asked) = scripted(vec![vec![upstream]]);
        let local = serve_scripted(connect, materialize_password(PASSWORD)).await;
        tokio::time::timeout(Duration::from_secs(5), startup_reply(local))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_refusal_that_is_not_about_availability_keeps_its_sqlstate() {
        assert_eq!(
            refusal_for("3D000").await,
            error_frame("3D000", "upstream refused the connection")
        );
    }

    #[tokio::test]
    async fn an_upstream_out_of_connections_is_reported_unavailable() {
        assert_eq!(
            refusal_for("53300").await,
            error_frame("08006", "upstream unavailable")
        );
    }

    #[tokio::test]
    async fn a_malformed_sqlstate_is_reported_unavailable() {
        assert_eq!(
            refusal_for("3D\x01").await,
            error_frame("08006", "upstream unavailable")
        );
    }

    #[tokio::test]
    async fn a_client_that_sends_no_startup_is_closed_within_the_budget() {
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = front.local_addr().unwrap();
        let (connect, asked) = scripted(vec![]);
        let materialized = Arc::new(AtomicUsize::new(0));
        let count = materialized.clone();
        let materialize: Materialize = Arc::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(Credential::from_bytes(PASSWORD.as_bytes().to_vec()).unwrap())
        });
        let endpoint = UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap();
        let handled = tokio::spawn(async move {
            let (client, _) = front.accept().await.unwrap();
            handle_connection(
                client,
                Upstream::new(endpoint, UpstreamTls::WhenOffered).unwrap(),
                SslPolicy::RefuseOnLoopback,
                materialize,
                connect,
                Duration::from_millis(200),
                &Trace::disabled(),
            )
            .await
        });

        let mut client = TcpStream::connect(local).await.unwrap();
        let (stage, error) = tokio::time::timeout(Duration::from_secs(3), handled)
            .await
            .expect("a silent client must not hold the listener past the budget")
            .unwrap()
            .unwrap_err();
        let mut written = Vec::new();
        client.read_to_end(&mut written).await.unwrap();

        assert_eq!(stage, "startup");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(written.is_empty());
        assert_eq!(materialized.load(Ordering::SeqCst), 0);
        assert!(asked.lock().unwrap().is_empty());
    }

    #[test]
    fn iteration_count_above_the_cap_is_rejected() {
        let client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        let server_first =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=1000001";
        assert!(client_final_message("pencil", server_first, client_first_bare).is_err());
    }

    #[test]
    fn an_iteration_count_below_4096_is_refused() {
        let client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        let with = |i: u32| {
            let server_first = format!(
                "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj,s=W22ZaJ0SNY7soEsUEjb6gQ==,i={i}"
            );
            client_final_message("pencil", &server_first, client_first_bare)
        };
        for i in [1, 4095] {
            assert!(
                matches!(with(i), Err(PostgresError::Scram(m)) if m == "iteration count out of range")
            );
        }
        assert!(with(4096).is_ok());
    }

    #[test]
    fn iteration_count_of_zero_is_rejected() {
        let client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO";
        let server_first =
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=0";
        assert!(client_final_message("pencil", server_first, client_first_bare).is_err());
    }

    #[test]
    fn truncated_sasl_message_is_an_error_not_a_panic() {
        for body in [&[][..], &[0, 0], &[0, 0, 0]] {
            assert!(sasl_payload(b'R', body, 12).is_err());
        }
    }

    #[test]
    fn sasl_payload_checks_tag_and_subtype() {
        let mut body = 12u32.to_be_bytes().to_vec();
        body.extend_from_slice(b"v=abc");
        assert_eq!(sasl_payload(b'R', &body, 12).unwrap(), b"v=abc");
        assert!(sasl_payload(b'R', &body, 11).is_err());
        assert!(sasl_payload(b'E', &body, 12).is_err());
    }

    #[tokio::test]
    async fn a_postgres_auth_failure_is_logged_without_the_password() {
        const WRONG: &str = "unit-test-wrong-pencil-zsdiag";
        let home = tempfile::tempdir().unwrap();
        let log_path = home.path().join("diag.jsonl");
        let diag = zs_diag::DiagLog::open_with_cap(&log_path, "t-1", 1 << 20).unwrap();
        let live = fake_postgres(None, 0).await;
        let (connect, _asked) = scripted(vec![vec![live.addr]]);
        let endpoint = UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap();
        let listener = PostgresListener::bind_endpoint(
            "127.0.0.1:0",
            endpoint,
            SslPolicy::RefuseOnLoopback,
            UpstreamTls::WhenOffered,
            materialize_password(WRONG),
        )
        .await
        .unwrap()
        .with_caller_check(admit_all())
        .with_diag(diag.clone(), "orders-db");
        let local = listener.local_addr();
        tokio::spawn(listener.serve_with(connect));

        let reply = tokio::time::timeout(Duration::from_secs(5), startup_reply(local))
            .await
            .unwrap();
        assert_eq!(reply, error_response("upstream authentication failed"));
        tokio::time::sleep(Duration::from_millis(200)).await;
        diag.close();

        let log = std::fs::read_to_string(&log_path).unwrap();
        let events: Vec<serde_json::Value> = log
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let event = |name: &str| events.iter().find(|e| e["event"] == name).cloned();
        assert!(event("conn_accepted").is_some(), "{log}");
        assert_eq!(
            event("materialized").unwrap()["fields"]["decision"],
            "allow"
        );
        assert!(event("upstream_connected").is_some(), "{log}");
        let failed = event("upstream_auth_failed").expect("an auth failure event");
        assert_eq!(failed["fields"]["sqlstate"], "28P01");
        assert_eq!(failed["error"]["kind"], "refused");
        assert_eq!(failed["error"]["text"], "bad proof");
        assert_eq!(failed["resource"], "orders-db");
        let ended = event("conn_failed").expect("a conn_failed event");
        assert_eq!(ended["fields"]["stage"], "auth", "{log}");
        assert_eq!(ended["error"]["kind"], "other", "{log}");
        assert!(!log.contains(WRONG));
        assert!(!log.contains(PASSWORD));
    }

    #[tokio::test]
    async fn a_clean_close_logs_the_side_that_closed_first() {
        let home = tempfile::tempdir().unwrap();
        let log_path = home.path().join("diag.jsonl");
        let diag = zs_diag::DiagLog::open_with_cap(&log_path, "t-1", 1 << 20).unwrap();
        let live = fake_postgres(None, 0).await;
        let (connect, _asked) = scripted(vec![vec![live.addr]]);
        let endpoint = UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap();
        let listener = PostgresListener::bind_endpoint(
            "127.0.0.1:0",
            endpoint,
            SslPolicy::RefuseOnLoopback,
            UpstreamTls::WhenOffered,
            materialize_password(PASSWORD),
        )
        .await
        .unwrap()
        .with_caller_check(admit_all())
        .with_diag(diag.clone(), "orders-db");
        let local = listener.local_addr();
        tokio::spawn(listener.serve_with(connect));

        let mut client = TcpStream::connect(local).await.unwrap();
        client
            .write_all(&startup_packet("alice", "appdb"))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while read_tagged(&mut client).await.unwrap().0 != b'Z' {}
        })
        .await
        .unwrap();
        drop(client);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(&log_path)
            .unwrap()
            .contains("\"conn_closed\"")
        {
            assert!(std::time::Instant::now() < deadline, "no conn_closed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        diag.close();

        let log = std::fs::read_to_string(&log_path).unwrap();
        let events: Vec<serde_json::Value> = log
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let event = |name: &str| events.iter().find(|e| e["event"] == name).cloned();
        assert!(event("upstream_auth_ok").is_some(), "{log}");
        let closed = event("conn_closed").expect("a conn_closed event");
        assert_eq!(closed["fields"]["closed_by"], "client", "{log}");
        assert!(closed["fields"]["bytes_down"].is_u64(), "{log}");
        assert!(event("conn_failed").is_none(), "{log}");
        assert!(!log.contains(PASSWORD));
    }

    #[tokio::test]
    async fn a_refusal_log_carries_only_the_message_field() {
        let home = tempfile::tempdir().unwrap();
        let log_path = home.path().join("diag.jsonl");
        let diag = zs_diag::DiagLog::open_with_cap(&log_path, "t-1", 1 << 20).unwrap();
        let upstream = scripted_upstream(|mut stream| async move {
            read_client_startup(&mut stream).await;
            let _ = write_tagged(
                &mut stream,
                b'E',
                b"SFATAL\0CP0001\0Mlogin blocked by policy\0WSQL statement \"SELECT zsdiag_marker_42\"\0\0",
            )
            .await;
        })
        .await;
        let (connect, _asked) = scripted(vec![vec![upstream]]);
        let endpoint = UpstreamEndpoint::new(UNRESOLVABLE_HOST, 5432).unwrap();
        let listener = PostgresListener::bind_endpoint(
            "127.0.0.1:0",
            endpoint,
            SslPolicy::RefuseOnLoopback,
            UpstreamTls::WhenOffered,
            materialize_password(PASSWORD),
        )
        .await
        .unwrap()
        .with_caller_check(admit_all())
        .with_diag(diag.clone(), "orders-db");
        let local = listener.local_addr();
        tokio::spawn(listener.serve_with(connect));

        let reply = tokio::time::timeout(Duration::from_secs(5), startup_reply(local))
            .await
            .unwrap();
        assert_eq!(reply, error_frame("P0001", UPSTREAM_REFUSED));
        tokio::time::sleep(Duration::from_millis(200)).await;
        diag.close();

        let log = std::fs::read_to_string(&log_path).unwrap();
        let failed: serde_json::Value = log
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .find(|e| e["event"] == "upstream_auth_failed")
            .expect("an auth failure event");
        assert_eq!(failed["error"]["kind"], "refused");
        assert_eq!(failed["error"]["text"], "login blocked by policy");
        assert!(!log.contains("zsdiag_marker_42"), "{log}");
    }

    const LARGE_BODY: usize = 1_500_000;

    #[tokio::test]
    async fn a_large_frontend_message_is_relayed_intact() {
        let trace = Trace::disabled();
        let (mut from_client, client) = tokio::io::duplex(64 * 1024);
        let (upstream, mut relayed_to_upstream) = tokio::io::duplex(64 * 1024);
        let counter = AtomicU64::new(0);

        let mut query = b"Q".to_vec();
        query.extend_from_slice(&(4 + 9u32).to_be_bytes());
        query.extend_from_slice(b"SELECT 1\0");
        let mut large = b"Q".to_vec();
        large.extend_from_slice(&(4 + LARGE_BODY as u32).to_be_bytes());
        large.extend(std::iter::repeat_n(b'q', LARGE_BODY));
        let expected: Vec<u8> = query.iter().chain(large.iter()).copied().collect();

        let write = async {
            from_client.write_all(&query).await.unwrap();
            from_client.write_all(&large).await.unwrap();
            from_client.shutdown().await.unwrap();
        };
        let copy = copy_frontend(client, upstream, &counter, &trace);
        let collect = async {
            let mut received = Vec::new();
            relayed_to_upstream
                .read_to_end(&mut received)
                .await
                .unwrap();
            received
        };
        let ((), copied, received) = tokio::join!(write, copy, collect);

        assert_eq!(copied.unwrap(), expected.len() as u64);
        assert_eq!(received.len(), expected.len());
        assert!(
            received.starts_with(&query),
            "positive control: the normal query is relayed first"
        );
        assert_eq!(received, expected);
        assert_eq!(counter.load(Ordering::Relaxed), expected.len() as u64);
    }

    #[tokio::test]
    async fn a_bad_frontend_length_ends_the_relay() {
        let trace = Trace::disabled();
        let (mut from_client, client) = tokio::io::duplex(1024);
        let (upstream, mut relayed_to_upstream) = tokio::io::duplex(1024);
        let counter = AtomicU64::new(0);
        from_client.write_all(&[b'Q', 0, 0, 0, 3]).await.unwrap();

        let error = copy_frontend(client, upstream, &counter, &trace)
            .await
            .expect_err("a length below the framing minimum must end the relay");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        let mut received = Vec::new();
        relayed_to_upstream
            .read_to_end(&mut received)
            .await
            .unwrap();
        assert!(
            received.is_empty(),
            "nothing is forwarded past a bad length"
        );
    }
}

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zs_credential::Credential;

pub use zs_upstream::{TlsConfigError, UpstreamEndpoint, UpstreamTls};

// Answer SSLRequest with 'N': accepting without encrypting would make the client believe it has TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslPolicy {
    RefuseOnLoopback,
}

// A `Denied` must deny the connection, never relay it unauthenticated.
pub use zs_protocol::Materialize;
pub type AuditRefusal = Arc<dyn Fn(&'static str, &'static str) -> Option<u64> + Send + Sync>;
pub type CancelAuthorize =
    Arc<dyn Fn() -> std::result::Result<(), zs_protocol::Denied> + Send + Sync>;

const CANCEL_REFUSED_REASON: &str = "cancel without a grant";

#[derive(Clone)]
struct Trace {
    diag: DiagLog,
    conn: u64,
    resource: String,
    host: String,
    port: u16,
    expected_user: Option<Arc<str>>,
    audit_refusal: AuditRefusal,
    cancel_authorize: Option<CancelAuthorize>,
}

impl Trace {
    fn event(&self, name: &'static str) -> Event {
        Event::new(Component::Postgres, name)
            .conn(self.conn)
            .resource(&self.resource)
            .dest(&self.host, self.port)
    }

    fn refuse_startup(&self, reason: &'static str) -> Vec<u8> {
        let (code, reply) = match reason {
            REPLICATION_REFUSED_REASON => ("replication", REPLICATION_REFUSED),
            _ => ("user_mismatch", USER_REFUSED),
        };
        let mut event = self.event("client_refused").warn().code("reason", code);
        if let Some(seq) = (self.audit_refusal)("connect", reason) {
            event = event.audit_seq(seq);
        }
        self.diag.emit(event);
        error_frame(reply.0, reply.1)
    }

    fn cancel_authorized(&self) -> bool {
        self.cancel_authorize
            .as_ref()
            .is_some_and(|authorize| authorize().is_ok())
    }

    fn refuse_cancel(&self) {
        let mut event = self.event("client_refused").warn().code("reason", "cancel");
        if let Some(seq) = (self.audit_refusal)("cancel", CANCEL_REFUSED_REASON) {
            event = event.audit_seq(seq);
        }
        self.diag.emit(event);
    }

    #[cfg(test)]
    fn disabled() -> Self {
        Self {
            diag: DiagLog::disabled(),
            conn: 0,
            resource: String::new(),
            host: String::new(),
            port: 0,
            expected_user: None,
            audit_refusal: no_refusal_audit(),
            cancel_authorize: None,
        }
    }
}

fn no_refusal_audit() -> AuditRefusal {
    Arc::new(|_: &'static str, _: &'static str| None::<u64>)
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

#[derive(Clone)]
struct Upstream {
    endpoint: UpstreamEndpoint,
    tls: UpstreamTls,
    config: Arc<rustls::ClientConfig>,
}

impl Upstream {
    fn new(endpoint: UpstreamEndpoint, tls: UpstreamTls) -> std::io::Result<Self> {
        let config = zs_upstream::client_config(&tls).map_err(std::io::Error::other)?;
        Ok(Self {
            endpoint,
            tls,
            config,
        })
    }
}

struct TlsStop {
    kind: &'static str,
    reply: (&'static str, &'static str),
    error: std::io::Error,
}

impl TlsStop {
    fn refused(kind: &'static str) -> Self {
        Self {
            kind,
            reply: UPSTREAM_TLS_FAILED,
            error: std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "upstream TLS refused",
            ),
        }
    }

    fn io(error: std::io::Error) -> Self {
        Self {
            kind: zs_diag::io_kind(&error),
            reply: UPSTREAM_UNAVAILABLE,
            error,
        }
    }

    fn timed_out() -> Self {
        Self {
            kind: "timed_out",
            reply: UPSTREAM_UNAVAILABLE,
            error: std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream TLS negotiation timed out",
            ),
        }
    }
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(bytes).await?;
    stream.flush().await
}

async fn negotiate_within(
    tcp: TcpStream,
    upstream: &Upstream,
    deadline: tokio::time::Instant,
    trace: &Trace,
) -> std::result::Result<Box<dyn Io>, TlsStop> {
    let negotiated = match tokio::time::timeout_at(deadline, negotiate(tcp, upstream, trace)).await
    {
        Ok(negotiated) => negotiated,
        Err(_) => {
            trace.diag.emit(
                trace
                    .event("tls")
                    .warn()
                    .code("result", "failed")
                    .failure("timed_out"),
            );
            Err(TlsStop::timed_out())
        }
    };
    if let Err(stop) = &negotiated {
        trace.diag.emit(
            trace
                .event("upstream_failed")
                .warn()
                .code("stage", "tls")
                .failure(stop.kind),
        );
    }
    negotiated
}

async fn negotiate(
    mut tcp: TcpStream,
    upstream: &Upstream,
    trace: &Trace,
) -> std::result::Result<Box<dyn Io>, TlsStop> {
    let failed = |stop: TlsStop| {
        trace.diag.emit(
            trace
                .event("tls")
                .warn()
                .code("result", "failed")
                .failure(stop.kind),
        );
        stop
    };
    let mut answer = [0u8; 1];
    let exchanged = async {
        send(&mut tcp, &SSL_REQUEST_PACKET).await?;
        tcp.read_exact(&mut answer).await
    }
    .await;
    if let Err(error) = exchanged {
        return Err(failed(TlsStop::io(error)));
    }
    match answer[0] {
        b'N' if upstream.tls.required() => {
            trace
                .diag
                .emit(trace.event("tls").warn().code("result", "not_offered"));
            Err(TlsStop::refused("not_offered"))
        }
        b'N' => {
            trace
                .diag
                .emit(trace.event("tls").code("result", "not_offered"));
            Ok(Box::new(tcp))
        }
        b'S' => handshake(tcp, upstream, trace).await.map_err(failed),
        _ => Err(failed(TlsStop::refused("bad_answer"))),
    }
}

async fn handshake(
    tcp: TcpStream,
    upstream: &Upstream,
    trace: &Trace,
) -> std::result::Result<Box<dyn Io>, TlsStop> {
    let mut probe = [0u8; 1];
    match tcp.try_read(&mut probe) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(0) => {
            return Err(TlsStop::io(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            )));
        }
        Ok(_) => return Err(TlsStop::refused("extra_bytes")),
        Err(error) => return Err(TlsStop::io(error)),
    }
    let name = upstream
        .tls
        .server_name(upstream.endpoint.host())
        .map_err(|_| TlsStop::refused("bad_server_name"))?;
    let connector = tokio_rustls::TlsConnector::from(upstream.config.clone());
    match connector.connect(name, tcp).await {
        Ok(stream) => {
            let result = if upstream.tls.pinned() {
                "pinned"
            } else {
                "verified"
            };
            trace.diag.emit(trace.event("tls").code("result", result));
            Ok(Box::new(stream))
        }
        Err(error) => Err(TlsStop {
            kind: zs_diag::io_kind(&error),
            reply: UPSTREAM_TLS_FAILED,
            error,
        }),
    }
}

fn postgres_error_kind(error: &PostgresError) -> &'static str {
    match error {
        PostgresError::BadStartup => "bad_startup",
        PostgresError::BadFraming => "bad_framing",
        PostgresError::Scram(_) | PostgresError::UnsupportedMethod(_) => "scram",
        PostgresError::Unavailable(_) => "unavailable",
        PostgresError::Refused { .. } | PostgresError::AuthRefused { .. } => "refused",
    }
}

fn auth_method(code: u32) -> &'static str {
    match code {
        3 => "cleartext",
        5 => "md5",
        _ => "other",
    }
}

pub struct PostgresListener {
    listener: TcpListener,
    caller_check: Option<zs_protocol::CallerCheck>,
    upstream: Upstream,
    ssl: SslPolicy,
    materialize: Materialize,
    diag: DiagLog,
    resource: String,
    expected_user: Option<Arc<str>>,
    audit_refusal: AuditRefusal,
    cancel_authorize: Option<CancelAuthorize>,
}

impl PostgresListener {
    pub fn with_caller_check(mut self, check: zs_protocol::CallerCheck) -> Self {
        self.caller_check = Some(check);
        self
    }

    pub async fn bind(
        local: &str,
        upstream: SocketAddr,
        ssl: SslPolicy,
        materialize: Materialize,
    ) -> std::io::Result<Self> {
        let endpoint = UpstreamEndpoint::new(upstream.ip().to_string(), upstream.port())?;
        Self::bind_endpoint(local, endpoint, ssl, UpstreamTls::WhenOffered, materialize).await
    }

    pub async fn bind_endpoint(
        local: &str,
        upstream: UpstreamEndpoint,
        ssl: SslPolicy,
        tls: UpstreamTls,
        materialize: Materialize,
    ) -> std::io::Result<Self> {
        let upstream = Upstream::new(upstream, tls)?;
        Ok(Self {
            listener: TcpListener::bind(local).await?,
            caller_check: None,
            upstream,
            ssl,
            materialize,
            diag: DiagLog::disabled(),
            resource: String::new(),
            expected_user: None,
            audit_refusal: no_refusal_audit(),
            cancel_authorize: None,
        })
    }

    pub fn with_diag(mut self, diag: DiagLog, resource: &str) -> Self {
        self.diag = diag;
        self.resource = resource.to_string();
        self
    }

    pub fn with_expected_user(mut self, user: Option<String>) -> Self {
        self.expected_user = user.map(Arc::from);
        self
    }

    pub fn with_refusal_audit(mut self, audit: AuditRefusal) -> Self {
        self.audit_refusal = audit;
        self
    }

    pub fn with_cancel_authorize(mut self, authorize: CancelAuthorize) -> Self {
        self.cancel_authorize = Some(authorize);
        self
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    pub async fn serve(self) -> std::io::Result<()> {
        self.serve_with(|upstream: UpstreamEndpoint| async move { upstream.connect().await })
            .await
    }

    async fn serve_with<C, F>(self, connect: C) -> std::io::Result<()>
    where
        C: Fn(UpstreamEndpoint) -> F + Clone + Send + 'static,
        F: Future<Output = std::io::Result<TcpStream>> + Send + 'static,
    {
        loop {
            let (client, peer) = self.listener.accept().await?;
            let admitted = match (&self.caller_check, client.local_addr()) {
                (Some(check), Ok(local)) => {
                    let check = check.clone();
                    tokio::task::spawn_blocking(move || check(peer, local))
                        .await
                        .unwrap_or(false)
                }
                _ => false,
            };
            if !admitted {
                self.diag.emit(
                    Event::new(Component::Postgres, "caller_refused")
                        .conn(self.diag.next_conn())
                        .token("listener", "postgres"),
                );
                drop(client);
                continue;
            }
            let upstream = self.upstream.clone();
            let ssl = self.ssl;
            let materialize = self.materialize.clone();
            let connect = connect.clone();
            let trace = Trace {
                diag: self.diag.clone(),
                conn: self.diag.next_conn(),
                resource: self.resource.clone(),
                host: self.upstream.endpoint.host().to_string(),
                port: self.upstream.endpoint.port(),
                expected_user: self.expected_user.clone(),
                audit_refusal: self.audit_refusal.clone(),
                cancel_authorize: self.cancel_authorize.clone(),
            };
            tokio::spawn(async move {
                trace.diag.emit(trace.event("conn_accepted"));
                if let Err((stage, error)) = handle_connection(
                    client,
                    upstream,
                    ssl,
                    materialize,
                    connect,
                    HANDSHAKE_BUDGET,
                    &trace,
                )
                .await
                {
                    trace.diag.emit(
                        trace
                            .event("conn_failed")
                            .warn()
                            .code("stage", stage)
                            .failure(zs_diag::io_kind(&error)),
                    );
                }
            });
        }
    }
}

type Staged = (&'static str, std::io::Error);

fn at(stage: &'static str) -> impl FnOnce(std::io::Error) -> Staged {
    move |error| (stage, error)
}

async fn handle_connection<C, F>(
    mut client: TcpStream,
    target: Upstream,
    ssl: SslPolicy,
    materialize: Materialize,
    connect: C,
    budget: std::time::Duration,
    trace: &Trace,
) -> std::result::Result<(), Staged>
where
    C: FnOnce(UpstreamEndpoint) -> F,
    F: Future<Output = std::io::Result<TcpStream>>,
{
    let startup = match tokio::time::timeout(budget, read_startup(&mut client, ssl)).await {
        Ok(startup) => startup.map_err(at("startup"))?,
        Err(_) => {
            return Err((
                "startup",
                std::io::Error::new(std::io::ErrorKind::TimedOut, "client startup timed out"),
            ));
        }
    };
    let startup = match startup {
        Startup::Session(payload) => payload,
        Startup::Cancel(request) => {
            if !trace.cancel_authorized() {
                trace.refuse_cancel();
                return Ok(());
            }
            let deadline = tokio::time::Instant::now() + budget;
            let tcp = connect(target.endpoint.clone())
                .await
                .map_err(at("cancel"))?;
            let mut upstream = negotiate_within(tcp, &target, deadline, trace)
                .await
                .map_err(|stop| ("cancel", stop.error))?;
            send(&mut upstream, &request).await.map_err(at("cancel"))?;
            let _ = upstream.shutdown().await;
            return Ok(());
        }
        Startup::Closed => return Ok(()),
    };
    let refusal = startup_refusal(&startup, trace.expected_user.as_deref())
        .map_err(std::io::Error::other)
        .map_err(at("startup"))?;
    if let Some(reason) = refusal {
        let _ = client.write_all(&trace.refuse_startup(reason)).await;
        return Ok(());
    }

    let credential = match materialize() {
        Ok(credential) => {
            trace
                .diag
                .emit(trace.event("materialized").code("decision", "allow"));
            credential
        }
        Err(denied) => {
            trace.diag.emit(
                trace
                    .event("materialized")
                    .warn()
                    .code("decision", "deny")
                    .code("deny_kind", denied.kind().as_str()),
            );
            let _ = client.write_all(&error_response(&denied.reason)).await;
            return Ok(());
        }
    };

    let tcp = match connect(target.endpoint.clone()).await {
        Ok(tcp) => tcp,
        Err(error) => {
            trace.diag.emit(
                trace
                    .event("upstream_failed")
                    .warn()
                    .code("stage", "connect")
                    .failure(zs_diag::io_kind(&error)),
            );
            return refuse(&mut client, UPSTREAM_UNAVAILABLE, error)
                .await
                .map_err(at("connect"));
        }
    };
    trace.diag.emit(trace.event("upstream_connected"));
    let deadline = tokio::time::Instant::now() + budget;
    let mut upstream = match negotiate_within(tcp, &target, deadline, trace).await {
        Ok(stream) => stream,
        Err(stop) => {
            return refuse(&mut client, stop.reply, stop.error)
                .await
                .map_err(at("tls"));
        }
    };
    if let Err(error) = send(&mut upstream, &startup).await {
        trace.diag.emit(
            trace
                .event("upstream_failed")
                .warn()
                .code("stage", "write")
                .failure(zs_diag::io_kind(&error)),
        );
        return refuse(&mut client, UPSTREAM_UNAVAILABLE, error)
            .await
            .map_err(at("write"));
    }

    let authenticated =
        tokio::time::timeout_at(deadline, authenticate_upstream(&mut upstream, &credential)).await;
    let startup_tail = match authenticated {
        Ok(Ok(tail)) => {
            trace.diag.emit(
                trace
                    .event("upstream_auth_ok")
                    .code("mechanism", "scram_sha_256"),
            );
            tail
        }
        Err(_) => {
            trace.diag.emit(
                trace
                    .event("upstream_auth_failed")
                    .warn()
                    .failure("timed_out"),
            );
            let error = std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upstream authentication timed out",
            );
            return refuse(&mut client, UPSTREAM_UNAVAILABLE, error)
                .await
                .map_err(at("auth"));
        }
        Ok(Err(PostgresError::Refused {
            sqlstate,
            detail,
            message,
        })) => {
            trace.diag.emit(
                trace
                    .event("upstream_auth_failed")
                    .warn()
                    .token("sqlstate", &sqlstate)
                    .failure("refused")
                    .server_text(ServerText::new(&message, credential.expose())),
            );
            return refuse(
                &mut client,
                (sqlstate.as_str(), UPSTREAM_REFUSED),
                std::io::Error::other(detail),
            )
            .await
            .map_err(at("auth"));
        }
        Ok(Err(PostgresError::AuthRefused { sqlstate, message })) => {
            trace.diag.emit(
                trace
                    .event("upstream_auth_failed")
                    .warn()
                    .token("sqlstate", &sqlstate)
                    .failure("refused")
                    .server_text(ServerText::new(&message, credential.expose())),
            );
            let error = PostgresError::AuthRefused { sqlstate, message };
            return refuse(
                &mut client,
                UPSTREAM_AUTHENTICATION_FAILED,
                std::io::Error::other(error),
            )
            .await
            .map_err(at("auth"));
        }
        Ok(Err(PostgresError::UnsupportedMethod(code))) => {
            trace.diag.emit(
                trace
                    .event("upstream_auth_failed")
                    .warn()
                    .code("method", auth_method(code))
                    .failure("scram"),
            );
            let error = std::io::Error::other(PostgresError::UnsupportedMethod(code));
            return refuse(&mut client, UPSTREAM_AUTHENTICATION_FAILED, error)
                .await
                .map_err(at("auth"));
        }
        Ok(Err(error)) => {
            trace.diag.emit(
                trace
                    .event("upstream_auth_failed")
                    .warn()
                    .failure(postgres_error_kind(&error)),
            );
            let refusal = match error {
                PostgresError::Unavailable(_) | PostgresError::BadFraming => UPSTREAM_UNAVAILABLE,
                _ => UPSTREAM_AUTHENTICATION_FAILED,
            };
            return refuse(&mut client, refusal, std::io::Error::other(error))
                .await
                .map_err(at("auth"));
        }
    };

    client
        .write_all(&authentication_ok())
        .await
        .map_err(at("ready"))?;
    if !startup_tail.is_empty() {
        client.write_all(&startup_tail).await.map_err(at("ready"))?;
    }
    client
        .write_all(&ready_for_query())
        .await
        .map_err(at("ready"))?;

    let started = std::time::Instant::now();
    let relayed = relay(client, upstream, trace).await;
    trace.diag.emit(
        trace
            .event("conn_closed")
            .num("bytes_up", relayed.up)
            .num("bytes_down", relayed.down)
            .num("ms", started.elapsed().as_millis() as u64)
            .code("closed_by", relayed.closed_by),
    );
    match relayed.failure {
        Some(error) => Err(("relay", error)),
        None => Ok(()),
    }
}

const HANDSHAKE_BUDGET: std::time::Duration = std::time::Duration::from_secs(15);
const UPSTREAM_UNAVAILABLE: (&str, &str) = ("08006", "upstream unavailable");
const UPSTREAM_REFUSED: &str = "upstream refused the connection";
const UPSTREAM_AUTHENTICATION_FAILED: (&str, &str) = ("28000", "upstream authentication failed");
const UPSTREAM_TLS_FAILED: (&str, &str) = ("08006", "upstream TLS failed");
const USER_REFUSED: (&str, &str) = ("28000", "database user not allowed by the binding");
const REPLICATION_REFUSED: (&str, &str) = ("28000", "replication connections are refused");

async fn refuse(
    client: &mut TcpStream,
    (code, reason): (&str, &str),
    error: std::io::Error,
) -> std::io::Result<()> {
    let _ = client.write_all(&error_frame(code, reason)).await;
    Err(error)
}

const CANCEL_REQUEST: u32 = 80_877_102;
const SSL_REQUEST: u32 = 80_877_103;
const GSSENC_REQUEST: u32 = 80_877_104;
const SSL_REQUEST_PACKET: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

enum Startup {
    Session(Vec<u8>),
    Cancel(Vec<u8>),
    Closed,
}

async fn read_startup(client: &mut TcpStream, ssl: SslPolicy) -> std::io::Result<Startup> {
    let mut packet = read_client_packet(client)
        .await?
        .ok_or_else(|| std::io::Error::other("implausible startup length"))?;
    for _ in 0..2 {
        if !matches!(packet_code(&packet), SSL_REQUEST | GSSENC_REQUEST) {
            break;
        }
        match ssl {
            SslPolicy::RefuseOnLoopback => client.write_all(b"N").await?,
        }
        packet = match read_client_packet(client).await {
            Ok(Some(next)) => next,
            _ => return Ok(Startup::Closed),
        };
    }
    Ok(match packet_code(&packet) {
        CANCEL_REQUEST if packet.len() == 16 => Startup::Cancel(packet),
        SSL_REQUEST | GSSENC_REQUEST | CANCEL_REQUEST => Startup::Closed,
        _ => Startup::Session(packet),
    })
}

async fn read_client_packet(client: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    client.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if !(8..=1_000_000).contains(&len) {
        return Ok(None);
    }
    let mut packet = len_bytes.to_vec();
    packet.resize(len, 0);
    client.read_exact(&mut packet[4..]).await?;
    Ok(Some(packet))
}

fn packet_code(packet: &[u8]) -> u32 {
    u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]])
}

async fn authenticate_upstream<S: AsyncRead + AsyncWrite + Unpin>(
    upstream: &mut S,
    credential: &Credential,
) -> Result<Vec<u8>> {
    let (tag, body) = read_tagged(upstream).await?;
    if tag == b'R'
        && let Some((head, _)) = body.split_first_chunk::<4>()
        && u32::from_be_bytes(*head) != 10
    {
        return Err(PostgresError::UnsupportedMethod(u32::from_be_bytes(*head)));
    }
    let mechanisms = sasl_payload(tag, &body, 10)?;
    if !String::from_utf8_lossy(mechanisms).contains("SCRAM-SHA-256") {
        return Err(PostgresError::UnsupportedMethod(10));
    }

    let mut nonce = [0u8; 18];
    let (client_first, client_first_bare) = client_first_message(&mut nonce);
    let mechanism = b"SCRAM-SHA-256\0";
    let mut msg = b"p".to_vec();
    let payload_len = mechanism.len() + 4 + client_first.len();
    msg.extend_from_slice(&((4 + payload_len) as u32).to_be_bytes());
    msg.extend_from_slice(mechanism);
    msg.extend_from_slice(&(client_first.len() as u32).to_be_bytes());
    msg.extend_from_slice(client_first.as_bytes());
    send(upstream, &msg)
        .await
        .map_err(|e| PostgresError::Unavailable(e.to_string()))?;

    let (tag, body) = read_tagged(upstream).await?;
    let server_first = String::from_utf8_lossy(sasl_payload(tag, &body, 11)?).into_owned();

    let password =
        zeroize::Zeroizing::new(String::from_utf8_lossy(credential.expose()).into_owned());
    let exchange = tokio::task::spawn_blocking(move || {
        client_final_message(&password, &server_first, &client_first_bare)
    })
    .await
    .map_err(|_| PostgresError::Scram("scram derivation did not complete".into()))??;

    let final_message = format!(
        "{},p={}",
        exchange.client_final_without_proof, exchange.proof
    );
    let mut msg = b"p".to_vec();
    msg.extend_from_slice(&((4 + final_message.len()) as u32).to_be_bytes());
    msg.extend_from_slice(final_message.as_bytes());
    send(upstream, &msg)
        .await
        .map_err(|e| PostgresError::Unavailable(e.to_string()))?;

    let (tag, final_body) = read_tagged(upstream).await?;
    let server_sig_text = String::from_utf8_lossy(sasl_payload(tag, &final_body, 12)?);
    let server_sig_b64 = server_sig_text
        .strip_prefix("v=")
        .ok_or_else(|| PostgresError::Scram("server final missing v= prefix".into()))?;
    let server_sig = base64::engine::general_purpose::STANDARD
        .decode(server_sig_b64)
        .map_err(|_| PostgresError::Scram("server signature is not valid base64".into()))?;
    if server_sig.len() != exchange.expected_server_signature.len()
        || server_sig
            .iter()
            .zip(exchange.expected_server_signature.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            != 0
    {
        return Err(PostgresError::Scram(
            "upstream server signature does not match".into(),
        ));
    }

    // SASLFinal is not the end: drain the rest of startup here, or the client sees a second auth sequence.
    let mut forward = Vec::new();
    loop {
        let (tag, body) = read_tagged(upstream).await?;
        match tag {
            b'R' => {}
            b'S' | b'K' => {
                if forward.len() + body.len() + 5 > MAX_FORWARDED_STARTUP {
                    return Err(PostgresError::BadFraming);
                }
                forward.push(tag);
                forward.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
                forward.extend_from_slice(&body);
            }
            b'Z' => break,
            b'E' => {
                return Err(upstream_refusal(
                    "upstream refused the connection after authentication",
                    &body,
                ));
            }
            _ => {}
        }
    }
    Ok(forward)
}

const MAX_FORWARDED_STARTUP: usize = 1_000_000;

fn error_message(body: &[u8]) -> String {
    body.split(|b| *b == 0)
        .find_map(|field| field.strip_prefix(b"M"))
        .map(|message| String::from_utf8_lossy(message).into_owned())
        .unwrap_or_default()
}

fn upstream_refusal(context: &str, body: &[u8]) -> PostgresError {
    let text = format!(
        "{context}: {}",
        String::from_utf8_lossy(body).replace('\0', " ").trim()
    );
    let sqlstate = body
        .split(|b| *b == 0)
        .find_map(|field| field.strip_prefix(b"C"))
        .filter(|code| {
            code.len() == 5
                && code
                    .iter()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
        });
    match sqlstate {
        Some(code) if code.starts_with(b"28") => PostgresError::AuthRefused {
            sqlstate: String::from_utf8_lossy(code).into_owned(),
            message: error_message(body),
        },
        Some(code) if ![&b"08"[..], b"53", b"57"].contains(&&code[..2]) => PostgresError::Refused {
            sqlstate: String::from_utf8_lossy(code).into_owned(),
            detail: text,
            message: error_message(body),
        },
        _ => PostgresError::Unavailable(text),
    }
}

fn sasl_payload(tag: u8, body: &[u8], subtype: u32) -> Result<&[u8]> {
    if tag == b'E' {
        return Err(upstream_refusal("upstream refused authentication", body));
    }
    if tag != b'R' {
        return Err(PostgresError::Scram(format!(
            "expected authentication request, got tag {}",
            tag as char
        )));
    }
    let (head, payload) = body
        .split_first_chunk::<4>()
        .ok_or_else(|| PostgresError::Scram("truncated authentication request".into()))?;
    let actual = u32::from_be_bytes(*head);
    if actual != subtype {
        return Err(PostgresError::Scram(format!(
            "upstream sent auth type {actual}, expected {subtype}; v1 supports SCRAM-SHA-256 only"
        )));
    }
    Ok(payload)
}

async fn read_tagged<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u8, Vec<u8>)> {
    let mut tag = [0u8; 1];
    stream
        .read_exact(&mut tag)
        .await
        .map_err(|e| PostgresError::Unavailable(e.to_string()))?;
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .map_err(|e| PostgresError::Unavailable(e.to_string()))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if !(4..=1_000_000).contains(&len) {
        return Err(PostgresError::BadFraming);
    }
    let mut body = vec![0u8; len - 4];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| PostgresError::Unavailable(e.to_string()))?;
    Ok((tag[0], body))
}

struct Relayed {
    up: u64,
    down: u64,
    closed_by: &'static str,
    failure: Option<std::io::Error>,
}

type Copied = std::result::Result<std::io::Result<u64>, tokio::task::JoinError>;

fn counted(joined: Copied, counter: &AtomicU64) -> std::io::Result<u64> {
    match joined {
        Ok(result) => result,
        Err(joined) if joined.is_cancelled() => Ok(counter.load(Ordering::Relaxed)),
        Err(joined) => Err(std::io::Error::other(joined)),
    }
}

async fn relay(client: TcpStream, upstream: Box<dyn Io>, trace: &Trace) -> Relayed {
    let (client_read, client_write) = client.into_split();
    let (upstream_read, upstream_write) = tokio::io::split(upstream);
    let up_bytes = Arc::new(AtomicU64::new(0));
    let down_bytes = Arc::new(AtomicU64::new(0));
    let (up_count, down_count) = (up_bytes.clone(), down_bytes.clone());
    let frontend_trace = trace.clone();
    let mut to_upstream = tokio::spawn(async move {
        copy_frontend(client_read, upstream_write, &up_count, &frontend_trace).await
    });
    let mut to_client =
        tokio::spawn(async move { copy_backend(upstream_read, client_write, &down_count).await });
    let first = tokio::select! {
        up = &mut to_upstream => First::Up(up),
        down = &mut to_client => First::Down(down),
    };
    let (closed_by, up, down) = match first {
        First::Up(up) => {
            to_client.abort();
            ("client", up, to_client.await)
        }
        First::Down(down) => {
            to_upstream.abort();
            ("upstream", to_upstream.await, down)
        }
    };
    let (up, down) = (counted(up, &up_bytes), counted(down, &down_bytes));
    let bytes = |copied: &std::io::Result<u64>| copied.as_ref().map_or(0, |n| *n);
    Relayed {
        up: bytes(&up),
        down: bytes(&down),
        closed_by,
        failure: up.err().or(down.err()),
    }
}

enum First {
    Up(Copied),
    Down(Copied),
}

const MAX_FRONTEND_MESSAGE: u32 = i32::MAX as u32;

async fn copy_frontend<R, W>(
    mut reader: R,
    mut writer: W,
    counter: &AtomicU64,
    trace: &Trace,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut body = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let mut tag = [0u8; 1];
        if reader.read(&mut tag).await? == 0 {
            break;
        }
        let mut length = [0u8; 4];
        reader.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length);
        if !(4..=MAX_FRONTEND_MESSAGE).contains(&length) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad postgres message length",
            ));
        }
        if tag[0] == b'X' {
            trace.diag.emit(trace.event("client_terminate"));
        }
        writer.write_all(&tag).await?;
        writer.write_all(&length.to_be_bytes()).await?;
        total += 5;
        let mut remaining = length as usize - 4;
        while remaining > 0 {
            let chunk = remaining.min(body.len());
            reader.read_exact(&mut body[..chunk]).await?;
            writer.write_all(&body[..chunk]).await?;
            remaining -= chunk;
            total += chunk as u64;
        }
        writer.flush().await?;
        counter.store(total, Ordering::Relaxed);
        if tag[0] == b'X' {
            break;
        }
    }
    writer.shutdown().await?;
    Ok(total)
}

async fn copy_backend<R, W>(
    mut reader: R,
    mut writer: W,
    counter: &AtomicU64,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut body = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut body).await?;
        if read == 0 {
            break;
        }
        writer.write_all(&body[..read]).await?;
        total += read as u64;
        counter.store(total, Ordering::Relaxed);
    }
    writer.shutdown().await?;
    Ok(total)
}

pub fn authentication_ok() -> Vec<u8> {
    let mut msg = b"R".to_vec();
    msg.extend_from_slice(&8u32.to_be_bytes());
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg
}

pub fn ready_for_query() -> Vec<u8> {
    let mut msg = b"Z".to_vec();
    msg.extend_from_slice(&5u32.to_be_bytes());
    msg.push(b'I');
    msg
}

// The reason must never contain a credential
pub fn error_response(reason: &str) -> Vec<u8> {
    error_frame("28000", reason)
}

fn error_frame(code: &str, reason: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(b"FATAL\0");
    body.push(b'C');
    body.extend_from_slice(code.as_bytes());
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(reason.as_bytes());
    body.push(0);
    body.push(0);
    let mut msg = b"E".to_vec();
    msg.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    msg.extend_from_slice(&body);
    msg
}

pub fn startup_packet(user: &str, database: &str) -> Vec<u8> {
    let mut body = 196_608u32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(user.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(database.as_bytes());
    body.push(0);
    body.push(0);
    let mut packet = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    packet.extend_from_slice(&body);
    packet
}
