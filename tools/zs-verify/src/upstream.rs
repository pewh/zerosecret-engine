use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

pub(crate) const ERR_UPSTREAM: &str =
    "cannot start the fake upstream; refusing to report on a scan that cannot run";
pub(crate) const WRONG_CREDENTIAL: &str = "zs-verify-negative-control-wrong-credential";
const NEGATIVE_CONTROL_HEADER: &str = "X-Zs-Verify-Control: negative";
const NEGATIVE_CONTROL_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Default)]
pub(crate) struct FakeUpstreamState {
    pub(crate) requests: AtomicUsize,
    pub(crate) auth_ok: AtomicUsize,
    pub(crate) auth_mismatch: AtomicUsize,
    pub(crate) negative_control_rejected: AtomicUsize,
    control_open: AtomicBool,
}

#[derive(Clone)]
pub(crate) enum Expectation {
    AuthorizationHeader(zeroize::Zeroizing<String>),
    NamedHeader {
        header: String,
        value: zeroize::Zeroizing<String>,
    },
    QueryParam {
        param: String,
        value: zeroize::Zeroizing<String>,
    },
}

impl Expectation {
    fn satisfied_by(&self, head: &str) -> bool {
        match self {
            Expectation::AuthorizationHeader(value) => header_carries(head, "Authorization", value),
            Expectation::NamedHeader { header, value } => header_carries(head, header, value),
            Expectation::QueryParam { param, value } => head
                .lines()
                .next()
                .and_then(|request_line| request_line.split(' ').nth(1))
                .and_then(|target| target.split_once('?'))
                .is_some_and(|(_, query)| {
                    query
                        .split('&')
                        .any(|pair| pair.split_once('=') == Some((param.as_str(), value.as_str())))
                }),
        }
    }

    fn request_head(&self) -> String {
        match self {
            Expectation::AuthorizationHeader(value) => {
                format!(
                    "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: {}",
                    value.as_str()
                )
            }
            Expectation::NamedHeader { header, value } => {
                format!(
                    "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n{header}: {}",
                    value.as_str()
                )
            }
            Expectation::QueryParam { param, value } => {
                format!(
                    "GET /?{param}={} HTTP/1.1\r\nHost: 127.0.0.1",
                    value.as_str()
                )
            }
        }
    }
}

fn header_carries(head: &str, name: &str, value: &str) -> bool {
    head.lines().skip(1).any(|line| {
        line.split_once(':')
            .is_some_and(|(n, v)| n.eq_ignore_ascii_case(name) && v.trim() == value)
    })
}

fn is_negative_control(head: &str) -> bool {
    head.lines()
        .skip(1)
        .any(|l| l.eq_ignore_ascii_case(NEGATIVE_CONTROL_HEADER))
}

pub(crate) fn credential_expectation(policy_file: &str, credential: &str) -> Expectation {
    let bearer = || {
        Expectation::AuthorizationHeader(zeroize::Zeroizing::new(format!("Bearer {credential}")))
    };
    if policy_file.is_empty() {
        return bearer();
    }
    let Some(policy) = std::fs::read_to_string(policy_file)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
    else {
        return bearer();
    };
    let auth = ["bindings", "resources"]
        .iter()
        .filter_map(|key| policy.get(*key)?.as_array())
        .flatten()
        .find_map(|entry| entry.get("auth"));
    let Some(auth) = auth else { return bearer() };
    match auth.get("scheme").and_then(|s| s.as_str()) {
        Some("api_key_header") => match auth.get("header").and_then(|h| h.as_str()) {
            Some(header) => Expectation::NamedHeader {
                header: header.to_string(),
                value: zeroize::Zeroizing::new(credential.to_string()),
            },
            None => bearer(),
        },
        Some("query_param") => match auth.get("param").and_then(|p| p.as_str()) {
            Some(param) => Expectation::QueryParam {
                param: param.to_string(),
                value: zeroize::Zeroizing::new(credential.to_string()),
            },
            None => bearer(),
        },
        // `basic` stays on bearer: matching the header name alone would pass anything sent.
        _ => bearer(),
    }
}

pub(crate) fn bind() -> Result<(TcpListener, SocketAddr), &'static str> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| ERR_UPSTREAM)?;
    let addr = listener.local_addr().map_err(|_| ERR_UPSTREAM)?;
    Ok((listener, addr))
}

pub(crate) fn serve(
    listener: TcpListener,
    expected_auth: Expectation,
    state: Arc<FakeUpstreamState>,
) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let state = state.clone();
            let expected = expected_auth.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") || buf.len() > 65536 {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let marked = is_negative_control(&head);
                if marked && state.control_open.load(Ordering::SeqCst) {
                    if !expected.satisfied_by(&head) {
                        state
                            .negative_control_rejected
                            .fetch_add(1, Ordering::SeqCst);
                    }
                } else {
                    state.requests.fetch_add(1, Ordering::SeqCst);
                    if !marked && expected.satisfied_by(&head) {
                        state.auth_ok.fetch_add(1, Ordering::SeqCst);
                    } else {
                        state.auth_mismatch.fetch_add(1, Ordering::SeqCst);
                    }
                }
                let body = br#"{"ok":true}"#;
                let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n");
                let _ =
                    stream.write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            });
        }
    });
}

pub(crate) fn run_negative_control(
    addr: SocketAddr,
    policy_file: &str,
    state: &FakeUpstreamState,
) -> bool {
    state.control_open.store(true, Ordering::SeqCst);
    let rejected = probe_wrong_credential(addr, policy_file, state);
    state.control_open.store(false, Ordering::SeqCst);
    rejected
}

fn probe_wrong_credential(addr: SocketAddr, policy_file: &str, state: &FakeUpstreamState) -> bool {
    let probe = credential_expectation(policy_file, WRONG_CREDENTIAL).request_head();
    let before = state.negative_control_rejected.load(Ordering::SeqCst);
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, NEGATIVE_CONTROL_TIMEOUT) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(NEGATIVE_CONTROL_TIMEOUT))
        .is_err()
        || stream
            .write_all(format!("{probe}\r\n{NEGATIVE_CONTROL_HEADER}\r\n\r\n").as_bytes())
            .is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() || response.is_empty() {
        return false;
    }
    state.negative_control_rejected.load(Ordering::SeqCst) == before + 1
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const CRED: &str = "sk_test_value";

    fn head(request_line: &str, headers: &[&str]) -> String {
        let mut out = String::from(request_line);
        for h in headers {
            out.push_str("\r\n");
            out.push_str(h);
        }
        out
    }

    #[test]
    fn bearer_matches_only_the_authorization_header() {
        let e = Expectation::AuthorizationHeader(zeroize::Zeroizing::new(format!("Bearer {CRED}")));
        assert!(e.satisfied_by(&head(
            "GET /v1/x HTTP/1.1",
            &["Authorization: Bearer sk_test_value"]
        )));
        assert!(!e.satisfied_by(&head(
            "GET /v1/x HTTP/1.1",
            &["Authorization: Bearer wrong"]
        )));
        assert!(!e.satisfied_by(&head("GET /v1/x HTTP/1.1", &["X-Api-Key: sk_test_value"])));
    }

    #[test]
    fn a_credential_in_the_path_does_not_satisfy_a_header_expectation() {
        let e = Expectation::AuthorizationHeader(zeroize::Zeroizing::new(format!("Bearer {CRED}")));
        assert!(!e.satisfied_by(&head(
            "GET /v1/x?Authorization=Bearer%20sk_test_value HTTP/1.1",
            &["Host: api.example.com"]
        )));
    }

    #[test]
    fn a_named_header_is_matched_case_insensitively() {
        let e = Expectation::NamedHeader {
            header: "X-Api-Key".into(),
            value: CRED.to_string().into(),
        };
        assert!(e.satisfied_by(&head("GET /v1/x HTTP/1.1", &["X-Api-Key: sk_test_value"])));
        assert!(e.satisfied_by(&head("GET /v1/x HTTP/1.1", &["x-api-key: sk_test_value"])));
        assert!(!e.satisfied_by(&head("GET /v1/x HTTP/1.1", &["X-Api-Key: wrong"])));
        assert!(!e.satisfied_by(&head(
            "GET /v1/x HTTP/1.1",
            &["Authorization: Bearer sk_test_value"]
        )));
    }

    #[test]
    fn a_query_parameter_is_matched_on_the_request_line() {
        let e = Expectation::QueryParam {
            param: "api_key".into(),
            value: CRED.to_string().into(),
        };
        assert!(e.satisfied_by(&head(
            "GET /v1/x?api_key=sk_test_value HTTP/1.1",
            &["Host: api.example.com"]
        )));
        assert!(!e.satisfied_by(&head(
            "GET /v1/x?api_key=wrong HTTP/1.1",
            &["Host: api.example.com"]
        )));
        assert!(!e.satisfied_by(&head(
            "GET /v1/x HTTP/1.1",
            &["Authorization: Bearer sk_test_value"]
        )));
    }

    #[test]
    fn a_config_without_an_auth_block_expects_bearer() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.json");
        std::fs::write(
            &policy,
            r#"{"bindings":[{"resource":"r","host":"h","protocol":"https"}]}"#,
        )
        .unwrap();
        let e = credential_expectation(&policy.display().to_string(), CRED);
        assert!(e.satisfied_by(&head(
            "GET /v1/x HTTP/1.1",
            &["Authorization: Bearer sk_test_value"]
        )));
    }

    #[test]
    fn a_query_param_config_produces_a_query_param_expectation() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.json");
        std::fs::write(
            &policy,
            r#"{"bindings":[{"resource":"r","host":"h","protocol":"https","auth":{"scheme":"query_param","param":"api_key"}}]}"#,
        )
        .unwrap();
        let e = credential_expectation(&policy.display().to_string(), CRED);
        assert!(e.satisfied_by(&head(
            "GET /v1/x?api_key=sk_test_value HTTP/1.1",
            &["Host: h"]
        )));
        assert!(!e.satisfied_by(&head(
            "GET /v1/x HTTP/1.1",
            &["Authorization: Bearer sk_test_value"]
        )));
    }

    #[test]
    fn an_api_key_header_config_produces_a_named_header_expectation() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("p.json");
        std::fs::write(
            &policy,
            r#"{"bindings":[{"resource":"r","host":"h","protocol":"https","auth":{"scheme":"api_key_header","header":"X-Api-Key"}}]}"#,
        )
        .unwrap();
        let e = credential_expectation(&policy.display().to_string(), CRED);
        assert!(e.satisfied_by(&head("GET /v1/x HTTP/1.1", &["X-Api-Key: sk_test_value"])));
        assert!(!e.satisfied_by(&head(
            "GET /v1/x HTTP/1.1",
            &["Authorization: Bearer sk_test_value"]
        )));
    }

    fn start(policy: &str, credential: &str) -> (SocketAddr, Arc<FakeUpstreamState>) {
        let (listener, addr) = bind().unwrap();
        let state = Arc::new(FakeUpstreamState::default());
        serve(
            listener,
            credential_expectation(policy, credential),
            state.clone(),
        );
        (addr, state)
    }

    fn send(addr: SocketAddr, request: &str) {
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .write_all(format!("{request}\r\n\r\n").as_bytes())
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(!response.is_empty(), "the upstream answers every request");
    }

    fn counts(state: &FakeUpstreamState) -> [usize; 4] {
        [
            state.requests.load(Ordering::SeqCst),
            state.auth_ok.load(Ordering::SeqCst),
            state.auth_mismatch.load(Ordering::SeqCst),
            state.negative_control_rejected.load(Ordering::SeqCst),
        ]
    }

    #[test]
    fn negative_control_rejects_wrong_credential() {
        let (addr, state) = start("", CRED);
        assert!(
            run_negative_control(addr, "", &state),
            "the oracle must reject a wrong credential"
        );
        assert_eq!(state.negative_control_rejected.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_negative_control_is_not_product_activity() {
        let (addr, state) = start("", CRED);
        assert!(run_negative_control(addr, "", &state));
        assert_eq!(counts(&state), [0, 0, 0, 1]);
    }

    #[test]
    fn a_product_path_wrong_credential_is_a_mismatch_not_a_control() {
        let (addr, state) = start("", CRED);
        send(
            addr,
            &head("GET /v1/x HTTP/1.1", &["Authorization: Bearer wrong"]),
        );
        assert_eq!(counts(&state), [1, 0, 1, 0]);
    }

    #[test]
    fn a_product_path_right_credential_is_accepted() {
        let (addr, state) = start("", CRED);
        send(
            addr,
            &head(
                "GET /v1/x HTTP/1.1",
                &["Authorization: Bearer sk_test_value"],
            ),
        );
        assert_eq!(counts(&state), [1, 1, 0, 0]);
    }

    #[test]
    fn the_negative_control_carries_the_wrong_value_where_each_scheme_expects_it() {
        let dir = tempfile::tempdir().unwrap();
        let schemes = [
            r#"{"bindings":[{"resource":"r","host":"h","protocol":"https"}]}"#,
            r#"{"bindings":[{"resource":"r","host":"h","protocol":"https","auth":{"scheme":"api_key_header","header":"X-Api-Key"}}]}"#,
            r#"{"bindings":[{"resource":"r","host":"h","protocol":"https","auth":{"scheme":"query_param","param":"api_key"}}]}"#,
        ];
        for (index, scheme) in schemes.iter().enumerate() {
            let policy = dir.path().join(format!("p{index}.json"));
            std::fs::write(&policy, scheme).unwrap();
            let policy = policy.display().to_string();
            let probe = credential_expectation(&policy, WRONG_CREDENTIAL).request_head();
            assert!(
                credential_expectation(&policy, WRONG_CREDENTIAL).satisfied_by(&probe),
                "scheme {index}: the wrong value sits where the scheme reads"
            );
            assert!(!credential_expectation(&policy, CRED).satisfied_by(&probe));
            let (addr, state) = start(&policy, CRED);
            assert!(
                run_negative_control(addr, &policy, &state),
                "scheme {index}"
            );
            assert_eq!(counts(&state), [0, 0, 0, 1], "scheme {index}");
        }
    }

    #[test]
    fn an_oracle_that_accepts_the_control_value_fails_the_control() {
        let (addr, state) = start("", WRONG_CREDENTIAL);
        assert!(!run_negative_control(addr, "", &state));
        assert_eq!(counts(&state), [0, 0, 0, 0]);
    }

    #[test]
    fn a_credential_that_differs_only_in_case_is_a_mismatch() {
        let bearer =
            Expectation::AuthorizationHeader(zeroize::Zeroizing::new(format!("Bearer {CRED}")));
        assert!(bearer.satisfied_by(&head(
            "GET /v1/x HTTP/1.1",
            &["authorization: Bearer sk_test_value"]
        )));
        assert!(!bearer.satisfied_by(&head(
            "GET /v1/x HTTP/1.1",
            &["Authorization: Bearer SK_TEST_VALUE"]
        )));
        let named = Expectation::NamedHeader {
            header: "X-Api-Key".into(),
            value: CRED.to_string().into(),
        };
        assert!(!named.satisfied_by(&head("GET /v1/x HTTP/1.1", &["X-Api-Key: Sk_Test_Value"])));
        let query = Expectation::QueryParam {
            param: "api_key".into(),
            value: CRED.to_string().into(),
        };
        assert!(!query.satisfied_by(&head("GET /v1/x?api_key=SK_TEST_VALUE HTTP/1.1", &[])));
    }

    #[test]
    fn a_query_parameter_must_match_a_whole_pair() {
        let e = Expectation::QueryParam {
            param: "api_key".into(),
            value: CRED.to_string().into(),
        };
        assert!(e.satisfied_by(&head(
            "GET /v1/x?a=1&api_key=sk_test_value&b=2 HTTP/1.1",
            &[]
        )));
        for line in [
            "GET /v1/x?api_key=sk_test_valueX HTTP/1.1",
            "GET /v1/x?xapi_key=sk_test_value HTTP/1.1",
            "GET /v1/api_key=sk_test_value HTTP/1.1",
            "GET /v1/x#api_key=sk_test_value HTTP/1.1",
        ] {
            assert!(!e.satisfied_by(&head(line, &[])), "{line}");
        }
    }

    #[test]
    fn a_marker_request_after_the_control_is_a_product_mismatch() {
        let (addr, state) = start("", CRED);
        assert!(run_negative_control(addr, "", &state));
        send(
            addr,
            &head(
                "GET /v1/x HTTP/1.1",
                &["Authorization: Bearer wrong", NEGATIVE_CONTROL_HEADER],
            ),
        );
        assert_eq!(counts(&state), [1, 0, 1, 1]);
        send(
            addr,
            &head(
                "GET /v1/x HTTP/1.1",
                &[
                    "Authorization: Bearer sk_test_value",
                    NEGATIVE_CONTROL_HEADER,
                ],
            ),
        );
        assert_eq!(counts(&state), [2, 0, 2, 1]);
    }

    #[test]
    fn a_marker_request_before_any_control_is_a_product_mismatch() {
        let (addr, state) = start("", CRED);
        send(
            addr,
            &head(
                "GET /v1/x HTTP/1.1",
                &["Authorization: Bearer wrong", NEGATIVE_CONTROL_HEADER],
            ),
        );
        assert_eq!(counts(&state), [1, 0, 1, 0]);
    }

    #[test]
    fn a_negative_control_without_an_upstream_fails() {
        let (listener, addr) = bind().unwrap();
        drop(listener);
        let state = FakeUpstreamState::default();
        assert!(!run_negative_control(addr, "", &state));
    }
}
