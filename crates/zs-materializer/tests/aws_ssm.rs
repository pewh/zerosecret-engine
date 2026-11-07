#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zs_credential::{Credential, IdentityToken};
use zs_grant::{AgentVerifier, ControlSigningKey, Grant, VerifiedGrant};
use zs_materializer::aws_ssm::{SsmStore, role_session_name};
use zs_materializer::{CredentialStore, GrantBoundCache, MaterializationError, RetrieveContext};
use zs_policy::{AwsRegion, AwsSsmSource, CredentialSource, RoleArn, SourceKind, SsmParameter};
use zs_test_aws::{
    DEFAULT_ISSUER, Failure, FakeAws, FakeAwsOptions, ParameterKind, TestCa, TestIssuer, TrustRule,
};
use zs_upstream::TransportKind;

const ROLE_ARN: &str = "arn:aws:iam::111122223333:role/zs/app-staging";
const RESOURCE: &str = "app-mysql";
const OTHER_RESOURCE: &str = "app-mongo";
const SUB: &str = "zs:acme:app:app-mysql";
const OTHER_SUB: &str = "zs:acme:app:app-mongo";
const SUBJECT: &str = "alice@company.com";
const DB: &str = "/app/staging/DB_PASSWORD";
const DB_VALUE: &str = "fake-db-pass-4f1c";
const MONGO: &str = "/app/staging/MONGO_PASSWORD";
const HOST_PARAM: &str = "/app/staging/DB_HOST";
const LIST: &str = "/app/staging/HOSTS";
const EMPTY: &str = "/app/staging/EMPTY";

struct H {
    aws: FakeAws,
    issuer: TestIssuer,
    key: ControlSigningKey,
    cache: GrantBoundCache<SsmStore>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn harness() -> H {
    harness_with(Duration::from_secs(5))
}

fn harness_with(timeout: Duration) -> H {
    let issuer = TestIssuer::new(DEFAULT_ISSUER);
    let aws = FakeAws::start(FakeAwsOptions::new(
        &issuer,
        vec![
            TrustRule::new(ROLE_ARN, SUB),
            TrustRule {
                sub: OTHER_SUB.to_string(),
                ..TrustRule::new("arn:aws:iam::111122223333:role/zs/app-mongo", OTHER_SUB)
            },
        ],
    ));
    aws.put_parameter(DB, DB_VALUE, ParameterKind::SecureString);
    aws.put_parameter(MONGO, "fake-mongo-pass-77aa", ParameterKind::SecureString);
    aws.put_parameter(HOST_PARAM, "db.internal", ParameterKind::String);
    aws.put_parameter(LIST, "a.internal,b.internal", ParameterKind::StringList);
    aws.put_parameter(EMPTY, "", ParameterKind::String);
    let cache = GrantBoundCache::new(SsmStore::with_timeout(aws.network(), timeout).unwrap());
    H {
        aws,
        issuer,
        key: ControlSigningKey::generate("k1"),
        cache,
    }
}

fn source(role_arn: &str, parameter: &str) -> CredentialSource {
    CredentialSource::AwsSsm(AwsSsmSource {
        role_arn: RoleArn::parse(role_arn).unwrap(),
        region: AwsRegion::parse("ap-southeast-1").unwrap(),
        parameter: SsmParameter::parse(parameter).unwrap(),
    })
}

fn verified_for(
    h: &H,
    resource: &str,
    source: CredentialSource,
    subject: &str,
    grant_id: &str,
    expires_at_ms: u64,
) -> VerifiedGrant {
    let signed = h
        .key
        .sign(Grant {
            subject: subject.into(),
            workload: "claude-code".into(),
            resource: resource.into(),
            host: "mysql.app.internal".into(),
            protocol: "mysql".into(),
            source,
            operations: vec!["connect".into()],
            environment: "development".into(),
            expires_at_ms,
            grant_id: grant_id.into(),
            materialization: zs_policy::Materialization::Retrieve,
            upstream_host: "mysql.app.internal".into(),
            upstream_port: 3306,
            upstream_tls: zs_policy::UpstreamTlsMode::Default,
            local_endpoint: false,
            version: zs_grant::GRANT_VERSION,
        })
        .unwrap();
    AgentVerifier::new(vec![(
        h.key.key_id().to_string(),
        ed25519_dalek::VerifyingKey::from_bytes(&h.key.verifying_key_bytes()).unwrap(),
    )])
    .verify(
        &signed,
        0,
        &zs_grant::VerifyContext {
            subject,
            workload: "claude-code",
            resource,
            operation: "connect",
            environment: None,
        },
    )
    .unwrap()
}

fn verified(h: &H, parameter: &str, grant_id: &str, expires_at_ms: u64) -> VerifiedGrant {
    verified_for(
        h,
        RESOURCE,
        source(ROLE_ARN, parameter),
        SUBJECT,
        grant_id,
        expires_at_ms,
    )
}

fn token(h: &H, sub: &str, exp_ms: u64) -> IdentityToken {
    IdentityToken::from_string(h.issuer.token(sub, "g-1", exp_ms / 1000))
}

fn in_5_min_ms() -> u64 {
    now_ms() + 300_000
}

async fn fetch(
    store: &dyn CredentialStore,
    grant: &VerifiedGrant,
    token: Option<&IdentityToken>,
    now_ms: u64,
) -> Result<Credential, MaterializationError> {
    store
        .retrieve(&RetrieveContext {
            grant,
            identity_token: token,
            now_ms,
        })
        .await
}

async fn happy(h: &H) -> Result<Credential, MaterializationError> {
    let exp = in_5_min_ms();
    let t = token(h, SUB, exp);
    fetch(&h.cache, &verified(h, DB, "g-1", exp), Some(&t), now_ms()).await
}

fn assert_clean(h: &H, error: &MaterializationError, token: Option<&IdentityToken>) {
    let text = error.to_string();
    let mut secrets = h.aws.secrets();
    if let Some(token) = token {
        secrets.push(token.expose().to_string());
        secrets.push(token.expose().rsplit('.').next().unwrap().to_string());
    }
    for secret in secrets {
        assert!(!text.contains(&secret), "a denial leaked a secret: {text}");
    }
    assert!(!text.contains(ROLE_ARN), "{text}");
    assert!(!text.contains("/app/staging/"), "{text}");
}

fn refused_code(error: &MaterializationError) -> (&'static str, String) {
    match error {
        MaterializationError::Refused { kind, step, code } => {
            assert_eq!(*kind, SourceKind::AwsSsm);
            (step, code.clone())
        }
        other => panic!("expected a refusal, got {other}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s01_happy_path_token_sts_session_ssm_value() {
    let h = harness();
    let value = happy(&h).await.unwrap();
    assert_eq!(value.expose(), DB_VALUE.as_bytes());
    let form = h.aws.last_sts_form();
    let get = |k: &str| {
        form.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    let CredentialSource::AwsSsm(db) = source(ROLE_ARN, DB) else {
        unreachable!()
    };
    assert_eq!(get("Action"), "AssumeRoleWithWebIdentity");
    assert_eq!(get("Version"), "2011-06-15");
    assert_eq!(get("RoleArn"), ROLE_ARN);
    assert_eq!(get("DurationSeconds"), "900");
    assert_eq!(get("Policy"), zs_policy::aws_ssm_session_policy(&db));
    assert_eq!(get("RoleSessionName"), SUBJECT);
    assert_eq!((h.aws.sts_ok(), h.aws.ssm_ok()), (1, 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn s03_sts_refusals_are_typed_and_leave_no_session() {
    let h = harness();
    happy(&h).await.unwrap();
    let exp = in_5_min_ms();
    let stranger = TestIssuer::new(DEFAULT_ISSUER);
    let other_issuer = TestIssuer::new("https://other.zs.test");
    let real = h.issuer.token(OTHER_SUB, "g", exp / 1000);
    let good = h.issuer.token(SUB, "g", exp / 1000);
    let r: Vec<&str> = real.split('.').collect();
    let g: Vec<&str> = good.split('.').collect();
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "wrong aud",
            h.issuer.sign(&serde_json::json!({
                "iss": DEFAULT_ISSUER, "aud": "zerosecret", "sub": SUB,
                "jti": "g", "iat": now_ms() / 1000, "exp": exp / 1000,
            })),
            "InvalidIdentityToken",
        ),
        ("wrong sub", real.clone(), "AccessDenied"),
        (
            "expired",
            h.issuer.token(SUB, "g", now_ms() / 1000 - 120),
            "ExpiredTokenException",
        ),
        (
            "unregistered issuer",
            other_issuer.token(SUB, "g", exp / 1000),
            "InvalidIdentityToken",
        ),
        (
            "key not in JWKS",
            stranger.token(SUB, "g", exp / 1000),
            "InvalidIdentityToken",
        ),
        (
            "payload swapped",
            format!("{}.{}.{}", r[0], g[1], r[2]),
            "InvalidIdentityToken",
        ),
    ];
    for (n, (name, raw, code)) in cases.into_iter().enumerate() {
        let token = IdentityToken::from_string(raw);
        let before = h.aws.ssm_calls();
        let grant = verified(&h, DB, &format!("g-refused-{n}"), exp);
        h.cache.inner().forget(RESOURCE);
        let error = fetch(h.cache.inner(), &grant, Some(&token), now_ms())
            .await
            .err()
            .unwrap_or_else(|| panic!("{name} must be refused"));
        assert_eq!(refused_code(&error), ("sts", code.to_string()), "{name}");
        assert_eq!(error.to_string(), "materialization failed: aws_ssm refused");
        assert_eq!(h.cache.inner().session_count(), 0, "{name}");
        assert_eq!(h.aws.ssm_calls(), before, "{name}: no SSM call");
        assert_clean(&h, &error, Some(&token));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s04_the_session_policy_names_only_the_granted_parameter() {
    let h = harness();
    happy(&h).await.unwrap();
    let form = h.aws.last_sts_form();
    let policy: serde_json::Value = serde_json::from_str(
        &form
            .iter()
            .find(|(n, _)| n == "Policy")
            .map(|(_, v)| v.clone())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        policy["Statement"][0]["Resource"],
        "arn:aws:ssm:ap-southeast-1:111122223333:parameter/app/staging/DB_PASSWORD"
    );
    let exp = in_5_min_ms();
    let t = token(&h, SUB, exp);
    let mongo = fetch(
        &h.cache,
        &verified(&h, MONGO, "g-2", exp),
        Some(&t),
        now_ms(),
    )
    .await
    .unwrap();
    assert_eq!(mongo.expose(), b"fake-mongo-pass-77aa");
    assert_eq!(
        h.aws.sts_ok(),
        2,
        "a source naming another parameter gets its own session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s06_ssm_not_found_string_list_and_empty_are_refused() {
    let h = harness();
    happy(&h).await.unwrap();
    let exp = in_5_min_ms();
    let t = token(&h, SUB, exp);
    let host = fetch(
        &h.cache,
        &verified(&h, HOST_PARAM, "g-host", exp),
        Some(&t),
        now_ms(),
    )
    .await;
    assert_eq!(host.unwrap().expose(), b"db.internal", "positive control");
    let missing = fetch(
        &h.cache,
        &verified(&h, "/app/staging/NOPE", "g-nope", exp),
        Some(&t),
        now_ms(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        refused_code(&missing),
        ("ssm", "ParameterNotFound".to_string())
    );
    assert_clean(&h, &missing, Some(&t));
    for (n, parameter) in [LIST, EMPTY].into_iter().enumerate() {
        let error = fetch(
            &h.cache,
            &verified(&h, parameter, &format!("g-bad-{n}"), exp),
            Some(&t),
            now_ms(),
        )
        .await
        .err()
        .unwrap();
        assert!(
            matches!(
                error,
                MaterializationError::InvalidValue(SourceKind::AwsSsm)
            ),
            "{parameter}: {error}"
        );
        assert_eq!(
            error.to_string(),
            "materialization failed: aws_ssm returned an unusable value"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s07_role_session_name_is_sanitized() {
    let h = harness();
    let exp = in_5_min_ms();
    let t = token(&h, SUB, exp);
    let long = format!("{}@acme.test", "a".repeat(70));
    for (n, subject) in [
        "alice@acme.test",
        "team/alice smith",
        long.as_str(),
        "x",
        "zoë+ops@acme.test",
    ]
    .into_iter()
    .enumerate()
    {
        let name = role_session_name(subject);
        assert!(
            (2..=64).contains(&name.len())
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"+=,.@-".contains(&c)),
            "{subject} -> {name}"
        );
        h.cache.forget(RESOURCE);
        let grant = verified_for(
            &h,
            RESOURCE,
            source(ROLE_ARN, DB),
            subject,
            &format!("g-name-{n}"),
            exp,
        );
        fetch(&h.cache, &grant, Some(&t), now_ms())
            .await
            .unwrap_or_else(|e| panic!("{subject}: {e}"));
        let sent = h
            .aws
            .last_sts_form()
            .into_iter()
            .find(|(k, _)| k == "RoleSessionName")
            .unwrap()
            .1;
        assert_eq!(sent, name);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s10_no_identity_token_is_denied_without_calling_aws() {
    let h = harness();
    happy(&h).await.unwrap();
    h.cache.forget(RESOURCE);
    let before = h.aws.sts_calls();
    let error = fetch(
        &h.cache,
        &verified(&h, DB, "g-2", in_5_min_ms()),
        None,
        now_ms(),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(error, MaterializationError::NoIdentityToken));
    assert_eq!(
        error.to_string(),
        "materialization failed: no identity token"
    );
    assert_eq!(h.aws.sts_calls(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn s11_sts_slow_is_denied_at_the_d5_timeout() {
    let h = harness();
    happy(&h).await.unwrap();
    h.cache.forget(RESOURCE);
    h.aws.set_delay(Some(Duration::from_secs(7)));
    let started = Instant::now();
    let error = fetch(
        &h.cache,
        &verified(&h, DB, "g-2", in_5_min_ms()),
        Some(&token(&h, SUB, in_5_min_ms())),
        now_ms(),
    )
    .await
    .err()
    .unwrap();
    let elapsed = started.elapsed();
    assert!(
        matches!(
            error,
            MaterializationError::Transport {
                transport: TransportKind::TimedOut,
                step: "sts",
                ..
            }
        ),
        "{error}"
    );
    assert_eq!(
        error.to_string(),
        "materialization failed: aws_ssm timed out"
    );
    assert!(
        elapsed >= Duration::from_secs(5) && elapsed < Duration::from_secs(7),
        "{elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s11_sts_unreachable_is_denied() {
    let h = harness();
    happy(&h).await.unwrap();
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut network = h.aws.network();
    network.resolve[0].1 = closed;
    let store = SsmStore::with_timeout(network, Duration::from_secs(2)).unwrap();
    let error = fetch(
        &store,
        &verified(&h, DB, "g-2", in_5_min_ms()),
        Some(&token(&h, SUB, in_5_min_ms())),
        now_ms(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        "materialization failed: aws_ssm unreachable"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_failure_reads_tls_refused_not_unreachable() {
    let h = harness();
    happy(&h).await.unwrap();
    let mut network = h.aws.network();
    network.extra_roots = vec![TestCa::new().root_der()];
    let store = SsmStore::with_timeout(network, Duration::from_secs(2)).unwrap();
    let error = fetch(
        &store,
        &verified(&h, DB, "g-2", in_5_min_ms()),
        Some(&token(&h, SUB, in_5_min_ms())),
        now_ms(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        error.to_string(),
        "materialization failed: aws_ssm tls refused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s12_session_expiry_refresh_and_refresh_failure() {
    let h = harness();
    h.aws.set_max_skew(3600);
    let store = h.cache.inner();
    let t0 = now_ms();
    let t = token(&h, SUB, t0 + 3_600_000);
    let grant = verified(&h, DB, "g-1", t0 + 3_600_000);
    fetch(store, &grant, Some(&t), t0).await.unwrap();
    assert_eq!(h.aws.sts_ok(), 1);

    h.aws.expire_sessions();
    fetch(store, &grant, Some(&t), t0).await.unwrap();
    assert_eq!(h.aws.sts_ok(), 2, "a server-side expiry refreshes once");

    h.aws.expire_sessions();
    h.aws.set_failure(Some(Failure::StsRefuse {
        status: 400,
        code: "IDPCommunicationError".to_string(),
    }));
    let error = fetch(store, &grant, Some(&t), t0).await.err().unwrap();
    assert_eq!(
        refused_code(&error),
        ("sts", "IDPCommunicationError".to_string())
    );
    assert_eq!(
        store.session_count(),
        0,
        "a failed refresh drops the session"
    );
    assert_clean(&h, &error, Some(&t));

    h.aws.set_failure(None);
    fetch(store, &grant, Some(&t), t0).await.unwrap();
    let before = h.aws.sts_ok();
    fetch(store, &grant, Some(&t), t0 + 845_000).await.unwrap();
    assert_eq!(
        h.aws.sts_ok(),
        before + 1,
        "a session within 60 s of its expiry is replaced before use"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s13_cache_lifetimes_revocation_and_source_change() {
    let h = harness();
    let exp = in_5_min_ms();
    let t = token(&h, SUB, exp);
    let g1 = verified(&h, DB, "g-1", exp);
    fetch(&h.cache, &g1, Some(&t), now_ms()).await.unwrap();
    let snap = || (h.aws.sts_calls(), h.aws.ssm_calls());
    let s0 = snap();
    fetch(&h.cache, &g1, Some(&t), now_ms()).await.unwrap();
    assert_eq!(snap(), s0, "a warm read makes no AWS call");

    let g2 = verified(&h, DB, "g-2", exp + 300_000);
    fetch(&h.cache, &g2, Some(&t), now_ms()).await.unwrap();
    let s1 = snap();
    assert_eq!(
        (s1.0 - s0.0, s1.1 - s0.1),
        (0, 1),
        "renewal: SSM again, session reused"
    );

    let g3 = verified(&h, HOST_PARAM, "g-3", exp);
    fetch(&h.cache, &g3, Some(&t), now_ms()).await.unwrap();
    let s2 = snap();
    assert_eq!(
        (s2.0 - s1.0, s2.1 - s1.1),
        (1, 1),
        "a source change needs a new session"
    );

    h.cache.forget(RESOURCE);
    assert_eq!(h.cache.inner().session_count(), 0);
    assert_eq!(h.cache.entry_count(), 0);
    let error = fetch(&h.cache, &g3, None, now_ms()).await.err().unwrap();
    assert!(matches!(error, MaterializationError::NoIdentityToken));
}

#[tokio::test(flavor = "multi_thread")]
async fn s14_garbage_sts_answers_are_refused() {
    let h = harness();
    happy(&h).await.unwrap();
    let ok = r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <SessionToken>AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp+IEXAMPLE</SessionToken>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <Expiration>2099-10-24T23:00:23Z</Expiration>
      <AccessKeyId>ASgeIAIOSFODNN7EXAMPLE</AccessKeyId>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>"#;
    let garbage = [
        "<html>502 Bad Gateway".to_string(),
        String::new(),
        ok.replace("<SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>", ""),
        ok.replace(
            "<AccessKeyId>ASgeIAIOSFODNN7EXAMPLE</AccessKeyId>",
            "<AccessKeyId>ASgeIAIOSFODNN7EXAMPLE</AccessKeyId><AccessKeyId>ASIAEVIL00000000000</AccessKeyId>",
        ),
        format!("<!DOCTYPE r [<!ENTITY x \"y\">]>{ok}"),
        ok.replace("<Credentials>", "<Credentials><!-- c -->"),
        ok.replace("2099-10-24T23:00:23Z", "<![CDATA[2099-10-24T23:00:23Z]]>"),
        ok.replace("</Credentials>", "</Credential>"),
        ok.replace("ASgeIAIOSFODNN7EXAMPLE", "ASgeIAIOSFODNN7&bogus;"),
        format!("{ok}<AssumeRoleWithWebIdentityResponse/>"),
        ok.replace("2099-10-24T23:00:23Z", "tomorrow"),
    ];
    let exp = in_5_min_ms();
    let t = token(&h, SUB, exp);
    for (n, doc) in garbage.iter().enumerate() {
        h.aws.set_failure(Some(Failure::StsGarbage(doc.clone())));
        h.cache.inner().forget(RESOURCE);
        let error = fetch(
            h.cache.inner(),
            &verified(&h, DB, &format!("g-garbage-{n}"), exp),
            Some(&t),
            now_ms(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(refused_code(&error).0, "sts", "{n}");
        assert_eq!(h.cache.inner().session_count(), 0, "{n}");
    }
    h.aws.set_failure(Some(Failure::StsGarbage(ok.to_string())));
    let accepted = fetch(
        h.cache.inner(),
        &verified(&h, DB, "g-well-formed", exp),
        Some(&t),
        now_ms(),
    )
    .await;
    assert!(
        !matches!(
            accepted,
            Err(MaterializationError::Refused { step: "sts", .. })
        ),
        "positive control: a well-formed answer passes the STS parser"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn s16_the_proxy_environment_is_ignored() {
    let h = harness();
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = proxy.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(socket);
        }
    });
    unsafe {
        std::env::set_var("HTTPS_PROXY", format!("http://{proxy_addr}"));
        std::env::set_var("ALL_PROXY", format!("http://{proxy_addr}"));
    }
    let store = SsmStore::with_timeout(h.aws.network(), Duration::from_secs(2)).unwrap();
    let exp = in_5_min_ms();
    let ok = fetch(
        &store,
        &verified(&h, DB, "g-1", exp),
        Some(&token(&h, SUB, exp)),
        now_ms(),
    )
    .await;
    let agent_hits = hits.load(std::sync::atomic::Ordering::SeqCst);
    let plain = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(h.aws.root_pem().as_bytes()).unwrap())
        .resolve(&h.aws.sts_host(), h.aws.sts_addr())
        .build()
        .unwrap();
    let _ = plain
        .post(format!("https://{}/", h.aws.sts_host()))
        .send()
        .await;
    let control_hits = hits.load(std::sync::atomic::Ordering::SeqCst) - agent_hits;
    unsafe {
        std::env::remove_var("HTTPS_PROXY");
        std::env::remove_var("ALL_PROXY");
    }
    assert!(ok.is_ok(), "{:?}", ok.err().map(|e| e.to_string()));
    assert_eq!(agent_hits, 0);
    assert!(
        control_hits > 0,
        "negative control: a default client obeys HTTPS_PROXY"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_first_use_calls_sts_and_ssm_once() {
    let h = harness();
    let exp = in_5_min_ms();
    let t = token(&h, SUB, exp);
    let grant = verified(&h, DB, "g-1", exp);
    let (a, b) = tokio::join!(
        fetch(&h.cache, &grant, Some(&t), now_ms()),
        fetch(&h.cache, &grant, Some(&t), now_ms())
    );
    assert_eq!(a.unwrap().expose(), DB_VALUE.as_bytes());
    assert_eq!(b.unwrap().expose(), DB_VALUE.as_bytes());
    assert_eq!((h.aws.sts_calls(), h.aws.ssm_calls()), (1, 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn renewal_with_the_same_source_refetches_once_under_the_new_grant() {
    let h = harness();
    let exp = in_5_min_ms();
    let t = token(&h, SUB, exp);
    let old = verified(&h, DB, "g-1", exp);
    fetch(&h.cache, &old, Some(&t), now_ms()).await.unwrap();
    fetch(&h.cache, &old, Some(&t), now_ms()).await.unwrap();
    assert_eq!(
        h.aws.ssm_calls(),
        1,
        "the old grant is served from the cache"
    );
    let renewed = verified(&h, DB, "g-2", exp + 300_000);
    fetch(&h.cache, &renewed, Some(&t), now_ms()).await.unwrap();
    fetch(&h.cache, &renewed, Some(&t), now_ms()).await.unwrap();
    assert_eq!(
        h.aws.ssm_calls(),
        2,
        "exactly one fresh fetch under the new grant"
    );
    assert_eq!(h.aws.sts_calls(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cache_never_serves_after_grant_expiry() {
    let h = harness();
    let now = now_ms();
    let exp = now + 120_000;
    let t = token(&h, SUB, exp);
    let grant = verified(&h, DB, "g-1", exp);
    fetch(&h.cache, &grant, Some(&t), now).await.unwrap();
    fetch(&h.cache, &grant, Some(&t), exp - 1).await.unwrap();
    assert_eq!(
        h.aws.ssm_calls(),
        1,
        "positive control: a hit before expiry"
    );
    fetch(&h.cache, &grant, Some(&t), exp).await.unwrap();
    assert_eq!(
        h.aws.ssm_calls(),
        2,
        "now_ms == expires_at_ms is a fresh fetch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cached_value_is_dropped_at_grant_expiry_without_another_read() {
    let h = harness();
    let now = now_ms();
    let t = token(&h, SUB, now + 600_000);
    let lasting = verified(&h, DB, "g-1", now + 60_000);
    fetch(&h.cache, &lasting, Some(&t), now).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    fetch(&h.cache, &lasting, Some(&t), now).await.unwrap();
    assert_eq!(
        h.aws.ssm_calls(),
        1,
        "positive control: a hit within the grant"
    );

    let short = verified(&h, DB, "g-2", now + 200);
    fetch(&h.cache, &short, Some(&t), now).await.unwrap();
    assert_eq!(h.aws.ssm_calls(), 2);
    tokio::time::sleep(Duration::from_millis(400)).await;
    fetch(&h.cache, &short, Some(&t), now).await.unwrap();
    assert_eq!(
        h.aws.ssm_calls(),
        3,
        "the value was dropped at expiry, not on the next read"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_that_expires_without_renewal_drops_its_session() {
    let h = harness();
    let now = now_ms();
    let short = now + 60_000;
    let first = verified(&h, DB, "g-1", short);
    fetch(&h.cache, &first, Some(&token(&h, SUB, short)), now)
        .await
        .unwrap();
    assert_eq!(h.cache.inner().session_count(), 1);
    assert_eq!(h.cache.entry_count(), 1);
    let long = now + 600_000;
    let other = verified_for(
        &h,
        OTHER_RESOURCE,
        source("arn:aws:iam::111122223333:role/zs/app-mongo", MONGO),
        SUBJECT,
        "g-9",
        long,
    );
    fetch(
        &h.cache,
        &other,
        Some(&token(&h, OTHER_SUB, long)),
        short + 1,
    )
    .await
    .unwrap();
    assert_eq!(
        h.cache.inner().session_count(),
        1,
        "only the live grant keeps a session"
    );
    assert_eq!(
        h.cache.entry_count(),
        1,
        "only the live grant keeps a value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_session_is_dropped_at_grant_expiry() {
    let h = harness();
    let now = now_ms();
    let long = now + 30_000;
    let lasting = verified_for(
        &h,
        OTHER_RESOURCE,
        source("arn:aws:iam::111122223333:role/zs/app-mongo", MONGO),
        SUBJECT,
        "g-lasting",
        long,
    );
    fetch(&h.cache, &lasting, Some(&token(&h, OTHER_SUB, long)), now)
        .await
        .unwrap();
    assert_eq!(h.cache.inner().session_count(), 1);

    let short = now + 400;
    let expiring = verified(&h, DB, "g-short", short);
    fetch(&h.cache, &expiring, Some(&token(&h, SUB, short)), now)
        .await
        .unwrap();
    assert_eq!(
        h.cache.inner().session_count(),
        2,
        "positive control: both grants keep a session before expiry"
    );

    tokio::time::sleep(Duration::from_millis(900)).await;

    assert_eq!(
        h.cache.inner().session_count(),
        1,
        "the session of the expired grant must be dropped without another read"
    );
    fetch(&h.cache, &lasting, Some(&token(&h, OTHER_SUB, long)), now)
        .await
        .unwrap();
    assert_eq!(
        h.aws.sts_calls(),
        2,
        "positive control: the live grant still reuses its session"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn kms_denied_is_refused_with_kind_aws_ssm() {
    let h = harness();
    happy(&h).await.unwrap();
    h.aws.set_failure(Some(Failure::KmsDenied));
    let exp = in_5_min_ms();
    let t = token(&h, SUB, exp);
    let error = fetch(&h.cache, &verified(&h, DB, "g-2", exp), Some(&t), now_ms())
        .await
        .err()
        .unwrap();
    assert_eq!(
        refused_code(&error),
        ("ssm", "AccessDeniedException".to_string())
    );
    assert!(h.aws.last_ssm_error().unwrap().contains("kms:Decrypt"));
    assert_clean(&h, &error, Some(&t));
}

#[tokio::test(flavor = "multi_thread")]
async fn denial_text_has_no_parameter_or_arn() {
    let h = harness();
    happy(&h).await.unwrap();
    let exp = in_5_min_ms();
    let t = token(&h, SUB, exp);
    let mut errors = Vec::new();
    for (n, fail) in [
        Some(Failure::StsRefuse {
            status: 403,
            code: "AccessDenied".to_string(),
        }),
        Some(Failure::SsmRefuse {
            code: "AccessDeniedException".to_string(),
        }),
        Some(Failure::KmsDenied),
        Some(Failure::StsGarbage("<x".to_string())),
    ]
    .into_iter()
    .enumerate()
    {
        h.cache.forget(RESOURCE);
        h.aws.set_failure(fail);
        errors.push(
            fetch(
                &h.cache,
                &verified(&h, DB, &format!("g-{n}"), exp),
                Some(&t),
                now_ms(),
            )
            .await
            .err()
            .unwrap(),
        );
    }
    h.aws.set_failure(None);
    errors.push(
        fetch(
            &h.cache,
            &verified(&h, "/app/staging/NOPE", "g-nope", exp),
            Some(&t),
            now_ms(),
        )
        .await
        .err()
        .unwrap(),
    );
    errors.push(
        fetch(
            &h.cache,
            &verified(&h, LIST, "g-list", exp),
            Some(&t),
            now_ms(),
        )
        .await
        .err()
        .unwrap(),
    );
    errors.push(
        fetch(&h.cache, &verified(&h, DB, "g-none", exp), None, now_ms())
            .await
            .err()
            .unwrap(),
    );
    assert_eq!(errors.len(), 7);
    for error in &errors {
        assert!(
            error.to_string().starts_with("materialization failed: "),
            "{error}"
        );
        assert_clean(&h, error, Some(&t));
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "latency measurement with no budget; CI runs it with --ignored"]
async fn s09_latency_cold_and_warm() {
    let h = harness();
    let n = 40;
    let pct = |v: &mut Vec<Duration>, p: f64| {
        v.sort();
        v[((v.len() as f64 - 1.0) * p).round() as usize]
    };
    let exp = now_ms() + 600_000;
    let t = token(&h, SUB, exp);
    let mut cold = Vec::new();
    for i in 0..n {
        h.cache.forget(RESOURCE);
        let grant = verified(&h, DB, &format!("g-cold-{i}"), exp);
        let started = Instant::now();
        fetch(&h.cache, &grant, Some(&t), now_ms()).await.unwrap();
        cold.push(started.elapsed());
    }
    let grant = verified(&h, DB, "g-warm", exp);
    fetch(&h.cache, &grant, Some(&t), now_ms()).await.unwrap();
    let calls = h.aws.sts_calls() + h.aws.ssm_calls();
    let mut warm = Vec::new();
    for _ in 0..(n * 25) {
        let started = Instant::now();
        fetch(&h.cache, &grant, Some(&t), now_ms()).await.unwrap();
        warm.push(started.elapsed());
    }
    assert_eq!(h.aws.sts_calls() + h.aws.ssm_calls(), calls);
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    eprintln!(
        "S09 profile={profile} cold n={} p50={:?} p99={:?}; warm n={} p50={:?} p99={:?}",
        cold.len(),
        pct(&mut cold, 0.5),
        pct(&mut cold, 0.99),
        warm.len(),
        pct(&mut warm, 0.5),
        pct(&mut warm, 0.99)
    );
}
