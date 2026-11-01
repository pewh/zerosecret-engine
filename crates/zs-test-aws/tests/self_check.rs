#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, SystemTime};

use zs_proto_http::sigv4;
use zs_test_aws::{
    DEFAULT_ISSUER, Failure, FakeAws, FakeAwsOptions, ParameterKind, TestIssuer, TrustRule,
};
use zs_upstream::http::{ProxyPolicy, Roots};

const ROLE_ARN: &str = "arn:aws:iam::111122223333:role/zs-acme-db";
const SUB: &str = "zs:acme:app:acme-db";
const DB: &str = "/acme/prod/DB_PASSWORD";
const OTHER: &str = "/acme/prod/OTHER";

struct Session {
    akid: String,
    secret: String,
    token: String,
}

fn exp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 300
}

fn start(issuer: &TestIssuer) -> FakeAws {
    let aws = FakeAws::start(FakeAwsOptions::new(
        issuer,
        vec![TrustRule::new(ROLE_ARN, SUB)],
    ));
    aws.put_parameter(DB, "synthetic-db-value-1", ParameterKind::SecureString);
    aws.put_parameter(
        OTHER,
        "synthetic-other-value-2",
        ParameterKind::SecureString,
    );
    aws
}

fn client(aws: &FakeAws) -> reqwest::Client {
    zs_upstream::http::client(
        Roots::WebPki,
        Duration::from_secs(5),
        None,
        true,
        ProxyPolicy::None,
        &aws.network(),
    )
    .unwrap()
}

fn policy(parameter: &str) -> String {
    zs_policy::aws_ssm_session_policy(&zs_policy::AwsSsmSource {
        role_arn: zs_policy::RoleArn::parse(ROLE_ARN).unwrap(),
        region: zs_policy::AwsRegion::parse("ap-southeast-1").unwrap(),
        parameter: zs_policy::SsmParameter::parse(parameter).unwrap(),
    })
}

fn element(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

async fn assume_role(aws: &FakeAws, token: &str, parameter: &str) -> Result<Session, String> {
    let body: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("Action", "AssumeRoleWithWebIdentity")
        .append_pair("Version", "2011-06-15")
        .append_pair("RoleArn", ROLE_ARN)
        .append_pair("RoleSessionName", "alice-company.com")
        .append_pair("DurationSeconds", "900")
        .append_pair("Policy", &policy(parameter))
        .append_pair("WebIdentityToken", token)
        .finish();
    let response = client(aws)
        .post(format!("https://{}/", aws.sts_host()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    if status != 200 {
        return Err(element(&text, "Code").unwrap_or(text));
    }
    Ok(Session {
        akid: element(&text, "AccessKeyId").unwrap(),
        secret: element(&text, "SecretAccessKey").unwrap(),
        token: element(&text, "SessionToken").unwrap(),
    })
}

async fn get_parameter(
    aws: &FakeAws,
    session: &Session,
    name: &str,
    tamper: bool,
) -> Result<String, String> {
    let body = serde_json::json!({"Name": name, "WithDecryption": true}).to_string();
    let host = aws.ssm_host();
    let date = sigv4::amz_date(SystemTime::now());
    let headers = [
        ("content-type", "application/x-amz-json-1.1"),
        ("host", host.as_str()),
        ("x-amz-date", date.as_str()),
        ("x-amz-security-token", session.token.as_str()),
        ("x-amz-target", "AmazonSSM.GetParameter"),
    ];
    let signature = sigv4::sign(
        session.secret.as_bytes(),
        &date,
        &sigv4::Scope {
            access_key_id: &session.akid,
            region: aws.region(),
            service: "ssm",
        },
        &sigv4::Request {
            method: "POST",
            path: "/",
            query: sigv4::Query::Raw(""),
            headers: &headers,
            payload_sha256: &sigv4::payload_sha256(body.as_bytes()),
        },
    )
    .unwrap();
    let mut authorization = signature.authorization();
    if tamper {
        let last = authorization.pop().unwrap();
        authorization.push(if last == '0' { '1' } else { '0' });
    }
    let mut request = client(aws).post(format!("https://{host}/"));
    for (name, value) in headers.iter().filter(|(name, _)| *name != "host") {
        request = request.header(*name, *value);
    }
    let response = request
        .header("authorization", authorization)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let value: serde_json::Value = response.json().await.unwrap();
    if status != 200 {
        return Err(format!(
            "{}: {}",
            value["__type"].as_str().unwrap_or_default(),
            value["message"].as_str().unwrap_or_default()
        ));
    }
    Ok(value["Parameter"]["Value"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn fake_sts_refuses_a_token_signed_by_another_key() {
    let issuer = TestIssuer::new(DEFAULT_ISSUER);
    let aws = start(&issuer);

    let session = assume_role(&aws, &issuer.token(SUB, "g-1", exp()), DB).await;
    assert!(session.is_ok(), "positive control: {:?}", session.err());
    assert_eq!(aws.sts_ok(), 1);

    let stranger = TestIssuer::new(DEFAULT_ISSUER);
    let refused = assume_role(&aws, &stranger.token(SUB, "g-1", exp()), DB).await;
    assert_eq!(refused.err().as_deref(), Some("InvalidIdentityToken"));

    let wrong_sub = assume_role(&aws, &issuer.token("zs:acme:app:other", "g-1", exp()), DB).await;
    assert_eq!(wrong_sub.err().as_deref(), Some("AccessDenied"));
    assert_eq!(aws.sts_calls(), 3);
    assert_eq!(aws.sts_ok(), 1);
}

#[tokio::test]
async fn fake_ssm_refuses_a_tampered_signature() {
    let issuer = TestIssuer::new(DEFAULT_ISSUER);
    let aws = start(&issuer);
    let session = assume_role(&aws, &issuer.token(SUB, "g-1", exp()), DB)
        .await
        .unwrap();

    let value = get_parameter(&aws, &session, DB, false).await;
    assert_eq!(
        value.as_deref(),
        Ok("synthetic-db-value-1"),
        "positive control"
    );

    let refused = get_parameter(&aws, &session, DB, true).await.unwrap_err();
    assert!(
        refused.starts_with("InvalidSignatureException: "),
        "{refused}"
    );
    assert_eq!(aws.ssm_ok(), 1);
}

#[tokio::test]
async fn fake_ssm_refuses_a_parameter_outside_the_session_policy() {
    let issuer = TestIssuer::new(DEFAULT_ISSUER);
    let aws = start(&issuer);
    let token = issuer.token(SUB, "g-1", exp());
    let db_session = assume_role(&aws, &token, DB).await.unwrap();
    let other_session = assume_role(&aws, &token, OTHER).await.unwrap();

    assert_eq!(
        get_parameter(&aws, &db_session, DB, false).await.as_deref(),
        Ok("synthetic-db-value-1"),
        "positive control: the session reads its own parameter"
    );
    assert_eq!(
        get_parameter(&aws, &other_session, OTHER, false)
            .await
            .as_deref(),
        Ok("synthetic-other-value-2"),
        "positive control: the role itself allows the other parameter"
    );

    let refused = get_parameter(&aws, &db_session, OTHER, false)
        .await
        .unwrap_err();
    assert!(
        refused.starts_with("AccessDeniedException: ")
            && refused.contains("no session policy allows the ssm:GetParameter action"),
        "{refused}"
    );
}

#[tokio::test]
async fn fake_kms_denied_returns_kms_access_denied() {
    let issuer = TestIssuer::new(DEFAULT_ISSUER);
    let aws = start(&issuer);
    let session = assume_role(&aws, &issuer.token(SUB, "g-1", exp()), DB)
        .await
        .unwrap();
    assert_eq!(
        get_parameter(&aws, &session, DB, false).await.as_deref(),
        Ok("synthetic-db-value-1"),
        "positive control"
    );

    aws.set_failure(Some(Failure::KmsDenied));
    let refused = get_parameter(&aws, &session, DB, false).await.unwrap_err();
    assert!(
        refused.starts_with("AccessDeniedException: ") && refused.contains("kms:Decrypt"),
        "{refused}"
    );
}
