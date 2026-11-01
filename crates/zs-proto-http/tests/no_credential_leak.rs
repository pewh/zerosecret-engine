#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zs_credential::Credential;
use zs_identity::{Subject, WorkloadLabel};
use zs_proto_http::{ApiKeyHeaderHttp, BasicAuthHttp, BearerHttp, QueryParamHttp};
use zs_protocol::{Context, Destination, InjectedRequest, Protocol};

const SECRET: &str = "sk_live_must_never_appear_anywhere";

fn credential() -> Credential {
    Credential::from_bytes(SECRET.as_bytes().to_vec()).unwrap()
}

fn workload(name: &str) -> WorkloadLabel {
    WorkloadLabel::new(name).unwrap()
}

fn all_schemes() -> Vec<(&'static str, Box<dyn Protocol>)> {
    let allowed = vec![workload("claude-code")];
    vec![
        (
            "bearer",
            Box::new(BearerHttp::new("api.example.com", allowed.clone())) as Box<dyn Protocol>,
        ),
        (
            "basic",
            Box::new(BasicAuthHttp::new("api.example.com", allowed.clone())),
        ),
        (
            "api-key-header",
            Box::new(ApiKeyHeaderHttp::new(
                "api.example.com",
                "X-Api-Key",
                allowed.clone(),
            )),
        ),
        (
            "query-param",
            Box::new(QueryParamHttp::new("api.example.com", "api_token", allowed)),
        ),
    ]
}

#[test]
fn no_scheme_leaks_the_credential_in_a_denial_message() {
    let subject = Subject::new("alice@company.com").unwrap();
    let denied = workload("not-granted");
    for (name, scheme) in all_schemes() {
        let error = scheme
            .authorize(&Context {
                subject: &subject,
                workload: &denied,
            })
            .expect_err("an ungranted workload must be denied");
        let text = format!("{error:?} {error}");
        assert!(
            !text.contains(SECRET),
            "{name} leaked the credential into a denial: {text}"
        );
    }
}

#[test]
fn no_scheme_leaks_the_credential_in_an_injection_error() {
    let bad = Credential::from_bytes(vec![0xFF, 0xFE, 0xFD]).unwrap();
    for (name, scheme) in all_schemes() {
        let mut request = InjectedRequest::default();
        let error = scheme
            .inject(&mut request, &bad)
            .expect_err("a non-utf-8 credential cannot be injected");
        let text = format!("{error:?} {error}");
        assert!(
            !text.contains("\u{fffd}") && !text.contains("fffd"),
            "{name} put raw credential bytes into an error: {text}"
        );
        assert!(
            text.len() < 200,
            "{name} error looks like it embeds the credential: {text}"
        );
    }
}

#[test]
fn each_scheme_injects_into_exactly_one_place() {
    let credential = credential();

    let mut request = InjectedRequest::default();
    BearerHttp::new("api.example.com", vec![])
        .inject(&mut request, &credential)
        .unwrap();
    assert_eq!(
        request.header("Authorization"),
        Some(format!("Bearer {SECRET}").as_str())
    );
    assert!(
        !request.path.contains(SECRET),
        "bearer must not touch the path"
    );

    let mut request = InjectedRequest::default();
    ApiKeyHeaderHttp::new("api.example.com", "X-Api-Key", vec![])
        .inject(&mut request, &credential)
        .unwrap();
    assert_eq!(request.header("X-Api-Key"), Some(SECRET));
    assert!(
        !request.path.contains(SECRET),
        "api-key header must not touch the path"
    );

    let mut request = InjectedRequest::default();
    QueryParamHttp::new("api.example.com", "api_token", vec![])
        .inject(&mut request, &credential)
        .unwrap();
    assert!(
        request.path.contains(SECRET),
        "the query-param scheme injects into the path by definition"
    );
    assert!(
        request.headers.iter().all(|(_, v)| !v.contains(SECRET)),
        "query-param must not also place the credential in a header"
    );
}

#[test]
fn client_supplied_credentials_are_replaced_not_appended() {
    let credential = credential();

    let mut request = InjectedRequest {
        headers: vec![("Authorization".into(), "Bearer attacker-chosen".into())],
        ..Default::default()
    };
    BearerHttp::new("api.example.com", vec![])
        .inject(&mut request, &credential)
        .unwrap();
    let authorizations = request
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
        .count();
    assert_eq!(authorizations, 1, "exactly one Authorization header");
    assert!(
        !request
            .header("Authorization")
            .unwrap()
            .contains("attacker-chosen")
    );

    let mut request = InjectedRequest {
        path: "/v1/x?api_token=attacker-chosen&keep=1".into(),
        ..Default::default()
    };
    QueryParamHttp::new("api.example.com", "api_token", vec![])
        .inject(&mut request, &credential)
        .unwrap();
    assert!(
        !request.path.contains("attacker-chosen"),
        "the client's own api_token must be dropped: {}",
        request.path
    );
    assert_eq!(
        request.path.matches("api_token=").count(),
        1,
        "exactly one api_token: {}",
        request.path
    );
    assert!(
        request.path.contains("keep=1"),
        "unrelated parameters must survive: {}",
        request.path
    );
}

#[test]
fn destination_carries_no_query_string() {
    let destination = Destination::new("api.example.com".to_string(), 443);
    let rendered = format!("{destination:?}");
    assert!(
        !rendered.contains('?'),
        "a destination must not carry a query string: {rendered}"
    );
}

#[test]
fn no_scheme_matches_a_host_it_was_not_built_for() {
    let elsewhere = Destination::new("api.attacker.test".to_string(), 443);
    let intended = Destination::new("api.example.com".to_string(), 443);
    for (name, scheme) in all_schemes() {
        assert!(
            scheme.matches(&intended),
            "{name} must match the host it was built for"
        );
        assert!(
            !scheme.matches(&elsewhere),
            "{name} must not match an unrelated host"
        );
    }
}
