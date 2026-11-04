#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_https_request_records_file_credential_ref() {
    let agent = common::setup_agent(true, true);
    let process = agent.agent.as_ref().expect("agent must run");
    let proxy = process.proxy_addr.clone();
    let ca = std::fs::read_to_string(&process.ca_path).unwrap();
    let (status, _) = common::proxied_request(&proxy, &ca, "api.stripe.com", 443, "/v1/customers")
        .await
        .unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "positive control: {status}"
    );

    let journal = std::fs::read_to_string(agent.dir.join(".zs-audit").join("audit.jsonl")).unwrap();
    let allowed: Vec<&str> = journal
        .lines()
        .filter(|line| line.contains("\"decision\":\"allow\""))
        .collect();
    assert!(!allowed.is_empty(), "{journal}");
    assert!(
        allowed
            .iter()
            .any(|line| line.contains("\"credential_ref\":\"file:stripe-prod\"")),
        "an allowed request must name its credential source: {journal}"
    );
    assert!(
        !journal.contains("sk_test_zsv_synthetic_value_9f27c4d1"),
        "the credential value must never reach the journal: {journal}"
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn userinfo_in_the_target_never_reaches_the_audit_host() {
    let agent = common::setup_agent(true, true);
    let process = agent.agent.as_ref().expect("agent must run");
    let proxy = process.proxy_addr.clone();
    let response = common::raw_exchange(
        &proxy,
        b"GET https://leak:zs-audit-userinfo-secret@api.stripe.com/v1/customers HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "positive control: {response}"
    );

    let journal = std::fs::read_to_string(agent.dir.join(".zs-audit").join("audit.jsonl")).unwrap();
    assert!(
        journal.contains("\"resource\":\"api.stripe.com:443\""),
        "the audit host must be the bare host: {journal}"
    );
    assert!(
        !journal.contains("zs-audit-userinfo-secret"),
        "the userinfo password must never reach the journal: {journal}"
    );
    assert!(
        !journal.contains("leak:"),
        "the userinfo user must never reach the journal: {journal}"
    );
}
