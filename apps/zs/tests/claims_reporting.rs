#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("zs")
}

fn zs(home: &Path, args: &[&str]) -> (i32, String) {
    let output = Command::new(binary())
        .args(args)
        .env("ZS_HOME", home)
        .env("USER", "alice")
        .current_dir(home)
        .output()
        .expect("zs must run");
    (
        output.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn workspace(https_mode: zs_policy::Materialization) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let signing = zs_grant::ControlSigningKey::generate("test-k1");
    let verifying_hex: String = signing
        .verifying_key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let grant = |resource: &str, protocol: &str, op: &str, mode: zs_policy::Materialization| {
        let host = match resource {
            "stripe-production" => "api.stripe.com",
            "analytics-db" => "db.internal",
            _ => "cache.internal",
        };
        let connection = if zs_policy::default_port(protocol).is_some() {
            common::default_connection(host, protocol)
        } else {
            common::uninterceptable_connection(host)
        };
        serde_json::to_string(
            &signing
                .sign(zs_grant::Grant {
                    subject: "alice".into(),
                    workload: "default".into(),
                    resource: resource.into(),
                    host: host.into(),
                    protocol: protocol.into(),
                    source: zs_policy::CredentialSource::file(format!("vault:kv/{resource}")),
                    operations: vec![op.into()],
                    environment: "development".into(),
                    expires_at_ms: now_ms + 3_600_000,
                    grant_id: format!("g-{resource}"),
                    materialization: mode,
                    upstream_host: connection.upstream_host,
                    upstream_port: connection.upstream_port,
                    upstream_tls: connection.upstream_tls,
                    local_endpoint: connection.local_endpoint,
                    version: zs_grant::GRANT_VERSION,
                })
                .unwrap(),
        )
        .unwrap()
    };

    let config = format!(
        r#"{{"bindings":[
            {{"resource":"stripe-production","host":"api.stripe.com","protocol":"https","auth":{{"scheme":"bearer"}}}},
            {{"resource":"analytics-db","host":"db.internal","protocol":"postgres","upstream_host":"127.0.0.1","upstream_port":5432}},
            {{"resource":"session-cache","host":"cache.internal","protocol":"cassandra"}}
        ],
        "signing_keys":[{{"key_id":"test-k1","verifying_key_hex":"{verifying_hex}"}}],
        "grants":[{}, {}, {}]}}"#,
        grant("stripe-production", "https", "GET", https_mode),
        grant(
            "analytics-db",
            "postgres",
            "connect",
            zs_policy::Materialization::Exchange
        ),
        grant(
            "session-cache",
            "cassandra",
            "GET",
            zs_policy::Materialization::Exchange
        ),
    );
    std::fs::write(dir.path().join("zs-policy.json"), config).unwrap();
    dir
}

#[test]
fn resources_reports_the_interception_layer_per_resource() {
    let home = workspace(zs_policy::Materialization::Retrieve);

    let (code, out) = zs(home.path(), &["resources"]);

    assert_eq!(code, 0, "{out}");
    let https_line = out
        .lines()
        .find(|l| l.contains("stripe-production"))
        .unwrap_or_else(|| panic!("no https line in:\n{out}"));
    let pg_line = out
        .lines()
        .find(|l| l.contains("analytics-db"))
        .unwrap_or_else(|| panic!("no postgres line in:\n{out}"));

    assert!(
        https_line.contains("L1"),
        "an HTTPS resource is proxy-intercepted (L1/L2): {https_line}"
    );
    assert!(
        pg_line.contains("L3"),
        "a postgres resource goes through a local listener (L3): {pg_line}"
    );
}

#[test]
fn resources_still_reports_the_materialization_mode() {
    let home = workspace(zs_policy::Materialization::Retrieve);

    let (_code, out) = zs(home.path(), &["resources"]);

    assert!(
        out.lines()
            .find(|l| l.contains("stripe-production"))
            .is_some_and(|l| l.contains("retrieve")),
        "the mode must be reported:\n{out}"
    );
}

// Read as a field: `strict-unknown` contains `strict` and the mode column contains a space.
fn verdict_for(out: &str, resource: &str) -> String {
    let line = out
        .lines()
        .find(|l| l.starts_with(&format!("{resource}\t")))
        .unwrap_or_else(|| panic!("no {resource} line in:\n{out}"));
    line.rsplit('\t').next().unwrap_or_default().trim().into()
}

#[test]
fn an_intercepted_retrieve_resource_is_strict() {
    let home = workspace(zs_policy::Materialization::Retrieve);

    let (_code, out) = zs(home.path(), &["resources"]);

    assert_eq!(
        verdict_for(&out, "stripe-production"),
        "strict",
        "an HTTPS resource is intercepted, so the workload never holds the credential:\n{out}"
    );
}

#[test]
fn an_intercepted_exchange_resource_is_strict() {
    let home = workspace(zs_policy::Materialization::Exchange);

    let (_code, out) = zs(home.path(), &["resources"]);

    assert_eq!(
        verdict_for(&out, "stripe-production"),
        "strict",
        "materialization must not decide the strict label:\n{out}"
    );
}

#[test]
fn an_unintercepted_protocol_is_not_strict() {
    let home = workspace(zs_policy::Materialization::Exchange);

    let (_code, out) = zs(home.path(), &["resources"]);

    assert_eq!(
        verdict_for(&out, "session-cache"),
        "not-strict",
        "no interception layer carries cassandra, so it cannot be strict:\n{out}"
    );
}

#[test]
fn an_unintercepted_protocol_reports_no_interception_layer() {
    let home = workspace(zs_policy::Materialization::Exchange);

    let (_code, out) = zs(home.path(), &["resources"]);
    let line = out
        .lines()
        .find(|l| l.starts_with("session-cache\t"))
        .unwrap_or_else(|| panic!("no session-cache line in:\n{out}"));
    let layer = line.split('\t').nth(3).unwrap_or_default();

    assert!(
        layer != "L1" && layer != "L3",
        "an unintercepted protocol has no layer, it must not claim one: {line}"
    );
}

#[test]
fn a_resource_with_no_grant_is_not_claimed_strict() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("zs-policy.json"),
        r#"{"bindings":[{"resource":"stripe-production","host":"api.stripe.com","protocol":"https"}],"signing_keys":[],"grants":[]}"#,
    )
    .unwrap();

    let (_code, out) = zs(dir.path(), &["resources"]);

    assert_eq!(
        verdict_for(&out, "stripe-production"),
        "strict-unknown",
        "a resource with no grant must be reported as unknown, never strict:\n{out}"
    );
}

#[test]
fn the_report_prints_no_credential_reference_value() {
    let home = workspace(zs_policy::Materialization::Retrieve);
    let creds = home.path().join(".zs-credentials");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("stripe-production"), "sk_live_must_not_appear").unwrap();

    let (_code, out) = zs(home.path(), &["resources"]);

    assert!(
        !out.contains("sk_live_must_not_appear"),
        "the report leaked a credential:\n{out}"
    );
}

#[test]
fn protocol_case_and_near_misses_are_classified_by_one_allowlist() {
    let dir = tempfile::tempdir().unwrap();
    let signing = zs_grant::ControlSigningKey::generate("test-k1");
    let grant = |resource: &str, protocol: &str| {
        let host = format!("{resource}.internal");
        let connection = if zs_policy::default_port(protocol).is_some() {
            common::default_connection(&host, protocol)
        } else {
            common::uninterceptable_connection(&host)
        };
        serde_json::to_string(
            &signing
                .sign(zs_grant::Grant {
                    subject: "alice".into(),
                    workload: "default".into(),
                    resource: resource.into(),
                    host: format!("{resource}.internal"),
                    protocol: protocol.into(),
                    source: zs_policy::CredentialSource::file(format!("vault:kv/{resource}")),
                    operations: vec!["GET".into()],
                    environment: "development".into(),
                    expires_at_ms: u64::MAX,
                    grant_id: format!("g-{resource}"),
                    materialization: zs_policy::Materialization::Retrieve,
                    upstream_host: connection.upstream_host,
                    upstream_port: connection.upstream_port,
                    upstream_tls: connection.upstream_tls,
                    local_endpoint: connection.local_endpoint,
                    version: zs_grant::GRANT_VERSION,
                })
                .unwrap(),
        )
        .unwrap()
    };
    let rows: [(&str, &str, bool, &str, &str); 8] = [
        ("upper-https", "HTTPS", true, "L1", "strict"),
        (
            "mixed-https-ungranted",
            "hTtPs",
            false,
            "L1",
            "strict-unknown",
        ),
        ("mixed-postgres", "PoStGrEs", true, "L3", "strict"),
        (
            "mixed-postgres-ungranted",
            "pOsTgReS",
            false,
            "L3",
            "strict-unknown",
        ),
        ("plain-http", "http", true, "L1", "strict"),
        ("long-https", "httpss", true, "-", "not-strict"),
        ("long-postgresql", "postgresql", true, "-", "not-strict"),
        ("padded-https", " https", false, "-", "not-strict"),
    ];
    let bindings: Vec<String> = rows
        .iter()
        .map(|(name, protocol, _, _, _)| {
            serde_json::json!({"resource": name, "host": format!("{name}.internal"), "protocol": protocol})
                .to_string()
        })
        .collect();
    let grants: Vec<String> = rows
        .iter()
        .filter(|(_, _, granted, _, _)| *granted)
        .map(|(name, protocol, _, _, _)| grant(name, protocol))
        .collect();
    std::fs::write(
        dir.path().join("zs-policy.json"),
        format!(
            r#"{{"bindings":[{}],"signing_keys":[],"grants":[{}]}}"#,
            bindings.join(","),
            grants.join(",")
        ),
    )
    .unwrap();

    let (code, out) = zs(dir.path(), &["resources"]);

    assert_eq!(code, 0, "{out}");
    for (name, protocol, _, layer, verdict) in rows {
        let line = out
            .lines()
            .find(|l| l.starts_with(&format!("{name}\t")))
            .unwrap_or_else(|| panic!("no {name} line in:\n{out}"));
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            fields[2], protocol,
            "protocol must print byte-for-byte: {line:?}"
        );
        assert_eq!(fields[3], layer, "{line:?}");
        assert_eq!(verdict_for(&out, name), verdict, "{line:?}");
    }
}
