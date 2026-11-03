#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use zs::connection::{Mismatch, grant_matches, reconcile};
use zs::{AgentHandler, GrantCache, ResourceBinding};
use zs_grant::{ControlSigningKey, Grant, SignedGrant};
use zs_mitm::{Flow, FlowHandler};
use zs_policy::{ResolvedConnection, UpstreamTlsMode};
use zs_protocol::Destination;

const MEMBER: &str = "alice@company.com";
const API: &str = "orders-api";
const API_HOST: &str = "api.orders.test";
const PG_HOST: &str = "pg.orders.test";
const MYSQL: &str = "orders-mysql";
const MYSQL_HOST: &str = "mysql.orders.test";
const MONGO_HOST: &str = "orders-mongo.internal";

#[allow(dead_code)]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn field_line(resource: &str, field: &str, file: &str, signed: &str) -> String {
    format!(
        "zs: {resource}: {field} is {file} in the policy file, but the control plane signed {signed}; remove {field} from the policy file, or ask an admin to change resource {resource}"
    )
}

fn ca_hash_line(resource: &str, path: &str, file_hex: &str, signed_hex: &str) -> String {
    format!(
        "zs: {resource}: upstream_ca {path} has SHA-256 {file_hex}, but the control plane signed {signed_hex}; restore the file, or, if the new file is intended, ask an admin to set the resource's CA SHA-256 to {file_hex}"
    )
}

fn ca_missing_line(resource: &str, signed_hex: &str) -> String {
    format!(
        "zs: {resource}: the control plane signed a CA bundle with SHA-256 {signed_hex}; set upstream_ca to that file"
    )
}

fn connection(host: &str, port: u16, tls: UpstreamTlsMode, local: bool) -> ResolvedConnection {
    ResolvedConnection {
        upstream_host: host.into(),
        upstream_port: port,
        upstream_tls: tls,
        local_endpoint: local,
    }
}

fn grant_for(host: &str, protocol: &str, connection: ResolvedConnection) -> Grant {
    let operation = if protocol.eq_ignore_ascii_case("https") || protocol == "http" {
        "GET"
    } else {
        "connect"
    };
    Grant {
        subject: MEMBER.into(),
        workload: "default".into(),
        resource: "r".into(),
        host: host.into(),
        protocol: protocol.into(),
        source: zs_policy::CredentialSource::file("r"),
        operations: vec![operation.into()],
        environment: "development".into(),
        expires_at_ms: u64::MAX,
        grant_id: "g-1".into(),
        materialization: zs_policy::Materialization::Retrieve,
        upstream_host: connection.upstream_host,
        upstream_port: connection.upstream_port,
        upstream_tls: connection.upstream_tls,
        local_endpoint: connection.local_endpoint,
    }
}

fn signed(host: &str, protocol: &str, connection: ResolvedConnection) -> SignedGrant {
    ControlSigningKey::generate("k1")
        .sign(grant_for(host, protocol, connection))
        .unwrap()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn agent(
    key: &ControlSigningKey,
    binding: ResourceBinding,
    grants: Vec<SignedGrant>,
) -> AgentHandler {
    let cache = GrantCache::new();
    for grant in grants {
        cache.insert(grant);
    }
    AgentHandler::from_grants(
        zs_identity::Subject::new(MEMBER).unwrap(),
        zs_identity::WorkloadLabel::new("default").unwrap(),
        vec![binding],
        cache,
        zs_grant::AgentVerifier::new(vec![(
            key.key_id().to_string(),
            ed25519_dalek::VerifyingKey::from_bytes(&key.verifying_key_bytes()).unwrap(),
        )]),
        no_materializer(),
    )
}

fn no_materializer() -> Arc<zs_materializer::Materializer> {
    struct NoExchange;
    #[async_trait::async_trait]
    impl zs_materializer::ExchangeProvider for NoExchange {
        async fn exchange(
            &self,
            _grant: &Grant,
        ) -> Result<zs_credential::Credential, zs_materializer::MaterializationError> {
            Err(zs_materializer::MaterializationError::Exchange(
                "not configured".into(),
            ))
        }
    }
    Arc::new(zs_materializer::Materializer::new(
        zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(
            "/nonexistent",
        ))),
        Arc::new(NoExchange),
    ))
}

fn deny_reason(flow: Flow) -> String {
    match flow {
        Flow::Deny { reason } => reason,
        other => panic!("expected a deny, got {other:?}"),
    }
}

fn intercepted(flow: Flow) -> (String, u16, bool) {
    match flow {
        Flow::Intercept {
            upstream_host,
            upstream_port,
            upstream_tls,
            ..
        } => (upstream_host, upstream_port, upstream_tls),
        other => panic!("expected an intercept, got {other:?}"),
    }
}

fn binding(value: Value) -> ResourceBinding {
    let mut value = value;
    value["resource"] = "r".into();
    serde_json::from_value(value).unwrap()
}

fn with_ca(mut binding: ResourceBinding, path: &str, sha256: [u8; 32]) -> ResourceBinding {
    binding.upstream_ca = Some(PathBuf::from(path));
    binding.loaded_ca = Some(Arc::new(zs_upstream::LoadedCa {
        roots: Vec::new(),
        sha256,
    }));
    binding
}

#[test]
fn a_default_signature_leaves_an_unchanged_binding_as_it_was() {
    let mut https = binding(json!({"host": API_HOST, "protocol": "https"}));
    let grant = signed(
        "API.ORDERS.TEST",
        "https",
        connection("API.ORDERS.TEST", 443, UpstreamTlsMode::Default, false),
    );
    reconcile(&mut https, &grant).unwrap();
    assert_eq!(https.upstream_host, None);
    assert_eq!(https.upstream_port, None);
    assert!(!https.upstream_plaintext);
    assert!(!https.local_endpoint);
    assert_eq!(https.upstream_cert_sha256, None);

    let mut pg = binding(json!({"host": PG_HOST, "protocol": "postgres"}));
    reconcile(
        &mut pg,
        &signed(
            PG_HOST,
            "postgres",
            connection(PG_HOST, 5432, UpstreamTlsMode::Default, false),
        ),
    )
    .unwrap();
    assert_eq!(pg.upstream_host, None);
    assert_eq!(pg.upstream_port, None);
    assert_eq!(
        pg.connection().unwrap(),
        connection(PG_HOST, 5432, UpstreamTlsMode::Default, false)
    );
}

#[test]
fn reconcile_fills_each_unset_field_from_the_signature() {
    let wanted = connection("127.0.0.1", 59080, UpstreamTlsMode::Plaintext, true);
    let mut https = binding(json!({"host": API_HOST, "protocol": "https"}));
    reconcile(&mut https, &signed(API_HOST, "https", wanted.clone())).unwrap();
    assert_eq!(https.upstream_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(https.upstream_port, Some(59080));
    assert!(https.upstream_plaintext);
    assert!(https.local_endpoint);
    assert_eq!(https.connection().unwrap(), wanted);

    let pin = UpstreamTlsMode::PinSha256([0xcd; 32]);
    let wanted = connection("db.orders.test", 6432, pin, false);
    let mut pg = binding(json!({"host": PG_HOST, "protocol": "postgres"}));
    reconcile(&mut pg, &signed(PG_HOST, "postgres", wanted.clone())).unwrap();
    assert_eq!(pg.upstream_cert_sha256.as_deref(), Some(&*"cd".repeat(32)));
    assert_eq!(pg.upstream_host.as_deref(), Some("db.orders.test"));
    assert_eq!(pg.upstream_port, Some(6432));
    assert_eq!(pg.connection().unwrap(), wanted);

    let wanted = connection("127.0.0.1", 27017, UpstreamTlsMode::Plaintext, false);
    let mut mongo = binding(json!({"host": MONGO_HOST, "protocol": "mongo", "user": "u"}));
    reconcile(&mut mongo, &signed(MONGO_HOST, "mongo", wanted.clone())).unwrap();
    assert!(mongo.upstream_plaintext);
    assert_eq!(mongo.upstream_port, None);
    assert_eq!(mongo.connection().unwrap(), wanted);
}

#[test]
fn reconcile_compares_hosts_without_case_and_pins_as_bytes() {
    let pin = UpstreamTlsMode::PinSha256([0xcd; 32]);
    let grant = signed(
        PG_HOST,
        "postgres",
        connection("db.orders.test", 6432, pin, false),
    );
    let mut upper = binding(json!({
        "host": "PG.ORDERS.TEST",
        "protocol": "POSTGRES",
        "upstream_host": "DB.ORDERS.TEST",
        "upstream_port": 6432,
        "upstream_cert_sha256": "CD".repeat(32),
    }));
    reconcile(&mut upper, &grant).unwrap();
    assert_eq!(grant_matches(&grant, &upper), Ok(()));

    let mut other = binding(json!({
        "host": PG_HOST,
        "protocol": "postgres",
        "upstream_cert_sha256": "CE".repeat(32),
    }));
    assert_eq!(
        reconcile(&mut other, &grant),
        Err(Mismatch::Tls {
            field: "upstream_cert_sha256",
            file: "ce".repeat(32),
            signed: UpstreamTlsMode::PinSha256([0xcd; 32]),
            running: Some(UpstreamTlsMode::PinSha256([0xce; 32])),
        })
    );
}

#[test]
fn reconcile_checks_host_and_protocol_before_any_field() {
    let grant = signed(
        API_HOST,
        "https",
        connection(API_HOST, 443, UpstreamTlsMode::Default, false),
    );
    for file in [
        json!({"host": "evil.example.test", "protocol": "https", "upstream_port": 1}),
        json!({"host": API_HOST, "protocol": "http", "upstream_port": 1}),
    ] {
        let mut b = binding(file);
        assert_eq!(reconcile(&mut b, &grant), Err(Mismatch::HostOrProtocol));
        assert_eq!(grant_matches(&grant, &b), Err(Mismatch::HostOrProtocol));
    }
}

#[test]
fn reconcile_stops_on_each_set_field_that_differs_and_changes_nothing() {
    let default_tls = "upstream_tls default".to_string();
    let cases: Vec<(Value, ResolvedConnection, &str, String, String)> = vec![
        (
            json!({"host": API_HOST, "protocol": "https", "upstream_host": "127.0.0.1"}),
            connection(API_HOST, 443, UpstreamTlsMode::Default, false),
            "upstream_host",
            "127.0.0.1".into(),
            API_HOST.into(),
        ),
        (
            json!({"host": API_HOST, "protocol": "https", "upstream_port": 8443}),
            connection(API_HOST, 443, UpstreamTlsMode::Default, false),
            "upstream_port",
            "8443".into(),
            "443".into(),
        ),
        (
            json!({"host": MONGO_HOST, "protocol": "mongo", "user": "u", "upstream_plaintext": true}),
            connection(MONGO_HOST, 27017, UpstreamTlsMode::Default, false),
            "upstream_plaintext",
            "true".into(),
            default_tls.clone(),
        ),
        (
            json!({"host": PG_HOST, "protocol": "postgres", "upstream_cert_sha256": "ab".repeat(32)}),
            connection(PG_HOST, 5432, UpstreamTlsMode::Default, false),
            "upstream_cert_sha256",
            "ab".repeat(32),
            default_tls,
        ),
        (
            json!({"host": API_HOST, "protocol": "https", "local_endpoint": true}),
            connection(API_HOST, 443, UpstreamTlsMode::Default, false),
            "local_endpoint",
            "true".into(),
            "false".into(),
        ),
    ];
    for (file, wanted, field, file_value, signed_value) in cases {
        let protocol = file["protocol"].as_str().unwrap().to_string();
        let host = file["host"].as_str().unwrap().to_string();
        let mut b = binding(file);
        let before = format!("{b:?}");
        assert_eq!(
            reconcile(&mut b, &signed(&host, &protocol, wanted)).map_err(|m| m.startup_line("r")),
            Err(field_line("r", field, &file_value, &signed_value)),
            "{field}"
        );
        assert_eq!(format!("{b:?}"), before, "{field}: nothing is filled");
    }

    let mut ca = with_ca(
        binding(json!({"host": MYSQL_HOST, "protocol": "mysql"})),
        "/tmp/ca.pem",
        [0x11; 32],
    );
    assert_eq!(
        reconcile(
            &mut ca,
            &signed(
                MYSQL_HOST,
                "mysql",
                connection(MYSQL_HOST, 3306, UpstreamTlsMode::Default, false)
            )
        ),
        Err(Mismatch::Tls {
            field: "upstream_ca",
            file: "/tmp/ca.pem".into(),
            signed: UpstreamTlsMode::Default,
            running: Some(UpstreamTlsMode::CaSha256([0x11; 32])),
        })
    );
}

#[test]
fn a_signed_ca_needs_the_loaded_ca_with_the_same_hash() {
    let grant = signed(
        MYSQL_HOST,
        "mysql",
        connection(
            MYSQL_HOST,
            3306,
            UpstreamTlsMode::CaSha256([0x22; 32]),
            false,
        ),
    );
    let mut missing = binding(json!({"host": MYSQL_HOST, "protocol": "mysql"}));
    assert_eq!(
        reconcile(&mut missing, &grant),
        Err(Mismatch::CaMissing {
            signed_hex: "22".repeat(32)
        })
    );

    let mut other = with_ca(missing.clone(), "/tmp/ca.pem", [0x11; 32]);
    assert_eq!(
        reconcile(&mut other, &grant),
        Err(Mismatch::CaHash {
            path: "/tmp/ca.pem".into(),
            file_hex: "11".repeat(32),
            signed_hex: "22".repeat(32),
        })
    );

    let mut same = with_ca(missing, "/tmp/ca.pem", [0x22; 32]);
    assert_eq!(reconcile(&mut same, &grant), Ok(()));
    assert_eq!(grant_matches(&grant, &same), Ok(()));
}

#[test]
fn grant_matches_reports_the_first_differing_field() {
    let https = binding(json!({"host": API_HOST, "protocol": "https"}));
    let base = connection(API_HOST, 443, UpstreamTlsMode::Default, false);
    assert_eq!(
        grant_matches(&signed(API_HOST, "https", base.clone()), &https),
        Ok(())
    );
    let upper = connection("API.ORDERS.TEST", 443, UpstreamTlsMode::Default, false);
    assert_eq!(
        grant_matches(&signed(API_HOST, "https", upper), &https),
        Ok(())
    );

    let field = |field: &'static str, file: &str, signed: &str| Mismatch::Field {
        field,
        file: file.into(),
        signed: signed.into(),
    };
    let cases = [
        (
            connection("127.0.0.1", 8443, UpstreamTlsMode::Plaintext, true),
            field("upstream_host", API_HOST, "127.0.0.1"),
        ),
        (
            connection(API_HOST, 8443, UpstreamTlsMode::Plaintext, true),
            field("upstream_port", "443", "8443"),
        ),
        (
            connection(API_HOST, 443, UpstreamTlsMode::Plaintext, true),
            Mismatch::Tls {
                field: "upstream_tls",
                file: "default".into(),
                signed: UpstreamTlsMode::Plaintext,
                running: Some(UpstreamTlsMode::Default),
            },
        ),
        (
            connection(API_HOST, 443, UpstreamTlsMode::Default, true),
            field("local_endpoint", "false", "true"),
        ),
    ];
    for (wanted, mismatch) in cases {
        assert_eq!(
            grant_matches(&signed(API_HOST, "https", wanted), &https),
            Err(mismatch.clone()),
            "{mismatch:?}"
        );
    }

    let mut plaintext = https.clone();
    plaintext.upstream_host = Some("127.0.0.1".into());
    plaintext.upstream_plaintext = true;
    assert_eq!(
        grant_matches(
            &signed(
                API_HOST,
                "https",
                connection("127.0.0.1", 443, UpstreamTlsMode::Default, false)
            ),
            &plaintext
        ),
        Err(Mismatch::Tls {
            field: "upstream_plaintext",
            file: "true".into(),
            signed: UpstreamTlsMode::Default,
            running: Some(UpstreamTlsMode::Plaintext),
        })
    );

    let mysql = with_ca(
        binding(json!({"host": MYSQL_HOST, "protocol": "mysql"})),
        "/tmp/ca.pem",
        [0x11; 32],
    );
    assert_eq!(
        grant_matches(
            &signed(
                MYSQL_HOST,
                "mysql",
                connection(
                    MYSQL_HOST,
                    3306,
                    UpstreamTlsMode::CaSha256([0x22; 32]),
                    false
                )
            ),
            &mysql
        ),
        Err(Mismatch::CaHash {
            path: "/tmp/ca.pem".into(),
            file_hex: "11".repeat(32),
            signed_hex: "22".repeat(32),
        })
    );
}

#[test]
fn mismatch_lines_are_the_spec_texts() {
    let field = Mismatch::Field {
        field: "upstream_port",
        file: "8443".into(),
        signed: "443".into(),
    };
    assert_eq!(
        field.startup_line(API),
        field_line(API, "upstream_port", "8443", "443")
    );
    assert_eq!(
        field.renewal_line(API),
        "zs: orders-api: the control plane changed upstream_port (signed 443, running 8443); restart zs run to use it"
    );
    assert_eq!(field.deny_reason(), "upstream_port differs from the grant");
    assert_eq!(field.failure(), "connection_mismatch");

    let renewal = |field: &str, signed: &str, running: &str| {
        format!(
            "zs: orders-api: the control plane changed {field} (signed {signed}, running {running}); restart zs run to use it"
        )
    };
    for (name, file, signed) in [
        ("upstream_host", "127.0.0.1", API_HOST),
        ("local_endpoint", "true", "false"),
    ] {
        let mismatch = Mismatch::Field {
            field: name,
            file: file.into(),
            signed: signed.into(),
        };
        assert_eq!(
            mismatch.startup_line(API),
            field_line(API, name, file, signed)
        );
        assert_eq!(mismatch.renewal_line(API), renewal(name, signed, file));
        assert_eq!(
            mismatch.deny_reason(),
            format!("{name} differs from the grant")
        );
        assert_eq!(mismatch.failure(), "connection_mismatch");
    }

    let pin = UpstreamTlsMode::PinSha256([0xcd; 32]);
    for (name, file, signed, running) in [
        (
            "upstream_plaintext",
            "true".to_string(),
            UpstreamTlsMode::Default,
            Some(UpstreamTlsMode::Plaintext),
        ),
        (
            "upstream_tls",
            "default".to_string(),
            UpstreamTlsMode::Plaintext,
            Some(UpstreamTlsMode::Default),
        ),
        (
            "upstream_cert_sha256",
            "ab".repeat(32),
            pin,
            Some(UpstreamTlsMode::PinSha256([0xab; 32])),
        ),
        (
            "upstream_ca",
            "/etc/ca.pem".to_string(),
            UpstreamTlsMode::Default,
            Some(UpstreamTlsMode::CaSha256([0x11; 32])),
        ),
        ("upstream_ca", "/etc/ca.pem".to_string(), pin, None),
    ] {
        let mismatch = Mismatch::Tls {
            field: name,
            file: file.clone(),
            signed,
            running,
        };
        assert_eq!(
            mismatch.startup_line(API),
            field_line(API, name, &file, &format!("upstream_tls {signed}"))
        );
        let shown = running.map_or(file.clone(), |mode| mode.to_string());
        assert_eq!(
            mismatch.renewal_line(API),
            renewal("upstream_tls", &signed.to_string(), &shown)
        );
        assert_eq!(
            mismatch.deny_reason(),
            "upstream_tls differs from the grant"
        );
        assert_eq!(mismatch.failure(), "connection_mismatch");
    }
    assert_eq!(
        Mismatch::Tls {
            field: "upstream_plaintext",
            file: "true".into(),
            signed: UpstreamTlsMode::Default,
            running: Some(UpstreamTlsMode::Plaintext),
        }
        .renewal_line(API),
        "zs: orders-api: the control plane changed upstream_tls (signed default, running plaintext); restart zs run to use it"
    );

    let hash = Mismatch::CaHash {
        path: "/etc/ca.pem".into(),
        file_hex: "11".repeat(32),
        signed_hex: "22".repeat(32),
    };
    assert_eq!(
        hash.startup_line(MYSQL),
        ca_hash_line(MYSQL, "/etc/ca.pem", &"11".repeat(32), &"22".repeat(32))
    );
    assert_eq!(
        hash.renewal_line(MYSQL),
        format!(
            "zs: orders-mysql: the control plane changed upstream_tls (signed ca-sha256:{}, running ca-sha256:{}); restart zs run to use it",
            "22".repeat(32),
            "11".repeat(32)
        )
    );
    assert_eq!(hash.deny_reason(), "upstream_tls differs from the grant");
    assert_eq!(hash.failure(), "connection_mismatch");

    let missing = Mismatch::CaMissing {
        signed_hex: "22".repeat(32),
    };
    assert_eq!(
        missing.startup_line(MYSQL),
        ca_missing_line(MYSQL, &"22".repeat(32))
    );
    assert_eq!(
        missing.renewal_line(MYSQL),
        format!(
            "zs: orders-mysql: the control plane changed upstream_tls (signed ca-sha256:{}, running default); restart zs run to use it",
            "22".repeat(32)
        )
    );
    assert_eq!(missing.deny_reason(), "upstream_tls differs from the grant");
    assert_eq!(missing.failure(), "connection_mismatch");

    let host = Mismatch::HostOrProtocol;
    assert_eq!(
        host.startup_line(API),
        "zs: orders-api: binding host does not match the grant"
    );
    assert_eq!(
        host.renewal_line(API),
        "zs: orders-api: binding host does not match the grant"
    );
    assert_eq!(host.deny_reason(), "binding host does not match the grant");
    assert_eq!(host.failure(), "host_mismatch");
}

#[test]
fn a_renewed_grant_with_a_changed_connection_is_skipped() {
    let key = ControlSigningKey::generate("k1");
    let soon = now_ms() + 60_000;
    let later = now_ms() + 600_000;
    let at = |port: u16, id: &str, expires_at_ms: u64| {
        let mut grant = grant_for(
            MYSQL_HOST,
            "mysql",
            connection(MYSQL_HOST, port, UpstreamTlsMode::Default, false),
        );
        grant.grant_id = id.into();
        grant.expires_at_ms = expires_at_ms;
        key.sign(grant).unwrap()
    };
    let mut mysql = binding(json!({"host": MYSQL_HOST, "protocol": "mysql"}));
    reconcile(&mut mysql, &at(3306, "g-1", soon)).unwrap();
    assert_eq!(mysql.connection().unwrap().upstream_port, 3306);

    let equal = agent(&key, mysql.clone(), vec![at(3306, "g-1", soon)]);
    assert!(equal.grant_needs_renewal("r", 150_000));
    assert_eq!(equal.accept_renewal(&mysql, at(3306, "g-2", later)), Ok(()));
    assert!(
        !equal.grant_needs_renewal("r", 150_000),
        "positive control: an equal connection replaces the grant"
    );
    equal.apply_revocations(&["g-1".into()]);
    let reason = equal.authorize_message("r", "connect").unwrap_err().reason;
    assert!(reason.contains("grant g-2 is revoked"), "{reason}");

    let changed = agent(&key, mysql.clone(), vec![at(3306, "g-1", soon)]);
    let mismatch = changed
        .accept_renewal(&mysql, at(3307, "g-3", later))
        .unwrap_err();
    assert_eq!(
        mismatch.renewal_line("r"),
        "zs: r: the control plane changed upstream_port (signed 3307, running 3306); restart zs run to use it"
    );
    assert_eq!(mismatch.failure(), "connection_mismatch");
    assert!(
        changed.grant_needs_renewal("r", 150_000),
        "the near-expiry grant stays cached"
    );
    assert!(changed.authorize_message("r", "connect").is_ok());
    changed.apply_revocations(&["g-1".into()]);
    let reason = changed
        .authorize_message("r", "connect")
        .unwrap_err()
        .reason;
    assert!(
        reason.contains("grant g-1 is revoked"),
        "the cached grant id is unchanged: {reason}"
    );
}

#[test]
fn a_grant_with_a_different_connection_is_denied() {
    let key = ControlSigningKey::generate("k1");
    let https = binding(json!({"host": API_HOST, "protocol": "https"}));
    assert_eq!(
        https.connection().unwrap().upstream_tls,
        UpstreamTlsMode::Default
    );
    let with = |tls: UpstreamTlsMode| {
        key.sign(grant_for(
            API_HOST,
            "https",
            connection(API_HOST, 443, tls, false),
        ))
        .unwrap()
    };
    let destination = Destination::new(API_HOST, 443);

    let equal = agent(&key, https.clone(), vec![with(UpstreamTlsMode::Default)]);
    assert_eq!(
        intercepted(equal.classify(&destination)),
        (API_HOST.to_string(), 443, true)
    );

    let plaintext = agent(&key, https.clone(), vec![with(UpstreamTlsMode::Plaintext)]);
    let reason = deny_reason(plaintext.classify(&destination));
    assert!(
        reason.contains("upstream_tls differs from the grant"),
        "{reason}"
    );
    assert!(plaintext.materialize(API_HOST, "GET").is_err());

    let mut file_plaintext = https.clone();
    file_plaintext.upstream_host = Some("127.0.0.1".into());
    file_plaintext.upstream_plaintext = true;
    let loopback = |tls: UpstreamTlsMode| {
        key.sign(grant_for(
            API_HOST,
            "https",
            connection("127.0.0.1", 443, tls, false),
        ))
        .unwrap()
    };
    let equal = agent(
        &key,
        file_plaintext.clone(),
        vec![loopback(UpstreamTlsMode::Plaintext)],
    );
    assert_eq!(
        intercepted(equal.classify(&destination)),
        ("127.0.0.1".to_string(), 443, false)
    );
    let reason = deny_reason(
        agent(
            &key,
            file_plaintext,
            vec![loopback(UpstreamTlsMode::Default)],
        )
        .classify(&destination),
    );
    assert!(
        reason.contains("upstream_tls differs from the grant"),
        "{reason}"
    );

    let port = binding(json!({"host": PG_HOST, "protocol": "postgres"}));
    let pg = |p: u16| {
        key.sign(grant_for(
            PG_HOST,
            "postgres",
            connection(PG_HOST, p, UpstreamTlsMode::Default, false),
        ))
        .unwrap()
    };
    assert!(
        agent(&key, port.clone(), vec![pg(5432)])
            .authorize_message("r", "connect")
            .is_ok()
    );
    let reason = agent(&key, port, vec![pg(6432)])
        .authorize_message("r", "connect")
        .unwrap_err()
        .reason;
    assert!(
        reason.contains("upstream_port differs from the grant"),
        "{reason}"
    );
}

#[test]
fn a_local_file_grant_is_checked_against_the_binding_connection() {
    let upstream = common::spawn_fake_upstream();
    let port = upstream.addr.port();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for (tls, allowed) in [
        (UpstreamTlsMode::Plaintext, true),
        (UpstreamTlsMode::Default, false),
    ] {
        let home = common::TestHome::new(".zs-ca");
        let (policy, creds, audit, ca_dir, _) = common::write_test_setup_signing(
            home.path(),
            port,
            &["GET"],
            connection("127.0.0.1", port, tls, false),
        );
        let mut agent = common::spawn_agent(
            &common::bin_path(),
            &policy,
            &creds,
            &audit,
            &ca_dir,
            &["sleep", "20"],
            true,
        )
        .unwrap();
        let ca = std::fs::read_to_string(&agent.ca_path).unwrap();
        let before = upstream.requests.load(std::sync::atomic::Ordering::SeqCst);
        let (status, _) = runtime
            .block_on(common::proxied_request(
                &agent.proxy_addr,
                &ca,
                "api.stripe.com",
                443,
                "/v1/customers",
            ))
            .unwrap();
        let _ = agent.child.kill();
        let _ = agent.child.wait();
        let reached = upstream.requests.load(std::sync::atomic::Ordering::SeqCst) - before;
        let journal = std::fs::read_to_string(&audit).unwrap();
        if allowed {
            assert!(status.starts_with("HTTP/1.1 200"), "signed {tls}: {status}");
            assert_eq!(reached, 1, "signed {tls}");
        } else {
            assert!(status.contains("502"), "signed {tls}: {status}");
            assert_eq!(reached, 0, "signed {tls}: nothing reaches the upstream");
            assert!(
                journal.contains("upstream_tls differs from the grant"),
                "signed {tls}:\n{journal}"
            );
        }
    }
}

#[test]
fn a_connect_to_an_unsigned_port_is_denied() {
    let key = ControlSigningKey::generate("k1");
    let reconciled = |file: Value, wanted: ResolvedConnection| {
        let protocol = file["protocol"].as_str().unwrap().to_string();
        let host = file["host"].as_str().unwrap().to_string();
        let grant = key.sign(grant_for(&host, &protocol, wanted)).unwrap();
        let mut b = binding(file);
        reconcile(&mut b, &grant).unwrap();
        agent(&key, b, vec![grant])
    };
    let to = |port: u16| Destination::new(API_HOST, port);

    let default = reconciled(
        json!({"host": API_HOST, "protocol": "https"}),
        connection(API_HOST, 443, UpstreamTlsMode::Default, false),
    );
    assert_eq!(
        intercepted(default.classify(&to(443))),
        (API_HOST.to_string(), 443, true)
    );
    let reason = deny_reason(default.classify(&to(8443)));
    assert!(
        reason.contains("port 8443 is not the signed port 443"),
        "{reason}"
    );

    let signed_8443 = reconciled(
        json!({"host": API_HOST, "protocol": "https"}),
        connection(API_HOST, 8443, UpstreamTlsMode::Default, false),
    );
    for port in [8443, 443] {
        assert_eq!(
            intercepted(signed_8443.classify(&to(port))),
            (API_HOST.to_string(), 8443, true),
            "CONNECT to {port}"
        );
    }
    let reason = deny_reason(signed_8443.classify(&to(9443)));
    assert!(
        reason.contains("port 9443 is not the signed port 8443"),
        "{reason}"
    );

    let loopback = reconciled(
        json!({"host": API_HOST, "protocol": "https"}),
        connection("127.0.0.1", 59080, UpstreamTlsMode::Plaintext, false),
    );
    assert_eq!(
        intercepted(loopback.classify(&to(443))),
        ("127.0.0.1".to_string(), 59080, false)
    );
    let reason = deny_reason(loopback.classify(&to(8443)));
    assert!(
        reason.contains("port 8443 is not the signed port 59080"),
        "{reason}"
    );

    let http_host = "plain.orders.test";
    let http = reconciled(
        json!({"host": http_host, "protocol": "http"}),
        connection(http_host, 80, UpstreamTlsMode::Default, false),
    );
    assert_eq!(
        intercepted(http.classify(&Destination::new(http_host, 80))),
        (http_host.to_string(), 80, false)
    );
    let reason = deny_reason(http.classify(&Destination::new(http_host, 8080)));
    assert!(
        reason.contains("port 8080 is not the signed port 80"),
        "{reason}"
    );
}
