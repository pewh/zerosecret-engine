#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zs::{HttpAuth, ResourceBinding};

fn binding(protocol: &str, port: Option<u16>) -> ResourceBinding {
    ResourceBinding {
        resource: "acme-db".into(),
        host: "db.acme.internal".into(),
        protocol: protocol.into(),
        upstream_host: None,
        upstream_port: port,
        upstream_plaintext: false,
        listen_port: None,
        local_endpoint: false,
        operations: Vec::new(),
        paths: None,
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

#[test]
fn an_unknown_l3_protocol_has_no_upstream_port() {
    let redis = binding("redis", None);
    assert_ne!(
        redis.upstream().1,
        5432,
        "an unknown protocol must not fall through to the postgres port"
    );
    assert!(
        redis.l3_fields().is_ok(),
        "an unknown protocol stays a valid load, and no layer carries it"
    );
    assert!(!redis.is_l3());
}

#[test]
fn each_l3_protocol_has_its_own_default_port() {
    assert_eq!(
        binding("postgres", None).upstream(),
        ("db.acme.internal".into(), 5432)
    );
    assert_eq!(
        binding("mysql", None).upstream(),
        ("db.acme.internal".into(), 3306)
    );
    assert_eq!(
        binding("mongo", None).upstream(),
        ("db.acme.internal".into(), 27017)
    );
    assert_eq!(
        binding("postgres", Some(6432)).upstream(),
        ("db.acme.internal".into(), 6432),
        "a set upstream_port wins over the protocol default"
    );
}
