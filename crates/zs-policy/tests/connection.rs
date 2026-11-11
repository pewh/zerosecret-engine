#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zs_policy::{
    Connection, ResolvedConnection, ResourcePolicy, UpstreamTlsMode, default_port, is_loopback_host,
};

const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&HEX[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn with_tls(upstream_tls: UpstreamTlsMode) -> Connection {
    Connection {
        upstream_tls,
        ..Connection::default()
    }
}

fn with_host(host: Option<&str>, upstream_tls: UpstreamTlsMode) -> Connection {
    Connection {
        upstream_host: host.map(str::to_string),
        upstream_tls,
        ..Connection::default()
    }
}

#[test]
fn tls_mode_round_trips_its_string_form() {
    let ca = format!("ca-sha256:{HEX}");
    let pin = format!("pin-sha256:{HEX}");
    for (text, mode) in [
        ("default", UpstreamTlsMode::Default),
        ("plaintext", UpstreamTlsMode::Plaintext),
        (ca.as_str(), UpstreamTlsMode::CaSha256(bytes())),
        (pin.as_str(), UpstreamTlsMode::PinSha256(bytes())),
    ] {
        let parsed: UpstreamTlsMode = text.parse().unwrap();
        assert_eq!(parsed, mode);
        assert_eq!(parsed.to_string(), text);
        let json = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, format!("\"{text}\""));
        assert_eq!(
            serde_json::from_str::<UpstreamTlsMode>(&json).unwrap(),
            mode
        );
    }
    assert_eq!(UpstreamTlsMode::default(), UpstreamTlsMode::Default);

    let upper: UpstreamTlsMode = format!("pin-sha256:{}", HEX.to_uppercase())
        .parse()
        .unwrap();
    assert_eq!(upper.to_string(), format!("pin-sha256:{HEX}"));

    assert!(
        format!("CA-SHA256:{HEX}")
            .parse::<UpstreamTlsMode>()
            .is_err()
    );
    assert!(
        format!("ca-sha256:{}", &HEX[..63])
            .parse::<UpstreamTlsMode>()
            .is_err()
    );
    assert!(
        format!("ca-sha256:{HEX}0")
            .parse::<UpstreamTlsMode>()
            .is_err()
    );
    assert!(
        format!("pin-sha256:{}g", &HEX[..63])
            .parse::<UpstreamTlsMode>()
            .is_err()
    );
    assert!("Default".parse::<UpstreamTlsMode>().is_err());
    assert!("".parse::<UpstreamTlsMode>().is_err());
}

#[test]
fn an_old_resource_without_connection_reads_as_default() {
    let json = r#"{"name":"a","host":"h","protocol":"https","operations":["GET"]}"#;
    let resource: ResourcePolicy = serde_json::from_str(json).unwrap();
    assert_eq!(resource.connection, Connection::default());
    let back = serde_json::to_value(&resource).unwrap();
    assert!(back.get("connection").is_none());

    let mut set = resource;
    set.connection.upstream_port = Some(8443);
    let back = serde_json::to_value(&set).unwrap();
    assert_eq!(back["connection"]["upstream_port"], 8443);
    let again: ResourcePolicy = serde_json::from_value(back).unwrap();
    assert_eq!(again, set);
}

#[test]
fn resolve_fills_protocol_defaults() {
    for (protocol, port) in [
        ("https", 443),
        ("http", 80),
        ("postgres", 5432),
        ("mysql", 3306),
        ("mongo", 27017),
        ("MySQL", 3306),
    ] {
        assert_eq!(default_port(protocol), Some(port));
        assert_eq!(
            Connection::default().resolve("db.x", protocol).unwrap(),
            ResolvedConnection {
                upstream_host: "db.x".to_string(),
                upstream_port: port,
                upstream_tls: UpstreamTlsMode::Default,
                local_endpoint: false,
            }
        );
    }
    assert_eq!(default_port("ftp"), None);

    let set = Connection {
        upstream_host: Some("10.1.2.3".to_string()),
        upstream_port: Some(8443),
        upstream_tls: UpstreamTlsMode::PinSha256(bytes()),
        local_endpoint: false,
    };
    assert_eq!(
        set.resolve("db.x", "postgres").unwrap(),
        ResolvedConnection {
            upstream_host: "10.1.2.3".to_string(),
            upstream_port: 8443,
            upstream_tls: UpstreamTlsMode::PinSha256(bytes()),
            local_endpoint: false,
        }
    );
    assert!(
        with_tls(UpstreamTlsMode::CaSha256(bytes()))
            .resolve("db.x", "https")
            .is_err()
    );
}

#[test]
fn loopback_hosts() {
    for host in ["localhost", "LOCALHOST", "127.0.0.1", "::1", "[::1]"] {
        assert!(is_loopback_host(host), "{host}");
    }
    for host in ["10.0.0.1", "[::ffff:10.0.0.1]", "example.com", ""] {
        assert!(!is_loopback_host(host), "{host}");
    }
}

#[test]
fn validate_applies_the_agent_rules() {
    let ca = UpstreamTlsMode::CaSha256(bytes());
    let pin = UpstreamTlsMode::PinSha256(bytes());

    for protocol in ["postgres", "mysql", "mongo", "redis"] {
        assert!(
            with_tls(ca).validate("db.x", protocol).is_ok(),
            "ca {protocol}"
        );
        assert!(
            with_tls(pin).validate("db.x", protocol).is_ok(),
            "pin {protocol}"
        );
    }
    for protocol in ["https", "http"] {
        let err = with_tls(ca).validate("db.x", protocol).unwrap_err();
        assert!(err.contains("upstream_tls"), "{err}");
        assert!(
            with_tls(pin).validate("db.x", protocol).is_err(),
            "pin {protocol}"
        );
    }

    let plain = UpstreamTlsMode::Plaintext;
    for protocol in ["mongo.example.com: mongo", "redis.example.com: redis"] {
        let (host, protocol) = protocol.split_once(": ").unwrap();
        assert!(
            with_tls(plain).validate(host, protocol).is_ok(),
            "{protocol}"
        );
    }
    for host in ["127.0.0.1", "localhost", "::1", "[::1]"] {
        assert!(
            with_host(Some(host), plain)
                .validate("api.example.com", "https")
                .is_ok(),
            "{host}"
        );
    }
    assert!(with_tls(plain).validate("localhost", "https").is_ok());
    for host in ["10.0.0.1", "[::ffff:10.0.0.1]"] {
        let err = with_host(Some(host), plain)
            .validate("api.example.com", "https")
            .unwrap_err();
        assert_eq!(
            err,
            "upstream_tls plaintext is allowed only on mongo and redis, or on https with a loopback upstream_host"
        );
    }
    assert!(
        with_tls(plain)
            .validate("api.example.com", "https")
            .is_err()
    );
    for protocol in ["postgres", "mysql", "http"] {
        assert!(
            with_tls(plain).validate("db.x", protocol).is_err(),
            "{protocol}"
        );
    }

    let local = Connection {
        local_endpoint: true,
        ..Connection::default()
    };
    assert!(local.validate("api.x", "https").is_ok());
    for protocol in ["http", "postgres", "mysql", "mongo", "redis"] {
        let err = local.validate("db.x", protocol).unwrap_err();
        assert!(err.contains("local_endpoint"), "{err}");
    }

    let port_zero = Connection {
        upstream_port: Some(0),
        ..Connection::default()
    };
    let err = port_zero.validate("db.x", "mysql").unwrap_err();
    assert!(err.contains("upstream_port"), "{err}");
    assert!(
        Connection {
            upstream_port: Some(3307),
            ..Connection::default()
        }
        .validate("db.x", "mysql")
        .is_ok()
    );

    let empty_host = with_host(Some(""), UpstreamTlsMode::Default);
    let err = empty_host.validate("db.x", "mysql").unwrap_err();
    assert!(err.contains("upstream_host"), "{err}");
    assert!(
        with_host(Some("db.y"), UpstreamTlsMode::Default)
            .validate("db.x", "mysql")
            .is_ok()
    );

    assert!(Connection::default().validate("x", "ftp").is_ok());
    assert!(local.validate("x", "ftp").is_err());
    assert!(with_tls(plain).validate("x", "ftp").is_err());
    assert!(with_tls(ca).validate("x", "ftp").is_err());
    assert!(port_zero.validate("x", "ftp").is_err());
    assert!(
        Connection {
            upstream_port: Some(22),
            ..Connection::default()
        }
        .validate("x", "ftp")
        .is_err()
    );
    assert!(
        with_host(Some("y"), UpstreamTlsMode::Default)
            .validate("x", "ftp")
            .is_err()
    );
}

#[test]
fn validate_accepts_only_a_host_name_or_an_ip_literal_as_upstream_host() {
    let longest = format!("{}.{}", "a".repeat(126), "b".repeat(126));
    assert_eq!(longest.len(), 253);
    for host in [
        "db.example.com",
        "DB.Example.COM",
        "a-b.c-d",
        "localhost",
        "10.1.2.3",
        "::1",
        "[::1]",
        "2001:db8::1",
        "[2001:db8::1]",
        longest.as_str(),
    ] {
        assert!(
            with_host(Some(host), UpstreamTlsMode::Default)
                .validate("db.x", "mysql")
                .is_ok(),
            "{host}"
        );
    }

    let too_long = format!("{longest}c");
    for host in [
        "",
        "db x",
        " db.x",
        "db.x:3306",
        "10.1.2.3:3306",
        "[::1]:443",
        "[::1",
        "::1]",
        "[10.1.2.3]",
        "[db.x]",
        "db..x",
        ".db.x",
        "db.x.",
        "db_x",
        "http://db.x",
        "db.x/path",
        "db\u{1e}x",
        "db\u{1f}x",
        "db\nx",
        "db\u{0}x",
        "dé.x",
        too_long.as_str(),
    ] {
        let err = with_host(Some(host), UpstreamTlsMode::Default)
            .validate("db.x", "mysql")
            .unwrap_err();
        assert!(err.contains("upstream_host"), "{host:?}: {err}");
    }
}

#[test]
fn summary_names_only_the_parts_that_are_not_default() {
    assert_eq!(Connection::default().summary(), "");
    assert_eq!(
        Connection {
            upstream_host: Some("127.0.0.1".to_string()),
            upstream_port: Some(59080),
            upstream_tls: UpstreamTlsMode::Plaintext,
            local_endpoint: false,
        }
        .summary(),
        "127.0.0.1:59080 plaintext"
    );
    assert_eq!(
        Connection {
            upstream_port: Some(3307),
            ..Connection::default()
        }
        .summary(),
        ":3307"
    );
    assert_eq!(
        with_host(Some("db.y"), UpstreamTlsMode::Default).summary(),
        "db.y"
    );
    assert_eq!(
        with_tls(UpstreamTlsMode::CaSha256(bytes())).summary(),
        "ca 00112233…"
    );
    assert_eq!(
        with_tls(UpstreamTlsMode::PinSha256(bytes())).summary(),
        "pin 00112233…"
    );
    assert_eq!(
        Connection {
            local_endpoint: true,
            ..Connection::default()
        }
        .summary(),
        "local endpoint"
    );
}
