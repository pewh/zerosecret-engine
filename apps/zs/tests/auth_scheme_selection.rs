#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zs::{AgentFile, HttpAuth};

fn config(auth_json: &str) -> AgentFile {
    let json = format!(
        r#"{{"bindings":[{{"resource":"example-api","host":"api.example.com"{auth_json}}}]}}"#
    );
    serde_json::from_str(&json).expect("config must parse")
}

#[test]
fn a_binding_without_an_auth_key_defaults_to_bearer() {
    let file = config("");
    assert_eq!(file.bindings[0].auth, HttpAuth::Bearer);
}

#[test]
fn each_scheme_parses_from_config() {
    assert_eq!(
        config(r#","auth":{"scheme":"basic"}"#).bindings[0].auth,
        HttpAuth::Basic
    );
    assert_eq!(
        config(r#","auth":{"scheme":"api-key-header","header":"X-Api-Key"}"#).bindings[0].auth,
        HttpAuth::ApiKeyHeader {
            header: "X-Api-Key".into()
        }
    );
    assert_eq!(
        config(r#","auth":{"scheme":"query-param","param":"api_token"}"#).bindings[0].auth,
        HttpAuth::QueryParam {
            param: "api_token".into()
        }
    );
}

#[test]
fn the_hmac_body_signature_scheme_parses_with_both_header_names() {
    let file = config(
        r#","auth":{"scheme":"hmac-body-signature","id_header":"va","signature_header":"signature"}"#,
    );
    assert_eq!(
        file.bindings[0].auth,
        HttpAuth::HmacBodySignature {
            id_header: "va".into(),
            signature_header: "signature".into(),
        }
    );
    assert!(file.validate().is_ok());
}

#[test]
fn the_hmac_body_signature_scheme_refuses_a_missing_header_name() {
    for auth in [
        r#"{"scheme":"hmac-body-signature"}"#,
        r#"{"scheme":"hmac-body-signature","id_header":"va"}"#,
        r#"{"scheme":"hmac-body-signature","signature_header":"signature"}"#,
    ] {
        let json = format!(r#"{{"bindings":[{{"resource":"r","host":"h","auth":{auth}}}]}}"#);
        assert!(serde_json::from_str::<AgentFile>(&json).is_err(), "{auth}");
    }
}

#[test]
fn the_hmac_body_signature_scheme_refuses_bad_header_names_at_load() {
    for (id_header, signature_header) in [
        ("va", "VA"),
        ("v a", "signature"),
        ("", "signature"),
        ("va", "sig:nature"),
        ("va", "Host"),
        ("va", "authorization"),
        ("va", "Content-Length"),
        ("va", "transfer-encoding"),
    ] {
        let file = config(&format!(
            r#","auth":{{"scheme":"hmac-body-signature","id_header":"{id_header}","signature_header":"{signature_header}"}}"#
        ));
        let err = file
            .validate()
            .expect_err(&format!("{id_header:?} / {signature_header:?}"));
        assert!(err.to_string().contains("example-api"), "{err}");
    }
}

#[test]
fn an_unknown_scheme_is_refused_rather_than_defaulted() {
    let json = r#"{"bindings":[{"resource":"r","host":"h","auth":{"scheme":"custom-signing"}}]}"#;
    assert!(
        serde_json::from_str::<AgentFile>(json).is_err(),
        "an unrecognised scheme must not silently become bearer"
    );
}

#[test]
fn custom_signing_is_not_a_v1_scheme() {
    let json = r#"{"bindings":[{"resource":"r","host":"h","auth":{"scheme":"custom-signing","key":"k"}}]}"#;
    assert!(serde_json::from_str::<AgentFile>(json).is_err());
}

#[test]
fn a_scheme_missing_its_parameter_is_refused() {
    for json in [
        r#"{"bindings":[{"resource":"r","host":"h","auth":{"scheme":"api-key-header"}}]}"#,
        r#"{"bindings":[{"resource":"r","host":"h","auth":{"scheme":"query-param"}}]}"#,
    ] {
        assert!(
            serde_json::from_str::<AgentFile>(json).is_err(),
            "a scheme without its parameter must be refused: {json}"
        );
    }
}

mod selection_is_honoured {
    use super::*;
    use std::sync::Arc;
    use zs::{AgentHandler, GrantCache, ResourceBinding};
    use zs_credential::Credential;
    use zs_protocol::{InjectedRequest, Protocol};

    const HOST: &str = "api.example.com";
    const SECRET: &str = "sk_selection_probe";

    fn protocol_for(auth: HttpAuth) -> Arc<dyn Protocol> {
        let handler = AgentHandler::from_grants(
            zs_identity::Subject::new("alice@company.com").unwrap(),
            zs_identity::WorkloadLabel::new("claude-code").unwrap(),
            vec![ResourceBinding {
                resource: "example-api".into(),
                host: HOST.into(),
                protocol: "https".into(),
                upstream_host: None,
                upstream_port: None,
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
                auth,
                source: None,
                loaded_ca: None,
            }],
            GrantCache::new(),
            zs_grant::AgentVerifier::new(vec![]),
            materializer(),
        );
        use zs_mitm::FlowHandler;
        handler
            .protocol_for(HOST)
            .expect("a binding must register a protocol")
    }

    fn materializer() -> Arc<zs_materializer::Materializer> {
        struct NoExchange;
        #[async_trait::async_trait]
        impl zs_materializer::ExchangeProvider for NoExchange {
            async fn exchange(
                &self,
                _grant: &zs_grant::Grant,
            ) -> Result<Credential, zs_materializer::MaterializationError> {
                Err(zs_materializer::MaterializationError::Exchange("no".into()))
            }
        }
        Arc::new(zs_materializer::Materializer::new(
            zs_materializer::StoreRegistry::new(Arc::new(zs_materializer::FileStore::new(
                "/nonexistent",
            ))),
            Arc::new(NoExchange),
        ))
    }

    fn inject(auth: HttpAuth) -> InjectedRequest {
        let mut request = InjectedRequest {
            path: "/v1/thing".into(),
            ..Default::default()
        };
        let credential = Credential::from_bytes(SECRET.as_bytes().to_vec()).unwrap();
        protocol_for(auth)
            .inject(&mut request, &credential)
            .expect("injection must succeed");
        request
    }

    #[test]
    fn bearer_builds_a_bearer_header() {
        let request = inject(HttpAuth::Bearer);
        assert_eq!(
            request.header("Authorization"),
            Some(format!("Bearer {SECRET}").as_str())
        );
    }

    #[test]
    fn basic_builds_a_basic_header_not_a_bearer_one() {
        let request = inject(HttpAuth::Basic);
        assert_eq!(
            request.header("Authorization"),
            Some(format!("Basic {SECRET}").as_str()),
            "a `basic` binding that emits `Bearer` is the config being ignored"
        );
    }

    #[test]
    fn api_key_header_builds_the_named_header_and_no_authorization() {
        let request = inject(HttpAuth::ApiKeyHeader {
            header: "X-Api-Key".into(),
        });
        assert_eq!(request.header("X-Api-Key"), Some(SECRET));
        assert!(
            request.header("Authorization").is_none(),
            "an api-key binding must not also send Authorization"
        );
    }

    #[test]
    fn query_param_builds_a_url_parameter_and_no_header() {
        let request = inject(HttpAuth::QueryParam {
            param: "api_token".into(),
        });
        assert!(
            request.path.contains(&format!("api_token={SECRET}")),
            "got {}",
            request.path
        );
        assert!(
            request.headers.iter().all(|(_, v)| !v.contains(SECRET)),
            "a query-param binding must not also send the credential in a header"
        );
    }
}

#[test]
fn a_plaintext_upstream_off_loopback_is_refused_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zs-policy.json");
    std::fs::write(
        &path,
        r#"{"bindings":[{"resource":"example-api","host":"api.example.com","upstream_host":"10.0.0.5","upstream_port":8080,"upstream_plaintext":true}]}"#,
    )
    .unwrap();
    let err = AgentFile::load(&path).expect_err("load must refuse");
    assert!(err.to_string().contains("loopback"), "{err}");
}

#[test]
fn a_plaintext_upstream_on_loopback_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zs-policy.json");
    std::fs::write(
        &path,
        r#"{"bindings":[{"resource":"example-api","host":"api.example.com","upstream_host":"127.0.0.1","upstream_port":8080,"upstream_plaintext":true}]}"#,
    )
    .unwrap();
    assert_eq!(
        AgentFile::load(&path).unwrap().bindings[0].https_upstream_tls(),
        Ok(false)
    );
}

#[test]
fn an_https_binding_without_operations_grants_get_only() {
    assert_eq!(config("").bindings[0].operations(), vec!["GET".to_string()]);
}
