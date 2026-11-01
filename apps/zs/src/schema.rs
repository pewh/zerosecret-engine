use std::io::Write;

pub const POLICY_JSON_SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ZeroSecretPolicy",
  "description": "Configuration schema for zs-policy.json",
  "type": "object",
  "required": ["bindings"],
  "properties": {
    "run": {
      "type": "object",
      "properties": {
        "control": { "type": "string" },
        "control_ca": { "type": "string" },
        "credentials_dir": { "type": "string" },
        "ca_dir": { "type": "string" },
        "audit": { "type": "string" }
      },
      "additionalProperties": false
    },
    "bindings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["resource", "host"],
        "additionalProperties": false,
        "properties": {
          "resource": { "type": "string" },
          "host": { "type": "string" },
          "protocol": {
            "type": "string",
            "enum": ["https", "http", "postgres", "mysql", "mongo"],
            "default": "https"
          },
          "listen_port": { "type": "integer", "minimum": 1, "maximum": 65535 },
          "local_endpoint": { "type": "boolean", "default": false },
          "upstream_host": { "type": "string" },
          "upstream_port": { "type": "integer", "minimum": 0, "maximum": 65535 },
          "upstream_plaintext": { "type": "boolean", "default": false },
          "upstream_ca": { "type": "string" },
          "upstream_cert_sha256": { "type": "string" },
          "client_auth_plugin": {
            "type": "string",
            "enum": ["caching_sha2_password", "mysql_native_password"]
          },
          "paths": { "type": "array", "items": { "type": "string" } },
          "source": {
            "type": "object",
            "description": "set only by the control plane; a local policy that sets it is refused"
          },
          "operations": { "type": "array", "items": { "type": "string" } },
          "user": { "type": "string", "minLength": 1 },
          "auth_source": { "type": "string", "minLength": 1 },
          "auth": {
            "type": "object",
            "required": ["scheme"],
            "properties": {
              "scheme": {
                "type": "string",
                "enum": [
                  "bearer",
                  "basic",
                  "api-key-header",
                  "query-param",
                  "websocket-json-field",
                  "aws-sigv4",
                  "hmac-body-signature"
                ],
                "default": "bearer"
              },
              "header": { "type": "string" },
              "param": { "type": "string" },
              "field": { "type": "string" },
              "access_key_id": { "type": "string" },
              "region": { "type": "string" },
              "service": { "type": "string" },
              "id_header": { "type": "string" },
              "signature_header": { "type": "string" }
            },
            "allOf": [
              {
                "if": { "properties": { "scheme": { "const": "api-key-header" } } },
                "then": { "required": ["header"] }
              },
              {
                "if": { "properties": { "scheme": { "const": "query-param" } } },
                "then": { "required": ["param"] }
              },
              {
                "if": { "properties": { "scheme": { "const": "websocket-json-field" } } },
                "then": { "required": ["field"] }
              },
              {
                "if": { "properties": { "scheme": { "const": "aws-sigv4" } } },
                "then": { "required": ["access_key_id", "region", "service"] }
              },
              {
                "if": { "properties": { "scheme": { "const": "hmac-body-signature" } } },
                "then": { "required": ["id_header", "signature_header"] }
              }
            ]
          }
        }
      }
    },
    "signing_keys": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["key_id", "verifying_key_hex"],
        "properties": {
          "key_id": { "type": "string" },
          "verifying_key_hex": { "type": "string" }
        }
      }
    },
    "grants": {
      "type": "array",
      "description": "Signed grants cached for offline use. zs writes these; do not author them by hand.",
      "items": {
        "type": "object",
        "required": ["grant", "signature", "signing_key_id"],
        "properties": {
          "grant": { "type": "object" },
          "signature": { "type": "string" },
          "signing_key_id": { "type": "string" }
        }
      }
    }
  }
}"#;

pub fn print_schema() -> i32 {
    stdout_line!("{POLICY_JSON_SCHEMA}");
    0
}
