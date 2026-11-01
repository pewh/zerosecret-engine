#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::process::Command;

fn schema() -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .arg("schema")
        .output()
        .expect("failed to execute zs schema");
    assert!(output.status.success(), "zs schema failed: {:?}", output);
    let stdout = String::from_utf8(output.stdout).expect("stdout not utf8");
    serde_json::from_str(&stdout).expect("stdout is not valid JSON")
}

fn property_names(object: &serde_json::Value) -> BTreeSet<String> {
    object["properties"]
        .as_object()
        .expect("properties object")
        .keys()
        .cloned()
        .collect()
}

fn expected_names(error: &str) -> BTreeSet<String> {
    let (_, expected) = error
        .split_once("expected one of ")
        .unwrap_or_else(|| panic!("no expected list in: {error}"));
    expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

fn probe<T: serde::de::DeserializeOwned>(json: serde_json::Value) -> String {
    match serde_json::from_value::<T>(json) {
        Ok(_) => panic!("probe value was accepted"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn test_zs_schema_emits_valid_json_schema() {
    let json = schema();
    assert_eq!(
        json["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(json["type"], "object");
    assert_eq!(json["required"], serde_json::json!(["bindings"]));
    assert!(json["properties"]["bindings"].is_object());
    assert!(json["properties"]["run"].is_object());
    assert!(json["properties"]["grants"].is_object());
    assert!(json["properties"]["signing_keys"].is_object());
}

#[test]
fn test_schema_binding_fields_match_the_parser() {
    let json = schema();
    let binding = &json["properties"]["bindings"]["items"];
    assert_eq!(binding["additionalProperties"], false);
    let error = probe::<zs::ResourceBinding>(serde_json::json!({
        "resource": "probe",
        "host": "probe.example",
        "zz_probe": true
    }));
    assert_eq!(property_names(binding), expected_names(&error));
}

#[test]
fn test_schema_run_fields_match_the_parser() {
    let json = schema();
    let run = &json["properties"]["run"];
    assert_eq!(run["additionalProperties"], false);
    let error = probe::<zs::RunSettings>(serde_json::json!({ "zz_probe": true }));
    assert_eq!(property_names(run), expected_names(&error));
}

#[test]
fn test_schema_auth_schemes_match_the_parser() {
    let json = schema();
    let schemes: BTreeSet<String> =
        json["properties"]["bindings"]["items"]["properties"]["auth"]["properties"]["scheme"]
            ["enum"]
            .as_array()
            .expect("scheme enum")
            .iter()
            .map(|v| v.as_str().expect("scheme string").to_string())
            .collect();
    let error = probe::<zs::HttpAuth>(serde_json::json!({ "scheme": "zz-probe" }));
    assert_eq!(schemes, expected_names(&error));
}

#[test]
fn test_schema_rejects_extra_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_zs"))
        .args(["schema", "--json"])
        .output()
        .expect("failed to execute zs schema");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
